// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai doctor`: report what this system can enforce.
//!
//! Every probe reads the system only through [`Host`]. A probe never fails the
//! tool: errors become `"unknown"` fields with a reason, and a panicking probe
//! is caught and reported as an internal error. JSON contract:
//! `docs/doctor-schema.md`.

use std::panic::{AssertUnwindSafe, catch_unwind};

use serde::Serialize;

use crate::host::Host;

pub mod dbus_proxy;
pub mod fuse;
pub mod gpu;
pub mod kernel;
pub mod landlock;
pub mod libc_probe;
pub mod libs;
pub mod lsm;
pub mod paths;
pub mod render;
pub mod session;
pub mod userns;
pub mod xdg;
pub mod yama;

/// Version of the `--json` contract. Bump on renames, removals or changed
/// meaning; adding fields does not bump it.
pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Everything this section reports is known.
    Ok,
    /// Some fields are unknown; see `errors`.
    Partial,
    /// Nothing in this section could be determined.
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldError {
    /// Dotted path of the unknown field, or `*` for the whole section.
    pub field: String,
    pub reason: String,
}

/// One report section: a status, why anything is unknown, and the data.
///
/// In `data`, `null` means "not present / not applicable". Whether a value
/// is unknown is stated only in `errors`.
#[derive(Debug, Clone, Serialize)]
pub struct Section<T> {
    pub status: Status,
    pub errors: Vec<FieldError>,
    #[serde(flatten)]
    pub data: T,
}

impl<T> Section<T> {
    /// `ok` without errors, `partial` with some.
    pub fn new(data: T, errors: Errors) -> Self {
        let status = if errors.0.is_empty() {
            Status::Ok
        } else {
            Status::Partial
        };
        Self {
            status,
            errors: errors.0,
            data,
        }
    }

    /// Nothing could be determined.
    pub fn unknown(data: T, errors: Errors) -> Self {
        Self {
            status: Status::Unknown,
            errors: errors.0,
            data,
        }
    }
}

/// Collects field errors while a probe runs.
#[derive(Debug, Default)]
pub struct Errors(Vec<FieldError>);

impl Errors {
    pub fn push(&mut self, field: impl Into<String>, reason: impl Into<String>) {
        self.0.push(FieldError {
            field: field.into(),
            reason: reason.into(),
        });
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    pub ulai_version: &'static str,
    pub kernel: Section<kernel::Kernel>,
    pub lsm: Section<lsm::Lsm>,
    pub landlock: Section<landlock::Landlock>,
    pub userns: Section<userns::Userns>,
    pub yama: Section<yama::Yama>,
    pub fuse: Section<fuse::Fuse>,
    pub libc: Section<libc_probe::Libc>,
    pub session: Section<session::Session>,
    pub gpu: Section<gpu::Gpu>,
    pub dbus_proxy: Section<dbus_proxy::DbusProxy>,
    pub xdg: Section<xdg::Xdg>,
}

/// Runs `probe`, turning a panic into an `unknown` section.
fn isolated<T: Default>(name: &str, probe: impl FnOnce() -> Section<T>) -> Section<T> {
    catch_unwind(AssertUnwindSafe(probe)).unwrap_or_else(|_| {
        tracing::error!(probe = name, "probe panicked");
        let mut errors = Errors::default();
        errors.push("*", "internal error: probe panicked");
        Section::unknown(T::default(), errors)
    })
}

/// Runs every probe. Never panics and never fails.
pub fn run(host: &dyn Host) -> Report {
    let lsm = isolated("lsm", || lsm::probe(host));
    let lsm_has_landlock = lsm.data.landlock_listed;
    let libs = catch_unwind(AssertUnwindSafe(|| {
        libs::LibIndex::build(host, libs::WANTED)
    }))
    .unwrap_or_else(|_| libs::LibIndex::failed("internal error: library lookup panicked"));

    Report {
        schema: SCHEMA_VERSION,
        ulai_version: env!("CARGO_PKG_VERSION"),
        kernel: isolated("kernel", || kernel::probe(host)),
        landlock: isolated("landlock", || landlock::probe(host, lsm_has_landlock)),
        lsm,
        userns: isolated("userns", || userns::probe(host)),
        yama: isolated("yama", || yama::probe(host)),
        fuse: isolated("fuse", || fuse::probe(host, &libs)),
        libc: isolated("libc", || libc_probe::probe(host)),
        session: isolated("session", || session::probe(host)),
        gpu: isolated("gpu", || gpu::probe(host, &libs)),
        dbus_proxy: isolated("dbus_proxy", || dbus_proxy::probe(host)),
        xdg: isolated("xdg", || xdg::probe(host)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHost;

    #[test]
    fn empty_host_never_panics_and_reports_schema_1() {
        let report = run(&FakeHost::new());
        assert_eq!(report.schema, 1);
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["schema"], 1);
        assert_eq!(json["kernel"]["status"], "unknown");
    }

    #[test]
    fn panicking_probe_is_isolated() {
        let mut host = FakeHost::new();
        host.panic_on = Some(lsm::LSM_PATH.into());
        let report = run(&host);
        assert_eq!(report.lsm.status, Status::Unknown);
        assert_eq!(
            report.lsm.errors,
            vec![FieldError {
                field: "*".into(),
                reason: "internal error: probe panicked".into()
            }]
        );
        // Other sections still ran.
        assert_eq!(report.kernel.status, Status::Unknown);
        assert!(report.kernel.errors[0].reason.contains("ENOSYS"));
        assert_eq!(report.landlock.data.label, landlock::Label::None);
    }

    #[test]
    fn section_status_follows_errors() {
        assert_eq!(Section::new((), Errors::default()).status, Status::Ok);
        let mut e = Errors::default();
        e.push("x", "y");
        assert_eq!(Section::new((), e).status, Status::Partial);
    }
}
