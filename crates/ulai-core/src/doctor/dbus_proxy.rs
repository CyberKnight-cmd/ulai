// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 10: `xdg-dbus-proxy` (SPEC §7) path and version.

use std::path::PathBuf;

use serde::Serialize;

use super::paths::find_program;
use super::{Errors, Section};
use crate::host::{Host, io_reason};

#[derive(Debug, Clone, Default, Serialize)]
pub struct DbusProxy {
    pub path: Option<PathBuf>,
    pub version: Option<String>,
}

/// Parses `xdg-dbus-proxy 0.1.9`.
pub fn parse_version(out: &str) -> Option<String> {
    let line = out.lines().next()?.trim();
    let v = line.strip_prefix("xdg-dbus-proxy")?.trim();
    (!v.is_empty()).then(|| v.to_owned())
}

pub fn probe(host: &dyn Host) -> Section<DbusProxy> {
    let mut errors = Errors::default();
    let Some(path) = find_program(host, "xdg-dbus-proxy", &["/usr/bin"]) else {
        return Section::new(DbusProxy::default(), errors);
    };
    let version = match host.run(&path, &["--version"]) {
        Ok(out) if out.success() => {
            let v = parse_version(&out.stdout);
            if v.is_none() {
                errors.push(
                    "version",
                    format!("unexpected output {:?}", out.stdout.trim()),
                );
            }
            v
        }
        Ok(out) => {
            errors.push("version", format!("--version exited with {:?}", out.code));
            None
        }
        Err(e) => {
            errors.push("version", format!("--version failed: {}", io_reason(&e)));
            None
        }
    };
    Section::new(
        DbusProxy {
            path: Some(path),
            version,
        },
        errors,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::testing::FakeHost;

    #[test]
    fn found_with_version() {
        let mut h = FakeHost::new();
        h.file_mode("/usr/bin/xdg-dbus-proxy", "", 0o755).command(
            "/usr/bin/xdg-dbus-proxy",
            0,
            "xdg-dbus-proxy 0.1.9\n",
        );
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.version.as_deref(), Some("0.1.9"));
    }

    #[test]
    fn missing_is_known_absence() {
        let s = probe(&FakeHost::new());
        assert_eq!(s.status, Status::Ok);
        assert!(s.data.path.is_none());
    }

    #[test]
    fn version_failure_keeps_path() {
        let mut h = FakeHost::new();
        h.file_mode("/usr/bin/xdg-dbus-proxy", "", 0o755)
            .command("/usr/bin/xdg-dbus-proxy", 1, "");
        let s = probe(&h);
        assert_eq!(s.status, Status::Partial);
        assert!(s.data.path.is_some());
        assert_eq!(s.errors[0].field, "version");
    }

    #[test]
    fn parse() {
        assert_eq!(
            parse_version("xdg-dbus-proxy 0.1.6").as_deref(),
            Some("0.1.6")
        );
        assert_eq!(parse_version("something else"), None);
        assert_eq!(parse_version(""), None);
    }
}
