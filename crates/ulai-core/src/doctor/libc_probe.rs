// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 7: the host's C library. glibc via `getconf GNU_LIBC_VERSION`;
//! musl via `/lib/ld-musl-*.so.1`. Never inferred from our own libc (the
//! `ulai` binary is static musl).

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::paths::find_program;
use super::{Errors, Section};
use crate::host::{Host, io_reason};

const GETCONF_DIRS: &[&str] = &["/usr/bin", "/bin"];

#[derive(Debug, Clone, Default, Serialize)]
pub struct Libc {
    /// e.g. `"2.44"`.
    pub glibc: Option<String>,
    /// Path of the musl dynamic loader, if installed system-wide.
    pub musl_loader: Option<PathBuf>,
}

/// Parses `glibc 2.44` (getconf output).
pub fn parse_getconf(out: &str) -> Option<String> {
    let v = out.trim().strip_prefix("glibc ")?.trim();
    (!v.is_empty() && v.chars().all(|c| c.is_ascii_digit() || c == '.')).then(|| v.to_owned())
}

fn musl_loader(host: &dyn Host) -> Option<PathBuf> {
    let entries = host.read_dir(Path::new("/lib")).ok()?;
    entries.iter().find_map(|e| {
        let name = e.name.to_str()?;
        (name.starts_with("ld-musl-") && name.ends_with(".so.1"))
            .then(|| Path::new("/lib").join(name))
    })
}

pub fn probe(host: &dyn Host) -> Section<Libc> {
    let mut errors = Errors::default();
    let mut glibc_reason = None;
    let glibc = match find_program(host, "getconf", GETCONF_DIRS) {
        None => {
            glibc_reason = Some("getconf not found".to_owned());
            None
        }
        Some(prog) => match host.run(&prog, &["GNU_LIBC_VERSION"]) {
            Ok(out) if out.success() => {
                let v = parse_getconf(&out.stdout);
                if v.is_none() {
                    glibc_reason =
                        Some(format!("unexpected getconf output {:?}", out.stdout.trim()));
                }
                v
            }
            // A non-glibc getconf rejects the variable: a known "not glibc".
            Ok(_) => None,
            Err(e) => {
                glibc_reason = Some(format!("getconf failed: {}", io_reason(&e)));
                None
            }
        },
    };
    let musl_loader = musl_loader(host);
    let data = Libc { glibc, musl_loader };
    match glibc_reason {
        Some(r) if data.musl_loader.is_none() => {
            errors.push("*", format!("{r}, and no musl loader in /lib"));
            Section::unknown(data, errors)
        }
        _ => Section::new(data, errors),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::testing::FakeHost;

    #[test]
    fn parse() {
        assert_eq!(parse_getconf("glibc 2.44\n").as_deref(), Some("2.44"));
        assert_eq!(parse_getconf("glibc 2.39").as_deref(), Some("2.39"));
        assert_eq!(parse_getconf("musl"), None);
        assert_eq!(parse_getconf("glibc "), None);
    }

    fn with_getconf(code: i32, out: &str) -> FakeHost {
        let mut h = FakeHost::new();
        h.file_mode("/usr/bin/getconf", "", 0o755)
            .command("/usr/bin/getconf", code, out);
        h
    }

    #[test]
    fn glibc_host() {
        let s = probe(&with_getconf(0, "glibc 2.44\n"));
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.glibc.as_deref(), Some("2.44"));
        assert_eq!(s.data.musl_loader, None);
    }

    #[test]
    fn musl_host_with_rejecting_getconf() {
        let mut h = with_getconf(1, "");
        h.file("/lib/ld-musl-x86_64.so.1", "");
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.glibc, None);
        assert_eq!(
            s.data.musl_loader,
            Some(PathBuf::from("/lib/ld-musl-x86_64.so.1"))
        );
    }

    #[test]
    fn musl_host_without_getconf() {
        let mut h = FakeHost::new();
        h.file("/lib/ld-musl-aarch64.so.1", "");
        assert_eq!(probe(&h).status, Status::Ok);
    }

    #[test]
    fn both_present() {
        let mut h = with_getconf(0, "glibc 2.41");
        h.file("/lib/ld-musl-x86_64.so.1", "");
        let s = probe(&h);
        assert_eq!(s.data.glibc.as_deref(), Some("2.41"));
        assert!(s.data.musl_loader.is_some());
    }

    #[test]
    fn neither_is_unknown() {
        let s = probe(&FakeHost::new());
        assert_eq!(s.status, Status::Unknown);
        assert!(s.errors[0].reason.contains("getconf not found"));
    }

    #[test]
    fn getconf_timeout_without_musl_is_unknown() {
        let mut h = FakeHost::new();
        h.file_mode("/usr/bin/getconf", "", 0o755)
            .command_error("/usr/bin/getconf", "timed out after 3 s");
        assert_eq!(probe(&h).status, Status::Unknown);
    }
}
