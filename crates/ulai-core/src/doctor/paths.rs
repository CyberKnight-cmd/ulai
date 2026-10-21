// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Small helpers shared by probes.

use std::io;
use std::path::{Path, PathBuf};

use crate::host::{FileKind, Host, io_reason};

/// Outcome of reading a file that may legitimately be absent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Read {
    Present(String),
    /// `ENOENT`: a known fact, not an error.
    Absent,
    /// Any other failure, with a short reason.
    Failed(String),
}

pub fn read_optional(host: &dyn Host, path: &Path) -> Read {
    match host.read_to_string(path) {
        Ok(s) => Read::Present(s),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Read::Absent,
        Err(e) => Read::Failed(io_reason(&e)),
    }
}

/// Absolute directories from `$PATH`, in order. Relative entries are skipped:
/// they would depend on the current directory.
pub fn path_dirs(host: &dyn Host) -> Vec<PathBuf> {
    host.env("PATH")
        .map(|p| {
            std::env::split_paths(&p)
                .filter(|d| d.is_absolute())
                .collect()
        })
        .unwrap_or_default()
}

/// Finds an executable regular file called `name` in `$PATH`, then in
/// `extra` directories.
pub fn find_program(host: &dyn Host, name: &str, extra: &[&str]) -> Option<PathBuf> {
    let mut dirs = path_dirs(host);
    dirs.extend(extra.iter().map(PathBuf::from));
    dirs.into_iter().map(|d| d.join(name)).find(|p| {
        host.metadata(p)
            .is_ok_and(|m| m.kind == FileKind::File && m.mode & 0o111 != 0)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHost;

    #[test]
    fn read_optional_distinguishes_absent() {
        let mut h = FakeHost::new();
        h.file("/a", "x");
        assert_eq!(
            read_optional(&h, Path::new("/a")),
            Read::Present("x".into())
        );
        assert_eq!(read_optional(&h, Path::new("/b")), Read::Absent);
    }

    #[test]
    fn find_program_needs_exec_bit_and_skips_relative_path_entries() {
        let mut h = FakeHost::new();
        h.file_mode("/opt/x/tool", "", 0o644)
            .file_mode("/usr/bin/tool", "", 0o755)
            .file_mode("rel/tool", "", 0o755)
            .set_env("PATH", "rel:/opt/x:/usr/bin");
        assert_eq!(
            find_program(&h, "tool", &[]),
            Some(PathBuf::from("/usr/bin/tool"))
        );
        assert_eq!(find_program(&h, "missing", &["/usr/bin"]), None);
    }

    #[test]
    fn find_program_uses_extra_dirs() {
        let mut h = FakeHost::new();
        h.file_mode("/sbin/ldconfig", "", 0o755);
        assert_eq!(
            find_program(&h, "ldconfig", &["/sbin"]),
            Some(PathBuf::from("/sbin/ldconfig"))
        );
    }
}
