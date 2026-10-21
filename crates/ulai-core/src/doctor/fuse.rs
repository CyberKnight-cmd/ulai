//! Probe 6: FUSE. `/dev/fuse`, the `fusermount` helpers (and whether they are
//! setuid root, which `no_new_privs` disables), and `libfuse.so.2`.
//! Informational: ULAI itself never uses FUSE (ADR-006).

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::libs::{LibIndex, Source};
use super::paths::find_program;
use super::{Errors, Section};
use crate::host::{FileKind, Host, io_reason};

const HELPER_DIRS: &[&str] = &["/usr/bin", "/bin"];

#[derive(Debug, Clone, Serialize)]
pub struct Helper {
    pub path: PathBuf,
    pub setuid_root: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Library {
    pub found: bool,
    pub path: Option<PathBuf>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Fuse {
    pub dev_fuse: Option<bool>,
    pub fusermount3: Option<Helper>,
    pub fusermount: Option<Helper>,
    pub libfuse2: Option<Library>,
}

fn helper(host: &dyn Host, name: &str) -> Option<Helper> {
    let path = find_program(host, name, HELPER_DIRS)?;
    let setuid_root = host
        .metadata(&path)
        .is_ok_and(|m| m.mode & 0o4000 != 0 && m.uid == 0);
    Some(Helper { path, setuid_root })
}

pub fn probe(host: &dyn Host, libs: &LibIndex) -> Section<Fuse> {
    let mut errors = Errors::default();
    let dev_fuse = match host.metadata(Path::new("/dev/fuse")) {
        Ok(m) => Some(m.kind == FileKind::CharDevice),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Some(false),
        Err(e) => {
            errors.push("dev_fuse", io_reason(&e));
            None
        }
    };
    let libfuse2 = if libs.source == Source::None {
        errors.push("libfuse2", libs.fallback_reason.clone().unwrap_or_default());
        None
    } else {
        let path = libs.get("libfuse.so.2").map(Path::to_path_buf);
        Some(Library {
            found: path.is_some(),
            path,
        })
    };
    Section::new(
        Fuse {
            dev_fuse,
            fusermount3: helper(host, "fusermount3"),
            fusermount: helper(host, "fusermount"),
            libfuse2,
        },
        errors,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::doctor::libs::WANTED;
    use crate::host::MetaInfo;
    use crate::testing::FakeHost;

    #[test]
    fn full_fuse_install() {
        let mut h = FakeHost::new();
        h.meta(
            "/dev/fuse",
            MetaInfo {
                kind: FileKind::CharDevice,
                mode: 0o20666,
                uid: 0,
            },
        )
        .meta(
            "/usr/bin/fusermount3",
            MetaInfo {
                kind: FileKind::File,
                mode: 0o104755,
                uid: 0,
            },
        )
        .file("/usr/lib/libfuse.so.2", "");
        let libs = LibIndex::build(&h, WANTED);
        let s = probe(&h, &libs);
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.dev_fuse, Some(true));
        assert!(s.data.fusermount3.as_ref().unwrap().setuid_root);
        assert!(s.data.fusermount.is_none());
        assert!(s.data.libfuse2.unwrap().found);
    }

    #[test]
    fn setuid_but_not_root_owned_is_not_setuid_root() {
        let mut h = FakeHost::new();
        h.meta(
            "/usr/bin/fusermount",
            MetaInfo {
                kind: FileKind::File,
                mode: 0o104755,
                uid: 1000,
            },
        );
        let s = probe(&h, &LibIndex::build(&h, WANTED));
        assert!(!s.data.fusermount.unwrap().setuid_root);
    }

    #[test]
    fn nothing_installed() {
        let h = FakeHost::new();
        let s = probe(&h, &LibIndex::build(&h, WANTED));
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.dev_fuse, Some(false));
        assert!(s.data.fusermount3.is_none());
        assert!(!s.data.libfuse2.unwrap().found);
    }

    #[test]
    fn regular_file_is_not_a_fuse_device() {
        let mut h = FakeHost::new();
        h.file("/dev/fuse", "");
        let s = probe(&h, &LibIndex::build(&h, WANTED));
        assert_eq!(s.data.dev_fuse, Some(false));
    }

    #[test]
    fn failed_lib_index_is_reported() {
        let h = FakeHost::new();
        let s = probe(&h, &LibIndex::failed("boom"));
        assert_eq!(s.status, Status::Partial);
        assert_eq!(s.errors[0].field, "libfuse2");
    }
}
