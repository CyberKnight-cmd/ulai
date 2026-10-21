//! Probe 2: active LSMs, from `/sys/kernel/security/lsm`.

use std::path::Path;

use serde::Serialize;

use super::paths::{Read, read_optional};
use super::{Errors, Section};
use crate::host::Host;

pub const LSM_PATH: &str = "/sys/kernel/security/lsm";

#[derive(Debug, Clone, Default, Serialize)]
pub struct Lsm {
    /// Active LSMs in kernel order.
    pub active: Vec<String>,
    /// Whether `landlock` is in the list; `null` if the list is unknown.
    pub landlock_listed: Option<bool>,
}

/// Parses the comma-separated list (the file has no trailing newline on
/// current kernels, but tolerate one and stray whitespace).
pub fn parse(contents: &str) -> Vec<String> {
    contents
        .split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect()
}

pub fn probe(host: &dyn Host) -> Section<Lsm> {
    let mut errors = Errors::default();
    let reason = match read_optional(host, Path::new(LSM_PATH)) {
        Read::Present(s) => {
            let active = parse(&s);
            let landlock_listed = Some(active.iter().any(|l| l == "landlock"));
            return Section::new(
                Lsm {
                    active,
                    landlock_listed,
                },
                errors,
            );
        }
        Read::Absent => format!("{LSM_PATH} not found (securityfs not mounted?)"),
        Read::Failed(r) => format!("cannot read {LSM_PATH}: {r}"),
    };
    errors.push("active", reason);
    Section::unknown(Lsm::default(), errors)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::testing::FakeHost;

    #[test]
    fn parses_list() {
        assert_eq!(
            parse("capability,landlock,lockdown,yama,bpf"),
            ["capability", "landlock", "lockdown", "yama", "bpf"]
        );
    }

    #[test]
    fn tolerates_newline_spaces_and_empty_items() {
        assert_eq!(
            parse(" capability, yama,,apparmor\n"),
            ["capability", "yama", "apparmor"]
        );
        assert!(parse("").is_empty());
        assert!(parse("\n").is_empty());
    }

    #[test]
    fn landlock_listed() {
        let mut h = FakeHost::new();
        h.file(LSM_PATH, "capability,landlock,yama");
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.landlock_listed, Some(true));
    }

    #[test]
    fn landlock_not_listed() {
        let mut h = FakeHost::new();
        h.file(LSM_PATH, "capability,apparmor");
        assert_eq!(probe(&h).data.landlock_listed, Some(false));
    }

    #[test]
    fn empty_file_is_known_empty_list() {
        let mut h = FakeHost::new();
        h.file(LSM_PATH, "");
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        assert!(s.data.active.is_empty());
        assert_eq!(s.data.landlock_listed, Some(false));
    }

    #[test]
    fn missing_file_is_unknown() {
        let s = probe(&FakeHost::new());
        assert_eq!(s.status, Status::Unknown);
        assert_eq!(s.data.landlock_listed, None);
        assert!(s.errors[0].reason.contains("not found"));
    }
}
