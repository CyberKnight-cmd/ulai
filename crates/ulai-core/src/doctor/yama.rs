//! Probe 5: Yama ptrace scope, from `/proc/sys/kernel/yama/ptrace_scope`.

use std::path::Path;

use serde::Serialize;

use super::paths::{Read, read_optional};
use super::{Errors, Section};
use crate::host::Host;

pub const PTRACE_SCOPE_PATH: &str = "/proc/sys/kernel/yama/ptrace_scope";

#[derive(Debug, Clone, Default, Serialize)]
pub struct Yama {
    /// `false` when the sysctl does not exist (Yama not built or not active).
    pub active: Option<bool>,
    pub ptrace_scope: Option<u8>,
    pub meaning: Option<&'static str>,
}

pub fn meaning(scope: u8) -> Option<&'static str> {
    Some(match scope {
        0 => "classic: any process of the same user can be traced",
        1 => "restricted: only descendants can be traced",
        2 => "admin-only: tracing needs CAP_SYS_PTRACE",
        3 => "disabled: no process can be traced",
        _ => return None,
    })
}

pub fn probe(host: &dyn Host) -> Section<Yama> {
    let mut errors = Errors::default();
    match read_optional(host, Path::new(PTRACE_SCOPE_PATH)) {
        Read::Present(s) => match s.trim().parse::<u8>() {
            Ok(v) if v <= 3 => Section::new(
                Yama {
                    active: Some(true),
                    ptrace_scope: Some(v),
                    meaning: meaning(v),
                },
                errors,
            ),
            _ => {
                errors.push("ptrace_scope", format!("unexpected value {:?}", s.trim()));
                Section::new(
                    Yama {
                        active: Some(true),
                        ..Yama::default()
                    },
                    errors,
                )
            }
        },
        Read::Absent => Section::new(
            Yama {
                active: Some(false),
                ..Yama::default()
            },
            errors,
        ),
        Read::Failed(r) => {
            errors.push("*", format!("cannot read {PTRACE_SCOPE_PATH}: {r}"));
            Section::unknown(Yama::default(), errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::testing::FakeHost;

    #[test]
    fn scopes_0_to_3() {
        for v in 0..=3u8 {
            let mut h = FakeHost::new();
            h.file(PTRACE_SCOPE_PATH, &format!("{v}\n"));
            let s = probe(&h);
            assert_eq!(s.status, Status::Ok);
            assert_eq!(s.data.ptrace_scope, Some(v));
            assert!(s.data.meaning.is_some());
        }
    }

    #[test]
    fn garbage_is_partial() {
        let mut h = FakeHost::new();
        h.file(PTRACE_SCOPE_PATH, "7");
        let s = probe(&h);
        assert_eq!(s.status, Status::Partial);
        assert_eq!(s.data.active, Some(true));
        assert_eq!(s.data.ptrace_scope, None);
    }

    #[test]
    fn missing_means_not_active() {
        let s = probe(&FakeHost::new());
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.active, Some(false));
    }
}
