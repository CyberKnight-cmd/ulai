//! Probe 3: Landlock ABI, protection label (SPEC §6.2) and enforceable
//! features.
//!
//! Uses the raw syscall: the `landlock` crate (0.4.7) exposes no way to read
//! the ABI without creating a ruleset, and caps its ABI enum at V9.

use serde::Serialize;

use super::{Errors, Section};
use crate::host::{Host, errno_name};

/// Highest ABI whose features this version of ULAI knows.
pub const NEWEST_KNOWN_ABI: i32 = 10;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// The syscall returned an ABI version.
    Available,
    /// `ENOSYS`: Landlock is not built into this kernel.
    NotBuilt,
    /// `EOPNOTSUPP`: built in but not enabled at boot (`lsm=`).
    Disabled,
    /// Any other error (e.g. blocked by a seccomp filter).
    #[default]
    Unknown,
}

/// SPEC §6.2 protection label.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Label {
    Strong,
    Weak,
    /// Strict and Guarded cannot run. Also used when the ABI is unknown:
    /// fail closed.
    #[default]
    None,
}

impl Label {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Strong => "Strong",
            Self::Weak => "Weak",
            Self::None => "None",
        }
    }
}

/// Maps an ABI (`None` = unavailable or unknown) to its label.
pub fn label_for(abi: Option<i32>) -> Label {
    match abi {
        Some(a) if a >= 9 => Label::Strong,
        Some(a) if a >= 1 => Label::Weak,
        _ => Label::None,
    }
}

/// SPEC features and the minimum ABI that enforces each.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Features {
    /// TCP bind/connect control (ABI ≥ 4).
    pub tcp_deny: bool,
    /// `LANDLOCK_ACCESS_FS_IOCTL_DEV` (ABI ≥ 5).
    pub ioctl_dev: bool,
    /// Abstract UNIX socket and signal scoping (ABI ≥ 6).
    pub ipc_scoping: bool,
    /// Audit logging of denials (ABI ≥ 7).
    pub audit: bool,
    /// Pathname UNIX socket control, `RESOLVE_UNIX` (ABI ≥ 9).
    pub pathname_sockets: bool,
    /// UDP bind/send control (ABI ≥ 10).
    pub udp: bool,
}

/// Minimum ABI per feature, in display order.
pub const FEATURE_TABLE: [(&str, i32); 6] = [
    ("TCP deny", 4),
    ("IOCTL_DEV", 5),
    ("IPC scoping", 6),
    ("audit", 7),
    ("pathname sockets", 9),
    ("UDP", 10),
];

pub fn features_for(abi: Option<i32>) -> Features {
    let a = abi.unwrap_or(0);
    Features {
        tcp_deny: a >= 4,
        ioctl_dev: a >= 5,
        ipc_scoping: a >= 6,
        audit: a >= 7,
        pathname_sockets: a >= 9,
        udp: a >= 10,
    }
}

impl Features {
    /// Same order as [`FEATURE_TABLE`].
    pub fn as_array(&self) -> [bool; 6] {
        [
            self.tcp_deny,
            self.ioctl_dev,
            self.ipc_scoping,
            self.audit,
            self.pathname_sockets,
            self.udp,
        ]
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Landlock {
    pub state: State,
    pub abi: Option<i32>,
    /// Symbolic errno when the syscall failed.
    pub errno: Option<String>,
    pub label: Label,
    /// The kernel reports a newer ABI than this ULAI knows; features beyond
    /// [`NEWEST_KNOWN_ABI`] are not listed.
    pub abi_newer_than_known: bool,
    pub features: Features,
    pub notes: Vec<String>,
}

/// Interprets the raw syscall result. `lsm_listed` comes from the LSM probe
/// and is only used to flag contradictions.
pub fn interpret(raw: Result<i32, i32>, lsm_listed: Option<bool>) -> Section<Landlock> {
    let mut errors = Errors::default();
    let mut ll = Landlock::default();
    match raw {
        Ok(abi) if abi >= 1 => {
            ll.state = State::Available;
            ll.abi = Some(abi);
            ll.abi_newer_than_known = abi > NEWEST_KNOWN_ABI;
        }
        Ok(other) => {
            errors.push("abi", format!("syscall returned unexpected value {other}"));
        }
        Err(e) => {
            ll.errno = Some(errno_name(e));
            match e {
                libc::ENOSYS => ll.state = State::NotBuilt,
                libc::EOPNOTSUPP => ll.state = State::Disabled,
                _ => errors.push(
                    "abi",
                    format!("landlock_create_ruleset failed with {}", errno_name(e)),
                ),
            }
        }
    }
    ll.label = label_for(ll.abi);
    ll.features = features_for(ll.abi);

    let available = ll.state == State::Available;
    match lsm_listed {
        Some(true) if !available && ll.state != State::Unknown => ll
            .notes
            .push("\"landlock\" is in the LSM list, but the syscall says it is unavailable".into()),
        Some(false) if available => ll
            .notes
            .push("the syscall works, but \"landlock\" is not in the LSM list".into()),
        _ => {}
    }

    if ll.state == State::Unknown {
        Section::unknown(ll, errors)
    } else {
        Section::new(ll, errors)
    }
}

pub fn probe(host: &dyn Host, lsm_listed: Option<bool>) -> Section<Landlock> {
    interpret(host.landlock_abi(), lsm_listed)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;

    #[test]
    fn label_table() {
        assert_eq!(label_for(None), Label::None);
        assert_eq!(label_for(Some(0)), Label::None);
        assert_eq!(label_for(Some(-1)), Label::None);
        for a in 1..=8 {
            assert_eq!(label_for(Some(a)), Label::Weak, "ABI {a}");
        }
        for a in 9..=12 {
            assert_eq!(label_for(Some(a)), Label::Strong, "ABI {a}");
        }
    }

    #[test]
    fn feature_table() {
        let f = |a| features_for(Some(a)).as_array();
        assert_eq!(features_for(None).as_array(), [false; 6]);
        assert_eq!(f(1), [false, false, false, false, false, false]);
        assert_eq!(f(3), [false, false, false, false, false, false]);
        assert_eq!(f(4), [true, false, false, false, false, false]);
        assert_eq!(f(5), [true, true, false, false, false, false]);
        assert_eq!(f(6), [true, true, true, false, false, false]);
        assert_eq!(f(7), [true, true, true, true, false, false]);
        assert_eq!(f(8), [true, true, true, true, false, false]);
        assert_eq!(f(9), [true, true, true, true, true, false]);
        assert_eq!(f(10), [true; 6]);
        assert_eq!(f(11), [true; 6]);
    }

    #[test]
    fn feature_table_matches_features_for() {
        for a in 0..=11 {
            let expected: Vec<bool> = FEATURE_TABLE.iter().map(|&(_, min)| a >= min).collect();
            assert_eq!(features_for(Some(a)).as_array().to_vec(), expected);
        }
    }

    #[test]
    fn available_abi() {
        let s = interpret(Ok(10), Some(true));
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.state, State::Available);
        assert_eq!(s.data.abi, Some(10));
        assert_eq!(s.data.label, Label::Strong);
        assert!(!s.data.abi_newer_than_known);
        assert!(s.data.notes.is_empty());
    }

    #[test]
    fn newer_abi_is_strong_and_flagged() {
        let s = interpret(Ok(11), Some(true));
        assert_eq!(s.data.label, Label::Strong);
        assert!(s.data.abi_newer_than_known);
    }

    #[test]
    fn debian_13_like_abi_6_is_weak() {
        let s = interpret(Ok(6), Some(true));
        assert_eq!(s.data.label, Label::Weak);
        assert!(s.data.features.ipc_scoping);
        assert!(!s.data.features.pathname_sockets);
    }

    #[test]
    fn enosys_is_not_built() {
        let s = interpret(Err(libc::ENOSYS), Some(false));
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.state, State::NotBuilt);
        assert_eq!(s.data.errno.as_deref(), Some("ENOSYS"));
        assert_eq!(s.data.label, Label::None);
        assert!(s.data.notes.is_empty());
    }

    #[test]
    fn eopnotsupp_is_disabled() {
        let s = interpret(Err(libc::EOPNOTSUPP), Some(false));
        assert_eq!(s.data.state, State::Disabled);
        assert_eq!(s.data.label, Label::None);
    }

    #[test]
    fn other_errno_is_unknown_and_fails_closed() {
        let s = interpret(Err(libc::EPERM), None);
        assert_eq!(s.status, Status::Unknown);
        assert_eq!(s.data.state, State::Unknown);
        assert_eq!(s.data.label, Label::None);
        assert_eq!(s.data.features, Features::default());
        assert!(s.errors[0].reason.contains("EPERM"));
    }

    #[test]
    fn zero_is_unknown() {
        let s = interpret(Ok(0), None);
        assert_eq!(s.status, Status::Unknown);
        assert_eq!(s.data.label, Label::None);
    }

    #[test]
    fn contradictions_are_noted() {
        let s = interpret(Err(libc::EOPNOTSUPP), Some(true));
        assert_eq!(s.data.notes.len(), 1);
        let s = interpret(Ok(7), Some(false));
        assert_eq!(s.data.notes.len(), 1);
    }
}
