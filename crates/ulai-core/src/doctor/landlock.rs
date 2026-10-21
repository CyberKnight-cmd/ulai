// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 3: Landlock ABI, protection label (SPEC §6.2) and enforceable
//! features.
//!
//! Uses the raw syscall: the `landlock` crate (0.4.7) exposes no way to read
//! the ABI without creating a ruleset, and caps its ABI enum at V9.
//!
//! The ABI → feature table is SPEC §6.2. ABI 1–10 match the Linux 7.2 uapi
//! header; ABI 8 (`TSYNC`) and ABI 11 (restrict_self no_new_privs flag) come
//! from the kernel documentation, as the header does not state their ABI.

use serde::Serialize;

use super::{Errors, Section};
use crate::host::{Host, errno_name};

/// Highest ABI whose features this version of ULAI knows.
pub const NEWEST_KNOWN_ABI: i32 = 11;

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

/// What each Landlock ABI adds, in ABI order (SPEC §6.2). The JSON field
/// names of the first six features predate this table and are kept for
/// schema 1.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct Features {
    /// ABI 1: base filesystem access rights.
    pub fs_base: bool,
    /// ABI 2: `LANDLOCK_ACCESS_FS_REFER` (rename/link across directories).
    pub refer: bool,
    /// ABI 3: `LANDLOCK_ACCESS_FS_TRUNCATE`.
    pub truncate: bool,
    /// ABI 4: TCP bind/connect.
    pub tcp_deny: bool,
    /// ABI 5: `LANDLOCK_ACCESS_FS_IOCTL_DEV`.
    pub ioctl_dev: bool,
    /// ABI 6: abstract UNIX socket and signal scoping.
    pub ipc_scoping: bool,
    /// ABI 7: audit logging of denials.
    pub audit: bool,
    /// ABI 8: `LANDLOCK_RESTRICT_SELF_TSYNC` (all threads at once).
    pub tsync: bool,
    /// ABI 9: `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (pathname UNIX sockets).
    pub pathname_sockets: bool,
    /// ABI 10: UDP bind and connect/send.
    pub udp: bool,
    /// ABI 10: quiet rules (`LANDLOCK_ADD_RULE_QUIET`, per-rule log
    /// suppression).
    pub quiet_rules: bool,
    /// ABI 11: no_new_privs flag for `landlock_restrict_self()`.
    pub restrict_self_nnp: bool,
}

/// Display name and minimum ABI per feature, in [`Features::as_array`] order.
pub const FEATURE_TABLE: [(&str, i32); 12] = [
    ("filesystem access control", 1),
    ("REFER (cross-directory rename/link)", 2),
    ("TRUNCATE", 3),
    ("TCP bind/connect", 4),
    ("IOCTL_DEV", 5),
    ("abstract-socket and signal scoping", 6),
    ("audit logging", 7),
    ("TSYNC (all threads)", 8),
    ("pathname UNIX sockets (RESOLVE_UNIX)", 9),
    ("UDP bind and connect/send", 10),
    ("quiet rules (ADD_RULE_QUIET)", 10),
    ("no_new_privs flag for restrict_self", 11),
];

pub fn features_for(abi: Option<i32>) -> Features {
    let a = abi.unwrap_or(0);
    Features {
        fs_base: a >= 1,
        refer: a >= 2,
        truncate: a >= 3,
        tcp_deny: a >= 4,
        ioctl_dev: a >= 5,
        ipc_scoping: a >= 6,
        audit: a >= 7,
        tsync: a >= 8,
        pathname_sockets: a >= 9,
        udp: a >= 10,
        quiet_rules: a >= 10,
        restrict_self_nnp: a >= 11,
    }
}

impl Features {
    /// Same order as [`FEATURE_TABLE`].
    pub fn as_array(&self) -> [bool; 12] {
        [
            self.fs_base,
            self.refer,
            self.truncate,
            self.tcp_deny,
            self.ioctl_dev,
            self.ipc_scoping,
            self.audit,
            self.tsync,
            self.pathname_sockets,
            self.udp,
            self.quiet_rules,
            self.restrict_self_nnp,
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
        let on = |a| -> Vec<&str> {
            FEATURE_TABLE
                .iter()
                .zip(features_for(Some(a)).as_array())
                .filter(|(_, on)| *on)
                .map(|((n, _), _)| *n)
                .collect()
        };
        assert_eq!(features_for(None).as_array(), [false; 12]);
        assert_eq!(on(1), ["filesystem access control"]);
        assert_eq!(on(3).len(), 3);
        // Debian 13 (ABI 6): no audit, no TSYNC, no pathname sockets, no UDP.
        assert_eq!(on(6).last(), Some(&"abstract-socket and signal scoping"));
        assert!(features_for(Some(7)).audit && !features_for(Some(7)).tsync);
        assert!(features_for(Some(8)).tsync && !features_for(Some(8)).pathname_sockets);
        let f9 = features_for(Some(9));
        assert!(f9.pathname_sockets && !f9.udp && !f9.quiet_rules);
        let f10 = features_for(Some(10));
        assert!(f10.udp && f10.quiet_rules && !f10.restrict_self_nnp);
        assert_eq!(features_for(Some(11)).as_array(), [true; 12]);
        assert_eq!(features_for(Some(12)).as_array(), [true; 12]);
    }

    #[test]
    fn feature_table_matches_features_for() {
        for a in 0..=12 {
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
        assert!(!interpret(Ok(11), Some(true)).data.abi_newer_than_known);
        let s = interpret(Ok(12), Some(true));
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
