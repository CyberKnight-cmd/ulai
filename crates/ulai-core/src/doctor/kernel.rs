// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 1: kernel release and architecture, from `uname(2)`.

use serde::Serialize;

use super::{Errors, Section};
use crate::host::{Host, io_reason};

#[derive(Debug, Clone, Default, Serialize)]
pub struct Kernel {
    pub release: Option<String>,
    pub arch: Option<String>,
}

pub fn probe(host: &dyn Host) -> Section<Kernel> {
    match host.uname() {
        Ok(u) => Section::new(
            Kernel {
                release: Some(u.release),
                arch: Some(u.machine),
            },
            Errors::default(),
        ),
        Err(e) => {
            let mut errors = Errors::default();
            errors.push("*", format!("uname failed: {}", io_reason(&e)));
            Section::unknown(Kernel::default(), errors)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::host::Uname;
    use crate::testing::FakeHost;

    #[test]
    fn reports_uname() {
        let mut h = FakeHost::new();
        h.uname = Ok(Uname {
            release: "7.2.9-arch1-1".into(),
            machine: "x86_64".into(),
        });
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        assert_eq!(s.data.release.as_deref(), Some("7.2.9-arch1-1"));
        assert_eq!(s.data.arch.as_deref(), Some("x86_64"));
    }

    #[test]
    fn uname_failure_is_unknown() {
        let s = probe(&FakeHost::new());
        assert_eq!(s.status, Status::Unknown);
        assert_eq!(s.errors[0].reason, "uname failed: ENOSYS");
    }
}
