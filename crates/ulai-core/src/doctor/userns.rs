//! Probe 4: unprivileged user namespaces (input for ADR-013 and SPEC O2).
//!
//! Reads the relevant sysctls, then runs a live probe in a fresh child
//! process (`ulai __userns-probe <dir>`). The child must be a new exec:
//! `unshare(CLONE_NEWUSER)` fails with `EINVAL` in a multi-threaded process.

use std::collections::BTreeMap;
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::paths::{Read, read_optional};
use super::{Errors, Section};
use crate::host::{Host, errno_name, io_reason};

/// Sysctls reported when present, as (key, path).
pub const SYSCTLS: [(&str, &str); 3] = [
    ("max_user_namespaces", "/proc/sys/user/max_user_namespaces"),
    (
        "unprivileged_userns_clone",
        "/proc/sys/kernel/unprivileged_userns_clone",
    ),
    (
        "apparmor_restrict_unprivileged_userns",
        "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
    ),
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    Unshare,
    Setgroups,
    UidMap,
    GidMap,
    MountPrivate,
    MountTmpfs,
}

impl Step {
    pub const ALL: [Step; 6] = [
        Step::Unshare,
        Step::Setgroups,
        Step::UidMap,
        Step::GidMap,
        Step::MountPrivate,
        Step::MountTmpfs,
    ];

    pub fn describe(self) -> &'static str {
        match self {
            Step::Unshare => "unshare(CLONE_NEWUSER|CLONE_NEWNS)",
            Step::Setgroups => "write /proc/self/setgroups",
            Step::UidMap => "write /proc/self/uid_map",
            Step::GidMap => "write /proc/self/gid_map",
            Step::MountPrivate => "make / private (MS_REC|MS_PRIVATE)",
            Step::MountTmpfs => "mount tmpfs",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub step: Step,
    pub ok: bool,
    pub errno: Option<String>,
}

/// Wire format between the probe child and the parent.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChildReport {
    steps: Vec<StepResult>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeOutcome {
    /// Every step succeeded.
    Ok,
    /// A step failed; see `failed_step`.
    Failed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct LiveProbe {
    pub result: ProbeOutcome,
    pub failed_step: Option<Step>,
    pub steps: Vec<StepResult>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Userns {
    /// Only sysctls that exist on this kernel.
    pub sysctls: BTreeMap<String, i64>,
    pub probe: LiveProbe,
    /// Results as root say nothing about unprivileged users.
    pub running_as_root: bool,
}

/// Parses the child's stdout into a probe result.
pub fn parse_child_output(stdout: &str) -> Result<LiveProbe, String> {
    let line = stdout.lines().next().unwrap_or("");
    let report: ChildReport =
        serde_json::from_str(line).map_err(|e| format!("bad probe output: {e}"))?;
    let failed = report.steps.iter().find(|s| !s.ok).map(|s| s.step);
    let complete = report.steps.len() == Step::ALL.len()
        && report.steps.iter().zip(Step::ALL).all(|(r, s)| r.step == s);
    let result = match failed {
        Some(_) => ProbeOutcome::Failed,
        None if complete => ProbeOutcome::Ok,
        None => return Err("probe output is incomplete".into()),
    };
    Ok(LiveProbe {
        result,
        failed_step: failed,
        steps: report.steps,
    })
}

pub fn probe(host: &dyn Host) -> Section<Userns> {
    let mut errors = Errors::default();
    let mut data = Userns {
        running_as_root: host.uid() == 0,
        ..Userns::default()
    };

    for (key, path) in SYSCTLS {
        match read_optional(host, Path::new(path)) {
            Read::Present(s) => match s.trim().parse::<i64>() {
                Ok(v) => {
                    data.sysctls.insert(key.to_owned(), v);
                }
                Err(_) => errors.push(
                    format!("sysctls.{key}"),
                    format!("unparsable value {:?}", s.trim()),
                ),
            },
            Read::Absent => {}
            Read::Failed(r) => errors.push(format!("sysctls.{key}"), format!("cannot read: {r}")),
        }
    }

    match host.userns_probe() {
        Ok(out) => match parse_child_output(&out) {
            Ok(p) => data.probe = p,
            Err(e) => errors.push("probe", e),
        },
        Err(e) => errors.push("probe", format!("probe child failed: {}", io_reason(&e))),
    }

    Section::new(data, errors)
}

/// Body of the hidden `ulai __userns-probe <dir>` subcommand. Runs each step
/// in order, stops at the first failure, and returns one JSON line.
///
/// Changes only this short-lived process's namespaces; the tmpfs is mounted
/// on the empty `dir` and disappears with the namespace when we exit.
pub fn child_main(dir: &Path) -> String {
    use crate::sys;

    // Read before unshare: afterwards they report the overflow id.
    let uid = sys::getuid();
    let gid = sys::getgid();

    let actions: [(Step, &dyn Fn() -> std::io::Result<()>); 6] = [
        (Step::Unshare, &|| {
            sys::unshare(libc::CLONE_NEWUSER | libc::CLONE_NEWNS)
        }),
        (Step::Setgroups, &|| {
            std::fs::write("/proc/self/setgroups", "deny")
        }),
        (Step::UidMap, &|| {
            std::fs::write("/proc/self/uid_map", format!("0 {uid} 1\n"))
        }),
        (Step::GidMap, &|| {
            std::fs::write("/proc/self/gid_map", format!("0 {gid} 1\n"))
        }),
        (Step::MountPrivate, &|| {
            sys::mount(
                None,
                Path::new("/"),
                None,
                libc::MS_REC | libc::MS_PRIVATE,
                None,
            )
        }),
        (Step::MountTmpfs, &|| {
            sys::mount(
                Some("tmpfs"),
                dir,
                Some("tmpfs"),
                libc::MS_NOSUID | libc::MS_NODEV | libc::MS_NOEXEC,
                Some("size=64k,mode=700"),
            )
        }),
    ];

    let mut steps = Vec::new();
    for (step, action) in actions {
        match action() {
            Ok(()) => steps.push(StepResult {
                step,
                ok: true,
                errno: None,
            }),
            Err(e) => {
                steps.push(StepResult {
                    step,
                    ok: false,
                    errno: Some(e.raw_os_error().map_or_else(|| e.to_string(), errno_name)),
                });
                break;
            }
        }
    }
    serde_json::to_string(&ChildReport { steps }).unwrap_or_else(|_| r#"{"steps":[]}"#.to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::testing::FakeHost;

    fn ok_line() -> String {
        let steps: Vec<_> = Step::ALL
            .iter()
            .map(|&step| StepResult {
                step,
                ok: true,
                errno: None,
            })
            .collect();
        serde_json::to_string(&ChildReport { steps }).unwrap()
    }

    #[test]
    fn all_steps_ok() {
        let p = parse_child_output(&ok_line()).unwrap();
        assert_eq!(p.result, ProbeOutcome::Ok);
        assert_eq!(p.failed_step, None);
        assert_eq!(p.steps.len(), 6);
    }

    #[test]
    fn reports_each_failing_step() {
        for (i, &step) in Step::ALL.iter().enumerate() {
            let mut steps: Vec<_> = Step::ALL[..i]
                .iter()
                .map(|&s| StepResult {
                    step: s,
                    ok: true,
                    errno: None,
                })
                .collect();
            steps.push(StepResult {
                step,
                ok: false,
                errno: Some("EPERM".into()),
            });
            let line = serde_json::to_string(&ChildReport { steps }).unwrap();
            let p = parse_child_output(&line).unwrap();
            assert_eq!(p.result, ProbeOutcome::Failed);
            assert_eq!(p.failed_step, Some(step));
        }
    }

    #[test]
    fn wire_format_is_snake_case() {
        let p = parse_child_output(
            r#"{"steps":[{"step":"unshare","ok":true,"errno":null},{"step":"setgroups","ok":false,"errno":"EACCES"}]}"#,
        )
        .unwrap();
        assert_eq!(p.failed_step, Some(Step::Setgroups));
    }

    #[test]
    fn garbage_and_incomplete_output_are_errors() {
        assert!(parse_child_output("").is_err());
        assert!(parse_child_output("Segmentation fault").is_err());
        assert!(
            parse_child_output(r#"{"steps":[{"step":"unshare","ok":true,"errno":null}]}"#).is_err()
        );
    }

    #[test]
    fn sysctls_present_absent_and_garbage() {
        let mut h = FakeHost::new();
        h.file("/proc/sys/user/max_user_namespaces", "94304\n")
            .file("/proc/sys/kernel/unprivileged_userns_clone", "banana\n");
        h.userns = Ok(ok_line());
        let s = probe(&h);
        assert_eq!(s.status, Status::Partial);
        assert_eq!(s.data.sysctls.get("max_user_namespaces"), Some(&94304));
        assert!(
            !s.data
                .sysctls
                .contains_key("apparmor_restrict_unprivileged_userns")
        );
        assert_eq!(s.errors.len(), 1);
        assert_eq!(s.errors[0].field, "sysctls.unprivileged_userns_clone");
        assert_eq!(s.data.probe.result, ProbeOutcome::Ok);
    }

    #[test]
    fn ubuntu_like_apparmor_restriction() {
        let mut h = FakeHost::new();
        h.file("/proc/sys/user/max_user_namespaces", "63229").file(
            "/proc/sys/kernel/apparmor_restrict_unprivileged_userns",
            "1",
        );
        h.userns = Ok(
            r#"{"steps":[{"step":"unshare","ok":true,"errno":null},{"step":"setgroups","ok":true,"errno":null},{"step":"uid_map","ok":false,"errno":"EPERM"}]}"#
                .into(),
        );
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        assert_eq!(
            s.data.sysctls.get("apparmor_restrict_unprivileged_userns"),
            Some(&1)
        );
        assert_eq!(s.data.probe.failed_step, Some(Step::UidMap));
    }

    #[test]
    fn child_failure_is_unknown_probe() {
        let mut h = FakeHost::new();
        h.userns = Err("timed out after 5 s".into());
        let s = probe(&h);
        assert_eq!(s.status, Status::Partial);
        assert_eq!(s.data.probe.result, ProbeOutcome::Unknown);
        assert!(s.errors[0].reason.contains("timed out"));
    }

    #[test]
    fn root_is_flagged() {
        let mut h = FakeHost::new();
        h.uid = 0;
        assert!(probe(&h).data.running_as_root);
    }
}
