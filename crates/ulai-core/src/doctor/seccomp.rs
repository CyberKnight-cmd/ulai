// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe: seccomp user notification, the mechanism ULAI uses below
//! Landlock ABI 9 (ADR-013, SPEC §6.7).
//!
//! Runs in a fresh child process (`ulai __seccomp-probe <dir>`), because the
//! probe forks and a seccomp filter can never be removed. That child is the
//! supervisor. Its own child installs a filter that notifies on `connect()`,
//! hands the listener fd back over a socketpair made before the filter, and
//! connects twice to a socket in `dir`. The supervisor answers the first
//! connect by connecting the app's own socket (`pidfd_getfd`), the second by
//! injecting a new socket (`SECCOMP_IOCTL_NOTIF_ADDFD`). It never lets a
//! notified call continue.

use std::fs::File;
use std::io::{Read as _, Write as _};
use std::os::fd::{AsFd, AsRawFd};
use std::os::unix::fs::{FileExt, FileTypeExt, MetadataExt};
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::Path;

use serde::{Deserialize, Serialize};

use super::{Errors, Section};
use crate::host::{Host, errno_name, io_reason};
use crate::sys::{self, Forked, SockFilter};

/// How long the supervisor waits for each step of its child.
const STEP_TIMEOUT_MS: i32 = 2000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Step {
    /// The child installs a filter with `SECCOMP_FILTER_FLAG_NEW_LISTENER`
    /// and passes the listener fd back.
    InstallFilter,
    /// `SECCOMP_IOCTL_NOTIF_RECV` delivers the child's `connect()`.
    Receive,
    /// The address is read from the child's memory, and
    /// `SECCOMP_IOCTL_NOTIF_ID_VALID` confirms the notification afterwards.
    ReadMemory,
    /// `pidfd_getfd` duplicates the child's socket (needs ptrace-attach
    /// permission, so Yama `ptrace_scope` ≥ 2 blocks it).
    PidfdGetfd,
    /// The supervisor connects that socket through
    /// `/proc/self/fd/<O_PATH fd>`.
    ProcFdConnect,
    /// The fallback: a new socket injected with `ADDFD` + `SETFD`.
    AddFd,
    /// The child saw `connect()` return 0 on both sockets.
    AppConnected,
}

impl Step {
    pub fn describe(self) -> &'static str {
        match self {
            Step::InstallFilter => "install a filter with a notification listener",
            Step::Receive => "receive the notification",
            Step::ReadMemory => "read the address and re-check the notification",
            Step::PidfdGetfd => "take the app's socket with pidfd_getfd",
            Step::ProcFdConnect => "connect it through /proc/self/fd",
            Step::AddFd => "inject a new socket with ADDFD",
            Step::AppConnected => "the app's connect() returned 0",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepResult {
    pub step: Step,
    pub ok: bool,
    pub errno: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ChildReport {
    steps: Vec<StepResult>,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    /// Notification works, and the app's own socket can be connected with
    /// `pidfd_getfd` (SPEC §6.7's preferred method).
    Ok,
    /// Notification works, but only the `ADDFD` fallback does.
    FallbackOnly,
    /// The mechanism does not work here; see the steps.
    Failed,
    #[default]
    Unknown,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Seccomp {
    pub result: Outcome,
    /// Every step, in order. A failed method step does not stop the others.
    pub steps: Vec<StepResult>,
}

fn ok(steps: &[StepResult], step: Step) -> bool {
    steps.iter().any(|s| s.step == step && s.ok)
}

/// Parses the child's stdout.
pub fn parse_child_output(stdout: &str) -> Result<Seccomp, String> {
    let line = stdout.lines().next().unwrap_or("");
    let report: ChildReport =
        serde_json::from_str(line).map_err(|e| format!("bad probe output: {e}"))?;
    let s = &report.steps;
    let base = ok(s, Step::InstallFilter) && ok(s, Step::Receive) && ok(s, Step::ReadMemory);
    let result = if !base || !ok(s, Step::AppConnected) {
        Outcome::Failed
    } else if ok(s, Step::PidfdGetfd) && ok(s, Step::ProcFdConnect) {
        Outcome::Ok
    } else if ok(s, Step::AddFd) {
        Outcome::FallbackOnly
    } else {
        Outcome::Failed
    };
    Ok(Seccomp {
        result,
        steps: report.steps,
    })
}

pub fn probe(host: &dyn Host) -> Section<Seccomp> {
    let mut errors = Errors::default();
    let mut data = Seccomp::default();
    match host.seccomp_probe() {
        Ok(out) => match parse_child_output(&out) {
            Ok(p) => data = p,
            Err(e) => errors.push("*", e),
        },
        Err(e) => errors.push("*", format!("probe child failed: {}", io_reason(&e))),
    }
    Section::new(data, errors)
}

/// The probe's filter: x86_64 syscalls only (anything else kills the
/// process), `connect` is notified, everything else allowed.
fn probe_filter() -> Vec<SockFilter> {
    const ARCH: u32 = 0xC000_003E; // AUDIT_ARCH_X86_64
    let ld = |k| SockFilter {
        code: (libc::BPF_LD | libc::BPF_W | libc::BPF_ABS) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    let jeq = |k, jt, jf| SockFilter {
        code: (libc::BPF_JMP | libc::BPF_JEQ | libc::BPF_K) as u16,
        jt,
        jf,
        k,
    };
    let ret = |k| SockFilter {
        code: (libc::BPF_RET | libc::BPF_K) as u16,
        jt: 0,
        jf: 0,
        k,
    };
    vec![
        ld(4), // seccomp_data.arch
        jeq(ARCH, 0, 4),
        ld(0), // seccomp_data.nr
        jeq(libc::SYS_connect as u32, 0, 1),
        ret(libc::SECCOMP_RET_USER_NOTIF),
        ret(libc::SECCOMP_RET_ALLOW),
        ret(libc::SECCOMP_RET_KILL_PROCESS),
    ]
}

struct Steps(Vec<StepResult>);

impl Steps {
    fn record<T>(&mut self, step: Step, r: std::io::Result<T>) -> Option<T> {
        let (ok, errno, v) = match r {
            Ok(v) => (true, None, Some(v)),
            Err(e) => (
                false,
                Some(e.raw_os_error().map_or_else(|| e.to_string(), errno_name)),
                None,
            ),
        };
        self.0.push(StepResult { step, ok, errno });
        v
    }
}

fn other(msg: &str) -> std::io::Error {
    std::io::Error::other(msg.to_owned())
}

/// Body of the hidden `ulai __seccomp-probe <dir>` subcommand: returns one
/// JSON line. Must run in a fresh, single-threaded process.
pub fn child_main(dir: &Path) -> String {
    let mut steps = Steps(Vec::new());
    if let Err(e) = supervise(dir, &mut steps) {
        tracing::debug!(error = %e, "seccomp probe stopped early");
    }
    serde_json::to_string(&ChildReport { steps: steps.0 })
        .unwrap_or_else(|_| r#"{"steps":[]}"#.to_owned())
}

fn supervise(dir: &Path, steps: &mut Steps) -> std::io::Result<()> {
    let target = dir.join("target.sock");
    let _server = UnixListener::bind(&target)?;
    let target_meta = std::fs::metadata(&target)?;
    let (sup, app) = sys::socketpair_stream()?;

    let pid = match sys::fork()? {
        Forked::Child => {
            drop(sup);
            app_main(app, &target)
        }
        Forked::Parent(pid) => pid,
    };
    drop(app);
    let mut sup = UnixStream::from(sup);
    let result = handle(&mut sup, pid, &target, &target_meta, steps);
    drop(sup);
    let waited = sys::waitpid(pid);
    let _ = std::fs::remove_file(&target);
    waited?;
    result
}

/// The sandboxed side, in the forked child of a single-threaded process:
/// no threads, no heap allocation, then `_exit`.
fn app_main(app: std::os::fd::OwnedFd, target: &Path) -> ! {
    let mut app = UnixStream::from(app);
    let filter = probe_filter();
    let listener =
        sys::set_no_new_privs().and_then(|()| sys::seccomp_install_with_listener(&filter));
    let status: i32 = match &listener {
        Ok(_) => 0,
        Err(e) => e.raw_os_error().unwrap_or(libc::EIO),
    };
    let _ = app.write_all(&status.to_ne_bytes());
    let Ok(listener) = listener else {
        sys::exit_now(1)
    };
    if sys::send_fd(app.as_fd(), listener.as_fd()).is_err() {
        sys::exit_now(1);
    }
    drop(listener);
    let mut results = [0i32; 2];
    let mut keep: [Option<UnixStream>; 2] = [None, None];
    for (r, k) in results.iter_mut().zip(&mut keep) {
        *r = match UnixStream::connect(target) {
            Ok(s) => {
                *k = Some(s);
                0
            }
            Err(e) => e.raw_os_error().unwrap_or(libc::EIO),
        };
    }
    for r in results {
        let _ = app.write_all(&r.to_ne_bytes());
    }
    sys::exit_now(0)
}

fn read_i32(s: &mut UnixStream) -> std::io::Result<i32> {
    let mut b = [0u8; 4];
    s.read_exact(&mut b)?;
    Ok(i32::from_ne_bytes(b))
}

fn wait_readable(fd: std::os::fd::BorrowedFd) -> std::io::Result<()> {
    if sys::poll_readable(fd, STEP_TIMEOUT_MS)? {
        Ok(())
    } else {
        Err(std::io::Error::from_raw_os_error(libc::ETIMEDOUT))
    }
}

/// Receives one notification for `connect()` and reads its address.
fn receive(
    listener: std::os::fd::BorrowedFd,
    steps: &mut Steps,
    target: &Path,
) -> Option<sys::Notification> {
    let n = steps.record(
        Step::Receive,
        wait_readable(listener)
            .and_then(|()| sys::notif_recv(listener))
            .and_then(|n| {
                if n.nr == libc::SYS_connect as i32 {
                    Ok(n)
                } else {
                    Err(other("notified for a syscall other than connect"))
                }
            }),
    )?;
    let read = (|| {
        let mem = File::open(format!("/proc/{}/mem", n.pid))?;
        let len = usize::try_from(n.args[2]).unwrap_or(usize::MAX).min(110);
        let mut addr = vec![0u8; len];
        mem.read_exact_at(&mut addr, n.args[1])?;
        if !sys::notif_id_valid(listener, n.id) {
            return Err(other("notification no longer valid after the read"));
        }
        let path = addr.get(2..).unwrap_or_default();
        let path = &path[..path.iter().position(|&b| b == 0).unwrap_or(path.len())];
        if path == target.as_os_str().as_encoded_bytes() {
            Ok(())
        } else {
            Err(other("the address read is not the one the app used"))
        }
    })();
    steps.record(Step::ReadMemory, read).map(|()| n)
}

/// Opens `target` with `O_PATH`, checks it is the expected socket inode,
/// and connects `sock` to it through `/proc/self/fd`.
fn connect_checked(
    sock: std::os::fd::BorrowedFd,
    target: &Path,
    expected: &std::fs::Metadata,
) -> std::io::Result<()> {
    let opath = File::from(sys::open_path(target)?);
    let m = opath.metadata()?;
    if !m.file_type().is_socket() || m.dev() != expected.dev() || m.ino() != expected.ino() {
        return Err(other("the path is not the expected socket"));
    }
    sys::connect_unix(
        sock,
        format!("/proc/self/fd/{}", opath.as_raw_fd()).as_bytes(),
    )
}

/// A new socket, connected to `target`, installed in place of the app's fd.
fn inject(
    listener: std::os::fd::BorrowedFd,
    n: &sys::Notification,
    target: &Path,
    target_meta: &std::fs::Metadata,
) -> std::io::Result<i32> {
    let s = sys::unix_stream_socket()?;
    connect_checked(s.as_fd(), target, target_meta)?;
    let fd = u32::try_from(n.args[0]).map_err(|_| other("bad fd"))?;
    sys::notif_addfd_setfd(listener, n.id, s.as_fd(), fd)
}

fn handle(
    sup: &mut UnixStream,
    pid: libc::pid_t,
    target: &Path,
    target_meta: &std::fs::Metadata,
    steps: &mut Steps,
) -> std::io::Result<()> {
    let listener = steps.record(
        Step::InstallFilter,
        wait_readable(sup.as_fd())
            .and_then(|()| read_i32(sup))
            .and_then(|status| match status {
                0 => sys::recv_fd(sup.as_fd()),
                e => Err(std::io::Error::from_raw_os_error(e)),
            }),
    );
    let Some(listener) = listener else {
        return Ok(());
    };
    let pidfd = sys::pidfd_open(pid)?;

    // Round 1: connect the app's own socket; if pidfd_getfd is refused,
    // fall back to ADDFD, as the real supervisor does.
    if let Some(n) = receive(listener.as_fd(), steps, target) {
        let fd = libc::c_int::try_from(n.args[0]).unwrap_or(-1);
        let dup = steps.record(
            Step::PidfdGetfd,
            sys::pidfd_getfd(pidfd.as_fd(), fd).and_then(|dup| {
                let d = dup.as_fd();
                let kind = sys::sockopt_int(d, libc::SO_TYPE)?;
                if sys::sockopt_int(d, libc::SO_DOMAIN)? == libc::AF_UNIX
                    && (kind == libc::SOCK_STREAM || kind == libc::SOCK_SEQPACKET)
                {
                    Ok(dup)
                } else {
                    Err(other("not an AF_UNIX stream or seqpacket socket"))
                }
            }),
        );
        let connected = match dup {
            Some(dup) => steps
                .record(
                    Step::ProcFdConnect,
                    connect_checked(dup.as_fd(), target, target_meta),
                )
                .is_some(),
            None => inject(listener.as_fd(), &n, target, target_meta).is_ok(),
        };
        let error = if connected { 0 } else { -libc::ECONNREFUSED };
        sys::notif_respond(listener.as_fd(), n.id, 0, error)?;
    }

    // Round 2: inject a new, connected socket in place of the app's fd.
    if let Some(n) = receive(listener.as_fd(), steps, target) {
        let added = steps
            .record(
                Step::AddFd,
                inject(listener.as_fd(), &n, target, target_meta),
            )
            .is_some();
        let error = if added { 0 } else { -libc::ECONNREFUSED };
        sys::notif_respond(listener.as_fd(), n.id, 0, error)?;
    }

    let connected = wait_readable(sup.as_fd()).and_then(|()| {
        let a = read_i32(sup)?;
        let b = read_i32(sup)?;
        match (a, b) {
            (0, 0) => Ok(()),
            (0, e) | (e, _) => Err(std::io::Error::from_raw_os_error(e)),
        }
    });
    steps.record(Step::AppConnected, connected);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(oks: &[(Step, bool)]) -> String {
        let steps: Vec<StepResult> = oks
            .iter()
            .map(|&(step, ok)| StepResult {
                step,
                ok,
                errno: (!ok).then(|| "EPERM".into()),
            })
            .collect();
        serde_json::to_string(&ChildReport { steps }).unwrap()
    }

    use Step::*;

    #[test]
    fn outcomes() {
        let all = [
            (InstallFilter, true),
            (Receive, true),
            (ReadMemory, true),
            (PidfdGetfd, true),
            (ProcFdConnect, true),
            (AddFd, true),
            (AppConnected, true),
        ];
        assert_eq!(parse_child_output(&line(&all)).unwrap().result, Outcome::Ok);
        let mut refused = all;
        refused[6].1 = false; // the app's connect() did not return 0
        assert_eq!(
            parse_child_output(&line(&refused[..])).unwrap().result,
            Outcome::Failed
        );
        let fallback = [
            (InstallFilter, true),
            (Receive, true),
            (ReadMemory, true),
            (PidfdGetfd, false),
            (AddFd, true),
            (AppConnected, true),
        ];
        assert_eq!(
            parse_child_output(&line(&fallback)).unwrap().result,
            Outcome::FallbackOnly
        );
        assert_eq!(
            parse_child_output(&line(&[(InstallFilter, false)]))
                .unwrap()
                .result,
            Outcome::Failed
        );
        assert!(parse_child_output("garbage").is_err());
    }

    #[test]
    fn the_filter_notifies_connect_and_checks_the_architecture() {
        let f = probe_filter();
        assert_eq!(f.len(), 7);
        assert_eq!(f[1].k, 0xC000_003E);
        assert_eq!(f[3].k, libc::SYS_connect as u32);
        assert_eq!(f[4].k, libc::SECCOMP_RET_USER_NOTIF);
        assert_eq!(f[6].k, libc::SECCOMP_RET_KILL_PROCESS);
    }
}
