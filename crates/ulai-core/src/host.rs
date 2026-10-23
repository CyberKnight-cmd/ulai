// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The [`Host`] trait: everything doctor needs from the running system.
//!
//! Probes see the system only through this trait, so unit tests can run them
//! against a fake host built from tempdir fixtures (see `testing`).

use std::ffi::OsString;
use std::fs;
use std::io::{self, Read};
use std::os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use crate::sys;

/// How long a helper command (`getconf`, `ldconfig`, …) may run.
pub const COMMAND_TIMEOUT: Duration = Duration::from_secs(3);
/// How long the user-namespace probe child may run.
pub const USERNS_PROBE_TIMEOUT: Duration = Duration::from_secs(5);
/// Hidden `ulai` subcommand that runs the user-namespace probe child.
pub const USERNS_PROBE_SUBCOMMAND: &str = "__userns-probe";
pub const SECCOMP_PROBE_SUBCOMMAND: &str = "__seccomp-probe";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FileKind {
    File,
    Dir,
    Symlink,
    CharDevice,
    BlockDevice,
    Other,
}

impl From<fs::FileType> for FileKind {
    fn from(t: fs::FileType) -> Self {
        if t.is_symlink() {
            Self::Symlink
        } else if t.is_dir() {
            Self::Dir
        } else if t.is_file() {
            Self::File
        } else if t.is_char_device() {
            Self::CharDevice
        } else if t.is_block_device() {
            Self::BlockDevice
        } else {
            Self::Other
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DirEntryInfo {
    pub name: OsString,
    /// Type of the entry itself (symlinks are not followed).
    pub kind: FileKind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MetaInfo {
    /// Type after following symlinks.
    pub kind: FileKind,
    /// Full `st_mode` bits.
    pub mode: u32,
    pub uid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CmdOutput {
    /// Exit code; `None` if killed by a signal.
    pub code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

impl CmdOutput {
    pub fn success(&self) -> bool {
        self.code == Some(0)
    }
}

pub use sys::Uname;

pub trait Host {
    fn read_to_string(&self, path: &Path) -> io::Result<String>;
    fn read_link(&self, path: &Path) -> io::Result<PathBuf>;
    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntryInfo>>;
    /// Like `stat(2)`: follows symlinks.
    fn metadata(&self, path: &Path) -> io::Result<MetaInfo>;
    fn env(&self, key: &str) -> Option<OsString>;
    /// Runs a host system tool with `LC_ALL=C` and a timeout.
    fn run(&self, program: &Path, args: &[&str]) -> io::Result<CmdOutput>;
    fn uname(&self) -> io::Result<Uname>;
    /// Raw Landlock ABI, or the raw errno.
    fn landlock_abi(&self) -> Result<i32, i32>;
    fn uid(&self) -> u32;
    /// Runs the user-namespace probe in a fresh child process and returns its
    /// stdout (one JSON line, parsed by `doctor::userns`).
    fn userns_probe(&self) -> io::Result<String>;
    /// Runs the seccomp user-notification probe in a fresh child process
    /// and returns its stdout (one JSON line, parsed by `doctor::seccomp`).
    fn seccomp_probe(&self) -> io::Result<String>;

    fn exists(&self, path: &Path) -> bool {
        self.metadata(path).is_ok()
    }
}

/// The real system.
#[derive(Debug, Clone, Default)]
pub struct SystemHost {
    /// Our own executable, re-executed for the user-namespace probe. When
    /// `None`, that probe reports "unknown".
    self_exe: Option<PathBuf>,
}

impl SystemHost {
    pub fn new(self_exe: Option<PathBuf>) -> Self {
        Self { self_exe }
    }
}

impl Host for SystemHost {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        fs::read_to_string(path)
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        fs::read_link(path)
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntryInfo>> {
        let mut out = Vec::new();
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            out.push(DirEntryInfo {
                name: entry.file_name(),
                kind: entry.file_type()?.into(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn metadata(&self, path: &Path) -> io::Result<MetaInfo> {
        let m = fs::metadata(path)?;
        Ok(MetaInfo {
            kind: m.file_type().into(),
            mode: m.mode(),
            uid: m.uid(),
        })
    }

    fn env(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }

    fn run(&self, program: &Path, args: &[&str]) -> io::Result<CmdOutput> {
        let mut cmd = Command::new(program);
        cmd.args(args).env_clear().env("LC_ALL", "C");
        if let Some(path) = std::env::var_os("PATH") {
            cmd.env("PATH", path);
        }
        run_with_timeout(cmd, COMMAND_TIMEOUT)
    }

    fn uname(&self) -> io::Result<Uname> {
        sys::uname()
    }

    fn landlock_abi(&self) -> Result<i32, i32> {
        sys::landlock_abi()
    }

    fn uid(&self) -> u32 {
        sys::getuid()
    }

    fn userns_probe(&self) -> io::Result<String> {
        self.probe_child(USERNS_PROBE_SUBCOMMAND)
    }

    fn seccomp_probe(&self) -> io::Result<String> {
        self.probe_child(SECCOMP_PROBE_SUBCOMMAND)
    }
}

impl SystemHost {
    /// Runs `ulai <subcommand> <empty private dir>` and returns its stdout.
    fn probe_child(&self, subcommand: &str) -> io::Result<String> {
        let exe = self.self_exe.as_ref().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Unsupported, "probe child not configured")
        })?;
        let dir = ProbeDir::create()?;
        let mut cmd = Command::new(exe);
        cmd.arg(subcommand)
            .arg(&dir.0)
            .env_clear()
            .env("LC_ALL", "C");
        let out = run_with_timeout(cmd, USERNS_PROBE_TIMEOUT)?;
        if !out.success() {
            return Err(io::Error::other(format!(
                "probe child exited with {:?}",
                out.code
            )));
        }
        Ok(out.stdout)
    }
}

/// Empty private directory for a probe child: the userns probe mounts a
/// tmpfs on it (inside its own mount namespace only), the seccomp probe
/// binds a socket in it and removes it again. Removed on drop.
struct ProbeDir(PathBuf);

impl ProbeDir {
    fn create() -> io::Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.subsec_nanos());
        let path =
            std::env::temp_dir().join(format!("ulai-doctor-probe-{}-{nanos}", std::process::id()));
        fs::DirBuilder::new().mode(0o700).create(&path)?;
        Ok(Self(path))
    }
}

impl Drop for ProbeDir {
    fn drop(&mut self) {
        if let Err(e) = fs::remove_dir(&self.0) {
            tracing::warn!(path = %self.0.display(), error = %e, "could not remove probe dir");
        }
    }
}

/// Spawns `cmd`, captures its output on reader threads (so a full pipe can
/// never deadlock us) and kills it after `timeout`.
fn run_with_timeout(mut cmd: Command, timeout: Duration) -> io::Result<CmdOutput> {
    let mut child = cmd
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let stdout = spawn_reader(child.stdout.take());
    let stderr = spawn_reader(child.stderr.take());

    let deadline = Instant::now() + timeout;
    let status = loop {
        if let Some(status) = child.try_wait()? {
            break status;
        }
        if Instant::now() >= deadline {
            // Best effort: the child may have exited in the meantime.
            let _ = child.kill();
            let _ = child.wait();
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!("timed out after {} s", timeout.as_secs()),
            ));
        }
        thread::sleep(Duration::from_millis(10));
    };
    Ok(CmdOutput {
        code: status.code(),
        stdout: join_reader(stdout),
        stderr: join_reader(stderr),
    })
}

type Reader = Option<thread::JoinHandle<String>>;

fn spawn_reader<R: Read + Send + 'static>(pipe: Option<R>) -> Reader {
    pipe.map(|mut p| {
        thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = p.read_to_end(&mut buf);
            String::from_utf8_lossy(&buf).into_owned()
        })
    })
}

fn join_reader(r: Reader) -> String {
    r.and_then(|h| h.join().ok()).unwrap_or_default()
}

/// Symbolic name for common errno values, e.g. `EPERM`. Falls back to the
/// number for anything else.
pub fn errno_name(errno: i32) -> String {
    let name = match errno {
        libc::EPERM => "EPERM",
        libc::ENOENT => "ENOENT",
        libc::EINTR => "EINTR",
        libc::EIO => "EIO",
        libc::EBADF => "EBADF",
        libc::EAGAIN => "EAGAIN",
        libc::ENOMEM => "ENOMEM",
        libc::EACCES => "EACCES",
        libc::EFAULT => "EFAULT",
        libc::EBUSY => "EBUSY",
        libc::EEXIST => "EEXIST",
        libc::ENOTDIR => "ENOTDIR",
        libc::EINVAL => "EINVAL",
        libc::ENOSPC => "ENOSPC",
        libc::EROFS => "EROFS",
        libc::ENOSYS => "ENOSYS",
        libc::EOVERFLOW => "EOVERFLOW",
        libc::EOPNOTSUPP => "EOPNOTSUPP",
        libc::EUSERS => "EUSERS",
        _ => return format!("errno {errno}"),
    };
    name.to_owned()
}

/// Short reason for an `io::Error`, e.g. `ENOENT` or `timed out after 3 s`.
pub fn io_reason(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => errno_name(n),
        None => e.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn errno_names() {
        assert_eq!(errno_name(libc::EPERM), "EPERM");
        assert_eq!(errno_name(libc::EOPNOTSUPP), "EOPNOTSUPP");
        assert_eq!(errno_name(9999), "errno 9999");
    }

    #[test]
    fn run_captures_output_and_exit_code() {
        let out = SystemHost::default()
            .run(
                Path::new("/bin/sh"),
                &["-c", "echo hi; echo err >&2; exit 3"],
            )
            .unwrap();
        assert_eq!(out.code, Some(3));
        assert_eq!(out.stdout, "hi\n");
        assert_eq!(out.stderr, "err\n");
    }

    #[test]
    fn run_does_not_deadlock_on_large_output() {
        let out = SystemHost::default()
            .run(Path::new("/bin/sh"), &["-c", "head -c 1000000 /dev/zero"])
            .unwrap();
        assert_eq!(out.stdout.len(), 1_000_000);
    }

    #[test]
    fn run_times_out() {
        let mut cmd = Command::new("/bin/sh");
        cmd.args(["-c", "sleep 10"]);
        let err = run_with_timeout(cmd, Duration::from_millis(100)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }

    #[test]
    fn missing_program_is_an_error_not_a_panic() {
        assert!(
            SystemHost::default()
                .run(Path::new("/nonexistent/ulai-test"), &[])
                .is_err()
        );
    }

    #[test]
    fn userns_probe_without_self_exe_is_unsupported() {
        let err = SystemHost::default().userns_probe().unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::Unsupported);
    }
}
