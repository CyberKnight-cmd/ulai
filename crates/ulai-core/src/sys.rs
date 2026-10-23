// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Raw system calls. This is the only module in the workspace allowed to use
//! `unsafe`; every block carries a `// SAFETY:` comment.
//!
//! Keep it small: each function wraps exactly one syscall and converts its
//! result to a safe Rust type. No policy lives here.

#![allow(unsafe_code)]

use std::ffi::{CStr, CString, OsStr};
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, FromRawFd, OwnedFd};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

/// Landlock uapi items that neither `libc` nor the `landlock` crate (0.4.7)
/// provide. Every value is copied from `include/uapi/linux/landlock.h` of
/// Linux 7.2 (Arch `linux-api-headers` 7.2-1); `tests::uapi_matches_header`
/// re-checks them against the installed header. Never edit a value by hand.
///
/// `landlock` 0.4.7 covers ABI 1–9 (including the ABI 7 logging flags, ABI 8
/// `TSYNC` and ABI 9 `RESOLVE_UNIX`). ABI 10 is missing upstream: UDP is
/// rust-landlock PR #140 and `ADD_RULE_QUIET` is PR #144. The ABI 11
/// `restrict_self` no_new_privs flag is not in the 7.2 header and is not
/// defined here until a header that has it is available.
pub mod uapi {
    /// `landlock_create_ruleset()` flag: return the ABI version.
    pub const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

    /// ABI 10: bind a UDP socket to a local port.
    pub const LANDLOCK_ACCESS_NET_BIND_UDP: u64 = 1 << 2;
    /// ABI 10: set the remote port of a UDP socket (connect or send).
    pub const LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP: u64 = 1 << 3;
    /// ABI 10: `landlock_add_rule()` flag marking an object "quiet" for the
    /// `quiet_*` fields of [`RulesetAttrV10`].
    pub const LANDLOCK_ADD_RULE_QUIET: u32 = 1 << 0;

    /// `struct landlock_ruleset_attr` as of ABI 10 (Linux 7.2 header). The
    /// kernel accepts shorter, older layouts; the `quiet_*` fields need
    /// ABI ≥ 10.
    #[repr(C)]
    #[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
    pub struct RulesetAttrV10 {
        pub handled_access_fs: u64,
        pub handled_access_net: u64,
        pub scoped: u64,
        pub quiet_access_fs: u64,
        pub quiet_access_net: u64,
        pub quiet_scoped: u64,
    }
}

use uapi::LANDLOCK_CREATE_RULESET_VERSION;

/// The raw Landlock ABI version: `landlock_create_ruleset(NULL, 0,
/// LANDLOCK_CREATE_RULESET_VERSION)`.
///
/// Returns the integer the kernel reports, or the raw errno on failure
/// (`ENOSYS`: not built in; `EOPNOTSUPP`: built in but disabled at boot).
pub fn landlock_abi() -> Result<i32, i32> {
    // SAFETY: with a NULL attr pointer, size 0 and the VERSION flag, the
    // kernel reads no user memory and only returns an integer or -1/errno.
    let ret = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            std::ptr::null::<libc::c_void>(),
            0 as libc::size_t,
            LANDLOCK_CREATE_RULESET_VERSION,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error().raw_os_error().unwrap_or(0))
    } else {
        i32::try_from(ret).map_err(|_| libc::EOVERFLOW)
    }
}

/// Fields of `uname(2)` that doctor reports.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Uname {
    pub release: String,
    pub machine: String,
}

pub fn uname() -> io::Result<Uname> {
    let mut buf = std::mem::MaybeUninit::<libc::utsname>::uninit();
    // SAFETY: `buf` is a valid, writable `utsname`; uname fills it entirely
    // on success, and we only read it after checking the return value.
    let ret = unsafe { libc::uname(buf.as_mut_ptr()) };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: uname returned 0, so every field is initialised.
    let u = unsafe { buf.assume_init() };
    Ok(Uname {
        release: c_chars_to_string(&u.release),
        machine: c_chars_to_string(&u.machine),
    })
}

fn c_chars_to_string(chars: &[libc::c_char]) -> String {
    // utsname fields are NUL-terminated within their array; stop at the first
    // NUL (or the array end, defensively) without reading past the slice.
    let bytes: Vec<u8> = chars
        .iter()
        .take_while(|&&c| c != 0)
        .map(|&c| c as u8)
        .collect();
    String::from_utf8_lossy(&bytes).into_owned()
}

pub fn getuid() -> u32 {
    // SAFETY: getuid has no preconditions and cannot fail.
    unsafe { libc::getuid() }
}

pub fn getgid() -> u32 {
    // SAFETY: getgid has no preconditions and cannot fail.
    unsafe { libc::getgid() }
}

/// `unshare(2)` with the given `CLONE_*` flags.
pub fn unshare(flags: libc::c_int) -> io::Result<()> {
    // SAFETY: unshare takes only an integer. It changes this process's
    // namespaces; callers use it only in the short-lived doctor probe child.
    let ret = unsafe { libc::unshare(flags) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// `mount(2)`. `source`, `fstype` and `data` may be `None` (NULL).
pub fn mount(
    source: Option<&str>,
    target: &Path,
    fstype: Option<&str>,
    flags: libc::c_ulong,
    data: Option<&str>,
) -> io::Result<()> {
    let source = opt_cstring(source.map(OsStr::new))?;
    let target = cstring(target.as_os_str())?;
    let fstype = opt_cstring(fstype.map(OsStr::new))?;
    let data = opt_cstring(data.map(OsStr::new))?;
    // SAFETY: every pointer is either NULL or points to a NUL-terminated
    // CString that outlives the call; the kernel copies the strings.
    let ret = unsafe {
        libc::mount(
            opt_ptr(&source),
            target.as_ptr(),
            opt_ptr(&fstype),
            flags,
            opt_ptr(&data).cast::<libc::c_void>(),
        )
    };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

// --- processes, sockets and seccomp user notification (SPEC §6.7) --------

fn cvt(ret: libc::c_int) -> io::Result<libc::c_int> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

fn cvt_long(ret: libc::c_long) -> io::Result<libc::c_long> {
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(ret)
    }
}

/// Wraps a file descriptor that a syscall has just returned to us.
fn owned(fd: libc::c_long) -> io::Result<OwnedFd> {
    let fd = libc::c_int::try_from(fd).map_err(|_| io::Error::from_raw_os_error(libc::EBADF))?;
    // SAFETY: `fd` was just returned by the kernel as a new descriptor that
    // nothing else owns.
    Ok(unsafe { OwnedFd::from_raw_fd(fd) })
}

pub enum Forked {
    Child,
    Parent(libc::pid_t),
}

/// `fork(2)`. Call it only while the process is single-threaded (the doctor
/// probe child, and `ulai-run` before it starts any thread). In the child,
/// do only async-signal-safe work until `exec` or [`exit_now`].
pub fn fork() -> io::Result<Forked> {
    // SAFETY: fork has no memory-safety preconditions; the single-thread
    // requirement above keeps the child free of other threads' held locks.
    match unsafe { libc::fork() } {
        -1 => Err(io::Error::last_os_error()),
        0 => Ok(Forked::Child),
        pid => Ok(Forked::Parent(pid)),
    }
}

/// `_exit(2)`: ends the process at once, without running destructors or
/// flushing stdio (safe after `fork`).
pub fn exit_now(code: libc::c_int) -> ! {
    // SAFETY: _exit never returns and has no preconditions.
    unsafe { libc::_exit(code) }
}

/// `waitpid(2)`; returns the raw wait status.
pub fn waitpid(pid: libc::pid_t) -> io::Result<libc::c_int> {
    let mut status = 0;
    // SAFETY: `status` is a valid, writable c_int for the call's duration.
    cvt(unsafe { libc::waitpid(pid, &mut status, 0) })?;
    Ok(status)
}

/// `poll(2)` for readability of one fd; `Ok(false)` on timeout.
pub fn poll_readable(fd: BorrowedFd, timeout_ms: libc::c_int) -> io::Result<bool> {
    let mut p = libc::pollfd {
        fd: fd.as_raw_fd(),
        events: libc::POLLIN,
        revents: 0,
    };
    // SAFETY: `p` is one valid pollfd and the count is 1.
    let n = cvt(unsafe { libc::poll(&mut p, 1, timeout_ms) })?;
    Ok(n > 0)
}

/// `socketpair(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)`.
pub fn socketpair_stream() -> io::Result<(OwnedFd, OwnedFd)> {
    let mut fds = [-1; 2];
    // SAFETY: `fds` has room for the two descriptors the kernel writes.
    cvt(unsafe {
        libc::socketpair(
            libc::AF_UNIX,
            libc::SOCK_STREAM | libc::SOCK_CLOEXEC,
            0,
            fds.as_mut_ptr(),
        )
    })?;
    Ok((owned(fds[0].into())?, owned(fds[1].into())?))
}

/// `socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC)`.
pub fn unix_stream_socket() -> io::Result<OwnedFd> {
    // SAFETY: socket takes only integers.
    owned(
        cvt(unsafe { libc::socket(libc::AF_UNIX, libc::SOCK_STREAM | libc::SOCK_CLOEXEC, 0) })?
            .into(),
    )
}

/// `connect(2)` of an existing socket to a pathname `AF_UNIX` address.
pub fn connect_unix(sock: BorrowedFd, path: &[u8]) -> io::Result<()> {
    // SAFETY: an all-zero sockaddr_un is a valid value.
    let mut addr: libc::sockaddr_un = unsafe { std::mem::zeroed() };
    if path.is_empty() || path.len() >= addr.sun_path.len() || path.contains(&0) {
        return Err(io::Error::from_raw_os_error(libc::EINVAL));
    }
    addr.sun_family = libc::AF_UNIX as libc::sa_family_t;
    for (dst, &b) in addr.sun_path.iter_mut().zip(path) {
        *dst = b as libc::c_char;
    }
    let len = std::mem::size_of::<libc::sa_family_t>() + path.len() + 1;
    // SAFETY: `addr` is a valid sockaddr_un and `len` does not exceed it.
    cvt(unsafe {
        libc::connect(
            sock.as_raw_fd(),
            (&raw const addr).cast::<libc::sockaddr>(),
            len as libc::socklen_t,
        )
    })?;
    Ok(())
}

/// `getsockopt(SOL_SOCKET, opt)` for an integer option.
pub fn sockopt_int(sock: BorrowedFd, opt: libc::c_int) -> io::Result<libc::c_int> {
    let mut v: libc::c_int = 0;
    let mut len = std::mem::size_of::<libc::c_int>() as libc::socklen_t;
    // SAFETY: `v` and `len` are valid and writable; len matches v's size.
    cvt(unsafe {
        libc::getsockopt(
            sock.as_raw_fd(),
            libc::SOL_SOCKET,
            opt,
            (&raw mut v).cast::<libc::c_void>(),
            &mut len,
        )
    })?;
    Ok(v)
}

/// Sends one file descriptor over a connected `AF_UNIX` socket
/// (`SCM_RIGHTS`, with a one-byte payload).
pub fn send_fd(sock: BorrowedFd, fd: BorrowedFd) -> io::Result<()> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    // Room for one cmsghdr with one int, correctly aligned.
    let mut control = [0u64; 4];
    // SAFETY: an all-zero msghdr is valid; the pointers set below point to
    // buffers that live until after sendmsg returns, and the cmsg macros
    // stay inside `control` (CMSG_SPACE(4) <= 32 bytes).
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = libc::CMSG_SPACE(4) as _;
        let c = libc::CMSG_FIRSTHDR(&msg);
        (*c).cmsg_level = libc::SOL_SOCKET;
        (*c).cmsg_type = libc::SCM_RIGHTS;
        (*c).cmsg_len = libc::CMSG_LEN(4) as _;
        libc::CMSG_DATA(c)
            .cast::<libc::c_int>()
            .write_unaligned(fd.as_raw_fd());
        cvt_long(libc::sendmsg(sock.as_raw_fd(), &msg, libc::MSG_NOSIGNAL) as libc::c_long)?;
    }
    Ok(())
}

/// Receives one file descriptor sent with [`send_fd`].
pub fn recv_fd(sock: BorrowedFd) -> io::Result<OwnedFd> {
    let mut byte = [0u8; 1];
    let mut iov = libc::iovec {
        iov_base: byte.as_mut_ptr().cast(),
        iov_len: 1,
    };
    let mut control = [0u64; 4];
    // SAFETY: as in send_fd; after recvmsg, the header is checked before
    // its data is read, and the fd it carries is new and owned by us.
    unsafe {
        let mut msg: libc::msghdr = std::mem::zeroed();
        msg.msg_iov = &mut iov;
        msg.msg_iovlen = 1;
        msg.msg_control = control.as_mut_ptr().cast();
        msg.msg_controllen = std::mem::size_of_val(&control) as _;
        let n = cvt_long(
            libc::recvmsg(sock.as_raw_fd(), &mut msg, libc::MSG_CMSG_CLOEXEC) as libc::c_long,
        )?;
        let c = libc::CMSG_FIRSTHDR(&msg);
        if n != 1
            || c.is_null()
            || (*c).cmsg_level != libc::SOL_SOCKET
            || (*c).cmsg_type != libc::SCM_RIGHTS
            || (*c).cmsg_len as usize != libc::CMSG_LEN(4) as usize
        {
            return Err(io::Error::from_raw_os_error(libc::EPROTO));
        }
        owned(
            libc::CMSG_DATA(c)
                .cast::<libc::c_int>()
                .read_unaligned()
                .into(),
        )
    }
}

/// `prctl(PR_SET_NO_NEW_PRIVS, 1)`.
pub fn set_no_new_privs() -> io::Result<()> {
    // SAFETY: prctl with these integer arguments has no memory effects.
    cvt(unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) })?;
    Ok(())
}

/// One classic-BPF instruction of a seccomp filter.
pub type SockFilter = libc::sock_filter;

/// Installs a seccomp filter on the calling thread with
/// `SECCOMP_FILTER_FLAG_NEW_LISTENER` and returns the notification fd.
/// Needs `no_new_privs`. Irreversible for this process and its children.
pub fn seccomp_install_with_listener(filter: &[SockFilter]) -> io::Result<OwnedFd> {
    let prog = libc::sock_fprog {
        len: u16::try_from(filter.len()).map_err(|_| io::Error::from_raw_os_error(libc::EINVAL))?,
        filter: filter.as_ptr().cast_mut(),
    };
    // SAFETY: `prog` points to `filter`, which outlives the call; the kernel
    // copies the program.
    let fd = cvt_long(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_SET_MODE_FILTER,
            libc::SECCOMP_FILTER_FLAG_NEW_LISTENER,
            &raw const prog,
        )
    })?;
    owned(fd)
}

/// A seccomp user notification (`struct seccomp_notif`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Notification {
    pub id: u64,
    pub pid: u32,
    pub nr: i32,
    pub arch: u32,
    pub args: [u64; 6],
}

/// `SECCOMP_IOCTL_NOTIF_RECV`: blocks until a notification arrives. The
/// buffer is sized from `SECCOMP_GET_NOTIF_SIZES`, as the kernel requires.
pub fn notif_recv(listener: BorrowedFd) -> io::Result<Notification> {
    // SAFETY: an all-zero seccomp_notif_sizes is valid; the kernel fills it.
    let mut sizes: libc::seccomp_notif_sizes = unsafe { std::mem::zeroed() };
    // SAFETY: `sizes` is valid and writable.
    cvt_long(unsafe {
        libc::syscall(
            libc::SYS_seccomp,
            libc::SECCOMP_GET_NOTIF_SIZES,
            0,
            &raw mut sizes,
        )
    })?;
    let len = usize::from(sizes.seccomp_notif).max(std::mem::size_of::<libc::seccomp_notif>());
    // The kernel requires the buffer to be zeroed; u64s keep it aligned.
    let mut buf = vec![0u64; len.div_ceil(8)];
    // SAFETY: `buf` is zeroed, aligned and at least as large as the kernel's
    // struct seccomp_notif.
    cvt(unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_RECV as _,
            buf.as_mut_ptr(),
        )
    })?;
    // SAFETY: the kernel wrote a seccomp_notif at the start of `buf`.
    let n: libc::seccomp_notif = unsafe { buf.as_ptr().cast::<libc::seccomp_notif>().read() };
    Ok(Notification {
        id: n.id,
        pid: n.pid,
        nr: n.data.nr,
        arch: n.data.arch,
        args: n.data.args,
    })
}

/// `SECCOMP_IOCTL_NOTIF_ID_VALID`: whether the notifying thread is still
/// blocked in that very call. Check it after every read of the target's
/// memory, or the memory may belong to a different process (pid reuse).
pub fn notif_id_valid(listener: BorrowedFd, id: u64) -> bool {
    let mut id = id;
    // SAFETY: the ioctl reads one u64 from a valid pointer.
    unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ID_VALID as _,
            &mut id,
        ) == 0
    }
}

/// `SECCOMP_IOCTL_NOTIF_SEND`: answers a notification. The syscall returns
/// `val` if `error` is 0, or fails with `-error`. Never uses
/// `SECCOMP_USER_NOTIF_FLAG_CONTINUE` (SPEC §6.7).
pub fn notif_respond(listener: BorrowedFd, id: u64, val: i64, error: i32) -> io::Result<()> {
    let mut resp = libc::seccomp_notif_resp {
        id,
        val,
        error,
        flags: 0,
    };
    // SAFETY: `resp` is a valid seccomp_notif_resp for the call's duration.
    cvt(unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_SEND as _,
            &mut resp,
        )
    })?;
    Ok(())
}

/// `SECCOMP_IOCTL_NOTIF_ADDFD` with `SETFD` and without `SEND`: installs
/// `src` in the target as fd number `target_fd`, replacing what was there.
/// The caller still has to answer the notification.
pub fn notif_addfd_setfd(
    listener: BorrowedFd,
    id: u64,
    src: BorrowedFd,
    target_fd: u32,
) -> io::Result<i32> {
    let mut add = libc::seccomp_notif_addfd {
        id,
        flags: libc::SECCOMP_ADDFD_FLAG_SETFD as u32,
        srcfd: src.as_raw_fd() as u32,
        newfd: target_fd,
        newfd_flags: libc::O_CLOEXEC as u32,
    };
    // SAFETY: `add` is a valid seccomp_notif_addfd for the call's duration.
    cvt(unsafe {
        libc::ioctl(
            listener.as_raw_fd(),
            libc::SECCOMP_IOCTL_NOTIF_ADDFD as _,
            &mut add,
        )
    })
}

/// `open(path, O_PATH | O_CLOEXEC)`: a handle to the inode itself, which
/// works for sockets (a plain `open` of a socket fails with `ENXIO`).
///
/// Not done with `OpenOptions::custom_flags`: on musl, Rust's std masks
/// custom flags with `!O_ACCMODE`, and musl's `O_ACCMODE` includes `O_PATH`
/// (as `O_SEARCH`), so the flag is silently dropped (RESEARCH.md,
/// 2026-10-24).
pub fn open_path(path: &Path) -> io::Result<OwnedFd> {
    let path = cstring(path.as_os_str())?;
    // SAFETY: `path` is a NUL-terminated CString that outlives the call.
    owned(cvt(unsafe { libc::open(path.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) })?.into())
}

/// `pidfd_open(2)`.
pub fn pidfd_open(pid: libc::pid_t) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_open takes only integers.
    owned(cvt_long(unsafe {
        libc::syscall(libc::SYS_pidfd_open, pid, 0)
    })?)
}

/// `pidfd_getfd(2)`: a duplicate of the target's fd `target_fd`. Needs
/// ptrace-attach permission over the target (Yama).
pub fn pidfd_getfd(pidfd: BorrowedFd, target_fd: libc::c_int) -> io::Result<OwnedFd> {
    // SAFETY: pidfd_getfd takes only integers.
    owned(cvt_long(unsafe {
        libc::syscall(libc::SYS_pidfd_getfd, pidfd.as_raw_fd(), target_fd, 0)
    })?)
}

fn cstring(s: &OsStr) -> io::Result<CString> {
    CString::new(s.as_bytes()).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn opt_cstring(s: Option<&OsStr>) -> io::Result<Option<CString>> {
    s.map(cstring).transpose()
}

fn opt_ptr(s: &Option<CString>) -> *const libc::c_char {
    s.as_deref().map_or(std::ptr::null(), CStr::as_ptr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn c_chars_stop_at_nul() {
        let raw: Vec<libc::c_char> = b"7.2.9\0junk".iter().map(|&b| b as libc::c_char).collect();
        assert_eq!(c_chars_to_string(&raw), "7.2.9");
    }

    #[test]
    fn c_chars_without_nul_use_whole_slice() {
        let raw: Vec<libc::c_char> = b"x86_64".iter().map(|&b| b as libc::c_char).collect();
        assert_eq!(c_chars_to_string(&raw), "x86_64");
    }

    /// Compares every constant in [`uapi`] with the installed kernel header.
    /// Constants an older header does not define yet are skipped and named.
    #[test]
    fn uapi_matches_header() {
        let Ok(header) = std::fs::read_to_string("/usr/include/linux/landlock.h") else {
            eprintln!("skipped: /usr/include/linux/landlock.h not installed");
            return;
        };
        let defined = |name: &str| -> Option<u64> {
            let line = header
                .lines()
                .find(|l| l.split_whitespace().take(2).eq(["#define", name]))?;
            let expr = line.split_whitespace().skip(2).collect::<String>();
            let inner = expr.trim_start_matches('(').trim_end_matches(')');
            let (one, shift) = inner.split_once("<<")?;
            assert!(one.starts_with('1'), "unexpected form for {name}: {line}");
            Some(1u64 << shift.parse::<u32>().expect("shift"))
        };
        for (name, value) in [
            (
                "LANDLOCK_CREATE_RULESET_VERSION",
                u64::from(uapi::LANDLOCK_CREATE_RULESET_VERSION),
            ),
            (
                "LANDLOCK_ACCESS_NET_BIND_UDP",
                uapi::LANDLOCK_ACCESS_NET_BIND_UDP,
            ),
            (
                "LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP",
                uapi::LANDLOCK_ACCESS_NET_CONNECT_SEND_UDP,
            ),
            (
                "LANDLOCK_ADD_RULE_QUIET",
                u64::from(uapi::LANDLOCK_ADD_RULE_QUIET),
            ),
        ] {
            match defined(name) {
                Some(h) => assert_eq!(h, value, "{name} differs from the header"),
                None => eprintln!("skipped: {name} not in this header (older kernel headers)"),
            }
        }
    }

    #[test]
    fn ruleset_attr_v10_layout() {
        // Six __u64 fields, no padding.
        assert_eq!(std::mem::size_of::<uapi::RulesetAttrV10>(), 48);
        assert_eq!(std::mem::align_of::<uapi::RulesetAttrV10>(), 8);
    }

    /// Talks to the real kernel; run locally with `cargo test -- --ignored`.
    #[test]
    #[ignore = "depends on the running kernel"]
    fn real_landlock_abi_is_sane() {
        match landlock_abi() {
            Ok(abi) => assert!(abi >= 1, "ABI {abi}"),
            Err(e) => assert!(e == libc::ENOSYS || e == libc::EOPNOTSUPP, "errno {e}"),
        }
    }

    /// Regression: `OpenOptions::custom_flags(O_PATH)` silently loses the
    /// flag on musl, and opening a socket without it fails with ENXIO. Run
    /// the tests on the musl target too (CI's musl job does, for this
    /// crate's library tests).
    #[test]
    fn open_path_opens_a_socket() {
        use std::os::unix::fs::FileTypeExt;
        let dir = tempfile::tempdir().unwrap();
        let sock = dir.path().join("s.sock");
        let _l = std::os::unix::net::UnixListener::bind(&sock).unwrap();
        let fd = open_path(&sock).unwrap();
        let meta = std::fs::File::from(fd).metadata().unwrap();
        assert!(meta.file_type().is_socket());
    }
}
