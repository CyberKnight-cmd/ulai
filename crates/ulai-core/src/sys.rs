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
}
