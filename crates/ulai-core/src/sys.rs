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

/// `LANDLOCK_CREATE_RULESET_VERSION` from `<linux/landlock.h>`. Not exported
/// by the `libc` crate.
const LANDLOCK_CREATE_RULESET_VERSION: libc::c_uint = 1 << 0;

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
