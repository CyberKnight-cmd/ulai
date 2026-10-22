// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! ULAI core library.
//!
//! `unsafe` is denied crate-wide; the single exception is [`sys`], which wraps
//! the raw syscalls nothing safe in the dependency set covers.

#![deny(unsafe_code)]

pub mod appimage;
pub mod host;
mod sys;

/// Landlock uapi items missing from `libc` and the `landlock` crate.
pub use sys::uapi as landlock_uapi;

pub mod doctor;
#[cfg(any(test, feature = "test-support"))]
pub mod testing;
#[cfg(any(test, feature = "test-support"))]
pub mod testing_appimage;
