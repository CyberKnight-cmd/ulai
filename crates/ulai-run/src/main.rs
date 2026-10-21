// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai-run`: the ULAI launcher (SPEC §10).
//!
//! Not implemented before milestone M2. Until then it refuses to launch
//! anything, so no app can run without the sandbox (fail closed).

#![forbid(unsafe_code)]

use std::process::ExitCode;

/// `EX_USAGE`-style code for "launcher not available in this build".
const EXIT_NOT_IMPLEMENTED: u8 = 64;

fn main() -> ExitCode {
    eprintln!("ulai-run: not implemented yet (milestone M2); refusing to launch");
    ExitCode::from(EXIT_NOT_IMPLEMENTED)
}
