// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The ULAI manifest: duplicate-key check, typed parse and validation.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ulai_core::manifest;

fuzz_target!(|data: &[u8]| {
    if let Ok(m) = manifest::parse(data) {
        let _ = manifest::validate(&m);
    }
});
