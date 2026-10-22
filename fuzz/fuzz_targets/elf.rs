// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Bundled ELF files: soname, needed, RPATH and symbol-version analysis.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ulai_core::elfinfo::analyse(data);
});
