// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Desktop entries and icon type detection.
#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let _ = ulai_core::appdir::parse_desktop_entry(&String::from_utf8_lossy(data));
    let _ = ulai_core::appdir::icon_type(data);
});
