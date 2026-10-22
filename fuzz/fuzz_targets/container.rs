// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The AppImage container (ELF header, sections, image offset) and digest.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ulai_core::appimage::Container;

fuzz_target!(|data: &[u8]| {
    // Container reads from a File (one open handle, SPEC §3.5); a tmpfs
    // file keeps that path realistic.
    let path = std::env::temp_dir().join(format!("ulai-fuzz-container-{}", std::process::id()));
    std::fs::write(&path, data).unwrap();
    if let Ok(c) = Container::open(&path) {
        let _ = c.signature_digest_hex();
        let _ = c.section_bytes(&c.sections.signature);
        let _ = c.section_bytes(&c.sections.update_info);
    }
});
