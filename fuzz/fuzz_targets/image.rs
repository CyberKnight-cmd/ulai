// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! SquashFS images: open, list, resolve and read every entry, with small
//! caps so that a slow input is a bug, not a timeout.
#![no_main]

use libfuzzer_sys::fuzz_target;
use ulai_core::appimage::Container;
use ulai_core::imagefs::{EntryKind, ImageFs, Limits};
use ulai_core::testing_appimage::Builder;

fuzz_target!(|data: &[u8]| {
    let mut fs = b"hsqs".to_vec();
    fs.extend_from_slice(data.get(4..).unwrap_or_default());
    let bytes = Builder::default().fs(&fs).build();
    let path = std::env::temp_dir().join(format!("ulai-fuzz-image-{}", std::process::id()));
    std::fs::write(&path, &bytes).unwrap();
    let Ok(c) = Container::open(&path) else { return };
    let limits = Limits { max_entries: 10_000, max_total_bytes: 64 << 20, ..Limits::default() };
    let Ok(img) = ImageFs::open(&c, limits) else { return };
    let entries: Vec<_> = img.entries().cloned().collect();
    for e in entries {
        let _ = img.resolve(&e.path);
        if matches!(e.kind, EntryKind::File { .. }) {
            let _ = img.read_head(&e.path, 16);
            let _ = img.read(&e.path, 1 << 20);
        }
    }
});
