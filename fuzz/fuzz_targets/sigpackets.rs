// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The signature packet splitter (SPEC §3.2), for files and sections. When
//! it accepts input, every packet it returns must be exactly one complete
//! signature packet with a definite length, and there must be 1 to 16.
#![no_main]

use libfuzzer_sys::fuzz_target;
use pgp::composed::{Deserializable as _, DetachedSignature};
use ulai_core::signature::{MAX_SIGNATURES, SigSource, packet_tags, split_signature_packets};

fuzz_target!(|data: &[u8]| {
    for source in [SigSource::File, SigSource::Embedded] {
        let Ok(packets) = split_signature_packets(data, source) else {
            continue;
        };
        assert!((1..=MAX_SIGNATURES).contains(&packets.len()));
        for p in &packets {
            assert_eq!(packet_tags(p).as_deref(), Some(&[2u8][..]), "{p:02x?}");
            // Partial (new format, 224..=254) or indeterminate (old format,
            // length type 3) lengths must never get through.
            if p[0] & 0x40 != 0 {
                assert!(!(224..=254).contains(&p[1]), "{p:02x?}");
            } else {
                assert_ne!(p[0] & 3, 3, "{p:02x?}");
            }
            let _ = DetachedSignature::from_bytes(p.as_slice());
        }
    }
});
