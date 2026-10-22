// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OpenPGP: a fuzzed signature against a fixed key, and a fuzzed key
//! against a fixed signature (GnuPG-made fixtures).
#![no_main]

use std::time::SystemTime;

use libfuzzer_sys::fuzz_target;
use ulai_core::signature::verify_detached;

const KEY: &[u8] = include_bytes!("../../tests/fixtures/openpgp/rsa3072-binary-sha256.key.asc");
const SIG: &[u8] = include_bytes!("../../tests/fixtures/openpgp/rsa3072-binary-sha256.sig.asc");
const MSG: &[u8] = include_bytes!("../../tests/fixtures/openpgp/msg");

fuzz_target!(|data: &[u8]| {
    let now = SystemTime::UNIX_EPOCH + std::time::Duration::from_secs(1_792_627_200);
    let _ = verify_detached(KEY, data, MSG, now);
    let _ = verify_detached(data, SIG, MSG, now);
});
