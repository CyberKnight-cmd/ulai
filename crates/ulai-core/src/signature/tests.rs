// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Tests against keys and signatures made by GnuPG, not by rPGP
//! (`tests/fixtures/openpgp/make.sh`).

use std::path::PathBuf;

use super::*;

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/openpgp")
}

fn read(name: &str) -> Vec<u8> {
    std::fs::read(fixtures().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// 2026-10-22, well after every fixture key was made (2020-01-01).
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_792_627_200)
}

fn run(case: &str) -> Result<Accepted, Rejection> {
    verify_detached(
        &read(&format!("{case}.key.asc")),
        &read(&format!("{case}.sig.asc")),
        read("msg").as_slice(),
        now(),
    )
}

#[test]
fn every_gnupg_case_has_the_expected_outcome() {
    let cases = String::from_utf8(read("cases.tsv")).unwrap();
    let mut n = 0;
    for line in cases.lines() {
        let [case, expected, reason]: [&str; 3] = line
            .split('\t')
            .collect::<Vec<_>>()
            .try_into()
            .expect("3 columns");
        let got = run(case);
        match (expected, &got) {
            ("valid", Ok(a)) => assert!(a.warnings.is_empty(), "{case}: {:?}", a.warnings),
            ("valid+warning", Ok(a)) => assert!(
                a.warnings.iter().any(|w| w.contains(reason)),
                "{case}: warnings {:?}",
                a.warnings
            ),
            ("invalid", Err(Rejection::Invalid(m)))
            | ("unsupported", Err(Rejection::Unsupported(m)))
            | ("corrupt", Err(Rejection::Corrupt(m))) => {
                assert!(m.contains(reason), "{case}: reason {m:?} lacks {reason:?}")
            }
            _ => panic!("{case}: expected {expected}, got {got:?}"),
        }
        n += 1;
    }
    assert_eq!(n, 15, "all cases ran");
}

#[test]
fn valid_result_reports_full_fingerprints_and_shape() {
    let a = run("rsa3072-text-sha512").unwrap();
    let s = &a.signer;
    assert_eq!(s.primary_fingerprint.len(), 40);
    assert_eq!(s.primary_fingerprint, s.primary_fingerprint.to_uppercase());
    assert_eq!(s.primary_fingerprint, s.signing_fingerprint);
    assert!(!s.signed_by_subkey);
    assert_eq!((s.algorithm.as_str(), s.rsa_bits), ("RSA", Some(3072)));
    assert_eq!((s.signature_type, s.hash), ("text", "SHA-512"));
    assert_eq!(s.key_version, 4);
    assert_eq!(s.user_ids, ["rsa3072 <rsa3072@fixtures.ulai.invalid>"]);

    let b = run("rsa3072-binary-sha256").unwrap();
    assert_eq!(
        (b.signer.signature_type, b.signer.hash),
        ("binary", "SHA-256")
    );

    let e = run("ed25519-text-sha512").unwrap();
    assert_eq!(
        (e.signer.algorithm.as_str(), e.signer.rsa_bits),
        ("Ed25519 (legacy EdDSA)", None)
    );
}

#[test]
fn subkey_signature_reports_both_fingerprints() {
    let a = run("subkey-signs").unwrap();
    assert!(a.signer.signed_by_subkey);
    assert_ne!(a.signer.primary_fingerprint, a.signer.signing_fingerprint);
    assert_eq!(a.signer.signing_fingerprint.len(), 40);
}

#[test]
fn tampered_data_is_invalid() {
    let mut msg = read("msg");
    msg[0] ^= 1;
    let r = verify_detached(
        &read("rsa3072-binary-sha256.key.asc"),
        &read("rsa3072-binary-sha256.sig.asc"),
        msg.as_slice(),
        now(),
    );
    assert_eq!(
        r,
        Err(Rejection::Invalid(
            "the signature does not match the signed data".into()
        ))
    );
}

#[test]
fn trailing_newline_is_invalid() {
    let mut msg = read("msg");
    msg.push(b'\n');
    let r = verify_detached(
        &read("rsa3072-binary-sha256.key.asc"),
        &read("rsa3072-binary-sha256.sig.asc"),
        msg.as_slice(),
        now(),
    );
    assert!(matches!(r, Err(Rejection::Invalid(_))), "{r:?}");
}

#[test]
fn nul_padding_after_armor_is_accepted() {
    // Embedded sections are NUL-padded to their full size.
    let mut key = read("ed25519-text-sha512.key.asc");
    key.extend_from_slice(&[0; 4096]);
    let mut sig = read("ed25519-text-sha512.sig.asc");
    sig.extend_from_slice(&[0; 512]);
    verify_detached(&key, &sig, read("msg").as_slice(), now()).unwrap();
}

#[test]
fn garbage_inputs_are_corrupt_not_panics() {
    let key = read("ed25519-text-sha512.key.asc");
    let sig = read("ed25519-text-sha512.sig.asc");
    let msg = read("msg");
    let mut nul_inside = sig.clone();
    nul_inside[40] = 0;
    let cases: Vec<(&str, Vec<u8>, Vec<u8>)> = vec![
        ("empty key", vec![], sig.clone()),
        ("empty signature", key.clone(), vec![]),
        ("not armor", b"hello".to_vec(), sig.clone()),
        ("key where signature expected", key.clone(), key.clone()),
        ("NUL inside armor", key.clone(), nul_inside),
        ("not UTF-8", vec![0xff, 0xfe, 0x41], sig.clone()),
        ("oversize", vec![b'A'; MAX_ARMOR_BYTES + 1], sig.clone()),
    ];
    for (what, k, s) in cases {
        let r = verify_detached(&k, &s, msg.as_slice(), now());
        assert!(matches!(r, Err(Rejection::Corrupt(_))), "{what}: {r:?}");
    }
}

#[test]
fn truncated_signature_is_corrupt() {
    let sig = read("rsa3072-binary-sha256.sig.asc");
    let cut = &sig[..sig.len() / 2];
    let r = verify_detached(
        &read("rsa3072-binary-sha256.key.asc"),
        cut,
        read("msg").as_slice(),
        now(),
    );
    assert!(matches!(r, Err(Rejection::Corrupt(_))), "{r:?}");
}

#[test]
fn binary_key_and_signature_are_accepted() {
    let msg = read("msg");
    for (k, s) in [
        (
            "rsa3072-binary-sha256.key.gpg",
            "rsa3072-binary-sha256.sig.gpg",
        ),
        (
            "rsa3072-binary-sha256.key.asc",
            "rsa3072-binary-sha256.sig.gpg",
        ),
        (
            "rsa3072-binary-sha256.key.gpg",
            "rsa3072-binary-sha256.sig.asc",
        ),
    ] {
        verify_detached(&read(k), &read(s), msg.as_slice(), now())
            .unwrap_or_else(|e| panic!("{k} + {s}: {e}"));
    }
}
