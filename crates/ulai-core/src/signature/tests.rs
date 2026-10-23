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

/// 2027-01-01: after every fixture signature was made (GnuPG ones at
/// 2020-01-01 + n days, Sequoia and RFC ones in 2022–2026).
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_798_761_600)
}

/// Verifies through the embedded scheme (`SigSource::Embedded`), where text
/// signatures count. The GnuPG fixtures' `msg` is a 64-digit hex digest,
/// like the data the embedded scheme signs.
pub(super) fn embedded(
    key: &[u8],
    sig: &[u8],
    data: &[u8],
    now: SystemTime,
) -> Result<Accepted, Rejection> {
    verify_signatures(key, sig, SigSource::Embedded, &mut &data[..], now)
        .unwrap()
        .result
}

fn run(case: &str) -> Result<Accepted, Rejection> {
    embedded(
        &read(&format!("{case}.key.asc")),
        &read(&format!("{case}.sig.asc")),
        &read("msg"),
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
    assert_eq!(n, 19, "all cases ran");
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
fn nul_padding_after_armor_is_accepted_only_in_sections() {
    // Embedded sections are NUL-padded to their full size.
    let mut key = read("ed25519-text-sha512.key.asc");
    key.extend_from_slice(&[0; 4096]);
    let mut sig = read("ed25519-text-sha512.sig.asc");
    sig.extend_from_slice(&[0; 512]);
    let msg = read("msg");
    verify_signatures(&key, &sig, SigSource::Embedded, &mut msg.as_slice(), now())
        .unwrap()
        .result
        .unwrap();
    // In a signature file, only whitespace may follow the armor.
    let r = verify_detached(&key, &sig, msg.as_slice(), now());
    assert!(
        matches!(&r, Err(Rejection::Corrupt(m)) if m.contains("whitespace")),
        "{r:?}"
    );
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
    ];
    for (what, k, s) in cases {
        let r = verify_detached(&k, &s, msg.as_slice(), now());
        assert!(matches!(r, Err(Rejection::Corrupt(_))), "{what}: {r:?}");
    }
    // The size limit is ULAI's policy, not damage.
    let r = verify_detached(
        &vec![b'A'; MAX_ARMOR_BYTES + 1],
        &sig,
        msg.as_slice(),
        now(),
    );
    assert!(
        matches!(&r, Err(Rejection::Unsupported(m)) if m.contains("64 KiB")),
        "{r:?}"
    );
}

/// A v4 public-subkey packet (tag 14) for ECDSA on a curve no one knows:
/// OID 1.3.6.1.4.1.37210.99 (the arc the OpenPGP interoperability test
/// suite uses for mock keys), then bytes that are not an MPI.
pub(super) fn unknown_curve_subkey_packet() -> Vec<u8> {
    let oid = [0x2b, 0x06, 0x01, 0x04, 0x01, 0x82, 0xa2, 0x5a, 0x63];
    let mut body = vec![4, 0x5e, 0x0b, 0xe1, 0x00, 19, oid.len() as u8];
    body.extend_from_slice(&oid);
    body.extend_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let mut p = vec![0xC0 | 14, body.len() as u8];
    p.extend(body);
    p
}

/// rPGP 0.21 cannot parse a certificate with such a subkey (RFC 9580 lets
/// implementations ignore subkeys they do not understand). The framing is
/// intact, so ULAI reports it as unsupported (exit 5), not as corrupt or
/// invalid. See the upstream issue linked from docs/RESEARCH.md.
#[test]
fn certificate_rpgp_cannot_read_is_unsupported() {
    let mut key = read("rsa3072-binary-sha256.key.gpg");
    key.extend(unknown_curve_subkey_packet());
    let r = verify_detached(
        &key,
        &read("rsa3072-binary-sha256.sig.gpg"),
        read("msg").as_slice(),
        now(),
    );
    assert!(
        matches!(&r, Err(Rejection::Unsupported(m)) if m.contains("rPGP")),
        "{r:?}"
    );
    // The same bytes with the last one cut off: the framing is broken.
    key.pop();
    let r = verify_detached(
        &key,
        &read("rsa3072-binary-sha256.sig.gpg"),
        read("msg").as_slice(),
        now(),
    );
    assert!(matches!(r, Err(Rejection::Corrupt(_))), "{r:?}");
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

/// Version byte of the first packet of a binary key or signature.
fn header_len(b: &[u8]) -> usize {
    if b[0] & 0x40 != 0 {
        if b[1] < 192 {
            2
        } else if b[1] < 224 {
            3
        } else {
            6
        }
    } else {
        [2, 3, 5][(b[0] & 3) as usize]
    }
}

#[test]
fn v5_keys_and_signatures_are_unsupported() {
    // No independent source of LibrePGP v5 material exists in our toolchain
    // (GnuPG 2.4.9 makes v4); patch the version byte of GnuPG-made packets.
    // The policy decision happens before any cryptography.
    let msg = read("msg");
    let mut k = read("rsa3072-binary-sha256.key.gpg");
    let i = header_len(&k);
    assert_eq!(k[i], 4);
    k[i] = 5;
    let r = verify_detached(
        &k,
        &read("rsa3072-binary-sha256.sig.asc"),
        msg.as_slice(),
        now(),
    );
    assert!(
        matches!(&r, Err(Rejection::Unsupported(m)) if m.contains("v5")),
        "{r:?}"
    );
    let mut s = read("rsa3072-binary-sha256.sig.gpg");
    let i = header_len(&s);
    assert_eq!(s[i], 4);
    s[i] = 5;
    let r = verify_detached(
        &read("rsa3072-binary-sha256.key.asc"),
        &s,
        msg.as_slice(),
        now(),
    );
    assert!(
        matches!(&r, Err(Rejection::Unsupported(m)) if m.contains("V5")),
        "{r:?}"
    );
}

fn rfc(name: &str) -> Vec<u8> {
    read(&format!("rfc9580/{name}"))
}

/// RFC 9580 Appendix A.3 (v6 certificate) and A.6 (v6 cleartext-signed
/// message): an independent v6 vector. The signed text is the dash-unescaped
/// cleartext.
#[test]
fn rfc9580_v6_vector() {
    // A text signature: it counts only through the embedded path.
    let a = embedded(
        &rfc("a3-v6-cert.key.asc"),
        &rfc("a6-v6-cleartext.sig.asc"),
        &rfc("a6-cleartext.txt"),
        now(),
    )
    .unwrap();
    assert_eq!(a.signer.key_version, 6);
    assert_eq!(a.signer.algorithm, "Ed25519");
    assert_eq!(a.signer.signature_type, "text");
    // The fingerprint printed in RFC 9580, Appendix A.3.
    assert_eq!(
        a.signer.primary_fingerprint,
        "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9"
    );
    let mut tampered = rfc("a6-cleartext.txt");
    tampered[0] ^= 1;
    assert!(
        embedded(
            &rfc("a3-v6-cert.key.asc"),
            &rfc("a6-v6-cleartext.sig.asc"),
            &tampered,
            now()
        )
        .is_err()
    );
}

/// RFC 9580 Appendix A.1 is a bare v4 key packet without a self-signature:
/// ULAI never trusts such a key, even though A.2 is a correct signature.
#[test]
fn rfc9580_bare_v4_key_is_invalid() {
    let r = verify_detached(
        &rfc("a1-v4-ed25519legacy.key.asc"),
        &rfc("a2-v4-ed25519legacy.sig.asc"),
        rfc("a2-msg.txt").as_slice(),
        now(),
    );
    assert_eq!(
        r,
        Err(Rejection::Invalid("the key has no self-signature".into()))
    );
}

/// A v6 key and signature made by Sequoia (sq 1.3.1): certification-only
/// primary key, Ed25519 signing subkey with a v6 back-signature.
#[test]
fn sequoia_v6_subkey_signature() {
    let a = verify_detached(
        &read("sequoia/sq-v6.key.asc"),
        &read("sequoia/sq-v6.sig.asc"),
        read("sequoia/msg").as_slice(),
        now(),
    )
    .unwrap();
    assert_eq!((a.signer.key_version, a.signer.signed_by_subkey), (6, true));
    assert_eq!(a.signer.primary_fingerprint.len(), 64);
    assert_eq!(a.signer.signing_fingerprint.len(), 64);
    assert_ne!(a.signer.primary_fingerprint, a.signer.signing_fingerprint);
}
