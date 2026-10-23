// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! What may be in a signature file or section, and how several signatures
//! are judged (SPEC §3.2). Built from the GnuPG fixtures: the `rsa3072-*`,
//! `sha1-data` and `crit-notation-data` cases share one key.

use std::path::PathBuf;

use super::packets::walk;
use super::*;

fn read(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openpgp")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{name}: {e}"))
}

/// 2027-01-01, after every fixture was made.
fn now() -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(1_798_761_600)
}

/// The binary packets of an armored fixture.
fn bin(name: &str) -> Vec<u8> {
    let mut out = Vec::new();
    pgp::armor::Dearmor::new(read(name).as_slice())
        .read_to_end(&mut out)
        .unwrap();
    out
}

const KEY: &str = "rsa3072-binary-sha256.key.asc";
/// Valid, by KEY.
const GOOD: &str = "rsa3072-binary-sha256.sig.asc";
/// By KEY, but SHA-1: fails policy.
const SHA1: &str = "sha1-data.sig.asc";
/// By KEY, but carries a critical notation: invalid.
const CRIT: &str = "crit-notation-data.sig.asc";
/// Valid signature over the same message, by another key.
const OTHER: &str = "ed25519-text-sha512.sig.asc";

fn run(sig: &[u8], source: SigSource) -> Verification {
    let msg = read("msg");
    verify_signatures(&read(KEY), sig, source, &mut msg.as_slice(), now()).unwrap()
}

fn statuses(v: &Verification) -> Vec<SigStatus> {
    v.signatures.iter().map(|s| s.status).collect()
}

fn packet(tag: u8, body: &[u8]) -> Vec<u8> {
    let mut p = vec![0xC0 | tag, body.len() as u8];
    p.extend_from_slice(body);
    p
}

#[test]
fn valid_signature_after_one_by_an_unknown_key() {
    let v = run(&[bin(OTHER), bin(GOOD)].concat(), SigSource::File);
    let a = v.result.as_ref().unwrap();
    assert!(a.warnings.is_empty(), "{:?}", a.warnings);
    assert_eq!(statuses(&v), [SigStatus::UnknownKey, SigStatus::Valid]);
    // The unknown signer is reported by the fingerprint it claims.
    assert_eq!(v.signatures[0].fingerprint.as_ref().unwrap().len(), 40);
    assert_eq!(
        v.signatures[0].algorithm.as_deref(),
        Some("Ed25519 (legacy EdDSA)")
    );
    assert_eq!(
        v.signatures[1].fingerprint.as_deref(),
        Some(a.signer.signing_fingerprint.as_str())
    );
    // Order does not matter.
    let w = run(&[bin(GOOD), bin(OTHER)].concat(), SigSource::File);
    assert_eq!(statuses(&w), [SigStatus::Valid, SigStatus::UnknownKey]);
    assert!(w.result.is_ok());
}

#[test]
fn one_valid_and_one_failing_signature_by_the_same_key_is_valid_with_a_warning() {
    for (bad, status) in [(CRIT, SigStatus::Invalid), (SHA1, SigStatus::Unsupported)] {
        for sig in [
            [bin(bad), bin(GOOD)].concat(),
            [bin(GOOD), bin(bad)].concat(),
        ] {
            let v = run(&sig, SigSource::File);
            let a = v.result.as_ref().unwrap_or_else(|e| panic!("{bad}: {e}"));
            assert_eq!(
                a.warnings,
                ["1 other signature by the same key did not verify"],
                "{bad}"
            );
            assert!(statuses(&v).contains(&status), "{bad}: {:?}", v.signatures);
        }
    }
}

#[test]
fn only_failing_signatures_report_the_worst() {
    // Invalid outranks unsupported, whatever the order.
    for sig in [
        [bin(SHA1), bin(CRIT)].concat(),
        [bin(CRIT), bin(SHA1)].concat(),
    ] {
        let v = run(&sig, SigSource::File);
        assert!(
            matches!(&v.result, Err(Rejection::Invalid(m)) if m.contains("critical notation")),
            "{:?}",
            v.result
        );
    }
    let v = run(&bin(OTHER), SigSource::File);
    assert_eq!(
        v.result,
        Err(Rejection::Invalid(
            "the signature was made by a key that is not in the supplied key".into()
        ))
    );
}

#[test]
fn sixteen_signatures_are_allowed_seventeen_are_corrupt() {
    let v = run(&bin(GOOD).repeat(16), SigSource::File);
    assert!(v.result.is_ok());
    assert_eq!(v.signatures.len(), 16);
    let v = run(&bin(GOOD).repeat(17), SigSource::File);
    assert!(
        matches!(&v.result, Err(Rejection::Corrupt(m)) if m.contains("at most 16")),
        "{:?}",
        v.result
    );
}

#[test]
fn trailing_garbage_is_corrupt() {
    // Binary file.
    let mut b = bin(GOOD);
    b.extend_from_slice(b"junk");
    assert!(matches!(
        run(&b, SigSource::File).result,
        Err(Rejection::Corrupt(_))
    ));
    // A byte that looks like a header, with a length past the end.
    let mut b = bin(GOOD);
    b.extend_from_slice(&[0xC2, 0x40]);
    assert!(matches!(
        run(&b, SigSource::File).result,
        Err(Rejection::Corrupt(_))
    ));
    // Binary file with trailing zeros: only a section may be zero-padded.
    let mut b = bin(GOOD);
    b.extend_from_slice(&[0; 8]);
    assert!(matches!(
        run(&b, SigSource::File).result,
        Err(Rejection::Corrupt(_))
    ));
    assert!(run(&b, SigSource::Embedded).result.is_ok());
    // Armored file: whitespace after the footer is fine, anything else not.
    let mut a = read(GOOD);
    a.extend_from_slice(b"\n  \r\n\t");
    assert!(run(&a, SigSource::File).result.is_ok());
    let mut a = read(GOOD);
    a.extend_from_slice(b"junk\n");
    let r = run(&a, SigSource::File).result;
    assert!(
        matches!(&r, Err(Rejection::Corrupt(m)) if m.contains("whitespace")),
        "{r:?}"
    );
    // A second armor block is not whitespace either.
    let r = run(&[read(GOOD), read(GOOD)].concat(), SigSource::File).result;
    assert!(matches!(r, Err(Rejection::Corrupt(_))), "{r:?}");
}

#[test]
fn non_zero_bytes_after_the_packet_inside_the_section_are_corrupt() {
    // Binary content in .sha256_sig.
    let mut b = bin(GOOD);
    b.extend_from_slice(&[0; 100]);
    b[bin(GOOD).len() + 50] = 1;
    let r = run(&b, SigSource::Embedded).result;
    assert!(
        matches!(&r, Err(Rejection::Corrupt(m)) if m.contains("zero bytes")),
        "{r:?}"
    );
    // Armored content, as appimagetool writes it.
    let mut a = read(GOOD);
    a.extend_from_slice(&[0; 100]);
    assert!(run(&a, SigSource::Embedded).result.is_ok());
    a[read(GOOD).len() + 50] = b'x';
    let r = run(&a, SigSource::Embedded).result;
    assert!(
        matches!(&r, Err(Rejection::Corrupt(m)) if m.contains("zero bytes")),
        "{r:?}"
    );
    // go-appimage writes no newline after the footer.
    let mut g = read(GOOD);
    while g.last() == Some(&b'\n') {
        g.pop();
    }
    g.extend_from_slice(&[0; 10]);
    assert!(run(&g, SigSource::Embedded).result.is_ok());
}

/// The positive self-certification (0x13) from the key itself.
fn certification() -> Vec<u8> {
    let key = bin(KEY);
    let (packets, _) = walk(&key).unwrap();
    let p = packets.iter().find(|p| p.tag == 2).unwrap();
    key[p.start..p.end].to_vec()
}

#[test]
fn a_certification_signature_never_counts() {
    let v = run(&certification(), SigSource::File);
    assert_eq!(statuses(&v), [SigStatus::Ignored]);
    assert_eq!(v.signatures[0].signature_type.as_deref(), Some("0x13"));
    assert_eq!(
        v.signatures[0].reason.as_deref(),
        Some("ignored: not a document signature")
    );
    assert!(
        matches!(&v.result, Err(Rejection::Unsupported(m)) if m.contains("no document signature")),
        "{:?}",
        v.result
    );
    let v = run(&[certification(), bin(GOOD)].concat(), SigSource::File);
    assert!(v.result.is_ok());
    assert_eq!(statuses(&v), [SigStatus::Ignored, SigStatus::Valid]);
}

#[test]
fn only_signature_marker_and_padding_packets_are_allowed() {
    let good = bin(GOOD);
    // Marker and padding, before and after: fine.
    let sig = [packet(10, b"PGP"), good.clone(), packet(21, &[0x55; 16])].concat();
    let v = run(&sig, SigSource::File);
    assert!(v.result.as_ref().unwrap().warnings.is_empty());
    // Unknown non-critical types are skipped, with a warning.
    let a = run(
        &[good.clone(), packet(40, &[1, 2, 3])].concat(),
        SigSource::File,
    )
    .result
    .unwrap();
    assert_eq!(
        a.warnings,
        ["1 packet of unknown type next to the signature ignored"]
    );
    // Anything else, before or after, is corrupt.
    for (tag, body, what) in [
        (11u8, &b"b\0\0\0\0\0x"[..], "literal data"),
        (8, &[0, 1, 2][..], "compressed data"),
        (6, &[4, 0, 0, 0, 0][..], "public key"),
        (38, &[1][..], "unassigned critical"),
    ] {
        for sig in [
            [good.clone(), packet(tag, body)].concat(),
            [packet(tag, body), good.clone()].concat(),
        ] {
            let r = run(&sig, SigSource::File).result;
            assert!(
                matches!(&r, Err(Rejection::Corrupt(m)) if m.contains(what)),
                "{what}: {r:?}"
            );
        }
    }
}

#[test]
fn a_literal_data_packet_in_a_signature_file_is_corrupt() {
    let sig = [bin(GOOD), packet(11, b"b\0\0\0\0\0hello")].concat();
    let r = run(&sig, SigSource::File).result;
    assert_eq!(
        r,
        Err(Rejection::Corrupt(
            "a literal data packet (type 11) is not allowed in a signature".into()
        ))
    );
}

#[test]
fn partial_lengths_and_empty_inputs_are_corrupt() {
    // A signature packet with a partial body length (only data packets may
    // use them).
    let good = bin(GOOD);
    let (packets, _) = walk(&good).unwrap();
    let body = &good[packets[0].body..packets[0].end];
    // A 256-byte partial chunk (0xE8 = 2^8), then the rest as a final chunk.
    let rest = body.len() - 256;
    assert!(rest < 192, "fixture size changed: {}", body.len());
    let mut partial = vec![0xC2, 0xE8];
    partial.extend_from_slice(&body[..256]);
    partial.push(rest as u8);
    partial.extend_from_slice(&body[256..]);
    let r = run(&partial, SigSource::File).result;
    assert!(
        matches!(&r, Err(Rejection::Corrupt(m)) if m.contains("partial")),
        "{r:?}"
    );
    for empty in [&b""[..], b"\n \n", &[0; 32]] {
        let r = run(empty, SigSource::Embedded).result;
        assert!(matches!(r, Err(Rejection::Corrupt(_))), "{r:?}");
    }
}

#[test]
fn walk_handles_every_length_form() {
    let mut b = vec![0xC2, 2, 0xAA, 0xBB];
    b.extend([0xC2, 192, 0]);
    b.extend(vec![0; 192]);
    b.extend([0xC2, 255, 0, 0, 0, 1, 0xCC]);
    b.extend([0xCB, 0xE1, 1, 2, 1, 9]); // partial 2 bytes, then final 1
    let (p, stop) = walk(&b).unwrap();
    assert_eq!(stop, b.len());
    assert_eq!(p.iter().map(|p| p.tag).collect::<Vec<_>>(), [2, 2, 2, 11]);
    assert!(p[3].partial && !p[0].partial);
    // Old format: one-, two-, four-octet and indeterminate lengths.
    let mut o = vec![0x88, 1, 0xAA, 0x89, 0, 1, 0xBB, 0x8A, 0, 0, 0, 1, 0xCC];
    o.extend([0x8B, 1, 2, 3]);
    let (p, _) = walk(&o).unwrap();
    assert_eq!(p.len(), 4);
    assert!(p[3].partial);
    // Walking stops at a byte that cannot start a packet.
    let (p, stop) = walk(&[0xC2, 1, 7, 0, 0]).unwrap();
    assert_eq!((p.len(), stop), (1, 3));
    // A length past the end is an error.
    assert!(walk(&[0xC2, 5, 1]).is_err());
}
