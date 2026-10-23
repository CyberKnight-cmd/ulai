// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The future-dated and critical-subpacket rules (SPEC §3.2). The GnuPG
//! fixtures cover what GnuPG can produce; the rest is signed here with rPGP
//! from a key generated in the test, so no secret key is ever stored.

use std::path::PathBuf;

use pgp::composed::{
    ArmorOptions, KeyType, SecretKeyParamsBuilder, SignedSecretKey, SubkeyParamsBuilder,
};
use pgp::packet::{Notation, SignatureConfig, Subpacket};
use pgp::types::{Password, SigningKey, Timestamp};
use rand_chacha::ChaCha8Rng;
use rand_chacha::rand_core::SeedableRng as _;

use super::*;

const MIN: u64 = 60;
/// 2020-01-01, the GnuPG fixtures' clock (`make.sh`).
const T0: u64 = 1_577_836_800;
const DAY: u64 = 86_400;
const MSG: &[u8] = b"ULAI test message";

fn read(name: &str) -> Vec<u8> {
    let p = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openpgp")
        .join(name);
    std::fs::read(&p).unwrap_or_else(|e| panic!("{name}: {e}"))
}

fn at(secs: u64) -> SystemTime {
    UNIX_EPOCH + Duration::from_secs(secs)
}

fn gnupg(case: &str, now: SystemTime) -> Result<Accepted, Rejection> {
    super::tests::embedded(
        &read(&format!("{case}.key.asc")),
        &read(&format!("{case}.sig.asc")),
        &read("msg"),
        now,
    )
}

fn public_key(case: &str) -> SignedPublicKey {
    parse_key(&read(&format!("{case}.key.asc"))).unwrap()
}

// --- future-dated signatures ------------------------------------------------

/// The data signature of `rsa3072-text-sha512` was made at T0 + 1 day.
#[test]
fn data_signature_up_to_30_minutes_ahead_is_accepted() {
    let made = T0 + DAY;
    for ahead in [0, 29 * MIN, 30 * MIN] {
        let r = gnupg("rsa3072-text-sha512", at(made - ahead));
        assert!(r.is_ok(), "{ahead}s ahead: {r:?}");
    }
}

#[test]
fn data_signature_31_minutes_ahead_is_rejected() {
    let r = gnupg("rsa3072-text-sha512", at(T0 + DAY - 31 * MIN));
    assert_eq!(
        r,
        Err(Rejection::FromFuture {
            what: "the signature".into(),
            seconds: 31 * MIN,
        })
    );
    assert_eq!(
        r.unwrap_err().to_string(),
        "invalid: the signature was created 31 minutes in the future"
    );
}

/// The self-signature of the `rsa3072` fixture key was made at T0.
#[test]
fn self_signature_from_the_future_is_rejected() {
    let key = public_key("rsa3072-text-sha512");
    assert!(newest_valid_self_signature(&key, at(T0 - 29 * MIN)).is_ok());
    assert_eq!(
        newest_valid_self_signature(&key, at(T0 - 31 * MIN)),
        Err(Rejection::FromFuture {
            what: "a self-signature".into(),
            seconds: 31 * MIN,
        })
    );
}

/// The binding (and back-signature) of the `subkey-signs` subkey were made
/// at T0.
#[test]
fn binding_signature_from_the_future_is_rejected() {
    let key = public_key("subkey-signs");
    let sub = &key.public_subkeys[0];
    assert!(newest_valid_signing_binding(&key, sub, at(T0 - 29 * MIN)).is_ok());
    assert_eq!(
        newest_valid_signing_binding(&key, sub, at(T0 - 31 * MIN)),
        Err(Rejection::FromFuture {
            what: "the subkey binding signature".into(),
            seconds: 31 * MIN,
        })
    );
}

/// `no-sign-flag`'s only self-signature was made at T0 + 2 days (GnuPG
/// exports only the newest one). With the clock at T0 + 1 day + 1 hour it
/// is not valid yet, so the key has no usable self-signature.
#[test]
fn key_whose_only_self_signature_is_from_the_future_is_rejected() {
    let r = gnupg("no-sign-flag", at(T0 + DAY + 60 * MIN));
    assert_eq!(
        r,
        Err(Rejection::FromFuture {
            what: "a self-signature".into(),
            seconds: 23 * 60 * MIN,
        })
    );
}

#[test]
fn human_durations() {
    assert_eq!(human_duration(&(31 * MIN + 59)), "31 minutes");
    assert_eq!(human_duration(&(60 * MIN)), "1 hour");
    assert_eq!(human_duration(&(125 * MIN)), "2 hours 5 minutes");
    assert_eq!(human_duration(&(47 * 60 * MIN)), "47 hours");
    assert_eq!(human_duration(&(3 * DAY + 5)), "3 days");
}

// --- critical subpackets, signed here with rPGP ---------------------------

fn rng() -> ChaCha8Rng {
    ChaCha8Rng::seed_from_u64(9580)
}

/// A v4 Ed25519 key that may certify and sign, with an Ed25519 signing
/// subkey.
fn rpgp_key() -> SignedSecretKey {
    let mut p = SecretKeyParamsBuilder::default();
    p.key_type(KeyType::Ed25519Legacy)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("rpgp <rpgp@fixtures.ulai.invalid>".into())
        .subkey(
            SubkeyParamsBuilder::default()
                .key_type(KeyType::Ed25519Legacy)
                .can_sign(true)
                .build()
                .unwrap(),
        );
    p.build().unwrap().generate(rng()).unwrap()
}

fn base_subpackets(signer: &impl KeyDetails) -> Vec<Subpacket> {
    vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(Timestamp::now())).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(signer.fingerprint())).unwrap(),
    ]
}

fn sign_data(signer: &impl SigningKey, extra: Vec<Subpacket>) -> Vec<u8> {
    let mut cfg = SignatureConfig::v4(
        SignatureType::Binary,
        signer.algorithm(),
        HashAlgorithm::Sha256,
    );
    cfg.hashed_subpackets = base_subpackets(signer);
    cfg.hashed_subpackets.extend(extra);
    let sig = cfg.sign(signer, &Password::empty(), MSG).unwrap();
    DetachedSignature::new(sig)
        .to_armored_bytes(ArmorOptions::default())
        .unwrap()
}

fn armored(key: &SignedPublicKey) -> Vec<u8> {
    key.to_armored_bytes(ArmorOptions::default()).unwrap()
}

fn check(key: &SignedPublicKey, sig: &[u8]) -> Result<Accepted, Rejection> {
    verify_detached(&armored(key), sig, MSG, SystemTime::now())
}

fn critical_notation() -> Subpacket {
    Subpacket::critical(SubpacketData::Notation(Notation {
        readable: true,
        name: "critical@fixtures.ulai.invalid".into(),
        value: "1".into(),
    }))
    .unwrap()
}

#[test]
fn rpgp_made_signature_is_valid_without_extras() {
    let sk = rpgp_key();
    let key = sk.to_public_key();
    check(&key, &sign_data(&sk.primary_key, vec![])).unwrap();
    let a = check(&key, &sign_data(&sk.secret_subkeys[0].key, vec![])).unwrap();
    assert!(a.signer.signed_by_subkey);
}

/// rPGP refuses to make a signature with a critical subpacket of an
/// unassigned type, so the signature is made with the subpacket marked
/// regular and the critical bit is set in the bytes afterwards. That also
/// breaks the cryptographic signature, but ULAI's own check runs before the
/// cryptography, so the reason must name the critical subpacket — which
/// shows that ULAI does not depend on rPGP for this rule.
#[test]
fn unknown_critical_subpacket_is_rejected() {
    let sk = rpgp_key();
    let key = sk.to_public_key();
    // 40 is unassigned in RFC 9580; 0xC3 0x5A is an unlikely value to find
    // elsewhere in the packet.
    let data = SubpacketData::Other(40, vec![0xC3, 0x5A].into());
    let regular = Subpacket::regular(data).unwrap();
    let mut cfg = SignatureConfig::v4(
        SignatureType::Binary,
        sk.primary_key.algorithm(),
        HashAlgorithm::Sha256,
    );
    cfg.hashed_subpackets = base_subpackets(&sk.primary_key);
    cfg.hashed_subpackets.push(regular);
    let sig = cfg.sign(&sk.primary_key, &Password::empty(), MSG).unwrap();
    let mut bytes = DetachedSignature::new(sig).to_bytes().unwrap();
    // Not critical: ignored, and the signature is valid.
    check(&key, &bytes).unwrap();
    let pattern = [3, 40, 0xC3, 0x5A]; // length, type, body
    let at = bytes
        .windows(4)
        .position(|w| w == pattern)
        .expect("subpacket in the packet");
    bytes[at + 1] |= 0x80;
    let r = check(&key, &bytes);
    assert!(
        matches!(&r, Err(Rejection::Invalid(m)) if m.contains("critical subpacket type 40")),
        "{r:?}"
    );
}

/// An experimental-range subpacket (100–110), marked critical. rPGP signs
/// this one.
#[test]
fn unknown_critical_experimental_subpacket_is_rejected() {
    let sk = rpgp_key();
    let critical = Subpacket::critical(SubpacketData::Experimental(101, vec![1].into())).unwrap();
    let r = check(
        &sk.to_public_key(),
        &sign_data(&sk.primary_key, vec![critical]),
    );
    assert!(
        matches!(&r, Err(Rejection::Invalid(m)) if m.contains("critical subpacket type 101")),
        "{r:?}"
    );
}

#[test]
fn critical_notation_on_data_signature_made_by_rpgp_is_rejected() {
    let sk = rpgp_key();
    let r = check(
        &sk.to_public_key(),
        &sign_data(&sk.primary_key, vec![critical_notation()]),
    );
    assert!(
        matches!(&r, Err(Rejection::Invalid(m)) if m.contains("critical notation")),
        "{r:?}"
    );
}

/// GnuPG refuses to sign with a subkey whose binding carries an unknown
/// critical notation, so this case is made with rPGP: the subkey's only
/// binding is replaced by one with a critical notation (and a valid
/// back-signature). The subkey is then unusable.
#[test]
fn critical_notation_on_binding_makes_the_subkey_unusable() {
    let sk = rpgp_key();
    let primary = &sk.primary_key;
    let sub = &sk.secret_subkeys[0].key;
    let mut key = sk.to_public_key();
    let sub_pub = key.public_subkeys[0].key.clone();
    let primary_pub = key.primary_key.clone();

    let mut back = SignatureConfig::v4(
        SignatureType::KeyBinding,
        sub.algorithm(),
        HashAlgorithm::Sha256,
    );
    back.hashed_subpackets = base_subpackets(sub);
    let back = back
        .sign_primary_key_binding(sub, &sub_pub, &Password::empty(), &primary_pub)
        .unwrap();

    let mut flags = pgp::packet::KeyFlags::default();
    flags.set_sign(true);
    let mut cfg = SignatureConfig::v4(
        SignatureType::SubkeyBinding,
        primary.algorithm(),
        HashAlgorithm::Sha256,
    );
    cfg.hashed_subpackets = base_subpackets(primary);
    cfg.hashed_subpackets.extend([
        Subpacket::regular(SubpacketData::KeyFlags(flags)).unwrap(),
        critical_notation(),
    ]);
    cfg.unhashed_subpackets =
        vec![Subpacket::regular(SubpacketData::EmbeddedSignature(Box::new(back))).unwrap()];
    let binding = cfg
        .sign_subkey_binding(primary, &primary_pub, &Password::empty(), &sub_pub)
        .unwrap();
    key.public_subkeys[0].signatures = vec![binding];

    let r = check(&key, &sign_data(sub, vec![]));
    assert!(
        matches!(&r, Err(Rejection::Invalid(m)) if m.contains("binding") && m.contains("critical notation")),
        "{r:?}"
    );
    // The primary key itself is unaffected.
    check(&key, &sign_data(primary, vec![])).unwrap();
}

/// A newer self-signature from the future does not count, and does not
/// spoil an older valid one: the key stays usable.
#[test]
fn future_self_signature_is_skipped_when_an_older_one_is_valid() {
    let sk = rpgp_key();
    let mut key = sk.to_public_key();
    let mut cfg = SignatureConfig::v4(
        SignatureType::Key,
        sk.primary_key.algorithm(),
        HashAlgorithm::Sha256,
    );
    let future = Timestamp::from_secs(Timestamp::now().as_secs() + 2 * 3600);
    cfg.hashed_subpackets = vec![
        Subpacket::regular(SubpacketData::SignatureCreationTime(future)).unwrap(),
        Subpacket::regular(SubpacketData::IssuerFingerprint(
            sk.primary_key.fingerprint(),
        ))
        .unwrap(),
    ];
    let direct = cfg
        .sign_key(&sk.primary_key, &Password::empty(), &key.primary_key)
        .unwrap();
    key.details.direct_signatures.push(direct);
    check(&key, &sign_data(&sk.primary_key, vec![])).unwrap();
    // Alone, it would be rejected.
    key.details.users.clear();
    let r = check(&key, &sign_data(&sk.primary_key, vec![]));
    assert!(matches!(r, Err(Rejection::FromFuture { .. })), "{r:?}");
}

/// Regression: NUL padding is stripped only after armor. A binary signature
/// whose last byte is zero (about 1 in 256 Ed25519 signatures) used to be
/// truncated and reported as corrupt.
#[test]
fn binary_signature_ending_in_zero_is_not_truncated() {
    let sk = rpgp_key();
    let key = sk.to_public_key();
    let bytes = (0u32..10_000)
        .find_map(|i| {
            let note = Subpacket::regular(SubpacketData::Notation(Notation {
                readable: true,
                name: "n@fixtures.ulai.invalid".into(),
                value: i.to_string().into(),
            }))
            .unwrap();
            let mut cfg = SignatureConfig::v4(
                SignatureType::Binary,
                sk.primary_key.algorithm(),
                HashAlgorithm::Sha256,
            );
            cfg.hashed_subpackets = base_subpackets(&sk.primary_key);
            cfg.hashed_subpackets.push(note);
            let sig = cfg.sign(&sk.primary_key, &Password::empty(), MSG).unwrap();
            let b = DetachedSignature::new(sig).to_bytes().unwrap();
            (b.last() == Some(&0)).then_some(b)
        })
        .expect("a signature ending in a zero byte");
    check(&key, &bytes).unwrap();
}

/// An unknown critical subpacket in the unhashed area is not covered by
/// the signature, so anyone could add it; it is ignored.
#[test]
fn critical_subpacket_in_unhashed_area_is_ignored() {
    let sk = rpgp_key();
    let mut cfg = SignatureConfig::v4(
        SignatureType::Binary,
        sk.primary_key.algorithm(),
        HashAlgorithm::Sha256,
    );
    cfg.hashed_subpackets = base_subpackets(&sk.primary_key);
    cfg.unhashed_subpackets = vec![critical_notation()];
    let sig = cfg.sign(&sk.primary_key, &Password::empty(), MSG).unwrap();
    let sig = DetachedSignature::new(sig)
        .to_armored_bytes(ArmorOptions::default())
        .unwrap();
    check(&sk.to_public_key(), &sig).unwrap();
}

/// A text signature (0x01) is computed over line-ending-normalised data, so
/// it does not bind a binary file's exact bytes: inserting a CR before an LF
/// leaves it valid. ULAI accepts text signatures only in the embedded
/// scheme (over the hex digest) and rejects them as detached signatures
/// over a whole file.
#[test]
fn text_signature_does_not_bind_a_binary_and_is_rejected_for_files() {
    let sk = rpgp_key();
    let key = armored(&sk.to_public_key());
    // Binary data with LF bytes, as any ELF file has.
    let data: Vec<u8> = b"\x7fELF\x02\x01\x01\0\nbinary\x00\x01\nmore\xff\n".to_vec();
    let mut cfg = SignatureConfig::v4(
        SignatureType::Text,
        sk.primary_key.algorithm(),
        HashAlgorithm::Sha256,
    );
    cfg.hashed_subpackets = base_subpackets(&sk.primary_key);
    let sig = cfg
        .sign(&sk.primary_key, &Password::empty(), data.as_slice())
        .unwrap();
    let sig = DetachedSignature::new(sig)
        .to_armored_bytes(ArmorOptions::default())
        .unwrap();

    let mut tampered = data.clone();
    let lf = tampered.iter().position(|&b| b == b'\n').unwrap();
    tampered.insert(lf, b'\r');
    assert_ne!(tampered, data);

    // The weakness: the signature still verifies over the changed bytes.
    let embedded = |d: &[u8]| {
        verify_signatures(
            &key,
            &sig,
            SigSource::Embedded,
            &mut &d[..],
            SystemTime::now(),
        )
        .unwrap()
        .result
    };
    embedded(&data).unwrap();
    embedded(&tampered).unwrap();

    // As a detached signature over a file, ULAI rejects it, changed or not.
    for d in [&data, &tampered] {
        let r = verify_detached(&key, &sig, d.as_slice(), SystemTime::now());
        assert!(
            matches!(&r, Err(Rejection::Unsupported(m)) if m.contains("must be binary (0x00)")),
            "{r:?}"
        );
    }
}
