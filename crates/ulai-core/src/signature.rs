// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! OpenPGP signature verification for AppImages (SPEC §3.2, ADR-016).
//!
//! rPGP parses packets and checks the cryptography. Everything that gives a
//! signature its meaning is decided here, because rPGP leaves it to the
//! application: which key may sign, revocation, expiry at signing time, key
//! flags, subkey back-signatures, and the algorithm policy for every
//! signature that is relied on.

use std::io::Read;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey, SignedPublicSubKey};
use pgp::crypto::hash::HashAlgorithm;
use pgp::crypto::public_key::PublicKeyAlgorithm;
use pgp::packet::{Signature, SignatureType, SignatureVersion, SubpacketData};
use pgp::ser::Serialize as _;
use pgp::types::{KeyDetails, KeyVersion, PublicParams, Tag};
use serde::Serialize;

/// Smallest accepted RSA modulus.
pub const MIN_RSA_BITS: u16 = 2048;
/// Largest armored key or signature ULAI will parse.
pub const MAX_ARMOR_BYTES: usize = 64 * 1024;
/// How far in the future a signature's creation time may be, to allow for
/// clock skew between signer and verifier. Same value as Sequoia's
/// `CLOCK_SKEW_TOLERANCE`.
pub const CLOCK_SKEW_TOLERANCE_SECS: u64 = 30 * 60;
/// Notation names ULAI understands when they are marked critical. None: a
/// critical notation makes the signature carrying it unusable (RFC 9580
/// §5.2.3.24).
const KNOWN_CRITICAL_NOTATIONS: &[&[u8]] = &[];

/// Why a signature was not accepted.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Rejection {
    /// The signature, digest or key binding does not verify, or the key is
    /// revoked, expired at signing time, or not allowed to sign.
    #[error("invalid: {0}")]
    Invalid(String),
    /// Malformed key or signature data.
    #[error("corrupt: {0}")]
    Corrupt(String),
    /// Well-formed, but outside ULAI's policy (algorithm, hash, key size,
    /// packet version).
    #[error("unsupported: {0}")]
    Unsupported(String),
    /// A signature ULAI relies on (data, self, binding or back-signature)
    /// was created more than [`CLOCK_SKEW_TOLERANCE_SECS`] after `now`.
    #[error("invalid: {what} was created {} in the future", human_duration(.seconds))]
    FromFuture {
        what: String,
        /// How far the creation time is after `now`.
        seconds: u64,
    },
}

/// `2_100` → `35 minutes`, `7_500` → `2 hours 5 minutes`, `200_000` → `2 days`.
pub fn human_duration(seconds: &u64) -> String {
    let plural = |n: u64, unit: &str| format!("{n} {unit}{}", if n == 1 { "" } else { "s" });
    let (m, h, d) = (seconds / 60, seconds / 3600, seconds / 86_400);
    match () {
        () if h == 0 => plural(m, "minute"),
        () if d < 2 => match m % 60 {
            0 => plural(h, "hour"),
            rest => format!("{} {}", plural(h, "hour"), plural(rest, "minute")),
        },
        () => plural(d, "day"),
    }
}

fn invalid(m: impl Into<String>) -> Rejection {
    Rejection::Invalid(m.into())
}
fn unsupported(m: impl Into<String>) -> Rejection {
    Rejection::Unsupported(m.into())
}
fn corrupt(m: impl Into<String>) -> Rejection {
    Rejection::Corrupt(m.into())
}

/// The key and signature behind a valid result.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Signer {
    /// Full fingerprint of the primary key, upper-case hex (v4: 40 digits,
    /// v6: 64). Never a short key id.
    pub primary_fingerprint: String,
    /// Full fingerprint of the key that made the signature (the primary key
    /// or a signing subkey).
    pub signing_fingerprint: String,
    pub signed_by_subkey: bool,
    pub key_version: u8,
    pub algorithm: String,
    /// RSA modulus size; `None` for other algorithms.
    pub rsa_bits: Option<u16>,
    pub user_ids: Vec<String>,
    /// `binary` (0x00) or `text` (0x01).
    pub signature_type: &'static str,
    pub hash: &'static str,
    /// Signature creation time, seconds since the Unix epoch.
    pub created: u64,
    /// When the signing key expires (seconds since the epoch), if it does.
    pub key_expires: Option<u64>,
}

/// A valid result. `warnings` holds non-fatal findings, such as a key that
/// expired after it made the signature.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Accepted {
    pub signer: Signer,
    pub warnings: Vec<String>,
}

/// Verifies `signature` (ASCII-armored detached OpenPGP signature) over the
/// bytes read from `data`, using the one key in `key` (ASCII-armored).
/// `now` is the verifier's clock: signatures created more than
/// [`CLOCK_SKEW_TOLERANCE_SECS`] after it are rejected, and keys that expired
/// since signing produce a warning.
pub fn verify_detached(
    key: &[u8],
    signature: &[u8],
    data: impl Read,
    now: SystemTime,
) -> Result<Accepted, Rejection> {
    let key = parse_key(key)?;
    let sig = parse_signature(signature)?;
    check_data_signature_policy(&sig, now)?;

    let primary = &key.primary_key;
    check_key_policy(
        primary.version(),
        primary.algorithm(),
        primary.public_params(),
        "primary key",
    )?;

    // The primary key must carry a valid self-signature; the newest one
    // decides its flags and expiry.
    let primary_sig = newest_valid_self_signature(&key, now)?;
    if !key.details.revocation_signatures.is_empty() {
        return Err(invalid("the key has been revoked"));
    }

    let created = sig
        .created()
        .map(|t| u64::from(t.as_secs()))
        .ok_or_else(|| corrupt("signature has no creation time"))?;
    let primary_created = u64::from(primary.created_at().as_secs());
    if created < primary_created {
        return Err(invalid("signature predates the key"));
    }
    let primary_expires = expiry(primary_created, primary_sig.key_expiration_time());

    let mut warnings = Vec::new();
    check_expiry("primary key", primary_expires, created, now, &mut warnings)?;

    // Which key made the signature?
    let (signer_fp, subkey) = find_signing_key(&key, &sig)?;
    let (key_version, algorithm, params, key_expires) = match subkey {
        None => {
            if !primary_sig.key_flags().sign() {
                return Err(invalid(
                    "the primary key is not allowed to sign (key flags)",
                ));
            }
            (
                primary.version(),
                primary.algorithm(),
                primary.public_params(),
                primary_expires,
            )
        }
        Some(sub) => {
            let k = &sub.key;
            check_key_policy(
                k.version(),
                k.algorithm(),
                k.public_params(),
                "signing subkey",
            )?;
            if sub
                .signatures
                .iter()
                .any(|s| s.typ() == Some(SignatureType::SubkeyRevocation))
            {
                return Err(invalid("the signing subkey has been revoked"));
            }
            let binding = newest_valid_signing_binding(&key, sub, now)?;
            let sub_created = u64::from(k.created_at().as_secs());
            if created < sub_created {
                return Err(invalid("signature predates the signing subkey"));
            }
            let sub_expires = expiry(sub_created, binding.key_expiration_time());
            check_expiry("signing subkey", sub_expires, created, now, &mut warnings)?;
            (
                k.version(),
                k.algorithm(),
                k.public_params(),
                min_opt(sub_expires, primary_expires),
            )
        }
    };

    // Finally, the signature over the data itself (streamed).
    let verified = match subkey {
        None => sig.verify(primary, data),
        Some(sub) => sig.verify(&sub.key, data),
    };
    verified.map_err(|e| {
        tracing::debug!(error = %e, "data signature verification failed");
        invalid("the signature does not match the signed data")
    })?;

    if let Some(exp) = sig.signature_expiration_time() {
        let sig_expires = created.saturating_add(u64::from(exp.as_secs()));
        if exp.as_secs() != 0 && sig_expires <= unix(now) {
            warnings.push("the signature itself has expired since it was made".into());
        }
    }

    Ok(Accepted {
        signer: Signer {
            primary_fingerprint: fingerprint(primary),
            signing_fingerprint: signer_fp,
            signed_by_subkey: subkey.is_some(),
            key_version: key_version_number(key_version),
            algorithm: algorithm_name(algorithm),
            rsa_bits: rsa_bits(params),
            user_ids: key
                .details
                .users
                .iter()
                .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
                .collect(),
            signature_type: if sig.typ() == Some(SignatureType::Text) {
                "text"
            } else {
                "binary"
            },
            hash: hash_name(sig.hash_alg()),
            created,
            key_expires,
        },
        warnings,
    })
}

/// Whether `bytes` (after trimming NUL padding) is ASCII armor rather than
/// binary OpenPGP. `gpg --detach-sign` and `gpg --export` write binary by
/// default; `--armor` and the AppImage sections use armor.
fn is_armor(bytes: &[u8]) -> bool {
    let start = bytes
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    bytes[start..].starts_with(b"-----BEGIN PGP ")
}

/// Strips the NUL padding after ASCII armor (embedded sections are armored
/// and padded to their full size) and applies the size limit. Binary input
/// is left as it is: its last bytes may legitimately be zero.
fn trimmed<'a>(input: &'a [u8], what: &str) -> Result<&'a [u8], Rejection> {
    let end = input.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    let bytes = if is_armor(&input[..end]) {
        &input[..end]
    } else {
        input
    };
    if bytes.len() > MAX_ARMOR_BYTES {
        return Err(corrupt(format!(
            "{what} is larger than {MAX_ARMOR_BYTES} bytes"
        )));
    }
    if bytes.is_empty() {
        return Err(corrupt(format!("{what} is empty")));
    }
    Ok(bytes)
}

/// Parses exactly one transferable public key (armored or binary).
fn parse_key(input: &[u8]) -> Result<SignedPublicKey, Rejection> {
    let bytes = trimmed(input, "key")?;
    let err = |e: pgp::errors::Error| corrupt(format!("cannot parse the public key: {e}"));
    let mut keys = Vec::new();
    if is_armor(bytes) {
        let (iter, _) =
            SignedPublicKey::from_string_many(armor_text(bytes, "key")?).map_err(err)?;
        for k in iter {
            keys.push(k.map_err(err)?);
        }
    } else {
        for k in SignedPublicKey::from_bytes_many(bytes).map_err(err)? {
            keys.push(k.map_err(err)?);
        }
    }
    match keys.len() {
        1 => Ok(keys.pop().expect("one key")),
        // rPGP skips v5 (LibrePGP) key packets instead of reporting them.
        0 if first_public_key_version(bytes) == Some(5) => Err(unsupported(
            "the key is a v5 (LibrePGP) key; only v4 and v6 are supported",
        )),
        0 => Err(corrupt("no public key found")),
        n => Err(corrupt(format!(
            "expected exactly one primary key, found {n}"
        ))),
    }
}

/// Version byte of the first packet if it is a public-key packet (tag 6).
fn first_public_key_version(input: &[u8]) -> Option<u8> {
    use std::io::Read as _;
    let bin: Vec<u8> = if is_armor(input) {
        let mut v = Vec::new();
        pgp::armor::Dearmor::new(input)
            .take(MAX_ARMOR_BYTES as u64)
            .read_to_end(&mut v)
            .ok()?;
        v
    } else {
        input.to_vec()
    };
    let h = *bin.first()?;
    if h & 0x80 == 0 {
        return None;
    }
    let (tag, header_len) = if h & 0x40 != 0 {
        let l0 = *bin.get(1)?;
        let hl = match l0 {
            0..=191 => 2,
            192..=223 => 3,
            255 => 6,
            _ => return None, // partial lengths are not used for keys
        };
        (h & 0x3F, hl)
    } else {
        let hl = match h & 3 {
            0 => 2,
            1 => 3,
            2 => 5,
            _ => return None,
        };
        ((h >> 2) & 0x0F, hl)
    };
    if tag != 6 {
        return None;
    }
    bin.get(header_len).copied()
}

/// Parses exactly one detached signature packet (armored or binary).
fn parse_signature(input: &[u8]) -> Result<Signature, Rejection> {
    let bytes = trimmed(input, "signature")?;
    let err = |e: pgp::errors::Error| corrupt(format!("cannot parse the signature: {e}"));
    let sig = if is_armor(bytes) {
        DetachedSignature::from_string(armor_text(bytes, "signature")?)
            .map_err(err)?
            .0
    } else {
        DetachedSignature::from_bytes(bytes).map_err(err)?
    };
    Ok(sig.signature)
}

/// The armor must be ASCII text without NUL bytes inside it.
fn armor_text<'a>(bytes: &'a [u8], what: &str) -> Result<&'a str, Rejection> {
    if bytes.contains(&0) {
        return Err(corrupt(format!(
            "{what} contains NUL bytes inside the armor"
        )));
    }
    std::str::from_utf8(bytes).map_err(|_| corrupt(format!("{what} is not ASCII armor")))
}

fn check_hash(alg: HashAlgorithm, what: &str) -> Result<(), Rejection> {
    match alg {
        HashAlgorithm::Sha256 | HashAlgorithm::Sha384 | HashAlgorithm::Sha512 => Ok(()),
        other => Err(unsupported(format!(
            "{what} uses hash {other:?}; only SHA-256, SHA-384 and SHA-512 are accepted"
        ))),
    }
}

fn check_sig_version(sig: &Signature, what: &str) -> Result<(), Rejection> {
    match sig.version() {
        SignatureVersion::V4 | SignatureVersion::V6 => Ok(()),
        v => Err(unsupported(format!(
            "{what} is a {v:?} signature; only v4 and v6 are supported"
        ))),
    }
}

/// Policy for every signature ULAI relies on (data, self, binding,
/// back-signature): version, hash, creation time not in the future, and no
/// critical subpacket ULAI does not understand.
fn check_sig_policy(sig: &Signature, what: &str, now: SystemTime) -> Result<(), Rejection> {
    check_sig_version(sig, what)?;
    let alg = sig
        .hash_alg()
        .ok_or_else(|| unsupported(format!("{what}: unknown hash")))?;
    check_hash(alg, what)?;
    check_not_future(sig, what, now)?;
    check_critical_subpackets(sig, what)
}

fn check_not_future(sig: &Signature, what: &str, now: SystemTime) -> Result<(), Rejection> {
    let (created, now) = (created(sig), unix(now));
    if created > now.saturating_add(CLOCK_SKEW_TOLERANCE_SECS) {
        return Err(Rejection::FromFuture {
            what: what.to_owned(),
            seconds: created - now,
        });
    }
    Ok(())
}

/// RFC 9580 §5.2.3.7: a critical subpacket the verifier does not understand
/// makes the signature unusable. rPGP 0.21 parses such subpackets without
/// complaint, so ULAI checks the hashed area itself. (A critical subpacket in
/// the unhashed area is not covered by the signature; anyone could add one,
/// so it carries no meaning and is ignored.)
fn check_critical_subpackets(sig: &Signature, what: &str) -> Result<(), Rejection> {
    let Some(config) = sig.config() else {
        return Ok(());
    };
    for sp in config.hashed_subpackets().filter(|sp| sp.is_critical) {
        let unknown = match &sp.data {
            SubpacketData::Notation(n) if !KNOWN_CRITICAL_NOTATIONS.contains(&n.name.as_ref()) => {
                format!(
                    "the critical notation {:?}",
                    String::from_utf8_lossy(&n.name)
                )
            }
            SubpacketData::Other(t, _) | SubpacketData::Experimental(t, _) => {
                format!("critical subpacket type {t}")
            }
            SubpacketData::RegularExpression(_) => "a critical regular expression".into(),
            _ => continue,
        };
        return Err(invalid(format!(
            "{what} carries {unknown}, which ULAI does not understand"
        )));
    }
    Ok(())
}

fn check_data_signature_policy(sig: &Signature, now: SystemTime) -> Result<(), Rejection> {
    check_sig_policy(sig, "the signature", now)?;
    match sig.typ() {
        Some(SignatureType::Binary | SignatureType::Text) => Ok(()),
        t => Err(unsupported(format!(
            "signature type {t:?}; expected binary or text"
        ))),
    }
}

fn check_key_policy(
    version: KeyVersion,
    alg: PublicKeyAlgorithm,
    params: &PublicParams,
    what: &str,
) -> Result<(), Rejection> {
    match version {
        KeyVersion::V4 | KeyVersion::V6 => {}
        v => {
            return Err(unsupported(format!(
                "{what} is a {v:?} key; only v4 and v6 are supported"
            )));
        }
    }
    match (alg, params) {
        (PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign, PublicParams::RSA(_)) => {
            let bits =
                rsa_bits(params).ok_or_else(|| corrupt(format!("{what}: bad RSA parameters")))?;
            if bits < MIN_RSA_BITS {
                return Err(unsupported(format!(
                    "{what} is RSA-{bits}; at least {MIN_RSA_BITS} bits are required"
                )));
            }
            Ok(())
        }
        (PublicKeyAlgorithm::EdDSALegacy, PublicParams::EdDSALegacy(p)) => {
            // Only Ed25519 is accepted in the legacy EdDSA form.
            let curve = format!("{p:?}");
            if curve.contains("Ed25519") {
                Ok(())
            } else {
                Err(unsupported(format!(
                    "{what}: EdDSA curve other than Ed25519"
                )))
            }
        }
        (PublicKeyAlgorithm::Ed25519, PublicParams::Ed25519(_)) => Ok(()),
        (a, _) => Err(unsupported(format!(
            "{what} uses {a:?}; only RSA and Ed25519 are supported"
        ))),
    }
}

/// Bit length of an RSA modulus, from its OpenPGP MPI encoding (the first
/// two bytes of the serialized public parameters).
fn rsa_bits(params: &PublicParams) -> Option<u16> {
    let PublicParams::RSA(_) = params else {
        return None;
    };
    let bytes = params.to_bytes().ok()?;
    Some(u16::from_be_bytes([*bytes.first()?, *bytes.get(1)?]))
}

/// The newest self-signature on the primary key that verifies and passes
/// policy: a direct-key signature, or a self-certification of a user id.
fn newest_valid_self_signature(
    key: &SignedPublicKey,
    now: SystemTime,
) -> Result<&Signature, Rejection> {
    let primary = &key.primary_key;
    let mut candidates: Vec<(&Signature, Result<(), Rejection>)> = Vec::new();
    for sig in &key.details.direct_signatures {
        let r = check_sig_policy(sig, "a direct-key self-signature", now).and_then(|()| {
            sig.verify_key(primary)
                .map_err(|e| invalid(format!("direct-key self-signature does not verify: {e}")))
        });
        candidates.push((sig, r));
    }
    for user in &key.details.users {
        for sig in &user.signatures {
            if !matches!(
                sig.typ(),
                Some(
                    SignatureType::CertGeneric
                        | SignatureType::CertPersona
                        | SignatureType::CertCasual
                        | SignatureType::CertPositive
                )
            ) || !issued_by(sig, primary)
            {
                continue;
            }
            let r = check_sig_policy(sig, "a self-signature", now).and_then(|()| {
                sig.verify_certification(primary, Tag::UserId, &user.id)
                    .map_err(|e| invalid(format!("self-signature does not verify: {e}")))
            });
            candidates.push((sig, r));
        }
    }
    let mut best: Option<&Signature> = None;
    let mut last_err = invalid("the key has no self-signature");
    for (sig, r) in candidates {
        match r {
            Ok(()) if best.is_none_or(|b| created(sig) >= created(b)) => best = Some(sig),
            Ok(()) => {}
            Err(e) => last_err = e,
        }
    }
    best.ok_or(last_err)
}

/// The newest subkey binding that verifies, passes policy, allows signing,
/// and carries a valid embedded primary-key binding (back-signature, 0x19).
fn newest_valid_signing_binding<'a>(
    key: &SignedPublicKey,
    sub: &'a SignedPublicSubKey,
    now: SystemTime,
) -> Result<&'a Signature, Rejection> {
    let mut best: Option<&Signature> = None;
    let mut last_err = invalid("the signing subkey has no binding signature");
    for sig in &sub.signatures {
        if sig.typ() != Some(SignatureType::SubkeyBinding) {
            continue;
        }
        let r = check_sig_policy(sig, "the subkey binding signature", now)
            .and_then(|()| {
                sig.verify_subkey_binding(&key.primary_key, &sub.key)
                    .map_err(|e| invalid(format!("subkey binding does not verify: {e}")))
            })
            .and_then(|()| {
                if sig.key_flags().sign() {
                    Ok(())
                } else {
                    Err(invalid("the subkey is not allowed to sign (key flags)"))
                }
            })
            .and_then(|()| {
                let back = sig.embedded_signature().ok_or_else(|| {
                    invalid(
                        "the signing subkey has no primary-key binding signature (back-signature)",
                    )
                })?;
                if back.typ() != Some(SignatureType::KeyBinding) {
                    return Err(invalid(
                        "the embedded signature is not a primary-key binding",
                    ));
                }
                check_sig_policy(back, "the back-signature", now)?;
                back.verify_primary_key_binding(&sub.key, &key.primary_key)
                    .map_err(|e| invalid(format!("back-signature does not verify: {e}")))
            });
        match r {
            Ok(()) => {
                if best.is_none_or(|b| created(sig) >= created(b)) {
                    best = Some(sig);
                }
            }
            Err(e) => last_err = e,
        }
    }
    best.ok_or(last_err)
}

/// Finds the key that made `sig`: the primary key or one subkey, matched by
/// issuer fingerprint or issuer key id.
fn find_signing_key<'a>(
    key: &'a SignedPublicKey,
    sig: &Signature,
) -> Result<(String, Option<&'a SignedPublicSubKey>), Rejection> {
    if sig.issuer_fingerprint().is_empty() && sig.issuer_key_id().is_empty() {
        return Err(corrupt("the signature names no issuer"));
    }
    if issued_by(sig, &key.primary_key) {
        return Ok((fingerprint(&key.primary_key), None));
    }
    let matches: Vec<&SignedPublicSubKey> = key
        .public_subkeys
        .iter()
        .filter(|s| issued_by(sig, &s.key))
        .collect();
    match matches.as_slice() {
        [one] => Ok((fingerprint(&one.key), Some(one))),
        [] => Err(invalid(
            "the signature was made by a key that is not in the supplied key",
        )),
        _ => Err(corrupt("the signature issuer matches more than one subkey")),
    }
}

fn issued_by(sig: &Signature, key: &impl KeyDetails) -> bool {
    let fps = sig.issuer_fingerprint();
    if !fps.is_empty() {
        return fps.iter().any(|fp| **fp == key.fingerprint());
    }
    sig.issuer_key_id()
        .iter()
        .any(|id| **id == key.legacy_key_id())
}

fn created(sig: &Signature) -> u64 {
    sig.created().map_or(0, |t| u64::from(t.as_secs()))
}

fn expiry(key_created: u64, validity: Option<pgp::types::Duration>) -> Option<u64> {
    match validity.map(|d| d.as_secs()) {
        None | Some(0) => None,
        Some(secs) => Some(key_created.saturating_add(u64::from(secs))),
    }
}

/// Expired before signing → invalid. Expired since → warning.
fn check_expiry(
    what: &str,
    expires: Option<u64>,
    signed: u64,
    now: SystemTime,
    warnings: &mut Vec<String>,
) -> Result<(), Rejection> {
    let Some(exp) = expires else { return Ok(()) };
    if exp <= signed {
        return Err(invalid(format!(
            "the {what} had expired when the signature was made"
        )));
    }
    if exp <= unix(now) {
        warnings.push(format!(
            "the {what} has expired since the signature was made"
        ));
    }
    Ok(())
}

fn min_opt(a: Option<u64>, b: Option<u64>) -> Option<u64> {
    match (a, b) {
        (Some(x), Some(y)) => Some(x.min(y)),
        (x, None) => x,
        (None, y) => y,
    }
}

fn unix(t: SystemTime) -> u64 {
    t.duration_since(UNIX_EPOCH)
        .unwrap_or(Duration::ZERO)
        .as_secs()
}

fn fingerprint(key: &impl KeyDetails) -> String {
    hex::encode_upper(key.fingerprint().as_bytes())
}

fn key_version_number(v: KeyVersion) -> u8 {
    match v {
        KeyVersion::V2 => 2,
        KeyVersion::V3 => 3,
        KeyVersion::V4 => 4,
        KeyVersion::V5 => 5,
        KeyVersion::V6 => 6,
        _ => 0,
    }
}

fn algorithm_name(a: PublicKeyAlgorithm) -> String {
    match a {
        PublicKeyAlgorithm::RSA | PublicKeyAlgorithm::RSASign => "RSA".into(),
        PublicKeyAlgorithm::EdDSALegacy => "Ed25519 (legacy EdDSA)".into(),
        PublicKeyAlgorithm::Ed25519 => "Ed25519".into(),
        other => format!("{other:?}"),
    }
}

fn hash_name(h: Option<HashAlgorithm>) -> &'static str {
    match h {
        Some(HashAlgorithm::Sha256) => "SHA-256",
        Some(HashAlgorithm::Sha384) => "SHA-384",
        Some(HashAlgorithm::Sha512) => "SHA-512",
        _ => "other",
    }
}

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_rules;
