// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Splits a signature file or `.sha256_sig` section into OpenPGP packets by
//! their own length headers (RFC 9580 §4.2), before rPGP sees any of them
//! (SPEC §3.2). rPGP's `DetachedSignature::from_bytes` returns the first
//! signature and never looks at what follows, so the rules about what else
//! may be there are enforced here.

use std::io::Read as _;

use super::{
    MAX_ARMOR_BYTES, MAX_SIGNATURES, Rejection, SigSource, armor_text, corrupt, unsupported,
};

const SIGNATURE: u8 = 2;
const MARKER: u8 = 10;
const PADDING: u8 = 21;

/// One packet found by its header.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct Framed {
    pub tag: u8,
    /// Offset of the header.
    pub start: usize,
    /// Offset of the body (the first chunk, for partial lengths).
    pub body: usize,
    /// Offset just after the packet.
    pub end: usize,
    /// Partial body lengths, or the old format's indeterminate length.
    pub partial: bool,
}

/// Walks packet headers from the start of `bin` for as long as the next
/// byte can start a packet (bit 7 set). Returns the packets and the offset
/// where walking stopped. An error means a header or length is malformed or
/// runs past the end of the input.
pub(super) fn walk(bin: &[u8]) -> Result<(Vec<Framed>, usize), String> {
    let mut out = Vec::new();
    let mut i = 0;
    let past_end = || "a packet length runs past the end of the data".to_owned();
    while i < bin.len() && bin[i] & 0x80 != 0 {
        let start = i;
        let h = bin[i];
        if h & 0x40 != 0 {
            // New format; partial body lengths chain until a final length.
            let tag = h & 0x3F;
            i += 1;
            let mut body = None;
            let mut partial = false;
            loop {
                let l0 = *bin.get(i).ok_or_else(past_end)? as usize;
                let (len, hl, last) = match l0 {
                    0..=191 => (l0, 1, true),
                    192..=223 => {
                        let l1 = *bin.get(i + 1).ok_or_else(past_end)? as usize;
                        (((l0 - 192) << 8) + l1 + 192, 2, true)
                    }
                    224..=254 => (1 << (l0 & 0x1F), 1, false),
                    _ => {
                        let b = bin.get(i + 1..i + 5).ok_or_else(past_end)?;
                        let n = u32::from_be_bytes(b.try_into().expect("4 bytes"));
                        (usize::try_from(n).map_err(|_| past_end())?, 5, true)
                    }
                };
                body.get_or_insert(i + hl);
                i = i
                    .checked_add(hl)
                    .and_then(|x| x.checked_add(len))
                    .filter(|&x| x <= bin.len())
                    .ok_or_else(past_end)?;
                if last {
                    break;
                }
                partial = true;
            }
            out.push(Framed {
                tag,
                start,
                body: body.expect("set in the first iteration"),
                end: i,
                partial,
            });
        } else {
            let tag = (h >> 2) & 0x0F;
            let (len, hl, partial) = match h & 3 {
                0 => (*bin.get(i + 1).ok_or_else(past_end)? as usize, 2, false),
                1 => {
                    let b = bin.get(i + 1..i + 3).ok_or_else(past_end)?;
                    (
                        u16::from_be_bytes(b.try_into().expect("2 bytes")) as usize,
                        3,
                        false,
                    )
                }
                2 => {
                    let b = bin.get(i + 1..i + 5).ok_or_else(past_end)?;
                    let n = u32::from_be_bytes(b.try_into().expect("4 bytes"));
                    (usize::try_from(n).map_err(|_| past_end())?, 5, false)
                }
                _ => (bin.len() - i - 1, 1, true), // indeterminate: to the end
            };
            let end = i
                .checked_add(hl)
                .and_then(|x| x.checked_add(len))
                .filter(|&x| x <= bin.len())
                .ok_or_else(past_end)?;
            out.push(Framed {
                tag,
                start,
                body: i + hl,
                end,
                partial,
            });
            i = end;
        }
    }
    Ok((out, i))
}

/// `(tag, body offset)` of every packet, if the packets fill `bin` exactly
/// and there is at least one.
pub(super) fn packet_framing(bin: &[u8]) -> Option<Vec<(u8, usize)>> {
    let (packets, stop) = walk(bin).ok()?;
    (stop == bin.len() && !packets.is_empty())
        .then(|| packets.into_iter().map(|p| (p.tag, p.body)).collect())
}

/// The signature packets of a signature file or section, each with its
/// header, ready for rPGP; plus how many unknown non-critical packets were
/// skipped.
///
/// - Only signature, marker and padding packets may appear, and unknown
///   non-critical ones (types 40–63), which RFC 9580 §4.3 says to ignore.
///   Any other type is corrupt.
/// - Armored: only whitespace before the armor; after the footer line,
///   only whitespace (`File`) or only zero bytes (`Embedded`).
/// - Binary: nothing after the last packet (`File`), or only zero bytes
///   (`Embedded`).
/// - At least one and at most [`MAX_SIGNATURES`] signature packets.
pub(super) fn signature_packets(
    input: &[u8],
    source: SigSource,
) -> Result<(Vec<Vec<u8>>, usize), Rejection> {
    if input.len() > MAX_ARMOR_BYTES {
        return Err(unsupported(format!(
            "the signature is larger than ULAI's limit of {} KiB",
            MAX_ARMOR_BYTES / 1024
        )));
    }
    let start = input
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(input.len());
    let armored = input[start..].starts_with(b"-----BEGIN PGP ");
    let bin = if armored {
        dearmor(input, start, source)?
    } else {
        input.to_vec()
    };
    if bin.is_empty() || bin.iter().all(|&b| b == 0) {
        return Err(corrupt("the signature is empty"));
    }
    let (packets, stop) = walk(&bin).map_err(|e| corrupt(format!("malformed signature: {e}")))?;
    if packets.is_empty() {
        return Err(corrupt("not an OpenPGP signature"));
    }
    let rest = &bin[stop..];
    let rest_ok = match (armored, source) {
        (false, SigSource::Embedded) => rest.iter().all(|&b| b == 0),
        _ => rest.is_empty(),
    };
    if !rest_ok {
        return Err(corrupt(match (armored, source) {
            (false, SigSource::Embedded) => {
                "the rest of .sha256_sig after the last packet must be zero bytes"
            }
            (true, _) => "there are bytes after the last packet inside the armor",
            (false, SigSource::File) => "there are bytes after the last packet",
        }));
    }

    let mut sigs = Vec::new();
    let mut ignored = 0;
    for p in &packets {
        if p.partial {
            return Err(corrupt(
                "partial or indeterminate packet lengths are not allowed in a signature",
            ));
        }
        match p.tag {
            SIGNATURE => sigs.push(bin[p.start..p.end].to_vec()),
            MARKER | PADDING => {}
            40..=63 => ignored += 1,
            t => {
                return Err(corrupt(format!(
                    "a {} packet (type {t}) is not allowed in a signature",
                    tag_name(t)
                )));
            }
        }
    }
    match sigs.len() {
        0 => Err(corrupt("no signature packet")),
        n if n > MAX_SIGNATURES => Err(corrupt(format!(
            "{n} signatures; at most {MAX_SIGNATURES} are allowed"
        ))),
        _ => Ok((sigs, ignored)),
    }
}

/// The binary packets of an armored signature that starts at `start`.
fn dearmor(input: &[u8], start: usize, source: SigSource) -> Result<Vec<u8>, Rejection> {
    const BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";
    const END: &[u8] = b"-----END PGP SIGNATURE-----";
    let text = &input[start..];
    if !text.starts_with(BEGIN) {
        let line = text.split(|&b| b == b'\n').next().unwrap_or_default();
        let name = String::from_utf8_lossy(line);
        return Err(corrupt(format!(
            "expected an armored signature, found {:?}",
            name.trim_matches(|c: char| c == '-' || c.is_whitespace())
        )));
    }
    let footer = text
        .windows(END.len())
        .position(|w| w == END)
        .ok_or_else(|| corrupt("the armor has no end line"))?;
    let mut end = start + footer + END.len();
    if input[end..].starts_with(b"\r\n") {
        end += 2;
    } else if input[end..].starts_with(b"\n") {
        end += 1;
    }
    let rest = &input[end..];
    match source {
        SigSource::File if !rest.iter().all(u8::is_ascii_whitespace) => {
            return Err(corrupt("only whitespace may follow the armor"));
        }
        SigSource::Embedded if !rest.iter().all(|&b| b == 0) => {
            return Err(corrupt(
                "the rest of .sha256_sig after the armor must be zero bytes",
            ));
        }
        _ => {}
    }
    let armor = armor_text(&input[start..end], "signature")?;
    let mut bin = Vec::new();
    pgp::armor::Dearmor::new(armor.as_bytes())
        .read_to_end(&mut bin)
        .map_err(|e| corrupt(format!("bad armor: {e}")))?;
    Ok(bin)
}

fn tag_name(tag: u8) -> &'static str {
    match tag {
        0 => "reserved",
        1 => "public-key encrypted session key",
        3 => "symmetric-key encrypted session key",
        4 => "one-pass signature",
        5 => "secret key",
        6 => "public key",
        7 => "secret subkey",
        8 => "compressed data",
        9 => "symmetrically encrypted data",
        11 => "literal data",
        12 => "trust",
        13 => "user id",
        14 => "public subkey",
        17 => "user attribute",
        18 => "encrypted and integrity protected data",
        19 => "modification detection code",
        20 => "AEAD encrypted data",
        _ => "unassigned critical",
    }
}
