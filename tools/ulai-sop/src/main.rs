// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai-sop`: the `version` and `verify` subcommands of the Stateless
//! OpenPGP CLI (draft-dkg-openpgp-stateless-cli), on top of ULAI's own
//! verifier and policy. Everything else is UNSUPPORTED_SUBCOMMAND.
//!
//! rPGP is used only to split inputs that hold several signatures or
//! certificates; each (signature, certificate) pair is then checked by
//! `ulai_core::signature::verify_detached`, exactly as `ulai verify` does.

#![forbid(unsafe_code)]

use std::io::Read;
use std::process::ExitCode;
use std::time::SystemTime;

use pgp::composed::{Deserializable, DetachedSignature, SignedPublicKey};
use pgp::ser::Serialize;

const NO_SIGNATURE: u8 = 3;
const MISSING_ARG: u8 = 19;
const BAD_DATA: u8 = 41;
const UNSUPPORTED_OPTION: u8 = 37;
const UNSUPPORTED_SUBCOMMAND: u8 = 69;

fn is_armor(b: &[u8]) -> bool {
    let s = b.iter().position(|c| !c.is_ascii_whitespace()).unwrap_or(0);
    b[s..].starts_with(b"-----BEGIN PGP ")
}

/// Every signature packet in `bytes`, re-serialised one by one.
fn split_signatures(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let sigs: Vec<DetachedSignature> = if is_armor(bytes) {
        let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        let (iter, _) = DetachedSignature::from_string_many(text).map_err(|e| e.to_string())?;
        iter.collect::<Result<_, _>>().map_err(|e| e.to_string())?
    } else {
        DetachedSignature::from_bytes_many(bytes)
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?
    };
    sigs.iter()
        .map(|s| s.to_bytes().map_err(|e| e.to_string()))
        .collect()
}

/// Every certificate in `bytes`, re-serialised one by one.
fn split_certs(bytes: &[u8]) -> Result<Vec<Vec<u8>>, String> {
    let keys: Vec<SignedPublicKey> = if is_armor(bytes) {
        let text = std::str::from_utf8(bytes).map_err(|e| e.to_string())?;
        let (iter, _) = SignedPublicKey::from_string_many(text).map_err(|e| e.to_string())?;
        iter.collect::<Result<_, _>>().map_err(|e| e.to_string())?
    } else {
        SignedPublicKey::from_bytes_many(bytes)
            .map_err(|e| e.to_string())?
            .collect::<Result<_, _>>()
            .map_err(|e| e.to_string())?
    };
    keys.iter()
        .map(|k| k.to_bytes().map_err(|e| e.to_string()))
        .collect()
}

/// Unix seconds → ISO 8601 UTC.
fn iso8601(secs: u64) -> String {
    let days = (secs / 86_400) as i64;
    let rem = secs % 86_400;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn verify(args: &[String]) -> ExitCode {
    let mut files = Vec::new();
    for a in args {
        if a.starts_with("--not-before") || a.starts_with("--not-after") {
            eprintln!("ulai-sop: {a} is not supported");
            return ExitCode::from(UNSUPPORTED_OPTION);
        } else if a.starts_with("--") {
            eprintln!("ulai-sop: unknown option {a}");
            return ExitCode::from(UNSUPPORTED_OPTION);
        }
        files.push(a);
    }
    if files.len() < 2 {
        eprintln!("ulai-sop: verify needs SIGNATURES and at least one CERTS");
        return ExitCode::from(MISSING_ARG);
    }
    let read = |p: &str| std::fs::read(p).map_err(|e| format!("{p}: {e}"));
    let mut data = Vec::new();
    if std::io::stdin().read_to_end(&mut data).is_err() {
        return ExitCode::from(BAD_DATA);
    }
    let sigs = match read(files[0]).and_then(|b| split_signatures(&b)) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("ulai-sop: signatures: {e}");
            return ExitCode::from(BAD_DATA);
        }
    };
    let mut certs = Vec::new();
    for f in &files[1..] {
        match read(f).and_then(|b| split_certs(&b)) {
            Ok(c) => certs.extend(c),
            Err(e) => {
                eprintln!("ulai-sop: certs: {e}");
                return ExitCode::from(BAD_DATA);
            }
        }
    }
    let mut good = 0;
    for sig in &sigs {
        for cert in &certs {
            match ulai_core::signature::verify_detached(
                cert,
                sig,
                data.as_slice(),
                SystemTime::now(),
            ) {
                Ok(a) => {
                    good += 1;
                    let s = &a.signer;
                    println!(
                        "{} {} {} mode:{}",
                        iso8601(s.created),
                        s.signing_fingerprint,
                        s.primary_fingerprint,
                        s.signature_type
                    );
                    break;
                }
                Err(e) => eprintln!("ulai-sop: {e}"),
            }
        }
    }
    if good == 0 {
        ExitCode::from(NO_SIGNATURE)
    } else {
        ExitCode::SUCCESS
    }
}

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match args.first().map(String::as_str) {
        Some("version") => {
            if args.iter().any(|a| a == "--backend") {
                println!("ulai-core {} (rPGP 0.21)", env!("CARGO_PKG_VERSION"));
            } else if args.iter().any(|a| a == "--extended") {
                println!(
                    "ulai-sop {}\nulai-core verifier with ULAI's signature policy (SPEC 3.2)",
                    env!("CARGO_PKG_VERSION")
                );
            } else {
                println!("ulai-sop {}", env!("CARGO_PKG_VERSION"));
            }
            ExitCode::SUCCESS
        }
        Some("verify") => verify(&args[1..]),
        Some(other) => {
            eprintln!("ulai-sop: {other} is not supported (only version and verify)");
            ExitCode::from(UNSUPPORTED_SUBCOMMAND)
        }
        None => {
            eprintln!("usage: ulai-sop version | verify SIGNATURES CERTS... < DATA");
            ExitCode::from(MISSING_ARG)
        }
    }
}
