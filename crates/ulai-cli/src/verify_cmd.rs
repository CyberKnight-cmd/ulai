// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai verify`.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use ulai_core::display::escape;
use ulai_core::verify::{self, KeySource, Method, Options, Report, Status};

pub fn run(
    file: &Path,
    signature: Option<PathBuf>,
    key: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode> {
    let opts = Options {
        signature,
        key,
        ..Options::default()
    };
    let report =
        verify::verify(file, &opts).with_context(|| format!("reading {}", file.display()))?;
    let text = if json {
        let mut s = serde_json::to_string_pretty(&report).context("serialising report")?;
        s.push('\n');
        s
    } else {
        human(&report)
    };
    crate::write_stdout(&text)?;
    Ok(ExitCode::from(report.status.exit_code()))
}

/// Full fingerprint in groups of four hex digits.
fn grouped(fpr: &str) -> String {
    fpr.as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c))
        .collect::<Vec<_>>()
        .join(" ")
}

/// Unix seconds → `YYYY-MM-DD HH:MM:SS UTC` (civil-from-days, no time zone
/// database needed).
fn utc(secs: u64) -> String {
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
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02} UTC",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

fn human(r: &Report) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "ULAI verify: {}", escape(&r.file));
    let (mark, word) = match r.status {
        Status::Valid => ("✓", "valid"),
        Status::Unsigned => ("✗", "unsigned"),
        Status::SignatureUnverifiable => ("?", "signature cannot be checked"),
        Status::Invalid => ("✗", "INVALID"),
        Status::Corrupt => ("✗", "corrupt"),
        Status::Unsupported => ("✗", "unsupported"),
    };
    let how = match (r.method, r.key_source) {
        (Some(Method::Embedded), Some(KeySource::Embedded)) => {
            " (embedded signature, key embedded in the file)"
        }
        (Some(Method::Embedded), Some(KeySource::Supplied)) => {
            " (embedded signature, key supplied by you)"
        }
        (Some(Method::Detached), Some(KeySource::Supplied)) => {
            " (detached signature, key supplied by you)"
        }
        (Some(Method::Embedded), None) => " (embedded signature)",
        (Some(Method::Detached), None) => " (detached signature)",
        _ => "",
    };
    let _ = writeln!(o, "  {mark} {word}{how}");
    if let Some(reason) = &r.reason {
        let _ = writeln!(o, "    {}", escape(reason));
    }
    if let Some(sig) = &r.signature_file {
        let _ = writeln!(o, "    signature file: {}", escape(sig));
    }
    if let Some(s) = &r.signer {
        let _ = writeln!(o, "    primary key:    {}", grouped(&s.primary_fingerprint));
        if s.signed_by_subkey {
            let _ = writeln!(o, "    signing subkey: {}", grouped(&s.signing_fingerprint));
        }
        for uid in &s.user_ids {
            let _ = writeln!(o, "    user id:        {}  (unverified claim)", escape(uid));
        }
        let algo = match s.rsa_bits {
            Some(bits) => format!("{}-{bits}", s.algorithm),
            None => s.algorithm.clone(),
        };
        let _ = writeln!(
            o,
            "    algorithm:      {algo}, v{} key, {} signature, {}",
            s.key_version, s.signature_type, s.hash
        );
        let _ = writeln!(o, "    signed:         {}", utc(s.created));
        if let Some(exp) = s.key_expires {
            let _ = writeln!(o, "    key expires:    {}", utc(exp));
        }
    }
    for w in &r.warnings {
        let _ = writeln!(o, "  ⚠ {}", escape(w));
    }
    if r.status == Status::Valid {
        let note = match r.method {
            Some(Method::Detached) => {
                "valid only means this key signed the file; check that the fingerprint belongs to the publisher"
            }
            _ => {
                "valid only means the file was signed by the key embedded in it; trust comes from pinning that key (M3)"
            }
        };
        let _ = writeln!(o, "    note: {note}");
    }
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn utc_dates() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(1_577_836_800), "2020-01-01 00:00:00 UTC");
        assert_eq!(utc(1_789_027_275), "2026-09-10 08:01:15 UTC");
        assert_eq!(utc(951_782_400), "2000-02-29 00:00:00 UTC");
    }

    /// A GnuPG-made key whose user id carries RLO and LRI
    /// (tests/fixtures/openpgp, case bidi-uid).
    #[test]
    fn hostile_user_id_cannot_reorder_the_output() {
        let dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/openpgp");
        let read = |n: &str| std::fs::read(dir.join(n)).unwrap();
        let accepted = ulai_core::signature::verify_detached(
            &read("bidi-uid.key.asc"),
            &read("bidi-uid.sig.asc"),
            read("msg").as_slice(),
            std::time::SystemTime::now(),
        )
        .unwrap();
        assert!(
            accepted.signer.user_ids[0].contains('\u{202E}'),
            "fixture has the RLO"
        );
        let report = Report {
            schema: 1,
            status: Status::Valid,
            file: "app.AppImage".into(),
            method: Some(Method::Detached),
            key_source: Some(KeySource::Supplied),
            signature_file: Some("app.AppImage.sig".into()),
            fs: None,
            ulai_file: Some(false),
            signer: Some(accepted.signer.clone()),
            warnings: vec![],
            reason: None,
        };
        let text = human(&report);
        for line in text.lines() {
            assert!(!line.chars().any(ulai_core::display::is_unsafe), "{line:?}");
        }
        assert!(text.contains("\\u{202E}FE3C 2B1A\\u{2066}"), "{text}");
        assert!(text.contains(&grouped(&accepted.signer.primary_fingerprint)));
    }

    #[test]
    fn fingerprints_are_grouped_in_full() {
        assert_eq!(
            grouped("E9FB29E74ADEACC5E3035B8AB69EB4CF7468332F"),
            "E9FB 29E7 4ADE ACC5 E303 5B8A B69E B4CF 7468 332F"
        );
    }
}
