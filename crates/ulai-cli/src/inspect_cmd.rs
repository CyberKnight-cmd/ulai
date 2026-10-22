// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai inspect` and `ulai validate`. Every string that comes from the
//! inspected file is escaped before it reaches the terminal (SPEC §3.5).

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{Context, Result};
use ulai_core::display::escape;
use ulai_core::inspect::{self, Report as InspectReport};
use ulai_core::validate::{self, Report as ValidateReport, Severity};
use ulai_core::verify::{self, Status as SigStatus};

fn emit<T: serde::Serialize>(
    report: &T,
    json: bool,
    human: impl FnOnce(&T) -> String,
) -> Result<()> {
    let text = if json {
        let mut s = serde_json::to_string_pretty(report).context("serialising report")?;
        s.push('\n');
        s
    } else {
        human(report)
    };
    crate::write_stdout(&text)
}

pub fn inspect(
    file: &Path,
    signature: Option<PathBuf>,
    key: Option<PathBuf>,
    json: bool,
) -> Result<ExitCode> {
    let opts = verify::Options {
        signature,
        key,
        ..verify::Options::default()
    };
    let r = inspect::inspect(file, &opts).with_context(|| format!("reading {}", file.display()))?;
    emit(&r, json, inspect_human)?;
    Ok(ExitCode::from(r.status.exit_code()))
}

pub fn validate(file: &Path, json: bool) -> Result<ExitCode> {
    let r = validate::validate(file).with_context(|| format!("reading {}", file.display()))?;
    emit(&r, json, validate_human)?;
    Ok(ExitCode::from(r.status.exit_code()))
}

fn sig_line(s: SigStatus) -> &'static str {
    match s {
        SigStatus::Valid => "✓ signature valid",
        SigStatus::Unsigned => "✗ unsigned",
        SigStatus::SignatureUnverifiable => "? signature found but cannot be checked",
        SigStatus::Invalid => "✗ signature INVALID",
        SigStatus::SignatureFromFuture => "✗ signature dated in the future",
        SigStatus::Corrupt => "✗ signature data corrupt",
        SigStatus::Unsupported => "✗ signature unsupported",
    }
}

fn inspect_human(r: &InspectReport) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "ULAI inspect: {}", escape(&r.file));
    let _ = writeln!(
        o,
        "  {} (run `ulai verify` for details)",
        sig_line(r.signature.status)
    );
    if let Some(s) = &r.signature.signer {
        let _ = writeln!(o, "    key: {}", s.primary_fingerprint);
    }
    if !r.authenticated {
        let _ = writeln!(
            o,
            "  ⚠ everything below is NOT authenticated: it is what the file claims"
        );
    }
    if let Some(c) = &r.container {
        let _ = writeln!(o, "\nContainer");
        let _ = writeln!(
            o,
            "    {} bytes, {:?} {}, {:?} image at offset {}",
            c.size, c.elf_class, c.machine, c.fs, c.fs_offset
        );
        for s in &c.sections {
            let _ = writeln!(
                o,
                "    {:12} offset {:>8}  size {:>5}  used {:>5}",
                s.name, s.offset, s.size, s.used
            );
        }
        if let Some(u) = &c.update_info {
            let _ = writeln!(o, "    update info: {}", escape(u));
        }
    }
    if let Some(reason) = &r.reason {
        let _ = writeln!(o, "  ✗ {}", escape(reason));
    }
    if let Some(c) = &r.contents {
        let _ = writeln!(
            o,
            "\nContents ({} entries, {} files, {} bytes)",
            c.entries, c.files, c.total_bytes
        );
        let _ = writeln!(
            o,
            "    AppRun: {}",
            if c.apprun { "present" } else { "missing" }
        );
        match &c.desktop {
            Some(d) => {
                let _ = writeln!(o, "    desktop entry: {}", escape(&d.path));
                for (k, v) in &d.fields {
                    let _ = writeln!(o, "      {k} = {}", escape(v));
                }
            }
            None => {
                let _ = writeln!(o, "    desktop entry: none");
            }
        }
        if c.desktop_files.len() > 1 {
            let _ = writeln!(
                o,
                "    ⚠ {} desktop entries at the root",
                c.desktop_files.len()
            );
        }
        match &c.icon {
            Some(i) => {
                let _ = writeln!(
                    o,
                    "    icon: {} ({:?}, {} bytes, not decoded)",
                    escape(&i.path),
                    i.kind,
                    i.size
                );
            }
            None => {
                let _ = writeln!(o, "    icon: none");
            }
        }
        let _ = writeln!(o, "\nManifest");
        match (&c.manifest, &c.manifest_error) {
            (Some(m), _) => {
                let _ = writeln!(o, "    id: {}", escape(&m.id));
                let _ = writeln!(o, "    name: {} {}", escape(&m.name), escape(&m.version));
                let _ = writeln!(o, "    summary: {}", escape(&m.summary));
                let _ = writeln!(
                    o,
                    "    runtime: {} (glibc floor {})",
                    escape(&m.runtime_mode),
                    escape(m.glibc_floor.as_deref().unwrap_or("-"))
                );
                let list = |v: &[String]| {
                    if v.is_empty() {
                        "none".to_owned()
                    } else {
                        v.iter().map(|s| escape(s)).collect::<Vec<_>>().join(", ")
                    }
                };
                let _ = writeln!(o, "    permissions: {}", list(&m.permissions));
                if !m.sensitive_permissions.is_empty() {
                    let _ = writeln!(
                        o,
                        "    ⚠ sensitive permissions: {}",
                        list(&m.sensitive_permissions)
                    );
                }
                if !m.own_paths.is_empty() {
                    let _ = writeln!(o, "    own paths: {}", list(&m.own_paths));
                }
                for p in &c.manifest_problems {
                    let _ = writeln!(o, "    ✗ {}: {}", escape(&p.field), escape(&p.message));
                }
            }
            (None, Some(e)) => {
                let _ = writeln!(o, "    ✗ {}", escape(e));
            }
            (None, None) => {
                let _ = writeln!(o, "    none: a legacy AppImage, not a ULAI file");
            }
        }
    }
    o
}

fn validate_human(r: &ValidateReport) -> String {
    let mut o = String::new();
    let _ = writeln!(o, "ULAI validate: {}", escape(&r.file));
    let verdict = match r.status {
        validate::Status::Conforms => "✓ conforms to the ULAI format",
        validate::Status::DoesNotConform => "✗ does not conform",
        validate::Status::Corrupt => "✗ corrupt",
        validate::Status::Unsupported => "✗ unsupported",
    };
    let _ = writeln!(o, "  {verdict}");
    for f in &r.findings {
        let mark = match f.severity {
            Severity::Error => "✗",
            Severity::Warning => "⚠",
            Severity::Info => " ",
        };
        let at = f
            .path
            .as_deref()
            .map(|p| format!(" [{}]", escape(p)))
            .unwrap_or_default();
        let _ = writeln!(o, "  {mark} {}{at}: {}", f.check, escape(&f.message));
    }
    let s = &r.summary;
    let _ = writeln!(
        o,
        "  {} ELF files; highest GLIBC {}, GLIBCXX {}, CXXABI {}",
        s.elf_files,
        s.max_glibc.as_deref().unwrap_or("-"),
        s.max_glibcxx.as_deref().unwrap_or("-"),
        s.max_cxxabi.as_deref().unwrap_or("-")
    );
    o
}
