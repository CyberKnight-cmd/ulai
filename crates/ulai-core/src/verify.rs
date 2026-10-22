// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai verify`: embedded signatures (SPEC §3.2) and, for legacy
//! AppImages, detached signatures (ADR-016). Statuses and exit codes are
//! stable API (SPEC §16).
//!
//! The signature itself needs only the ELF and its sections, so it works on
//! DwarFS images too. The filesystem is read for one decision only: whether
//! the file is a ULAI file, for which detached signatures are ignored.

use std::fs::File;
use std::io::{self, Read};
use std::os::unix::fs::FileExt;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::Serialize;

use crate::appimage::{Container, ContainerError, FsKind};
use crate::imagefs::{ImageFs, Limits};
use crate::signature::{self, MAX_ARMOR_BYTES, Rejection, Signer};

/// Version of the `ulai verify --json` output.
pub const SCHEMA_VERSION: u32 = 1;

/// Path of the ULAI manifest inside the image (SPEC §4).
pub const MANIFEST_PATH: &str = ".ulai/manifest.json";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Valid,
    Unsigned,
    SignatureUnverifiable,
    Invalid,
    /// A signature was created more than 30 minutes after the verifier's
    /// clock (SPEC §3.2). Exit code as `invalid`.
    SignatureFromFuture,
    Corrupt,
    Unsupported,
}

impl Status {
    /// Stable exit codes (SPEC §16).
    pub fn exit_code(self) -> u8 {
        match self {
            Status::Valid => 0,
            Status::Unsigned | Status::SignatureUnverifiable => 3,
            Status::Invalid | Status::SignatureFromFuture => 4,
            Status::Corrupt | Status::Unsupported => 5,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    /// `.sha256_sig` inside the file.
    Embedded,
    /// A separate signature file (ADR-016).
    Detached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum KeySource {
    /// `.sig_key` inside the file.
    Embedded,
    /// `--key`.
    Supplied,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    pub status: Status,
    pub file: String,
    pub method: Option<Method>,
    pub key_source: Option<KeySource>,
    /// The detached signature file that was used or found.
    pub signature_file: Option<String>,
    pub fs: Option<FsKind>,
    /// Whether the image contains `/.ulai/manifest.json`; `null` if unknown.
    pub ulai_file: Option<bool>,
    pub signer: Option<Signer>,
    pub warnings: Vec<String>,
    /// Why the status is not `valid`.
    pub reason: Option<String>,
}

#[derive(Debug, Clone)]
pub struct Options {
    /// `--signature`: a detached signature file.
    pub signature: Option<PathBuf>,
    /// `--key`: a public key file.
    pub key: Option<PathBuf>,
    /// Current time, for "expired since signing" warnings.
    pub now: SystemTime,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            signature: None,
            key: None,
            now: SystemTime::now(),
        }
    }
}

impl Report {
    fn new(path: &Path) -> Self {
        Self {
            schema: SCHEMA_VERSION,
            status: Status::Unsigned,
            file: path.display().to_string(),
            method: None,
            key_source: None,
            signature_file: None,
            fs: None,
            ulai_file: None,
            signer: None,
            warnings: Vec::new(),
            reason: None,
        }
    }

    fn reject(mut self, r: Rejection) -> Self {
        let (status, reason) = match r {
            Rejection::Invalid(m) => (Status::Invalid, m),
            Rejection::Corrupt(m) => (Status::Corrupt, m),
            Rejection::Unsupported(m) => (Status::Unsupported, m),
            Rejection::FromFuture { what, seconds } => (
                Status::SignatureFromFuture,
                format!(
                    "{what} was created {} in the future; check that this computer's clock is set correctly",
                    signature::human_duration(&seconds)
                ),
            ),
        };
        self.status = status;
        self.reason = Some(reason);
        self
    }

    fn with(mut self, status: Status, reason: impl Into<String>) -> Self {
        self.status = status;
        self.reason = Some(reason.into());
        self
    }
}

/// Verifies the AppImage at `path`. Only I/O errors on files the caller
/// named (the AppImage, `--signature`, `--key`) are returned as `Err`
/// (exit 1); every finding about the file itself is a [`Report`].
pub fn verify(path: &Path, opts: &Options) -> io::Result<Report> {
    let mut report = Report::new(path);
    let container = match Container::open(path) {
        Ok(c) => c,
        Err(ContainerError::Io(e)) => return Err(e),
        Err(
            e
            @ (ContainerError::NotElf | ContainerError::NotType2 | ContainerError::Unsupported(_)),
        ) => {
            return Ok(report.with(Status::Unsupported, e.to_string()));
        }
        Err(e @ ContainerError::Corrupt(_)) => {
            return Ok(report.with(Status::Corrupt, e.to_string()));
        }
    };
    report.fs = Some(container.fs_kind);

    let embedded_sig = nonempty(container.section_bytes(&container.sections.signature)?);
    if let Some(sig) = embedded_sig {
        report.method = Some(Method::Embedded);
        if opts.signature.is_some() {
            report
                .warnings
                .push("the file has an embedded signature; --signature was ignored".into());
        }
        let key = match nonempty(container.section_bytes(&container.sections.key)?) {
            Some(k) => {
                report.key_source = Some(KeySource::Embedded);
                k
            }
            None => match &opts.key {
                Some(p) => {
                    report.key_source = Some(KeySource::Supplied);
                    match read_small(p, "key")? {
                        Ok(k) => k,
                        Err(m) => return Ok(report.with(Status::Unsupported, m)),
                    }
                }
                None => {
                    return Ok(report.with(
                        Status::SignatureUnverifiable,
                        "the file is signed, but .sig_key holds no key; pass --key",
                    ));
                }
            },
        };
        let digest = container.signature_digest_hex()?;
        return Ok(finish(
            report,
            signature::verify_detached(&key, &sig, digest.as_bytes(), opts.now),
        ));
    }

    // No embedded signature. A ULAI file must have one (ADR-016).
    report.ulai_file = is_ulai_file(&container);
    if report.ulai_file == Some(true) {
        return Ok(report.with(
            Status::Unsigned,
            "ULAI files must carry an embedded signature; detached signatures are ignored (ADR-016)",
        ));
    }

    let sig_path = match &opts.signature {
        Some(p) => Some(p.clone()),
        None => match discover(path) {
            Discovery::None => None,
            Discovery::One(p) => Some(p),
            Discovery::Ambiguous(a, b) => {
                return Ok(report.with(
                    Status::SignatureUnverifiable,
                    format!(
                        "both {} and {} exist; choose one with --signature",
                        a.display(),
                        b.display()
                    ),
                ));
            }
        },
    };
    let Some(sig_path) = sig_path else {
        return Ok(report.with(
            Status::Unsigned,
            "no embedded signature and no detached signature",
        ));
    };
    report.method = Some(Method::Detached);
    report.signature_file = Some(sig_path.display().to_string());
    let sig = match read_small(&sig_path, "signature")? {
        Ok(s) => s,
        Err(m) => return Ok(report.with(Status::Unsupported, m)),
    };
    let Some(key_path) = &opts.key else {
        return Ok(report.with(
            Status::SignatureUnverifiable,
            "a detached signature was found, but no key is available; pass --key",
        ));
    };
    report.key_source = Some(KeySource::Supplied);
    let key = match read_small(key_path, "key")? {
        Ok(k) => k,
        Err(m) => return Ok(report.with(Status::Unsupported, m)),
    };
    let data = io::BufReader::with_capacity(
        1 << 20,
        PositionedReader {
            file: container.file(),
            pos: 0,
        },
    );
    Ok(finish(
        report,
        signature::verify_detached(&key, &sig, data, opts.now),
    ))
}

fn finish(mut report: Report, result: Result<signature::Accepted, Rejection>) -> Report {
    match result {
        Ok(a) => {
            report.status = Status::Valid;
            report.signer = Some(a.signer);
            report.warnings.extend(a.warnings);
            report
        }
        Err(r) => report.reject(r),
    }
}

/// `Some` only if the section exists and holds something other than NULs.
fn nonempty(section: Option<Vec<u8>>) -> Option<Vec<u8>> {
    section.filter(|b| b.iter().any(|&x| x != 0))
}

/// Whether the image contains the ULAI manifest. DwarFS images cannot be
/// ULAI files (SPEC §3). `None` when the SquashFS image cannot be read.
fn is_ulai_file(container: &Container) -> Option<bool> {
    match container.fs_kind {
        FsKind::Dwarfs => Some(false),
        FsKind::Squashfs => {
            let fs = ImageFs::open(container, Limits::default()).ok()?;
            Some(fs.resolve(MANIFEST_PATH).is_ok())
        }
    }
}

enum Discovery {
    None,
    One(PathBuf),
    Ambiguous(PathBuf, PathBuf),
}

/// Exactly `<file>.sig` or `<file>.asc` next to the file (ADR-016).
fn discover(path: &Path) -> Discovery {
    let with = |ext: &str| {
        let mut s = path.as_os_str().to_owned();
        s.push(ext);
        PathBuf::from(s)
    };
    let (sig, asc) = (with(".sig"), with(".asc"));
    match (sig.is_file(), asc.is_file()) {
        (true, true) => Discovery::Ambiguous(sig, asc),
        (true, false) => Discovery::One(sig),
        (false, true) => Discovery::One(asc),
        (false, false) => Discovery::None,
    }
}

/// Reads a key or signature file the user named. Over the size limit, the
/// inner `Err` says why (status `unsupported`).
fn read_small(path: &Path, what: &str) -> io::Result<Result<Vec<u8>, String>> {
    let mut buf = Vec::new();
    File::open(path)?
        .take(MAX_ARMOR_BYTES as u64 + 1)
        .read_to_end(&mut buf)?;
    if buf.len() <= MAX_ARMOR_BYTES {
        return Ok(Ok(buf));
    }
    let mut m = format!(
        "the {what} file {} is larger than ULAI's limit of {} KiB",
        path.display(),
        MAX_ARMOR_BYTES / 1024
    );
    if what == "key" {
        m.push_str(
            "; export only the key and its self-signatures, without third-party \
             certifications: gpg --export --export-options export-minimal <fingerprint>",
        );
    }
    Ok(Err(m))
}

/// Streams the whole file through the already open handle (positioned reads
/// do not depend on, or move, the shared file offset).
struct PositionedReader<'a> {
    file: &'a File,
    pos: u64,
}

impl Read for PositionedReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let n = self.file.read_at(buf, self.pos)?;
        self.pos += n as u64;
        Ok(n)
    }
}

#[cfg(test)]
mod tests;
