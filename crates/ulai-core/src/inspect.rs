// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai inspect`: what is in an AppImage, without executing it.
//!
//! The signature is checked first (SPEC §3.2). Everything shown from a file
//! whose signature is not valid is marked as not authenticated. All strings
//! come from the file and must be escaped before printing (`display`).

use std::path::Path;

use serde::Serialize;

use crate::appdir::{self, DesktopEntry, Icon};
use crate::appimage::{ByteRange, Container, ContainerError, ElfClass, FsKind};
use crate::imagefs::{EntryKind, FsError, ImageFs, Limits};
use crate::manifest::{self, Manifest, Problem};
use crate::verify::{self, MANIFEST_PATH};

pub const SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Ok,
    Corrupt,
    Unsupported,
}

impl Status {
    pub fn exit_code(self) -> u8 {
        match self {
            Status::Ok => 0,
            Status::Corrupt | Status::Unsupported => 5,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Section {
    pub name: &'static str,
    pub offset: u64,
    pub size: u64,
    /// Bytes before the NUL padding.
    pub used: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ContainerInfo {
    pub size: u64,
    pub elf_class: ElfClass,
    pub machine: String,
    pub fs: FsKind,
    pub fs_offset: u64,
    pub sections: Vec<Section>,
    /// `.upd_info` text, if any (untrusted).
    pub update_info: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Contents {
    pub entries: usize,
    pub files: usize,
    pub total_bytes: u64,
    pub apprun: bool,
    pub desktop_files: Vec<String>,
    pub desktop: Option<DesktopEntry>,
    pub icon: Option<Icon>,
    pub ulai_file: bool,
    pub manifest: Option<Manifest>,
    pub manifest_error: Option<String>,
    pub manifest_problems: Vec<Problem>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    pub status: Status,
    pub file: String,
    /// True only if the signature is valid; all content below is
    /// unauthenticated otherwise.
    pub authenticated: bool,
    pub signature: verify::Report,
    pub container: Option<ContainerInfo>,
    pub contents: Option<Contents>,
    pub reason: Option<String>,
}

pub fn inspect(path: &Path, opts: &verify::Options) -> std::io::Result<Report> {
    let signature = verify::verify(path, opts)?;
    let mut report = Report {
        schema: SCHEMA_VERSION,
        status: Status::Ok,
        file: path.display().to_string(),
        authenticated: signature.status == verify::Status::Valid,
        signature,
        container: None,
        contents: None,
        reason: None,
    };
    let c = match Container::open(path) {
        Ok(c) => c,
        Err(ContainerError::Io(e)) => return Err(e),
        Err(e @ ContainerError::Corrupt(_)) => {
            return Ok(fail(report, Status::Corrupt, e.to_string()));
        }
        Err(e) => return Ok(fail(report, Status::Unsupported, e.to_string())),
    };
    let sections = section_list(&c)?;
    let update_info = c
        .section_bytes(&c.sections.update_info)?
        .map(|b| String::from_utf8_lossy(trim_nul(&b)).into_owned())
        .filter(|s| !s.is_empty());
    report.container = Some(ContainerInfo {
        size: c.len(),
        elf_class: c.class,
        machine: c.machine_name(),
        fs: c.fs_kind,
        fs_offset: c.fs_offset,
        sections,
        update_info,
    });

    let fs = match ImageFs::open(&c, Limits::default()) {
        Ok(fs) => fs,
        Err(FsError::Io(e)) => return Err(e),
        Err(e @ FsError::Unsupported(_)) => {
            return Ok(fail(report, Status::Unsupported, e.to_string()));
        }
        Err(e) => return Ok(fail(report, Status::Corrupt, e.to_string())),
    };
    let mut contents = Contents::default();
    for e in fs.entries() {
        contents.entries += 1;
        if let EntryKind::File { size } = e.kind {
            contents.files += 1;
            contents.total_bytes += size;
        }
    }
    contents.apprun = fs.resolve("AppRun").is_ok();
    contents.desktop_files = appdir::root_desktop_files(&fs);
    if let Some(first) = contents.desktop_files.first() {
        contents.desktop = appdir::read_desktop_entry(&fs, first).ok();
    }
    let icon_key = contents
        .desktop
        .as_ref()
        .and_then(|d| d.fields.get("Icon").cloned());
    contents.icon = appdir::find_icon(&fs, icon_key.as_deref());
    match fs.read(MANIFEST_PATH, manifest::MAX_BYTES as u64) {
        Ok(bytes) => {
            contents.ulai_file = true;
            match manifest::parse(&bytes) {
                Ok(m) => {
                    contents.manifest_problems = manifest::validate(&m);
                    contents.manifest = Some(m);
                }
                Err(e) => contents.manifest_error = Some(e.to_string()),
            }
        }
        Err(FsError::NotFound(_)) => {}
        Err(e) => {
            contents.ulai_file = true;
            contents.manifest_error = Some(e.to_string());
        }
    }
    report.contents = Some(contents);
    Ok(report)
}

fn fail(mut r: Report, status: Status, reason: String) -> Report {
    r.status = status;
    r.reason = Some(reason);
    r
}

fn trim_nul(b: &[u8]) -> &[u8] {
    &b[..b.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1)]
}

fn section_list(c: &Container) -> std::io::Result<Vec<Section>> {
    let s = &c.sections;
    let all: [(&'static str, &Option<ByteRange>); 4] = [
        (crate::appimage::SECTION_DIGEST_MD5, &s.digest_md5),
        (crate::appimage::SECTION_UPDATE_INFO, &s.update_info),
        (crate::appimage::SECTION_SIGNATURE, &s.signature),
        (crate::appimage::SECTION_KEY, &s.key),
    ];
    let mut out = Vec::new();
    for (name, range) in all {
        let Some(r) = range else { continue };
        let used = c
            .section_bytes(range)?
            .map_or(0, |b| trim_nul(&b).len() as u64);
        out.push(Section {
            name,
            offset: r.start,
            size: r.end - r.start,
            used,
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::*;

    fn fixture(name: &str) -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/appimage")
            .join(name)
    }

    #[test]
    fn signed_ulai_fixture() {
        let r = inspect(
            &fixture("upstream-ed25519.AppImage"),
            &verify::Options::default(),
        )
        .unwrap();
        assert_eq!(r.status, Status::Ok);
        assert!(r.authenticated);
        let c = r.contents.unwrap();
        assert!(c.ulai_file && c.apprun);
        assert_eq!(c.manifest.unwrap().id, "org.ulai.Fixture");
        assert!(c.manifest_problems.is_empty());
        assert_eq!(c.desktop.unwrap().fields["Name"], "ULAI Fixture");
        let icon = c.icon.unwrap();
        assert_eq!(
            (icon.kind, icon.path.as_str()),
            (appdir::IconType::Png, "org.ulai.Fixture.png")
        );
        let cont = r.container.unwrap();
        assert_eq!(cont.sections.len(), 4);
        assert!(
            cont.sections
                .iter()
                .any(|s| s.name == ".sig_key" && s.used > 0)
        );
    }

    #[test]
    fn legacy_fixture_is_not_authenticated() {
        let r = inspect(
            &fixture("legacy-unsigned.AppImage"),
            &verify::Options::default(),
        )
        .unwrap();
        assert_eq!(r.status, Status::Ok);
        assert!(!r.authenticated);
        assert_eq!(r.signature.status, verify::Status::SignatureUnverifiable);
        assert!(!r.contents.unwrap().ulai_file);
    }
}
