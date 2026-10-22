// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai validate`: does a file conform to the ULAI format (SPEC §3, §4,
//! §11.1)? Reads the image in-process; nothing is executed.

use std::path::Path;

use serde::Serialize;

use crate::appdir::{find_icon, read_desktop_entry, root_desktop_files};
use crate::appimage::{Container, ContainerError, FsKind};
use crate::elfinfo::{self, ElfInfo};
use crate::imagefs::{EntryKind, FsError, ImageFs, Limits};
use crate::manifest::{self, Manifest};
use crate::verify::{self, MANIFEST_PATH};

pub const SCHEMA_VERSION: u32 = 1;
/// Largest bundled ELF file ULAI will read to check it.
pub const MAX_ELF_BYTES: u64 = 1 << 30;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// Short name of the check, e.g. `excluded_library`.
    pub check: &'static str,
    /// Path inside the image, or a manifest field, if any.
    pub path: Option<String>,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// No errors (warnings allowed).
    Conforms,
    DoesNotConform,
    Corrupt,
    Unsupported,
}

impl Status {
    /// Exit codes (SPEC §16).
    pub fn exit_code(self) -> u8 {
        match self {
            Status::Conforms => 0,
            Status::DoesNotConform => 4,
            Status::Corrupt | Status::Unsupported => 5,
        }
    }
}

/// Data SPEC §11.2 needs about the bundled C++ runtime.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct Summary {
    pub elf_files: usize,
    pub max_glibc: Option<String>,
    pub max_glibcxx: Option<String>,
    pub max_cxxabi: Option<String>,
    pub libstdcxx_bundled: bool,
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub schema: u32,
    pub status: Status,
    pub file: String,
    pub signature: Option<verify::Status>,
    pub findings: Vec<Finding>,
    pub summary: Summary,
}

/// What SPEC §11.1 says about a bundled library name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LibClass {
    /// glibc or the dynamic loader: must come from the host.
    Glibc,
    /// The GPU and driver stack: must come from the host.
    Gpu,
    /// Report and point to SPEC §11.2.
    Warn,
}

fn so_base(name: &str, base: &str) -> bool {
    // libc.so, libc.so.6, libc-2.31.so — but not libcairo.so.
    name == format!("{base}.so")
        || name.starts_with(&format!("{base}.so."))
        || (name.starts_with(&format!("{base}-")) && name.contains(".so"))
}

/// `base.so`, `base.so.N…`, or `base_variant…` (the Mesa/NVIDIA naming,
/// e.g. `libdrm_amdgpu.so.1`, `libEGL_mesa.so.0`). A hyphen does not
/// continue the family: `libdrm-egl-server.so` is a Qt plugin.
fn family(name: &str, base: &str) -> bool {
    name.strip_prefix(base)
        .is_some_and(|rest| rest == ".so" || rest.starts_with(".so.") || rest.starts_with('_'))
}

/// Classifies a library by its soname (or file name), per SPEC §11.1.
///
/// Families match `base.so*` and `base_*` only. So `libGL*` covers
/// `libGL.so.1` but not libGLU or libGLEW (ordinary application libraries),
/// and `libvulkan*` covers the loader and Mesa ICDs (`libvulkan_intel.so`)
/// but not Qt's `libvulkan-server.so`.
pub fn classify(name: &str) -> Option<LibClass> {
    const GLIBC: &[&str] = &[
        "libc",
        "libm",
        "libdl",
        "libpthread",
        "librt",
        "libresolv",
        "libutil",
        "libanl",
    ];
    if GLIBC.iter().any(|b| so_base(name, b)) || name.starts_with("ld-linux") {
        return Some(LibClass::Glibc);
    }
    const GPU: &[&str] = &[
        "libGL",
        "libEGL",
        "libGLX",
        "libGLdispatch",
        "libOpenGL",
        "libGLESv1_CM",
        "libGLESv2",
        "libvulkan",
        "libgbm",
        "libdrm",
        "libglapi",
        "libOSMesa",
        "libxatracker",
        "libcuda",
    ];
    // Driver files that use a hyphen or a suffix rather than a family name.
    let driver_file = name.ends_with("_dri.so")
        || name.starts_with("libgallium-")
        || name.starts_with("libnvidia-")
        || name == "nvidia_drv.so";
    if driver_file || GPU.iter().any(|b| family(name, b)) {
        return Some(LibClass::Gpu);
    }
    if so_base(name, "libstdc++")
        || so_base(name, "libgcc_s")
        || name.starts_with("libLLVM")
        || so_base(name, "libfontconfig")
    {
        return Some(LibClass::Warn);
    }
    None
}

struct Out {
    findings: Vec<Finding>,
}

impl Out {
    fn add(
        &mut self,
        severity: Severity,
        check: &'static str,
        path: Option<&str>,
        message: impl Into<String>,
    ) {
        self.findings.push(Finding {
            severity,
            check,
            path: path.map(str::to_owned),
            message: message.into(),
        });
    }
}

pub fn validate(path: &Path) -> std::io::Result<Report> {
    let mut report = Report {
        schema: SCHEMA_VERSION,
        status: Status::Conforms,
        file: path.display().to_string(),
        signature: None,
        findings: Vec::new(),
        summary: Summary::default(),
    };
    let container = match Container::open(path) {
        Ok(c) => c,
        Err(ContainerError::Io(e)) => return Err(e),
        Err(e @ ContainerError::Corrupt(_)) => {
            return Ok(fatal(report, Status::Corrupt, e.to_string()));
        }
        Err(e) => return Ok(fatal(report, Status::Unsupported, e.to_string())),
    };
    if container.fs_kind == FsKind::Dwarfs {
        return Ok(fatal(
            report,
            Status::Unsupported,
            "DwarFS images cannot be validated yet; ULAI files use SquashFS",
        ));
    }
    let fs = match ImageFs::open(&container, Limits::default()) {
        Ok(fs) => fs,
        Err(FsError::Io(e)) => return Err(e),
        Err(e @ FsError::Unsupported(_)) => {
            return Ok(fatal(report, Status::Unsupported, e.to_string()));
        }
        Err(e) => return Ok(fatal(report, Status::Corrupt, e.to_string())),
    };
    let mut out = Out {
        findings: Vec::new(),
    };

    // Signature (SPEC §3 item 5): unsigned is allowed for development builds.
    let sig = verify::verify(path, &verify::Options::default())?;
    report.signature = Some(sig.status);
    match sig.status {
        verify::Status::Valid => {}
        verify::Status::Unsigned | verify::Status::SignatureUnverifiable => out.add(
            Severity::Warning,
            "signature",
            None,
            "not signed: acceptable for development builds only; installed as Strict by default",
        ),
        s => out.add(
            Severity::Error,
            "signature",
            None,
            format!("signature is {s:?}: {}", sig.reason.unwrap_or_default()),
        ),
    }

    // Manifest (SPEC §4).
    let manifest = check_manifest(&fs, &mut out);

    // AppDir conventions (SPEC §3 item 3).
    let entry = manifest
        .as_ref()
        .map_or("AppRun", Manifest::entry)
        .to_owned();
    match fs.resolve(&entry).map(|p| fs.get(&p).cloned()) {
        Ok(Some(e)) if matches!(e.kind, EntryKind::File { .. }) => {
            if e.mode & 0o111 == 0 {
                out.add(
                    Severity::Error,
                    "entry_point",
                    Some(&entry),
                    "the entry point is not executable",
                );
            }
        }
        Ok(Some(_)) => out.add(
            Severity::Error,
            "entry_point",
            Some(&entry),
            "the entry point is not a regular file",
        ),
        Ok(None) | Err(_) => out.add(
            Severity::Error,
            "entry_point",
            Some(&entry),
            "the entry point does not exist in the image",
        ),
    }
    let desktops = root_desktop_files(&fs);
    let mut icon_key = None;
    match desktops.as_slice() {
        [one] => {
            if let Ok(d) = read_desktop_entry(&fs, one) {
                icon_key = d.fields.get("Icon").cloned();
            }
            if let Some(m) = &manifest
                && one != &format!("{}.desktop", m.id)
            {
                out.add(
                    Severity::Warning,
                    "desktop_entry",
                    Some(one),
                    format!("should be named {}.desktop (the app id)", m.id),
                );
            }
        }
        [] => out.add(
            Severity::Error,
            "desktop_entry",
            None,
            "no .desktop file at the image root",
        ),
        many => out.add(
            Severity::Error,
            "desktop_entry",
            None,
            format!(
                "{} .desktop files at the image root; exactly one is required",
                many.len()
            ),
        ),
    }
    if find_icon(&fs, icon_key.as_deref()).is_none() {
        out.add(Severity::Error, "icon", None, "no icon at the image root");
    }

    // Architecture of the runtime itself.
    if let Some(m) = &manifest
        && !m.arch.contains(&container.machine_name())
    {
        out.add(
            Severity::Error,
            "arch",
            None,
            format!(
                "the runtime is {} but the manifest lists {:?}",
                container.machine_name(),
                m.arch
            ),
        );
    }

    // Bundled ELF files (SPEC §3.4, §11.1).
    check_elf_files(&fs, manifest.as_ref(), &mut out, &mut report.summary);

    out.findings
        .sort_by(|a, b| a.severity.cmp(&b.severity).then(a.path.cmp(&b.path)));
    report.status = if out.findings.iter().any(|f| f.severity == Severity::Error) {
        Status::DoesNotConform
    } else {
        Status::Conforms
    };
    report.findings = out.findings;
    Ok(report)
}

fn fatal(mut r: Report, status: Status, message: impl Into<String>) -> Report {
    r.status = status;
    r.findings.push(Finding {
        severity: Severity::Error,
        check: "container",
        path: None,
        message: message.into(),
    });
    r
}

fn check_manifest(fs: &ImageFs, out: &mut Out) -> Option<Manifest> {
    let bytes = match fs.read(MANIFEST_PATH, manifest::MAX_BYTES as u64) {
        Ok(b) => b,
        Err(FsError::NotFound(_)) => {
            out.add(
                Severity::Error,
                "manifest",
                Some(MANIFEST_PATH),
                "not a ULAI file: the image has no /.ulai/manifest.json",
            );
            return None;
        }
        Err(e) => {
            out.add(
                Severity::Error,
                "manifest",
                Some(MANIFEST_PATH),
                e.to_string(),
            );
            return None;
        }
    };
    let m = match manifest::parse(&bytes) {
        Ok(m) => m,
        Err(e) => {
            out.add(
                Severity::Error,
                "manifest",
                Some(MANIFEST_PATH),
                e.to_string(),
            );
            return None;
        }
    };
    for p in manifest::validate(&m) {
        out.add(Severity::Error, "manifest", Some(&p.field), p.message);
    }
    // Unknown top-level fields are allowed; mention them.
    if let Ok(serde_json::Value::Object(obj)) = serde_json::from_slice::<serde_json::Value>(&bytes)
    {
        let known = serde_json::to_value(&m).ok();
        for k in obj.keys() {
            if known.as_ref().and_then(|v| v.get(k)).is_none() {
                out.add(
                    Severity::Info,
                    "manifest",
                    Some(k),
                    "unknown field (ignored)",
                );
            }
        }
    }
    Some(m)
}

fn check_elf_files(
    fs: &ImageFs,
    manifest: Option<&Manifest>,
    out: &mut Out,
    summary: &mut Summary,
) {
    let files: Vec<(String, u64)> = fs
        .entries()
        .filter_map(|e| match e.kind {
            EntryKind::File { size } if size >= 64 => Some((e.path.clone(), size)),
            _ => None,
        })
        .collect();
    let mut max_glibc: Option<((u32, u32), String)> = None;
    let mut max_cxx: Option<Vec<u32>> = None;
    let mut max_abi: Option<Vec<u32>> = None;
    for (path, size) in files {
        let head = match fs.read_head(&path, 4) {
            Ok(h) => h,
            Err(e) => {
                out.add(
                    Severity::Error,
                    "image",
                    Some(&path),
                    format!("cannot read: {e}"),
                );
                continue;
            }
        };
        if !elfinfo::is_elf(&head) {
            continue;
        }
        summary.elf_files += 1;
        let basename = path.rsplit('/').next().unwrap_or(&path).to_owned();
        let info = if size > MAX_ELF_BYTES {
            out.add(
                Severity::Warning,
                "elf",
                Some(&path),
                format!("larger than {MAX_ELF_BYTES} bytes; not inspected"),
            );
            None
        } else {
            match fs
                .read(&path, MAX_ELF_BYTES)
                .map_err(|e| e.to_string())
                .and_then(|d| elfinfo::analyse(&d).map_err(|e| e.to_string()))
            {
                Ok(i) => Some(i),
                Err(e) => {
                    out.add(
                        Severity::Warning,
                        "elf",
                        Some(&path),
                        format!("cannot parse: {e}"),
                    );
                    None
                }
            }
        };
        let name = info
            .as_ref()
            .and_then(|i| i.soname.clone())
            .unwrap_or(basename);
        match classify(&name) {
            Some(LibClass::Glibc) => out.add(Severity::Error, "excluded_library", Some(&path), format!("{name}: glibc and the dynamic loader must come from the host in native mode (SPEC §11.1)")),
            Some(LibClass::Gpu) => out.add(Severity::Error, "excluded_library", Some(&path), format!("{name}: GPU and driver libraries must come from the host (SPEC §11.1)")),
            Some(LibClass::Warn) => {
                if name.starts_with("libstdc++") {
                    summary.libstdcxx_bundled = true;
                }
                out.add(Severity::Warning, "excluded_library", Some(&path), format!("{name}: may conflict with the host's copy needed by GPU drivers (SPEC §11.2)"));
            }
            None => {}
        }
        let Some(info) = info else { continue };
        check_one_elf(&path, &info, manifest, out);
        if let Some(v) = info.max_glibc
            && max_glibc.as_ref().is_none_or(|(m, _)| v > *m)
        {
            max_glibc = Some((v, path.clone()));
        }
        max_cxx = max_cxx.max(info.max_glibcxx);
        max_abi = max_abi.max(info.max_cxxabi);
    }
    summary.max_glibc = max_glibc.as_ref().map(|((a, b), _)| format!("{a}.{b}"));
    summary.max_glibcxx = max_cxx.as_deref().map(elfinfo::dotted_str);
    summary.max_cxxabi = max_abi.as_deref().map(elfinfo::dotted_str);
    if let (Some(m), Some(((a, b), who))) = (manifest, &max_glibc)
        && m.runtime_mode == "native"
        && let Some(floor) = m.glibc_floor.as_deref().and_then(manifest::parse_version)
        && (*a, *b) > floor
    {
        out.add(
            Severity::Error,
            "glibc_floor",
            Some(who),
            format!(
                "requires GLIBC_{a}.{b}, newer than glibc_floor {}.{}",
                floor.0, floor.1
            ),
        );
    }
    if summary.max_glibcxx.is_some() || summary.max_cxxabi.is_some() {
        out.add(
            Severity::Info,
            "cxx_runtime",
            None,
            format!(
                "highest GLIBCXX {}, CXXABI {}; libstdc++ bundled: {}",
                summary.max_glibcxx.as_deref().unwrap_or("none"),
                summary.max_cxxabi.as_deref().unwrap_or("none"),
                summary.libstdcxx_bundled
            ),
        );
    }
}

fn check_one_elf(path: &str, info: &ElfInfo, manifest: Option<&Manifest>, out: &mut Out) {
    if let Some(m) = manifest
        && !m.arch.contains(&info.machine)
    {
        out.add(
            Severity::Error,
            "arch",
            Some(path),
            format!(
                "built for {} but the manifest lists {:?}",
                info.machine, m.arch
            ),
        );
    }
    for rp in &info.rpaths {
        if rp.starts_with('/') {
            out.add(
                Severity::Error,
                "rpath",
                Some(path),
                format!("RPATH/RUNPATH {rp:?} points at an absolute host path; use $ORIGIN"),
            );
        }
    }
}

#[cfg(test)]
mod tests;
