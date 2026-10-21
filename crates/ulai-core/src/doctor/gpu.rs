// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 9: GPUs and the host graphics stack (SPEC §11).
//!
//! Reads sysfs, procfs, `/dev/dri` and loader manifests; never opens a
//! device or loads a library.

use std::io;
use std::path::{Path, PathBuf};

use serde::Serialize;

use super::libs::{LibIndex, Source};
use super::paths::{Read, read_optional};
use super::{Errors, Section};
use crate::host::{Host, io_reason};

pub const DRM_CLASS: &str = "/sys/class/drm";
pub const NVIDIA_VERSION: &str = "/proc/driver/nvidia/version";
pub const VULKAN_ICD_DIRS: &[&str] = &["/usr/share/vulkan/icd.d", "/etc/vulkan/icd.d"];
pub const EGL_VENDOR_DIRS: &[&str] = &["/usr/share/glvnd/egl_vendor.d", "/etc/glvnd/egl_vendor.d"];
pub const LOADERS: &[&str] = &["libvulkan.so.1", "libEGL.so.1", "libGL.so.1"];

/// Kernel drivers whose userspace GL/Vulkan drivers come from Mesa.
const MESA_DRIVERS: &[&str] = &[
    "amdgpu",
    "radeon",
    "i915",
    "xe",
    "nouveau",
    "virtio_gpu",
    "vmwgfx",
    "msm",
    "panfrost",
    "panthor",
    "lima",
    "v3d",
    "vc4",
    "etnaviv",
    "asahi",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Stack {
    /// NVIDIA's proprietary userspace driver.
    Nvidia,
    Mesa,
    Unknown,
}

#[derive(Debug, Clone, Serialize)]
pub struct Card {
    pub name: String,
    /// e.g. `"0x10de"`; `null` for non-PCI devices.
    pub pci_vendor: Option<String>,
    /// `nvidia`, `amd`, `intel`, or `null` for other vendors.
    pub vendor: Option<&'static str>,
    pub pci_device: Option<String>,
    /// Bound kernel driver; `null` when unbound.
    pub driver: Option<String>,
    pub stack: Stack,
}

#[derive(Debug, Clone, Serialize)]
pub struct Nvidia {
    pub version: Option<String>,
    /// `open` or `proprietary`.
    pub kernel_module: &'static str,
}

#[derive(Debug, Clone, Serialize)]
pub struct Manifest {
    pub path: PathBuf,
    pub library_path: Option<String>,
    /// Why the file could not be read or parsed.
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct Loaders {
    pub source: Source,
    #[serde(rename = "libvulkan.so.1")]
    pub libvulkan: Option<PathBuf>,
    #[serde(rename = "libEGL.so.1")]
    pub libegl: Option<PathBuf>,
    #[serde(rename = "libGL.so.1")]
    pub libgl: Option<PathBuf>,
}

impl Default for Loaders {
    fn default() -> Self {
        Self {
            source: Source::None,
            libvulkan: None,
            libegl: None,
            libgl: None,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Gpu {
    pub cards: Vec<Card>,
    pub nvidia: Option<Nvidia>,
    pub render_nodes: Vec<PathBuf>,
    pub vulkan_icds: Vec<Manifest>,
    pub egl_vendors: Vec<Manifest>,
    pub loaders: Loaders,
}

pub fn vendor_name(pci_vendor: &str) -> Option<&'static str> {
    match pci_vendor {
        "0x10de" => Some("nvidia"),
        "0x1002" => Some("amd"),
        "0x8086" => Some("intel"),
        _ => None,
    }
}

pub fn stack_for(driver: Option<&str>) -> Stack {
    match driver {
        Some("nvidia") => Stack::Nvidia,
        Some(d) if MESA_DRIVERS.contains(&d) => Stack::Mesa,
        _ => Stack::Unknown,
    }
}

/// `card0`, `card1`, … but not connectors such as `card1-DP-1`.
pub fn is_card_name(name: &str) -> bool {
    name.strip_prefix("card")
        .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()))
}

/// Parses `/proc/driver/nvidia/version`, e.g.
/// `NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  615.78.08  Release Build …`.
pub fn parse_nvidia_version(contents: &str) -> Option<Nvidia> {
    let line = contents.lines().find(|l| l.starts_with("NVRM version:"))?;
    let version = line
        .split_whitespace()
        .find(|t| {
            t.contains('.')
                && t.split('.')
                    .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
        })
        .map(str::to_owned);
    let kernel_module = if line.contains("Open Kernel Module") {
        "open"
    } else {
        "proprietary"
    };
    Some(Nvidia {
        version,
        kernel_module,
    })
}

/// Extracts `ICD.library_path` from a Vulkan ICD or glvnd EGL vendor file.
pub fn parse_manifest(contents: &str) -> Result<Option<String>, String> {
    let v: serde_json::Value =
        serde_json::from_str(contents).map_err(|e| format!("invalid JSON: {e}"))?;
    Ok(v.get("ICD")
        .and_then(|i| i.get("library_path"))
        .and_then(|p| p.as_str())
        .map(str::to_owned))
}

fn trimmed(host: &dyn Host, path: &Path, field: &str, errors: &mut Errors) -> Option<String> {
    match read_optional(host, path) {
        Read::Present(s) => Some(s.trim().to_owned()),
        Read::Absent => None,
        Read::Failed(r) => {
            errors.push(field, r);
            None
        }
    }
}

fn cards(host: &dyn Host, errors: &mut Errors) -> Vec<Card> {
    let entries = match host.read_dir(Path::new(DRM_CLASS)) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Vec::new(),
        Err(e) => {
            errors.push(
                "cards",
                format!("cannot list {DRM_CLASS}: {}", io_reason(&e)),
            );
            return Vec::new();
        }
    };
    let mut out = Vec::new();
    for entry in entries {
        let Some(name) = entry.name.to_str().filter(|n| is_card_name(n)) else {
            continue;
        };
        let dev = Path::new(DRM_CLASS).join(name).join("device");
        let field = |f: &str| format!("cards.{name}.{f}");
        let pci_vendor = trimmed(host, &dev.join("vendor"), &field("pci_vendor"), errors);
        let pci_device = trimmed(host, &dev.join("device"), &field("pci_device"), errors);
        let driver = match host.read_link(&dev.join("driver")) {
            Ok(target) => target.file_name().map(|n| n.to_string_lossy().into_owned()),
            Err(e) if e.kind() == io::ErrorKind::NotFound => None,
            Err(e) => {
                errors.push(field("driver"), io_reason(&e));
                None
            }
        };
        out.push(Card {
            name: name.to_owned(),
            vendor: pci_vendor.as_deref().and_then(vendor_name),
            pci_vendor,
            pci_device,
            stack: stack_for(driver.as_deref()),
            driver,
        });
    }
    out
}

fn render_nodes(host: &dyn Host, errors: &mut Errors) -> Vec<PathBuf> {
    match host.read_dir(Path::new("/dev/dri")) {
        Ok(entries) => entries
            .iter()
            .filter_map(|e| e.name.to_str())
            .filter(|n| n.starts_with("renderD"))
            .map(|n| Path::new("/dev/dri").join(n))
            .collect(),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Vec::new(),
        Err(e) => {
            errors.push("render_nodes", io_reason(&e));
            Vec::new()
        }
    }
}

fn manifests(host: &dyn Host, dirs: &[&str], field: &str, errors: &mut Errors) -> Vec<Manifest> {
    let mut out = Vec::new();
    for dir in dirs {
        let entries = match host.read_dir(Path::new(dir)) {
            Ok(e) => e,
            Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
            Err(e) => {
                errors.push(field, format!("cannot list {dir}: {}", io_reason(&e)));
                continue;
            }
        };
        for entry in entries {
            let Some(name) = entry.name.to_str().filter(|n| n.ends_with(".json")) else {
                continue;
            };
            let path = Path::new(dir).join(name);
            let (library_path, error) = match host.read_to_string(&path) {
                Ok(s) => match parse_manifest(&s) {
                    Ok(p) => (p, None),
                    Err(e) => (None, Some(e)),
                },
                Err(e) => (None, Some(io_reason(&e))),
            };
            out.push(Manifest {
                path,
                library_path,
                error,
            });
        }
    }
    out
}

pub fn probe(host: &dyn Host, libs: &LibIndex) -> Section<Gpu> {
    let mut errors = Errors::default();
    let nvidia = match read_optional(host, Path::new(NVIDIA_VERSION)) {
        Read::Present(s) => {
            let n = parse_nvidia_version(&s);
            if n.is_none() {
                errors.push("nvidia", "unrecognised /proc/driver/nvidia/version");
            }
            n
        }
        Read::Absent => None,
        Read::Failed(r) => {
            errors.push("nvidia", r);
            None
        }
    };
    let loaders = if libs.source == Source::None {
        errors.push("loaders", libs.fallback_reason.clone().unwrap_or_default());
        Loaders::default()
    } else {
        let get = |n| libs.get(n).map(Path::to_path_buf);
        Loaders {
            source: libs.source,
            libvulkan: get(LOADERS[0]),
            libegl: get(LOADERS[1]),
            libgl: get(LOADERS[2]),
        }
    };
    let data = Gpu {
        cards: cards(host, &mut errors),
        nvidia,
        render_nodes: render_nodes(host, &mut errors),
        vulkan_icds: manifests(host, VULKAN_ICD_DIRS, "vulkan_icds", &mut errors),
        egl_vendors: manifests(host, EGL_VENDOR_DIRS, "egl_vendors", &mut errors),
        loaders,
    };
    Section::new(data, errors)
}

/// Fixture: an Intel + NVIDIA hybrid laptop, as sysfs lays it out.
#[cfg(any(test, feature = "test-support"))]
pub fn hybrid_fixture(h: &mut crate::testing::FakeHost) {
    h.file("/sys/class/drm/card0/device/vendor", "0x8086\n")
        .file("/sys/class/drm/card0/device/device", "0xa7a0\n")
        .symlink("/sys/class/drm/card0/device/driver", "../../../bus/pci/drivers/i915")
        .file("/sys/class/drm/card1/device/vendor", "0x10de\n")
        .file("/sys/class/drm/card1/device/device", "0x28e0\n")
        .symlink("/sys/class/drm/card1/device/driver", "../../../bus/pci/drivers/nvidia")
        // A connector: must not be reported as a card.
        .file("/sys/class/drm/card1-eDP-1/status", "connected\n")
        .file("/sys/class/drm/renderD128/dev", "226:128\n")
        .file("/dev/dri/card0", "")
        .file("/dev/dri/card1", "")
        .file("/dev/dri/renderD128", "")
        .file("/dev/dri/renderD129", "")
        .file(
            NVIDIA_VERSION,
            "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  615.78.08  Release Build  (root@)  \nGCC version:  gcc version 15.2.1\n",
        )
        .file(
            "/usr/share/vulkan/icd.d/nvidia_icd.json",
            r#"{"file_format_version":"1.0.1","ICD":{"library_path":"libGLX_nvidia.so.0","api_version":"1.4.312"}}"#,
        )
        .file(
            "/usr/share/vulkan/icd.d/intel_icd.x86_64.json",
            r#"{"ICD":{"api_version":"1.4.318","library_path":"/usr/lib/libvulkan_intel.so"},"file_format_version":"1.0.1"}"#,
        )
        .file(
            "/usr/share/glvnd/egl_vendor.d/10_nvidia.json",
            r#"{"file_format_version":"1.0.0","ICD":{"library_path":"libEGL_nvidia.so.0"}}"#,
        )
        .file(
            "/usr/share/glvnd/egl_vendor.d/50_mesa.json",
            r#"{"file_format_version":"1.0.0","ICD":{"library_path":"libEGL_mesa.so.0"}}"#,
        );
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::doctor::libs::WANTED;
    use crate::testing::FakeHost;

    fn run(h: &FakeHost) -> Section<Gpu> {
        probe(h, &LibIndex::build(h, WANTED))
    }

    #[test]
    fn card_names() {
        assert!(is_card_name("card0"));
        assert!(is_card_name("card12"));
        assert!(!is_card_name("card1-DP-1"));
        assert!(!is_card_name("card"));
        assert!(!is_card_name("renderD128"));
        assert!(!is_card_name("version"));
    }

    #[test]
    fn hybrid_laptop() {
        let mut h = FakeHost::new();
        hybrid_fixture(&mut h);
        h.file("/usr/lib/libvulkan.so.1", "")
            .file("/usr/lib/libEGL.so.1", "");
        let s = run(&h);
        assert_eq!(s.status, Status::Ok, "{:?}", s.errors);
        let g = s.data;
        assert_eq!(g.cards.len(), 2);
        let c0 = &g.cards[0];
        assert_eq!(c0.name, "card0");
        assert_eq!(c0.vendor, Some("intel"));
        assert_eq!(c0.driver.as_deref(), Some("i915"));
        assert_eq!(c0.stack, Stack::Mesa);
        let c1 = &g.cards[1];
        assert_eq!(c1.pci_vendor.as_deref(), Some("0x10de"));
        assert_eq!(c1.pci_device.as_deref(), Some("0x28e0"));
        assert_eq!(c1.stack, Stack::Nvidia);
        let nv = g.nvidia.unwrap();
        assert_eq!(nv.version.as_deref(), Some("615.78.08"));
        assert_eq!(nv.kernel_module, "open");
        assert_eq!(
            g.render_nodes,
            [
                PathBuf::from("/dev/dri/renderD128"),
                PathBuf::from("/dev/dri/renderD129")
            ]
        );
        assert_eq!(g.vulkan_icds.len(), 2);
        assert_eq!(
            g.vulkan_icds[1].library_path.as_deref(),
            Some("libGLX_nvidia.so.0")
        );
        assert_eq!(g.egl_vendors.len(), 2);
        assert_eq!(g.loaders.source, Source::Scan);
        assert!(g.loaders.libvulkan.is_some());
        assert!(g.loaders.libgl.is_none());
    }

    #[test]
    fn unbound_and_non_pci_cards() {
        let mut h = FakeHost::new();
        h.file("/sys/class/drm/card0/device/vendor", "0x1af4\n")
            .dir("/sys/class/drm/card1/device");
        let g = run(&h).data;
        assert_eq!(g.cards[0].vendor, None);
        assert_eq!(g.cards[0].pci_vendor.as_deref(), Some("0x1af4"));
        assert_eq!(g.cards[0].driver, None);
        assert_eq!(g.cards[0].stack, Stack::Unknown);
        assert_eq!(g.cards[1].pci_vendor, None);
    }

    #[test]
    fn amd_desktop() {
        let mut h = FakeHost::new();
        h.file("/sys/class/drm/card0/device/vendor", "0x1002")
            .symlink("/sys/class/drm/card0/device/driver", "../../amdgpu");
        let g = run(&h).data;
        assert_eq!(g.cards[0].vendor, Some("amd"));
        assert_eq!(g.cards[0].stack, Stack::Mesa);
        assert!(g.nvidia.is_none());
    }

    #[test]
    fn no_drm_at_all() {
        let s = run(&FakeHost::new());
        assert_eq!(s.status, Status::Ok);
        assert!(s.data.cards.is_empty());
        assert!(s.data.render_nodes.is_empty());
    }

    #[test]
    fn nvidia_version_strings() {
        let open = parse_nvidia_version(
            "NVRM version: NVIDIA UNIX Open Kernel Module for x86_64  615.78.08  Release Build  (root@)",
        )
        .unwrap();
        assert_eq!(open.version.as_deref(), Some("615.78.08"));
        assert_eq!(open.kernel_module, "open");
        let prop = parse_nvidia_version(
            "NVRM version: NVIDIA UNIX x86_64 Kernel Module  550.54.14  Thu Feb 22 01:44:30 UTC 2024",
        )
        .unwrap();
        assert_eq!(prop.version.as_deref(), Some("550.54.14"));
        assert_eq!(prop.kernel_module, "proprietary");
        assert!(parse_nvidia_version("garbage").is_none());
    }

    #[test]
    fn malformed_manifest_is_reported_per_file() {
        let mut h = FakeHost::new();
        h.file("/etc/vulkan/icd.d/broken.json", "{not json")
            .file("/etc/vulkan/icd.d/nolib.json", r#"{"ICD":{}}"#)
            .file("/etc/vulkan/icd.d/README", "ignored");
        let s = run(&h);
        assert_eq!(s.status, Status::Ok);
        let icds = s.data.vulkan_icds;
        assert_eq!(icds.len(), 2);
        assert!(
            icds[0]
                .error
                .as_deref()
                .unwrap()
                .starts_with("invalid JSON")
        );
        assert_eq!(icds[1].library_path, None);
        assert_eq!(icds[1].error, None);
    }

    #[test]
    fn unrecognised_nvidia_file_is_partial() {
        let mut h = FakeHost::new();
        h.file(NVIDIA_VERSION, "something new\n");
        let s = run(&h);
        assert_eq!(s.status, Status::Partial);
        assert_eq!(s.errors[0].field, "nvidia");
    }
}
