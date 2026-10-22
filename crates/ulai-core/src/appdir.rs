// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! AppDir conventions at the image root (SPEC §3): `AppRun`, exactly one
//! desktop entry, and an icon. Everything returned here is untrusted text
//! from the file; escape it before printing (see `display`).

use std::collections::BTreeMap;

use serde::Serialize;

use crate::imagefs::{EntryKind, FsError, ImageFs};

/// Largest desktop entry ULAI reads.
pub const MAX_DESKTOP_BYTES: u64 = 64 * 1024;

/// Keys of `[Desktop Entry]` that ULAI reports (unlocalised values only).
pub const DESKTOP_KEYS: &[&str] = &[
    "Type",
    "Name",
    "GenericName",
    "Comment",
    "Exec",
    "Icon",
    "Categories",
    "Keywords",
    "MimeType",
    "StartupWMClass",
    "Terminal",
];

/// The `[Desktop Entry]` group of a desktop file: unlocalised keys only.
/// Values are kept as written (escape sequences are not expanded).
pub fn parse_desktop_entry(text: &str) -> BTreeMap<String, String> {
    let mut out = BTreeMap::new();
    let mut in_group = false;
    for line in text.lines() {
        let line = line.trim_start();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line.starts_with('[') {
            in_group = line.trim_end() == "[Desktop Entry]";
            continue;
        }
        if !in_group {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim();
        if k.contains('[') {
            continue; // localised, e.g. Name[de]
        }
        out.entry(k.to_owned())
            .or_insert_with(|| v.trim().to_owned());
    }
    out
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum IconType {
    Png,
    Svg,
    Xpm,
    Unknown,
}

/// Identifies an icon by its first bytes. Never decodes it.
pub fn icon_type(head: &[u8]) -> IconType {
    let text = String::from_utf8_lossy(&head[..head.len().min(1024)]).to_ascii_lowercase();
    if head.starts_with(b"\x89PNG\r\n\x1a\n") {
        IconType::Png
    } else if text.trim_start().starts_with("/* xpm */") {
        IconType::Xpm
    } else if text.contains("<svg") {
        IconType::Svg
    } else {
        IconType::Unknown
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Icon {
    pub path: String,
    #[serde(rename = "type")]
    pub kind: IconType,
    pub size: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DesktopEntry {
    pub path: String,
    /// Selected keys (see [`DESKTOP_KEYS`]).
    pub fields: BTreeMap<String, String>,
}

/// Desktop files directly at the image root.
pub fn root_desktop_files(fs: &ImageFs) -> Vec<String> {
    fs.entries()
        .filter(|e| !e.path.contains('/') && e.path.ends_with(".desktop"))
        .filter(|e| matches!(e.kind, EntryKind::File { .. } | EntryKind::Symlink { .. }))
        .map(|e| e.path.clone())
        .collect()
}

pub fn read_desktop_entry(fs: &ImageFs, path: &str) -> Result<DesktopEntry, FsError> {
    let bytes = fs.read(path, MAX_DESKTOP_BYTES)?;
    let all = parse_desktop_entry(&String::from_utf8_lossy(&bytes));
    let fields = all
        .into_iter()
        .filter(|(k, _)| DESKTOP_KEYS.contains(&k.as_str()))
        .collect();
    Ok(DesktopEntry {
        path: path.to_owned(),
        fields,
    })
}

/// The app icon: `<Icon>.{png,svg,svgz,xpm}` at the root, else `.DirIcon`.
pub fn find_icon(fs: &ImageFs, icon_key: Option<&str>) -> Option<Icon> {
    let mut candidates = Vec::new();
    if let Some(name) = icon_key.filter(|n| !n.is_empty() && !n.contains('/')) {
        for ext in ["png", "svg", "svgz", "xpm"] {
            candidates.push(format!("{name}.{ext}"));
        }
    }
    candidates.push(".DirIcon".into());
    for c in candidates {
        let Ok(real) = fs.resolve(&c) else { continue };
        let Some(EntryKind::File { size }) = fs.get(&real).map(|e| e.kind.clone()) else {
            continue;
        };
        let kind = if c.ends_with(".svgz") {
            IconType::Svg
        } else {
            fs.read_head(&real, 1024)
                .map_or(IconType::Unknown, |h| icon_type(&h))
        };
        return Some(Icon {
            path: c,
            kind,
            size,
        });
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn desktop_entry_parsing() {
        let d = parse_desktop_entry(
            "# comment\n[Desktop Entry]\nType=Application\nName = ULAI Fixture \nName[de]=Prüfling\n\
             Exec=AppRun %U\nName=second value ignored\n[Desktop Action new]\nName=Action\nExec=evil\n",
        );
        assert_eq!(d["Name"], "ULAI Fixture");
        assert_eq!(d["Exec"], "AppRun %U");
        assert_eq!(d.len(), 3, "{d:?}");
    }

    #[test]
    fn icon_types_by_magic() {
        assert_eq!(icon_type(b"\x89PNG\r\n\x1a\n...."), IconType::Png);
        assert_eq!(
            icon_type(b"<?xml version=\"1.0\"?>\n<svg xmlns="),
            IconType::Svg
        );
        assert_eq!(icon_type(b"/* XPM */\nstatic char"), IconType::Xpm);
        assert_eq!(icon_type(b"GIF89a"), IconType::Unknown);
        assert_eq!(icon_type(b""), IconType::Unknown);
    }
}
