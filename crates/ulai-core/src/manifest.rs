// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The ULAI manifest, `/.ulai/manifest.json` (SPEC §4).
//!
//! Parsing is in two steps. [`parse`] checks the size cap, rejects duplicate
//! keys at any level and builds the typed [`Manifest`]; unknown fields are
//! ignored (forward compatibility). [`validate`] then checks every known
//! field strictly and returns all problems, each with its field path.
//! `schemas/manifest-0.1.schema.json` describes the same rules where JSON
//! Schema can express them.

use std::collections::BTreeSet;
use std::fmt;

use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Serialize};

/// Largest manifest accepted (SPEC §4).
pub const MAX_BYTES: usize = 64 * 1024;

/// Ordinary permissions (SPEC §5.1).
pub const PERMISSIONS: &[&str] = &[
    "user-files",
    "network",
    "gpu",
    "audio",
    "notifications",
    "system-bus",
];
/// Sensitive permissions without a path (SPEC §5.2).
pub const SENSITIVE: &[&str] = &["x11", "secrets", "ssh-keys", "camera", "full-home"];
/// The sensitive permission for one hidden path (SPEC §5.2).
pub const DOTFILE: &str = "dotfile";
pub const DOTFILE_KINDS: &[&str] = &["file", "dir"];
pub const DOTFILE_ACCESS: &[&str] = &["read", "read-write"];
/// Longest `reason` (it is shown in the consent dialog).
pub const MAX_REASON_CHARS: usize = 300;
pub const ARCHES: &[&str] = &["x86_64", "aarch64"];
pub const BROWSERS: &[&str] = &["chromium-family", "firefox"];

/// Own paths that would cover far more than one app's data (SPEC §4).
pub const TOO_BROAD: &[&str] = &[
    "~",
    "~/.config",
    "~/.local",
    "~/.local/share",
    "~/.local/state",
    "~/.cache",
];

/// The protected set (SPEC §6.3): never reachable through own paths.
pub const PROTECTED: &[&str] = &[
    "~/.ssh",
    "~/.gnupg",
    "~/.password-store",
    "~/.local/share/keyrings",
    "~/.mozilla",
    "~/.config/google-chrome",
    "~/.config/chromium",
    "~/.config/BraveSoftware",
    "~/.config/microsoft-edge",
    "~/.config/vivaldi",
    "~/.config/opera",
    "~/.thunderbird",
    "~/.aws",
    "~/.azure",
    "~/.config/gcloud",
    "~/.oci",
    "~/.kube",
    "~/.docker",
    "~/.netrc",
    "~/.git-credentials",
    "~/.config/gh",
    "~/.electrum",
    "~/.bitcoin",
    "~/.ethereum",
    "~/.bashrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zshrc",
    "~/.zprofile",
    "~/.config/fish",
    "~/.config/autostart",
    "~/.config/systemd",
    "~/.local/share/systemd",
    "~/.config/environment.d",
    "~/.xprofile",
    "~/.xinitrc",
    "~/.local/bin",
    "~/bin",
    "~/.local/share/gnome-shell/extensions",
    "~/.local/share/plasma",
    "~/.local/share/ulai",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ParseError {
    #[error("manifest is larger than {MAX_BYTES} bytes")]
    TooLarge,
    #[error("manifest is not valid JSON: {0}")]
    Json(String),
    #[error("duplicate key {0:?} in the manifest")]
    DuplicateKey(String),
    #[error("manifest has the wrong shape: {0}")]
    Shape(String),
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Manifest {
    pub ulai: String,
    pub id: String,
    pub name: String,
    pub version: String,
    pub summary: String,
    pub arch: Vec<String>,
    pub runtime_mode: String,
    #[serde(default)]
    pub glibc_floor: Option<String>,
    #[serde(default)]
    pub entry: Option<String>,
    pub permissions: Vec<String>,
    #[serde(default)]
    pub sensitive_permissions: Vec<SensitivePermission>,
    #[serde(default)]
    pub own_paths: Vec<String>,
    #[serde(default)]
    pub integrations: Option<Integrations>,
    #[serde(default)]
    pub homepage: Option<String>,
}

/// One sensitive permission (SPEC §5.2), for example
/// `{ "id": "ssh-keys", "reason": "…" }` or
/// `{ "id": "dotfile", "path": "~/.gitconfig", "kind": "file",
/// "access": "read", "reason": "…" }`. `kind` and `access` are kept as
/// strings so that `validate` can name a wrong value.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensitivePermission {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access: Option<String>,
    /// Why the app needs it; shown in the consent dialog.
    pub reason: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Integrations {
    #[serde(default)]
    pub mime_types: Vec<String>,
    #[serde(default)]
    pub autostart: bool,
    #[serde(default)]
    pub native_messaging: Vec<NativeMessaging>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NativeMessaging {
    pub browser: String,
    pub host_manifest: String,
}

impl Manifest {
    /// The entry point inside the image (default `AppRun`).
    pub fn entry(&self) -> &str {
        self.entry.as_deref().unwrap_or("AppRun")
    }
}

/// Size cap, duplicate-key check, then the typed parse.
pub fn parse(bytes: &[u8]) -> Result<Manifest, ParseError> {
    if bytes.len() > MAX_BYTES {
        return Err(ParseError::TooLarge);
    }
    reject_duplicate_keys(bytes)?;
    serde_json::from_slice(bytes).map_err(|e| {
        if e.is_data() {
            ParseError::Shape(e.to_string())
        } else {
            ParseError::Json(e.to_string())
        }
    })
}

/// Walks the whole document once and fails on the first duplicate key at
/// any nesting level. serde_json would otherwise keep the last value, while
/// other JSON parsers keep the first.
pub fn reject_duplicate_keys(bytes: &[u8]) -> Result<(), ParseError> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let r = NoDuplicates.deserialize(&mut de).and_then(|()| de.end());
    r.map_err(|e| {
        let msg = e.to_string();
        match msg.strip_prefix(DUP_PREFIX) {
            Some(rest) => {
                ParseError::DuplicateKey(rest.split(" at line").next().unwrap_or(rest).to_owned())
            }
            None => ParseError::Json(msg),
        }
    })
}

const DUP_PREFIX: &str = "duplicate key: ";

struct NoDuplicates;

impl<'de> DeserializeSeed<'de> for NoDuplicates {
    type Value = ();
    fn deserialize<D: de::Deserializer<'de>>(self, d: D) -> Result<(), D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for NoDuplicates {
    type Value = ();
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }
    fn visit_bool<E>(self, _: bool) -> Result<(), E> {
        Ok(())
    }
    fn visit_i64<E>(self, _: i64) -> Result<(), E> {
        Ok(())
    }
    fn visit_u64<E>(self, _: u64) -> Result<(), E> {
        Ok(())
    }
    fn visit_f64<E>(self, _: f64) -> Result<(), E> {
        Ok(())
    }
    fn visit_str<E>(self, _: &str) -> Result<(), E> {
        Ok(())
    }
    fn visit_unit<E>(self) -> Result<(), E> {
        Ok(())
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<(), A::Error> {
        while seq.next_element_seed(NoDuplicates)?.is_some() {}
        Ok(())
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<(), A::Error> {
        let mut seen = BTreeSet::new();
        while let Some(key) = map.next_key::<String>()? {
            if !seen.insert(key.clone()) {
                return Err(de::Error::custom(format!("{DUP_PREFIX}{key}")));
            }
            map.next_value_seed(NoDuplicates)?;
        }
        Ok(())
    }
}

/// One validation problem.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Problem {
    /// JSON path of the field, e.g. `own_paths[1]`.
    pub field: String,
    pub message: String,
}

/// Checks every known field (SPEC §4, §5). Returns all problems found.
pub fn validate(m: &Manifest) -> Vec<Problem> {
    let mut p = Problems::default();
    if m.ulai != "0.1" {
        p.add(
            "ulai",
            format!(
                "unsupported manifest version {:?}; this ULAI reads \"0.1\"",
                m.ulai
            ),
        );
    }
    check_id(&m.id, &mut p);
    text_field("name", &m.name, 100, &mut p);
    text_field("version", &m.version, 64, &mut p);
    text_field("summary", &m.summary, 200, &mut p);

    if m.arch.is_empty() {
        p.add("arch", "must list at least one architecture");
    }
    for (i, a) in m.arch.iter().enumerate() {
        if !ARCHES.contains(&a.as_str()) {
            p.add(format!("arch[{i}]"), format!("unknown architecture {a:?}"));
        }
    }
    duplicates("arch", &m.arch, &mut p);

    match m.runtime_mode.as_str() {
        "native" => match &m.glibc_floor {
            None => p.add("glibc_floor", "required when runtime_mode is \"native\""),
            Some(v) if parse_version(v).is_none() => {
                p.add("glibc_floor", format!("{v:?} is not of the form 2.N"))
            }
            Some(_) => {}
        },
        "portable" => {
            if let Some(v) = &m.glibc_floor
                && parse_version(v).is_none()
            {
                p.add("glibc_floor", format!("{v:?} is not of the form 2.N"));
            }
        }
        other => p.add(
            "runtime_mode",
            format!("must be \"native\" or \"portable\", not {other:?}"),
        ),
    }

    if let Some(e) = &m.entry {
        image_path("entry", e, &mut p);
    }

    for (i, perm) in m.permissions.iter().enumerate() {
        if !PERMISSIONS.contains(&perm.as_str()) {
            let hint = if is_sensitive(perm) {
                " (it is a sensitive permission; list it in sensitive_permissions)"
            } else {
                ""
            };
            p.add(
                format!("permissions[{i}]"),
                format!("unknown permission {perm:?}{hint}"),
            );
        }
    }
    duplicates("permissions", &m.permissions, &mut p);
    for (i, perm) in m.sensitive_permissions.iter().enumerate() {
        sensitive_permission(&format!("sensitive_permissions[{i}]"), perm, &mut p);
    }
    // The same permission twice: by id, or by path for dotfiles.
    let keys: Vec<String> = m
        .sensitive_permissions
        .iter()
        .map(|s| match (&s.path, s.id == DOTFILE) {
            (Some(path), true) => format!("{DOTFILE} {path}"),
            _ => s.id.clone(),
        })
        .collect();
    duplicates("sensitive_permissions", &keys, &mut p);

    for (i, o) in m.own_paths.iter().enumerate() {
        own_path(&format!("own_paths[{i}]"), o, &mut p);
    }
    duplicates("own_paths", &m.own_paths, &mut p);

    if let Some(int) = &m.integrations {
        for (i, t) in int.mime_types.iter().enumerate() {
            if !is_mime_type(t) {
                p.add(
                    format!("integrations.mime_types[{i}]"),
                    format!("{t:?} is not a MIME type"),
                );
            }
        }
        for (i, nm) in int.native_messaging.iter().enumerate() {
            let f = format!("integrations.native_messaging[{i}]");
            if !BROWSERS.contains(&nm.browser.as_str()) {
                p.add(
                    format!("{f}.browser"),
                    format!("unknown browser family {:?}", nm.browser),
                );
            }
            image_path(&format!("{f}.host_manifest"), &nm.host_manifest, &mut p);
        }
    }

    if let Some(h) = &m.homepage
        && !(h.starts_with("https://")
            && h.len() > 8
            && h.len() <= 2048
            && !h.chars().any(char::is_whitespace))
    {
        p.add("homepage", "must be an https:// URL");
    }
    p.0
}

#[derive(Default)]
struct Problems(Vec<Problem>);

impl Problems {
    fn add(&mut self, field: impl Into<String>, message: impl Into<String>) {
        self.0.push(Problem {
            field: field.into(),
            message: message.into(),
        });
    }
}

fn is_sensitive(perm: &str) -> bool {
    SENSITIVE.contains(&perm) || perm == DOTFILE
}

/// SPEC §5.2. Every entry needs a reason. Only `dotfile` takes `path`,
/// `kind` and `access`, and then needs all three.
fn sensitive_permission(field: &str, s: &SensitivePermission, p: &mut Problems) {
    text_field(&format!("{field}.reason"), &s.reason, MAX_REASON_CHARS, p);
    if s.id == DOTFILE {
        match &s.path {
            Some(path) => dotfile_path(&format!("{field}.path"), path, p),
            None => p.add(format!("{field}.path"), "required for \"dotfile\""),
        }
        for (name, v, allowed) in [
            ("kind", &s.kind, DOTFILE_KINDS),
            ("access", &s.access, DOTFILE_ACCESS),
        ] {
            match v {
                Some(v) if allowed.contains(&v.as_str()) => {}
                Some(v) => p.add(
                    format!("{field}.{name}"),
                    format!("must be one of {allowed:?}, not {v:?}"),
                ),
                None => p.add(format!("{field}.{name}"), "required for \"dotfile\""),
            }
        }
        return;
    }
    if !SENSITIVE.contains(&s.id.as_str()) {
        p.add(
            format!("{field}.id"),
            format!("unknown sensitive permission {:?}", s.id),
        );
        return;
    }
    for (name, v) in [("path", &s.path), ("kind", &s.kind), ("access", &s.access)] {
        if v.is_some() {
            p.add(
                format!("{field}.{name}"),
                format!("only \"dotfile\" takes {name}"),
            );
        }
    }
}

/// Reverse-DNS app id: 2–255 bytes of `[A-Za-z0-9_-]` components separated
/// by dots, at least two components, none starting with a digit, and no
/// hyphen in the last one (the D-Bus and Flatpak rules).
fn check_id(id: &str, p: &mut Problems) {
    let parts: Vec<&str> = id.split('.').collect();
    let ok = id.len() <= 255
        && parts.len() >= 2
        && parts.iter().all(|c| {
            !c.is_empty()
                && !c.as_bytes()[0].is_ascii_digit()
                && c.bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
        })
        && !parts.last().is_some_and(|c| c.contains('-'));
    if !ok {
        p.add(
            "id",
            format!("{id:?} is not a reverse-DNS app id (e.g. org.example.App)"),
        );
    }
}

/// Non-empty, bounded, and free of control characters.
fn text_field(field: &str, v: &str, max: usize, p: &mut Problems) {
    if v.trim().is_empty() {
        p.add(field, "must not be empty");
    } else if v.chars().count() > max {
        p.add(field, format!("longer than {max} characters"));
    }
    if v.chars().any(crate::display::is_unsafe) {
        p.add(field, "contains control or bidi characters");
    }
}

fn duplicates(field: &str, list: &[String], p: &mut Problems) {
    let mut seen = BTreeSet::new();
    for v in list {
        if !seen.insert(v) {
            p.add(field, format!("{v:?} is listed twice"));
        }
    }
}

/// `2.N` (as used for glibc floors).
pub fn parse_version(v: &str) -> Option<(u32, u32)> {
    let (a, b) = v.split_once('.')?;
    if a.is_empty()
        || b.is_empty()
        || !a.bytes().all(|c| c.is_ascii_digit())
        || !b.bytes().all(|c| c.is_ascii_digit())
    {
        return None;
    }
    Some((a.parse().ok()?, b.parse().ok()?))
}

/// A relative path inside the image: no leading `/`, no `..` or `.`
/// components, no empty components, no NUL.
fn image_path(field: &str, v: &str, p: &mut Problems) {
    let bad = v.is_empty()
        || v.starts_with('/')
        || v.contains('\0')
        || v.split('/').any(|c| c.is_empty() || c == "." || c == "..");
    if bad {
        p.add(
            field,
            format!("{v:?} is not a relative path inside the image"),
        );
    }
}

/// Normalises a `~/…` path: returns its components, or `None` if it is not
/// strictly inside `$HOME` (absolute, `..`, `.`, empty components).
fn home_components(v: &str) -> Option<Vec<&str>> {
    let rest = v
        .strip_prefix("~/")
        .or(if v == "~" { Some("") } else { None })?;
    if rest.is_empty() {
        return Some(Vec::new());
    }
    let parts: Vec<&str> = rest.split('/').collect();
    if parts
        .iter()
        .any(|c| c.is_empty() || *c == "." || *c == ".." || c.contains('\0'))
    {
        return None;
    }
    Some(parts)
}

fn is_prefix(a: &[&str], b: &[&str]) -> bool {
    a.len() <= b.len() && a.iter().zip(b).all(|(x, y)| x == y)
}

/// SPEC §4: inside `$HOME`, not too broad, and neither equal to, inside,
/// nor containing a protected path.
fn own_path(field: &str, v: &str, p: &mut Problems) {
    let Some(parts) = home_components(v) else {
        p.add(
            field,
            format!("{v:?} must be a path inside the home directory, written ~/…"),
        );
        return;
    };
    let normal = if parts.is_empty() {
        "~".to_owned()
    } else {
        format!("~/{}", parts.join("/"))
    };
    if TOO_BROAD.contains(&normal.as_str()) {
        p.add(field, format!("{v:?} is too broad"));
        return;
    }
    for prot in PROTECTED {
        let pp = home_components(prot).expect("protected paths are well-formed");
        if is_prefix(&parts, &pp) || is_prefix(&pp, &parts) {
            p.add(field, format!("{v:?} overlaps the protected path {prot}"));
            return;
        }
    }
}

/// Characters that would make a path a pattern. Paths are literal.
const GLOB_CHARS: &[char] = &['*', '?', '[', ']', '{', '}'];

/// A `dotfile` path names one hidden entry of the home directory, or a path
/// below one: written `~/.name[/…]`, already normalised (no `.`, `..` or
/// empty components, no trailing `/`), without glob characters. It must not
/// be inside the protected set or contain any of it (SPEC §6.3): protected
/// paths are reachable only through their own permissions (`ssh-keys`,
/// `secrets`, `full-home`).
fn dotfile_path(field: &str, v: &str, p: &mut Problems) {
    let parts = match home_components(v) {
        Some(parts)
            if parts
                .first()
                .is_some_and(|c| c.starts_with('.') && c.len() > 1) =>
        {
            parts
        }
        _ => {
            p.add(
                field,
                format!("{v:?} must be a hidden path in the home directory, written ~/.name"),
            );
            return;
        }
    };
    if v.contains(GLOB_CHARS) {
        p.add(
            field,
            format!("{v:?} contains glob characters; paths are literal"),
        );
        return;
    }
    for prot in PROTECTED {
        let pp = home_components(prot).expect("protected paths are well-formed");
        if is_prefix(&parts, &pp) || is_prefix(&pp, &parts) {
            p.add(
                field,
                format!(
                    "{v:?} overlaps the protected path {prot}, which only its own \
                     permission can grant (ssh-keys, secrets or full-home)"
                ),
            );
            return;
        }
    }
}

/// `type/subtype` with RFC 6838 restricted-name characters.
fn is_mime_type(t: &str) -> bool {
    let ok = |s: &str| {
        !s.is_empty()
            && s.len() <= 127
            && s.as_bytes()[0].is_ascii_alphanumeric()
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"!#$&-^_.+".contains(&b))
    };
    matches!(t.split_once('/'), Some((a, b)) if ok(a) && ok(b))
}

#[cfg(test)]
mod tests;
