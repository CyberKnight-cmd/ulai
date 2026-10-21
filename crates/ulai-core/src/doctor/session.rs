// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 8: graphical session, from the environment.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{Errors, Section};
use crate::host::Host;

#[derive(Debug, Clone, Default, Serialize)]
pub struct Session {
    #[serde(rename = "type")]
    pub session_type: Option<String>,
    pub wayland_display: Option<String>,
    /// Whether the Wayland socket exists; `null` when it cannot be located.
    pub wayland_socket_exists: Option<bool>,
    pub display: Option<String>,
    pub current_desktop: Option<String>,
}

fn var(host: &dyn Host, key: &str) -> Option<String> {
    host.env(key)
        .map(|v| v.to_string_lossy().into_owned())
        .filter(|v| !v.is_empty())
}

/// `WAYLAND_DISPLAY` may be a name relative to `XDG_RUNTIME_DIR` or an
/// absolute path.
pub fn wayland_socket(display: &str, runtime_dir: Option<&str>) -> Option<PathBuf> {
    let d = Path::new(display);
    if d.is_absolute() {
        Some(d.to_path_buf())
    } else {
        runtime_dir
            .map(Path::new)
            .filter(|r| r.is_absolute())
            .map(|r| r.join(d))
    }
}

pub fn probe(host: &dyn Host) -> Section<Session> {
    let wayland_display = var(host, "WAYLAND_DISPLAY");
    let runtime_dir = var(host, "XDG_RUNTIME_DIR");
    let wayland_socket_exists = wayland_display
        .as_deref()
        .and_then(|d| wayland_socket(d, runtime_dir.as_deref()))
        .map(|p| host.exists(&p));
    Section::new(
        Session {
            session_type: var(host, "XDG_SESSION_TYPE"),
            wayland_display,
            wayland_socket_exists,
            display: var(host, "DISPLAY"),
            current_desktop: var(host, "XDG_CURRENT_DESKTOP"),
        },
        Errors::default(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeHost;

    #[test]
    fn wayland_session() {
        let mut h = FakeHost::new();
        h.set_env("XDG_SESSION_TYPE", "wayland")
            .set_env("WAYLAND_DISPLAY", "wayland-0")
            .set_env("XDG_RUNTIME_DIR", "/run/user/1000")
            .set_env("DISPLAY", ":0")
            .set_env("XDG_CURRENT_DESKTOP", "KDE")
            .file("/run/user/1000/wayland-0", "");
        let s = probe(&h).data;
        assert_eq!(s.session_type.as_deref(), Some("wayland"));
        assert_eq!(s.wayland_socket_exists, Some(true));
        assert_eq!(s.display.as_deref(), Some(":0"));
    }

    #[test]
    fn x11_only() {
        let mut h = FakeHost::new();
        h.set_env("XDG_SESSION_TYPE", "x11")
            .set_env("DISPLAY", ":1");
        let s = probe(&h).data;
        assert_eq!(s.wayland_display, None);
        assert_eq!(s.wayland_socket_exists, None);
    }

    #[test]
    fn missing_socket_and_empty_vars() {
        let mut h = FakeHost::new();
        h.set_env("WAYLAND_DISPLAY", "wayland-1")
            .set_env("XDG_RUNTIME_DIR", "/run/user/1000")
            .set_env("DISPLAY", "");
        let s = probe(&h).data;
        assert_eq!(s.wayland_socket_exists, Some(false));
        assert_eq!(s.display, None);
    }

    #[test]
    fn socket_paths() {
        assert_eq!(
            wayland_socket("/tmp/w", None),
            Some(PathBuf::from("/tmp/w"))
        );
        assert_eq!(wayland_socket("wayland-0", None), None);
        assert_eq!(wayland_socket("wayland-0", Some("relative")), None);
    }
}
