// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Probe 11: XDG base directories (with the spec defaults) and
//! `XDG_RUNTIME_DIR`. Relative values are ignored, as the Base Directory
//! specification requires.

use std::path::{Path, PathBuf};

use serde::Serialize;

use super::{Errors, Section};
use crate::host::{FileKind, Host, io_reason};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DirSource {
    Env,
    Default,
}

#[derive(Debug, Clone, Serialize)]
pub struct BaseDir {
    pub path: PathBuf,
    pub source: DirSource,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct RuntimeDir {
    pub path: Option<PathBuf>,
    pub exists: Option<bool>,
    pub owner_ok: Option<bool>,
    /// Octal permission bits, e.g. `"0700"`.
    pub mode: Option<String>,
    pub mode_ok: Option<bool>,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Xdg {
    pub home: Option<PathBuf>,
    pub config_home: Option<BaseDir>,
    pub data_home: Option<BaseDir>,
    pub state_home: Option<BaseDir>,
    pub cache_home: Option<BaseDir>,
    pub data_dirs: Vec<PathBuf>,
    pub config_dirs: Vec<PathBuf>,
    pub runtime_dir: RuntimeDir,
    /// `$XDG_DATA_HOME/ulai` (SPEC §8).
    pub ulai_store: Option<PathBuf>,
}

fn abs_env(host: &dyn Host, key: &str) -> Option<PathBuf> {
    host.env(key).map(PathBuf::from).filter(|p| p.is_absolute())
}

fn base(
    host: &dyn Host,
    key: &str,
    home: Option<&Path>,
    default_rel: &str,
    field: &str,
    errors: &mut Errors,
) -> Option<BaseDir> {
    if let Some(path) = abs_env(host, key) {
        return Some(BaseDir {
            path,
            source: DirSource::Env,
        });
    }
    match home {
        Some(h) => Some(BaseDir {
            path: h.join(default_rel),
            source: DirSource::Default,
        }),
        None => {
            errors.push(field, format!("{key} unset and HOME unknown"));
            None
        }
    }
}

fn dir_list(host: &dyn Host, key: &str, default: &[&str]) -> Vec<PathBuf> {
    let list: Vec<PathBuf> = host
        .env(key)
        .map(|v| {
            std::env::split_paths(&v)
                .filter(|p| p.is_absolute())
                .collect()
        })
        .unwrap_or_default();
    if list.is_empty() {
        default.iter().map(PathBuf::from).collect()
    } else {
        list
    }
}

fn runtime_dir(host: &dyn Host, errors: &mut Errors) -> RuntimeDir {
    let Some(path) = abs_env(host, "XDG_RUNTIME_DIR") else {
        return RuntimeDir::default();
    };
    let mut rd = RuntimeDir {
        path: Some(path.clone()),
        ..RuntimeDir::default()
    };
    match host.metadata(&path) {
        Ok(m) => {
            let perms = m.mode & 0o7777;
            rd.exists = Some(m.kind == FileKind::Dir);
            rd.owner_ok = Some(m.uid == host.uid());
            rd.mode = Some(format!("{perms:04o}"));
            rd.mode_ok = Some(perms == 0o700);
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => rd.exists = Some(false),
        Err(e) => errors.push("runtime_dir", io_reason(&e)),
    }
    rd
}

pub fn probe(host: &dyn Host) -> Section<Xdg> {
    let mut errors = Errors::default();
    let home = abs_env(host, "HOME");
    if home.is_none() {
        errors.push("home", "HOME unset or not absolute");
    }
    let h = home.as_deref();
    let config_home = base(
        host,
        "XDG_CONFIG_HOME",
        h,
        ".config",
        "config_home",
        &mut errors,
    );
    let data_home = base(
        host,
        "XDG_DATA_HOME",
        h,
        ".local/share",
        "data_home",
        &mut errors,
    );
    let state_home = base(
        host,
        "XDG_STATE_HOME",
        h,
        ".local/state",
        "state_home",
        &mut errors,
    );
    let cache_home = base(
        host,
        "XDG_CACHE_HOME",
        h,
        ".cache",
        "cache_home",
        &mut errors,
    );
    let ulai_store = data_home.as_ref().map(|d| d.path.join("ulai"));
    Section::new(
        Xdg {
            home,
            config_home,
            data_home,
            state_home,
            cache_home,
            data_dirs: dir_list(host, "XDG_DATA_DIRS", &["/usr/local/share", "/usr/share"]),
            config_dirs: dir_list(host, "XDG_CONFIG_DIRS", &["/etc/xdg"]),
            runtime_dir: runtime_dir(host, &mut errors),
            ulai_store,
        },
        errors,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::doctor::Status;
    use crate::host::MetaInfo;
    use crate::testing::FakeHost;

    #[test]
    fn defaults() {
        let mut h = FakeHost::new();
        h.set_env("HOME", "/home/u");
        let s = probe(&h);
        assert_eq!(s.status, Status::Ok);
        let d = s.data;
        assert_eq!(
            d.config_home.unwrap().path,
            PathBuf::from("/home/u/.config")
        );
        let data = d.data_home.unwrap();
        assert_eq!(data.path, PathBuf::from("/home/u/.local/share"));
        assert_eq!(data.source, DirSource::Default);
        assert_eq!(
            d.state_home.unwrap().path,
            PathBuf::from("/home/u/.local/state")
        );
        assert_eq!(d.cache_home.unwrap().path, PathBuf::from("/home/u/.cache"));
        assert_eq!(
            d.data_dirs,
            [
                PathBuf::from("/usr/local/share"),
                PathBuf::from("/usr/share")
            ]
        );
        assert_eq!(d.config_dirs, [PathBuf::from("/etc/xdg")]);
        assert_eq!(d.runtime_dir.path, None);
        assert_eq!(
            d.ulai_store,
            Some(PathBuf::from("/home/u/.local/share/ulai"))
        );
    }

    #[test]
    fn env_overrides_and_relative_values_ignored() {
        let mut h = FakeHost::new();
        h.set_env("HOME", "/home/u")
            .set_env("XDG_DATA_HOME", "/data")
            .set_env("XDG_CONFIG_HOME", "relative/cfg")
            .set_env("XDG_DATA_DIRS", "rel:/opt/share")
            .set_env("XDG_CONFIG_DIRS", "only/relative");
        let d = probe(&h).data;
        assert_eq!(d.data_home.as_ref().unwrap().source, DirSource::Env);
        assert_eq!(d.ulai_store, Some(PathBuf::from("/data/ulai")));
        let cfg = d.config_home.unwrap();
        assert_eq!(cfg.path, PathBuf::from("/home/u/.config"));
        assert_eq!(cfg.source, DirSource::Default);
        assert_eq!(d.data_dirs, [PathBuf::from("/opt/share")]);
        assert_eq!(d.config_dirs, [PathBuf::from("/etc/xdg")]);
    }

    #[test]
    fn no_home_is_partial() {
        let s = probe(&FakeHost::new());
        assert_eq!(s.status, Status::Partial);
        assert!(s.data.config_home.is_none());
        assert_eq!(s.errors[0].field, "home");
    }

    #[test]
    fn runtime_dir_checks() {
        let mut h = FakeHost::new();
        h.set_env("HOME", "/home/u")
            .set_env("XDG_RUNTIME_DIR", "/run/user/1000")
            .meta(
                "/run/user/1000",
                MetaInfo {
                    kind: FileKind::Dir,
                    mode: 0o40700,
                    uid: 1000,
                },
            );
        let rd = probe(&h).data.runtime_dir;
        assert_eq!(rd.exists, Some(true));
        assert_eq!(rd.owner_ok, Some(true));
        assert_eq!(rd.mode.as_deref(), Some("0700"));
        assert_eq!(rd.mode_ok, Some(true));
    }

    #[test]
    fn runtime_dir_wrong_owner_and_mode() {
        let mut h = FakeHost::new();
        h.set_env("XDG_RUNTIME_DIR", "/run/user/1000").meta(
            "/run/user/1000",
            MetaInfo {
                kind: FileKind::Dir,
                mode: 0o40755,
                uid: 0,
            },
        );
        let rd = probe(&h).data.runtime_dir;
        assert_eq!(rd.owner_ok, Some(false));
        assert_eq!(rd.mode_ok, Some(false));
    }

    #[test]
    fn runtime_dir_missing() {
        let mut h = FakeHost::new();
        h.set_env("XDG_RUNTIME_DIR", "/run/user/1000");
        assert_eq!(probe(&h).data.runtime_dir.exists, Some(false));
    }
}
