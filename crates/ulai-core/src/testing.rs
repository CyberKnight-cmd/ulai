// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A fake [`Host`] for tests: the filesystem is a tempdir, and env, commands
//! and syscalls are canned. No test using it touches the real system.
//!
//! Absolute paths are mapped under the tempdir root (`/sys/x` →
//! `<root>/sys/x`). Use relative symlink targets in fixtures: `metadata`
//! follows symlinks, and an absolute target would escape into the real host.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs;
use std::io;
use std::os::unix::fs::{PermissionsExt, symlink};
use std::path::{Path, PathBuf};

use crate::host::{CmdOutput, DirEntryInfo, Host, MetaInfo, Uname};

pub struct FakeHost {
    root: tempfile::TempDir,
    env: HashMap<String, OsString>,
    commands: HashMap<PathBuf, Result<CmdOutput, String>>,
    meta_overrides: HashMap<PathBuf, MetaInfo>,
    pub uname: Result<Uname, i32>,
    pub landlock: Result<i32, i32>,
    pub uid: u32,
    pub userns: Result<String, String>,
    /// Reading this path panics, to test probe isolation.
    pub panic_on: Option<PathBuf>,
}

impl Default for FakeHost {
    fn default() -> Self {
        Self::new()
    }
}

impl FakeHost {
    /// An empty system: no files, no env, every syscall fails with `ENOSYS`.
    pub fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("tempdir"),
            env: HashMap::new(),
            commands: HashMap::new(),
            meta_overrides: HashMap::new(),
            uname: Err(libc::ENOSYS),
            landlock: Err(libc::ENOSYS),
            uid: 1000,
            userns: Err("not configured".into()),
            panic_on: None,
        }
    }

    pub fn root(&self) -> &Path {
        self.root.path()
    }

    fn map(&self, path: &Path) -> PathBuf {
        let rel = path.strip_prefix("/").unwrap_or(path);
        self.root.path().join(rel)
    }

    fn check_panic(&self, path: &Path) {
        if self.panic_on.as_deref() == Some(path) {
            panic!("injected panic reading {}", path.display());
        }
    }

    pub fn file(&mut self, path: &str, contents: &str) -> &mut Self {
        let p = self.map(Path::new(path));
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(&p, contents).expect("write");
        self
    }

    pub fn file_mode(&mut self, path: &str, contents: &str, mode: u32) -> &mut Self {
        self.file(path, contents);
        fs::set_permissions(self.map(Path::new(path)), fs::Permissions::from_mode(mode))
            .expect("chmod");
        self
    }

    pub fn dir(&mut self, path: &str) -> &mut Self {
        fs::create_dir_all(self.map(Path::new(path))).expect("mkdir");
        self
    }

    /// Creates `path` as a symlink with the literal `target`.
    pub fn symlink(&mut self, path: &str, target: &str) -> &mut Self {
        let p = self.map(Path::new(path));
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        symlink(target, p).expect("symlink");
        self
    }

    /// Makes `metadata(path)` return `meta` (for device nodes, root-owned
    /// setuid files and similar things a test cannot create).
    pub fn meta(&mut self, path: &str, meta: MetaInfo) -> &mut Self {
        self.meta_overrides.insert(PathBuf::from(path), meta);
        self
    }

    pub fn set_env(&mut self, key: &str, value: &str) -> &mut Self {
        self.env.insert(key.to_owned(), value.into());
        self
    }

    /// Canned output for `program` (any arguments).
    pub fn command(&mut self, program: &str, code: i32, stdout: &str) -> &mut Self {
        self.commands.insert(
            PathBuf::from(program),
            Ok(CmdOutput {
                code: Some(code),
                stdout: stdout.to_owned(),
                stderr: String::new(),
            }),
        );
        self
    }

    /// Makes running `program` fail with `error` (e.g. a timeout).
    pub fn command_error(&mut self, program: &str, error: &str) -> &mut Self {
        self.commands
            .insert(PathBuf::from(program), Err(error.to_owned()));
        self
    }
}

impl Host for FakeHost {
    fn read_to_string(&self, path: &Path) -> io::Result<String> {
        self.check_panic(path);
        fs::read_to_string(self.map(path))
    }

    fn read_link(&self, path: &Path) -> io::Result<PathBuf> {
        self.check_panic(path);
        fs::read_link(self.map(path))
    }

    fn read_dir(&self, path: &Path) -> io::Result<Vec<DirEntryInfo>> {
        self.check_panic(path);
        let mut out = Vec::new();
        for entry in fs::read_dir(self.map(path))? {
            let entry = entry?;
            out.push(DirEntryInfo {
                name: entry.file_name(),
                kind: entry.file_type()?.into(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn metadata(&self, path: &Path) -> io::Result<MetaInfo> {
        self.check_panic(path);
        if let Some(m) = self.meta_overrides.get(path) {
            return Ok(*m);
        }
        use std::os::unix::fs::MetadataExt;
        let m = fs::metadata(self.map(path))?;
        Ok(MetaInfo {
            kind: m.file_type().into(),
            mode: m.mode(),
            uid: m.uid(),
        })
    }

    fn env(&self, key: &str) -> Option<OsString> {
        self.env.get(key).cloned()
    }

    fn run(&self, program: &Path, _args: &[&str]) -> io::Result<CmdOutput> {
        match self.commands.get(program) {
            Some(Ok(out)) => Ok(out.clone()),
            Some(Err(e)) => Err(io::Error::other(e.clone())),
            None => Err(io::Error::from_raw_os_error(libc::ENOENT)),
        }
    }

    fn uname(&self) -> io::Result<Uname> {
        self.uname.clone().map_err(io::Error::from_raw_os_error)
    }

    fn landlock_abi(&self) -> Result<i32, i32> {
        self.landlock
    }

    fn uid(&self) -> u32 {
        self.uid
    }

    fn userns_probe(&self) -> io::Result<String> {
        self.userns.clone().map_err(io::Error::other)
    }
}
