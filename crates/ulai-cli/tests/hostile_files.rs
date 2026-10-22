// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Crafted hostile files (ROADMAP M1): a bad signature, path traversal in
//! the image, and decompression bombs. Each goes through verify, inspect and
//! validate; none may crash ULAI, leak host files, or execute anything.

use std::io::Cursor;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use backhand::compression::Compressor;
use backhand::{FilesystemWriter, NodeHeader};
use ulai_core::testing_appimage::Builder;

fn h(mode: u16) -> NodeHeader {
    NodeHeader {
        permissions: mode,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

fn image(build: impl FnOnce(&mut FilesystemWriter)) -> Vec<u8> {
    let mut w = FilesystemWriter::default();
    w.set_compressor(backhand::FilesystemCompressor::new(Compressor::Gzip, None).unwrap());
    build(&mut w);
    let mut out = Cursor::new(Vec::new());
    w.write(&mut out).unwrap();
    out.into_inner()
}

fn write(dir: &Path, name: &str, bytes: &[u8]) -> PathBuf {
    let p = dir.join(name);
    std::fs::write(&p, bytes).unwrap();
    p
}

fn ulai(args: &[&str], file: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ulai"))
        .args(args)
        .arg(file)
        .output()
        .unwrap()
}

fn json(args: &[&str], file: &Path) -> (i32, serde_json::Value) {
    let mut a = args.to_vec();
    a.push("--json");
    let out = ulai(&a, file);
    (
        out.status.code().unwrap(),
        serde_json::from_slice(&out.stdout)
            .unwrap_or_else(|e| panic!("{e}: {}", String::from_utf8_lossy(&out.stderr))),
    )
}

fn errors(j: &serde_json::Value) -> Vec<String> {
    j["findings"]
        .as_array()
        .unwrap()
        .iter()
        .filter(|f| f["severity"] == "error")
        .map(|f| format!("{}: {}", f["check"], f["message"]))
        .collect()
}

/// No process other than ulai itself may start (execve or execveat).
fn assert_no_exec(file: &Path) {
    let Some(strace) = std::env::var_os("PATH").and_then(|p| {
        std::env::split_paths(&p)
            .map(|d| d.join("strace"))
            .find(|p| p.is_file())
    }) else {
        eprintln!("skipped no-exec check: strace not installed");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    for cmd in ["verify", "inspect", "validate"] {
        let log = dir.path().join(cmd);
        let out = Command::new(&strace)
            .args(["-f", "-qq", "-e", "trace=execve,execveat", "-o"])
            .arg(&log)
            .arg(env!("CARGO_BIN_EXE_ulai"))
            .arg(cmd)
            .arg(file)
            .output()
            .unwrap();
        assert!(out.status.code().is_some(), "{cmd} was killed by a signal");
        let trace = std::fs::read_to_string(&log).unwrap();
        let execs = trace
            .lines()
            .filter(|l| l.contains("execve(") || l.contains("execveat("))
            .count();
        assert_eq!(
            execs,
            1,
            "{cmd} {}: only ulai's own exec allowed:\n{trace}",
            file.display()
        );
    }
}

#[test]
fn bad_signature() {
    let dir = tempfile::tempdir().unwrap();
    let mut b = std::fs::read(
        PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/fixtures/appimage/upstream-rsa3072.AppImage"),
    )
    .unwrap();
    let i = b.len() - 500;
    b[i] ^= 0x01; // inside the SquashFS image, covered by the signature
    let f = write(dir.path(), "bad-signature.AppImage", &b);
    assert_eq!(json(&["verify"], &f).1["status"], "invalid");
    assert_eq!(ulai(&["verify"], &f).status.code(), Some(4));
    let (code, j) = json(&["inspect"], &f);
    assert_eq!(j["authenticated"], false);
    assert!(code == 0 || code == 5, "{code}");
    let (code, j) = json(&["validate"], &f);
    assert_ne!(code, 0);
    assert!(
        errors(&j).iter().any(|e| e.contains("signature")),
        "{:?}",
        errors(&j)
    );
    assert_no_exec(&f);
}

#[test]
fn path_traversal_through_symlinks() {
    let dir = tempfile::tempdir().unwrap();
    let fs = image(|w| {
        w.push_symlink("../../../../../../bin/sh", "AppRun", h(0o777))
            .unwrap();
        w.push_symlink(
            "../../../../../../etc/passwd",
            "org.evil.App.desktop",
            h(0o777),
        )
        .unwrap();
        w.push_symlink("/etc/shadow", "org.evil.App.png", h(0o777))
            .unwrap();
        w.push_symlink("/etc/passwd", ".DirIcon", h(0o777)).unwrap();
        w.push_dir(".ulai", h(0o755)).unwrap();
        w.push_symlink(
            "../../../../../../etc/hostname",
            ".ulai/manifest.json",
            h(0o777),
        )
        .unwrap();
    });
    let f = write(
        dir.path(),
        "traversal.AppImage",
        &Builder::default().fs(&fs).build(),
    );
    let (code, j) = json(&["inspect"], &f);
    assert_eq!(code, 0);
    let c = &j["contents"];
    assert_eq!(c["apprun"], false, "AppRun escapes the image");
    assert!(c["desktop"].is_null(), "{c}");
    assert!(
        c["icon"].is_null(),
        "/etc/shadow must resolve inside the image, where it does not exist: {c}"
    );
    assert!(
        c["manifest_error"]
            .as_str()
            .unwrap()
            .contains("escapes the image root"),
        "{c}"
    );
    let (code, j) = json(&["validate"], &f);
    assert_eq!(code, 4);
    let e = errors(&j);
    assert!(e.iter().any(|e| e.starts_with("\"entry_point\"")), "{e:?}");
    // Nothing from the host's /etc ever appears.
    for cmd in [&["inspect"][..], &["validate"], &["inspect", "--json"]] {
        let out = String::from_utf8(ulai(cmd, &f).stdout).unwrap();
        assert!(
            !out.contains("root:x:0:0") && !out.contains("root:"),
            "{cmd:?} leaked a host file:\n{out}"
        );
    }
    assert_no_exec(&f);
}

#[test]
fn compression_ratio_bomb() {
    // 20 MB of zeros behind an ELF magic: a few KB compressed. validate reads
    // every bundled ELF in full, so the ratio limit must stop it.
    let dir = tempfile::tempdir().unwrap();
    let mut bomb = b"\x7fELF".to_vec();
    bomb.resize(20 << 20, 0);
    let fs = image(|w| {
        w.push_file(Cursor::new(b"#!/bin/sh\n".to_vec()), "AppRun", h(0o755))
            .unwrap();
        w.push_file(Cursor::new(bomb), "tool", h(0o755)).unwrap();
    });
    assert!(fs.len() < 100_000, "the bomb compresses well: {}", fs.len());
    let f = write(
        dir.path(),
        "ratio-bomb.AppImage",
        &Builder::default().fs(&fs).build(),
    );
    let (code, j) = json(&["validate"], &f);
    assert_eq!(code, 4);
    let e = errors(&j);
    assert!(
        e.iter()
            .any(|e| e.contains("limit") && e.contains("decompressed")),
        "{e:?}"
    );
    assert_no_exec(&f);
}

/// Data written with 128 KiB blocks, superblock patched to claim 4 KiB. The
/// image is rejected safely (backhand's own consistency checks usually fire
/// before ULAI's per-block cap; the cap itself is tested directly in
/// `imagefs::tests::hook_caps_decompression_bombs`).
#[test]
fn inconsistent_block_size_fails_safely() {
    let dir = tempfile::tempdir().unwrap();
    let fs = image(|w| {
        w.push_file(Cursor::new(b"#!/bin/sh\n".to_vec()), "AppRun", h(0o755))
            .unwrap();
        let desktop = format!("[Desktop Entry]\nName={}\n", "A".repeat(30_000));
        w.push_file(
            Cursor::new(desktop.into_bytes()),
            "org.bomb.App.desktop",
            h(0o644),
        )
        .unwrap();
        w.push_file(
            Cursor::new(vec![b'\x7f', b'E', b'L', b'F', 0, 0, 0, 0].repeat(4096)),
            "tool",
            h(0o755),
        )
        .unwrap();
    });
    let (mut bytes, layout) = Builder::default().fs(&fs).build_with_layout();
    let sb = layout.fs_offset as usize;
    bytes[sb + 12..sb + 16].copy_from_slice(&4096u32.to_le_bytes()); // block_size
    bytes[sb + 22..sb + 24].copy_from_slice(&12u16.to_le_bytes()); // block_log
    let f = write(dir.path(), "block-bomb.AppImage", &bytes);
    let (code, j) = json(&["inspect"], &f);
    assert!(code == 0 || code == 5, "{code}");
    assert!(
        j["contents"]["desktop"].is_null() || j["status"] == "corrupt",
        "the oversized block was not accepted: {j}"
    );
    let (code, j) = json(&["validate"], &f);
    assert!(code == 4 || code == 5, "{code}: {j}");
    assert_no_exec(&f);
}
