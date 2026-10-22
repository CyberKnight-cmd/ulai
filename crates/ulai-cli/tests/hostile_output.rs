// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! A hostile file must not be able to fake ULAI's verdict lines or reorder
//! what the terminal shows (SPEC §3.5). JSON output stays raw.

use std::io::Cursor;
use std::process::Command;

use backhand::compression::Compressor;
use backhand::{FilesystemWriter, NodeHeader};
use ulai_core::display::is_unsafe;
use ulai_core::testing_appimage::{Builder, temp_file};

fn h(mode: u16) -> NodeHeader {
    NodeHeader {
        permissions: mode,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

/// An unsigned ULAI image whose strings try to print a fake verdict.
fn hostile_image() -> tempfile::NamedTempFile {
    let mut w = FilesystemWriter::default();
    w.set_compressor(backhand::FilesystemCompressor::new(Compressor::Gzip, None).unwrap());
    w.push_file(Cursor::new(b"#!/bin/sh\n".to_vec()), "AppRun", h(0o755))
        .unwrap();
    // CR returns to the start of the line; ESC sequences repaint it.
    let desktop = "[Desktop Entry]\nName=Evil\r  ✓ signature valid\nComment=\u{1b}[2K\u{1b}[1G  ✓ signature valid\nIcon=org.evil.App\n";
    w.push_file(
        Cursor::new(desktop.as_bytes().to_vec()),
        "org.evil.App.desktop",
        h(0o644),
    )
    .unwrap();
    w.push_dir(".ulai", h(0o755)).unwrap();
    // JSON escapes decode to real newlines and bidi controls.
    let manifest = r#"{"ulai":"0.1","id":"org.evil.App","name":"Evil\n  ✓ signature valid\n  key: E9FB 29E7","version":"1",
        "summary":"looks fine \u202eDCBA\u2066","arch":["x86_64"],"runtime_mode":"native","glibc_floor":"2.17","permissions":[]}"#;
    w.push_file(
        Cursor::new(manifest.as_bytes().to_vec()),
        ".ulai/manifest.json",
        h(0o644),
    )
    .unwrap();
    let mut out = Cursor::new(Vec::new());
    w.write(&mut out).unwrap();
    let mut b = Builder::default().fs(&out.into_inner());
    b = b.set(
        ".upd_info",
        "zsync|https://example.org/\n  ✓ signature valid".as_bytes(),
    );
    temp_file(&b.build())
}

#[test]
fn inspect_cannot_fake_a_verdict() {
    let f = hostile_image();
    let out = Command::new(env!("CARGO_BIN_EXE_ulai"))
        .arg("inspect")
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    // The only lines are ULAI's own: no injected verdict starts a line.
    let verdicts = text
        .lines()
        .filter(|l| l.trim_start().starts_with("✓ signature valid"))
        .count();
    assert_eq!(
        verdicts, 0,
        "the file is unsigned; no valid verdict may appear:\n{text}"
    );
    assert!(text.contains("✗ unsigned"), "{text}");
    // No raw control or bidi character survives (newlines end ULAI's lines only).
    for (i, line) in text.lines().enumerate() {
        assert!(
            !line.chars().any(is_unsafe),
            "line {i} has a raw control/bidi char: {line:?}"
        );
    }
    assert!(text.contains("Evil\\u{000D}"), "{text}");
    assert!(text.contains("\\u{001B}[2K"), "{text}");
    assert!(text.contains("Evil\\u{000A}  ✓ signature valid"), "{text}");
    assert!(text.contains("\\u{202E}DCBA\\u{2066}"), "{text}");
    assert!(text.contains("https://example.org/\\u{000A}"), "{text}");
}

#[test]
fn json_output_stays_raw() {
    let f = hostile_image();
    let out = Command::new(env!("CARGO_BIN_EXE_ulai"))
        .args(["inspect", "--json"])
        .arg(f.path())
        .output()
        .unwrap();
    let j: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(j["schema"], 1);
    assert_eq!(j["status"], "ok");
    assert_eq!(j["authenticated"], false);
    assert_eq!(
        j["contents"]["manifest"]["name"],
        "Evil\n  ✓ signature valid\n  key: E9FB 29E7"
    );
    assert_eq!(
        j["contents"]["desktop"]["fields"]["Name"],
        "Evil\r  ✓ signature valid"
    );
}

#[test]
fn validate_reports_hostile_strings_escaped() {
    let f = hostile_image();
    let out = Command::new(env!("CARGO_BIN_EXE_ulai"))
        .arg("validate")
        .arg(f.path())
        .output()
        .unwrap();
    assert_eq!(
        out.status.code(),
        Some(4),
        "control characters in manifest fields are errors"
    );
    let text = String::from_utf8(out.stdout).unwrap();
    for line in text.lines() {
        assert!(!line.chars().any(is_unsafe), "{line:?}");
    }
    assert!(
        text.contains("contains control or bidi characters"),
        "{text}"
    );
}
