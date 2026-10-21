// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Runs the real `ulai` binary on the real host. These tests assert only the
//! shape of the output (exit code, JSON contract), never this machine's
//! values, so they pass on any system.

use std::process::{Command, Stdio};

fn ulai() -> Command {
    Command::new(env!("CARGO_BIN_EXE_ulai"))
}

#[test]
fn json_has_schema_1_and_every_section() {
    let out = ulai().args(["doctor", "--json"]).output().unwrap();
    assert!(out.status.success(), "exit {:?}", out.status);
    let v: serde_json::Value = serde_json::from_slice(&out.stdout).expect("valid JSON");
    assert_eq!(v["schema"], 1);
    let status = v["status"].as_str().expect("top-level status");
    assert!(
        ["ok", "partial", "unknown"].contains(&status),
        "status = {status}"
    );
    for section in [
        "kernel",
        "lsm",
        "landlock",
        "userns",
        "yama",
        "fuse",
        "libc",
        "session",
        "gpu",
        "dbus_proxy",
        "xdg",
    ] {
        let s = &v[section];
        let status = s["status"]
            .as_str()
            .unwrap_or_else(|| panic!("{section}.status"));
        assert!(
            ["ok", "partial", "unknown"].contains(&status),
            "{section}.status = {status}"
        );
        assert!(s["errors"].is_array(), "{section}.errors");
    }
    let label = v["landlock"]["label"].as_str().unwrap();
    assert!(["strong", "weak", "none"].contains(&label));
}

#[test]
fn human_output_exits_zero() {
    let out = ulai().arg("doctor").output().unwrap();
    assert!(out.status.success());
    let text = String::from_utf8(out.stdout).unwrap();
    assert!(text.starts_with("ULAI doctor "));
    assert!(text.contains("\nLandlock\n"));
}

#[test]
fn broken_pipe_is_not_a_failure() {
    // Read end closed before the child starts: every write gets EPIPE.
    let (reader, writer) = std::io::pipe().unwrap();
    drop(reader);
    let out = ulai()
        .arg("doctor")
        .stdout(writer)
        .stderr(Stdio::piped())
        .output()
        .unwrap();
    assert!(out.status.success(), "exit {:?}", out.status);
    assert!(
        out.stderr.is_empty(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
}

#[test]
fn userns_probe_child_is_hidden_from_help() {
    let out = ulai().arg("--help").output().unwrap();
    assert!(!String::from_utf8_lossy(&out.stdout).contains("__userns-probe"));
}
