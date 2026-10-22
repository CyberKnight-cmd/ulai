// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai verify` against AppImages made by the real tools
//! (tests/fixtures/appimage), plus the no-execution guarantee.

use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn fixtures() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../tests/fixtures/appimage")
}

fn ulai(args: &[&std::ffi::OsStr]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ulai"))
        .args(args)
        .output()
        .expect("run ulai")
}

fn verify(file: &Path, extra: &[&str]) -> (i32, serde_json::Value) {
    let mut args: Vec<&std::ffi::OsStr> =
        vec!["verify".as_ref(), file.as_os_str(), "--json".as_ref()];
    args.extend(extra.iter().map(|s| std::ffi::OsStr::new(*s)));
    let out = ulai(&args);
    let json = serde_json::from_slice(&out.stdout).unwrap_or_else(|e| {
        panic!(
            "{}: {e}\n{}",
            file.display(),
            String::from_utf8_lossy(&out.stderr)
        )
    });
    (out.status.code().expect("exit code"), json)
}

fn fingerprint(name: &str) -> String {
    let f = std::fs::read_to_string(fixtures().join("fingerprints.txt")).unwrap();
    f.lines()
        .find_map(|l| l.strip_prefix(&format!("{name} ")))
        .unwrap()
        .to_owned()
}

/// A temporary copy of a fixture, with optional byte edits.
fn copy(name: &str, edit: impl FnOnce(&mut Vec<u8>)) -> (tempfile::TempDir, PathBuf) {
    let dir = tempfile::tempdir().unwrap();
    let mut bytes = std::fs::read(fixtures().join(name)).unwrap();
    edit(&mut bytes);
    let p = dir.path().join(name);
    std::fs::write(&p, bytes).unwrap();
    (dir, p)
}

#[test]
fn embedded_signatures_from_real_tools_are_valid() {
    for (file, key, sig_type, hash) in [
        ("upstream-rsa3072.AppImage", "rsa3072", "text", "SHA-512"),
        ("upstream-ed25519.AppImage", "ed25519", "text", "SHA-512"),
        (
            "goappimage-rsa3072.AppImage",
            "rsa3072",
            "binary",
            "SHA-256",
        ),
    ] {
        let (code, j) = verify(&fixtures().join(file), &[]);
        assert_eq!(
            (code, j["status"].as_str()),
            (0, Some("valid")),
            "{file}: {j}"
        );
        assert_eq!(j["schema"], 1);
        assert_eq!(j["method"], "embedded");
        assert_eq!(j["key_source"], "embedded");
        assert_eq!(
            j["ulai_file"],
            serde_json::Value::Null,
            "{file}: not looked up for embedded"
        );
        assert_eq!(
            j["signer"]["primary_fingerprint"],
            fingerprint(key),
            "{file}"
        );
        assert_eq!(
            (
                j["signer"]["signature_type"].as_str(),
                j["signer"]["hash"].as_str()
            ),
            (Some(sig_type), Some(hash))
        );
    }
}

#[test]
fn elf32_appimage_from_the_i686_runtime_is_valid() {
    let (code, j) = verify(&fixtures().join("elf32-rsa3072.AppImage"), &[]);
    assert_eq!((code, j["status"].as_str()), (0, Some("valid")), "{j}");
    assert_eq!(j["signer"]["primary_fingerprint"], fingerprint("elf32"));
    let out = ulai(&[
        "inspect".as_ref(),
        "--json".as_ref(),
        fixtures().join("elf32-rsa3072.AppImage").as_os_str(),
    ]);
    let i: serde_json::Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(i["container"]["elf_class"], "elf32");
    assert_eq!(i["container"]["machine"], "i386");
    assert_eq!(i["container"]["fs"], "squashfs");
}

#[test]
fn tampered_embedded_file_is_invalid() {
    // Flip one byte inside the SquashFS image (the last 1000 bytes).
    let (_d, p) = copy("upstream-rsa3072.AppImage", |b| {
        let i = b.len() - 1000;
        b[i] ^= 1;
    });
    let (code, j) = verify(&p, &[]);
    assert_eq!((code, j["status"].as_str()), (4, Some("invalid")), "{j}");
}

#[test]
fn legacy_detached_signature() {
    let legacy = fixtures().join("legacy-unsigned.AppImage");
    let key = fixtures().join("rsa3072.pub.asc");
    let wrong = fixtures().join("ed25519.pub.asc");
    let (code, j) = verify(&legacy, &["--key", key.to_str().unwrap()]);
    assert_eq!(
        (code, j["status"].as_str(), j["method"].as_str()),
        (0, Some("valid"), Some("detached")),
        "{j}"
    );
    assert_eq!(j["ulai_file"], false);
    assert_eq!(j["signer"]["primary_fingerprint"], fingerprint("rsa3072"));
    // No key: unverifiable, never fetched from anywhere.
    let (code, j) = verify(&legacy, &[]);
    assert_eq!(
        (code, j["status"].as_str()),
        (3, Some("signature_unverifiable"))
    );
    // Wrong key: invalid.
    let (code, j) = verify(&legacy, &["--key", wrong.to_str().unwrap()]);
    assert_eq!((code, j["status"].as_str()), (4, Some("invalid")), "{j}");
}

#[test]
fn tampered_legacy_file_with_matching_sig_is_invalid() {
    let (d, p) = copy("legacy-unsigned.AppImage", |b| {
        let i = b.len() / 2;
        b[i] ^= 0x80;
    });
    std::fs::copy(
        fixtures().join("legacy-unsigned.AppImage.sig"),
        d.path().join("legacy-unsigned.AppImage.sig"),
    )
    .unwrap();
    let key = fixtures().join("rsa3072.pub.asc");
    let (code, j) = verify(&p, &["--key", key.to_str().unwrap()]);
    assert_eq!((code, j["status"].as_str()), (4, Some("invalid")), "{j}");
}

#[test]
fn detached_signature_next_to_a_ulai_file_is_ignored() {
    // Blank the embedded signature of a ULAI file, then offer a detached one.
    let (d, p) = copy("upstream-rsa3072.AppImage", |b| {
        let start = find(b, b"-----BEGIN PGP SIGNATURE-----");
        // Through the end of the armor, up to the section's NUL padding.
        let end = start
            + b[start..]
                .iter()
                .position(|&x| x == 0)
                .expect("NUL padding");
        b[start..end].fill(0);
    });
    std::fs::write(d.path().join("upstream-rsa3072.AppImage.sig"), b"anything").unwrap();
    let key = fixtures().join("rsa3072.pub.asc");
    let (code, j) = verify(&p, &["--key", key.to_str().unwrap()]);
    assert_eq!((code, j["status"].as_str()), (3, Some("unsigned")), "{j}");
    assert_eq!(j["ulai_file"], true);
    assert!(j["reason"].as_str().unwrap().contains("ADR-016"));
}

fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .expect("needle")
}

#[test]
fn human_output_shows_full_fingerprint_and_meaning() {
    let out = ulai(&[
        "verify".as_ref(),
        fixtures().join("upstream-ed25519.AppImage").as_os_str(),
    ]);
    assert_eq!(out.status.code(), Some(0));
    let text = String::from_utf8(out.stdout).unwrap();
    let fpr = fingerprint("ed25519");
    let grouped: Vec<String> = fpr
        .as_bytes()
        .chunks(4)
        .map(|c| String::from_utf8_lossy(c).into_owned())
        .collect();
    assert!(text.contains(&grouped.join(" ")), "{text}");
    assert!(text.contains("signed by the key embedded in it"));
}

/// The no-execution guarantee (AGENTS rule 1): tracing every exec in the
/// process tree, `ulai verify` and `ulai doctor` exec only... nothing but
/// themselves for verify. Skipped with a note if strace is unavailable.
#[test]
fn verify_never_executes_anything() {
    let Ok(strace) = which("strace") else {
        eprintln!("skipped: strace not installed");
        return;
    };
    let dir = tempfile::tempdir().unwrap();
    let log = dir.path().join("trace");
    for file in ["upstream-rsa3072.AppImage", "legacy-unsigned.AppImage"] {
        let fixture = fixtures().join(file);
        let status = Command::new(&strace)
            .args(["-f", "-qq", "-e", "trace=execve,execveat", "-o"])
            .arg(&log)
            .arg(env!("CARGO_BIN_EXE_ulai"))
            .arg("verify")
            .arg(&fixture)
            .arg("--key")
            .arg(fixtures().join("rsa3072.pub.asc"))
            .output()
            .expect("strace");
        assert!(
            status.status.success(),
            "{}",
            String::from_utf8_lossy(&status.stderr)
        );
        let trace = std::fs::read_to_string(&log).unwrap();
        let execs: Vec<&str> = trace
            .lines()
            .filter(|l| l.contains("execve(") || l.contains("execveat("))
            .collect();
        assert_eq!(
            execs.len(),
            1,
            "{file}: expected only ulai's own exec:\n{trace}"
        );
        assert!(
            execs[0].contains(env!("CARGO_BIN_EXE_ulai")),
            "{}",
            execs[0]
        );
    }
}

fn which(name: &str) -> Result<PathBuf, ()> {
    std::env::var_os("PATH")
        .and_then(|p| {
            std::env::split_paths(&p)
                .map(|d| d.join(name))
                .find(|p| p.is_file())
        })
        .ok_or(())
}
