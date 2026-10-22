// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Branch tests with synthetic files. Valid signatures over whole AppImages
//! are tested against tool-made fixtures in `tests/fixtures/appimage`.

use std::io::Write;
use std::time::{Duration, UNIX_EPOCH};

use super::*;
use crate::testing_appimage::Builder;

struct Dir {
    dir: tempfile::TempDir,
}

impl Dir {
    fn new() -> Self {
        Self {
            dir: tempfile::tempdir().unwrap(),
        }
    }
    fn write(&self, name: &str, bytes: &[u8]) -> PathBuf {
        let p = self.dir.path().join(name);
        std::fs::File::create(&p).unwrap().write_all(bytes).unwrap();
        p
    }
}

fn run(path: &Path, opts: &Options) -> Report {
    verify(path, opts).expect("no I/O error")
}

fn fixture_key() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/openpgp/rsa3072-binary-sha256.key.asc")
}

#[test]
fn exit_codes_are_stable() {
    use Status::*;
    let got: Vec<u8> = [
        Valid,
        Unsigned,
        SignatureUnverifiable,
        Invalid,
        SignatureFromFuture,
        Corrupt,
        Unsupported,
    ]
    .iter()
    .map(|s| s.exit_code())
    .collect();
    assert_eq!(got, [0, 3, 3, 4, 4, 5, 5]);
    let json = serde_json::to_value(SignatureUnverifiable).unwrap();
    assert_eq!(json, "signature_unverifiable");
    let json = serde_json::to_value(SignatureFromFuture).unwrap();
    assert_eq!(json, "signature_from_future");
}

/// A tool-made AppImage checked with the clock set to before its signature
/// was made (a computer whose clock is wrong).
#[test]
fn signature_from_the_future_has_its_own_status() {
    let app = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/appimage/upstream-ed25519.AppImage");
    let r = run(
        &app,
        &Options {
            now: UNIX_EPOCH + Duration::from_secs(1_577_836_800),
            ..Options::default()
        },
    );
    assert_eq!(r.status, Status::SignatureFromFuture);
    assert_eq!(r.status.exit_code(), 4);
    let reason = r.reason.unwrap();
    assert!(reason.starts_with("the signature was created "), "{reason}");
    assert!(reason.contains(" days in the future"), "{reason}");
    assert!(reason.contains("clock"), "{reason}");
}

#[test]
fn not_an_appimage_is_unsupported() {
    let d = Dir::new();
    let r = run(
        &d.write("x", b"#!/bin/sh\necho not an AppImage\n"),
        &Options::default(),
    );
    assert_eq!(r.status, Status::Unsupported);
    assert_eq!(r.schema, 1);
}

#[test]
fn corrupt_layout_is_corrupt() {
    let d = Dir::new();
    let b = Builder {
        e_shoff: Some(1 << 40),
        ..Builder::default()
    };
    assert_eq!(
        run(&d.write("x", &b.build()), &Options::default()).status,
        Status::Corrupt
    );
}

#[test]
fn missing_file_is_an_io_error() {
    assert!(
        verify(
            Path::new("/nonexistent/ulai-test.AppImage"),
            &Options::default()
        )
        .is_err()
    );
}

#[test]
fn unsigned_without_detached_signature() {
    let d = Dir::new();
    let r = run(
        &d.write("app.AppImage", &Builder::default().build()),
        &Options::default(),
    );
    assert_eq!(r.status, Status::Unsigned);
    assert_eq!(r.method, None);
    assert_eq!(
        r.ulai_file, None,
        "the synthetic image is not a readable SquashFS"
    );
}

#[test]
fn detached_signature_without_key_is_unverifiable() {
    let d = Dir::new();
    let app = d.write("app.AppImage", &Builder::default().build());
    d.write("app.AppImage.sig", b"anything");
    let r = run(&app, &Options::default());
    assert_eq!(r.status, Status::SignatureUnverifiable);
    assert_eq!(r.method, Some(Method::Detached));
    assert!(r.signature_file.unwrap().ends_with("app.AppImage.sig"));
    assert_eq!(r.status.exit_code(), 3);
}

#[test]
fn asc_is_discovered_too_and_both_is_ambiguous() {
    let d = Dir::new();
    let app = d.write("app.AppImage", &Builder::default().build());
    d.write("app.AppImage.asc", b"anything");
    let r = run(&app, &Options::default());
    assert!(r.signature_file.unwrap().ends_with(".asc"));
    d.write("app.AppImage.sig", b"anything");
    let r = run(&app, &Options::default());
    assert_eq!(r.status, Status::SignatureUnverifiable);
    assert!(r.reason.unwrap().contains("both"));
}

#[test]
fn only_exact_names_are_discovered() {
    let d = Dir::new();
    let app = d.write("app.AppImage", &Builder::default().build());
    for other in [
        "app.sig",
        "app.AppImage.SIG",
        "app.AppImage.sig.asc",
        "app.AppImage.gpg",
        "SHA256SUMS.asc",
    ] {
        d.write(other, b"x");
    }
    assert_eq!(run(&app, &Options::default()).status, Status::Unsigned);
}

#[test]
fn garbage_detached_signature_with_key_is_corrupt() {
    let d = Dir::new();
    let app = d.write("app.AppImage", &Builder::default().build());
    d.write("app.AppImage.sig", b"not an OpenPGP signature");
    let opts = Options {
        key: Some(fixture_key()),
        ..Options::default()
    };
    let r = run(&app, &opts);
    assert_eq!(
        (r.status, r.key_source),
        (Status::Corrupt, Some(KeySource::Supplied))
    );
}

#[test]
fn embedded_signature_without_embedded_key() {
    let d = Dir::new();
    let app = d.write(
        "app.AppImage",
        &Builder::default()
            .set(".sha256_sig", b"-----BEGIN PGP SIGNATURE-----")
            .build(),
    );
    let r = run(&app, &Options::default());
    assert_eq!(r.status, Status::SignatureUnverifiable);
    assert_eq!(r.method, Some(Method::Embedded));
    // With --key the (garbage) signature is parsed: corrupt, not unverifiable.
    let r = run(
        &app,
        &Options {
            key: Some(fixture_key()),
            ..Options::default()
        },
    );
    assert_eq!(
        (r.status, r.key_source),
        (Status::Corrupt, Some(KeySource::Supplied))
    );
}

#[test]
fn embedded_garbage_is_corrupt_and_detached_is_then_ignored() {
    let d = Dir::new();
    let b = Builder::default()
        .set(".sha256_sig", b"garbage signature")
        .set(".sig_key", b"garbage key");
    let app = d.write("app.AppImage", &b.build());
    d.write("app.AppImage.sig", b"x");
    let r = run(&app, &Options::default());
    assert_eq!(
        (r.status, r.method),
        (Status::Corrupt, Some(Method::Embedded))
    );
    assert_eq!(r.signature_file, None);
}

#[test]
fn verify_reaches_the_signature_on_dwarfs_without_reading_it() {
    // A DwarFS "image" that is just a magic: the filesystem is never read.
    let d = Dir::new();
    let b = Builder::default()
        .fs(b"DWARFS\x02\x05nothing readable")
        .set(".sha256_sig", b"garbage signature")
        .set(".sig_key", b"garbage key");
    let r = run(&d.write("app.AppImage", &b.build()), &Options::default());
    assert_eq!((r.fs, r.status), (Some(FsKind::Dwarfs), Status::Corrupt));
    // Unsigned DwarFS files are legacy AppImages (never ULAI files).
    let r = run(
        &d.write(
            "legacy.AppImage",
            &Builder::default().fs(b"DWARFS\x02\x05").build(),
        ),
        &Options::default(),
    );
    assert_eq!((r.status, r.ulai_file), (Status::Unsigned, Some(false)));
}
