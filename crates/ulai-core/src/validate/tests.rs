// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::Cursor;
use std::path::PathBuf;

use backhand::compression::Compressor;
use backhand::{FilesystemWriter, NodeHeader};

use super::*;
use crate::testing_appimage::{Builder, temp_file};

#[test]
fn classification() {
    use LibClass::*;
    let cases: &[(&str, Option<LibClass>)] = &[
        ("libc.so.6", Some(Glibc)),
        ("libc-2.31.so", Some(Glibc)),
        ("libm.so.6", Some(Glibc)),
        ("libpthread.so.0", Some(Glibc)),
        ("libutil.so.1", Some(Glibc)),
        ("ld-linux-x86-64.so.2", Some(Glibc)),
        ("libcairo.so.2", None),
        ("libmount.so.1", None),
        ("librtmp.so.1", None),
        ("libuuid.so.1", None),
        ("libz.so.1", None),
        ("libGL.so.1", Some(Gpu)),
        ("libGLX_mesa.so.0", Some(Gpu)),
        ("libGLESv2.so.2", Some(Gpu)),
        ("libGLdispatch.so.0", Some(Gpu)),
        ("libEGL_nvidia.so.0", Some(Gpu)),
        ("libvulkan.so.1", Some(Gpu)),
        ("libvulkan_intel.so", Some(Gpu)),
        ("libdrm_amdgpu.so.1", Some(Gpu)),
        ("libgbm.so.1", Some(Gpu)),
        ("iris_dri.so", Some(Gpu)),
        ("libgallium-24.2.so", Some(Gpu)),
        ("libnvidia-glcore.so.550.54", Some(Gpu)),
        ("libGLU.so.1", None),
        ("libGLEW.so.2.2", None),
        ("libstdc++.so.6", Some(Warn)),
        ("libgcc_s.so.1", Some(Warn)),
        ("libLLVM-17.so", Some(Warn)),
        ("libfontconfig.so.1", Some(Warn)),
    ];
    for (name, want) in cases {
        assert_eq!(classify(name), *want, "{name}");
    }
}

fn fixture(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/fixtures/appimage")
        .join(name)
}

fn errors(r: &Report) -> Vec<(&'static str, Option<String>)> {
    r.findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .map(|f| (f.check, f.path.clone()))
        .collect()
}

#[test]
fn signed_fixture_conforms() {
    let r = validate(&fixture("upstream-rsa3072.AppImage")).unwrap();
    assert_eq!(r.status, Status::Conforms, "{:#?}", r.findings);
    assert_eq!(r.signature, Some(verify::Status::Valid));
    assert_eq!(r.status.exit_code(), 0);
}

#[test]
fn legacy_fixture_is_not_a_ulai_file() {
    let r = validate(&fixture("legacy-unsigned.AppImage")).unwrap();
    assert_eq!(r.status, Status::DoesNotConform);
    assert!(
        errors(&r).iter().any(|(c, _)| *c == "manifest"),
        "{:#?}",
        r.findings
    );
    assert!(
        r.findings
            .iter()
            .any(|f| f.check == "signature" && f.severity == Severity::Warning)
    );
    assert_eq!(r.status.exit_code(), 4);
}

fn h(mode: u16) -> NodeHeader {
    NodeHeader {
        permissions: mode,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n0000";

fn manifest(glibc_floor: &str) -> Vec<u8> {
    format!(
        r#"{{"ulai":"0.1","id":"org.test.App","name":"Test","version":"1","summary":"s",
            "arch":["x86_64"],"runtime_mode":"native","glibc_floor":"{glibc_floor}","permissions":[]}}"#
    )
    .into_bytes()
}

/// A minimal unsigned ULAI image, then `extra` files.
fn ulai_image(
    apprun_mode: u16,
    extra: impl FnOnce(&mut FilesystemWriter),
) -> tempfile::NamedTempFile {
    let mut w = FilesystemWriter::default();
    w.set_compressor(backhand::FilesystemCompressor::new(Compressor::Gzip, None).unwrap());
    w.push_file(
        Cursor::new(b"#!/bin/sh\n".to_vec()),
        "AppRun",
        h(apprun_mode),
    )
    .unwrap();
    w.push_file(
        Cursor::new(b"[Desktop Entry]\nName=T\nIcon=org.test.App\n".to_vec()),
        "org.test.App.desktop",
        h(0o644),
    )
    .unwrap();
    w.push_file(Cursor::new(PNG.to_vec()), "org.test.App.png", h(0o644))
        .unwrap();
    w.push_dir(".ulai", h(0o755)).unwrap();
    w.push_file(
        Cursor::new(manifest("2.17")),
        ".ulai/manifest.json",
        h(0o644),
    )
    .unwrap();
    extra(&mut w);
    let mut out = Cursor::new(Vec::new());
    w.write(&mut out).unwrap();
    temp_file(&Builder::default().fs(&out.into_inner()).build())
}

/// A small, real ELF (our synthetic AppImage runtime), with a machine byte.
fn small_elf(machine: u16) -> Vec<u8> {
    let mut b = Builder {
        sections: vec![],
        ..Builder::default()
    }
    .fs(b"x")
    .build();
    b[18..20].copy_from_slice(&machine.to_le_bytes());
    b
}

#[test]
fn minimal_ulai_image_conforms_apart_from_signature() {
    let f = ulai_image(0o755, |_| {});
    let r = validate(f.path()).unwrap();
    assert_eq!(r.status, Status::Conforms, "{:#?}", r.findings);
    assert!(
        r.findings.iter().any(|f| f.check == "signature"),
        "unsigned is a warning"
    );
}

#[test]
fn bundled_glibc_and_gpu_libraries_are_errors() {
    let f = ulai_image(0o755, |w| {
        w.push_dir("usr", h(0o755)).unwrap();
        w.push_dir("usr/lib", h(0o755)).unwrap();
        w.push_file(Cursor::new(small_elf(62)), "usr/lib/libc.so.6", h(0o755))
            .unwrap();
        w.push_file(Cursor::new(small_elf(62)), "usr/lib/iris_dri.so", h(0o755))
            .unwrap();
        w.push_file(
            Cursor::new(small_elf(62)),
            "usr/lib/libstdc++.so.6",
            h(0o755),
        )
        .unwrap();
        w.push_file(
            Cursor::new(small_elf(62)),
            "usr/lib/libGLEW.so.2.2",
            h(0o755),
        )
        .unwrap();
    });
    let r = validate(f.path()).unwrap();
    assert_eq!(r.status, Status::DoesNotConform);
    let e = errors(&r);
    assert!(
        e.contains(&("excluded_library", Some("usr/lib/libc.so.6".into()))),
        "{e:?}"
    );
    assert!(
        e.contains(&("excluded_library", Some("usr/lib/iris_dri.so".into()))),
        "{e:?}"
    );
    assert!(
        !e.iter()
            .any(|(_, p)| p.as_deref() == Some("usr/lib/libGLEW.so.2.2"))
    );
    assert!(r.summary.libstdcxx_bundled);
    assert_eq!(r.summary.elf_files, 4);
}

#[test]
fn wrong_architecture_is_an_error() {
    let f = ulai_image(0o755, |w| {
        w.push_file(Cursor::new(small_elf(183)), "tool", h(0o755))
            .unwrap();
    });
    let r = validate(f.path()).unwrap();
    assert!(
        errors(&r).contains(&("arch", Some("tool".into()))),
        "{:#?}",
        r.findings
    );
}

#[test]
fn appdir_conventions() {
    let f = ulai_image(0o644, |w| {
        w.push_file(
            Cursor::new(b"[Desktop Entry]\n".to_vec()),
            "second.desktop",
            h(0o644),
        )
        .unwrap();
    });
    let e = errors(&validate(f.path()).unwrap());
    assert!(e.contains(&("entry_point", Some("AppRun".into()))), "{e:?}");
    assert!(e.iter().any(|(c, _)| *c == "desktop_entry"), "{e:?}");
}

#[test]
fn glibc_floor_is_enforced_with_a_real_dynamic_elf() {
    // Our own test binary: dynamically linked against glibc on the default
    // target, with GLIBC_2.x symbol versions. Bundled, never executed.
    if !cfg!(target_env = "gnu") {
        return;
    }
    let me = std::fs::read(std::env::current_exe().unwrap()).unwrap();
    let mut w = FilesystemWriter::default();
    w.set_compressor(backhand::FilesystemCompressor::new(Compressor::Gzip, None).unwrap());
    w.push_file(Cursor::new(b"#!/bin/sh\n".to_vec()), "AppRun", h(0o755))
        .unwrap();
    w.push_file(
        Cursor::new(b"[Desktop Entry]\nIcon=org.test.App\n".to_vec()),
        "org.test.App.desktop",
        h(0o644),
    )
    .unwrap();
    w.push_file(Cursor::new(PNG.to_vec()), "org.test.App.png", h(0o644))
        .unwrap();
    w.push_dir(".ulai", h(0o755)).unwrap();
    w.push_file(
        Cursor::new(manifest("2.1")),
        ".ulai/manifest.json",
        h(0o644),
    )
    .unwrap();
    w.push_file(Cursor::new(me), "tool", h(0o755)).unwrap();
    let mut out = Cursor::new(Vec::new());
    w.write(&mut out).unwrap();
    let f = temp_file(&Builder::default().fs(&out.into_inner()).build());
    let r = validate(f.path()).unwrap();
    assert!(
        errors(&r).contains(&("glibc_floor", Some("tool".into()))),
        "{:#?}",
        r.findings
    );
    assert!(r.summary.max_glibc.is_some());
}

#[test]
fn absolute_rpath_is_an_error() {
    let info = ElfInfo {
        machine: "x86_64".into(),
        rpaths: vec!["$ORIGIN/../lib".into(), "/usr/local/lib".into()],
        ..ElfInfo::default()
    };
    let mut out = Out {
        findings: Vec::new(),
    };
    check_one_elf("usr/bin/tool", &info, None, &mut out);
    assert_eq!(out.findings.len(), 1);
    assert!(out.findings[0].message.contains("/usr/local/lib"));
}

#[test]
fn dwarfs_and_garbage_are_not_validated() {
    let f = temp_file(&Builder::default().fs(b"DWARFS\x02\x05").build());
    assert_eq!(validate(f.path()).unwrap().status, Status::Unsupported);
    let f = temp_file(b"not an appimage");
    assert_eq!(validate(f.path()).unwrap().status.exit_code(), 5);
}
