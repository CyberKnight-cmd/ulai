// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use std::io::{Cursor, Write};

use backhand::{FilesystemWriter, NodeHeader};

use super::*;
use crate::testing_appimage::{Builder, temp_file};

fn header(mode: u16) -> NodeHeader {
    NodeHeader {
        permissions: mode,
        uid: 0,
        gid: 0,
        mtime: 0,
    }
}

/// A gzip SquashFS built by backhand's writer (tests only).
fn squashfs(build: impl FnOnce(&mut FilesystemWriter)) -> Vec<u8> {
    let mut w = FilesystemWriter::default();
    w.set_compressor(backhand::FilesystemCompressor::new(Compressor::Gzip, None).expect("gzip"));
    build(&mut w);
    let mut out = Cursor::new(Vec::new());
    w.write(&mut out).expect("write squashfs");
    out.into_inner()
}

fn open_fs(fs: &[u8]) -> (tempfile::NamedTempFile, Result<ImageFs, FsError>) {
    let file = temp_file(&Builder::default().fs(fs).build());
    let c = Container::open(file.path()).expect("container");
    let r = ImageFs::open(&c, Limits::default());
    (file, r)
}

fn sample() -> Vec<u8> {
    squashfs(|w| {
        w.push_dir("usr", header(0o755)).unwrap();
        w.push_dir("usr/bin", header(0o755)).unwrap();
        w.push_file(
            Cursor::new(b"#!/bin/sh\necho hi\n".to_vec()),
            "AppRun",
            header(0o755),
        )
        .unwrap();
        w.push_file(
            Cursor::new(vec![7u8; 300_000]),
            "usr/bin/tool",
            header(0o755),
        )
        .unwrap();
        w.push_symlink("usr/bin/tool", "rel-link", header(0o777))
            .unwrap();
        w.push_symlink("/usr/bin/tool", "abs-link", header(0o777))
            .unwrap();
        w.push_symlink("../../AppRun", "usr/bin/up-link", header(0o777))
            .unwrap();
    })
}

#[test]
fn lists_and_reads_a_real_squashfs() {
    let (_f, fs) = open_fs(&sample());
    let fs = fs.unwrap();
    let paths: Vec<&str> = fs.entries().map(|e| e.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "AppRun",
            "abs-link",
            "rel-link",
            "usr",
            "usr/bin",
            "usr/bin/tool",
            "usr/bin/up-link"
        ]
    );
    assert_eq!(
        fs.get("usr/bin/tool").unwrap().kind,
        EntryKind::File { size: 300_000 }
    );
    assert_eq!(fs.read("AppRun", 1 << 20).unwrap(), b"#!/bin/sh\necho hi\n");
    // 300 kB spans more than one 128 KiB data block.
    assert_eq!(
        fs.read("usr/bin/tool", 1 << 20).unwrap(),
        vec![7u8; 300_000]
    );
}

#[test]
fn symlinks_resolve_inside_the_image() {
    let (_f, fs) = open_fs(&sample());
    let fs = fs.unwrap();
    assert_eq!(fs.resolve("rel-link").unwrap(), "usr/bin/tool");
    // Absolute target: from the image root, never the host's /usr/bin/tool.
    assert_eq!(fs.resolve("abs-link").unwrap(), "usr/bin/tool");
    assert_eq!(fs.resolve("usr/bin/up-link").unwrap(), "AppRun");
    assert_eq!(fs.read("abs-link", 1 << 20).unwrap().len(), 300_000);
}

#[test]
fn read_limits() {
    let (_f, fs) = open_fs(&sample());
    let fs = fs.unwrap();
    assert!(matches!(
        fs.read("usr/bin/tool", 1000),
        Err(FsError::Limit(_))
    ));
    assert!(matches!(fs.read("usr", 1000), Err(FsError::Corrupt(_))));
    assert!(matches!(
        fs.read("missing", 1000),
        Err(FsError::NotFound(_))
    ));
}

fn entries(list: &[(&str, EntryKind)]) -> BTreeMap<String, Entry> {
    list.iter()
        .map(|(p, k)| {
            (
                (*p).to_owned(),
                Entry {
                    path: (*p).to_owned(),
                    kind: k.clone(),
                    mode: 0o644,
                },
            )
        })
        .collect()
}

fn link(t: &str) -> EntryKind {
    EntryKind::Symlink { target: t.into() }
}

#[test]
fn hostile_symlinks() {
    let e = entries(&[
        ("loop-a", link("loop-b")),
        ("loop-b", link("loop-a")),
        ("self", link("self")),
        ("escape", link("../../etc/passwd")),
        ("abs-escape", link("/../etc/passwd")),
        ("etc-passwd", link("/etc/passwd")),
        ("dir", EntryKind::Dir),
        ("dir/file", EntryKind::File { size: 1 }),
    ]);
    let err = |p| resolve_in(&e, 40, p).unwrap_err().to_string();
    assert!(err("loop-a").contains("too many symlink hops"));
    assert!(err("self").contains("too many symlink hops"));
    assert!(err("escape").contains("escapes the image root"));
    assert!(err("abs-escape").contains("escapes the image root"));
    // /etc/passwd resolves against the image root, where it does not exist.
    assert!(matches!(resolve_in(&e, 40, "etc-passwd"), Err(FsError::NotFound(p)) if p == "etc"));
    assert!(err("../dir").contains("escapes the image root"));
    assert_eq!(resolve_in(&e, 40, "dir/./file").unwrap(), "dir/file");
    // A nested absolute symlink restarts at the image root, not at its
    // own directory: dir/abs -> /target is "target", never "dir/target".
    let n = entries(&[
        ("target", EntryKind::File { size: 1 }),
        ("dir", EntryKind::Dir),
        ("dir/target", EntryKind::File { size: 2 }),
        ("dir/abs", link("/target")),
    ]);
    assert_eq!(resolve_in(&n, 40, "dir/abs").unwrap(), "target");
    assert!(resolve_in(&e, 40, "dir/\0x").is_err());
}

#[test]
fn path_validation() {
    use std::path::Path;
    assert_eq!(validate_path(Path::new("/"), 100).unwrap(), None);
    assert_eq!(
        validate_path(Path::new("/a/b"), 100).unwrap().as_deref(),
        Some("a/b")
    );
    for bad in ["/a/../b", "/a/./b", "/a//b", "/..", "/a/"] {
        assert!(validate_path(Path::new(bad), 100).is_err(), "{bad}");
    }
    assert!(matches!(
        validate_path(Path::new("/aaaa"), 3),
        Err(FsError::Limit(_))
    ));
}

fn zlib(data: &[u8]) -> Vec<u8> {
    let mut e = flate2::write::ZlibEncoder::new(Vec::new(), flate2::Compression::best());
    e.write_all(data).unwrap();
    e.finish().unwrap()
}

fn zstd(data: &[u8]) -> Vec<u8> {
    ruzstd::encoding::compress_to_vec(data, ruzstd::encoding::CompressionLevel::Fastest)
}

#[test]
fn hook_caps_decompression_bombs() {
    let bomb = vec![0u8; 2 << 20]; // 2 MiB of zeros
    for (name, packed, c) in [
        ("zstd", zstd(&bomb), Compressor::Zstd),
        ("zlib", zlib(&bomb), Compressor::Gzip),
    ] {
        assert!(
            packed.len() < 20_000,
            "{name} bomb is small: {}",
            packed.len()
        );
        let mut out = Vec::new();
        // Data block cap (1 MiB): rejected.
        let r = with_block_cap(1 << 20, || CAPPED.decompress(&packed, &mut out, c));
        assert!(r.is_err(), "{name} over data cap");
        assert!(out.is_empty(), "{name}: partial output discarded");
        // Metadata cap (8 KiB): rejected.
        let r = with_block_cap(METADATA_BLOCK_MAX, || {
            CAPPED.decompress(&packed, &mut out, c)
        });
        assert!(r.is_err(), "{name} over metadata cap");
        // Exactly at the cap: accepted.
        let small = zlib_or_zstd(c, &vec![1u8; METADATA_BLOCK_MAX]);
        with_block_cap(METADATA_BLOCK_MAX, || {
            CAPPED.decompress(&small, &mut out, c)
        })
        .unwrap();
        assert_eq!(out.len(), METADATA_BLOCK_MAX);
    }
}

fn zlib_or_zstd(c: Compressor, data: &[u8]) -> Vec<u8> {
    if c == Compressor::Zstd {
        zstd(data)
    } else {
        zlib(data)
    }
}

#[test]
fn hook_fails_closed_without_a_cap_and_for_unsupported_formats() {
    let mut out = Vec::new();
    assert!(
        CAPPED
            .decompress(&zstd(b"x"), &mut out, Compressor::Zstd)
            .is_err()
    );
    for c in [
        Compressor::Xz,
        Compressor::Lzo,
        Compressor::Lz4,
        Compressor::Lzma,
    ] {
        let r = with_block_cap(1 << 20, || CAPPED.decompress(b"whatever", &mut out, c));
        assert!(
            matches!(r, Err(BackhandError::UnsupportedCompression(_))),
            "{c:?}"
        );
    }
    let r = with_block_cap(4, || {
        CAPPED.decompress(b"12345", &mut out, Compressor::Uncompressed)
    });
    assert!(r.is_err(), "uncompressed block over the cap");
}

#[test]
fn dwarfs_is_unsupported() {
    let file = temp_file(&Builder::default().fs(b"DWARFS\x02\x05rest").build());
    let c = Container::open(file.path()).unwrap();
    assert!(matches!(
        ImageFs::open(&c, Limits::default()),
        Err(FsError::Unsupported(_))
    ));
}

#[test]
fn garbage_squashfs_is_corrupt() {
    let (_f, r) = open_fs(b"hsqs and then nothing sensible at all, just bytes");
    assert!(
        matches!(r, Err(FsError::Corrupt(_) | FsError::Io(_))),
        "{r:?}"
    );
}

#[test]
fn entry_limit() {
    let file = temp_file(&Builder::default().fs(&sample()).build());
    let c = Container::open(file.path()).unwrap();
    let limits = Limits {
        max_entries: 3,
        ..Limits::default()
    };
    assert!(matches!(ImageFs::open(&c, limits), Err(FsError::Limit(_))));
}

/// Opt-in: every file of the real SquashFS apps (spike S2 counts).
#[test]
#[ignore = "needs ULAI_REAL_APPS"]
fn real_squashfs_apps_read_completely() {
    let Some(dir) = std::env::var_os("ULAI_REAL_APPS") else {
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    for (name, files) in [
        ("nvim-linux-x86_64.appimage", 2130),
        ("KeePassXC-2.7.12-x86_64.AppImage", 284),
        ("Obsidian-1.14.4.AppImage", 100),
    ] {
        let c = Container::open(&dir.join(name)).unwrap();
        let fs = ImageFs::open(&c, Limits::default()).unwrap_or_else(|e| panic!("{name}: {e}"));
        let mut n = 0;
        for e in fs
            .entries()
            .filter(|e| matches!(e.kind, EntryKind::File { .. }))
            .cloned()
            .collect::<Vec<_>>()
        {
            fs.read(&e.path, 1 << 30)
                .unwrap_or_else(|err| panic!("{name} {}: {err}", e.path));
            n += 1;
        }
        assert_eq!(n, files, "{name}");
        eprintln!("ok {name}: {n} files");
    }
}
