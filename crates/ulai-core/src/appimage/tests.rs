// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

use super::*;
use crate::testing_appimage::{Builder, Class, temp_file};

fn open(bytes: &[u8]) -> Result<Container, ContainerError> {
    let f = temp_file(bytes);
    Container::open(f.path())
}

fn corrupt_msg(r: Result<Container, ContainerError>) -> String {
    match r {
        Err(ContainerError::Corrupt(m)) => m,
        other => panic!("expected Corrupt, got {other:?}"),
    }
}

#[test]
fn valid_elf64_squashfs() {
    let (bytes, layout) = Builder::default().build_with_layout();
    let c = open(&bytes).unwrap();
    assert_eq!(c.class, ElfClass::Elf64);
    assert_eq!(c.fs_kind, FsKind::Squashfs);
    assert_eq!(c.fs_offset, layout.fs_offset);
    let (off, size) = layout.sections[".sha256_sig"];
    assert_eq!(c.sections.signature, Some(off..off + size));
    assert!(c.sections.key.is_some() && c.sections.digest_md5.is_some());
}

#[test]
fn valid_elf32_and_dwarfs() {
    let b = Builder {
        class: Class::Elf32,
        ..Builder::default()
    }
    .fs(b"DWARFS\x02\x05...");
    let c = open(&b.build()).unwrap();
    assert_eq!(c.class, ElfClass::Elf32);
    assert_eq!(c.fs_kind, FsKind::Dwarfs);
}

#[test]
fn not_elf_and_not_type2() {
    assert!(matches!(
        open(b"hello world, definitely not ELF"),
        Err(ContainerError::NotElf)
    ));
    assert!(matches!(open(b""), Err(ContainerError::NotElf)));
    let b = Builder {
        type2_magic: false,
        ..Builder::default()
    };
    assert!(matches!(open(&b.build()), Err(ContainerError::NotType2)));
}

#[test]
fn missing_sections_are_fine() {
    let b = Builder {
        sections: vec![],
        ..Builder::default()
    };
    let c = open(&b.build()).unwrap();
    assert_eq!(c.sections, Sections::default());
}

#[test]
fn magic_must_be_exactly_at_offset() {
    // One byte early: the real offset holds "sqs...".
    let c = open(&Builder::default().fs(b"Xhsqs-shifted-by-one").build());
    assert!(matches!(c, Err(ContainerError::Unsupported(_))), "{c:?}");
    let c = open(&Builder::default().fs(b"ISO9660 something else").build());
    assert!(matches!(c, Err(ContainerError::Unsupported(_))));
}

#[test]
fn nothing_after_the_elf() {
    let m = corrupt_msg(open(&Builder::default().fs(b"").build()));
    assert!(m.contains("past the end"), "{m}");
}

#[test]
fn e_shoff_past_eof() {
    let b = Builder {
        e_shoff: Some(1 << 40),
        ..Builder::default()
    };
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("past the end"), "{m}");
}

#[test]
fn e_shoff_overflow() {
    let b = Builder {
        e_shoff: Some(u64::MAX - 10),
        ..Builder::default()
    };
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("overflow"), "{m}");
}

#[test]
fn huge_e_shnum() {
    let b = Builder {
        e_shnum: Some(u16::MAX),
        ..Builder::default()
    };
    assert!(matches!(open(&b.build()), Err(ContainerError::Corrupt(_))));
}

#[test]
fn zero_e_shnum() {
    let b = Builder {
        e_shnum: Some(0),
        ..Builder::default()
    };
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("e_shnum = 0"), "{m}");
}

#[test]
fn wrong_e_shentsize() {
    let b = Builder {
        e_shentsize: Some(63),
        ..Builder::default()
    };
    assert!(matches!(open(&b.build()), Err(ContainerError::Corrupt(_))));
}

#[test]
fn section_past_eof() {
    let mut b = Builder::default();
    b.section_header.insert(".sig_key".into(), (100, 1 << 40));
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains(".sig_key runs past the end"), "{m}");
}

#[test]
fn section_offset_plus_size_overflows() {
    let mut b = Builder::default();
    b.section_header
        .insert(".sha256_sig".into(), (u64::MAX - 5, 100));
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("overflows"), "{m}");
}

#[test]
fn section_overlapping_filesystem() {
    let (bytes, layout) = Builder::default().build_with_layout();
    let mut b = Builder::default();
    b.section_header
        .insert(".sig_key".into(), (layout.fs_offset - 4, 8));
    let _ = bytes;
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("overlaps the filesystem image"), "{m}");
}

#[test]
fn overlapping_sections() {
    let (_, layout) = Builder::default().build_with_layout();
    let (sig_off, _) = layout.sections[".sha256_sig"];
    let mut b = Builder::default();
    b.section_header
        .insert(".sig_key".into(), (sig_off + 10, 100));
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("overlap"), "{m}");
}

#[test]
fn duplicate_section() {
    let mut b = Builder::default();
    b.sections.push((".sha256_sig".into(), vec![0; 16]));
    let m = corrupt_msg(open(&b.build()));
    assert!(m.contains("duplicate .sha256_sig"), "{m}");
}

#[test]
fn digest_zeroes_each_range_independently() {
    // Non-contiguous sections: something between signature and key.
    let b = Builder {
        sections: vec![
            (".sha256_sig".into(), b"SIGNATURE".to_vec()),
            (".filler".into(), b"keep-me".to_vec()),
            (".sig_key".into(), b"KEY".to_vec()),
        ],
        ..Builder::default()
    };
    let (bytes, layout) = b.build_with_layout();
    let c = open(&bytes).unwrap();
    let mut expected = bytes.clone();
    for n in [".sha256_sig", ".sig_key"] {
        let (o, s) = layout.sections[n];
        expected[o as usize..(o + s) as usize].fill(0);
    }
    let want = hex::encode(Sha256::digest(&expected));
    assert_eq!(c.signature_digest_hex().unwrap(), want);
    assert_eq!(want.len(), 64);
    assert_eq!(want, want.to_lowercase());
    // The bytes between the sections were not zeroed.
    let (fo, _) = layout.sections[".filler"];
    assert_eq!(&expected[fo as usize..fo as usize + 7], b"keep-me");
}

#[test]
fn digest_across_chunk_boundary() {
    // A 3 MiB file with a zeroed range spanning the 1 MiB chunk boundary.
    let data: Vec<u8> = (0..3 * 1024 * 1024).map(|i| (i % 251) as u8).collect();
    let f = temp_file(&data);
    let file = File::open(f.path()).unwrap();
    let range = (1 << 20) - 10..(1 << 20) + 10;
    let got = sha256_with_zeroed(&file, data.len() as u64, std::slice::from_ref(&range)).unwrap();
    let mut z = data.clone();
    z[range.start as usize..range.end as usize].fill(0);
    assert_eq!(got, <[u8; 32]>::from(Sha256::digest(&z)));
}

/// Real AppImages fetched by hand (never committed). Opt in with
/// `ULAI_REAL_APPS=~/.cache/ulai-real-apps cargo test -- --ignored`.
/// Expected values were measured independently in spike S4 (RESEARCH.md).
#[test]
#[ignore = "needs ULAI_REAL_APPS"]
fn real_apps_match_s4() {
    let Some(dir) = std::env::var_os("ULAI_REAL_APPS") else {
        eprintln!("skipped: ULAI_REAL_APPS not set");
        return;
    };
    let dir = std::path::PathBuf::from(dir);
    let expected: &[(&str, u64, FsKind)] = &[
        ("krita-6.0.4-x86_64.AppImage", 944632, FsKind::Squashfs),
        ("kdenlive-26.08.2-x86_64.AppImage", 944632, FsKind::Squashfs),
        (
            "shotcut-linux-x86_64-26.9.27.AppImage",
            193728,
            FsKind::Squashfs,
        ),
        ("KeePassXC-2.7.12-x86_64.AppImage", 193728, FsKind::Squashfs),
        (
            "audacity-linux-4.0.1-x86_64.AppImage",
            944632,
            FsKind::Squashfs,
        ),
        ("Obsidian-1.14.4.AppImage", 188392, FsKind::Squashfs),
        ("nvim-linux-x86_64.appimage", 944632, FsKind::Squashfs),
        (
            "OBS_Studio-32.2.2-1-anylinux-x86_64.AppImage",
            1507016,
            FsKind::Dwarfs,
        ),
        (
            "GIMP-3.2.6-2-anylinux-x86_64.AppImage",
            1507016,
            FsKind::Dwarfs,
        ),
        (
            "mpv-v0.41.0-anylinux-x86_64.AppImage",
            1507016,
            FsKind::Dwarfs,
        ),
    ];
    for (name, offset, kind) in expected {
        let c = Container::open(&dir.join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(
            (c.fs_offset, c.fs_kind, c.class),
            (*offset, *kind, ElfClass::Elf64),
            "{name}"
        );
        assert!(
            c.sections.signature.is_some() && c.sections.key.is_some(),
            "{name}"
        );
        eprintln!("ok {name}: {:?} at {}", c.fs_kind, c.fs_offset);
    }
}
