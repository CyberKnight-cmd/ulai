// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! What `ulai validate` needs to know about an ELF file bundled in an image:
//! its machine, soname, needed libraries, RPATH/RUNPATH, and the highest
//! glibc / libstdc++ symbol versions it requires (SPEC §3.4, §11). Parsed
//! in memory with `object`; nothing is loaded or executed.

use object::read::elf::{Dyn, FileHeader};
use object::{Endianness, elf};
use serde::Serialize;

/// First bytes of every ELF file.
pub const ELF_MAGIC: [u8; 4] = *b"\x7fELF";

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
pub struct ElfInfo {
    /// `x86_64`, `aarch64`, or the ELF constant name for others.
    pub machine: String,
    pub soname: Option<String>,
    pub needed: Vec<String>,
    /// Entries of DT_RPATH and DT_RUNPATH, split on `:`.
    pub rpaths: Vec<String>,
    /// Highest `GLIBC_x.y` version required.
    pub max_glibc: Option<(u32, u32)>,
    /// Highest `GLIBCXX_x.y.z` version required.
    pub max_glibcxx: Option<Vec<u32>>,
    /// Highest `CXXABI_x.y.z` version required.
    pub max_cxxabi: Option<Vec<u32>>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
#[error("malformed ELF: {0}")]
pub struct ElfError(pub String);

pub fn is_elf(data: &[u8]) -> bool {
    data.starts_with(&ELF_MAGIC)
}

pub fn analyse(data: &[u8]) -> Result<ElfInfo, ElfError> {
    match data.get(4) {
        Some(1) => analyse_as::<elf::FileHeader32<Endianness>>(data),
        Some(2) => analyse_as::<elf::FileHeader64<Endianness>>(data),
        _ => Err(ElfError("unknown ELF class".into())),
    }
}

fn analyse_as<H: FileHeader<Endian = Endianness>>(data: &[u8]) -> Result<ElfInfo, ElfError> {
    let e = |m: object::read::Error| ElfError(m.to_string());
    let header = H::parse(data).map_err(e)?;
    let endian = header.endian().map_err(e)?;
    let machine = match header.e_machine(endian) {
        elf::EM_X86_64 => "x86_64".to_owned(),
        elf::EM_AARCH64 => "aarch64".to_owned(),
        m => format!("{m:?}"),
    };
    let mut info = ElfInfo {
        machine,
        ..ElfInfo::default()
    };
    let sections = header.sections(endian, data).map_err(e)?;

    if let Some((dyns, link)) = sections.dynamic(endian, data).map_err(e)? {
        let strings = sections.strings(endian, data, link).map_err(e)?;
        for d in dyns {
            let tag = d.d_tag(endian);
            if tag == elf::DT_NULL {
                break;
            }
            if ![
                elf::DT_SONAME,
                elf::DT_NEEDED,
                elf::DT_RPATH,
                elf::DT_RUNPATH,
            ]
            .contains(&tag)
            {
                continue;
            }
            let off: u64 = d.d_val(endian).into();
            let s = u32::try_from(off)
                .ok()
                .and_then(|o| strings.get(o).ok())
                .ok_or_else(|| ElfError("dynamic string out of range".into()))?;
            let s = String::from_utf8_lossy(s).into_owned();
            match tag {
                elf::DT_SONAME => info.soname = Some(s),
                elf::DT_NEEDED => info.needed.push(s),
                _ => info
                    .rpaths
                    .extend(s.split(':').filter(|p| !p.is_empty()).map(str::to_owned)),
            }
        }
    }

    if let Some((mut needs, link)) = sections.gnu_verneed(endian, data).map_err(e)? {
        let strings = sections.strings(endian, data, link).map_err(e)?;
        while let Some((_need, mut aux)) = needs.next().map_err(e)? {
            while let Some(a) = aux.next().map_err(e)? {
                let Ok(name) = strings.get(a.vna_name.get(endian)) else {
                    continue;
                };
                let name = String::from_utf8_lossy(name);
                if let Some(v) = name.strip_prefix("GLIBC_") {
                    if let Some(v) = crate::manifest::parse_version(v) {
                        info.max_glibc = info.max_glibc.max(Some(v));
                    }
                } else if let Some(v) = name.strip_prefix("GLIBCXX_") {
                    info.max_glibcxx = info.max_glibcxx.take().max(dotted(v));
                } else if let Some(v) = name.strip_prefix("CXXABI_") {
                    info.max_cxxabi = info.max_cxxabi.take().max(dotted(v));
                }
            }
        }
    }
    Ok(info)
}

/// `3.4.29` → `[3, 4, 29]`; `None` if any part is not a number.
fn dotted(v: &str) -> Option<Vec<u32>> {
    v.split('.').map(|p| p.parse().ok()).collect()
}

/// Formats `[3, 4, 29]` as `3.4.29`.
pub fn dotted_str(v: &[u32]) -> String {
    v.iter().map(u32::to_string).collect::<Vec<_>>().join(".")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dotted_versions_compare_numerically() {
        assert!(dotted("3.4.29") > dotted("3.4.9"));
        assert!(dotted("1.3.13") > dotted("1.3"));
        assert_eq!(dotted("x.1"), None);
        assert_eq!(dotted_str(&[3, 4, 29]), "3.4.29");
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        assert!(analyse(b"\x7fELF").is_err());
        assert!(analyse(b"\x7fELF\x02\x01\x01\0\0\0\0\0\0\0\0\0").is_err());
        assert!(analyse(b"").is_err());
        assert!(!is_elf(b"#!/bin/sh"));
    }

    /// The test binary itself: built by us, dynamically linked on the
    /// default (glibc) target. Static (musl) builds have no dynamic section.
    #[test]
    fn analyses_the_test_binary() {
        let data = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let info = analyse(&data).unwrap();
        assert_eq!(info.machine, std::env::consts::ARCH);
        if cfg!(target_env = "gnu") {
            assert!(
                info.needed.iter().any(|n| n.starts_with("libc.so")),
                "{info:?}"
            );
            assert!(info.max_glibc.unwrap() >= (2, 2), "{info:?}");
        }
    }
}
