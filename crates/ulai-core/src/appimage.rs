// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! The AppImage type 2 container (SPEC §3.1): ELF header, the signature and
//! update sections, and where the filesystem image starts.
//!
//! Nothing here executes or maps the file. It is opened once, and every
//! read, including the digest, goes through that one [`File`] (SPEC §3.5).

use std::fs::File;
use std::io;
use std::ops::Range;
use std::os::unix::fs::FileExt;
use std::path::Path;

use object::read::ReadCache;
use object::read::elf::{FileHeader, SectionHeader};
use object::{Endianness, elf};
use sha2::{Digest, Sha256};

/// Offset 8 of a type 2 AppImage: `A`, `I`, 2.
pub const TYPE2_MAGIC: [u8; 3] = [0x41, 0x49, 0x02];

/// `e_ident` index of the ELF class byte.
const EI_CLASS: usize = 4;
const ELFCLASS32: u8 = 1;
const ELFCLASS64: u8 = 2;

/// Sections ULAI reads. Each may appear at most once.
pub const SECTION_DIGEST_MD5: &str = ".digest_md5";
pub const SECTION_SIGNATURE: &str = ".sha256_sig";
pub const SECTION_KEY: &str = ".sig_key";
pub const SECTION_UPDATE_INFO: &str = ".upd_info";
const KNOWN_SECTIONS: [&str; 4] = [
    SECTION_DIGEST_MD5,
    SECTION_SIGNATURE,
    SECTION_KEY,
    SECTION_UPDATE_INFO,
];

#[derive(Debug, thiserror::Error)]
pub enum ContainerError {
    #[error("not an ELF file")]
    NotElf,
    #[error("not a type 2 AppImage (no AI\\x02 magic at offset 8)")]
    NotType2,
    #[error("corrupt AppImage: {0}")]
    Corrupt(String),
    #[error("unsupported AppImage: {0}")]
    Unsupported(String),
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}

impl ContainerError {
    fn corrupt(msg: impl Into<String>) -> Self {
        Self::Corrupt(msg.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ElfClass {
    Elf32,
    Elf64,
}

/// The filesystem image appended to the runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum FsKind {
    /// Magic `hsqs`.
    Squashfs,
    /// Magic `DWARFS` (uruntime/AnyLinux). Legacy AppImages only.
    Dwarfs,
}

/// Byte range of one section in the file.
pub type ByteRange = Range<u64>;

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Sections {
    pub digest_md5: Option<ByteRange>,
    pub signature: Option<ByteRange>,
    pub key: Option<ByteRange>,
    pub update_info: Option<ByteRange>,
}

impl Sections {
    fn slot(&mut self, name: &str) -> Option<&mut Option<ByteRange>> {
        match name {
            SECTION_DIGEST_MD5 => Some(&mut self.digest_md5),
            SECTION_SIGNATURE => Some(&mut self.signature),
            SECTION_KEY => Some(&mut self.key),
            SECTION_UPDATE_INFO => Some(&mut self.update_info),
            _ => None,
        }
    }

    fn present(&self) -> Vec<(&'static str, ByteRange)> {
        [
            (SECTION_DIGEST_MD5, &self.digest_md5),
            (SECTION_SIGNATURE, &self.signature),
            (SECTION_KEY, &self.key),
            (SECTION_UPDATE_INFO, &self.update_info),
        ]
        .into_iter()
        .filter_map(|(n, r)| r.clone().map(|r| (n, r)))
        .collect()
    }
}

/// An opened, structurally valid AppImage.
#[derive(Debug)]
pub struct Container {
    file: File,
    len: u64,
    pub class: ElfClass,
    /// `e_machine` of the runtime (62 = x86_64, 183 = aarch64).
    pub machine: u16,
    /// Where the filesystem image starts: the end of the ELF, i.e.
    /// `e_shoff + e_shentsize × e_shnum`.
    pub fs_offset: u64,
    pub fs_kind: FsKind,
    pub sections: Sections,
}

impl Container {
    pub fn open(path: &Path) -> Result<Self, ContainerError> {
        Self::from_file(File::open(path)?)
    }

    pub fn from_file(file: File) -> Result<Self, ContainerError> {
        let len = file.metadata()?.len();
        let mut ident = [0u8; 16];
        read_exact_at(&file, &mut ident, 0, len).map_err(|_| ContainerError::NotElf)?;
        if ident[..4] != elf::ELFMAG {
            return Err(ContainerError::NotElf);
        }
        if ident[8..11] != TYPE2_MAGIC {
            return Err(ContainerError::NotType2);
        }
        let (class, fs_offset, sections) = match ident[EI_CLASS] {
            ELFCLASS64 => {
                let (o, s) = parse_elf::<elf::FileHeader64<Endianness>>(&file, len)?;
                (ElfClass::Elf64, o, s)
            }
            ELFCLASS32 => {
                let (o, s) = parse_elf::<elf::FileHeader32<Endianness>>(&file, len)?;
                (ElfClass::Elf32, o, s)
            }
            c => return Err(ContainerError::corrupt(format!("unknown ELF class {c}"))),
        };

        // The filesystem magic MUST start exactly at the offset; no scanning.
        let mut magic = [0u8; 6];
        read_exact_at(&file, &mut magic, fs_offset, len)
            .map_err(|_| ContainerError::corrupt("no filesystem image after the ELF"))?;
        let fs_kind = if magic[..4] == *b"hsqs" {
            FsKind::Squashfs
        } else if magic == *b"DWARFS" {
            FsKind::Dwarfs
        } else {
            return Err(ContainerError::Unsupported(format!(
                "no known filesystem magic at offset {fs_offset}"
            )));
        };

        // e_machine sits at offset 18 in both ELF classes; the header has
        // already been parsed, so its endianness byte is valid.
        let mut m = [0u8; 2];
        read_exact_at(&file, &mut m, 18, len)?;
        let machine = if ident[5] == 2 {
            u16::from_be_bytes(m)
        } else {
            u16::from_le_bytes(m)
        };

        Ok(Self {
            file,
            len,
            class,
            machine,
            fs_offset,
            fs_kind,
            sections,
        })
    }

    /// `x86_64`, `aarch64`, or `e_machine N`.
    pub fn machine_name(&self) -> String {
        match self.machine {
            62 => "x86_64".into(),
            183 => "aarch64".into(),
            m => format!("e_machine {m}"),
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The underlying file, for readers that need positioned access.
    pub fn file(&self) -> &File {
        &self.file
    }

    /// Contents of a section, or `None` if the file has no such section.
    pub fn section_bytes(&self, range: &Option<ByteRange>) -> io::Result<Option<Vec<u8>>> {
        let Some(r) = range else { return Ok(None) };
        let size = usize::try_from(r.end - r.start)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "section too large"))?;
        let mut buf = vec![0u8; size];
        self.file.read_exact_at(&mut buf, r.start)?;
        Ok(Some(buf))
    }

    /// SHA-256 of the whole file with `zeroed` byte ranges read as zeros.
    /// Each range is applied independently; they need not be contiguous.
    pub fn sha256_with_zeroed(&self, zeroed: &[ByteRange]) -> io::Result<[u8; 32]> {
        sha256_with_zeroed(&self.file, self.len, zeroed)
    }

    /// The AppImage signature digest (SPEC §3.2): SHA-256 with `.sha256_sig`
    /// and `.sig_key` zeroed, as lowercase hex.
    pub fn signature_digest_hex(&self) -> io::Result<String> {
        let zeroed: Vec<ByteRange> = [&self.sections.signature, &self.sections.key]
            .into_iter()
            .flatten()
            .cloned()
            .collect();
        Ok(hex::encode(self.sha256_with_zeroed(&zeroed)?))
    }
}

fn read_exact_at(file: &File, buf: &mut [u8], offset: u64, len: u64) -> io::Result<()> {
    let end = offset
        .checked_add(buf.len() as u64)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "offset overflow"))?;
    if end > len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "past end of file",
        ));
    }
    file.read_exact_at(buf, offset)
}

/// Parses the ELF header and section table; returns the filesystem offset
/// and the known sections.
fn parse_elf<H>(file: &File, len: u64) -> Result<(u64, Sections), ContainerError>
where
    H: FileHeader<Endian = Endianness>,
{
    let cache = ReadCache::new(file);
    let header =
        H::parse(&cache).map_err(|e| ContainerError::corrupt(format!("ELF header: {e}")))?;
    let endian = header
        .endian()
        .map_err(|e| ContainerError::corrupt(format!("ELF header: {e}")))?;

    // The end of the ELF, computed exactly as AppImage tooling does, with
    // checked arithmetic (SPEC §3.1).
    let shoff: u64 = header.e_shoff(endian).into();
    let shentsize = u64::from(header.e_shentsize(endian));
    let shnum = u64::from(header.e_shnum(endian));
    if shnum == 0 {
        // e_shnum == 0 means "no sections" or extended numbering; neither
        // gives the runtime's offset formula a meaning.
        return Err(ContainerError::corrupt(
            "ELF has no section headers (e_shnum = 0)",
        ));
    }
    if shentsize != std::mem::size_of::<H::SectionHeader>() as u64 {
        return Err(ContainerError::corrupt(format!(
            "unexpected e_shentsize {shentsize}"
        )));
    }
    let fs_offset = shentsize
        .checked_mul(shnum)
        .and_then(|t| t.checked_add(shoff))
        .ok_or_else(|| {
            ContainerError::corrupt("ELF end overflows (e_shoff + e_shentsize × e_shnum)")
        })?;
    if fs_offset >= len {
        return Err(ContainerError::corrupt(format!(
            "ELF end {fs_offset} is at or past the end of the file ({len} bytes)"
        )));
    }

    let table = header
        .sections(endian, &cache)
        .map_err(|e| ContainerError::corrupt(format!("section table: {e}")))?;
    let mut sections = Sections::default();
    for sh in table.iter() {
        let Ok(name) = table.section_name(endian, sh) else {
            continue;
        };
        let Ok(name) = std::str::from_utf8(name) else {
            continue;
        };
        if !KNOWN_SECTIONS.contains(&name) {
            continue;
        }
        if sh.sh_type(endian) == elf::SHT_NOBITS {
            return Err(ContainerError::corrupt(format!(
                "{name} occupies no file bytes"
            )));
        }
        let start: u64 = sh.sh_offset(endian).into();
        let size: u64 = sh.sh_size(endian).into();
        let end = start
            .checked_add(size)
            .ok_or_else(|| ContainerError::corrupt(format!("{name}: offset + size overflows")))?;
        if end > len {
            return Err(ContainerError::corrupt(format!(
                "{name} runs past the end of the file"
            )));
        }
        if end > fs_offset {
            return Err(ContainerError::corrupt(format!(
                "{name} overlaps the filesystem image"
            )));
        }
        let slot = sections.slot(name).expect("known section");
        if slot.is_some() {
            return Err(ContainerError::corrupt(format!("duplicate {name} section")));
        }
        *slot = Some(start..end);
    }

    let present = sections.present();
    for (i, (a, ra)) in present.iter().enumerate() {
        for (b, rb) in &present[i + 1..] {
            if ra.start < rb.end && rb.start < ra.end {
                return Err(ContainerError::corrupt(format!("{a} and {b} overlap")));
            }
        }
    }
    Ok((fs_offset, sections))
}

/// SHA-256 over `len` bytes of `file`, reading `zeroed` ranges as zeros.
pub fn sha256_with_zeroed(file: &File, len: u64, zeroed: &[ByteRange]) -> io::Result<[u8; 32]> {
    const CHUNK: usize = 1 << 20;
    let mut hasher = Sha256::new();
    let mut buf = vec![0u8; CHUNK];
    let mut pos = 0u64;
    while pos < len {
        let n = usize::try_from((len - pos).min(CHUNK as u64)).expect("chunk fits usize");
        let chunk = &mut buf[..n];
        file.read_exact_at(chunk, pos)?;
        let chunk_end = pos + n as u64;
        for r in zeroed {
            let s = r.start.max(pos);
            let e = r.end.min(chunk_end);
            if s < e {
                chunk[(s - pos) as usize..(e - pos) as usize].fill(0);
            }
        }
        hasher.update(&*chunk);
        pos = chunk_end;
    }
    Ok(hasher.finalize().into())
}

#[cfg(test)]
mod tests;
