// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Builds synthetic type 2 AppImages for tests: a minimal ELF (no code, never
//! executable) with named sections and an appended "filesystem", plus knobs
//! for producing hostile layouts.

use std::collections::HashMap;

const SHT_PROGBITS: u32 = 1;
const SHT_STRTAB: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone)]
pub struct Builder {
    pub class: Class,
    /// Named sections in file order, with their contents.
    pub sections: Vec<(String, Vec<u8>)>,
    /// Bytes appended after the section headers (the "filesystem").
    pub fs: Vec<u8>,
    /// Override `e_shoff`.
    pub e_shoff: Option<u64>,
    /// Override `e_shnum`.
    pub e_shnum: Option<u16>,
    /// Override `e_shentsize`.
    pub e_shentsize: Option<u16>,
    /// Override a section's (offset, size) in its header.
    pub section_header: HashMap<String, (u64, u64)>,
    /// Write the type 2 magic at offset 8.
    pub type2_magic: bool,
}

impl Default for Builder {
    fn default() -> Self {
        Self {
            class: Class::Elf64,
            sections: vec![
                (".digest_md5".into(), vec![0; 16]),
                (".upd_info".into(), vec![0; 1024]),
                (".sha256_sig".into(), vec![0; 1024]),
                (".sig_key".into(), vec![0; 8192]),
            ],
            fs: b"hsqs-not-really-a-squashfs".to_vec(),
            e_shoff: None,
            e_shnum: None,
            e_shentsize: None,
            section_header: HashMap::new(),
            type2_magic: true,
        }
    }
}

/// Where the builder put things, for tests that patch bytes.
#[derive(Debug, Clone, Default)]
pub struct Layout {
    /// (offset, size) of each named section's data.
    pub sections: HashMap<String, (u64, u64)>,
    /// Where the "filesystem" starts (the real ELF end).
    pub fs_offset: u64,
}

impl Builder {
    pub fn fs(mut self, fs: &[u8]) -> Self {
        self.fs = fs.to_vec();
        self
    }

    /// Sets the contents of a section, padded with zeros to its current size
    /// (or exactly `content` if the section is new).
    pub fn set(mut self, name: &str, content: &[u8]) -> Self {
        if let Some((_, data)) = self.sections.iter_mut().find(|(n, _)| n == name) {
            assert!(content.len() <= data.len(), "{name} content too large");
            data.fill(0);
            data[..content.len()].copy_from_slice(content);
        } else {
            self.sections.push((name.into(), content.to_vec()));
        }
        self
    }

    pub fn build(&self) -> Vec<u8> {
        self.build_with_layout().0
    }

    pub fn build_with_layout(&self) -> (Vec<u8>, Layout) {
        let is64 = self.class == Class::Elf64;
        let ehsize: u64 = if is64 { 64 } else { 52 };
        let shentsize: u64 = if is64 { 64 } else { 40 };

        // .shstrtab: "\0.shstrtab\0name1\0name2\0..."
        let mut shstrtab = vec![0u8];
        let mut name_off = Vec::new();
        for name in
            std::iter::once(".shstrtab").chain(self.sections.iter().map(|(n, _)| n.as_str()))
        {
            name_off.push(shstrtab.len() as u32);
            shstrtab.extend_from_slice(name.as_bytes());
            shstrtab.push(0);
        }

        let mut out = vec![0u8; ehsize as usize];
        let mut layout = Layout::default();
        let shstr_off = out.len() as u64;
        out.extend_from_slice(&shstrtab);
        let mut placed = Vec::new();
        for (name, data) in &self.sections {
            let off = out.len() as u64;
            out.extend_from_slice(data);
            layout
                .sections
                .insert(name.clone(), (off, data.len() as u64));
            placed.push((off, data.len() as u64));
        }
        // Align the section header table.
        while !out.len().is_multiple_of(8) {
            out.push(0);
        }
        let shoff = out.len() as u64;
        let shnum = 2 + self.sections.len() as u64;

        let push_sh = |out: &mut Vec<u8>, name: u32, ty: u32, off: u64, size: u64| {
            if is64 {
                out.extend_from_slice(&name.to_le_bytes());
                out.extend_from_slice(&ty.to_le_bytes());
                out.extend_from_slice(&0u64.to_le_bytes()); // flags
                out.extend_from_slice(&0u64.to_le_bytes()); // addr
                out.extend_from_slice(&off.to_le_bytes());
                out.extend_from_slice(&size.to_le_bytes());
                out.extend_from_slice(&0u32.to_le_bytes()); // link
                out.extend_from_slice(&0u32.to_le_bytes()); // info
                out.extend_from_slice(&1u64.to_le_bytes()); // addralign
                out.extend_from_slice(&0u64.to_le_bytes()); // entsize
            } else {
                for v in [name, ty, 0, 0, off as u32, size as u32, 0, 0, 1, 0] {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        };
        push_sh(&mut out, 0, 0, 0, 0); // SHN_UNDEF
        push_sh(
            &mut out,
            name_off[0],
            SHT_STRTAB,
            shstr_off,
            shstrtab.len() as u64,
        );
        for (i, (name, _)) in self.sections.iter().enumerate() {
            let (off, size) = self.section_header.get(name).copied().unwrap_or(placed[i]);
            push_sh(&mut out, name_off[i + 1], SHT_PROGBITS, off, size);
        }
        layout.fs_offset = out.len() as u64;
        out.extend_from_slice(&self.fs);

        // ELF header.
        let h = &mut out[..ehsize as usize];
        h[..4].copy_from_slice(b"\x7fELF");
        h[4] = if is64 { 2 } else { 1 }; // EI_CLASS
        h[5] = 1; // little endian
        h[6] = 1; // EV_CURRENT
        if self.type2_magic {
            h[8..11].copy_from_slice(&[0x41, 0x49, 0x02]);
        }
        let shoff = self.e_shoff.unwrap_or(shoff);
        let shnum = self.e_shnum.map(u64::from).unwrap_or(shnum) as u16;
        let shentsize = self.e_shentsize.unwrap_or(shentsize as u16);
        let w16 = |h: &mut [u8], at: usize, v: u16| h[at..at + 2].copy_from_slice(&v.to_le_bytes());
        w16(h, 16, 2); // ET_EXEC
        w16(h, 18, if is64 { 62 } else { 3 }); // x86_64 / i386
        h[20..24].copy_from_slice(&1u32.to_le_bytes());
        if is64 {
            h[40..48].copy_from_slice(&shoff.to_le_bytes());
            w16(h, 52, 64); // e_ehsize
            w16(h, 54, 56); // e_phentsize
            w16(h, 58, shentsize);
            w16(h, 60, shnum);
            w16(h, 62, 1); // e_shstrndx
        } else {
            h[32..36].copy_from_slice(&(shoff as u32).to_le_bytes());
            w16(h, 40, 52);
            w16(h, 42, 32);
            w16(h, 46, shentsize);
            w16(h, 48, shnum);
            w16(h, 50, 1);
        }
        (out, layout)
    }
}

/// Writes `bytes` to a new temporary file and returns it (kept alive by the
/// returned handle).
pub fn temp_file(bytes: &[u8]) -> tempfile::NamedTempFile {
    use std::io::Write;
    let mut f = tempfile::NamedTempFile::new().expect("tempfile");
    f.write_all(bytes).expect("write");
    f
}
