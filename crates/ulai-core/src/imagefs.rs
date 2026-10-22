// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! Read-only, in-process access to the SquashFS image of an AppImage
//! (SPEC §3.5). No FUSE, no execution, no C code.
//!
//! Decompression goes through [`Capped`], which decodes zstd with `ruzstd`
//! and gzip with `flate2` (miniz_oxide) and enforces a size cap on every
//! block: 8 KiB while the image's metadata is read (when it is opened), the
//! image's block size afterwards (file data). backhand reads all metadata
//! tables when it opens an image, so the stricter cap cannot reject a valid
//! data block; if that ever changed, the result would be a "corrupt" error,
//! not a silent weakening.

use std::cell::Cell;
use std::collections::BTreeMap;
use std::io::{BufReader, Read};

use backhand::compression::{CompressionAction, Compressor};
use backhand::kind::Kind;
use backhand::{
    BackhandError, FilesystemCompressor, FilesystemReader, InnerNode, SquashfsFileReader,
    SuperBlock,
};
use serde::Serialize;

use crate::appimage::{Container, FsKind};

/// Largest decompressed size of one metadata block (SquashFS constant).
pub const METADATA_BLOCK_MAX: usize = 8 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FsError {
    #[error("unsupported filesystem: {0}")]
    Unsupported(String),
    #[error("corrupt filesystem: {0}")]
    Corrupt(String),
    #[error("limit exceeded: {0}")]
    Limit(String),
    #[error("not found in the image: {0}")]
    NotFound(String),
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),
}

fn corrupt(m: impl Into<String>) -> FsError {
    FsError::Corrupt(m.into())
}

/// Bounds on what one image may make ULAI do (decompression-bomb and
/// resource protection).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    pub max_entries: usize,
    pub max_path_bytes: usize,
    pub max_symlink_hops: usize,
    /// Total bytes ULAI will decompress from one image.
    pub max_total_bytes: u64,
    /// Decompressed bytes per byte of the image on disk.
    pub max_ratio: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_entries: 1_000_000,
            max_path_bytes: 4096,
            max_symlink_hops: 40,
            max_total_bytes: 32 << 30,
            max_ratio: 100,
        }
    }
}

thread_local! {
    /// Cap for the next decompressed block on this thread; 0 = none set,
    /// which the hook treats as an error (fail closed).
    static BLOCK_CAP: Cell<usize> = const { Cell::new(0) };
}

/// Sets the per-block cap for the duration of `f`.
fn with_block_cap<T>(cap: usize, f: impl FnOnce() -> T) -> T {
    let prev = BLOCK_CAP.with(|c| c.replace(cap));
    let out = f();
    BLOCK_CAP.with(|c| c.set(prev));
    out
}

/// Decompressor hook with a hard output cap per block.
struct Capped;

impl Capped {
    fn read_capped(mut r: impl Read, out: &mut Vec<u8>, cap: usize) -> Result<(), BackhandError> {
        let start = out.len();
        let read = (&mut r)
            .take(cap as u64 + 1)
            .read_to_end(out)
            .map_err(|_| BackhandError::CorruptedOrInvalidSquashfs)?;
        if read > cap {
            out.truncate(start);
            return Err(BackhandError::CorruptedOrInvalidSquashfs);
        }
        Ok(())
    }
}

impl CompressionAction for Capped {
    type Error = BackhandError;
    type Compressor = Compressor;
    type FilesystemCompressor = FilesystemCompressor;
    type SuperBlock = SuperBlock;

    fn decompress(
        &self,
        bytes: &[u8],
        out: &mut Vec<u8>,
        c: Compressor,
    ) -> Result<(), BackhandError> {
        let cap = BLOCK_CAP.with(Cell::get);
        if cap == 0 {
            return Err(BackhandError::CorruptedOrInvalidSquashfs);
        }
        match c {
            Compressor::Uncompressed => {
                if bytes.len() > cap {
                    return Err(BackhandError::CorruptedOrInvalidSquashfs);
                }
                out.extend_from_slice(bytes);
                Ok(())
            }
            Compressor::Zstd => {
                let d = ruzstd::decoding::StreamingDecoder::new(bytes)
                    .map_err(|_| BackhandError::CorruptedOrInvalidSquashfs)?;
                Self::read_capped(d, out, cap)
            }
            Compressor::Gzip => Self::read_capped(flate2::read::ZlibDecoder::new(bytes), out, cap),
            other => Err(BackhandError::UnsupportedCompression(format!("{other:?}"))),
        }
    }

    fn compress(
        &self,
        _: &[u8],
        _: FilesystemCompressor,
        _: u32,
    ) -> Result<Vec<u8>, BackhandError> {
        Err(BackhandError::UnsupportedCompression(
            "ULAI never writes images".into(),
        ))
    }
}

static CAPPED: Capped = Capped;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EntryKind {
    File { size: u64 },
    Dir,
    Symlink { target: String },
    CharDevice,
    BlockDevice,
    Fifo,
    Socket,
}

/// One entry, with a validated path relative to the image root (`a/b`,
/// no leading slash; the root itself is not listed).
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Entry {
    pub path: String,
    #[serde(flatten)]
    pub kind: EntryKind,
    pub mode: u16,
}

/// An opened SquashFS image.
pub struct ImageFs {
    reader: FilesystemReader<'static>,
    entries: BTreeMap<String, Entry>,
    /// Data readers of regular files, by path (built once at open).
    files: BTreeMap<String, SquashfsFileReader>,
    block_size: usize,
    image_bytes: u64,
    limits: Limits,
    read_total: Cell<u64>,
}

impl std::fmt::Debug for ImageFs {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ImageFs")
            .field("entries", &self.entries.len())
            .field("block_size", &self.block_size)
            .finish()
    }
}

/// Error for a compression format ULAI does not read (xz, lzo, lz4, lzma).
fn map_open_error(e: BackhandError) -> FsError {
    match e {
        BackhandError::UnsupportedCompression(c) => {
            FsError::Unsupported(format!("SquashFS compression {c} is not supported"))
        }
        BackhandError::StdIo(e) => FsError::Io(e),
        other => corrupt(format!("SquashFS: {other}")),
    }
}

impl ImageFs {
    pub fn open(container: &Container, limits: Limits) -> Result<Self, FsError> {
        if container.fs_kind != FsKind::Squashfs {
            return Err(FsError::Unsupported(
                "DwarFS images cannot be read yet (planned before M3)".into(),
            ));
        }
        let file = container.file().try_clone()?;
        let image_bytes = container.len() - container.fs_offset;
        let reader = with_block_cap(METADATA_BLOCK_MAX, || {
            FilesystemReader::from_reader_with_offset_and_kind(
                BufReader::new(file),
                container.fs_offset,
                Kind::new_v4(&CAPPED),
            )
        })
        .map_err(map_open_error)?;
        let block_size = reader.block_size as usize;
        if !(4096..=1 << 20).contains(&block_size) || !block_size.is_power_of_two() {
            return Err(corrupt(format!("invalid block size {block_size}")));
        }

        let mut entries = BTreeMap::new();
        let mut files = BTreeMap::new();
        for node in reader.files() {
            let path = validate_path(&node.fullpath, limits.max_path_bytes)?;
            let Some(path) = path else { continue }; // the root
            let kind = match &node.inner {
                InnerNode::File(f) => {
                    files.insert(path.clone(), f.clone());
                    EntryKind::File {
                        size: f.file_len() as u64,
                    }
                }
                InnerNode::Dir(_) => EntryKind::Dir,
                InnerNode::Symlink(s) => EntryKind::Symlink {
                    target: s
                        .link
                        .to_str()
                        .ok_or_else(|| corrupt(format!("{path}: symlink target is not UTF-8")))?
                        .to_owned(),
                },
                InnerNode::CharacterDevice(_) => EntryKind::CharDevice,
                InnerNode::BlockDevice(_) => EntryKind::BlockDevice,
                InnerNode::NamedPipe => EntryKind::Fifo,
                InnerNode::Socket => EntryKind::Socket,
            };
            let entry = Entry {
                path: path.clone(),
                kind,
                mode: node.header.permissions,
            };
            if entries.insert(path.clone(), entry).is_some() {
                return Err(corrupt(format!("duplicate entry {path}")));
            }
            if entries.len() > limits.max_entries {
                return Err(FsError::Limit(format!(
                    "more than {} entries",
                    limits.max_entries
                )));
            }
        }
        Ok(Self {
            reader,
            entries,
            files,
            block_size,
            image_bytes,
            limits,
            read_total: Cell::new(0),
        })
    }

    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn get(&self, path: &str) -> Option<&Entry> {
        self.entries.get(path)
    }

    pub fn block_size(&self) -> usize {
        self.block_size
    }

    /// Resolves `path` (relative to the image root) through symlinks, staying
    /// inside the image. See [`resolve_in`].
    pub fn resolve(&self, path: &str) -> Result<String, FsError> {
        resolve_in(&self.entries, self.limits.max_symlink_hops, path)
    }

    /// The first `n` bytes of a regular file (fewer if it is shorter), e.g.
    /// to check for a magic number. Decompresses only the blocks needed.
    pub fn read_head(&self, path: &str, n: usize) -> Result<Vec<u8>, FsError> {
        let real = self.resolve(path)?;
        let f = self
            .files
            .get(&real)
            .ok_or_else(|| corrupt(format!("{real} is not a regular file")))?;
        let mut buf = Vec::with_capacity(n);
        with_block_cap(self.block_size, || {
            self.reader
                .file(f)
                .reader()
                .take(n as u64)
                .read_to_end(&mut buf)
        })
        .map_err(|e| corrupt(format!("{real}: {e}")))?;
        Ok(buf)
    }

    /// Reads a regular file (after resolving symlinks), at most `max` bytes.
    pub fn read(&self, path: &str, max: u64) -> Result<Vec<u8>, FsError> {
        let real = self.resolve(path)?;
        let size = match self.entries.get(&real).map(|e| &e.kind) {
            Some(EntryKind::File { size }) => *size,
            Some(_) => return Err(corrupt(format!("{real} is not a regular file"))),
            None => return Err(FsError::NotFound(real)),
        };
        if size > max {
            return Err(FsError::Limit(format!(
                "{real} is {size} bytes, limit {max}"
            )));
        }
        let total = self.read_total.get().saturating_add(size);
        let ratio_cap = self.image_bytes.saturating_mul(self.limits.max_ratio);
        if total > self.limits.max_total_bytes || total > ratio_cap {
            return Err(FsError::Limit(
                "total decompressed size exceeds the image limits".into(),
            ));
        }
        let f = self
            .files
            .get(&real)
            .ok_or_else(|| FsError::NotFound(real.clone()))?;
        let mut buf = Vec::new();
        with_block_cap(self.block_size, || {
            self.reader
                .file(f)
                .reader()
                .take(size + 1)
                .read_to_end(&mut buf)
        })
        .map_err(|e| corrupt(format!("{real}: {e}")))?;
        if buf.len() as u64 != size {
            return Err(corrupt(format!("{real}: size mismatch")));
        }
        self.read_total.set(total);
        Ok(buf)
    }
}

/// Resolves `path` through the symlinks in `entries`, staying inside the
/// image: absolute targets resolve against the image root (never the host),
/// `..` above the root is an error, and more than `max_hops` symlinks is an
/// error (loops).
pub fn resolve_in(
    entries: &BTreeMap<String, Entry>,
    max_hops: usize,
    path: &str,
) -> Result<String, FsError> {
    let mut pending: Vec<String> = split(path)?.into_iter().rev().collect();
    let mut done: Vec<String> = Vec::new();
    let mut hops = 0usize;
    while let Some(part) = pending.pop() {
        match part.as_str() {
            "." => continue,
            ".." => {
                if done.pop().is_none() {
                    return Err(corrupt(format!("{path}: escapes the image root")));
                }
                continue;
            }
            _ => {}
        }
        done.push(part);
        let here = done.join("/");
        match entries.get(&here).map(|e| &e.kind) {
            Some(EntryKind::Symlink { target }) => {
                hops += 1;
                if hops > max_hops {
                    return Err(corrupt(format!("{path}: too many symlink hops (loop?)")));
                }
                done.pop();
                if target.starts_with('/') {
                    done.clear();
                }
                for p in split(target)?.into_iter().rev() {
                    pending.push(p);
                }
            }
            Some(_) => {}
            None => return Err(FsError::NotFound(here)),
        }
    }
    Ok(done.join("/"))
}

/// Splits a path into components, rejecting empty and NUL-containing input.
fn split(p: &str) -> Result<Vec<String>, FsError> {
    if p.contains('\0') {
        return Err(corrupt("path contains a NUL byte"));
    }
    Ok(p.split('/')
        .filter(|c| !c.is_empty())
        .map(str::to_owned)
        .collect())
}

/// Validates a path from the image's directory tree. Returns `None` for the
/// root. Names must be UTF-8, non-empty, and not `.` or `..`.
fn validate_path(p: &std::path::Path, max_bytes: usize) -> Result<Option<String>, FsError> {
    let s = p.to_str().ok_or_else(|| corrupt("a path is not UTF-8"))?;
    if s.len() > max_bytes {
        return Err(FsError::Limit(format!(
            "path longer than {max_bytes} bytes"
        )));
    }
    let rel = s.strip_prefix('/').unwrap_or(s);
    if rel.is_empty() {
        return Ok(None);
    }
    for c in rel.split('/') {
        if c.is_empty() || c == "." || c == ".." || c.contains('\0') {
            return Err(corrupt(format!("invalid path component in {s:?}")));
        }
    }
    Ok(Some(rel.to_owned()))
}

#[cfg(test)]
mod tests;
