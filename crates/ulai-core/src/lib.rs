//! ULAI core library.
//!
//! `unsafe` is denied crate-wide; the single exception is [`sys`], which wraps
//! the raw syscalls nothing safe in the dependency set covers.

#![deny(unsafe_code)]
