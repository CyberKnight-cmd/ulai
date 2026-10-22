// SPDX-FileCopyrightText: 2026 The ULAI contributors
//
// SPDX-License-Identifier: GPL-3.0-or-later

//! `ulai`: the ULAI command-line tool.

#![forbid(unsafe_code)]

use std::io::{self, Write};
use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ulai_core::doctor;
use ulai_core::host::{SystemHost, USERNS_PROBE_SUBCOMMAND};

mod verify_cmd;

#[derive(Parser)]
#[command(
    name = "ulai",
    version,
    about = "Universal Linux Application Interface"
)]
struct Cli {
    /// Log debug details to stderr.
    #[arg(short, long, global = true)]
    verbose: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Report what this system supports and which protection ULAI can enforce.
    Doctor {
        /// Machine-readable output (see docs/doctor-schema.md).
        #[arg(long)]
        json: bool,
    },
    /// Verify an AppImage's signature (SPEC §3.2, ADR-016). Never executes it.
    ///
    /// Exit codes: 0 valid, 3 unsigned or signature unverifiable, 4 invalid,
    /// 5 corrupt or unsupported, 1 internal error.
    Verify {
        file: PathBuf,
        /// Detached signature file (legacy AppImages only). Without it,
        /// exactly FILE.sig or FILE.asc is used if present.
        #[arg(long, value_name = "FILE")]
        signature: Option<PathBuf>,
        /// Public key to verify with. Never fetched from the network.
        #[arg(long, value_name = "FILE")]
        key: Option<PathBuf>,
        /// Machine-readable output.
        #[arg(long)]
        json: bool,
    },
    /// Internal: user-namespace probe child run by `doctor`.
    #[command(name = USERNS_PROBE_SUBCOMMAND, hide = true)]
    UsernsProbe { dir: PathBuf },
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();
    match cli.command {
        // Runs before anything else so the process stays single-threaded.
        Command::UsernsProbe { dir } => {
            println!("{}", doctor::userns::child_main(&dir));
            Ok(ExitCode::SUCCESS)
        }
        Command::Doctor { json } => {
            init_logging(cli.verbose);
            run_doctor(json)
        }
        Command::Verify {
            file,
            signature,
            key,
            json,
        } => {
            init_logging(cli.verbose);
            verify_cmd::run(&file, signature, key, json)
        }
    }
}

fn init_logging(verbose: bool) {
    let level = if verbose {
        tracing::Level::DEBUG
    } else {
        tracing::Level::WARN
    };
    tracing_subscriber::fmt()
        .with_max_level(level)
        .with_writer(io::stderr)
        .without_time()
        .init();
}

fn run_doctor(json: bool) -> Result<ExitCode> {
    let host = SystemHost::new(std::env::current_exe().ok());
    let report = doctor::run(&host);
    let text = if json {
        let mut s = serde_json::to_string_pretty(&report).context("serialising report")?;
        s.push('\n');
        s
    } else {
        doctor::render::human(&report)
    };
    write_stdout(&text)?;
    Ok(ExitCode::SUCCESS)
}

/// Writes to stdout; a reader that went away (`| head`) is not an error.
pub(crate) fn write_stdout(text: &str) -> Result<()> {
    match io::stdout().lock().write_all(text.as_bytes()) {
        // `ulai doctor | head`: the reader went away; not our failure.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(()),
        other => other.context("writing output"),
    }
}
