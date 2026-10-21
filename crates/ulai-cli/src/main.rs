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
    match io::stdout().lock().write_all(text.as_bytes()) {
        // `ulai doctor | head`: the reader went away; not our failure.
        Err(e) if e.kind() == io::ErrorKind::BrokenPipe => Ok(ExitCode::SUCCESS),
        other => {
            other.context("writing report")?;
            Ok(ExitCode::SUCCESS)
        }
    }
}
