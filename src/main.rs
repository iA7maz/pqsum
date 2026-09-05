//! Entry point: parse, run, and turn errors into the documented exit codes.

use std::io::Write;
use std::process::ExitCode;

use clap::Parser;

use pqsum::cli::{normalize_args, Cli};
use pqsum::error::Error;

fn main() -> ExitCode {
    pqsum::init();

    let cli = match Cli::try_parse_from(normalize_args(std::env::args_os())) {
        Ok(cli) => cli,
        Err(e) => {
            // clap prints --help and --version through the same error path,
            // and those are a success, not a usage mistake.
            let _ = e.print();
            return if e.use_stderr() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            };
        }
    };

    match pqsum::run(&cli) {
        Ok(()) => {
            // A closed pipe (`pqsum --list-algos | head`) is not a failure.
            let _ = std::io::stdout().flush();
            ExitCode::SUCCESS
        }
        Err(e) => {
            report(&e, cli.status);
            ExitCode::from(e.exit_code() as u8)
        }
    }
}

/// Print an error the way a Unix tool should: to stderr, prefixed with the
/// program name, with no stack trace or backtrace noise.
fn report(error: &Error, status_only: bool) {
    if status_only {
        return;
    }
    match error {
        // The per-file FAILED lines and the summary have already been
        // printed; repeating the count here would just be noise.
        Error::Verification(_) => {}
        other => eprintln!("pqsum: {other}"),
    }
}
