//! Terminal output.
//!
//! Verification results follow the shape `sha256sum --check` uses, because
//! that is what existing scripts and existing habits expect:
//!
//! ```text
//! release.tar.gz: OK
//! release.tar.gz: FAILED (file contents have changed since signing)
//! ```
//!
//! `--quiet` drops the OK lines but keeps failures, and `--status` prints
//! nothing at all and leaves only the exit code, again matching coreutils.

use std::io::Write;
use std::path::Path;

#[derive(Debug, Clone, Copy, Default)]
pub struct Reporter {
    quiet: bool,
    status: bool,
    verbose: bool,
}

impl Reporter {
    pub fn new(quiet: bool, status: bool, verbose: bool) -> Self {
        Reporter {
            quiet,
            status,
            verbose,
        }
    }

    /// True when nothing at all should be printed.
    pub fn silent(&self) -> bool {
        self.status
    }

    pub fn is_verbose(&self) -> bool {
        self.verbose && !self.status
    }

    /// A file verified successfully.
    pub fn ok(&self, path: &Path) {
        if self.status || self.quiet {
            return;
        }
        println!("{}: OK", path.display());
    }

    /// A file failed to verify. Always shown unless `--status`.
    pub fn failed(&self, path: &Path, reason: impl std::fmt::Display) {
        if self.status {
            return;
        }
        println!("{}: FAILED ({reason})", path.display());
        let _ = std::io::stdout().flush();
    }

    /// Ordinary progress output, suppressed by `--quiet`.
    pub fn info(&self, message: impl std::fmt::Display) {
        if self.status || self.quiet {
            return;
        }
        println!("{message}");
    }

    /// Output that is part of the answer rather than progress: `--info`
    /// dumps, `--list-algos` tables. Only `--status` hides it.
    pub fn print(&self, message: impl std::fmt::Display) {
        if self.status {
            return;
        }
        println!("{message}");
    }

    /// Extra detail, shown only with `--verbose`.
    pub fn detail(&self, message: impl std::fmt::Display) {
        if self.is_verbose() {
            println!("{message}");
        }
    }

    /// A warning that does not stop the run. Goes to stderr so it does not
    /// pollute output a script may be parsing.
    pub fn warn(&self, message: impl std::fmt::Display) {
        if self.status {
            return;
        }
        eprintln!("pqsum: warning: {message}");
    }

    /// The trailing summary after a batch of verifications.
    pub fn summary(&self, failures: usize, total: usize) {
        if self.status || failures == 0 {
            return;
        }
        // The noun agrees with the total, not the failure count: "1 of 2
        // signatures", but "1 of 1 signature".
        let noun = if total == 1 {
            "signature"
        } else {
            "signatures"
        };
        eprintln!("pqsum: WARNING: {failures} of {total} {noun} did NOT verify");
    }
}
