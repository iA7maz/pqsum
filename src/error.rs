//! Error type and process exit-code mapping.
//!
//! Exit codes follow the convention used by the coreutils checksum tools:
//!
//! * `0` — everything succeeded
//! * `1` — a signature did not verify (the file is not authentic)
//! * `2` — the tool could not do its job (bad usage, I/O error, corrupt input)
//!
//! Keeping "did not verify" distinct from "could not check" matters: a script
//! that treats a missing key file as a valid rejection is a security bug.

use std::fmt;
use std::io;
use std::path::{Path, PathBuf};

pub type Result<T> = std::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    /// An I/O failure, optionally attributed to the path that caused it.
    Io(Option<PathBuf>, io::Error),
    /// The algorithm name is not one pqsum knows about.
    UnknownAlgorithm(String),
    /// The algorithm is known but was not compiled into this liboqs build.
    AlgorithmUnavailable(String),
    /// A signature, key or manifest file is malformed.
    Malformed { path: PathBuf, reason: String },
    /// Inputs disagree about which algorithm is in play.
    Mismatch {
        what: &'static str,
        expected: String,
        found: String,
    },
    /// liboqs refused an operation.
    Backend(String),
    /// The command line did not make sense.
    Usage(String),
    /// A single artefact was well formed but not authentic. The caller turns
    /// this into a `FAILED (reason)` line and a `Verification` exit status.
    Rejected(crate::sigfile::Reason),
    /// At least one file failed verification. Carries the failure count.
    Verification(usize),
}

impl Error {
    pub fn io(path: impl AsRef<Path>, source: io::Error) -> Self {
        Error::Io(Some(path.as_ref().to_path_buf()), source)
    }

    pub fn malformed(path: impl AsRef<Path>, reason: impl Into<String>) -> Self {
        Error::Malformed {
            path: path.as_ref().to_path_buf(),
            reason: reason.into(),
        }
    }

    pub fn usage(msg: impl Into<String>) -> Self {
        Error::Usage(msg.into())
    }

    /// The process exit status this error should produce.
    pub fn exit_code(&self) -> i32 {
        match self {
            Error::Verification(_) | Error::Rejected(_) => 1,
            _ => 2,
        }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Io(Some(path), source) => write!(f, "{}: {}", path.display(), source),
            Error::Io(None, source) => write!(f, "{}", source),
            Error::UnknownAlgorithm(name) => {
                write!(f, "unknown algorithm '{name}' (try --list-algos)")
            }
            Error::AlgorithmUnavailable(name) => write!(
                f,
                "algorithm '{name}' is not available in this build of liboqs (try --list-algos)"
            ),
            Error::Rejected(reason) => write!(f, "{reason}"),
            Error::Malformed { path, reason } => write!(f, "{}: {}", path.display(), reason),
            Error::Mismatch {
                what,
                expected,
                found,
            } => {
                write!(f, "{what} mismatch: expected {expected}, found {found}")
            }
            Error::Backend(msg) => write!(f, "liboqs: {msg}"),
            Error::Usage(msg) => write!(f, "{msg}"),
            Error::Verification(1) => write!(f, "WARNING: 1 signature did NOT verify"),
            Error::Verification(n) => write!(f, "WARNING: {n} signatures did NOT verify"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::Io(_, source) => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    fn from(source: io::Error) -> Self {
        Error::Io(None, source)
    }
}

impl From<oqs::Error> for Error {
    fn from(source: oqs::Error) -> Self {
        Error::Backend(source.to_string())
    }
}
