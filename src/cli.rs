//! Command-line surface.
//!
//! The documented interface is flag-driven (`pqsum --sign FILE --key ...`),
//! which is what the README promises and what reads naturally next to
//! `sha256sum`. Subcommand spellings (`pqsum sign FILE --key ...`) are
//! accepted too and rewritten to the flag form before parsing, so there is
//! only ever one parser to reason about.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{ArgGroup, Parser};

use crate::algo;
use crate::error::{Error, Result};
use crate::hash::{HashAlg, DEFAULT_HASH};

const AFTER_HELP: &str = "\
EXAMPLES:
  Generate a keypair:
    pqsum --keygen --algo ML-DSA-65 --out keys/

  Sign a release and publish release.tar.gz.pq alongside it:
    pqsum --sign release.tar.gz --key keys/private.key

  Verify what you downloaded:
    pqsum --verify release.tar.gz --sig release.tar.gz.pq --pub keys/public.key

  Sign a whole directory into one manifest, then check it later:
    pqsum --sign dist/ --recursive --key keys/private.key --manifest dist/PQSUMS
    pqsum --check dist/PQSUMS --pub keys/public.key

EXIT STATUS:
  0  success
  1  a signature did not verify
  2  the check could not be carried out (bad usage, missing file, corrupt input)
";

#[derive(Parser, Debug)]
#[command(
    name = "pqsum",
    version,
    about = "Sign and verify files with NIST post-quantum signatures",
    long_about = "Sign and verify files with NIST post-quantum signatures (ML-DSA, SLH-DSA).\n\n\
                  pqsum streams a file through a digest and signs the digest, so signing a \
                  multi-gigabyte image costs no more memory than signing a text file.",
    after_help = AFTER_HELP,
    disable_help_subcommand = true,
    group = ArgGroup::new("mode")
        .required(true)
        .args(["keygen", "sign", "verify", "check", "info", "list_algos"])
)]
pub struct Cli {
    // --- modes ------------------------------------------------------------
    /// Generate a new post-quantum keypair
    #[arg(long, help_heading = "Modes")]
    pub keygen: bool,

    /// Sign files, writing FILE.pq beside each one
    #[arg(long, value_name = "FILE", num_args = 1.., help_heading = "Modes")]
    pub sign: Vec<PathBuf>,

    /// Verify files against their signatures
    #[arg(long, value_name = "FILE", num_args = 1.., help_heading = "Modes")]
    pub verify: Vec<PathBuf>,

    /// Verify every file listed in a signed manifest
    #[arg(long, value_name = "MANIFEST", help_heading = "Modes")]
    pub check: Option<PathBuf>,

    /// Describe a signature file without verifying it
    #[arg(long, value_name = "FILE.pq", help_heading = "Modes")]
    pub info: Option<PathBuf>,

    /// List the signature algorithms this build supports
    #[arg(long, help_heading = "Modes")]
    pub list_algos: bool,

    // --- options ----------------------------------------------------------
    /// Signature algorithm for --keygen [default: ML-DSA-65]
    #[arg(short = 'a', long, value_name = "ALG")]
    pub algo: Option<String>,

    /// Digest algorithm used when signing [default: SHA3-512]
    #[arg(short = 'H', long, value_name = "HASH")]
    pub hash: Option<String>,

    /// Private key file
    #[arg(short = 'k', long, value_name = "FILE")]
    pub key: Option<PathBuf>,

    /// Public key file
    #[arg(short = 'p', long = "pub", alias = "public", value_name = "FILE")]
    pub public: Option<PathBuf>,

    /// Signature file to verify against [default: FILE.pq]
    #[arg(short = 's', long, value_name = "FILE")]
    pub sig: Option<PathBuf>,

    /// Output directory for --keygen, or signature path for --sign
    #[arg(short = 'o', long, value_name = "PATH")]
    pub out: Option<PathBuf>,

    /// Write or read one signed manifest instead of per-file signatures
    #[arg(short = 'm', long, value_name = "FILE")]
    pub manifest: Option<PathBuf>,

    /// Include the contents of directories
    #[arg(short = 'r', long)]
    pub recursive: bool,

    /// Overwrite existing output files
    #[arg(short = 'f', long)]
    pub force: bool,

    /// Do not print a line for each successful file
    #[arg(short = 'q', long)]
    pub quiet: bool,

    /// Print nothing; report the result through the exit status
    #[arg(long)]
    pub status: bool,

    /// Print extra detail about keys and algorithms
    #[arg(short = 'v', long)]
    pub verbose: bool,
}

/// The mode the user selected, with its arguments already validated.
pub enum Mode {
    Keygen {
        algorithm: &'static algo::AlgoInfo,
        out_dir: PathBuf,
    },
    Sign {
        inputs: Vec<PathBuf>,
        key: PathBuf,
        hash: HashAlg,
        out: Option<PathBuf>,
    },
    SignManifest {
        inputs: Vec<PathBuf>,
        key: PathBuf,
        hash: HashAlg,
        manifest: PathBuf,
    },
    Verify {
        inputs: Vec<PathBuf>,
        public: PathBuf,
        sig: Option<PathBuf>,
    },
    Check {
        manifest: PathBuf,
        public: PathBuf,
    },
    Info {
        path: PathBuf,
    },
    ListAlgos,
}

impl Cli {
    /// Work out which mode was asked for and reject option combinations that
    /// cannot mean anything.
    ///
    /// Rejecting rather than ignoring matters here: a user who types
    /// `--verify f --algo ML-DSA-87` believes they have pinned the algorithm,
    /// and silently ignoring the flag would leave them with false confidence.
    pub fn mode(&self) -> Result<Mode> {
        if self.keygen {
            self.reject(&[
                ("--hash", self.hash.is_some()),
                ("--sig", self.sig.is_some()),
            ])?;
            let algorithm = algo::lookup(self.algo.as_deref().unwrap_or(algo::DEFAULT_ALGORITHM))?;
            return Ok(Mode::Keygen {
                algorithm,
                out_dir: self.out.clone().unwrap_or_else(|| PathBuf::from(".")),
            });
        }

        if !self.sign.is_empty() {
            self.reject(&[
                ("--algo", self.algo.is_some()),
                ("--sig", self.sig.is_some()),
            ])?;
            let key = self
                .key
                .clone()
                .ok_or_else(|| Error::usage("--sign requires a private key (--key FILE)"))?;
            let hash = self.hash_alg()?;

            return Ok(match &self.manifest {
                Some(manifest) => {
                    if self.out.is_some() {
                        return Err(Error::usage(
                            "--out and --manifest both name the output; use one of them",
                        ));
                    }
                    Mode::SignManifest {
                        inputs: self.sign.clone(),
                        key,
                        hash,
                        manifest: manifest.clone(),
                    }
                }
                None => Mode::Sign {
                    inputs: self.sign.clone(),
                    key,
                    hash,
                    out: self.out.clone(),
                },
            });
        }

        if !self.verify.is_empty() {
            self.reject(&[
                ("--algo", self.algo.is_some()),
                ("--hash", self.hash.is_some()),
                ("--out", self.out.is_some()),
            ])?;
            let public = self.public_key_path("--verify")?;

            // `--verify FILES --manifest M` is the same request as
            // `--check M`, so accept it rather than making the user re-type.
            if let Some(manifest) = &self.manifest {
                if self.sig.is_some() {
                    return Err(Error::usage("--sig and --manifest cannot be combined"));
                }
                return Ok(Mode::Check {
                    manifest: manifest.clone(),
                    public,
                });
            }

            return Ok(Mode::Verify {
                inputs: self.verify.clone(),
                public,
                sig: self.sig.clone(),
            });
        }

        if let Some(manifest) = &self.check {
            self.reject(&[
                ("--algo", self.algo.is_some()),
                ("--hash", self.hash.is_some()),
                ("--sig", self.sig.is_some()),
                ("--out", self.out.is_some()),
            ])?;
            return Ok(Mode::Check {
                manifest: manifest.clone(),
                public: self.public_key_path("--check")?,
            });
        }

        if let Some(path) = &self.info {
            return Ok(Mode::Info { path: path.clone() });
        }

        if self.list_algos {
            return Ok(Mode::ListAlgos);
        }

        // clap's required ArgGroup makes this unreachable in practice.
        Err(Error::usage("no mode selected; see --help"))
    }

    fn hash_alg(&self) -> Result<HashAlg> {
        match &self.hash {
            Some(name) => HashAlg::parse(name).map_err(|_| {
                Error::usage(format!(
                    "unknown digest '{name}' (choose SHA3-512, SHA3-256, SHA-512 or SHA-256)"
                ))
            }),
            None => Ok(DEFAULT_HASH),
        }
    }

    fn public_key_path(&self, mode: &str) -> Result<PathBuf> {
        self.public
            .clone()
            .ok_or_else(|| Error::usage(format!("{mode} requires a public key (--pub FILE)")))
    }

    fn reject(&self, unusable: &[(&str, bool)]) -> Result<()> {
        for (flag, present) in unusable {
            if *present {
                return Err(Error::usage(format!("{flag} does not apply to this mode")));
            }
        }
        Ok(())
    }
}

/// Rewrite a leading subcommand into its flag form.
///
/// `pqsum sign a b --key k` becomes `pqsum --sign a b --key k`. Anything that
/// is not a recognised subcommand is passed through untouched, so `pqsum
/// --sign ...` and an accidental `pqsum somefile` both reach clap unchanged.
pub fn normalize_args<I, T>(args: I) -> Vec<OsString>
where
    I: IntoIterator<Item = T>,
    T: Into<OsString>,
{
    const SUBCOMMANDS: &[(&str, &str)] = &[
        ("keygen", "--keygen"),
        ("sign", "--sign"),
        ("verify", "--verify"),
        ("check", "--check"),
        ("info", "--info"),
        ("list-algos", "--list-algos"),
        ("list", "--list-algos"),
    ];

    let mut args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    if let Some(first) = args.get(1).and_then(|a| a.to_str()) {
        if let Some((_, flag)) = SUBCOMMANDS.iter().find(|(name, _)| *name == first) {
            args[1] = OsString::from(*flag);
        }
    }
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Mode> {
        let argv = normalize_args(std::iter::once("pqsum").chain(args.iter().copied()));
        let cli = Cli::try_parse_from(argv).map_err(|e| Error::usage(e.to_string()))?;
        cli.mode()
    }

    #[test]
    fn readme_invocations_parse() {
        oqs::init();

        assert!(matches!(
            parse(&["--keygen", "--algo", "ML-DSA-65", "--out", "keys/"]).unwrap(),
            Mode::Keygen { .. }
        ));
        assert!(matches!(
            parse(&["--sign", "release.tar.gz", "--key", "keys/private.key"]).unwrap(),
            Mode::Sign { .. }
        ));
        assert!(matches!(
            parse(&[
                "--verify",
                "release.tar.gz",
                "--sig",
                "release.tar.gz.pq",
                "--pub",
                "keys/public.key"
            ])
            .unwrap(),
            Mode::Verify { .. }
        ));
    }

    #[test]
    fn subcommand_form_is_equivalent() {
        oqs::init();
        assert!(matches!(
            parse(&["sign", "a.txt", "--key", "k"]).unwrap(),
            Mode::Sign { .. }
        ));
        assert!(matches!(
            parse(&["keygen", "--out", "keys/"]).unwrap(),
            Mode::Keygen { .. }
        ));
        assert!(matches!(parse(&["list-algos"]).unwrap(), Mode::ListAlgos));
    }

    #[test]
    fn keygen_defaults_to_ml_dsa_65() {
        oqs::init();
        match parse(&["--keygen"]).unwrap() {
            Mode::Keygen { algorithm, out_dir } => {
                assert_eq!(algorithm.name, "ML-DSA-65");
                assert_eq!(out_dir, PathBuf::from("."));
            }
            _ => panic!("expected keygen"),
        }
    }

    #[test]
    fn signing_many_files_is_accepted() {
        oqs::init();
        match parse(&["--sign", "a", "b", "c", "--key", "k"]).unwrap() {
            Mode::Sign { inputs, .. } => assert_eq!(inputs.len(), 3),
            _ => panic!("expected sign"),
        }
    }

    #[test]
    fn manifest_switches_sign_and_verify_modes() {
        oqs::init();
        assert!(matches!(
            parse(&["--sign", "dist", "-r", "--key", "k", "--manifest", "M"]).unwrap(),
            Mode::SignManifest { .. }
        ));
        assert!(matches!(
            parse(&["--verify", "dist", "--pub", "p", "--manifest", "M"]).unwrap(),
            Mode::Check { .. }
        ));
    }

    #[test]
    fn missing_keys_are_caught_before_any_work_happens() {
        oqs::init();
        assert!(parse(&["--sign", "a"]).is_err());
        assert!(parse(&["--verify", "a"]).is_err());
        assert!(parse(&["--check", "M"]).is_err());
    }

    #[test]
    fn inapplicable_options_are_rejected_not_ignored() {
        oqs::init();
        assert!(parse(&["--verify", "a", "--pub", "p", "--algo", "ML-DSA-87"]).is_err());
        assert!(parse(&["--sign", "a", "--key", "k", "--algo", "ML-DSA-87"]).is_err());
        assert!(parse(&["--keygen", "--hash", "SHA-256"]).is_err());
        assert!(parse(&["--sign", "a", "--key", "k", "--manifest", "M", "--out", "O"]).is_err());
    }

    #[test]
    fn a_mode_is_required_and_modes_are_exclusive() {
        oqs::init();
        assert!(parse(&[]).is_err());
        assert!(parse(&["--keygen", "--list-algos"]).is_err());
    }

    #[test]
    fn unknown_algorithms_and_digests_are_rejected() {
        oqs::init();
        assert!(parse(&["--keygen", "--algo", "rsa-4096"]).is_err());
        assert!(parse(&["--sign", "a", "--key", "k", "--hash", "md5"]).is_err());
    }
}
