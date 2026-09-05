//! pqsum — post-quantum file signing and verification.
//!
//! The binary is a thin shell around this library, so the file formats can be
//! exercised directly from tests and reused by other Rust programs.
//!
//! # How a signature is produced
//!
//! 1. The file is streamed through a digest (SHA3-512 by default) in 1 MiB
//!    chunks, so memory use does not depend on file size.
//! 2. A canonical, length-prefixed message binding the signature algorithm,
//!    the digest algorithm and the digest is built.
//! 3. That message is signed with ML-DSA (or another algorithm from
//!    [`algo::ALGORITHMS`]) through liboqs.
//! 4. The signature, the digest and a fingerprint of the signing public key
//!    are written to a `.pq` file.
//!
//! Verification recomputes the digest and repeats step 2, so a signature only
//! checks out against the same file, the same digest algorithm and the same
//! signing key.
//!
//! # Example
//!
//! ```no_run
//! use pqsum::{algo, hash::HashAlg, keyfile, sigfile::SignatureFile};
//!
//! pqsum::init();
//! let key = keyfile::generate(algo::lookup("ML-DSA-65")?)?;
//! let digest = HashAlg::Sha3_512.digest_path(std::path::Path::new("release.tar.gz"))?;
//! let signature = SignatureFile::create(&key, HashAlg::Sha3_512, digest.clone())?;
//! assert!(signature.check(&key.public_key(), &digest).is_ok());
//! # Ok::<(), pqsum::error::Error>(())
//! ```

pub mod algo;
pub mod armor;
pub mod cli;
pub mod error;
pub mod hash;
pub mod keyfile;
pub mod manifest;
pub mod ops;
pub mod report;
pub mod sigfile;
pub mod util;

pub use error::{Error, Result};

/// Initialise liboqs.
///
/// Must be called once before any signing or verification. Calling it more
/// than once is harmless.
pub fn init() {
    oqs::init();
}

/// Run the tool for an already-parsed command line.
pub fn run(cli: &cli::Cli) -> Result<()> {
    use cli::Mode;

    let reporter = report::Reporter::new(cli.quiet, cli.status, cli.verbose);

    match cli.mode()? {
        Mode::Keygen { algorithm, out_dir } => {
            ops::keygen(algorithm, &out_dir, cli.force, &reporter)
        }
        Mode::Sign {
            inputs,
            key,
            hash,
            out,
        } => ops::sign(
            &inputs,
            &key,
            hash,
            out.as_deref(),
            cli.recursive,
            cli.force,
            &reporter,
        ),
        Mode::SignManifest {
            inputs,
            key,
            hash,
            manifest,
        } => ops::sign_manifest(
            &inputs,
            &key,
            hash,
            &manifest,
            cli.recursive,
            cli.force,
            &reporter,
        ),
        Mode::Verify {
            inputs,
            public,
            sig,
        } => ops::verify(&inputs, &public, sig.as_deref(), cli.recursive, &reporter),
        Mode::Check { manifest, public } => ops::check_manifest(&manifest, &public, &reporter),
        Mode::Info { path } => ops::info(&path, &reporter),
        Mode::ListAlgos => {
            ops::list_algorithms(&reporter);
            Ok(())
        }
    }
}
