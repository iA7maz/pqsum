//! Reading and writing pqsum key files.
//!
//! A public key file holds just the public key. A private key file holds the
//! secret key *and* its public key, so that signing knows which public key the
//! signature will be checked against without the user having to keep the two
//! files together. Both are armored text (see [`crate::armor`]).

use std::fs;
use std::path::{Path, PathBuf};

use zeroize::Zeroizing;

use crate::algo::{self, AlgoInfo};
use crate::armor::{self, Framer, Unframer};
use crate::error::{Error, Result};
use crate::hash::{fingerprint, short_fingerprint};
use crate::util::{self, MODE_PRIVATE, MODE_PUBLIC};

/// Default file names produced by `--keygen`.
pub const PUBLIC_KEY_FILENAME: &str = "public.key";
pub const PRIVATE_KEY_FILENAME: &str = "private.key";

/// A public key loaded from disk, or freshly generated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublicKey {
    pub algorithm: &'static AlgoInfo,
    pub bytes: Vec<u8>,
}

/// A private key together with the public key it belongs to.
///
/// The secret bytes live in a [`Zeroizing`] buffer so they are wiped when the
/// value is dropped rather than left in freed heap memory.
pub struct PrivateKey {
    pub algorithm: &'static AlgoInfo,
    pub secret: Zeroizing<Vec<u8>>,
    pub public: Vec<u8>,
}

impl PublicKey {
    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.bytes)
    }

    pub fn short_id(&self) -> String {
        short_fingerprint(&self.fingerprint())
    }

    pub fn to_armored(&self, created: &str) -> String {
        armor::encode(
            armor::PUBLIC_KEY_LABEL,
            &[
                ("Algorithm", self.algorithm.name.to_string()),
                ("Fingerprint", hex::encode(self.fingerprint())),
                ("Created", created.to_string()),
            ],
            &self.bytes,
        )
    }

    pub fn write(&self, path: &Path, created: &str, force: bool) -> Result<()> {
        util::write_atomic(
            path,
            self.to_armored(created).as_bytes(),
            Some(MODE_PUBLIC),
            force,
        )
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = read_to_string(path)?;
        let block = armor::decode(&text, armor::PUBLIC_KEY_LABEL, path)?;
        let algorithm = algo::lookup_from_file(block.require("Algorithm", path)?, path)?;

        let declared_fingerprint = block.header("Fingerprint").map(str::to_owned);
        let key = PublicKey {
            algorithm,
            bytes: block.payload,
        };
        key.check_length(path)?;
        key.check_declared_fingerprint(declared_fingerprint.as_deref(), path)?;
        Ok(key)
    }

    /// A public key whose length does not match the algorithm can never verify
    /// anything, so reject it at load time with a clear message.
    fn check_length(&self, path: &Path) -> Result<()> {
        let expected = algo::scheme(self.algorithm)?.length_public_key();
        if self.bytes.len() != expected {
            return Err(Error::malformed(
                path,
                format!(
                    "public key is {} bytes, but {} keys are {} bytes",
                    self.bytes.len(),
                    self.algorithm.name,
                    expected
                ),
            ));
        }
        Ok(())
    }

    /// The `Fingerprint` header is a convenience for humans; if it is present
    /// and wrong, the file has been edited and should not be trusted.
    fn check_declared_fingerprint(&self, declared: Option<&str>, path: &Path) -> Result<()> {
        let Some(declared) = declared else {
            return Ok(());
        };
        if !declared.eq_ignore_ascii_case(&hex::encode(self.fingerprint())) {
            return Err(Error::malformed(
                path,
                "Fingerprint header does not match the key it labels",
            ));
        }
        Ok(())
    }
}

/// Deliberately hand-written rather than derived: a private key must not be
/// able to leak into a log line or a panic message.
impl std::fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PrivateKey")
            .field("algorithm", &self.algorithm.name)
            .field("fingerprint", &self.short_id())
            .field("secret", &"<redacted>")
            .finish()
    }
}

impl PrivateKey {
    pub fn public_key(&self) -> PublicKey {
        PublicKey {
            algorithm: self.algorithm,
            bytes: self.public.clone(),
        }
    }

    pub fn fingerprint(&self) -> [u8; 32] {
        fingerprint(&self.public)
    }

    pub fn short_id(&self) -> String {
        short_fingerprint(&self.fingerprint())
    }

    pub fn to_armored(&self, created: &str) -> Zeroizing<String> {
        let payload = Zeroizing::new(Framer::new().push(&self.secret).push(&self.public).finish());
        Zeroizing::new(armor::encode(
            armor::PRIVATE_KEY_LABEL,
            &[
                ("Algorithm", self.algorithm.name.to_string()),
                ("Fingerprint", hex::encode(self.fingerprint())),
                ("Created", created.to_string()),
            ],
            &payload,
        ))
    }

    pub fn write(&self, path: &Path, created: &str, force: bool) -> Result<()> {
        let armored = self.to_armored(created);
        util::write_atomic(path, armored.as_bytes(), Some(MODE_PRIVATE), force)
    }

    pub fn load(path: &Path) -> Result<Self> {
        util::warn_if_key_is_exposed(path);

        let text = Zeroizing::new(read_to_string(path)?);
        let block = armor::decode(&text, armor::PRIVATE_KEY_LABEL, path)?;
        let algorithm = algo::lookup_from_file(block.require("Algorithm", path)?, path)?;

        let payload = Zeroizing::new(block.payload);
        let mut fields = Unframer::new(&payload);
        let secret = Zeroizing::new(fields.next_field(path)?.to_vec());
        let public = fields.next_field(path)?.to_vec();
        fields.finish(path)?;

        let scheme = algo::scheme(algorithm)?;
        if secret.len() != scheme.length_secret_key() || public.len() != scheme.length_public_key()
        {
            return Err(Error::malformed(
                path,
                format!(
                    "key material does not have the shape of an {} key",
                    algorithm.name
                ),
            ));
        }

        Ok(PrivateKey {
            algorithm,
            secret,
            public,
        })
    }
}

/// Generate a fresh keypair.
pub fn generate(algorithm: &'static AlgoInfo) -> Result<PrivateKey> {
    let scheme = algo::scheme(algorithm)?;
    let (public, secret) = scheme.keypair()?;
    Ok(PrivateKey {
        algorithm,
        secret: Zeroizing::new(secret.into_vec()),
        public: public.into_vec(),
    })
}

/// Where `--keygen --out DIR` puts its two files.
pub fn key_paths(out_dir: &Path) -> (PathBuf, PathBuf) {
    (
        out_dir.join(PRIVATE_KEY_FILENAME),
        out_dir.join(PUBLIC_KEY_FILENAME),
    )
}

fn read_to_string(path: &Path) -> Result<String> {
    let bytes = fs::read(path).map_err(|e| Error::io(path, e))?;
    String::from_utf8(bytes)
        .map_err(|_| Error::malformed(path, "not a text file (expected an armored pqsum key)"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_algorithm() -> &'static AlgoInfo {
        oqs::init();
        algo::lookup("ML-DSA-44").expect("ML-DSA-44 is compiled in")
    }

    #[test]
    fn keypair_round_trips_through_disk() {
        let algorithm = test_algorithm();
        let dir = tempfile::tempdir().unwrap();
        let (private_path, public_path) = key_paths(dir.path());

        let key = generate(algorithm).unwrap();
        key.write(&private_path, "1970-01-01T00:00:00Z", false)
            .unwrap();
        key.public_key()
            .write(&public_path, "1970-01-01T00:00:00Z", false)
            .unwrap();

        let loaded_private = PrivateKey::load(&private_path).unwrap();
        let loaded_public = PublicKey::load(&public_path).unwrap();

        assert_eq!(loaded_private.secret.as_slice(), key.secret.as_slice());
        assert_eq!(loaded_private.public, key.public);
        assert_eq!(loaded_public.bytes, key.public);
        assert_eq!(loaded_public.fingerprint(), key.fingerprint());
        assert_eq!(loaded_private.algorithm.name, algorithm.name);
    }

    #[test]
    fn generated_keys_are_distinct() {
        let algorithm = test_algorithm();
        let a = generate(algorithm).unwrap();
        let b = generate(algorithm).unwrap();
        assert_ne!(a.public, b.public);
        assert_ne!(a.fingerprint(), b.fingerprint());
    }

    #[cfg(unix)]
    #[test]
    fn private_key_is_written_unreadable_to_others() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("private.key");
        generate(test_algorithm())
            .unwrap()
            .write(&path, "now", false)
            .unwrap();
        let mode = fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, MODE_PRIVATE,
            "private key must not be group or world readable"
        );
    }

    #[test]
    fn tampered_fingerprint_header_is_rejected() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public.key");
        let key = generate(test_algorithm()).unwrap().public_key();
        key.write(&path, "now", false).unwrap();

        let text = fs::read_to_string(&path).unwrap();
        let real = hex::encode(key.fingerprint());
        let fake = format!("{}0", &real[1..]);
        fs::write(&path, text.replace(&real, &fake)).unwrap();

        let err = PublicKey::load(&path).unwrap_err();
        assert!(
            matches!(err, Error::Malformed { .. }),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn truncated_public_key_is_rejected() {
        let algorithm = test_algorithm();
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public.key");

        // Hand-build a block so it is well formed but the wrong length.
        let text = armor::encode(
            armor::PUBLIC_KEY_LABEL,
            &[("Algorithm", algorithm.name.to_string())],
            b"too short",
        );
        fs::write(&path, text).unwrap();

        let err = PublicKey::load(&path).unwrap_err();
        assert!(
            format!("{err}").contains("bytes"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn a_public_key_is_not_a_private_key() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("public.key");
        generate(test_algorithm())
            .unwrap()
            .public_key()
            .write(&path, "now", false)
            .unwrap();
        assert!(PrivateKey::load(&path).is_err());
    }
}
