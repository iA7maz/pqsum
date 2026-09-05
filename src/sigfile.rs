//! The detached signature file (`FILE.pq`).
//!
//! # What is signed
//!
//! Not the file itself: pqsum streams the file through a digest and signs a
//! canonical, length-prefixed encoding of
//!
//! ```text
//! "pqsum/v1/detached\0" || algorithm || digest-algorithm || digest
//! ```
//!
//! Length prefixes make the encoding unambiguous, so no two different
//! (algorithm, digest algorithm, digest) triples can produce the same signed
//! bytes. Naming the algorithms inside the signed message means an attacker
//! cannot take a signature made over a SHA-256 digest and present it as
//! covering a SHA3-512 one, and cannot re-label a signature as coming from a
//! different scheme.
//!
//! The file's *name* is deliberately not covered, matching how detached
//! signatures normally behave: renaming a release tarball does not invalidate
//! it. Use a signed manifest (see [`crate::manifest`]) when names matter.
//!
//! # On-disk layout
//!
//! All integers are little-endian.
//!
//! ```text
//! offset  size  field
//! 0       6     magic, "PQSUM\x1a"
//! 6       1     format version (1)
//! 7       1     flags (reserved, must be 0)
//! 8       1+n   algorithm name, u8 length prefix
//! ..      1+n   digest algorithm name, u8 length prefix
//! ..      2+n   digest, u16 length prefix
//! ..      32    SHA3-256 fingerprint of the signing public key
//! ..      4+n   signature, u32 length prefix
//! ```
//!
//! The 0x1a byte in the magic is the DOS end-of-file character: it makes a
//! signature file that has been mangled by a text-mode transfer fail loudly
//! rather than subtly.

use std::path::{Path, PathBuf};

use crate::algo::{self, AlgoInfo};
use crate::error::{Error, Result};
use crate::hash::{fingerprint, HashAlg};
use crate::keyfile::{PrivateKey, PublicKey};

const MAGIC: &[u8; 6] = b"PQSUM\x1a";
const VERSION: u8 = 1;
const DOMAIN: &[u8] = b"pqsum/v1/detached\x00";

/// The extension appended to a file name to get its signature file.
pub const SIGNATURE_EXTENSION: &str = "pq";

/// The signature that accompanies one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFile {
    pub algorithm: &'static AlgoInfo,
    pub hash: HashAlg,
    pub digest: Vec<u8>,
    pub key_fingerprint: [u8; 32],
    pub signature: Vec<u8>,
}

/// The canonical byte string that the signature is computed over.
fn signed_message(algorithm: &str, hash: HashAlg, digest: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(DOMAIN.len() + algorithm.len() + digest.len() + 16);
    message.extend_from_slice(DOMAIN);
    push_u16_prefixed(&mut message, algorithm.as_bytes());
    push_u16_prefixed(&mut message, hash.name().as_bytes());
    push_u16_prefixed(&mut message, digest);
    message
}

fn push_u16_prefixed(out: &mut Vec<u8>, field: &[u8]) {
    out.extend_from_slice(&(field.len() as u16).to_le_bytes());
    out.extend_from_slice(field);
}

impl SignatureFile {
    /// Sign a digest that was computed elsewhere (usually by streaming a file).
    pub fn create(key: &PrivateKey, hash: HashAlg, digest: Vec<u8>) -> Result<Self> {
        let scheme = algo::scheme(key.algorithm)?;
        let message = signed_message(key.algorithm.name, hash, &digest);
        let secret = scheme
            .secret_key_from_bytes(&key.secret)
            .ok_or_else(|| Error::Backend("secret key has the wrong length".into()))?;
        let signature = scheme.sign(&message, secret)?;

        Ok(SignatureFile {
            algorithm: key.algorithm,
            hash,
            digest,
            key_fingerprint: fingerprint(&key.public),
            signature: signature.into_vec(),
        })
    }

    /// Check this signature against a public key and a freshly computed digest.
    ///
    /// Returns the reason on failure rather than a bare boolean, so the caller
    /// can tell the user whether the file changed, the wrong key was supplied,
    /// or the signature itself is bad.
    pub fn check(&self, public_key: &PublicKey, digest: &[u8]) -> std::result::Result<(), Reason> {
        if public_key.algorithm.name != self.algorithm.name {
            return Err(Reason::AlgorithmMismatch {
                signature: self.algorithm.name,
                key: public_key.algorithm.name,
            });
        }
        if public_key.fingerprint() != self.key_fingerprint {
            return Err(Reason::WrongKey);
        }
        if digest != self.digest {
            return Err(Reason::ContentChanged);
        }

        let scheme = algo::scheme(self.algorithm).map_err(|_| Reason::BadSignature)?;
        let message = signed_message(self.algorithm.name, self.hash, &self.digest);
        let signature = scheme
            .signature_from_bytes(&self.signature)
            .ok_or(Reason::BadSignature)?;
        let key = scheme
            .public_key_from_bytes(&public_key.bytes)
            .ok_or(Reason::BadSignature)?;

        scheme
            .verify(&message, signature, key)
            .map_err(|_| Reason::BadSignature)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(self.signature.len() + self.digest.len() + 64);
        out.extend_from_slice(MAGIC);
        out.push(VERSION);
        out.push(0); // flags

        let name = self.algorithm.name.as_bytes();
        out.push(name.len() as u8);
        out.extend_from_slice(name);

        let hash_name = self.hash.name().as_bytes();
        out.push(hash_name.len() as u8);
        out.extend_from_slice(hash_name);

        out.extend_from_slice(&(self.digest.len() as u16).to_le_bytes());
        out.extend_from_slice(&self.digest);

        out.extend_from_slice(&self.key_fingerprint);

        out.extend_from_slice(&(self.signature.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8], path: &Path) -> Result<Self> {
        let mut cursor = Cursor {
            bytes,
            offset: 0,
            path,
        };

        if cursor.take(MAGIC.len())? != MAGIC {
            return Err(Error::malformed(path, "not a pqsum signature file"));
        }
        let version = cursor.take(1)?[0];
        if version != VERSION {
            return Err(Error::malformed(
                path,
                format!("signature format version {version} is newer than this pqsum understands"),
            ));
        }
        let flags = cursor.take(1)?[0];
        if flags != 0 {
            return Err(Error::malformed(
                path,
                format!("unsupported signature flags {flags:#04x}"),
            ));
        }

        let algorithm_name = cursor.take_string_u8()?;
        let algorithm = algo::lookup_from_file(&algorithm_name, path)?;
        let hash_name = cursor.take_string_u8()?;
        let hash = HashAlg::parse_from_file(&hash_name, path)?;

        let digest_len = u16::from_le_bytes(cursor.take(2)?.try_into().expect("2 bytes")) as usize;
        let digest = cursor.take(digest_len)?.to_vec();
        if digest.len() != hash.output_len() {
            return Err(Error::malformed(
                path,
                format!(
                    "digest is {} bytes, but {hash} produces {}",
                    digest.len(),
                    hash.output_len()
                ),
            ));
        }

        let key_fingerprint: [u8; 32] = cursor.take(32)?.try_into().expect("32 bytes");

        let signature_len =
            u32::from_le_bytes(cursor.take(4)?.try_into().expect("4 bytes")) as usize;
        let signature = cursor.take(signature_len)?.to_vec();
        cursor.expect_end()?;

        Ok(SignatureFile {
            algorithm,
            hash,
            digest,
            key_fingerprint,
            signature,
        })
    }

    pub fn load(path: &Path) -> Result<Self> {
        let bytes = std::fs::read(path).map_err(|e| Error::io(path, e))?;
        SignatureFile::decode(&bytes, path)
    }

    pub fn write(&self, path: &Path, force: bool) -> Result<()> {
        crate::util::write_atomic(path, &self.encode(), Some(crate::util::MODE_PUBLIC), force)
    }
}

/// Why a signature did not verify.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    /// The digest of the file on disk is not the one that was signed.
    ContentChanged,
    /// The signature was made by a different key than the one supplied.
    WrongKey,
    /// The public key is for a different algorithm than the signature.
    AlgorithmMismatch {
        signature: &'static str,
        key: &'static str,
    },
    /// The signature bytes themselves do not check out.
    BadSignature,
}

impl std::fmt::Display for Reason {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Reason::ContentChanged => f.write_str("file contents have changed since signing"),
            Reason::WrongKey => f.write_str("signed by a different key"),
            Reason::AlgorithmMismatch { signature, key } => {
                write!(f, "signature is {signature} but the public key is {key}")
            }
            Reason::BadSignature => f.write_str("signature is invalid"),
        }
    }
}

/// The conventional signature path for a file: `release.tar.gz` becomes
/// `release.tar.gz.pq`.
pub fn default_signature_path(file: &Path) -> PathBuf {
    let mut name = file.as_os_str().to_os_string();
    name.push(".");
    name.push(SIGNATURE_EXTENSION);
    PathBuf::from(name)
}

/// A bounds-checked reader over the signature file body.
struct Cursor<'a> {
    bytes: &'a [u8],
    offset: usize,
    path: &'a Path,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, len: usize) -> Result<&'a [u8]> {
        let end = self
            .offset
            .checked_add(len)
            .ok_or_else(|| self.truncated())?;
        if end > self.bytes.len() {
            return Err(self.truncated());
        }
        let slice = &self.bytes[self.offset..end];
        self.offset = end;
        Ok(slice)
    }

    fn take_string_u8(&mut self) -> Result<String> {
        let len = self.take(1)?[0] as usize;
        let bytes = self.take(len)?;
        String::from_utf8(bytes.to_vec())
            .map_err(|_| Error::malformed(self.path, "algorithm name is not valid UTF-8"))
    }

    fn expect_end(&self) -> Result<()> {
        if self.offset == self.bytes.len() {
            Ok(())
        } else {
            Err(Error::malformed(
                self.path,
                "trailing bytes after signature",
            ))
        }
    }

    fn truncated(&self) -> Error {
        Error::malformed(self.path, "signature file is truncated")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keyfile;

    fn key() -> PrivateKey {
        oqs::init();
        keyfile::generate(algo::lookup("ML-DSA-44").unwrap()).unwrap()
    }

    fn p() -> &'static Path {
        Path::new("<test>")
    }

    fn digest_of(data: &[u8]) -> Vec<u8> {
        HashAlg::Sha3_512.digest_reader(data).unwrap()
    }

    #[test]
    fn signature_verifies_and_round_trips() {
        let key = key();
        let digest = digest_of(b"hello world");
        let sig = SignatureFile::create(&key, HashAlg::Sha3_512, digest.clone()).unwrap();

        assert_eq!(sig.check(&key.public_key(), &digest), Ok(()));

        let decoded = SignatureFile::decode(&sig.encode(), p()).unwrap();
        assert_eq!(decoded, sig);
        assert_eq!(decoded.check(&key.public_key(), &digest), Ok(()));
    }

    #[test]
    fn modified_content_is_detected() {
        let key = key();
        let sig =
            SignatureFile::create(&key, HashAlg::Sha3_512, digest_of(b"hello world")).unwrap();
        assert_eq!(
            sig.check(&key.public_key(), &digest_of(b"hello worlD")),
            Err(Reason::ContentChanged)
        );
    }

    #[test]
    fn another_key_does_not_verify() {
        let signer = key();
        let stranger = key();
        let digest = digest_of(b"payload");
        let sig = SignatureFile::create(&signer, HashAlg::Sha3_512, digest.clone()).unwrap();
        assert_eq!(
            sig.check(&stranger.public_key(), &digest),
            Err(Reason::WrongKey)
        );
    }

    #[test]
    fn tampered_signature_bytes_do_not_verify() {
        let key = key();
        let digest = digest_of(b"payload");
        let mut sig = SignatureFile::create(&key, HashAlg::Sha3_512, digest.clone()).unwrap();
        sig.signature[0] ^= 0xff;
        assert_eq!(
            sig.check(&key.public_key(), &digest),
            Err(Reason::BadSignature)
        );
    }

    #[test]
    fn relabelling_the_digest_algorithm_does_not_verify() {
        // The digest algorithm is inside the signed message, so swapping the
        // label in the file must invalidate the signature rather than being
        // silently accepted.
        let key = key();
        let digest = digest_of(b"payload");
        let mut sig = SignatureFile::create(&key, HashAlg::Sha3_512, digest.clone()).unwrap();
        sig.hash = HashAlg::Sha512;
        assert_eq!(
            sig.check(&key.public_key(), &digest),
            Err(Reason::BadSignature)
        );
    }

    #[test]
    fn corrupt_files_are_rejected_cleanly() {
        let key = key();
        let sig = SignatureFile::create(&key, HashAlg::Sha3_512, digest_of(b"x")).unwrap();
        let encoded = sig.encode();

        assert!(SignatureFile::decode(b"", p()).is_err());
        assert!(SignatureFile::decode(b"not a signature at all", p()).is_err());
        assert!(SignatureFile::decode(&encoded[..encoded.len() - 1], p()).is_err());

        let mut extended = encoded.clone();
        extended.push(0);
        assert!(SignatureFile::decode(&extended, p()).is_err());

        let mut wrong_version = encoded.clone();
        wrong_version[6] = 99;
        assert!(SignatureFile::decode(&wrong_version, p()).is_err());
    }

    #[test]
    fn signature_paths_keep_the_original_extension() {
        assert_eq!(
            default_signature_path(Path::new("release.tar.gz")),
            PathBuf::from("release.tar.gz.pq")
        );
        assert_eq!(
            default_signature_path(Path::new("/tmp/dir/file")),
            PathBuf::from("/tmp/dir/file.pq")
        );
    }
}
