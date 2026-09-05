//! Streaming digests.
//!
//! pqsum never signs file contents directly. It streams the file through a
//! hash function in fixed-size chunks and signs the digest, which is what lets
//! a multi-gigabyte ISO be signed in constant memory. The digest algorithm is
//! recorded alongside the signature so verification uses the same one.

use std::fmt;
use std::fs::File;
use std::io::{self, BufReader, Read};
use std::path::Path;

use sha2::{Sha256, Sha512};
use sha3::{Digest, Sha3_256, Sha3_512};

use crate::error::{Error, Result};

/// Read granularity. Large enough that syscall overhead disappears on fast
/// storage, small enough to stay out of the way in a container.
const CHUNK: usize = 1 << 20; // 1 MiB

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HashAlg {
    Sha3_512,
    Sha3_256,
    Sha512,
    Sha256,
}

/// The digest used when the user does not name one.
///
/// SHA3-512 offers 256-bit collision resistance, which keeps the digest from
/// being the weakest link under any of the signature algorithms on offer.
pub const DEFAULT_HASH: HashAlg = HashAlg::Sha3_512;

impl HashAlg {
    pub const ALL: &'static [HashAlg] = &[
        HashAlg::Sha3_512,
        HashAlg::Sha3_256,
        HashAlg::Sha512,
        HashAlg::Sha256,
    ];

    pub fn name(self) -> &'static str {
        match self {
            HashAlg::Sha3_512 => "SHA3-512",
            HashAlg::Sha3_256 => "SHA3-256",
            HashAlg::Sha512 => "SHA-512",
            HashAlg::Sha256 => "SHA-256",
        }
    }

    pub fn output_len(self) -> usize {
        match self {
            HashAlg::Sha3_512 | HashAlg::Sha512 => 64,
            HashAlg::Sha3_256 | HashAlg::Sha256 => 32,
        }
    }

    pub fn parse(name: &str) -> Result<Self> {
        let wanted: String = name
            .chars()
            .filter(|c| !matches!(c, '-' | '_' | ' '))
            .flat_map(|c| c.to_lowercase())
            .collect();
        match wanted.as_str() {
            "sha3512" => Ok(HashAlg::Sha3_512),
            "sha3256" => Ok(HashAlg::Sha3_256),
            "sha512" => Ok(HashAlg::Sha512),
            "sha256" => Ok(HashAlg::Sha256),
            _ => Err(Error::UnknownAlgorithm(name.to_string())),
        }
    }

    /// Parse a digest name that came out of a signature or manifest file.
    pub fn parse_from_file(name: &str, path: &Path) -> Result<Self> {
        HashAlg::parse(name)
            .map_err(|_| Error::malformed(path, format!("names an unrecognised digest '{name}'")))
    }

    /// Hash everything `reader` yields.
    pub fn digest_reader<R: Read>(self, reader: R) -> io::Result<Vec<u8>> {
        fn run<D: Digest + io::Write, R: Read>(
            mut hasher: D,
            mut reader: R,
        ) -> io::Result<Vec<u8>> {
            let mut buf = vec![0u8; CHUNK];
            loop {
                let n = match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => n,
                    Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
                    Err(e) => return Err(e),
                };
                hasher.update(&buf[..n]);
            }
            Ok(hasher.finalize().to_vec())
        }

        match self {
            HashAlg::Sha3_512 => run(Sha3_512::new(), reader),
            HashAlg::Sha3_256 => run(Sha3_256::new(), reader),
            HashAlg::Sha512 => run(Sha512::new(), reader),
            HashAlg::Sha256 => run(Sha256::new(), reader),
        }
    }

    /// Hash a file on disk, or standard input when `path` is `-`.
    pub fn digest_path(self, path: &Path) -> Result<Vec<u8>> {
        if path == Path::new("-") {
            let stdin = io::stdin();
            return self
                .digest_reader(stdin.lock())
                .map_err(|e| Error::Io(None, e));
        }
        let file = File::open(path).map_err(|e| Error::io(path, e))?;
        self.digest_reader(BufReader::with_capacity(CHUNK, file))
            .map_err(|e| Error::io(path, e))
    }
}

impl fmt::Display for HashAlg {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// SHA3-256 over a public key, used as its short identity everywhere pqsum
/// needs to say "this signature belongs to that key".
pub fn fingerprint(public_key: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(b"pqsum/v1/fingerprint\x00");
    hasher.update(public_key);
    hasher.finalize().into()
}

/// The first 8 bytes of a fingerprint, hex encoded — short enough to read out
/// loud, long enough to spot the wrong key.
pub fn short_fingerprint(fingerprint: &[u8]) -> String {
    hex::encode(&fingerprint[..fingerprint.len().min(8)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_matches_known_vector() {
        // SHA3-256("abc"), FIPS 202 test vector.
        let got = HashAlg::Sha3_256.digest_reader(&b"abc"[..]).unwrap();
        assert_eq!(
            hex::encode(got),
            "3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532"
        );
    }

    #[test]
    fn chunking_does_not_change_the_digest() {
        // Feed more than one chunk to be sure the streaming loop is correct.
        let data = vec![0xa5u8; CHUNK * 2 + 12345];
        let streamed = HashAlg::Sha3_512.digest_reader(&data[..]).unwrap();
        let oneshot = <Sha3_512 as Digest>::digest(&data).to_vec();
        assert_eq!(streamed, oneshot);
    }

    #[test]
    fn output_len_is_declared_correctly() {
        for alg in HashAlg::ALL {
            assert_eq!(alg.digest_reader(&b""[..]).unwrap().len(), alg.output_len());
        }
    }

    #[test]
    fn names_round_trip() {
        for alg in HashAlg::ALL {
            assert_eq!(HashAlg::parse(alg.name()).unwrap(), *alg);
        }
        assert!(HashAlg::parse("md5").is_err());
    }
}
