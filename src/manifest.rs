//! Signed manifests: one signature covering many files.
//!
//! A detached `.pq` file per artefact is right for a single tarball, but a
//! release directory usually wants one signature over a list of files, the way
//! `SHA256SUMS` works — except signed, and with the file names covered too.
//!
//! The format is deliberately a superset of what `sha256sum --check` style
//! tools produce: a header comment block, then `<digest>  <path>` lines, then
//! an armored signature block. The digest lines can be read by eye and the
//! whole body above the signature block is what gets signed, so adding,
//! removing or renaming an entry invalidates the manifest.
//!
//! ```text
//! # pqsum manifest v1
//! # algorithm: ML-DSA-65
//! # digest: SHA3-512
//! # key: 4e9f0c1d2a3b4c5d
//! 9f86d0818884...  release.tar.gz
//! 2c26b46b68ff...  release.tar.gz.asc
//! -----BEGIN PQSUM MANIFEST SIGNATURE-----
//! ...
//! -----END PQSUM MANIFEST SIGNATURE-----
//! ```

use std::path::{Path, PathBuf};

use crate::algo::{self, AlgoInfo};
use crate::armor;
use crate::error::{Error, Result};
use crate::hash::{fingerprint, short_fingerprint, HashAlg};
use crate::keyfile::{PrivateKey, PublicKey};
use crate::sigfile::Reason;

const DOMAIN: &[u8] = b"pqsum/v1/manifest\x00";
const VERSION_LINE: &str = "# pqsum manifest v1";

/// The conventional manifest file name in a release directory.
pub const DEFAULT_MANIFEST_NAME: &str = "PQSUMS";

/// One `<digest>  <path>` line.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    pub digest: Vec<u8>,
    pub path: PathBuf,
}

/// A manifest, signed or not yet signed.
///
/// The signer is held as the rendered short id rather than raw fingerprint
/// bytes, because that string is part of the signed body: when reading a
/// manifest back it must come from the file, not from whichever key the
/// verifier happened to supply.
#[derive(Debug, Clone)]
pub struct Manifest {
    pub algorithm: &'static AlgoInfo,
    pub hash: HashAlg,
    pub key_id: String,
    pub entries: Vec<Entry>,
}

impl Manifest {
    /// The exact bytes covered by the signature.
    ///
    /// This is the rendered text of the header and entry lines: it is what a
    /// reader sees, so there is no gap between "what was signed" and "what the
    /// file says".
    fn body(&self) -> String {
        let mut out = String::new();
        out.push_str(VERSION_LINE);
        out.push('\n');
        out.push_str(&format!("# algorithm: {}\n", self.algorithm.name));
        out.push_str(&format!("# digest: {}\n", self.hash.name()));
        out.push_str(&format!("# key: {}\n", self.key_id));
        for entry in &self.entries {
            out.push_str(&format!(
                "{}  {}\n",
                hex::encode(&entry.digest),
                escape_path(&entry.path)
            ));
        }
        out
    }

    fn signed_message(&self) -> Vec<u8> {
        let body = self.body();
        let mut message = Vec::with_capacity(DOMAIN.len() + body.len() + 4);
        message.extend_from_slice(DOMAIN);
        message.extend_from_slice(&(body.len() as u32).to_le_bytes());
        message.extend_from_slice(body.as_bytes());
        message
    }

    /// Build and sign a manifest over a set of already-computed digests.
    pub fn create(key: &PrivateKey, hash: HashAlg, entries: Vec<Entry>) -> Result<String> {
        // The manifest is a text format, so a path that is not valid UTF-8
        // cannot be written into it faithfully. Refusing is the only honest
        // option: rendering it lossily would produce a manifest that verifies
        // but names a file that does not exist.
        for entry in &entries {
            if entry.path.to_str().is_none() {
                return Err(Error::usage(format!(
                    "{}: file name is not valid UTF-8 and cannot go in a manifest; \
                     sign this file on its own instead",
                    entry.path.display()
                )));
            }
        }

        let key_fingerprint = fingerprint(&key.public);
        let manifest = Manifest {
            algorithm: key.algorithm,
            hash,
            key_id: short_fingerprint(&key_fingerprint),
            entries,
        };

        let scheme = algo::scheme(key.algorithm)?;
        let secret = scheme
            .secret_key_from_bytes(&key.secret)
            .ok_or_else(|| Error::Backend("secret key has the wrong length".into()))?;
        let signature = scheme.sign(&manifest.signed_message(), secret)?;

        let mut out = manifest.body();
        out.push_str(&armor::encode(
            armor::MANIFEST_SIGNATURE_LABEL,
            &[
                ("Algorithm", key.algorithm.name.to_string()),
                ("Fingerprint", hex::encode(key_fingerprint)),
            ],
            signature.as_ref(),
        ));
        Ok(out)
    }

    /// Parse a manifest and check its signature.
    ///
    /// Parsing and verification are one step on purpose: there is no way to
    /// get the entry list out of this module without having checked that the
    /// list is the one that was signed.
    pub fn open(text: &str, public_key: &PublicKey, path: &Path) -> Result<VerifiedManifest> {
        let block = armor::decode(text, armor::MANIFEST_SIGNATURE_LABEL, path)?;

        let begin = format!("-----BEGIN {}-----", armor::MANIFEST_SIGNATURE_LABEL);
        let body_len = text
            .find(&begin)
            .ok_or_else(|| Error::malformed(path, "manifest has no signature block"))?;
        let body = &text[..body_len];

        let parsed = parse_body(body, path)?;

        let manifest = Manifest {
            algorithm: parsed.algorithm,
            hash: parsed.hash,
            key_id: parsed.key_id,
            entries: parsed.entries,
        };

        // Re-render the body from what was parsed and require it to match the
        // bytes on disk. This closes the gap between the lenient parser and
        // the strict signed encoding: anything the parser accepted but would
        // not itself produce is rejected here. Note that everything compared
        // comes from the file, so supplying the wrong public key cannot make
        // an intact manifest look malformed.
        if manifest.body() != body {
            return Err(Error::malformed(
                path,
                "manifest body is not in canonical form (it has been edited)",
            ));
        }

        // Now the manifest is known to be well formed, so any remaining
        // problem is about authenticity, and is reported the same way a
        // detached signature would report it.
        if manifest.algorithm.name != public_key.algorithm.name {
            return Err(Error::Rejected(Reason::AlgorithmMismatch {
                signature: manifest.algorithm.name,
                key: public_key.algorithm.name,
            }));
        }
        if manifest.key_id != short_fingerprint(&public_key.fingerprint()) {
            return Err(Error::Rejected(Reason::WrongKey));
        }

        let scheme = algo::scheme(manifest.algorithm)?;
        let signature = scheme
            .signature_from_bytes(&block.payload)
            .ok_or(Error::Rejected(Reason::BadSignature))?;
        let key = scheme
            .public_key_from_bytes(&public_key.bytes)
            .ok_or_else(|| Error::Backend("public key has the wrong length".into()))?;

        match scheme.verify(&manifest.signed_message(), signature, key) {
            Ok(()) => Ok(VerifiedManifest(manifest)),
            Err(_) => Err(Error::Rejected(Reason::BadSignature)),
        }
    }
}

/// A manifest whose signature has been checked. Only this type exposes the
/// entry list, so a caller cannot act on unverified contents by accident.
#[derive(Debug)]
pub struct VerifiedManifest(Manifest);

impl VerifiedManifest {
    pub fn entries(&self) -> &[Entry] {
        &self.0.entries
    }

    pub fn hash(&self) -> HashAlg {
        self.0.hash
    }

    pub fn algorithm(&self) -> &'static AlgoInfo {
        self.0.algorithm
    }

    /// Compare a freshly computed digest against the manifest entry.
    pub fn check_entry(&self, entry: &Entry, digest: &[u8]) -> std::result::Result<(), Reason> {
        if digest == entry.digest {
            Ok(())
        } else {
            Err(Reason::ContentChanged)
        }
    }
}

struct ParsedBody {
    algorithm: &'static AlgoInfo,
    hash: HashAlg,
    key_id: String,
    entries: Vec<Entry>,
}

fn parse_body(body: &str, path: &Path) -> Result<ParsedBody> {
    let mut algorithm_name = None;
    let mut hash_name = None;
    let mut key_id = None;
    let mut entries = Vec::new();
    let mut seen_version = false;

    for (number, line) in body.lines().enumerate() {
        let number = number + 1;
        if line.trim().is_empty() {
            continue;
        }
        if let Some(comment) = line.strip_prefix('#') {
            let comment = comment.trim();
            if line.trim_end() == VERSION_LINE {
                seen_version = true;
            } else if let Some(value) = comment.strip_prefix("algorithm:") {
                algorithm_name = Some(value.trim().to_string());
            } else if let Some(value) = comment.strip_prefix("digest:") {
                hash_name = Some(value.trim().to_string());
            } else if let Some(value) = comment.strip_prefix("key:") {
                key_id = Some(value.trim().to_string());
            }
            continue;
        }

        let (digest_hex, name) = line.split_once("  ").ok_or_else(|| {
            Error::malformed(path, format!("line {number}: expected '<digest>  <path>'"))
        })?;
        let digest = hex::decode(digest_hex.trim()).map_err(|_| {
            Error::malformed(path, format!("line {number}: digest is not hexadecimal"))
        })?;
        entries.push(Entry {
            digest,
            path: unescape_path(name, path, number)?,
        });
    }

    if !seen_version {
        return Err(Error::malformed(
            path,
            "not a pqsum manifest (missing version line)",
        ));
    }
    let algorithm_name = algorithm_name
        .ok_or_else(|| Error::malformed(path, "manifest does not name a signature algorithm"))?;
    let hash_name = hash_name
        .ok_or_else(|| Error::malformed(path, "manifest does not name a digest algorithm"))?;
    let key_id =
        key_id.ok_or_else(|| Error::malformed(path, "manifest does not name a signing key"))?;

    let hash = HashAlg::parse_from_file(&hash_name, path)?;
    for entry in &entries {
        if entry.digest.len() != hash.output_len() {
            return Err(Error::malformed(
                path,
                format!(
                    "{}: digest length does not match {hash}",
                    entry.path.display()
                ),
            ));
        }
    }

    Ok(ParsedBody {
        algorithm: algo::lookup_from_file(&algorithm_name, path)?,
        hash,
        key_id,
        entries,
    })
}

/// Escape a path so it survives a line-oriented format.
///
/// Same convention as the coreutils checksum tools: a leading backslash marks
/// an escaped line, and backslashes and newlines inside the name are encoded.
///
/// Paths reaching here are already known to be valid UTF-8; [`Manifest::create`]
/// rejects anything else rather than letting a lossy conversion through.
fn escape_path(path: &Path) -> String {
    let raw = path.to_string_lossy();
    if raw.contains('\\') || raw.contains('\n') || raw.contains('\r') {
        let escaped: String = raw
            .chars()
            .map(|c| match c {
                '\\' => "\\\\".to_string(),
                '\n' => "\\n".to_string(),
                '\r' => "\\r".to_string(),
                other => other.to_string(),
            })
            .collect();
        format!("\\{escaped}")
    } else {
        raw.into_owned()
    }
}

fn unescape_path(name: &str, path: &Path, line: usize) -> Result<PathBuf> {
    let Some(escaped) = name.strip_prefix('\\') else {
        return Ok(PathBuf::from(name));
    };

    let mut out = String::with_capacity(escaped.len());
    let mut chars = escaped.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('\\') => out.push('\\'),
            Some('n') => out.push('\n'),
            Some('r') => out.push('\r'),
            _ => {
                return Err(Error::malformed(
                    path,
                    format!("line {line}: invalid escape sequence in file name"),
                ))
            }
        }
    }
    Ok(PathBuf::from(out))
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

    fn entries() -> Vec<Entry> {
        vec![
            Entry {
                digest: HashAlg::Sha3_512.digest_reader(&b"one"[..]).unwrap(),
                path: PathBuf::from("one.txt"),
            },
            Entry {
                digest: HashAlg::Sha3_512.digest_reader(&b"two"[..]).unwrap(),
                path: PathBuf::from("sub/two.txt"),
            },
        ]
    }

    #[test]
    fn manifest_round_trips() {
        let key = key();
        let text = Manifest::create(&key, HashAlg::Sha3_512, entries()).unwrap();
        let verified = Manifest::open(&text, &key.public_key(), p()).unwrap();

        assert_eq!(verified.entries(), entries().as_slice());
        assert_eq!(verified.hash(), HashAlg::Sha3_512);
        assert_eq!(verified.algorithm().name, key.algorithm.name);
    }

    #[test]
    fn manifest_is_human_readable() {
        let key = key();
        let text = Manifest::create(&key, HashAlg::Sha3_512, entries()).unwrap();
        assert!(text.starts_with("# pqsum manifest v1\n"));
        assert!(text.contains("  one.txt\n"));
        assert!(text.contains("  sub/two.txt\n"));
    }

    #[test]
    fn editing_an_entry_invalidates_the_manifest() {
        let key = key();
        let text = Manifest::create(&key, HashAlg::Sha3_512, entries()).unwrap();
        let tampered = text.replace("one.txt", "own.txt");
        assert!(Manifest::open(&tampered, &key.public_key(), p()).is_err());
    }

    #[test]
    fn removing_an_entry_invalidates_the_manifest() {
        let key = key();
        let text = Manifest::create(&key, HashAlg::Sha3_512, entries()).unwrap();
        let tampered: String = text
            .lines()
            .filter(|l| !l.contains("one.txt"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(Manifest::open(&tampered, &key.public_key(), p()).is_err());
    }

    #[test]
    fn another_key_does_not_open_the_manifest() {
        let signer = key();
        let stranger = key();
        let text = Manifest::create(&signer, HashAlg::Sha3_512, entries()).unwrap();

        // The manifest is intact; only the key is wrong. Saying so beats
        // reporting it as a malformed file, which is what a verifier that
        // rendered the signer id from the supplied key would end up doing.
        let err = Manifest::open(&text, &stranger.public_key(), p()).unwrap_err();
        assert!(
            matches!(err, Error::Rejected(Reason::WrongKey)),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn non_canonical_bodies_are_rejected() {
        // Extra whitespace parses fine but is not what was signed; the
        // canonical-form check must catch it rather than the signature check
        // failing with a confusing message.
        let key = key();
        let text = Manifest::create(&key, HashAlg::Sha3_512, entries()).unwrap();
        let tampered = text.replace("# digest:", "#  digest:");
        assert!(Manifest::open(&tampered, &key.public_key(), p()).is_err());
    }

    #[test]
    fn awkward_file_names_round_trip() {
        let key = key();
        let digest = HashAlg::Sha3_512.digest_reader(&b"x"[..]).unwrap();
        let awkward = vec![
            Entry {
                digest: digest.clone(),
                path: PathBuf::from("spaces  in name.txt"),
            },
            Entry {
                digest: digest.clone(),
                path: PathBuf::from("back\\slash.txt"),
            },
            Entry {
                digest,
                path: PathBuf::from("new\nline.txt"),
            },
        ];

        let text = Manifest::create(&key, HashAlg::Sha3_512, awkward.clone()).unwrap();
        let verified = Manifest::open(&text, &key.public_key(), p()).unwrap();
        assert_eq!(verified.entries(), awkward.as_slice());
    }

    #[cfg(unix)]
    #[test]
    fn non_utf8_file_names_are_refused_rather_than_mangled() {
        // A lossy conversion would produce a manifest that verifies but names
        // a file that does not exist, which is worse than refusing.
        use std::os::unix::ffi::OsStrExt;

        let key = key();
        let entries = vec![Entry {
            digest: HashAlg::Sha3_512.digest_reader(&b"x"[..]).unwrap(),
            path: PathBuf::from(std::ffi::OsStr::from_bytes(b"invalid-\xff-name")),
        }];

        let err = Manifest::create(&key, HashAlg::Sha3_512, entries).unwrap_err();
        assert!(
            format!("{err}").contains("UTF-8"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn foreign_files_are_not_mistaken_for_manifests() {
        let key = key();
        assert!(Manifest::open("just some text\n", &key.public_key(), p()).is_err());

        let sha256sums = "e3b0c442  file.txt\n";
        assert!(Manifest::open(sha256sums, &key.public_key(), p()).is_err());
    }
}
