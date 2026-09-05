//! The operations behind each command-line mode.

use std::fs;
use std::path::{Path, PathBuf};

use crate::algo::{self, AlgoInfo, ALGORITHMS};
use crate::error::{Error, Result};
use crate::hash::{short_fingerprint, HashAlg};
use crate::keyfile::{self, PrivateKey, PublicKey};
use crate::manifest::{Entry, Manifest};
use crate::report::Reporter;
use crate::sigfile::{default_signature_path, SignatureFile, SIGNATURE_EXTENSION};
use crate::util;

/// Generate a keypair into `out_dir`.
pub fn keygen(
    algorithm: &'static AlgoInfo,
    out_dir: &Path,
    force: bool,
    reporter: &Reporter,
) -> Result<()> {
    let (private_path, public_path) = keyfile::key_paths(out_dir);
    let created = util::now_rfc3339();

    let key = keyfile::generate(algorithm)?;
    key.write(&private_path, &created, force)?;

    // If the public key cannot be written, the private key alone is useless
    // and confusing, so take it back out rather than leaving half a keypair.
    if let Err(e) = key.public_key().write(&public_path, &created, force) {
        let _ = fs::remove_file(&private_path);
        return Err(e);
    }

    reporter.info(format!("generated {} keypair", algorithm.name));
    reporter.info(format!("  private key: {}", private_path.display()));
    reporter.info(format!("  public key:  {}", public_path.display()));
    reporter.info(format!("  fingerprint: {}", hex::encode(key.fingerprint())));
    reporter.detail(format!("  key id:      {}", key.short_id()));
    reporter.info(String::new());
    reporter.info(format!(
        "Keep {} secret. Publish {} so others can verify your signatures.",
        private_path.display(),
        public_path.display()
    ));
    Ok(())
}

/// Sign one or more files, writing a detached signature beside each.
pub fn sign(
    inputs: &[PathBuf],
    key_path: &Path,
    hash: HashAlg,
    out: Option<&Path>,
    recursive: bool,
    force: bool,
    reporter: &Reporter,
) -> Result<()> {
    let key = PrivateKey::load(key_path)?;
    let files = expand_inputs(inputs, recursive)?;

    if files.is_empty() {
        return Err(Error::usage("no files to sign"));
    }
    if out.is_some() && files.len() > 1 {
        return Err(Error::usage(
            "--out takes a single signature path; sign one file at a time, or use --manifest",
        ));
    }

    reporter.detail(format!(
        "signing with {} key {}",
        key.algorithm.name,
        key.short_id()
    ));

    for file in &files {
        let signature_path = match out {
            Some(path) => path.to_path_buf(),
            None if file == Path::new("-") => {
                return Err(Error::usage("reading from stdin requires --out"))
            }
            None => default_signature_path(file),
        };

        let digest = hash.digest_path(file)?;
        let signature = SignatureFile::create(&key, hash, digest)?;
        signature.write(&signature_path, force)?;

        reporter.info(format!(
            "{}: signed -> {}",
            file.display(),
            signature_path.display()
        ));
    }
    Ok(())
}

/// Sign a set of files into one signed manifest.
pub fn sign_manifest(
    inputs: &[PathBuf],
    key_path: &Path,
    hash: HashAlg,
    manifest_path: &Path,
    recursive: bool,
    force: bool,
    reporter: &Reporter,
) -> Result<()> {
    let key = PrivateKey::load(key_path)?;
    let files = expand_inputs(inputs, recursive)?;

    if files.is_empty() {
        return Err(Error::usage("no files to sign"));
    }

    // Entries are stored relative to the manifest, so the manifest and the
    // files it covers can be moved or published together.
    let base = manifest_path.parent().unwrap_or(Path::new("."));

    let mut entries = Vec::with_capacity(files.len());
    for file in &files {
        if file == manifest_path {
            continue;
        }
        if file == Path::new("-") {
            return Err(Error::usage("a manifest cannot cover standard input"));
        }
        let digest = hash.digest_path(file)?;
        entries.push(Entry {
            digest,
            path: relativize(file, base),
        });
        reporter.detail(format!("{}: hashed", file.display()));
    }

    let text = Manifest::create(&key, hash, entries)?;
    util::write_atomic(
        manifest_path,
        text.as_bytes(),
        Some(util::MODE_PUBLIC),
        force,
    )?;

    reporter.info(format!(
        "wrote {} covering {} file(s), signed with {} key {}",
        manifest_path.display(),
        files.len(),
        key.algorithm.name,
        key.short_id()
    ));
    Ok(())
}

/// Verify files against detached signatures.
pub fn verify(
    inputs: &[PathBuf],
    public_key_path: &Path,
    signature_path: Option<&Path>,
    recursive: bool,
    reporter: &Reporter,
) -> Result<()> {
    let public_key = PublicKey::load(public_key_path)?;
    let files = expand_inputs(inputs, recursive)?;

    if files.is_empty() {
        return Err(Error::usage("no files to verify"));
    }
    if signature_path.is_some() && files.len() > 1 {
        return Err(Error::usage(
            "--sig takes a single signature; verify one file at a time",
        ));
    }

    reporter.detail(format!(
        "verifying against {} key {}",
        public_key.algorithm.name,
        public_key.short_id()
    ));

    let mut failures = 0;
    for file in &files {
        let signature_path = match signature_path {
            Some(path) => path.to_path_buf(),
            None => default_signature_path(file),
        };

        match verify_one(file, &signature_path, &public_key) {
            Ok(()) => reporter.ok(file),
            Err(VerifyFailure::Rejected(reason)) => {
                failures += 1;
                reporter.failed(file, reason);
            }
            // Being unable to check a file is not the same as the file being
            // bad, so it is reported as an error and stops the run.
            Err(VerifyFailure::Unreadable(e)) => return Err(e),
        }
    }

    reporter.summary(failures, files.len());
    if failures > 0 {
        return Err(Error::Verification(failures));
    }
    Ok(())
}

enum VerifyFailure {
    Rejected(crate::sigfile::Reason),
    Unreadable(Error),
}

fn verify_one(
    file: &Path,
    signature_path: &Path,
    public_key: &PublicKey,
) -> std::result::Result<(), VerifyFailure> {
    let signature = SignatureFile::load(signature_path).map_err(VerifyFailure::Unreadable)?;
    let digest = signature
        .hash
        .digest_path(file)
        .map_err(VerifyFailure::Unreadable)?;
    signature
        .check(public_key, &digest)
        .map_err(VerifyFailure::Rejected)
}

/// Verify every file listed in a signed manifest.
pub fn check_manifest(
    manifest_path: &Path,
    public_key_path: &Path,
    reporter: &Reporter,
) -> Result<()> {
    let public_key = PublicKey::load(public_key_path)?;
    let text = fs::read_to_string(manifest_path).map_err(|e| Error::io(manifest_path, e))?;
    let manifest = match Manifest::open(&text, &public_key, manifest_path) {
        Ok(manifest) => manifest,
        // The manifest parsed but its signature does not check out: the list
        // of files is not authentic. That is a rejection (status 1), not an
        // inability to check (status 2), and it is reported in the same shape
        // as any other rejected artefact.
        Err(Error::Verification(_)) => {
            reporter.failed(manifest_path, "signature is invalid");
            reporter.summary(1, 1);
            return Err(Error::Verification(1));
        }
        Err(other) => return Err(other),
    };

    reporter.detail(format!(
        "manifest signed with {} key {}, digests are {}",
        manifest.algorithm().name,
        public_key.short_id(),
        manifest.hash()
    ));

    // Entries are relative to the manifest itself.
    let base = manifest_path.parent().unwrap_or(Path::new("."));

    let mut failures = 0;
    let entries = manifest.entries();
    for entry in entries {
        let path = base.join(&entry.path);
        let digest = match manifest.hash().digest_path(&path) {
            Ok(digest) => digest,
            Err(Error::Io(_, e)) if e.kind() == std::io::ErrorKind::NotFound => {
                failures += 1;
                reporter.failed(&entry.path, "missing");
                continue;
            }
            Err(e) => return Err(e),
        };

        match manifest.check_entry(entry, &digest) {
            Ok(()) => reporter.ok(&entry.path),
            Err(reason) => {
                failures += 1;
                reporter.failed(&entry.path, reason);
            }
        }
    }

    reporter.summary(failures, entries.len());
    if failures > 0 {
        return Err(Error::Verification(failures));
    }
    Ok(())
}

/// Describe a signature file without verifying anything.
pub fn info(path: &Path, reporter: &Reporter) -> Result<()> {
    let signature = SignatureFile::load(path)?;
    reporter.print(format!("file:        {}", path.display()));
    reporter.print(format!("algorithm:   {}", signature.algorithm.name));
    reporter.print(format!(
        "             NIST category {}, {} family",
        signature.algorithm.level, signature.algorithm.family
    ));
    reporter.print(format!("digest:      {}", signature.hash));
    reporter.print(format!("             {}", hex::encode(&signature.digest)));
    reporter.print(format!(
        "signing key: {}",
        short_fingerprint(&signature.key_fingerprint)
    ));
    reporter.print(format!(
        "             {}",
        hex::encode(signature.key_fingerprint)
    ));
    reporter.print(format!("signature:   {} bytes", signature.signature.len()));
    Ok(())
}

/// Print the algorithm table.
pub fn list_algorithms(reporter: &Reporter) {
    reporter.print(format!(
        "{:<28} {:<8} {:<6} {}",
        "ALGORITHM", "FAMILY", "LEVEL", "STATUS"
    ));
    for info in ALGORITHMS {
        let status = if info.oqs.is_enabled() {
            "available"
        } else {
            "not built"
        };
        let default = if info.name == algo::DEFAULT_ALGORITHM {
            " (default)"
        } else {
            ""
        };
        reporter.print(format!(
            "{:<28} {:<8} {:<6} {status}{default}",
            info.name, info.family, info.level
        ));
    }
    reporter.print(String::new());
    reporter.print("Digests: SHA3-512 (default), SHA3-256, SHA-512, SHA-256");
}

/// Turn the user's arguments into a concrete list of files.
///
/// Directories are an error unless `--recursive` was given, so a stray `pqsum
/// --sign .` does not quietly do something enormous. Files named explicitly
/// are always taken at face value; only directory contents are filtered.
fn expand_inputs(inputs: &[PathBuf], recursive: bool) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    for input in inputs {
        if input == Path::new("-") {
            files.push(input.clone());
            continue;
        }

        let metadata = fs::metadata(input).map_err(|e| Error::io(input, e))?;
        if !metadata.is_dir() {
            files.push(input.clone());
            continue;
        }
        if !recursive {
            return Err(Error::usage(format!(
                "{}: is a directory (use --recursive to include its contents)",
                input.display()
            )));
        }
        walk(input, &mut files)?;
    }
    Ok(files)
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .map_err(|e| Error::io(dir, e))?
        .collect::<std::io::Result<Vec<_>>>()
        .map_err(|e| Error::io(dir, e))?;
    // Sort so a manifest built on one machine matches one built on another.
    entries.sort_by_key(|e| e.file_name());

    for entry in entries {
        let path = entry.path();
        // Do not follow directory symlinks: a loop would hang the walk, and a
        // link out of the tree would sign things the user did not name.
        let metadata = fs::symlink_metadata(&path).map_err(|e| Error::io(&path, e))?;
        if metadata.is_symlink() {
            continue;
        }
        if metadata.is_dir() {
            walk(&path, out)?;
        } else if !is_signature_file(&path) {
            out.push(path);
        }
    }
    Ok(())
}

fn is_signature_file(path: &Path) -> bool {
    path.extension()
        .is_some_and(|ext| ext == SIGNATURE_EXTENSION)
}

/// Express `path` relative to `base` when it sits underneath it.
fn relativize(path: &Path, base: &Path) -> PathBuf {
    path.strip_prefix(base).unwrap_or(path).to_path_buf()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn directories_need_recursive() {
        let dir = tempfile::tempdir().unwrap();
        fs::write(dir.path().join("a.txt"), b"a").unwrap();

        let inputs = vec![dir.path().to_path_buf()];
        assert!(expand_inputs(&inputs, false).is_err());
        assert_eq!(expand_inputs(&inputs, true).unwrap().len(), 1);
    }

    #[test]
    fn walking_is_sorted_and_skips_signatures() {
        let dir = tempfile::tempdir().unwrap();
        fs::create_dir(dir.path().join("sub")).unwrap();
        fs::write(dir.path().join("b.txt"), b"b").unwrap();
        fs::write(dir.path().join("a.txt"), b"a").unwrap();
        fs::write(dir.path().join("a.txt.pq"), b"signature").unwrap();
        fs::write(dir.path().join("sub").join("c.txt"), b"c").unwrap();

        let files = expand_inputs(&[dir.path().to_path_buf()], true).unwrap();
        let names: Vec<_> = files
            .iter()
            .map(|p| p.strip_prefix(dir.path()).unwrap().to_owned())
            .collect();
        assert_eq!(
            names,
            vec![
                PathBuf::from("a.txt"),
                PathBuf::from("b.txt"),
                PathBuf::from("sub/c.txt")
            ]
        );
    }

    #[test]
    fn missing_inputs_are_reported() {
        let inputs = vec![PathBuf::from("definitely/not/here")];
        assert!(expand_inputs(&inputs, false).is_err());
    }

    #[test]
    fn relativize_only_strips_a_real_prefix() {
        assert_eq!(
            relativize(Path::new("a/b/c"), Path::new("a")),
            PathBuf::from("b/c")
        );
        assert_eq!(
            relativize(Path::new("a/b/c"), Path::new("x")),
            PathBuf::from("a/b/c")
        );
    }
}
