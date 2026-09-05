//! End-to-end tests that drive the real binary.
//!
//! The unit tests cover the formats; these cover the contract the tool makes
//! with whoever calls it — the exit codes, the output lines, and the exact
//! invocations the README promises.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use assert_cmd::prelude::*;
use predicates::prelude::*;
use tempfile::TempDir;

/// Exit status for "a signature did not verify".
const REJECTED: i32 = 1;
/// Exit status for "the check could not be carried out".
const ERROR: i32 = 2;

struct Sandbox {
    dir: TempDir,
}

impl Sandbox {
    fn new() -> Self {
        Sandbox {
            dir: tempfile::tempdir().expect("temp dir"),
        }
    }

    fn path(&self, relative: &str) -> PathBuf {
        self.dir.path().join(relative)
    }

    fn write(&self, relative: &str, contents: &[u8]) -> PathBuf {
        let path = self.path(relative);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(&path, contents).expect("write file");
        path
    }

    fn pqsum(&self) -> Command {
        let mut command = Command::cargo_bin("pqsum").expect("binary is built");
        command.current_dir(self.dir.path());
        command
    }

    /// Generate a keypair in `keys/` and return (private, public) paths.
    fn keygen(&self) -> (PathBuf, PathBuf) {
        self.keygen_with("ML-DSA-44", "keys")
    }

    fn keygen_with(&self, algorithm: &str, out: &str) -> (PathBuf, PathBuf) {
        self.pqsum()
            .args(["--keygen", "--algo", algorithm, "--out", out])
            .assert()
            .success();
        (
            PathBuf::from(out).join("private.key"),
            PathBuf::from(out).join("public.key"),
        )
    }
}

fn code(assert: &assert_cmd::assert::Assert) -> i32 {
    assert
        .get_output()
        .status
        .code()
        .expect("process exited normally")
}

// --- the README's own commands ------------------------------------------

#[test]
fn the_documented_workflow_works() {
    let sandbox = Sandbox::new();

    sandbox
        .pqsum()
        .args(["--keygen", "--algo", "ML-DSA-65", "--out", "keys/"])
        .assert()
        .success();
    assert!(sandbox.path("keys/private.key").exists());
    assert!(sandbox.path("keys/public.key").exists());

    sandbox.write("release.tar.gz", b"a plausible release");

    sandbox
        .pqsum()
        .args(["--sign", "release.tar.gz", "--key", "keys/private.key"])
        .assert()
        .success();
    assert!(sandbox.path("release.tar.gz.pq").exists());

    sandbox
        .pqsum()
        .args([
            "--verify",
            "release.tar.gz",
            "--sig",
            "release.tar.gz.pq",
            "--pub",
            "keys/public.key",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("release.tar.gz: OK"));
}

#[test]
fn subcommand_spelling_is_accepted_too() {
    let sandbox = Sandbox::new();
    sandbox
        .pqsum()
        .args(["keygen", "--out", "keys"])
        .assert()
        .success();
    sandbox.write("f.txt", b"data");
    sandbox
        .pqsum()
        .args(["sign", "f.txt", "--key", "keys/private.key"])
        .assert()
        .success();
    sandbox
        .pqsum()
        .args(["verify", "f.txt", "--pub", "keys/public.key"])
        .assert()
        .success();
}

// --- rejection ------------------------------------------------------------

#[test]
fn a_modified_file_is_rejected_with_status_1() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("data.bin", b"original contents");

    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();
    sandbox.write("data.bin", b"modified contents");

    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), REJECTED);
    assert
        .stdout(predicate::str::contains("data.bin: FAILED"))
        .stderr(predicate::str::contains("did NOT verify"));
}

#[test]
fn a_signature_from_another_key_is_rejected() {
    let sandbox = Sandbox::new();
    let (private, _) = sandbox.keygen_with("ML-DSA-44", "mine");
    let (_, stranger) = sandbox.keygen_with("ML-DSA-44", "theirs");
    sandbox.write("data.bin", b"contents");

    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();

    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--pub"])
        .arg(&stranger)
        .assert();
    assert_eq!(code(&assert), REJECTED);
    assert.stdout(predicate::str::contains("signed by a different key"));
}

#[test]
fn a_corrupt_signature_file_is_an_error_not_a_rejection() {
    // The distinction matters: a script that treats "I could not read the
    // signature" as "the file is bad" is annoying, but one that treats it as
    // "the file is fine" is a security hole. Neither should be status 1.
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();

    sandbox.write("data.bin.pq", b"this is not a signature");
    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), ERROR);
    assert.stderr(predicate::str::contains("not a pqsum signature file"));
}

#[test]
fn a_missing_signature_is_an_error_not_a_silent_pass() {
    let sandbox = Sandbox::new();
    let (_, public) = sandbox.keygen();
    sandbox.write("data.bin", b"never signed");

    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), ERROR);
}

#[test]
fn a_truncated_signature_is_rejected() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();

    let signature = fs::read(sandbox.path("data.bin.pq")).unwrap();
    fs::write(
        sandbox.path("data.bin.pq"),
        &signature[..signature.len() / 2],
    )
    .unwrap();

    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), ERROR);
}

#[test]
fn a_flipped_bit_in_the_signature_is_rejected() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();

    let mut signature = fs::read(sandbox.path("data.bin.pq")).unwrap();
    let last = signature.len() - 1;
    signature[last] ^= 0x01;
    fs::write(sandbox.path("data.bin.pq"), signature).unwrap();

    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), REJECTED);
}

// --- output modes ---------------------------------------------------------

#[test]
fn status_prints_nothing_and_speaks_only_through_the_exit_code() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();

    sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--status", "--pub"])
        .arg(&public)
        .assert()
        .success()
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());

    sandbox.write("data.bin", b"changed");
    let assert = sandbox
        .pqsum()
        .args(["--verify", "data.bin", "--status", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), REJECTED);
    assert
        .stdout(predicate::str::is_empty())
        .stderr(predicate::str::is_empty());
}

#[test]
fn quiet_hides_successes_but_never_failures() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("good.bin", b"good");
    sandbox.write("bad.bin", b"bad");
    sandbox
        .pqsum()
        .args(["--sign", "good.bin", "bad.bin", "--key"])
        .arg(&private)
        .assert()
        .success();
    sandbox.write("bad.bin", b"tampered");

    let assert = sandbox
        .pqsum()
        .args(["--verify", "good.bin", "bad.bin", "--quiet", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), REJECTED);
    assert
        .stdout(predicate::str::contains("good.bin").not())
        .stdout(predicate::str::contains("bad.bin: FAILED"));
}

// --- manifests ------------------------------------------------------------

#[test]
fn a_manifest_covers_a_whole_directory() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("dist/one.bin", b"one");
    sandbox.write("dist/nested/two.bin", b"two");

    sandbox
        .pqsum()
        .args([
            "--sign",
            "dist",
            "--recursive",
            "--manifest",
            "dist/PQSUMS",
            "--key",
        ])
        .arg(&private)
        .assert()
        .success();

    sandbox
        .pqsum()
        .args(["--check", "dist/PQSUMS", "--pub"])
        .arg(&public)
        .assert()
        .success()
        .stdout(predicate::str::contains("one.bin: OK"))
        .stdout(predicate::str::contains("nested/two.bin: OK"));
}

#[test]
fn a_manifest_detects_changed_and_missing_files() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("dist/one.bin", b"one");
    sandbox.write("dist/two.bin", b"two");
    sandbox
        .pqsum()
        .args(["--sign", "dist", "-r", "--manifest", "dist/PQSUMS", "--key"])
        .arg(&private)
        .assert()
        .success();

    sandbox.write("dist/one.bin", b"changed");
    fs::remove_file(sandbox.path("dist/two.bin")).unwrap();

    let assert = sandbox
        .pqsum()
        .args(["--check", "dist/PQSUMS", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), REJECTED);
    assert
        .stdout(predicate::str::contains("one.bin: FAILED"))
        .stdout(predicate::str::contains("two.bin: FAILED (missing)"));
}

#[test]
fn an_edited_manifest_is_rejected_before_any_file_is_checked() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("dist/one.bin", b"one");
    sandbox
        .pqsum()
        .args(["--sign", "dist", "-r", "--manifest", "dist/PQSUMS", "--key"])
        .arg(&private)
        .assert()
        .success();

    let manifest = fs::read_to_string(sandbox.path("dist/PQSUMS")).unwrap();
    fs::write(
        sandbox.path("dist/PQSUMS"),
        manifest.replace("one.bin", "two.bin"),
    )
    .unwrap();

    // The edited list is well formed but no longer authentic, so this is a
    // rejection, and no individual file is reported as OK on the way there.
    let assert = sandbox
        .pqsum()
        .args(["--check", "dist/PQSUMS", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), REJECTED);
    assert
        .stdout(predicate::str::contains("OK").not())
        .stdout(predicate::str::contains("PQSUMS: FAILED"));
}

#[test]
fn a_manifest_that_is_not_a_manifest_is_an_error() {
    // Distinct from the case above: here the file cannot be understood at
    // all, so pqsum could not carry out the check rather than having carried
    // it out and found a problem.
    let sandbox = Sandbox::new();
    let (_, public) = sandbox.keygen();
    sandbox.write("PQSUMS", b"e3b0c442  file.txt\n");

    let assert = sandbox
        .pqsum()
        .args(["--check", "PQSUMS", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), ERROR);
}

#[test]
fn a_reformatted_manifest_is_rejected() {
    // Whitespace a lenient parser would tolerate is still not the body that
    // was signed; the canonical-form check must catch it.
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("dist/one.bin", b"one");
    sandbox
        .pqsum()
        .args(["--sign", "dist", "-r", "--manifest", "dist/PQSUMS", "--key"])
        .arg(&private)
        .assert()
        .success();

    let manifest = fs::read_to_string(sandbox.path("dist/PQSUMS")).unwrap();
    fs::write(
        sandbox.path("dist/PQSUMS"),
        manifest.replace("# digest:", "#  digest:"),
    )
    .unwrap();

    let assert = sandbox
        .pqsum()
        .args(["--check", "dist/PQSUMS", "--pub"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), ERROR);
}

// --- safety rails ---------------------------------------------------------

#[test]
fn existing_files_are_never_overwritten_without_force() {
    let sandbox = Sandbox::new();
    let (private, _) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();
    let original = fs::read(sandbox.path("data.bin.pq")).unwrap();

    let assert = sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert();
    assert_eq!(code(&assert), ERROR);
    assert.stderr(predicate::str::contains("--force"));
    assert_eq!(fs::read(sandbox.path("data.bin.pq")).unwrap(), original);

    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--force", "--key"])
        .arg(&private)
        .assert()
        .success();
}

#[test]
fn keygen_refuses_to_clobber_an_existing_key() {
    let sandbox = Sandbox::new();
    sandbox.keygen();
    let original = fs::read(sandbox.path("keys/private.key")).unwrap();

    let assert = sandbox.pqsum().args(["--keygen", "--out", "keys"]).assert();
    assert_eq!(code(&assert), ERROR);
    assert_eq!(
        fs::read(sandbox.path("keys/private.key")).unwrap(),
        original
    );
}

#[cfg(unix)]
#[test]
fn a_generated_private_key_is_not_readable_by_others() {
    use std::os::unix::fs::PermissionsExt;
    let sandbox = Sandbox::new();
    sandbox.keygen();
    let mode = fs::metadata(sandbox.path("keys/private.key"))
        .unwrap()
        .permissions()
        .mode()
        & 0o777;
    assert_eq!(mode, 0o600, "private key should be owner-only");
}

#[test]
fn a_directory_is_not_signed_by_accident() {
    let sandbox = Sandbox::new();
    let (private, _) = sandbox.keygen();
    sandbox.write("dist/one.bin", b"one");

    let assert = sandbox
        .pqsum()
        .args(["--sign", "dist", "--key"])
        .arg(&private)
        .assert();
    assert_eq!(code(&assert), ERROR);
    assert.stderr(predicate::str::contains("--recursive"));
}

// --- usage ----------------------------------------------------------------

#[test]
fn usage_mistakes_exit_2_and_explain_themselves() {
    let sandbox = Sandbox::new();

    for args in [
        vec!["--sign", "f"],                    // no key
        vec!["--verify", "f"],                  // no public key
        vec!["--keygen", "--algo", "rsa-4096"], // unknown algorithm
        vec!["--keygen", "--list-algos"],       // two modes
        vec![],                                 // no mode
    ] {
        let assert = sandbox.pqsum().args(&args).assert();
        assert_eq!(code(&assert), ERROR, "unexpected status for {args:?}");
    }
}

#[test]
fn help_and_version_succeed() {
    let sandbox = Sandbox::new();

    // Every documented flag must actually appear in the help. Help headings
    // are easy to get wrong in a way that hides an option without breaking
    // it, which is exactly the kind of drift a reader would notice first.
    let mut assert = sandbox.pqsum().arg("--help").assert().success();
    for flag in [
        "--keygen",
        "--sign",
        "--verify",
        "--check",
        "--info",
        "--list-algos",
        "--algo",
        "--hash",
        "--key",
        "--pub",
        "--sig",
        "--out",
        "--manifest",
        "--recursive",
        "--force",
        "--quiet",
        "--status",
        "--verbose",
        "EXIT STATUS",
    ] {
        assert = assert.stdout(predicate::str::contains(flag));
    }
    sandbox
        .pqsum()
        .arg("--version")
        .assert()
        .success()
        .stdout(predicate::str::starts_with("pqsum "));
}

#[test]
fn info_describes_a_signature_without_needing_a_key() {
    let sandbox = Sandbox::new();
    let (private, _) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&private)
        .assert()
        .success();

    sandbox
        .pqsum()
        .args(["--info", "data.bin.pq"])
        .assert()
        .success()
        .stdout(predicate::str::contains("ML-DSA-44"))
        .stdout(predicate::str::contains("SHA3-512"));
}

#[test]
fn list_algos_reports_what_this_build_supports() {
    let sandbox = Sandbox::new();
    sandbox
        .pqsum()
        .arg("--list-algos")
        .assert()
        .success()
        .stdout(predicate::str::contains("ML-DSA-65"))
        .stdout(predicate::str::contains("SPHINCS+-SHA2-128f-simple"))
        .stdout(predicate::str::contains("(default)"));
}

// --- algorithms and digests ----------------------------------------------

#[test]
fn every_algorithm_family_round_trips() {
    let sandbox = Sandbox::new();
    sandbox.write("data.bin", b"contents");

    // One representative per family; the cheapest parameter set of each, so
    // the suite stays fast while still exercising all three code paths.
    for (index, algorithm) in ["ML-DSA-44", "SLH-DSA-SHA2-128f", "Falcon-512"]
        .iter()
        .enumerate()
    {
        let dir = format!("keys{index}");
        let (private, public) = sandbox.keygen_with(algorithm, &dir);
        let signature = format!("data-{index}.pq");

        sandbox
            .pqsum()
            .args(["--sign", "data.bin", "--out", &signature, "--key"])
            .arg(&private)
            .assert()
            .success();
        sandbox
            .pqsum()
            .args(["--verify", "data.bin", "--sig", &signature, "--pub"])
            .arg(&public)
            .assert()
            .success();
    }
}

#[test]
fn every_digest_round_trips_and_is_recorded() {
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");

    for digest in ["SHA3-512", "SHA3-256", "SHA-512", "SHA-256"] {
        let signature = format!("data-{digest}.pq");
        sandbox
            .pqsum()
            .args([
                "--sign", "data.bin", "--hash", digest, "--out", &signature, "--key",
            ])
            .arg(&private)
            .assert()
            .success();

        // Verification picks the digest up from the signature; the caller
        // does not have to remember which one was used.
        sandbox
            .pqsum()
            .args(["--verify", "data.bin", "--sig", &signature, "--pub"])
            .arg(&public)
            .assert()
            .success();
        sandbox
            .pqsum()
            .args(["--info", &signature])
            .assert()
            .success()
            .stdout(predicate::str::contains(digest));
    }
}

#[test]
fn a_public_key_alone_cannot_sign() {
    let sandbox = Sandbox::new();
    let (_, public) = sandbox.keygen();
    sandbox.write("data.bin", b"contents");

    let assert = sandbox
        .pqsum()
        .args(["--sign", "data.bin", "--key"])
        .arg(&public)
        .assert();
    assert_eq!(code(&assert), ERROR);
}

#[test]
fn signatures_survive_being_moved_next_to_a_renamed_file() {
    // Detached signatures cover contents, not names, so renaming a release
    // must not break verification.
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("release-1.0.tar.gz", b"contents");
    sandbox
        .pqsum()
        .args(["--sign", "release-1.0.tar.gz", "--key"])
        .arg(&private)
        .assert()
        .success();

    fs::rename(
        sandbox.path("release-1.0.tar.gz"),
        sandbox.path("renamed.tar.gz"),
    )
    .unwrap();
    fs::rename(
        sandbox.path("release-1.0.tar.gz.pq"),
        sandbox.path("renamed.tar.gz.pq"),
    )
    .unwrap();

    sandbox
        .pqsum()
        .args(["--verify", "renamed.tar.gz", "--pub"])
        .arg(&public)
        .assert()
        .success();
}

#[test]
fn signing_reads_standard_input_when_told_where_to_put_the_signature() {
    use std::io::Write;
    use std::process::Stdio;

    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();

    let mut child = sandbox
        .pqsum()
        .args(["--sign", "-", "--out", "stdin.pq", "--key"])
        .arg(&private)
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .spawn()
        .expect("spawn");
    child
        .stdin
        .as_mut()
        .unwrap()
        .write_all(b"piped contents")
        .unwrap();
    assert!(child.wait().unwrap().success());

    // The same bytes on disk must verify against that signature.
    sandbox.write("same.bin", b"piped contents");
    sandbox
        .pqsum()
        .args(["--verify", "same.bin", "--sig", "stdin.pq", "--pub"])
        .arg(&public)
        .assert()
        .success();
}

#[test]
fn key_files_are_plain_text_that_says_what_it_is() {
    let sandbox = Sandbox::new();
    sandbox.keygen();

    let public = fs::read_to_string(sandbox.path("keys/public.key")).unwrap();
    assert!(public.starts_with("-----BEGIN PQSUM PUBLIC KEY-----"));
    assert!(public.contains("Algorithm: ML-DSA-44"));
    assert!(public
        .trim_end()
        .ends_with("-----END PQSUM PUBLIC KEY-----"));

    let private = fs::read_to_string(sandbox.path("keys/private.key")).unwrap();
    assert!(private.starts_with("-----BEGIN PQSUM PRIVATE KEY-----"));
}

#[test]
fn recursive_signing_skips_the_signatures_it_just_wrote() {
    // Running --sign twice over a directory must not start signing the .pq
    // files from the first run.
    let sandbox = Sandbox::new();
    let (private, public) = sandbox.keygen();
    sandbox.write("dist/one.bin", b"one");
    sandbox.write("dist/two.bin", b"two");

    for _ in 0..2 {
        sandbox
            .pqsum()
            .args(["--sign", "dist", "-r", "--force", "--key"])
            .arg(&private)
            .assert()
            .success();
    }

    assert!(!sandbox.path("dist/one.bin.pq.pq").exists());
    sandbox
        .pqsum()
        .args(["--verify", "dist", "-r", "--pub"])
        .arg(&public)
        .assert()
        .success()
        .stdout(predicate::str::contains("one.bin: OK"))
        .stdout(predicate::str::contains("two.bin: OK"));
}

#[test]
fn inputs_are_resolved_before_any_signing_starts() {
    let sandbox = Sandbox::new();
    let (private, _) = sandbox.keygen();
    sandbox.write("first.bin", b"first");

    // The second path does not exist, so the run must fail — and it must fail
    // before writing a signature for the file that did exist.
    let assert = sandbox
        .pqsum()
        .args(["--sign", "first.bin", "missing.bin", "--key"])
        .arg(&private)
        .assert();
    assert_eq!(code(&assert), ERROR);
    assert!(
        !Path::new(&sandbox.path("first.bin.pq")).exists(),
        "inputs are resolved before any signing starts"
    );
}
