# pqsum

**A lightweight, post-quantum cryptographic file verification utility for Linux.**

[![CI](https://github.com/iA7maz/pqsum/actions/workflows/ci.yml/badge.svg)](https://github.com/iA7maz/pqsum/actions/workflows/ci.yml)

`pqsum` brings NIST-standardized Post-Quantum Cryptography (PQC) to the command line. Designed to feel as intuitive as `sha256sum`, it generates and verifies quantum-resistant signatures for files and software packages, protecting data integrity against "Harvest Now, Decrypt Later" attacks.

## Why pqsum?

Standard utilities rely on classical hash functions and cryptographic signatures (like RSA or ECC via GPG) that are vulnerable to future quantum computing attacks. While enterprise infrastructure is migrating to PQC, everyday Linux users and open-source maintainers lack a simple, drop-in CLI utility to sign and verify files using the new NIST standards (ML-DSA / SLH-DSA). `pqsum` bridges this gap.

## Features

* **NIST-Standard PQC:** Powered by [`liboqs`](https://github.com/open-quantum-safe/liboqs) — ML-DSA (FIPS 204), SLH-DSA (FIPS 205) and Falcon, 17 parameter sets in all.
* **Familiar CLI Experience:** `FILE: OK` / `FILE: FAILED`, `--quiet`, `--status` and coreutils exit codes, so it drops into scripts that already handle `sha256sum`.
* **Memory Safe:** Written in Rust for speed and safety. Private keys are wiped from memory on drop and written `0600`.
* **Large File Support:** Streaming architecture — signing a 2 GiB image uses **3.5 MiB of RAM**, the same as signing a text file ([measured](#performance)).
* **Signed manifests:** One signature over a whole release directory, in a format you can still read with `cat`.

## How pqsum compares

Signing a release is a solved problem — for classical cryptography. The established tools are mature, well audited and, in most respects, better than this one. They share a single property that pqsum exists to change: **the signature algorithm is broken by a sufficiently large quantum computer.**

| Tool | What it is for | Signature algorithm | Survives Shor's algorithm |
| ---- | -------------- | ------------------- | ------------------------- |
| `sha256sum` | Detecting accidental corruption | none — anyone can recompute a checksum | n/a (no authenticity at all) |
| GnuPG | General-purpose signing, encryption and a full trust model | RSA / ECC | No |
| minisign, signify | Simple detached file signatures | Ed25519 | No |
| cosign | Container and supply-chain artefacts | ECDSA (default) | No |
| **pqsum** | **Detached file signatures** | **ML-DSA, SLH-DSA, Falcon** | **Yes** |

A checksum published next to a download is not a security control: an attacker who can replace the tarball can replace the `SHA256SUMS` line beside it. A signature fixes that — but a classical signature only fixes it until the day the underlying maths does not hold. For an artefact that must still be verifiable in a decade, that day is the one that matters.

### What pqsum contributes

* **NIST standards with coreutils ergonomics.** ML-DSA (FIPS 204) and SLH-DSA (FIPS 205) are available today through liboqs and OpenSSL providers, but as libraries and low-level primitives. pqsum is the part that was missing: a tool a maintainer can actually use in a release script, with `FILE: OK` output and exit codes that behave.
* **Constant memory on any file size.** Signing a 2 GiB image costs 3.5 MiB of RAM, the same as a text file, because the file is streamed through the digest and only the digest is signed. [Measured below.](#performance)
* **Manifests that cover file names.** A detached signature covers bytes, so an attacker who can rename files can pair a genuine signature with a genuine-but-different artefact. A signed manifest closes that, and stays readable as plain text.
* **Failure to check is never a pass.** Exit `1` means "did not verify"; exit `2` means "could not check". They are never collapsed, so a script cannot mistake an unreadable signature for a valid one.
* **Algorithm agility built in.** Signature files name their algorithm as a string. 17 parameter sets ship today and adding more requires no format change — which matters for a field where the standards are still settling.

### What pqsum is not

It is not a GnuPG replacement. There is no key distribution, no revocation, no expiry, no web of trust and no encryption — pqsum signs and verifies files, and that is all. Those omissions are deliberate scope, not oversights, and they are documented in [docs/SECURITY.md](docs/SECURITY.md) so you can decide whether the trade is right for you.

## Installation

### From source

**Prerequisites:** Rust 1.85+, `cmake`, a C compiler, and `libclang`. You do *not* need to install `liboqs` separately — it is built from source and linked statically, so the resulting binary depends only on libc.

```bash
# Debian/Ubuntu
sudo apt install cmake clang libclang-dev pkg-config
```

```bash
git clone https://github.com/iA7maz/pqsum.git
cd pqsum
cargo build --release
sudo install -m755 target/release/pqsum /usr/local/bin/pqsum
```

### With Docker

No toolchain needed, and nothing is installed on your machine:

```bash
docker build -t pqsum https://github.com/iA7maz/pqsum.git
```

```bash
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD:/data" pqsum --verify release.tar.gz --pub public.key
```

`--user` keeps anything the container writes owned by you rather than by the image's user.

## Quick Start

Generate a new post-quantum keypair:

```bash
pqsum --keygen --algo ML-DSA-65 --out keys/
```

Sign a file (generates a `release.tar.gz.pq` signature file):

```bash
pqsum --sign release.tar.gz --key keys/private.key
```

Verify a file:

```bash
pqsum --verify release.tar.gz --sig release.tar.gz.pq --pub keys/public.key
```

`--sig` is optional — `pqsum` looks for `FILE.pq` by default:

```bash
pqsum --verify release.tar.gz --pub keys/public.key
```

### Signing a whole release

One signature covering every file in a directory, checked in one command:

```bash
pqsum --sign dist/ --recursive --key keys/private.key --manifest dist/PQSUMS
```

```bash
pqsum --check dist/PQSUMS --pub keys/public.key
```

The manifest stays human-readable:

```text
# pqsum manifest v1
# algorithm: ML-DSA-65
# digest: SHA3-512
# key: 5b56d2c855a2a714
e72beaf8ebfa0337...  pqsum-0.1.0-x86_64.tar.gz
fd2a9ad8e0521755...  pqsum-0.1.0-aarch64.tar.gz
-----BEGIN PQSUM MANIFEST SIGNATURE-----
...
-----END PQSUM MANIFEST SIGNATURE-----
```

### In a release pipeline

```bash
pqsum --check dist/PQSUMS --pub keys/public.key --status || exit 1
```

## Exit status

| Code | Meaning |
| ---- | ------- |
| `0`  | Everything verified |
| `1`  | A signature did **not** verify — the file is not authentic |
| `2`  | The check could not be carried out (bad usage, missing file, corrupt signature) |

The split between `1` and `2` is deliberate. A script that treats "I could not read the signature file" as a valid rejection is merely annoying; one that treats it as a pass is a security hole. `pqsum` never exits `0` for a file it did not actually check.

## Algorithms

```bash
pqsum --list-algos
```

| Family | Parameter sets | Standard | Notes |
| ------ | -------------- | -------- | ----- |
| **ML-DSA** | 44, 65, 87 | FIPS 204 | Lattice based. The default (`ML-DSA-65`) is the general-purpose choice. |
| **SLH-DSA** | SHA2/SHAKE × 128/192/256 × f/s | FIPS 205 | Hash based. Slower and larger, but its security rests only on the hash function — a good hedge against a lattice break. |
| **Falcon** | 512, 1024 | Selected, not yet standardised | Smallest signatures. |

Names are matched loosely: `ML-DSA-65`, `mldsa65`, `ml_dsa_65` and `Dilithium3` all select the same algorithm.

Digests: `SHA3-512` (default), `SHA3-256`, `SHA-512`, `SHA-256`. The digest is recorded in the signature, so verification never needs to be told which one you picked.

## Performance

Measured with `scripts/bench` on a release build. Peak memory is the kernel's own `VmHWM` high-water mark:

| File size | Sign | Verify | Peak RSS |
| --------- | ---- | ------ | -------- |
| 1 MiB | 0.01s | 0.01s | 3.5 MiB |
| 64 MiB | 0.24s (266 MiB/s) | 0.23s (278 MiB/s) | 3.4 MiB |
| 512 MiB | 1.78s (287 MiB/s) | 1.83s (279 MiB/s) | 3.5 MiB |
| 2048 MiB | 7.60s (269 MiB/s) | 7.22s (283 MiB/s) | 3.5 MiB |

Memory stays flat because the file is streamed through the digest in 1 MiB chunks and only the digest is signed. The benchmark also re-signs the 2 GiB file under a hard 128 MiB address-space limit to prove the point.

## FAQ

### If files are hashed with SHA3-512, what is post-quantum about pqsum?

The hash was never the quantum-vulnerable part. Two different quantum algorithms are involved, and they are not remotely equivalent in impact:

* **Shor's algorithm** breaks asymmetric cryptography built on factoring or discrete logarithms — RSA, DSA, ECDSA and Ed25519 all fail completely. This is the actual problem, and it is what pqsum addresses.
* **Grover's algorithm** applies to hash functions, but only offers a quadratic speedup: it reduces a 2ⁿ search to 2^(n/2). Against SHA3-512 that turns a 2⁵¹² preimage search into 2²⁵⁶, and offers no practical advantage against its 2²⁵⁶ collision bound. The standard mitigation is simply to use a large enough output, which SHA3-512 is. NIST's position is that even SHA-256 remains adequate against a quantum adversary.

Both GnuPG and pqsum use the same **hash-then-sign** construction — nobody signs a multi-gigabyte file directly. The difference is entirely in the second step:

```text
GnuPG:  SHA-256 digest  ->  signed with RSA / ECC     <- Shor breaks this
pqsum:  SHA3-512 digest ->  signed with ML-DSA        <- Shor does not
```

SHA3-512 is the default precisely so the digest does not become the *new* weakest link once the signature is quantum-resistant: its 256-bit collision resistance matches or exceeds the strength of every signature algorithm on offer.

The clearest illustration is SLH-DSA (FIPS 205), one of the two NIST post-quantum signature standards, which pqsum supports in all twelve parameter sets. It is constructed **entirely from hash functions** — no lattices, no number theory. It is considered the conservative post-quantum choice precisely *because* hash functions resist quantum attack. For SLH-DSA, "it relies on a hash" is not a caveat; it is the entire security argument.

### Why not just use GnuPG?

If your threat model does not extend past the useful life of RSA or ECC, GnuPG is more mature, more audited and more widely deployed — use it. pqsum is for the case where a signature has to remain meaningful after a cryptographically relevant quantum computer exists, which mainly means long-lived artefacts: distribution roots of trust, firmware, archives. See [How pqsum compares](#how-pqsum-compares).

### Is a signature made today at risk?

No. Unlike encryption, a signature cannot be forged retroactively — "harvest now, decrypt later" is a confidentiality problem, not a signature one. The risk is **future forgery**: once the hardware exists, anyone can mint signatures that verify against a classical public key you published years earlier. Because migrating a published trust anchor takes years, the move has to begin well before that point. This is set out in full in [docs/SECURITY.md](docs/SECURITY.md).

### Which algorithm should I choose?

`ML-DSA-65`, the default, unless you have a specific reason otherwise. Choose an SLH-DSA parameter set when you want security resting only on hash functions and can accept slower signing and larger signatures. See [Algorithms](#algorithms).

### Is it ready for production?

It is version 0.1.0. The formats are specified and tested, but private keys are stored unencrypted at rest, and there is no revocation, expiry or key distribution. Those gaps are listed explicitly, with a roadmap, in [docs/SECURITY.md](docs/SECURITY.md) — read that before making pqsum load-bearing.

## Documentation

* [docs/USAGE.md](docs/USAGE.md) — every option, with examples
* [docs/FORMAT.md](docs/FORMAT.md) — the on-disk formats, specified well enough to write another implementation
* [docs/SECURITY.md](docs/SECURITY.md) — threat model: what pqsum does and does not protect you from
* [docs/ROADMAP.md](docs/ROADMAP.md) — what is planned next, and what community review has already settled
* [CONTRIBUTING.md](CONTRIBUTING.md) — how to build, test and hack on it

## Contributing

Contributions are welcome! Please check the issues page for "good first issue" tags, particularly around supporting additional NIST candidate algorithms and cross-platform compilation.

Everything builds and tests inside a container, so you do not need a Rust toolchain on your machine:

```bash
scripts/dev cargo test
```

See [CONTRIBUTING.md](CONTRIBUTING.md) for details.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
