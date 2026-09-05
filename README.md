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

## Documentation

* [docs/USAGE.md](docs/USAGE.md) — every option, with examples
* [docs/FORMAT.md](docs/FORMAT.md) — the on-disk formats, specified well enough to write another implementation
* [docs/SECURITY.md](docs/SECURITY.md) — threat model: what pqsum does and does not protect you from
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
