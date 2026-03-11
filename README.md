# pqsum

**A lightweight, post-quantum cryptographic file verification utility for Linux.**

`pqsum` brings NIST-standardized Post-Quantum Cryptography (PQC) to the command line. Designed to feel as intuitive as `sha256sum`, it generates and verifies quantum-resistant signatures for files and software packages, protecting data integrity against "Harvest Now, Decrypt Later" attacks.

## Why pqsum?
Standard utilities rely on classical hash functions and cryptographic signatures (like RSA or ECC via GPG) that are vulnerable to future quantum computing attacks. While enterprise infrastructure is migrating to PQC, everyday Linux users and open-source maintainers lack a simple, drop-in CLI utility to sign and verify files using the new NIST standards (ML-DSA / SLH-DSA). `pqsum` bridges this gap.

## Features
* **NIST-Standard PQC:** Powered by `liboqs`, supporting algorithms like ML-DSA (Dilithium).
* **Familiar CLI Experience:** Built to mirror the simplicity of GNU Coreutils.
* **Memory Safe:** Written in Rust for speed and safety.
* **Large File Support:** Efficient streaming architecture for signing massive ISOs or binaries without high RAM usage.

## Installation

**Prerequisites:** You will need Rust, Cargo, and the `liboqs` C library installed on your system.

```bash
# Clone the repository
git clone [https://github.com/yourusername/pqsum.git](https://github.com/yourusername/pqsum.git)
cd pqsum

# Build for release
cargo build --release

# Move to your bin directory
sudo cp target/release/pqsum /usr/local/bin/
```

## Quick Start
Generate a new post-quantum keypair:

```bash
pqsum --keygen --algo ML-DSA-65 --out keys/
Sign a file (generates a release.tar.gz.pq signature file):
```
```bash
pqsum --sign release.tar.gz --key keys/private.key 
Verify a file:
```
```bash
pqsum --verify release.tar.gz --sig release.tar.gz.pq --pub keys/public.key
```
## Contributing 
Contributions are welcome! Please check the issues page for "good first issue" tags, particularly around supporting additional NIST candidate algorithms and cross-platform compilation.
