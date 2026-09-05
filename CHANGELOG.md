# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-09-05

First working release: the tool described by the README now exists.

### Added

- `--keygen`, `--sign` and `--verify`, matching the interface the README
  documented. Subcommand spellings (`pqsum sign ...`) are accepted as
  equivalents.
- 17 signature algorithms via liboqs: ML-DSA 44/65/87 (FIPS 204), all twelve
  SLH-DSA parameter sets (FIPS 205) and Falcon 512/1024. `ML-DSA-65` is the
  default. Names are matched loosely, so `mldsa65` and `Dilithium3` work too.
- Streaming digests in 1 MiB chunks: signing a 2 GiB file uses 3.5 MiB of RAM
  and runs at roughly 280 MiB/s. Selectable with `--hash` from SHA3-512
  (default), SHA3-256, SHA-512 and SHA-256; the choice is recorded in the
  signature so verification does not need to be told.
- Signed manifests (`--manifest`, `--check`): one signature over a whole
  release directory, in a `sha256sum`-shaped text format that also covers file
  names.
- `--info` to describe a signature file without needing a key, and
  `--list-algos` to show what the build supports.
- Coreutils-style output and exit codes: `FILE: OK` / `FILE: FAILED (reason)`,
  `--quiet`, `--status`, and `0` / `1` / `2` for verified, rejected and
  could-not-check.
- `--recursive` for directories, skipping existing `.pq` files so a repeated
  run does not sign its own signatures.
- Armored, self-describing key files; private keys written `0600`, held in
  zeroizing buffers, and redacted from `Debug` output.
- Atomic writes throughout, and a refusal to overwrite existing keys or
  signatures without `--force`.
- Containerised toolchain: `scripts/dev` for builds and tests without
  installing anything on the host, plus `scripts/smoke`, `scripts/bench` and
  `scripts/check-image`.
- Documentation: `docs/USAGE.md`, `docs/FORMAT.md` (specified well enough to
  reimplement) and `docs/SECURITY.md` (threat model and known gaps).

[0.1.0]: https://github.com/iA7maz/pqsum/releases/tag/v0.1.0
