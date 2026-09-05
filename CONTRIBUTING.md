# Contributing to pqsum

Thanks for taking a look. Bug reports, tests and documentation fixes are as
welcome as code.

## Getting a build

Everything runs in a container, so you do not need Rust, cmake or liboqs on
your machine — only Docker:

```bash
git clone https://github.com/iA7maz/pqsum.git
cd pqsum
scripts/dev cargo build
```

The first run builds the dev image and compiles liboqs from source, which
takes a few minutes. After that it is incremental.

`scripts/dev` runs any command inside that image:

```bash
scripts/dev cargo test
scripts/dev cargo clippy --all-targets -- -D warnings
scripts/dev cargo fmt --all
scripts/dev bash                        # interactive shell
```

It runs as your own user and keeps the cargo registry and build artefacts in
Docker volumes, so a checkout never ends up with root-owned files in it.

If you would rather build natively:

```bash
sudo apt install cmake clang libclang-dev pkg-config    # Debian/Ubuntu
cargo build
```

## Before opening a pull request

```bash
scripts/dev cargo fmt --all -- --check
scripts/dev cargo clippy --all-targets --all-features -- -D warnings
scripts/dev cargo test
```

CI runs exactly these, plus:

```bash
scripts/dev scripts/smoke /build/debug/pqsum   # end-to-end against a real binary
scripts/check-image                            # the shipped container image works
```

## Layout

| Path | What lives there |
| ---- | ---------------- |
| `src/algo.rs` | The algorithm registry and name matching |
| `src/hash.rs` | Streaming digests and key fingerprints |
| `src/armor.rs` | The PEM-style text container |
| `src/keyfile.rs` | Reading and writing key files |
| `src/sigfile.rs` | The binary detached signature format |
| `src/manifest.rs` | Signed manifests |
| `src/ops.rs` | What each command actually does |
| `src/cli.rs` | Argument parsing and mode validation |
| `src/report.rs` | Terminal output |
| `src/util.rs` | Atomic writes, permissions, timestamps |
| `tests/cli.rs` | End-to-end tests driving the real binary |
| `docs/FORMAT.md` | The on-disk formats |

`src/main.rs` is a thin shell around the library so the formats can be
exercised directly from tests.

## Things worth knowing before you change something

**Exit codes are part of the interface.** `0` verified, `1` did not verify,
`2` could not check. Never collapse `2` into `1`: a script that treats "the
signature file was unreadable" as a valid rejection is annoying, but one that
treats it as a pass is a security hole.

**Options that do not apply to a mode are rejected, not ignored.** See
`Cli::mode`. Silently ignoring `--algo` on `--verify` would leave a user
believing they had pinned something they had not.

**Anything that goes into a signature is length-prefixed and domain
separated.** If you add a field to a signed message, prefix it, and do not
reuse an existing domain string. See `docs/FORMAT.md`.

**The manifest parser is lenient; the manifest format is not.** After parsing,
the body is re-rendered and compared to the bytes on disk. If you touch the
parser or the renderer, keep them exact inverses.

**Do not derive `Debug` on anything holding key material.** `PrivateKey` has a
hand-written one that redacts the secret.

## Adding an algorithm

liboqs already exposes more schemes than pqsum lists. To add one:

1. Add a row to the `algos!` table in `src/algo.rs` with the canonical liboqs
   name, the `oqs::sig::Algorithm` variant, its family and NIST category.
2. Enable the corresponding `oqs` feature in `Cargo.toml` if it is a new
   family.
3. Add an alias only if the name is genuinely different — case and punctuation
   are already ignored.

The `canonical_names_match_liboqs` test asserts that every canonical name
equals `Algorithm::name()`, so a typo or a rename in a liboqs upgrade fails
the suite rather than producing signature files nobody can read back.

No format change is needed: signature files name their algorithm as a string.

## Tests

Unit tests live next to the code they cover; end-to-end tests are in
`tests/cli.rs`. New behaviour should come with a test that would fail without
it. For anything security-relevant, prefer a test that asserts the *negative*
case — that a tampered file is rejected, not just that a good one is accepted.

`scripts/bench` measures throughput and peak memory if you are changing
anything on the hot path.

## Commit messages

A short imperative summary line, then why the change is needed if that is not
obvious from the diff.
