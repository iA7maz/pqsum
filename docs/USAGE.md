# pqsum usage

```text
pqsum <MODE> [OPTIONS]
```

Every mode has a flag form (`pqsum --sign FILE`) and a subcommand form
(`pqsum sign FILE`). They are identical; the flag form is what the README uses
and what reads naturally alongside `sha256sum`.

## Modes

Exactly one is required.

| Mode | What it does |
| ---- | ------------ |
| `--keygen` | Generate a keypair into `--out` (default `.`) |
| `--sign FILE...` | Sign files, writing `FILE.pq` beside each |
| `--verify FILE...` | Verify files against their signatures |
| `--check MANIFEST` | Verify every file listed in a signed manifest |
| `--info FILE.pq` | Describe a signature without verifying anything |
| `--list-algos` | List the algorithms this build supports |

## Options

| Option | Applies to | Meaning |
| ------ | ---------- | ------- |
| `-a`, `--algo ALG` | `--keygen` | Signature algorithm. Default `ML-DSA-65` |
| `-H`, `--hash HASH` | `--sign` | Digest algorithm. Default `SHA3-512` |
| `-k`, `--key FILE` | `--sign` | Private key |
| `-p`, `--pub FILE` | `--verify`, `--check` | Public key |
| `-s`, `--sig FILE` | `--verify` | Signature file. Default `FILE.pq` |
| `-o`, `--out PATH` | `--keygen`, `--sign` | Output directory (keygen) or signature path (sign) |
| `-m`, `--manifest FILE` | `--sign`, `--verify` | Use one signed manifest instead of per-file signatures |
| `-r`, `--recursive` | `--sign`, `--verify` | Include the contents of directories |
| `-f`, `--force` | `--keygen`, `--sign` | Overwrite existing output files |
| `-q`, `--quiet` | all | Do not print a line for each success |
| `--status` | all | Print nothing; report through the exit status |
| `-v`, `--verbose` | all | Print extra detail about keys and algorithms |

Options that cannot apply to the chosen mode are **rejected**, not ignored.
`pqsum --verify f --pub p --algo ML-DSA-87` is an error, because a user who
typed it believes they have pinned the algorithm, and quietly ignoring the
flag would leave them with false confidence. The algorithm always comes from
the key and the signature.

## Exit status

| Code | Meaning |
| ---- | ------- |
| `0` | Success |
| `1` | A signature did not verify |
| `2` | The check could not be carried out |

---

## Generating keys

```bash
pqsum --keygen --out keys/
```

Writes `keys/private.key` (mode `0600`) and `keys/public.key`, and prints the
key's fingerprint. Pick a different algorithm with `--algo`:

```bash
pqsum --keygen --algo SLH-DSA-SHA2-128f --out keys/
```

`--keygen` refuses to overwrite an existing key. If writing the public key
fails, the private key is removed again rather than leaving half a keypair.

## Signing

One file:

```bash
pqsum --sign release.tar.gz --key keys/private.key
```

Several at once:

```bash
pqsum --sign dist/*.tar.gz --key keys/private.key
```

Somewhere other than `FILE.pq` (single file only):

```bash
pqsum --sign release.tar.gz --out signatures/release.pq --key keys/private.key
```

From standard input — `--out` is required, since there is no file name to
derive one from:

```bash
tar czf - src/ | pqsum --sign - --out src.tar.gz.pq --key keys/private.key
```

A whole directory:

```bash
pqsum --sign dist/ --recursive --key keys/private.key
```

Directory walks skip existing `.pq` files, so running `--sign -r` twice does
not start signing the first run's signatures. Directories are an error without
`--recursive`, so a stray `pqsum --sign .` cannot quietly do something
enormous.

Re-signing needs `--force`:

```bash
pqsum --sign release.tar.gz --force --key keys/private.key
```

## Verifying

```bash
pqsum --verify release.tar.gz --pub keys/public.key
```

With an explicit signature path:

```bash
pqsum --verify release.tar.gz --sig signatures/release.pq --pub keys/public.key
```

Many files, or a directory:

```bash
pqsum --verify dist/*.tar.gz --pub keys/public.key
pqsum --verify dist/ --recursive --pub keys/public.key
```

Output matches `sha256sum --check`:

```text
release.tar.gz: OK
other.tar.gz: FAILED (file contents have changed since signing)
pqsum: WARNING: 1 of 2 signatures did NOT verify
```

The reason in parentheses is one of:

| Reason | Meaning |
| ------ | ------- |
| `file contents have changed since signing` | The digest does not match |
| `signed by a different key` | The signature was made by another key |
| `signature is ALG but the public key is ALG` | Key and signature disagree on the algorithm |
| `signature is invalid` | The signature bytes themselves do not check out |
| `missing` | (manifest check) the file is not there |

## Manifests

Sign a directory into one manifest:

```bash
pqsum --sign dist/ --recursive --key keys/private.key --manifest dist/PQSUMS
```

Check it:

```bash
pqsum --check dist/PQSUMS --pub keys/public.key
```

`pqsum --verify dist/ --manifest dist/PQSUMS --pub keys/public.key` is accepted
as the same request.

A manifest covers file **names** as well as contents, so adding, removing or
renaming an entry invalidates it. When that happens the manifest is rejected
outright — before any individual file is reported — because the list itself
cannot be trusted:

```text
dist/PQSUMS: FAILED (signature is invalid)
pqsum: WARNING: 1 of 1 signature did NOT verify
```

That is exit status `1`. A manifest that cannot be parsed at all, or whose
body has been reformatted so it is no longer the bytes that were signed, is
exit status `2` instead — pqsum could not carry out the check, rather than
having carried it out and found a problem.

Paths inside a manifest are relative to the manifest's own directory, so a
release directory can be moved or published wholesale.

## Inspecting a signature

```bash
pqsum --info release.tar.gz.pq
```

```text
file:        release.tar.gz.pq
algorithm:   ML-DSA-65
             NIST category 3, ML-DSA family
digest:      SHA3-512
             20e2e84f0f5bbeefe37d5ea1fd7c8502213ff241632daed27f970c8bcb594c86
signing key: 5b56d2c855a2a714
             5b56d2c855a2a714436c4f5233ca6247565c2254188a68151b32e0117c32299f
signature:   3309 bytes
```

This needs no key. It is the quick way to answer "which key was this signed
with, and do I have it?".

## Scripting

`--status` prints nothing at all:

```bash
if pqsum --verify release.tar.gz --pub keys/public.key --status; then
    install_it
else
    case $? in
        1) echo "signature does not match - do not install" >&2 ;;
        2) echo "could not check the signature" >&2 ;;
    esac
    exit 1
fi
```

`--quiet` keeps failures but drops the `OK` lines, which is usually what you
want when checking hundreds of files:

```bash
pqsum --check dist/PQSUMS --pub keys/public.key --quiet
```

## Choosing an algorithm

* **`ML-DSA-65`** (default) — use this unless you have a reason not to.
* **`ML-DSA-87`** — same family, NIST category 5.
* **`SLH-DSA-*`** — hash based. Much slower to sign and much larger signatures,
  but security rests only on the hash function. Worth it for long-lived
  signatures such as a root of trust.
* **`Falcon-512` / `Falcon-1024`** — smallest signatures. Not yet a NIST
  standard.

The `f` and `s` in SLH-DSA parameter sets are "fast" and "small": `f` signs
faster with larger signatures, `s` the other way round.

```bash
pqsum --list-algos
```
