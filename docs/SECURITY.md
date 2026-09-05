# Security model

What pqsum protects you from, what it does not, and where the sharp edges are.
Read this before relying on it for anything that matters.

## What a pqsum signature means

A successful verification tells you exactly one thing:

> The bytes of this file are the bytes that were signed by the holder of the
> private key matching the public key you supplied.

Everything else — whether that key belongs to who you think, whether the key
has since been compromised, whether the signer was entitled to sign — is
outside what the signature can tell you.

## The threat it is built for

Classical signature schemes (RSA, ECDSA, Ed25519) are broken by Shor's
algorithm on a sufficiently large quantum computer. For **signatures**, this
matters differently than it does for encryption:

* For encryption, the concern is "harvest now, decrypt later" — an adversary
  records ciphertext today and decrypts it once the hardware exists. The data
  is already lost at capture time.
* For signatures, a signature made today cannot be retroactively forged. The
  concern is instead **future forgery**: once such a computer exists, anyone
  can mint signatures that verify against a classical public key you published
  years ago. Anything long-lived — a distribution's root of trust, firmware
  signing, an archive that must still be verifiable in 2045 — needs to have
  moved to post-quantum signatures *before* that point, because migrating a
  published trust anchor takes years.

pqsum exists so that migration can start now for the ordinary case: a
maintainer publishing a release, and a user checking it.

ML-DSA and SLH-DSA are the NIST standards for this (FIPS 204 and FIPS 205).
Both are believed secure against classical and quantum adversaries.

### Why a classical hash is not a weak link

pqsum hashes with SHA3-512, which is not itself a "post-quantum algorithm".
That is not an inconsistency: hash functions were never the part quantum
computers break.

* **Shor's algorithm** applies to problems with hidden periodic structure —
  integer factorisation and discrete logarithms. It reduces RSA, DSA, ECDSA
  and Ed25519 from infeasible to routine. There is no analogous structure in
  a hash function for it to exploit.
* **Grover's algorithm** does apply, but yields only a quadratic speedup: a
  2^n search becomes 2^(n/2).

For SHA3-512 that gives:

| Property | Classical | With Grover |
| -------- | --------- | ----------- |
| Preimage resistance | 2^512 | 2^256 |
| Collision resistance | 2^256 (birthday bound) | ~2^256 in practice |

The quantum collision algorithms that beat the birthday bound (BHT and
relatives) require quantum memory on the order of the search space, which is
why NIST does not credit them with a practical advantage, and why its position
is that doubling an output length is a sufficient response to Grover. SHA3-512
is already well past that threshold; the weakest link in a pqsum signature is
therefore the signature scheme, not the digest.

This is also why `--hash SHA-256` is offered but not the default. It remains
secure against known quantum attack, but its 128-bit collision resistance
gives less margin than the signature algorithms it would sit underneath, and
in a hash-then-sign construction the digest's collision resistance is a
security parameter: an adversary who finds a collision can move a valid
signature onto a different file.

The strongest illustration that hashes are not the problem is FIPS 205 itself.
SLH-DSA is built entirely out of hash functions, with no number-theoretic or
lattice assumption anywhere in it. It is the conservative post-quantum choice
*because* its security reduces to hash properties, which quantum computers do
not meaningfully erode.

## What pqsum does not do

**It does not distribute keys.** This is the hard part of any signing system
and pqsum does not solve it. `--verify` is only as meaningful as your
confidence that `public.key` is genuinely the maintainer's. Obtain it over a
channel you trust — the project's HTTPS site, a distribution package, in
person — and compare fingerprints out of band:

```bash
pqsum --info release.tar.gz.pq   # shows which key signed it
```

A signature verified against a public key that the same attacker supplied
proves nothing at all.

**There is no revocation, expiry, or timestamping.** A signature made by a key
that was later compromised still verifies. There is no mechanism to say "this
key is no longer valid after date X", and no proof of *when* something was
signed. If a key is compromised you must distribute a new public key by the
same out-of-band means you used for the first one.

**There is no web of trust, no certificates, no key servers.** One key, one
file. This is deliberate — it is the part of GPG that most people get wrong —
but it means pqsum is not a drop-in replacement for a PKI.

**Private keys are stored unencrypted.** `private.key` is protected by file
permissions (`0600`) and nothing else. Anyone who can read the file can sign
as you. Passphrase protection is a known gap; see *Roadmap* below.

**It signs contents, not names.** A detached `FILE.pq` covers the bytes of the
file, not what it is called. Renaming a release does not invalidate its
signature, and an attacker who can rename files can present a genuine
signature next to a genuine-but-different file. Where names matter, use a
signed manifest — it covers names too.

**It does not encrypt anything.** pqsum provides integrity and authenticity.
Confidentiality is not in scope.

## Design decisions that carry security weight

**Digests are signed, not files.** The file is streamed through SHA3-512 and
the digest is signed. Security therefore also depends on the digest's
collision resistance: an attacker who can find a collision can move a
signature between two colliding files. SHA3-512 is the default because its
256-bit collision resistance keeps it from being the weak link under any of
the offered signature algorithms. `--hash SHA-256` is available for
compatibility but gives 128-bit collision resistance — enough today, less
future margin than the rest of the design.

**Algorithm names are inside the signed message.** The signed bytes are

```text
"pqsum/v1/detached\0" || len|algorithm || len|digest-algorithm || len|digest
```

so a signature cannot be relabelled as covering a different digest algorithm
or as coming from a different scheme. The length prefixes make the encoding
unambiguous.

**Domain separation.** Detached signatures, manifests and key fingerprints
each use a distinct prefix, so a signature produced in one context can never
be replayed as valid in another.

**Manifests are checked against a canonical rendering.** After parsing, the
body is re-rendered from the parsed entries and required to equal the bytes on
disk. Without this, a lenient parser and a strict signed encoding disagree,
and "what the signature covers" drifts from "what a human reads".

**Failure to check is not a pass.** Exit status `1` means a signature did not
verify; `2` means the check could not be carried out. pqsum never exits `0`
for a file it did not actually check. Scripts should treat both as failure —
the distinction exists so error messages can be useful, not so that `2` can be
ignored.

**Key material is wiped.** Secret keys live in `Zeroizing` buffers and are
cleared on drop. `PrivateKey` has a hand-written `Debug` that redacts the
secret, so it cannot leak into a log line or panic message.

## Known limitations

| Limitation | Impact |
| ---------- | ------ |
| Private keys unencrypted at rest | File read = full key compromise |
| No revocation or expiry | A compromised key verifies forever |
| No timestamping | Cannot prove *when* something was signed |
| Wiping is best-effort | Memory may still be swapped to disk or captured in a core dump |
| Side-channel resistance inherited from liboqs | pqsum adds no protections of its own; signing on shared hardware carries the usual risks |
| Fingerprint is not a trust decision | It identifies a key, it does not vouch for it |

## Dependencies

Cryptography comes from [liboqs](https://github.com/open-quantum-safe/liboqs)
via the `oqs` crate, built from source and linked statically. Digests come
from the RustCrypto `sha2` and `sha3` crates. pqsum implements no primitives
itself — the code here is framing, parsing and file handling, which is
deliberately the only part it is in a position to get right.

liboqs itself states that it is research-quality software and that its
algorithm implementations have not all been through the same review as, say,
OpenSSL's. That applies transitively to pqsum.

## Roadmap for the gaps above

Contributions welcome on any of these:

* Passphrase-protected private keys (Argon2id + an AEAD around the secret).
* Key expiry and a revocation statement format.
* Optional signed timestamps.
* Hybrid signatures (classical + post-quantum in one file), so a signature
  stays valid if either scheme is broken.

## Reporting a vulnerability

Please report security issues privately through
[GitHub Security Advisories](https://github.com/iA7maz/pqsum/security/advisories/new)
rather than a public issue.
