# Roadmap

What is planned, in the order it should happen, and why. Items marked
**[decided]** carry an answer from community review rather than a preference.

The governing constraint: **anything that changes a file format should land
before anything that creates users.** pqsum has no adoption yet, which makes
now the cheapest moment in the project's life to break a format. That window
closes the day a GitHub Action or a crates.io release ships.

### If only five things get done

Encrypted private keys (1.5) · numeric identifiers / format v2 (1.2) ·
crates.io and a properly built release (Phase 3) · the GitHub Action
(Phase 3) · fuzzing (2.2).

That list deliberately no longer includes switching to HashML-DSA, which
community review turned into "do not do this" — see 1.3 and 1.4.

---

## Already done

Recorded so they are not mistaken for outstanding work.

* **stdin signing and `--out`.** `pqsum --sign - --out FILE.pq` works and is
  covered by an end-to-end test.
* **A tagged `v0.1.0` release** with an x86_64 binary attached. Static, musl
  and aarch64 builds, and signing it with a real release key, are still open —
  see Phase 3.
* **liboqs is pinned**, via `oqs-sys 0.11.0+liboqs-0.13.0` in `Cargo.lock`.
  What remains is documenting which version, not doing the pinning.
* **First outside review**, on the Open Quantum Safe discussions. It settled
  four questions; a second review from a different audience is still worth
  having — see 2.6.

---

## Phase 1 — settle the formats

### 1.1 Scope the zeroization claim [decided]

The README and `docs/SECURITY.md` currently say private keys are "wiped from
memory on drop" without qualification. That guarantee only holds for memory
pqsum owns. Temporary allocations below the FFI boundary, inside liboqs, are
not ours to promise about.

Reword both to scope the claim to pqsum-controlled memory.

### 1.2 pqsum-owned algorithm identifiers, format v2 [decided]

Today a signature file stores the algorithm as the liboqs name string
(`ML-DSA-65`), and `algo.rs` has a test asserting our table matches
`oqs::sig::Algorithm::name()` exactly. That makes an upstream naming decision
part of pqsum's permanent file format.

Instead:

* Define a numeric identifier space owned by pqsum, mapped internally to
  liboqs algorithms.
* Binary signature files store the numeric id (format **v2**).
* The text manifest keeps human-readable names — it is meant to be read — but
  those become *pqsum's* canonical names, resolved through the same registry
  rather than inherited from the backend.
* `canonical_names_match_liboqs` inverts: assert the mapping *resolves*, not
  that the strings are identical.
* v1 files stay readable.

An upstream rename then touches one table instead of every signature ever
written.

### 1.3 Keep the canonical signed-message framing [decided — no change]

Considered moving domain separation to ML-DSA's `ctx` parameter. **Rejected.**
Context-string support is not uniform across schemes, so it would make
verification semantics algorithm-dependent; a single mandatory cross-algorithm
contract is preferable for a v1 format.

The current construction stands:

```text
"pqsum/v1/detached\0" || len|alg || len|digest-alg || len|digest
```

### 1.4 Never label the construction HashML-DSA [decided]

`sign(SHA3-512(file))` with *pure* ML-DSA is a **pqsum-specific scheme**. FIPS
204's HashML-DSA has its own domain separation and pre-hash identification, and
the two must not share a label.

pqsum has never claimed HashML-DSA. Keep it that way, and state explicitly in
`FORMAT.md` that this is a pqsum scheme, not a FIPS 204 pre-hash variant.

Supporting real HashML-DSA as a **separate, explicitly identified** scheme is
worthwhile but deferred — see 2.1, since liboqs 0.13 exposes only pure ML-DSA
and there is no way to reach `ML-DSA.Sign_internal` through it.

### 1.5 Encrypted private keys at rest

Passphrase protection with Argon2id + XChaCha20-Poly1305. `--passphrase-file`
for CI. Unencrypted becomes an explicit `--no-passphrase` opt-in.

Not adopting a `PQSUM_PASSPHRASE` environment variable: env vars leak through
`/proc`, process listings and CI logs. If added later, document the hazard.

Independent of every format decision above, and the first thing anyone
comparing pqsum to minisign will look for.

### 1.6 Trusted comment field

minisign-style signer-supplied text (version, date, purpose) covered by the
signature. Cheap, and it stops a signature being reused across releases.

### 1.7 Key expiry and not-before dates

Optional fields in the public key file, checked on verify. A cheap partial
answer to having no revocation.

### 1.8 Decide Falcon's status

Not yet a finished standard. Either mark experimental with a warning at
keygen, or remove until FN-DSA is final. Removing is a breaking change that
costs nothing today and a great deal later.

---

## Phase 2 — dependencies and assurance

### 2.1 Evaluate a pure-Rust backend

RustCrypto `ml-dsa` and `slh-dsa`, feature-gated alongside liboqs. Run both in
CI and **cross-verify signatures between backends** — that is the strongest
assurance available without an audit.

Also the unblocker for HashML-DSA (1.4), if that crate exposes the pre-hash or
internal API that liboqs does not.

Note both are young and unaudited; this is about removing a single point of
failure, not about one being obviously safer.

### 2.2 Fuzz the parsers

`cargo fuzz` targets for `sigfile::decode`, `manifest::parse_body`, `armor`
and `keyfile::load`. These are the attacker-controlled inputs.

### 2.3 Test vectors

Known-answer tests in `tests/vectors/` so a second implementation can be
written from `FORMAT.md` alone — which is what `FORMAT.md` already promises.
Do this *after* format v2 lands.

### 2.4 Supply chain

`cargo deny` and `cargo audit` in CI. Document which liboqs version is pinned
(already pinned via `oqs-sys 0.11.0+liboqs-0.13.0` in `Cargo.lock`).

### 2.5 Threat model table

In `SECURITY.md`: attacker capabilities as rows (replace the file, replace file
and key, steal the laptop, compromise CI, own a quantum computer in 2040)
against what pqsum does and does not stop.

### 2.6 A second outside review, on the construction itself

The Open Quantum Safe thread reviewed how pqsum *uses* liboqs, and was worth
it. It is not the same as having the signed-message construction examined by
people who do nothing but analyse constructions.

Ask on Cryptography Stack Exchange or the NIST **pqc-forum** specifically
about the canonical framing — the length-prefixed encoding of
`(algorithm, digest algorithm, digest)`, the domain separation between
detached signatures, manifests and fingerprints, and whether signing a digest
under a scheme with no standardised pre-hash introduces anything the framing
does not already cover.

Worth doing after format v2 lands, so the thing being reviewed is the thing
that will ship. The replies become a `FORMAT.md` section either way.

---

## Phase 3 — adoption

Deliberately after Phase 1. Shipping these first means asking the first real
users to migrate.

* **Publish to crates.io**, add `cargo install pqsum` to the README.
* **Prebuilt binaries** for x86_64, aarch64 and musl, with a `PQSUMS` manifest
  signed by a real release key. Dogfood it visibly.
* **Reproducible builds** — document a Docker invocation producing a
  bit-identical binary. For a signing tool this is the credibility move.
* **Shell completions and a man page** (clap generates both). Then AUR,
  Homebrew, and a `.deb` via `cargo-deb`.
* **A trusted-keys directory** — `~/.config/pqsum/trusted/*.key` with defaults
  for `.pq` and `PQSUMS`. The minimum viable key management.
* **GitHub Action** (`iA7maz/pqsum-action`) to sign release assets. The most
  likely source of first real users.
* **`pqsum-core` crate** exposing only the verify path, no CLI dependencies,
  so installers can embed verification.
* **Git integration** — `gpg.format` wrapper for signing commits and tags.
* **Hybrid signatures** — Ed25519 + ML-DSA in one file, both required. Most
  migration guidance recommends hybrid during the transition.

### Not planned: `--check` on unsigned `SHA256SUMS`

Proposed as a drop-in convenience, but it would have pqsum exit `0` for input
that proves no authenticity at all — against the one discipline the tool is
built around. If ever added it needs its own exit code or a mandatory
`--insecure-unsigned` flag.

---

## Documentation and hygiene

* Fix key distribution guidance: state plainly that a public key fetched from
  the same server as the tarball proves nothing, and recommend publishing the
  fingerprint in at least two independent places.
* Add `pqsum --fingerprint public.key` — currently the fingerprint is only
  printed at keygen, and `--info` covers signature files only.
* Document why the digest is stored in the signature file even though
  verification recomputes it: it distinguishes "contents changed" from
  "signature invalid", and feeds `--info`.
* Real security contact in `Cargo.toml` instead of "pqsum contributors".
* `--json` output for machine consumers.
* Move "Is it ready for production?" higher in the README, with the liboqs
  research-quality caveat alongside it.
* Version the file formats separately from the CLI in `CHANGELOG.md`.
