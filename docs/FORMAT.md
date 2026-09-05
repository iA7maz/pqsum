# pqsum file formats

Version 1. This document specifies the three artefacts pqsum reads and writes
in enough detail to write an independent implementation.

All multi-byte integers are **little-endian**. All text is UTF-8. Line endings
in text formats are LF.

---

## 1. Armored text container

Keys and manifest signatures use a PEM-style container. It exists so that key
material survives being pasted into an issue, a CI secret or a wiki page, and
so `head` tells you what a file is.

```text
-----BEGIN <LABEL>-----
Header-Name: value
Another-Header: value

<base64, wrapped at 64 columns>
-----END <LABEL>-----
```

Rules:

* Labels in use: `PQSUM PUBLIC KEY`, `PQSUM PRIVATE KEY`,
  `PQSUM MANIFEST SIGNATURE`.
* Headers run from the `BEGIN` line to the first blank line. A header line is
  `Name: value`; names are matched case-insensitively, values are trimmed.
* The header block may be empty, in which case the base64 body starts
  immediately.
* Text before `BEGIN` and after `END` is ignored. This is what allows a
  manifest to carry its signature in a trailing block.
* Base64 is standard alphabet with padding.

### Payload framing

Where a payload holds more than one field, fields are length-prefixed:

```text
u32 length | bytes | u32 length | bytes | ...
```

A decoder must reject trailing bytes after the last declared field.

---

## 2. Key files

### Public key — `public.key`

Label `PQSUM PUBLIC KEY`. The payload is the raw public key as produced by
liboqs, with no framing.

Headers:

| Header | Required | Meaning |
| ------ | -------- | ------- |
| `Algorithm` | yes | Canonical algorithm name, e.g. `ML-DSA-65` |
| `Fingerprint` | no | Hex fingerprint of this key (see below) |
| `Created` | no | RFC 3339 UTC timestamp |

A reader **must**:

* reject the file if the payload length is not the public key length for the
  named algorithm;
* if `Fingerprint` is present, recompute it and reject the file on a mismatch.
  The header is a convenience for humans, so a wrong one means the file has
  been edited.

### Private key — `private.key`

Label `PQSUM PRIVATE KEY`. The payload is two framed fields:

```text
u32 len | secret key bytes | u32 len | public key bytes
```

The public key is stored alongside the secret key so signing knows which key a
signature will be checked against without needing both files.

Headers are the same as for public keys; `Fingerprint` covers the *public*
key. Private key files are written with mode `0600`; pqsum warns (but does not
refuse) when loading one that is group or world accessible.

### Key fingerprint

```text
fingerprint = SHA3-256( "pqsum/v1/fingerprint\x00" || public_key_bytes )
```

32 bytes, rendered lowercase hex. The **short id** used in human-facing output
is the first 8 bytes (16 hex characters).

---

## 3. Detached signature — `FILE.pq`

A flat binary record.

```text
offset  size    field
0       6       magic, ASCII "PQSUM" followed by 0x1a
6       1       format version, currently 1
7       1       flags, reserved, must be 0
8       1       algorithm name length, n
9       n       algorithm name, UTF-8
+       1       digest algorithm name length, m
+       m       digest algorithm name, UTF-8
+       2       digest length, u16
+       d       digest bytes
+       32      signing key fingerprint
+       4       signature length, u32
+       s       signature bytes
```

The `0x1a` byte in the magic is the DOS end-of-file character. It makes a
signature file that has been through a text-mode transfer fail loudly rather
than subtly.

A reader must reject a file with trailing bytes after the signature, a version
it does not recognise, non-zero flags, or a digest whose length does not match
the named digest algorithm.

### What is signed

Not the file itself. pqsum streams the file through the digest and signs a
canonical encoding of the digest and the algorithms that produced it:

```text
message = "pqsum/v1/detached\x00"
        || u16 len | algorithm name
        || u16 len | digest algorithm name
        || u16 len | digest
```

Length prefixes make the encoding unambiguous: no two distinct
`(algorithm, digest algorithm, digest)` triples produce the same message.

Naming both algorithms *inside* the signed message is what stops an attacker
relabelling a signature — a signature made over a SHA-256 digest cannot be
presented as covering a SHA3-512 one, and a signature cannot be re-labelled as
coming from a different scheme.

### What is deliberately not signed

The **file name**. Detached signatures cover contents, so renaming a release
tarball does not invalidate its signature. When names matter, use a manifest.

---

## 4. Signed manifest

A text file: a header block, then one line per file, then an armored signature
block. Everything above the `BEGIN` line is the signed body.

```text
# pqsum manifest v1
# algorithm: ML-DSA-65
# digest: SHA3-512
# key: 5b56d2c855a2a714
<hex digest><two spaces><path>
<hex digest><two spaces><path>
-----BEGIN PQSUM MANIFEST SIGNATURE-----
Algorithm: ML-DSA-65
Fingerprint: 5b56d2c8...

<base64 signature>
-----END PQSUM MANIFEST SIGNATURE-----
```

* The first line must be exactly `# pqsum manifest v1`.
* `# algorithm:`, `# digest:` and `# key:` are all required. `# key:` is the
  signer's short id (see §2). It is part of the signed body and a verifier
  must compare it against the public key it was given, reporting a mismatch as
  "signed by a different key" rather than as a malformed file.
* Entry lines are `<hex digest>` then **two spaces** then the path — the same
  shape `sha256sum` produces.
* Paths are relative to the directory containing the manifest.

### What is signed

```text
message = "pqsum/v1/manifest\x00" || u32 len | body
```

where `body` is the exact bytes of everything above the `-----BEGIN` line.

### Canonical form

After parsing a manifest, a verifier **must** re-render the body from the
parsed fields and require it to equal the bytes on disk, before checking the
signature.

This closes the gap between a lenient parser and the strict signed encoding.
Without it, a parser that tolerated (say) extra whitespace would accept a body
that is not the one that was signed, and the difference between "what the
signature covers" and "what a human reads" becomes exploitable.

Every value used in that re-render must come from the file, never from the
verifier's inputs. In particular the signer id is the one parsed out of
`# key:`, not the short id of whichever public key was supplied — otherwise
presenting the wrong key makes an intact manifest look malformed, and the
error blames the file instead of the key.

### Path escaping

Paths containing a backslash, LF or CR are escaped, using the same convention
as the coreutils checksum tools: the line's path field is prefixed with `\`,
and within it `\` becomes `\\`, LF becomes `\n`, and CR becomes `\r`. Paths
without those characters are written literally, including ones containing
spaces.

---

## 5. Digest algorithms

| Name in files | Output |
| ------------- | ------ |
| `SHA3-512` (default) | 64 bytes |
| `SHA3-256` | 32 bytes |
| `SHA-512` | 64 bytes |
| `SHA-256` | 32 bytes |

SHA3-512 is the default because its 256-bit collision resistance keeps the
digest from being the weakest link under any of the signature algorithms on
offer.

## 6. Algorithm names

Canonical names are exactly the names liboqs uses, so a pqsum file names its
algorithm the same way the underlying library does — for example
`ML-DSA-65`, `SPHINCS+-SHA2-128f-simple`, `Falcon-512`.

On the command line, names are matched after lowercasing and removing `-`,
`_`, ` `, `.` and `+`, and a small alias table adds the FIPS spellings
(`SLH-DSA-SHA2-128f`) and the pre-standard research names (`Dilithium3`).
Only canonical names appear in files.

## 7. Version and compatibility

The version byte in a detached signature and the `# pqsum manifest v1` line
both identify format version 1. A reader that encounters a higher version must
refuse the file rather than guess; pqsum reports it as
`signature format version N is newer than this pqsum understands`.
