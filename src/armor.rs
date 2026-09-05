//! A small PEM-style container for text-safe key and signature material.
//!
//! Keys are the artefacts people copy into issue trackers, paste into CI
//! secrets and commit next to a release. A base64 body between labelled
//! delimiters survives all of that, and the header lines mean you can tell
//! what a file is with `head` instead of a hex editor.
//!
//! ```text
//! -----BEGIN PQSUM PUBLIC KEY-----
//! Algorithm: ML-DSA-65
//! Fingerprint: 4e9f...
//!
//! Ej8BAAAA...
//! -----END PQSUM PUBLIC KEY-----
//! ```

use std::path::Path;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;

use crate::error::{Error, Result};

const WRAP: usize = 64;

pub const PUBLIC_KEY_LABEL: &str = "PQSUM PUBLIC KEY";
pub const PRIVATE_KEY_LABEL: &str = "PQSUM PRIVATE KEY";
pub const MANIFEST_SIGNATURE_LABEL: &str = "PQSUM MANIFEST SIGNATURE";

/// A parsed armor block: its headers, in file order, and its decoded payload.
pub struct Block {
    pub headers: Vec<(String, String)>,
    pub payload: Vec<u8>,
}

impl Block {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
            .map(|(_, v)| v.as_str())
    }

    /// Fetch a header that the format requires to be present.
    pub fn require(&self, name: &str, path: &Path) -> Result<&str> {
        self.header(name)
            .ok_or_else(|| Error::malformed(path, format!("missing {name} header")))
    }
}

/// Render an armor block.
pub fn encode(label: &str, headers: &[(&str, String)], payload: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {label}-----\n"));
    for (key, value) in headers {
        out.push_str(&format!("{key}: {value}\n"));
    }
    out.push('\n');

    let encoded = B64.encode(payload);
    for chunk in encoded.as_bytes().chunks(WRAP) {
        out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
        out.push('\n');
    }
    out.push_str(&format!("-----END {label}-----\n"));
    out
}

/// Parse the first block with the given label out of `text`.
///
/// Leading and trailing text is ignored, so a manifest can carry its signature
/// in a trailing block with the signed body above it.
pub fn decode(text: &str, label: &str, path: &Path) -> Result<Block> {
    let begin = format!("-----BEGIN {label}-----");
    let end = format!("-----END {label}-----");

    let mut lines = text.lines();
    let found = lines.by_ref().any(|line| line.trim_end() == begin);
    if !found {
        return Err(Error::malformed(path, format!("no {label} block found")));
    }

    let mut headers = Vec::new();
    let mut body = String::new();
    let mut in_headers = true;
    let mut closed = false;

    for line in lines {
        let line = line.trim_end();
        if line == end {
            closed = true;
            break;
        }
        if in_headers {
            if line.trim().is_empty() {
                in_headers = false;
                continue;
            }
            match line.split_once(':') {
                Some((key, value)) if !key.trim().is_empty() => {
                    headers.push((key.trim().to_string(), value.trim().to_string()));
                    continue;
                }
                // No colon: this block carries no headers and we are already
                // looking at base64.
                _ => in_headers = false,
            }
        }
        body.push_str(line.trim());
    }

    if !closed {
        return Err(Error::malformed(
            path,
            format!("{label} block is not terminated"),
        ));
    }

    let payload = B64
        .decode(body.as_bytes())
        .map_err(|e| Error::malformed(path, format!("invalid base64 in {label} block: {e}")))?;

    Ok(Block { headers, payload })
}

/// Length-prefixed framing for payloads that hold more than one field.
pub struct Framer(Vec<u8>);

impl Framer {
    pub fn new() -> Self {
        Framer(Vec::new())
    }

    pub fn push(mut self, field: &[u8]) -> Self {
        self.0
            .extend_from_slice(&(field.len() as u32).to_le_bytes());
        self.0.extend_from_slice(field);
        self
    }

    pub fn finish(self) -> Vec<u8> {
        self.0
    }
}

impl Default for Framer {
    fn default() -> Self {
        Framer::new()
    }
}

/// Read back fields written by [`Framer`].
pub struct Unframer<'a> {
    rest: &'a [u8],
}

impl<'a> Unframer<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        Unframer { rest: bytes }
    }

    pub fn next_field(&mut self, path: &Path) -> Result<&'a [u8]> {
        if self.rest.len() < 4 {
            return Err(Error::malformed(path, "truncated key material"));
        }
        let (len_bytes, tail) = self.rest.split_at(4);
        let len = u32::from_le_bytes(len_bytes.try_into().expect("4 bytes")) as usize;
        if tail.len() < len {
            return Err(Error::malformed(path, "truncated key material"));
        }
        let (field, rest) = tail.split_at(len);
        self.rest = rest;
        Ok(field)
    }

    pub fn finish(self, path: &Path) -> Result<()> {
        if self.rest.is_empty() {
            Ok(())
        } else {
            Err(Error::malformed(path, "trailing bytes after key material"))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p() -> &'static Path {
        Path::new("<test>")
    }

    #[test]
    fn round_trips_headers_and_payload() {
        let payload: Vec<u8> = (0u8..=255).cycle().take(500).collect();
        let text = encode(
            PUBLIC_KEY_LABEL,
            &[
                ("Algorithm", "ML-DSA-65".into()),
                ("Created", "1970-01-01T00:00:00Z".into()),
            ],
            &payload,
        );

        let block = decode(&text, PUBLIC_KEY_LABEL, p()).unwrap();
        assert_eq!(block.payload, payload);
        assert_eq!(block.header("algorithm"), Some("ML-DSA-65"));
        assert_eq!(block.header("Created"), Some("1970-01-01T00:00:00Z"));
        assert_eq!(block.header("nope"), None);
    }

    #[test]
    fn body_lines_are_wrapped() {
        let text = encode(PUBLIC_KEY_LABEL, &[], &[0u8; 200]);
        for line in text.lines().filter(|l| !l.starts_with("-----")) {
            assert!(line.len() <= WRAP, "line too long: {line}");
        }
    }

    #[test]
    fn surrounding_text_is_ignored() {
        let inner = encode(MANIFEST_SIGNATURE_LABEL, &[], b"payload");
        let text = format!("some notes\nmore notes\n{inner}trailing\n");
        let block = decode(&text, MANIFEST_SIGNATURE_LABEL, p()).unwrap();
        assert_eq!(block.payload, b"payload");
    }

    #[test]
    fn rejects_missing_or_unterminated_blocks() {
        assert!(decode("nothing here", PUBLIC_KEY_LABEL, p()).is_err());

        let truncated =
            encode(PUBLIC_KEY_LABEL, &[], b"x").replace("-----END PQSUM PUBLIC KEY-----", "");
        assert!(decode(&truncated, PUBLIC_KEY_LABEL, p()).is_err());
    }

    #[test]
    fn rejects_corrupt_base64() {
        let text = encode(PUBLIC_KEY_LABEL, &[], b"payload").replace("cGF5", "!!!!");
        assert!(decode(&text, PUBLIC_KEY_LABEL, p()).is_err());
    }

    #[test]
    fn framing_round_trips() {
        let framed = Framer::new().push(b"one").push(b"").push(b"three").finish();
        let mut un = Unframer::new(&framed);
        assert_eq!(un.next_field(p()).unwrap(), b"one");
        assert_eq!(un.next_field(p()).unwrap(), b"");
        assert_eq!(un.next_field(p()).unwrap(), b"three");
        assert!(un.finish(p()).is_ok());
    }

    #[test]
    fn framing_detects_truncation() {
        let framed = Framer::new().push(b"hello").finish();
        let mut un = Unframer::new(&framed[..framed.len() - 2]);
        assert!(un.next_field(p()).is_err());
    }
}
