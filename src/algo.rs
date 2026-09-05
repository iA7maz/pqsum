//! The registry of signature algorithms pqsum exposes.
//!
//! Canonical names are the ones liboqs uses, so a signature file written by
//! pqsum names its algorithm the same way the underlying library does. On top
//! of that each entry carries aliases, which is where the FIPS spellings
//! (`SLH-DSA-...`), the pre-standard research names (`Dilithium3`) and
//! punctuation-free forms (`mldsa65`) are accepted.

use crate::error::{Error, Result};

/// A signature algorithm pqsum knows how to drive.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlgoInfo {
    /// Canonical name, identical to `oqs::sig::Algorithm::name()`.
    pub name: &'static str,
    /// Alternative spellings accepted on the command line.
    ///
    /// Only genuinely different names belong here. Case and punctuation are
    /// already ignored by [`lookup`], so `mldsa65` and `ml_dsa_65` match
    /// `ML-DSA-65` without needing entries of their own.
    pub aliases: &'static [&'static str],
    pub oqs: oqs::sig::Algorithm,
    pub family: &'static str,
    /// NIST security category (1, 3 or 5).
    pub level: u8,
}

macro_rules! algos {
    ($( $name:literal, $variant:ident, $family:literal, $level:literal, [$($alias:literal),* $(,)?] );* $(;)?) => {
        pub const ALGORITHMS: &[AlgoInfo] = &[
            $(AlgoInfo {
                name: $name,
                aliases: &[$($alias),*],
                oqs: oqs::sig::Algorithm::$variant,
                family: $family,
                level: $level,
            }),*
        ];
    };
}

algos! {
    // FIPS 204 — lattice based, the general-purpose default.
    "ML-DSA-44", MlDsa44, "ML-DSA", 2, ["dilithium2"];
    "ML-DSA-65", MlDsa65, "ML-DSA", 3, ["dilithium3"];
    "ML-DSA-87", MlDsa87, "ML-DSA", 5, ["dilithium5"];

    // FIPS 205 — hash based. Slower and larger, but its security rests only on
    // the hash function, which makes it a good hedge against lattice breaks.
    "SPHINCS+-SHA2-128f-simple",  SphincsSha2128fSimple,  "SLH-DSA", 1, ["slh-dsa-sha2-128f", "sphincs-sha2-128f"];
    "SPHINCS+-SHA2-128s-simple",  SphincsSha2128sSimple,  "SLH-DSA", 1, ["slh-dsa-sha2-128s", "sphincs-sha2-128s"];
    "SPHINCS+-SHA2-192f-simple",  SphincsSha2192fSimple,  "SLH-DSA", 3, ["slh-dsa-sha2-192f", "sphincs-sha2-192f"];
    "SPHINCS+-SHA2-192s-simple",  SphincsSha2192sSimple,  "SLH-DSA", 3, ["slh-dsa-sha2-192s", "sphincs-sha2-192s"];
    "SPHINCS+-SHA2-256f-simple",  SphincsSha2256fSimple,  "SLH-DSA", 5, ["slh-dsa-sha2-256f", "sphincs-sha2-256f"];
    "SPHINCS+-SHA2-256s-simple",  SphincsSha2256sSimple,  "SLH-DSA", 5, ["slh-dsa-sha2-256s", "sphincs-sha2-256s"];
    "SPHINCS+-SHAKE-128f-simple", SphincsShake128fSimple, "SLH-DSA", 1, ["slh-dsa-shake-128f", "sphincs-shake-128f"];
    "SPHINCS+-SHAKE-128s-simple", SphincsShake128sSimple, "SLH-DSA", 1, ["slh-dsa-shake-128s", "sphincs-shake-128s"];
    "SPHINCS+-SHAKE-192f-simple", SphincsShake192fSimple, "SLH-DSA", 3, ["slh-dsa-shake-192f", "sphincs-shake-192f"];
    "SPHINCS+-SHAKE-192s-simple", SphincsShake192sSimple, "SLH-DSA", 3, ["slh-dsa-shake-192s", "sphincs-shake-192s"];
    "SPHINCS+-SHAKE-256f-simple", SphincsShake256fSimple, "SLH-DSA", 5, ["slh-dsa-shake-256f", "sphincs-shake-256f"];
    "SPHINCS+-SHAKE-256s-simple", SphincsShake256sSimple, "SLH-DSA", 5, ["slh-dsa-shake-256s", "sphincs-shake-256s"];

    // Not a NIST standard yet, but selected for standardisation and useful
    // when signature size dominates.
    "Falcon-512",  Falcon512,  "Falcon", 1, [];
    "Falcon-1024", Falcon1024, "Falcon", 5, [];
}

/// The algorithm used when the user does not name one.
pub const DEFAULT_ALGORITHM: &str = "ML-DSA-65";

/// Normalise a user-supplied name: case and separators are ignored, so
/// `ml_dsa_65`, `ML-DSA-65` and `mldsa65` all match.
fn normalize(s: &str) -> String {
    s.chars()
        .filter(|c| !matches!(c, '-' | '_' | ' ' | '.' | '+'))
        .flat_map(|c| c.to_lowercase())
        .collect()
}

/// Look up an algorithm by canonical name or alias.
pub fn lookup(name: &str) -> Result<&'static AlgoInfo> {
    let wanted = normalize(name);
    let info = ALGORITHMS
        .iter()
        .find(|a| {
            normalize(a.name) == wanted || a.aliases.iter().any(|alias| normalize(alias) == wanted)
        })
        .ok_or_else(|| Error::UnknownAlgorithm(name.to_string()))?;

    if !info.oqs.is_enabled() {
        return Err(Error::AlgorithmUnavailable(info.name.to_string()));
    }
    Ok(info)
}

/// Look up an algorithm named inside a key or signature file.
///
/// Same as [`lookup`], but the error mentions the file so the user knows which
/// artefact referenced an algorithm this build cannot handle.
pub fn lookup_from_file(name: &str, path: &std::path::Path) -> Result<&'static AlgoInfo> {
    lookup(name).map_err(|e| match e {
        Error::UnknownAlgorithm(n) => {
            Error::malformed(path, format!("names an unrecognised algorithm '{n}'"))
        }
        other => other,
    })
}

/// Construct the liboqs signature scheme for this algorithm.
pub fn scheme(info: &AlgoInfo) -> Result<oqs::sig::Sig> {
    Ok(oqs::sig::Sig::new(info.oqs)?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_names_match_liboqs() {
        // If a liboqs upgrade renames an algorithm, catch it here rather than
        // by writing signature files nobody can read back.
        for info in ALGORITHMS {
            assert_eq!(
                info.name,
                info.oqs.name(),
                "canonical name drifted from liboqs"
            );
        }
    }

    #[test]
    fn names_and_aliases_are_unique() {
        let mut seen = std::collections::HashSet::new();
        for info in ALGORITHMS {
            for name in std::iter::once(info.name).chain(info.aliases.iter().copied()) {
                assert!(
                    seen.insert(normalize(name)),
                    "duplicate algorithm name: {name}"
                );
            }
        }
    }

    #[test]
    fn lookup_ignores_case_and_separators() {
        oqs::init();
        let expected = lookup("ML-DSA-65").unwrap().name;
        for spelling in ["ml-dsa-65", "MLDSA65", "ml_dsa_65", "Dilithium3", "  ", ""] {
            match lookup(spelling) {
                Ok(info) if spelling.trim().is_empty() => {
                    panic!("empty name matched {}", info.name)
                }
                Ok(info) => assert_eq!(info.name, expected),
                Err(_) => assert!(spelling.trim().is_empty()),
            }
        }
    }

    #[test]
    fn default_algorithm_is_registered() {
        oqs::init();
        assert!(lookup(DEFAULT_ALGORITHM).is_ok());
    }
}
