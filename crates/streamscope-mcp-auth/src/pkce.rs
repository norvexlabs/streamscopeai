//! PKCE (RFC 7636) S256 helpers.
//!
//! Verifier shape: 32 random bytes → base64url-no-pad (43 chars). Challenge:
//! `base64url-no-pad(SHA256(verifier))`. Verify: recompute challenge from the
//! supplied verifier and compare against the stored value with a constant-time
//! comparator.
//!
//! The method is fixed to S256 — `plain` is rejected at the /authorize
//! and /token endpoints. The constant-time check protects against trivial
//! timing oracles even though the challenge is not strictly secret (it is
//! transmitted to us at /authorize). It costs nothing.

use base64::Engine;
use rand::Rng;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

const VERIFIER_BYTES: usize = 32;

/// Generate a fresh PKCE code verifier — 32 random bytes, base64url no-pad.
///
/// The string is opaque (43 chars from a 64-char alphabet) and must be stored
/// privately on the client side until the token exchange.
pub fn generate_code_verifier() -> String {
    let mut bytes = [0u8; VERIFIER_BYTES];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

/// Derive the S256 challenge for a given verifier: `base64url(sha256(verifier))`.
///
/// This is what the client sends in the /authorize request. We recompute it
/// from the supplied verifier at /token to verify the exchange.
pub fn derive_s256_challenge(verifier: &str) -> String {
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

/// Verify a verifier against a stored challenge with a constant-time compare.
pub fn verify_s256_challenge(verifier: &str, expected_challenge: &str) -> bool {
    let derived = derive_s256_challenge(verifier);
    // `ct_eq` on slices short-circuits on a length mismatch and is constant
    // time over the contents otherwise. Length is not secret here — both sides
    // are base64 of a SHA-256 — so that short-circuit leaks nothing.
    derived
        .as_bytes()
        .ct_eq(expected_challenge.as_bytes())
        .into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn verifier_is_43_chars_url_safe() {
        let v = generate_code_verifier();
        assert_eq!(v.len(), 43);
        for c in v.chars() {
            assert!(
                c.is_ascii_alphanumeric() || c == '-' || c == '_',
                "non-url-safe char in verifier: {c:?}"
            );
        }
    }

    #[test]
    fn challenge_matches_verifier() {
        let v = generate_code_verifier();
        let c = derive_s256_challenge(&v);
        assert!(verify_s256_challenge(&v, &c));
    }

    #[test]
    fn challenge_mismatch_rejected() {
        let v1 = generate_code_verifier();
        let v2 = generate_code_verifier();
        assert_ne!(v1, v2);
        let c1 = derive_s256_challenge(&v1);
        assert!(!verify_s256_challenge(&v2, &c1));
    }

    /// Vector from RFC 7636 §A.1.
    #[test]
    fn rfc7636_vector() {
        let v = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        let c = derive_s256_challenge(v);
        assert_eq!(c, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
    }
}
