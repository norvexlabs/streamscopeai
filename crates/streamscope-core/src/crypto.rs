//! Credential encryption at rest — AES-256-GCM with HKDF-SHA256 key derivation.
//!
//! All upstream API keys and agent credentials are encrypted before storage.
//! The encryption key is derived from `ENCRYPTION_KEY` env var using HKDF with
//! domain separation (`"streamscope-v2"`). Both proxy and admin-api refuse to
//! start without this key. Ciphertext format: `base64(12-byte nonce || ciphertext)`.

use aes_gcm::{
    aead::{Aead, Generate, KeyInit, Nonce},
    Aes256Gcm,
};
use hkdf::Hkdf;
use sha2::Sha256;

/// Derive a 256-bit encryption key from a passphrase using HKDF-SHA256.
/// Uses a fixed info string for deterministic derivation.
pub fn derive_key(secret: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, secret.as_bytes());
    let mut okm = [0u8; 32];
    hk.expand(b"streamscope-v2", &mut okm)
        .expect("HKDF expand: 32 bytes is always valid for SHA-256");
    okm
}

/// Encrypt plaintext with AES-256-GCM. Returns base64(nonce || ciphertext).
pub fn encrypt(plaintext: &str, key: &[u8; 32]) -> Result<String, String> {
    use base64::Engine;
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::<Aes256Gcm>::try_generate().map_err(|e| format!("nonce generation failed: {e}"))?;
    let ciphertext = cipher
        .encrypt(&nonce, plaintext.as_bytes())
        .map_err(|e| format!("encryption failed: {e}"))?;

    let mut combined = nonce.to_vec();
    combined.extend_from_slice(&ciphertext);
    Ok(base64::engine::general_purpose::STANDARD.encode(&combined))
}

/// Decrypt base64(nonce || ciphertext) with AES-256-GCM. Returns plaintext.
pub fn decrypt(encoded: &str, key: &[u8; 32]) -> Result<String, String> {
    use base64::Engine;
    let combined = base64::engine::general_purpose::STANDARD
        .decode(encoded)
        .map_err(|e| format!("base64 decode failed: {e}"))?;

    if combined.len() < 12 {
        return Err("ciphertext too short".to_string());
    }

    let (nonce_bytes, ciphertext) = combined.split_at(12);
    let nonce = Nonce::<Aes256Gcm>::try_from(nonce_bytes).map_err(|_| "ciphertext too short".to_string())?;
    let cipher = Aes256Gcm::new(key.into());
    let plaintext = cipher
        .decrypt(&nonce, ciphertext)
        .map_err(|e| format!("decryption failed: {e}"))?;

    String::from_utf8(plaintext).map_err(|e| format!("invalid UTF-8: {e}"))
}

/// Cached encryption key — derived once from ENCRYPTION_KEY env var at first access.
static ENCRYPTION_KEY: std::sync::OnceLock<Option<[u8; 32]>> = std::sync::OnceLock::new();

/// Get encryption key from ENCRYPTION_KEY env var. Derived once and cached for process lifetime.
pub fn get_encryption_key() -> Option<[u8; 32]> {
    *ENCRYPTION_KEY.get_or_init(|| {
        match std::env::var("ENCRYPTION_KEY") {
            Ok(secret) if !secret.is_empty() => Some(derive_key(&secret)),
            _ => {
                tracing::warn!("ENCRYPTION_KEY not set — API key encryption disabled");
                None
            }
        }
    })
}

/// Validate that ENCRYPTION_KEY is set. Call at startup to fail fast.
/// Returns the derived key or an error message.
pub fn require_encryption_key() -> Result<[u8; 32], String> {
    get_encryption_key().ok_or_else(|| {
        "ENCRYPTION_KEY environment variable is required but not set. \
         Set it to a strong secret (32+ chars) for encrypting upstream credentials."
            .to_string()
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = derive_key("test-secret-key");
        let plaintext = "sk-proj-abc123xyz";
        let encrypted = encrypt(plaintext, &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    /// Stored credentials outlive the cipher library: a ciphertext written by
    /// an independent AES-256-GCM implementation (nonce, ciphertext, tag) under
    /// the HKDF key decrypts, and the key derivation gives the same bytes.
    #[test]
    fn a_ciphertext_from_another_implementation_decrypts() {
        let key = derive_key("known-answer-secret");
        assert_eq!(hex::encode(key), "153419819c2f64f406c20cf2946ffeaf382e70a8c622b384237ba60ae65fe909");
        let stored = "AAECAwQFBgcICQoLxkOQaq1m3DSln3TgHRa6cfZuDBPGN0VSZyRtpyp/ZdfY2nS9";
        assert_eq!(decrypt(stored, &key).unwrap(), "sk-known-answer-0123");
    }

    #[test]
    fn wrong_key_fails() {
        let key1 = derive_key("key-one");
        let key2 = derive_key("key-two");
        let encrypted = encrypt("secret", &key1).unwrap();
        assert!(decrypt(&encrypted, &key2).is_err());
    }

    #[test]
    fn empty_plaintext() {
        let key = derive_key("test-key");
        let encrypted = encrypt("", &key).unwrap();
        let decrypted = decrypt(&encrypted, &key).unwrap();
        assert_eq!(decrypted, "");
    }

    #[test]
    fn short_ciphertext_fails() {
        let key = derive_key("test-key");
        assert!(decrypt("dG9vc2hvcnQ=", &key).is_err()); // "tooshort" base64
    }

    #[test]
    fn each_encryption_produces_unique_output() {
        let key = derive_key("test-key");
        let plaintext = "same-input";
        let enc1 = encrypt(plaintext, &key).unwrap();
        let enc2 = encrypt(plaintext, &key).unwrap();
        // Different nonces → different ciphertexts.
        assert_ne!(enc1, enc2);
        // Both decrypt to same plaintext.
        assert_eq!(decrypt(&enc1, &key).unwrap(), plaintext);
        assert_eq!(decrypt(&enc2, &key).unwrap(), plaintext);
    }
}
