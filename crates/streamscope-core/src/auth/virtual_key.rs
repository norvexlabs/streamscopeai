//! Virtual key lifecycle — generation and hashing.
//!
//! `sk-*` keys are proxy-issued identity tokens backed by upstream credentials
//! the proxy holds. `vk-*` keys are BYOK identity tokens where the client
//! provides its own upstream credential in the auth header. A single key spans
//! both LLM (`/v1/*`, `/mcp/<slug>`) and MCP protocols — the route grammar
//! implies the protocol and the key's workspace allowlist gates the target.
//!
//! Authentication ([`super::authenticate`]) resolves the key hash against the
//! published configuration — no database round-trip on the hot path.

use rand::Rng;
use sha2::{Digest, Sha256};


/// Generate a new virtual API key: `sk-<base58(32 random bytes)>` (256-bit entropy).
pub fn generate_virtual_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("sk-{}", bs58::encode(bytes).into_string())
}

/// Generate a forward-auth key for BYOK: `vk-<base58(32 random bytes)>` (256-bit entropy).
///
/// These keys are identity tokens embedded in URLs (`/fwd/{key}/v1/...`).
/// The real upstream credential is the client's own API key in the auth header.
pub fn generate_forward_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("vk-{}", bs58::encode(bytes).into_string())
}

/// Generate a long-lived admin-API automation key: `ak-<base58(32 random bytes)>`
/// (256-bit entropy).
///
/// `ak-*` keys authenticate to the control plane (`/api/v1/admin/*`), never the
/// proxy data plane — they're resolved by the admin auth path against the
/// dedicated `automation_keys` table, never `api_keys` and never the proxy's
/// configuration.
pub fn generate_admin_key() -> String {
    let mut bytes = [0u8; 32];
    rand::rng().fill_bytes(&mut bytes);
    format!("ak-{}", bs58::encode(bytes).into_string())
}

/// The sha256 of a key, hex — what the database stores and a config body carries.
pub fn hash_key(key: &str) -> String {
    hex::encode(key_digest(key))
}

/// The sha256 of a key, raw — what the gateway's configuration indexes keys by.
pub fn key_digest(key: &str) -> [u8; 32] {
    Sha256::digest(key.as_bytes()).into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_generate_key_format() {
        let key = generate_virtual_key();
        assert!(key.starts_with("sk-"));
        assert!(key.len() > 5);
    }

    #[test]
    fn test_generate_forward_key_format() {
        let key = generate_forward_key();
        assert!(key.starts_with("vk-"));
        assert!(key.len() > 5);
        // Must be different from sk- keys
        assert!(!key.starts_with("sk-"));
    }

    #[test]
    fn test_generate_admin_key_format() {
        let key = generate_admin_key();
        assert!(key.starts_with("ak-"));
        assert!(key.len() > 5);
        // Must be distinct from the data-plane key families.
        assert!(!key.starts_with("sk-"));
        assert!(!key.starts_with("vk-"));
    }

    #[test]
    fn test_hash_deterministic() {
        let key = "sk-test123";
        let h1 = hash_key(key);
        let h2 = hash_key(key);
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // sha256 hex
    }
}
