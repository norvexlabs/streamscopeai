//! The login flow's secrets, sealed so only this process can open them.
//!
//! An authorization-code login has to carry three values from the redirect out
//! to the callback: the CSRF `state`, the PKCE `code_verifier`, and the `nonce`
//! that binds the ID token to this login. The browser is the only thing that
//! spans both requests, so they have to ride along with it.
//!
//! They ride **sealed**. The SvelteKit layer stores the blob in its one-time
//! cookie and never sees inside, so the verifier and nonce are asserted by this
//! process to itself rather than trusted back from another tier.
//!
//! Sealing also keeps the flow **stateless**, which is a hard requirement
//! rather than an elegance: admin-api runs as several replicas behind a
//! round-robin load balancer, so `/begin` and `/callback` routinely land on
//! different processes. An in-memory store would fail whenever they didn't.

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use super::OidcError;

/// How long a started login may take to come back. Long enough for a password
/// manager, MFA prompt, and account chooser; short enough to bound replay of a
/// leaked blob.
pub const FLOW_TTL_SECS: i64 = 600;

/// Which plane the user is signing in to. A login authenticates exactly one —
/// an admin login that turns out not to be a console account is denied rather
/// than silently downgraded into a portal session.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Plane {
    Admin,
    Portal,
}

/// The sealed contents of an in-flight login.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FlowState {
    /// Schema version, so a blob minted by an older build is rejected cleanly
    /// rather than deserializing into something subtly wrong.
    pub v: u8,
    pub state: String,
    pub code_verifier: String,
    pub nonce: String,
    pub tenant_id: Uuid,
    pub tenant_slug: String,
    /// The issuer in force when the flow began. Re-read at the callback so a
    /// tenant that is reconfigured mid-login cannot have an in-flight token
    /// verified against a different provider than the one it came from.
    pub issuer: String,
    pub plane: Plane,
    /// Pinned rather than recomputed: the token exchange must present exactly
    /// the redirect URI the authorization request carried, and origin settings
    /// can change between the two halves.
    pub redirect_uri: String,
    pub return_to: Option<String>,
    pub exp: i64,
}

const FLOW_SCHEMA_VERSION: u8 = 1;

impl FlowState {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        state: String,
        code_verifier: String,
        nonce: String,
        tenant_id: Uuid,
        tenant_slug: String,
        issuer: String,
        plane: Plane,
        redirect_uri: String,
        return_to: Option<String>,
        now: i64,
    ) -> Self {
        Self {
            v: FLOW_SCHEMA_VERSION,
            state,
            code_verifier,
            nonce,
            tenant_id,
            tenant_slug,
            issuer,
            plane,
            redirect_uri,
            return_to,
            exp: now + FLOW_TTL_SECS,
        }
    }
}

/// Seal a flow into an opaque token.
///
/// AES-256-GCM under the deployment's `ENCRYPTION_KEY` — the same primitive
/// that protects the stored OIDC client secret. Authenticated, so a tampered
/// blob fails to open rather than yielding attacker-chosen contents.
pub fn seal(flow: &FlowState) -> Result<String, OidcError> {
    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or(OidcError::EncryptionUnavailable)?;
    let json = serde_json::to_string(flow).map_err(|e| OidcError::Flow(e.to_string()))?;
    streamscope_core::crypto::encrypt(&json, &key).map_err(|e| OidcError::Flow(e.to_string()))
}

/// Open a sealed flow, rejecting anything tampered, stale, or from another
/// schema version.
///
/// `now` is passed in rather than read here so expiry is testable without
/// waiting.
pub fn open(token: &str, now: i64) -> Result<FlowState, OidcError> {
    let key = streamscope_core::crypto::get_encryption_key()
        .ok_or(OidcError::EncryptionUnavailable)?;
    let json = streamscope_core::crypto::decrypt(token, &key)
        .map_err(|_| OidcError::Flow("login state could not be opened".into()))?;
    let flow: FlowState = serde_json::from_str(&json)
        .map_err(|_| OidcError::Flow("login state is malformed".into()))?;

    if flow.v != FLOW_SCHEMA_VERSION {
        return Err(OidcError::Flow("login state is from an incompatible version".into()));
    }
    if now > flow.exp {
        return Err(OidcError::Flow("login took too long — start again".into()));
    }
    Ok(flow)
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn with_key<R>(f: impl FnOnce() -> R) -> R {
        // SAFETY: every writer in this test binary stores this same value and
        // all env access here goes through Rust std (no FFI readers), so the
        // hazard `set_var` guards against cannot arise. Mirrors the
        // `ENCRYPTION_KEY` setters in `streamscope-core`.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-oidc-flow-key-long-enough");
        }
        f()
    }

    fn sample(now: i64) -> FlowState {
        FlowState::new(
            "state-abc".into(),
            "verifier-xyz".into(),
            "nonce-123".into(),
            Uuid::nil(),
            "acme".into(),
            "https://idp.example.test".into(),
            Plane::Portal,
            "https://gw.example.test/auth/oidc/callback".into(),
            Some("/portal/t/acme/mcp".into()),
            now,
        )
    }

    #[test]
    fn round_trips_every_field() {
        with_key(|| {
            let flow = sample(1_000);
            let opened = open(&seal(&flow).expect("seals"), 1_000).expect("opens");
            assert_eq!(opened.state, flow.state);
            assert_eq!(opened.code_verifier, flow.code_verifier);
            assert_eq!(opened.nonce, flow.nonce);
            assert_eq!(opened.tenant_id, flow.tenant_id);
            assert_eq!(opened.tenant_slug, flow.tenant_slug);
            assert_eq!(opened.issuer, flow.issuer);
            assert_eq!(opened.plane, Plane::Portal);
            assert_eq!(opened.redirect_uri, flow.redirect_uri);
            assert_eq!(opened.return_to, flow.return_to);
        });
    }

    /// The token is opaque to whoever carries it — the verifier and nonce must
    /// not be readable from the blob, or sealing buys nothing over a plain
    /// cookie.
    #[test]
    fn sealed_token_reveals_nothing() {
        with_key(|| {
            let sealed = seal(&sample(1_000)).expect("seals");
            for secret in ["verifier-xyz", "nonce-123", "state-abc", "acme"] {
                assert!(!sealed.contains(secret), "{secret} leaked into {sealed}");
            }
        });
    }

    #[test]
    fn expired_flow_is_refused() {
        with_key(|| {
            let sealed = seal(&sample(1_000)).expect("seals");
            assert!(open(&sealed, 1_000 + FLOW_TTL_SECS).is_ok(), "exactly at expiry still opens");
            assert_matches!(
                open(&sealed, 1_000 + FLOW_TTL_SECS + 1),
                Err(OidcError::Flow(_))
            );
        });
    }

    /// Authenticated encryption: a blob whose ciphertext was edited must fail
    /// to open rather than produce attacker-influenced contents.
    #[test]
    fn tampered_token_is_refused() {
        with_key(|| {
            let sealed = seal(&sample(1_000)).expect("seals");
            let mut bytes = sealed.clone().into_bytes();
            let last = bytes.len() - 1;
            bytes[last] = if bytes[last] == b'A' { b'B' } else { b'A' };
            let tampered = String::from_utf8(bytes).expect("still utf8");
            assert_matches!(open(&tampered, 1_000), Err(OidcError::Flow(_)));
        });
    }

    #[test]
    fn garbage_is_refused() {
        with_key(|| {
            for token in ["", "not-base64!!", "aGVsbG8="] {
                assert_matches!(open(token, 1_000), Err(OidcError::Flow(_)));
            }
        });
    }

    /// A blob from a future schema must be refused outright rather than
    /// deserialized into a shape this build would misread.
    #[test]
    fn foreign_schema_version_is_refused() {
        with_key(|| {
            let mut flow = sample(1_000);
            flow.v = FLOW_SCHEMA_VERSION + 1;
            let sealed = seal(&flow).expect("seals");
            assert_matches!(open(&sealed, 1_000), Err(OidcError::Flow(_)));
        });
    }

    #[test]
    fn plane_survives_the_round_trip() {
        with_key(|| {
            let mut flow = sample(1_000);
            flow.plane = Plane::Admin;
            let opened = open(&seal(&flow).expect("seals"), 1_000).expect("opens");
            assert_eq!(opened.plane, Plane::Admin);
        });
    }
}
