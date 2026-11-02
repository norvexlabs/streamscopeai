//! MCP access-token issuance + validation, signed with the per-tenant key the
//! [`keys`](crate::keys) ring derives.
//!
//! Algorithm: **ES256**, over the per-tenant P-256 key the ring derives. This
//! is the one surface whose tokens leave for a party that may want to check
//! them without asking us, so it is the one surface that signs asymmetrically:
//! the matching public key is published as a JWK set at the authorization
//! server's `jwks_uri`, and a holder can verify locally against it. Every other
//! streamscope-issued JWT — console session, portal session, CLI access, and
//! both surfaces' refresh tokens — stays HS256, because nothing outside this
//! deployment ever verifies one, and a published key for them would describe a
//! capability no client has.
//!
//! The validator does NOT consult the database; revocation is checked
//! separately by the caller against the per-tenant config snapshot of revoked
//! `jti`s pushed by config_sync. That keeps the hot validation path
//! allocation-free and DB-free.

use jsonwebtoken::{decode, encode, Algorithm, Validation};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;

use crate::keys::{self, KeyError, Keyring};

/// `typ` claim value on a proxy-issued MCP **access** token.
///
/// Access and refresh tokens are JWTs signed with the same per-tenant key and
/// the refresh shape is a structural superset of the access shape, so without
/// an explicit type claim a 30-day refresh token would validate as an access
/// bearer. [`encode_access_token`] stamps this value and [`decode_and_verify`]
/// rejects any token whose `typ` is not exactly this — refresh tokens carry
/// `typ = "refresh"` and are refused.
pub const ACCESS_TOKEN_TYP: &str = "access";

/// `iss` claim value on every streamscope-issued JWT, on all five surfaces.
///
/// **Deliberate deviation from RFC 9068**, which would want the authorization
/// server's issuer URL. That URL is per-tenant and origin-derived, so pinning
/// it in the token would force a tenant → slug → origin resolution on every
/// verification — including the proxy's DB-free MCP hot path, and including
/// console and portal sessions, which are not OAuth tokens at all. The
/// RFC-observable issuer already reaches clients where they read it: the
/// discovery documents and the RFC 9207 `iss` authorization-response
/// parameter. Pinning one constant here keeps `iss` a *verified* claim on
/// every surface rather than a decorative one.
pub const TOKEN_ISSUER: &str = "streamscope";

/// `surface` claim value on MCP OAuth tokens (access and refresh alike).
pub const SURFACE_MCP: &str = "mcp";

/// `surface` claim value on CLI OAuth refresh tokens.
pub const SURFACE_CLI: &str = "cli";

/// JWT claim shape for proxy-issued MCP access tokens.
///
/// * `sub` — UUID of the `users` row (auto-provisioned on first issuance).
/// * `aud` — canonical resource URI of the bound virtual server
///   (`{public_origin}/mcp/{slug}`). The MCP handler rejects with `-32401`
///   when the request slug doesn't resolve to this URI — the RFC 8707
///   audience-binding guarantee.
/// * `tenant_id` — duplicate of the routing tenant; lets the validator pick
///   the right per-tenant key without DB lookup.
/// * `workspace_id` — the workspace through which the subject reaches the bound
///   virtual server. The validator binds the minted `UserContext` to this
///   workspace, so MCP usage on the token counts against that workspace's
///   budget / rate bucket and audit rows carry it. Resolved at mint time (the
///   most specific workspace granting the user access to the server), so the
///   claim — not a re-derivation at validation — is the source of truth.
/// * `virtual_server_id` — the MCP virtual server this token was minted for.
///   The `aud` names the server by *slug*, and a slug is reusable: delete a
///   virtual server and its issued-token rows cascade away with it, so a
///   recreated server with the same slug would inherit every bearer still
///   matching that audience, with nothing left in the revoked set to stop them.
///   The id does not come back, so binding to it is what makes a token die
///   with the server it was issued against. It is also what makes the
///   workspace allowlist real on this path: that list MUST be built from this
///   claim, because one synthesized from the requested slug would be compared
///   against the very slug it came from.
/// * `client_id` — the registered `mcp_oauth_clients.client_id`. Used by the
///   rate limiter and audit row.
/// * `scope` — single implicit scope `mcp:invoke`.
/// * `jti` — token identifier. The validator looks up this value in the
///   tenant's revoked-jti set; revoked tokens are rejected.
/// * `typ` — token type, always [`ACCESS_TOKEN_TYP`]. Distinguishes an access
///   token from a same-key-signed refresh token (`typ = "refresh"`).
/// * `surface` — the OAuth surface that minted this token, always
///   [`SURFACE_MCP`]. Keeps an MCP token and a CLI token apart structurally:
///   both are signed with the same per-tenant key, so nothing else in the
///   payload prevents one being presented where the other belongs.
/// * `iss` — always [`TOKEN_ISSUER`].
/// * `nbf` — equal to `iat`. Verified, and required: `validate_nbf` alone is a
///   no-op on a token that simply omits the claim.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAccessClaims {
    pub sub: String,
    pub aud: String,
    pub iss: String,
    pub tenant_id: String,
    pub workspace_id: String,
    pub virtual_server_id: String,
    pub client_id: String,
    pub scope: String,
    pub jti: String,
    pub typ: String,
    pub surface: String,
    pub iat: i64,
    pub nbf: i64,
    pub exp: i64,
}

#[derive(Debug, Error)]
pub enum McpJwtError {
    #[error("{0}")]
    Key(#[from] KeyError),
    #[error("invalid signature or claims")]
    InvalidSignature,
    #[error("token expired")]
    Expired,
    #[error("wrong token type (expected an access token)")]
    WrongTokenType,
    #[error("wrong OAuth surface (expected an MCP token)")]
    WrongSurface,
    #[error("wrong issuer")]
    WrongIssuer,
    #[error("encoding error")]
    Encode,
}

/// Encode an MCP access token, labelled with the `kid` of the key that signed
/// it so a verifier can pick the same one after a secret rotation.
pub fn encode_access_token(
    claims: &McpAccessClaims,
    ring: &Keyring,
) -> Result<String, McpJwtError> {
    // Fail loud rather than mint a token `decode_and_verify` would refuse.
    if claims.typ != ACCESS_TOKEN_TYP {
        return Err(McpJwtError::WrongTokenType);
    }
    if claims.surface != SURFACE_MCP {
        return Err(McpJwtError::WrongSurface);
    }
    if claims.iss != TOKEN_ISSUER {
        return Err(McpJwtError::WrongIssuer);
    }
    let (header, key) = ring.es256_signing_header(&claims.tenant_id);
    encode(&header, claims, &key).map_err(|e| {
        tracing::error!("mcp jwt encode: {e}");
        McpJwtError::Encode
    })
}

/// The `Validation` every MCP access token is checked against.
///
/// Extracted so a test can drive it with a claim shape whose `nbf` is absent:
/// on [`McpAccessClaims`] that field is mandatory, so serde would do the
/// rejecting and the `nbf` entry in the required set could be deleted without
/// any test noticing. Each of the workspace's validation builders keeps its own
/// list, so isolating one says nothing about the others.
///
/// Audience matching is disabled here and done by the caller against the routed
/// virtual server, so the error code is precise (`-32401` audience mismatch vs.
/// generic signature failure).
fn access_token_validation() -> Validation {
    // Pinned to ES256. `jsonwebtoken` refuses a token whose header algorithm is
    // not in this set, which is what closes the substitution attack a published
    // key set invites: without the pin, an attacker could present an HS256
    // token signed with our own **public** key as its HMAC secret — the key is
    // public precisely so that everyone has it.
    let mut validation = Validation::new(Algorithm::ES256);
    validation.validate_aud = false;
    validation.validate_nbf = true;
    validation.set_required_spec_claims(&["exp", "iat", "nbf", "iss", "sub"]);
    validation.set_issuer(&[TOKEN_ISSUER]);
    validation
}

/// Verify an MCP access token and return its claims. The caller MUST also:
///   * confirm the `aud` matches the request's resource URI (RFC 8707), and
///   * confirm the `jti` isn't in the per-tenant revoked-jti set.
///
/// The signing key comes from the token's `kid` header, so a token minted
/// under a rotated-out `AUTH_SECRET_SECONDARY` still verifies while it lives.
pub fn decode_and_verify(
    token: &str,
    ring: &Keyring,
) -> Result<McpAccessClaims, McpJwtError> {
    let (kid_tenant, key) = keys::es256_verification_key_for(token, ring)?;
    decode_and_verify_with_key(token, &kid_tenant, &key)
}

/// Verify an MCP access token against a key the caller already resolved.
///
/// This is the entry point for a verifier that has no signing ring — the proxy,
/// which holds no `AUTH_SECRET` and takes the tenant's public keys off its
/// config snapshot. [`decode_and_verify`] is the same check with the key looked
/// up from a ring instead.
///
/// `kid_tenant` MUST be the tenant named by the **token's own `kid`**, i.e. the
/// label that selected `key`. The equality check below is what binds the two:
/// a caller that passed some other tenant here — the one it wishes the token
/// belonged to, say — would disable the check rather than fail it.
///
/// **Callers that select the key by `kid` are trusting an attacker-supplied
/// label to reach for a key, and that is safe only because of that check.** A
/// mismatched `kid` selects a key that cannot verify the signature; a matching
/// one proves the payload agrees with the label. Anything a caller does with
/// `kid_tenant` *before* this returns — loading tenant config, for instance —
/// is acting on an unverified value and must not be a side effect that outlives
/// a rejection.
pub fn decode_and_verify_with_key(
    token: &str,
    kid_tenant: &str,
    key: &jsonwebtoken::DecodingKey,
) -> Result<McpAccessClaims, McpJwtError> {
    let data = decode::<McpAccessClaims>(token, key, &access_token_validation())
    .map_err(|e| match *e.kind() {
            jsonwebtoken::errors::ErrorKind::ExpiredSignature => McpJwtError::Expired,
            _ => McpJwtError::InvalidSignature,
        })?;

    // The `kid` picked the key but is attacker-supplied, so the verified
    // payload must name the same tenant — otherwise a token could be re-pointed
    // at another tenant's config while still validating under its own key.
    if data.claims.tenant_id != kid_tenant {
        return Err(McpJwtError::InvalidSignature);
    }

    // Token-type binding: access and refresh tokens are signed with the same
    // per-tenant key and the refresh shape is a superset of this one, so a
    // refresh token deserializes cleanly into `McpAccessClaims`. Reject
    // anything that isn't an access token — without this a 30-day refresh
    // token would be usable as an access bearer.
    if data.claims.typ != ACCESS_TOKEN_TYP {
        return Err(McpJwtError::WrongTokenType);
    }
    if data.claims.surface != SURFACE_MCP {
        return Err(McpJwtError::WrongSurface);
    }

    Ok(data.claims)
}

/// Generate a fresh `jti` (UUIDv4 stringified).
pub fn new_jti() -> String {
    Uuid::new_v4().to_string()
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::Engine;
    use jsonwebtoken::{DecodingKey, EncodingKey};
    use std::assert_matches;

    const SECRET: &str = "very-secret-test-only-at-least-32-chars";
    const OLD_SECRET: &str = "outgoing-secret-test-only-32-chars-min";

    fn ring() -> Keyring {
        Keyring::new(SECRET, None).expect("ring")
    }

    fn fixture_claims(tenant: &str, aud: &str) -> McpAccessClaims {
        let now = chrono::Utc::now();
        McpAccessClaims {
            sub: Uuid::new_v4().to_string(),
            aud: aud.to_string(),
            iss: TOKEN_ISSUER.to_string(),
            tenant_id: tenant.to_string(),
            workspace_id: Uuid::new_v4().to_string(),
            virtual_server_id: Uuid::new_v4().to_string(),
            client_id: "test-client".to_string(),
            scope: "mcp:invoke".to_string(),
            jti: new_jti(),
            typ: ACCESS_TOKEN_TYP.to_string(),
            surface: SURFACE_MCP.to_string(),
            iat: now.timestamp(),
            nbf: now.timestamp(),
            exp: (now + chrono::Duration::hours(1)).timestamp(),
        }
    }

    /// Re-encode a token's payload under the same key, so a single claim can be
    /// altered without the signature going stale.
    fn resign_with_payload(tenant: &str, ring: &Keyring, payload: serde_json::Value) -> String {
        let (header, key) = ring.es256_signing_header(tenant);
        encode(&header, &payload, &key).expect("encode")
    }

    #[test]
    fn round_trip_succeeds() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/tools");
        let token = encode_access_token(&claims, &ring).unwrap();
        let parsed = decode_and_verify(&token, &ring).unwrap();
        assert_eq!(parsed.sub, claims.sub);
        assert_eq!(parsed.tenant_id, claims.tenant_id);
        assert_eq!(parsed.aud, claims.aud);
        assert_eq!(parsed.client_id, claims.client_id);
        assert_eq!(parsed.jti, claims.jti);
    }

    /// A token minted before `AUTH_SECRET` rotated must keep working while its
    /// secondary generation is still on the ring — that overlap is the whole point of
    /// naming the generation in `kid`.
    #[test]
    fn a_token_from_the_secondary_generation_still_verifies() {
        let old_ring = Keyring::new(OLD_SECRET, None).expect("ring");
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let token = encode_access_token(&claims, &old_ring).unwrap();

        // Rotated: the old secret verifies, the new one signs.
        let rotated = Keyring::new(SECRET, Some(OLD_SECRET)).expect("ring");
        assert_eq!(decode_and_verify(&token, &rotated).unwrap().jti, claims.jti);

        // Once the secondary generation is dropped, the same token stops verifying.
        assert_matches!(
            decode_and_verify(&token, &ring()).unwrap_err(),
            McpJwtError::Key(KeyError::UnknownGeneration)
        );
    }

    #[test]
    fn a_token_with_no_kid_is_rejected() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let (_, key) = ring.es256_signing_header("acme");
        let token = encode(
            &jsonwebtoken::Header::new(Algorithm::ES256),
            &claims,
            &key,
        )
        .unwrap();
        assert_matches!(
            decode_and_verify(&token, &ring).unwrap_err(),
            McpJwtError::Key(KeyError::MissingKid)
        );
    }

    /// The attack a published key set invites, and the reason
    /// `access_token_validation` pins the algorithm.
    ///
    /// Our verification key is public by design. An attacker who takes it and
    /// signs an HS256 token with it as the HMAC secret produces something a
    /// naive verifier — one that reads `alg` from the header and picks the
    /// matching primitive — accepts as ours. The token here is otherwise
    /// entirely well-formed: right `kid`, right tenant, right claims.
    ///
    /// The pin is partly structural: `jsonwebtoken` refuses a `Validation`
    /// whose `algorithms` mix families, so the widening that would open this
    /// hole cannot be made by accident — it fails every ES256 token at once,
    /// loudly. This asserts the outcome regardless, because that is a property
    /// of the crate rather than of our code, and the crate can change.
    #[test]
    fn a_token_signed_with_our_public_key_as_an_hmac_secret_is_rejected() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let jwk = ring.public_jwks("acme").into_iter().next().expect("a key");

        // The forger's material: exactly what the key set publishes.
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let mut public_point = vec![0x04u8];
        public_point.extend_from_slice(&b64.decode(&jwk.x).expect("x"));
        public_point.extend_from_slice(&b64.decode(&jwk.y).expect("y"));

        let forged = encode(
            &jsonwebtoken::Header {
                kid: Some(jwk.kid.clone()),
                ..jsonwebtoken::Header::new(Algorithm::HS256)
            },
            &claims,
            &EncodingKey::from_secret(&public_point),
        )
        .expect("forge");

        assert_matches!(
            decode_and_verify(&forged, &ring).unwrap_err(),
            McpJwtError::InvalidSignature
        );
    }

    /// A holder of the published key set must be able to verify a real token
    /// with nothing else — that is the entire point of publishing one. This
    /// verifies through the JWK's own coordinates rather than through the ring,
    /// so it fails if what we publish is not what we sign with.
    #[test]
    fn the_published_jwk_verifies_a_real_token() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let token = encode_access_token(&claims, &ring).expect("encode");

        let jwk = ring
            .public_jwks("acme")
            .into_iter()
            .find(|k| Some(&k.kid) == jsonwebtoken::decode_header(&token).expect("header").kid.as_ref())
            .expect("the key set names the token's kid");
        assert_eq!(jwk.kty, "EC");
        assert_eq!(jwk.crv, "P-256");
        assert_eq!(jwk.alg, "ES256");

        let key = DecodingKey::from_ec_components(&jwk.x, &jwk.y).expect("jwk");
        let decoded = decode::<McpAccessClaims>(&token, &key, &access_token_validation())
            .expect("verifies under the published key");
        assert_eq!(decoded.claims.jti, claims.jti);
    }

    /// A tenant's published key must not verify another tenant's token, or the
    /// per-tenant derivation buys nothing on this surface.
    #[test]
    fn one_tenants_published_key_does_not_verify_anothers_token() {
        let ring = ring();
        let token =
            encode_access_token(&fixture_claims("acme", "https://example.com/mcp/a"), &ring)
                .expect("encode");
        let other = ring.public_jwks("globex").into_iter().next().expect("a key");
        let key = DecodingKey::from_ec_components(&other.x, &other.y).expect("jwk");
        assert!(decode::<McpAccessClaims>(&token, &key, &access_token_validation()).is_err());
    }

    #[test]
    fn cross_tenant_token_rejected() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let token = encode_access_token(&claims, &ring).unwrap();

        // Tampered: change tenant_id in the payload but reuse the header and
        // signature. The `kid` still names `acme`, so the key that verifies is
        // acme's — and it no longer matches this payload.
        let parts: Vec<&str> = token.split('.').collect();
        let mut payload: serde_json::Value = serde_json::from_slice(
            &base64::engine::general_purpose::URL_SAFE_NO_PAD
                .decode(parts[1])
                .unwrap(),
        )
        .unwrap();
        payload["tenant_id"] = serde_json::Value::String("other".to_string());
        let new_payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(serde_json::to_vec(&payload).unwrap());
        let tampered = format!("{}.{}.{}", parts[0], new_payload, parts[2]);

        let err = decode_and_verify(&tampered, &ring).unwrap_err();
        assert_matches!(err, McpJwtError::InvalidSignature);
    }

    /// A validly-signed token whose `kid` names one tenant and whose payload
    /// names another would run under the wrong tenant's config.
    #[test]
    fn a_kid_that_disagrees_with_the_payload_is_rejected() {
        let ring = ring();
        let mut claims = fixture_claims("acme", "https://example.com/mcp/a");
        claims.tenant_id = "other".to_string();
        let token = resign_with_payload(
            "acme",
            &ring,
            serde_json::to_value(&claims).expect("claims"),
        );
        assert_matches!(
            decode_and_verify(&token, &ring).unwrap_err(),
            McpJwtError::InvalidSignature
        );
    }

    #[test]
    fn expired_rejected() {
        let ring = ring();
        let mut claims = fixture_claims("acme", "https://example.com/mcp/a");
        let now = chrono::Utc::now();
        claims.iat = (now - chrono::Duration::hours(2)).timestamp();
        claims.nbf = claims.iat;
        claims.exp = (now - chrono::Duration::hours(1)).timestamp();
        let token = encode_access_token(&claims, &ring).unwrap();
        let err = decode_and_verify(&token, &ring).unwrap_err();
        assert_matches!(err, McpJwtError::Expired);
    }

    #[test]
    fn a_token_not_yet_valid_is_rejected() {
        let ring = ring();
        let mut claims = fixture_claims("acme", "https://example.com/mcp/a");
        let now = chrono::Utc::now();
        claims.nbf = (now + chrono::Duration::hours(1)).timestamp();
        let token = encode_access_token(&claims, &ring).unwrap();
        assert_matches!(
            decode_and_verify(&token, &ring).unwrap_err(),
            McpJwtError::InvalidSignature
        );
    }

    /// A token with no `nbf` is refused. Two mechanisms reach that outcome —
    /// `McpAccessClaims.nbf` is a mandatory serde field, and `nbf` is in the
    /// required spec claims — so this asserts the outcome, not either one.
    /// `the_required_claims_refuse_a_token_with_no_nbf` isolates the second.
    #[test]
    fn a_token_with_no_nbf_is_rejected() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let mut payload = serde_json::to_value(&claims).expect("claims");
        payload.as_object_mut().expect("object").remove("nbf");
        let token = resign_with_payload("acme", &ring, payload);
        assert_matches!(
            decode_and_verify(&token, &ring).unwrap_err(),
            McpJwtError::InvalidSignature
        );
    }

    /// A claim shape that names only what this test reads, so a missing `nbf`
    /// deserializes cleanly — which is what makes it the honest test of the
    /// required-claims entry rather than of serde.
    #[derive(serde::Deserialize)]
    struct SubsetAccessClaims {
        tenant_id: String,
    }

    /// `validate_nbf` is a no-op on a token that simply omits the claim, so the
    /// requirement is what makes the not-yet-valid check real. Drive the
    /// validation directly with a shape that would otherwise tolerate the
    /// missing field.
    #[test]
    fn the_required_claims_refuse_a_token_with_no_nbf() {
        let ring = ring();
        let claims = fixture_claims("acme", "https://example.com/mcp/a");
        let (kid, _) = ring.signing_key("acme");
        let (_, key) = ring.es256_verification_key(&kid).expect("key");

        let check = |token: &str| {
            decode::<SubsetAccessClaims>(token, &key, &access_token_validation())
        };

        // Control: with `nbf` present the same subset shape decodes, so the
        // refusal below is about the missing claim and not the shape.
        let intact = encode_access_token(&claims, &ring).expect("encode");
        assert_eq!(check(&intact).expect("intact decodes").claims.tenant_id, "acme");

        let mut payload = serde_json::to_value(&claims).expect("claims");
        payload.as_object_mut().expect("object").remove("nbf");
        assert!(check(&resign_with_payload("acme", &ring, payload)).is_err());
    }

    #[test]
    fn a_foreign_issuer_is_rejected() {
        let ring = ring();
        let mut claims = fixture_claims("acme", "https://example.com/mcp/a");
        claims.iss = "someone-else".to_string();
        let token = resign_with_payload(
            "acme",
            &ring,
            serde_json::to_value(&claims).expect("claims"),
        );
        assert_matches!(
            decode_and_verify(&token, &ring).unwrap_err(),
            McpJwtError::InvalidSignature
        );
    }

    #[test]
    fn refresh_typed_token_rejected_as_access() {
        // A refresh token is signed with the same per-tenant key and its
        // payload is a superset of the access shape, so it deserializes
        // cleanly into `McpAccessClaims`. `decode_and_verify` must reject it
        // on the `typ` claim — otherwise a 30-day refresh token would be
        // usable as an access bearer.
        let ring = ring();
        let now = chrono::Utc::now();
        let token = resign_with_payload(
            "acme",
            &ring,
            serde_json::json!({
                "sub": Uuid::new_v4().to_string(),
                "aud": "https://example.com/mcp/a",
                "iss": TOKEN_ISSUER,
                "tenant_id": "acme",
                "workspace_id": Uuid::new_v4().to_string(),
                "virtual_server_id": Uuid::new_v4().to_string(),
                "client_id": "test-client",
                "scope": "mcp:invoke",
                "jti": new_jti(),
                "typ": "refresh",
                "surface": SURFACE_MCP,
                "original_jti": new_jti(),
                "iat": now.timestamp(),
                "nbf": now.timestamp(),
                "exp": (now + chrono::Duration::days(30)).timestamp(),
            }),
        );
        let err = decode_and_verify(&token, &ring).unwrap_err();
        assert_matches!(err, McpJwtError::WrongTokenType);
    }

    /// A CLI token and an MCP token are signed with the same per-tenant key,
    /// so only the surface claim keeps one out of the other's endpoint.
    #[test]
    fn a_cli_surfaced_token_is_rejected_as_an_mcp_access_token() {
        let ring = ring();
        let mut claims = fixture_claims("acme", "https://example.com/mcp/a");
        claims.surface = SURFACE_CLI.to_string();
        let token = resign_with_payload(
            "acme",
            &ring,
            serde_json::to_value(&claims).expect("claims"),
        );
        assert_matches!(
            decode_and_verify(&token, &ring).unwrap_err(),
            McpJwtError::WrongSurface
        );
    }

    #[test]
    fn encode_rejects_claims_it_could_not_verify() {
        let ring = ring();
        let base = fixture_claims("acme", "https://example.com/mcp/a");

        let mut wrong_typ = base.clone();
        wrong_typ.typ = "refresh".to_string();
        assert_matches!(
            encode_access_token(&wrong_typ, &ring).unwrap_err(),
            McpJwtError::WrongTokenType
        );

        let mut wrong_surface = base.clone();
        wrong_surface.surface = SURFACE_CLI.to_string();
        assert_matches!(
            encode_access_token(&wrong_surface, &ring).unwrap_err(),
            McpJwtError::WrongSurface
        );

        let mut wrong_issuer = base;
        wrong_issuer.iss = "someone-else".to_string();
        assert_matches!(
            encode_access_token(&wrong_issuer, &ring).unwrap_err(),
            McpJwtError::WrongIssuer
        );
    }
}
