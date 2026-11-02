//! Proxy-side spec-OAuth glue.
//!
//! Two surfaces:
//!
//! 1. **`/.well-known/oauth-protected-resource/mcp/{slug}`** (RFC 9728) — public
//!    metadata document the MCP client fetches on receiving a 401 from
//!    `/mcp/{slug}`. Returns the audience URI + the URL of our authorization
//!    server (the admin-api).
//!
//! 2. **JWT bearer validation in the MCP handler** — when `extract_bearer`
//!    returns a value that looks like a JWT (three dot-separated segments), we
//!    route through [`validate_jwt_bearer`] instead of the cache-backed `sk-*`
//!    key lookup. The validator (a) verifies the signature against the tenant's
//!    published ES256 keys, (b) confirms the `aud` matches the `slug`'s
//!    canonical URI, (c) confirms the `jti` is not in the per-tenant revoked-jti
//!    set, and (d) returns a synthetic `UserContext` that the rest of the
//!    request pipeline treats identically to an `sk-*` key.
//!
//! **This process holds no JWT signing secret.** The verification keys arrive as
//! data on the per-tenant config snapshot (`McpConfig::jwks`), so the data plane
//! can check a token admin-api minted but cannot mint one itself — and a
//! compromise here forges no session on any surface. Reintroducing a local
//! derivation (a `Keyring` built from `AUTH_SECRET`) would quietly undo that,
//! because the tokens would keep verifying either way.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderValue, Response, StatusCode};
use streamscope_core::auth::{TenantRequestCtx, UserContext};
use streamscope_core::config::TenantId;
use streamscope_core::error::{AppError, AuthError};
use streamscope_mcp_auth::jwt::{decode_and_verify_with_key, McpAccessClaims, McpJwtError};
use streamscope_mcp_auth::keys;
use streamscope_mcp_auth::metadata::IMPLICIT_SCOPE;
use streamscope_mcp_auth::{
    audience_for_slug, build_protected_resource_metadata, ProtectedResourceMetadata,
};

use crate::proxy::AppState;

// ---------------------------------------------------------------------------
// 1. /.well-known/oauth-protected-resource/mcp/{slug}
// ---------------------------------------------------------------------------

/// Axum handler for the protected-resource-metadata endpoint. Public
/// (no auth). Resolves the slug to a virtual server across all tenant
/// configs (slug uniqueness for OAuth-enabled VS is enforced in the DB by the
/// `mcp_virtual_servers_oauth_slug_unique` partial unique index).
///
/// Per-tenant URLs (`proxy_public_url`, `api_public_url`,
/// `admin_public_url`) come from the tenant's `TenantConfig` snapshot —
/// admin-api collapses the SYSTEM-default-with-tenant-override layering at
/// snapshot time. The advertised authorization server lives on the
/// canonical admin-API origin (`api_public_url`; the production deploy
/// shapes serve UI and API on separate vhosts and the UI origin never
/// routes `/api/v1/*`), falling back to `admin_public_url` when unset (API
/// co-resident with the UI). If the proxy or admin URL is unset we surface
/// 503 instead of falling back to a global default — the AS discovery
/// document needs the admin origin (consent page), so this stays the
/// fail-closed gate even when `api_public_url` alone is configured.
pub async fn protected_resource_metadata_handler(
    State(state): State<Arc<AppState>>,
    Path(slug): Path<String>,
) -> Response<Body> {
    let registry = state.tenant_registry.load();
    // A tenant with no public identity of its own cannot be named in a metadata
    // document, so an empty `tenant_slug` reads here as "no such resource" — the
    // 401 challenge still treats the mount as OAuth-enabled.
    let found = registry
        .mcp_slug(&slug)
        .and_then(|entry| entry.oauth.as_ref())
        .filter(|oauth| !oauth.tenant_slug.is_empty());
    let Some(streamscope_core::config::McpSlugOauth {
        tenant_slug,
        proxy_url,
        admin_url,
        api_url,
    }) = found.cloned()
    else {
        return Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"error":"no OAuth-enabled virtual server matches this slug"}"#,
            ))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    };

    // Fail closed unless the advertised authorization server is fully
    // resolvable: its discovery document needs the admin origin for the
    // browser consent page, so an api-only configuration must 503 here
    // rather than advertise an AS whose own metadata endpoint errors.
    let (Some(proxy_url), Some(admin_url)) = (proxy_url, admin_url) else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("Content-Type", "application/json")
            .body(Body::from(
                r#"{"error":"proxy/admin public URL not configured for this tenant — set them under Settings → Defaults"}"#,
            ))
            .unwrap_or_else(|_| Response::new(Body::empty()));
    };
    // Machine-facing AS origin: api_public_url, co-resident fallback admin.
    let auth_server_url = api_url.unwrap_or(admin_url);

    let metadata = build_protected_resource_metadata(
        &proxy_url,
        &auth_server_url,
        &tenant_slug,
        &slug,
    );
    serialize_metadata(&metadata)
}

fn serialize_metadata(m: &ProtectedResourceMetadata) -> Response<Body> {
    let body = serde_json::to_vec(m).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header("Cache-Control", "public, max-age=300")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// ---------------------------------------------------------------------------
// 2. JWT bearer validation in the MCP handler
// ---------------------------------------------------------------------------

/// Heuristic: does this bearer look like a JWT? (Three non-empty
/// dot-separated segments.) The handler dispatches to [`validate_jwt_bearer`]
/// when this is true; otherwise it authenticates an `sk-*`/`vk-*` key.
/// Proxy-issued keys are base58 with no `.`, so the segment count alone
/// distinguishes them from a JWT.
pub fn looks_like_jwt(bearer: &str) -> bool {
    let parts: Vec<&str> = bearer.split('.').collect();
    parts.len() == 3 && parts.iter().all(|p| !p.is_empty())
}

/// Validate a JWT bearer for `/mcp/<slug>`. Returns a synthetic UserContext
/// matching the issued JWT's claims, with the tenant configuration it was
/// verified and resolved against, or an `AuthError`.
pub async fn validate_jwt_bearer(
    state: &AppState,
    slug: &str,
    bearer: &str,
) -> Result<TenantRequestCtx, AppError> {
    fn invalid(token: &str) -> AppError {
        AppError::Auth(AuthError::InvalidKey(
            token.chars().take(8).collect::<String>(),
        ))
    }

    // Key selection precedes signature verification here, and that inverts the
    // usual order: the `kid` naming the tenant is read from an UNVERIFIED header
    // so we can find the tenant's config and, in it, the public key to check the
    // signature with. Two things make that safe, and both must be preserved:
    //
    //   * nothing below acts on `kid_tenant` beyond looking up a config and a
    //     key — no audit, no counter, no state that outlives a rejection; and
    //   * `decode_and_verify_with_key` re-checks the verified payload's
    //     `tenant_id` against the `kid_tenant` we pass, so a token relabelled to
    //     point at another tenant selects a key that cannot verify it.
    //
    // This process holds no signing secret. The keys come from the config
    // snapshot admin-api pushes, so a generation missing there is a token we
    // refuse — never a cue to derive one locally.
    let (kid, kid_tenant) = keys::kid_and_tenant_of(bearer).map_err(|e| {
        tracing::debug!("validate_jwt_bearer: {e:?}");
        invalid(bearer)
    })?;
    // `debug`, not `warn`: this is now reachable before any signature check, so
    // any request carrying a JWT-shaped bearer can drive it at request rate.
    let tenant_id_uuid: uuid::Uuid = kid_tenant.parse().map_err(|_| {
        tracing::debug!("validate_jwt_bearer: kid tenant not uuid");
        invalid(bearer)
    })?;

    // Look up the virtual server — and this token's verification key — in the
    // per-tenant snapshot.
    let cfg = state
        .load_tenant_config(TenantId(tenant_id_uuid))
        .ok_or_else(|| invalid(bearer))?;

    // Either the generation was retired, or this replica holds a snapshot older
    // than the rotation that minted the token. Both resolve by the next config
    // push, so this is a 401 and not a 503: the token itself is what we cannot
    // accept.
    let key = keys::es256_key_from_jwks(&kid, &cfg.mcp.jwks).map_err(|e| {
        tracing::debug!(
            tenant_id = %tenant_id_uuid,
            known_keys = cfg.mcp.jwks.len(),
            "validate_jwt_bearer: no published key for this token ({e:?})"
        );
        invalid(bearer)
    })?;

    let claims: McpAccessClaims =
        decode_and_verify_with_key(bearer, &kid_tenant, &key).map_err(|e| {
            tracing::debug!("validate_jwt_bearer: {e:?}");
            match e {
                McpJwtError::Expired => AppError::Auth(AuthError::KeyExpired(
                    bearer.chars().take(8).collect::<String>(),
                )),
                _ => invalid(bearer),
            }
        })?;

    let user_id_uuid: uuid::Uuid = claims.sub.parse().map_err(|_| {
        tracing::warn!("validate_jwt_bearer: sub not uuid");
        invalid(bearer)
    })?;
    let workspace_id_uuid: uuid::Uuid = claims.workspace_id.parse().map_err(|_| {
        tracing::warn!("validate_jwt_bearer: workspace_id not uuid");
        invalid(bearer)
    })?;
    let jti_uuid: uuid::Uuid = claims.jti.parse().map_err(|_| {
        tracing::warn!("validate_jwt_bearer: jti not uuid");
        invalid(bearer)
    })?;

    // Audience must match the slug's canonical URI under THIS tenant's
    // resolved proxy URL — tokens minted for tenant A (with audience
    // `<A's URL>/mcp/<slug>`) cannot be replayed against tenant B even if
    // the slug happens to collide. Reject when the tenant has no public
    // URL configured.
    // Operator-misconfig vs client-error: if the tenant has no resolved
    // proxy URL we surface `AuthError::ServiceUnavailable` (renders 503)
    // rather than `InvalidKey` (401). The metadata endpoint
    // (`protected_resource_metadata_handler`) and the Origin guard
    // (`mcp/handler.rs::validate_origin_header`) take the same 503 path
    // for the same root cause — consistent shape for client retries +
    // ops dashboards.
    let proxy_origin = cfg.proxy_public_url.as_deref().ok_or_else(|| {
        tracing::warn!(
            tenant_id = %tenant_id_uuid,
            slug = %slug,
            "validate_jwt_bearer: tenant proxy_public_url unset — failing closed"
        );
        AppError::Auth(AuthError::ServiceUnavailable(
            "tenant proxy_public_url not configured".into(),
        ))
    })?;
    let expected_aud = audience_for_slug(proxy_origin, slug);
    if claims.aud != expected_aud {
        tracing::debug!(
            "validate_jwt_bearer: audience mismatch (expected {}, got {})",
            expected_aud,
            claims.aud
        );
        return Err(invalid(bearer));
    }
    let vs_id = cfg
        .mcp
        .virtual_server_by_slug
        .get(slug)
        .ok_or_else(|| invalid(bearer))?;
    let vs = cfg
        .mcp
        .virtual_servers
        .get(vs_id)
        .ok_or_else(|| invalid(bearer))?;
    if !vs.oauth_enabled {
        return Err(invalid(bearer));
    }

    // The audience pinned the SLUG; this pins the server. A slug outlives the
    // virtual server that held it — delete one and its issued-token rows
    // cascade away, taking them out of the revoked set — so a server recreated
    // under the same slug would otherwise honour every bearer still matching
    // that audience.
    let claim_vs_id: uuid::Uuid = claims.virtual_server_id.parse().map_err(|_| {
        tracing::warn!("validate_jwt_bearer: virtual_server_id not uuid");
        invalid(bearer)
    })?;
    if claim_vs_id != *vs_id {
        tracing::info!(
            slug = %slug,
            "validate_jwt_bearer: token names a different virtual server than this slug resolves to"
        );
        return Err(invalid(bearer));
    }

    // Revocation check.
    if cfg.mcp.revoked_jtis.contains(&jti_uuid) {
        tracing::info!("validate_jwt_bearer: jti revoked ({})", claims.jti);
        return Err(invalid(bearer));
    }

    // Resolve the rate-limit cap. `sk-`/`vk-` keys carry their workspace bucket
    // pre-baked on their `UserContext`; the JWT path mints a fresh context
    // bound to the claim's `workspace_id`, so resolve the SAME per-workspace cap
    // the snapshot bakes for keyed paths (`workspace_rate_limits`, keyed by the
    // claim's workspace). The usage counter also keys off this `workspace_id`,
    // so the cap and the counter agree. A workspace with no row is uncapped —
    // the no-row-means-uncapped rule applies to any workspace without a cap
    // (Option A).
    let rate_limit = cfg
        .workspace_rate_limits
        .get(&workspace_id_uuid)
        .cloned()
        .unwrap_or_else(streamscope_core::auth::RateLimitConfig::unlimited);

    let user = UserContext {
        user_id: user_id_uuid,
        tenant_id: tenant_id_uuid,
        // Workspace comes straight from the token claim (resolved at mint time
        // to the workspace granting this user the server) and is scoped down to
        // the virtual server the token NAMES (see `allowed_virtual_server_ids`).
        workspace_id: workspace_id_uuid,
        email: None,
        display_name: None,
        real_api_key: String::new(),
        model_map: std::sync::Arc::default(),
        rate_limit,
        // The member bucket resolves exactly as a baked key's does, so a token
        // is held to its member's limit inside the claim's workspace.
        user_rate_override: cfg.member_limit_for(workspace_id_uuid, user_id_uuid),
        key_budget: None,
        // The org-total ceiling applies to every path that spends, so an MCP
        // token is held to it exactly as a key is — unless the claim's workspace
        // is one the organisation does not fund, which `tenant_budget_for`
        // resolves the same way admin bakes it onto a key.
        tenant_budget: cfg.tenant_budget_for(workspace_id_uuid),
        expires_at: None,
        // jti is not a real key id but the rate-limit / audit pipeline keys
        // off `key_id`; reuse the jti as a stable per-token identifier so
        // burst-limit math is per-issued-token.
        key_id: Some(jti_uuid),
        app_id: Some(claims.client_id.clone()),
        session_id: None,
        // OAuth tokens are MCP-only and grant exactly the server the CLAIM
        // names. It MUST come from the claim: derived from the addressed slug,
        // this list would contain whatever that slug just resolved to, and the
        // handler's `allows_virtual_server` check would compare a value to
        // itself — a guard no token could fail.
        allowed_provider_ids: Vec::new(),
        allowed_virtual_server_ids: vec![claim_vs_id],
        // What the subject consented to at `/authorize`, narrowed there against
        // what this server grants. Carried verbatim so the per-method check
        // reads the grant itself rather than a re-derivation of it.
        mcp_scope: Some(claims.scope.clone()),
        // Spec-OAuth JWTs are minted for exactly one MCP virtual server; they
        // carry no A2A reach.
        allowed_a2a_agent_ids: Vec::new(),
        forward_auth: false,
        byok_passthrough: Vec::new(),
        inline_ai: false,
        // No key row, so no key-level class: the token runs as its workspace,
        // which `QosTable::effective_class` resolves from the config snapshot.
        qos_class_id: None,
        qos_class_elevated: false,
    };
    Ok(TenantRequestCtx { user, config: cfg })
}

// ---------------------------------------------------------------------------
// Helpers used by the existing 401 path
// ---------------------------------------------------------------------------

/// Build a `WWW-Authenticate: Bearer resource_metadata="...", scope="..."`
/// header value for a given slug. The MCP handler attaches this to 401
/// responses when the addressed VS has `oauth_enabled = true`.
///
/// Per spec MCP 2025-11-25 § Authorization, the `scope` parameter (RFC 6750
/// §3) tells the client which scopes to request during authorization, so it
/// can follow the principle of least privilege and skip scopes that aren't
/// needed for the current request. An unauthenticated request has not named a
/// method yet, so the challenge advertises full access — the client narrows
/// from there using the `scopes_supported` list in the discovery document.
pub fn www_authenticate_header(proxy_origin: &str, slug: &str) -> HeaderValue {
    let value = format!(
        "Bearer resource_metadata=\"{}\", scope=\"{IMPLICIT_SCOPE}\"",
        resource_metadata_url(proxy_origin, slug)
    );
    HeaderValue::from_str(&value)
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer"))
}

fn resource_metadata_url(proxy_origin: &str, slug: &str) -> String {
    format!(
        "{}/.well-known/oauth-protected-resource/mcp/{}",
        proxy_origin.trim_end_matches('/'),
        slug
    )
}

/// The RFC 6750 §3.1 `insufficient_scope` challenge for a token that
/// authenticated but may not call the method it asked for.
///
/// Distinct from [`www_authenticate_header`] in the one way that matters to a
/// client: it names the **missing** scope rather than full access, so a client
/// following least privilege re-authorizes for exactly what it now needs
/// instead of escalating to everything.
pub fn insufficient_scope_header(
    proxy_origin: &str,
    slug: &str,
    required_scope: &str,
) -> HeaderValue {
    let value = format!(
        "Bearer error=\"insufficient_scope\", error_description=\"the access token does not grant this method\", resource_metadata=\"{}\", scope=\"{required_scope}\"",
        resource_metadata_url(proxy_origin, slug)
    );
    HeaderValue::from_str(&value)
        .unwrap_or_else(|_| HeaderValue::from_static("Bearer error=\"insufficient_scope\""))
}

/// Does this request's credential permit `method`?
///
/// Returns the scope the client must obtain when it does not. A credential with
/// no scope (`sk-`/`vk-` keys) is not scope-limited and always passes — its
/// bounds are the workspace's grants, checked elsewhere.
pub fn scope_check(ctx: &UserContext, method: &str) -> Result<(), String> {
    let Some(granted) = ctx.mcp_scope.as_deref() else {
        return Ok(());
    };
    streamscope_mcp_auth::metadata::scope_permits(granted, method)
        .map_err(|required| required.to_string())
}

/// May this credential open the long-lived server-push channel?
///
/// The channel is **not method-scoped**: it carries whatever the subject's own
/// calls produce — sampling and elicitation round-trips, `list_changed`
/// notifications, and replayed `tools/call` / `prompts/get` stream frames. A
/// token granted only `mcp:prompts.read` could therefore watch the payloads of
/// tool calls it was never allowed to make.
///
/// Rather than filter the stream per event — which would mean classifying every
/// server-initiated frame and failing open on anything new — this requires full
/// access. A narrow token keeps every method its scope allows over POST and
/// simply does not get the optional push channel, which the spec marks as a MAY
/// for exactly this kind of reason.
pub fn channel_scope_check(ctx: &UserContext) -> Result<(), String> {
    let Some(granted) = ctx.mcp_scope.as_deref() else {
        return Ok(());
    };
    if granted.split_whitespace().any(|g| g == IMPLICIT_SCOPE) {
        Ok(())
    } else {
        Err(IMPLICIT_SCOPE.to_string())
    }
}

/// Append a `WWW-Authenticate` header to an existing 401 response. Mutates in
/// place. Caller is responsible for confirming the request slug's VS has
/// `oauth_enabled = true` (otherwise the 401 stays plain JSON-RPC).
///
/// Looks up the tenant's resolved `proxy_public_url` from the registry so
/// the metadata pointer matches the per-tenant origin. If the tenant has
/// no URL configured the header is omitted — the 401 still goes out, just
/// without the discovery hint, and the resource-metadata GET would also
/// 503 if the client asked.
pub fn add_www_authenticate(response: &mut Response<Body>, state: &AppState, slug: &str) {
    let Some(proxy_origin) = proxy_origin_for_slug(state, slug) else {
        return;
    };
    response
        .headers_mut()
        .insert("WWW-Authenticate", www_authenticate_header(&proxy_origin, slug));
}

/// Append the `insufficient_scope` challenge to a 403. Same omit-if-unresolved
/// rule as [`add_www_authenticate`].
pub fn add_insufficient_scope(
    response: &mut Response<Body>,
    state: &AppState,
    slug: &str,
    required_scope: &str,
) {
    let Some(proxy_origin) = proxy_origin_for_slug(state, slug) else {
        return;
    };
    response.headers_mut().insert(
        "WWW-Authenticate",
        insufficient_scope_header(&proxy_origin, slug, required_scope),
    );
}

fn proxy_origin_for_slug(state: &AppState, slug: &str) -> Option<String> {
    let registry = state.tenant_registry.load();
    registry
        .mcp_slug(slug)?
        .proxy_urls
        .first()
        .cloned()
}

pub fn slug_has_oauth_enabled(state: &AppState, slug: &str) -> bool {
    let registry = state.tenant_registry.load();
    registry
        .mcp_slug(slug)
        .is_some_and(|entry| entry.oauth.is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn looks_like_jwt_rejects_proxy_keys() {
        // sk-/vk- keys are base58 with no '.', so they never look like a JWT
        // and authenticate as a key instead of the JWT validator.
        assert!(!looks_like_jwt("sk-abcdefghijklmnopqrstuvwx"));
        assert!(!looks_like_jwt("vk-abcdefghijklmnopqrstuvwx"));
    }

    #[test]
    fn looks_like_jwt_requires_three_segments() {
        assert!(!looks_like_jwt("two.segments"));
        assert!(!looks_like_jwt("four.dot.separated.segments"));
    }

    #[test]
    fn looks_like_jwt_rejects_empty_segments() {
        assert!(!looks_like_jwt("a..c"));
        assert!(!looks_like_jwt(".b.c"));
        assert!(!looks_like_jwt("a.b."));
    }

    #[test]
    fn looks_like_jwt_accepts_three_non_empty_segments() {
        assert!(looks_like_jwt("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0.signature"));
    }

    #[test]
    fn www_authenticate_includes_resource_metadata_and_scope() {
        // Spec MCP 2025-11-25 § Authorization: WWW-Authenticate SHOULD
        // include a `scope` parameter so clients know which scopes to
        // request during authorization.
        let header = www_authenticate_header("https://gw.acme.test", "acme-tools");
        let s = header.to_str().unwrap();
        assert!(s.starts_with("Bearer "));
        assert!(
            s.contains("resource_metadata="),
            "must carry the RFC 9728 metadata URL: {s}"
        );
        assert!(
            s.contains("/.well-known/oauth-protected-resource/mcp/acme-tools"),
            "metadata URL must include the slug-scoped path: {s}"
        );
        assert!(
            s.contains("scope=\"mcp:invoke\""),
            "must include the implicit scope so clients can least-privilege their request: {s}"
        );
    }

    // -----------------------------------------------------------------------
    // validate_jwt_bearer — the DB-free validation order this module owns:
    // signature -> typ -> tenant config -> RFC 8707 audience -> oauth_enabled
    // -> revoked jti. Each test below drives exactly one of those gates.
    // -----------------------------------------------------------------------

    mod bearer {
        use super::*;
        use std::collections::{HashMap, HashSet};
        use std::sync::Arc;
        use std::time::Duration;
        use std::assert_matches;
        use streamscope_core::config::mcp::McpVirtualServer;
        use streamscope_core::config::{TenantConfig, TenantId};
        use streamscope_core::proxy::{AppState, NoopStats};
        use streamscope_mcp_auth::jwt::{encode_access_token, McpAccessClaims, ACCESS_TOKEN_TYP};
        use uuid::Uuid;

        const SECRET: &str = "spec-oauth-unit-test-secret-32-bytes-min";

        /// A ring stands in for admin-api here — the *minting* side. The
        /// validator under test never builds one; it is handed public keys on
        /// the tenant config, which is the whole point of these tests.
        fn ring(secret: &str) -> streamscope_mcp_auth::Keyring {
            streamscope_mcp_auth::Keyring::new(secret, None).expect("ring")
        }
        const PROXY_URL: &str = "https://gw.acme.test";
        const SLUG: &str = "acme-tools";

        /// Put the token-signing secret into this process's environment.
        ///
        /// Used by exactly one test, and inverted from what it once was: it is
        /// no longer setup that makes validation *work*, it is the adversarial
        /// condition under which validation must still **fail**. If the
        /// validator ever re-derived keys locally, that test would start passing
        /// tokens the config snapshot does not vouch for, and nothing else here
        /// would notice.
        ///
        /// SAFETY: `set_var` is unsafe because a concurrent libc `getenv` from
        /// another thread can observe a torn environment block while `setenv`
        /// reallocates it. Rust-to-Rust access cannot race — std serializes
        /// `set_var`/`var` behind its own lock — so the hazard is exclusively
        /// FFI readers, and this test binary has none on any reachable path.
        /// The precedent is the `ENCRYPTION_KEY` setters in `config_sync` and
        /// `mcp::multiplex`, which are sound for the same reason.
        fn plant_signing_secret_in_env() {
            unsafe {
                std::env::set_var("AUTH_SECRET", SECRET);
            }
        }

        /// A virtual server built through serde so only the fields under test
        /// are named — every other field takes its declared default, and a new
        /// field added upstream won't break this helper.
        fn virtual_server(id: Uuid, tenant: Uuid, oauth_enabled: bool) -> McpVirtualServer {
            serde_json::from_value(serde_json::json!({
                "id": id,
                "tenant_id": tenant,
                "slug": SLUG,
                "name": "Acme Tools",
                "oauth_enabled": oauth_enabled,
            }))
            .expect("virtual server fixture")
        }

        /// An offline `AppState` whose registry holds exactly one tenant. Mirrors
        /// the shape `router_tests::rig` documents for test contexts: no edge
        /// uplink, no upstream, no audit consumers that outlive the call.
        fn state_with(cfg: TenantConfig, tenant: Uuid) -> Arc<AppState> {
            let (audit_tx, audit_rx) = streamscope_core::audit::create_audit_channel();
            // The validator never sends, but a closed channel would be a
            // misleading state to test against — keep the receiver alive.
            std::mem::forget(audit_rx);

            let registry = streamscope_core::config::new_tenant_registry();
            let mut map = HashMap::new();
            map.insert(TenantId(tenant), Arc::new(cfg));
            streamscope_core::config::publish(&registry, streamscope_core::config::Registry::new(map));

            Arc::new(AppState {
                usage: Arc::new(streamscope_core::usage::UsageTracker::new()),
                http_client: streamscope_core::proxy::client::UpstreamClient::new()
                    .expect("upstream client builds offline"),
                tenant_registry: registry,
                audit_tx,
                session_detector:
                    streamscope_core::proxy::content::SessionDetector::with_capacity(
                        8,
                        Duration::from_secs(60),
                        8,
                    ),
                inline_exchanges:
                    streamscope_core::proxy::inline_exchange::InlineExchangeStore::default(),
                script_engine: Arc::new(streamscope_core::scripting::ScriptEngine::new()),
                lb_counters: dashmap::DashMap::new(),
                circuit_breaker: Arc::new(
                    streamscope_core::proxy::health::CircuitBreaker::new(
                        false,
                        5,
                        Duration::from_secs(30),
                    ),
                ),
                health_event_tx: None,
                proxy_stats: Arc::new(NoopStats),
                web_search_clients: Arc::new(
            streamscope_core::extension_http::ExtensionClients::build(
                "search",
                reqwest::Client::builder,
            )
            .unwrap(),
        ),
                web_audit_tx: None,
                mixed_pending_cache: Arc::new(streamscope_core::web::MixedPendingCache::default()),
                response_cache: Arc::new(
                    streamscope_core::proxy::response_cache::ResponseCache::new(1024, 4),
                ),
                audit_task_tracker: tokio_util::task::TaskTracker::new(),
                config_ready: Arc::new(std::sync::atomic::AtomicBool::new(true)),
                dispatch_gate: std::sync::Arc::new(
                    streamscope_core::proxy::dispatch_gate::DispatchGate::new(Default::default()),
                ),
            })
        }

        struct Fixture {
            state: Arc<AppState>,
            tenant: Uuid,
            user: Uuid,
            workspace: Uuid,
            virtual_server: Uuid,
            jti: Uuid,
        }

        /// The happy-path world: one tenant with a resolved proxy URL and one
        /// OAuth-enabled virtual server on `SLUG`.
        fn fixture() -> Fixture {
            fixture_with(|_| {})
        }

        fn fixture_with(tweak: impl FnOnce(&mut TenantConfig)) -> Fixture {
            let tenant = Uuid::new_v4();
            let vs_id = Uuid::new_v4();

            let mut cfg = TenantConfig {
                proxy_public_url: Some(PROXY_URL.to_string()),
                ..Default::default()
            };
            cfg.mcp
                .virtual_servers
                .insert(vs_id, virtual_server(vs_id, tenant, true));
            cfg.mcp.virtual_server_by_slug.insert(SLUG.to_string(), vs_id);
            // The published keys admin-api would have put on the snapshot. This
            // is the validator's ONLY key source, so a `tweak` that empties or
            // replaces it is how the no-key and wrong-key paths get driven.
            cfg.mcp.jwks = ring(SECRET).public_jwks(&tenant.to_string());
            tweak(&mut cfg);

            Fixture {
                state: state_with(cfg, tenant),
                tenant,
                user: Uuid::new_v4(),
                workspace: Uuid::new_v4(),
                virtual_server: vs_id,
                jti: Uuid::new_v4(),
            }
        }

        impl Fixture {
            /// Mint a token for this fixture, letting the caller override the
            /// one claim under test.
            fn token(&self, mutate: impl FnOnce(&mut McpAccessClaims)) -> String {
                let mut claims = self.claims();
                mutate(&mut claims);
                encode_access_token(&claims, &ring(SECRET)).expect("mint access token")
            }

            fn claims(&self) -> McpAccessClaims {
                let now = chrono::Utc::now().timestamp();
                McpAccessClaims {
                    sub: self.user.to_string(),
                    aud: audience_for_slug(PROXY_URL, SLUG),
                    iss: streamscope_mcp_auth::TOKEN_ISSUER.to_string(),
                    tenant_id: self.tenant.to_string(),
                    workspace_id: self.workspace.to_string(),
                    virtual_server_id: self.virtual_server.to_string(),
                    client_id: "mco-test".to_string(),
                    scope: "mcp:invoke".to_string(),
                    jti: self.jti.to_string(),
                    typ: ACCESS_TOKEN_TYP.to_string(),
                    surface: streamscope_mcp_auth::SURFACE_MCP.to_string(),
                    iat: now,
                    nbf: now,
                    exp: now + 3600,
                }
            }
        }

        #[tokio::test]
        async fn accepts_a_well_formed_token_and_binds_the_claim_workspace() {
            let f = fixture();
            let token = f.token(|_| {});
            let ctx = validate_jwt_bearer(&f.state, SLUG, &token)
                .await.map(|c| c.user)
                .expect("valid token accepted");

            assert_eq!(ctx.tenant_id, f.tenant);
            assert_eq!(ctx.user_id, f.user);
            // The workspace comes from the claim, resolved at mint time — not
            // re-derived here. A drift in that rule silently re-buckets budget,
            // rate limits and audit rows.
            assert_eq!(ctx.workspace_id, f.workspace);
        }

        /// The data plane verifies **only** what the config snapshot published.
        ///
        /// The token here is genuine — correctly signed, unexpired, right
        /// audience — and the secret that signed it is sitting in this process's
        /// environment. The one thing missing is a published key. If the
        /// validator ever fell back to deriving from `AUTH_SECRET`, this token
        /// would sail through, and every other test here would still pass
        /// because they all supply keys. That makes this the test standing
        /// between "the proxy holds no signing authority" and a silent
        /// regression to holding it.
        #[tokio::test]
        async fn refuses_a_token_with_no_published_key_even_when_the_secret_is_in_env() {
            plant_signing_secret_in_env();
            let f = fixture_with(|cfg| cfg.mcp.jwks.clear());
            let token = f.token(|_| {});
            assert_matches!(
                validate_jwt_bearer(&f.state, SLUG, &token).await.map(|c| c.user),
                Err(AppError::Auth(AuthError::InvalidKey(_))),
                "accepted a token the snapshot published no key for"
            );
        }

        /// A published set that names other generations is not a wildcard: the
        /// `kid` must match. Distinguishes "we have keys" from "we have *this*
        /// key" — an implementation that verified against every published key in
        /// turn would pass the test above and fail here.
        #[tokio::test]
        async fn refuses_a_token_whose_generation_is_not_the_published_one() {
            plant_signing_secret_in_env();
            let other = "a-different-signing-secret-32-bytes-min";
            let f = fixture_with(|cfg| {
                let tenant = cfg
                    .mcp
                    .jwks
                    .first()
                    .and_then(|k| k.kid.split_once('.').map(|(_, t)| t.to_string()))
                    .expect("fixture publishes a key");
                cfg.mcp.jwks = ring(other).public_jwks(&tenant);
            });
            let token = f.token(|_| {});
            assert_matches!(
                validate_jwt_bearer(&f.state, SLUG, &token).await.map(|c| c.user),
                Err(AppError::Auth(AuthError::InvalidKey(_))),
                "accepted a token signed by a generation the snapshot never published"
            );
        }

        /// The rotation overlap, from the verifier's side: a snapshot carrying
        /// two generations accepts a token signed by either. This is what makes
        /// `AUTH_SECRET_SECONDARY` mean anything on the data plane now that the
        /// proxy no longer reads the ring itself.
        #[tokio::test]
        async fn accepts_either_generation_the_snapshot_publishes() {
            let incoming = "the-incoming-signing-secret-32-bytes-x";
            let f = fixture_with(|cfg| {
                let tenant = cfg
                    .mcp
                    .jwks
                    .first()
                    .and_then(|k| k.kid.split_once('.').map(|(_, t)| t.to_string()))
                    .expect("fixture publishes a key");
                cfg.mcp
                    .jwks
                    .extend(ring(incoming).public_jwks(&tenant));
            });

            // Signed by the generation that was already published.
            validate_jwt_bearer(&f.state, SLUG, &f.token(|_| {}))
                .await
                .expect("active generation accepted");

            // Signed by the one that joined the ring.
            let mut claims = f.claims();
            claims.jti = Uuid::new_v4().to_string();
            let staged = encode_access_token(&claims, &ring(incoming)).expect("mint");
            validate_jwt_bearer(&f.state, SLUG, &staged)
                .await.map(|c| c.user)
                .expect("staged generation accepted");
        }

        /// RFC 8707: a token minted for one resource must not be replayable
        /// against another. The audience is rebuilt from *this* tenant's
        /// resolved proxy URL, so a token carrying another origin is refused.
        #[tokio::test]
        async fn rejects_foreign_audience() {
            let f = fixture();
            let token = f.token(|c| {
                c.aud = audience_for_slug("https://gw.evil.test", SLUG);
            });
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        /// Same origin, different slug — the audience is slug-scoped, so a
        /// token for one virtual server cannot address a sibling.
        #[tokio::test]
        async fn rejects_audience_for_a_sibling_slug() {
            let f = fixture();
            let token = f.token(|c| {
                c.aud = audience_for_slug(PROXY_URL, "some-other-server");
            });
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        /// A slug outlives the virtual server that held it. Deleting one
        /// cascades its issued-token rows away, so nothing is left in the
        /// revoked set — and the audience, which names the *slug*, still matches
        /// a server recreated under it. Only the id refuses the inherited
        /// bearer, and this is the one claim that carries it.
        #[tokio::test]
        async fn rejects_a_token_naming_a_different_virtual_server() {
            let f = fixture();
            let token = f.token(|c| {
                c.virtual_server_id = Uuid::new_v4().to_string();
            });
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        // `allowed_virtual_server_ids` is deliberately built from the claim, not
        // from the addressed slug — but no test can observe the difference, and
        // one that pretended to would be the very shape it claims to guard
        // against. The equality check above makes the two provably equal on
        // every path that reaches the assignment, so
        // `rejects_a_token_naming_a_different_virtual_server` is the whole
        // guard: it is what stops the two diverging in the first place.

        // Refresh-token-as-access-bearer is refused by `decode_and_verify`'s
        // `typ` check, which owns that rule and tests it directly
        // (`streamscope_mcp_auth::jwt::tests::refresh_typed_token_rejected_as_access`).
        // Re-proving it here would mean pulling `jsonwebtoken` into the proxy
        // solely to forge a token this crate can't legitimately mint.

        #[tokio::test]
        async fn rejects_a_revoked_jti() {
            let jti = Uuid::new_v4();
            let mut f = fixture_with(|cfg| {
                cfg.mcp.revoked_jtis = HashSet::from([jti]);
            });
            f.jti = jti;
            let token = f.token(|_| {});
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        /// Turning OAuth off on a virtual server must stop already-issued
        /// tokens, not merely stop new ones being minted.
        #[tokio::test]
        async fn rejects_when_the_virtual_server_has_oauth_disabled() {
            let f = fixture_with(|cfg| {
                cfg.mcp
                    .virtual_servers
                    .values_mut()
                    .next()
                    .expect("fixture inserts one virtual server")
                    .oauth_enabled = false;
            });
            let token = f.token(|_| {});
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        /// The audience follows the tenant's **resolved** proxy URL, which is
        /// its own override when it has one and the SYSTEM default otherwise.
        ///
        /// Both directions are refused, and both are reachable in production: a
        /// tenant that adopts an override invalidates tokens minted under the
        /// shared default, and a tenant whose override is withdrawn invalidates
        /// the ones minted under it. The tempting "accept either" fallback would
        /// mean a tenant on the shared default could mint a token that keeps
        /// working after an operator moves it behind its own hostname — the
        /// audience would stop naming where the token is actually usable.
        ///
        /// The sibling worry — two tenants with the same slug resolving to the
        /// same default origin, hence the same audience — cannot arise: a
        /// partial unique index makes an OAuth-enabled slug globally unique
        /// (`mcp_virtual_servers_oauth_slug_unique`), so one slug has exactly
        /// one owning tenant. Keep that index if this reasoning is to hold.
        #[tokio::test]
        async fn rejects_a_token_minted_under_a_different_resolved_proxy_url() {
            const TENANT_OVERRIDE: &str = "https://acme-gw.example.test";

            // Minted under the shared default, presented after the tenant took
            // an override.
            let f = fixture_with(|cfg| {
                cfg.proxy_public_url = Some(TENANT_OVERRIDE.to_string());
            });
            let minted_under_default = f.token(|c| {
                c.aud = audience_for_slug(PROXY_URL, SLUG);
            });
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &minted_under_default)
                    .await.map(|c| c.user)
                    .is_err(),
                "a token whose audience names the shared default must not pass \
                 once the tenant resolves its own origin"
            );

            // ...and the reverse: minted under the override, presented after it
            // was withdrawn.
            let g = fixture();
            let minted_under_override = g.token(|c| {
                c.aud = audience_for_slug(TENANT_OVERRIDE, SLUG);
            });
            assert!(
                validate_jwt_bearer(&g.state, SLUG, &minted_under_override)
                    .await.map(|c| c.user)
                    .is_err(),
                "a token whose audience names a withdrawn override must not pass"
            );

            // The matching combination still authenticates, so the two
            // rejections above are about the audience and not about the
            // fixture being broken.
            let ok = f.token(|c| {
                c.aud = audience_for_slug(TENANT_OVERRIDE, SLUG);
            });
            validate_jwt_bearer(&f.state, SLUG, &ok)
                .await.map(|c| c.user)
                .expect("the audience matching the resolved override is accepted");
        }

        /// An operator misconfiguration (no resolved proxy URL) must fail
        /// closed and surface as unavailable, never as a client credential
        /// error — the audience cannot be computed, so nothing can be trusted.
        #[tokio::test]
        async fn fails_closed_when_the_tenant_has_no_proxy_url() {
            let f = fixture_with(|cfg| {
                cfg.proxy_public_url = None;
            });
            let token = f.token(|_| {});
            let err = validate_jwt_bearer(&f.state, SLUG, &token)
                .await.map(|c| c.user)
                .expect_err("must not authenticate without a resolvable audience");
            assert_matches!(
                err,
                AppError::Auth(AuthError::ServiceUnavailable(_)),
                "operator misconfig must render 503, not 401"
            );
        }

        /// The tenant is picked from the token's own (unverified) claim, so a
        /// token whose tenant isn't in this replica's registry must be refused
        /// rather than falling back to any other tenant's config.
        #[tokio::test]
        async fn rejects_a_token_for_an_unknown_tenant() {
            let f = fixture();
            let token = f.token(|c| {
                c.tenant_id = Uuid::new_v4().to_string();
            });
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        #[tokio::test]
        async fn rejects_a_token_signed_with_the_wrong_secret() {
            let f = fixture();
            let token = encode_access_token(
                &f.claims(),
                &ring("a-completely-different-auth-secret-32ch"),
            )
            .expect("mint under the wrong secret");
            assert!(
                validate_jwt_bearer(&f.state, SLUG, &token)
                    .await.map(|c| c.user)
                    .is_err()
            );
        }

        #[tokio::test]
        async fn rejects_an_expired_token() {
            let f = fixture();
            let token = f.token(|c| {
                // Well outside jsonwebtoken's 60s default leeway.
                c.iat = chrono::Utc::now().timestamp() - 7200;
                c.exp = chrono::Utc::now().timestamp() - 3600;
            });
            let err = validate_jwt_bearer(&f.state, SLUG, &token)
                .await.map(|c| c.user)
                .expect_err("expired token must be refused");
            assert_matches!(
                err,
                AppError::Auth(AuthError::KeyExpired(_)),
                "expiry must be distinguishable from a bad signature"
            );
        }

        /// A claim that should be a UUID but isn't must be refused outright,
        /// never coerced to nil (which would collapse distinct principals).
        #[tokio::test]
        async fn rejects_non_uuid_identity_claims() {
            for mutate in [
                (|c: &mut McpAccessClaims| c.sub = "not-a-uuid".into())
                    as fn(&mut McpAccessClaims),
                |c: &mut McpAccessClaims| c.workspace_id = "not-a-uuid".into(),
                |c: &mut McpAccessClaims| c.jti = "not-a-uuid".into(),
            ] {
                let f = fixture();
                let token = f.token(mutate);
                assert!(
                    validate_jwt_bearer(&f.state, SLUG, &token)
                        .await.map(|c| c.user)
                        .is_err()
                );
            }
        }
    }
}
