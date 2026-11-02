//! MCP gateway CRUD — upstream servers + virtual servers + virtual routes.
//!
//! All four upstream auth modes (`no_auth`, `service_account`, `per_user_oauth`,
//! `byot`) are honored end-to-end by the proxy. The admin surface persists
//! the row shape; the proxy resolves the bearer per request.


use streamscope_mcp_auth::ssrf::Egress;
use streamscope_mcp_auth::egress::Surface;
use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use streamscope_core::config::mcp::is_valid_route_prefix;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, TotalPage};
use crate::db::tenant::TenantConn;

// ---------------------------------------------------------------------------
// Validation helpers — kept here so the JSON shape on the wire matches the
// one synced to proxies.
// ---------------------------------------------------------------------------

const VALID_TRANSPORTS: &[&str] = &["streamable_http", "sse"];
const VALID_AUTH_MODES: &[&str] = &["no_auth", "service_account", "per_user_oauth", "byot"];

/// Slug pattern: `^[a-z][a-z0-9-]{0,30}$` — bookmark-stable, URL-safe.
pub(crate) fn is_valid_slug(s: &str) -> bool {
    let len = s.len();
    if !(1..=31).contains(&len) {
        return false;
    }
    let mut bytes = s.bytes();
    match bytes.next() {
        Some(b) if b.is_ascii_lowercase() => {}
        _ => return false,
    }
    bytes.all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}


/// What [`is_valid_route_prefix`] accepts, in the words a caller is told.
const PREFIX_RULE: &str = "prefix must be empty, or up to 16 lowercase letters, digits and single underscores, starting with a letter and not ending in an underscore";

// Spec-OAuth requires an OAuth-enabled slug to be unique ACROSS tenants: the
// protected-resource-metadata endpoint at
// `/.well-known/oauth-protected-resource/mcp/<slug>` is unauthenticated, so a slug
// claimed by two tenants would be unresolvable.
//
// The rule is enforced by the partial unique index
// `mcp_virtual_servers_oauth_slug_unique (slug) WHERE oauth_enabled` — the create
// and update handlers below map its violation to `McpOauthSlugCollision`. It
// cannot be pre-checked in the application: the runtime role is `NOBYPASSRLS`
// against a `FORCE`d RLS policy, so a SELECT for another tenant's row matches zero
// rows by construction. The index is the only thing that can see across tenants.

// ===========================================================================
// MCP UPSTREAM SERVERS
// ===========================================================================

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpUpstreamServerRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub upstream_url: String,
    pub transport: String,
    pub auth_mode: String,
    pub enabled: bool,
    pub connect_timeout_ms: i32,
    pub request_timeout_ms: i32,
    pub cred_version: i64,
    /// Presence-only signal. `true` iff `encrypted_credential`
    /// IS NOT NULL on the underlying row. The plaintext is never echoed.
    pub has_credential: bool,
    // ── Per-user OAuth client config ──
    pub oauth_issuer_url: Option<String>,
    pub oauth_authorization_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_revocation_url: Option<String>,
    pub oauth_client_id: Option<String>,
    /// Presence-only signal for the encrypted client secret. `true` iff the
    /// underlying row has a non-NULL `encrypted_oauth_client_secret`.
    pub has_oauth_client_secret: bool,
    pub oauth_default_scopes: Vec<String>,
    /// `true` for synthetic gateway-managed rows (e.g. `builtin-web` for the
    /// built-in web-search virtual server). The admin UI surfaces a
    /// `<SystemRowBadge>` and disables Edit/Delete for these — operators
    /// configure them through the matching settings tab, not the upstream
    /// CRUD form.
    pub built_in: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateMcpUpstreamServer {
    pub name: String,
    pub description: Option<String>,
    pub upstream_url: String,
    /// Defaults to `"streamable_http"`.
    pub transport: Option<String>,
    /// Defaults to `"no_auth"`. All four modes (`"no_auth"`,
    /// `"service_account"`, `"per_user_oauth"`, `"byot"`) are honored.
    pub auth_mode: Option<String>,
    /// Bearer token plaintext. Required when `auth_mode =
    /// "service_account"`; rejected when any other auth_mode is set. Encrypted
    /// at rest with AES-256-GCM (`ENCRYPTION_KEY` HKDF-derived). Never echoed
    /// in responses — `has_credential: bool` surfaces presence.
    pub credential: Option<String>,
    // ── Per-user OAuth client config ──
    /// Required when `auth_mode = "per_user_oauth"`. Forbidden otherwise.
    pub oauth_issuer_url: Option<String>,
    pub oauth_authorization_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_revocation_url: Option<String>,
    pub oauth_client_id: Option<String>,
    /// Plaintext client secret (encrypted at rest, never echoed in responses).
    /// Required when `auth_mode = "per_user_oauth"`; forbidden otherwise.
    pub oauth_client_secret: Option<String>,
    pub oauth_default_scopes: Option<Vec<String>>,
    pub enabled: Option<bool>,
    pub connect_timeout_ms: Option<i32>,
    pub request_timeout_ms: Option<i32>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMcpUpstreamServer {
    pub name: Option<String>,
    /// `null` or `""` clears it; absent leaves it.
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub description: Option<String>,
    pub upstream_url: Option<String>,
    pub transport: Option<String>,
    /// Locked post-create — only accepted when equal to the existing value
    /// (idempotent passthrough). Any other value rejects with
    /// `McpUpstreamAuthModeLocked`. Each mode carries a distinct credential
    /// shape; flips would silently strand or drop credentials.
    pub auth_mode: Option<String>,
    /// Rotate the service-account bearer token. Empty string rejects with
    /// `McpUpstreamCredentialRequired`; supplying any value on a
    /// non-`service_account` row rejects with `McpUpstreamCredentialNotAllowed`.
    /// Absent preserves the existing ciphertext.
    pub credential: Option<String>,
    // ── Per-user OAuth client config ──
    pub oauth_issuer_url: Option<String>,
    pub oauth_authorization_url: Option<String>,
    pub oauth_token_url: Option<String>,
    /// Optional for every mode, so clearable: `null` or `""` clears it.
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub oauth_revocation_url: Option<String>,
    pub oauth_client_id: Option<String>,
    /// Rotate the OAuth client secret. Absent preserves the existing
    /// ciphertext (no clear-via-empty-string — the resulting-shape check
    /// would reject a per_user_oauth row without a secret).
    pub oauth_client_secret: Option<String>,
    /// Optional for every mode, so clearable: `null` or `[]` clears them.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<Vec<String>>)]
    pub oauth_default_scopes: Option<Option<Vec<String>>>,
    pub enabled: Option<bool>,
    pub connect_timeout_ms: Option<i32>,
    pub request_timeout_ms: Option<i32>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct McpUpstreamServerListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// Treat an empty string as absent so callers never thread `Some("")` into
/// validators or `.bind(...)` (which would write `""` into a nullable TEXT
/// column even though every shape check uses `is_empty()` to mean "not set").
fn nonempty_str(s: Option<&str>) -> Option<&str> {
    s.filter(|v| !v.is_empty())
}

/// Treat an empty `Vec` as absent — same canonical-shape rule as
/// [`nonempty_str`] for `TEXT[]` columns where `[]` would mask "unset".
fn nonempty_vec<T>(v: Option<&Vec<T>>) -> Option<&Vec<T>> {
    v.filter(|v| !v.is_empty())
}

/// Validate every operator-supplied URL on the row against the SSRF guard.
/// Catches IP literals (loopback / RFC 1918 / link-local / IMDS / multicast)
/// at write time so the proxy and admin-api callers never fan out to them.
/// Hostnames pass — DNS-rebinding is a separate concern and the trust
/// boundary here is "an admin typed it", not "anyone can register one".
fn validate_outbound_urls(
    upstream_url: Option<&str>,
    oauth_issuer_url: Option<&str>,
    oauth_authorization_url: Option<&str>,
    oauth_token_url: Option<&str>,
    oauth_revocation_url: Option<&str>,
    egress: Egress,
) -> Result<(), ApiError> {
    let candidates: [(&str, Option<&str>); 5] = [
        ("upstream_url", upstream_url),
        ("oauth_issuer_url", oauth_issuer_url),
        ("oauth_authorization_url", oauth_authorization_url),
        ("oauth_token_url", oauth_token_url),
        ("oauth_revocation_url", oauth_revocation_url),
    ];
    for (label, url) in candidates {
        // Empty strings are passed through as "clear / no value here" — the
        // resulting-shape check downstream is where empty surfaces as a typed
        // `McpUpstreamOauthClientIncomplete`. Running the SSRF guard on an
        // empty string would short-circuit with a generic `validation_failed`
        // and mask the real error code.
        if let Some(u) = url
            && !u.is_empty()
            && let Err(e) = streamscope_mcp_auth::ssrf::check_url_for(u, egress)
        {
            // An unlisted internal address is the egress policy's refusal, not a
            // bad URL: it answers `egress_refused` and names the list that
            // decided it, so an admin knows where the fix is.
            return Err(match (e, egress) {
                (streamscope_mcp_auth::SsrfError::InternalAddress, Egress::Surface(surface)) => {
                    ApiError::bad_request(format!(
                        "{label}: this address is internal and the platform's {} egress list does \
                         not open it (no list opens the cloud metadata endpoint) — a platform \
                         administrator lists a private address under Settings → Egress (SYSTEM).",
                        surface.as_str()
                    ))
                    .code(ApiErrorCode::EgressRefused)
                }
                (e, _) => ApiError::bad_request(format!("{label} rejected by SSRF guard: {e}")),
            });
        }
    }
    Ok(())
}

/// What MCP upstream URLs may point at: an internal address only when the
/// platform's `mcp` egress list lists it, at write-time validation and OAuth
/// discovery alike — a deployment-level decision, never a per-tenant one.
pub(crate) const MCP_EGRESS: Egress = Egress::Surface(Surface::Mcp);

fn validate_upstream_create(body: &CreateMcpUpstreamServer, egress: Egress) -> Result<(), ApiError> {
    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    if !body.upstream_url.starts_with("http://") && !body.upstream_url.starts_with("https://") {
        return Err(ApiError::bad_request("upstream_url must be http(s)://..."));
    }
    if let Some(t) = &body.transport
        && !VALID_TRANSPORTS.contains(&t.as_str())
    {
        return Err(ApiError::bad_request("transport must be one of: streamable_http, sse"));
    }
    if let Some(a) = &body.auth_mode
        && !VALID_AUTH_MODES.contains(&a.as_str())
    {
        return Err(ApiError::bad_request(
            "auth_mode must be one of: no_auth, service_account, per_user_oauth, byot",
        ));
    }
    validate_outbound_urls(
        Some(body.upstream_url.as_str()),
        body.oauth_issuer_url.as_deref(),
        body.oauth_authorization_url.as_deref(),
        body.oauth_token_url.as_deref(),
        body.oauth_revocation_url.as_deref(),
        egress,
    )?;
    Ok(())
}

/// Validate the `(auth_mode, credential)` shape on create/update.
///
/// Rules:
/// - `auth_mode = service_account` + credential missing/empty on **create** →
///   `McpUpstreamCredentialRequired` (you can't ship a service-account row
///   without a token; the proxy would 503 every request).
/// - `auth_mode = service_account` + empty-string credential (any op) →
///   `McpUpstreamCredentialRequired` (use `auth_mode = no_auth` to clear).
/// - `auth_mode != service_account` + credential set → `McpUpstreamCredentialNotAllowed`
///   (the field is meaningless outside service_account; surface the
///   contradiction rather than silently dropping).
/// - `auth_mode = None` (PATCH not changing auth_mode) + credential set → allow
///   (rotation case — caller is rotating the token without changing mode).
///   Caller is responsible for the row's resulting shape.
fn validate_credential_shape(
    auth_mode: Option<&str>,
    credential: Option<&str>,
    is_create: bool,
) -> Result<(), ApiError> {
    let auth_mode = auth_mode.map(str::trim);
    let credential = credential.map(str::trim);

    // On create, omitted auth_mode defaults to "no_auth" downstream — fold
    // that defaulting into validation so a credential supplied alongside an
    // omitted auth_mode is rejected with `McpUpstreamCredentialNotAllowed`
    // rather than silently encrypted into a no_auth row.
    let effective_auth_mode = if is_create { auth_mode.or(Some("no_auth")) } else { auth_mode };

    match (effective_auth_mode, credential, is_create) {
        // service_account on create — credential required.
        (Some("service_account"), None, true) | (Some("service_account"), Some(""), true) => {
            Err(ApiError::bad_request(
                "credential is required when auth_mode = service_account",
            )
            .code(ApiErrorCode::McpUpstreamCredentialRequired))
        }
        // Empty-string credential while in service_account mode (any op).
        (Some("service_account"), Some(""), false) => Err(ApiError::bad_request(
            "credential must be a non-empty bearer token; to clear, set auth_mode = no_auth",
        )
        .code(ApiErrorCode::McpUpstreamCredentialRequired)),
        // Credential supplied with non-service-account auth_mode.
        (Some(other), Some(c), _) if other != "service_account" && !c.is_empty() => {
            Err(ApiError::bad_request(
                "credential is only valid when auth_mode = service_account",
            )
            .code(ApiErrorCode::McpUpstreamCredentialNotAllowed))
        }
        _ => Ok(()),
    }
}

/// Validate the OAuth client config shape.
///
/// On create with `auth_mode = per_user_oauth`, every required field must
/// be present (issuer URL, authorization URL, token URL, client_id,
/// client_secret). When auth_mode is anything else, none of the OAuth
/// client fields may be supplied — surface the contradiction rather than
/// silently dropping the operator's input.
///
/// On update we apply the same rule based on the **effective** auth_mode
/// after the patch — if the row's existing auth_mode is `per_user_oauth`
/// and the patch doesn't change it, the OAuth fields are allowed; if the
/// patch flips to `per_user_oauth`, the operator must supply the missing
/// fields.
#[allow(clippy::too_many_arguments)]
fn validate_oauth_client_shape(
    effective_auth_mode: Option<&str>,
    issuer_url: Option<&str>,
    auth_url: Option<&str>,
    token_url: Option<&str>,
    revocation_url: Option<&str>,
    client_id: Option<&str>,
    client_secret: Option<&str>,
    default_scopes: Option<&Vec<String>>,
    is_create: bool,
) -> Result<(), ApiError> {
    let any_oauth_field_set = issuer_url.is_some_and(|s| !s.is_empty())
        || auth_url.is_some_and(|s| !s.is_empty())
        || token_url.is_some_and(|s| !s.is_empty())
        || revocation_url.is_some_and(|s| !s.is_empty())
        || client_id.is_some_and(|s| !s.is_empty())
        || client_secret.is_some_and(|s| !s.is_empty())
        || default_scopes.is_some_and(|v| !v.is_empty());

    match (effective_auth_mode, is_create) {
        (Some("per_user_oauth"), true) => {
            for (field, value) in [
                ("oauth_issuer_url", issuer_url),
                ("oauth_authorization_url", auth_url),
                ("oauth_token_url", token_url),
                ("oauth_client_id", client_id),
                ("oauth_client_secret", client_secret),
            ] {
                if value.is_none_or(str::is_empty) {
                    return Err(ApiError::bad_request(format!(
                        "{field} is required when auth_mode = per_user_oauth"
                    ))
                    .code(ApiErrorCode::McpUpstreamOauthClientIncomplete));
                }
            }
            Ok(())
        }
        (Some(other), _) if other != "per_user_oauth" && any_oauth_field_set => {
            Err(ApiError::bad_request(
                "oauth_* fields are only valid when auth_mode = per_user_oauth",
            )
            .code(ApiErrorCode::McpUpstreamOauthClientNotAllowed))
        }
        _ => Ok(()),
    }
}

/// Validate the OAuth client config shape on a PATCH that lands on
/// `per_user_oauth`. Composes `(patch ∪ existing)` and rejects when any
/// required field is empty/missing. Mirrors the create-time validation in
/// `validate_oauth_client_shape`'s `(Some("per_user_oauth"), true)` arm.
fn validate_oauth_client_resulting_shape(
    issuer_url: Option<&str>,
    auth_url: Option<&str>,
    token_url: Option<&str>,
    client_id: Option<&str>,
    secret_present: bool,
) -> Result<(), ApiError> {
    let mut missing: Vec<&str> = Vec::new();
    if issuer_url.is_none_or(str::is_empty) {
        missing.push("oauth_issuer_url");
    }
    if auth_url.is_none_or(str::is_empty) {
        missing.push("oauth_authorization_url");
    }
    if token_url.is_none_or(str::is_empty) {
        missing.push("oauth_token_url");
    }
    if client_id.is_none_or(str::is_empty) {
        missing.push("oauth_client_id");
    }
    if !secret_present {
        missing.push("oauth_client_secret");
    }
    if missing.is_empty() {
        Ok(())
    } else {
        Err(ApiError::bad_request(format!(
            "auth_mode = per_user_oauth requires: {}",
            missing.join(", ")
        ))
        .code(ApiErrorCode::McpUpstreamOauthClientIncomplete))
    }
}

/// Enforce the BYOT single-route invariant on
/// `mcp_virtual_routes`. A virtual server may host either:
///   * exactly one route bound to a `byot` upstream, OR
///   * any number of routes bound to non-`byot` upstreams.
///
/// Mixing the two modes breaks the forward-auth contract (a `vk-*`
/// agent's bearer can't be split across upstreams). `excluded_route_id`
/// lets the PATCH path ignore the row being updated when counting
/// siblings.
async fn validate_byot_route_invariant(
    db: &mut TenantConn,
    virtual_server_id: Uuid,
    upstream_server_id: Uuid,
    excluded_route_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let new_auth_mode: String = sqlx::query_scalar(
        "SELECT auth_mode FROM mcp_upstream_servers WHERE id = $1",
    )
    .bind(upstream_server_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("validate byot route lookup upstream: {e}");
        ApiError::internal("failed to validate route")
    })?;

    // Pull every other route on this virtual server with its upstream's mode.
    let sibling_modes: Vec<(Uuid, String)> = if let Some(excl) = excluded_route_id {
        sqlx::query_as::<_, (Uuid, String)>(
            r#"SELECT r.id, u.auth_mode
               FROM mcp_virtual_routes r
               JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
               WHERE r.virtual_server_id = $1 AND r.id <> $2"#,
        )
        .bind(virtual_server_id)
        .bind(excl)
    } else {
        sqlx::query_as::<_, (Uuid, String)>(
            r#"SELECT r.id, u.auth_mode
               FROM mcp_virtual_routes r
               JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
               WHERE r.virtual_server_id = $1"#,
        )
        .bind(virtual_server_id)
    }
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("validate byot route count siblings: {e}");
        ApiError::internal("failed to validate route")
    })?;

    let any_sibling_is_byot = sibling_modes.iter().any(|(_, m)| m == "byot");
    let new_is_byot = new_auth_mode == "byot";

    if new_is_byot && !sibling_modes.is_empty() {
        return Err(ApiError::bad_request(
            "byot upstream can only be routed to a virtual server with no other routes",
        )
        .code(ApiErrorCode::McpKeyMultiUpstream));
    }
    if !new_is_byot && any_sibling_is_byot {
        return Err(ApiError::bad_request(
            "this virtual server already has a byot route; byot requires exclusive single-route binding",
        )
        .code(ApiErrorCode::McpKeyMultiUpstream));
    }
    Ok(())
}

/// The OAuth-client fields a `per_user_oauth` upstream must carry before its
/// endpoint can be granted to a workspace or connected by a portal user. This
/// is the single source of truth for "is the OAuth client complete?" — the
/// grant gate, the adopt gate, and (in spirit) the portal connect path and the
/// admin-UI completeness badge all use this exact set: client_id, client
/// secret, authorization_url, token_url. (Issuer URL is informational and not
/// required to start the auth-code flow.)
///
/// Invariant: keep this in sync with the portal connect check
/// (`portal_mcp_connections`) and the UI badge (`has_oauth_client_secret` +
/// `oauth_client_id`/URLs on `McpUpstreamServerRow`).
pub(crate) fn oauth_client_missing_fields(
    client_id: Option<&str>,
    has_secret: bool,
    authorization_url: Option<&str>,
    token_url: Option<&str>,
) -> Vec<&'static str> {
    let mut missing: Vec<&'static str> = Vec::new();
    if client_id.is_none_or(str::is_empty) {
        missing.push("oauth_client_id");
    }
    if !has_secret {
        missing.push("oauth_client_secret");
    }
    if authorization_url.is_none_or(str::is_empty) {
        missing.push("oauth_authorization_url");
    }
    if token_url.is_none_or(str::is_empty) {
        missing.push("oauth_token_url");
    }
    missing
}

/// Ensure every `per_user_oauth` upstream routed by a virtual server carries a
/// complete OAuth client before the endpoint is exposed to a workspace. The
/// Client ID / Secret are a single tenant-wide OAuth-App credential that
/// identifies the gateway to the provider; without it no portal user can begin
/// their per-account login, so granting an incomplete endpoint produces one
/// that fails every connect. Non-`per_user_oauth` upstreams pass through
/// untouched.
pub(crate) async fn ensure_endpoint_oauth_grantable(
    db: &mut TenantConn,
    virtual_server_id: Uuid,
) -> Result<(), ApiError> {
    let routed = sqlx::query_as::<_, (String, Option<String>, bool, Option<String>, Option<String>)>(
        r#"SELECT u.name, u.oauth_client_id,
                  (u.encrypted_oauth_client_secret IS NOT NULL) AS has_secret,
                  u.oauth_authorization_url, u.oauth_token_url
           FROM mcp_virtual_routes r
           JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
           WHERE r.virtual_server_id = $1 AND u.auth_mode = 'per_user_oauth'"#,
    )
    .bind(virtual_server_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("grant gate: resolve routed oauth upstreams: {e}");
        ApiError::internal("failed to validate endpoint")
    })?;

    for (name, client_id, has_secret, auth_url, token_url) in routed {
        let missing = oauth_client_missing_fields(
            client_id.as_deref(),
            has_secret,
            auth_url.as_deref(),
            token_url.as_deref(),
        );
        if !missing.is_empty() {
            return Err(ApiError::bad_request(format!(
                "MCP server \"{name}\" uses per_user_oauth but its OAuth client is incomplete \
                 (missing: {}); set the OAuth client ID and secret on the upstream before \
                 granting this endpoint to a workspace",
                missing.join(", ")
            ))
            .code(ApiErrorCode::McpUpstreamOauthClientIncomplete));
        }
    }
    Ok(())
}

/// Encrypt the bearer-token plaintext for storage in
/// `mcp_upstream_servers.encrypted_credential` (BYTEA holding base64 UTF-8
/// bytes). Returns `Ok(None)` when no credential is supplied; returns
/// `Ok(Some(bytes))` on success. Fails fast with HTTP 503 when
/// `ENCRYPTION_KEY` is unset, mirroring the LLM upstream encrypt helper.
pub(crate) fn encrypt_mcp_credential(credential: Option<&str>) -> Result<Option<Vec<u8>>, ApiError> {
    match credential {
        Some(plain) if !plain.is_empty() => {
            let key = streamscope_core::crypto::get_encryption_key().ok_or_else(|| {
                tracing::error!("ENCRYPTION_KEY not set — refusing to store mcp upstream credential");
                ApiError::server_misconfigured("ENCRYPTION_KEY not configured")
            })?;
            let encrypted = streamscope_core::crypto::encrypt(plain, &key).map_err(|e| {
                tracing::error!("encrypt mcp upstream credential: {e}");
                ApiError::internal("failed to encrypt credential")
            })?;
            Ok(Some(encrypted.into_bytes()))
        }
        _ => Ok(None),
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/upstream-servers",
    tag = "MCP Servers",
    params(McpUpstreamServerListQuery),
    responses(
        (status = 200, description = "Paginated list of MCP upstream servers", body = TotalPage<McpUpstreamServerRow>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mcp_upstream_servers(
    mut db: TenantConn,
    Query(query): Query<McpUpstreamServerListQuery>,
) -> Result<Json<TotalPage<McpUpstreamServerRow>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mcp_upstream_servers")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count mcp_upstream_servers: {e}");
            ApiError::internal("failed to list mcp upstream servers")
        })?;
    let rows = sqlx::query_as::<_, McpUpstreamServerRow>(
        r#"SELECT id, name, description, upstream_url, transport, auth_mode, enabled,
                  connect_timeout_ms, request_timeout_ms, cred_version,
                  (encrypted_credential IS NOT NULL) AS has_credential,
                  oauth_issuer_url, oauth_authorization_url, oauth_token_url,
                  oauth_revocation_url, oauth_client_id,
                  (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret,
                  COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes,
                  built_in, created_at, updated_at
           FROM mcp_upstream_servers
           ORDER BY name LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp_upstream_servers: {e}");
        ApiError::internal("failed to list mcp upstream servers")
    })?;
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/upstream-servers/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Upstream server ID")),
    responses(
        (status = 200, description = "MCP upstream server", body = McpUpstreamServerRow),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mcp_upstream_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<McpUpstreamServerRow>, ApiError> {
    let row = sqlx::query_as::<_, McpUpstreamServerRow>(
        r#"SELECT id, name, description, upstream_url, transport, auth_mode, enabled,
                  connect_timeout_ms, request_timeout_ms, cred_version,
                  (encrypted_credential IS NOT NULL) AS has_credential,
                  oauth_issuer_url, oauth_authorization_url, oauth_token_url,
                  oauth_revocation_url, oauth_client_id,
                  (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret,
                  COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes,
                  built_in, created_at, updated_at
           FROM mcp_upstream_servers
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get mcp_upstream_server: {e}");
        ApiError::internal("failed to fetch mcp upstream server")
    })?
    .ok_or_else(|| ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound))?;
    Ok(Json(row))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/upstream-servers",
    tag = "MCP Servers",
    request_body = CreateMcpUpstreamServer,
    responses(
        (status = 201, description = "Created", body = McpUpstreamServerRow),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 409, description = "Name taken", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mcp_upstream_server(
    mut db: TenantConn,
    Json(body): Json<CreateMcpUpstreamServer>,
) -> Result<(StatusCode, Json<McpUpstreamServerRow>), ApiError> {
    let egress = MCP_EGRESS;
    validate_upstream_create(&body, egress)?;
    validate_credential_shape(body.auth_mode.as_deref(), body.credential.as_deref(), true)?;
    let effective_auth_mode_for_oauth = body.auth_mode.as_deref().or(Some("no_auth"));
    // Empty oauth_* strings/arrays are normalised to "absent" so the canonical
    // row shape never carries `""` or `[]` in a column that should be NULL.
    // Mirrors the `description` empty→NULL pattern below.
    let oauth_issuer_url = nonempty_str(body.oauth_issuer_url.as_deref());
    let oauth_authorization_url = nonempty_str(body.oauth_authorization_url.as_deref());
    let oauth_token_url = nonempty_str(body.oauth_token_url.as_deref());
    let oauth_revocation_url = nonempty_str(body.oauth_revocation_url.as_deref());
    let oauth_client_id = nonempty_str(body.oauth_client_id.as_deref());
    let oauth_client_secret = nonempty_str(body.oauth_client_secret.as_deref());
    let oauth_default_scopes = nonempty_vec(body.oauth_default_scopes.as_ref());
    validate_oauth_client_shape(
        effective_auth_mode_for_oauth,
        oauth_issuer_url,
        oauth_authorization_url,
        oauth_token_url,
        oauth_revocation_url,
        oauth_client_id,
        oauth_client_secret,
        oauth_default_scopes,
        true,
    )?;
    let transport = body.transport.unwrap_or_else(|| "streamable_http".into());
    let auth_mode = body.auth_mode.unwrap_or_else(|| "no_auth".into());
    let enabled = body.enabled.unwrap_or(true);
    let connect_timeout_ms = body.connect_timeout_ms.unwrap_or(10_000);
    let request_timeout_ms = body.request_timeout_ms.unwrap_or(60_000);
    let encrypted_credential = encrypt_mcp_credential(body.credential.as_deref())?;
    let encrypted_oauth_client_secret = encrypt_mcp_credential(oauth_client_secret)?;
    // Normalize description so create + patch agree on the "empty means NULL"
    // semantics — keeps a single canonical row shape regardless of which
    // endpoint set the value.
    let description = body
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let row = sqlx::query_as::<_, McpUpstreamServerRow>(
        r#"INSERT INTO mcp_upstream_servers
               (tenant_id, name, description, upstream_url, transport, auth_mode,
                enabled, connect_timeout_ms, request_timeout_ms, encrypted_credential,
                oauth_issuer_url, oauth_authorization_url, oauth_token_url,
                oauth_revocation_url, oauth_client_id, encrypted_oauth_client_secret,
                oauth_default_scopes)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                   $11, $12, $13, $14, $15, $16, $17)
           RETURNING id, name, description, upstream_url, transport, auth_mode, enabled,
                     connect_timeout_ms, request_timeout_ms, cred_version,
                     (encrypted_credential IS NOT NULL) AS has_credential,
                     oauth_issuer_url, oauth_authorization_url, oauth_token_url,
                     oauth_revocation_url, oauth_client_id,
                     (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret,
                     COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes,
                     built_in, created_at, updated_at"#,
    )
    .bind(db.tenant_uuid())
    .bind(&body.name)
    .bind(description)
    .bind(&body.upstream_url)
    .bind(&transport)
    .bind(&auth_mode)
    .bind(enabled)
    .bind(connect_timeout_ms)
    .bind(request_timeout_ms)
    .bind(encrypted_credential)
    .bind(oauth_issuer_url)
    .bind(oauth_authorization_url)
    .bind(oauth_token_url)
    .bind(oauth_revocation_url)
    .bind(oauth_client_id)
    .bind(encrypted_oauth_client_secret)
    .bind(oauth_default_scopes)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("mcp upstream server with this name already exists", ApiErrorCode::McpUpstreamServerNameTaken)
        } else {
            tracing::error!("create mcp_upstream_server: {e}");
            ApiError::internal("failed to create mcp upstream server")
        }
    })?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/mcp/upstream-servers/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Upstream server ID")),
    request_body = UpdateMcpUpstreamServer,
    responses(
        (status = 200, description = "Updated", body = McpUpstreamServerRow),
        (status = 400, description = "Invalid", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_mcp_upstream_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMcpUpstreamServer>,
) -> Result<Json<McpUpstreamServerRow>, ApiError> {
    if let Some(t) = &body.transport
        && !VALID_TRANSPORTS.contains(&t.as_str())
    {
        return Err(ApiError::bad_request("transport must be one of: streamable_http, sse"));
    }
    if let Some(a) = &body.auth_mode
        && !VALID_AUTH_MODES.contains(&a.as_str())
    {
        return Err(ApiError::bad_request(
            "auth_mode must be one of: no_auth, service_account, per_user_oauth, byot",
        ));
    }
    if let Some(url) = &body.upstream_url
        && !url.starts_with("http://")
        && !url.starts_with("https://")
    {
        return Err(ApiError::bad_request("upstream_url must be http(s)://..."));
    }
    // Empty oauth_* strings/arrays are normalised to "absent" so a PATCH like
    // `{oauth_token_url: ""}` on a non-`per_user_oauth` row never lands `""` in
    // the column via `COALESCE($N, oauth_token_url)`. Mirrors `description_param`
    // below — the canonical row shape is "field set or NULL", never empty.
    let oauth_issuer_url = nonempty_str(body.oauth_issuer_url.as_deref());
    let oauth_authorization_url = nonempty_str(body.oauth_authorization_url.as_deref());
    let oauth_token_url = nonempty_str(body.oauth_token_url.as_deref());
    let oauth_revocation_url = nonempty_str(body.oauth_revocation_url.as_deref());
    let oauth_client_id = nonempty_str(body.oauth_client_id.as_deref());
    let oauth_client_secret = nonempty_str(body.oauth_client_secret.as_deref());
    let oauth_default_scopes = nonempty_vec(body.oauth_default_scopes.as_ref().and_then(Option::as_ref));

    let egress = MCP_EGRESS;
    validate_outbound_urls(
        body.upstream_url.as_deref(),
        oauth_issuer_url,
        oauth_authorization_url,
        oauth_token_url,
        oauth_revocation_url,
        egress,
    )?;

    // Pull built_in + every column we need for shape validation in one round
    // trip. The PATCH gates on five facts about the existing row: is it
    // built-in (reject), what auth_mode is locked in (matches body when
    // supplied), are the per-user-OAuth columns already populated (required
    // for `per_user_oauth` resulting-shape check), and is the OAuth client
    // secret already on file.
    #[derive(sqlx::FromRow)]
    struct ExistingRow {
        built_in: bool,
        auth_mode: String,
        oauth_issuer_url: Option<String>,
        oauth_authorization_url: Option<String>,
        oauth_token_url: Option<String>,
        oauth_client_id: Option<String>,
        has_oauth_client_secret: bool,
    }
    let existing: ExistingRow = sqlx::query_as::<_, ExistingRow>(
        r#"SELECT built_in, auth_mode, oauth_issuer_url, oauth_authorization_url,
                  oauth_token_url, oauth_client_id,
                  (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret
           FROM mcp_upstream_servers
           WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("fetch existing upstream: {e}");
        ApiError::internal("failed to fetch existing upstream")
    })?
    .ok_or_else(|| {
        ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound)
    })?;

    // Refuse mutation on built-in (gateway-managed) rows. The synthetic
    // `internal://*` upstreams (e.g. `builtin-web` for `/mcp/web`) are
    // configured through the dedicated web admin endpoints (phase 2); the
    // generic upstream PATCH must not let an operator repoint or rename them.
    if existing.built_in {
        return Err(ApiError::conflict(
            "built-in upstream is gateway-managed; configure via the web admin endpoints",
            ApiErrorCode::McpUpstreamServerBuiltInProtected,
        ));
    }

    // auth_mode is locked post-create. Each mode carries a distinct credential
    // shape (service_account ↔ bearer, per_user_oauth ↔ client + token store,
    // byot ↔ no server-side credential); flipping silently strands or drops
    // credentials, so we surface a typed 400 here and require delete+recreate.
    if let Some(new_mode) = body.auth_mode.as_deref()
        && new_mode != existing.auth_mode
    {
        return Err(ApiError::bad_request(
            "auth_mode is locked post-create; delete and recreate the upstream to change it",
        )
        .code(ApiErrorCode::McpUpstreamAuthModeLocked));
    }

    // Validate credential + oauth shape against the locked-in auth_mode.
    // `body.auth_mode` is either absent (no_op) or equals existing.auth_mode
    // (passthrough), so we always validate against the existing row.
    let effective_auth_mode = existing.auth_mode.as_str();
    validate_credential_shape(Some(effective_auth_mode), body.credential.as_deref(), false)?;

    if effective_auth_mode == "per_user_oauth" {
        // Compose (patch ∪ existing) and reject when any required field is
        // empty/missing after the merge. Feed the **raw** `body.oauth_*` values
        // (not the empty→None normalisation) so an explicit `""` PATCH on a
        // required field surfaces as `mcp_upstream_oauth_client_incomplete`
        // rather than silently merging through to the existing value.
        let combined_secret_present = body
            .oauth_client_secret
            .as_deref()
            .map(|s| !s.is_empty())
            .unwrap_or(existing.has_oauth_client_secret);
        // MCP 2026-07-28 (SEP-2352): a client's credentials are bound to the
        // authorization server that issued them. They MUST NOT be reused with
        // a different one, and a change of authorization server MUST mean
        // re-registration.
        //
        // Without this, pointing an upstream at a new issuer while leaving the
        // stored `oauth_client_id` and secret in place would send the old
        // server's client secret to the new one on the very next connect — a
        // credential disclosure to whoever now sits at that address, and an
        // authorization flow that fails in a way the operator cannot read.
        //
        // The PATCH is refused rather than silently clearing the credentials:
        // clearing would break every existing connection with no message, and
        // the operator is the only one who can supply the new registration.
        // Trailing slashes are normalised away — an issuer identifier is a
        // URL, and one written with and without a trailing slash names the
        // same server. Setting an issuer for the FIRST time is not a change:
        // there was no prior server the credentials could belong to.
        // The issuer NAMES the authorization server; the token URL is where the
        // client secret is actually POSTed (`client_secret_post`, on both the
        // initial exchange and every refresh). Repointing either one sends the
        // stored secret somewhere new, so both are guarded — guarding only the
        // issuer would block the change that renames the server while allowing
        // the one that redirects the credential.
        let server_moved = |new: Option<&str>, old: Option<&str>| -> bool {
            match (new, old) {
                (Some(new), Some(old)) if !old.is_empty() => {
                    new.trim_end_matches('/') != old.trim_end_matches('/')
                }
                // Setting one for the FIRST time is not a move: there was no
                // prior server the credentials could belong to.
                _ => false,
            }
        };
        if (server_moved(
            nonempty_str(body.oauth_issuer_url.as_deref()),
            existing.oauth_issuer_url.as_deref(),
        ) || server_moved(
            nonempty_str(body.oauth_token_url.as_deref()),
            existing.oauth_token_url.as_deref(),
        ))
            && (existing.oauth_client_id.is_some() || existing.has_oauth_client_secret)
            // BOTH halves must be replaced, not just the id. Requiring only a
            // new `client_id` would still send the PREVIOUS server's client
            // secret to the new one on the next connect — the exact disclosure
            // this guard exists to prevent, merely with a different identifier
            // attached to it.
            && (nonempty_str(body.oauth_client_id.as_deref()).is_none()
                || nonempty_str(body.oauth_client_secret.as_deref()).is_none())
        {
            return Err(ApiError::bad_request(
                "changing oauth_issuer_url or oauth_token_url means changing authorization \
                 server, and the registered client credentials belong to the previous one — \
                 supply BOTH a new oauth_client_id and a new oauth_client_secret in the same \
                 request (register the client with the new server first)",
            )
            .code(ApiErrorCode::McpUpstreamOauthClientIncomplete));
        }

        validate_oauth_client_resulting_shape(
            body.oauth_issuer_url
                .as_deref()
                .or(existing.oauth_issuer_url.as_deref()),
            body.oauth_authorization_url
                .as_deref()
                .or(existing.oauth_authorization_url.as_deref()),
            body.oauth_token_url
                .as_deref()
                .or(existing.oauth_token_url.as_deref()),
            body.oauth_client_id
                .as_deref()
                .or(existing.oauth_client_id.as_deref()),
            combined_secret_present,
        )?;
    } else {
        // Non-per_user_oauth modes: reject oauth_* fields entirely. Same rule
        // as create — surface the contradiction rather than silently dropping.
        validate_oauth_client_shape(
            Some(effective_auth_mode),
            oauth_issuer_url,
            oauth_authorization_url,
            oauth_token_url,
            oauth_revocation_url,
            oauth_client_id,
            oauth_client_secret,
            oauth_default_scopes,
            false,
        )?;
    }

    // Credential + secret rotation: encrypt fresh ciphertext when supplied,
    // otherwise leave the existing column untouched. `auth_mode` is locked, so
    // no nullification CASE is needed — `service_account` rows always carry a
    // credential (validated above), `per_user_oauth` rows always carry the
    // client_secret (resulting-shape check), and the other two modes never had
    // either column populated to begin with.
    let encrypted_credential = match body.credential.as_deref() {
        Some(plain) if !plain.is_empty() => Some(encrypt_mcp_credential(Some(plain))?),
        _ => None,
    }
    .flatten();
    let encrypted_oauth_client_secret = oauth_client_secret
        .map(|plain| encrypt_mcp_credential(Some(plain)))
        .transpose()?
        .flatten();

    // Description-clear: empty string explicitly nulls the column. Absent
    // field preserves. The UI sends `form.description.trim()` verbatim so
    // operators can clear by emptying the input. Same rule on create.
    let description_param: Option<Option<&str>> = body.description.as_deref().map(|s| {
        let t = s.trim();
        if t.is_empty() { None } else { Some(t) }
    });

    let row = sqlx::query_as::<_, McpUpstreamServerRow>(
        r#"UPDATE mcp_upstream_servers SET
               name                   = COALESCE($2, name),
               description            = CASE
                                            WHEN $3::boolean THEN $4
                                            ELSE description
                                        END,
               upstream_url           = COALESCE($5, upstream_url),
               transport              = COALESCE($6, transport),
               enabled                = COALESCE($7, enabled),
               connect_timeout_ms     = COALESCE($8, connect_timeout_ms),
               request_timeout_ms     = COALESCE($9, request_timeout_ms),
               encrypted_credential   = COALESCE($10, encrypted_credential),
               oauth_issuer_url        = COALESCE($11, oauth_issuer_url),
               oauth_authorization_url = COALESCE($12, oauth_authorization_url),
               oauth_token_url         = COALESCE($13, oauth_token_url),
               oauth_revocation_url    = CASE WHEN $18 THEN $14 ELSE oauth_revocation_url END,
               oauth_client_id         = COALESCE($15, oauth_client_id),
               encrypted_oauth_client_secret = COALESCE($16, encrypted_oauth_client_secret),
               oauth_default_scopes    = CASE WHEN $19 THEN $17 ELSE oauth_default_scopes END,
               -- cred_version participates in the proxy capability cache key
               -- ((upstream_id, cred_version, method)). Bump only when the
               -- mutation affects what's cached: the credential, the OAuth
               -- client secret, the upstream URL, or the transport. Cosmetic
               -- edits (name, description, enabled, timeouts, oauth_*_url
               -- metadata) leave the cache valid.
               cred_version = cred_version + CASE
                   WHEN $10::bytea IS NOT NULL THEN 1
                   WHEN $16::bytea IS NOT NULL THEN 1
                   WHEN $5::text IS NOT NULL AND $5 IS DISTINCT FROM upstream_url THEN 1
                   WHEN $6::text IS NOT NULL AND $6 IS DISTINCT FROM transport THEN 1
                   ELSE 0
               END,
               updated_at = NOW()
           WHERE id = $1
           RETURNING id, name, description, upstream_url, transport, auth_mode, enabled,
                     connect_timeout_ms, request_timeout_ms, cred_version,
                     (encrypted_credential IS NOT NULL) AS has_credential,
                     oauth_issuer_url, oauth_authorization_url, oauth_token_url,
                     oauth_revocation_url, oauth_client_id,
                     (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret,
                     COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes,
                     built_in, created_at, updated_at"#,
    )
    .bind(id)
    .bind(&body.name)
    .bind(description_param.is_some())
    .bind(description_param.flatten())
    .bind(&body.upstream_url)
    .bind(&body.transport)
    .bind(body.enabled)
    .bind(body.connect_timeout_ms)
    .bind(body.request_timeout_ms)
    .bind(encrypted_credential)
    .bind(oauth_issuer_url)
    .bind(oauth_authorization_url)
    .bind(oauth_token_url)
    .bind(oauth_revocation_url)
    .bind(oauth_client_id)
    .bind(encrypted_oauth_client_secret)
    .bind(oauth_default_scopes)
    .bind(body.oauth_revocation_url.is_some()) // $18
    .bind(body.oauth_default_scopes.is_some()) // $19
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update mcp_upstream_server: {e}");
        ApiError::internal("failed to update mcp upstream server")
    })?
    .ok_or_else(|| {
        ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound)
    })?;

    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/upstream-servers/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Upstream server ID")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "In use by virtual route", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mcp_upstream_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // `WHERE NOT built_in` keeps the synthetic gateway-internal upstreams
    // (e.g. `builtin-web` for `/mcp/web`) safe from DELETE — operators get
    // a typed 409 instead of removing the proxy's only dispatch entry.
    let result = sqlx::query("DELETE FROM mcp_upstream_servers WHERE id = $1 AND NOT built_in")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            // A virtual route still references it (its foreign key is ON
            // DELETE RESTRICT), read from the SQLSTATE: locale-independent
            // (`e.to_string()` carries Postgres' translated `lc_messages` text
            // and would downgrade the typed 409 to a generic 500 outside `en`).
            if super::is_still_referenced(&e) {
                ApiError::conflict(
                    "upstream server is referenced by one or more virtual routes; \
                     detach them from the owning endpoint first",
                    ApiErrorCode::McpUpstreamServerInUse,
                )
            } else {
                tracing::error!("delete mcp_upstream_server: {e}");
                ApiError::internal("failed to delete mcp upstream server")
            }
        })?;
    if result.rows_affected() == 0 {
        // Either the row doesn't exist or it's built_in. Disambiguate so
        // the UI / curl gets the right error.
        let built_in: Option<bool> =
            sqlx::query_scalar("SELECT built_in FROM mcp_upstream_servers WHERE id = $1")
                .bind(id)
                .fetch_optional(db.conn())
                .await
                .map_err(|e| {
                    tracing::error!("disambiguate delete mcp_upstream_server: {e}");
                    ApiError::internal("failed to delete mcp upstream server")
                })?;
        return Err(match built_in {
            Some(true) => ApiError::conflict(
                "built-in upstream cannot be deleted; it is gateway-managed",
                ApiErrorCode::McpUpstreamServerBuiltInProtected,
            ),
            _ => ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound),
        });
    }
    Ok(Json(ActionResponse::ok()))
}

// ===========================================================================
// MCP UPSTREAM CONNECTIONS (per-user OAuth admin view)
// ===========================================================================
//
// Lists which tenant users have/haven't connected each per-user-OAuth
// upstream + lets the admin revoke a user's session. LEFT JOIN against
// `users` so disconnected users appear with NULL credentials columns —
// surfaces the "8 / 12 connected" tenant-wide picture in one query. The
// row delete is operator-side; the proxy picks it up in the tenant's config
// body.

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpUpstreamUserConnection {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    /// `mcp_user_credentials.created_at` for connected users; null otherwise.
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Bumped on each successful upstream call. Null when never used or not connected.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Granted OAuth scope (space-separated). Null when not connected.
    pub scope: Option<String>,
    /// True when a `mcp_user_credentials` row exists for this (user, upstream).
    pub has_session: bool,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct McpConnectionsListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// When false, only return rows for users who have actually connected.
    /// Default true (full per-user-OAuth admin view = connected + disconnected).
    pub include_disconnected: Option<bool>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/upstreams/{id}/connections",
    tag = "MCP Servers",
    params(
        ("id" = Uuid, Path, description = "Upstream MCP server ID"),
        McpConnectionsListQuery,
    ),
    responses(
        (status = 200, description = "Per-user OAuth connection state for this upstream", body = OffsetPage<McpUpstreamUserConnection>),
        (status = 404, description = "Upstream not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mcp_upstream_connections(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(query): Query<McpConnectionsListQuery>,
) -> Result<Json<OffsetPage<McpUpstreamUserConnection>>, ApiError> {
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = crate::routes::resolve_offset(query.offset);
    let include_disconnected = query.include_disconnected.unwrap_or(true);

    // Verify upstream exists in this tenant (RLS-scoped).
    let exists: Option<(Uuid,)> = sqlx::query_as(
        "SELECT id FROM mcp_upstream_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp upstream connections (existence): {e}");
        ApiError::internal("failed to check upstream existence")
    })?;
    if exists.is_none() {
        return Err(ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound));
    }

    // Connections only make sense for `per_user_oauth` upstreams. Reject
    // any other auth_mode early so callers don't render a confusing wall
    // of "disconnected" rows for service-account/byot/no_auth upstreams.
    let auth_mode: Option<(String,)> = sqlx::query_as(
        "SELECT auth_mode::text FROM mcp_upstream_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp upstream connections (auth_mode): {e}");
        ApiError::internal("failed to read upstream auth_mode")
    })?;
    if let Some((mode,)) = auth_mode
        && mode != "per_user_oauth"
    {
        return Err(ApiError::bad_request(format!(
            "connections are only available on per_user_oauth upstreams (this one is {mode})"
        ))
        .code(ApiErrorCode::McpUpstreamCredentialNotAllowed));
    }

    let connected_only_clause = if include_disconnected { "" } else { " AND c.id IS NOT NULL" };
    let sql = format!(
        "SELECT u.id AS user_id, \
                u.email AS email, \
                u.display_name AS display_name, \
                c.created_at AS connected_at, \
                c.last_used_at AS last_used_at, \
                c.scope AS scope, \
                (c.id IS NOT NULL) AS has_session \
         FROM users u \
         LEFT JOIN mcp_user_credentials c \
                ON c.user_id = u.id AND c.upstream_server_id = $1 \
         WHERE u.is_active = true{connected_only_clause} \
         ORDER BY (c.id IS NOT NULL) DESC, u.email \
         LIMIT $2 OFFSET $3"
    );

    let rows = sqlx::query_as::<_, McpUpstreamUserConnection>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list mcp upstream connections: {e}");
            ApiError::internal("failed to list connections")
        })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/upstreams/{id}/connections/{user_id}",
    tag = "MCP Servers",
    params(
        ("id" = Uuid, Path, description = "Upstream MCP server ID"),
        ("user_id" = Uuid, Path, description = "User ID whose connection to revoke"),
    ),
    responses(
        (status = 200, description = "Connection deleted", body = ActionResponse),
        (status = 404, description = "Connection not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mcp_upstream_connection(
    mut db: TenantConn,
    Path((upstream_id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Best-effort RFC 7009 revoke at the upstream IdP is the portal's
    // responsibility (see `mcp/oauth.rs` POST /actions/revoke). Admin-side
    // this is an operator-initiated cleanup: drop the row, signal the
    // proxy to refresh the per-tenant snapshot. The next request from
    // this user will fail credential resolution and force a re-connect.
    let result = sqlx::query(
        "DELETE FROM mcp_user_credentials \
         WHERE upstream_server_id = $1 AND user_id = $2",
    )
    .bind(upstream_id)
    .bind(user_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete mcp upstream connection: {e}");
        ApiError::internal("failed to delete user connection")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("user connection not found", ApiErrorCode::McpUserCredentialNotFound));
    }

    Ok(Json(ActionResponse::ok()))
}

// ===========================================================================
// MCP VIRTUAL SERVERS
// ===========================================================================

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpVirtualServerRow {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    /// MCP 2025-11-25 `serverInfo.title` — display-friendly variant of
    /// `name`. Clients show this in their UI; when null, falls back to
    /// `name`. Surfaced in the `initialize` response.
    pub display_title: Option<String>,
    /// MCP 2025-11-25 `serverInfo.websiteUrl` — optional URL the client
    /// may surface to users (e.g. linking to the product's docs).
    pub website_url: Option<String>,
    pub enabled: bool,
    /// When true, the proxy advertises spec-compliant OAuth on this
    /// virtual server. Unauthenticated requests return RFC 9728-compliant
    /// `WWW-Authenticate: Bearer resource_metadata=...` headers, and
    /// proxy-issued JWT bearers (audience-bound to the slug) are accepted.
    pub oauth_enabled: bool,
    /// When true, server-initiated `sampling/createMessage` calls on this
    /// virtual server are intercepted by the gateway and answered through
    /// the standard LLM pipeline instead of being forwarded to the agent.
    pub sampling_intercept_enabled: bool,
    /// Presence-only signal. `true` iff `sampling_credential` is set in DB.
    /// The plaintext bearer is never returned over the wire.
    pub sampling_credential_set: bool,
    /// Model alias the synthetic LLM call requests (e.g. `claude-default`).
    /// `None` when not yet configured.
    pub sampling_model_alias: Option<String>,
    /// `true` when this endpoint routes a `per_user_oauth` upstream whose
    /// shared OAuth-App client is incomplete (missing client_id, secret,
    /// authorization_url, or token_url). Such an endpoint can't be granted to
    /// a workspace or connected from the portal until the client is set, so
    /// the admin UI marks it not-grantable. Required-field set mirrors
    /// `oauth_client_missing_fields` / `ensure_endpoint_oauth_grantable`.
    pub oauth_incomplete: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateMcpVirtualServer {
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    /// MCP 2025-11-25 `serverInfo.title` — display-friendly variant of name.
    pub display_title: Option<String>,
    /// MCP 2025-11-25 `serverInfo.websiteUrl` — must be a valid `http(s)://` URL.
    pub website_url: Option<String>,
    pub enabled: Option<bool>,
    /// See [`McpVirtualServerRow::oauth_enabled`]. Defaults to `false`.
    pub oauth_enabled: Option<bool>,
    /// See [`McpVirtualServerRow::sampling_intercept_enabled`]. Defaults to `false`.
    pub sampling_intercept_enabled: Option<bool>,
    /// LLM-family bearer pasted by the operator. Encrypted at rest with the
    /// process `ENCRYPTION_KEY`. Write-only — the API never returns it.
    pub sampling_credential: Option<String>,
    pub sampling_model_alias: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMcpVirtualServer {
    pub name: Option<String>,
    /// `null` or `""` clears it; absent leaves it.
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub description: Option<String>,
    /// A value replaces; `null` or `""` clears; absent leaves alone.
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub display_title: Option<String>,
    /// A value replaces; `null` or `""` clears; absent leaves alone. Validated as `http(s)://`.
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub website_url: Option<String>,
    pub enabled: Option<bool>,
    pub oauth_enabled: Option<bool>,
    pub sampling_intercept_enabled: Option<bool>,
    /// A write-only secret: a value replaces; `""` clears (removes the stored
    /// bearer); absent or `null` leaves the existing ciphertext untouched.
    pub sampling_credential: Option<String>,
    /// A value replaces; `null` or `""` clears; absent leaves alone.
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub sampling_model_alias: Option<String>,
    // slug is intentionally not patchable — bookmark stability + OAuth audience binding.
}

/// Maximum length of a serverInfo `title` — matches the DB CHECK constraint.
const DISPLAY_TITLE_MAX_LEN: usize = 256;
/// Maximum length of a serverInfo `websiteUrl` — matches the DB CHECK
/// constraint and common browser address-bar limits.
const WEBSITE_URL_MAX_LEN: usize = 2048;

/// Validate a `website_url`. Accepts only `http://` and `https://` URLs that
/// parse cleanly. Returns the trimmed URL or an `ApiError` on failure.
fn validate_website_url(url: &str) -> Result<String, ApiError> {
    let trimmed = url.trim();
    if trimmed.len() > WEBSITE_URL_MAX_LEN {
        return Err(ApiError::bad_request(format!(
            "website_url exceeds {WEBSITE_URL_MAX_LEN}-char limit"
        ))
        .code(ApiErrorCode::ValidationFailed));
    }
    let parsed = reqwest::Url::parse(trimmed).map_err(|_| {
        ApiError::bad_request("website_url must be a valid URL")
            .code(ApiErrorCode::ValidationFailed)
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err(ApiError::bad_request(
            "website_url must use http:// or https://",
        )
        .code(ApiErrorCode::ValidationFailed));
    }
    Ok(trimmed.to_string())
}

/// Validate a `display_title`. Returns the trimmed string or an error if
/// it exceeds the DB length limit.
fn validate_display_title(title: &str) -> Result<String, ApiError> {
    let trimmed = title.trim();
    if trimmed.len() > DISPLAY_TITLE_MAX_LEN {
        return Err(ApiError::bad_request(format!(
            "display_title exceeds {DISPLAY_TITLE_MAX_LEN}-char limit"
        ))
        .code(ApiErrorCode::ValidationFailed));
    }
    Ok(trimmed.to_string())
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct McpVirtualServerListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/virtual-servers",
    tag = "MCP Servers",
    params(McpVirtualServerListQuery),
    responses(
        (status = 200, description = "Paginated list", body = TotalPage<McpVirtualServerRow>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mcp_virtual_servers(
    mut db: TenantConn,
    Query(query): Query<McpVirtualServerListQuery>,
) -> Result<Json<TotalPage<McpVirtualServerRow>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mcp_virtual_servers")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count mcp_virtual_servers: {e}");
            ApiError::internal("failed to list mcp virtual servers")
        })?;
    let rows = sqlx::query_as::<_, McpVirtualServerRow>(
        r#"SELECT id, slug, name, description, display_title, website_url,
                  enabled, oauth_enabled,
                  sampling_intercept_enabled,
                  (sampling_credential IS NOT NULL) AS sampling_credential_set,
                  sampling_model_alias,
                  EXISTS (
                    SELECT 1 FROM mcp_virtual_routes r
                    JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
                    WHERE r.virtual_server_id = vs.id
                      AND u.auth_mode = 'per_user_oauth'
                      AND (u.oauth_client_id IS NULL OR u.oauth_client_id = ''
                           OR u.encrypted_oauth_client_secret IS NULL
                           OR u.oauth_authorization_url IS NULL OR u.oauth_authorization_url = ''
                           OR u.oauth_token_url IS NULL OR u.oauth_token_url = '')
                  ) AS oauth_incomplete,
                  created_at, updated_at
           FROM mcp_virtual_servers vs
           ORDER BY slug
           LIMIT $1 OFFSET $2"#,
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp_virtual_servers: {e}");
        ApiError::internal("failed to list mcp virtual servers")
    })?;
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/virtual-servers/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Virtual server ID")),
    responses(
        (status = 200, description = "Virtual server", body = McpVirtualServerRow),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mcp_virtual_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<McpVirtualServerRow>, ApiError> {
    let row = sqlx::query_as::<_, McpVirtualServerRow>(
        r#"SELECT id, slug, name, description, display_title, website_url,
                  enabled, oauth_enabled,
                  sampling_intercept_enabled,
                  (sampling_credential IS NOT NULL) AS sampling_credential_set,
                  sampling_model_alias,
                  EXISTS (
                    SELECT 1 FROM mcp_virtual_routes r
                    JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
                    WHERE r.virtual_server_id = vs.id
                      AND u.auth_mode = 'per_user_oauth'
                      AND (u.oauth_client_id IS NULL OR u.oauth_client_id = ''
                           OR u.encrypted_oauth_client_secret IS NULL
                           OR u.oauth_authorization_url IS NULL OR u.oauth_authorization_url = ''
                           OR u.oauth_token_url IS NULL OR u.oauth_token_url = '')
                  ) AS oauth_incomplete,
                  created_at, updated_at
           FROM mcp_virtual_servers vs WHERE vs.id = $1"#,
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get mcp_virtual_server: {e}");
        ApiError::internal("failed to fetch mcp virtual server")
    })?
    .ok_or_else(|| ApiError::not_found("mcp virtual server not found", ApiErrorCode::McpVirtualServerNotFound))?;
    Ok(Json(row))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/virtual-servers",
    tag = "MCP Servers",
    request_body = CreateMcpVirtualServer,
    responses(
        (status = 201, description = "Created", body = McpVirtualServerRow),
        (status = 400, description = "Invalid", body = ApiErrorResponse),
        (status = 409, description = "Slug taken", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mcp_virtual_server(
    mut db: TenantConn,
    Json(body): Json<CreateMcpVirtualServer>,
) -> Result<(StatusCode, Json<McpVirtualServerRow>), ApiError> {
    if !is_valid_slug(&body.slug) {
        return Err(ApiError::bad_request(
            "slug must match ^[a-z][a-z0-9-]{0,30}$ (lowercase, start with a letter, max 31 chars)",
        )
        .code(ApiErrorCode::McpVirtualServerSlugInvalid));
    }
    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    let enabled = body.enabled.unwrap_or(true);
    let oauth_enabled = body.oauth_enabled.unwrap_or(false);
    let sampling_intercept_enabled = body.sampling_intercept_enabled.unwrap_or(false);
    let sampling_cred_plain = body.sampling_credential.as_deref().filter(|s| !s.is_empty());
    let sampling_model_alias = body
        .sampling_model_alias
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);
    if sampling_intercept_enabled
        && (sampling_cred_plain.is_none() || sampling_model_alias.is_none())
    {
        return Err(ApiError::bad_request(
            "sampling_intercept_enabled requires both sampling_credential and sampling_model_alias",
        )
        .code(ApiErrorCode::McpSamplingMisconfigured));
    }
    let sampling_credential_bytes = encrypt_mcp_credential(sampling_cred_plain)?;
    let display_title = body
        .display_title
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(validate_display_title)
        .transpose()?;
    let website_url = body
        .website_url
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(validate_website_url)
        .transpose()?;
    let row = sqlx::query_as::<_, McpVirtualServerRow>(
        r#"INSERT INTO mcp_virtual_servers
               (tenant_id, slug, name, description, display_title, website_url,
                enabled, oauth_enabled,
                sampling_intercept_enabled, sampling_credential, sampling_model_alias)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
           RETURNING id, slug, name, description, display_title, website_url,
                     enabled, oauth_enabled,
                     sampling_intercept_enabled,
                     (sampling_credential IS NOT NULL) AS sampling_credential_set,
                     sampling_model_alias,
                     -- A freshly created endpoint has no routes yet, so it can
                     -- never be oauth-incomplete here.
                     false AS oauth_incomplete,
                     created_at, updated_at"#,
    )
    .bind(db.tenant_uuid())
    .bind(&body.slug)
    .bind(&body.name)
    .bind(&body.description)
    .bind(&display_title)
    .bind(&website_url)
    .bind(enabled)
    .bind(oauth_enabled)
    .bind(sampling_intercept_enabled)
    .bind(sampling_credential_bytes)
    .bind(sampling_model_alias)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        // Two unique indexes can fire here and they mean different things, so
        // this one case genuinely needs to know WHICH — `constraint()` is the
        // structured way to ask. The SQLSTATE still gates the fallback, so a
        // renamed index degrades to the generic conflict rather than to a 500.
        let constraint = e.as_database_error().and_then(|d| d.constraint()).unwrap_or_default();
        if constraint == "mcp_virtual_servers_oauth_slug_unique" {
            // Cross-tenant OAuth-slug collision, caught by the partial unique
            // index — the only layer that can see across tenants.
            ApiError::conflict(format!(
                "slug '{slug}' is already used by an OAuth-enabled virtual server in another tenant",
                slug = body.slug,
            ), ApiErrorCode::McpOauthSlugCollision)
        } else if super::is_unique_violation(&e) {
            ApiError::conflict("virtual server slug already exists for this tenant", ApiErrorCode::McpVirtualServerSlugTaken)
        } else {
            tracing::error!("create mcp_virtual_server: {e}");
            ApiError::internal("failed to create mcp virtual server")
        }
    })?;

    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/mcp/virtual-servers/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Virtual server ID")),
    request_body = UpdateMcpVirtualServer,
    responses(
        (status = 200, description = "Updated", body = McpVirtualServerRow),
        (status = 400, description = "Invalid", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_mcp_virtual_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMcpVirtualServer>,
) -> Result<Json<McpVirtualServerRow>, ApiError> {
    // Capture tenant uuid up front because the transaction below holds a
    // mutable borrow on `db` for its full lifetime.
    // Lock the row while we read-validate-update so two interleaved PATCHes
    // can't both pass the misconfig check against the same stale snapshot.
    // Concrete bad path without `FOR UPDATE`: row starts `enabled=false,
    // has_cred=true`. PATCH A flipping `enabled=true` reads `has_cred=true`
    // (passes); PATCH B clearing the credential reads `enabled=false`
    // (passes); whichever UPDATE lands second leaves the row enabled with
    // no credential. The proxy's `build_sampling_intercept` collapses that
    // to disabled defensively, but the contract should hold at the
    // boundary, not be patched up downstream. The row lock bounds the
    // critical section to one PATCH at a time per row.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update mcp_virtual_server: begin tx: {e}");
        ApiError::internal("failed to update mcp virtual server")
    })?;
    let current: Option<(String, bool, bool, Option<String>)> = sqlx::query_as(
        r#"SELECT slug,
                  sampling_intercept_enabled,
                  (sampling_credential IS NOT NULL) AS has_cred,
                  sampling_model_alias
           FROM mcp_virtual_servers
           WHERE id = $1
           FOR UPDATE"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update mcp_virtual_server: lookup current: {e}");
        ApiError::internal("failed to update mcp virtual server")
    })?;

    // Tri-state credential patch:
    //   None             → leave existing ciphertext alone.
    //   Some("")         → clear (NULL).
    //   Some("plain")    → encrypt and replace.
    let (update_cred, cred_bytes) = match body.sampling_credential.as_deref() {
        None => (false, None),
        Some("") => (true, None),
        Some(plain) => (true, encrypt_mcp_credential(Some(plain))?),
    };
    let (update_alias, alias_value) = match body.sampling_model_alias.as_deref() {
        None => (false, None),
        Some(s) if s.trim().is_empty() => (true, None),
        Some(s) => (true, Some(s.trim().to_string())),
    };
    let (update_title, title_value) = match body.display_title.as_deref() {
        None => (false, None),
        Some(s) if s.trim().is_empty() => (true, None),
        Some(s) => (true, Some(validate_display_title(s)?)),
    };
    let (update_website, website_value) = match body.website_url.as_deref() {
        None => (false, None),
        Some(s) if s.trim().is_empty() => (true, None),
        Some(s) => (true, Some(validate_website_url(s)?)),
    };
    if let Some((_, cur_enabled, cur_has_cred, cur_alias)) = current.as_ref() {
        let final_enabled = body.sampling_intercept_enabled.unwrap_or(*cur_enabled);
        let final_has_cred = if update_cred { cred_bytes.is_some() } else { *cur_has_cred };
        let final_has_alias = if update_alias {
            alias_value.is_some()
        } else {
            cur_alias.as_ref().is_some_and(|s| !s.trim().is_empty())
        };
        if final_enabled && (!final_has_cred || !final_has_alias) {
            return Err(ApiError::bad_request(
                "sampling_intercept_enabled requires both sampling_credential and sampling_model_alias",
            )
            .code(ApiErrorCode::McpSamplingMisconfigured));
        }
    }

    let row = sqlx::query_as::<_, McpVirtualServerRow>(
        r#"UPDATE mcp_virtual_servers SET
               name = COALESCE($2, name),
               description = CASE WHEN $3::text IS NULL THEN description ELSE NULLIF(TRIM($3), '') END,
               enabled = COALESCE($4, enabled),
               oauth_enabled = COALESCE($5, oauth_enabled),
               sampling_intercept_enabled = COALESCE($6, sampling_intercept_enabled),
               sampling_credential = CASE WHEN $7 THEN $8 ELSE sampling_credential END,
               sampling_model_alias = CASE WHEN $9 THEN $10 ELSE sampling_model_alias END,
               display_title = CASE WHEN $11 THEN $12 ELSE display_title END,
               website_url = CASE WHEN $13 THEN $14 ELSE website_url END,
               updated_at = NOW()
           WHERE id = $1
           RETURNING id, slug, name, description, display_title, website_url,
                     enabled, oauth_enabled,
                     sampling_intercept_enabled,
                     (sampling_credential IS NOT NULL) AS sampling_credential_set,
                     sampling_model_alias,
                     EXISTS (
                       SELECT 1 FROM mcp_virtual_routes r
                       JOIN mcp_upstream_servers u ON u.id = r.upstream_server_id
                       WHERE r.virtual_server_id = mcp_virtual_servers.id
                         AND u.auth_mode = 'per_user_oauth'
                         AND (u.oauth_client_id IS NULL OR u.oauth_client_id = ''
                              OR u.encrypted_oauth_client_secret IS NULL
                              OR u.oauth_authorization_url IS NULL OR u.oauth_authorization_url = ''
                              OR u.oauth_token_url IS NULL OR u.oauth_token_url = '')
                     ) AS oauth_incomplete,
                     created_at, updated_at"#,
    )
    .bind(id)
    .bind(&body.name)
    .bind(&body.description)
    .bind(body.enabled)
    .bind(body.oauth_enabled)
    .bind(body.sampling_intercept_enabled)
    .bind(update_cred)
    .bind(cred_bytes)
    .bind(update_alias)
    .bind(alias_value)
    .bind(update_title)
    .bind(&title_value)
    .bind(update_website)
    .bind(&website_value)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        // The sink here is the `oauth_enabled` TOGGLE, not a slug write: turning
        // OAuth on for a server whose slug is already OAuth-taken in another
        // tenant fires the partial unique index. Mirror the create path — ask
        // WHICH constraint via `constraint()`, then fall back on the SQLSTATE so
        // a renamed index still reads as a conflict rather than as a fault.
        let constraint = e.as_database_error().and_then(|d| d.constraint()).unwrap_or_default();
        if constraint == "mcp_virtual_servers_oauth_slug_unique" {
            ApiError::conflict(
                "slug is already used by an OAuth-enabled virtual server in another tenant",
                ApiErrorCode::McpOauthSlugCollision,
            )
        } else if super::is_unique_violation(&e) {
            // Reachable ONLY if the index above is renamed and `constraint()`
            // stops matching: this UPDATE writes neither `slug` nor `tenant_id`,
            // so the per-tenant `(tenant_id, slug)` index cannot fire and the
            // OAuth index is the only unique violation it can raise. So this
            // degradation arm must keep saying CROSS-TENANT — reporting a
            // tenant-local slug clash here would send the caller looking for a
            // sibling virtual server that does not exist.
            ApiError::conflict(
                "slug is already used by an OAuth-enabled virtual server in another tenant",
                ApiErrorCode::McpOauthSlugCollision,
            )
        } else {
            tracing::error!("update mcp_virtual_server: {e}");
            ApiError::internal("failed to update mcp virtual server")
        }
    })?
    .ok_or_else(|| ApiError::not_found("mcp virtual server not found", ApiErrorCode::McpVirtualServerNotFound))?;
    tx.commit().await.map_err(|e| {
        tracing::error!("update mcp_virtual_server: commit tx: {e}");
        ApiError::internal("failed to update mcp virtual server")
    })?;
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/virtual-servers/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Virtual server ID")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mcp_virtual_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Routes cascade via the FK; mcp_sessions cascade too (live sessions
    // disappear on delete — operator should disable first if they want to
    // drain).
    let result = sqlx::query("DELETE FROM mcp_virtual_servers WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("delete mcp_virtual_server: {e}");
            ApiError::internal("failed to delete mcp virtual server")
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("mcp virtual server not found", ApiErrorCode::McpVirtualServerNotFound));
    }
    Ok(Json(ActionResponse::ok()))
}

// ===========================================================================
// MCP VIRTUAL ROUTES
// ===========================================================================

/// Allow/deny list filter applied per-route to tools / resources / prompts
/// surfaced from an upstream. JSONB-backed; both fields optional, mutually
/// exclusive in practice (allow wins if both are set). Storage uses
/// `sqlx::types::Json<McpRouteFilterShape>` so the wire schema, the OpenAPI
/// projection, and the row type are all the same struct — no opaque
/// `serde_json::Value` newtype on the public surface.
#[derive(Serialize, Deserialize, ToSchema, Clone, Debug, Default)]
pub struct McpRouteFilterShape {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allow: Option<Vec<String>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub deny: Option<Vec<String>>,
}

/// sqlx-compatible JSONB wrapper; serialised transparently as the inner
/// shape so the wire shape stays `{ allow?, deny? }` (no envelope).
type McpRouteFilter = sqlx::types::Json<McpRouteFilterShape>;

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpVirtualRouteRow {
    pub id: Uuid,
    pub virtual_server_id: Uuid,
    pub upstream_server_id: Uuid,
    pub prefix: String,
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub tools_filter: Option<McpRouteFilter>,
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub resources_filter: Option<McpRouteFilter>,
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub prompts_filter: Option<McpRouteFilter>,
    pub enabled: bool,
    pub position: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateMcpVirtualRoute {
    pub virtual_server_id: Uuid,
    pub upstream_server_id: Uuid,
    /// Empty string allowed — only on a virtual server's first route; prefixed
    /// routes may be added beside it.
    pub prefix: Option<String>,
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub tools_filter: Option<McpRouteFilter>,
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub resources_filter: Option<McpRouteFilter>,
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub prompts_filter: Option<McpRouteFilter>,
    pub enabled: Option<bool>,
    pub position: Option<i32>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMcpVirtualRoute {
    pub prefix: Option<String>,
    /// Absent leaves the filter; `null` removes it (everything passes).
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub tools_filter: Option<Option<McpRouteFilter>>,
    /// As `tools_filter`.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub resources_filter: Option<Option<McpRouteFilter>>,
    /// As `tools_filter`.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<McpRouteFilterShape>)]
    pub prompts_filter: Option<Option<McpRouteFilter>>,
    pub enabled: Option<bool>,
    pub position: Option<i32>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct McpVirtualRouteListQuery {
    pub virtual_server_id: Option<Uuid>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/virtual-routes",
    tag = "MCP Servers",
    params(McpVirtualRouteListQuery),
    responses(
        (status = 200, description = "Paginated list", body = TotalPage<McpVirtualRouteRow>),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mcp_virtual_routes(
    mut db: TenantConn,
    Query(query): Query<McpVirtualRouteListQuery>,
) -> Result<Json<TotalPage<McpVirtualRouteRow>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();
    let (total, rows) = if let Some(vs_id) = query.virtual_server_id {
        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_virtual_routes WHERE virtual_server_id = $1",
        )
        .bind(vs_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count mcp_virtual_routes: {e}");
            ApiError::internal("failed to list mcp virtual routes")
        })?;
        let rows = sqlx::query_as::<_, McpVirtualRouteRow>(
            r#"SELECT id, virtual_server_id, upstream_server_id, prefix,
                      tools_filter, resources_filter, prompts_filter,
                      enabled, position, created_at, updated_at
               FROM mcp_virtual_routes
               WHERE virtual_server_id = $1
               ORDER BY position, prefix
               LIMIT $2 OFFSET $3"#,
        )
        .bind(vs_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list mcp_virtual_routes: {e}");
            ApiError::internal("failed to list mcp virtual routes")
        })?;
        (total, rows)
    } else {
        let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mcp_virtual_routes")
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("count mcp_virtual_routes: {e}");
                ApiError::internal("failed to list mcp virtual routes")
            })?;
        let rows = sqlx::query_as::<_, McpVirtualRouteRow>(
            r#"SELECT id, virtual_server_id, upstream_server_id, prefix,
                      tools_filter, resources_filter, prompts_filter,
                      enabled, position, created_at, updated_at
               FROM mcp_virtual_routes
               ORDER BY virtual_server_id, position
               LIMIT $1 OFFSET $2"#,
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list mcp_virtual_routes: {e}");
            ApiError::internal("failed to list mcp virtual routes")
        })?;
        (total, rows)
    };
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/virtual-routes",
    tag = "MCP Servers",
    request_body = CreateMcpVirtualRoute,
    responses(
        (status = 201, description = "Created", body = McpVirtualRouteRow),
        (status = 400, description = "Invalid", body = ApiErrorResponse),
        (status = 404, description = "Virtual server or upstream not found", body = ApiErrorResponse),
        (status = 409, description = "Prefix collision", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mcp_virtual_route(
    mut db: TenantConn,
    Json(body): Json<CreateMcpVirtualRoute>,
) -> Result<(StatusCode, Json<McpVirtualRouteRow>), ApiError> {
    let prefix = body.prefix.unwrap_or_default();
    if !is_valid_route_prefix(&prefix) {
        return Err(ApiError::bad_request(PREFIX_RULE).code(ApiErrorCode::McpRoutePrefixInvalid));
    }

    // Verify virtual_server + upstream_server exist for this tenant.
    let vs_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mcp_virtual_servers WHERE id = $1)",
    )
    .bind(body.virtual_server_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create mcp_virtual_route check vs: {e}");
        ApiError::internal("failed to verify virtual server")
    })?;
    if !vs_exists {
        return Err(ApiError::not_found("virtual server not found", ApiErrorCode::McpVirtualServerNotFound));
    }
    let up_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM mcp_upstream_servers WHERE id = $1)",
    )
    .bind(body.upstream_server_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create mcp_virtual_route check up: {e}");
        ApiError::internal("failed to verify upstream server")
    })?;
    if !up_exists {
        return Err(ApiError::not_found("upstream server not found", ApiErrorCode::McpUpstreamServerNotFound));
    }

    // If prefix is empty, allow only when no other route exists on the
    // virtual server yet (its no-namespacing route; prefixed routes may be
    // added beside it later).
    if prefix.is_empty() {
        let other: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_virtual_routes WHERE virtual_server_id = $1",
        )
        .bind(body.virtual_server_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("create mcp_virtual_route count siblings: {e}");
            ApiError::internal("failed to validate prefix")
        })?;
        if other > 0 {
            return Err(ApiError::bad_request(
                "empty prefix is only allowed on the first route of a virtual server",
            )
            .code(ApiErrorCode::McpRoutePrefixInvalid));
        }
    }

    // BYOT routing requires single-route virtual servers — enforce on
    // create. Mixing a `byot` upstream with any other route would break the
    // forward-auth contract (which upstream gets the client's bearer?).
    validate_byot_route_invariant(&mut db, body.virtual_server_id, body.upstream_server_id, None)
        .await?;

    let enabled = body.enabled.unwrap_or(true);
    let position = body.position.unwrap_or(0);

    let row = sqlx::query_as::<_, McpVirtualRouteRow>(
        r#"INSERT INTO mcp_virtual_routes
               (tenant_id, virtual_server_id, upstream_server_id, prefix,
                tools_filter, resources_filter, prompts_filter, enabled, position)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
           RETURNING id, virtual_server_id, upstream_server_id, prefix,
                     tools_filter, resources_filter, prompts_filter,
                     enabled, position, created_at, updated_at"#,
    )
    .bind(db.tenant_uuid())
    .bind(body.virtual_server_id)
    .bind(body.upstream_server_id)
    .bind(&prefix)
    .bind(&body.tools_filter)
    .bind(&body.resources_filter)
    .bind(&body.prompts_filter)
    .bind(enabled)
    .bind(position)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("a route with this prefix already exists on the virtual server", ApiErrorCode::McpRoutePrefixTaken)
        } else {
            tracing::error!("create mcp_virtual_route: {e}");
            ApiError::internal("failed to create mcp virtual route")
        }
    })?;
    Ok((StatusCode::CREATED, Json(row)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/virtual-routes/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Route ID")),
    responses(
        (status = 200, description = "Route", body = McpVirtualRouteRow),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mcp_virtual_route(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<McpVirtualRouteRow>, ApiError> {
    let row = sqlx::query_as::<_, McpVirtualRouteRow>(
        r#"SELECT id, virtual_server_id, upstream_server_id, prefix,
                  tools_filter, resources_filter, prompts_filter,
                  enabled, position, created_at, updated_at
           FROM mcp_virtual_routes WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get mcp_virtual_route: {e}");
        ApiError::internal("failed to fetch mcp virtual route")
    })?
    .ok_or_else(|| ApiError::not_found("mcp virtual route not found", ApiErrorCode::McpVirtualRouteNotFound))?;
    Ok(Json(row))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/mcp/virtual-routes/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Route ID")),
    request_body = UpdateMcpVirtualRoute,
    responses(
        (status = 200, description = "Updated", body = McpVirtualRouteRow),
        (status = 400, description = "Invalid", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
// BYOT single-route invariant: `upstream_server_id` and `virtual_server_id` are
// intentionally NOT in the PATCH allow-list — flipping either could route a
// byot virtual server to a non-byot upstream or convert a single-route VS into
// a multi-route one without re-running `validate_byot_route_invariant`. That
// validator counts disabled routes by design, so toggling `enabled=false` here
// also does NOT relax the invariant. Do not add either id to
// `UpdateMcpVirtualRoute` without re-validating BYOT shape on the parent VS.
pub async fn update_mcp_virtual_route(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMcpVirtualRoute>,
) -> Result<Json<McpVirtualRouteRow>, ApiError> {
    if let Some(p) = &body.prefix
        && !is_valid_route_prefix(p)
    {
        return Err(ApiError::bad_request(PREFIX_RULE).code(ApiErrorCode::McpRoutePrefixInvalid));
    }
    let row = sqlx::query_as::<_, McpVirtualRouteRow>(
        r#"UPDATE mcp_virtual_routes SET
               prefix = COALESCE($2, prefix),
               tools_filter = CASE WHEN $8 THEN $3::jsonb ELSE tools_filter END,
               resources_filter = CASE WHEN $9 THEN $4::jsonb ELSE resources_filter END,
               prompts_filter = CASE WHEN $10 THEN $5::jsonb ELSE prompts_filter END,
               enabled = COALESCE($6, enabled),
               position = COALESCE($7, position),
               updated_at = NOW()
           WHERE id = $1
           RETURNING id, virtual_server_id, upstream_server_id, prefix,
                     tools_filter, resources_filter, prompts_filter,
                     enabled, position, created_at, updated_at"#,
    )
    .bind(id)
    .bind(&body.prefix)
    .bind(body.tools_filter.as_ref().and_then(Option::as_ref))
    .bind(body.resources_filter.as_ref().and_then(Option::as_ref))
    .bind(body.prompts_filter.as_ref().and_then(Option::as_ref))
    .bind(body.enabled)
    .bind(body.position)
    .bind(body.tools_filter.is_some()) // $8
    .bind(body.resources_filter.is_some()) // $9
    .bind(body.prompts_filter.is_some()) // $10
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("prefix collision on this virtual server", ApiErrorCode::McpRoutePrefixTaken)
        } else {
            tracing::error!("update mcp_virtual_route: {e}");
            ApiError::internal("failed to update mcp virtual route")
        }
    })?
    .ok_or_else(|| ApiError::not_found("mcp virtual route not found", ApiErrorCode::McpVirtualRouteNotFound))?;
    Ok(Json(row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/virtual-routes/{id}",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Route ID")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mcp_virtual_route(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let result = sqlx::query("DELETE FROM mcp_virtual_routes WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("delete mcp_virtual_route: {e}");
            ApiError::internal("failed to delete mcp virtual route")
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("mcp virtual route not found", ApiErrorCode::McpVirtualRouteNotFound));
    }
    Ok(Json(ActionResponse::ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_validation() {
        assert!(is_valid_slug("alpha"));
        assert!(is_valid_slug("a"));
        assert!(is_valid_slug("github-bot"));
        assert!(is_valid_slug("a1b2c3"));
        assert!(!is_valid_slug(""));
        assert!(!is_valid_slug("Alpha"));
        assert!(!is_valid_slug("1alpha"));
        assert!(!is_valid_slug("alpha_beta"));
        assert!(is_valid_slug("alpha--ok"));
        assert!(!is_valid_slug(&"a".repeat(32)));
    }

    #[test]
    fn oauth_client_completeness() {
        // Fully configured → nothing missing.
        assert!(
            oauth_client_missing_fields(Some("cid"), true, Some("https://a/auth"), Some("https://a/tok"))
                .is_empty()
        );
        // Each field independently flagged.
        assert_eq!(
            oauth_client_missing_fields(None, true, Some("https://a/auth"), Some("https://a/tok")),
            vec!["oauth_client_id"]
        );
        assert_eq!(
            oauth_client_missing_fields(Some("cid"), false, Some("https://a/auth"), Some("https://a/tok")),
            vec!["oauth_client_secret"]
        );
        assert_eq!(
            oauth_client_missing_fields(Some("cid"), true, None, Some("https://a/tok")),
            vec!["oauth_authorization_url"]
        );
        assert_eq!(
            oauth_client_missing_fields(Some("cid"), true, Some("https://a/auth"), None),
            vec!["oauth_token_url"]
        );
        // Empty strings count as missing; everything absent lists all four.
        assert_eq!(
            oauth_client_missing_fields(Some(""), false, Some(""), None),
            vec![
                "oauth_client_id",
                "oauth_client_secret",
                "oauth_authorization_url",
                "oauth_token_url"
            ]
        );
    }
}
