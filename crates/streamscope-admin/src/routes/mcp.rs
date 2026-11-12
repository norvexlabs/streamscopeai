//! MCP gateway CRUD — upstream servers + virtual servers + virtual routes.
//!
//! An upstream is an adopted `server.json` remote: the headers it declares,
//! each filled by the administrator (stored encrypted here), the user (in the
//! portal) or the calling client (per request, never stored), plus the user's
//! own OAuth token when `auth_mode = per_user_oauth`. The admin surface
//! persists the row shape; the proxy resolves the headers per request
//! ([`streamscope_core::mcp::header_inputs::resolve`]).


use streamscope_mcp_auth::ssrf::Egress;
use streamscope_mcp_auth::egress::Surface;
use axum::Json;
use axum::extract::{Path, Query};
use axum::http::StatusCode;
use serde::{Deserialize, Serialize};
use streamscope_core::config::mcp::is_valid_route_prefix;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use std::collections::{BTreeMap, HashMap};

use streamscope_core::config::mcp::McpAuthMode;
use streamscope_core::mcp::header_inputs::{self as hi, Filler, Remote};

use super::mcp_inputs;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, TotalPage};
use crate::db::tenant::TenantConn;

// ---------------------------------------------------------------------------
// Validation helpers — kept here so the JSON shape on the wire matches the
// one synced to proxies.
// ---------------------------------------------------------------------------


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

/// Every column an upstream read returns, in [`UpstreamDbRow`]'s shape.
const UPSTREAM_COLS: &str = r#"id, name, description, upstream_url, transport, auth_mode, enabled,
    connect_timeout_ms, request_timeout_ms, cred_version,
    remote, encrypted_admin_inputs, required_user_input_ids, url_variables, catalog_entry_id,
    oauth_issuer_url, oauth_authorization_url, oauth_token_url,
    oauth_revocation_url, oauth_client_id,
    (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret,
    COALESCE(oauth_default_scopes, ARRAY[]::TEXT[]) AS oauth_default_scopes,
    built_in, created_at, updated_at"#;

#[derive(sqlx::FromRow)]
struct UpstreamDbRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    upstream_url: String,
    transport: String,
    auth_mode: String,
    enabled: bool,
    connect_timeout_ms: i32,
    request_timeout_ms: i32,
    cred_version: i64,
    remote: sqlx::types::Json<Remote>,
    encrypted_admin_inputs: sqlx::types::Json<HashMap<String, String>>,
    required_user_input_ids: Vec<String>,
    url_variables: sqlx::types::Json<BTreeMap<String, String>>,
    catalog_entry_id: Option<Uuid>,
    oauth_issuer_url: Option<String>,
    oauth_authorization_url: Option<String>,
    oauth_token_url: Option<String>,
    oauth_revocation_url: Option<String>,
    oauth_client_id: Option<String>,
    has_oauth_client_secret: bool,
    oauth_default_scopes: Vec<String>,
    built_in: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct McpUpstreamServerRow {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// The finished URL: the remote's URL template with its variables filled.
    pub upstream_url: String,
    /// Derived from `remote.type`.
    pub transport: String,
    /// `headers` | `per_user_oauth`.
    pub auth_mode: String,
    pub enabled: bool,
    pub connect_timeout_ms: i32,
    pub request_timeout_ms: i32,
    pub cred_version: i64,
    /// The adopted `server.json` remote: its declared headers and, in
    /// `_meta["ai.streamscope/inputs"].fillers`, who fills each input.
    /// Its keys are the MCP Registry schema's own camelCase (`isRequired`,
    /// `_meta`), unlike the rest of this body: it is that canonical document.
    pub remote: Remote,
    /// The NON-secret admin-filled values, input id → value.
    pub inputs: BTreeMap<String, String>,
    /// The secret admin-filled inputs that have a value (never the value).
    pub secret_input_ids: Vec<String>,
    /// The user-filled inputs a user must fill before the upstream is usable.
    pub required_user_input_ids: Vec<String>,
    /// The headers a client must send for this upstream, lowercased.
    pub client_headers: Vec<String>,
    /// The values `upstream_url` was finished with: variable name → value
    /// (a default counts as its value). Never secret.
    pub url_variables: BTreeMap<String, String>,
    /// The catalog entry the upstream was adopted from; `None` for one created
    /// by hand, or once that entry is deleted.
    pub catalog_entry_id: Option<Uuid>,
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

impl From<UpstreamDbRow> for McpUpstreamServerRow {
    fn from(r: UpstreamDbRow) -> Self {
        let remote = r.remote.0;
        let specs = mcp_inputs::stored_specs(r.id, &remote, &r.auth_mode);
        let (inputs, secret_input_ids) =
            mcp_inputs::admin_values_view(&remote, specs.as_deref(), &r.encrypted_admin_inputs.0);
        let client_headers = specs.as_deref().map(mcp_inputs::client_headers).unwrap_or_default();
        Self {
            id: r.id,
            name: r.name,
            description: r.description,
            upstream_url: r.upstream_url,
            transport: r.transport,
            auth_mode: r.auth_mode,
            enabled: r.enabled,
            connect_timeout_ms: r.connect_timeout_ms,
            request_timeout_ms: r.request_timeout_ms,
            cred_version: r.cred_version,
            remote,
            inputs,
            secret_input_ids,
            required_user_input_ids: r.required_user_input_ids,
            client_headers,
            url_variables: r.url_variables.0,
            catalog_entry_id: r.catalog_entry_id,
            oauth_issuer_url: r.oauth_issuer_url,
            oauth_authorization_url: r.oauth_authorization_url,
            oauth_token_url: r.oauth_token_url,
            oauth_revocation_url: r.oauth_revocation_url,
            oauth_client_id: r.oauth_client_id,
            has_oauth_client_secret: r.has_oauth_client_secret,
            oauth_default_scopes: r.oauth_default_scopes,
            built_in: r.built_in,
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct CreateMcpUpstreamServer {
    pub name: String,
    pub description: Option<String>,
    /// The `server.json` remote, with each declared input's filler in
    /// `_meta["ai.streamscope/inputs"].fillers`. `{"type": "streamable-http",
    /// "url": "…"}` declares no header (no auth).
    /// Its keys are the MCP Registry schema's own camelCase (`isRequired`,
    /// `_meta`), unlike the rest of this body: it is that canonical document.
    pub remote: Remote,
    /// Values of the remote URL's `{variables}` (a variable's default fills an
    /// absent one). Never secret. Stored, with the defaults used, as the row's
    /// `url_variables`.
    #[serde(default)]
    pub url_variables: HashMap<String, String>,
    /// `headers` (default) or `per_user_oauth` (the declared headers plus the
    /// user's OAuth token as `Authorization: Bearer`).
    pub auth_mode: Option<String>,
    /// Values of the NON-secret admin-filled inputs: input id → value.
    #[serde(default)]
    pub inputs: HashMap<String, String>,
    /// Values of the secret admin-filled inputs: input id → value. Encrypted
    /// at rest, never echoed.
    #[serde(default)]
    pub secret_inputs: HashMap<String, String>,
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
    /// Replace the remote (declaration and fillers). A filler moved away from
    /// `user` drops that input from every user's values; one moved away from
    /// `admin` drops the stored admin value; a change of the client-filled
    /// headers re-checks every virtual server the upstream is routed on.
    /// Its keys are the MCP Registry schema's own camelCase (`isRequired`,
    /// `_meta`), unlike the rest of this body: it is that canonical document.
    pub remote: Option<Remote>,
    /// Re-finish the URL with these variable values, merged onto the stored
    /// ones: a variable left out keeps its stored value; one the template
    /// uses with neither a stored nor a sent value is refused (a default fills
    /// one only at create and adopt). The URL is recomputed when this is present
    /// or `remote.url` changes; a stored value of a variable the remote no
    /// longer declares is dropped.
    pub url_variables: Option<HashMap<String, String>>,
    /// Locked post-create — only accepted when equal to the existing value
    /// (idempotent passthrough). Any other value rejects with
    /// `McpUpstreamAuthModeLocked`.
    pub auth_mode: Option<String>,
    /// NON-secret admin values: a value sets, `null` clears.
    #[serde(default)]
    pub inputs: HashMap<String, Option<String>>,
    /// Secret admin values: a value sets, `""` clears, `null` keeps.
    #[serde(default)]
    pub secret_inputs: HashMap<String, Option<String>>,
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
pub(crate) fn validate_outbound_urls(
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

/// The stored `auth_mode` a request names: `headers` or `per_user_oauth`.
fn parse_auth_mode(mode: &str) -> Result<McpAuthMode, ApiError> {
    McpAuthMode::parse(mode)
        .ok_or_else(|| ApiError::bad_request("auth_mode must be one of: headers, per_user_oauth"))
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
            Ok(Some(super::mcp_inputs::encrypt_value(plain)?.into_bytes()))
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
    let rows = sqlx::query_as::<_, UpstreamDbRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {UPSTREAM_COLS} FROM mcp_upstream_servers ORDER BY name LIMIT $1 OFFSET $2"
    )))
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp_upstream_servers: {e}");
        ApiError::internal("failed to list mcp upstream servers")
    })?;
    let rows = rows.into_iter().map(McpUpstreamServerRow::from).collect();
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
    let row = sqlx::query_as::<_, UpstreamDbRow>(sqlx::AssertSqlSafe(format!(
        "SELECT {UPSTREAM_COLS} FROM mcp_upstream_servers WHERE id = $1"
    )))
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get mcp_upstream_server: {e}");
        ApiError::internal("failed to fetch mcp upstream server")
    })?
    .ok_or_else(|| ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound))?;
    Ok(Json(row.into()))
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
    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("name must not be empty"));
    }
    let auth_mode = match body.auth_mode.as_deref() {
        Some(m) => parse_auth_mode(m)?,
        None => McpAuthMode::Headers,
    };
    let specs = mcp_inputs::specs_of(&body.remote, auth_mode.as_str())?;
    let upstream_url =
        hi::finish_url(&body.remote, &body.url_variables).map_err(|e| mcp_inputs::remote_error(&e))?;
    let url_variables = mcp_inputs::url_values_used(&body.remote, &body.url_variables);
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
    validate_outbound_urls(
        Some(&upstream_url),
        oauth_issuer_url,
        oauth_authorization_url,
        oauth_token_url,
        oauth_revocation_url,
        MCP_EGRESS,
    )?;
    validate_oauth_client_shape(
        Some(auth_mode.as_str()),
        oauth_issuer_url,
        oauth_authorization_url,
        oauth_token_url,
        oauth_revocation_url,
        oauth_client_id,
        oauth_client_secret,
        oauth_default_scopes,
        true,
    )?;

    // The admin's values: only admin-filled ids, every required one present.
    let ops = mcp_inputs::plan_value_patch(
        &body.remote,
        &specs,
        Filler::Admin,
        &mcp_inputs::as_patch(&body.inputs),
        &mcp_inputs::as_patch(&body.secret_inputs),
    )
    .map_err(mcp_inputs::PatchRefusal::into_api)?;
    let (admin_values, _) = mcp_inputs::encrypt_ops(&ops)?;
    mcp_inputs::require_filled(&specs, Filler::Admin, &admin_values)?;
    let required_user_input_ids = hi::required_user_input_ids(&specs);

    let enabled = body.enabled.unwrap_or(true);
    let connect_timeout_ms = body.connect_timeout_ms.unwrap_or(10_000);
    let request_timeout_ms = body.request_timeout_ms.unwrap_or(60_000);
    let encrypted_oauth_client_secret = encrypt_mcp_credential(oauth_client_secret)?;
    // Normalize description so create + patch agree on the "empty means NULL"
    // semantics — keeps a single canonical row shape regardless of which
    // endpoint set the value.
    let description = body
        .description
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());

    let row = sqlx::query_as::<_, UpstreamDbRow>(sqlx::AssertSqlSafe(format!(
        r#"INSERT INTO mcp_upstream_servers
               (tenant_id, name, description, upstream_url, transport, auth_mode,
                enabled, connect_timeout_ms, request_timeout_ms,
                remote, encrypted_admin_inputs, required_user_input_ids,
                oauth_issuer_url, oauth_authorization_url, oauth_token_url,
                oauth_revocation_url, oauth_client_id, encrypted_oauth_client_secret,
                oauth_default_scopes, url_variables)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10,
                   $11, $12, $13, $14, $15, $16, $17, $18, $19, $20)
           RETURNING {UPSTREAM_COLS}"#
    )))
    .bind(db.tenant_uuid())
    .bind(&body.name)
    .bind(description)
    .bind(&upstream_url)
    .bind(body.remote.kind.transport_str())
    .bind(auth_mode.as_str())
    .bind(enabled)
    .bind(connect_timeout_ms)
    .bind(request_timeout_ms)
    .bind(sqlx::types::Json(&body.remote))
    .bind(sqlx::types::Json(&admin_values))
    .bind(&required_user_input_ids)
    .bind(oauth_issuer_url)
    .bind(oauth_authorization_url)
    .bind(oauth_token_url)
    .bind(oauth_revocation_url)
    .bind(oauth_client_id)
    .bind(encrypted_oauth_client_secret)
    .bind(oauth_default_scopes)
    .bind(sqlx::types::Json(&url_variables))
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

    Ok((StatusCode::CREATED, Json(row.into())))
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
        (status = 409, description = "Built-in; a client header another upstream on a shared virtual server reads; or a client-filled Authorization on an upstream routed on an OAuth sign-in virtual server", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_mcp_upstream_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateMcpUpstreamServer>,
) -> Result<Json<McpUpstreamServerRow>, ApiError> {
    if let Some(a) = &body.auth_mode {
        parse_auth_mode(a)?;
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

    validate_outbound_urls(
        None,
        oauth_issuer_url,
        oauth_authorization_url,
        oauth_token_url,
        oauth_revocation_url,
        MCP_EGRESS,
    )?;

    let fail = |e: sqlx::Error| {
        tracing::error!("update mcp_upstream_server: {e}");
        ApiError::internal("failed to update mcp upstream server")
    };
    // One transaction: the row, the admin values, the users' values and the
    // collision check commit together. Lock order is shared with the route
    // insert (`mcp_inputs::lock_and_check_route_binding`): the virtual servers
    // this upstream is routed on first, then this row.
    let mut tx = db.conn().begin().await.map_err(fail)?;
    let locked_vs = mcp_inputs::lock_upstream_virtual_servers(&mut tx, id).await?;

    #[derive(sqlx::FromRow)]
    struct ExistingRow {
        built_in: bool,
        name: String,
        auth_mode: String,
        upstream_url: String,
        transport: String,
        remote: sqlx::types::Json<Remote>,
        url_variables: sqlx::types::Json<BTreeMap<String, String>>,
        encrypted_admin_inputs: sqlx::types::Json<HashMap<String, String>>,
        oauth_issuer_url: Option<String>,
        oauth_authorization_url: Option<String>,
        oauth_token_url: Option<String>,
        oauth_client_id: Option<String>,
        has_oauth_client_secret: bool,
    }
    // `FOR NO KEY UPDATE`: a concurrent route insert's foreign-key check
    // (`FOR KEY SHARE`) on this row must not wait on it.
    let existing: ExistingRow = sqlx::query_as::<_, ExistingRow>(
        r#"SELECT built_in, name, auth_mode, upstream_url, transport, remote, url_variables,
                  encrypted_admin_inputs,
                  oauth_issuer_url, oauth_authorization_url, oauth_token_url, oauth_client_id,
                  (encrypted_oauth_client_secret IS NOT NULL) AS has_oauth_client_secret
           FROM mcp_upstream_servers
           WHERE id = $1
           FOR NO KEY UPDATE"#,
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(fail)?
    .ok_or_else(|| {
        ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound)
    })?;

    // Refuse mutation on built-in (gateway-managed) rows. The synthetic
    // `internal://*` upstreams (e.g. `builtin-web` for `/mcp/web`) are
    // configured through the dedicated web admin endpoints; the generic
    // upstream PATCH must not let an operator repoint or rename them.
    if existing.built_in {
        return Err(ApiError::conflict(
            "built-in upstream is gateway-managed; configure via the web admin endpoints",
            ApiErrorCode::McpUpstreamServerBuiltInProtected,
        ));
    }

    // auth_mode is locked post-create: `per_user_oauth` carries an OAuth
    // client and every user's token store, and reserves `Authorization`;
    // flipping silently strands or drops them, so re-adopt to switch.
    if let Some(new_mode) = body.auth_mode.as_deref()
        && new_mode != existing.auth_mode
    {
        return Err(ApiError::bad_request(
            "auth_mode is locked post-create; delete and recreate the upstream to change it",
        )
        .code(ApiErrorCode::McpUpstreamAuthModeLocked));
    }

    // Validate the oauth shape against the locked-in auth_mode.
    let effective_auth_mode = existing.auth_mode.as_str();
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

    // The declaration: the new remote (or the stored one), its fillers
    // validated, the URL re-finished when its template or variables change.
    let stored_remote = &existing.remote.0;
    let remote_changed = body.remote.as_ref().is_some_and(|r| r != stored_remote);
    let remote = body.remote.clone().unwrap_or_else(|| stored_remote.clone());
    let specs = mcp_inputs::specs_of(&remote, effective_auth_mode)?;
    let stored_specs =
        mcp_inputs::stored_specs(id, stored_remote, effective_auth_mode).unwrap_or_default();
    // The URL is finished again when its template or a variable changes,
    // from the stored values merged with the body's — a default never fills
    // a variable here (see `merged_url_variables`).
    let stored_vars = &existing.url_variables.0;
    let (upstream_url, url_variables) = if body.url_variables.is_some() || remote.url != stored_remote.url {
        let vars = mcp_inputs::merged_url_variables(&remote, stored_vars, body.url_variables.as_ref())
            .map_err(|e| mcp_inputs::remote_error(&e))?;
        let url = hi::finish_url(&remote, &vars).map_err(|e| mcp_inputs::remote_error(&e))?;
        validate_outbound_urls(Some(&url), None, None, None, None, MCP_EGRESS)?;
        (url, mcp_inputs::url_values_used(&remote, &vars))
    } else {
        let kept = stored_vars
            .iter()
            .filter(|(k, _)| remote.variables.contains_key(*k))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        (existing.upstream_url.clone(), kept)
    };
    let transport = remote.kind.transport_str();

    // Admin values: a stored value whose input is no longer admin-filled is
    // dropped, then the patch applies; every required admin input must hold
    // a value afterwards.
    let ops = mcp_inputs::plan_value_patch(&remote, &specs, Filler::Admin, &body.inputs, &body.secret_inputs)
        .map_err(mcp_inputs::PatchRefusal::into_api)?;
    let (set, remove) = mcp_inputs::encrypt_ops(&ops)?;
    let mut admin_values: HashMap<String, String> = existing
        .encrypted_admin_inputs
        .0
        .iter()
        .filter(|(k, _)| specs.iter().any(|s| s.filler == Filler::Admin && &s.declared.id == *k))
        // A value stored as a secret is never shown back; if its input stops
        // being secret it is dropped (and must be set again), not revealed.
        .filter(|(k, _)| {
            let now = specs.iter().find(|s| &s.declared.id == *k);
            let before = stored_specs.iter().find(|s| &s.declared.id == *k);
            match (now, before) {
                (Some(n), Some(b)) => {
                    mcp_inputs::is_secret(&remote, n) == mcp_inputs::is_secret(stored_remote, b)
                }
                _ => true,
            }
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    for id in &remove {
        admin_values.remove(id);
    }
    admin_values.extend(set);
    mcp_inputs::require_filled(&specs, Filler::Admin, &admin_values)?;
    if remote_changed {
        mcp_inputs::require_stored_values_valid(&specs, Filler::Admin, &admin_values)?;
    }
    let admin_changed = admin_values != existing.encrypted_admin_inputs.0;

    // A change of the client-filled headers re-runs the collision rule on
    // every virtual server this upstream is routed on.
    if mcp_inputs::client_headers(&specs) != mcp_inputs::client_headers(&stored_specs) {
        let name = body.name.as_deref().unwrap_or(&existing.name);
        mcp_inputs::check_upstream_collisions(&mut tx, id, name, &specs, &locked_vs).await?;
    }

    // Users keep only the values of inputs that are still user-filled and
    // whose accepted values did not change: a value the new `choices` or
    // `format` might refuse is dropped, so the user is asked for it again
    // rather than shown as connected while the gateway ignores it.
    if remote_changed {
        let user_ids: Vec<String> = specs
            .iter()
            .filter(|s| s.filler == Filler::User)
            .filter(|s| {
                stored_specs.iter().any(|old| {
                    old.filler == Filler::User
                        && old.declared.id == s.declared.id
                        && old.declared.input.choices == s.declared.input.choices
                        && old.declared.input.format == s.declared.input.format
                })
            })
            .map(|s| s.declared.id.clone())
            .collect();
        sqlx::query(
            r#"UPDATE mcp_user_inputs
               SET encrypted_values = (
                       SELECT COALESCE(jsonb_object_agg(e.key, e.value), '{}'::jsonb)
                       FROM jsonb_each(encrypted_values) e
                       WHERE e.key = ANY($2)),
                   updated_at = NOW()
               WHERE upstream_server_id = $1
                 AND EXISTS (SELECT 1 FROM jsonb_object_keys(encrypted_values) k
                             WHERE NOT (k = ANY($2)))"#,
        )
        .bind(id)
        .bind(&user_ids)
        .execute(&mut *tx)
        .await
        .map_err(fail)?;
        // A user left with no value has no connection to show or revoke.
        sqlx::query(
            "DELETE FROM mcp_user_inputs WHERE upstream_server_id = $1 AND encrypted_values = '{}'::jsonb",
        )
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(fail)?;
    }

    // A server moved to another origin never receives what users gave the
    // old one: every user's entered values and OAuth tokens are deleted, and
    // each enters or connects again for the new server.
    let origin = |u: &str| url::Url::parse(u).ok().map(|u| u.origin().ascii_serialization());
    if origin(&upstream_url) != origin(&existing.upstream_url) {
        for table in ["mcp_user_inputs", "mcp_user_credentials"] {
            sqlx::query(sqlx::AssertSqlSafe(format!("DELETE FROM {table} WHERE upstream_server_id = $1")))
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(fail)?;
        }
    }

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

    // cred_version keys the proxy's capability cache and its handshake /
    // listener reset, so it moves with everything that changes what reaches
    // the upstream: the declaration or its fillers, an admin value, the URL,
    // the transport, the OAuth client secret. Cosmetic edits (name,
    // description, enabled, timeouts, oauth_*_url metadata) leave it.
    let bump = remote_changed
        || admin_changed
        || upstream_url != existing.upstream_url
        || transport != existing.transport
        || encrypted_oauth_client_secret.is_some();
    let required_user_input_ids = hi::required_user_input_ids(&specs);

    let row = sqlx::query_as::<_, UpstreamDbRow>(sqlx::AssertSqlSafe(format!(
        r#"UPDATE mcp_upstream_servers SET
               name                   = COALESCE($2, name),
               description            = CASE
                                            WHEN $3::boolean THEN $4
                                            ELSE description
                                        END,
               upstream_url           = $5,
               transport              = $6,
               enabled                = COALESCE($7, enabled),
               connect_timeout_ms     = COALESCE($8, connect_timeout_ms),
               request_timeout_ms     = COALESCE($9, request_timeout_ms),
               remote                 = $10,
               encrypted_admin_inputs = $11,
               required_user_input_ids = $12,
               oauth_issuer_url        = COALESCE($13, oauth_issuer_url),
               oauth_authorization_url = COALESCE($14, oauth_authorization_url),
               oauth_token_url         = COALESCE($15, oauth_token_url),
               oauth_revocation_url    = CASE WHEN $20 THEN $16 ELSE oauth_revocation_url END,
               oauth_client_id         = COALESCE($17, oauth_client_id),
               encrypted_oauth_client_secret = COALESCE($18, encrypted_oauth_client_secret),
               oauth_default_scopes    = CASE WHEN $21 THEN $19 ELSE oauth_default_scopes END,
               cred_version = cred_version + CASE WHEN $22 THEN 1 ELSE 0 END,
               url_variables = $23,
               updated_at = NOW()
           WHERE id = $1
           RETURNING {UPSTREAM_COLS}"#
    )))
    .bind(id)
    .bind(&body.name)
    .bind(description_param.is_some())
    .bind(description_param.flatten())
    .bind(&upstream_url)
    .bind(transport)
    .bind(body.enabled)
    .bind(body.connect_timeout_ms)
    .bind(body.request_timeout_ms)
    .bind(sqlx::types::Json(&remote))
    .bind(sqlx::types::Json(&admin_values))
    .bind(&required_user_input_ids)
    .bind(oauth_issuer_url)
    .bind(oauth_authorization_url)
    .bind(oauth_token_url)
    .bind(oauth_revocation_url)
    .bind(oauth_client_id)
    .bind(encrypted_oauth_client_secret)
    .bind(oauth_default_scopes)
    .bind(body.oauth_revocation_url.is_some()) // $20
    .bind(body.oauth_default_scopes.is_some()) // $21
    .bind(bump) // $22
    .bind(sqlx::types::Json(&url_variables)) // $23
    .fetch_one(&mut *tx)
    .await
    .map_err(fail)?;
    tx.commit().await.map_err(fail)?;

    Ok(Json(row.into()))
}

/// What the console's Test button found on one upstream, probed with the
/// administrator's own values only (no user, no client).
#[derive(Serialize, ToSchema)]
pub struct McpUpstreamTestResult {
    pub upstream_id: Uuid,
    pub upstream_name: String,
    pub upstream_url: String,
    pub auth_mode: String,
    /// One of: `ok`; `needs_user_value` (a required input each user fills —
    /// the test has no user, so it does not call); `needs_client_value` (a
    /// required header the client sends on each request); `needs_user_sign_in`
    /// (a per-user OAuth upstream: the call carries a user's token);
    /// `unavailable` (an administrator value is missing, unreadable or no
    /// longer fits its declaration); `redirected` (a 3xx, never followed);
    /// `http_error`; `jsonrpc_error`.
    pub status: String,
    /// Human-readable detail when `status != ok`, in the gateway's own words
    /// (never text the upstream sent).
    pub error: Option<String>,
    /// The required user-filled inputs the test could not fill.
    pub needs_user_input_ids: Vec<String>,
    /// The required client-filled inputs the test could not fill.
    pub needs_client_input_ids: Vec<String>,
    pub tools: Vec<super::portal_mcp_test::PortalMcpTestEntry>,
    pub prompts: Vec<super::portal_mcp_test::PortalMcpTestEntry>,
    pub resources: Vec<super::portal_mcp_test::PortalMcpTestResource>,
    /// Only for a gateway-internal upstream (the built-in web server): its
    /// configuration state.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub builtin_status: Option<super::portal_mcp_test::PortalMcpBuiltinStatus>,
}

/// Why the console's test does not call the upstream.
#[derive(Debug, PartialEq, Eq)]
struct TestBlocked {
    status: &'static str,
    message: String,
    user_ids: Vec<String>,
    client_ids: Vec<String>,
}

impl TestBlocked {
    fn unavailable(message: impl Into<String>) -> Self {
        Self { status: "unavailable", message: message.into(), user_ids: vec![], client_ids: vec![] }
    }
}

/// Whether a call to an upstream can go out at all, whoever makes it: the
/// administrator's values decrypted, or why every call fails — a stored
/// administrator value that cannot be read, a required one missing, a
/// declaration that no longer validates, or a per-user OAuth upstream with no
/// token URL or client ID. A call that can go out may still wait on a user's
/// or the client's value. The console's test reports these as `unavailable`;
/// the alert scan notifies the administrator of them.
pub(crate) fn upstream_unusable(
    remote: &Remote,
    auth_mode: &str,
    encrypted_admin_inputs: &HashMap<String, String>,
    oauth_token_url: Option<&str>,
    oauth_client_id: Option<&str>,
    log: Log,
) -> Result<HashMap<String, String>, String> {
    let admin = mcp_inputs::decrypt_values_with(encrypted_admin_inputs, log == Log::Warn);
    if admin.len() != encrypted_admin_inputs.len() {
        return Err("a stored administrator value cannot be read; set it again".into());
    }
    let oauth = mcp_inputs::is_oauth(auth_mode);
    if oauth && oauth_token_url.is_none_or(str::is_empty) {
        return Err("its OAuth client has no token URL; set it in the upstream's settings".into());
    }
    if oauth && oauth_client_id.is_none_or(str::is_empty) {
        return Err("its OAuth client has no client ID; set it in the upstream's settings".into());
    }
    match admin_test_auth(remote, oauth, &admin, log) {
        Err(b) if b.status == "unavailable" => Err(b.message),
        _ => Ok(admin),
    }
}

/// Whether a check logs what it finds: the console's test does, once per press;
/// the alert scan, which re-checks every cycle, does not (its notification is
/// the record).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum Log {
    Warn,
    Quiet,
}

/// The headers the console's test sends: the administrator's values alone,
/// through the gateway's own resolver. An input a user or the client fills is
/// reported, never guessed; a per-user OAuth upstream needs a user's token.
fn admin_test_auth(
    remote: &Remote,
    oauth: bool,
    admin: &HashMap<String, String>,
    log: Log,
) -> Result<hi::UpstreamAuth, TestBlocked> {
    let values = hi::InputValues { admin: Some(admin), user: None, client: None };
    match hi::resolve(remote, oauth, values) {
        Ok(_) if oauth => Err(TestBlocked {
            status: "needs_user_sign_in",
            message: "needs a user's OAuth sign-in: every call carries the signed-in user's token".into(),
            user_ids: vec![],
            client_ids: vec![],
        }),
        Ok(auth) => Ok(auth),
        Err(hi::ResolveError::Missing(m)) if !m.admin.is_empty() => Err(TestBlocked::unavailable(format!(
            "an administrator value is missing or no longer fits its declaration: {}",
            m.admin.join(", ")
        ))),
        Err(hi::ResolveError::Missing(m)) => {
            let mut parts = Vec::new();
            if !m.user.is_empty() {
                parts.push(format!("needs a user's value: {}", m.user.join(", ")));
            }
            if !m.client.is_empty() {
                parts.push(format!("needs the client's value: {}", m.client.join(", ")));
            }
            let status = if m.user.is_empty() { "needs_client_value" } else { "needs_user_value" };
            Err(TestBlocked { status, message: parts.join("; "), user_ids: m.user, client_ids: m.client })
        }
        Err(e) => {
            if log == Log::Warn {
                tracing::warn!("admin mcp test: headers unresolved: {e:?}");
            }
            Err(TestBlocked::unavailable("the stored declaration does not validate"))
        }
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/upstream-servers/{id}/actions/test",
    tag = "MCP Servers",
    params(("id" = Uuid, Path, description = "Upstream server ID")),
    responses(
        (status = 200, description = "What the test call to the upstream returned", body = McpUpstreamTestResult),
        (status = 404, description = "Not found", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_mcp_upstream_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<McpUpstreamTestResult>, ApiError> {
    #[derive(sqlx::FromRow)]
    struct TestRow {
        name: String,
        upstream_url: String,
        auth_mode: String,
        remote: sqlx::types::Json<Remote>,
        encrypted_admin_inputs: sqlx::types::Json<HashMap<String, String>>,
        request_timeout_ms: i32,
        oauth_token_url: Option<String>,
        oauth_client_id: Option<String>,
    }
    let row = sqlx::query_as::<_, TestRow>(
        r#"SELECT name, upstream_url, auth_mode, remote, encrypted_admin_inputs, request_timeout_ms,
                  oauth_token_url, oauth_client_id
           FROM mcp_upstream_servers WHERE id = $1"#,
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("admin mcp test: load upstream: {e}");
        ApiError::internal("failed to load mcp upstream server")
    })?
    .ok_or_else(|| ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound))?;

    let mut result = McpUpstreamTestResult {
        upstream_id: id,
        upstream_name: row.name,
        upstream_url: row.upstream_url.clone(),
        auth_mode: row.auth_mode.clone(),
        status: "ok".into(),
        error: None,
        needs_user_input_ids: vec![],
        needs_client_input_ids: vec![],
        tools: vec![],
        prompts: vec![],
        resources: vec![],
        builtin_status: None,
    };

    if streamscope_core::web::is_internal_upstream_url(&row.upstream_url) {
        let tenant_id = db.tenant_uuid();
        let preview =
            super::portal_mcp_test::preview_internal_upstream(db.conn(), tenant_id, &row.upstream_url, "").await?;
        result.tools = preview.tools;
        result.prompts = preview.prompts;
        result.resources = preview.resources;
        result.builtin_status = Some(preview.builtin_status);
        return Ok(Json(result));
    }

    let auth = match upstream_unusable(
        &row.remote.0,
        &row.auth_mode,
        &row.encrypted_admin_inputs.0,
        row.oauth_token_url.as_deref(),
        row.oauth_client_id.as_deref(),
        Log::Warn,
    ) {
        Err(reason) => Err(TestBlocked::unavailable(reason)),
        Ok(admin) => admin_test_auth(&row.remote.0, mcp_inputs::is_oauth(&row.auth_mode), &admin, Log::Warn),
    };
    let auth = match auth {
        Ok(auth) => auth,
        Err(blocked) => {
            result.status = blocked.status.into();
            result.error = Some(blocked.message);
            result.needs_user_input_ids = blocked.user_ids;
            result.needs_client_input_ids = blocked.client_ids;
            return Ok(Json(result));
        }
    };

    // The call may ride TLS to a server behind a private CA: read the trusted
    // CAs fresh (only the replica that imported one refreshes its cache).
    crate::custom_ca::refresh_from_conn(db.conn()).await;
    // The probe can take several upstream round trips: the pooled connection
    // goes back before it, not after.
    drop(db);
    let probe =
        super::portal_mcp_test::probe_upstream(&row.upstream_url, &auth, row.request_timeout_ms, "").await;
    result.status = probe.status.into();
    result.error = probe.error;
    result.tools = probe.tools;
    result.prompts = probe.prompts;
    result.resources = probe.resources;
    Ok(Json(result))
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
// MCP UPSTREAM CONNECTIONS (per-user admin view)
// ===========================================================================
//
// Lists which tenant users have/haven't connected each upstream users connect
// to — a per-user OAuth one, or one with user-filled header inputs — and lets
// the admin revoke a user's connection. LEFT JOINs against `users` so
// disconnected users appear with NULL columns — surfaces the "8 / 12
// connected" tenant-wide picture in one query. The row delete is
// operator-side; the proxy picks it up in the tenant's config body.

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpUpstreamUserConnection {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    /// When the user first connected (OAuth credential, else first filled
    /// input); null when neither exists.
    pub connected_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Bumped on each successful upstream call. Null when never used or not connected.
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Granted OAuth scope (space-separated). Null when not connected.
    pub scope: Option<String>,
    /// True when a `mcp_user_credentials` row exists for this (user, upstream).
    pub has_session: bool,
    /// The user-filled inputs this user has a value for (never the value).
    pub filled_input_ids: Vec<String>,
    /// The user can call the upstream: an OAuth credential when the upstream
    /// is per-user OAuth, and every required user input filled.
    pub connected: bool,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct McpConnectionsListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// When false, only return rows for users who have an OAuth credential
    /// or filled inputs. Default true (connected + disconnected).
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
        (status = 200, description = "Per-user connection state for this upstream", body = OffsetPage<McpUpstreamUserConnection>),
        (status = 400, description = "Users do not connect to this upstream", body = ApiErrorResponse),
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

    // Verify the upstream exists in this tenant (RLS-scoped) and read what a
    // user connects to on it.
    let upstream: Option<(String, sqlx::types::Json<Remote>, Vec<String>)> = sqlx::query_as(
        "SELECT auth_mode, remote, required_user_input_ids FROM mcp_upstream_servers WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list mcp upstream connections (upstream): {e}");
        ApiError::internal("failed to check upstream existence")
    })?;
    let Some((auth_mode, remote, required)) = upstream else {
        return Err(ApiError::not_found("mcp upstream server not found", ApiErrorCode::McpUpstreamServerNotFound));
    };

    // Connections only make sense where a user connects: per-user OAuth, or a
    // user-filled input. Reject any other upstream early so callers don't
    // render a confusing wall of "disconnected" rows.
    let oauth = mcp_inputs::is_oauth(&auth_mode);
    let has_user_inputs = mcp_inputs::stored_specs(id, &remote, &auth_mode)
        .is_some_and(|specs| specs.iter().any(|s| s.filler == Filler::User));
    if !oauth && !has_user_inputs {
        return Err(ApiError::bad_request(
            "users do not connect to this upstream: it has neither per-user OAuth nor user-filled inputs",
        )
        .code(ApiErrorCode::McpUpstreamNotPerUserOauth));
    }

    let connected_only_clause =
        if include_disconnected { "" } else { " AND (c.id IS NOT NULL OR i.id IS NOT NULL)" };
    let sql = format!(
        "SELECT u.id AS user_id, \
                u.email AS email, \
                u.display_name AS display_name, \
                COALESCE(c.created_at, i.created_at) AS connected_at, \
                c.last_used_at AS last_used_at, \
                c.scope AS scope, \
                (c.id IS NOT NULL) AS has_session, \
                ARRAY(SELECT k FROM jsonb_object_keys(COALESCE(i.encrypted_values, '{{}}'::jsonb)) k ORDER BY k) \
                    AS filled_input_ids, \
                ((NOT $4 OR (c.id IS NOT NULL AND (c.expires_at IS NULL OR c.expires_at > now() \
                                                   OR c.encrypted_refresh_token IS NOT NULL))) \
                 AND $5::text[] <@ ARRAY(SELECT jsonb_object_keys(COALESCE(i.encrypted_values, '{{}}'::jsonb)))) \
                    AS connected \
         FROM users u \
         LEFT JOIN mcp_user_credentials c \
                ON c.user_id = u.id AND c.upstream_server_id = $1 \
         LEFT JOIN mcp_user_inputs i \
                ON i.user_id = u.id AND i.upstream_server_id = $1 \
         WHERE u.is_active = true{connected_only_clause} \
         ORDER BY (c.id IS NOT NULL OR i.id IS NOT NULL) DESC, u.email \
         LIMIT $2 OFFSET $3"
    );

    let rows = sqlx::query_as::<_, McpUpstreamUserConnection>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(limit + 1)
        .bind(offset)
        .bind(oauth)
        .bind(&required)
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
    // this is an operator-initiated cleanup: drop the user's OAuth credential
    // and filled inputs together; the proxy picks the change up in the
    // tenant's config body, and the user's next request asks for a re-connect.
    let fail = |e: sqlx::Error| {
        tracing::error!("delete mcp upstream connection: {e}");
        ApiError::internal("failed to delete user connection")
    };
    let mut tx = db.conn().begin().await.map_err(fail)?;
    let creds = sqlx::query(
        "DELETE FROM mcp_user_credentials \
         WHERE upstream_server_id = $1 AND user_id = $2",
    )
    .bind(upstream_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(fail)?
    .rows_affected();
    let inputs = sqlx::query(
        "DELETE FROM mcp_user_inputs \
         WHERE upstream_server_id = $1 AND user_id = $2",
    )
    .bind(upstream_id)
    .bind(user_id)
    .execute(&mut *tx)
    .await
    .map_err(fail)?
    .rows_affected();
    tx.commit().await.map_err(fail)?;

    if creds + inputs == 0 {
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
    /// The headers a client must send to this endpoint (lowercased): the
    /// client-filled inputs of its enabled routes' upstreams.
    #[sqlx(skip)]
    pub client_headers: Vec<String>,
    /// `true` when one of those headers is `Authorization`: the gateway key
    /// then rides the `/fwd/{key}/mcp/<slug>` path instead of that header.
    #[sqlx(skip)]
    pub fwd_mount: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Fill each row's client-header facts.
async fn with_client_facts(
    conn: &mut crate::db::tenant::Scoped,
    rows: &mut [McpVirtualServerRow],
) -> Result<(), ApiError> {
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut facts = mcp_inputs::vs_client_facts(conn, &ids).await?;
    for r in rows {
        let f = facts.remove(&r.id).unwrap_or_default();
        r.client_headers = f.client_headers;
        r.fwd_mount = f.fwd_mount;
    }
    Ok(())
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
    let mut rows = rows;
    with_client_facts(db.conn(), &mut rows).await?;
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
    let mut rows = [row];
    with_client_facts(db.conn(), &mut rows).await?;
    let [row] = rows;
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
        (status = 409, description = "OAuth slug taken in another tenant, or an upstream routed here reads the client's own Authorization", body = ApiErrorResponse),
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
    let current: Option<(String, bool, bool, Option<String>, bool)> = sqlx::query_as(
        r#"SELECT slug,
                  sampling_intercept_enabled,
                  (sampling_credential IS NOT NULL) AS has_cred,
                  sampling_model_alias,
                  oauth_enabled
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
    // Turning OAuth sign-in on: no upstream routed here may read the client's
    // own Authorization, which an OAuth client spends on the gateway's token.
    // The row lock above is the first half of the route binding's lock order.
    if let Some((slug, _, _, _, was_oauth)) = current.as_ref()
        && body.oauth_enabled == Some(true)
        && !was_oauth
    {
        mcp_inputs::check_oauth_sign_in_bindings(&mut tx, id, slug).await?;
    }
    if let Some((_, cur_enabled, cur_has_cred, cur_alias, _)) = current.as_ref() {
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
    let mut rows = [row];
    with_client_facts(db.conn(), &mut rows).await?;
    let [row] = rows;
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
        (status = 409, description = "Prefix collision, a client header collision, or a client-filled Authorization on an OAuth sign-in virtual server", body = ApiErrorResponse),
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

    let fail = |e: sqlx::Error| {
        tracing::error!("create mcp_virtual_route: {e}");
        ApiError::internal("failed to create mcp virtual route")
    };
    let tenant_id = db.tenant_uuid();
    // One transaction: the virtual server row lock taken by the collision
    // check serialises route inserts on it until this one commits.
    let mut tx = db.conn().begin().await.map_err(fail)?;

    // The virtual server and upstream exist in this tenant, and the upstream
    // reads no client header another upstream on this server already reads.
    match mcp_inputs::lock_and_check_route_binding(&mut tx, body.virtual_server_id, body.upstream_server_id)
        .await?
    {
        None => {
            return Err(ApiError::not_found("virtual server not found", ApiErrorCode::McpVirtualServerNotFound));
        }
        Some(false) => {
            return Err(ApiError::not_found("upstream server not found", ApiErrorCode::McpUpstreamServerNotFound));
        }
        Some(true) => {}
    }

    // If prefix is empty, allow only when no other route exists on the
    // virtual server yet (its no-namespacing route; prefixed routes may be
    // added beside it later).
    if prefix.is_empty() {
        let other: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM mcp_virtual_routes WHERE virtual_server_id = $1",
        )
        .bind(body.virtual_server_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(fail)?;
        if other > 0 {
            return Err(ApiError::bad_request(
                "empty prefix is only allowed on the first route of a virtual server",
            )
            .code(ApiErrorCode::McpRoutePrefixInvalid));
        }
    }

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
    .bind(tenant_id)
    .bind(body.virtual_server_id)
    .bind(body.upstream_server_id)
    .bind(&prefix)
    .bind(&body.tools_filter)
    .bind(&body.resources_filter)
    .bind(&body.prompts_filter)
    .bind(enabled)
    .bind(position)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            ApiError::conflict("a route with this prefix already exists on the virtual server", ApiErrorCode::McpRoutePrefixTaken)
        } else {
            tracing::error!("create mcp_virtual_route: {e}");
            ApiError::internal("failed to create mcp virtual route")
        }
    })?;
    tx.commit().await.map_err(fail)?;
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
// Client-header collision rule: `upstream_server_id` and `virtual_server_id`
// are intentionally NOT in the PATCH allow-list — rebinding either would pair
// two upstreams on one virtual server without re-running
// `mcp_inputs::lock_and_check_route_binding`. That check counts disabled routes
// by design, so toggling `enabled` here cannot create a collision either. Do
// not add either id to `UpdateMcpVirtualRoute` without running it.
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

    fn test_remote(headers: &[(&str, bool, Filler)]) -> Remote {
        use streamscope_core::mcp::header_inputs::{Input, InputsMeta, KeyValueInput, RemoteMeta};
        Remote {
            url: "https://mcp.example/mcp".into(),
            headers: headers
                .iter()
                .map(|(name, required, _)| KeyValueInput {
                    name: (*name).into(),
                    input: Input { is_required: *required, ..Default::default() },
                    variables: BTreeMap::new(),
                })
                .collect(),
            meta: Some(RemoteMeta {
                inputs: InputsMeta {
                    fillers: headers.iter().map(|(name, _, f)| ((*name).to_string(), *f)).collect(),
                },
                ..RemoteMeta::default()
            }),
            ..Default::default()
        }
    }

    /// The console's test sends the administrator's values alone: it calls
    /// when they are all the upstream needs (an optional user input left
    /// out), and otherwise names who must supply what — never calling with a
    /// header missing.
    /// Every call fails, whoever makes it, on an unreadable or missing
    /// administrator value or an incomplete OAuth client; one waiting only on
    /// a user's or the client's value is usable (the controls).
    #[test]
    fn an_upstream_is_unusable_only_for_what_the_administrator_must_fix() {
        // SAFETY: same value as every other ENCRYPTION_KEY setter in this binary.
        unsafe {
            std::env::set_var("ENCRYPTION_KEY", "test-oidc-flow-key-long-enough");
        }
        let ct = |v: &str| mcp_inputs::encrypt_value(v).expect("encrypts");
        let r = test_remote(&[("X-Url", true, Filler::Admin), ("X-Token", true, Filler::User)]);
        let set = HashMap::from([("X-Url".to_string(), ct("https://jira"))]);
        let tok = Some("https://idp/token");
        let cid = Some("client");

        // Usable: the admin's value is set; the user's is theirs to fill.
        let admin = upstream_unusable(&r, "headers", &set, None, None, Log::Quiet).expect("usable");
        assert_eq!(admin.get("X-Url").map(String::as_str), Some("https://jira"));
        let client_only = test_remote(&[("X-Key", true, Filler::Client)]);
        assert!(upstream_unusable(&client_only, "headers", &HashMap::new(), None, None, Log::Quiet).is_ok());

        // The admin's required value missing, or stored but unreadable.
        let e = upstream_unusable(&r, "headers", &HashMap::new(), None, None, Log::Quiet).unwrap_err();
        assert!(e.contains("X-Url"), "{e}");
        let bad = HashMap::from([("X-Url".to_string(), "not-a-ciphertext".to_string())]);
        assert!(upstream_unusable(&r, "headers", &bad, None, None, Log::Quiet).unwrap_err().contains("cannot be read"));

        // Per-user OAuth: complete client usable; each missing field named.
        let oauth = test_remote(&[("X-Url", true, Filler::Admin)]);
        assert!(upstream_unusable(&oauth, "per_user_oauth", &set, tok, cid, Log::Quiet).is_ok());
        assert!(upstream_unusable(&oauth, "per_user_oauth", &set, None, cid, Log::Quiet).unwrap_err().contains("token URL"));
        assert!(upstream_unusable(&oauth, "per_user_oauth", &set, Some(""), cid, Log::Quiet).unwrap_err().contains("token URL"));
        assert!(upstream_unusable(&oauth, "per_user_oauth", &set, tok, None, Log::Quiet).unwrap_err().contains("client ID"));
        // The OAuth fields are not read on a header upstream.
        assert!(upstream_unusable(&r, "headers", &set, None, None, Log::Quiet).is_ok());
    }

    #[test]
    fn the_console_test_calls_with_the_admin_values_or_names_what_it_lacks() {
        let admin = HashMap::from([("X-Url".to_string(), "https://jira".to_string())]);
        let none = HashMap::new();

        // Positive: every required input is the admin's; an optional user one is absent.
        let r = test_remote(&[("X-Url", true, Filler::Admin), ("X-Team", false, Filler::User)]);
        let auth = admin_test_auth(&r, false, &admin, Log::Quiet).expect("calls");
        let names: Vec<&str> = auth.headers().iter().map(|(n, _)| n.as_str()).collect();
        assert_eq!(names, vec!["x-url"]);

        // A required user input: reported, not a failure.
        let r = test_remote(&[("X-Url", true, Filler::Admin), ("X-Token", true, Filler::User)]);
        let b = admin_test_auth(&r, false, &admin, Log::Quiet).unwrap_err();
        assert_eq!((b.status, b.user_ids.clone(), b.client_ids.clone()), ("needs_user_value", vec!["X-Token".to_string()], vec![]));
        assert!(b.message.contains("needs a user's value: X-Token"), "{}", b.message);

        // A required client input.
        let r = test_remote(&[("X-Key", true, Filler::Client)]);
        let b = admin_test_auth(&r, false, &none, Log::Quiet).unwrap_err();
        assert_eq!((b.status, b.client_ids.clone()), ("needs_client_value", vec!["X-Key".to_string()]));
        assert!(b.message.contains("needs the client's value: X-Key"), "{}", b.message);

        // Both: the user's need leads, both are named.
        let r = test_remote(&[("X-Token", true, Filler::User), ("X-Key", true, Filler::Client)]);
        let b = admin_test_auth(&r, false, &none, Log::Quiet).unwrap_err();
        assert_eq!(b.status, "needs_user_value");
        assert_eq!((b.user_ids, b.client_ids), (vec!["X-Token".to_string()], vec!["X-Key".to_string()]));

        // The administrator's own value missing: the upstream is unavailable.
        let r = test_remote(&[("X-Url", true, Filler::Admin), ("X-Token", true, Filler::User)]);
        let b = admin_test_auth(&r, false, &none, Log::Quiet).unwrap_err();
        assert_eq!(b.status, "unavailable");
        assert!(b.message.contains("X-Url") && b.user_ids.is_empty(), "{}", b.message);

        // Per-user OAuth: the call needs a user's token, whatever the headers.
        let r = test_remote(&[("X-Url", true, Filler::Admin)]);
        assert_eq!(admin_test_auth(&r, true, &admin, Log::Quiet).unwrap_err().status, "needs_user_sign_in");
        // A remote with no header at all calls with none.
        assert!(admin_test_auth(&test_remote(&[]), false, &none, Log::Quiet).expect("calls").headers().is_empty());
    }

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
