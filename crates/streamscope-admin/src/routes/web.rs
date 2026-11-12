//! Per-tenant web admin endpoints.
//!
//! Three handlers form the operator surface for the built-in `/mcp/web`
//! virtual server:
//!
//! - `GET  /api/v1/admin/settings/web` — typed [`WebSettings`]
//!   plus a `has_credential` indicator (the plaintext is never echoed).
//! - `PATCH  /api/v1/admin/settings/web` — partial update of the
//!   tenant's `system_settings.web` JSON, with an optional
//!   `credential` field that rotates the AES-256-GCM ciphertext stored on
//!   the synthetic `builtin-web` row in `mcp_upstream_servers` (empty string
//!   clears the credential) and an optional `destination_lists` field that
//!   replaces the destination lists the Web tool attaches
//!   (`web_destination_lists`).
//! - `POST /api/v1/admin/web/actions/test` — dispatches one search through
//!   the configured backend with `surface = "admin_test"` so operators can
//!   verify connectivity, URL filters, and SSRF policy without burning real
//!   LLM traffic. The audit row lands in `web_audit` like any other
//!   call.
//!
//! Settings live in `system_settings.web` (one nested JSON object,
//! written atomically via `routes::merge_settings_blob`). Credentials
//! ride on `mcp_upstream_servers.encrypted_credential` so the same
//! AES-256-GCM-at-rest path applied to every other MCP upstream covers the
//! built-in too — there is no plaintext-at-rest path on this surface.

use axum::{Extension, Json, extract::State};
use serde::{Deserialize, Serialize};
use streamscope_core::web::{
    BUILTIN_WEB_UPSTREAM_NAME, FetchProvider, SearchRequest, SearchResult,
    WebAuditRecord, WebContext, WebProvider, WebSettings, WebSurface,
};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::tenant::{AdminTenantCtx, Scoped, TenantConn};

const WEB_SETTINGS_KEY: &str = "web";

// ---------------------------------------------------------------------------
// Wire shapes
// ---------------------------------------------------------------------------

/// Response for `GET /api/v1/admin/settings/web`. The settings struct
/// is the typed projection of `system_settings.web`; `has_credential`
/// is presence-only — the plaintext credential is never echoed back.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WebSettingsResponse {
    #[serde(flatten)]
    pub settings: WebSettings,
    /// `true` iff the synthetic `builtin-web` row carries a non-NULL
    /// `encrypted_credential`.
    pub has_credential: bool,
    /// The destination lists the Web tool attaches: an allow list narrows the
    /// URLs it considers to what it names, a block list removes what it names.
    pub destination_lists: Vec<super::client_access_profiles::AttachedDestinationList>,
}

/// Body for `PATCH /api/v1/admin/settings/web`. Settings fields are
/// optional — partial updates are the norm. The `credential` field is
/// write-only:
///
/// - `Some("...")` (non-empty) → encrypt and store on the `builtin-web` row,
///   bumping `cred_version` so the proxy's hot path picks the change up.
/// - `Some("")` → clear the credential (sets `encrypted_credential = NULL`).
/// - `None` → leave the existing credential in place.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct UpdateWebSettingsRequest {
    /// Tri-state: absent leaves the search backend alone, `null` removes it
    /// (`web_fetch` stays served; `web_search` is withdrawn), a value sets it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<WebProvider>)]
    pub backend: Option<Option<WebProvider>>,
    /// Tri-state like `backend`: absent leaves it, `null` or `""` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub endpoint: Option<Option<String>>,
    /// Tri-state like `backend`: absent leaves it, `null` or `""` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub engine_id: Option<Option<String>>,
    #[serde(default)]
    pub fetch_provider: Option<FetchProvider>,
    #[serde(default)]
    pub max_results: Option<u32>,
    #[serde(default)]
    pub fetch_max_bytes: Option<u64>,
    #[serde(default)]
    pub audit_provider_response_max_kb: Option<u64>,
    #[serde(default)]
    pub substitution_max_iterations: Option<u32>,
    #[serde(default)]
    pub substitution_max_parallel: Option<u32>,
    #[serde(default)]
    pub substitution_round_max_bytes: Option<u64>,
    #[serde(default)]
    pub substitution_history_max_bytes: Option<u64>,
    #[serde(default)]
    pub mixed_pending_cache_ttl_seconds: Option<u64>,
    /// Backend API key plaintext. Encrypted at rest with AES-256-GCM.
    /// A write-only secret: absent or `null` keeps the stored one, `""` clears it.
    #[serde(default)]
    pub credential: Option<String>,
    /// The destination lists the Web tool attaches, each once as allow or
    /// block — the whole set. Absent leaves them as they are.
    #[serde(default)]
    pub destination_lists: Option<Vec<super::client_access_profiles::DestinationAttachment>>,
}

/// Body for `POST /api/v1/admin/web/actions/test`.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct WebTestRequest {
    pub query: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_results: Option<u32>,
}

/// Response for the test search. Wraps the raw [`SearchResult`] alongside
/// the `request_id` of the audit row so operators can correlate.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WebTestResponse {
    pub request_id: Uuid,
    #[serde(flatten)]
    pub result: SearchResult,
}

// ---------------------------------------------------------------------------
// GET — load settings + credential presence
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings/web",
    tag = "Web",
    responses(
        (status = 200, description = "Current web settings", body = WebSettingsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_web_settings(
    mut db: TenantConn,
) -> Result<Json<WebSettingsResponse>, ApiError> {
    let settings = load_settings(db.conn()).await?;
    let has_credential = builtin_has_credential(db.conn()).await?;
    let destination_lists = super::destination_lists::web_attachments(db.conn()).await?;
    Ok(Json(WebSettingsResponse { settings, has_credential, destination_lists }))
}

// ---------------------------------------------------------------------------
// PATCH — partial settings update + optional credential rotation
// ---------------------------------------------------------------------------

#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings/web",
    tag = "Web",
    request_body = UpdateWebSettingsRequest,
    responses(
        (status = 200, description = "Updated settings", body = WebSettingsResponse),
        (status = 400, description = "Invalid body", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
        (status = 503, description = "ENCRYPTION_KEY not configured", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_web_settings(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(body): Json<UpdateWebSettingsRequest>,
) -> Result<Json<WebSettingsResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Build the partial patch (only the fields the caller set, normalized as the
    // typed struct expects) and the full fresh-row base.
    let patch = web_patch_json(&body);
    let base = super::default_merged::<WebSettings>(&patch);

    // Merge atomically and validate the MERGED shape read-after-write, inside a
    // tx: the `ON CONFLICT` row lock the merge takes serializes concurrent
    // writers (so `current` is the true post-merge state, not a stale read +
    // racing write — replacing the advisory lock), and an invalid cross-field
    // combination rolls back via the dropped tx. The optional credential
    // rotation rides the same tx so the two commit together.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin web settings tx: {e}");
        ApiError::internal("failed to update settings")
    })?;
    let (old, new) =
        super::merge_settings_blob(&mut tx, WEB_SETTINGS_KEY, tenant_id, &base, &patch).await?;
    let current: WebSettings = serde_json::from_value(new).map_err(|e| {
        tracing::error!("deserialize merged web settings: {e}");
        ApiError::internal("failed to update settings")
    })?;

    validate_web_settings(&current)?;

    let lists_before = super::destination_lists::web_attachments(&mut tx).await?;
    if let Some(lists) = &body.destination_lists {
        super::destination_lists::set_web_attachments(&mut tx, tenant_id, lists).await?;
    }

    // Credential rotation rides on the synthetic `builtin-web` row.
    if let Some(plain) = body.credential.as_deref() {
        rotate_builtin_credential(&mut tx, tenant_id, plain).await?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("commit web settings tx: {e}");
        ApiError::internal("failed to update settings")
    })?;

    let before: WebSettings = old.and_then(|v| serde_json::from_value(v).ok()).unwrap_or_default();

    let destination_lists = super::destination_lists::web_attachments(db.conn()).await?;
    // Diff the effective settings and the attached lists (the rotated
    // credential is never part of either, so nothing secret rides here).
    audit_sink.record(
        Some(&serde_json::json!({ "settings": before, "destination_lists": lists_before })),
        Some(&serde_json::json!({ "settings": current, "destination_lists": destination_lists })),
    );

    let has_credential = builtin_has_credential(db.conn()).await?;
    Ok(Json(WebSettingsResponse { settings: current, has_credential, destination_lists }))
}

/// Cross-field validation against the merged web settings shape. A set
/// endpoint passes the write-time SSRF check (`extension_http::validate_endpoint`:
/// an http(s) URL with a host, never the metadata address, an internal IP
/// literal only when the platform's `extensions` egress list lists it; a host
/// name is resolved only at call time), SearXNG needs one, and the
/// paid backends + Tavily fetch
/// are not yet implemented. Refusing here avoids committing a row that would
/// 400 every dispatch; called on the post-merge value so a partial PATCH can't
/// land an invalid combination.
fn validate_web_settings(current: &WebSettings) -> Result<(), ApiError> {
    if let Some(endpoint) = current.endpoint.as_deref().map(str::trim).filter(|e| !e.is_empty())
        && let Err(reason) = streamscope_core::extension_http::validate_endpoint(endpoint)
    {
        return Err(ApiError::bad_request(format!("endpoint {reason}")));
    }
    match current.backend {
        Some(WebProvider::Searxng)
            if current.endpoint.as_deref().map(str::trim).unwrap_or("").is_empty() =>
        {
            return Err(ApiError::bad_request("backend `searxng` requires an endpoint URL"));
        }
        Some(
            WebProvider::Brave | WebProvider::Tavily | WebProvider::GoogleCse | WebProvider::Serper,
        ) => {
            return Err(ApiError::bad_request(
                "paid web backends are not yet implemented — use `searxng` or leave the backend unset",
            ));
        }
        _ => {}
    }
    if matches!(current.fetch_provider, FetchProvider::Tavily) {
        return Err(ApiError::bad_request(
            "fetch_provider `tavily` is not yet implemented — use `builtin`",
        ));
    }
    Ok(())
}

/// Partial JSON patch of only the fields the caller set, normalized exactly as
/// the typed struct expects. Keys MUST be the serde field names of
/// [`WebSettings`] — the round-trip test guards against drift. The write-only
/// `credential` field is handled separately (it lives on `builtin-web`, not in
/// the settings struct).
fn web_patch_json(body: &UpdateWebSettingsRequest) -> serde_json::Value {
    let mut p = serde_json::Map::new();
    if let Some(v) = &body.backend {
        // `null` clears it: the settings struct reads a null backend as unset.
        p.insert("backend".into(), serde_json::to_value(v).unwrap_or(serde_json::Value::Null));
    }
    let cleared_or_set = |v: &Option<String>| match v.as_deref() {
        None | Some("") => serde_json::Value::Null,
        Some(s) => serde_json::Value::String(s.to_string()),
    };
    if let Some(e) = &body.endpoint {
        p.insert("endpoint".into(), cleared_or_set(e));
    }
    if let Some(e) = &body.engine_id {
        p.insert("engine_id".into(), cleared_or_set(e));
    }
    if let Some(v) = &body.fetch_provider {
        p.insert("fetch_provider".into(), serde_json::to_value(v).unwrap_or(serde_json::Value::Null));
    }
    if let Some(n) = body.max_results {
        p.insert("max_results".into(), serde_json::json!(n));
    }
    if let Some(n) = body.fetch_max_bytes {
        p.insert("fetch_max_bytes".into(), serde_json::json!(n));
    }
    if let Some(n) = body.audit_provider_response_max_kb {
        p.insert("audit_provider_response_max_kb".into(), serde_json::json!(n));
    }
    if let Some(n) = body.substitution_max_iterations {
        p.insert("substitution_max_iterations".into(), serde_json::json!(n));
    }
    if let Some(n) = body.substitution_max_parallel {
        p.insert("substitution_max_parallel".into(), serde_json::json!(n));
    }
    if let Some(n) = body.substitution_round_max_bytes {
        p.insert("substitution_round_max_bytes".into(), serde_json::json!(n));
    }
    if let Some(n) = body.substitution_history_max_bytes {
        p.insert("substitution_history_max_bytes".into(), serde_json::json!(n));
    }
    if let Some(n) = body.mixed_pending_cache_ttl_seconds {
        p.insert("mixed_pending_cache_ttl_seconds".into(), serde_json::json!(n));
    }
    serde_json::Value::Object(p)
}

// ---------------------------------------------------------------------------
// POST — operator test search
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/admin/web/actions/test",
    tag = "Web",
    request_body = WebTestRequest,
    responses(
        (status = 200, description = "Search dispatched", body = WebTestResponse),
        (status = 400, description = "No backend configured / invalid query", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_web(
    State(state): State<std::sync::Arc<crate::AdminState>>,
    Extension(ctx): Extension<AdminTenantCtx>,
    mut db: TenantConn,
    Json(body): Json<WebTestRequest>,
) -> Result<Json<WebTestResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let admin_account_id = ctx.admin_account_id;

    if body.query.trim().is_empty() {
        return Err(ApiError::bad_request("query must not be empty"));
    }

    let mut settings = load_settings(db.conn()).await?;
    settings.destinations = streamscope_core::web::WebDestinations::from_lists(
        &super::destination_lists::web_lists(db.conn()).await.map_err(|e| {
            tracing::error!("load web destination lists: {e}");
            ApiError::internal("failed to load settings")
        })?,
    );
    if !settings.is_configured() {
        return Err(ApiError::bad_request(
            "no backend configured — set web.backend and its endpoint before running a test",
        )
        .code(ApiErrorCode::WebBackendUnconfigured));
    }

    let credential = load_builtin_credential(db.conn()).await?;
    // Released before the outbound search: the request holds one connection
    // at a time, and the audit row below is written on the ingest door's own.
    drop(db);
    let upstream_id = streamscope_core::web::builtin_upstream_id(tenant_id);

    // The test endpoint runs a single search end-to-end through the same
    // `service::search` path the proxy uses. We capture the audit record
    // through a one-off audit channel and write it directly to the DB
    // afterwards so test traffic is visible alongside production calls.
    let (audit_tx, mut audit_rx) =
        streamscope_core::audit::counted_channel::<WebAuditRecord>(8);

    // The same SSRF guard the proxy's search path applies. Built per probe so
    // it trusts the custom CA bundle current at the time of the test.
    let custom_ca = crate::custom_ca::current();
    let search_clients = streamscope_core::extension_http::ExtensionClients::build(
        "search",
        move || {
            streamscope_core::tls::add_custom_roots(
                reqwest::Client::builder().timeout(std::time::Duration::from_secs(15)),
                custom_ca.as_deref(),
            )
        },
    )
    .map_err(|e| {
        tracing::error!("build web test search clients: {e}");
        ApiError::internal("web test failed")
    })?;

    let request_id = streamscope_core::ids::mint_request_id();
    let result = {
        let ctx = WebContext {
            settings: &settings,
            credential: credential.as_deref(),
            search_clients: &search_clients,
            audit_tx: Some(&audit_tx),
            request_id,
            tenant_id,
            // Operator probe — not tied to a customer workspace.
            workspace_id: Uuid::nil(),
            user_id: admin_account_id,
            upstream_server_id: upstream_id,
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: Some(streamscope_core::middleware::attribution::DETECTION_DIRECT.to_string()),
            ip: None,
            // Operator backend probe — guardrail scanning belongs to live
            // `/mcp/web` traffic, not the connectivity test.
            surface: WebSurface::AdminProbe,
            parent_request_id: None,
            tool_use_id: None,
            cancel_token: None,
        };
        streamscope_core::web::service::search(
            &ctx,
            SearchRequest {
                query: body.query.clone(),
                max_results: body.max_results,
                language: None,
            },
        )
        .await
    };
    drop(audit_tx);

    // Drain whatever the service queued (typically one record per call).
    let mut records: Vec<WebAuditRecord> = Vec::new();
    while let Some(r) = audit_rx.recv().await {
        records.push(r);
    }
    if !records.is_empty()
        && let Ok(mut payload) = serde_json::to_value(&records)
    {
        // The query and the backend's answer are outside text; Postgres
        // stores no U+0000.
        streamscope_core::pg_text::scrub_nul_json(&mut payload);
        // Written as the edge ingest writes it: the audit tables take their
        // rows through the ingest door.
        let written: Result<(), sqlx::Error> = async {
            let mut tx = state.db.begin_ingest().await?;
            crate::edge_v2::writers::insert_web_audit_jsonb(tx.conn(), &payload).await?;
            tx.commit().await
        }
        .await;
        if let Err(e) = written {
            tracing::warn!(
                "test search audit insert failed (search succeeded; row not persisted): {e:?}"
            );
        }
    }

    match result {
        Ok(result) => Ok(Json(WebTestResponse { request_id, result })),
        Err(e) => {
            // Log the full error server-side; surface a sanitised public
            // message + the audit-categorised discriminator so operators can
            // cross-reference the audit row without leaking transport / URL
            // / upstream-body detail to the wire.
            let category = e.category();
            tracing::warn!(
                tenant_id = %tenant_id,
                request_id = %request_id,
                error_category = category,
                "admin test search failed: {e:?}"
            );
            let public = format!(
                "test search failed ({category}); see web_audit for the row"
            );
            // Operator-config issues (no backend, missing credential, invalid
            // config / URL, scheme refused, filter denied) → 400. Upstream
            // / transport / SSRF / oversized / cancelled → 502 (the gateway
            // reached the operator's config but couldn't complete the call).
            // Internal errors → 500.
            use streamscope_core::web::WebError;
            let err = match &e {
                WebError::NoBackend
                | WebError::MissingCredential { .. }
                | WebError::InvalidConfig(_)
                | WebError::InvalidUrl(_)
                | WebError::SchemeRefused(_)
                | WebError::UrlFilterDenied { .. }
                | WebError::PolicyBlocked(_) => ApiError::bad_request(public),
                WebError::SsrfRefused(_)
                | WebError::RateLimited { .. }
                | WebError::UpstreamError { .. }
                | WebError::Transport(_)
                | WebError::Oversized { .. }
                | WebError::Cancelled => ApiError::bad_gateway(public),
                WebError::Internal(_) => ApiError::internal("web test failed"),
            };
            Err(err.code(ApiErrorCode::WebTestFailed))
        }
    }
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

async fn load_settings(
    conn: &mut Scoped,
) -> Result<WebSettings, ApiError> {
    let raw: Option<serde_json::Value> = sqlx::query_scalar(
        "SELECT value FROM system_settings WHERE key = $1",
    )
    .bind(WEB_SETTINGS_KEY)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load web settings: {e}");
        ApiError::internal("failed to load settings")
    })?;
    Ok(raw
        .and_then(|v| serde_json::from_value::<WebSettings>(v).ok())
        .unwrap_or_default())
}

async fn builtin_has_credential(
    conn: &mut Scoped,
) -> Result<bool, ApiError> {
    let row: Option<bool> = sqlx::query_scalar(
        "SELECT (encrypted_credential IS NOT NULL) AS has_credential
         FROM mcp_upstream_servers
         WHERE name = $1 AND built_in",
    )
    .bind(BUILTIN_WEB_UPSTREAM_NAME)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("read builtin-web credential presence: {e}");
        ApiError::internal("failed to load settings")
    })?;
    Ok(row.unwrap_or(false))
}

async fn load_builtin_credential(
    conn: &mut Scoped,
) -> Result<Option<String>, ApiError> {
    let row: Option<(Option<Vec<u8>>,)> = sqlx::query_as(
        "SELECT encrypted_credential FROM mcp_upstream_servers WHERE name = $1 AND built_in",
    )
    .bind(BUILTIN_WEB_UPSTREAM_NAME)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("read builtin-web encrypted credential: {e}");
        ApiError::internal("failed to load credential")
    })?;
    let Some(bytes) = row.and_then(|(b,)| b) else {
        return Ok(None);
    };
    let encoded = String::from_utf8(bytes).map_err(|e| {
        tracing::error!("encrypted credential is not UTF-8 base64: {e}");
        ApiError::internal("failed to load credential")
    })?;
    Ok(streamscope_core::web::decrypt_upstream_credential(&encoded))
}

async fn rotate_builtin_credential(
    conn: &mut Scoped,
    tenant_id: Uuid,
    plain: &str,
) -> Result<(), ApiError> {
    let new_value: Option<Vec<u8>> = if plain.is_empty() {
        None
    } else {
        let key = streamscope_core::crypto::get_encryption_key().ok_or_else(|| {
            tracing::error!("ENCRYPTION_KEY unset — refusing to store web credential");
            ApiError::server_misconfigured("ENCRYPTION_KEY not configured")
        })?;
        let encrypted = streamscope_core::crypto::encrypt(plain, &key).map_err(|e| {
            tracing::error!("encrypt web credential: {e}");
            ApiError::internal("failed to encrypt credential")
        })?;
        Some(encrypted.into_bytes())
    };

    let updated = sqlx::query(
        "UPDATE mcp_upstream_servers
         SET encrypted_credential = $1,
             cred_version = cred_version + 1,
             updated_at = now()
         WHERE name = $2 AND tenant_id = $3 AND built_in",
    )
    .bind(new_value)
    .bind(BUILTIN_WEB_UPSTREAM_NAME)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("rotate builtin-web credential: {e}");
        ApiError::internal("failed to update credential")
    })?;

    if updated.rows_affected() == 0 {
        // The seed pass owns the synthetic row; if it isn't there yet the
        // tenant hasn't completed first-startup seeding. Surface so the UI
        // can suggest a retry rather than silently swallow.
        return Err(ApiError::service_unavailable(
            "builtin-web upstream row not found — tenant seeding incomplete",
        )
        .code(ApiErrorCode::TenantSeedingIncomplete));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn searxng_at(endpoint: &str) -> WebSettings {
        WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some(endpoint.to_string()),
            ..Default::default()
        }
    }

    #[test]
    fn an_endpoint_that_is_not_an_http_url_with_a_host_is_a_400() {
        // No test of this crate lists anything on `extensions`, so an internal
        // literal is refused like the metadata address (the listed side is
        // held by the `extension_http` tests).
        for bad in [
            "searx.example:8080",
            "ftp://searx.example",
            "not a url",
            "file:///etc/passwd",
            "https://10.0.0.5",
            "http://169.254.169.254/",
        ] {
            let err = validate_web_settings(&searxng_at(bad)).expect_err(bad);
            assert_eq!(err.status, axum::http::StatusCode::BAD_REQUEST, "{bad}");
            assert_eq!(err.code, ApiErrorCode::ValidationFailed, "{bad}");
        }
        // Validated whatever the backend: an endpoint left on an unset backend
        // is still a URL the next backend switch would dispatch to.
        let unset = WebSettings { endpoint: Some("nope".into()), ..Default::default() };
        assert!(validate_web_settings(&unset).is_err());
    }

    #[test]
    fn an_http_or_https_endpoint_with_a_host_is_accepted() {
        for good in ["http://search.internal:8080", "https://searx.example/", "https://93.184.216.34"] {
            assert!(validate_web_settings(&searxng_at(good)).is_ok(), "{good}");
        }
        assert!(validate_web_settings(&WebSettings::default()).is_ok());
    }

    // Drift guard for the patch builder: a typo'd JSON key would silently no-op
    // the SQL `value || patch` merge. Round-tripping a full body through
    // `default_merged` (the same shallow merge the SQL `||` applies) proves every
    // key is a real serde field and the per-field normalization survives.
    #[test]
    fn web_patch_round_trips_every_field() {
        let body = UpdateWebSettingsRequest {
            backend: Some(Some(WebProvider::Searxng)),
            endpoint: Some(Some("https://searx.example".into())),
            engine_id: Some(Some("cx-123".into())),
            fetch_provider: Some(FetchProvider::Builtin),
            max_results: Some(42),
            fetch_max_bytes: Some(1234),
            audit_provider_response_max_kb: Some(77),
            substitution_max_iterations: Some(11),
            substitution_max_parallel: Some(3),
            substitution_round_max_bytes: Some(555),
            substitution_history_max_bytes: Some(666),
            mixed_pending_cache_ttl_seconds: Some(99),
            credential: None,
            destination_lists: None,
        };
        let patch = web_patch_json(&body);
        let merged = super::super::default_merged::<WebSettings>(&patch);
        let got: WebSettings = serde_json::from_value(merged).expect("merged base must deserialize");

        assert_eq!(got.backend, Some(WebProvider::Searxng));
        assert_eq!(got.endpoint.as_deref(), Some("https://searx.example"));
        assert_eq!(got.engine_id.as_deref(), Some("cx-123"));
        assert_eq!(got.fetch_provider, FetchProvider::Builtin);
        assert_eq!(got.max_results, 42);
        assert_eq!(got.fetch_max_bytes, 1234);
        assert_eq!(got.audit_provider_response_max_kb, 77);
        assert_eq!(got.substitution_max_iterations, 11);
        assert_eq!(got.substitution_max_parallel, 3);
        assert_eq!(got.substitution_round_max_bytes, 555);
        assert_eq!(got.substitution_history_max_bytes, 666);
        assert_eq!(got.mixed_pending_cache_ttl_seconds, 99);
    }

    /// `"backend": null` removes a configured search backend (the stored blob
    /// is merged with the patch as SQL `value || patch` does); an absent
    /// `backend` leaves it as it is.
    #[test]
    fn a_null_backend_clears_it_and_an_absent_one_keeps_it() {
        let stored = serde_json::to_value(WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some("https://searx.example".into()),
            ..WebSettings::default()
        })
        .unwrap();
        let apply = |body: &str| -> WebSettings {
            let body: UpdateWebSettingsRequest = serde_json::from_str(body).unwrap();
            let mut merged = stored.clone();
            if let (Some(m), serde_json::Value::Object(p)) = (merged.as_object_mut(), web_patch_json(&body)) {
                m.extend(p);
            }
            serde_json::from_value(merged).unwrap()
        };
        assert_eq!(apply(r#"{"backend": null}"#).backend, None);
        // The console sends `null` for an emptied Endpoint field too.
        assert_eq!(apply(r#"{"endpoint": null}"#).endpoint, None);
        assert_eq!(apply(r#"{"max_results": 3}"#).endpoint.as_deref(), Some("https://searx.example"));
        assert_eq!(apply(r#"{"max_results": 3}"#).backend, Some(WebProvider::Searxng));
        assert_eq!(apply(r#"{"backend": "searxng"}"#).backend, Some(WebProvider::Searxng));
    }

    #[test]
    fn web_patch_clears_empty_endpoint_and_engine_id() {
        let body = UpdateWebSettingsRequest {
            endpoint: Some(Some(String::new())),
            engine_id: Some(Some(String::new())),
            ..Default::default()
        };
        let patch = web_patch_json(&body);
        assert_eq!(patch.get("endpoint"), Some(&serde_json::Value::Null));
        assert_eq!(patch.get("engine_id"), Some(&serde_json::Value::Null));
        // `credential` is write-only and never enters the settings patch.
        let body = UpdateWebSettingsRequest {
            credential: Some("sk-secret".into()),
            ..Default::default()
        };
        let patch = web_patch_json(&body);
        assert_eq!(patch.as_object().map(serde_json::Map::len), Some(0));
    }
}
