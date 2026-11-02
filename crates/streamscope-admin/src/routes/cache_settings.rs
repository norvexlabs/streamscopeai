//! Tenant-wide response-cache settings — `GET`/`PATCH
//! /api/v1/admin/settings/cache`.
//!
//! What lives here is what the tenant decides once, across every alias: the
//! master switch and the largest response worth storing. Per-alias policy
//! (mode, TTL, similarity threshold, sharing scope) lives on the named cache
//! preset a route references — see `routes/cache_presets.rs`.
//!
//! Stored as one nested JSON object under `system_settings.cache`, written
//! through `routes::merge_settings_blob` so two concurrent writers compose per
//! top-level key instead of clobbering each other.


use axum::{Extension, Json};
use serde::Deserialize;
use streamscope_core::config::upstream_transport::UpstreamTransport;
use streamscope_core::pricing::{Rates, Unit};
use streamscope_core::proxy::response_cache::CacheSettings;
use utoipa::ToSchema;

use super::{ApiError, ApiErrorResponse};
use crate::db::tenant::TenantConn;

const CACHE_SETTINGS_KEY: &str = "cache";

/// Body for `PATCH /api/v1/admin/settings/cache`. Every field is optional —
/// partial updates are the norm.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
#[serde(default)]
pub struct UpdateCacheSettingsRequest {
    pub enabled: Option<bool>,
    pub max_entry_kb: Option<u32>,
    /// Tri-state: absent leaves the alias alone, `null` clears it (turning
    /// semantic matching off tenant-wide), a string sets it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub embedding_alias: Option<Option<String>>,
    pub embedding_timeout_ms: Option<u32>,
}

/// Largest per-entry ceiling an operator can set. Above this a single response
/// could crowd out most of a replica's cache budget on its own.
const MAX_ENTRY_KB_CEILING: u32 = 8192;

/// Bounds on the embedding round-trip budget. Below the floor no real provider
/// could answer, so semantic matching would never work; above the ceiling the
/// lookup costs more than the upstream call it is trying to avoid.
///
/// The ceiling has to leave a slow provider somewhere to go: a tenant that hits
/// the cap has no remaining lever, and the failure is silent (the alias just
/// degrades to exact-only). It is a per-tenant opt-in bounded by the request
/// that pays for it, so headroom here is cheap.
const MIN_EMBEDDING_TIMEOUT_MS: u32 = 50;
const MAX_EMBEDDING_TIMEOUT_MS: u32 = 15_000;

/// Bound on the embeddings-probe response body. The probe only reads the
/// vector's length, and the URL it reaches is tenant-admin-writable.
const EMBED_PROBE_BODY_CAP: u64 = 4 * 1024 * 1024;

/// Build the partial patch: only the keys the caller actually set. Keys MUST be
/// exact serde field names of [`CacheSettings`] — the round-trip test below is
/// the drift guard, because a typo'd key would silently no-op the SQL merge.
fn cache_patch_json(body: &UpdateCacheSettingsRequest) -> serde_json::Value {
    let mut patch = serde_json::Map::new();
    if let Some(v) = body.enabled {
        patch.insert("enabled".to_string(), serde_json::json!(v));
    }
    if let Some(v) = body.max_entry_kb {
        patch.insert("max_entry_kb".to_string(), serde_json::json!(v));
    }
    // `Some(None)` is an explicit clear, and JSON null is exactly what the
    // merged blob must end up holding for `Option<String>` to read back as
    // "unset" — so both arms of the outer `Some` write a key.
    if let Some(v) = &body.embedding_alias {
        patch.insert(
            "embedding_alias".to_string(),
            match v.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
                Some(s) => serde_json::json!(s),
                None => serde_json::Value::Null,
            },
        );
    }
    if let Some(v) = body.embedding_timeout_ms {
        patch.insert("embedding_timeout_ms".to_string(), serde_json::json!(v));
    }
    serde_json::Value::Object(patch)
}

/// Validate what the caller SET, before anything is written.
///
/// `merge_settings_blob` autocommits, so a post-merge check would reject the
/// request while leaving the bad value persisted — and `max_entry_kb = 0` makes
/// every store refuse `entry_too_large`, silently disabling the tenant's cache.
/// Every field here is an independent scalar, so the request body is sufficient;
/// there is no cross-field rule needing the merged state.
fn validate(body: &UpdateCacheSettingsRequest) -> Result<(), ApiError> {
    if let Some(kb) = body.max_entry_kb
        && !(1..=MAX_ENTRY_KB_CEILING).contains(&kb)
    {
        return Err(ApiError::bad_request(format!(
            "max_entry_kb must be between 1 and {MAX_ENTRY_KB_CEILING}"
        )));
    }
    if let Some(ms) = body.embedding_timeout_ms
        && !(MIN_EMBEDDING_TIMEOUT_MS..=MAX_EMBEDDING_TIMEOUT_MS).contains(&ms)
    {
        return Err(ApiError::bad_request(format!(
            "embedding_timeout_ms must be between {MIN_EMBEDDING_TIMEOUT_MS} and {MAX_EMBEDDING_TIMEOUT_MS}"
        )));
    }
    Ok(())
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings/cache",
    tag = "Settings",
    responses(
        (status = 200, description = "Tenant response-cache settings", body = CacheSettings),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_cache_settings(mut db: TenantConn) -> Result<Json<CacheSettings>, ApiError> {
    Ok(Json(load_cache_settings(&mut db).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/settings/cache",
    tag = "Settings",
    request_body = UpdateCacheSettingsRequest,
    responses(
        (status = 200, description = "Updated settings", body = CacheSettings),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_cache_settings(
    Extension(audit_sink): Extension<crate::middleware::AuditDiffSink>,
    mut db: TenantConn,
    Json(body): Json<UpdateCacheSettingsRequest>,
) -> Result<Json<CacheSettings>, ApiError> {
    validate(&body)?;
    let tenant_id = db.tenant_uuid();
    let patch = cache_patch_json(&body);
    let base = super::default_merged::<CacheSettings>(&patch);

    // One statement under the ON CONFLICT row lock: no load→edit→save window, so
    // two concurrent edits to different keys both land.
    let (old, new) =
        super::merge_settings_blob(db.conn(), CACHE_SETTINGS_KEY, tenant_id, &base, &patch).await?;
    let current: CacheSettings = serde_json::from_value(new).map_err(|e| {
        tracing::error!("deserialize merged cache settings: {e}");
        ApiError::internal("failed to update settings")
    })?;

    let before: Option<CacheSettings> = old.and_then(|v| serde_json::from_value(v).ok());
    audit_sink.record(before.as_ref(), Some(&current));
    Ok(Json(current))
}

// ---------------------------------------------------------------------------
// Embedding-alias probe
// ---------------------------------------------------------------------------

/// Body for `POST /api/v1/admin/settings/cache/actions/probe-embedding`.
///
/// The alias is passed explicitly rather than read from the stored settings so
/// the UI can check a candidate before committing it.
#[derive(Debug, Clone, Deserialize, ToSchema)]
pub struct ProbeEmbeddingRequest {
    pub alias: String,
}

/// What one bound target answered.
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct EmbeddingProbeTarget {
    pub provider: String,
    pub server: String,
    pub upstream_model: String,
    pub ok: bool,
    /// Stable machine-readable outcome. The UI branches on this, never on
    /// `message`.
    pub code: String,
    pub message: Option<String>,
    /// Vector width, when one came back.
    pub dimensions: Option<i32>,
    pub elapsed_ms: u32,
}

/// Result of probing an embedding alias.
#[derive(Debug, Clone, serde::Serialize, ToSchema)]
pub struct ProbeEmbeddingResponse {
    pub alias: String,
    /// True only when **every** target the runtime can pick succeeded.
    pub ok: bool,
    pub targets: Vec<EmbeddingProbeTarget>,
    /// Non-fatal problems worth showing: unpriced model, load-balanced alias,
    /// non-standard endpoint paths.
    pub warnings: Vec<String>,
    /// Set when a successful probe reclassified a model as an embedding model.
    pub classified: Vec<String>,
}

/// One candidate target, as the routing table sees it.
#[derive(sqlx::FromRow)]
struct ProbeTargetRow {
    model_id: uuid::Uuid,
    provider_id: uuid::Uuid,
    provider_name: String,
    server_name: String,
    upstream_model: String,
    upstream_url: Option<String>,
    encrypted_key: Option<String>,
    byok: bool,
    api_format: String,
    chat_endpoint_path: Option<String>,
    /// How the server is addressed and authenticated. The probe must build the
    /// same URL with the same credential header the proxy will, or a correctly
    /// configured Azure server fails a check it should pass.
    transport: String,
    model_type: String,
    priority: i32,
    /// Resolved price list — the model's own map, else the catalog row of the
    /// SAME provider. An empty map is a price nobody has on file, which stays
    /// distinct from a rate of zero meaning the model is genuinely free.
    #[sqlx(json)]
    rates: Rates,
}

/// Largest slice of an upstream error kept for the admin's diagnosis.
///
/// The text is what makes a refusal actionable (`'input_type' parameter is
/// required for asymmetric models` names the exact problem), so it is kept — but
/// bounded, because an upstream may answer with an arbitrarily large body. This
/// is the admin plane; the rule against forwarding upstream bodies protects
/// data-plane clients.
const MAX_UPSTREAM_MESSAGE_BYTES: usize = 400;

fn truncate_upstream_message(body: &str) -> String {
    let trimmed = body.trim();
    if trimmed.len() <= MAX_UPSTREAM_MESSAGE_BYTES {
        return trimmed.to_string();
    }
    let cut = trimmed.floor_char_boundary(MAX_UPSTREAM_MESSAGE_BYTES);
    format!("{}…", &trimmed[..cut])
}

/// Probe one target with the SAME call the proxy's cache would make.
///
/// Fidelity is the whole point: the body is `{model, input}` and nothing else,
/// the path is `/v1/embeddings`, and the credential is a bearer token that is
/// deliberately EMPTY for a keyless server — which is exactly what the proxy
/// sends, and what an unauthenticated self-hosted embedder accepts. Adding a
/// parameter to make a refusing model pass here would make the probe lie.
async fn probe_one_target(
    row: &ProbeTargetRow,
    timeout: std::time::Duration,
) -> (bool, String, Option<String>, Option<i32>, u32) {
    // Structural refusals, decided from row data alone — no network call, no
    // spend, and a far more actionable message than the 401/404 the call would
    // produce.
    if row.byok {
        return (
            false,
            "byok_passthrough".into(),
            Some(
                "This alias resolves through a pass-through provider, which forwards the caller's \
                 own credential. The cache has no caller to borrow from, so it can never embed here."
                    .into(),
            ),
            None,
            0,
        );
    }
    if matches!(row.api_format.as_str(), "google_gemini" | "anthropic_messages") {
        return (
            false,
            "provider_protocol_unsupported".into(),
            Some(format!(
                "The gateway's embedding call speaks only the OpenAI embeddings shape, and this \
                 server is {}. Point the alias at an OpenAI-compatible embeddings endpoint.",
                row.api_format
            )),
            None,
            0,
        );
    }
    let Some(base) = row.upstream_url.as_deref().filter(|u| !u.is_empty()) else {
        return (
            false,
            "no_upstream_url".into(),
            Some("This server has no URL configured.".into()),
            None,
            0,
        );
    };

    let api_key = match super::upstreams::decrypt_server_key(row.encrypted_key.clone()) {
        Ok(k) => k.unwrap_or_default(),
        Err(_) => {
            return (
                false,
                "credential_unreadable".into(),
                Some("This server's stored credential could not be decrypted.".into()),
                None,
                0,
            );
        }
    };

    match streamscope_core::proxy::client::check_provider_url(base) {
        Ok(()) => {}
        Err(streamscope_mcp_auth::ssrf::SsrfError::InternalAddress) => {
            return (false, "egress_refused".into(), Some(super::upstreams::PROVIDER_NOT_LISTED.into()), None, 0);
        }
        Err(_) => {
            return (
                false,
                "upstream_url_invalid".into(),
                Some("This server's URL is not an http(s) URL with a host.".into()),
                None,
                0,
            );
        }
    }
    let client = match super::upstreams::upstream_probe_client() {
        Ok(c) => c,
        Err(e) => {
            // Falling back to a default client would drop the imported CAs and
            // then blame the operator for a trust store they already fixed.
            tracing::error!("build probe client: {e}");
            return (
                false,
                "probe_setup_failed".into(),
                Some("The gateway could not build an HTTPS client for this check.".into()),
                None,
                0,
            );
        }
    };

    // Concatenated exactly the way the proxy builds it — no trailing-slash
    // normalisation. A URL stored with a trailing slash yields `//v1/embeddings`
    // at runtime, and a probe that quietly tidied that up would pass while every
    // real request 404s.
    let transport = UpstreamTransport::from_str_relaxed(&row.transport);
    let url = if transport.owns_url() {
        transport.upstream_url(base, "/v1/embeddings")
    } else {
        format!("{base}/v1/embeddings")
    };
    let started = std::time::Instant::now();
    let mut req = client
        .post(&url)
        .timeout(timeout)
        .json(&serde_json::json!({ "model": row.upstream_model, "input": "probe" }));
    // Authenticated exactly the way the proxy authenticates a real request, so a
    // probe cannot pass on a credential the data plane would reject.
    let endpoint = streamscope_core::proxy::client::UpstreamEndpoint {
        url: base,
        api_key: &api_key,
        transport,
    };
    req = match endpoint.stored_credential_header().await {
        Ok(Some((name, value))) => req.header(name, value),
        // Protocol-decided: this probe is the OpenAI-shaped embeddings endpoint.
        Ok(None) => req.header("Authorization", format!("Bearer {api_key}")),
        Err(_) => {
            return (
                false,
                "credential_unreadable".into(),
                Some("The gateway could not obtain a token for this server's credential.".into()),
                None,
                0,
            );
        }
    };
    let resp = req.send().await;
    let elapsed_ms = started.elapsed().as_millis().min(u128::from(u32::MAX)) as u32;

    match resp {
        // The guard refused the address the name resolved to: said as such,
        // never with the resolved address (a probe is no oracle into the
        // private network).
        Err(e) if let Some(refused) = super::upstreams::egress_refusal_message(&e) => {
            (false, "egress_refused".into(), Some(refused.to_string()), None, elapsed_ms)
        }
        Err(e) => {
            let chain = super::upstreams::error_source_chain(&e);
            let msg = if super::upstreams::is_tls_trust_error(&chain) {
                format!(
                    "TLS certificate for {url} is not trusted — import its CA under \
                     Settings → Trusted CAs (super-admin)."
                )
            } else {
                truncate_upstream_message(&chain)
            };
            (false, "unreachable".into(), Some(msg), None, elapsed_ms)
        }
        Ok(r) if !r.status().is_success() => {
            let status = r.status().as_u16();
            let body = super::upstreams::read_capped_lossy(
                r,
                super::upstreams::PROBE_ERROR_BODY_CAP,
            )
            .await;
            // Summarised, never echoed raw. This probe resolves through the
            // tenant's own routes to a tenant-admin-writable upstream URL, so a
            // verbatim body makes the probe a read primitive for whatever that
            // URL reaches. The shared summariser drops HTML outright and caps
            // the rest — the same bound model discovery uses.
            let snippet = super::upstreams::summarize_probe_body(&body);
            let msg = if snippet.is_empty() {
                status.to_string()
            } else {
                format!("{status}: {snippet}")
            };
            (false, "upstream_rejected".into(), Some(msg), None, elapsed_ms)
        }
        Ok(r) => match streamscope_core::http_body::read_body_capped(r, EMBED_PROBE_BODY_CAP)
            .await
            .ok()
            .and_then(|raw| serde_json::from_slice::<serde_json::Value>(&raw).ok())
        {
            Some(body) => match embedding_dimensions(&body) {
                Some(d) => (true, "ok".into(), None, Some(d), elapsed_ms),
                None => (
                    false,
                    "no_vector".into(),
                    Some(
                        "The server answered, but the response carried no usable embedding vector."
                            .into(),
                    ),
                    None,
                    elapsed_ms,
                ),
            },
            None => (
                false,
                "no_vector".into(),
                Some("The server's response was not readable JSON.".into()),
                None,
                elapsed_ms,
            ),
        },
    }
}

/// Width of the first vector in an OpenAI-shaped embeddings response.
///
/// Mirrors the runtime parser's acceptance rule — a body this rejects is a body
/// the cache could not have used either.
fn embedding_dimensions(body: &serde_json::Value) -> Option<i32> {
    let raw = body
        .get("data")?
        .as_array()?
        .first()?
        .get("embedding")?
        .as_array()?;
    if raw.is_empty() || !raw.iter().all(|v| v.as_f64().is_some_and(f64::is_finite)) {
        return None;
    }
    i32::try_from(raw.len()).ok()
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/settings/cache/actions/probe-embedding",
    tag = "Settings",
    request_body = ProbeEmbeddingRequest,
    responses(
        (status = 200, description = "Probe result", body = ProbeEmbeddingResponse),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn probe_embedding_alias(
    Extension(audit_sink): Extension<crate::middleware::AuditDiffSink>,
    mut db: TenantConn,
    Json(body): Json<ProbeEmbeddingRequest>,
) -> Result<Json<ProbeEmbeddingResponse>, ApiError> {
    let alias = body.alias.trim().to_string();
    if alias.is_empty() {
        return Err(ApiError::bad_request("alias must not be empty"));
    }

    // Fresh trusted-CA read: the cache is process-local and only the replica
    // that handled the import refreshes it, so an outbound TLS hop on a
    // sibling replica would otherwise use a stale trust set.
    crate::custom_ca::refresh_from_conn(db.conn()).await;

    // Same joins, filters and ordering the config snapshot uses to build the
    // routing table, so what is probed is what the proxy will resolve. The
    // catalog LATERAL is the real pricing resolution — a simpler COALESCE would
    // drift from what the audit row is actually priced with.
    let rows: Vec<ProbeTargetRow> = sqlx::query_as(sqlx::AssertSqlSafe(
        &*crate::routes::with_catalog_join(
        concat!(r#"SELECT m.id                      AS model_id,
                  dp.id                     AS provider_id,
                  dp.name                   AS provider_name,
                  s.name                    AS server_name,
                  m.upstream_model,
                  "#, server_url_sql!("s"), r#" AS upstream_url,
                  s.encrypted_key,
                  dp.byok,
                  COALESCE(m.upstream_api_format, s.upstream_api_format) AS api_format,
                  s.chat_endpoint_path,
                  s.transport,
                  COALESCE(m.model_type, 'text') AS model_type,
                  r.priority,
                  COALESCE(m.rates, catp.rates, '{}'::jsonb) AS rates
           FROM downstream_routes r
           JOIN downstream_providers dp ON dp.id = r.provider_id
           JOIN upstream_models m ON m.id = r.model_id
           JOIN upstream_servers s ON s.id = m.server_id
--{catalog_join}
           WHERE r.alias = $1 AND "#, live_route_sql!(), r#"
           ORDER BY dp.id, r.priority DESC, r.weight DESC"#),
            "m",
            "s",
        ),
    ))
    .bind(&alias)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("probe embedding alias: {e}");
        ApiError::internal("failed to resolve alias")
    })?;

    // No binding at all. Includes the case where the alias is served only by a
    // pass-through downstream — that is a fallback for absent aliases, not a
    // route, so it never appears here and the runtime could never embed with it.
    if rows.is_empty() {
        return Ok(Json(ProbeEmbeddingResponse {
            alias,
            ok: false,
            targets: Vec::new(),
            warnings: Vec::new(),
            classified: Vec::new(),
        }));
    }

    // The routing table is built PER DOWNSTREAM PROVIDER, and a key resolves an
    // alias only within its own provider's map. So each provider has its own
    // highest-priority group, and every one of them must work — a single global
    // maximum would certify one provider's binding while another provider's keys
    // silently resolve something else.
    //
    // Within a group the proxy round-robins and the cache takes the first
    // resolved target without ever failing over, so every member of a group is
    // reachable in practice and all of them must pass.
    let mut groups: std::collections::BTreeMap<uuid::Uuid, Vec<&ProbeTargetRow>> =
        std::collections::BTreeMap::new();
    for row in &rows {
        let group = groups.entry(row.provider_id).or_default();
        match group.first() {
            // Rows arrive priority-descending per provider, so the first row
            // fixes that provider's serving priority.
            Some(first) if first.priority != row.priority => continue,
            _ => group.push(row),
        }
    }

    // Probe each distinct model once even when several providers route to it —
    // the answer is a property of the model, and a duplicate probe is duplicate
    // spend.
    let mut seen = std::collections::HashSet::new();
    let candidates: Vec<&ProbeTargetRow> = groups
        .values()
        .flatten()
        .copied()
        .filter(|r| seen.insert(r.model_id))
        .collect();

    // The budget the runtime actually enforces. A probe given a longer leash
    // would pass on an embedder that times out on every real request.
    let settings = load_cache_settings(&mut db).await?;
    let timeout = settings.embedding_timeout();

    let mut targets = Vec::with_capacity(candidates.len());
    let mut warnings = Vec::new();
    let mut classified = Vec::new();
    let mut all_ok = true;

    for row in &candidates {
        let (ok, code, message, dimensions, elapsed_ms) = probe_one_target(row, timeout).await;
        // A call that answered only just inside the budget will not survive
        // ordinary variance, and a timeout at runtime is a silent downgrade to
        // exact-only matching.
        if ok && u128::from(elapsed_ms) * 5 >= timeout.as_millis() * 4 {
            warnings.push(format!(
                "{} answered in {elapsed_ms} ms, close to the {} ms limit — raise the embedding \
                 timeout or expect intermittent misses.",
                row.upstream_model,
                timeout.as_millis()
            ));
        }
        // Absent, not zero: a rate of zero is an operator saying the model is
        // free, which needs no warning. Only an unknown price does — that one is
        // recorded at a floor of zero, so the spend it hides is real.
        if ok && !row.rates.units.contains_key(&Unit::InputToken) {
            warnings.push(format!(
                "{} has no input price on file, so every embedding will be recorded at $0.",
                row.upstream_model
            ));
        }
        if !ok && row.chat_endpoint_path.is_some() {
            warnings.push(format!(
                "{} uses a non-standard endpoint path; the cache always calls /v1/embeddings.",
                row.server_name
            ));
        }
        all_ok &= ok;
        if ok && row.model_type != "embedding" {
            classified.push(row.upstream_model.clone());
        }
        targets.push(EmbeddingProbeTarget {
            provider: row.provider_name.clone(),
            server: row.server_name.clone(),
            upstream_model: row.upstream_model.clone(),
            ok,
            code,
            message,
            dimensions,
            elapsed_ms,
        });
    }

    // Reported per provider: only models inside one provider's serving group
    // ever share traffic, so two providers each routing one model is not a split.
    for group in groups.values() {
        let distinct = group.iter().map(|r| r.model_id).collect::<std::collections::HashSet<_>>();
        if distinct.len() > 1 {
            warnings.push(format!(
                "Under {}, this alias is load-balanced across several embedding models. Each keeps \
                 its own vector space, so cached answers are split between them.",
                group[0].provider_name
            ));
        }
    }

    // Record what the probe proved, keyed by the model row that was actually
    // probed — matching on the model NAME would stamp a failing row whenever a
    // same-named sibling on another server passed. `model_type` is not part of
    // the config snapshot, so this needs no tenant dirty-marking.
    let to_stamp: Vec<uuid::Uuid> = candidates
        .iter()
        .zip(&targets)
        .filter(|(row, t)| t.ok && row.model_type != "embedding")
        .map(|(row, _)| row.model_id)
        .collect();
    if !to_stamp.is_empty() {
        let mut tx = db.conn().begin().await.map_err(|e| {
            tracing::error!("stamp embedding model_type: {e}");
            ApiError::internal("failed to record model classification")
        })?;
        for id in &to_stamp {
            sqlx::query("UPDATE upstream_models SET model_type = 'embedding' WHERE id = $1")
                .bind(id)
                .execute(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("stamp embedding model_type: {e}");
                    ApiError::internal("failed to record model classification")
                })?;
        }
        tx.commit().await.map_err(|e| {
            tracing::error!("stamp embedding model_type: {e}");
            ApiError::internal("failed to record model classification")
        })?;
    }

    // The generic change-diff registry has no entry for a settings route, and
    // this one mutates `upstream_models` besides — so the summary is stamped
    // explicitly or the action leaves no admin-audit trace.
    audit_sink.set(
        serde_json::json!({
            "alias": alias,
            "unclassified_models": candidates
                .iter()
                .filter(|r| r.model_type != "embedding")
                .map(|r| r.upstream_model.clone())
                .collect::<Vec<_>>(),
        }),
        serde_json::json!({
            "alias": alias,
            "ok": all_ok,
            "targets_probed": targets.len(),
            "classified_as_embedding": classified,
            "outcomes": targets.iter().map(|t| serde_json::json!({
                "upstream_model": t.upstream_model,
                "code": t.code,
            })).collect::<Vec<_>>(),
        }),
    );

    Ok(Json(ProbeEmbeddingResponse {
        alias,
        ok: all_ok,
        targets,
        warnings,
        classified,
    }))
}

/// One selectable alias for the embedding picker.
#[derive(Debug, Clone, serde::Serialize, ToSchema, sqlx::FromRow)]
pub struct EmbeddingAliasOption {
    pub alias: String,
    /// True once a probe has confirmed this alias produces vectors.
    pub verified: bool,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/settings/cache/embedding-aliases",
    tag = "Settings",
    responses(
        (status = 200, description = "Aliases selectable as an embedding source",
         body = super::OffsetPage<EmbeddingAliasOption>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_embedding_aliases(
    mut db: TenantConn,
) -> Result<Json<super::OffsetPage<EmbeddingAliasOption>>, ApiError> {
    // Every routable alias, with the ones already proven to embed marked. The
    // list is deliberately not filtered down to verified aliases: an alias is
    // usually chosen before it has ever been probed.
    let items: Vec<EmbeddingAliasOption> = sqlx::query_as(concat!(
        r#"SELECT r.alias,
                  bool_or(COALESCE(m.model_type, 'text') = 'embedding') AS verified
           FROM downstream_routes r
           JOIN upstream_models m ON m.id = r.model_id
           JOIN upstream_servers s ON s.id = m.server_id
           WHERE "#, live_route_sql!(), r#"
           GROUP BY r.alias
           ORDER BY bool_or(COALESCE(m.model_type, 'text') = 'embedding') DESC, r.alias"#,
    ))
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list embedding aliases: {e}");
        ApiError::internal("failed to load aliases")
    })?;

    Ok(Json(super::OffsetPage {
        limit: items.len() as i64,
        offset: 0,
        has_more: false,
        scan_cut: false,
        items,
    }))
}

/// The tenant's stored cache settings, or the compiled defaults.
async fn load_cache_settings(db: &mut TenantConn) -> Result<CacheSettings, ApiError> {
    let raw: Option<serde_json::Value> =
        sqlx::query_scalar("SELECT value FROM system_settings WHERE key = $1")
            .bind(CACHE_SETTINGS_KEY)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("load cache settings: {e}");
                ApiError::internal("failed to load settings")
            })?;
    Ok(raw
        .and_then(|v| serde_json::from_value::<CacheSettings>(v).ok())
        .unwrap_or_default())
}

#[cfg(test)]
mod tests {
    use super::*;

    // Drift guard for the patch builder: a typo'd JSON key would silently no-op
    // the SQL `value || patch` merge. Round-tripping a full body through
    // `default_merged` (the same shallow merge the SQL `||` applies) proves every
    // key is a real serde field.
    #[test]
    fn cache_patch_round_trips_every_field() {
        let body = UpdateCacheSettingsRequest {
            enabled: Some(false),
            max_entry_kb: Some(512),
            embedding_alias: Some(Some("embed-small".to_string())),
            embedding_timeout_ms: Some(400),
        };
        let patch = cache_patch_json(&body);
        let merged = super::super::default_merged::<CacheSettings>(&patch);
        let got: CacheSettings =
            serde_json::from_value(merged).expect("merged base must deserialize");
        assert!(!got.enabled);
        assert_eq!(got.max_entry_kb, 512);
        assert_eq!(got.embedding_alias.as_deref(), Some("embed-small"));
        assert_eq!(got.embedding_timeout_ms, 400);
    }

    #[test]
    fn clearing_the_embedding_alias_writes_a_null_the_merge_can_apply() {
        // An absent key would leave the old alias in the blob; only an explicit
        // null overwrites it through the SQL `value || patch` merge.
        let patch = cache_patch_json(&UpdateCacheSettingsRequest {
            embedding_alias: Some(None),
            ..Default::default()
        });
        assert_eq!(patch.get("embedding_alias"), Some(&serde_json::Value::Null));
        let got: CacheSettings =
            serde_json::from_value(super::super::default_merged::<CacheSettings>(&patch))
                .expect("merged base must deserialize");
        assert_eq!(got.embedding_alias, None);

        // Whitespace is the same intent as clearing — an all-spaces alias would
        // otherwise resolve to nothing on every request.
        let blank = cache_patch_json(&UpdateCacheSettingsRequest {
            embedding_alias: Some(Some("   ".to_string())),
            ..Default::default()
        });
        assert_eq!(blank.get("embedding_alias"), Some(&serde_json::Value::Null));
    }

    #[test]
    fn empty_body_patches_nothing() {
        let patch = cache_patch_json(&UpdateCacheSettingsRequest::default());
        assert_eq!(patch.as_object().map(serde_json::Map::len), Some(0));
    }

    #[test]
    fn validation_rejects_out_of_range_entry_size_before_writing() {
        assert!(validate(&UpdateCacheSettingsRequest {
            max_entry_kb: Some(0),
            ..Default::default()
        })
        .is_err());
        assert!(validate(&UpdateCacheSettingsRequest {
            max_entry_kb: Some(MAX_ENTRY_KB_CEILING + 1),
            ..Default::default()
        })
        .is_err());
        assert!(validate(&UpdateCacheSettingsRequest {
            max_entry_kb: Some(512),
            ..Default::default()
        })
        .is_ok());
        // An untouched field is nothing to validate.
        assert!(validate(&UpdateCacheSettingsRequest::default()).is_ok());
    }

    #[test]
    fn validation_bounds_the_embedding_timeout() {
        for ms in [0, MIN_EMBEDDING_TIMEOUT_MS - 1, MAX_EMBEDDING_TIMEOUT_MS + 1] {
            assert!(
                validate(&UpdateCacheSettingsRequest {
                    embedding_timeout_ms: Some(ms),
                    ..Default::default()
                })
                .is_err(),
                "{ms} ms should be rejected"
            );
        }
        assert!(validate(&UpdateCacheSettingsRequest {
            embedding_timeout_ms: Some(300),
            ..Default::default()
        })
        .is_ok());
    }
}
