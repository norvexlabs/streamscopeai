//! Downstream provider and route management.
//!
//! Downstream providers represent client-facing API endpoints with their own
//! model alias mappings. Routes bind a downstream provider to upstream models,
//! controlling which models are available to which API keys. Each route maps
//! a client-visible alias to a specific upstream server + model pair.


use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use utoipa::ToSchema;

use super::key_lifecycle::{DeletionResponse, DryRunQuery};
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::{Scoped, TenantConn};
use streamscope_core::proxy::routing::ModelCapabilities as Caps;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Downstream Provider types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateProviderRequest {
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    /// **Create-only** — ignored on update. The link to an upstream server is a
    /// structural relationship set when the provider is created (a mirror's
    /// source, or a BYOK pass-through target); `update_provider` deliberately
    /// leaves it untouched so a name/description/icon edit can never re-point or
    /// unlink it. This body type is shared by the PUT route, where the field is
    /// accepted but silently unused.
    pub upstream_server_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct ProviderResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub upstream_server_id: Option<Uuid>,
    pub route_count: i64,
    /// Number of workspaces whose allowlist includes this provider. Keys are no
    /// longer provider-bound, so this measures provider reach across workspaces.
    pub workspace_count: i64,
    /// `true` for a BYOK pass-through downstream (keyless upstream; clients
    /// forward their own credential, unconfigured models pass through). Granting
    /// one to a workspace lets its members provision `vk-` keys against it.
    pub byok: bool,
    /// Its linked upstream server's on/off state (`true` when linked to none).
    /// For a pass-through it is the live-grant rule: one that is not enabled
    /// reaches nothing and is not offered for grants.
    pub enabled: bool,
    /// A seed-shipped pass-through: switched on and off from its server and
    /// granted per workspace, never edited or deleted here (both answer
    /// `409 BuiltinProviderProtected`).
    pub is_builtin: bool,
    /// The workspaces whose allowlist holds this provider, by name.
    pub granted_workspaces: Vec<GrantedWorkspace>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A workspace holding a grant on a provider.
#[derive(Serialize, ToSchema)]
pub struct GrantedWorkspace {
    pub id: Uuid,
    pub name: String,
}

#[derive(sqlx::FromRow)]
struct ProviderRow {
    id: Uuid,
    tenant_id: Uuid,
    name: String,
    description: Option<String>,
    icon: Option<String>,
    upstream_server_id: Option<Uuid>,
    route_count: Option<i64>,
    workspace_count: Option<i64>,
    #[sqlx(default)]
    byok: bool,
    enabled: bool,
    is_builtin: bool,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl ProviderRow {
    fn into_response(self, granted_workspaces: Vec<GrantedWorkspace>) -> ProviderResponse {
        let row = self;
        ProviderResponse {
            id: row.id,
            tenant_id: row.tenant_id,
            name: row.name,
            description: row.description,
            icon: row.icon,
            upstream_server_id: row.upstream_server_id,
            route_count: row.route_count.unwrap_or(0),
            workspace_count: row.workspace_count.unwrap_or(0),
            byok: row.byok,
            enabled: row.enabled,
            is_builtin: row.is_builtin,
            granted_workspaces,
            created_at: row.created_at,
        }
    }
}

/// The workspaces granting each of `provider_ids`, by provider, in name order.
async fn granted_workspaces(
    conn: &mut Scoped,
    provider_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, Vec<GrantedWorkspace>>, ApiError> {
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT a.downstream_provider_id, w.id, w.name \
         FROM workspace_downstream_access a \
         JOIN workspaces w ON w.id = a.workspace_id \
         WHERE a.downstream_provider_id = ANY($1) \
         ORDER BY w.name, w.id",
    )
    .bind(provider_ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("list provider grants: {e}");
        ApiError::internal("Failed to list downstream providers")
    })?;
    let mut by_provider: std::collections::HashMap<Uuid, Vec<GrantedWorkspace>> = std::collections::HashMap::new();
    for (provider_id, id, name) in rows {
        by_provider.entry(provider_id).or_default().push(GrantedWorkspace { id, name });
    }
    Ok(by_provider)
}

#[derive(Serialize, ToSchema)]
pub struct ProviderDetailResponse {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    pub upstream_server_id: Option<Uuid>,
    pub routes: Vec<RouteResponse>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

// ---------------------------------------------------------------------------
// Downstream Route types
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct CreateRouteRequest {
    pub alias: String,
    pub model_id: Uuid,
    /// Invocation preset to bind. Absent / null = the model's **default** preset.
    /// The preset MUST belong to `model_id`. The route is a pure pointer — it does
    /// not redefine the upstream's capabilities/window/protocol/healing (those are
    /// model truth) nor its invocation beyond selecting a preset.
    #[serde(default)]
    pub preset_id: Option<Uuid>,
    /// Response-cache policy to bind. Absent / null = the alias is uncached.
    #[serde(default)]
    pub cache_preset_id: Option<Uuid>,
    pub priority: Option<i32>,
    pub weight: Option<i32>,
    /// Client-facing advertised window (token-scaling). The one alias-scoped
    /// client knob; never sent upstream.
    pub client_context_window: Option<i32>,
    /// Operator-supplied client tags (e.g. `["opencode", "claude-code"]`)
    /// used by the portal quickstart renderer to filter routes per client.
    /// Empty / absent = visible to every client.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Subset of `tags` marking this route as the canonical default for the
    /// named tag — the renderer's top-level `{{model_alias}}` resolves to a
    /// route whose `default_for_tags` contains the template's tag.
    #[serde(default)]
    pub default_for_tags: Option<Vec<String>>,
    /// When a `default_for_tags` entry is already claimed by another route in
    /// this provider, move the default to this route (clearing it from the
    /// others) instead of rejecting. Absent / false ⇒ reject with
    /// `RouteDefaultTagConflict` so the caller can confirm first.
    #[serde(default)]
    pub reassign_default_tags: Option<bool>,
}

/// A client model slot besides the default: `fast` for a client's
/// background work (titles, search, commit messages), `plan` for its planning
/// model. One route per slot in a provider, and one route may fill both; a
/// client config whose slot no route fills uses the default route there.
#[derive(Serialize, Deserialize, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ClientSlot {
    Fast,
    Plan,
}

impl ClientSlot {
    /// The column's spelling (CHECK-constrained to these two).
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Fast => "fast",
            Self::Plan => "plan",
        }
    }

    pub(crate) fn parse(s: &str) -> Option<Self> {
        match s {
            "fast" => Some(Self::Fast),
            "plan" => Some(Self::Plan),
            _ => None,
        }
    }
}

#[derive(Deserialize, ToSchema)]
pub struct BatchCreateRoutesRequest {
    pub routes: Vec<CreateRouteRequest>,
}

#[derive(Serialize, ToSchema)]
pub struct BatchCreateRoutesResponse {
    pub items: Vec<RouteResponse>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateRouteRequest {
    pub alias: Option<String>,
    pub model_id: Option<Uuid>,
    /// Bound invocation preset — tri-state PATCH: absent = unchanged, explicit
    /// `null` = reset to the model's default preset, value = bind that preset
    /// (which MUST belong to the route's model).
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<Uuid>)]
    pub preset_id: Option<Option<Uuid>>,
    /// Bound cache preset — tri-state PATCH: absent = unchanged, explicit
    /// `null` = stop caching this alias, value = bind that preset.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<Uuid>)]
    pub cache_preset_id: Option<Option<Uuid>>,
    pub priority: Option<i32>,
    pub weight: Option<i32>,
    /// The window advertised to this alias's clients — tri-state: absent =
    /// unchanged, explicit `null` = advertise the model's own, value = that.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<i32>)]
    pub client_context_window: Option<Option<i32>>,
    pub enabled: Option<bool>,
    /// Replaces the existing tag set when present. Pass `[]` to clear.
    #[serde(default)]
    pub tags: Option<Vec<String>>,
    /// Replaces the existing default-for-tags set when present. Pass `[]`
    /// to clear.
    #[serde(default)]
    pub default_for_tags: Option<Vec<String>>,
    /// When a `default_for_tags` entry is already claimed by another route in
    /// this provider, move the default to this route (clearing it from the
    /// others) instead of rejecting. Absent / false ⇒ reject with
    /// `RouteDefaultTagConflict` so the caller can confirm first.
    #[serde(default)]
    pub reassign_default_tags: Option<bool>,
    /// Which priority classes this target may serve. Replaces the set when
    /// present; `[]` means every class, which is what every route starts as.
    #[serde(default)]
    pub qos_class_ids: Option<Vec<Uuid>>,
    /// The client model slots this route fills — tri-state PATCH: absent =
    /// unchanged, explicit `null` (or `[]`) = none, a list = exactly those
    /// (each taken off the provider's route that held it).
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<Vec<ClientSlot>>)]
    pub client_slots: Option<Option<Vec<ClientSlot>>>,
}

#[derive(Serialize, Clone, ToSchema)]
pub struct RouteResponse {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub alias: String,
    /// Null when the route is **orphaned** — its upstream model (or server) was
    /// deleted. The row is kept (disabled, flagged) for cleanup; see `disabled_reason`.
    pub model_id: Option<Uuid>,
    pub upstream_model: Option<String>,
    pub server_id: Option<Uuid>,
    pub server_name: Option<String>,
    pub provider: Option<String>,
    pub priority: i32,
    pub weight: i32,
    pub client_context_window: Option<i32>,
    /// Bound invocation preset (NULL = the model's default preset).
    pub preset_id: Option<Uuid>,
    /// Resolved preset name (the route's preset, else the model's default).
    /// NULL when the route is orphaned (no model).
    pub preset_name: Option<String>,
    /// Bound response-cache preset (NULL = the alias is uncached).
    pub cache_preset_id: Option<Uuid>,
    /// Name of the bound cache preset, for display without a second lookup.
    pub cache_preset_name: Option<String>,
    /// Resolved model type (upstream model → 'text').
    pub model_type: Option<String>,
    pub tags: Vec<String>,
    pub default_for_tags: Vec<String>,
    /// The client model slots this route fills.
    pub client_slots: Vec<ClientSlot>,
    /// Priority classes this target accepts; empty = every class.
    #[serde(default)]
    pub qos_class_ids: Vec<Uuid>,
    // Resolved capabilities (COALESCE'd: upstream model → catalog)
    pub resolved_supports_vision: bool,
    pub resolved_supports_reasoning: bool,
    pub resolved_supports_function_calling: bool,
    pub resolved_supports_caching: bool,
    pub resolved_supports_audio_input: bool,
    pub resolved_supports_audio_output: bool,
    pub resolved_supports_video_input: bool,
    pub resolved_supports_pdf_input: bool,
    pub resolved_supports_response_schema: bool,
    pub resolved_supports_system_messages: bool,
    /// Resolved window/output (COALESCE'd: upstream model → catalog).
    /// NULL = the bound model declares no value (unknown). This is the honest
    /// real window the proxy/`GET /v1/models` advertise — distinct from
    /// `client_context_window` (token-scaling).
    pub resolved_context_window: Option<i32>,
    pub resolved_max_output_tokens: Option<i32>,
    pub auto_synced: bool,
    pub enabled: bool,
    /// Why the route is disabled, if it is: `upstream_model_vanished` (soft —
    /// model gone from the provider, reinstated if it returns) or
    /// `upstream_model_deleted` (orphan — operator deleted the model/server).
    pub disabled_reason: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(sqlx::FromRow)]
struct RouteRow {
    id: Uuid,
    provider_id: Uuid,
    alias: String,
    model_id: Option<Uuid>,
    upstream_model: Option<String>,
    server_id: Option<Uuid>,
    server_name: Option<String>,
    provider: Option<String>,
    priority: i32,
    weight: i32,
    client_context_window: Option<i32>,
    #[sqlx(default)]
    preset_id: Option<Uuid>,
    #[sqlx(default)]
    preset_name: Option<String>,
    #[sqlx(default)]
    cache_preset_id: Option<Uuid>,
    #[sqlx(default)]
    cache_preset_name: Option<String>,
    model_type: Option<String>,
    tags: Vec<String>,
    default_for_tags: Vec<String>,
    client_slots: Vec<String>,
    #[sqlx(default)]
    qos_class_ids: Vec<Uuid>,
    // Resolved capabilities
    #[sqlx(default)]
    resolved_supports_vision: Option<bool>,
    #[sqlx(default)]
    resolved_supports_reasoning: Option<bool>,
    #[sqlx(default)]
    resolved_supports_function_calling: Option<bool>,
    #[sqlx(default)]
    resolved_supports_caching: Option<bool>,
    #[sqlx(default)]
    resolved_supports_audio_input: Option<bool>,
    #[sqlx(default)]
    resolved_supports_audio_output: Option<bool>,
    #[sqlx(default)]
    resolved_supports_video_input: Option<bool>,
    #[sqlx(default)]
    resolved_supports_pdf_input: Option<bool>,
    #[sqlx(default)]
    resolved_supports_response_schema: Option<bool>,
    #[sqlx(default)]
    resolved_supports_system_messages: Option<bool>,
    #[sqlx(default)]
    resolved_context_window: Option<i32>,
    #[sqlx(default)]
    resolved_max_output_tokens: Option<i32>,
    auto_synced: bool,
    enabled: bool,
    #[sqlx(default)]
    disabled_reason: Option<String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl From<RouteRow> for RouteResponse {
    fn from(row: RouteRow) -> Self {
        Self {
            id: row.id,
            provider_id: row.provider_id,
            alias: row.alias,
            model_id: row.model_id,
            upstream_model: row.upstream_model,
            server_id: row.server_id,
            server_name: row.server_name,
            provider: row.provider,
            priority: row.priority,
            weight: row.weight,
            model_type: row.model_type,
            client_context_window: row.client_context_window,
            preset_id: row.preset_id,
            preset_name: row.preset_name,
            cache_preset_id: row.cache_preset_id,
            cache_preset_name: row.cache_preset_name,
            tags: row.tags,
            default_for_tags: row.default_for_tags,
            client_slots: row.client_slots.iter().filter_map(|s| ClientSlot::parse(s)).collect(),
            qos_class_ids: row.qos_class_ids,
            // Resolved capabilities: NULL falls back to the standard text-LLM
            // baseline — the SAME constants the proxy resolves with.
            resolved_supports_vision: row.resolved_supports_vision.unwrap_or(Caps::DEFAULT_VISION),
            resolved_supports_reasoning: row.resolved_supports_reasoning.unwrap_or(Caps::DEFAULT_REASONING),
            resolved_supports_function_calling: row.resolved_supports_function_calling.unwrap_or(Caps::DEFAULT_FUNCTION_CALLING),
            resolved_supports_caching: row.resolved_supports_caching.unwrap_or(Caps::DEFAULT_CACHING),
            resolved_supports_audio_input: row.resolved_supports_audio_input.unwrap_or(Caps::DEFAULT_AUDIO_INPUT),
            resolved_supports_audio_output: row.resolved_supports_audio_output.unwrap_or(Caps::DEFAULT_AUDIO_OUTPUT),
            resolved_supports_video_input: row.resolved_supports_video_input.unwrap_or(Caps::DEFAULT_VIDEO_INPUT),
            resolved_supports_pdf_input: row.resolved_supports_pdf_input.unwrap_or(Caps::DEFAULT_PDF_INPUT),
            resolved_supports_response_schema: row.resolved_supports_response_schema.unwrap_or(Caps::DEFAULT_RESPONSE_SCHEMA),
            resolved_supports_system_messages: row.resolved_supports_system_messages.unwrap_or(Caps::DEFAULT_SYSTEM_MESSAGES),
            resolved_context_window: row.resolved_context_window,
            resolved_max_output_tokens: row.resolved_max_output_tokens,
            auto_synced: row.auto_synced,
            enabled: row.enabled,
            disabled_reason: row.disabled_reason,
            created_at: row.created_at,
        }
    }
}

// The route is a pure pointer: capabilities / window / model_type are upstream
// model truth (resolved model → catalog, no route override term); invocation
// rides the bound preset (`pr`, the route's preset or the model's default).
/// Built once from the shared [`crate::routes::catalog_join`], so route
/// capability inheritance uses the same ladder as every other resolution site.
static ROUTE_SELECT: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
    crate::routes::with_catalog_join(ROUTE_SELECT_TEMPLATE, "m", "s")
});

const ROUTE_SELECT_TEMPLATE: &str = concat!(r#"
    SELECT r.id, r.provider_id, r.alias, r.model_id,
           m.upstream_model, s.id as server_id, s.name as server_name, s.provider,
           r.priority, r.weight,
           r.client_context_window,
           r.preset_id, pr.name as preset_name,
           r.cache_preset_id, cachep.name as cache_preset_name,
           COALESCE(m.model_type, 'text') as model_type,
           r.tags, r.default_for_tags,
           COALESCE((SELECT array_agg(cs.slot ORDER BY cs.slot) FROM route_client_slots cs
                     WHERE cs.tenant_id = r.tenant_id AND cs.route_id = r.id), '{}') as client_slots,
           -- Resolved capabilities: upstream model → catalog → default
           COALESCE(m.supports_vision, c.supports_vision) as resolved_supports_vision,
           COALESCE(m.supports_reasoning, c.supports_reasoning) as resolved_supports_reasoning,
           COALESCE(m.supports_function_calling, c.supports_function_calling) as resolved_supports_function_calling,
           COALESCE(m.supports_caching, c.supports_caching) as resolved_supports_caching,
           COALESCE(m.supports_audio_input, c.supports_audio_input) as resolved_supports_audio_input,
           COALESCE(m.supports_audio_output, c.supports_audio_output) as resolved_supports_audio_output,
           COALESCE(m.supports_video_input, c.supports_video_input) as resolved_supports_video_input,
           COALESCE(m.supports_pdf_input, c.supports_pdf_input) as resolved_supports_pdf_input,
           COALESCE(m.supports_response_schema, c.supports_response_schema) as resolved_supports_response_schema,
           COALESCE(m.supports_system_messages, c.supports_system_messages) as resolved_supports_system_messages,
           COALESCE(m.context_window, c.context_window) as resolved_context_window,
           "#, resolved_max_output_sql!("m", "c"), r#" as resolved_max_output_tokens,
           r.auto_synced, r.enabled, r.disabled_reason, r.created_at,
           -- Which priority classes this target accepts. An empty array means
           -- every class: the restriction is opt-in.
           COALESCE((SELECT array_agg(rq.qos_class_id)
                     FROM route_qos_classes rq WHERE rq.route_id = r.id), '{}') as qos_class_ids
    FROM downstream_routes r
    LEFT JOIN upstream_models m ON m.id = r.model_id
    LEFT JOIN upstream_servers s ON s.id = m.server_id
    LEFT JOIN model_presets pr
        ON pr.id = COALESCE(
            r.preset_id,
            (SELECT d.id FROM model_presets d WHERE d.model_id = m.id AND d.is_default)
        )
    LEFT JOIN cache_presets cachep ON cachep.id = r.cache_preset_id
--{catalog_join}
"#);

/// Conflict target matching `idx_downstream_routes_unique` (`NULLS NOT
/// DISTINCT`, so a NULL `preset_id` — the model's default preset — is a value
/// and the default-preset route participates in uniqueness). The index is
/// partial on a present model, so the target restates its predicate.
const ROUTE_CONFLICT: &str = "(tenant_id, provider_id, alias, model_id, preset_id) WHERE model_id IS NOT NULL";

/// Fetch one fully-resolved route row by id (used after create/update mutations).
async fn fetch_route_by_id(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<RouteRow, sqlx::Error> {
    sqlx::query_as::<_, RouteRow>(sqlx::AssertSqlSafe(&*format!(
        "{} WHERE r.id = $1", ROUTE_SELECT.as_str()
    )))
    .bind(id)
    .fetch_one(conn)
    .await
}

/// Verify a cache preset exists within this tenant. `None` (= uncached) always
/// passes.
///
/// The FK alone is NOT enough: Postgres enforces foreign keys with elevated
/// privileges that ignore RLS, so a guessed UUID would otherwise let a route
/// bind another tenant's cache preset. The explicit `tenant_id` predicate is
/// the isolation check.
async fn verify_cache_preset(
    conn: &mut Scoped,
    tenant_id: Uuid,
    cache_preset_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(cid) = cache_preset_id else {
        return Ok(());
    };
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM cache_presets WHERE id = $1 AND tenant_id = $2)",
    )
    .bind(cid)
    .bind(tenant_id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        tracing::error!("verify cache preset: {e}");
        ApiError::internal("Failed to verify cache preset")
    })?;
    if !ok {
        return Err(ApiError::bad_request("cache preset not found")
            .code(ApiErrorCode::CachePresetNotFound));
    }
    Ok(())
}

/// Verify a preset belongs to the given model within the tenant. Returns
/// `PresetNotFound` otherwise. `None` preset_id (= model default) always passes.
async fn verify_preset_for_model(
    conn: &mut Scoped,
    tenant_id: Uuid,
    model_id: Uuid,
    preset_id: Option<Uuid>,
) -> Result<(), ApiError> {
    let Some(pid) = preset_id else { return Ok(()) };
    let ok: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM model_presets WHERE id = $1 AND model_id = $2 AND tenant_id = $3)",
    )
    .bind(pid)
    .bind(model_id)
    .bind(tenant_id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        tracing::error!("verify preset for model: {e}");
        ApiError::internal("Failed to verify preset")
    })?;
    if !ok {
        return Err(ApiError::bad_request("Preset does not belong to this model")
            .code(ApiErrorCode::PresetNotFound));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Downstream Provider CRUD
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/downstream-providers",
    tag = "Downstream Providers",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of downstream providers", body = TotalPage<ProviderResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_providers(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<ProviderResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let tenant_id = db.tenant_uuid();
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM downstream_providers WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("count downstream providers: {e}");
        ApiError::internal("Failed to list downstream providers")
    })?;
    let rows = sqlx::query_as::<_, ProviderRow>(
        r#"SELECT p.id, p.tenant_id, p.name, p.description, p.icon, p.upstream_server_id, p.byok, p.is_builtin, p.created_at,
                  COALESCE((SELECT s.enabled FROM upstream_servers s WHERE s.id = p.upstream_server_id), true) AS enabled,
                  COUNT(DISTINCT r.id)::bigint as route_count,
                  COUNT(DISTINCT wda.workspace_id)::bigint as workspace_count
           FROM downstream_providers p
           LEFT JOIN downstream_routes r ON r.provider_id = p.id
           LEFT JOIN workspace_downstream_access wda ON wda.downstream_provider_id = p.id
           WHERE p.tenant_id = $1
           GROUP BY p.tenant_id, p.id
           ORDER BY p.name LIMIT $2 OFFSET $3"#,
    )
    .bind(tenant_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list downstream providers: {e}");
        ApiError::internal("Failed to list downstream providers")
    })?;

    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut grants = granted_workspaces(db.conn(), &ids).await?;
    let items: Vec<ProviderResponse> = rows
        .into_iter()
        .map(|r| {
            let granted = grants.remove(&r.id).unwrap_or_default();
            r.into_response(granted)
        })
        .collect();
    Ok(Json(TotalPage::new(items, limit, offset, total)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/downstream-providers",
    tag = "Downstream Providers",
    request_body = CreateProviderRequest,
    responses(
        (status = 201, description = "Provider created", body = ProviderResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "A provider with that name already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_provider(
    mut db: TenantConn,
    Json(req): Json<CreateProviderRequest>,
) -> Result<(StatusCode, Json<ProviderResponse>), ApiError> {
    let row = sqlx::query_as::<_, ProviderRow>(
        r#"INSERT INTO downstream_providers (tenant_id, name, description, icon, upstream_server_id)
           VALUES ($1, $2, $3, $4, $5)
           RETURNING id, tenant_id, name, description, icon, upstream_server_id, byok, is_builtin, created_at, 0::bigint as route_count, 0::bigint as workspace_count,
                     COALESCE((SELECT s.enabled FROM upstream_servers s WHERE s.id = upstream_server_id), true) AS enabled"#,
    )
    .bind(db.tenant_uuid())
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.icon)
    .bind(req.upstream_server_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        // `idx_downstream_providers_name` is UNIQUE on (tenant_id, name), so a
        // repeat is an ordinary, caller-resolvable conflict — not a fault. It
        // needs the typed 409 for two reasons: the UI branches on `code`, and a
        // caller that first LOOKS for the provider and creates it when absent
        // races every concurrent caller doing the same, so the loser must be
        // able to tell "someone else just made it" from "the server broke".
        if super::is_unique_violation(&e) {
            return ApiError::conflict("A provider with that name already exists", ApiErrorCode::DownstreamNameTaken);
        }
        tracing::error!("create downstream provider: {e}");
        ApiError::internal("Failed to create downstream provider")
    })?;

    Ok((StatusCode::CREATED, Json(row.into_response(Vec::new()))))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/downstream-providers/{id}",
    tag = "Downstream Providers",
    params(("id" = Uuid, Path, description = "Provider ID")),
    responses(
        (status = 200, description = "Provider details with routes", body = ProviderDetailResponse),
        (status = 404, description = "Provider not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_provider(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ProviderDetailResponse>, ApiError> {
    let provider = sqlx::query_as::<_, ProviderRow>(
        r#"SELECT p.id, p.tenant_id, p.name, p.description, p.icon, p.upstream_server_id, p.byok, p.is_builtin, p.created_at,
                  COALESCE((SELECT s.enabled FROM upstream_servers s WHERE s.id = p.upstream_server_id), true) AS enabled,
                  COUNT(DISTINCT r.id)::bigint as route_count,
                  COUNT(DISTINCT wda.workspace_id)::bigint as workspace_count
           FROM downstream_providers p
           LEFT JOIN downstream_routes r ON r.provider_id = p.id
           LEFT JOIN workspace_downstream_access wda ON wda.downstream_provider_id = p.id
           WHERE p.id = $1 AND p.tenant_id = $2
           GROUP BY p.tenant_id, p.id"#,
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get downstream provider: {e}");
        ApiError::internal("Failed to fetch downstream provider")
    })?
    .ok_or_else(|| ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound))?;

    let routes = sqlx::query_as::<_, RouteRow>(
        sqlx::AssertSqlSafe(&*format!("{} WHERE r.provider_id = $1 ORDER BY r.alias, r.priority DESC, r.weight DESC", ROUTE_SELECT.as_str()),
    ))
    .bind(id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get downstream routes: {e}");
        ApiError::internal("Failed to fetch downstream routes")
    })?;

    Ok(Json(ProviderDetailResponse {
        id: provider.id,
        tenant_id: provider.tenant_id,
        name: provider.name,
        description: provider.description,
        icon: provider.icon,
        upstream_server_id: provider.upstream_server_id,
        routes: routes.into_iter().map(Into::into).collect(),
        created_at: provider.created_at,
    }))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/downstream-providers/{id}",
    tag = "Downstream Providers",
    params(("id" = Uuid, Path, description = "Provider ID")),
    request_body = CreateProviderRequest,
    responses(
        (status = 200, description = "Updated provider", body = ProviderResponse),
        (status = 404, description = "Provider not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "A provider with that name already exists", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_provider(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<CreateProviderRequest>,
) -> Result<Json<ProviderResponse>, ApiError> {
    // Built-in BYOK pass-throughs are seed-managed and undeletable; renaming one
    // would break the `(tenant_id, name)` seed upsert key, so the next startup
    // sync would create a fresh copy beside it (the delete-guard's resurrection
    // hole via the back door). Refuse every mutation — control exposure by
    // turning its server off or by workspace grants instead.
    let is_builtin: Option<bool> = sqlx::query_scalar(
        "SELECT is_builtin FROM downstream_providers WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update downstream builtin check: {e}");
        ApiError::internal("Failed to update downstream provider")
    })?;
    if is_builtin == Some(true) {
        return Err(ApiError::conflict(
            "built-in BYOK provider cannot be edited; turn its server off or revoke its workspace grants instead",
            ApiErrorCode::BuiltinProviderProtected,
        ));
    }

    // `upstream_server_id` is a STRUCTURAL link set at creation (a mirror's source
    // server, or a BYOK downstream's keyless upstream) — NOT an editable provider
    // field. It is deliberately left untouched here: overwriting it from the request
    // would (a) null a mirror/BYOK link on a name-only edit (the UI omits the field),
    // and (b) let a BYOK downstream be re-pointed onto a managed server, which the
    // next server edit would then treat as BYOK and silently wipe its stored
    // credential. To change a provider's upstream, delete and recreate it.
    let row = sqlx::query_as::<_, ProviderRow>(
        r#"WITH updated AS (
               UPDATE downstream_providers SET
                   name = $2,
                   description = $3,
                   icon = $4
               WHERE id = $1 AND tenant_id = $5
               RETURNING *
           )
           SELECT u.id, u.tenant_id, u.name, u.description, u.icon, u.upstream_server_id, u.byok, u.is_builtin, u.created_at,
                  COALESCE((SELECT s.enabled FROM upstream_servers s WHERE s.id = u.upstream_server_id), true) AS enabled,
                  (SELECT COUNT(*) FROM downstream_routes WHERE provider_id = u.id)::bigint as route_count,
                  (SELECT COUNT(*) FROM workspace_downstream_access WHERE downstream_provider_id = u.id)::bigint as workspace_count
           FROM updated u"#,
    )
    .bind(id)
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.icon)
    .bind(db.tenant_uuid())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        // A rename lands on the same `idx_downstream_providers_name` the create
        // does, so the taken-name case is a conflict here too. Keep the two arms
        // in step: this predicate and `create_provider`'s guard the one index,
        // and a fix applied to only one of them leaves the other answering a
        // caller-resolvable clash as a server fault.
        if super::is_unique_violation(&e) {
            return ApiError::conflict("A provider with that name already exists", ApiErrorCode::DownstreamNameTaken);
        }
        tracing::error!("update downstream provider: {e}");
        ApiError::internal("Failed to update downstream provider")
    })?
    .ok_or_else(|| ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound))?;

    let granted = granted_workspaces(db.conn(), &[row.id]).await?.remove(&row.id).unwrap_or_default();
    Ok(Json(row.into_response(granted)))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/downstream-providers/{id}",
    tag = "Downstream Providers",
    params(("id" = Uuid, Path, description = "Provider ID"), DryRunQuery),
    responses(
        (status = 200, description = "Provider deleted (or dry-run impact)", body = DeletionResponse),
        (status = 404, description = "Provider not found", body = ApiErrorResponse),
        (status = 409, description = "A built-in pass-through (`builtin_provider_protected`)", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_provider(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(q): Query<DryRunQuery>,
) -> Result<Json<DeletionResponse>, ApiError> {
    // Built-in BYOK pass-through downstreams are seed-managed and controlled by
    // turning their server on/off and by workspace grants, not deletion —
    // deleting one would let the next startup sync re-create it. Refuse (its
    // linked keyless upstream is likewise protected in delete_server).
    let row: Option<(bool, bool, Option<Uuid>)> = sqlx::query_as(
        "SELECT is_builtin, byok, upstream_server_id FROM downstream_providers WHERE id = $1 AND tenant_id = $2",
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete downstream provider read: {e}");
        ApiError::internal("Failed to delete downstream provider")
    })?;
    let Some((is_builtin, byok, server_id)) = row else {
        return Err(ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound));
    };
    if is_builtin {
        return Err(ApiError::conflict(
            "built-in BYOK provider cannot be deleted; turn its server off or revoke its workspace grants instead",
            ApiErrorCode::BuiltinProviderProtected,
        ));
    }

    // A pass-through is deleted as one unit with its keyless server, through
    // the one function that deletes either half; the preview is that deletion,
    // rolled back. No provider lock is taken before it: it locks the server
    // first, then the provider.
    if let (true, Some(server_id)) = (byok, server_id) {
        let tenant = db.tenant_uuid();
        let mut tx = db.conn().begin().await.map_err(|e| {
            tracing::error!("delete pass-through begin: {e}");
            ApiError::internal("Failed to delete downstream provider")
        })?;
        // The provider goes with its server — or it was deleted meanwhile
        // (its server gone, or no longer its pass-through), and nothing is
        // committed. Answered in this endpoint's own terms.
        let gone = || ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound);
        let done = super::upstreams::delete_server_with_passthrough(&mut tx, tenant, server_id)
            .await
            .map_err(|e| match e.code {
                ApiErrorCode::ServerNotFound => gone(),
                ApiErrorCode::InternalError => ApiError::internal("Failed to delete downstream provider"),
                _ => e,
            })?;
        if !done.took_passthrough(id) {
            return Err(gone());
        }
        let dry_run = q.dry_run.unwrap_or(false);
        let ended = if dry_run { tx.rollback().await } else { tx.commit().await };
        ended.map_err(|e| {
            tracing::error!("delete pass-through end: {e}");
            ApiError::internal("Failed to delete downstream provider")
        })?;
        return Ok(Json(DeletionResponse {
            dry_run,
            affected_keys: done.keys_revoked,
            affected_users: done.workspaces_ungranted,
            affected_oauth_sessions: 0,
        }));
    }

    // The provider leaves every workspace allowlist (FK cascade on
    // `workspace_downstream_access`); the impact reports how many workspaces
    // lose access, and the keys bound to it, which are revoked with it.
    let affected_workspaces: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM workspace_downstream_access WHERE downstream_provider_id = $1",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .unwrap_or(0);

    if q.dry_run.unwrap_or(false) {
        let bound = super::key_lifecycle::count_keys_bound_to(db.conn(), id).await.map_err(|e| {
            tracing::error!("count keys bound to downstream provider: {e}");
            ApiError::internal("Failed to delete downstream provider")
        })?;
        return Ok(Json(DeletionResponse {
            dry_run: true,
            affected_keys: bound,
            affected_users: affected_workspaces,
            affected_oauth_sessions: 0,
        }));
    }

    let tenant = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("delete downstream provider begin: {e}");
        ApiError::internal("Failed to delete downstream provider")
    })?;
    let revoked = super::key_lifecycle::revoke_keys_bound_to(&mut tx, id).await.map_err(|e| {
        tracing::error!("revoke keys bound to downstream provider: {e}");
        ApiError::internal("Failed to delete downstream provider")
    })?;
    let result = sqlx::query("DELETE FROM downstream_providers WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(tenant)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("delete downstream provider: {e}");
            ApiError::internal("Failed to delete downstream provider")
        })?;
    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound));
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("delete downstream provider commit: {e}");
        ApiError::internal("Failed to delete downstream provider")
    })?;

    Ok(Json(DeletionResponse {
        dry_run: false,
        affected_keys: revoked,
        affected_users: affected_workspaces,
        affected_oauth_sessions: 0,
    }))
}

// ---------------------------------------------------------------------------
// Downstream Route CRUD
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/downstream-providers/{id}/routes",
    tag = "Routes",
    params(("id" = Uuid, Path, description = "Provider ID"), PageQuery),
    responses(
        (status = 200, description = "Paginated list of routes for provider", body = TotalPage<RouteResponse>),
        (status = 404, description = "Provider not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_routes(
    mut db: TenantConn,
    Path(provider_id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<RouteResponse>>, ApiError> {
    // Verify provider belongs to tenant.
    let provider_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM downstream_providers WHERE id = $1 AND tenant_id = $2)")
            .bind(provider_id)
            .bind(db.tenant_uuid())
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("list routes check provider: {e}");
                ApiError::internal("Failed to verify provider")
            })?;
    if !provider_exists {
        return Err(ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound));
    }

    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM downstream_routes WHERE provider_id = $1",
    )
    .bind(provider_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("count routes: {e}");
        ApiError::internal("Failed to list routes")
    })?;
    let routes = sqlx::query_as::<_, RouteRow>(
        sqlx::AssertSqlSafe(&*format!("{} WHERE r.provider_id = $1 ORDER BY r.alias, r.priority DESC, r.weight DESC LIMIT $2 OFFSET $3", ROUTE_SELECT.as_str()),
    ))
    .bind(provider_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list routes: {e}");
        ApiError::internal("Failed to list routes")
    })?;

    let items: Vec<RouteResponse> = routes.into_iter().map(Into::into).collect();
    Ok(Json(TotalPage::new(items, limit, offset, total)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/downstream-providers/{id}/routes",
    tag = "Routes",
    params(("id" = Uuid, Path, description = "Provider ID")),
    request_body = CreateRouteRequest,
    responses(
        (status = 201, description = "Route created", body = RouteResponse),
        (status = 200, description = "Route already exists", body = RouteResponse),
        (status = 400, description = "Invalid model ID", body = ApiErrorResponse),
        (status = 404, description = "Provider not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_route(
    mut db: TenantConn,
    Path(provider_id): Path<Uuid>,
    Json(req): Json<CreateRouteRequest>,
) -> Result<(StatusCode, Json<RouteResponse>), ApiError> {
    // Verify provider exists and belongs to tenant.
    let provider_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM downstream_providers WHERE id = $1 AND tenant_id = $2)")
            .bind(provider_id)
            .bind(db.tenant_uuid())
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("create route check provider: {e}");
                ApiError::internal("Failed to verify provider")
            })?;
    if !provider_exists {
        return Err(ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound));
    }

    // Verify model exists.
    let model_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM upstream_models WHERE id = $1)",
    )
    .bind(req.model_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create route check model: {e}");
        ApiError::internal("Failed to verify model")
    })?;

    if !model_exists {
        return Err(ApiError::bad_request("Invalid model ID").code(ApiErrorCode::ModelNotFound));
    }

    let tenant_id = db.tenant_uuid();
    // The bound preset must belong to the route's model.
    verify_preset_for_model(db.conn(), tenant_id, req.model_id, req.preset_id).await?;
    verify_cache_preset(db.conn(), tenant_id, req.cache_preset_id).await?;

    let priority = req.priority.unwrap_or(0);
    let weight = req.weight.unwrap_or(1).max(1);

    let tags = req.tags.clone().unwrap_or_default();
    let default_for_tags = req.default_for_tags.clone().unwrap_or_default();
    validate_default_for_tags(&tags, &default_for_tags)?;

    let reassign = req.reassign_default_tags.unwrap_or(false);
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("create route begin tx: {e}");
        ApiError::internal("Failed to create downstream route")
    })?;

    // Try insert; on conflict (same provider/alias/model/preset) it's a no-op.
    let inserted_id: Option<Uuid> = sqlx::query_scalar(sqlx::AssertSqlSafe(&*format!(
        r#"INSERT INTO downstream_routes
               (provider_id, alias, model_id, preset_id, cache_preset_id, priority, weight,
                client_context_window, tenant_id, tags, default_for_tags)
           VALUES ($1, $2, $3, $4, $11, $5, $6, $7, $8, $9, $10)
           ON CONFLICT {ROUTE_CONFLICT} DO NOTHING
           RETURNING id"#
    )))
    .bind(provider_id)
    .bind(&req.alias)
    .bind(req.model_id)
    .bind(req.preset_id)
    .bind(priority)
    .bind(weight)
    .bind(req.client_context_window)
    .bind(tenant_id)
    .bind(&tags)
    .bind(&default_for_tags)
    .bind(req.cache_preset_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("create downstream route: {e}");
        ApiError::internal("Failed to create downstream route")
    })?;

    if let Some(id) = inserted_id {
        // A new route was created — only now enforce default-tag exclusivity
        // against its siblings (clear or reject), atomically with the insert.
        reassign_or_reject_default_tags(
            &mut tx,
            tenant_id,
            provider_id,
            Some(id),
            &default_for_tags,
            reassign,
        )
        .await?;
        tx.commit().await.map_err(|e| {
            tracing::error!("create route commit: {e}");
            ApiError::internal("Failed to create downstream route")
        })?;
        let row = fetch_route_by_id(db.conn(), id).await.map_err(|e| {
            tracing::error!("fetch created downstream route: {e}");
            ApiError::internal("Failed to fetch created downstream route")
        })?;
        Ok((StatusCode::CREATED, Json(row.into())))
    } else {
        // Route already exists (same provider/alias/model/preset) — no side effects.
        tx.commit().await.map_err(|e| {
            tracing::error!("create route commit: {e}");
            ApiError::internal("Failed to create downstream route")
        })?;
        let existing = sqlx::query_as::<_, RouteRow>(
            sqlx::AssertSqlSafe(&*format!(
                "{} WHERE r.provider_id = $1 AND r.alias = $2 AND r.model_id = $3 \
                 AND COALESCE(r.preset_id, '00000000-0000-0000-0000-000000000000'::uuid) \
                   = COALESCE($4::uuid, '00000000-0000-0000-0000-000000000000'::uuid)",
                ROUTE_SELECT.as_str()
            )),
        )
        .bind(provider_id)
        .bind(&req.alias)
        .bind(req.model_id)
        .bind(req.preset_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("fetch existing downstream route: {e}");
            ApiError::internal("Failed to fetch existing downstream route")
        })?;
        Ok((StatusCode::OK, Json(existing.into())))
    }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/downstream-providers/{id}/routes/actions/batch-create",
    tag = "Routes",
    params(("id" = Uuid, Path, description = "Provider ID")),
    request_body = BatchCreateRoutesRequest,
    responses(
        (status = 201, description = "Routes created", body = BatchCreateRoutesResponse),
        (status = 404, description = "Provider not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn batch_create_routes(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(provider_id): Path<Uuid>,
    Json(req): Json<BatchCreateRoutesRequest>,
) -> Result<(StatusCode, Json<BatchCreateRoutesResponse>), ApiError> {
    // Verify provider exists.
    let provider_exists: bool =
        sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM downstream_providers WHERE id = $1 AND tenant_id = $2)")
            .bind(provider_id)
            .bind(db.tenant_uuid())
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("batch create routes check provider: {e}");
                ApiError::internal("Failed to verify provider")
            })?;
    if !provider_exists {
        return Err(ApiError::not_found("Downstream provider not found", ApiErrorCode::DownstreamNotFound));
    }

    let tenant_id = db.tenant_uuid();
    let mut results = Vec::new();
    for route_req in &req.routes {
        // Verify model exists.
        let model_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS(SELECT 1 FROM upstream_models WHERE id = $1)",
        )
        .bind(route_req.model_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("batch create route check model: {e}");
            ApiError::internal("Failed to verify model")
        })?;

        if !model_exists {
            continue; // Skip routes with invalid model
        }

        // The bound preset must belong to the route's model.
        verify_preset_for_model(db.conn(), tenant_id, route_req.model_id, route_req.preset_id).await?;
        verify_cache_preset(db.conn(), tenant_id, route_req.cache_preset_id).await?;

        let priority = route_req.priority.unwrap_or(0);
        let weight = route_req.weight.unwrap_or(1).max(1);

        let tags = route_req.tags.clone().unwrap_or_default();
        let default_for_tags = route_req.default_for_tags.clone().unwrap_or_default();
        validate_default_for_tags(&tags, &default_for_tags)?;
        let inserted_id: Option<Uuid> = sqlx::query_scalar(sqlx::AssertSqlSafe(&*format!(
            r#"INSERT INTO downstream_routes
                   (provider_id, alias, model_id, preset_id, cache_preset_id, priority, weight,
                    client_context_window, tenant_id, tags, default_for_tags)
               VALUES ($1, $2, $3, $4, $11, $5, $6, $7, $8, $9, $10)
               ON CONFLICT {ROUTE_CONFLICT} DO NOTHING
               RETURNING id"#
        )))
        .bind(provider_id)
        .bind(&route_req.alias)
        .bind(route_req.model_id)
        .bind(route_req.preset_id)
        .bind(priority)
        .bind(weight)
        .bind(route_req.client_context_window)
        .bind(tenant_id)
        .bind(&tags)
        .bind(&default_for_tags)
        .bind(route_req.cache_preset_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("batch create route: {e}");
            ApiError::internal("Failed to create batch route")
        })?;

        if let Some(id) = inserted_id {
            let row = fetch_route_by_id(db.conn(), id).await.map_err(|e| {
                tracing::error!("fetch batch-created route: {e}");
                ApiError::internal("Failed to fetch created route")
            })?;
            results.push(row.into());
        }
    }

    let requested = req.routes.len();
    let added = results.len();
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({
            "requested": requested,
            "added": added,
            "skipped": requested - added,
        }),
    );
    Ok((StatusCode::CREATED, Json(BatchCreateRoutesResponse { items: results })))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/downstream-providers/{id}/routes/{route_id}",
    tag = "Routes",
    params(
        ("id" = Uuid, Path, description = "Provider ID"),
        ("route_id" = Uuid, Path, description = "Route ID"),
    ),
    request_body = UpdateRouteRequest,
    responses(
        (status = 200, description = "Updated route", body = RouteResponse),
        (status = 400, description = "Invalid request", body = ApiErrorResponse),
        (status = 404, description = "Route not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_route(
    mut db: TenantConn,
    Path((provider_id, route_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(req): Json<UpdateRouteRequest>,
) -> Result<Json<RouteResponse>, ApiError> {
    // Verify route belongs to this provider and provider belongs to tenant.
    let route_exists: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
               SELECT 1 FROM downstream_routes r
               JOIN downstream_providers p ON p.id = r.provider_id
               WHERE r.id = $1 AND r.provider_id = $2 AND p.tenant_id = $3
           )"#,
    )
    .bind(route_id)
    .bind(provider_id)
    .bind(db.tenant_uuid())
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update route check: {e}");
        ApiError::internal("Failed to verify route")
    })?;

    if !route_exists {
        return Err(ApiError::not_found("Downstream route not found", ApiErrorCode::RouteNotFound));
    }

    // The `default_for_tags ⊆ tags` invariant has to hold against the
    // POST-update state, not just the request payload. A caller sending only
    // `default_for_tags` could otherwise smuggle an orphan; a caller shrinking
    // `tags` could leave stale defaults behind. Fetch whichever side the
    // request omits and validate the combined shape.
    if req.tags.is_some() || req.default_for_tags.is_some() {
        #[derive(sqlx::FromRow)]
        struct ExistingTags {
            tags: Vec<String>,
            default_for_tags: Vec<String>,
        }
        let existing: ExistingTags = sqlx::query_as(
            "SELECT tags, default_for_tags FROM downstream_routes WHERE id = $1",
        )
        .bind(route_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("fetch existing route tags: {e}");
            ApiError::internal("Failed to verify route tags")
        })?;
        let effective_tags = req.tags.as_deref().unwrap_or(&existing.tags);
        let effective_defaults = req
            .default_for_tags
            .as_deref()
            .unwrap_or(&existing.default_for_tags);
        validate_default_for_tags(effective_tags, effective_defaults)?;
    }

    let tenant_id = db.tenant_uuid();

    // Resolve the effective (post-update) model + preset and validate the binding.
    // A preset must belong to the route's model — checked against the model the
    // route WILL have (req.model_id if changing, else the current one) and the
    // preset it WILL have (req.preset_id tri-state, else the current one).
    let (cur_model_id, cur_preset_id): (Option<Uuid>, Option<Uuid>) =
        sqlx::query_as("SELECT model_id, preset_id FROM downstream_routes WHERE id = $1")
            .bind(route_id)
            .fetch_one(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("fetch route model/preset: {e}");
                ApiError::internal("Failed to verify route")
            })?;
    let effective_model_id = req.model_id.or(cur_model_id);
    let effective_preset_id = match req.preset_id {
        Some(inner) => inner,
        None => cur_preset_id,
    };
    if let Some(mid) = effective_model_id {
        verify_preset_for_model(db.conn(), tenant_id, mid, effective_preset_id).await?;
    }
    if let Some(inner) = req.cache_preset_id {
        verify_cache_preset(db.conn(), tenant_id, inner).await?;
    }

    // `preset_id`, `cache_preset_id` and `client_context_window` are tri-state:
    // absent ⇒ unchanged; key present with a value ⇒ set; key present with JSON
    // null ⇒ reset to NULL (the model's default preset / no caching / the
    // model's own window). They ride one jsonb patch so `jsonb_exists` can tell
    // "absent" from "explicit null"; the window's value is bound on its own.
    let mut tri_state_patch = serde_json::Map::new();
    let as_json = |v: Option<Uuid>| {
        v.map_or(serde_json::Value::Null, |u| serde_json::Value::String(u.to_string()))
    };
    if let Some(inner) = req.preset_id {
        tri_state_patch.insert("preset_id".to_string(), as_json(inner));
    }
    if let Some(inner) = req.cache_preset_id {
        tri_state_patch.insert("cache_preset_id".to_string(), as_json(inner));
    }
    if let Some(inner) = req.client_context_window {
        tri_state_patch.insert("client_context_window".to_string(), inner.map_or(serde_json::Value::Null, Into::into));
    }
    let tri_state_patch = serde_json::Value::Object(tri_state_patch);

    // The classes this target accepts live in their own table, so the generic
    // `change_diff` — which snapshots the `downstream_routes` row — would record
    // a change to nothing. Snapshot the whole response shape instead and stamp
    // it below; it carries the row's own fields too, so nothing is lost by
    // taking precedence over the generic capture.
    let before_route = match (&req.qos_class_ids, &req.client_slots) {
        (Some(_), _) | (_, Some(_)) => Some(RouteResponse::from(
            fetch_route_by_id(db.conn(), route_id).await.map_err(|e| {
                tracing::error!("snapshot route before update: {e}");
                ApiError::internal("Failed to update downstream route")
            })?,
        )),
        (None, None) => None,
    };

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update route begin tx: {e}");
        ApiError::internal("Failed to update downstream route")
    })?;
    // When this update sets `default_for_tags`, reassign each entry off any
    // sibling (or reject), atomically with the update below. Absent ⇒ defaults
    // unchanged, nothing to reassign.
    reassign_or_reject_default_tags(
        &mut tx,
        tenant_id,
        provider_id,
        Some(route_id),
        &req.default_for_tags.clone().unwrap_or_default(),
        req.reassign_default_tags.unwrap_or(false),
    )
    .await?;

    // The route is a pure pointer: only alias / model / preset / LB / tags /
    // client-window / enabled are updatable. Capabilities, window, protocol,
    // type and healing are upstream-model truth and are NOT route-editable.
    let updated_id: Uuid = sqlx::query_scalar::<_, Uuid>(
        r#"UPDATE downstream_routes SET
               alias = COALESCE($3, alias),
               model_id = COALESCE($4, model_id),
               priority = COALESCE($5, priority),
               weight = COALESCE($6, weight),
               client_context_window = CASE WHEN jsonb_exists($9::jsonb, 'client_context_window')
                   THEN $7 ELSE client_context_window END,
               enabled = COALESCE($8, enabled),
               -- $9 is a jsonb patch naming each tri-state field the request set
               -- (preset_id, cache_preset_id, client_context_window): absent ⇒
               -- unchanged; key with a value ⇒ set; key with JSON null ⇒ reset.
               -- The window's value itself is bound as $7.
               preset_id = CASE WHEN jsonb_exists($9::jsonb, 'preset_id')
                   THEN ($9::jsonb ->> 'preset_id')::uuid ELSE preset_id END,
               cache_preset_id = CASE WHEN jsonb_exists($9::jsonb, 'cache_preset_id')
                   THEN ($9::jsonb ->> 'cache_preset_id')::uuid ELSE cache_preset_id END,
               tags = COALESCE($10, tags),
               default_for_tags = COALESCE($11, default_for_tags),
               auto_synced = false
           WHERE id = $1 AND provider_id = $2
           RETURNING id"#,
    )
    .bind(route_id)
    .bind(provider_id)
    .bind(&req.alias)
    .bind(req.model_id)
    .bind(req.priority)
    .bind(req.weight)
    .bind(req.client_context_window.flatten())
    .bind(req.enabled)
    .bind(&tri_state_patch)
    .bind(req.tags.as_deref())
    .bind(req.default_for_tags.as_deref())
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update downstream route: {e}");
        ApiError::internal("Failed to update downstream route")
    })?
    .ok_or_else(|| ApiError::not_found("Downstream route not found", ApiErrorCode::RouteNotFound))?;

    let moved = match &req.client_slots {
        Some(slots) => {
            let slots = slots.as_deref().unwrap_or(&[]);
            set_client_slots(&mut tx, tenant_id, provider_id, updated_id, slots).await?
        }
        None => Vec::new(),
    };

    // Which priority classes this target accepts — a replace, in the same
    // transaction as the row, so a target is never left accepting a set nobody
    // asked for. An empty list is the open state, not a closed one.
    if let Some(class_ids) = &req.qos_class_ids {
        sqlx::query("DELETE FROM route_qos_classes WHERE route_id = $1")
            .bind(updated_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("clear route qos classes: {e}");
                ApiError::internal("Failed to update downstream route")
            })?;
        // The same id twice is a caller's list, not a missing class: without
        // this the second insert does nothing and reads as "not found".
        let mut unique: Vec<Uuid> = class_ids.clone();
        unique.sort_unstable();
        unique.dedup();
        for class_id in &unique {
            // The tenant predicate is the isolation check: a foreign key is
            // enforced above RLS, so the FK alone would accept another tenant's
            // class id.
            let inserted = sqlx::query(
                "INSERT INTO route_qos_classes (route_id, qos_class_id, tenant_id) \
                 SELECT $1, q.id, q.tenant_id FROM qos_classes q \
                 WHERE q.id = $2 AND q.tenant_id = $3 AND NOT q.suppressed \
                 ON CONFLICT DO NOTHING",
            )
            .bind(updated_id)
            .bind(class_id)
            .bind(tenant_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("set route qos class: {e}");
                ApiError::internal("Failed to update downstream route")
            })?
            .rows_affected();
            if inserted == 0 {
                return Err(ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound));
            }
        }
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("update route commit: {e}");
        ApiError::internal("Failed to update downstream route")
    })?;

    let row = fetch_route_by_id(db.conn(), updated_id).await.map_err(|e| {
        tracing::error!("fetch updated downstream route: {e}");
        ApiError::internal("Failed to fetch updated downstream route")
    })?;
    let response = RouteResponse::from(row);
    if let Some(before) = &before_route {
        record_slot_moved(&audit_sink, Some(before), &response, &moved);
    }
    Ok(Json(response))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/downstream-providers/{id}/routes/{route_id}",
    tag = "Routes",
    params(
        ("id" = Uuid, Path, description = "Provider ID"),
        ("route_id" = Uuid, Path, description = "Route ID"),
    ),
    responses(
        (status = 200, description = "Route deleted", body = ActionResponse),
        (status = 404, description = "Route not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_route(
    mut db: TenantConn,
    Path((provider_id, route_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    // The route's client slots go with it (cascade), in a table the generic
    // capture of the route row does not see: a slotted route's diff is the
    // whole route, slots included.
    let before = fetch_route_by_id(db.conn(), route_id).await.ok().map(RouteResponse::from);
    let result = sqlx::query(
        r#"DELETE FROM downstream_routes
           WHERE id = $1 AND provider_id = $2
             AND EXISTS(SELECT 1 FROM downstream_providers WHERE id = $2 AND tenant_id = $3)"#,
    )
    .bind(route_id)
    .bind(provider_id)
    .bind(db.tenant_uuid())
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete downstream route: {e}");
        ApiError::internal("Failed to delete downstream route")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("Downstream route not found", ApiErrorCode::RouteNotFound));
    }
    if let Some(before) = before.filter(|r| !r.client_slots.is_empty()) {
        audit_sink.record(Some(&before), None::<&RouteResponse>);
    }

    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/downstream-providers/{id}/routes/{route_id}/actions/flush-cache",
    tag = "Downstream",
    params(
        ("id" = Uuid, Path, description = "Downstream provider ID"),
        ("route_id" = Uuid, Path, description = "Route ID"),
    ),
    responses(
        (status = 200, description = "Flush dispatched", body = ActionResponse),
        (status = 404, description = "Route not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn flush_route_cache(
    mut db: TenantConn,
    Path((provider_id, route_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM downstream_routes r \
         JOIN downstream_providers p ON p.id = r.provider_id \
         WHERE r.id = $1 AND r.provider_id = $2 AND p.tenant_id = $3)",
    )
    .bind(route_id)
    .bind(provider_id)
    .bind(tenant_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("verify route for cache flush: {e}");
        ApiError::internal("Failed to flush route cache")
    })?;
    if !exists {
        return Err(ApiError::not_found("Downstream route not found", ApiErrorCode::RouteNotFound));
    }

    sqlx::query("UPDATE downstream_routes SET cache_generation = cache_generation + 1 WHERE id = $1")
        .bind(route_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("raise route cache generation: {e}");
            ApiError::internal("Failed to flush route cache")
        })?;
    Ok(Json(ActionResponse::ok().with_message(
        "cached responses for this alias are being dropped across the fleet",
    )))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/maintenance/flush-response-cache",
    tag = "Settings",
    responses(
        (status = 200, description = "Flush dispatched", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn flush_tenant_cache(
    mut db: TenantConn,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // The tenant's response-cache generation rides the config body's settings;
    // raising it tells every edge holding the tenant to drop its cached responses.
    sqlx::query(
        "INSERT INTO system_settings (key, value, tenant_id) VALUES ('response_cache_generation', '1'::jsonb, $1) \
         ON CONFLICT (tenant_id, key) DO UPDATE \
            SET value = to_jsonb(COALESCE((system_settings.value #>> '{}')::bigint, 0) + 1)",
    )
    .bind(tenant_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("raise tenant cache generation: {e}");
        ApiError::internal("Failed to flush response cache")
    })?;
    Ok(Json(ActionResponse::ok().with_message(
        "every cached response for this tenant is being dropped across the fleet",
    )))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Slugify a preset name for a mirror alias suffix: lowercase, non-alphanumeric
/// runs collapse to a single `-`, trimmed. e.g. "Non-Think (fast)" → "non-think-fast".
fn slugify_preset(name: &str) -> String {
    let mut out = String::with_capacity(name.len());
    let mut prev_dash = false;
    for ch in name.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').to_string()
}

/// Every entry in `default_for_tags` must also appear in `tags` — a route
/// can't claim to be the "default for tag X" if X isn't in its tag set.
fn validate_default_for_tags(tags: &[String], default_for_tags: &[String]) -> Result<(), ApiError> {
    // `default_for_tags` must be a subset of `tags` — a route can only be the
    // default for a client it is offered to. EXCEPTION: the wildcard `"*"` in
    // `tags` means "offered to every client", so it satisfies any default entry
    // (e.g. Tags `["*"]` + Default `["opencode"]` = offered to all, default for
    // opencode). The wildcard in `default_for_tags` itself is the global default.
    if tags.iter().any(|t| t == crate::routes::quickstart::WILDCARD_TAG) {
        return Ok(());
    }
    if let Some(orphan) = default_for_tags.iter().find(|t| !tags.contains(t)) {
        return Err(ApiError::bad_request(format!(
            "default_for_tags entry {orphan:?} is not in this route's tag set \
             (add it to Tags, or use \"*\" in Tags to offer this route to all clients)"
        ))
        .code(ApiErrorCode::ValidationFailed));
    }
    Ok(())
}

/// A slot a write took from another route of the provider, recorded in the
/// audit diff beside the route that took it.
#[derive(Serialize, Clone)]
struct SlotMoved {
    id: Uuid,
    alias: String,
    client_slot: ClientSlot,
}

/// Make `slots` exactly the client slots `route_id` fills; a slot another
/// route of the provider held moves here and is returned, for the audit. Slot
/// writes of one provider are serialized on its row (`FOR NO KEY UPDATE`, so
/// foreign-key checks against the provider still pass), so the holder read is
/// the one replaced and two writers never lock slot rows in opposite orders.
/// Which kind of model the route serves is not checked here: a model's type
/// can change later, so the render skips a slot whose alias is not a chat
/// model (`slot_alias`).
async fn set_client_slots(
    conn: &mut Scoped,
    tenant_id: Uuid,
    provider_id: Uuid,
    route_id: Uuid,
    slots: &[ClientSlot],
) -> Result<Vec<SlotMoved>, ApiError> {
    let failed = |e: sqlx::Error| {
        tracing::error!("set route client slots: {e}");
        ApiError::internal("Failed to set the route's client slots")
    };
    sqlx::query("SELECT 1 FROM downstream_providers WHERE tenant_id = $1 AND id = $2 FOR NO KEY UPDATE")
        .bind(tenant_id)
        .bind(provider_id)
        .execute(&mut *conn)
        .await
        .map_err(failed)?;
    let mut slots = slots.to_vec();
    slots.sort_unstable();
    slots.dedup();
    let wanted: Vec<&'static str> = slots.iter().map(|s| s.as_str()).collect();
    sqlx::query(
        "DELETE FROM route_client_slots WHERE tenant_id = $1 AND route_id = $2 AND NOT (slot = ANY($3))",
    )
    .bind(tenant_id)
    .bind(route_id)
    .bind(&wanted)
    .execute(&mut *conn)
    .await
    .map_err(failed)?;
    let mut moved = Vec::new();
    for slot in &slots {
        let from: Option<(Uuid, String)> = sqlx::query_as(
            "SELECT cs.route_id, r.alias FROM route_client_slots cs \
             JOIN downstream_routes r ON r.tenant_id = cs.tenant_id AND r.id = cs.route_id \
             WHERE cs.tenant_id = $1 AND cs.provider_id = $2 AND cs.slot = $3 AND cs.route_id <> $4",
        )
        .bind(tenant_id)
        .bind(provider_id)
        .bind(slot.as_str())
        .bind(route_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(failed)?;
        sqlx::query(
            "INSERT INTO route_client_slots (tenant_id, provider_id, slot, route_id) VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, provider_id, slot) DO UPDATE SET route_id = EXCLUDED.route_id",
        )
        .bind(tenant_id)
        .bind(provider_id)
        .bind(slot.as_str())
        .bind(route_id)
        .execute(&mut *conn)
        .await
        .map_err(failed)?;
        if let Some((id, alias)) = from {
            moved.push(SlotMoved { id, alias, client_slot: *slot });
        }
    }
    Ok(moved)
}

/// Stamp the audit diff of a write that set a route's slots. The slots live
/// in their own table, so the generic capture of the route row sees neither
/// them nor the route that lost one: this records the route before and after,
/// and beside the after the slots taken from other routes.
fn record_slot_moved(
    sink: &crate::middleware::AuditDiffSink,
    before: Option<&RouteResponse>,
    after: &RouteResponse,
    moved: &[SlotMoved],
) {
    if moved.is_empty() {
        sink.record(before, Some(after));
        return;
    }
    let mut after_json = serde_json::to_value(after).unwrap_or(serde_json::Value::Null);
    if let Some(obj) = after_json.as_object_mut() {
        obj.insert(
            "slots_taken_from".into(),
            serde_json::to_value(moved).unwrap_or(serde_json::Value::Null),
        );
    }
    sink.set(serde_json::to_value(before).unwrap_or(serde_json::Value::Null), after_json);
}

/// Enforce that each `default_for_tags` entry is the canonical default for at
/// most one route per provider (the `"*"` global default included). Runs on the
/// caller's connection — pass `&mut *tx` to keep it in the write transaction.
///
/// When a sibling route (same provider, `tenant_id`, excluding `exclude_id`)
/// already claims one of `wanted`: with `reassign` set, the conflicting tags are
/// stripped from those siblings here so the caller's route becomes the sole
/// default; otherwise it's a `RouteDefaultTagConflict` naming the routes to clear
/// first. A sibling whose default set empties out keeps its `tags` (it stays a
/// selectable route, just no longer the default).
async fn reassign_or_reject_default_tags(
    conn: &mut Scoped,
    tenant_id: Uuid,
    provider_id: Uuid,
    exclude_id: Option<Uuid>,
    wanted: &[String],
    reassign: bool,
) -> Result<(), ApiError> {
    if wanted.is_empty() {
        return Ok(());
    }
    let conflicts: Vec<(String, Vec<String>)> = sqlx::query_as(
        "SELECT alias, default_for_tags FROM downstream_routes \
         WHERE provider_id = $1 AND tenant_id = $2 AND default_for_tags && $3 \
           AND ($4::uuid IS NULL OR id <> $4)",
    )
    .bind(provider_id)
    .bind(tenant_id)
    .bind(wanted)
    .bind(exclude_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("default-tag conflict lookup: {e}");
        ApiError::internal("Failed to check route default tags")
    })?;

    if conflicts.is_empty() {
        return Ok(());
    }

    if !reassign {
        let detail = conflicts
            .iter()
            .map(|(alias, tags)| {
                let overlap: Vec<&str> =
                    tags.iter().filter(|t| wanted.contains(t)).map(String::as_str).collect();
                format!("{alias:?} (default for {})", overlap.join(", "))
            })
            .collect::<Vec<_>>()
            .join("; ");
        return Err(ApiError::conflict(format!(
            "another route is already the default for those tags: {detail}. \
             Retry with reassign_default_tags to move the default to this route."
        ), ApiErrorCode::RouteDefaultTagConflict));
    }

    // Reassign: drop the wanted tags from every conflicting sibling.
    sqlx::query(
        "UPDATE downstream_routes \
         SET default_for_tags = COALESCE( \
                 (SELECT array_agg(t) FROM unnest(default_for_tags) AS t WHERE NOT (t = ANY($3))), \
                 '{}') \
         WHERE provider_id = $1 AND tenant_id = $2 AND default_for_tags && $3 \
           AND ($4::uuid IS NULL OR id <> $4)",
    )
    .bind(provider_id)
    .bind(tenant_id)
    .bind(wanted)
    .bind(exclude_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("reassign default tags: {e}");
        ApiError::internal("Failed to reassign route default tags")
    })?;
    Ok(())
}

/// Mirror-sync: auto-create/update a downstream provider that mirrors all models
/// from the given upstream server. Creates the provider if it doesn't exist yet.
/// New models get routes with `auto_synced = true` and `enabled = true`.
/// Existing auto_synced routes are not touched; manually customized routes are preserved.
///
/// Invariants: the mirror is owned by `auto_sync_enabled` — when the server is in
/// manual mode this is a no-op (no downstream is ever auto-created). The mirror is
/// only ever **this** server's own row (`upstream_server_id = server_id`); a
/// same-named downstream owned by someone else is never re-pointed (no hijack) —
/// it raises `SyncError::NameConflict` instead.
pub async fn mirror_sync_downstream(
    conn: &mut Scoped,
    server_id: Uuid,
    server_name: &str,
    tenant_id: Uuid,
) -> Result<MirrorSyncResult, super::model_sync::SyncError> {
    use super::model_sync::SyncError;

    // Autosync is the single switch that owns the mirror. Manual server ⇒ never
    // auto-create/maintain a downstream from any path (create / sync-now / worker
    // / model CRUD all route through here). Discovery + model population happen in
    // `apply_sync` regardless, so manual mode still feeds custom downstreams.
    let auto_sync: bool = sqlx::query_scalar("SELECT auto_sync_enabled FROM upstream_servers WHERE id = $1")
        .bind(server_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(SyncError::Db)?
        .unwrap_or(false);
    if !auto_sync {
        return Ok(MirrorSyncResult { provider_id: Uuid::nil(), routes_added: 0, total_models: 0 });
    }

    // Find this server's existing mirror provider, or create one. Never adopt a
    // foreign same-named downstream (no hijack).
    let provider_id: Uuid = match sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM downstream_providers WHERE upstream_server_id = $1 AND tenant_id = $2",
    )
    .bind(server_id)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(SyncError::Db)?
    {
        Some(id) => {
            // Backfill icon from upstream server if not already set
            sqlx::query(
                "UPDATE downstream_providers SET icon = (SELECT provider FROM upstream_servers WHERE id = $1) \
                 WHERE id = $2 AND icon IS NULL",
            )
            .bind(server_id)
            .bind(id)
            .execute(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
            id
        }
        None => {
            // No mirror exists yet for this server. The name must be free — a
            // downstream of the same name owned by someone else is NEVER hijacked.
            if sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM downstream_providers WHERE tenant_id = $1 AND name = $2",
            )
            .bind(tenant_id)
            .bind(server_name)
            .fetch_optional(&mut *conn)
            .await
            .map_err(SyncError::Db)?
            .is_some()
            {
                return Err(SyncError::NameConflict { name: server_name.to_string() });
            }
            // Set icon from upstream server's provider type so the downstream inherits the correct icon.
            let id: Uuid = sqlx::query_scalar(
                r#"INSERT INTO downstream_providers (tenant_id, name, description, icon, upstream_server_id)
                   VALUES ($1, $2, $3, (SELECT provider FROM upstream_servers WHERE id = $4), $4)
                   RETURNING id"#,
            )
            .bind(tenant_id)
            .bind(server_name)
            .bind(format!("Mirror of upstream server {server_name}"))
            .bind(server_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
            tracing::info!("Created mirror downstream provider '{server_name}' for server {server_id}");
            id
        }
    };

    // Get all enabled upstream models for this server, each with its presets.
    // One auto route per (model × preset): the default preset → alias = model
    // name (preset_id NULL); each non-default preset →
    // alias = "<model>-<preset-slug>" bound to that preset.
    let models: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT id, upstream_model FROM upstream_models WHERE server_id = $1 AND enabled = true",
    )
    .bind(server_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(SyncError::Db)?;

    let mut added = 0u32;
    for (model_id, model_name) in &models {
        let mut presets: Vec<(Uuid, String, bool)> = sqlx::query_as(
            "SELECT id, name, is_default FROM model_presets WHERE model_id = $1 ORDER BY is_default DESC, name",
        )
        .bind(model_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(SyncError::Db)?;

        // Defensive: a model should always carry a default preset, but if none
        // exists yet, still mirror the bare model alias with a NULL preset.
        if presets.is_empty() {
            presets.push((Uuid::nil(), String::new(), true));
        }

        for (preset_id, preset_name, is_default) in &presets {
            // Default preset rides the bare model alias with a NULL preset_id so
            // it tracks whichever preset is default; non-default presets get a
            // suffixed alias bound explicitly to the preset.
            let (alias, bound_preset): (String, Option<Uuid>) = if *is_default {
                (model_name.clone(), None)
            } else {
                (format!("{model_name}-{}", slugify_preset(preset_name)), Some(*preset_id))
            };
            let result = sqlx::query(sqlx::AssertSqlSafe(&*format!(
                r#"INSERT INTO downstream_routes (provider_id, alias, model_id, preset_id, auto_synced, enabled, tenant_id)
                   VALUES ($1, $2, $3, $4, true, true, $5)
                   ON CONFLICT {ROUTE_CONFLICT} DO NOTHING"#
            )))
            .bind(provider_id)
            .bind(&alias)
            .bind(model_id)
            .bind(bound_preset)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await
            .map_err(SyncError::Db)?;
            if result.rows_affected() > 0 {
                added += 1;
            }
        }
    }

    if added > 0 {
        tracing::info!(
            "Mirror sync for '{server_name}': added {added} routes to downstream provider {provider_id}"
        );
    }

    Ok(MirrorSyncResult {
        provider_id,
        routes_added: added,
        total_models: models.len() as u32,
    })
}

#[derive(Serialize, ToSchema)]
pub struct MirrorSyncResult {
    pub provider_id: Uuid,
    pub routes_added: u32,
    pub total_models: u32,
}

/// Operator-facing impact of orphaning a set of models' downstream routes.
#[derive(Serialize, Default)]
pub struct OrphanImpact {
    /// Curated (`auto_synced = false`) routes that were orphaned — disabled +
    /// flagged, then severed from their model when the model row is deleted.
    pub orphaned_routes: u32,
    /// Distinct downstream providers that lost a route to the deleted model(s).
    pub downstreams: Vec<String>,
}

impl From<OrphanImpact> for super::ActionImpact {
    fn from(o: OrphanImpact) -> Self {
        Self {
            orphaned_routes: Some(o.orphaned_routes),
            downstreams: Some(o.downstreams),
            ..Self::default()
        }
    }
}

/// Orphan every curated route referencing any of `model_ids`, in preparation for
/// deleting those model rows (operator delete of a model, or a whole server).
/// Disposable `auto_synced` routes are deleted; curated (`auto_synced = false`)
/// routes are disabled + flagged `upstream_model_deleted` and **kept** — the
/// caller then deletes the model rows and the FK (`ON DELETE SET NULL`) nulls the
/// flagged routes' `model_id`, leaving them as orphans for cleanup. A curated
/// route is never destroyed. Returns the affected downstreams for the warning.
pub async fn orphan_model_routes(
    conn: &mut Scoped,
    model_ids: &[Uuid],
) -> Result<OrphanImpact, sqlx::Error> {
    if model_ids.is_empty() {
        return Ok(OrphanImpact { orphaned_routes: 0, downstreams: Vec::new() });
    }
    // Distinct downstreams holding a curated route to one of these models — the
    // operator-facing impact, collected before we flag them.
    let downstreams: Vec<String> = sqlx::query_scalar(
        "SELECT DISTINCT p.name FROM downstream_routes r \
         JOIN downstream_providers p ON p.id = r.provider_id \
         WHERE r.model_id = ANY($1) AND r.auto_synced = false \
         ORDER BY p.name",
    )
    .bind(model_ids)
    .fetch_all(&mut *conn)
    .await?;

    // Disposable auto routes go away with the model.
    sqlx::query("DELETE FROM downstream_routes WHERE model_id = ANY($1) AND auto_synced = true")
        .bind(model_ids)
        .execute(&mut *conn)
        .await?;

    // Curated routes survive, flagged orphaned (model_id nulled by the FK once the
    // caller deletes the model row).
    let flagged = sqlx::query(
        "UPDATE downstream_routes SET enabled = false, disabled_reason = $2 \
         WHERE model_id = ANY($1) AND auto_synced = false",
    )
    .bind(model_ids)
    .bind(super::model_sync::DISABLED_REASON_ORPHANED)
    .execute(&mut *conn)
    .await?;

    Ok(OrphanImpact { orphaned_routes: flagged.rows_affected() as u32, downstreams })
}

// ---------------------------------------------------------------------------
// Route collisions
// ---------------------------------------------------------------------------

/// One upstream target an alias resolves to within a colliding alias group.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct CollisionTarget {
    pub provider_id: Uuid,
    pub provider_name: String,
    pub upstream_model: String,
    pub server_name: String,
}

/// An alias that resolves to more than one distinct upstream model across more
/// than one provider — a silent load-balance that's usually a misconfiguration.
#[derive(Serialize, ToSchema)]
pub struct AliasCollision {
    pub alias: String,
    pub targets: Vec<CollisionTarget>,
}

#[derive(Serialize, ToSchema)]
pub struct RouteCollisionsResponse {
    pub collisions: Vec<AliasCollision>,
}

#[derive(sqlx::FromRow)]
struct CollisionRow {
    alias: String,
    provider_id: Uuid,
    provider_name: String,
    upstream_model: String,
    server_name: String,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/downstream-routes/collisions",
    tag = "Downstream",
    responses(
        (status = 200, description = "Alias collisions", body = RouteCollisionsResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_route_collisions(
    mut db: TenantConn,
) -> Result<Json<RouteCollisionsResponse>, ApiError> {
    // An alias collides when its enabled routes span ≥2 providers AND resolve to
    // ≥2 distinct upstream models. Same model on two providers (failover) and
    // multiple routes within one provider (LB) are intentional and NOT flagged.
    let rows = sqlx::query_as::<_, CollisionRow>(
        "SELECT r.alias, dp.id AS provider_id, dp.name AS provider_name, \
                m.upstream_model, s.name AS server_name \
         FROM downstream_routes r \
         JOIN upstream_models m ON m.id = r.model_id \
         JOIN upstream_servers s ON s.id = m.server_id \
         JOIN downstream_providers dp ON dp.id = r.provider_id \
         WHERE r.enabled = true AND r.alias IN ( \
             SELECT r2.alias FROM downstream_routes r2 \
             JOIN upstream_models m2 ON m2.id = r2.model_id \
             WHERE r2.enabled = true \
             GROUP BY r2.alias \
             HAVING COUNT(DISTINCT r2.provider_id) >= 2 \
                AND COUNT(DISTINCT m2.upstream_model) >= 2 \
         ) \
         ORDER BY r.alias, dp.name, m.upstream_model",
    )
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list route collisions: {e}");
        ApiError::internal("failed to compute route collisions")
    })?;

    // Group the flat rows by alias, deduping identical (provider, model) targets
    // (an alias may have several routes to the same model on one provider — a
    // legitimate LB fan-out we don't want to list twice).
    let mut collisions: Vec<AliasCollision> = Vec::new();
    for row in rows {
        let target = CollisionTarget {
            provider_id: row.provider_id,
            provider_name: row.provider_name,
            upstream_model: row.upstream_model,
            server_name: row.server_name,
        };
        match collisions.last_mut() {
            Some(c) if c.alias == row.alias => {
                if !c.targets.iter().any(|t| {
                    t.provider_id == target.provider_id && t.upstream_model == target.upstream_model
                }) {
                    c.targets.push(target);
                }
            }
            _ => collisions.push(AliasCollision {
                alias: row.alias,
                targets: vec![target],
            }),
        }
    }

    Ok(Json(RouteCollisionsResponse { collisions }))
}
