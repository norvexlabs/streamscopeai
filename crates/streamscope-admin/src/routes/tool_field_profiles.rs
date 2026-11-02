//! Tool field profile CRUD — first-class management of the per-tenant field
//! profile registry.
//!
//! Storage is the `tool_field_profiles` table (one row per profile, keyed
//! `(tenant_id, profile_key)`). Every row carries an `is_builtin` flag (a user
//! edit flips it false) and a `suppressed` flag (a deleted builtin seed-sync
//! skips). A mutation reaches the proxies through the config change triggers.
//!
//! Discovery endpoint (`/tool-field-profiles/discover`) aggregates unique
//! `(tool_name, field)` pairs from recent audit traces so operators can
//! register profiles for fields they've actually seen in traffic.

use std::collections::{BTreeMap, BTreeSet};

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use streamscope_core::config::tool_rules::{
    self, FieldProfile, FieldProfileValidationError,
};
use streamscope_core::config::tool_rules_normalize::Normalizer;

use crate::seed_loader::ToolIdEntry;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, SourceFilter};
use crate::db::tenant::{Scoped, TenantConn};
use crate::middleware::AuditDiffSink;

const MAX_PROFILE_ID_LEN: usize = 96;
fn is_valid_profile_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_PROFILE_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

// ---------------------------------------------------------------------------
// Query + request types
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct FieldProfileListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter by normaliser kind; a value naming none answers 400.
    #[param(value_type = Option<Normalizer>)]
    pub normalizer: Option<String>,
    /// Filter by origin. Omit for all.
    pub source: Option<SourceFilter>,
    /// Case-insensitive substring match on id, tool_pattern, field, source, description.
    pub q: Option<String>,
}

/// Body of POST /tool-field-profiles. Mirrors `tool_rules::FieldProfile` minus
/// server-managed `is_builtin` (always false on user create).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateFieldProfile {
    pub id: Option<String>,
    pub description: Option<String>,
    pub source: Option<String>,
    /// Canonical concept identifier the wire tool maps to (`shell_exec`,
    /// `read_file`, `db_query`, etc.). Free-form string; `tool_ids.json`
    /// documents the shipped taxonomy but new ids are first-class.
    pub tool_id: String,
    pub tool_pattern: String,
    /// Optional pipe-separated glob over the request `app_id`. Mutually
    /// exclusive with `mcp_server`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_filter: Option<String>,
    /// Optional MCP server identifier (matches `mcp__<server>__<tool>`).
    /// Mutually exclusive with `app_filter`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    /// Optional server-tool discriminator (Anthropic `web_search_20250305`,
    /// OpenAI Responses `web_search_preview`, Gemini `google_search`, or any
    /// future provider's wire tag). Mutually exclusive with `app_filter` and
    /// `mcp_server`. The matching `ServerType` tier outranks `mcp_server`,
    /// `app_filter`, and generic in canonical-id resolution.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    pub field: String,
    /// Optional actual arg key on the wire — used when the client emits a
    /// different name than the canonical `field`. Defaults to `field`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_field: Option<String>,
    pub normalizer: Normalizer,
    #[serde(default = "default_priority")]
    pub priority: i32,
}

fn default_priority() -> i32 {
    100
}

#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateFieldProfile {
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub source: Option<Option<String>>,
    pub tool_id: Option<String>,
    pub tool_pattern: Option<String>,
    /// PATCH triple-state: absent = unchanged, `null` = clear, value = set.
    /// `double_option::deserialize` overrides serde's default outer-`Option`
    /// collapse so `null` lands as `Some(None)` instead of being read as
    /// "field absent".
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub app_filter: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub mcp_server: Option<Option<String>>,
    /// Server-tool discriminator. Same triple-state semantics as `app_filter`.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub server_type: Option<Option<String>>,
    pub field: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub wire_field: Option<Option<String>>,
    pub normalizer: Option<Normalizer>,
    pub priority: Option<i32>,
}

pub use super::ResetImpact;

/// One discovered `(tool_name, field)` pair from recent audit traces, with
/// the count of distinct tool definitions that exposed it. Operators click
/// "Register profile" to seed a CRUD form pre-filled with this pair.
#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoveredField {
    pub tool_name: String,
    pub field: String,
    /// How many distinct tool definitions in the lookback window included
    /// this field. Higher = more confident the field is real, not a typo.
    pub occurrences: usize,
    /// True when a profile already covers this `(tool_name, field)` —
    /// surfaced so the UI can hide already-registered fields.
    pub already_covered: bool,
    /// Suggested canonical `tool_id` for the row. Stage C ships only the
    /// "registry hard-map" classifier (Layer 1): MCP-namespaced tools whose
    /// server matches a shipped `mcp_server` profile get a high-confidence
    /// suggestion. Other tools have `None` — operator picks manually.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggested_tool_id: Option<String>,
    /// Confidence in `[0.0, 1.0]`. `1.0` for registry hard-map matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_confidence: Option<f32>,
    /// Where the suggestion came from: `"registry"` for MCP hard-map; `null`
    /// otherwise. Future layers (`heuristic`, `llm`) are deferred.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub suggestion_source: Option<String>,
    /// MCP server identity if the tool name parses as `mcp__<server>__<local>`.
    /// Surfaced so the UI can display "via MCP server foo" alongside the row.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct DiscoverResponse {
    pub fields: Vec<DiscoveredField>,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DiscoverQuery {
    /// How many of the most recent turns that declared tools to scan
    /// (default 500, cap 5000).
    pub lookback: Option<i64>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-field-profiles",
    tag = "Tool Field Profiles",
    params(FieldProfileListQuery),
    responses(
        (status = 200, description = "Paginated field profile list", body = OffsetPage<FieldProfile>),
        (status = 400, description = "The normalizer filter names no normaliser kind", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tool_field_profiles(
    mut db: TenantConn,
    Query(query): Query<FieldProfileListQuery>,
) -> Result<Json<OffsetPage<FieldProfile>>, ApiError> {
    let (limit, offset) = PageQuery {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve();
    let wanted: Option<Normalizer> = match query.normalizer.as_deref() {
        None => None,
        Some(kind) => Some(
            serde_json::from_value::<Normalizer>(serde_json::Value::String(kind.to_string())).map_err(|_| {
                ApiError::bad_request(format!("unknown normalizer `{kind}`"))
                    .code(ApiErrorCode::ToolFieldProfileNormalizerInvalid)
            })?,
        ),
    };

    let tenant_id = db.tenant_uuid();
    let profiles = load_profiles(db.conn(), tenant_id).await?;

    let filtered: Vec<FieldProfile> = profiles
        .into_iter()
        .filter(|p| {
            if wanted.is_some_and(|want| p.normalizer != want) {
                return false;
            }
            if query.source.is_some_and(|want| !want.admits(p.is_builtin)) {
                return false;
            }
            if let Some(q) = &query.q {
                let needle = q.to_lowercase();
                let hit_id = p
                    .id
                    .as_deref()
                    .map(|id| id.to_lowercase().contains(&needle))
                    .unwrap_or(false);
                let hit_pattern = p.tool_pattern.to_lowercase().contains(&needle);
                let hit_field = p.field.to_lowercase().contains(&needle);
                let hit_source = p
                    .source
                    .as_deref()
                    .map(|s| s.to_lowercase().contains(&needle))
                    .unwrap_or(false);
                let hit_desc = p
                    .description
                    .as_deref()
                    .map(|d| d.to_lowercase().contains(&needle))
                    .unwrap_or(false);
                if !(hit_id || hit_pattern || hit_field || hit_source || hit_desc) {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len() as i64;
    let start = offset.min(total) as usize;
    let end = (offset + limit).min(total) as usize;
    let items: Vec<FieldProfile> = filtered[start..end].to_vec();
    let has_more = (offset + items.len() as i64) < total;
    Ok(Json(OffsetPage {
        items,
        limit,
        offset,
        has_more,
        scan_cut: false,
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-field-profiles/{id}",
    tag = "Tool Field Profiles",
    params(("id" = String, Path, description = "Field profile id")),
    responses(
        (status = 200, description = "Field profile", body = FieldProfile),
        (status = 404, description = "Field profile not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tool_field_profile(
    mut db: TenantConn,
    Path(id): Path<String>,
) -> Result<Json<FieldProfile>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let profiles = load_profiles(db.conn(), tenant_id).await?;
    let profile = profiles
        .into_iter()
        .find(|p| p.id.as_deref() == Some(id.as_str()))
        .ok_or_else(|| {
            ApiError::not_found("field profile not found", ApiErrorCode::ToolFieldProfileNotFound)
        })?;
    Ok(Json(profile))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tool-field-profiles",
    tag = "Tool Field Profiles",
    request_body = CreateFieldProfile,
    responses(
        (status = 201, description = "Field profile created", body = FieldProfile),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 409, description = "Field profile id already exists", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_tool_field_profile(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(body): Json<CreateFieldProfile>,
) -> Result<(StatusCode, Json<FieldProfile>), ApiError> {
    let tenant_id = db.tenant_uuid();
    let id = body
        .id
        .clone()
        .unwrap_or_else(|| format!("TFP-{}", uuid::Uuid::new_v4()));
    if !is_valid_profile_id(&id) {
        return Err(ApiError::bad_request(format!(
            "field profile id must be 1..={MAX_PROFILE_ID_LEN} chars of [A-Za-z0-9._-]"
        ))
        .code(ApiErrorCode::ToolFieldProfileIdInvalid));
    }

    let profile = FieldProfile {
        id: Some(id.clone()),
        description: body.description,
        source: body.source,
        tool_id: body.tool_id,
        tool_pattern: body.tool_pattern,
        app_filter: body.app_filter,
        mcp_server: body.mcp_server,
        server_type: body.server_type,
        field: body.field,
        wire_field: body.wire_field,
        normalizer: body.normalizer,
        priority: body.priority,
        is_builtin: false,
    };
    map_validate(tool_rules::validate_field_profile(&profile))?;

    // Insert one row (no blob, no lock); a suppressed row with the same key is
    // resurrected, a live row is a 409.
    let seq = next_seq(db.conn(), tenant_id).await?;
    if !insert_profile(db.conn(), tenant_id, &profile, seq).await? {
        return Err(ApiError::conflict(format!(
            "field profile id '{id}' already exists"
        ), ApiErrorCode::ToolFieldProfileIdCollision));
    }

    audit_sink.record(None::<&FieldProfile>, Some(&profile));
    Ok((StatusCode::CREATED, Json(profile)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/tool-field-profiles/{id}",
    tag = "Tool Field Profiles",
    params(("id" = String, Path, description = "Field profile id")),
    request_body = UpdateFieldProfile,
    responses(
        (status = 200, description = "Field profile updated", body = FieldProfile),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 404, description = "Field profile not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_tool_field_profile(
    mut db: TenantConn,
    Path(id): Path<String>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(body): Json<UpdateFieldProfile>,
) -> Result<Json<FieldProfile>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Lock just this profile's row for the read→patch→write (FOR UPDATE) so a
    // concurrent PATCH to the SAME profile serializes; other rows never contend.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin tool_field_profiles tx: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    let row: Option<FieldProfileRow> = sqlx::query_as(
        "SELECT profile_key, description, source, tool_id, tool_pattern, app_filter, mcp_server, \
                server_type, field, wire_field, normalizer, priority, is_builtin \
         FROM tool_field_profiles WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("lock tool field profile: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    let mut profile = row
        .ok_or_else(|| {
            ApiError::not_found("field profile not found", ApiErrorCode::ToolFieldProfileNotFound)
        })?
        .into_profile()
        .map_err(|e| {
            tracing::error!("decode tool field profile: {e}");
            ApiError::internal("failed to update field profiles")
        })?;
    let before = profile.clone();
    let mut content_changed = false;

    if let Some(description) = body.description {
        if profile.description != description {
            content_changed = true;
        }
        profile.description = description;
    }
    if let Some(source) = body.source {
        if profile.source != source {
            content_changed = true;
        }
        profile.source = source;
    }
    if let Some(tool_id) = body.tool_id {
        if profile.tool_id != tool_id {
            content_changed = true;
        }
        profile.tool_id = tool_id;
    }
    if let Some(tp) = body.tool_pattern {
        if profile.tool_pattern != tp {
            content_changed = true;
        }
        profile.tool_pattern = tp;
    }
    if let Some(app_filter) = body.app_filter {
        if profile.app_filter != app_filter {
            content_changed = true;
        }
        profile.app_filter = app_filter;
    }
    if let Some(mcp_server) = body.mcp_server {
        if profile.mcp_server != mcp_server {
            content_changed = true;
        }
        profile.mcp_server = mcp_server;
    }
    if let Some(server_type) = body.server_type {
        if profile.server_type != server_type {
            content_changed = true;
        }
        profile.server_type = server_type;
    }
    if let Some(field) = body.field {
        if profile.field != field {
            content_changed = true;
        }
        profile.field = field;
    }
    if let Some(wire_field) = body.wire_field {
        if profile.wire_field != wire_field {
            content_changed = true;
        }
        profile.wire_field = wire_field;
    }
    if let Some(n) = body.normalizer
        && profile.normalizer != n
    {
        content_changed = true;
        profile.normalizer = n;
    }
    if let Some(priority) = body.priority {
        if profile.priority != priority {
            content_changed = true;
        }
        profile.priority = priority;
    }

    if content_changed && profile.is_builtin {
        profile.is_builtin = false;
    }
    map_validate(tool_rules::validate_field_profile(&profile))?;
    let updated = profile.clone();

    write_profile(&mut tx, tenant_id, &id, &updated).await?;
    tx.commit().await.map_err(|e| {
        tracing::error!("commit tool_field_profiles tx: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    audit_sink.record(Some(&before), Some(&updated));
    Ok(Json(updated))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/tool-field-profiles/{id}",
    tag = "Tool Field Profiles",
    params(("id" = String, Path, description = "Field profile id")),
    responses(
        (status = 200, description = "Field profile deleted", body = ActionResponse),
        (status = 404, description = "Field profile not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_tool_field_profile(
    mut db: TenantConn,
    Path(id): Path<String>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Load the one row first (for the audit before-image), then remove it.
    let row: Option<FieldProfileRow> = sqlx::query_as(
        "SELECT profile_key, description, source, tool_id, tool_pattern, app_filter, mcp_server, \
                server_type, field, wire_field, normalizer, priority, is_builtin \
         FROM tool_field_profiles WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("load tool field profile for delete: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    let removed = row
        .ok_or_else(|| {
            ApiError::not_found("field profile not found", ApiErrorCode::ToolFieldProfileNotFound)
        })?
        .into_profile()
        .map_err(|e| {
            tracing::error!("decode tool field profile for delete: {e}");
            ApiError::internal("failed to update field profiles")
        })?;

    // A profile that came from the seed — edited or not — is hidden; a user
    // profile is removed. The row decides, in the one statement that acts on it.
    let acted: i64 = sqlx::query_scalar(
        "WITH hidden AS ( \
           UPDATE tool_field_profiles SET suppressed = true, updated_at = now() \
           WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed AND seeded \
           RETURNING 1), \
         removed AS ( \
           DELETE FROM tool_field_profiles \
           WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed AND NOT seeded \
           RETURNING 1) \
         SELECT (SELECT count(*) FROM hidden) + (SELECT count(*) FROM removed)",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete tool field profile: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    // A concurrent delete got there first.
    if acted == 0 {
        return Err(ApiError::not_found("field profile not found", ApiErrorCode::ToolFieldProfileNotFound));
    }
    audit_sink.record(Some(&removed), None::<&FieldProfile>);

    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tool-field-profiles/actions/reset",
    tag = "Tool Field Profiles",
    responses(
        (status = 200, description = "Builtins restored", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_tool_field_profiles(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let loader = crate::seed_loader::SeedLoader::new();
    let seed_profiles = loader.load_tool_field_profiles();

    // Reset = force-restore every builtin from disk (re-stamp `is_builtin=true`,
    // clear suppression) and drop builtins no longer on disk; user-created rows
    // (`is_builtin=false`) are preserved. One transaction, no lock — the rows are
    // independent.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin tool_field_profiles tx: {e}");
        ApiError::internal("failed to reset field profiles")
    })?;

    // Deleted profiles the seed still ships — restoring them un-suppresses, so
    // report it.
    let seed_keys: Vec<&str> =
        seed_profiles.iter().filter_map(|s| s.get("id").and_then(|v| v.as_str())).collect();
    let cleared_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tool_field_profiles WHERE tenant_id = $1 AND suppressed AND profile_key = ANY($2)",
    )
    .bind(tenant_id)
    .bind(&seed_keys)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("count suppressed field profiles: {e}");
        ApiError::internal("failed to reset field profiles")
    })?;

    let mut restored_keys: Vec<String> = Vec::new();
    let mut seq: i64 = SEQ_STEP;
    for seed in &seed_profiles {
        let mut profile: FieldProfile = match serde_json::from_value(seed.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(
                    seed_id = ?seed.get("id").and_then(|v| v.as_str()),
                    error = %e,
                    "failed to deserialize builtin field profile during reset — skipping"
                );
                continue;
            }
        };
        profile.is_builtin = true;
        let Some(key) = profile.id.clone() else { continue };
        // Force-restore (overwrite any current state, clear suppression).
        sqlx::query(
            "INSERT INTO tool_field_profiles \
               (tenant_id, profile_key, description, source, tool_id, tool_pattern, app_filter, \
                mcp_server, server_type, field, wire_field, normalizer, priority, seq, is_builtin, suppressed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true, false) \
             ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
               description = EXCLUDED.description, source = EXCLUDED.source, tool_id = EXCLUDED.tool_id, \
               tool_pattern = EXCLUDED.tool_pattern, app_filter = EXCLUDED.app_filter, \
               mcp_server = EXCLUDED.mcp_server, server_type = EXCLUDED.server_type, field = EXCLUDED.field, \
               wire_field = EXCLUDED.wire_field, normalizer = EXCLUDED.normalizer, priority = EXCLUDED.priority, \
               seq = EXCLUDED.seq, is_builtin = true, suppressed = false, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(&key)
        .bind(&profile.description)
        .bind(&profile.source)
        .bind(&profile.tool_id)
        .bind(&profile.tool_pattern)
        .bind(&profile.app_filter)
        .bind(&profile.mcp_server)
        .bind(&profile.server_type)
        .bind(&profile.field)
        .bind(&profile.wire_field)
        .bind(normalizer_str(&profile.normalizer))
        .bind(profile.priority)
        .bind(seq)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("restore tool field profile: {e}");
            ApiError::internal("failed to reset field profiles")
        })?;
        restored_keys.push(key);
        seq += SEQ_STEP;
    }
    let restored_count = restored_keys.len();

    // Drop builtins no longer shipped on disk (orphan cleanup); user rows stay,
    // and so does a deleted (suppressed) row, so its delete stays final.
    sqlx::query(
        "DELETE FROM tool_field_profiles \
         WHERE tenant_id = $1 AND is_builtin AND NOT suppressed AND profile_key <> ALL($2)",
    )
    .bind(tenant_id)
    .bind(&restored_keys)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("prune orphan builtin field profiles: {e}");
        ApiError::internal("failed to reset field profiles")
    })?;

    let preserved_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tool_field_profiles WHERE tenant_id = $1 AND NOT is_builtin AND NOT suppressed",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("count preserved field profiles: {e}");
        ApiError::internal("failed to reset field profiles")
    })?;
    let preserved_count = preserved_count as usize;
    let cleared_count = cleared_count as usize;

    tx.commit().await.map_err(|e| {
        tracing::error!("commit tool_field_profiles tx: {e}");
        ApiError::internal("failed to reset field profiles")
    })?;

    let impact = ResetImpact {
        builtins_restored: restored_count,
        custom_preserved: preserved_count,
        deleted_builtins_cleared: cleared_count,
    };
    audit_sink.record(None::<&ResetImpact>, Some(&impact));
    Ok(Json(
        ActionResponse::ok()
            .with_message(format!(
                "restored {restored_count} builtins, preserved {preserved_count} custom"
            ))
            .with_impact(impact),
    ))
}

/// Aggregate `(tool_name, field)` pairs from the deduplicated tool blobs
/// referenced by `conversation_turns.tools_available_hash` (read by hash
/// from `tool_definitions`) over the recent N turns. Lets operators see what
/// fields tools actually expose before authoring profiles.
#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-field-profiles/discover",
    tag = "Tool Field Profiles",
    params(DiscoverQuery),
    responses(
        (status = 200, description = "Discovered (tool_name, field) pairs", body = DiscoverResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn discover_tool_fields(
    mut db: TenantConn,
    Query(query): Query<DiscoverQuery>,
) -> Result<Json<DiscoverResponse>, ApiError> {
    let lookback = query.lookback.unwrap_or(500).clamp(1, 5000);
    let tenant_id = db.tenant_uuid();
    let fields = aggregate_field_coverage(db.conn(), tenant_id, lookback).await?;
    Ok(Json(DiscoverResponse { fields }))
}

/// Aggregate `(tool_name, field)` occurrence counts from recent tool-definition
/// blobs and tag each pair with whether an existing field profile already
/// covers it. Shared by the `/discover` endpoint and the agent's tool-inventory
/// cycle (which feeds the coverage list into the expert prompt so it proposes
/// profiles for the high-occurrence uncovered fields). Returned sorted by
/// occurrences DESC.
pub(crate) async fn aggregate_field_coverage(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    lookback: i64,
) -> Result<Vec<DiscoveredField>, ApiError> {
    let scan_err = |e: sqlx::Error| {
        tracing::error!("discover_tool_fields query: {e}");
        ApiError::internal("failed to scan audit traces for tool fields")
    };
    let hashes = crate::audit_store::tool_activity::recent_tool_set_hashes(&mut *conn, tenant_id, lookback)
        .await
        .map_err(scan_err)?;
    let distinct: Vec<String> = hashes.iter().cloned().collect::<BTreeSet<_>>().into_iter().collect();
    let sets = crate::content_store::tool_definitions::get_many(&mut *conn, tenant_id, &distinct)
        .await
        .map_err(scan_err)?;

    let counts = count_tool_fields(&hashes, &sets);

    // Determine which pairs are already covered by an existing profile, and
    // surface a `tool_id` suggestion for unprofiled rows when the registry
    // hard-map (the only Stage C classifier) finds a match.
    let profiles = load_profiles(&mut *conn, tenant_id).await?;
    let profile_set = tool_rules::FieldProfileSet::new(profiles.clone());
    let mut fields: Vec<DiscoveredField> = counts
        .into_iter()
        .map(|((tool_name, field), occurrences)| {
            // When a profile declares a `wire_field`, the
            // discovered name from the request_tools schema is the wire form
            // (e.g. Cursor's `target_file`), not the canonical `field`. Match
            // against `wire_field` when present, falling back to `field`.
            // Without this, profiles that rename the wire form silently
            // report as uncovered and the operator sees noise.
            let already_covered = profiles.iter().any(|p| {
                let effective_field = p.wire_field.as_deref().unwrap_or(p.field.as_str());
                effective_field == field && tool_rules::matches_glob(&tool_name, &p.tool_pattern)
            });
            // Layer 1 classifier: parse MCP namespace. If the tool name is
            // `mcp__<server>__<local>` and a registered MCP-server profile
            // resolves the local name, suggest its `tool_id`.
            let (effective, mcp_server) = match tool_rules::parse_mcp_namespace(&tool_name) {
                Some((srv, local)) => (local.to_string(), Some(srv.to_string())),
                None => (tool_name.clone(), None),
            };
            let suggested_tool_id = if !already_covered && mcp_server.is_some() {
                profile_set
                    .resolve_tool_id(&effective, None, mcp_server.as_deref())
                    .map(|s| s.to_string())
            } else {
                None
            };
            let (suggestion_confidence, suggestion_source) = if suggested_tool_id.is_some() {
                (Some(1.0_f32), Some("registry".to_string()))
            } else {
                (None, None)
            };
            DiscoveredField {
                tool_name,
                field,
                occurrences,
                already_covered,
                suggested_tool_id,
                suggestion_confidence,
                suggestion_source,
                mcp_server,
            }
        })
        .collect();
    fields.sort_by(|a, b| {
        b.occurrences
            .cmp(&a.occurrences)
            .then_with(|| a.tool_name.cmp(&b.tool_name))
            .then_with(|| a.field.cmp(&b.field))
    });
    Ok(fields)
}

/// `(tool_name, field)` → occurrences over the turns' tool sets: each turn
/// counts its set once, so a set several turns declared weighs as many; a set
/// no longer stored counts for nothing. A set is the raw model-facing tools
/// list (its shape varies by protocol).
fn count_tool_fields(
    turn_hashes: &[String],
    sets: &std::collections::HashMap<String, serde_json::Value>,
) -> BTreeMap<(String, String), usize> {
    let mut counts: BTreeMap<(String, String), usize> = BTreeMap::new();
    for val in turn_hashes.iter().filter_map(|h| sets.get(h)) {
        let Some(arr) = val.as_array() else { continue };
        for tool in arr {
            collect_tool_fields(tool, &mut counts);
        }
    }
    counts
}

/// Walk a single tool definition and pull out (tool_name, field) pairs from
/// its input schema. Handles MCP-style `inputSchema.properties`, OpenAI-style
/// `parameters.properties`, and Anthropic-style `input_schema.properties`.
fn collect_tool_fields(
    tool: &serde_json::Value,
    counts: &mut BTreeMap<(String, String), usize>,
) {
    let Some(obj) = tool.as_object() else { return };
    // Tool name lives at one of several keys depending on protocol shape.
    let name = obj
        .get("name")
        .and_then(|v| v.as_str())
        .or_else(|| obj.get("function").and_then(|f| f.get("name")).and_then(|v| v.as_str()))
        .unwrap_or("");
    if name.is_empty() {
        return;
    }
    // OpenAI Chat function-calling wraps the schema under `function.parameters`.
    let function_inner = obj.get("function").and_then(|v| v.as_object());
    let schema_candidates = ["inputSchema", "input_schema", "parameters"];
    let mut seen_fields: BTreeSet<String> = BTreeSet::new();
    for key in &schema_candidates {
        let schema = obj
            .get(*key)
            .or_else(|| function_inner.and_then(|f| f.get(*key)));
        if let Some(props) = schema
            .and_then(|s| s.get("properties"))
            .and_then(|p| p.as_object())
        {
            for field_name in props.keys() {
                seen_fields.insert(field_name.clone());
            }
        }
    }
    for field in seen_fields {
        *counts.entry((name.to_string(), field)).or_insert(0) += 1;
    }
}

// ---------------------------------------------------------------------------
// Tool ID taxonomy
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize, ToSchema)]
pub struct ToolIdsResponse {
    pub tool_ids: Vec<ToolIdEntry>,
}

/// Return the canonical `tool_id` taxonomy shipped with the engine. The UI
/// uses this to populate the tool_id autocomplete in the profile + rule
/// modals. Free-form custom ids are still accepted by CRUD validation —
/// this list is documentation, not an enum.
#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-ids",
    tag = "Tool Field Profiles",
    responses(
        (status = 200, description = "Canonical tool_id taxonomy", body = ToolIdsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tool_ids(_db: TenantConn) -> Result<Json<ToolIdsResponse>, ApiError> {
    Ok(Json(ToolIdsResponse {
        tool_ids: crate::seed_loader::load_tool_ids().to_vec(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct KnownServerToolTypesResponse {
    pub server_types: Vec<tool_rules::KnownServerToolType>,
}

/// Return the canonical list of known native server-tool wire tags. The UI's
/// `server_type` autocomplete in `FieldProfileEditModal` sources from this
/// endpoint instead of hard-coding tags, so adding a new variant to the Rust
/// `known_server_tool_types()` function propagates to the UI automatically.
/// Operators can still author profiles for unlisted providers — this is a
/// suggestion list, not a closed set.
#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-field-profiles/known-server-types",
    tag = "Tool Field Profiles",
    responses(
        (status = 200, description = "Known native server-tool tags", body = KnownServerToolTypesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_known_server_tool_types(
    _db: TenantConn,
) -> Result<Json<KnownServerToolTypesResponse>, ApiError> {
    Ok(Json(KnownServerToolTypesResponse {
        server_types: tool_rules::known_server_tool_types(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ResourceIdsResponse {
    pub resource_ids: Vec<ToolIdEntry>,
}

/// Return the canonical `resource_id` taxonomy. Same shape as
/// [`list_tool_ids`] — free-form custom ids are accepted, the list is
/// documentation. Rule-editor `(_, resource_reads)` autocompletes against
/// this.
#[utoipa::path(
    get,
    path = "/api/v1/admin/resource-ids",
    tag = "Tool Field Profiles",
    responses(
        (status = 200, description = "Canonical resource_id taxonomy", body = ResourceIdsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_resource_ids(_db: TenantConn) -> Result<Json<ResourceIdsResponse>, ApiError> {
    Ok(Json(ResourceIdsResponse {
        resource_ids: crate::seed_loader::load_resource_ids().to_vec(),
    }))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct PromptIdsResponse {
    pub prompt_ids: Vec<ToolIdEntry>,
}

/// Return the canonical `prompt_id` taxonomy. Rule-editor
/// `(request, prompt_invocations)` autocompletes against this.
#[utoipa::path(
    get,
    path = "/api/v1/admin/prompt-ids",
    tag = "Tool Field Profiles",
    responses(
        (status = 200, description = "Canonical prompt_id taxonomy", body = PromptIdsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_prompt_ids(_db: TenantConn) -> Result<Json<PromptIdsResponse>, ApiError> {
    Ok(Json(PromptIdsResponse {
        prompt_ids: crate::seed_loader::load_prompt_ids().to_vec(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Field-profile suggestions (agent-proposed) — review surface
// ---------------------------------------------------------------------------

/// A pending/reviewed field-profile suggestion proposed by the agent. Displayed
/// read-only; on approval the row is registered in `tool_field_profiles`.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
#[allow(dead_code)] // constructed by sqlx::query_as at runtime
pub struct FieldProfileSuggestionResponse {
    pub id: uuid::Uuid,
    pub expert_axis: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proposed_profile_id: Option<String>,
    pub description: Option<String>,
    pub source: Option<String>,
    pub tool_id: String,
    pub tool_pattern: String,
    pub app_filter: Option<String>,
    pub mcp_server: Option<String>,
    pub server_type: Option<String>,
    pub field: String,
    pub wire_field: Option<String>,
    pub normalizer: String,
    pub priority: i32,
    pub rationale: String,
    pub status: String,
    #[schema(value_type = Option<Vec<String>>)]
    pub source_sessions: Option<sqlx::types::Json<Vec<String>>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of every field an approval installs; send it back on approve so
    /// the approval installs exactly what was reviewed.
    pub content_hash: String,
}

/// The columns an approval installs from a pending suggestion — what the claim
/// returns and what its `content_hash` covers, one list for both.
macro_rules! field_profile_suggestion_columns {
    () => {
        "proposed_profile_id, description, source, tool_id, tool_pattern, app_filter, mcp_server, server_type, field, wire_field, normalizer, priority"
    };
}
const FIELD_PROFILE_SUGGESTION_COLUMNS: &str = field_profile_suggestion_columns!();
/// `content_hash` of a suggestion row, over exactly [`FIELD_PROFILE_SUGGESTION_COLUMNS`].
const FIELD_PROFILE_SUGGESTION_HASH_SQL: &str =
    concat!("encode(sha256(convert_to(jsonb_build_array(", field_profile_suggestion_columns!(), ")::text, 'UTF8')), 'hex')");

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/field-profile-suggestions",
    tag = "Experts",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of field profile suggestions", body = OffsetPage<FieldProfileSuggestionResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_field_profile_suggestions(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<FieldProfileSuggestionResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let min_seen = crate::settings::admin_settings().agent_suggestion_min_seen;
    let rows: Vec<FieldProfileSuggestionResponse> =
        sqlx::query_as::<_, FieldProfileSuggestionResponse>(sqlx::AssertSqlSafe(format!(
            "SELECT id, expert_axis, proposed_profile_id, description, source, tool_id, \
                    tool_pattern, app_filter, mcp_server, server_type, field, wire_field, \
                    normalizer, priority, rationale, status, source_sessions, created_at, reviewed_at, \
                    {FIELD_PROFILE_SUGGESTION_HASH_SQL} AS content_hash \
             FROM field_profile_suggestions \
             WHERE status != 'pending' OR seen_count >= $3 \
             ORDER BY created_at DESC LIMIT $1 OFFSET $2",
        )))
        .bind(limit + 1)
        .bind(offset)
        .bind(min_seen)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list field profile suggestions: {e}");
            ApiError::internal("internal error")
        })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/field-profile-suggestions/{id}/actions/approve",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Field profile suggestion ID")),
    request_body = super::transforms::ApproveSuggestionRequest,
    responses(
        (status = 200, description = "Suggestion approved; the field profile is registered", body = ActionResponse),
        (status = 400, description = "The proposed profile is invalid", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Suggestion not found or not pending", body = ApiErrorResponse),
        (status = 409, description = "The suggestion changed since it was reviewed (`suggestion_changed`), or the field profile id already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_field_profile_suggestion(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<super::transforms::ApproveSuggestionRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Claim and read the suggestion in the transaction that registers the
    // profile, so the profile is built from exactly the row marked approved.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin field profile approve tx: {e}");
        ApiError::internal("internal error")
    })?;
    let (
        proposed_profile_id,
        description,
        source,
        tool_id,
        tool_pattern,
        app_filter,
        mcp_server,
        server_type,
        field,
        wire_field,
        normalizer_str,
        priority,
    ) = super::transforms::claim_pending_suggestion::<(
        Option<String>, // proposed_profile_id
        Option<String>, // description
        Option<String>, // source
        String,         // tool_id
        String,         // tool_pattern
        Option<String>, // app_filter
        Option<String>, // mcp_server
        Option<String>, // server_type
        String,         // field
        Option<String>, // wire_field
        String,         // normalizer
        i32,            // priority
    )>(
        &mut tx,
        "field_profile_suggestions",
        id,
        "approved",
        FIELD_PROFILE_SUGGESTION_COLUMNS,
        Some(super::transforms::ReviewedContent {
            hash_sql: FIELD_PROFILE_SUGGESTION_HASH_SQL,
            content_hash: &req.content_hash,
        }),
    )
    .await?;

    let normalizer: Normalizer = serde_json::from_value(serde_json::Value::String(normalizer_str))
        .map_err(|e| {
            ApiError::bad_request(format!("suggestion has invalid normalizer: {e}"))
                .code(ApiErrorCode::ToolFieldProfileInvalid)
        })?;

    let new_id = proposed_profile_id
        .filter(|p| is_valid_profile_id(p))
        .unwrap_or_else(|| format!("TFP-{}", uuid::Uuid::new_v4()));
    let profile = FieldProfile {
        id: Some(new_id.clone()),
        description,
        source,
        tool_id,
        tool_pattern,
        app_filter,
        mcp_server,
        server_type,
        field,
        wire_field,
        normalizer,
        priority,
        is_builtin: false,
    };
    map_validate(tool_rules::validate_field_profile(&profile))?;

    // Register the profile (one row), committed with the claim — no blob.
    let seq = next_seq(&mut tx, tenant_id).await?;
    if !insert_profile(&mut tx, tenant_id, &profile, seq).await? {
        return Err(ApiError::conflict(format!(
            "field profile id '{new_id}' already exists"
        ), ApiErrorCode::ToolFieldProfileIdCollision));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("commit field profile approve tx: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/field-profile-suggestions/{id}/actions/reject",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Field profile suggestion ID")),
    responses(
        (status = 200, description = "Suggestion rejected", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Suggestion not found or not pending", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_field_profile_suggestion(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    super::transforms::reject_pending_suggestion(&mut db, "field_profile_suggestions", id).await
}

fn map_validate(result: Result<(), FieldProfileValidationError>) -> Result<(), ApiError> {
    match result {
        Ok(()) => Ok(()),
        Err(FieldProfileValidationError::EmptyToolPattern) => {
            Err(ApiError::bad_request("tool_pattern must not be empty")
                .code(ApiErrorCode::ToolFieldProfileInvalid))
        }
        Err(FieldProfileValidationError::EmptyField) => {
            Err(ApiError::bad_request("field must not be empty")
                .code(ApiErrorCode::ToolFieldProfileInvalid))
        }
        Err(FieldProfileValidationError::InvalidFieldChar { ch }) => Err(ApiError::bad_request(
            format!(
                "field must be a plain identifier (got non-alphanumeric/underscore char {ch:?}); \
                 do not include the rule-side `arg.` prefix"
            ),
        )
        .code(ApiErrorCode::ToolFieldProfileInvalid)),
        Err(FieldProfileValidationError::EmptyToolId) => Err(ApiError::bad_request(
            "tool_id must not be empty — pick a canonical concept id (e.g. `read_file`, `shell_exec`)",
        )
        .code(ApiErrorCode::ToolFieldProfileInvalid)),
        Err(FieldProfileValidationError::InvalidToolIdChar { ch }) => Err(ApiError::bad_request(
            format!(
                "tool_id must use only [A-Za-z0-9_] chars (got {ch:?}); use `_` instead of `.` or `-`"
            ),
        )
        .code(ApiErrorCode::ToolFieldProfileInvalid)),
        Err(FieldProfileValidationError::AppFilterMcpServerExclusive) => Err(ApiError::bad_request(
            "app_filter and mcp_server are mutually exclusive — a profile is either app-scoped \
             or mcp-server-scoped, never both",
        )
        .code(ApiErrorCode::ToolFieldProfileAppMcpExclusive)),
        Err(FieldProfileValidationError::ServerTypeScopeExclusive) => Err(ApiError::bad_request(
            "server_type is mutually exclusive with app_filter and mcp_server — a profile is \
             either server-type-scoped, mcp-server-scoped, app-scoped, or generic, never a \
             combination",
        )
        .code(ApiErrorCode::ToolFieldProfileServerTypeExclusive)),
        Err(FieldProfileValidationError::EmptyScopeFilter { field }) => Err(ApiError::bad_request(
            format!("{field} must not be empty or whitespace-only — use null to clear instead"),
        )
        .code(ApiErrorCode::ToolFieldProfileInvalid)),
    }
}

// ---------------------------------------------------------------------------
// Storage — `tool_field_profiles` is one row per profile (`(tenant_id,
// profile_key)`). A user edit flips `is_builtin=false`; a deleted builtin is a
// `suppressed` row that seed-sync skips. `seq` (gap-spaced) preserves load order
// for the proxy's `FieldProfileSet` position tiebreaker.
// ---------------------------------------------------------------------------

/// Gap between adjacent profile `seq` values on insert (room to splice without
/// renumbering — mirrors `tool_policy_rules`). Shared with seed-sync.
pub(crate) const SEQ_STEP: i64 = 1024;

/// One `tool_field_profiles` row (the `normalizer` enum as snake_case TEXT).
#[derive(sqlx::FromRow)]
struct FieldProfileRow {
    profile_key: String,
    description: Option<String>,
    source: Option<String>,
    tool_id: String,
    tool_pattern: String,
    app_filter: Option<String>,
    mcp_server: Option<String>,
    server_type: Option<String>,
    field: String,
    wire_field: Option<String>,
    normalizer: String,
    priority: i32,
    is_builtin: bool,
}

impl FieldProfileRow {
    fn into_profile(self) -> Result<FieldProfile, serde_json::Error> {
        Ok(FieldProfile {
            id: Some(self.profile_key),
            description: self.description,
            source: self.source,
            tool_id: self.tool_id,
            tool_pattern: self.tool_pattern,
            app_filter: self.app_filter,
            mcp_server: self.mcp_server,
            server_type: self.server_type,
            field: self.field,
            wire_field: self.wire_field,
            normalizer: serde_json::from_value(serde_json::Value::String(self.normalizer))?,
            priority: self.priority,
            is_builtin: self.is_builtin,
        })
    }
}

/// Serialize the `Normalizer` enum to its snake_case discriminant for the TEXT column.
fn normalizer_str(n: &Normalizer) -> String {
    serde_json::to_value(n)
        .ok()
        .and_then(|v| v.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Load the tenant's live (non-suppressed) field profiles in load order. Tenant
/// bound explicitly (snapshot + admin handlers). Malformed rows are dropped.
pub(crate) async fn load_profiles(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<Vec<FieldProfile>, ApiError> {
    let rows: Vec<FieldProfileRow> = sqlx::query_as(
        "SELECT profile_key, description, source, tool_id, tool_pattern, app_filter, mcp_server, \
                server_type, field, wire_field, normalizer, priority, is_builtin \
         FROM tool_field_profiles WHERE tenant_id = $1 AND NOT suppressed ORDER BY seq, profile_key",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load tool_field_profiles: {e}");
        ApiError::internal("failed to load tool field profiles")
    })?;
    Ok(rows.into_iter().filter_map(into_profile_logged).collect())
}

/// RLS-scoped loader (no tenant bind) for the admin-side classifier — parallel
/// to `tool_rules::load_rules_rls`. Used by analytics aggregation that already
/// runs in tenant scope.
pub(crate) async fn load_profiles_rls(executor: &mut Scoped) -> Result<Vec<FieldProfile>, sqlx::Error> {
    let rows: Vec<FieldProfileRow> = sqlx::query_as(
        "SELECT profile_key, description, source, tool_id, tool_pattern, app_filter, mcp_server, \
                server_type, field, wire_field, normalizer, priority, is_builtin \
         FROM tool_field_profiles WHERE NOT suppressed ORDER BY seq, profile_key",
    )
    .fetch_all(executor)
    .await?;
    Ok(rows.into_iter().filter_map(into_profile_logged).collect())
}

fn into_profile_logged(r: FieldProfileRow) -> Option<FieldProfile> {
    let key = r.profile_key.clone();
    r.into_profile()
        .map_err(|e| tracing::warn!(profile = %key, error = %e, "dropping malformed tool field profile"))
        .ok()
}

/// Next `seq` for a new profile (MAX + STEP), tenant bound.
async fn next_seq(conn: &mut Scoped, tenant_id: uuid::Uuid) -> Result<i64, ApiError> {
    let max: Option<i64> =
        sqlx::query_scalar("SELECT MAX(seq) FROM tool_field_profiles WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("next field profile seq: {e}");
                ApiError::internal("failed to update field profiles")
            })?;
    Ok(max.unwrap_or(0) + SEQ_STEP)
}

/// Insert a new user profile (`is_builtin=false`). A suppressed row with the
/// same key is resurrected; a live row is a collision → `Ok(false)`.
async fn insert_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    p: &FieldProfile,
    seq: i64,
) -> Result<bool, ApiError> {
    let res: Option<(String,)> = sqlx::query_as(
        "INSERT INTO tool_field_profiles \
           (tenant_id, profile_key, description, source, tool_id, tool_pattern, app_filter, \
            mcp_server, server_type, field, wire_field, normalizer, priority, seq, is_builtin, suppressed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, false, false) \
         ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
           description = EXCLUDED.description, source = EXCLUDED.source, tool_id = EXCLUDED.tool_id, \
           tool_pattern = EXCLUDED.tool_pattern, app_filter = EXCLUDED.app_filter, \
           mcp_server = EXCLUDED.mcp_server, server_type = EXCLUDED.server_type, field = EXCLUDED.field, \
           wire_field = EXCLUDED.wire_field, normalizer = EXCLUDED.normalizer, priority = EXCLUDED.priority, \
           seq = EXCLUDED.seq, is_builtin = false, suppressed = false, updated_at = now() \
         WHERE tool_field_profiles.suppressed \
         RETURNING profile_key",
    )
    .bind(tenant_id)
    .bind(p.id.as_deref().unwrap_or_default())
    .bind(&p.description)
    .bind(&p.source)
    .bind(&p.tool_id)
    .bind(&p.tool_pattern)
    .bind(&p.app_filter)
    .bind(&p.mcp_server)
    .bind(&p.server_type)
    .bind(&p.field)
    .bind(&p.wire_field)
    .bind(normalizer_str(&p.normalizer))
    .bind(p.priority)
    .bind(seq)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("insert tool field profile: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    Ok(res.is_some())
}

/// Single-row UPDATE of an existing profile (every column except `seq`/`suppressed`).
async fn write_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    id: &str,
    p: &FieldProfile,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE tool_field_profiles SET \
           description = $3, source = $4, tool_id = $5, tool_pattern = $6, app_filter = $7, \
           mcp_server = $8, server_type = $9, field = $10, wire_field = $11, normalizer = $12, \
           priority = $13, is_builtin = $14, updated_at = now() \
         WHERE tenant_id = $1 AND profile_key = $2",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(&p.description)
    .bind(&p.source)
    .bind(&p.tool_id)
    .bind(&p.tool_pattern)
    .bind(&p.app_filter)
    .bind(&p.mcp_server)
    .bind(&p.server_type)
    .bind(&p.field)
    .bind(&p.wire_field)
    .bind(normalizer_str(&p.normalizer))
    .bind(p.priority)
    .bind(p.is_builtin)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("update tool field profile: {e}");
        ApiError::internal("failed to update field profiles")
    })?;
    Ok(())
}

/// The builtin upsert for `tool_field_profiles`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const TOOL_FIELD_PROFILE_UPSERT: &str = "INSERT INTO tool_field_profiles \
           (tenant_id, profile_key, description, source, tool_id, tool_pattern, app_filter, \
            mcp_server, server_type, field, wire_field, normalizer, priority, seq, is_builtin, suppressed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, true, false) \
         ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
           description = EXCLUDED.description, source = EXCLUDED.source, tool_id = EXCLUDED.tool_id, \
           tool_pattern = EXCLUDED.tool_pattern, app_filter = EXCLUDED.app_filter, \
           mcp_server = EXCLUDED.mcp_server, server_type = EXCLUDED.server_type, field = EXCLUDED.field, \
           wire_field = EXCLUDED.wire_field, normalizer = EXCLUDED.normalizer, priority = EXCLUDED.priority, \
           seq = EXCLUDED.seq, updated_at = now() \
         WHERE tool_field_profiles.is_builtin AND NOT tool_field_profiles.suppressed \
           AND (tool_field_profiles.description, tool_field_profiles.source, tool_field_profiles.tool_id, tool_field_profiles.tool_pattern, tool_field_profiles.app_filter, tool_field_profiles.mcp_server, tool_field_profiles.server_type, tool_field_profiles.field, tool_field_profiles.wire_field, tool_field_profiles.normalizer, tool_field_profiles.priority, tool_field_profiles.seq) \
               IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.source, EXCLUDED.tool_id, EXCLUDED.tool_pattern, EXCLUDED.app_filter, EXCLUDED.mcp_server, EXCLUDED.server_type, EXCLUDED.field, EXCLUDED.wire_field, EXCLUDED.normalizer, EXCLUDED.priority, EXCLUDED.seq)";

/// Seed UPSERT of a builtin field profile (`is_builtin=true`). The
/// `WHERE is_builtin AND NOT suppressed` guard preserves a user edit and never
/// resurrects a soft-deleted builtin; a fresh row inserts. Shared by seed-sync.
pub(crate) async fn upsert_builtin_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    p: &FieldProfile,
    seq: i64,
) -> Result<(), sqlx::Error> {
    sqlx::query(TOOL_FIELD_PROFILE_UPSERT)
    .bind(tenant_id)
    .bind(p.id.as_deref().unwrap_or_default())
    .bind(&p.description)
    .bind(&p.source)
    .bind(&p.tool_id)
    .bind(&p.tool_pattern)
    .bind(&p.app_filter)
    .bind(&p.mcp_server)
    .bind(&p.server_type)
    .bind(&p.field)
    .bind(&p.wire_field)
    .bind(normalizer_str(&p.normalizer))
    .bind(p.priority)
    .bind(seq)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn each_turn_counts_its_set_once_and_a_set_no_longer_stored_counts_for_nothing() {
        let set = serde_json::json!([
            {"name": "Read", "input_schema": {"properties": {"file_path": {"type": "string"}}}}
        ]);
        let sets: std::collections::HashMap<String, serde_json::Value> =
            [("a".to_string(), set)].into_iter().collect();
        let turns: Vec<String> = ["a", "a", "gone", "a"].iter().map(|h| h.to_string()).collect();
        let counts = count_tool_fields(&turns, &sets);
        assert_eq!(counts.get(&("Read".to_string(), "file_path".to_string())), Some(&3));
        assert_eq!(counts.len(), 1);
        assert!(count_tool_fields(&["gone".to_string()], &sets).is_empty());
    }
}
