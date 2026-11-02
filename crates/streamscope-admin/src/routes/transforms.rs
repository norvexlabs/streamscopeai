//! Transform program CRUD and agent suggestion management.
//!
//! Manages Rhai scripts that modify LLM requests and responses. Programs have
//! a phase (request/response), scope (global, system_prompt, messages, tools),
//! priority, and optional model/app filters. Also manages program suggestions
//! from the LLM agent: approve, reject, dismiss, and wipe operations.
//! Expert memory and snippet endpoints for the agent dashboard live here too.

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};

use utoipa::{IntoParams, ToSchema};

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, TotalPage};
use crate::AdminState;
use crate::agent::experts::{default_snippet_keys, EXPERT_COLORS};
use crate::db::tenant::{Scoped, TenantConn};

// Valid scopes per phase.
const VALID_REQUEST_SCOPES: &[&str] = &["global", "system_prompt", "messages", "tools"];
const VALID_RESPONSE_SCOPES: &[&str] = &["global", "text", "tool", "thinking"];
const VALID_PHASES: &[&str] = &["request", "response"];

// ─── Programs ───

#[derive(Deserialize, ToSchema)]
pub struct CreateProgramRequest {
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    #[serde(default = "default_phase")]
    pub phase: String,
    #[serde(default = "default_scope")]
    pub scope: String,
    #[serde(default = "default_priority")]
    pub priority: i32,
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub model_filter: Option<String>,
    #[serde(default)]
    pub app_filter: Option<String>,
    /// Optional fast-find trigger regex. When set, the program runs only if the
    /// in-scope content matches. Empty/omitted ⇒ always run.
    #[serde(default)]
    pub trigger_regex: Option<String>,
    /// Execution mode: `"full"`/omitted runs the script once over the whole scope;
    /// `"span"` runs it once per `trigger_regex` match on just the matched span.
    /// `"span"` requires a non-blank `trigger_regex`.
    #[serde(default)]
    pub match_mode: Option<String>,
    /// Transform profile scope. Omitted/`null` → **shared** (runs for every
    /// profile's effective set — the baseline). A profile id → **specific** to
    /// that transform profile.
    #[serde(default)]
    pub profile_id: Option<uuid::Uuid>,
}

fn default_phase() -> String {
    "request".to_string()
}
fn default_scope() -> String {
    "global".to_string()
}
fn default_priority() -> i32 {
    100
}

/// Validate an optional `trigger_regex`: a blank value is normalized to `None`;
/// a non-blank value must compile against the `regex` crate (the same engine the
/// proxy's fast-find uses) or the request is rejected.
/// Replace a profile's own transform programs with a fresh copy of the builtin
/// seed set (the "seed" content adapter — used by reset-to-seed and
/// create-from-seed). `as_default = true` keeps the original program names and
/// `is_builtin = true` (the pristine shared base, for resetting the Default
/// profile); `false` suffixes each name with the profile id and sets
/// `is_builtin = false` (independent copies — the `(tenant_id, name)` uniqueness
/// forbids reusing the Default's names). Returns the count written.
pub(crate) async fn seed_programs_onto_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    profile_id: uuid::Uuid,
    as_default: bool,
) -> Result<i64, ApiError> {
    let loader = crate::seed_loader::SeedLoader::new();
    sqlx::query("DELETE FROM transform_programs WHERE tenant_id = $1 AND profile_id = $2")
        .bind(tenant_id)
        .bind(profile_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("clear programs for seed: {e}");
            ApiError::internal("failed to seed transform programs")
        })?;
    let suffix = format!(" ({})", &profile_id.simple().to_string()[..8]);
    let mut count = 0i64;
    for script in loader.load_scripts() {
        let engine = streamscope_core::scripting::ScriptEngine::new();
        if engine.validate(&script.source).is_err() {
            continue;
        }
        let name = if as_default {
            script.name.clone()
        } else {
            format!("{}{}", script.name, suffix)
        };
        sqlx::query(
            "INSERT INTO transform_programs (tenant_id, name, description, source, phase, scope, priority, enabled, model_filter, app_filter, trigger_regex, match_mode, is_builtin, profile_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) \
             ON CONFLICT (tenant_id, name) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(&name)
        .bind(&script.description)
        .bind(&script.source)
        .bind(&script.phase)
        .bind(&script.scope)
        .bind(script.priority)
        .bind(script.enabled)
        .bind(&script.model_filter)
        .bind(&script.app_filter)
        .bind(&script.trigger_regex)
        .bind(&script.match_mode)
        .bind(as_default)
        .bind(profile_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("seed program onto profile: {e}");
            ApiError::internal("failed to seed transform programs")
        })?;
        count += 1;
    }
    Ok(count)
}

pub(crate) fn validate_trigger_regex(raw: Option<&str>) -> Result<Option<String>, ApiError> {
    match raw.map(str::trim).filter(|s| !s.is_empty()) {
        None => Ok(None),
        Some(pat) => match regex::Regex::new(pat) {
            Ok(_) => Ok(Some(pat.to_string())),
            Err(e) => Err(ApiError::bad_request(format!("invalid trigger_regex: {e}"))
                .code(ApiErrorCode::TransformTriggerInvalid)),
        },
    }
}

/// Validate `match_mode`. Only `"span"` is stored (everything else — `"full"`,
/// blank, unrecognized — normalizes to `None`, the default full-context mode, so
/// the column only ever holds `NULL` or `"span"`). `"span"` requires a non-blank
/// `trigger_regex` (it is the span finder); on update the trigger is taken from
/// the same request, so switching to span must also supply the pattern.
pub(crate) fn validate_match_mode(
    raw: Option<&str>,
    trigger_regex: Option<&str>,
) -> Result<Option<String>, ApiError> {
    match raw.map(str::trim) {
        Some("span") => {
            if trigger_regex.map(str::trim).is_some_and(|t| !t.is_empty()) {
                Ok(Some("span".to_string()))
            } else {
                Err(ApiError::bad_request(
                    "span match_mode requires a non-blank trigger_regex",
                )
                .code(ApiErrorCode::TransformSpanModeNeedsTrigger))
            }
        }
        _ => Ok(None),
    }
}

// ─── Response types ───

#[derive(Serialize, sqlx::FromRow, ToSchema)]
#[allow(dead_code)] // constructed by sqlx::query_as at runtime
pub struct ProgramResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub description: Option<String>,
    pub source: String,
    pub phase: String,
    pub scope: String,
    pub priority: i32,
    pub version: i32,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
    pub model_filter: Option<String>,
    pub app_filter: Option<String>,
    pub trigger_regex: Option<String>,
    pub match_mode: Option<String>,
    /// Transform profile scope. `None` → shared (the baseline); `Some` →
    /// specific to that transform profile.
    pub profile_id: Option<uuid::Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateProgramResponse {
    pub id: uuid::Uuid,
    pub name: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct StatusMessageResponse {
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ValidateProgramResponse {
    pub valid: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct TestProgramResponse {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    /// What the program returned for the test context — whatever value the script produced; `null` when it returned nothing.
    #[schema(value_type = Option<Object>)]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
#[allow(dead_code)] // constructed by sqlx::query_as at runtime
pub struct SuggestionResponse {
    pub id: uuid::Uuid,
    pub expert_axis: String,
    pub title: String,
    pub rationale: String,
    pub proposed_source: String,
    pub proposed_phase: String,
    pub proposed_scope: String,
    pub proposed_model_filter: Option<String>,
    pub proposed_app_filter: Option<String>,
    /// Optional fast-find / span-finder regex carried onto the promoted program.
    pub proposed_trigger_regex: Option<String>,
    /// `span` = per-match `fn transform(m)`; `None`/`full` = whole-scope `fn transform(ctx)`.
    pub proposed_match_mode: Option<String>,
    pub status: String,
    pub program_id: Option<uuid::Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of every field an approval installs; send it back on approve so
    /// the approval installs exactly what was reviewed.
    pub content_hash: String,
}

/// Expert prompt snippet — stored one row per snippet in the `prompt_snippets`
/// table (keyed `(tenant_id, snippet_key)`). Shape matches the markdown
/// frontmatter loader at `seed_loader::SnippetEntry`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct PromptSnippet {
    /// Stable key used in expert `prompt_snippets` arrays (e.g. `memory`, `session`).
    pub key: String,
    /// Human-readable label shown in the admin UI.
    pub label: String,
    /// Markdown content rendered into the agent prompt.
    pub content: String,
    /// True for built-in snippets that re-seed on startup; user-created snippets
    /// (and user-edited builtins) set this false so seeds don't overwrite them.
    #[serde(default)]
    pub is_builtin: bool,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
#[allow(dead_code)] // constructed by sqlx::query_as at runtime
pub struct ToolRuleSuggestionResponse {
    pub id: uuid::Uuid,
    pub expert_axis: String,
    /// Agent-minted stable rule identifier (e.g. `ASI06-01`), carried onto
    /// the rule an approval creates.
    pub proposed_rule_id: String,
    pub title: String,
    pub description: Option<String>,
    pub risk: String,
    pub phase: String,
    pub scope: String,
    /// AND-of-conditions the rule would match, so the UI renders the rule
    /// preview without a second query. Read as stored, so a list never fails
    /// over one row: the spec states the shape an agent writes.
    #[schema(value_type = Vec<streamscope_core::config::tool_rules::MatchCondition>)]
    pub match_conditions: sqlx::types::Json<serde_json::Value>,
    /// The rule's action, read as stored (see `match_conditions`).
    #[schema(value_type = streamscope_core::config::tool_rules::RuleAction)]
    pub action: sqlx::types::Json<serde_json::Value>,
    pub priority: i32,
    pub model_filter: Option<String>,
    pub app_filter: Option<String>,
    pub mcp_server_filter: Option<String>,
    pub rationale: String,
    pub status: String,
    #[schema(value_type = Option<Vec<String>>)]
    pub source_sessions: Option<sqlx::types::Json<Vec<String>>>,
    /// External security-framework entries the agent cited when proposing
    /// this rule (e.g. `["OWASP-LLM01", "CWE-78"]`). Populated only when the
    /// expert consumed the framework knowledge pack. Display-only.
    #[schema(value_type = Option<Vec<String>>)]
    pub framework_refs: Option<sqlx::types::Json<Vec<String>>>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub reviewed_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Hash of every field an approval installs; send it back on approve so
    /// the approval installs exactly what was reviewed.
    pub content_hash: String,
}

// ─── Expert response types ───

#[derive(Serialize, ToSchema)]
pub struct ExpertResponse {
    pub id: uuid::Uuid,
    pub axis: String,
    pub description: Option<String>,
    pub prompt: String,
    pub enabled: bool,
    pub is_builtin: bool,
    pub last_processed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub sessions_analyzed: i64,
    pub has_memory: bool,
    pub input_types: Vec<String>,
    pub output_types: Vec<String>,
    pub model_override: Option<String>,
    pub prompt_snippets: Vec<String>,
    pub color: Option<String>,
    /// Whether this expert pools into merged analysis calls with shape-compatible
    /// experts; `false` = always analyzed by its own solo call.
    pub merge_enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateExpertResponse {
    pub id: uuid::Uuid,
    pub axis: String,
}

#[derive(Serialize, ToSchema)]
pub struct ExpertMemoryResponse {
    pub memory: String,
}

#[derive(Serialize, ToSchema)]
pub struct AgentStatusResponse {
    pub enabled: bool,
    pub model: String,
    pub interval_secs: u64,
    pub last_cycle_at: Option<String>,
    pub pending_suggestions: i64,
    pub expert_count: i64,
}

/// One judge-model option: an alias, which is the value an expert profile's
/// `model` (or an expert's override) stores and the agent sends, with every
/// enabled route it resolves to whose model can answer the judge (not an image,
/// audio, video, embedding or rerank model). An alias appears once however many
/// routes carry it (an alias may load-balance across presets on one provider,
/// or be carried by several providers).
#[derive(Serialize, ToSchema)]
pub struct AgentModelEntry {
    pub alias: String,
    /// The distinct (server, upstream model) pairs behind the alias, never empty.
    pub targets: Vec<AgentModelTarget>,
    /// Whether the Agent workspace holds a live grant on a provider carrying
    /// the alias. `false` means the gateway refuses the agent's analysis
    /// calls on it until a provider is granted to the Agent workspace.
    pub granted_to_agent: bool,
}

/// One upstream model a judge-model alias resolves to, and the server serving it.
#[derive(Serialize, ToSchema)]
pub struct AgentModelTarget {
    pub upstream_model: String,
    pub server_name: String,
    pub provider: String,
}

#[derive(Serialize, ToSchema)]
pub struct AgentModelsResponse {
    /// `Some` once the tenant's agent key has been provisioned (it lives in the
    /// Agent workspace and reaches the providers granted to it). `None` before then.
    pub key_id: Option<uuid::Uuid>,
    /// One entry per alias with at least one such route, ordered by alias —
    /// the judge-model options for an expert profile's `model` (and
    /// per-expert overrides).
    pub models: Vec<AgentModelEntry>,
}

#[derive(Serialize, ToSchema)]
pub struct AlertCounts {
    pub major: i64,
    pub minor: i64,
}

#[derive(Serialize, ToSchema)]
pub struct SuggestionCounts {
    pub pending: i64,
    pub implemented: i64,
    pub rejected: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ExpertDashboardEntry {
    pub id: uuid::Uuid,
    pub axis: String,
    pub description: Option<String>,
    pub enabled: bool,
    pub sessions_analyzed: i64,
    pub last_processed_at: Option<chrono::DateTime<chrono::Utc>>,
    pub has_memory: bool,
    pub input_types: Vec<String>,
    pub output_types: Vec<String>,
    pub model_override: Option<String>,
    pub color: Option<String>,
    pub prompt_snippets: Option<Vec<String>>,
    pub alert_counts: AlertCounts,
    pub suggestion_counts: SuggestionCounts,
}

#[derive(Serialize, ToSchema)]
pub struct RecentSuggestion {
    pub id: uuid::Uuid,
    pub expert_axis: String,
    pub title: String,
    pub status: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct AgentMetrics {
    pub enabled: bool,
    pub model: String,
    pub interval_secs: u64,
    pub last_cycle_at: Option<String>,
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    /// What the agent's own calls cost over the window, and in which currency.
    /// `null` when the window straddles a change of the tenant's accounting
    /// currency.
    pub spend: Option<super::SpendTotal>,
    pub errors: i64,
}

#[derive(Serialize, ToSchema)]
pub struct ExpertDashboardResponse {
    pub total_alerts: AlertCounts,
    pub total_sessions_analyzed: i64,
    pub pending_suggestions: i64,
    pub pending_tool_rule_suggestions: i64,
    pub active_experts: usize,
    pub experts: Vec<ExpertDashboardEntry>,
    pub recent_suggestions: Vec<RecentSuggestion>,
    pub agent: AgentMetrics,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/transforms/programs",
    tag = "Transforms",
    request_body = CreateProgramRequest,
    responses(
        (status = 201, description = "Program created", body = CreateProgramResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Conflict — name already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_program(
    mut db: TenantConn,
    Json(req): Json<CreateProgramRequest>,
) -> Result<(StatusCode, Json<CreateProgramResponse>), ApiError> {
    // Validate phase
    if !VALID_PHASES.contains(&req.phase.as_str()) {
        return Err(ApiError::bad_request(format!("invalid phase '{}', must be one of: {}", req.phase, VALID_PHASES.join(", ")))
            .code(ApiErrorCode::TransformPhaseInvalid));
    }
    // Validate scope (phase-dependent)
    let valid_scopes = match req.phase.as_str() {
        "response" => VALID_RESPONSE_SCOPES,
        _ => VALID_REQUEST_SCOPES,
    };
    if !valid_scopes.contains(&req.scope.as_str()) {
        return Err(ApiError::bad_request(format!("invalid scope '{}' for phase '{}', must be one of: {}", req.scope, req.phase, valid_scopes.join(", ")))
            .code(ApiErrorCode::TransformScopeInvalid));
    }

    // Reject excessively large scripts before compilation
    let max_script_size = crate::settings::admin_settings().max_script_size;
    if req.source.len() > max_script_size {
        return Err(ApiError::bad_request(format!("script too large ({} bytes, max {max_script_size})", req.source.len()))
            .code(ApiErrorCode::TransformScriptTooLarge));
    }

    // Validate script compiles
    let engine = streamscope_core::scripting::ScriptEngine::new();
    if let Err(e) = engine.validate(&req.source) {
        return Err(ApiError::bad_request(format!("script compilation error: {e}"))
            .code(ApiErrorCode::TransformScriptCompileError));
    }

    // Normalize empty filter strings to NULL
    let model_filter = req.model_filter.as_deref().filter(|s| !s.is_empty());
    let app_filter = req.app_filter.as_deref().filter(|s| !s.is_empty());
    let trigger_regex = validate_trigger_regex(req.trigger_regex.as_deref())?;
    let match_mode = validate_match_mode(req.match_mode.as_deref(), trigger_regex.as_deref())?;

    // A program belongs to a profile (profile_id is NOT NULL). An explicit
    // profile must exist in this tenant; with none given the program lands on the
    // Default transform profile (the shared base).
    let tenant_uuid = db.tenant_uuid();
    let profile_id = match req.profile_id {
        Some(pid) => {
            super::profiles::ensure_profile_exists(
                db.conn(),
                pid,
                streamscope_core::config::ProfileKind::Transform,
            )
            .await?;
            pid
        }
        None => super::profiles::default_profile_id(
            db.conn(),
            tenant_uuid,
            streamscope_core::config::ProfileKind::Transform,
        )
        .await?
        .ok_or_else(|| ApiError::internal("no default transform profile"))?,
    };

    let row = sqlx::query_as::<_, (uuid::Uuid, chrono::DateTime<chrono::Utc>)>(
        "INSERT INTO transform_programs (name, description, source, phase, scope, priority, enabled, model_filter, app_filter, trigger_regex, match_mode, profile_id, tenant_id) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13) RETURNING id, created_at",
    )
    .bind(&req.name)
    .bind(&req.description)
    .bind(&req.source)
    .bind(&req.phase)
    .bind(&req.scope)
    .bind(req.priority)
    .bind(req.enabled)
    .bind(model_filter)
    .bind(app_filter)
    .bind(&trigger_regex)
    .bind(&match_mode)
    .bind(profile_id)
    .bind(tenant_uuid)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create program: {e}");
        if super::is_unique_violation(&e) {
            ApiError::conflict("program name already exists", ApiErrorCode::TransformNameTaken)
        } else {
            ApiError::internal("internal error")
        }
    })?;


    Ok((
        StatusCode::CREATED,
        Json(CreateProgramResponse {
            id: row.0,
            name: req.name.clone(),
            created_at: row.1,
        }),
    ))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ProgramListQuery {
    /// Maximum number of items to return. Default 50, capped at the platform max.
    #[serde(default)]
    pub limit: Option<i64>,
    /// Number of items to skip from the beginning. Default 0.
    #[serde(default)]
    pub offset: Option<i64>,
    /// Filter to one transform profile's own programs. Omit for all programs
    /// across every profile.
    #[serde(default)]
    pub profile_id: Option<uuid::Uuid>,
    /// When true, return only the **Default** profile's programs (the shared
    /// base). Ignored when `profile_id` is set.
    #[serde(default)]
    pub shared_only: Option<bool>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/transforms/programs",
    tag = "Transforms",
    params(ProgramListQuery),
    responses(
        (status = 200, description = "Paginated list of transform programs", body = TotalPage<ProgramResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_programs(
    mut db: TenantConn,
    Query(q): Query<ProgramListQuery>,
) -> Result<Json<TotalPage<ProgramResponse>>, ApiError> {
    let limit = q.limit.unwrap_or(50).clamp(1, 500);
    let offset = crate::routes::resolve_offset(q.offset);

    // Default-as-base: `profile_id=P` → P's own programs; `shared_only` → the
    // Default profile's programs (the shared base); neither → all programs.
    // profile_id wins over shared_only when both are set. $1 = profile filter
    // (NULL ⇒ no filter), shared by COUNT and the page.
    let tenant_uuid = db.tenant_uuid();
    let profile_filter: Option<uuid::Uuid> = if let Some(pid) = q.profile_id {
        Some(pid)
    } else if q.shared_only.unwrap_or(false) {
        super::profiles::default_profile_id(
            db.conn(),
            tenant_uuid,
            streamscope_core::config::ProfileKind::Transform,
        )
        .await?
    } else {
        None
    };

    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM transform_programs \
         WHERE ($1::uuid IS NULL OR profile_id = $1) AND NOT suppressed",
    )
    .bind(profile_filter)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("count programs: {e}");
        ApiError::internal("internal error")
    })?;

    let rows: Vec<ProgramResponse> = sqlx::query_as::<_, ProgramResponse>(
        "SELECT id, name, description, source, phase, scope, priority, version, enabled, created_at, updated_at, model_filter, app_filter, trigger_regex, match_mode, profile_id \
         FROM transform_programs \
         WHERE ($1::uuid IS NULL OR profile_id = $1) AND NOT suppressed \
         ORDER BY priority, name LIMIT $2 OFFSET $3",
    )
    .bind(profile_filter)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list programs: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/transforms/programs/{id}",
    tag = "Transforms",
    params(("id" = Uuid, Path, description = "Program ID")),
    responses(
        (status = 200, description = "Transform program details", body = ProgramResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Program not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_program(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ProgramResponse>, ApiError> {
    let row: Option<ProgramResponse> = sqlx::query_as::<_, ProgramResponse>(
        "SELECT id, name, description, source, phase, scope, priority, version, enabled, created_at, updated_at, model_filter, app_filter, trigger_regex, match_mode, profile_id \
         FROM transform_programs WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get program: {e}");
        ApiError::internal("internal error")
    })?;

    match row {
        Some(program) => Ok(Json(program)),
        None => Err(ApiError::not_found("program not found", ApiErrorCode::TransformNotFound)),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateProgramRequest {
    pub name: Option<String>,
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub source: Option<String>,
    pub phase: Option<String>,
    pub scope: Option<String>,
    pub priority: Option<i32>,
    pub enabled: Option<bool>,
    #[serde(default, deserialize_with = "crate::routes::double_option::null_as_blank")]
    pub model_filter: Option<String>,
    #[serde(default, deserialize_with = "crate::routes::double_option::null_as_blank")]
    pub app_filter: Option<String>,
    #[serde(default, deserialize_with = "crate::routes::double_option::null_as_blank")]
    pub trigger_regex: Option<String>,
    #[serde(default, deserialize_with = "crate::routes::double_option::null_as_blank")]
    pub match_mode: Option<String>,
    /// Transform profile scope (tri-state PATCH): absent → unchanged; `null` →
    /// **shared** (the Default transform profile, the base every profile reads);
    /// a profile id → **specific** to that transform profile.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<uuid::Uuid>)]
    pub profile_id: Option<Option<uuid::Uuid>>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/transforms/programs/{id}",
    tag = "Transforms",
    params(("id" = Uuid, Path, description = "Program ID")),
    request_body = UpdateProgramRequest,
    responses(
        (status = 200, description = "Program updated", body = StatusMessageResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Program not found", body = ApiErrorResponse),
        (status = 409, description = "Another program has that name", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_program(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<UpdateProgramRequest>,
) -> Result<Json<StatusMessageResponse>, ApiError> {
    // Validate phase if provided
    if let Some(phase) = &req.phase
        && !VALID_PHASES.contains(&phase.as_str()) {
            return Err(ApiError::bad_request(format!("invalid phase '{}', must be one of: {}", phase, VALID_PHASES.join(", ")))
                .code(ApiErrorCode::TransformPhaseInvalid));
        }
    // Validate scope if provided (phase-dependent — use provided phase, or fetch existing from DB)
    if let Some(scope) = &req.scope {
        let phase_str = if let Some(p) = &req.phase {
            p.clone()
        } else {
            // Fetch existing phase from DB for validation
            let existing: Option<(String,)> = sqlx::query_as(
                "SELECT phase FROM transform_programs WHERE id = $1 AND NOT suppressed",
            )
            .bind(id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("fetch program phase: {e}");
                ApiError::internal("internal error")
            })?;
            existing.map(|(p,)| p).unwrap_or_else(|| "request".to_string())
        };
        let valid_scopes = match phase_str.as_str() {
            "response" => VALID_RESPONSE_SCOPES,
            _ => VALID_REQUEST_SCOPES,
        };
        if !valid_scopes.contains(&scope.as_str()) {
            return Err(ApiError::bad_request(format!("invalid scope '{}' for phase '{}', must be one of: {}", scope, phase_str, valid_scopes.join(", ")))
                .code(ApiErrorCode::TransformScopeInvalid));
        }
    }

    // Validate new source if provided
    if let Some(source) = &req.source {
        let max_script_size = crate::settings::admin_settings().max_script_size;
        if source.len() > max_script_size {
            return Err(ApiError::bad_request(format!("script too large ({} bytes, max {max_script_size})", source.len()))
                .code(ApiErrorCode::TransformScriptTooLarge));
        }
        let engine = streamscope_core::scripting::ScriptEngine::new();
        if let Err(e) = engine.validate(source) {
            return Err(ApiError::bad_request(format!("script compilation error: {e}"))
                .code(ApiErrorCode::TransformScriptCompileError));
        }
    }


    // Normalised exactly as on create (trimmed, compiled); a blank trigger
    // clears it, through the empty-string sentinel the SQL below reads. An
    // omitted field leaves it unchanged.
    let trigger_bind: Option<String> = match req.trigger_regex.as_deref() {
        None => None,
        Some(raw) => Some(validate_trigger_regex(Some(raw))?.unwrap_or_default()),
    };

    // Resolve match_mode (3-way): omitted ⇒ unchanged; "span" ⇒ requires a
    // non-blank `trigger_regex` in this request and stores "span"; anything else
    // clears to NULL (full). The empty-string bind is the SQL "set NULL" sentinel.
    let match_mode_bind: Option<String> = match req.match_mode.as_deref().map(str::trim) {
        None => None,
        Some("span") => {
            if req
                .trigger_regex
                .as_deref()
                .map(str::trim)
                .is_some_and(|t| !t.is_empty())
            {
                Some("span".to_string())
            } else {
                return Err(ApiError::bad_request(
                    "span match_mode requires a non-blank trigger_regex",
                )
                .code(ApiErrorCode::TransformSpanModeNeedsTrigger));
            }
        }
        Some(_) => Some(String::new()),
    };

    // Resolve the optional profile move (tri-state via double-option): absent ⇒
    // unchanged; `null` ⇒ shared, i.e. the Default profile (`profile_id` is NOT
    // NULL); a profile id ⇒ that profile (validated in-tenant).
    let (profile_present, profile_target): (bool, Option<uuid::Uuid>) = match req.profile_id {
        None => (false, None),
        Some(None) => {
            let tenant_uuid = db.tenant_uuid();
            let default_id = super::profiles::default_profile_id(
                db.conn(),
                tenant_uuid,
                streamscope_core::config::ProfileKind::Transform,
            )
            .await?
            .ok_or_else(|| ApiError::internal("no default transform profile"))?;
            (true, Some(default_id))
        }
        Some(Some(pid)) => {
            super::profiles::ensure_profile_exists(
                db.conn(),
                pid,
                streamscope_core::config::ProfileKind::Transform,
            )
            .await?;
            (true, Some(pid))
        }
    };

    let result = sqlx::query(
        "UPDATE transform_programs SET \
         name = COALESCE($2, name), \
         description = CASE WHEN $15 THEN $3 ELSE description END, \
         source = COALESCE($4, source), \
         phase = COALESCE($5, phase), \
         scope = COALESCE($6, scope), \
         priority = COALESCE($7, priority), \
         enabled = COALESCE($8, enabled), \
         model_filter = CASE WHEN $9 = '' THEN NULL WHEN $9 IS NOT NULL THEN $9 ELSE model_filter END, \
         app_filter = CASE WHEN $10 = '' THEN NULL WHEN $10 IS NOT NULL THEN $10 ELSE app_filter END, \
         trigger_regex = CASE WHEN $11 = '' THEN NULL WHEN $11 IS NOT NULL THEN $11 ELSE trigger_regex END, \
         match_mode = CASE WHEN $12 = '' THEN NULL WHEN $12 IS NOT NULL THEN $12 ELSE match_mode END, \
         profile_id = CASE WHEN $13 THEN $14 ELSE profile_id END, \
         version = version + CASE WHEN $4 IS NOT NULL THEN 1 ELSE 0 END, \
         is_builtin = false, \
         updated_at = now() \
         WHERE id = $1 AND NOT suppressed \
         AND NOT ( \
           ($11::text IS NOT NULL OR $12::text IS NOT NULL) \
           AND (CASE WHEN $12 = '' THEN NULL WHEN $12 IS NOT NULL THEN $12 ELSE match_mode END) IS NOT DISTINCT FROM 'span' \
           AND (CASE WHEN $11 = '' THEN NULL WHEN $11 IS NOT NULL THEN $11 ELSE trigger_regex END) IS NULL \
         )",
    )
    .bind(id)
    .bind(&req.name)
    .bind(req.description.as_ref().and_then(|d| d.as_deref()))
    .bind(&req.source)
    .bind(&req.phase)
    .bind(&req.scope)
    .bind(req.priority)
    .bind(req.enabled)
    .bind(&req.model_filter)
    .bind(&req.app_filter)
    .bind(&trigger_bind)
    .bind(&match_mode_bind)
    .bind(profile_present)
    .bind(profile_target)
    .bind(req.description.is_some()) // $15
    .execute(db.conn())
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            return ApiError::conflict(
                "program name already exists (a deleted built-in keeps its name)",
                ApiErrorCode::TransformNameTaken,
            );
        }
        tracing::error!("update program: {e}");
        ApiError::internal("internal error")
    })?;

    if result.rows_affected() == 0 {
        // The UPDATE refuses a write that names the trigger or the mode and would
        // leave a span program without its trigger — checked against the row it
        // locks, so a concurrent edit cannot slip one past (the table's
        // `transform_programs_span_has_trigger` CHECK holds the same rule for
        // every writer). Tell a refusal apart from a missing program.
        let exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM transform_programs WHERE id = $1 AND NOT suppressed)",
        )
        .bind(id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("update program existence: {e}");
            ApiError::internal("internal error")
        })?;
        return Err(if exists {
            ApiError::bad_request("a span program needs its trigger_regex; switch match_mode off span to clear it")
                .code(ApiErrorCode::TransformSpanModeNeedsTrigger)
        } else {
            ApiError::not_found("program not found", ApiErrorCode::TransformNotFound)
        });
    }


    Ok(Json(StatusMessageResponse {
        status: "updated".into(),
        message: None,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/transforms/programs/{id}",
    tag = "Transforms",
    params(("id" = Uuid, Path, description = "Program ID")),
    responses(
        (status = 200, description = "Program deleted", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Program not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_program(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // A row that came from the seed — edited or not — is soft-deleted
    // (suppressed) so seed-sync won't resurrect it on restart; a user-created
    // program is hard-deleted. The row decides, in the one statement that acts
    // on it; a row already deleted answers 404.
    let acted: i64 = sqlx::query_scalar(
        "WITH hidden AS ( \
           UPDATE transform_programs SET suppressed = true, updated_at = now() \
           WHERE id = $1 AND NOT suppressed AND seeded RETURNING 1), \
         removed AS ( \
           DELETE FROM transform_programs WHERE id = $1 AND NOT suppressed AND NOT seeded RETURNING 1) \
         SELECT (SELECT count(*) FROM hidden) + (SELECT count(*) FROM removed)",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete program: {e}");
        ApiError::internal("internal error")
    })?;
    if acted == 0 {
        return Err(ApiError::not_found("program not found", ApiErrorCode::TransformNotFound));
    }

    Ok(Json(ActionResponse::ok()))
}

#[derive(Deserialize, ToSchema)]
pub struct ValidateRequest {
    pub source: String,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/transforms/programs/actions/validate",
    tag = "Transforms",
    request_body = ValidateRequest,
    responses(
        (status = 200, description = "Validation result", body = ValidateProgramResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn validate_program(
    Json(req): Json<ValidateRequest>,
) -> Result<Json<ValidateProgramResponse>, ApiError> {
    let engine = streamscope_core::scripting::ScriptEngine::new();
    match engine.validate(&req.source) {
        Ok(()) => Ok(Json(ValidateProgramResponse {
            valid: true,
            error: None,
        })),
        Err(e) => Ok(Json(ValidateProgramResponse {
            valid: false,
            error: Some(e),
        })),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct TestProgramRequest {
    pub source: String,
    /// The context object the program runs against; free-form, read by the script as written.
    #[schema(value_type = Object)]
    pub context: serde_json::Value,
    /// Execution mode for the preview. `"span"` runs the script once per
    /// `trigger_regex` match over the sample context's text; anything else runs
    /// the full-context script once.
    #[serde(default)]
    pub match_mode: Option<String>,
    /// The span finder, required when `match_mode == "span"`.
    #[serde(default)]
    pub trigger_regex: Option<String>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/transforms/programs/actions/test",
    tag = "Transforms",
    request_body = TestProgramRequest,
    responses(
        (status = 200, description = "Test execution result", body = TestProgramResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_program(
    Json(req): Json<TestProgramRequest>,
) -> Result<Json<TestProgramResponse>, ApiError> {
    let engine = streamscope_core::scripting::ScriptEngine::new();

    // Parse context from JSON
    let ctx = parse_test_context(&req.context).map_err(|e| {
        ApiError::bad_request(format!("invalid context: {e}"))
            .code(ApiErrorCode::TransformTestContextInvalid)
    })?;

    // Span mode previews the per-match splice (needs the trigger as the finder);
    // any other mode runs the full-context script once.
    let span_trigger = req
        .trigger_regex
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty());
    let outcome = if req.match_mode.as_deref() == Some("span") {
        match span_trigger {
            Some(t) => engine.test_execute_span(&req.source, t, ctx),
            None => Err("span match_mode requires a non-blank trigger_regex".to_string()),
        }
    } else {
        engine.test_execute(&req.source, ctx)
    };

    match outcome {
        Ok(result) => Ok(Json(TestProgramResponse {
            success: true,
            result: Some(context_to_json(&result)),
            error: None,
        })),
        Err(e) => Ok(Json(TestProgramResponse {
            success: false,
            result: None,
            error: Some(e),
        })),
    }
}

fn parse_test_context(
    val: &serde_json::Value,
) -> Result<streamscope_core::scripting::context::RequestContext, String> {
    use streamscope_core::scripting::context::{RhaiMessage, RhaiTool, RequestContext};

    let obj = val.as_object().ok_or("expected JSON object")?;

    let system_prompt = obj
        .get("system_prompt")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let messages = obj
        .get("messages")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|m| {
                    Some(RhaiMessage {
                        role: m.get("role")?.as_str()?.to_string(),
                        content: m.get("content")?.as_str()?.to_string(),
                        tool_call_id: m.get("tool_call_id").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        tool_calls: vec![],
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let tools = obj
        .get("tools")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    Some(RhaiTool {
                        name: t.get("name")?.as_str()?.to_string(),
                        description: t.get("description").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        parameters_json: t.get("parameters_json").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        is_gateway_substituted: t
                            .get("is_gateway_substituted")
                            .and_then(|v| v.as_bool())
                            .unwrap_or(false),
                        kind: t.get("kind").and_then(|v| v.as_str()).map(|s| s.to_string()),
                        config_json: t.get("config_json").and_then(|v| v.as_str()).map(|s| s.to_string()),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let metadata = obj
        .get("metadata")
        .and_then(|v| v.as_object())
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default();

    Ok(RequestContext {
        system_prompt,
        messages,
        tools,
        model: obj
            .get("model")
            .and_then(|v| v.as_str())
            .unwrap_or("test-model")
            .to_string(),
        user_id: obj
            .get("user_id")
            .and_then(|v| v.as_str())
            .unwrap_or("test-user")
            .to_string(),
        app_id: obj
            .get("app_id")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string()),
        api_version: obj
            .get("api_version")
            .and_then(|v| v.as_str())
            .unwrap_or("chat_completions")
            .to_string(),
        metadata,
        labels: vec![],
    })
}

fn context_to_json(
    ctx: &streamscope_core::scripting::context::RequestContext,
) -> serde_json::Value {
    serde_json::json!({
        "system_prompt": ctx.system_prompt,
        "messages": ctx.messages.iter().map(|m| serde_json::json!({
            "role": m.role,
            "content": m.content,
            "tool_call_id": m.tool_call_id,
        })).collect::<Vec<_>>(),
        "tools": ctx.tools.iter().map(|t| serde_json::json!({
            "name": t.name,
            "description": t.description,
            "parameters_json": t.parameters_json,
        })).collect::<Vec<_>>(),
        "model": ctx.model,
        "user_id": ctx.user_id,
        "app_id": ctx.app_id,
        "api_version": ctx.api_version,
        "metadata": ctx.metadata,
        "labels": ctx.labels,
    })
}

// ─── Suggestions ───

#[utoipa::path(
    get,
    path = "/api/v1/admin/transforms/suggestions",
    tag = "Transforms",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of transform suggestions", body = OffsetPage<SuggestionResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_suggestions(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<SuggestionResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let min_seen = crate::settings::admin_settings().agent_suggestion_min_seen;
    // Pending entries surface only after the multi-cycle gate
    // (`seen_count >= min_seen`); approved/rejected history is always
    // visible so reviewers can browse decisions and undo as needed.
    let rows: Vec<SuggestionResponse> = sqlx::query_as::<_, SuggestionResponse>(sqlx::AssertSqlSafe(format!(
        "SELECT id, expert_axis, title, rationale, proposed_source, proposed_phase, proposed_scope, proposed_model_filter, proposed_app_filter, proposed_trigger_regex, proposed_match_mode, status, program_id, created_at, reviewed_at, \
                {PROGRAM_SUGGESTION_HASH_SQL} AS content_hash \
         FROM program_suggestions \
         WHERE status != 'pending' OR seen_count >= $3 \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )))
    .bind(limit + 1)
    .bind(offset)
    .bind(min_seen)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list suggestions: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[derive(Deserialize, ToSchema)]
pub struct ApproveToolRuleSuggestionRequest {
    /// `content_hash` of the suggestion as the reviewer saw it.
    pub content_hash: String,
    /// The tool profile the promoted rule lands in. Omit (or `null`) to use
    /// the tenant default profile.
    #[serde(default)]
    pub profile_id: Option<uuid::Uuid>,
}

/// The content a reviewer approves: the suggestion's `content_hash` as the
/// list showed it. Required on every approve body — an agent re-proposal
/// rewrites a pending row in place, so the hash is what ties the installed
/// content to the content that was reviewed.
#[derive(Deserialize, ToSchema)]
pub struct ApproveSuggestionRequest {
    /// `content_hash` of the suggestion as the reviewer saw it.
    pub content_hash: String,
}

/// The reviewed version a claim must still match: the table's content-hash
/// SQL expression and the hash the reviewer approved.
pub(super) struct ReviewedContent<'a> {
    pub hash_sql: &'static str,
    pub content_hash: &'a str,
}

/// The columns an approval installs from a pending suggestion — what the claim
/// returns and what its `content_hash` covers, one list for both.
macro_rules! program_suggestion_columns {
    () => {
        "title, proposed_source, proposed_phase, proposed_scope, proposed_model_filter, proposed_app_filter, proposed_trigger_regex, proposed_match_mode"
    };
}
pub(super) const PROGRAM_SUGGESTION_COLUMNS: &str = program_suggestion_columns!();
/// `content_hash` of a suggestion row, over exactly [`PROGRAM_SUGGESTION_COLUMNS`].
pub(super) const PROGRAM_SUGGESTION_HASH_SQL: &str =
    concat!("encode(sha256(convert_to(jsonb_build_array(", program_suggestion_columns!(), ")::text, 'UTF8')), 'hex')");

/// The columns an approval installs from a pending suggestion — what the claim
/// returns and what its `content_hash` covers, one list for both.
macro_rules! tool_rule_suggestion_columns {
    () => {
        "proposed_rule_id, title, description, risk, phase, scope, match_conditions, action, priority, model_filter, app_filter, mcp_server_filter, framework_refs"
    };
}
pub(super) const TOOL_RULE_SUGGESTION_COLUMNS: &str = tool_rule_suggestion_columns!();
/// `content_hash` of a suggestion row, over exactly [`TOOL_RULE_SUGGESTION_COLUMNS`].
pub(super) const TOOL_RULE_SUGGESTION_HASH_SQL: &str =
    concat!("encode(sha256(convert_to(jsonb_build_array(", tool_rule_suggestion_columns!(), ")::text, 'UTF8')), 'hex')");

/// Claim a pending suggestion in `table` for `status` and return its proposed
/// content, read as `columns`. The claim IS the read: an agent cycle that
/// re-proposes the suggestion rewrites the pending row in place, so content read
/// before the claim could differ from the row marked approved — and with
/// `reviewed`, a row whose content no longer hashes to what the reviewer saw is
/// not claimed (409 `SuggestionChanged`). Must run inside the transaction that
/// installs the content — its row lock also serialises two concurrent
/// approvals, the second answering 404. A failure after the claim rolls the
/// transaction back and leaves the suggestion pending.
pub(super) async fn claim_pending_suggestion<T>(
    conn: &mut Scoped,
    table: &'static str,
    id: uuid::Uuid,
    status: &'static str,
    columns: &'static str,
    reviewed: Option<ReviewedContent<'_>>,
) -> Result<T, ApiError>
where
    T: Send + Unpin + for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow>,
{
    let mut sql = format!(
        "UPDATE {table} SET status = $2, reviewed_at = now() \
         WHERE id = $1 AND status = 'pending'"
    );
    if let Some(r) = &reviewed {
        sql.push_str(" AND ");
        sql.push_str(r.hash_sql);
        sql.push_str(" = $3");
    }
    sql.push_str(" RETURNING ");
    sql.push_str(columns);
    let mut q = sqlx::query_as::<_, T>(sqlx::AssertSqlSafe(sql)).bind(id).bind(status);
    if let Some(r) = &reviewed {
        q = q.bind(r.content_hash);
    }
    let claimed = q.fetch_optional(&mut *conn).await.map_err(|e| {
        tracing::error!("claim {table} {id} {status}: {e}");
        ApiError::internal("internal error")
    })?;
    if let Some(row) = claimed {
        return Ok(row);
    }
    // Nothing claimed: still pending means the content moved under the
    // reviewer; anything else is gone or already decided.
    if reviewed.is_some() {
        let still_pending = sqlx::query_scalar::<_, bool>(sqlx::AssertSqlSafe(format!(
            "SELECT EXISTS (SELECT 1 FROM {table} WHERE id = $1 AND status = 'pending')"
        )))
        .bind(id)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("recheck {table} {id}: {e}");
            ApiError::internal("internal error")
        })?;
        if still_pending {
            return Err(ApiError::conflict(
                "the suggestion changed since it was reviewed — reload it and review again",
                ApiErrorCode::SuggestionChanged,
            ));
        }
    }
    Err(ApiError::not_found("suggestion not found or not pending", ApiErrorCode::SuggestionNotFound))
}

/// Reject a pending suggestion in `table`; the row is kept as history.
pub(super) async fn reject_pending_suggestion(
    db: &mut TenantConn,
    table: &'static str,
    id: uuid::Uuid,
) -> Result<Json<ActionResponse>, ApiError> {
    claim_pending_suggestion::<(uuid::Uuid,)>(db.conn(), table, id, "rejected", "id", None).await?;
    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/transforms/suggestions/{id}/actions/approve",
    tag = "Transforms",
    params(("id" = Uuid, Path, description = "Suggestion ID")),
    request_body = ApproveSuggestionRequest,
    responses(
        (status = 200, description = "Suggestion approved; `impact.program_id` names the program it created", body = ActionResponse),
        (status = 400, description = "The proposed program is invalid", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Suggestion not found or not pending", body = ApiErrorResponse),
        (status = 409, description = "The suggestion changed since it was reviewed (`suggestion_changed`), or a program with its title already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_suggestion(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<ApproveSuggestionRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Claim and read the suggestion in the transaction that creates the
    // program, so the program is built from exactly the row marked implemented.
    let tenant_uuid = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin suggestion approve tx: {e}");
        ApiError::internal("internal error")
    })?;
    let (title, source, phase, scope, model_filter, app_filter, trigger_raw, match_mode_raw) =
        claim_pending_suggestion::<(String, String, String, String, Option<String>, Option<String>, Option<String>, Option<String>)>(
            &mut tx,
            "program_suggestions",
            id,
            "implemented",
            PROGRAM_SUGGESTION_COLUMNS,
            Some(ReviewedContent { hash_sql: PROGRAM_SUGGESTION_HASH_SQL, content_hash: &req.content_hash }),
        )
        .await?;

    // Normalise the span/trigger fields (rejects a bad trigger or span
    // without a trigger). `match_mode` selects the script contract.
    let trigger_regex = validate_trigger_regex(trigger_raw.as_deref())?;
    let match_mode = validate_match_mode(match_mode_raw.as_deref(), trigger_regex.as_deref())?;

    // Validate the proposed source compiles. Span sources use
    // `fn transform(m)`; the compile check is contract-agnostic.
    let engine = streamscope_core::scripting::ScriptEngine::new();
    if let Err(e) = engine.validate(&source) {
        return Err(ApiError::bad_request(format!("proposed script does not compile: {e}"))
            .code(ApiErrorCode::TransformScriptCompileError));
    }

    // Validate phase/scope combination
    let valid_scopes = match phase.as_str() {
        "response" => VALID_RESPONSE_SCOPES,
        _ => VALID_REQUEST_SCOPES,
    };
    if !valid_scopes.contains(&scope.as_str()) {
        return Err(ApiError::bad_request(format!("invalid scope '{}' for phase '{}', must be one of: {}", scope, phase, valid_scopes.join(", ")))
            .code(ApiErrorCode::TransformScopeInvalid));
    }

    // Create the program on the Default transform profile (the shared base) —
    // profile_id is NOT NULL.
    let default_transform_id = super::profiles::default_profile_id(
        &mut tx,
        tenant_uuid,
        streamscope_core::config::ProfileKind::Transform,
    )
    .await?
    .ok_or_else(|| ApiError::internal("no default transform profile"))?;
    let program_id = sqlx::query_scalar::<_, uuid::Uuid>(
        "INSERT INTO transform_programs (name, description, source, phase, scope, priority, enabled, model_filter, app_filter, trigger_regex, match_mode, tenant_id, profile_id) \
         VALUES ($1, $2, $3, $4, $5, 100, true, $6, $7, $8, $9, $10, $11) RETURNING id",
    )
    .bind(&title)
    .bind(format!("Auto-created from suggestion {id}"))
    .bind(&source)
    .bind(&phase)
    .bind(&scope)
    .bind(&model_filter)
    .bind(&app_filter)
    .bind(&trigger_regex)
    .bind(&match_mode)
    .bind(tenant_uuid)
    .bind(default_transform_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if super::is_unique_violation(&e) {
            return ApiError::conflict(
                "a program with this suggestion's title already exists (a deleted built-in keeps its name) — \
                 rename that program, or reject the suggestion",
                ApiErrorCode::TransformNameTaken,
            );
        }
        tracing::error!("create program from suggestion: {e}");
        ApiError::internal("failed to create program")
    })?;
    sqlx::query("UPDATE program_suggestions SET program_id = $2 WHERE id = $1")
        .bind(id)
        .bind(program_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("link suggestion to program: {e}");
            ApiError::internal("internal error")
        })?;
    tx.commit().await.map_err(|e| {
        tracing::error!("commit suggestion approve tx: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(ActionResponse::ok().with_impact(super::ActionImpact { program_id: Some(program_id), ..Default::default() })))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/transforms/suggestions/{id}/actions/reject",
    tag = "Transforms",
    params(("id" = Uuid, Path, description = "Suggestion ID")),
    responses(
        (status = 200, description = "Suggestion rejected", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Suggestion not found or not pending", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_suggestion(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    reject_pending_suggestion(&mut db, "program_suggestions", id).await
}

// ─── Tool Rule Suggestions ───

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/tool-rule-suggestions",
    tag = "Experts",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of tool rule suggestions", body = OffsetPage<ToolRuleSuggestionResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tool_rule_suggestions(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<ToolRuleSuggestionResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let min_seen = crate::settings::admin_settings().agent_suggestion_min_seen;
    let rows: Vec<ToolRuleSuggestionResponse> = sqlx::query_as::<_, ToolRuleSuggestionResponse>(sqlx::AssertSqlSafe(format!(
        "SELECT id, expert_axis, proposed_rule_id, title, description, risk, \
                phase, scope, match_conditions, action, priority, model_filter, \
                app_filter, mcp_server_filter, rationale, status, source_sessions, \
                framework_refs, created_at, reviewed_at, \
                {TOOL_RULE_SUGGESTION_HASH_SQL} AS content_hash \
         FROM tool_rule_suggestions \
         WHERE status != 'pending' OR seen_count >= $3 \
         ORDER BY created_at DESC LIMIT $1 OFFSET $2",
    )))
    .bind(limit + 1)
    .bind(offset)
    .bind(min_seen)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list tool rule suggestions: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/tool-rule-suggestions/{id}/actions/approve",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Tool rule suggestion ID")),
    request_body = ApproveToolRuleSuggestionRequest,
    responses(
        (status = 200, description = "Suggestion approved; the rule is active", body = ActionResponse),
        (status = 400, description = "The proposed rule is invalid", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Suggestion not found or not pending", body = ApiErrorResponse),
        (status = 409, description = "The suggestion changed since it was reviewed (`suggestion_changed`), or a rule with the proposed id already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn approve_tool_rule_suggestion(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<ApproveToolRuleSuggestionRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Claim and read the suggestion in the unified rule shape, in the
    // transaction that inserts the rule — the rule is built from exactly the row
    // marked approved. Phase/scope/match and the tagged action JSONB are stored
    // verbatim from the agent proposal. proposed_rule_id propagates onto the
    // promoted rule so the blocked-tool banner has a stable code; framework_refs
    // carries the expert's citations forward to the active rule.
    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin tool_rules tx: {e}");
        ApiError::internal("internal error")
    })?;
    let (
        proposed_rule_id,
        title,
        description,
        risk,
        phase_str,
        scope_str,
        match_json,
        action_json,
        priority,
        model_filter,
        app_filter,
        mcp_server_filter,
        framework_refs,
    ) = claim_pending_suggestion::<(
        String,                                            // proposed_rule_id
        String,                                            // title
        Option<String>,                                    // description
        String,                                            // risk
        String,                                            // phase
        String,                                            // scope
        sqlx::types::Json<serde_json::Value>,              // match_conditions
        sqlx::types::Json<serde_json::Value>,              // action
        i32,                                               // priority
        Option<String>,                                    // model_filter
        Option<String>,                                    // app_filter
        Option<String>,                                    // mcp_server_filter
        Option<sqlx::types::Json<Vec<String>>>,            // framework_refs
    )>(
        &mut tx,
        "tool_rule_suggestions",
        id,
        "approved",
        TOOL_RULE_SUGGESTION_COLUMNS,
        Some(ReviewedContent { hash_sql: TOOL_RULE_SUGGESTION_HASH_SQL, content_hash: &req.content_hash }),
    )
    .await?;

    // Reconstruct the full Rule, validate via the unified validator, and
    // serialize back to JSON for storage in tool_rules.
    use streamscope_core::config::tool_rules;
    let phase: tool_rules::Phase = serde_json::from_value(serde_json::json!(phase_str))
        .map_err(|_| {
            ApiError::bad_request(format!("suggestion has invalid phase: {phase_str}"))
                .code(ApiErrorCode::SuggestionRuleInvalid)
        })?;
    let scope: tool_rules::Scope = serde_json::from_value(serde_json::json!(scope_str))
        .map_err(|_| {
            ApiError::bad_request(format!("suggestion has invalid scope: {scope_str}"))
                .code(ApiErrorCode::SuggestionRuleInvalid)
        })?;
    let conditions: Vec<tool_rules::MatchCondition> =
        serde_json::from_value(match_json.0.clone()).map_err(|e| {
            ApiError::bad_request(format!("suggestion has invalid match[]: {e}"))
                .code(ApiErrorCode::SuggestionRuleInvalid)
        })?;
    let action: tool_rules::RuleAction =
        serde_json::from_value(action_json.0.clone()).map_err(|e| {
            ApiError::bad_request(format!("suggestion has invalid action: {e}"))
                .code(ApiErrorCode::SuggestionRuleInvalid)
        })?;

    // The landing scope: operator-chosen profile (validated in-tenant), or the
    // Default tool profile (the shared base) when none is given — a rule always
    // belongs to a profile (profile_id is NOT NULL).
    let target_profile_id: Option<uuid::Uuid> = match req.profile_id {
        Some(pid) => {
            super::profiles::ensure_profile_exists(&mut tx, pid, streamscope_core::config::ProfileKind::Tools).await?;
            Some(pid)
        }
        None => super::profiles::default_profile_id(
            &mut tx,
            tenant_id,
            streamscope_core::config::ProfileKind::Tools,
        )
        .await?,
    };

    let rule = tool_rules::Rule {
        id: proposed_rule_id,
        title: Some(title),
        description,
        risk,
        phase,
        scope,
        conditions,
        action,
        priority,
        model_filter,
        app_filter,
        mcp_server_filter,
        a2a_agent_filter: None,
        enabled: true,
        framework_refs: framework_refs
            .as_deref()
            .cloned()
            .unwrap_or_default(),
        // Approved rules become custom (user-owned) — sync won't overwrite.
        is_builtin: false,
        // Shared (None) or a specific profile, per the operator's choice.
        profile_id: target_profile_id,
        // Approvals never fork — that's the per-profile "Customize here" path.
        forked_from: None,
    };
    tool_rules::validate(&rule).map_err(|_| {
        ApiError::bad_request("suggestion failed validation against rule schema")
            .code(ApiErrorCode::SuggestionRuleInvalid)
    })?;

    // Per-row insert — no whole-collection rewrite — committed with the claim.
    // A live `rule_id` collision (most likely an existing builtin
    // re-suggestion) → 409 so the operator resolves it manually; the
    // transaction rolls back and the suggestion stays pending.
    if super::tool_rules::add_rule(&mut tx, tenant_id, &rule)
        .await?
        .is_none()
    {
        return Err(ApiError::conflict(format!(
            "rule id '{}' already exists in tool_rules — reject this suggestion \
             or delete the existing rule first",
            rule.id
        ), ApiErrorCode::ToolRiskRuleIdCollision));
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("commit tool_rules tx: {e}");
        ApiError::internal("failed to update config")
    })?;


    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/tool-rule-suggestions/{id}/actions/reject",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Tool rule suggestion ID")),
    responses(
        (status = 200, description = "Suggestion rejected", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Suggestion not found or not pending", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reject_tool_rule_suggestion(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    reject_pending_suggestion(&mut db, "tool_rule_suggestions", id).await
}

// ─── Prompt Snippets ───

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/prompt-snippets",
    tag = "Experts",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of prompt snippets", body = TotalPage<PromptSnippet>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_prompt_snippets(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<PromptSnippet>>, ApiError> {
    let all: Vec<PromptSnippet> = sqlx::query_as::<_, (String, String, String, bool)>(
        "SELECT snippet_key, label, content, is_builtin FROM prompt_snippets \
         WHERE NOT suppressed ORDER BY snippet_key",
    )
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list prompt snippets: {e}");
        ApiError::internal("internal error")
    })?
    .into_iter()
    .map(|(key, label, content, is_builtin)| PromptSnippet {
        key,
        label,
        content,
        is_builtin,
    })
    .collect();
    let total = all.len() as i64;
    let (limit, offset) = page.resolve();
    let start = offset.max(0) as usize;
    let end = (start + limit as usize).min(all.len());
    let items = if start < all.len() {
        all[start..end].to_vec()
    } else {
        Vec::new()
    };

    Ok(Json(TotalPage::new(items, limit, offset, total)))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateSnippetRequest {
    pub content: String,
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/experts/prompt-snippets/{key}",
    tag = "Experts",
    params(("key" = String, Path, description = "Snippet key")),
    request_body = UpdateSnippetRequest,
    responses(
        (status = 200, description = "Snippet updated", body = StatusMessageResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Snippet not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_prompt_snippet(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(key): Path<String>,
    Json(req): Json<UpdateSnippetRequest>,
) -> Result<Json<StatusMessageResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Single-statement content update of this snippet's row (no blob, no lock).
    // The `FROM` subquery captures the pre-update content (same statement snapshot)
    // for the audit change_diff. 404 when the key doesn't name a live snippet.
    // A content change makes the row the admin's (`is_builtin = false`), so the
    // seed reconcile never overwrites it; `restore_prompt_snippet` hands it back.
    let updated: Option<(String,)> = sqlx::query_as(
        "UPDATE prompt_snippets AS s SET content = $3, \
            is_builtin = s.is_builtin AND s.content IS NOT DISTINCT FROM $3, updated_at = now() \
         FROM (SELECT content FROM prompt_snippets \
               WHERE tenant_id = $1 AND snippet_key = $2 AND NOT suppressed) AS prev \
         WHERE s.tenant_id = $1 AND s.snippet_key = $2 AND NOT s.suppressed \
         RETURNING prev.content",
    )
    .bind(tenant_id)
    .bind(&key)
    .bind(&req.content)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update snippet: {e}");
        ApiError::internal("failed to save")
    })?;
    let Some((old_content,)) = updated else {
        return Err(ApiError::not_found("snippet not found", ApiErrorCode::SnippetNotFound));
    };
    audit_sink.record(
        Some(&serde_json::json!({ "content": old_content })),
        Some(&serde_json::json!({ "content": req.content })),
    );

    Ok(Json(StatusMessageResponse {
        status: "updated".into(),
        message: None,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/prompt-snippets/{key}/actions/restore-default",
    tag = "Experts",
    params(("key" = String, Path, description = "Snippet key")),
    responses(
        (status = 200, description = "Snippet restored to the shipped text; later releases update it again", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "No live snippet, or no shipped snippet, with that key", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn restore_prompt_snippet(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(key): Path<String>,
) -> Result<Json<ActionResponse>, ApiError> {
    let shipped = crate::seed_loader::SeedLoader::new()
        .load_snippets()
        .into_iter()
        .find(|s| s.key == key)
        .ok_or_else(|| ApiError::not_found("no shipped snippet with that key", ApiErrorCode::SnippetNotFound))?;
    // Back to the shipped text and to the seed's care (`is_builtin = true`), so
    // the next release's text reaches it again. A hidden snippet stays hidden.
    let restored: Option<(String, String)> = sqlx::query_as(
        "UPDATE prompt_snippets AS s SET label = $3, content = $4, is_builtin = true, updated_at = now() \
         FROM (SELECT label, content FROM prompt_snippets \
               WHERE tenant_id = $1 AND snippet_key = $2 AND NOT suppressed) AS prev \
         WHERE s.tenant_id = $1 AND s.snippet_key = $2 AND NOT s.suppressed \
         RETURNING prev.label, prev.content",
    )
    .bind(db.tenant_uuid())
    .bind(&key)
    .bind(&shipped.label)
    .bind(&shipped.content)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("restore snippet: {e}");
        ApiError::internal("failed to restore the snippet")
    })?;
    let Some((old_label, old_content)) = restored else {
        return Err(ApiError::not_found("snippet not found", ApiErrorCode::SnippetNotFound));
    };
    audit_sink.record(
        Some(&serde_json::json!({ "label": old_label, "content": old_content })),
        Some(&serde_json::json!({ "label": shipped.label, "content": shipped.content })),
    );
    Ok(Json(ActionResponse::ok()))
}

// ─── Experts ───

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts",
    tag = "Experts",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of agent experts", body = TotalPage<ExpertResponse>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_experts(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<ExpertResponse>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM agent_experts WHERE NOT suppressed")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count experts: {e}");
            ApiError::internal("internal error")
        })?;
    #[derive(sqlx::FromRow)]
    struct ExpertRow {
        id: uuid::Uuid,
        axis: String,
        description: Option<String>,
        prompt: String,
        enabled: bool,
        is_builtin: bool,
        last_processed_at: Option<chrono::DateTime<chrono::Utc>>,
        sessions_analyzed: i64,
        memory: String,
        input_types: Vec<String>,
        output_types: Vec<String>,
        model_override: Option<String>,
        created_at: chrono::DateTime<chrono::Utc>,
        updated_at: chrono::DateTime<chrono::Utc>,
        prompt_snippets: Vec<String>,
        color: Option<String>,
        merge_enabled: bool,
    }

    let rows = sqlx::query_as::<_, ExpertRow>(
        "SELECT id, axis, description, prompt, enabled, is_builtin, last_processed_at, sessions_analyzed, memory, input_types, output_types, model_override, created_at, updated_at, prompt_snippets, color, merge_enabled \
         FROM agent_experts WHERE NOT suppressed ORDER BY axis LIMIT $1 OFFSET $2",
    )
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list experts: {e}");
        ApiError::internal("internal error")
    })?;

    let experts: Vec<ExpertResponse> = rows
        .into_iter()
        .map(|r| ExpertResponse {
            id: r.id,
            axis: r.axis,
            description: r.description,
            prompt: r.prompt,
            enabled: r.enabled,
            is_builtin: r.is_builtin,
            last_processed_at: r.last_processed_at,
            sessions_analyzed: r.sessions_analyzed,
            has_memory: !r.memory.is_empty(),
            input_types: r.input_types,
            output_types: r.output_types,
            model_override: r.model_override,
            prompt_snippets: r.prompt_snippets,
            color: r.color,
            merge_enabled: r.merge_enabled,
            created_at: r.created_at,
            updated_at: r.updated_at,
        })
        .collect();

    Ok(Json(TotalPage::new(experts, limit, offset, total)))
}

#[derive(Deserialize, ToSchema)]
pub struct CreateExpertRequest {
    pub axis: String,
    pub description: Option<String>,
    pub prompt: String,
    #[serde(default = "default_true")]
    pub enabled: bool,
    pub input_types: Option<Vec<String>>,
    pub output_types: Option<Vec<String>>,
    pub model_override: Option<String>,
    pub prompt_snippets: Option<Vec<String>>,
    pub color: Option<String>,
    /// Pool into merged analysis calls with shape-compatible experts (default
    /// true); `false` = always a solo call.
    #[serde(default = "default_true")]
    pub merge_enabled: bool,
}

fn default_true() -> bool {
    true
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/experts",
    tag = "Experts",
    request_body = CreateExpertRequest,
    responses(
        (status = 201, description = "Expert created", body = CreateExpertResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 409, description = "Conflict — axis already exists", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_expert(
    mut db: TenantConn,
    Json(req): Json<CreateExpertRequest>,
) -> Result<(StatusCode, Json<CreateExpertResponse>), ApiError> {
    if req.axis.is_empty() || req.prompt.is_empty() {
        return Err(ApiError::bad_request("axis and prompt are required"));
    }

    let default_inputs = vec!["session".to_string()];
    let default_outputs = vec!["transform_suggestion".to_string()];
    let input_types = req.input_types.as_ref().unwrap_or(&default_inputs);
    let output_types = req.output_types.as_ref().unwrap_or(&default_outputs);

    // Auto-populate prompt_snippets from input/output types if not provided
    let prompt_snippets = req.prompt_snippets.unwrap_or_else(|| default_snippet_keys(input_types, output_types));

    // Auto-assign color from palette if not provided
    let color = if let Some(c) = req.color {
        Some(c)
    } else {
        // Find used colors
        let used_colors: Vec<String> = sqlx::query_scalar(
            "SELECT color FROM agent_experts WHERE color IS NOT NULL AND NOT suppressed",
        )
        .fetch_all(db.conn())
        .await
        .unwrap_or_default();

        EXPERT_COLORS.iter()
            .find(|c| !used_colors.contains(&c.to_string()))
            .map(|c| c.to_string())
    };

    let row = sqlx::query_as::<_, (uuid::Uuid,)>(
        "INSERT INTO agent_experts (axis, description, prompt, enabled, is_builtin, input_types, output_types, model_override, prompt_snippets, color, merge_enabled, tenant_id) \
         VALUES ($1, $2, $3, $4, false, $5, $6, $7, $8, $9, $10, $11) RETURNING id",
    )
    .bind(&req.axis)
    .bind(&req.description)
    .bind(&req.prompt)
    .bind(req.enabled)
    .bind(input_types)
    .bind(output_types)
    .bind(&req.model_override)
    .bind(&prompt_snippets)
    .bind(&color)
    .bind(req.merge_enabled)
    .bind(db.tenant_uuid())
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create expert: {e}");
        if super::is_unique_violation(&e) {
            ApiError::conflict("expert axis already exists", ApiErrorCode::ExpertAxisTaken)
        } else {
            ApiError::internal("internal error")
        }
    })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateExpertResponse {
            id: row.0,
            axis: req.axis,
        }),
    ))
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateExpertRequest {
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub prompt: Option<String>,
    pub enabled: Option<bool>,
    pub input_types: Option<Vec<String>>,
    pub output_types: Option<Vec<String>>,
    /// Absent leaves it; `null` clears it, back to the expert profile's model.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub model_override: Option<Option<String>>,
    pub prompt_snippets: Option<Vec<String>>,
    /// Not clearable: an expert without a colour is given one from the palette
    /// at the next start.
    pub color: Option<String>,
    /// Pool into merged analysis calls; `false` = always a solo call. Toggling
    /// this alone does NOT detach a builtin from seed-sync.
    pub merge_enabled: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/experts/{id}",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Expert ID")),
    request_body = UpdateExpertRequest,
    responses(
        (status = 200, description = "Expert updated", body = StatusMessageResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Expert not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_expert(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<UpdateExpertRequest>,
) -> Result<Json<StatusMessageResponse>, ApiError> {
    // A content edit detaches the expert from seed-sync (is_builtin = false);
    // toggling merge_enabled alone doesn't — the flag is already excluded from
    // the sync overwrite, so the builtin keeps receiving prompt updates.
    let content_edit = req.description.is_some()
        || req.prompt.is_some()
        || req.enabled.is_some()
        || req.input_types.is_some()
        || req.output_types.is_some()
        || req.model_override.is_some()
        || req.prompt_snippets.is_some()
        || req.color.is_some();

    let result = sqlx::query(
        "UPDATE agent_experts SET \
         description = CASE WHEN $2::boolean THEN $3 ELSE description END, \
         prompt = COALESCE($4, prompt), \
         enabled = COALESCE($5, enabled), \
         input_types = COALESCE($6, input_types), \
         output_types = COALESCE($7, output_types), \
         model_override = CASE WHEN $8::boolean THEN $9 ELSE model_override END, \
         prompt_snippets = COALESCE($10, prompt_snippets), \
         color = CASE WHEN $11::boolean THEN $12 ELSE color END, \
         merge_enabled = COALESCE($13, merge_enabled), \
         is_builtin = CASE WHEN $14::boolean THEN false ELSE is_builtin END, \
         updated_at = now() \
         WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .bind(req.description.is_some())
    .bind(req.description.as_ref().and_then(|v| v.as_deref()))
    .bind(&req.prompt)
    .bind(req.enabled)
    .bind(&req.input_types)
    .bind(&req.output_types)
    .bind(req.model_override.is_some())
    // A blank override is no override: the agent would send it as the model name.
    .bind(req.model_override.as_ref().and_then(|v| v.as_deref()).map(str::trim).filter(|m| !m.is_empty()))
    .bind(&req.prompt_snippets)
    .bind(req.color.is_some())
    .bind(&req.color)
    .bind(req.merge_enabled)
    .bind(content_edit)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update expert: {e}");
        ApiError::internal("internal error")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("expert not found", ApiErrorCode::ExpertNotFound));
    }

    Ok(Json(StatusMessageResponse {
        status: "updated".into(),
        message: None,
    }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/experts/{id}",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Expert ID")),
    responses(
        (status = 200, description = "Expert deleted", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Expert not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_expert(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // A row that came from the seed — edited or not — is soft-deleted
    // (suppressed) so seed-sync won't resurrect it on restart; a user-created
    // expert is hard-deleted. The row decides, in the one statement that acts
    // on it; a row already deleted answers 404.
    let acted: i64 = sqlx::query_scalar(
        "WITH hidden AS ( \
           UPDATE agent_experts SET suppressed = true, updated_at = now() \
           WHERE id = $1 AND NOT suppressed AND seeded RETURNING 1), \
         removed AS ( \
           DELETE FROM agent_experts WHERE id = $1 AND NOT suppressed AND NOT seeded RETURNING 1) \
         SELECT (SELECT count(*) FROM hidden) + (SELECT count(*) FROM removed)",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("agent expert delete failed: {e}");
        ApiError::internal("internal error")
    })?;
    if acted == 0 {
        return Err(ApiError::not_found("expert not found", ApiErrorCode::ExpertNotFound));
    }

    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/agent-status",
    tag = "Experts",
    responses(
        (status = 200, description = "Agent status", body = AgentStatusResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn agent_status(
    mut db: TenantConn,
) -> Result<Json<AgentStatusResponse>, ApiError> {
    // Read agent settings
    let settings: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT key, value FROM system_settings WHERE key LIKE 'agent_%'",
    )
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("agent status: {e}");
        ApiError::internal("internal error")
    })?;

    let get = |key: &str| -> Option<serde_json::Value> {
        settings.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };

    let enabled = get("agent_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let model = default_expert_profile_model(db.conn()).await;
    let interval = get("agent_interval_secs")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(crate::agent::DEFAULT_AGENT_INTERVAL_SECS);
    let last_cycle = get("agent_last_cycle_at")
        .and_then(|v| v.as_str().map(|s| s.to_string()));

    // Counts — pending entries count only after the multi-cycle gate so
    // the dashboard number matches what the list endpoints actually return.
    let pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM program_suggestions WHERE status = 'pending' AND seen_count >= $1",
    )
    .bind(crate::settings::admin_settings().agent_suggestion_min_seen)
    .fetch_one(db.conn())
    .await
    .unwrap_or(0);

    let expert_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM agent_experts WHERE enabled = true AND NOT suppressed",
    )
    .fetch_one(db.conn())
    .await
    .unwrap_or(0);

    Ok(Json(AgentStatusResponse {
        enabled,
        model,
        interval_secs: interval,
        last_cycle_at: last_cycle,
        pending_suggestions: pending,
        expert_count,
    }))
}

/// Reset an expert's watermark so it rescans all sessions on the next cycle.
#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/{id}/actions/reset",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Expert ID")),
    responses(
        (status = 200, description = "Expert watermark reset", body = StatusMessageResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Expert not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_expert(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<StatusMessageResponse>, ApiError> {
    let result = sqlx::query(
        "UPDATE agent_experts SET last_processed_at = NULL, sessions_analyzed = 0, updated_at = now() WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("reset expert: {e}");
        ApiError::internal("internal error")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("expert not found", ApiErrorCode::ExpertNotFound));
    }

    // Trigger immediate agent cycle
    crate::leader::insert_agent_trigger(&state.db, None).await;

    Ok(Json(StatusMessageResponse {
        status: "reset".into(),
        message: Some("Expert watermark cleared. Agent cycle triggered.".into()),
    }))
}

/// Trigger an immediate agent analysis cycle.
#[utoipa::path(
    post,
    path = "/api/v1/admin/experts/actions/agent-run",
    tag = "Experts",
    responses(
        (status = 200, description = "Agent cycle triggered", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn trigger_agent_run(
    State(state): State<Arc<AdminState>>,
) -> Json<ActionResponse> {
    crate::leader::insert_agent_trigger(&state.db, None).await;
    Json(ActionResponse::ok().with_message("Agent cycle triggered."))
}

// ─── Expert Memory ───

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/{id}/memory",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Expert ID")),
    responses(
        (status = 200, description = "Expert memory content", body = ExpertMemoryResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Expert not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_expert_memory(
    mut db: TenantConn,
    Path(id): Path<uuid::Uuid>,
) -> Result<Json<ExpertMemoryResponse>, ApiError> {
    let row: Option<(String,)> = sqlx::query_as(
        "SELECT memory FROM agent_experts WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get expert memory: {e}");
        ApiError::internal("internal error")
    })?;

    match row {
        Some((memory,)) => Ok(Json(ExpertMemoryResponse { memory })),
        None => Err(ApiError::not_found("expert not found", ApiErrorCode::ExpertNotFound)),
    }
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMemoryRequest {
    pub memory: String,
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/experts/{id}/memory",
    tag = "Experts",
    params(("id" = Uuid, Path, description = "Expert ID")),
    request_body = UpdateMemoryRequest,
    responses(
        (status = 200, description = "Expert memory updated", body = StatusMessageResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 404, description = "Expert not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_expert_memory(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(id): Path<uuid::Uuid>,
    Json(req): Json<UpdateMemoryRequest>,
) -> Result<Json<StatusMessageResponse>, ApiError> {
    // The `FROM` subquery captures the pre-update memory (same statement snapshot)
    // for the audit change_diff. 404 when no live expert matches.
    let updated: Option<(String,)> = sqlx::query_as(
        "UPDATE agent_experts AS e SET memory = $2, updated_at = now() \
         FROM (SELECT memory FROM agent_experts WHERE id = $1 AND NOT suppressed) AS prev \
         WHERE e.id = $1 AND NOT e.suppressed \
         RETURNING prev.memory",
    )
    .bind(id)
    .bind(&req.memory)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update expert memory: {e}");
        ApiError::internal("internal error")
    })?;

    let Some((old_memory,)) = updated else {
        return Err(ApiError::not_found("expert not found", ApiErrorCode::ExpertNotFound));
    };
    audit_sink.record(
        Some(&serde_json::json!({ "memory": old_memory })),
        Some(&serde_json::json!({ "memory": req.memory })),
    );

    Ok(Json(StatusMessageResponse {
        status: "updated".into(),
        message: None,
    }))
}

// ─── Expert Dashboard ───

/// One cross-session issue — a cluster/anomaly finding that spans several
/// sessions, linking to each via `source_session_ids`. The first-class home that
/// replaced stamping a multi-session finding onto one arbitrary session's alert.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct CrossSessionIssue {
    pub id: uuid::Uuid,
    pub axis: Option<String>,
    pub level: Option<String>,
    pub note: Option<String>,
    pub source_session_ids: Vec<uuid::Uuid>,
    pub key_id: Option<uuid::Uuid>,
    pub workspace_id: Option<uuid::Uuid>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CrossSessionIssueQuery {
    /// Maximum items to return. Default 50, capped at 200.
    pub limit: Option<i64>,
    /// Items to skip. Default 0.
    pub offset: Option<i64>,
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Filter by emitting expert axis (e.g. `anomaly`).
    pub axis: Option<String>,
    /// Filter by severity (`info` | `minor` | `major`).
    pub level: Option<String>,
    /// Only issues that include this session among their members (for the
    /// "appears in N cross-session issues" section on a session).
    pub session_id: Option<uuid::Uuid>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<super::WorkspaceIds>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/cross-session-issues",
    tag = "Experts",
    params(CrossSessionIssueQuery),
    responses(
        (status = 200, description = "Cross-session issues linking the sessions they span", body = OffsetPage<CrossSessionIssue>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_cross_session_issues(
    mut db: TenantConn,
    Query(params): Query<CrossSessionIssueQuery>,
) -> Result<Json<OffsetPage<CrossSessionIssue>>, ApiError> {
    let (start_ts, end_ts) = super::TimeWindow {
        days: params.days,
        start: params.start,
        end: params.end,
    }
    .resolve(30)?;
    let limit = params.limit.unwrap_or(50).clamp(1, 200);
    let offset = crate::routes::resolve_offset(params.offset);
    let workspace_ids = super::parse_workspace_ids(&params.workspace_ids);

    // Value-only splices ($N are integers, safe by type); every filter is bound.
    let mut sql = String::from(
        "SELECT r.id, r.axis, r.level, r.note, r.key_id, r.workspace_id, r.created_at, \
         COALESCE(ARRAY_AGG(m.session_id ORDER BY m.seq) FILTER (WHERE m.session_id IS NOT NULL), '{}') AS source_session_ids \
         FROM cross_session_relations r \
         LEFT JOIN cross_session_relation_members m ON m.relation_id = r.id AND m.role = 'subject' \
         WHERE r.kind = 'issue' AND r.created_at >= $1 AND r.created_at < $2",
    );
    let mut idx: u32 = 3;
    if params.axis.is_some() {
        sql.push_str(&format!(" AND r.axis = ${idx}"));
        idx += 1;
    }
    if params.level.is_some() {
        sql.push_str(&format!(" AND r.level = ${idx}"));
        idx += 1;
    }
    if workspace_ids.is_some() {
        sql.push_str(&format!(" AND r.workspace_id = ANY(${idx})"));
        idx += 1;
    }
    if params.session_id.is_some() {
        sql.push_str(&format!(
            " AND EXISTS (SELECT 1 FROM cross_session_relation_members mm \
                WHERE mm.relation_id = r.id AND mm.session_id = ${idx})"
        ));
        idx += 1;
    }
    sql.push_str(&format!(
        " GROUP BY r.tenant_id, r.id ORDER BY r.created_at DESC LIMIT ${idx} OFFSET ${}",
        idx + 1
    ));

    let mut q = sqlx::query_as::<_, CrossSessionIssue>(sqlx::AssertSqlSafe(&*sql))
        .bind(start_ts)
        .bind(end_ts);
    if let Some(a) = &params.axis {
        q = q.bind(a);
    }
    if let Some(l) = &params.level {
        q = q.bind(l);
    }
    if let Some(ws) = &workspace_ids {
        q = q.bind(ws);
    }
    if let Some(sid) = &params.session_id {
        q = q.bind(sid);
    }
    let rows = q
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list_cross_session_issues: {e}");
            ApiError::internal("failed to query cross-session issues")
        })?;

    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/dashboard",
    tag = "Experts",
    params(super::WindowWorkspacesQuery),
    responses(
        (status = 200, description = "Expert dashboard overview", body = ExpertDashboardResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn expert_dashboard(
    mut db: TenantConn,
    Query(params): Query<super::WindowWorkspacesQuery>,
) -> Result<Json<ExpertDashboardResponse>, ApiError> {
    let (start_ts, end_ts) = params.time_window().resolve(30)?;
    let workspace_ids = params.workspace_ids();
    let tenant_id = db.tenant_uuid();
    let failed = |e: sqlx::Error| {
        tracing::error!("expert dashboard: {e}");
        ApiError::internal("failed to load the expert dashboard")
    };

    // Alert counts from sessions
    // Predicate matches the `idx_sessions_alert` partial index and
    // intentionally excludes `info` rows — those are neutral annotations,
    // not alarms.
    let alert_rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT alert_level, COUNT(*) FROM sessions WHERE tenant_id = $1 AND alert_level IN ('minor', 'major') AND updated_at >= $2 AND updated_at < $3 \
         AND ($4::uuid[] IS NULL OR workspace_id = ANY($4)) GROUP BY alert_level",
    )
    .bind(tenant_id)
    .bind(start_ts)
    .bind(end_ts)
    .bind(&workspace_ids)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;

    let mut major_alerts: i64 = 0;
    let mut minor_alerts: i64 = 0;
    for (level, count) in &alert_rows {
        match level.as_str() {
            "major" => major_alerts = *count,
            "minor" => minor_alerts = *count,
            _ => {}
        }
    }

    // Expert details with per-expert alert counts
    #[allow(clippy::type_complexity)]
    let expert_rows: Vec<(uuid::Uuid, String, Option<String>, bool, i64, Option<chrono::DateTime<chrono::Utc>>, String, Vec<String>, Vec<String>, Option<String>)> = sqlx::query_as(
        "SELECT id, axis, description, enabled, sessions_analyzed, last_processed_at, memory, \
         input_types, output_types, model_override \
         FROM agent_experts WHERE NOT suppressed ORDER BY axis",
    )
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;

    let mut experts = Vec::new();
    for (id, axis, description, enabled, sessions_analyzed, last_processed_at, memory, input_types, output_types, model_override) in &expert_rows {
        // Per-expert alert counts
        let expert_alerts: Vec<(String, i64)> = sqlx::query_as(
            "SELECT alert_level, COUNT(*) FROM sessions WHERE tenant_id = $1 AND alert_expert_axis LIKE '%' || $2 || '%' AND alert_level IN ('minor', 'major') AND updated_at >= $3 AND updated_at < $4 \
             AND ($5::uuid[] IS NULL OR workspace_id = ANY($5)) GROUP BY alert_level",
        )
        .bind(tenant_id)
        .bind(axis)
        .bind(start_ts)
        .bind(end_ts)
        .bind(&workspace_ids)
        .fetch_all(db.conn())
        .await
        .map_err(failed)?;

        let mut expert_major: i64 = 0;
        let mut expert_minor: i64 = 0;
        for (level, count) in &expert_alerts {
            match level.as_str() {
                "major" => expert_major = *count,
                "minor" => expert_minor = *count,
                _ => {}
            }
        }

        // Per-expert suggestion counts — pending entries only count after
        // the multi-cycle gate. Approved/rejected always count.
        let suggestion_count_rows: Vec<(String, i64)> = sqlx::query_as(
            "SELECT status, COUNT(*) FROM program_suggestions \
             WHERE expert_axis = $1 \
               AND (status != 'pending' OR seen_count >= $2) \
             GROUP BY status",
        )
        .bind(axis)
        .bind(crate::settings::admin_settings().agent_suggestion_min_seen)
        .fetch_all(db.conn())
        .await
        .map_err(failed)?;

        let mut pending: i64 = 0;
        let mut implemented: i64 = 0;
        let mut rejected: i64 = 0;
        for (status, count) in &suggestion_count_rows {
            match status.as_str() {
                "pending" => pending = *count,
                "implemented" => implemented = *count,
                "rejected" => rejected = *count,
                _ => {}
            }
        }

        experts.push(ExpertDashboardEntry {
            id: *id,
            axis: axis.clone(),
            description: description.clone(),
            enabled: *enabled,
            sessions_analyzed: *sessions_analyzed,
            last_processed_at: *last_processed_at,
            has_memory: !memory.is_empty(),
            input_types: input_types.clone(),
            output_types: output_types.clone(),
            model_override: model_override.clone(),
            color: None,
            prompt_snippets: None,
            alert_counts: AlertCounts { major: expert_major, minor: expert_minor },
            suggestion_counts: SuggestionCounts { pending, implemented, rejected },
        });
    }

    // Total sessions analyzed
    let total_analyzed: i64 = expert_rows.iter().map(|(_, _, _, _, sa, _, _, _, _, _)| sa).sum();
    let active_experts = expert_rows.iter().filter(|(_, _, _, enabled, _, _, _, _, _, _)| *enabled).count();

    // Pending suggestions total — gated by seen_count so dashboard matches
    // the visibility of the list endpoints.
    let min_seen = crate::settings::admin_settings().agent_suggestion_min_seen;
    let total_pending: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM program_suggestions WHERE status = 'pending' AND seen_count >= $1",
    )
    .bind(min_seen)
    .fetch_one(db.conn())
    .await
    .map_err(failed)?;

    let pending_tool_rule_suggestions: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tool_rule_suggestions WHERE status = 'pending' AND seen_count >= $1",
    )
    .bind(min_seen)
    .fetch_one(db.conn())
    .await
    .map_err(failed)?;

    // Recent suggestions (last 8) — same visibility rule
    let suggestion_rows: Vec<(uuid::Uuid, String, String, String, chrono::DateTime<chrono::Utc>)> = sqlx::query_as(
        "SELECT id, expert_axis, title, status, created_at \
         FROM program_suggestions \
         WHERE status != 'pending' OR seen_count >= $1 \
         ORDER BY created_at DESC LIMIT 8",
    )
    .bind(min_seen)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;

    let recent_suggestions: Vec<RecentSuggestion> = suggestion_rows
        .into_iter()
        .map(|(id, expert_axis, title, status, created_at)| {
            RecentSuggestion {
                id,
                expert_axis,
                title,
                status,
                created_at,
            }
        })
        .collect();

    // Agent status
    let settings: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT key, value FROM system_settings WHERE key LIKE 'agent_%'",
    )
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;

    let get_setting = |key: &str| -> Option<serde_json::Value> {
        settings.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };

    let agent_enabled = get_setting("agent_enabled")
        .and_then(|v| v.as_bool())
        .unwrap_or(false);
    let agent_model = default_expert_profile_model(db.conn()).await;
    let agent_interval = get_setting("agent_interval_secs")
        .and_then(|v| v.as_u64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
        .unwrap_or(crate::agent::DEFAULT_AGENT_INTERVAL_SECS);
    let last_cycle = get_setting("agent_last_cycle_at")
        .and_then(|v| v.as_str().map(|s| s.to_string()));

    // Agent usage metrics (requests, tokens, cost, errors) — the agent's own
    // traffic, stamped `source = 'agent'` at ingestion. `workspace_ids` does not narrow
    // it: the agent runs in its own workspace, whatever it analyses.
    let usage = crate::audit_store::usage::agent_usage(db.conn(), tenant_id, (start_ts, end_ts))
        .await
        .map_err(failed)?;
    let spend =
        super::denominated_spend(db.conn(), usage.currency_count, usage.currency, usage.amount).await;

    Ok(Json(ExpertDashboardResponse {
        total_alerts: AlertCounts { major: major_alerts, minor: minor_alerts },
        total_sessions_analyzed: total_analyzed,
        pending_suggestions: total_pending,
        pending_tool_rule_suggestions,
        active_experts,
        experts,
        recent_suggestions,
        agent: AgentMetrics {
            enabled: agent_enabled,
            model: agent_model,
            interval_secs: agent_interval,
            last_cycle_at: last_cycle,
            requests: usage.requests,
            prompt_tokens: usage.prompt_tokens,
            completion_tokens: usage.completion_tokens,
            spend,
            errors: usage.errors,
        },
    }))
}


/// The tenant's baseline judge model — the Default expert profile's `model`,
/// falling back to the built-in default for a tenant whose expert profiles have
/// not been seeded yet.
async fn default_expert_profile_model(conn: &mut Scoped) -> String {
    sqlx::query_scalar::<_, Option<String>>(
        "SELECT model FROM profiles WHERE kind = 'expert' AND is_default",
    )
    .fetch_optional(conn)
    .await
    .ok()
    .flatten()
    .flatten()
    .unwrap_or_else(|| crate::agent::DEFAULT_AGENT_MODEL.to_string())
}

// ─── Agent Models ───

/// The rows [`get_agent_models`] folds: one per enabled route to a model that
/// can answer the judge, ordered by alias so each alias's routes are adjacent.
/// Its fragments come from [`crate::routes::with_agent_route_parts`].
const AGENT_MODEL_ROWS_SQL: &str = concat!(r#"
    SELECT r.alias, s.id, m.upstream_model, s.name, s.provider,
--{agent_granted}
           AS granted
      FROM downstream_routes r
      JOIN upstream_models m ON m.id = r.model_id
      JOIN upstream_servers s ON s.id = m.server_id
     WHERE "#, live_route_sql!(), r#"
       AND
--{judge_capable}
     ORDER BY r.alias, s.name, s.id, m.upstream_model"#);

/// [`AGENT_MODEL_ROWS_SQL`] with its fragments spliced, built once.
static AGENT_MODEL_ROWS: std::sync::LazyLock<String> =
    std::sync::LazyLock::new(|| crate::routes::with_agent_route_parts(AGENT_MODEL_ROWS_SQL));

/// Whether the agent key is provisioned, plus one option per alias the agent
/// can target — the list for the expert-profile judge-model picker (the
/// Default profile's `model`, overridable per profile and per expert).
#[utoipa::path(
    get,
    path = "/api/v1/admin/experts/agent-models",
    tag = "Experts",
    responses(
        (status = 200, description = "Agent model configuration", body = AgentModelsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_agent_models(
    mut db: TenantConn,
) -> Result<Json<AgentModelsResponse>, ApiError> {
    let key_id: Option<uuid::Uuid> = sqlx::query_scalar(
        "SELECT ak.id \
         FROM api_keys ak \
         JOIN users u ON u.id = ak.user_id \
         WHERE u.email = 'agent@streamscope.internal' \
           AND ak.name = 'agent-key' AND ak.revoked_at IS NULL \
         LIMIT 1",
    )
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("agent models: agent key lookup: {e}");
        ApiError::internal("failed to load agent models")
    })?;

    // Every enabled route to a model that can answer — the judge replies in
    // text through a forced tool call, so an image, audio, video, embedding or
    // rerank model never serves it. Flat rows ordered by alias, folded below.
    let rows: Vec<(String, uuid::Uuid, String, String, String, bool)> = sqlx::query_as(sqlx::AssertSqlSafe(
        AGENT_MODEL_ROWS.as_str(),
    ))
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("agent models: routes: {e}");
        ApiError::internal("failed to load agent models")
    })?;

    let mut models: Vec<AgentModelEntry> = Vec::new();
    // A target is a (server, model) pair: keyed on the server's id, since two
    // servers may share a name.
    let mut seen: Vec<(uuid::Uuid, String)> = Vec::new();
    for (alias, server_id, upstream_model, server_name, provider, granted) in rows {
        let key = (server_id, upstream_model.clone());
        let target = AgentModelTarget { upstream_model, server_name, provider };
        match models.last_mut() {
            Some(m) if m.alias == alias => {
                m.granted_to_agent |= granted;
                if !seen.contains(&key) {
                    seen.push(key);
                    m.targets.push(target);
                }
            }
            _ => {
                seen.clear();
                seen.push(key);
                models.push(AgentModelEntry {
                    alias,
                    targets: vec![target],
                    granted_to_agent: granted,
                });
            }
        }
    }

    Ok(Json(AgentModelsResponse { key_id, models }))
}

// ─── Router ───

pub fn transforms_router() -> axum::Router<Arc<AdminState>> {
    use axum::routing::{get, post};

    axum::Router::new()
        .route("/programs", post(create_program).get(list_programs))
        .route(
            "/programs/{id}",
            get(get_program).patch(update_program).delete(delete_program),
        )
        .route("/programs/actions/validate", post(validate_program))
        .route("/programs/actions/test", post(test_program))
        .route("/suggestions", get(list_suggestions))
        .route("/suggestions/{id}/actions/approve", post(approve_suggestion))
        .route("/suggestions/{id}/actions/reject", post(reject_suggestion))
}

pub fn experts_router() -> axum::Router<Arc<AdminState>> {
    use axum::routing::{get, patch, post, put};

    axum::Router::new()
        .route("/", get(list_experts).post(create_expert))
        .route("/{id}", patch(update_expert).delete(delete_expert))
        .route("/{id}/actions/reset", post(reset_expert))
        .route("/{id}/memory", get(get_expert_memory).put(update_expert_memory))
        // Agent controls (tenant-scoped collection actions)
        .route("/agent-status", get(agent_status))
        .route("/actions/agent-run", post(trigger_agent_run))
        .route("/agent-models", get(get_agent_models))
        .route("/dashboard", get(expert_dashboard))
        .route("/cross-session-issues", get(list_cross_session_issues))
        // Prompt snippets
        .route("/prompt-snippets", get(list_prompt_snippets))
        .route("/prompt-snippets/{key}", put(update_prompt_snippet))
        .route("/prompt-snippets/{key}/actions/restore-default", post(restore_prompt_snippet))
        // Tool rule suggestions
        .route("/tool-rule-suggestions", get(list_tool_rule_suggestions))
        .route("/tool-rule-suggestions/{id}/actions/approve", post(approve_tool_rule_suggestion))
        .route("/tool-rule-suggestions/{id}/actions/reject", post(reject_tool_rule_suggestion))
        // Field profile suggestions
        .route(
            "/field-profile-suggestions",
            get(super::tool_field_profiles::list_field_profile_suggestions),
        )
        .route(
            "/field-profile-suggestions/{id}/actions/approve",
            post(super::tool_field_profiles::approve_field_profile_suggestion),
        )
        .route(
            "/field-profile-suggestions/{id}/actions/reject",
            post(super::tool_field_profiles::reject_field_profile_suggestion),
        )
}
