//! Usage analytics, cost breakdowns, timeseries, and tool inventory.
//!
//! The HTTP surface of the dashboard views — usage summaries (by user, model,
//! app), cost breakdowns, request timeseries, error analytics, and tool call
//! inventory with risk classification: query structs, response types and the
//! handlers. The aggregates over the audit facts are in the audit store
//! (`crate::audit_store::analytics`); every query is tenant-scoped via RLS.

use crate::db::Global;
use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::{Query, State};
use axum::Json;
use chrono::{DateTime, Timelike, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use utoipa::{IntoParams, ToSchema};

use crate::sql_pattern::{contains_pattern, prefix_pattern, search_text};
use super::{ApiError, ApiErrorResponse};
use crate::AdminState;
use crate::audit_store::AuditScope;
use crate::audit_store::analytics::{
    a2a as a2a_store, mcp as mcp_store, tools as tools_store, usage, web as web_store,
};
use crate::db::tenant::{Scoped, TenantConn};
use crate::routes::{
    AnalyticsScope, SpendBreakdown,
    SpendTotal, TimeWindow, WindowQuery, WindowWorkspacesQuery,
    WorkspaceIds, parse_workspace_ids,
};

/// The `risk` a tool-inventory list can narrow to.
#[derive(Debug, Clone, Copy, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolRiskFilter {
    Safe,
    Caution,
    Danger,
    Unknown,
    /// Tools with at least one blocked call, whatever their risk.
    Blocked,
}

impl ToolRiskFilter {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Safe => "safe",
            Self::Caution => "caution",
            Self::Danger => "danger",
            Self::Unknown => "unknown",
            Self::Blocked => "blocked",
        }
    }
}

/// The `outcome` a tool-call feed can narrow to.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallOutcome {
    Ok,
    Blocked,
    /// A call policy would have blocked, which ran: an out-of-band exchange's.
    NotApplied,
    Redacted,
    ArgsModified,
}

/// Default lookback window (days) for usage analytics. Public so sibling
/// modules (e.g. `tool_rules`) can mirror the same default.
pub const DEFAULT_USAGE_DAYS: i32 = 1;

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UsageQuery {
    pub user_id: Option<Uuid>,
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339). Defaults to now when only `start` set.
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl UsageQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    pub(crate) fn scope(&self) -> AnalyticsScope {
        AnalyticsScope {
            user_id: self.user_id,
            workspace_ids: parse_workspace_ids(&self.workspace_ids),
            ..Default::default()
        }
    }
}

#[derive(Serialize, Default, ToSchema)]
pub struct UsageSummary {
    pub total_requests: i64,
    pub total_sessions: i64,
    pub total_prompt_tokens: i64,
    pub total_completion_tokens: i64,
    pub total_cache_creation_tokens: i64,
    pub total_cache_read_tokens: i64,
    pub total_reasoning_tokens: i64,
    /// What the window spent, one entry per accounting currency its rows were
    /// written in, each decomposed per pricing unit.
    ///
    /// **Never empty, and one entry in the ordinary case** — read that entry as
    /// the window's spend. A window with no priced traffic still reports a zero
    /// in the tenant's current accounting currency, so "nothing spent" cannot be
    /// mistaken for "spend in an unknown denomination".
    ///
    /// More than one entry means the window straddles a change of the tenant's
    /// accounting currency. Those subtotals are in different denominations:
    /// report them separately, never summed.
    pub spend: Vec<SpendBreakdown>,
    pub avg_latency_ms: f64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    pub avg_ttft_ms: f64,
    pub p50_ttft_ms: f64,
    pub p95_ttft_ms: f64,
    pub error_count: i64,
    pub high_latency_count: i64,
    // SSE response processing stats
    pub streaming_requests: i64,
    pub response_fastpath: i64,
    pub response_buffered: i64,
    pub response_tool_blocks: i64,
    // Media metrics
    pub total_embedding_requests: i64,
    pub total_audio_requests: i64,
    pub total_image_requests: i64,
    pub total_video_requests: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/overview",
    tag = "Analytics",
    params(UsageQuery),
    responses(
        (status = 200, description = "Usage summary", body = UsageSummary),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn usage_summary(
    mut db: TenantConn,
    Query(query): Query<UsageQuery>,
) -> Result<Json<UsageSummary>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    usage::usage_summary(db.conn(), tenant_id, start_ts, end_ts, scope).await.map(Json)
}

// --- Usage Breakdown ---

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct BreakdownQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    pub user_id: Option<Uuid>,
    /// Dimension to group by. Defaults to the model used.
    pub by: Option<BreakdownBy>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

/// The dimension a usage breakdown groups by. `server_model` and
/// `workspace_model` group by model within each server / workspace (the
/// server / workspace is the entry's `parent_key`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum BreakdownBy {
    #[default]
    Model,
    User,
    Server,
    ServerModel,
    Workspace,
    WorkspaceModel,
    Provider,
    App,
}

impl BreakdownQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope {
            user_id: self.user_id,
            workspace_ids: parse_workspace_ids(&self.workspace_ids),
            ..Default::default()
        }
    }
}

/// Usage grouped by one dimension: the top groups of the window, largest first.
#[derive(Serialize, ToSchema)]
pub struct UsageBreakdown {
    pub entries: Vec<BreakdownEntry>,
}

#[derive(Serialize, ToSchema)]
pub struct BreakdownEntry {
    pub key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_key: Option<String>,
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    /// What this entry spent, decomposed per pricing unit.
    ///
    /// `null` when the entry's rows straddle a change of the tenant's
    /// accounting currency: they are then stated in different denominations,
    /// and a single figure would be in neither. Render that as unavailable —
    /// the window's own components are on the overview.
    pub spend: Option<SpendBreakdown>,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub reasoning_tokens: i64,
    pub streaming_count: i64,
    pub avg_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub error_count: i64,
    pub high_latency_count: i64,
    /// User email when `by=user` and the user has one on file. Lets the UI
    /// build a `?user_email=…` deep-link that the audit / sessions backends
    /// match exactly, instead of relying on the rendered display-name `key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    /// User UUID when `by=user`. Fallback identifier the UI uses when
    /// `user_email` is absent — pairs with `AuditQuery::user_id` /
    /// `SessionListQuery::user_id` so deep-links still resolve for users
    /// without an email on file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
    /// The upstream server's id when `by=server` (the entry) or
    /// `by=server_model` (its parent), so a row can open that server's
    /// dashboard, which is addressed by id.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/breakdown",
    tag = "Analytics",
    params(BreakdownQuery),
    responses(
        (status = 200, description = "Usage breakdown by dimension", body = UsageBreakdown),
        (status = 400, description = "Invalid time window or dimension", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn usage_breakdown(
    mut db: TenantConn,
    Query(query): Query<BreakdownQuery>,
) -> Result<Json<UsageBreakdown>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    let group_by = query.by.unwrap_or_default();
    usage::usage_breakdown(db.conn(), tenant_id, start_ts, end_ts, scope, group_by).await.map(Json)
}

// --- Tool risk rules (stored in system_settings.tool_rules.rules) ---

/// Admin wire alias for the unified rule shape that lives in
/// `streamscope-core`. The struct itself (phase / scope / match[] / action)
/// is defined once in `streamscope_core::config::tool_rules::Rule` and used
/// verbatim by:
///   - the proxy enforcement pipeline (request + response phases)
///   - the admin CRUD handlers in `tool_rules.rs`
///   - the tool risk config JSONB in `system_settings`
///   - the OpenAPI spec exposed to the admin UI
///
/// One shape, one schema, no duplicate definition.
pub use streamscope_core::config::tool_rules::Rule as ToolRule;

// --- Tool Inventory ---

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ToolInventoryQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    pub app_id: Option<String>,
    pub user_id: Option<Uuid>,
    /// Case-insensitive substring on `tool_name` or resolved `tool_id`.
    /// Narrows only the `tools[]` row list — `summary` and `coverage`
    /// reflect the period as a whole.
    pub q: Option<String>,
    /// Risk class filter. Narrows only the `tools[]` row list, same as `q`.
    pub risk: Option<ToolRiskFilter>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl ToolInventoryQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope {
            user_id: self.user_id,
            app_id: self.app_id.clone(),
            workspace_ids: parse_workspace_ids(&self.workspace_ids),
            ..Default::default()
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct ToolEntry {
    pub tool_name: String,
    /// Canonical tool concept resolved through the field-profile registry.
    /// `None` when no profile matched `(tool_name, app_id, mcp_server)`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    /// Highest-severity risk seen across all calls to this tool in the window.
    /// Drives the card's border accent and the `?risk=` row filter; the UI
    /// renders the per-risk breakdown via the *_count fields below.
    pub risk_level: String,
    pub call_count: i64,
    pub blocked_count: i64,
    /// What policy would have blocked and nothing stopped in an out-of-band
    /// exchange, a tool it removed from a request or a call in an answer, entry
    /// for entry as `blocked_count` counts them: not in `blocked_count`.
    pub not_applied_count: i64,
    /// Calls classified `safe` in the window.
    pub safe_count: i64,
    /// Calls classified `caution`.
    pub caution_count: i64,
    /// Calls classified `danger` (does not include `blocked_count`).
    pub danger_count: i64,
    /// Calls that matched no risk rule.
    pub unknown_count: i64,
    pub session_count: i64,
    pub user_count: i64,
    pub last_used: chrono::DateTime<chrono::Utc>,
    pub app_ids: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_description: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ToolInventoryResponse {
    pub tools: Vec<ToolEntry>,
    pub summary: ToolSummary,
    pub coverage: ProfileCoverage,
}

#[derive(Serialize, ToSchema)]
pub struct ToolSummary {
    pub total_tools: usize,
    pub total_calls: i64,
    pub blocked_count: i64,
    /// Entries policy would have blocked and nothing stopped: not in
    /// `blocked_count`.
    pub not_applied_count: i64,
    pub safe_count: usize,
    pub caution_count: usize,
    pub danger_count: usize,
    pub unknown_count: usize,
    /// Total tool_result blocks rewritten by `replace` rules in the same window.
    pub redacted_count: i64,
}

/// One unprofiled wire tool name with its call count — used to surface the
/// top contributors to the coverage gap on the dashboard.
#[derive(Serialize, ToSchema)]
pub struct UnprofiledTool {
    pub tool_name: String,
    pub call_count: i64,
}

/// Headline Stage-C metric: how many tool calls in the window resolved to a
/// canonical `tool_id` via the field-profile registry, and which wire names
/// dominate the unresolved tail.
#[derive(Serialize, ToSchema)]
pub struct ProfileCoverage {
    /// Calls where `FieldProfileSet::resolve(...)` returned `Some(tool_id)`.
    pub profiled_calls: i64,
    /// Equals `summary.total_calls` — duplicated here for self-contained
    /// rendering of the coverage panel.
    pub total_calls: i64,
    /// Top 10 wire tool names by call count where `tool_id` resolution failed.
    pub top_unprofiled: Vec<UnprofiledTool>,
}

// ── App Registry ─────────────────────────────────────────────────────────

/// Metadata for a known AI coding client.
#[derive(Debug, Serialize, Deserialize, Clone, ToSchema)]
pub struct AppInfo {
    pub id: String,
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub url: String,
    /// Whether this entry is built-in (true) or user-defined (false).
    #[serde(default)]
    pub builtin: bool,
    /// User-Agent substrings used for detection (case-insensitive).
    #[serde(default)]
    pub ua_patterns: Vec<String>,
    /// Referer domain substrings used for detection (case-insensitive).
    #[serde(default)]
    pub referer_patterns: Vec<String>,
    /// Substrings of the opening of the system prompt (case-insensitive), tried
    /// only when no header named the app. Each is at least
    /// `MIN_PROMPT_PATTERN_CHARS` characters: it is tried against every
    /// unclassified request, so a short one would claim other clients' traffic.
    #[serde(default)]
    pub prompt_patterns: Vec<String>,
}

/// One `apps` table row (the storage projection of [`AppInfo`]).
#[derive(sqlx::FromRow)]
struct AppRow {
    app_key: String,
    name: String,
    description: String,
    url: String,
    is_builtin: bool,
    ua_patterns: Vec<String>,
    referer_patterns: Vec<String>,
    prompt_patterns: Vec<String>,
}

impl From<AppRow> for AppInfo {
    fn from(r: AppRow) -> Self {
        AppInfo {
            id: r.app_key,
            name: r.name,
            description: r.description,
            url: r.url,
            builtin: r.is_builtin,
            ua_patterns: r.ua_patterns,
            referer_patterns: r.referer_patterns,
            prompt_patterns: r.prompt_patterns,
        }
    }
}

/// Load the tenant's live (non-suppressed) app registry from the `apps` table.
///
/// The DB is the single source of truth — seeded from `seeds/apps/` at tenant
/// creation, synced on startup. RLS-scoped via the tenant connection.
async fn merged_app_registry(executor: &mut Scoped) -> Vec<AppInfo> {
    match sqlx::query_as::<_, AppRow>(
        "SELECT app_key, name, description, url, is_builtin, ua_patterns, referer_patterns, prompt_patterns \
         FROM apps WHERE NOT suppressed ORDER BY app_key",
    )
    .fetch_all(executor)
    .await
    {
        Ok(rows) => rows.into_iter().map(AppInfo::from).collect(),
        Err(e) => {
            tracing::warn!("failed to query apps: {e}");
            vec![]
        }
    }
}

/// Load the app registry for the config snapshot, tenant bound explicitly
/// (defense-in-depth on top of RLS). Best-effort: an error yields an empty set
/// (app attribution degrades gracefully — it never blocks a request).
pub(crate) async fn load_apps_snapshot(
    conn: &mut Scoped,
    tenant_id: Uuid,
) -> Vec<AppInfo> {
    match sqlx::query_as::<_, AppRow>(
        "SELECT app_key, name, description, url, is_builtin, ua_patterns, referer_patterns, prompt_patterns \
         FROM apps WHERE tenant_id = $1 AND NOT suppressed ORDER BY app_key",
    )
    .bind(tenant_id)
    .fetch_all(&mut *conn)
    .await
    {
        Ok(rows) => rows.into_iter().map(AppInfo::from).collect(),
        Err(e) => {
            tracing::warn!(%tenant_id, "failed to load apps for snapshot: {e}");
            vec![]
        }
    }
}

/// Refuse a prompt pattern shorter than `MIN_PROMPT_PATTERN_CHARS` (after
/// trimming): it is tried against the opening of every request no header named,
/// so "you are" would attribute every other client's traffic to this app.
fn validate_prompt_patterns(apps: &[AppInfo]) -> Result<(), ApiError> {
    use streamscope_core::middleware::attribution::MIN_PROMPT_PATTERN_CHARS;
    for a in apps {
        if let Some(p) = a
            .prompt_patterns
            .iter()
            .find(|p| p.trim().chars().count() < MIN_PROMPT_PATTERN_CHARS)
        {
            return Err(ApiError::bad_request(format!(
                "app '{}': prompt pattern {p:?} is shorter than {MIN_PROMPT_PATTERN_CHARS} characters",
                a.id
            )));
        }
    }
    Ok(())
}

/// Full-array replace of the tenant's app registry from a settings PATCH payload
/// (the only apps-edit surface). Each incoming app is upserted; an app that came
/// from the seed (`seeded` or still builtin) and is no longer in the array is
/// soft-deleted (`suppressed=true`, so seed-sync won't resurrect it) and a user
/// app no longer in the array is removed outright.
/// Runs inside the caller's settings transaction (multiple statements, no lock —
/// concurrent edits to different rows never contend).
pub(crate) async fn replace_apps(
    conn: &mut Scoped,
    tenant_id: Uuid,
    apps: &[AppInfo],
) -> Result<(), ApiError> {
    validate_prompt_patterns(apps)?;
    // Only the seed makes an app builtin: a request may hand one to the admin
    // (`builtin: false`, an edit) but never make one — a new app, or a deleted
    // one re-added, is the admin's, and an existing app's flag can only be
    // lowered.
    for a in apps {
        sqlx::query(
            "INSERT INTO apps \
               (tenant_id, app_key, name, description, url, is_builtin, ua_patterns, referer_patterns, prompt_patterns, suppressed) \
             VALUES ($1, $2, $3, $4, $5, false, $7, $8, $9, false) \
             ON CONFLICT (tenant_id, app_key) DO UPDATE SET \
               name = EXCLUDED.name, description = EXCLUDED.description, url = EXCLUDED.url, \
               is_builtin = apps.is_builtin AND NOT apps.suppressed AND $6, ua_patterns = EXCLUDED.ua_patterns, \
               referer_patterns = EXCLUDED.referer_patterns, prompt_patterns = EXCLUDED.prompt_patterns, \
               suppressed = false, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(&a.id)
        .bind(&a.name)
        .bind(&a.description)
        .bind(&a.url)
        .bind(a.builtin)
        .bind(&a.ua_patterns)
        .bind(&a.referer_patterns)
        .bind(&a.prompt_patterns)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("apps upsert: {e}");
            ApiError::internal("failed to update settings")
        })?;
    }
    let keys: Vec<String> = apps.iter().map(|a| a.id.clone()).collect();
    sqlx::query(
        "UPDATE apps SET suppressed = true, updated_at = now() \
         WHERE tenant_id = $1 AND seeded AND NOT suppressed AND app_key <> ALL($2)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("apps suppress-missing: {e}");
        ApiError::internal("failed to update settings")
    })?;
    sqlx::query(
        "DELETE FROM apps WHERE tenant_id = $1 AND NOT seeded AND app_key <> ALL($2)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("apps delete-missing: {e}");
        ApiError::internal("failed to update settings")
    })?;
    Ok(())
}

/// GET /analytics/apps — returns the merged registry of known + custom AI clients.
#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/apps",
    tag = "Analytics",
    params(super::PageQuery),
    responses(
        (status = 200, description = "Paginated registry of known AI client apps", body = super::TotalPage<AppInfo>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_apps(
    mut db: TenantConn,
    Query(page): Query<super::PageQuery>,
) -> Json<super::TotalPage<AppInfo>> {
    let all = merged_app_registry(db.conn()).await;
    let total = all.len() as i64;
    let (limit, offset) = page.resolve();
    let start = offset.max(0) as usize;
    let end = (start + limit as usize).min(all.len());
    let items = if start < all.len() { all[start..end].to_vec() } else { Vec::new() };
    Json(super::TotalPage::new(items, limit, offset, total))
}

// ── Tool Inventory ───────────────────────────────────────────────────────

// Re-export shared matching from streamscope-core.
use streamscope_core::config::tool_rules::{classify_tool_call, FieldProfileSet, Rule};

/// Load field profiles from system_settings — parallel to `load_risk_rules`.
/// Tenant-isolated query is fine because the audit handlers already run in
/// tenant scope; analytics aggregation reads `system_settings` filtered
/// implicitly via the query path. Falls back to an empty set on error so a
/// classifier still runs (returns `tool_id: None`).
pub(crate) async fn load_field_profiles(executor: &mut Scoped) -> FieldProfileSet {
    match super::tool_field_profiles::load_profiles_rls(executor).await {
        Ok(profiles) => FieldProfileSet::new(profiles),
        Err(e) => {
            tracing::warn!("failed to query tool_field_profiles: {e}");
            FieldProfileSet::default()
        }
    }
}

/// Load risk rules from the `tool_policy_rules` table (RLS-scoped to the
/// executor's tenant). Returns exactly the tenant's rules — including an empty
/// set when every rule has been removed — so the admin-side classifier scores
/// against the same policy the proxy enforces (the snapshot ships these same
/// rows). Falls back to the built-in defaults only on a read error. Malformed
/// rows are dropped with a warn (in `load_rules_rls`).
pub(crate) async fn load_risk_rules(executor: &mut Scoped) -> Vec<Rule> {
    match crate::routes::tool_rules::load_rules_rls(executor).await {
        Ok(rules) => rules,
        Err(e) => {
            tracing::warn!("failed to query tool rules: {e}");
            streamscope_core::config::default_tool_rules()
        }
    }
}

// ── Transform Stats ──────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TransformStatsQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl TransformStatsQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope { workspace_ids: parse_workspace_ids(&self.workspace_ids), ..Default::default() }
    }
}

#[derive(Serialize, ToSchema)]
pub struct TransformStatsResponse {
    pub transforms: Vec<TransformStatEntry>,
    pub total_requests: i64,
    pub requests_with_transforms: i64,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct TransformStatEntry {
    pub name: String,
    /// UUID of the matching `transform_programs` row. `None` when the diff
    /// carries a name that no longer maps to a current program (renamed or
    /// deleted) — UI renders those rows non-clickable rather than producing
    /// a broken `/transforms/<bad-id>` link.
    #[sqlx(default)]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<Uuid>,
    pub total: i64,
    pub modify_count: i64,
    pub pass_count: i64,
    pub error_count: i64,
    pub last_seen: Option<chrono::DateTime<chrono::Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/transforms",
    tag = "Analytics",
    params(TransformStatsQuery),
    responses(
        (status = 200, description = "Transform execution statistics", body = TransformStatsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn transform_stats(
    State(state): State<Arc<AdminState>>,
    db: TenantConn,
    Query(query): Query<TransformStatsQuery>,
) -> Result<Json<TransformStatsResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    tools_store::transform_stats(db, state.db.clone(), start_ts, end_ts, scope).await.map(Json)
}

// ── Tool Inventory ──────────────────────────────────────────────────

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/tools",
    tag = "Analytics",
    params(ToolInventoryQuery),
    responses(
        (status = 200, description = "Tool call inventory with risk classification", body = ToolInventoryResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn tool_inventory(
    mut db: TenantConn,
    Query(query): Query<ToolInventoryQuery>,
) -> Result<Json<ToolInventoryResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    tools_store::tool_inventory_impl(
        db.conn(),
        tenant_id,
        (start_ts, end_ts),
        scope.app_id,
        scope.user_id,
        scope.workspace_ids,
        query.q.as_deref(),
        query.risk,
    )
    .await
        .map(Json)
        .map_err(|e| {
            tracing::error!("tool_inventory: {e}");
            ApiError::internal("database query failed")
        })
}

// ── Tool Invocations Feed (cross-session) ───────────────────────────────

/// Extract a short human-readable summary from tool call arguments.
/// Supports both snake_case (Claude Code) and camelCase (OpenCode) argument names.
fn extract_argument_summary(tool_name: &str, args: &serde_json::Value) -> String {
    let lowered = tool_name.to_ascii_lowercase();
    // Strip dotted prefix (e.g. "repo_browser.read" → "read")
    let base = lowered.rsplit('.').next().unwrap_or(&lowered);

    // Tool-specific candidate keys (first match wins)
    let keys: &[&str] = if base.contains("bash") || base.contains("execute") || base == "run_terminal_cmd" {
        &["command"]
    } else if base.contains("read") || base.contains("write") || base.contains("edit")
        || base == "notebookedit"
    {
        &["file_path", "filePath", "path"]
    } else if base.contains("grep") || base.contains("glob") || base.contains("search_files")
        || base.contains("find_file") || base == "print_tree"
    {
        &["pattern", "path"]
    } else if base.contains("websearch") || base == "web_search" || base.contains("search_web") {
        &["query"]
    } else if base.contains("webfetch") || base.contains("fetch_url") || base.contains("read_url") {
        &["url"]
    } else if base == "agent" || base == "skill" {
        &["prompt"]
    } else {
        &[]
    };

    // Try each candidate key in order, then fall back to first string value
    let val = if !keys.is_empty() {
        keys.iter()
            .find_map(|k| args.get(*k).and_then(|v| v.as_str()))
    } else {
        args.as_object()
            .and_then(|obj| obj.values().find_map(|v| v.as_str()))
    };

    match val {
        Some(s) if s.len() > 120 => {
            let end = s.floor_char_boundary(117);
            format!("{}...", &s[..end])
        }
        Some(s) => s.to_string(),
        None => compact_args_summary(args, 120),
    }
}

/// Render a compact `key: value, key: value` summary from arbitrary JSON args.
fn compact_args_summary(args: &serde_json::Value, max_len: usize) -> String {
    let obj = match args.as_object() {
        Some(o) if !o.is_empty() => o,
        _ => return String::new(),
    };

    let mut buf = String::with_capacity(max_len);
    for (i, (k, v)) in obj.iter().enumerate() {
        if i > 0 {
            buf.push_str(", ");
        }
        buf.push_str(k);
        buf.push_str(": ");
        buf.push_str(&format_compact_value(v, 60));
        if buf.len() > max_len {
            buf.truncate(buf.floor_char_boundary(max_len.saturating_sub(3)));
            buf.push_str("...");
            break;
        }
    }
    buf
}

/// Render a single JSON value compactly for argument summaries.
fn format_compact_value(v: &serde_json::Value, max_len: usize) -> String {
    match v {
        serde_json::Value::String(s) => {
            if s.len() > max_len {
                let end = s.floor_char_boundary(max_len.saturating_sub(3));
                format!("{}...", &s[..end])
            } else {
                s.clone()
            }
        }
        serde_json::Value::Array(arr) => format!("[{} items]", arr.len()),
        serde_json::Value::Object(obj) => format!("{{{} keys}}", obj.len()),
        serde_json::Value::Null => "null".into(),
        serde_json::Value::Bool(b) => b.to_string(),
        serde_json::Value::Number(n) => n.to_string(),
    }
}

// ── Tool Calls Feed (cross-protocol, cross-session) ───────────────────────
//
// `/api/v1/admin/tool-calls` exposes a discriminated `ToolCallRow` union
// (LLM / MCP / Web). `kind=all` merges all three server-side by
// `timestamp DESC`. Mirrors the audit-page pattern: one card list, one
// filter bar grouped Kind → Common → Kind-specific, server-side merge.

/// The row families of the tool-calls feed: a tool call is made over LLM
/// tool use, MCP or the built-in Web tool. An agent call (A2A) is not a tool
/// call, so `a2a` is not a value here — the audit list carries those.
#[derive(Debug, Clone, Copy, PartialEq, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolCallKind {
    Llm,
    Mcp,
    Web,
    #[default]
    All,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ToolCallsQuery {
    /// Row family to return. Defaults to `all` (mixed chronology of every
    /// kind). Distinct from `/audit?kind=*` default of `llm` — the tool-calls
    /// page is built around the cross-protocol mixed view.
    pub kind: Option<ToolCallKind>,
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub app_id: Option<String>,
    pub user_id: Option<Uuid>,
    pub user_email: Option<String>,
    pub search: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Focus a single row by `request_id` (MCP / Web side) for deep-link
    /// auto-expand. LLM rows use `invocation_id` on the client side
    /// instead — see `/tool-calls/+page.svelte` for the resolver.
    pub request_id: Option<Uuid>,
    // ── LLM-specific filters ───────────────────────────────────────────
    pub tool_name: Option<String>,
    /// What happened to the call.
    pub outcome: Option<ToolCallOutcome>,
    // ── MCP-specific filters ───────────────────────────────────────────
    pub tool_id: Option<String>,
    pub resource_uri: Option<String>,
    pub prompt_id: Option<String>,
    pub virtual_server_id: Option<Uuid>,
    pub upstream_server_id: Option<Uuid>,
    // ── Web-specific filters ───────────────────────────────────────────
    /// `mcp` | `substitution` | `admin_test`.
    pub surface: Option<String>,
    /// `search` | `fetch`.
    pub operation: Option<String>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl ToolCallsQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    /// Whose rows every arm of the feed may return: the `user_id` and
    /// `workspace_ids` the console sent, over the whole tenant otherwise.
    fn audit_scope(&self) -> AuditScope {
        AuditScope::tenant(self.user_id, self.workspace_ids.clone())
    }
}

/// `kind`-discriminated row family for the unified tool-calls feed. UI
/// branches on `row.kind` and dispatches to the matching detail component.
/// Boxed variants because `WebAuditLogEntry` is wide (~1 KB of optional
/// JSON columns) and the size mismatch with the LLM shape would blow up
/// per-row allocation in the `kind=all` merge.
#[derive(Serialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ToolCallRow {
    Llm {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<ToolInvocation>,
    },
    Mcp {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<super::audit::McpAuditLogEntry>,
    },
    Web {
        #[serde(flatten)]
        #[schema(inline)]
        entry: Box<super::audit::WebAuditLogEntry>,
    },
}

fn tool_call_row_timestamp(row: &ToolCallRow) -> chrono::DateTime<chrono::Utc> {
    match row {
        ToolCallRow::Llm { entry } => entry.timestamp,
        ToolCallRow::Mcp { entry } => entry.timestamp,
        ToolCallRow::Web { entry } => entry.timestamp,
    }
}

#[derive(Serialize, Clone, ToSchema)]
pub struct ToolInvocation {
    pub invocation_id: String,
    pub tool_name: String,
    pub tool_use_id: String,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_display: String,
    /// Raw email of the row's user (when resolved). Distinct from
    /// `user_display` (which falls back to display name or id). Drives the
    /// row-card "filter by user" button so the click reapplies a precise
    /// email filter, not the display-name fallback.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    pub call_request_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_request_id: Option<String>,
    /// Call-side `gateway_audit.latency_total_ms`. Surfaced on the unified
    /// tool-call row card's header strip so LLM rows align visually with
    /// MCP / web rows. `None` for synthetic blocked invocations whose call
    /// turn was suppressed before the latency was stamped.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_total_ms: Option<i64>,
    /// Outcome tags: any of `ok`, `blocked_request`, `blocked_response`,
    /// `not_applied_response`, `redacted`, `args_modified`.
    pub outcomes: Vec<String>,
    /// Canonical `ConversationEvent::ToolCall` event — rendered by the UI with
    /// the same component the session view uses.
    pub call_event: crate::conversation::ConversationEvent,
    /// Canonical `ConversationEvent::ToolResult` event when paired.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_event: Option<crate::conversation::ConversationEvent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_definition: Option<streamscope_core::api::domain_request::DomainToolSummary>,
    pub argument_summary: String,
    pub risk_level: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub risk_title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub redaction: Option<streamscope_core::proxy::content::RedactedToolResultInfo>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub block_info: Option<streamscope_core::proxy::content::BlockedToolInfo>,
}

// Response envelope: we use the shared `OffsetPage<ToolInvocation>` directly
// (`items + limit + offset + has_more`) — no `total`, since the over-fetch
// + in-memory expansion would make an accurate DB count prohibitively
// expensive without a separate COUNT query. Matches the pagination shape
// every other list endpoint already uses.

#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-calls",
    tag = "Analytics",
    params(ToolCallsQuery),
    responses(
        (status = 200, description = "Unified tool-call feed (LLM / MCP / Web, kind-discriminated)", body = super::OffsetPage<ToolCallRow>),
        (status = 400, description = "Invalid window or kind, a search term under 3 characters, or the page is too deep", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn tool_calls(
    mut db: TenantConn,
    Query(q): Query<ToolCallsQuery>,
) -> Result<Json<super::OffsetPage<ToolCallRow>>, ApiError> {
    use super::audit::{AuditKind, AuditQuery};

    let limit = q.limit.unwrap_or(50).clamp(1, 200);
    let offset = crate::routes::resolve_offset(q.offset);
    let kind = q.kind.unwrap_or_default();
    // The LLM arm walks turns in memory, and `All` merges every arm in memory.
    if matches!(kind, ToolCallKind::Llm | ToolCallKind::All) {
        super::check_merged_offset(offset)?;
    }
    let target = limit + offset + 1;
    // Deep-link focus widens the default window to ~1 year so MCP / Web
    // rows older than the rolling 24h still resolve. Mirrors the LLM
    // helper's per-row widening (`collect_tool_invocations`).
    let default_days = if q.request_id.is_some() { 365 } else { 1 };
    let (start_ts, end_ts) = q.time_window().resolve(default_days)?;
    super::check_search(q.search.as_deref())?;

    // The user and the workspace selection are this console request's own, and
    // travel as ONE `AuditScope` to every arm — the LLM walk and the MCP / Web
    // helpers alike honour the same multi-id `workspace_ids` set.
    let scope = q.audit_scope();
    // The `AuditQuery` for the MCP / Web helpers: only fields a given helper
    // inspects are set; LLM-only knobs (`model`, `finish_reason`, etc.) are
    // deliberately left out.
    let make_audit_query = |kind: AuditKind, methods: Option<String>| {
        let mut query = AuditQuery::default();
        query.user_email = q.user_email.clone();
        query.app_id = q.app_id.clone();
        query.start = Some(start_ts);
        query.end = Some(end_ts);
        query.search = q.search.clone();
        query.request_id = q.request_id;
        query.kind = Some(kind);
        query.methods = methods;
        query.tool_id = q.tool_id.clone();
        query.resource_uri = q.resource_uri.clone();
        query.prompt_id = q.prompt_id.clone();
        query.virtual_server_id = q.virtual_server_id;
        query.upstream_server_id = q.upstream_server_id;
        query.surface = q.surface.clone();
        query.operation = q.operation.clone();
        query
    };

    if kind == ToolCallKind::Llm {
        let (mut invs, hit_cap) =
            collect_tool_invocations(&mut db, &q, &scope, target as usize).await?;
        let start = (offset as usize).min(invs.len());
        let end = ((offset + limit + 1) as usize).min(invs.len());
        let page_rows: Vec<ToolCallRow> = invs
            .drain(start..end)
            .map(|t| ToolCallRow::Llm { entry: Box::new(t) })
            .collect();
        let mut page = super::OffsetPage::from_overfetched(page_rows, limit, offset);
        if hit_cap {
            page.has_more = true;
        }
        return Ok(Json(page));
    }

    if kind == ToolCallKind::Mcp {
        let mcp_query = make_audit_query(
            AuditKind::Mcp,
            Some("tools/call,resources/read,prompts/get".into()),
        );
        let rows = crate::audit_store::logs::list_audit_logs_mcp(
            db.conn(),
            &mcp_query,
            &scope,
            limit,
            offset,
        )
        .await?;
        let wrapped: Vec<ToolCallRow> = rows
            .into_iter()
            .map(|entry| ToolCallRow::Mcp { entry: Box::new(entry) })
            .collect();
        return Ok(Json(super::OffsetPage::from_overfetched(
            wrapped, limit, offset,
        )));
    }

    if kind == ToolCallKind::Web {
        let web_query = make_audit_query(AuditKind::Web, None);
        let rows = crate::audit_store::logs::list_audit_logs_web(
            db.conn(),
            &web_query,
            &scope,
            limit,
            offset,
            None,
        )
        .await?;
        let wrapped: Vec<ToolCallRow> = rows
            .into_iter()
            .map(|entry| ToolCallRow::Web { entry: Box::new(entry) })
            .collect();
        return Ok(Json(super::OffsetPage::from_overfetched(
            wrapped, limit, offset,
        )));
    }

    // `kind == All` — over-fetch each side, merge by timestamp DESC, slice.
    // Identical structure to `audit_store::logs::list_audit_logs_all`.
    let (llm_invs, hit_cap) =
        collect_tool_invocations(&mut db, &q, &scope, target as usize).await?;
    let mcp_query = make_audit_query(
        AuditKind::Mcp,
        Some("tools/call,resources/read,prompts/get".into()),
    );
    let mcp_rows = crate::audit_store::logs::list_audit_logs_mcp(
        db.conn(),
        &mcp_query,
        &scope,
        target,
        0,
    )
    .await?;
    let web_query = make_audit_query(AuditKind::Web, None);
    let web_rows = crate::audit_store::logs::list_audit_logs_web(
        db.conn(),
        &web_query,
        &scope,
        target,
        0,
        None,
    )
    .await?;

    let mut all: Vec<ToolCallRow> =
        Vec::with_capacity(llm_invs.len() + mcp_rows.len() + web_rows.len());
    for inv in llm_invs {
        all.push(ToolCallRow::Llm { entry: Box::new(inv) });
    }
    for row in mcp_rows {
        all.push(ToolCallRow::Mcp { entry: Box::new(row) });
    }
    for row in web_rows {
        all.push(ToolCallRow::Web { entry: Box::new(row) });
    }
    // A stable sort on the timestamp: rows sharing one keep their arm's own
    // order (each arm is totally ordered — the turn walk and the MCP / web
    // queries break a tie on the request id), and arms tie in the order they
    // were appended, so the merged order is total and a page boundary exact.
    all.sort_by_key(|row| std::cmp::Reverse(tool_call_row_timestamp(row)));

    let start = (offset as usize).min(all.len());
    let end = ((offset + limit + 1) as usize).min(all.len());
    let page_rows: Vec<ToolCallRow> = all.drain(start..end).collect();
    let mut page = super::OffsetPage::from_overfetched(page_rows, limit, offset);
    if hit_cap {
        page.has_more = true;
    }
    Ok(Json(page))
}

/// Whether a value inside `value` contains `term` (already lowercased): the
/// argument VALUES, as `tool_call_search_blob` holds them — an object's keys
/// and the JSON punctuation are not searched. A raw argument string (the
/// Chat Completions shape) is searched whole, as the blob stores it.
fn json_values_contain(value: &serde_json::Value, term: &str) -> bool {
    match value {
        serde_json::Value::String(s) => s.to_lowercase().contains(term),
        serde_json::Value::Number(n) => n.to_string().contains(term),
        serde_json::Value::Bool(b) => b.to_string().contains(term),
        serde_json::Value::Array(items) => items.iter().any(|v| json_values_contain(v, term)),
        serde_json::Value::Object(map) => map.values().any(|v| json_values_contain(v, term)),
        serde_json::Value::Null => false,
    }
}

/// Walk session turns synthesizing `ToolInvocation` rows until we have
/// `target` of them (or hit `HARD_TURN_CAP`). Returns the collected rows
/// sorted `timestamp DESC` plus a flag indicating whether the scan stopped
/// at the defensive ceiling. The caller slices and wraps with
/// `OffsetPage::from_overfetched`; passing `target = offset + limit + 1`
/// gives the standard `has_more` sentinel shape.
async fn collect_tool_invocations(
    db: &mut TenantConn,
    query: &ToolCallsQuery,
    scope: &AuditScope,
    target: usize,
) -> Result<(Vec<ToolInvocation>, bool), ApiError> {
    use crate::conversation::{build_events, stored_protocol, ConversationEvent, TurnRow};

    // A deep-link focus (`?invocation_id=…` or `?request_id=…`) widens the
    // default window to ~1 year so a turn outside the rolling 24h still
    // resolves. The LATERAL next-turn JOIN is bounded by the same window
    // for Memoize stability — dropping it entirely would defeat that
    // optimization (>5× slower warm-cache at 30-day scale). 365 days is the
    // same heuristic the audit page would apply by simply not sending
    // start/end.
    let default_days = if query.request_id.is_some() { 365 } else { 1 };
    let (start_ts, end_ts) = query.time_window().resolve(default_days)?;
    let tenant_id = db.tenant_uuid();

    // The term once: its contains-pattern, its prefix pattern, and (below) the
    // folded text the per-call filter tests.
    let term = search_text(query.search.as_deref());
    let search = term.as_deref().map(|t| (contains_pattern(t), prefix_pattern(t)));

    // Batched keyset-cursor fetch — chunks ordered by
    // `(timestamp DESC, request_id DESC)` until `target` post-filter
    // invocations are collected or `HARD_TURN_CAP` is hit. The cap bounds
    // memory for pathological scroll depths under dense tool use combined
    // with `outcome` / `search` / `tool_name` narrowing.
    const HARD_TURN_CAP: i64 = 100_000;

    let turns = tools_store::ToolCallTurns::new(
        tenant_id,
        (start_ts, end_ts),
        scope,
        query.app_id.as_deref(),
        query.user_email.as_deref(),
        query.request_id,
        search,
    );

    let risk_rules = load_risk_rules(db.conn()).await;
    let field_profiles = load_field_profiles(db.conn()).await;
    let tool_name_filter = query.tool_name.as_ref().map(|s| s.to_ascii_lowercase());
    let outcome_filter = query.outcome;
    // The term the SQL binds, folded like ILIKE folds, so what the SQL
    // admitted (a non-ASCII or NUL-bearing term included) is what is tested here.
    let search_term = term.as_deref().map(str::to_lowercase);

    let mut invocations: Vec<ToolInvocation> = Vec::new();
    let mut cursor: Option<(chrono::DateTime<chrono::Utc>, Uuid)> = None;
    let mut turns_scanned: i64 = 0;
    let mut hit_hard_cap = false;

    while invocations.len() < target {
        if turns_scanned >= HARD_TURN_CAP {
            hit_hard_cap = true;
            break;
        }
        let mut batch = turns.batch(db.conn(), cursor).await.map_err(|e| {
            tracing::error!("collect_tool_invocations query: {e}");
            ApiError::internal("database query failed")
        })?;
        if batch.is_empty() {
            break;
        }
        turns_scanned += batch.len() as i64;
        // Advance cursor to the oldest row we just scanned so the next
        // batch strictly precedes it in the keyset ordering.
        if let Some(last) = batch.last() {
            cursor = Some((last.timestamp, last.request_id));
        }

        // Resolve the answering turns' messages for this batch only — avoids
        // a cross-batch pre-scan and keeps memory proportional to one batch
        // (`BATCH_SIZE`, in `audit_store/analytics/tools.rs`). Each row's
        // hashes are narrowed (`trace::answer_hashes`) before any body is
        // fetched; the call turn's own messages are never rendered: only its
        // calls are listed.
        let answer_hashes: Vec<Vec<String>> = batch
            .iter_mut()
            .map(|r| {
                crate::audit_store::trace::answer_hashes(
                    r.next_sliced.unwrap_or(false),
                    r.next_hashes.take(),
                    r.call_message_hashes.as_deref().unwrap_or_default(),
                )
            })
            .collect();
        let hash_set: std::collections::HashSet<String> =
            answer_hashes.iter().flatten().cloned().collect();
        let hash_vec: Vec<String> = hash_set.into_iter().collect();
        let hash_to_msg: std::collections::HashMap<String, serde_json::Value> =
            crate::content_store::messages::get_many(db.conn(), tenant_id, &hash_vec)
                .await
                .map_err(|e| {
                    tracing::error!("collect_tool_invocations message fetch: {e}");
                    ApiError::internal("database query failed")
                })?;

    for (r, answer) in batch.into_iter().zip(answer_hashes) {
        let Some(proto) = stored_protocol(&r.api_version, r.request_id) else {
            continue;
        };
        // No history: the feed lists the calls this turn's answer made, which
        // `build_events` reads from the response alone.
        let messages_arr = serde_json::Value::Array(Vec::new());
        let model_str = r.model_requested.as_deref().or(r.model_used.as_deref()).unwrap_or("");
        // Decode the full transform_diff once so the ToolCall event join in
        // `build_events` can attach response-phase block metadata.
        let parsed_transform_diff: Option<streamscope_core::proxy::content::TransformDiff> = r
            .transform_diff
            .as_ref()
            .and_then(|v| serde_json::from_value(v.clone()).ok());
        let turn = TurnRow {
            turn_number: r.turn_number,
            protocol: proto,
            system_prompt: None,
            messages_json: &messages_arr,
            request_tools: r.request_tools.as_deref(),
            // Hashes not needed here — invocations feed doesn't surface
            // ToolsChanged events (they belong on the session viewer).
            tools_available_hash: None,
            tools_effective_hash: None,
            request_params: r.request_params.as_ref(),
            response_content: r.response_content.as_deref(),
            response_tool_calls: r.response_tool_calls.as_ref(),
            thinking: None,
            model: model_str,
            metadata: None,
            include_raw: false,
            // Only the response's own ToolCall events are read, and there is
            // no history to filter.
            dedup_filtered: false,
            transform_diff: parsed_transform_diff.as_ref(),
        };
        let call_events = match build_events(&turn) {
            Ok(b) => b.events,
            Err(e) => {
                tracing::warn!("collect_tool_invocations: build_events failed for call turn: {e}");
                continue;
            }
        };

        let (result_events, result_req_id) = if let (Some(next_req_id), Some(next_turn_number)) =
            (r.next_request_id, r.next_turn_number)
        {
            'answer: {
                // An answering turn whose protocol does not parse pairs no result.
                let Some(next_proto) =
                    r.next_api_version.as_deref().and_then(|v| stored_protocol(v, next_req_id))
                else {
                    break 'answer (Vec::new(), Some(next_req_id));
                };
                // The messages the client appended for the answering turn (the
                // tool_result blocks we want to pair), narrowed above. Then
                // `dedup_filtered=true` makes `build_events` mark them is_new=true.
                let next_messages_filtered = serde_json::Value::Array(
                    answer.iter().filter_map(|h| hash_to_msg.get(h).cloned()).collect(),
                );
                let next_model = r
                    .next_model_requested
                    .as_deref()
                    .or(r.next_model_used.as_deref())
                    .unwrap_or("");
                // The next turn's `transform_diff` carries any request-phase
                // tool_result redactions fired when the client posted the
                // `tool_result` for this invocation's tool_use — `build_events`
                // joins `redacted_tool_results[].tool_use_id` against the
                // `ToolResult` events it emits and stamps `redacted` on them.
                // Without this the /tools feed would silently drop the redaction
                // banner that the session view already shows correctly.
                // Only its redaction records: its own answer is not read, so
                // its response-phase records name nothing here.
                let next_transform_diff: Option<streamscope_core::proxy::content::TransformDiff> = r
                    .next_transform_diff
                    .as_ref()
                    .and_then(|v| serde_json::from_value(v.clone()).ok())
                    .map(|diff: streamscope_core::proxy::content::TransformDiff| {
                        streamscope_core::proxy::content::TransformDiff {
                            response_blocked_tools: None,
                            intercepted_tool_calls: None,
                            ..diff
                        }
                    });
                let next_turn = TurnRow {
                    // The answering turn's own number: a child need not be the
                    // call turn's next turn by number.
                    turn_number: next_turn_number,
                    protocol: next_proto,
                    // Only its request is read: its ToolResult events, and the
                    // calls it sends back. Its own answer's calls are none of
                    // those, so it is left out.
                    system_prompt: None,
                    messages_json: &next_messages_filtered,
                    request_tools: r.next_request_tools.as_deref(),
                    tools_available_hash: None,
                    tools_effective_hash: None,
                    request_params: r.next_request_params.as_ref(),
                    response_content: None,
                    response_tool_calls: None,
                    thinking: None,
                    model: next_model,
                    metadata: None,
                    include_raw: false,
                    dedup_filtered: true,
                    transform_diff: next_transform_diff.as_ref(),
                };
                match build_events(&next_turn) {
                    Ok(b) => (b.events, Some(next_req_id)),
                    Err(e) => {
                        tracing::warn!("collect_tool_invocations: build_events failed for result turn: {e}");
                        (Vec::new(), Some(next_req_id))
                    }
                }
            }
        } else {
            (Vec::new(), None)
        };

        // Each of this turn's calls with its result, by the call's place.
        let mut results = crate::conversation::pair_results(&call_events, &result_events);

        // Request-phase block records (`transform_diff.blocked_tools`) are
        // intentionally NOT listed in the /tools invocations feed — the tool
        // was stripped before the model ran so there is no call to show. They
        // surface on the turn's REQUEST PARAMS header in the session view.
        // The list `build_events` read, so a pinned record names its entry.
        let blocked_resp_infos: &[streamscope_core::proxy::content::BlockedToolInfo] = parsed_transform_diff
            .as_ref()
            .and_then(|diff| diff.response_blocked_tools.as_deref())
            .unwrap_or_default();
        // Canonical, protocol-normalized tool definitions — same helper the
        // proxy/session view uses. Never parse raw `request_tools` JSON here.
        let normalized_tools: Vec<streamscope_core::api::domain_request::DomainToolSummary> = r
            .request_tools
            .as_deref()
            .and_then(|v| {
                streamscope_core::api::domain_request::parse_stored_tools(proto, v)
            })
            .unwrap_or_default();
        let find_tool_def = |name: &str| -> Option<streamscope_core::api::domain_request::DomainToolSummary> {
            normalized_tools.iter().find(|t| t.name == name).cloned()
        };

        // The SQL predicate admitted this turn on its calls' names and arguments
        // (as JSON, punctuation included), a removed call's record, the user's
        // email or display name, or the session id from its start. Narrow to the
        // calls that match; when none does on its own — a match on the email, on
        // the arguments' JSON syntax, … — keep every call of the turn. A turn the SQL admitted must yield a row,
        // or a term matching every turn there and none here walks the scan up to
        // `HARD_TURN_CAP` for an empty page.
        // The turn's own record — user, email, session — matches every call.
        let record_matches = search_term.as_deref().is_some_and(|term| {
            r.user_display.as_deref().unwrap_or("").to_lowercase().contains(term)
                || r.user_email.as_deref().unwrap_or("").to_lowercase().contains(term)
                || r.session_id.to_string().starts_with(term)
        });
        let call_matches = |name: &str, arguments: &serde_json::Value, term: &str| -> bool {
            record_matches
                || name.to_lowercase().contains(term)
                || json_values_contain(arguments, term)
        };
        let blocked_matches = |info: &streamscope_core::proxy::content::BlockedToolInfo, term: &str| {
            record_matches
                || info.name.to_lowercase().contains(term)
                || info.description.to_lowercase().contains(term)
                || info.arguments.as_ref().is_some_and(|a| json_values_contain(a, term))
        };
        // Per event, whether it matches the term (`true` with no term) —
        // computed once, read below. Only this turn's own calls are listed;
        // history replayed in the request is skipped, so it is not tested.
        let call_hits: Vec<bool> = call_events
            .iter()
            .map(|ev| match (ev, search_term.as_deref()) {
                (ConversationEvent::ToolCall { name, arguments, is_new: true, blocked, .. }, Some(term)) => {
                    // A record pinned on the call speaks for it, as for a stripped
                    // one — the arguments policy read (healed) included.
                    call_matches(name, arguments, term)
                        || blocked.as_ref().is_some_and(|pinned| {
                            pinned.reason.to_lowercase().contains(term)
                                || pinned.rule_title.as_deref().is_some_and(|t| t.to_lowercase().contains(term))
                                || pinned
                                    .record
                                    .and_then(|at| blocked_resp_infos.get(at))
                                    .is_some_and(|info| blocked_matches(info, term))
                        })
                }
                _ => true,
            })
            .collect();
        let some_call_matches = search_term.as_deref().is_some_and(|term| {
            call_events
                .iter()
                .zip(&call_hits)
                .any(|(ev, hit)| *hit && matches!(ev, ConversationEvent::ToolCall { is_new: true, .. }))
                || blocked_resp_infos.iter().any(|info| blocked_matches(info, term))
        });

        // The records pinned on a call, so the rows below list only the others.
        let mut pinned_records: std::collections::HashSet<usize> = std::collections::HashSet::new();
        // A call's place among this turn's calls: its row's key.
        let mut place: usize = 0;
        for (event_at, (ev, call_hit)) in call_events.iter().zip(&call_hits).enumerate() {
            if let ConversationEvent::ToolCall { is_new: true, blocked: Some(pinned), .. } = ev {
                pinned_records.extend(pinned.record);
            }
            if let ConversationEvent::ToolCall {
                name,
                id,
                arguments,
                is_new,
                blocked,
                ..
            } = ev
            {
                // Only count tool_calls the model emitted THIS turn; historical
                // tool_calls replayed in the request (Anthropic: user message
                // echoes prior assistant tool_use) would otherwise show up as
                // separate invocations at every subsequent turn.
                if !is_new {
                    continue;
                }
                let call_place = place;
                place += 1;
                if let Some(f) = &tool_name_filter
                    && !name.to_ascii_lowercase().contains(f)
                {
                    continue;
                }
                if some_call_matches && !call_hit {
                    continue;
                }
                let risk = classify_tool_call(
                    &risk_rules,
                    None,
                    r.app_id.as_deref(),
                    Some(&field_profiles),
                    name,
                    Some(arguments),
                );
                let mut outcomes = Vec::new();
                // The record `build_events` pinned on this call, so a row and the
                // conversation name one call: an answer an out-of-band exchange
                // recorded keeps calls of the same tool policy let through.
                let block_info = blocked
                    .as_ref()
                    .and_then(|pinned| pinned.record)
                    .and_then(|at| blocked_resp_infos.get(at))
                    .cloned();
                if let Some(pinned) = blocked {
                    outcomes.push(if pinned.not_applied { "not_applied_response" } else { "blocked_response" }.to_string());
                }
                // The call's own result, and the redaction `build_events` pinned
                // on it from the answering turn's record.
                let result_event_val = results.get_mut(event_at).and_then(Option::take);
                let redaction = match &result_event_val {
                    Some(ConversationEvent::ToolResult { redacted, .. }) => redacted.clone(),
                    _ => None,
                };
                if redaction.is_some() {
                    outcomes.push("redacted".to_string());
                }
                if outcomes.is_empty() {
                    outcomes.push("ok".to_string());
                }

                let summary = extract_argument_summary(name, arguments);
                if let Some(of) = outcome_filter {
                    let matches = match of {
                        ToolCallOutcome::Ok => outcomes.iter().any(|o| o == "ok"),
                        ToolCallOutcome::Blocked => outcomes.iter().any(|o| o.starts_with("blocked_")),
                        ToolCallOutcome::NotApplied => outcomes.iter().any(|o| o == "not_applied_response"),
                        ToolCallOutcome::Redacted => outcomes.iter().any(|o| o == "redacted"),
                        ToolCallOutcome::ArgsModified => outcomes.iter().any(|o| o == "args_modified"),
                    };
                    if !matches {
                        continue;
                    }
                }

                invocations.push(ToolInvocation {
                    invocation_id: format!("{}:{}", r.request_id, call_place),
                    tool_name: name.clone(),
                    tool_use_id: id.clone(),
                    timestamp: r.timestamp,
                    user_display: r.user_display.clone().unwrap_or_default(),
                    user_email: r.user_email.clone(),
                    session_id: r.session_id.to_string(),
                    app_id: r.app_id.clone(),
                    call_request_id: r.request_id.to_string(),
                    result_request_id: result_req_id.map(|u| u.to_string()),
                    latency_total_ms: r.latency_total_ms,
                    outcomes,
                    call_event: ev.clone(),
                    result_event: result_event_val,
                    tool_definition: find_tool_def(name),
                    argument_summary: summary,
                    risk_level: risk.risk,
                    risk_title: risk.title,
                    redaction,
                    block_info,
                });
            }
        }

        // List a response-phase record that pinned no call (`build_events`
        // pins each on its call, rebuilding a stripped one) on a row of its
        // own, with the rule-identity banner attached via `blocked`.
        //
        // Request-phase blocks are NOT synthesized here: the tool never
        // reached the model, so there is no call to show in the tool log.
        // Those surface on the turn's REQUEST PARAMS header in the session
        // view instead. An entry not applied stripped nothing: its call has its own
        // row, unless the row keeps only the answer's first choice.
        for (at, info) in blocked_resp_infos.iter().enumerate() {
            // A record pinned on a call is that call's row.
            if pinned_records.contains(&at) {
                continue;
            }
            let (phase_tag, phase_outcome) = if info.not_applied {
                ("not_applied_response", ToolCallOutcome::NotApplied)
            } else {
                ("blocked_response", ToolCallOutcome::Blocked)
            };
            if let Some(f) = &tool_name_filter
                && !info.name.to_ascii_lowercase().contains(f)
            {
                continue;
            }
            if outcome_filter.is_some_and(|of| of != phase_outcome) {
                continue;
            }
            // The same rule as the ToolCall branch above: narrow to the blocked
            // records that match when some call or record of the turn does.
            if let Some(term) = &search_term
                && some_call_matches
                && !blocked_matches(info, term)
            {
                continue;
            }
            let synthetic_block = Some(Box::new(crate::conversation::ToolCallBlock::of_record(at, info)));
            let synthetic = ConversationEvent::ToolCall {
                name: info.name.clone(),
                arguments: info.arguments.clone().unwrap_or(serde_json::json!({})),
                id: info.name.clone(),
                turn: r.turn_number,
                is_new: true,
                metadata: None,
                raw: None,
                risk_level: Some("blocked".to_string()),
                risk_description: Some(info.description.clone()),
                blocked: synthetic_block,
                intercepted: None,
                modifications: None,
            };
            invocations.push(ToolInvocation {
                invocation_id: format!("{}:{}:{}", r.request_id, phase_tag, at),
                tool_name: info.name.clone(),
                tool_use_id: String::new(),
                timestamp: r.timestamp,
                user_display: r.user_display.clone().unwrap_or_default(),
                user_email: r.user_email.clone(),
                session_id: r.session_id.to_string(),
                app_id: r.app_id.clone(),
                call_request_id: r.request_id.to_string(),
                result_request_id: None,
                latency_total_ms: r.latency_total_ms,
                outcomes: vec![phase_tag.to_string()],
                call_event: synthetic,
                result_event: None,
                tool_definition: find_tool_def(&info.name),
                argument_summary: info.description.clone(),
                risk_level: "blocked".to_string(),
                risk_title: Some(info.title.clone()),
                redaction: None,
                block_info: Some(info.clone()),
            });
        }
    }
    } // end while cursor loop

    // Newest first. The sort is stable: calls of one turn share its timestamp
    // and keep the order they were made in (the walk reads turns by
    // timestamp, then request id).
    invocations.sort_by_key(|i| std::cmp::Reverse(i.timestamp));
    if hit_hard_cap {
        tracing::warn!(
            "collect_tool_invocations hit HARD_TURN_CAP after scanning {turns_scanned} turns; \
             returning truncated set (tenant={tenant_id}, target={target})"
        );
    }
    Ok((invocations, hit_hard_cap))
}

// ── Timeseries ──────────────────────────────────────────────────────────

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct TimeseriesQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    pub user_id: Option<Uuid>,
    pub app_id: Option<String>,
    pub model: Option<String>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl TimeseriesQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope {
            user_id: self.user_id,
            app_id: self.app_id.clone(),
            model: self.model.clone(),
            workspace_ids: parse_workspace_ids(&self.workspace_ids),
            ..Default::default()
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct TimeseriesBucket {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub request_count: i64,
    pub error_count: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub reasoning_tokens: i64,
    /// What this bucket spent, and in which currency. `null` when the bucket
    /// straddles a change of the tenant's accounting currency — its rows are
    /// then in different denominations and no single figure states them.
    pub spend: Option<SpendTotal>,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
}

#[derive(Serialize, ToSchema)]
pub struct TimeseriesResponse {
    pub interval: String,
    pub buckets: Vec<TimeseriesBucket>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/timeseries",
    tag = "Analytics",
    params(TimeseriesQuery),
    responses(
        (status = 200, description = "Usage timeseries buckets", body = TimeseriesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn usage_timeseries(
    mut db: TenantConn,
    Query(query): Query<TimeseriesQuery>,
) -> Result<Json<TimeseriesResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(1)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    usage::usage_timeseries(db.conn(), tenant_id, start_ts, end_ts, scope).await.map(Json)
}

// ── Users & Keys Dashboard ──────────────────────────────────────────

#[derive(Serialize, ToSchema)]
pub struct UsersKeysDashboard {
    pub summary: UserKeysSummary,
    pub top_users_by_cost: Vec<TopUserEntry>,
    pub top_keys_by_requests: Vec<TopKeyEntry>,
    pub dormant_keys: Vec<DormantKeyEntry>,
    pub expiring_soon: Vec<ExpiringKeyEntry>,
}

#[derive(Serialize, ToSchema)]
pub struct UserKeysSummary {
    pub total_users: i64,
    pub active_users: i64,
    pub disabled_users: i64,
    pub active_keys: i64,
    pub expired_keys: i64,
    pub revoked_keys: i64,
    pub total_requests: i64,
    /// What the window cost, and in which currency. `null` when the window
    /// straddles a change of the tenant's accounting currency.
    pub spend: Option<SpendTotal>,
}

/// One user of the spend ranking, ordered by the shared spend rule: by what
/// the user spent in today's accounting currency, largest first; users with
/// nothing in it follow, by currency code, then by amount within one
/// currency. A user whose window straddles a currency change reports
/// `spend: null` but keeps its place by its spend in today's currency.
#[derive(Serialize, ToSchema)]
pub struct TopUserEntry {
    pub user_id: Uuid,
    pub email: Option<String>,
    pub display_name: Option<String>,
    pub request_count: i64,
    /// `null` when this user's window straddles a change of the accounting
    /// currency.
    pub spend: Option<SpendTotal>,
}

#[derive(Serialize, ToSchema)]
pub struct TopKeyEntry {
    pub key_id: Uuid,
    pub key_name: Option<String>,
    pub key_prefix: String,
    pub user_id: Uuid,
    pub user_email: Option<String>,
    pub user_display_name: Option<String>,
    pub request_count: i64,
    /// `null` when this key's window straddles a change of the accounting
    /// currency.
    pub spend: Option<SpendTotal>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub workspace_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct DormantKeyEntry {
    pub key_id: Uuid,
    pub key_name: Option<String>,
    pub key_prefix: String,
    pub user_email: Option<String>,
    pub last_used_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
    pub workspace_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ExpiringKeyEntry {
    pub key_id: Uuid,
    pub key_name: Option<String>,
    pub key_prefix: String,
    pub user_email: Option<String>,
    pub expires_at: DateTime<Utc>,
    pub days_remaining: i32,
    pub workspace_name: Option<String>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UsersKeysDaysQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl UsersKeysDaysQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope { workspace_ids: parse_workspace_ids(&self.workspace_ids), ..Default::default() }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/users-keys",
    tag = "Analytics",
    params(UsersKeysDaysQuery),
    responses(
        (status = 200, description = "Users and keys dashboard", body = UsersKeysDashboard),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn users_keys_dashboard(
    State(state): State<Arc<AdminState>>,
    db: TenantConn,
    Query(query): Query<UsersKeysDaysQuery>,
) -> Result<Json<UsersKeysDashboard>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    usage::users_keys_dashboard(db, state.db.clone(), start_ts, end_ts, scope).await.map(Json)
}

// ---------------------------------------------------------------------------
// Proxy Dashboard
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct ProxyDashboard {
    pub protocol_stats: Vec<ProtocolStats>,
    pub translation_stats: TranslationStats,
}

#[derive(Serialize, Clone, ToSchema)]
pub struct ProtocolStats {
    pub api_version: String,
    /// Requests that arrived in this protocol — the client's inbound wire format.
    pub inbound_count: i64,
    /// Requests sent upstream in this protocol, after any protocol translation.
    pub outbound_count: i64,
    pub total_tokens: i64,
    pub error_count: i64,
    /// What this protocol's requests cost, and in which currency. `null` when
    /// the window straddles a change of the tenant's accounting currency.
    pub spend: Option<SpendTotal>,
}

#[derive(Serialize, ToSchema)]
pub struct TranslationStats {
    pub total_translated: i64,
    pub pairs: Vec<TranslationPair>,
}

#[derive(Serialize, ToSchema)]
pub struct TranslationPair {
    pub from_protocol: String,
    pub to_protocol: String,
    pub count: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/proxy",
    tag = "Analytics",
    params(WindowWorkspacesQuery),
    responses(
        (status = 200, description = "Proxy protocol dashboard", body = ProxyDashboard),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn proxy_dashboard(
    mut db: TenantConn,
    Query(params): Query<WindowWorkspacesQuery>,
) -> Result<Json<ProxyDashboard>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let (start_ts, end_ts) = params.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    usage::proxy_dashboard(db.conn(), tenant_id, start_ts, end_ts, &params).await.map(Json)
}

// --- Error Analytics ---

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ErrorQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl ErrorQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope { workspace_ids: parse_workspace_ids(&self.workspace_ids), ..Default::default() }
    }
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct ErrorCategoryEntry {
    pub category: String,
    pub count: i64,
    pub latest_at: DateTime<Utc>,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct StatusCodeEntry {
    pub status_code: i16,
    pub count: i64,
}

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct ModelErrorEntry {
    pub model: String,
    pub count: i64,
    pub top_category: String,
}

#[derive(Serialize, ToSchema)]
pub struct ErrorAnalytics {
    pub total_errors: i64,
    pub by_category: Vec<ErrorCategoryEntry>,
    pub by_status_code: Vec<StatusCodeEntry>,
    pub by_model: Vec<ModelErrorEntry>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/errors",
    tag = "Analytics",
    params(ErrorQuery),
    responses(
        (status = 200, description = "Error analytics breakdown", body = ErrorAnalytics),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn error_analytics(
    mut db: TenantConn,
    Query(query): Query<ErrorQuery>,
) -> Result<Json<ErrorAnalytics>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    usage::error_analytics(db.conn(), tenant_id, start_ts, end_ts, scope).await.map(Json)
}

// ---------------------------------------------------------------------------
// Global Usage Analytics (super-admin only, cross-tenant, raw pool)
// ---------------------------------------------------------------------------

/// Per-tenant usage row returned by the global usage query.
#[derive(Serialize, ToSchema)]
pub struct TenantUsage {
    pub tenant_id: Uuid,
    pub tenant_name: String,
    pub slug: String,
    pub total_requests: i64,
    pub total_prompt_tokens: i64,
    pub total_completion_tokens: i64,
    pub total_cache_creation_tokens: i64,
    pub total_cache_read_tokens: i64,
    pub total_reasoning_tokens: i64,
    /// What the tenant spent, in its accounting currency. `null` when the
    /// window straddles a change of that currency.
    pub spend: Option<SpendTotal>,
    pub error_count: i64,
    pub active_users: i64,
}

/// Aggregate totals across all tenants.
#[derive(Serialize, Default, ToSchema)]
pub struct UsageTotals {
    pub total_requests: i64,
    pub total_prompt_tokens: i64,
    pub total_completion_tokens: i64,
    pub total_cache_creation_tokens: i64,
    pub total_cache_read_tokens: i64,
    pub total_reasoning_tokens: i64,
    /// What every tenant spent, one entry per currency its rows are booked in,
    /// ordered by currency code — tenants keep their books in their own
    /// currencies, so amounts in different ones are never added. A window
    /// whose traffic priced nothing still lists its currency, with a zero;
    /// the list is empty only when no tenant had traffic.
    pub spend: Vec<SpendTotal>,
    pub error_count: i64,
}

/// Top-level response for the global usage analytics endpoint.
#[derive(Serialize, ToSchema)]
pub struct GlobalUsageSummary {
    pub tenants: Vec<TenantUsage>,
    pub totals: UsageTotals,
}

/// `GET /api/v1/admin/global/analytics/overview?days=N`
///
/// Returns per-tenant usage breakdown for the super-admin global dashboard.
/// Iterates non-SYSTEM tenants with scoped connections (RLS-compliant). The
/// Agent workspace's traffic is left out: it is the gateway's own analysis,
/// not a tenant's load.
#[utoipa::path(
    get,
    path = "/api/v1/admin/global/analytics/overview",
    tag = "Analytics",
    params(WindowQuery),
    responses(
        (status = 200, description = "Global per-tenant usage summary", body = GlobalUsageSummary),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn global_usage_summary(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<WindowQuery>,
) -> Result<Json<GlobalUsageSummary>, ApiError> {
    use crate::db::tenant::{TenantConn, TenantId};

    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;

    let tenant_rows: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT id, name, slug FROM tenants WHERE slug != 'system'",
    )
    .fetch_all(state.db.global(Global::TenantIteration))
    .await
    .map_err(|e| {
        tracing::error!("global usage summary list tenants: {e}");
        ApiError::internal("database query failed")
    })?;

    let mut tenants = Vec::new();
    // Every tenant's spend per currency, folded into the totals below.
    let mut spend_parts: Vec<SpendTotal> = Vec::new();
    for (tid, tname, tslug) in &tenant_rows {
        let mut db = TenantConn::acquire(&state.db, TenantId::from_row(*tid)).await
            .map_err(|e| {
                tracing::error!("global usage summary acquire: {e}");
                ApiError::internal("database query failed")
            })?;

        let row = usage::tenant_usage_totals(db.conn(), *tid, start_ts, end_ts)
            .await
            .map_err(|e| {
                tracing::error!("global usage summary tenant {}: {e}", tslug);
                ApiError::internal("database query failed")
            })?;

        if row.requests > 0 {
            // A tenant with traffic holds at least one currency, so no zero
            // needs denominating: its figure is its one part, read as every
            // stored currency is, or none across a currency change.
            let spend = if row.currency_count == 1 { row.spend_parts.first().copied() } else { None };
            spend_parts.extend(row.spend_parts);
            tenants.push(TenantUsage {
                tenant_id: *tid,
                tenant_name: tname.clone(),
                slug: tslug.clone(),
                total_requests: row.requests,
                total_prompt_tokens: row.prompt_tokens,
                total_completion_tokens: row.completion_tokens,
                total_cache_creation_tokens: row.cache_creation_tokens,
                total_cache_read_tokens: row.cache_read_tokens,
                total_reasoning_tokens: row.reasoning_tokens,
                spend,
                error_count: row.errors,
                active_users: row.active_users,
            });
        }
    }

    tenants.sort_by(|a, b| b.total_requests.cmp(&a.total_requests).then_with(|| a.slug.cmp(&b.slug)));

    let totals = tenants.iter().fold(UsageTotals::default(), |mut acc, t| {
        acc.total_requests += t.total_requests;
        acc.total_prompt_tokens += t.total_prompt_tokens;
        acc.total_completion_tokens += t.total_completion_tokens;
        acc.total_cache_creation_tokens += t.total_cache_creation_tokens;
        acc.total_cache_read_tokens += t.total_cache_read_tokens;
        acc.total_reasoning_tokens += t.total_reasoning_tokens;
        acc.error_count += t.error_count;
        acc
    });
    let mut by_currency: std::collections::BTreeMap<streamscope_core::pricing::Currency, f64> =
        Default::default();
    for part in spend_parts {
        *by_currency.entry(part.currency).or_default() += part.amount;
    }
    let totals = UsageTotals {
        spend: by_currency.into_iter().map(|(currency, amount)| SpendTotal { currency, amount }).collect(),
        ..totals
    };

    Ok(Json(GlobalUsageSummary { tenants, totals }))
}

// ---------------------------------------------------------------------------
// Per-Edge Operational Telemetry (super-admin only, global, raw pool)
// ---------------------------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct EdgeStatsQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
}

impl EdgeStatsQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
}

/// One time bucket of an edge's operational telemetry. Cumulative counters are
/// reported as per-bucket deltas; gauges as the bucket mean.
#[derive(Serialize, ToSchema)]
pub struct EdgeStatsBucket {
    pub bucket_start: DateTime<Utc>,
    /// Requests served in this bucket (delta of the cumulative counter).
    pub requests: i64,
    /// Errors in this bucket (delta of the cumulative counter).
    pub errors: i64,
    /// Platform-induced latency percentiles in milliseconds — the proxy's own
    /// auth + transform + routing time, excluding the upstream provider.
    pub p50_overhead_ms: f64,
    pub p95_overhead_ms: f64,
    pub p99_overhead_ms: f64,
    /// Mean CPU utilisation (percent) across samples in the bucket.
    pub avg_cpu_percent: f64,
    /// Mean resident memory (MB) across samples in the bucket.
    pub avg_memory_mb: f64,
    /// Memory ceiling (MB) the edge runs under — the cgroup `memory.max` the
    /// working-set figure is measured against. `None` when no sample in the
    /// bucket reported a limit (off-cgroup or unconstrained replicas). Near
    /// constant per replica, so the bucket reports the max observed.
    pub memory_limit_mb: Option<f64>,
    /// Mean concurrent streams across samples in the bucket.
    pub avg_active_streams: f64,
}

/// Per-edge operational time-series.
#[derive(Serialize, ToSchema)]
pub struct EdgeStatsSeries {
    pub edge_node_id: Uuid,
    pub edge_name: String,
    pub buckets: Vec<EdgeStatsBucket>,
}

/// Response for the global per-edge stats endpoint.
#[derive(Serialize, ToSchema)]
pub struct GlobalEdgeStatsResponse {
    /// Bucket granularity — `hour` or `day`.
    pub interval: String,
    /// One series per edge node that reported samples in the window.
    pub edges: Vec<EdgeStatsSeries>,
}

#[derive(sqlx::FromRow)]
struct EdgeStatsRow {
    edge_node_id: Uuid,
    bucket: Option<DateTime<Utc>>,
    requests: Option<i64>,
    errors: Option<i64>,
    avg_cpu: Option<f64>,
    avg_mem_bytes: Option<f64>,
    max_mem_limit_bytes: Option<f64>,
    avg_streams: Option<f64>,
    /// Per-bucket overhead-sample counts summed over the time bucket's
    /// per-sample deltas — a windowed delta histogram positioned against
    /// `streamscope_core::metrics::OVERHEAD_BOUNDS_US`. Percentiles are
    /// interpolated from it in Rust.
    hist_buckets: Option<Vec<i64>>,
}

/// Interpolate p50/p95/p99 (ms) from a windowed overhead delta histogram.
/// Returns zeros when the histogram is missing, empty, or (defensively) not
/// shaped against the shared bounds.
fn overhead_percentiles_ms(hist: &Option<Vec<i64>>) -> (f64, f64, f64) {
    use streamscope_core::metrics::{histogram_quantile, OVERHEAD_BOUNDS_US, OVERHEAD_BUCKET_COUNT};
    let Some(hist) = hist else { return (0.0, 0.0, 0.0) };
    if hist.len() != OVERHEAD_BUCKET_COUNT {
        return (0.0, 0.0, 0.0);
    }
    let counts: Vec<u64> = hist.iter().map(|&v| v.max(0) as u64).collect();
    (
        histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.50) / 1000.0,
        histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.95) / 1000.0,
        histogram_quantile(&OVERHEAD_BOUNDS_US, &counts, 0.99) / 1000.0,
    )
}

/// `GET /api/v1/admin/global/edge-stats?days=N`
///
/// Per-edge operational telemetry over time — request throughput,
/// platform-induced latency, and resource usage — for the system-tenant
/// Platform Overview. Reads the append-only `edge_stats_samples` table on the
/// raw pool (edge telemetry is global infrastructure, no RLS).
#[utoipa::path(
    get,
    path = "/api/v1/admin/global/edge-stats",
    tag = "Analytics",
    params(EdgeStatsQuery),
    responses(
        (status = 200, description = "Per-edge operational time-series", body = GlobalEdgeStatsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn global_edge_stats(
    State(state): State<Arc<AdminState>>,
    Query(query): Query<EdgeStatsQuery>,
) -> Result<Json<GlobalEdgeStatsResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(1)?;
    let interval = bucket_interval(start_ts, end_ts);

    let names: Vec<(Uuid, String)> = sqlx::query_as("SELECT id, name FROM edge_nodes")
        .fetch_all(state.db.global(Global::Infra))
        .await
        .map_err(|e| {
            tracing::error!("edge stats names: {e}");
            ApiError::internal("database query failed")
        })?;
    let name_of: std::collections::HashMap<Uuid, String> = names.into_iter().collect();

    // Cumulative counters → per-sample deltas. The CTE reaches 10 min before
    // the window so the first in-window sample has a real `LAG` predecessor
    // (otherwise its whole interval would read as 0); the outer query then
    // drops the pre-window buckets. A delta below its predecessor means the
    // proxy restarted — count the post-restart value itself rather than a
    // negative. Gauges are bucket-averaged.
    //
    // The overhead histogram follows the same delta model element-wise:
    // `overhead_buckets` is a cumulative per-bucket count array, so each
    // sample's delta is the element-wise difference from its predecessor
    // (restart detected on the whole histogram via `overhead_count`), and the
    // time bucket's windowed histogram is the element-wise SUM of those
    // deltas. Percentiles are interpolated from it in Rust — never averaged.
    let sql = format!(
        "WITH lagged AS ( \
            SELECT i.edge_node_id AS edge_node_id, \
                date_trunc('{interval}', s.sampled_at) AS bucket, \
                s.requests_total, LAG(s.requests_total) OVER w AS prev_req, \
                s.errors_total,   LAG(s.errors_total)   OVER w AS prev_err, \
                s.cpu_percent, s.memory_rss_bytes, s.memory_limit_bytes, s.active_streams, \
                s.overhead_buckets, LAG(s.overhead_buckets) OVER w AS prev_buckets, \
                s.overhead_count,   LAG(s.overhead_count)   OVER w AS prev_count \
            FROM edge_stats_samples s \
            JOIN edge_instances i ON i.id = s.edge_instance_id \
            WHERE s.sampled_at >= $1 - INTERVAL '10 minutes' AND s.sampled_at < $2 \
            WINDOW w AS (PARTITION BY s.edge_instance_id ORDER BY s.sampled_at) \
         ), deltas AS ( \
            SELECT edge_node_id, bucket, \
                CASE WHEN requests_total < prev_req THEN requests_total ELSE requests_total - prev_req END AS d_req, \
                CASE WHEN errors_total   < prev_err THEN errors_total   ELSE errors_total   - prev_err END AS d_err, \
                cpu_percent, memory_rss_bytes, memory_limit_bytes, active_streams, \
                CASE \
                    WHEN overhead_buckets IS NULL OR prev_buckets IS NULL THEN NULL \
                    WHEN overhead_count < prev_count THEN overhead_buckets \
                    ELSE (SELECT array_agg(GREATEST(cur - COALESCE(prev, 0), 0) ORDER BY ord) \
                          FROM unnest(overhead_buckets, prev_buckets) WITH ORDINALITY AS u(cur, prev, ord)) \
                END AS d_buckets \
            FROM lagged \
         ), agg AS ( \
            SELECT edge_node_id, bucket, \
                COALESCE(SUM(d_req), 0)::bigint AS requests, \
                COALESCE(SUM(d_err), 0)::bigint AS errors, \
                AVG(cpu_percent)::double precision      AS avg_cpu, \
                AVG(memory_rss_bytes)::double precision AS avg_mem_bytes, \
                MAX(memory_limit_bytes)::double precision AS max_mem_limit_bytes, \
                AVG(active_streams)::double precision   AS avg_streams \
            FROM deltas \
            WHERE bucket >= date_trunc('{interval}', $1) \
            GROUP BY edge_node_id, bucket \
         ), hist AS ( \
            SELECT edge_node_id, bucket, array_agg(cnt ORDER BY ord) AS hist_buckets \
            FROM ( \
                SELECT d.edge_node_id, d.bucket, u.ord, SUM(u.v)::bigint AS cnt \
                FROM deltas d, unnest(d.d_buckets) WITH ORDINALITY AS u(v, ord) \
                WHERE d.bucket >= date_trunc('{interval}', $1) \
                GROUP BY d.edge_node_id, d.bucket, u.ord \
            ) per_slot \
            GROUP BY edge_node_id, bucket \
         ) \
         SELECT a.edge_node_id, a.bucket, a.requests, a.errors, \
            a.avg_cpu, a.avg_mem_bytes, a.max_mem_limit_bytes, a.avg_streams, \
            h.hist_buckets \
         FROM agg a \
         LEFT JOIN hist h ON h.edge_node_id = a.edge_node_id AND h.bucket = a.bucket \
         ORDER BY a.edge_node_id, a.bucket"
    );
    let rows = sqlx::query_as::<_, EdgeStatsRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(start_ts)
        .bind(end_ts)
        .fetch_all(state.db.global(Global::Infra))
        .await
        .map_err(|e| {
            tracing::error!("global edge stats: {e}");
            ApiError::internal("database query failed")
        })?;

    // Group buckets per edge.
    let mut by_edge: std::collections::HashMap<Uuid, std::collections::HashMap<DateTime<Utc>, EdgeStatsBucket>> =
        std::collections::HashMap::new();
    for r in rows {
        let Some(bucket) = r.bucket else { continue };
        let (p50_ms, p95_ms, p99_ms) = overhead_percentiles_ms(&r.hist_buckets);
        by_edge.entry(r.edge_node_id).or_default().insert(
            bucket,
            EdgeStatsBucket {
                bucket_start: bucket,
                requests: r.requests.unwrap_or(0),
                errors: r.errors.unwrap_or(0),
                p50_overhead_ms: p50_ms,
                p95_overhead_ms: p95_ms,
                p99_overhead_ms: p99_ms,
                avg_cpu_percent: r.avg_cpu.unwrap_or(0.0),
                avg_memory_mb: r.avg_mem_bytes.unwrap_or(0.0) / 1_048_576.0,
                memory_limit_mb: r.max_mem_limit_bytes.map(|b| b / 1_048_576.0),
                avg_active_streams: r.avg_streams.unwrap_or(0.0),
            },
        );
    }

    // Fill the bucket axis so every edge series has the same x-axis.
    let axis = build_bucket_axis(start_ts, end_ts, interval);
    let mut edges: Vec<EdgeStatsSeries> = by_edge
        .into_iter()
        .map(|(edge_node_id, mut buckets)| {
            let series = axis
                .iter()
                .map(|ts| {
                    buckets.remove(ts).unwrap_or(EdgeStatsBucket {
                        bucket_start: *ts,
                        requests: 0,
                        errors: 0,
                        p50_overhead_ms: 0.0,
                        p95_overhead_ms: 0.0,
                        p99_overhead_ms: 0.0,
                        avg_cpu_percent: 0.0,
                        avg_memory_mb: 0.0,
                        memory_limit_mb: None,
                        avg_active_streams: 0.0,
                    })
                })
                .collect();
            EdgeStatsSeries {
                edge_node_id,
                edge_name: name_of.get(&edge_node_id).cloned().unwrap_or_default(),
                buckets: series,
            }
        })
        .collect();
    edges.sort_by(|a, b| a.edge_name.cmp(&b.edge_name));

    Ok(Json(GlobalEdgeStatsResponse { interval: interval.to_string(), edges }))
}

// --- Media Analytics ---

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MediaAnalyticsQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl MediaAnalyticsQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope { workspace_ids: parse_workspace_ids(&self.workspace_ids), ..Default::default() }
    }
}

/// Direction-aware media analytics: each media type has sub-directions
/// (e.g. image has generation=text→image and vision=image→text).
#[derive(Serialize, ToSchema)]
pub struct MediaAnalyticsResponse {
    /// Per-direction stats (e.g. "image_generation", "image_vision", "audio_speech", "audio_transcription")
    pub directions: Vec<MediaDirectionStat>,
    /// Top users with per-type request counts
    pub users: Vec<MediaUserStat>,
}

#[derive(Serialize, ToSchema)]
pub struct MediaDirectionStat {
    /// Media category: "image", "audio", "embedding", "video"
    pub category: String,
    /// Direction: "generation", "vision", "speech", "transcription", "encode"
    pub direction: String,
    /// Human label: "text→image", "image→text", etc.
    pub label: String,
    pub requests: i64,
    pub units: i64,
    /// What this direction cost, and in which currency. `null` when the
    /// window straddles a change of the tenant's accounting currency.
    pub spend: Option<SpendTotal>,
    pub p95_latency: Option<f64>,
}

/// One user of the media spend ranking, ordered by the shared spend rule
/// (see `TopUserEntry`).
#[derive(Serialize, ToSchema)]
pub struct MediaUserStat {
    pub user_email: String,
    pub total_requests: i64,
    /// `null` when this user's window straddles a change of the accounting
    /// currency.
    pub spend: Option<SpendTotal>,
    pub image_requests: i64,
    pub audio_requests: i64,
    pub embedding_requests: i64,
    pub video_requests: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/media",
    tag = "Analytics",
    params(MediaAnalyticsQuery),
    responses(
        (status = 200, description = "Media analytics by direction and top users", body = MediaAnalyticsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn media_analytics(
    mut db: TenantConn,
    Query(query): Query<MediaAnalyticsQuery>,
) -> Result<Json<MediaAnalyticsResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    usage::media_analytics(db.conn(), tenant_id, start_ts, end_ts, scope).await.map(Json)
}

// --- Response-cache analytics ---

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CacheAnalyticsQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl CacheAnalyticsQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope { workspace_ids: parse_workspace_ids(&self.workspace_ids), ..Default::default() }
    }
}

/// What the response cache did, and what it was worth, over the window.
///
/// Every figure covers only requests that went through an alias with a cache
/// preset bound — an uncached gateway reports zeroes throughout.
#[derive(Serialize, ToSchema)]
pub struct CacheAnalyticsResponse {
    /// Requests the cache was consulted for. Excludes `bypassed`.
    pub lookups: i64,
    /// Requests where the client sent `Cache-Control: no-cache`/`no-store`.
    /// Kept out of `lookups` so a client opting out cannot depress the hit rate.
    pub bypassed: i64,
    /// Requests answered from the cache, with no upstream call.
    pub hits: i64,
    /// Requests that matched under `observe` and were still sent upstream.
    /// These saved nothing — they are the tuning signal for whether to enforce.
    pub observe_hits: i64,
    /// `hits / lookups`. Zero for an `observe`-only tenant by construction:
    /// observe never serves.
    pub hit_rate: f64,
    /// What the cache saved and cost, in one currency. `null` when the window
    /// straddles a change of the tenant's accounting currency: its figures are
    /// then in more than one denomination and no single one states them.
    pub savings: Option<CacheSavings>,
    /// Why responses were not stored, tenant-wide, commonest first. A cache
    /// with a low hit rate and a full `tool_calls` bucket is not underused —
    /// it is being asked to cache something it never can.
    pub store_skips: Vec<CacheSkipStat>,
    /// Why semantic matching could not run, tenant-wide, commonest first. A
    /// semantic alias silently degraded to exact (`embedding_timeout`,
    /// `embedding_failed`) is indistinguishable from one nobody repeats
    /// prompts on unless this is reported.
    pub semantic_skips: Vec<CacheSkipStat>,
    /// Per-alias breakdown, ranked by net savings under the shared spend rule
    /// (see `TopUserEntry`): by the net saved in today's accounting currency,
    /// richest first, then aliases with nothing in it.
    pub aliases: Vec<CacheAliasStat>,
}

/// The response cache's money figures over the window, all in `currency`.
#[derive(Serialize, ToSchema)]
pub struct CacheSavings {
    #[schema(value_type = String, example = "USD")]
    pub currency: streamscope_core::pricing::Currency,
    /// What the upstream calls the hits replaced would have cost.
    pub gross_avoided: f64,
    /// What enforcing would additionally have saved, from the observe matches.
    pub would_avoid: f64,
    /// Embedding spend on enforcing (`exact`/`semantic`) aliases. Charged
    /// against savings — it is the cost of running the cache.
    pub embedding_cost: f64,
    /// Embedding spend on `observe` aliases. Reported separately and NOT
    /// charged against savings: observe is a measurement run, so folding its
    /// cost in would make a tenant evaluating the cache read as losing money.
    pub tuning_cost: f64,
    /// `gross_avoided - embedding_cost`. Can be negative — a semantic
    /// alias nobody repeats prompts on pays for embeddings and saves nothing.
    pub net_saved: f64,
}

/// One alias's money figures over the window, all in `currency`.
#[derive(Serialize, ToSchema)]
pub struct CacheAliasSavings {
    #[schema(value_type = String, example = "USD")]
    pub currency: streamscope_core::pricing::Currency,
    pub gross_avoided: f64,
    pub would_avoid: f64,
    /// The alias's embedding spend, whatever its mode.
    pub embedding_cost: f64,
    /// `gross_avoided` less the embedding spend of an enforcing alias; an
    /// `observe` alias's embeddings are measurement and not charged here.
    pub net_saved: f64,
}

/// One reason a cache step did not run, and how often.
#[derive(Serialize, ToSchema)]
pub struct CacheSkipStat {
    /// Machine-readable reason, straight off the audit badge — e.g.
    /// `tool_calls`, `entry_too_large`, `cache_full`, `client_bypass`,
    /// `embedding_timeout`, `no_embedding_alias`.
    pub reason: String,
    pub count: i64,
}

#[derive(Serialize, ToSchema)]
pub struct CacheAliasStat {
    /// The alias the client asked for.
    pub alias: String,
    /// Cache mode in force: `exact`, `semantic`, or `observe`. An alias whose
    /// preset changed mid-window appears once per mode it ran under.
    pub mode: String,
    pub lookups: i64,
    pub hits: i64,
    pub observe_hits: i64,
    pub hit_rate: f64,
    /// `null` when this alias's window straddles a change of the accounting
    /// currency.
    pub savings: Option<CacheAliasSavings>,
    /// Why this alias's responses were not stored, commonest first.
    pub store_skips: Vec<CacheSkipStat>,
    /// Why semantic matching could not run, commonest first. Always empty on an
    /// `exact`-mode row, which never attempts it — reasons are attributed to the
    /// mode that was in force, so an alias that ran both modes in the window
    /// carries each reason on the row that produced it.
    pub semantic_skips: Vec<CacheSkipStat>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/cache",
    tag = "Analytics",
    params(CacheAnalyticsQuery),
    responses(
        (status = 200, description = "Response-cache hit rate and savings", body = CacheAnalyticsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cache_analytics(
    mut db: TenantConn,
    Query(query): Query<CacheAnalyticsQuery>,
) -> Result<Json<CacheAnalyticsResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let workspace_ids = query.scope().workspace_ids;
    let tenant_id = db.tenant_uuid();
    usage::cache_analytics(db.conn(), tenant_id, start_ts, end_ts, workspace_ids).await.map(Json)
}

// ── MCP Dashboard ───────────────────────────────────────────────────
//
// Top-N panel + summary + timeseries + errors-by-method endpoints powering
// the /mcp Dashboard tab. All pivot through the shared `mcp_dashboard_panel`
// SQL builder against `MCP_AUDIT_JOIN`. The INNER JOIN to `mcp_audit` makes
// the `kind='mcp'` filter implicit — no `WHERE g.kind='mcp'` clause needed.

/// Sort dimension for top-N panels. `count` is the default (busiest); `p95`
/// flips to slowest-by-P95-latency. Honored on every panel — answers "which
/// X is slowest" for tools, resources, prompts, endpoints, upstreams, users,
/// apps, and methods alike.
#[derive(Debug, Clone, Copy, Default, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum DashboardSortBy {
    #[default]
    Count,
    P95,
}

/// One row in a top-N MCP dashboard panel.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpInvocationCount {
    /// Pivot value: `tool_id`, `prompt_id`, `resource_uri`, or a UUID/string
    /// identifier (virtual_server_id, upstream_server_id, user_id, app_id).
    /// Always cast to TEXT server-side so the UI can resolve display names.
    pub key: String,
    pub call_count: i64,
    /// Distinct virtual servers that hosted this pivot value. Always 1 when
    /// pivot is `virtual_server_id`.
    pub virtual_server_count: i64,
    /// Distinct users who invoked it. Always 1 when pivot is `g.user_id`.
    pub user_count: i64,
    pub last_used: chrono::DateTime<chrono::Utc>,
    /// Calls that returned a JSON-RPC error (`mcp_audit.error_code IS NOT NULL`)
    /// or HTTP 4xx/5xx (`gateway_audit.status_code >= 400`). Either side counts.
    pub error_count: i64,
    /// P95 of `gateway_audit.latency_total_ms` for this group. Null when the
    /// group has no rows with non-null latency.
    pub p95_latency_ms: Option<f64>,
    /// User email when pivot is `g.user_id` and the user has one on file.
    /// Lets the UI build a `?user_email=…` deep-link that audit / sessions
    /// match exactly, instead of relying on the rendered display-name `key`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    /// User UUID when pivot is `g.user_id`. Fallback identifier the UI uses
    /// when `user_email` is absent — pairs with `AuditQuery::user_id` /
    /// `SessionListQuery::user_id` so deep-links still resolve for users
    /// without an email on file.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
}

/// Wrapper response for the dashboard panels. `total_calls` lets the UI
/// render "N of M" alongside the top-K list without a second round trip.
#[derive(Serialize, ToSchema)]
pub struct McpDashboardPanel {
    pub items: Vec<McpInvocationCount>,
    pub total_calls: i64,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct McpDashboardQuery {
    pub days: Option<i32>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub app_id: Option<String>,
    pub user_id: Option<Uuid>,
    /// Top-N rows to return. Default 20, max 100 (server-side cap).
    pub limit: Option<i64>,
    /// Sort dimension. Default `count`. Honored on every panel.
    pub sort_by: Option<DashboardSortBy>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl McpDashboardQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    pub(crate) fn resolved_limit(&self) -> i64 {
        self.limit.unwrap_or(20).clamp(1, 100)
    }
}

// ── Top-N panel handlers (thin wrappers over mcp_dashboard_panel) ──

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-resource",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top resources by `resources/read` call count", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_resource(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "m.resource_uri", Some("resources/read"))
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-prompt",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top prompts by `prompts/get` call count", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_prompt(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "m.prompt_id", Some("prompts/get"))
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-tool",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top tools by `tools/call` count or P95 latency (`sort_by`)", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_tool(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "m.tool_id", Some("tools/call"))
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-endpoint",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top endpoints (virtual servers) by call count", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_endpoint(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "m.virtual_server_id", None)
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-upstream",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top upstream MCP servers by call count", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_upstream(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "m.upstream_server_id", None)
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-method",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Method distribution (initialize / tools/* / prompts/* / resources/* / sampling / elicitation / list_changed)", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_method(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "m.method", None)
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-user",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top users by MCP call count", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_user(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "g.user_id", None)
        .await
        .map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/by-app",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Top apps by MCP call count (MCP-only — `app_id` is the resolved client ID)", body = McpDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_by_app(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardPanel>, ApiError> {
    mcp_store::mcp_dashboard_panel(db.conn(), &query, "g.app_id", None)
        .await
        .map(Json)
}

// ── Summary endpoint (6 metric cards) ──

#[derive(Serialize, ToSchema)]
pub struct McpDashboardSummaryPrevious {
    pub calls: i64,
    pub sessions: i64,
    pub tool_calls: i64,
    pub errors: i64,
    pub p95_latency_ms: f64,
}

#[derive(Serialize, ToSchema)]
pub struct McpDashboardSummary {
    pub calls: i64,
    pub sessions: i64,
    pub tool_calls: i64,
    pub errors: i64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    /// Distinct users with at least one call in the period.
    pub unique_users: i64,
    /// Snapshot count of MCP-surface `oauth_issued_tokens WHERE revoked_at IS
    /// NULL AND expires_at > NOW()`. Not period-scoped — always "right now".
    pub live_tokens: i64,
    /// Same metrics for the prior equivalent period (for delta UI).
    pub previous: McpDashboardSummaryPrevious,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/summary",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "MCP dashboard 6-metric summary", body = McpDashboardSummary),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_summary(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpDashboardSummary>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    mcp_store::mcp_dashboard_summary(db.conn(), start, end, &query).await.map(Json)
}

// ── Timeseries endpoint (call volume by method + dual latency split) ──

#[derive(Serialize, ToSchema)]
pub struct McpTimeseriesBucket {
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub call_count: i64,
    /// Calls per JSON-RPC method in this bucket (e.g. `{"tools/call": 42}`).
    pub by_method: std::collections::HashMap<String, i64>,
    /// Gateway end-to-end latency percentiles (`gateway_audit.latency_total_ms`).
    pub gateway_p50_ms: f64,
    pub gateway_p95_ms: f64,
    pub gateway_p99_ms: f64,
    /// Upstream-only latency percentiles (`mcp_audit.upstream_latency_ms`).
    /// Gap between gateway and upstream P95 = proxy overhead.
    pub upstream_p50_ms: f64,
    pub upstream_p95_ms: f64,
    pub upstream_p99_ms: f64,
}

#[derive(Serialize, ToSchema)]
pub struct McpTimeseriesResponse {
    /// Bucket interval: `"hour"` when the window ≤ 1 day, else `"day"`.
    pub interval: String,
    pub buckets: Vec<McpTimeseriesBucket>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/timeseries",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "MCP call volume by method + gateway/upstream latency percentiles, bucketed by hour or day", body = McpTimeseriesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_timeseries(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpTimeseriesResponse>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    mcp_store::mcp_dashboard_timeseries(db.conn(), start, end, &query).await.map(Json)
}

// ── Errors-by-method endpoint ──

#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct McpErrorsByMethodRow {
    pub method: String,
    pub error_count: i64,
    /// Most common JSON-RPC `error_code` for this method, when one exists.
    /// Null when all errors came from the HTTP path (`g.status_code >= 400`)
    /// without a JSON-RPC error code.
    pub top_error_code: Option<i32>,
}

#[derive(Serialize, ToSchema)]
pub struct McpErrorsByMethodResponse {
    pub items: Vec<McpErrorsByMethodRow>,
    pub total_errors: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/dashboard/errors-by-method",
    tag = "MCP Dashboard",
    params(McpDashboardQuery),
    responses(
        (status = 200, description = "Error counts grouped by JSON-RPC method, with the most common error_code per method", body = McpErrorsByMethodResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn mcp_dashboard_errors_by_method(
    mut db: TenantConn,
    Query(query): Query<McpDashboardQuery>,
) -> Result<Json<McpErrorsByMethodResponse>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    mcp_store::mcp_dashboard_errors_by_method(db.conn(), start, end, &query).await.map(Json)
}

// ── Web Dashboard ───────────────────────────────────────────────────────────
//
// Powers the `/dashboard/web` page. Same shape as the MCP dashboard — typed
// summary + a set of top-N panels — but pivots on web_audit columns
// (operation, surface, backend, host, query) and skips cost/tokens since
// the Web MCP has no billing dimension.
//
// Joins through `WEB_AUDIT_JOIN` so the `kind='web'` filter is implicit.

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct WebDashboardQuery {
    pub days: Option<i32>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    /// Top-N rows. Default 20, max 100.
    pub limit: Option<i64>,
    /// Narrow to one user — admin-side capability, not surfaced in the
    /// dashboard UI but needed for cross-tenant audit drilldowns and
    /// xdist test scoping.
    pub user_id: Option<Uuid>,
    /// Partial email match (ILIKE `%email%`). Resolved against the `users`
    /// table via the LEFT JOIN every web-dashboard query carries.
    pub user_email: Option<String>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl WebDashboardQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    pub(crate) fn resolved_limit(&self) -> i64 {
        self.limit.unwrap_or(20).clamp(1, 100)
    }
}

#[derive(Serialize, ToSchema)]
pub struct WebDashboardSummary {
    pub requests: i64,
    pub searches: i64,
    pub fetches: i64,
    pub unique_users: i64,
    /// Distinct hostnames seen across `operation='fetch'` rows.
    pub unique_hosts: i64,
    /// HTTP 4xx/5xx or non-null `error_category`.
    pub errors: i64,
    /// Calls where the policy/filter chain prevented full forwarding —
    /// union of `web_blocked`, `web_ssrf_refused`, `web_scheme_refused`,
    /// `web_url_filtered`, `web_all_results_filtered`, `web_rate_limited`.
    pub blocked: i64,
    /// Subset of `blocked` where the target host resolved to a private /
    /// loopback / link-local / IMDS address.
    pub ssrf_blocks: i64,
    /// Subset of `blocked` where the URL-filter chain dropped at least one URL.
    pub domain_filter_denies: i64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
    /// `latency_total_ms > 10000`. Feeds the reliability card subtitle.
    pub slow_count: i64,
}

/// One row in a top-N Web dashboard panel.
#[derive(Serialize, ToSchema)]
pub struct WebDashboardItem {
    /// Pivot value: host (fetch), normalized query (search), or display name (user).
    pub key: String,
    pub requests: i64,
    pub errors: i64,
    pub p95_latency_ms: Option<f64>,
    pub last_used: chrono::DateTime<chrono::Utc>,
    /// Total response bytes — populated by the `by-host` panel only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<i64>,
    /// Average `result_count` — populated by the `by-query` panel only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub avg_result_count: Option<f64>,
    /// User email — populated by the `by-user` panel only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_email: Option<String>,
    /// User UUID — populated by the `by-user` panel only.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct WebDashboardPanel {
    pub items: Vec<WebDashboardItem>,
    /// Unfiltered (pre-LIMIT) total request count across all pivot values.
    /// Lets the UI render "N of M" without a second round trip.
    pub total_requests: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/web/dashboard/summary",
    tag = "Web Dashboard",
    params(WebDashboardQuery),
    responses(
        (status = 200, description = "Web dashboard headline metrics — request count, search/fetch split, unique users/hosts, latency percentiles, error and policy-block counts", body = WebDashboardSummary),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn web_dashboard_summary(
    mut db: TenantConn,
    Query(query): Query<WebDashboardQuery>,
) -> Result<Json<WebDashboardSummary>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    web_store::web_dashboard_summary(db.conn(), start, end, &query).await.map(Json)
}

// ── Top-N panels ──

#[utoipa::path(
    get,
    path = "/api/v1/admin/web/dashboard/by-host",
    tag = "Web Dashboard",
    params(WebDashboardQuery),
    responses(
        (status = 200, description = "Top hosts by fetch request count. Host is extracted from the URL via `split_part(split_part(query,'://',2),'/',1)`. Honors all filters; `operation` is implicitly `fetch`.", body = WebDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn web_dashboard_by_host(
    mut db: TenantConn,
    Query(query): Query<WebDashboardQuery>,
) -> Result<Json<WebDashboardPanel>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    web_store::web_dashboard_by_host(db.conn(), start, end, &query).await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/web/dashboard/by-query",
    tag = "Web Dashboard",
    params(WebDashboardQuery),
    responses(
        (status = 200, description = "Top search queries by call count. Queries are normalized (`lower(trim(query))`). Honors all filters; `operation` is implicitly `search`.", body = WebDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn web_dashboard_by_query(
    mut db: TenantConn,
    Query(query): Query<WebDashboardQuery>,
) -> Result<Json<WebDashboardPanel>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    web_store::web_dashboard_by_query(db.conn(), start, end, &query).await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/web/dashboard/by-user",
    tag = "Web Dashboard",
    params(WebDashboardQuery),
    responses(
        (status = 200, description = "Top users by web request count. `key` renders the user's display name / email / UUID fallback; `user_email` and `user_id` carry the deep-link payload.", body = WebDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn web_dashboard_by_user(
    mut db: TenantConn,
    Query(query): Query<WebDashboardQuery>,
) -> Result<Json<WebDashboardPanel>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    web_store::web_dashboard_by_user(db.conn(), start, end, &query).await.map(Json)
}

// ============================================================================
// Cross-protocol analytics — feeds the `/dashboard` Overview page.
//
// These query `gateway_audit` directly (the parent table that has both LLM
// and MCP child rows joined to it) so no UNION is needed for protocol-
// agnostic metrics: count, error_category, latency_total_ms, status_code,
// kind, user_id, app_id, session_id all live on the parent.
//
// Only metrics that are unit-comparable across both protocols belong here —
// tokens, cost, finish_reason, JSON-RPC methods, etc. live on the protocol-
// specific endpoints (`/analytics/{overview,breakdown,...}` for LLM,
// `/mcp/dashboard/*` for MCP).
// ============================================================================

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CrossQuery {
    pub user_id: Option<Uuid>,
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl CrossQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope {
            user_id: self.user_id,
            workspace_ids: parse_workspace_ids(&self.workspace_ids),
            ..Default::default()
        }
    }
}

#[derive(Serialize, ToSchema)]
pub struct CrossOverview {
    pub total_requests: i64,
    pub total_sessions: i64,
    pub error_count: i64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/cross/overview",
    tag = "Analytics",
    params(CrossQuery),
    responses(
        (status = 200, description = "Cross-protocol headline metrics for the Dashboard Overview page (sessions, requests, error count, p95 latency). Aggregates over both LLM and MCP traffic via the gateway_audit parent table.", body = CrossOverview),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cross_overview(
    mut db: TenantConn,
    Query(query): Query<CrossQuery>,
) -> Result<Json<CrossOverview>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    usage::cross_overview(db.conn(), tenant_id, start_ts, end_ts, scope).await.map(Json)
}

#[derive(Serialize, ToSchema)]
pub struct CrossTimeseriesBucket {
    pub bucket_start: DateTime<Utc>,
    pub llm_count: i64,
    pub mcp_count: i64,
    pub a2a_count: i64,
    pub error_count: i64,
}

#[derive(Serialize, ToSchema)]
pub struct CrossTimeseriesResponse {
    /// Bucket interval — `"hour"` for windows ≤ 48h, `"day"` otherwise.
    pub interval: String,
    pub buckets: Vec<CrossTimeseriesBucket>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/cross/timeseries",
    tag = "Analytics",
    params(CrossQuery),
    responses(
        (status = 200, description = "Cross-protocol stacked timeseries — request volume bucketed by hour or day with LLM, MCP and A2A counts side by side. Used by the Dashboard Overview's main chart.", body = CrossTimeseriesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cross_timeseries(
    mut db: TenantConn,
    Query(query): Query<CrossQuery>,
) -> Result<Json<CrossTimeseriesResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    usage::cross_timeseries(db.conn(), tenant_id, start_ts, end_ts, scope).await.map(Json)
}

// ---------------------------------------------------------------------------
// /analytics/cross/upstream-timeseries — per-upstream sparkline data for the
// Dashboard "Top LLM upstreams" / "Top MCP upstreams" cards.
// ---------------------------------------------------------------------------

/// Audit protocol kind for the upstream-timeseries pivot. Each variant reads
/// its own audit child table and pivots on that protocol's notion of an
/// upstream: an LLM server, an MCP server, an A2A agent.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum UpstreamTimeseriesKind {
    Llm,
    Mcp,
    A2a,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct UpstreamTimeseriesQuery {
    pub user_id: Option<Uuid>,
    pub days: Option<i32>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    /// Pivot protocol. Required — the SQL is different per side.
    pub kind: UpstreamTimeseriesKind,
    /// Top-N upstreams to return, clamped to [1, 12].
    pub limit: Option<i64>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl UpstreamTimeseriesQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
    fn scope(&self) -> AnalyticsScope {
        AnalyticsScope {
            user_id: self.user_id,
            workspace_ids: parse_workspace_ids(&self.workspace_ids),
            ..Default::default()
        }
    }
    pub(crate) fn resolved_limit(&self) -> i64 {
        self.limit.unwrap_or(4).clamp(1, 12)
    }
}

/// One upstream's sparkline. `buckets` is aligned with the shared
/// `UpstreamTimeseriesResponse::bucket_starts` so the UI can render
/// without per-upstream timestamp lookups.
#[derive(Serialize, ToSchema)]
pub struct UpstreamSparkline {
    /// LLM: `upstream_servers.name`. MCP: `upstream_server_id` cast to TEXT.
    /// A2A: the agent's slug. Each matches the `key` shape the matching
    /// breakdown already returns (`BreakdownEntry` by=server,
    /// `McpInvocationCount` pivot=upstream_server_id, `A2aBreakdownItem`
    /// by-agent), so the two surfaces join on it.
    pub key: String,
    /// Total request count over the entire window. Mirrors what the breakdown
    /// / by-upstream callers already display next to the row.
    pub total: i64,
    /// Per-bucket counts, length == `bucket_starts.len()`. Zeros fill buckets
    /// with no traffic.
    pub buckets: Vec<i64>,
}

#[derive(Serialize, ToSchema)]
pub struct UpstreamTimeseriesResponse {
    /// `"hour"` when the window is ≤ 48 hours, `"day"` otherwise. Mirrors the
    /// granularity of `/analytics/cross/timeseries`.
    pub interval: String,
    /// Bucket-start timestamps in chronological order. Shared across every
    /// upstream so the response is compact even at top-N × ~30 buckets.
    pub bucket_starts: Vec<DateTime<Utc>>,
    /// Top-N upstreams by total request count, descending.
    pub upstreams: Vec<UpstreamSparkline>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/cross/upstream-timeseries",
    tag = "Analytics",
    params(UpstreamTimeseriesQuery),
    responses(
        (status = 200, description = "Top-N upstreams with per-bucket request counts. Powers the dashboard upstream-card sparklines.", body = UpstreamTimeseriesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cross_upstream_timeseries(
    mut db: TenantConn,
    Query(query): Query<UpstreamTimeseriesQuery>,
) -> Result<Json<UpstreamTimeseriesResponse>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let scope = query.scope();
    let tenant_id = db.tenant_uuid();
    let limit = query.resolved_limit();
    usage::cross_upstream_timeseries(db.conn(), tenant_id, start_ts, end_ts, scope, limit, &query).await.map(Json)
}

/// The bucket size for a window: `"hour"` up to 48 hours, `"day"` beyond.
pub(crate) fn bucket_interval(start: DateTime<Utc>, end: DateTime<Utc>) -> &'static str {
    if (end - start).num_hours() <= 48 { "hour" } else { "day" }
}

/// Build a chronological bucket axis between `start` and `end` aligned to
/// `interval` ("hour" or "day"), so the sparkline has a fixed denominator
/// regardless of traffic gaps.
pub(crate) fn build_bucket_axis(start: DateTime<Utc>, end: DateTime<Utc>, interval: &str) -> Vec<DateTime<Utc>> {
    let step = match interval {
        "hour" => chrono::Duration::hours(1),
        _ => chrono::Duration::days(1),
    };
    let truncated = match interval {
        "hour" => start
            .date_naive()
            .and_hms_opt(start.hour(), 0, 0)
            .map(|n| DateTime::<Utc>::from_naive_utc_and_offset(n, Utc))
            .unwrap_or(start),
        _ => start
            .date_naive()
            .and_hms_opt(0, 0, 0)
            .map(|n| DateTime::<Utc>::from_naive_utc_and_offset(n, Utc))
            .unwrap_or(start),
    };
    let mut cursor = truncated;
    let mut out = Vec::new();
    while cursor < end {
        out.push(cursor);
        cursor += step;
    }
    out
}

// /analytics/cross/attention — actionable counts for the Dashboard Overview's
// attention queue. Four cheap COUNT queries on already-indexed columns; the
// UI renders each as a clickable tile that deep-links into the relevant
// management surface (sessions list, audit filtered, keys page).

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct CrossAttentionQuery {
    /// Activity lookback for alerts / blocked / auth failures, in days. Default 1.
    pub window_days: Option<i32>,
    /// Forward window for credential expiry warnings, in days. Default 7.
    pub expiry_window_days: Option<i32>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionAlerts {
    pub total: i64,
    pub major: i64,
    pub minor: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionBlocked {
    pub total: i64,
    /// Most-frequent rule id across the blocked-tool events in window. Empty
    /// `None` when no blocks. Used by the UI as a one-line subtitle.
    pub top_rule_id: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionGuardrail {
    /// Rows in the window whose badges carry a `guardrail` finding — the inline
    /// injection guardrail flagged untrusted web content. Spans both surfaces:
    /// `llm_audit` (content folded back into a model on the substitution loop)
    /// and `web_audit` (the direct `/mcp/web` observe scan). Counts both observe
    /// (flag) and enforce (block) verdicts.
    pub total: i64,
    /// Subset of `total` whose guardrail badge carries `action: "block"` — the
    /// enforce-mode stripped subset (observe-mode flags are excluded). Only the
    /// substitution loop strips, so this is an LLM-side count.
    pub blocked: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionExpiring {
    pub total: i64,
    /// Rows whose `expires_at` is already in the past (not yet revoked).
    pub expired: i64,
    /// Rows whose `expires_at` falls within the next 24 hours.
    pub lt_24h: i64,
    /// Rows whose `expires_at` falls within the configured expiry window
    /// (default 7 days). Inclusive of `lt_24h` and `expired`.
    pub lt_7d: i64,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionErrors {
    pub total: i64,
    /// Most-frequent `gateway_audit.error_category` value in the window
    /// (e.g. `"auth"`, `"upstream"`, `"timeout"`, `"rate_limit"`). `None`
    /// when there are no errors. Surfaces as the tile's subtitle.
    pub top_error_category: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct AttentionBudget {
    /// Scopes (organisation ceiling, workspace pool, member limit, or per-key cap) at or over
    /// their daily/monthly budget cap in the current window.
    pub breached: i64,
    /// Scopes between 80% and 100% of cap (approaching the ceiling).
    pub approaching: i64,
    /// Worst offender's spend as a fraction of its cap (≥0). `None` when no cap
    /// is configured or no spend recorded. Surfaces as the tile's subtitle.
    pub worst_ratio: Option<f64>,
    /// Worst offender's scope (`"tenant"` | `"workspace"` | `"user"` (a
    /// member) | `"key"`) for the deep-link.
    pub worst_scope_kind: Option<String>,
    pub worst_scope_id: Option<Uuid>,
    /// The workspace the worst offender belongs to — where a member's limit is
    /// set (its Limits tab). `None` for the organisation ceiling.
    pub worst_workspace_id: Option<Uuid>,
}

/// Whether the tenant's LLM upstream servers can serve traffic now, and whether
/// capacity ran out in the window.
#[derive(Serialize, ToSchema)]
pub struct AttentionUpstreams {
    /// Enabled upstream servers.
    pub servers_total: i64,
    /// Servers with some — not all — of their enabled endpoints out of rotation.
    pub degraded: i64,
    /// Servers with every enabled endpoint out of rotation.
    pub down: i64,
    /// The server that is down, when exactly one is, so the tile can open it.
    pub down_server_id: Option<Uuid>,
    /// Refusals the dispatch gate gave for want of capacity in the window —
    /// including each one a request then moved on from to a fallback.
    pub refused: i64,
    /// Endpoints whose engine gauges the gateway reads and which have gone
    /// quiet — their queue bound is not being applied.
    pub engines_silent: i64,
}

/// Per-scope budget status for the current daily/monthly window — the shared
/// evaluation behind both the attention tile and the proactive-alert producer.
pub(crate) struct BudgetScopeStatus {
    pub scope_kind: String, // 'tenant' | 'workspace' | 'user' | 'key'
    pub scope_id: Uuid,
    pub workspace_id: Uuid,
    pub window_kind: String, // 'daily' | 'monthly'
    pub window_start: DateTime<Utc>,
    /// Both in the tenant's accounting currency. The counter stores millionths
    /// of that currency; the query converts once here so nothing downstream has
    /// to know the counter's unit.
    pub spent: f64,
    pub cap: f64,
}

/// The share of a budget at which it is "approaching" — the band the budget
/// notifications fire at and the portal Home warns from (the console meters
/// colour from the same value, `meterTone` in `lib/limits.ts`).
const BUDGET_APPROACHING_SHARE: f64 = 0.8;

impl BudgetScopeStatus {
    /// spend / cap. `cap` is always > 0 — only capped scopes are returned.
    pub fn ratio(&self) -> f64 {
        self.spent / self.cap
    }

    /// 0 = ok, 1 = approaching (≥80%), 2 = breached (≥100%).
    pub fn band(&self) -> i16 {
        budget_band(self.spent, self.cap)
    }
}

/// Where `used` stands against `cap`: 0 = ok, 1 = approaching (≥
/// [`BUDGET_APPROACHING_SHARE`]), 2 = breached (≥ the cap). No cap (`cap ≤ 0`)
/// is always 0. The one decision behind the budget notifications and the
/// portal Home's warnings — keep every reader on it.
pub(crate) fn budget_band(used: f64, cap: f64) -> i16 {
    if cap <= 0.0 {
        return 0;
    }
    let r = used / cap;
    if r >= 1.0 {
        2
    } else if r >= BUDGET_APPROACHING_SHARE {
        1
    } else {
        0
    }
}

/// Evaluate every capped tenant / workspace / member / per-key scope's spend
/// against its cap for the current daily + monthly windows. Spend comes from the
/// fleet-convergent `usage_counters` (millionths of the tenant's accounting
/// currency, converted to whole units here). Caps are the ones ENFORCED, read
/// through [`crate::limits`] — so a workspace inheriting the tenant default
/// budget is evaluated against that default, and a member against the
/// workspace's default member limit or their exception — never a raw column.
/// Window starts match the edge's epoch alignment exactly. `workspace_filter`
/// optionally narrows to one workspace — and drops the tenant scope, which
/// belongs to no single workspace (its rows carry a nil `workspace_id` for the
/// same reason).
///
/// A member row's `scope_id` is the USER (what a person is shown and linked
/// to); its counter is found under the membership id
/// ([`streamscope_core::auth::member_limits::member_scope_id`]).
pub(crate) async fn evaluate_budget_scopes(
    conn: &mut Scoped,
    tenant_id: Uuid,
    workspace_filter: Option<Uuid>,
) -> Result<Vec<BudgetScopeStatus>, sqlx::Error> {
    use streamscope_core::auth::member_limits::member_scope_id;
    let now_ms = streamscope_core::usage::now_ms();
    let (Some(daily_start), Some(monthly_start)) = (
        DateTime::<Utc>::from_timestamp_millis(
            streamscope_core::usage::UsageWindowKind::Daily.window_start_ms(now_ms) as i64,
        ),
        DateTime::<Utc>::from_timestamp_millis(
            streamscope_core::usage::UsageWindowKind::Monthly.window_start_ms(now_ms) as i64,
        ),
    ) else {
        return Ok(Vec::new());
    };

    // (scope_kind, scope_id shown, counter scope_id, workspace_id, daily cap, monthly cap)
    let mut caps: Vec<(&'static str, Uuid, Uuid, Uuid, f64, f64)> = Vec::new();
    let settings = crate::limits::load_tenant_budget_settings(&mut *conn).await?;
    if workspace_filter.is_none() {
        caps.push(("tenant", tenant_id, tenant_id, Uuid::nil(), settings.org_daily, settings.org_monthly));
    }
    for (ws, pool) in crate::limits::load_pools_with_default(&mut *conn, settings.default).await? {
        if workspace_filter.is_none_or(|f| f == ws) {
            caps.push(("workspace", ws, ws, ws, pool.daily_budget, pool.monthly_budget));
        }
    }
    for ((ws, user), bucket) in crate::limits::load_member_buckets(&mut *conn, workspace_filter).await? {
        caps.push(("user", user, member_scope_id(ws, user), ws, bucket.daily_budget, bucket.monthly_budget));
    }
    let key_caps: Vec<(Uuid, Uuid, Option<f64>, Option<f64>)> = sqlx::query_as(
        "SELECT id, workspace_id, daily_budget, monthly_budget FROM api_keys \
          WHERE tenant_id = $1 AND revoked_at IS NULL \
            AND (daily_budget > 0 OR monthly_budget > 0) \
            AND ($2::uuid IS NULL OR workspace_id = $2)",
    )
    .bind(tenant_id)
    .bind(workspace_filter)
    .fetch_all(&mut *conn)
    .await?;
    for (key, ws, daily, monthly) in key_caps {
        caps.push(("key", key, key, ws, daily.unwrap_or(0.0), monthly.unwrap_or(0.0)));
    }
    caps.retain(|c| c.4 > 0.0 || c.5 > 0.0);
    if caps.is_empty() {
        return Ok(Vec::new());
    }

    // The tenant's current-window budget rows, matched to the caps below: rows
    // exist only for scopes that spent, so this is bounded by activity, not by
    // how many members a default applies to.
    let spend_rows: Vec<(String, Uuid, String, i64)> = sqlx::query_as(
        "SELECT scope_kind, scope_id, window_kind, total FROM usage_counters \
          WHERE tenant_id = $1 AND metric = 'budget_micros' \
            AND ((window_kind = 'daily' AND window_start = $2) OR (window_kind = 'monthly' AND window_start = $3))",
    )
    .bind(tenant_id)
    .bind(daily_start)
    .bind(monthly_start)
    .fetch_all(&mut *conn)
    .await?;
    let spend: HashMap<(String, Uuid, String), f64> = spend_rows
        .into_iter()
        .map(|(kind, id, window, total)| ((kind, id, window), total as f64 / 1_000_000.0))
        .collect();

    let mut out = Vec::new();
    for (kind, shown, counter, ws, daily_cap, monthly_cap) in caps {
        for (window_kind, window_start, cap) in [("daily", daily_start, daily_cap), ("monthly", monthly_start, monthly_cap)] {
            if cap <= 0.0 {
                continue;
            }
            let spent = spend.get(&(kind.to_string(), counter, window_kind.to_string())).copied();
            // A member who has spent nothing has nothing to report: a default
            // applies to every member, and a row each would scale with headcount.
            if kind == "user" && spent.is_none() {
                continue;
            }
            out.push(BudgetScopeStatus {
                scope_kind: kind.to_string(),
                scope_id: shown,
                workspace_id: ws,
                window_kind: window_kind.to_string(),
                window_start,
                spent: spent.unwrap_or(0.0),
                cap,
            });
        }
    }
    Ok(out)
}

/// Current daily + monthly budget spend, in the tenant's accounting currency,
/// for every scope of one kind
/// (`"user"` | `"key"`) in a tenant, from the fleet-convergent `usage_counters`.
/// Keyed by the COUNTER's `scope_id` → `(daily, monthly)` — for `"user"` that is
/// the membership id ([`streamscope_core::auth::member_limits::member_scope_id`]),
/// not the user id. A scope with no recorded spend is absent. Lets the per-user-override and per-key budget surfaces show
/// spend-vs-cap the same way the workspace ceiling does (the workspace ceiling
/// has its own single-scope fetch). Window starts match the edge's epoch
/// alignment exactly, like [`evaluate_budget_scopes`].
pub(crate) async fn current_budget_spend(
    conn: &mut Scoped,
    tenant_id: Uuid,
    scope_kind: &str,
) -> Result<HashMap<Uuid, (f64, f64)>, sqlx::Error> {
    let now_ms = streamscope_core::usage::now_ms();
    let daily_start = DateTime::<Utc>::from_timestamp_millis(
        streamscope_core::usage::UsageWindowKind::Daily.window_start_ms(now_ms) as i64,
    );
    let monthly_start = DateTime::<Utc>::from_timestamp_millis(
        streamscope_core::usage::UsageWindowKind::Monthly.window_start_ms(now_ms) as i64,
    );
    let rows: Vec<(Uuid, f64, f64)> = sqlx::query_as(
        "SELECT scope_id, \
            COALESCE(MAX(total) FILTER (WHERE window_kind = 'daily'   AND window_start = $2), 0)::float8 AS daily_micros, \
            COALESCE(MAX(total) FILTER (WHERE window_kind = 'monthly' AND window_start = $3), 0)::float8 AS monthly_micros \
           FROM usage_counters \
          WHERE tenant_id = $1 AND scope_kind = $4 AND metric = 'budget_micros' \
            AND ((window_kind = 'daily' AND window_start = $2) OR (window_kind = 'monthly' AND window_start = $3)) \
          GROUP BY scope_id",
    )
    .bind(tenant_id)
    .bind(daily_start)
    .bind(monthly_start)
    .bind(scope_kind)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows
        .into_iter()
        .map(|(id, daily_micros, monthly_micros)| (id, (daily_micros / 1_000_000.0, monthly_micros / 1_000_000.0)))
        .collect())
}

#[derive(Serialize, ToSchema)]
pub struct AttentionResponse {
    pub alerts: AttentionAlerts,
    pub blocked: AttentionBlocked,
    pub guardrail: AttentionGuardrail,
    pub expiring: AttentionExpiring,
    pub errors: AttentionErrors,
    pub budget: AttentionBudget,
    pub upstreams: AttentionUpstreams,
    pub generated_at: DateTime<Utc>,
    /// Echoed window so the UI can label "in last Nd" without re-computing.
    pub window_days: i32,
    pub expiry_window_days: i32,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/analytics/cross/attention",
    tag = "Analytics",
    params(CrossAttentionQuery),
    responses(
        (status = 200, description = "Attention queue: counts of items needing operator action — flagged sessions, blocked tool calls, expiring credentials, and authentication failures. Each tile on the Dashboard Overview reads from a field on this response and deep-links into the corresponding management surface.", body = AttentionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn cross_attention(
    mut db: TenantConn,
    Query(query): Query<CrossAttentionQuery>,
) -> Result<Json<AttentionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let window_days = query.window_days.unwrap_or(1).clamp(1, 30);
    let expiry_window_days = query.expiry_window_days.unwrap_or(7).clamp(1, 90);
    tools_store::cross_attention(&mut db, tenant_id, window_days, expiry_window_days, &query).await.map(Json)
}

#[cfg(test)]
mod tests {

    #[test]
    fn a_budget_band_turns_at_its_share_and_at_its_cap_on_both_sides() {
        use super::budget_band;
        // 80 % of a cap of 10 is 8; the ratio form avoids `cap * share`
        // rounding (0.3 * 0.8 is 0.24000000000000002).
        assert_eq!(budget_band(7.99, 10.0), 0);
        assert_eq!(budget_band(8.0, 10.0), 1);
        assert_eq!(budget_band(0.24, 0.3), 1);
        assert_eq!(budget_band(9.99, 10.0), 1);
        assert_eq!(budget_band(10.0, 10.0), 2);
        assert_eq!(budget_band(15.0, 10.0), 2);
        assert_eq!(budget_band(0.0, 10.0), 0);
        // No cap: never a band, however much was spent.
        assert_eq!(budget_band(5.0, 0.0), 0);
        assert_eq!(budget_band(5.0, -1.0), 0);
    }

    /// The events of one stored turn: its request's messages, and its answer's
    /// calls with the response-phase records in its transform diff.
    fn turn_events(
        protocol: streamscope_core::api::sse::ApiVersion,
        messages: serde_json::Value,
        calls: Option<serde_json::Value>,
        blocked: Option<serde_json::Value>,
    ) -> Vec<crate::conversation::ConversationEvent> {
        let diff: Option<streamscope_core::proxy::content::TransformDiff> = blocked.map(|records| {
            serde_json::from_value(serde_json::json!({
                "transform_programs": [], "system_prompt_modified": false,
                "messages_original_count": 0, "messages_after_count": 0, "telemetry_dropped": [],
                "response_blocked_tools": records,
            }))
            .unwrap()
        });
        let turn = crate::conversation::TurnRow {
            turn_number: 1,
            protocol,
            system_prompt: None,
            messages_json: &messages,
            request_tools: None,
            tools_available_hash: None,
            tools_effective_hash: None,
            request_params: None,
            response_content: None,
            response_tool_calls: calls.as_ref(),
            thinking: None,
            model: "m",
            metadata: None,
            include_raw: false,
            dedup_filtered: true,
            transform_diff: diff.as_ref(),
        };
        crate::conversation::build_events(&turn).unwrap().events
    }

    /// Each paired result's text, by the call's place.
    fn paired(
        calls: &[crate::conversation::ConversationEvent],
        answer: &[crate::conversation::ConversationEvent],
    ) -> Vec<Option<String>> {
        crate::conversation::pair_results(calls, answer)
            .into_iter()
            .zip(calls)
            .filter(|(_, call)| matches!(call, crate::conversation::ConversationEvent::ToolCall { is_new: true, .. }))
            .map(|(r, _)| match r {
                Some(crate::conversation::ConversationEvent::ToolResult { content, .. }) => Some(content),
                _ => None,
            })
            .collect()
    }

    /// A call recorded without an id takes no result: no id
    /// names one, so none is shown rather than a sibling's — even when a
    /// result answers an empty id. Its sibling with an id (the control) takes
    /// its own.
    #[test]
    fn a_call_recorded_without_an_id_takes_no_result() {
        use streamscope_core::api::sse::ApiVersion;
        let chat = ApiVersion::ChatCompletions;
        let recorded = |at: usize| {
            serde_json::json!({"index": at, "id": "", "function_name": "search", "arguments": "{}", "server_tool": false})
        };
        let calls = turn_events(
            chat,
            serde_json::json!([{"role": "user", "content": "go"}]),
            Some(serde_json::json!([recorded(0), recorded(1), {"index": 2, "id": "own", "function_name": "search", "arguments": "{}", "server_tool": false}])),
            None,
        );
        let minted = |id: &str| serde_json::json!({"type": "function", "id": id, "function": {"name": "search", "arguments": "{}"}});
        let answer = turn_events(
            chat,
            serde_json::json!([
                {"role": "assistant", "tool_calls": [minted("call_0"), minted("call_1")]},
                {"role": "tool", "tool_call_id": "call_0", "content": "A"},
                {"role": "tool", "tool_call_id": "", "content": "B"},
                {"role": "tool", "tool_call_id": "own", "content": "C"},
            ]),
            None,
            None,
        );
        assert_eq!(paired(&calls, &answer), [None, None, Some("C".to_string())]);
    }

    /// Calls repeating an id take its results in order (the control: a call
    /// with an id of its own takes only its own), and a call policy removed —
    /// which a whole answer's row records beside its siblings — takes none.
    #[test]
    fn calls_repeating_an_id_take_its_results_in_order() {
        use streamscope_core::api::sse::ApiVersion;
        let chat = ApiVersion::ChatCompletions;
        let call = |id: &str| serde_json::json!({"type": "function", "id": id, "function": {"name": "search", "arguments": "{}"}});
        let calls = turn_events(
            chat,
            serde_json::json!([{"role": "user", "content": "go"}]),
            Some(serde_json::json!([call("x"), call("x"), call("y")])),
            None,
        );
        let answer = turn_events(
            chat,
            serde_json::json!([
                {"role": "assistant", "tool_calls": [call("x"), call("x"), call("y")]},
                {"role": "tool", "tool_call_id": "y", "content": "3"},
                {"role": "tool", "tool_call_id": "x", "content": "1"},
                {"role": "tool", "tool_call_id": "x", "content": "2"},
            ]),
            None,
            None,
        );
        let text = |t: &str| Some(t.to_string());
        assert_eq!(paired(&calls, &answer), [text("1"), text("2"), text("3")]);

        let removed = serde_json::json!([{
            "name": "search", "title": "t", "description": "d", "rule_id": "R-1", "tool_use_id": "x", "call_index": 0,
        }]);
        let calls = turn_events(
            chat,
            serde_json::json!([{"role": "user", "content": "go"}]),
            Some(serde_json::json!([call("x"), call("x")])),
            Some(removed),
        );
        let answer = turn_events(
            chat,
            serde_json::json!([
                {"role": "assistant", "tool_calls": [call("x")]},
                {"role": "tool", "tool_call_id": "x", "content": "1"},
            ]),
            None,
            None,
        );
        assert_eq!(paired(&calls, &answer), [None, text("1")]);
    }

    #[test]
    fn a_call_matches_on_its_argument_values_not_its_keys() {
        let args = serde_json::json!({"path": "src/Main.rs", "opts": {"depth": 3, "tags": ["x", "Yz"]}});
        assert!(super::json_values_contain(&args, "main.rs"));
        assert!(super::json_values_contain(&args, "yz"));
        assert!(super::json_values_contain(&args, "3"));
        assert!(!super::json_values_contain(&args, "path"));
        assert!(!super::json_values_contain(&args, "depth"));
        assert!(!super::json_values_contain(&args, "\""));
        // A raw argument string is searched whole, as the SQL blob holds it.
        let raw = serde_json::Value::String(r#"{"path": "a"}"#.to_string());
        assert!(super::json_values_contain(&raw, "path"));
        assert!(!super::json_values_contain(&serde_json::Value::Null, "null"));
    }
    use super::AppInfo;

    #[test]
    fn a_prompt_pattern_shorter_than_the_minimum_is_refused() {
        use streamscope_core::middleware::attribution::MIN_PROMPT_PATTERN_CHARS;
        let app = |pattern: String| AppInfo {
            id: "custom".into(),
            name: String::new(),
            description: String::new(),
            url: String::new(),
            builtin: false,
            ua_patterns: vec![],
            referer_patterns: vec![],
            prompt_patterns: vec![pattern],
        };
        let at = "é".repeat(MIN_PROMPT_PATTERN_CHARS);
        let below = "é".repeat(MIN_PROMPT_PATTERN_CHARS - 1);
        assert!(super::validate_prompt_patterns(&[app(at.clone())]).is_ok());
        // Surrounding whitespace is not part of the pattern.
        assert!(super::validate_prompt_patterns(&[app(format!("  {below}  "))]).is_err());
        assert!(super::validate_prompt_patterns(&[app(String::new())]).is_err());
        // An app with no prompt pattern is untouched by the rule.
        let mut none = app(at);
        none.prompt_patterns.clear();
        assert!(super::validate_prompt_patterns(&[none]).is_ok());
    }

    #[test]
    fn appinfo_deserialize_all_fields() {
        let json = serde_json::json!({
            "id": "cursor",
            "name": "Cursor",
            "description": "AI code editor",
            "url": "https://cursor.com",
            "builtin": true,
            "ua_patterns": ["cursor/"],
            "referer_patterns": ["cursor.sh"]
        });
        let info: AppInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.id, "cursor");
        assert_eq!(info.name, "Cursor");
        assert_eq!(info.description, "AI code editor");
        assert_eq!(info.url, "https://cursor.com");
        assert!(info.builtin);
        assert_eq!(info.ua_patterns, vec!["cursor/"]);
        assert_eq!(info.referer_patterns, vec!["cursor.sh"]);
    }

    #[test]
    fn appinfo_deserialize_minimal() {
        let json = serde_json::json!({"id": "custom-app"});
        let info: AppInfo = serde_json::from_value(json).unwrap();
        assert_eq!(info.id, "custom-app");
        assert_eq!(info.name, "");
        assert_eq!(info.description, "");
        assert_eq!(info.url, "");
        assert!(!info.builtin);
        assert!(info.ua_patterns.is_empty());
        assert!(info.referer_patterns.is_empty());
    }

    #[test]
    fn appinfo_vec_survives_partial_entries() {
        let json = serde_json::json!([
            {"id": "full", "name": "Full App", "description": "Has everything", "url": "https://example.com", "builtin": true},
            {"id": "minimal"},
            {"id": "partial", "name": "Partial", "ua_patterns": ["partial/"]}
        ]);
        let apps: Vec<AppInfo> = serde_json::from_value(json).unwrap();
        assert_eq!(apps.len(), 3);
        assert_eq!(apps[0].id, "full");
        assert_eq!(apps[1].id, "minimal");
        assert_eq!(apps[1].name, "");
        assert_eq!(apps[2].id, "partial");
        assert_eq!(apps[2].ua_patterns, vec!["partial/"]);
    }

    #[test]
    fn appinfo_missing_id_fails() {
        let json = serde_json::json!({"name": "No ID App"});
        let result: Result<AppInfo, _> = serde_json::from_value(json);
        assert!(result.is_err());
    }

    #[test]
    fn overhead_percentiles_interpolate_from_delta_histogram() {
        use streamscope_core::metrics::OVERHEAD_BUCKET_COUNT;

        // 90 samples <=256µs, 10 samples in (1024, 2048]µs: p50 sits inside
        // the first bucket, p95+ inside the fourth.
        let mut hist = vec![0i64; OVERHEAD_BUCKET_COUNT];
        hist[0] = 90;
        hist[3] = 10;
        let (p50, p95, p99) = super::overhead_percentiles_ms(&Some(hist));
        assert!(p50 > 0.0 && p50 <= 0.256, "p50={p50}");
        assert!((1.024..=2.048).contains(&p95), "p95={p95}");
        assert!((1.024..=2.048).contains(&p99), "p99={p99}");
        assert!(p95 <= p99);

        // Missing or wrongly-shaped histograms read as zeros, never a panic.
        assert_eq!(super::overhead_percentiles_ms(&None), (0.0, 0.0, 0.0));
        assert_eq!(super::overhead_percentiles_ms(&Some(vec![5; 3])), (0.0, 0.0, 0.0));
    }
}

// ---------------------------------------------------------------------------
// A2A Dashboard
//
// The agent-to-agent analog of the MCP and Web dashboards: the same query
// shape, the same panel envelope, the same UI primitives. What is worth asking
// about A2A traffic is different, though — an agent call has no tool and no
// tokens, so the pivots are the AGENT, the operation, and the fate of the task
// it created.
// ---------------------------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct A2aDashboardQuery {
    pub days: Option<i32>,
    pub start: Option<DateTime<Utc>>,
    pub end: Option<DateTime<Utc>>,
    pub app_id: Option<String>,
    pub user_id: Option<Uuid>,
    /// Top-N rows. Default 20, max 100.
    pub limit: Option<i64>,
    /// Comma-separated workspace ids to include (UUIDs). Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl A2aDashboardQuery {
    pub(crate) fn time_window(&self) -> TimeWindow {
        TimeWindow {
            days: self.days,
            start: self.start,
            end: self.end,
        }
    }
    pub(crate) fn resolved_limit(&self) -> i64 {
        self.limit.unwrap_or(20).clamp(1, 100)
    }
}

#[derive(Serialize, ToSchema)]
pub struct A2aDashboardSummary {
    pub calls: i64,
    /// Distinct agents addressed in the window.
    pub agents: i64,
    /// Distinct remote tasks the calls created or addressed.
    pub tasks: i64,
    /// Distinct A2A conversations (`contextId`).
    pub contexts: i64,
    pub unique_users: i64,
    /// HTTP 4xx/5xx or a JSON-RPC error code.
    pub errors: i64,
    /// Calls tool policy refused before they reached the agent.
    pub blocked: i64,
    /// Calls carrying at least one inline-guardrail finding (either direction).
    pub guardrail_flagged: i64,
    /// Streamed calls (`SendStreamingMessage` / `SubscribeToTask`).
    pub streamed: i64,
    pub p50_latency_ms: f64,
    pub p95_latency_ms: f64,
    pub p99_latency_ms: f64,
}

/// One row of an A2A breakdown panel.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct A2aBreakdownItem {
    /// Pivot value — an agent slug, a method, a task state, or a user's display
    /// name. Always TEXT so one component renders every panel.
    pub key: String,
    /// The value a deep-link filters on, when it differs from the displayed
    /// `key`. The user pivot displays a name but filters by `user_id`; every
    /// other pivot's key IS its filter value (an agent's slug, a method, a task
    /// state) and leaves this `None`. A panel row must never link on a label —
    /// a display name is not a filter, and the audit list would come back empty.
    pub filter_id: Option<String>,
    pub call_count: i64,
    pub error_count: i64,
    pub p95_latency_ms: Option<f64>,
    pub last_used: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct A2aDashboardPanel {
    pub items: Vec<A2aBreakdownItem>,
    /// Calls across every group, before the top-N cut — the denominator the UI
    /// renders shares against.
    pub total_calls: i64,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/dashboard/summary",
    tag = "A2A Dashboard",
    params(A2aDashboardQuery),
    responses(
        (status = 200, description = "A2A headline metrics — calls, agents, tasks, conversations, errors, policy blocks, guardrail findings, latency percentiles", body = A2aDashboardSummary),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn a2a_dashboard_summary(
    mut db: TenantConn,
    Query(query): Query<A2aDashboardQuery>,
) -> Result<Json<A2aDashboardSummary>, ApiError> {
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    a2a_store::a2a_dashboard_summary(db.conn(), start, end, &query).await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/dashboard/by-agent",
    tag = "A2A Dashboard",
    params(A2aDashboardQuery),
    responses(
        (status = 200, description = "Top remote agents by call count", body = A2aDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn a2a_dashboard_by_agent(
    mut db: TenantConn,
    Query(query): Query<A2aDashboardQuery>,
) -> Result<Json<A2aDashboardPanel>, ApiError> {
    a2a_store::a2a_dashboard_panel(db.conn(), &query, "ag.slug").await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/dashboard/by-method",
    tag = "A2A Dashboard",
    params(A2aDashboardQuery),
    responses(
        (status = 200, description = "A2A operations by call count", body = A2aDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn a2a_dashboard_by_method(
    mut db: TenantConn,
    Query(query): Query<A2aDashboardQuery>,
) -> Result<Json<A2aDashboardPanel>, ApiError> {
    a2a_store::a2a_dashboard_panel(db.conn(), &query, "a2.method").await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/dashboard/by-task-state",
    tag = "A2A Dashboard",
    params(A2aDashboardQuery),
    responses(
        (status = 200, description = "How remote tasks ended — the A2A analog of a finish-reason breakdown", body = A2aDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn a2a_dashboard_by_task_state(
    mut db: TenantConn,
    Query(query): Query<A2aDashboardQuery>,
) -> Result<Json<A2aDashboardPanel>, ApiError> {
    a2a_store::a2a_dashboard_panel(db.conn(), &query, "a2.task_state").await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/dashboard/by-user",
    tag = "A2A Dashboard",
    params(A2aDashboardQuery),
    responses(
        (status = 200, description = "Top users by A2A call count", body = A2aDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn a2a_dashboard_by_user(
    mut db: TenantConn,
    Query(query): Query<A2aDashboardQuery>,
) -> Result<Json<A2aDashboardPanel>, ApiError> {
    a2a_store::a2a_dashboard_panel(db.conn(), &query, "g.user_id").await.map(Json)
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/a2a/dashboard/by-app",
    tag = "A2A Dashboard",
    params(A2aDashboardQuery),
    responses(
        (status = 200, description = "Top calling apps by A2A call count", body = A2aDashboardPanel),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn a2a_dashboard_by_app(
    mut db: TenantConn,
    Query(query): Query<A2aDashboardQuery>,
) -> Result<Json<A2aDashboardPanel>, ApiError> {
    a2a_store::a2a_dashboard_panel(db.conn(), &query, "g.app_id").await.map(Json)
}
