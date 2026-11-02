//! Tool risk rule CRUD — first-class management of the per-tenant rule list.
//!
//! Storage is the `tool_policy_rules` table, **one row per rule**. Each mutation
//! is a single-row statement (insert / update-by-`rule_id` / soft-delete), so
//! concurrent edits to different rules touch different rows and never contend —
//! there is no whole-collection read-modify-write to lose an update on. A
//! user-deleted builtin is a `suppressed` row (seed-sync skips it), never a
//! tombstone side-list. `seq` carries the evaluation/display order (gap-spaced so
//! a reorder is a single-row update); the config snapshot ships the rules under
//! the `tool_rules` settings key built from this table, so the proxy wire is
//! unchanged.
//!
//! A mutation reaches the proxies through the config change triggers.

use super::is_unique_violation;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};

use streamscope_core::config::tool_rules::{
    self, ActionKind, MatchCondition, Phase, RuleAction, Scope, ValidationError,
};

use super::analytics::ToolRule;
use super::analytics::DEFAULT_USAGE_DAYS;
use super::{
    ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage,
    PageQuery, SourceFilter, TimeWindow, WorkspaceIds, parse_workspace_ids,
};
use crate::db::tenant::{Scoped, TenantConn};
use crate::middleware::AuditDiffSink;

/// Rule ids are embedded in URLs (`/tool-rules/{id}`) and in the UI's
/// `#rule-{id}` scroll anchor. Restrict to a safe charset so deep-links don't
/// need url-encoding beyond basic escaping and CSS selectors stay valid.
const MAX_RULE_ID_LEN: usize = 64;
pub(crate) fn is_valid_rule_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= MAX_RULE_ID_LEN
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

// ---------------------------------------------------------------------------
// Query + request types
// ---------------------------------------------------------------------------

/// The `view` a tool-rule list can ask for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ToolRuleView {
    /// The Default profile's rules — the shared base.
    Shared,
}

#[derive(Debug, Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ToolRuleListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
    /// Filter by risk level: `safe`, `caution`, `danger`, `unknown`.
    pub risk: Option<String>,
    /// Filter by action kind. Omit for all.
    pub action: Option<ActionKind>,
    /// Filter by phase. Omit for all.
    pub phase: Option<Phase>,
    /// Filter by scope. Omit for all.
    pub scope: Option<Scope>,
    /// Filter by origin. Omit for all.
    pub source: Option<SourceFilter>,
    /// Scope to one profile's **effective set**: for a Layered profile the
    /// Default's rules (minus any it forked) plus its own; for a Standalone/Default
    /// profile its own rules only. Omit for all rules across every profile.
    pub profile_id: Option<uuid::Uuid>,
    /// `shared` → only the Default profile's rules (the shared base). Mutually
    /// exclusive with `profile_id`.
    pub view: Option<ToolRuleView>,
    /// Filter by enabled state. Omit for all.
    pub enabled: Option<bool>,
    /// Case-insensitive substring match on title, id, or any condition value.
    pub q: Option<String>,
    /// Activity-window: rolling lookback in days. Mutually exclusive with
    /// `start`/`end`. The window scopes `call_count_window` /
    /// `tool_count_window` / `last_seen` on each row — it does NOT filter
    /// rules out of the response.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
    /// Optional app filter for the activity window — narrows the per-rule
    /// classification stream the same way `/analytics/tools` does.
    pub app_id: Option<String>,
    /// Comma-separated workspace ids to include (UUIDs) in the activity window.
    /// Omit for all workspaces.
    #[param(value_type = Option<String>)]
    pub workspace_ids: Option<WorkspaceIds>,
}

impl ToolRuleListQuery {
    fn time_window(&self) -> TimeWindow {
        TimeWindow {
            days: self.days,
            start: self.start,
            end: self.end,
        }
    }
}

/// Per-rule activity aggregated over the request's time window.
#[derive(Debug, Clone, Default, Serialize, ToSchema)]
pub struct RuleActivity {
    /// Calls that fired this rule (first-match-wins, per the unified evaluator).
    pub call_count_window: i64,
    /// Distinct wire tool names with at least one matching call.
    pub tool_count_window: i64,
    /// Most recent matching call timestamp; `None` when the rule never fired
    /// in the window.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_seen: Option<DateTime<Utc>>,
}

/// List-row shape — flattens [`ToolRule`] and adds activity counters scoped to
/// the request's [`TimeWindow`]. Activity fields are read-only: they're never
/// deserialised on `PATCH`, never accepted on `POST`.
#[derive(Debug, Serialize, ToSchema)]
pub struct ToolRuleListItem {
    #[serde(flatten)]
    #[schema(inline)]
    pub rule: ToolRule,
    #[serde(flatten)]
    #[schema(inline)]
    pub activity: RuleActivity,
}

/// Body of POST /tool-rules. Mirrors `tool_rules::Rule` minus server-managed
/// `is_builtin` (always false on user create — settable only via reset/seed).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateToolRule {
    /// Optional stable identifier. When omitted, the server mints a UUID.
    pub id: Option<String>,
    pub title: Option<String>,
    pub description: Option<String>,
    pub risk: String,
    pub phase: Phase,
    pub scope: Scope,
    #[serde(default)]
    #[serde(rename = "match")]
    pub conditions: Vec<MatchCondition>,
    pub action: RuleAction,
    #[serde(default = "default_priority")]
    pub priority: i32,
    pub model_filter: Option<String>,
    /// Optional pipe-separated glob over the request `app_id`. Scopes the
    /// rule to specific clients.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_filter: Option<String>,
    /// Optional pipe-separated glob over the MCP upstream server name. Scopes
    /// the rule to specific upstreams; only meaningful for
    /// `(request, resource_reads | prompt_invocations)` and MCP-gateway
    /// `(response, tool_calls)` paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server_filter: Option<String>,
    /// Optional pipe-separated glob over the A2A upstream agent slug. Scopes the
    /// rule to specific agents; only meaningful on the `agent_calls` scope.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_agent_filter: Option<String>,
    pub enabled: Option<bool>,
    #[serde(default)]
    pub framework_refs: Vec<String>,
    /// Profile scope. Omit (or `null`) → **shared** (applies to every profile —
    /// the baseline). A UUID scopes the rule to that one profile.
    #[serde(default)]
    pub profile_id: Option<uuid::Uuid>,
    /// Copy-on-write link: when set (with `profile_id = Some(P)`), this rule is a
    /// per-profile fork of the shared rule with this id — it overrides that shared
    /// rule inside P. Used by the "Customize here" action.
    #[serde(default)]
    pub forked_from: Option<String>,
}

impl CreateToolRule {
    /// The rule this body describes, under `id`. A user-created rule is never
    /// builtin; a body naming no profile lands in `fallback_profile`.
    fn into_rule(self, id: String, fallback_profile: Option<uuid::Uuid>) -> ToolRule {
        ToolRule {
            id,
            title: self.title,
            description: self.description,
            risk: self.risk,
            phase: self.phase,
            scope: self.scope,
            conditions: self.conditions,
            action: self.action,
            priority: self.priority,
            model_filter: self.model_filter,
            app_filter: self.app_filter,
            mcp_server_filter: self.mcp_server_filter,
            a2a_agent_filter: self.a2a_agent_filter,
            enabled: self.enabled.unwrap_or(true),
            framework_refs: self.framework_refs,
            is_builtin: false,
            profile_id: self.profile_id.or(fallback_profile),
            forked_from: self.forked_from,
        }
    }
}

fn default_priority() -> i32 {
    100
}

/// Body of PATCH /tool-rules/{id}. Every field is optional — a missing
/// field means "leave as-is". `position` reorders the rule within the list
/// (lower = earlier) but does not promote a builtin to custom.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateToolRule {
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub title: Option<Option<String>>,
    /// Absent leaves it; `null` clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    pub risk: Option<String>,
    pub phase: Option<Phase>,
    pub scope: Option<Scope>,
    #[serde(rename = "match")]
    pub conditions: Option<Vec<MatchCondition>>,
    pub action: Option<RuleAction>,
    pub priority: Option<i32>,
    /// PATCH triple-state: absent = unchanged, `null` = clear, value = set.
    /// `double_option::deserialize` overrides serde's default outer-`Option`
    /// collapse so `null` lands as `Some(None)` instead of being read as
    /// "field absent".
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub model_filter: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub app_filter: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub mcp_server_filter: Option<Option<String>>,
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    pub a2a_agent_filter: Option<Option<String>>,
    pub enabled: Option<bool>,
    pub framework_refs: Option<Vec<String>>,
    /// Reassign the rule to another tool profile. Absent = unchanged. A rule
    /// always belongs to a profile, so there is no "clear to null".
    pub profile_id: Option<uuid::Uuid>,
    /// Move the rule to this 0-based position in the list. Equal-priority
    /// rules use list order as the tiebreaker so manual ordering matters.
    pub position: Option<usize>,
}

/// Body of POST /tool-rules/actions/test. Carries a draft rule (the create
/// body: its id may be omitted) and a list of sample tool names + optional
/// sample args; returns one match result per sample. The rule isn't persisted —
/// used by the modal sandbox to preview matching.
#[derive(Debug, Deserialize, ToSchema)]
pub struct TestToolRule {
    pub rule: CreateToolRule,
    pub sample_tool_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    /// The tool-call arguments to test the rule against, as a tool would send them.
    #[schema(value_type = Object, nullable)]
    pub sample_args: Option<serde_json::Value>,
    /// Optional sample tool_result content body — only relevant for
    /// `phase=request, scope=tool_results` rules. Ignored otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_content: Option<String>,
    /// Optional model name for `model_filter` evaluation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample_model: Option<String>,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TestMatch {
    pub tool_name: String,
    pub matched: bool,
    /// Human-readable reason when match/no-match is non-obvious
    /// (e.g. "name matched but arg_patterns did not").
    pub reason: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct TestToolRuleResponse {
    pub matches: Vec<TestMatch>,
}

pub use super::ResetImpact;

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-rules",
    tag = "Tool Rules",
    params(ToolRuleListQuery),
    responses(
        (status = 200, description = "Paginated rule list", body = OffsetPage<ToolRuleListItem>),
        (status = 400, description = "Invalid time window", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tool_rules(
    mut db: TenantConn,
    Query(query): Query<ToolRuleListQuery>,
) -> Result<Json<OffsetPage<ToolRuleListItem>>, ApiError> {
    let (limit, offset) = PageQuery {
        limit: query.limit,
        offset: query.offset,
    }
    .resolve();

    let (start_ts, end_ts) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;

    let tenant_id = db.tenant_uuid();
    let rules = load_rules(db.conn(), tenant_id).await?;

    // Default-as-base scoping. `view=shared` → the Default profile's rules (the
    // shared base); `profile_id=P` → P's effective set. For a Layered P that is the
    // Default's rules (minus the ones P forked) ∪ P's own; for a Standalone/Default
    // P it is P's own rules only.
    let default_tool_id = super::profiles::default_profile_id(
        db.conn(),
        tenant_id,
        streamscope_core::config::ProfileKind::Tools,
    )
    .await?;
    let view_shared = query.view == Some(ToolRuleView::Shared);
    let queried_layered = match query.profile_id {
        Some(pid) if !view_shared => match super::profiles::profile_mode(db.conn(), pid).await? {
            Some((is_default, standalone)) => !is_default && !standalone,
            None => true,
        },
        _ => false,
    };
    let suppressed_in_profile: std::collections::HashSet<String> = match query.profile_id {
        Some(pid) if !view_shared && queried_layered => rules
            .iter()
            .filter(|r| r.profile_id == Some(pid))
            .filter_map(|r| r.forked_from.clone())
            .collect(),
        _ => std::collections::HashSet::new(),
    };

    let filtered: Vec<ToolRule> = rules
        .into_iter()
        .filter(|r| {
            if view_shared {
                if r.profile_id != default_tool_id {
                    return false;
                }
            } else if let Some(profile_id) = query.profile_id {
                let belongs = if queried_layered && r.profile_id == default_tool_id {
                    // inherited Default rule, unless P forked it
                    !suppressed_in_profile.contains(r.id.as_str())
                } else {
                    r.profile_id == Some(profile_id)
                };
                if !belongs {
                    return false;
                }
            }
            if let Some(risk) = &query.risk
                && &r.risk != risk
            {
                return false;
            }
            if query.action.is_some_and(|want| r.action.kind() != want)
                || query.phase.is_some_and(|want| r.phase != want)
                || query.scope.is_some_and(|want| r.scope != want)
                || query.source.is_some_and(|want| !want.admits(r.is_builtin))
            {
                return false;
            }
            if let Some(enabled) = query.enabled
                && r.enabled != enabled
            {
                return false;
            }
            if let Some(q) = &query.q {
                let needle = q.to_lowercase();
                let hit_title = r
                    .title
                    .as_deref()
                    .map(|t| t.to_lowercase().contains(&needle))
                    .unwrap_or(false);
                let hit_id = r.id.to_lowercase().contains(&needle);
                let hit_condition = r.conditions.iter().any(|c| {
                    let v_str = c.value.to_string().to_lowercase();
                    v_str.contains(&needle) || c.target.to_lowercase().contains(&needle)
                });
                if !(hit_title || hit_id || hit_condition) {
                    return false;
                }
            }
            true
        })
        .collect();

    let total = filtered.len() as i64;
    let start = offset.min(total) as usize;
    let end = (offset + limit).min(total) as usize;
    let page_rules: Vec<ToolRule> = filtered[start..end].to_vec();
    let has_more = (offset + page_rules.len() as i64) < total;

    // Compute per-rule activity over the requested window, narrowed to the same
    // workspace selection the dashboard filter applies (the session's workspace,
    // stamped at ingestion) — agent traffic is just an unselected workspace by
    // default.
    let workspace_ids = parse_workspace_ids(&query.workspace_ids);
    // Reuse the unified classification path. We classify against the FULL set
    // of rules so first-match-wins is honoured exactly the way the proxy sees
    // it; the per-page filter below restricts only what we EMIT.
    let activity_map = compute_rule_activity(
        db.conn(),
        tenant_id,
        (start_ts, end_ts),
        query.app_id.clone(),
        workspace_ids,
    )
    .await
    .map_err(|e| {
        tracing::error!("rule activity: {e}");
        ApiError::internal("failed to compute rule activity")
    })?;

    let items: Vec<ToolRuleListItem> = page_rules
        .into_iter()
        .map(|rule| {
            let activity = activity_map.get(&rule.id).cloned().unwrap_or_default();
            ToolRuleListItem { rule, activity }
        })
        .collect();

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
    path = "/api/v1/admin/tool-rules/{id}",
    tag = "Tool Rules",
    params(("id" = String, Path, description = "Rule id (stable code or UUID)")),
    responses(
        (status = 200, description = "Rule", body = ToolRule),
        (status = 404, description = "Rule not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_tool_rule(
    mut db: TenantConn,
    Path(id): Path<String>,
) -> Result<Json<ToolRule>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let rules = load_rules(db.conn(), tenant_id).await?;
    let rule = rules
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| {
            ApiError::not_found("rule not found", ApiErrorCode::ToolRiskRuleNotFound)
        })?;
    Ok(Json(rule))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tool-rules",
    tag = "Tool Rules",
    request_body = CreateToolRule,
    responses(
        (status = 201, description = "Rule created", body = ToolRule),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 409, description = "Rule id already exists", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_tool_rule(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(body): Json<CreateToolRule>,
) -> Result<(StatusCode, Json<ToolRule>), ApiError> {
    let tenant_id = db.tenant_uuid();

    let id = body.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if !is_valid_rule_id(&id) {
        return Err(ApiError::bad_request(format!(
            "rule id must be 1..={MAX_RULE_ID_LEN} chars of [A-Za-z0-9._-]"
        ))
        .code(ApiErrorCode::ToolRiskRuleIdInvalid));
    }

    // Fast-path validation reads — a visible duplicate id, profile existence, and
    // fork shape. The DB unique constraints (`(tenant_id, rule_id)` and the
    // once-per-profile fork partial index) are the race-proof authority now that
    // no advisory lock serializes these checks: a collision slipping past here is
    // mapped to the typed 409 from `insert_rule`'s 23505 / a null resurrect.
    let conn = db.conn();
    let existing = load_rules(conn, tenant_id).await?;
    if existing.iter().any(|r| r.id == id) {
        return Err(ApiError::conflict(format!("rule id '{id}' already exists"), ApiErrorCode::ToolRiskRuleIdCollision));
    }
    // The kind's Default profile is the shared base — a rule with no explicit
    // profile lands there (profile_id is NOT NULL; there is no shared baseline).
    let default_tool_id = super::profiles::default_profile_id(
        conn,
        tenant_id,
        streamscope_core::config::ProfileKind::Tools,
    )
    .await?;
    if let Some(pid) = body.profile_id {
        super::profiles::ensure_profile_exists(conn, pid, streamscope_core::config::ProfileKind::Tools).await?;
    }
    // A fork ("Customize here") is a Layered profile's override of a Default rule
    // (the shared base): it requires a profile, must reference an existing Default
    // rule, and is unique per (origin, profile).
    if let Some(origin) = &body.forked_from {
        let Some(pid) = body.profile_id else {
            return Err(ApiError::bad_request(
                "forked_from requires a profile_id (a fork is profile-specific)",
            )
            .code(ApiErrorCode::ValidationFailed));
        };
        let origin_is_default_rule = existing.iter().any(|r| {
            r.id == *origin && r.profile_id == default_tool_id
        });
        if !origin_is_default_rule {
            return Err(ApiError::bad_request(
                "forked_from must reference an existing Default-profile rule",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
        if existing
            .iter()
            .any(|r| r.profile_id == Some(pid) && r.forked_from.as_deref() == Some(origin.as_str()))
        {
            return Err(ApiError::conflict(
                "this Default rule is already customized in this profile",
                ApiErrorCode::ToolRiskRuleIdCollision,
            ));
        }
    }

    // Stamp the chosen profile, or default to the kind's Default profile (the
    // shared base) — there is no shared-baseline NULL scope.
    let rule = body.into_rule(id.clone(), default_tool_id);
    map_validate(tool_rules::validate(&rule))?;
    let seq = next_rule_seq(conn, tenant_id).await?;
    let created = insert_rule(conn, tenant_id, &rule, seq).await?.ok_or_else(|| {
        ApiError::conflict(format!("rule id '{id}' already exists"), ApiErrorCode::ToolRiskRuleIdCollision)
    })?;

    audit_sink.record(None::<&ToolRule>, Some(&created));
    Ok((StatusCode::CREATED, Json(created)))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/tool-rules/{id}",
    tag = "Tool Rules",
    params(("id" = String, Path, description = "Rule id")),
    request_body = UpdateToolRule,
    responses(
        (status = 200, description = "Rule updated", body = ToolRule),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 404, description = "Rule not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_tool_rule(
    mut db: TenantConn,
    Path(id): Path<String>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(body): Json<UpdateToolRule>,
) -> Result<Json<ToolRule>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin tool_rules tx: {e}");
        ApiError::internal("failed to begin tool risk rule update")
    })?;
    let mut rules = load_rules(&mut tx, tenant_id).await?;
    let pos = rules
        .iter()
        .position(|r| r.id == id)
        .ok_or_else(|| {
            ApiError::not_found("rule not found", ApiErrorCode::ToolRiskRuleNotFound)
        })?;

    // When reassigning the rule's profile, validate the target exists in-tenant.
    // A fork is bound to its profile (its `forked_from` suppresses a shared rule
    // there) — reparenting it would move that suppression and could duplicate a
    // fork in the target; reject it. Delete the fork and customize the other
    // profile instead.
    if let Some(pid) = body.profile_id {
        if rules[pos].forked_from.is_some() && rules[pos].profile_id != Some(pid) {
            return Err(ApiError::bad_request(
                "a customized (forked) rule can't be moved to another profile",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
        super::profiles::ensure_profile_exists(&mut tx, pid, streamscope_core::config::ProfileKind::Tools).await?;
    }

    let before_rule = rules[pos].clone();
    let rule = &mut rules[pos];
    let mut content_changed = false;

    if let Some(title) = body.title {
        if rule.title != title {
            content_changed = true;
        }
        rule.title = title;
    }
    if let Some(description) = body.description {
        if rule.description != description {
            content_changed = true;
        }
        rule.description = description;
    }
    if let Some(risk_val) = body.risk {
        if rule.risk != risk_val {
            content_changed = true;
        }
        rule.risk = risk_val;
    }
    if let Some(phase) = body.phase {
        if rule.phase != phase {
            content_changed = true;
        }
        rule.phase = phase;
    }
    if let Some(scope) = body.scope {
        if rule.scope != scope {
            content_changed = true;
        }
        rule.scope = scope;
    }
    if let Some(conditions) = body.conditions {
        content_changed = true;
        rule.conditions = conditions;
    }
    if let Some(action) = body.action {
        content_changed = true;
        rule.action = action;
    }
    if let Some(priority) = body.priority {
        if rule.priority != priority {
            content_changed = true;
        }
        rule.priority = priority;
    }
    if let Some(model_filter) = body.model_filter {
        // model_filter: Option<Option<String>> — outer Some means "field present
        // in payload", inner controls clear-vs-set semantics.
        if rule.model_filter != model_filter {
            content_changed = true;
        }
        rule.model_filter = model_filter;
    }
    if let Some(app_filter) = body.app_filter {
        if rule.app_filter != app_filter {
            content_changed = true;
        }
        rule.app_filter = app_filter;
    }
    if let Some(mcp_server_filter) = body.mcp_server_filter {
        if rule.mcp_server_filter != mcp_server_filter {
            content_changed = true;
        }
        rule.mcp_server_filter = mcp_server_filter;
    }
    if let Some(a2a_agent_filter) = body.a2a_agent_filter {
        if rule.a2a_agent_filter != a2a_agent_filter {
            content_changed = true;
        }
        rule.a2a_agent_filter = a2a_agent_filter;
    }
    if let Some(enabled) = body.enabled {
        // Toggling enabled alone does NOT promote a builtin to custom —
        // operators may want to disable a builtin without "owning" it.
        rule.enabled = enabled;
    }
    if let Some(framework_refs) = body.framework_refs {
        content_changed = true;
        rule.framework_refs = framework_refs;
    }
    if let Some(profile_id) = body.profile_id {
        if rule.profile_id != Some(profile_id) {
            content_changed = true;
        }
        rule.profile_id = Some(profile_id);
    }

    // Any content change flips `is_builtin` so seed-sync doesn't overwrite
    // the operator's edits on restart.
    if content_changed && rule.is_builtin {
        rule.is_builtin = false;
    }

    map_validate(tool_rules::validate(rule))?;
    let updated = rule.clone();

    // Single-row content write, then (if requested) a single-row seq reorder —
    // both inside one tx so a mid-sequence failure rolls back together.
    write_rule(&mut tx, tenant_id, &updated).await?;
    if let Some(new_pos) = body.position {
        reorder_rule(&mut tx, tenant_id, &id, new_pos).await?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("commit tool_rules tx: {e}");
        ApiError::internal("failed to commit tool risk rule update")
    })?;

    audit_sink.record(Some(&before_rule), Some(&updated));

    Ok(Json(updated))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/tool-rules/{id}",
    tag = "Tool Rules",
    params(("id" = String, Path, description = "Rule id")),
    responses(
        (status = 200, description = "Rule deleted", body = ActionResponse),
        (status = 404, description = "Rule not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_tool_rule(
    mut db: TenantConn,
    Path(id): Path<String>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let conn = db.conn();
    let removed = load_rules(conn, tenant_id)
        .await?
        .into_iter()
        .find(|r| r.id == id)
        .ok_or_else(|| {
            ApiError::not_found("rule not found", ApiErrorCode::ToolRiskRuleNotFound)
        })?;

    // A rule that came from the seed — edited or not — becomes a `suppressed`
    // row so seed-sync won't resurrect it on restart; a user rule is removed
    // outright. The row decides, in the one statement that acts on it — no
    // whole-collection rewrite, no tombstone side-list.
    let acted: i64 = sqlx::query_scalar(
        "WITH hidden AS ( \
           UPDATE tool_policy_rules SET suppressed = true, updated_at = now() \
           WHERE tenant_id = $1 AND rule_id = $2 AND NOT suppressed AND seeded \
           RETURNING 1), \
         removed AS ( \
           DELETE FROM tool_policy_rules \
           WHERE tenant_id = $1 AND rule_id = $2 AND NOT suppressed AND NOT seeded \
           RETURNING 1) \
         SELECT (SELECT count(*) FROM hidden) + (SELECT count(*) FROM removed)",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_one(conn)
    .await
    .map_err(|e| {
        tracing::error!("delete tool rule: {e}");
        ApiError::internal("failed to delete tool risk rule")
    })?;
    // A concurrent delete got there first.
    if acted == 0 {
        return Err(ApiError::not_found("rule not found", ApiErrorCode::ToolRiskRuleNotFound));
    }

    audit_sink.record(Some(&removed), None::<&ToolRule>);
    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tool-rules/actions/reset",
    tag = "Tool Rules",
    responses(
        (status = 200, description = "Builtins restored", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_tool_rules(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let loader = crate::seed_loader::SeedLoader::new();
    let seed_rules = loader.load_tool_rules();

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin tool_rules tx: {e}");
        ApiError::internal("failed to begin tool risk rule reset")
    })?;

    // Builtins live on the Default tool profile (the shared base) — stamp it.
    let default_tool_id = super::profiles::default_profile_id(
        &mut tx,
        tenant_id,
        streamscope_core::config::ProfileKind::Tools,
    )
    .await?
    .ok_or_else(|| {
        tracing::error!(%tenant_id, "reset tool rules: no default tool profile");
        ApiError::internal("failed to reset tool risk rules")
    })?;

    // Deleted rules the seed still ships — un-suppressed by the restore below;
    // count them for the impact summary.
    let seed_ids: Vec<&String> = crate::seed_loader::builtin_tool_rule_ids().iter().collect();
    let cleared_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tool_policy_rules WHERE tenant_id = $1 AND suppressed AND rule_id = ANY($2)",
    )
    .bind(tenant_id)
    .bind(&seed_ids)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("count suppressed builtins: {e}");
        ApiError::internal("failed to reset tool risk rules")
    })?;

    // Restore every builtin to pristine seed state — content, `enabled`, Default
    // profile scope (the shared base), `is_builtin`, and un-suppressed — forced
    // over any prior operator edit. This is the one path that reclaims a
    // user-edited builtin (unlike seed-sync, which leaves `is_builtin=false` rows alone).
    let mut restored_count = 0usize;
    let mut seq: i64 = 0;
    for seed in &seed_rules {
        let rule: ToolRule = match serde_json::from_value(seed.clone()) {
            Ok(r) => r,
            Err(e) => {
                tracing::warn!(
                    seed_id = ?seed.get("id").and_then(|v| v.as_str()),
                    error = %e,
                    "failed to deserialize builtin seed rule during reset — skipping"
                );
                continue;
            }
        };
        sqlx::query(
            "INSERT INTO tool_policy_rules \
               (tenant_id, rule_id, profile_id, seq, title, description, risk, phase, scope, \
                conditions, action, priority, model_filter, app_filter, mcp_server_filter, \
                a2a_agent_filter, enabled, framework_refs, forked_from, is_builtin, suppressed) \
             VALUES ($1,$2,$16,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$17,true,$15,NULL,true,false) \
             ON CONFLICT (tenant_id, rule_id) DO UPDATE SET \
                profile_id = $16, seq = EXCLUDED.seq, title = EXCLUDED.title, \
                description = EXCLUDED.description, risk = EXCLUDED.risk, phase = EXCLUDED.phase, \
                scope = EXCLUDED.scope, conditions = EXCLUDED.conditions, action = EXCLUDED.action, \
                priority = EXCLUDED.priority, model_filter = EXCLUDED.model_filter, \
                app_filter = EXCLUDED.app_filter, mcp_server_filter = EXCLUDED.mcp_server_filter, \
                a2a_agent_filter = EXCLUDED.a2a_agent_filter, \
                enabled = true, framework_refs = EXCLUDED.framework_refs, forked_from = NULL, \
                is_builtin = true, suppressed = false, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(&rule.id)
        .bind(seq)
        .bind(rule.title.as_deref())
        .bind(rule.description.as_deref())
        .bind(&rule.risk)
        .bind(enum_str(&rule.phase))
        .bind(enum_str(&rule.scope))
        .bind(serde_json::to_value(&rule.conditions).unwrap_or_else(|_| serde_json::json!([])))
        .bind(serde_json::to_value(&rule.action).unwrap_or_default())
        .bind(rule.priority)
        .bind(rule.model_filter.as_deref())
        .bind(rule.app_filter.as_deref())
        .bind(rule.mcp_server_filter.as_deref())
        .bind(&rule.framework_refs)
        .bind(default_tool_id)
        .bind(rule.a2a_agent_filter.as_deref())
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("restore builtin tool rule '{}': {e}", rule.id);
            ApiError::internal("failed to reset tool risk rules")
        })?;
        seq += SEQ_STEP;
        restored_count += 1;
    }

    // Keep restored builtins ordered strictly before user rules (first-match-wins
    // is load-bearing — a reset must not let a user rule reordered to a low `seq`
    // interleave ahead of a builtin). Push every user rule's `seq` above the
    // highest builtin `seq` (`seq` here is one step past the last builtin),
    // preserving their relative order.
    sqlx::query(
        "UPDATE tool_policy_rules SET seq = seq + $2 WHERE tenant_id = $1 AND NOT is_builtin",
    )
    .bind(tenant_id)
    .bind(seq)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("reorder user tool rules on reset: {e}");
        ApiError::internal("failed to reset tool risk rules")
    })?;

    // User rules (is_builtin = false) keep their content; count them for the impact.
    let preserved_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tool_policy_rules WHERE tenant_id = $1 AND NOT is_builtin AND NOT suppressed",
    )
    .bind(tenant_id)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("count preserved tool rules: {e}");
        ApiError::internal("failed to reset tool risk rules")
    })?;
    let preserved_count = preserved_count as usize;
    let cleared_count = cleared_count as usize;

    tx.commit().await.map_err(|e| {
        tracing::error!("commit tool_rules tx: {e}");
        ApiError::internal("failed to commit tool risk rule reset")
    })?;

    let impact = ResetImpact {
        builtins_restored: restored_count,
        custom_preserved: preserved_count,
        deleted_builtins_cleared: cleared_count,
    };
    // Bulk reset — record a summary rather than a per-rule diff.
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({
            "action": "reset_to_builtins",
            "builtins_restored": restored_count,
            "custom_preserved": preserved_count,
            "deleted_builtins_cleared": cleared_count,
        }),
    );
    Ok(Json(
        ActionResponse::ok()
            .with_message(format!(
                "restored {restored_count} builtins, preserved {preserved_count} custom"
            ))
            .with_impact(impact),
    ))
}

#[derive(Debug, Serialize, ToSchema)]
pub struct SecurityFrameworksResponse {
    pub frameworks: Vec<crate::seed_loader::SecurityFramework>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/security-frameworks",
    tag = "Tool Rules",
    responses(
        (status = 200, description = "Security framework knowledge pack", body = SecurityFrameworksResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_security_frameworks(
    _db: TenantConn,
) -> Result<Json<SecurityFrameworksResponse>, ApiError> {
    Ok(Json(SecurityFrameworksResponse {
        frameworks: crate::seed_loader::load_security_frameworks().to_vec(),
    }))
}

/// One entry of the detector registry, as the rule editor renders it.
#[derive(Debug, Serialize, ToSchema)]
pub struct ToolRuleDetector {
    /// Wire value for a condition's `value` when `op` is `detector`.
    pub name: String,
    /// Operator-facing name for the option list.
    pub label: String,
    /// One line describing what the detector recognises.
    pub summary: String,
}

#[derive(Debug, Serialize, ToSchema)]
pub struct ToolRuleDetectorsResponse {
    pub detectors: Vec<ToolRuleDetector>,
}

/// The closed set of detectors this build implements — the options the rule
/// editor offers for a `detector` condition. Server-owned, so a detector added
/// to the engine reaches the editor with no frontend change.
#[utoipa::path(
    get,
    path = "/api/v1/admin/tool-rule-detectors",
    tag = "Tool Rules",
    responses(
        (status = 200, description = "Detector registry", body = ToolRuleDetectorsResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_tool_rule_detectors(
    _db: TenantConn,
) -> Result<Json<ToolRuleDetectorsResponse>, ApiError> {
    Ok(Json(ToolRuleDetectorsResponse {
        detectors: streamscope_core::config::tool_rules_detectors::DETECTORS
            .iter()
            .map(|d| ToolRuleDetector {
                name: d.name.to_string(),
                label: d.label.to_string(),
                summary: d.summary.to_string(),
            })
            .collect(),
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/tool-rules/actions/test",
    tag = "Tool Rules",
    request_body = TestToolRule,
    responses(
        (status = 200, description = "Match results", body = TestToolRuleResponse),
        (status = 400, description = "Invalid pattern or regex", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn test_tool_rule(
    mut db: TenantConn,
    Json(body): Json<TestToolRule>,
) -> Result<Json<TestToolRuleResponse>, ApiError> {
    let draft_id = body.rule.id.clone().unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let rule = body.rule.into_rule(draft_id, None);
    map_validate(tool_rules::validate(&rule))?;
    let model = body.sample_model.as_deref();
    let sample_args = body.sample_args.as_ref();
    // Load the tenant's field profile registry so `any_arg` and
    // `arg.<field>` previews resolve through the same canonical-field path
    // they would in production. Without this the sandbox can't show any
    // matches for cross-field rules.
    let field_profiles =
        crate::routes::analytics::load_field_profiles(&mut *db.conn()).await;

    let mut matches = Vec::with_capacity(body.sample_tool_names.len());
    for name in &body.sample_tool_names {
        // The sandbox uses the wire-name as a direct stand-in for `tool_id`
        // so operators can test rules against named samples without having
        // to declare a profile first. Real evaluation always resolves
        // tool_id from the field-profile registry.
        let (effective_name, mcp_server) = match tool_rules::parse_mcp_namespace(name) {
            Some((srv, local)) => (local.to_string(), Some(srv.to_string())),
            None => (name.clone(), None),
        };
        let synthetic_tool_id = effective_name.clone();
        let hit = match (rule.phase, rule.scope) {
            (Phase::Response, Scope::ToolCalls) => {
                let resolver = tool_rules::ToolCallResolver {
                    name: &effective_name,
                    arguments: sample_args,
                    field_profiles: Some(&field_profiles),
                    app_id: None,
                    mcp_server: mcp_server.as_deref(),
                    tool_id: Some(&synthetic_tool_id),
                };
                // A shell call that only applies a patch also meets a block
                // rule on the patch tool, as it does in enforcement.
                tool_rules::evaluate(&rule, &resolver)
                    || tool_rules::patch_block(&[&rule], &resolver).is_some()
            }
            (Phase::Request, Scope::ToolDefinitions) => {
                let resolver = tool_rules::ToolDefinitionResolver {
                    tool_id: Some(&synthetic_tool_id),
                };
                tool_rules::evaluate(&rule, &resolver)
            }
            (Phase::Request, Scope::ToolResults) => {
                let resolver = tool_rules::ToolResultResolver {
                    name: &effective_name,
                    arguments: sample_args,
                    content: body.sample_content.as_deref().unwrap_or(""),
                    field_profiles: Some(&field_profiles),
                    app_id: None,
                    mcp_server: mcp_server.as_deref(),
                    tool_id: Some(&synthetic_tool_id),
                };
                tool_rules::evaluate(&rule, &resolver)
            }
            // Other (phase, scope) combos are rejected by validate() above —
            // any survivor here is a future-shape we haven't taught the
            // sandbox about yet. Default to no match.
            _ => false,
        };
        // Honour model_filter — extract_for would otherwise filter the rule
        // out at scope-extraction time; the sandbox runs the rule directly
        // so we replicate the check here.
        let model_ok = match (&rule.model_filter, model) {
            (None, _) => true,
            (Some(_), None) => false,
            (Some(filter), Some(m)) => tool_rules::matches_glob(m, filter),
        };
        let matched = hit && model_ok;
        let reason = if matched {
            "all conditions matched".to_string()
        } else if !model_ok {
            "model_filter excluded the sample".to_string()
        } else {
            "one or more conditions did not match".to_string()
        };
        matches.push(TestMatch {
            tool_name: name.clone(),
            matched,
            reason,
        });
    }

    Ok(Json(TestToolRuleResponse { matches }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Map a `tool_rules::ValidationError` into a typed `ApiError` so the admin UI can
/// branch on `error.code` instead of parsing the message.
fn map_validate(result: Result<(), ValidationError>) -> Result<(), ApiError> {
    match result {
        Ok(()) => Ok(()),
        Err(ValidationError::ScopeForbidsAction { phase, scope, action }) => {
            Err(ApiError::bad_request(format!(
                "action {action:?} is not permitted on (phase={phase:?}, scope={scope:?})"
            ))
            .code(ApiErrorCode::ToolRiskRuleScopeInvalid))
        }
        Err(ValidationError::InvalidTarget { target, scope }) => {
            Err(ApiError::bad_request(format!(
                "target {target:?} is not permitted on scope {scope:?}"
            ))
            .code(ApiErrorCode::ToolRiskRuleTargetInvalid))
        }
        Err(ValidationError::InvalidRegex { which, error }) => Err(ApiError::bad_request(
            format!("invalid regex at {which}: {error}"),
        )
        .code(ApiErrorCode::ToolRiskRuleRegexInvalid)),
        Err(ValidationError::InvalidRiskLevel { value }) => {
            Err(ApiError::bad_request(format!(
                "risk must be one of safe|caution|danger|unknown, got {value:?}"
            ))
            .code(ApiErrorCode::ToolRiskRuleRiskInvalid))
        }
        Err(ValidationError::InvalidArrayValue) => Err(ApiError::bad_request(
            "contains_any/in value must be a non-empty array of strings",
        )
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::InvalidScalarValue { target, op }) => Err(ApiError::bad_request(
            format!("condition target={target:?} op={op:?} requires a non-empty string value"),
        )
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::InvalidOpForTarget { target, op }) => Err(ApiError::bad_request(
            format!(
                "op {op:?} is not valid on target {target:?} — `equals`/`in` are reserved for `tool_id`, \
                 `glob`/`contains_any`/`regex` are forbidden on `tool_id`"
            ),
        )
        .code(ApiErrorCode::ToolRiskRuleTargetInvalid)),
        Err(ValidationError::InvalidModelFilter) => Err(ApiError::bad_request(
            "model_filter must be a non-empty glob or null — empty string would suppress every match",
        )
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::InvalidAppFilter) => Err(ApiError::bad_request(
            "app_filter must be a non-empty glob or null — empty string would suppress every match",
        )
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::InvalidMcpServerFilter) => Err(ApiError::bad_request(
            "mcp_server_filter must be a non-empty glob or null — empty string would suppress every match",
        )
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::InvalidA2aAgentFilter) => Err(ApiError::bad_request(
            "a2a_agent_filter must be a non-empty glob or null — empty string would suppress every match",
        )
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::NeedleCarriesFormSeparator { target }) => {
            Err(ApiError::bad_request(format!(
                "condition target={target:?} has a match value containing a NUL character — \
                 no canonicalised value can contain one, so the rule could never match"
            ))
            .code(ApiErrorCode::ValidationFailed))
        }
        Err(ValidationError::UnknownDetector { name }) => Err(ApiError::bad_request(format!(
            "no detector named {name:?} — pick one of: {}",
            streamscope_core::config::tool_rules_detectors::detector_names().join(", ")
        ))
        .code(ApiErrorCode::ValidationFailed)),
        Err(ValidationError::AmbiguousReplaceAction) => Err(ApiError::bad_request(
            "Replace action must specify at least one of `regex`, `with`, or `drop: true` — \
             omitting all three is almost always unintentional",
        )
        .code(ApiErrorCode::ToolRiskRuleActionInvalid)),
    }
}

/// One stored tool-policy rule, as read from `tool_policy_rules`. `phase`/`scope`
/// are their snake_case serde strings; `conditions`/`action` are JSONB;
/// `framework_refs` is a `TEXT[]`; the rest are scalar columns.
#[derive(sqlx::FromRow)]
struct RuleRow {
    rule_id: String,
    profile_id: Option<uuid::Uuid>,
    title: Option<String>,
    description: Option<String>,
    risk: String,
    phase: String,
    scope: String,
    conditions: serde_json::Value,
    action: serde_json::Value,
    priority: i32,
    model_filter: Option<String>,
    app_filter: Option<String>,
    mcp_server_filter: Option<String>,
    a2a_agent_filter: Option<String>,
    enabled: bool,
    framework_refs: Vec<String>,
    forked_from: Option<String>,
    is_builtin: bool,
}

impl RuleRow {
    /// Reconstruct the wire [`ToolRule`]. A row whose `phase`/`scope`/`action`/
    /// `conditions` fails to parse is dropped by the caller — a single malformed
    /// row can't take the whole policy surface offline (mirrors the old
    /// per-entry blob decode).
    fn into_rule(self) -> Result<ToolRule, serde_json::Error> {
        Ok(ToolRule {
            id: self.rule_id,
            title: self.title,
            description: self.description,
            risk: self.risk,
            phase: serde_json::from_value(serde_json::Value::String(self.phase))?,
            scope: serde_json::from_value(serde_json::Value::String(self.scope))?,
            conditions: serde_json::from_value(self.conditions)?,
            action: serde_json::from_value(self.action)?,
            priority: self.priority,
            model_filter: self.model_filter,
            app_filter: self.app_filter,
            mcp_server_filter: self.mcp_server_filter,
            a2a_agent_filter: self.a2a_agent_filter,
            enabled: self.enabled,
            framework_refs: self.framework_refs,
            is_builtin: self.is_builtin,
            profile_id: self.profile_id,
            forked_from: self.forked_from,
        })
    }
}

/// A [`RuleRow`] plus its stored `seq`, for the reorder path.
#[derive(sqlx::FromRow)]
struct RuleSeqRow {
    seq: i64,
    #[sqlx(flatten)]
    rule: RuleRow,
}

/// Column list shared by every `tool_policy_rules` read (kept in sync with
/// [`RuleRow`]).
const RULE_COLUMNS: &str = "rule_id, profile_id, title, description, risk, phase, scope, \
    conditions, action, priority, model_filter, app_filter, mcp_server_filter, \
    a2a_agent_filter, enabled, framework_refs, forked_from, is_builtin";

/// Gap between adjacent `seq` values so a reorder usually lands at the midpoint
/// of two neighbours with a single-row update (no renumber). Seed-sync spaces
/// builtins by this step too (`seed_scripts`).
pub(crate) const SEQ_STEP: i64 = 1024;

/// Serialize a [`Phase`]/[`Scope`]/enum to its snake_case wire string for a TEXT
/// column.
fn enum_str<T: Serialize>(v: &T) -> String {
    serde_json::to_value(v)
        .ok()
        .and_then(|x| x.as_str().map(str::to_string))
        .unwrap_or_default()
}

/// Load this tenant's visible (non-suppressed) tool-policy rules in evaluation
/// order (`seq`, then `id` as a deterministic tiebreaker). Rows that fail to
/// decode are logged and skipped.
pub(crate) async fn load_rules(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<Vec<ToolRule>, ApiError> {
    let sql = format!(
        "SELECT {RULE_COLUMNS} FROM tool_policy_rules \
         WHERE tenant_id = $1 AND NOT suppressed ORDER BY seq, id"
    );
    let rows = sqlx::query_as::<_, RuleRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .fetch_all(conn)
        .await
        .map_err(|e| {
            tracing::error!("load tool_rules: {e}");
            ApiError::internal("failed to load tool risk rules")
        })?;

    Ok(rows
        .into_iter()
        .filter_map(|row| {
            let id = row.rule_id.clone();
            row.into_rule()
                .map_err(|e| {
                    tracing::warn!(rule_id = %id, error = %e, "dropping malformed tool risk rule");
                })
                .ok()
        })
        .collect())
}

/// Read this tenant's visible (non-suppressed) rules via an **RLS-scoped**
/// executor — the connection's `app.tenant_id` GUC confines the read, so no
/// explicit tenant bind (the classifier/inventory readers already hold such a
/// handle). Keep the column list in sync with [`RULE_COLUMNS`] / [`RuleRow`].
pub(crate) async fn load_rules_rls(executor: &mut Scoped) -> Result<Vec<ToolRule>, sqlx::Error> {
    let rows = sqlx::query_as::<_, RuleRow>(
        "SELECT rule_id, profile_id, title, description, risk, phase, scope, conditions, action, \
                priority, model_filter, app_filter, mcp_server_filter, a2a_agent_filter, enabled, \
                framework_refs, forked_from, is_builtin \
         FROM tool_policy_rules WHERE NOT suppressed ORDER BY seq, id",
    )
    .fetch_all(executor)
    .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let id = r.rule_id.clone();
            r.into_rule()
                .inspect_err(|e| tracing::warn!(rule_id = %id, error = %e, "dropping malformed tool risk rule"))
                .ok()
        })
        .collect())
}

/// Next append `seq` for a new rule (highest existing + one gap step). A fresh
/// tenant starts at 0.
async fn next_rule_seq(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<i64, ApiError> {
    let max: Option<i64> =
        sqlx::query_scalar("SELECT MAX(seq)::bigint FROM tool_policy_rules WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(conn)
            .await
            .map_err(|e| {
                tracing::error!("next tool rule seq: {e}");
                ApiError::internal("failed to allocate tool rule order")
            })?;
    Ok(max.map(|m| m + SEQ_STEP).unwrap_or(0))
}

/// Insert a new rule. Returns the inserted row's effective `ToolRule`. A
/// `rule_id` that collides with a **suppressed** row resurrects it as the new
/// (user) rule; a collision with a *live* row yields `None` (the caller maps it
/// to a typed 409 — the pre-`SELECT` check is no longer authoritative without a
/// lock). `is_builtin` is forced false for any create/resurrect.
async fn insert_rule(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    rule: &ToolRule,
    seq: i64,
) -> Result<Option<ToolRule>, ApiError> {
    let sql = format!(
        "INSERT INTO tool_policy_rules \
           (tenant_id, rule_id, profile_id, seq, title, description, risk, phase, scope, \
            conditions, action, priority, model_filter, app_filter, mcp_server_filter, \
            a2a_agent_filter, enabled, framework_refs, forked_from, is_builtin, suppressed) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$19,$16,$17,$18,false,false) \
         ON CONFLICT (tenant_id, rule_id) DO UPDATE SET \
            profile_id = EXCLUDED.profile_id, seq = EXCLUDED.seq, title = EXCLUDED.title, \
            description = EXCLUDED.description, risk = EXCLUDED.risk, phase = EXCLUDED.phase, \
            scope = EXCLUDED.scope, conditions = EXCLUDED.conditions, action = EXCLUDED.action, \
            priority = EXCLUDED.priority, model_filter = EXCLUDED.model_filter, \
            app_filter = EXCLUDED.app_filter, mcp_server_filter = EXCLUDED.mcp_server_filter, \
            a2a_agent_filter = EXCLUDED.a2a_agent_filter, \
            enabled = EXCLUDED.enabled, framework_refs = EXCLUDED.framework_refs, \
            forked_from = EXCLUDED.forked_from, is_builtin = false, suppressed = false, \
            updated_at = now() \
         WHERE tool_policy_rules.suppressed \
         RETURNING {RULE_COLUMNS}"
    );
    let row = sqlx::query_as::<_, RuleRow>(sqlx::AssertSqlSafe(&*sql))
    .bind(tenant_id)
    .bind(&rule.id)
    .bind(rule.profile_id)
    .bind(seq)
    .bind(rule.title.as_deref())
    .bind(rule.description.as_deref())
    .bind(&rule.risk)
    .bind(enum_str(&rule.phase))
    .bind(enum_str(&rule.scope))
    .bind(serde_json::to_value(&rule.conditions).unwrap_or_else(|_| serde_json::json!([])))
    .bind(serde_json::to_value(&rule.action).unwrap_or_default())
    .bind(rule.priority)
    .bind(rule.model_filter.as_deref())
    .bind(rule.app_filter.as_deref())
    .bind(rule.mcp_server_filter.as_deref())
    .bind(rule.enabled)
    .bind(&rule.framework_refs)
    .bind(rule.forked_from.as_deref())
    .bind(rule.a2a_agent_filter.as_deref())
    .fetch_optional(conn)
    .await
    .map_err(|e| {
        // The (tenant_id, rule_id) conflict is absorbed by ON CONFLICT; a 23505
        // here is the once-per-profile fork partial-unique index racing past the
        // Rust pre-check (no lock) — surface it as the typed 409.
        if is_unique_violation(&e) {
            ApiError::conflict("this shared rule is already customized in this profile", ApiErrorCode::ToolRiskRuleIdCollision)
        } else {
            tracing::error!("insert tool rule: {e}");
            ApiError::internal("failed to create tool risk rule")
        }
    })?;
    row.map(RuleRow::into_rule)
        .transpose()
        .map_err(|e| {
            tracing::error!("decode inserted tool rule: {e}");
            ApiError::internal("failed to create tool risk rule")
        })
}

/// The builtin upsert for `tool_policy_rules`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const TOOL_RULE_UPSERT: &str = "INSERT INTO tool_policy_rules \
           (tenant_id, rule_id, profile_id, seq, title, description, risk, phase, scope, \
            conditions, action, priority, model_filter, app_filter, mcp_server_filter, \
            a2a_agent_filter, enabled, framework_refs, forked_from, is_builtin, suppressed) \
         VALUES ($1,$2,$17,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$18,$15,$16,NULL,true,false) \
         ON CONFLICT (tenant_id, rule_id) DO UPDATE SET \
            title = EXCLUDED.title, description = EXCLUDED.description, risk = EXCLUDED.risk, \
            phase = EXCLUDED.phase, scope = EXCLUDED.scope, conditions = EXCLUDED.conditions, \
            action = EXCLUDED.action, priority = EXCLUDED.priority, \
            model_filter = EXCLUDED.model_filter, app_filter = EXCLUDED.app_filter, \
            mcp_server_filter = EXCLUDED.mcp_server_filter, \
            a2a_agent_filter = EXCLUDED.a2a_agent_filter, framework_refs = EXCLUDED.framework_refs, \
            updated_at = now() \
         WHERE tool_policy_rules.is_builtin AND NOT tool_policy_rules.suppressed \
           AND (tool_policy_rules.title, tool_policy_rules.description, tool_policy_rules.risk, tool_policy_rules.phase, tool_policy_rules.scope, tool_policy_rules.conditions, tool_policy_rules.action, tool_policy_rules.priority, tool_policy_rules.model_filter, tool_policy_rules.app_filter, tool_policy_rules.mcp_server_filter, tool_policy_rules.a2a_agent_filter, tool_policy_rules.framework_refs) \
               IS DISTINCT FROM (EXCLUDED.title, EXCLUDED.description, EXCLUDED.risk, EXCLUDED.phase, EXCLUDED.scope, EXCLUDED.conditions, EXCLUDED.action, EXCLUDED.priority, EXCLUDED.model_filter, EXCLUDED.app_filter, EXCLUDED.mcp_server_filter, EXCLUDED.a2a_agent_filter, EXCLUDED.framework_refs)";

/// Seed-sync UPSERT for one builtin rule: insert it on the **Default tool
/// profile** (`default_profile_id` — the shared base; `profile_id` is NOT NULL),
/// `is_builtin`, `enabled`/`seq` per seed, or refresh an existing **pristine**
/// builtin's content. The `WHERE is_builtin AND NOT suppressed` guard makes it a
/// no-op on a user-edited (`is_builtin=false`) or user-deleted (`suppressed`)
/// row — so re-sync never overwrites an edit nor resurrects a deleted builtin.
/// `enabled`, `seq`, and `profile_id` are preserved on refresh (operator-owned:
/// a builtin a user moved to another profile stays there). Errors propagate to
/// the seed caller (no ApiError in the seed path).
pub(crate) async fn upsert_builtin_rule(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    rule: &ToolRule,
    seq: i64,
    default_profile_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(TOOL_RULE_UPSERT)
    .bind(tenant_id)
    .bind(&rule.id)
    .bind(seq)
    .bind(rule.title.as_deref())
    .bind(rule.description.as_deref())
    .bind(&rule.risk)
    .bind(enum_str(&rule.phase))
    .bind(enum_str(&rule.scope))
    .bind(serde_json::to_value(&rule.conditions).unwrap_or_else(|_| serde_json::json!([])))
    .bind(serde_json::to_value(&rule.action).unwrap_or_default())
    .bind(rule.priority)
    .bind(rule.model_filter.as_deref())
    .bind(rule.app_filter.as_deref())
    .bind(rule.mcp_server_filter.as_deref())
    .bind(rule.enabled)
    .bind(&rule.framework_refs)
    .bind(default_profile_id)
    .bind(rule.a2a_agent_filter.as_deref())
    .execute(conn)
    .await?;
    Ok(())
}

/// Replace a profile's own tool rules with a fresh copy of the builtin seed set
/// (the "seed" content adapter — used by reset-to-seed and create-from-seed).
/// `as_default = true` keeps the original `rule_id`s and `is_builtin = true` (the
/// pristine shared base, for resetting the Default profile); `false` mints fresh
/// `rule_id`s and `is_builtin = false` (independent copies, for a Standalone
/// profile — the `(tenant_id, rule_id)` uniqueness forbids reusing the Default's
/// ids). Returns the number of rules written.
pub(crate) async fn seed_rules_onto_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    profile_id: uuid::Uuid,
    as_default: bool,
) -> Result<i64, ApiError> {
    let loader = crate::seed_loader::SeedLoader::new();
    let seeds = loader.load_tool_rules();
    sqlx::query("DELETE FROM tool_policy_rules WHERE tenant_id = $1 AND profile_id = $2")
        .bind(tenant_id)
        .bind(profile_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("clear rules for seed: {e}");
            ApiError::internal("failed to seed tool rules")
        })?;
    let mut seq: i64 = 0;
    let mut count = 0i64;
    for seed in &seeds {
        let rule: ToolRule = match serde_json::from_value(seed.clone()) {
            Ok(r) => r,
            Err(_) => continue,
        };
        let rule_id = if as_default {
            rule.id.clone()
        } else {
            uuid::Uuid::new_v4().to_string()
        };
        sqlx::query(
            "INSERT INTO tool_policy_rules \
               (tenant_id, rule_id, profile_id, seq, title, description, risk, phase, scope, \
                conditions, action, priority, model_filter, app_filter, mcp_server_filter, \
                a2a_agent_filter, enabled, framework_refs, forked_from, is_builtin, suppressed) \
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$19,$16,$17,NULL,$18,false)",
        )
        .bind(tenant_id)
        .bind(&rule_id)
        .bind(profile_id)
        .bind(seq)
        .bind(rule.title.as_deref())
        .bind(rule.description.as_deref())
        .bind(&rule.risk)
        .bind(enum_str(&rule.phase))
        .bind(enum_str(&rule.scope))
        .bind(serde_json::to_value(&rule.conditions).unwrap_or_else(|_| serde_json::json!([])))
        .bind(serde_json::to_value(&rule.action).unwrap_or_default())
        .bind(rule.priority)
        .bind(rule.model_filter.as_deref())
        .bind(rule.app_filter.as_deref())
        .bind(rule.mcp_server_filter.as_deref())
        .bind(rule.enabled)
        .bind(&rule.framework_refs)
        .bind(as_default)
        .bind(rule.a2a_agent_filter.as_deref())
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("seed rule onto profile: {e}");
            ApiError::internal("failed to seed tool rules")
        })?;
        seq += SEQ_STEP;
        count += 1;
    }
    Ok(count)
}

/// Allocate an append `seq` and insert a new rule. Used by the agent
/// suggestion-applier (`transforms::approve_tool_rule_suggestion`); returns
/// `None` on a live `rule_id` collision (mirrors create's 409).
pub(crate) async fn add_rule(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    rule: &ToolRule,
) -> Result<Option<ToolRule>, ApiError> {
    let seq = next_rule_seq(conn, tenant_id).await?;
    insert_rule(conn, tenant_id, rule, seq).await
}

/// Overwrite a live rule's content in place (single-row update, addressed by
/// `rule_id`). `is_builtin`/`suppressed`/`seq` are managed separately and not
/// touched here.
async fn write_rule(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    rule: &ToolRule,
) -> Result<(), ApiError> {
    sqlx::query(
        "UPDATE tool_policy_rules SET \
            profile_id = $3, title = $4, description = $5, risk = $6, phase = $7, scope = $8, \
            conditions = $9, action = $10, priority = $11, model_filter = $12, app_filter = $13, \
            mcp_server_filter = $14, a2a_agent_filter = $18, enabled = $15, \
            framework_refs = $16, is_builtin = $17, updated_at = now() \
         WHERE tenant_id = $1 AND rule_id = $2",
    )
    .bind(tenant_id)
    .bind(&rule.id)
    .bind(rule.profile_id)
    .bind(rule.title.as_deref())
    .bind(rule.description.as_deref())
    .bind(&rule.risk)
    .bind(enum_str(&rule.phase))
    .bind(enum_str(&rule.scope))
    .bind(serde_json::to_value(&rule.conditions).unwrap_or_else(|_| serde_json::json!([])))
    .bind(serde_json::to_value(&rule.action).unwrap_or_default())
    .bind(rule.priority)
    .bind(rule.model_filter.as_deref())
    .bind(rule.app_filter.as_deref())
    .bind(rule.mcp_server_filter.as_deref())
    .bind(rule.enabled)
    .bind(&rule.framework_refs)
    .bind(rule.is_builtin)
    .bind(rule.a2a_agent_filter.as_deref())
    .execute(conn)
    .await
    .map_err(|e| {
        tracing::error!("update tool rule: {e}");
        ApiError::internal("failed to update tool risk rule")
    })?;
    Ok(())
}

/// Compute per-rule activity over a time window. Returns a map keyed by
/// `Rule.id`.
///
/// Activity is the union of three sources, each carrying the authoritative
/// `rule_id` written by the proxy at the time the rule fired:
///
/// 1. **Classify** rules — re-run `classify_tool_call` against
///    `response_tool_calls` so unblocked-but-classified calls are credited
///    to their rule (the proxy doesn't persist a per-classify diff).
/// 2. **Block** rules — read `transform_diff.blocked_tools[]` (request-phase)
///    and `transform_diff.response_blocked_tools[]` (response-phase). Blocked
///    response calls are stripped from `response_tool_calls`, so without this
///    source a block-only rule reads "no activity" while the inventory
///    dashboard's `summary.blocked_count` proudly counts the same calls.
/// 3. **Replace** rules on tool_results — read
///    `transform_diff.redacted_tool_results[]`. Same shape: `rule_id` is on
///    each entry, no re-classification needed.
///
/// One classification stream feeds the inventory dashboard; the proxy's
/// authoritative diffs feed block/replace numbers — together they reconcile
/// with `summary.{blocked_count, redacted_count}` by construction.
async fn compute_rule_activity(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    time: (DateTime<Utc>, DateTime<Utc>),
    app_id: Option<String>,
    workspace_ids: Option<Vec<uuid::Uuid>>,
) -> anyhow::Result<std::collections::HashMap<String, RuleActivity>> {
    let activity = crate::audit_store::tool_activity::rule_activity_rows(
        conn,
        tenant_id,
        time,
        app_id.as_deref(),
        workspace_ids.as_deref(),
    )
    .await?;

    struct Bucket {
        call_count: i64,
        tools: std::collections::HashSet<String>,
        last_seen: Option<DateTime<Utc>>,
    }
    let mut buckets: std::collections::HashMap<String, Bucket> = std::collections::HashMap::new();
    let bump = |buckets: &mut std::collections::HashMap<String, Bucket>,
                rule_id: String,
                tool_name: Option<String>,
                ts: chrono::DateTime<chrono::Utc>| {
        let bucket = buckets.entry(rule_id).or_insert_with(|| Bucket {
            call_count: 0,
            tools: std::collections::HashSet::new(),
            last_seen: None,
        });
        bucket.call_count += 1;
        if let Some(name) = tool_name
            && !name.is_empty()
        {
            bucket.tools.insert(name);
        }
        bucket.last_seen = Some(match bucket.last_seen {
            Some(prev) if prev >= ts => prev,
            _ => ts,
        });
    };

    // ── Source 1: classify rules via the same path the inventory uses ────
    let risk_rules = crate::routes::analytics::load_risk_rules(&mut *conn).await;
    let field_profiles = crate::routes::analytics::load_field_profiles(&mut *conn).await;

    for row in &activity.turns {
        let Some(proto) = crate::conversation::stored_protocol(&row.api_version, row.request_id) else {
            continue;
        };
        let blocks = streamscope_core::api::domain_request::domain_assistant_content_from_stored(
            proto,
            None,
            row.response_tool_calls.as_ref(),
            None,
        );
        for block in blocks {
            let streamscope_core::api::domain_request::DomainContentBlock::ToolUse {
                name,
                input,
                input_raw,
                ..
            } = block
            else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let arguments = if input.is_null() {
                match input_raw {
                    Some(s) => serde_json::Value::String(s),
                    None => serde_json::Value::Object(serde_json::Map::new()),
                }
            } else {
                input
            };

            let result = tool_rules::classify_tool_call(
                &risk_rules,
                None,
                row.app_id.as_deref(),
                Some(&field_profiles),
                &name,
                Some(&arguments),
            );
            // Synthetic "unknown" fallbacks have no rule id.
            let Some(rule_id) = result.id else { continue };
            bump(&mut buckets, rule_id, Some(name.clone()), row.timestamp);
        }
    }

    // ── Source 2: block actions — read transform_diff arrays directly ────
    // Bucketed by the `rule_id` every blocked entry persists.
    for row in activity.blocked {
        let Some(rule_id) = row.rule_id else { continue };
        bump(&mut buckets, rule_id, row.tool_name, row.timestamp);
    }

    // ── Source 3: replace actions on tool_results ───────────────────────
    for row in activity.redacted {
        let Some(rule_id) = row.rule_id else { continue };
        bump(&mut buckets, rule_id, row.tool_name, row.timestamp);
    }

    Ok(buckets
        .into_iter()
        .map(|(id, b)| {
            (
                id,
                RuleActivity {
                    call_count_window: b.call_count,
                    tool_count_window: b.tools.len() as i64,
                    last_seen: b.last_seen,
                },
            )
        })
        .collect())
}

/// Reassign a rule's `seq` to reorder it to a target rank within its context
/// (shared rules order among shared; a profile rule orders among that profile's
/// effective set — shared-not-forked-here ∪ the profile's rules). `ordered` is
/// the tenant's current rules in `seq` order (as returned by [`load_rules`]),
/// paired with each rule's stored `seq`. A single-row UPDATE of the moved rule's
/// `seq` to the midpoint of its new neighbours keeps reorders contention-free;
/// when the gap is exhausted the whole tenant is renumbered in the caller's tx.
async fn reorder_rule(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    moved_id: &str,
    target_rank: usize,
) -> Result<(), ApiError> {
    // Read (seq, rule) for every visible rule in evaluation order.
    let sql = format!(
        "SELECT seq, {RULE_COLUMNS} FROM tool_policy_rules \
         WHERE tenant_id = $1 AND NOT suppressed ORDER BY seq, id"
    );
    let rows = sqlx::query_as::<_, RuleSeqRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("load tool rules for reorder: {e}");
            ApiError::internal("failed to reorder tool risk rule")
        })?;

    let Some(moved_idx) = rows.iter().position(|r| r.rule.rule_id == moved_id) else {
        return Ok(());
    };
    let moved_profile = rows[moved_idx].rule.profile_id;

    // The member set the rank counts over (mirrors the effective-set rules the
    // proxy evaluates): shared rules rank among shared; a profile rule ranks
    // among shared-not-forked-here ∪ that profile's own rules.
    let suppressed_in_profile: std::collections::HashSet<&str> = match moved_profile {
        None => std::collections::HashSet::new(),
        Some(pid) => rows
            .iter()
            .filter(|r| r.rule.profile_id == Some(pid))
            .filter_map(|r| r.rule.forked_from.as_deref())
            .collect(),
    };
    let member_indices: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, r)| match (moved_profile, r.rule.profile_id) {
            (None, p) => p.is_none(),
            (Some(_), None) => !suppressed_in_profile.contains(r.rule.rule_id.as_str()),
            (Some(pid), Some(p)) => p == pid,
        })
        .map(|(i, _)| i)
        .collect();

    // Neighbours in the GLOBAL order that bracket the chosen rank, ignoring the
    // moved row itself.
    let others: Vec<usize> = member_indices
        .iter()
        .copied()
        .filter(|&i| i != moved_idx)
        .collect();
    let rank = target_rank.min(others.len());
    let lower_seq = if rank == 0 { None } else { Some(rows[others[rank - 1]].seq) };
    let upper_seq = others.get(rank).map(|&i| rows[i].seq);

    let new_seq = match (lower_seq, upper_seq) {
        (None, None) => 0,
        (None, Some(u)) => u - SEQ_STEP,
        (Some(l), None) => l + SEQ_STEP,
        (Some(l), Some(u)) if u - l > 1 => l + (u - l) / 2,
        // Gap exhausted — renumber the whole tenant with fresh gaps, placing the
        // moved row at its rank, then we're done.
        (Some(_), Some(_)) => {
            return renumber_rules(conn, tenant_id, &rows, moved_idx, &others, rank).await;
        }
    };

    sqlx::query("UPDATE tool_policy_rules SET seq = $3, updated_at = now() WHERE tenant_id = $1 AND rule_id = $2")
        .bind(tenant_id)
        .bind(moved_id)
        .bind(new_seq)
        .execute(conn)
        .await
        .map_err(|e| {
            tracing::error!("reorder tool rule: {e}");
            ApiError::internal("failed to reorder tool risk rule")
        })?;
    Ok(())
}

/// Renumber every rule's `seq` with fresh gaps in global order, with the moved
/// row spliced to `rank` among `others`. Rare (only when a midpoint gap is
/// exhausted), runs in the caller's transaction.
async fn renumber_rules(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    rows: &[RuleSeqRow],
    moved_idx: usize,
    others: &[usize],
    rank: usize,
) -> Result<(), ApiError> {
    let mut order: Vec<&str> = others.iter().map(|&i| rows[i].rule.rule_id.as_str()).collect();
    // `others` excludes the moved row and any non-member rows; rebuild the full
    // global order by inserting the moved row at its rank among members and
    // appending non-members in their existing order.
    let member_set: std::collections::HashSet<usize> = others.iter().copied().collect();
    order.insert(rank.min(order.len()), rows[moved_idx].rule.rule_id.as_str());
    let mut full: Vec<&str> = Vec::with_capacity(rows.len());
    let mut reordered = order.into_iter();
    for (i, r) in rows.iter().enumerate() {
        if i == moved_idx || member_set.contains(&i) {
            if let Some(next) = reordered.next() {
                full.push(next);
            }
        } else {
            full.push(r.rule.rule_id.as_str());
        }
    }
    for (idx, rule_id) in full.iter().enumerate() {
        sqlx::query("UPDATE tool_policy_rules SET seq = $3 WHERE tenant_id = $1 AND rule_id = $2")
            .bind(tenant_id)
            .bind(*rule_id)
            .bind(idx as i64 * SEQ_STEP)
            .execute(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("renumber tool rules: {e}");
                ApiError::internal("failed to reorder tool risk rule")
            })?;
    }
    Ok(())
}
