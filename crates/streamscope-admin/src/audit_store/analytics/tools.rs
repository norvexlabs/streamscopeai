//! The tool views: the tool inventory with its risk classification, the turns
//! the tool-call feed walks, the transform statistics and the attention queue.
//! The tool-call feed builds its events from the turns here through the
//! canonical `build_events` pipeline, in `routes/analytics.rs`.

use std::collections::HashMap;

use anyhow::Context;
use chrono::{DateTime, Utc};
use streamscope_core::config::tool_rules::classify_tool_call;
use uuid::Uuid;

use crate::audit_store::AuditScope;
use crate::audit_store::filters::{
    AUDIT_LOG_JOIN, AUDIT_LOG_TURN_WINDOW, AUDIT_LOG_WINDOW, AnalyticsFilterBuilder, WEB_AUDIT_JOIN, window_sql,
};
use crate::db::tenant::{Scoped, TenantConn};
use crate::sql_pattern::contains_pattern;
use crate::routes::{AnalyticsScope, ApiError, parse_workspace_ids};
use crate::routes::analytics::{
    AttentionAlerts, AttentionBlocked, AttentionBudget, AttentionErrors, AttentionExpiring,
    AttentionGuardrail, AttentionResponse, AttentionUpstreams, CrossAttentionQuery,
    ProfileCoverage, ToolEntry, ToolInventoryResponse, ToolRiskFilter, ToolSummary,
    TransformStatEntry, TransformStatsResponse, UnprofiledTool, evaluate_budget_scopes,
    load_field_profiles, load_risk_rules,
};

/// Per-turn row for argument-aware risk classification in tool inventory.
/// The turn's `response_tool_calls` JSON is decoded in Rust via the canonical
/// domain layer (`domain_assistant_content_from_stored`) so every inbound
/// protocol lands on a single `DomainContentBlock::ToolUse` shape — no SQL
/// COALESCE on `function.name` / `function_name` / `input` fallbacks.
#[derive(sqlx::FromRow)]
struct InventoryTurnRow {
    request_id: Uuid,
    api_version: String,
    response_tool_calls: Option<serde_json::Value>,
    app_id: Option<String>,
    session_id: Uuid,
    user_id: Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
}

/// Core tool inventory logic — callable from both HTTP handler and agent code.
///
/// `q` and `risk` narrow only the `tools[]` row list (server-side filter applied
/// after aggregation). `summary` and `coverage` always reflect the period as a
/// whole — narrowing them by the row filter would make headline counts
/// tautological the moment a Risk filter is picked.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn tool_inventory_impl(
    conn: &mut Scoped,
    tenant_id: Uuid,
    time: (DateTime<Utc>, DateTime<Utc>),
    app_id: Option<String>,
    user_id: Option<Uuid>,
    workspace_ids: Option<Vec<Uuid>>,
    q: Option<&str>,
    risk: Option<ToolRiskFilter>,
) -> anyhow::Result<ToolInventoryResponse> {
    let mut filters = AnalyticsFilterBuilder::new(2);
    let (lo, hi) = filters.push_time_window(&["ct.timestamp"], time);
    if let Some(app) = &app_id {
        filters.push_eq_str("s.app_id", app);
    }
    if let Some(uid) = user_id {
        filters.push_eq_uuid("s.user_id", uid);
    }
    if let Some(ws) = &workspace_ids {
        filters.push_exists_workspaces("ct.request_id", "ct.timestamp", "ct.tenant_id", (lo, hi), ws);
    }
    let where_extra = filters.where_sql();

    // Fetch one row per turn and decode `response_tool_calls` in Rust via the
    // canonical domain layer — every inbound protocol (Anthropic Messages,
    // OpenAI Chat Completions, OpenAI Responses, Gemini) flows through the
    // same `domain_assistant_content_from_stored` helper the session/audit
    // viewers use, so adding a new protocol never forces a parallel SQL
    // change here.
    let turns_sql = format!(
        r#"SELECT
                ct.request_id,
                ct.api_version,
                ct.response_tool_calls,
                s.app_id,
                s.session_id,
                s.user_id,
                ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            WHERE ct.tenant_id = $1
              AND ct.response_tool_calls IS NOT NULL
              AND ct.response_tool_calls != 'null'::jsonb
              AND jsonb_array_length(ct.response_tool_calls) > 0
              {where_extra}"#
    );

    let turns_query = filters.apply_query_as(
        sqlx::query_as::<_, InventoryTurnRow>(sqlx::AssertSqlSafe(&*turns_sql)).bind(tenant_id),
    );

    let turn_rows = turns_query
        .fetch_all(&mut *conn)
        .await?;

    // Decode each turn's stored tool calls into canonical `DomainContentBlock::ToolUse`
    // blocks, then flatten into the `(name, args, session/user/app/ts)` tuples the
    // aggregation loop below consumes — one row per individual tool call. Tool-name
    // and argument normalization lives in one place, the domain layer, never in
    // SQL.
    struct InventoryCall {
        tool_name: String,
        arguments: serde_json::Value,
        app_id: Option<String>,
        session_id: Uuid,
        user_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
    }
    let mut call_rows: Vec<InventoryCall> = Vec::with_capacity(turn_rows.len());
    for row in &turn_rows {
        // `decode_stored_tool_call` is shape-driven — it recognizes every
        // stored wire format (accumulator / OpenAI CC / Anthropic / Gemini /
        // Responses raw) regardless of the `protocol` arg, which only
        // influences the synthetic id prefix for calls with no stored id.
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
            if let streamscope_core::api::domain_request::DomainContentBlock::ToolUse {
                name,
                input,
                input_raw,
                ..
            } = block
            {
                if name.is_empty() {
                    continue;
                }
                // Prefer the parsed object. When the model emitted malformed
                // JSON the domain layer already tried parsing and stashed the
                // raw string in `input_raw`; don't try again — pass the raw
                // through as `Value::String` so regex-based risk rules still
                // fire against the substring they'd have matched in JSON form.
                // Falling back to `{}` would silently pass every
                // argument-based rule for malformed calls.
                let arguments = if input.is_null() {
                    match input_raw {
                        Some(s) => serde_json::Value::String(s),
                        None => serde_json::Value::Object(serde_json::Map::new()),
                    }
                } else {
                    input
                };
                call_rows.push(InventoryCall {
                    tool_name: name,
                    arguments,
                    app_id: row.app_id.clone(),
                    session_id: row.session_id,
                    user_id: row.user_id,
                    timestamp: row.timestamp,
                });
            }
        }
    }

    // Load risk classification rules + field profiles from system_settings.
    // Field profiles drive `tool_id` resolution; classification falls back to
    // unclassified when none matches.
    let risk_rules = load_risk_rules(&mut *conn).await;
    let field_profiles = load_field_profiles(&mut *conn).await;

    // Classify each individual call with arguments, then aggregate per tool name.
    struct ToolAgg {
        // Most recent resolved tool_id seen for this wire name. Field profiles
        // can disambiguate the same wire name into different tool_ids based on
        // app_id / mcp_server, but at the dashboard level we surface one — the
        // last-seen wins, which lines up with `last_used`.
        tool_id: Option<String>,
        call_count: i64,
        blocked_count: i64,
        // Per-risk-level call counts (drive the chip row on the dashboard card).
        safe_count: i64,
        caution_count: i64,
        danger_count: i64,
        unknown_count: i64,
        sessions: std::collections::HashSet<Uuid>,
        users: std::collections::HashSet<Uuid>,
        app_ids: std::collections::HashSet<String>,
        last_used: chrono::DateTime<chrono::Utc>,
        // Highest-risk classification seen for this tool name (for the per-tool display)
        worst_risk: String,
        worst_title: Option<String>,
        worst_description: Option<String>,
    }

    let mut tool_aggs: std::collections::HashMap<String, ToolAgg> = std::collections::HashMap::new();
    let mut risk_counts: HashMap<String, usize> = HashMap::new();
    let mut profiled_calls: i64 = 0;
    let mut unprofiled_call_counts: std::collections::HashMap<String, i64> = std::collections::HashMap::new();
    let mut total_calls: i64 = 0;

    fn risk_severity(r: &str) -> u8 {
        match r { "danger" => 3, "caution" => 2, "unknown" => 1, _ => 0 }
    }

    for row in &call_rows {
        let name = row.tool_name.clone();
        // Inventory aggregation runs across all models for this tenant; pass
        // None as the model filter so model_filter rules don't suppress
        // classifications in the per-tool stats. Per-model breakdowns (when
        // we add them) should switch this to the row's model_used.
        let result = classify_tool_call(
            &risk_rules,
            None,
            row.app_id.as_deref(),
            Some(&field_profiles),
            &name,
            Some(&row.arguments),
        );

        total_calls += 1;

        // Per-risk-level counts
        *risk_counts.entry(result.risk.clone()).or_insert(0) += 1;

        // Profile coverage: classify_tool_call already walks the field-profile
        // registry; reading `result.tool_id` here avoids a second resolve call.
        if result.tool_id.is_some() {
            profiled_calls += 1;
        } else {
            *unprofiled_call_counts.entry(name.clone()).or_insert(0) += 1;
        }

        // Per-tool aggregation
        let agg = tool_aggs.entry(name.clone()).or_insert_with(|| ToolAgg {
            tool_id: None,
            call_count: 0,
            blocked_count: 0,
            safe_count: 0,
            caution_count: 0,
            danger_count: 0,
            unknown_count: 0,
            sessions: std::collections::HashSet::new(),
            users: std::collections::HashSet::new(),
            app_ids: std::collections::HashSet::new(),
            last_used: row.timestamp,
            worst_risk: "safe".to_string(),
            worst_title: None,
            worst_description: None,
        });
        agg.call_count += 1;
        match result.risk.as_str() {
            "safe" => agg.safe_count += 1,
            "caution" => agg.caution_count += 1,
            "danger" => agg.danger_count += 1,
            _ => agg.unknown_count += 1,
        }
        agg.sessions.insert(row.session_id);
        agg.users.insert(row.user_id);
        if let Some(app) = &row.app_id { agg.app_ids.insert(app.clone()); }
        if row.timestamp >= agg.last_used {
            agg.last_used = row.timestamp;
            // Last-seen tool_id wins — covers the case where a profile is
            // added or refined mid-window.
            if result.tool_id.is_some() {
                agg.tool_id = result.tool_id.clone();
            }
        }
        if risk_severity(&result.risk) > risk_severity(&agg.worst_risk) {
            agg.worst_risk = result.risk;
            agg.worst_title = result.title;
            agg.worst_description = result.description;
        }
        // First-seen tool_id wins when last_used didn't advance (e.g. equal
        // timestamps in the same turn). Prevents an entry from staying `None`
        // when the very first row already resolved.
        if agg.tool_id.is_none() && result.tool_id.is_some() {
            agg.tool_id = result.tool_id;
        }
    }

    // Fetch blocked tools from transform_diff (request-side + response-side).
    // Both UNION branches reference the same placeholders, so binds happen
    // once and PostgreSQL substitutes them in both halves.
    let blocked_sql = format!(
        r#"SELECT bt_elem->>'name' AS tool_name, s.app_id, s.session_id, s.user_id, ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            CROSS JOIN LATERAL jsonb_array_elements(ct.transform_diff->'blocked_tools') AS bt_elem
            WHERE ct.tenant_id = $1
              AND ct.transform_diff->'blocked_tools' IS NOT NULL
              AND jsonb_array_length(ct.transform_diff->'blocked_tools') > 0
              {where_extra}
        UNION ALL
        SELECT bt_elem->>'name' AS tool_name, s.app_id, s.session_id, s.user_id, ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            CROSS JOIN LATERAL jsonb_array_elements(ct.transform_diff->'response_blocked_tools') AS bt_elem
            WHERE ct.tenant_id = $1
              AND ct.transform_diff->'response_blocked_tools' IS NOT NULL
              AND jsonb_array_length(ct.transform_diff->'response_blocked_tools') > 0
              {where_extra}"#
    );

    #[derive(sqlx::FromRow)]
    struct BlockedRow {
        tool_name: Option<String>,
        app_id: Option<String>,
        session_id: Uuid,
        user_id: Uuid,
        timestamp: chrono::DateTime<chrono::Utc>,
    }

    let blocked_query = filters.apply_query_as(
        sqlx::query_as::<_, BlockedRow>(sqlx::AssertSqlSafe(&*blocked_sql)).bind(tenant_id),
    );

    // Propagated, not defaulted: a failure here would render as "nothing was
    // blocked", which is indistinguishable from a policy that blocked nothing
    // and is the more dangerous of the two to believe.
    let blocked_rows = blocked_query
        .fetch_all(&mut *conn)
        .await
        .context("tool inventory blocked-call aggregate")?;

    let mut total_blocked: i64 = 0;
    for row in &blocked_rows {
        let name = match &row.tool_name {
            Some(n) if !n.is_empty() => n.clone(),
            _ => continue,
        };
        total_blocked += 1;

        let agg = tool_aggs.entry(name).or_insert_with(|| ToolAgg {
            tool_id: None,
            call_count: 0,
            blocked_count: 0,
            safe_count: 0,
            caution_count: 0,
            danger_count: 0,
            unknown_count: 0,
            sessions: std::collections::HashSet::new(),
            users: std::collections::HashSet::new(),
            app_ids: std::collections::HashSet::new(),
            last_used: row.timestamp,
            worst_risk: "danger".to_string(),
            worst_title: Some("Blocked by policy".to_string()),
            worst_description: Some("Tool call blocked by policy".to_string()),
        });
        agg.blocked_count += 1;
        agg.sessions.insert(row.session_id);
        agg.users.insert(row.user_id);
        if let Some(app) = &row.app_id { agg.app_ids.insert(app.clone()); }
        if row.timestamp > agg.last_used { agg.last_used = row.timestamp; }
    }

    // Build tools list sorted by call count
    let mut tools: Vec<ToolEntry> = tool_aggs.into_iter().map(|(name, agg)| {
        ToolEntry {
            tool_name: name,
            tool_id: agg.tool_id,
            risk_level: agg.worst_risk,
            call_count: agg.call_count,
            blocked_count: agg.blocked_count,
            safe_count: agg.safe_count,
            caution_count: agg.caution_count,
            danger_count: agg.danger_count,
            unknown_count: agg.unknown_count,
            session_count: agg.sessions.len() as i64,
            user_count: agg.users.len() as i64,
            last_used: agg.last_used,
            app_ids: agg.app_ids.into_iter().collect(),
            rule_title: agg.worst_title,
            rule_description: agg.worst_description,
        }
    }).collect();
    tools.sort_by(|a, b| {
        b.call_count
            .cmp(&a.call_count)
            .then_with(|| a.tool_name.cmp(&b.tool_name))
            .then_with(|| a.tool_id.cmp(&b.tool_id))
    });

    // Aggregate `redacted_count` from `transform_diff.redacted_tool_results[]`
    // over the same window/scope. Counts the number of redaction entries (one
    // per rewritten tool_result block), matching what the Log tab surfaces.
    let redacted_sql = format!(
        r#"SELECT COALESCE(SUM(jsonb_array_length(ct.transform_diff->'redacted_tool_results')), 0)::bigint
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            WHERE ct.tenant_id = $1
              AND ct.transform_diff->'redacted_tool_results' IS NOT NULL
              AND jsonb_array_length(ct.transform_diff->'redacted_tool_results') > 0
              {where_extra}"#
    );
    let redacted_count: i64 = filters
        .apply_query_scalar(sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(&*redacted_sql)).bind(tenant_id))
        .fetch_one(&mut *conn)
        .await
        .unwrap_or(0);

    // Coverage: top-N unprofiled wire names by call count.
    let mut top_unprofiled: Vec<UnprofiledTool> = unprofiled_call_counts
        .into_iter()
        .map(|(tool_name, call_count)| UnprofiledTool { tool_name, call_count })
        .collect();
    top_unprofiled.sort_by(|a, b| b.call_count.cmp(&a.call_count).then_with(|| a.tool_name.cmp(&b.tool_name)));
    top_unprofiled.truncate(10);

    let coverage = ProfileCoverage {
        profiled_calls,
        total_calls,
        top_unprofiled,
    };

    // Headline summary — computed before any q/risk row filter is applied so
    // the cards reflect the period as a whole, not "the period filtered by the
    // chip the operator just clicked".
    let summary = ToolSummary {
        total_tools: tools.len(),
        total_calls,
        blocked_count: total_blocked,
        safe_count: risk_counts.get("safe").copied().unwrap_or(0),
        caution_count: risk_counts.get("caution").copied().unwrap_or(0),
        danger_count: risk_counts.get("danger").copied().unwrap_or(0),
        unknown_count: risk_counts.get("unknown").copied().unwrap_or(0),
        redacted_count,
    };

    // Apply row-only filters (`q`, `risk`) AFTER summary + coverage so headline
    // counts don't go tautological when the operator picks Risk=danger.
    if let Some(needle) = q.map(|s| s.trim().to_ascii_lowercase()).filter(|s| !s.is_empty()) {
        tools.retain(|t| {
            t.tool_name.to_ascii_lowercase().contains(&needle)
                || t.tool_id
                    .as_deref()
                    .map(|id| id.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
        });
    }
    match risk {
        None => {}
        Some(ToolRiskFilter::Blocked) => tools.retain(|t| t.blocked_count > 0),
        Some(level) => tools.retain(|t| t.risk_level == level.as_str()),
    }
    tools.truncate(500);

    Ok(ToolInventoryResponse { tools, summary, coverage })
}

#[derive(sqlx::FromRow)]
pub(crate) struct InvocationRow {
    pub(crate) request_id: Uuid,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
    pub(crate) session_id: Uuid,
    pub(crate) user_display: Option<String>,
    pub(crate) user_email: Option<String>,
    pub(crate) latency_total_ms: Option<i64>,
    pub(crate) app_id: Option<String>,
    pub(crate) turn_number: i32,
    pub(crate) api_version: String,
    pub(crate) model_used: Option<String>,
    pub(crate) model_requested: Option<String>,
    pub(crate) request_tools_hash: Option<String>,
    /// The tool set `request_tools_hash` names, read by [`ToolCallTurns::batch`]
    /// from the content store; `None` when the turn has none or (defensively)
    /// the tenant holds no such set.
    /// Shared: rows of one batch naming the same set hold one copy.
    #[sqlx(skip)]
    pub(crate) request_tools: Option<std::sync::Arc<serde_json::Value>>,
    pub(crate) request_params: Option<serde_json::Value>,
    pub(crate) response_content: Option<String>,
    pub(crate) response_tool_calls: Option<serde_json::Value>,
    pub(crate) transform_diff: Option<serde_json::Value>,
    pub(crate) next_request_id: Option<Uuid>,
    pub(crate) next_api_version: Option<String>,
    pub(crate) next_request_tools_hash: Option<String>,
    /// The tool set `next_request_tools_hash` names, read like
    /// [`Self::request_tools`].
    #[sqlx(skip)]
    pub(crate) next_request_tools: Option<std::sync::Arc<serde_json::Value>>,
    pub(crate) next_request_params: Option<serde_json::Value>,
    pub(crate) next_response_content: Option<String>,
    pub(crate) next_response_tool_calls: Option<serde_json::Value>,
    /// The answering turn's real turn number (`trace::answer_laterals`).
    pub(crate) next_turn_number: Option<i32>,
    /// `true`: [`Self::next_hashes`] is the slice the call turn's child added;
    /// `false`: the next turn's whole history, narrowed by
    /// `trace::answer_hashes` with [`Self::call_message_hashes`].
    pub(crate) next_sliced: Option<bool>,
    pub(crate) next_hashes: Option<Vec<String>>,
    /// The call turn's history — read only when the answering turn is not
    /// such a child.
    pub(crate) call_message_hashes: Option<Vec<String>>,
    pub(crate) next_transform_diff: Option<serde_json::Value>,
    pub(crate) next_model_used: Option<String>,
    pub(crate) next_model_requested: Option<String>,
}

/// Turns asked of each batch of the tool-call feed's walk.
const BATCH_SIZE: i64 = 500;

/// The tool-call feed's turn walk: turns that carry a tool call, or a call
/// tool policy blocked, newest first, each with its next turn (where a call's
/// result arrives) resolved beside it. The feed lists only the call turn's own
/// calls (its response), so the call turn's history is read only to narrow a
/// next turn that is no child counted from it; a child's results are in the
/// slice it added. The SQL has its window, scope, focus and
/// search filters spliced in once; each batch binds the keyset cursor
/// `(timestamp, request_id)` of the last row of the one before.
pub(crate) struct ToolCallTurns {
    tenant_id: Uuid,
    filters: AnalyticsFilterBuilder,
    sql: String,
    search: Option<(String, String)>,
}

impl ToolCallTurns {
    /// `scope` is whose turns the walk may return; `search` is the term's
    /// `(contains, prefix)` pattern pair.
    pub(crate) fn new(
        tenant_id: Uuid,
        window: (DateTime<Utc>, DateTime<Utc>),
        scope: &AuditScope,
        app_id: Option<&str>,
        user_email: Option<&str>,
        request_id: Option<Uuid>,
        search: Option<(String, String)>,
    ) -> Self {
        let (start_ts, end_ts) = window;
        let has_search = search.is_some();
        // Build dimension filters; tenant_id reserves $1, then time window + scope.
        let mut filters = AnalyticsFilterBuilder::new(2);
        let (lo, hi) = filters.push_time_window(&["ct.timestamp"], (start_ts, end_ts));
        // The page's outer-joined facts state the window in their ON clauses.
        let llm_window = window_sql(&["a.timestamp"], lo, hi);
        let gateway_window = window_sql(&["g.timestamp"], lo, hi);
        let next_window = window_sql(&["nxt_a.timestamp"], lo, hi);
        let turn_window = window_sql(&["ct.timestamp"], lo, hi);
        let answer = crate::audit_store::trace::answer_laterals(Some((lo, hi)));
        let resolved_window = window_sql(&["r.timestamp"], lo, hi);
        if let Some(app) = app_id {
            filters.push_ilike("s.app_id", &contains_pattern(app));
        }
        if let Some(uid) = scope.user_id() {
            filters.push_eq_uuid("s.user_id", uid);
        }
        if let Some(user_email) = user_email {
            filters.push_ilike("COALESCE(u.email, '')", &contains_pattern(user_email));
        }
        // Deep-link focus — restrict the LLM walk to the single turn the operator
        // is opening. Without this the helper sweeps the time window like a list
        // query and a row older than `days=1` can't be expanded (matches the
        // audit-side `query.request_id` clause pattern).
        if let Some(rid) = request_id {
            filters.push_eq_uuid("ct.request_id", rid);
        }
        if let Some(ws) = scope.workspace_ids() {
            filters.push_exists_workspaces("ct.request_id", "ct.timestamp", "ct.tenant_id", (lo, hi), ws);
        }
        // Cursor `(timestamp, request_id)` binds come after every filter bind.
        let cursor_ts_idx = filters.next_bind_idx();
        let cursor_rid_idx = cursor_ts_idx + 1;
        // Search bind, when active, comes after the cursor binds. The predicate
        // admits a turn on what the caller's per-call filter
        // (`collect_tool_invocations`) tests: the calls' names
        // and arguments and the names, descriptions and argument values of the
        // calls response policy removed (all in `tool_call_search_blob`), the
        // user's email or display name, and the session id from its start. It is a
        // filter over the window's turns: no index can serve `ILIKE` for the
        // runtime role under FORCE RLS.
        let search_idx = cursor_rid_idx + 1;
        let search_prefix_idx = search_idx + 1;
        let search_clause = if has_search {
            format!(
                " AND (ct.tool_call_search_blob ILIKE ${search_idx} \
                  OR ct.session_id::text ILIKE ${search_prefix_idx} \
                  OR COALESCE(u.email, '') ILIKE ${search_idx} \
                  OR COALESCE(u.display_name, '') ILIKE ${search_idx})"
            )
        } else {
            String::new()
        };
        let where_extra = filters.where_sql().to_string();

        // The page is chosen first, from the base table: resolving the next
        // turn and its added slice (`conversation_turns_resolved`) costs a walk
        // per row, so it runs on the page's rows only, never on every candidate in
        // the window.
        let sql = format!(
            r#"WITH page AS MATERIALIZED (
            SELECT ct.tenant_id, ct.request_id, ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            LEFT JOIN users u ON u.id = s.user_id
            WHERE ct.tenant_id = $1
              AND (
                (ct.response_tool_calls IS NOT NULL
                  AND ct.response_tool_calls != 'null'::jsonb
                  AND jsonb_array_length(ct.response_tool_calls) > 0)
                OR (ct.transform_diff->'blocked_tools' IS NOT NULL
                  AND jsonb_array_length(ct.transform_diff->'blocked_tools') > 0)
                OR (ct.transform_diff->'response_blocked_tools' IS NOT NULL
                  AND jsonb_array_length(ct.transform_diff->'response_blocked_tools') > 0)
              )
              {where_extra}
              {search_clause}
              AND (
                ${cursor_ts_idx}::timestamptz IS NULL
                OR (ct.timestamp, ct.request_id) < (${cursor_ts_idx}::timestamptz, ${cursor_rid_idx}::uuid)
              )
            ORDER BY ct.timestamp DESC, ct.request_id DESC
            LIMIT {BATCH_SIZE}
        )
        SELECT
            ct.request_id,
            ct.timestamp,
            ct.session_id,
            COALESCE(u.display_name, u.email, s.user_id::text) AS user_display,
            u.email                AS user_email,
            g.latency_total_ms     AS latency_total_ms,
            s.app_id,
            ct.turn_number,
            ct.api_version,
            a.model_used,
            a.model_requested,
            ct.tools_available_hash AS request_tools_hash,
            ct.request_params,
            ct.response_content,
            ct.response_tool_calls,
            ct.transform_diff,
            nxt.request_id         AS next_request_id,
            nxt.api_version        AS next_api_version,
            nxt.tools_available_hash AS next_request_tools_hash,
            nxt.request_params     AS next_request_params,
            nxt.response_content   AS next_response_content,
            nxt.response_tool_calls AS next_response_tool_calls,
            nxt.turn_number        AS next_turn_number,
            nxt.sliced             AS next_sliced,
            nxt.hashes             AS next_hashes,
            CASE WHEN NOT nxt.sliced
                 THEN turn_message_hashes(ct.history_head) END AS call_message_hashes,
            nxt.transform_diff     AS next_transform_diff,
            nxt_a.model_used       AS next_model_used,
            nxt_a.model_requested  AS next_model_requested
        FROM page p
        JOIN conversation_turns ct
            ON ct.tenant_id = p.tenant_id AND ct.request_id = p.request_id AND ct.timestamp = p.timestamp{turn_window}
        JOIN sessions s ON s.session_id = ct.session_id
        LEFT JOIN users u ON u.id = s.user_id
        LEFT JOIN llm_audit a ON a.request_id = ct.request_id AND a.timestamp = ct.timestamp{llm_window}
        LEFT JOIN gateway_audit g ON g.request_id = ct.request_id AND g.timestamp = ct.timestamp{gateway_window}
        -- The turn that answers the call turn (`trace::answer_laterals`): the
        -- one rule the trace reads too.
        {answer}
        LEFT JOIN LATERAL (
            -- The chosen turn, resolved by its key: a LATERAL with a LIMIT so
            -- the planner probes it per page row, never resolving (walking
            -- the history of) every turn of the window to join them.
            SELECT r.request_id, r.timestamp, r.turn_number, r.api_version,
                   r.tools_available_hash, r.request_params, r.response_content,
                   r.response_tool_calls, r.transform_diff, ans.answer_sliced AS sliced,
                   CASE WHEN ans.answer_sliced THEN r.added_hashes ELSE r.message_hashes END AS hashes
            FROM conversation_turns_resolved r
            WHERE r.tenant_id = ct.tenant_id
              AND r.request_id = ans.answer_request_id
              AND r.timestamp = ans.answer_timestamp{resolved_window}
            LIMIT 1
        ) nxt ON TRUE
        LEFT JOIN llm_audit nxt_a ON nxt_a.request_id = nxt.request_id AND nxt_a.timestamp = nxt.timestamp{next_window}
        ORDER BY ct.timestamp DESC, ct.request_id DESC"#
        );
        Self { tenant_id, filters, sql, search }
    }

    /// The next batch after `cursor` (`None`: the first), each row's tool sets
    /// read from the content store in one more round trip.
    pub(crate) async fn batch(
        &self,
        conn: &mut Scoped,
        cursor: Option<(DateTime<Utc>, Uuid)>,
    ) -> sqlx::Result<Vec<InvocationRow>> {
        let mut sqlx_query = self.filters.apply_query_as(
            sqlx::query_as::<_, InvocationRow>(sqlx::AssertSqlSafe(&*self.sql)).bind(self.tenant_id),
        );
        // Cursor tuple — NULL on first iteration.
        sqlx_query = sqlx_query
            .bind(cursor.map(|(ts, _)| ts))
            .bind(cursor.map(|(_, rid)| rid));
        if let Some((contains, prefix)) = &self.search {
            sqlx_query = sqlx_query.bind(contains.clone()).bind(prefix.clone());
        }
        let mut rows = sqlx_query.fetch_all(&mut *conn).await?;
        let hashes: Vec<String> = rows
            .iter()
            .flat_map(|r| [r.request_tools_hash.as_ref(), r.next_request_tools_hash.as_ref()])
            .flatten()
            .cloned()
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect();
        let sets: std::collections::HashMap<String, std::sync::Arc<serde_json::Value>> =
            crate::content_store::tool_definitions::get_many(&mut *conn, self.tenant_id, &hashes)
                .await?
                .into_iter()
                .map(|(h, v)| (h, std::sync::Arc::new(v)))
                .collect();
        for r in &mut rows {
            r.request_tools = r.request_tools_hash.as_ref().and_then(|h| sets.get(h).cloned());
            r.next_request_tools = r.next_request_tools_hash.as_ref().and_then(|h| sets.get(h).cloned());
        }
        Ok(rows)
    }
}

/// Transform and policy label counts of the window. Its two aggregates run
/// concurrently on their own tenant connections from `pool`; `db` is released
/// before they run.
pub(crate) async fn transform_stats(
    db: TenantConn,
    pool: crate::db::Db,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<TransformStatsResponse, ApiError> {
    let tenant_id = db.tenant_uuid();
    let tenant_kind = db.tenant_id();

    let workspace_ids = scope.workspace_ids.clone();
    drop(db);

    // Per-program stats and the request-count aggregate are independent —
    // run them on separate connections so the wall-clock is the slower
    // query, not the sum. The labels CTE pivots on conversation_turns
    // (heavy: lateral expand of every transform_diff JSONB); the counts
    // query pivots on llm_audit only (light: index-bound badge tally).
    let labels_fut = {
        let pool = pool.clone();
        let workspace_ids = workspace_ids.clone();
        async move {
            let mut conn = TenantConn::acquire(&pool, tenant_kind).await
                .map_err(|e| {
                    tracing::error!("transform_stats labels acquire: {e}");
                    ApiError::internal("database query failed")
                })?;
            let mut tr_filters = AnalyticsFilterBuilder::new(2);
            // The window on every fact of the join — the turn's too.
            tr_filters.push_time_window(AUDIT_LOG_TURN_WINDOW, (start_ts, end_ts));
            if let Some(ws) = &workspace_ids {
                tr_filters.push_workspaces("g.workspace_id", ws);
            }
            let tr_where = tr_filters.where_sql();
            let labels_sql = format!(
                r#"WITH tr_programs AS (
                    SELECT
                        prog->>'name' AS name,
                        prog->>'outcome' AS outcome,
                        ct.timestamp
                    FROM {AUDIT_LOG_JOIN}
                    JOIN conversation_turns ct ON ct.tenant_id = a.tenant_id
                      AND ct.request_id = a.request_id AND ct.timestamp = a.timestamp
                    CROSS JOIN LATERAL jsonb_array_elements(
                        COALESCE(ct.transform_diff->'transform_programs', '[]'::jsonb)
                        || COALESCE(ct.transform_diff->'response_transform_programs', '[]'::jsonb)
                    ) AS prog
                    WHERE a.tenant_id = $1
                      {tr_where}
                )
                SELECT
                    name,
                    COUNT(*)::bigint AS total,
                    COALESCE(SUM(CASE WHEN outcome = 'modified' THEN 1 ELSE 0 END), 0)::bigint AS modify_count,
                    COALESCE(SUM(CASE WHEN outcome = 'passed' THEN 1 ELSE 0 END), 0)::bigint AS pass_count,
                    COALESCE(SUM(CASE WHEN outcome = 'errored' THEN 1 ELSE 0 END), 0)::bigint AS error_count,
                    MAX(timestamp) AS last_seen
                FROM tr_programs
                WHERE name IS NOT NULL
                GROUP BY name
                ORDER BY total DESC, name"#
            );
            let q = tr_filters.apply_query_as(
                sqlx::query_as::<_, TransformStatEntry>(sqlx::AssertSqlSafe(&*labels_sql)).bind(tenant_id),
            );
            q.fetch_all(conn.conn()).await.map_err(|e| {
                tracing::error!("transform stats query: {e}");
                ApiError::internal("database query failed")
            })
        }
    };

    let counts_fut = {
        let pool = pool.clone();
        let workspace_ids = workspace_ids.clone();
        async move {
            let mut conn = TenantConn::acquire(&pool, tenant_kind).await
                .map_err(|e| {
                    tracing::error!("transform_stats counts acquire: {e}");
                    ApiError::internal("database query failed")
                })?;
            let mut counts_filters = AnalyticsFilterBuilder::new(2);
            counts_filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
            if let Some(ws) = &workspace_ids {
                counts_filters.push_workspaces("g.workspace_id", ws);
            }
            let counts_sql = format!(
                r#"SELECT
                    COUNT(*)::bigint,
                    COALESCE(SUM(CASE WHEN badges @> '[{{"code":"modified"}}]'::jsonb THEN 1 ELSE 0 END), 0)::bigint
                FROM {AUDIT_LOG_JOIN}
                WHERE tenant_id = $1{}"#,
                counts_filters.where_sql()
            );
            let q = counts_filters.apply_query_as(
                sqlx::query_as::<_, (Option<i64>, Option<i64>)>(sqlx::AssertSqlSafe(&*counts_sql)).bind(tenant_id),
            );
            q.fetch_one(conn.conn()).await.map_err(|e| {
                tracing::error!("transform counts query: {e}");
                ApiError::internal("database query failed")
            })
        }
    };

    let (mut rows, counts) = tokio::try_join!(labels_fut, counts_fut)?;

    // Resolve name → program UUID so the UI can deep-link each row to
    // `/transforms/<id>`. A name with no live row stays `id: None` and
    // renders non-clickable.
    let mut name_to_id_conn = TenantConn::acquire(&pool, tenant_kind).await
        .map_err(|e| {
            tracing::error!("transform_stats program-id acquire: {e}");
            ApiError::internal("database query failed")
        })?;
    let name_to_id: std::collections::HashMap<String, Uuid> = sqlx::query_as::<_, (Uuid, String)>(
        "SELECT id, name FROM transform_programs WHERE tenant_id = $1 AND NOT suppressed",
    )
    .bind(tenant_id)
    .fetch_all(name_to_id_conn.conn())
    .await
    .map_err(|e| {
        tracing::error!("transform_stats program-id lookup: {e}");
        ApiError::internal("database query failed")
    })?
    .into_iter()
    .map(|(id, name)| (name, id))
    .collect();
    for row in &mut rows {
        row.id = name_to_id.get(&row.name).copied();
    }

    Ok(TransformStatsResponse {
        transforms: rows,
        total_requests: counts.0.unwrap_or(0),
        requests_with_transforms: counts.1.unwrap_or(0),
    })
}

/// The attention queue: the counts behind each tile over the last
/// `window_days`, keys expiring within `expiry_window_days`, the budget scopes
/// and the live server load.
pub(crate) async fn cross_attention(
    db: &mut TenantConn,
    tenant_id: Uuid,
    window_days: i32,
    expiry_window_days: i32,
    query: &CrossAttentionQuery,
) -> Result<AttentionResponse, ApiError> {
    // The workspace filter binds at $2. The two day counts reach the SQL as
    // `INTERVAL` literals via `interval_days` (Postgres takes no bind inside an
    // INTERVAL literal); that helper's `i32` parameter is what keeps it safe. The
    // expiring-credentials tile scopes its `api_keys` side via `$2` and drops the
    // workspace-less `mcp_user_credentials` union when a workspace is set.
    let window_interval = interval_days(window_days);
    let expiry_sql = interval_days(expiry_window_days);
    let workspace_ids = parse_workspace_ids(&query.workspace_ids);
    // The budget tile's shared evaluator filters by a single workspace. The
    // other tiles aggregate over the whole `workspace_ids` set; to stay
    // consistent, only narrow the budget tile when exactly ONE workspace is
    // explicitly selected — otherwise (the default multi-id lens, or none) it
    // stays tenant-wide rather than reflecting one arbitrary workspace.
    let budget_workspace_id = match workspace_ids.as_deref() {
        Some([only]) => Some(*only),
        _ => None,
    };
    let ws_alerts = if workspace_ids.is_some() {
        " AND sessions.workspace_id = ANY($2)"
    } else {
        ""
    };
    let ws_blocked = if workspace_ids.is_some() {
        " AND g.workspace_id = ANY($2)"
    } else {
        ""
    };
    let ws_errors = if workspace_ids.is_some() {
        " AND workspace_id = ANY($2)"
    } else {
        ""
    };

    // 1. Alerts — sessions flagged by the agent in the activity window.
    //    Uses the partial index idx_sessions_alert WHERE alert_level IN
    //    ('minor','major').
    let alerts_sql = format!(
        "SELECT \
            COUNT(*)::bigint AS total, \
            COUNT(*) FILTER (WHERE alert_level = 'major')::bigint AS major, \
            COUNT(*) FILTER (WHERE alert_level = 'minor')::bigint AS minor \
         FROM sessions \
         WHERE tenant_id = $1 \
           AND alert_level IN ('minor', 'major') \
           AND updated_at >= NOW() - {window_interval}{ws_alerts}"
    );
    let alerts: (Option<i64>, Option<i64>, Option<i64>) = {
        let mut q = sqlx::query_as(sqlx::AssertSqlSafe(&*alerts_sql)).bind(tenant_id);
        if let Some(ref ws) = workspace_ids {
            q = q.bind(ws.clone());
        }
        q.fetch_one(db.conn()).await
    }
    .map_err(|e| {
        tracing::error!("cross attention alerts: {e}");
        ApiError::internal("database query failed")
    })?;

    // 2. Blocked tool calls — gateway-side `tool_blocked` badge, response phase.
    //    The same badge filter as the overview's `response_tool_blocks` count.
    let blocked_filter = "a.badges @> '[{\"code\":\"tool_blocked\",\"phase\":\"response\"}]'::jsonb";
    let blocked_sql = format!(
        "SELECT \
            COUNT(*)::bigint AS total, \
            ( \
                SELECT (elem->>'id')::text \
                FROM {AUDIT_LOG_JOIN} \
                LEFT JOIN conversation_turns ct \
                    ON ct.request_id = a.request_id AND ct.timestamp = a.timestamp \
                   AND ct.timestamp >= NOW() - {window_interval}, \
                    jsonb_array_elements( \
                        COALESCE(ct.transform_diff->'response_blocked_tools', '[]'::jsonb) \
                    ) AS elem \
                WHERE g.tenant_id = $1 \
                  AND a.timestamp >= NOW() - {window_interval} \
                  AND g.timestamp >= NOW() - {window_interval} \
                  AND {blocked_filter}{ws_blocked} \
                GROUP BY elem->>'id' \
                ORDER BY COUNT(*) DESC, elem->>'id' \
                LIMIT 1 \
            ) AS top_rule_id \
         FROM {AUDIT_LOG_JOIN} \
         WHERE g.tenant_id = $1 \
           AND a.timestamp >= NOW() - {window_interval} \
           AND g.timestamp >= NOW() - {window_interval} \
           AND {blocked_filter}{ws_blocked}"
    );
    let blocked: (Option<i64>, Option<String>) = {
        let mut q = sqlx::query_as(sqlx::AssertSqlSafe(&*blocked_sql)).bind(tenant_id);
        if let Some(ref ws) = workspace_ids {
            q = q.bind(ws.clone());
        }
        q.fetch_one(db.conn()).await
    }
    .map_err(|e| {
        tracing::error!("cross attention blocked: {e}");
        ApiError::internal("database query failed")
    })?;

    // 2b. Guardrail — rows the inline guardrail wants an operator to look at:
    //     a finding, or content it could not screen in full. Counts both
    //     surfaces through the SHARED predicate so the tile matches the
    //     `has_guardrail` audit filter it links to exactly: `llm_audit` rows
    //     (content folded back into a model on the substitution loop) plus
    //     `web_audit` rows (the direct `/mcp/web` observe scan).
    //     `blocked` is the enforce-mode (stripped) subset — only the
    //     substitution path strips, so it stays an LLM-side count. Honors the
    //     workspace scope (`g`-side, identical across the two joins).
    let llm_guardrail = crate::audit_store::guardrail::guardrail_badge_predicate("a");
    let web_guardrail = crate::audit_store::guardrail::guardrail_badge_predicate("w");
    let guardrail_sql = format!(
        "SELECT \
            ( \
                (SELECT COUNT(*) FROM {AUDIT_LOG_JOIN} \
                 WHERE g.tenant_id = $1 \
                   AND a.timestamp >= NOW() - {window_interval} \
                   AND g.timestamp >= NOW() - {window_interval} \
                   AND {llm_guardrail}{ws_blocked}) \
                + \
                (SELECT COUNT(*) FROM {WEB_AUDIT_JOIN} \
                 WHERE g.tenant_id = $1 \
                   AND w.timestamp >= NOW() - {window_interval} \
                   AND g.timestamp >= NOW() - {window_interval} \
                   AND {web_guardrail}{ws_blocked}) \
            )::bigint AS total, \
            (SELECT COUNT(*) FROM {AUDIT_LOG_JOIN} \
             WHERE g.tenant_id = $1 \
               AND a.timestamp >= NOW() - {window_interval} \
               AND g.timestamp >= NOW() - {window_interval} \
               AND a.badges @> '[{{\"code\":\"guardrail\",\"action\":\"block\"}}]'::jsonb{ws_blocked} \
            )::bigint AS blocked"
    );
    let guardrail: (Option<i64>, Option<i64>) = {
        let mut q = sqlx::query_as(sqlx::AssertSqlSafe(&*guardrail_sql)).bind(tenant_id);
        if let Some(ref ws) = workspace_ids {
            q = q.bind(ws.clone());
        }
        q.fetch_one(db.conn()).await
    }
    .map_err(|e| {
        tracing::error!("cross attention guardrail: {e}");
        ApiError::internal("database query failed")
    })?;

    // 3. Expiring credentials — union of api_keys and mcp_user_credentials.
    //    Both have indexes on (expires_at WHERE expires_at IS NOT NULL).
    //    The "expired" bucket counts rows already past expiry but not yet
    //    revoked, so they still show up as live credentials to the user.
    // `mcp_user_credentials` carry no workspace dimension, so a workspace scope
    // narrows the tile to that workspace's expiring `api_keys` only.
    let ws_keys = if workspace_ids.is_some() { " AND k.workspace_id = ANY($2)" } else { "" };
    let mcp_union = if workspace_ids.is_some() {
        String::new()
    } else {
        format!(
            " UNION ALL \
            SELECT mc.expires_at \
            FROM mcp_user_credentials mc \
            WHERE mc.tenant_id = $1 \
              AND mc.expires_at IS NOT NULL \
              AND mc.expires_at < NOW() + {expiry_sql}"
        )
    };
    let expiring_sql = format!(
        "WITH all_expiring AS ( \
            SELECT k.expires_at \
            FROM api_keys k \
            WHERE k.tenant_id = $1 \
              AND k.revoked_at IS NULL \
              AND k.expires_at IS NOT NULL \
              AND k.expires_at < NOW() + {expiry_sql}{ws_keys}{mcp_union} \
        ) \
        SELECT \
            COUNT(*)::bigint AS total, \
            COUNT(*) FILTER (WHERE expires_at <= NOW())::bigint AS expired, \
            COUNT(*) FILTER (WHERE expires_at > NOW() AND expires_at < NOW() + INTERVAL '24 hours')::bigint AS lt_24h, \
            COUNT(*)::bigint AS lt_7d \
         FROM all_expiring"
    );
    let expiring: (Option<i64>, Option<i64>, Option<i64>, Option<i64>) = {
        let mut q = sqlx::query_as(sqlx::AssertSqlSafe(&*expiring_sql)).bind(tenant_id);
        if let Some(ref ws) = workspace_ids {
            q = q.bind(ws.clone());
        }
        q.fetch_one(db.conn()).await
    }
    .map_err(|e| {
        tracing::error!("cross attention expiring: {e}");
        ApiError::internal("database query failed")
    })?;

    // 4. Errors — any gateway_audit row with a populated error_category in
    //    the window, regardless of HTTP status. Covers upstream errors, auth
    //    failures (MCP-side only — LLM 401s bypass audit pre-tenant-context),
    //    rate limits, timeouts, internal failures, etc. Broader than the
    //    Recent Errors feed below (which lists only the last 8 by time):
    //    this tile is the operator's "is anything wrong right now" counter
    //    with a click-through to the filtered audit list.
    let errors_sql = format!(
        "SELECT \
            COUNT(*)::bigint AS total, \
            ( \
                SELECT error_category FROM gateway_audit \
                WHERE tenant_id = $1 \
                  AND error_category IS NOT NULL \
                  AND timestamp >= NOW() - {window_interval}{ws_errors} \
                GROUP BY error_category \
                ORDER BY COUNT(*) DESC, error_category \
                LIMIT 1 \
            ) AS top_error_category \
         FROM gateway_audit \
         WHERE tenant_id = $1 \
           AND error_category IS NOT NULL \
           AND timestamp >= NOW() - {window_interval}{ws_errors}"
    );
    let errors: (Option<i64>, Option<String>) = {
        let mut q = sqlx::query_as(sqlx::AssertSqlSafe(&*errors_sql)).bind(tenant_id);
        if let Some(ref ws) = workspace_ids {
            q = q.bind(ws.clone());
        }
        q.fetch_one(db.conn()).await
    }
    .map_err(|e| {
        tracing::error!("cross attention errors: {e}");
        ApiError::internal("database query failed")
    })?;

    // 5. Budget — scopes at/over (or approaching) their cap in the *current*
    //    daily/monthly window, via the shared evaluator (same query that backs
    //    the proactive-alert producer). Per-scope rows fold into the tile's
    //    breached / approaching counts + worst-offender subtitle.
    let budget = match evaluate_budget_scopes(db.conn(), tenant_id, budget_workspace_id).await {
        Ok(scopes) => {
            let breached = scopes.iter().filter(|s| s.band() == 2).count() as i64;
            let approaching = scopes.iter().filter(|s| s.band() == 1).count() as i64;
            let worst = scopes.iter().max_by(|a, b| {
                a.ratio()
                    .partial_cmp(&b.ratio())
                    .unwrap_or(std::cmp::Ordering::Equal)
            });
            AttentionBudget {
                breached,
                approaching,
                worst_ratio: worst.map(|s| s.ratio()),
                worst_scope_kind: worst.map(|s| s.scope_kind.clone()),
                worst_scope_id: worst.map(|s| s.scope_id),
                worst_workspace_id: worst.map(|s| s.workspace_id).filter(|w| !w.is_nil()),
            }
        }
        Err(e) => {
            tracing::error!("cross attention budget: {e}");
            AttentionBudget {
                breached: 0,
                approaching: 0,
                worst_ratio: None,
                worst_scope_kind: None,
                worst_scope_id: None,
                worst_workspace_id: None,
            }
        }
    };

    // 6. Upstreams — the servers' health NOW (the same out-of-rotation reading
    //    as the server list and the server dashboard), and the gate refusals in
    //    the window. Health is tenant-wide: a server serves every workspace.
    let health_sql = format!(
        "SELECT s.id, s.enabled, {} FROM upstream_servers s WHERE s.enabled",
        crate::routes::upstream_endpoints::server_health_columns_sql()
    );
    let servers: Vec<(Uuid, bool, i64, i64, i64)> = sqlx::query_as(sqlx::AssertSqlSafe(&*health_sql))
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("cross attention upstream health: {e}");
            ApiError::internal("database query failed")
        })?;
    // Every refusal a server's pool gave — the ones the Servers view counts —
    // including each one a request moved on from: a saturated server whose
    // every alias has a fallback refuses as much as one without, and it is
    // exactly there that nothing else shows it. Both halves read a partial
    // index of the rare rows they count.
    let refused_sql = format!(
        "SELECT (SELECT COUNT(*) FROM llm_audit \
                  WHERE tenant_id = $1 AND gate_refusal IS NOT NULL AND upstream_server_id IS NOT NULL \
                    AND timestamp >= NOW() - {window_interval}{ws_errors}) \
              + (SELECT COUNT(*) FROM llm_audit \
                  CROSS JOIN LATERAL jsonb_to_recordset(moved_on_from) AS m(server_id uuid, outcome text) \
                  WHERE tenant_id = $1 AND moved_on_from IS NOT NULL AND m.outcome = 'refused' \
                    AND m.server_id IS NOT NULL \
                    AND timestamp >= NOW() - {window_interval}{ws_errors})"
    );
    let refused: i64 = {
        let mut q = sqlx::query_scalar(sqlx::AssertSqlSafe(&*refused_sql)).bind(tenant_id);
        if let Some(ref ws) = workspace_ids {
            q = q.bind(ws.clone());
        }
        q.fetch_one(db.conn()).await
    }
    .map_err(|e| {
        tracing::error!("cross attention refusals: {e}");
        ApiError::internal("database query failed")
    })?;
    let (live, _) = crate::routes::server_analytics::summarize_live(
        &crate::routes::server_analytics::latest_load(db, None).await?,
    );
    let upstreams = {
        use crate::routes::upstream_endpoints::ServerHealth;
        let health: Vec<(Uuid, ServerHealth)> = servers
            .iter()
            .map(|(id, enabled, endpoints, down, out)| (*id, ServerHealth::of(*enabled, *endpoints, *down, *out)))
            .collect();
        let down: Vec<Uuid> =
            health.iter().filter(|(_, h)| *h == ServerHealth::Down).map(|(id, _)| *id).collect();
        AttentionUpstreams {
            servers_total: i64::try_from(servers.len()).unwrap_or(i64::MAX),
            degraded: health.iter().filter(|(_, h)| *h == ServerHealth::Degraded).count() as i64,
            down: down.len() as i64,
            down_server_id: match down.as_slice() {
                [only] => Some(*only),
                _ => None,
            },
            refused,
            engines_silent: live.values().map(|s| s.engines_silent).sum(),
        }
    };

    Ok(AttentionResponse {
        alerts: AttentionAlerts {
            total: alerts.0.unwrap_or(0),
            major: alerts.1.unwrap_or(0),
            minor: alerts.2.unwrap_or(0),
        },
        blocked: AttentionBlocked {
            total: blocked.0.unwrap_or(0),
            top_rule_id: blocked.1,
        },
        guardrail: AttentionGuardrail {
            total: guardrail.0.unwrap_or(0),
            blocked: guardrail.1.unwrap_or(0),
        },
        expiring: AttentionExpiring {
            total: expiring.0.unwrap_or(0),
            expired: expiring.1.unwrap_or(0),
            lt_24h: expiring.2.unwrap_or(0),
            lt_7d: expiring.3.unwrap_or(0),
        },
        errors: AttentionErrors {
            total: errors.0.unwrap_or(0),
            top_error_category: errors.1,
        },
        budget,
        upstreams,
        generated_at: Utc::now(),
        window_days,
        expiry_window_days,
    })
}

/// Render a day count as a SQL `INTERVAL` literal.
///
/// Postgres will not accept a bind parameter inside an `INTERVAL '…'` literal, so
/// the day count is the one request-derived value in this file that reaches the SQL
/// as text rather than as a bound `$N`. Taking `i32` is what makes that safe, and it
/// is the whole point of this function existing: an `i32`'s `Display` can emit only
/// digits and a leading `-`, so no caller — however careless — can smuggle SQL
/// through it. Keep the parameter an integer; never widen it to `&str` / `String`
/// (a "30 days" or "1 week" string would be a straight injection). Callers clamp the
/// value to a sane range separately; that is a product concern, not a safety one.
fn interval_days(days: i32) -> String {
    format!("INTERVAL '{days} days'")
}
