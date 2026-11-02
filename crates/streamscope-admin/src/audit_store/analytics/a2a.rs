//! The A2A gateway dashboard, over `a2a_audit` joined to its `gateway_audit`
//! row.

use chrono::{DateTime, Utc};

use crate::audit_store::filters::{A2A_AUDIT_WINDOW, AnalyticsFilterBuilder, window_sql};
use crate::db::tenant::Scoped;
use crate::routes::{ApiError, parse_workspace_ids};
use crate::routes::analytics::{
    A2aBreakdownItem, A2aDashboardPanel, A2aDashboardQuery, A2aDashboardSummary,
    DEFAULT_USAGE_DAYS,
};

/// The A2A dashboard's metric cards over the window.
pub(crate) async fn a2a_dashboard_summary(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &A2aDashboardQuery,
) -> Result<A2aDashboardSummary, ApiError> {
    let mut sql = format!(
        "SELECT \
            COUNT(*)::BIGINT AS calls, \
            COUNT(DISTINCT a2.agent_id)::BIGINT AS agents, \
            COUNT(DISTINCT a2.a2a_task_id)::BIGINT AS tasks, \
            COUNT(DISTINCT a2.a2a_context_id)::BIGINT AS contexts, \
            COUNT(DISTINCT g.user_id) FILTER (WHERE g.user_id IS NOT NULL)::BIGINT AS unique_users, \
            COUNT(*) FILTER (WHERE {errors})::BIGINT AS errors, \
            COUNT(*) FILTER (WHERE {blocked})::BIGINT AS blocked, \
            COUNT(*) FILTER (WHERE {guardrail})::BIGINT AS guardrail_flagged, \
            COUNT(*) FILTER ( \
                WHERE a2.method IN ('SendStreamingMessage', 'SubscribeToTask') \
            )::BIGINT AS streamed, \
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p50_latency_ms, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p99_latency_ms \
         FROM {join} \
         WHERE TRUE{window}",
        join = crate::audit_store::filters::A2A_AUDIT_JOIN,
        window = window_sql(A2A_AUDIT_WINDOW, 1, 2),
        errors = A2A_ERROR_PREDICATE,
        blocked = A2A_BLOCKED_PREDICATE,
        guardrail = crate::audit_store::guardrail::guardrail_badge_predicate("a2"),
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());

    let q = sqlx::query_as::<_, A2aSummaryRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(start)
        .bind(end);
    let row = filters.apply_query_as(q)
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("a2a dashboard summary: {e}");
            ApiError::internal("failed to query A2A dashboard summary")
        })?;

    Ok(A2aDashboardSummary {
        calls: row.calls.unwrap_or(0),
        agents: row.agents.unwrap_or(0),
        tasks: row.tasks.unwrap_or(0),
        contexts: row.contexts.unwrap_or(0),
        unique_users: row.unique_users.unwrap_or(0),
        errors: row.errors.unwrap_or(0),
        blocked: row.blocked.unwrap_or(0),
        guardrail_flagged: row.guardrail_flagged.unwrap_or(0),
        streamed: row.streamed.unwrap_or(0),
        p50_latency_ms: row.p50_latency_ms.unwrap_or(0.0),
        p95_latency_ms: row.p95_latency_ms.unwrap_or(0.0),
        p99_latency_ms: row.p99_latency_ms.unwrap_or(0.0),
    })
}

/// The pivots an A2A panel may group by. `&'static str` + an allowlist: no
/// request byte reaches the SQL, and a future caller's typo fails closed.
fn a2a_allowed_pivot(s: &str) -> bool {
    matches!(
        s,
        "ag.slug" | "a2.method" | "a2.task_state" | "g.user_id" | "g.app_id"
    )
}

/// The dashboard's scope filters — app, user, workspaces — bound from
/// `first_bind_idx`.
fn scope_filters(query: &A2aDashboardQuery, first_bind_idx: u32) -> AnalyticsFilterBuilder {
    let mut f = AnalyticsFilterBuilder::new(first_bind_idx);
    let ws = parse_workspace_ids(&query.workspace_ids);
    f.push_scope(query.app_id.as_deref(), query.user_id, ws.as_deref());
    f
}

/// Generic top-N A2A panel. Pivots on `pivot_column` (a compile-time constant,
/// allowlisted above), applies the standard scope filters, and carries the
/// pre-LIMIT total on every row so one scan answers both the list and its
/// denominator.
pub(crate) async fn a2a_dashboard_panel(
    conn: &mut Scoped,
    query: &A2aDashboardQuery,
    pivot_column: &'static str,
) -> Result<A2aDashboardPanel, ApiError> {
    if !a2a_allowed_pivot(pivot_column) {
        // Fail closed rather than assert: the admin binary catches no panic, so a
        // fired assert would drop the connection instead of answering.
        tracing::error!("a2a_dashboard_panel: unknown pivot column {pivot_column}");
        return Err(ApiError::internal("internal error"));
    }
    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let limit = query.resolved_limit();

    // The user pivot renders a name, not a UUID — same convention as every other
    // breakdown.
    let is_user_pivot = pivot_column == "g.user_id";
    let (key_select, group_by) = if is_user_pivot {
        (
            "COALESCE(u.display_name, u.email, g.user_id::TEXT) AS key, \
             g.user_id::TEXT AS filter_id"
                .to_string(),
            "GROUP BY u.display_name, u.email, g.user_id".to_string(),
        )
    } else {
        (
            format!("({pivot_column})::TEXT AS key, NULL::TEXT AS filter_id"),
            format!("GROUP BY ({pivot_column})::TEXT"),
        )
    };

    let mut sql = format!(
        "SELECT \
            {key_select}, \
            COUNT(*)::BIGINT AS call_count, \
            COUNT(*) FILTER (WHERE {errors})::BIGINT AS error_count, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            MAX(timestamp) AS last_used, \
            (SUM(COUNT(*)) OVER ())::BIGINT AS panel_total \
         FROM {join} \
         LEFT JOIN a2a_upstream_agents ag ON ag.id = a2.agent_id \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE TRUE{window} \
           AND {pivot_column} IS NOT NULL",
        join = crate::audit_store::filters::A2A_AUDIT_JOIN,
        window = window_sql(A2A_AUDIT_WINDOW, 1, 2),
        errors = A2A_ERROR_PREDICATE,
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());
    let next_idx = filters.next_bind_idx();
    sql.push_str(&format!(
        " {group_by} ORDER BY call_count DESC, key, filter_id LIMIT ${next_idx}"
    ));

    let q = sqlx::query_as::<_, A2aPanelRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(start)
        .bind(end);
    let rows = filters.apply_query_as(q)
        .bind(limit)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("a2a dashboard panel ({pivot_column}): {e}");
            ApiError::internal("failed to query A2A dashboard panel")
        })?;

    let total_calls = rows.first().map(|r| r.panel_total).unwrap_or(0);
    Ok(A2aDashboardPanel {
        items: rows
            .into_iter()
            .map(|r| A2aBreakdownItem {
                key: r.key,
                filter_id: r.filter_id,
                call_count: r.call_count,
                error_count: r.error_count,
                p95_latency_ms: r.p95_latency_ms,
                last_used: r.last_used,
            })
            .collect(),
        total_calls,
    })
}

/// A call that failed, whichever layer failed it. Kept as one predicate so the
/// summary, the panels, and the timeseries can never disagree on what an error is.
const A2A_ERROR_PREDICATE: &str = "(g.status_code >= 400 OR a2.error_code IS NOT NULL)";

/// Tool policy refused the call — the same `tool_blocked` chip the LLM and MCP
/// paths stamp.
const A2A_BLOCKED_PREDICATE: &str = "a2.badges @> '[{\"code\":\"tool_blocked\"}]'::jsonb";

#[derive(sqlx::FromRow)]
struct A2aSummaryRow {
    calls: Option<i64>,
    agents: Option<i64>,
    tasks: Option<i64>,
    contexts: Option<i64>,
    unique_users: Option<i64>,
    errors: Option<i64>,
    blocked: Option<i64>,
    guardrail_flagged: Option<i64>,
    streamed: Option<i64>,
    p50_latency_ms: Option<f64>,
    p95_latency_ms: Option<f64>,
    p99_latency_ms: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct A2aPanelRow {
    key: String,
    filter_id: Option<String>,
    call_count: i64,
    error_count: i64,
    p95_latency_ms: Option<f64>,
    last_used: chrono::DateTime<chrono::Utc>,
    panel_total: i64,
}
