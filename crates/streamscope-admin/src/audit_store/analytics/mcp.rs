//! The MCP gateway dashboard: its metric cards, top-N panels, time series and
//! errors by method, over `mcp_audit` joined to its `gateway_audit` row.

use std::collections::HashMap;

use chrono::{DateTime, Timelike, Utc};
use uuid::Uuid;

use crate::audit_store::filters::{MCP_AUDIT_WINDOW, AnalyticsFilterBuilder, window_sql};
use crate::db::tenant::Scoped;
use crate::routes::{ApiError, parse_workspace_ids};
use crate::routes::analytics::{
    DEFAULT_USAGE_DAYS, DashboardSortBy, McpDashboardPanel, McpDashboardQuery,
    McpDashboardSummary, McpDashboardSummaryPrevious, McpErrorsByMethodResponse,
    McpErrorsByMethodRow, McpInvocationCount, McpTimeseriesBucket, McpTimeseriesResponse,
};

/// The MCP dashboard's metric cards over the window, each with the previous
/// window of the same length beside it.
pub(crate) async fn mcp_dashboard_summary(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &McpDashboardQuery,
) -> Result<McpDashboardSummary, ApiError> {
    let prev_duration = end - start;
    let prev_start = start - prev_duration;
    let prev_end = start;

    // Single query computes both periods using FILTER (WHERE …) on each
    // aggregate. The outer WHERE narrows to the union of both windows, on both
    // facts, so each prunes its partitions. RLS scopes to tenant on both tables.
    let mut sql = format!(
        "SELECT \
            COUNT(*) FILTER (WHERE timestamp >= $1 AND timestamp < $2)::BIGINT AS calls, \
            COUNT(DISTINCT m.mcp_session_id) FILTER ( \
                WHERE timestamp >= $1 AND timestamp < $2 AND m.mcp_session_id IS NOT NULL \
            )::BIGINT AS sessions, \
            COUNT(*) FILTER ( \
                WHERE timestamp >= $1 AND timestamp < $2 AND m.method = 'tools/call' \
            )::BIGINT AS tool_calls, \
            COUNT(*) FILTER ( \
                WHERE timestamp >= $1 AND timestamp < $2 \
                  AND (g.status_code >= 400 OR m.error_code IS NOT NULL) \
            )::BIGINT AS errors, \
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY g.latency_total_ms) \
                FILTER (WHERE timestamp >= $1 AND timestamp < $2) AS p50_latency_ms, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) \
                FILTER (WHERE timestamp >= $1 AND timestamp < $2) AS p95_latency_ms, \
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY g.latency_total_ms) \
                FILTER (WHERE timestamp >= $1 AND timestamp < $2) AS p99_latency_ms, \
            COUNT(DISTINCT g.user_id) FILTER ( \
                WHERE timestamp >= $1 AND timestamp < $2 AND g.user_id IS NOT NULL \
            )::BIGINT AS unique_users, \
            COUNT(*) FILTER (WHERE timestamp >= $3 AND timestamp < $4)::BIGINT AS prev_calls, \
            COUNT(DISTINCT m.mcp_session_id) FILTER ( \
                WHERE timestamp >= $3 AND timestamp < $4 AND m.mcp_session_id IS NOT NULL \
            )::BIGINT AS prev_sessions, \
            COUNT(*) FILTER ( \
                WHERE timestamp >= $3 AND timestamp < $4 AND m.method = 'tools/call' \
            )::BIGINT AS prev_tool_calls, \
            COUNT(*) FILTER ( \
                WHERE timestamp >= $3 AND timestamp < $4 \
                  AND (g.status_code >= 400 OR m.error_code IS NOT NULL) \
            )::BIGINT AS prev_errors, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) \
                FILTER (WHERE timestamp >= $3 AND timestamp < $4) AS prev_p95_latency_ms \
         FROM {join} \
         WHERE TRUE{window}",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
        window = window_sql(MCP_AUDIT_WINDOW, 3, 2),
    );
    let filters = scope_filters(query, 5);
    sql.push_str(filters.where_sql());

    let q = sqlx::query_as::<_, McpSummaryRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(start)
        .bind(end)
        .bind(prev_start)
        .bind(prev_end);
    let row = filters.apply_query_as(q).fetch_one(&mut *conn).await.map_err(|e| {
        tracing::error!("mcp dashboard summary: {e}");
        ApiError::internal("failed to query MCP dashboard summary")
    })?;

    // Live tokens — snapshot, not period-scoped.
    let live_tokens: (Option<i64>,) = sqlx::query_as(
        "SELECT COUNT(*)::BIGINT FROM oauth_issued_tokens \
         WHERE surface = 'mcp' AND revoked_at IS NULL AND expires_at > NOW()",
    )
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("mcp dashboard live_tokens: {e}");
        ApiError::internal("failed to query live tokens")
    })?;

    Ok(McpDashboardSummary {
        calls: row.calls.unwrap_or(0),
        sessions: row.sessions.unwrap_or(0),
        tool_calls: row.tool_calls.unwrap_or(0),
        errors: row.errors.unwrap_or(0),
        p50_latency_ms: row.p50_latency_ms.unwrap_or(0.0),
        p95_latency_ms: row.p95_latency_ms.unwrap_or(0.0),
        p99_latency_ms: row.p99_latency_ms.unwrap_or(0.0),
        unique_users: row.unique_users.unwrap_or(0),
        live_tokens: live_tokens.0.unwrap_or(0),
        previous: McpDashboardSummaryPrevious {
            calls: row.prev_calls.unwrap_or(0),
            sessions: row.prev_sessions.unwrap_or(0),
            tool_calls: row.prev_tool_calls.unwrap_or(0),
            errors: row.prev_errors.unwrap_or(0),
            p95_latency_ms: row.prev_p95_latency_ms.unwrap_or(0.0),
        },
    })
}

/// MCP calls of the window per hour (a window of a day or less) or per day.
pub(crate) async fn mcp_dashboard_timeseries(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &McpDashboardQuery,
) -> Result<McpTimeseriesResponse, ApiError> {
    let bucket_hourly = (end - start) <= chrono::Duration::days(1);
    let trunc = if bucket_hourly { "hour" } else { "day" };

    // The shared filter clause, built once. RLS scopes the tenant; the window
    // is $1/$2, the scope filters follow.
    let filters = scope_filters(query, 3);
    let filter = filters.where_sql();

    // Step 0: zero-fill the bucket axis so a tenant with one or two calls in
    // a wide window still produces a renderable chart. We pre-compute the
    // full set of `bucket_ts` covering [start, end), then merge in the per-
    // bucket aggregates client-side. (Same pattern the LLM `usage_timeseries`
    // endpoint uses — but here we keep it in Rust so we don't have to thread
    // the `bind`s through a CTE.)
    let mut all_buckets: Vec<chrono::DateTime<chrono::Utc>> = Vec::new();
    let mut t = match if bucket_hourly {
        start
            .with_minute(0)
            .and_then(|d| d.with_second(0))
            .and_then(|d| d.with_nanosecond(0))
    } else {
        start
            .with_hour(0)
            .and_then(|d| d.with_minute(0))
            .and_then(|d| d.with_second(0))
            .and_then(|d| d.with_nanosecond(0))
    } {
        Some(d) => d,
        None => start,
    };
    let step = if bucket_hourly {
        chrono::Duration::hours(1)
    } else {
        chrono::Duration::days(1)
    };
    while t < end {
        all_buckets.push(t);
        t += step;
    }

    // Q1: counts per (bucket, method).
    let counts_sql = format!(
        "SELECT date_trunc('{trunc}', timestamp) AS bucket_ts, \
                m.method AS method, \
                COUNT(*)::BIGINT AS method_count \
         FROM {join} \
         WHERE TRUE{window}{filter} \
         GROUP BY bucket_ts, m.method \
         ORDER BY bucket_ts",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
        window = window_sql(MCP_AUDIT_WINDOW, 1, 2),
    );
    let cq = sqlx::query_as::<_, McpTimeseriesCountsRow>(sqlx::AssertSqlSafe(&*counts_sql))
        .bind(start)
        .bind(end);
    let count_rows = filters.apply_query_as(cq).fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("mcp dashboard timeseries (counts): {e}");
        ApiError::internal("failed to query MCP timeseries counts")
    })?;

    // Q2: per-bucket latency percentiles for both gateway and upstream.
    let latency_sql = format!(
        "SELECT date_trunc('{trunc}', timestamp) AS bucket_ts, \
                PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY g.latency_total_ms)    AS g_p50, \
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms)    AS g_p95, \
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY g.latency_total_ms)    AS g_p99, \
                PERCENTILE_CONT(0.5)  WITHIN GROUP (ORDER BY m.upstream_latency_ms) AS up_p50, \
                PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY m.upstream_latency_ms) AS up_p95, \
                PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY m.upstream_latency_ms) AS up_p99 \
         FROM {join} \
         WHERE TRUE{window}{filter} \
         GROUP BY bucket_ts \
         ORDER BY bucket_ts",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
        window = window_sql(MCP_AUDIT_WINDOW, 1, 2),
    );
    let lq = sqlx::query_as::<_, McpTimeseriesLatencyRow>(sqlx::AssertSqlSafe(&*latency_sql))
        .bind(start)
        .bind(end);
    let latency_rows = filters.apply_query_as(lq).fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("mcp dashboard timeseries (latency): {e}");
        ApiError::internal("failed to query MCP timeseries latency")
    })?;

    // Seed the bucket map with zeroed entries for every tick in the window
    // — the LEFT-JOIN-style merge below fills in real values where present.
    let mut by_bucket: std::collections::BTreeMap<chrono::DateTime<chrono::Utc>, McpTimeseriesBucket> =
        std::collections::BTreeMap::new();
    for ts in all_buckets {
        by_bucket.insert(
            ts,
            McpTimeseriesBucket {
                timestamp: ts,
                call_count: 0,
                by_method: HashMap::new(),
                gateway_p50_ms: 0.0,
                gateway_p95_ms: 0.0,
                gateway_p99_ms: 0.0,
                upstream_p50_ms: 0.0,
                upstream_p95_ms: 0.0,
                upstream_p99_ms: 0.0,
            },
        );
    }
    for row in count_rows {
        let entry = by_bucket
            .entry(row.bucket_ts)
            .or_insert_with(|| McpTimeseriesBucket {
                timestamp: row.bucket_ts,
                call_count: 0,
                by_method: HashMap::new(),
                gateway_p50_ms: 0.0,
                gateway_p95_ms: 0.0,
                gateway_p99_ms: 0.0,
                upstream_p50_ms: 0.0,
                upstream_p95_ms: 0.0,
                upstream_p99_ms: 0.0,
            });
        entry.call_count += row.method_count;
        entry.by_method.insert(row.method, row.method_count);
    }
    for row in latency_rows {
        let entry = by_bucket
            .entry(row.bucket_ts)
            .or_insert_with(|| McpTimeseriesBucket {
                timestamp: row.bucket_ts,
                call_count: 0,
                by_method: HashMap::new(),
                gateway_p50_ms: 0.0,
                gateway_p95_ms: 0.0,
                gateway_p99_ms: 0.0,
                upstream_p50_ms: 0.0,
                upstream_p95_ms: 0.0,
                upstream_p99_ms: 0.0,
            });
        entry.gateway_p50_ms = row.g_p50.unwrap_or(0.0);
        entry.gateway_p95_ms = row.g_p95.unwrap_or(0.0);
        entry.gateway_p99_ms = row.g_p99.unwrap_or(0.0);
        entry.upstream_p50_ms = row.up_p50.unwrap_or(0.0);
        entry.upstream_p95_ms = row.up_p95.unwrap_or(0.0);
        entry.upstream_p99_ms = row.up_p99.unwrap_or(0.0);
    }

    Ok(McpTimeseriesResponse {
        interval: if bucket_hourly { "hour".to_string() } else { "day".to_string() },
        buckets: by_bucket.into_values().collect(),
    })
}

/// MCP errors of the window per method, with each method's commonest error
/// code.
pub(crate) async fn mcp_dashboard_errors_by_method(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &McpDashboardQuery,
) -> Result<McpErrorsByMethodResponse, ApiError> {
    let limit = query.resolved_limit();

    // MODE() within group picks the most common error_code per method. NULL
    // codes (HTTP-only errors) are kept in the count but excluded from MODE.
    let mut sql = format!(
        "SELECT m.method AS method, \
                COUNT(*)::BIGINT AS error_count, \
                MODE() WITHIN GROUP (ORDER BY m.error_code) AS top_error_code, \
                (SUM(COUNT(*)) OVER ())::BIGINT AS panel_total \
         FROM {join} \
         WHERE TRUE{window} \
           AND (g.status_code >= 400 OR m.error_code IS NOT NULL)",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
        window = window_sql(MCP_AUDIT_WINDOW, 1, 2),
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());
    let next_idx = filters.next_bind_idx();
    sql.push_str(&format!(
        " GROUP BY m.method ORDER BY error_count DESC, method LIMIT ${next_idx}"
    ));

    let q = sqlx::query_as::<_, McpErrorsRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(start)
        .bind(end);
    let q = filters.apply_query_as(q).bind(limit);

    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("mcp dashboard errors_by_method: {e}");
        ApiError::internal("failed to query MCP errors-by-method")
    })?;
    // Every method's errors, counted before the LIMIT; no row means none.
    let total_errors = rows.first().map_or(0, |r| r.panel_total);
    let items = rows.into_iter().map(|r| r.item).collect();

    Ok(McpErrorsByMethodResponse { items, total_errors })
}

/// The dashboard's scope filters — app, user, workspaces — bound from
/// `first_bind_idx`.
fn scope_filters(query: &McpDashboardQuery, first_bind_idx: u32) -> AnalyticsFilterBuilder {
    let mut f = AnalyticsFilterBuilder::new(first_bind_idx);
    let ws = parse_workspace_ids(&query.workspace_ids);
    f.push_scope(query.app_id.as_deref(), query.user_id, ws.as_deref());
    f
}

/// Whitelist of allowed pivot column expressions. Each entry includes its
/// table prefix (`m.` for `mcp_audit`, `g.` for `gateway_audit`). Strings
/// flow into raw `format!()` SQL and MUST never be operator-supplied.
fn allowed_pivot(s: &str) -> bool {
    matches!(
        s,
        "m.tool_id"
            | "m.prompt_id"
            | "m.resource_uri"
            | "m.virtual_server_id"
            | "m.upstream_server_id"
            | "m.method"
            | "g.user_id"
            | "g.app_id"
    )
}

fn allowed_method(s: &str) -> bool {
    matches!(
        s,
        "initialize"
            | "tools/list"
            | "tools/call"
            | "resources/list"
            | "resources/read"
            | "prompts/list"
            | "prompts/get"
            | "sampling/createMessage"
            | "elicitation/create"
    )
}

/// Generic top-N MCP panel builder. Pivots on `pivot_column`, optionally
/// filters by JSON-RPC `method`, and applies the standard `app_id`/`user_id`
/// scope filters. Returns one `McpInvocationCount` per distinct pivot value,
/// sorted by `query.sort_by`.
pub(crate) async fn mcp_dashboard_panel(
    conn: &mut Scoped,
    query: &McpDashboardQuery,
    pivot_column: &'static str,
    method_filter: Option<&'static str>,
) -> Result<McpDashboardPanel, ApiError> {
    // `pivot_column` / `method_filter` are `&'static str`, so no request byte can
    // reach them — these guard against a bad *literal* introduced by a future
    // caller. Fail closed rather than assert: the guard has to hold in release
    // (that is the build e2e and prod run), and the admin binary carries no
    // catch-panic layer, so a fired assert would drop the connection instead of
    // answering. A 500 on the first dashboard render is loud enough.
    if !allowed_pivot(pivot_column) {
        tracing::error!("mcp_dashboard_panel: unknown pivot column {pivot_column}");
        return Err(ApiError::internal("internal error"));
    }
    if let Some(m) = method_filter
        && !allowed_method(m)
    {
        tracing::error!("mcp_dashboard_panel: unknown method filter {m}");
        return Err(ApiError::internal("internal error"));
    }

    let (start, end) = query.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let limit = query.resolved_limit();
    let sort_by = query.sort_by.unwrap_or_default();

    // For the user pivot, render the email / display name instead of the raw
    // UUID — same convention as `/analytics/breakdown?group_by=user`. Other
    // pivots already produce human-readable strings (tool_id, prompt_id,
    // resource_uri) or are resolved client-side (virtual_server_id,
    // upstream_server_id).
    let is_user_pivot = pivot_column == "g.user_id";
    let (key_select, user_join, group_by_clause) = if is_user_pivot {
        (
            // `user_email` / `user_id` are the deep-link payload; `key` stays
            // the human-readable display.
            "COALESCE(u.display_name, u.email, g.user_id::TEXT) AS key, \
             u.email AS user_email, \
             g.user_id AS user_id".to_string(),
            " LEFT JOIN users u ON u.id = g.user_id",
            "GROUP BY u.display_name, u.email, g.user_id".to_string(),
        )
    } else {
        (
            format!("({pivot_column})::TEXT AS key, NULL::TEXT AS user_email, NULL::UUID AS user_id"),
            "",
            format!("GROUP BY ({pivot_column})::TEXT"),
        )
    };
    // Window-function `panel_total` carries the unfiltered (pre-LIMIT) count
    // of grouped rows on every result row, so a single scan answers both the
    // top-N list and "N of M". Saves one round-trip per panel — material at
    // 9 concurrent panels per dashboard refresh.
    let mut sql = format!(
        "SELECT \
            {key_select}, \
            COUNT(*)::BIGINT AS call_count, \
            COUNT(DISTINCT m.virtual_server_id)::BIGINT AS virtual_server_count, \
            COUNT(DISTINCT g.user_id)::BIGINT AS user_count, \
            MAX(timestamp) AS last_used, \
            COUNT(*) FILTER ( \
                WHERE g.status_code >= 400 OR m.error_code IS NOT NULL \
            )::BIGINT AS error_count, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            (SUM(COUNT(*)) OVER ())::BIGINT AS panel_total \
         FROM {join}{user_join} \
         WHERE TRUE{window} \
           AND {pivot_column} IS NOT NULL",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
        window = window_sql(MCP_AUDIT_WINDOW, 1, 2),
    );
    let mut filters = scope_filters(query, 3);
    if let Some(m) = method_filter {
        filters.push_eq_str("m.method", m);
    }
    sql.push_str(filters.where_sql());
    let next_idx = filters.next_bind_idx();
    let order_clause = match sort_by {
        DashboardSortBy::Count => "ORDER BY call_count DESC, key, user_id",
        DashboardSortBy::P95 => "ORDER BY p95_latency_ms DESC NULLS LAST, key, user_id",
    };
    sql.push_str(&format!(
        " {group_by_clause} \
          {order_clause} \
          LIMIT ${next_idx}",
    ));

    let q = sqlx::query_as::<_, McpInvocationCountRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(start)
        .bind(end);
    let q = filters.apply_query_as(q).bind(limit);

    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("mcp dashboard panel ({pivot_column}/{method_filter:?}): {e}");
        ApiError::internal("failed to query MCP dashboard panel")
    })?;

    // `panel_total` is constant across all rows; pull it from the first.
    // Empty result → no rows match the filter, so the total is 0.
    let total_calls = rows.first().map(|r| r.panel_total).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|r| McpInvocationCount {
            key: r.key,
            call_count: r.call_count,
            virtual_server_count: r.virtual_server_count,
            user_count: r.user_count,
            last_used: r.last_used,
            error_count: r.error_count,
            p95_latency_ms: r.p95_latency_ms,
            user_email: r.user_email,
            user_id: r.user_id,
        })
        .collect();

    Ok(McpDashboardPanel {
        items,
        total_calls,
    })
}

/// Internal row shape for `mcp_dashboard_panel` — adds `panel_total` carried
/// through the window function so we can compute the totals in the same scan
/// instead of issuing a second `COUNT(*)` query (saves one round trip per
/// panel × 9 panels per dashboard refresh).
#[derive(sqlx::FromRow)]
struct McpInvocationCountRow {
    key: String,
    call_count: i64,
    virtual_server_count: i64,
    user_count: i64,
    last_used: chrono::DateTime<chrono::Utc>,
    error_count: i64,
    p95_latency_ms: Option<f64>,
    panel_total: i64,
    /// Populated only when the panel pivots on `g.user_id`; NULL otherwise.
    #[sqlx(default)]
    user_email: Option<String>,
    /// Populated only when the panel pivots on `g.user_id`; NULL otherwise.
    #[sqlx(default)]
    user_id: Option<Uuid>,
}

/// A row of `mcp_dashboard_errors_by_method`, with the window's error total
/// carried on every row.
#[derive(sqlx::FromRow)]
struct McpErrorsRow {
    #[sqlx(flatten)]
    item: McpErrorsByMethodRow,
    panel_total: i64,
}

#[derive(sqlx::FromRow)]
struct McpSummaryRow {
    calls: Option<i64>,
    sessions: Option<i64>,
    tool_calls: Option<i64>,
    errors: Option<i64>,
    p50_latency_ms: Option<f64>,
    p95_latency_ms: Option<f64>,
    p99_latency_ms: Option<f64>,
    unique_users: Option<i64>,
    prev_calls: Option<i64>,
    prev_sessions: Option<i64>,
    prev_tool_calls: Option<i64>,
    prev_errors: Option<i64>,
    prev_p95_latency_ms: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct McpTimeseriesCountsRow {
    bucket_ts: chrono::DateTime<chrono::Utc>,
    method: String,
    method_count: i64,
}

#[derive(sqlx::FromRow)]
struct McpTimeseriesLatencyRow {
    bucket_ts: chrono::DateTime<chrono::Utc>,
    g_p50: Option<f64>,
    g_p95: Option<f64>,
    g_p99: Option<f64>,
    up_p50: Option<f64>,
    up_p95: Option<f64>,
    up_p99: Option<f64>,
}
