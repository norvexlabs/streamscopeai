//! Usage totals over `gateway_audit ⋈ llm_audit`: per key, per user, the
//! portal's own-or-workspace view, a workspace's members, and the agent's own
//! traffic. Every read states its window on both tables
//! (`filters::AUDIT_LOG_WINDOW`).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::tenant::Scoped;
use crate::routes::portal::PortalDataScope;
use super::filters::{AUDIT_LOG_JOIN, AUDIT_LOG_WINDOW, AnalyticsFilterBuilder, window_sql};
use crate::routes::SPEND_TOTAL_COLUMNS;

type Window = (DateTime<Utc>, DateTime<Utc>);

/// One key's totals over the window, before the spend is denominated: the
/// caller needs `currency_count` to decide whether a zero needs the tenant's
/// fallback currency.
#[derive(sqlx::FromRow)]
pub(crate) struct KeyUsageTotals {
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub reasoning_tokens: i64,
    pub amount: f64,
    pub currency_count: i64,
    pub currency: Option<String>,
    pub avg_latency_ms: f64,
    pub last_used_at: Option<DateTime<Utc>>,
}

/// One key's totals over the window.
pub(crate) async fn key_usage(
    conn: &mut Scoped,
    key_id: Uuid,
    window: Window,
) -> sqlx::Result<KeyUsageTotals> {
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(AUDIT_LOG_WINDOW, window);
    let where_extra = filters.where_sql();

    let sql = format!(
        r#"SELECT
            COUNT(*)::bigint AS requests,
            COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
            COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
            COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
            COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
            COALESCE(SUM(reasoning_tokens), 0)::bigint AS reasoning_tokens,
            {SPEND_TOTAL_COLUMNS},
            COALESCE(AVG(latency_total_ms), 0.0)::double precision AS avg_latency_ms,
            MAX(timestamp) AS last_used_at
        FROM {AUDIT_LOG_JOIN}
        WHERE key_id = $1{where_extra}"#
    );

    // An aggregate with no GROUP BY answers exactly one row.
    filters
        .apply_query_as(sqlx::query_as::<_, KeyUsageTotals>(sqlx::AssertSqlSafe(&*sql)).bind(key_id))
        .fetch_one(&mut *conn)
        .await
}

/// A user's totals over the window, before the spend is denominated: the
/// caller needs `currency_count` to decide whether a zero needs the tenant's
/// fallback currency.
#[derive(sqlx::FromRow)]
pub(crate) struct UserUsageTotals {
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub reasoning_tokens: i64,
    pub amount: f64,
    pub currency_count: i64,
    pub currency: Option<String>,
    pub avg_latency_ms: f64,
}

/// One user's totals over the window, narrowed to `workspace_ids` when given.
pub(crate) async fn user_usage(
    conn: &mut Scoped,
    user_id: Uuid,
    window: Window,
    workspace_ids: Option<&[Uuid]>,
) -> sqlx::Result<UserUsageTotals> {
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(AUDIT_LOG_WINDOW, window);
    if let Some(ws) = workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let where_extra = filters.where_sql();

    let sql = format!(
        r#"SELECT
            COUNT(*)::bigint AS requests,
            COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens,
            COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens,
            COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
            COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens,
            COALESCE(SUM(reasoning_tokens), 0)::bigint AS reasoning_tokens,
            {SPEND_TOTAL_COLUMNS},
            COALESCE(AVG(latency_total_ms), 0.0)::double precision AS avg_latency_ms
        FROM {AUDIT_LOG_JOIN}
        WHERE user_id = $1{where_extra}"#
    );

    // An aggregate with no GROUP BY answers exactly one row.
    filters
        .apply_query_as(sqlx::query_as::<_, UserUsageTotals>(sqlx::AssertSqlSafe(&*sql)).bind(user_id))
        .fetch_one(&mut *conn)
        .await
}

/// The portal's figures for one scope, for one of its keys, or for one member
/// of a workspace.
#[derive(sqlx::FromRow)]
pub(crate) struct PortalUsage {
    pub requests: i64,
    pub tokens: i64,
    pub amount: f64,
    pub currency_count: i64,
    pub currency: Option<String>,
}

/// The portal's totals for one scope. `gateway_audit.workspace_id` is the issuing key's
/// workspace, so it confines an `ak-` key's totals.
///
/// The portal's usage figures — these totals, [`portal_daily`],
/// [`portal_per_key`] and [`workspace_member_usage`] — count one population: LLM requests (the ones
/// that carry tokens and cost), attributed to the workspace stamped on the
/// row. Keep them in step: the per-key rows sum to the part of these totals
/// made with the scope's live keys.
pub(crate) async fn portal_totals(
    conn: &mut Scoped,
    scope: &PortalDataScope,
    (start_ts, end_ts): Window,
) -> sqlx::Result<PortalUsage> {
    let sql = format!(
        r#"SELECT COUNT(*)::bigint AS requests,
                  COALESCE(SUM(prompt_tokens + completion_tokens), 0)::bigint AS tokens,
                  COALESCE(SUM(cost), 0.0)::float8 AS amount,
                  COUNT(DISTINCT a.cost_currency)::bigint AS currency_count,
                  MIN(a.cost_currency) AS currency
           FROM {AUDIT_LOG_JOIN}
           WHERE ($1::uuid IS NULL OR g.user_id = $1){window}
             AND ($4::uuid IS NULL OR g.workspace_id = $4)"#,
        window = window_sql(AUDIT_LOG_WINDOW, 2, 3),
    );
    sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
    .bind(scope.user_id())
    .bind(start_ts)
    .bind(end_ts)
    .bind(scope.workspace_id())
    .fetch_one(&mut *conn)
    .await
}

/// One UTC day of a scope's traffic, or (`day` = `None`) the whole window.
#[derive(sqlx::FromRow)]
pub(crate) struct PortalDayUsage {
    /// 00:00 UTC of the day; `None` on the window's total.
    pub day: Option<DateTime<Utc>>,
    pub requests: i64,
    pub amount: f64,
    pub currency_count: i64,
    pub currency: Option<String>,
}

/// The scope's LLM requests and spend per UTC day over the window, plus one
/// row (`day` = `None`) for the whole window — the same population as
/// [`portal_totals`], so the days sum to the total and the total's currency
/// count is exact (it is not derivable from the days' counts). Days without
/// traffic have no row.
///
/// Cost: the portal Home reads it with the caller's own scope over 7 days, so
/// it walks the caller's rows of that week on `gateway_audit (tenant_id,
/// user_id, timestamp)` and their `llm_audit` rows by key — one aggregate, no
/// other user's rows.
pub(crate) async fn portal_daily(
    conn: &mut Scoped,
    scope: &PortalDataScope,
    (start_ts, end_ts): Window,
) -> sqlx::Result<Vec<PortalDayUsage>> {
    let sql = format!(
        r#"SELECT date_trunc('day', g.timestamp, 'UTC') AS day,
                  COUNT(*)::bigint AS requests,
                  COALESCE(SUM(cost), 0.0)::float8 AS amount,
                  COUNT(DISTINCT a.cost_currency)::bigint AS currency_count,
                  MIN(a.cost_currency) AS currency
           FROM {AUDIT_LOG_JOIN}
           WHERE ($1::uuid IS NULL OR g.user_id = $1){window}
             AND ($4::uuid IS NULL OR g.workspace_id = $4)
           GROUP BY GROUPING SETS ((date_trunc('day', g.timestamp, 'UTC')), ())"#,
        window = window_sql(AUDIT_LOG_WINDOW, 2, 3),
    );
    sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
    .bind(scope.user_id())
    .bind(start_ts)
    .bind(end_ts)
    .bind(scope.workspace_id())
    .fetch_all(&mut *conn)
    .await
}

/// One live key of the scope with its traffic over the window.
#[derive(sqlx::FromRow)]
pub(crate) struct PortalKeyUsageRow {
    pub id: Uuid,
    pub key_prefix: String,
    pub name: Option<String>,
    pub workspace: String,
    #[sqlx(flatten)]
    pub usage: PortalUsage,
    pub last_used: Option<DateTime<Utc>>,
}

/// Every live key of the scope, busiest first — a key with no traffic in the
/// window is listed with zeros. `last_used` is the key's latest request of any
/// kind; the counts are its LLM requests, like the totals.
pub(crate) async fn portal_per_key(
    conn: &mut Scoped,
    scope: &PortalDataScope,
    (start_ts, end_ts): Window,
) -> sqlx::Result<Vec<PortalKeyUsageRow>> {
    let sql = format!(
        r#"SELECT k.id, k.key_prefix, k.name, w.name as workspace,
                  COUNT(a.request_id)::bigint as requests,
                  COALESCE(SUM(a.prompt_tokens + a.completion_tokens), 0)::bigint as tokens,
                  COALESCE(SUM(a.cost), 0.0)::float8 as amount,
                  COUNT(DISTINCT a.cost_currency)::bigint as currency_count,
                  MIN(a.cost_currency) as currency,
                  MAX(g.timestamp) as last_used
           FROM api_keys k
           LEFT JOIN gateway_audit g ON g.key_id = k.id{gateway_window}
           LEFT JOIN llm_audit a ON a.request_id = g.request_id AND a.timestamp = g.timestamp{llm_window}
           JOIN workspaces w ON w.id = k.workspace_id
           WHERE ($1::uuid IS NULL OR k.user_id = $1) AND k.revoked_at IS NULL
             AND ($4::uuid IS NULL OR k.workspace_id = $4)
           GROUP BY k.tenant_id, k.id, k.key_prefix, k.name, w.name
           ORDER BY requests DESC, k.id"#,
        gateway_window = window_sql(&["g.timestamp"], 2, 3),
        llm_window = window_sql(&["a.timestamp"], 2, 3),
    );
    sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
    .bind(scope.user_id())
    .bind(start_ts)
    .bind(end_ts)
    .bind(scope.workspace_id())
    .fetch_all(&mut *conn)
    .await
}

/// One member of a workspace with their traffic in it.
#[derive(sqlx::FromRow)]
pub(crate) struct WorkspaceMemberUsageRow {
    pub user_id: Uuid,
    pub email: String,
    #[sqlx(flatten)]
    pub usage: PortalUsage,
}

/// Each member of `workspace_id` with their traffic **in this workspace**
/// only (the workspace stamped on the row), busiest first; `exclude_email`
/// (the internal agent account) is left out.
pub(crate) async fn workspace_member_usage(
    conn: &mut Scoped,
    workspace_id: Uuid,
    (start_ts, end_ts): Window,
    exclude_email: &str,
) -> sqlx::Result<Vec<WorkspaceMemberUsageRow>> {
    let sql = format!(
        r#"SELECT u.id AS user_id, u.email,
                  COUNT(a.request_id)::bigint AS requests,
                  COALESCE(SUM(a.prompt_tokens + a.completion_tokens), 0)::bigint AS tokens,
                  {SPEND_TOTAL_COLUMNS}
           FROM workspace_members m
           JOIN users u ON u.id = m.user_id
           LEFT JOIN ({AUDIT_LOG_JOIN})
             ON g.user_id = m.user_id AND g.workspace_id = m.workspace_id{window}
           WHERE m.workspace_id = $1 AND u.email <> $4
           GROUP BY u.tenant_id, u.id, u.email
           ORDER BY requests DESC, u.id"#,
        window = window_sql(AUDIT_LOG_WINDOW, 2, 3),
    );
    sqlx::query_as::<_, WorkspaceMemberUsageRow>(sqlx::AssertSqlSafe(&*sql))
    .bind(workspace_id)
    .bind(start_ts)
    .bind(end_ts)
    .bind(exclude_email)
    .fetch_all(&mut *conn)
    .await
}

/// The agent's own traffic over the window, before the spend is denominated.
#[derive(sqlx::FromRow)]
pub(crate) struct AgentUsage {
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub amount: f64,
    pub currency_count: i64,
    pub currency: Option<String>,
    pub errors: i64,
}

/// The agent's own traffic over the window — rows stamped `source = 'agent'`
/// at ingestion.
pub(crate) async fn agent_usage(
    conn: &mut Scoped,
    tenant_id: Uuid,
    (start_ts, end_ts): Window,
) -> sqlx::Result<AgentUsage> {
    // An aggregate with no GROUP BY answers exactly one row.
    let sql = format!(
        "SELECT COUNT(*)::bigint AS requests, \
         COALESCE(SUM(prompt_tokens),0)::bigint AS prompt_tokens, \
         COALESCE(SUM(completion_tokens),0)::bigint AS completion_tokens, \
         {SPEND_TOTAL_COLUMNS}, \
         COUNT(*) FILTER (WHERE error_category IS NOT NULL)::bigint AS errors \
         FROM {AUDIT_LOG_JOIN} \
         WHERE tenant_id = $1 AND source = 'agent'{window}",
        window = window_sql(AUDIT_LOG_WINDOW, 2, 3),
    );
    sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
    .bind(tenant_id)
    .bind(start_ts)
    .bind(end_ts)
    .fetch_one(&mut *conn)
    .await
}
