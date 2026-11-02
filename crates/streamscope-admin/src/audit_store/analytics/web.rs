//! The web (search / fetch) dashboard, over `web_audit` joined to its
//! `gateway_audit` row.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::audit_store::filters::{WEB_AUDIT_WINDOW, AnalyticsFilterBuilder, window_sql};
use crate::db::tenant::Scoped;
use crate::sql_pattern::contains_pattern;
use crate::routes::{ApiError, parse_workspace_ids};
use crate::routes::analytics::{
    WebDashboardItem, WebDashboardPanel, WebDashboardQuery, WebDashboardSummary,
};

/// The web dashboard's metric cards over the window.
pub(crate) async fn web_dashboard_summary(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &WebDashboardQuery,
) -> Result<WebDashboardSummary, ApiError> {
    let mut sql = format!(
        "SELECT \
            COUNT(*)::BIGINT AS requests, \
            COUNT(*) FILTER (WHERE w.operation = 'search')::BIGINT AS searches, \
            COUNT(*) FILTER (WHERE w.operation = 'fetch')::BIGINT AS fetches, \
            COUNT(DISTINCT g.user_id) FILTER (WHERE g.user_id IS NOT NULL)::BIGINT AS unique_users, \
            COUNT(DISTINCT split_part(split_part(w.query, '://', 2), '/', 1)) \
                FILTER ( \
                    WHERE w.operation = 'fetch' \
                      AND w.query IS NOT NULL \
                      AND split_part(split_part(w.query, '://', 2), '/', 1) != '' \
                )::BIGINT AS unique_hosts, \
            COUNT(*) FILTER ( \
                WHERE g.status_code >= 400 OR w.error_category IS NOT NULL \
            )::BIGINT AS errors, \
            COUNT(*) FILTER (WHERE {blocked_any})::BIGINT AS blocked, \
            COUNT(*) FILTER (WHERE {ssrf})::BIGINT AS ssrf_blocks, \
            COUNT(*) FILTER (WHERE {url_filtered})::BIGINT AS domain_filter_denies, \
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p50_latency_ms, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p99_latency_ms, \
            COUNT(*) FILTER (WHERE g.latency_total_ms > 10000)::BIGINT AS slow_count \
         FROM {join} \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE TRUE{window}",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
        window = window_sql(WEB_AUDIT_WINDOW, 1, 2),
        blocked_any = BADGE_BLOCKED_ANY,
        ssrf = BADGE_SSRF,
        url_filtered = BADGE_URL_FILTERED,
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());

    let q = sqlx::query_as::<_, WebSummaryRow>(sqlx::AssertSqlSafe(&*sql)).bind(start).bind(end);
    let q = filters.apply_query_as(q);
    let row = q.fetch_one(&mut *conn).await.map_err(|e| {
        tracing::error!("web dashboard summary: {e}");
        ApiError::internal("failed to query web dashboard summary")
    })?;

    Ok(WebDashboardSummary {
        requests: row.requests.unwrap_or(0),
        searches: row.searches.unwrap_or(0),
        fetches: row.fetches.unwrap_or(0),
        unique_users: row.unique_users.unwrap_or(0),
        unique_hosts: row.unique_hosts.unwrap_or(0),
        errors: row.errors.unwrap_or(0),
        blocked: row.blocked.unwrap_or(0),
        ssrf_blocks: row.ssrf_blocks.unwrap_or(0),
        domain_filter_denies: row.domain_filter_denies.unwrap_or(0),
        p50_latency_ms: row.p50_latency_ms.unwrap_or(0.0),
        p95_latency_ms: row.p95_latency_ms.unwrap_or(0.0),
        p99_latency_ms: row.p99_latency_ms.unwrap_or(0.0),
        slow_count: row.slow_count.unwrap_or(0),
    })
}

/// The top fetched hosts of the window.
pub(crate) async fn web_dashboard_by_host(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &WebDashboardQuery,
) -> Result<WebDashboardPanel, ApiError> {
    let limit = query.resolved_limit();

    // by-host pivots fetch URLs to their host. The `operation = 'fetch'`
    // predicate is forced here even if the caller passed
    // `operation=search` — by-host on search rows is meaningless.
    let host_expr = "split_part(split_part(w.query, '://', 2), '/', 1)";
    let mut sql = format!(
        "SELECT \
            {host_expr} AS key, \
            COUNT(*)::BIGINT AS requests, \
            COUNT(*) FILTER ( \
                WHERE g.status_code >= 400 OR w.error_category IS NOT NULL \
            )::BIGINT AS errors, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            MAX(timestamp) AS last_used, \
            COALESCE(SUM(w.bytes_out), 0)::BIGINT AS bytes_out, \
            (SUM(COUNT(*)) OVER ())::BIGINT AS panel_total \
         FROM {join} \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE TRUE{window} \
           AND w.operation = 'fetch' \
           AND w.query IS NOT NULL \
           AND {host_expr} != ''",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
        window = window_sql(WEB_AUDIT_WINDOW, 1, 2),
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());
    let next_idx = filters.next_bind_idx();
    sql.push_str(&format!(
        " GROUP BY {host_expr} \
          ORDER BY requests DESC, key \
          LIMIT ${next_idx}"
    ));

    let q = sqlx::query_as::<_, WebHostRow>(sqlx::AssertSqlSafe(&*sql)).bind(start).bind(end);
    let q = filters.apply_query_as(q).bind(limit);

    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("web dashboard by-host: {e}");
        ApiError::internal("failed to query web by-host")
    })?;

    let total_requests = rows.first().map(|r| r.panel_total).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|r| WebDashboardItem {
            key: r.key,
            requests: r.requests,
            errors: r.errors,
            p95_latency_ms: r.p95_latency_ms,
            last_used: r.last_used,
            bytes_out: Some(r.bytes_out),
            avg_result_count: None,
            user_email: None,
            user_id: None,
        })
        .collect();
    Ok(WebDashboardPanel { items, total_requests })
}

/// The top search queries of the window.
pub(crate) async fn web_dashboard_by_query(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &WebDashboardQuery,
) -> Result<WebDashboardPanel, ApiError> {
    let limit = query.resolved_limit();

    let mut sql = format!(
        "SELECT \
            lower(trim(w.query)) AS key, \
            COUNT(*)::BIGINT AS requests, \
            COUNT(*) FILTER ( \
                WHERE g.status_code >= 400 OR w.error_category IS NOT NULL \
            )::BIGINT AS errors, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            MAX(timestamp) AS last_used, \
            AVG(w.result_count::DOUBLE PRECISION) AS avg_result_count, \
            (SUM(COUNT(*)) OVER ())::BIGINT AS panel_total \
         FROM {join} \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE TRUE{window} \
           AND w.operation = 'search' \
           AND w.query IS NOT NULL \
           AND trim(w.query) != ''",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
        window = window_sql(WEB_AUDIT_WINDOW, 1, 2),
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());
    let next_idx = filters.next_bind_idx();
    sql.push_str(&format!(
        " GROUP BY lower(trim(w.query)) \
          ORDER BY requests DESC, key \
          LIMIT ${next_idx}"
    ));

    let q = sqlx::query_as::<_, WebQueryRow>(sqlx::AssertSqlSafe(&*sql)).bind(start).bind(end);
    let q = filters.apply_query_as(q).bind(limit);

    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("web dashboard by-query: {e}");
        ApiError::internal("failed to query web by-query")
    })?;

    let total_requests = rows.first().map(|r| r.panel_total).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|r| WebDashboardItem {
            key: r.key,
            requests: r.requests,
            errors: r.errors,
            p95_latency_ms: r.p95_latency_ms,
            last_used: r.last_used,
            bytes_out: None,
            avg_result_count: r.avg_result_count,
            user_email: None,
            user_id: None,
        })
        .collect();
    Ok(WebDashboardPanel { items, total_requests })
}

/// The top web users of the window.
pub(crate) async fn web_dashboard_by_user(
    conn: &mut Scoped,
    start: DateTime<Utc>,
    end: DateTime<Utc>,
    query: &WebDashboardQuery,
) -> Result<WebDashboardPanel, ApiError> {
    let limit = query.resolved_limit();

    let mut sql = format!(
        "SELECT \
            COALESCE(u.display_name, u.email, g.user_id::TEXT) AS key, \
            u.email AS user_email, \
            g.user_id AS user_id, \
            COUNT(*)::BIGINT AS requests, \
            COUNT(*) FILTER ( \
                WHERE g.status_code >= 400 OR w.error_category IS NOT NULL \
            )::BIGINT AS errors, \
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) AS p95_latency_ms, \
            MAX(timestamp) AS last_used, \
            (SUM(COUNT(*)) OVER ())::BIGINT AS panel_total \
         FROM {join} \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE TRUE{window} \
           AND g.user_id IS NOT NULL",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
        window = window_sql(WEB_AUDIT_WINDOW, 1, 2),
    );
    let filters = scope_filters(query, 3);
    sql.push_str(filters.where_sql());
    let next_idx = filters.next_bind_idx();
    sql.push_str(&format!(
        " GROUP BY u.display_name, u.email, g.user_id \
          ORDER BY requests DESC, key, g.user_id \
          LIMIT ${next_idx}"
    ));

    let q = sqlx::query_as::<_, WebUserRow>(sqlx::AssertSqlSafe(&*sql)).bind(start).bind(end);
    let q = filters.apply_query_as(q).bind(limit);

    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("web dashboard by-user: {e}");
        ApiError::internal("failed to query web by-user")
    })?;

    let total_requests = rows.first().map(|r| r.panel_total).unwrap_or(0);
    let items = rows
        .into_iter()
        .map(|r| WebDashboardItem {
            key: r.key,
            requests: r.requests,
            errors: r.errors,
            p95_latency_ms: r.p95_latency_ms,
            last_used: r.last_used,
            bytes_out: None,
            avg_result_count: None,
            user_email: r.user_email,
            user_id: r.user_id,
        })
        .collect();
    Ok(WebDashboardPanel { items, total_requests })
}

/// The scope filters shared by all four web-dashboard reads — user,
/// workspaces, user email — bound from `first_bind_idx`. The email
/// filter reads `u.email`, so each read joins `users u`.
fn scope_filters(query: &WebDashboardQuery, first_bind_idx: u32) -> AnalyticsFilterBuilder {
    let mut f = AnalyticsFilterBuilder::new(first_bind_idx);
    let ws = parse_workspace_ids(&query.workspace_ids);
    f.push_scope(None, query.user_id, ws.as_deref());
    if let Some(email) = &query.user_email {
        f.push_ilike("COALESCE(u.email, '')", &contains_pattern(email));
    }
    f
}

// Postgres JSONB array containment predicates for the badge codes the
// summary KPI tile and breakdown panels care about. Each constant is an
// `EXISTS(...)`-style fragment that goes inside a `COUNT(*) FILTER (WHERE …)`.
const BADGE_URL_FILTERED: &str = "w.badges @> '[{\"code\":\"web_url_filtered\"}]'::jsonb";

const BADGE_SSRF: &str = "w.badges @> '[{\"code\":\"web_ssrf_refused\"}]'::jsonb";

const BADGE_BLOCKED_ANY: &str = "(\
    w.badges @> '[{\"code\":\"web_blocked\"}]'::jsonb \
 OR w.badges @> '[{\"code\":\"web_ssrf_refused\"}]'::jsonb \
 OR w.badges @> '[{\"code\":\"web_scheme_refused\"}]'::jsonb \
 OR w.badges @> '[{\"code\":\"web_url_filtered\"}]'::jsonb \
 OR w.badges @> '[{\"code\":\"web_all_results_filtered\"}]'::jsonb \
 OR w.badges @> '[{\"code\":\"web_rate_limited\"}]'::jsonb\
)";

#[derive(sqlx::FromRow)]
struct WebSummaryRow {
    requests: Option<i64>,
    searches: Option<i64>,
    fetches: Option<i64>,
    unique_users: Option<i64>,
    unique_hosts: Option<i64>,
    errors: Option<i64>,
    blocked: Option<i64>,
    ssrf_blocks: Option<i64>,
    domain_filter_denies: Option<i64>,
    p50_latency_ms: Option<f64>,
    p95_latency_ms: Option<f64>,
    p99_latency_ms: Option<f64>,
    slow_count: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct WebHostRow {
    key: String,
    requests: i64,
    errors: i64,
    p95_latency_ms: Option<f64>,
    last_used: chrono::DateTime<chrono::Utc>,
    bytes_out: i64,
    panel_total: i64,
}

#[derive(sqlx::FromRow)]
struct WebQueryRow {
    key: String,
    requests: i64,
    errors: i64,
    p95_latency_ms: Option<f64>,
    last_used: chrono::DateTime<chrono::Utc>,
    avg_result_count: Option<f64>,
    panel_total: i64,
}

#[derive(sqlx::FromRow)]
struct WebUserRow {
    key: String,
    requests: i64,
    errors: i64,
    p95_latency_ms: Option<f64>,
    last_used: chrono::DateTime<chrono::Utc>,
    user_email: Option<String>,
    user_id: Option<Uuid>,
    panel_total: i64,
}
