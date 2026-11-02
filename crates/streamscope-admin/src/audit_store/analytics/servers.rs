//! The server dashboard's attempt relation: every attempt at an upstream
//! server, the one a request ended with and the ones it moved on from, read
//! from `gateway_audit` joined to `llm_audit`, and its two aggregate passes
//! (the fleet list and one server's page).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::tenant::Scoped;
use crate::routes::server_analytics::ServerTraffic;
use crate::audit_store::filters::{AUDIT_LOG_JOIN, AUDIT_LOG_WINDOW, AnalyticsFilterBuilder};
use crate::routes::AnalyticsScope;

/// The columns of the attempt a row ENDED with, over `gateway_audit g` joined
/// to `llm_audit a`; see [`MOVED_ATTEMPT`] for the rest of the relation `t`
/// every figure here is read from. `outcome` is `served`, `failed` (the
/// server's failure), `refused`, or `other` — sent, but ended by neither the
/// server nor the gate. A server's failure is a stream that went quiet
/// (`timeout`) or broke (`stream_error`), or an `upstream` failure audited
/// 5xx — no answer, or the server's own error — 408 or 429. An `upstream` 4xx
/// is the client's own bad request, `upstream_truncated` an answer (the model
/// ran out of room), and the rest (`client_disconnect`, the gateway's own
/// `internal`, …) are not the server's doing. Both halves spell the rule out
/// and must agree (`both_halves_agree_on_a_servers_failure`).
/// `earlier.busy_ms` comes from [`EARLIER_BUSY`], joined in the same FROM. `latency_ms` and `ttft_ms` leave out the request's
/// whole wait AND the time its earlier attempts took (their elapsed less their
/// wait, which the wait already covers): the engine that answered did not take
/// that long.
const ENDED_ATTEMPT: &str = r#"
    a.timestamp, a.upstream_server_id AS server_id, a.endpoint_id, a.endpoint_url, a.qos_class_id,
    g.user_id,
    CASE WHEN a.gate_refusal IS NOT NULL THEN 'refused'
         WHEN g.error_category IN ('timeout', 'stream_error')
              OR (g.error_category = 'upstream' AND (g.status_code >= 500 OR g.status_code IN (408, 429)))
              THEN 'failed'
         WHEN g.error_category IS NULL OR g.error_category = 'upstream_truncated' THEN 'served'
         ELSE 'other' END AS outcome,
    a.gate_refusal AS refusal,
    false AS moved_on,
    COALESCE(a.pool_wait_ms, 0)::bigint AS wait_ms,
    GREATEST(g.latency_total_ms - COALESCE(a.queue_wait_ms, 0) - COALESCE(earlier.busy_ms, 0), 0)::bigint
        AS latency_ms,
    (CASE WHEN a.latency_ttft_ms > 0 AND a.media_call IS NULL AND a.catchall_path IS NULL
          THEN GREATEST(a.latency_ttft_ms - COALESCE(a.queue_wait_ms, 0) - COALESCE(earlier.busy_ms, 0), 0)
     END)::bigint AS ttft_ms,
    COALESCE(a.prompt_tokens, 0)::bigint AS prompt_tokens,
    COALESCE(a.completion_tokens, 0)::bigint AS completion_tokens,
    a.badges @> '[{"code":"spilled"}]'::jsonb AS spilled"#;

/// The same columns for an attempt a row moved on from, `m` being one entry
/// of its `moved_on_from` ([`MOVED_ON_FROM`]). It answered nothing, so it has
/// no latency and no tokens. Keep the column list aligned with
/// [`ENDED_ATTEMPT`]: the two are one `UNION ALL`.
const MOVED_ATTEMPT: &str = r#"
    a.timestamp, m.server_id, m.endpoint_id, NULL::text, a.qos_class_id,
    g.user_id,
    CASE WHEN m.outcome = 'refused' THEN 'refused'
         WHEN m.reason IN ('timeout', 'stream_error')
              OR (m.reason = 'upstream' AND (m.status >= 500 OR m.status IN (408, 429)))
              THEN 'failed'
         ELSE 'other' END,
    CASE WHEN m.outcome = 'refused' THEN m.reason END,
    true,
    m.wait_ms::bigint,
    NULL::bigint,
    NULL::bigint,
    0::bigint,
    0::bigint,
    false"#;

/// Each attempt a row moved on from, as `m`. Spliced after the audit join, with
/// `a.moved_on_from IS NOT NULL` in the WHERE, which the partial index on it
/// serves. The ingest keeps only entries of this shape, so the casts hold; the
/// numbers are read as `numeric` because JSON may spell an integer `5.0`, which
/// a `bigint` column refuses — the ingest has already refused any fraction.
const MOVED_ON_FROM: &str = "CROSS JOIN LATERAL jsonb_to_recordset(a.moved_on_from) \
     AS m(server_id uuid, endpoint_id uuid, outcome text, reason text, status numeric, wait_ms numeric, elapsed_ms numeric)";

/// How long a row's earlier attempts kept the request busy beyond their waits
/// (which `queue_wait_ms` already covers), as `earlier.busy_ms` — NULL for a
/// row that moved on from nothing. Spliced after the audit join of the ended
/// half, once, so latency and time to first token subtract the same figure.
const EARLIER_BUSY: &str = "LEFT JOIN LATERAL (SELECT SUM(GREATEST(x.elapsed_ms - x.wait_ms, 0)) AS busy_ms \
     FROM jsonb_to_recordset(a.moved_on_from) AS x(elapsed_ms numeric, wait_ms numeric)) earlier ON true";

/// The [`ServerTraffic`] columns over the attempts relation `t`. Every
/// aggregate on this page reads through it, so a figure means the same thing
/// per server, per endpoint, per class and per bucket.
const TRAFFIC_COLUMNS: &str = r#"
    COUNT(*)::bigint AS requests,
    COUNT(*) FILTER (WHERE t.outcome = 'failed')::bigint AS errors,
    COUNT(*) FILTER (WHERE t.outcome = 'failed' AND t.moved_on)::bigint AS failed_over,
    COUNT(*) FILTER (WHERE t.outcome = 'refused')::bigint AS refusals,
    COUNT(*) FILTER (WHERE t.outcome = 'refused' AND t.moved_on)::bigint AS passed_on,
    COUNT(*) FILTER (WHERE t.wait_ms > 0 AND t.outcome <> 'refused')::bigint AS queued,
    COALESCE(SUM(t.wait_ms), 0)::bigint AS wait_ms_total,
    COUNT(*) FILTER (WHERE t.spilled)::bigint AS spilled,
    COALESCE(SUM(t.prompt_tokens), 0)::bigint AS prompt_tokens,
    COALESCE(SUM(t.completion_tokens), 0)::bigint AS completion_tokens,
    (PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY t.latency_ms)
        FILTER (WHERE t.outcome = 'served'))::float8 AS latency_p50_ms,
    (PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY t.latency_ms)
        FILTER (WHERE t.outcome = 'served'))::float8 AS latency_p95_ms,
    (PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY t.latency_ms)
        FILTER (WHERE t.outcome = 'served'))::float8 AS latency_p99_ms,
    (PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY t.ttft_ms)
        FILTER (WHERE t.outcome = 'served' AND t.ttft_ms IS NOT NULL))::float8 AS ttft_p95_ms,
    (PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY t.wait_ms)
        FILTER (WHERE t.wait_ms > 0 AND t.outcome <> 'refused'))::float8 AS queue_wait_p50_ms,
    (PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY t.wait_ms)
        FILTER (WHERE t.wait_ms > 0 AND t.outcome <> 'refused'))::float8 AS queue_wait_p95_ms"#;

/// The rows that are a server's own work. A response-cache hit keeps the
/// server it would have gone to (its cost and alias are attributed there) but
/// the server never saw it: counted here, it would inflate the requests and
/// drag the latency down to the cache's few milliseconds — hiding the slow
/// engine this page exists to show. An observe-mode hit still went upstream,
/// so it counts.
const THE_SERVERS_OWN_WORK: &str = "a.cache_outcome IS DISTINCT FROM 'hit'";

/// One row of the fleet's single pass: a server's total (`by_bucket` 1) or
/// one of its buckets (`by_bucket` 0).
#[derive(sqlx::FromRow)]
pub(crate) struct FleetRow {
    pub(crate) by_bucket: i32,
    pub(crate) server_id: Uuid,
    pub(crate) bucket: Option<DateTime<Utc>>,
    #[sqlx(flatten)]
    pub(crate) traffic: ServerTraffic,
}

/// One row of the server page's single aggregate pass; `grain` names the
/// grouping set it belongs to (see `server_dashboard`).
#[derive(sqlx::FromRow)]
pub(crate) struct GrainRow {
    pub(crate) grain: i32,
    pub(crate) bucket: Option<DateTime<Utc>>,
    pub(crate) endpoint_id: Option<Uuid>,
    pub(crate) qos_class_id: Option<Uuid>,
    pub(crate) refusal: Option<String>,
    pub(crate) user_id: Option<Uuid>,
    pub(crate) url: Option<String>,
    #[sqlx(flatten)]
    pub(crate) traffic: ServerTraffic,
}

/// Every server's totals over the window and its attempts per bucket of
/// `interval` (`date_trunc` unit), in one pass.
pub(crate) async fn fleet_rows(
    conn: &mut Scoped,
    tenant_id: Uuid,
    window: (DateTime<Utc>, DateTime<Utc>),
    interval: &'static str,
    scope_filter: &AnalyticsScope,
) -> sqlx::Result<Vec<FleetRow>> {
    let (start, end) = window;
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(AUDIT_LOG_WINDOW, (start, end));
    if let Some(user_id) = scope_filter.user_id {
        filters.push_eq_uuid("g.user_id", user_id);
    }
    if let Some(ws) = &scope_filter.workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let extra = filters.where_sql();

    // One pass over every attempt at every server: each server's totals, and
    // its attempts per bucket for the sparkline. `by_bucket` is 0 on a
    // per-bucket row, 1 on a server total.
    let attempts = format!(
        "SELECT {ENDED_ATTEMPT} FROM {AUDIT_LOG_JOIN} {EARLIER_BUSY} \
         WHERE a.tenant_id = $1 AND a.upstream_server_id IS NOT NULL AND {THE_SERVERS_OWN_WORK}{extra} \
         UNION ALL \
         SELECT {MOVED_ATTEMPT} FROM {AUDIT_LOG_JOIN} {MOVED_ON_FROM} \
         WHERE a.tenant_id = $1 AND a.moved_on_from IS NOT NULL AND m.server_id IS NOT NULL{extra}"
    );
    let bucket_expr = format!("date_trunc('{interval}', t.timestamp)");
    let fleet_sql = format!(
        "SELECT GROUPING({bucket_expr})::int AS by_bucket, t.server_id, \
                {bucket_expr} AS bucket, {TRAFFIC_COLUMNS} \
         FROM ({attempts}) t \
         GROUP BY GROUPING SETS ((t.server_id), (t.server_id, {bucket_expr}))"
    );
    filters
        .apply_query_as(sqlx::query_as::<_, FleetRow>(sqlx::AssertSqlSafe(&*fleet_sql)).bind(tenant_id))
        .fetch_all(&mut *conn)
        .await
}

/// One server's attempts over the window at every grain its page shows, in
/// one pass; `GrainRow::grain` names the grouping set.
pub(crate) async fn grain_rows(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
    window: (DateTime<Utc>, DateTime<Utc>),
    interval: &'static str,
    scope_filter: &AnalyticsScope,
) -> sqlx::Result<Vec<GrainRow>> {
    let (start, end) = window;
    let mut filters = AnalyticsFilterBuilder::new(3);
    filters.push_time_window(AUDIT_LOG_WINDOW, (start, end));
    if let Some(user_id) = scope_filter.user_id {
        filters.push_eq_uuid("g.user_id", user_id);
    }
    if let Some(ws) = &scope_filter.workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let extra = filters.where_sql();
    // Every attempt at this server: the ones requests ended with here, and
    // the ones they moved on from here.
    let attempts = format!(
        "SELECT {ENDED_ATTEMPT} FROM {AUDIT_LOG_JOIN} {EARLIER_BUSY} \
         WHERE a.tenant_id = $1 AND a.upstream_server_id = $2 AND {THE_SERVERS_OWN_WORK}{extra} \
         UNION ALL \
         SELECT {MOVED_ATTEMPT} FROM {AUDIT_LOG_JOIN} {MOVED_ON_FROM} \
         WHERE a.tenant_id = $1 AND a.moved_on_from IS NOT NULL AND m.server_id = $2{extra}"
    );

    // ONE pass over them for every grain the page shows: the total, each
    // bucket, each endpoint, each class, each class's refusals by reason and
    // each user (for who waited longest). `GROUPING(...)` says which set a row
    // belongs to — a bit is set for each key the row is NOT grouped by (bucket
    // 16, endpoint 8, class 4, refusal 2, user 1), so a NULL key inside its own
    // set is a real NULL ("no class", "no endpoint") and never confused with
    // "all".
    let bucket_expr = format!("date_trunc('{interval}', t.timestamp)");
    let grains_sql = format!(
        "SELECT GROUPING({bucket_expr}, t.endpoint_id, t.qos_class_id, t.refusal, t.user_id)::int AS grain, \
                {bucket_expr} AS bucket, t.endpoint_id, t.qos_class_id, t.refusal, t.user_id, \
                (array_agg(t.endpoint_url ORDER BY t.timestamp DESC) \
                    FILTER (WHERE t.endpoint_url IS NOT NULL))[1] AS url, \
                {TRAFFIC_COLUMNS} \
         FROM ({attempts}) t \
         GROUP BY GROUPING SETS ((), ({bucket_expr}), (t.endpoint_id), (t.qos_class_id), \
                                 (t.qos_class_id, t.refusal), (t.user_id), ({bucket_expr}, t.qos_class_id))"
    );
    filters
        .apply_query_as(
            sqlx::query_as::<_, GrainRow>(sqlx::AssertSqlSafe(&*grains_sql))
                .bind(tenant_id)
                .bind(server_id),
        )
        .fetch_all(&mut *conn)
        .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_halves_agree_on_a_servers_failure() {
        let rule = |category: &str, status: &str| {
            format!(
                "WHEN {category} IN ('timeout', 'stream_error')\n              \
                 OR ({category} = 'upstream' AND ({status} >= 500 OR {status} IN (408, 429)))\n              \
                 THEN 'failed'"
            )
        };
        assert!(ENDED_ATTEMPT.contains(&rule("g.error_category", "g.status_code")), "{ENDED_ATTEMPT}");
        assert!(MOVED_ATTEMPT.contains(&rule("m.reason", "m.status")), "{MOVED_ATTEMPT}");
    }
}
