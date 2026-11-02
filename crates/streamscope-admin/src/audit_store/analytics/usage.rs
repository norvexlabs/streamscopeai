//! The usage and cost dashboards: the overview, breakdowns, time series, the
//! users & keys and proxy dashboards, errors, media, the response cache and the
//! gateway-wide (cross-protocol) views, each over a resolved window and scope.
//! The handlers in `routes/analytics.rs` keep the HTTP surface and resolve the
//! window and scope before the call.

use std::collections::HashMap;

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::audit_store::filters::{
    A2A_AUDIT_JOIN, A2A_AUDIT_WINDOW, AUDIT_LOG_JOIN, AUDIT_LOG_WINDOW, AnalyticsFilterBuilder,
    MCP_AUDIT_JOIN, MCP_AUDIT_WINDOW, window_sql,
};
use crate::db::tenant::{Scoped, TenantConn};
use crate::routes::{
    AnalyticsScope, ApiError, SPEND_TOTAL_COLUMNS, SpendBreakdown, SpendTotal, WindowWorkspacesQuery,
    billed_unit_columns, billed_unit_columns_forwarded, read_spend_units, SpendRank,
    spend_rank_order_sql, spend_total,
};
use crate::routes::analytics::{
    BreakdownBy, BreakdownEntry, CacheAliasSavings, CacheAliasStat, CacheAnalyticsResponse,
    CacheSavings, CacheSkipStat, CrossOverview,
    CrossTimeseriesBucket, CrossTimeseriesResponse, DormantKeyEntry, ErrorAnalytics,
    ErrorCategoryEntry, ExpiringKeyEntry, MediaAnalyticsResponse, MediaDirectionStat,
    MediaUserStat, ModelErrorEntry, ProtocolStats, ProxyDashboard, StatusCodeEntry,
    TimeseriesBucket, TimeseriesResponse, TopKeyEntry, TopUserEntry, TranslationPair,
    TranslationStats, UpstreamSparkline, UpstreamTimeseriesKind, UpstreamTimeseriesQuery,
    UpstreamTimeseriesResponse, UsageBreakdown, UsageSummary, UserKeysSummary,
    UsersKeysDashboard, bucket_interval, build_bucket_axis,
};

/// The usage overview of the window: totals, latency percentiles, the SSE
/// processing mix, the session count and the spend per currency.
pub(crate) async fn usage_summary(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<UsageSummary, ApiError> {
    let summary_sql_base = format!(r#"SELECT
        COUNT(*)::bigint as total_requests,
        COALESCE(SUM(prompt_tokens), 0)::bigint as total_prompt_tokens,
        COALESCE(SUM(completion_tokens), 0)::bigint as total_completion_tokens,
        COALESCE(SUM(cache_creation_tokens), 0)::bigint as total_cache_creation_tokens,
        COALESCE(SUM(cache_read_tokens), 0)::bigint as total_cache_read_tokens,
        COALESCE(SUM(reasoning_tokens), 0)::bigint as total_reasoning_tokens,
        -- Latency describes the requests that were answered: a failed LLM
        -- request records no latency, and would read as an instant one.
        COALESCE(AVG(latency_total_ms) FILTER (WHERE error_category IS NULL), 0.0)::double precision as avg_latency_ms,
        COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY latency_total_ms) FILTER (WHERE error_category IS NULL), 0)::double precision as p50_latency_ms,
        COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_total_ms) FILTER (WHERE error_category IS NULL), 0)::double precision as p95_latency_ms,
        COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_total_ms) FILTER (WHERE error_category IS NULL), 0)::double precision as p99_latency_ms,
        COALESCE(AVG(NULLIF(latency_ttft_ms, 0)), 0.0)::double precision as avg_ttft_ms,
        COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY NULLIF(latency_ttft_ms, 0)), 0)::double precision as p50_ttft_ms,
        COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY NULLIF(latency_ttft_ms, 0)), 0)::double precision as p95_ttft_ms,
        -- Observe/analyze rows (pipeline_path='analyze') are not completions: they
        -- carry an empty finish_reason and zero_completion by design, so the
        -- completion-based error heuristic must not treat them as errors. A real
        -- error on such a row still surfaces via error_category.
        COALESCE(SUM(CASE WHEN error_category IS NOT NULL OR (pipeline_path IS DISTINCT FROM 'analyze' AND (finish_reason IN ('error', '') OR zero_completion = true)) THEN 1 ELSE 0 END), 0)::bigint as error_count,
        COALESCE(SUM(CASE WHEN NULLIF(latency_ttft_ms, 0) > 10000 THEN 1 ELSE 0 END), 0)::bigint as high_latency_count, -- HIGH_LATENCY_THRESHOLD_MS
        COALESCE(SUM(CASE WHEN (media_call->>'endpoint') = 'embeddings' THEN 1 ELSE 0 END), 0)::bigint as total_embedding_requests,
        COALESCE(SUM(CASE WHEN (media_call->>'endpoint') IN ('audio_speech','audio_transcription','audio_translation') THEN 1 ELSE 0 END), 0)::bigint as total_audio_requests,
        COALESCE(SUM(CASE WHEN (media_call->>'endpoint') IN ('image_generation','image_edit','image_variation') THEN 1 ELSE 0 END), 0)::bigint as total_image_requests,
        COALESCE(SUM(CASE WHEN (media_call->>'endpoint') = 'video_generation' THEN 1 ELSE 0 END), 0)::bigint as total_video_requests,
        -- Spend rides this scan rather than a second one: at ~734k rows a
        -- separate pass over the same partitions doubled the endpoint, while
        -- these columns cost about a tenth of it. They answer the window
        -- outright unless it holds more than one currency.
        {}
    FROM {AUDIT_LOG_JOIN}"#, crate::routes::spend_breakdown_columns_ungrouped());

    let mut filters = AnalyticsFilterBuilder::new(2);
    if let Some(uid) = scope.user_id {
        filters.push_eq_uuid("user_id", uid);
    }
    filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
    if let Some(ws) = &scope.workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }

    let summary_sql = format!("{summary_sql_base} WHERE tenant_id = $1{}", filters.where_sql());
    let summary_query =
        filters.apply_query(sqlx::query(sqlx::AssertSqlSafe(&*summary_sql)).bind(tenant_id));

    // Fetched as a raw row because the per-unit spend columns are generated
    // from the `Unit` vocabulary and cannot be named by a derive; the scalar
    // half still maps through `SummaryRow`.
    let summary_row = summary_query
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("usage summary: {e}");
            ApiError::internal("database query failed")
        })?;
    // A decode failure is an error, not an absent row. Swallowing it would
    // serve a 200 with every metric zeroed — which is exactly how drift
    // between this hand-assembled select list and the struct would present,
    // and nobody would see it.
    let row: Option<SummaryRow> = summary_row
        .as_ref()
        .map(<SummaryRow as sqlx::FromRow<_>>::from_row)
        .transpose()
        .map_err(|e| {
            tracing::error!("usage summary decode: {e}");
            ApiError::internal("database query failed")
        })?;

    // Session count from sessions table (filter on `updated_at`).
    let mut sess_filters = AnalyticsFilterBuilder::new(2);
    if let Some(uid) = scope.user_id {
        sess_filters.push_eq_uuid("user_id", uid);
    }
    sess_filters.push_time_window(&["updated_at"], (start_ts, end_ts));
    if let Some(ws) = &scope.workspace_ids {
        sess_filters.push_workspaces("sessions.workspace_id", ws);
    }
    let sess_sql = format!(
        "SELECT COUNT(*)::bigint FROM sessions WHERE tenant_id = $1{}",
        sess_filters.where_sql()
    );
    let sess_query =
        sess_filters.apply_query_scalar(sqlx::query_scalar(sqlx::AssertSqlSafe(&*sess_sql)).bind(tenant_id));
    let session_count: i64 = sess_query
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| { tracing::warn!("session count query failed: {e}"); 0 });

    // SSE processing stats — streaming/fastpath/buffered/blocked
    let sse_sql = format!(
        "SELECT \
            COALESCE(SUM(CASE WHEN stream = true THEN 1 ELSE 0 END), 0)::bigint, \
            COALESCE(SUM(CASE WHEN pipeline_path = 'fastpath' THEN 1 ELSE 0 END), 0)::bigint, \
            COALESCE(SUM(CASE WHEN pipeline_path = 'buffered' THEN 1 ELSE 0 END), 0)::bigint, \
            COALESCE(SUM(CASE WHEN badges @> '[{{\"code\":\"tool_blocked\",\"phase\":\"response\"}}]'::jsonb THEN 1 ELSE 0 END), 0)::bigint \
         FROM {AUDIT_LOG_JOIN} WHERE tenant_id = $1{}",
        filters.where_sql()
    );
    #[allow(clippy::type_complexity)]
    let sse_query = filters.apply_query_as(
        sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>, Option<i64>)>(sqlx::AssertSqlSafe(&*sse_sql))
            .bind(tenant_id),
    );
    let sse_stats = sse_query.fetch_optional(&mut *conn).await.unwrap_or(None);

    let (streaming_requests, response_fastpath, response_buffered, response_tool_blocks) =
        sse_stats.map(|(a, b, c, d)| (a.unwrap_or(0), b.unwrap_or(0), c.unwrap_or(0), d.unwrap_or(0))).unwrap_or_default();

    // How many accounting currencies the window holds decides what it costs to
    // report its spend. Zero or one is answered by the summary scan above; only
    // a window that genuinely straddles a currency change pays for the grouped
    // second pass.
    let currency_count = {
        use sqlx::Row;
        summary_row
            .as_ref()
            .and_then(|r| r.try_get::<i64, _>("currency_count").ok())
            .unwrap_or(0)
    };
    let spend: Vec<SpendBreakdown> = match (currency_count, summary_row.as_ref()) {
        (1, Some(r)) => crate::routes::read_spend_breakdown(r, tenant_id).into_iter().collect(),
        (n, _) if n > 1 => spend_by_currency(&mut *conn, "a.tenant_id = $1", tenant_id, true, &filters)
            .await
            .map_err(|e| {
                tracing::error!("usage summary spend: {e}");
                ApiError::internal("database query failed")
            })?,
        _ => Vec::new(),
    };
    // Nothing priced in the window — or a currency this build cannot name.
    // Report a zero in the tenant's current accounting currency rather than an
    // empty list: a reader must be able to tell "spent nothing" from "spent
    // something we cannot denominate".
    let spend = if spend.is_empty() {
        vec![SpendBreakdown {
            currency: crate::routes::pricing::accounting_currency(&mut *conn).await,
            amount: 0.0,
            media: 0.0,
            embedding: 0.0,
            units: Vec::new(),
        }]
    } else {
        spend
    };

    let summary = match row {
        Some(r) => UsageSummary {
            total_requests: r.total_requests.unwrap_or(0),
            total_sessions: session_count,
            total_prompt_tokens: r.total_prompt_tokens.unwrap_or(0),
            total_completion_tokens: r.total_completion_tokens.unwrap_or(0),
            total_cache_creation_tokens: r.total_cache_creation_tokens.unwrap_or(0),
            total_cache_read_tokens: r.total_cache_read_tokens.unwrap_or(0),
            total_reasoning_tokens: r.total_reasoning_tokens.unwrap_or(0),
            spend,
            avg_latency_ms: r.avg_latency_ms.unwrap_or(0.0),
            p50_latency_ms: r.p50_latency_ms.unwrap_or(0.0),
            p95_latency_ms: r.p95_latency_ms.unwrap_or(0.0),
            p99_latency_ms: r.p99_latency_ms.unwrap_or(0.0),
            avg_ttft_ms: r.avg_ttft_ms.unwrap_or(0.0),
            p50_ttft_ms: r.p50_ttft_ms.unwrap_or(0.0),
            p95_ttft_ms: r.p95_ttft_ms.unwrap_or(0.0),
            error_count: r.error_count.unwrap_or(0),
            high_latency_count: r.high_latency_count.unwrap_or(0),
            streaming_requests,
            response_fastpath,
            response_buffered,
            response_tool_blocks,
            total_embedding_requests: r.total_embedding_requests.unwrap_or(0),
            total_audio_requests: r.total_audio_requests.unwrap_or(0),
            total_image_requests: r.total_image_requests.unwrap_or(0),
            total_video_requests: r.total_video_requests.unwrap_or(0),
        },
        None => UsageSummary { total_sessions: session_count, spend, ..Default::default() },
    };

    Ok(summary)
}

/// Usage of the window grouped by one dimension, largest groups first.
pub(crate) async fn usage_breakdown(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
    group_by: BreakdownBy,
) -> Result<UsageBreakdown, ApiError> {
    // Shared aggregate columns used by all branches. The money columns carry
    // the currency each group was written in — one distinct value is the
    // ordinary case, more than one is a group straddling a currency change and
    // is reported as no figure rather than a sum of two denominations.
    let agg_cols = format!(r#"
                COUNT(*)::bigint as requests,
                COALESCE(SUM(a.prompt_tokens), 0)::bigint as prompt_tokens,
                COALESCE(SUM(a.completion_tokens), 0)::bigint as completion_tokens,
                COALESCE(SUM(a.cost), 0.0)::double precision as cost,
                COUNT(DISTINCT a.cost_currency)::bigint as currency_count,
                MIN(a.cost_currency) as currency,
                COALESCE(SUM(CASE WHEN a.media_call IS NOT NULL THEN a.cost ELSE 0 END), 0.0)::double precision as media_cost,
                COALESCE(SUM(a.embedding_cost), 0.0)::double precision as embedding_cost{spend_units},
                COALESCE(SUM(a.cache_creation_tokens), 0)::bigint as cache_creation_tokens,
                COALESCE(SUM(a.cache_read_tokens), 0)::bigint as cache_read_tokens,
                COALESCE(SUM(a.reasoning_tokens), 0)::bigint as reasoning_tokens,
                COALESCE(SUM(CASE WHEN a.stream = true THEN 1 ELSE 0 END), 0)::bigint as streaming_count,
                COALESCE(AVG(g.latency_total_ms) FILTER (WHERE g.error_category IS NULL), 0.0)::double precision as avg_latency_ms,
                COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) FILTER (WHERE g.error_category IS NULL), 0)::double precision as p95_latency_ms,
                COALESCE(SUM(CASE WHEN g.error_category IS NOT NULL OR (a.pipeline_path IS DISTINCT FROM 'analyze' AND (a.finish_reason IN ('error', '') OR a.zero_completion = true)) THEN 1 ELSE 0 END), 0)::bigint as error_count,
                COALESCE(SUM(CASE WHEN NULLIF(a.latency_ttft_ms, 0) > 10000 THEN 1 ELSE 0 END), 0)::bigint as high_latency_count"#,
        spend_units = billed_unit_columns()
    );
    // Every branch below aggregates inside a LIMITed subquery and forwards the
    // result, so the money columns are forwarded by name too.
    let agg_out = format!(
        "agg.cost, agg.currency_count, agg.currency, agg.media_cost, agg.embedding_cost{}",
        billed_unit_columns_forwarded()
    );

    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
    if let Some(uid) = scope.user_id {
        filters.push_eq_uuid("g.user_id", uid);
    }
    if let Some(ws) = &scope.workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let where_extra = filters.where_sql();

    // Variants that group by an audit-side column AND join a small side table
    // (users / upstream_servers / workspaces) for the
    // display label aggregate first, LIMIT to the top-N, then join the side
    // table to enrich the surviving rows. Joining BEFORE the LIMIT lets the
    // planner cascade a misestimated audit-row count (the partitioned
    // `gateway_audit ⋈ llm_audit` hash join routinely under-estimates to
    // `rows=1`) into a nested-loop against the side table, producing a
    // cartesian Join Filter that scans millions of rows.
    let sql = match group_by {
        BreakdownBy::User => {
            format!(r#"SELECT
                COALESCE(u.display_name, u.email, agg.user_id::text) as key,
                NULL::text as parent_key,
                agg.requests, agg.prompt_tokens, agg.completion_tokens,
                {agg_out},
                agg.cache_creation_tokens, agg.cache_read_tokens, agg.reasoning_tokens,
                agg.streaming_count, agg.avg_latency_ms, agg.p95_latency_ms,
                agg.error_count, agg.high_latency_count,
                u.email as user_email,
                agg.user_id as user_id
            FROM (
                SELECT g.user_id,{agg_cols}
                FROM {AUDIT_LOG_JOIN}
                WHERE a.tenant_id = $1{where_extra}
                GROUP BY g.user_id
                ORDER BY requests DESC, g.user_id
                LIMIT 20
            ) agg
            LEFT JOIN users u ON u.id = agg.user_id
            ORDER BY agg.requests DESC, agg.user_id"#)
        }
        BreakdownBy::Server => {
            format!(r#"SELECT
                COALESCE(s.name, agg.upstream_server_id::text) as key,
                NULL::text as parent_key,
                agg.requests, agg.prompt_tokens, agg.completion_tokens,
                {agg_out},
                agg.cache_creation_tokens, agg.cache_read_tokens, agg.reasoning_tokens,
                agg.streaming_count, agg.avg_latency_ms, agg.p95_latency_ms,
                agg.error_count, agg.high_latency_count,
                agg.upstream_server_id as server_id
            FROM (
                SELECT a.upstream_server_id,{agg_cols}
                FROM {AUDIT_LOG_JOIN}
                WHERE a.tenant_id = $1 AND a.upstream_server_id IS NOT NULL
                  AND a.cache_outcome IS DISTINCT FROM 'hit'{where_extra}
                GROUP BY a.upstream_server_id
                ORDER BY requests DESC, a.upstream_server_id
                LIMIT 20
            ) agg
            LEFT JOIN upstream_servers s ON s.id = agg.upstream_server_id
            ORDER BY agg.requests DESC, agg.upstream_server_id"#)
        }
        BreakdownBy::ServerModel => {
            format!(r#"SELECT
                agg.model_used as key,
                COALESCE(s.name, agg.upstream_server_id::text) as parent_key,
                agg.requests, agg.prompt_tokens, agg.completion_tokens,
                {agg_out},
                agg.cache_creation_tokens, agg.cache_read_tokens, agg.reasoning_tokens,
                agg.streaming_count, agg.avg_latency_ms, agg.p95_latency_ms,
                agg.error_count, agg.high_latency_count,
                agg.upstream_server_id as server_id
            FROM (
                SELECT a.upstream_server_id, a.model_used,{agg_cols}
                FROM {AUDIT_LOG_JOIN}
                WHERE a.tenant_id = $1 AND a.upstream_server_id IS NOT NULL AND g.error_category IS NULL
                  AND a.cache_outcome IS DISTINCT FROM 'hit'{where_extra}
                GROUP BY a.upstream_server_id, a.model_used
                ORDER BY requests DESC, a.upstream_server_id, a.model_used
                LIMIT 100
            ) agg
            LEFT JOIN upstream_servers s ON s.id = agg.upstream_server_id
            ORDER BY parent_key, agg.upstream_server_id, agg.requests DESC, agg.model_used"#)
        }
        BreakdownBy::Workspace => {
            // gateway_audit carries workspace_id directly, so aggregation groups
            // by workspace without joining api_keys.
            format!(r#"SELECT
                COALESCE(ws.name, agg.workspace_id::text) as key,
                NULL::text as parent_key,
                agg.requests, agg.prompt_tokens, agg.completion_tokens,
                {agg_out},
                agg.cache_creation_tokens, agg.cache_read_tokens, agg.reasoning_tokens,
                agg.streaming_count, agg.avg_latency_ms, agg.p95_latency_ms,
                agg.error_count, agg.high_latency_count
            FROM (
                SELECT g.workspace_id,{agg_cols}
                FROM {AUDIT_LOG_JOIN}
                WHERE a.tenant_id = $1{where_extra}
                GROUP BY g.workspace_id
                ORDER BY requests DESC, g.workspace_id
                LIMIT 20
            ) agg
            LEFT JOIN workspaces ws ON ws.id = agg.workspace_id
            ORDER BY agg.requests DESC, agg.workspace_id"#)
        }
        BreakdownBy::WorkspaceModel => {
            format!(r#"SELECT
                COALESCE(agg.model_requested, 'unknown') as key,
                COALESCE(ws.name, agg.workspace_id::text) as parent_key,
                agg.requests, agg.prompt_tokens, agg.completion_tokens,
                {agg_out},
                agg.cache_creation_tokens, agg.cache_read_tokens, agg.reasoning_tokens,
                agg.streaming_count, agg.avg_latency_ms, agg.p95_latency_ms,
                agg.error_count, agg.high_latency_count
            FROM (
                SELECT g.workspace_id, a.model_requested,{agg_cols}
                FROM {AUDIT_LOG_JOIN}
                WHERE a.tenant_id = $1 AND g.error_category IS NULL{where_extra}
                GROUP BY g.workspace_id, a.model_requested
                ORDER BY requests DESC, g.workspace_id, a.model_requested
                LIMIT 100
            ) agg
            LEFT JOIN workspaces ws ON ws.id = agg.workspace_id
            ORDER BY parent_key, agg.workspace_id, agg.requests DESC, agg.model_requested"#)
        }
        BreakdownBy::Provider => {
            format!(r#"SELECT
                a.provider as key,
                NULL::text as parent_key,{agg_cols}
            FROM {AUDIT_LOG_JOIN}
            WHERE a.tenant_id = $1 AND g.error_category IS NULL{where_extra}
            GROUP BY a.provider
            ORDER BY requests DESC, key
            LIMIT 20"#)
        }
        BreakdownBy::App => {
            format!(r#"SELECT
                COALESCE(g.app_id, 'unknown') as key,
                NULL::text as parent_key,{agg_cols}
            FROM {AUDIT_LOG_JOIN}
            WHERE a.tenant_id = $1 AND g.error_category IS NULL{where_extra}
            GROUP BY g.app_id
            ORDER BY requests DESC, key
            LIMIT 20"#)
        }
        BreakdownBy::Model => {
            // Group by model_used
            format!(r#"SELECT
                a.model_used as key,
                NULL::text as parent_key,{agg_cols}
            FROM {AUDIT_LOG_JOIN}
            WHERE a.tenant_id = $1 AND g.error_category IS NULL{where_extra}
            GROUP BY a.model_used
            ORDER BY requests DESC, key
            LIMIT 20"#)
        }
    };

    let sqlx_query =
        filters.apply_query(sqlx::query(sqlx::AssertSqlSafe(&*sql)).bind(tenant_id));
    let rows = sqlx_query.fetch_all(&mut *conn).await
        .map_err(|e| {
            tracing::error!("usage breakdown: {e}");
            ApiError::internal("database query failed")
        })?;

    Ok(UsageBreakdown { entries: rows.iter().map(read_breakdown_entry).collect() })
}

/// Usage of the window per hour (a window of a day or less) or per day.
pub(crate) async fn usage_timeseries(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<TimeseriesResponse, ApiError> {
    // Bucket size: hourly when the window is ≤ 1 day, otherwise daily. The
    // boundary is timestamp-based (24 h), so an absolute window picks its
    // resolution from its own length, whatever `days` said.
    let bucket_hourly = (end_ts - start_ts) <= chrono::Duration::days(1);
    let trunc = if bucket_hourly { "hour" } else { "day" };
    let interval_str = if bucket_hourly { "1 hour" } else { "1 day" };

    // tenant_id at $1; push_time_window emits $2/$3 for [start, end).
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
    filters.push_scope(scope.app_id.as_deref(), scope.user_id, scope.workspace_ids.as_deref());
    if let Some(model) = &scope.model {
        filters.push_eq_str("a.model_used", model);
    }
    let where_extra = filters.where_sql();

    let sql = format!(
        r#"WITH buckets AS (
            SELECT generate_series(
                date_trunc('{trunc}', $2::timestamptz),
                date_trunc('{trunc}', $3::timestamptz),
                '{interval_str}'::interval
            ) AS bucket_ts
        ),
        agg AS (
            SELECT
                date_trunc('{trunc}', a.timestamp) AS bucket_ts,
                COUNT(*)::bigint AS request_count,
                COALESCE(SUM(CASE WHEN a.pipeline_path IS DISTINCT FROM 'analyze' AND (a.finish_reason IN ('error', '') OR a.zero_completion = true) THEN 1 ELSE 0 END), 0)::bigint AS error_count,
                COALESCE(SUM(a.prompt_tokens), 0)::bigint AS prompt_tokens,
                COALESCE(SUM(a.completion_tokens), 0)::bigint AS completion_tokens,
                COALESCE(SUM(a.cache_creation_tokens), 0)::bigint AS cache_creation_tokens,
                COALESCE(SUM(a.cache_read_tokens), 0)::bigint AS cache_read_tokens,
                COALESCE(SUM(a.reasoning_tokens), 0)::bigint AS reasoning_tokens,
                {SPEND_TOTAL_COLUMNS},
                COALESCE(PERCENTILE_CONT(0.5) WITHIN GROUP (ORDER BY g.latency_total_ms) FILTER (WHERE g.error_category IS NULL), 0)::double precision AS p50_latency_ms,
                COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY g.latency_total_ms) FILTER (WHERE g.error_category IS NULL), 0)::double precision AS p95_latency_ms,
                COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY g.latency_total_ms) FILTER (WHERE g.error_category IS NULL), 0)::double precision AS p99_latency_ms
            FROM {AUDIT_LOG_JOIN}
            WHERE a.tenant_id = $1
              {where_extra}
            GROUP BY date_trunc('{trunc}', a.timestamp)
        )
        SELECT
            b.bucket_ts AS timestamp,
            COALESCE(a.request_count, 0)::bigint AS request_count,
            COALESCE(a.error_count, 0)::bigint AS error_count,
            COALESCE(a.prompt_tokens, 0)::bigint AS prompt_tokens,
            COALESCE(a.completion_tokens, 0)::bigint AS completion_tokens,
            COALESCE(a.cache_creation_tokens, 0)::bigint AS cache_creation_tokens,
            COALESCE(a.cache_read_tokens, 0)::bigint AS cache_read_tokens,
            COALESCE(a.reasoning_tokens, 0)::bigint AS reasoning_tokens,
            COALESCE(a.amount, 0.0)::double precision AS amount,
            COALESCE(a.currency_count, 0)::bigint AS currency_count,
            a.currency AS currency,
            COALESCE(a.p50_latency_ms, 0.0)::double precision AS p50_latency_ms,
            COALESCE(a.p95_latency_ms, 0.0)::double precision AS p95_latency_ms,
            COALESCE(a.p99_latency_ms, 0.0)::double precision AS p99_latency_ms
        FROM buckets b
        LEFT JOIN agg a ON a.bucket_ts = b.bucket_ts
        ORDER BY b.bucket_ts"#
    );

    let sqlx_query =
        filters.apply_query(sqlx::query(sqlx::AssertSqlSafe(&*sql)).bind(tenant_id));

    let rows = sqlx_query
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("timeseries query: {e}");
            ApiError::internal("database query failed")
        })?;

    // A bucket with no traffic still reports a zero, and needs a denomination
    // to report it in. Read the tenant's current currency once, and only when
    // some bucket actually needs it.
    let fallback = {
        use sqlx::Row;
        let needed = rows
            .iter()
            .any(|r| r.try_get::<i64, _>("currency_count").unwrap_or(0) == 0);
        if needed {
            crate::routes::pricing::accounting_currency(&mut *conn).await
        } else {
            streamscope_core::pricing::Currency::USD
        }
    };

    let buckets: Vec<TimeseriesBucket> = {
        use sqlx::Row;
        rows.iter()
            .map(|row| {
                // `generate_series` produces the bucket key, so it is never
                // NULL — a row that cannot yield one means the query changed
                // shape, and skipping it would silently shorten the series.
                let timestamp: DateTime<Utc> = row.try_get("timestamp").map_err(|e| {
                    tracing::error!("timeseries bucket key: {e}");
                    ApiError::internal("database query failed")
                })?;
                Ok(TimeseriesBucket {
                timestamp,
                request_count: row.try_get("request_count").unwrap_or(0),
                error_count: row.try_get("error_count").unwrap_or(0),
                prompt_tokens: row.try_get("prompt_tokens").unwrap_or(0),
                completion_tokens: row.try_get("completion_tokens").unwrap_or(0),
                cache_creation_tokens: row.try_get("cache_creation_tokens").unwrap_or(0),
                cache_read_tokens: row.try_get("cache_read_tokens").unwrap_or(0),
                reasoning_tokens: row.try_get("reasoning_tokens").unwrap_or(0),
                spend: crate::routes::spend_total(
                    row.try_get("currency_count").unwrap_or(0),
                    row.try_get("currency").ok().flatten(),
                    row.try_get("amount").unwrap_or(0.0),
                    fallback,
                ),
                p50_latency_ms: row.try_get("p50_latency_ms").unwrap_or(0.0),
                p95_latency_ms: row.try_get("p95_latency_ms").unwrap_or(0.0),
                p99_latency_ms: row.try_get("p99_latency_ms").unwrap_or(0.0),
                })
            })
            .collect::<Result<Vec<_>, ApiError>>()?
    };

    let interval = if bucket_hourly { "hourly" } else { "daily" };
    Ok(TimeseriesResponse {
        interval: interval.to_string(),
        buckets,
    })
}

/// The users & keys dashboard. Its audit queries fan out on their own
/// tenant connections from `pool`; `db` is released before they run.
pub(crate) async fn users_keys_dashboard(
    mut db: TenantConn,
    pool: crate::db::Db,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<UsersKeysDashboard, ApiError> {
    let tenant_id_val = db.tenant_uuid();
    let tenant_kind = db.tenant_id();

    let workspace_ids = scope.workspace_ids;

    // The dashboard fans out to six independent SELECTs. Two are pure
    // metadata reads (`user_counts`, `expiring`) and stay on the inbound
    // connection. The four audit-touching queries each get their own
    // tenant-scoped connection and run concurrently — the wall-clock
    // becomes the slowest individual query rather than the sum.
    let audit_totals_fut = {
        let pool = pool.clone();
        let workspace_ids = workspace_ids.clone();
        async move {
            let mut conn = TenantConn::acquire(&pool, tenant_kind).await
                .map_err(|e| {
                    tracing::error!("users-keys audit_totals acquire: {e}");
                    ApiError::internal("database query failed")
                })?;
            let mut filters = AnalyticsFilterBuilder::new(2);
            filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
            if let Some(ws) = &workspace_ids {
                filters.push_workspaces("g.workspace_id", ws);
            }
            let sql = format!(
                "SELECT COUNT(*)::bigint, {SPEND_TOTAL_COLUMNS} \
                 FROM {AUDIT_LOG_JOIN} \
                 WHERE tenant_id = $1{}",
                filters.where_sql()
            );
            let q = filters.apply_query_as(
                sqlx::query_as::<_, (i64, f64, i64, Option<String>)>(sqlx::AssertSqlSafe(&*sql)).bind(tenant_id_val),
            );
            q.fetch_one(conn.conn()).await.map_err(|e| {
                tracing::error!("users-keys audit_totals: {e}");
                ApiError::internal("database query failed")
            })
        }
    };

    let top_users_fut = {
        let pool = pool.clone();
        let workspace_ids = workspace_ids.clone();
        async move {
            let mut conn = TenantConn::acquire(&pool, tenant_kind).await
                .map_err(|e| {
                    tracing::error!("users-keys top_users acquire: {e}");
                    ApiError::internal("database query failed")
                })?;
            // Read here, beside the query it leads, rather than ahead of the
            // fan-out: it also denominates the dashboard's zero total.
            let current = crate::routes::pricing::accounting_currency(conn.conn()).await;
            let mut filters = AnalyticsFilterBuilder::new(2);
            filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
            if let Some(ws) = &workspace_ids {
                filters.push_workspaces("g.workspace_id", ws);
            }
            // Ranked by `SpendRank`: never two amounts in different
            // denominations compared, and a user whose window straddles a
            // currency change keeps its place by what it spent today.
            let sql = format!(
                "SELECT u.id AS user_id, u.email, u.display_name, COUNT(*)::bigint AS request_count, \
                    {SPEND_TOTAL_COLUMNS} \
                 FROM {AUDIT_LOG_JOIN} JOIN users u ON u.id = g.user_id \
                 WHERE u.tenant_id = $1{} \
                 GROUP BY u.tenant_id, u.id, u.email, u.display_name \
                 ORDER BY {}, COUNT(*) DESC, u.id \
                 LIMIT 10",
                filters.where_sql(),
                spend_rank_order_sql(filters.next_bind_idx()),
            );
            let q = filters.apply_query_as(
                sqlx::query_as::<_, TopUserRow>(sqlx::AssertSqlSafe(&*sql))
                    .bind(tenant_id_val),
            )
            .bind(current.as_str().to_owned());
            q.fetch_all(conn.conn()).await.map(|rows| (rows, current)).map_err(|e| {
                tracing::error!("users-keys top_users: {e}");
                ApiError::internal("database query failed")
            })
        }
    };

    let top_keys_fut = {
        let pool = pool.clone();
        let workspace_ids = workspace_ids.clone();
        async move {
            let mut conn = TenantConn::acquire(&pool, tenant_kind).await
                .map_err(|e| {
                    tracing::error!("users-keys top_keys acquire: {e}");
                    ApiError::internal("database query failed")
                })?;
            let mut filters = AnalyticsFilterBuilder::new(2);
            filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
            if let Some(ws) = &workspace_ids {
                filters.push_workspaces("g.workspace_id", ws);
            }
            let sql = format!(
                "SELECT k.id AS key_id, k.name AS key_name, \
                    COALESCE(k.key_prefix, LEFT(k.key_hash, 8)) AS key_prefix, k.user_id, \
                    u.email AS user_email, u.display_name AS user_display_name, \
                    COUNT(*)::bigint AS request_count, {SPEND_TOTAL_COLUMNS}, \
                    MAX(a.timestamp) AS last_used_at, ws.name AS workspace_name \
                 FROM {AUDIT_LOG_JOIN} \
                 JOIN api_keys k ON k.id = g.key_id \
                 JOIN users u ON u.id = k.user_id \
                 LEFT JOIN workspaces ws ON ws.id = k.workspace_id \
                 WHERE g.key_id IS NOT NULL AND u.tenant_id = $1{} \
                 GROUP BY k.tenant_id, k.id, k.name, k.key_prefix, k.key_hash, k.user_id, u.email, u.display_name, ws.name \
                 ORDER BY COUNT(*) DESC, k.id \
                 LIMIT 10",
                filters.where_sql()
            );
            let q = filters.apply_query_as(
                sqlx::query_as::<_, TopKeyRow>(sqlx::AssertSqlSafe(&*sql))
                    .bind(tenant_id_val),
            );
            q.fetch_all(conn.conn()).await.map_err(|e| {
                tracing::error!("users-keys top_keys: {e}");
                ApiError::internal("database query failed")
            })
        }
    };

    let dormant_fut = {
        let pool = pool.clone();
        let workspace_ids = workspace_ids.clone();
        async move {
            let mut conn = TenantConn::acquire(&pool, tenant_kind).await
                .map_err(|e| {
                    tracing::error!("users-keys dormant acquire: {e}");
                    ApiError::internal("database query failed")
                })?;
            // The key_usage CTE is bounded by the same time window as the
            // other audit aggregates — without it the CTE scans all
            // partitions every call and the endpoint scales with total
            // audit_log size.
            let ws_clause = if workspace_ids.is_some() { " AND k.workspace_id = ANY($4)" } else { "" };
            let dormant_sql = format!(
                "WITH key_usage AS ( \
                    SELECT key_id, MAX(timestamp) as last_used \
                    FROM gateway_audit \
                    WHERE key_id IS NOT NULL \
                      AND timestamp >= $1 \
                      AND timestamp < $2 \
                    GROUP BY key_id \
                ) \
                SELECT k.id, k.name, COALESCE(k.key_prefix, LEFT(k.key_hash, 8)), u.email, \
                    ku.last_used, k.created_at, ws.name \
                FROM api_keys k \
                JOIN users u ON u.id = k.user_id \
                LEFT JOIN key_usage ku ON ku.key_id = k.id \
                LEFT JOIN workspaces ws ON ws.id = k.workspace_id \
                WHERE k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW()) \
                    AND k.created_at < NOW() - INTERVAL '30 days' AND u.tenant_id = $3{ws_clause} \
                ORDER BY ku.last_used ASC NULLS FIRST, k.id \
                LIMIT 20"
            );
            let mut dormant_q = sqlx::query_as::<_, (Uuid, Option<String>, String, Option<String>, Option<DateTime<Utc>>, DateTime<Utc>, Option<String>)>(sqlx::AssertSqlSafe(&*dormant_sql))
                .bind(start_ts)
                .bind(end_ts)
                .bind(tenant_id_val);
            if let Some(ref ws) = workspace_ids {
                dormant_q = dormant_q.bind(ws.clone());
            }
            dormant_q
            .fetch_all(conn.conn())
            .await
            .map_err(|e| {
                tracing::error!("users-keys dormant: {e}");
                ApiError::internal("database query failed")
            })
        }
    };

    // user_counts and expiring don't touch the audit tables, so they
    // run on the inbound `db` connection. user_counts goes first
    // because expiring borrows the same conn.
    // Workspace scope: users count by membership (`workspace_members`), key
    // counts by the key's `workspace_id`. `$2` is the workspace when set.
    let (users_total_sql, users_active_sql) = if workspace_ids.is_some() {
        (
            "(SELECT COUNT(*) FROM workspace_members wm WHERE wm.workspace_id = ANY($2))",
            "(SELECT COUNT(*) FROM workspace_members wm JOIN users u ON u.id = wm.user_id WHERE wm.workspace_id = ANY($2) AND u.is_active = true)",
        )
    } else {
        (
            "(SELECT COUNT(*) FROM users WHERE tenant_id = $1)",
            "(SELECT COUNT(*) FROM users WHERE tenant_id = $1 AND is_active = true)",
        )
    };
    let key_ws = if workspace_ids.is_some() { " AND k.workspace_id = ANY($2)" } else { "" };
    let user_counts_sql = format!(
        "SELECT \
            {users_total_sql} as total_users, \
            {users_active_sql} as active_users, \
            (SELECT COUNT(*) FROM api_keys k JOIN users u ON u.id = k.user_id \
                WHERE u.tenant_id = $1 AND k.revoked_at IS NULL AND (k.expires_at IS NULL OR k.expires_at > NOW()){key_ws}) as active_keys, \
            (SELECT COUNT(*) FROM api_keys k JOIN users u ON u.id = k.user_id \
                WHERE u.tenant_id = $1 AND k.revoked_at IS NULL AND k.expires_at IS NOT NULL AND k.expires_at <= NOW(){key_ws}) as expired_keys, \
            (SELECT COUNT(*) FROM api_keys k JOIN users u ON u.id = k.user_id \
                WHERE u.tenant_id = $1 AND k.revoked_at IS NOT NULL{key_ws}) as revoked_keys"
    );
    let mut user_counts_q = sqlx::query_as::<_, (Option<i64>, Option<i64>, Option<i64>, Option<i64>, Option<i64>)>(sqlx::AssertSqlSafe(&*user_counts_sql))
        .bind(tenant_id_val);
    if let Some(ref ws) = workspace_ids {
        user_counts_q = user_counts_q.bind(ws.clone());
    }
    let user_counts = user_counts_q
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("users-keys dashboard user counts: {e}");
        ApiError::internal("database query failed")
    })?;
    let expiring_ws = if workspace_ids.is_some() { " AND k.workspace_id = ANY($2)" } else { "" };
    let expiring_sql = format!(
        "SELECT k.id, k.name, COALESCE(k.key_prefix, LEFT(k.key_hash, 8)), u.email, \
            k.expires_at, EXTRACT(DAY FROM k.expires_at - NOW())::int as days_remaining, \
            ws.name \
        FROM api_keys k \
        JOIN users u ON u.id = k.user_id \
        LEFT JOIN workspaces ws ON ws.id = k.workspace_id \
        WHERE k.revoked_at IS NULL AND k.expires_at BETWEEN NOW() AND NOW() + INTERVAL '30 days' \
            AND u.tenant_id = $1{expiring_ws} \
        ORDER BY k.expires_at ASC, k.id \
        LIMIT 20"
    );
    let mut expiring_q = sqlx::query_as::<_, (Uuid, Option<String>, String, Option<String>, DateTime<Utc>, i32, Option<String>)>(sqlx::AssertSqlSafe(&*expiring_sql))
        .bind(tenant_id_val);
    if let Some(ref ws) = workspace_ids {
        expiring_q = expiring_q.bind(ws.clone());
    }
    let expiring = expiring_q
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("users-keys dashboard expiring keys: {e}");
        ApiError::internal("database query failed")
    })?;

    // Drop the inbound connection back to the pool before fanning out, so
    // the four parallel acquires below cap worst-case in-flight count at
    // 4 (not 5). Matters under pytest-xdist E2E where 4 workers × this
    // handler can otherwise saturate the 20-conn pool exactly.
    drop(db);

    let (audit_totals, top_users, top_keys, dormant) = tokio::try_join!(
        audit_totals_fut,
        top_users_fut,
        top_keys_fut,
        dormant_fut,
    )?;

    let (total_users, active_users, active_keys, expired_keys, revoked_keys) = user_counts;
    let total_users = total_users.unwrap_or(0);
    let active_users = active_users.unwrap_or(0);
    let (total_requests, amount, currency_count, currency) = audit_totals;
    let (top_users, current) = top_users;

    let summary = UserKeysSummary {
        total_users,
        active_users,
        disabled_users: total_users - active_users,
        active_keys: active_keys.unwrap_or(0),
        expired_keys: expired_keys.unwrap_or(0),
        revoked_keys: revoked_keys.unwrap_or(0),
        total_requests,
        spend: spend_total(currency_count, currency, amount, current),
    };

    let top_users_by_cost = top_users
        .into_iter()
        .map(|r| TopUserEntry {
            user_id: r.user_id,
            email: r.email,
            display_name: r.display_name,
            request_count: r.request_count,
            spend: spend_total(r.currency_count, r.currency, r.amount, current),
        })
        .collect();

    let top_keys_by_requests = top_keys
        .into_iter()
        .map(|r| TopKeyEntry {
            key_id: r.key_id,
            key_name: r.key_name,
            key_prefix: r.key_prefix,
            user_id: r.user_id,
            user_email: r.user_email,
            user_display_name: r.user_display_name,
            request_count: r.request_count,
            spend: spend_total(r.currency_count, r.currency, r.amount, current),
            last_used_at: r.last_used_at,
            workspace_name: r.workspace_name,
        })
        .collect();

    let dormant_keys = dormant
        .into_iter()
        .map(|(key_id, key_name, key_prefix, user_email, last_used_at, created_at, workspace_name)| DormantKeyEntry {
            key_id,
            key_name,
            key_prefix,
            user_email,
            last_used_at,
            created_at,
            workspace_name,
        })
        .collect();

    let expiring_soon = expiring
        .into_iter()
        .map(|(key_id, key_name, key_prefix, user_email, expires_at, days_remaining, workspace_name)| ExpiringKeyEntry {
            key_id,
            key_name,
            key_prefix,
            user_email,
            expires_at,
            days_remaining,
            workspace_name,
        })
        .collect();

    Ok(UsersKeysDashboard {
        summary,
        top_users_by_cost,
        top_keys_by_requests,
        dormant_keys,
        expiring_soon,
    })
}

/// The proxy dashboard of the window.
pub(crate) async fn proxy_dashboard(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    params: &WindowWorkspacesQuery,
) -> Result<ProxyDashboard, ApiError> {
    // The workspace filter binds at $4 (after tenant/start/end). `g.workspace_id`
    // is qualified — ambiguous bare across the gateway_audit ⋈ llm_audit join.
    let workspace_ids = params.workspace_ids();
    let ws_filter = if workspace_ids.is_some() {
        " AND g.workspace_id = ANY($4)"
    } else {
        ""
    };
    let llm_window = window_sql(AUDIT_LOG_WINDOW, 2, 3);

    let protocol_sql = format!(
        "SELECT api_version, \
                COUNT(*) as request_count, \
                SUM(COALESCE(prompt_tokens, 0) + COALESCE(completion_tokens, 0)) as total_tokens, \
                SUM(CASE WHEN finish_reason IN ('error', 'timeout') THEN 1 ELSE 0 END) as error_count, \
                {SPEND_TOTAL_COLUMNS} \
         FROM {AUDIT_LOG_JOIN} \
         WHERE tenant_id = $1{llm_window}{ws_filter} \
         GROUP BY api_version \
         ORDER BY request_count DESC"
    );
    let mut proto_query = sqlx::query_as::<_, ProtocolRow>(sqlx::AssertSqlSafe(&*protocol_sql))
        .bind(tenant_id)
        .bind(start_ts)
        .bind(end_ts);
    if let Some(ref ws) = workspace_ids {
        proto_query = proto_query.bind(ws.clone());
    }
    let protocol_rows = proto_query.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!(tenant_id = %tenant_id, error = %e, "proxy dashboard: protocol stats query failed");
        ApiError::internal("database query failed")
    })?;

    // Translation pairs come from the typed `protocol_translated` badge.
    let translation_sql = format!(
        "SELECT badge->>'from' AS from_protocol, badge->>'to' AS to_protocol, COUNT(*) AS cnt \
         FROM {AUDIT_LOG_JOIN}, jsonb_array_elements(badges) AS badge \
         WHERE tenant_id = $1{llm_window}{ws_filter} \
           AND badge->>'code' = 'protocol_translated' \
         GROUP BY badge->>'from', badge->>'to' \
         ORDER BY cnt DESC"
    );
    let mut trans_query =
        sqlx::query_as::<_, (Option<String>, Option<String>, Option<i64>)>(sqlx::AssertSqlSafe(&*translation_sql))
            .bind(tenant_id)
            .bind(start_ts)
            .bind(end_ts);
    if let Some(ref ws) = workspace_ids {
        trans_query = trans_query.bind(ws.clone());
    }
    // Translation pairs are secondary content — a failure here degrades to
    // "no translations" rather than failing the whole dashboard.
    let translation_rows = trans_query.fetch_all(&mut *conn).await.unwrap_or_else(|e| {
        tracing::warn!(tenant_id = %tenant_id, error = %e, "proxy dashboard: translation pairs query failed; showing none");
        Vec::new()
    });

    // Translation pairs come straight off the typed `protocol_translated` badge.
    let mut pairs_map: HashMap<(String, String), i64> = HashMap::new();
    let mut total_translated: i64 = 0;
    for (from, to, count) in translation_rows {
        if let (Some(from), Some(to), Some(count)) = (from, to, count) {
            *pairs_map.entry((from, to)).or_default() += count;
            total_translated += count;
        }
    }

    // Per-protocol outbound delta: a translated request leaves its `from`
    // protocol and arrives in its `to` protocol when sent upstream.
    let mut outbound_delta: HashMap<String, i64> = HashMap::new();
    for ((from, to), count) in &pairs_map {
        *outbound_delta.entry(from.clone()).or_default() -= count;
        *outbound_delta.entry(to.clone()).or_default() += count;
    }

    // A protocol with no traffic still reports a zero, in the tenant's
    // current accounting currency — read only when some protocol has none.
    let all_four_seen = ["chat_completions", "responses", "anthropic_messages", "google_gemini"]
        .iter()
        .all(|v| protocol_rows.iter().any(|r| r.api_version.as_deref() == Some(*v)));
    let current = if all_four_seen {
        streamscope_core::pricing::Currency::USD
    } else {
        crate::routes::pricing::accounting_currency(&mut *conn).await
    };
    let mut protocol_map: HashMap<String, ProtocolStats> = HashMap::new();
    // Ensure all 4 protocols appear even with zero traffic.
    for ver in ["chat_completions", "responses", "anthropic_messages", "google_gemini"] {
        protocol_map.insert(ver.to_string(), ProtocolStats {
            api_version: ver.to_string(),
            inbound_count: 0,
            outbound_count: 0,
            total_tokens: 0,
            error_count: 0,
            spend: spend_total(0, None, 0.0, current),
        });
    }
    for r in protocol_rows {
        let ver = r.api_version.unwrap_or_default();
        if let Some(entry) = protocol_map.get_mut(&ver) {
            entry.inbound_count = r.request_count.unwrap_or(0);
            entry.total_tokens = r.total_tokens.unwrap_or(0);
            entry.error_count = r.error_count.unwrap_or(0);
            entry.spend = spend_total(r.currency_count, r.currency, r.amount, current);
        }
    }
    // outbound = inbound + (translated in) − (translated out), clamped at 0.
    for (ver, entry) in &mut protocol_map {
        let delta = outbound_delta.get(ver).copied().unwrap_or(0);
        entry.outbound_count = (entry.inbound_count + delta).max(0);
    }
    // Busiest first; equal traffic orders by name, so the order is the same on
    // every refresh and every replica (the maps iterate in no fixed order).
    let mut protocol_stats: Vec<ProtocolStats> = protocol_map.into_values().collect();
    protocol_stats.sort_by(|a, b| {
        b.inbound_count.cmp(&a.inbound_count).then_with(|| a.api_version.cmp(&b.api_version))
    });

    let mut pairs: Vec<TranslationPair> = pairs_map
        .into_iter()
        .map(|((from_protocol, to_protocol), count)| TranslationPair {
            from_protocol,
            to_protocol,
            count,
        })
        .collect();
    pairs.sort_by(|a, b| {
        b.count
            .cmp(&a.count)
            .then_with(|| a.from_protocol.cmp(&b.from_protocol))
            .then_with(|| a.to_protocol.cmp(&b.to_protocol))
    });

    Ok(ProxyDashboard {
        protocol_stats,
        translation_stats: TranslationStats {
            total_translated,
            pairs,
        },
    })
}

/// Errors of the window: by category, by model and over time.
pub(crate) async fn error_analytics(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<ErrorAnalytics, ApiError> {
    // All three sub-queries share the same tenant + time binds.
    let mut filters = AnalyticsFilterBuilder::new(2);
    let (lo, hi) = filters.push_time_window(&["g.timestamp"], (start_ts, end_ts));
    // `g.workspace_id` — every sub-query below aliases `gateway_audit` as `g`
    // (the bare-FROM ones below are aliased to match the join query).
    if let Some(ws) = &scope.workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let where_extra = filters.where_sql().to_string();

    let cat_sql = format!(
        "SELECT COALESCE(error_category, 'unknown') as category, \
                COUNT(*)::bigint as count, \
                MAX(timestamp) as latest_at \
         FROM gateway_audit g \
         WHERE tenant_id = $1 AND error_category IS NOT NULL \
               {where_extra} \
         GROUP BY error_category \
         ORDER BY count DESC, category"
    );
    let cat_query = filters.apply_query_as(
        sqlx::query_as::<_, ErrorCategoryEntry>(sqlx::AssertSqlSafe(&*cat_sql)).bind(tenant_id),
    );
    let by_category = cat_query.fetch_all(&mut *conn).await
        .map_err(|e| {
            tracing::error!("error analytics by_category: {e}");
            ApiError::internal("database query failed")
        })?;

    let total_errors: i64 = by_category.iter().map(|e| e.count).sum();

    let status_sql = format!(
        "SELECT status_code, COUNT(*)::bigint as count \
         FROM gateway_audit g \
         WHERE tenant_id = $1 AND error_category IS NOT NULL \
               AND status_code IS NOT NULL \
               {where_extra} \
         GROUP BY status_code \
         ORDER BY count DESC, status_code"
    );
    let status_query = filters.apply_query_as(
        sqlx::query_as::<_, StatusCodeEntry>(sqlx::AssertSqlSafe(&*status_sql)).bind(tenant_id),
    );
    let by_status_code = status_query.fetch_all(&mut *conn).await
        .map_err(|e| {
            tracing::error!("error analytics by_status_code: {e}");
            ApiError::internal("database query failed")
        })?;

    // The shared filters bound `g`; the join states the window on `a` too.
    let llm_window = window_sql(&["a.timestamp"], lo, hi);
    let model_sql = format!(
        "SELECT model_requested as model, \
                COUNT(*)::bigint as count, \
                COALESCE(MODE() WITHIN GROUP (ORDER BY error_category), 'unknown') as top_category \
         FROM {AUDIT_LOG_JOIN} \
         WHERE tenant_id = $1 AND error_category IS NOT NULL \
               AND model_requested != '' \
               {where_extra}{llm_window} \
         GROUP BY model_requested \
         ORDER BY count DESC, model \
         LIMIT 20"
    );
    let model_query = filters.apply_query_as(
        sqlx::query_as::<_, ModelErrorEntry>(sqlx::AssertSqlSafe(&*model_sql)).bind(tenant_id),
    );
    let by_model = model_query.fetch_all(&mut *conn).await
        .map_err(|e| {
            tracing::error!("error analytics by_model: {e}");
            ApiError::internal("database query failed")
        })?;

    Ok(ErrorAnalytics {
        total_errors,
        by_category,
        by_status_code,
        by_model,
    })
}

/// Media endpoint usage of the window.
pub(crate) async fn media_analytics(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<MediaAnalyticsResponse, ApiError> {
    // The workspace filter binds at $4 (after tenant/start/end). `g.workspace_id`
    // is qualified (ambiguous bare across the audit join).
    let workspace_ids = scope.workspace_ids;
    // $1 is the tenant; the window and the workspaces bind after it, and the
    // current currency's code after them.
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
    if let Some(ws) = &workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let scope = filters.where_sql();
    let current_bind = filters.next_bind_idx();

    // --- Direction-based breakdown ---
    // Media endpoint requests: derive category + direction from the canonical
    // media_call.endpoint discriminator. Chat media (vision/input/output):
    // derive category + direction from chat_media_summary JSONB entries.
    // `ELSE 'unknown'` surfaces forward-compat drift: any endpoint string not in the
    // closed set (e.g. a new upstream endpoint family before we add a DomainMediaEndpoint
    // variant) lands in its own bucket instead of silently disappearing into 'other'.
    let media_category = "CASE (media_call->>'endpoint') \
        WHEN 'embeddings' THEN 'embedding' \
        WHEN 'audio_speech' THEN 'audio' \
        WHEN 'audio_transcription' THEN 'audio' \
        WHEN 'audio_translation' THEN 'audio' \
        WHEN 'image_generation' THEN 'image' \
        WHEN 'image_edit' THEN 'image' \
        WHEN 'image_variation' THEN 'image' \
        WHEN 'video_generation' THEN 'video' \
        ELSE 'unknown' END";
    let media_direction = "CASE (media_call->>'endpoint') \
        WHEN 'embeddings' THEN 'encode' \
        WHEN 'audio_speech' THEN 'speech' \
        WHEN 'audio_transcription' THEN 'transcription' \
        WHEN 'audio_translation' THEN 'translation' \
        WHEN 'image_generation' THEN 'generation' \
        WHEN 'image_edit' THEN 'edit' \
        WHEN 'image_variation' THEN 'edit' \
        WHEN 'video_generation' THEN 'generation' \
        ELSE 'unknown' END";
    let media_units = "COALESCE((media_call->>'output_units')::int, 0)";

    let direction_sql = format!(
        r#"SELECT category, direction, SUM(req_count)::bigint as requests,
            SUM(units)::bigint as units, COALESCE(SUM(cost), 0.0)::double precision as amount,
            COUNT(DISTINCT cost_currency)::bigint as currency_count, MIN(cost_currency) as currency,
            COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY p95_val), 0)::double precision as p95_latency
        FROM (
            SELECT {cat} as category, {dir} as direction,
                1::bigint as req_count, {units}::bigint as units,
                COALESCE(cost, 0) as cost, cost_currency, latency_total_ms as p95_val
            FROM {AUDIT_LOG_JOIN}
            WHERE tenant_id = $1{scope}
                AND media_call IS NOT NULL
            UNION ALL
            SELECT
                CASE WHEN entry->>'media_type' LIKE 'image/%' THEN 'image'
                     WHEN entry->>'media_type' LIKE 'audio/%' THEN 'audio'
                     WHEN entry->>'media_type' LIKE 'video/%' THEN 'video' ELSE 'image' END,
                CASE WHEN entry->>'media_type' LIKE 'image/%' THEN 'vision'
                     WHEN entry->>'media_type' LIKE 'audio/%' THEN 'input' ELSE 'vision' END,
                1::bigint, 0::bigint,
                COALESCE(cost, 0)::double precision / GREATEST(jsonb_array_length(chat_media_summary), 1),
                cost_currency,
                latency_total_ms
            FROM {AUDIT_LOG_JOIN}, jsonb_array_elements(chat_media_summary) AS entry
            WHERE tenant_id = $1{scope}
                AND chat_media_summary IS NOT NULL
                AND media_call IS NULL
        ) sub GROUP BY category, direction ORDER BY requests DESC, category, direction"#,
        cat = media_category,
        dir = media_direction,
        units = media_units,
    );

    let direction_rows: Vec<MediaDirectionRow> = {
        let q = filters.apply_query_as(sqlx::query_as(sqlx::AssertSqlSafe(&*direction_sql)).bind(tenant_id));
        // This query IS the response's `directions`, so a failure must surface
        // as one — zeros are indistinguishable from "no media traffic", and the
        // UI has no way to tell them apart.
        q.fetch_all(&mut *conn).await.map_err(|e| {
            tracing::error!("media direction aggregate: {e}");
            ApiError::internal("database query failed")
        })?
    };

    // Every group holds at least one row, so no zero needs denominating here;
    // the current currency leads the users' spend ranking below.
    let current = crate::routes::pricing::accounting_currency(&mut *conn).await;
    let directions: Vec<MediaDirectionStat> = direction_rows
        .into_iter()
        .map(|MediaDirectionRow { category, direction, requests, units, amount, currency_count, currency, p95_latency: p95 }| {
            let label = match (category.as_str(), direction.as_str()) {
                ("image", "generation") => "text → image",
                ("image", "vision") => "image → text",
                ("audio", "speech") => "text → audio",
                ("audio", "transcription") => "audio → text",
                ("audio", "input") => "audio → text",
                ("embedding", "encode") => "text → vector",
                ("video", "generation") => "text → video",
                ("unknown", _) => "unrecognized endpoint",
                _ => "other",
            }.to_string();
            MediaDirectionStat {
                category,
                direction,
                label,
                requests,
                units,
                spend: spend_total(currency_count, currency, amount, current),
                p95_latency: if p95 > 0.0 { Some(p95) } else { None },
            }
        })
        .collect();

    // --- Top users with per-type columns ---
    // Image / audio counts include both media RPCs (via media_call.endpoint)
    // and chat turns carrying embedded media (via chat_media_summary).
    let image_count = "SUM(CASE WHEN (a.media_call->>'endpoint') IN ('image_generation','image_edit','image_variation') \
        OR (a.chat_media_summary IS NOT NULL AND a.chat_media_summary::text LIKE '%image/%') THEN 1 ELSE 0 END)";
    let audio_count = "SUM(CASE WHEN (a.media_call->>'endpoint') IN ('audio_speech','audio_transcription','audio_translation') \
        OR (a.chat_media_summary IS NOT NULL AND a.chat_media_summary::text LIKE '%audio/%') THEN 1 ELSE 0 END)";
    let embedding_count = "SUM(CASE WHEN (a.media_call->>'endpoint') = 'embeddings' THEN 1 ELSE 0 END)";
    let video_count = "SUM(CASE WHEN (a.media_call->>'endpoint') = 'video_generation' THEN 1 ELSE 0 END)";

    // Ranked by `SpendRank`: never two amounts in different denominations
    // compared. The current currency's code binds after the workspace filter.
    let user_sql = format!(
        r#"SELECT COALESCE(u.email, g.user_id::text) AS user_email, COUNT(*)::bigint AS total_requests,
            {SPEND_TOTAL_COLUMNS},
            COALESCE({img}, 0)::bigint AS image_requests,
            COALESCE({aud}, 0)::bigint AS audio_requests,
            COALESCE({emb}, 0)::bigint AS embedding_requests,
            COALESCE({vid}, 0)::bigint AS video_requests
        FROM {AUDIT_LOG_JOIN} LEFT JOIN users u ON g.user_id = u.id
        WHERE a.tenant_id = $1{scope}
            AND (a.media_call IS NOT NULL OR a.chat_media_summary IS NOT NULL)
        GROUP BY 1 ORDER BY {rank}, COUNT(*) DESC, 1 LIMIT 10"#,
        img = image_count,
        aud = audio_count,
        emb = embedding_count,
        vid = video_count,
        rank = spend_rank_order_sql(current_bind),
    );

    let user_rows: Vec<MediaUserRow> = {
        let q = filters
            .apply_query_as(sqlx::query_as(sqlx::AssertSqlSafe(&*user_sql)).bind(tenant_id))
            .bind(current.as_str().to_owned());
        q.fetch_all(&mut *conn).await.map_err(|e| {
            tracing::error!("media per-user aggregate: {e}");
            ApiError::internal("database query failed")
        })?
    };

    let users: Vec<MediaUserStat> = user_rows
        .into_iter()
        .map(|r| MediaUserStat {
            user_email: r.user_email,
            total_requests: r.total_requests,
            spend: spend_total(r.currency_count, r.currency, r.amount, current),
            image_requests: r.image_requests,
            audio_requests: r.audio_requests,
            embedding_requests: r.embedding_requests,
            video_requests: r.video_requests,
        })
        .collect();

    Ok(MediaAnalyticsResponse { directions, users })
}

/// Response-cache activity of the window.
pub(crate) async fn cache_analytics(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    workspace_ids: Option<Vec<Uuid>>,
) -> Result<CacheAnalyticsResponse, ApiError> {
    // `llm_audit` alone, not `AUDIT_LOG_JOIN`: every column here is LLM-side and
    // denormalized (tenant_id, workspace_id, timestamp), so the join would only
    // cost a lookup per row — and skipping it lets `cache_mode IS NOT NULL` ride
    // the partial index that exists for exactly this query.
    // Denominates the zero of a window with no cached savings, and leads the
    // aliases' spend ranking.
    let current = crate::routes::pricing::accounting_currency(&mut *conn).await;
    // $1 is the tenant; the window and the workspaces bind after it, and the
    // current currency's code after them in the savings aggregate.
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(&["timestamp"], (start_ts, end_ts));
    if let Some(ws) = &workspace_ids {
        filters.push_workspaces("workspace_id", ws);
    }
    let scope = filters.where_sql();
    let current_bind = filters.next_bind_idx();
    // A row that carries a savings figure. Only these name the currency an
    // alias's savings are in: a bypassed or missed request records no money,
    // and its currency must not make an alias's savings read as mixed.
    const SAVING: &str = "((cache_outcome IN ('hit', 'observe_hit') AND avoided_cost <> 0) OR embedding_cost <> 0)";
    let sql = format!(
        r#"SELECT model_requested, cache_mode,
            COUNT(*) FILTER (WHERE cache_outcome <> 'bypass')::bigint AS lookups,
            COUNT(*) FILTER (WHERE cache_outcome = 'bypass')::bigint AS bypassed,
            COUNT(*) FILTER (WHERE cache_outcome = 'hit')::bigint AS hits,
            COUNT(*) FILTER (WHERE cache_outcome = 'observe_hit')::bigint AS observe_hits,
            COALESCE(SUM(avoided_cost) FILTER (WHERE cache_outcome = 'hit'), 0)::double precision AS gross_avoided,
            COALESCE(SUM(avoided_cost) FILTER (WHERE cache_outcome = 'observe_hit'), 0)::double precision AS would_avoid,
            COALESCE(SUM(embedding_cost), 0)::double precision AS embedding_cost,
            COUNT(DISTINCT cost_currency) FILTER (WHERE {SAVING})::bigint AS currency_count,
            MIN(cost_currency) FILTER (WHERE {SAVING}) AS currency,
            BOOL_OR({SAVING} AND cost_currency = ${current_bind}) AS saved_in_current,
            COALESCE(SUM(avoided_cost) FILTER (WHERE cache_outcome = 'hit' AND cost_currency = ${current_bind}), 0)::double precision AS gross_avoided_in_current,
            COALESCE(SUM(embedding_cost) FILTER (WHERE cost_currency = ${current_bind}), 0)::double precision AS embedding_cost_in_current
        FROM llm_audit
        WHERE tenant_id = $1{scope}
            AND cache_mode IS NOT NULL
        GROUP BY model_requested, cache_mode"#
    );

    let rows: Vec<CacheAliasRow> = {
        let q = filters
            .apply_query_as(sqlx::query_as(sqlx::AssertSqlSafe(&*sql)).bind(tenant_id))
            .bind(current.as_str().to_owned());
        // Every headline figure below is derived from these rows, so a failed
        // query must surface as an error rather than as a zero-savings report
        // the operator would read as "the cache is not being used".
        q.fetch_all(&mut *conn).await.map_err(|e| {
            tracing::error!("cache savings aggregate: {e}");
            ApiError::internal("database query failed")
        })?
    };

    // Why the cache did not do its job, straight off the audit badges the
    // pipeline already stamps — the reasons are only ever recorded there, so
    // this is a second pass over the same rows rather than more columns on the
    // aggregate above. Same `cache_mode IS NOT NULL` predicate, so it rides the
    // same partial index and covers exactly the cache-enabled aliases.
    let skip_sql = format!(
        r#"SELECT model_requested, cache_mode, b->>'code' AS code, b->>'reason' AS reason,
            COUNT(*)::bigint AS count
        FROM llm_audit, LATERAL jsonb_array_elements(badges) AS b
        WHERE tenant_id = $1{scope}
            AND cache_mode IS NOT NULL
            AND b->>'code' IN ('cache_store_skipped', 'cache_semantic_skipped')
        GROUP BY model_requested, cache_mode, b->>'code', b->>'reason'"#
    );
    let skip_rows: Vec<CacheSkipRow> = {
        let q = filters.apply_query_as(sqlx::query_as(sqlx::AssertSqlSafe(&*skip_sql)).bind(tenant_id));
        match q.fetch_all(&mut *conn).await {
            Ok(rows) => rows,
            // The savings figures above are still worth returning, but an empty
            // skip list is indistinguishable from "nothing was skipped" — which
            // is the exact silent degradation this whole breakdown exists to
            // end. Say so in the log rather than only in the response.
            Err(e) => {
                tracing::warn!("cache skip-reason aggregate failed: {e}");
                Vec::new()
            }
        }
    };
    // Keyed by `(alias, mode)`, matching the aggregate's own grouping: a skip
    // belongs to the policy that was in force when it happened, so an alias
    // whose preset changed mid-window attributes each reason to the mode that
    // produced it — and an exact-mode group can never show a semantic skip.
    let mut store_skips: HashMap<(String, String), Vec<CacheSkipStat>> = HashMap::new();
    let mut semantic_skips: HashMap<(String, String), Vec<CacheSkipStat>> = HashMap::new();
    // Tenant-wide totals are summed from the query rows, never by folding up
    // the per-group lists — summing at this finer grouping is the same total,
    // whereas re-adding the per-alias lists would count a reason once per mode.
    let mut store_totals: HashMap<String, i64> = HashMap::new();
    let mut semantic_totals: HashMap<String, i64> = HashMap::new();
    for r in skip_rows {
        // A badge with no `reason` cannot happen — both variants carry one —
        // but a missing key must not silently become a zero-count bucket.
        let Some(reason) = r.reason else { continue };
        let semantic = r.code.as_deref() == Some("cache_semantic_skipped");
        let (by_group, totals) = if semantic {
            (&mut semantic_skips, &mut semantic_totals)
        } else {
            (&mut store_skips, &mut store_totals)
        };
        *totals.entry(reason.clone()).or_insert(0) += r.count;
        by_group
            .entry((r.model_requested, r.cache_mode))
            .or_default()
            .push(CacheSkipStat { reason, count: r.count });
    }
    for list in store_skips.values_mut().chain(semantic_skips.values_mut()) {
        sort_skips(list);
    }

    let mut out = CacheAnalyticsResponse {
        lookups: 0,
        bypassed: 0,
        hits: 0,
        observe_hits: 0,
        hit_rate: 0.0,
        savings: None,
        store_skips: Vec::new(),
        semantic_skips: Vec::new(),
        aliases: Vec::with_capacity(rows.len()),
    };
    // The window's money figures are summed across the groups only while every
    // group is in one and the same currency.
    let mut totals = CacheSavings {
        currency: current,
        gross_avoided: 0.0,
        would_avoid: 0.0,
        embedding_cost: 0.0,
        tuning_cost: 0.0,
        net_saved: 0.0,
    };
    let mut denomination: Option<streamscope_core::pricing::Currency> = None;
    let mut straddles = false;
    // Each alias's rank key, kept beside it until the sort.
    let mut ranks: Vec<SpendRank> = Vec::with_capacity(rows.len());

    for r in rows {
        // An observe alias's embedding spend is measurement, not running cost —
        // the split the whole net-saved figure depends on.
        let observing = r.cache_mode == "observe";
        let enforcing_embedding = if observing { 0.0 } else { r.embedding_cost };

        out.lookups += r.lookups;
        out.bypassed += r.bypassed;
        out.hits += r.hits;
        out.observe_hits += r.observe_hits;

        // A group with no savings row holds only zeros, stated in today's
        // currency; it names no denomination for the totals.
        let saved_anything = r.currency_count > 0;
        let lowest_currency = r.currency.as_deref().and_then(streamscope_core::pricing::Currency::parse);
        ranks.push(cache_alias_rank(&r, observing, lowest_currency, current));
        let savings = spend_total(r.currency_count, r.currency, 0.0, current).map(|s| {
            CacheAliasSavings {
                currency: s.currency,
                gross_avoided: r.gross_avoided,
                would_avoid: r.would_avoid,
                embedding_cost: r.embedding_cost,
                net_saved: r.gross_avoided - enforcing_embedding,
            }
        });
        match &savings {
            Some(_) if !saved_anything => {}
            Some(s) if denomination.is_none_or(|d| d == s.currency) => {
                denomination = Some(s.currency);
                totals.gross_avoided += r.gross_avoided;
                totals.would_avoid += r.would_avoid;
                totals.embedding_cost += enforcing_embedding;
                totals.tuning_cost += if observing { r.embedding_cost } else { 0.0 };
            }
            _ => straddles = true,
        }


        let group = (r.model_requested, r.cache_mode);
        out.aliases.push(CacheAliasStat {
            store_skips: store_skips.remove(&group).unwrap_or_default(),
            semantic_skips: semantic_skips.remove(&group).unwrap_or_default(),
            alias: group.0,
            mode: group.1,
            lookups: r.lookups,
            hits: r.hits,
            observe_hits: r.observe_hits,
            hit_rate: rate(r.hits, r.lookups),
            savings,
        });
    }

    out.store_skips = collect_skips(store_totals);
    out.semantic_skips = collect_skips(semantic_totals);
    out.hit_rate = rate(out.hits, out.lookups);
    if !straddles {
        totals.currency = denomination.unwrap_or(current);
        totals.net_saved = totals.gross_avoided - totals.embedding_cost;
        out.savings = Some(totals);
    }
    // Richest first under the shared spend rule, so the alias actually paying
    // for itself leads; equal figures by traffic, then by name.
    let mut ranked: Vec<(SpendRank, CacheAliasStat)> = ranks.into_iter().zip(out.aliases).collect();
    ranked.sort_by(|(ra, a), (rb, b)| {
        ra.cmp(rb)
            .then_with(|| b.lookups.cmp(&a.lookups))
            .then_with(|| a.alias.cmp(&b.alias))
            .then_with(|| a.mode.cmp(&b.mode))
    });
    out.aliases = ranked.into_iter().map(|(_, a)| a).collect();

    Ok(out)
}

/// Gateway-wide totals of the window across every protocol.
pub(crate) async fn cross_overview(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<CrossOverview, ApiError> {
    // gateway_audit alone — no JOIN needed; error_category covers both LLM
    // (finish_reason='error' propagated) and MCP (-32xxx codes propagated).
    let mut filters = AnalyticsFilterBuilder::new(2);
    if let Some(uid) = scope.user_id {
        filters.push_eq_uuid("user_id", uid);
    }
    filters.push_time_window(&["timestamp"], (start_ts, end_ts));
    if let Some(ws) = &scope.workspace_ids {
        filters.push_workspaces("workspace_id", ws);
    }

    let sql = format!(
        "SELECT \
            COUNT(*)::bigint as total_requests, \
            COALESCE(SUM(CASE WHEN error_category IS NOT NULL THEN 1 ELSE 0 END), 0)::bigint as error_count, \
            COALESCE(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_total_ms), 0)::double precision as p50_latency_ms, \
            COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_total_ms), 0)::double precision as p95_latency_ms, \
            COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_total_ms), 0)::double precision as p99_latency_ms \
         FROM gateway_audit WHERE tenant_id = $1{}",
        filters.where_sql()
    );
    let q = filters.apply_query_as(
        sqlx::query_as::<_, CrossOverviewRow>(sqlx::AssertSqlSafe(&*sql)).bind(tenant_id),
    );
    let row = q.fetch_optional(&mut *conn).await.map_err(|e| {
        tracing::error!("cross overview: {e}");
        ApiError::internal("database query failed")
    })?;

    // Sessions are cross-protocol (one session can hold both LLM and MCP turns).
    let mut sess_filters = AnalyticsFilterBuilder::new(2);
    if let Some(uid) = scope.user_id {
        sess_filters.push_eq_uuid("user_id", uid);
    }
    sess_filters.push_time_window(&["updated_at"], (start_ts, end_ts));
    if let Some(ws) = &scope.workspace_ids {
        sess_filters.push_workspaces("sessions.workspace_id", ws);
    }
    let sess_sql = format!(
        "SELECT COUNT(*)::bigint FROM sessions WHERE tenant_id = $1{}",
        sess_filters.where_sql()
    );
    let total_sessions: i64 = sess_filters
        .apply_query_scalar(sqlx::query_scalar(sqlx::AssertSqlSafe(&*sess_sql)).bind(tenant_id))
        .fetch_one(&mut *conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("cross overview session count: {e}");
            0
        });

    let r = row.unwrap_or(CrossOverviewRow {
        total_requests: None,
        error_count: None,
        p50_latency_ms: None,
        p95_latency_ms: None,
        p99_latency_ms: None,
    });

    Ok(CrossOverview {
        total_requests: r.total_requests.unwrap_or(0),
        total_sessions,
        error_count: r.error_count.unwrap_or(0),
        p50_latency_ms: r.p50_latency_ms.unwrap_or(0.0),
        p95_latency_ms: r.p95_latency_ms.unwrap_or(0.0),
        p99_latency_ms: r.p99_latency_ms.unwrap_or(0.0),
    })
}

/// Gateway-wide traffic of the window per bucket, across every protocol.
pub(crate) async fn cross_timeseries(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
) -> Result<CrossTimeseriesResponse, ApiError> {
    // Bucket granularity tracks the window: hourly for short, daily for long.
    let interval = bucket_interval(start_ts, end_ts);

    let mut filters = AnalyticsFilterBuilder::new(2);
    if let Some(uid) = scope.user_id {
        filters.push_eq_uuid("user_id", uid);
    }
    filters.push_time_window(&["timestamp"], (start_ts, end_ts));
    if let Some(ws) = &scope.workspace_ids {
        filters.push_workspaces("workspace_id", ws);
    }

    let sql = format!(
        "SELECT \
            date_trunc('{interval}', timestamp) AS bucket, \
            SUM(CASE WHEN kind = 'llm' THEN 1 ELSE 0 END)::bigint AS llm_count, \
            SUM(CASE WHEN kind = 'mcp' THEN 1 ELSE 0 END)::bigint AS mcp_count, \
            SUM(CASE WHEN kind = 'a2a' THEN 1 ELSE 0 END)::bigint AS a2a_count, \
            SUM(CASE WHEN error_category IS NOT NULL THEN 1 ELSE 0 END)::bigint AS error_count \
         FROM gateway_audit WHERE tenant_id = $1{} \
         GROUP BY bucket ORDER BY bucket",
        filters.where_sql()
    );
    let q = filters.apply_query_as(
        sqlx::query_as::<_, CrossTimeseriesRow>(sqlx::AssertSqlSafe(&*sql)).bind(tenant_id),
    );
    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("cross timeseries: {e}");
        ApiError::internal("database query failed")
    })?;

    let by_bucket: std::collections::HashMap<DateTime<Utc>, (i64, i64, i64, i64)> = rows
        .into_iter()
        .filter_map(|r| {
            r.bucket.map(|b| {
                (
                    b,
                    (
                        r.llm_count.unwrap_or(0),
                        r.mcp_count.unwrap_or(0),
                        r.a2a_count.unwrap_or(0),
                        r.error_count.unwrap_or(0),
                    ),
                )
            })
        })
        .collect();
    let buckets: Vec<CrossTimeseriesBucket> = build_bucket_axis(start_ts, end_ts, interval)
        .into_iter()
        .map(|ts| {
            let (llm, mcp, a2a, err) = by_bucket.get(&ts).copied().unwrap_or_default();
            CrossTimeseriesBucket {
                bucket_start: ts,
                llm_count: llm,
                mcp_count: mcp,
                a2a_count: a2a,
                error_count: err,
            }
        })
        .collect();

    Ok(CrossTimeseriesResponse {
        interval: interval.to_string(),
        buckets,
    })
}

/// The top upstreams of the window per bucket.
pub(crate) async fn cross_upstream_timeseries(
    conn: &mut Scoped,
    tenant_id: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
    scope: AnalyticsScope,
    limit: i64,
    query: &UpstreamTimeseriesQuery,
) -> Result<UpstreamTimeseriesResponse, ApiError> {
    let interval = bucket_interval(start_ts, end_ts);

    // Build the filter clause. `$1` = tenant_id, `$2` / `$3` = window bounds,
    // `$4` = limit. Optional `user_id` takes 5+ as added.
    let mut filters = AnalyticsFilterBuilder::new(5);
    if let Some(uid) = scope.user_id {
        filters.push_eq_uuid("g.user_id", uid);
    }
    if let Some(ws) = &scope.workspace_ids {
        filters.push_workspaces("g.workspace_id", ws);
    }
    let extra = filters.where_sql().to_string();

    let sql = match query.kind {
        UpstreamTimeseriesKind::Llm => format!(
            "WITH filtered AS ( \
                 SELECT \
                     a.upstream_server_id, \
                     date_trunc('{interval}', g.timestamp) AS bucket \
                 FROM {AUDIT_LOG_JOIN} \
                 WHERE g.tenant_id = $1 \
                   AND g.kind = 'llm' \
                   {window} \
                   AND a.upstream_server_id IS NOT NULL \
                   AND a.cache_outcome IS DISTINCT FROM 'hit'{extra} \
             ), \
             per_bucket AS ( \
                 SELECT upstream_server_id, bucket, COUNT(*)::bigint AS bucket_count \
                 FROM filtered \
                 GROUP BY upstream_server_id, bucket \
             ), \
             totals AS ( \
                 SELECT upstream_server_id, SUM(bucket_count)::bigint AS total \
                 FROM per_bucket \
                 GROUP BY upstream_server_id \
                 ORDER BY total DESC, upstream_server_id \
                 LIMIT $4 \
             ) \
             SELECT COALESCE(s.name, t.upstream_server_id::text) AS key, pb.bucket, pb.bucket_count, t.total \
             FROM totals t \
             JOIN per_bucket pb USING (upstream_server_id) \
             LEFT JOIN upstream_servers s ON s.id = t.upstream_server_id \
             ORDER BY t.total DESC, t.upstream_server_id, pb.bucket",
            window = window_sql(AUDIT_LOG_WINDOW, 2, 3),
        ),
        UpstreamTimeseriesKind::Mcp => format!(
            "WITH filtered AS ( \
                 SELECT \
                     m.upstream_server_id, \
                     date_trunc('{interval}', g.timestamp) AS bucket \
                 FROM {MCP_AUDIT_JOIN} \
                 WHERE g.tenant_id = $1 \
                   AND g.kind = 'mcp' \
                   {window} \
                   AND m.upstream_server_id IS NOT NULL{extra} \
             ), \
             per_bucket AS ( \
                 SELECT upstream_server_id, bucket, COUNT(*)::bigint AS bucket_count \
                 FROM filtered \
                 GROUP BY upstream_server_id, bucket \
             ), \
             totals AS ( \
                 SELECT upstream_server_id, SUM(bucket_count)::bigint AS total \
                 FROM per_bucket \
                 GROUP BY upstream_server_id \
                 ORDER BY total DESC, upstream_server_id \
                 LIMIT $4 \
             ) \
             SELECT t.upstream_server_id::text AS key, pb.bucket, pb.bucket_count, t.total \
             FROM totals t \
             JOIN per_bucket pb USING (upstream_server_id) \
             ORDER BY t.total DESC, t.upstream_server_id, pb.bucket",
            window = window_sql(MCP_AUDIT_WINDOW, 2, 3),
        ),
        // A2A's upstream is the registered agent; the key is its slug, matching
        // the `by-agent` dashboard pivot so the two surfaces line up.
        UpstreamTimeseriesKind::A2a => format!(
            "WITH filtered AS ( \
                 SELECT \
                     a2.agent_id, \
                     date_trunc('{interval}', g.timestamp) AS bucket \
                 FROM {A2A_AUDIT_JOIN} \
                 WHERE g.tenant_id = $1 \
                   AND g.kind = 'a2a' \
                   {window} \
                   AND a2.agent_id IS NOT NULL{extra} \
             ), \
             per_bucket AS ( \
                 SELECT agent_id, bucket, COUNT(*)::bigint AS bucket_count \
                 FROM filtered \
                 GROUP BY agent_id, bucket \
             ), \
             totals AS ( \
                 SELECT agent_id, SUM(bucket_count)::bigint AS total \
                 FROM per_bucket \
                 GROUP BY agent_id \
                 ORDER BY total DESC, agent_id \
                 LIMIT $4 \
             ) \
             SELECT COALESCE(ag.slug, t.agent_id::text) AS key, pb.bucket, pb.bucket_count, t.total \
             FROM totals t \
             JOIN per_bucket pb USING (agent_id) \
             LEFT JOIN a2a_upstream_agents ag ON ag.id = t.agent_id \
             ORDER BY t.total DESC, t.agent_id, pb.bucket",
            window = window_sql(A2A_AUDIT_WINDOW, 2, 3),
        ),
    };

    let q = filters.apply_query_as(
        sqlx::query_as::<_, UpstreamBucketRow>(sqlx::AssertSqlSafe(&*sql))
            .bind(tenant_id)
            .bind(start_ts)
            .bind(end_ts)
            .bind(limit),
    );

    let rows = q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("cross upstream-timeseries: {e}");
        ApiError::internal("database query failed")
    })?;

    // Materialise shared bucket axis covering the full window so empty buckets
    // render as zero on the sparkline (otherwise the line collapses to whatever
    // buckets had traffic).
    let bucket_starts = build_bucket_axis(start_ts, end_ts, interval);
    let bucket_index: std::collections::HashMap<DateTime<Utc>, usize> = bucket_starts
        .iter()
        .enumerate()
        .map(|(i, ts)| (*ts, i))
        .collect();

    // Pivot rows: keep the order of first appearance (already sorted by total DESC).
    let mut order: Vec<String> = Vec::new();
    let mut by_key: std::collections::HashMap<String, (i64, Vec<i64>)> =
        std::collections::HashMap::new();
    for row in rows {
        let entry = by_key.entry(row.key.clone()).or_insert_with(|| {
            order.push(row.key.clone());
            (row.total, vec![0; bucket_starts.len()])
        });
        if let Some(&idx) = bucket_index.get(&row.bucket) {
            entry.1[idx] = row.bucket_count;
        }
    }

    let upstreams: Vec<UpstreamSparkline> = order
        .into_iter()
        .map(|key| {
            let (total, buckets) = by_key.remove(&key).unwrap();
            UpstreamSparkline { key, total, buckets }
        })
        .collect();

    Ok(UpstreamTimeseriesResponse {
        interval: interval.to_string(),
        bucket_starts,
        upstreams,
    })
}

/// One tenant's totals over the window, its agent workspace left out.
#[derive(sqlx::FromRow)]
pub(crate) struct TenantUsageTotals {
    pub requests: i64,
    pub prompt_tokens: i64,
    pub completion_tokens: i64,
    pub cache_creation_tokens: i64,
    pub cache_read_tokens: i64,
    pub reasoning_tokens: i64,
    pub amount: f64,
    pub currency_count: i64,
    pub currency: Option<String>,
    pub errors: i64,
    pub active_users: i64,
    /// The spend per currency: one entry for a window in one currency, one
    /// per currency for a window straddling a change, none for no traffic.
    /// Filled by [`tenant_usage_totals`], not the row.
    #[sqlx(skip)]
    pub spend_parts: Vec<SpendTotal>,
}

/// The window's spend per currency, largest first: the second, grouped pass
/// an aggregate over [`SPEND_TOTAL_COLUMNS`] needs once it finds more than one
/// currency — and only then, since it scans the same rows again.
///
/// `head` is the query's leading condition, a constant; `tenant` binds at `$1`
/// when `head` names it (`binds_tenant`), and `filters` carries every later
/// bind.
async fn spend_by_currency(
    conn: &mut Scoped,
    head: &'static str,
    tenant: Uuid,
    binds_tenant: bool,
    filters: &AnalyticsFilterBuilder,
) -> sqlx::Result<Vec<SpendBreakdown>> {
    let sql = format!(
        "SELECT {} FROM {AUDIT_LOG_JOIN} WHERE {head}{} GROUP BY a.cost_currency",
        crate::routes::spend_breakdown_columns(),
        filters.where_sql()
    );
    let mut q = sqlx::query(sqlx::AssertSqlSafe(&*sql));
    if binds_tenant {
        q = q.bind(tenant);
    }
    let rows = filters.apply_query(q).fetch_all(&mut *conn).await?;
    Ok(crate::routes::read_spend_breakdowns(&rows, tenant))
}

/// One tenant's totals over the window, its agent workspace left out.
pub(crate) async fn tenant_usage_totals(
    conn: &mut Scoped,
    tenant: Uuid,
    start_ts: DateTime<Utc>,
    end_ts: DateTime<Utc>,
) -> sqlx::Result<TenantUsageTotals> {
    const NOT_AGENT: &str = "NOT COALESCE(g.workspace_id = \
             (SELECT id FROM workspaces WHERE role = 'agent' LIMIT 1), false)";
    let mut filters = AnalyticsFilterBuilder::new(1);
    filters.push_time_window(AUDIT_LOG_WINDOW, (start_ts, end_ts));
    let select_clause = format!(
        "SELECT \
            COUNT(*)::bigint AS requests, \
            COALESCE(SUM(prompt_tokens), 0)::bigint AS prompt_tokens, \
            COALESCE(SUM(completion_tokens), 0)::bigint AS completion_tokens, \
            COALESCE(SUM(cache_creation_tokens), 0)::bigint AS cache_creation_tokens, \
            COALESCE(SUM(cache_read_tokens), 0)::bigint AS cache_read_tokens, \
            COALESCE(SUM(reasoning_tokens), 0)::bigint AS reasoning_tokens, \
            {SPEND_TOTAL_COLUMNS}, \
            COUNT(*) FILTER (WHERE error_category IS NOT NULL)::bigint AS errors, \
            COUNT(DISTINCT user_id)::bigint AS active_users \
         FROM {AUDIT_LOG_JOIN} \
         WHERE {NOT_AGENT}{}",
        filters.where_sql()
    );

    // An aggregate with no GROUP BY answers exactly one row.
    let mut totals: TenantUsageTotals = filters
        .apply_query_as(sqlx::query_as(sqlx::AssertSqlSafe(&*select_clause)))
        .fetch_one(&mut *conn)
        .await?;

    totals.spend_parts = match totals.currency_count {
        0 => Vec::new(),
        // The one currency's part is the row itself, read as every stored
        // currency is (`stored_currency`: a code that does not parse states
        // no amount, and is logged).
        1 => totals
            .currency
            .as_deref()
            .and_then(|code| crate::routes::stored_currency(code, Some(tenant)))
            .map(|currency| SpendTotal { currency, amount: totals.amount })
            .into_iter()
            .collect(),
        _ => spend_by_currency(&mut *conn, NOT_AGENT, tenant, false, &filters)
            .await?
            .into_iter()
            .map(|b| SpendTotal { currency: b.currency, amount: b.amount })
            .collect(),
    };
    Ok(totals)
}

/// A cache alias's place in the ranking by net savings: the keys
/// `spend_rank_order_sql` states, over the alias's rows that carry a savings
/// figure. An alias with none saved nothing, which it reports as a zero in
/// today's currency — and ranks as one, ahead of an alias that lost money.
fn cache_alias_rank(
    r: &CacheAliasRow,
    observing: bool,
    lowest_currency: Option<streamscope_core::pricing::Currency>,
    current: streamscope_core::pricing::Currency,
) -> SpendRank {
    if r.currency_count == 0 {
        return SpendRank { in_current: Some(0.0), lowest_currency: Some(current), single: Some(0.0) };
    }
    let enforcing_embedding = if observing { 0.0 } else { r.embedding_cost };
    SpendRank {
        in_current: r.saved_in_current.unwrap_or(false).then_some(
            r.gross_avoided_in_current - if observing { 0.0 } else { r.embedding_cost_in_current },
        ),
        lowest_currency,
        single: (r.currency_count == 1).then_some(r.gross_avoided - enforcing_embedding),
    }
}

/// One `(category, direction)` group of the media dashboard.
#[derive(sqlx::FromRow)]
struct MediaDirectionRow {
    category: String,
    direction: String,
    requests: i64,
    units: i64,
    amount: f64,
    currency_count: i64,
    currency: Option<String>,
    p95_latency: f64,
}

/// One user of the media dashboard's spend ranking.
#[derive(sqlx::FromRow)]
struct MediaUserRow {
    user_email: String,
    total_requests: i64,
    amount: f64,
    currency_count: i64,
    currency: Option<String>,
    image_requests: i64,
    audio_requests: i64,
    embedding_requests: i64,
    video_requests: i64,
}

/// One user of the users & keys dashboard's spend ranking.
#[derive(sqlx::FromRow)]
struct TopUserRow {
    user_id: Uuid,
    email: Option<String>,
    display_name: Option<String>,
    request_count: i64,
    amount: f64,
    currency_count: i64,
    currency: Option<String>,
}

/// One key of the users & keys dashboard's busiest keys.
#[derive(sqlx::FromRow)]
struct TopKeyRow {
    key_id: Uuid,
    key_name: Option<String>,
    key_prefix: String,
    user_id: Uuid,
    user_email: Option<String>,
    user_display_name: Option<String>,
    request_count: i64,
    amount: f64,
    currency_count: i64,
    currency: Option<String>,
    last_used_at: Option<DateTime<Utc>>,
    workspace_name: Option<String>,
}

#[derive(sqlx::FromRow)]
struct SummaryRow {
    total_requests: Option<i64>,
    total_prompt_tokens: Option<i64>,
    total_completion_tokens: Option<i64>,
    total_cache_creation_tokens: Option<i64>,
    total_cache_read_tokens: Option<i64>,
    total_reasoning_tokens: Option<i64>,
    avg_latency_ms: Option<f64>,
    p50_latency_ms: Option<f64>,
    p95_latency_ms: Option<f64>,
    p99_latency_ms: Option<f64>,
    avg_ttft_ms: Option<f64>,
    p50_ttft_ms: Option<f64>,
    p95_ttft_ms: Option<f64>,
    error_count: Option<i64>,
    high_latency_count: Option<i64>,
    total_embedding_requests: Option<i64>,
    total_audio_requests: Option<i64>,
    total_image_requests: Option<i64>,
    total_video_requests: Option<i64>,
}

/// Read one row of a `usage_breakdown` aggregate.
///
/// Written by hand rather than derived because the per-unit spend columns are
/// generated from the closed `Unit` vocabulary — a derive would have to name
/// each of them, and would silently stop covering a unit added later.
fn read_breakdown_entry(row: &sqlx::postgres::PgRow) -> BreakdownEntry {
    use sqlx::Row;
    // One currency in the group is the ordinary case and the only one where a
    // single figure means anything; more than one is a window straddling a
    // currency change, and is reported as no figure at all.
    let spend = match row.try_get::<i64, _>("currency_count").unwrap_or(0) {
        1 => row
            .try_get::<String, _>("currency")
            .ok()
            .and_then(|c| streamscope_core::pricing::Currency::parse(&c))
            .map(|currency| SpendBreakdown {
                currency,
                amount: row.try_get("cost").unwrap_or(0.0),
                media: row.try_get("media_cost").unwrap_or(0.0),
                embedding: row.try_get("embedding_cost").unwrap_or(0.0),
                units: read_spend_units(row),
            }),
        _ => None,
    };
    BreakdownEntry {
        key: row.try_get("key").unwrap_or_else(|_| "unknown".to_string()),
        parent_key: row.try_get("parent_key").ok().flatten(),
        requests: row.try_get("requests").unwrap_or(0),
        prompt_tokens: row.try_get("prompt_tokens").unwrap_or(0),
        completion_tokens: row.try_get("completion_tokens").unwrap_or(0),
        spend,
        cache_creation_tokens: row.try_get("cache_creation_tokens").unwrap_or(0),
        cache_read_tokens: row.try_get("cache_read_tokens").unwrap_or(0),
        reasoning_tokens: row.try_get("reasoning_tokens").unwrap_or(0),
        streaming_count: row.try_get("streaming_count").unwrap_or(0),
        avg_latency_ms: row.try_get("avg_latency_ms").unwrap_or(0.0),
        p95_latency_ms: row.try_get("p95_latency_ms").unwrap_or(0.0),
        error_count: row.try_get("error_count").unwrap_or(0),
        high_latency_count: row.try_get("high_latency_count").unwrap_or(0),
        user_email: row.try_get("user_email").ok().flatten(),
        user_id: row.try_get("user_id").ok().flatten(),
        server_id: row.try_get("server_id").ok().flatten(),
    }
}

#[derive(sqlx::FromRow)]
struct ProtocolRow {
    api_version: Option<String>,
    request_count: Option<i64>,
    total_tokens: Option<i64>,
    error_count: Option<i64>,
    amount: f64,
    currency_count: i64,
    currency: Option<String>,
}

/// One `(alias, mode)` group as the aggregate returns it. `cache_mode` is
/// non-null by the query's own `IS NOT NULL` predicate.
#[derive(sqlx::FromRow)]
struct CacheAliasRow {
    model_requested: String,
    cache_mode: String,
    lookups: i64,
    bypassed: i64,
    hits: i64,
    observe_hits: i64,
    gross_avoided: f64,
    would_avoid: f64,
    embedding_cost: f64,
    /// Distinct currencies over the rows that carry a savings figure.
    currency_count: i64,
    currency: Option<String>,
    /// Whether a row carrying a savings figure is in today's currency.
    saved_in_current: Option<bool>,
    gross_avoided_in_current: f64,
    embedding_cost_in_current: f64,
}

/// One `(alias, badge code, reason)` group from the skip aggregate. `code` and
/// `reason` come out of the badge JSON, so both are nullable to the type system
/// even though the two badges this query selects always carry them.
#[derive(sqlx::FromRow)]
struct CacheSkipRow {
    model_requested: String,
    cache_mode: String,
    code: Option<String>,
    reason: Option<String>,
    count: i64,
}

/// Share of `total` that `part` represents, guarding the empty window.
fn rate(part: i64, total: i64) -> f64 {
    if total > 0 { part as f64 / total as f64 } else { 0.0 }
}

/// Commonest reason first, then by name so equal counts hold a stable order
/// across reloads rather than shuffling with the hash iteration.
fn sort_skips(list: &mut [CacheSkipStat]) {
    list.sort_by(|a, b| b.count.cmp(&a.count).then_with(|| a.reason.cmp(&b.reason)));
}

fn collect_skips(totals: HashMap<String, i64>) -> Vec<CacheSkipStat> {
    let mut out: Vec<CacheSkipStat> = totals
        .into_iter()
        .map(|(reason, count)| CacheSkipStat { reason, count })
        .collect();
    sort_skips(&mut out);
    out
}

#[derive(sqlx::FromRow)]
struct CrossOverviewRow {
    total_requests: Option<i64>,
    error_count: Option<i64>,
    p50_latency_ms: Option<f64>,
    p95_latency_ms: Option<f64>,
    p99_latency_ms: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct CrossTimeseriesRow {
    bucket: Option<DateTime<Utc>>,
    llm_count: Option<i64>,
    mcp_count: Option<i64>,
    a2a_count: Option<i64>,
    error_count: Option<i64>,
}

#[derive(sqlx::FromRow)]
struct UpstreamBucketRow {
    key: String,
    bucket: DateTime<Utc>,
    bucket_count: i64,
    total: i64,
}

#[cfg(test)]
mod cache_rank_tests {
    use super::*;
    use streamscope_core::pricing::Currency;

    fn alias(currency_count: i64, gross: f64, embedding: f64) -> CacheAliasRow {
        CacheAliasRow {
            model_requested: "a".into(),
            cache_mode: "semantic".into(),
            lookups: 1,
            bypassed: 0,
            hits: 0,
            observe_hits: 0,
            gross_avoided: gross,
            would_avoid: 0.0,
            embedding_cost: embedding,
            currency_count,
            currency: (currency_count > 0).then(|| "USD".to_string()),
            saved_in_current: Some(currency_count > 0),
            gross_avoided_in_current: gross,
            embedding_cost_in_current: embedding,
        }
    }

    #[test]
    fn an_alias_that_saved_nothing_ranks_as_a_zero_ahead_of_one_that_lost_money() {
        let usd = Currency::USD;
        let nothing = cache_alias_rank(&alias(0, 0.0, 0.0), false, None, usd);
        let losing = cache_alias_rank(&alias(1, 0.0, 0.5), false, Some(usd), usd);
        let saving = cache_alias_rank(&alias(1, 2.0, 0.5), false, Some(usd), usd);
        assert_eq!(losing.in_current, Some(-0.5));
        assert_eq!(nothing.cmp(&losing), std::cmp::Ordering::Less, "zero ranks ahead of a loss");
        // Positive control: a real saving still ranks ahead of the zero.
        assert_eq!(saving.cmp(&nothing), std::cmp::Ordering::Less);
    }
}
