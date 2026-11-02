//! The audit log lists: one per row family (`llm_audit`, `mcp_audit`,
//! `web_audit`, `a2a_audit`, each joined to its `gateway_audit` row) and their
//! `kind=all` merge. The user and the workspaces a list returns come from its
//! [`AuditScope`]; every other filter from its [`AuditQuery`].

use std::sync::LazyLock;

use uuid::Uuid;

use super::filters::{
    A2A_AUDIT_WINDOW, AUDIT_LOG_JOIN, AUDIT_LOG_WINDOW, MCP_AUDIT_WINDOW, WEB_AUDIT_WINDOW, since_sql, until_sql,
};
use super::scope::AuditScope;
use super::search::{SearchRows, SearchWalk};
use crate::sql_pattern::{contains_pattern, search_pattern};
use crate::db::tenant::Scoped;
use crate::routes::audit::{
    A2aAuditLogEntry, AuditKind, AuditLogEntry, AuditLogRow, AuditQuery, McpAuditLogEntry, WebAuditLogEntry,
};
use crate::routes::{ApiError, OffsetPage};

/// Whitelist for `a2a_audit.task_state` — the 1.0 task lifecycle. Anything else
/// is rejected at the handler rather than bound, so the filter can never widen
/// into an unexpected value.
const ALLOWED_A2A_TASK_STATES: &[&str] = &[
    "TASK_STATE_SUBMITTED",
    "TASK_STATE_WORKING",
    "TASK_STATE_COMPLETED",
    "TASK_STATE_FAILED",
    "TASK_STATE_CANCELED",
    "TASK_STATE_REJECTED",
    "TASK_STATE_INPUT_REQUIRED",
    "TASK_STATE_AUTH_REQUIRED",
];

/// Whitelist for `web_audit.surface`. Matches the literal `surface` values
/// the proxy emits — see `crates/streamscope-core/src/web/audit.rs`. Reject
/// anything else at the handler so unknown values can't sneak into the
/// inline SQL literal.
const ALLOWED_WEB_SURFACES: &[&str] = &["mcp", "substitution", "admin_test"];
const ALLOWED_WEB_OPERATIONS: &[&str] = &["search", "fetch"];

/// Whitelist for the `methods` query parameter. The closed list prevents
/// SQL injection through the comma-separated bind list and keeps the UI
/// contract narrow — only methods the Tool Calls feed currently renders.
const ALLOWED_MCP_METHODS: &[&str] = &[
    "tools/call",
    "resources/read",
    "prompts/get",
];

/// The same whitelist for the A2A arm — the seven client-addressable operations
/// of the 1.0 vocabulary. Per-kind, because the whitelists have no value in
/// common: screening an A2A method against the MCP list would reject every one of
/// them, leave an empty bind list, and drop the predicate — a filter that
/// silently returns everything.
const ALLOWED_A2A_METHODS: &[&str] = &[
    "SendMessage",
    "SendStreamingMessage",
    "GetTask",
    "ListTasks",
    "CancelTask",
    "SubscribeToTask",
    "GetExtendedAgentCard",
];

fn parse_method_filter(raw: &str) -> Vec<String> {
    parse_methods_against(raw, ALLOWED_MCP_METHODS)
}

fn parse_a2a_method_filter(raw: &str) -> Vec<String> {
    parse_methods_against(raw, ALLOWED_A2A_METHODS)
}

fn parse_methods_against(raw: &str, allowed: &[&str]) -> Vec<String> {
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .filter(|s| allowed.contains(s))
        .map(str::to_string)
        .collect()
}

/// Translate a coarse media-type category ("embedding" / "audio" / "image" /
/// "video") or a canonical `DomainMediaEndpoint::as_str` ("embeddings" /
/// "audio_speech" / …) into an inline SQL predicate on `media_call->>'endpoint'`.
/// Returns `None` for an unrecognized value so the caller can reject it rather
/// than silently match everything.
///
/// **Injection safety:** `category` is untrusted (it arrives on the query
/// string), and it is used only as the *scrutinee* of the match — never as SQL.
/// Each arm returns a finished `&'static str` fragment, so the returned SQL is a
/// compile-time constant and no caller-supplied byte can reach it. Keep the
/// `&'static str` in the return type: build the fragment with `format!` and the
/// guarantee decays back into a convention.
fn media_category_filter_sql(category: &str) -> Option<&'static str> {
    const EMBEDDINGS: &str = " AND (a.media_call->>'endpoint') IN ('embeddings')";
    const AUDIO_SPEECH: &str = " AND (a.media_call->>'endpoint') IN ('audio_speech')";
    const AUDIO_TRANSCRIPTION: &str = " AND (a.media_call->>'endpoint') IN ('audio_transcription')";
    const AUDIO_TRANSLATION: &str = " AND (a.media_call->>'endpoint') IN ('audio_translation')";
    const IMAGE_GENERATION: &str = " AND (a.media_call->>'endpoint') IN ('image_generation')";
    const IMAGE_EDIT: &str = " AND (a.media_call->>'endpoint') IN ('image_edit')";
    const IMAGE_VARIATION: &str = " AND (a.media_call->>'endpoint') IN ('image_variation')";
    const VIDEO_GENERATION: &str = " AND (a.media_call->>'endpoint') IN ('video_generation')";
    const AUDIO_ANY: &str = " AND (a.media_call->>'endpoint') \
                             IN ('audio_speech','audio_transcription','audio_translation')";
    const IMAGE_ANY: &str = " AND (a.media_call->>'endpoint') \
                             IN ('image_generation','image_edit','image_variation')";

    match category {
        "embedding" | "embeddings" => Some(EMBEDDINGS),
        "audio" => Some(AUDIO_ANY),
        "audio_speech" => Some(AUDIO_SPEECH),
        "audio_transcription" => Some(AUDIO_TRANSCRIPTION),
        "audio_translation" => Some(AUDIO_TRANSLATION),
        "image" => Some(IMAGE_ANY),
        "image_generation" => Some(IMAGE_GENERATION),
        "image_edit" => Some(IMAGE_EDIT),
        "image_variation" => Some(IMAGE_VARIATION),
        "video" | "video_generation" => Some(VIDEO_GENERATION),
        _ => None,
    }
}

/// Human-readable label for finish_reason values.
fn finish_reason_display(raw: &str) -> &'static str {
    match raw {
        "stop" => "completed",
        "length" => "truncated",
        "tool_calls" => "tool_call",
        "content_filter" => "filtered",
        "error" => "error",
        _ => "unknown",
    }
}

const ALL_COLUMNS: &str = "\
    g.request_id, g.timestamp, g.user_id, g.tenant_id, g.app_id, g.session_id, \
    ct.session_id AS conversation_session_id, \
    g.user_agent, g.detection_method, \
    g.client_ip, g.end_user, g.end_user_groups, \
    a.model_requested, a.model_used, a.provider, a.api_version, a.stream, \
    a.prompt_tokens, a.completion_tokens, a.reasoning_tokens, a.cache_creation_tokens, a.cache_read_tokens, \
    a.finish_reason, a.native_finish_reason, a.cost, \
    a.cost_currency, a.source_cost, a.source_currency, a.fx_rate, a.billed_units, \
    a.embedding_cost, a.embedding_tokens, a.zero_completion, \
    a.latency_ttft_ms, g.latency_total_ms, \
    a.badges, a.pipeline_path, a.catchall_path, a.catchall_method, \
    g.status_code, g.error_category, g.error_detail, g.limit_bucket, \
    a.media_call, \
    a.chat_media_summary, \
    ct.transform_diff as transform_diff, \
    u.email as user_email, \
    us.name as upstream_server_name, \
    a.endpoint_url, \
    a.queue_wait_ms, a.qos_class_id, \
    ws.name as workspace_name, \
    ak.name as key_name, ak.key_prefix, \
    sa.alert_level AS session_alert_level, sa.alert_expert_axis AS session_alert_axis";

/// The search's FROM: the join starts from the keys the walk found, each one
/// primary-key probe. Keep it driven from the keys: as an IN filter after the
/// joins, the planner (which estimates one row for the gateway ⋈ llm join)
/// joins the tenant's whole audit first — minutes at 100k rows, for five hits.
/// The keys are made distinct first, so a key the lookup returned twice is
/// still one row.
static SEARCH_KEYS_JOIN: LazyLock<String> = LazyLock::new(|| {
    format!(
        "(SELECT DISTINCT rid, ts FROM unnest($1::uuid[], $2::timestamptz[]) AS u(rid, ts)) AS k \
         JOIN ({AUDIT_LOG_JOIN}) ON g.request_id = k.rid AND g.timestamp = k.ts"
    )
});

/// The LLM-side audit list, shared by the `kind=llm` and `kind=all` paths and
/// the portal. `limit` is the per-side cap the caller wants (the helper adds
/// the `+1` overfetch); `offset` is where the page starts.
///
/// A search walks `search_llm_audit` (001_init.sql) with [`SearchWalk`]: the
/// function answers the text match — the requested and used model, the user
/// agent, and the messages each request ADDED to its session — inside the
/// window, the user and the workspaces, and every other filter applies to the
/// keys it returns.
pub(crate) async fn list_audit_logs_llm(
    conn: &mut Scoped,
    query: &AuditQuery,
    scope: &AuditScope,
    limit: i64,
    offset: i64,
) -> Result<SearchRows<AuditLogEntry>, ApiError> {
    let fail = |e: sqlx::Error| {
        tracing::error!("list audit logs (llm): {e}");
        ApiError::internal("Failed to query audit logs")
    };
    // The turn is outer-joined, so its window rides the join's ON clause: a
    // WHERE bound would drop every row that has no turn.
    let select = |from: &'static str, filters: &LlmFilters| {
        format!(
            "SELECT {ALL_COLUMNS} FROM {from} \
             LEFT JOIN users u ON g.user_id = u.id \
             LEFT JOIN upstream_servers us ON us.id = a.upstream_server_id \
             LEFT JOIN api_keys ak ON ak.id = g.key_id \
             LEFT JOIN workspaces ws ON ws.id = g.workspace_id \
             LEFT JOIN conversation_turns ct ON ct.request_id = a.request_id AND ct.timestamp = a.timestamp{} \
             LEFT JOIN sessions sa ON sa.session_id = COALESCE(ct.session_id, g.session_id) \
             WHERE ",
            filters.turn_window
        )
    };

    // A media category no endpoint belongs to matches nothing: answer that
    // without walking a search over keys that could never pass.
    if let Some(mt) = &query.media_type
        && mt != "_any"
        && media_category_filter_sql(mt).is_none()
    {
        return Ok(SearchRows { rows: Vec::new(), scan_cut: false });
    }

    let Some(pattern) = search_pattern(query.search.as_deref()) else {
        let filters = llm_filters(query, scope, 1);
        let bind_idx = filters.next_idx;
        let mut sql = format!("{}1=1{}", select(AUDIT_LOG_JOIN, &filters), filters.sql);
        sql.push_str(&format!(
            " ORDER BY g.timestamp DESC, g.request_id DESC LIMIT ${bind_idx} OFFSET ${}",
            bind_idx + 1
        ));
        // OffsetPage: overfetch limit+1 so `has_more` is cheap (no COUNT on partitioned table).
        let rows = bind_llm_filters(sqlx::query_as(sqlx::AssertSqlSafe(&*sql)), query, scope)
            .bind(limit + 1)
            .bind(offset)
            .fetch_all(&mut *conn)
            .await
            .map_err(fail)?;
        return Ok(SearchRows { rows: finish_rows(rows), scan_cut: false });
    };

    let filters = llm_filters(query, scope, 3);
    let (limit_idx, post_filtered) = (filters.next_idx, filters.post_filtered);
    let mut sql = format!("{}1=1{}", select(&SEARCH_KEYS_JOIN, &filters), filters.sql);
    // The page keeps only the rows it still needs.
    sql.push_str(&format!(" ORDER BY g.timestamp DESC, g.request_id DESC LIMIT ${limit_idx}"));

    let workspaces = scope.workspace_ids();
    let mut walk = SearchWalk::new(offset.saturating_add(limit).saturating_add(1), post_filtered);
    let mut rows: Vec<AuditLogEntry> = Vec::new();
    loop {
        let (cursor_ts, cursor_id) = walk.cursor().unzip();
        let keys = sqlx::query_as::<_, (Uuid, chrono::DateTime<chrono::Utc>)>(
            "SELECT request_id, \"timestamp\" FROM search_llm_audit($1, $2, $3, false, $4, $5, $6, $7, $8)",
        )
        .bind(&pattern)
        .bind(query.start)
        .bind(query.end)
        .bind(cursor_ts)
        .bind(cursor_id)
        .bind(walk.batch())
        .bind(scope.user_id())
        .bind(workspaces)
        .fetch_all(&mut *conn)
        .await
        .map_err(fail)?;
        if !keys.is_empty() {
            let ids: Vec<Uuid> = keys.iter().map(|k| k.0).collect();
            let stamps: Vec<chrono::DateTime<chrono::Utc>> = keys.iter().map(|k| k.1).collect();
            let found = bind_llm_filters(
                sqlx::query_as(sqlx::AssertSqlSafe(&*sql)).bind(ids).bind(stamps),
                query,
                scope,
            )
            .bind(i64::try_from(walk.needed().saturating_sub(rows.len())).unwrap_or(i64::MAX))
            .fetch_all(&mut *conn)
            .await
            .map_err(fail)?;
            rows.extend(found);
        }
        if !walk.advance(keys.len(), keys.last().map(|k| (k.1, k.0)), rows.len()) {
            break;
        }
    }
    let rows = rows
        .into_iter()
        .skip(usize::try_from(offset).unwrap_or(0))
        .take(usize::try_from(limit.saturating_add(1)).unwrap_or(usize::MAX))
        .collect();
    Ok(SearchRows { rows: finish_rows(rows), scan_cut: walk.cut() })
}

/// Fill each row's computed fields: the `finish_reason_display` label, and the
/// `session_alert` badge its session carries. Every list row passes through
/// here — a row built without it lacks its session's alert.
fn finish_rows(mut rows: Vec<AuditLogEntry>) -> Vec<AuditLogEntry> {
    for row in &mut rows {
        row.finish_reason_display = finish_reason_display(&row.finish_reason).to_string();
        // Only the session states its alert: one carried in a stored record is dropped.
        row.badges.0.retain(|b| !matches!(b, streamscope_core::audit::AuditBadge::SessionAlert { .. }));
        if let Some(badge) = session_alert_badge(row.session_alert_level.as_deref(), row.session_alert_axis.as_deref()) {
            row.badges.0.push(badge);
        }
    }
    rows
}

/// The `session_alert` badge for a session's structured alert columns: its
/// most severe level and the experts that raised alerts on it. Never read from
/// the alert note, which carries text the judge model wrote. `None` without
/// both, or for a level the badge cannot state.
fn session_alert_badge(level: Option<&str>, axis: Option<&str>) -> Option<streamscope_core::audit::AuditBadge> {
    let level = streamscope_core::audit::AlertLevel::parse(level?)?;
    let experts: Vec<String> =
        axis?.split(',').map(str::trim).filter(|e| !e.is_empty()).map(str::to_string).collect();
    (!experts.is_empty()).then_some(streamscope_core::audit::AuditBadge::SessionAlert { experts, level })
}

/// The LLM audit list's filters, numbered from the caller's first free bind.
struct LlmFilters {
    /// The WHERE conditions, each leading with ` AND `.
    sql: String,
    /// The list's window on the outer-joined turn, for its ON clause, on the
    /// same binds as the window in `sql`.
    turn_window: String,
    next_idx: u32,
    /// Whether a filter the search lookup does not apply itself was added
    /// (it applies the user, the workspaces and the window).
    post_filtered: bool,
}

/// The LLM audit list's filters, numbering binds from `bind_idx`;
/// [`bind_llm_filters`] binds them in the same order.
fn llm_filters(query: &AuditQuery, scope: &AuditScope, mut bind_idx: u32) -> LlmFilters {
    let mut sql = String::new();
    let mut turn_window = String::new();
    if scope.user_id().is_some() {
        sql.push_str(&format!(" AND g.user_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if scope.workspace_ids().is_some() {
        sql.push_str(&format!(" AND g.workspace_id = ANY(${bind_idx})"));
        bind_idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&since_sql(AUDIT_LOG_WINDOW, bind_idx));
        turn_window.push_str(&since_sql(&["ct.timestamp"], bind_idx));
        bind_idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&until_sql(AUDIT_LOG_WINDOW, bind_idx));
        turn_window.push_str(&until_sql(&["ct.timestamp"], bind_idx));
        bind_idx += 1;
    }
    // Everything above is applied by the search itself; every filter appended
    // below narrows its keys afterwards — keep each new one below this mark.
    let selective_end = sql.len();
    if query.model.is_some() {
        sql.push_str(&format!(
            " AND (a.model_requested ILIKE ${bind_idx} OR a.model_used ILIKE ${bind_idx})"
        ));
        bind_idx += 1;
    }
    if query.finish_reason.is_some() {
        sql.push_str(&format!(" AND a.finish_reason = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.app_id.is_some() {
        sql.push_str(&format!(" AND g.app_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if let Some(ec) = &query.error_category {
        if ec == "_any" {
            sql.push_str(" AND g.error_category IS NOT NULL");
        } else {
            sql.push_str(&format!(" AND g.error_category = ${bind_idx}"));
            bind_idx += 1;
        }
    }
    if let Some(mt) = &query.media_type {
        if mt == "_any" {
            sql.push_str(" AND a.media_call IS NOT NULL");
        } else if let Some(clause) = media_category_filter_sql(mt) {
            sql.push_str(clause);
        } else {
            // Unrecognized category string: match nothing rather than leaking
            // the SQL by binding arbitrary input. (`list_audit_logs_llm` answers
            // one empty before walking a search over it.)
            sql.push_str(" AND 1 = 0");
        }
    }
    if query.user_email.is_some() {
        sql.push_str(&format!(" AND u.email ILIKE ${bind_idx}"));
        bind_idx += 1;
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND g.request_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.upstream_server.is_some() {
        sql.push_str(&format!(" AND us.name = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.api_version.is_some() {
        sql.push_str(&format!(" AND a.api_version = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.has_blocked == Some(true) {
        // Static clause — no bind. Same predicate as analytics/overview's
        // blocked-tool count and the Dashboard Overview's Blocked tile.
        sql.push_str(
            " AND a.badges @> '[{\"code\":\"tool_blocked\",\"phase\":\"response\"}]'::jsonb",
        );
    }
    if query.has_guardrail == Some(true) {
        // Static clause — no bind. The shared predicate is what keeps this list
        // and the Dashboard Overview's guardrail tile counting the same rows.
        sql.push_str(&format!(
            " AND {}",
            crate::audit_store::guardrail::guardrail_badge_predicate("a")
        ));
    }
    let post_filtered = sql.len() > selective_end;
    LlmFilters { sql, turn_window, next_idx: bind_idx, post_filtered }
}

/// Bind [`llm_filters`]' parameters, in its order.
fn bind_llm_filters<'q>(
    mut q: sqlx::query::QueryAs<'q, sqlx::Postgres, AuditLogEntry, sqlx::postgres::PgArguments>,
    query: &AuditQuery,
    scope: &'q AuditScope,
) -> sqlx::query::QueryAs<'q, sqlx::Postgres, AuditLogEntry, sqlx::postgres::PgArguments> {
    if let Some(user_id) = scope.user_id() {
        q = q.bind(user_id);
    }
    if let Some(workspace_ids) = scope.workspace_ids() {
        q = q.bind(workspace_ids);
    }
    if let Some(start_ts) = query.start {
        q = q.bind(start_ts);
    }
    if let Some(end_ts) = query.end {
        q = q.bind(end_ts);
    }
    if let Some(model) = &query.model {
        q = q.bind(contains_pattern(model));
    }
    if let Some(finish_reason) = &query.finish_reason {
        q = q.bind(finish_reason.clone());
    }
    if let Some(app_id) = &query.app_id {
        q = q.bind(app_id.clone());
    }
    if let Some(error_category) = &query.error_category
        && error_category != "_any" {
            q = q.bind(error_category.clone());
        }
    // `media_type` carries no bind: `media_category_filter_sql` renders it as an
    // inline IN clause over literal endpoint names.
    if let Some(user_email) = &query.user_email {
        q = q.bind(contains_pattern(user_email));
    }
    if let Some(rid) = query.request_id {
        q = q.bind(rid);
    }
    if let Some(server) = &query.upstream_server {
        q = q.bind(server.clone());
    }
    if let Some(av) = &query.api_version {
        q = q.bind(av.clone());
    }
    q
}

/// Build the MCP-side audit query. The user and the workspaces come from
/// `scope`; from `query` it applies the filters with an MCP analog — `app_id`,
/// the window, `user_email`, the search, `methods`, `request_id`, `jti`, the
/// tool / resource / prompt / server ids and the gateway-level
/// `error_category`. LLM-only filters (`model`, `finish_reason`, `media_type`)
/// do not apply — the audit page hides them from the toolbar when `kind=mcp`.
pub(crate) async fn list_audit_logs_mcp(
    conn: &mut Scoped,
    query: &AuditQuery,
    scope: &AuditScope,
    limit: i64,
    offset: i64,
) -> Result<Vec<McpAuditLogEntry>, ApiError> {
    let search = search_pattern(query.search.as_deref());
    let has_search = search.is_some();

    let mut sql = format!(
        "SELECT \
            request_id, timestamp, g.user_id, g.app_id, g.session_id, \
            m.mcp_session_id, m.virtual_server_id, vs.slug AS virtual_server_slug, \
            m.upstream_server_id, up.name AS upstream_server_name, \
            m.method, m.tool_id, m.prompt_id, m.resource_uri, \
            g.status_code, m.error_code, m.error_message, \
            g.latency_total_ms, m.upstream_latency_ms, \
            m.request_bytes, m.response_bytes, \
            m.protocol_version, m.badges, m.transform_diff, \
            m.params, m.result, \
            u.email AS user_email \
         FROM {join} \
         LEFT JOIN mcp_virtual_servers vs ON vs.id = m.virtual_server_id \
         LEFT JOIN mcp_upstream_servers up ON up.id = m.upstream_server_id \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE g.kind = 'mcp'",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
    );

    let mut bind_idx: u32 = 1;
    if scope.user_id().is_some() {
        sql.push_str(&format!(" AND g.user_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if scope.workspace_ids().is_some() {
        sql.push_str(&format!(" AND g.workspace_id = ANY(${bind_idx})"));
        bind_idx += 1;
    }
    if query.app_id.is_some() {
        sql.push_str(&format!(" AND g.app_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&since_sql(MCP_AUDIT_WINDOW, bind_idx));
        bind_idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&until_sql(MCP_AUDIT_WINDOW, bind_idx));
        bind_idx += 1;
    }
    if query.user_email.is_some() {
        sql.push_str(&format!(" AND u.email ILIKE ${bind_idx}"));
        bind_idx += 1;
    }
    if has_search {
        // Substring across method / tool_id / mcp_session_id / VS slug.
        sql.push_str(&format!(
            " AND (m.method ILIKE ${bind_idx} \
                 OR m.tool_id ILIKE ${bind_idx} \
                 OR m.mcp_session_id ILIKE ${bind_idx} \
                 OR vs.slug ILIKE ${bind_idx})"
        ));
        bind_idx += 1;
    }
    let method_filter: Vec<String> = query
        .methods
        .as_deref()
        .map(parse_method_filter)
        .unwrap_or_default();
    let has_method_filter = !method_filter.is_empty();
    if has_method_filter {
        sql.push_str(&format!(" AND m.method = ANY(${bind_idx}::text[])"));
        bind_idx += 1;
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND g.request_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.jti.is_some() {
        sql.push_str(&format!(" AND g.key_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.tool_id.is_some() {
        sql.push_str(&format!(" AND m.tool_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.resource_uri.is_some() {
        sql.push_str(&format!(" AND m.resource_uri ILIKE ${bind_idx}"));
        bind_idx += 1;
    }
    if query.prompt_id.is_some() {
        sql.push_str(&format!(" AND m.prompt_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.virtual_server_id.is_some() {
        sql.push_str(&format!(" AND m.virtual_server_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.upstream_server_id.is_some() {
        sql.push_str(&format!(" AND m.upstream_server_id = ${bind_idx}"));
        bind_idx += 1;
    }
    // `error_category` is a gateway-level filter shared across LLM and MCP, and
    // every arm of the `kind=all` merge must apply it: the Dashboard Overview's
    // "Errors" tile links to `?error_category=_any&kind=all`, so an arm that
    // left it off would list non-error rows beside the filtered ones. The MCP
    // filter toolbar hides it from the operator.
    if let Some(ec) = &query.error_category {
        if ec == "_any" {
            sql.push_str(" AND g.error_category IS NOT NULL");
        } else {
            sql.push_str(&format!(" AND g.error_category = ${bind_idx}"));
            bind_idx += 1;
        }
    }
    sql.push_str(&format!(
        " ORDER BY timestamp DESC, request_id DESC LIMIT ${bind_idx} OFFSET ${}",
        bind_idx + 1
    ));

    let mut q = sqlx::query_as::<_, McpAuditLogEntry>(sqlx::AssertSqlSafe(&*sql));
    if let Some(user_id) = scope.user_id() {
        q = q.bind(user_id);
    }
    if let Some(workspace_ids) = scope.workspace_ids() {
        q = q.bind(workspace_ids);
    }
    if let Some(app_id) = &query.app_id {
        q = q.bind(app_id);
    }
    if let Some(start_ts) = query.start {
        q = q.bind(start_ts);
    }
    if let Some(end_ts) = query.end {
        q = q.bind(end_ts);
    }
    if let Some(user_email) = &query.user_email {
        q = q.bind(contains_pattern(user_email));
    }
    if let Some(pattern) = search {
        q = q.bind(pattern);
    }
    if has_method_filter {
        q = q.bind(method_filter);
    }
    if let Some(rid) = query.request_id {
        q = q.bind(rid);
    }
    if let Some(jti) = query.jti {
        q = q.bind(jti);
    }
    if let Some(tool_id) = &query.tool_id {
        q = q.bind(tool_id);
    }
    if let Some(resource_uri) = &query.resource_uri {
        q = q.bind(contains_pattern(resource_uri));
    }
    if let Some(prompt_id) = &query.prompt_id {
        q = q.bind(prompt_id);
    }
    if let Some(vs_id) = query.virtual_server_id {
        q = q.bind(vs_id);
    }
    if let Some(us_id) = query.upstream_server_id {
        q = q.bind(us_id);
    }
    if let Some(ec) = &query.error_category
        && ec != "_any"
    {
        q = q.bind(ec);
    }
    q = q.bind(limit + 1).bind(offset);

    q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("list audit logs (mcp): {e}");
        ApiError::internal("Failed to query MCP audit logs")
    })
}

/// Build the web-side audit query. The user and the workspaces come from
/// `scope`; from `query` it applies the filters with a web analog — `app_id`,
/// the window, `user_email`, the search, `error_category`, `request_id`,
/// `surface`, `operation`, `has_guardrail`. LLM/MCP-only filters do not apply.
///
/// `parent_request_id_filter` scopes the result to substitution children of
/// a single orchestrating LLM row — used by the
/// `GET /audit/{request_id}/web` child endpoint. `None` returns
/// every row in the window.
pub(crate) async fn list_audit_logs_web(
    conn: &mut Scoped,
    query: &AuditQuery,
    scope: &AuditScope,
    limit: i64,
    offset: i64,
    parent_request_id_filter: Option<Uuid>,
) -> Result<Vec<WebAuditLogEntry>, ApiError> {
    let search = search_pattern(query.search.as_deref());
    let has_search = search.is_some();
    // Reject unknown surface / operation values here rather than silently
    // dropping the filter. The handler doesn't see them otherwise — the
    // tool-calls dispatcher constructs `AuditQuery` directly.
    if let Some(s) = &query.surface
        && !s.is_empty()
        && !ALLOWED_WEB_SURFACES.contains(&s.as_str())
    {
        return Err(ApiError::bad_request(format!(
            "surface must be one of {ALLOWED_WEB_SURFACES:?}"
        )));
    }
    if let Some(op) = &query.operation
        && !op.is_empty()
        && !ALLOWED_WEB_OPERATIONS.contains(&op.as_str())
    {
        return Err(ApiError::bad_request(format!(
            "operation must be one of {ALLOWED_WEB_OPERATIONS:?}"
        )));
    }

    let mut sql = format!(
        "SELECT \
            request_id, timestamp, g.user_id, u.email AS user_email, \
            g.app_id, g.session_id, \
            w.upstream_server_id, up.name AS upstream_server_name, \
            w.operation, w.backend, w.query, w.result_count, \
            w.bytes_in, w.bytes_out, \
            COALESCE(w.upstream_latency_ms, 0) AS upstream_latency_ms, \
            w.upstream_status, \
            g.status_code, g.error_category, g.error_detail, \
            g.latency_total_ms, w.surface, w.parent_request_id, \
            w.badges, \
            w.url_results, w.filter_chain, \
            w.request_args, w.response_summary, \
            w.provider_request, w.provider_response, \
            w.fetch_content_summary, \
            w.transform_diff \
         FROM {join} \
         LEFT JOIN mcp_upstream_servers up ON up.id = w.upstream_server_id \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE g.kind = 'web'",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
    );

    let mut bind_idx: u32 = 1;
    if scope.user_id().is_some() {
        sql.push_str(&format!(" AND g.user_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if scope.workspace_ids().is_some() {
        sql.push_str(&format!(" AND g.workspace_id = ANY(${bind_idx})"));
        bind_idx += 1;
    }
    if query.app_id.is_some() {
        sql.push_str(&format!(" AND g.app_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&since_sql(WEB_AUDIT_WINDOW, bind_idx));
        bind_idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&until_sql(WEB_AUDIT_WINDOW, bind_idx));
        bind_idx += 1;
    }
    if query.user_email.is_some() {
        sql.push_str(&format!(" AND u.email ILIKE ${bind_idx}"));
        bind_idx += 1;
    }
    if has_search {
        // Substring across query / operation / backend / surface.
        sql.push_str(&format!(
            " AND (w.query ILIKE ${bind_idx} \
                 OR w.operation ILIKE ${bind_idx} \
                 OR w.backend ILIKE ${bind_idx} \
                 OR w.surface ILIKE ${bind_idx})"
        ));
        bind_idx += 1;
    }
    if let Some(ec) = &query.error_category {
        if ec == "_any" {
            sql.push_str(" AND g.error_category IS NOT NULL");
        } else {
            sql.push_str(&format!(" AND g.error_category = ${bind_idx}"));
            bind_idx += 1;
        }
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND g.request_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if parent_request_id_filter.is_some() {
        sql.push_str(&format!(" AND w.parent_request_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.surface.as_deref().is_some_and(|s| !s.is_empty()) {
        sql.push_str(&format!(" AND w.surface = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.operation.as_deref().is_some_and(|s| !s.is_empty()) {
        sql.push_str(&format!(" AND w.operation = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.has_guardrail == Some(true) {
        // Static clause — no bind. Same shared predicate as the LLM listing: the
        // inline guardrail also badges direct `/mcp/web` rows in observe mode, so
        // the filter spans both surfaces.
        sql.push_str(&format!(
            " AND {}",
            crate::audit_store::guardrail::guardrail_badge_predicate("w")
        ));
    }
    sql.push_str(&format!(
        " ORDER BY timestamp DESC, request_id DESC LIMIT ${bind_idx} OFFSET ${}",
        bind_idx + 1
    ));

    let mut q = sqlx::query_as::<_, WebAuditLogEntry>(sqlx::AssertSqlSafe(&*sql));
    if let Some(user_id) = scope.user_id() {
        q = q.bind(user_id);
    }
    if let Some(workspace_ids) = scope.workspace_ids() {
        q = q.bind(workspace_ids);
    }
    if let Some(app_id) = &query.app_id {
        q = q.bind(app_id);
    }
    if let Some(start_ts) = query.start {
        q = q.bind(start_ts);
    }
    if let Some(end_ts) = query.end {
        q = q.bind(end_ts);
    }
    if let Some(user_email) = &query.user_email {
        q = q.bind(contains_pattern(user_email));
    }
    if let Some(pattern) = search {
        q = q.bind(pattern);
    }
    if let Some(error_category) = &query.error_category
        && error_category != "_any"
    {
        q = q.bind(error_category);
    }
    if let Some(rid) = query.request_id {
        q = q.bind(rid);
    }
    if let Some(parent_id) = parent_request_id_filter {
        q = q.bind(parent_id);
    }
    if let Some(surface) = query.surface.as_deref()
        && !surface.is_empty()
    {
        q = q.bind(surface.to_string());
    }
    if let Some(operation) = query.operation.as_deref()
        && !operation.is_empty()
    {
        q = q.bind(operation.to_string());
    }
    q = q.bind(limit + 1).bind(offset);

    q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("list audit logs (web): {e}");
        ApiError::internal("Failed to query web audit logs")
    })
}

/// Build the A2A-side audit query. The user and the workspaces come from
/// `scope`; from `query` it applies the gateway-level filters (`app_id`, the
/// window, `user_email`, `error_category`, `request_id`), the search and the
/// A2A ones (`agent_slug`, `task_state`, `methods`, `has_blocked`,
/// `has_guardrail`). LLM/MCP-only filters do not apply.
pub(crate) async fn list_audit_logs_a2a(
    conn: &mut Scoped,
    query: &AuditQuery,
    scope: &AuditScope,
    limit: i64,
    offset: i64,
) -> Result<Vec<A2aAuditLogEntry>, ApiError> {
    let search = search_pattern(query.search.as_deref());
    let has_search = search.is_some();

    let mut sql = format!(
        "SELECT \
            request_id, timestamp, g.user_id, g.app_id, g.session_id, \
            a2.agent_id, ag.slug AS agent_slug, ag.name AS agent_name, \
            a2.method, a2.a2a_context_id, a2.a2a_task_id, a2.task_state, \
            g.status_code, g.error_category, g.error_detail, \
            a2.error_code, a2.error_message, \
            g.latency_total_ms, a2.upstream_latency_ms, \
            a2.request_bytes, a2.response_bytes, \
            a2.protocol_version, a2.badges, a2.transform_diff, \
            a2.params, a2.result, a2.stream_events, \
            u.email AS user_email \
         FROM {join} \
         LEFT JOIN a2a_upstream_agents ag ON ag.id = a2.agent_id \
         LEFT JOIN users u ON u.id = g.user_id \
         WHERE g.kind = 'a2a'",
        join = crate::audit_store::filters::A2A_AUDIT_JOIN,
    );

    let mut bind_idx: u32 = 1;
    if scope.user_id().is_some() {
        sql.push_str(&format!(" AND g.user_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if scope.workspace_ids().is_some() {
        sql.push_str(&format!(" AND g.workspace_id = ANY(${bind_idx})"));
        bind_idx += 1;
    }
    if query.app_id.is_some() {
        sql.push_str(&format!(" AND g.app_id = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.start.is_some() {
        sql.push_str(&since_sql(A2A_AUDIT_WINDOW, bind_idx));
        bind_idx += 1;
    }
    if query.end.is_some() {
        sql.push_str(&until_sql(A2A_AUDIT_WINDOW, bind_idx));
        bind_idx += 1;
    }
    if query.user_email.is_some() {
        sql.push_str(&format!(" AND u.email ILIKE ${bind_idx}"));
        bind_idx += 1;
    }
    if has_search {
        // Substring across method / context / task / agent slug.
        sql.push_str(&format!(
            " AND (a2.method ILIKE ${bind_idx} \
                 OR a2.a2a_context_id ILIKE ${bind_idx} \
                 OR a2.a2a_task_id ILIKE ${bind_idx} \
                 OR ag.slug ILIKE ${bind_idx})"
        ));
        bind_idx += 1;
    }
    if query.agent_slug.is_some() {
        sql.push_str(&format!(" AND ag.slug = ${bind_idx}"));
        bind_idx += 1;
    }
    // An unrecognized value is REJECTED, never dropped. A whitelist that silently
    // discards what it doesn't know leaves the predicate off the query, and the
    // filter answers with every row — a filter that returns everything is worse
    // than no filter, because the operator believes it narrowed something.
    let task_state = query.task_state.as_deref().filter(|s| !s.is_empty());
    if let Some(state) = task_state
        && !ALLOWED_A2A_TASK_STATES.contains(&state)
    {
        return Err(ApiError::bad_request("unknown A2A task state"));
    }
    if task_state.is_some() {
        sql.push_str(&format!(" AND a2.task_state = ${bind_idx}"));
        bind_idx += 1;
    }
    if query.has_blocked == Some(true) {
        // Static clause — no bind. An A2A block fires on the REQUEST phase (the
        // call is refused before it reaches the agent), so this predicate must not
        // copy the LLM arm's `phase:"response"`-pinned literal.
        sql.push_str(" AND a2.badges @> '[{\"code\":\"tool_blocked\"}]'::jsonb");
    }
    if query.has_guardrail == Some(true) {
        // Static clause — no bind. Same shared predicate as every other arm: a
        // reply the gateway could not finish screening (a truncated stream, a
        // classifier outage) badges `guardrail_error`, and that is the call an
        // operator most needs to open.
        sql.push_str(&format!(
            " AND {}",
            crate::audit_store::guardrail::guardrail_badge_predicate("a2")
        ));
    }
    // Same rule as the task state: a `methods` filter naming nothing this
    // vocabulary knows is a client error, not an invitation to answer with
    // everything. (The merged `kind=all` feed asks first — an arm that recognizes
    // none of the requested methods is skipped there rather than queried.)
    let method_filter: Vec<String> = query
        .methods
        .as_deref()
        .map(parse_a2a_method_filter)
        .unwrap_or_default();
    let has_method_filter = !method_filter.is_empty();
    if !has_method_filter
        && query
            .methods
            .as_deref()
            .is_some_and(|m| m.split(',').any(|s| !s.trim().is_empty()))
    {
        return Err(ApiError::bad_request("unknown A2A method"));
    }
    if has_method_filter {
        sql.push_str(&format!(" AND a2.method = ANY(${bind_idx}::text[])"));
        bind_idx += 1;
    }
    if query.request_id.is_some() {
        sql.push_str(&format!(" AND g.request_id = ${bind_idx}"));
        bind_idx += 1;
    }
    // Gateway-level error filter — keeps the Dashboard "Errors" click-through
    // (`?error_category=_any&kind=all`) consistent across every arm.
    if let Some(ec) = &query.error_category {
        if ec == "_any" {
            sql.push_str(" AND g.error_category IS NOT NULL");
        } else {
            sql.push_str(&format!(" AND g.error_category = ${bind_idx}"));
            bind_idx += 1;
        }
    }
    sql.push_str(&format!(
        " ORDER BY timestamp DESC, request_id DESC LIMIT ${bind_idx} OFFSET ${}",
        bind_idx + 1
    ));

    let mut q = sqlx::query_as::<_, A2aAuditLogEntry>(sqlx::AssertSqlSafe(&*sql));
    if let Some(user_id) = scope.user_id() {
        q = q.bind(user_id);
    }
    if let Some(workspace_ids) = scope.workspace_ids() {
        q = q.bind(workspace_ids);
    }
    if let Some(app_id) = &query.app_id {
        q = q.bind(app_id);
    }
    if let Some(start_ts) = query.start {
        q = q.bind(start_ts);
    }
    if let Some(end_ts) = query.end {
        q = q.bind(end_ts);
    }
    if let Some(user_email) = &query.user_email {
        q = q.bind(contains_pattern(user_email));
    }
    if let Some(pattern) = search {
        q = q.bind(pattern);
    }
    // Bound in the order the predicates were appended: agent, then task state.
    if let Some(agent_slug) = &query.agent_slug {
        q = q.bind(agent_slug.clone());
    }
    if let Some(state) = task_state {
        q = q.bind(state.to_string());
    }
    if has_method_filter {
        q = q.bind(method_filter);
    }
    if let Some(rid) = query.request_id {
        q = q.bind(rid);
    }
    if let Some(ec) = &query.error_category
        && ec != "_any"
    {
        q = q.bind(ec);
    }
    q = q.bind(limit + 1).bind(offset);

    q.fetch_all(&mut *conn).await.map_err(|e| {
        tracing::error!("list audit logs (a2a): {e}");
        ApiError::internal("Failed to query A2A audit logs")
    })
}

/// The audit log list for one `kind` (default `llm`), as the console and the
/// portal both serve it: the rows `scope` allows, filtered by `query`, one page
/// of `limit` from `offset`. Only the LLM arm (and the `all` merge through it)
/// walks a search lookup, so only they can report `scan_cut`.
pub(crate) async fn list_audit_rows(
    conn: &mut Scoped,
    query: &AuditQuery,
    scope: &AuditScope,
    limit: i64,
    offset: i64,
) -> Result<OffsetPage<AuditLogRow>, ApiError> {
    let wrap = |rows: Vec<AuditLogRow>| OffsetPage::from_overfetched(rows, limit, offset);
    Ok(match query.kind.unwrap_or_default() {
        AuditKind::Llm => {
            let found = list_audit_logs_llm(conn, query, scope, limit, offset).await?;
            wrap(found.rows.into_iter().map(|entry| AuditLogRow::Llm { entry: Box::new(entry) }).collect())
                .with_scan_cut(found.scan_cut)
        }
        AuditKind::Mcp => wrap(
            list_audit_logs_mcp(conn, query, scope, limit, offset)
                .await?
                .into_iter()
                .map(|entry| AuditLogRow::Mcp { entry: Box::new(entry) })
                .collect(),
        ),
        AuditKind::Web => wrap(
            list_audit_logs_web(conn, query, scope, limit, offset, None)
                .await?
                .into_iter()
                .map(|entry| AuditLogRow::Web { entry: Box::new(entry) })
                .collect(),
        ),
        AuditKind::A2a => wrap(
            list_audit_logs_a2a(conn, query, scope, limit, offset)
                .await?
                .into_iter()
                .map(|entry| AuditLogRow::A2a { entry: Box::new(entry) })
                .collect(),
        ),
        AuditKind::All => list_audit_logs_all(conn, query, scope, limit, offset).await?,
    })
}

/// `kind=all` merge — run the LLM, MCP, web, and A2A queries server-side,
/// then interleave by `timestamp DESC` and slice the requested page. Each
/// helper already over-fetches its side, so for the merge we ask each for
/// the prefix `[0, offset + limit + 1]` and slice. The cost grows with
/// `offset` on every side, so a deeper offset than `MAX_MERGED_OFFSET` is
/// refused here (`routes::check_merged_offset`); the partition pruning on
/// `timestamp` keeps single-side fetches fast.
pub(crate) async fn list_audit_logs_all(
    conn: &mut Scoped,
    query: &AuditQuery,
    scope: &AuditScope,
    limit: i64,
    offset: i64,
) -> Result<OffsetPage<AuditLogRow>, ApiError> {
    crate::routes::check_merged_offset(offset)?;
    // Each side fetches `[0, offset+limit+1]`. We can't ask the side
    // helpers for "starting at offset N" in the merged ordering — only
    // the global merge knows where each side's row N lands.
    let target = offset.saturating_add(limit).saturating_add(1);

    // `methods` names an operation in ONE protocol's vocabulary — MCP's
    // (`tools/call`) or A2A's (`SendMessage`) — and the two share nothing. An arm
    // whose vocabulary contains none of the requested methods can never match, and
    // its own filter would parse to an empty list and drop the predicate, so it
    // would answer with EVERY row: a filter that silently returns everything.
    // Include only the arms that recognize what was asked for; the LLM and web
    // arms have no `method` at all, so any methods filter excludes them.
    let methods = query
        .methods
        .as_deref()
        .filter(|m| !m.split(',').all(|s| s.trim().is_empty()));
    let mcp_named = methods.is_none_or(|m| !parse_method_filter(m).is_empty());
    let a2a_named = methods.is_none_or(|m| !parse_a2a_method_filter(m).is_empty());

    let llm = if methods.is_some() {
        SearchRows { rows: Vec::new(), scan_cut: false }
    } else {
        list_audit_logs_llm(conn, query, scope, target, 0).await?
    };
    let llm_rows = llm.rows;
    // `has_guardrail` is an LLM/web/A2A concept — the MCP arm has no guardrail
    // badge and ignores the predicate, so under `kind=all` it would otherwise
    // flood the interleave with every MCP row and make a `?has_guardrail=true`
    // deep-link look unfiltered. Exclude the MCP arm entirely when the guardrail
    // filter is requested (it can never contribute a match).
    let mcp_rows = if query.has_guardrail == Some(true) || !mcp_named {
        Vec::new()
    } else {
        list_audit_logs_mcp(conn, query, scope, target, 0).await?
    };
    let web_rows = if methods.is_some() {
        Vec::new()
    } else {
        list_audit_logs_web(conn, query, scope, target, 0, None).await?
    };
    // A2A rows DO carry guardrail badges (both hops screen), so the arm filters
    // on the badge rather than being excluded — a guardrail deep-link that hid
    // exactly the agent calls the guardrail flagged would be the one place an
    // operator cannot look.
    let a2a_rows = if a2a_named {
        list_audit_logs_a2a(conn, query, scope, target, 0).await?
    } else {
        Vec::new()
    };

    let mut all: Vec<AuditLogRow> = Vec::with_capacity(
        llm_rows.len() + mcp_rows.len() + web_rows.len() + a2a_rows.len(),
    );
    for row in llm_rows {
        all.push(AuditLogRow::Llm { entry: Box::new(row) });
    }
    for row in mcp_rows {
        all.push(AuditLogRow::Mcp { entry: Box::new(row) });
    }
    for row in web_rows {
        all.push(AuditLogRow::Web { entry: Box::new(row) });
    }
    for row in a2a_rows {
        all.push(AuditLogRow::A2a { entry: Box::new(row) });
    }

    // Each arm's own order — newest first, then request id — so every arm's
    // rows keep their order in the merge and a page boundary is exact.
    all.sort_by_key(|row| std::cmp::Reverse(audit_log_row_order(row)));

    // Slice [offset, offset+limit+1) — `OffsetPage::from_overfetched`
    // turns the trailing `+1` into `has_more`.
    let start = (offset as usize).min(all.len());
    let end = ((offset + limit + 1) as usize).min(all.len());
    let page_rows: Vec<AuditLogRow> = all.drain(start..end).collect();

    Ok(OffsetPage::from_overfetched(page_rows, limit, offset).with_scan_cut(llm.scan_cut))
}

/// A row's place in the `kind=all` merge: `(timestamp, request_id)`, the
/// order every arm's query sorts by (descending).
fn audit_log_row_order(row: &AuditLogRow) -> (chrono::DateTime<chrono::Utc>, Uuid) {
    match row {
        AuditLogRow::Llm { entry } => (entry.timestamp, entry.request_id),
        AuditLogRow::Mcp { entry } => (entry.timestamp, entry.request_id),
        AuditLogRow::Web { entry } => (entry.timestamp, entry.request_id),
        AuditLogRow::A2a { entry } => (entry.timestamp, entry.request_id),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_session_alert_badge_reads_only_the_structured_columns() {
        use streamscope_core::audit::{AlertLevel, AuditBadge};
        assert_eq!(
            session_alert_badge(Some("major"), Some("anomaly, security")),
            Some(AuditBadge::SessionAlert {
                experts: vec!["anomaly".to_string(), "security".to_string()],
                level: AlertLevel::Major,
            }),
        );
        assert_eq!(session_alert_badge(Some("major"), Some(" , ")), None);
        assert_eq!(session_alert_badge(None, Some("anomaly")), None);
        assert_eq!(session_alert_badge(Some("major"), None), None);
        assert_eq!(session_alert_badge(Some("bogus"), Some("anomaly")), None);
    }
}
