//! The reads behind a session's timeline: its turns (each joined to its
//! `gateway_audit` / `llm_audit` row) and the MCP, web and A2A gateway calls
//! that share its session id. The caller builds the timeline's events from
//! these rows through the canonical `build_events` pipeline.

use uuid::Uuid;

use crate::db::tenant::Scoped;
use crate::routes::audit::{A2aTransformDiff, McpTransformDiff, SessionTurnSummary};
use crate::routes::spend_total;

/// One MCP gateway call of a session timeline, read through the canonical
/// `MCP_AUDIT_JOIN`.
#[derive(sqlx::FromRow)]
pub(crate) struct McpCallRowForSession {
    pub(crate) request_id: Uuid,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
    pub(crate) method: String,
    pub(crate) tool_id: Option<String>,
    pub(crate) prompt_id: Option<String>,
    pub(crate) resource_uri: Option<String>,
    pub(crate) error_code: Option<i32>,
    pub(crate) error_message: Option<String>,
    pub(crate) status_code: Option<i16>,
    pub(crate) latency_total_ms: Option<i64>,
    pub(crate) transform_diff: Option<sqlx::types::Json<McpTransformDiff>>,
    pub(crate) virtual_server_slug: Option<String>,
    pub(crate) upstream_server_name: Option<String>,
    pub(crate) params: Option<sqlx::types::Json<serde_json::Value>>,
    pub(crate) result: Option<sqlx::types::Json<serde_json::Value>>,
}

/// The select list of a [`WebCallRowForSession`] over `WEB_AUDIT_JOIN` — the
/// one copy every web-call read uses, so a field and its column cannot drift.
pub(crate) const WEB_CALL_COLUMNS: &str = "request_id, timestamp, w.operation, w.surface, w.backend, \
     w.query, w.result_count, \
     g.status_code, g.error_category, g.error_detail, \
     g.latency_total_ms, w.parent_request_id, w.tool_use_id, w.badges";

/// One web (search / fetch) call of a session timeline or of a request's
/// substitution loop, read through the canonical `WEB_AUDIT_JOIN`.
#[derive(sqlx::FromRow)]
pub(crate) struct WebCallRowForSession {
    pub(crate) request_id: Uuid,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
    pub(crate) operation: String,
    pub(crate) surface: String,
    pub(crate) backend: String,
    pub(crate) query: Option<String>,
    pub(crate) result_count: Option<i32>,
    pub(crate) status_code: Option<i16>,
    pub(crate) error_category: Option<String>,
    pub(crate) error_detail: Option<String>,
    pub(crate) latency_total_ms: Option<i64>,
    pub(crate) parent_request_id: Option<Uuid>,
    pub(crate) tool_use_id: Option<String>,
    pub(crate) badges: sqlx::types::Json<Vec<streamscope_core::audit::AuditBadge>>,
}

/// The select list of an [`A2aCallRowForSession`] over `A2A_AUDIT_JOIN`
/// followed by [`A2A_CALL_JOINS`] — the one copy every A2A-call read uses.
pub(crate) const A2A_CALL_COLUMNS: &str = "request_id, timestamp, a2.method, \
     ag.slug AS agent_slug, ag.name AS agent_name, \
     u.email AS user_email, g.app_id, \
     a2.a2a_context_id, a2.a2a_task_id, a2.task_state, \
     g.status_code, a2.error_code, a2.error_message, g.latency_total_ms, \
     a2.params, a2.result, a2.stream_events, a2.badges, a2.transform_diff";

/// The lookups [`A2A_CALL_COLUMNS`] reads beside `A2A_AUDIT_JOIN`.
pub(crate) const A2A_CALL_JOINS: &str = "LEFT JOIN a2a_upstream_agents ag ON ag.id = a2.agent_id \
     LEFT JOIN users u ON u.id = g.user_id";

/// One A2A gateway call of a session timeline or a request's trace, read
/// through the canonical `A2A_AUDIT_JOIN`.
#[derive(sqlx::FromRow)]
pub(crate) struct A2aCallRowForSession {
    pub(crate) request_id: Uuid,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
    pub(crate) method: String,
    pub(crate) agent_slug: Option<String>,
    pub(crate) agent_name: Option<String>,
    /// Caller principal — resolved from `gateway_audit.user_id` → `users.email`,
    /// with `gateway_audit.app_id` as the fallback client identity.
    pub(crate) user_email: Option<String>,
    pub(crate) app_id: Option<String>,
    pub(crate) a2a_context_id: Option<String>,
    pub(crate) a2a_task_id: Option<String>,
    pub(crate) task_state: Option<String>,
    pub(crate) status_code: Option<i16>,
    pub(crate) error_code: Option<i32>,
    pub(crate) error_message: Option<String>,
    pub(crate) latency_total_ms: Option<i64>,
    pub(crate) params: Option<sqlx::types::Json<serde_json::Value>>,
    pub(crate) result: Option<sqlx::types::Json<serde_json::Value>>,
    pub(crate) stream_events: Option<sqlx::types::Json<serde_json::Value>>,
    pub(crate) badges: sqlx::types::Json<Vec<streamscope_core::audit::AuditBadge>>,
    pub(crate) transform_diff: Option<sqlx::types::Json<A2aTransformDiff>>,
}

/// A session's turns, ordered by turn number (then timestamp and request id,
/// so a page boundary between turns sharing a number is stable), each with its audit row's
/// usage, cost and latency (a turn with no audit row carries none) — and no
/// turn's history, which this list never renders. `limit` is the page size
/// the caller wants plus its overfetch. Each summary comes with its system
/// prompt's hash and no prompt: the caller reads the bodies from the content
/// store.
pub(crate) async fn session_turns(
    conn: &mut Scoped,
    session_id: Uuid,
    limit: i64,
    offset: i64,
) -> sqlx::Result<Vec<(Option<String>, SessionTurnSummary)>> {
    let rows = sqlx::query(
        "SELECT t.request_id, t.timestamp, t.turn_number, t.parent_request_id, \
         t.is_baseline, t.message_count, t.response_content, t.response_tool_calls, \
         t.system_prompt_hash, t.transform_diff, t.request_size_bytes, t.response_size_bytes, \
         a.prompt_tokens, a.completion_tokens, \
         a.cache_creation_tokens, a.cache_read_tokens, a.reasoning_tokens, \
         a.cost, a.cost_currency, a.finish_reason, \
         a.latency_ttft_ms, g.latency_total_ms, a.model_used \
         FROM conversation_turns t \
         LEFT JOIN gateway_audit g ON t.request_id = g.request_id AND t.timestamp = g.timestamp \
         LEFT JOIN llm_audit a ON t.request_id = a.request_id AND t.timestamp = a.timestamp \
         WHERE t.session_id = $1 \
         ORDER BY t.turn_number, t.timestamp, t.request_id LIMIT $2 OFFSET $3",
    )
    .bind(session_id)
    .bind(limit)
    .bind(offset)
    .fetch_all(&mut *conn)
    .await?;

    use sqlx::Row;
    let summaries: Vec<(Option<String>, SessionTurnSummary)> = rows
        .into_iter()
        .map(|r| (r.get("system_prompt_hash"), SessionTurnSummary {
            request_id: r.get("request_id"),
            timestamp: r.get("timestamp"),
            turn_number: r.get("turn_number"),
            parent_request_id: r.get("parent_request_id"),
            is_baseline: r.get("is_baseline"),
            message_count: r.get("message_count"),
            response_content: r.get("response_content"),
            response_tool_calls: r.get("response_tool_calls"),
            system_prompt: None,
            transform_diff: r.try_get("transform_diff").unwrap_or(None),
            request_size_bytes: r.get("request_size_bytes"),
            response_size_bytes: r.get("response_size_bytes"),
            prompt_tokens: r.get("prompt_tokens"),
            completion_tokens: r.get("completion_tokens"),
            cache_creation_tokens: r.get("cache_creation_tokens"),
            cache_read_tokens: r.get("cache_read_tokens"),
            reasoning_tokens: r.get("reasoning_tokens"),
            // A turn is one audit row: the currency it was written in is on
            // the row, and a turn with no audit row (LEFT JOIN miss) has no
            // figure at all rather than a zero in a guessed denomination.
            spend: spend_total(
                1,
                r.try_get("cost_currency").unwrap_or(None),
                r.try_get("cost").unwrap_or(None).unwrap_or(0.0),
                Default::default(),
            ),
            finish_reason: r.get("finish_reason"),
            latency_ttft_ms: r.get("latency_ttft_ms"),
            latency_total_ms: r.get("latency_total_ms"),
            model_used: r.get("model_used"),
        }))
        .collect();
    Ok(summaries)
}

/// One turn of a session with its audit row, as [`turns`] selects it — one
/// field per column, decoded by name. A turn with no audit row (LEFT JOIN
/// miss) carries NULL in every audit column; its protocol is the one stamped
/// on the turn. The JSON columns a reader decodes into a typed shape stay
/// [`RawJson`], so one undecodable JSON value costs that value — logged —
/// never the whole timeline; every other column is written typed by the
/// ingest and decodes strictly.
#[derive(sqlx::FromRow)]
pub(crate) struct TimelineTurn {
    pub(crate) request_id: Uuid,
    pub(crate) timestamp: chrono::DateTime<chrono::Utc>,
    pub(crate) turn_number: i32,
    pub(crate) is_baseline: bool,
    pub(crate) response_content: Option<String>,
    pub(crate) response_tool_calls: Option<serde_json::Value>,
    /// The system prompt's hash; NULL except where the conversation renders
    /// the prompt — on a turn that [`Self::opens_view`] — unless [`turns`] was
    /// asked for every prompt (the raw format). The caller reads the bodies
    /// from the content store.
    pub(crate) system_prompt_hash: Option<String>,
    pub(crate) transform_diff: RawJson,
    /// The session's first turn (exactly one: the first row by turn number,
    /// timestamp and request id) or a baseline turn: the conversation renders
    /// its whole history unfiltered and resets what it has seen.
    pub(crate) opens_view: bool,
    /// [`Self::message_hashes`] is the turn's whole history: a turn that
    /// [`Self::opens_view`], one whose slice is counted from no landed
    /// parent (`added_from = 0`), or one whose parent is not a row of the
    /// session ordered before it.
    pub(crate) reads_whole: bool,
    /// What [`turns`] read of the turn's history: all of it where
    /// [`Self::reads_whole`], else only the slice the turn added
    /// (`added_hashes`).
    pub(crate) message_hashes: Option<Vec<String>>,
    /// The length of the turn's whole history, whichever slice was read.
    pub(crate) message_count: i32,
    /// The turn the edge named as its parent, and how many leading messages of
    /// this turn's history that parent carried.
    pub(crate) parent_request_id: Option<Uuid>,
    pub(crate) added_from: i32,
    pub(crate) tools_available_hash: Option<String>,
    pub(crate) tools_effective_hash: Option<String>,
    pub(crate) request_params: Option<serde_json::Value>,
    pub(crate) event_type: String,
    pub(crate) api_version: String,
    pub(crate) prompt_tokens: Option<i32>,
    pub(crate) completion_tokens: Option<i32>,
    pub(crate) cache_creation_tokens: Option<i32>,
    pub(crate) cache_read_tokens: Option<i32>,
    pub(crate) reasoning_tokens: Option<i32>,
    pub(crate) cost: Option<f64>,
    pub(crate) cost_currency: Option<String>,
    pub(crate) finish_reason: Option<String>,
    pub(crate) latency_ttft_ms: Option<i64>,
    pub(crate) latency_total_ms: Option<i64>,
    pub(crate) model_used: Option<String>,
    pub(crate) model_requested: Option<String>,
    pub(crate) badges: RawJson,
    pub(crate) error_category: Option<String>,
    pub(crate) status_code: Option<i16>,
    pub(crate) error_detail: Option<String>,
    pub(crate) provider: Option<String>,
    pub(crate) media_call: RawJson,
    pub(crate) chat_media_summary: RawJson,
    pub(crate) upstream_server_name: Option<String>,
    pub(crate) workspace_name: Option<String>,
    pub(crate) user_email: Option<String>,
    pub(crate) key_name: Option<String>,
    pub(crate) key_prefix: Option<String>,
    pub(crate) client_ip: Option<String>,
    pub(crate) end_user: Option<String>,
    pub(crate) end_user_groups: Option<Vec<String>>,
}

/// A JSON column read as stored, decoded into its type by the reader that
/// needs it. A value that does not decode reads as absent, logged with the
/// column and the request it came from.
#[derive(sqlx::Type, Default)]
#[sqlx(transparent)]
pub(crate) struct RawJson(Option<serde_json::Value>);

impl RawJson {
    pub(crate) fn decode<T: serde::de::DeserializeOwned>(
        &self,
        column: &str,
        request_id: Uuid,
    ) -> Option<T> {
        T::deserialize(self.0.as_ref()?)
            .inspect_err(|e| tracing::warn!(%request_id, "undecodable {column} on an audit turn: {e}"))
            .ok()
    }

    /// The column as a turn's transform diff.
    pub(crate) fn transform_diff(
        &self,
        request_id: Uuid,
    ) -> Option<sqlx::types::Json<streamscope_core::proxy::content::TransformDiff>> {
        self.decode("transform_diff", request_id).map(sqlx::types::Json)
    }
}

/// Every turn of a session with its audit row, ordered by turn number.
///
/// A turn's history is read whole on the session's first turn (one row: the
/// first by turn number, timestamp and request id — the order the rows come
/// in), on a baseline turn, on a turn whose slice is counted from
/// no landed parent (`added_from = 0`, where the slice IS the whole history),
/// and on a turn whose parent is not a row walked before it (expired with its
/// week, or never in this session): its prefix renders nowhere else. Every
/// other turn reads the slice it added (`added_hashes`), so the read is
/// linear in the session's messages rather than in turns × history. The two
/// predicates are computed here once, as `opens_view` and `reads_whole`, and
/// the caller branches on them alone. The system prompt's hash is read where
/// the prompt is rendered — where the turn opens the view — unless
/// `every_prompt`.
pub(crate) async fn turns(
    conn: &mut Scoped,
    session_id: Uuid,
    every_prompt: bool,
) -> sqlx::Result<Vec<TimelineTurn>> {
    sqlx::query_as(
        "SELECT t.request_id, t.timestamp, t.turn_number, \
         t.is_baseline, t.response_content, t.response_tool_calls, \
         CASE WHEN $2 OR v.opens_view THEN t.system_prompt_hash END AS system_prompt_hash, \
         t.transform_diff, v.opens_view, v.reads_whole, \
         CASE WHEN v.reads_whole THEN t.message_hashes ELSE t.added_hashes END AS message_hashes, \
         t.message_count, t.parent_request_id, t.added_from, t.tools_available_hash, t.tools_effective_hash, t.request_params, \
         t.event_type, \
         t.api_version, \
         a.prompt_tokens, a.completion_tokens, \
         a.cache_creation_tokens, a.cache_read_tokens, a.reasoning_tokens, \
         a.cost, a.cost_currency, a.finish_reason, \
         a.latency_ttft_ms, g.latency_total_ms, a.model_used, a.model_requested, a.badges, \
         g.error_category, g.status_code, g.error_detail, \
         a.provider, \
         a.media_call, a.chat_media_summary, \
         us.name as upstream_server_name, \
         ws.name as workspace_name, \
         u.email as user_email, \
         ak.name as key_name, ak.key_prefix, \
         g.client_ip, g.end_user, g.end_user_groups \
         FROM conversation_turns_resolved t \
         LEFT JOIN gateway_audit g ON t.request_id = g.request_id AND t.timestamp = g.timestamp \
         LEFT JOIN llm_audit a ON t.request_id = a.request_id AND t.timestamp = a.timestamp \
         LEFT JOIN upstream_servers us ON us.id = a.upstream_server_id \
         LEFT JOIN api_keys ak ON ak.id = g.key_id \
         LEFT JOIN workspaces ws ON ws.id = g.workspace_id \
         LEFT JOIN users u ON g.user_id = u.id \
         CROSS JOIN (SELECT c.request_id AS first, c.timestamp AS first_ts FROM conversation_turns c \
                     WHERE c.session_id = $1 \
                     ORDER BY c.turn_number, c.timestamp, c.request_id LIMIT 1) f \
         CROSS JOIN LATERAL (SELECT o.opens_view, \
                                    o.opens_view OR t.added_from = 0 OR NOT EXISTS ( \
                                        SELECT 1 FROM conversation_turns p \
                                         WHERE p.session_id = $1 \
                                           AND p.request_id = t.parent_request_id \
                                           AND p.timestamp <= t.timestamp + interval '1 day' \
                                           AND p.timestamp >= f.first_ts - interval '1 day' \
                                           AND (p.turn_number, p.timestamp, p.request_id) \
                                             < (t.turn_number, t.timestamp, t.request_id)) AS reads_whole \
                             FROM (SELECT t.is_baseline OR t.request_id = f.first AS opens_view) o) v \
         WHERE t.session_id = $1 \
         ORDER BY t.turn_number, t.timestamp, t.request_id",
    )
    .bind(session_id)
    .bind(every_prompt)
    .fetch_all(&mut *conn)
    .await
}

/// The session's MCP gateway calls, joined on `g.session_id`, oldest first.
pub(crate) async fn mcp_calls(
    conn: &mut Scoped,
    session_id: Uuid,
) -> sqlx::Result<Vec<McpCallRowForSession>> {
    sqlx::query_as::<_, McpCallRowForSession>(sqlx::AssertSqlSafe(&*format!(
        "SELECT request_id, timestamp, m.method, m.tool_id, m.prompt_id, \
                m.resource_uri, m.error_code, m.error_message, \
                g.status_code, g.latency_total_ms, m.transform_diff, \
                vs.slug AS virtual_server_slug, up.name AS upstream_server_name, \
                m.params, m.result \
         FROM {join} \
         LEFT JOIN mcp_virtual_servers vs ON vs.id = m.virtual_server_id \
         LEFT JOIN mcp_upstream_servers up ON up.id = m.upstream_server_id \
         WHERE g.session_id = $1 \
         ORDER BY timestamp ASC",
        join = crate::audit_store::filters::MCP_AUDIT_JOIN,
    )))
    .bind(session_id)
    .fetch_all(&mut *conn)
    .await
}

/// The session's web calls: the direct ones joined on `g.session_id`, and the
/// substitution children of its turns (`turn_request_ids`), oldest first.
pub(crate) async fn web_calls(
    conn: &mut Scoped,
    session_id: Uuid,
    turn_request_ids: &[Uuid],
) -> sqlx::Result<Vec<WebCallRowForSession>> {
    sqlx::query_as::<_, WebCallRowForSession>(sqlx::AssertSqlSafe(&*format!(
        "SELECT {WEB_CALL_COLUMNS} \
         FROM {join} \
         WHERE g.session_id = $1 \
            OR w.parent_request_id = ANY($2) \
         ORDER BY timestamp ASC",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
    )))
    .bind(session_id)
    .bind(turn_request_ids)
    .fetch_all(&mut *conn)
    .await
}

/// The session's A2A gateway calls, joined on `g.session_id`, oldest first.
pub(crate) async fn a2a_calls(
    conn: &mut Scoped,
    session_id: Uuid,
) -> sqlx::Result<Vec<A2aCallRowForSession>> {
    sqlx::query_as::<_, A2aCallRowForSession>(sqlx::AssertSqlSafe(&*format!(
        "SELECT {A2A_CALL_COLUMNS} \
         FROM {join} {A2A_CALL_JOINS} \
         WHERE g.session_id = $1 \
         ORDER BY timestamp ASC",
        join = crate::audit_store::filters::A2A_AUDIT_JOIN,
    )))
    .bind(session_id)
    .fetch_all(&mut *conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::RawJson;

    #[test]
    fn a_json_column_decodes_into_its_type_and_an_undecodable_one_reads_absent() {
        let id = uuid::Uuid::nil();
        let badges = RawJson(Some(serde_json::json!([])));
        assert_eq!(badges.decode::<Vec<u8>>("badges", id), Some(Vec::new()));
        let wrong = RawJson(Some(serde_json::json!({"not": "a list"})));
        assert_eq!(wrong.decode::<Vec<u8>>("badges", id), None);
        assert_eq!(RawJson(None).decode::<Vec<u8>>("badges", id), None);
    }
}
