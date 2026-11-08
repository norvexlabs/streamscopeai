//! The reads behind one request's trace: its turn, the turn after it (where a
//! tool call's result arrives), its media call, its error envelope, its
//! server-side substitution web calls, and the A2A call or error record a
//! request without a turn resolves to. The caller builds the trace's events
//! from these rows through the canonical `build_events` pipeline.

use chrono::{DateTime, Utc};
use uuid::Uuid;

use super::timeline::{
    A2A_CALL_COLUMNS, A2A_CALL_JOINS, A2aCallRowForSession, RawJson, WEB_CALL_COLUMNS,
    WebCallRowForSession,
};
use crate::db::tenant::Scoped;
use crate::audit_store::filters::window_sql;

/// The request's turn, as [`turn`] selects it from
/// `conversation_turns_resolved` — one field per column, decoded by name.
#[derive(sqlx::FromRow)]
pub(crate) struct TraceTurn {
    pub(crate) request_id: Uuid,
    pub(crate) timestamp: DateTime<Utc>,
    pub(crate) session_id: Option<Uuid>,
    pub(crate) turn_number: i32,
    pub(crate) parent_request_id: Option<Uuid>,
    pub(crate) is_baseline: bool,
    pub(crate) message_hashes: Option<Vec<String>>,
    pub(crate) message_count: i32,
    pub(crate) tools_available_hash: Option<String>,
    pub(crate) tools_effective_hash: Option<String>,
    pub(crate) request_params: Option<serde_json::Value>,
    /// The turn's system prompt, by hash: the caller reads its body from
    /// the content store.
    pub(crate) system_prompt_hash: Option<String>,
    pub(crate) transform_diff: RawJson,
    pub(crate) response_content: Option<String>,
    pub(crate) response_tool_calls: Option<serde_json::Value>,
    pub(crate) request_size_bytes: Option<i32>,
    pub(crate) response_size_bytes: Option<i32>,
    pub(crate) event_type: String,
    /// The inbound protocol stamped on the turn.
    pub(crate) api_version: String,
}

/// The request's turn, from `conversation_turns_resolved`.
pub(crate) async fn turn(
    conn: &mut Scoped,
    request_id: Uuid,
) -> sqlx::Result<Option<TraceTurn>> {
    sqlx::query_as(
        "SELECT request_id, timestamp, session_id, turn_number, parent_request_id, \
         is_baseline, message_hashes, message_count, \
         tools_available_hash, tools_effective_hash, \
         request_params, system_prompt_hash, transform_diff, response_content, \
         response_tool_calls, request_size_bytes, response_size_bytes, event_type, \
         api_version \
         FROM conversation_turns_resolved WHERE request_id = $1 LIMIT 1",
    )
    .bind(request_id)
    .fetch_optional(&mut *conn)
    .await
}

/// A media turn's canonical `media_call` and envelope metadata. `media_call` is
/// nullable (pre-request error records have no body to capture into a
/// canonical shape).
pub(crate) type MediaRow = (
    RawJson,        // media_call: a `DomainMediaCall`, decoded by the reader
    Option<String>, // model_requested
    Option<String>, // model_used
    Option<String>, // provider
    Option<i64>,    // latency_total_ms
    Option<f64>,    // cost
    Option<String>, // cost_currency
);

/// Keyed on the turn's `(request_id, timestamp)`, so the read probes one
/// weekly partition of each fact.
pub(crate) async fn media_meta(
    conn: &mut Scoped,
    request_id: Uuid,
    timestamp: DateTime<Utc>,
) -> sqlx::Result<Option<MediaRow>> {
    sqlx::query_as(
        "SELECT a.media_call, a.model_requested, a.model_used, a.provider, \
                g.latency_total_ms, a.cost, a.cost_currency \
         FROM gateway_audit g JOIN llm_audit a USING (request_id, timestamp, tenant_id) \
         WHERE g.request_id = $1 AND g.timestamp = $2",
    )
    .bind(request_id)
    .bind(timestamp)
    .fetch_optional(&mut *conn)
    .await
}

/// A chat turn's audit row as its trace reads it: its models, and the stored
/// blobs the request carried itself (`chat_media_summary`).
#[derive(sqlx::FromRow, Default)]
pub(crate) struct LlmMeta {
    pub(crate) model_requested: Option<String>,
    pub(crate) model_used: Option<String>,
    pub(crate) chat_media_summary: RawJson,
}

/// A chat turn's audit row ([`LlmMeta`]), keyed on the turn's
/// `(request_id, timestamp)` — `None` when the turn has no audit row. A turn
/// carries its audit record's own timestamp text (the ingest writer copies
/// it), so the two rows' timestamps are equal; the timeline joins on the same
/// equality.
pub(crate) async fn llm_meta(
    conn: &mut Scoped,
    request_id: Uuid,
    timestamp: DateTime<Utc>,
) -> sqlx::Result<Option<LlmMeta>> {
    sqlx::query_as(
        "SELECT model_requested, model_used, chat_media_summary \
         FROM llm_audit WHERE request_id = $1 AND timestamp = $2",
    )
    .bind(request_id)
    .bind(timestamp)
    .fetch_optional(&mut *conn)
    .await
}

/// The SQL that finds the turn answering a call turn — where its tool results
/// arrive — for each row of an outer query that names the call turn `ct`
/// (`tenant_id`, `request_id`, `timestamp`, `session_id`, `turn_number`). The
/// ONE rule, shared by the trace ([`answering_turn`]) and the tool-call feed:
///
/// - the call turn's CHILD (the turn of the same session naming it as
///   parent, `idx_turns_parent`; bounded to no more than a day before the
///   call turn, a margin for clock skew between edges that still prunes
///   every older week) when the child added something counted
///   from the call turn: `0 < added_from < message_count` (the call turn's
///   history was its prefix and it carries more), and it is no baseline;
/// - otherwise the session's next turn by a higher turn number (ties among
///   those by timestamp and request id, the session view's order), whose added messages
///   the caller takes as its whole history less the call turn's
///   ([`answer_hashes`]).
///
/// It joins two laterals, `kid` and `seq`, and a third, `ans`, that names the
/// choice: `answer_request_id`, `answer_timestamp`, `answer_turn_number` (the
/// answering turn's real number) and `answer_sliced` (its added slice is
/// counted from the call turn). A reader resolves the chosen turn by
/// `ans`'s key inside its own `LATERAL … LIMIT 1`, so the probe is an index
/// scan per row. `ans` keeps its `OFFSET 0`: pulled up, its `COALESCE`s are
/// spliced into that probe's condition and the planner reads the whole
/// partition per row instead of probing the key. `window` names the caller's
/// window binds `($lo, $hi)`, stated on `kc.timestamp` and `nct.timestamp`
/// (`None`: no window); keep the `seq` window a function of those binds
/// only, never of `ct.timestamp`, or the feed loses its Memoize node on
/// (session_id, tenant_id, turn_number).
pub(crate) fn answer_laterals(window: Option<(u32, u32)>) -> String {
    let (kid_window, seq_window) = match window {
        Some((lo, hi)) => (window_sql(&["kc.timestamp"], lo, hi), window_sql(&["nct.timestamp"], lo, hi)),
        None => (String::new(), String::new()),
    };
    format!(
        "LEFT JOIN LATERAL ( \
             SELECT kc.request_id, kc.timestamp, kc.turn_number \
               FROM conversation_turns kc \
              WHERE kc.tenant_id = ct.tenant_id \
                AND kc.parent_request_id = ct.request_id \
                AND kc.session_id = ct.session_id \
                AND kc.timestamp >= ct.timestamp - interval '1 day' \
                AND kc.added_from > 0 AND kc.added_from < kc.message_count \
                AND NOT kc.is_baseline{kid_window} \
              ORDER BY kc.turn_number, kc.timestamp, kc.request_id \
              LIMIT 1 \
         ) kid ON TRUE \
         LEFT JOIN LATERAL ( \
             SELECT nct.request_id, nct.timestamp, nct.turn_number \
               FROM conversation_turns nct \
              WHERE kid.request_id IS NULL \
                AND nct.session_id = ct.session_id \
                AND nct.tenant_id = ct.tenant_id \
                AND nct.turn_number > ct.turn_number{seq_window} \
              ORDER BY nct.turn_number, nct.timestamp, nct.request_id \
              LIMIT 1 \
         ) seq ON TRUE \
         CROSS JOIN LATERAL ( \
             SELECT COALESCE(kid.request_id, seq.request_id) AS answer_request_id, \
                    COALESCE(kid.timestamp, seq.timestamp) AS answer_timestamp, \
                    COALESCE(kid.turn_number, seq.turn_number) AS answer_turn_number, \
                    kid.request_id IS NOT NULL AS answer_sliced \
             OFFSET 0 \
         ) ans"
    )
}

/// The messages the client appended for the answering turn — where a call's
/// results are. `sliced`: `hashes` is the child's added slice, taken whole.
/// Otherwise `hashes` is the next turn's whole history, less every message
/// the call turn carried.
pub(crate) fn answer_hashes(sliced: bool, hashes: Option<Vec<String>>, call_hashes: &[String]) -> Vec<String> {
    let hashes = hashes.unwrap_or_default();
    if sliced {
        return hashes;
    }
    let call: std::collections::HashSet<&str> = call_hashes.iter().map(String::as_str).collect();
    hashes.into_iter().filter(|h| !call.contains(h.as_str())).collect()
}

/// The turn that answers a call turn, as [`answer_laterals`] chooses it.
#[derive(sqlx::FromRow)]
pub(crate) struct AnswerRef {
    pub(crate) answer_request_id: Uuid,
    pub(crate) answer_timestamp: DateTime<Utc>,
    pub(crate) answer_turn_number: i32,
    pub(crate) answer_sliced: bool,
}

/// The turn answering the call turn `(request_id, timestamp)` of `session_id`
/// at `turn_number` — `None` when the session has none after it.
pub(crate) async fn answering_turn(
    conn: &mut Scoped,
    request_id: Uuid,
    timestamp: DateTime<Utc>,
    session_id: Uuid,
    turn_number: i32,
) -> sqlx::Result<Option<AnswerRef>> {
    sqlx::query_as::<_, AnswerRef>(sqlx::AssertSqlSafe(&*format!(
        "SELECT ans.answer_request_id, ans.answer_timestamp, ans.answer_turn_number, ans.answer_sliced \
           FROM (SELECT current_tenant_id() AS tenant_id, $1::uuid AS request_id, \
                        $2::timestamptz AS timestamp, $3::uuid AS session_id, \
                        $4::int AS turn_number) ct \
           {laterals} \
          WHERE ans.answer_request_id IS NOT NULL",
        laterals = answer_laterals(None),
    )))
    .bind(request_id)
    .bind(timestamp)
    .bind(session_id)
    .bind(turn_number)
    .fetch_optional(&mut *conn)
    .await
}

/// The turn that answers a call turn, resolved: its real turn number, the
/// hashes [`answer_hashes`] narrows, and what `build_events` needs to render
/// its tool results and the calls it sends back — no system prompt and no
/// answer (a trace reads it only for those results).
#[derive(sqlx::FromRow)]
pub(crate) struct NextTurn {
    pub(crate) request_id: Uuid,
    pub(crate) turn_number: i32,
    /// `true`: [`Self::hashes`] is the slice the call turn's child added;
    /// `false`: the next turn's whole history (see [`answer_hashes`]).
    pub(crate) sliced: bool,
    pub(crate) hashes: Option<Vec<String>>,
    pub(crate) tools_available_hash: Option<String>,
    pub(crate) request_params: Option<serde_json::Value>,
    pub(crate) api_version: String,
    pub(crate) model_requested: Option<String>,
    pub(crate) model_used: Option<String>,
}

/// The turn answering the call turn `(request_id, timestamp)`
/// ([`answering_turn`]), read by its key.
pub(crate) async fn next_turn(
    conn: &mut Scoped,
    request_id: Uuid,
    timestamp: DateTime<Utc>,
    session_id: Uuid,
    turn_number: i32,
) -> sqlx::Result<Option<NextTurn>> {
    let Some(answer) = answering_turn(&mut *conn, request_id, timestamp, session_id, turn_number).await? else {
        return Ok(None);
    };
    sqlx::query_as(
        "SELECT nct.request_id, $4::int AS turn_number, $3 AS sliced, \
         CASE WHEN $3 THEN nct.added_hashes ELSE nct.message_hashes END AS hashes, \
         nct.tools_available_hash, nct.request_params, \
         nct.api_version, \
         na.model_requested, na.model_used \
         FROM conversation_turns_resolved nct \
         LEFT JOIN llm_audit na ON na.request_id = nct.request_id \
           AND na.timestamp = nct.timestamp AND na.timestamp = $2 \
         WHERE nct.request_id = $1 AND nct.timestamp = $2",
    )
    .bind(answer.answer_request_id)
    .bind(answer.answer_timestamp)
    .bind(answer.answer_sliced)
    .bind(answer.answer_turn_number)
    .fetch_optional(&mut *conn)
    .await
}

/// The request's server-side substitution web calls (joined by
/// `parent_request_id`), oldest first.
pub(crate) async fn substitution_web_calls(
    conn: &mut Scoped,
    request_id: Uuid,
) -> sqlx::Result<Vec<WebCallRowForSession>> {
    sqlx::query_as::<_, WebCallRowForSession>(sqlx::AssertSqlSafe(&*format!(
        "SELECT {WEB_CALL_COLUMNS} \
         FROM {join} \
         WHERE w.parent_request_id = $1 AND w.surface = 'substitution' \
         ORDER BY timestamp ASC",
        join = crate::audit_store::filters::WEB_AUDIT_JOIN,
    )))
    .bind(request_id)
    .fetch_all(&mut *conn)
    .await
}

/// `(status_code, error_category, error_detail, model_used, provider)`.
pub(crate) type ErrorEnvelopeRow = (Option<i16>, Option<String>, Option<String>, Option<String>, Option<String>);

/// The turn's error envelope, read whether or not it failed, keyed on the
/// turn's `(request_id, timestamp)`.
pub(crate) async fn error_envelope(
    conn: &mut Scoped,
    request_id: Uuid,
    timestamp: DateTime<Utc>,
) -> sqlx::Result<Option<ErrorEnvelopeRow>> {
    sqlx::query_as(
        "SELECT g.status_code, g.error_category, g.error_detail, a.model_used, a.provider \
         FROM gateway_audit g JOIN llm_audit a USING (request_id, timestamp, tenant_id) \
         WHERE g.request_id = $1 AND g.timestamp = $2",
    )
    .bind(request_id)
    .bind(timestamp)
    .fetch_optional(&mut *conn)
    .await
}

/// The request's `a2a_audit` row, if it is an A2A gateway call.
pub(crate) async fn a2a_call(
    conn: &mut Scoped,
    request_id: Uuid,
) -> sqlx::Result<Option<A2aCallRowForSession>> {
    sqlx::query_as::<_, A2aCallRowForSession>(sqlx::AssertSqlSafe(&*format!(
        "SELECT {A2A_CALL_COLUMNS} \
         FROM {join} {A2A_CALL_JOINS} \
         WHERE g.request_id = $1 \
         LIMIT 1",
        join = crate::audit_store::filters::A2A_AUDIT_JOIN,
    )))
    .bind(request_id)
    .fetch_optional(&mut *conn)
    .await
}

/// `(timestamp, status_code, error_category, error_detail, model_used, provider)`.
pub(crate) type FallbackRow = (
    DateTime<Utc>,
    Option<i16>,
    Option<String>,
    Option<String>,
    Option<String>,
    Option<String>,
);

/// The request's error envelope, only when it carries one (a 4xx/5xx or an
/// explicit `error_category`): a successful request whose turn is not written
/// yet reads `None`.
pub(crate) async fn error_fallback(
    conn: &mut Scoped,
    request_id: Uuid,
) -> sqlx::Result<Option<FallbackRow>> {
    sqlx::query_as(
        "SELECT g.timestamp, g.status_code, g.error_category, g.error_detail, \
                a.model_used, a.provider \
         FROM gateway_audit g JOIN llm_audit a USING (request_id, timestamp, tenant_id) \
         WHERE g.request_id = $1 \
           AND (g.error_category IS NOT NULL OR g.status_code >= 400) \
         LIMIT 1",
    )
    .bind(request_id)
    .fetch_optional(conn)
    .await
}

#[cfg(test)]
mod answer_tests {
    use super::answer_hashes;

    fn v(xs: &[&str]) -> Vec<String> {
        xs.iter().map(|s| (*s).to_string()).collect()
    }

    #[test]
    fn a_slice_is_taken_whole_and_a_whole_history_loses_what_the_call_turn_carried() {
        let call = v(&["u1", "a", "r1", "u2"]);
        // The child's slice: kept as it is, even a message the call turn also carried.
        assert_eq!(answer_hashes(true, Some(v(&["a", "rb", "u3"])), &call), v(&["a", "rb", "u3"]));
        // A whole history: only what the call turn did not carry, in order.
        assert_eq!(
            answer_hashes(false, Some(v(&["u1", "a", "r1", "u2", "b", "rb", "u3"])), &call),
            v(&["b", "rb", "u3"])
        );
        assert_eq!(answer_hashes(false, None, &call), Vec::<String>::new());
        assert_eq!(answer_hashes(true, None, &call), Vec::<String>::new());
    }
}
