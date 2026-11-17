//! Tool activity read from `conversation_turns`: the tool calls a window's
//! turns carried (for the tool inventory and per-rule activity) and the tool
//! sets recent turns declared (for field discovery).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::tenant::Scoped;
use super::filters::AnalyticsFilterBuilder;

/// A turn whose response carried at least one tool call.
#[derive(sqlx::FromRow)]
pub(crate) struct ToolCallTurnRow {
    pub request_id: Uuid,
    pub api_version: String,
    pub response_tool_calls: Option<serde_json::Value>,
    pub app_id: Option<String>,
    pub session_id: Uuid,
    pub user_id: Uuid,
    pub timestamp: DateTime<Utc>,
}

/// The tool-call turns of a window, streamed: one statement, read row by row
/// off the wire. Each row carries the turn's whole `response_tool_calls` — a
/// Write or Edit call's arguments hold a whole file — so a reader folds each
/// row into its aggregate as it arrives and holds one row, whatever the
/// window; the window is read once. Nothing else may run on the connection
/// while the stream is open.
pub(crate) struct ToolCallScan {
    tenant_id: Uuid,
    filters: AnalyticsFilterBuilder,
    sql: String,
}

impl ToolCallScan {
    /// `filters` carries the window and the scope over `conversation_turns ct`
    /// joined to `sessions s`, its binds from `$2` (`$1` is the tenant).
    pub(crate) fn new(tenant_id: Uuid, filters: AnalyticsFilterBuilder) -> Self {
        let where_extra = filters.where_sql();
        let sql = format!(
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
        Self { tenant_id, filters, sql }
    }

    /// The window's rows, one at a time.
    pub(crate) fn rows<'a>(
        &'a self,
        conn: &'a mut Scoped,
    ) -> futures::stream::BoxStream<'a, sqlx::Result<ToolCallTurnRow>> {
        self.filters
            .apply_query_as(sqlx::query_as::<_, ToolCallTurnRow>(sqlx::AssertSqlSafe(&*self.sql)).bind(self.tenant_id))
            .fetch(conn)
    }
}

/// One entry of a turn's `transform_diff` naming the rule that acted.
#[derive(sqlx::FromRow)]
pub(crate) struct RuleActionRow {
    pub rule_id: Option<String>,
    pub tool_name: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// What per-rule activity is computed from: the tool calls to classify, and
/// the block / replace entries the pipeline recorded.
pub(crate) struct RuleActivityRows {
    /// Streamed by the caller, on the same connection, once the entries are read.
    pub turns: ToolCallScan,
    /// Request- and response-phase `blocked_tools` entries.
    pub blocked: Vec<RuleActionRow>,
    /// `redacted_tool_results` entries.
    pub redacted: Vec<RuleActionRow>,
}

/// The window's tool-call turns (as a scan) plus its block and replace
/// entries, narrowed by `app_id` and `workspace_ids` (both read from the
/// session). The two entry reads are best effort and read as empty on failure
/// (logged); the caller streams the scan afterwards, where a read error
/// surfaces. Run it on a connection, never inside a transaction: a
/// failed best-effort read would abort it.
pub(crate) async fn rule_activity_rows(
    conn: &mut Scoped,
    tenant_id: Uuid,
    time: (DateTime<Utc>, DateTime<Utc>),
    app_id: Option<&str>,
    workspace_ids: Option<&[Uuid]>,
) -> sqlx::Result<RuleActivityRows> {
    let mut filters = AnalyticsFilterBuilder::new(2);
    filters.push_time_window(&["ct.timestamp"], time);
    if let Some(app) = app_id {
        filters.push_eq_str("s.app_id", app);
    }
    if let Some(ws) = workspace_ids {
        filters.push_workspaces("s.workspace_id", ws);
    }
    let where_extra = filters.where_sql();

    let turns = ToolCallScan::new(tenant_id, filters.clone());

    // Both the request-phase (`blocked_tools`) and response-phase
    // (`response_blocked_tools`) paths persist `rule_id` + `name` on every
    // entry; read them straight from the JSONB.
    let blocked_sql = format!(
        r#"SELECT
                bt_elem->>'rule_id' AS rule_id,
                bt_elem->>'name'    AS tool_name,
                ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            CROSS JOIN LATERAL jsonb_array_elements(ct.transform_diff->'blocked_tools') AS bt_elem
            WHERE ct.tenant_id = $1
              AND ct.transform_diff->'blocked_tools' IS NOT NULL
              AND jsonb_array_length(ct.transform_diff->'blocked_tools') > 0
              {where_extra}
        UNION ALL
        SELECT
                bt_elem->>'rule_id' AS rule_id,
                bt_elem->>'name'    AS tool_name,
                ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            CROSS JOIN LATERAL jsonb_array_elements(ct.transform_diff->'response_blocked_tools') AS bt_elem
            WHERE ct.tenant_id = $1
              AND ct.transform_diff->'response_blocked_tools' IS NOT NULL
              AND jsonb_array_length(ct.transform_diff->'response_blocked_tools') > 0
              {where_extra}"#
    );
    let blocked = filters
        .apply_query_as(sqlx::query_as::<_, RuleActionRow>(sqlx::AssertSqlSafe(&*blocked_sql)).bind(tenant_id))
        .fetch_all(&mut *conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("rule activity: blocked-tool entries unread: {e}");
            Vec::new()
        });

    let redacted_sql = format!(
        r#"SELECT
                rd_elem->>'rule_id'   AS rule_id,
                rd_elem->>'tool_name' AS tool_name,
                ct.timestamp
            FROM conversation_turns ct
            JOIN sessions s ON s.session_id = ct.session_id
            CROSS JOIN LATERAL jsonb_array_elements(ct.transform_diff->'redacted_tool_results') AS rd_elem
            WHERE ct.tenant_id = $1
              AND ct.transform_diff->'redacted_tool_results' IS NOT NULL
              AND jsonb_array_length(ct.transform_diff->'redacted_tool_results') > 0
              {where_extra}"#
    );
    let redacted = filters
        .apply_query_as(sqlx::query_as::<_, RuleActionRow>(sqlx::AssertSqlSafe(&*redacted_sql)).bind(tenant_id))
        .fetch_all(&mut *conn)
        .await
        .unwrap_or_else(|e| {
            tracing::warn!("rule activity: redacted-tool entries unread: {e}");
            Vec::new()
        });

    Ok(RuleActivityRows { turns, blocked, redacted })
}

/// The tool-set hashes the most recent `lookback` turns declared, newest
/// first, one per turn (a set several turns declared repeats). The sets
/// themselves are read from the content store by these keys; `lookback`
/// counts every turn that declared a set, and a turn whose set is no longer
/// stored counts for nothing in the coverage built from them.
pub(crate) async fn recent_tool_set_hashes(
    conn: &mut Scoped,
    tenant_id: Uuid,
    lookback: i64,
) -> sqlx::Result<Vec<String>> {
    sqlx::query_scalar(
        "SELECT ct.tools_available_hash \
         FROM conversation_turns ct \
         WHERE ct.tenant_id = $1 AND ct.tools_available_hash IS NOT NULL \
         ORDER BY ct.timestamp DESC \
         LIMIT $2",
    )
    .bind(tenant_id)
    .bind(lookback)
    .fetch_all(&mut *conn)
    .await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_tool_call_scan_is_one_unbounded_statement_read_once() {
        let now = Utc::now();
        let mut filters = AnalyticsFilterBuilder::new(2);
        filters.push_time_window(&["ct.timestamp"], (now - chrono::Duration::days(30), now));
        filters.push_eq_str("s.app_id", "app");
        let sql = ToolCallScan::new(Uuid::nil(), filters).sql;
        // The filters bind $2..$4 and nothing else is bound: no cursor, no
        // page — a re-read per page would re-scan the window.
        assert!(sql.contains("$4") && !sql.contains("$5"), "{sql}");
        assert!(!sql.contains("LIMIT") && !sql.contains("ORDER BY"), "{sql}");
    }
}
