//! The guardrail predicates — the attention form (a finding or a scan that
//! could not complete) and the per-category finding form — and the detections
//! since a point in time, read from the `guardrail` badges on `llm_audit` (the
//! inbound scan) and `web_audit` (the `/mcp/web` observe scan).

use chrono::{DateTime, Utc};
use uuid::Uuid;

use crate::db::tenant::Scoped;
use super::filters::{AUDIT_LOG_JOIN, AUDIT_LOG_WINDOW, WEB_AUDIT_JOIN, WEB_AUDIT_WINDOW, since_sql};

/// Badge containment predicate for `<col>.badges`: a `guardrail` badge whose
/// `categories` array includes one of `cats` (and, with `action`, is also of
/// that action). `@>` is key-order-independent and matches array membership.
/// Every input is `&'static str` because all of it is spliced into the SQL
/// text: `col` / `action` are literals written here, and `cats` are the
/// compile-time badge tokens of the guardrail categories — none can carry a
/// runtime string.
fn badge_pred(col: &'static str, action: Option<&'static str>, cats: &[&'static str]) -> String {
    let act = action.map(|a| format!(",\"action\":\"{a}\"")).unwrap_or_default();
    let parts: Vec<String> = cats
        .iter()
        .map(|c| {
            format!(
                "{col}.badges @> '[{{\"code\":\"guardrail\",\"categories\":[\"{c}\"]{act}}}]'::jsonb"
            )
        })
        .collect();
    format!("({})", parts.join(" OR "))
}

/// Predicate for "this row is one the guardrail wants an operator to look at":
/// a **finding** (`guardrail`) or a scan the gateway could not complete
/// (`guardrail_error` — a detector outage, or content past the scan window cap
/// that was therefore never classified). Both belong in the same bucket because
/// the operator's question is the same one — *did anything reach the model
/// unscreened?* — and a coverage gap answers it as loudly as a finding does.
///
/// The attention tile and every `has_guardrail` list filter go through this, on
/// every audit kind, so the tile and the list it links to can never disagree
/// about what they are counting. The per-category detection counts below are a
/// different question — findings of the categories an alarm watches — and read
/// `badge_pred`, which a scan that could not complete does not match.
///
/// `alias` is the row's table alias and is `&'static str` by contract: text
/// spliced into a query is a compile-time constant, so a request-derived string
/// cannot reach it.
pub(crate) fn guardrail_badge_predicate(alias: &'static str) -> String {
    format!(
        "({alias}.badges @> '[{{\"code\":\"guardrail\"}}]'::jsonb \
          OR {alias}.badges @> '[{{\"code\":\"guardrail_error\"}}]'::jsonb)"
    )
}

/// Detections of `cats` since `since`: `(inbound, web, blocked)` — `inbound`
/// counts `llm_audit` badges, `web` counts `web_audit` badges, `blocked` is
/// the enforce-mode stripped subset of `inbound` (observe never strips). No
/// categories count nothing.
pub(crate) async fn detection_counts(
    conn: &mut Scoped,
    tenant_id: Uuid,
    since: DateTime<Utc>,
    cats: &[&'static str],
) -> sqlx::Result<(i64, i64, i64)> {
    if cats.is_empty() {
        return Ok((0, 0, 0));
    }
    let inbound_pred = badge_pred("a", None, cats);
    let web_pred = badge_pred("w", None, cats);
    let blocked_pred = badge_pred("a", Some("block"), cats);
    // One pass over the LLM rows: a blocked detection is also an inbound one,
    // so `blocked` filters the rows `inbound` counts. `tenant_id` is bound on
    // both subqueries per the tenant-isolation invariant.
    let sql = format!(
        "SELECT l.inbound, wc.web, l.blocked FROM \
            (SELECT COUNT(*)::bigint AS inbound, \
                    COUNT(*) FILTER (WHERE {blocked_pred})::bigint AS blocked \
               FROM {llm_join} \
              WHERE g.tenant_id = $1{llm_since} \
                AND {inbound_pred}) l, \
            (SELECT COUNT(*)::bigint AS web FROM {web_join} \
              WHERE g.tenant_id = $1{web_since} \
                AND {web_pred}) wc",
        llm_join = AUDIT_LOG_JOIN,
        web_join = WEB_AUDIT_JOIN,
        llm_since = since_sql(AUDIT_LOG_WINDOW, 2),
        web_since = since_sql(WEB_AUDIT_WINDOW, 2),
    );
    sqlx::query_as(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(since)
        .fetch_one(&mut *conn)
        .await
}

/// The most recent request carrying a detection of `cats` since `since`,
/// across both surfaces; `None` for no categories.
pub(crate) async fn latest_detection(
    conn: &mut Scoped,
    tenant_id: Uuid,
    since: DateTime<Utc>,
    cats: &[&'static str],
) -> sqlx::Result<Option<Uuid>> {
    if cats.is_empty() {
        return Ok(None);
    }
    let inbound_pred = badge_pred("a", None, cats);
    let web_pred = badge_pred("w", None, cats);
    let target_sql = format!(
        "SELECT request_id FROM ( \
            SELECT a.request_id AS request_id, a.timestamp AS ts FROM {llm_join} \
              WHERE g.tenant_id = $1{llm_since} \
                AND {inbound_pred} \
            UNION ALL \
            SELECT w.request_id AS request_id, w.timestamp AS ts FROM {web_join} \
              WHERE g.tenant_id = $1{web_since} \
                AND {web_pred} \
         ) u ORDER BY ts DESC LIMIT 1",
        llm_join = AUDIT_LOG_JOIN,
        web_join = WEB_AUDIT_JOIN,
        llm_since = since_sql(AUDIT_LOG_WINDOW, 2),
        web_since = since_sql(WEB_AUDIT_WINDOW, 2),
    );
    sqlx::query_scalar(sqlx::AssertSqlSafe(&*target_sql))
        .bind(tenant_id)
        .bind(since)
        .fetch_optional(&mut *conn)
        .await
}
