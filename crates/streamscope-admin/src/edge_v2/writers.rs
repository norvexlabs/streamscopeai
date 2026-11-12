//! The row writers behind `POST /api/v2/edge/ingest`: audit records and their
//! content, usage counters, instance stats, endpoint stands and load samples.
//!
//! The share writers run on an [`IngestConn`] — one transaction for every
//! tenant of a request, as `streamscope_ingest` — so every statement names its
//! rows' `tenant_id` (in the row it inserts, and in every lookup it makes).
//!
//! One item must never stall the edge's outbox: a request whose transaction
//! fails falls back to one transaction per share through
//! [`write_tenant_share_rows`], which isolates a row refused for its data, and
//! a best-effort write inside a transaction runs under a SAVEPOINT.

use std::collections::{HashMap, HashSet};

use crate::AdminState;
use crate::content_store::history_chunks;
use crate::db::Global;
use crate::db::tenant::{IngestConn, Scoped, TenantConn, TenantId};
use streamscope_edge_api::ingest::EdgeProxyStats;

/// What one usage report came to: the fleet totals of the counters that
/// merged, the counters settled without merging, and whether every counter was
/// one or the other (none failed transiently).
pub(crate) struct UsageMerge {
    pub totals: Vec<streamscope_core::usage::UsageCounterAuthoritative>,
    pub settled: Vec<streamscope_core::usage::UsageCounterKey>,
    pub complete: bool,
}

/// How long before the janitor deletes a window's watermark the merge stops
/// merging into it: a merge that read the clock just before that point still
/// finishes long before the watermark goes, so a restated counter never meets
/// a deleted watermark (which would add its whole cumulative again).
const SETTLE_BEFORE_EXPIRY_MS: u64 = 60_000;

/// Merge a batch of edge usage reports into the global `usage_counters` totals
/// and return the authoritative totals to echo back. Idempotent: per
/// `(edge, counter)` we store the last-seen cumulative (a watermark) and add
/// only the positive delta, so a re-sent report adds zero and an edge restart
/// rebases — no spend is double-counted. (Spend can be
/// slightly under-counted: at most one usage interval of unreported delta on
/// a crash — consistent with the estimate-not-ledger stance.) Grouped by
/// tenant for RLS, like the audit batch.
///
/// A counter that can never merge — a deleted tenant's, a window out of range
/// or within [`SETTLE_BEFORE_EXPIRY_MS`] of [`UsageWindowKind::kept_for_ms`], a
/// value the database refuses for its data — is settled: dropped, and named so the edge stops restating it.
/// One that failed transiently is in neither list and clears `complete`, so
/// the caller does not stamp the instance as merged.
///
/// [`UsageWindowKind::kept_for_ms`]: streamscope_core::usage::UsageWindowKind::kept_for_ms
pub(crate) async fn merge_usage_reports(
    state: &AdminState,
    edge_instance_id: uuid::Uuid,
    reports: Vec<streamscope_core::usage::UsageCounterReport>,
    epoch: i64,
) -> UsageMerge {
    use streamscope_core::usage::UsageCounterAuthoritative;

    let mut by_tenant: HashMap<uuid::Uuid, Vec<streamscope_core::usage::UsageCounterReport>> =
        HashMap::new();
    for r in reports {
        by_tenant.entry(r.key.tenant_id).or_default().push(r);
    }

    // Deleted-tenant guard: an edge keeps a removed tenant's buffered cumulative
    // counters until their window rolls off. usage_counters.tenant_id is
    // FK-bound to tenants(id), so a merge for a deleted tenant would raise an FK
    // error on every restatement. See [`prune_deleted_tenants`].
    let deleted = prune_deleted_tenants(&state.db, edge_instance_id, "usage_report", &mut by_tenant).await;
    let mut merge = UsageMerge {
        totals: Vec::new(),
        settled: deleted.into_iter().flat_map(|(_, items)| items).map(|r| r.key).collect(),
        complete: true,
    };

    let mut clock: Option<(u64, std::time::Instant)> = None;
    for (tenant_id, items) in by_tenant {
        let mut db = match TenantConn::acquire(&state.db, TenantId::from_edge(tenant_id)).await {
            Ok(db) => db,
            Err(e) => {
                tracing::warn!(edge_instance_id = %edge_instance_id, %tenant_id, "usage merge: tenant connection failed: {e}");
                merge.complete = false;
                continue;
            }
        };
        for r in items {
            // The database's clock, the one the janitor deletes watermarks by
            // (a replica's own may run behind it): read once per report, and
            // again every `CLOCK_REREAD`, so a long report stays well inside
            // the settle margin.
            let now_ms = match clock {
                Some((ms, read)) if read.elapsed() < CLOCK_REREAD => ms,
                _ => {
                    let Some(ms) = db_clock_ms(db.conn(), edge_instance_id, tenant_id).await else {
                        merge.complete = false;
                        break;
                    };
                    clock = Some((ms, std::time::Instant::now()));
                    ms
                }
            };
            let window_start = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(r.key.window_start_ms as i64);
            let Some(window_start) = window_start else {
                tracing::error!(edge_instance_id = %edge_instance_id, %tenant_id, "usage merge: window start out of range — counter dropped");
                merge.settled.push(r.key);
                continue;
            };
            if r.key.window_start_ms.saturating_add(r.key.window_kind.kept_for_ms()) <= now_ms.saturating_add(SETTLE_BEFORE_EXPIRY_MS) {
                // Its watermark may already be gone: merging would add the
                // whole cumulative again to a window nothing reads.
                tracing::warn!(edge_instance_id = %edge_instance_id, %tenant_id, "usage merge: window past retention — counter dropped");
                merge.settled.push(r.key);
                continue;
            }
            match merge_one_counter(db.conn(), edge_instance_id, &r, window_start, epoch).await {
                Ok(Some(total)) => merge.totals.push(UsageCounterAuthoritative {
                    key: r.key,
                    total: total.max(0) as u64,
                }),
                Ok(None) => merge.complete = false,
                Err(e) if is_permanent_row_rejection(&e) => {
                    tracing::error!(edge_instance_id = %edge_instance_id, %tenant_id, "usage merge refused for its data — counter dropped: {e}");
                    merge.settled.push(r.key);
                }
                Err(e) => {
                    merge.complete = false;
                    tracing::warn!(edge_instance_id = %edge_instance_id, %tenant_id, "usage merge failed: {e}")
                }
            }
        }
    }
    merge
}

/// How often a merge reads the database clock again: far inside
/// [`SETTLE_BEFORE_EXPIRY_MS`].
const CLOCK_REREAD: std::time::Duration = std::time::Duration::from_secs(10);

/// The database's clock now, in ms (logged and `None` when it cannot be read).
async fn db_clock_ms(conn: &mut Scoped, edge_instance_id: uuid::Uuid, tenant_id: uuid::Uuid) -> Option<u64> {
    match sqlx::query_scalar::<_, i64>("SELECT (extract(epoch FROM clock_timestamp()) * 1000)::bigint")
        .fetch_one(conn)
        .await
    {
        Ok(ms) => Some(ms.max(0) as u64),
        Err(e) => {
            tracing::warn!(%edge_instance_id, %tenant_id, "usage merge: reading the database clock failed: {e}");
            None
        }
    }
}

/// Single-counter watermark/delta merge inside one transaction. Returns the new
/// global total for the counter, in that counter's own unit — `None` when the
/// report's epoch is no longer the instance's current one (nothing merged).
///
/// A watermark stored under another epoch is a previous process's, so the whole
/// value is the new delta; within one epoch the cumulative only grows, so a
/// lower value is a late duplicate and adds nothing. The watermark row is
/// created first and locked, so two replicas merging the same restated counter
/// at once (an edge retrying a request another replica is still serving) take
/// turns: the second sees the first's watermark and adds nothing.
async fn merge_one_counter(
    conn: &mut Scoped,
    edge_instance_id: uuid::Uuid,
    report: &streamscope_core::usage::UsageCounterReport,
    window_start: chrono::DateTime<chrono::Utc>,
    epoch: i64,
) -> Result<Option<i64>, sqlx::Error> {
    let k = &report.key;
    let scope_kind = k.scope_kind.as_str();
    let metric = k.metric.as_str();
    let window_kind = k.window_kind.as_str();
    let reported = i64::try_from(report.cumulative).unwrap_or(i64::MAX);

    let mut tx = conn.begin().await?;

    // The instance row is share-locked for the merge, so an epoch
    // change waits for it and a merge that started under an older
    // epoch cannot rebase over the newer process's watermark.
    let current: Option<Option<i64>> =
        sqlx::query_scalar("SELECT process_epoch FROM edge_instances WHERE id = $1 FOR SHARE")
            .bind(edge_instance_id)
            .fetch_optional(&mut *tx)
            .await?;
    if current.flatten() != Some(epoch) {
        return Ok(None);
    }
    // A new watermark starts at 0 under this epoch: the whole cumulative is
    // the delta, as for a counter never seen.
    sqlx::query(
        "INSERT INTO usage_counter_watermarks \
           (edge_instance_id, tenant_id, scope_kind, scope_id, metric, window_kind, window_start, last_seen, process_epoch) \
         VALUES ($1,$2,$3,$4,$5,$6,$7,0,$8) \
         ON CONFLICT (edge_instance_id, tenant_id, scope_kind, scope_id, metric, window_kind, window_start) DO NOTHING",
    )
    .bind(edge_instance_id)
    .bind(k.tenant_id)
    .bind(scope_kind)
    .bind(k.scope_id)
    .bind(metric)
    .bind(window_kind)
    .bind(window_start)
    .bind(epoch)
    .execute(&mut *tx)
    .await?;
    let (old, old_epoch): (i64, Option<i64>) = sqlx::query_as(
        "SELECT last_seen, process_epoch FROM usage_counter_watermarks \
          WHERE edge_instance_id = $1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 \
            AND metric=$5 AND window_kind=$6 AND window_start=$7 \
            FOR UPDATE",
    )
    .bind(edge_instance_id)
    .bind(k.tenant_id)
    .bind(scope_kind)
    .bind(k.scope_id)
    .bind(metric)
    .bind(window_kind)
    .bind(window_start)
    .fetch_one(&mut *tx)
    .await?;
    let (delta, last_seen) = if old_epoch == Some(epoch) {
        ((reported - old).max(0), reported.max(old))
    } else {
        (reported, reported)
    };
    if delta == 0 && old_epoch == Some(epoch) {
        // A restatement: nothing to write, only the total to answer with.
        let total: Option<i64> = sqlx::query_scalar(
            "SELECT total FROM usage_counters \
              WHERE tenant_id=$1 AND scope_kind=$2 AND scope_id=$3 AND metric=$4 AND window_kind=$5 AND window_start=$6",
        )
        .bind(k.tenant_id)
        .bind(scope_kind)
        .bind(k.scope_id)
        .bind(metric)
        .bind(window_kind)
        .bind(window_start)
        .fetch_optional(&mut *tx)
        .await?;
        tx.commit().await?;
        return Ok(Some(total.unwrap_or(0)));
    }

    sqlx::query(
        "UPDATE usage_counter_watermarks SET last_seen = $8, process_epoch = $9 \
          WHERE edge_instance_id = $1 AND tenant_id=$2 AND scope_kind=$3 AND scope_id=$4 \
            AND metric=$5 AND window_kind=$6 AND window_start=$7",
    )
    .bind(edge_instance_id)
    .bind(k.tenant_id)
    .bind(scope_kind)
    .bind(k.scope_id)
    .bind(metric)
    .bind(window_kind)
    .bind(window_start)
    .bind(last_seen)
    .bind(epoch)
    .execute(&mut *tx)
    .await?;

    let total: i64 = sqlx::query_scalar(
        "INSERT INTO usage_counters \
           (tenant_id, scope_kind, scope_id, metric, window_kind, window_start, total, updated_at) \
         VALUES ($1,$2,$3,$4,$5,$6,$7, now()) \
         ON CONFLICT (tenant_id, scope_kind, scope_id, metric, window_kind, window_start) \
         DO UPDATE SET total = usage_counters.total + $7, updated_at = now() \
         RETURNING total",
    )
    .bind(k.tenant_id)
    .bind(scope_kind)
    .bind(k.scope_id)
    .bind(metric)
    .bind(window_kind)
    .bind(window_start)
    .bind(delta)
    .fetch_one(&mut *tx)
    .await?;

    tx.commit().await?;
    Ok(Some(total))
}

/// Whether a failed write was refused for the DATA it carried — a refusal that
/// every redelivery of the same rows repeats: SQLSTATE class `22` (data
/// exception: an untranslatable character, a value out of range, a malformed
/// timestamp or number), `21000` (one statement touching the same row twice —
/// a property of the batch's composition, which a row-at-a-time retry
/// dissolves), `23502` (not-null) and `23514` (check), and `54000` (a value
/// past a Postgres size limit). Everything else — a lost connection, a lock or
/// serialization failure, a foreign key to a row that has not synced yet — may
/// succeed on redelivery, so it is not permanent.
pub(crate) fn is_permanent_row_rejection(e: &sqlx::Error) -> bool {
    e.as_database_error()
        .and_then(|d| d.code())
        .is_some_and(|code| is_permanent_sqlstate(&code))
}

/// The SQLSTATE half of [`is_permanent_row_rejection`].
fn is_permanent_sqlstate(code: &str) -> bool {
    (code.len() == 5 && code.starts_with("22"))
        || matches!(code, "21000" | "23502" | "23514" | "54000")
}

/// The JSON array a set-based `jsonb_array_elements($1)` insert binds.
pub(crate) fn json_array(items: &[&serde_json::Value]) -> serde_json::Value {
    serde_json::Value::Array(items.iter().map(|&v| v.clone()).collect())
}

/// The natural key a dropped item is logged under.
fn item_key(item: &serde_json::Value) -> &str {
    ["request_id", "hash", "content_hash", "mcp_session_id"]
        .iter()
        .find_map(|k| item.get(*k).and_then(|v| v.as_str()))
        .unwrap_or("-")
}

/// A row [`write_tenant_share`] writes: anything that names itself in the log
/// line of a drop.
pub(crate) trait ShareRow: Sync {
    fn log_key(&self) -> std::borrow::Cow<'_, str>;
}

impl ShareRow for serde_json::Value {
    fn log_key(&self) -> std::borrow::Cow<'_, str> {
        std::borrow::Cow::Borrowed(item_key(self))
    }
}

/// The statement(s) [`write_tenant_share_rows`] runs for a set of rows, on the
/// transaction it opened.
pub(crate) type ShareWrite<'w, T = serde_json::Value> = dyn for<'a> FnMut(
        &'a mut IngestConn,
        &'a [&'a T],
    ) -> futures::future::BoxFuture<'a, Result<(), sqlx::Error>>
    + Send
    + 'w;

/// A row of a committed share that the database refused for its data, and why.
pub(crate) struct DroppedRow<'i, T> {
    pub(crate) item: &'i T,
    pub(crate) error: sqlx::Error,
}

/// Write one tenant's share alone, in its own ingest transaction: `Some(dropped
/// rows)` once it committed, `None` when it was rolled back and must be
/// redelivered. The fallback when a request's single transaction failed.
///
/// A refusal that [`is_permanent_row_rejection`] classifies bisects the share
/// — each half under its own SAVEPOINT in the same transaction, recursing into
/// a refused half — so only the refused rows are dropped, in O(k log n)
/// attempts for k bad rows. Any other failure rolls the whole share back: the
/// edge redelivers it and the natural-key dedupe absorbs what an earlier
/// delivery landed. The dropped rows are logged at `error`, with the
/// database's reason, and notified only once the share commits — a share
/// rolled back drops nothing.
pub(crate) async fn write_tenant_share_rows<'i, T: ShareRow>(
    db: &crate::db::Db,
    tenant_id: uuid::Uuid,
    node_id: uuid::Uuid,
    channel: &'static str,
    items: &[&'i T],
    write: &mut ShareWrite<'_, T>,
) -> Option<Vec<DroppedRow<'i, T>>> {
    /// One attempt under a SAVEPOINT of the share's transaction, so a refusal
    /// undoes only this attempt.
    async fn attempt<T: ShareRow>(
        tx: &mut IngestConn,
        items: &[&T],
        write: &mut ShareWrite<'_, T>,
    ) -> Result<(), sqlx::Error> {
        let mut sp = tx.savepoint().await?;
        match write(sp.conn(), items).await {
            Ok(()) => sp.commit().await,
            // Dropping the savepoint rolls it back. A failed rollback leaves
            // the transaction aborted, and its COMMIT then fails: the share is
            // redelivered, never half-kept.
            Err(e) => Err(e),
        }
    }

    if items.is_empty() {
        return Some(Vec::new());
    }
    let mut dropped: Vec<DroppedRow<'i, T>> = Vec::new();
    let written: Result<(), sqlx::Error> = async {
        let mut tx = db.begin_ingest().await?;
        // Parts still to write, taken front half first.
        let mut pending: Vec<&[&'i T]> = vec![items];
        while let Some(part) = pending.pop() {
            match attempt(tx.conn(), part, write).await {
                Ok(()) => {}
                Err(e) if !is_permanent_row_rejection(&e) => return Err(e),
                Err(e) if part.len() == 1 => dropped.push(DroppedRow { item: part[0], error: e }),
                Err(e) => {
                    if part.len() == items.len() {
                        tracing::warn!(node_id = %node_id, %tenant_id, channel, rows = items.len(), "edge batch refused for its data, isolating the rows: {e}");
                    }
                    let mid = part.len() / 2;
                    pending.push(&part[mid..]);
                    pending.push(&part[..mid]);
                }
            }
        }
        tx.commit().await
    }
    .await;
    match written {
        Ok(()) => {
            if !dropped.is_empty() {
                notify_rows_dropped(db, tenant_id, channel).await;
            }
            for d in &dropped {
                tracing::error!(
                    node_id = %node_id, %tenant_id, channel, key = %d.item.log_key(),
                    "edge batch row refused by the database for its data — dropped: {}", d.error
                );
            }
            Some(dropped)
        }
        Err(e) => {
            tracing::error!(node_id = %node_id, %tenant_id, channel, "edge batch write failed, withholding the ack for redelivery: {e}");
            None
        }
    }
}

/// Tell the tenant's operators that edge sync dropped rows — the visible mark
/// of a loss that would otherwise live only in the log. One notification per
/// channel per day, carrying no count: a resent share drops its refused
/// rows again, so a running count would count them again; the admin-api log
/// names each row. Best-effort, since the rows are already gone either way.
/// The SYSTEM tenant carries no workload and no operator reads its feed for
/// one, so it is never notified.
async fn notify_rows_dropped(db: &crate::db::Db, tenant_id: uuid::Uuid, channel: &'static str) {
    if tenant_id == TenantId::SYSTEM.as_uuid() {
        return;
    }
    let n = crate::notifications::NewNotification {
        workspace_id: None,
        kind: crate::notifications::NotificationKind::EdgeSyncRowsDropped,
        dedup_key: format!("edge_sync_rows_dropped:{channel}:{}", chrono::Utc::now().format("%Y-%m-%d")),
        title: format!("Edge sync dropped records it could not store ({channel})"),
        summary: "Records arriving from an edge today were refused by the database for their content and \
                  dropped, so they could not hold back the rest of the sync. The admin-api log names each one."
            .to_string(),
        target_kind: None,
        target_id: None,
        payload: serde_json::json!({ "channel": channel }),
    };
    let notified: Result<bool, sqlx::Error> = async {
        let mut tdb = TenantConn::acquire(db, TenantId::from_edge(tenant_id)).await?;
        crate::notifications::notify(tdb.conn(), tenant_id, n).await
    }
    .await;
    if let Err(e) = notified {
        tracing::warn!(%tenant_id, channel, "failed to raise the edge-sync drop notification: {e}");
    }
}

/// Write the LLM records of a request — any tenants: the `gateway_audit` +
/// `llm_audit` rows, the stamp of every media blob they name, the
/// `conversation_turns` rows with their history (chunks, system prompt,
/// membership) and each newly inserted turn's session rollup. Runs inside the
/// caller's transaction, so the audit rows (carrying badges) and the turn rows
/// (carrying `transform_diff`) become visible together.
pub(crate) async fn ingest_llm_audit(
    conn: &mut IngestConn,
    items: &[&serde_json::Value],
    node_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    // Alignment rule: only admit records we actually intend to insert — an
    // empty-`message_hashes` array would yield an audit row with no matching
    // turn. Require non-empty.
    let chat_hashes = |item: &serde_json::Value| -> Option<Vec<String>> {
        let hashes: Vec<String> = item
            .get("message_hashes")?
            .as_array()?
            .iter()
            .filter_map(|v| v.as_str().map(str::to_string))
            .collect();
        (!hashes.is_empty()).then_some(hashes)
    };
    let is_media_turn = |item: &serde_json::Value| -> bool {
        item.get("media_call").is_some_and(|v| !v.is_null())
            && item.get("conversation_session_id").is_some_and(|v| !v.is_null())
            && chat_hashes(item).is_none()
    };
    let chat: Vec<(&serde_json::Value, Vec<String>)> =
        items.iter().filter_map(|item| chat_hashes(item).map(|h| (*item, h))).collect();
    let media_items: Vec<&serde_json::Value> = items.iter().copied().filter(|i| is_media_turn(i)).collect();
    // The session UPSERT stays per-record — it aggregates (turn_count + 1,
    // total_tokens + ...) — so it reads the typed record.
    let records: Vec<streamscope_core::audit::AuditRecord> = items
        .iter()
        .filter(|item| chat_hashes(item).is_some() || is_media_turn(item))
        .filter_map(|item| {
            serde_json::from_value::<streamscope_core::audit::AuditRecord>((*item).clone())
                .map_err(|e| {
                    // A record dropped here is simply absent from the session
                    // upsert; its audit/turn rows still land below.
                    tracing::warn!(
                        node_id = %node_id,
                        "audit record failed typed deserialization — session upsert skipped: {e}"
                    );
                })
                .ok()
        })
        .collect();

    // gateway_audit parent must land first so the FK from llm_audit resolves.
    insert_audit_jsonb(conn, &json_array(items)).await?;
    // The session aggregate (`turn_count + 1`, `total_* + ...`) is the one
    // non-idempotent write here. A request that already committed is
    // redelivered when its answer is lost, so the increment is gated on the
    // turn row being NEWLY inserted: the `conversation_turns` insert is keyed
    // on its primary key with `ON CONFLICT DO NOTHING`, so `RETURNING` yields
    // exactly the turns landing for the first time. The session row is thus an
    // exact rollup of `conversation_turns`, incremented once per turn.
    let mut fresh: HashSet<(uuid::Uuid, uuid::Uuid)> = HashSet::new();
    let mut added: Vec<AddedMessages> = Vec::new();
    if !chat.is_empty() {
        let turns = ChatTurns::build(conn, &chat).await?;
        turns.write_content(conn).await?;
        fresh.extend(bulk_insert_chat_turns(conn, &json_array(&turns.rows.iter().collect::<Vec<_>>())).await?);
        added = turns.added;
    }
    if !media_items.is_empty() {
        fresh.extend(bulk_insert_media_turns(conn, &json_array(&media_items)).await?);
    }
    // Once per turn written: the same record twice in one request (two shares
    // of a tenant, a restated record) inserts one turn, so it counts once.
    let mut counted: HashSet<(uuid::Uuid, uuid::Uuid)> = HashSet::new();
    let mut sessions: Vec<(&streamscope_core::audit::AuditRecord, uuid::Uuid)> = records
        .iter()
        .filter_map(|r| r.conversation_session_id.map(|s| (r, s)))
        .filter(|(r, _)| fresh.contains(&(r.tenant_id, r.request_id)) && counted.insert((r.tenant_id, r.request_id)))
        .collect();
    // One order for every writer, so two requests updating the same sessions
    // never wait on each other in a cycle.
    sessions.sort_by_key(|(r, s)| (r.tenant_id, *s, r.timestamp));
    for (record, session_id) in sessions {
        upsert_session_for_turn(conn, record, session_id).await?;
    }
    insert_session_messages(conn, &added, &fresh).await?;
    Ok(())
}

/// The turn rows of a request's chat records, and the history they name: each
/// record's chunks and the hashes it added to its session. The bodies a turn
/// names are stamped by the ingest — a carried one by its writer, any other
/// by the share's content check — so nothing here stamps them.
struct ChatTurns {
    /// The `conversation_turns` rows, as the JSON elements
    /// [`bulk_insert_chat_turns`] reads.
    rows: Vec<serde_json::Value>,
    /// Every chunk of every history, once per (tenant, hash), by key.
    chunks: Vec<serde_json::Value>,
    /// Per turn with a session: the hashes it added to it.
    added: Vec<AddedMessages>,
}

/// The messages one turn added to its session.
struct AddedMessages {
    tenant: uuid::Uuid,
    request: uuid::Uuid,
    session: uuid::Uuid,
    hashes: Vec<String>,
}

impl ChatTurns {
    /// Derive each record's history: its chunks, and how many of its leading
    /// messages the session's previous turn carried (`added_from`) — read off
    /// the parent turn when this request carries it, else off the parent's
    /// stored chain; 0 when neither is found.
    async fn build(conn: &mut IngestConn, chat: &[(&serde_json::Value, Vec<String>)]) -> Result<Self, sqlx::Error> {
        let uuid_of = |v: &serde_json::Value, k: &str| -> Option<uuid::Uuid> {
            v.get(k).and_then(|x| x.as_str()).filter(|s| !s.is_empty()).and_then(|s| s.parse().ok())
        };
        let in_request: HashMap<(uuid::Uuid, uuid::Uuid), &Vec<String>> = chat
            .iter()
            .filter_map(|(v, h)| Some(((uuid_of(v, "tenant_id")?, uuid_of(v, "request_id")?), h)))
            .collect();
        let missing: Vec<(uuid::Uuid, uuid::Uuid)> = chat
            .iter()
            .filter_map(|(v, _)| Some((uuid_of(v, "tenant_id")?, uuid_of(v, "parent_request_id")?)))
            .filter(|key| !in_request.contains_key(key))
            .collect();
        let stored: HashMap<(uuid::Uuid, uuid::Uuid), (String, usize)> = if missing.is_empty() {
            HashMap::new()
        } else {
            let (tenants, requests): (Vec<uuid::Uuid>, Vec<uuid::Uuid>) = missing.iter().copied().unzip();
            let rows: Vec<(uuid::Uuid, uuid::Uuid, String, i32)> = sqlx::query_as(
                "SELECT ct.tenant_id, ct.request_id, ct.history_head, ct.message_count \
                   FROM conversation_turns ct \
                   JOIN unnest($1::uuid[], $2::uuid[]) AS p(tenant_id, request_id) \
                     ON ct.tenant_id = p.tenant_id AND ct.request_id = p.request_id \
                  WHERE ct.history_head IS NOT NULL",
            )
            .bind(&tenants)
            .bind(&requests)
            .fetch_all(&mut *conn)
            .await?;
            rows.into_iter()
                .map(|(t, r, head, n)| ((t, r), (head, usize::try_from(n).unwrap_or(0))))
                .collect()
        };

        let mut turns = ChatTurns {
            rows: Vec::with_capacity(chat.len()),
            chunks: Vec::new(),
            added: Vec::new(),
        };
        let mut seen_chunks: HashSet<(uuid::Uuid, String)> = HashSet::new();
        for (v, hashes) in chat {
            let (Some(tenant), Some(request)) = (uuid_of(v, "tenant_id"), uuid_of(v, "request_id")) else {
                continue;
            };
            // From the parent turn in this request, else as stored. A parent not
            // landed yet (still in an edge outbox, or on another edge) leaves
            // the turn a baseline: its whole history counts as added, so the
            // audit search also lists it for the history it repeats. The turn
            // is written once, so a later parent does not revise it.
            let added_from = uuid_of(v, "parent_request_id")
                .map(|parent| match (in_request.get(&(tenant, parent)), stored.get(&(tenant, parent))) {
                    (Some(p), _) => super::history::added_from_parent(hashes, p),
                    (None, Some((head, n))) => super::history::added_from_stored(hashes, head, *n),
                    (None, None) => 0,
                })
                .unwrap_or(0);
            let chunks = super::history::chunks(hashes);
            let head = chunks.last().map(|c| c.hash.clone());
            for c in chunks {
                if seen_chunks.insert((tenant, c.hash.clone())) {
                    turns.chunks.push(serde_json::json!({
                        "tenant_id": tenant, "hash": c.hash, "parent_hash": c.parent, "hashes": c.hashes,
                    }));
                }
            }
            if let Some(session) = uuid_of(v, "conversation_session_id") {
                turns.added.push(AddedMessages { tenant, request, session, hashes: hashes[added_from..].to_vec() });
            }
            let mut row = serde_json::json!({
                "tenant_id": tenant,
                "request_id": v.get("request_id"),
                "timestamp": v.get("timestamp"),
                "conversation_session_id": v.get("conversation_session_id"),
                "turn_number": v.get("turn_number"),
                "parent_request_id": v.get("parent_request_id"),
                "is_baseline": v.get("is_baseline"),
                "history_head": head,
                "message_count": hashes.len(),
                "added_from": added_from,
                "message_hashes": hashes,
                "tools_available_hash": v.get("tools_available_hash"),
                "tools_effective_hash": v.get("tools_effective_hash"),
                "request_params": v.get("request_params"),
                "system_prompt_hash": v.get("system_prompt_hash"),
                "transform_diff": v.get("transform_diff"),
                "response_content": v.get("response_content"),
                "response_tool_calls": v.get("response_tool_calls"),
                "api_version": v.get("api_version"),
            });
            // An absent field must reach the insert as SQL NULL: kept as a JSON
            // `null`, `j->'transform_diff'` would store a jsonb null that no
            // reader decodes as "no diff".
            if let Some(fields) = row.as_object_mut() {
                fields.retain(|_, value| !value.is_null());
            }
            turns.rows.push(row);
        }
        let key = |v: &serde_json::Value| (v["tenant_id"].to_string(), v["hash"].as_str().unwrap_or("").to_string());
        turns.chunks.sort_by_key(key);
        Ok(turns)
    }

    /// Store the chunks.
    async fn write_content(&self, conn: &mut IngestConn) -> Result<(), sqlx::Error> {
        let chunk_refs: Vec<&serde_json::Value> = self.chunks.iter().collect();
        history_chunks::insert_chunks_jsonb(conn, &json_array(&chunk_refs)).await
    }
}

/// Record which messages each newly inserted turn (`fresh`: tenant, request)
/// added to its session (`conversation_session_messages`) — the turn's whole
/// history for a baseline turn. Only for a session row that exists: a record
/// whose session upsert was skipped writes no membership rather than refusing
/// the request.
async fn insert_session_messages(
    conn: &mut IngestConn,
    added: &[AddedMessages],
    fresh: &HashSet<(uuid::Uuid, uuid::Uuid)>,
) -> Result<(), sqlx::Error> {
    let mut rows: Vec<(uuid::Uuid, uuid::Uuid, &str)> = added
        .iter()
        .filter(|a| fresh.contains(&(a.tenant, a.request)))
        .flat_map(|a| a.hashes.iter().map(move |h| (a.tenant, a.session, h.as_str())))
        .collect();
    if rows.is_empty() {
        return Ok(());
    }
    rows.sort();
    rows.dedup();
    let tenants: Vec<uuid::Uuid> = rows.iter().map(|r| r.0).collect();
    let sessions: Vec<uuid::Uuid> = rows.iter().map(|r| r.1).collect();
    let hashes: Vec<&str> = rows.iter().map(|r| r.2).collect();
    sqlx::query(
        "INSERT INTO conversation_session_messages (tenant_id, session_id, hash) \
         SELECT n.tenant_id, n.session_id, n.hash \
           FROM unnest($1::uuid[], $2::uuid[], $3::text[]) AS n(tenant_id, session_id, hash) \
          WHERE EXISTS (SELECT 1 FROM sessions s WHERE s.tenant_id = n.tenant_id AND s.session_id = n.session_id) \
         ON CONFLICT (tenant_id, session_id, hash) DO NOTHING",
    )
    .bind(&tenants)
    .bind(&sessions)
    .bind(&hashes)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// Drop `by_tenant` entries whose tenant no longer exists, in one round trip.
///
/// An edge keeps buffering data (audit, MCP/web records, SSE events, messages,
/// tool definitions, blobs, usage counters) for a tenant that may be deleted
/// *after* the data was captured. Every target table FK-references
/// `tenants(id) ON DELETE CASCADE`, so re-inserting a deleted tenant's row
/// FK-violates on each resend — and the edge would resend that share forever,
/// stalling its outbox. The parent rows are already CASCADE-gone, so the
/// buffered items are undeliverable: pruning them answers the share as the
/// tenant's deletion, and the edge drops it. On a lookup error keep everything (the per-item handling
/// stays the fallback). `edge` identifies the reporting edge for logs only. Returns the entries
/// dropped.
pub(crate) async fn prune_deleted_tenants<T>(
    pool: &crate::db::Db,
    edge: uuid::Uuid,
    channel: &str,
    by_tenant: &mut HashMap<uuid::Uuid, T>,
) -> Vec<(uuid::Uuid, T)> {
    if by_tenant.is_empty() {
        return Vec::new();
    }
    let ids: Vec<uuid::Uuid> = by_tenant.keys().copied().collect();
    let existing: Vec<uuid::Uuid> =
        match sqlx::query_scalar("SELECT id FROM tenants WHERE id = ANY($1)")
            .bind(&ids)
            .fetch_all(pool.global(Global::TenantRegistry))
            .await
        {
            Ok(rows) => rows,
            Err(e) => {
                tracing::warn!(edge = %edge, channel, "tenant existence check failed, keeping all: {e}");
                return Vec::new();
            }
        };
    if existing.len() == by_tenant.len() {
        return Vec::new(); // common case: every tenant is live.
    }
    let live: std::collections::HashSet<uuid::Uuid> = existing.into_iter().collect();
    let deleted: Vec<(uuid::Uuid, T)> = by_tenant.extract_if(|tid, _| !live.contains(tid)).collect();
    for (tid, _) in &deleted {
        tracing::info!(edge = %edge, tenant_id = %tid, channel,
            "dropping buffered edge data for a deleted tenant (undeliverable)");
    }
    deleted
}

/// Store one replica's live load on this tenant's replica endpoints as
/// `upstream_load_samples` rows of beat `beat_id`, sampled now on the
/// database clock.
pub(crate) async fn insert_load_samples(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    instance_id: uuid::Uuid,
    beat_id: uuid::Uuid,
    rows: &[streamscope_core::proxy::qos_metrics::EndpointLoadReport],
) -> Result<(), sqlx::Error> {
    if rows.is_empty() {
        return Ok(());
    }
    let i32c = |v: u32| i32::try_from(v).unwrap_or(i32::MAX);
    let mut server_ids = Vec::with_capacity(rows.len());
    let mut endpoint_ids = Vec::with_capacity(rows.len());
    let mut in_flight = Vec::with_capacity(rows.len());
    let mut server_held = Vec::with_capacity(rows.len());
    let mut engine_read = Vec::with_capacity(rows.len());
    let mut waiting = Vec::with_capacity(rows.len());
    let mut running = Vec::with_capacity(rows.len());
    let mut kv_usage = Vec::with_capacity(rows.len());
    let mut age_ms = Vec::with_capacity(rows.len());
    // The engine's cumulative counters, one array per column in this order.
    let mut counters: [Vec<Option<f64>>; 11] = Default::default();
    // The learned limit's cumulative decisions, one array per column in this
    // order; NULL where the limit is not learned.
    let mut decisions: [Vec<Option<i64>>; 4] = Default::default();
    let mut held_by_class: Vec<serde_json::Value> = Vec::with_capacity(rows.len());
    let mut gated = Vec::with_capacity(rows.len());
    let mut adaptive_limit: Vec<Option<i32>> = Vec::with_capacity(rows.len());
    let mut adaptive_state: Vec<Option<&'static str>> = Vec::with_capacity(rows.len());
    let mut low_load_itl_us: Vec<Option<i32>> = Vec::with_capacity(rows.len());
    // The highest each gauge reached since the replica's previous beat.
    let mut in_flight_peak: Vec<i32> = Vec::with_capacity(rows.len());
    let mut server_held_peak: Vec<i32> = Vec::with_capacity(rows.len());
    let mut waiting_peak: Vec<Option<i32>> = Vec::with_capacity(rows.len());
    let mut running_peak: Vec<Option<i32>> = Vec::with_capacity(rows.len());
    let mut kv_usage_peak: Vec<Option<f64>> = Vec::with_capacity(rows.len());
    let mut running_queued_peak: Vec<Option<i32>> = Vec::with_capacity(rows.len());
    for r in rows {
        in_flight_peak.push(i32c(r.in_flight_peak));
        server_held_peak.push(i32c(r.server_held_peak));
        waiting_peak.push(r.engine.and_then(|g| g.waiting_peak).map(i32c));
        running_peak.push(r.engine.and_then(|g| g.running_peak).map(i32c));
        kv_usage_peak.push(r.engine.and_then(|g| g.kv_usage_peak));
        running_queued_peak.push(r.engine.and_then(|g| g.running_queued_peak).map(i32c));
        server_ids.push(r.server_id);
        endpoint_ids.push(r.endpoint_id);
        in_flight.push(i32c(r.in_flight));
        server_held.push(i32c(r.server_held));
        engine_read.push(r.engine_read);
        waiting.push(r.engine.map(|g| i32c(g.waiting)));
        running.push(r.engine.and_then(|g| g.running).map(i32c));
        kv_usage.push(r.engine.and_then(|g| g.kv_usage));
        age_ms.push(r.engine.map(|g| i32::try_from(g.age_ms).unwrap_or(i32::MAX)));
        let c = r.engine.map(|g| g.counters).unwrap_or_default();
        for (column, value) in counters.iter_mut().zip([
            c.preemptions,
            c.prompt_tokens,
            c.generation_tokens,
            c.prefix_queries,
            c.prefix_hits,
            c.queue_time_sum,
            c.queue_time_count,
            c.ttft_sum,
            c.ttft_count,
            c.itl_sum,
            c.itl_count,
        ]) {
            column.push(value);
        }
        let d = r.adaptive.and_then(|a| a.decisions);
        let i64c = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
        for (column, value) in decisions.iter_mut().zip([
            d.map(|d| d.grew),
            d.map(|d| d.stepped_down),
            d.map(|d| d.cut_preemption),
            d.map(|d| d.cut_kv_full),
        ]) {
            column.push(value.map(i64c));
        }
        held_by_class.push(serde_json::json!(r.server_held_by_class));
        gated.push(r.gated);
        adaptive_limit.push(r.adaptive.and_then(|a| a.limit).map(i32c));
        adaptive_state.push(r.adaptive.map(|a| a.state.as_str()));
        low_load_itl_us.push(r.adaptive.and_then(|a| a.low_load_itl_us).map(i32c));
    }
    sqlx::query(
        "INSERT INTO upstream_load_samples \
         (tenant_id, edge_instance_id, beat_id, sampled_at, server_id, endpoint_id, in_flight, server_held, \
          engine_read, engine_waiting, engine_running, engine_kv_usage, engine_age_ms, \
          engine_preemptions, engine_prompt_tokens, engine_generation_tokens, \
          engine_prefix_queries, engine_prefix_hits, engine_queue_time_sum, \
          engine_queue_time_count, engine_ttft_sum, engine_ttft_count, server_held_by_class, gated, \
          adaptive_limit, adaptive_state, adaptive_low_load_itl_us, \
          in_flight_peak, server_held_peak, engine_waiting_peak, engine_running_peak, \
          engine_kv_usage_peak, engine_running_queued_peak, \
          engine_itl_sum, engine_itl_count, \
          adaptive_grew, adaptive_stepped_down, adaptive_cut_preemption, adaptive_cut_kv_full) \
         SELECT $1, $2, $12, now(), u.server_id, u.endpoint_id, u.in_flight, u.server_held, \
                u.engine_read, u.waiting, u.running, u.kv_usage, u.age_ms, \
                u.preemptions, u.prompt_tokens, u.generation_tokens, u.prefix_queries, \
                u.prefix_hits, u.queue_time_sum, u.queue_time_count, u.ttft_sum, u.ttft_count, \
                u.held_by_class, u.gated, u.adaptive_limit, u.adaptive_state, u.low_load_itl_us, \
                u.in_flight_peak, u.server_held_peak, u.waiting_peak, u.running_peak, u.kv_usage_peak, \
                u.running_queued_peak, u.itl_sum, u.itl_count, \
                u.grew, u.stepped_down, u.cut_preemption, u.cut_kv_full \
         FROM unnest($3::uuid[], $4::uuid[], $5::int[], $6::int[], $7::bool[], \
                     $8::int[], $9::int[], $10::float8[], $11::int[], \
                     $13::float8[], $14::float8[], $15::float8[], $16::float8[], $17::float8[], \
                     $18::float8[], $19::float8[], $20::float8[], $21::float8[], $22::jsonb[], \
                     $23::bool[], $24::int[], $25::text[], $26::int[], \
                     $27::int[], $28::int[], $29::int[], $30::int[], $31::float8[], $32::int[], \
                     $33::float8[], $34::float8[], $35::int8[], $36::int8[], $37::int8[], $38::int8[]) \
           AS u(server_id, endpoint_id, in_flight, server_held, engine_read, \
                waiting, running, kv_usage, age_ms, \
                preemptions, prompt_tokens, generation_tokens, prefix_queries, prefix_hits, \
                queue_time_sum, queue_time_count, ttft_sum, ttft_count, held_by_class, gated, \
                adaptive_limit, adaptive_state, low_load_itl_us, \
                in_flight_peak, server_held_peak, waiting_peak, running_peak, kv_usage_peak, \
                running_queued_peak, itl_sum, itl_count, \
                grew, stepped_down, cut_preemption, cut_kv_full)",
    )
    .bind(tenant_id)
    .bind(instance_id)
    .bind(&server_ids)
    .bind(&endpoint_ids)
    .bind(&in_flight)
    .bind(&server_held)
    .bind(&engine_read)
    .bind(&waiting)
    .bind(&running)
    .bind(&kv_usage)
    .bind(&age_ms)
    .bind(beat_id)
    .bind(&counters[0])
    .bind(&counters[1])
    .bind(&counters[2])
    .bind(&counters[3])
    .bind(&counters[4])
    .bind(&counters[5])
    .bind(&counters[6])
    .bind(&counters[7])
    .bind(&counters[8])
    .bind(&held_by_class)
    .bind(&gated)
    .bind(&adaptive_limit)
    .bind(&adaptive_state)
    .bind(&low_load_itl_us)
    .bind(&in_flight_peak)
    .bind(&server_held_peak)
    .bind(&waiting_peak)
    .bind(&running_peak)
    .bind(&kv_usage_peak)
    .bind(&running_queued_peak)
    .bind(&counters[9])
    .bind(&counters[10])
    .bind(&decisions[0])
    .bind(&decisions[1])
    .bind(&decisions[2])
    .bind(&decisions[3])
    .execute(conn)
    .await
    .map(|_| ())
}

/// Record one gateway's stand on each replica endpoint of this tenant it routes
/// to, on the database's clock (the stand carries the reporting process's
/// `epoch_started_at`, matched by equality when read), and
/// delete its stands on this tenant's endpoints the report no longer states. A
/// stand that has not changed is rewritten once it is a heartbeat old (a fifth
/// of the connected window), so it survives as many failed writes as the
/// window allows beats; a beat landing sooner writes nothing. A replica's
/// reports are written in order (the caller's newer-wins claim), so a stand
/// never moves backwards.
/// Only an endpoint of this tenant still at the URL the gateway reached is
/// recorded (the join is the check), and a stand the report names at a URL the
/// endpoint no longer has is retired like one it does not name. Runs on a
/// connection scoped to `tenant_id`.
pub(crate) async fn record_endpoint_stands(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    instance_id: uuid::Uuid,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    states: &[streamscope_core::proxy::health::EndpointState],
) -> Result<(), sqlx::Error> {
    let endpoint_ids: Vec<uuid::Uuid> = states.iter().map(|s| s.endpoint_id).collect();
    let urls: Vec<&str> = states.iter().map(|s| s.url.as_str()).collect();
    let out: Vec<bool> = states.iter().map(|s| s.out).collect();
    // Both statements run even when the first fails: outside a transaction the
    // retirement still applies on its own.
    let stated = sqlx::query(
        "INSERT INTO upstream_endpoint_stands \
             (tenant_id, endpoint_id, edge_instance_id, out_of_rotation, session_started_at, stated_at) \
         SELECT DISTINCT ON (e.id) $1, e.id, $2, s.out, $3, now() \
           FROM unnest($4::uuid[], $5::text[], $6::bool[]) AS s(endpoint_id, url, out) \
           JOIN upstream_server_endpoints e ON e.id = s.endpoint_id AND e.tenant_id = $1 AND e.url = s.url \
          ORDER BY e.id, s.out DESC \
         ON CONFLICT (tenant_id, endpoint_id, edge_instance_id) DO UPDATE SET \
             out_of_rotation = EXCLUDED.out_of_rotation, session_started_at = EXCLUDED.session_started_at, \
             stated_at = EXCLUDED.stated_at \
          WHERE upstream_endpoint_stands.out_of_rotation IS DISTINCT FROM EXCLUDED.out_of_rotation \
             OR upstream_endpoint_stands.session_started_at IS DISTINCT FROM EXCLUDED.session_started_at \
             OR upstream_endpoint_stands.stated_at < EXCLUDED.stated_at - make_interval(secs => $7)",
    )
    .bind(tenant_id)
    .bind(instance_id)
    .bind(epoch_started_at)
    .bind(&endpoint_ids)
    .bind(&urls)
    .bind(&out)
    .bind(crate::settings::admin_settings().edge_connected_window().num_milliseconds() as f64 / 5000.0)
    .execute(&mut *conn)
    .await;
    let retired = sqlx::query(
        "DELETE FROM upstream_endpoint_stands st \
          WHERE st.edge_instance_id = $1 \
            AND NOT EXISTS (SELECT 1 FROM unnest($2::uuid[], $3::text[]) AS s(endpoint_id, url) \
                              JOIN upstream_server_endpoints e ON e.id = s.endpoint_id AND e.url = s.url \
                             WHERE s.endpoint_id = st.endpoint_id)",
    )
    .bind(instance_id)
    .bind(&endpoint_ids)
    .bind(&urls)
    .execute(&mut *conn)
    .await;
    stated.and(retired).map(|_| ())
}

/// The operator-facing name of the server a breaker event names, for the
/// notification title.
pub(crate) async fn upstream_server_name(
    conn: &mut Scoped,
    event: &streamscope_core::proxy::health::HealthTransitionEvent,
) -> Result<Option<String>, sqlx::Error> {
    let Some(id) = event.upstream_server_id.as_deref().and_then(|s| s.parse::<uuid::Uuid>().ok()) else {
        return Ok(None);
    };
    sqlx::query_scalar("SELECT name FROM upstream_servers WHERE id = $1 AND tenant_id = $2")
        .bind(id)
        .bind(event.tenant_id)
        .fetch_optional(conn)
        .await
}

/// Record the breaker state of a replica endpoint as this gateway sees it, for
/// the server page. Only an endpoint
/// of this tenant's server, still at the URL the event names, is recorded (the
/// INSERT's WHERE is the check): a breaker reported again after a reconnect
/// may describe the host it pointed at before. An event naming no endpoint (the
/// server as a whole) records nothing here.
pub(crate) async fn record_endpoint_health(
    conn: &mut Scoped,
    instance_id: uuid::Uuid,
    event: &streamscope_core::proxy::health::HealthTransitionEvent,
) -> Result<(), sqlx::Error> {
    let Some(endpoint_id) = event.endpoint_id else {
        return Ok(());
    };
    sqlx::query(
        "INSERT INTO upstream_endpoint_health \
             (tenant_id, endpoint_id, edge_instance_id, status, reason, changed_at, reported_at) \
         SELECT $1, e.id, $3, $4, $5, \
                CASE WHEN $4 = 'down' THEN to_timestamp($6) ELSE NOW() END, NOW() \
           FROM upstream_server_endpoints e \
          WHERE e.id = $2 AND e.tenant_id = $1 AND e.url = $7 \
         ON CONFLICT (tenant_id, endpoint_id, edge_instance_id) DO UPDATE SET \
             status = EXCLUDED.status, reason = EXCLUDED.reason, \
             changed_at = EXCLUDED.changed_at, reported_at = EXCLUDED.reported_at",
    )
    .bind(event.tenant_id)
    .bind(endpoint_id)
    .bind(instance_id)
    .bind(if event.new_status == "down" { "down" } else { "up" })
    .bind(&event.reason)
    // When the breaker opened: a re-report after a reconnect keeps the
    // outage's start.
    .bind(event.episode_epoch as f64)
    .bind(&event.endpoint_url)
    .execute(conn)
    .await
    .map(|_| ())
}

/// The operator notification for a breaker event. Episode-scoped dedup so a
/// flapping server re-notifies once per outage; the down + up of one episode
/// share `episode_epoch`. Each replica endpoint trips on its own, so the
/// endpoint is part of the key.
pub(crate) fn health_notification(
    event: &streamscope_core::proxy::health::HealthTransitionEvent,
    server_name: Option<String>,
) -> crate::notifications::NewNotification {
    let is_down = event.new_status == "down";
    let server_uuid = event.upstream_server_id.as_deref().and_then(|s| s.parse::<uuid::Uuid>().ok());
    let server_disc = event.upstream_server_id.as_deref().unwrap_or(&event.provider);
    let dedup_key = match event.endpoint_id {
        Some(ep) => format!("upstream_health:{server_disc}:{ep}:{}:{}", event.episode_epoch, event.new_status),
        None => format!("upstream_health:{server_disc}:{}:{}", event.episode_epoch, event.new_status),
    };
    let label = match (&server_name, &event.endpoint_url) {
        (Some(name), Some(url)) => format!("{name} ({url})"),
        (Some(name), None) => name.clone(),
        (None, _) => event.provider.clone(),
    };
    let (kind, title, summary) = if is_down {
        (
            crate::notifications::NotificationKind::UpstreamUnhealthy,
            format!("Upstream unavailable: {label}"),
            format!(
                "{label} ({}) stopped responding and was taken out of rotation: {}",
                event.provider, event.reason
            ),
        )
    } else {
        (
            crate::notifications::NotificationKind::UpstreamRecovered,
            format!("Upstream recovered: {label}"),
            format!("{label} ({}) is responding again and back in rotation.", event.provider),
        )
    };
    crate::notifications::NewNotification {
        workspace_id: None,
        kind,
        dedup_key,
        title,
        summary,
        target_kind: Some("upstream_server"),
        target_id: server_uuid,
        payload: serde_json::json!({
            "upstream_server_id": event.upstream_server_id,
            "provider": event.provider,
            "model": event.model,
            "status": event.new_status,
            "reason": event.reason,
        }),
    }
}

/// Append one `edge_stats_samples` row for an instance, keyed by its report's
/// `(process_epoch, seq)`: written once however often the report is delivered
/// (`ON CONFLICT DO NOTHING` on the key), and only while that epoch is the
/// instance's current one.
pub(crate) async fn insert_stats_sample(
    db: &crate::db::Db,
    instance_id: uuid::Uuid,
    s: &EdgeProxyStats,
    (epoch, seq): (i64, i64),
) -> Result<(), sqlx::Error> {
    // u64 counters into i64 columns — clamp rather than wrap on the
    // (practically unreachable) overflow case; a wrapped-negative counter
    // would corrupt the delta query that derives per-interval rates.
    let i64c = |v: u64| i64::try_from(v).unwrap_or(i64::MAX);
    let overhead_buckets: Vec<i64> = s.overhead_buckets.iter().map(|&v| i64c(v)).collect();
    sqlx::query(
        "INSERT INTO edge_stats_samples \
         (edge_instance_id, requests_total, errors_total, active_streams, \
          cpu_percent, memory_rss_bytes, memory_limit_bytes, uptime_secs, \
          overhead_buckets, overhead_sum_us, overhead_count, \
          pending_audit_count, process_epoch, state_seq) \
         SELECT $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14 \
          WHERE EXISTS (SELECT 1 FROM edge_instances WHERE id = $1 AND process_epoch = $13) \
         ON CONFLICT (edge_instance_id, process_epoch, state_seq) DO NOTHING",
    )
    .bind(instance_id)
    .bind(i64c(s.requests_total))
    .bind(i64c(s.errors_total))
    .bind(i64c(s.active_streams))
    .bind(s.cpu_percent)
    .bind(i64c(s.memory_rss_bytes))
    .bind(s.memory_limit_bytes.map(i64c))
    .bind(i64c(s.uptime_secs))
    .bind(&overhead_buckets)
    .bind(i64c(s.overhead_sum_us))
    .bind(i64c(s.overhead_count))
    .bind(i64c(s.pending_audit_count))
    .bind(epoch)
    .bind(seq)
    .execute(db.global(Global::Infra))
    .await
    .map(|_| ())
}

/// Count one "model not found" answer from a replica endpoint. Only an
/// endpoint of this tenant, still at the URL that refused, is recorded (the
/// WHERE is the check).
pub(crate) async fn record_model_missing(
    conn: &mut Scoped,
    event: &streamscope_core::proxy::health::EndpointModelMissing,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO upstream_endpoint_mismatches (tenant_id, endpoint_id, upstream_model, last_seen_at) \
         SELECT $1, e.id, $3, NOW() FROM upstream_server_endpoints e \
          WHERE e.id = $2 AND e.tenant_id = $1 AND e.url = $4 \
         ON CONFLICT (tenant_id, endpoint_id, upstream_model) DO UPDATE SET \
             reports = upstream_endpoint_mismatches.reports + 1, last_seen_at = EXCLUDED.last_seen_at",
    )
    .bind(event.tenant_id)
    .bind(event.endpoint_id)
    .bind(&event.model)
    .bind(&event.url)
    .execute(conn)
    .await
    .map(|_| ())
}

/// Bulk INSERT audit records into PostgreSQL via JSONB.
///
/// LLM rows are split across two tables: `gateway_audit` (parent / common
/// columns + `kind` discriminator) and `llm_audit` (LLM-specific columns + FK
/// to the parent). The parent INSERT runs first; the child FK is `ON DELETE
/// CASCADE` so retention only has to delete the parent row.
///
/// Both INSERTs read the same JSONB payload via `jsonb_array_elements()`. No
/// Rust-side deserialization is needed.
async fn insert_audit_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    insert_gateway_audit_jsonb(conn, payload, "llm").await?;
    insert_llm_audit_jsonb(conn, payload).await?;
    Ok(())
}

/// UPSERT the materialized `sessions` row for gateway traffic that carries a
/// session id but produces no LLM turn — an MCP-only or A2A-only client.
///
/// Without it such a session is invisible everywhere a session is *listed* or
/// *owned*, because both read `sessions` and only the LLM/media ingest path
/// writes there; the audit trail shows the calls but nothing ties them into a
/// session. Set-based over the same JSONB batch the audit insert reads, so it
/// costs one statement per batch.
///
/// **Invariant: every aggregate on this row is LLM-denominated** (turn count,
/// tokens, cost, latency), so a gateway-only row seeds them at zero and a
/// conflict touches no aggregate at all. An LLM turn arriving later accumulates
/// onto it normally; a row the LLM path already wrote must never be disturbed by
/// MCP/A2A traffic sharing its id.
///
/// The conflict arm therefore moves only `updated_at` and — for a row that has
/// none yet — `workspace_id`. Attribution is provenance rather than an
/// aggregate, and it is write-once: a nil workspace is filled in by the earliest
/// call that knows one, and a workspace already recorded is never overwritten.
/// Without that fill-in a session whose first call arrived unattributed would
/// stay unattributed for life, which means absent from every workspace-filtered
/// listing rather than merely unlabelled.
///
/// **`wid` must be resolved across the whole partition, not read off the
/// `DISTINCT ON` row.** That row is the session's *earliest* call, so a bare
/// `wid` would discard a workspace carried by a later call in the same batch —
/// and for a session that begins and ends inside one flush, no later batch ever
/// arrives to correct it. Hence the `FIRST_VALUE` over the full partition,
/// ordered so attributed calls sort ahead of unattributed ones: it yields the
/// earliest call that names a workspace, or nil when none does.
///
/// A session with a call this delivery inserted (`fresh`, the `(tenant_id,
/// request_id)` pairs [`insert_gateway_audit_jsonb_fresh`] returned) takes this
/// transaction's id as `landed_xid`, so the expert agent reads it again; a
/// redelivered call leaves the stamp where it was.
async fn upsert_gateway_only_sessions(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
    fresh: &[(uuid::Uuid, uuid::Uuid)],
) -> Result<(), sqlx::Error> {
    let (fresh_tenants, fresh_requests): (Vec<uuid::Uuid>, Vec<uuid::Uuid>) = fresh.iter().copied().unzip();
    sqlx::query(
        // `session_id` is the hashed session UUID — typed on the wire, so it
        // always casts — and absent on untracked traffic (an admin test call).
        // Per session in the batch: identity from its earliest call, `created_at`
        // from the earliest timestamp and `updated_at` from the latest.
        // A new row has no LLM turn, so no spend to name a currency for
        // (`cost_currency_count` 0); the update arm leaves the classification
        // to the LLM upsert, the only writer that adds spend.
        "INSERT INTO sessions (session_id, tenant_id, user_id, user_email, source, key_id, \
                               workspace_id, turn_count, cost_currency, cost_currency_count, \
                               created_at, updated_at, landed_xid) \
         SELECT DISTINCT ON (tid, sid) \
                sid, tid, uid, \
                (SELECT email FROM users WHERE tenant_id = tid AND id = uid), \
                CASE WHEN (SELECT email FROM users WHERE tenant_id = tid AND id = uid) = $2 THEN 'agent' ELSE 'user' END, \
                kid, \
                FIRST_VALUE(wid) OVER ( \
                    PARTITION BY tid, sid \
                    ORDER BY (wid = '00000000-0000-0000-0000-000000000000'::uuid), ts \
                    ROWS BETWEEN UNBOUNDED PRECEDING AND UNBOUNDED FOLLOWING \
                ), 0, NULL, 0, \
                MIN(ts) OVER (PARTITION BY tid, sid), \
                MAX(ts) OVER (PARTITION BY tid, sid), \
                CASE WHEN bool_or(fresh) OVER (PARTITION BY tid, sid) \
                     THEN pg_current_xact_id()::text::bigint END \
         FROM ( \
             SELECT (j->>'session_id')::uuid      AS sid, \
                    (j->>'tenant_id')::uuid       AS tid, \
                    (j->>'user_id')::uuid         AS uid, \
                    (j->>'key_id')::uuid          AS kid, \
                    COALESCE((j->>'workspace_id')::uuid, \
                             '00000000-0000-0000-0000-000000000000'::uuid) AS wid, \
                    (j->>'timestamp')::timestamptz AS ts, \
                    ((j->>'tenant_id')::uuid, (j->>'request_id')::uuid) IN \
                        (SELECT f.t, f.r FROM unnest($3::uuid[], $4::uuid[]) AS f(t, r)) AS fresh \
             FROM jsonb_array_elements($1) AS j \
             WHERE j->>'session_id' IS NOT NULL \
               AND j->>'tenant_id' IS NOT NULL \
               AND j->>'user_id' IS NOT NULL \
               AND j->>'timestamp' IS NOT NULL \
         ) s \
         ORDER BY tid, sid, ts \
         ON CONFLICT (tenant_id, session_id) DO UPDATE SET \
             created_at = LEAST(sessions.created_at, EXCLUDED.created_at), \
             updated_at = GREATEST(sessions.updated_at, EXCLUDED.updated_at), \
             landed_xid = COALESCE(EXCLUDED.landed_xid, sessions.landed_xid), \
             workspace_id = COALESCE( \
                 NULLIF(sessions.workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), \
                 EXCLUDED.workspace_id)",
    )
    .bind(payload)
    .bind(crate::agent::AGENT_EMAIL)
    .bind(&fresh_tenants)
    .bind(&fresh_requests)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::debug!("upsert gateway-only sessions via jsonb: {e}");
        e
    })?;
    Ok(())
}

/// The parent `gateway_audit` insert for every record in the JSONB array (`$1`),
/// `$2` the kind discriminator (`"llm"`, `"mcp"`, `"web"`, `"a2a"`) — one writer
/// serves every protocol. `$3` is the agent's email.
///
/// `source` is stamped here, once, from the row's user identity: the built-in
/// expert agent's own traffic ('agent') vs everything else ('user'). Reads
/// filter `source <> 'agent'` as a constant predicate instead of resolving the
/// agent user_id per query. `users(email, tenant_id)` is unique-indexed; this is
/// the async/batched ingest path, not a request-latency path.
macro_rules! gateway_audit_insert {
    () => {
        "INSERT INTO gateway_audit (
        request_id, timestamp, tenant_id, workspace_id, user_id, key_id, app_id, session_id,
        user_agent, ip, client_ip, end_user, end_user_groups, detection_method, kind, source,
        latency_total_ms, status_code, error_category, error_detail, limit_bucket
    )
    SELECT
        (j->>'request_id')::uuid,
        (j->>'timestamp')::timestamptz,
        (j->>'tenant_id')::uuid,
        COALESCE((j->>'workspace_id')::uuid, '00000000-0000-0000-0000-000000000000'::uuid),
        (j->>'user_id')::uuid,
        (j->>'key_id')::uuid,
        j->>'app_id',
        (j->>'session_id')::uuid,
        j->>'user_agent',
        j->>'ip',
        j->>'client_ip',
        j->>'end_user',
        ARRAY(SELECT jsonb_array_elements_text(COALESCE(j->'end_user_groups', '[]'::jsonb))),
        j->>'detection_method',
        $2::text,
        CASE WHEN (j->>'user_id')::uuid = (
                 SELECT u.id FROM users u
                  WHERE u.email = $3 AND u.tenant_id = (j->>'tenant_id')::uuid
             ) THEN 'agent' ELSE 'user' END,
        COALESCE((j->>'latency_total_ms')::bigint, 0),
        (j->>'status_code')::smallint,
        j->>'error_category',
        j->>'error_detail',
        j->>'limit_bucket'
    FROM jsonb_array_elements($1) AS j
    ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING"
    };
}
const GATEWAY_AUDIT_INSERT: &str = gateway_audit_insert!();
/// [`GATEWAY_AUDIT_INSERT`], returning each row it inserted.
const GATEWAY_AUDIT_INSERT_RETURNING: &str = concat!(gateway_audit_insert!(), " RETURNING tenant_id, request_id");

/// Insert the parent `gateway_audit` row for every record in the JSONB array.
async fn insert_gateway_audit_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
    kind: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(GATEWAY_AUDIT_INSERT)
        .bind(payload)
        .bind(kind)
        .bind(crate::agent::AGENT_EMAIL)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::debug!("bulk insert gateway_audit via jsonb: {e}");
            e
        })?;
    Ok(())
}

/// [`insert_gateway_audit_jsonb`], returning the `(tenant_id, request_id)` of
/// each row it inserted (a row already stored is not among them) — what a
/// gateway-only session upsert stamps by.
async fn insert_gateway_audit_jsonb_fresh(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
    kind: &str,
) -> Result<Vec<(uuid::Uuid, uuid::Uuid)>, sqlx::Error> {
    sqlx::query_as(GATEWAY_AUDIT_INSERT_RETURNING)
        .bind(payload)
        .bind(kind)
        .bind(crate::agent::AGENT_EMAIL)
        .fetch_all(&mut *conn)
        .await
        .map_err(|e| {
            tracing::debug!("bulk insert gateway_audit via jsonb: {e}");
            e
        })
}

/// MCP audit batch — writes both `gateway_audit` (kind='mcp') and `mcp_audit`
/// rows for every record in the JSONB array, on the ingest connection — which
/// sees every tenant, so each row carries and each lookup binds its own
/// `tenant_id`.
///
/// Side effects:
/// 0. **Gateway-only session materialization** — see
///    [`upsert_gateway_only_sessions`]: an MCP-only session gets the `sessions`
///    row that listing and ownership checks read, which the LLM ingest path
///    would otherwise never write for it.
/// 1. **Session pin write-through** — every audit row that carries
///    `(virtual_server_id, upstream_server_id, mcp_session_id, user_id)`
///    UPSERTs an `mcp_sessions` row so the live-sessions admin UI sees it
///    and (future) cross-instance reverse-routing has a DB lookup target.
///    `protocol_version` defaults to `'unknown'` for non-`initialize`
///    rows; the schema requires NOT NULL but the column is overwritten on
///    the next initialize call from the same session.
///
/// Server-initiated events among the rows are announced by the caller, after
/// its transaction commits ([`is_mcp_fanout_method`]).
///
/// Returns the `request_id`s of the `mcp_audit` rows this call inserted (a row
/// already stored is not among them).
pub async fn insert_mcp_audit_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<Vec<uuid::Uuid>, sqlx::Error> {
    let fresh = insert_gateway_audit_jsonb_fresh(conn, payload, "mcp").await?;
    upsert_gateway_only_sessions(&mut *conn, payload, &fresh).await?;

    let inserted: Vec<(uuid::Uuid,)> = sqlx::query_as(
        // Cross-instance protocol_version recovery happens in two layers:
        //   1. The `batch_pv` CTE extracts the session's negotiated version
        //      from any row in THIS batch that carries one — handles the
        //      case where `initialize` and a follow-up call ride the same
        //      ingest from a single proxy instance, since `mcp_sessions`
        //      hasn't been UPSERTed yet at the moment the audit row is
        //      emitted.
        //   2. The cross-batch fallback (subquery on mcp_sessions) handles
        //      the actual horizontal-scaling case: a sibling proxy emits an
        //      audit row with NULL `protocol_version` because it didn't see
        //      `initialize`, but the row from the box that did handle it
        //      already landed and populated mcp_sessions.
        // The 'unknown' filter on the mcp_sessions subquery skips placeholder
        // rows written when the version was unavailable at session-pin time.
        "WITH batch_pv AS (
            SELECT (j->>'tenant_id')::uuid     AS tenant_id,
                   j->>'mcp_session_id'         AS session_id,
                   MAX(j->>'protocol_version')  AS protocol_version
            FROM jsonb_array_elements($1) AS j
            WHERE j->>'protocol_version' IS NOT NULL
              AND j->>'protocol_version' <> ''
              AND j->>'mcp_session_id' IS NOT NULL
            GROUP BY 1, 2
        )
        INSERT INTO mcp_audit (
            request_id, timestamp, tenant_id, workspace_id,
            virtual_server_id, upstream_server_id, mcp_session_id,
            method, tool_id, prompt_id, resource_uri,
            params, result, error_code, error_message,
            upstream_latency_ms, request_bytes, response_bytes,
            protocol_version, badges, transform_diff
        )
        SELECT
            (j->>'request_id')::uuid,
            (j->>'timestamp')::timestamptz,
            (j->>'tenant_id')::uuid,
            COALESCE((j->>'workspace_id')::uuid, '00000000-0000-0000-0000-000000000000'::uuid),
            (j->>'virtual_server_id')::uuid,
            (j->>'upstream_server_id')::uuid,
            j->>'mcp_session_id',
            j->>'method',
            j->>'tool_id',
            j->>'prompt_id',
            j->>'resource_uri',
            j->'params',
            j->'result',
            (j->>'error_code')::int,
            j->>'error_message',
            COALESCE((j->>'upstream_latency_ms')::bigint, 0),
            (j->>'request_bytes')::int,
            (j->>'response_bytes')::int,
            COALESCE(
                j->>'protocol_version',
                (SELECT b.protocol_version FROM batch_pv b
                 WHERE b.tenant_id = (j->>'tenant_id')::uuid
                   AND b.session_id = j->>'mcp_session_id'),
                (SELECT s.protocol_version FROM mcp_sessions s
                 WHERE s.tenant_id = (j->>'tenant_id')::uuid
                   AND s.session_id = j->>'mcp_session_id'
                   AND s.protocol_version <> 'unknown'
                 LIMIT 1)
            ),
            COALESCE(j->'badges', '[]'::jsonb),
            COALESCE(j->'transform_diff', '{}'::jsonb)
        FROM jsonb_array_elements($1) AS j
        ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING
        RETURNING request_id",
    )
    .bind(payload)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::debug!("bulk insert mcp_audit via jsonb: {e}");
        e
    })?;
    let inserted: Vec<uuid::Uuid> = inserted.into_iter().map(|(id,)| id).collect();

    // Session pin write-through. The sub-query against mcp_upstream_servers
    // pulls upstream_url so reverse-path lookups on a different instance
    // can target the right URL without round-tripping back through the
    // proxy's in-process map. Rows missing user_id / virtual_server_id /
    // upstream_server_id are skipped (probe / unauthenticated rows).
    // Dedupe per `(tenant_id, session_id)` before the UPSERT — a single
    // streaming `tools/call` produces 4-5 audit rows in the batch
    // (the per-request row + per-event sampling / elicitation / list_changed
    // rows), all sharing the same session. PostgreSQL refuses
    // `ON CONFLICT DO UPDATE` against a batch that touches the same target
    // tuple twice, so the SELECT keeps only the most recent row per session.
    // Don't fail the audit insert on a session-pin mishap — the pin is an
    // observability + cross-instance hint, the audit is durable. It runs
    // under a SAVEPOINT: a failed statement aborts the caller's transaction,
    // whose COMMIT would then silently roll back every audit row above.
    let pinned: Result<(), sqlx::Error> = async {
        let mut sp = conn.savepoint().await?;
        sqlx::query(
            "INSERT INTO mcp_sessions
                (tenant_id, session_id, virtual_server_id, user_id, key_id,
                 protocol_version, capabilities,
                 upstream_server_id, upstream_url, last_seen_at)
            SELECT DISTINCT ON ((j->>'tenant_id')::uuid, j->>'mcp_session_id')
                (j->>'tenant_id')::uuid,
                j->>'mcp_session_id',
                (j->>'virtual_server_id')::uuid,
                (j->>'user_id')::uuid,
                (j->>'key_id')::uuid,
                COALESCE(j->>'protocol_version', 'unknown'),
                '{}'::jsonb,
                (j->>'upstream_server_id')::uuid,
                (SELECT u.upstream_url FROM mcp_upstream_servers u
                 WHERE u.tenant_id = (j->>'tenant_id')::uuid
                   AND u.id = (j->>'upstream_server_id')::uuid),
                COALESCE((j->>'timestamp')::timestamptz, NOW())
            FROM jsonb_array_elements($1) AS j
            WHERE j ? 'mcp_session_id'
              AND j->>'mcp_session_id' IS NOT NULL
              AND j ? 'virtual_server_id'
              AND j->>'virtual_server_id' IS NOT NULL
              AND j ? 'user_id'
              AND j->>'user_id' IS NOT NULL
              AND j ? 'upstream_server_id'
              AND j->>'upstream_server_id' IS NOT NULL
              -- Skip rows whose parent VS / upstream / user got deleted
              -- between the proxy's audit event and our batch processing.
              -- The session pin is an observability hint, not durable state;
              -- a deleted parent means the pin would never be useful anyway.
              -- Without these guards, the FK constraints reject the whole
              -- batch with a warn — visible noise, no functional impact.
              AND EXISTS (SELECT 1 FROM mcp_virtual_servers vs
                           WHERE vs.tenant_id = (j->>'tenant_id')::uuid
                             AND vs.id = (j->>'virtual_server_id')::uuid)
              AND EXISTS (SELECT 1 FROM mcp_upstream_servers us
                           WHERE us.tenant_id = (j->>'tenant_id')::uuid
                             AND us.id = (j->>'upstream_server_id')::uuid)
              AND EXISTS (SELECT 1 FROM users u
                           WHERE u.tenant_id = (j->>'tenant_id')::uuid
                             AND u.id = (j->>'user_id')::uuid)
            ORDER BY
                (j->>'tenant_id')::uuid,
                j->>'mcp_session_id',
                (j->>'timestamp')::timestamptz DESC NULLS LAST
            ON CONFLICT (tenant_id, session_id) DO UPDATE
                SET upstream_server_id = COALESCE(EXCLUDED.upstream_server_id,
                                                  mcp_sessions.upstream_server_id),
                    upstream_url       = COALESCE(EXCLUDED.upstream_url,
                                                  mcp_sessions.upstream_url),
                    -- Promote 'unknown' to a real version when a later batch
                    -- (notably the initialize ingest) lands after a sibling-
                    -- instance follow-up call already wrote the placeholder.
                    -- Cross-instance batches arrive in arbitrary order, so the
                    -- row that wins on first INSERT must yield to the row that
                    -- carries the negotiated version.
                    protocol_version   = CASE
                                             WHEN mcp_sessions.protocol_version = 'unknown'
                                                  AND EXCLUDED.protocol_version <> 'unknown'
                                                 THEN EXCLUDED.protocol_version
                                             ELSE mcp_sessions.protocol_version
                                         END,
                    last_seen_at       = GREATEST(mcp_sessions.last_seen_at,
                                                  EXCLUDED.last_seen_at)",
        )
        .bind(payload)
        .execute(sp.conn())
        .await?;
        sp.commit().await
    }
    .await;
    if let Err(e) = pinned {
        tracing::warn!("mcp_sessions pin upsert failed: {e}");
    }

    Ok(inserted)
}

pub(crate) use streamscope_edge_api::ingest::is_mcp_fanout_method;

/// A2A audit batch — writes both `gateway_audit` (kind='a2a') and `a2a_audit`
/// rows for every record in the JSONB array, on the ingest connection — which
/// sees every tenant, so each row carries and each lookup binds its own
/// `tenant_id`.
///
/// One side effect, shared with the MCP sibling: a `sessions` row for an
/// A2A-only session (see [`upsert_gateway_only_sessions`]). Unlike MCP there is
/// no session-pin write-through (the protocol's own `contextId`/`taskId` are
/// stored as plain columns) and no protocol-version recovery (the dispatcher
/// negotiates the version per request and stamps it on every record).
pub async fn insert_a2a_audit_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    let fresh = insert_gateway_audit_jsonb_fresh(conn, payload, "a2a").await?;
    upsert_gateway_only_sessions(&mut *conn, payload, &fresh).await?;

    sqlx::query(
        "INSERT INTO a2a_audit (
            request_id, timestamp, tenant_id, workspace_id,
            agent_id, method, a2a_context_id, a2a_task_id, task_state,
            params, result, stream_events, error_code, error_message,
            upstream_latency_ms, request_bytes, response_bytes,
            protocol_version, badges, transform_diff
        )
        SELECT
            (j->>'request_id')::uuid,
            (j->>'timestamp')::timestamptz,
            (j->>'tenant_id')::uuid,
            COALESCE((j->>'workspace_id')::uuid, '00000000-0000-0000-0000-000000000000'::uuid),
            (j->>'agent_id')::uuid,
            j->>'method',
            j->>'a2a_context_id',
            j->>'a2a_task_id',
            j->>'task_state',
            j->'params',
            j->'result',
            j->'stream_events',
            (j->>'error_code')::int,
            j->>'error_message',
            COALESCE((j->>'upstream_latency_ms')::bigint, 0),
            (j->>'request_bytes')::int,
            (j->>'response_bytes')::int,
            j->>'protocol_version',
            COALESCE(j->'badges', '[]'::jsonb),
            COALESCE(j->'transform_diff', '{}'::jsonb)
        FROM jsonb_array_elements($1) AS j
        ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::debug!("bulk insert a2a_audit via jsonb: {e}");
        e
    })?;
    Ok(())
}

/// Web audit batch — writes both `gateway_audit (kind='web')`
/// and `web_audit` rows for every record in the JSONB array, on the ingest
/// connection — which sees every tenant, so each row carries its own
/// `tenant_id`.
///
/// Dedupes on `(tenant_id, request_id, timestamp)` for both tables so re-delivery from
/// the edge outbox is safe. No session-pin write-through (the
/// built-in MCP virtual server doesn't open MCP sessions per backend call).
pub async fn insert_web_audit_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    insert_gateway_audit_jsonb(conn, payload, "web").await?;

    sqlx::query(
        "INSERT INTO web_audit (
            request_id, timestamp, tenant_id, workspace_id,
            upstream_server_id, operation, backend, query, result_count,
            bytes_in, bytes_out, upstream_latency_ms, upstream_status,
            error_category, error_detail, surface, parent_request_id, tool_use_id,
            url_results, filter_chain,
            request_args, response_summary,
            provider_request, provider_response,
            fetch_content_summary,
            badges, transform_diff
        )
        SELECT
            (j->>'request_id')::uuid,
            (j->>'timestamp')::timestamptz,
            (j->>'tenant_id')::uuid,
            COALESCE((j->>'workspace_id')::uuid, '00000000-0000-0000-0000-000000000000'::uuid),
            (j->>'upstream_server_id')::uuid,
            j->>'operation',
            j->>'backend',
            j->>'query',
            (j->>'result_count')::int,
            (j->>'bytes_in')::bigint,
            (j->>'bytes_out')::bigint,
            COALESCE((j->>'upstream_latency_ms')::bigint, 0),
            (j->>'upstream_status')::int,
            j->>'error_category',
            j->>'error_detail',
            COALESCE(j->>'surface', 'mcp'),
            NULLIF(j->>'parent_request_id', '')::uuid,
            j->>'tool_use_id',
            j->'url_results',
            j->'filter_chain',
            j->'request_args',
            j->'response_summary',
            j->'provider_request',
            j->'provider_response',
            j->'fetch_content_summary',
            COALESCE(j->'badges', '[]'::jsonb),
            COALESCE(j->'transform_diff', '{}'::jsonb)
        FROM jsonb_array_elements($1) AS j
        ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::debug!("bulk insert web_audit via jsonb: {e}");
        e
    })?;

    Ok(())
}

/// Insert SSE event rows for `Last-Event-ID` replay. Bulk JSONB INSERT;
/// dedupe on the natural key `(tenant_id, mcp_session_id, sequence)` so
/// re-delivery from the edge outbox is safe. `event_data` is decoded
/// from base64 (the proxy serializes it as a base64 string in the record).
pub async fn insert_mcp_sse_events_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO mcp_sse_events (
            tenant_id, user_id, mcp_session_id, virtual_server_id,
            event_id, sequence, event_data, created_at
        )
        SELECT
            (j->>'tenant_id')::uuid,
            (j->>'user_id')::uuid,
            j->>'mcp_session_id',
            (j->>'virtual_server_id')::uuid,
            j->>'event_id',
            (j->>'sequence')::bigint,
            decode(j->>'event_data', 'base64'),
            COALESCE((j->>'created_at')::timestamptz, NOW())
        FROM jsonb_array_elements($1) AS j
        ON CONFLICT (tenant_id, mcp_session_id, sequence, created_at) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::debug!("bulk insert mcp_sse_events via jsonb: {e}");
        e
    })?;
    Ok(())
}

/// Insert the LLM-specific `llm_audit` row for every record in the JSONB array.
/// Must run AFTER `insert_gateway_audit_jsonb` because of the FK.
async fn insert_llm_audit_jsonb(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO llm_audit (
            request_id, timestamp, tenant_id, workspace_id,
            model_requested, model_used, provider, api_version, stream,
            prompt_tokens, completion_tokens, reasoning_tokens,
            cache_creation_tokens, cache_read_tokens,
            finish_reason, native_finish_reason,
            cost, cost_currency, source_cost, source_currency, fx_rate, billed_units,
            embedding_cost, embedding_tokens, zero_completion,
            cache_mode, cache_outcome, avoided_cost,
            latency_ttft_ms, badges, pipeline_path,
            catchall_path, catchall_method,
            upstream_server_id, upstream_model_id,
            media_call, chat_media_summary,
            endpoint_id, endpoint_url,
            queue_wait_ms, qos_class_id, gate_refusal, pool_wait_ms, moved_on_from
        )
        SELECT
            (j->>'request_id')::uuid,
            (j->>'timestamp')::timestamptz,
            (j->>'tenant_id')::uuid,
            COALESCE((j->>'workspace_id')::uuid, '00000000-0000-0000-0000-000000000000'::uuid),
            j->>'model_requested',
            j->>'model_used',
            j->>'provider',
            j->>'api_version',
            COALESCE((j->>'stream')::boolean, true),
            COALESCE((j->>'prompt_tokens')::int, 0),
            COALESCE((j->>'completion_tokens')::int, 0),
            (j->>'reasoning_tokens')::int,
            (j->>'cache_creation_tokens')::int,
            (j->>'cache_read_tokens')::int,
            COALESCE(j->>'finish_reason', ''),
            j->>'native_finish_reason',
            COALESCE((j->>'cost')::float8, 0),
            COALESCE(j->>'cost_currency', 'USD'),
            COALESCE((j->>'source_cost')::float8, 0),
            COALESCE(j->>'source_currency', 'USD'),
            COALESCE((j->>'fx_rate')::float8, 1),
            COALESCE(j->'billed_units', '{}'::jsonb),
            COALESCE((j->>'embedding_cost')::float8, 0),
            COALESCE((j->>'embedding_tokens')::int, 0),
            COALESCE((j->>'zero_completion')::boolean, false),
            j->>'cache_mode',
            j->>'cache_outcome',
            COALESCE((j->>'avoided_cost')::float8, 0),
            COALESCE((j->>'latency_ttft_ms')::bigint, 0),
            COALESCE(j->'badges', '[]'::jsonb),
            j->>'pipeline_path',
            j->>'catchall_path',
            j->>'catchall_method',
            (j->>'upstream_server_id')::uuid,
            (j->>'upstream_model_id')::uuid,
            j->'media_call',
            j->'chat_media_summary',
            (j->>'endpoint_id')::uuid,
            j->>'endpoint_url',
            COALESCE((j->>'queue_wait_ms')::int, 0),
            (j->>'qos_class_id')::uuid,
            j->>'gate_refusal',
            (j->>'pool_wait_ms')::int,
            -- Only well-formed entries — every field's `.type()` checked, which
            -- (unlike a comparison) never unwraps an array in lax mode — so
            -- every reader's
            -- `jsonb_to_recordset(... server_id uuid, endpoint_id uuid,
            -- outcome text, reason text, status numeric, wait_ms numeric,
            -- elapsed_ms numeric)`
            -- can cast any row it meets: one malformed entry would otherwise
            -- fail every query over its window. The gateway writes this list
            -- itself; an entry failing the shape is a defect there, not data.
            -- NULL for an empty list.
            CASE WHEN jsonb_typeof(j->'moved_on_from') = 'array' THEN NULLIF(jsonb_path_query_array(
                j->'moved_on_from',
                '$[*] ? (@.type() == \"object\"
                    && (!exists(@.server_id) || @.server_id.type() == \"null\"
                        || (@.server_id.type() == \"string\"
                            && @.server_id like_regex \"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$\"))
                    && (!exists(@.endpoint_id) || @.endpoint_id.type() == \"null\"
                        || (@.endpoint_id.type() == \"string\"
                            && @.endpoint_id like_regex \"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$\"))
                    && @.outcome.type() == \"string\" && (@.outcome == \"refused\" || @.outcome == \"failed\")
                    && @.reason.type() == \"string\"
                    && (!exists(@.status) || @.status.type() == \"null\"
                        || (@.status.type() == \"number\" && @.status >= 0 && @.status < 1000
                            && @.status == @.status.floor()))
                    && @.wait_ms.type() == \"number\" && @.wait_ms >= 0
                    && @.wait_ms == @.wait_ms.floor() && @.wait_ms < 1e15
                    && @.elapsed_ms.type() == \"number\" && @.elapsed_ms >= 0
                    && @.elapsed_ms == @.elapsed_ms.floor() && @.elapsed_ms < 1e15)'), '[]'::jsonb) END
        FROM jsonb_array_elements($1) AS j
        ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING",
    )
    .bind(payload)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::debug!("bulk insert llm_audit via jsonb: {e}");
        e
    })?;
    Ok(())
}

/// Bulk INSERT chat conversation turns via a single JSONB statement, from the
/// rows [`ChatTurns::build`] derived (their history content is already stored).
/// `message_bytes` is the stored size of the distinct messages of the turn's
/// history (a message repeated in it counts once — it is stored once), read
/// from the messages this request and earlier ones stored. Returns the (tenant, request)
/// of every turn inserted for the first time.
async fn bulk_insert_chat_turns(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<Vec<(uuid::Uuid, uuid::Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO conversation_turns ( \
             request_id, timestamp, tenant_id, session_id, turn_number, \
             parent_request_id, is_baseline, history_head, message_count, message_bytes, added_from, \
             tools_available_hash, tools_effective_hash, \
             request_params, system_prompt_hash, transform_diff, \
             response_content, response_tool_calls, \
             request_size_bytes, response_size_bytes, api_version \
         ) \
         SELECT \
             (j->>'request_id')::uuid, \
             (j->>'timestamp')::timestamptz, \
             (j->>'tenant_id')::uuid, \
             NULLIF(j->>'conversation_session_id', '')::uuid, \
             COALESCE((j->>'turn_number')::int, 0), \
             NULLIF(j->>'parent_request_id', '')::uuid, \
             COALESCE((j->>'is_baseline')::bool, true), \
             j->>'history_head', \
             (j->>'message_count')::int, \
             (SELECT COALESCE(sum(cm.content_size), 0) FROM conversation_messages cm \
               WHERE cm.tenant_id = (j->>'tenant_id')::uuid \
                 AND cm.hash = ANY (ARRAY(SELECT jsonb_array_elements_text(j->'message_hashes')))), \
             (j->>'added_from')::int, \
             j->>'tools_available_hash', \
             j->>'tools_effective_hash', \
             j->'request_params', \
             j->>'system_prompt_hash', \
             j->'transform_diff', \
             j->>'response_content', \
             j->'response_tool_calls', \
             NULL::int, \
             octet_length(j->>'response_content')::int, \
             j->>'api_version' \
         FROM jsonb_array_elements($1) AS j \
         ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING \
         RETURNING tenant_id, request_id",
    )
    .bind(payload)
    .fetch_all(&mut *conn)
    .await
}

/// Bulk INSERT media conversation turns via a single JSONB statement.
///
/// Media turns carry `event_type='media'` and the inbound protocol. The call
/// itself lives on `llm_audit.media_call` (canonical `DomainMediaCall` JSONB) —
/// the session renderer joins the audit row for details.
async fn bulk_insert_media_turns(
    conn: &mut IngestConn,
    payload: &serde_json::Value,
) -> Result<Vec<(uuid::Uuid, uuid::Uuid)>, sqlx::Error> {
    sqlx::query_as(
        "INSERT INTO conversation_turns ( \
             request_id, timestamp, tenant_id, session_id, turn_number, \
             parent_request_id, is_baseline, message_count, \
             event_type, api_version \
         ) \
         SELECT \
             (j->>'request_id')::uuid, \
             (j->>'timestamp')::timestamptz, \
             (j->>'tenant_id')::uuid, \
             (j->>'conversation_session_id')::uuid, \
             COALESCE((j->>'turn_number')::int, 0), \
             NULLIF(j->>'parent_request_id', '')::uuid, \
             COALESCE((j->>'is_baseline')::bool, true), \
             0, \
             'media', \
             j->>'api_version' \
         FROM jsonb_array_elements($1) AS j \
         WHERE j->'media_call' IS NOT NULL \
           AND j->>'conversation_session_id' IS NOT NULL \
         ON CONFLICT (tenant_id, request_id, timestamp) DO NOTHING \
         RETURNING tenant_id, request_id",
    )
    .bind(payload)
    .fetch_all(&mut *conn)
    .await
}

/// UPSERT the materialized `sessions` row for a turn (chat or media). Runs only
/// for a turn this delivery inserted, so its `landed_xid` — this transaction's
/// id, the order the expert agent reads sessions in — moves once per new turn.
///
/// Aggregative (turn_count+1, token/cost sums), so it stays per-record —
/// batching aggregation across records is complex and the common case is
/// one turn per session per batch.
async fn upsert_session_for_turn(
    conn: &mut IngestConn,
    record: &streamscope_core::audit::AuditRecord,
    session_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    // For media turns, fall back to the first text input block in the canonical
    // media_call when no chat prompt is set.
    let first_prompt: Option<String> = record.first_user_prompt.clone().or_else(|| {
        record.media_call.as_ref().and_then(|c| {
            c.input.iter().find_map(|b| match b {
                streamscope_core::api::domain_request::DomainContentBlock::Text {
                    text, ..
                } => Some(text.clone()),
                _ => None,
            })
        })
    });

    sqlx::query(SESSION_TURN_UPSERT)
    .bind(session_id)            // $1
    .bind(record.tenant_id)      // $2
    .bind(record.user_id)        // $3
    .bind(&record.app_id)        // $4
    .bind(&record.model_used)    // $5
    .bind(record.prompt_tokens as i64) // $6
    .bind(record.completion_tokens as i64) // $7
    .bind(record.cost)       // $8
    .bind(&first_prompt)         // $9
    // $10 — the session's window is the span of its turns' timestamps, so it is
    // parsed from the same RFC 3339 text the turn row is (`(j->>'timestamp')::
    // timestamptz`, which rounds nanoseconds to the microsecond); a bound
    // `DateTime` truncates instead and can end the window a microsecond before
    // its own last turn. Turns may land out of order (an edge resends), so the
    // window only ever widens. It is also the turn's place in that order for the
    // session's last model and latency and its first prompt, which a turn that
    // lands late must not overwrite.
    .bind(record.timestamp.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true))
    .bind(record.latency_total_ms as i64) // $11
    .bind(record.cache_creation_tokens.unwrap_or(0) as i64) // $12
    .bind(record.cache_read_tokens.unwrap_or(0) as i64) // $13
    .bind(record.key_id)         // $14
    .bind(record.reasoning_tokens.unwrap_or(0) as i64) // $15
    .bind(crate::agent::AGENT_EMAIL) // $16 — stamps source='agent' for the expert agent's own sessions
    .bind(record.workspace_id)   // $17
    // $18 — the currency the turn's charge is booked in, as its `llm_audit`
    // row stamps it.
    .bind(record.cost_currency.as_str())
    .execute(&mut *conn)
    .await?;

    // Header-derived parent→child linkage (X-Parent-Session-Id) is a first-class
    // cross_session_relations row, not a sessions column. First-write-wins via the
    // one-parent-per-child guard, so a later agent-inferred link can't override it;
    // the parent session row may not exist yet (members reference ids by value).
    // Best-effort: a linkage write must never fail the turn's session upsert.
    if let Some(parent_id) = record.parent_session_id
        && let Err(e) = write_header_linkage(conn, record.tenant_id, session_id, parent_id).await
    {
        tracing::warn!(child = %session_id, parent = %parent_id, "header linkage relation write failed: {e}");
    }
    Ok(())
}

/// How a turn moves its session's spend classification
/// (`sessions.cost_currency_count`). Every LLM and media turn counts, charged
/// or not — the rows a spend aggregate counts the currencies of:
/// - 0 (no LLM turn yet) takes this turn's currency (1);
/// - 1 stays 1 when this turn is booked in the same currency;
/// - anything else is 2, and names no currency. 2 is terminal.
///
/// The upsert's row lock serializes the turns of one session, and each SET
/// reads the row as it was before the update, so the two columns move
/// together.
macro_rules! session_spend_currency_update {
    () => {
        "cost_currency_count = CASE \
             WHEN sessions.cost_currency_count = 0 THEN 1 \
             WHEN sessions.cost_currency_count = 1 \
                  AND sessions.cost_currency = EXCLUDED.cost_currency THEN 1 \
             ELSE 2 END, \
         cost_currency = CASE \
             WHEN sessions.cost_currency_count = 0 THEN EXCLUDED.cost_currency \
             WHEN sessions.cost_currency_count = 1 \
                  AND sessions.cost_currency = EXCLUDED.cost_currency THEN sessions.cost_currency \
             ELSE NULL END, "
    };
}

/// The per-turn session upsert [`upsert_session_for_turn`] runs. A new row is
/// in its first turn's currency (`$18`, count 1).
const SESSION_TURN_UPSERT: &str = concat!(
        "INSERT INTO sessions (session_id, tenant_id, user_id, user_email, source, key_id, workspace_id, app_id, model_used, \
         turn_count, total_prompt_tokens, total_completion_tokens, \
         total_cache_creation_tokens, total_cache_read_tokens, total_reasoning_tokens, \
         total_cost, cost_currency, cost_currency_count, \
         first_user_prompt, created_at, updated_at, last_latency_ms, last_llm_at, first_prompt_at, landed_xid) \
         VALUES ($1, $2, $3, (SELECT email FROM users WHERE tenant_id = $2 AND id = $3), \
                 CASE WHEN (SELECT email FROM users WHERE tenant_id = $2 AND id = $3) = $16 THEN 'agent' ELSE 'user' END, \
                 $14, $17, $4, $5, \
                 1, $6, $7, $12, $13, $15, $8, $18, 1, $9, $10::timestamptz, $10::timestamptz, $11, \
                 $10::timestamptz, CASE WHEN $9::text IS NULL THEN NULL ELSE $10::timestamptz END, \
                 pg_current_xact_id()::text::bigint) \
         ON CONFLICT (tenant_id, session_id) DO UPDATE SET \
             turn_count = sessions.turn_count + 1, \
             landed_xid = EXCLUDED.landed_xid, ",
        session_spend_currency_update!(),
        "total_prompt_tokens = sessions.total_prompt_tokens + EXCLUDED.total_prompt_tokens, \
             total_completion_tokens = sessions.total_completion_tokens + EXCLUDED.total_completion_tokens, \
             total_cache_creation_tokens = sessions.total_cache_creation_tokens + EXCLUDED.total_cache_creation_tokens, \
             total_cache_read_tokens = sessions.total_cache_read_tokens + EXCLUDED.total_cache_read_tokens, \
             total_reasoning_tokens = sessions.total_reasoning_tokens + EXCLUDED.total_reasoning_tokens, \
             total_cost = sessions.total_cost + EXCLUDED.total_cost, \
             model_used = CASE WHEN EXCLUDED.last_llm_at >= sessions.last_llm_at \
                                    OR sessions.last_llm_at IS NULL \
                               THEN EXCLUDED.model_used ELSE sessions.model_used END, \
             user_email = COALESCE(EXCLUDED.user_email, sessions.user_email), \
             key_id = COALESCE(sessions.key_id, EXCLUDED.key_id), \
             workspace_id = COALESCE( \
                 NULLIF(sessions.workspace_id, '00000000-0000-0000-0000-000000000000'::uuid), \
                 EXCLUDED.workspace_id), \
             app_id = COALESCE(sessions.app_id, EXCLUDED.app_id), \
             created_at = LEAST(sessions.created_at, EXCLUDED.created_at), \
             updated_at = GREATEST(sessions.updated_at, EXCLUDED.updated_at), \
             last_latency_ms = CASE WHEN EXCLUDED.last_llm_at >= sessions.last_llm_at \
                                         OR sessions.last_llm_at IS NULL \
                                    THEN EXCLUDED.last_latency_ms ELSE sessions.last_latency_ms END, \
             last_llm_at = GREATEST(sessions.last_llm_at, EXCLUDED.last_llm_at), \
             first_user_prompt = CASE WHEN EXCLUDED.first_user_prompt IS NOT NULL \
                                       AND (sessions.first_user_prompt IS NULL \
                                            OR EXCLUDED.first_prompt_at < sessions.first_prompt_at) \
                                 THEN EXCLUDED.first_user_prompt ELSE sessions.first_user_prompt END, \
             first_prompt_at = CASE WHEN EXCLUDED.first_user_prompt IS NOT NULL \
                                     AND (sessions.first_user_prompt IS NULL \
                                          OR EXCLUDED.first_prompt_at < sessions.first_prompt_at) \
                               THEN EXCLUDED.first_prompt_at ELSE sessions.first_prompt_at END",
);

/// The header-derived parent→child linkage of `child_id` (X-Parent-Session-Id):
/// the relation [`crate::agent::suggestion::write_linkage_relation`] writes,
/// with origin and confidence `header` and no spawn call — the child card
/// content-matches the parent's detected spawn points on read instead —
/// first-write-wins through the one-parent-per-child guard. Under a savepoint,
/// so a refused relation leaves the request's transaction healthy.
async fn write_header_linkage(
    conn: &mut IngestConn,
    tenant_id: uuid::Uuid,
    child_id: uuid::Uuid,
    parent_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    use crate::agent::suggestion::{LINKAGE_CHILD_SQL, LINKAGE_PARENT_SQL, LINKAGE_RELATION_SQL};
    if child_id == parent_id {
        return Ok(());
    }
    let mut sp = conn.savepoint().await?;
    let relation_id: uuid::Uuid = sqlx::query_scalar(LINKAGE_RELATION_SQL)
        .bind(tenant_id)
        .bind("header")
        .bind(None::<i32>)
        .bind(None::<&str>)
        .bind("header")
        .fetch_one(sp.conn())
        .await?;
    let landed: Option<uuid::Uuid> = sqlx::query_scalar(LINKAGE_CHILD_SQL)
        .bind(relation_id)
        .bind(tenant_id)
        .bind(child_id)
        .fetch_optional(sp.conn())
        .await?;
    if landed.is_none() {
        // The child already has a parent: dropping the savepoint undoes the relation.
        return Ok(());
    }
    sqlx::query(LINKAGE_PARENT_SQL)
        .bind(relation_id)
        .bind(tenant_id)
        .bind(parent_id)
        .execute(sp.conn())
        .await?;
    sp.commit().await
}

#[cfg(test)]
mod session_spend_currency_tests {
    use super::SESSION_TURN_UPSERT;

    /// The whitespace-folded text of the per-turn upsert's update arm.
    fn update_arm() -> String {
        let (_, arm) = SESSION_TURN_UPSERT
            .split_once("DO UPDATE SET")
            .expect("the upsert has an update arm");
        arm.split_whitespace().collect::<Vec<_>>().join(" ")
    }

    /// A tripwire on the update arm's state machine: each transition of
    /// `cost_currency_count`, and of the currency beside it, in order. The
    /// e2e (`test_a_window_spanning_a_currency_change_reports_components_not_a_sum`)
    /// observes the 1 -> 2 step and a session staying 1 through requests; this
    /// holds the text of every arm.
    #[test]
    fn a_turn_moves_the_spend_classification_one_step() {
        let arm = update_arm();
        let case = |column: &str| -> String {
            let from = arm.find(column).expect("the column's CASE");
            let to = from + arm[from..].find(" END").expect("the CASE's end");
            arm[from..to].to_string()
        };
        // Each column's arms, in order: CASE takes the first match, so the
        // order is part of the rule.
        for (column, arms) in [
            ("cost_currency_count = CASE", [
                // No LLM turn yet: the first one names the currency.
                "WHEN sessions.cost_currency_count = 0 THEN 1",
                // Same currency: still one.
                "WHEN sessions.cost_currency_count = 1 AND sessions.cost_currency = EXCLUDED.cost_currency THEN 1",
                // Another currency: no single figure.
                "ELSE 2",
            ]),
            ("cost_currency = CASE", [
                "WHEN sessions.cost_currency_count = 0 THEN EXCLUDED.cost_currency",
                "WHEN sessions.cost_currency_count = 1 AND sessions.cost_currency = EXCLUDED.cost_currency THEN sessions.cost_currency",
                "ELSE NULL",
            ]),
        ] {
            let case = case(column);
            let mut at = 0;
            for arm_text in arms {
                let found = case[at..].find(arm_text).unwrap_or_else(|| {
                    panic!("{column}: `{arm_text}` missing or out of order: {case}")
                });
                at += found + arm_text.len();
            }
            assert_eq!(case.matches("WHEN").count(), arms.len() - 1, "{column}: an arm too many: {case}");
        }
        assert_eq!(arm.matches("cost_currency_count = CASE").count(), 1, "{arm}");
        assert_eq!(arm.matches("cost_currency = CASE").count(), 1, "{arm}");
    }

    /// A new session row starts in its first turn's currency, classified.
    #[test]
    fn a_new_session_is_in_its_first_turns_currency() {
        let (insert, _) = SESSION_TURN_UPSERT.split_once("ON CONFLICT").expect("an upsert");
        let insert = insert.split_whitespace().collect::<Vec<_>>().join(" ");
        assert!(insert.contains("total_cost, cost_currency, cost_currency_count,"), "{insert}");
        assert!(insert.contains("$8, $18, 1, $9"), "{insert}");
    }
}

#[cfg(test)]
mod permanent_rejection_tests {
    use super::is_permanent_sqlstate;

    /// One case per class the writer drops a row for, and the neighbours it
    /// must NOT — a transient refusal dropped here is an audit row lost.
    #[test]
    fn only_a_refusal_of_the_data_itself_is_permanent() {
        for permanent in ["22000", "22003", "22P02", "22P05", "22021", "22023", "21000", "23502", "23514", "54000"] {
            assert!(is_permanent_sqlstate(permanent), "{permanent} must isolate the row");
        }
        for transient in [
            "23503", // foreign key: the parent may not have synced yet
            "23505", // unique: the inserts dedupe with ON CONFLICT
            "40001", "40P01", // serialization / deadlock
            "08006", "57P01", "53300", // connection lost, admin shutdown, too many connections
            "54001", // statement too complex — not a property of one row
            "21001", "2200", "",
        ] {
            assert!(!is_permanent_sqlstate(transient), "{transient} must withhold the ack");
        }
    }
}
