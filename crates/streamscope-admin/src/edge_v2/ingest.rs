//! `POST /api/v2/edge/ingest`: per-tenant shares, instance state and usage
//! from one edge process instance.
//!
//! Every write is keyed and every side effect follows a real insert, so the
//! same request delivered twice stores the same rows once:
//!
//! - **Shares** are written together, every tenant of the request in ONE
//!   ingest transaction ([`crate::db::Db::begin_ingest`]), one statement per
//!   record kind across the shares, by the writers in [`super::writers`]:
//!   audit rows `DO NOTHING` on their key, a session's aggregate incremented
//!   only for a newly inserted turn, content `DO NOTHING` on its hash and
//!   stamped, SSE events on their sequence. A blob keeps its bytes and is
//!   stamped, and a credential rotation keeps the later `expires_at`. Whether
//!   each share's tenant still exists, and whether it holds every body the
//!   share names but does not carry, is read inside that transaction: a share
//!   naming one it does not hold, other than one the edge reports
//!   unavailable, is answered `Retry` with those keys and nothing of it is
//!   written; a record naming an unavailable body it does not hold is stored
//!   badged `content_unavailable`. When the request's transaction fails
//!   (once retried on a deadlock or serialization failure), each share is
//!   written alone ([`write_share_alone`]) in up to four transactions: the
//!   tenant and content check, its content (through
//!   [`write_tenant_share_rows`], which isolates a row the database refuses
//!   for its data), the check of which refused bodies admin-api already holds
//!   (only when one was refused), then its records, those naming a refused
//!   body it does not hold badged. The split is safe because content is keyed (`DO NOTHING`, a
//!   second write changes nothing) and a failure at any step answers `Retry`,
//!   which resends the whole share — so atomicity is per request, with a
//!   per-share fallback that converges on resend. A server-initiated MCP event is appended to
//!   `edge_events` after its share commits, only for an audit row that delivery
//!   inserted.
//! - **Instance state** applies only from the instance's current process
//!   epoch. Its stated parts apply only when its `(epoch, seq)` is newer than
//!   the last applied — per instance for the stats sample and the edge's
//!   metadata, per tenant (a claim in `edge_instance_tenant_state`, taken in
//!   the same transaction as the writes) for stands and load samples. Its
//!   one-shot events (breaker transitions, "model not found" answers) apply
//!   once per event id (`edge_instance_events`, in the same transaction).
//! - **Usage** merges by watermark, rebasing when the epoch changes.

use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use axum::Json;
use axum::extract::State;
use axum::extract::connect_info::ConnectInfo;
use axum::response::{IntoResponse, Response};

use streamscope_edge_api::ingest::{
    ContentKey, IngestRequest, IngestResponse, InstanceState, OneShot, Record, RecordKind, RowRef, ShareOutcome,
    TenantShare, UsageSync,
};

use crate::AdminState;
use crate::routes::{ApiError, ApiErrorResponse};
use crate::db::Global;
use crate::db::tenant::{IngestConn, TenantConn, TenantId};
use super::writers::{
    ShareRow, ShareWrite, health_notification, ingest_llm_audit, is_mcp_fanout_method,
    insert_a2a_audit_jsonb, insert_load_samples, insert_mcp_audit_jsonb, insert_mcp_sse_events_jsonb,
    insert_stats_sample, insert_web_audit_jsonb, json_array,
    merge_usage_reports, prune_deleted_tenants, record_endpoint_health, record_endpoint_stands,
    record_model_missing, upstream_server_name, write_tenant_share_rows,
};

use super::auth::{instance_id};
use crate::content_store::media_blobs::insert_blobs;
use crate::content_store::messages::insert_messages_jsonb;
use crate::content_store::not_held;
use crate::content_store::system_prompts::insert_prompts_jsonb;
use crate::content_store::tool_definitions::insert_tool_definitions_jsonb;

/// The channel name shares are logged and notified under.
const CHANNEL: &str = "ingest";

#[utoipa::path(
    post,
    path = "/api/v2/edge/ingest",
    request_body = streamscope_edge_api::ingest::IngestRequest,
    responses(
        (status = 200, description = "One outcome per share", body = streamscope_edge_api::ingest::IngestResponse),
        (status = 400, description = "Malformed request", body = ApiErrorResponse),
        (status = 401, description = "Missing or unknown edge token", body = ApiErrorResponse),
        (status = 413, description = "Request larger than the ingest maximum"),
    ),
    security(("bearer_auth" = [])),
    tag = "Edge Nodes"
)]
pub(crate) async fn ingest_handler(
    State(state): State<Arc<AdminState>>,
    ConnectInfo(remote): ConnectInfo<SocketAddr>,
    request: axum::extract::Request,
) -> Response {
    // The token is checked from the headers before the body is read.
    let (node_id, body) = match super::auth::authenticated_body(
        request,
        &state.db,
        streamscope_edge_api::ingest::INGEST_REQUEST_MAX_BYTES,
    )
    .await
    {
        Ok(parts) => parts,
        Err(refused) => return refused,
    };
    let req = match parse_request(&body) {
        Ok((req, dropped)) => {
            for (part, e) in dropped {
                tracing::warn!(%node_id, "edge ingest: unreadable {part} dropped ({e}); its shares are written");
            }
            req
        }
        Err(e) => {
            tracing::warn!(%node_id, "invalid edge ingest request: {e}");
            return ApiError::bad_request("Malformed ingest request").into_response();
        }
    };
    let Ok(epoch) = i64::try_from(req.process_epoch) else {
        return ApiError::bad_request("process_epoch out of range").into_response();
    };
    let internal = |what: &str, e: sqlx::Error| {
        tracing::error!(%node_id, instance = %req.instance, "edge ingest: {what}: {e}");
        ApiError::internal("Failed to record the edge instance").into_response()
    };
    let instance = match instance_id(&state.db, node_id, req.instance).await {
        Ok(id) => id,
        Err(e) => return internal("instance", e),
    };
    let verdict = match observe_epoch(&state.db, instance, epoch, &remote.ip().to_string()).await {
        Ok(v) => v,
        Err(e) => return internal("epoch", e),
    };

    let shares = write_shares(&state, node_id, req.instance, req.shares).await;

    let mut usage = None;
    let mut one_shots_settled = false;
    match verdict {
        EpochVerdict::Current { epoch_started_at } => {
            if let Some(st) = &req.instance_state {
                one_shots_settled = apply_instance_state(&state, node_id, instance, epoch, epoch_started_at, st).await;
            }
            if let Some(report) = req.usage {
                let merge = merge_usage_reports(&state, instance, report.counters, epoch).await;
                // After every counter's own transaction, and only when each
                // merged or settled: a stamp names a merge that is already visible.
                if merge.complete
                    && let Err(e) = stamp_usage_merged(&state.db, instance, epoch).await
                {
                    tracing::warn!(%node_id, %instance, "edge ingest: usage merge stamp: {e}");
                }
                usage = Some(UsageSync { totals: merge.totals, settled: merge.settled });
            }
        }
        EpochVerdict::Stale => {
            // An older process's events can never apply; it need not restate them.
            one_shots_settled = req.instance_state.is_some();
            if req.instance_state.is_some() || req.usage.is_some() {
                tracing::info!(
                    %node_id, %instance, epoch,
                    "edge ingest from an older process epoch — instance state and usage not applied"
                );
            }
        }
    }
    Json(IngestResponse { shares, usage, one_shots_settled }).into_response()
}

/// Stamp the instance's `usage_merged_at`: a report it sent has merged. The
/// edge reports every counter it holds every usage interval (an empty report
/// when it holds none), so the second stamp after a moment covers everything
/// accrued before it.
async fn stamp_usage_merged(db: &crate::db::Db, instance: uuid::Uuid, epoch: i64) -> Result<(), sqlx::Error> {
    // Only while the report's process is still the instance's current one: a
    // newer process's counters are not what this report merged.
    sqlx::query("UPDATE edge_instances SET usage_merged_at = now() WHERE id = $1 AND process_epoch = $2")
        .bind(instance)
        .bind(epoch)
        .execute(db.global(Global::Infra))
        .await
        .map(|_| ())
}

/// Whether the request's process epoch is the instance's current one.
#[derive(Clone, Copy, Debug)]
enum EpochVerdict {
    /// It is (or just became) current; `epoch_started_at` is when admin-api
    /// first saw it.
    Current { epoch_started_at: chrono::DateTime<chrono::Utc> },
    /// The instance already runs a newer epoch: the request is answered, but
    /// none of its instance-state writes apply.
    Stale,
}

/// Record the request's process epoch on the instance. The first epoch, or an
/// equal or newer one, becomes current: `last_seen_at` and `endpoint` are
/// stamped, and a changed epoch restarts `epoch_started_at` and the state
/// sequence. An older epoch is [`EpochVerdict::Stale`] and changes nothing:
/// the instance id lives in the edge's store beside the epoch counter, so a
/// store that restarts its counter is a new instance, and an older epoch is
/// always a request from a process that has since been replaced.
async fn observe_epoch(
    db: &crate::db::Db,
    instance: uuid::Uuid,
    epoch: i64,
    endpoint: &str,
) -> Result<EpochVerdict, sqlx::Error> {
    // Every SET expression reads the row as it was, so the CASEs compare the
    // epoch being replaced.
    let current: Option<(chrono::DateTime<chrono::Utc>,)> = sqlx::query_as(
        "UPDATE edge_instances SET \
             epoch_started_at = CASE WHEN process_epoch IS DISTINCT FROM $2 THEN now() \
                                     ELSE epoch_started_at END, \
             state_seq        = CASE WHEN process_epoch IS DISTINCT FROM $2 THEN NULL \
                                     ELSE state_seq END, \
             process_epoch    = $2, \
             last_seen_at     = now(), \
             endpoint         = $3 \
          WHERE id = $1 AND (process_epoch IS NULL OR $2 >= process_epoch) \
         RETURNING epoch_started_at",
    )
    .bind(instance)
    .bind(epoch)
    .bind(endpoint)
    .fetch_optional(db.global(Global::Infra))
    .await?;
    Ok(match current {
        Some((epoch_started_at,)) => EpochVerdict::Current { epoch_started_at },
        None => EpochVerdict::Stale,
    })
}

/// Parse the body under the edge link's depth bound, with every NUL character
/// (which Postgres cannot store, in `text` or `jsonb`) replaced first — so no
/// writer below ever sees one. The instance state and the usage report ride
/// beside the shares: one that cannot be read is dropped alone (returned with
/// its error; the edge restates it until answered), never the audit it
/// travels with.
fn parse_request(body: &[u8]) -> Result<(IngestRequest, Vec<DroppedPart>), String> {
    let text = std::str::from_utf8(body).map_err(|e| e.to_string())?;
    let mut value: serde_json::Value =
        streamscope_core::edge_wire::from_str_bounded(text).map_err(|e| e.to_string())?;
    if streamscope_core::pg_text::json_text_may_carry_nul(text) {
        let replaced = streamscope_core::pg_text::scrub_nul_json(&mut value);
        if replaced > 0 {
            tracing::warn!(replaced, "edge ingest carried NUL characters Postgres cannot store — replaced with U+FFFD");
        }
    }
    let parts = value.as_object_mut().map(|o| (o.remove("instance_state"), o.remove("usage")));
    let mut request: IngestRequest = serde_json::from_value(value).map_err(|e| e.to_string())?;
    let mut dropped = Vec::new();
    if let Some((state, usage)) = parts {
        request.instance_state = read_part(state, "instance state", &mut dropped);
        request.usage = read_part(usage, "usage report", &mut dropped);
    }
    Ok((request, dropped))
}

/// A part of an ingest request that could not be read: which, and why.
type DroppedPart = (&'static str, serde_json::Error);

fn read_part<T: serde::de::DeserializeOwned>(
    value: Option<serde_json::Value>,
    what: &'static str,
    dropped: &mut Vec<DroppedPart>,
) -> Option<T> {
    match value? {
        serde_json::Value::Null => None,
        v => serde_json::from_value(v).map_err(|e| dropped.push((what, e))).ok(),
    }
}

// ---------------------------------------------------------------------------
// Shares
// ---------------------------------------------------------------------------

/// What a share row is, in the order a share writes them: content before the
/// records that point at it, the parent `gateway_audit` rows inside each audit
/// writer.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum ItemKind {
    Message,
    ToolDefinition,
    SystemPrompt,
    Blob,
    Record(RecordKind),
}

/// One row of a share, in the JSON shape its writer reads.
#[derive(Clone)]
struct ShareItem {
    kind: ItemKind,
    /// The record it is; `None` for content.
    row: Option<RowRef>,
    /// The body it is; `None` for a record.
    key: Option<ContentKey>,
    /// The bodies a record names; empty for content.
    names: Vec<ContentKey>,
    value: serde_json::Value,
}

impl ShareRow for ShareItem {
    fn log_key(&self) -> std::borrow::Cow<'_, str> {
        match (&self.row, &self.key) {
            (Some(r), _) => std::borrow::Cow::Owned(format!("{}:{}", r.kind.as_str(), r.key)),
            (None, Some(ContentKey::Blob { content_hash, blob_type })) => {
                std::borrow::Cow::Owned(format!("blob:{}:{content_hash}", blob_type.as_str()))
            }
            (None, Some(ContentKey::Message { hash })) => std::borrow::Cow::Owned(format!("message:{hash}")),
            (None, Some(ContentKey::ToolDefinition { hash })) => std::borrow::Cow::Owned(format!("tool_definition:{hash}")),
            (None, Some(ContentKey::SystemPrompt { hash })) => std::borrow::Cow::Owned(format!("system_prompt:{hash}")),
            (None, None) => std::borrow::Cow::Borrowed("-"),
        }
    }
}

/// One share, read into the rows its writers take, before anything is written.
struct PreparedShare {
    tenant: uuid::Uuid,
    items: Vec<ShareItem>,
    /// Every body its records name that it does not carry. Each must be held
    /// by admin-api, unless it is `unavailable`.
    uncarried: Vec<ContentKey>,
    /// The bodies the edge says it cannot deliver.
    unavailable: HashSet<ContentKey>,
    /// Records refused before writing (naming another tenant, unencodable),
    /// and why the first was.
    refused: Vec<RowRef>,
    reason: Option<String>,
}

/// What admin-api holds of the bodies a share names but does not carry.
#[derive(Default)]
struct ContentCheck {
    /// Not held, and not reported unavailable: asked for in a `Retry`, and the
    /// share is not written.
    missing: Vec<ContentKey>,
    /// Not held, and reported unavailable: the records naming one are written
    /// badged.
    lost: HashSet<ContentKey>,
}

/// Read, in the caller's transaction, which of the bodies each share names but
/// does not carry its tenant holds — renewing their stamps — for every share
/// at once (one stamp and one read per store, [`not_held`]); answered
/// index-aligned with `shares`.
async fn check_content(conn: &mut IngestConn, shares: &[&PreparedShare]) -> Result<Vec<ContentCheck>, sqlx::Error> {
    let named: HashSet<(uuid::Uuid, ContentKey)> =
        shares.iter().flat_map(|s| s.uncarried.iter().map(|k| (s.tenant, k.clone()))).collect();
    let absent = if named.is_empty() { HashSet::new() } else { not_held(conn, &named).await? };
    Ok(shares
        .iter()
        .map(|s| {
            let (lost, missing): (Vec<ContentKey>, Vec<ContentKey>) = s
                .uncarried
                .iter()
                .filter(|k| absent.contains(&(s.tenant, (*k).clone())))
                .cloned()
                .partition(|k| s.unavailable.contains(k));
            ContentCheck { missing, lost: lost.into_iter().collect() }
        })
        .collect())
}

impl PreparedShare {
    /// Its rows as written: a record naming a body admin-api does not hold
    /// and will never be sent (`lost`) is badged `content_unavailable`.
    fn items_to_write(&self, lost: &HashSet<ContentKey>) -> Vec<Cow<'_, ShareItem>> {
        self.items
            .iter()
            .map(|item| {
                if !item.names.iter().any(|k| lost.contains(k)) {
                    return Cow::Borrowed(item);
                }
                let mut badged = item.clone();
                badge_content_unavailable(&mut badged.value);
                Cow::Owned(badged)
            })
            .collect()
    }
}

/// Add the `content_unavailable` badge to a record's JSON body, once.
fn badge_content_unavailable(record: &mut serde_json::Value) {
    let badge = streamscope_core::audit::AuditBadge::ContentUnavailable;
    let (Ok(value), Some(fields)) = (serde_json::to_value(&badge), record.as_object_mut()) else {
        tracing::error!("edge ingest: a record that is not a JSON object could not be badged content_unavailable");
        return;
    };
    let badges = fields.entry("badges").or_insert_with(|| serde_json::Value::Array(Vec::new()));
    if let Some(list) = badges.as_array_mut()
        && !list.iter().any(|b| b.get("code").and_then(|c| c.as_str()) == Some(badge.code()))
    {
        list.push(value);
    }
}

/// What a request's single transaction found and wrote.
struct RequestWritten {
    /// The tenants that exist.
    live: HashSet<uuid::Uuid>,
    /// Per share index: the bodies its tenant does not hold and the edge must
    /// send (the share was not written).
    missing: HashMap<usize, Vec<ContentKey>>,
    /// The `mcp_audit` rows inserted, by `request_id`.
    new_mcp: HashSet<uuid::Uuid>,
}

/// Write every share and answer each, in request order.
/// `origin` is the edge's own instance id, which its MCP events carry.
async fn write_shares(
    state: &AdminState,
    node_id: uuid::Uuid,
    origin: uuid::Uuid,
    shares: Vec<TenantShare>,
) -> Vec<ShareOutcome> {
    // A request carrying usage or instance state only opens no transaction.
    if shares.is_empty() {
        return Vec::new();
    }
    let prepared: Vec<PreparedShare> = shares.iter().map(|share| prepare_share(node_id, share)).collect();
    // The whole request in one transaction; a deadlock or serialization
    // failure is retried once.
    let mut attempt = 0;
    let written = loop {
        match write_request(state, node_id, &prepared).await {
            Ok(written) => break Some(written),
            Err(e) if attempt == 0 && is_retryable(&e) => attempt += 1,
            // Any failure but an outage may be one share's doing — a row refused
            // for its data, a reference to a tenant deleted meanwhile, a record
            // that does not decode, a share big enough to trip a statement
            // timeout: writing the shares one by one confines it to that share,
            // so it never holds the others back. An outage (the database
            // unreachable) would fail every share the same way, only slower and
            // with more load: the whole request is asked for again.
            Err(e) if !is_outage(&e) => {
                tracing::warn!(%node_id, shares = prepared.len(), "edge ingest: the request's transaction failed, writing each share alone: {e}");
                break None;
            }
            Err(e) => {
                tracing::warn!(%node_id, shares = prepared.len(), "edge ingest: the request's transaction failed, asking for it again: {e}");
                return prepared.iter().map(|_| ShareOutcome::Retry { missing: Vec::new() }).collect();
            }
        }
    };
    let Some(written) = written else {
        // Share by share, stopping at the first outage: the shares after it are
        // asked for again together rather than each waiting out its own failure.
        let mut outcomes = Vec::with_capacity(prepared.len());
        let mut out = false;
        for share in &prepared {
            if out {
                outcomes.push(ShareOutcome::Retry { missing: Vec::new() });
                continue;
            }
            let (outcome, outage) = write_share_alone(state, node_id, origin, share).await;
            out = outage;
            outcomes.push(outcome);
        }
        return outcomes;
    };
    let mut new_mcp = written.new_mcp;
    let mut outcomes = Vec::with_capacity(prepared.len());
    for (i, share) in prepared.iter().enumerate() {
        outcomes.push(if !written.live.contains(&share.tenant) {
            // A share for a tenant deleted since the edge captured it can never
            // be stored (every target table references the tenant): answered
            // TenantDeleted so the edge drops it.
            tracing::info!(%node_id, tenant_id = %share.tenant, rows = share.items.len(),
                "edge ingest: share for a deleted tenant dropped");
            ShareOutcome::TenantDeleted
        } else if let Some(missing) = written.missing.get(&i) {
            ShareOutcome::Retry { missing: missing.clone() }
        } else {
            announce_mcp_events(state, share.tenant, origin, &share.items, &mut new_mcp, &HashSet::new()).await;
            match &share.reason {
                None => ShareOutcome::Committed,
                Some(reason) => ShareOutcome::Rejected { rows: share.refused.clone(), reason: reason.clone() },
            }
        });
    }
    outcomes
}

/// A failure worth one more attempt of the same transaction.
fn is_retryable(e: &sqlx::Error) -> bool {
    e.as_database_error().and_then(|d| d.code()).is_some_and(|c| c == "40P01" || c == "40001")
}

/// A failure of the database rather than of any share's rows: unreachable
/// (I/O, TLS, the pool timed out or closed) or refusing work (SQLSTATE class
/// `08` connection, `53` insufficient resources, `57` operator intervention —
/// statement timeout, shutdown — or `55P03` lock not available). Nothing one
/// share holds causes it, so writing the shares one by one would only add load.
fn is_outage(e: &sqlx::Error) -> bool {
    match e {
        sqlx::Error::Io(_) | sqlx::Error::Tls(_) | sqlx::Error::PoolTimedOut | sqlx::Error::PoolClosed => true,
        _ => e.as_database_error().and_then(|d| d.code()).is_some_and(|c| is_outage_sqlstate(&c)),
    }
}

/// The SQLSTATE half of [`is_outage`].
fn is_outage_sqlstate(code: &str) -> bool {
    code.starts_with("08") || code.starts_with("53") || code.starts_with("57") || code == "55P03"
}



/// Read a share into the rows its writers take. A record naming another tenant
/// than its share's is refused here, never written into that tenant's rows.
fn prepare_share(node_id: uuid::Uuid, share: &TenantShare) -> PreparedShare {
    let tenant = share.tenant;
    let mut refused: Vec<RowRef> = Vec::new();
    let mut items: Vec<ShareItem> = Vec::new();
    for m in &share.content.messages {
        items.push(ShareItem {
            kind: ItemKind::Message,
            row: None,
            key: Some(ContentKey::Message { hash: m.hash.clone() }),
            names: Vec::new(),
            value: serde_json::json!({ "tenant_id": tenant, "hash": m.hash, "message": m.message, "content_size": m.content_size }),
        });
    }
    for t in &share.content.tool_definitions {
        items.push(ShareItem {
            kind: ItemKind::ToolDefinition,
            row: None,
            key: Some(ContentKey::ToolDefinition { hash: t.hash.clone() }),
            names: Vec::new(),
            value: serde_json::json!({ "tenant_id": tenant, "hash": t.hash, "definition": t.definition, "content_size": t.content_size }),
        });
    }
    for p in &share.content.system_prompts {
        items.push(ShareItem {
            kind: ItemKind::SystemPrompt,
            row: None,
            key: Some(ContentKey::SystemPrompt { hash: p.hash.clone() }),
            names: Vec::new(),
            value: serde_json::json!({ "tenant_id": tenant, "hash": p.hash, "prompt": p.prompt, "content_size": p.content_size }),
        });
    }
    for b in &share.content.blobs {
        items.push(ShareItem {
            kind: ItemKind::Blob,
            row: None,
            key: Some(ContentKey::from(b.blob_ref())),
            names: Vec::new(),
            value: serde_json::json!({
                "tenant_id": tenant,
                "content_hash": b.content_hash,
                "blob_type": b.blob_type.as_str(),
                "media_type": b.media_type,
                "data_base64": b.data_base64,
            }),
        });
    }
    for record in &share.records {
        let row = record.row_ref();
        if record.tenant_id() != tenant {
            tracing::error!(%node_id, %tenant, key = %row.key, kind = row.kind.as_str(),
                "edge ingest record names another tenant than its share — dropped");
            refused.push(row);
            continue;
        }
        match record_value(record) {
            Ok(value) => items.push(ShareItem {
                kind: ItemKind::Record(row.kind),
                row: Some(row),
                key: None,
                names: record.content_keys(),
                value,
            }),
            Err(e) => {
                tracing::error!(%node_id, %tenant, key = %row.key, "edge ingest record could not be encoded — dropped: {e}");
                refused.push(row);
            }
        }
    }
    let reason = (!refused.is_empty()).then(|| "record names another tenant than its share".to_string());
    let carried: HashSet<ContentKey> = share.content.keys().collect();
    let mut uncarried: Vec<ContentKey> = Vec::new();
    let mut seen: HashSet<&ContentKey> = HashSet::new();
    for key in items.iter().flat_map(|i| &i.names) {
        if !carried.contains(key) && seen.insert(key) {
            uncarried.push(key.clone());
        }
    }
    let unavailable = share.unavailable.iter().cloned().collect();
    PreparedShare { tenant, items, uncarried, unavailable, refused, reason }
}

/// Write the whole request in one ingest transaction: the tenants that still
/// exist and the bodies each holds of those its share names but does not carry
/// are read first, then every writable share's rows, kind by kind across the
/// shares.
async fn write_request(
    state: &AdminState,
    node_id: uuid::Uuid,
    shares: &[PreparedShare],
) -> Result<RequestWritten, sqlx::Error> {
    let mut tx = state.db.begin_ingest().await?;
    let named: Vec<uuid::Uuid> = shares.iter().map(|s| s.tenant).collect::<HashSet<_>>().into_iter().collect();
    let live: HashSet<uuid::Uuid> = sqlx::query_scalar("SELECT id FROM tenants WHERE id = ANY($1)")
        .bind(&named)
        .fetch_all(tx.conn())
        .await?
        .into_iter()
        .collect();
    let mut missing: HashMap<usize, Vec<ContentKey>> = HashMap::new();
    let mut writable: Vec<Cow<'_, ShareItem>> = Vec::new();
    let checked: Vec<(usize, &PreparedShare)> =
        shares.iter().enumerate().filter(|(_, s)| live.contains(&s.tenant)).collect();
    let checks = check_content(tx.conn(), &checked.iter().map(|(_, s)| *s).collect::<Vec<_>>()).await?;
    for ((i, share), check) in checked.into_iter().zip(checks) {
        if !check.missing.is_empty() {
            missing.insert(i, check.missing);
            continue;
        }
        writable.extend(share.items_to_write(&check.lost));
    }
    let items: Vec<&ShareItem> = writable.iter().map(|i| i.as_ref()).collect();
    let new_mcp: NewRows = Arc::default();
    write_part(tx.conn(), &items, node_id, Arc::clone(&new_mcp)).await?;
    tx.commit().await?;
    let new_mcp = new_mcp.lock().map(|s| s.clone()).unwrap_or_default();
    Ok(RequestWritten { live, missing, new_mcp })
}

/// Write one share in its own transaction — the fallback when the request's
/// failed — isolating any row the database refuses for its data.
async fn write_share_alone(
    state: &AdminState,
    node_id: uuid::Uuid,
    origin: uuid::Uuid,
    share: &PreparedShare,
) -> (ShareOutcome, bool) {
    let tenant = share.tenant;
    // Checked in a transaction of its own. A tenant deleted between it and the
    // share's write fails that write (every row references the tenant), and
    // the edge redelivers; a body named and not carried has its stale stamp
    // renewed here, which is what keeps the purge off it while its records land.
    let checked: Result<(bool, ContentCheck), sqlx::Error> = async {
        let mut tx = state.db.begin_ingest().await?;
        let live: bool = sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM tenants WHERE id = $1)")
            .bind(tenant)
            .fetch_one(tx.conn())
            .await?;
        let check = if live {
            check_content(tx.conn(), &[share]).await?.pop().unwrap_or_default()
        } else {
            ContentCheck::default()
        };
        tx.commit().await?;
        Ok((live, check))
    }
    .await;
    let mut lost = match checked {
        Ok((false, _)) => {
            tracing::info!(%node_id, %tenant, rows = share.items.len(), "edge ingest: share for a deleted tenant dropped");
            return (ShareOutcome::TenantDeleted, false);
        }
        Ok((true, check)) if !check.missing.is_empty() => {
            return (ShareOutcome::Retry { missing: check.missing }, false);
        }
        Ok((true, check)) => check.lost,
        Err(e) => {
            tracing::warn!(%node_id, %tenant, "edge ingest: share pre-check failed: {e}");
            return (ShareOutcome::Retry { missing: Vec::new() }, is_outage(&e));
        }
    };

    // The class of a refusal, never the database's text: that names tables
    // and constraints.
    let refusal = |what: &str, e: &sqlx::Error| match e.as_database_error().and_then(|d| d.code()) {
        Some(code) => format!("{what} refused by the database (SQLSTATE {code})"),
        None => format!("{what} refused by the database"),
    };
    let mut refused = share.refused.clone();
    let mut reason = share.reason.clone();
    let new_mcp: NewRows = Arc::default();
    let write: &mut ShareWrite<'_, ShareItem> =
        &mut |conn: &mut IngestConn, part: &[&ShareItem]| Box::pin(write_part(conn, part, node_id, Arc::clone(&new_mcp)));
    // The bodies first, so a record naming one the database refuses for its
    // data, and that admin-api does not already hold under its key, is
    // written badged: that body will never be stored.
    let content: Vec<&ShareItem> = share.items.iter().filter(|i| i.key.is_some()).collect();
    let Some(dropped) = write_tenant_share_rows(&state.db, tenant, node_id, CHANNEL, &content, write).await else {
        return (ShareOutcome::Retry { missing: Vec::new() }, false);
    };
    let mut refused_bodies: HashSet<(uuid::Uuid, ContentKey)> = HashSet::new();
    for d in &dropped {
        let what = match &d.item.key {
            Some(ContentKey::Message { .. }) => "a message body",
            Some(ContentKey::ToolDefinition { .. }) => "a tool-definition body",
            Some(ContentKey::SystemPrompt { .. }) => "a system-prompt body",
            Some(ContentKey::Blob { .. }) | None => "a blob body",
        };
        reason.get_or_insert_with(|| refusal(what, &d.error));
        refused_bodies.extend(d.item.key.clone().map(|k| (tenant, k)));
    }
    if !refused_bodies.is_empty() {
        let absent: Result<HashSet<(uuid::Uuid, ContentKey)>, sqlx::Error> = async {
            let mut tx = state.db.begin_ingest().await?;
            let absent = not_held(tx.conn(), &refused_bodies).await?;
            tx.commit().await?;
            Ok(absent)
        }
        .await;
        match absent {
            Ok(absent) => lost.extend(absent.into_iter().map(|(_, k)| k)),
            Err(e) => {
                tracing::warn!(%node_id, %tenant, "edge ingest: refused bodies check failed: {e}");
                return (ShareOutcome::Retry { missing: Vec::new() }, is_outage(&e));
            }
        }
    }
    let to_write = share.items_to_write(&lost);
    let records: Vec<&ShareItem> = to_write.iter().map(|i| i.as_ref()).filter(|i| i.key.is_none()).collect();
    let Some(dropped) = write_tenant_share_rows(&state.db, tenant, node_id, CHANNEL, &records, write).await else {
        return (ShareOutcome::Retry { missing: Vec::new() }, false);
    };
    let mut dropped_rows: HashSet<&RowRef> = HashSet::new();
    for d in &dropped {
        reason.get_or_insert_with(|| refusal("a record", &d.error));
        if let Some(row) = &d.item.row {
            refused.push(row.clone());
            dropped_rows.insert(row);
        }
    }
    let mut new_mcp: HashSet<uuid::Uuid> = new_mcp.lock().map(|s| s.clone()).unwrap_or_default();
    announce_mcp_events(state, tenant, origin, &share.items, &mut new_mcp, &dropped_rows).await;
    let outcome = match reason {
        None => ShareOutcome::Committed,
        Some(reason) => ShareOutcome::Rejected { rows: refused, reason },
    };
    (outcome, false)
}

/// A record's body in the JSON shape its writer reads.
fn record_value(record: &Record) -> Result<serde_json::Value, serde_json::Error> {
    match record {
        Record::LlmAudit(r) => serde_json::to_value(r),
        Record::McpAudit(r) => serde_json::to_value(r),
        Record::A2aAudit(r) => serde_json::to_value(r),
        Record::WebAudit(r) => serde_json::to_value(r),
        Record::McpSseEvent(r) => serde_json::to_value(r),
        Record::CredentialRotation(r) => serde_json::to_value(r),
    }
}

/// The `mcp_audit` rows the writer inserted, by `request_id`. A row inserted by
/// an attempt that was then rolled back is inserted — and reported — again by
/// the attempt that keeps it, unless it is the row that was dropped.
type NewRows = Arc<Mutex<HashSet<uuid::Uuid>>>;

/// Announce, once the share has committed, each server-initiated MCP event
/// among its records that this delivery stored for the first time (a
/// redelivered row was not inserted, so it is not announced again). The
/// origin instance is never sent its own event back. Best-effort: a lost
/// announcement costs a notification, not data.
async fn announce_mcp_events(
    state: &AdminState,
    tenant: uuid::Uuid,
    origin: uuid::Uuid,
    items: &[ShareItem],
    new_mcp: &mut HashSet<uuid::Uuid>,
    dropped: &HashSet<&RowRef>,
) {
    for item in items {
        if item.kind != ItemKind::Record(RecordKind::McpAudit) || item.row.as_ref().is_some_and(|r| dropped.contains(r)) {
            continue;
        }
        let v = &item.value;
        let method = v.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let is_new = v
            .get("request_id")
            .and_then(|r| r.as_str())
            .and_then(|r| r.parse::<uuid::Uuid>().ok())
            // Taken out once announced: the same record in two shares of one
            // request is inserted once, and announced once.
            .is_some_and(|id| new_mcp.remove(&id));
        if !is_new || !is_mcp_fanout_method(method) {
            continue;
        }
        let body = serde_json::json!({
            "type": "mcp_user_event",
            "tenant_id": v.get("tenant_id"),
            "user_id": v.get("user_id"),
            "method": method,
            "mcp_session_id": v.get("mcp_session_id"),
            "virtual_server_id": v.get("virtual_server_id"),
            "upstream_server_id": v.get("upstream_server_id"),
            "origin": origin,
            "event_key": item.row.as_ref().map(|r| r.key.clone()),
        });
        if let Err(e) = super::events::append(&state.db, tenant, Some(origin), &body).await {
            tracing::warn!(%tenant, %origin, "edge ingest: MCP user event not announced: {e}");
        }
    }
}

/// Write a set of share rows — a whole request's, one share's, or a half of one
/// being isolated — kind by kind in [`ItemKind`] order, each kind in one
/// statement across every tenant the rows name.
async fn write_part(
    conn: &mut IngestConn,
    part: &[&ShareItem],
    node_id: uuid::Uuid,
    new_mcp: NewRows,
) -> Result<(), sqlx::Error> {
    let mut kinds: Vec<ItemKind> = part.iter().map(|i| i.kind).collect();
    kinds.sort();
    kinds.dedup();
    for kind in kinds {
        let mut values: Vec<&serde_json::Value> = part.iter().filter(|i| i.kind == kind).map(|i| &i.value).collect();
        // In key order within each kind, so two concurrent requests writing the
        // same rows of one kind take them in the same order. Across kinds a row
        // can be locked twice (a session by the LLM and the MCP upsert, a
        // message by its insert and its stamp), so a deadlock stays possible:
        // it is retried, and then the request is written share by share.
        values.sort_by_cached_key(|v| row_key(v));
        match kind {
            ItemKind::Message => insert_messages_jsonb(conn, &json_array(&values)).await?,
            ItemKind::ToolDefinition => insert_tool_definitions_jsonb(conn, &json_array(&values)).await?,
            ItemKind::SystemPrompt => insert_prompts_jsonb(conn, &json_array(&values)).await?,
            ItemKind::Blob => insert_blobs(conn, &json_array(&values)).await?,
            ItemKind::Record(RecordKind::LlmAudit) => ingest_llm_audit(conn, &values, node_id).await?,
            ItemKind::Record(RecordKind::McpAudit) => {
                let inserted = insert_mcp_audit_jsonb(conn, &json_array(&values)).await?;
                if let Ok(mut set) = new_mcp.lock() {
                    set.extend(inserted);
                }
            }
            ItemKind::Record(RecordKind::A2aAudit) => insert_a2a_audit_jsonb(conn, &json_array(&values)).await?,
            ItemKind::Record(RecordKind::WebAudit) => insert_web_audit_jsonb(conn, &json_array(&values)).await?,
            ItemKind::Record(RecordKind::McpSseEvent) => {
                insert_mcp_sse_events_jsonb(conn, &json_array(&values)).await?
            }
            ItemKind::Record(RecordKind::CredentialRotation) => {
                for v in values {
                    upsert_rotated_credential(conn, v).await?;
                }
            }
        }
    }
    Ok(())
}

/// The fields that key an ingested row, in a fixed order — enough to order
/// every kind's rows the same way in every request.
fn row_key(v: &serde_json::Value) -> Vec<String> {
    ["tenant_id", "hash", "content_hash", "blob_type", "request_id", "timestamp", "user_id", "upstream_server_id"]
        .iter()
        .map(|k| v.get(k).map(|x| x.as_str().map_or_else(|| x.to_string(), str::to_string)).unwrap_or_default())
        .collect()
}

/// Store a rotated per-user MCP credential, keeping the one with the later
/// `expires_at`: a rotation that arrives after a newer one (a redelivery, or a
/// sibling replica's older refresh) changes nothing. Where either side has no
/// expiry the two cannot be ordered, and the rotation is taken. A user or upstream deleted since the
/// rotation makes it a no-op, never a foreign-key refusal. The tokens are
/// ciphertext strings, stored as their bytes.
async fn upsert_rotated_credential(conn: &mut IngestConn, cred: &serde_json::Value) -> Result<(), sqlx::Error> {
    let cred: streamscope_core::config::mcp::McpUserCredential =
        serde_json::from_value(cred.clone()).map_err(|e| sqlx::Error::Decode(Box::new(e)))?;
    sqlx::query(
        "INSERT INTO mcp_user_credentials \
             (tenant_id, user_id, upstream_server_id, encrypted_access_token, encrypted_refresh_token, expires_at, scope) \
         SELECT $1, $2, $3, $4, $5, $6, $7 \
          WHERE EXISTS (SELECT 1 FROM users WHERE tenant_id = $1 AND id = $2) \
            AND EXISTS (SELECT 1 FROM mcp_upstream_servers WHERE tenant_id = $1 AND id = $3) \
         ON CONFLICT (tenant_id, user_id, upstream_server_id) DO UPDATE \
            SET encrypted_access_token = EXCLUDED.encrypted_access_token, \
                encrypted_refresh_token = COALESCE(EXCLUDED.encrypted_refresh_token, \
                                                   mcp_user_credentials.encrypted_refresh_token), \
                expires_at = EXCLUDED.expires_at, \
                scope = COALESCE(EXCLUDED.scope, mcp_user_credentials.scope), \
                updated_at = NOW() \
          WHERE mcp_user_credentials.expires_at IS NULL \
             OR EXCLUDED.expires_at IS NULL \
             OR EXCLUDED.expires_at > mcp_user_credentials.expires_at",
    )
    .bind(cred.tenant_id)
    .bind(cred.user_id)
    .bind(cred.upstream_server_id)
    .bind(cred.encrypted_access_token.as_bytes())
    .bind(cred.encrypted_refresh_token.as_deref().map(str::as_bytes))
    .bind(cred.expires_at)
    .bind(&cred.scope)
    .execute(conn)
    .await
    .map(|_| ())
}

// ---------------------------------------------------------------------------
// Instance state
// ---------------------------------------------------------------------------

/// One tenant's part of an [`InstanceState`].
#[derive(Default)]
struct TenantState<'a> {
    load: Vec<streamscope_core::proxy::qos_metrics::EndpointLoadReport>,
    states: Vec<streamscope_core::proxy::health::EndpointState>,
    health: Vec<&'a OneShot<streamscope_core::proxy::health::HealthTransitionEvent>>,
    model_missing: Vec<&'a OneShot<streamscope_core::proxy::health::EndpointModelMissing>>,
}

impl TenantState<'_> {
    /// Whether the report states where the instance routes for this tenant;
    /// one naming the tenant only for an event says nothing about it.
    fn states_routes(&self) -> bool {
        !self.load.is_empty() || !self.states.is_empty()
    }
}

/// Apply an instance-state report of the instance's current epoch. Best-effort:
/// the next report restates the stated parts and every unanswered event, so a
/// failure is logged — and a tenant whose write failed claims nothing, so a
/// redelivery of the same report applies it. Returns whether every tenant's
/// one-shot events are stored: only then may the edge stop restating them.
async fn apply_instance_state(
    state: &AdminState,
    node_id: uuid::Uuid,
    instance: uuid::Uuid,
    epoch: i64,
    epoch_started_at: chrono::DateTime<chrono::Utc>,
    st: &InstanceState,
) -> bool {
    let Ok(seq) = i64::try_from(st.seq) else {
        tracing::warn!(%node_id, %instance, "edge instance state seq out of range — not applied");
        return false;
    };
    let mut one_shots_settled = true;
    let pool = state.db.global(Global::Infra);

    // The instance-wide part: claimed newer-wins on the instance row, so the
    // edge's metadata never moves back to an older report.
    let mut patch = serde_json::Map::new();
    if let Some(stats) = &st.stats {
        patch.insert("stats".into(), serde_json::to_value(stats).unwrap_or_default());
        patch.insert("stats_updated_at".into(), serde_json::json!(chrono::Utc::now().to_rfc3339()));
    }
    if let Some(runtime) = &st.runtime {
        patch.insert("runtime".into(), serde_json::to_value(runtime).unwrap_or_default());
    }
    let claimed = match sqlx::query(
        "WITH claim AS ( \
             UPDATE edge_instances SET state_seq = $3 \
              WHERE id = $1 AND process_epoch = $2 AND (state_seq IS NULL OR state_seq < $3) \
             RETURNING edge_node_id) \
         UPDATE edge_nodes n SET metadata = COALESCE(n.metadata, '{}'::jsonb) || $4::jsonb, last_seen = NOW() \
           FROM claim WHERE n.id = claim.edge_node_id",
    )
    .bind(instance)
    .bind(epoch)
    .bind(seq)
    .bind(serde_json::Value::Object(patch))
    .execute(pool)
    .await
    {
        Ok(r) => r.rows_affected() > 0,
        Err(e) => {
            tracing::warn!(%node_id, %instance, "edge instance state: claim failed: {e}");
            false
        }
    };
    // Only the report that won the claim is sampled: a late older one would
    // land out of order in a series consumers difference.
    if claimed
        && let Some(stats) = &st.stats
        && let Err(e) = insert_stats_sample(&state.db, instance, stats, (epoch, seq)).await
    {
        tracing::warn!(%node_id, %instance, "edge instance state: stats sample failed: {e}");
    }

    let mut by_tenant: HashMap<uuid::Uuid, TenantState<'_>> = HashMap::new();
    for r in &st.endpoints.load {
        by_tenant.entry(r.tenant_id).or_default().load.push(r.clone());
    }
    for s in &st.endpoints.states {
        by_tenant.entry(s.tenant_id).or_default().states.push(s.clone());
    }
    for h in &st.health {
        by_tenant.entry(h.event.tenant_id).or_default().health.push(h);
    }
    for m in &st.model_missing {
        by_tenant.entry(m.event.tenant_id).or_default().model_missing.push(m);
    }
    prune_deleted_tenants(&state.db, node_id, "ingest_instance_state", &mut by_tenant).await;
    let beat_id = uuid::Uuid::new_v5(&instance, format!("{epoch}/{seq}").as_bytes());
    for (tenant, part) in by_tenant {
        let applied: Result<bool, sqlx::Error> = async {
            let mut tdb = TenantConn::acquire(&state.db, TenantId::from_edge(tenant)).await?;
            let mut tx = tdb.conn().begin().await?;
            // The stated part, newer-wins: a report not newer than the claim
            // writes none of it.
            let claimed = part.states_routes()
                && sqlx::query(
                    "INSERT INTO edge_instance_tenant_state (tenant_id, edge_instance_id, process_epoch, state_seq) \
                     SELECT $1, $2, $3, $4 \
                      WHERE EXISTS (SELECT 1 FROM edge_instances WHERE id = $2 AND process_epoch = $3) \
                     ON CONFLICT (tenant_id, edge_instance_id) DO UPDATE SET \
                         process_epoch = EXCLUDED.process_epoch, state_seq = EXCLUDED.state_seq, applied_at = NOW() \
                      WHERE edge_instance_tenant_state.process_epoch <> EXCLUDED.process_epoch \
                         OR edge_instance_tenant_state.state_seq < EXCLUDED.state_seq",
                )
                .bind(tenant)
                .bind(instance)
                .bind(epoch)
                .bind(seq)
                .execute(&mut *tx)
                .await?
                .rows_affected()
                    > 0;
            if claimed {
                record_endpoint_stands(&mut tx, tenant, instance, epoch_started_at, &part.states).await?;
                insert_load_samples(&mut tx, tenant, instance, beat_id, &part.load).await?;
            }
            // The one-shot part, once per event id, whichever report carries
            // it: the edge restates each event until a request carrying it is
            // answered, so a later report holds every event an earlier one
            // did, in the order they happened.
            let ids: Vec<i64> = part
                .health
                .iter()
                .map(|e| e.id)
                .chain(part.model_missing.iter().map(|e| e.id))
                .filter_map(|id| i64::try_from(id).ok())
                .collect();
            let fresh: HashSet<i64> = if ids.is_empty() {
                HashSet::new()
            } else {
                sqlx::query_scalar(
                    "INSERT INTO edge_instance_events (edge_instance_id, process_epoch, event_id) \
                     SELECT $1, $2, unnest($3::bigint[]) \
                     ON CONFLICT DO NOTHING RETURNING event_id",
                )
                .bind(instance)
                .bind(epoch)
                .bind(&ids)
                .fetch_all(&mut *tx)
                .await?
                .into_iter()
                .collect()
            };
            let is_fresh = |id: u64| i64::try_from(id).is_ok_and(|id| fresh.contains(&id));
            for e in part.health.into_iter().filter(|e| is_fresh(e.id)) {
                let server_name = upstream_server_name(&mut tx, &e.event).await?;
                record_endpoint_health(&mut tx, instance, &e.event).await?;
                crate::notifications::notify(&mut tx, tenant, health_notification(&e.event, server_name)).await?;
            }
            for e in part.model_missing.into_iter().filter(|e| is_fresh(e.id)) {
                record_model_missing(&mut tx, &e.event).await?;
            }
            tx.commit().await?;
            Ok(claimed)
        }
        .await;
        if let Err(e) = applied {
            one_shots_settled = false;
            tracing::warn!(%node_id, %instance, %tenant, "edge instance state not applied for the tenant: {e}");
        }
    }
    // The report is written: live load reads this beat, and stands lapse
    // relative to it. Only while it is still the instance's latest report.
    if let Err(e) = sqlx::query(
        "UPDATE edge_instances SET state_beat_id = $4, state_written_at = now() \
          WHERE id = $1 AND process_epoch = $2 AND state_seq = $3",
    )
    .bind(instance)
    .bind(epoch)
    .bind(seq)
    .bind(beat_id)
    .execute(pool)
    .await
    {
        tracing::warn!(%node_id, %instance, "edge instance state: beat mark failed: {e}");
    }
    one_shots_settled
}

#[cfg(test)]
mod tests {
    use super::{is_outage, is_outage_sqlstate};

    /// A database that cannot be reached is an outage, answered with one Retry
    /// for the whole request; a failure of one share's own data is not, and is
    /// isolated by writing the shares one by one.
    #[test]
    fn only_an_unreachable_database_reads_as_an_outage() {
        assert!(is_outage(&sqlx::Error::PoolTimedOut));
        assert!(is_outage(&sqlx::Error::PoolClosed));
        assert!(is_outage(&sqlx::Error::Io(std::io::Error::other("reset"))));
        assert!(!is_outage(&sqlx::Error::Decode("a record that does not decode".into())));
        assert!(!is_outage(&sqlx::Error::RowNotFound));
    }

    /// One case per class on each side: the database refusing work is an
    /// outage; a refusal of one share's rows — data, a constraint, a reference,
    /// a privilege, a deadlock — never is.
    #[test]
    fn only_a_database_refusing_work_is_an_outage_sqlstate() {
        for code in ["08006", "08001", "53300", "53200", "57014", "57P01", "55P03"] {
            assert!(is_outage_sqlstate(code), "{code} is an outage");
        }
        for code in ["22001", "23505", "23503", "23514", "21000", "54000", "42501", "40P01", "55000", "XX000"] {
            assert!(!is_outage_sqlstate(code), "{code} is not an outage");
        }
    }
}
