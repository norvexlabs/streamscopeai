//! The edge's link to admin-api: two loops over `/api/v2/edge/*`, each on its
//! own interval, and the sink every audit producer writes through.
//!
//! - **Sync** ([`SyncV2`]) asks for config changes and events every
//!   `EDGE_SYNC_INTERVAL_MS`; the events are dispatched here.
//! - **Ingest** ships the outbox every `EDGE_SHIP_INTERVAL_MS`, with this
//!   instance's state every `EDGE_STATE_INTERVAL_SECS` and its usage counters
//!   every `EDGE_USAGE_SYNC_INTERVAL_SECS`.
//!
//! Nothing is held open: every request restates what it depends on, and a
//! failed one backs off (doubling, with jitter) and is retried. What a request
//! carried stays until an answer covers it — outbox rows until their share's
//! outcome, one-shot events and usage cumulatives until any ingest answer.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use base64::Engine;
use streamscope_core::audit::a2a::{A2aAuditForwarderTrait, A2aAuditRecord};
use streamscope_core::audit::mcp::McpAuditForwarderTrait;
use streamscope_core::audit::{AuditForwarderTrait, AuditRecord, BlobRef, BlobType, McpAuditRecord};
use streamscope_core::config::mcp::McpUserCredential;
use streamscope_core::config::TenantRegistry;
use streamscope_core::mcp::sse_events::McpSseEventRecord;
use streamscope_core::proxy::health::EdgeHealthEvent;
use streamscope_core::usage::{UsageCounterKey, UsageCounterReport};
use streamscope_core::web::{WebAuditForwarderTrait, WebAuditRecord};
use streamscope_edge_api::ingest::{
    BlobContent, Content, EdgeProxyStats, EdgeRuntimeReport, EndpointBeat, INGEST_REQUEST_MAX_BYTES,
    IngestRequest, IngestResponse, InstanceState, MessageContent, OneShot, Record, ShareOutcome,
    SystemPromptContent, ToolDefinitionContent, UsageReport,
};
use streamscope_edge_api::sync::{Epoch, Event};

use crate::outbox_v2::{Applied, Enqueued, OutboxV2, PendingShare, UploadKey, Uploads};
use crate::settings::proxy_settings;
use crate::sync_v2::SyncV2;

/// Room an ingest request keeps for its own envelope around the shares.
const INGEST_ENVELOPE_RESERVE_BYTES: usize = 64 * 1024;

/// The most one-shot events kept for restating: an admin unreachable for long
/// enough must not grow a request past what admin-api reads.
const ONE_SHOTS_MAX: usize = 1024;

/// The most usage counters kept for restating, for the same reason.
const UNANSWERED_USAGE_MAX: usize = 20_000;

/// The slowest transfer an edge link is given time for, beyond the request
/// timeout: a full request on a slow link still completes.
const TRANSFER_FLOOR_BYTES_PER_SEC: usize = 256 * 1024;

/// The longest an edge waits between two sync requests, whatever its settings:
/// admin-api counts an instance live only while its last sync is
/// `INSTANCE_LIVE_SECS` old, and on top of the wait come a quarter of jitter,
/// the edge's apply and admin's rebuilds — a third leaves room for them.
const LONGEST_WAIT: Duration = Duration::from_secs(streamscope_edge_api::ingest::INSTANCE_LIVE_SECS / 3);

fn longest_wait(d: Duration) -> Duration {
    d.min(LONGEST_WAIT)
}

/// The request timeout plus the time `bytes` take at the floor rate.
fn transfer_timeout(base: Duration, bytes: usize) -> Duration {
    base + Duration::from_secs((bytes / TRANSFER_FLOOR_BYTES_PER_SEC) as u64)
}

/// Drop the oldest windows' counters past [`UNANSWERED_USAGE_MAX`]. A dropped
/// counter's delta is not merged — an under-count, within the
/// estimate-not-ledger stance of fleet counters, logged once per drop.
fn hold_usage_to_its_cap(usage: &mut HashMap<UsageCounterKey, u64>) {
    if usage.len() <= UNANSWERED_USAGE_MAX {
        return;
    }
    let mut keys: Vec<UsageCounterKey> = usage.keys().cloned().collect();
    keys.sort_by_key(|k| k.window_start_ms);
    let excess = usage.len() - UNANSWERED_USAGE_MAX;
    for k in keys.into_iter().take(excess) {
        usage.remove(&k);
    }
    tracing::error!(dropped = excess, "edge usage counters unanswered past the cap — the oldest windows' deltas are dropped");
}

/// How long a shutdown keeps shipping the outbox before giving up — what is
/// left stays on disk and ships on the next start.
const SHUTDOWN_DRAIN: Duration = Duration::from_secs(10);

// ---------------------------------------------------------------------------
// The sink: every producer's records into the outbox
// ---------------------------------------------------------------------------

/// Writes every record the proxy produces into the outbox, with the content it
/// references. A record that cannot be buffered is logged and lost — there
/// is no other durable place for it — and takes no other tenant's records
/// with it: each tenant's are written in a transaction of their own.
#[derive(Clone)]
pub struct OutboxSink {
    outbox: Arc<OutboxV2>,
    /// LLM audit records buffered this process lifetime (monotonic).
    buffered_llm: Arc<AtomicU64>,
    /// Successful (HTTP 200) `tools/call` MCP audit records buffered this
    /// process lifetime (monotonic) — the proxy-bounce e2e waits on it before
    /// killing the process.
    durable_tools_call: Arc<AtomicU64>,
    /// Woken when a buffered record is waited on by other instances (a
    /// server-initiated MCP event): the ingest loop ships it at once instead
    /// of on its next tick.
    ship_now: Arc<tokio::sync::Notify>,
}

impl OutboxSink {
    pub fn new(outbox: Arc<OutboxV2>) -> Self {
        Self { outbox, buffered_llm: Arc::default(), durable_tools_call: Arc::default(), ship_now: Arc::default() }
    }

    /// What the ingest loop waits on beside its tick ([`LinkConfig::ship_now`]).
    pub fn ship_now(&self) -> Arc<tokio::sync::Notify> {
        self.ship_now.clone()
    }

    pub fn buffered_llm(&self) -> u64 {
        self.buffered_llm.load(Ordering::Relaxed)
    }

    pub fn durable_tools_call(&self) -> u64 {
        self.durable_tools_call.load(Ordering::Relaxed)
    }

    /// Buffer each tenant's records with their content, in a transaction per
    /// tenant: one tenant's failure takes no other's records with it. Calls
    /// `held` for each record the outbox holds; returns how many it does not
    /// — a failed tenant's (logged here) and any it dropped itself (logged by
    /// the outbox).
    async fn enqueue_groups(
        &self,
        groups: impl IntoIterator<Item = (uuid::Uuid, Vec<Enqueued>, Content)>,
        mut held: impl FnMut(&Record),
    ) -> usize {
        let mut lost = 0;
        for (tenant, records, content) in groups {
            match self.outbox.enqueue(tenant, &records, &content).await {
                Ok(indexes) => {
                    lost += records.len() - indexes.len();
                    indexes.into_iter().for_each(|i| held(&records[i].record));
                }
                Err(e) => {
                    lost += records.len();
                    tracing::error!(%tenant, count = records.len(), "records could not be buffered for admin-api — lost: {e}");
                }
            }
        }
        lost
    }

    /// [`enqueue_groups`](Self::enqueue_groups) for records without content.
    async fn enqueue_plain(&self, records: impl IntoIterator<Item = Record>, held: impl FnMut(&Record)) -> usize {
        let mut by_tenant: HashMap<uuid::Uuid, Vec<Enqueued>> = HashMap::new();
        for record in records {
            by_tenant.entry(record.tenant_id()).or_default().push(Enqueued { record });
        }
        self.enqueue_groups(by_tenant.into_iter().map(|(t, r)| (t, r, Content::default())), held).await
    }

    /// Buffer a batch of MCP SSE events (the `Last-Event-ID` replay rows).
    pub async fn forward_sse_events(&self, records: Vec<McpSseEventRecord>) {
        let records = records.into_iter().map(|r| Record::McpSseEvent(Box::new(r)));
        // A loss is logged where it happens (`enqueue_groups`, the outbox).
        self.enqueue_plain(records, |_| {}).await;
    }
}

/// One LLM audit record's content, moved out of the record: the record keeps
/// only the hashes it names.
fn take_content(record: &mut AuditRecord, content: &mut Content) {
    // Prefer the per-message strings serialised once at request-capture time;
    // the `request_messages` tree only when the media-strip pass rebuilt it.
    let messages_json: Option<Vec<String>> = record.request_messages_json.take().or_else(|| {
        record
            .request_messages
            .as_ref()?
            .as_array()
            .map(|arr| arr.iter().map(|m| serde_json::to_string(m).unwrap_or_default()).collect())
    });
    // Each message is stored, and named by the turn, under the hash of the
    // stored bytes — never under its session-link hash, which leaves parts out
    // and so is shared by messages that differ. A message with no body to ship
    // is named by a key no stored body has (a stored key is 64 hex digits): it
    // reads as unavailable, never as another request's message.
    if let Some(links) = &record.link_hashes {
        let mut keys = Vec::with_capacity(links.len());
        for (i, link) in links.iter().enumerate() {
            let parsed = messages_json.as_ref().and_then(|all| all.get(i)).map(|json| serde_json::from_str::<serde_json::Value>(json));
            match parsed {
                Some(Ok(message)) => {
                    let (hash, size) = streamscope_core::proxy::content::stored_message_key(&message);
                    content.messages.push(MessageContent {
                        hash: hash.clone(),
                        message,
                        content_size: i32::try_from(size).unwrap_or(i32::MAX),
                    });
                    keys.push(hash);
                }
                Some(Err(e)) => {
                    tracing::error!(
                        request_id = %record.request_id, link = %link,
                        "conversation message could not be read back for shipping — not stored: {e}"
                    );
                    keys.push(format!("unstored-{link}"));
                }
                None => keys.push(format!("unstored-{link}")),
            }
        }
        record.message_hashes = Some(keys);
    }
    let mut blob = |content_hash: String, blob_type: BlobType, media_type: String, data: &[u8]| {
        let b = BlobContent {
            content_hash,
            blob_type,
            media_type,
            data_base64: base64::engine::general_purpose::STANDARD.encode(data),
        };
        content.blobs.push(b);
    };
    let (request_blob, response_blob) = record
        .media_call
        .as_ref()
        .map(|c| (first_blob_ref(&c.input, BlobType::RequestUpload), first_blob_ref(&c.output, BlobType::ResponseBody)))
        .unwrap_or((None, None));
    if let (Some((hash, blob_type, mime)), Some(data)) = (request_blob, record.media_blob_data.take()) {
        blob(hash, blob_type, mime, &data);
    }
    if let (Some((hash, blob_type, mime)), Some(data)) = (response_blob, record.media_response_blob_data.take()) {
        blob(hash, blob_type, mime, &data);
    }
    for b in std::mem::take(&mut record.message_blobs) {
        // A stripped entry carries no bytes to store.
        if !b.data.is_empty() {
            record.buffered_blobs.push(BlobRef { content_hash: b.content_hash.clone(), blob_type: b.blob_type });
            blob(b.content_hash, b.blob_type, b.media_type, &b.data);
        }
    }
    for t in std::mem::take(&mut record.tool_definitions_to_buffer) {
        match serde_json::from_str::<serde_json::Value>(&t.definition_json) {
            Ok(definition) => {
                content.tool_definitions.push(ToolDefinitionContent {
                    hash: t.hash,
                    definition,
                    content_size: i32::try_from(t.content_size).unwrap_or(i32::MAX),
                });
            }
            Err(e) => tracing::error!(
                request_id = %record.request_id, hash = %t.hash,
                "tool definitions could not be read back for shipping — not stored: {e}"
            ),
        }
    }
    if let Some(prompt) = record.system_prompt.take().filter(|p| !p.is_empty()) {
        let hash = streamscope_core::audit::system_prompt_hash(&prompt);
        content.system_prompts.push(SystemPromptContent {
            hash: hash.clone(),
            content_size: i32::try_from(prompt.len()).unwrap_or(i32::MAX),
            prompt,
        });
        record.system_prompt_hash = Some(hash);
    }
    // Content travels as content; the record keeps only what names it.
    record.request_messages = None;
    record.request_tools = None;
}

/// `(content_hash, blob_type, media_type)` of the first blob reference in a
/// list; a reference naming no type is the side's (`side`), as
/// [`Record::content_keys`] reads it.
fn first_blob_ref(
    blocks: &[streamscope_core::api::domain_request::DomainContentBlock],
    side: BlobType,
) -> Option<(String, BlobType, String)> {
    blocks.iter().find_map(|b| match b {
        streamscope_core::api::domain_request::DomainContentBlock::BlobRef { content_hash, media_type, blob_type, .. } => {
            Some((content_hash.clone(), blob_type.unwrap_or(side), media_type.clone()))
        }
        _ => None,
    })
}

impl AuditForwarderTrait for OutboxSink {
    fn forward_batch(
        &self,
        mut records: Vec<AuditRecord>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, anyhow::Error>> + Send + '_>> {
        Box::pin(async move {
            let mut by_tenant: HashMap<uuid::Uuid, (Vec<Enqueued>, Content)> = HashMap::new();
            for mut record in records.drain(..) {
                let (enqueued, content) = by_tenant.entry(record.tenant_id).or_default();
                take_content(&mut record, content);
                enqueued.push(Enqueued { record: Record::LlmAudit(Box::new(record)) });
            }
            // Per record: what the outbox holds counts as buffered, and the
            // rest — a failed tenant's, or one the outbox dropped — is
            // answered lost, so the emission accounting closes and no loss is
            // reported for records another tenant's write kept.
            let mut held = 0u64;
            let lost = self
                .enqueue_groups(by_tenant.into_iter().map(|(t, (r, c))| (t, r, c)), |_| held += 1)
                .await;
            self.buffered_llm.fetch_add(held, Ordering::Relaxed);
            Ok(lost)
        })
    }
}

impl McpAuditForwarderTrait for OutboxSink {
    fn forward_batch<'a>(
        &'a self,
        records: &'a [McpAuditRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            let (mut fanout, mut tool_calls) = (false, 0u64);
            self.enqueue_plain(records.iter().map(|r| Record::McpAudit(Box::new(r.clone()))), |held| {
                if let Record::McpAudit(r) = held {
                    fanout |= streamscope_edge_api::ingest::is_mcp_fanout_method(&r.method);
                    // Only successful calls the outbox holds: the bounce e2e
                    // waits for exactly those before it kills the process.
                    tool_calls += u64::from(r.method == "tools/call" && r.status_code == Some(200));
                }
            })
            .await;
            if fanout {
                self.ship_now.notify_one();
            }
            self.durable_tools_call.fetch_add(tool_calls, Ordering::Relaxed);
            Ok(())
        })
    }
}

impl A2aAuditForwarderTrait for OutboxSink {
    fn forward_batch<'a>(
        &'a self,
        records: &'a [A2aAuditRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            self.enqueue_plain(records.iter().map(|r| Record::A2aAudit(Box::new(r.clone()))), |_| {}).await;
            Ok(())
        })
    }
}

impl WebAuditForwarderTrait for OutboxSink {
    fn forward_batch<'a>(
        &'a self,
        records: &'a [WebAuditRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>> {
        Box::pin(async move {
            self.enqueue_plain(records.iter().map(|r| Record::WebAudit(Box::new(r.clone()))), |_| {}).await;
            Ok(())
        })
    }
}

/// A refreshed per-user MCP credential, buffered before admin-api has it: a
/// process that dies between the refresh and the delivery still delivers it
/// on its next start (the tokens are already ciphertext).
impl crate::mcp::oauth::RotationSink for OutboxSink {
    fn persist_rotation<'a>(
        &'a self,
        cred: McpUserCredential,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            let (tenant, user, upstream) = (cred.tenant_id, cred.user_id, cred.upstream_server_id);
            let records = [Enqueued { record: Record::CredentialRotation(Box::new(cred)) }];
            // One the outbox drops (it cannot travel whole) is logged there.
            if let Err(e) = self.outbox.enqueue(tenant, &records, &Content::default()).await {
                tracing::error!(%tenant, %user, %upstream, "rotated MCP credential could not be buffered for admin-api: {e}");
            }
        })
    }
}

/// Batch the proxy-side MCP SSE event channel into the outbox: up to
/// `audit_batch_size` records or every `audit_batch_deadline_ms`, whichever
/// comes first. On shutdown the channel is drained before the task exits.
pub async fn mcp_sse_event_writer_task(
    mut rx: streamscope_core::audit::AuditReceiver<McpSseEventRecord>,
    sink: OutboxSink,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let s = streamscope_core::settings::core_settings();
    let (max_batch, deadline_ms) = (s.audit_batch_size, s.audit_batch_deadline_ms);
    let mut batch: Vec<McpSseEventRecord> = Vec::with_capacity(max_batch);
    loop {
        let deadline = tokio::time::sleep(Duration::from_millis(deadline_ms));
        tokio::pin!(deadline);
        let mut done = false;
        loop {
            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some(record) => {
                        batch.push(record);
                        if batch.len() >= max_batch {
                            break;
                        }
                    }
                    None => {
                        done = true;
                        break;
                    }
                },
                () = &mut deadline => break,
                () = shutdown.cancelled() => {
                    while let Ok(record) = rx.try_recv() {
                        batch.push(record);
                        if batch.len() >= max_batch {
                            let records = std::mem::take(&mut batch);
                            let n = records.len();
                            sink.forward_sse_events(records).await;
                            rx.forwarded(n);
                        }
                    }
                    done = true;
                    break;
                }
            }
        }
        if !batch.is_empty() {
            let records = std::mem::take(&mut batch);
            let n = records.len();
            sink.forward_sse_events(records).await;
            rx.forwarded(n);
        }
        if done {
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Events from admin-api
// ---------------------------------------------------------------------------

/// Dispatch one event from a sync answer. An MCP user event (a
/// server-initiated message another instance relayed) is published to this
/// process's bus for its (tenant, user, virtual server), so a `GET /mcp/<slug>`
/// subscriber here sees it without a request of its own.
pub fn dispatch_event(bus: &crate::mcp::event_bus::PerUserEventBus, event: &Event) {
    #[derive(serde::Deserialize)]
    struct McpUserEvent {
        tenant_id: uuid::Uuid,
        user_id: uuid::Uuid,
        method: String,
        #[serde(default)]
        mcp_session_id: Option<String>,
        /// The bus is keyed by virtual server: without one the event would
        /// have to reach every virtual server the user has open, so it is not
        /// published.
        #[serde(default)]
        virtual_server_id: Option<uuid::Uuid>,
    }
    match event.body.get("type").and_then(|t| t.as_str()) {
        Some("mcp_user_event") => {}
        other => {
            tracing::debug!(id = event.id, kind = ?other, "edge event of an unknown kind — ignored");
            return;
        }
    }
    let e: McpUserEvent = match serde_json::from_value(event.body.clone()) {
        Ok(e) => e,
        Err(err) => {
            tracing::warn!(id = event.id, "MCP user event could not be read — not published: {err}");
            return;
        }
    };
    let Some(vs_id) = e.virtual_server_id else {
        tracing::debug!(id = event.id, method = %e.method, "MCP user event without a virtual server — not published");
        return;
    };
    // The thin frame a GET-channel subscriber reads: the method and session
    // the audit row carries, never its transform diff.
    let mut data = serde_json::Map::new();
    data.insert("jsonrpc".into(), serde_json::json!("2.0"));
    data.insert("method".into(), serde_json::json!(e.method));
    if let Some(sid) = e.mcp_session_id {
        data.insert("mcp_session_id".into(), serde_json::json!(sid));
    }
    let data = serde_json::Value::Object(data).to_string();
    let mut wire = Vec::with_capacity(64 + data.len());
    wire.extend_from_slice(b"event: notification\ndata: ");
    wire.extend_from_slice(data.as_bytes());
    wire.extend_from_slice(b"\n\n");
    bus.publish(e.tenant_id, e.user_id, vs_id, crate::mcp::event_bus::UserEvent(bytes::Bytes::from(wire)));
}

// ---------------------------------------------------------------------------
// The link
// ---------------------------------------------------------------------------

/// What the link reads and writes in this process.
pub struct LinkConfig {
    pub admin_api_url: String,
    pub token: String,
    pub instance: uuid::Uuid,
    pub epoch: Epoch,
    pub sync: SyncV2,
    pub outbox: Arc<OutboxV2>,
    /// What the sync requests report as `outbox_pending`.
    pub(crate) pending: Pending,
    pub tenant_registry: TenantRegistry,
    pub usage: Arc<streamscope_core::usage::UsageTracker>,
    pub proxy_stats: Arc<crate::stats::ProxyStats>,
    pub response_cache: Arc<streamscope_core::proxy::response_cache::ResponseCache>,
    pub dispatch_gate: Arc<streamscope_core::proxy::dispatch_gate::DispatchGate>,
    pub circuit_breaker: Arc<streamscope_core::proxy::health::CircuitBreaker>,
    pub health_event_rx: tokio::sync::mpsc::Receiver<EdgeHealthEvent>,
    pub mcp_event_bus: Arc<crate::mcp::event_bus::PerUserEventBus>,
    /// [`OutboxSink::ship_now`]: cuts the ingest loop's wait short.
    pub ship_now: Arc<tokio::sync::Notify>,
    /// Cancelled once every producer has flushed into the outbox: the sync
    /// loop stops, and the ingest loop ships what it can within
    /// [`SHUTDOWN_DRAIN`] before it stops.
    pub shutdown: tokio_util::sync::CancellationToken,
}

/// Run both loops until shutdown.
pub async fn run(cfg: LinkConfig) {
    let ps = proxy_settings();
    let build = |b: reqwest::ClientBuilder| {
        streamscope_core::tls::add_custom_roots(
            b.connect_timeout(ps.edge_request_timeout),
            streamscope_core::settings::core_settings().custom_ca_bundle.as_deref(),
        )
        .build()
    };
    // Ingest: each request carries a total timeout scaled to what it uploads.
    // Sync: an answer of any size streams in, and a stall — no byte for the
    // request timeout — ends the attempt.
    let (client, sync_client) = match (build(reqwest::Client::builder()), build(reqwest::Client::builder().read_timeout(ps.edge_request_timeout))) {
        (Ok(c), Ok(s)) => (c, s),
        (Err(e), _) | (_, Err(e)) => {
            tracing::error!("edge link: building the HTTP client failed — this edge cannot reach admin-api: {e}");
            return;
        }
    };
    let base = cfg.admin_api_url.trim_end_matches('/').to_string();
    let pending = cfg.pending.clone();
    let sync = SyncLoop {
        client: sync_client,
        url: format!("{base}/api/v2/edge/sync"),
        token: cfg.token.clone(),
        instance: cfg.instance,
        epoch: cfg.epoch,
        sync: cfg.sync,
        pending: pending.clone(),
        bus: cfg.mcp_event_bus,
        proxy_stats: cfg.proxy_stats.clone(),
        shutdown: cfg.shutdown.clone(),
    };
    let ingest = IngestLoop {
        client,
        url: format!("{base}/api/v2/edge/ingest"),
        base: base.clone(),
        token: cfg.token,
        instance: cfg.instance,
        epoch: cfg.epoch,
        outbox: cfg.outbox,
        pending,
        tenant_registry: cfg.tenant_registry,
        usage: cfg.usage,
        proxy_stats: cfg.proxy_stats,
        response_cache: cfg.response_cache,
        dispatch_gate: cfg.dispatch_gate,
        circuit_breaker: cfg.circuit_breaker,
        health_event_rx: cfg.health_event_rx,
        one_shots: OneShots::default(),
        seq: 0,
        unanswered_usage: HashMap::new(),
        upload: None,
        upload_waits: HashMap::new(),
        ship_now: cfg.ship_now,
        shutdown: cfg.shutdown,
    };
    tokio::join!(sync.run(), ingest.run());
}

/// What `outbox_pending` reports: every audit record the proxy has produced
/// and admin-api has not yet answered for.
#[derive(Clone)]
pub(crate) struct Pending {
    /// Streamed responses' audit tasks still running: a task hands its record
    /// to an audit channel before it ends.
    tasks: tokio_util::task::TaskTracker,
    /// Each audit channel's records taken and not yet forwarded into the outbox.
    channels: Arc<[streamscope_core::audit::PendingCount]>,
    outbox: Arc<OutboxV2>,
}

impl Pending {
    pub(crate) fn new(
        tasks: tokio_util::task::TaskTracker,
        channels: Vec<streamscope_core::audit::PendingCount>,
        outbox: Arc<OutboxV2>,
    ) -> Self {
        Self { tasks, channels: channels.into(), outbox }
    }

    pub(crate) async fn count(&self) -> u64 {
        match self.try_count().await {
            Ok(n) => n,
            Err(e) => {
                tracing::warn!("edge outbox count failed: {e}");
                self.tasks.len() as u64 + self.channel_count()
            }
        }
    }

    /// The count, or the outbox's error: a caller deciding that nothing is
    /// pending must not read a failed count as 0.
    pub(crate) async fn try_count(&self) -> Result<u64, anyhow::Error> {
        count_upstream_first(|| self.tasks.len() as u64, || self.channel_count(), || self.outbox.pending()).await
    }

    fn channel_count(&self) -> u64 {
        self.channels.iter().map(streamscope_core::audit::PendingCount::get).sum()
    }
}

/// Read the stages a record moves through in its order — the stream tasks, the
/// audit channels, the outbox last — and sum them: a record moving on between
/// two reads is counted twice, never missed.
async fn count_upstream_first<F, E>(
    tasks: impl FnOnce() -> u64,
    channels: impl FnOnce() -> u64,
    outbox: impl FnOnce() -> F,
) -> Result<u64, E>
where
    F: std::future::Future<Output = Result<u64, E>>,
{
    let tasks = tasks();
    let channels = channels();
    Ok(tasks + channels + outbox().await?)
}

/// Capped exponential backoff with up to 25% jitter.
struct Backoff {
    next: Duration,
    max: Duration,
}

impl Backoff {
    /// Doubling from `EDGE_BACKOFF_INITIAL_SECS` up to `max`.
    fn new(max: Duration) -> Self {
        Self { next: Self::initial(), max: max.max(Duration::from_secs(1)) }
    }

    /// The ingest loop's: up to `EDGE_BACKOFF_MAX_SECS`, so an edge resending
    /// a large request to a struggling admin-api backs off for real.
    fn for_ingest() -> Self {
        Self::new(Duration::from_secs(proxy_settings().edge_backoff_max_secs))
    }

    /// The sync loop's: held under the live window too (see [`LONGEST_WAIT`]).
    fn for_sync() -> Self {
        Self::new(longest_wait(Duration::from_secs(proxy_settings().edge_backoff_max_secs)))
    }

    fn initial() -> Duration {
        Duration::from_secs(proxy_settings().edge_backoff_initial_secs.max(1))
    }

    fn reset(&mut self) {
        self.next = Self::initial();
    }
    /// The wait before the next attempt; doubles up to the cap.
    fn fail(&mut self) -> Duration {
        let wait = self.next.min(self.max);
        self.next = (self.next * 2).min(self.max);
        wait + Duration::from_millis(jitter_ms(wait.as_millis() as u64 / 4))
    }
}

/// A pseudo-random value in `[0, max_ms)`.
fn jitter_ms(max_ms: u64) -> u64 {
    if max_ms == 0 {
        return 0;
    }
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.subsec_nanos() as u64)
        .unwrap_or(0);
    nanos % max_ms
}

struct SyncLoop {
    client: reqwest::Client,
    url: String,
    token: String,
    instance: uuid::Uuid,
    epoch: Epoch,
    sync: SyncV2,
    pending: Pending,
    bus: Arc<crate::mcp::event_bus::PerUserEventBus>,
    proxy_stats: Arc<crate::stats::ProxyStats>,
    shutdown: tokio_util::sync::CancellationToken,
}

impl SyncLoop {
    async fn run(mut self) {
        let ps = proxy_settings();
        let interval = longest_wait(Duration::from_millis(ps.edge_sync_interval_ms.max(50)));
        // Admin-api holds a quiet answer up to the interval, so a change is
        // sent as it happens; the hold stays well inside the read timeout.
        let hold = interval.min(ps.edge_request_timeout / 2);
        let mut backoff = Backoff::for_sync();
        let mut wait = Duration::ZERO;
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => return,
                () = tokio::time::sleep(wait) => {}
            }
            let started = Instant::now();
            let ask = crate::sync_v2::Ask { outbox_pending: self.pending.count().await, wait: hold };
            // Never cancelled mid-answer: an apply cut short could leave the
            // snapshot and the held set out of step. A held poll ends within
            // the hold, so shutdown waits at most that long.
            match self.sync.poll_once(&self.client, &self.url, &self.token, self.instance, self.epoch, ask).await {
                Ok(events) => {
                    for event in &events {
                        dispatch_event(&self.bus, event);
                    }
                    backoff.reset();
                    if self.sync.current() && self.proxy_stats.record_config_synced() {
                        tracing::info!("edge config sync: the control plane has nothing newer for this gateway");
                    }
                    // A held answer already took the interval; one answered at
                    // once (nothing to hold for) waits out the rest of it.
                    wait = if self.sync.poll_again() { Duration::ZERO } else { interval.saturating_sub(started.elapsed()) };
                }
                // Not a failing admin-api: a connection that died under a held
                // answer. Asked again at once, through whatever replica the
                // address now reaches.
                Err(e) if e.is::<crate::sync_v2::AnswerLost>() => {
                    wait = Duration::ZERO;
                    tracing::warn!("edge config sync: {e}");
                }
                Err(e) => {
                    wait = backoff.fail();
                    tracing::warn!(retry_in_ms = wait.as_millis() as u64, "edge config sync failed: {e}");
                }
            }
        }
    }
}

/// One-shot events not yet carried by an answered ingest request, numbered in
/// the order they happened within this process epoch.
#[derive(Default)]
struct OneShots {
    next_id: u64,
    /// The highest id an answered request carried, settled or not.
    answered_carry: u64,
    health: Vec<OneShot<streamscope_core::proxy::health::HealthTransitionEvent>>,
    model_missing: Vec<OneShot<streamscope_core::proxy::health::EndpointModelMissing>>,
}

impl OneShots {
    fn push(&mut self, event: EdgeHealthEvent) {
        self.next_id += 1;
        let id = self.next_id;
        match event {
            EdgeHealthEvent::Transition(event) => self.health.push(OneShot { id, event }),
            EdgeHealthEvent::ModelMissing(event) => self.model_missing.push(OneShot { id, event }),
        }
        // Held to its cap, oldest first, so restating them never outgrows a request.
        let held = self.health.len() + self.model_missing.len();
        if held > ONE_SHOTS_MAX {
            let oldest = self.health.first().map(|e| e.id).into_iter().chain(self.model_missing.first().map(|e| e.id)).min();
            if let Some(oldest) = oldest {
                self.health.retain(|e| e.id != oldest);
                self.model_missing.retain(|e| e.id != oldest);
                tracing::error!(dropped_event = oldest, "edge one-shot events unanswered past the cap — the oldest is dropped");
            }
        }
    }

    /// Forget every event up to `id`: a request carrying them was answered.
    fn answered(&mut self, id: u64) {
        self.health.retain(|e| e.id > id);
        self.model_missing.retain(|e| e.id > id);
    }
}

struct IngestLoop {
    client: reqwest::Client,
    url: String,
    /// admin-api's base URL, for a blob going up by itself.
    base: String,
    token: String,
    instance: uuid::Uuid,
    epoch: Epoch,
    outbox: Arc<OutboxV2>,
    pending: Pending,
    tenant_registry: TenantRegistry,
    usage: Arc<streamscope_core::usage::UsageTracker>,
    proxy_stats: Arc<crate::stats::ProxyStats>,
    response_cache: Arc<streamscope_core::proxy::response_cache::ResponseCache>,
    dispatch_gate: Arc<streamscope_core::proxy::dispatch_gate::DispatchGate>,
    circuit_breaker: Arc<streamscope_core::proxy::health::CircuitBreaker>,
    health_event_rx: tokio::sync::mpsc::Receiver<EdgeHealthEvent>,
    one_shots: OneShots,
    /// The last instance-state report's sequence number in this epoch.
    seq: u64,
    /// Usage cumulatives admin has not answered for: every report restates
    /// them (a cumulative is idempotent; a pruned window's last report would
    /// otherwise be lost), until an answer names the counter.
    unanswered_usage: HashMap<UsageCounterKey, u64>,
    /// The blob going up by itself, if any: one at a time, on a task beside
    /// the ingest requests, so a large blob holds back only the records that
    /// need it.
    upload: Option<(UploadKey, UploadTask)>,
    /// Blobs whose upload failed: each is sent again once its own backoff has
    /// passed, and meanwhile only the records that need it wait. A blob is
    /// never given up for failing: an outage of admin-api must not strip
    /// media from the audit trail.
    upload_waits: HashMap<UploadKey, (Instant, Backoff)>,
    ship_now: Arc<tokio::sync::Notify>,
    shutdown: tokio_util::sync::CancellationToken,
}

/// A blob on its way up; the task wakes the ingest loop when it ends.
type UploadTask = tokio::task::JoinHandle<(PendingShare, Result<ShareOutcome, anyhow::Error>)>;

/// How often the outbox forgets acks no share named for a day.
const ACK_SWEEP_EVERY: Duration = Duration::from_secs(600);

/// The least time between two ingest requests sent early for an event.
const SHIP_NOW_SPACING: Duration = Duration::from_millis(200);

/// How long a failed upload's backoff is remembered after it has passed: a
/// blob the outbox no longer holds is forgotten after it.
const UPLOAD_WAIT_KEPT: Duration = Duration::from_secs(3600);

/// When the next instance-state and usage reports are due.
struct Due {
    state: Instant,
    usage: Instant,
}

impl IngestLoop {
    async fn run(mut self) {
        let ps = proxy_settings();
        let interval = Duration::from_millis(ps.edge_ship_interval_ms.max(50));
        let state_every = Duration::from_secs(ps.edge_state_interval_secs.max(1));
        let usage_every = Duration::from_secs(ps.edge_usage_sync_interval_secs.max(1));
        let cap = ps.edge_outbox_max_mb * 1024 * 1024;
        // On a task of its own: however many acks go stale, shipping goes on.
        let sweeper = {
            let outbox = self.outbox.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(ACK_SWEEP_EVERY);
                loop {
                    every.tick().await;
                    if let Err(e) = outbox.forget_stale_acks().await {
                        tracing::warn!("forgetting stale outbox acks failed: {e}");
                    }
                }
            })
        };
        // The first state report goes at once: admin-api learns the epoch.
        let now = Instant::now();
        let mut due = Due { state: now, usage: now };
        let mut backoff = Backoff::for_ingest();
        let mut wait = Duration::ZERO;
        let mut failing = false;
        let mut shipped_at = Instant::now();
        loop {
            tokio::select! {
                () = self.shutdown.cancelled() => break,
                () = tokio::time::sleep(wait) => {}
                // Not while backing off: a failing admin-api is not retried
                // sooner. A stream of wakes ships at most once per
                // `SHIP_NOW_SPACING`, gathering what came meanwhile.
                () = self.ship_now.notified(), if !failing => {
                    tokio::time::sleep_until((shipped_at + SHIP_NOW_SPACING).into()).await;
                }
            }
            shipped_at = Instant::now();
            if cap > 0
                && let Err(e) = self.outbox.enforce_cap(cap).await
            {
                tracing::warn!("edge outbox size cap check failed: {e}");
            }
            match self.ship_once(&mut due, state_every, usage_every).await {
                Ok(more) => {
                    backoff.reset();
                    failing = false;
                    wait = if more { Duration::ZERO } else { interval };
                }
                Err(e) => {
                    wait = backoff.fail();
                    failing = true;
                    tracing::warn!(retry_in_ms = wait.as_millis() as u64, "edge ingest failed: {e}");
                }
            }
        }
        sweeper.abort();
        // Every producer has flushed into the outbox: ship what can be shipped
        // in the time left. The rest stays on disk for the next start.
        let deadline = Instant::now() + SHUTDOWN_DRAIN;
        while Instant::now() < deadline {
            match tokio::time::timeout_at(deadline.into(), self.ship_once(&mut due, state_every, usage_every)).await {
                Ok(Ok(true)) => continue,
                Ok(Ok(false)) => {
                    // What is left can only be waiting for its blob to go up.
                    if self.outbox.pending().await.unwrap_or(0) == 0 {
                        tracing::info!("edge outbox drained at shutdown");
                    } else {
                        tracing::warn!(
                            "edge outbox drained at shutdown but for the records whose blob is still going up — they ship on the next start"
                        );
                    }
                    return;
                }
                Ok(Err(e)) => {
                    tracing::warn!("edge outbox drain at shutdown stopped — the rest ships on the next start: {e}");
                    return;
                }
                Err(_) => break,
            }
        }
        tracing::warn!("edge outbox drain at shutdown timed out — the rest ships on the next start");
    }

    /// One ingest request, when there is anything to send — and every usage
    /// interval regardless, so admin stamps a merge even for an edge holding no
    /// counter. `Ok(true)` when it
    /// carried shares (more may be waiting); an error — including an answer
    /// asking to retry a share for a transient failure — backs off, while a
    /// share asked to carry bodies admin-api lacks goes again at once.
    async fn ship_once(&mut self, due: &mut Due, state_every: Duration, usage_every: Duration) -> Result<bool, anyhow::Error> {
        while let Ok(event) = self.health_event_rx.try_recv() {
            self.one_shots.push(event);
        }
        let now = Instant::now();
        // Early only for an event no answered request carried yet: one whose
        // apply keeps failing is restated at the state interval, not every ship.
        let state_due = now >= due.state || self.one_shots.next_id > self.one_shots.answered_carry;
        let usage_due = now >= due.usage;

        let instance_state = if state_due {
            let pending_audit = self.pending.count().await;
            Some(self.instance_state(pending_audit))
        } else {
            None
        };
        let answered_up_to = self.one_shots.next_id;
        let usage = if usage_due {
            for UsageCounterReport { key, cumulative } in self.usage.drain_report(streamscope_core::usage::now_ms()) {
                let slot = self.unanswered_usage.entry(key).or_insert(0);
                *slot = (*slot).max(cumulative);
            }
            hold_usage_to_its_cap(&mut self.unanswered_usage);
            // Sent even when empty: admin stamps every merge, and two stamps
            // after a moment are how a caller knows everything accrued before
            // it has merged.
            Some(UsageReport {
                counters: self
                    .unanswered_usage
                    .iter()
                    .map(|(key, cumulative)| UsageCounterReport { key: key.clone(), cumulative: *cumulative })
                    .collect(),
            })
        } else {
            None
        };
        // The state and the usage restate everything unanswered, so they are
        // measured first and the shares get what the request has left.
        let mut request = IngestRequest { instance: self.instance, process_epoch: self.epoch, shares: Vec::new(), instance_state, usage };
        let fixed = serde_json::to_vec(&request).map(|v| v.len()).unwrap_or(INGEST_REQUEST_MAX_BYTES);
        let budget = INGEST_REQUEST_MAX_BYTES.saturating_sub(fixed + INGEST_ENVELOPE_RESERVE_BYTES);
        let uploaded = self.settle_upload().await;
        let held = Uploads {
            held: self
                .upload
                .iter()
                .map(|(key, _)| key.clone())
                .chain(self.upload_waits.iter().filter(|(_, (until, _))| *until > now).map(|(key, _)| key.clone()))
                .collect(),
            may_start: self.upload.is_none(),
        };
        let (uploads, pending): (Vec<_>, Vec<_>) =
            self.outbox.assemble(budget, &held).await?.into_iter().partition(|p| p.upload().is_some());
        for share in uploads {
            self.start_upload(share);
        }
        if pending.is_empty() && request.instance_state.is_none() && request.usage.is_none() {
            return Ok(uploaded);
        }
        request.shares = pending.iter().map(|p| p.share.clone()).collect();
        // A request's first share may pass the budget (it always carries one
        // record); if it leaves no room for the state and usage, they wait for
        // the next request — both restate everything unanswered.
        let shares_size: usize = request.shares.iter().map(|s| serde_json::to_vec(s).map_or(0, |v| v.len())).sum();
        if fixed + shares_size + INGEST_ENVELOPE_RESERVE_BYTES > INGEST_REQUEST_MAX_BYTES {
            request.instance_state = None;
            request.usage = None;
        }

        for share in &pending {
            self.proxy_stats.record_content_shipped(share.content_weight());
        }
        let answer = self.exchange(&request, fixed).await?;
        if answer.shares.len() != pending.len() {
            anyhow::bail!("admin-api answered {} shares for {} sent", answer.shares.len(), pending.len());
        }
        let mut retried = 0;
        for (share, outcome) in pending.iter().zip(&answer.shares) {
            let applied = self.outbox.apply(share, outcome).await;
            if let Err(e) = &applied {
                tracing::warn!(tenant = %share.share.tenant, "applying an ingest outcome to the outbox failed: {e}");
            }
            if backs_off(outcome, &applied) {
                retried += 1;
            }
        }
        if request.instance_state.is_some() {
            if answer.one_shots_settled {
                self.one_shots.answered(answered_up_to);
            }
            self.one_shots.answered_carry = answered_up_to;
            due.state = now + state_every;
        }
        if request.usage.is_some() {
            // A counter is answered for when admin names it — merged (with its
            // fleet total) or settled; the rest did not merge this time, or the
            // report was not read or came from a stale epoch: restated.
            match answer.usage {
                Some(sync) => {
                    for t in sync.totals {
                        if let Some(sent) = self.unanswered_usage.remove(&t.key) {
                            self.usage.answered(&t.key, sent, Some(t.total));
                        }
                    }
                    for key in sync.settled {
                        if let Some(sent) = self.unanswered_usage.remove(&key) {
                            self.usage.answered(&key, sent, None);
                        }
                    }
                }
                None => {
                    if !self.unanswered_usage.is_empty() {
                        tracing::warn!(
                            "admin-api did not merge this usage report — restated next interval (if it persists: an unreadable report, or another process sharing this data directory)"
                        );
                    }
                }
            }
            due.usage = now + usage_every;
        }
        if retried > 0 {
            anyhow::bail!("admin-api asked to retry {retried} of {} shares", pending.len());
        }
        Ok(!pending.is_empty() || uploaded)
    }

    /// Send `share`'s blob up on a task of its own, unless one already is.
    fn start_upload(&mut self, mut share: PendingShare) {
        let Some(key) = share.upload_key() else { return };
        if self.upload.is_some() {
            return;
        }
        let (client, base, token, ship_now, stats) =
            (self.client.clone(), self.base.clone(), self.token.clone(), self.ship_now.clone(), self.proxy_stats.clone());
        let task = tokio::spawn(async move {
            let outcome = upload(&client, &base, &token, &stats, &mut share).await;
            ship_now.notify_one();
            (share, outcome)
        });
        self.upload = Some((key, task));
    }

    /// Apply a finished upload's outcome. `true` when its blob is settled —
    /// stored, or dropped — so the records that need it may go; a failure
    /// waits out that blob's own backoff.
    async fn settle_upload(&mut self) -> bool {
        let now = Instant::now();
        self.upload_waits.retain(|_, (until, _)| *until + UPLOAD_WAIT_KEPT > now);
        let Some((key, task)) = self.upload.take_if(|(_, task)| task.is_finished()) else { return false };
        let failed = match task.await {
            Ok((share, Ok(outcome))) => self.outbox.apply(&share, &outcome).await.err(),
            Ok((_, Err(e))) => Some(e),
            Err(e) => Some(anyhow::anyhow!("the upload task ended: {e}")),
        };
        let Some(e) = failed else {
            self.upload_waits.remove(&key);
            return true;
        };
        let (until, backoff) = self.upload_waits.entry(key.clone()).or_insert_with(|| (now, Backoff::for_ingest()));
        let wait = backoff.fail();
        *until = now + wait;
        tracing::warn!(retry_in_ms = wait.as_millis() as u64, tenant = %key.0, hash = %key.2, "edge blob upload failed: {e}");
        false
    }

    /// This instance's state now, every stated part in full.
    fn instance_state(&mut self, pending_audit: u64) -> InstanceState {
        self.seq += 1;
        let mut stats = self.proxy_stats.snapshot();
        stats.cache = self.response_cache.stats();
        stats.pending_audit_count = pending_audit;
        let stats = Some(reported_stats(stats));
        let core = streamscope_core::settings::core_settings();
        let proxy = proxy_settings();
        let mut effective = core.effective_values();
        effective.extend(proxy.effective_values());
        let mut loaded_overrides = core.loaded_overrides.clone();
        loaded_overrides.extend(proxy.loaded_overrides.clone());
        InstanceState {
            seq: self.seq,
            stats,
            runtime: Some(EdgeRuntimeReport { effective, loaded_overrides }),
            endpoints: EndpointBeat {
                load: streamscope_core::proxy::qos_metrics::load_report(&self.dispatch_gate, &self.tenant_registry.load()),
                states: self.circuit_breaker.endpoint_states(streamscope_core::proxy::health::ROUTES_TO_WINDOW),
            },
            health: self.one_shots.health.clone(),
            model_missing: self.one_shots.model_missing.clone(),
        }
    }

    async fn exchange(&self, request: &IngestRequest, size_hint: usize) -> Result<IngestResponse, anyhow::Error> {
        let body = serde_json::to_vec(request)?;
        let timeout = transfer_timeout(proxy_settings().edge_request_timeout, body.len().max(size_hint));
        let resp = self
            .client
            .post(&self.url)
            .bearer_auth(&self.token)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .timeout(timeout)
            .body(body)
            .send()
            .await?;
        let status = resp.status();
        // An answer is one outcome per share and the usage totals: small.
        let body = streamscope_core::http_body::read_body_capped(resp, 16 * 1024 * 1024).await?;
        if !status.is_success() {
            anyhow::bail!("ingest answered {status}");
        }
        Ok(serde_json::from_slice(&body)?)
    }
}


/// The longest media type sent as a blob's `Content-Type`.
const UPLOAD_MEDIA_TYPE_MAX_BYTES: usize = 255;

/// The `Content-Type` a blob goes up with. Its media type comes from a
/// client's request: one that is not a short, printable-ASCII header value
/// goes up as plain bytes, rather than being refused (and the blob dropped)
/// or stalling on a request head admin-api will not read.
fn upload_media_type(media_type: &str) -> reqwest::header::HeaderValue {
    Some(media_type)
        .filter(|m| !m.is_empty() && m.len() <= UPLOAD_MEDIA_TYPE_MAX_BYTES && m.bytes().all(|b| (0x20..0x7f).contains(&b)))
        .and_then(|m| reqwest::header::HeaderValue::from_str(m).ok())
        .unwrap_or(reqwest::header::HeaderValue::from_static("application/octet-stream"))
}

/// Send a blob up raw, by itself, and read admin-api's answer as the outcome
/// of the content-only share that carried it (the blob is taken out of it).
/// An answer that a resend would get again (refused for its data, too large,
/// a tenant gone) settles it; anything else is an error, retried after the
/// backoff.
async fn upload(
    client: &reqwest::Client,
    base: &str,
    token: &str,
    stats: &crate::stats::ProxyStats,
    share: &mut PendingShare,
) -> Result<ShareOutcome, anyhow::Error> {
    let Some(blob) = share.take_upload() else {
        anyhow::bail!("not a blob upload");
    };
    let url = format!("{base}{}", streamscope_edge_api::ingest::blob_path(share.share.tenant, &blob.blob_ref()));
    let media_type = upload_media_type(&blob.media_type);
    // Decoded in place, off the async workers: a blob may be up to the
    // platform's cap. The encoded copy goes as soon as it is decoded.
    let data = tokio::task::block_in_place(|| base64::engine::general_purpose::STANDARD.decode(&blob.data_base64))?;
    drop(blob);
    let timeout = transfer_timeout(proxy_settings().edge_request_timeout, data.len());
    // It goes up raw: its decoded bytes.
    stats.record_content_shipped((1, data.len() as u64));
    let resp = client
        .put(&url)
        .bearer_auth(token)
        .header(reqwest::header::CONTENT_TYPE, media_type)
        .timeout(timeout)
        .body(data)
        .send()
        .await?;
    let status = resp.status();
    // Read for the log only: an answer whose body cannot be read still
    // settles by its status.
    let body = streamscope_core::http_body::read_body_capped(resp, 64 * 1024).await.unwrap_or_default();
    if status.is_success() {
        return Ok(ShareOutcome::Committed);
    }
    match upload_refusal(status, &body) {
        Some(Refusal::TenantGone) => Ok(ShareOutcome::TenantDeleted),
        Some(Refusal::Settled) => {
            Ok(ShareOutcome::Rejected { rows: Vec::new(), reason: format!("{status}: {}", String::from_utf8_lossy(&body)) })
        }
        None => anyhow::bail!("blob upload answered {status}"),
    }
}

/// Whether a share's answer, as the outbox applied it, backs the ingest loop
/// off. A share whose acks admin-api's ask made the outbox forget goes again
/// at once, carrying those bodies: that is no failure. Any other retry —
/// transient, unapplied, or one the same share would get again — is.
fn backs_off(outcome: &ShareOutcome, applied: &Result<Applied, anyhow::Error>) -> bool {
    matches!(outcome, ShareOutcome::Retry { .. }) && !matches!(applied, Ok(Applied::Asked))
}

/// An upload answer a resend would get again.
enum Refusal {
    TenantGone,
    Settled,
}

/// Whether an upload's refusal settles the blob: only admin-api's own answer,
/// named by its error code, does. The same status from anything in front of
/// it (an ingress' body-size limit, a missing route) is retried, never taken
/// as a reason to drop the blob.
fn upload_refusal(status: reqwest::StatusCode, body: &[u8]) -> Option<Refusal> {
    let code = serde_json::from_slice::<serde_json::Value>(body).ok()?;
    let code = code.pointer("/error/code")?.as_str()?;
    match (status, code) {
        (reqwest::StatusCode::GONE, "tenant_not_found") => Some(Refusal::TenantGone),
        (reqwest::StatusCode::BAD_REQUEST, "validation_failed")
        | (reqwest::StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large")
        | (reqwest::StatusCode::UNPROCESSABLE_ENTITY, "edge_blob_refused") => Some(Refusal::Settled),
        _ => None,
    }
}

/// The replica's stats as the wire states them. Destructured whole on both
/// sides, so a field added to either is a compile error rather than a value
/// never reported; a gauge that went negative, or a CPU reading that is not a
/// number, is reported as 0 (JSON has no NaN, and admin would drop the state).
fn reported_stats(s: crate::stats::StatsSnapshot) -> EdgeProxyStats {
    let crate::stats::StatsSnapshot {
        requests_total,
        errors_total,
        active_streams,
        cpu_percent,
        memory_rss_bytes,
        memory_limit_bytes,
        cores,
        uptime_secs,
        http2_requests,
        http11_requests,
        overhead_buckets,
        overhead_sum_us,
        overhead_count,
        pending_audit_count,
        cache,
    } = s;
    let streamscope_core::proxy::response_cache::CacheStats {
        entries,
        bytes,
        max_bytes,
        semantic_vectors,
        semantic_buckets,
        stores_total,
        evictions_total,
        expired_total,
    } = cache;
    // Through its shortest decimal form, so 12.3 is stored as 12.3 and not as
    // the f32's exact widening.
    let cpu_percent = cpu_percent.to_string().parse::<f64>().ok().filter(|v| v.is_finite()).unwrap_or(0.0);
    EdgeProxyStats {
        requests_total,
        errors_total,
        active_streams: u64::try_from(active_streams).unwrap_or(0),
        cpu_percent,
        memory_rss_bytes,
        memory_limit_bytes,
        cores: u32::from(cores),
        uptime_secs,
        http2_requests,
        http11_requests,
        overhead_buckets: overhead_buckets.to_vec(),
        overhead_sum_us,
        overhead_count,
        pending_audit_count,
        cache: streamscope_edge_api::ingest::EdgeCacheStats {
            entries,
            bytes,
            max_bytes,
            semantic_vectors,
            semantic_buckets,
            stores_total,
            evictions_total,
            expired_total,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One tenant whose write the outbox refuses loses its own records only:
    /// every other tenant's in the same batch land, and the loss is counted
    /// for exactly the refused records.
    #[tokio::test]
    async fn a_tenant_whose_write_fails_takes_no_other_tenants_records_with_it() {
        use sqlx::{Connection, Executor};
        let dir = std::env::temp_dir().join(format!("streamscope_sink_{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        let outbox = Arc::new(OutboxV2::open(dir.to_str().unwrap()).await.unwrap());
        let file = dir.join(crate::outbox_v2::store_file());
        let refused = uuid::Uuid::new_v4();
        let mut conn = sqlx::SqliteConnection::connect(&format!("sqlite://{}", file.display())).await.unwrap();
        conn.execute(sqlx::AssertSqlSafe(format!(
            "CREATE TRIGGER refuse BEFORE INSERT ON records WHEN NEW.tenant_id = '{refused}' \
             BEGIN SELECT RAISE(ABORT, 'refused'); END"
        )))
        .await
        .unwrap();
        drop(conn);
        let event = |tenant: uuid::Uuid, seq: i64| {
            Record::McpSseEvent(Box::new(McpSseEventRecord {
                tenant_id: tenant,
                user_id: uuid::Uuid::nil(),
                mcp_session_id: "s".into(),
                virtual_server_id: None,
                event_id: format!("e{seq}"),
                sequence: seq,
                event_data: b"x".to_vec(),
                created_at: chrono::Utc::now(),
            }))
        };
        // Eight other tenants: whatever order the batch is written in, most
        // are written after the refused one.
        let others: Vec<uuid::Uuid> = (0..8).map(|_| uuid::Uuid::new_v4()).collect();
        let batch = others.iter().map(|t| event(*t, 1)).chain([event(refused, 1), event(refused, 2)]);
        let sink = OutboxSink::new(outbox.clone());
        let mut held = 0;
        let lost = sink.enqueue_plain(batch, |_| held += 1).await;
        assert_eq!((held, lost), (8, 2), "the refused tenant's two records lost, every other held");
        assert_eq!(outbox.pending().await.unwrap(), 8);
        drop(outbox);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// What the edge carries for a turn is every body the record names
    /// (`Record::content_keys`, which admin-api checks), each under the key
    /// the record names it by — so a turn with all its bodies names none
    /// unavailable.
    #[test]
    fn a_turn_carries_every_body_its_record_names() {
        let call: streamscope_core::api::domain_request::DomainMediaCall = serde_json::from_value(serde_json::json!({
            "endpoint": "image_edit",
            "model": "m",
            "input": [{"type": "blob_ref", "content_hash": "up", "media_type": "image/png"}],
            "output": [
                {"type": "blob_ref", "content_hash": "out", "media_type": "image/png", "blob_type": "response_body"},
                {"type": "blob_ref", "content_hash": "out2", "media_type": "image/png", "blob_type": "response_body"},
            ],
        }))
        .unwrap();
        let mut record = AuditRecord {
            link_hashes: Some(vec!["h1".into(), "h2".into()]),
            request_messages_json: Some(vec![r#"{"role":"user","content":"a"}"#.into(), r#"{"role":"user","content":"b"}"#.into()]),
            tools_available_hash: Some("tools".into()),
            tool_definitions_to_buffer: vec![streamscope_core::audit::ToolDefinitionBlobEntry {
                hash: "tools".into(),
                tenant_id: String::new(),
                definition_json: "[]".into(),
                content_size: 2,
            }],
            system_prompt: Some("be brief".into()),
            media_call: Some(call),
            media_blob_data: Some(bytes::Bytes::from_static(b"up")),
            media_response_blob_data: Some(bytes::Bytes::from_static(b"out")),
            message_blobs: vec![streamscope_core::audit::MessageBlobEntry {
                content_hash: "out2".into(),
                blob_type: BlobType::ResponseBody,
                media_type: "image/png".into(),
                data: bytes::Bytes::from_static(b"out2"),
                size_bytes: 4,
            }, streamscope_core::audit::MessageBlobEntry {
                // Stripped: no bytes to store, so never named.
                content_hash: "stripped".into(),
                blob_type: BlobType::ChatImage,
                media_type: "image/png".into(),
                data: bytes::Bytes::new(),
                size_bytes: 0,
            }],
            ..Default::default()
        };
        let mut content = Content::default();
        take_content(&mut record, &mut content);
        let prompt_hash = streamscope_core::audit::system_prompt_hash("be brief");
        assert_eq!(record.system_prompt, None, "the prompt travels as content");
        assert_eq!(record.system_prompt_hash.as_deref(), Some(prompt_hash.as_str()));
        assert_eq!(content.system_prompts.len(), 1);
        assert_eq!((content.system_prompts[0].prompt.as_str(), content.system_prompts[0].content_size), ("be brief", 8));
        assert_eq!(record.buffered_blobs, vec![BlobRef { content_hash: "out2".into(), blob_type: BlobType::ResponseBody }]);
        let carried: std::collections::HashSet<_> = content.keys().collect();
        let named = Record::LlmAudit(Box::new(record)).content_keys();
        assert_eq!(named.len(), 7, "{named:?}");
        for key in &named {
            assert!(carried.contains(key), "{key:?} is named but not carried");
        }
        // No prompt, or an empty one: nothing is carried or named.
        let mut empty = AuditRecord { system_prompt: Some(String::new()), ..Default::default() };
        let mut content = Content::default();
        take_content(&mut empty, &mut content);
        assert!(content.is_empty());
        assert_eq!(empty.system_prompt_hash, None);
    }

    /// A message is stored, and its turn names it, under the hash of the
    /// stored bytes: two messages the session-link hash cannot tell apart — a
    /// teammate's `<system-reminder>`, their `name` — are two bodies, so one
    /// user's message is never read back for another's turn.
    #[test]
    fn a_message_is_named_by_the_hash_of_what_is_stored() {
        let ship = |link: &str, messages: &[serde_json::Value]| {
            let mut record = AuditRecord {
                link_hashes: Some(vec![link.to_string(); messages.len()]),
                request_messages_json: Some(messages.iter().map(|m| m.to_string()).collect()),
                ..Default::default()
            };
            let mut content = Content::default();
            take_content(&mut record, &mut content);
            (record.message_hashes.unwrap_or_default(), content.messages)
        };
        let prompt = |reminder: &str| serde_json::json!({"role": "user", "content": [
            {"type": "text", "text": format!("<system-reminder>{reminder}</system-reminder>")},
            {"type": "text", "text": "commit"},
        ]});
        // One link hash (the reminder left out), two different messages.
        let (alice, alice_bodies) = ship("same-link", &[prompt("alice@example.com")]);
        let (bob, bob_bodies) = ship("same-link", &[prompt("bob@example.com")]);
        assert_ne!(alice, bob, "two different messages are two stored bodies");
        for (keys, bodies) in [(&alice, &alice_bodies), (&bob, &bob_bodies)] {
            let stored = serde_json::to_string(&bodies[0].message).unwrap();
            assert_eq!(keys[0], hex::encode(<sha2::Sha256 as sha2::Digest>::digest(stored.as_bytes())), "the key is the hash of the stored bytes");
            assert_eq!(bodies[0].hash, keys[0], "the body travels under the key its turn names");
            assert_eq!(bodies[0].content_size as usize, stored.len());
        }
        // A field the link hash does not read is part of the message, too.
        let (named_a, _) = ship("l", &[serde_json::json!({"role": "user", "name": "alice", "content": "hi"})]);
        let (named_b, _) = ship("l", &[serde_json::json!({"role": "user", "name": "bob", "content": "hi"})]);
        assert_ne!(named_a, named_b);
        // The body is stored exactly as sent — a member named like a cache
        // breakpoint in a tool's arguments included.
        let call = serde_json::json!({"role": "model", "parts": [{"functionCall": {"name": "fetch", "args": {"cache_control": "no-store"}}}]});
        let (_, call_bodies) = ship("l", std::slice::from_ref(&call));
        assert_eq!(call_bodies[0].message, call);
        // Positive control: the same message, sent twice, is one body.
        let plain = serde_json::json!({"role": "user", "content": [{"type": "text", "text": "hi"}]});
        let (p1, _) = ship("l", std::slice::from_ref(&plain));
        let (p2, _) = ship("l", std::slice::from_ref(&plain));
        assert_eq!(p1, p2);
        // A message with no body to ship names a key no stored body has.
        let mut record = AuditRecord { link_hashes: Some(vec!["abc".into()]), ..Default::default() };
        let mut content = Content::default();
        take_content(&mut record, &mut content);
        assert_eq!(record.message_hashes, Some(vec!["unstored-abc".to_string()]));
        assert!(content.messages.is_empty());
    }

    #[tokio::test]
    async fn a_record_moving_on_during_a_count_is_counted() {
        // One record moves one stage on (0 the stream tasks, 1 the channels, 2
        // the outbox) right after the count's `after`-th read, whichever stage
        // that read was: read in the order a record moves, some read still
        // counts it, between any two of the three reads.
        for from in 0..2u8 {
            for after in 1..=2u8 {
                let at = std::cell::Cell::new(from);
                let reads = std::cell::Cell::new(0u8);
                let read = |stage: u8| {
                    let seen = u64::from(at.get() == stage);
                    reads.set(reads.get() + 1);
                    if reads.get() == after && at.get() < 2 {
                        at.set(at.get() + 1);
                    }
                    seen
                };
                let counted: Result<u64, ()> =
                    count_upstream_first(|| read(0), || read(1), || async { Ok(read(2)) }).await;
                assert!(
                    counted.expect("counted") >= 1,
                    "a record moving on from stage {from} after read {after} was counted by no read"
                );
            }
        }
    }

    #[test]
    fn only_admins_own_refusal_settles_a_blob() {
        use reqwest::StatusCode as S;
        let read = |status, body: &[u8]| match upload_refusal(status, body) {
            Some(Refusal::TenantGone) => "tenant gone",
            Some(Refusal::Settled) => "settled",
            None => "retried",
        };
        let answer = |code: &str| format!(r#"{{"error":{{"message":"m","type":"invalid_request","code":"{code}"}}}}"#).into_bytes();
        assert_eq!(read(S::GONE, &answer("tenant_not_found")), "tenant gone");
        assert_eq!(read(S::BAD_REQUEST, &answer("validation_failed")), "settled");
        assert_eq!(read(S::PAYLOAD_TOO_LARGE, &answer("payload_too_large")), "settled");
        assert_eq!(read(S::UNPROCESSABLE_ENTITY, &answer("edge_blob_refused")), "settled");
        // The same status from an ingress, or a code that does not go with it: retried.
        assert_eq!(read(S::PAYLOAD_TOO_LARGE, b"<html>413 Request Entity Too Large</html>"), "retried");
        assert_eq!(read(S::BAD_REQUEST, b""), "retried");
        assert_eq!(read(S::PAYLOAD_TOO_LARGE, &answer("edge_blob_refused")), "retried");
        assert_eq!(read(S::NOT_FOUND, &answer("tenant_not_found")), "retried");
        assert_eq!(read(S::INTERNAL_SERVER_ERROR, &answer("internal_error")), "retried");
    }

    #[test]
    fn a_blob_goes_up_under_its_media_type_only_when_admin_can_read_it_back() {
        let sent = |m: &str| upload_media_type(m).to_str().unwrap().to_string();
        assert_eq!(sent("image/png"), "image/png");
        assert_eq!(sent("image/png; name=\"a b\""), "image/png; name=\"a b\"");
        let longest = format!("image/{}", "x".repeat(UPLOAD_MEDIA_TYPE_MAX_BYTES - 6));
        assert_eq!(sent(&longest), longest);
        for unreadable in [
            String::new(),
            format!("{longest}x"),
            "image/png;name=é".to_string(),
            "image/png\u{7f}".to_string(),
            "image/png\n".to_string(),
        ] {
            assert_eq!(sent(&unreadable), "application/octet-stream", "{unreadable:?}");
        }
    }

    #[test]
    fn one_shot_events_are_numbered_in_order_and_kept_until_answered() {
        let mut o = OneShots::default();
        let missing = |m: &str| {
            EdgeHealthEvent::ModelMissing(streamscope_core::proxy::health::EndpointModelMissing {
                tenant_id: uuid::Uuid::nil(),
                endpoint_id: uuid::Uuid::nil(),
                model: m.into(),
                url: "http://e".into(),
            })
        };
        o.push(missing("a"));
        o.push(missing("b"));
        let carried = o.next_id;
        o.push(missing("c"));
        assert_eq!(o.model_missing.iter().map(|e| e.id).collect::<Vec<_>>(), vec![1, 2, 3]);
        o.answered(carried);
        assert_eq!(o.model_missing.iter().map(|e| e.id).collect::<Vec<_>>(), vec![3], "a later event stays");
        assert_eq!(o.health.len() + o.model_missing.len(), 1);
    }

    #[test]
    fn one_shot_events_are_held_to_their_cap_dropping_the_oldest() {
        let mut o = OneShots::default();
        let missing = || {
            EdgeHealthEvent::ModelMissing(streamscope_core::proxy::health::EndpointModelMissing {
                tenant_id: uuid::Uuid::nil(),
                endpoint_id: uuid::Uuid::nil(),
                model: "m".into(),
                url: "http://e".into(),
            })
        };
        for _ in 0..ONE_SHOTS_MAX {
            o.push(missing());
        }
        assert_eq!(o.model_missing.len(), ONE_SHOTS_MAX, "at the cap: all kept");
        assert_eq!(o.model_missing[0].id, 1);
        o.push(missing());
        assert_eq!(o.model_missing.len(), ONE_SHOTS_MAX, "past it: held to it");
        assert_eq!(o.model_missing[0].id, 2, "the oldest went");
        assert_eq!(o.model_missing.last().map(|e| e.id), Some(ONE_SHOTS_MAX as u64 + 1));
    }

    #[test]
    fn unanswered_usage_is_held_to_its_cap_dropping_the_oldest_windows() {
        use streamscope_core::usage::{UsageMetric, UsageScopeKind, UsageWindowKind};
        let key = |w: u64| UsageCounterKey {
            tenant_id: uuid::Uuid::nil(),
            scope_kind: UsageScopeKind::Tenant,
            scope_id: uuid::Uuid::nil(),
            metric: UsageMetric::BudgetMicros,
            window_kind: UsageWindowKind::Minute,
            window_start_ms: w,
        };
        let mut usage: HashMap<UsageCounterKey, u64> = (0..UNANSWERED_USAGE_MAX as u64).map(|w| (key(w), 1)).collect();
        hold_usage_to_its_cap(&mut usage);
        assert_eq!(usage.len(), UNANSWERED_USAGE_MAX, "at the cap: all kept");
        usage.insert(key(UNANSWERED_USAGE_MAX as u64), 1);
        usage.insert(key(UNANSWERED_USAGE_MAX as u64 + 1), 1);
        hold_usage_to_its_cap(&mut usage);
        assert_eq!(usage.len(), UNANSWERED_USAGE_MAX);
        assert!(!usage.contains_key(&key(0)) && !usage.contains_key(&key(1)), "the oldest windows went");
        assert!(usage.contains_key(&key(UNANSWERED_USAGE_MAX as u64 + 1)), "the newest stays");
    }

    #[test]
    fn an_mcp_user_event_reaches_the_bus_of_its_user_and_virtual_server() {
        let bus = crate::mcp::event_bus::PerUserEventBus::new(8);
        let (t, u, vs) = (uuid::Uuid::from_u128(1), uuid::Uuid::from_u128(2), uuid::Uuid::from_u128(3));
        let mut rx = bus.subscribe(t, u, vs);
        let event = |body: serde_json::Value| Event { id: 1, tenant: t, body };
        dispatch_event(&bus, &event(serde_json::json!({
            "type": "mcp_user_event", "tenant_id": t, "user_id": u, "method": "notifications/tools/list_changed",
            "mcp_session_id": "s1", "virtual_server_id": vs,
        })));
        let got = rx.try_recv().expect("published");
        let text = String::from_utf8(got.0.to_vec()).unwrap();
        assert!(text.starts_with("event: notification\ndata: "));
        assert!(text.contains("notifications/tools/list_changed") && text.contains("s1"));
        // An event of another kind, or one naming no virtual server, is not published.
        dispatch_event(&bus, &event(serde_json::json!({ "type": "other" })));
        dispatch_event(&bus, &event(serde_json::json!({
            "type": "mcp_user_event", "tenant_id": t, "user_id": u, "method": "m",
        })));
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn backoff_doubles_to_its_cap_and_resets() {
        let mut b = Backoff::new(Duration::from_secs(8));
        let first = b.fail();
        let second = b.fail();
        assert!(second > first.mul_f64(1.5), "doubles (jitter is at most a quarter)");
        for _ in 0..20 {
            b.fail();
        }
        let max = Duration::from_secs(8);
        assert!(b.fail() >= max, "reaches its own cap");
        assert!(b.fail() <= max + max / 4);
        assert!(Backoff::for_sync().max <= LONGEST_WAIT, "the sync loop's never passes the live window's share");
        b.reset();
        assert!(b.fail() <= Backoff::initial() + Backoff::initial() / 4);
    }

    #[test]
    fn only_a_retry_that_forgot_an_ack_goes_again_without_backing_off() {
        let asked = ShareOutcome::Retry { missing: vec![streamscope_edge_api::ingest::ContentKey::Message { hash: "m".into() }] };
        assert!(!backs_off(&asked, &Ok(Applied::Asked)), "the bodies it forgot go now");
        assert!(backs_off(&asked, &Ok(Applied::Kept)), "nothing forgotten: the same share would be asked again");
        assert!(backs_off(&asked, &Err(anyhow::anyhow!("disk full"))), "an ask not recorded is named again");
        assert!(backs_off(&ShareOutcome::Retry { missing: vec![] }, &Ok(Applied::Kept)), "a transient retry");
        assert!(!backs_off(&ShareOutcome::Committed, &Ok(Applied::Deleted)));
    }
}
