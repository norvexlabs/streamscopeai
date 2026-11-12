//! Mandatory audit pipeline — every proxied request produces an [`AuditRecord`].
//!
//! Records flow through an MPSC channel to a background writer task that batches
//! them before forwarding. The channel has bounded capacity; when full, request
//! handlers block (backpressure) rather than drop records. This guarantees a
//! complete audit trail at the cost of latency under extreme load.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::api::sse::ApiVersion;
use crate::settings::core_settings;

/// Serde default for a conversion multiplier: no conversion.
fn one() -> f64 {
    1.0
}

/// Process-lifetime LLM audit-emission accounting, surfaced by the proxy's
/// gated `/debug/buffered-audit` endpoint. Each counter marks one stage of
/// the emission pipeline; once traffic stops and the channel drains, the
/// stage invariants are `stream_tasks_spawned == stream_tasks_finalized` and
/// `channel_sent == buffered (proxy-side) + writer_dropped` (`channel_lost`
/// counts records the channel REJECTED — disjoint from `channel_sent`).
/// A persistent gap localizes which stage lost a record — the audit trail is
/// mandatory, so any nonzero loss counter is a defect signal.
pub struct EmissionStats {
    /// Streaming audit tasks spawned (`spawn_audit_task` calls).
    pub stream_tasks_spawned: AtomicU64,
    /// Streaming audit tasks that reached `finalize_audit`.
    pub stream_tasks_finalized: AtomicU64,
    /// Records accepted by the audit MPSC channel (`send_audit` succeeded).
    pub channel_sent: AtomicU64,
    /// Records lost because the audit channel was closed (`send_audit` failed).
    pub channel_lost: AtomicU64,
    /// Records dropped because the forwarder could not store them, counted by
    /// the writer task alone: the records a forwarder answers it lost, or a
    /// whole batch whose forwarder errored.
    pub writer_dropped: AtomicU64,
}

impl EmissionStats {
    pub fn snapshot(&self) -> serde_json::Value {
        serde_json::json!({
            "stream_tasks_spawned": self.stream_tasks_spawned.load(Ordering::Relaxed),
            "stream_tasks_finalized": self.stream_tasks_finalized.load(Ordering::Relaxed),
            "channel_sent": self.channel_sent.load(Ordering::Relaxed),
            "channel_lost": self.channel_lost.load(Ordering::Relaxed),
            "writer_dropped": self.writer_dropped.load(Ordering::Relaxed),
        })
    }
}

/// The sending half of an audit channel (LLM, MCP, A2A, web or MCP-SSE). Each record
/// it hands to the channel counts as pending ([`AuditSender::pending_count`]) until the
/// writer holding the [`AuditReceiver`] has forwarded it, stored or not — so a
/// record taken off the channel is still counted while its batch is filled and
/// forwarded, and the proxy's `outbox_pending` never misses one between two
/// stages.
pub struct AuditSender<T> {
    tx: tokio::sync::mpsc::Sender<T>,
    pending: std::sync::Arc<AtomicU64>,
}

impl<T> Clone for AuditSender<T> {
    fn clone(&self) -> Self {
        Self { tx: self.tx.clone(), pending: self.pending.clone() }
    }
}

impl<T> AuditSender<T> {
    /// Send without waiting; a refused record is not counted.
    pub fn try_send(&self, record: T) -> Result<(), tokio::sync::mpsc::error::TrySendError<T>> {
        let permit = match self.tx.try_reserve() {
            Ok(permit) => permit,
            Err(tokio::sync::mpsc::error::TrySendError::Full(())) => {
                return Err(tokio::sync::mpsc::error::TrySendError::Full(record));
            }
            Err(tokio::sync::mpsc::error::TrySendError::Closed(())) => {
                return Err(tokio::sync::mpsc::error::TrySendError::Closed(record));
            }
        };
        self.pending.fetch_add(1, Ordering::Release);
        permit.send(record);
        Ok(())
    }

    /// Send, waiting for capacity. Counted only once the channel takes it, so
    /// a send cancelled while it waits leaves nothing counted.
    pub async fn send(&self, record: T) -> Result<(), tokio::sync::mpsc::error::SendError<T>> {
        let Ok(permit) = self.tx.reserve().await else {
            return Err(tokio::sync::mpsc::error::SendError(record));
        };
        self.pending.fetch_add(1, Ordering::Release);
        permit.send(record);
        Ok(())
    }

    /// The count of records this channel took and its writer has not yet
    /// forwarded, as a handle that does not keep the channel open.
    pub fn pending_count(&self) -> PendingCount {
        PendingCount(self.pending.clone())
    }
}

/// An audit channel's pending count, held apart from its sender
/// ([`AuditSender::pending_count`]).
#[derive(Clone)]
pub struct PendingCount(std::sync::Arc<AtomicU64>);

impl PendingCount {
    pub fn get(&self) -> u64 {
        self.0.load(Ordering::Acquire)
    }
}

/// The receiving half of an audit channel, held by its writer. A record it
/// yields stays counted until the writer calls [`AuditReceiver::forwarded`].
pub struct AuditReceiver<T> {
    rx: tokio::sync::mpsc::Receiver<T>,
    pending: std::sync::Arc<AtomicU64>,
}

impl<T> AuditReceiver<T> {
    pub async fn recv(&mut self) -> Option<T> {
        self.rx.recv().await
    }

    pub fn try_recv(&mut self) -> Result<T, tokio::sync::mpsc::error::TryRecvError> {
        self.rx.try_recv()
    }

    /// `n` records taken off this channel have been forwarded (stored or not):
    /// they leave the pending count. Called after the forward returns, so a
    /// reader that sees them gone sees the forward's writes too.
    pub fn forwarded(&self, n: usize) {
        self.pending.fetch_sub(n as u64, Ordering::Release);
    }
}

/// An audit channel of `capacity` records, counted from when it takes a record
/// until its writer has forwarded it.
pub fn counted_channel<T>(capacity: usize) -> (AuditSender<T>, AuditReceiver<T>) {
    let (tx, rx) = tokio::sync::mpsc::channel(capacity);
    let pending = std::sync::Arc::new(AtomicU64::new(0));
    (AuditSender { tx, pending: pending.clone() }, AuditReceiver { rx, pending })
}

/// Global emission accounting for the LLM audit pipeline.
pub static EMISSION_STATS: EmissionStats = EmissionStats {
    stream_tasks_spawned: AtomicU64::new(0),
    stream_tasks_finalized: AtomicU64::new(0),
    channel_sent: AtomicU64::new(0),
    channel_lost: AtomicU64::new(0),
    writer_dropped: AtomicU64::new(0),
};

pub mod a2a;
pub mod badge;
pub mod blob_type;
pub mod mcp;
pub use badge::{
    AlertLevel, AuditBadge, BadgeBuilder, BlockKind, GuardrailAction, Phase,
};
pub use blob_type::{BlobRef, BlobType};
pub use mcp::McpAuditRecord;

/// Audit record — written asynchronously via MPSC channel after each request.
/// An attempt a request moved on from: refused by a server's pool, or sent to
/// one of its replicas and failed. The row names only the attempt the request
/// ENDED with, so each earlier one is recorded here, to be counted at the
/// server — and replica — where it happened.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EarlierAttempt {
    /// `None` for a target naming no server (a pass-through): its time still
    /// counts against the later attempts' latency, though no page counts it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_id: Option<uuid::Uuid>,
    /// The replica it was sent to; `None` for a refusal, which reached none.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<uuid::Uuid>,
    /// [`EarlierAttempt::REFUSED`] or [`EarlierAttempt::FAILED`].
    pub outcome: String,
    /// Why: the gate's refusal reason (`GateRefusal::as_str`), or the failure's
    /// audit error category — the same vocabulary as `error_category`, so a
    /// reader tells the server's own failure from the gateway's.
    pub reason: String,
    /// The status the failure is audited with (a failed attempt only): with
    /// the category, what tells a server's failure (5xx, 408, 429) from a
    /// client's own bad request answered 4xx.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status: Option<u16>,
    /// What the request waited at that server's pool before this attempt.
    pub wait_ms: u64,
    /// How long the attempt took, its wait included: what a later target's
    /// latency must not be charged with.
    pub elapsed_ms: u64,
}

impl EarlierAttempt {
    /// Refused by the server's pool: it reached no replica.
    pub const REFUSED: &'static str = "refused";
    /// Sent to a replica, and failed.
    pub const FAILED: &'static str = "failed";
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    pub request_id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub user_id: uuid::Uuid,
    pub tenant_id: uuid::Uuid,
    /// Workspace the request's key was minted against (the scope that
    /// allowlisted the target + billed the spend). NOT NULL in `gateway_audit`;
    /// nil UUID for pre-auth errors that never resolved a key.
    pub workspace_id: uuid::Uuid,
    pub key_id: Option<uuid::Uuid>,
    pub app_id: Option<String>,
    /// Gateway-side session id in the canonical hashed form: the client's
    /// session header run through `session_id_from_client(raw, tenant_id,
    /// user_id)`. Every `gateway_audit.session_id` producer (LLM, media, MCP,
    /// A2A, web) stores this same UUID — never the raw header — so rows
    /// correlate cross-protocol on the column.
    pub session_id: Option<uuid::Uuid>,
    pub user_agent: Option<String>,
    pub detection_method: Option<String>,

    // Forwarded end-client identity — present only for Inline AI traffic, where
    // a trusted inline key relays the gateway-resolved end client. A normal key
    // can never set these. Empty on a direct request, whose principal is the
    // key's own `user_id`. Written to `gateway_audit.client_ip/end_user/
    // end_user_groups`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub end_user: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub end_user_groups: Vec<String>,

    // Request
    pub model_requested: String,
    pub model_used: String,
    pub provider: String,
    pub api_version: ApiVersion,
    pub stream: bool,

    // Response
    pub prompt_tokens: u32,
    pub completion_tokens: u32,
    pub reasoning_tokens: Option<u32>,
    pub cache_creation_tokens: Option<u32>,
    pub cache_read_tokens: Option<u32>,
    pub finish_reason: String,
    pub native_finish_reason: Option<String>,

    // Cost. `cost` is the row's true total, in `cost_currency` — the
    // tenant's accounting currency as it was when the row was written. Spend
    // aggregates read it. `billed_units` decomposes it per pricing unit, so
    // `cost = (sum of billed_units[*].cost) + embedding_cost`.
    pub cost: f64,
    /// Currency `cost` and `embedding_cost` are expressed in.
    #[serde(default)]
    pub cost_currency: crate::pricing::Currency,
    /// What the provider charges, in the currency it quotes.
    #[serde(default)]
    pub source_cost: f64,
    /// Currency the provider quotes. Differs from `cost_currency` whenever the
    /// model is priced in something other than the tenant's ledger currency.
    #[serde(default)]
    pub source_currency: crate::pricing::Currency,
    /// Multiplier that took `source_cost` to `cost`, stamped at write time
    /// so the row stays reconcilable against the provider's invoice after the
    /// operator's conversion table moves. One when no conversion applied.
    #[serde(default = "one")]
    pub fx_rate: f64,
    /// Per-unit decomposition of `cost`. Counts are what was CHARGED — the
    /// provider's reported count less anything that partitions out of it, each
    /// of which carries its own line.
    #[serde(default, deserialize_with = "crate::pricing::deserialize_billed_units")]
    pub billed_units: crate::pricing::BilledUnits,
    /// The response cache's own embedding call, charged to the request that
    /// triggered it — a Semantic preset embeds on every exact miss, so this is
    /// non-zero on misses and on semantic hits alike.
    ///
    /// Defaulted on deserialize: the proxy's outbox survives an upgrade and
    /// ships records written by the previous binary, which carry no such
    /// field. Without the default those records fail to deserialize and lose
    /// their session upsert.
    #[serde(default)]
    pub embedding_cost: f64,
    /// Prompt tokens the embedding call consumed. Kept out of `prompt_tokens`,
    /// which describes the completion only.
    #[serde(default)]
    pub embedding_tokens: u32,
    /// Milliseconds the request waited for upstream capacity before it was
    /// dispatched, on every target it tried. Part of `latency_ttft_ms` and
    /// `latency_total_ms`: a view of the upstream itself subtracts it, or it
    /// would blame an engine for a queue in front of it. Zero on every request
    /// that never waited.
    #[serde(default)]
    pub queue_wait_ms: u64,
    /// The QoS class the request ran as, when its tenant has classes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qos_class_id: Option<uuid::Uuid>,
    pub zero_completion: bool,

    /// The response-cache policy in force for this request, or `None` when the
    /// alias binds no cache preset. Recorded rather than resolved later: a
    /// preset edit would otherwise rewrite what past requests were subject to.
    #[serde(default)]
    pub cache_mode: Option<crate::proxy::response_cache::CacheMode>,
    /// What the cache did. `None` exactly when `cache_mode` is `None`.
    #[serde(default)]
    pub cache_outcome: Option<crate::proxy::response_cache::CacheOutcome>,
    /// What the avoided upstream call would have cost. **Not** part of
    /// `cost` — this request did not spend it. Counts as money saved only
    /// when `cache_outcome` is `Hit`.
    #[serde(default)]
    pub avoided_cost: f64,

    // Timing. Both run from the moment the gateway starts forwarding — after
    // its own checks and transforms — so any hold for capacity
    // (`queue_wait_ms`) and any earlier attempt the request moved on from are
    // in them.
    pub latency_ttft_ms: u64,
    pub latency_total_ms: u64,

    // Typed audit badges — stable codes, never free-form strings. See
    // `audit::badge::AuditBadge`.
    pub badges: Vec<AuditBadge>,

    // Internal pipeline path (`fastpath` | `buffered`). Analytics-only,
    // not user-facing.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub pipeline_path: Option<String>,

    // Catch-all proxy hit metadata (only populated when the request fell to
    // the catch-all handler).
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub catchall_path: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub catchall_method: Option<String>,

    // Content logging (optional — populated when content_logging_enabled)
    /// Request messages as a `Value` tree. On the chat path this is set only
    /// when the finalize-time media-strip pass rebuilt and mutated the
    /// captured messages (blob storage on, media found); the media handler
    /// sets it directly from its parsed body. The edge buffer serialises it
    /// as the fallback when `request_messages_json` is absent.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_messages: Option<serde_json::Value>,
    /// Pre-serialised per-message JSON, aligned 1:1 with `link_hashes`,
    /// captured pre-transform — the primary form of the request messages
    /// (no `Value` tree is built on the capture path). Transient — consumed
    /// by the edge SQLite buffer, then dropped before the audit row is
    /// forwarded to admin-api. Cleared when the media-strip pass replaces it
    /// with a mutated `request_messages` tree.
    #[serde(skip)]
    pub request_messages_json: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_tools: Option<serde_json::Value>,
    /// SHA-256 hash of `request_tools` (the client-sent tool blob). Resolves
    /// to a row in the central `tool_definitions` content-addressed side table.
    /// `None` when the request had no tools.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tools_available_hash: Option<String>,
    /// SHA-256 hash of the post-policy effective tool blob (`Some` only when
    /// tool policy modified the available set; equals `tools_available_hash`
    /// when no rule fired — in which case writers may leave this `None` to
    /// avoid storing a duplicate). Resolves to `tool_definitions`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub tools_effective_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub request_params: Option<serde_json::Value>,
    /// The request's system prompt. Transient — the edge outbox moves it into
    /// its content, and the record carries only `system_prompt_hash`.
    #[serde(skip)]
    pub system_prompt: Option<String>,
    /// The system prompt's key in the central `system_prompts` content store
    /// ([`system_prompt_hash`](crate::audit::system_prompt_hash)); `None` when
    /// the request had none.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub system_prompt_hash: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub transform_diff: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub response_content: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub response_tool_calls: Option<serde_json::Value>,

    // Session detection (optional — populated when content_logging_enabled)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub conversation_session_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub turn_number: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_request_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub is_baseline: Option<bool>,
    /// The key of each message of the turn's history in the content store:
    /// the hash of the message as stored ([`crate::proxy::content::stored_message_key`]),
    /// so a stored body is only ever named by a request that sent those exact
    /// bytes. Set by the edge when the record's content is taken out for
    /// shipping, never at assembly.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub message_hashes: Option<Vec<String>>,
    /// The session-link hash of each message, aligned with `message_hashes`:
    /// what a client injects and withdraws between turns left out, so the next
    /// turn of the session can tell which leading messages it repeats. Never a
    /// content-store key.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub link_hashes: Option<Vec<String>>,
    /// First meaningful user prompt text (max 200 chars), extracted protocol-aware at the proxy.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub first_user_prompt: Option<String>,

    // Hierarchical session linking (from X-Parent-Session-Id header)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub parent_session_id: Option<uuid::Uuid>,

    // Upstream tracking
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_server_id: Option<uuid::Uuid>,
    /// The replica endpoint that answered (no foreign key — the row keeps
    /// naming it after it is removed) and its URL at the time.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_id: Option<uuid::Uuid>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub endpoint_url: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub upstream_model_id: Option<uuid::Uuid>,

    // Error tracking (None = success)
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub status_code: Option<u16>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error_category: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub error_detail: Option<String>,
    /// On a limit refusal: which limit refused the request — `organisation`,
    /// `workspace`, `member` or `key` (`LimitBucket`). The UI explains a
    /// refusal from this, never from `error_detail`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub limit_bucket: Option<String>,
    /// On a request that ENDED refused by the dispatch gate — by the pool of
    /// the server this row names — why no capacity was given: `shed`,
    /// `queue_timeout`, `gateway_saturated`, `shutting_down` or `superseded`
    /// (`GateRefusal::as_str`). `None` on every request that reached an
    /// upstream, including one refused on the way (see `moved_on_from`). The
    /// server dashboard groups refusals by it, never by `error_detail`.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub gate_refusal: Option<String>,
    /// Every attempt the request moved on from before the one this row names,
    /// in order — each is the attempted server's to count, whatever became of
    /// the request after.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub moved_on_from: Vec<EarlierAttempt>,
    /// What the request waited at the pool of the server this row names before
    /// the attempt the row ends with. `queue_wait_ms` is everything the caller
    /// waited, on every target it tried: this plus each `moved_on_from` wait.
    #[serde(default)]
    pub pool_wait_ms: u64,

    /// Canonical media RPC turn — source of truth for embeddings / speech /
    /// transcription / translation / image generation|edit|variation / video
    /// generation. Serialized as the `llm_audit.media_call` JSONB column.
    /// `None` for chat/text routes.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub media_call: Option<crate::api::domain_request::DomainMediaCall>,

    // Transient blob data — extracted by EdgeAuditSender before serialization.
    // These carry the actual binary payload to the edge outbox for later
    // shipping to admin-api's audit_media_blobs table. Never serialized to JSON. Keyed by
    // the corresponding BlobRef.content_hash in `media_call.input` / `media_call.output`.
    #[serde(skip)]
    pub media_blob_data: Option<bytes::Bytes>,
    #[serde(skip)]
    pub media_response_blob_data: Option<bytes::Bytes>,

    // Chat message media blobs — extracted from request_messages by strip_media_from_messages().
    // Transient: forwarded to blob pipeline, never serialized.
    #[serde(skip)]
    pub message_blobs: Vec<MessageBlobEntry>,
    /// The blobs of `message_blobs` (those a chat message embeds, a media
    /// call's extra outputs), named by key once the edge outbox has taken
    /// their bytes as content — so the record names every blob it was given,
    /// and none it was not (blob storage off, past the cap). Read by the
    /// ingest's content check, never stored on the row.
    #[serde(skip_serializing_if = "Vec::is_empty", default)]
    pub buffered_blobs: Vec<BlobRef>,
    // Tool-definition blobs extracted at audit finalize. Each entry pairs the
    // hash carried on `tools_available_hash`/`tools_effective_hash` with the
    // full JSON blob; the edge sender drains this into the SQLite buffer and
    // forwards it via the `tool_definitions_sync` envelope so central can
    // UPSERT the deduplicated row in `tool_definitions`. Transient — never
    // serialized to JSON.
    #[serde(skip)]
    pub tool_definitions_to_buffer: Vec<ToolDefinitionBlobEntry>,
    /// Compact summary of media extracted from chat messages (stored in
    /// llm_audit). Typed on the wire, so every stored entry decodes for every
    /// reader.
    #[serde(skip_serializing_if = "Option::is_none", default)]
    pub chat_media_summary: Option<Vec<ChatMediaSummaryEntry>>,
}

/// The sha256 hex of a system prompt — its key in the central `system_prompts`
/// content store. The edge names a prompt by it and admin-api stores it under
/// it, so both ends compute it here.
pub fn system_prompt_hash(prompt: &str) -> String {
    use sha2::Digest;
    hex::encode(sha2::Sha256::digest(prompt.as_bytes()))
}

/// A media blob extracted from a chat message content block.
#[derive(Debug, Clone)]
pub struct MessageBlobEntry {
    pub content_hash: String,
    pub blob_type: BlobType,
    pub media_type: String,
    pub data: bytes::Bytes,
    pub size_bytes: usize,
}

/// A tool-definition blob captured at audit finalize. Edge sender drains
/// these into the SQLite buffer + `tool_definitions_sync` envelope so central
/// UPSERTs `tool_definitions(hash, tenant_id) → definition JSONB` once per
/// unique tool blob. `definition_json` is pre-serialised to skip a second
/// `to_string` walk by the buffer.
#[derive(Debug, Clone)]
pub struct ToolDefinitionBlobEntry {
    pub hash: String,
    pub tenant_id: String,
    pub definition_json: String,
    pub content_size: usize,
}

/// Summary entry for `chat_media_summary` stored on llm_audit.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct ChatMediaSummaryEntry {
    pub content_hash: String,
    pub blob_type: BlobType,
    pub media_type: String,
    pub size_bytes: usize,
}

impl Default for AuditRecord {
    fn default() -> Self {
        Self {
            request_id: uuid::Uuid::nil(),
            timestamp: chrono::Utc::now(),
            user_id: uuid::Uuid::nil(),
            // Default to SYSTEM tenant for pre-auth errors.
            // With RLS, nil UUID records would be invisible to all tenants.
            tenant_id: uuid::Uuid::from_u128(1),
            workspace_id: uuid::Uuid::nil(),
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: None,
            client_ip: None,
            end_user: None,
            end_user_groups: Vec::new(),
            model_requested: String::new(),
            model_used: String::new(),
            provider: String::new(),
            api_version: ApiVersion::ChatCompletions,
            stream: false,
            prompt_tokens: 0,
            completion_tokens: 0,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_read_tokens: None,
            finish_reason: String::new(),
            native_finish_reason: None,
            cost: 0.0,
            cost_currency: crate::pricing::Currency::USD,
            source_cost: 0.0,
            source_currency: crate::pricing::Currency::USD,
            fx_rate: 1.0,
            billed_units: std::collections::BTreeMap::new(),
            embedding_cost: 0.0,
            embedding_tokens: 0,
            queue_wait_ms: 0,
            qos_class_id: None,
            zero_completion: true,
            cache_mode: None,
            cache_outcome: None,
            avoided_cost: 0.0,
            latency_ttft_ms: 0,
            latency_total_ms: 0,
            badges: Vec::new(),
            pipeline_path: None,
            catchall_path: None,
            catchall_method: None,
            request_messages: None,
            request_messages_json: None,
            request_tools: None,
            tools_available_hash: None,
            tools_effective_hash: None,
            request_params: None,
            system_prompt: None,
            system_prompt_hash: None,
            transform_diff: None,
            response_content: None,
            response_tool_calls: None,
            conversation_session_id: None,
            turn_number: None,
            parent_request_id: None,
            is_baseline: None,
            message_hashes: None,
            link_hashes: None,
            first_user_prompt: None,
            parent_session_id: None,
            upstream_server_id: None,
            endpoint_id: None,
            endpoint_url: None,
            upstream_model_id: None,
            status_code: None,
            error_category: None,
            error_detail: None,
            limit_bucket: None,
            gate_refusal: None,
            moved_on_from: Vec::new(),
            pool_wait_ms: 0,
            media_call: None,
            media_blob_data: None,
            media_response_blob_data: None,
            message_blobs: Vec::new(),
            buffered_blobs: Vec::new(),
            tool_definitions_to_buffer: Vec::new(),
            chat_media_summary: None,
        }
    }
}

impl AuditRecord {
    /// Create a minimal audit record for an error that occurred before the response pipeline.
    ///
    /// The workspace is required, not optional: an error row with a nil
    /// workspace is left out of every workspace-scoped view — the dashboards,
    /// the attention queue, the per-server figures — so an authenticated
    /// request's failure must carry its key's workspace. Nil only before auth.
    pub fn error_record(
        request_id: uuid::Uuid,
        user_id: uuid::Uuid,
        tenant_id: uuid::Uuid,
        workspace_id: uuid::Uuid,
        key_id: Option<uuid::Uuid>,
        error: &crate::error::AppError,
    ) -> Self {
        let (status, category, detail) = error.audit_error_info();
        Self {
            request_id,
            timestamp: chrono::Utc::now(),
            user_id,
            tenant_id,
            workspace_id,
            key_id,
            finish_reason: "error".to_string(),
            status_code: Some(status),
            error_category: Some(category.to_string()),
            error_detail: Some(detail),
            limit_bucket: error.limit_bucket().map(|b| b.as_str().to_string()),
            gate_refusal: error.gate_refusal().map(str::to_string),
            ..Default::default()
        }
    }
}

/// Creates the counted channel pair for async audit writing using [`core_settings()`].
pub fn create_audit_channel() -> (AuditSender<AuditRecord>, AuditReceiver<AuditRecord>) {
    counted_channel(core_settings().audit_channel_capacity)
}

/// Background task that receives audit records and forwards them in batches.
///
/// Drains the MPSC channel into batches of up to `batch_size` records, then writes
/// them to the edge outbox (SQLite). Under high throughput the channel fills
/// up and applies backpressure to request handlers (audit is mandatory —
/// records are never dropped).
pub async fn audit_writer_task(
    mut rx: AuditReceiver<AuditRecord>,
    forwarder: Box<dyn AuditForwarderTrait + Send>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let s = core_settings();
    let max_batch = s.audit_batch_size;
    let deadline_ms = s.audit_batch_deadline_ms;
    let mut batch: Vec<AuditRecord> = Vec::with_capacity(max_batch);
    let mut sender_dropped = false;

    loop {
        // Collect up to max_batch records or wait deadline_ms.
        // Short deadline ensures rapid drain under sustained load
        // while keeping idle-state CPU near zero via the recv() await.
        let deadline = tokio::time::sleep(Duration::from_millis(deadline_ms));
        tokio::pin!(deadline);

        loop {
            tokio::select! {
                maybe = rx.recv() => {
                    match maybe {
                        Some(record) => {
                            batch.push(record);
                            if batch.len() >= max_batch {
                                break;
                            }
                        }
                        None => {
                            // All senders dropped — drain remaining batch and exit
                            // gracefully. Without this match the bare `Some(record)`
                            // pattern silently fell through on close, leaving the
                            // task busy-looping the deadline branch forever.
                            sender_dropped = true;
                            break;
                        }
                    }
                }
                () = &mut deadline => {
                    break;
                }
                () = shutdown.cancelled() => {
                    // Shutdown requested. The HTTP server has fully drained
                    // upstream, so no new records will be produced —
                    // exhaustively drain whatever is still queued, flushing in
                    // bounded batches, then exit via the tail below.
                    while let Ok(record) = rx.try_recv() {
                        batch.push(record);
                        if batch.len() >= max_batch {
                            let records = std::mem::take(&mut batch);
                            let count = records.len();
                            let lost = match forwarder.forward_batch(records).await {
                                Ok(lost) => lost,
                                Err(e) => {
                                    tracing::error!(count, "audit shutdown-drain forward failed: {e}");
                                    count
                                }
                            };
                            EMISSION_STATS.writer_dropped.fetch_add(lost as u64, Ordering::Relaxed);
                            rx.forwarded(count);
                        }
                    }
                    sender_dropped = true;
                    break;
                }
            }
        }

        if !batch.is_empty() {
            let records = std::mem::take(&mut batch);
            let count = records.len();
            let lost = match forwarder.forward_batch(records).await {
                Ok(lost) => lost,
                Err(e) => {
                    tracing::error!(count, "audit forward failed, dropping records: {e}");
                    count
                }
            };
            EMISSION_STATS.writer_dropped.fetch_add(lost as u64, Ordering::Relaxed);
            rx.forwarded(count);
        }

        if sender_dropped {
            tracing::info!("audit writer task: draining complete, exiting");
            return;
        }
    }
}

/// Trait for audit forwarding — allows the proxy to provide an AuditForwarder implementation.
///
/// Takes ownership of `records` so the impl can `mem::take` transient fields
/// (`request_messages_json`, `media_*_blob_data`, `message_blobs`) instead of
/// deep-cloning the whole `AuditRecord` just to strip them.
///
/// Answers how many of `records` it could not store (`Ok`), or `Err` when it
/// stored none; the writer task counts either in
/// [`EmissionStats::writer_dropped`], the one place it is counted.
pub trait AuditForwarderTrait: Send + Sync {
    fn forward_batch(
        &self,
        records: Vec<AuditRecord>,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, anyhow::Error>> + Send + '_>>;
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    #[tokio::test]
    async fn an_audit_record_counts_from_its_send_until_its_writer_forwards_it() {
        let (tx, mut rx) = counted_channel::<u32>(1);
        let pending = tx.pending_count();
        assert_eq!(pending.get(), 0);
        tx.try_send(1).expect("the channel has room");
        assert_eq!(pending.get(), 1);
        // Refused (full): not counted.
        assert!(tx.try_send(2).is_err());
        assert_eq!(pending.get(), 1);
        // A send waiting for room and then cancelled counts nothing.
        assert!(tokio::time::timeout(Duration::from_millis(20), tx.send(3)).await.is_err());
        assert_eq!(pending.get(), 1);
        // Taken off the channel, it stays counted while its writer holds it.
        assert_eq!(rx.recv().await, Some(1));
        assert_eq!(pending.get(), 1);
        rx.forwarded(1);
        assert_eq!(pending.get(), 0);
        // Positive control: a send with room counts.
        tx.send(4).await.expect("the channel has room");
        assert_eq!(pending.get(), 1);
    }

    #[test]
    fn an_error_row_keeps_its_workspace_and_a_refusals_reason() {
        let workspace = uuid::Uuid::new_v4();
        let refusal = crate::error::AppError::Saturated {
            message: "busy".into(),
            reason: "shed",
            retry_after_secs: 1,
        };
        let row = AuditRecord::error_record(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            workspace,
            None,
            &refusal,
        );
        assert_eq!(row.workspace_id, workspace);
        assert_eq!(row.error_category.as_deref(), Some("capacity"));
        assert_eq!(row.gate_refusal.as_deref(), Some("shed"));
        // The reason travels to admin on the wire.
        assert_eq!(serde_json::to_value(&row).expect("json")["gate_refusal"], "shed");
        // Any other failure carries none.
        let other = AuditRecord::error_record(
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            uuid::Uuid::new_v4(),
            workspace,
            None,
            &crate::error::AppError::BadRequest("no".into()),
        );
        assert_eq!(other.gate_refusal, None);
    }

    /// Forwarder that just counts the records it receives.
    struct CountingForwarder {
        forwarded: Arc<AtomicUsize>,
    }

    impl AuditForwarderTrait for CountingForwarder {
        fn forward_batch(
            &self,
            records: Vec<AuditRecord>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, anyhow::Error>> + Send + '_>>
        {
            let forwarded = self.forwarded.clone();
            Box::pin(async move {
                forwarded.fetch_add(records.len(), Ordering::SeqCst);
                Ok(0)
            })
        }
    }

    /// On shutdown the writer must exit even while a sender is still live, and
    /// the exhaustive drain must flush every queued record first. With the
    /// channel held open, the only way the task can terminate is the
    /// cancellation arm — without it this test would hang past the timeout.
    #[tokio::test]
    async fn audit_writer_drains_and_exits_on_cancellation() {
        const N: usize = 50;
        let forwarded = Arc::new(AtomicUsize::new(0));
        let forwarder = Box::new(CountingForwarder {
            forwarded: forwarded.clone(),
        });
        let (tx, rx) = create_audit_channel();
        let token = tokio_util::sync::CancellationToken::new();

        let handle = tokio::spawn(audit_writer_task(rx, forwarder, token.clone()));

        for _ in 0..N {
            tx.send(AuditRecord::default()).await.expect("send record");
        }
        token.cancel();

        tokio::time::timeout(std::time::Duration::from_secs(5), handle)
            .await
            .expect("audit writer did not exit within 5s of cancellation")
            .expect("audit writer task panicked");

        assert_eq!(
            forwarded.load(Ordering::SeqCst),
            N,
            "shutdown drain must flush every queued record"
        );

        // `tx` is still alive here — the task exited solely via cancellation.
        drop(tx);
    }

    #[test]
    fn a_system_prompt_is_keyed_by_its_sha256_hex() {
        assert_eq!(system_prompt_hash("abc"), "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    }
}
