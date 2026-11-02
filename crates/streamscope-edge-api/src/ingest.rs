//! `POST /api/v2/edge/ingest` — the edge ships per-tenant shares (records with
//! the content they reference), its instance state and its usage counters.
//!
//! Every share is written in its tenant's own transaction and every row is
//! keyed, so a share delivered twice writes once: the edge may resend a share
//! until it has an outcome for it. Instance state carries `(process_epoch,
//! seq)` and applies newer-wins; usage carries monotonic cumulatives.
//!
//! The record payloads are the types the proxy already produces
//! ([`AuditRecord`], [`McpAuditRecord`], …); this module only frames them.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use streamscope_core::audit::a2a::A2aAuditRecord;
use streamscope_core::audit::mcp::McpAuditRecord;
use streamscope_core::api::domain_request::DomainContentBlock;
pub use streamscope_core::audit::BlobRef;
use streamscope_core::audit::{AuditRecord, BlobType};
use streamscope_core::config::mcp::McpUserCredential;
use streamscope_core::mcp::sse_events::McpSseEventRecord;
use streamscope_core::proxy::health::{EndpointModelMissing, EndpointState, HealthTransitionEvent};
use streamscope_core::proxy::qos_metrics::EndpointLoadReport;
use streamscope_core::usage::{UsageCounterAuthoritative, UsageCounterKey, UsageCounterReport};
use streamscope_core::web::audit::WebAuditRecord;

use crate::sync::Epoch;

/// The most bytes of records and content the edge puts in one share. Both ends
/// ship together, so this is a constant rather than a negotiated limit. A blob
/// larger than it goes up by itself, raw ([`blob_path`]), ahead of the records
/// that reference it, which then leave it out ([`TenantShare`]).
pub const SHARE_BUDGET_BYTES: usize = 4 * 1024 * 1024;

/// The largest ingest request body admin-api reads. The edge fills a request
/// with shares up to it; a single share always fits, since a share is at most
/// [`SHARE_BUDGET_BYTES`] plus one content row of at most
/// [`CONTENT_MAX_BYTES`].
pub const INGEST_REQUEST_MAX_BYTES: usize = 32 * 1024 * 1024;

/// The largest content row other than a blob the edge buffers, measured as it
/// travels. Half the request leaves room for the share it rides in; anything
/// larger could never fit an ingest request and would stall the outbox, so it
/// is refused at buffering, with an error, and its records ship without it.
/// A blob is held to the platform's blob cap instead (`EDGE_BLOB_MAX_MB`): one
/// too large for a share goes up by itself.
pub const CONTENT_MAX_BYTES: usize = INGEST_REQUEST_MAX_BYTES / 2;

/// Where a blob goes up raw, relative to admin-api's base URL: `PUT` with the
/// edge token, the bytes as the body and the media type as `Content-Type`.
pub fn blob_path(tenant: uuid::Uuid, blob: &BlobRef) -> String {
    format!("/api/v2/edge/blobs/{tenant}/{}/{}", blob.blob_type.as_str(), blob.content_hash)
}

/// An instance whose last sync is older than this is not live. An edge waits at
/// most a third of it between syncs, and a stalled sync ends after its
/// request timeout (no byte read for that long), below it.
pub const INSTANCE_LIVE_SECS: u64 = 15;

const _: () = assert!(SHARE_BUDGET_BYTES * 2 <= INGEST_REQUEST_MAX_BYTES);

/// JSON levels of an [`IngestRequest`] around one record (`{kind, body}`):
/// the request, its shares, the share, its records. A record nested deeper
/// than admin-api's parse bound less these is refused with the whole request.
pub const RECORD_ENCLOSING_DEPTH: usize = 4;

/// JSON levels of an [`IngestRequest`] around one content item (a
/// [`MessageContent`], [`ToolDefinitionContent`], [`SystemPromptContent`] or
/// [`BlobContent`]): the request, its shares, the share, its content, the item
/// list.
pub const CONTENT_ENCLOSING_DEPTH: usize = 5;

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct IngestRequest {
    /// The edge instance: an id created with the edge's durable store and kept
    /// in it, the `instance_key` of its `edge_instances` row under the
    /// authenticated edge.
    pub instance: uuid::Uuid,
    pub process_epoch: Epoch,
    /// Each written in its tenant's own transaction; answered index-aligned
    /// in [`IngestResponse::shares`].
    #[serde(default)]
    pub shares: Vec<TenantShare>,
    /// Sent when due (every heartbeat interval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instance_state: Option<InstanceState>,
    /// Sent when due (every usage-sync interval).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageReport>,
}

/// One tenant's records and the content they reference, written together.
///
/// Every body a record names ([`Record::content_keys`]) is carried in
/// `content`, left out (this edge delivered it earlier — in a share admin-api
/// committed, or a blob that went up by itself), or named in `unavailable`
/// (the edge cannot deliver it). Admin-api checks every key a record names
/// that the share does not carry: one it does not hold is asked for in
/// [`ShareOutcome::Retry`] and nothing is written — unless the share names it
/// `unavailable`, when the records naming it are stored badged
/// `content_unavailable`.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct TenantShare {
    pub tenant: uuid::Uuid,
    #[serde(default)]
    pub content: Content,
    #[serde(default)]
    pub records: Vec<Record>,
    /// Bodies the records name that the edge does not have to send: refused
    /// when buffered (too large for any request), or lost since.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unavailable: Vec<ContentKey>,
}

/// Names one content-addressed body: its store and its key within the tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ContentKey {
    Message { hash: String },
    ToolDefinition { hash: String },
    SystemPrompt { hash: String },
    Blob { content_hash: String, blob_type: BlobType },
}

impl From<BlobRef> for ContentKey {
    fn from(b: BlobRef) -> Self {
        ContentKey::Blob { content_hash: b.content_hash, blob_type: b.blob_type }
    }
}

/// Content-addressed rows records point at. Written `DO NOTHING` on their key:
/// content repeats freely across shares.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct Content {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub messages: Vec<MessageContent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_definitions: Vec<ToolDefinitionContent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_prompts: Vec<SystemPromptContent>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blobs: Vec<BlobContent>,
}

impl Content {
    pub fn is_empty(&self) -> bool {
        self.messages.is_empty()
            && self.tool_definitions.is_empty()
            && self.system_prompts.is_empty()
            && self.blobs.is_empty()
    }

    /// The key of every body carried.
    pub fn keys(&self) -> impl Iterator<Item = ContentKey> + '_ {
        let messages = self.messages.iter().map(|m| ContentKey::Message { hash: m.hash.clone() });
        let tools = self.tool_definitions.iter().map(|t| ContentKey::ToolDefinition { hash: t.hash.clone() });
        let prompts = self.system_prompts.iter().map(|p| ContentKey::SystemPrompt { hash: p.hash.clone() });
        let blobs = self.blobs.iter().map(|b| ContentKey::from(b.blob_ref()));
        messages.chain(tools).chain(prompts).chain(blobs)
    }
}

/// A conversation message, keyed by its content hash within the tenant.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct MessageContent {
    pub hash: String,
    /// One conversation message in its client protocol's wire shape.
    #[schema(value_type = Object)]
    pub message: serde_json::Value,
    pub content_size: i32,
}

/// A tool-definition set, keyed by its content hash within the tenant.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct ToolDefinitionContent {
    pub hash: String,
    /// A tools array in its client protocol's wire shape.
    #[schema(value_type = Object)]
    pub definition: serde_json::Value,
    pub content_size: i32,
}

/// A system prompt, keyed by its
/// [`system_prompt_hash`](streamscope_core::audit::system_prompt_hash) within
/// the tenant.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SystemPromptContent {
    pub hash: String,
    pub prompt: String,
    /// The prompt's length in bytes.
    pub content_size: i32,
}

/// A media blob, keyed by `(content_hash, blob_type)` within the tenant.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct BlobContent {
    pub content_hash: String,
    pub blob_type: BlobType,
    pub media_type: String,
    /// The bytes, standard base64 (decoded by the database on insert).
    pub data_base64: String,
}

impl BlobContent {
    pub fn blob_ref(&self) -> BlobRef {
        BlobRef { content_hash: self.content_hash.clone(), blob_type: self.blob_type }
    }
}

/// The record kinds a share carries. The string form is the `kind` tag on
/// the wire and the outbox's `records.kind`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum RecordKind {
    LlmAudit,
    McpAudit,
    A2aAudit,
    WebAudit,
    McpSseEvent,
    CredentialRotation,
}

impl RecordKind {
    pub const ALL: [RecordKind; 6] = [
        RecordKind::LlmAudit,
        RecordKind::McpAudit,
        RecordKind::A2aAudit,
        RecordKind::WebAudit,
        RecordKind::McpSseEvent,
        RecordKind::CredentialRotation,
    ];

    pub fn as_str(self) -> &'static str {
        match self {
            RecordKind::LlmAudit => "llm_audit",
            RecordKind::McpAudit => "mcp_audit",
            RecordKind::A2aAudit => "a2a_audit",
            RecordKind::WebAudit => "web_audit",
            RecordKind::McpSseEvent => "mcp_sse_event",
            RecordKind::CredentialRotation => "credential_rotation",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|k| k.as_str() == s)
    }
}

/// One record, framed by its kind. The body is the record type the proxy
/// produces for that kind, unchanged.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", content = "body", rename_all = "snake_case")]
pub enum Record {
    LlmAudit(Box<AuditRecord>),
    McpAudit(Box<McpAuditRecord>),
    A2aAudit(Box<A2aAuditRecord>),
    WebAudit(Box<WebAuditRecord>),
    McpSseEvent(Box<McpSseEventRecord>),
    /// A refreshed per-user MCP credential; admin-api keeps the one with the
    /// later `expires_at`.
    CredentialRotation(Box<McpUserCredential>),
}

impl utoipa::PartialSchema for Record {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::SchemaType::new(utoipa::openapi::schema::Type::Object))
            .description(Some(
                "`{ \"kind\": <RecordKind>, \"body\": <the record> }` — the body is the proxy's audit / \
                 MCP / A2A / web audit record, MCP SSE event row or rotated MCP credential",
            ))
            .into()
    }
}

impl utoipa::ToSchema for Record {}

/// Names one record of a share: what [`ShareOutcome::Rejected`] lists.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize, ToSchema)]
pub struct RowRef {
    pub kind: RecordKind,
    pub key: String,
}

impl Record {
    pub fn kind(&self) -> RecordKind {
        match self {
            Record::LlmAudit(_) => RecordKind::LlmAudit,
            Record::McpAudit(_) => RecordKind::McpAudit,
            Record::A2aAudit(_) => RecordKind::A2aAudit,
            Record::WebAudit(_) => RecordKind::WebAudit,
            Record::McpSseEvent(_) => RecordKind::McpSseEvent,
            Record::CredentialRotation(_) => RecordKind::CredentialRotation,
        }
    }

    pub fn tenant_id(&self) -> uuid::Uuid {
        match self {
            Record::LlmAudit(r) => r.tenant_id,
            Record::McpAudit(r) => r.tenant_id,
            Record::A2aAudit(r) => r.tenant_id,
            Record::WebAudit(r) => r.tenant_id,
            Record::McpSseEvent(r) => r.tenant_id,
            Record::CredentialRotation(r) => r.tenant_id,
        }
    }

    /// The key admin-api dedupes the record on, as text: the outbox keeps one
    /// record per `(tenant, kind, natural_key)`, and a rejection names it.
    /// Audit rows are keyed `(request_id, timestamp)`, SSE events
    /// `(session, sequence, created_at)`, a credential `(user, upstream)`.
    pub fn natural_key(&self) -> String {
        fn at(ts: &chrono::DateTime<chrono::Utc>) -> String {
            ts.to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
        }
        match self {
            Record::LlmAudit(r) => format!("{}/{}", r.request_id, at(&r.timestamp)),
            Record::McpAudit(r) => format!("{}/{}", r.request_id, at(&r.timestamp)),
            Record::A2aAudit(r) => format!("{}/{}", r.request_id, at(&r.timestamp)),
            Record::WebAudit(r) => format!("{}/{}", r.request_id, at(&r.timestamp)),
            Record::McpSseEvent(r) => format!("{}/{}/{}", r.mcp_session_id, r.sequence, at(&r.created_at)),
            Record::CredentialRotation(r) => format!("{}/{}", r.user_id, r.upstream_server_id),
        }
    }

    pub fn row_ref(&self) -> RowRef {
        RowRef { kind: self.kind(), key: self.natural_key() }
    }

    /// Every content-addressed body the record names: an LLM turn's history
    /// messages, its tool sets, its system prompt and the media blobs its
    /// media call references. Both ends read a record's needs from here — the
    /// edge to say where each is ([`TenantShare`]), admin-api to check them —
    /// so the two cannot disagree on what a record needs.
    ///
    /// The blobs a chat message embeds, and a media call's extra outputs, are
    /// named by `buffered_blobs`: the edge lists there exactly the blobs it
    /// was given the bytes of, so a blob that was never stored (blob storage
    /// off, past the cap) is never named, and every blob named is one the
    /// edge carries, holds or reports unavailable.
    pub fn content_keys(&self) -> Vec<ContentKey> {
        let Record::LlmAudit(r) = self else {
            return Vec::new();
        };
        let mut keys: Vec<ContentKey> = Vec::new();
        for hash in r.message_hashes.iter().flatten() {
            keys.push(ContentKey::Message { hash: hash.clone() });
        }
        for hash in [&r.tools_available_hash, &r.tools_effective_hash].into_iter().flatten() {
            keys.push(ContentKey::ToolDefinition { hash: hash.clone() });
        }
        if let Some(hash) = &r.system_prompt_hash {
            keys.push(ContentKey::SystemPrompt { hash: hash.clone() });
        }
        if let Some(call) = &r.media_call {
            // The edge stores a media call's blob under the side's type when
            // its block names none.
            let sides = [(&call.input, BlobType::RequestUpload), (&call.output, BlobType::ResponseBody)];
            for (blocks, side) in sides {
                for block in blocks {
                    if let DomainContentBlock::BlobRef { content_hash, blob_type, .. } = block {
                        keys.push(ContentKey::Blob { content_hash: content_hash.clone(), blob_type: blob_type.unwrap_or(side) });
                    }
                }
            }
        }
        for b in &r.buffered_blobs {
            keys.push(ContentKey::from(b.clone()));
        }
        let mut seen = std::collections::HashSet::new();
        keys.retain(|k| seen.insert(k.clone()));
        keys
    }
}

/// One instance's state, restated every heartbeat interval. The stated parts
/// apply only when `(process_epoch, seq)` is newer than what admin-api applied
/// for the instance (per tenant for the tenant-scoped parts), and never from
/// an epoch older than the instance's current one. The one-shot parts
/// (`health`, `model_missing`) apply once per [`OneShot::id`] instead, whatever
/// report carries them.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct InstanceState {
    /// Increases with every report within one process epoch.
    pub seq: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stats: Option<EdgeProxyStats>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub runtime: Option<EdgeRuntimeReport>,
    #[serde(default)]
    pub endpoints: EndpointBeat,
    /// Breaker transitions not yet answered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub health: Vec<OneShot<HealthTransition>>,
    /// "Model not found" answers from endpoints, not yet answered.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    #[schema(value_type = Vec<Object>)]
    pub model_missing: Vec<OneShot<ModelMissing>>,
}

/// An event that happened once. The edge numbers its events within its process
/// epoch, in the order they happened, and restates every one in each report
/// until an ingest request carrying it is answered; admin-api applies each
/// `(process_epoch, id)` once. A later report therefore carries every event an
/// earlier unanswered one did, so whichever lands first applies them in order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OneShot<T> {
    pub id: u64,
    pub event: T,
}

/// The instance's live load on each replica endpoint and its stand on each
/// endpoint it routes to. Stated in full: an endpoint the beat does not name
/// is one the instance no longer routes to.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct EndpointBeat {
    /// One `EndpointLoadReport` per replica endpoint (edge protocol only).
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub load: Vec<EndpointLoadReport>,
    /// One `EndpointState` per endpoint the instance routes to (edge protocol only).
    #[serde(default)]
    #[schema(value_type = Vec<Object>)]
    pub states: Vec<EndpointState>,
}

pub type HealthTransition = HealthTransitionEvent;
pub type ModelMissing = EndpointModelMissing;

/// Whether an MCP audit record of `method` is a server-initiated event other
/// instances relay to their subscribers: admin-api announces each one it
/// stores, and the edge that buffers one ships it at once.
pub fn is_mcp_fanout_method(method: &str) -> bool {
    matches!(
        method,
        "sampling/createMessage"
            | "elicitation/create"
            | "notifications/tools/list_changed"
            | "notifications/resources/list_changed"
            | "notifications/prompts/list_changed"
    )
}

/// This instance's monotonic cumulative per usage counter.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct UsageReport {
    /// One `UsageCounterReport` per counter (edge protocol only).
    #[schema(value_type = Vec<Object>)]
    pub counters: Vec<UsageCounterReport>,
}

/// What admin did with the counters a [`UsageReport`] named. A counter in
/// neither list did not merge this time (a transient failure): the edge
/// restates it.
#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct UsageSync {
    /// The fleet-wide total of every counter that merged.
    #[schema(value_type = Vec<Object>)]
    pub totals: Vec<UsageCounterAuthoritative>,
    /// Counters that can never merge — a deleted tenant's, a window past
    /// retention or out of range, a value the database refuses — dropped,
    /// never to be restated.
    #[schema(value_type = Vec<Object>)]
    pub settled: Vec<UsageCounterKey>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct IngestResponse {
    /// One outcome per request share, in request order.
    pub shares: Vec<ShareOutcome>,
    /// Present when the request carried usage from the instance's current
    /// epoch.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub usage: Option<UsageSync>,
    /// The request's one-shot events are stored (or need never be): the edge
    /// may forget them. False when the request carried none, or when applying
    /// them failed for some tenant — the edge then restates them.
    #[serde(default)]
    pub one_shots_settled: bool,
}

/// What became of one share. Only `Retry` keeps it at the edge.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ShareOutcome {
    /// Every row is stored (or already was).
    Committed,
    /// The share committed without these rows, which the database refused for
    /// their data — every resend would be refused the same way.
    Rejected { rows: Vec<RowRef>, reason: String },
    /// The tenant no longer exists; nothing of the share can be stored.
    TenantDeleted,
    /// Nothing was written. `missing` names the bodies the share did not
    /// carry and admin-api does not hold — resend them with the records;
    /// empty for a transient failure.
    Retry {
        #[serde(default)]
        missing: Vec<ContentKey>,
    },
}

/// Per-replica runtime stats, as reported with the instance state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct EdgeProxyStats {
    pub requests_total: u64,
    pub errors_total: u64,
    pub active_streams: u64,
    /// CPU% (100% == one core) and working-set bytes from the replica's cgroup —
    /// real pod/container usage, not host-wide.
    pub cpu_percent: f64,
    pub memory_rss_bytes: u64,
    /// Denominator for the replica's memory-pressure reading: its cgroup ceiling
    /// (`memory.max`) normally, or — on the single-host VM appliance — the host's
    /// total RAM, paired with a host-wide `memory_rss_bytes` (the appliance
    /// reports whole-VM pressure, not the proxy container's slice of its own cap).
    /// `None` off-cgroup or when unconstrained.
    pub memory_limit_bytes: Option<u64>,
    /// Effective Tokio worker-thread count (the replica's parallelism), not host cores.
    pub cores: u32,
    pub uptime_secs: u64,
    pub http2_requests: u64,
    pub http11_requests: u64,
    /// Proxy-overhead histogram — the platform's own auth + transform +
    /// routing time, excluding upstream. CUMULATIVE per-bucket counts since
    /// proxy start, positioned against the shared bounds
    /// (`streamscope_core::metrics::OVERHEAD_BOUNDS_US`, last slot =
    /// overflow); windowed percentiles come from differencing consecutive
    /// samples, like `requests_total`.
    pub overhead_buckets: Vec<u64>,
    /// Cumulative sum of recorded overhead in µs (histogram `_sum`).
    pub overhead_sum_us: u64,
    /// Cumulative recorded-sample count (== sum of `overhead_buckets`).
    pub overhead_count: u64,
    /// Audit records buffered locally on this edge that haven't yet flushed
    /// upstream. Non-zero means the edge is queueing (admin-api disconnected,
    /// remote backpressure, or a sync_request in flight).
    pub pending_audit_count: u64,
    /// Response-cache occupancy and lifetime counters for the replica that sent
    /// this heartbeat.
    pub cache: EdgeCacheStats,
}

/// What one replica's response cache holds, as reported by heartbeat.
///
/// Gauges (`entries`, `bytes`, `semantic_*`) are point-in-time; the `*_total`
/// counters are CUMULATIVE since that process started, so a rate comes from
/// differencing successive reports — never from the raw value.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, ToSchema)]
pub struct EdgeCacheStats {
    pub entries: u64,
    pub bytes: u64,
    /// The replica's global byte ceiling — the denominator for `bytes`.
    pub max_bytes: u64,
    /// Indexed prompt vectors. Above `entries` means vectors are outliving the
    /// answers they point at, which has no symptom other than memory.
    pub semantic_vectors: u64,
    pub semantic_buckets: u64,
    pub stores_total: u64,
    /// Entries given up to make room. Rising against a flat `entries` means the
    /// cache is too small for its traffic — answers are thrown out before they
    /// can be hit, which from the audit side is indistinguishable from nobody
    /// repeating a prompt.
    pub evictions_total: u64,
    /// Entries dropped for reaching their TTL — the cache working as configured,
    /// deliberately counted apart from eviction.
    pub expired_total: u64,
}

/// Runtime-config state an edge reports with its instance state.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
pub struct EdgeRuntimeReport {
    /// Token → effective running value for every core + proxy setting.
    pub effective: HashMap<String, String>,
    /// The central-override subset the edge actually applied at startup.
    /// Compared against the desired override set to detect "restart pending".
    pub loaded_overrides: HashMap<String, String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn credential(expires: Option<&str>) -> McpUserCredential {
        McpUserCredential {
            tenant_id: uuid::Uuid::nil(),
            user_id: uuid::Uuid::from_u128(1),
            upstream_server_id: uuid::Uuid::from_u128(2),
            encrypted_access_token: "a".into(),
            encrypted_refresh_token: None,
            expires_at: expires.map(|s| s.parse().unwrap()),
            scope: None,
        }
    }

    #[test]
    fn a_record_travels_as_its_kind_and_the_producers_body() {
        let rec = Record::CredentialRotation(Box::new(credential(Some("2026-10-03T10:00:00Z"))));
        let v = serde_json::to_value(&rec).unwrap();
        assert_eq!(v["kind"], "credential_rotation");
        assert_eq!(v["body"], serde_json::to_value(credential(Some("2026-10-03T10:00:00Z"))).unwrap());
        let back: Record = serde_json::from_value(v).unwrap();
        assert_eq!(back.kind(), RecordKind::CredentialRotation);
        // The kind's wire tag and `as_str` are one spelling.
        for k in RecordKind::ALL {
            assert_eq!(serde_json::to_value(k).unwrap(), k.as_str());
            assert_eq!(RecordKind::parse(k.as_str()), Some(k));
        }
    }

    #[test]
    fn a_rotation_is_keyed_by_user_and_upstream_not_by_its_tokens() {
        let a = Record::CredentialRotation(Box::new(credential(Some("2026-10-03T10:00:00Z"))));
        let b = Record::CredentialRotation(Box::new(credential(Some("2026-10-04T10:00:00Z"))));
        assert_eq!(a.natural_key(), b.natural_key());
    }

    #[test]
    fn a_content_key_travels_tagged_by_its_store() {
        let keys = [
            (ContentKey::Message { hash: "m".into() }, serde_json::json!({"kind": "message", "hash": "m"})),
            (ContentKey::ToolDefinition { hash: "t".into() }, serde_json::json!({"kind": "tool_definition", "hash": "t"})),
            (ContentKey::SystemPrompt { hash: "p".into() }, serde_json::json!({"kind": "system_prompt", "hash": "p"})),
            (
                ContentKey::Blob { content_hash: "b".into(), blob_type: BlobType::ChatImage },
                serde_json::json!({"kind": "blob", "content_hash": "b", "blob_type": "chat_image"}),
            ),
        ];
        for (key, wire) in keys {
            assert_eq!(serde_json::to_value(&key).unwrap(), wire);
            assert_eq!(serde_json::from_value::<ContentKey>(wire).unwrap(), key);
        }
        // A share names nothing it need not: empty lists stay off the wire.
        let share = serde_json::to_value(TenantShare::default()).unwrap();
        assert!(share.get("unavailable").is_none(), "{share}");
    }

    fn llm(r: AuditRecord) -> Record {
        Record::LlmAudit(Box::new(r))
    }

    #[test]
    fn a_turn_names_its_history_tools_prompt_and_media_call_blobs_once_each() {
        let call: streamscope_core::api::domain_request::DomainMediaCall = serde_json::from_value(serde_json::json!({
            "endpoint": "image_edit",
            "model": "m",
            "input": [
                {"type": "blob_ref", "content_hash": "up", "media_type": "image/png", "blob_type": "request_upload"},
                {"type": "text", "text": "a cat"},
            ],
            "output": [
                {"type": "blob_ref", "content_hash": "out", "media_type": "image/png"},
                {"type": "stripped", "media_type": "image/png", "size_bytes": 9, "reason": "oversized"},
            ],
        }))
        .unwrap();
        let r = AuditRecord {
            message_hashes: Some(vec!["m1".into(), "m2".into(), "m1".into()]),
            tools_available_hash: Some("ta".into()),
            tools_effective_hash: Some("te".into()),
            system_prompt_hash: Some("sp".into()),
            media_call: Some(call),
            buffered_blobs: vec![
                BlobRef { content_hash: "img".into(), blob_type: BlobType::ChatImage },
                BlobRef { content_hash: "out".into(), blob_type: BlobType::ResponseBody },
            ],
            // Listed whether or not it was stored: never named.
            chat_media_summary: Some(vec![streamscope_core::audit::ChatMediaSummaryEntry {
                content_hash: "never-stored".into(),
                blob_type: BlobType::ChatImage,
                media_type: "image/png".into(),
                size_bytes: 9,
            }]),
            ..Default::default()
        };
        assert_eq!(
            llm(r).content_keys(),
            vec![
                ContentKey::Message { hash: "m1".into() },
                ContentKey::Message { hash: "m2".into() },
                ContentKey::ToolDefinition { hash: "ta".into() },
                ContentKey::ToolDefinition { hash: "te".into() },
                ContentKey::SystemPrompt { hash: "sp".into() },
                ContentKey::Blob { content_hash: "up".into(), blob_type: BlobType::RequestUpload },
                // A block naming no type is stored under its side's.
                ContentKey::Blob { content_hash: "out".into(), blob_type: BlobType::ResponseBody },
                ContentKey::Blob { content_hash: "img".into(), blob_type: BlobType::ChatImage },
            ]
        );
        // The inline prompt never travels: only its hash does.
        let r = AuditRecord { system_prompt: Some("secret prompt".into()), ..Default::default() };
        assert!(!serde_json::to_string(&r).unwrap().contains("secret prompt"));
        assert!(llm(r).content_keys().is_empty(), "a turn with no content names none");
        // Only an LLM turn names content.
        assert!(Record::CredentialRotation(Box::new(credential(None))).content_keys().is_empty());
    }

    #[test]
    fn content_names_every_body_it_carries() {
        let content = Content {
            messages: vec![MessageContent { hash: "m".into(), message: serde_json::json!({}), content_size: 2 }],
            tool_definitions: vec![ToolDefinitionContent { hash: "t".into(), definition: serde_json::json!([]), content_size: 2 }],
            system_prompts: vec![SystemPromptContent { hash: "p".into(), prompt: "x".into(), content_size: 1 }],
            blobs: vec![BlobContent {
                content_hash: "b".into(),
                blob_type: BlobType::ChatFile,
                media_type: "text/plain".into(),
                data_base64: String::new(),
            }],
        };
        assert!(!content.is_empty());
        assert_eq!(
            content.keys().collect::<Vec<_>>(),
            vec![
                ContentKey::Message { hash: "m".into() },
                ContentKey::ToolDefinition { hash: "t".into() },
                ContentKey::SystemPrompt { hash: "p".into() },
                ContentKey::Blob { content_hash: "b".into(), blob_type: BlobType::ChatFile },
            ]
        );
        assert!(Content::default().is_empty());
        assert!(!Content { system_prompts: content.system_prompts.clone(), ..Default::default() }.is_empty());
    }

    #[test]
    fn every_outcome_has_a_distinct_tag() {
        let outcomes = [
            ShareOutcome::Committed,
            ShareOutcome::Rejected { rows: vec![], reason: String::new() },
            ShareOutcome::TenantDeleted,
            ShareOutcome::Retry { missing: vec![] },
            ShareOutcome::Retry { missing: vec![ContentKey::Message { hash: "h".into() }] },
        ];
        let tags: std::collections::BTreeSet<String> = outcomes
            .iter()
            .map(|o| serde_json::to_value(o).unwrap()["outcome"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(tags.len(), outcomes.len() - 1, "the two retries share their tag");
        for o in outcomes {
            let back: ShareOutcome = serde_json::from_value(serde_json::to_value(&o).unwrap()).unwrap();
            assert_eq!(back, o);
        }
    }
}
