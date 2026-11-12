//! Response cache for the LLM plane — an in-memory, per-replica store that
//! serves a previously-computed answer instead of calling the upstream.
//!
//! ## Identity
//!
//! A cached answer belongs to exactly one `(alias, model, invocation preset,
//! response policy, client request)` tuple. Serving one entry under a
//! different model or a different system prompt is a correctness bug, so the
//! key is split into two SHA-256 digests, both mandatory:
//!
//! - **identity** — upstream model + the resolved invocation preset + the
//!   response-shaping policy: nothing of the request. Editing the bound preset
//!   or swapping the model therefore self-invalidates every entry it produced.
//! - **content** — the client's own request: its protocol and its body as a
//!   same-protocol forward sends it, without the members that change nothing
//!   the model answers ([`UNKEYED`]). What the gateway models of a request is
//!   lossy, so a key built from that reading would let two requests the model
//!   reads differently share an answer; the cost is that the same conversation
//!   sent on two protocols is two entries.
//!
//! ## Partitioning
//!
//! An entry is scoped to `(tenant, share-scope component, route)`. A response
//! computed for one workspace is never served to another unless the route's
//! preset explicitly opts into tenant-wide sharing — a completion can embed the
//! requester's own prompt, so widening the scope is an admin decision, not a
//! default. Tenant isolation is absolute regardless of preset.
//!
//! ## Bounds
//!
//! Per-tenant FIFO entry cap plus a global byte ceiling, both operator settings.
//! Eviction only ever drops the *storing* tenant's own oldest entries, so one
//! tenant's churn cannot evict another's. When the global ceiling is reached and
//! the storing tenant has nothing left of its own to give up, the store is
//! refused rather than stealing from a neighbour; TTL expiry reclaims the space.
//! Entries are lost on restart — a cold replica simply misses.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use crate::api::domain::{FinishReason, Usage};
use crate::api::ApiRequest;
use crate::api::domain_request::{DomainContentBlock, DomainMessage, DomainRequest, DomainRole};
use crate::api::sse::ApiVersion;

// ---------------------------------------------------------------------------
// Policy (baked per route by the admin snapshot, carried on the config wire)
// ---------------------------------------------------------------------------

/// What a cache preset does on the hot path.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheMode {
    /// Serve only on a hash-identical request.
    Exact,
    /// Exact prefix (system + history + tools + identity) plus an
    /// embedding-similar last user message.
    Semantic,
    /// Record what *would* have been served, in audit only. The threshold-tuning
    /// mode an admin runs before enforcing.
    Observe,
}

impl CacheMode {
    /// Parse the DB / wire string. Unknown values fall back to the least
    /// surprising behaviour — `Observe` never serves from cache, so an admin
    /// running a newer mode against an older edge gets recording, not a wrong
    /// answer.
    pub fn parse(s: &str) -> Self {
        match s {
            "exact" => Self::Exact,
            "semantic" => Self::Semantic,
            _ => Self::Observe,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exact => "exact",
            Self::Semantic => "semantic",
            Self::Observe => "observe",
        }
    }

    /// Whether a hit on this mode is actually served to the client.
    pub fn serves(self) -> bool {
        matches!(self, Self::Exact | Self::Semantic)
    }
}

/// What the cache actually did for one request, recorded on its audit row.
///
/// Orthogonal to [`CacheMode`], which is the *policy*: an `Observe` alias that
/// matches produces `ObserveHit`, not `Hit`, because the answer was recorded but
/// never served. Summing savings over `Hit` alone is what keeps a tuning run
/// from reading as money saved.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheOutcome {
    /// An entry matched and was served. The request never reached an upstream.
    Hit,
    /// An entry matched under `observe`, and was deliberately not served.
    ObserveHit,
    /// No entry matched. The request went upstream.
    Miss,
    /// The client sent `Cache-Control: no-cache`/`no-store`, so the cache was
    /// neither read nor written. Kept distinct from `Miss` so a client opting
    /// out cannot depress the hit rate of an otherwise healthy alias.
    Bypass,
}

impl CacheOutcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Hit => "hit",
            Self::ObserveHit => "observe_hit",
            Self::Miss => "miss",
            Self::Bypass => "bypass",
        }
    }
}

/// The response cache's verdict on one request, as it lands on the audit row.
///
/// Carried whole rather than as three loose fields so the invariant the schema
/// depends on — mode, outcome and avoided cost are all present together or all
/// absent — cannot be broken by setting one of them at a call site.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct CacheAudit {
    pub mode: CacheMode,
    pub outcome: CacheOutcome,
    pub avoided_cost: f64,
}

/// How widely a computed response may be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CacheShareScope {
    /// Strictest: only the user who produced it.
    User,
    /// Default: the workspace that produced it.
    Workspace,
    /// Tenant-wide. A data-sharing decision — the admin UI warns before setting it.
    Tenant,
}

impl CacheShareScope {
    /// Parse the DB / wire string. Unknown values fall back to the **narrowest**
    /// scope, so a newer scope name can never widen sharing on an older edge.
    pub fn parse(s: &str) -> Self {
        match s {
            "workspace" => Self::Workspace,
            "tenant" => Self::Tenant,
            _ => Self::User,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Workspace => "workspace",
            Self::Tenant => "tenant",
        }
    }

    /// The partition discriminator for this scope. `Tenant` collapses to nil so
    /// every workspace in the tenant shares one bucket.
    pub fn partition_id(self, workspace_id: Option<Uuid>, user_id: Uuid) -> Uuid {
        match self {
            Self::User => user_id,
            Self::Workspace => workspace_id.unwrap_or(Uuid::nil()),
            Self::Tenant => Uuid::nil(),
        }
    }
}

/// The resolved caching policy for one alias — the route's referenced preset,
/// flattened to values at snapshot build so the proxy wire stays value-based
/// (a preset edit re-bakes and propagates like any other config change).
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub struct CachePolicy {
    pub mode: CacheMode,
    pub ttl_seconds: u32,
    pub threshold: f32,
    pub share_scope: CacheShareScope,
}

impl CachePolicy {
    /// Build from the four nullable columns the config snapshot projects.
    /// `None` on the mode means the route references no preset — uncached.
    pub fn from_parts(
        mode: Option<&str>,
        ttl_seconds: Option<i32>,
        threshold: Option<f32>,
        share_scope: Option<&str>,
    ) -> Option<Self> {
        let mode = CacheMode::parse(mode?);
        Some(Self {
            mode,
            // A non-positive TTL from a corrupt row would make every entry
            // instantly stale; clamp to the schema's own default instead.
            ttl_seconds: ttl_seconds.filter(|v| *v > 0).unwrap_or(3600) as u32,
            threshold: threshold.filter(|v| *v > 0.0 && *v <= 1.0).unwrap_or(0.9),
            share_scope: CacheShareScope::parse(share_scope.unwrap_or("workspace")),
        })
    }

    pub fn ttl(&self) -> Duration {
        Duration::from_secs(self.ttl_seconds as u64)
    }
}

// ---------------------------------------------------------------------------
// Tenant settings (the `system_settings.cache` blob)
// ---------------------------------------------------------------------------

/// Tenant-wide response-cache settings — typed projection of the
/// `system_settings.cache` key. Lives on `TenantConfig.cache`.
///
/// Per-alias policy is *not* here: mode, TTL, threshold and sharing scope live
/// on the named cache preset a route references. What belongs here is what the
/// tenant decides once, across every alias.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, utoipa::ToSchema)]
pub struct CacheSettings {
    /// Tenant-wide master switch. `false` makes every alias behave as uncached
    /// regardless of the preset it references — the one-flip incident lever, so
    /// an admin never has to edit N presets to stop serving cached answers.
    #[serde(default = "default_true")]
    pub enabled: bool,

    /// Largest single response the tenant will cache, in KB. A response over
    /// this is served normally and left uncached, with an audit marker — big
    /// answers would evict many small ones for one rare reuse.
    #[serde(default = "default_max_entry_kb")]
    pub max_entry_kb: u32,

    /// Alias the gateway calls to turn a prompt into a vector, for `semantic`
    /// mode. It is an ordinary embeddings alias from the tenant's own catalog,
    /// so no separate credential exists — the tenant's routing resolves it like
    /// any other model.
    ///
    /// Unset means semantic matching is unavailable: a `semantic` preset still
    /// serves exact hits, and each request says so on its audit row rather than
    /// quietly behaving as `exact`.
    #[serde(default)]
    pub embedding_alias: Option<String>,

    /// Hard ceiling on the embedding round-trip. Exceeding it abandons the
    /// semantic lookup and takes the miss — a cache is an optimization, so it
    /// must never become the slowest part of a request.
    #[serde(default = "default_embedding_timeout_ms")]
    pub embedding_timeout_ms: u32,
}

fn default_true() -> bool {
    true
}

fn default_max_entry_kb() -> u32 {
    256
}

/// Budget for one embedding round-trip.
///
/// Sized for an embedding provider reached over the internet, which is the
/// common deployment: measured round trips to a cloud embedder run ~150 ms but
/// tail well past a second, and a budget that clips the tail turns semantic
/// matching off for those requests without the operator ever asking for that.
///
/// The asymmetry sets the number. Failing open means a too-generous budget only
/// costs latency on a provider that is already broken, whereas a too-tight one
/// silently degrades every semantic alias to exact-only — which reads exactly
/// like "semantic matching does not work". Size it for the tail, not the median:
/// a probe of the *same* model at 247 ms proves reachability, never headroom.
fn default_embedding_timeout_ms() -> u32 {
    3_000
}

impl Default for CacheSettings {
    fn default() -> Self {
        Self {
            enabled: default_true(),
            max_entry_kb: default_max_entry_kb(),
            embedding_alias: None,
            embedding_timeout_ms: default_embedding_timeout_ms(),
        }
    }
}

impl CacheSettings {
    /// Per-entry ceiling in bytes, as the store wants it.
    pub fn max_entry_bytes(&self) -> usize {
        self.max_entry_kb as usize * 1024
    }

    pub fn embedding_timeout(&self) -> Duration {
        Duration::from_millis(self.embedding_timeout_ms as u64)
    }
}

// ---------------------------------------------------------------------------
// Key
// ---------------------------------------------------------------------------

/// Fully-qualified cache key. Every field is part of the identity — two entries
/// differing in any one of them are different answers.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct CacheKey {
    pub tenant_id: Uuid,
    /// Share-scope discriminator (workspace id / user id / nil).
    pub partition_id: Uuid,
    /// The alias binding this answer was computed under. Also the flush grain.
    pub route_id: Uuid,
    /// Upstream model + preset + response policy (`identity_hash`).
    pub identity: [u8; 32],
    /// The client's request, as `content_hash` reads it.
    pub content: [u8; 32],
}

/// The set of entries a semantic lookup is allowed to consider: everything that
/// must match exactly, with only the final user message left to vary.
///
/// It is the [`CacheKey`] with `content` replaced by the prefix guard, so a
/// candidate found here becomes a full key by pairing the bucket with the
/// candidate's own content hash.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct SemanticBucket {
    pub tenant_id: Uuid,
    pub partition_id: Uuid,
    pub route_id: Uuid,
    pub identity: [u8; 32],
    /// See `semantic_of` — covers the embedding alias too.
    pub prefix: [u8; 32],
    /// The embedding model that produced every vector in this bucket.
    ///
    /// The alias alone is not enough: one alias can resolve to several embedding
    /// models (load-balanced targets round-robin per call) and can be re-pointed
    /// at a different model. Vectors from different models are not comparable —
    /// with equal dimensions the cosine is a meaningless number that can still
    /// clear the threshold — so the producing model is part of the bucket
    /// identity. Two models therefore occupy two buckets, each internally
    /// consistent, and a re-point simply leaves the old bucket to expire.
    pub embed_model: [u8; 32],
}

impl SemanticBucket {
    /// The full key of one member of this bucket.
    fn key_for(&self, content: [u8; 32]) -> CacheKey {
        CacheKey {
            tenant_id: self.tenant_id,
            partition_id: self.partition_id,
            route_id: self.route_id,
            identity: self.identity,
            content,
        }
    }
}

/// A stored entry's position in the semantic index: which bucket it belongs to
/// and the vector that represents its prompt.
#[derive(Debug, Clone)]
pub struct SemanticIndexEntry {
    pub bucket: SemanticBucket,
    pub embedding: std::sync::Arc<[f32]>,
}

/// Cosine similarity, with every degenerate case collapsing to "no match".
///
/// A dimension mismatch means the vectors came from different embedding models.
/// The producing model is part of the bucket identity, so members of one bucket
/// are comparable by construction and this is a backstop rather than the primary
/// guard — which matters, because equal-dimension vectors from different models
/// would pass this check while comparing as meaningless numbers that can still
/// clear the threshold. Do not weaken `SemanticBucket::embed_model` on the
/// assumption that this catches a model mix-up: it only catches the subset that
/// happens to differ in width. `-1.0` can never clear a threshold, which is
/// bounded to `(0, 1]`.
fn cosine(a: &[f32], b: &[f32]) -> f32 {
    if a.len() != b.len() || a.is_empty() {
        return -1.0;
    }
    let mut dot = 0.0f32;
    let mut norm_a = 0.0f32;
    let mut norm_b = 0.0f32;
    for (x, y) in a.iter().zip(b.iter()) {
        dot += x * y;
        norm_a += x * x;
        norm_b += y * y;
    }
    if norm_a <= 0.0 || norm_b <= 0.0 || !dot.is_finite() {
        return -1.0;
    }
    let sim = dot / (norm_a.sqrt() * norm_b.sqrt());
    if sim.is_finite() { sim } else { -1.0 }
}

/// Feeds `serde_json` output straight into a digest without an intermediate
/// `Vec<u8>`.
struct HashWriter<'a>(&'a mut Sha256);

impl std::io::Write for HashWriter<'_> {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.update(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Hash a `serde_json::Value` canonically. `serde_json`'s object map is a
/// `BTreeMap` in this build (no `preserve_order` feature), so key order is
/// sorted and the byte stream is stable across runs and across the protocol the
/// value was parsed from.
fn hash_json(h: &mut Sha256, v: &serde_json::Value) {
    let _ = serde_json::to_writer(HashWriter(h), v);
}

/// Length-prefix a field so `("ab", "c")` and `("a", "bc")` can never collide.
fn hash_str(h: &mut Sha256, s: &str) {
    h.update((s.len() as u64).to_le_bytes());
    h.update(s.as_bytes());
}

fn hash_opt_str(h: &mut Sha256, s: Option<&str>) {
    match s {
        Some(v) => {
            h.update([1u8]);
            hash_str(h, v);
        }
        None => h.update([0u8]),
    }
}

/// The members of a request body the key leaves out, each changing nothing
/// the model answers: the model (the route keys it), whether and how the
/// answer streams (a streamed and a whole answer are one answer, rendered
/// differently), and the caller's identity and bookkeeping (`user`,
/// `safety_identifier`, the provider prompt cache's key and retention,
/// `metadata` — keying them would split every shared-scope cache per user).
/// `store` keys: a Responses answer stored upstream has an id a later
/// `previous_response_id` names, one not stored has none.
const UNKEYED: &[&str] = &[
    "model",
    "stream",
    "stream_options",
    "user",
    "safety_identifier",
    "prompt_cache_key",
    "prompt_cache_retention",
    "metadata",
];

/// The request as the key reads it: its protocol, the `anthropic-beta` header
/// (forwarded to an Anthropic upstream, where it changes what the model does),
/// and its body as a same-protocol forward sends it, without [`UNKEYED`].
/// What the gateway models of a request is lossy — a member it does not model,
/// where a message's text parts break — so the key reads the client's own
/// request, and a difference anywhere in it is another request. The same
/// request sent on two protocols is two entries.
struct Keyed {
    protocol: u8,
    beta: Option<String>,
    body: serde_json::Value,
    /// The request's own values of the [`CALLER_ECHOED`] members the key left
    /// out — what a served answer must carry in place of its producer's.
    caller: serde_json::Map<String, serde_json::Value>,
}

/// `None` when the body cannot be serialized: the request is then not cached
/// at all, never keyed by a placeholder two requests would share.
fn keyed(request: &ApiRequest, headers: &axum::http::HeaderMap) -> Option<Keyed> {
    let protocol = match request {
        ApiRequest::ChatCompletions(_) => 1u8,
        ApiRequest::Responses(_) => 2,
        ApiRequest::AnthropicMessages(_) => 3,
        ApiRequest::GoogleGemini(_) => 4,
    };
    let mut body = request.wire_value()?;
    let members = body.as_object_mut()?;
    let mut caller = serde_json::Map::new();
    for key in UNKEYED {
        if let Some(value) = members.remove(*key)
            && CALLER_ECHOED.contains(key)
        {
            caller.insert((*key).to_string(), value);
        }
    }
    let beta = headers.get("anthropic-beta").map(|v| String::from_utf8_lossy(v.as_bytes()).into_owned());
    Some(Keyed { protocol, beta, body, caller })
}

/// The [`UNKEYED`] members that name the CALLER — who asked and the caller's
/// bookkeeping — and that a response may echo back at its top level (an
/// OpenAI Responses object carries `metadata`, `user`, `safety_identifier`,
/// `prompt_cache_key` and `prompt_cache_retention`). Two callers share an entry
/// exactly because the key leaves these out, so a served answer carries the
/// requester's own values, never the producer's.
const CALLER_ECHOED: &[&str] = &["user", "safety_identifier", "prompt_cache_key", "prompt_cache_retention", "metadata"];

/// Put the requester's own [`CALLER_ECHOED`] values into a stored answer's
/// body: each member the body carries at its top level takes the request's
/// value, or — when the request sent none — the value an upstream reports for
/// an absent one (`metadata` an empty object, every other member `null`). A
/// member the body does not carry is never added.
fn restamp_caller(body: &mut serde_json::Value, caller: &serde_json::Map<String, serde_json::Value>) {
    let Some(members) = body.as_object_mut() else { return };
    for key in CALLER_ECHOED {
        if let Some(slot) = members.get_mut(*key) {
            *slot = match caller.get(*key) {
                Some(value) => value.clone(),
                None if *key == "metadata" => serde_json::Value::Object(serde_json::Map::new()),
                None => serde_json::Value::Null,
            };
        }
    }
}

fn hash_keyed(h: &mut Sha256, keyed: &Keyed) {
    h.update([keyed.protocol]);
    hash_opt_str(h, keyed.beta.as_deref());
    hash_json(h, &keyed.body);
}

fn content_of(keyed: &Keyed) -> [u8; 32] {
    let mut h = Sha256::new();
    hash_keyed(&mut h, keyed);
    h.finalize().into()
}


/// The final conversation item with its text blanked: what the semantic
/// prefix keeps of it. Only the text the query reads is blanked — the item
/// itself when it is a string (a Responses `input`), its `content` string, and
/// the `text` of each part in its `content` or `parts` — so every other member
/// (a `name`, a part's settings, how many parts) still has to match exactly.
fn without_text(item: &mut serde_json::Value) {
    match item {
        serde_json::Value::String(text) => text.clear(),
        serde_json::Value::Object(members) => {
            for key in ["content", "parts"] {
                match members.get_mut(key) {
                    Some(serde_json::Value::String(text)) => text.clear(),
                    Some(serde_json::Value::Array(parts)) => {
                        for part in parts {
                            if let Some(serde_json::Value::String(text)) = part.get_mut("text") {
                                text.clear();
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        _ => {}
    }
}


/// The two halves semantic mode needs: the **prefix guard** and the text to
/// embed.
///
/// Semantic matching relaxes exactly one thing — the wording of the final user
/// message. Everything else (system prompt, the entire preceding history, tool
/// definitions, response format) must still match bit-for-bit, so two requests
/// with different instructions or different histories can never collide however
/// similar their last question reads. The embedding alias is mixed into the
/// prefix as well: changing it makes previously-stored vectors incomparable, so
/// they must not share a bucket with vectors from the new model.
///
/// `None` — semantic matching does not apply, and the request falls back to
/// exact matching — when the conversation's shape makes it unsafe:
///
/// - the last message is not the user's (an assistant prefill or a tool result
///   changes what the model is being asked to do), or
/// - it carries anything but text (an image or a document drives the answer, and
///   only the text is embedded), or
/// - its text is blank (nothing to embed; every blank prompt would match every
///   other one), or
/// - its text is longer than [`MAX_EMBED_INPUT_BYTES`] — a correctness rule,
///   not a budget. The model reads the whole message, so whatever the
///   *embedding* does not read is a difference the vector cannot represent.
///   Truncating instead of declining would make "10 KB document + summarise the
///   risks" and "the same document + list the parties" embed to identical
///   bytes: a similarity of exactly 1.0, which no threshold rejects and the
///   prefix guard cannot catch, because the difference lives in the part that
///   was cut.
///
/// Takes the request as the key read it, and blanks its body in place.
fn semantic_of(request: &ApiRequest, mut keyed: Keyed, embedding_alias: &str) -> Option<SemanticRequest> {
    let body = &mut keyed.body;
    // The final conversation item, converted alone, is the one message
    // matched by meaning: it must be exactly one user message of text. An item
    // the gateway reads as more than one message (an Anthropic user turn
    // holding tool results beside its text) is matched exactly.
    let (items_key, _) = request.conversation_keys();
    let last = match body.get(items_key)? {
        serde_json::Value::Array(items) => items.len().checked_sub(1)?,
        // A Responses `input` given as a string is its one user message.
        serde_json::Value::String(_) => 0,
        _ => return None,
    };
    let item = DomainRequest::item_conversation(request, last);
    let [DomainMessage { role: DomainRole::User, content }] = item.as_slice() else {
        return None;
    };
    let mut query = String::new();
    for block in content {
        match block {
            DomainContentBlock::Text { text, .. } => {
                if !query.is_empty() {
                    query.push('\n');
                }
                query.push_str(text);
            }
            _ => return None,
        }
    }
    if query.trim().is_empty() || query.len() > MAX_EMBED_INPUT_BYTES {
        return None;
    }

    // The prefix is the whole request but that item's text.
    match body.get_mut(items_key) {
        Some(serde_json::Value::Array(items)) => items.last_mut().into_iter().for_each(without_text),
        Some(item) => without_text(item),
        None => {}
    }
    let mut h = Sha256::new();
    hash_str(&mut h, embedding_alias);
    hash_keyed(&mut h, &keyed);
    Some(SemanticRequest {
        prefix: h.finalize().into(),
        query,
    })
}

/// What a semantic lookup needs from the request: the exact-match guard and the
/// text whose meaning may vary.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SemanticRequest {
    pub prefix: [u8; 32],
    pub query: String,
}

/// Longest question the gateway will represent as a vector.
///
/// The whole question must fit, because a vector built from part of it cannot
/// distinguish requests that differ in the rest — see `semantic_of`,
/// which declines rather than truncates. Deliberately conservative: it sits
/// well under the context window of the embedding models a tenant is likely to
/// name, since an upstream that truncates internally reintroduces exactly the
/// collision this bound exists to prevent, and the gateway cannot see that
/// happen. Set an embedding model whose window exceeds this.
pub const MAX_EMBED_INPUT_BYTES: usize = 8192;

/// Identity of the **response-phase policy** a stored answer was shaped by.
///
/// A stored body is captured *after* the storing request's response transforms
/// ran, and a hit is served without re-running them. Two workspaces can resolve
/// different transform profiles, and `share_scope` `tenant`/`user` lets an entry
/// cross between them — so without this in the key, workspace B would be served
/// a body shaped by workspace A's programs while B's own were silently skipped.
/// Folding it into the identity also covers the temporal case: editing a
/// program changes its `version_hash`, so entries stored under the old one
/// become unreachable instead of serving stale output until TTL.
///
/// Deliberately conservative: every response-phase program counts, including
/// ones whose `model_filter`/`app_filter` would exclude this particular request.
/// Being too specific costs a miss; being too loose serves the wrong body.
///
/// Request-phase programs need no such treatment — the lookup runs on the
/// already-transformed request, so a request-phase difference changes
/// `content_hash` on its own.
pub fn response_policy_hash(programs: &[crate::scripting::TransformProgram]) -> [u8; 32] {
    let mut relevant: Vec<&crate::scripting::TransformProgram> = programs
        .iter()
        .filter(|p| p.enabled && p.phase == "response")
        .collect();
    // The effective set is resolved per profile and its order is not guaranteed
    // stable across snapshot builds; sort so an identical policy always hashes
    // identically.
    relevant.sort_by(|a, b| a.id.cmp(&b.id));
    let mut h = Sha256::new();
    h.update((relevant.len() as u64).to_le_bytes());
    for p in relevant {
        hash_str(&mut h, &p.id);
        // `version_hash` alone is NOT enough: it tracks the program's `source`
        // only, so editing a trigger, a filter, the scope, the match mode or the
        // priority would leave every stored entry serving output the new
        // configuration would not produce, until TTL. Hash every field that can
        // change what the program does to a body — `priority` included, because
        // it sets the order programs compose in.
        hash_str(&mut h, &p.version_hash);
        hash_str(&mut h, &p.scope);
        h.update(p.priority.to_le_bytes());
        hash_opt_str(&mut h, p.trigger_regex.as_deref());
        hash_opt_str(&mut h, p.match_mode.as_deref());
        hash_opt_str(&mut h, p.model_filter.as_deref());
        hash_opt_str(&mut h, p.app_filter.as_deref());
    }
    h.finalize().into()
}

/// The identity half of the key: which model, under which invocation preset
/// and response-shaping policy — what decides the answer beside the request,
/// whose every member the content half reads ([`content_hash`]).
///
/// `preset_settings` is the resolved preset for the target **actually**
/// forwarded to — preset merge happens per-target inside the failover loop, so
/// the route row alone is not enough.
pub fn identity_hash(
    upstream_model: &str,
    upstream_model_id: Option<&str>,
    preset_settings: &serde_json::Value,
    response_policy: &[u8; 32],
) -> [u8; 32] {
    let mut h = Sha256::new();
    hash_str(&mut h, upstream_model);
    hash_opt_str(&mut h, upstream_model_id);
    hash_json(&mut h, preset_settings);
    h.update(response_policy);
    h.finalize().into()
}

// ---------------------------------------------------------------------------
// Per-request context — the one entry point the hot path calls
// ---------------------------------------------------------------------------

/// The cache decision for one request: which entry (if any) may be served, what
/// key a store would use, and the audit badges the outcome earns.
///
/// Absent entirely when the alias has no cache preset or the tenant switched
/// caching off, which is the zero-cost path — no key is hashed at all.
pub struct RequestCacheContext {
    pub key: CacheKey,
    pub policy: CachePolicy,
    pub max_entry_bytes: usize,
    /// The entry to serve. `None` on a miss, in `observe` mode, or when the
    /// client asked to bypass.
    pub served: Option<CachedResponse>,
    /// Age of an entry that matched but was NOT served (observe mode).
    observed_age: Option<Duration>,
    /// What serving the matched entry would have saved, at the alias's current
    /// rates. Zero on a miss.
    avoided_cost: f64,
    /// Cosine similarity of a semantic match. `None` on an exact match — the
    /// two are distinguishable on the audit row, which is what makes an
    /// observe-mode run answer "how many of these need semantic at all?".
    similarity: Option<f32>,
    /// Where a stored answer would sit in the semantic index. Present only when
    /// the alias does semantic matching, the request's shape supports it, and
    /// the prompt was embedded successfully.
    pub semantic: Option<SemanticIndexEntry>,
    /// The semantic stage's prefix and query, read with the key; `None` when
    /// the alias does not match by meaning or the request's shape cannot be.
    semantic_request: Option<SemanticRequest>,
    /// Why semantic matching could not run, when the alias asked for it. Purely
    /// operator-facing: an alias configured for semantic that silently degrades
    /// to exact is the failure mode nobody would otherwise notice.
    semantic_skipped: Option<&'static str>,
    /// Client sent `Cache-Control: no-cache` — neither read nor written.
    pub bypass: bool,
    /// The request asked for more than one alternative answer (`n` /
    /// `candidateCount`). Decided from the REQUEST, not the response body,
    /// because a streaming store has no body to inspect — and the SSE parser
    /// folds every choice's deltas into one accumulator, so a multi-choice
    /// stream would be stored as a garbled merge of all of them.
    pub multi_choice_request: bool,
    /// Time spent waiting on the embedding upstream. Subtracted from the proxy
    /// overhead sample: that metric means "what the gateway itself added" and is
    /// what an operator watches for a gateway regression, so charging a third
    /// party's latency to it would read as the proxy having got slower.
    pub embed_elapsed: Duration,
    /// What the embedding call cost, priced at the embed target's own rates when
    /// the call was made. Charged to this request — it is the request that
    /// caused it. Zero when nothing was embedded.
    ///
    /// **Priced at the source, never later.** A cache hit deliberately zeroes
    /// the request's pricing before the audit stage, so a figure derived there
    /// would be `$0` on precisely the rows a semantic cache exists to produce.
    pub embedding_cost: f64,
    /// Whether [`Self::embedding_cost`] is a real figure. False when the
    /// embedding model had no usable price — the triggering request badges
    /// itself so the zero is diagnosable instead of passing as free.
    pub embedding_priced: bool,
    /// Prompt tokens the embedding consumed. Reported alongside its cost and
    /// deliberately kept out of the request's own `prompt_tokens`.
    pub embedding_tokens: u32,
    /// The request's own values of the members a stored answer may echo of its
    /// producer ([`CALLER_ECHOED`]); [`Self::accept`] writes them into the
    /// entry it serves.
    caller: serde_json::Map<String, serde_json::Value>,
}

impl RequestCacheContext {
    /// Badges this outcome contributes to the request's audit row.
    pub fn badges(&self) -> Vec<crate::audit::AuditBadge> {
        let mut out = Vec::new();
        if self.bypass {
            out.push(crate::audit::AuditBadge::CacheStoreSkipped {
                reason: "client_bypass".to_string(),
            });
            return out;
        }
        if let Some(entry) = &self.served {
            out.push(crate::audit::AuditBadge::CacheHit {
                avoided_cost: self.avoided_cost,
                age_seconds: entry.age().as_secs(),
                similarity: self.similarity,
            });
        } else if let Some(age) = self.observed_age {
            out.push(crate::audit::AuditBadge::CacheObserveHit {
                age_seconds: age.as_secs(),
                similarity: self.similarity,
            });
        }
        if let Some(reason) = self.semantic_skipped {
            out.push(crate::audit::AuditBadge::CacheSemanticSkipped {
                reason: reason.to_string(),
            });
        }
        out
    }

    /// This outcome as it lands on the audit row.
    ///
    /// `avoided_cost` is what the upstream call this request skipped would
    /// have cost. It is zero unless an entry matched, and counts as money
    /// *saved* only on [`CacheOutcome::Hit`] — under observe the request still
    /// goes upstream and is billed, so there the same figure means "what
    /// enforcing would have saved".
    pub fn audit(&self) -> CacheAudit {
        let outcome = if self.bypass {
            CacheOutcome::Bypass
        } else if self.served.is_some() {
            CacheOutcome::Hit
        } else if self.observed_age.is_some() {
            CacheOutcome::ObserveHit
        } else {
            CacheOutcome::Miss
        };
        CacheAudit { mode: self.policy.mode, outcome, avoided_cost: self.avoided_cost }
    }

    /// A served hit must not be stored again, and a bypass stores nothing.
    ///
    /// An observe-mode match is also left alone: re-storing would reset the
    /// entry's `stored_at`, so `cache_observe_hit.age_seconds` would report time
    /// since the last identical request instead of true entry age — destroying
    /// the tuning signal observe mode exists to produce.
    pub fn should_store(&self) -> bool {
        !self.bypass && self.served.is_none() && self.observed_age.is_none()
    }
}

/// Whether the client asked to skip the cache for this request.
///
/// Only `no-cache` and `no-store` are honoured — the two directives that mean
/// "don't give me a stored copy". Other `Cache-Control` values (`max-age`, …)
/// are ignored rather than guessed at.
fn client_requests_bypass(headers: &axum::http::HeaderMap) -> bool {
    headers
        .get(axum::http::header::CACHE_CONTROL)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| {
            v.split(',')
                .any(|d| matches!(d.trim(), "no-cache" | "no-store"))
        })
}

/// Resolve the cache decision for one request.
///
/// Returns `None` — doing no work at all — when the alias binds no cache preset
/// or the tenant's master switch is off.
#[allow(clippy::too_many_arguments)]
pub fn request_context(
    cache: &ResponseCache,
    config: &crate::config::TenantConfig,
    target: &super::routing::UpstreamTarget,
    request: &crate::api::ApiRequest,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    headers: &axum::http::HeaderMap,
    response_programs: &[crate::scripting::TransformProgram],
) -> Option<RequestCacheContext> {
    if !config.cache.enabled {
        return None;
    }
    let policy = target.cache?;
    // A target with no alias binding (BYOK pass-through) has no cache identity.
    let route_id = target.route_id?;

    let Some(keyed) = keyed(request, headers) else {
        tracing::warn!(route_id = %route_id, "response cache skipped: the request body could not be serialized for its key");
        return None;
    };
    let content = content_of(&keyed);
    let multi_choice_request = asks_for_multiple_answers(&keyed.body);
    let key = CacheKey {
        tenant_id,
        partition_id: policy.share_scope.partition_id(Some(workspace_id), user_id),
        route_id,
        identity: identity_hash(
            &target.model,
            target.upstream_model_id.as_deref(),
            &target.preset_settings,
            &response_policy_hash(response_programs),
        ),
        content,
    };

    let bypass = client_requests_bypass(headers);
    let mut ctx = RequestCacheContext {
        key,
        policy,
        max_entry_bytes: config.cache.max_entry_bytes(),
        served: None,
        observed_age: None,
        avoided_cost: 0.0,
        similarity: None,
        semantic: None,
        semantic_skipped: None,
        bypass,
        multi_choice_request,
        semantic_request: None,
        embed_elapsed: Duration::ZERO,
        embedding_cost: 0.0,
        embedding_priced: true,
        embedding_tokens: 0,
        caller: keyed.caller.clone(),
    };
    if bypass {
        return Some(ctx);
    }

    if let Some(entry) = cache.get(&ctx.key, policy.ttl()) {
        ctx.accept(entry, None, &target.pricing, config);
        return Some(ctx);
    }
    // An exact miss: the semantic stage's prefix and query, from the same
    // reading of the request — the body is blanked in place, never copied
    // again.
    ctx.semantic_request = config
        .cache
        .embedding_alias
        .as_deref()
        .filter(|a| !a.is_empty() && matches_semantically(policy.mode))
        .and_then(|alias| semantic_of(request, keyed, alias));
    Some(ctx)
}

impl RequestCacheContext {
    /// Record a matched entry as this request's outcome, pricing what it saved
    /// BEFORE the row's own pricing is zeroed — the savings figure is the cost
    /// the upstream call would have incurred.
    ///
    /// An `observe` preset takes the same match but does not serve it, so the
    /// request still goes upstream and is billed normally.
    fn accept(
        &mut self,
        entry: CachedResponse,
        similarity: Option<f32>,
        pricing: &crate::pricing::Rates,
        config: &crate::config::TenantConfig,
    ) {
        // Stated in the tenant's accounting currency, like every other figure on
        // the row — a saving reported in the provider's currency could not be
        // added to the spend it is compared against.
        self.avoided_cost = pricing
            .bill(
                &entry.usage.billed_units(),
                config.pricing.accounting_currency,
                &config.pricing.fx,
            )
            .amount();
        self.similarity = similarity;
        if self.policy.mode.serves() {
            let mut entry = entry;
            restamp_caller(&mut entry.body, &self.caller);
            self.served = Some(entry);
        } else {
            self.observed_age = Some(entry.age());
        }
    }
}

/// Did the client ask for more than one alternative answer?
///
/// Read off the request body the key reads, not the response, so it holds for a
/// streaming request that has no body yet.
fn asks_for_multiple_answers(body: &serde_json::Value) -> bool {
    // Chat Completions `n`, Gemini `generationConfig.candidateCount`.
    [body.get("n"), body.pointer("/generationConfig/candidateCount")]
        .into_iter()
        .flatten()
        .filter_map(serde_json::Value::as_u64)
        .any(|n| n > 1)
}

/// Whether this alias does semantic matching at all.
///
/// `Observe` is included on purpose: its whole job is to show an admin what
/// enforcing would do, and the number they need to see is the similarity of the
/// nearest stored prompt. An exact match under `observe` reports no similarity,
/// so one observe run distinguishes "exact matching would already have served
/// this" from "only semantic matching would".
fn matches_semantically(mode: CacheMode) -> bool {
    matches!(mode, CacheMode::Semantic | CacheMode::Observe)
}

/// Second-stage lookup for a semantic alias: embed this request's final user
/// message and find the nearest stored prompt behind the same prefix guard.
///
/// Runs only after [`request_context`] has already missed on the exact key, so
/// a repeated identical request never pays for an embedding. Every failure —
/// no alias configured, upstream error, timeout — leaves the request as a plain
/// miss and badges why; the cache must never turn a working request into a
/// failed one.
///
/// Also produces the [`SemanticIndexEntry`] a later store files the answer
/// under, so the embedding computed here is paid for once per miss.
pub async fn semantic_lookup(
    state: &super::AppState,
    user: &crate::auth::UserContext,
    config: &crate::config::TenantConfig,
    target: &super::routing::UpstreamTarget,
    ctx: &mut RequestCacheContext,
) {
    if ctx.bypass || ctx.served.is_some() || ctx.observed_age.is_some() {
        return;
    }
    if !matches_semantically(ctx.policy.mode) {
        return;
    }
    let Some(alias) = config.cache.embedding_alias.as_deref().filter(|a| !a.is_empty()) else {
        ctx.semantic_skipped = Some("no_embedding_alias");
        return;
    };

    // A request whose shape semantic matching cannot handle is served exactly,
    // which is complete and correct — there is nothing for an operator to fix,
    // so it is not badged.
    let Some(parts) = ctx.semantic_request.take() else {
        return;
    };

    let started = Instant::now();
    let embedded = super::cache_embed::embed(state, user, config, alias, &parts.query).await;
    ctx.embed_elapsed = started.elapsed();
    let (embedding, embed_model) = match embedded {
        Ok(e) => {
            // Charged to this request whatever happens next: the call was made,
            // and it is made on a miss as much as on a hit. Recorded here, once,
            // at the only point that knows the embed target's own rates.
            ctx.embedding_cost = e.cost;
            ctx.embedding_priced = e.priced;
            ctx.embedding_tokens = e.tokens;
            let mut h = Sha256::new();
            hash_str(&mut h, &e.model_key);
            (std::sync::Arc::<[f32]>::from(e.vector), h.finalize().into())
        }
        Err(reason) => {
            ctx.semantic_skipped = Some(reason);
            return;
        }
    };

    let bucket = SemanticBucket {
        tenant_id: ctx.key.tenant_id,
        partition_id: ctx.key.partition_id,
        route_id: ctx.key.route_id,
        identity: ctx.key.identity,
        prefix: parts.prefix,
        // Not known until the embedding call returns which model served it.
        embed_model,
    };
    if let Some((entry, similarity)) = state.response_cache.get_semantic(
        &bucket,
        &embedding,
        ctx.policy.threshold,
        ctx.policy.ttl(),
    ) {
        ctx.accept(entry, Some(similarity), &target.pricing, config);
        return;
    }
    // A miss: hand the vector to the store so this answer becomes matchable.
    ctx.semantic = Some(SemanticIndexEntry { bucket, embedding });
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// One cached answer. Holds both the served wire body (for the same-protocol
/// fast path, and as the source a stream-stored entry's Chat Completions body
/// is translated from) and the accumulated summary (for re-rendering the
/// answer as SSE).
#[derive(Debug, Clone)]
pub struct CachedResponse {
    /// The client-facing JSON body exactly as it was served.
    pub body: serde_json::Value,
    /// The protocol `body` is written in.
    pub protocol: ApiVersion,
    /// Real upstream model name that produced it (audit attribution).
    pub upstream_model: String,
    pub text: String,
    pub reasoning: String,
    pub finish_reason: Option<FinishReason>,
    pub native_finish_reason: Option<String>,
    pub usage: Usage,
    /// Approximate heap footprint, used for the global byte ceiling.
    pub size_bytes: usize,
    stored_at: Instant,
    expires_at: Instant,
    /// Which semantic bucket indexes this entry, when it has one. Held here so
    /// dropping the entry can retire its index member in the same step — an
    /// index that outlived its entry would keep a vector alive and hand out
    /// candidates that no longer exist.
    bucket: Option<SemanticBucket>,
}

impl CachedResponse {
    pub fn age(&self) -> Duration {
        self.stored_at.elapsed()
    }

    fn is_expired(&self, now: Instant) -> bool {
        now >= self.expires_at
    }

    /// Servable only if it satisfies BOTH the TTL it was stored under and the
    /// one in force now.
    ///
    /// The second half is what makes a preset edit take effect: an admin who
    /// cuts a preset's TTL from a day to five minutes is saying "stop serving
    /// stale answers", and entries already stored under the old TTL must obey
    /// that immediately — otherwise the field the UI presents as governing how
    /// long an answer stays servable is silently wrong for a whole day.
    /// Raising the TTL deliberately does NOT extend an entry past the expiry it
    /// was stored with; a tightening is instant, a loosening only applies to
    /// what is stored after it.
    fn is_stale(&self, now: Instant, max_age: Duration) -> bool {
        self.is_expired(now) || now.duration_since(self.stored_at) >= max_age
    }
}

/// What a caller must supply to store an entry. Separated from [`CachedResponse`]
/// so the TTL and size accounting stay owned by the store.
pub struct StoreRequest {
    pub body: serde_json::Value,
    pub protocol: ApiVersion,
    pub upstream_model: String,
    pub text: String,
    pub reasoning: String,
    pub finish_reason: Option<FinishReason>,
    pub native_finish_reason: Option<String>,
    pub usage: Usage,
    pub ttl: Duration,
    /// Where to index this answer for semantic lookup. `None` on an exact-mode
    /// alias (which needs no vector) and whenever the prompt could not be
    /// embedded — the entry is then stored exact-matchable only.
    pub semantic: Option<SemanticIndexEntry>,
}

/// Why a store was refused. Every variant surfaces as an audit marker — a
/// response that could not be cached is never silently dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StoreRejection {
    /// Entry alone exceeds the per-entry size cap.
    EntryTooLarge,
    /// The global byte ceiling is reached and the storing tenant has nothing of
    /// its own left to evict.
    CacheFull,
}

impl StoreRejection {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::EntryTooLarge => "entry_too_large",
            Self::CacheFull => "cache_full",
        }
    }
}

// ---------------------------------------------------------------------------
// Store
// ---------------------------------------------------------------------------

/// Per-tenant bookkeeping. Keeping insertion order here makes eviction O(1)
/// amortized and confines it to the tenant doing the storing.
#[derive(Default)]
struct TenantState {
    /// Insertion-ordered keys. May hold tombstones for entries already dropped
    /// by TTL-on-read; the eviction loop skips them.
    order: VecDeque<CacheKey>,
    entries: usize,
    bytes: usize,
}

/// One indexed prompt vector. `content` completes its bucket into a full
/// [`CacheKey`].
struct SemanticMember {
    content: [u8; 32],
    embedding: std::sync::Arc<[f32]>,
}

/// Most vectors one bucket will hold. A bucket is one exact prefix on one
/// alias, so it fills with rephrasings of a single question; past a point the
/// extra candidates add cosine work without adding recall. Oldest members are
/// dropped first, which only ever costs a *semantic* match — the entries
/// themselves stay exact-matchable and are evicted on their own schedule.
const MAX_SEMANTIC_MEMBERS_PER_BUCKET: usize = 128;

/// What one replica's cache is holding and how it got there.
///
/// The counters are CUMULATIVE since process start — never reset on read, so a
/// consumer derives a rate by differencing successive samples (the same
/// contract as every other operational metric). The rest are live gauges.
///
/// This is the half of cache health that no audit row can answer: a request's
/// row records what happened to *it*, never what the store is holding or what
/// it gave up to hold it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheStats {
    /// Live entries (gauge).
    pub entries: u64,
    /// Bytes those entries account for (gauge).
    pub bytes: u64,
    /// The global byte ceiling this replica enforces — the denominator for
    /// `bytes`, so a reader never has to know the operator's setting to judge
    /// how full the cache is.
    pub max_bytes: u64,
    /// Prompt vectors currently indexed (gauge), counted live rather than
    /// tracked incrementally: a vector outliving its entry is a pure leak whose
    /// only other symptom is memory, and a maintained counter would drift by the
    /// exact amount it is meant to expose.
    ///
    /// Exceeding `entries` proves a leak; the converse does not hold, since
    /// exact-mode entries carry no vector and a smaller leak hides inside them.
    pub semantic_vectors: u64,
    /// Distinct semantic buckets holding those vectors (gauge).
    pub semantic_buckets: u64,
    /// Answers admitted to the cache.
    pub stores_total: u64,
    /// Entries dropped to make room for a new one — always the storing tenant's
    /// own oldest. Rising against a flat `entries` is the signature of a cache
    /// too small for its traffic: entries are being thrown out before they can
    /// be hit, which reads identically to "nobody repeats prompts" from the
    /// audit side.
    pub evictions_total: u64,
    /// Entries dropped for reaching their TTL, on read or by the sweeper.
    /// Deliberately separate from evictions: expiry is the cache working as
    /// configured, eviction is it running out of room.
    pub expired_total: u64,
}

/// In-memory response cache. One instance per proxy replica, shared via `Arc`.
pub struct ResponseCache {
    entries: dashmap::DashMap<CacheKey, CachedResponse>,
    tenants: dashmap::DashMap<Uuid, TenantState>,
    /// Semantic index: the candidate vectors behind each exact prefix guard.
    /// Kept in step with `entries` by `store`/`drop_entry` — see
    /// [`CachedResponse::bucket`].
    semantic: dashmap::DashMap<SemanticBucket, Vec<SemanticMember>>,
    total_bytes: AtomicUsize,
    max_bytes: usize,
    max_entries_per_tenant: usize,
    /// Cumulative lifetime counters — see [`CacheStats`]. Never reset.
    stores_total: AtomicU64,
    evictions_total: AtomicU64,
    expired_total: AtomicU64,
}

impl std::fmt::Debug for ResponseCache {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ResponseCache")
            .field("entries", &self.entries.len())
            .field("total_bytes", &self.total_bytes.load(Ordering::Relaxed))
            .field("max_bytes", &self.max_bytes)
            .field("max_entries_per_tenant", &self.max_entries_per_tenant)
            .finish()
    }
}

impl ResponseCache {
    pub fn new(max_bytes: usize, max_entries_per_tenant: usize) -> Self {
        Self {
            entries: dashmap::DashMap::new(),
            tenants: dashmap::DashMap::new(),
            semantic: dashmap::DashMap::new(),
            total_bytes: AtomicUsize::new(0),
            max_bytes,
            max_entries_per_tenant,
            stores_total: AtomicU64::new(0),
            evictions_total: AtomicU64::new(0),
            expired_total: AtomicU64::new(0),
        }
    }

    /// Live entry count. Metrics / tests only.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    pub fn total_bytes(&self) -> usize {
        self.total_bytes.load(Ordering::Relaxed)
    }

    /// This replica's occupancy and lifetime counters.
    ///
    /// `semantic_vectors` walks the index, so this is a heartbeat/scrape-rate
    /// call, not a hot-path one.
    pub fn stats(&self) -> CacheStats {
        let mut semantic_vectors = 0u64;
        for bucket in self.semantic.iter() {
            semantic_vectors += bucket.value().len() as u64;
        }
        CacheStats {
            entries: self.entries.len() as u64,
            bytes: self.total_bytes.load(Ordering::Relaxed) as u64,
            max_bytes: self.max_bytes as u64,
            semantic_vectors,
            semantic_buckets: self.semantic.len() as u64,
            stores_total: self.stores_total.load(Ordering::Relaxed),
            evictions_total: self.evictions_total.load(Ordering::Relaxed),
            expired_total: self.expired_total.load(Ordering::Relaxed),
        }
    }

    /// Look up a servable entry, dropping it if it is past its life. Returns a
    /// clone so the shard lock is released before the caller renders anything.
    ///
    /// `max_age` is the TTL of the policy in force RIGHT NOW, which is not
    /// necessarily the one the entry was stored under — see
    /// [`CachedResponse::is_stale`]. A stale entry is dropped rather than just
    /// skipped, so a request that finds an entry the admin has since shortened
    /// out of range reclaims its memory there and then, instead of parking it
    /// until the expiry it was stored with.
    pub fn get(&self, key: &CacheKey, max_age: Duration) -> Option<CachedResponse> {
        let now = Instant::now();
        let mut hit = None;
        let mut stale = false;
        // Scoped so the read guard is released before any mutation — DashMap's
        // per-shard lock is not reentrant, so removing while a `Ref` into the
        // same shard is alive deadlocks.
        if let Some(e) = self.entries.get(key) {
            if e.is_stale(now, max_age) {
                stale = true;
            } else {
                hit = Some(e.clone());
            }
        }
        if stale && self.drop_entry(key) {
            self.expired_total.fetch_add(1, Ordering::Relaxed);
        }
        hit
    }

    /// Find the nearest stored prompt in one semantic bucket.
    ///
    /// Every member of the bucket already shares this request's exact prefix
    /// guard — same system prompt, same history, same tools, same model, same
    /// alias — so the only thing similarity decides is whether the final
    /// question means the same. Returns the closest match at or above
    /// `threshold`, with its similarity, or `None`.
    ///
    /// Candidates are tried in descending similarity rather than assuming the
    /// best one is live: an entry can have been evicted or aged out between
    /// indexing and now, and settling for a *worse* match than the caller's
    /// threshold would be wrong, but skipping to the next-best match at or above
    /// it is exactly right.
    pub fn get_semantic(
        &self,
        bucket: &SemanticBucket,
        query: &[f32],
        threshold: f32,
        max_age: Duration,
    ) -> Option<(CachedResponse, f32)> {
        // Score under the read guard, probe outside it: `get` mutates `entries`
        // and `tenants` on a stale hit, and holding a shard lock across that is
        // how a reentrant deadlock starts.
        let mut ranked: Vec<([u8; 32], f32)> = {
            let members = self.semantic.get(bucket)?;
            members
                .iter()
                .map(|m| (m.content, cosine(query, &m.embedding)))
                .filter(|(_, sim)| *sim >= threshold)
                .collect()
        };
        // Descending similarity. `total_cmp` because a NaN would otherwise make
        // the comparator inconsistent and `sort_by` can panic on that.
        ranked.sort_by(|a, b| b.1.total_cmp(&a.1));

        for (content, sim) in ranked {
            if let Some(entry) = self.get(&bucket.key_for(content), max_age) {
                return Some((entry, sim));
            }
        }
        None
    }

    /// Insert (or replace) an entry.
    ///
    /// `max_entry_bytes` is the per-entry ceiling from tenant settings; the
    /// per-tenant entry cap and the global byte ceiling come from operator
    /// settings. Returns the rejection reason when nothing was stored.
    pub fn store(
        &self,
        key: CacheKey,
        req: StoreRequest,
        max_entry_bytes: usize,
    ) -> Result<(), StoreRejection> {
        let size_bytes = estimate_size(&req);
        if size_bytes > max_entry_bytes {
            return Err(StoreRejection::EntryTooLarge);
        }

        let now = Instant::now();
        let entry = CachedResponse {
            body: req.body,
            protocol: req.protocol,
            upstream_model: req.upstream_model,
            text: req.text,
            reasoning: req.reasoning,
            finish_reason: req.finish_reason,
            native_finish_reason: req.native_finish_reason,
            usage: req.usage,
            size_bytes,
            stored_at: now,
            expires_at: now + req.ttl,
            bucket: req.semantic.as_ref().map(|s| s.bucket.clone()),
        };

        // Everything below runs under the tenant's bookkeeping guard, INCLUDING the
        // map insert. Publishing the entry outside the guard would let a
        // concurrent `flush_tenant` or TTL `drop_entry` interleave between the
        // bookkeeping and the insert, leaving an entry with no accounting behind
        // it (unevictable) or double-decrementing one that was already dropped.
        //
        // Accounting is derived from what `insert` actually returns, never from a
        // separate earlier read, so a racing removal cannot be counted twice.
        let mut state = self.tenants.entry(key.tenant_id).or_default();

        // Reserve room: evict this tenant's own oldest entries until both the
        // per-tenant entry cap and the global byte ceiling admit the new one. The
        // check is deliberately conservative about an overwrite (it does not
        // assume the old copy's bytes come back), so at worst one extra entry is
        // evicted — never too few. Every removal settles the global counter
        // immediately, so `total_bytes` is never transiently wrong for a
        // concurrent storer on another shard.
        //
        // The drain can walk past THIS key's own queue slot. Consuming it without
        // putting one back would leave a live, counted entry in no queue at all —
        // unreachable by eviction until its TTL, and a permanently lost slot that
        // makes the per-tenant cap drift upward. So the slot is remembered here
        // and restored on every exit that leaves a live copy behind. It is
        // restored at exit rather than rotated inside the loop: rotating would
        // spin forever when that slot is the queue's only element.
        let mut popped_own_slot = false;
        // Vectors whose entries this store removes. Retired after the tenant
        // guard is released, so the two maps are never locked at once. Missing
        // this is a pure leak: the byte accounting settles as if the vector went
        // with its entry, while the `Arc` stays alive in its bucket — and it
        // would leak fastest under exactly the memory pressure that causes
        // eviction in the first place.
        let mut orphaned: Vec<(SemanticBucket, [u8; 32])> = Vec::new();
        loop {
            let global_bytes = self.total_bytes.load(Ordering::Relaxed);
            if state.entries < self.max_entries_per_tenant
                && global_bytes + size_bytes <= self.max_bytes
            {
                break;
            }
            let Some(victim) = state.order.pop_front() else {
                // Nothing of our own left to give up. Refuse rather than evicting
                // a neighbour tenant's entries — but any live copy of `key` keeps
                // living, so give it its slot back first.
                if global_bytes + size_bytes > self.max_bytes {
                    if popped_own_slot {
                        state.order.push_back(key);
                    }
                    // This exit still evicted entries on its way here, and their
                    // vectors are retired on the same terms as any other
                    // eviction. Returning straight out would strand exactly the
                    // ones freed under the heaviest memory pressure.
                    drop(state);
                    for (bucket, content) in orphaned {
                        self.retire_semantic(&bucket, content);
                    }
                    return Err(StoreRejection::CacheFull);
                }
                break;
            };
            if victim == key {
                popped_own_slot = true;
                continue; // the slot we are about to overwrite
            }
            // A tombstone (already TTL-dropped) frees nothing but still costs a
            // queue slot, so keep draining.
            if let Some((_, old)) = self.entries.remove(&victim) {
                self.total_bytes.fetch_sub(old.size_bytes, Ordering::Relaxed);
                state.bytes = state.bytes.saturating_sub(old.size_bytes);
                state.entries = state.entries.saturating_sub(1);
                self.evictions_total.fetch_add(1, Ordering::Relaxed);
                if let Some(bucket) = old.bucket {
                    orphaned.push((bucket, victim.content));
                }
            }
        }

        let content = key.content;
        let new_bucket = req.semantic.as_ref().map(|s| &s.bucket);
        match self.entries.insert(key.clone(), entry) {
            // Overwrote a live copy: the entry count is unchanged, and it needs a
            // queue slot only if the drain above consumed the one it had.
            Some(old) => {
                self.total_bytes.fetch_sub(old.size_bytes, Ordering::Relaxed);
                state.bytes = state.bytes.saturating_sub(old.size_bytes) + size_bytes;
                // The replacement may carry no vector (this request could not
                // embed) or sit in a different bucket (the tenant changed
                // embedding model). Either way the old entry's member no longer
                // has an entry claiming it, so nothing would ever retire it.
                if let Some(stale) = old.bucket.filter(|b| Some(b) != new_bucket) {
                    orphaned.push((stale, content));
                }
                if popped_own_slot {
                    state.order.push_back(key);
                }
            }
            // Genuinely new (or the old copy was dropped underneath us): one
            // entry, one slot — whether or not a stale slot was consumed above.
            None => {
                state.bytes += size_bytes;
                state.entries += 1;
                state.order.push_back(key.clone());
            }
        }
        self.total_bytes.fetch_add(size_bytes, Ordering::Relaxed);
        // Release the tenant guard before touching the semantic index: nothing
        // below needs it, and holding two maps' locks at once is a nesting the
        // next reader would have to re-derive as safe.
        drop(state);
        for (bucket, content) in orphaned {
            self.retire_semantic(&bucket, content);
        }
        // Index last: the entry is now published, so a concurrent lookup that
        // finds this vector will find the entry behind it. The reverse order
        // would hand out a candidate key that resolves to nothing.
        if let Some(sem) = req.semantic {
            self.index_semantic(sem, content);
        }
        self.stores_total.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    /// Add (or refresh) one entry's vector in its bucket.
    fn index_semantic(&self, sem: SemanticIndexEntry, content: [u8; 32]) {
        let mut members = self.semantic.entry(sem.bucket).or_default();
        match members.iter_mut().find(|m| m.content == content) {
            // Re-storing the same conversation: same prompt, so the vector is
            // the same too. Replace rather than append, or the bucket would
            // accumulate duplicates of a hot key.
            Some(existing) => existing.embedding = sem.embedding,
            None => {
                if members.len() >= MAX_SEMANTIC_MEMBERS_PER_BUCKET {
                    members.remove(0);
                }
                members.push(SemanticMember {
                    content,
                    embedding: sem.embedding,
                });
            }
        }
    }

    /// Drop every entry bound to one alias. The per-route flush verb.
    pub fn flush_route(&self, tenant_id: Uuid, route_id: Uuid) -> usize {
        self.flush_matching(|k| k.tenant_id == tenant_id && k.route_id == route_id)
    }

    /// Drop every entry belonging to one tenant. The tenant-wide flush verb, and
    /// the cleanup a deleted tenant needs.
    ///
    /// The tenant's bookkeeping row is deliberately left in place — removing it
    /// could race a store that is mid-insert under that guard and orphan the
    /// entry it is about to publish. `prune_expired` reaps empty rows instead.
    pub fn flush_tenant(&self, tenant_id: Uuid) -> usize {
        self.flush_matching(|k| k.tenant_id == tenant_id)
    }

    fn flush_matching(&self, pred: impl Fn(&CacheKey) -> bool) -> usize {
        let victims: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|e| pred(e.key()))
            .map(|e| e.key().clone())
            .collect();
        // Counted from what this flush actually removed, not from the victim
        // list it collected: a concurrent TTL sweep may take an entry between
        // the two, and reporting it here would tell the operator more answers
        // were dropped than existed.
        victims.iter().filter(|k| self.drop_entry(k)).count()
    }

    /// Sweep expired entries and their queue tombstones. Runs on the proxy's
    /// existing background-task cadence — TTL-on-read alone would leave an entry
    /// nobody asks for again resident until eviction pressure reached it.
    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let victims: Vec<CacheKey> = self
            .entries
            .iter()
            .filter(|e| e.value().is_expired(now))
            .map(|e| e.key().clone())
            .collect();
        // Counted from what this sweep actually removed, not from the victim
        // list it collected: `drop_entry` is also the flush path, so an entry a
        // concurrent flush took first is not an expiry.
        let n = victims.iter().filter(|k| self.drop_entry(k)).count();
        self.expired_total.fetch_add(n as u64, Ordering::Relaxed);
        // Compact the per-tenant queues: drop keys whose entries are gone, and
        // forget tenants that no longer hold anything.
        self.tenants.retain(|_, state| {
            state.order.retain(|k| self.entries.contains_key(k));
            state.entries > 0 || !state.order.is_empty()
        });
        // Backstop for the semantic index: drop any vector whose entry is gone
        // and then any bucket left empty, so a tenant that stops using an alias
        // does not leave its prefixes behind forever. Every removal path already
        // retires its own vector; this makes "the index holds only live entries"
        // an invariant of the sweep rather than something each caller has to get
        // right, and a leaked vector is otherwise unbounded and invisible (the
        // byte accounting settles as if it had gone with its entry).
        self.semantic.retain(|bucket, members| {
            members.retain(|m| self.entries.contains_key(&bucket.key_for(m.content)));
            !members.is_empty()
        });
        n
    }

    /// Remove one entry and fix both the tenant and global accounting. The
    /// tenant's `order` keeps a tombstone; `prune_expired` compacts it.
    ///
    /// Returns whether THIS call was the one that removed it. Callers count
    /// their reason off that: `drop_entry` serves the TTL paths and the operator
    /// flush path alike, so a caller that counted unconditionally would book a
    /// removal a racing flush had already performed — reporting a deliberate
    /// flush as cache pressure, or the same expiry twice.
    fn drop_entry(&self, key: &CacheKey) -> bool {
        let Some((_, removed)) = self.entries.remove(key) else {
            return false;
        };
        self.total_bytes
            .fetch_sub(removed.size_bytes, Ordering::Relaxed);
        if let Some(mut state) = self.tenants.get_mut(&key.tenant_id) {
            state.bytes -= removed.size_bytes.min(state.bytes);
            state.entries = state.entries.saturating_sub(1);
        }
        // Retire the vector alongside the answer it points at.
        if let Some(bucket) = &removed.bucket {
            self.retire_semantic(bucket, key.content);
        }
        true
    }

    /// Drop one vector from its bucket. The now-possibly-empty bucket is left
    /// for `prune_expired` to reap rather than removed here, for the same
    /// reason `TenantState` is: removing it could race a store publishing into
    /// it.
    fn retire_semantic(&self, bucket: &SemanticBucket, content: [u8; 32]) {
        if let Some(mut members) = self.semantic.get_mut(bucket) {
            members.retain(|m| m.content != content);
        }
    }
}

/// Approximate heap cost of an entry. The JSON body dominates; the accumulated
/// text is counted separately because the summary is what streaming hits replay.
fn estimate_size(req: &StoreRequest) -> usize {
    let body = serde_json::to_string(&req.body).map(|s| s.len()).unwrap_or(0);
    // The prompt vector is charged to the entry that owns it — at a few
    // thousand dimensions it is not a rounding error, and the byte ceiling has
    // to see it or a semantic alias would silently overrun its budget.
    let vector = req
        .semantic
        .as_ref()
        .map(|s| s.embedding.len() * std::mem::size_of::<f32>())
        .unwrap_or(0);
    body + req.text.len() + req.reasoning.len() + req.upstream_model.len() + vector + 256
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    /// The content half of the key for a request sent with no header the key
    /// reads — the hot path keys its headers too (`request_context`).
    pub(crate) fn content_hash(request: &ApiRequest) -> Option<[u8; 32]> {
        Some(content_of(&keyed(request, &axum::http::HeaderMap::new())?))
    }

    /// The semantic stage's prefix and query for a request sent with no header
    /// the key reads (see `semantic_of`).
    pub(crate) fn semantic_request(request: &ApiRequest, embedding_alias: &str) -> Option<SemanticRequest> {
        semantic_of(request, keyed(request, &axum::http::HeaderMap::new())?, embedding_alias)
    }

    fn key(tenant: Uuid, partition: Uuid, route: Uuid, tag: u8) -> CacheKey {
        CacheKey {
            tenant_id: tenant,
            partition_id: partition,
            route_id: route,
            identity: [tag; 32],
            content: [tag; 32],
        }
    }

    fn store_req(ttl_secs: u64) -> StoreRequest {
        store_req_semantic(ttl_secs, None)
    }

    fn store_req_semantic(ttl_secs: u64, semantic: Option<SemanticIndexEntry>) -> StoreRequest {
        StoreRequest {
            semantic,
            body: serde_json::json!({"choices": [{"message": {"content": "hi"}}]}),
            protocol: ApiVersion::ChatCompletions,
            upstream_model: "gpt-4o".to_string(),
            text: "hi".to_string(),
            reasoning: String::new(),
            finish_reason: Some(FinishReason::Stop),
            native_finish_reason: Some("stop".to_string()),
            usage: Usage {
                prompt_tokens: 10,
                completion_tokens: 2,
                total_tokens: 12,
                ..Default::default()
            },
            ttl: Duration::from_secs(ttl_secs),
        }
    }

    const BIG: usize = 1 << 20;

    /// A context in `mode` with nothing matched yet.
    fn ctx_for(mode: CacheMode) -> RequestCacheContext {
        RequestCacheContext {
            key: key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1),
            policy: CachePolicy {
                mode,
                ttl_seconds: 60,
                threshold: 0.9,
                share_scope: CacheShareScope::Workspace,
            },
            max_entry_bytes: BIG,
            multi_choice_request: false,
            served: None,
            observed_age: None,
            avoided_cost: 0.0,
            similarity: None,
            semantic: None,
            semantic_request: None,
            semantic_skipped: None,
            bypass: false,
            embed_elapsed: Duration::ZERO,
            embedding_cost: 0.0,
            embedding_priced: true,
            embedding_tokens: 0,
            caller: serde_json::Map::new(),
        }
    }

    fn stored_entry() -> CachedResponse {
        let cache = ResponseCache::new(BIG, 8);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        cache.store(k.clone(), store_req(60), BIG).expect("stored");
        cache.get(&k, Duration::from_secs(60)).expect("just stored")
    }

    /// The audit row must distinguish a match that was *served* from one that
    /// was only recorded. Collapsing them would make an observe run — where the
    /// request still goes upstream and is billed — report as money saved.
    #[test]
    fn an_observe_match_is_never_recorded_as_a_hit() {
        use crate::pricing::{Currency, Rate, Rates, Unit};
        let pricing = Rates::from_units(
            std::collections::BTreeMap::from([
                (Unit::InputToken, Rate::Flat(1000.0)),
                (Unit::OutputToken, Rate::Flat(1000.0)),
            ]),
            Currency::USD,
        );
        let config = crate::config::TenantConfig::default();

        let mut enforcing = ctx_for(CacheMode::Exact);
        enforcing.accept(stored_entry(), None, &pricing, &config);
        let enforcing = enforcing.audit();
        assert_eq!(enforcing.outcome, CacheOutcome::Hit);
        assert!(enforcing.avoided_cost > 0.0, "a hit on a priced model saved real money");

        let mut observing = ctx_for(CacheMode::Observe);
        observing.accept(stored_entry(), None, &pricing, &config);
        let observing = observing.audit();
        assert_eq!(observing.outcome, CacheOutcome::ObserveHit);
        // The same counterfactual is recorded — it is what an observe run is
        // for — but the outcome is what stops it being summed as savings.
        assert!(observing.avoided_cost > 0.0);
    }

    /// Two callers share an entry because the key leaves out who they are, so
    /// the answer one stored must reach the other carrying the second caller's
    /// own `metadata`, `safety_identifier`, `prompt_cache_key` and `user`, never
    /// the first one's (an OpenAI Responses object echoes each of them).
    #[test]
    fn a_served_answer_carries_the_requesters_own_caller_fields() {
        let ask = |caller: serde_json::Value| {
            let mut body = serde_json::json!({"model": "m", "input": "hello"});
            for (k, v) in caller.as_object().expect("object") {
                body[k] = v.clone();
            }
            domain_request(ApiVersion::Responses, body)
        };
        let producer = ask(serde_json::json!({
            "metadata": {"account": "a-1"}, "safety_identifier": "user-a",
            "prompt_cache_key": "conv-a", "user": "alice",
        }));
        let requester = ask(serde_json::json!({"metadata": {"account": "b-2"}, "safety_identifier": "user-b"}));
        let headers = axum::http::HeaderMap::new();
        let (a, b) = (keyed(&producer, &headers).unwrap(), keyed(&requester, &headers).unwrap());
        // Positive control: the two requests ARE one entry, so a hit is served.
        assert_eq!(content_of(&a), content_of(&b));

        let cache = ResponseCache::new(BIG, 8);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        let mut stored = store_req(60);
        stored.protocol = ApiVersion::Responses;
        stored.body = serde_json::json!({
            "id": "resp_1", "object": "response", "output": [],
            "metadata": {"account": "a-1"}, "safety_identifier": "user-a",
            "prompt_cache_key": "conv-a", "user": "alice",
        });
        cache.store(k.clone(), stored, BIG).expect("stored");

        let mut ctx = ctx_for(CacheMode::Exact);
        ctx.caller = b.caller;
        let entry = cache.get(&k, Duration::from_secs(60)).expect("stored");
        ctx.accept(entry, None, &crate::pricing::Rates::free(), &crate::config::TenantConfig::default());
        let served = ctx.served.expect("an exact match is served").body;
        assert_eq!(served["metadata"], serde_json::json!({"account": "b-2"}));
        assert_eq!(served["safety_identifier"], "user-b");
        // Members the requester did not send read as an upstream reports them
        // absent — never the producer's.
        assert_eq!(served["prompt_cache_key"], serde_json::Value::Null);
        assert_eq!(served["user"], serde_json::Value::Null);
        // The answer itself is untouched, and nothing is added that the body
        // did not carry.
        assert_eq!(served["id"], "resp_1");
        assert!(served.get("prompt_cache_retention").is_none());
        // The stored entry keeps the producer's values for the next requester.
        let again = cache.get(&k, Duration::from_secs(60)).expect("still stored");
        assert_eq!(again.body["safety_identifier"], "user-a");
    }

    #[test]
    fn an_absent_metadata_reads_as_an_empty_object() {
        let mut body = serde_json::json!({"metadata": {"k": "v"}, "output": []});
        restamp_caller(&mut body, &serde_json::Map::new());
        assert_eq!(body["metadata"], serde_json::json!({}));
    }

    /// A client opting out never got a chance to hit, so counting it as a miss
    /// would let one `no-cache` caller depress a healthy alias's hit rate.
    #[test]
    fn a_bypass_is_neither_a_hit_nor_a_miss() {
        let mut ctx = ctx_for(CacheMode::Exact);
        ctx.bypass = true;
        assert_eq!(ctx.audit().outcome, CacheOutcome::Bypass);

        assert_eq!(ctx_for(CacheMode::Semantic).audit().outcome, CacheOutcome::Miss);
    }

    /// Look up under a policy TTL wide enough never to interfere. These cases
    /// exercise storage, expiry and eviction — policy tightening has its own
    /// test below.
    fn get(cache: &ResponseCache, k: &CacheKey) -> Option<CachedResponse> {
        cache.get(k, Duration::from_secs(86_400))
    }

    #[test]
    fn round_trips_a_stored_entry() {
        let cache = ResponseCache::new(BIG, 10);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        cache.store(k.clone(), store_req(60), BIG).unwrap();
        let got = get(&cache, &k).expect("stored entry should hit");
        assert_eq!(got.text, "hi");
        assert_eq!(got.usage.completion_tokens, 2);
    }

    #[test]
    fn expired_entry_misses_and_is_dropped() {
        let cache = ResponseCache::new(BIG, 10);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        cache.store(k.clone(), store_req(0), BIG).unwrap();
        assert!(get(&cache, &k).is_none());
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.total_bytes(), 0);
    }

    // Cutting a preset's TTL must take effect on answers already stored — the
    // admin UI presents that field as governing how long an answer stays
    // servable, so honouring only the store-time TTL would leave it silently
    // wrong for the remainder of the OLD lifetime.
    #[test]
    fn shortened_policy_ttl_retires_an_entry_stored_under_the_old_one() {
        let cache = ResponseCache::new(BIG, 10);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        cache.store(k.clone(), store_req(86_400), BIG).unwrap();

        // Still servable under the TTL it was stored with.
        assert!(cache.get(&k, Duration::from_secs(86_400)).is_some());

        // The admin cuts the preset to an interval this entry already exceeds.
        assert!(
            cache.get(&k, Duration::ZERO).is_none(),
            "a tightened TTL must retire the entry immediately"
        );
        // …and reclaims its memory rather than parking it until the old expiry.
        assert_eq!(cache.len(), 0);
        assert_eq!(cache.total_bytes(), 0);
    }

    // The converse: raising a TTL must not resurrect or extend an entry past
    // the expiry it was stored with.
    #[test]
    fn raised_policy_ttl_does_not_extend_a_stored_entry() {
        let cache = ResponseCache::new(BIG, 10);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        cache.store(k.clone(), store_req(0), BIG).unwrap();
        assert!(cache.get(&k, Duration::from_secs(86_400)).is_none());
    }

    #[test]
    fn partitions_never_serve_each_other() {
        let cache = ResponseCache::new(BIG, 10);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        let ws_a = Uuid::new_v4();
        let ws_b = Uuid::new_v4();
        let mut k_a = key(tenant, ws_a, route, 1);
        k_a.identity = [7; 32];
        k_a.content = [8; 32];
        let mut k_b = k_a.clone();
        k_b.partition_id = ws_b;

        cache.store(k_a.clone(), store_req(60), BIG).unwrap();
        assert!(get(&cache, &k_a).is_some());
        assert!(
            get(&cache, &k_b).is_none(),
            "a different workspace partition must not hit"
        );

        // Same partition, different tenant: also isolated.
        let mut k_other_tenant = k_a.clone();
        k_other_tenant.tenant_id = Uuid::new_v4();
        assert!(get(&cache, &k_other_tenant).is_none());
    }

    #[test]
    fn per_tenant_cap_evicts_oldest_first() {
        let cache = ResponseCache::new(BIG, 2);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        let k1 = key(tenant, Uuid::nil(), route, 1);
        let k2 = key(tenant, Uuid::nil(), route, 2);
        let k3 = key(tenant, Uuid::nil(), route, 3);
        cache.store(k1.clone(), store_req(60), BIG).unwrap();
        cache.store(k2.clone(), store_req(60), BIG).unwrap();
        cache.store(k3.clone(), store_req(60), BIG).unwrap();
        assert!(get(&cache, &k1).is_none(), "oldest should have been evicted");
        assert!(get(&cache, &k2).is_some());
        assert!(get(&cache, &k3).is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn eviction_and_expiry_are_counted_apart() {
        // The two look identical in `entries` — one means the cache is too
        // small, the other means it is working as configured — so an operator
        // can only tell them apart if they are counted separately.
        let cache = ResponseCache::new(BIG, 2);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        for tag in 1..=3u8 {
            cache
                .store(key(tenant, Uuid::nil(), route, tag), store_req(60), BIG)
                .unwrap();
        }
        let s = cache.stats();
        assert_eq!(s.stores_total, 3);
        assert_eq!(s.evictions_total, 1, "the third store gave up the oldest");
        assert_eq!(s.expired_total, 0, "nothing reached its TTL");
        assert_eq!(s.entries, 2);
        assert_eq!(s.max_bytes, BIG as u64);

        // A TTL drop on read is an expiry, and leaves the eviction count alone.
        // Its own cache, with room to spare: storing into a full one would evict
        // as well, and the point here is that the two never share a counter.
        let cache = ResponseCache::new(BIG, 10);
        let dead = key(tenant, Uuid::nil(), route, 9);
        cache.store(dead.clone(), store_req(0), BIG).unwrap();
        assert!(get(&cache, &dead).is_none());
        let s = cache.stats();
        assert_eq!(s.expired_total, 1);
        assert_eq!(s.evictions_total, 0);
    }

    #[test]
    fn a_flush_is_neither_an_eviction_nor_an_expiry() {
        // `drop_entry` serves the TTL path and the operator flush path alike, so
        // counting there would report a deliberate flush as cache pressure.
        let cache = ResponseCache::new(BIG, 10);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        cache
            .store(key(tenant, Uuid::nil(), route, 1), store_req(60), BIG)
            .unwrap();
        assert_eq!(cache.flush_tenant(tenant), 1);
        let s = cache.stats();
        assert_eq!(s.entries, 0);
        assert_eq!(s.evictions_total, 0);
        assert_eq!(s.expired_total, 0);
    }

    #[test]
    fn one_tenant_cannot_evict_another() {
        let cache = ResponseCache::new(BIG, 1);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let route = Uuid::new_v4();
        let ka = key(a, Uuid::nil(), route, 1);
        cache.store(ka.clone(), store_req(60), BIG).unwrap();
        for tag in 2..8u8 {
            cache
                .store(key(b, Uuid::nil(), route, tag), store_req(60), BIG)
                .unwrap();
        }
        assert!(
            get(&cache, &ka).is_some(),
            "tenant B's churn must not evict tenant A"
        );
    }

    #[test]
    fn oversized_entry_is_refused() {
        let cache = ResponseCache::new(BIG, 10);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        assert_eq!(
            cache.store(k, store_req(60), 1),
            Err(StoreRejection::EntryTooLarge)
        );
        assert_eq!(cache.len(), 0);
    }

    #[test]
    fn global_ceiling_refuses_rather_than_stealing() {
        // Room for one entry only, and the tenant already holds it.
        let cache = ResponseCache::new(400, 10);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let route = Uuid::new_v4();
        cache
            .store(key(a, Uuid::nil(), route, 1), store_req(60), BIG)
            .unwrap();
        assert_eq!(
            cache.store(key(b, Uuid::nil(), route, 2), store_req(60), BIG),
            Err(StoreRejection::CacheFull),
            "a second tenant must not push the first one out"
        );
    }

    #[test]
    fn replacing_a_key_does_not_grow_accounting() {
        let cache = ResponseCache::new(BIG, 10);
        let k = key(Uuid::nil(), Uuid::nil(), Uuid::nil(), 1);
        cache.store(k.clone(), store_req(60), BIG).unwrap();
        let after_first = cache.total_bytes();
        cache.store(k.clone(), store_req(60), BIG).unwrap();
        assert_eq!(cache.len(), 1);
        assert_eq!(cache.total_bytes(), after_first);
    }

    #[test]
    fn repeated_store_at_cap_keeps_the_key_evictable() {
        // Storing the same key over and over while the tenant sits at its cap
        // walks the drain past that key's own queue slot. If the slot were
        // consumed and not restored, the entry would become unevictable and the
        // cap would drift upward on every later insert.
        let cache = ResponseCache::new(BIG, 2);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        let hot = key(tenant, Uuid::nil(), route, 1);
        cache
            .store(key(tenant, Uuid::nil(), route, 9), store_req(60), BIG)
            .unwrap();
        for _ in 0..6 {
            cache.store(hot.clone(), store_req(60), BIG).unwrap();
        }
        assert!(get(&cache, &hot).is_some());
        assert!(cache.len() <= 2, "cap drifted to {}", cache.len());

        // The hot key must still be reachable by eviction: pushing fresh keys
        // past the cap has to be able to reclaim it.
        for tag in 20..26u8 {
            cache
                .store(key(tenant, Uuid::nil(), route, tag), store_req(60), BIG)
                .unwrap();
        }
        assert!(
            get(&cache, &hot).is_none(),
            "the repeatedly-stored key never became evictable"
        );
        assert!(cache.len() <= 2, "cap drifted to {}", cache.len());
    }

    #[test]
    fn refused_store_keeps_the_existing_copy_evictable() {
        // A `CacheFull` refusal must not strand the live copy of the key it was
        // asked to overwrite.
        let cache = ResponseCache::new(400, 10);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        let k = key(tenant, Uuid::nil(), route, 1);
        cache.store(k.clone(), store_req(60), BIG).unwrap();
        // The ceiling admits one entry, so re-storing drains the queue (past this
        // key's own slot) and refuses.
        assert_eq!(
            cache.store(k.clone(), store_req(60), BIG),
            Err(StoreRejection::CacheFull)
        );
        assert!(get(&cache, &k).is_some(), "the refusal must not drop the live copy");
        // Still evictable afterwards: a different key can reclaim its space.
        let other = key(tenant, Uuid::nil(), route, 2);
        cache.store(other.clone(), store_req(60), BIG).unwrap();
        assert!(get(&cache, &other).is_some());
    }

    #[test]
    fn flush_route_drops_only_that_alias() {
        let cache = ResponseCache::new(BIG, 10);
        let tenant = Uuid::new_v4();
        let r1 = Uuid::new_v4();
        let r2 = Uuid::new_v4();
        let k1 = key(tenant, Uuid::nil(), r1, 1);
        let k2 = key(tenant, Uuid::nil(), r2, 2);
        cache.store(k1.clone(), store_req(60), BIG).unwrap();
        cache.store(k2.clone(), store_req(60), BIG).unwrap();
        assert_eq!(cache.flush_route(tenant, r1), 1);
        assert!(get(&cache, &k1).is_none());
        assert!(get(&cache, &k2).is_some());
    }

    #[test]
    fn flush_tenant_drops_only_that_tenant() {
        let cache = ResponseCache::new(BIG, 10);
        let a = Uuid::new_v4();
        let b = Uuid::new_v4();
        let route = Uuid::new_v4();
        let ka = key(a, Uuid::nil(), route, 1);
        let kb = key(b, Uuid::nil(), route, 2);
        cache.store(ka.clone(), store_req(60), BIG).unwrap();
        cache.store(kb.clone(), store_req(60), BIG).unwrap();
        assert_eq!(cache.flush_tenant(a), 1);
        assert!(get(&cache, &ka).is_none());
        assert!(get(&cache, &kb).is_some());
    }

    #[test]
    fn prune_expired_reclaims_and_compacts() {
        let cache = ResponseCache::new(BIG, 10);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        cache
            .store(key(tenant, Uuid::nil(), route, 1), store_req(0), BIG)
            .unwrap();
        let live = key(tenant, Uuid::nil(), route, 2);
        cache.store(live.clone(), store_req(600), BIG).unwrap();
        assert_eq!(cache.prune_expired(), 1);
        assert_eq!(cache.len(), 1);
        assert!(get(&cache, &live).is_some());
    }

    // ── key construction ──

    fn domain_request(version: ApiVersion, body: serde_json::Value) -> ApiRequest {
        let bytes = bytes::Bytes::from(serde_json::to_vec(&body).unwrap());
        ApiRequest::parse(version, &bytes).expect("valid request body")
    }

    fn chat_request(body: serde_json::Value) -> ApiRequest {
        domain_request(ApiVersion::ChatCompletions, body)
    }

    #[test]
    fn identical_conversations_hash_identically() {
        let body = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        });
        assert_eq!(
            content_hash(&chat_request(body.clone())),
            content_hash(&chat_request(body))
        );
    }

    #[test]
    fn system_prompt_is_part_of_the_content_hash() {
        let a = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        }));
        let b = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hello"},
            ],
        }));
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    #[test]
    fn history_is_part_of_the_content_hash() {
        let a = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        }));
        let b = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "earlier"},
                {"role": "assistant", "content": "sure"},
                {"role": "user", "content": "hello"},
            ],
        }));
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    /// A Gemini call part's signature is sent back to a Gemini upstream with
    /// the call, so a history that signs a call is a different request from
    /// one that does not.
    #[test]
    fn a_calls_signature_is_part_of_the_content_hash() {
        let history = |part: serde_json::Value| {
            domain_request(
                ApiVersion::GoogleGemini,
                serde_json::json!({"contents": [
                    {"role": "user", "parts": [{"text": "q"}]},
                    {"role": "model", "parts": [part]},
                    {"role": "user", "parts": [{"functionResponse": {"id": "c1", "name": "f", "response": {}}}]}]}),
            )
        };
        let call = serde_json::json!({"functionCall": {"id": "c1", "name": "f", "args": {}}});
        let mut signed = call.clone();
        signed["thoughtSignature"] = "Sig1".into();
        assert_ne!(content_hash(&history(call)), content_hash(&history(signed)));
    }

    #[test]
    fn tool_definitions_are_part_of_the_content_hash() {
        let base = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        });
        let mut with_tools = base.clone();
        with_tools["tools"] = serde_json::json!([{
            "type": "function",
            "function": {"name": "lookup", "parameters": {"type": "object"}},
        }]);
        assert_ne!(
            content_hash(&chat_request(base)),
            content_hash(&chat_request(with_tools))
        );
    }

    #[test]
    fn message_boundaries_cannot_collide() {
        // Length-prefixing means splitting the same characters across a
        // different message boundary is a different conversation.
        let a = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "ab"}],
        }));
        let b = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "a"},
                {"role": "user", "content": "b"},
            ],
        }));
        assert_ne!(content_hash(&a), content_hash(&b));
    }

    /// A tool is more than its name and schema: a Chat custom tool's input
    /// `format` and a Responses hosted tool's configuration decide the answer
    /// too, so requests differing only there are different requests.
    #[test]
    fn the_key_covers_what_a_tool_is_beyond_its_name() {
        let key = |protocol: ApiVersion, tools: serde_json::Value| {
            let mut body = serde_json::json!({"model": "m", "tools": tools});
            match protocol {
                ApiVersion::Responses => body["input"] = serde_json::json!("hello"),
                _ => body["messages"] = serde_json::json!([{"role": "user", "content": "hello"}]),
            }
            content_hash(&domain_request(protocol, body))
        };
        let grammar = |definition: &str| {
            serde_json::json!([{"type": "custom", "custom": {"name": "apply_patch",
                "format": {"type": "grammar", "grammar": {"syntax": "lark", "definition": definition}}}}])
        };
        assert_ne!(key(ApiVersion::ChatCompletions, grammar("start: /a/")), key(ApiVersion::ChatCompletions, grammar("start: /b/")));
        assert_ne!(
            key(ApiVersion::ChatCompletions, grammar("start: /a/")),
            key(ApiVersion::ChatCompletions, serde_json::json!([{"type": "function", "function": {"name": "apply_patch"}}])),
            "a freeform tool is not the function of the same name"
        );
        let strict = |on: bool| serde_json::json!([{"type": "function", "function": {"name": "f", "strict": on}}]);
        assert_ne!(key(ApiVersion::ChatCompletions, strict(true)), key(ApiVersion::ChatCompletions, strict(false)));
        let search = |ids: serde_json::Value| serde_json::json!([{"type": "file_search", "vector_store_ids": ids}]);
        assert_ne!(
            key(ApiVersion::Responses, search(serde_json::json!(["vs_1"]))),
            key(ApiVersion::Responses, search(serde_json::json!(["vs_2"])))
        );
    }

    #[test]
    fn identity_covers_model_and_preset() {
        let none = response_policy_hash(&[]);
        let base = identity_hash("gpt-4o", Some("mid"), &serde_json::json!({}), &none);
        assert_ne!(
            base,
            identity_hash("gpt-4o-mini", Some("mid"), &serde_json::json!({}), &none),
            "a different upstream model is a different answer"
        );
        assert_ne!(
            base,
            identity_hash("gpt-4o", Some("other"), &serde_json::json!({}), &none),
            "a different upstream model row is a different answer"
        );
        assert_ne!(
            base,
            identity_hash("gpt-4o", Some("mid"), &serde_json::json!({"temperature": 0.1}), &none),
            "editing the bound preset must self-invalidate"
        );
        // Positive control: the same model and preset key alike.
        assert_eq!(base, identity_hash("gpt-4o", Some("mid"), &serde_json::json!({}), &none));
    }

    /// Every sampling parameter the client sets is part of its request, and so
    /// of the content half: the temperature, the cap in the spelling the client
    /// used (a server reading only `max_tokens` treats the two differently),
    /// how Anthropic thinking is displayed, and "do not reason" — a request of
    /// its own, not the absence of one.
    #[test]
    fn the_key_covers_every_sampling_parameter_the_client_set() {
        let chat = |extra: serde_json::Value| {
            let mut body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hello"}]});
            body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            content_hash(&chat_request(body))
        };
        assert_ne!(chat(serde_json::json!({"temperature": 0.5})), chat(serde_json::json!({"temperature": 0.9})));
        assert_ne!(chat(serde_json::json!({"max_tokens": 50})), chat(serde_json::json!({"max_completion_tokens": 50})));
        assert_ne!(
            chat(serde_json::json!({"max_completion_tokens": 50, "max_tokens": 10})),
            chat(serde_json::json!({"max_completion_tokens": 50, "max_tokens": 4000}))
        );
        let off = chat(serde_json::json!({"reasoning_effort": "none"}));
        assert_ne!(off, chat(serde_json::json!({})));
        assert_ne!(off, chat(serde_json::json!({"reasoning_effort": "low"})));
        // Positive control: the same request, its members in another order,
        // keys alike.
        assert_eq!(
            chat(serde_json::json!({"temperature": 0.5, "max_tokens": 50})),
            chat(serde_json::json!({"max_tokens": 50, "temperature": 0.5}))
        );
        let anthropic = |display: Option<&str>| {
            let mut thinking = serde_json::json!({"type": "adaptive"});
            if let Some(d) = display {
                thinking["display"] = serde_json::json!(d);
            }
            content_hash(&domain_request(ApiVersion::AnthropicMessages, serde_json::json!({
                "model": "m", "max_tokens": 1024, "thinking": thinking,
                "messages": [{"role": "user", "content": "hello"}],
            })))
        };
        assert_ne!(anthropic(Some("summarized")), anthropic(Some("omitted")));
        assert_ne!(anthropic(Some("omitted")), anthropic(None));
        assert_eq!(anthropic(Some("omitted")), anthropic(Some("omitted")));
    }

    fn response_program(id: &str, version: &str, phase: &str) -> crate::scripting::TransformProgram {
        crate::scripting::TransformProgram {
            id: id.to_string(),
            name: id.to_string(),
            source: String::new(),
            phase: phase.to_string(),
            scope: "content".to_string(),
            priority: 0,
            enabled: true,
            version_hash: version.to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }
    }

    #[test]
    fn a_multi_answer_request_is_recognized_from_the_request_not_the_body() {
        let one = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        }));
        assert!(!asks_for_multiple_answers(&keyed(&one, &axum::http::HeaderMap::new()).unwrap().body));

        // Read from the request, not the answer: a streaming store has no
        // body yet.
        let many = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
            "n": 2,
        }));
        assert!(asks_for_multiple_answers(&keyed(&many, &axum::http::HeaderMap::new()).unwrap().body));

        let gemini_many = ApiRequest::GoogleGemini(crate::api::gemini::GeminiRequest {
            model: "m".into(),
            stream: None,
            contents: vec![],
            system_instruction: None,
            tools: None,
            tool_config: None,
            generation_config: Some(crate::api::gemini::GeminiGenerationConfig {
                candidate_count: Some(3),
                temperature: None,
                top_p: None,
                top_k: None,
                max_output_tokens: None,
                stop_sequences: None,
                presence_penalty: None,
                frequency_penalty: None,
                seed: None,
                response_mime_type: None,
                response_schema: None,
                response_json_schema: None,
                thinking_config: None,
            }),
            safety_settings: None,
            cached_content: None,
        });
        assert!(asks_for_multiple_answers(&keyed(&gemini_many, &axum::http::HeaderMap::new()).unwrap().body));
    }

    #[test]
    fn identity_covers_the_response_shaping_policy() {
        let id_with = |programs: &[crate::scripting::TransformProgram]| {
            identity_hash(
                "gpt-4o",
                Some("mid"),
                &serde_json::json!({}),
                &response_policy_hash(programs),
            )
        };

        let a = response_program("redact", "v1", "response");
        let bare = id_with(&[]);
        assert_ne!(
            bare,
            id_with(std::slice::from_ref(&a)),
            "a workspace whose response transforms differ must not read another's entries"
        );

        // Editing a program self-invalidates: stale output must not survive to
        // TTL. `version_hash` moves only when the SOURCE changes, so every other
        // field that changes what the program does must be hashed too.
        let edited = response_program("redact", "v2", "response");
        assert_ne!(id_with(std::slice::from_ref(&a)), id_with(&[edited]));
        for mutate in [
            (|p: &mut crate::scripting::TransformProgram| p.trigger_regex = Some("Acme".into()))
                as fn(&mut crate::scripting::TransformProgram),
            |p| p.match_mode = Some("span".into()),
            |p| p.model_filter = Some("gpt-4o".into()),
            |p| p.app_filter = Some("claude-code".into()),
            |p| p.scope = "tools".to_string(),
            |p| p.priority = 10,
        ] {
            let mut changed = a.clone();
            mutate(&mut changed);
            assert_ne!(
                id_with(std::slice::from_ref(&a)),
                id_with(&[changed]),
                "a behavioural edit that leaves `version_hash` alone must still invalidate"
            );
        }

        // Disabled and request-phase programs shape nothing on the way out.
        let mut off = a.clone();
        off.enabled = false;
        assert_eq!(bare, id_with(&[off]));
        assert_eq!(bare, id_with(&[response_program("r", "v1", "request")]));

        // The effective set's order is not guaranteed stable across snapshot
        // builds, so the same policy must hash the same either way round.
        let b = response_program("mask", "v1", "response");
        assert_eq!(
            id_with(&[a.clone(), b.clone()]),
            id_with(&[b, a]),
            "policy identity must not depend on program ordering"
        );
    }

    #[test]
    fn streaming_flag_is_not_part_of_the_key() {
        let non_stream = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
        }));
        let stream = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": true,
        }));
        // A streaming request is the same answer, rendered differently.
        assert_eq!(content_hash(&non_stream), content_hash(&stream));
    }

    /// A caller's bookkeeping members split no shared cache. A client's
    /// telemetry line in an Anthropic system text reaches the model on a
    /// same-protocol forward, so it keys like any prompt text: what it says is
    /// the client's to choose, and a stripped line would let one caller's
    /// text shape an answer served to another.
    #[test]
    fn caller_bookkeeping_does_not_key_and_a_telemetry_line_does() {
        let anthropic = |system: serde_json::Value| {
            content_hash(&domain_request(ApiVersion::AnthropicMessages, serde_json::json!({
                "model": "m", "max_tokens": 9, "system": system, "messages": [{"role": "user", "content": "q"}],
            })))
        };
        let billing = |cch: &str| format!("x-anthropic-billing-header: cc_version=1; cch={cch};\nYou are terse.");
        assert_ne!(anthropic(serde_json::json!(billing("A"))), anthropic(serde_json::json!(billing("B"))));
        assert_ne!(anthropic(serde_json::json!(billing("A"))), anthropic(serde_json::json!("You are terse.")));
        assert_eq!(anthropic(serde_json::json!(billing("A"))), anthropic(serde_json::json!(billing("A"))));
        let chat = |extra: serde_json::Value| {
            let mut body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "q"}]});
            body.as_object_mut().unwrap().extend(extra.as_object().unwrap().clone());
            content_hash(&chat_request(body))
        };
        assert_eq!(
            chat(serde_json::json!({"safety_identifier": "u1", "prompt_cache_key": "s1", "user": "a"})),
            chat(serde_json::json!({"safety_identifier": "u2", "prompt_cache_key": "s2", "user": "b"}))
        );
        assert_ne!(chat(serde_json::json!({"seed": 1})), chat(serde_json::json!({"seed": 2})));
        assert_ne!(chat(serde_json::json!({"store": true})), chat(serde_json::json!({"store": false})));
        // The `anthropic-beta` header reaches an Anthropic upstream, so it keys.
        let request = domain_request(ApiVersion::AnthropicMessages, serde_json::json!({
            "model": "m", "max_tokens": 9, "messages": [{"role": "user", "content": "q"}],
        }));
        let with = |beta: Option<&str>| {
            let mut headers = axum::http::HeaderMap::new();
            if let Some(b) = beta {
                headers.insert("anthropic-beta", b.parse().unwrap());
            }
            content_of(&keyed(&request, &headers).unwrap())
        };
        assert_ne!(with(Some("context-1m-2025-08-07")), with(None));
        assert_ne!(with(Some("context-1m-2025-08-07")), with(Some("output-128k-2025-02-19")));
        assert_eq!(with(None), content_hash(&request).unwrap());
    }

    /// The key reads the client's own request: the same conversation sent on
    /// two protocols is two entries.
    #[test]
    fn the_same_conversation_on_two_protocols_is_two_entries() {
        let chat = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "hello"},
            ],
        }));
        let anthropic = domain_request(
            ApiVersion::AnthropicMessages,
            serde_json::json!({
                "model": "m",
                "max_tokens": 100,
                "system": "be terse",
                "messages": [{"role": "user", "content": [{"type": "text", "text": "hello"}]}],
            }),
        );
        assert_ne!(content_hash(&chat), content_hash(&anthropic));
        assert_ne!(semantic_request(&chat, "embed-1").map(|p| p.prefix), semantic_request(&anthropic, "embed-1").map(|p| p.prefix));
    }

    /// What the gateway does not model of a request is still part of it: the
    /// same member at another place, a message's text split differently, a
    /// setting on a part — each is another request, though the gateway's own
    /// reading of the two is the same.
    #[test]
    fn a_difference_the_gateway_does_not_model_is_another_request() {
        let chat = |messages: serde_json::Value| content_hash(&chat_request(serde_json::json!({"model": "m", "messages": messages})));
        let anthropic = |messages: serde_json::Value| {
            content_hash(&domain_request(ApiVersion::AnthropicMessages, serde_json::json!({"model": "m", "max_tokens": 9, "messages": messages})))
        };
        let image = |set: bool| {
            let mut image = serde_json::json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}});
            if set {
                image["transformations"] = serde_json::json!({"oversized_image": "error"});
            }
            image
        };
        let assistant = |set: bool| match set {
            true => serde_json::json!({"role": "assistant", "content": "a", "reasoning_content": "r"}),
            false => serde_json::json!({"role": "assistant", "content": "a"}),
        };
        let user_named = |set: bool| match set {
            true => serde_json::json!({"role": "user", "content": "q", "name": "example_user"}),
            false => serde_json::json!({"role": "user", "content": "q"}),
        };
        let text = |set: bool| match set {
            true => serde_json::json!({"type": "text", "text": "q", "cache_control": {"type": "ephemeral"}}),
            false => serde_json::json!({"type": "text", "text": "q"}),
        };
        let pic = serde_json::json!({"type": "image_url", "image_url": {"url": "data:image/png;base64,iVBO"}});
        type Key<'a> = Box<dyn Fn(bool) -> Option<[u8; 32]> + 'a>;
        let placed: Vec<Key> = vec![
            // The same key on the other of two assistant messages.
            Box::new(|first| chat(serde_json::json!([
                {"role": "user", "content": "q"}, assistant(first), {"role": "user", "content": "q"}, assistant(!first),
                {"role": "user", "content": "q"},
            ]))),
            // The same `name` on the other of two user messages.
            Box::new(|first| chat(serde_json::json!([user_named(first), {"role": "assistant", "content": "a"}, user_named(!first)]))),
            // The same text part setting on the other of two text parts.
            Box::new(|first| chat(serde_json::json!([{"role": "user", "content": [text(first), text(!first)]}]))),
            // A tool result's image between its text parts, or after them: the
            // gateway joins the text either way.
            Box::new(|first| {
                let content = match first {
                    true => serde_json::json!([{"type": "text", "text": "ab"}, pic]),
                    false => serde_json::json!([{"type": "text", "text": "a"}, pic, {"type": "text", "text": "b"}]),
                };
                chat(serde_json::json!([
                    {"role": "user", "content": "q"},
                    {"role": "assistant", "tool_calls": [{"id": "c", "type": "function", "function": {"name": "f", "arguments": "{}"}}]},
                    {"role": "tool", "tool_call_id": "c", "content": content},
                ]))
            }),
            // Reasoning on a message the gateway keeps nothing of, or on the next.
            Box::new(|first| match first {
                true => chat(serde_json::json!([
                    {"role": "user", "content": "q"}, {"role": "assistant", "content": null, "reasoning_content": "r"},
                    {"role": "assistant", "content": "a"},
                ])),
                false => chat(serde_json::json!([
                    {"role": "user", "content": "q"}, {"role": "assistant", "content": "a", "reasoning_content": "r"},
                ])),
            }),
            // An image's detail.
            Box::new(|first| {
                let detail = if first { "low" } else { "high" };
                chat(serde_json::json!([{"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "https://x/i.png", "detail": detail}}, {"type": "text", "text": "q"},
                ]}]))
            }),
            // The same setting on the other of two Anthropic images, at the top
            // and inside a tool result.
            Box::new(|first| anthropic(serde_json::json!([{"role": "user", "content": [image(first), image(!first)]}]))),
            Box::new(|first| anthropic(serde_json::json!([
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "f", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": [image(first), image(!first)]}]},
            ]))),
        ];
        for (case, key) in placed.iter().enumerate() {
            assert_ne!(key(true), key(false), "case {case}");
            // Positive control: the same request keys alike.
            assert_eq!(key(true), key(true), "case {case}");
        }
    }

    // ── semantic matching ──

    fn bucket(tenant: Uuid, route: Uuid, prefix: u8) -> SemanticBucket {
        bucket_from_model(tenant, route, prefix, 7)
    }

    fn bucket_from_model(tenant: Uuid, route: Uuid, prefix: u8, embed_model: u8) -> SemanticBucket {
        SemanticBucket {
            tenant_id: tenant,
            partition_id: Uuid::nil(),
            route_id: route,
            identity: [1; 32],
            prefix: [prefix; 32],
            embed_model: [embed_model; 32],
        }
    }

    fn vector(v: [f32; 3]) -> std::sync::Arc<[f32]> {
        std::sync::Arc::from(v.as_slice())
    }

    /// Store one entry into a bucket under a chosen vector.
    fn store_semantic(
        cache: &ResponseCache,
        b: &SemanticBucket,
        content: u8,
        embedding: [f32; 3],
    ) -> CacheKey {
        let key = b.key_for([content; 32]);
        cache
            .store(
                key.clone(),
                store_req_semantic(
                    600,
                    Some(SemanticIndexEntry {
                        bucket: b.clone(),
                        embedding: vector(embedding),
                    }),
                ),
                BIG,
            )
            .unwrap();
        key
    }

    const DAY: Duration = Duration::from_secs(86_400);

    #[test]
    fn semantic_lookup_returns_the_nearest_match_above_the_threshold() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        store_semantic(&cache, &b, 2, [0.9, 0.1, 0.0]);

        // Closer to the second entry than the first.
        let (_, sim) = cache
            .get_semantic(&b, &[0.9, 0.12, 0.0], 0.8, DAY)
            .expect("a near vector should match");
        let (_, sim_first) = cache
            .get_semantic(&b, &[1.0, 0.0, 0.0], 0.8, DAY)
            .expect("an exact vector should match");
        assert!(sim > 0.99, "nearest match similarity was {sim}");
        assert!(sim_first > 0.99);
    }

    #[test]
    fn vectors_from_different_embedding_models_never_match_each_other() {
        // One alias can resolve to two embedding models — load-balanced targets
        // round-robin per call, and an alias can be re-pointed. Identical
        // vectors from different models must not match, because a cosine
        // between two models' vectors is meaningless even when it reads 1.0.
        let cache = ResponseCache::new(BIG, 10);
        let (tenant, route) = (Uuid::new_v4(), Uuid::new_v4());
        let first = bucket_from_model(tenant, route, 1, 10);
        let second = bucket_from_model(tenant, route, 1, 20);

        store_semantic(&cache, &first, 1, [1.0, 0.0, 0.0]);

        // Everything else about these buckets is equal — only the producing
        // model differs, and that alone must keep them apart.
        assert!(
            cache.get_semantic(&second, &[1.0, 0.0, 0.0], 0.8, DAY).is_none(),
            "an identical vector from another embedding model must not match"
        );
        assert!(
            cache.get_semantic(&first, &[1.0, 0.0, 0.0], 0.8, DAY).is_some(),
            "the storing model's own bucket must still match"
        );
    }

    #[test]
    fn semantic_lookup_respects_the_threshold() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        // Orthogonal: cosine 0, far below any legal threshold.
        assert!(cache.get_semantic(&b, &[0.0, 1.0, 0.0], 0.8, DAY).is_none());
    }

    // The prefix guard is the correctness story: a different system prompt,
    // history, tool set, model or embedding alias lands in a different bucket,
    // so an identical prompt vector must not reach across.
    #[test]
    fn a_different_prefix_never_matches_however_close_the_vector() {
        let cache = ResponseCache::new(BIG, 10);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        let b = bucket(tenant, route, 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);

        let other_prefix = bucket(tenant, route, 2);
        assert!(
            cache
                .get_semantic(&other_prefix, &[1.0, 0.0, 0.0], 0.8, DAY)
                .is_none()
        );

        let mut other_tenant = b.clone();
        other_tenant.tenant_id = Uuid::new_v4();
        assert!(
            cache
                .get_semantic(&other_tenant, &[1.0, 0.0, 0.0], 0.8, DAY)
                .is_none()
        );

        let mut other_partition = b.clone();
        other_partition.partition_id = Uuid::new_v4();
        assert!(
            cache
                .get_semantic(&other_partition, &[1.0, 0.0, 0.0], 0.8, DAY)
                .is_none()
        );
    }

    #[test]
    fn semantic_lookup_honours_the_live_policy_ttl() {
        // The same dual-TTL rule the exact path obeys: an admin who cuts a
        // preset's lifetime must stop being served older answers, whichever
        // lookup finds them.
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        assert!(cache.get_semantic(&b, &[1.0, 0.0, 0.0], 0.8, DAY).is_some());
        assert!(
            cache
                .get_semantic(&b, &[1.0, 0.0, 0.0], 0.8, Duration::ZERO)
                .is_none(),
            "a tightened TTL must retire the entry on the semantic path too"
        );
    }

    #[test]
    fn dropping_an_entry_retires_its_vector() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        let key = store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        cache.flush_route(key.tenant_id, key.route_id);
        assert!(cache.get_semantic(&b, &[1.0, 0.0, 0.0], 0.8, DAY).is_none());
        cache.prune_expired();
        assert!(
            cache.semantic.is_empty(),
            "an emptied bucket must not survive the sweep"
        );
    }

    // An index member that outlived its entry must not be handed out as a
    // match; the next-best live candidate is the right answer.
    #[test]
    fn a_stale_candidate_falls_through_to_the_next_live_one() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        let best = store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        store_semantic(&cache, &b, 2, [0.95, 0.05, 0.0]);
        // Remove the closest entry the way an eviction would, without touching
        // the index.
        cache.entries.remove(&best);

        let (entry, sim) = cache
            .get_semantic(&b, &[1.0, 0.0, 0.0], 0.8, DAY)
            .expect("the second candidate should still serve");
        assert_eq!(entry.text, "hi");
        assert!(sim >= 0.8);
    }

    #[test]
    fn re_storing_the_same_key_does_not_grow_its_bucket() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        for _ in 0..5 {
            store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        }
        assert_eq!(cache.semantic.get(&b).map(|m| m.len()), Some(1));
    }

    #[test]
    fn a_bucket_is_bounded() {
        let cache = ResponseCache::new(BIG, 10_000);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        for i in 0..(MAX_SEMANTIC_MEMBERS_PER_BUCKET + 20) {
            let key = b.key_for(content_tag(i));
            cache
                .store(
                    key,
                    store_req_semantic(
                        600,
                        Some(SemanticIndexEntry {
                            bucket: b.clone(),
                            embedding: vector([i as f32, 1.0, 0.0]),
                        }),
                    ),
                    BIG,
                )
                .unwrap();
        }
        assert_eq!(
            cache.semantic.get(&b).map(|m| m.len()),
            Some(MAX_SEMANTIC_MEMBERS_PER_BUCKET)
        );
    }

    #[test]
    fn reported_vectors_track_the_entries_that_own_them() {
        // The whole point of reporting this gauge: a leaked vector has no
        // symptom other than memory, so `semantic_vectors` drifting above
        // `entries` is the only way anyone would ever see one.
        let cache = ResponseCache::new(BIG, 2);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        store_semantic(&cache, &b, 2, [0.0, 1.0, 0.0]);
        assert_eq!(cache.stats().semantic_vectors, 2);
        assert_eq!(cache.stats().semantic_buckets, 1);

        // Evicting the oldest must take its vector with it.
        store_semantic(&cache, &b, 3, [0.0, 0.0, 1.0]);
        let s = cache.stats();
        assert_eq!(s.entries, 2);
        assert_eq!(s.semantic_vectors, 2, "an evicted vector is a pure leak");
    }

    fn content_tag(i: usize) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[..8].copy_from_slice(&(i as u64).to_le_bytes());
        out
    }

    // Eviction must take an entry's vector with it. Missing this is invisible
    // — correctness is unaffected — but it leaks a vector per eviction, and it
    // leaks fastest under exactly the memory pressure that causes eviction.
    #[test]
    fn evicting_an_entry_retires_its_vector() {
        let cache = ResponseCache::new(BIG, 2);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        store_semantic(&cache, &b, 2, [0.0, 1.0, 0.0]);
        // Third store pushes the tenant past its cap and evicts the first.
        store_semantic(&cache, &b, 3, [0.0, 0.0, 1.0]);

        assert_eq!(cache.len(), 2);
        assert_eq!(
            cache.semantic.get(&b).map(|m| m.len()),
            Some(2),
            "the evicted entry's vector must not outlive it"
        );
        assert!(
            cache.get_semantic(&b, &[1.0, 0.0, 0.0], 0.9, DAY).is_none(),
            "the evicted entry must not still be reachable as a candidate"
        );
    }

    // Re-storing a key whose prompt could not be embedded this time (or that
    // moved to a new bucket after an embedding-model change) leaves the old
    // vector claimed by nothing — so nothing would ever retire it.
    #[test]
    fn replacing_an_indexed_entry_without_a_vector_retires_the_old_one() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        let key = store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        cache.store(key, store_req(600), BIG).unwrap();
        assert_eq!(cache.semantic.get(&b).map(|m| m.len()), Some(0));
    }

    // A store that evicts and then refuses still owns what it evicted. This is
    // the path under the heaviest memory pressure — the one that can least
    // afford to strand a vector.
    #[test]
    fn a_refused_store_still_retires_the_vectors_it_evicted() {
        // Room for two ordinary entries and no more.
        let cache = ResponseCache::new(700, 10);
        let tenant = Uuid::new_v4();
        let route = Uuid::new_v4();
        let b = bucket(tenant, route, 1);
        store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        // A neighbour takes the rest of the ceiling, so this tenant cannot buy
        // room by evicting only its own.
        cache
            .store(
                key(Uuid::new_v4(), Uuid::nil(), route, 9),
                store_req(600),
                BIG,
            )
            .unwrap();

        let mut oversized = store_req(600);
        oversized.text = "z".repeat(600);
        assert_eq!(
            cache.store(b.key_for([2; 32]), oversized, BIG),
            Err(StoreRejection::CacheFull)
        );
        assert_eq!(
            cache.semantic.get(&b).map(|m| m.len()),
            Some(0),
            "the refusal stranded the vector of the entry it evicted"
        );
    }

    // The sweep is the backstop that makes "the index holds only live entries"
    // an invariant rather than something every removal path has to remember.
    #[test]
    fn prune_drops_vectors_whose_entries_are_gone() {
        let cache = ResponseCache::new(BIG, 10);
        let b = bucket(Uuid::new_v4(), Uuid::new_v4(), 1);
        let key = store_semantic(&cache, &b, 1, [1.0, 0.0, 0.0]);
        // Remove the entry the way a path that forgot to retire its vector would.
        cache.entries.remove(&key);
        cache.prune_expired();
        assert!(
            cache.semantic.is_empty(),
            "the sweep must reclaim a vector whose entry is gone"
        );
    }

    #[test]
    fn mismatched_vector_dimensions_never_match() {
        // Switching the embedding model changes the vector width. Comparing
        // across it is meaningless, and a meaningless number above the
        // threshold would serve an unrelated answer.
        assert_eq!(cosine(&[1.0, 0.0], &[1.0, 0.0, 0.0]), -1.0);
        assert_eq!(cosine(&[], &[]), -1.0);
        assert_eq!(cosine(&[0.0, 0.0], &[1.0, 0.0]), -1.0);
        assert!((cosine(&[1.0, 0.0], &[1.0, 0.0]) - 1.0).abs() < 1e-6);
        assert!(cosine(&[1.0, 0.0], &[0.0, 1.0]).abs() < 1e-6);
    }

    #[test]
    fn a_vector_is_charged_to_the_entry_that_owns_it() {
        let plain = estimate_size(&store_req(60));
        let with_vector = estimate_size(&store_req_semantic(
            60,
            Some(SemanticIndexEntry {
                bucket: bucket(Uuid::nil(), Uuid::nil(), 1),
                embedding: vector([1.0, 0.0, 0.0]),
            }),
        ));
        assert_eq!(with_vector, plain + 3 * std::mem::size_of::<f32>());
    }

    // ── the prefix guard, derived from a request ──

    #[test]
    fn semantic_request_splits_off_the_final_user_message() {
        let req = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "earlier"},
                {"role": "assistant", "content": "sure"},
                {"role": "user", "content": "what is the refund policy?"},
            ],
        }));
        let parts = semantic_request(&req, "embed-1").expect("a text user turn is embeddable");
        assert_eq!(parts.query, "what is the refund policy?");

        // Rewording only the final question keeps the guard identical…
        let reworded = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "system", "content": "be terse"},
                {"role": "user", "content": "earlier"},
                {"role": "assistant", "content": "sure"},
                {"role": "user", "content": "how do refunds work?"},
            ],
        }));
        assert_eq!(
            semantic_request(&reworded, "embed-1").map(|p| p.prefix),
            Some(parts.prefix)
        );

        // …while touching anything else does not.
        for changed in [
            serde_json::json!({
                "model": "m",
                "messages": [
                    {"role": "system", "content": "be verbose"},
                    {"role": "user", "content": "earlier"},
                    {"role": "assistant", "content": "sure"},
                    {"role": "user", "content": "what is the refund policy?"},
                ],
            }),
            serde_json::json!({
                "model": "m",
                "messages": [
                    {"role": "system", "content": "be terse"},
                    {"role": "user", "content": "something else"},
                    {"role": "assistant", "content": "sure"},
                    {"role": "user", "content": "what is the refund policy?"},
                ],
            }),
            serde_json::json!({
                "model": "m",
                "messages": [
                    {"role": "system", "content": "be terse"},
                    {"role": "user", "content": "earlier"},
                    {"role": "assistant", "content": "sure"},
                    {"role": "user", "content": "what is the refund policy?"},
                ],
                "tools": [{
                    "type": "function",
                    "function": {"name": "lookup", "parameters": {"type": "object"}},
                }],
            }),
        ] {
            assert_ne!(
                semantic_request(&chat_request(changed), "embed-1").map(|p| p.prefix),
                Some(parts.prefix),
                "the prefix guard must cover everything but the last user message"
            );
        }

        // A different embedding model produces incomparable vectors, so its
        // entries must not share a bucket.
        assert_ne!(
            semantic_request(&req, "embed-2").map(|p| p.prefix),
            Some(parts.prefix)
        );
    }

    #[test]
    fn semantic_request_declines_shapes_it_cannot_represent() {
        // Trailing assistant turn (a prefill): the ask is not the last message.
        let prefill = chat_request(serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "hello"},
                {"role": "assistant", "content": "Sure, here"},
            ],
        }));
        assert!(semantic_request(&prefill, "embed-1").is_none());

        // Non-text content drives the answer but is not embedded.
        let with_image = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": [
                {"type": "text", "text": "what is this?"},
                {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
            ]}],
        }));
        assert!(semantic_request(&with_image, "embed-1").is_none());

        // Nothing to embed — every blank prompt would otherwise match every other.
        let blank = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "   "}],
        }));
        assert!(semantic_request(&blank, "embed-1").is_none());
    }

    // Truncating an over-long question instead of declining it would make two
    // requests that share a long head — the same pasted document, different
    // questions after it — embed to identical bytes: similarity exactly 1.0,
    // which no threshold rejects and the prefix guard cannot see, because the
    // difference lives in the part that was cut.
    #[test]
    fn an_over_long_question_is_matched_exactly_or_not_at_all() {
        let document = "x".repeat(MAX_EMBED_INPUT_BYTES);
        let ask = |tail: &str| {
            chat_request(serde_json::json!({
                "model": "m",
                "messages": [{"role": "user", "content": format!("{document} {tail}")}],
            }))
        };
        assert!(semantic_request(&ask("summarise the risks"), "embed-1").is_none());
        assert!(semantic_request(&ask("list the parties"), "embed-1").is_none());

        // Right up to the bound is still embeddable, so the rule is a bound and
        // not an accidental blanket refusal of long prompts.
        let at_limit = chat_request(serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "y".repeat(MAX_EMBED_INPUT_BYTES)}],
        }));
        assert!(semantic_request(&at_limit, "embed-1").is_some());
    }

    /// The bucket reads none of the last user message's text, and all of what
    /// it carries beside; a final turn the gateway reads as more than one
    /// message is matched exactly.
    #[test]
    fn the_bucket_reads_all_of_the_last_user_message_but_its_text() {
        let ask = |content: serde_json::Value, name: &str| {
            semantic_request(
                &chat_request(serde_json::json!({"model": "m", "messages": [
                    {"role": "system", "content": "be terse"}, {"role": "user", "content": content, "name": name},
                ]})),
                "embed-1",
            )
            .expect("a text user turn is embeddable")
        };
        let part = |text: &str| serde_json::json!([{"type": "text", "text": text, "cache_control": {"type": "ephemeral"}}]);
        let a = ask(serde_json::json!("what is the capital of France"), "u");
        assert_eq!(a.prefix, ask(serde_json::json!("capital of France?"), "u").prefix);
        let b = ask(part("capital of France?"), "u");
        assert_eq!(b.prefix, ask(part("what is the capital of France"), "u").prefix);
        assert_eq!(b.query, "capital of France?");
        // Everything beside the text still matches exactly: the message's
        // `name`, a part's settings, its parts.
        assert_ne!(a.prefix, ask(serde_json::json!("what is the capital of France"), "v").prefix);
        assert_ne!(a.prefix, b.prefix);
        // Only the text the query reads is blanked: a member nesting a `text`
        // or `content` of its own still keys.
        let member = |context: &str| {
            semantic_request(
                &chat_request(serde_json::json!({"model": "m", "messages": [
                    {"role": "user", "content": "q", "context": {"content": context, "text": context}},
                ]})),
                "embed-1",
            )
            .expect("a text user turn is embeddable")
            .prefix
        };
        assert_ne!(member("tenant A"), member("tenant B"));
        // A Responses input string is its one user message.
        let responses = domain_request(ApiVersion::Responses, serde_json::json!({"model": "m", "input": "hello"}));
        assert_eq!(semantic_request(&responses, "embed-1").map(|p| p.query).as_deref(), Some("hello"));
        // An Anthropic user turn carrying a tool result beside its question.
        let tool_turn = domain_request(ApiVersion::AnthropicMessages, serde_json::json!({"model": "m", "max_tokens": 9, "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "f", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "r"}, {"type": "text", "text": "and?"}]},
        ]}));
        assert!(semantic_request(&tool_turn, "embed-1").is_none());
    }

    #[test]
    fn observe_mode_matches_semantically_so_a_run_can_be_tuned() {
        assert!(matches_semantically(CacheMode::Semantic));
        assert!(matches_semantically(CacheMode::Observe));
        assert!(!matches_semantically(CacheMode::Exact));
    }

    // ── policy parsing ──

    #[test]
    fn unknown_policy_strings_fail_to_the_safe_side() {
        assert_eq!(CacheMode::parse("who-knows"), CacheMode::Observe);
        assert!(!CacheMode::parse("who-knows").serves());
        assert_eq!(CacheShareScope::parse("everyone"), CacheShareScope::User);
    }

    #[test]
    fn policy_clamps_corrupt_values() {
        let p = CachePolicy::from_parts(Some("exact"), Some(-5), Some(9.0), Some("workspace"))
            .expect("mode present");
        assert_eq!(p.ttl_seconds, 3600);
        assert!((p.threshold - 0.9).abs() < f32::EPSILON);
        assert!(CachePolicy::from_parts(None, Some(60), Some(0.9), Some("workspace")).is_none());
    }

    #[test]
    fn share_scope_partitions_as_documented() {
        let ws = Uuid::new_v4();
        let user = Uuid::new_v4();
        assert_eq!(CacheShareScope::User.partition_id(Some(ws), user), user);
        assert_eq!(CacheShareScope::Workspace.partition_id(Some(ws), user), ws);
        assert_eq!(
            CacheShareScope::Tenant.partition_id(Some(ws), user),
            Uuid::nil()
        );
    }
}
