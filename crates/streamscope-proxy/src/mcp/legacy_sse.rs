//! Legacy MCP SSE upstream transport (`GET /sse` + `POST /messages`).
//!
//! Pre-Streamable-HTTP MCP servers expose two endpoints:
//!
//! - `GET /sse` — long-lived `text/event-stream` channel. The first event
//!   has type `endpoint` and carries the URL the client should `POST` to
//!   (server-defined; typically a sibling `/messages?session=...` URL).
//!   All subsequent events are JSON-RPC payloads on the `data:` field.
//! - `POST <messages_url>` — JSON-RPC requests / notifications. The server
//!   replies `202 Accepted`; the actual JSON-RPC response rides back on
//!   the long-lived GET channel, correlated by the `id` field.
//!
//! This module owns:
//!
//! 1. **Drain task**: opens GET /sse, parses events, demuxes by id into a
//!    pending oneshot map, and forwards server-initiated payloads (sampling,
//!    elicitation, list_changed notifications) to a caller-provided sink.
//!    Reconnects with backoff on connection drop.
//!
//! 2. **`call_request(req)`** — registers a oneshot for `req.id`, POSTs
//!    the body to the discovered endpoint, awaits the matching response
//!    on the GET channel with a per-call timeout. Returns `SessionLost`
//!    (mapped to JSON-RPC `-32507`) on connection drop or timeout.
//!
//! 3. **`LegacySseSessionMap`** — per-process map keyed by
//!    `(tenant_id, upstream_id, agent_session_id)`. Bounded by
//!    `MCP_LEGACY_SSE_MAX_SESSIONS_PER_INSTANCE` (default 256), idle TTL
//!    30 min via the same sweeper that runs the `McpSessionMap`.
//!
//! v1 scope:
//! - Sync request/response over legacy SSE for every method
//!   (initialize, tools/list, tools/call, prompts/list, prompts/get,
//!   resources/list, resources/read).
//! - Server-initiated sampling/elicitation/list_changed forwarded to the
//!   per-(tenant, user) event bus (concurrent `GET /mcp/<slug>`).
//! - Reverse path (the agent's reply to a server-initiated `sampling`
//!   request) currently re-uses the Streamable-HTTP forward path; a
//!   sampling-aware reverse-routing-through-this-session is a follow-up.

use std::collections::VecDeque;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::BytesMut;
use dashmap::DashMap;
use futures::StreamExt;
use streamscope_core::api::sse::SseDecoder;
use streamscope_core::config::mcp::McpUpstreamServer;
use tokio::sync::oneshot;
use tokio_util::codec::Decoder;
use uuid::Uuid;

/// Recover a poisoned `std::sync::Mutex` guard. The locks below protect
/// short-held simple state (no invariants kept across `.await` points), so
/// a poisoning panic from another thread is best handled by reading
/// whatever value was current — the alternative would crash the whole
/// proxy instance for one bad session.
pub(crate) trait MutexExt<T> {
    fn lock_or_poisoned(&self) -> std::sync::MutexGuard<'_, T>;
}
impl<T> MutexExt<T> for Mutex<T> {
    fn lock_or_poisoned(&self) -> std::sync::MutexGuard<'_, T> {
        self.lock().unwrap_or_else(|e| e.into_inner())
    }
}

use super::jsonrpc::{JsonRpcRequest, JsonRpcResponse, RpcId};
use super::upstream::{
    MCP_MAX_RESPONSE_BYTES, UpstreamError, read_capped_response, redact_upstream_body,
};

/// Caller-supplied sink for upstream-originated events that don't match a
/// pending request id. Production wiring forwards these to the
/// `PerUserEventBus` (concurrent GET-channel subscribers see them) and
/// emits the corresponding audit row. Tests use a plain
/// `Mutex<Vec<Value>>` for assertions.
pub trait UpstreamEventSink: Send + Sync + 'static {
    fn on_event(&self, payload: serde_json::Value);
}

/// Identity of a legacy-SSE session — one per (tenant, user, upstream,
/// agent-side `Mcp-Session-Id`) tuple. The `user_id` term is load-bearing:
/// it stops user B from spoofing user A's `Mcp-Session-Id` and stealing
/// (or being attributed for) A's upstream session. Within the same user
/// the agent_session_id splits failure domains across concurrent agent
/// sessions on the same upstream.
#[derive(Clone, Hash, PartialEq, Eq, Debug)]
pub struct SessionKey {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub upstream_id: Uuid,
    pub agent_session_id: String,
}

/// Resolve the idle-eviction window from settings (`MCP_SESSION_IDLE_TTL_SECS`).
/// Kept in lockstep with the Streamable-HTTP `McpSessionMap` on the same
/// operator-tuned value.
fn session_idle_ttl() -> Duration {
    Duration::from_secs(crate::settings::proxy_settings().mcp_session_idle_ttl_secs)
}

struct PendingMap {
    inner: DashMap<String, oneshot::Sender<JsonRpcResponse>>,
    /// IDs whose caller already gave up (timed out / disconnected).
    /// Late-arriving responses for these IDs are dropped instead of
    /// being routed to a recycled oneshot. Without this set a server
    /// that responds slowly + an agent that recycles JSON-RPC ids per
    /// session would route the previous call's payload to the new
    /// caller. Entries age out after `ABANDONED_TTL`.
    abandoned: DashMap<String, Instant>,
}

/// Resolve the abandoned-id TTL from settings.
fn abandoned_ttl() -> Duration {
    Duration::from_secs(crate::settings::proxy_settings().mcp_legacy_sse_abandoned_ttl_secs)
}

impl PendingMap {
    fn new() -> Self {
        Self {
            inner: DashMap::new(),
            abandoned: DashMap::new(),
        }
    }

    fn insert(&self, id_key: String, tx: oneshot::Sender<JsonRpcResponse>) {
        // If the id was previously abandoned, the caller is reusing the
        // same id for a fresh request. Clear the abandoned marker so the
        // new oneshot can correctly receive THIS call's response.
        self.abandoned.remove(&id_key);
        self.inner.insert(id_key, tx);
    }

    fn remove(&self, id_key: &str) -> Option<oneshot::Sender<JsonRpcResponse>> {
        self.inner.remove(id_key).map(|(_, tx)| tx)
    }

    /// Mark an id as abandoned (timeout / disconnect). Late-arriving
    /// responses are silently dropped. Call before / instead of `remove`
    /// when the caller has already given up on the response.
    fn abandon(&self, id_key: &str) {
        self.inner.remove(id_key);
        self.abandoned.insert(id_key.to_string(), Instant::now());
    }

    /// True if this id was abandoned within `ABANDONED_TTL`. Used by
    /// `handle_event` to drop late responses instead of forwarding them
    /// to the event sink (where they'd surface as bogus server-initiated
    /// events).
    fn is_abandoned(&self, id_key: &str) -> bool {
        let cutoff = Instant::now() - abandoned_ttl();
        match self.abandoned.get(id_key) {
            Some(stamp) if *stamp >= cutoff => true,
            Some(_) => {
                // Expired; clear it so the map stays bounded.
                drop(self.abandoned.get(id_key));
                self.abandoned.remove(id_key);
                false
            }
            None => false,
        }
    }

    /// Drop every pending oneshot. Drives every awaiting `call_request` to
    /// `Err(RecvError)` which the caller maps to `SessionLost`.
    fn drain(&self) -> usize {
        let keys: Vec<String> = self
            .inner
            .iter()
            .map(|kv| kv.key().clone())
            .collect();
        let n = keys.len();
        for k in keys {
            self.inner.remove(&k);
        }
        // Periodic abandoned-set GC piggybacks on drain calls.
        let cutoff = Instant::now() - abandoned_ttl();
        let stale: Vec<String> = self
            .abandoned
            .iter()
            .filter(|kv| *kv.value() < cutoff)
            .map(|kv| kv.key().clone())
            .collect();
        for k in stale {
            self.abandoned.remove(&k);
        }
        n
    }
}

/// One legacy-SSE upstream connection. The drain task owns the GET stream;
/// the public surface is `call_request` (POST + await) and `cancel` (drop
/// the session, abort the drain task).
pub struct LegacySseSession {
    pub key: SessionKey,
    /// Discovered via the first `event: endpoint` SSE event. `None` until
    /// the upstream sends it; calls before discovery race-wait.
    messages_url: arc_swap::ArcSwap<Option<String>>,
    /// Bearer for upstream auth — refreshed in place when per-user-OAuth
    /// rotates, so reconnects pick up the new token without rebuilding the
    /// session.
    bearer: arc_swap::ArcSwap<Option<String>>,
    pending: Arc<PendingMap>,
    request_timeout: Duration,
    last_activity: Mutex<Instant>,
    drain_handle: Mutex<Option<tokio::task::JoinHandle<()>>>,
    /// Set by `cancel()` so the drain task exits its reconnect loop.
    cancelled: Arc<std::sync::atomic::AtomicBool>,
}

impl LegacySseSession {
    /// Open a legacy SSE session against `upstream`. Spawns the drain task
    /// and returns immediately — the caller's first `call_request` may
    /// race the upstream's `endpoint` event; `call_request` waits up to
    /// `request_timeout` for the endpoint URL to land.
    pub fn open(
        key: SessionKey,
        upstream: &McpUpstreamServer,
        bearer: Option<String>,
        request_timeout: Duration,
        reconnect_backoff: Duration,
        sink: Arc<dyn UpstreamEventSink>,
    ) -> Arc<Self> {
        let pending = Arc::new(PendingMap::new());
        let cancelled = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let messages_url = arc_swap::ArcSwap::new(Arc::new(None));
        let bearer_slot = arc_swap::ArcSwap::new(Arc::new(bearer));

        let session = Arc::new(Self {
            key: key.clone(),
            messages_url,
            bearer: bearer_slot,
            pending: pending.clone(),
            request_timeout,
            last_activity: Mutex::new(Instant::now()),
            drain_handle: Mutex::new(None),
            cancelled: cancelled.clone(),
        });

        let drain = {
            let session = session.clone();
            let upstream_url = upstream.upstream_url.clone();
            let cancelled = cancelled.clone();
            tokio::spawn(async move {
                run_drain(
                    upstream_url,
                    session,
                    pending,
                    sink,
                    reconnect_backoff,
                    cancelled,
                )
                .await;
            })
        };
        *session.drain_handle.lock_or_poisoned() = Some(drain);
        session
    }

    pub fn refresh_bearer(&self, bearer: Option<String>) {
        self.bearer.store(Arc::new(bearer));
    }

    pub fn touch(&self) {
        *self.last_activity.lock_or_poisoned() = Instant::now();
    }

    pub fn last_activity(&self) -> Instant {
        *self.last_activity.lock_or_poisoned()
    }

    /// Cancel the session and abort the drain task. Pending oneshots
    /// resolve to `RecvError` → `SessionLost`.
    pub fn cancel(&self) {
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        let n = self.pending.drain();
        if n > 0 {
            tracing::debug!(session = ?self.key, n, "legacy SSE session cancelled — pending drained");
        }
        if let Some(handle) = self.drain_handle.lock_or_poisoned().take() {
            handle.abort();
        }
    }

    /// POST a JSON-RPC request to the discovered endpoint, await the
    /// matching response on the GET channel. Returns `SessionLost` on
    /// connection drop or timeout. The request MUST carry an `id`.
    pub async fn call_request(
        &self,
        client: &reqwest::Client,
        request: &JsonRpcRequest,
    ) -> Result<JsonRpcResponse, UpstreamError> {
        self.touch();
        let id_key = match request.id.as_ref() {
            Some(RpcId::Number(n)) => format!("n:{n}"),
            Some(RpcId::String(s)) => format!("s:{s}"),
            Some(RpcId::Null) | None => {
                return Err(UpstreamError::SessionLost(
                    "request without id cannot await on legacy SSE session".into(),
                ));
            }
        };

        // Wait briefly for the endpoint URL to land if the drain task hasn't
        // finished its handshake yet. Bounded by request_timeout; it's the
        // same bound the caller already accepts for the round-trip.
        let messages_url = self.await_endpoint().await?;

        // `messages_url` is the server-controlled `endpoint` event — an absolute
        // URL we POST the bearer to. Vet it for an internal IP-literal before
        // sending; the guarded client additionally pins the resolved IP at DNS
        // time, so a hostname resolving internal is also refused at connect.
        if let Err(e) = streamscope_mcp_auth::ssrf::check_url_for(
            &messages_url,
            super::upstream::MCP_EGRESS,
        ) {
            return Err(UpstreamError::SsrfRefused(e.to_string()));
        }

        let (tx, rx) = oneshot::channel();
        self.pending.insert(id_key.clone(), tx);

        let body = serde_json::to_vec(request)?;
        let bearer_snapshot = self.bearer.load_full();
        let mut builder = client
            .post(&messages_url)
            .header("Content-Type", "application/json")
            .header("Accept", "application/json, text/event-stream")
            .timeout(self.request_timeout)
            .body(body);
        if let Some(token) = bearer_snapshot.as_ref() {
            builder = builder.header("Authorization", format!("Bearer {token}"));
        }

        let post_resp = match builder.send().await {
            Ok(r) => r,
            Err(e) => {
                self.pending.remove(&id_key);
                return Err(UpstreamError::Transport(e));
            }
        };
        let status = post_resp.status();
        if !status.is_success() && status.as_u16() != 202 {
            self.pending.remove(&id_key);
            let raw_bytes = read_capped_response(post_resp, MCP_MAX_RESPONSE_BYTES)
                .await
                .unwrap_or_default();
            let raw = String::from_utf8_lossy(&raw_bytes);
            let redacted = redact_upstream_body(&raw, bearer_snapshot.as_deref());
            return Err(UpstreamError::Http {
                status: status.as_u16(),
                body: redacted,
                jsonrpc_code: super::upstream::jsonrpc_error_code(&raw_bytes),
                required_capabilities: super::upstream::jsonrpc_required_capabilities(&raw_bytes),
            });
        }

        // Drain post body so the connection returns to the pool.
        // 202 Accepted typically has empty body; some servers return 200 +
        // empty. Either way the response we care about arrives on GET.
        match tokio::time::timeout(self.request_timeout, rx).await {
            Ok(Ok(resp)) => {
                self.touch();
                Ok(resp)
            }
            Ok(Err(_recv)) => Err(UpstreamError::SessionLost(
                "drain task ended before response arrived".into(),
            )),
            Err(_timeout) => {
                // Stamp the id as abandoned so a late-arriving response
                // is dropped instead of routed to a recycled oneshot
                // owned by the next call (which would silently return
                // the previous call's payload). The abandoned set ages
                // out after `ABANDONED_TTL`.
                self.pending.abandon(&id_key);
                Err(UpstreamError::SessionLost(format!(
                    "no response within {}ms",
                    self.request_timeout.as_millis()
                )))
            }
        }
    }

    async fn await_endpoint(&self) -> Result<String, UpstreamError> {
        if let Some(url) = self.messages_url.load_full().as_ref() {
            return Ok(url.clone());
        }
        let deadline = Instant::now() + self.request_timeout;
        loop {
            tokio::time::sleep(Duration::from_millis(25)).await;
            if let Some(url) = self.messages_url.load_full().as_ref() {
                return Ok(url.clone());
            }
            if Instant::now() >= deadline {
                return Err(UpstreamError::SessionLost(
                    "upstream never sent endpoint event".into(),
                ));
            }
            if self.cancelled.load(std::sync::atomic::Ordering::SeqCst) {
                return Err(UpstreamError::SessionLost("session cancelled".into()));
            }
        }
    }
}

impl Drop for LegacySseSession {
    fn drop(&mut self) {
        // Belt-and-suspenders: Drop without an explicit cancel still aborts
        // the spawned drain task so a session that's evicted from the map
        // never leaves a dangling tokio task pumping to a closed sink.
        self.cancelled.store(true, std::sync::atomic::Ordering::SeqCst);
        if let Some(handle) = self.drain_handle.lock_or_poisoned().take() {
            handle.abort();
        }
    }
}

async fn run_drain(
    upstream_url: String,
    session: Arc<LegacySseSession>,
    pending: Arc<PendingMap>,
    sink: Arc<dyn UpstreamEventSink>,
    reconnect_backoff: Duration,
    cancelled: Arc<std::sync::atomic::AtomicBool>,
) {
    while !cancelled.load(std::sync::atomic::Ordering::SeqCst) {
        // Vetted, and the client fetched, on EVERY connection, against the
        // egress lists as they stand then: a listing removed while the session
        // lives stops it at its next reconnect (an IP literal never reaches
        // the resolver), and the client is rebuilt on a list change.
        let outcome = match streamscope_mcp_auth::ssrf::check_url_for(&upstream_url, super::upstream::MCP_EGRESS) {
            Ok(_) => {
                // The stream-shaped client: the request/response one's total
                // timeout would cut the long-lived GET drain mid-stream.
                let client = super::upstream::guarded_stream_client(super::upstream::MCP_EGRESS);
                let bearer_snapshot = session.bearer.load_full();
                drain_once(
                    &client,
                    &upstream_url,
                    bearer_snapshot.as_deref(),
                    &session,
                    pending.as_ref(),
                    sink.as_ref(),
                )
                .await
            }
            Err(e) => Err(format!("refused by the SSRF guard: {e}")),
        };
        match outcome {
            Ok(()) => {
                tracing::debug!(session = ?session.key, "legacy SSE drain ended cleanly");
            }
            Err(e) => {
                tracing::warn!(session = ?session.key, error = %e, "legacy SSE drain ended with error");
            }
        }
        // Reset endpoint — must be re-discovered on reconnect.
        session.messages_url.store(Arc::new(None));
        // Resolve every in-flight call with a session-lost-style oneshot
        // close. Dropping the senders is enough — the receivers' RecvError
        // becomes `SessionLost` at the call site.
        let dropped = pending.drain();
        if dropped > 0 {
            tracing::debug!(session = ?session.key, dropped, "legacy SSE drain reset pending");
        }
        if cancelled.load(std::sync::atomic::Ordering::SeqCst) {
            break;
        }
        tokio::time::sleep(reconnect_backoff).await;
    }
}

async fn drain_once(
    client: &reqwest::Client,
    upstream_url: &str,
    bearer: Option<&str>,
    session: &Arc<LegacySseSession>,
    pending: &PendingMap,
    sink: &dyn UpstreamEventSink,
) -> Result<(), String> {
    let mut builder = client
        .get(upstream_url)
        .header("Accept", "text/event-stream");
    if let Some(token) = bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let resp = builder.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if !status.is_success() {
        return Err(format!("GET failed: HTTP {}", status.as_u16()));
    }
    let mut byte_stream = resp.bytes_stream();
    let mut decoder = SseDecoder::new();
    let mut buf = BytesMut::with_capacity(8 * 1024);
    while let Some(chunk) = byte_stream.next().await {
        if session
            .cancelled
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Ok(());
        }
        let bytes = chunk.map_err(|e| e.to_string())?;
        buf.extend_from_slice(&bytes);
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(ev)) => {
                    session.touch();
                    handle_event(ev, upstream_url, session, pending, sink);
                }
                Ok(None) => break,
                Err(e) => return Err(format!("SSE decode error: {e}")),
            }
        }
    }
    // EOF: try to drain a tail event the server flushed without `\n\n`.
    if let Ok(Some(ev)) = decoder.decode_eof(&mut buf) {
        session.touch();
        handle_event(ev, upstream_url, session, pending, sink);
    }
    Ok(())
}

fn handle_event(
    ev: streamscope_core::api::sse::SseEvent,
    upstream_url: &str,
    session: &Arc<LegacySseSession>,
    pending: &PendingMap,
    sink: &dyn UpstreamEventSink,
) {
    if ev.event_type.as_deref() == Some("endpoint") {
        let resolved = resolve_endpoint(upstream_url, ev.data.trim());
        session.messages_url.store(Arc::new(Some(resolved)));
        return;
    }

    let payload: serde_json::Value = match serde_json::from_str(&ev.data) {
        Ok(v) => v,
        Err(e) => {
            tracing::debug!(error = %e, raw = %ev.data, "legacy SSE: dropping non-JSON event");
            return;
        }
    };

    if let Some(id_key) = id_key_from_value(&payload) {
        // Late response for a call the caller already gave up on —
        // dropping is mandatory to prevent routing it to a future call
        // that recycled the same id.
        if pending.is_abandoned(&id_key) {
            tracing::debug!(
                id_key = %id_key,
                "legacy SSE: dropping late response for abandoned id"
            );
            return;
        }
        if let Some(tx) = pending.remove(&id_key) {
            match serde_json::from_value::<JsonRpcResponse>(payload.clone()) {
                Ok(resp) => {
                    let _ = tx.send(resp);
                    return;
                }
                Err(e) => {
                    tracing::warn!(
                        error = %e,
                        "legacy SSE: payload with known id is not a JSON-RPC response — forwarding to sink"
                    );
                }
            }
        }
    }

    sink.on_event(payload);
}

fn id_key_from_value(value: &serde_json::Value) -> Option<String> {
    let id = value.get("id")?;
    match id {
        serde_json::Value::Number(n) => Some(format!("n:{n}")),
        serde_json::Value::String(s) => Some(format!("s:{s}")),
        _ => None,
    }
}

/// Resolve the `endpoint` event payload against the upstream's GET URL.
///
/// MCP servers commonly emit a path-relative URL (`/messages?session=…`).
/// We support absolute URLs verbatim, root-relative paths joined onto the
/// origin, and same-directory relatives joined onto the GET URL's parent.
/// Falls back to the raw value when nothing parses — the POST will fail
/// with a transport error which the caller already handles.
fn resolve_endpoint(base: &str, raw: &str) -> String {
    let raw = raw.trim();
    if raw.starts_with("http://") || raw.starts_with("https://") {
        return raw.to_string();
    }
    // Find scheme:// + authority in `base` so we can compute origin and
    // parent-dir. Without a `url` crate dep we walk by hand.
    let scheme_end = match base.find("://") {
        Some(i) => i + 3,
        None => return raw.to_string(),
    };
    let authority_end = base[scheme_end..]
        .find('/')
        .map(|i| scheme_end + i)
        .unwrap_or(base.len());
    let origin = &base[..authority_end];
    if let Some(stripped) = raw.strip_prefix('/') {
        return format!("{origin}/{stripped}");
    }
    // Same-directory relative: drop the GET URL's last path segment.
    let path = &base[authority_end..];
    let parent_end = path
        .rfind('/')
        .map(|i| authority_end + i + 1)
        .unwrap_or(authority_end);
    let parent = &base[..parent_end];
    format!("{parent}{raw}")
}

/// Per-process map of `(tenant, upstream, agent_session) → LegacySseSession`.
///
/// `get_or_open` is the only public mutator: it returns an existing session
/// when one is live, or opens a fresh one within the per-instance cap. A
/// background sweep evicts entries idle longer than [`session_idle_ttl`].
pub struct LegacySseSessionMap {
    inner: DashMap<SessionKey, Arc<LegacySseSession>>,
    /// FIFO of session keys for cap-based eviction (oldest opened first).
    /// We use a coarse Mutex here — the lock is held for nanoseconds during
    /// open and the cap is a few hundred entries, so this is not a hot path.
    order: Mutex<VecDeque<SessionKey>>,
    max_per_instance: usize,
}

impl LegacySseSessionMap {
    pub fn new(max_per_instance: usize) -> Arc<Self> {
        Arc::new(Self {
            inner: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            max_per_instance: max_per_instance.max(1),
        })
    }

    /// Returns `Some(session)` if one already exists for this key; else
    /// opens a new one (under the cap). Returns `None` when the cap is
    /// exhausted and no idle entry is available to evict — the caller
    /// surfaces `-32507` to the agent.
    #[allow(clippy::too_many_arguments)]
    pub fn get_or_open(
        self: &Arc<Self>,
        key: SessionKey,
        upstream: &McpUpstreamServer,
        bearer: Option<String>,
        request_timeout: Duration,
        reconnect_backoff: Duration,
        sink: Arc<dyn UpstreamEventSink>,
    ) -> Option<Arc<LegacySseSession>> {
        if let Some(existing) = self.inner.get(&key) {
            existing.refresh_bearer(bearer);
            existing.touch();
            return Some(existing.clone());
        }
        // Capacity check — best-effort eviction of one idle entry, else refuse.
        if self.inner.len() >= self.max_per_instance {
            self.evict_one_idle();
            if self.inner.len() >= self.max_per_instance {
                tracing::warn!(
                    cap = self.max_per_instance,
                    "legacy SSE session map at capacity; refusing new session"
                );
                return None;
            }
        }
        let session = LegacySseSession::open(
            key.clone(),
            upstream,
            bearer,
            request_timeout,
            reconnect_backoff,
            sink,
        );
        self.inner.insert(key.clone(), session.clone());
        self.order.lock_or_poisoned().push_back(key);
        Some(session)
    }

    /// Drop the oldest entry that's been idle past the TTL. Used by
    /// `get_or_open` under capacity pressure. Returns true if an entry
    /// was evicted.
    fn evict_one_idle(&self) -> bool {
        let cutoff = Instant::now() - session_idle_ttl();
        let mut order = self.order.lock_or_poisoned();
        let mut idx = 0;
        while idx < order.len() {
            let candidate = &order[idx];
            if let Some(entry) = self.inner.get(candidate) {
                if entry.last_activity() < cutoff {
                    let key = candidate.clone();
                    drop(entry);
                    order.remove(idx);
                    if let Some((_, sess)) = self.inner.remove(&key) {
                        sess.cancel();
                    }
                    return true;
                }
                idx += 1;
            } else {
                // Stale order entry — clean it up and keep scanning.
                order.remove(idx);
            }
        }
        false
    }

    /// Periodic sweep — remove every entry idle longer than the TTL.
    pub fn sweep(&self) -> usize {
        let cutoff = Instant::now() - session_idle_ttl();
        let stale: Vec<SessionKey> = self
            .inner
            .iter()
            .filter(|kv| kv.value().last_activity() < cutoff)
            .map(|kv| kv.key().clone())
            .collect();
        let n = stale.len();
        for key in &stale {
            if let Some((_, sess)) = self.inner.remove(key) {
                sess.cancel();
            }
        }
        if !stale.is_empty() {
            let mut order = self.order.lock_or_poisoned();
            order.retain(|k| !stale.contains(k));
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_key_handles_number_and_string() {
        let v = serde_json::json!({"id": 42, "result": {}});
        assert_eq!(id_key_from_value(&v), Some("n:42".into()));
        let v = serde_json::json!({"id": "abc", "result": {}});
        assert_eq!(id_key_from_value(&v), Some("s:abc".into()));
        let v = serde_json::json!({"result": {}});
        assert_eq!(id_key_from_value(&v), None);
    }

    #[test]
    fn resolve_endpoint_absolute() {
        assert_eq!(
            resolve_endpoint("https://x.example/sse", "https://y.example/messages?s=1"),
            "https://y.example/messages?s=1"
        );
    }

    #[test]
    fn resolve_endpoint_root_relative() {
        assert_eq!(
            resolve_endpoint("https://x.example/sse", "/messages?s=1"),
            "https://x.example/messages?s=1"
        );
    }

    #[test]
    fn resolve_endpoint_same_directory() {
        assert_eq!(
            resolve_endpoint("https://x.example/api/sse", "messages?s=1"),
            "https://x.example/api/messages?s=1"
        );
    }

    #[test]
    fn resolve_endpoint_root_path_no_trailing_slash() {
        assert_eq!(
            resolve_endpoint("https://x.example", "messages?s=1"),
            "https://x.examplemessages?s=1"
        );
        // Weird, but the GET URL is malformed — the agent's deployment is
        // misconfigured. Better to fall through to the POST and 4xx than
        // silently rewrite.
    }

    struct CountingSink {
        received: std::sync::Mutex<Vec<serde_json::Value>>,
    }
    impl UpstreamEventSink for CountingSink {
        fn on_event(&self, payload: serde_json::Value) {
            self.received.lock_or_poisoned().push(payload);
        }
    }

    #[test]
    fn pending_map_drain_clears_entries() {
        let pending = PendingMap::new();
        let (tx1, _rx1) = oneshot::channel::<JsonRpcResponse>();
        let (tx2, _rx2) = oneshot::channel::<JsonRpcResponse>();
        pending.insert("n:1".into(), tx1);
        pending.insert("n:2".into(), tx2);
        assert_eq!(pending.drain(), 2);
        assert!(pending.remove("n:1").is_none());
    }

    #[tokio::test]
    async fn handle_event_routes_response_to_pending() {
        // Build a synthetic session shell. We can't easily exercise the
        // real `open()` path in a unit test (it spawns a real HTTP GET);
        // instead we exercise `handle_event` directly with a constructed
        // session/pending pair.
        let pending = PendingMap::new();
        let (tx, rx) = oneshot::channel::<JsonRpcResponse>();
        pending.insert("n:7".into(), tx);
        let sink_concrete = Arc::new(CountingSink {
            received: std::sync::Mutex::new(Vec::new()),
        });
        let sink: Arc<dyn UpstreamEventSink> = sink_concrete.clone();

        let session = Arc::new(LegacySseSession {
            key: SessionKey {
                tenant_id: Uuid::nil(),
                user_id: Uuid::nil(),
                upstream_id: Uuid::nil(),
                agent_session_id: "agent-1".into(),
            },
            messages_url: arc_swap::ArcSwap::new(Arc::new(None)),
            bearer: arc_swap::ArcSwap::new(Arc::new(None)),
            pending: Arc::new(PendingMap::new()),
            request_timeout: Duration::from_secs(5),
            last_activity: Mutex::new(Instant::now()),
            drain_handle: Mutex::new(None),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });

        let ev = streamscope_core::api::sse::SseEvent {
            event_type: None,
            data: r#"{"jsonrpc":"2.0","id":7,"result":{"ok":true}}"#.to_string(),
            id: None,
        };
        handle_event(ev, "http://x.example/sse", &session, &pending, sink.as_ref());

        let resp = rx.await.expect("response delivered");
        assert!(resp.error.is_none());
        assert_eq!(
            sink_concrete.received.lock_or_poisoned().len(),
            0,
            "response must NOT also flow to sink"
        );
    }

    #[tokio::test]
    async fn handle_event_endpoint_sets_messages_url() {
        let pending = PendingMap::new();
        let sink = Arc::new(CountingSink {
            received: std::sync::Mutex::new(Vec::new()),
        }) as Arc<dyn UpstreamEventSink>;
        let session = Arc::new(LegacySseSession {
            key: SessionKey {
                tenant_id: Uuid::nil(),
                user_id: Uuid::nil(),
                upstream_id: Uuid::nil(),
                agent_session_id: "agent-1".into(),
            },
            messages_url: arc_swap::ArcSwap::new(Arc::new(None)),
            bearer: arc_swap::ArcSwap::new(Arc::new(None)),
            pending: Arc::new(PendingMap::new()),
            request_timeout: Duration::from_secs(5),
            last_activity: Mutex::new(Instant::now()),
            drain_handle: Mutex::new(None),
            cancelled: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        });
        let ev = streamscope_core::api::sse::SseEvent {
            event_type: Some("endpoint".to_string()),
            data: "/messages?session=abc".to_string(),
            id: None,
        };
        handle_event(ev, "http://x.example/sse", &session, &pending, sink.as_ref());
        let url = session.messages_url.load_full();
        assert_eq!(
            url.as_ref().clone(),
            Some("http://x.example/messages?session=abc".to_string())
        );
    }
}
