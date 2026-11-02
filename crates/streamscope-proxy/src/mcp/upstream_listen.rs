//! Gateway-maintained notification listeners for upstream MCP servers.
//!
//! Without these, an upstream's notifications reach the gateway only when they
//! ride an in-flight `tools/call` / `prompts/get` response — so a server that
//! announces a catalog change with no request in flight is silent, and a
//! client that subscribed and then waited quietly heard nothing. That bound
//! predates the era split, but it is the reason the era a request leg speaks
//! could not be chosen freely: notification sourcing was a side effect of the
//! *legacy* request path, so addressing an upstream in the modern era would
//! have cost the subscription.
//!
//! A listener breaks that coupling. It holds one long-lived stream per
//! `(tenant, user, virtual server, upstream)` — a `GET` SSE channel for a
//! legacy-addressed upstream, a `subscriptions/listen` stream for a modern one
//! — and feeds every event into the same [`UpstreamEventSink`] the legacy-SSE
//! transport and the streaming pump already use. Downstream, nothing changes:
//! events land on the per-`(tenant, user, virtual server)` bus exactly as
//! before, so both the legacy `GET /mcp/<slug>` channel and the modern
//! `subscriptions/listen` stream see them without knowing where they came
//! from.
//!
//! **The key includes the virtual server**, not just the upstream. The bus is
//! keyed that way, and one upstream may be routed by two virtual servers at
//! once: a listener shared between them would publish VS-A's events onto
//! VS-B's stream, which is the cross-VS leak `event_bus` documents at length.
//!
//! **Listeners are started on demand and reaped on idle.** A stream nobody is
//! reading is an open connection and an upstream's resources, so the
//! downstream pumps touch their listener on every keepalive tick and the
//! session sweeper drops anything that has gone quiet for the idle window.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use arc_swap::ArcSwap;
use bytes::BytesMut;
use dashmap::DashMap;
use futures::StreamExt;
use serde_json::Value;
use streamscope_core::api::sse::SseDecoder;
use tokio_util::codec::Decoder;
use uuid::Uuid;

use super::jsonrpc::METHOD_NOT_FOUND;
use super::legacy_sse::{MutexExt, UpstreamEventSink};
use super::modern;

/// Which stream a listener opens, decided by the era the gateway addresses
/// this upstream in.
#[derive(Debug, Clone, PartialEq)]
pub enum ListenTransport {
    /// Legacy Streamable HTTP: the spec's optional `GET <url>` SSE channel.
    /// The server pushes whatever it has; there is no filter to send, because
    /// subscriptions were registered out of band by `resources/subscribe`.
    LegacyGet {
        session_id: Option<String>,
        protocol_version: Option<String>,
    },
    /// Modern: `subscriptions/listen`, whose *response* is the long-lived
    /// stream. The filter travels in the request, so widening it means
    /// re-opening the stream — see [`UpstreamListenerMap::ensure`].
    ModernListen {
        client_capabilities: Value,
        client_info: Value,
    },
}

impl ListenTransport {
    fn is_modern(&self) -> bool {
        matches!(self, Self::ModernListen { .. })
    }
}

/// The state the spawned task shares with its listener handle.
///
/// Held by an `Arc` on both sides — and the task holds **only this**, never the
/// [`UpstreamListener`] itself. A task that held its own listener would keep it
/// alive after the map dropped it, so `Drop` would never fire, the stream would
/// reconnect forever into a bus nobody reads, and the next `ensure` for that
/// key would spawn a *second* listener publishing every upstream event twice.
#[derive(Debug)]
struct ListenerShared {
    cancelled: AtomicBool,
    /// The bearer the task presents on its next reconnect. Swapped rather than
    /// captured so a per-user OAuth rotation reaches a stream that may have
    /// been open since before the refresh.
    bearer: ArcSwap<Option<String>>,
    /// Set when the task ended on a settled answer — the upstream offers no
    /// stream. (A URL the SSRF guard refuses is not one: the egress lists
    /// change at runtime, so it is retried like a failed connection.) Distinct from
    /// "cancelled": a settled listener must NOT be respawned (that is a
    /// reconnect loop against a fixed answer) and must NOT be reported as a
    /// live source, or the acknowledgement promises a client notifications
    /// nothing is listening for.
    settled: AtomicBool,
}

/// One upstream's listener. The stream itself lives in a spawned task.
#[derive(Debug)]
pub struct UpstreamListener {
    shared: Arc<ListenerShared>,
    last_activity: std::sync::Mutex<Instant>,
    /// What the modern stream asked for. Compared on `ensure` so a widened
    /// subscription re-opens rather than silently missing the new type.
    /// Meaningless for a legacy `GET` channel, which has no filter.
    filter: std::sync::Mutex<modern::SubscriptionFilter>,
    /// How the running stream was opened. Compared on `ensure` too: a legacy
    /// channel bakes in the upstream session it was opened with, and an
    /// upstream that restarted has swept that session — the request path
    /// re-handshakes, and without this the listener would reconnect with the
    /// dead id forever while `ensure` kept calling it healthy.
    transport: std::sync::Mutex<ListenTransport>,
    task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct ListenerKey {
    pub tenant_id: Uuid,
    pub user_id: Uuid,
    pub virtual_server_id: Uuid,
    pub upstream_id: Uuid,
    /// The route's namespace prefix.
    ///
    /// In the key because the sink re-envelopes `resources/updated` URIs under
    /// exactly one prefix. Two routes in one virtual server may point at the
    /// same upstream — the data model allows it — and a shared listener would
    /// stamp the last one's prefix on both routes' notifications. The
    /// mis-enveloped URI then fails the downstream filter and the notification
    /// is dropped with no trace, while the acknowledgement had honored it.
    pub route_prefix: String,
}

impl UpstreamListener {
    fn touch(&self) {
        *self.last_activity.lock_or_poisoned() = Instant::now();
    }

    fn last_activity(&self) -> Instant {
        *self.last_activity.lock_or_poisoned()
    }

    fn cancel(&self) {
        self.shared.cancelled.store(true, Ordering::SeqCst);
        if let Some(handle) = self.task.lock_or_poisoned().take() {
            handle.abort();
        }
    }

    /// Whether this entry still has a stream behind it.
    ///
    /// A finished task leaves the entry in the map with nothing running, and
    /// every subscriber's keepalive `touch` then keeps that corpse alive past
    /// the sweeper — so reuse has to ask, not assume.
    fn is_live(&self) -> bool {
        if self.shared.settled.load(Ordering::SeqCst) {
            return false;
        }
        match &*self.task.lock_or_poisoned() {
            Some(handle) => !handle.is_finished(),
            None => false,
        }
    }
}

impl Drop for UpstreamListener {
    fn drop(&mut self) {
        // Backstop only. Every removal path cancels EXPLICITLY before
        // dropping, because relying on the refcount here is what made the
        // first version of this leak: whether `Drop` runs depends on nobody
        // else holding an `Arc`, which is a property of code far from the
        // removal, and getting it wrong leaks a reconnecting stream in
        // silence.
        self.cancel();
    }
}

/// Every listener this proxy instance holds.
#[derive(Debug)]
pub struct UpstreamListenerMap {
    listeners: DashMap<ListenerKey, Arc<UpstreamListener>>,
    max_listeners: usize,
}

/// What one `ensure` call needs in order to open a stream. Grouped into a
/// struct because a listener is addressed by four ids and opened with five
/// more values, and a nine-argument function is a place to transpose two of
/// them.
pub struct ListenRequest {
    pub key: ListenerKey,
    pub upstream_url: String,
    pub bearer: Option<String>,
    pub transport: ListenTransport,
    /// What the caller needs delivered. Only read for a modern stream.
    pub filter: modern::SubscriptionFilter,
}

impl UpstreamListenerMap {
    pub fn new(max_listeners: usize) -> Arc<Self> {
        Arc::new(Self {
            listeners: DashMap::new(),
            max_listeners: max_listeners.max(1),
        })
    }

    /// Start a listener for `req.key`, or keep the running one.
    ///
    /// An existing modern listener whose filter does not already cover what
    /// the caller wants is **replaced**, because the filter travelled in the
    /// request that opened the stream and a modern server delivers only what
    /// it was asked for. Widening in place is not possible; leaving it narrow
    /// would leave a client waiting on a type the acknowledgement said was
    /// honored.
    pub fn ensure(&self, req: ListenRequest, sink: Arc<dyn UpstreamEventSink>) -> bool {
        let mut req = req;
        if let Some(existing) = self.listeners.get(&req.key) {
            existing.touch();
            existing.shared.bearer.store(Arc::new(req.bearer.clone()));
            if existing.shared.settled.load(Ordering::SeqCst) {
                // The upstream answered that it has no stream to offer. That
                // is a fixed answer, not a failure to retry — but it is also
                // not a live source, and the caller must not honor it.
                return false;
            }
            let reusable = existing.is_live()
                && *existing.transport.lock_or_poisoned() == req.transport
                && {
                    let current = existing.filter.lock_or_poisoned();
                    if !req.transport.is_modern() || covers(&current, &req.filter) {
                        true
                    } else {
                        // The re-opened stream asks for the UNION. Asking only
                        // for what this caller wants would silently unsubscribe
                        // every earlier one — and the client that owns those is
                        // still reading a stream that would simply go quiet.
                        req.filter = widen(&current, &req.filter);
                        false
                    }
                };
            if reusable {
                return true;
            }
            tracing::debug!(
                upstream_id = %req.key.upstream_id,
                "MCP listener: re-opening the upstream stream"
            );
            let handle = existing.clone();
            drop(existing);
            // Cancelled EXPLICITLY, before the map drops its reference. The
            // task holds no reference back, so the `Drop` backstop would fire
            // too — but a removal path that depends on a refcount reaching
            // zero somewhere else is the shape that leaked here once already.
            handle.cancel();
            self.listeners.remove(&req.key);
        }

        if self.listeners.len() >= self.max_listeners {
            // Refusing costs this subscription its live notifications, which
            // the caller reports honestly because `false` reaches it. Evicting
            // a running listener at random would instead cut a stream some
            // other client is actively reading.
            tracing::warn!(
                tenant_id = %req.key.tenant_id,
                cap = self.max_listeners,
                "MCP listener map at capacity; not opening another upstream stream"
            );
            return false;
        }

        let shared = Arc::new(ListenerShared {
            cancelled: AtomicBool::new(false),
            bearer: ArcSwap::from(Arc::new(req.bearer)),
            settled: AtomicBool::new(false),
        });
        let listener = Arc::new(UpstreamListener {
            shared: shared.clone(),
            last_activity: std::sync::Mutex::new(Instant::now()),
            filter: std::sync::Mutex::new(req.filter.clone()),
            transport: std::sync::Mutex::new(req.transport.clone()),
            task: std::sync::Mutex::new(None),
        });

        let task = tokio::spawn(run_listener(
            shared,
            req.key.upstream_id,
            req.upstream_url,
            req.transport,
            req.filter,
            sink,
        ));
        *listener.task.lock_or_poisoned() = Some(task);
        // Displacing a concurrent insert would leak its task, so cancel
        // whatever was there rather than letting the map drop it silently.
        if let Some(displaced) = self.listeners.insert(req.key, listener) {
            displaced.cancel();
        }
        true
    }

    /// Keep a listener alive while a downstream subscriber is still reading.
    /// Called from the downstream pumps' keepalive tick: an open stream makes
    /// no requests, so without this the listener behind it would look idle and
    /// be reaped out from under it.
    pub fn touch(&self, key: &ListenerKey) {
        if let Some(l) = self.listeners.get(key) {
            l.touch();
        }
    }

    /// Drop listeners nobody has touched within the idle window.
    pub fn sweep(&self, idle_ttl: Duration) -> usize {
        let cutoff = Instant::now() - idle_ttl;
        let stale: Vec<ListenerKey> = self
            .listeners
            .iter()
            .filter(|kv| kv.value().last_activity() < cutoff)
            .map(|kv| kv.key().clone())
            .collect();
        let n = stale.len();
        for key in stale {
            if let Some((_, listener)) = self.listeners.remove(&key) {
                // Explicit, not left to `Drop`. An idle listener is usually a
                // *live* stream — `last_activity` moves only on `touch`, never
                // on a received event — so the common sweep target is a
                // running task, and a task that outlives its map entry
                // reconnects forever AND lets the next `ensure` spawn a second
                // one, publishing every upstream event twice.
                listener.cancel();
            }
        }
        n
    }

    /// Stop every listener — graceful shutdown.
    pub fn cancel_all(&self) {
        for entry in self.listeners.iter() {
            entry.value().cancel();
        }
        self.listeners.clear();
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.listeners.len()
    }
}

/// Whether a running stream's filter already delivers everything `wanted` asks
/// for. A superset is fine — the gateway narrows again downstream, per
/// subscriber, so an over-broad upstream stream costs bandwidth rather than
/// correctness.
fn covers(current: &modern::SubscriptionFilter, wanted: &modern::SubscriptionFilter) -> bool {
    (current.tools_list_changed || !wanted.tools_list_changed)
        && (current.prompts_list_changed || !wanted.prompts_list_changed)
        && (current.resources_list_changed || !wanted.resources_list_changed)
        && wanted
            .resource_subscriptions
            .iter()
            .all(|uri| current.resource_subscriptions.contains(uri))
}

/// The union of two filters — what a re-opened stream must ask for so the
/// widening does not drop what the previous one was already delivering.
pub fn widen(
    current: &modern::SubscriptionFilter,
    wanted: &modern::SubscriptionFilter,
) -> modern::SubscriptionFilter {
    let mut uris = current.resource_subscriptions.clone();
    for uri in &wanted.resource_subscriptions {
        if !uris.contains(uri) {
            uris.push(uri.clone());
        }
    }
    modern::SubscriptionFilter {
        tools_list_changed: current.tools_list_changed || wanted.tools_list_changed,
        prompts_list_changed: current.prompts_list_changed || wanted.prompts_list_changed,
        resources_list_changed: current.resources_list_changed || wanted.resources_list_changed,
        resource_subscriptions: uris,
    }
}

async fn run_listener(
    shared: Arc<ListenerShared>,
    upstream_id: Uuid,
    upstream_url: String,
    transport: ListenTransport,
    filter: modern::SubscriptionFilter,
    sink: Arc<dyn UpstreamEventSink>,
) {
    let egress = super::upstream::MCP_EGRESS;
    // The guarded client pins the resolved IP at connect and re-vets every
    // redirect hop — this stream is opened on the gateway's own initiative to
    // an operator-supplied URL, so it is exactly the shape the SSRF guard
    // exists for. An IP literal never reaches the resolver, so it is vetted
    // here — on EVERY connection, against the lists as they stand then: a
    // listing removed while the listener runs stops it at its next reconnect,
    // and one added lets a refused listener connect.
    let refused = |upstream_url: &str| match streamscope_mcp_auth::ssrf::check_url_for(upstream_url, egress) {
        Ok(_) => false,
        Err(e) => {
            tracing::warn!(
                upstream_id = %upstream_id,
                error = %e,
                "MCP listener: refusing to open a stream to an internal address"
            );
            true
        }
    };
    // Exponential, capped. A listener is opened on the GATEWAY's initiative,
    // not in response to a client request, so a persistently failing upstream
    // would otherwise be hammered at the base interval for as long as anyone
    // holds a subscription — hundreds of requests a minute against a server
    // that is already unwell, with nobody waiting on any of them. Reset on a
    // stream that actually connected, so a long-lived listener that drops once
    // reconnects promptly.
    let base = Duration::from_millis(
        crate::settings::proxy_settings()
            .mcp_legacy_sse_reconnect_backoff_ms
            .max(1),
    );
    let mut backoff = base;

    while !shared.cancelled.load(Ordering::SeqCst) {
        // Refused now is not refused for good — the lists change at runtime —
        // so it waits like a failed connection, never settles.
        if refused(&upstream_url) {
            backoff = next_backoff(backoff);
            tokio::time::sleep(backoff).await;
            continue;
        }
        // The STREAM-shaped client. `guarded_upstream_client` carries a total
        // request timeout — the correct bound for a request/response call, and
        // fatal here: it applies through the end of the response body, so every
        // listener would be torn down on a 60-second cycle, losing whatever
        // arrived in each reconnect gap. That is precisely the quiet subscription
        // this module exists to prevent, and no test shorter than the timeout
        // would show it. Fetched per connection: a list change rebuilds it.
        let client = super::upstream::guarded_stream_client(egress);
        let bearer = shared.bearer.load_full();
        let outcome = listen_once(
            &client,
            &upstream_url,
            bearer.as_deref(),
            &transport,
            &filter,
            shared.as_ref(),
            sink.as_ref(),
        )
        .await;
        match outcome {
            Ok(Unsupported::Yes) => {
                // The endpoint is optional in the legacy era, and a server
                // that answers `405` is telling us it does not offer one.
                // Retrying would be a reconnect loop against a settled
                // answer — the listener simply ends, and notifications from
                // this upstream keep arriving the way they always did, on
                // in-flight responses.
                tracing::debug!(
                    upstream_id = %upstream_id,
                    "MCP listener: upstream offers no notification stream; not retrying"
                );
                shared.settled.store(true, Ordering::SeqCst);
                return;
            }
            Ok(Unsupported::No) => {
                tracing::debug!(
                    upstream_id = %upstream_id,
                    "MCP listener: upstream stream ended cleanly"
                );
                backoff = base;
            }
            Err(e) => {
                tracing::warn!(
                    upstream_id = %upstream_id,
                    error = %e,
                    backoff_ms = backoff.as_millis() as u64,
                    "MCP listener: upstream stream ended with an error"
                );
                backoff = next_backoff(backoff);
            }
        }
        if shared.cancelled.load(Ordering::SeqCst) {
            return;
        }
        tokio::time::sleep(backoff).await;
    }
}

/// How long to wait before the next reconnect, given how long we waited last
/// time.
///
/// Doubling with a ceiling. A listener is opened on the GATEWAY's initiative,
/// so a persistently failing upstream would otherwise be retried at the base
/// interval for as long as anyone holds a subscription — hundreds of requests
/// a minute against a server that is already unwell, with nobody waiting on
/// any of them. The ceiling is what stops the other failure mode: unbounded
/// doubling would eventually stop retrying at all, and a subscription that
/// gave up is indistinguishable from one that is merely quiet.
fn next_backoff(current: Duration) -> Duration {
    const MAX_BACKOFF: Duration = Duration::from_secs(30);
    current.saturating_mul(2).min(MAX_BACKOFF)
}

/// Whether the upstream told us it has no stream to offer, which is a settled
/// answer rather than a failure to retry.
enum Unsupported {
    Yes,
    No,
}

/// Read a 2xx that is NOT a stream and say which of the two things wearing
/// that shape it is. Telling them apart is what stops a permanent reconnect
/// loop on one side and a permanently silenced subscription on the other.
///
/// `-32601` in a JSON-RPC body is the server saying it does not implement the
/// method — settled, and retrying it would hammer an upstream once per backoff
/// forever. Anything else (an intermediary's HTML error page during a deploy, a
/// truncated body) is transient, so it is retried: settling on one of those
/// would silence the subscription for good on a passing event.
///
/// `read_timeout` is load-bearing and must be the REQUEST/RESPONSE deadline,
/// never the stream one the response arrived on. A body that is not a stream is
/// an envelope of a few hundred bytes, but a server that misframes a long-lived
/// stream as `application/json` produces one that never ends — and read under
/// the stream client's deadlines that classification blocks for minutes, so the
/// attempt neither fails nor retries and nothing is logged, while the
/// acknowledgement has already promised the subscriber delivery. A read that
/// runs out of time is transient by the rule above: it says nothing about
/// whether the method exists.
async fn classify_non_stream_answer(
    resp: reqwest::Response,
    content_type: &str,
    read_timeout: Duration,
) -> Result<Unsupported, String> {
    let read = super::upstream::read_capped_response(resp, 64 * 1024);
    let Ok(body) = tokio::time::timeout(read_timeout, read).await else {
        return Err(format!(
            "expected a stream, got {content_type:?}, and its body did not end within {}s",
            read_timeout.as_secs()
        ));
    };
    // Every arm below is transient except the `-32601`, so the read's own
    // failure changes no decision — but it is the operator's only clue about
    // WHICH of the three shapes arrived, and collapsing them all into one line
    // is how a misframed body and an oversized one look identical in a log.
    let body = match body {
        Ok(bytes) => bytes,
        Err(e) => return Err(format!("expected a stream, got {content_type:?}; body unreadable: {e}")),
    };
    if super::upstream::jsonrpc_error_code(&body) == Some(METHOD_NOT_FOUND) {
        return Ok(Unsupported::Yes);
    }
    Err(format!("expected a stream, got {content_type:?}"))
}

#[allow(clippy::too_many_arguments)]
async fn listen_once(
    client: &reqwest::Client,
    upstream_url: &str,
    bearer: Option<&str>,
    transport: &ListenTransport,
    filter: &modern::SubscriptionFilter,
    shared: &ListenerShared,
    sink: &dyn UpstreamEventSink,
) -> Result<Unsupported, String> {
    let mut builder = match transport {
        ListenTransport::LegacyGet {
            session_id,
            protocol_version,
        } => {
            let mut b = client
                .get(upstream_url)
                .header("Accept", "text/event-stream");
            if let Some(sid) = session_id {
                b = b.header("Mcp-Session-Id", sid.as_str());
            }
            if let Some(v) = protocol_version {
                b = b.header("MCP-Protocol-Version", v.as_str());
            }
            b
        }
        ListenTransport::ModernListen {
            client_capabilities,
            client_info,
        } => {
            // `to_json` emits the flag object; the wire nests it under
            // `notifications`, which is where `SubscriptionFilter::parse`
            // reads it from. Sending it flat is not an error the upstream
            // reports — it parses an empty filter and delivers nothing, so the
            // subscription simply stays quiet forever.
            let params = serde_json::json!({ "notifications": filter.to_json() });
            let request = super::jsonrpc::JsonRpcRequest {
                jsonrpc: "2.0".to_string(),
                id: Some(super::jsonrpc::RpcId::String(format!(
                    "sts-listen-{}",
                    Uuid::new_v4()
                ))),
                method: modern::METHOD_SUBSCRIPTIONS_LISTEN.to_string(),
                params: Some(modern::upgrade_request_params(
                    Some(&params),
                    client_capabilities,
                    client_info,
                    None,
                )),
            };
            let body = serde_json::to_vec(&request).map_err(|e| e.to_string())?;
            client
                .post(upstream_url)
                .header("Content-Type", "application/json")
                .header("Accept", "application/json, text/event-stream")
                .header("MCP-Protocol-Version", modern::MODERN_PROTOCOL_VERSION)
                .header("Mcp-Method", modern::METHOD_SUBSCRIPTIONS_LISTEN)
                .body(body)
        }
    };
    if let Some(token) = bearer {
        builder = builder.header("Authorization", format!("Bearer {token}"));
    }
    let resp = builder.send().await.map_err(|e| e.to_string())?;
    let status = resp.status();
    if status.as_u16() == 405 || status.as_u16() == 501 {
        return Ok(Unsupported::Yes);
    }
    if !status.is_success() {
        return Err(format!("stream refused: HTTP {}", status.as_u16()));
    }
    let content_type = resp
        .headers()
        .get(reqwest::header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    if !content_type.starts_with("text/event-stream") {
        return classify_non_stream_answer(
            resp,
            &content_type,
            Duration::from_secs(
                crate::settings::proxy_settings()
                    .mcp_http_client_timeout_secs
                    .max(1),
            ),
        )
        .await;
    }

    let mut byte_stream = resp.bytes_stream();
    let mut decoder = SseDecoder::new();
    let mut buf = BytesMut::with_capacity(8 * 1024);
    while let Some(chunk) = byte_stream.next().await {
        if shared.cancelled.load(Ordering::SeqCst) {
            return Ok(Unsupported::No);
        }
        let bytes = chunk.map_err(|e| e.to_string())?;
        buf.extend_from_slice(&bytes);
        loop {
            match decoder.decode(&mut buf) {
                Ok(Some(ev)) => forward(&ev.data, transport.is_modern(), sink),
                Ok(None) => break,
                Err(e) => return Err(format!("SSE decode error: {e}")),
            }
        }
    }
    if let Ok(Some(ev)) = decoder.decode_eof(&mut buf) {
        forward(&ev.data, transport.is_modern(), sink);
    }
    Ok(Unsupported::No)
}

/// Hand one decoded event to the sink, if it is something a downstream
/// subscriber could act on.
///
/// The acknowledgement and the closing result of a modern `subscriptions/listen`
/// describe *this* gateway-owned stream, not the upstream's state — relaying
/// either would put a `resultType` on a client's notification channel and, in
/// the acknowledgement's case, tell the client its own subscription had just
/// been confirmed by a server it never addressed.
fn forward(raw: &str, modern_stream: bool, sink: &dyn UpstreamEventSink) {
    let Ok(mut payload) = serde_json::from_str::<Value>(raw) else {
        return;
    };
    let Some(method) = payload.get("method").and_then(Value::as_str) else {
        return;
    };
    // A modern stream carries notifications and nothing else — that era
    // deleted server-initiated requests outright. One arriving here is a
    // non-conforming upstream, and relaying it would put a question on a
    // notification channel: a modern subscriber's revision defines no way to
    // answer it, and a legacy one would answer into a stream nothing is
    // waiting on. A legacy `GET` channel is the opposite case — carrying
    // server-initiated requests is what that channel is FOR — so the check is
    // on the stream's era, not on the message's shape.
    if modern_stream && !method.starts_with("notifications/") {
        tracing::debug!(
            method = %method,
            "MCP listener: dropping a non-notification from a modern stream"
        );
        return;
    }
    if modern_stream {
        // The upstream stamped its own subscription id, naming the stream the
        // GATEWAY opened — meaningless to a downstream subscriber, which
        // correlates on the id of its own subscription. `stamp_subscription_id`
        // writes ours over it on the way out, so leaving the upstream's here
        // would be invisible until the day that stamp is skipped.
        //
        // It lives in `params._meta`, which is where the spec puts it and
        // where the downstream stamp writes — stripping a top-level `_meta`
        // instead is a no-op on every real message.
        if let Some(meta) = payload
            .get_mut("params")
            .and_then(|p| p.as_object_mut())
            .and_then(|p| p.get_mut("_meta"))
            .and_then(|m| m.as_object_mut())
        {
            meta.remove(modern::META_SUBSCRIPTION_ID);
            let empty = meta.is_empty();
            if empty && let Some(params) = payload.get_mut("params").and_then(|p| p.as_object_mut())
            {
                params.remove("_meta");
            }
        }
    }
    sink.on_event(payload);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[allow(clippy::redundant_clone)]
    fn filter(tools: bool, uris: &[&str]) -> modern::SubscriptionFilter {
        modern::SubscriptionFilter {
            tools_list_changed: tools,
            prompts_list_changed: false,
            resources_list_changed: false,
            resource_subscriptions: uris.iter().map(|s| s.to_string()).collect(),
        }
    }

    struct Collect(std::sync::Mutex<Vec<Value>>);
    impl UpstreamEventSink for Collect {
        fn on_event(&self, payload: Value) {
            self.0.lock_or_poisoned().push(payload);
        }
    }

    fn nil_key() -> ListenerKey {
        ListenerKey {
            tenant_id: Uuid::nil(),
            user_id: Uuid::nil(),
            virtual_server_id: Uuid::nil(),
            upstream_id: Uuid::nil(),
            route_prefix: String::new(),
        }
    }

    /// A request whose spawned task never connects: the loopback URL is
    /// refused by the SSRF fast-fail (it backs off and retries), so no socket
    /// is ever opened and what is under test is the map's own bookkeeping.
    fn request(f: modern::SubscriptionFilter) -> ListenRequest {
        ListenRequest {
            key: nil_key(),
            upstream_url: "http://127.0.0.1:1/mcp".to_string(),
            bearer: None,
            transport: ListenTransport::ModernListen {
                client_capabilities: serde_json::json!({}),
                client_info: serde_json::json!({}),
            },
            filter: f,
        }
    }

    #[tokio::test]
    async fn ensure_re_opens_with_the_union_not_the_new_callers_filter() {
        // The regression this guards: replacing the running filter with the
        // caller's would unsubscribe everything an earlier subscriber asked
        // for, and its stream would go quiet rather than error — the failure
        // is a notification that never arrives, which looks exactly like a
        // server with nothing to say.
        let map = UpstreamListenerMap::new(4);
        let key = nil_key();
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        let req = request;

        map.ensure(req(filter(true, &["a"])), sink.clone());
        map.ensure(req(filter(false, &["b"])), sink.clone());
        assert_eq!(map.len(), 1);
        let running = map.listeners.get(&key).unwrap();
        let f = running.filter.lock_or_poisoned().clone();
        assert!(f.tools_list_changed, "{f:?}");
        assert!(f.resource_subscriptions.contains(&"a".to_string()), "{f:?}");
        assert!(f.resource_subscriptions.contains(&"b".to_string()), "{f:?}");
    }

    #[tokio::test]
    async fn a_swept_listener_actually_stops() {
        // The bug this pins: the task used to hold an `Arc` to its own
        // listener, so the map dropping its reference was never the last one
        // and `Drop` — the only thing that cancelled — never fired. The
        // symptom is invisible from the map: `len()` reads 0 while the task
        // reconnects forever, and the NEXT `ensure` for that key spawns a
        // second stream, publishing every upstream event twice.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        assert!(map.ensure(request(filter(true, &[])), sink.clone()));
        let shared = map.listeners.get(&nil_key()).unwrap().shared.clone();
        assert!(!shared.cancelled.load(Ordering::SeqCst));

        // Zero TTL: everything is idle.
        assert_eq!(map.sweep(Duration::from_secs(0)), 1);
        assert_eq!(map.len(), 0);
        // The claim that matters — the task was told to stop, not merely
        // forgotten about.
        assert!(shared.cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_stops_every_listener() {
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        assert!(map.ensure(request(filter(true, &[])), sink));
        let shared = map.listeners.get(&nil_key()).unwrap().shared.clone();
        map.cancel_all();
        assert_eq!(map.len(), 0);
        // `clear()` alone would drop the entries and cancel nothing, leaving
        // streams reconnecting into a draining audit channel while the process
        // goes away — and the docs claim shutdown closes them.
        assert!(shared.cancelled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn a_settled_listener_is_not_reported_as_a_live_source() {
        // An upstream that answered `405` has no stream to offer. That is a
        // fixed answer, so it must not be respawned in a loop — and it must
        // not be counted as sourceable either, or the acknowledgement promises
        // a client notifications nothing is listening for.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        assert!(map.ensure(request(filter(true, &[])), sink.clone()));
        map.listeners
            .get(&nil_key())
            .unwrap()
            .shared
            .settled
            .store(true, Ordering::SeqCst);
        assert!(!map.ensure(request(filter(true, &[])), sink));
    }

    #[tokio::test]
    async fn a_stale_transport_re_opens_rather_than_being_reused() {
        // A legacy channel bakes in the upstream session it was opened with.
        // When that upstream restarts, the request path re-handshakes and
        // `ensure` is called with the new id — but a reuse path that compared
        // only the filter would keep reconnecting on the dead one forever
        // while reporting the listener healthy.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        let legacy = |sid: &str| {
            let mut r = request(filter(false, &[]));
            r.transport = ListenTransport::LegacyGet {
                session_id: Some(sid.to_string()),
                protocol_version: None,
            };
            r
        };
        assert!(map.ensure(legacy("old-session"), sink.clone()));
        let first = map.listeners.get(&nil_key()).unwrap().shared.clone();
        assert!(map.ensure(legacy("new-session"), sink));
        assert!(first.cancelled.load(Ordering::SeqCst), "the stale stream kept running");
        let now = map.listeners.get(&nil_key()).unwrap();
        assert_eq!(
            *now.transport.lock_or_poisoned(),
            ListenTransport::LegacyGet {
                session_id: Some("new-session".to_string()),
                protocol_version: None,
            }
        );
    }

    #[test]
    fn a_running_stream_covers_a_subset_but_not_a_new_type() {
        let running = filter(true, &["a"]);
        assert!(covers(&running, &filter(true, &["a"])));
        assert!(covers(&running, &filter(false, &[])));
        // A type the running stream never asked for. A modern server delivers
        // only what the request named, so treating this as covered would
        // leave the client waiting on a notification the acknowledgement said
        // was honored.
        assert!(!covers(&running, &filter(true, &["b"])));
        let mut wants_prompts = filter(true, &[]);
        wants_prompts.prompts_list_changed = true;
        assert!(!covers(&running, &wants_prompts));
    }

    #[test]
    fn widening_never_drops_what_the_stream_already_delivered() {
        // The re-opened stream has to ask for the union. Asking only for the
        // new subscription would silently unsubscribe every earlier one, and
        // the client that owned them is still reading.
        let widened = widen(&filter(true, &["a"]), &filter(false, &["b"]));
        assert!(widened.tools_list_changed);
        assert!(widened.resource_subscriptions.contains(&"a".to_string()));
        assert!(widened.resource_subscriptions.contains(&"b".to_string()));
        assert_eq!(widened.resource_subscriptions.len(), 2);
        assert!(covers(&widened, &filter(true, &["a"])));
        assert!(covers(&widened, &filter(false, &["b"])));
    }

    #[test]
    fn every_flag_is_unioned_from_both_sides() {
        // One flag asserted is three flags assumed: each is its own `||`, and
        // a mistake in any of them drops that notification type for whichever
        // subscriber asked for it — silently, since the stream simply stays
        // quiet on that type.
        let mut only_prompts = filter(false, &[]);
        only_prompts.prompts_list_changed = true;
        let mut only_resources = filter(false, &[]);
        only_resources.resources_list_changed = true;

        for (a, b) in [
            (only_prompts.clone(), only_resources.clone()),
            (only_resources, only_prompts),
        ] {
            let w = widen(&a, &b);
            assert!(w.prompts_list_changed, "{w:?}");
            assert!(w.resources_list_changed, "{w:?}");
        }

        // And a flag neither side asked for is not invented.
        let neither = widen(&filter(false, &[]), &filter(false, &[]));
        assert!(!neither.tools_list_changed);
        assert!(!neither.prompts_list_changed);
        assert!(!neither.resources_list_changed);
    }

    #[test]
    fn a_type_nobody_asked_for_is_covered_by_a_stream_that_does_not_carry_it() {
        // The `!wanted` half of each clause. Without it a filter asking for
        // nothing would read as *not* covered by a stream carrying nothing,
        // and every `ensure` would re-open a perfectly good stream — dropping
        // whatever arrived during the reconnect, on every call.
        assert!(covers(&filter(false, &[]), &filter(false, &[])));
    }

    #[tokio::test]
    async fn a_recently_touched_listener_survives_the_sweep() {
        // The negative control for `a_swept_listener_actually_stops`: without
        // it, a sweeper that reaped everything unconditionally — or compared
        // the clock the wrong way round — would pass that test perfectly while
        // cutting every live subscription on the next tick.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        assert!(map.ensure(request(filter(true, &[])), sink));
        assert_eq!(map.sweep(Duration::from_secs(3600)), 0);
        assert_eq!(map.len(), 1);
        assert!(
            !map.listeners
                .get(&nil_key())
                .unwrap()
                .shared
                .cancelled
                .load(Ordering::SeqCst)
        );
    }

    #[tokio::test]
    async fn an_entry_whose_task_is_gone_is_re_opened_rather_than_reused() {
        // A finished task leaves the entry behind, and every subscriber's
        // keepalive `touch` then keeps that corpse past the sweeper. Reuse has
        // to ask whether a stream is actually running, not whether a map entry
        // exists.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        assert!(map.ensure(request(filter(true, &[])), sink.clone()));
        {
            let entry = map.listeners.get(&nil_key()).unwrap();
            assert!(entry.is_live() || entry.task.lock_or_poisoned().is_some());
            // Simulate the task having ended without the entry being removed.
            *entry.task.lock_or_poisoned() = None;
            assert!(!entry.is_live());
        }
        let first = map.listeners.get(&nil_key()).unwrap().shared.clone();
        assert!(map.ensure(request(filter(true, &[])), sink));
        let now = map.listeners.get(&nil_key()).unwrap().shared.clone();
        assert!(!Arc::ptr_eq(&first, &now), "the dead entry was reused");
    }

    #[tokio::test]
    async fn dropping_a_listener_handle_stops_its_task() {
        // The backstop, asserted so it stays one. Every removal path cancels
        // explicitly, so nothing depends on this alone — but a `Drop` that
        // quietly stopped cancelling would remove the only safety net under a
        // future removal path that forgets.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        assert!(map.ensure(request(filter(true, &[])), sink));
        let (_, listener) = map.listeners.remove(&nil_key()).unwrap();
        let shared = listener.shared.clone();
        assert!(!shared.cancelled.load(Ordering::SeqCst));
        drop(listener);
        assert!(shared.cancelled.load(Ordering::SeqCst));
    }

    #[test]
    fn the_backoff_doubles_and_then_stops_growing() {
        // Both halves matter and each fails silently on its own. Without the
        // doubling a failing upstream is retried at the base interval
        // forever; without the ceiling the interval grows until the
        // subscription has effectively given up, which looks exactly like a
        // server with nothing to say.
        assert_eq!(next_backoff(Duration::from_secs(1)), Duration::from_secs(2));
        assert_eq!(next_backoff(Duration::from_secs(2)), Duration::from_secs(4));
        // The ceiling, on both sides of it.
        assert_eq!(next_backoff(Duration::from_secs(15)), Duration::from_secs(30));
        assert_eq!(next_backoff(Duration::from_secs(16)), Duration::from_secs(30));
        assert_eq!(next_backoff(Duration::from_secs(30)), Duration::from_secs(30));
        // A pathological configured base must not wrap into a short interval.
        assert_eq!(next_backoff(Duration::MAX), Duration::from_secs(30));
    }

    #[tokio::test]
    async fn touching_a_listener_is_what_keeps_it_out_of_the_sweep() {
        // The positive control for `touch` itself. A sweeper is only correct
        // relative to something moving the clock forward, and an open
        // subscription issues no requests — so if `touch` stopped working,
        // every live stream would be cut on the next tick while both
        // sweep tests kept passing.
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        let ttl = Duration::from_millis(100);

        let untouched = UpstreamListenerMap::new(4);
        assert!(untouched.ensure(request(filter(true, &[])), sink.clone()));
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(untouched.sweep(ttl), 1, "an idle listener should be reaped");

        let touched = UpstreamListenerMap::new(4);
        assert!(touched.ensure(request(filter(true, &[])), sink));
        tokio::time::sleep(Duration::from_millis(250)).await;
        touched.touch(&nil_key());
        assert_eq!(touched.sweep(ttl), 0, "a touched listener must survive");
    }

    #[tokio::test]
    async fn an_unchanged_legacy_listener_is_reused() {
        // A legacy channel has no filter to compare, so its reuse rests
        // entirely on the transport being unchanged. Re-opening it on every
        // call would drop whatever arrived during each reconnect — a stream
        // that is up, and lossy, and looks healthy.
        let map = UpstreamListenerMap::new(4);
        let sink: Arc<dyn UpstreamEventSink> = Arc::new(Collect(std::sync::Mutex::new(Vec::new())));
        let legacy = || {
            let mut r = request(filter(false, &[]));
            r.transport = ListenTransport::LegacyGet {
                session_id: Some("s".into()),
                protocol_version: None,
            };
            r
        };
        assert!(map.ensure(legacy(), sink.clone()));
        let first = map.listeners.get(&nil_key()).unwrap().shared.clone();
        assert!(map.ensure(legacy(), sink));
        let now = map.listeners.get(&nil_key()).unwrap().shared.clone();
        assert!(Arc::ptr_eq(&first, &now), "a healthy legacy stream was re-opened");
    }

    #[test]
    fn only_a_modern_stream_reports_itself_as_one() {
        // The flag gates both the filter comparison and what `forward` will
        // relay. Reading a legacy `GET` channel as modern would drop every
        // server-initiated request that channel exists to carry.
        assert!(
            ListenTransport::ModernListen {
                client_capabilities: serde_json::json!({}),
                client_info: serde_json::json!({}),
            }
            .is_modern()
        );
        assert!(
            !ListenTransport::LegacyGet {
                session_id: None,
                protocol_version: None,
            }
            .is_modern()
        );
    }

    #[test]
    fn only_notifications_reach_the_sink() {
        let sink = Collect(std::sync::Mutex::new(Vec::new()));
        // A JSON-RPC *response* — the acknowledgement or the closing result of
        // the gateway's own listen request. It describes this stream, not the
        // upstream's state.
        forward(r#"{"jsonrpc":"2.0","id":1,"result":{"resultType":"ack"}}"#, true, &sink);
        // A server-initiated request and a notification both carry `method`
        // and both are the upstream telling us something.
        forward(r#"{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}"#, true, &sink);
        forward("not json", true, &sink);
        let got = sink.0.lock_or_poisoned();
        assert_eq!(got.len(), 1, "{got:?}");
        assert_eq!(got[0]["method"], "notifications/tools/list_changed");
    }

    #[test]
    fn the_upstreams_subscription_id_is_stripped() {
        // Ours is stamped downstream, per subscriber. Two ids on one message
        // disagree, and the client's own is the only one it can correlate.
        let sink = Collect(std::sync::Mutex::new(Vec::new()));
        forward(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"upstream-7","progressToken":3}}}"#,
            true,
            &sink,
        );
        let got = sink.0.lock_or_poisoned();
        assert!(
            got[0]["params"]["_meta"]
                .get(modern::META_SUBSCRIPTION_ID)
                .is_none(),
            "{got:?}"
        );
        // Everything else in `_meta` is the upstream's to send.
        assert_eq!(got[0]["params"]["_meta"]["progressToken"], 3);
    }

    #[test]
    fn a_legacy_stream_leaves_meta_untouched() {
        // There is no subscription id in that era, so nothing to strip — and
        // stripping by shape rather than by era would edit a key that meant
        // something else.
        let sink = Collect(std::sync::Mutex::new(Vec::new()));
        forward(
            r#"{"jsonrpc":"2.0","method":"notifications/message","params":{"_meta":{"io.modelcontextprotocol/subscriptionId":"x"}}}"#,
            false,
            &sink,
        );
        let got = sink.0.lock_or_poisoned();
        assert_eq!(got[0]["params"]["_meta"][modern::META_SUBSCRIPTION_ID], "x");
    }

    /// One HTTP/1.1 response on a fresh loopback port, written by hand so the
    /// body can be left deliberately unfinished. That is the shape a server
    /// produces when it misframes a long-lived stream as `application/json`,
    /// and no HTTP server library will emit it for us.
    async fn serve_once(
        content_type: &str,
        payload: &'static str,
        finish: bool,
    ) -> (String, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let head = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: {content_type}\r\nTransfer-Encoding: chunked\r\n\r\n"
        );
        let task = tokio::spawn(async move {
            let Ok((mut sock, _)) = listener.accept().await else {
                return;
            };
            // Drain the request head, or the client's write never completes.
            let mut scratch = [0u8; 4096];
            let _ = sock.read(&mut scratch).await;
            let _ = sock.write_all(head.as_bytes()).await;
            let _ = sock
                .write_all(format!("{:X}\r\n{payload}\r\n", payload.len()).as_bytes())
                .await;
            if finish {
                let _ = sock.write_all(b"0\r\n\r\n").await;
                return;
            }
            // Hold the connection open with the body unterminated.
            std::future::pending::<()>().await;
        });
        (format!("http://{addr}/"), task)
    }

    #[tokio::test]
    async fn an_unfinished_non_stream_body_ends_the_attempt_instead_of_blocking_on_it() {
        // The defect this pins: the classification read inherited the deadlines
        // of the STREAM client the response arrived on — a wall-clock ceiling
        // plus an idle bound measured in minutes. An upstream that misframes
        // its `subscriptions/listen` stream as `application/json` therefore
        // parked the listener inside this read: no error, no retry, nothing
        // logged, while the acknowledgement had already told the subscriber
        // that type would be delivered.
        let (url, server) = serve_once("application/json", r#"{"jsonrpc":"2.0"}"#, false).await;
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let started = Instant::now();
        let out =
            classify_non_stream_answer(resp, "application/json", Duration::from_millis(200)).await;
        let e = out
            .err()
            .expect("a body that never ends says nothing about whether the method exists");
        assert!(e.contains("did not end"), "{e}");
        assert!(started.elapsed() < Duration::from_secs(5), "{:?}", started.elapsed());
        server.abort();
    }

    #[tokio::test]
    async fn a_method_not_found_body_still_settles_the_listener() {
        // The positive control the bound needs. A deadline that turned every
        // non-stream answer into a retry would leave the `-32601` case — the
        // upstream stating it has no such method — reconnecting forever, and
        // this test would go on passing on the timeout alone without it.
        let (url, server) = serve_once(
            "application/json",
            r#"{"jsonrpc":"2.0","id":1,"error":{"code":-32601,"message":"no"}}"#,
            true,
        )
        .await;
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let out =
            classify_non_stream_answer(resp, "application/json", Duration::from_secs(10)).await;
        assert!(matches!(out, Ok(Unsupported::Yes)));
        server.abort();
    }

    #[tokio::test]
    async fn a_finished_body_that_is_not_method_not_found_is_retried() {
        // An intermediary's error page during a deploy. Transient, so the
        // listener retries — and it must not be reported as the timeout, which
        // is a different fault an operator would chase differently.
        let (url, server) = serve_once("text/html", "<html>bad gateway</html>", true).await;
        let resp = reqwest::Client::new().get(&url).send().await.unwrap();
        let out = classify_non_stream_answer(resp, "text/html", Duration::from_secs(10)).await;
        let e = out.err().expect("an error page is not a statement about the method");
        assert!(e.contains("expected a stream") && !e.contains("did not end"), "{e}");
        server.abort();
    }
}
