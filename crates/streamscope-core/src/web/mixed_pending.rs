//! Cross-request cache that folds dispatched intercepted tool-call results
//! from a *mixed-pending* round into the next request's conversation history.
//!
//! ## Why
//!
//! When an upstream turn emits both real and intercepted `tool_use` blocks in
//! the same round ("mixed-pending"), the substitution agent loop dispatches
//! the intercepted call through `WebService` for audit but cannot
//! splice the result into history *within the same request* — the strict
//! Anthropic protocol expects one `tool_result` per `tool_use` and the real
//! `tool_use` is the client's responsibility to resolve. The dispatched
//! result is computed at round-N but the model can only see it once the
//! client comes back with the real tool's continuation in a subsequent
//! request.
//!
//! This cache parks the dispatched result keyed on
//! `(tenant_id, session_id, tool_use_id)`. On the next request in the same
//! session, the inbound splice in `proxy::handle_completion` drains all
//! cache entries for that session, appends a synthesised
//! `assistant tool_use(intercepted) → user tool_result(cached)` pair to the
//! end of `DomainRequest.messages` BEFORE the request goes through transforms
//! and routing. The model's next response sees the dispatched call as
//! historical context.
//!
//! ## Bounds
//!
//! - **TTL** — entries older than `web_search.mixed_pending_cache_ttl_seconds`
//!   (default 3600s = 1h) are pruned on read and on a periodic background
//!   sweep. Bounded growth.
//! - **Single-use** — `drain_for_session` removes entries on retrieval. A
//!   subsequent request in the same session does not re-see the same
//!   intercepted result.
//! - **In-memory** — cross-request but same edge instance. Cross-edge
//!   (load-balanced) requires DB persistence; defer to v2 once production
//!   traffic justifies it.
//! - **Per-session size cap** — `MAX_ENTRIES_PER_SESSION` guards against a
//!   pathological model emitting many intercepted calls per round; oldest
//!   entries are evicted FIFO.

use std::time::{Duration, Instant};

use uuid::Uuid;

/// Hard cap on number of cached entries per session. A model emitting more
/// than this many intercepted calls in a single mixed-pending round is
/// pathological; oldest entries are evicted FIFO.
const MAX_ENTRIES_PER_SESSION: usize = 32;

/// One cached intercepted-and-dispatched call. Stored under a session key
/// until the client's next request in that session drains and splices it.
#[derive(Debug, Clone)]
pub struct MixedPendingEntry {
    /// Tenant guard: every read checks this matches the requesting tenant
    /// before splicing. Defence-in-depth — the session_id UUID is already
    /// tenant-scoped via `session_id_from_client(_, tenant_id, _)`, but a
    /// hash collision or an internal bug shouldn't leak across tenants.
    pub tenant_id: Uuid,
    /// Upstream-supplied `tool_use_id` for the intercepted call. Used as the
    /// `id` on the synthesised `assistant tool_use` block and the
    /// `tool_call_id` on the matching `user tool_result` block.
    pub tool_use_id: String,
    /// The pre-substitution canonical tool name the client declared in its
    /// original request (e.g. `web_search`). Used as the `name` on the
    /// synthesised `assistant tool_use` block — the model must see the same
    /// name it asked for, not the post-substitution wire name.
    pub original_tool_name: String,
    /// Arguments the model emitted, parsed as JSON. `Null` if parsing
    /// failed (rare — the dispatcher already validated the shape).
    pub arguments: serde_json::Value,
    /// The `thoughtSignature` on the call's part (Gemini), spliced back with
    /// the call.
    pub thought_signature: Option<String>,
    /// Model-facing `tool_result` text, spliced verbatim on the next request.
    /// Already guardrail-screened and spotlight-wrapped at park time (the
    /// splice runs in the synchronous request phase and cannot scan): the
    /// JSON-stringified `SearchResult` / `FetchResult` from
    /// `dispatch_intercept`, datamark-wrapped when spotlight is on, or the
    /// enforce-mode placeholder when the scan withheld the content.
    pub result_text: String,
    /// `true` if `dispatch_intercept` returned an error; used to set
    /// `is_error` on the synthesised `tool_result`.
    pub is_error: bool,
    /// When this entry was recorded. Used for TTL eviction.
    pub recorded_at: Instant,
}

/// Process-wide cache keyed by gateway-side session UUID.
///
/// Cloning is shallow (the inner `DashMap` is `Arc`-like). One instance
/// lives on `AppState` for the lifetime of the proxy; tests construct
/// throwaway instances.
#[derive(Debug)]
pub struct MixedPendingCache {
    entries: dashmap::DashMap<Uuid, Vec<MixedPendingEntry>>,
    ttl: Duration,
}

impl MixedPendingCache {
    /// Construct a cache with the given TTL. `ttl_seconds = 0` disables
    /// caching (every insert is immediately considered expired).
    pub fn new(ttl: Duration) -> Self {
        Self {
            entries: dashmap::DashMap::new(),
            ttl,
        }
    }

    /// Convenience: build from the per-tenant TTL setting.
    pub fn from_ttl_secs(ttl_seconds: u64) -> Self {
        Self::new(Duration::from_secs(ttl_seconds))
    }

    /// Configured TTL.
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// Approximate count of all session buckets currently held. Used by
    /// metrics / tests; not on the hot path.
    pub fn session_count(&self) -> usize {
        self.entries.len()
    }

    /// Insert a dispatched intercepted call under `session_id`. Caps
    /// per-session entries at [`MAX_ENTRIES_PER_SESSION`] FIFO. The cap
    /// is rare in practice (a model would need to emit more than 32
    /// intercepted calls in a single mixed-pending round); when it does
    /// kick in we log a warning so an operator can spot pathological
    /// behaviour — the entry is dropped silently from the cache, but the
    /// audit trail of *this* turn still has the dispatch's
    /// `web_audit` row so nothing executed without record.
    pub fn record(&self, session_id: Uuid, entry: MixedPendingEntry) {
        let mut bucket = self.entries.entry(session_id).or_default();
        if bucket.len() >= MAX_ENTRIES_PER_SESSION {
            let dropped = bucket.remove(0);
            tracing::warn!(
                session_id = %session_id,
                tenant_id = %dropped.tenant_id,
                tool_name = %dropped.original_tool_name,
                tool_use_id = %dropped.tool_use_id,
                cap = MAX_ENTRIES_PER_SESSION,
                "mixed-pending cache: per-session FIFO cap reached; oldest entry evicted"
            );
        }
        bucket.push(entry);
    }

    /// Drain all non-expired entries for `(tenant_id, session_id)`. Used by
    /// the inbound splice on the *next* request in the same session.
    /// Expired entries within the bucket are dropped silently. Tenant
    /// mismatches are dropped silently (defence-in-depth).
    ///
    /// Removes the bucket entirely (single-use). Subsequent calls return
    /// empty until new entries are recorded.
    pub fn drain_for_session(
        &self,
        tenant_id: Uuid,
        session_id: Uuid,
    ) -> Vec<MixedPendingEntry> {
        let now = Instant::now();
        let Some((_, bucket)) = self.entries.remove(&session_id) else {
            return Vec::new();
        };
        bucket
            .into_iter()
            .filter(|e| {
                e.tenant_id == tenant_id
                    && now.saturating_duration_since(e.recorded_at) < self.ttl
            })
            .collect()
    }

    /// Periodic eviction — drop expired entries and remove empty buckets.
    /// Returns the number of entries pruned. Call from a background task
    /// (default cadence: every TTL/4) so a quiescent cache doesn't grow
    /// unbounded with stale buckets.
    pub fn prune_expired(&self) -> usize {
        let now = Instant::now();
        let mut pruned = 0usize;
        self.entries.retain(|_session_id, bucket| {
            let before = bucket.len();
            bucket.retain(|e| now.saturating_duration_since(e.recorded_at) < self.ttl);
            pruned += before - bucket.len();
            !bucket.is_empty()
        });
        pruned
    }

    /// Test/debug hook — count of all entries across all sessions. O(N).
    #[doc(hidden)]
    pub fn entry_count_for_test(&self) -> usize {
        self.entries.iter().map(|b| b.value().len()).sum()
    }
}

impl Default for MixedPendingCache {
    fn default() -> Self {
        Self::from_ttl_secs(3600)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(tenant: Uuid, tool_use_id: &str) -> MixedPendingEntry {
        MixedPendingEntry {
            tenant_id: tenant,
            tool_use_id: tool_use_id.to_string(),
            original_tool_name: "web_search".to_string(),
            arguments: serde_json::json!({"query": "x"}),
            result_text: r#"{"hits":[]}"#.to_string(),
            is_error: false,
            recorded_at: Instant::now(),
            thought_signature: None,
        }
    }

    #[test]
    fn record_then_drain_returns_entries() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let session = Uuid::new_v4();
        cache.record(session, entry(tenant, "tu_1"));
        cache.record(session, entry(tenant, "tu_2"));
        let drained = cache.drain_for_session(tenant, session);
        assert_eq!(drained.len(), 2);
        assert_eq!(drained[0].tool_use_id, "tu_1");
        assert_eq!(drained[1].tool_use_id, "tu_2");
        // Single-use: second drain returns empty.
        assert!(cache.drain_for_session(tenant, session).is_empty());
    }

    #[test]
    fn drain_filters_by_tenant() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let session = Uuid::new_v4();
        cache.record(session, entry(tenant_a, "tu_a"));
        // Tenant B querying the same session sees nothing.
        assert!(cache.drain_for_session(tenant_b, session).is_empty());
        // After cross-tenant drain, tenant A's entry is GONE because
        // drain_for_session removes the whole bucket. This is intentional
        // belt-and-suspenders: a session UUID collision across tenants
        // shouldn't surface anything to either side, and the bucket
        // semantically belongs to whichever tenant queried first. In
        // practice session_id_from_client incorporates tenant_id so a
        // collision is cryptographically impossible.
        assert!(cache.drain_for_session(tenant_a, session).is_empty());
    }

    #[test]
    fn drain_drops_expired_entries() {
        let cache = MixedPendingCache::new(Duration::from_millis(10));
        let tenant = Uuid::new_v4();
        let session = Uuid::new_v4();
        cache.record(session, entry(tenant, "tu_old"));
        std::thread::sleep(Duration::from_millis(20));
        let drained = cache.drain_for_session(tenant, session);
        assert!(drained.is_empty(), "expired entries must not surface");
    }

    #[test]
    fn prune_expired_drops_old_buckets() {
        let cache = MixedPendingCache::new(Duration::from_millis(10));
        let tenant = Uuid::new_v4();
        let session = Uuid::new_v4();
        cache.record(session, entry(tenant, "tu_x"));
        assert_eq!(cache.session_count(), 1);
        std::thread::sleep(Duration::from_millis(20));
        assert_eq!(cache.prune_expired(), 1);
        assert_eq!(cache.session_count(), 0);
    }

    #[test]
    fn prune_keeps_fresh_entries_in_partially_expired_bucket() {
        let cache = MixedPendingCache::new(Duration::from_millis(50));
        let tenant = Uuid::new_v4();
        let session = Uuid::new_v4();
        cache.record(session, entry(tenant, "tu_old"));
        std::thread::sleep(Duration::from_millis(40));
        cache.record(session, entry(tenant, "tu_fresh"));
        std::thread::sleep(Duration::from_millis(20));
        // tu_old has now exceeded 50ms; tu_fresh is at ~20ms (under 50ms).
        let pruned = cache.prune_expired();
        assert_eq!(pruned, 1, "exactly the old entry pruned");
        let drained = cache.drain_for_session(tenant, session);
        assert_eq!(drained.len(), 1);
        assert_eq!(drained[0].tool_use_id, "tu_fresh");
    }

    #[test]
    fn record_caps_per_session_at_max_entries() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let session = Uuid::new_v4();
        for i in 0..(MAX_ENTRIES_PER_SESSION + 5) {
            cache.record(session, entry(tenant, &format!("tu_{i}")));
        }
        let drained = cache.drain_for_session(tenant, session);
        assert_eq!(drained.len(), MAX_ENTRIES_PER_SESSION);
        // FIFO eviction: oldest 5 dropped, newest 32 retained.
        assert_eq!(drained[0].tool_use_id, "tu_5");
        assert_eq!(
            drained.last().unwrap().tool_use_id,
            format!("tu_{}", MAX_ENTRIES_PER_SESSION + 5 - 1)
        );
    }

    #[test]
    fn isolated_sessions_dont_cross() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let s1 = Uuid::new_v4();
        let s2 = Uuid::new_v4();
        cache.record(s1, entry(tenant, "tu_1"));
        cache.record(s2, entry(tenant, "tu_2"));
        let d1 = cache.drain_for_session(tenant, s1);
        assert_eq!(d1.len(), 1);
        assert_eq!(d1[0].tool_use_id, "tu_1");
        let d2 = cache.drain_for_session(tenant, s2);
        assert_eq!(d2.len(), 1);
        assert_eq!(d2[0].tool_use_id, "tu_2");
    }
}
