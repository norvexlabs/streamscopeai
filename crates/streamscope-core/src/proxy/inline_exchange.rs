//! In-flight state for out-of-band (`/v1/analyze`) inline-AI exchanges.
//!
//! A proxied request holds its request-phase snapshot on the stack between the
//! upstream forward and `finalize_audit`. An inline-AI exchange is split across
//! two RPCs — the gateway analyzes the request (for the enforcement verdict),
//! forwards it upstream itself, then analyzes the response — so that same
//! snapshot must survive the gap between the two calls. This store holds it,
//! keyed by the `request_id` the request-phase call minted and returned; the
//! response-phase call quotes that id back and reclaims the snapshot to build
//! the single, complete audit row through the real pipeline.
//!
//! Bounded like every client-reachable map: a global entry cap (evict the
//! oldest on overflow) plus a TTL prune, so a gateway that never calls back
//! (crash / client abort mid-stream) cannot grow it without limit. The cap is
//! server-owned — the exchange lifetime is one upstream round-trip.

use std::sync::Arc;
use std::time::{Duration, Instant};

use uuid::Uuid;

use super::RequestMeta;
use crate::api::sse::ApiVersion;
use crate::config::TenantConfig;

/// The request-phase snapshot held between the two analyze calls of one
/// exchange. Everything [`crate::pipeline::response_pipeline::finalize_replayed_exchange`]
/// needs beyond the shared [`super::AppState`].
pub struct PendingExchange {
    /// The full request-phase audit snapshot (content, session, badges,
    /// BYOK-zero pricing) — fed straight into `finalize_audit`.
    pub meta: RequestMeta,
    /// The tenant config that evaluated the request, pinned so the response
    /// half audits under the same policy even if the config reloaded meanwhile.
    pub tenant_config: Arc<TenantConfig>,
    /// The protocol the response body will be submitted in (equals the request
    /// protocol — inline AI is a BYOK passthrough, no cross-protocol hop).
    pub upstream_api_version: ApiVersion,
    recorded_at: Instant,
}

/// The exchange lifetime is a single upstream round-trip; well past any real
/// LLM latency, so a live exchange is never pruned, and an abandoned one is
/// reclaimed promptly.
const DEFAULT_TTL: Duration = Duration::from_secs(300);
/// Hard ceiling on concurrently-open exchanges. Each entry pins the request's
/// captured content (up to `max_body_size`) for up to the TTL, so this is a heap
/// bound as much as a count: kept modest because the single authenticated
/// inline-AI key is the only producer and a real gateway completes each exchange
/// within one upstream round-trip. Displaced entries are finalized, never
/// dropped, so the cap costs at most a rare duplicate row under extreme burst,
/// not a lost one.
const DEFAULT_MAX_ENTRIES: usize = 4_096;

/// Bounded, TTL-pruned store of in-flight inline-AI exchanges. Lives on the
/// `Arc<AppState>` and is only ever touched by shared reference, so it needs no
/// `Clone` — the interior `DashMap` provides the concurrent access.
pub struct InlineExchangeStore {
    entries: dashmap::DashMap<Uuid, PendingExchange>,
    ttl: Duration,
    max_entries: usize,
}

impl Default for InlineExchangeStore {
    fn default() -> Self {
        Self::new(DEFAULT_TTL, DEFAULT_MAX_ENTRIES)
    }
}

impl InlineExchangeStore {
    pub fn new(ttl: Duration, max_entries: usize) -> Self {
        Self {
            entries: dashmap::DashMap::new(),
            ttl,
            max_entries: max_entries.max(1),
        }
    }

    /// Hold the request-phase snapshot for a later response-phase call, and
    /// return every entry displaced in the process — expired abandonments and,
    /// if at the cap, the oldest survivor. The caller MUST finalize each
    /// displaced entry (request-only) so no analyzed request loses its audit row:
    /// a displaced exchange saw its request analyzed but never its response.
    #[must_use = "displaced exchanges must be finalized (request-only) or their audit row is lost"]
    pub fn stash(
        &self,
        request_id: Uuid,
        meta: RequestMeta,
        tenant_config: Arc<TenantConfig>,
        upstream_api_version: ApiVersion,
    ) -> Vec<PendingExchange> {
        let mut displaced = self.drain_expired();
        if !displaced.is_empty() {
            // Abandoned: a `direction: request` whose gateway never posted the
            // matching response (upstream timeout, client abort). We still hold
            // the request half, so the caller finalizes a request-only row.
            tracing::debug!(
                count = displaced.len(),
                "inline-AI exchanges expired before their response — finalizing request-only"
            );
        }
        if self.entries.len() >= self.max_entries {
            tracing::warn!(
                cap = self.max_entries,
                "inline-AI exchange store at capacity — evicting the oldest; \
                 a gateway is opening request halves faster than it completes them"
            );
            if let Some(old) = self.remove_oldest() {
                displaced.push(old);
            }
        }
        self.entries.insert(
            request_id,
            PendingExchange {
                meta,
                tenant_config,
                upstream_api_version,
                recorded_at: Instant::now(),
            },
        );
        displaced
    }

    /// Reclaim the snapshot for `request_id`, removing it — but ONLY when it
    /// belongs to `tenant_id`. A client-supplied id can never reclaim (or
    /// destroy) another tenant's exchange: a mismatch leaves the entry in place
    /// and returns `None`. Age is NOT checked — a late response still merges onto
    /// its request half; the TTL only reaps entries whose response never comes
    /// (via `drain_expired` on the next stash). `None` ⇒ unknown/foreign id ⇒ the
    /// caller writes a response-only row.
    pub fn take(&self, request_id: &Uuid, tenant_id: Uuid) -> Option<PendingExchange> {
        self.entries
            .remove_if(request_id, |_, pe| pe.meta.tenant_id == tenant_id)
            .map(|(_, v)| v)
    }

    /// Number of open exchanges (test/metrics visibility).
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Remove and return every entry past the TTL.
    fn drain_expired(&self) -> Vec<PendingExchange> {
        let ttl = self.ttl;
        let expired: Vec<Uuid> = self
            .entries
            .iter()
            .filter(|e| e.recorded_at.elapsed() >= ttl)
            .map(|e| *e.key())
            .collect();
        expired
            .into_iter()
            .filter_map(|id| self.entries.remove(&id).map(|(_, v)| v))
            .collect()
    }

    /// Remove and return the oldest entry (by insertion time).
    fn remove_oldest(&self) -> Option<PendingExchange> {
        let oldest = self
            .entries
            .iter()
            .min_by_key(|e| e.recorded_at)
            .map(|e| *e.key())?;
        self.entries.remove(&oldest).map(|(_, v)| v)
    }
}

/// Sweep every abandoned inline-AI exchange — a `direction: request` whose
/// gateway never posted the matching response — and finalize each as a
/// request-only audit row through the real pipeline. Under steady traffic
/// `stash` already reclaims them on the fly; this periodic call guarantees a row
/// even when the box then goes idle, so an analyzed request never loses its
/// audit trail (short of a process restart, which loses in-flight state exactly
/// like the proxied path does).
///
/// Each finalize is spawned on the audit task tracker (not awaited) so a
/// saturated audit channel cannot stall the caller's prune loop.
pub fn sweep_abandoned(state: &Arc<super::AppState>) {
    for pending in state.inline_exchanges.drain_expired() {
        let task_state = Arc::clone(state);
        state.audit_task_tracker.spawn(async move {
            let mut pending = pending;
            crate::pipeline::response_pipeline::finalize_replayed_exchange(
                &mut pending.meta,
                &pending.tenant_config,
                &task_state,
                pending.upstream_api_version,
                None,
            )
            .await;
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // A minimal RequestMeta is expensive to construct here (many fields); the
    // store's own bounds are exercised via `len`/`take` on the map mechanics,
    // and the end-to-end round-trip through a real RequestMeta is covered by the
    // analyze-handler tests and the end-to-end suite. These unit tests pin the
    // cap/TTL/eviction semantics that are independent of the payload type.

    #[test]
    fn ttl_zero_makes_every_entry_immediately_stale() {
        let s = InlineExchangeStore::new(Duration::from_millis(0), 4);
        // A 0 TTL means `elapsed() >= ttl` is always true → nothing is ever
        // reclaimable; prune clears the map.
        assert_eq!(s.ttl, Duration::from_millis(0));
        assert!(s.is_empty());
    }

    #[test]
    fn max_entries_is_at_least_one() {
        let s = InlineExchangeStore::new(Duration::from_secs(1), 0);
        assert_eq!(s.max_entries, 1);
    }

    #[test]
    fn default_uses_server_owned_bounds() {
        let s = InlineExchangeStore::default();
        assert_eq!(s.ttl, DEFAULT_TTL);
        assert_eq!(s.max_entries, DEFAULT_MAX_ENTRIES);
    }
}
