//! Per-session SSE sequence allocator for MCP server-initiated event ids.
//!
//! Each `(tenant_id, mcp_session_id)` pair gets its own monotonically
//! increasing counter. The pump in `handler.rs` calls [`McpSseSequenceMap::next`]
//! immediately before encoding an SSE frame to produce the `q` (sequence)
//! field that lands inside the signed `ssevt.…` event id.
//!
//! ## Why per-proxy is enough
//!
//! The upstream SSE connection for a given MCP session is pinned to whichever
//! proxy POSTed `tools/call` first — sibling proxies don't see the upstream
//! events directly. So one proxy at a time owns the counter for any given
//! session, and a `DashMap<(tenant_id, session_id), u64>` is monotonic for
//! that session's lifetime *within a proxy run*.
//!
//! After a proxy restart the counter resets to zero for sessions that were
//! mid-stream. Clients reconnecting with `Last-Event-ID: ssevt.…q=N` find
//! no rows with `sequence > N` (the new run starts at zero) and silently
//! tail forward.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

/// Per-(tenant, mcp_session) sequence allocator. Cheap; backed by `DashMap`
/// for lock-free `fetch_add` semantics under concurrent SSE pumps.
pub struct McpSseSequenceMap {
    entries: DashMap<(Uuid, String), Entry>,
}

struct Entry {
    next: u64,
    last_touch: Instant,
}

impl Default for McpSseSequenceMap {
    fn default() -> Self {
        Self::empty()
    }
}

impl McpSseSequenceMap {
    pub fn new() -> Arc<Self> {
        Arc::new(Self::empty())
    }

    fn empty() -> Self {
        Self {
            entries: DashMap::new(),
        }
    }

    /// Allocate the next sequence number for `(tenant_id, session_id)`.
    /// Returns 0 for the first call, 1 for the second, etc.
    pub fn next(&self, tenant_id: Uuid, session_id: &str) -> u64 {
        let key = (tenant_id, session_id.to_string());
        let mut entry = self
            .entries
            .entry(key)
            .or_insert(Entry {
                next: 0,
                last_touch: Instant::now(),
            });
        let q = entry.next;
        entry.next = entry.next.saturating_add(1);
        entry.last_touch = Instant::now();
        q
    }

    /// Drop entries that haven't been touched in `max_age`. Safe to run
    /// periodically from a sweep task; idempotent.
    pub fn prune_idle(&self, max_age: Duration) -> usize {
        let now = Instant::now();
        let stale: Vec<_> = self
            .entries
            .iter()
            .filter(|kv| now.duration_since(kv.value().last_touch) > max_age)
            .map(|kv| kv.key().clone())
            .collect();
        let n = stale.len();
        for key in stale {
            self.entries.remove(&key);
        }
        n
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_monotonic_per_session() {
        let map = McpSseSequenceMap::empty();
        let t = Uuid::new_v4();
        assert_eq!(map.next(t, "s1"), 0);
        assert_eq!(map.next(t, "s1"), 1);
        assert_eq!(map.next(t, "s1"), 2);
    }

    #[test]
    fn sessions_are_isolated() {
        let map = McpSseSequenceMap::empty();
        let t = Uuid::new_v4();
        assert_eq!(map.next(t, "s1"), 0);
        assert_eq!(map.next(t, "s2"), 0);
        assert_eq!(map.next(t, "s1"), 1);
        assert_eq!(map.next(t, "s2"), 1);
    }

    #[test]
    fn tenants_are_isolated() {
        let map = McpSseSequenceMap::empty();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        assert_eq!(map.next(t1, "s"), 0);
        assert_eq!(map.next(t2, "s"), 0);
        assert_eq!(map.next(t1, "s"), 1);
        assert_eq!(map.next(t2, "s"), 1);
    }

    #[test]
    fn prune_drops_idle_entries() {
        let map = McpSseSequenceMap::empty();
        let t = Uuid::new_v4();
        let _ = map.next(t, "s1");
        assert_eq!(map.len(), 1);
        // Sleep is ugly but the map's clock is `Instant`; test the boundary
        // by asking for a very short max_age.
        std::thread::sleep(Duration::from_millis(20));
        let n = map.prune_idle(Duration::from_millis(10));
        assert_eq!(n, 1);
        assert_eq!(map.len(), 0);
    }

    #[test]
    fn prune_keeps_recent_entries() {
        let map = McpSseSequenceMap::empty();
        let t = Uuid::new_v4();
        let _ = map.next(t, "s1");
        let n = map.prune_idle(Duration::from_secs(60));
        assert_eq!(n, 0);
        assert_eq!(map.len(), 1);
    }
}
