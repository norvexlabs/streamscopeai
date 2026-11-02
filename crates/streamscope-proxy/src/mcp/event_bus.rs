//! Per-(tenant, user, virtual_server) broadcast bus for MCP server-initiated events.
//!
//! Backs the long-lived `GET /mcp/<slug>` SSE channel. Sources of events:
//!
//! 1. **In-band**: the `stream_method_response` pump for `tools/call` /
//!    `prompts/get` SSE classifies each upstream event. Sampling, elicitation,
//!    and `notifications/.../list_changed` events are published here in
//!    addition to the existing audit emission and downstream-stream
//!    forwarding, so any concurrent GET subscriber for the same user sees the
//!    event without polling.
//!
//! 2. **Cross-instance**: admin-api's ingest of a typed `mcp_audit` row for
//!    sampling/elicitation/list_changed appends an `mcp_user_event` to the
//!    edge events (never for the instance that raised it, whose own
//!    `tools/call` SSE pump already published it here); every other instance
//!    receives it on its next config sync and publishes it onto this local bus
//!    (`edge_link::dispatch_event`).
//!
//! ## Why the key includes `virtual_server_id`
//!
//! A user may hold concurrent GET subscriptions on multiple virtual servers
//! at once (one MCP key per VS, one terminal tab per VS). Without
//! `virtual_server_id` in the key, sampling / elicitation / `list_changed`
//! events from VS-A would land on VS-B's GET stream as well — same user,
//! same tenant. The agent on VS-B would then refresh its catalog (cheap
//! waste) AND learn that VS-A's catalog moved (a cross-VS information leak,
//! albeit within one user's own isolation domain). Keying broadcast on the
//! 3-tuple confines each event to the GET subscriber that initiated the
//! upstream traffic (held end to end by `test_mcp_cross_vs_isolation.py`).
//!
//! The bus is in-process and intentionally lossy — a slow GET subscriber that
//! falls more than `mcp_get_bus_capacity` events behind is closed. Audit
//! rows are the durable record; the bus is best-effort live tail.

use std::sync::Arc;

use bytes::Bytes;
use dashmap::DashMap;
use tokio::sync::broadcast;
use uuid::Uuid;

/// Wire bytes for one SSE event. Already encoded as `event: ... \ndata: ...\n\n`
/// so the GET handler can pass it through verbatim.
#[derive(Clone)]
pub struct UserEvent(pub Bytes);

/// Per-(tenant, user, virtual_server) broadcast bus. One sender lazily created
/// per active user×VS. Senders with zero subscribers stay alive until
/// `prune_idle()` runs; publish to a channel with no subscribers is a fast no-op.
pub struct PerUserEventBus {
    capacity: usize,
    senders: DashMap<(Uuid, Uuid, Uuid), broadcast::Sender<UserEvent>>,
}

impl PerUserEventBus {
    pub fn new(capacity: usize) -> Arc<Self> {
        Arc::new(Self {
            capacity: capacity.max(8),
            senders: DashMap::new(),
        })
    }

    /// Subscribe to events for `(tenant_id, user_id, virtual_server_id)`. The
    /// returned receiver stays open until dropped or until it lags more than
    /// `capacity` events behind; on lag it surfaces `RecvError::Lagged` and
    /// the GET handler drops the connection so the client can reconnect from
    /// a clean state.
    pub fn subscribe(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        virtual_server_id: Uuid,
    ) -> broadcast::Receiver<UserEvent> {
        let entry = self
            .senders
            .entry((tenant_id, user_id, virtual_server_id))
            .or_insert_with(|| {
                let (tx, _rx) = broadcast::channel(self.capacity);
                tx
            });
        entry.subscribe()
    }

    /// Publish an event. If no subscribers exist, returns 0; otherwise returns
    /// the number of subscribers reached. Send failure is logged at debug
    /// (the audit row is the durable record).
    pub fn publish(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        virtual_server_id: Uuid,
        ev: UserEvent,
    ) -> usize {
        let key = (tenant_id, user_id, virtual_server_id);
        let Some(tx) = self.senders.get(&key) else {
            return 0;
        };
        tx.send(ev).unwrap_or_default()
    }

    /// Drop bus entries with zero live subscribers. Cheap to run periodically
    /// from a sweep task; safe to call from any thread.
    pub fn prune_idle(&self) -> usize {
        let stale: Vec<_> = self
            .senders
            .iter()
            .filter(|kv| kv.value().receiver_count() == 0)
            .map(|kv| *kv.key())
            .collect();
        let n = stale.len();
        for key in stale {
            self.senders.remove(&key);
        }
        n
    }

    /// Test-only — current entry count.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.senders.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn subscribe_then_publish_delivers() {
        let bus = PerUserEventBus::new(16);
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        let v = Uuid::new_v4();
        let mut rx = bus.subscribe(t, u, v);
        let n = bus.publish(t, u, v, UserEvent(Bytes::from_static(b"data: hi\n\n")));
        assert_eq!(n, 1);
        let ev = rx.recv().await.unwrap();
        assert_eq!(&ev.0[..], b"data: hi\n\n");
    }

    #[tokio::test]
    async fn cross_user_isolation() {
        let bus = PerUserEventBus::new(16);
        let t = Uuid::new_v4();
        let v = Uuid::new_v4();
        let u1 = Uuid::new_v4();
        let u2 = Uuid::new_v4();
        let _rx1 = bus.subscribe(t, u1, v);
        let mut rx2 = bus.subscribe(t, u2, v);
        let _ = bus.publish(t, u1, v, UserEvent(Bytes::from_static(b"u1\n\n")));
        let _ = bus.publish(t, u2, v, UserEvent(Bytes::from_static(b"u2\n\n")));
        let ev = rx2.recv().await.unwrap();
        assert_eq!(&ev.0[..], b"u2\n\n");
    }

    #[tokio::test]
    async fn cross_tenant_isolation() {
        let bus = PerUserEventBus::new(16);
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let u = Uuid::new_v4();
        let v = Uuid::new_v4();
        let _rx1 = bus.subscribe(t1, u, v);
        let mut rx2 = bus.subscribe(t2, u, v);
        let _ = bus.publish(t1, u, v, UserEvent(Bytes::from_static(b"t1\n\n")));
        let _ = bus.publish(t2, u, v, UserEvent(Bytes::from_static(b"t2\n\n")));
        let ev = rx2.recv().await.unwrap();
        assert_eq!(&ev.0[..], b"t2\n\n");
    }

    #[tokio::test]
    async fn cross_vs_isolation() {
        // Same tenant + same user + two VSes: events must NOT cross the VS
        // boundary. Regression gate for the cross-VS over-fan-out finding —
        // see the module-level "Why the key includes `virtual_server_id`"
        // section.
        let bus = PerUserEventBus::new(16);
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        let v1 = Uuid::new_v4();
        let v2 = Uuid::new_v4();
        let mut rx_v1 = bus.subscribe(t, u, v1);
        let mut rx_v2 = bus.subscribe(t, u, v2);
        // Publish to v1 only.
        let n = bus.publish(t, u, v1, UserEvent(Bytes::from_static(b"v1\n\n")));
        assert_eq!(n, 1);
        // v1's subscriber sees the event.
        let ev = rx_v1.recv().await.unwrap();
        assert_eq!(&ev.0[..], b"v1\n\n");
        // v2's subscriber sees nothing — try_recv yields Empty rather than
        // a stale message.
        assert!(matches!(
            rx_v2.try_recv(),
            Err(tokio::sync::broadcast::error::TryRecvError::Empty)
        ));
    }

    #[tokio::test]
    async fn no_subscribers_is_zero() {
        let bus = PerUserEventBus::new(16);
        let n = bus.publish(
            Uuid::new_v4(),
            Uuid::new_v4(),
            Uuid::new_v4(),
            UserEvent(Bytes::from_static(b"x\n\n")),
        );
        assert_eq!(n, 0);
    }

    #[tokio::test]
    async fn prune_drops_idle_entries() {
        let bus = PerUserEventBus::new(16);
        let t = Uuid::new_v4();
        let u = Uuid::new_v4();
        let v = Uuid::new_v4();
        {
            let _rx = bus.subscribe(t, u, v);
        }
        // Receiver dropped — entry is now idle.
        assert_eq!(bus.len(), 1);
        assert_eq!(bus.prune_idle(), 1);
        assert_eq!(bus.len(), 0);
    }
}
