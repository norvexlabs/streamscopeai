//! Admission waits for room in the audit pipeline, when the gateway fails
//! closed.
//!
//! Every request a gateway serves ends in an audit record, sent to a bounded
//! channel in front of the outbox writer (which writes to local disk, so an
//! unreachable admin-api does not fill it; a writer slower than the records
//! arriving does). Under `AUDIT_FAIL_MODE=closed` a request is admitted only
//! once every audit channel has room for one: new requests wait here —
//! throughput falls to what the audit trail takes in — instead of finished
//! requests' records piling up in memory, and no audit row is dropped in front
//! of the outbox. `closed` is the default. Under `open` nothing waits here; a
//! record that finds its channel full is dropped and counted
//! (`AuditSender::deliver`). The hold has no deadline: a writer that stops
//! (a disk that hangs) stops the gateway under `closed`.
//!
//! Invariant to preserve: **every route that produces an audit record carries
//! [`hold_for_audit_room`]**; the probes (`/health`, `/ready`), the metadata
//! documents and the metrics listener do not, so a held gateway still answers
//! them. On the routes that carry it every request is held, those that end
//! in no record (a model list) included: telling them apart route by route
//! is a list kept in step with every handler's audit, and a wrong entry lets
//! records past the hold.
//!
//! Admission looks for room; it reserves none. A slot the writer frees may
//! admit several held requests at once, whose records then wait in
//! `deliver`. What waits is bounded by the requests in flight — the clients'
//! own concurrency — never by the rate they arrive at, which is what the
//! hold is for. A reservation held for the request's life would cap the
//! gateway's concurrency at a channel's size even with every channel empty.
//!
//! A held request waits as long as the pipeline stays full: under `closed`, a
//! writer that stops draining (a full disk) stops the gateway, by design, and
//! `/ready` still answers.

use std::sync::atomic::{AtomicU64, Ordering};

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::Response;
use streamscope_core::audit::{AuditRecord, AuditSender, McpAuditRecord};
use streamscope_core::audit::a2a::A2aAuditRecord;
use streamscope_core::web::WebAuditRecord;

/// Requests admitted after waiting for room (cumulative; `/metrics`).
static HELD: AtomicU64 = AtomicU64::new(0);

pub fn held_total() -> u64 {
    HELD.load(Ordering::Relaxed)
}

/// The audit channels a request may write to.
#[derive(Clone)]
pub struct AuditRoom {
    pub llm: AuditSender<AuditRecord>,
    pub mcp: AuditSender<McpAuditRecord>,
    pub a2a: AuditSender<A2aAuditRecord>,
    pub web: AuditSender<WebAuditRecord>,
}

impl AuditRoom {

    /// Wait until every channel has room; whether any had to be waited for.
    async fn wait(&self) -> bool {
        // Each in turn: all share one outbox writer, so a channel that is
        // full marks the whole pipeline as behind.
        let llm = self.llm.room().await;
        let mcp = self.mcp.room().await;
        let a2a = self.a2a.room().await;
        let web = self.web.room().await;
        llm || mcp || a2a || web
    }
}

/// Hold the request until the audit pipeline has room for its record.
pub async fn hold_for_audit_room(State(room): State<AuditRoom>, request: Request, next: Next) -> Response {
    let closed = streamscope_core::settings::core_settings().audit_fail_mode == streamscope_core::settings::AuditFailMode::Closed;
    if closed && room.wait().await {
        HELD.fetch_add(1, Ordering::Relaxed);
    }
    next.run(request).await
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A request waits while a channel is full and goes once it has room;
    /// with room it goes at once (the positive control).
    #[tokio::test]
    async fn a_request_waits_for_room_in_a_full_channel() {
        let (llm, mut llm_rx) = streamscope_core::audit::counted_channel::<AuditRecord>(1);
        let room = AuditRoom {
            llm: llm.clone(),
            mcp: streamscope_core::audit::counted_channel(1).0,
            a2a: streamscope_core::audit::counted_channel(1).0,
            web: streamscope_core::audit::counted_channel(1).0,
        };
        assert!(!room.wait().await, "room: admitted at once");
        llm.try_send(AuditRecord::default()).expect("room for one");
        let waiting = tokio::spawn({
            let room = room.clone();
            async move { room.wait().await }
        });
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        assert!(!waiting.is_finished(), "held while the channel is full");
        llm_rx.recv().await.expect("the record");
        assert!(waiting.await.unwrap(), "admitted once the writer took a record, and counted as held");
    }
}
