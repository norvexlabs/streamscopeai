//! A2A audit record + pipeline plumbing — the `kind='a2a'` sibling of
//! [`super::mcp`]. One record per gateway A2A request; the edge buffers
//! records offline and ships them to admin-api as `a2a_audit_batch`
//! envelopes, landing one `gateway_audit` parent + one `a2a_audit` child row
//! per record in a single transaction.

use serde::{Deserialize, Serialize};

use super::badge::AuditBadge;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aAuditRecord {
    // ── gateway_audit columns (the parent row) ────────────────────────────
    pub request_id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tenant_id: uuid::Uuid,
    /// Workspace the calling key belongs to — written to
    /// `gateway_audit.workspace_id`.
    pub workspace_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Hashed session id used by `gateway_audit.session_id` — same scheme as
    /// LLM/MCP sessions so cross-kind correlation works.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_method: Option<String>,

    pub latency_total_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,
    /// The limit bucket that refused the call — written to
    /// `gateway_audit.limit_bucket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_bucket: Option<String>,

    // ── a2a_audit columns (the child row) ─────────────────────────────────
    pub agent_id: uuid::Uuid,
    /// A2A operation name (1.0 vocabulary: `SendMessage`, `GetTask`, …).
    pub method: String,
    /// Raw wire `contextId` — the per-protocol conversation correlator
    /// (human-readable in the audit row; `session_id` is the hashed one).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_context_id: Option<String>,
    /// Raw wire `taskId` — one unit of remote work.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_task_id: Option<String>,
    /// Last observed `TASK_STATE_*` for the call.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    /// Accumulated `StreamResponse` envelopes for a streamed call. NULL on
    /// every row a non-streaming dispatch writes.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stream_events: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_code: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_message: Option<String>,
    #[serde(default)]
    pub upstream_latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_bytes: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_bytes: Option<i32>,
    /// Negotiated A2A dialect (`"1.0"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,

    /// Typed audit signal — same `AuditBadge` enum as LLM/MCP audit so the
    /// UI consumer is shared.
    #[serde(default)]
    pub badges: Vec<AuditBadge>,

    /// Per-rule diff payload (filled by policy evaluation; empty object when
    /// no rule fired).
    #[serde(default = "default_empty_object")]
    pub transform_diff: serde_json::Value,
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

/// Trait for forwarding A2A audit records — parallels
/// [`super::mcp::McpAuditForwarderTrait`]. Implemented on the edge side by
/// `EdgeA2aAuditSender`.
pub trait A2aAuditForwarderTrait: Send + Sync {
    fn forward_batch<'a>(
        &'a self,
        records: &'a [A2aAuditRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;
}

/// Channel pair for the A2A audit pipeline.
pub fn create_a2a_audit_channel() -> (
    crate::audit::AuditSender<A2aAuditRecord>,
    crate::audit::AuditReceiver<A2aAuditRecord>,
) {
    crate::audit::counted_channel(crate::settings::core_settings().audit_channel_capacity)
}

/// Background task that drains A2A audit records into batches and forwards
/// them via the supplied trait object. Mirrors
/// [`super::mcp::mcp_audit_writer_task`].
pub async fn a2a_audit_writer_task(
    mut rx: crate::audit::AuditReceiver<A2aAuditRecord>,
    forwarder: Box<dyn A2aAuditForwarderTrait + Send>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let s = crate::settings::core_settings();
    let max_batch = s.audit_batch_size;
    let deadline_ms = s.audit_batch_deadline_ms;
    let mut batch: Vec<A2aAuditRecord> = Vec::with_capacity(max_batch);

    loop {
        let deadline = tokio::time::sleep(std::time::Duration::from_millis(deadline_ms));
        tokio::pin!(deadline);
        let mut sender_dropped = false;

        loop {
            tokio::select! {
                maybe = rx.recv() => match maybe {
                    Some(record) => {
                        batch.push(record);
                        if batch.len() >= max_batch {
                            break;
                        }
                    }
                    None => {
                        // All senders dropped. Flush whatever we have, then exit.
                        sender_dropped = true;
                        break;
                    }
                },
                () = &mut deadline => {
                    break;
                }
                () = shutdown.cancelled() => {
                    // Shutdown requested — exhaustively drain the channel,
                    // flushing in bounded batches, then exit via the tail.
                    while let Ok(record) = rx.try_recv() {
                        batch.push(record);
                        if batch.len() >= max_batch {
                            let records = std::mem::take(&mut batch);
                            let forwarded = forwarder.forward_batch(&records).await;
                            rx.forwarded(records.len());
                            if let Err(e) = forwarded {
                                tracing::error!(count = records.len(), "a2a audit shutdown-drain forward failed: {e}");
                            }
                        }
                    }
                    sender_dropped = true;
                    break;
                }
            }
        }

        if !batch.is_empty() {
            let records = std::mem::take(&mut batch);
            let forwarded = forwarder.forward_batch(&records).await;
            rx.forwarded(records.len());
            if let Err(e) = forwarded {
                tracing::error!(count = records.len(), "a2a audit forward failed: {e}");
            }
        }
        if sender_dropped {
            tracing::info!("a2a audit writer task: draining complete, exiting");
            return;
        }
    }
}
