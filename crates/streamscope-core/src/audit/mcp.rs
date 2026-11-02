//! MCP gateway audit record — child of `gateway_audit` (kind='mcp') with
//! per-request JSON-RPC metadata in `mcp_audit`.
//!
//! Mirrors the SQL shape from migration 034. Two physical rows are written
//! per request:
//!
//! 1. `gateway_audit` — common fields shared with LLM traffic (request_id,
//!    timestamp, tenant_id, user_id, key_id, app_id, session_id, user_agent,
//!    ip, kind='mcp', latency_total_ms, status_code, error_*).
//! 2. `mcp_audit` — JSON-RPC method, params, result, virtual server,
//!    upstream server, optional resolved tool/prompt/resource ID.
//!
//! The proxy emits `McpAuditRecord` to its outbox; the edge ships them in an
//! ingest share. Admin-api fans the JSONB array into both tables in a single
//! round-trip.

use serde::{Deserialize, Serialize};

use crate::audit::badge::AuditBadge;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpAuditRecord {
    // ── gateway_audit columns (the parent row) ────────────────────────────
    pub request_id: uuid::Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tenant_id: uuid::Uuid,
    /// Workspace the MCP key belongs to — written to `gateway_audit.workspace_id`.
    pub workspace_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Hashed session id used by `gateway_audit.session_id` — same scheme as
    /// LLM sessions so cross-kind correlation works.
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
    /// The limit bucket that refused the call (`organisation` | `workspace` |
    /// `member` | `key`) — written to `gateway_audit.limit_bucket`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub limit_bucket: Option<String>,

    // ── mcp_audit columns (the child row) ─────────────────────────────────
    pub virtual_server_id: uuid::Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_server_id: Option<uuid::Uuid>,
    /// Raw `Mcp-Session-Id` header value — stays human-readable in the audit
    /// row so admin UI can surface it. Different from `session_id` (hashed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_session_id: Option<String>,
    pub method: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resource_uri: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub params: Option<serde_json::Value>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub protocol_version: Option<String>,

    /// Typed audit signal — same `AuditBadge` enum as LLM audit so the UI
    /// consumer is shared.
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

/// Outcome of a sampling-intercept attempt — populates the
/// `transform_diff.sampling_intercept` field on the `mcp_audit` row when an
/// upstream `sampling/createMessage` was handled by the gateway. Two shapes:
///
/// - `Served { … }` — synthetic LLM call succeeded; the linked `llm_audit`
///   row carries the matching badge + cost. Cross-link is via shared
///   `gateway_audit.session_id`.
/// - `Failed { reason }` — interception attempted but the synthetic call
///   could not be served (auth rejection, budget exceeded, capability
///   mismatch). The agent does NOT see the call in this case to avoid
///   double-billing; the upstream receives a JSON-RPC error.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SamplingInterceptOutcome {
    Served {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        model: Option<String>,
        latency_ms: u64,
    },
    Failed {
        reason: String,
    },
}

impl SamplingInterceptOutcome {
    /// Encode as the JSON value embedded under
    /// `transform_diff.sampling_intercept` on the `mcp_audit` row.
    pub fn to_diff_value(&self) -> serde_json::Value {
        serde_json::to_value(self).unwrap_or(serde_json::Value::Null)
    }
}

// Note: the LLM-side counterpart marker for sampling intercept lives in
// `streamscope_core::proxy::content::SyntheticSourceTag` — that's where the
// `TransformDiff` struct it lands on is defined.

/// Trait for forwarding MCP audit records — parallels [`AuditForwarderTrait`]
/// for LLM audit. Implemented on the edge side by `McpAuditSender`.
pub trait McpAuditForwarderTrait: Send + Sync {
    fn forward_batch<'a>(
        &'a self,
        records: &'a [McpAuditRecord],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>>;
}

/// Channel pair for the MCP audit pipeline.
pub fn create_mcp_audit_channel() -> (
    crate::audit::AuditSender<McpAuditRecord>,
    crate::audit::AuditReceiver<McpAuditRecord>,
) {
    crate::audit::counted_channel(crate::settings::core_settings().audit_channel_capacity)
}

/// Background task that drains MCP audit records into batches and forwards
/// them via the supplied trait object. Mirrors [`audit_writer_task`] for LLM.
pub async fn mcp_audit_writer_task(
    mut rx: crate::audit::AuditReceiver<McpAuditRecord>,
    forwarder: Box<dyn McpAuditForwarderTrait + Send>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let s = crate::settings::core_settings();
    let max_batch = s.audit_batch_size;
    let deadline_ms = s.audit_batch_deadline_ms;
    let mut batch: Vec<McpAuditRecord> = Vec::with_capacity(max_batch);

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
                                tracing::error!(count = records.len(), "mcp audit shutdown-drain forward failed: {e}");
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
                tracing::error!(count = records.len(), "mcp audit forward failed: {e}");
            }
        }
        if sender_dropped {
            tracing::info!("mcp audit writer task: draining complete, exiting");
            return;
        }
    }
}
