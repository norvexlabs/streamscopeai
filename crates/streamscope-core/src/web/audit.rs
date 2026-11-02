//! Web-search audit pipeline. Mirrors [`crate::audit::mcp`] one-for-one:
//! flat record struct → MPSC channel → background writer task → forwarder
//! trait the edge implements to ship rows to admin-api.
//!
//! Two physical rows per backend call: a `gateway_audit` parent
//! (`kind='web'`) and a `web_audit` child carrying the
//! operation-specific payload. Admin-api inserts both in one transaction
//! per the `mcp_audit_batch` envelope pattern.

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use crate::audit::badge::AuditBadge;

/// Audit-side discriminator for the upstream provider's raw response. The
/// service layer caps oversized payloads at the configured KB limit; this
/// enum exposes the cap outcome to consumers (UI, edge → admin sync) as a
/// typed shape rather than free-form JSON.
///
/// Wire format is `#[serde(untagged)]` — `Stripped` matches when the JSON
/// carries the three discriminator fields (`stripped`, `size_bytes`,
/// `reason`); anything else falls through to `Captured`. The writer always
/// emits `stripped: true` for the Stripped variant.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(untagged)]
pub enum WebProviderResponse {
    Stripped(StrippedProviderResponse),
    /// Raw provider body, kept as `serde_json::Value` because the shape is
    /// backend-specific (SearXNG wraps results, Brave/Tavily/etc each have
    /// their own envelope).
    Captured(serde_json::Value),
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct StrippedProviderResponse {
    /// Discriminator for `#[serde(untagged)]` deserialize. Always `true`
    /// when emitted by the cap path.
    pub stripped: bool,
    /// Wire bytes of the upstream response (raw HTTP body length).
    pub size_bytes: u64,
    /// Stable short reason — currently `"oversized"` only.
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WebAuditRecord {
    // ── gateway_audit columns (the parent row) ────────────────────────────
    pub request_id: Uuid,
    pub timestamp: chrono::DateTime<chrono::Utc>,
    pub tenant_id: Uuid,
    /// Workspace the key belongs to — written to `gateway_audit.workspace_id`.
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub key_id: Option<Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_id: Option<String>,
    /// Gateway-side session id in the canonical hashed form
    /// (`session_id_from_client`) — same as every other
    /// `gateway_audit.session_id` producer, so web rows correlate
    /// cross-protocol. `None` on the direct `/mcp/web` and admin-test paths.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<uuid::Uuid>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    /// `gateway_audit.detection_method`: `request` for a substitution call,
    /// which carries its orchestrating request's app and follows it; `direct`
    /// for a call no request made, which names no app.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detection_method: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    pub latency_total_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub status_code: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_category: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<String>,

    /// Orchestrating LLM `gateway_audit.request_id` when this row was produced
    /// by the substitution agent loop. `None` for direct MCP `/mcp/web` calls.
    /// Matches `web_audit.parent_request_id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parent_request_id: Option<Uuid>,
    /// Id of the intercepted model tool_use this dispatch fulfils (substitution
    /// surface only) — joins the row to the LLM turn's `intercepted_tool_calls`
    /// + `guardrail_steps`. `None` for direct MCP `/mcp/web` calls.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tool_use_id: Option<String>,

    // ── web_audit columns (the child row) ──────────────────────────
    /// `mcp_upstream_servers.id` of the synthetic `builtin-web` row.
    pub upstream_server_id: Uuid,
    /// `"search"` or `"fetch"`.
    pub operation: String,
    /// Configured backend code (`"searxng"` | `"brave"` | …).
    pub backend: String,
    /// search → query string; fetch → URL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    /// search → hits returned to caller (post-filter); fetch → 1 on success.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub result_count: Option<i32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_in: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bytes_out: Option<i64>,
    #[serde(default)]
    pub upstream_latency_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<i32>,

    /// One of `"mcp"` (direct `/mcp/web`), `"substitution"` (agent-loop
    /// dispatch), or `"admin_test"` (operator probe via the admin Test
    /// Search panel). Default `"mcp"`.
    #[serde(default = "default_surface")]
    pub surface: String,

    /// Per-URL filter verdicts for search hits + fetch target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url_results: Option<serde_json::Value>,
    /// Ordered filter ids that ran in the chain.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub filter_chain: Option<serde_json::Value>,

    /// Caller-supplied arguments verbatim.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub request_args: Option<serde_json::Value>,
    /// Final response shape returned to the caller.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub response_summary: Option<serde_json::Value>,
    /// Provider-side request URL+method (credentials redacted).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_request: Option<serde_json::Value>,
    /// Provider's raw response (capped at the configured KB limit; oversize
    /// replaced with the [`WebProviderResponse::Stripped`] marker).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_response: Option<WebProviderResponse>,
    /// For fetch operations: blob hashes/MIMEs into audit_media_blobs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub fetch_content_summary: Option<serde_json::Value>,

    /// Typed audit signal — same `AuditBadge` enum as llm_audit / mcp_audit.
    #[serde(default)]
    pub badges: Vec<AuditBadge>,

    /// Per-rule diff payload.
    #[serde(default = "default_empty_object")]
    pub transform_diff: serde_json::Value,
}

fn default_surface() -> String {
    "mcp".to_string()
}

fn default_empty_object() -> serde_json::Value {
    serde_json::Value::Object(Default::default())
}

/// Parallels [`crate::audit::AuditForwarderTrait`] / [`crate::audit::mcp::McpAuditForwarderTrait`].
/// Implemented on the edge side to ship batches to admin-api.
pub trait WebAuditForwarderTrait: Send + Sync {
    fn forward_batch<'a>(
        &'a self,
        records: &'a [WebAuditRecord],
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<(), anyhow::Error>> + Send + 'a>,
    >;
}

/// Channel pair for the web-search audit pipeline.
pub fn create_web_audit_channel() -> (
    crate::audit::AuditSender<WebAuditRecord>,
    crate::audit::AuditReceiver<WebAuditRecord>,
) {
    crate::audit::counted_channel(crate::settings::core_settings().audit_channel_capacity)
}

/// Background task that drains web-search audit records into batches and
/// forwards them via the supplied trait object. Mirrors
/// [`crate::audit::mcp::mcp_audit_writer_task`].
pub async fn web_audit_writer_task(
    mut rx: crate::audit::AuditReceiver<WebAuditRecord>,
    forwarder: Box<dyn WebAuditForwarderTrait + Send>,
    shutdown: tokio_util::sync::CancellationToken,
) {
    let s = crate::settings::core_settings();
    let max_batch = s.audit_batch_size;
    let deadline_ms = s.audit_batch_deadline_ms;
    let mut batch: Vec<WebAuditRecord> = Vec::with_capacity(max_batch);

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
                                tracing::error!(count = records.len(), "web_search audit shutdown-drain forward failed: {e}");
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
                tracing::error!(
                    count = records.len(),
                    "web_search audit forward failed: {e}"
                );
            }
        }
        if sender_dropped {
            tracing::info!("web_search audit writer task: draining complete, exiting");
            return;
        }
    }
}
