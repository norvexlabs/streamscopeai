//! Orchestration layer that ties backend, URL filter, audit, and (later)
//! tool policy together. The MCP virtual server calls into [`search`] and
//! [`fetch`]; the v2 substitution surface will call the same functions.
//!
//! Per-call flow:
//! 1. Search: construct the configured [`super::Backend`] from settings +
//!    decrypted credential. Short-circuit with [`super::WebError::NoBackend`] /
//!    [`super::WebError::MissingCredential`] if unconfigured. Fetch needs no
//!    backend — the built-in fetcher serves every tenant.
//! 2. Build the URL [`super::FilterChain`] from settings (allow/deny lists).
//! 3. Run the operation against the backend (or built-in fetcher).
//! 4. Walk every produced URL through the filter chain; record verdicts.
//! 5. Cap `provider_response` at the configured KB limit.
//! 6. Emit one `WebAuditRecord` to the audit channel.
//! 7. Return the post-filter result to the caller.
//!
//! Audit emission is best-effort: a closed channel logs a warning but does
//! not fail the call.

use std::sync::Arc;
use std::time::Instant;

use uuid::Uuid;

use super::audit::{StrippedProviderResponse, WebAuditRecord, WebProviderResponse};
use super::backend::{Backend, BackendSearchOutcome};
use super::fetch::fetch_builtin;
use super::filters::DestinationListFilter;
use super::settings::WebSettings;
use super::types::{
    FetchRequest, FetchResult, SearchHit, SearchRequest, SearchResult, WebError,
};
use super::url_filter::{FilterChain, FilterContext, FilterVerdict, UrlFilter, UrlVerdictRecord};
use crate::audit::badge::AuditBadge;

/// The gateway surface a web call flows through. Folds the audit `surface`
/// discriminator and the observe self-scan policy into one value so the two can
/// never desync: only [`WebSurface::DirectMcp`] carries injection-guardrail
/// settings, so the observe self-scan in [`guardrail_observe_badges`] is
/// reachable *only* on the direct `/mcp/web` surface — by construction, not by a
/// runtime assertion. The audit label derives from the variant.
pub enum WebSurface<'a> {
    /// Direct `/mcp/web` traffic. The result returns straight to the client, so
    /// [`search`] / [`fetch`] run an observe-mode injection scan over the
    /// untrusted text and stamp a `Guardrail` / `GuardrailError` badge on the
    /// `web_audit` row. Carries the inline injection-guardrail settings that
    /// scan drives.
    DirectMcp {
        guardrail: &'a crate::guardrail::GuardrailSettings,
    },
    /// Agent substitution loop. The loop folds web results back into the model
    /// and runs its own latency-overlapped (and, in enforce mode, strip-capable)
    /// scan at the fold-back layer, so the service must NOT self-scan here.
    Substitution,
    /// Operator connectivity probe. Guardrail scanning belongs to live
    /// `/mcp/web` traffic, not the test — no self-scan.
    AdminProbe,
}

impl WebSurface<'_> {
    /// The persisted `web_audit.surface` discriminator. Keep the strings in sync
    /// with the `WebAuditRecord.surface` reads (`audit.rs` substitution filter).
    pub fn audit_label(&self) -> &'static str {
        match self {
            WebSurface::DirectMcp { .. } => "mcp",
            WebSurface::Substitution => "substitution",
            WebSurface::AdminProbe => "admin_test",
        }
    }
}

/// Caller context — stable per-(tenant, request) data carried into audit.
pub struct WebContext<'a> {
    pub settings: &'a WebSettings,
    /// Decrypted backend credential. `None` for SearXNG.
    pub credential: Option<&'a str>,
    /// The SSRF-guarded client pair a search backend call picks from by its
    /// endpoint's origin (see [`crate::extension_http`]).
    pub search_clients: &'a crate::extension_http::ExtensionClients,
    pub audit_tx: Option<&'a crate::audit::AuditSender<WebAuditRecord>>,

    pub request_id: Uuid,
    pub tenant_id: Uuid,
    pub workspace_id: Uuid,
    pub user_id: Uuid,
    pub upstream_server_id: Uuid,
    pub key_id: Option<Uuid>,
    pub app_id: Option<String>,
    /// Gateway-side session id in the canonical hashed form
    /// (`session_id_from_client`) — see
    /// [`WebAuditRecord::session_id`](crate::web::audit::WebAuditRecord).
    pub session_id: Option<Uuid>,
    pub user_agent: Option<String>,
    /// `detection_method` of the audit row: `request` on the substitution
    /// surface (the call follows its request's app —
    /// [`DETECTION_REQUEST`](crate::middleware::attribution::DETECTION_REQUEST)),
    /// `direct` where no request made the call
    /// ([`DETECTION_DIRECT`](crate::middleware::attribution::DETECTION_DIRECT)).
    pub detection_method: Option<String>,
    pub ip: Option<String>,
    /// Which gateway surface this call flows through. Drives both the audit
    /// `surface` label and whether the service runs its own observe self-scan
    /// (only [`WebSurface::DirectMcp`] does).
    pub surface: WebSurface<'a>,
    /// Parent LLM `request_id` when this call is part of a substitution loop;
    /// `None` for direct MCP traffic.
    pub parent_request_id: Option<Uuid>,
    /// Id of the intercepted model tool_use this dispatch fulfils — set on the
    /// substitution surface so the `web_audit` row joins to the LLM turn's
    /// `intercepted_tool_calls` + `guardrail_steps`. `None` for direct MCP.
    pub tool_use_id: Option<String>,
    /// Optional cooperative cancellation signal. When the substitution agent
    /// loop's stream is dropped (client SSE disconnect), the loop's
    /// `_cancel_drop_guard` triggers `cancel.cancel()`; this short-circuits
    /// in-flight backend HTTP calls inside [`search`] / [`fetch`] so the
    /// gateway stops wasting upstream egress on conversations the client
    /// has abandoned. `None` for direct MCP traffic — the MCP `tools/call`
    /// future is dropped by the JSON-RPC layer when the client disconnects,
    /// so a token isn't needed there.
    pub cancel_token: Option<&'a tokio_util::sync::CancellationToken>,
}

impl WebContext<'_> {
    fn filter_chain(&self) -> FilterChain {
        let dlf = DestinationListFilter::new(self.settings.destinations.clone());
        if dlf.is_inert() {
            FilterChain::default()
        } else {
            FilterChain::new(vec![Arc::new(dlf) as Arc<dyn UrlFilter>])
        }
    }

    fn filter_context(&self, op: &'static str) -> FilterContext {
        FilterContext {
            operation: op,
            tenant_id: Some(self.tenant_id),
            user_id: Some(self.user_id),
        }
    }

    /// `true` when the caller has cancelled this call. Cheap polling check
    /// callers run before each major step (backend dispatch, fetch) to
    /// short-circuit before the next IO.
    fn is_cancelled(&self) -> bool {
        self.cancel_token.is_some_and(|t| t.is_cancelled())
    }
}

/// Drive `fut` until it completes OR `ctx.cancel_token` fires, whichever
/// comes first. On cancellation, returns `Err(WebError::Cancelled)`
/// without polling `fut` further — `tokio::select!` drops the future,
/// which lets reqwest cancel the underlying TCP connection.
async fn select_with_cancel<F, T>(
    ctx: &WebContext<'_>,
    fut: F,
) -> Result<T, WebError>
where
    F: std::future::Future<Output = Result<T, WebError>>,
{
    if let Some(token) = ctx.cancel_token {
        tokio::select! {
            biased;
            () = token.cancelled() => Err(WebError::Cancelled),
            r = fut => r,
        }
    } else {
        fut.await
    }
}

/// Run a search. Returns the post-filter result; audit row is sent on the
/// way out (success and error paths).
pub async fn search(
    ctx: &WebContext<'_>,
    req: SearchRequest,
) -> Result<SearchResult, WebError> {
    let started = Instant::now();
    let request_args = serde_json::to_value(&req).ok();

    // Cooperative cancellation check before any IO. The substitution agent
    // loop's `_cancel_drop_guard` fires `token.cancel()` when the client SSE
    // stream is dropped; short-circuiting here keeps the gateway from
    // burning a backend HTTP slot on a request the caller has abandoned.
    if ctx.is_cancelled() {
        let e = WebError::Cancelled;
        emit_error(ctx, "search", &req.query, &e, request_args, started.elapsed().as_millis() as u64).await;
        return Err(e);
    }

    // Cap requested max_results against tenant + hard cap.
    let effective_max = ctx.settings.effective_max_results(req.max_results);
    let mut effective_req = req.clone();
    effective_req.max_results = Some(effective_max);

    // Build backend; short-circuit with audit on failure.
    let backend = match Backend::from_settings(ctx.settings, ctx.credential) {
        Ok(b) => b,
        Err(e) => {
            emit_error(ctx, "search", &req.query, &e, request_args, started.elapsed().as_millis() as u64).await;
            return Err(e);
        }
    };
    let backend_provider = backend.provider();

    // Run the upstream call. `tokio::select!` against the cancel token so
    // that an in-flight backend HTTP request is dropped (cancelling the
    // TCP connection at the reqwest level) the moment the substitution
    // agent loop's drop-guard fires.
    let backend_fut = backend.search(ctx.search_clients, &effective_req);
    let outcome = match select_with_cancel(ctx, backend_fut).await {
        Ok(o) => o,
        Err(e) => {
            emit_error(ctx, "search", &req.query, &e, request_args, started.elapsed().as_millis() as u64).await;
            return Err(e);
        }
    };
    let BackendSearchOutcome {
        result: pre_filter,
        provider_request,
        provider_response,
        upstream_latency_ms,
        upstream_status,
        bytes_in,
        bytes_out,
    } = outcome;

    // Run URL filters against every hit.
    let chain = ctx.filter_chain();
    let chain_ids = chain.ids();
    let filter_ctx = ctx.filter_context("search");
    let mut url_results = Vec::with_capacity(pre_filter.hits.len());
    let mut allowed: Vec<SearchHit> = Vec::with_capacity(pre_filter.hits.len());
    let mut denied = 0u32;
    for hit in pre_filter.hits {
        let parsed = match url::Url::parse(&hit.url) {
            Ok(u) => u,
            Err(_) => {
                // Malformed URLs from the backend get dropped + recorded.
                url_results.push(UrlVerdictRecord {
                    url: hit.url.clone(),
                    title: Some(hit.title.clone()),
                    verdict: "deny".into(),
                    filter_id: Some("internal_invalid_url"),
                    reason: Some("malformed url from upstream".into()),
                });
                denied += 1;
                continue;
            }
        };
        if chain.is_empty() {
            url_results.push(UrlVerdictRecord {
                url: hit.url.clone(),
                title: Some(hit.title.clone()),
                verdict: "allow".into(),
                filter_id: None,
                reason: None,
            });
            allowed.push(hit);
        } else {
            // Search side defaults to fail-open per plan.
            match chain.evaluate(&parsed, &filter_ctx, true).await {
                FilterVerdict::Allow => {
                    url_results.push(UrlVerdictRecord {
                        url: hit.url.clone(),
                        title: Some(hit.title.clone()),
                        verdict: "allow".into(),
                        filter_id: None,
                        reason: None,
                    });
                    allowed.push(hit);
                }
                FilterVerdict::Deny { reason } => {
                    url_results.push(UrlVerdictRecord {
                        url: hit.url.clone(),
                        title: Some(hit.title.clone()),
                        verdict: "deny".into(),
                        // The destination-list filter is the chain's only deny source.
                        filter_id: Some("destination_list"),
                        reason: Some(reason),
                    });
                    denied += 1;
                }
            }
        }
    }

    let final_result = SearchResult {
        backend: pre_filter.backend,
        total_filtered: denied,
        hits: allowed,
    };

    // Build badges + audit row.
    let mut badges = Vec::new();
    if denied > 0 {
        badges.push(AuditBadge::WebUrlFiltered { count: denied });
        if final_result.hits.is_empty() {
            badges.push(AuditBadge::WebAllResultsFiltered);
        }
    }

    // Direct `/mcp/web` observe scan over the untrusted result text (the same
    // surface `dispatch_intercept` scores — one shared builder, so both paths
    // scan every attacker-influenced field) before it reaches the client. No-op
    // (empty) on any non-`DirectMcp` surface.
    badges.extend(guardrail_observe_badges(ctx, &final_result.classifiable()).await);

    let provider_response_capped = cap_provider_response(
        provider_response,
        ctx.settings.audit_provider_response_max_kb,
        bytes_in,
    );

    let response_summary = serde_json::to_value(&final_result).ok();

    let record = WebAuditRecord {
        request_id: ctx.request_id,
        timestamp: chrono::Utc::now(),
        tenant_id: ctx.tenant_id,
        workspace_id: ctx.workspace_id,
        user_id: ctx.user_id,
        key_id: ctx.key_id,
        app_id: ctx.app_id.clone(),
        session_id: ctx.session_id,
        user_agent: ctx.user_agent.clone(),
        detection_method: ctx.detection_method.clone(),
        ip: ctx.ip.clone(),
        latency_total_ms: started.elapsed().as_millis() as u64,
        status_code: Some(200),
        error_category: None,
        error_detail: None,
        parent_request_id: ctx.parent_request_id,
        tool_use_id: ctx.tool_use_id.clone(),
        upstream_server_id: ctx.upstream_server_id,
        operation: "search".into(),
        backend: backend_provider.code().to_string(),
        query: Some(effective_req.query.clone()),
        result_count: Some(final_result.hits.len() as i32),
        bytes_in: Some(bytes_in as i64),
        bytes_out: Some(bytes_out as i64),
        upstream_latency_ms,
        upstream_status: Some(upstream_status as i32),
        surface: ctx.surface.audit_label().to_string(),
        url_results: serde_json::to_value(&url_results).ok(),
        filter_chain: serde_json::to_value(&chain_ids).ok(),
        request_args,
        response_summary,
        provider_request: Some(provider_request),
        provider_response: Some(provider_response_capped),
        fetch_content_summary: None,
        badges,
        transform_diff: serde_json::Value::Object(Default::default()),
    };
    emit(ctx, record).await;

    Ok(final_result)
}

/// Run a fetch. Same audit/policy/filter pipeline.
pub async fn fetch(
    ctx: &WebContext<'_>,
    req: FetchRequest,
) -> Result<FetchResult, WebError> {
    let started = Instant::now();
    let request_args = serde_json::to_value(&req).ok();

    // Cooperative cancellation check before any IO. See `search` for the
    // contract — same drop-guard pattern fires the token when the
    // substitution agent loop's stream is dropped.
    if ctx.is_cancelled() {
        let e = WebError::Cancelled;
        emit_error(ctx, "fetch", &req.url, &e, request_args, started.elapsed().as_millis() as u64).await;
        return Err(e);
    }

    // No search backend is needed: the built-in fetcher serves every tenant,
    // as `served_web_tools` advertises. The URL filter chain and the SSRF
    // guard below apply the same with or without one.
    let backend_code = audit_backend(ctx, "fetch");

    // Run URL filter chain BEFORE the SSRF guard (policy first, security
    // second). Any deny short-circuits both.
    let chain = ctx.filter_chain();
    let chain_ids = chain.ids();
    let parsed = match url::Url::parse(&req.url) {
        Ok(u) => u,
        Err(e) => {
            let err = WebError::InvalidUrl(e.to_string());
            emit_error(ctx, "fetch", &req.url, &err, request_args, started.elapsed().as_millis() as u64).await;
            return Err(err);
        }
    };

    let filter_verdict = if chain.is_empty() {
        FilterVerdict::Allow
    } else {
        chain
            .evaluate(&parsed, &ctx.filter_context("fetch"), false)
            .await
    };

    if let FilterVerdict::Deny { reason } = filter_verdict {
        let url_results = vec![UrlVerdictRecord {
            url: req.url.clone(),
            title: None,
            verdict: "deny".into(),
            filter_id: Some("destination_list"),
            reason: Some(reason.clone()),
        }];
        let err = WebError::UrlFilterDenied {
            filter_id: "destination_list".into(),
            reason,
            url: req.url.clone(),
        };
        let mut record =
            base_record(ctx, "fetch", &backend_code, &req.url, started.elapsed().as_millis() as u64);
        record.error_category = Some(err.category().to_string());
        record.error_detail = Some(err.to_string());
        record.url_results = serde_json::to_value(&url_results).ok();
        record.filter_chain = serde_json::to_value(&chain_ids).ok();
        record.request_args = request_args;
        record
            .badges
            .push(AuditBadge::WebUrlFiltered { count: 1 });
        emit(ctx, record).await;
        return Err(err);
    }

    // Built-in fetch (SSRF + bounded body + extraction). Cancel-aware
    // wrapper drops the in-flight TCP connection if the substitution agent
    // loop's drop-guard fires mid-fetch.
    let cap = ctx.settings.fetch_max_bytes;
    // Internal targets only as the platform's `web` egress list lists them —
    // web-fetch targets are end-user supplied, so this is never a tenant knob.
    let fetch_fut = fetch_builtin(&req, cap);
    let (result, raw_bytes) = match select_with_cancel(ctx, fetch_fut).await {
        Ok(pair) => pair,
        Err(e) => {
            let mut record =
                base_record(ctx, "fetch", &backend_code, &req.url, started.elapsed().as_millis() as u64);
            record.request_args = request_args;
            record.error_category = Some(e.category().to_string());
            record.error_detail = Some(e.to_string());
            // Record the URL we considered + its allow verdict (deny would
            // have short-circuited above) so the audit row is never blank.
            record.url_results = serde_json::to_value(&[UrlVerdictRecord {
                url: req.url.clone(),
                title: None,
                verdict: "allow".into(),
                filter_id: None,
                reason: None,
            }])
            .ok();
            record.filter_chain = serde_json::to_value(&chain_ids).ok();
            match &e {
                WebError::SsrfRefused(_) => {
                    record.badges.push(AuditBadge::WebSsrfRefused);
                }
                WebError::SchemeRefused(_) => {
                    record.badges.push(AuditBadge::WebSchemeRefused);
                }
                WebError::Oversized { .. } => {
                    record.badges.push(AuditBadge::WebContentStripped {
                        reason: "oversized".into(),
                    });
                }
                _ => {}
            }
            emit(ctx, record).await;
            return Err(e);
        }
    };

    // A 3xx hop can land on a host the pre-fetch filter never saw — the
    // domain-list check above ran only on `req.url`. Re-evaluate every URL the
    // fetch actually traversed (each redirect hop + the final URL) so an
    // allowed domain can't 302 into a denied / non-allowlisted one. The SSRF
    // guard already re-vets each hop's resolved IP; this closes the policy
    // side of the same redirect gap.
    if !chain.is_empty() {
        let mut hops: Vec<&str> =
            result.redirect_chain.iter().map(String::as_str).collect();
        hops.push(result.final_url.as_str());
        for hop in hops {
            // The initial URL already cleared the pre-fetch filter check.
            if hop == req.url {
                continue;
            }
            let Ok(parsed_hop) = url::Url::parse(hop) else {
                continue;
            };
            if let FilterVerdict::Deny { reason } = chain
                .evaluate(&parsed_hop, &ctx.filter_context("fetch"), false)
                .await
            {
                let err = WebError::UrlFilterDenied {
                    filter_id: "destination_list".into(),
                    reason: reason.clone(),
                    url: hop.to_string(),
                };
                let mut record = base_record(
                    ctx,
                    "fetch",
                    &backend_code,
                    &req.url,
                    started.elapsed().as_millis() as u64,
                );
                record.error_category = Some(err.category().to_string());
                record.error_detail = Some(err.to_string());
                record.url_results = serde_json::to_value(&[UrlVerdictRecord {
                    url: hop.to_string(),
                    title: None,
                    verdict: "deny".into(),
                    filter_id: Some("destination_list"),
                    reason: Some(reason),
                }])
                .ok();
                record.filter_chain = serde_json::to_value(&chain_ids).ok();
                record.request_args = request_args.clone();
                record.badges.push(AuditBadge::WebUrlFiltered { count: 1 });
                emit(ctx, record).await;
                return Err(err);
            }
        }
    }

    // Build content-summary stub for audit. Phase 1 doesn't actually persist
    // the bytes into audit_media_blobs — that wiring lives at the edge audit
    // layer; the summary fields here are placeholders for that hop.
    let raw_size = raw_bytes.len();
    let extracted_size = result.extracted_text.len();
    let fetch_content_summary = serde_json::json!({
        "raw_size": raw_size,
        "extracted_size": extracted_size,
        "fetch_url": result.url,
        "final_url": result.final_url,
        "redirect_chain": result.redirect_chain,
        "content_type": result.content_type,
    });

    let response_summary = serde_json::to_value(&result).ok();

    // Direct `/mcp/web` observe scan over the fetched page's extracted text
    // before it reaches the client. No-op on the substitution surface. Runs
    // before the record is stamped so `latency_total_ms` includes the scan the
    // caller actually waited on (parity with the `search` path).
    let guardrail_badges = guardrail_observe_badges(ctx, &result.classifiable()).await;

    let mut record = base_record(
        ctx,
        "fetch",
        &backend_code,
        &req.url,
        started.elapsed().as_millis() as u64,
    );
    record.result_count = Some(1);
    record.bytes_in = Some(raw_size as i64);
    record.bytes_out = Some(req.url.len() as i64);
    record.upstream_status = Some(result.status as i32);
    record.url_results = serde_json::to_value(&[UrlVerdictRecord {
        url: req.url.clone(),
        title: None,
        verdict: "allow".into(),
        filter_id: None,
        reason: None,
    }])
    .ok();
    record.filter_chain = serde_json::to_value(&chain_ids).ok();
    record.request_args = request_args;
    record.response_summary = response_summary;
    record.fetch_content_summary = Some(fetch_content_summary);
    record.badges.extend(guardrail_badges);
    emit(ctx, record).await;

    Ok(result)
}

/// Build the common audit-row skeleton.
///
/// `query` is mandatory by type: it holds the search string for
/// `operation = "search"` and the target URL for `operation = "fetch"`, and a
/// row must never be emitted without it (leaving it blank silently discards
/// the one field that identifies what the call was for). Keep it a required
/// parameter — every construction path, success and error alike, has it.
fn base_record(
    ctx: &WebContext<'_>,
    operation: &str,
    backend_code: &str,
    query: &str,
    latency_ms: u64,
) -> WebAuditRecord {
    WebAuditRecord {
        request_id: ctx.request_id,
        timestamp: chrono::Utc::now(),
        tenant_id: ctx.tenant_id,
        workspace_id: ctx.workspace_id,
        user_id: ctx.user_id,
        key_id: ctx.key_id,
        app_id: ctx.app_id.clone(),
        session_id: ctx.session_id,
        user_agent: ctx.user_agent.clone(),
        detection_method: ctx.detection_method.clone(),
        ip: ctx.ip.clone(),
        latency_total_ms: latency_ms,
        status_code: Some(200),
        error_category: None,
        error_detail: None,
        parent_request_id: ctx.parent_request_id,
        tool_use_id: ctx.tool_use_id.clone(),
        upstream_server_id: ctx.upstream_server_id,
        operation: operation.to_string(),
        backend: backend_code.to_string(),
        query: Some(query.to_string()),
        result_count: None,
        bytes_in: None,
        bytes_out: None,
        upstream_latency_ms: 0,
        upstream_status: None,
        surface: ctx.surface.audit_label().to_string(),
        url_results: None,
        filter_chain: None,
        request_args: None,
        response_summary: None,
        provider_request: None,
        provider_response: None,
        fetch_content_summary: None,
        badges: Vec::new(),
        transform_diff: serde_json::Value::Object(Default::default()),
    }
}

async fn emit_error(
    ctx: &WebContext<'_>,
    operation: &str,
    query: &str,
    err: &WebError,
    request_args: Option<serde_json::Value>,
    latency_ms: u64,
) {
    let backend_code = audit_backend(ctx, operation);
    let mut record = base_record(ctx, operation, &backend_code, query, latency_ms);
    record.error_category = Some(err.category().to_string());
    record.error_detail = Some(err.to_string());
    record.request_args = request_args;
    emit(ctx, record).await;
}

/// What a `web_audit` row names as the backend of `operation`: the search
/// backend for a search (empty when none is configured), the built-in fetcher
/// for a fetch — which never goes through the search backend.
fn audit_backend(ctx: &WebContext<'_>, operation: &str) -> String {
    if operation == "fetch" {
        return FETCH_BACKEND_BUILTIN.to_string();
    }
    ctx.settings.backend.map(|b| b.code().to_string()).unwrap_or_default()
}

/// The `web_audit.backend` of a fetch served by the built-in fetcher.
pub const FETCH_BACKEND_BUILTIN: &str = "builtin";

/// Send a `web_audit` record on the channel with back-pressure.
///
/// Mirrors [`crate::proxy::send_audit`]: audit is mandatory, never silently
/// dropped. A saturated channel blocks the caller until the writer task
/// drains, applying natural back-pressure to the substitution agent loop
/// (and to MCP `/mcp/web` callers). Never `try_send`: under load it would
/// silently drop audit rows, and nothing is silently discarded.
async fn emit(ctx: &WebContext<'_>, record: WebAuditRecord) {
    if let Some(tx) = ctx.audit_tx
        && let Err(e) = tx.send(record).await
    {
        tracing::error!(
            request_id = %ctx.request_id,
            "web_search audit channel closed — record lost: {e}"
        );
    }
}

/// Observe-mode injection scan for the **direct `/mcp/web` surface**.
///
/// Only the [`WebSurface::DirectMcp`] surface carries guardrail settings; the
/// substitution loop runs its own latency-overlapped (and enforce-capable) scan
/// at the fold-back layer, so this only ever fires for direct `/mcp/web`
/// traffic — never double-scanning.
///
/// The fetched/searched content goes straight back to the MCP client, so there
/// is nothing to strip or block here: this is observe-only. We score the
/// untrusted text inline — bounded by the tenant's `timeout_ms`, fail-open —
/// and return badges to stamp on the same `web_audit` row: a
/// [`AuditBadge::Guardrail`] (`action: Flag`) when a finding clears the
/// threshold, or [`AuditBadge::GuardrailError`] when the detector itself fails
/// (the call is never failed over a guardrail error on third-party content) or
/// the content was too large to screen end-to-end (`incomplete_scan` — a clean
/// verdict over part of a page is not an all-clear for the page).
/// Returns an empty vec when the guardrail is inert or the text is empty.
async fn guardrail_observe_badges(ctx: &WebContext<'_>, classifiable: &str) -> Vec<AuditBadge> {
    // The self-scan is reachable only on the direct `/mcp/web` surface: only
    // `DirectMcp` carries guardrail settings, so the substitution loop and the
    // admin probe can't double-scan content the fold-back layer already screens
    // — the type makes that impossible, no runtime assertion needed.
    let WebSurface::DirectMcp { guardrail: settings } = &ctx.surface else {
        return Vec::new();
    };
    let Some(cfg) = crate::guardrail::ClassifierConfig::from_settings(settings) else {
        return Vec::new();
    };
    if classifiable.trim().is_empty() {
        return Vec::new();
    }
    // Fetched page / search snippets — third-party content, so the content cap.
    let max_windows = cfg.max_windows_content;
    match crate::guardrail::classify_with_shared_client(cfg, &[classifiable], max_windows).await {
        // `classify_texts` returns one `ScanResult` per input; we passed one.
        Ok(results) => match results.first() {
            Some(r) if r.verdict.flagged => vec![AuditBadge::Guardrail {
                categories: vec![r.verdict.category],
                max_confidence: r.verdict.confidence,
                action: crate::audit::badge::GuardrailAction::Flag,
            }],
            // Clean, but the windows didn't cover the whole page: the tail went
            // to the client unscreened. Badge it — same signal the fold-back
            // observe path emits — so a partial scan never reads as an all-clear.
            Some(r) if !r.fully_scanned => vec![AuditBadge::GuardrailError {
                reason: crate::guardrail::scan::INCOMPLETE_SCAN_REASON.to_string(),
            }],
            _ => Vec::new(),
        },
        Err(e) => {
            // Fail-open: the content still returns to the client; the outage is
            // recorded as a badge AND logged for operator attention (mirrors the
            // substitution observe path's warn so a detector outage isn't a
            // log-side blind spot on this surface).
            tracing::warn!(
                request_id = %ctx.request_id,
                error = %e,
                "/mcp/web inline guardrail classifier error (observe, fail-open — content passed)"
            );
            vec![AuditBadge::GuardrailError {
                reason: e.reason_token().to_string(),
            }]
        }
    }
}

/// Execute one substituted tool call through the configured backend and
/// return the JSON-stringified result the agent loop will feed back to the
/// model as a `tool_result`. The same audit / URL-filter / SSRF surface as a
/// direct MCP call — the only differences are `surface` and
/// `parent_request_id` on `ctx`, set by the caller.
///
/// Returns the serialized [`SearchResult`] / [`FetchResult`] on success, or a
/// [`WebError`] the agent loop surfaces as an `is_error: true`
/// `tool_result` (the model can then decide to retry or apologise — the
/// upstream call is never aborted on a tool-execution failure).
pub async fn dispatch_intercept(
    binding: &crate::proxy::content::InterceptBinding,
    arguments_json: &str,
    ctx: &WebContext<'_>,
) -> Result<DispatchOutcome, WebError> {
    use crate::config::tool_rules::{InterceptKind, WebInterceptKind};

    match &binding.intercept {
        InterceptKind::WebExecutor { kind } => match kind {
            WebInterceptKind::Search => {
                let req: SearchRequest =
                    parse_audited_args(ctx, "search", arguments_json).await?;
                let target = req.query.clone();
                let result = search(ctx, req).await?;
                // Score every attacker-influenced string the model will read in
                // the folded envelope (not just the prose) — see
                // `SearchResult::classifiable`. Captured before serialization so
                // the classifier sees clean text, not JSON punctuation.
                let classifiable = result.classifiable();
                let folded = serde_json::to_string(&result).map_err(|e| {
                    WebError::Internal(format!("serialize search result: {e}"))
                })?;
                Ok(DispatchOutcome { folded, classifiable, target })
            }
            WebInterceptKind::Fetch => {
                let req: FetchRequest = parse_audited_args(ctx, "fetch", arguments_json).await?;
                let result = fetch(ctx, req).await?;
                // The page body is not the only untrusted surface the model reads
                // — the response content-type and every redirect hop are
                // attacker-chosen too. See `FetchResult::classifiable`.
                let classifiable = result.classifiable();
                let target = result.final_url.clone();
                let folded = serde_json::to_string(&result)
                    .map_err(|e| WebError::Internal(format!("serialize fetch result: {e}")))?;
                Ok(DispatchOutcome { folded, classifiable, target })
            }
        },
    }
}

/// Result of one intercepted web tool-call. `folded` is the JSON-stringified
/// `SearchResult`/`FetchResult` the agent loop feeds back to the model as a
/// `tool_result`; `classifiable` is the raw untrusted text (fetched page body /
/// joined search snippets) the inline guardrail scores — kept separate so the
/// classifier sees clean prose, not the JSON envelope. `target` is the fetched
/// URL or search query, shown on the guardrail trace step.
#[derive(Debug, Clone)]
pub struct DispatchOutcome {
    pub folded: String,
    pub classifiable: String,
    pub target: String,
}

/// Empty argument strings are treated as `{}` — a model that emits a
/// no-arg tool_use against `web_search`/`web_fetch` is asking for the
/// schema's default, not an opaque parse failure.
fn normalize_args(arguments_json: &str) -> &str {
    let trimmed = arguments_json.trim();
    if trimmed.is_empty() { "{}" } else { trimmed }
}

fn parse_args<T: serde::de::DeserializeOwned>(arguments_json: &str) -> Result<T, WebError> {
    serde_json::from_str(normalize_args(arguments_json))
        .map_err(|e| WebError::InvalidConfig(format!("parse intercept args: {e}")))
}

/// Longest raw-argument prefix kept as a row's `query` when nothing better can
/// be extracted. Enough to recognise the call, short of storing a whole payload
/// in a column meant for a search string or URL.
const MAX_RAW_TARGET_LEN: usize = 200;

/// Best-effort identification of what a malformed call was trying to reach.
///
/// Prefers the typed field — `query` for a search, `url` for a fetch — which
/// survives when the payload is valid JSON but the wrong shape (the common
/// case: a missing sibling field). Falls back to the raw arguments, truncated
/// on a char boundary. Never returns empty: naming what the call was for is the
/// row's entire value.
fn best_effort_target(raw: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(raw)
        && let Some(s) = v
            .get("query")
            .or_else(|| v.get("url"))
            .and_then(|x| x.as_str())
        && !s.is_empty()
    {
        return s.to_string();
    }
    raw[..raw.floor_char_boundary(MAX_RAW_TARGET_LEN)].to_string()
}

/// Decode tool-call arguments **inside** the audit boundary.
///
/// [`search`] and [`fetch`] capture their audit record on entry, so every way
/// they can fail is recorded — but a call that dies while *decoding* its
/// arguments never reaches them, and would leave no `web_audit` row at all.
/// Route every argument decode through here instead: a malformed call is
/// audited exactly once, carrying the raw arguments, and the executors are
/// never entered so there is no second emission.
///
/// Keep [`parse_args`] private. The audited seam is only a guarantee while it
/// is the sole way in.
pub async fn parse_audited_args<T: serde::de::DeserializeOwned>(
    ctx: &WebContext<'_>,
    operation: &str,
    arguments_json: &str,
) -> Result<T, WebError> {
    match parse_args::<T>(arguments_json) {
        Ok(req) => Ok(req),
        Err(e) => {
            let raw = normalize_args(arguments_json);
            emit_error(
                ctx,
                operation,
                &best_effort_target(raw),
                &e,
                // Wrapped in an object rather than stored as a bare JSON string:
                // the arguments that failed to parse may not be JSON at all, and
                // the audit drawer renders `request_args` only when it is an
                // object.
                Some(serde_json::json!({ "raw": raw })),
                0,
            )
            .await;
            Err(e)
        }
    }
}

/// Replace the captured provider response with a `Stripped` marker when the
/// upstream wire body exceeded the configured KB cap. `bytes_in` is the raw
/// HTTP body length captured by the backend layer (already plumbed on
/// `BackendSearchOutcome`); using it skips a `serde_json::to_string` walk
/// per call versus measuring on the parsed `Value`.
fn cap_provider_response(
    value: serde_json::Value,
    max_kb: u64,
    bytes_in: u64,
) -> WebProviderResponse {
    let max_bytes = max_kb.saturating_mul(1024);
    if bytes_in <= max_bytes {
        return WebProviderResponse::Captured(value);
    }
    WebProviderResponse::Stripped(StrippedProviderResponse {
        stripped: true,
        size_bytes: bytes_in,
        reason: "oversized".to_string(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cap_returns_value_under_limit() {
        let v = serde_json::json!({"a": 1});
        let capped = cap_provider_response(v.clone(), 1024, 16);
        match capped {
            WebProviderResponse::Captured(out) => assert_eq!(out, v),
            WebProviderResponse::Stripped(_) => panic!("expected Captured"),
        }
    }

    #[test]
    fn cap_strips_oversized_payload_using_bytes_in() {
        let v = serde_json::json!({"a": 1});
        // 1 KB cap, but bytes_in claims the wire body was 5 MB.
        let capped = cap_provider_response(v, 1, 5 * 1024 * 1024);
        match capped {
            WebProviderResponse::Stripped(s) => {
                assert!(s.stripped);
                assert_eq!(s.reason, "oversized");
                assert_eq!(s.size_bytes, 5 * 1024 * 1024);
            }
            WebProviderResponse::Captured(_) => panic!("expected Stripped"),
        }
    }

    #[test]
    fn cap_provider_response_round_trips_through_serde() {
        // Stripped writer shape must deserialize back into the typed enum so
        // edge → admin sync (and any future deserializing reader) sees a
        // `Stripped` variant rather than treating it as an opaque `Captured`.
        let stripped = cap_provider_response(serde_json::json!({}), 1, 5 * 1024 * 1024);
        let wire = serde_json::to_value(&stripped).unwrap();
        assert_eq!(wire["stripped"], serde_json::json!(true));
        let parsed: WebProviderResponse = serde_json::from_value(wire).unwrap();
        match parsed {
            WebProviderResponse::Stripped(s) => assert_eq!(s.reason, "oversized"),
            WebProviderResponse::Captured(_) => panic!("untagged matched wrong variant"),
        }

        // A regular response with no `stripped` key falls through to Captured.
        let captured = WebProviderResponse::Captured(serde_json::json!({"foo": 1}));
        let wire = serde_json::to_value(&captured).unwrap();
        let parsed: WebProviderResponse = serde_json::from_value(wire).unwrap();
        match parsed {
            WebProviderResponse::Captured(v) => assert_eq!(v["foo"], serde_json::json!(1)),
            WebProviderResponse::Stripped(_) => panic!("untagged matched wrong variant"),
        }
    }

    #[test]
    fn parse_args_accepts_empty_as_default_object() {
        let parsed: serde_json::Value = parse_args("").unwrap();
        assert_eq!(parsed, serde_json::json!({}));
        let parsed: serde_json::Value = parse_args("   ").unwrap();
        assert_eq!(parsed, serde_json::json!({}));
    }

    #[test]
    fn parse_args_round_trips_search_request() {
        let parsed: SearchRequest = parse_args(r#"{"query":"openai"}"#).unwrap();
        assert_eq!(parsed.query, "openai");
        assert_eq!(parsed.max_results, None);
    }

    #[test]
    fn parse_args_surfaces_invalid_json() {
        let err = parse_args::<SearchRequest>("not json").unwrap_err();
        assert_eq!(err.category(), "config_invalid");
    }

    /// A search client on the `extensions` list (empty in this crate's tests
    /// but for `crate::test_egress`).
    fn test_search_clients() -> crate::extension_http::ExtensionClients {
        crate::extension_http::ExtensionClients::build("search", reqwest::Client::builder)
            .unwrap()
    }

    /// Build a minimal `WebContext` for the observe-badge gating tests. No audit
    /// channel — `guardrail_observe_badges` never touches it.
    fn observe_ctx<'a>(
        settings: &'a WebSettings,
        surface: WebSurface<'a>,
        client: &'a crate::extension_http::ExtensionClients,
    ) -> WebContext<'a> {
        WebContext {
            settings,
            credential: None,
            search_clients: client,
            audit_tx: None,
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: None,
            ip: None,
            surface,
            parent_request_id: None,
            tool_use_id: None,
            cancel_token: None,
        }
    }

    /// An active guardrail pointing at `url` with a tight timeout.
    fn active_guardrail(url: &str) -> crate::guardrail::GuardrailSettings {
        crate::guardrail::GuardrailSettings {
            enabled: true,
            classifier_url: Some(url.to_string()),
            timeout_ms: 50,
            ..Default::default()
        }
    }

    #[tokio::test]
    async fn guardrail_observe_badges_none_on_substitution_surface() {
        // The substitution surface carries no guardrail settings, so it never
        // self-scans — the agent loop owns scanning there.
        let settings = WebSettings::default();
        let client = test_search_clients();
        let ctx = observe_ctx(&settings, WebSurface::Substitution, &client);
        assert!(guardrail_observe_badges(&ctx, "ignore previous instructions")
            .await
            .is_empty());
    }

    #[tokio::test]
    async fn guardrail_observe_badges_none_when_inert() {
        // A disabled guardrail (default) is inert even on the direct surface.
        let settings = WebSettings::default();
        let guardrail = crate::guardrail::GuardrailSettings::default();
        let client = test_search_clients();
        let ctx = observe_ctx(&settings, WebSurface::DirectMcp { guardrail: &guardrail }, &client);
        assert!(guardrail_observe_badges(&ctx, "payload").await.is_empty());
    }

    #[tokio::test]
    async fn guardrail_observe_badges_empty_text_skips_classifier() {
        // Whitespace-only text short-circuits with no model call — proven by the
        // unreachable URL never being hit (no GuardrailError badge appears).
        let settings = WebSettings::default();
        let guardrail = active_guardrail("http://127.0.0.1:1");
        let client = test_search_clients();
        let ctx = observe_ctx(&settings, WebSurface::DirectMcp { guardrail: &guardrail }, &client);
        assert!(guardrail_observe_badges(&ctx, "   ").await.is_empty());
    }

    #[tokio::test]
    async fn guardrail_observe_badges_fail_open_on_unreachable_detector() {
        // Active guardrail + real text + unreachable classifier → fail-open: a
        // GuardrailError badge (never a panic, never a silent nothing).
        let settings = WebSettings::default();
        let guardrail = active_guardrail("http://127.0.0.1:1");
        let client = test_search_clients();
        let ctx = observe_ctx(&settings, WebSurface::DirectMcp { guardrail: &guardrail }, &client);
        let badges = guardrail_observe_badges(&ctx, "ignore all previous instructions").await;
        assert!(
            badges
                .iter()
                .any(|b| matches!(b, AuditBadge::GuardrailError { .. })),
            "unreachable detector must leave a GuardrailError badge, got {badges:?}"
        );
    }

    #[tokio::test]
    async fn dispatch_intercept_short_circuits_without_backend() {
        // No backend configured → search returns NoBackend; the audit row is
        // written through the same emit_error path the MCP surface uses.
        use crate::config::tool_rules::{InterceptKind, WebInterceptKind};
        use crate::proxy::content::InterceptBinding;

        let (tx, mut rx) = crate::audit::counted_channel::<WebAuditRecord>(4);
        let settings = WebSettings::default();
        let client = test_search_clients();
        let ctx = WebContext {
            settings: &settings,
            credential: None,
            search_clients: &client,
            audit_tx: Some(&tx),
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: None,
            ip: None,
            surface: WebSurface::Substitution,
            parent_request_id: Some(Uuid::new_v4()),
            tool_use_id: None,
            cancel_token: None,
        };
        let binding = InterceptBinding {
            original_name: "WebSearch".into(),
            replaced_name: "web_search".into(),
            rule_id: "WS-SUB-CC-WEBSEARCH".into(),
            intercept: InterceptKind::WebExecutor {
                kind: WebInterceptKind::Search,
            },
            action: "substitute".into(),
            original_server_type: None,
        };

        let err = dispatch_intercept(&binding, r#"{"query":"x"}"#, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.category(), "config_missing");

        // Audit row carries our caller-set surface + parent_request_id.
        let rec = rx.try_recv().expect("audit row emitted");
        assert_eq!(rec.surface, "substitution");
        assert_eq!(rec.parent_request_id, ctx.parent_request_id);
        assert_eq!(rec.error_category.as_deref(), Some("config_missing"));
        // A row rejected before any backend exists still names what was asked.
        assert_eq!(rec.query.as_deref(), Some("x"));

        // Fetch needs no backend: the same unconfigured context gets past the
        // configuration check to the URL's own validation.
        let fetch_binding = InterceptBinding {
            original_name: "WebFetch".into(),
            replaced_name: "web_fetch".into(),
            rule_id: "WS-SUB-CC-WEBFETCH".into(),
            intercept: InterceptKind::WebExecutor {
                kind: WebInterceptKind::Fetch,
            },
            action: "substitute".into(),
            original_server_type: None,
        };
        let err = dispatch_intercept(&fetch_binding, r#"{"url":"not a url"}"#, &ctx)
            .await
            .unwrap_err();
        std::assert_matches!(err, WebError::InvalidUrl(_));
        let rec = rx.try_recv().expect("audit row emitted");
        assert_ne!(rec.error_category.as_deref(), Some("config_missing"));
        assert_eq!(rec.backend, FETCH_BACKEND_BUILTIN, "a fetch row names the fetcher it used");
    }

    #[tokio::test]
    async fn dispatch_intercept_audits_unparseable_arguments() {
        // Argument decoding is the one step that runs before `search`/`fetch`,
        // so it is the one place a web call could fail without leaving a
        // `web_audit` row. It must audit like every other failure: one row,
        // `config_invalid`, carrying the raw arguments.
        use crate::config::tool_rules::{InterceptKind, WebInterceptKind};
        use crate::proxy::content::InterceptBinding;

        let (tx, mut rx) = crate::audit::counted_channel::<WebAuditRecord>(4);
        let settings = WebSettings::default();
        let client = test_search_clients();
        let ctx = WebContext {
            settings: &settings,
            credential: None,
            search_clients: &client,
            audit_tx: Some(&tx),
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: None,
            ip: None,
            surface: WebSurface::Substitution,
            parent_request_id: Some(Uuid::new_v4()),
            tool_use_id: None,
            cancel_token: None,
        };
        let binding = InterceptBinding {
            original_name: "WebFetch".into(),
            replaced_name: "web_fetch".into(),
            rule_id: "WS-SUB-TEST".into(),
            intercept: InterceptKind::WebExecutor {
                kind: WebInterceptKind::Fetch,
            },
            action: "substitute".into(),
            original_server_type: None,
        };

        // Valid JSON, wrong shape — a known field with the wrong type, the shape
        // a model actually emits when it guesses the schema. (An *unknown* field
        // would not fail: serde ignores those.) `url` is still recoverable.
        let err = dispatch_intercept(&binding, r#"{"url":"http://x.test/","max_bytes":"lots"}"#, &ctx)
            .await
            .unwrap_err();
        assert_eq!(err.category(), "config_invalid");
        let rec = rx.try_recv().expect("audit row emitted for unparseable args");
        assert_eq!(rec.error_category.as_deref(), Some("config_invalid"));
        assert_eq!(rec.operation, "fetch");
        assert_eq!(rec.query.as_deref(), Some("http://x.test/"));
        assert!(rec.request_args.is_some(), "raw arguments retained on the row");

        // Not JSON at all — no typed field to recover, so the row falls back to
        // the raw text. It must still name something.
        let err = dispatch_intercept(&binding, "not json", &ctx).await.unwrap_err();
        assert_eq!(err.category(), "config_invalid");
        let rec = rx.try_recv().expect("audit row emitted for non-JSON args");
        assert_eq!(rec.query.as_deref(), Some("not json"));

        // Exactly one row per failed call — the executor is never entered, so
        // nothing emits a second time.
        assert!(rx.try_recv().is_err(), "no duplicate audit row");
    }

    #[tokio::test]
    async fn search_short_circuits_on_cancelled_token_before_backend_call() {
        // A pre-cancelled token in the WebContext means `search` returns
        // `Cancelled` *before* any backend HTTP is attempted. The audit row
        // is still emitted (operators need to see the cancel) and the
        // category is the new `cancelled` discriminator.
        use crate::web::types::WebProvider;
        use tokio_util::sync::CancellationToken;

        let (tx, mut rx) = crate::audit::counted_channel::<WebAuditRecord>(4);
        // Configure with a backend so the call would otherwise be dispatched —
        // we want to assert the cancel beats the backend dispatch.
        let settings = WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some("http://0.0.0.0:1/search".into()), // never reached
            ..Default::default()
        };
        let client = test_search_clients();
        let token = CancellationToken::new();
        token.cancel();
        let ctx = WebContext {
            settings: &settings,
            credential: None,
            search_clients: &client,
            audit_tx: Some(&tx),
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: None,
            ip: None,
            surface: WebSurface::Substitution,
            parent_request_id: Some(Uuid::new_v4()),
            tool_use_id: None,
            cancel_token: Some(&token),
        };
        let req = SearchRequest {
            query: "x".into(),
            max_results: Some(3),
            language: None,
        };
        let err = search(&ctx, req).await.unwrap_err();
        assert_eq!(err.category(), "cancelled");

        let rec = rx.try_recv().expect("audit row emitted on cancelled call");
        assert_eq!(rec.error_category.as_deref(), Some("cancelled"));
        // An error row carries the query like any other row — a blank `query`
        // would leave the operator unable to tell what the failed call was for.
        assert_eq!(rec.query.as_deref(), Some("x"));
    }

    #[tokio::test]
    async fn fetch_short_circuits_on_cancelled_token_before_http() {
        use crate::web::types::WebProvider;
        use tokio_util::sync::CancellationToken;

        let (tx, mut rx) = crate::audit::counted_channel::<WebAuditRecord>(4);
        let settings = WebSettings {
            backend: Some(WebProvider::Searxng),
            endpoint: Some("http://0.0.0.0:1/search".into()),
            ..Default::default()
        };
        let client = test_search_clients();
        let token = CancellationToken::new();
        token.cancel();
        let ctx = WebContext {
            settings: &settings,
            credential: None,
            search_clients: &client,
            audit_tx: Some(&tx),
            request_id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            workspace_id: Uuid::new_v4(),
            user_id: Uuid::new_v4(),
            upstream_server_id: Uuid::new_v4(),
            key_id: None,
            app_id: None,
            session_id: None,
            user_agent: None,
            detection_method: None,
            ip: None,
            surface: WebSurface::Substitution,
            parent_request_id: Some(Uuid::new_v4()),
            tool_use_id: None,
            cancel_token: Some(&token),
        };
        let req = FetchRequest {
            url: "http://example.test/page".into(),
            max_bytes: None,
        };
        let err = fetch(&ctx, req).await.unwrap_err();
        assert_eq!(err.category(), "cancelled");

        let rec = rx.try_recv().expect("audit row emitted on cancelled fetch");
        assert_eq!(rec.error_category.as_deref(), Some("cancelled"));
        // For a fetch the `query` column holds the target URL — present even
        // when the call never left the gateway.
        assert_eq!(rec.query.as_deref(), Some("http://example.test/page"));
    }

    #[test]
    fn cancelled_error_round_trips_through_category_and_rpc_code() {
        // Cancelled is a new variant — confirm both downstream surfaces
        // (admin audit category, MCP rpc_code) land the right values.
        let e = WebError::Cancelled;
        assert_eq!(e.category(), "cancelled");
        assert_eq!(e.rpc_code(), -32003);
    }

    /// Architecture test: every code path that runs a web search or fetch
    /// MUST go through one of two legitimate entry points so the URL filter
    /// chain, SSRF guard, and `web_audit` channel all fire uniformly:
    ///
    /// - `crates/streamscope-core/src/web/service.rs::dispatch_intercept`
    ///   — the substitution agent loop's chokepoint
    /// - `crates/streamscope-proxy/src/mcp/virtual_servers/web_search.rs`
    ///   — the `/mcp/web` virtual MCP server's tool dispatcher
    ///
    /// Both call into the underlying `service::search` / `service::fetch`
    /// fns *as the only callers*. This test scans the workspace source for
    /// any other caller of those fns and fails the build if a new bypass
    /// appears. Pairs with the substitution feature's "single-chokepoint
    /// invariant" — a refactor that adds a parallel executor will trip
    /// here long before it lands silently in production.
    ///
    /// The test reads the workspace tree via `CARGO_MANIFEST_DIR`. From
    /// `crates/streamscope-core/`, the workspace root is `../..`.
    #[test]
    fn web_search_and_fetch_have_only_two_callers() {
        use std::path::PathBuf;

        let manifest_dir =
            PathBuf::from(env!("CARGO_MANIFEST_DIR"));
        let workspace_root = manifest_dir
            .parent()
            .and_then(|p| p.parent())
            .expect("workspace root resolves from CARGO_MANIFEST_DIR/../..")
            .to_path_buf();

        // Files where direct calls to `service::{search,fetch}` are legitimate.
        // Stored as POSIX-relative paths from the workspace root.
        //
        // - `service.rs` — the executors themselves (tests, helpers).
        // - `mcp/virtual_servers/web.rs` — direct MCP `/mcp/web` path.
        // - `routes/web.rs` — the admin Test endpoint (`POST /api/v1/admin/web/actions/test`).
        //   Operator-initiated traffic, audited under `surface = "admin_test"`, and
        //   never on the substitution code path — keeping it out of
        //   `dispatch_intercept` avoids dragging the substitution agent loop's
        //   plumbing into a one-shot operator probe.
        let allowed_relative: &[&str] = &[
            "crates/streamscope-core/src/web/service.rs",
            "crates/streamscope-proxy/src/mcp/virtual_servers/web.rs",
            "crates/streamscope-admin/src/routes/web.rs",
        ];

        // Forbidden patterns — match the two underlying executor entry points
        // by their exact callable form. `dispatch_intercept` is the only
        // legitimate gateway for substitution-side code. The list catches
        // the natural call shapes including re-exports through
        // `crate::web::{search,fetch}` (a future `pub use service::*`
        // would otherwise slip past). Heuristic: UFCS / fn-pointer forms
        // (`let f = service::search;`) are not caught, but vanishingly rare
        // in practice — adding them would require runtime reflection.
        let forbidden: &[&str] = &[
            "service::search(",
            "service::fetch(",
            "web::service::search(",
            "web::service::fetch(",
            "WebService::search(",
            "WebService::fetch(",
            "crate::web::search(",
            "crate::web::fetch(",
        ];

        fn walk(dir: &std::path::Path, out: &mut Vec<PathBuf>) {
            let entries = match std::fs::read_dir(dir) {
                Ok(e) => e,
                Err(_) => return,
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() {
                    let name = path.file_name().and_then(|n| n.to_str()).unwrap_or("");
                    // Skip vendor / build-output dirs.
                    if matches!(name, "target" | "node_modules" | ".git") {
                        continue;
                    }
                    walk(&path, out);
                } else if path.extension().and_then(|e| e.to_str()) == Some("rs") {
                    out.push(path);
                }
            }
        }

        let crates_dir = workspace_root.join("crates");
        let mut rs_files = Vec::new();
        walk(&crates_dir, &mut rs_files);
        assert!(
            !rs_files.is_empty(),
            "no .rs files found under {} — workspace layout changed?",
            crates_dir.display(),
        );

        let mut violations: Vec<(PathBuf, usize, String, &'static str)> =
            Vec::new();
        for path in &rs_files {
            let rel = path
                .strip_prefix(&workspace_root)
                .unwrap_or(path.as_path())
                .to_string_lossy()
                .replace('\\', "/");
            if allowed_relative.contains(&rel.as_str()) {
                continue;
            }
            let content = match std::fs::read_to_string(path) {
                Ok(c) => c,
                Err(_) => continue,
            };
            for (line_no, line) in content.lines().enumerate() {
                // Skip comments and obvious string-literal lines — a
                // doc-comment or `let docs = "see service::search(...)";`
                // mentioning the API is fine.
                let trimmed = line.trim_start();
                if trimmed.starts_with("//")
                    || trimmed.starts_with("///")
                    || trimmed.starts_with('"')
                    || trimmed.starts_with("r#\"")
                    || trimmed.starts_with("r\"")
                {
                    continue;
                }
                for pat in forbidden {
                    if line.contains(pat) {
                        violations.push((
                            path.clone(),
                            line_no + 1,
                            line.trim().to_string(),
                            pat,
                        ));
                        break;
                    }
                }
            }
        }

        if !violations.is_empty() {
            let mut msg = String::from(
                "single-chokepoint invariant violated — direct callers of \
                 web search executors found outside the allowed list:\n",
            );
            for (path, line_no, line, pat) in &violations {
                let rel = path
                    .strip_prefix(&workspace_root)
                    .unwrap_or(path.as_path())
                    .display();
                msg.push_str(&format!(
                    "  {rel}:{line_no} matches `{pat}` :: {line}\n"
                ));
            }
            msg.push_str(
                "Substitution dispatch must go through \
                 `WebService::dispatch_intercept`. If a new entry point \
                 is genuinely needed, add it to the `allowed_relative` list \
                 in this test (and document why).",
            );
            panic!("{msg}");
        }
    }
}
