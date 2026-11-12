//! `POST /v1/analyze` — the out-of-band analysis RPC contract.
//!
//! An external enforcement point (an inline gateway's ICAP sidecar) submits
//! a body it intercepted in one of the four supported protocols. For a
//! `direction: "request"` prompt the gateway runs the same request-phase
//! pipeline a proxied call gets (tool policy → transforms → inbound guardrail)
//! and returns a verdict plus the transformed body instead of forwarding
//! anything upstream. For a `direction: "response"` model answer it runs the
//! observe-only PII leakage scan (the response surface) — verdicts there are
//! only ever allow/flag, since the bytes already streamed to the end client.
//! The caller owns enforcement — this endpoint only analyzes, mutates, and
//! audits.
//!
//! The envelope is versioned (`version: 2`); `findings` and `badges` reuse the
//! audit-side serde types verbatim so there is no parallel schema to drift.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::State;
use axum::http::Request;
use axum::response::{IntoResponse, Response};
use bytes::Bytes;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use std::time::Instant;

use crate::api::ApiRequest;
use crate::api::sse::ApiVersion;
use crate::audit::AuditRecord;
use crate::audit::BadgeBuilder;
use crate::audit::badge::{AuditBadge, GuardrailAction};
use crate::auth;
use crate::error::AppError;
use crate::middleware::attribution;
use crate::pipeline::TransformFlags;
use crate::proxy::content::{self, GuardrailStepDiff};
use crate::proxy::inline_exchange::PendingExchange;
use crate::pipeline::response_pipeline::ReplayedAnswer;
use crate::proxy::{AppState, ContentMeta, RequestMeta, TenantRequestCtx, send_audit};
use crate::settings::core_settings;

/// Contract version this build speaks. A request with any other `version` is
/// refused with a 400 — the envelope has no compatibility shims.
pub const ANALYZE_CONTRACT_VERSION: u32 = 2;

/// What the submitting enforcement point can DO with the analysis — the
/// audit-truth switch. A verdict-only caller cannot apply a rewrite on the
/// wire, so the gateway must never record one as applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzeEnforcement {
    /// The caller can replace the on-wire body with `transformed`. Policy
    /// mutations are recorded as applied (`modified` badge) and `transformed`
    /// is returned. Asking for no body (`include_transformed: false`) means
    /// forwarding the original: recorded and refused as for `verdict_only`.
    Rewrite,
    /// The caller only enforces the verdict (allow/block). `transformed` is
    /// never returned; a policy mutation is recorded as
    /// `modified_not_applied`, and a guardrail ENFORCE finding escalates the
    /// verdict to `block` — forwarding the original would bypass the strip.
    /// The safe default.
    #[default]
    VerdictOnly,
}

/// Which side of the LLM exchange the submitted body is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzeDirection {
    /// An inbound LLM request (prompt) — full pipeline + verdict + transform.
    #[default]
    Request,
    /// An LLM response body — observe-only scan (PII surface); the verdict is
    /// only ever `allow` or `flag`, and `transformed` is never returned.
    Response,
}

/// Client identity attached by the submitting enforcement point. All fields
/// describe the *end client* whose traffic was intercepted, not the sidecar.
#[derive(Debug, Clone, Default, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeClientMeta {
    /// End-client source IP.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,
    /// Authenticated user name/identifier.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,
    /// Authenticated group memberships.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub groups: Vec<String>,
    /// Recognized application (e.g. a cloud-app catalog name).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app: Option<String>,
    /// Caller-side session correlation id.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_id: Option<String>,
    /// The end client's original `User-Agent`, verbatim. Required by the
    /// contract whenever the intercepted request carried one — it is the
    /// client-identification signal on both audit trails.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
}

fn default_true() -> bool {
    true
}

/// The `POST /v1/analyze` request envelope.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(deny_unknown_fields)]
pub struct AnalyzeRequest {
    /// Contract version; must equal [`ANALYZE_CONTRACT_VERSION`].
    pub version: u32,
    /// Protocol the `body` is written in.
    pub protocol: ApiVersion,
    /// Which side of the exchange `body` is. Defaults to `request`.
    #[serde(default)]
    pub direction: AnalyzeDirection,
    /// The intercepted body, verbatim JSON in the submitted protocol. For
    /// `direction: request` this is the prompt; for `direction: response` it is
    /// the model's answer.
    pub body: serde_json::Value,
    /// With `direction: response`, the `request_id` the matching
    /// `direction: request` call returned — quoted back so the gateway's two
    /// analyze calls for one exchange finalize a single audit row (the request
    /// half's content + this response half). Absent ⇒ an uncorrelated response,
    /// audited observe-only on its own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reference_id: Option<String>,
    /// The HTTP status the upstream answered with. Required with `direction:
    /// response` (only it tells an answer delivered with an error inside from
    /// a refusal the client received), refused with `direction: request`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upstream_status: Option<u16>,
    /// Model identifier when the protocol does not carry it in the body
    /// (Gemini puts it in the URL path); required for `google_gemini`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Whether the response should include the transformed body when the
    /// pipeline mutated it. Defaults to true. Only meaningful with
    /// `enforcement: "rewrite"` — a verdict-only caller never receives it. False
    /// means the caller forwards the original, so a change is recorded not
    /// applied and an enforce finding escalates to `block`.
    #[serde(default = "default_true")]
    pub include_transformed: bool,
    /// What the caller can do with the analysis. Defaults to `verdict_only`
    /// (the safe direction — the audit never claims an unapplied rewrite).
    #[serde(default)]
    pub enforcement: AnalyzeEnforcement,
    /// End-client identity for audit attribution.
    #[serde(default)]
    pub client: AnalyzeClientMeta,
}

/// Analysis outcome the caller enforces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum AnalyzeVerdict {
    /// Nothing found, nothing changed — forward the original.
    Allow,
    /// Something was found (observe-mode finding) and/or the body was
    /// mutated — forward `transformed` when present, original otherwise.
    Flag,
    /// Refuse the request; `category`/`reason` describe why.
    Block,
}

/// Facts about the analyzed exchange, extracted for the caller's audit log.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AnalyzeAnalysis {
    /// The model the submitted body addresses.
    pub model: String,
    /// Protocol the body was parsed as (echo of the envelope).
    pub protocol: ApiVersion,
    /// Provider inferred from the model/protocol, when known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider: Option<String>,
    /// Whether the request asked for a streaming response.
    pub stream: bool,
    /// Number of conversation messages in the body.
    pub message_count: usize,
    /// Number of tool definitions offered in the body.
    pub tool_count: usize,
}

/// The `POST /v1/analyze` response envelope (HTTP 200 = analysis ran).
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct AnalyzeResponse {
    /// Contract version (equals the request's).
    pub version: u32,
    /// The gateway's audit-row id for this analysis — the cross-system
    /// correlation key (the caller logs it beside its own record).
    pub request_id: String,
    /// The verdict the caller enforces.
    pub verdict: AnalyzeVerdict,
    /// Finding category behind a `flag`/`block` verdict (a
    /// [`GuardrailCategory`](crate::guardrail::GuardrailCategory) wire token).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub category: Option<String>,
    /// Highest positive-class confidence across findings, in `[0, 1]`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<f32>,
    /// Human-readable refusal text for a `block` verdict (block-page copy).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Whether the pipeline mutated the submitted body. With
    /// `enforcement: "verdict_only"` this reports that policy WOULD modify —
    /// the wire keeps the original, and the audit row says `modified_not_applied`.
    pub modified: bool,
    /// The mutated body, in the same protocol as submitted. Present only when
    /// `modified`, the caller declared `enforcement: "rewrite"`, and the
    /// envelope asked for it (`include_transformed`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transformed: Option<serde_json::Value>,
    /// Extracted facts for the caller's audit record.
    pub analysis: AnalyzeAnalysis,
    /// Per-message guardrail findings, audit-side serde verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub findings: Vec<GuardrailStepDiff>,
    /// Every audit badge the pipeline emitted, audit-side serde verbatim.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub badges: Vec<AuditBadge>,
}

/// What [`derive_verdict`] resolved from the pipeline's outputs.
#[derive(Debug, Clone, PartialEq)]
pub struct VerdictOutcome {
    pub verdict: AnalyzeVerdict,
    pub category: Option<String>,
    pub confidence: Option<f32>,
    pub reason: Option<String>,
}

/// Map the pipeline's badge/finding outputs onto the caller-facing verdict.
///
/// - No findings, nothing modified → `allow`.
/// - Guardrail flagged (observe) or the pipeline mutated the body (enforce
///   strip, transform, redaction) → `flag`; the caller forwards the
///   transformed body when one is present.
/// - Guardrail *enforce* finding with `hard_block` set → `block`: the caller
///   is asked to refuse the request outright instead of forwarding the
///   stripped version. `hard_block=false` keeps enforce findings at `flag`
///   (the placeholder-stripped body is the enforcement).
pub fn derive_verdict(
    badges: &[AuditBadge],
    steps: &[GuardrailStepDiff],
    modified: bool,
    hard_block: bool,
) -> VerdictOutcome {
    // The BadgeBuilder aggregates all guardrail findings into at most one
    // Guardrail badge per row; its action already carries the strongest
    // outcome (Block over Flag).
    let guardrail = badges.iter().find_map(|b| match b {
        AuditBadge::Guardrail {
            categories,
            max_confidence,
            action,
        } => Some((categories, *max_confidence, *action)),
        _ => None,
    });

    match guardrail {
        Some((categories, max_confidence, action)) => {
            // Prefer the category of the highest-confidence verdict step —
            // it names the finding that drove `max_confidence`; fall back to
            // the badge's (deduped) category union.
            let category = steps
                .iter()
                .filter(|s| s.confidence.is_some())
                .max_by(|a, b| {
                    a.confidence
                        .partial_cmp(&b.confidence)
                        .unwrap_or(std::cmp::Ordering::Equal)
                })
                .and_then(|s| s.category)
                .or_else(|| categories.first().copied())
                .map(|c| c.badge_str().to_string());
            if action == GuardrailAction::Block && hard_block {
                let reason = category.as_deref().map_or_else(
                    || "Request blocked by AI guardrail".to_string(),
                    |c| format!("Request blocked by AI guardrail: {}", c.replace('_', " ")),
                );
                VerdictOutcome {
                    verdict: AnalyzeVerdict::Block,
                    category,
                    confidence: Some(max_confidence),
                    reason: Some(reason),
                }
            } else {
                VerdictOutcome {
                    verdict: AnalyzeVerdict::Flag,
                    category,
                    confidence: Some(max_confidence),
                    reason: None,
                }
            }
        }
        None if modified => VerdictOutcome {
            verdict: AnalyzeVerdict::Flag,
            category: None,
            confidence: None,
            reason: None,
        },
        None => VerdictOutcome {
            verdict: AnalyzeVerdict::Allow,
            category: None,
            confidence: None,
            reason: None,
        },
    }
}

/// Count the conversation messages in the submitted wire body, protocol-aware.
/// A cheap derived fact for the caller's audit log — reads the raw JSON so it
/// costs nothing beyond a key lookup (Responses' `input` may be a bare string,
/// which counts as one message).
fn message_count(protocol: ApiVersion, body: &serde_json::Value) -> usize {
    let key = match protocol {
        ApiVersion::ChatCompletions | ApiVersion::AnthropicMessages => "messages",
        ApiVersion::Responses => "input",
        ApiVersion::GoogleGemini => "contents",
    };
    match body.get(key) {
        Some(serde_json::Value::Array(a)) => a.len(),
        Some(serde_json::Value::String(_)) => 1,
        _ => 0,
    }
}

/// `POST /v1/analyze` — run the request-phase pipeline on an out-of-band body
/// and return verdict + transform instead of forwarding anything upstream.
///
/// Auth accepts the unified `inline` key (a forward-auth key in the inline
/// workspace) — the same key that BYOK-proxies on `/fwd/{key}/…` — and the
/// caller's workspace policy — its guardrail profile, tool rules, transforms —
/// IS the analyze policy: no parallel configuration. The same RPM ceiling as a
/// proxied call applies; TPM/budget do not (no upstream tokens are consumed).
/// Every analysis lands one audit row marked `provider="inline-ai"` /
/// `pipeline_path="analyze"`.
pub async fn analyze_handler(
    State(state): State<Arc<AppState>>,
    req: Request<Body>,
) -> Result<Response, AppError> {
    let (parts, body) = req.into_parts();
    let headers = parts.headers;

    let bearer = auth::extract_api_token(&headers)?;
    // The inline key is a forward-auth key (it BYOK-proxies on /fwd), so the
    // proxy-mount exclusion does not apply here; the `inline` flag — baked from
    // `workspaces.role = 'inline'` — is the gate. Any other key is refused, so a
    // leaked ordinary key cannot spray analyze audit rows.
    let ctx = auth::authenticate(&bearer, &state.tenant_registry.load())?;
    if !ctx.user.inline_ai {
        return Err(AppError::Auth(crate::error::AuthError::Forbidden(
            "analyze requires an inline workspace key".to_string(),
        )));
    }
    crate::middleware::rate_limit::check_rate_limit(&ctx.user, &state.usage)?;

    let body_bytes = axum::body::to_bytes(body, core_settings().max_body_size)
        .await
        .map_err(|e| AppError::BadRequest(format!("failed to read body: {e}")))?;
    let envelope: AnalyzeRequest = serde_json::from_slice(&body_bytes)
        .map_err(|e| AppError::BadRequest(format!("invalid analyze envelope: {e}")))?;
    if envelope.version != ANALYZE_CONTRACT_VERSION {
        return Err(AppError::BadRequest(format!(
            "unsupported analyze contract version {} (this build speaks {})",
            envelope.version, ANALYZE_CONTRACT_VERSION
        )));
    }
    if envelope.direction == AnalyzeDirection::Response {
        let status = response_status(envelope.upstream_status)?;
        return analyze_response(&state, &ctx, envelope, status).await;
    }
    if envelope.upstream_status.is_some() {
        return Err(AppError::BadRequest(
            "`upstream_status` belongs to direction \"response\"".to_string(),
        ));
    }
    analyze_request(&state, &ctx, envelope).await
}

/// A response half's `upstream_status`: stated, and an HTTP final status.
fn response_status(status: Option<u16>) -> Result<u16, AppError> {
    match status {
        Some(status) if (200..=599).contains(&status) => Ok(status),
        Some(status) => Err(AppError::BadRequest(format!("`upstream_status` {status} is not an HTTP final status"))),
        None => Err(AppError::BadRequest("`upstream_status` is required with direction \"response\"".to_string())),
    }
}

/// The end client's app and how it was named.
#[derive(Debug, Default, PartialEq)]
struct ClientApp {
    app_id: Option<String>,
    detection_method: Option<String>,
}

/// Attribute the end client exactly as the proxied handler would: the inline gateway's own
/// classification when it sent one (it saw the destination, which this gateway
/// does not), else the registry's tiers over what the inline gateway relayed — the
/// User-Agent, then the system prompt's opening. One implementation: the relayed
/// User-Agent goes through [`attribution::extract_attribution`] as a header.
fn resolve_client_app(
    client: &AnalyzeClientMeta,
    system_prompt: Option<&str>,
    app_patterns: &[crate::config::AppPattern],
) -> ClientApp {
    // The inline gateway naming the app is the client naming it: recorded as the proxied
    // path records an explicit `X-App-Id`.
    if let Some(app) = &client.app {
        return ClientApp { app_id: Some(app.clone()), detection_method: Some("header".to_string()) };
    }
    let mut headers = axum::http::HeaderMap::new();
    if let Some(ua) = client
        .user_agent
        .as_deref()
        .and_then(|ua| axum::http::HeaderValue::from_str(ua).ok())
    {
        headers.insert(axum::http::header::USER_AGENT, ua);
    }
    let mut attr = attribution::extract_attribution(&headers, uuid::Uuid::nil(), app_patterns, false);
    attr.classify_by_system_prompt(system_prompt, app_patterns);
    ClientApp { app_id: attr.app_id, detection_method: attr.detection_method }
}

/// Build the request-phase [`RequestMeta`] an inline-AI exchange shares with a
/// BYOK-proxied request: identity + rate/budget gating from the caller's own
/// context, `pricing` zeroed (BYOK is funded on the client's provider account,
/// so the gateway meters no cost), and no upstream ids (the gateway performed
/// the round-trip). The caller fills `content`/`badges`/`program_outcomes`/
/// `flags`/`intercept_bindings`/`estimated_input_tokens` for the request half;
/// an orphaned response leaves them at their empty defaults.
fn passthrough_meta_base(
    ctx: &TenantRequestCtx,
    request_id: uuid::Uuid,
    protocol: ApiVersion,
    model: String,
    is_streaming: bool,
    client: &AnalyzeClientMeta,
    app: ClientApp,
) -> RequestMeta {
    // Compute the TPM/budget gating flags exactly as the proxied handler so
    // post-response accrual behaves identically — for the grant-less Inline AI
    // workspace these are all false (no cap configured), so the budget ledger is
    // never charged, matching a BYOK passthrough.
    let ws = &ctx.user.rate_limit;
    let tpm_capped = (!ws.exempt && ws.tokens_per_minute > 0)
        || ctx
            .user
            .user_rate_override
            .as_ref()
            .is_some_and(|o| !o.exempt && o.tokens_per_minute > 0);
    RequestMeta {
        request_id,
        user_id: ctx.user.user_id,
        tenant_id: ctx.user.tenant_id,
        workspace_id: ctx.user.workspace_id,
        tpm_capped,
        rate_override: ctx.user.user_rate_override.is_some(),
        key_budget_capped: ctx.user.key_budget.is_some(),
        tenant_budget_capped: ctx.user.tenant_budget.is_some(),
        key_id: ctx.user.key_id,
        app_id: app.app_id,
        // The end client's raw session id hashed into the canonical
        // cross-protocol form, like every other `gateway_audit.session_id`.
        session_id: client.session_id.as_deref().map(|sid| {
            content::session_id_from_client(sid, ctx.user.tenant_id, ctx.user.user_id)
        }),
        parent_session_id: None,
        user_agent: client.user_agent.clone(),
        detection_method: app.detection_method,
        // The gateway-resolved end client, relayed by the trusted inline key.
        client_ip: client.ip.clone(),
        end_user: client.user.clone(),
        end_user_groups: client.groups.clone(),
        model_requested: model.clone(),
        model_used: model,
        provider: "inline-ai".to_string(),
        api_version: protocol,
        is_streaming,
        badges: BadgeBuilder::new(),
        program_outcomes: Vec::new(),
        flags: TransformFlags::default(),
        content: None,
        request_started_at: Instant::now(),
        estimated_input_tokens: 0,
        upstream_server_id: None,
        // Inline AI observes a call it did not forward: no endpoint answered it.
        endpoint_id: None,
        endpoint_url: None,
        upstream_model_id: None,
        // The inline path runs no response cache: this gateway never made the
        // upstream call, so there is nothing to serve from a cache and nothing
        // to embed. Priced exactly like a bring-your-own-key request, because
        // that is what it is — the client funded the call on its own provider
        // account, so the row records real tokens at a cost of zero, and that
        // zero is known rather than unknown.
        pricing: crate::pricing::Rates::free(),
        embedding_cost: 0.0,
        embedding_priced: true,
        embedding_tokens: 0,
        cache_audit: None,
        intercept_bindings: Vec::new(),
        // Set from the request phase; an orphaned response half has none.
        withheld_tools: Vec::new(),
        // `/v1/analyze` forwards nothing, so it is never gated and waits for no
        // capacity.
        queue_wait_ms: 0,
        pool_wait_ms: 0,
        moved_on_from: Vec::new(),
        qos_class_id: None,
        gate_permit: None,
        serving: None,
    }
}

/// `direction: "request"` — analyze an intercepted prompt exactly as the proxied
/// request phase does, return the enforcement verdict, and HOLD the request-phase
/// audit snapshot for the matching `direction: "response"` call to complete. A
/// terminal `block` verdict (the gateway will refuse the request, so no response
/// follows) finalizes its request-only audit row immediately.
async fn analyze_request(
    state: &Arc<AppState>,
    ctx: &TenantRequestCtx,
    envelope: AnalyzeRequest,
) -> Result<Response, AppError> {
    // Parse the submitted body in its own protocol. Gemini carries the model in
    // the URL on the proxied route, so the envelope supplies it here — the same
    // fixup, not a rewrite.
    let wire = Bytes::from(
        serde_json::to_vec(&envelope.body)
            .map_err(|e| AppError::BadRequest(format!("invalid analyze body: {e}")))?,
    );
    let mut api_request = ApiRequest::parse(envelope.protocol, &wire)?;
    if envelope.protocol == ApiVersion::GoogleGemini {
        let model = envelope
            .model
            .as_deref()
            .filter(|m| !m.is_empty())
            .ok_or_else(|| {
                AppError::BadRequest(
                    "`model` is required for protocol \"google_gemini\"".to_string(),
                )
            })?;
        api_request.set_model(model.to_string());
    }
    if api_request.model().len() > super::MAX_MODEL_NAME_LEN {
        return Err(AppError::BadRequest("model name too long".to_string()));
    }

    // Facts for the caller's audit log, captured before the pipeline mutates
    // anything.
    let analysis = AnalyzeAnalysis {
        model: api_request.model().to_string(),
        protocol: envelope.protocol,
        provider: None,
        stream: api_request.is_streaming(),
        message_count: message_count(envelope.protocol, &envelope.body),
        tool_count: api_request.tool_names().len(),
    };

    // The pipeline injects `stream_options.include_usage` for streaming
    // ChatCompletions — internal plumbing for the gateway's own usage
    // accounting that must not leak into the transformed body the caller
    // forwards to the real wire. Snapshot and restore around the phase.
    let stream_options_snapshot = match &api_request {
        ApiRequest::ChatCompletions(c) => Some(c.stream_options.clone()),
        _ => None,
    };

    let request_id = crate::ids::mint_request_id();
    let key_id = ctx.user.key_id.unwrap_or_else(uuid::Uuid::nil);

    // Capture the request content and detect the conversation session BEFORE the
    // pipeline runs — identical to the proxied handler, so the audit row and
    // session linkage are byte-for-byte what a BYOK-proxied request produces.
    let pre_content = content::extract_request_content(&api_request, wire.len());
    // The proxied path's identity fields, over the body as analyzed: a re-sent
    // analysis is the same turn, as a re-sent proxied request is.
    let request_key = content::request_key(
        ctx.user.user_id,
        key_id,
        envelope.client.session_id.as_deref(),
        envelope.protocol.as_str(),
        api_request.model(),
        api_request.is_streaming(),
        &wire,
    );
    // Served while this analysis runs — what this gateway serves of an inline
    // exchange; the upstream call and its delivery are the inline gateway's,
    // which this one cannot see. A copy analyzed meanwhile is this turn again,
    // under the same rule as a proxied request (`SessionDetector::detect_serving`).
    let (session_info, serving) = state.session_detector.detect_serving(
        ctx.user.user_id,
        key_id,
        ctx.user.tenant_id,
        &pre_content.session_hashes,
        envelope.client.session_id.as_deref(),
        request_key,
    );
    let client_app = resolve_client_app(
        &envelope.client,
        pre_content.system_prompt.as_deref(),
        &ctx.config.app_patterns,
    );

    let capture_diffs = ctx.config.content_logging_enabled;
    let effective_tool_rules = ctx.config.effective_tool_rules(ctx.user.workspace_id);
    let effective_transforms = ctx.config.effective_transforms(ctx.user.workspace_id);
    let phase = crate::pipeline::run_request_phase(
        &mut api_request,
        &ctx.user,
        &state.script_engine,
        &effective_transforms,
        ctx.config.effective_guardrail(ctx.user.workspace_id),
        client_app.app_id.as_deref(),
        None,
        None,
        false,
        capture_diffs,
        &effective_tool_rules,
        Some(&ctx.config.tool_field_profiles),
        Some(&ctx.config.mcp),
        ctx.config.sanitize_tool_names,
        ctx.config.rhai_fail_mode_enum(),
        Some(&pre_content),
        Some(session_info.session_id),
    )
    .await;
    let mut phase = match phase {
        Ok(p) => p,
        Err(e) => {
            // Terminal request-phase error — one error row, the proxied path's
            // canonical `error_record` (not a content row: the pipeline failed
            // before there was anything to audit).
            let mut record = AuditRecord::error_record(
                request_id,
                ctx.user.user_id,
                ctx.user.tenant_id,
                ctx.user.workspace_id,
                ctx.user.key_id,
                &e,
            );
            record.app_id = client_app.app_id.clone();
            record.detection_method = client_app.detection_method.clone();
            record.user_agent = envelope.client.user_agent.clone();
            record.model_requested = analysis.model.clone();
            record.provider = "inline-ai".to_string();
            record.api_version = envelope.protocol;
            record.pipeline_path = Some("analyze".to_string());
            send_audit(&state.audit_tx, record, &request_id.to_string()).await;
            return Err(e);
        }
    };
    if let (ApiRequest::ChatCompletions(c), Some(snapshot)) =
        (&mut api_request, stream_options_snapshot)
    {
        c.stream_options = snapshot;
    }

    // Assemble the request-phase audit pieces exactly as the proxied handler
    // (mod.rs). `merged_badges` drains only the badge sets, leaving the rest of
    // the transform/guardrail outcomes intact for the diff + response.
    let mut badges = phase.merged_badges();
    let transform_result = phase.transform;
    let inbound_guardrail_steps = phase.guardrail.steps;
    let mut program_outcomes = transform_result.program_outcomes;
    let flags = transform_result.flags;

    let modified = badges.is_modified();
    let verdict_only = envelope.enforcement == AnalyzeEnforcement::VerdictOnly;
    // What the pipeline changed reaches the wire only in a `transformed` body:
    // a rewrite caller that did not ask for one forwards the original.
    let applied = !verdict_only && envelope.include_transformed;
    if !applied && modified {
        // The caller cannot apply the rewrite, so the wire keeps the original:
        // the audit must say "would have modified", never "modified".
        badges.demote_modified_to_not_applied();
    }
    // A caller forwarding the original cannot forward a guardrail-enforce strip,
    // so the finding escalates to `block` — forwarding the original would bypass it.
    let outcome = derive_verdict(&badges.clone().finish(), &inbound_guardrail_steps, modified, !applied);
    // A call policy removes is still offered to the model when the caller
    // forwards the original; a refused request offers nothing.
    let tool_blocks_stand = applied || outcome.verdict == AnalyzeVerdict::Block;
    if !tool_blocks_stand {
        badges.demote_request_tool_blocks_to_not_applied();
    }
    let badges_vec = badges.clone().finish();

    let transformed = if modified && applied {
        let bytes = api_request.serialize()?;
        Some(
            serde_json::from_slice::<serde_json::Value>(&bytes)
                .map_err(|e| AppError::Internal(format!("re-encode transformed body: {e}")))?,
        )
    } else {
        None
    };

    // Record the turn (in-memory) so the next turn's content-prefix match keeps
    // the conversation session stable — always, regardless of content logging,
    // exactly as the proxied handler does.
    let is_baseline = session_info.is_baseline || flags.compression_applied;
    let final_info = content::SessionInfo {
        session_id: session_info.session_id,
        parent_request_id: session_info.parent_request_id,
        turn_number: session_info.turn_number,
        is_baseline,
    };
    state.session_detector.record(
        ctx.user.user_id,
        key_id,
        request_id,
        &final_info,
        pre_content.session_hashes.clone(),
        envelope.client.session_id.clone(),
    );

    // Build the content payload the audit row renders from — only when content
    // logging is on (the session linkage above is computed regardless).
    let content_meta = if ctx.config.content_logging_enabled {
        let ib = (!transform_result.injection_blocks.is_empty())
            .then_some(transform_result.injection_blocks);
        let bt = (!transform_result.blocked_tools.is_empty()).then(|| {
            transform_result
                .blocked_tools
                .into_iter()
                .map(|info| content::BlockedToolInfo { not_applied: !tool_blocks_stand, ..info })
                .collect()
        });
        let rtr = (!transform_result.redacted_tool_results.is_empty())
            .then_some(transform_result.redacted_tool_results);
        // The effective request — the system prompt, messages and tools the
        // turn records as sent — is what the caller forwards: the transformed
        // body only when it forwards it, else the client's own request — a
        // refused request records no change either. What policy would have
        // changed stays on the steps, the blocked entries and the badges.
        let sends_transformed = applied && outcome.verdict != AnalyzeVerdict::Block;
        let (mut transform_diff, effective_tools) = content::build_transform_diff(
            &pre_content,
            &api_request,
            program_outcomes.clone(),
            flags.system_prompt_modified && sends_transformed,
            flags.tools_modified && sends_transformed,
            transform_result.step_diffs,
            ib,
            bt,
            rtr,
            (!inbound_guardrail_steps.is_empty()).then(|| inbound_guardrail_steps.clone()),
            Vec::new(), // telemetry_dropped — inline AI never translates protocols
        );
        if !sends_transformed {
            transform_diff.effective_messages = None;
            transform_diff.messages_after_count = transform_diff.messages_original_count;
        }
        Some(ContentMeta {
            request_messages_json: pre_content.messages_json,
            media_scan_needed: pre_content.media_scan_needed,
            request_tools: pre_content.tools,
            effective_tools,
            request_params: pre_content.params,
            system_prompt: pre_content.system_prompt,
            transform_diff: serde_json::to_value(&transform_diff).ok(),
            link_hashes: pre_content.link_hashes,
            session_info: final_info,
            request_size_bytes: pre_content.request_size_bytes,
            first_user_prompt: pre_content.first_user_prompt,
        })
    } else {
        None
    };

    // The full request-phase snapshot — the same struct a proxied request hands
    // to the response pipeline.
    let mut meta = passthrough_meta_base(
        ctx,
        request_id,
        envelope.protocol,
        analysis.model.clone(),
        analysis.stream,
        &envelope.client,
        client_app,
    );
    meta.badges = badges;
    meta.program_outcomes = std::mem::take(&mut program_outcomes);
    meta.flags = flags;
    meta.content = content_meta;
    meta.estimated_input_tokens =
        crate::middleware::tokens::estimate_input_tokens_from_bytes(wire.len(), None);
    meta.intercept_bindings = transform_result.intercept_bindings;
    meta.withheld_tools = transform_result.withheld_tools;

    if outcome.verdict == AnalyzeVerdict::Block {
        // The verdict is the answer: released before its audit is written, as
        // a proxied stream releases at its last byte.
        drop(serving);
        // The gateway will refuse the request outright — no upstream call, no
        // response half — so finalize the (request-only) audit row now, through
        // the same pipeline a proxied request uses.
        crate::pipeline::response_pipeline::finalize_replayed_exchange(
            &mut meta,
            &ctx.config,
            state,
            envelope.protocol,
            None,
        )
        .await;
    } else {
        // The gateway forwards the request; the response half completes the row.
        // `stash` returns any exchange it displaced (an expired abandonment, or
        // the oldest under cap pressure) — finalize each request-only, off the
        // request path, so a displaced request never loses its audit row.
        let displaced =
            state
                .inline_exchanges
                .stash(request_id, meta, ctx.config.clone(), envelope.protocol);
        for pending in displaced {
            spawn_request_only_finalize(state, pending);
        }
    }

    let response = AnalyzeResponse {
        version: ANALYZE_CONTRACT_VERSION,
        request_id: request_id.to_string(),
        verdict: outcome.verdict,
        category: outcome.category,
        confidence: outcome.confidence,
        reason: outcome.reason,
        modified,
        transformed,
        analysis,
        findings: inbound_guardrail_steps,
        badges: badges_vec,
    };
    Ok((axum::http::StatusCode::OK, axum::Json(response)).into_response())
}

/// Finalize a displaced request-half (an exchange whose response never arrived)
/// as a request-only audit row, off the request path via the audit task tracker
/// so graceful shutdown waits for it. Its outcome is genuinely unknown — the
/// request was analyzed, the response never observed — so the row carries the
/// request content and no response, at zero cost, through the same pipeline.
fn spawn_request_only_finalize(state: &Arc<AppState>, pending: PendingExchange) {
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

/// The answer as the row's own finalize reads it (`read_whole_answer`), so the
/// verdict returned here and the row's scan read the same texts, framed the
/// same way.
fn read_answer(protocol: ApiVersion, body: &serde_json::Value) -> crate::pipeline::response::TransformState {
    let mut ts = crate::pipeline::response::TransformState::new(protocol);
    crate::pipeline::response_pipeline::read_whole_answer(body, protocol, &mut ts);
    ts
}

/// The response-direction analog of [`message_count`]: how many answer units
/// the body carries (choices / content blocks / output items / candidates).
fn response_unit_count(protocol: ApiVersion, body: &serde_json::Value) -> usize {
    let key = match protocol {
        ApiVersion::ChatCompletions => "choices",
        ApiVersion::AnthropicMessages => "content",
        ApiVersion::Responses => "output",
        ApiVersion::GoogleGemini => "candidates",
    };
    body.get(key)
        .and_then(serde_json::Value::as_array)
        .map_or(0, Vec::len)
}

/// The `direction: "response"` branch: an LLM **response** body, observed for
/// PII leakage (P3) — the same scan a proxied response gets in the response
/// pipeline's `finalize_audit`, gated by the same workspace knobs
/// (`pii.enabled && pii.scan_response`). The row also records the answer's tool
/// policy as not applied (`finalize_replayed_exchange`), which shapes no
/// verdict. No transforms and no injection classifier (that classifier
/// deliberately does not scan the Response surface), so the verdict is only
/// ever `allow` or `flag` and `transformed` is never produced — the bytes already streamed to
/// the end client; this is the audit half of the inline gateway's observe mode.
async fn analyze_response(
    state: &Arc<AppState>,
    ctx: &TenantRequestCtx,
    mut envelope: AnalyzeRequest,
    upstream_status: u16,
) -> Result<Response, AppError> {
    if envelope.enforcement == AnalyzeEnforcement::Rewrite {
        return Err(AppError::BadRequest(
            "direction \"response\" analysis is verdict-only; enforcement \"rewrite\" does not apply"
                .to_string(),
        ));
    }
    // The response body names its model for the JSON protocols; Gemini's rides
    // the envelope (on the wire it lives in the URL), exactly as on the
    // request direction.
    let model = envelope
        .body
        .get("model")
        .and_then(serde_json::Value::as_str)
        .map(str::to_string)
        .or_else(|| envelope.model.clone())
        .unwrap_or_default();
    if envelope.protocol == ApiVersion::GoogleGemini && model.is_empty() {
        return Err(AppError::BadRequest(
            "`model` is required for protocol \"google_gemini\"".to_string(),
        ));
    }
    if model.len() > super::MAX_MODEL_NAME_LEN {
        return Err(AppError::BadRequest("model name too long".to_string()));
    }
    let analysis = AnalyzeAnalysis {
        model: model.clone(),
        protocol: envelope.protocol,
        provider: None,
        stream: false,
        message_count: response_unit_count(envelope.protocol, &envelope.body),
        tool_count: 0,
    };

    // The observe verdict returned to the caller (the gateway records it beside
    // the row). The row's own `finalize_audit` runs the identical PII leakage
    // scan; here it only shapes the returned verdict — never enforced, the bytes
    // already reached the client.
    let pii = &ctx.config.effective_guardrail(ctx.user.workspace_id).pii;
    // A refused answer's body is no answer, and the row reads none of it.
    let inputs = if pii.enabled && pii.scan_response && (200..300).contains(&upstream_status) {
        read_answer(envelope.protocol, &envelope.body).response_pii_inputs()
    } else {
        Vec::new()
    };
    let (findings, badges) = if !inputs.is_empty() {
        crate::guardrail::run_pii_observe(pii, &inputs, crate::guardrail::GuardrailSurface::Response)
            .map(|o| (o.steps, o.badges))
            .unwrap_or_default()
    } else {
        (Vec::new(), Vec::new())
    };
    // Observe-only by construction: nothing was modified and nothing can
    // hard-block, so the verdict resolves to allow or flag.
    let outcome = derive_verdict(&badges, &findings, false, false);

    // Complete ONE audit row through the real pipeline. Prefer the held request
    // half (correlated by `reference_id`) so the row carries the whole turn —
    // request messages, session linkage, the request-phase badges, and this
    // response's content + usage. Fall back to a response-only row when the
    // request half is gone (expired / evicted / an uncorrelated call) so no
    // outcome escapes. Both paths ship the row via the same `finalize_audit` a
    // proxied request uses — no hand-built `AuditRecord`.
    // `take` reclaims the entry only when it belongs to this tenant, so a
    // client-supplied id can neither read nor destroy another tenant's exchange.
    let pending = envelope
        .reference_id
        .as_deref()
        .and_then(|s| uuid::Uuid::parse_str(s).ok())
        .and_then(|id| state.inline_exchanges.take(&id, ctx.user.tenant_id));
    let request_id = if let Some(mut pending) = pending {
        if pending.upstream_api_version != envelope.protocol {
            // Inline AI never translates protocols, so the response must be in
            // the request's protocol. A mismatch is a gateway bug — finalize the
            // (valid) request half request-only so its row is not lost, then
            // reject the malformed response call.
            crate::pipeline::response_pipeline::finalize_replayed_exchange(
                &mut pending.meta,
                &pending.tenant_config,
                state,
                pending.upstream_api_version,
                None,
            )
            .await;
            return Err(AppError::BadRequest(format!(
                "response protocol {:?} does not match the request half's {:?}",
                envelope.protocol, pending.upstream_api_version
            )));
        }
        let rid = pending.meta.request_id;
        crate::pipeline::response_pipeline::finalize_replayed_exchange(
            &mut pending.meta,
            &pending.tenant_config,
            state,
            pending.upstream_api_version,
            Some(ReplayedAnswer { status: upstream_status, body: &mut envelope.body }),
        )
        .await;
        rid
    } else {
        let request_id = crate::ids::mint_request_id();
        let mut meta = passthrough_meta_base(
            ctx,
            request_id,
            envelope.protocol,
            model,
            false,
            &envelope.client,
            // An orphaned response has no request body, so no prompt to read.
            resolve_client_app(&envelope.client, None, &ctx.config.app_patterns),
        );
        crate::pipeline::response_pipeline::finalize_replayed_exchange(
            &mut meta,
            &ctx.config,
            state,
            envelope.protocol,
            Some(ReplayedAnswer { status: upstream_status, body: &mut envelope.body }),
        )
        .await;
        request_id
    };

    let response = AnalyzeResponse {
        version: ANALYZE_CONTRACT_VERSION,
        request_id: request_id.to_string(),
        verdict: outcome.verdict,
        category: outcome.category,
        confidence: outcome.confidence,
        reason: outcome.reason,
        modified: false,
        transformed: None,
        analysis,
        findings,
        badges,
    };
    Ok((axum::http::StatusCode::OK, axum::Json(response)).into_response())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::guardrail::GuardrailCategory;

    /// Both sides of each bound, and the one absence the contract refuses.
    #[test]
    fn a_response_half_states_an_http_final_status() {
        for status in [200, 204, 299, 300, 429, 599] {
            assert_eq!(response_status(Some(status)).ok(), Some(status));
        }
        for status in [Some(0), Some(100), Some(199), Some(600), None] {
            assert!(response_status(status).is_err(), "{status:?}");
        }
    }

    #[test]
    fn an_analyzed_client_is_attributed_as_a_proxied_one_would_be() {
        let patterns = vec![
            crate::config::AppPattern {
                app_id: "vibe".into(),
                ua_patterns: vec!["mistral-vibe/".into()],
                ..Default::default()
            },
            crate::config::AppPattern {
                app_id: "goose".into(),
                prompt_patterns: vec!["ai agent called goose".into()],
                ..Default::default()
            },
        ];
        let goose_prompt = Some("You are a general-purpose AI agent called goose.");
        let named = |app: &str, method: Option<&str>| ClientApp {
            app_id: Some(app.to_string()),
            detection_method: method.map(str::to_string),
        };

        // The inline gateway's own classification wins, recorded as an explicit header is.
        let relayed = AnalyzeClientMeta { app: Some("chatgpt".into()), ..Default::default() };
        assert_eq!(resolve_client_app(&relayed, goose_prompt, &patterns), named("chatgpt", Some("header")));

        // Without one, the relayed User-Agent, then the prompt, name the app.
        let vibe = AnalyzeClientMeta { user_agent: Some("Mistral-Vibe/2.15.0".into()), ..Default::default() };
        assert_eq!(
            resolve_client_app(&vibe, goose_prompt, &patterns),
            named("vibe", Some("user_agent"))
        );
        let bare = AnalyzeClientMeta::default();
        assert_eq!(
            resolve_client_app(&bare, goose_prompt, &patterns),
            named("goose", Some(attribution::DETECTION_SYSTEM_PROMPT))
        );
        assert_eq!(resolve_client_app(&bare, None, &patterns), ClientApp::default());
    }

    fn guardrail_badge(action: GuardrailAction, confidence: f32) -> AuditBadge {
        AuditBadge::Guardrail {
            categories: vec![GuardrailCategory::PromptInjection],
            max_confidence: confidence,
            action,
        }
    }

    fn step(category: Option<GuardrailCategory>, confidence: Option<f32>) -> GuardrailStepDiff {
        GuardrailStepDiff {
            call_id: None,
            tool_use_id: "0".to_string(),
            name: "guardrail:classifier".to_string(),
            phase: crate::audit::Phase::Request,
            target: "message".to_string(),
            category,
            confidence,
            outcome: crate::proxy::content::GuardrailStepOutcome::Flagged,
            error: None,
            entities: None,
        }
    }

    #[test]
    fn clean_is_allow() {
        let out = derive_verdict(&[], &[], false, false);
        assert_eq!(out.verdict, AnalyzeVerdict::Allow);
        assert_eq!(out.category, None);
        assert_eq!(out.confidence, None);
        assert_eq!(out.reason, None);
    }

    #[test]
    fn observe_flag_is_flag_with_category_and_confidence() {
        let badges = vec![guardrail_badge(GuardrailAction::Flag, 0.91)];
        let steps = vec![step(Some(GuardrailCategory::PromptInjection), Some(0.91))];
        let out = derive_verdict(&badges, &steps, false, false);
        assert_eq!(out.verdict, AnalyzeVerdict::Flag);
        assert_eq!(out.category.as_deref(), Some("prompt_injection"));
        assert_eq!(out.confidence, Some(0.91));
        assert_eq!(out.reason, None);
    }

    #[test]
    fn enforce_without_hard_block_stays_flag() {
        let badges = vec![guardrail_badge(GuardrailAction::Block, 0.97)];
        let out = derive_verdict(&badges, &[], true, false);
        assert_eq!(out.verdict, AnalyzeVerdict::Flag);
        assert_eq!(out.confidence, Some(0.97));
    }

    #[test]
    fn enforce_with_hard_block_is_block_with_reason() {
        let badges = vec![guardrail_badge(GuardrailAction::Block, 0.97)];
        let steps = vec![step(Some(GuardrailCategory::Jailbreak), Some(0.97))];
        let out = derive_verdict(&badges, &steps, true, true);
        assert_eq!(out.verdict, AnalyzeVerdict::Block);
        assert_eq!(out.category.as_deref(), Some("jailbreak"));
        assert_eq!(
            out.reason.as_deref(),
            Some("Request blocked by AI guardrail: jailbreak")
        );
    }

    #[test]
    fn observe_finding_never_hard_blocks() {
        // hard_block only escalates enforce (Block-action) findings.
        let badges = vec![guardrail_badge(GuardrailAction::Flag, 0.88)];
        let out = derive_verdict(&badges, &[], false, true);
        assert_eq!(out.verdict, AnalyzeVerdict::Flag);
    }

    #[test]
    fn transform_only_modification_is_flag() {
        let out = derive_verdict(&[], &[], true, false);
        assert_eq!(out.verdict, AnalyzeVerdict::Flag);
        assert_eq!(out.category, None);
    }

    #[test]
    fn highest_confidence_step_names_the_category() {
        let badges = vec![AuditBadge::Guardrail {
            categories: vec![GuardrailCategory::PromptInjection, GuardrailCategory::Pii],
            max_confidence: 0.95,
            action: GuardrailAction::Flag,
        }];
        let steps = vec![
            step(Some(GuardrailCategory::PromptInjection), Some(0.60)),
            step(Some(GuardrailCategory::Pii), Some(0.95)),
        ];
        let out = derive_verdict(&badges, &steps, false, false);
        assert_eq!(out.category.as_deref(), Some("pii"));
    }

    #[test]
    fn no_verdict_steps_fall_back_to_badge_category() {
        let badges = vec![guardrail_badge(GuardrailAction::Flag, 0.80)];
        // An Error step carries no category/confidence — must not panic or win.
        let steps = vec![step(None, None)];
        let out = derive_verdict(&badges, &steps, false, false);
        assert_eq!(out.category.as_deref(), Some("prompt_injection"));
    }

    #[test]
    fn message_count_is_protocol_aware() {
        use serde_json::json;
        let msgs =
            json!({"messages": [{"role":"user","content":"a"},{"role":"assistant","content":"b"}]});
        assert_eq!(message_count(ApiVersion::ChatCompletions, &msgs), 2);
        assert_eq!(message_count(ApiVersion::AnthropicMessages, &msgs), 2);
        let gem = json!({"contents": [{"parts":[{"text":"hi"}]}]});
        assert_eq!(message_count(ApiVersion::GoogleGemini, &gem), 1);
        // Responses' `input` may be a bare string — that is one message.
        let resp_str = json!({"input": "hello"});
        assert_eq!(message_count(ApiVersion::Responses, &resp_str), 1);
        let resp_arr = json!({"input": [{"role":"user","content":"x"}]});
        assert_eq!(message_count(ApiVersion::Responses, &resp_arr), 1);
        assert_eq!(message_count(ApiVersion::Responses, &json!({})), 0);
    }

    /// The answer text the response PII scan reads first ([`read_answer`]).
    fn response_text(protocol: ApiVersion, body: &serde_json::Value) -> String {
        read_answer(protocol, body).full_response_content()
    }

    /// The verdict scans the answer exactly as the analyzed row's own
    /// `finalize_audit` scans it — the same reader, the same framing: the
    /// first choice's text, reasoning in every spelling inside `<thinking>`,
    /// then the other choices.
    #[test]
    fn response_text_is_the_rows_own_scan_surface() {
        use serde_json::json;
        let chat = json!({"choices": [
            {"index":0,"message":{"role":"assistant","content":"Hello world"}},
            {"index":1,"message":{"role":"assistant","content":[{"type":"text","text":"alt"}]}}
        ]});
        assert_eq!(response_text(ApiVersion::ChatCompletions, &chat), "Hello world");
        assert_eq!(response_unit_count(ApiVersion::ChatCompletions, &chat), 2);
        // The other choice is read too, named by where it sits.
        let inputs: Vec<(String, String)> = read_answer(ApiVersion::ChatCompletions, &chat)
            .response_pii_inputs()
            .into_iter()
            .map(|i| (i.target, i.classifiable))
            .collect();
        assert_eq!(inputs, [(String::new(), "Hello world".to_string()), ("choices[1]".into(), "alt".into())]);

        // Chat reasoning in every spelling: a key, or a Mistral `thinking` chunk.
        let framed = "<thinking>\nwhy\n</thinking>\n\nok";
        let keyed = json!({"choices": [
            {"index":0,"message":{"role":"assistant","content":"ok","reasoning_content":"why"}}
        ]});
        assert_eq!(response_text(ApiVersion::ChatCompletions, &keyed), framed);
        let chunks = json!({"choices": [{"index":0,"message":{"role":"assistant","content":[
            {"type":"thinking","thinking":[{"type":"text","text":"why"}]},
            {"type":"text","text":"ok"}
        ]}}]});
        assert_eq!(response_text(ApiVersion::ChatCompletions, &chunks), framed);
        // A part that is no Chat `text` chunk is not text.
        let loose = json!({"choices": [{"index":0,"message":{"role":"assistant","content":[
            {"text":"untyped"}, {"type":"output_text","text":"typed"}, {"type":"text","text":"chat"}
        ]}}]});
        assert_eq!(response_text(ApiVersion::ChatCompletions, &loose), "chat");
        // Text chunks join, so a value split across two reads whole.
        let split = json!({"choices": [{"index":0,"message":{"role":"assistant","content":[
            {"type":"text","text":"mail a@"}, {"type":"text","text":"b.com"}
        ]}}]});
        assert_eq!(response_text(ApiVersion::ChatCompletions, &split), "mail a@b.com");

        // Thinking is scanned too — a leak in the visible reasoning is a leak.
        let anthropic = json!({"content": [
            {"type":"thinking","thinking":"let me recall the number"},
            {"type":"text","text":"one"},
            {"type":"tool_use","id":"t1","name":"t","input":{}},
            {"type":"text","text":"two"}
        ]});
        let text = response_text(ApiVersion::AnthropicMessages, &anthropic);
        assert!(text.starts_with("<thinking>\nlet me recall the number\n</thinking>"), "{text}");
        assert!(text.contains("one") && text.contains("two"), "{text}");
        assert_eq!(response_unit_count(ApiVersion::AnthropicMessages, &anthropic), 4);

        let responses = json!({"output": [
            {"type":"reasoning","summary":[{"type":"summary_text","text":"pondering"}]},
            {"type":"message","content":[{"type":"output_text","text":"answer"}]}
        ]});
        let text = response_text(ApiVersion::Responses, &responses);
        assert!(text.contains("pondering") && text.ends_with("answer"), "{text}");

        let gemini = json!({"candidates": [
            {"content":{"parts":[{"text":"g1"},{"text":"g2"}],"role":"model"}}
        ]});
        assert_eq!(response_text(ApiVersion::GoogleGemini, &gemini), "g1g2");
        assert_eq!(response_unit_count(ApiVersion::GoogleGemini, &gemini), 1);

        // Malformed / empty shapes read as no text, never a panic.
        assert_eq!(response_text(ApiVersion::ChatCompletions, &json!({})), "");
        assert_eq!(
            response_text(ApiVersion::AnthropicMessages, &json!({"content":"bare string"})),
            ""
        );
    }

    /// The response direction is observe-only by construction: with
    /// `modified=false, hard_block=false`, a PII observe outcome can only ever
    /// resolve allow or flag.
    #[test]
    fn response_direction_pii_finding_is_flag_never_block() {
        let pii = crate::guardrail::PiiSettings {
            scan_response: true,
            ..Default::default()
        };
        let inputs = [crate::guardrail::GuardrailInput {
            id: "response".to_string(),
            classifiable: "the SSN is 178-05-1120 thanks".to_string(),
            target: String::new(),
        }];
        let out = crate::guardrail::run_pii_observe(
            &pii,
            &inputs,
            crate::guardrail::GuardrailSurface::Response,
        )
        .expect("SSN in the response text must be found");
        let verdict = derive_verdict(&out.badges, &out.steps, false, false);
        assert_eq!(verdict.verdict, AnalyzeVerdict::Flag);
        assert_eq!(verdict.category.as_deref(), Some("pii"));
        // And a clean response is a plain allow.
        let clean = derive_verdict(&[], &[], false, false);
        assert_eq!(clean.verdict, AnalyzeVerdict::Allow);
    }

    #[test]
    fn envelope_accepts_all_four_protocol_spellings() {
        for (spelling, expect) in [
            ("chat_completions", ApiVersion::ChatCompletions),
            ("responses", ApiVersion::Responses),
            ("anthropic_messages", ApiVersion::AnthropicMessages),
            ("google_gemini", ApiVersion::GoogleGemini),
        ] {
            let json = format!(
                r#"{{"version":2,"protocol":"{spelling}","body":{{"model":"m","messages":[]}}}}"#
            );
            let req: AnalyzeRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(req.protocol, expect);
            assert_eq!(req.version, ANALYZE_CONTRACT_VERSION);
            assert_eq!(req.direction, AnalyzeDirection::Request);
            assert!(req.include_transformed, "include_transformed defaults true");
            assert_eq!(
                req.enforcement,
                AnalyzeEnforcement::VerdictOnly,
                "enforcement defaults to the safe verdict_only"
            );
            assert!(req.client.user_agent.is_none());
        }
    }

    #[test]
    fn enforcement_spellings_round_trip() {
        for (spelling, expect) in [
            ("rewrite", AnalyzeEnforcement::Rewrite),
            ("verdict_only", AnalyzeEnforcement::VerdictOnly),
        ] {
            let json = format!(
                r#"{{"version":2,"protocol":"responses","body":{{}},"enforcement":"{spelling}"}}"#
            );
            let req: AnalyzeRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(req.enforcement, expect);
        }
    }

    #[test]
    fn envelope_rejects_unknown_fields() {
        let json = r#"{"version":2,"protocol":"responses","body":{},"bogus":true}"#;
        assert!(serde_json::from_str::<AnalyzeRequest>(json).is_err());
    }

    #[test]
    fn envelope_client_meta_round_trips() {
        let json = r#"{
            "version": 2,
            "protocol": "anthropic_messages",
            "direction": "request",
            "body": {"model": "claude", "messages": []},
            "client": {
                "ip": "10.1.2.3",
                "user": "alice@example.com",
                "groups": ["staff"],
                "app": "claude-web",
                "session_id": "s-1",
                "user_agent": "Mozilla/5.0"
            }
        }"#;
        let req: AnalyzeRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.client.user_agent.as_deref(), Some("Mozilla/5.0"));
        let back = serde_json::to_value(&req).unwrap();
        assert_eq!(back["client"]["user_agent"], "Mozilla/5.0");
        assert_eq!(back["client"]["groups"][0], "staff");
    }

    #[test]
    fn response_serializes_verdicts_and_skips_absent_fields() {
        let resp = AnalyzeResponse {
            version: ANALYZE_CONTRACT_VERSION,
            request_id: "req-1".to_string(),
            verdict: AnalyzeVerdict::Allow,
            category: None,
            confidence: None,
            reason: None,
            modified: false,
            transformed: None,
            analysis: AnalyzeAnalysis {
                model: "claude-sonnet-5".to_string(),
                protocol: ApiVersion::AnthropicMessages,
                provider: Some("anthropic".to_string()),
                stream: false,
                message_count: 2,
                tool_count: 0,
            },
            findings: Vec::new(),
            badges: Vec::new(),
        };
        let v = serde_json::to_value(&resp).unwrap();
        assert_eq!(v["verdict"], "allow");
        assert_eq!(v["analysis"]["protocol"], "anthropic_messages");
        assert!(v.get("category").is_none());
        assert!(v.get("transformed").is_none());
        assert!(v.get("findings").is_none());
        assert_eq!(
            serde_json::to_value(AnalyzeVerdict::Flag).unwrap(),
            serde_json::json!("flag")
        );
        assert_eq!(
            serde_json::to_value(AnalyzeVerdict::Block).unwrap(),
            serde_json::json!("block")
        );
    }
}
