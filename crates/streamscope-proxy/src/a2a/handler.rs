//! `/a2a/<slug>` request handling: the pre-auth rewritten agent card and the
//! authenticated JSON-RPC dispatcher.
//!
//! Dispatch policy: `SendMessage`, `GetTask`, `ListTasks`, `CancelTask`, and
//! `GetExtendedAgentCard` forward to the upstream agent with full audit
//! capture; `SendStreamingMessage` / `SubscribeToTask` open an SSE stream
//! piped through to the client (see [`stream_response`]); the four
//! `*TaskPushNotificationConfig` methods are refused with `-32003` (the
//! rewritten card advertises `pushNotifications: false`); unknown methods get
//! `-32601`. Clients MUST send `A2A-Version: 1.0` — an absent header means
//! a 0.3-dialect client per spec, refused with `-32009`.
//!
//! A message-bearing call ([`A2aMethod::is_message`]) additionally runs the
//! [`policy`] and [`guardrail`] hops — the same rule engine and the same
//! classifier that gate the LLM and MCP paths, screening what the caller sends
//! (before it leaves) and what the agent replies (before it is handed back).
//! Enforcement rewrites the payload; the audit row keeps the original prose plus
//! a diff of what fired, so an operator always sees what was really said.

use std::sync::Arc;

use axum::body::Body;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, Response, StatusCode};
use serde_json::Value;
use uuid::Uuid;

use streamscope_core::a2a::errors::{jsonrpc_error, A2aErrorCode};
use streamscope_core::a2a::model::{A2aMethod, A2aRequest, A2aStreamEvent};
use streamscope_core::a2a::wire::v1_0;
use streamscope_core::audit::a2a::A2aAuditRecord;
use streamscope_core::config::a2a::A2aUpstreamAgent;
use streamscope_core::error::{AppError, AuthError};
use streamscope_core::proxy::AppState;

use super::{guardrail, policy, upstream};
use crate::mcp::handler::extract_bearer;

/// Router state: the proxy's shared `AppState` plus the A2A audit channel.
#[derive(Clone)]
pub struct A2aRouterState {
    pub app: Arc<AppState>,
    pub a2a_audit_tx: streamscope_core::audit::AuditSender<A2aAuditRecord>,
}

/// The dialect this gateway speaks. Patch levels never participate in
/// negotiation (spec § 3.6).
const SUPPORTED_VERSION: &str = "1.0";

/// Whether this gateway serves the streaming methods. The rewritten card ANDs
/// this with the upstream's own `capabilities.streaming`, so an agent that
/// doesn't stream still advertises `false` — the card never promises what
/// either side can't deliver.
const GATEWAY_SERVES_STREAMING: bool = true;

/// The largest JSON-RPC request body read.
const MAX_REQUEST_BODY_BYTES: usize = 2 * 1024 * 1024;

// ─── Agent card (pre-auth) ───────────────────────────────────────────────────

/// `GET /a2a/{slug}/.well-known/agent-card.json` (and the legacy
/// `agent.json` alias — the ecosystem still splits on the filename).
///
/// Unauthenticated by design — card discovery happens before a client has
/// credentials (the rewritten card is what TELLS it which credential scheme
/// to use). Tenant resolution is by the globally-unique agent slug, the
/// `protected_resource_metadata_handler` precedent. The card is rewritten
/// per request: interface pinned to this gateway mount, gateway key scheme,
/// push notifications off, streaming advertised only when both the gateway and
/// the upstream agent serve it, signatures stripped.
pub async fn agent_card_handler(
    State(state): State<A2aRouterState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
) -> Response<Body> {
    let registry = state.app.tenant_registry.load();
    let mut found: Option<(A2aUpstreamAgent, Option<String>)> = None;
    for cfg in registry.values() {
        if let Some(agent) = cfg.a2a.lookup_by_slug(&slug) {
            found = Some((agent.clone(), cfg.proxy_public_url.clone()));
            break;
        }
    }
    let Some((agent, proxy_url)) = found else {
        return json_response(
            StatusCode::NOT_FOUND,
            serde_json::json!({"error": "no A2A agent matches this slug"}),
        );
    };
    // Fail closed: without the tenant's public proxy URL the rewritten
    // interface would advertise an unreachable endpoint.
    let Some(proxy_url) = proxy_url else {
        return json_response(
            StatusCode::SERVICE_UNAVAILABLE,
            serde_json::json!({"error": "proxy public URL not configured for this tenant — set it under Settings → Defaults"}),
        );
    };
    let mount_url = format!("{}/a2a/{}", proxy_url.trim_end_matches('/'), agent.slug);
    let card = streamscope_core::a2a::card::rewrite_card(&agent.agent_card, &mount_url, GATEWAY_SERVES_STREAMING);
    let body = serde_json::to_vec(&card).unwrap_or_else(|_| b"{}".to_vec());

    // HTTP caching contract (spec § 8.6.1 server requirements): a strong
    // content-derived ETag — the served body is a pure function of the cached
    // card and the mount URL — plus Last-Modified from the card's last
    // upstream fetch. A matching If-None-Match answers 304 with no body.
    let etag = {
        use sha2::{Digest, Sha256};
        format!("\"{}\"", hex::encode(Sha256::digest(&body)))
    };
    let last_modified = agent
        .card_fetched_at
        .map(|t| t.format("%a, %d %b %Y %H:%M:%S GMT").to_string());
    // Short TTL: cheap to re-serve, and a card refresh / credential-scheme
    // change should propagate quickly.
    const CACHE_CONTROL: &str = "public, max-age=300";

    // RFC 9110 § 13.1.2: If-None-Match uses WEAK comparison — a `W/` prefix
    // on the client's validator must still match our strong ETag.
    let revalidated = headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|inm| {
            inm.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t.strip_prefix("W/").unwrap_or(t) == etag
            })
        });

    let mut builder = Response::builder()
        .status(if revalidated { StatusCode::NOT_MODIFIED } else { StatusCode::OK })
        .header("cache-control", CACHE_CONTROL)
        .header("etag", &etag);
    if let Some(lm) = &last_modified {
        builder = builder.header("last-modified", lm);
    }
    if revalidated {
        return builder
            .body(Body::empty())
            .unwrap_or_else(|_| Response::new(Body::empty()));
    }
    builder
        .header("content-type", "application/json")
        .body(Body::from(body))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// ─── JSON-RPC dispatcher ─────────────────────────────────────────────────────

/// Resolved per-request identity + agent, produced by the auth gauntlet.
struct A2aIdentity {
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
    key_id: Option<Uuid>,
    user: streamscope_core::auth::UserContext,
    /// The configuration of the caller's tenant, from the same registry load
    /// that authenticated it: every config read of the call goes through it.
    config: Arc<streamscope_core::config::TenantConfig>,
    agent: A2aUpstreamAgent,
    /// Which client made this call, resolved by the same three-tier detection
    /// (`X-App-Id` header → referer → user-agent) the LLM and MCP paths use. It
    /// is both an audit column and a policy axis: an `app_filter` on an
    /// `agent_calls` rule has nothing to match without it.
    app_id: Option<String>,
    detection_method: Option<String>,
}

/// Resolve the calling key and the addressed agent, enforcing the workspace
/// allowlist. Unknown slug / missing tenant config renders the same generic
/// invalid-key error as a bad credential — a probing client learns nothing
/// about which slugs exist inside other tenants.
async fn resolve_identity(
    state: &AppState,
    headers: &HeaderMap,
    slug: &str,
) -> Result<A2aIdentity, AppError> {
    let bearer = extract_bearer(headers).ok_or(AppError::Auth(AuthError::MissingHeader))?;
    let streamscope_core::auth::TenantRequestCtx { user: ctx, config: cfg } =
        streamscope_core::auth::authenticate_proxy(&bearer, &state.tenant_registry.load())?;
    let invalid = || {
        AppError::Auth(AuthError::UnrecognizedFormat(
            streamscope_core::auth::credential_prefix(&bearer, 12),
        ))
    };
    // Resolve the slug against the CALLER's tenant config only — never a
    // cross-tenant scan (that is reserved for the unauthenticated card GET,
    // which discloses only what the card itself publishes).
    let agent = cfg.a2a.lookup_by_slug(slug).ok_or_else(invalid)?.clone();
    if !ctx.allows_a2a_agent(agent.id) {
        return Err(AppError::Auth(AuthError::WorkspaceA2aAccessDenied {
            workspace_id: ctx.workspace_id,
            agent_id: agent.id,
        }));
    }
    let attribution = streamscope_core::middleware::attribution::extract_attribution(
        headers,
        ctx.user_id,
        &cfg.app_patterns,
        false,
    );
    Ok(A2aIdentity {
        tenant_id: ctx.tenant_id,
        workspace_id: ctx.workspace_id,
        user_id: ctx.user_id,
        key_id: ctx.key_id,
        user: ctx,
        config: cfg,
        agent,
        app_id: attribution.app_id,
        detection_method: attribution.detection_method,
    })
}

/// `POST /a2a/{slug}` — the JSON-RPC 2.0 binding endpoint.
pub async fn a2a_handler(
    State(state): State<A2aRouterState>,
    Path(slug): Path<String>,
    headers: HeaderMap,
    body: Body,
) -> Response<Body> {
    let started = std::time::Instant::now();
    let request_id = streamscope_core::ids::mint_request_id();

    // ── Auth + allowlist (HTTP-level errors — no JSON-RPC envelope yet) ──
    let identity = match resolve_identity(&state.app, &headers, &slug).await {
        Ok(identity) => identity,
        Err(e) => return app_error_response(e),
    };

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string);
    let session_id = headers
        .get("x-session-id")
        .and_then(|v| v.to_str().ok())
        .map(|raw| {
            streamscope_core::proxy::content::session_id_from_client(
                raw,
                identity.tenant_id,
                identity.user_id,
            )
        });

    // Everything from here on is auditable — one record per request, emitted
    // on every outcome, through `reply` as the single exit point.
    let mut audit = AuditDraft {
        state: &state,
        identity: &identity,
        request_id,
        started,
        user_agent,
        session_id,
        request_bytes: 0,
        screening: Screening::default(),
    };

    // Read once the caller is known. Over the size cap, or not received
    // within the body deadline, the error names which.
    let body = match axum::body::to_bytes(body, MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(e) => {
            let e = AppError::BadRequest(format!(
                "could not read the request body (at most {MAX_REQUEST_BODY_BYTES} bytes): {e}"
            ));
            audit.record_rejection(&e).await;
            return app_error_response(e);
        }
    };
    audit.request_bytes = body.len() as i32;

    // ── RPM + budget (fleet-convergent counters, same checks as MCP; TPM is
    // token-denominated and nothing on the A2A wire carries tokens). A denial
    // is audited like any other outcome — an operator investigating a capped
    // key must see the refused calls, not a silent gap — but the client gets
    // the honest HTTP 429 rather than a JSON-RPC error (the JSON-RPC error
    // space has no rate-limit code, and 429 is what a client can act on).
    for check in [
        streamscope_core::middleware::rate_limit::check_rate_limit(&identity.user, &state.app.usage),
        streamscope_core::middleware::rate_limit::check_budget(
            &identity.user,
            &state.app.usage,
            identity.config.pricing.accounting_currency,
        ),
    ] {
        if let Err(e) = check {
            audit.record_rejection(&e).await;
            return app_error_response(e);
        }
    }

    // ── Version negotiation (spec § 3.6: absent ⇒ 0.3) ──
    let version = headers
        .get("a2a-version")
        .and_then(|v| v.to_str().ok())
        .map(str::trim)
        .unwrap_or("");
    if version != SUPPORTED_VERSION {
        let detail = if version.is_empty() {
            "A2A-Version header missing (0.3-dialect clients are not supported); send A2A-Version: 1.0"
                .to_string()
        } else {
            format!("A2A protocol version {version} is not supported; send A2A-Version: 1.0")
        };
        let envelope = jsonrpc_error(&Value::Null, A2aErrorCode::VersionNotSupported, &detail);
        return audit
            .reply(None, StatusCode::BAD_REQUEST, envelope, None, 0)
            .await;
    }

    // ── Content-Type gate (spec error table: ContentTypeNotSupportedError).
    // Only a PRESENT non-JSON media type is refused; an absent header falls
    // through to the JSON parse, which stays the authoritative check. ──
    let media_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|ct| ct.split(';').next().unwrap_or("").trim().to_ascii_lowercase())
        .unwrap_or_default();
    if !media_type.is_empty()
        && media_type != "application/json"
        && !media_type.ends_with("+json")
    {
        let envelope = jsonrpc_error(
            &Value::Null,
            A2aErrorCode::ContentTypeNotSupported,
            &format!("unsupported Content-Type {media_type}; send application/json"),
        );
        return audit
            .reply(None, StatusCode::BAD_REQUEST, envelope, None, 0)
            .await;
    }

    // ── JSON-RPC envelope parse ──
    let parsed: Value = match serde_json::from_slice(&body) {
        Ok(v) => v,
        Err(e) => {
            let envelope = jsonrpc_error(
                &Value::Null,
                A2aErrorCode::ParseError,
                &format!("request body is not valid JSON: {e}"),
            );
            return audit
                .reply(None, StatusCode::BAD_REQUEST, envelope, None, 0)
                .await;
        }
    };
    if !parsed.is_object() || parsed.get("jsonrpc").and_then(Value::as_str) != Some("2.0") {
        let envelope = jsonrpc_error(
            &Value::Null,
            A2aErrorCode::InvalidRequest,
            "expected a single JSON-RPC 2.0 request object",
        );
        return audit
            .reply(None, StatusCode::BAD_REQUEST, envelope, None, 0)
            .await;
    }
    let rpc_id = parsed.get("id").cloned().unwrap_or(Value::Null);
    let Some(method_str) = parsed.get("method").and_then(Value::as_str) else {
        let envelope = jsonrpc_error(
            &rpc_id,
            A2aErrorCode::InvalidRequest,
            "request has no method",
        );
        return audit
            .reply(None, StatusCode::BAD_REQUEST, envelope, None, 0)
            .await;
    };
    let request = A2aRequest {
        rpc_id: rpc_id.clone(),
        method: A2aMethod::parse(method_str),
        params: parsed.get("params").cloned().unwrap_or(Value::Null),
    };

    // ── Method gate ──
    if request.method.is_push_notification_config() {
        let envelope = jsonrpc_error(
            &rpc_id,
            A2aErrorCode::PushNotificationNotSupported,
            "push notifications are not supported through this gateway",
        );
        return audit
            .reply(Some(&request), StatusCode::OK, envelope, None, 0)
            .await;
    }
    if matches!(request.method, A2aMethod::Unknown(_)) {
        let envelope = jsonrpc_error(
            &rpc_id,
            A2aErrorCode::MethodNotFound,
            &format!("method not found: {method_str}"),
        );
        return audit
            .reply(Some(&request), StatusCode::OK, envelope, None, 0)
            .await;
    }

    // ── Request-phase screening (message-bearing calls only) ──
    //
    // A refusal ends the call here — the agent is never contacted. An enforced
    // rewrite re-serializes the envelope so the agent sees the screened message;
    // the audit row keeps the original (`request.params`) plus the diff of what
    // fired, so the operator sees what was really sent AND what was withheld.
    let mut body = body;
    if request.method.is_message() {
        let mut params = request.params.clone();
        match screen_request(&identity, &mut params, &mut audit.screening).await {
            RequestScreen::Blocked { message } => {
                let envelope = jsonrpc_error(&rpc_id, A2aErrorCode::BlockedByPolicy, &message);
                return audit
                    .reply(Some(&request), StatusCode::OK, envelope, None, 0)
                    .await;
            }
            RequestScreen::Rewritten => {
                let mut envelope = parsed.clone();
                envelope["params"] = params;
                match serde_json::to_vec(&envelope) {
                    Ok(bytes) => body = bytes::Bytes::from(bytes),
                    Err(e) => {
                        // Never forward the un-screened body as a fallback — that
                        // would hand the agent exactly the content the guardrail
                        // just withheld. Fail the call instead.
                        tracing::error!("a2a screened body re-serialization failed: {e}");
                        let envelope = jsonrpc_error(
                            &rpc_id,
                            A2aErrorCode::InternalError,
                            "the gateway could not apply its policy to this message",
                        );
                        return audit
                            .reply(
                                Some(&request),
                                StatusCode::INTERNAL_SERVER_ERROR,
                                envelope,
                                None,
                                0,
                            )
                            .await;
                    }
                }
            }
            RequestScreen::Clean => {}
        }
    }

    if request.method.is_streaming() {
        return stream_response(state.clone(), audit, request, body, &headers).await;
    }

    // ── Forward ──
    let service_headers = service_headers(&headers);
    let reply = match upstream::forward_call(&identity.agent, body.clone(), &service_headers).await
    {
        Ok(reply) => reply,
        Err(e) => {
            // Transport-level failure: sanitized JSON-RPC internal error —
            // never the raw transport detail.
            let envelope = jsonrpc_error(&rpc_id, A2aErrorCode::InternalError, &e.to_string());
            return audit
                .reply(Some(&request), StatusCode::BAD_GATEWAY, envelope, None, 0)
                .await;
        }
    };

    let upstream_ms = reply.latency_ms;
    let mut response_json: Value = match serde_json::from_slice(&reply.body) {
        Ok(v) => v,
        Err(_) => {
            // Upstream broke the JSON-RPC contract — sanitized internal
            // error toward the client; the audit row records the failure.
            let envelope = jsonrpc_error(
                &rpc_id,
                A2aErrorCode::InvalidAgentResponse,
                "upstream agent returned a non-JSON response",
            );
            return audit
                .reply(Some(&request), StatusCode::BAD_GATEWAY, envelope, None, upstream_ms)
                .await;
        }
    };

    // GetExtendedAgentCard returns a card whose interfaces/auth point at the
    // upstream — rewrite it exactly like the public card so clients never
    // learn (or try to use) the upstream endpoint. Fail CLOSED: without the
    // tenant's public URL there is no mount to rewrite to, and passing the
    // upstream card through would hand the client the real endpoint and its
    // credential scheme.
    //
    // The audit keeps the card the AGENT served, snapshotted before the rewrite:
    // its `supportedInterfaces`, its `securitySchemes`, its `signatures` are
    // exactly the fields an investigator goes looking for after suspecting a peer
    // was compromised (did it start advertising a new endpoint? did its signature
    // stop verifying?), and the rewritten copy would show them all as ours.
    let mut original_envelope: Option<Value> = None;
    if request.method == A2aMethod::GetExtendedAgentCard
        && response_json.get("result").is_some()
    {
        original_envelope = Some(response_json.clone());
    }
    if request.method == A2aMethod::GetExtendedAgentCard
        && let Some(result) = response_json.get_mut("result")
    {
        let Some(proxy_url) = identity.config.proxy_public_url.clone() else {
            let envelope = jsonrpc_error(
                &rpc_id,
                A2aErrorCode::InternalError,
                "gateway public URL is not configured for this tenant",
            );
            return audit
                .reply(
                    Some(&request),
                    StatusCode::SERVICE_UNAVAILABLE,
                    envelope,
                    None,
                    upstream_ms,
                )
                .await;
        };
        let mount_url = format!(
            "{}/a2a/{}",
            proxy_url.trim_end_matches('/'),
            identity.agent.slug
        );
        *result = streamscope_core::a2a::card::rewrite_card(result, &mount_url, GATEWAY_SERVES_STREAMING);
    }

    // ── Response-phase screening ──
    //
    // The agent's reply is third-party content the caller will fold into its own
    // model's context, so it is screened like fetched web content. The audit row
    // records the ORIGINAL reply (`original_envelope`); the client gets the
    // screened one. Non-streamed only — a streamed reply is already on the wire
    // (see `stream_response`).
    if request.method.reply_carries_content() {
        let before = original_envelope
            .clone()
            .unwrap_or_else(|| response_json.clone());
        if screen_reply(
            &identity,
            &request.method,
            &mut response_json,
            &mut audit.screening,
        )
        .await
        {
            original_envelope = Some(before);
        }
    }

    let status =
        StatusCode::from_u16(reply.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
    audit
        .reply(
            Some(&request),
            status,
            response_json,
            original_envelope,
            upstream_ms,
        )
        .await
}

// ─── Policy + guardrail hops ─────────────────────────────────────────────────

/// The phase a policy finding fired in, as stamped on the audit row.
const PHASE_REQUEST: &str = "request";
const PHASE_RESPONSE: &str = "response";

/// What the request-phase hops decided.
enum RequestScreen {
    /// Nothing fired — forward the body verbatim.
    Clean,
    /// A rule or a verdict rewrote the message; `params` now holds the screened
    /// version and must be forwarded in place of the original.
    Rewritten,
    /// A `Block` rule matched. The agent is never contacted.
    Blocked { message: String },
}

/// Everything the policy + guardrail hops produced for one call — the audit
/// row's badges and its `transform_diff`. Carried on the [`AuditDraft`] so every
/// exit path stamps it without a per-call-site argument.
#[derive(Default)]
pub struct Screening {
    badges: Vec<streamscope_core::audit::AuditBadge>,
    /// Every rule that fired, with the phase it fired in. A Vec, not a slot: a
    /// request-phase rule can rewrite the outbound message AND a response-phase
    /// rule the reply, and an operator looking at a modified call must see both —
    /// keeping one would let the later finding erase the earlier one's record.
    policy: Vec<(&'static str, streamscope_core::config::tool_rules::RiskResult)>,
    guardrail_steps: Vec<streamscope_core::proxy::content::GuardrailStepDiff>,
}

impl Screening {
    /// Record a rule that fired. A bare `allow` with no rule id carries nothing
    /// an operator can act on, so it is dropped rather than stored as noise.
    fn add_policy(
        &mut self,
        phase: &'static str,
        result: streamscope_core::config::tool_rules::RiskResult,
    ) {
        if result.id.is_some() || result.action != "allow" {
            self.policy.push((phase, result));
        }
    }

    /// The typed `transform_diff` payload: every rule that fired plus every
    /// guardrail finding. `{}` when nothing fired — an empty diff renders as no
    /// banner rather than an empty one.
    fn transform_diff(&self) -> Value {
        let mut diff = serde_json::Map::new();
        if !self.policy.is_empty() {
            let findings: Vec<Value> = self
                .policy
                .iter()
                .map(|(phase, r)| {
                    serde_json::json!({
                        "phase": phase,
                        "rule_id": r.id,
                        "risk": r.risk,
                        "title": r.title,
                        "description": r.description,
                        "action": r.action,
                    })
                })
                .collect();
            diff.insert("policy_findings".to_string(), Value::Array(findings));
        }
        if !self.guardrail_steps.is_empty()
            && let Ok(steps) = serde_json::to_value(&self.guardrail_steps)
        {
            diff.insert("guardrail_steps".to_string(), steps);
        }
        Value::Object(diff)
    }
}

/// Resolve the workspace's effective tool rules + guardrail. Both go through the
/// canonical per-workspace resolvers — never the tenant defaults directly — so an
/// Off profile really means off.
fn effective_policy(
    identity: &A2aIdentity,
) -> (
    Vec<streamscope_core::config::tool_rules::Rule>,
    streamscope_core::guardrail::GuardrailSettings,
) {
    let ws = identity.user.workspace_id;
    (
        identity.config.effective_tool_rules(ws).into_owned(),
        identity.config.effective_guardrail(ws).clone(),
    )
}

/// Screen the caller's message: policy first (a refusal costs no classifier
/// call), then the guardrail. `params` is rewritten in place when either
/// enforces.
async fn screen_request(
    identity: &A2aIdentity,
    params: &mut Value,
    screening: &mut Screening,
) -> RequestScreen {
    let (rules, guardrail) = effective_policy(identity);
    use streamscope_core::a2a::domain;

    let mut slots = domain::request_slots(params);
    // The message's free-form `metadata` map is screened alongside its parts —
    // otherwise a caller routes around a rule by moving the content one field over.
    let mut texts = domain::request_text_slots(params);
    if slots.is_empty() && texts.is_empty() {
        return RequestScreen::Clean;
    }

    let ctx = policy::PolicyContext {
        rules: &rules,
        agent_slug: &identity.agent.slug,
        app_id: identity.app_id.as_deref(),
    };
    let mut rewritten = false;
    match policy::evaluate(
        &ctx,
        streamscope_core::config::tool_rules::Phase::Request,
        &slots,
        &texts,
    ) {
        policy::PolicyDecision::Block { result, message } => {
            let mut bb = streamscope_core::audit::BadgeBuilder::new();
            bb.add_tool_blocked(
                streamscope_core::audit::Phase::Request,
                identity.agent.slug.clone(),
            );
            screening.badges.extend(bb.finish());
            screening.add_policy(PHASE_REQUEST, result);
            return RequestScreen::Blocked { message };
        }
        policy::PolicyDecision::Replace {
            result,
            slots: new_slots,
            texts: new_texts,
        } => {
            slots = new_slots;
            texts = new_texts;
            screening.add_policy(PHASE_REQUEST, result);
            rewritten = true;
        }
        policy::PolicyDecision::Allow(Some(result)) => screening.add_policy(PHASE_REQUEST, result),
        policy::PolicyDecision::Allow(None) => {}
    }

    let outcome =
        guardrail::screen_request(&guardrail, &mut slots, &mut texts, &identity.agent.slug).await;
    rewritten |= outcome.modified;
    screening.badges.extend(outcome.badges);
    screening.guardrail_steps.extend(outcome.steps);

    if rewritten {
        for slot in &slots {
            domain::write_back(params, slot);
        }
        for slot in &texts {
            domain::write_text(params, slot);
        }
        return RequestScreen::Rewritten;
    }
    RequestScreen::Clean
}

/// Screen the parts of an agent reply — the ONE place the response phase runs.
///
/// Both reply paths call it (a buffered `result`, or the events a stream
/// captured), because the two of them drifting apart is exactly how a screening
/// hole gets built: one path grows a check, the other doesn't. `truncated` says
/// the caller could only hand over a prefix of the reply.
///
/// Returns the rewritten slots when enforcement changed something — the caller
/// writes them back where they came from. A stream passes `Enforcement::Observe`:
/// those bytes are already on the wire, so a finding can only be recorded.
#[allow(clippy::too_many_arguments)]
async fn screen_reply_slots(
    rules: &[streamscope_core::config::tool_rules::Rule],
    guardrail: &streamscope_core::guardrail::GuardrailSettings,
    agent_slug: &str,
    app_id: Option<&str>,
    mut slots: Vec<streamscope_core::a2a::domain::PartsSlot>,
    mut texts: Vec<streamscope_core::a2a::domain::TextSlot>,
    enforce: bool,
    truncated: bool,
    screening: &mut Screening,
) -> Option<ScreenedReply> {
    let ctx = policy::PolicyContext {
        rules,
        agent_slug,
        app_id,
    };
    let response_rules_apply = policy::has_rules(
        &ctx,
        streamscope_core::config::tool_rules::Phase::Response,
    );

    // The incomplete marker is raised BEFORE the empty check, not after: a reply
    // the pump could not read at all yields no slots, and an early return would
    // report the emptiest possible scan as the cleanest one.
    if truncated && (response_rules_apply || guardrail::screens_reply(guardrail)) {
        let outcome = guardrail::incomplete_capture(agent_slug);
        screening.badges.extend(outcome.badges);
        screening.guardrail_steps.extend(outcome.steps);
    }
    if slots.is_empty() && texts.is_empty() {
        return None;
    }

    let mut rewritten = false;
    match policy::evaluate(
        &ctx,
        streamscope_core::config::tool_rules::Phase::Response,
        &slots,
        &texts,
    ) {
        policy::PolicyDecision::Replace {
            result: risk,
            slots: new_slots,
            texts: new_texts,
        } => {
            if enforce {
                slots = new_slots;
                texts = new_texts;
                rewritten = true;
            }
            screening.add_policy(PHASE_RESPONSE, risk);
        }
        policy::PolicyDecision::Allow(Some(risk)) => screening.add_policy(PHASE_RESPONSE, risk),
        policy::PolicyDecision::Allow(None) => {}
        // `validate()` forbids Block on the response phase — the work is already
        // done and the reply exists; there is nothing to refuse.
        policy::PolicyDecision::Block { result: risk, .. } => {
            screening.add_policy(PHASE_RESPONSE, risk)
        }
    }

    let outcome =
        guardrail::screen_reply(guardrail, &mut slots, &mut texts, agent_slug, enforce).await;
    rewritten |= outcome.modified;
    screening.badges.extend(outcome.badges);
    screening.guardrail_steps.extend(outcome.steps);

    rewritten.then_some(ScreenedReply { slots, texts })
}

/// What enforcement changed in a reply — written back where each piece came from.
struct ScreenedReply {
    slots: Vec<streamscope_core::a2a::domain::PartsSlot>,
    texts: Vec<streamscope_core::a2a::domain::TextSlot>,
}

/// Screen a buffered reply (`result`) and rewrite it in place. Returns whether it
/// was rewritten — the caller then keeps the original for the audit row.
///
/// `GetExtendedAgentCard` answers with a card, not a task: its content is the
/// agent's own prose (its description, its skills'), which the caller's model
/// reads as documentation. `card::rewrite_card` fixes the card's endpoint and auth
/// scheme, but a rewrite is not a screen — so the prose is classified like any
/// other reply.
async fn screen_reply(
    identity: &A2aIdentity,
    method: &A2aMethod,
    envelope: &mut Value,
    screening: &mut Screening,
) -> bool {
    use streamscope_core::a2a::domain;

    let (rules, guardrail) = effective_policy(identity);
    let screen = async |slots, texts, screening: &mut Screening| {
        screen_reply_slots(
            &rules,
            &guardrail,
            &identity.agent.slug,
            identity.app_id.as_deref(),
            slots,
            texts,
            true,
            false,
            screening,
        )
        .await
    };

    // A JSON-RPC reply is a oneof: `result` or `error`. Both carry
    // agent-authored text, so both are screened — an agent whose *failure*
    // message reaches the caller's model unscreened is the same injection
    // channel as one whose answer does, just on the sad path.
    if let Some(result) = envelope.get_mut("result") {
        let (slots, texts) = if *method == A2aMethod::GetExtendedAgentCard {
            (Vec::new(), domain::card_text_slots(result))
        } else {
            (domain::reply_slots(result), domain::reply_text_slots(result))
        };
        let Some(rewritten) = screen(slots, texts, screening).await else {
            return false;
        };
        for slot in &rewritten.slots {
            domain::write_back(result, slot);
        }
        for slot in &rewritten.texts {
            domain::write_text(result, slot);
        }
        return true;
    }

    if envelope.get("error").is_some() {
        let texts = domain::error_text_slots(envelope);
        if texts.is_empty() {
            return false;
        }
        let Some(rewritten) = screen(Vec::new(), texts, screening).await else {
            return false;
        };
        for slot in &rewritten.texts {
            domain::write_text(envelope, slot);
        }
        return true;
    }

    false
}

/// The A2A service parameters passed through verbatim in both directions
/// (spec § 3.2.6). Everything else the client sent is the gateway's business,
/// not the upstream's.
fn service_headers(headers: &HeaderMap) -> Vec<(&'static str, String)> {
    ["a2a-version", "a2a-extensions"]
        .iter()
        .filter_map(|name| {
            headers
                .get(*name)
                .and_then(|v| v.to_str().ok())
                .map(|v| (*name, v.to_string()))
        })
        .collect()
}

// ─── Streaming (SendStreamingMessage / SubscribeToTask) ──────────────────────

/// Open the upstream SSE stream and pipe it to the client, tee-ing decoded
/// events into the audit accumulator.
///
/// The response returns to the client as soon as the upstream stream opens; a
/// spawned pump drives it. **The pipe is never blocked on audit work**: an
/// event that fails to parse is kept verbatim, and once the audit accumulator
/// hits its cap it stops retaining events (leaving a truncation marker) while
/// the wire stream continues untouched. Exactly one audit record is emitted
/// when the pump ends — on upstream EOF, client disconnect, transport error,
/// or the byte cap.
///
/// `gateway_audit.error_category` values the pump writes. The dashboards
/// aggregate on these strings, so a client hanging up must not land in the
/// upstream bucket — that would blame the agent for a well-behaved client.
const UPSTREAM_ERROR: &str = "upstream";
const CANCELLED: &str = "cancelled";

/// Audit-side accumulation for one streamed call. Deliberately off the wire
/// path: the pump forwards each chunk to the client *before* feeding it here,
/// so no amount of bookkeeping can stall the stream.
struct StreamCapture {
    events: Vec<Value>,
    audit_bytes: usize,
    audit_byte_cap: usize,
    truncated: bool,
    context_id: Option<String>,
    task_id: Option<String>,
    task_state: Option<String>,
    /// Whether the last observed state is terminal — the signal that the task
    /// finished, whatever the client did with the connection afterwards.
    task_terminal: bool,
}

impl StreamCapture {
    fn new(audit_byte_cap: usize) -> Self {
        Self {
            events: Vec::new(),
            audit_bytes: 0,
            audit_byte_cap,
            truncated: false,
            context_id: None,
            task_id: None,
            task_state: None,
            task_terminal: false,
        }
    }

    /// Retain one decoded SSE event. A payload that fails to parse is kept as
    /// raw text (nothing is silently discarded); overflowing the cap leaves a
    /// truncation marker and stops retaining — it never stops the wire.
    fn retain(&mut self, data: &str) {
        let parsed: Value = serde_json::from_str(data)
            .unwrap_or_else(|_| serde_json::json!({ "unparsed": data }));

        // Correlators ride the JSON-RPC envelope's `result` (the StreamResponse
        // payload). Tracked even once retention is capped: the audit row's task
        // state must stay accurate on a long stream.
        if let Some(result) = parsed.get("result") {
            let event = v1_0::parse_stream_response(result);
            let (ctx, task, state) = event.correlators();
            if let Some(c) = ctx {
                self.context_id = Some(c.to_string());
            }
            if let Some(t) = task {
                self.task_id = Some(t.to_string());
            }
            if let Some(s) = state {
                self.task_state = Some(v1_0::emit_task_state(s));
                self.task_terminal = s.is_terminal();
            }
        }

        if self.truncated {
            return;
        }
        self.audit_bytes += data.len();
        if self.audit_bytes > self.audit_byte_cap {
            self.truncated = true;
            self.events.push(serde_json::json!({
                "truncated": true,
                "reason": "audit stream capture cap reached",
            }));
            return;
        }
        self.events.push(parsed);
    }
}

async fn stream_response(
    state: A2aRouterState,
    mut audit: AuditDraft<'_>,
    request: A2aRequest,
    body: bytes::Bytes,
    headers: &HeaderMap,
) -> Response<Body> {
    use bytes::{Bytes, BytesMut};
    use futures::StreamExt;
    use streamscope_core::api::sse::SseDecoder;
    use tokio_util::codec::Decoder;

    let upstream_resp =
        match upstream::open_stream(&audit.identity.agent, body, &service_headers(headers)).await {
            Ok(upstream::StreamOpen::Sse(resp)) => resp,
            // The upstream declined to stream and answered an envelope
            // instead — e.g. `SubscribeToTask` on an already-terminal task,
            // which the spec answers with `-32004`. Forward its verdict
            // verbatim; inventing a gateway error here would hide the real
            // reason from the client.
            Ok(upstream::StreamOpen::Json(reply)) => {
                let mut envelope: Value =
                    serde_json::from_slice(&reply.body).unwrap_or_else(|_| {
                        jsonrpc_error(
                            &request.rpc_id,
                            A2aErrorCode::InvalidAgentResponse,
                            "upstream agent returned a non-JSON response",
                        )
                    });
                // This reply is fully buffered, so it is screened and enforced like
                // any other — the streaming *method* does not make it a stream. An
                // agent that answers `SendStreamingMessage` with plain JSON (a
                // short answer, or a task that is already done) would otherwise
                // reach the caller through the one branch the response hop skipped.
                let mut original_envelope = None;
                let identity = audit.identity;
                if request.method.reply_carries_content() {
                    let before = envelope.clone();
                    if screen_reply(
                        identity,
                        &request.method,
                        &mut envelope,
                        &mut audit.screening,
                    )
                    .await
                    {
                        original_envelope = Some(before);
                    }
                }
                let status = StatusCode::from_u16(reply.status)
                    .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
                return audit
                    .reply(
                        Some(&request),
                        status,
                        envelope,
                        original_envelope,
                        reply.latency_ms,
                    )
                    .await;
            }
            Err(e) => {
                let envelope =
                    jsonrpc_error(&request.rpc_id, A2aErrorCode::InternalError, &e.to_string());
                return audit
                    .reply(Some(&request), StatusCode::BAD_GATEWAY, envelope, None, 0)
                    .await;
            }
        };

    // Bounded channel: the pump's `send().await` blocks when the client
    // hasn't drained, propagating backpressure up the upstream stream instead
    // of queueing events in proxy memory.
    let (tx, rx) = tokio::sync::mpsc::channel::<Result<Bytes, std::io::Error>>(64);

    let settings = crate::settings::proxy_settings();
    let stream_byte_cap = settings.a2a_stream_max_bytes;
    let audit_byte_cap = settings.a2a_audit_stream_max_bytes;

    // The draft borrows the identity; the pump owns its own copy of what it
    // needs to emit the record after the response future has resolved.
    let record_base = audit.base_record(StatusCode::OK.as_u16());
    let audit_tx = state.a2a_audit_tx.clone();
    let method = request.method.as_str().to_string();
    let params = request.params.clone();
    let request_bytes = audit.request_bytes;
    let started = audit.started;
    // Reply-phase screening for a stream is observe-only and runs once, at the
    // end, over the events the pump captured — the bytes went out as they came
    // in, so a finding here is a record, never a rewrite.
    let reply_screen = request
        .method
        .reply_carries_content()
        .then(|| effective_policy(audit.identity))
        .map(|(rules, guardrail)| {
            (
                rules,
                guardrail,
                audit.identity.agent.slug.clone(),
                audit.identity.app_id.clone(),
            )
        });
    let mut screening = std::mem::take(&mut audit.screening);

    // Tracked, not a bare spawn: graceful shutdown waits on the tracker before
    // draining the audit writers, so a stream in flight still lands its row.
    state.app.audit_task_tracker.clone().spawn(async move {
        let mut byte_stream = upstream_resp.bytes_stream();
        let mut decoder = SseDecoder::new();
        let mut buf = BytesMut::with_capacity(8 * 1024);

        let mut total_bytes: usize = 0;
        let mut capture = StreamCapture::new(audit_byte_cap);
        let mut failure: Option<(&'static str, String)> = None;
        let mut client_connected = true;

        'pump: loop {
            let next = tokio::select! {
                // Biased, upstream first: at the end of a stream both arms can
                // be ready at once (the client hangs up on the terminal event
                // just as the upstream closes). A random pick would report a
                // completed task as a cancelled one.
                biased;
                next = byte_stream.next() => next,
                // A client that goes away mid-stream is noticed immediately,
                // not on the next upstream chunk — a silent upstream would
                // otherwise hold this task (and the shutdown drain) open.
                () = tx.closed() => {
                    client_connected = false;
                    break 'pump;
                }
            };
            let chunk = match next {
                Some(Ok(chunk)) => chunk,
                Some(Err(e)) => {
                    // Poison the client's stream. A bare `break` would close
                    // the body cleanly, and EOF is A2A 1.0's terminal signal —
                    // the client would read a failed transfer as a completed
                    // task.
                    let msg = format!("upstream stream error: {e}");
                    let _ = tx.send(Err(std::io::Error::other(msg.clone()))).await;
                    failure = Some((UPSTREAM_ERROR, msg));
                    break 'pump;
                }
                None => break 'pump, // upstream EOF — the terminal state per spec
            };

            total_bytes += chunk.len();
            if total_bytes > stream_byte_cap {
                let msg = "upstream stream exceeded the byte cap".to_string();
                let _ = tx.send(Err(std::io::Error::other(msg.clone()))).await;
                failure = Some((UPSTREAM_ERROR, msg));
                break 'pump;
            }

            // Forward the bytes verbatim FIRST — the client's stream never
            // waits on our bookkeeping.
            if tx.send(Ok(chunk.clone())).await.is_err() {
                client_connected = false;
                break 'pump;
            }

            buf.extend_from_slice(&chunk);
            loop {
                match decoder.decode(&mut buf) {
                    Ok(Some(ev)) => capture.retain(&ev.data),
                    Ok(None) => break,
                    Err(e) => {
                        // The decoder has already consumed the malformed
                        // block, so it cannot be retained. Surface it on both
                        // sides rather than dropping it silently.
                        let msg = format!("malformed upstream SSE: {e}");
                        let _ = tx.send(Err(std::io::Error::other(msg.clone()))).await;
                        failure = Some((UPSTREAM_ERROR, msg));
                        break 'pump;
                    }
                }
            }
        }

        // Tail between the last `\n\n` and EOF: an upstream may close without
        // a trailing blank line, and in A2A 1.0 the terminal `statusUpdate` is
        // the last event — without this it would vanish from the audit row and
        // `task_state` would read as non-terminal. Runs on the client-disconnect
        // path too: those bytes arrived and are just as audit-relevant.
        if failure.is_none() {
            match decoder.decode_eof(&mut buf) {
                Ok(Some(ev)) => capture.retain(&ev.data),
                Ok(None) => {}
                Err(e) => {
                    // A tail truncated mid-character. Same contract as a
                    // malformed event mid-stream: never let it read as a clean
                    // close, which is exactly what a completed task looks like.
                    let msg = format!("malformed upstream SSE at EOF: {e}");
                    let _ = tx.send(Err(std::io::Error::other(msg.clone()))).await;
                    failure = Some((UPSTREAM_ERROR, msg));
                }
            }
        }
        // A client hanging up once the task reached a terminal state is the
        // normal end of a stream, not a fault — recording it as one would
        // inflate the agent's error rate on every well-behaved client.
        if !client_connected && failure.is_none() && !capture.task_terminal {
            failure = Some((CANCELLED, "client disconnected mid-stream".to_string()));
        }

        // Screen what the agent streamed — through the same core the buffered
        // path uses, in observe mode: the client already holds these bytes, so a
        // finding lands on the audit row and nowhere else. Skipping this would
        // leave the streamed path — the one an agent framework actually uses —
        // entirely unscreened.
        if let Some((rules, guardrail, agent_slug, app_id)) = reply_screen
            && !capture.events.is_empty()
        {
            let slots = guardrail::slots_from_stream_events(&capture.events);
            let texts = guardrail::text_slots_from_stream_events(&capture.events);
            // "Incomplete" covers both ways the screen can be handed less than the
            // agent sent: the capture stopped at the byte cap, or it retained an
            // event nothing could read (a non-JSON `data:` line, an envelope in no
            // shape we know). Both were forwarded to the client; neither may be
            // scanned around and then reported clean.
            let incomplete =
                capture.truncated || guardrail::capture_has_unreadable_event(&capture.events);
            screen_reply_slots(
                &rules,
                &guardrail,
                &agent_slug,
                app_id.as_deref(),
                slots,
                texts,
                false,
                incomplete,
                &mut screening,
            )
            .await;
        }

        let mut record = record_base;
        record.method = method;
        record.params = Some(params);
        record.badges = screening.badges.clone();
        record.transform_diff = screening.transform_diff();
        record.a2a_context_id = capture.context_id;
        record.a2a_task_id = capture.task_id;
        record.task_state = capture.task_state;
        record.stream_events = (!capture.events.is_empty()).then_some(Value::Array(capture.events));
        record.response_bytes = Some(i32::try_from(total_bytes).unwrap_or(i32::MAX));
        record.request_bytes = Some(request_bytes);
        record.latency_total_ms = started.elapsed().as_millis() as u64;
        record.upstream_latency_ms = record.latency_total_ms;
        if let Some((category, detail)) = failure {
            record.error_category = Some(category.to_string());
            record.error_detail = Some(detail.clone());
            record.error_message = Some(detail);
        }
        if let Err(e) = audit_tx.try_send(record) {
            tracing::warn!("a2a streaming audit channel send failed: {e}");
        }
    });

    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(rx));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .header("cache-control", "no-cache")
        .header("a2a-version", SUPPORTED_VERSION)
        .body(body)
        .unwrap_or_else(|_| Response::new(Body::empty()))
}

// ─── Audit + response rendering ──────────────────────────────────────────────

/// Per-request audit context. `reply` is the single exit point for every
/// post-auth outcome: it emits exactly one `A2aAuditRecord` and renders the
/// JSON-RPC envelope with the negotiated version header.
struct AuditDraft<'a> {
    state: &'a A2aRouterState,
    identity: &'a A2aIdentity,
    request_id: Uuid,
    started: std::time::Instant,
    user_agent: Option<String>,
    session_id: Option<Uuid>,
    request_bytes: i32,
    /// What the policy + guardrail hops produced. Filled in as the call moves
    /// through them; stamped on the record by `base_record`, so no exit path can
    /// emit a row that forgets a rule fired.
    screening: Screening,
}

impl AuditDraft<'_> {
    /// Base record with the request-scoped fields every outcome shares.
    /// `stream_events` is left NULL here and filled only by the streaming pump,
    /// which owns the record from the moment the SSE body starts.
    /// Every exit path (`reply`, `record_rejection`, the pump) builds on this,
    /// so a column is never populated on one and forgotten on another.
    fn base_record(&self, status: u16) -> A2aAuditRecord {
        A2aAuditRecord {
            request_id: self.request_id,
            timestamp: chrono::Utc::now(),
            tenant_id: self.identity.tenant_id,
            workspace_id: self.identity.workspace_id,
            user_id: self.identity.user_id,
            key_id: self.identity.key_id,
            app_id: self.identity.app_id.clone(),
            session_id: self.session_id,
            user_agent: self.user_agent.clone(),
            ip: None,
            detection_method: self.identity.detection_method.clone(),
            latency_total_ms: self.started.elapsed().as_millis() as u64,
            status_code: Some(status),
            error_category: None,
            error_detail: None,
            limit_bucket: None,
            agent_id: self.identity.agent.id,
            method: "(rejected)".to_string(),
            a2a_context_id: None,
            a2a_task_id: None,
            task_state: None,
            params: None,
            result: None,
            stream_events: None,
            error_code: None,
            error_message: None,
            upstream_latency_ms: 0,
            request_bytes: Some(self.request_bytes),
            response_bytes: None,
            protocol_version: Some(SUPPORTED_VERSION.to_string()),
            badges: self.screening.badges.clone(),
            transform_diff: self.screening.transform_diff(),
        }
    }

    fn emit(&self, record: A2aAuditRecord) {
        if let Err(e) = self.state.a2a_audit_tx.try_send(record) {
            tracing::warn!(request_id = %self.request_id, "a2a audit channel send failed: {e}");
        }
    }

    /// Audit a gateway-level rejection (an unreadable body, rate limit, budget)
    /// that never reaches the JSON-RPC layer. The client is answered with the proxy's
    /// standard error response, but the refusal is still on the record.
    async fn record_rejection(&self, err: &AppError) {
        let (status, category, detail) = err.audit_error_info();
        let mut record = self.base_record(status);
        record.error_category = Some(category.to_string());
        record.error_detail = Some(detail);
        record.limit_bucket = err.limit_bucket().map(|b| b.as_str().to_string());
        self.emit(record);
    }

    /// `original_envelope` is the agent's reply as it arrived, when the
    /// response-phase hops rewrote what the client gets. Every audited field —
    /// the result, the error message, the correlators — is read from it, because
    /// the audit row stores **what the agent actually said**: an investigator
    /// needs the real prose, not the placeholder that replaced it. The wire
    /// carries the screened `envelope`. `None` when nothing was rewritten.
    async fn reply(
        &self,
        request: Option<&A2aRequest>,
        status: StatusCode,
        envelope: Value,
        original_envelope: Option<Value>,
        upstream_ms: u64,
    ) -> Response<Body> {
        let (method, params, ids) = match request {
            Some(req) => (
                req.method.as_str().to_string(),
                Some(req.params.clone()),
                req.param_ids(),
            ),
            // Pre-dispatch failures (version, parse): no method resolved.
            None => ("(invalid)".to_string(), None, Default::default()),
        };

        // Everything audited is read from the reply as the AGENT sent it; only
        // the bytes on the wire are the screened ones.
        let audited = original_envelope.as_ref().unwrap_or(&envelope);

        // Correlators: prefer what the RESPONSE carries (the server mints
        // task ids), fall back to the request params.
        let (mut context_id, mut task_id, mut task_state) =
            (ids.context_id.clone(), ids.task_id.clone(), None);
        let error = audited.get("error");
        if error.is_none()
            && let Some(result) = audited.get("result")
        {
            // SendMessage results wrap `task`/`message`; GetTask returns a
            // bare Task — probe both shapes.
            let event = match v1_0::parse_stream_response(result) {
                A2aStreamEvent::Unknown(_) => v1_0::parse_task(result)
                    .map(A2aStreamEvent::Task)
                    .unwrap_or(A2aStreamEvent::Unknown(Value::Null)),
                ev => ev,
            };
            let (ctx, task, state_ref) = event.correlators();
            if let Some(c) = ctx {
                context_id = Some(c.to_string());
            }
            if let Some(t) = task {
                task_id = Some(t.to_string());
            }
            task_state = state_ref.map(v1_0::emit_task_state);
        }
        let (error_code, error_message) = match error {
            Some(err) => (
                err.get("code").and_then(Value::as_i64).map(|c| c as i32),
                err.get("message")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            ),
            None => (None, None),
        };

        let body = serde_json::to_vec(&envelope).unwrap_or_else(|_| b"{}".to_vec());
        let mut record = self.base_record(status.as_u16());
        record.method = method;
        record.a2a_context_id = context_id;
        record.a2a_task_id = task_id;
        record.task_state = task_state;
        record.params = params;
        record.result = error
            .is_none()
            .then(|| audited.get("result").cloned().unwrap_or(Value::Null));
        record.error_code = error_code;
        record.error_message = error_message.clone();
        // `rpc_error` is the shared category for a JSON-RPC-level failure —
        // same value the MCP path stamps, so the dashboard's error breakdown
        // buckets both protocols together instead of growing a per-protocol
        // bucket the UI has no arm for.
        record.error_category = error_code.map(|_| "rpc_error".to_string());
        record.error_detail = error_message;
        record.upstream_latency_ms = upstream_ms;
        record.response_bytes = Some(body.len() as i32);
        self.emit(record);

        Response::builder()
            .status(status)
            .header("content-type", "application/json")
            .header("a2a-version", SUPPORTED_VERSION)
            .body(Body::from(body))
            .unwrap_or_else(|_| Response::new(Body::empty()))
    }
}

/// HTTP-level error (auth / body read / rate limit / budget) — pre-envelope, so the
/// response is the proxy's standard JSON error shape (`AppError`'s
/// `IntoResponse`), not JSON-RPC.
fn app_error_response(e: AppError) -> Response<Body> {
    use axum::response::IntoResponse;
    e.into_response()
}

fn json_response(status: StatusCode, body: Value) -> Response<Body> {
    let bytes = serde_json::to_vec(&body).unwrap_or_else(|_| b"{}".to_vec());
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Body::from(bytes))
        .unwrap_or_else(|_| Response::new(Body::empty()))
}
