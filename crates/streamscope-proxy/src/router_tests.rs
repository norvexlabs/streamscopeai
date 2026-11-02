//! In-process tests over the REAL proxy router.
//!
//! These build the production surface through [`crate::build_app`] — the same
//! construction `run` serves — and drive it with `tower::ServiceExt::oneshot`.
//! The proxy has no auth *middleware*: every handler resolves the `sk-`/`vk-`
//! key inline against the in-memory tenant registry. So the wiring these tests
//! own is the mount tree itself — is a route reachable, is it authenticated, is
//! the scrape surface absent — plus the liveness/readiness split.
//!
//! **No config is loaded and no upstream exists.** The registry is empty, so no
//! key resolves and every authenticated route stops at 401 without attempting an
//! upstream call. That bounds what this tier can prove: it asserts the fence, not
//! what happens behind it. A request that authenticates and forwards is E2E's job.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use tower::ServiceExt;

use streamscope_core::api::sse::ApiVersion;
use streamscope_core::proxy::{AppState, NoopStats};

use crate::{a2a, build_app, mcp};

/// The audit receivers are held alive for the router's lifetime: dropping them
/// would close the channels under the handlers.
struct TestRig {
    app: axum::Router,
    state: Arc<AppState>,
    _keepalive: Keepalive,
}

#[allow(dead_code)]
struct Keepalive {
    audit_rx: streamscope_core::audit::AuditReceiver<streamscope_core::audit::AuditRecord>,
    mcp_audit_rx: streamscope_core::audit::AuditReceiver<streamscope_core::audit::mcp::McpAuditRecord>,
    a2a_audit_rx: streamscope_core::audit::AuditReceiver<streamscope_core::audit::a2a::A2aAuditRecord>,
    web_audit_rx: streamscope_core::audit::AuditReceiver<streamscope_core::web::WebAuditRecord>,
    mcp_sse_event_rx:
        streamscope_core::audit::AuditReceiver<streamscope_core::mcp::sse_events::McpSseEventRecord>,
}

/// The production router over an offline `AppState`: an empty tenant registry (no
/// config synced yet), no edge link (`health_event_tx` / `web_audit_tx` are
/// `None` — the shape the state documents for test contexts), and no upstream.
///
/// The public-metadata limiter is given a cap no test can reach, so it is inert
/// for everything except the throttle tests, which build their own rig.
fn rig() -> TestRig {
    rig_with_metadata_cap(u32::MAX)
}

fn rig_with_metadata_cap(metadata_cap: u32) -> TestRig {
    let (audit_tx, audit_rx) = streamscope_core::audit::create_audit_channel();
    let (mcp_audit_tx, mcp_audit_rx) = streamscope_core::audit::mcp::create_mcp_audit_channel();
    let (a2a_audit_tx, a2a_audit_rx) = streamscope_core::audit::a2a::create_a2a_audit_channel();
    let (web_audit_tx, web_audit_rx) = streamscope_core::web::create_web_audit_channel();
    let (mcp_sse_event_tx, mcp_sse_event_rx) = streamscope_core::audit::counted_channel(16);

    let state = Arc::new(AppState {
        usage: Arc::new(streamscope_core::usage::UsageTracker::new()),
        http_client: streamscope_core::proxy::client::UpstreamClient::new()
            .expect("upstream client builds offline"),
        tenant_registry: streamscope_core::config::new_tenant_registry(),
        audit_tx,
        session_detector: streamscope_core::proxy::content::SessionDetector::with_capacity(
            16,
            Duration::from_secs(60),
            64,
        ),
        inline_exchanges: streamscope_core::proxy::inline_exchange::InlineExchangeStore::default(),
        script_engine: Arc::new(streamscope_core::scripting::ScriptEngine::new()),
        lb_counters: dashmap::DashMap::new(),
        circuit_breaker: Arc::new(streamscope_core::proxy::health::CircuitBreaker::new(
            false,
            5,
            Duration::from_secs(30),
        )),
        health_event_tx: None,
        proxy_stats: Arc::new(NoopStats),
        web_search_clients: Arc::new(
            streamscope_core::extension_http::ExtensionClients::build(
                "search",
                reqwest::Client::builder,
            )
            .unwrap(),
        ),
        web_audit_tx: None,
        mixed_pending_cache: Arc::new(streamscope_core::web::MixedPendingCache::default()),
        response_cache: Arc::new(
            streamscope_core::proxy::response_cache::ResponseCache::new(1024 * 1024, 16),
        ),
        audit_task_tracker: tokio_util::task::TaskTracker::new(),
        config_ready: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        dispatch_gate: std::sync::Arc::new(
            streamscope_core::proxy::dispatch_gate::DispatchGate::new(Default::default()),
        ),
    });

    let mcp_state = mcp::McpRouterState {
        app: state.clone(),
        mcp: mcp::McpAppState::with_rotation_sink(
            mcp_audit_tx,
            mcp_sse_event_tx,
            web_audit_tx,
            mcp::sse_seq::McpSseSequenceMap::new(),
            None,
            mcp::event_bus::PerUserEventBus::new(16),
            tokio_util::sync::CancellationToken::new(),
        ),
    };

    let a2a_state = a2a::A2aRouterState {
        app: state.clone(),
        a2a_audit_tx,
    };

    TestRig {
        app: build_app(
            state.clone(),
            mcp_state,
            a2a_state,
            Arc::new(streamscope_core::middleware::ip_rate_limit::RateLimiter::new(
                metadata_cap,
                300,
                crate::ip_rate_limit::PUBLIC_METADATA_LIMIT_CLEANUP_THRESHOLD,
            )),
        ),
        state,
        _keepalive: Keepalive { audit_rx, mcp_audit_rx, a2a_audit_rx, web_audit_rx, mcp_sse_event_rx },
    }
}

fn json_post(uri: &str, key: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder()
        .method("POST")
        .uri(uri)
        .header("content-type", "application/json");
    if let Some(key) = key {
        builder = builder.header("authorization", format!("Bearer {key}"));
    }
    builder
        .body(Body::from(
            serde_json::json!({
                "model": "gpt-4o",
                "messages": [{ "role": "user", "content": "hi" }],
            })
            .to_string(),
        ))
        .expect("well-formed request")
}

// ---------------------------------------------------------------------------
// The key fence — every data-plane route authenticates
// ---------------------------------------------------------------------------

/// Assert a refusal carries the authentication-error envelope of the grammar its
/// route speaks, as that protocol's spec defines it: OpenAI's `error.type`
/// (the gateway's `auth_error`), Anthropic's typed `authentication_error`
/// object, Gemini's AIP-193 `code` + `UNAUTHENTICATED` status — each with an
/// `error.message`. That envelope is the contract the protocol's SDKs parse; a
/// refusal in another protocol's shape reaches the client as raw JSON, so it is
/// a regression even though the status is right.
async fn assert_auth_error(resp: axum::response::Response, grammar: ApiVersion) {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    let body: serde_json::Value = serde_json::from_slice(&bytes).expect("error body is JSON");
    match grammar {
        ApiVersion::ChatCompletions | ApiVersion::Responses => {
            assert_eq!(body["error"]["type"], "auth_error", "OpenAI envelope expected, got {body}");
            assert!(body.get("type").is_none(), "no Anthropic discriminator on OpenAI, got {body}");
        }
        ApiVersion::AnthropicMessages => {
            assert_eq!(body["type"], "error", "Anthropic envelope expected, got {body}");
            assert_eq!(body["error"]["type"], "authentication_error", "got {body}");
        }
        ApiVersion::GoogleGemini => {
            assert_eq!(body["error"]["code"], 401, "AIP-193 envelope expected, got {body}");
            assert_eq!(body["error"]["status"], "UNAUTHENTICATED", "got {body}");
        }
    }
    assert!(
        body["error"]["message"].is_string(),
        "refusal must carry a message, got {body}"
    );
}

/// No key at all: every inbound protocol, the media endpoints, and the `/v1/*`
/// catch-all are refused. The catch-all matters most — an unmatched `/v1/…` path
/// must land on an AUTHENTICATED forwarder, never an open one.
#[tokio::test]
async fn every_data_plane_route_requires_a_key() {
    let rig = rig();

    for (uri, grammar) in [
        ("/v1/chat/completions", ApiVersion::ChatCompletions),
        ("/v1/responses", ApiVersion::Responses),
        ("/v1/messages", ApiVersion::AnthropicMessages),
        ("/v1/messages/count_tokens", ApiVersion::AnthropicMessages),
        ("/fwd/vk-does-not-exist/v1/messages", ApiVersion::AnthropicMessages),
        ("/v1/embeddings", ApiVersion::ChatCompletions),
        ("/v1/audio/speech", ApiVersion::ChatCompletions),
        ("/v1/images/generations", ApiVersion::ChatCompletions),
        // The catch-all for unmatched /v1/* paths.
        ("/v1/some/unmatched/passthrough", ApiVersion::ChatCompletions),
    ] {
        let resp = rig
            .app
            .clone()
            .oneshot(json_post(uri, None))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{uri} must not serve an unauthenticated request"
        );
        assert_auth_error(resp, grammar).await;
    }
}

/// A key that resolves to nothing (empty registry — no config synced) is refused
/// exactly like a missing one: no tenant, no route, no upstream call.
#[tokio::test]
async fn an_unknown_key_is_refused() {
    let rig = rig();

    for key in ["sk-does-not-exist", "vk-does-not-exist", "not-even-a-key"] {
        let resp = rig
            .app
            .clone()
            .oneshot(json_post("/v1/chat/completions", Some(key)))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "key {key} must not authenticate against an empty registry"
        );
        assert_auth_error(resp, ApiVersion::ChatCompletions).await;
    }
}

/// The `/v1/*` surface accepts a key on either header channel — `Bearer` or the
/// Anthropic-native `x-api-key`. Both are credentials, so an unresolvable key is
/// refused on both; neither is a side door.
#[tokio::test]
async fn an_unknown_key_is_refused_on_either_header_channel() {
    let rig = rig();

    for (header, value) in [
        ("authorization", "Bearer sk-does-not-exist"),
        ("x-api-key", "sk-does-not-exist"),
    ] {
        let resp = rig
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/messages")
                    .header("content-type", "application/json")
                    .header(header, value)
                    .body(Body::from(
                        serde_json::json!({
                            "model": "claude-sonnet-4-5",
                            "max_tokens": 64,
                            "messages": [{ "role": "user", "content": "hi" }],
                        })
                        .to_string(),
                    ))
                    .expect("well-formed request"),
            )
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "an unknown key on the {header} channel must not authenticate"
        );
        assert_auth_error(resp, ApiVersion::AnthropicMessages).await;
    }
}

/// Gemini is the one inbound protocol that is neither a `/v1/*` path nor a
/// `Bearer` credential: it mounts at `/v1beta/models/{model}:{method}`, and its
/// native key rides `x-goog-api-key` — or the `?key=` query parameter Google's
/// own reference uses in every `curl` example. Every one of those is a way in,
/// so every one must be fenced. A channel that skips the check would be an
/// unauthenticated forwarder.
///
/// This test alone cannot tell a fenced channel from an UNREAD one — an unknown
/// key is refused either way.
/// `the_query_parameter_is_read_as_a_credential_on_the_gemini_surface_only`
/// below is its positive control.
#[tokio::test]
async fn the_gemini_surface_is_fenced_on_every_credential_channel() {
    let rig = rig();

    const GENERATE: &str = "/v1beta/models/gemini-2.5-flash:generateContent";
    const STREAM: &str = "/v1beta/models/gemini-2.5-flash:streamGenerateContent";

    let gemini_request = |uri: &str, credential: Option<(&str, &str)>| {
        let mut builder = Request::builder()
            .method("POST")
            .uri(uri)
            .header("content-type", "application/json");
        if let Some((name, value)) = credential {
            builder = builder.header(name, value);
        }
        builder
            .body(Body::from(
                serde_json::json!({
                    "contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
                })
                .to_string(),
            ))
            .expect("well-formed request")
    };

    for (label, uri, credential) in [
        ("no credential", GENERATE, None),
        ("no credential, streaming", STREAM, None),
        ("unknown key, native header", GENERATE, Some(("x-goog-api-key", "sk-does-not-exist"))),
        ("unknown key, bearer", GENERATE, Some(("authorization", "Bearer sk-does-not-exist"))),
        ("unknown key, x-api-key", GENERATE, Some(("x-api-key", "sk-does-not-exist"))),
        // The `?key=` query parameter is Gemini's native auth (the gemini CLI/SDK
        // sends it), normalized onto the header — the fence must see it as a
        // credential, not as an anonymous request with a stray query string.
        ("unknown key, query parameter", "/v1beta/models/gemini-2.5-flash:generateContent?key=sk-does-not-exist", None),
    ] {
        let resp = rig
            .app
            .clone()
            .oneshot(gemini_request(uri, credential))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{label} must not serve a Gemini request"
        );
        assert_auth_error(resp, ApiVersion::GoogleGemini).await;
    }
}

/// The list endpoints refuse in the grammar their list is served in. Gemini's
/// has its own path; `/v1/models` is the one path two specs share, so its
/// grammar — errors included — is the client's `anthropic-version`
/// declaration, and the same request without it is the positive control that
/// the OpenAI grammar still answers there.
#[tokio::test]
async fn a_model_list_refuses_in_the_grammar_it_lists_in() {
    let rig = rig();

    let list = |uri: &str, anthropic: bool| {
        let mut builder = Request::builder().method("GET").uri(uri);
        if anthropic {
            builder = builder.header("anthropic-version", "2023-06-01");
        }
        builder.body(Body::empty()).expect("well-formed request")
    };

    for (uri, anthropic, grammar) in [
        ("/v1/models", true, ApiVersion::AnthropicMessages),
        ("/v1/models", false, ApiVersion::ChatCompletions),
        ("/fwd/vk-does-not-exist/v1/models", true, ApiVersion::AnthropicMessages),
        ("/fwd/vk-does-not-exist/v1/models", false, ApiVersion::ChatCompletions),
        ("/v1beta/models", false, ApiVersion::GoogleGemini),
        ("/v1beta/models/gemini-2.5-flash", false, ApiVersion::GoogleGemini),
    ] {
        let resp = rig.app.clone().oneshot(list(uri, anthropic)).await.expect("router responds");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri} must not list unauthenticated");
        assert_auth_error(resp, grammar).await;
    }
}

/// The positive control for `?key=`: the fence test above passes whether the
/// query parameter is READ or ignored, because an unknown key and an absent one
/// are both 401. That is exactly how this channel came to be unimplemented on
/// the gateway mount while a test named for it stayed green.
///
/// The registry here is empty, so no key can ever resolve — but the two
/// refusals still say different things, and the difference is the evidence:
/// a credential that was read and did not resolve is `invalid API key`, while
/// one that was never read at all is `missing authorization header`. Asserting
/// on the message is unusual and deliberate: the proxy's error envelope carries
/// no machine code, and this distinction is the only observable proof the
/// channel reached the extractor.
///
/// The second half pins the boundary the other way. `?key=` is Gemini's
/// spelling — neither the OpenAI nor the Anthropic spec defines a query
/// channel, so the same parameter on `/v1/chat/completions` must remain no
/// credential at all. Without this case the surface gate could be deleted and
/// every other assertion here would still pass.
#[tokio::test]
async fn the_query_parameter_is_read_as_a_credential_on_the_gemini_surface_only() {
    let rig = rig();

    async fn refusal_message(rig: &TestRig, uri: &str, body: serde_json::Value) -> String {
        let resp = rig
            .app
            .clone()
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri(uri)
                    .header("content-type", "application/json")
                    .body(Body::from(body.to_string()))
                    .expect("well-formed request"),
            )
            .await
            .expect("router responds");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{uri} must not authenticate");
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
            .await
            .expect("read body");
        let parsed: serde_json::Value = serde_json::from_slice(&bytes).expect("error body is JSON");
        parsed["error"]["message"]
            .as_str()
            .expect("refusal carries a message")
            .to_string()
    }

    let gemini_body = serde_json::json!({
        "contents": [{ "role": "user", "parts": [{ "text": "hi" }] }],
    });
    let cc_body = serde_json::json!({
        "model": "gpt-4o",
        "messages": [{ "role": "user", "content": "hi" }],
    });

    // Both the request/response verb and the streaming one — the SDK puts
    // `alt=sse` ahead of the key on the streaming form, so the parameter is not
    // at the head of the query string there.
    for uri in [
        "/v1beta/models/gemini-2.5-flash:generateContent?key=sk-does-not-exist",
        "/v1beta/models/gemini-2.5-flash:streamGenerateContent?alt=sse&key=sk-does-not-exist",
    ] {
        let message = refusal_message(&rig, uri, gemini_body.clone()).await;
        assert!(
            message.contains("invalid API key"),
            "the `?key=` credential must reach the key lookup on {uri}, got {message:?}"
        );
    }

    // A Gemini request with NO credential at all is the control for the control:
    // it must still refuse as missing, or the assertion above proves nothing.
    let message = refusal_message(
        &rig,
        "/v1beta/models/gemini-2.5-flash:generateContent",
        gemini_body.clone(),
    )
    .await;
    assert!(
        message.contains("missing authorization header"),
        "a Gemini request with no credential is missing one, got {message:?}"
    );

    // …and the same parameter on a protocol whose spec never defined it is not
    // a credential — the request is refused as having presented none.
    let message =
        refusal_message(&rig, "/v1/chat/completions?key=sk-does-not-exist", cc_body).await;
    assert!(
        message.contains("missing authorization header"),
        "`?key=` is Gemini's spelling and must not authenticate elsewhere, got {message:?}"
    );
}

/// The BYOK forwarding family (`/fwd/{key}/…`) carries the gateway key in the
/// PATH rather than a header, and forwards the caller's *own* upstream credential
/// onward. That makes its fence load-bearing in the same way the catch-all's is: a
/// `/fwd/…` route that skipped the key check would be an open relay to the
/// upstream. The whole family — the LLM protocols, Gemini, media, the catch-all,
/// and the MCP mount — is refused when the path key resolves to nothing.
#[tokio::test]
async fn the_byok_forward_surface_is_fenced() {
    let rig = rig();

    for uri in [
        "/fwd/sk-does-not-exist/v1/chat/completions",
        "/fwd/sk-does-not-exist/v1/responses",
        "/fwd/sk-does-not-exist/v1/messages",
        "/fwd/sk-does-not-exist/v1beta/models/gemini-2.5-flash:generateContent",
        "/fwd/sk-does-not-exist/v1/embeddings",
        "/fwd/sk-does-not-exist/v1/images/generations",
        // The BYOK catch-all — an unmatched /fwd/{key}/v1/* path.
        "/fwd/sk-does-not-exist/v1/some/unmatched/passthrough",
        "/fwd/sk-does-not-exist/mcp/web",
    ] {
        let resp = rig
            .app
            .clone()
            .oneshot(json_post(uri, None))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{uri} must not forward on an unresolvable key"
        );
    }
}

/// The MCP gateway mount is reachable and behind the same fence.
#[tokio::test]
async fn the_mcp_mount_is_reachable_and_authenticated() {
    let rig = rig();
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/mcp/web")
                .header("content-type", "application/json")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "tools/list",
                    })
                    .to_string(),
                ))
                .expect("well-formed request"),
        )
        .await
        .expect("router responds");

    // Mounted (not a 404) and refused (not served).
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

// ---------------------------------------------------------------------------
// Probes + scrape-surface isolation
// ---------------------------------------------------------------------------

/// `/health` is liveness — 200 while the process is up, config or not. `/ready`
/// tracks "config loaded": 503 on a freshly-booted replica, 200 once a snapshot
/// lands. An orchestrator must not route traffic to a proxy that cannot yet
/// resolve a key.
///
/// The liveness body is a bare `status`: it is served unauthenticated on the
/// public vhost, so it must disclose no version or component detail.
#[tokio::test]
async fn readiness_tracks_config_loaded_while_liveness_does_not() {
    let rig = rig();

    let health = rig
        .app
        .clone()
        .oneshot(Request::builder().uri("/health").body(Body::empty()).unwrap())
        .await
        .expect("router responds");
    assert_eq!(health.status(), StatusCode::OK);
    let body = axum::body::to_bytes(health.into_body(), 1 << 20)
        .await
        .expect("read body");
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&body).expect("liveness body is JSON"),
        serde_json::json!({ "status": "healthy" }),
        "liveness must disclose nothing beyond its status"
    );

    let before = rig
        .app
        .clone()
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
        .await
        .expect("router responds");
    assert_eq!(
        before.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "a proxy without config must not be declared ready"
    );

    rig.state
        .config_ready
        .store(true, std::sync::atomic::Ordering::Relaxed);

    let after = rig
        .app
        .oneshot(Request::builder().uri("/ready").body(Body::empty()).unwrap())
        .await
        .expect("router responds");
    assert_eq!(after.status(), StatusCode::OK);
}

/// The A2A JSON-RPC mount is fenced like every other data-plane route: no
/// key ⇒ 401, never a 404 (which would mean the mount vanished) and never a
/// served response.
#[tokio::test]
async fn the_a2a_mount_is_reachable_and_authenticated() {
    let rig = rig();
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/a2a/echo")
                .header("content-type", "application/json")
                .header("a2a-version", "1.0")
                .body(Body::from(
                    serde_json::json!({
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "SendMessage",
                        "params": {},
                    })
                    .to_string(),
                ))
                .expect("well-formed request"),
        )
        .await
        .expect("router responds");

    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    assert_auth_error(resp, ApiVersion::ChatCompletions).await;
}

/// The agent card is served pre-auth (a client needs the card to learn WHICH
/// credential to present), at BOTH well-known filenames. With an empty tenant
/// registry no slug resolves, so the mounted route answers 404 — the point is
/// that it is mounted and does not demand a key.
#[tokio::test]
async fn the_a2a_agent_card_is_public_on_both_well_known_paths() {
    for path in [
        "/a2a/echo/.well-known/agent-card.json",
        "/a2a/echo/.well-known/agent.json",
    ] {
        let rig = rig();
        let resp = rig
            .app
            .oneshot(Request::builder().uri(path).body(Body::empty()).unwrap())
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::NOT_FOUND,
            "{path} must be mounted and public (unknown slug ⇒ 404, never 401)"
        );
    }
}

// ---------------------------------------------------------------------------
// The public-metadata throttle — the only ceiling on the pre-auth surfaces
// ---------------------------------------------------------------------------

/// Every discovery request in this section carries an `X-Forwarded-For`, because
/// that is how the limiter gets a key: under the default one-hop trust model the
/// rightmost entry is the client. A request with no forwarding header and no
/// `ConnectInfo` has no attributable source and is deliberately passed through.
fn metadata_get(path: &str, source_ip: &str) -> Request<Body> {
    Request::builder()
        .uri(path)
        .header("x-forwarded-for", source_ip)
        .body(Body::empty())
        .expect("well-formed request")
}

/// One limiter spans BOTH discovery documents. Budget per surface would let a
/// caller throttled on the agent card move to the MCP metadata endpoint for a
/// fresh one, which is the same registry scan under a different path.
#[tokio::test]
async fn the_public_metadata_throttle_is_shared_across_both_surfaces() {
    let rig = rig_with_metadata_cap(2);
    let paths = [
        "/a2a/echo/.well-known/agent-card.json",
        "/.well-known/oauth-protected-resource/mcp/echo",
    ];

    // Two requests, one per surface, exhaust the shared cap of 2. Neither is
    // throttled, and with an empty registry both stop at 404 (the pre-auth
    // mount's normal answer for an unknown slug).
    for path in paths {
        let resp = rig
            .app
            .clone()
            .oneshot(metadata_get(path, "203.0.113.7"))
            .await
            .expect("router responds");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{path} is under the cap");
    }

    // The third request from that source is refused on EITHER surface.
    for path in paths {
        let resp = rig
            .app
            .clone()
            .oneshot(metadata_get(path, "203.0.113.7"))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{path} must share the exhausted budget, not hold its own"
        );
    }

    // A different source is untouched — otherwise one scanner takes discovery
    // offline for every other client behind every other address.
    let resp = rig
        .app
        .clone()
        .oneshot(metadata_get(paths[0], "198.51.100.4"))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// The throttle is mounted with `route_layer`, so it must charge only these two
/// routes. A source that has exhausted its discovery budget still gets liveness,
/// readiness and the ordinary data plane — a limiter that leaked onto them would
/// turn a scan of a public document into an outage.
#[tokio::test]
async fn the_throttle_charges_only_the_discovery_routes() {
    let rig = rig_with_metadata_cap(1);
    let exhaust = rig
        .app
        .clone()
        .oneshot(metadata_get(
            "/.well-known/oauth-protected-resource/mcp/echo",
            "203.0.113.7",
        ))
        .await
        .expect("router responds");
    assert_eq!(exhaust.status(), StatusCode::NOT_FOUND);

    let throttled = rig
        .app
        .clone()
        .oneshot(metadata_get(
            "/.well-known/oauth-protected-resource/mcp/echo",
            "203.0.113.7",
        ))
        .await
        .expect("router responds");
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // Same source, other routes: liveness answers, and the data plane still
    // refuses on its own terms (401, not 429).
    let health = rig
        .app
        .clone()
        .oneshot(metadata_get("/health", "203.0.113.7"))
        .await
        .expect("router responds");
    assert_eq!(health.status(), StatusCode::OK, "liveness is never throttled");

    let mut chat = json_post("/v1/chat/completions", None);
    chat.headers_mut()
        .insert("x-forwarded-for", "203.0.113.7".parse().unwrap());
    let chat = rig.app.clone().oneshot(chat).await.expect("router responds");
    assert_eq!(
        chat.status(),
        StatusCode::UNAUTHORIZED,
        "the data plane answers on its own terms, not the discovery throttle's"
    );
}

/// With no forwarding header the key is the real TCP peer, which only exists
/// because the serve site mounts with `into_make_service_with_connect_info`.
/// That wiring is load-bearing and otherwise invisible: the middleware passes a
/// request through when it can find no source, so a serve-site refactor back to
/// a plain `into_make_service` would silently disable the limiter for every
/// directly-reached request — and passing-through is indistinguishable from
/// not-counting in every other test here, all of which supply an
/// `X-Forwarded-For`.
#[tokio::test]
async fn with_no_forwarding_header_the_throttle_keys_on_the_tcp_peer() {
    let rig = rig_with_metadata_cap(1);
    let peer_get = |ip: [u8; 4]| {
        let mut req = Request::builder()
            .uri("/a2a/echo/.well-known/agent-card.json")
            .body(Body::empty())
            .expect("well-formed request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 4242))));
        req
    };

    let first = rig
        .app
        .clone()
        .oneshot(peer_get([203, 0, 113, 7]))
        .await
        .expect("router responds");
    assert_eq!(first.status(), StatusCode::NOT_FOUND, "the first is under the cap");

    let second = rig
        .app
        .clone()
        .oneshot(peer_get([203, 0, 113, 7]))
        .await
        .expect("router responds");
    assert_eq!(
        second.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the peer address must be a usable limiter key on its own"
    );

    // A different peer keeps its own budget — the key is the address, not a
    // single global counter that happens to be full.
    let other = rig
        .app
        .clone()
        .oneshot(peer_get([198, 51, 100, 4]))
        .await
        .expect("router responds");
    assert_eq!(other.status(), StatusCode::NOT_FOUND);
}

/// A cap of 0 means "disabled", not "refuse everything". Without the
/// short-circuit every source sits at a cap of 0 from its first request and the
/// documents a client needs in order to authenticate become unreachable.
#[tokio::test]
async fn a_zero_cap_disables_the_throttle_rather_than_closing_it() {
    let rig = rig_with_metadata_cap(0);
    for _ in 0..5 {
        let resp = rig
            .app
            .clone()
            .oneshot(metadata_get(
                "/a2a/echo/.well-known/agent-card.json",
                "203.0.113.7",
            ))
            .await
            .expect("router responds");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "0 disables the limiter");
    }
}

/// The Prometheus exposition rides its own `METRICS_PORT` listener. The main port
/// is reverse-proxied by the public Caddy vhosts unauthenticated, so a `/metrics`
/// route mounted here would be internet-reachable.
#[tokio::test]
async fn metrics_are_not_exposed_on_the_main_port() {
    let rig = rig();
    let resp = rig
        .app
        .oneshot(
            Request::builder()
                .uri("/metrics")
                .body(Body::empty())
                .unwrap(),
        )
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}
