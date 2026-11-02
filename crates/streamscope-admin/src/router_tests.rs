//! In-process tests over the REAL admin-api router.
//!
//! These build the production surface through [`crate::build_app`] — the same
//! construction `bring_up` serves — and drive it with `tower::ServiceExt::oneshot`.
//! They cover the wiring between axum and our middleware: mount points, layer
//! order, the auth fence, fail-closed CORS, the per-IP flood cap, and the
//! liveness/readiness split. A dropped layer or a mis-nested router fails here in
//! a sub-second `cargo test` instead of surfacing (if at all) in the ~13-minute
//! E2E run.
//!
//! **The pool is deliberately dead.** `AdminState` is built over a lazily-connected
//! pool pointed at a closed port, so any query fails immediately. That is what
//! makes the assertions sharp: a 401 proves the request was rejected by middleware
//! *before* the DB was ever touched — had it reached a handler, the dead pool would
//! surface as a 5xx. It also means the *positive* auth path (a signature-valid JWT
//! is accepted) is NOT testable here — verifying a token ends in a `tenants` lookup.
//! That path stays in the E2E suite; this tier owns the rejection matrix and the
//! layer wiring.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, Request, StatusCode};
use tower::ServiceExt;

use crate::db::Db;
use streamscope_core::middleware::ip_rate_limit::RateLimiter;
use crate::{build_app, metrics, AdminState,
            PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD};

/// An `AdminState` over a dead pool. `pre_auth_ip_cap` is the per-source-IP
/// request cap (the production value comes from settings; tests pin a small one
/// so the flood cap is reachable in a handful of requests).
fn test_state(pre_auth_ip_cap: u32) -> Arc<AdminState> {
    test_state_with_caps(pre_auth_ip_cap, 0, 0)
}

fn test_state_with_caps(
    pre_auth_ip_cap: u32,
    automation_key_cap: u32,
    automation_key_ip_cap: u32,
) -> Arc<AdminState> {
    Arc::new(AdminState {
        db: Db::unreachable_for_test(),
        instance_id: uuid::Uuid::new_v4(),
        login_rate_limiter: RateLimiter::new(10, 300, 100),
        invite_rate_limiter: RateLimiter::new(10, 300, 100),
        pre_auth_ip_rate_limiter: RateLimiter::per_instance(
            pre_auth_ip_cap,
            300,
            PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD,
            1,
        ),
        automation_key_rate_limiter: RateLimiter::per_instance(
            automation_key_cap,
            300,
            PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD,
            1,
        ),
        automation_key_ip_rate_limiter: crate::middleware::DistinctKeyFailures::new(
            automation_key_ip_cap,
            300,
            PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD,
            1,
        ),
        http_client: reqwest::Client::new(),
        cors_allowlist: arc_swap::ArcSwap::from_pointee(std::collections::HashSet::new()),
    })
}

fn router(state: Arc<AdminState>) -> axum::Router {
    build_app(state, Arc::new(metrics::AdminMetrics::new()))
}

/// A request carrying `ConnectInfo` — axum's `into_make_service_with_connect_info`
/// supplies it in production; `oneshot` does not, and the per-IP limiter resolves
/// its key from it.
fn request(method: &str, uri: &str) -> Request<Body> {
    let mut req = Request::builder()
        .method(method)
        .uri(uri)
        .body(Body::empty())
        .expect("well-formed request");
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))));
    req
}

async fn body_json(resp: axum::response::Response) -> serde_json::Value {
    let bytes = axum::body::to_bytes(resp.into_body(), 1 << 20)
        .await
        .expect("read body");
    serde_json::from_slice(&bytes).unwrap_or(serde_json::Value::Null)
}

// ---------------------------------------------------------------------------
// The auth fence
// ---------------------------------------------------------------------------

/// Every route on both authenticated planes — admin and portal, read AND
/// mutating — is behind its plane's auth middleware. An unauthenticated request
/// is rejected with 401 without reaching a handler (and therefore without
/// touching the DB, which is dead here: a handler would 5xx).
#[tokio::test]
async fn unauthenticated_requests_are_rejected_before_any_handler() {
    let app = router(test_state(0));

    for (method, path) in [
        ("GET", "/api/v1/admin/users"),
        ("POST", "/api/v1/admin/users"),
        ("GET", "/api/v1/admin/keys"),
        ("POST", "/api/v1/admin/keys"),
        ("GET", "/api/v1/admin/tenants/acme"),
        ("DELETE", "/api/v1/admin/tenants/acme"),
        ("GET", "/api/v1/admin/global/analytics/overview"),
        ("GET", "/api/v1/portal/auth/me"),
        ("GET", "/api/v1/portal/sessions"),
        ("GET", "/api/v1/portal/audit"),
        ("GET", "/api/v1/portal/audit/00000000-0000-0000-0000-000000000000"),
        (
            "GET",
            "/api/v1/portal/sessions/00000000-0000-0000-0000-000000000000/conversation",
        ),
    ] {
        let resp = app
            .clone()
            .oneshot(request(method, path))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{method} {path} must be behind the auth fence"
        );
    }
}

/// The credential shapes `admin_auth` must reject. None of these can reach the
/// DB: a non-`Bearer` scheme and a non-`ak-`, non-JWT bearer are refused on
/// inspection, and a JWT-shaped token fails signature verification first.
#[tokio::test]
async fn malformed_credentials_are_rejected_with_401() {
    let app = router(test_state(0));

    for (label, value) in [
        ("basic auth", "Basic dXNlcjpwYXNz"),
        ("bare token, no scheme", "sk-not-a-scheme"),
        ("bearer garbage", "Bearer not-a-token"),
        ("bearer empty", "Bearer "),
        (
            "bearer JWT-shaped but unsigned-for-us",
            "Bearer eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJub3QtYS11dWlkIn0.c2ln",
        ),
    ] {
        let mut req = request("GET", "/api/v1/admin/users");
        req.headers_mut()
            .insert(header::AUTHORIZATION, value.parse().expect("header value"));

        let resp = app.clone().oneshot(req).await.expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::UNAUTHORIZED,
            "{label} must not authenticate"
        );
    }
}

// ---------------------------------------------------------------------------
// Liveness vs readiness (load-bearing: every readiness consumer polls /ready)
// ---------------------------------------------------------------------------

/// `/health` is liveness — always 200, never a dependency check, so a Postgres
/// blip can't restart-storm the fleet. `/ready` is readiness — 503 while the DB
/// is unreachable. The dead pool makes the distinction observable.
///
/// Both bodies are a bare `status`: these probes are served unauthenticated on
/// the public vhost, so they must disclose no version or component detail to
/// fingerprint. Consumers gate on the 200/503 alone.
#[tokio::test]
/// The wiring only: `/ready` answers a bare 503 while the replica cannot serve
/// (here no Postgres and no edge cache). Which dependency decides is
/// `readiness` itself, locked on both sides by
/// `a_replica_is_ready_only_with_postgres_up_and_its_edge_cache_built`.
async fn health_is_liveness_only_and_ready_is_closed_while_unservable() {
    let app = router(test_state(0));

    let health = app
        .clone()
        .oneshot(request("GET", "/health"))
        .await
        .expect("router responds");
    assert_eq!(health.status(), StatusCode::OK, "liveness must not probe PG");
    assert_eq!(
        body_json(health).await,
        serde_json::json!({ "status": "alive" }),
        "liveness must disclose nothing beyond its status"
    );

    let ready = app
        .clone()
        .oneshot(request("GET", "/ready"))
        .await
        .expect("router responds");
    assert_eq!(
        ready.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "readiness must fail while the replica cannot serve"
    );
    assert_eq!(
        body_json(ready).await,
        serde_json::json!({ "status": "not_ready" }),
        "readiness must disclose nothing beyond its status"
    );
}

// ---------------------------------------------------------------------------
// Global layers: request-id, metrics isolation, method/route mapping
// ---------------------------------------------------------------------------

/// `request_id_mw` is the OUTERMOST layer, so every response carries the
/// correlation header — including ones short-circuited by inner middleware (401)
/// and ones that never matched a route (404). A caller-supplied id is echoed
/// back; otherwise one is minted.
#[tokio::test]
async fn every_response_carries_a_request_id() {
    let app = router(test_state(0));

    for (label, method, path) in [
        ("handler", "GET", "/health"),
        ("auth rejection", "GET", "/api/v1/admin/users"),
        ("unmatched route", "GET", "/nope"),
    ] {
        let resp = app
            .clone()
            .oneshot(request(method, path))
            .await
            .expect("router responds");
        let id = resp
            .headers()
            .get("x-request-id")
            .unwrap_or_else(|| panic!("{label}: response must carry x-request-id"));
        uuid::Uuid::parse_str(id.to_str().expect("ascii header"))
            .unwrap_or_else(|_| panic!("{label}: x-request-id must be a UUID"));
    }

    // A caller-supplied correlation id survives the round trip.
    let supplied = uuid::Uuid::new_v4().to_string();
    let mut req = request("GET", "/health");
    req.headers_mut()
        .insert("x-request-id", supplied.parse().expect("header value"));
    let resp = app.oneshot(req).await.expect("router responds");
    assert_eq!(
        resp.headers().get("x-request-id").expect("header present"),
        supplied.as_str()
    );
}

/// The Prometheus exposition rides its own `METRICS_PORT` listener and must NOT
/// be reachable on the main port — the public vhosts reverse-proxy the whole main
/// port unauthenticated, so a `/metrics` route here would be internet-reachable.
#[tokio::test]
async fn metrics_are_not_exposed_on_the_main_port() {
    let app = router(test_state(0));
    let resp = app
        .oneshot(request("GET", "/metrics"))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::NOT_FOUND);
}

/// A known path with an unsupported method maps to 405, not 404 — i.e. the route
/// is mounted and axum's method fallback is intact.
#[tokio::test]
async fn wrong_method_on_a_known_path_is_405() {
    let app = router(test_state(0));
    let resp = app
        .oneshot(request("DELETE", "/health"))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::METHOD_NOT_ALLOWED);
}

/// The OpenAPI surface is mounted iff `API_DOCS_PUBLIC` is on — the Kairos prod
/// deploy turns it off so the public vhost 404s it. Asserted against the resolved
/// setting so the test is env-independent.
#[tokio::test]
async fn openapi_surface_follows_the_api_docs_public_setting() {
    let app = router(test_state(0));
    let resp = app
        .oneshot(request("GET", "/api/docs/openapi.json"))
        .await
        .expect("router responds");

    if crate::settings::admin_settings().api_docs_public {
        assert_eq!(resp.status(), StatusCode::OK);
    } else {
        assert_eq!(resp.status(), StatusCode::NOT_FOUND);
    }
}

// ---------------------------------------------------------------------------
// CORS — fail-closed until a tenant's origin is in the allowlist
// ---------------------------------------------------------------------------

/// The allowlist starts empty (it is populated from every tenant's resolved
/// `admin_public_url` by the sweeper). Until an origin is in it, the CORS layer
/// grants nothing; once it is, the origin is reflected back. A regression here
/// either locks every console out or opens the API to any origin.
#[tokio::test]
async fn cors_is_fail_closed_until_the_origin_is_allowlisted() {
    let origin = "https://console.example.com";

    let state = test_state(0);
    let denied = router(state.clone())
        .oneshot({
            let mut req = request("GET", "/health");
            req.headers_mut()
                .insert(header::ORIGIN, origin.parse().expect("header value"));
            req
        })
        .await
        .expect("router responds");
    assert!(
        denied
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .is_none(),
        "an unknown origin must not be granted CORS"
    );

    state
        .cors_allowlist
        .store(Arc::new(std::collections::HashSet::from([origin.to_string()])));

    let allowed = router(state)
        .oneshot({
            let mut req = request("GET", "/health");
            req.headers_mut()
                .insert(header::ORIGIN, origin.parse().expect("header value"));
            req
        })
        .await
        .expect("router responds");
    assert_eq!(
        allowed
            .headers()
            .get(header::ACCESS_CONTROL_ALLOW_ORIGIN)
            .expect("allowlisted origin must be granted CORS"),
        origin
    );
}

// ---------------------------------------------------------------------------
// Per-source-IP flood cap on the pre-auth surface
// ---------------------------------------------------------------------------

/// `pre_auth_ip_rate_limit_mw` is the outermost layer on the public routers, so a
/// flood is throttled per source IP before any handler (and before
/// `security_audit_mw` could amplify it into audit rows). The limiter keys on the
/// client IP: a second IP is unaffected by the first one's exhausted budget.
#[tokio::test]
async fn pre_auth_surface_is_capped_per_source_ip() {
    let app = router(test_state(2));
    let public = "/api/v1/cli/version";

    // Under the cap: whatever the handler returns, it is not a throttle.
    for i in 0..2 {
        let resp = app
            .clone()
            .oneshot(request("GET", public))
            .await
            .expect("router responds");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "request {i} is within the cap"
        );
    }

    // Over the cap: throttled, with the machine-readable code the UI branches on.
    let throttled = app
        .clone()
        .oneshot(request("GET", public))
        .await
        .expect("router responds");
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        body_json(throttled).await["error"]["code"],
        "rate_limit_exceeded"
    );

    // A different source IP has its own budget.
    let mut other = Request::builder()
        .method("GET")
        .uri(public)
        .body(Body::empty())
        .expect("well-formed request");
    other
        .extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 2], 4242))));
    let resp = app.oneshot(other).await.expect("router responds");
    assert_ne!(
        resp.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the cap must key on the source IP, not be global"
    );
}

/// An organisation's sign-in facts are bounded per visitor and by nothing an
/// organisation's visitors share: many visitors each under the cap all get an
/// answer however many there are (a budget keyed by the organisation alone let
/// any of them — or a health probe — lock everyone's sign-in), and one visitor
/// past the cap is refused.
#[tokio::test]
async fn auth_info_is_capped_per_visitor_and_never_per_organisation() {
    let app = router(test_state(2));
    let path = "/api/v1/tenants/acme/auth-info";
    let from = |last: u8| {
        let mut req = Request::builder()
            .method("GET")
            .uri(path)
            .body(Body::empty())
            .expect("well-formed request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([10, 0, 0, last], 4242))));
        req
    };
    for visitor in 1..=40u8 {
        let resp = app.clone().oneshot(from(visitor)).await.expect("router responds");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "visitor {visitor} of the same organisation is refused by a budget it never used"
        );
    }
    for _ in 0..2 {
        let resp = app.clone().oneshot(from(41)).await.expect("router responds");
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "within one visitor's cap");
    }
    let throttled = app.oneshot(from(41)).await.expect("router responds");
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS, "one visitor past its cap");
}

/// An IPv6 source is charged by its /64: a host rotating through the addresses of
/// its network spends one budget, and the next network has its own (the
/// positive control: the cap is not simply global).
#[tokio::test]
async fn pre_auth_cap_charges_an_ipv6_source_by_its_64() {
    let app = router(test_state(2));
    let public = "/api/v1/cli/version";
    let from = |ip: std::net::Ipv6Addr| {
        let mut req = Request::builder()
            .method("GET")
            .uri(public)
            .body(Body::empty())
            .expect("well-formed request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from((ip, 4242))));
        req
    };
    let net = |host: u16| std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 1, 0, 0, 0, host);
    for host in 1..=2 {
        let resp = app.clone().oneshot(from(net(host))).await.expect("router responds");
        assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "host {host} is within the cap");
    }
    let rotated = app.clone().oneshot(from(net(3))).await.expect("router responds");
    assert_eq!(
        rotated.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a third address in the same /64 is the same source"
    );
    let next = std::net::Ipv6Addr::new(0x2001, 0xdb8, 0, 2, 0, 0, 0, 1);
    let resp = app.oneshot(from(next)).await.expect("router responds");
    assert_ne!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "the next /64 has its own budget");
}

/// The per-request session checks are NOT charged to the pre-auth cap.
///
/// The browser tier calls `/auth/me` once for every console request, so a cap
/// sized for anonymous sign-in traffic turned a few dashboard refreshes into 429
/// for everybody. The positive control is the sign-in surface beside it in the
/// same state: it must still throttle, or the first half proves nothing.
#[tokio::test]
async fn session_checks_are_not_charged_to_the_pre_auth_cap() {
    let app = router(test_state(2));

    for i in 0..5 {
        let resp = app
            .clone()
            .oneshot(request("GET", "/api/v1/auth/me"))
            .await
            .expect("router responds");
        assert_ne!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "/api/v1/auth/me request {i} must not be counted against the pre-auth cap"
        );
    }

    for _ in 0..2 {
        app.clone()
            .oneshot(request("GET", "/api/v1/auth/setup/status"))
            .await
            .expect("router responds");
    }
    let throttled = app
        .clone()
        .oneshot(request("GET", "/api/v1/auth/setup/status"))
        .await
        .expect("router responds");
    assert_eq!(
        throttled.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "the sign-in surface beside it must still be capped"
    );
}

/// `/portal/auth/header-me` exists only in one of its two roles — the
/// per-request check under header auth, or the claim exchange when a
/// deployment turns it on. This binary runs standard auth with the exchange
/// off, so the path must answer like one that was never there: 404 to every
/// method and to a burst, never a 405 naming its methods or a 429 from a cap.
/// The positive control is `/api/v1/auth/setup/status`, which a burst does
/// throttle in the same state.
#[tokio::test]
async fn a_switched_off_header_me_cannot_be_told_from_an_absent_path() {
    let app = router(test_state(2));
    for method in ["GET", "POST", "GET", "GET", "GET"] {
        let resp = app
            .clone()
            .oneshot(request(method, "/api/v1/portal/auth/header-me"))
            .await
            .expect("router responds");
        assert_eq!(resp.status(), StatusCode::NOT_FOUND, "{method} header-me must be absent");
    }
    for _ in 0..2 {
        app.clone()
            .oneshot(request("GET", "/api/v1/auth/setup/status"))
            .await
            .expect("router responds");
    }
    let throttled = app
        .oneshot(request("GET", "/api/v1/auth/setup/status"))
        .await
        .expect("router responds");
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS, "the cap is live in this state");
}

#[test]
fn header_me_is_mounted_in_either_role_and_only_then() {
    assert!(crate::routes::header_me_is_mounted(true, false));
    assert!(crate::routes::header_me_is_mounted(false, true));
    assert!(crate::routes::header_me_is_mounted(true, true));
    assert!(!crate::routes::header_me_is_mounted(false, false));
}

/// An authenticated `ak-` automation key is capped per key, on both planes.
///
/// The pre-auth IP limiter cannot reach these: an automation key authenticates,
/// so it lands on the guarded routers, which carry no limiter of their own. The
/// cap is keyed on the presented key rather than the caller's IP — a leaked key
/// is throttled wherever it is used from, and one key exhausting its budget
/// leaves every other key untouched.
///
/// The dead pool is what makes the ordering observable: the check runs before
/// the cross-tenant lookup, so the throttle answers 429 on a key that could
/// never have resolved anyway.
#[tokio::test]
async fn automation_keys_are_capped_per_key_on_both_planes() {
    let state = test_state_with_caps(0, 2, 0);
    // Only a key that AUTHENTICATED is charged to the budget — junk tokens must
    // not be able to fill the limiter's map with attacker-chosen entries — and
    // the dead pool can authenticate nothing. So seed the bucket exactly as two
    // successful requests would have, then assert on what the middleware does
    // with a key already at its cap.
    let spent = streamscope_core::auth::virtual_key::hash_key("ak-leaked");
    state.automation_key_rate_limiter.record_failure(&spent);
    state.automation_key_rate_limiter.record_failure(&spent);
    let app = router(state);

    let with_key = |path: &str, key: &str| {
        let mut req = request("GET", path);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {key}").parse().expect("header value"),
        );
        req
    };

    // At its cap: throttled before the lookup, rather than rejected as unknown.
    let throttled = app
        .clone()
        .oneshot(with_key("/api/v1/admin/users", "ak-leaked"))
        .await
        .expect("router responds");
    assert_eq!(throttled.status(), StatusCode::TOO_MANY_REQUESTS);

    // The budget follows the key across planes — the same key is already spent
    // on the portal plane, which shares the limiter.
    let portal = app
        .clone()
        .oneshot(with_key("/api/v1/portal/sessions", "ak-leaked"))
        .await
        .expect("router responds");
    assert_eq!(portal.status(), StatusCode::TOO_MANY_REQUESTS);

    // A different key has its own budget: the cap is per key, not global. It
    // reaches the lookup, which the dead pool answers as an outage.
    let other = app
        .clone()
        .oneshot(with_key("/api/v1/admin/users", "ak-innocent"))
        .await
        .expect("router responds");
    assert_eq!(
        other.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "one key's exhausted budget must not throttle another"
    );

    // A JWT-shaped bearer is a console session, not automation. It is neither
    // charged nor checked against the automation budget — a repeat run past the
    // cap still answers 401, where a counted credential would be throttled.
    for i in 0..3 {
        let session = app
            .clone()
            .oneshot(with_key(
                "/api/v1/admin/users",
                "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJub3QtYS11dWlkIn0.c2ln",
            ))
            .await
            .expect("router responds");
        assert_eq!(
            session.status(),
            StatusCode::UNAUTHORIZED,
            "session request {i} must not draw on the automation budget"
        );
    }
}

/// A prober who varies the key is bounded by SOURCE, which is the case the
/// per-key limiter above structurally cannot see.
///
/// Every attempt in this test presents a different `ak-`, so the per-key
/// limiter draws a fresh bucket each time and never fires — yet each attempt
/// would drive a full O(tenants) resolve scan. The per-source layer is what
/// stops that, and it sits outside the auth middleware so a throttled source is
/// refused before any of the work happens.
///
/// Driven through the real router: the dead pool makes auth answer each key
/// with its marked 503 (a key it could not accept, charged like a refusal), and
/// once at the cap the answer turns to 429 (never reached auth).
#[tokio::test]
async fn varying_the_key_is_still_bounded_by_source_ip() {
    // Two distinct failed keys per source, so the third is refused.
    let state = test_state_with_caps(0, 0, 2);
    let app = router(state);

    let probe = |path: &str, key: &str, ip: &str| {
        let mut req = request("GET", path);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {key}").parse().expect("header value"),
        );
        req.headers_mut()
            .insert("x-forwarded-for", ip.parse().expect("header value"));
        req
    };

    // A different key every time — nothing the per-key limiter can count.
    for i in 0..2 {
        let resp = app
            .clone()
            .oneshot(probe("/api/v1/admin/users", &format!("ak-guess-{i}"), "203.0.113.9"))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "attempt {i} is under the cap and must reach authentication"
        );
    }

    let throttled = app
        .clone()
        .oneshot(probe("/api/v1/admin/users", "ak-guess-2", "203.0.113.9"))
        .await
        .expect("router responds");
    assert_eq!(
        throttled.status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a source past its failed-auth cap must be refused before the tenant scan"
    );

    // Every guarded router carries the layer, and they share one budget — a
    // prober cannot switch planes, or reach for a super-admin surface, to get a
    // fresh one. Each path here is a DIFFERENT mount: dropping the layer from
    // any one of them must fail this test.
    for path in [
        "/api/v1/portal/sessions",              // portal_routes
        "/api/v1/admin/tenants",                // tenant_routes
        "/api/v1/admin/global/analytics/overview", // super_admin_global
        "/api/v1/admin/edge-nodes",             // edge_admin_routes
    ] {
        let resp = app
            .clone()
            .oneshot(probe(path, "ak-guess-3", "203.0.113.9"))
            .await
            .expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::TOO_MANY_REQUESTS,
            "{path} must carry the per-source throttle"
        );
    }

    // Another source is untouched: the cap is per source, not global. Without
    // this the limiter would be a denial-of-service primitive — one prober
    // could lock every automation client out of the deployment.
    let elsewhere = app
        .clone()
        .oneshot(probe("/api/v1/admin/users", "ak-guess-4", "198.51.100.4"))
        .await
        .expect("router responds");
    assert_eq!(
        elsewhere.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "one source's exhausted budget must not throttle another"
    );

    // A console session from the throttled source still gets through. Browser
    // traffic reaches admin-api from the UI tier's single IP, so counting
    // session 401s here would let one expired tab throttle every user.
    let session = app
        .clone()
        .oneshot(probe(
            "/api/v1/admin/users",
            "eyJhbGciOiJIUzI1NiJ9.eyJhdWQiOiJ4In0.c2ln",
            "203.0.113.9",
        ))
        .await
        .expect("router responds");
    assert_eq!(
        session.status(),
        StatusCode::UNAUTHORIZED,
        "a session must not be throttled by an automation-key prober sharing its IP"
    );
}

/// One key repeated is one key: a client left running with a revoked or
/// mistyped credential must not throttle the address it shares with everybody
/// else at its site.
///
/// The counterpart to the varied-key case above, through the same router, so it
/// is the mounted middleware being measured and not the limiter in isolation.
#[tokio::test]
async fn one_repeated_key_does_not_throttle_its_source() {
    let state = test_state_with_caps(0, 0, 2);
    let app = router(state);

    for i in 0..20 {
        let mut req = request("GET", "/api/v1/admin/users");
        req.headers_mut().insert(
            header::AUTHORIZATION,
            "Bearer ak-one-stale-key".parse().expect("header value"),
        );
        req.headers_mut()
            .insert("x-forwarded-for", "203.0.113.9".parse().expect("header value"));
        let resp = app.clone().oneshot(req).await.expect("router responds");
        assert_eq!(
            resp.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "attempt {i} with the SAME key must never be throttled"
        );
    }
}

/// What charges the per-source throttle: a key the auth layer did not accept —
/// a 401, or the 503 it marks `AutomationKeyUnverified` (it could not look the
/// key up). A handler's own 503 is never charged: that caller's key
/// authenticated. The inner handler is a stub, so this is the mounted
/// middleware's own decision.
#[tokio::test]
async fn the_source_throttle_charges_only_keys_auth_did_not_accept() {
    use axum::extract::Path;
    use axum::response::IntoResponse;
    let state = test_state_with_caps(0, 0, 2);
    let app = axum::Router::new()
        .route(
            "/answer/{status}",
            axum::routing::get(|Path(status): Path<u16>| async move {
                StatusCode::from_u16(status).expect("valid status")
            }),
        )
        .route(
            "/unverified",
            axum::routing::get(|| async {
                let mut resp = StatusCode::SERVICE_UNAVAILABLE.into_response();
                resp.extensions_mut().insert(crate::middleware::AutomationKeyUnverified);
                resp
            }),
        )
        .layer(axum::middleware::from_fn_with_state(
            state,
            crate::middleware::automation_key_ip_rate_limit_mw,
        ));
    let call = |path: &str, key: &str| {
        let mut req = request("GET", path);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {key}").parse().expect("header value"),
        );
        app.clone().oneshot(req)
    };

    // A handler's own 503 for many distinct keys: none is charged.
    for i in 0..10 {
        let resp = call("/answer/503", &format!("ak-authenticated-{i}")).await.expect("responds");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "handler 503 {i} is not throttled");
    }
    // One refused key and one unverified key: two distinct keys, the cap.
    assert_eq!(call("/answer/401", "ak-refused").await.expect("responds").status(), StatusCode::UNAUTHORIZED);
    assert_eq!(call("/unverified", "ak-unverified").await.expect("responds").status(), StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        call("/answer/401", "ak-third").await.expect("responds").status(),
        StatusCode::TOO_MANY_REQUESTS,
        "a refusal and an unverified key must both charge the source"
    );
}

/// An `ak-` key the database could not be asked about is a 503
/// `maintenance_in_progress` on both planes — never the 401 that automation
/// reads as a revoked key. The dead pool IS the outage.
#[tokio::test]
async fn an_outage_never_reads_as_a_revoked_automation_key() {
    let app = router(test_state(1000));
    for path in ["/api/v1/admin/users", "/api/v1/portal/sessions"] {
        let mut req = request("GET", path);
        req.headers_mut()
            .insert(header::AUTHORIZATION, "Bearer ak-live-key".parse().expect("header value"));
        let resp = app.clone().oneshot(req).await.expect("router responds");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        assert_eq!(body_json(resp).await["error"]["code"], "maintenance_in_progress", "{path}");
    }
}

/// Sign-in during an outage is a 503, never "invalid credentials" or "no such
/// tenant": both are claims about the user's input that nothing checked.
#[tokio::test]
async fn an_outage_never_reads_as_bad_credentials_or_a_missing_tenant() {
    // SAFETY: every writer in this test binary stores this same value and all
    // env access here goes through Rust std (no FFI readers).
    unsafe {
        std::env::set_var("AUTH_SECRET", "test-router-auth-secret-long-enough-for-hs256");
    }
    // Positive control: sign-in is configured, so a 503 here is not the
    // keyring check's own "authentication not configured".
    assert!(crate::routes::admin_auth::keyring().is_some(), "AUTH_SECRET must configure sign-in");
    let app = router(test_state(1000));
    let login = serde_json::json!({"tenant_slug": "acme", "email": "a@corp.test", "password": "pw"});
    for path in ["/api/v1/auth/login", "/api/v1/portal/auth/login"] {
        let resp = app.clone().oneshot(post_json(path, login.clone(), None)).await.expect("responds");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{path}");
        let body = body_json(resp).await;
        assert_eq!(body["error"]["code"], "maintenance_in_progress", "{path}");
        assert_eq!(
            body["error"]["message"], "the tenant could not be looked up",
            "{path}: the 503 is the slug lookup's, not an earlier check's"
        );
    }
}

/// The portal plane marks its `ak-` 503 for the source throttle as the admin
/// plane does: two distinct keys the portal could not check exhaust the cap of
/// two, and the next request — on either plane — is throttled.
#[tokio::test]
async fn the_portal_plane_charges_a_key_it_could_not_check() {
    let app = router(test_state_with_caps(0, 0, 2));
    let probe = |path: &str, key: &str| {
        let mut req = request("GET", path);
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {key}").parse().expect("header value"),
        );
        req.headers_mut()
            .insert("x-forwarded-for", "203.0.113.7".parse().expect("header value"));
        req
    };
    for i in 0..2 {
        let resp = app
            .clone()
            .oneshot(probe("/api/v1/portal/sessions", &format!("ak-portal-guess-{i}")))
            .await
            .expect("router responds");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "portal attempt {i} reaches auth");
    }
    let resp = app
        .clone()
        .oneshot(probe("/api/v1/admin/users", "ak-portal-guess-2"))
        .await
        .expect("router responds");
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS, "the portal's 503s must charge the source");
}

// ---------------------------------------------------------------------------
// The OIDC login surface
// ---------------------------------------------------------------------------

/// `/api/v2/edge/ingest` is mounted and refuses a request without a valid edge
/// token before its body is read (as do `/sync` and `/mcp-sse-replay`). The token check discriminates: a bearer
/// gets past it to the edge-node lookup, which fails on the dead pool (500) —
/// so the 401s are the check, not a route that refuses everything. A body
/// above axum's 2 MiB default is still read (the route raises the limit to
/// the ingest maximum) and only the one past that maximum is 413.
#[tokio::test]
async fn edge_ingest_is_mounted_behind_the_edge_token() {
    let uri = "/api/v2/edge/ingest";
    let body = serde_json::json!({ "instance": uuid::Uuid::nil(), "process_epoch": 1 });

    let resp = router(test_state(1000)).oneshot(post_json(uri, body.clone(), None)).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "no token");
    let resp = router(test_state(1000)).oneshot(post_json(uri, body.clone(), Some(""))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "empty bearer");
    let resp = router(test_state(1000)).oneshot(post_json(uri, body, Some("edge-token"))).await.unwrap();
    assert_eq!(resp.status(), StatusCode::INTERNAL_SERVER_ERROR, "a bearer reaches the lookup");

    // The token is checked before a byte of the body is read: a body past
    // every limit, sent with no token, is refused as unauthenticated — never
    // buffered to find out it is too large.
    for path in [uri, "/api/v2/edge/sync", "/api/v2/edge/mcp-sse-replay"] {
        let mut req = request("POST", path);
        *req.body_mut() = Body::from(vec![b' '; streamscope_edge_api::sync::SYNC_RESPONSE_MAX_BYTES + 1]);
        let resp = router(test_state(1000)).oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{path}: refused before its body is read");
    }
}

/// A request body, since the login endpoints are all POSTs.
fn post_json(uri: &str, body: serde_json::Value, bearer: Option<&str>) -> Request<Body> {
    let mut req = Request::builder()
        .method("POST")
        .uri(uri)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(body.to_string()))
        .expect("well-formed request");
    if let Some(token) = bearer {
        req.headers_mut().insert(
            header::AUTHORIZATION,
            format!("Bearer {token}").parse().expect("header value"),
        );
    }
    req.extensions_mut()
        .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))));
    req
}

/// The login endpoints are service-to-service: the shared secret is what lets a
/// request through to a handler at all. It proves *which service* is calling and
/// nothing about who is signing in — identity comes from the provider's
/// signature, checked inside the callback.
///
/// The secret is configured here on purpose. Left unset, every request is
/// refused by the "not configured" branch and the comparison is never reached —
/// so the test would pass just as happily with the comparison deleted. The
/// matching-bearer case is what makes the refusals mean something: it must get
/// *past* auth (and then fail on the dead pool, or on its own bogus arguments),
/// proving the check discriminates rather than refusing everything.
#[tokio::test]
async fn oidc_login_endpoints_require_the_service_secret() {
    const SECRET: &str = "test-internal-service-secret";
    // SAFETY: no other test in this binary reads `INTERNAL_SERVICE_SECRET`
    // (the auth-fence cases send no bearer, so they are refused a step earlier
    // either way), and all access here is through Rust std with no FFI reader.
    unsafe {
        std::env::set_var("INTERNAL_SERVICE_SECRET", SECRET);
    }
    let app = router(test_state(1000));

    for (path, body) in [
        (
            "/api/v1/internal/oidc/begin",
            serde_json::json!({
                "tenant_slug": "acme",
                "plane": "admin",
                "redirect_uri": "https://ui.test/auth/oidc/callback",
            }),
        ),
        (
            "/api/v1/internal/oidc/callback",
            serde_json::json!({"flow_token": "x", "code": "y", "state": "z"}),
        ),
        (
            "/api/v1/internal/oidc/end-session-url",
            serde_json::json!({"tenant_slug": "acme"}),
        ),
    ] {
        for bearer in [None, Some("not-the-secret"), Some("")] {
            let resp = app
                .clone()
                .oneshot(post_json(path, body.clone(), bearer))
                .await
                .expect("router responds");
            assert_eq!(
                resp.status(),
                StatusCode::UNAUTHORIZED,
                "{path} with bearer {bearer:?} must be refused before the handler"
            );
        }

        let admitted = app
            .clone()
            .oneshot(post_json(path, body.clone(), Some(SECRET)))
            .await
            .expect("router responds");
        assert_ne!(
            admitted.status(),
            StatusCode::UNAUTHORIZED,
            "{path} with the right secret must reach its handler — otherwise the \
             refusals above prove nothing"
        );
    }
}

/// Taking an identity on a caller's word is off unless an operator turns it on.
///
/// `ALLOW_OIDC_CLAIM_EXCHANGE` is unset in this binary, so the endpoint must
/// answer 404 — masquerading as absent rather than advertising a disabled
/// surface — and must do so before the service-secret check, which is why a
/// request with no credential at all still gets 404 rather than 401.
#[tokio::test]
async fn claim_exchange_is_absent_unless_enabled() {
    let app = router(test_state(1000));

    let resp = app
        .oneshot(post_json(
            "/api/v1/auth/oidc-exchange",
            serde_json::json!({
                "email": "someone@example.com",
                "email_verified": true,
                "oidc_sub": "sub-1",
                "oidc_issuer": "https://idp.test",
                "tenant_slug": "acme",
            }),
            None,
        ))
        .await
        .expect("router responds");
    assert_eq!(
        resp.status(),
        StatusCode::NOT_FOUND,
        "claim exchange must be absent by default"
    );
}

/// A signature-valid session the database cannot be asked about is a 503 on
/// both planes — never a 401, which the console reads as "signed out".
///
/// The dead pool IS the outage. The control proves the 503 is about the
/// lookup, not the token: the same request with a bad signature is still a 401.
#[tokio::test]
async fn an_outage_never_reads_as_a_refused_session() {
    // SAFETY: every writer in this test binary stores this same value and all
    // env access here goes through Rust std (no FFI readers); no other test in
    // this binary asserts on an unconfigured keyring.
    unsafe {
        std::env::set_var("AUTH_SECRET", "test-router-auth-secret-long-enough-for-hs256");
    }
    let ring = crate::routes::admin_auth::keyring().expect("keyring from AUTH_SECRET");
    let tenant = uuid::Uuid::new_v4();
    let console = crate::routes::admin_auth::generate_jwt(
        &ring,
        &uuid::Uuid::new_v4(),
        "a@corp.test",
        "admin",
        &tenant.to_string(),
        false,
    )
    .expect("console jwt");
    let portal = crate::routes::portal_auth::generate_portal_jwt(&uuid::Uuid::new_v4(), "u@corp.test", tenant)
        .expect("portal jwt");
    let other = streamscope_mcp_auth::keys::Keyring::new("another-secret-entirely-long-enough-for-hs256", None)
        .expect("ring");
    let forged = crate::routes::admin_auth::generate_jwt(
        &other,
        &uuid::Uuid::new_v4(),
        "a@corp.test",
        "admin",
        &tenant.to_string(),
        false,
    )
    .expect("forged jwt");
    let app = router(test_state(1000));

    let with_bearer = |method: &str, path: &str, token: &str| {
        let mut req = request(method, path);
        req.headers_mut()
            .insert(header::AUTHORIZATION, format!("Bearer {token}").parse().expect("header"));
        req
    };
    for (method, path, token) in [
        ("GET", "/api/v1/auth/me", console.as_str()),
        ("POST", "/api/v1/auth/logout", console.as_str()),
        ("GET", "/api/v1/admin/users", console.as_str()),
        ("GET", "/api/v1/portal/keys", portal.as_str()),
    ] {
        let resp = app.clone().oneshot(with_bearer(method, path, token)).await.expect("router responds");
        assert_eq!(resp.status(), StatusCode::SERVICE_UNAVAILABLE, "{method} {path}");
        assert_eq!(
            body_json(resp).await["error"]["code"],
            "maintenance_in_progress",
            "{method} {path}: the 503 carries a code the UI can branch on"
        );

        // Control: a token signed with another secret is refused before any
        // lookup, outage or not.
        let resp = app.clone().oneshot(with_bearer(method, path, &forged)).await.expect("router responds");
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED, "{method} {path} with a forged signature");
    }
}
