//! The API design rules — the error envelope, no 204, a declared `security`
//! matching the router's fence, `PATCH` for a partial body, verbs under
//! `actions/`, no bare-array body, every `$ref` registered, every open object
//! field documented, every response described — checked against
//! the spec the binary publishes and the router it serves.
//!
//! The spec is read from `published_api_doc()` — the same document `/api/docs`
//! serves — so an endpoint added without following a rule fails `cargo test`,
//! not a review. The router half drives `build_app` over a dead pool (see
//! `router_tests`), so a 401 proves a middleware answered.
//!
//! Out of scope by design: the OAuth surfaces (`/api/v1/mcp/oauth/*`,
//! `/api/v1/cli/oauth/*`), whose errors are RFC-shaped, and the edge protocol
//! (`/api/v2/edge/*`), which only our own edge speaks.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode};
use serde_json::Value;
use tower::ServiceExt;

use crate::db::Db;
use crate::{build_app, metrics, published_api_doc, AdminState, PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD};
use streamscope_core::middleware::ip_rate_limit::RateLimiter;

const METHODS: [&str; 5] = ["get", "post", "put", "patch", "delete"];
const OUT_OF_SCOPE: [&str; 3] = ["/api/v1/mcp/oauth/", "/api/v1/cli/oauth/", "/api/v2/edge/"];

struct Operation {
    method: &'static str,
    path: String,
    op: Value,
}

fn operations() -> Vec<Operation> {
    let spec = serde_json::to_value(published_api_doc()).expect("the spec serialises");
    let mut ops = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("spec has paths") {
        if OUT_OF_SCOPE.iter().any(|p| path.starts_with(p)) {
            continue;
        }
        for method in METHODS {
            if let Some(op) = item.get(method) {
                ops.push(Operation { method, path: path.clone(), op: op.clone() });
            }
        }
    }
    assert!(ops.len() > 300, "the spec walk found only {} operations", ops.len());
    ops
}

fn fail_on(violations: Vec<String>, rule: &str) {
    assert!(
        violations.is_empty(),
        "{rule} — {} operation(s):\n  {}",
        violations.len(),
        violations.join("\n  ")
    );
}

/// Errors: every documented 4xx/5xx answer is the `ApiErrorResponse` envelope.
/// A response line without `body = ApiErrorResponse` publishes an error shape
/// the client cannot type.
#[test]
fn every_documented_error_is_the_api_error_envelope() {
    let mut violations = Vec::new();
    for o in operations() {
        let Some(responses) = o.op["responses"].as_object() else { continue };
        for (status, resp) in responses {
            if !(status.starts_with('4') || status.starts_with('5')) {
                continue;
            }
            let schema_ref = resp["content"]["application/json"]["schema"]["$ref"].as_str();
            if schema_ref != Some("#/components/schemas/ApiErrorResponse") {
                violations.push(format!("{} {} {status}", o.method.to_uppercase(), o.path));
            }
        }
    }
    fail_on(violations, "an error response must document `body = ApiErrorResponse`");
}

/// Every response says what it is: OpenAPI makes a response's `description`
/// required, so a response line without one publishes an invalid document.
/// Checked over every path, the out-of-scope surfaces included.
#[test]
fn every_response_has_a_description() {
    let spec = serde_json::to_value(published_api_doc()).expect("the spec serialises");
    let mut violations = Vec::new();
    for (path, item) in spec["paths"].as_object().expect("spec has paths") {
        for method in METHODS {
            let Some(responses) = item[method]["responses"].as_object() else { continue };
            for (status, resp) in responses {
                if resp.get("$ref").is_none() && !resp["description"].is_string() {
                    violations.push(format!("{} {path} {status}", method.to_uppercase()));
                }
            }
        }
    }
    fail_on(violations, "a response must carry `description = \"…\"`");
}

/// Side effects answer 200 with `ActionResponse`; an empty 204 tells the client
/// nothing and is not part of the API.
#[test]
fn no_operation_answers_204() {
    let violations = operations()
        .into_iter()
        .filter(|o| o.op["responses"].get("204").is_some())
        .map(|o| format!("{} {}", o.method.to_uppercase(), o.path))
        .collect();
    fail_on(violations, "204 is not an answer; use 200 + ActionResponse");
}

/// A security requirement names a scheme the spec defines, or a generated
/// client sends no credential for it.
#[test]
fn every_security_requirement_names_a_defined_scheme() {
    let mut violations = Vec::new();
    for o in operations() {
        for req in o.op["security"].as_array().into_iter().flatten() {
            for scheme in req.as_object().into_iter().flat_map(|m| m.keys()) {
                if scheme != "bearer_auth" {
                    violations.push(format!("{} {} names `{scheme}`", o.method.to_uppercase(), o.path));
                }
            }
        }
    }
    fail_on(violations, "the only security scheme is `bearer_auth`");
}

/// `PUT`s whose body is all-optional on purpose: each replaces a whole limit
/// set, and an absent field means "no limit", not "unchanged".
const FULL_REPLACE_PUTS: [&str; 5] = [
    "/api/v1/admin/workspaces/{id}/rate-limits",
    "/api/v1/admin/workspaces/{id}/member-defaults",
    "/api/v1/admin/workspaces/{id}/rate-limit-overrides/{user_id}",
    "/api/v1/portal/workspaces/{id}/members/{uid}/keys/{key_id}/budget",
    "/api/v1/portal/workspaces/{id}/members/{uid}/limits",
];

/// Sign-in and account-creation steps: verbs by nature, addressed by fixed
/// URLs that browsers, the IdP redirect and invite links already carry.
const SESSION_VERBS: [&str; 10] = [
    "/api/v1/auth/login",
    "/api/v1/auth/logout",
    "/api/v1/auth/setup",
    "/api/v1/auth/oidc-exchange",
    "/api/v1/portal/auth/login",
    "/api/v1/portal/auth/logout",
    "/api/v1/internal/oidc/begin",
    "/api/v1/internal/oidc/callback",
    "/api/v1/internal/oidc/end-session-url",
    "/api/v1/invites/{token}/accept",
];

/// The schema a JSON request body names, resolved through one `$ref`.
fn request_schema<'a>(spec: &'a Value, op: &'a Value) -> Option<&'a Value> {
    let schema = &op["requestBody"]["content"]["application/json"]["schema"];
    match schema["$ref"].as_str() {
        Some(r) => spec.pointer(r.trim_start_matches('#')),
        None => (!schema.is_null()).then_some(schema),
    }
}

/// A partial update is `PATCH`. A `PUT` whose body requires nothing is a
/// partial update under the wrong verb — a client reading the spec would
/// expect it to reset what it omits.
#[test]
fn a_put_body_that_requires_nothing_is_a_patch() {
    let spec = serde_json::to_value(published_api_doc()).expect("the spec serialises");
    let mut violations = Vec::new();
    for o in operations().into_iter().filter(|o| o.method == "put") {
        if FULL_REPLACE_PUTS.contains(&o.path.as_str()) {
            continue;
        }
        let Some(schema) = request_schema(&spec, &o.op) else { continue };
        let requires_nothing = schema["required"].as_array().is_none_or(|r| r.is_empty());
        if schema["type"] == "object" && requires_nothing {
            violations.push(format!("PUT {}", o.path));
        }
    }
    fail_on(violations, "an all-optional PUT body is a partial update: make it PATCH");
}

/// `POST` creates in a collection or runs a verb under `actions/` (or
/// `maintenance/`); never a bare verb segment like `/config/test`. A
/// collection is a path that also answers another method or has `/{id}`
/// children.
#[test]
fn a_post_targets_a_collection_or_an_action() {
    let ops = operations();
    let mut violations = Vec::new();
    for o in ops.iter().filter(|o| o.method == "post") {
        let segments: Vec<&str> = o.path.split('/').collect();
        if segments.contains(&"actions")
            || segments.contains(&"maintenance")
            || SESSION_VERBS.contains(&o.path.as_str())
        {
            continue;
        }
        let collection = ops.iter().any(|p| {
            (p.path == o.path && p.method != "post")
                || p.path
                    .strip_prefix(o.path.as_str())
                    .and_then(|rest| rest.strip_prefix("/{"))
                    .is_some_and(|rest| !rest.contains('/'))
        });
        if !collection {
            violations.push(format!("POST {}", o.path));
        }
    }
    fail_on(violations, "a POST verb belongs under `…/actions/{verb}`");
}

/// A list answers a page envelope and an aggregate a typed object; a bare
/// top-level array can grow neither paging nor a field without breaking every
/// client that parses it.
#[test]
fn no_success_body_is_a_top_level_array() {
    /// Whether a body schema can be an array at the top: through `$ref`s, a
    /// nullable `type: ["array", "null"]`, or any arm of a composition.
    fn can_be_array(schema: &Value, spec: &Value, depth: u8) -> bool {
        if depth > 8 {
            return false;
        }
        if let Some(r) = schema["$ref"].as_str() {
            return spec
                .pointer(r.trim_start_matches('#'))
                .is_some_and(|s| can_be_array(s, spec, depth + 1));
        }
        let typed_array = match &schema["type"] {
            Value::String(t) => t == "array",
            Value::Array(ts) => ts.iter().any(|t| t == "array"),
            _ => false,
        };
        typed_array
            || ["oneOf", "anyOf", "allOf"].iter().any(|k| {
                schema[*k]
                    .as_array()
                    .is_some_and(|arms| arms.iter().any(|a| can_be_array(a, spec, depth + 1)))
            })
    }
    let spec = serde_json::to_value(published_api_doc()).expect("the spec serialises");
    let mut violations = Vec::new();
    for o in operations() {
        let Some(responses) = o.op["responses"].as_object() else { continue };
        for (status, resp) in responses.iter().filter(|(s, _)| s.starts_with('2')) {
            let resp = match resp["$ref"].as_str() {
                Some(r) => spec.pointer(r.trim_start_matches('#')).unwrap_or(resp),
                None => resp,
            };
            let Some(content) = resp["content"].as_object() else { continue };
            for (media, body) in content.iter().filter(|(m, _)| m.contains("json")) {
                if can_be_array(&body["schema"], &spec, 0) {
                    violations.push(format!("{} {} {status} {media}", o.method.to_uppercase(), o.path));
                }
            }
        }
    }
    fail_on(violations, "a list is `OffsetPage`/`TotalPage`, an aggregate a typed object");
}

/// Every `$ref` names a schema the spec defines. A type reached only through a
/// query parameter is not collected on its own, and a dangling reference breaks
/// every generated client, not one endpoint.
#[test]
fn every_reference_in_the_spec_resolves() {
    fn walk(v: &Value, at: &str, spec: &Value, out: &mut Vec<String>) {
        match v {
            Value::Object(map) => {
                if let Some(r) = map.get("$ref").and_then(Value::as_str)
                    && spec.pointer(r.trim_start_matches('#')).is_none()
                {
                    out.push(format!("{at} → {r}"));
                }
                for (k, child) in map {
                    walk(child, &format!("{at}/{k}"), spec, out);
                }
            }
            Value::Array(items) => {
                for (i, child) in items.iter().enumerate() {
                    walk(child, &format!("{at}/{i}"), spec, out);
                }
            }
            _ => {}
        }
    }
    let spec = serde_json::to_value(published_api_doc()).expect("the spec serialises");
    let mut violations = Vec::new();
    walk(&spec, "", &spec, &mut violations);
    fail_on(violations, "a `$ref` must name a registered schema (add it to `components`)");
}

/// A schema field typed only as "an object" — a `serde_json::Value` behind
/// `value_type = Object`, or lists and maps of them at any depth, in a
/// component or an inline request/response body — says in its
/// description what it holds: a fixed shape is typed instead, and an open one
/// (a client's own wire, a script's result, a stored audit body) is the only
/// kind left, so its description is the whole contract a client gets.
#[test]
fn every_open_object_field_says_what_it_holds() {
    fn bare(p: &Value) -> bool {
        if p == &Value::Bool(true) {
            return true;
        }
        let Some(m) = p.as_object() else { return false };
        if ["$ref", "oneOf", "allOf", "anyOf", "properties", "items", "additionalProperties"]
            .iter()
            .any(|k| m.contains_key(*k))
        {
            return false;
        }
        match m.get("type") {
            None => true,
            Some(Value::String(t)) => t == "object",
            Some(Value::Array(ts)) => ts.iter().any(|t| t == "object"),
            _ => false,
        }
    }
    fn is_open(p: &Value) -> bool {
        bare(p)
            || p.get("items").is_some_and(is_open)
            || p.get("additionalProperties").is_some_and(is_open)
            || ["oneOf", "anyOf"].iter().any(|k| {
                p.get(*k)
                    .and_then(Value::as_array)
                    .is_some_and(|alts| alts.iter().any(|a| a["type"] != "null" && is_open(a)))
            })
    }
    let spec = serde_json::to_value(published_api_doc()).expect("the spec serialises");
    let mut violations = Vec::new();
    // Every object schema inside a component: its own properties, each variant
    // of a tagged enum (`oneOf` / `allOf` / `anyOf`), and inline objects reached
    // through a property, a list's items or a map's values — at any depth.
    fn walk(at: &str, schema: &Value, out: &mut Vec<String>) {
        for (field, p) in schema["properties"].as_object().into_iter().flatten() {
            let described = p.get("description").and_then(Value::as_str).is_some_and(|d| !d.trim().is_empty());
            if is_open(p) && !described {
                out.push(format!("{at}.{field}"));
            }
            walk(&format!("{at}.{field}"), p, out);
        }
        for k in ["oneOf", "allOf", "anyOf"] {
            for variant in schema[k].as_array().into_iter().flatten() {
                walk(at, variant, out);
            }
        }
        for k in ["items", "additionalProperties"] {
            if let Some(inner) = schema.get(k) {
                walk(&format!("{at}[]"), inner, out);
            }
        }
    }
    for (name, schema) in spec["components"]["schemas"].as_object().expect("spec has schemas") {
        // A component that is itself open is reached through a `$ref`, which
        // the field check cannot see past: its own description is its contract.
        let described = schema.get("description").and_then(Value::as_str).is_some_and(|d| !d.trim().is_empty());
        if is_open(schema) && !described {
            violations.push(format!("component {name}"));
        }
        walk(name, schema, &mut violations);
    }
    // A request or response body that is an open object outright: no field
    // to describe, and an operation's response description is mandatory
    // anyway, so it says nothing about the shape — type the body instead.
    for o in operations() {
        let mut bodies: Vec<(String, &Value)> = Vec::new();
        for (ct, c) in o.op["requestBody"]["content"].as_object().into_iter().flatten() {
            bodies.push((format!("request {ct}"), &c["schema"]));
        }
        for (code, r) in o.op["responses"].as_object().into_iter().flatten() {
            for (ct, c) in r["content"].as_object().into_iter().flatten() {
                bodies.push((format!("{code} {ct}"), &c["schema"]));
            }
        }
        for (at, schema) in bodies {
            let label = format!("{} {} {at}", o.method.to_uppercase(), o.path);
            if is_open(schema) {
                violations.push(label.clone());
            }
            walk(&label, schema, &mut violations);
        }
    }
    fail_on(violations, "an open-object field needs a doc comment saying what it holds (or a type)");
}

/// An `AdminState` over a dead pool with every limiter open.
fn dead_pool_state() -> Arc<AdminState> {
    let open = || RateLimiter::per_instance(0, 300, PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD, 1);
    Arc::new(AdminState {
        db: Db::unreachable_for_test(),
        instance_id: uuid::Uuid::new_v4(),
        login_rate_limiter: RateLimiter::new(10, 300, 100),
        invite_rate_limiter: RateLimiter::new(10, 300, 100),
        pre_auth_ip_rate_limiter: open(),
        automation_key_rate_limiter: open(),
        automation_key_ip_rate_limiter: crate::middleware::DistinctKeyFailures::new(
            0,
            300,
            PRE_AUTH_IP_LIMIT_CLEANUP_THRESHOLD,
            1,
        ),
        http_client: reqwest::Client::new(),
        cors_allowlist: arc_swap::ArcSwap::from_pointee(std::collections::HashSet::new()),
    })
}

/// The spec path with every `{param}` filled by a value any parameter type parses.
fn concrete(path: &str) -> String {
    let mut out = String::new();
    let mut rest = path;
    while let Some(open) = rest.find('{') {
        out.push_str(&rest[..open]);
        let close = rest[open..].find('}').map_or(rest.len(), |c| open + c + 1);
        out.push_str("00000000-0000-0000-0000-000000000000");
        rest = &rest[close..];
    }
    out.push_str(rest);
    out
}

/// Every operation that declares a credential refuses a request without one —
/// 401, the envelope, `missing_auth_header` — and every operation that refuses
/// one declares it. Both halves read the router as served: a middleware that
/// answers an empty status, or a secured route the spec calls public, fails.
#[tokio::test]
async fn a_request_without_a_credential_is_refused_in_the_envelope_exactly_where_the_spec_says() {
    let app = build_app(dead_pool_state(), Arc::new(metrics::AdminMetrics::new()));
    let mut violations = Vec::new();
    let mut secured = 0;
    for o in operations() {
        let declared = o.op["security"].as_array().is_some_and(|s| !s.is_empty());
        let uri = concrete(&o.path);
        let mut req = Request::builder()
            .method(o.method.to_uppercase().as_str())
            .uri(&uri)
            .body(Body::empty())
            .expect("well-formed request");
        req.extensions_mut()
            .insert(ConnectInfo(SocketAddr::from(([127, 0, 0, 1], 4242))));
        let resp = app.clone().oneshot(req).await.expect("router responds");
        let status = resp.status();
        let bytes = axum::body::to_bytes(resp.into_body(), 1 << 16).await.unwrap_or_default();
        let body: Value = serde_json::from_slice(&bytes).unwrap_or(Value::Null);
        let code = body["error"]["code"].as_str();
        let refused = status == StatusCode::UNAUTHORIZED;
        let name = format!("{} {}", o.method.to_uppercase(), o.path);
        if declared {
            secured += 1;
            if !refused || code != Some("missing_auth_header") {
                violations.push(format!("{name}: declared secured, answered {status} {code:?}"));
            }
        } else if refused {
            violations.push(format!("{name}: refuses without a credential but declares no `security`"));
        }
    }
    assert!(secured > 300, "only {secured} secured operations were driven");
    fail_on(violations, "the credential fence and the spec must agree");
}
