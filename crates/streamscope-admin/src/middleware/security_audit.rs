//! Pre-auth security-event audit middleware.
//!
//! Wraps the public / pre-auth surfaces — admin & portal login, account setup,
//! OIDC exchange, invite acceptance, and the MCP-OAuth grant/register flow —
//! and records every attempt (success AND failure) to the global
//! `security_audit` table: attempted identity, source IP, outcome. The lone
//! exception is a rate-limiter rejection (`429` with the `rate_limit_exceeded`
//! code) — auditing the throttled overflow would let a runaway client flood the
//! table one row per rejected attempt, so those are dropped. Other `429`s (e.g.
//! a resource-quota cap) carry a different code and stay audited.
//!
//! Unlike the admin/portal middlewares there is no authenticated actor and no
//! tenant context (a failed login can abort before any tenant resolves), so it
//! writes on the raw pool to a non-RLS table with a nullable tenant. Identity
//! and tenant slug are best-effort, lifted from the request body / path.
//!
//! Mechanics are shared via [`crate::middleware::audit_common`].

use crate::db::Global;
use std::sync::Arc;

use axum::extract::{MatchedPath, OriginalUri, Request, State};
use axum::http::Method;
use axum::middleware::Next;
use axum::response::Response;
use serde_json::Value;
use tracing::error;
use uuid::Uuid;

use crate::middleware::audit_common::{
    PRE_AUTH_BODY_LIMIT, buffer_request_body, capture_error_body, derive_action, first_string_field,
    is_mutating, AUDIT_WRITE_TIMEOUT, CONTROL_PLANE_ACTION_OVERRIDES,
};
use crate::middleware::request_id::RequestId;
use crate::AdminState;

/// Mount prefixes stripped before deriving the action from the path. The
/// security middleware fronts several differently-mounted public routers.
const SECURITY_PREFIXES: &[&str] = &[
    "/api/v1/auth",
    "/api/v1/portal",
    "/api/v1/invites",
    "/api/v1/mcp/oauth",
    "/api/v1/cli/oauth",
    // The OIDC login flow. A sign-in belongs on this plane whether it succeeds
    // or is refused. Note a refused callback identifies no tenant: the tenant
    // lives inside the sealed flow token, and a callback that fails before that
    // token opens has nothing to attribute itself to.
    "/api/v1/internal/oidc",
];

/// Side-effecting GET routes that must be audited despite not being a mutating
/// verb. The MCP-OAuth browser callback completes a per-user connection (stores
/// upstream tokens) on a GET because the external IdP redirects the browser to
/// it; auditing it is required for "no mutating surface without a row".
const SIDE_EFFECT_GET_SUFFIXES: &[&str] = &["/mcp/connections/oauth/callback"];

/// A GET that changes state (an OAuth callback spends its code and stores a
/// connection): audited, and run to completion, like a mutating method.
pub(crate) fn is_side_effect_get(method: &Method, path: &str, route_template: Option<&str>) -> bool {
    *method == Method::GET
        && SIDE_EFFECT_GET_SUFFIXES
            .iter()
            .any(|s| path.ends_with(s) || route_template.is_some_and(|t| t.ends_with(s)))
}

/// The security-audit writes in flight, detached from their requests, so
/// graceful shutdown waits for them.
pub static AUDIT_WRITES: std::sync::LazyLock<tokio_util::task::TaskTracker> =
    std::sync::LazyLock::new(tokio_util::task::TaskTracker::new);

pub async fn security_audit_mw(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();

    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let route_template = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());

    let is_side_effect_get = is_side_effect_get(&method, &path, route_template.as_deref());

    if !is_mutating(&method) && !is_side_effect_get {
        return next.run(req).await;
    }

    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0)
        .unwrap_or_else(streamscope_core::ids::mint_request_id);
    let actor_ip = super::ip_rate_limit::client_ip(req.headers(), req.extensions())
        .map(|ip| ip.to_string());

    // A body the layer cannot read whole reaches the handler as a body that
    // fails to read, never as an empty one: the handler's own extractor refuses
    // it in its own grammar (the RFC OAuth shape on those endpoints), and the
    // refusal is recorded below like any other.
    let (req, body_json) = match buffer_request_body(req, PRE_AUTH_BODY_LIMIT).await {
        Ok(read) => read,
        Err(refused) => {
            let (parts, unread) = *refused;
            (Request::from_parts(parts, unread.into_failing_body()), None)
        }
    };
    let resp = next.run(req).await;
    let status = resp.status().as_u16();
    let (resp, response_error) = capture_error_body(resp, status).await;

    // Drop rate-limiter throttle overflow: a request the limiter already
    // rejected was throttled before any work ran, so auditing it would let a
    // runaway client (a buggy retry loop, not just an attacker) write one
    // `security_audit` row per rejected attempt, defeating the limiter and
    // filling the table. The attempts that tripped the limiter are already
    // audited; the overflow carries no new signal. Keyed on the
    // `rate_limit_exceeded` code — NOT a bare 429 — so resource-quota 429s
    // (e.g. the MCP-OAuth DCR per-tenant cap) stay audited.
    if status == 429
        && response_error
            .as_ref()
            .and_then(|e| e.get("error"))
            .and_then(|e| e.get("code"))
            .and_then(Value::as_str)
            == Some("rate_limit_exceeded")
    {
        return resp;
    }

    // Attempted identity: the login email, or the OAuth client_id, lifted from
    // the (already-redacted) request body. NULL for the body-less callback.
    let identity =
        first_string_field(body_json.as_ref(), &["email", "client_id", "username"]).map(str::to_string);
    // Tenant slug: from the body (admin login / oidc-exchange carry it) or the
    // `{tenant_slug}` path segment (MCP-OAuth routes). Best-effort, nullable.
    let tenant_slug = first_string_field(body_json.as_ref(), &["tenant_slug"])
        .map(|s| s.to_string())
        .or_else(|| tenant_slug_from_path(route_template.as_deref(), &path));

    let (action, _kind, _id) = derive_action(
        &method, route_template.as_deref(), &path, SECURITY_PREFIXES,
        CONTROL_PLANE_ACTION_OVERRIDES,
    );

    // Detach the write: unlike the admin/portal planes, this middleware fronts
    // UNAUTHENTICATED endpoints, so a login/OAuth flood must not add synchronous
    // DB latency to the auth path (an attacker-controlled write-amplifier
    // otherwise). Fire-and-forget on a spawned task, bounded by the same 500ms
    // timeout; the response returns immediately. Loss only under extreme pool
    // exhaustion — acceptable for a best-effort security log.
    let pool = state.db.clone();
    let method_s = method.as_str().to_string();
    // Redact before the value crosses into the writer, so the raw path — which
    // can carry a live bearer — has no path to the row at all.
    let audit_path = redact_path(route_template.as_deref(), &path);
    // Tracked, so graceful shutdown waits for it.
    AUDIT_WRITES.spawn(async move {
        let write = write_security_audit(
            &pool,
            tenant_slug.as_deref(),
            identity.as_deref(),
            actor_ip.as_deref(),
            &method_s,
            &audit_path,
            route_template.as_deref(),
            &action,
            status,
            body_json.as_ref(),
            response_error.as_ref(),
            request_id,
        );
        match tokio::time::timeout(AUDIT_WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => error!(%request_id, "security_audit write failed: {e}"),
            Err(_) => error!(%request_id, "security_audit write timed out"),
        }
    });
    resp
}

/// Extract the `{tenant_slug}` path parameter by aligning the matched template
/// against the concrete path. The matched template is the *nested* suffix of
/// the full path (axum strips the mount prefix), so the raw path carries extra
/// leading prefix segments — align from the END so `{tenant_slug}` maps to the
/// correct concrete segment regardless of prefix depth. Returns None when the
/// route has no such segment.
fn tenant_slug_from_path(template: Option<&str>, raw_path: &str) -> Option<String> {
    let template = template?;
    let t_segs: Vec<&str> = template.trim_matches('/').split('/').collect();
    let p_segs: Vec<&str> = raw_path.trim_matches('/').split('/').collect();
    for (i, seg) in t_segs.iter().rev().enumerate() {
        if *seg == "{tenant_slug}" {
            let idx = p_segs.len().checked_sub(i + 1)?;
            return p_segs.get(idx).map(|s| (*s).to_string());
        }
    }
    None
}

/// Replace secret-bearing path segments with their template placeholder.
///
/// **The URL is the one place body redaction cannot reach.** `POST
/// /api/v1/invites/{token}/accept` carries a live account-minting bearer in the
/// path, and this table is global, un-RLS'd, surfaced on the super-admin
/// security feed, and included in every backup. It is also written on FAILED
/// accepts — a short password or a mismatched email returns before the invite is
/// claimed — so the token stored is one that still works.
///
/// A parameter is secret-bearing when its NAME is, judged by
/// [`is_redact_path_param`] — the body predicate widened by `code`, which body
/// redaction scopes out only because it doubles as the `ApiErrorResponse` field
/// name. Segments the template does not name (`{id}`, `{tenant_slug}`,
/// literals) are untouched: a path with nothing left in it audits nothing
/// useful.
///
/// Aligned from the END like [`tenant_slug_from_path`] — axum's matched template
/// is the nested suffix of the full path, so leading prefix segments differ.
fn redact_path(template: Option<&str>, raw_path: &str) -> String {
    let Some(template) = template else {
        return raw_path.to_string();
    };
    let t_segs: Vec<&str> = template.trim_matches('/').split('/').collect();
    let mut p_segs: Vec<String> = raw_path
        .trim_matches('/')
        .split('/')
        .map(str::to_string)
        .collect();

    for (i, seg) in t_segs.iter().rev().enumerate() {
        let Some(name) = seg.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
            continue;
        };
        if !crate::middleware::audit_common::is_redact_path_param(name) {
            continue;
        }
        let Some(idx) = p_segs.len().checked_sub(i + 1) else {
            continue;
        };
        if let Some(target) = p_segs.get_mut(idx) {
            *target = format!("{{{name}}}");
        }
    }

    let joined = p_segs.join("/");
    if raw_path.starts_with('/') {
        format!("/{joined}")
    } else {
        joined
    }
}

#[allow(clippy::too_many_arguments)]
async fn write_security_audit(
    pool: &crate::db::Db,
    tenant_slug: Option<&str>,
    actor_identity: Option<&str>,
    actor_ip: Option<&str>,
    method: &str,
    path: &str,
    route_template: Option<&str>,
    action: &str,
    status_code: u16,
    request_body: Option<&Value>,
    response_error: Option<&Value>,
    request_id: Uuid,
) -> Result<(), sqlx::Error> {
    // Every value here can carry caller-chosen text, and a U+0000 would make
    // Postgres refuse the row — keeping the request out of the audit trail.
    use streamscope_core::pg_text::{storable_json, storable_str};
    let tenant_slug = tenant_slug.map(storable_str);
    let actor_identity = actor_identity.map(storable_str);
    let path = storable_str(path);
    let route_template = route_template.map(storable_str);
    let request_body = request_body.map(storable_json);
    let response_error = response_error.map(storable_json);
    sqlx::query(
        r#"
        INSERT INTO security_audit
          (tenant_id, tenant_slug, actor_identity, actor_ip,
           method, path, route_template, action, succeeded, status_code,
           request_body, response_error, request_id)
        VALUES (NULL, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
        "#,
    )
    .bind(tenant_slug.as_deref())
    .bind(actor_identity.as_deref())
    .bind(actor_ip)
    .bind(method)
    .bind(&*path)
    .bind(route_template.as_deref())
    .bind(action)
    .bind(status_code < 400)
    .bind(status_code as i16)
    .bind(request_body.as_deref())
    .bind(response_error.as_deref())
    .bind(request_id)
    .execute(pool.global(Global::Infra))
    .await
    .map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An invite token is a live account-minting bearer sitting in a URL, and
    /// the row is written even when the accept FAILS — so anything stored here
    /// is a credential that still works.
    #[test]
    fn an_invite_token_never_reaches_the_audit_row() {
        assert_eq!(
            redact_path(Some("/{token}/accept"), "/api/v1/invites/s3cr3t-live/accept"),
            "/api/v1/invites/{token}/accept"
        );
        assert_eq!(
            redact_path(Some("/{token}"), "/api/v1/invites/s3cr3t-live"),
            "/api/v1/invites/{token}"
        );
    }

    /// A row whose path is entirely placeholders says nothing an operator can
    /// act on, so only segments the template NAMES as secret are replaced.
    #[test]
    fn everything_that_is_not_a_secret_survives() {
        assert_eq!(
            redact_path(
                Some("/{tenant_slug}/authorize/approve"),
                "/api/v1/mcp/oauth/acme/authorize/approve"
            ),
            "/api/v1/mcp/oauth/acme/authorize/approve"
        );
        // An id is not a secret, and losing it would cost the audit its subject.
        assert_eq!(
            redact_path(Some("/{id}"), "/api/v1/admin/users/0b1c2d3e"),
            "/api/v1/admin/users/0b1c2d3e"
        );
    }

    /// Alignment is from the end because axum's matched template is the nested
    /// suffix of the full path. Aligning from the front would redact whichever
    /// segment happened to sit at that index — here, the mount prefix.
    #[test]
    fn alignment_survives_a_deep_mount_prefix() {
        assert_eq!(
            redact_path(
                Some("/{token}/accept"),
                "/deeply/nested/mount/invites/s3cr3t/accept"
            ),
            "/deeply/nested/mount/invites/{token}/accept"
        );
    }

    /// No template means no way to tell a secret segment from an id, so the
    /// path is left alone rather than blanked — and `route_template` is
    /// `Option` on every row, so this arm is reachable.
    #[test]
    fn an_unmatched_route_is_left_intact() {
        assert_eq!(
            redact_path(None, "/api/v1/invites/s3cr3t/accept"),
            "/api/v1/invites/s3cr3t/accept"
        );
    }
}
