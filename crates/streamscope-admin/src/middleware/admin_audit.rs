//! Admin-action audit middleware.
//!
//! Records WHO performed WHAT mutating admin call. Runs *after* `admin_auth`
//! (so `AdminTenantCtx` is on extensions) and skips non-mutating verbs.
//!
//! Insert path: synchronous after the handler returns, bounded by a 500ms
//! timeout so a slow DB never blocks the response. On timeout or write error
//! the request still succeeds — audit is observability, not authorization.
//!
//! Body capture: the inbound request body is read whole up to
//! `CONSOLE_BODY_LIMIT` (a larger, broken-off or late one is refused here and
//! recorded), parsed as JSON up to `MAX_PARSED_BODY_BYTES` and recursively
//! redacted before insert. The body is then handed to the handler unchanged so
//! downstream extractors work as normal.
//!
//! The buffering / redaction / action-derivation / IP mechanics are shared
//! with the portal- and security-audit middlewares via
//! [`crate::middleware::audit_common`].

use std::sync::Arc;

use axum::extract::{MatchedPath, OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tracing::error;
use uuid::Uuid;

use crate::db::tenant::{AdminTenantCtx, TenantConn};
use crate::middleware::audit_common::{
    CONSOLE_BODY_LIMIT, build_generic_diff, capped_change_diff, buffer_request_body, capture_created_id, capture_error_body, derive_action,
    is_mutating, needs_before_snapshot, resolve_diff_target, snapshot_row,
    AuditDiffSink, DiffKind, AUDIT_WRITE_TIMEOUT, ADMIN_ACTION_OVERRIDES,
};
use crate::middleware::request_id::RequestId;
use crate::AdminState;

/// Mount prefix stripped before deriving the resource kind from the path.
const ADMIN_PREFIXES: &[&str] = &["/api/v1/admin"];

pub async fn admin_audit_mw(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    if !is_mutating(&method) {
        return next.run(req).await;
    }

    // `req.uri().path()` is stripped by axum's `nest()` — inside the admin
    // sub-router it shows `/users`, not `/api/v1/admin/users`. `OriginalUri`
    // preserves the pre-nest path so audit rows record the full URL the
    // operator actually called.
    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let route_template = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());
    let ctx = req.extensions().get::<AdminTenantCtx>().cloned();
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0)
        .unwrap_or_else(streamscope_core::ids::mint_request_id);
    let actor_ip = super::ip_rate_limit::client_ip(req.headers(), req.extensions())
        .map(|ip| ip.to_string());

    // Resolve whether this route maps to a single-table resource the middleware
    // can diff generically, and snapshot the row *before* the handler mutates it
    // (update / delete / single-row action). Registered resources get a
    // before→after diff with zero handler code; a handler that stamps its own
    // diff (settings blobs, bulk/sync summaries) still wins below.
    let resolved = resolve_diff_target(&method, route_template.as_deref(), &path, ADMIN_PREFIXES);

    // Buffer + redact the request body, then hand the handler a sink it can use
    // to stamp a structured change diff. A body the layer cannot read whole is
    // refused here, and recorded like any refusal: the handler never runs on a
    // body it was not sent.
    let sink = AuditDiffSink::default();
    let mut before_snapshot = None;
    let (resp, body_json) = match buffer_request_body(req, CONSOLE_BODY_LIMIT).await {
        Ok((mut req, body_json)) => {
            // The row as it stands once the body is in: read before the body,
            // a slow upload would date it by the upload's length.
            let snapshot = match (ctx.as_ref(), resolved.as_ref()) {
                (Some(ctx), Some(r)) if needs_before_snapshot(r) => {
                    snapshot_row(
                        &state.db,
                        ctx.tenant_id,
                        r.table,
                        r.id_col,
                        r.resource_id.as_deref().unwrap_or_default(),
                    )
                    .await
                }
                _ => None,
            };
            before_snapshot = snapshot;
            req.extensions_mut().insert(sink.clone());
            (next.run(req).await, body_json)
        }
        Err(refused) => (refused.1.into_api_error().into_response(), None),
    };
    let status = resp.status().as_u16();
    let handler_diff = sink.take();

    // For a registered collection create, read the new row's id from the success
    // body so we can snapshot the created row as the diff's `after`.
    let need_created_id = handler_diff.is_none()
        && status < 300
        && matches!(resolved.as_ref().map(|r| r.kind), Some(DiffKind::Create));
    let (resp, created_id) = if need_created_id {
        let id_field = resolved.as_ref().map(|r| r.id_col).unwrap_or("id");
        capture_created_id(resp, id_field).await
    } else {
        (resp, None)
    };
    // On a failure status, capture the typed `{code, message}` reason.
    let (resp, response_error) = capture_error_body(resp, status).await;

    if let Some(ctx) = ctx {
        // Handler-stamped diff wins; otherwise build the generic one on success.
        let change_diff = match handler_diff {
            Some(d) => Some(d),
            None if status < 300 => match resolved.as_ref() {
                Some(r) => {
                    build_generic_diff(
                        &state.db,
                        ctx.tenant_id,
                        r,
                        before_snapshot,
                        created_id.as_deref(),
                    )
                    .await
                }
                None => None,
            },
            None => None,
        };

        let (action, resource_kind, resource_id) = derive_action(
            &method, route_template.as_deref(), &path, ADMIN_PREFIXES, ADMIN_ACTION_OVERRIDES,
        );
        let pool = state.db.clone();
        let write = write_audit(
            &pool,
            &ctx,
            actor_ip.as_deref(),
            method.as_str(),
            &path,
            route_template.as_deref(),
            &action,
            &resource_kind,
            resource_id.as_deref(),
            body_json.as_ref(),
            change_diff.as_ref(),
            response_error.as_ref(),
            status,
            request_id,
        );
        match tokio::time::timeout(AUDIT_WRITE_TIMEOUT, write).await {
            Ok(Ok(())) => {}
            Ok(Err(e)) => {
                error!(%request_id, "admin_audit write failed: {e}");
            }
            Err(_) => {
                error!(%request_id, "admin_audit write timed out");
            }
        }
    }
    resp
}

#[allow(clippy::too_many_arguments)]
async fn write_audit(
    pool: &crate::db::Db,
    ctx: &AdminTenantCtx,
    actor_ip: Option<&str>,
    method: &str,
    path: &str,
    route_template: Option<&str>,
    action: &str,
    resource_kind: &str,
    resource_id: Option<&str>,
    request_body: Option<&Value>,
    change_diff: Option<&Value>,
    response_error: Option<&Value>,
    status_code: u16,
    request_id: Uuid,
) -> Result<(), sqlx::Error> {
    // Every value here can carry caller-chosen text, and a U+0000 would make
    // Postgres refuse the row — keeping the request out of the audit trail.
    use streamscope_core::pg_text::{storable_json, storable_str};
    let path = storable_str(path);
    let resource_id = resource_id.map(storable_str);
    let request_body = request_body.map(storable_json);
    let change_diff = change_diff.map(capped_change_diff);
    let change_diff = change_diff.as_deref().map(storable_json);
    let response_error = response_error.map(storable_json);
    // Acquire a tenant-scoped connection so RLS (both `admin_audit`'s
    // INSERT-time WITH CHECK and `admin_accounts`'s SELECT-time USING) sees
    // the right tenant.
    let mut db = TenantConn::acquire(pool, ctx.tenant_id).await?;
    // Resolve the actor's email + kind. A human session's `admin_account_id` is an
    // `admin_accounts` row; an `ak-` automation key's is the owning service
    // account's `users` row (there is no `admin_accounts` row for it). `actor_id`
    // carries the owning account either way; `actor_key_id` names the exact key.
    let (actor_kind, email): (&str, Option<String>) = match ctx.actor_key_id {
        None => (
            "human",
            sqlx::query_scalar::<_, String>("SELECT email FROM admin_accounts WHERE id = $1")
                .bind(ctx.admin_account_id)
                .fetch_optional(db.conn())
                .await
                .ok()
                .flatten(),
        ),
        Some(_) => (
            "admin_key",
            sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE id = $1")
                .bind(ctx.admin_account_id)
                .fetch_optional(db.conn())
                .await
                .ok()
                .flatten(),
        ),
    };
    sqlx::query(
        r#"
        INSERT INTO admin_audit
          (tenant_id, actor_kind, actor_id, actor_email, actor_key_id, actor_ip, is_super_admin,
           method, path, route_template, action, resource_kind, resource_id,
           request_body, change_diff, response_error, status_code, request_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18)
        "#,
    )
    .bind(ctx.tenant_id.as_uuid())
    .bind(actor_kind)
    .bind(ctx.admin_account_id)
    .bind(email.as_deref())
    .bind(ctx.actor_key_id)
    .bind(actor_ip)
    .bind(ctx.is_super_admin)
    .bind(method)
    .bind(&*path)
    .bind(route_template)
    .bind(action)
    .bind(resource_kind)
    .bind(resource_id.as_deref())
    .bind(request_body.as_deref())
    .bind(change_diff.as_deref())
    .bind(response_error.as_deref())
    .bind(status_code as i16)
    .bind(request_id)
    .execute(db.conn())
    .await
    .map(|_| ())
}
