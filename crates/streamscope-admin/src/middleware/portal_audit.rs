//! Portal-action audit middleware.
//!
//! Records WHO (which portal end-user) performed WHAT mutating portal call on
//! `/api/v1/portal/*`. Runs *after* `portal_auth` (so [`PortalUser`] is on
//! extensions) and skips non-mutating verbs. Same insert discipline as
//! `admin_audit_mw`: synchronous, 500ms-bounded, fail-open (audit is
//! observability, not authorization).
//!
//! Mechanics (body buffering, redaction, action derivation, IP resolution) are
//! shared with the admin/security middlewares via [`crate::middleware::audit_common`].

use std::sync::Arc;

use axum::extract::{MatchedPath, OriginalUri, Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde_json::Value;
use tracing::error;
use uuid::Uuid;

use crate::db::tenant::{TenantConn, TenantId};
use crate::middleware::audit_common::{
    CONSOLE_BODY_LIMIT, build_generic_diff, capped_change_diff, buffer_request_body, capture_created_id, capture_error_body, derive_action,
    first_string_field, is_mutating, needs_before_snapshot, resolve_diff_target,
    snapshot_row, workspace_id_from_path, AuditDiffSink, DiffKind, PortalAuditTarget,
    AUDIT_WRITE_TIMEOUT, CONTROL_PLANE_ACTION_OVERRIDES,
};
use crate::middleware::request_id::RequestId;
use crate::routes::portal_auth::PortalUser;
use crate::AdminState;

/// Mount prefix stripped before deriving the resource kind from the path.
const PORTAL_PREFIXES: &[&str] = &["/api/v1/portal"];

pub async fn portal_audit_mw(
    State(state): State<Arc<AdminState>>,
    req: Request,
    next: Next,
) -> Response {
    let method = req.method().clone();
    if !is_mutating(&method) {
        return next.run(req).await;
    }

    let path = req
        .extensions()
        .get::<OriginalUri>()
        .map(|o| o.0.path().to_string())
        .unwrap_or_else(|| req.uri().path().to_string());
    let route_template = req
        .extensions()
        .get::<MatchedPath>()
        .map(|m| m.as_str().to_string());
    let user = req.extensions().get::<PortalUser>().cloned();
    let request_id = req
        .extensions()
        .get::<RequestId>()
        .map(|r| r.0)
        .unwrap_or_else(streamscope_core::ids::mint_request_id);
    let actor_ip = super::ip_rate_limit::client_ip(req.headers(), req.extensions())
        .map(|ip| ip.to_string());

    // Resolve a registered single-table resource and snapshot it before the
    // handler runs (see admin_audit_mw for the full rationale). Portal scopes the
    // read to the caller's tenant.
    let resolved = resolve_diff_target(&method, route_template.as_deref(), &path, PORTAL_PREFIXES);

    // Buffer + redact the request body. Two handler seams: `AuditDiffSink`
    // stamps a `{before, after}` diff (e.g. revoke-for-member); `PortalAuditTarget`
    // stamps the member a manager acted on behalf of. Self-service mutations
    // leave both NULL. A body the layer cannot read whole is refused here, and
    // recorded like any refusal: the handler never runs on a body it was not
    // sent.
    let sink = AuditDiffSink::default();
    let target = PortalAuditTarget::default();
    let mut before_snapshot = None;
    let (resp, body_json) = match buffer_request_body(req, CONSOLE_BODY_LIMIT).await {
        Ok((mut req, body_json)) => {
            // The row as it stands once the body is in: read before the body,
            // a slow upload would date it by the upload's length.
            let snapshot = match (user.as_ref(), resolved.as_ref()) {
                (Some(user), Some(r)) if needs_before_snapshot(r) => {
                    snapshot_row(
                        &state.db,
                        TenantId::from_credential(user.tenant_id),
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
            req.extensions_mut().insert(target.clone());
            (next.run(req).await, body_json)
        }
        Err(refused) => (refused.1.into_api_error().into_response(), None),
    };
    let status = resp.status().as_u16();
    let handler_diff = sink.take();
    let target_user_id = target.take();

    let need_created_id = handler_diff.is_none()
        && status < 300
        && matches!(resolved.as_ref().map(|r| r.kind), Some(DiffKind::Create));
    let (resp, created_id) = if need_created_id {
        let id_field = resolved.as_ref().map(|r| r.id_col).unwrap_or("id");
        capture_created_id(resp, id_field).await
    } else {
        (resp, None)
    };
    let (resp, response_error) = capture_error_body(resp, status).await;

    if let Some(user) = user {
        // Handler-stamped diff wins; otherwise build the generic one on success.
        let change_diff = match handler_diff {
            Some(d) => Some(d),
            None if status < 300 => match resolved.as_ref() {
                Some(r) => {
                    build_generic_diff(
                        &state.db,
                        TenantId::from_credential(user.tenant_id),
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

        // Workspace scope: most mutations carry it in the request body (key
        // creation, quickstart render); the manager mint/revoke-for-member
        // routes carry it in the `/workspaces/{id}/...` path instead. NULL only
        // when neither applies.
        let workspace_id = first_string_field(body_json.as_ref(), &["workspace_id"])
            .and_then(|s| Uuid::parse_str(s).ok())
            .or_else(|| workspace_id_from_path(route_template.as_deref(), &path));
        let (action, resource_kind, resource_id) = derive_action(
            &method, route_template.as_deref(), &path, PORTAL_PREFIXES,
            CONTROL_PLANE_ACTION_OVERRIDES,
        );
        let pool = state.db.clone();
        let write = write_portal_audit(
            &pool,
            &user,
            workspace_id,
            target_user_id,
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
            Ok(Err(e)) => error!(%request_id, "portal_audit write failed: {e}"),
            Err(_) => error!(%request_id, "portal_audit write timed out"),
        }
    }
    resp
}

#[allow(clippy::too_many_arguments)]
async fn write_portal_audit(
    pool: &crate::db::Db,
    user: &PortalUser,
    workspace_id: Option<Uuid>,
    target_user_id: Option<Uuid>,
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
    // Tenant-scoped connection so the `portal_audit` RLS WITH CHECK passes.
    let mut db = TenantConn::acquire(pool, TenantId::from_credential(user.tenant_id)).await?;
    // An `ak-` portal key actor → 'portal_key' + the key id; actor_id/email are
    // already the owning service account. A human session → 'human', NULL key.
    let (actor_kind, actor_key_id) = match user.key_id {
        Some(kid) => ("portal_key", Some(kid)),
        None => ("human", None),
    };
    sqlx::query(
        r#"
        INSERT INTO portal_audit
          (tenant_id, actor_id, actor_email, actor_ip, actor_kind, actor_key_id,
           workspace_id, target_user_id,
           method, path, route_template, action, resource_kind, resource_id,
           request_body, change_diff, response_error, status_code, request_id)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19)
        "#,
    )
    .bind(user.tenant_id)
    .bind(user.user_id)
    .bind(&user.email)
    .bind(actor_ip)
    .bind(actor_kind)
    .bind(actor_key_id)
    .bind(workspace_id)
    .bind(target_user_id)
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
