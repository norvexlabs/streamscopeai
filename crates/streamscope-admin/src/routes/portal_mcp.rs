//! Portal — MCP self-service.
//!
//! Portal users land here to list the MCP virtual servers their workspaces
//! allowlist. Keys are minted through the unified portal `/keys` endpoint — a
//! single key spans both LLM and MCP, gated per request by the workspace
//! allowlist — so there is no MCP-specific key flow.

use axum::extract::Query;
use axum::{Extension, Json};
use serde::Serialize;
use utoipa::ToSchema;
use uuid::Uuid;

use super::portal_auth::PortalUser;
use super::{ApiError, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::TenantConn;

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalMcpVirtualServer {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    /// `true` when at least one of this virtual server's routes points at a
    /// built-in upstream (e.g. the synthetic `builtin-web` row that backs
    /// `/mcp/web`). Lets the portal badge the built-in web server and sort
    /// it first in the quickstart MCP picker, regardless of its slug.
    pub built_in: bool,
    /// `true` when at least one of this virtual server's routes points at a
    /// `per_user_oauth` upstream — i.e. the calling user must link their own
    /// account in the portal before requests through this server succeed.
    pub requires_connection: bool,
    /// Aggregate per-user-OAuth connection state for the **current user**:
    /// - `none` — no `per_user_oauth` upstreams (nothing to connect).
    /// - `connected` — every `per_user_oauth` upstream has a present, unexpired
    ///   credential for this user.
    /// - `needs_connection` — at least one `per_user_oauth` upstream is missing
    ///   a credential or its credential has expired. The config is still valid
    ///   to write; the user connects in the portal to make it live.
    ///
    /// Both the web quickstart and the `ssai` CLI surface this so a
    /// user is warned to connect first; keep the two in sync.
    pub connection_status: String,
}

/// A virtual server the caller may use: enabled, and in one of their
/// workspaces' MCP allowlists (`$1` the user, `$2` the portal key's bound
/// workspace or NULL). The Default workspace gates on its explicit allowlist
/// like any other. A disabled server is hidden: the proxy rejects it at request
/// time, so the portal must not offer it.
pub(crate) const VISIBLE_VS: &str = "vs.enabled \
    AND vs.id IN ( \
          SELECT wma.virtual_server_id \
          FROM workspace_mcp_access wma \
          JOIN workspace_members wm ON wm.workspace_id = wma.workspace_id \
          WHERE wm.user_id = $1 \
            AND ($2::uuid IS NULL OR wm.workspace_id = $2))";

/// The virtual server `vs` has a `per_user_oauth` upstream the caller (`$1`,
/// in tenant `$3`) holds no present, unexpired credential for — the one test
/// behind `needs_connection` on the list and the portal Home's sign-in items.
const NEEDS_CONNECTION: &str = "EXISTS ( \
      SELECT 1 \
        FROM mcp_virtual_routes vr \
        JOIN mcp_upstream_servers us ON us.id = vr.upstream_server_id \
       WHERE vr.virtual_server_id = vs.id \
         AND vr.enabled \
         AND us.enabled \
         AND us.auth_mode = 'per_user_oauth' \
         AND NOT EXISTS ( \
               SELECT 1 \
                 FROM mcp_user_credentials c \
                WHERE c.tenant_id = $3 \
                  AND c.user_id = $1 \
                  AND c.upstream_server_id = us.id \
                  AND (c.expires_at IS NULL OR c.expires_at > now())))";

/// A virtual server waiting for the caller's sign-in.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalMcpSignInNeeded {
    pub slug: String,
    pub name: String,
}

/// The visible virtual servers that need the caller's sign-in (at most `limit`),
/// by slug — what `list_virtual_servers` marks `needs_connection`.
pub(crate) async fn servers_needing_sign_in(
    conn: &mut crate::db::tenant::Scoped,
    user: &PortalUser,
    tenant_id: Uuid,
    limit: i64,
) -> sqlx::Result<Vec<PortalMcpSignInNeeded>> {
    sqlx::query_as::<_, PortalMcpSignInNeeded>(sqlx::AssertSqlSafe(format!(
        "SELECT vs.slug, vs.name FROM mcp_virtual_servers vs \
          WHERE {VISIBLE_VS} AND {NEEDS_CONNECTION} ORDER BY vs.slug LIMIT $4"
    )))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .bind(tenant_id)
    .bind(limit)
    .fetch_all(&mut *conn)
    .await
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/mcp/virtual-servers",
    tag = "Portal MCP",
    operation_id = "portal_list_mcp_virtual_servers",
    params(PageQuery),
    responses(
        (status = 200, description = "Virtual servers the user's workspaces allowlist, by slug", body = TotalPage<PortalMcpVirtualServer>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_virtual_servers(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<PortalMcpVirtualServer>>, ApiError> {
    let (limit, offset) = page.resolve();
    let failed = |e: sqlx::Error| {
        tracing::error!("portal list mcp virtual servers: {e}");
        ApiError::internal("internal error")
    };
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM mcp_virtual_servers vs WHERE {VISIBLE_VS}"
    )))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_one(db.conn())
    .await
    .map_err(failed)?;
    let rows = sqlx::query_as::<_, PortalMcpVirtualServer>(sqlx::AssertSqlSafe(format!(
        r#"SELECT vs.id, vs.slug, vs.name, vs.description,
                  EXISTS (
                      SELECT 1
                        FROM mcp_virtual_routes vr
                        JOIN mcp_upstream_servers us ON us.id = vr.upstream_server_id
                       WHERE vr.virtual_server_id = vs.id
                         AND vr.enabled
                         AND us.enabled
                         AND us.built_in
                  ) AS built_in,
                  EXISTS (
                      SELECT 1
                        FROM mcp_virtual_routes vr
                        JOIN mcp_upstream_servers us ON us.id = vr.upstream_server_id
                       WHERE vr.virtual_server_id = vs.id
                         AND vr.enabled
                         AND us.enabled
                         AND us.auth_mode = 'per_user_oauth'
                  ) AS requires_connection,
                  CASE
                    WHEN NOT EXISTS (
                        SELECT 1
                          FROM mcp_virtual_routes vr
                          JOIN mcp_upstream_servers us ON us.id = vr.upstream_server_id
                         WHERE vr.virtual_server_id = vs.id
                           AND vr.enabled
                           AND us.enabled
                           AND us.auth_mode = 'per_user_oauth'
                    ) THEN 'none'
                    WHEN {NEEDS_CONNECTION} THEN 'needs_connection'
                    ELSE 'connected'
                  END AS connection_status
           FROM mcp_virtual_servers vs
           WHERE {VISIBLE_VS}
           ORDER BY vs.slug
           LIMIT $4 OFFSET $5"#
    )))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .bind(db.tenant_uuid())
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}
