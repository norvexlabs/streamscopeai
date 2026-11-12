//! Portal — MCP self-service.
//!
//! Portal users land here to list the MCP virtual servers their workspaces
//! allowlist. Keys are minted through the unified portal `/keys` endpoint — a
//! single key spans both LLM and MCP, gated per request by the workspace
//! allowlist — so there is no MCP-specific key flow.
//!
//! They also list the local MCP servers their workspaces are handed: servers
//! their own machine starts, which client provisioning writes into a client
//! config as a command line. The gateway is not on that path.

use axum::extract::Query;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use streamscope_core::mcp::local_server::LocalLaunch;
use utoipa::{IntoParams, ToSchema};
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
    /// `true` when at least one of this virtual server's routes points at an
    /// upstream that asks something of each user — a `per_user_oauth` one
    /// (link their own account) or one with required user-filled inputs —
    /// before requests through this server succeed.
    pub requires_connection: bool,
    /// Aggregate connection state for the **current user**:
    /// - `none` — no upstream asks anything of the user (nothing to connect).
    /// - `connected` — on every such upstream the user holds a present,
    ///   unexpired OAuth credential where one is needed and has filled every
    ///   required input.
    /// - `needs_connection` — at least one is missing. The config is still
    ///   valid to write; the user connects in the portal to make it live.
    ///
    /// Both the web quickstart and the `ssai` CLI surface this so a
    /// user is warned to connect first; keep the two in sync.
    pub connection_status: String,
    /// The headers the client must send itself (lowercased): the
    /// client-filled inputs of the routed upstreams.
    #[sqlx(skip)]
    pub client_headers: Vec<String>,
    /// `true` when one of those headers is `Authorization`: the gateway key
    /// then rides the `/fwd/{key}/mcp/<slug>` path.
    #[sqlx(skip)]
    pub fwd_mount: bool,
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

/// The upstream `us` asks something of each user: their OAuth token, or a
/// required user-filled input.
const ASKS_USER: &str = "(us.auth_mode = 'per_user_oauth' OR cardinality(us.required_user_input_ids) > 0)";

/// The virtual server `vs` has an upstream the caller (`$1`, in tenant `$3`)
/// is not connected to: per-user OAuth with no present, unexpired credential,
/// or a required user input with no value — the one test behind
/// `needs_connection` on the list and the portal Home's sign-in items, and the
/// connections list's own status (`portal_mcp_connections::connection_status`).
const NEEDS_CONNECTION: &str = "EXISTS ( \
      SELECT 1 \
        FROM mcp_virtual_routes vr \
        JOIN mcp_upstream_servers us ON us.id = vr.upstream_server_id \
       WHERE vr.virtual_server_id = vs.id \
         AND vr.enabled \
         AND us.enabled \
         AND ((us.auth_mode = 'per_user_oauth' \
               AND NOT EXISTS ( \
                     SELECT 1 \
                       FROM mcp_user_credentials c \
                      WHERE c.tenant_id = $3 \
                        AND c.user_id = $1 \
                        AND c.upstream_server_id = us.id \
                        AND (c.expires_at IS NULL OR c.expires_at > now()))) \
              OR NOT (us.required_user_input_ids <@ ARRAY( \
                     SELECT jsonb_object_keys(i.encrypted_values) \
                       FROM mcp_user_inputs i \
                      WHERE i.tenant_id = $3 \
                        AND i.user_id = $1 \
                        AND i.upstream_server_id = us.id))))";

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

/// How many visible virtual servers need the caller's sign-in — the count
/// [`servers_needing_sign_in`] lists the first of.
pub(crate) async fn count_servers_needing_sign_in(
    conn: &mut crate::db::tenant::Scoped,
    user: &PortalUser,
    tenant_id: Uuid,
) -> sqlx::Result<i64> {
    sqlx::query_scalar::<_, i64>(sqlx::AssertSqlSafe(format!(
        "SELECT count(*) FROM mcp_virtual_servers vs WHERE {VISIBLE_VS} AND {NEEDS_CONNECTION}"
    )))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await
}

/// Which of the caller's workspaces the list is for.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalVirtualServersQuery {
    /// Only the virtual servers this workspace grants — what a configuration
    /// made for it can use. The caller must be a member. Left out: every
    /// virtual server any of the caller's workspaces grants (an `ak-` key: its
    /// bound workspace's).
    pub workspace_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/mcp/virtual-servers",
    tag = "Portal MCP",
    operation_id = "portal_list_mcp_virtual_servers",
    params(PortalVirtualServersQuery, PageQuery),
    responses(
        (status = 200, description = "Virtual servers the user's workspaces allowlist — or the one workspace named — by slug", body = TotalPage<PortalMcpVirtualServer>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Not a member of the workspace named, or a key bound to another", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_virtual_servers(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(q): Query<PortalVirtualServersQuery>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<PortalMcpVirtualServer>>, ApiError> {
    let (limit, offset) = page.resolve();
    // `VISIBLE_VS` narrows to one workspace when `$2` names it: the one asked
    // for, once the caller is established as a member of it, else a key's own.
    let scope = match q.workspace_id {
        Some(asked) => {
            Some(super::portal_manager::require_workspace_member(db.conn(), &user, asked).await?.workspace_id())
        }
        None => user.key_workspace_id,
    };
    let failed = |e: sqlx::Error| {
        tracing::error!("portal list mcp virtual servers: {e}");
        ApiError::internal("internal error")
    };
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM mcp_virtual_servers vs WHERE {VISIBLE_VS}"
    )))
    .bind(user.user_id)
    .bind(scope)
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
                         AND {ASKS_USER}
                  ) AS requires_connection,
                  CASE
                    WHEN NOT EXISTS (
                        SELECT 1
                          FROM mcp_virtual_routes vr
                          JOIN mcp_upstream_servers us ON us.id = vr.upstream_server_id
                         WHERE vr.virtual_server_id = vs.id
                           AND vr.enabled
                           AND us.enabled
                           AND {ASKS_USER}
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
    .bind(scope)
    .bind(db.tenant_uuid())
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;
    let mut rows = rows;
    let ids: Vec<Uuid> = rows.iter().map(|r| r.id).collect();
    let mut facts = super::mcp_inputs::vs_client_facts(db.conn(), &ids).await?;
    for r in &mut rows {
        let f = facts.remove(&r.id).unwrap_or_default();
        r.client_headers = f.client_headers;
        r.fwd_mount = f.fwd_mount;
    }
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[derive(sqlx::FromRow)]
struct LocalRow {
    id: Uuid,
    slug: String,
    name: String,
    description: Option<String>,
    #[sqlx(json)]
    launch: LocalLaunch,
}

/// A local MCP server a member's workspace is handed: a server their own
/// machine starts.
#[derive(Serialize, ToSchema)]
pub struct PortalMcpLocalServer {
    pub id: Uuid,
    /// The server's key in the client's MCP config.
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    /// The command line the client config is written with. An `env` entry
    /// with no value is the member's to fill in their own config.
    pub launch: LocalLaunch,
    /// `launch` as one line, for display: the administrator's environment
    /// values as `NAME=value`, then the command and its arguments, each part
    /// quoted as a shell would need it.
    pub command_line: String,
}

/// A local server the caller is handed: enabled, and granted to one of their
/// workspaces (`$1` the user, `$2` the one workspace the list is for or NULL)
/// — the shape of [`VISIBLE_VS`].
const VISIBLE_LOCAL: &str = "l.enabled \
    AND l.id IN ( \
          SELECT a.local_server_id \
          FROM workspace_mcp_local_access a \
          JOIN workspace_members wm ON wm.workspace_id = a.workspace_id \
          WHERE wm.user_id = $1 \
            AND ($2::uuid IS NULL OR wm.workspace_id = $2))";

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct LocalServersQuery {
    /// Only the servers this workspace is handed — what a configuration made
    /// for it can carry. The caller must be a member. Left out: every server
    /// any of the caller's workspaces is handed (an `ak-` key: its bound
    /// workspace's).
    pub workspace_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/mcp/local-servers",
    tag = "Portal MCP",
    operation_id = "portal_list_mcp_local_servers",
    params(PageQuery, LocalServersQuery),
    responses(
        (status = 200, description = "Local MCP servers the user's workspaces are handed — or the one workspace named — by slug", body = TotalPage<PortalMcpLocalServer>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Not a member of the workspace named, or a key bound to another", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_local_servers(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(page): Query<PageQuery>,
    Query(q): Query<LocalServersQuery>,
) -> Result<Json<TotalPage<PortalMcpLocalServer>>, ApiError> {
    let (limit, offset) = page.resolve();
    // As for the virtual servers: the workspace asked for, once the caller is
    // established as a member of it, else a key's own.
    let scope = match q.workspace_id {
        Some(asked) => {
            Some(super::portal_manager::require_workspace_member(db.conn(), &user, asked).await?.workspace_id())
        }
        None => user.key_workspace_id,
    };
    let failed = |e: sqlx::Error| {
        tracing::error!("portal list mcp local servers: {e}");
        ApiError::internal("internal error")
    };
    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*) FROM mcp_local_servers l WHERE {VISIBLE_LOCAL}"
    )))
    .bind(user.user_id)
    .bind(scope)
    .fetch_one(db.conn())
    .await
    .map_err(failed)?;
    let rows = sqlx::query_as::<_, LocalRow>(sqlx::AssertSqlSafe(format!(
        "SELECT l.id, l.slug, l.name, l.description, l.launch FROM mcp_local_servers l \
          WHERE {VISIBLE_LOCAL} ORDER BY l.slug LIMIT $3 OFFSET $4"
    )))
    .bind(user.user_id)
    .bind(scope)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;
    let rows: Vec<PortalMcpLocalServer> = rows
        .into_iter()
        .map(|r| PortalMcpLocalServer {
            id: r.id,
            slug: r.slug,
            name: r.name,
            description: r.description,
            command_line: r.launch.command_line(),
            launch: r.launch,
        })
        .collect();
    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}
