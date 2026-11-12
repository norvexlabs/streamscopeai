//! Local MCP servers — MCP servers that run on the developer's machine.
//!
//! A local server is neither an upstream nor a virtual server: the gateway
//! never connects to it and no edge reads it. An administrator stores the
//! command line that starts it ([`LocalLaunch`]: typed by hand, or prefilled
//! from a catalog package at adopt), grants it to workspaces, and client
//! provisioning (the web Quickstart and `ssai provision`) writes it into a
//! member's client config. Every rule about a launch is read from
//! [`streamscope_core::mcp::local_server`], never restated here.

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;
use serde::{Deserialize, Serialize};
use streamscope_core::mcp::local_server::{is_display_text, LocalLaunch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::mcp::is_valid_slug;
use super::{is_unique_violation, ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn};

/// SELECT column list shared by every read and RETURNING.
const LOCAL_SELECT_COLS: &str =
    "id, slug, name, description, launch, catalog_entry_id, enabled, created_at, updated_at";

const MAX_NAME_CHARS: usize = 100;
const MAX_DESCRIPTION_CHARS: usize = 500;

#[derive(sqlx::FromRow)]
struct LocalRow {
    id: Uuid,
    slug: String,
    name: String,
    description: Option<String>,
    #[sqlx(json)]
    launch: LocalLaunch,
    catalog_entry_id: Option<Uuid>,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// A workspace a local server is granted to.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct McpLocalServerWorkspace {
    pub id: Uuid,
    pub name: String,
}

/// A local MCP server as returned to the console.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpLocalServer {
    pub id: Uuid,
    /// The server's key in a client's MCP config, and the prefix of its tool
    /// names (`mcp__<slug>__…`).
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    /// The command line a client config is written with.
    pub launch: LocalLaunch,
    /// `launch` as one line, for display: the administrator's environment
    /// values as `NAME=value`, then the command and its arguments, each part
    /// quoted as a shell would need it. A variable left to the developer is
    /// not in it.
    pub command_line: String,
    /// The catalog entry the server was adopted from, while it exists.
    pub catalog_entry_id: Option<Uuid>,
    pub enabled: bool,
    /// The workspaces the server is granted to, by name. Empty when none is.
    pub workspaces: Vec<McpLocalServerWorkspace>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

impl From<LocalRow> for McpLocalServer {
    fn from(r: LocalRow) -> Self {
        Self {
            id: r.id,
            slug: r.slug,
            name: r.name,
            description: r.description,
            command_line: r.launch.command_line(),
            launch: r.launch,
            catalog_entry_id: r.catalog_entry_id,
            enabled: r.enabled,
            workspaces: Vec::new(),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// The 400 for a launch the core model refuses: its `Display` is the message.
pub(crate) fn launch_error(e: &streamscope_core::mcp::local_server::LaunchError) -> ApiError {
    ApiError::bad_request(e.to_string()).code(ApiErrorCode::McpLocalServerInvalid)
}

pub(crate) fn validate_slug(slug: &str) -> Result<(), ApiError> {
    if is_valid_slug(slug) {
        return Ok(());
    }
    Err(ApiError::bad_request("slug must be 1–31 chars, start with a letter, and contain only a–z, 0–9, and -")
        .code(ApiErrorCode::McpLocalServerInvalid))
}

/// A name is what a developer picks the server by: it shows as it is stored
/// (no control, invisible or reordering character).
pub(crate) fn validate_name(name: &str) -> Result<(), ApiError> {
    if name.trim().is_empty()
        || name != name.trim()
        || name.chars().count() > MAX_NAME_CHARS
        || !is_display_text(name)
    {
        return Err(ApiError::bad_request(format!(
            "name must be 1–{MAX_NAME_CHARS} characters, without surrounding spaces, control or invisible characters"
        ))
        .code(ApiErrorCode::McpLocalServerInvalid));
    }
    Ok(())
}

/// Text taken from a catalog document as a default name or description, made
/// to fit the field: every run of whitespace (a newline, a tab) is one
/// space, the ends are trimmed, and it is cut to `max_chars` characters. What
/// an administrator types is validated as typed, never rewritten.
pub(crate) fn one_line(text: &str, max_chars: usize) -> String {
    let joined = text.split_whitespace().collect::<Vec<_>>().join(" ");
    joined.chars().take(max_chars).collect::<String>().trim_end().to_string()
}

/// [`one_line`] for a default name.
pub(crate) fn default_name(text: &str) -> String {
    one_line(text, MAX_NAME_CHARS)
}

/// [`one_line`] for a default description.
pub(crate) fn default_description(text: &str) -> String {
    one_line(text, MAX_DESCRIPTION_CHARS)
}

/// A description is one line, on create, edit and adopt alike: no control
/// character (so no newline or tab), no invisible or reordering one.
pub(crate) fn validate_description(description: Option<&str>) -> Result<(), ApiError> {
    if description.is_some_and(|d| d.chars().count() > MAX_DESCRIPTION_CHARS || !is_display_text(d)) {
        return Err(ApiError::bad_request(format!(
            "description must be one line of at most {MAX_DESCRIPTION_CHARS} characters, without control or invisible characters"
        ))
        .code(ApiErrorCode::McpLocalServerInvalid));
    }
    Ok(())
}

/// The 409 for a slug another local server or an MCP endpoint has.
pub(crate) fn slug_taken(message: &'static str) -> ApiError {
    ApiError::conflict(message, ApiErrorCode::McpLocalServerSlugTaken)
}

/// Whether an MCP endpoint or a local server has this slug: one namespace
/// for both kinds, since a client config holds one entry per slug.
pub(crate) async fn slug_is_taken(conn: &mut Scoped, slug: &str) -> Result<bool, ApiError> {
    sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM mcp_virtual_servers WHERE slug = $1) \
             OR EXISTS (SELECT 1 FROM mcp_local_servers WHERE slug = $1)",
    )
    .bind(slug)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "local server: slug check");
        ApiError::internal("failed to save local server")
    })
}

/// Refuse a slug that is taken ([`slug_is_taken`]) — what a new local server
/// is checked by, typed or adopted. Best effort against an endpoint created
/// at the same moment: a clash that slips through is caught when a config is
/// rendered.
pub(crate) async fn refuse_taken_slug(conn: &mut Scoped, slug: &str) -> Result<(), ApiError> {
    if slug_is_taken(conn, slug).await? {
        return Err(slug_taken(
            "a local server or an MCP endpoint already uses this slug — a client config holds one entry per slug",
        ));
    }
    Ok(())
}

/// A local server to insert, every field validated by the caller.
pub(crate) struct NewLocalServer<'a> {
    pub slug: &'a str,
    pub name: &'a str,
    pub description: Option<&'a str>,
    pub launch: &'a LocalLaunch,
    pub catalog_entry_id: Option<Uuid>,
    pub enabled: bool,
}

/// Fill each server's `workspaces` in one read, whatever the number of rows.
pub(crate) async fn with_workspaces(conn: &mut Scoped, servers: &mut [McpLocalServer]) -> Result<(), ApiError> {
    if servers.is_empty() {
        return Ok(());
    }
    let ids: Vec<Uuid> = servers.iter().map(|s| s.id).collect();
    let rows: Vec<(Uuid, Uuid, String)> = sqlx::query_as(
        "SELECT a.local_server_id, w.id, w.name FROM workspace_mcp_local_access a \
           JOIN workspaces w ON w.tenant_id = a.tenant_id AND w.id = a.workspace_id \
          WHERE a.local_server_id = ANY($1) ORDER BY lower(w.name), w.id",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "load local servers' workspaces");
        ApiError::internal("failed to load local servers")
    })?;
    for (server_id, id, name) in rows {
        if let Some(server) = servers.iter_mut().find(|s| s.id == server_id) {
            server.workspaces.push(McpLocalServerWorkspace { id, name });
        }
    }
    Ok(())
}

/// Grant `server_id` to each of `workspace_ids`, refusing — before anything
/// is written — a workspace that does not exist in the tenant, and the Agent
/// and Inline AI workspaces: they hold the gateway's own keys and have no
/// developer to hand a local server to. The one gate every grant goes through.
pub(crate) async fn grant_to_workspaces(
    conn: &mut Scoped,
    tenant_id: Uuid,
    server_id: Uuid,
    workspace_ids: &[Uuid],
) -> Result<i64, ApiError> {
    ensure_developer_workspaces(conn, workspace_ids).await?;
    let mut granted = 0i64;
    for ws_id in workspace_ids {
        granted += sqlx::query(
            "INSERT INTO workspace_mcp_local_access (workspace_id, local_server_id, tenant_id) \
             VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
        )
        .bind(ws_id)
        .bind(server_id)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "grant local server");
            ApiError::internal("failed to grant local MCP server")
        })?
        .rows_affected() as i64;
    }
    Ok(granted)
}

/// Every one of `workspace_ids` is a workspace of this tenant that has
/// developers: 404 for one that is not there, 400 for the Agent or the Inline
/// AI workspace.
pub(crate) async fn ensure_developer_workspaces(conn: &mut Scoped, workspace_ids: &[Uuid]) -> Result<(), ApiError> {
    if workspace_ids.is_empty() {
        return Ok(());
    }
    // RLS scopes the read: an id of another tenant is simply not found.
    let rows: Vec<(Uuid, String, String)> =
        sqlx::query_as("SELECT id, role, name FROM workspaces WHERE id = ANY($1)")
            .bind(workspace_ids)
            .fetch_all(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!(error = %e, "read workspaces for a local server grant");
                ApiError::internal("failed to grant local MCP server")
            })?;
    for ws_id in workspace_ids {
        let Some((_, role, name)) = rows.iter().find(|(id, _, _)| id == ws_id) else {
            return Err(ApiError::not_found("workspace not found", ApiErrorCode::WorkspaceNotFound));
        };
        if matches!(role.as_str(), "agent" | "inline") {
            return Err(ApiError::bad_request(format!(
                "the '{name}' workspace has no developers: a local MCP server cannot be granted to it"
            ))
            .code(ApiErrorCode::McpLocalServerWorkspaceIneligible));
        }
    }
    Ok(())
}

/// Insert one local server.
pub(crate) async fn insert_local_server(
    conn: &mut Scoped,
    tenant_id: Uuid,
    new: NewLocalServer<'_>,
) -> Result<McpLocalServer, ApiError> {
    let sql = format!(
        "INSERT INTO mcp_local_servers (tenant_id, slug, name, description, launch, catalog_entry_id, enabled) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING {LOCAL_SELECT_COLS}"
    );
    sqlx::query_as::<_, LocalRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(new.slug)
        .bind(new.name)
        .bind(new.description)
        .bind(sqlx::types::Json(new.launch))
        .bind(new.catalog_entry_id)
        .bind(new.enabled)
        .fetch_one(&mut *conn)
        .await
        .map(McpLocalServer::from)
        .map_err(|e| {
            if is_unique_violation(&e) {
                return slug_taken(
                    "a local server or an MCP endpoint already uses this slug — a client config holds one entry per slug",
                );
            }
            tracing::error!(error = %e, "insert local server");
            ApiError::internal("failed to create local server")
        })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/local-servers",
    tag = "MCP Local Servers",
    params(PageQuery),
    responses(
        (status = 200, description = "Local MCP servers, by name", body = OffsetPage<McpLocalServer>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mcp_local_servers(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<McpLocalServer>>, ApiError> {
    let (limit, offset) = page.resolve();
    let sql = format!(
        "SELECT {LOCAL_SELECT_COLS} FROM mcp_local_servers ORDER BY lower(name), id LIMIT $1 OFFSET $2"
    );
    let rows = sqlx::query_as::<_, LocalRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(limit + 1)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "list local servers");
            ApiError::internal("failed to list local servers")
        })?;
    let mut rows: Vec<McpLocalServer> = rows.into_iter().map(McpLocalServer::from).collect();
    with_workspaces(db.conn(), &mut rows).await?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/local-servers/{id}",
    tag = "MCP Local Servers",
    params(("id" = Uuid, Path, description = "Local server ID")),
    responses(
        (status = 200, description = "Local MCP server", body = McpLocalServer),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mcp_local_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<McpLocalServer>, ApiError> {
    let sql = format!("SELECT {LOCAL_SELECT_COLS} FROM mcp_local_servers WHERE id = $1");
    let server = sqlx::query_as::<_, LocalRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "get local server");
            ApiError::internal("failed to get local server")
        })?
        .map(McpLocalServer::from)
        .ok_or(ApiError::not_found("local server not found", ApiErrorCode::McpLocalServerNotFound))?;
    let mut servers = [server];
    with_workspaces(db.conn(), &mut servers).await?;
    let [server] = servers;
    Ok(Json(server))
}

/// Request body for creating a local server from a typed command line.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMcpLocalServer {
    pub slug: String,
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    pub launch: LocalLaunch,
    #[serde(default)]
    pub enabled: Option<bool>,
    /// Workspaces to grant the new server to. The Agent and Inline AI
    /// workspaces are refused.
    #[serde(default)]
    pub workspace_ids: Vec<Uuid>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/local-servers",
    tag = "MCP Local Servers",
    request_body = CreateMcpLocalServer,
    responses(
        (status = 201, description = "Local server created", body = McpLocalServer),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 404, description = "A workspace to grant it to was not found", body = ApiErrorResponse),
        (status = 409, description = "Slug taken", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mcp_local_server(
    mut db: TenantConn,
    Json(req): Json<CreateMcpLocalServer>,
) -> Result<(StatusCode, Json<McpLocalServer>), ApiError> {
    validate_slug(&req.slug)?;
    validate_name(&req.name)?;
    let description = req.description.as_deref().map(str::trim).filter(|d| !d.is_empty());
    validate_description(description)?;
    req.launch.validate().map_err(|e| launch_error(&e))?;
    refuse_taken_slug(db.conn(), &req.slug).await?;
    let tenant_id = db.tenant_uuid();
    // The server and its grants are one write: a refused workspace leaves no
    // server behind.
    let fail = |e: sqlx::Error| {
        tracing::error!(error = %e, "create local server");
        ApiError::internal("failed to create local server")
    };
    let mut tx = db.conn().begin().await.map_err(fail)?;
    let row = insert_local_server(
        &mut tx,
        tenant_id,
        NewLocalServer {
            slug: &req.slug,
            name: &req.name,
            description,
            launch: &req.launch,
            catalog_entry_id: None,
            enabled: req.enabled.unwrap_or(true),
        },
    )
    .await?;
    grant_to_workspaces(&mut tx, tenant_id, row.id, &req.workspace_ids).await?;
    let mut servers = [row];
    with_workspaces(&mut tx, &mut servers).await?;
    tx.commit().await.map_err(fail)?;
    let [row] = servers;
    Ok((StatusCode::CREATED, Json(row)))
}

/// Request body for editing a local server. Omitted fields are unchanged;
/// `launch` replaces the whole command line, except that a variable stored as
/// secret keeps the mark for as long as it exists: it is marked again whatever
/// the body says, and a value for it is refused. A variable the body no
/// longer carries is removed, mark included.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMcpLocalServer {
    /// A local server keeps the slug it was created with: it is the server's
    /// key in every client config already written. Any other value is refused
    /// (`mcp_local_server_slug_immutable`).
    #[serde(default)]
    pub slug: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// Absent leaves it; `null` (or blank) clears it.
    #[serde(default, deserialize_with = "super::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub description: Option<Option<String>>,
    #[serde(default)]
    pub launch: Option<LocalLaunch>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/mcp/local-servers/{id}",
    tag = "MCP Local Servers",
    params(("id" = Uuid, Path, description = "Local server ID")),
    request_body = UpdateMcpLocalServer,
    responses(
        (status = 200, description = "Local server updated", body = McpLocalServer),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_mcp_local_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateMcpLocalServer>,
) -> Result<Json<McpLocalServer>, ApiError> {
    if let Some(name) = &req.name {
        validate_name(name)?;
    }
    // A blank description clears it, as `null` does.
    let description: Option<Option<String>> = req
        .description
        .map(|d| d.map(|s| s.trim().to_string()).filter(|s| !s.is_empty()));
    validate_description(description.as_ref().and_then(|d| d.as_deref()))?;
    let fail = |e: sqlx::Error| {
        tracing::error!(error = %e, "update local server");
        ApiError::internal("failed to update local server")
    };
    // The stored row is read and rewritten in one transaction, locked: the
    // secret marks kept below are the ones of the launch this write replaces,
    // whatever another edit does meanwhile.
    let mut tx = db.conn().begin().await.map_err(fail)?;
    let stored: Option<(String, sqlx::types::Json<LocalLaunch>)> =
        sqlx::query_as("SELECT slug, launch FROM mcp_local_servers WHERE id = $1 FOR UPDATE")
            .bind(id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(fail)?;
    let Some((stored_slug, stored_launch)) = stored else {
        return Err(ApiError::not_found("local server not found", ApiErrorCode::McpLocalServerNotFound));
    };
    // The slug is the server's key in every client config already written,
    // and what a developer's machine finds its entry by when the server is
    // withdrawn: it never changes.
    if req.slug.as_deref().is_some_and(|slug| slug != stored_slug) {
        return Err(ApiError::bad_request(
            "a local server's slug cannot be changed: client configs already written hold it under this slug — \
             delete the server and add it again under the new one",
        )
        .code(ApiErrorCode::McpLocalServerSlugImmutable));
    }
    let mut launch = req.launch;
    if let Some(launch) = &mut launch {
        launch.keep_secrets(Some(&stored_launch.0), &[]);
        launch.validate().map_err(|e| launch_error(&e))?;
    }
    let sql = format!(
        "UPDATE mcp_local_servers SET \
           name        = COALESCE($2, name), \
           description = CASE WHEN $3 THEN $4 ELSE description END, \
           launch      = COALESCE($5, launch), \
           enabled     = COALESCE($6, enabled), \
           updated_at  = NOW() \
         WHERE id = $1 RETURNING {LOCAL_SELECT_COLS}"
    );
    let row = sqlx::query_as::<_, LocalRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(req.name.as_deref())
        .bind(description.is_some())
        .bind(description.flatten())
        .bind(launch.as_ref().map(sqlx::types::Json))
        .bind(req.enabled)
        .fetch_one(&mut *tx)
        .await
        .map_err(fail)?;
    let mut servers = [McpLocalServer::from(row)];
    with_workspaces(&mut tx, &mut servers).await?;
    tx.commit().await.map_err(fail)?;
    let [server] = servers;
    Ok(Json(server))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/local-servers/{id}",
    tag = "MCP Local Servers",
    params(("id" = Uuid, Path, description = "Local server ID")),
    responses(
        (status = 200, description = "Local server deleted, with its workspace grants", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mcp_local_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let deleted = sqlx::query("DELETE FROM mcp_local_servers WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "delete local server");
            ApiError::internal("failed to delete local server")
        })?
        .rows_affected();
    if deleted == 0 {
        return Err(ApiError::not_found("local server not found", ApiErrorCode::McpLocalServerNotFound));
    }
    Ok(Json(ActionResponse::ok()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A default taken from a catalog document fits the field it fills: one
    /// line, trimmed, cut on a character — and then passes the rule a typed
    /// value is held to, which refuses the same text as it stood.
    #[test]
    fn a_catalog_default_is_made_one_line_that_fits_its_field() {
        let raw = "  Reads files.\n\n\tWrites   them too.\r\n";
        assert!(validate_description(Some(raw)).is_err());
        let fitted = default_description(raw);
        assert_eq!(fitted, "Reads files. Writes them too.");
        assert!(validate_description(Some(&fitted)).is_ok());

        assert_eq!(default_name(" Files\nserver "), "Files server");
        // Cut to the limit by characters, on both sides of it, never inside one.
        let exact: String = "é".repeat(MAX_NAME_CHARS);
        assert_eq!(default_name(&exact), exact);
        let over = format!("{exact}é");
        assert_eq!(default_name(&over), exact);
        assert!(validate_name(&default_name(&over)).is_ok() && validate_name(&over).is_err());
        // A cut that lands on a space leaves no trailing one.
        let spaced = format!("{} tail", "a".repeat(MAX_NAME_CHARS - 1));
        assert_eq!(default_name(&spaced), "a".repeat(MAX_NAME_CHARS - 1));
        // What fitting cannot repair still fails, naming its field.
        let hidden = default_name("Files\u{202E}server");
        let refused = validate_name(&hidden).expect_err("a reordering character");
        assert!(format!("{refused:?}").contains("name must"), "{refused:?}");
    }
}
