//! MCP server catalog — a curated, browsable list of remote MCP servers.
//!
//! Tenant-scoped seed data (mirrors `model_catalog`): every tenant gets the
//! shipped catalog seeded as builtins; an admin browses it here and (slice 2)
//! adopts an entry in one click to provision the real upstream + virtual server
//! + route + workspace grants.
//!
//! This module is the read-only browse surface (list + detail).

use super::is_unique_violation;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::TenantConn;
use crate::routes::mcp::{encrypt_mcp_credential, is_valid_slug};
use crate::seed_loader::McpCatalogTool;

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;

/// sqlx-compatible JSONB wrapper for the tools list; serialised transparently as
/// the inner array so the wire shape stays `[{ name, description? }]`.
type CatalogTools = sqlx::types::Json<Vec<McpCatalogTool>>;

/// SELECT column list shared by list + detail queries.
const CATALOG_SELECT_COLS: &str = r#"
    id, source, source_name, name, display_title, description, category, featured,
    website_url, repository_url, icon_url, upstream_url, transport, auth_mode,
    oauth_issuer_url, oauth_authorization_url, oauth_token_url, oauth_revocation_url,
    oauth_default_scopes, tools, tool_count, liveness, is_builtin, enabled,
    created_at, updated_at
"#;

/// A catalog entry as returned to the admin UI.
#[derive(Debug, Serialize, sqlx::FromRow, ToSchema)]
pub struct McpCatalogEntry {
    pub id: Uuid,
    pub source: Option<String>,
    pub source_name: String,
    pub name: String,
    pub display_title: Option<String>,
    pub description: Option<String>,
    pub category: Option<String>,
    pub featured: bool,
    pub website_url: Option<String>,
    pub repository_url: Option<String>,
    pub icon_url: Option<String>,
    pub upstream_url: String,
    pub transport: String,
    pub auth_mode: String,
    pub oauth_issuer_url: Option<String>,
    pub oauth_authorization_url: Option<String>,
    pub oauth_token_url: Option<String>,
    pub oauth_revocation_url: Option<String>,
    pub oauth_default_scopes: Vec<String>,
    #[schema(value_type = Vec<McpCatalogToolSchema>)]
    pub tools: CatalogTools,
    pub tool_count: Option<i32>,
    pub liveness: Option<String>,
    pub is_builtin: bool,
    pub enabled: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// OpenAPI projection of the JSONB `tools` element (the row type uses the
/// `sqlx::types::Json` wrapper, which isn't itself `ToSchema`).
#[derive(Debug, Serialize, ToSchema)]
#[allow(dead_code)]
pub struct McpCatalogToolSchema {
    pub name: String,
    pub description: Option<String>,
}

/// Static per-provider OAuth-setup guides for the upstream-server modal.
#[derive(Debug, Serialize, ToSchema)]
pub struct OauthProviderRecipesResponse {
    pub recipes: Vec<crate::seed_loader::OauthProviderRecipe>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/oauth-provider-recipes",
    tag = "MCP Catalog",
    responses(
        (status = 200, description = "Provider OAuth-app setup guides", body = OauthProviderRecipesResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_oauth_provider_recipes(
    _db: TenantConn,
) -> Result<Json<OauthProviderRecipesResponse>, ApiError> {
    Ok(Json(OauthProviderRecipesResponse {
        recipes: crate::seed_loader::load_oauth_provider_recipes().to_vec(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/catalog",
    tag = "MCP Catalog",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of catalog entries", body = TotalPage<McpCatalogEntry>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_mcp_catalog(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<McpCatalogEntry>>, ApiError> {
    let (limit, offset) = page.resolve();
    let total: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mcp_catalog WHERE NOT suppressed")
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to count mcp catalog");
            ApiError::internal("failed to list mcp catalog")
        })?;

    let sql = format!(
        r#"SELECT {CATALOG_SELECT_COLS}
           FROM mcp_catalog
           WHERE NOT suppressed
           ORDER BY featured DESC, lower(name)
           LIMIT $1 OFFSET $2"#
    );
    let rows = sqlx::query_as::<_, McpCatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list mcp catalog");
            ApiError::internal("failed to list mcp catalog")
        })?;

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/mcp/catalog/{id}",
    tag = "MCP Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    responses(
        (status = 200, description = "Catalog entry", body = McpCatalogEntry),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_mcp_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<McpCatalogEntry>, ApiError> {
    let sql = format!(
        r#"SELECT {CATALOG_SELECT_COLS} FROM mcp_catalog WHERE id = $1 AND NOT suppressed"#
    );
    let row = sqlx::query_as::<_, McpCatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to get mcp catalog entry");
            ApiError::internal("failed to get mcp catalog entry")
        })?
        .ok_or(
            ApiError::not_found("catalog entry not found", ApiErrorCode::McpCatalogEntryNotFound),
        )?;

    Ok(Json(row))
}

// ── Adopt: provision the full MCP chain from a catalog entry ────────────────

/// Request body for adopting a catalog entry.
#[derive(Debug, Deserialize, ToSchema)]
pub struct AdoptCatalogEntry {
    /// Slug for the new `/mcp/<slug>` endpoint. Defaults to a slugified name;
    /// a numeric suffix is appended on collision.
    #[serde(default)]
    pub slug: Option<String>,
    /// Shared bearer token — required when the entry's `auth_mode` is
    /// `service_account`. Encrypted at rest.
    #[serde(default)]
    pub credential: Option<String>,
    /// OAuth client id/secret to register on the upstream (per_user_oauth).
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
    /// Workspaces to grant the new endpoint to.
    #[serde(default)]
    pub workspace_ids: Vec<Uuid>,
}

/// Result of an adopt action.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdoptResult {
    pub upstream_id: Uuid,
    pub virtual_server_id: Uuid,
    pub slug: String,
    pub workspaces_granted: i64,
}

/// Turn an arbitrary display name into a valid `/mcp/<slug>` slug
/// (`^[a-z][a-z0-9-]{0,30}$`): lowercase, non-alnum → `-`, collapse repeats,
/// trim, ensure a leading letter, cap length. Returns `"server"` as a fallback.
fn slugify(name: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for ch in name.to_lowercase().chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch);
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        return "server".to_string();
    }
    let mut slug: String = trimmed.chars().take(31).collect();
    // Guarantee a leading ascii letter.
    if !slug.chars().next().is_some_and(|c| c.is_ascii_lowercase()) {
        slug = format!("s{slug}");
        slug.truncate(31);
    }
    let slug = slug.trim_end_matches('-').to_string();
    if slug.is_empty() { "server".to_string() } else { slug }
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/catalog/{id}/actions/adopt",
    tag = "MCP Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    request_body = AdoptCatalogEntry,
    responses(
        (status = 200, description = "Catalog entry adopted", body = AdoptResult),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
// The action is audited by the admin middleware (actor + path + request body).
// The generic change-diff registry maps this route to `mcp_catalog`, whose row
// adopt never mutates, so the before/after diff is intentionally empty — the
// provisioned upstream/endpoint ids ride the response, not a row diff.
pub async fn adopt_mcp_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<AdoptCatalogEntry>,
) -> Result<Json<AdoptResult>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Load the source entry (RLS-scoped).
    let sql = format!(r#"SELECT {CATALOG_SELECT_COLS} FROM mcp_catalog WHERE id = $1 AND NOT suppressed"#);
    let entry = sqlx::query_as::<_, McpCatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "adopt: load catalog entry");
            ApiError::internal("failed to adopt catalog entry")
        })?
        .ok_or(
            ApiError::not_found("catalog entry not found", ApiErrorCode::McpCatalogEntryNotFound),
        )?;

    // service_account upstreams are useless without their shared token.
    let credential = req.credential.as_deref().filter(|c| !c.is_empty());
    if entry.auth_mode == "service_account" && credential.is_none() {
        return Err(ApiError::bad_request(
            "this server uses a shared service-account token — provide the credential to adopt it",
        )
        .code(ApiErrorCode::McpCatalogCredentialRequired));
    }
    let encrypted_credential = encrypt_mcp_credential(credential)?;
    let oauth_client_secret = req.oauth_client_secret.as_deref().filter(|c| !c.is_empty());
    let encrypted_oauth_secret = encrypt_mcp_credential(oauth_client_secret)?;
    let oauth_client_id = req.oauth_client_id.as_deref().filter(|c| !c.is_empty());

    // A per_user_oauth endpoint can't be granted to a workspace until its
    // shared OAuth-App client is set — granting one would yield an endpoint
    // that fails every portal connect. Adopting *without* a workspace stays
    // allowed so the operator can configure the client and grant later. The
    // required-field set mirrors `ensure_endpoint_oauth_grantable` and the
    // portal connect path (client_id, secret, authorization_url, token_url).
    if entry.auth_mode == "per_user_oauth" && !req.workspace_ids.is_empty() {
        let missing = super::mcp::oauth_client_missing_fields(
            oauth_client_id,
            encrypted_oauth_secret.is_some(),
            entry.oauth_authorization_url.as_deref(),
            entry.oauth_token_url.as_deref(),
        );
        if !missing.is_empty() {
            return Err(ApiError::bad_request(format!(
                "this server uses per_user_oauth — provide the OAuth client ID and secret to \
                 grant it to a workspace (missing: {}); or adopt without a workspace and \
                 configure the client first",
                missing.join(", ")
            ))
            .code(ApiErrorCode::McpUpstreamOauthClientIncomplete));
        }
    }

    // Resolve a unique, valid slug.
    let base_slug = match req.slug.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            if !is_valid_slug(s) {
                return Err(ApiError::bad_request(
                    "slug must be 1–31 chars, start with a letter, and contain only a–z, 0–9, and -",
                )
                .code(ApiErrorCode::McpVirtualServerSlugInvalid));
            }
            s.to_string()
        }
        None => slugify(&entry.name),
    };
    let slug = unique_slug(&mut db, &base_slug).await?;
    // Upstream names are UNIQUE per tenant — adopting the same entry twice must
    // not collide, so resolve a free name the same way as the slug.
    let upstream_name = unique_upstream_name(&mut db, &entry.name).await?;

    let oauth_scopes: &[String] = &entry.oauth_default_scopes;

    // Provision upstream + virtual server + route + workspace grants atomically.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!(error = %e, "adopt: begin tx");
        ApiError::internal("failed to adopt catalog entry")
    })?;

    let upstream_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_upstream_servers \
           (tenant_id, name, description, upstream_url, transport, auth_mode, enabled, \
            encrypted_credential, oauth_issuer_url, oauth_authorization_url, oauth_token_url, \
            oauth_revocation_url, oauth_client_id, encrypted_oauth_client_secret, oauth_default_scopes) \
         VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, $9, $10, $11, $12, $13, $14) \
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(&upstream_name)
    .bind(&entry.description)
    .bind(&entry.upstream_url)
    .bind(&entry.transport)
    .bind(&entry.auth_mode)
    .bind(&encrypted_credential)
    .bind(&entry.oauth_issuer_url)
    .bind(&entry.oauth_authorization_url)
    .bind(&entry.oauth_token_url)
    .bind(&entry.oauth_revocation_url)
    .bind(oauth_client_id)
    .bind(&encrypted_oauth_secret)
    .bind(if oauth_scopes.is_empty() { None } else { Some(oauth_scopes) })
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        // The pre-resolved name only collides under a concurrent adopt race.
        if is_unique_violation(&e) {
            return ApiError::conflict("an upstream server with this name already exists", ApiErrorCode::McpUpstreamServerNameTaken);
        }
        tracing::error!(error = %e, "adopt: insert upstream");
        ApiError::internal("failed to create upstream server").code(ApiErrorCode::McpCatalogAdoptFailed)
    })?;

    let virtual_server_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_virtual_servers (tenant_id, slug, name, description, enabled) \
         VALUES ($1, $2, $3, $4, true) RETURNING id",
    )
    .bind(tenant_id)
    .bind(&slug)
    .bind(&upstream_name)
    .bind(&entry.description)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            return ApiError::conflict("an endpoint with this slug already exists", ApiErrorCode::McpVirtualServerSlugTaken);
        }
        tracing::error!(error = %e, "adopt: insert virtual server");
        ApiError::internal("failed to create endpoint").code(ApiErrorCode::McpCatalogAdoptFailed)
    })?;

    // Single route, empty prefix (only route on the endpoint).
    sqlx::query(
        "INSERT INTO mcp_virtual_routes \
           (tenant_id, virtual_server_id, upstream_server_id, prefix, enabled, position) \
         VALUES ($1, $2, $3, '', true, 0)",
    )
    .bind(tenant_id)
    .bind(virtual_server_id)
    .bind(upstream_id)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "adopt: insert route");
        ApiError::internal("failed to attach upstream").code(ApiErrorCode::McpCatalogAdoptFailed)
    })?;

    let mut workspaces_granted = 0i64;
    for ws_id in &req.workspace_ids {
        let res = sqlx::query(
            "INSERT INTO workspace_mcp_access (workspace_id, virtual_server_id, tenant_id) \
             SELECT $1, $2, $3 WHERE EXISTS (SELECT 1 FROM workspaces WHERE id = $1) \
             ON CONFLICT DO NOTHING",
        )
        .bind(ws_id)
        .bind(virtual_server_id)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "adopt: grant workspace");
            ApiError::internal("failed to grant workspace").code(ApiErrorCode::McpCatalogAdoptFailed)
        })?;
        workspaces_granted += res.rows_affected() as i64;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "adopt: commit tx");
        ApiError::internal("failed to adopt catalog entry")
    })?;


    Ok(Json(AdoptResult { upstream_id, virtual_server_id, slug, workspaces_granted }))
}

/// Find a free slug from `base`, appending `-2`, `-3`, … on collision (capped
/// at the 31-char slug length).
async fn unique_slug(db: &mut TenantConn, base: &str) -> Result<String, ApiError> {
    for n in 1..=50 {
        let candidate = if n == 1 {
            base.to_string()
        } else {
            let suffix = format!("-{n}");
            let head: String = base.chars().take(31 - suffix.len()).collect();
            format!("{}{suffix}", head.trim_end_matches('-'))
        };
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM mcp_virtual_servers WHERE slug = $1)",
        )
        .bind(&candidate)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "adopt: slug uniqueness check");
            ApiError::internal("failed to adopt catalog entry")
        })?;
        if !taken {
            return Ok(candidate);
        }
    }
    Err(ApiError::bad_request("could not derive a free endpoint slug — pass one explicitly")
        .code(ApiErrorCode::McpVirtualServerSlugTaken))
}

/// Find a free upstream name from `base`, appending ` (2)`, ` (3)`, … on
/// collision with the per-tenant UNIQUE(name) constraint.
async fn unique_upstream_name(db: &mut TenantConn, base: &str) -> Result<String, ApiError> {
    for n in 1..=50 {
        let candidate = if n == 1 { base.to_string() } else { format!("{base} ({n})") };
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM mcp_upstream_servers WHERE name = $1)",
        )
        .bind(&candidate)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "adopt: upstream-name uniqueness check");
            ApiError::internal("failed to adopt catalog entry")
        })?;
        if !taken {
            return Ok(candidate);
        }
    }
    Err(ApiError::bad_request("could not derive a free upstream name")
        .code(ApiErrorCode::McpCatalogAdoptFailed))
}

// ── Curation: delete / reset builtins ──────────────────────────────────────

#[utoipa::path(
    delete,
    path = "/api/v1/admin/mcp/catalog/{id}",
    tag = "MCP Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    responses(
        (status = 200, description = "Catalog entry deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_mcp_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // A row that came from the seed — edited or not — is soft-deleted
    // (suppressed) so seed-sync won't resurrect it on restart; a user-created
    // entry is hard-deleted. An already-deleted row answers 404, as a read does
    // — including the loser of two concurrent deletes, which waits on the row
    // lock and then finds it suppressed or gone.
    let fail = |e: sqlx::Error| {
        tracing::error!(error = %e, "delete catalog entry");
        ApiError::internal("failed to delete catalog entry")
    };
    let mut tx = db.conn().begin().await.map_err(fail)?;
    let seeded: Option<bool> = sqlx::query_scalar(
        "SELECT seeded FROM mcp_catalog WHERE id = $1 AND NOT suppressed FOR UPDATE",
    )
    .bind(id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(fail)?;
    let Some(seeded) = seeded else {
        return Err(ApiError::not_found("catalog entry not found", ApiErrorCode::McpCatalogEntryNotFound));
    };
    let stmt = if seeded {
        "UPDATE mcp_catalog SET suppressed = true, updated_at = NOW() WHERE id = $1"
    } else {
        "DELETE FROM mcp_catalog WHERE id = $1"
    };
    sqlx::query(stmt).bind(id).execute(&mut *tx).await.map_err(fail)?;
    tx.commit().await.map_err(fail)?;

    Ok(Json(ActionResponse::ok()))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/catalog/actions/reset",
    tag = "MCP Catalog",
    responses(
        (status = 200, description = "Catalog reset and reseeded", body = ActionResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset_mcp_catalog(
    mut db: TenantConn,
) -> Result<Json<ActionResponse>, ApiError> {
    let tid = db.tenant_uuid();

    // Reset wipes the catalog then re-seeds builtins fresh, atomically. Dropping
    // every row clears any suppressed soft-deletes, so re-seed restores the full
    // builtin set.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!(error = %e, "reset catalog: begin tx");
        ApiError::internal("failed to reset catalog")
    })?;

    sqlx::query("DELETE FROM mcp_catalog")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: delete");
            ApiError::internal("failed to reset catalog")
        })?;

    let loader = crate::seed_loader::SeedLoader::new();
    // A failed re-seed aborts the whole reset: `tx` is dropped without a commit,
    // so the DELETE above rolls back too and the caller keeps its catalog rather
    // than being left with a partially re-seeded one.
    let reseeded = crate::seed_scripts::sync_mcp_catalog(tid, &mut tx, &loader)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: reseed");
            ApiError::internal("failed to reset catalog")
        })?;

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "reset catalog: commit tx");
        ApiError::internal("failed to reset catalog")
    })?;

    Ok(Json(
        ActionResponse::ok().with_message(format!("Reseeded {reseeded} catalog entries")),
    ))
}

// ── Create / edit custom entries ────────────────────────────────────────────

const VALID_TRANSPORTS: [&str; 2] = ["streamable_http", "sse"];
const VALID_AUTH_MODES: [&str; 4] = ["no_auth", "service_account", "per_user_oauth", "byot"];

fn default_transport() -> String {
    "streamable_http".to_string()
}
fn default_auth_mode() -> String {
    "no_auth".to_string()
}

/// Validate the enum + URL fields shared by create and edit.
fn validate_entry_fields(transport: &str, auth_mode: &str, upstream_url: &str) -> Result<(), ApiError> {
    if !VALID_TRANSPORTS.contains(&transport) {
        return Err(ApiError::bad_request("transport must be 'streamable_http' or 'sse'")
            .code(ApiErrorCode::McpCatalogEntryInvalid));
    }
    if !VALID_AUTH_MODES.contains(&auth_mode) {
        return Err(ApiError::bad_request(
            "auth_mode must be one of no_auth, service_account, per_user_oauth, byot",
        )
        .code(ApiErrorCode::McpCatalogEntryInvalid));
    }
    if !(upstream_url.starts_with("http://") || upstream_url.starts_with("https://")) {
        return Err(ApiError::bad_request("upstream_url must be an http(s) URL")
            .code(ApiErrorCode::McpCatalogEntryInvalid));
    }
    Ok(())
}

/// Find a free `source_name` from `base` (the per-tenant seed-sync dedupe key),
/// appending ` (2)`, ` (3)`, … on collision.
async fn unique_source_name(db: &mut TenantConn, base: &str) -> Result<String, ApiError> {
    for n in 1..=100 {
        let candidate = if n == 1 { base.to_string() } else { format!("{base} ({n})") };
        let taken: bool =
            sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM mcp_catalog WHERE source_name = $1)")
                .bind(&candidate)
                .fetch_one(db.conn())
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, "catalog create: source_name check");
                    ApiError::internal("failed to create catalog entry")
                })?;
        if !taken {
            return Ok(candidate);
        }
    }
    Err(ApiError::bad_request("could not derive a free entry name — pass source_name explicitly")
        .code(ApiErrorCode::McpCatalogSourceNameTaken))
}

/// Request body for creating a custom catalog entry.
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMcpCatalogEntry {
    pub name: String,
    pub upstream_url: String,
    /// Seed-sync dedupe key. Defaults to `name` (uniquified per tenant).
    #[serde(default)]
    pub source_name: Option<String>,
    #[serde(default)]
    pub display_title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub category: Option<String>,
    #[serde(default)]
    pub featured: bool,
    #[serde(default)]
    pub website_url: Option<String>,
    #[serde(default)]
    pub repository_url: Option<String>,
    #[serde(default)]
    pub icon_url: Option<String>,
    #[serde(default = "default_transport")]
    pub transport: String,
    #[serde(default = "default_auth_mode")]
    pub auth_mode: String,
    #[serde(default)]
    pub oauth_issuer_url: Option<String>,
    #[serde(default)]
    pub oauth_authorization_url: Option<String>,
    #[serde(default)]
    pub oauth_token_url: Option<String>,
    #[serde(default)]
    pub oauth_revocation_url: Option<String>,
    #[serde(default)]
    pub oauth_default_scopes: Vec<String>,
    #[serde(default)]
    #[schema(value_type = Vec<McpCatalogToolSchema>)]
    pub tools: Vec<McpCatalogTool>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/catalog",
    tag = "MCP Catalog",
    request_body = CreateMcpCatalogEntry,
    responses(
        (status = 201, description = "Catalog entry created", body = McpCatalogEntry),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mcp_catalog_entry(
    mut db: TenantConn,
    Json(req): Json<CreateMcpCatalogEntry>,
) -> Result<(StatusCode, Json<McpCatalogEntry>), ApiError> {
    let name = req.name.trim();
    if name.is_empty() {
        return Err(ApiError::bad_request("name is required")
            .code(ApiErrorCode::McpCatalogEntryInvalid));
    }
    let upstream_url = req.upstream_url.trim();
    validate_entry_fields(&req.transport, &req.auth_mode, upstream_url)?;

    let tenant_id = db.tenant_uuid();
    let base_source = req
        .source_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(name);
    let source_name = unique_source_name(&mut db, base_source).await?;

    let tools: CatalogTools = sqlx::types::Json(req.tools);
    let tool_count = tools.0.len() as i32;
    let scopes: &[String] = &req.oauth_default_scopes;

    let sql = format!(
        r#"INSERT INTO mcp_catalog
             (tenant_id, source, source_name, name, display_title, description, category,
              featured, website_url, repository_url, icon_url, upstream_url, transport, auth_mode,
              oauth_issuer_url, oauth_authorization_url, oauth_token_url, oauth_revocation_url,
              oauth_default_scopes, tools, tool_count, is_builtin, enabled)
           VALUES ($1, 'custom', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16,
                   $17, $18, $19, $20, false, true)
           RETURNING {CATALOG_SELECT_COLS}"#
    );
    let row = sqlx::query_as::<_, McpCatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(&source_name)
        .bind(name)
        .bind(&req.display_title)
        .bind(&req.description)
        .bind(&req.category)
        .bind(req.featured)
        .bind(&req.website_url)
        .bind(&req.repository_url)
        .bind(&req.icon_url)
        .bind(upstream_url)
        .bind(&req.transport)
        .bind(&req.auth_mode)
        .bind(&req.oauth_issuer_url)
        .bind(&req.oauth_authorization_url)
        .bind(&req.oauth_token_url)
        .bind(&req.oauth_revocation_url)
        .bind(scopes)
        .bind(&tools)
        .bind(tool_count)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                return ApiError::conflict("a catalog entry with this name already exists", ApiErrorCode::McpCatalogSourceNameTaken);
            }
            tracing::error!(error = %e, "create catalog entry");
            ApiError::internal("failed to create catalog entry")
        })?;

    Ok((StatusCode::CREATED, Json(row)))
}

/// Request body for editing a catalog entry. Omitted fields are unchanged and
/// `null` or `""` clears an optional text field;
/// editing a built-in flips it to a user entry so seed-sync stops overwriting it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMcpCatalogEntry {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub display_title: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub description: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub category: Option<String>,
    #[serde(default)]
    pub featured: Option<bool>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub website_url: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub repository_url: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub icon_url: Option<String>,
    #[serde(default)]
    pub upstream_url: Option<String>,
    #[serde(default)]
    pub transport: Option<String>,
    #[serde(default)]
    pub auth_mode: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub oauth_issuer_url: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub oauth_authorization_url: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub oauth_token_url: Option<String>,
    #[serde(default, deserialize_with = "super::double_option::null_as_blank")]
    pub oauth_revocation_url: Option<String>,
    #[serde(default)]
    pub oauth_default_scopes: Option<Vec<String>>,
    #[serde(default)]
    #[schema(value_type = Vec<McpCatalogToolSchema>)]
    pub tools: Option<Vec<McpCatalogTool>>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/mcp/catalog/{id}",
    tag = "MCP Catalog",
    params(("id" = Uuid, Path, description = "Catalog entry ID")),
    request_body = UpdateMcpCatalogEntry,
    responses(
        (status = 200, description = "Catalog entry updated", body = McpCatalogEntry),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_mcp_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateMcpCatalogEntry>,
) -> Result<Json<McpCatalogEntry>, ApiError> {
    // Validate any provided enum/URL fields against the current row's values.
    let current: Option<(String, String, String)> = sqlx::query_as(
        "SELECT transport, auth_mode, upstream_url FROM mcp_catalog WHERE id = $1 AND NOT suppressed",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "update catalog entry: lookup");
        ApiError::internal("failed to update catalog entry")
    })?;
    let (cur_transport, cur_auth, cur_url) = current.ok_or(
        ApiError::not_found("catalog entry not found", ApiErrorCode::McpCatalogEntryNotFound),
    )?;

    let transport = req.transport.as_deref().unwrap_or(&cur_transport);
    let auth_mode = req.auth_mode.as_deref().unwrap_or(&cur_auth);
    let upstream_url = req
        .upstream_url
        .as_deref()
        .map(str::trim)
        .unwrap_or(&cur_url);
    validate_entry_fields(transport, auth_mode, upstream_url)?;

    // tools edits also refresh the derived tool_count.
    let tools: Option<CatalogTools> = req.tools.map(sqlx::types::Json);
    let tool_count: Option<i32> = tools.as_ref().map(|t| t.0.len() as i32);
    let scopes: Option<&[String]> = req.oauth_default_scopes.as_deref();
    let name = req.name.as_deref().map(str::trim).filter(|s| !s.is_empty());

    // Omitted (NULL bind) → unchanged; explicit empty string → cleared to NULL
    // (the same edit-clears-field semantics as the upstream-server modal). NOT
    // NULL columns (name/upstream_url/transport/auth_mode) only COALESCE.
    let sql = format!(
        r#"UPDATE mcp_catalog SET
             name                    = COALESCE($2, name),
             display_title           = CASE WHEN $3 IS NULL THEN display_title ELSE NULLIF($3, '') END,
             description             = CASE WHEN $4 IS NULL THEN description ELSE NULLIF($4, '') END,
             category                = CASE WHEN $5 IS NULL THEN category ELSE NULLIF($5, '') END,
             featured                = COALESCE($6, featured),
             website_url             = CASE WHEN $7 IS NULL THEN website_url ELSE NULLIF($7, '') END,
             repository_url          = CASE WHEN $8 IS NULL THEN repository_url ELSE NULLIF($8, '') END,
             icon_url                = CASE WHEN $9 IS NULL THEN icon_url ELSE NULLIF($9, '') END,
             upstream_url            = COALESCE($10, upstream_url),
             transport               = COALESCE($11, transport),
             auth_mode               = COALESCE($12, auth_mode),
             oauth_issuer_url        = CASE WHEN $13 IS NULL THEN oauth_issuer_url ELSE NULLIF($13, '') END,
             oauth_authorization_url = CASE WHEN $14 IS NULL THEN oauth_authorization_url ELSE NULLIF($14, '') END,
             oauth_token_url         = CASE WHEN $15 IS NULL THEN oauth_token_url ELSE NULLIF($15, '') END,
             oauth_revocation_url    = CASE WHEN $16 IS NULL THEN oauth_revocation_url ELSE NULLIF($16, '') END,
             oauth_default_scopes    = COALESCE($17, oauth_default_scopes),
             tools                   = COALESCE($18, tools),
             tool_count              = COALESCE($19, tool_count),
             enabled                 = COALESCE($20, enabled),
             is_builtin              = false,
             updated_at              = NOW()
           WHERE id = $1 AND NOT suppressed
           RETURNING {CATALOG_SELECT_COLS}"#
    );
    let row = sqlx::query_as::<_, McpCatalogEntry>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(name)
        .bind(&req.display_title)
        .bind(&req.description)
        .bind(&req.category)
        .bind(req.featured)
        .bind(&req.website_url)
        .bind(&req.repository_url)
        .bind(&req.icon_url)
        .bind(req.upstream_url.as_deref().map(str::trim))
        .bind(&req.transport)
        .bind(&req.auth_mode)
        .bind(&req.oauth_issuer_url)
        .bind(&req.oauth_authorization_url)
        .bind(&req.oauth_token_url)
        .bind(&req.oauth_revocation_url)
        .bind(scopes)
        .bind(&tools)
        .bind(tool_count)
        .bind(req.enabled)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update catalog entry");
            ApiError::internal("failed to update catalog entry")
        })?;

    Ok(Json(row))
}

#[cfg(test)]
mod tests {
    use super::slugify;
    use crate::routes::mcp::is_valid_slug;

    /// Every `slugify` output must satisfy `is_valid_slug` (1–31 chars, leading
    /// `a–z`, only `a–z0–9-`) — adopt binds it straight into a slug column.
    #[test]
    fn slugify_always_valid() {
        let cases = [
            "Airtable",
            "Notion (official)",
            "  GitHub  ",
            "123 numbers first",
            "!!!",
            "",
            "café-déjà",                       // non-ascii dropped
            "a-----b",                          // collapsed dashes
            &"x".repeat(80),                    // over length cap
            "ALLCAPS NAME WITH SPACES",
            "trailing-dashes---",
        ];
        for c in cases {
            let s = slugify(c);
            assert!(
                is_valid_slug(&s),
                "slugify({c:?}) = {s:?} is not a valid slug",
            );
        }
    }

    #[test]
    fn slugify_known_outputs() {
        assert_eq!(slugify("Airtable"), "airtable");
        assert_eq!(slugify("Notion (official)"), "notion-official");
        assert_eq!(slugify("123 first"), "s123-first");
        assert_eq!(slugify(""), "server");
        assert_eq!(slugify("!!!"), "server");
    }

    #[test]
    fn slugify_caps_length_at_31() {
        assert!(slugify(&"word ".repeat(20)).len() <= 31);
    }
}
