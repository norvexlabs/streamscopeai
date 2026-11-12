//! MCP server catalog — a curated, browsable list of MCP servers, each entry
//! a canonical `server.json` document (MCP Registry schema 2025-12-11).
//!
//! Tenant-scoped seed data (mirrors `model_catalog`): every tenant gets the
//! shipped catalog seeded as builtins; an admin browses it here, pastes a
//! `server.json` to add one (no server-side fetch), and adopts an entry.
//! Adopting one of its remotes provisions the real upstream, virtual server,
//! route and workspace grants; adopting one of its packages creates a local
//! server (the command line a developer's machine starts) and its workspace
//! grants.

use std::collections::{BTreeMap, HashMap};

use super::is_unique_violation;

use serde::{Deserialize, Serialize};
use streamscope_core::config::mcp::McpAuthMode;
use streamscope_core::mcp::header_inputs::{self as hi, Filler, InputsMeta, RemoteMeta, ServerJson};
use streamscope_core::mcp::local_server::{self as local, LocalLaunch};
use utoipa::ToSchema;
use uuid::Uuid;

use super::mcp_inputs;
use super::mcp_local;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use crate::db::tenant::{Scoped, TenantConn};
use crate::routes::mcp::{encrypt_mcp_credential, is_valid_slug};

use axum::extract::{Path, Query};
use axum::http::StatusCode;
use axum::Json;

/// SELECT column list shared by every read and RETURNING.
const CATALOG_SELECT_COLS: &str = r#"
    id, source, source_name, server_json, is_builtin, enabled, created_at, updated_at
"#;

/// The list order: featured entries first, then by display name.
const CATALOG_ORDER: &str = r#"
    (server_json->'_meta'->'ai.streamscope/catalog'->>'featured')::boolean DESC NULLS LAST,
    lower(COALESCE(server_json->>'title', server_json->>'name')), id
"#;

#[derive(sqlx::FromRow)]
struct CatalogRow {
    id: Uuid,
    source: Option<String>,
    source_name: String,
    server_json: sqlx::types::Json<ServerJson>,
    is_builtin: bool,
    enabled: bool,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

/// A catalog entry as returned to the admin UI.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpCatalogEntry {
    pub id: Uuid,
    pub source: Option<String>,
    /// The per-tenant seed key; unique in the tenant.
    pub source_name: String,
    /// The whole `server.json` document. The gateway's own facts (category,
    /// featured, liveness, tools, OAuth hints) are in its
    /// `_meta["ai.streamscope/catalog"]`.
    /// A `server.json` document: its keys are the MCP Registry schema's own
    /// camelCase (`websiteUrl`, `_meta`), unlike the rest of this body.
    pub server_json: ServerJson,
    pub is_builtin: bool,
    pub enabled: bool,
    /// The upstreams adopted from this entry (each upstream records the entry
    /// it was adopted from), by name. Empty when none is.
    pub adopted_upstreams: Vec<McpCatalogAdoptedUpstream>,
    /// The document's `packages[]`, each as adopting it would start the
    /// local-server form. Empty for a document that declares none.
    pub packages: Vec<McpCatalogPackage>,
    /// The local servers adopted from this entry, by name. Empty when none is.
    pub adopted_local_servers: Vec<McpCatalogAdoptedLocalServer>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// One upstream adopted from a catalog entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpCatalogAdoptedUpstream {
    pub id: Uuid,
    pub name: String,
}

/// One local server adopted from a catalog entry.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpCatalogAdoptedLocalServer {
    pub id: Uuid,
    pub name: String,
    pub slug: String,
}

/// One package of a catalog document, as adopting it starts the local-server
/// form.
#[derive(Debug, Serialize, ToSchema)]
pub struct McpCatalogPackage {
    /// The package's position in the document's `packages[]`: what adopt takes
    /// as `package_index`.
    pub index: usize,
    pub registry_type: String,
    pub identifier: String,
    pub version: Option<String>,
    /// The package's transport type (`stdio`, `streamable-http`, `sse`).
    pub transport: String,
    /// The command line derived from the package. Its `command` is empty and
    /// it has no argument when none is derived; its `env` is the package's
    /// either way.
    pub launch: LocalLaunch,
    /// The derived launch as one line, for display (the administrator-set
    /// environment as `NAME=value`, then the command and its arguments).
    /// Absent when no command was derived.
    pub command_line: Option<String>,
    /// Why no command was derived (`registry_type`, `transport`, `no_version`,
    /// `invalid_version`, `invalid_identifier`, `runtime_hint`,
    /// `runtime_arguments`, `argument`, `interpolation`). Absent when one was.
    pub underived_reason: Option<String>,
    /// The same, for a person to read.
    pub underived_message: Option<String>,
}

/// The document's packages as the console lists them. An entry that does not
/// read as a package is left out (a document with a remote keeps whatever its
/// `packages` holds).
fn packages_of(doc: &ServerJson) -> Vec<McpCatalogPackage> {
    doc.package_views()
        .into_iter()
        .enumerate()
        .filter_map(|(index, view)| {
            let view = view?;
            let prefill = local::prefill(&view);
            Some(McpCatalogPackage {
                index,
                registry_type: view.registry_type,
                identifier: view.identifier,
                version: view.version,
                transport: view.transport.kind,
                command_line: prefill.underived.is_none().then(|| prefill.launch.command_line()),
                launch: prefill.launch,
                underived_reason: prefill.underived.as_ref().map(|u| u.code().to_string()),
                underived_message: prefill.underived.as_ref().map(ToString::to_string),
            })
        })
        .collect()
}

impl From<CatalogRow> for McpCatalogEntry {
    fn from(r: CatalogRow) -> Self {
        Self {
            packages: packages_of(&r.server_json.0),
            adopted_local_servers: Vec::new(),
            id: r.id,
            source: r.source,
            source_name: r.source_name,
            server_json: r.server_json.0,
            is_builtin: r.is_builtin,
            enabled: r.enabled,
            adopted_upstreams: Vec::new(),
            created_at: r.created_at,
            updated_at: r.updated_at,
        }
    }
}

/// Fill each entry's `adopted_upstreams` and `adopted_local_servers`, in one
/// read each.
async fn with_adopted(conn: &mut Scoped, entries: &mut [McpCatalogEntry]) -> Result<(), ApiError> {
    if entries.is_empty() {
        return Ok(());
    }
    #[derive(sqlx::FromRow)]
    struct Adopted {
        catalog_entry_id: Uuid,
        id: Uuid,
        name: String,
    }
    let ids: Vec<Uuid> = entries.iter().map(|e| e.id).collect();
    let rows = sqlx::query_as::<_, Adopted>(
        "SELECT catalog_entry_id, id, name FROM mcp_upstream_servers \
         WHERE catalog_entry_id = ANY($1) ORDER BY name, id",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "load catalog entries' adopted upstreams");
        ApiError::internal("failed to list mcp catalog")
    })?;
    let mut by_entry: HashMap<Uuid, Vec<McpCatalogAdoptedUpstream>> = HashMap::new();
    for r in rows {
        by_entry.entry(r.catalog_entry_id).or_default().push(McpCatalogAdoptedUpstream { id: r.id, name: r.name });
    }
    #[derive(sqlx::FromRow)]
    struct AdoptedLocal {
        catalog_entry_id: Uuid,
        id: Uuid,
        name: String,
        slug: String,
    }
    let rows = sqlx::query_as::<_, AdoptedLocal>(
        "SELECT catalog_entry_id, id, name, slug FROM mcp_local_servers \
         WHERE catalog_entry_id = ANY($1) ORDER BY name, id",
    )
    .bind(&ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "load catalog entries' adopted local servers");
        ApiError::internal("failed to list mcp catalog")
    })?;
    let mut local_by_entry: HashMap<Uuid, Vec<McpCatalogAdoptedLocalServer>> = HashMap::new();
    for r in rows {
        local_by_entry
            .entry(r.catalog_entry_id)
            .or_default()
            .push(McpCatalogAdoptedLocalServer { id: r.id, name: r.name, slug: r.slug });
    }
    for e in entries {
        e.adopted_upstreams = by_entry.remove(&e.id).unwrap_or_default();
        e.adopted_local_servers = local_by_entry.remove(&e.id).unwrap_or_default();
    }
    Ok(())
}

/// Validate a document an admin saves.
fn validate_server_json(doc: &ServerJson) -> Result<(), ApiError> {
    doc.validate().map_err(|e| mcp_inputs::remote_error(&e))
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
           ORDER BY {CATALOG_ORDER}
           LIMIT $1 OFFSET $2"#
    );
    let rows = sqlx::query_as::<_, CatalogRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "failed to list mcp catalog");
            ApiError::internal("failed to list mcp catalog")
        })?;

    let mut rows: Vec<McpCatalogEntry> = rows.into_iter().map(McpCatalogEntry::from).collect();
    with_adopted(db.conn(), &mut rows).await?;
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
    let row = sqlx::query_as::<_, CatalogRow>(sqlx::AssertSqlSafe(&*sql))
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

    let mut entries = [McpCatalogEntry::from(row)];
    with_adopted(db.conn(), &mut entries).await?;
    let [entry] = entries;
    Ok(Json(entry))
}

// ── Adopt: provision the full MCP chain from a catalog entry ────────────────

/// Request body for adopting a catalog entry: one of its remotes (the gateway
/// connects to it) or one of its packages (a developer's machine starts it).
#[derive(Debug, Deserialize, ToSchema)]
pub struct AdoptCatalogEntry {
    /// Slug for the new `/mcp/<slug>` endpoint, or for the local server.
    /// Defaults to a slugified name. For an endpoint a numeric suffix is
    /// appended on collision; for a local server only a slug the server
    /// derived is suffixed — one given here that is taken is a 409.
    #[serde(default)]
    pub slug: Option<String>,
    /// Which of the document's `remotes[]` to adopt. Defaults to the first
    /// when no `package_index` is given; refused beside one.
    #[serde(default)]
    pub remote_index: Option<usize>,
    /// Which of the document's `packages[]` to adopt as a local server. The
    /// remote-only fields (`url_variables`, `auth_mode`, `fillers`, `inputs`,
    /// `secret_inputs`, the OAuth client) are then refused.
    #[serde(default)]
    pub package_index: Option<usize>,
    /// The local server's name (a package adopt). Defaults to the document's
    /// title, else its name; validated like a typed server's.
    #[serde(default)]
    pub name: Option<String>,
    /// The local server's description (a package adopt). Defaults to the
    /// document's.
    #[serde(default)]
    pub description: Option<String>,
    /// The local server's command line (a package adopt). Defaults to the one
    /// derived from the package; required when none is derived. A variable the
    /// package declares secret is stored as secret, and holds no value.
    #[serde(default)]
    pub launch: Option<LocalLaunch>,
    /// Values of the remote URL's `{variables}` (a variable's default fills
    /// an absent one). Never secret. Stored, with the defaults used, as the
    /// upstream's `url_variables`.
    #[serde(default)]
    pub url_variables: HashMap<String, String>,
    /// `headers` or `per_user_oauth`. Defaults to `per_user_oauth` when the
    /// entry carries OAuth hints, else `headers`.
    #[serde(default)]
    pub auth_mode: Option<String>,
    /// Who fills each input the remote declares: input id → `admin` | `user`
    /// | `client`. Every declared input needs one.
    #[serde(default)]
    pub fillers: BTreeMap<String, Filler>,
    /// Values of the NON-secret admin-filled inputs: input id → value.
    #[serde(default)]
    pub inputs: HashMap<String, String>,
    /// Values of the secret admin-filled inputs: input id → value. Encrypted
    /// at rest, never echoed.
    #[serde(default)]
    pub secret_inputs: HashMap<String, String>,
    /// OAuth client id/secret to register on the upstream (per_user_oauth).
    #[serde(default)]
    pub oauth_client_id: Option<String>,
    #[serde(default)]
    pub oauth_client_secret: Option<String>,
    /// Workspaces to grant the new endpoint to.
    #[serde(default)]
    pub workspace_ids: Vec<Uuid>,
}

/// Result of an adopt action: the upstream and endpoint a remote adopt
/// created, or the local server a package adopt created.
#[derive(Debug, Serialize, ToSchema)]
pub struct AdoptResult {
    pub upstream_id: Option<Uuid>,
    pub virtual_server_id: Option<Uuid>,
    pub local_server_id: Option<Uuid>,
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

/// The OAuth endpoints an adopted per-user-OAuth upstream is stored with.
struct OauthEndpoints {
    issuer_url: Option<String>,
    authorization_url: Option<String>,
    token_url: Option<String>,
    revocation_url: Option<String>,
    default_scopes: Vec<String>,
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
        (status = 409, description = "Name or slug taken", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
// The action is audited by the admin middleware (actor + path + request body,
// `secret_inputs` and the OAuth client secret redacted). The generic
// change-diff registry maps this route to `mcp_catalog`, whose row adopt never
// mutates, so the before/after diff is intentionally empty — the provisioned
// upstream/endpoint ids ride the response, not a row diff. A package adopt
// records the local server it stored — its launch included, which the request
// may leave to the derivation — through the diff sink.
pub async fn adopt_mcp_catalog_entry(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Json(req): Json<AdoptCatalogEntry>,
) -> Result<Json<AdoptResult>, ApiError> {
    let tenant_id = db.tenant_uuid();

    // Load the source entry (RLS-scoped).
    let sql = format!(r#"SELECT {CATALOG_SELECT_COLS} FROM mcp_catalog WHERE id = $1 AND NOT suppressed"#);
    let entry: McpCatalogEntry = sqlx::query_as::<_, CatalogRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "adopt: load catalog entry");
            ApiError::internal("failed to adopt catalog entry")
        })?
        .ok_or(
            ApiError::not_found("catalog entry not found", ApiErrorCode::McpCatalogEntryNotFound),
        )?
        .into();
    if let Some(package_index) = req.package_index {
        return adopt_package(&mut db, &entry, package_index, req, &audit_sink).await.map(Json);
    }
    if req.launch.is_some() || req.name.is_some() || req.description.is_some() {
        return Err(ApiError::bad_request("launch, name and description are only valid with package_index")
            .code(ApiErrorCode::McpLocalServerInvalid));
    }
    let doc = &entry.server_json;
    let remote_index = req.remote_index.unwrap_or(0);
    let hints = doc.catalog_meta().oauth;

    let auth_mode = match req.auth_mode.as_deref() {
        None if hints.is_some() => McpAuthMode::PerUserOauth,
        None => McpAuthMode::Headers,
        Some(m) => McpAuthMode::parse(m).ok_or_else(|| {
            ApiError::bad_request("auth_mode must be one of: headers, per_user_oauth")
        })?,
    };
    let oauth = auth_mode == McpAuthMode::PerUserOauth;

    // The chosen remote, with the admin's fillers, validated and finished.
    let mut remote = doc.remotes.get(remote_index).cloned().ok_or_else(|| {
        ApiError::bad_request(format!(
            "remote_index {remote_index} is out of range: the server declares {} remote(s)",
            doc.remotes.len()
        ))
        .code(ApiErrorCode::McpRemoteInvalid)
    })?;
    // The admin's fillers; the remote's other `_meta` namespaces are kept.
    let other = remote.meta.take().map(|m| m.other).unwrap_or_default();
    remote.meta = Some(RemoteMeta { inputs: InputsMeta { fillers: req.fillers.clone() }, other });
    let specs = mcp_inputs::specs_of(&remote, auth_mode.as_str())?;
    let upstream_url =
        hi::finish_url(&remote, &req.url_variables).map_err(|e| mcp_inputs::remote_error(&e))?;
    let url_variables = mcp_inputs::url_values_used(&remote, &req.url_variables);
    super::mcp::validate_outbound_urls(Some(&upstream_url), None, None, None, None, super::mcp::MCP_EGRESS)?;

    // The admin's values: only admin-filled ids, every required one present.
    let ops = mcp_inputs::plan_value_patch(
        &remote,
        &specs,
        Filler::Admin,
        &mcp_inputs::as_patch(&req.inputs),
        &mcp_inputs::as_patch(&req.secret_inputs),
    )
    .map_err(mcp_inputs::PatchRefusal::into_api)?;
    let (admin_values, _) = mcp_inputs::encrypt_ops(&ops)?;
    mcp_inputs::require_filled(&specs, Filler::Admin, &admin_values)?;
    let required_user_input_ids = hi::required_user_input_ids(&specs);

    let oauth_client_secret = req.oauth_client_secret.as_deref().filter(|c| !c.is_empty());
    let oauth_client_id = req.oauth_client_id.as_deref().filter(|c| !c.is_empty());
    if !oauth && (oauth_client_id.is_some() || oauth_client_secret.is_some()) {
        return Err(ApiError::bad_request(
            "oauth_client_id and oauth_client_secret are only valid when auth_mode = per_user_oauth",
        )
        .code(ApiErrorCode::McpUpstreamOauthClientNotAllowed));
    }
    let encrypted_oauth_secret = encrypt_mcp_credential(oauth_client_secret)?;

    // A per-user-OAuth upstream needs its endpoints: the entry's hints, else
    // what the server publishes (RFC 9728 → 8414).
    let endpoints = if !oauth {
        None
    } else {
        let hints = hints.unwrap_or_default();
        let hinted = |v: &Option<String>| v.as_deref().is_some_and(|s| !s.is_empty());
        if hinted(&hints.authorization_url) && hinted(&hints.token_url) {
            Some(OauthEndpoints {
                issuer_url: hints.issuer_url,
                authorization_url: hints.authorization_url,
                token_url: hints.token_url,
                revocation_url: hints.revocation_url,
                default_scopes: hints.default_scopes,
            })
        } else {
            crate::custom_ca::refresh_from_conn(db.conn()).await;
            let found = super::mcp_discovery::discover_oauth_endpoints(&upstream_url).await?;
            Some(OauthEndpoints {
                issuer_url: Some(found.issuer_url),
                authorization_url: Some(found.authorization_url),
                token_url: Some(found.token_url),
                revocation_url: found.revocation_url,
                default_scopes: if hints.default_scopes.is_empty() {
                    found.default_scopes
                } else {
                    hints.default_scopes
                },
            })
        }
    };
    if let Some(ep) = &endpoints {
        super::mcp::validate_outbound_urls(
            None,
            ep.issuer_url.as_deref(),
            ep.authorization_url.as_deref(),
            ep.token_url.as_deref(),
            ep.revocation_url.as_deref(),
            super::mcp::MCP_EGRESS,
        )?;
    }

    // A per_user_oauth endpoint can't be granted to a workspace until its
    // shared OAuth-App client is set — granting one would yield an endpoint
    // that fails every portal connect. Adopting *without* a workspace stays
    // allowed so the operator can configure the client and grant later. The
    // required-field set mirrors `ensure_endpoint_oauth_grantable` and the
    // portal connect path (client_id, secret, authorization_url, token_url).
    if let Some(ep) = &endpoints
        && !req.workspace_ids.is_empty()
    {
        let missing = super::mcp::oauth_client_missing_fields(
            oauth_client_id,
            encrypted_oauth_secret.is_some(),
            ep.authorization_url.as_deref(),
            ep.token_url.as_deref(),
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
    let display_name = doc.display_name().to_string();
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
        None => slugify(&display_name),
    };
    let slug = unique_slug(&mut db, &base_slug).await?;
    // Upstream names are UNIQUE per tenant — adopting the same entry twice must
    // not collide, so resolve a free name the same way as the slug.
    let upstream_name = unique_upstream_name(&mut db, &display_name).await?;

    let (issuer, authz, token, revocation, scopes) = match endpoints {
        Some(ep) => (ep.issuer_url, ep.authorization_url, ep.token_url, ep.revocation_url, ep.default_scopes),
        None => (None, None, None, None, Vec::new()),
    };

    // Provision upstream + virtual server + route + workspace grants atomically.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!(error = %e, "adopt: begin tx");
        ApiError::internal("failed to adopt catalog entry")
    })?;

    let upstream_id: Uuid = sqlx::query_scalar(
        "INSERT INTO mcp_upstream_servers \
           (tenant_id, name, description, upstream_url, transport, auth_mode, enabled, \
            remote, encrypted_admin_inputs, required_user_input_ids, \
            oauth_issuer_url, oauth_authorization_url, oauth_token_url, \
            oauth_revocation_url, oauth_client_id, encrypted_oauth_client_secret, oauth_default_scopes, \
            url_variables, catalog_entry_id) \
         VALUES ($1, $2, $3, $4, $5, $6, true, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) \
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(&upstream_name)
    .bind(&doc.description)
    .bind(&upstream_url)
    .bind(remote.kind.transport_str())
    .bind(auth_mode.as_str())
    .bind(sqlx::types::Json(&remote))
    .bind(sqlx::types::Json(&admin_values))
    .bind(&required_user_input_ids)
    .bind(&issuer)
    .bind(&authz)
    .bind(&token)
    .bind(&revocation)
    .bind(oauth_client_id)
    .bind(&encrypted_oauth_secret)
    .bind(if scopes.is_empty() { None } else { Some(&scopes) })
    .bind(sqlx::types::Json(&url_variables))
    .bind(entry.id)
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
    .bind(&doc.description)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        if is_unique_violation(&e) {
            return ApiError::conflict("an endpoint with this slug already exists", ApiErrorCode::McpVirtualServerSlugTaken);
        }
        tracing::error!(error = %e, "adopt: insert virtual server");
        ApiError::internal("failed to create endpoint").code(ApiErrorCode::McpCatalogAdoptFailed)
    })?;

    // Single route, empty prefix (only route on the endpoint), so the
    // client-header collision rule has nothing to compare against.
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

    Ok(Json(AdoptResult {
        upstream_id: Some(upstream_id),
        virtual_server_id: Some(virtual_server_id),
        local_server_id: None,
        slug,
        workspaces_granted,
    }))
}

/// Adopt one package of an entry as a local server: the command line the
/// request carries (else the one derived from the package), stored with the
/// package's secret variables kept valueless, and granted to the workspaces
/// named.
async fn adopt_package(
    db: &mut TenantConn,
    entry: &McpCatalogEntry,
    package_index: usize,
    req: AdoptCatalogEntry,
    audit_sink: &crate::middleware::AuditDiffSink,
) -> Result<AdoptResult, ApiError> {
    let invalid = |msg: String| ApiError::bad_request(msg).code(ApiErrorCode::McpLocalServerInvalid);
    if req.remote_index.is_some()
        || req.auth_mode.is_some()
        || !req.url_variables.is_empty()
        || !req.fillers.is_empty()
        || !req.inputs.is_empty()
        || !req.secret_inputs.is_empty()
        || req.oauth_client_id.is_some()
        || req.oauth_client_secret.is_some()
    {
        return Err(invalid(
            "a package is adopted as a local server: remote_index, url_variables, auth_mode, fillers, \
             inputs, secret_inputs and the OAuth client are only valid for a remote"
                .to_string(),
        ));
    }
    let doc = &entry.server_json;
    let views = doc.package_views();
    let view = views.get(package_index).and_then(Option::as_ref).ok_or_else(|| {
        invalid(format!(
            "package_index {package_index} is out of range: the server declares {} package(s)",
            views.len()
        ))
    })?;
    let prefill = local::prefill(view);
    let mut launch = match (req.launch, prefill.underived) {
        (Some(launch), _) => launch,
        (None, None) => prefill.launch,
        (None, Some(why)) => return Err(invalid(why.to_string())),
    };
    // A variable the package declares secret is one here too, whatever the
    // request says of it: `validate` then refuses a value for it.
    launch.keep_secrets(None, &local::secret_env_names(view));
    launch.validate().map_err(|e| mcp_local::launch_error(&e))?;

    // What the administrator gave is held to the rule as typed; a default
    // taken from the document is first made to fit the field (a registry
    // description runs over several lines). One that still fails says which
    // field to override.
    let name = match req.name.as_deref() {
        Some(name) => name.to_string(),
        None => mcp_local::default_name(doc.display_name()),
    };
    mcp_local::validate_name(&name)?;
    let description = match req.description.as_deref() {
        Some(d) => d.trim().to_string(),
        None => mcp_local::default_description(&doc.description),
    };
    let description = Some(description.as_str()).filter(|d| !d.is_empty());
    mcp_local::validate_description(description)?;
    // A slug the administrator chose is theirs: taken, it is refused. Only a
    // slug derived here is moved to a free one.
    let slug = match req.slug.as_deref().map(str::trim).filter(|s| !s.is_empty()) {
        Some(s) => {
            mcp_local::validate_slug(s)?;
            mcp_local::refuse_taken_slug(db.conn(), s).await?;
            s.to_string()
        }
        None => free_local_slug(db, &slugify(&name)).await?,
    };
    let tenant_id = db.tenant_uuid();

    let fail = |e: sqlx::Error| {
        tracing::error!(error = %e, "adopt package");
        ApiError::internal("failed to adopt catalog entry")
    };
    let mut tx = db.conn().begin().await.map_err(fail)?;
    let server = mcp_local::insert_local_server(
        &mut tx,
        tenant_id,
        mcp_local::NewLocalServer {
            slug: &slug,
            name: &name,
            description,
            launch: &launch,
            catalog_entry_id: Some(entry.id),
            enabled: true,
        },
    )
    .await?;
    let workspaces_granted = mcp_local::grant_to_workspaces(&mut tx, tenant_id, server.id, &req.workspace_ids).await?;
    tx.commit().await.map_err(fail)?;
    audit_sink.record(None::<&mcp_local::McpLocalServer>, Some(&server));

    Ok(AdoptResult {
        upstream_id: None,
        virtual_server_id: None,
        local_server_id: Some(server.id),
        slug: server.slug,
        workspaces_granted,
    })
}

/// `base`, then `base-2`, `base-3`, … (capped at the 31-char slug length):
/// the first one [`mcp_local::slug_is_taken`] says is free, if any of fifty is.
async fn first_free_slug(db: &mut TenantConn, base: &str) -> Result<Option<String>, ApiError> {
    for n in 1..=50 {
        let candidate = if n == 1 {
            base.to_string()
        } else {
            let suffix = format!("-{n}");
            let head: String = base.chars().take(31 - suffix.len()).collect();
            format!("{}{suffix}", head.trim_end_matches('-'))
        };
        if !mcp_local::slug_is_taken(db.conn(), &candidate).await? {
            return Ok(Some(candidate));
        }
    }
    Ok(None)
}

/// A free slug for a new endpoint, from `base`.
async fn unique_slug(db: &mut TenantConn, base: &str) -> Result<String, ApiError> {
    first_free_slug(db, base).await?.ok_or_else(|| {
        ApiError::bad_request("could not derive a free slug — pass one explicitly")
            .code(ApiErrorCode::McpVirtualServerSlugTaken)
    })
}

/// A free slug for a new local server, from a `base` the server derived.
async fn free_local_slug(db: &mut TenantConn, base: &str) -> Result<String, ApiError> {
    first_free_slug(db, base)
        .await?
        .ok_or_else(|| mcp_local::slug_taken("could not derive a free slug for the local server — pass one explicitly"))
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

    // The seed is read before anything is deleted: a seed that does not parse
    // or validate must leave the tenant's catalog as it is.
    let entries = crate::seed_loader::SeedLoader::new().load_mcp_catalog().map_err(|e| {
        tracing::error!(error = %e, "reset catalog: seed unusable");
        ApiError::internal("failed to reset catalog")
    })?;

    // Reset wipes the catalog then re-seeds builtins fresh, atomically. Dropping
    // every row clears any suppressed soft-deletes, so re-seed restores the full
    // builtin set.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!(error = %e, "reset catalog: begin tx");
        ApiError::internal("failed to reset catalog")
    })?;

    // The upstreams and local servers adopted from a seeded entry are linked
    // to it again once it is re-seeded (its seed key is the same, its id is new); a link to an
    // entry the seed does not carry is forgotten with that entry.
    let links: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT u.id, c.source_name FROM mcp_upstream_servers u \
         JOIN mcp_catalog c ON c.tenant_id = u.tenant_id AND c.id = u.catalog_entry_id",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "reset catalog: read adopted links");
        ApiError::internal("failed to reset catalog")
    })?;

    let local_links: Vec<(Uuid, String)> = sqlx::query_as(
        "SELECT l.id, c.source_name FROM mcp_local_servers l \
         JOIN mcp_catalog c ON c.tenant_id = l.tenant_id AND c.id = l.catalog_entry_id",
    )
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!(error = %e, "reset catalog: read adopted local links");
        ApiError::internal("failed to reset catalog")
    })?;

    sqlx::query("DELETE FROM mcp_catalog")
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: delete");
            ApiError::internal("failed to reset catalog")
        })?;

    // A failed re-seed aborts the whole reset: `tx` is dropped without a commit,
    // so the DELETE above rolls back too and the caller keeps its catalog rather
    // than being left with a partially re-seeded one.
    let reseeded = crate::seed_scripts::sync_mcp_catalog_entries(tid, &mut tx, &entries)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: reseed");
            ApiError::internal("failed to reset catalog")
        })?;

    if !links.is_empty() {
        let (upstream_ids, source_names): (Vec<Uuid>, Vec<String>) = links.into_iter().unzip();
        sqlx::query(
            "UPDATE mcp_upstream_servers u SET catalog_entry_id = c.id \
             FROM unnest($1::uuid[], $2::text[]) AS l(upstream_id, source_name), mcp_catalog c \
             WHERE u.id = l.upstream_id AND c.tenant_id = u.tenant_id AND c.source_name = l.source_name",
        )
        .bind(&upstream_ids)
        .bind(&source_names)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: relink adopted upstreams");
            ApiError::internal("failed to reset catalog")
        })?;
    }

    if !local_links.is_empty() {
        let (server_ids, source_names): (Vec<Uuid>, Vec<String>) = local_links.into_iter().unzip();
        sqlx::query(
            "UPDATE mcp_local_servers l SET catalog_entry_id = c.id \
             FROM unnest($1::uuid[], $2::text[]) AS k(server_id, source_name), mcp_catalog c \
             WHERE l.id = k.server_id AND c.tenant_id = l.tenant_id AND c.source_name = k.source_name",
        )
        .bind(&server_ids)
        .bind(&source_names)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "reset catalog: relink adopted local servers");
            ApiError::internal("failed to reset catalog")
        })?;
    }

    tx.commit().await.map_err(|e| {
        tracing::error!(error = %e, "reset catalog: commit tx");
        ApiError::internal("failed to reset catalog")
    })?;

    Ok(Json(
        ActionResponse::ok().with_message(format!("Reseeded {reseeded} catalog entries")),
    ))
}

// ── Create / edit custom entries ────────────────────────────────────────────

/// Request body for creating a custom catalog entry: a pasted `server.json`
/// document (the gateway fetches nothing).
#[derive(Debug, Deserialize, ToSchema)]
pub struct CreateMcpCatalogEntry {
    /// A `server.json` document: its keys are the MCP Registry schema's own
    /// camelCase (`websiteUrl`, `_meta`), unlike the rest of this body.
    pub server_json: ServerJson,
    /// Seed-sync dedupe key, unique in the tenant. Defaults to
    /// `server_json.name`.
    #[serde(default)]
    pub source_name: Option<String>,
    #[serde(default)]
    pub enabled: Option<bool>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/mcp/catalog",
    tag = "MCP Catalog",
    request_body = CreateMcpCatalogEntry,
    responses(
        (status = 201, description = "Catalog entry created", body = McpCatalogEntry),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 409, description = "An entry with this source_name exists", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_mcp_catalog_entry(
    mut db: TenantConn,
    Json(req): Json<CreateMcpCatalogEntry>,
) -> Result<(StatusCode, Json<McpCatalogEntry>), ApiError> {
    validate_server_json(&req.server_json)?;
    let source_name = req
        .source_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or(&req.server_json.name)
        .to_string();

    let tenant_id = db.tenant_uuid();
    let sql = format!(
        r#"INSERT INTO mcp_catalog (tenant_id, source, source_name, server_json, is_builtin, enabled)
           VALUES ($1, 'custom', $2, $3, false, $4)
           RETURNING {CATALOG_SELECT_COLS}"#
    );
    let row = sqlx::query_as::<_, CatalogRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(tenant_id)
        .bind(&source_name)
        .bind(sqlx::types::Json(&req.server_json))
        .bind(req.enabled.unwrap_or(true))
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            if is_unique_violation(&e) {
                return ApiError::conflict(
                    "a catalog entry with this source_name already exists",
                    ApiErrorCode::McpCatalogSourceNameTaken,
                );
            }
            tracing::error!(error = %e, "create catalog entry");
            ApiError::internal("failed to create catalog entry")
        })?;

    Ok((StatusCode::CREATED, Json(row.into())))
}

/// Request body for editing a catalog entry. Omitted fields are unchanged;
/// `server_json` replaces the whole document. Editing a built-in flips it to
/// a user entry so seed-sync stops overwriting it.
#[derive(Debug, Deserialize, ToSchema)]
pub struct UpdateMcpCatalogEntry {
    #[serde(default)]
    /// A `server.json` document: its keys are the MCP Registry schema's own
    /// camelCase (`websiteUrl`, `_meta`), unlike the rest of this body.
    pub server_json: Option<ServerJson>,
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
    if let Some(doc) = &req.server_json {
        validate_server_json(doc)?;
    }
    let sql = format!(
        r#"UPDATE mcp_catalog SET
             server_json = COALESCE($2, server_json),
             enabled     = COALESCE($3, enabled),
             is_builtin  = false,
             updated_at  = NOW()
           WHERE id = $1 AND NOT suppressed
           RETURNING {CATALOG_SELECT_COLS}"#
    );
    let row = sqlx::query_as::<_, CatalogRow>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(req.server_json.as_ref().map(sqlx::types::Json))
        .bind(req.enabled)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!(error = %e, "update catalog entry");
            ApiError::internal("failed to update catalog entry")
        })?
        .ok_or(
            ApiError::not_found("catalog entry not found", ApiErrorCode::McpCatalogEntryNotFound),
        )?;

    let mut entries = [McpCatalogEntry::from(row)];
    with_adopted(db.conn(), &mut entries).await?;
    let [entry] = entries;
    Ok(Json(entry))
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
