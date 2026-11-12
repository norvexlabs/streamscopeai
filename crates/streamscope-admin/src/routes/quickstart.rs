//! Portal quickstart — config-snippet generator for end-user clients.
//!
//! Two endpoints scoped under `/api/v1/portal/quickstart/*`:
//!
//! * `GET /clients` — lists the `ClientProfile` entries the named workspace is
//!   offered (its client-access profile), each marked compatible or not with
//!   the downstream providers and MCP virtual servers that workspace grants.
//! * `POST /render` — mints any keys the chosen template needs, builds the
//!   placeholder map (resolved capabilities, endpoint URLs, gateway origin,
//!   …), runs the shared `streamscope-client-templates` render engine, and returns
//!   `RenderResponse` with placeholder bodies plus a `MintedSecrets` map.
//!
//! The placeholder bodies never carry plaintext keys — they always read
//! `<paste-your-api-key-here>` etc. The plaintext flows in
//! `MintedSecrets` so the UI can splice it into the clipboard payload at
//! copy-time, never into the DOM.

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use super::downstream::ClientSlot;

use streamscope_core::auth::virtual_key::{generate_forward_key, generate_virtual_key, hash_key};
use streamscope_core::api::sse::ApiVersion;
use streamscope_core::proxy::routing::ModelCapabilities as Caps;
use streamscope_core::proxy::routing::upstream_api_version_for_provider;

use crate::AdminState;
use crate::db::tenant::{Scoped, TenantConn};
use streamscope_core::mcp::local_server::LocalLaunch;
use streamscope_client_templates::{
    companion_files, mcp_client_header_placeholder, mcp_header_item, mcp_local_server_item, render, ClientProfile, LocalMcpForm,
    McpAuthMode,
    TemplateKind, Value, API_KEY_PLACEHOLDER, UPSTREAM_API_KEY_PLACEHOLDER,
};

use super::portal_auth::PortalUser;
use super::portal_manager::{confine_to_key_workspace, require_workspace_member, MemberOf};
use super::{ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};

// ---------------------------------------------------------------------------
// GET /clients — list compatible profiles
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct ClientProfileSummary {
    pub id: String,
    pub label: String,
    pub homepage: String,
    pub supports_llm: bool,
    pub supports_mcp: bool,
    /// `true` iff this profile has at least one template the user can render
    /// given their accessible downstream providers / MCP virtual servers.
    pub compatible: bool,
    /// User-actionable reason why `compatible = false`, naming the specific
    /// gap (e.g. *no compatible LLM provider in your workspaces* or *no MCP
    /// virtual servers your workspaces can reach*). `None` when `compatible`
    /// is `true` — the UI shows this string as the disabled-card tooltip.
    pub incompatibility_reason: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ListClientsResponse {
    pub clients: Vec<ClientProfileSummary>,
}

/// Query of the two client reads: the workspace the answer is for.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct QuickstartClientsQuery {
    /// The workspace whose clients are read: what it is offered depends on the
    /// client-access profile assigned to it. Required for a signed-in member,
    /// who must belong to it. An `ak-` key answers for the workspace it is
    /// bound to: it may leave this out, and is refused another workspace.
    pub workspace_id: Option<Uuid>,
}

/// The workspace a client read is for: the one named, else the one an `ak-`
/// key is bound to. A signed-in member who names none is refused — no answer
/// stands for "across my workspaces", since each may be offered different
/// clients.
fn named_workspace(asked: Option<Uuid>, key_workspace_id: Option<Uuid>) -> Result<Uuid, ApiError> {
    asked.or(key_workspace_id).ok_or_else(|| {
        ApiError::bad_request("workspace_id is required: name the workspace whose clients to read")
            .code(ApiErrorCode::ValidationFailed)
    })
}

/// [`named_workspace`], once the caller is established as acting in it.
async fn clients_workspace(
    conn: &mut Scoped,
    user: &PortalUser,
    q: &QuickstartClientsQuery,
) -> Result<MemberOf, ApiError> {
    let workspace_id = named_workspace(q.workspace_id, user.key_workspace_id)?;
    require_workspace_member(conn, user, workspace_id).await
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/quickstart/clients",
    tag = "Portal Quickstart",
    operation_id = "portal_quickstart_list_clients",
    params(QuickstartClientsQuery),
    responses(
        (status = 200, description = "The client profiles the workspace is offered, each marked compatible or not with what the workspace grants", body = ListClientsResponse),
        (status = 400, description = "No workspace named", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 403, description = "Not a member of the workspace, or a key bound to another", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_clients(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    provision: Option<Extension<super::portal_auth::ProvisionToken>>,
    axum::extract::Query(q): axum::extract::Query<QuickstartClientsQuery>,
) -> Result<Json<ListClientsResponse>, ApiError> {
    let cli = user.is_cli(provision.as_ref().map(|p| &p.0));
    let member = clients_workspace(db.conn(), &user, &q).await?;
    let workspace_id = member.workspace_id();
    let profiles = load_offered_profiles(db.conn(), member).await?;

    // Compatibility is binary: "does the workspace grant at least one LLM
    // provider?" (or one MCP virtual server). Upstream `upstream_api_format`
    // never enters the predicate — the proxy translates between any client
    // protocol and any upstream protocol. A granted provider counts when it
    // has an enabled route OR is a BYOK downstream: a BYOK (`byok = true`)
    // provider serves LLM via pass-through and has NO routes by design, so
    // gating on `downstream_routes` alone would wrongly mark a BYOK-only
    // workspace as having no LLM access (disabling LLM-only clients like codex
    // that have no MCP template to slip through on).
    // Read for the named workspace alone: a render draws only on its grants.
    // The caller's membership of it is already proved (`member`), so both reads
    // key on the workspace.
    static HAS_LLM_ACCESS: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        crate::routes::with_live_provider_grants(concat!(
            r#"SELECT EXISTS(
            SELECT 1
            FROM downstream_providers dp
            WHERE EXISTS (
                    SELECT 1 FROM (
--{live_provider_grants}
                    ) wda
                    WHERE wda.downstream_provider_id = dp.id AND wda.workspace_id = $1
                  )
              AND (
                    dp.byok = true
                    OR EXISTS (
                        SELECT 1 FROM downstream_routes r
                        JOIN upstream_models m ON m.id = r.model_id
                        JOIN upstream_servers s ON s.id = m.server_id
                        WHERE r.provider_id = dp.id AND "#, live_route_sql!(), r#"
                    )
                  )
        )"#,
        ))
    });
    let has_llm_access: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(HAS_LLM_ACCESS.as_str()))
    .bind(workspace_id)
    .fetch_one(db.conn())
    .await
    .unwrap_or(false);

    let has_mcp_access: bool = sqlx::query_scalar(
        r#"SELECT EXISTS(
            SELECT 1 FROM mcp_virtual_servers vs
            WHERE vs.enabled AND EXISTS (
                    SELECT 1 FROM workspace_mcp_access wma
                    WHERE wma.workspace_id = $1 AND wma.virtual_server_id = vs.id
                  )
        )"#,
    )
    .bind(workspace_id)
    .fetch_one(db.conn())
    .await
    .unwrap_or(false);

    let has_local_mcp_access: bool = sqlx::query_scalar(
        "SELECT EXISTS( \
            SELECT 1 FROM mcp_local_servers l \
            WHERE l.enabled AND EXISTS ( \
                    SELECT 1 FROM workspace_mcp_local_access a \
                    WHERE a.workspace_id = $1 AND a.local_server_id = l.id))",
    )
    .bind(workspace_id)
    .fetch_one(db.conn())
    .await
    .unwrap_or(false);

    // Per-template kind requirements (matches the render-time validation in
    // `render_endpoint`): Llm / Instructions templates need an LLM provider,
    // Mcp templates need a virtual server. Combined needs the LLM side only —
    // its MCP section is optional (`{{#if mcp_servers}}`, renders with 0..N
    // servers), so an LLM-only workspace can still provision a combined
    // client; an MCP-only user must not be offered it (the render would 400
    // on the required key).
    let template_reachable = |t: &streamscope_client_templates::ClientProfileTemplate| match t.kind {
        TemplateKind::Llm | TemplateKind::Instructions | TemplateKind::Combined => has_llm_access,
        // A local MCP server stands in for a virtual one where the caller can
        // write it with this template.
        TemplateKind::Mcp => has_mcp_access || (has_local_mcp_access && writes_local_for(t.local_mcp, cli)),
    };

    let clients = profiles
        .into_iter()
        .map(|p| {
            let compatible = p.templates.iter().any(template_reachable);
            // Build a reason that names the most-actionable gap. Prefer the
            // strongest claim (both missing) and degrade to the specific one
            // — keeps the disabled-card tooltip short while still telling
            // the user what to ask their admin for.
            let needs_llm = p.templates.iter().any(|t| t.kind.needs_llm());
            let needs_mcp = p
                .templates
                .iter()
                .any(|t| matches!(t.kind, TemplateKind::Mcp | TemplateKind::Combined));
            let incompatibility_reason = if compatible {
                None
            } else if needs_llm && needs_mcp && !has_llm_access && !has_mcp_access {
                Some(
                    "This workspace grants no LLM downstream provider and no MCP virtual server. Ask an admin to grant access on /admin/workspaces.".to_string(),
                )
            } else if needs_llm && !has_llm_access {
                Some(
                    "This workspace grants no LLM downstream provider. Ask an admin to grant access on /admin/workspaces.".to_string(),
                )
            } else if needs_mcp && !has_mcp_access {
                Some(
                    "This workspace grants no MCP virtual server. Ask an admin to set one up at /admin/gateways/mcp and grant access on /admin/workspaces.".to_string(),
                )
            } else {
                None
            };
            ClientProfileSummary {
                compatible,
                incompatibility_reason,
                id: p.id,
                label: p.label,
                homepage: p.homepage,
                supports_llm: p.supports_llm,
                supports_mcp: p.supports_mcp,
            }
        })
        .collect();

    Ok(Json(ListClientsResponse { clients }))
}

// ---------------------------------------------------------------------------
// GET /clients/{id} — full profile for the wizard's template selection
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/portal/quickstart/clients/{id}",
    tag = "Portal Quickstart",
    operation_id = "portal_quickstart_get_client",
    params(("id" = String, Path, description = "Client profile id (e.g. 'claude-code')"), QuickstartClientsQuery),
    responses(
        (status = 200, description = "Full client profile with template list", body = ClientProfile),
        (status = 400, description = "No workspace named", body = ApiErrorResponse),
        (status = 403, description = "Not a member of the workspace, a key bound to another, or a client the workspace is not offered", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_client(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    axum::extract::Path(id): axum::extract::Path<String>,
    axum::extract::Query(q): axum::extract::Query<QuickstartClientsQuery>,
) -> Result<Json<ClientProfile>, ApiError> {
    let member = clients_workspace(db.conn(), &user, &q).await?;
    let profiles = load_profiles(db.conn()).await?;
    let profile = profiles.into_iter().find(|p| p.id == id).ok_or_else(|| {
        ApiError::not_found("client profile not found", ApiErrorCode::ClientProfileNotFound)
    })?;
    let offered = super::client_access_profiles::offered_clients(db.conn(), member).await?;
    if !offered.contains(&profile.id) {
        return Err(super::client_access_profiles::client_disabled(&profile.id));
    }
    Ok(Json(profile))
}

// ---------------------------------------------------------------------------
// GET /routes — list LLM routes the user can mint a key against
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct PortalRoute {
    pub id: Uuid,
    pub provider_id: Uuid,
    pub provider_name: String,
    pub alias: String,
    pub upstream_model: String,
    pub upstream_api_format: Option<String>,
    pub context_window: Option<i32>,
    pub max_output_tokens: Option<i32>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/quickstart/routes",
    tag = "Portal Quickstart",
    operation_id = "portal_quickstart_list_routes",
    params(PageQuery),
    responses(
        (status = 200, description = "Downstream routes the user can mint LLM keys against, by provider then alias", body = OffsetPage<PortalRoute>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_routes(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    axum::extract::Query(page): axum::extract::Query<PageQuery>,
) -> Result<Json<OffsetPage<PortalRoute>>, ApiError> {
    let (limit, offset) = page.resolve();
    #[derive(sqlx::FromRow)]
    struct Row {
        id: Uuid,
        provider_id: Uuid,
        provider_name: String,
        alias: String,
        upstream_model: String,
        upstream_api_format: Option<String>,
        context_window: Option<i32>,
        max_output_tokens: Option<i32>,
        preset_settings: Option<serde_json::Value>,
    }
    // Built once: the catalog join and the live grants are constants.
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        // Both markers splice constants only. The catalog join comes first, so
        // the grants go in by hand: `with_live_provider_grants` takes a
        // `&'static str`, which an assembled query is not.
        crate::routes::with_catalog_join(
        concat!(r#"
        SELECT r.id,
               r.provider_id,
               dp.name AS provider_name,
               r.alias,
               m.upstream_model,
               COALESCE(m.upstream_api_format, s.upstream_api_format) AS upstream_api_format,
               COALESCE(m.context_window, c.context_window) AS context_window,
               "#, resolved_max_output_sql!("m", "c"), r#" AS max_output_tokens,
               p.settings AS preset_settings
        FROM downstream_routes r
        JOIN downstream_providers dp ON dp.id = r.provider_id
        JOIN upstream_models m ON m.id = r.model_id
        JOIN upstream_servers s ON s.id = m.server_id
--{catalog_join}
        LEFT JOIN LATERAL (
            SELECT mp.settings
            FROM model_presets mp
            WHERE mp.model_id = m.id
              AND (mp.id = r.preset_id OR (r.preset_id IS NULL AND mp.is_default))
            LIMIT 1
        ) p ON true
        WHERE "#, live_route_sql!(), r#"
          AND EXISTS (
                SELECT 1 FROM workspace_members wm
                JOIN (
--{live_provider_grants}
                ) wda ON wda.workspace_id = wm.workspace_id
                WHERE wm.user_id = $1 AND wda.downstream_provider_id = dp.id
                  AND ($2::uuid IS NULL OR wm.workspace_id = $2)
              )
        ORDER BY dp.name, r.alias, r.id
        LIMIT $3 OFFSET $4
        "#),
            "m",
            "s",
        )
        .replace(crate::routes::LIVE_PROVIDER_GRANTS_MARKER, crate::routes::LIVE_PROVIDER_GRANTS)
    });
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(SQL.as_str()))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("quickstart list routes: {e}");
        ApiError::internal("internal error")
    })?;

    let routes = rows
        .into_iter()
        .map(|r| PortalRoute {
            id: r.id,
            provider_id: r.provider_id,
            provider_name: r.provider_name,
            alias: r.alias,
            upstream_model: r.upstream_model,
            upstream_api_format: r.upstream_api_format,
            context_window: r.context_window,
            // Surface the alias's effective preset cap (proxy force-merges it)
            // in preference to the model/catalog ceiling.
            max_output_tokens: r
                .preset_settings
                .as_ref()
                .and_then(streamscope_core::proxy::json_merge::preset_max_output_tokens)
                .and_then(|v| i32::try_from(v).ok())
                .or(r.max_output_tokens),
        })
        .collect();
    Ok(Json(OffsetPage::from_overfetched(routes, limit, offset)))
}

// ---------------------------------------------------------------------------
// GET /keys — list the user's existing keys for the reuse picker
// ---------------------------------------------------------------------------

/// Query for [`list_keys`] — scopes the reuse picker to one workspace and,
/// optionally, to a forward-auth mode (BYOK vs proxy-issued).
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct QuickstartKeysQuery {
    /// Workspace whose keys the caller can reuse. A key is bound to one
    /// workspace and serves every provider / MCP server that workspace grants.
    pub workspace_id: Uuid,
    /// When set, restrict to keys of this mode — `true` = BYOK (`vk-`),
    /// `false` = proxy-issued (`sk-`). The render's BYOK choice must match the
    /// reused key's mode, so the wizard filters by it.
    #[serde(default)]
    pub forward_auth: Option<bool>,
    /// Maximum number of items to return. Default 50, capped at 500.
    pub limit: Option<i64>,
    /// Number of items to skip from the beginning. Default 0.
    pub offset: Option<i64>,
}

/// One existing key the caller can reuse instead of minting a fresh one. The
/// plaintext is never returned — reuse renders the snippet with the api-key
/// placeholder and the user pastes the value they saved at creation time.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct QuickstartKey {
    pub id: Uuid,
    pub name: String,
    /// First few characters of the key — a recognition hint, not the secret.
    pub key_prefix: String,
    pub forward_auth: bool,
    pub workspace_id: Uuid,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/quickstart/keys",
    tag = "Portal Quickstart",
    operation_id = "portal_quickstart_list_keys",
    params(QuickstartKeysQuery),
    responses(
        (status = 200, description = "Existing non-revoked keys the user can reuse, newest first", body = OffsetPage<QuickstartKey>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_keys(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    axum::extract::Query(q): axum::extract::Query<QuickstartKeysQuery>,
) -> Result<Json<OffsetPage<QuickstartKey>>, ApiError> {
    // A portal `ak-` key may only list reuse-candidates in its bound workspace.
    confine_to_key_workspace(&user, q.workspace_id)?;
    let (limit, offset) = PageQuery { limit: q.limit, offset: q.offset }.resolve();
    let tenant_uuid = db.tenant_uuid();
    let keys: Vec<QuickstartKey> = sqlx::query_as(
        r#"SELECT id,
                  COALESCE(name, '') AS name,
                  COALESCE(key_prefix, LEFT(key_hash, 8)) AS key_prefix,
                  forward_auth,
                  workspace_id,
                  created_at,
                  expires_at
           FROM api_keys
           WHERE tenant_id = $1
             AND user_id = $2
             AND workspace_id = $3
             AND revoked_at IS NULL
             AND (expires_at IS NULL OR expires_at > now())
             AND ($4::bool IS NULL OR forward_auth = $4)
           ORDER BY created_at DESC, id
           LIMIT $5 OFFSET $6"#,
    )
    .bind(tenant_uuid)
    .bind(user.user_id)
    .bind(q.workspace_id)
    .bind(q.forward_auth)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("quickstart list keys: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(Json(OffsetPage::from_overfetched(keys, limit, offset)))
}

// ---------------------------------------------------------------------------
// POST /render — mint key(s) + render snippets
// ---------------------------------------------------------------------------

#[derive(Deserialize, ToSchema)]
pub struct RenderRequest {
    pub client_id: String,
    /// Index into `ClientProfile.templates`. The wizard picks one template
    /// up front (e.g. anthropic-messages variant) before calling render.
    pub template_index: usize,
    /// Workspace the snippet draws on. The minted (or reused) key is bound to
    /// it, and the chosen provider + MCP servers must be granted by it. The
    /// caller must be a member.
    pub workspace_id: Uuid,
    /// The gateway key to embed. One unified key serves both the LLM and MCP
    /// sections — the route grammar (`/v1/*` vs `/mcp/<slug>`) implies the
    /// protocol and the workspace allowlist gates each target at request time.
    /// Required for every static template; `spec_oauth` MCP-only templates mint
    /// nothing and may omit it.
    #[serde(default)]
    pub key: Option<KeySpec>,
    /// Downstream provider to render the LLM snippet against. Required for
    /// `kind = llm | combined | instructions`. Must be granted by the
    /// workspace. The snippet renders against every enabled route under this
    /// provider; single-model templates resolve `{{model_alias}}` to the
    /// default route, `{{#each routes}}` templates get the full list.
    #[serde(default)]
    pub llm_provider_id: Option<Uuid>,
    /// MCP virtual servers to wire up. A `kind = mcp` template requires at
    /// least one; `kind = combined` accepts 0..N (its body wraps the MCP
    /// section in `{{#if mcp_servers}}`). Each must be granted by the workspace.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerSelection>,
    /// Local MCP servers (run on the member's own machine) to write into the
    /// config. Each must be granted by the workspace. A template with no form
    /// for one leaves it out and says so in `warnings`.
    #[serde(default)]
    pub mcp_local_servers: Vec<McpLocalServerSelection>,
}

/// The gateway key a render embeds. Exactly one mode: mint a fresh key
/// (`name` or `name_prefix` auto-suffix), reuse an existing one
/// (`reuse_key_id`), or render against a key the caller holds out-of-band
/// (`external`). In reuse/external mode the snippet still renders the api-key
/// placeholder (the gateway keeps only the hash, so the plaintext can't be
/// recovered) and the caller splices the value it saved at creation time.
#[derive(Deserialize, ToSchema)]
pub struct KeySpec {
    /// Name for a freshly-minted key. `None` (and no `reuse_key_id`) → the
    /// backend derives the next free `<name_prefix>` / `<name_prefix>-N` name.
    /// Mutually exclusive with `name_prefix` and `reuse_key_id`.
    #[serde(default)]
    pub name: Option<String>,
    /// Prefix for a backend-derived name (next free `<prefix>` /
    /// `<prefix>-N`) instead of the default derived from the selected
    /// client(s) — the CLI's CI mode mints under `ci`. Mutually exclusive
    /// with `name` and `reuse_key_id`.
    #[serde(default)]
    pub name_prefix: Option<String>,
    /// Reuse this existing key instead of minting. Mutually exclusive with
    /// `name`. The key must belong to the caller and be bound to `workspace_id`.
    #[serde(default)]
    pub reuse_key_id: Option<Uuid>,
    /// Expiry for a freshly-minted key. Ignored when `reuse_key_id` is set.
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// `true` mints a `vk-` BYOK forward-auth key (the client forwards its own
    /// upstream credential via `/fwd/{key}/...`). Ignored when `reuse_key_id`
    /// is set — the reused key's own mode is used.
    #[serde(default)]
    pub forward_auth: bool,
    /// The caller already holds a gateway key out-of-band and splices it
    /// itself (the CLI's `STREAMSCOPE_GATEWAY_KEY` escape hatch): nothing is
    /// minted or reused, templates render with the api-key sentinel, and
    /// `forward_auth` must state the key's mode (it decides the URL shape).
    /// Mutually exclusive with every other field.
    #[serde(default)]
    pub external: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct McpServerSelection {
    pub virtual_server_id: Uuid,
}

#[derive(Deserialize, ToSchema)]
pub struct McpLocalServerSelection {
    pub local_server_id: Uuid,
}

/// The MCP servers one render was asked for: the gateway's, and the local
/// ones as [`load_local_selection`] read them.
#[derive(Clone, Copy)]
pub(crate) struct McpSelections<'a> {
    pub servers: &'a [McpServerSelection],
    pub local: &'a [SelectedLocalServer],
    pub reader: RenderReader,
}

/// Who reads what [`populate_template_placeholders`] builds. It decides one
/// thing: whether a local MCP server on a template that writes it only in a
/// project's own file (`local_mcp = project`) counts as written.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum RenderReader {
    /// The web Quickstart: the page shows the config OUTSIDE a project, which
    /// leaves such a server out — a selection of nothing else has nothing to
    /// show, and is refused.
    Web,
    /// The provision bundle: the CLI decides project or global and renders
    /// again from the placeholders, so the server travels and a selection of
    /// nothing else is accepted.
    Cli,
}

/// A selected local MCP server, read and checked against the workspace.
pub(crate) struct SelectedLocalServer {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub launch: LocalLaunch,
}

/// Whether a caller can be handed a local MCP server through a template of
/// this form: the CLI writes a project's own file, so any form will do; the
/// portal page shows the config outside a project, which only a `config`
/// form writes a local server into — a client offered there on the strength
/// of a `project` form would be refused at render.
pub(crate) fn writes_local_for(form: LocalMcpForm, cli: bool) -> bool {
    match form {
        LocalMcpForm::None => false,
        LocalMcpForm::Config => true,
        LocalMcpForm::Project => cli,
    }
}

/// Read the selected local MCP servers in one statement — once per render or
/// bundle, whatever the number of templates — and hold each to the same gate
/// as a virtual server: selected once, enabled (a disabled one reads as not
/// found), and granted to the workspace the caller was established as a
/// member of — the one the key is bound to. Returned in selection order.
pub(crate) async fn load_local_selection(
    tx: &mut Scoped,
    selection: &[McpLocalServerSelection],
    member: MemberOf,
) -> Result<Vec<SelectedLocalServer>, ApiError> {
    if selection.is_empty() {
        return Ok(Vec::new());
    }
    let ids: Vec<Uuid> = selection.iter().map(|s| s.local_server_id).collect();
    let mut seen: HashSet<Uuid> = HashSet::new();
    if !ids.iter().all(|id| seen.insert(*id)) {
        return Err(ApiError::bad_request("the same local MCP server was selected twice")
            .code(ApiErrorCode::ValidationFailed));
    }
    type Row = (Uuid, String, String, Option<String>, sqlx::types::Json<LocalLaunch>, bool);
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT l.id, l.slug, l.name, l.description, l.launch, \
                EXISTS (SELECT 1 FROM workspace_mcp_local_access a \
                         WHERE a.workspace_id = $2 AND a.local_server_id = l.id) \
           FROM mcp_local_servers l WHERE l.id = ANY($1) AND l.enabled",
    )
    .bind(&ids)
    .bind(member.workspace_id())
    .fetch_all(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("quickstart fetch local mcp servers: {e}");
        ApiError::internal("internal error")
    })?;
    let mut by_id: std::collections::HashMap<Uuid, Row> = rows.into_iter().map(|r| (r.0, r)).collect();
    let mut out = Vec::with_capacity(ids.len());
    for id in ids {
        let (id, slug, name, description, launch, granted) = by_id.remove(&id).ok_or_else(|| {
            ApiError::bad_request("local MCP server not found").code(ApiErrorCode::McpLocalServerNotFound)
        })?;
        if !granted {
            return Err(ApiError::forbidden("this workspace is not granted that local MCP server")
                .code(ApiErrorCode::PermissionDenied));
        }
        out.push(SelectedLocalServer { id, slug, name, description, launch: launch.0 });
    }
    Ok(out)
}

/// Why a selected MCP virtual server was left out of a rendered config.
#[derive(Serialize, ToSchema, Clone, Copy, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum McpServerOmitReason {
    /// A sign-in (OAuth) template, and a server whose client sends its own
    /// `Authorization`: it is reached on the `/fwd/{key}/mcp/<slug>` path,
    /// and a sign-in setup has no gateway key to put there.
    SignInCannotReachFwd,
    /// A pass-through (`vk-`) key, and a server some route of which carries
    /// more than what the client sends (an OAuth sign-in, an administrator's
    /// or a user's value): such a key reaches only a server whose every route
    /// carries just the client's own headers, its `Authorization` included.
    PassThroughKeyNotAccepted,
    /// A local MCP server, and a client template with no form for one.
    LocalServerNotSupported,
    /// A local MCP server, and a client template that writes one only in a
    /// project's own config file: the config rendered here (the one outside a
    /// project) leaves it out. `ssai provision` in a project writes it.
    LocalServerProjectOnly,
}

/// Why a virtual server is left out — the two reasons [`mcp_server_item`]
/// gives, each one of [`McpServerOmitReason`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VirtualOmit {
    SignInCannotReachFwd,
    PassThroughKeyNotAccepted,
}

/// A selected MCP server the rendered config leaves out, and why: a virtual
/// server (`virtual_server_id`) or a local one (`local_server_id`).
#[derive(Serialize, ToSchema, Clone, Debug, PartialEq, Eq)]
pub struct McpServerWarning {
    pub virtual_server_id: Option<Uuid>,
    pub local_server_id: Option<Uuid>,
    pub slug: String,
    pub reason: McpServerOmitReason,
    /// The same, for a person to read.
    pub message: String,
}

impl McpServerWarning {
    /// A virtual server the template's credential cannot reach.
    fn new(virtual_server_id: Uuid, slug: &str, omit: VirtualOmit) -> Self {
        let (reason, message) = match omit {
            VirtualOmit::SignInCannotReachFwd => (
                McpServerOmitReason::SignInCannotReachFwd,
                format!(
                    "MCP server '{slug}' was left out: it reads the client's own Authorization header, so \
                     it is reached with the gateway key in its URL, which a sign-in (OAuth) setup does \
                     not have — use a setup that embeds a gateway key for it"
                ),
            ),
            VirtualOmit::PassThroughKeyNotAccepted => (
                McpServerOmitReason::PassThroughKeyNotAccepted,
                format!(
                    "MCP server '{slug}' was left out: a pass-through key reaches only a server that \
                     carries just what the client sends, its own Authorization included — use a \
                     gateway key for it"
                ),
            ),
        };
        Self { virtual_server_id: Some(virtual_server_id), local_server_id: None, slug: slug.to_string(), reason, message }
    }

    /// A local server the template has no form for at all (`project_only`
    /// false), or writes only in a project's own config file.
    fn local(local_server_id: Uuid, slug: &str, client: &str, project_only: bool) -> Self {
        let (reason, message) = if project_only {
            (
                McpServerOmitReason::LocalServerProjectOnly,
                format!(
                    "local MCP server '{slug}' is not in this config: {client} is given a local server only \
                     in a project's own config file — run `ssai provision` in the project to write it"
                ),
            )
        } else {
            (
                McpServerOmitReason::LocalServerNotSupported,
                format!(
                    "local MCP server '{slug}' was left out: the {client} setup has no form for a server \
                     that runs on your machine"
                ),
            )
        };
        Self { virtual_server_id: None, local_server_id: Some(local_server_id), slug: slug.to_string(), reason, message }
    }
}

#[derive(Serialize, ToSchema)]
pub struct RenderedTemplate {
    pub kind: TemplateKind,
    pub format: streamscope_client_templates::TemplateFormat,
    pub filename: Option<String>,
    pub title: String,
    pub instructions: Option<String>,
    /// Body with the api-key placeholder (`<paste-your-api-key-here>`) left
    /// intact — the same sentinel appears in the LLM section and in every MCP
    /// server entry, since one key serves both. Safe to render to the DOM. The
    /// UI substitutes the real key at copy-time using `MintedSecrets`.
    pub body: String,
}

#[derive(Serialize, ToSchema, Default)]
pub struct MintedSecrets {
    /// Plaintext gateway key when this render minted one. Substituted into the
    /// clipboard at copy-time only. `None` when the render reused an existing
    /// key (or the template mints nothing, e.g. spec-OAuth MCP).
    pub api_key: Option<String>,
}

/// A key created during a render — surfaced so the UI can show the resolved
/// (auto-suffixed) name and refresh `/portal/keys` without a round-trip.
#[derive(Serialize, ToSchema)]
pub struct MintedKey {
    pub id: Uuid,
    pub name: String,
}

#[derive(Serialize, ToSchema)]
pub struct RenderResponse {
    pub template: RenderedTemplate,
    /// Files the client needs ALONGSIDE `template` — a credential the tool
    /// reads from its own env/secrets file rather than from the config the
    /// profile templates, or what it reads about the models from a file of its
    /// own (Aider's model metadata). Same sentinel contract as `template.body`:
    /// the UI substitutes the plaintext at copy-time. Empty for a template that
    /// declares none.
    pub companions: Vec<RenderedTemplate>,
    /// Keys created during this render. Empty when the render reused an
    /// existing key or minted nothing.
    pub minted_keys: Vec<MintedKey>,
    pub minted_secrets: MintedSecrets,
    /// The selected MCP virtual servers the config leaves out, each with why.
    /// Empty when every selected server is in it.
    pub warnings: Vec<McpServerWarning>,
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/quickstart/actions/render",
    tag = "Portal Quickstart",
    operation_id = "portal_quickstart_render",
    request_body = RenderRequest,
    responses(
        (status = 200, description = "Rendered snippet plus any minted plaintext keys", body = RenderResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "No access to provider or virtual server", body = ApiErrorResponse),
        (status = 404, description = "client_id not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn render_endpoint(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Json(body): Json<RenderRequest>,
) -> Result<Json<RenderResponse>, ApiError> {
    let tenant_uuid = db.tenant_uuid();

    // Every key this render mints is written inside one transaction and
    // committed only once the template has rendered successfully. A mid-loop
    // RBAC / BYOT / DB failure or a render error rolls every minted key back,
    // so a 4xx never strands orphan keys in the caller's key list.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("quickstart render begin tx: {e}");
        ApiError::internal("internal error")
    })?;

    // Before anything is read for the workspace: a portal `ak-` key renders and
    // mints only within its bound workspace, and the caller is a member — a
    // refused client would otherwise tell a non-member what another team is
    // offered.
    let member = require_workspace_member(&mut tx, &user, body.workspace_id).await?;

    let profiles = load_profiles(&mut tx).await?;
    let profile = profiles
        .into_iter()
        .find(|p| p.id == body.client_id)
        .ok_or_else(|| {
            ApiError::not_found("client profile not found", ApiErrorCode::ClientProfileNotFound)
        })?;
    let offered = super::client_access_profiles::offered_clients(&mut tx, member).await?;
    if !offered.contains(&profile.id) {
        return Err(super::client_access_profiles::client_disabled(&profile.id));
    }

    let template = profile
        .templates
        .get(body.template_index)
        .cloned()
        .ok_or_else(|| {
            ApiError::bad_request("template_index out of range")
                .code(ApiErrorCode::ClientProfileNotCompatible)
        })?;

    let needs_key = template_needs_key(&template, !body.mcp_servers.is_empty());
    let ctx = build_render_context(
        &mut tx,
        &state,
        tenant_uuid,
        &user,
        member,
        body.key.as_ref(),
        needs_key,
        &body.client_id,
        body.llm_provider_id,
    )
    .await?;

    let mut route_cache = RouteCache::new();
    let local_servers = load_local_selection(&mut tx, &body.mcp_local_servers, member).await?;
    let (placeholders, warnings) = populate_template_placeholders(
        &mut tx,
        &ctx,
        &template,
        body.llm_provider_id,
        McpSelections { servers: &body.mcp_servers, local: &local_servers, reader: RenderReader::Web },
        body.workspace_id,
        &mut route_cache,
    )
    .await?;

    let (body_rendered, instructions_rendered) =
        render_template_with(&template, &placeholders)?;

    tx.commit().await.map_err(|e| {
        tracing::error!("quickstart render commit: {e}");
        ApiError::internal("internal error")
    })?;

    // Companion files are part of the config, not an extra: a Goose render
    // that omits `secrets.yaml` hands the user a `config.yaml` with no
    // credential anywhere. Built from the SAME shared function the CLI writes
    // from, so the two surfaces cannot describe a different config.
    let companions = companion_files(&template, &placeholders)
        .map_err(|e| {
            tracing::warn!(client = %body.client_id, "quickstart companion render failed: {e}");
            ApiError::bad_request(format!("companion render failed: {e}"))
                .code(ApiErrorCode::ClientProfileTemplateInvalid)
        })?
        .into_iter()
        .map(|c| RenderedTemplate {
            kind: template.kind,
            format: c.format,
            filename: c.path,
            title: c.title,
            instructions: Some(c.instructions),
            body: c.body,
        })
        .collect();

    Ok(Json(RenderResponse {
        template: RenderedTemplate {
            kind: template.kind,
            format: template.format,
            filename: template.filename,
            title: template.title,
            instructions: instructions_rendered,
            body: body_rendered,
        },
        companions,
        minted_keys: ctx.minted_keys,
        minted_secrets: ctx.minted_secrets,
        warnings,
    }))
}

/// Whether a template needs the unified gateway key: every LLM-bearing
/// template does; an MCP-only template only when servers are selected AND the
/// auth mode is static (spec-OAuth templates mint nothing).
pub(crate) fn template_needs_key(
    template: &streamscope_client_templates::ClientProfileTemplate,
    has_mcp_servers: bool,
) -> bool {
    let mcp_static = matches!(template.mcp_auth_mode, McpAuthMode::Static);
    template.kind.needs_llm() || (has_mcp_servers && mcp_static)
}

/// Per-render context shared by every template the render covers: tenant
/// placeholders, the resolved public origin, and the single gateway key
/// (minted or reused) all templates embed.
pub(crate) struct RenderContext {
    /// `tenant_slug` / `tenant_name` (+ `api_key_prefix` when a key was
    /// resolved) — cloned as the base of each template's placeholder map.
    pub base_placeholders: BTreeMap<String, Value>,
    /// The tenant's slug — half of the name a rendered config registers the
    /// gateway under ([`client_provider_key`]).
    pub tenant_slug: String,
    pub public_origin: String,
    pub forward_auth: bool,
    pub key_name: String,
    pub minted_keys: Vec<MintedKey>,
    pub minted_secrets: MintedSecrets,
    /// Id of the key the render embeds — minted or reused. `None` when the
    /// render needed no key (spec-OAuth MCP-only).
    pub key_id: Option<Uuid>,
}

/// Build the shared render context: tenant placeholders, public origin, and
/// the unified gateway key (mint or reuse) inside the caller's transaction.
///
/// It mints a key bound to a workspace, so it takes the [`MemberOf`] that only
/// the membership gate hands out: a caller that has not passed the gate for
/// that workspace cannot call it.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_render_context(
    tx: &mut Scoped,
    state: &AdminState,
    tenant_uuid: Uuid,
    user: &PortalUser,
    member: MemberOf,
    key: Option<&KeySpec>,
    needs_key: bool,
    key_name_prefix: &str,
    // For a BYOK (`forward_auth`) mint, the BYOK downstream the key binds to.
    // The minted `vk-` key passes unconfigured models through to that
    // downstream's upstream with the client's forwarded credential.
    byok_downstream_id: Option<Uuid>,
) -> Result<RenderContext, ApiError> {
    let mut base_placeholders: BTreeMap<String, Value> = BTreeMap::new();
    let mut minted_keys: Vec<MintedKey> = Vec::new();
    let mut minted_secrets = MintedSecrets::default();

    // Tenant-level placeholders.
    let (tenant_slug, tenant_name): (String, String) =
        sqlx::query_as("SELECT slug, name FROM tenants WHERE id = $1")
            .bind(tenant_uuid)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("quickstart fetch tenant: {e}");
                ApiError::internal("internal error")
            })?;
    base_placeholders.insert("tenant_slug".into(), Value::String(tenant_slug.clone()));
    base_placeholders.insert("tenant_name".into(), Value::String(tenant_name));

    // Resolve the public origin used to build {{base_url}} / {{mcp_url}}.
    // Errors with ProxyPublicUrlUnset if neither tenant override nor SYSTEM
    // default is configured — the UI surfaces that as a CTA banner.
    let public_origin = crate::tenant_public_url::resolve_public_url(
        &state.db,
        tenant_uuid,
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;

    // The key is bound to the member's workspace; every provider / MCP server
    // the snippet wires is verified against that workspace's access tables
    // below — the Default workspace gates on its explicit allowlist like any
    // other.
    let workspace_id = member.workspace_id();

    // ----- Resolve the gateway key (mint or reuse) -----
    // One unified key serves both the LLM and MCP sections of every template
    // this render covers. A static template always needs it; a spec-OAuth
    // MCP-only template mints nothing.
    let mut forward_auth = false;
    let mut key_name = String::new();
    let mut key_id: Option<Uuid> = None;
    if needs_key {
        let key = key.ok_or_else(|| {
            ApiError::bad_request("a key (mint or reuse) is required for this template")
                .code(ApiErrorCode::ClientProfileNotCompatible)
        })?;
        let mint_fields = key.name.is_some() || key.name_prefix.is_some();
        if (key.reuse_key_id.is_some() && mint_fields)
            || (key.name.is_some() && key.name_prefix.is_some())
            || (key.external && (key.reuse_key_id.is_some() || mint_fields))
        {
            return Err(ApiError::bad_request(
                "pick one key mode: mint (name or name_prefix), reuse_key_id, or external",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
        // `expires_at` only means something at mint time — reject rather
        // than silently ignore it on the other modes (a caller expecting a
        // TTL would otherwise get a key that never expires).
        if key.expires_at.is_some() && (key.external || key.reuse_key_id.is_some()) {
            return Err(ApiError::bad_request(
                "expires_at applies only when minting a fresh key",
            )
            .code(ApiErrorCode::ValidationFailed));
        }

        if key.external {
            // The caller splices its own key locally — render with the
            // sentinel only. `forward_auth` must be stated: it decides
            // whether URLs take the `/fwd/<key>` BYOK shape.
            forward_auth = key.forward_auth;
            key_name = "external".to_string();
        } else if let Some(reuse_id) = key.reuse_key_id {
            // Reuse an existing key in this workspace owned by the caller. The
            // key's own mode (BYOK vs proxy-issued) wins. Expired keys are as
            // dead as revoked ones — reusing one would render configs around
            // a key the proxy rejects (routine state now that short-TTL CI
            // keys exist), so the liveness predicate matches the keys listing.
            let row: Option<(bool, Option<String>, Option<String>)> = sqlx::query_as(
                r#"SELECT forward_auth, name, key_prefix
                   FROM api_keys
                   WHERE id = $1 AND tenant_id = $2 AND user_id = $3
                     AND workspace_id = $4 AND revoked_at IS NULL
                     AND (expires_at IS NULL OR expires_at > now())"#,
            )
            .bind(reuse_id)
            .bind(tenant_uuid)
            .bind(user.user_id)
            .bind(workspace_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("quickstart load reuse key: {e}");
                ApiError::internal("internal error")
            })?;
            let (fa, name, prefix) = row.ok_or_else(|| {
                ApiError::bad_request("reuse_key_id is not a usable key in this workspace")
                    .code(ApiErrorCode::ValidationFailed)
            })?;
            forward_auth = fa;
            key_name = name.unwrap_or_default();
            key_id = Some(reuse_id);
            if let Some(p) = prefix {
                base_placeholders.insert("api_key_prefix".into(), Value::String(p));
            }
        } else {
            forward_auth = key.forward_auth;
            let prefix = key
                .name_prefix
                .as_deref()
                .map(str::trim)
                .filter(|p| !p.is_empty())
                .unwrap_or(key_name_prefix);
            key_name = match &key.name {
                Some(n) if !n.trim().is_empty() => n.trim().to_string(),
                _ => next_available_name(&mut *tx, tenant_uuid, user.user_id, prefix).await?,
            };
        }

        // Bind the key to a BYOK downstream when one was selected (LLM BYOK
        // pass-through). Optional here — a `vk-` key is also valid for MCP
        // bring-your-own-token (no LLM downstream). Validate when present (it must
        // be a `byok` downstream granted to the workspace); the LLM template
        // branch enforces that an LLM BYOK render names a BYOK downstream.
        let bound_downstream_id = match (forward_auth, byok_downstream_id) {
            (true, Some(dp)) => {
                let ok: bool = crate::routes::byok_downstream_bindable(tx, dp, workspace_id)
                .await
                .map_err(|e| {
                    tracing::error!("quickstart validate byok downstream: {e}");
                    ApiError::internal("internal error")
                })?;
                if !ok {
                    return Err(ApiError::bad_request(
                        "the selected provider is not a BYOK downstream granted to this workspace",
                    )
                    .code(ApiErrorCode::ClientProfileNotCompatible));
                }
                Some(dp)
            }
            _ => None,
        };

        // Mint only when not reusing and not caller-supplied.
        if !key.external && key.reuse_key_id.is_none() {
            let id = Uuid::new_v4();
            let plaintext = if forward_auth {
                generate_forward_key()
            } else {
                generate_virtual_key()
            };
            let key_hash = hash_key(&plaintext);
            let key_prefix = plaintext[..plaintext.len().min(12)].to_string();
            // WHO is minting decides the class, not which client is being
            // configured: a portal `ak-` key is the CLI running unattended in
            // CI, a session is a person at their own machine. Both surfaces
            // mint here, so they cannot disagree.
            let principal = match user.key_id {
                Some(_) => crate::routes::qos_classes::MintPrincipal::Automation,
                None => crate::routes::qos_classes::MintPrincipal::Person,
            };
            let qos_class_id = crate::routes::qos_classes::default_class_for_mint(
                &mut *tx,
                workspace_id,
                principal,
            )
            .await?;
            sqlx::query(
                r#"INSERT INTO api_keys
                    (id, tenant_id, workspace_id, user_id, key_hash, key_prefix, name,
                     forward_auth, expires_at, created_at, downstream_provider_id, qos_class_id)
                   VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, now(), $10, $11)"#,
            )
            .bind(id)
            .bind(tenant_uuid)
            .bind(workspace_id)
            .bind(user.user_id)
            .bind(&key_hash)
            .bind(&key_prefix)
            .bind(&key_name)
            .bind(forward_auth)
            .bind(key.expires_at)
            .bind(bound_downstream_id)
            .bind(qos_class_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                if crate::routes::bound_passthrough_gone(&e) {
                    return ApiError::bad_request(
                        "the selected provider is not a BYOK downstream granted to this workspace",
                    )
                    .code(ApiErrorCode::ClientProfileNotCompatible);
                }
                tracing::error!("quickstart mint key: {e}");
                ApiError::internal("internal error")
            })?;
            minted_keys.push(MintedKey {
                id,
                name: key_name.clone(),
            });
            minted_secrets.api_key = Some(plaintext);
            key_id = Some(id);
            base_placeholders.insert("api_key_prefix".into(), Value::String(key_prefix));
            tracing::info!(
                user_id = %user.user_id,
                key_id = %id,
                workspace_id = %workspace_id,
                "quickstart minted key"
            );
        }
    }

    Ok(RenderContext {
        base_placeholders,
        tenant_slug,
        public_origin,
        forward_auth,
        key_name,
        minted_keys,
        minted_secrets,
        key_id,
    })
}

/// The name a rendered config registers the gateway's provider under
/// (`{{provider_key}}`): `streamscope_<tenant>_<provider>`, the provider being
/// the downstream provider the user provisioned against.
///
/// Invariant to preserve: distinct for every (tenant, provider) pair. Clients
/// merge configs by that name — OpenCode deep-merges its user-scope and
/// project-scope files, and a provisioning into a user-scope file lands beside
/// any other — so two provisions sharing a name are silently fused into ONE
/// provider: the project's key and base URL win, and the model lists are
/// unioned, sending another tenant's or provider's model names with this key.
/// Slugging folds case and punctuation while provider names are unique only as
/// typed ("NVIDIA" beside "Nvidia"), so when any of `older_names` — the
/// tenant's providers created before this one — slugs to the same part, the
/// provider's id prefix is appended. Only older ones decide it, so adding a
/// provider never renames an existing one's key and a re-provision updates its
/// own entry in place.
fn client_provider_key(
    tenant_slug: &str,
    provider_name: &str,
    provider_id: Uuid,
    older_names: &[String],
) -> String {
    // The provider part as `slugify` gives it, minus a trailing `-` its length
    // cap can leave. Every other name is compared in the same form.
    let slug = |name: &str| crate::service_account::slugify(name).trim_end_matches('-').to_string();
    let mut provider = slug(provider_name);
    if provider.is_empty() || older_names.iter().any(|n| slug(n) == provider) {
        let id = provider_id.simple().to_string();
        provider = [provider.as_str(), &id[..8]]
            .into_iter()
            .filter(|p| !p.is_empty())
            .collect::<Vec<_>>()
            .join("-");
    }
    // `_` between the parts: a slug never contains one, so the parts cannot run
    // together — `acme-prod` + `nvidia` and `acme` + `prod-nvidia` stay apart.
    // The tenant slug verbatim: it is already validated `[a-z0-9-]`, and one
    // that `slugify`'s length cap cut would let two long slugs sharing a prefix
    // collide.
    ["streamscope".to_string(), tenant_slug.to_string(), provider]
        .into_iter()
        .filter(|part| !part.is_empty())
        .collect::<Vec<_>>()
        .join("_")
}

/// Build one template's full placeholder map on top of the shared context:
/// validates the template's LLM / MCP requirements against the request and
/// the workspace's grants, then runs the provider and MCP branches. Returns
/// with it the selected MCP servers the config leaves out — the one function
/// behind both the Web Quickstart and the CLI bundle, so the two report the
/// same servers.
pub(crate) async fn populate_template_placeholders(
    tx: &mut Scoped,
    ctx: &RenderContext,
    template: &streamscope_client_templates::ClientProfileTemplate,
    llm_provider_id: Option<Uuid>,
    mcp: McpSelections<'_>,
    workspace_id: Uuid,
    route_cache: &mut RouteCache,
) -> Result<(BTreeMap<String, Value>, Vec<McpServerWarning>), ApiError> {
    let McpSelections { servers: mcp_servers, local: mcp_local_servers, reader } = mcp;
    let mut placeholders = ctx.base_placeholders.clone();
    let mut warnings: Vec<McpServerWarning> = Vec::new();
    let public_origin = &ctx.public_origin;
    let forward_auth = ctx.forward_auth;

    let needs_llm = template.kind.needs_llm();
    // `kind = mcp` strictly requires at least one MCP server; `kind =
    // combined` accepts 0..N — its body wraps the MCP section in
    // `{{#if mcp_servers}}` so an empty list simply drops the block.
    let mcp_required = matches!(template.kind, TemplateKind::Mcp);

    // ----- LLM branch -----
    if needs_llm {
        let provider_id = llm_provider_id.ok_or_else(|| {
            ApiError::bad_request("llm_provider_id is required for this template")
                .code(ApiErrorCode::ClientProfileNotCompatible)
        })?;

        // The KEY's bound workspace must grant the chosen provider — gate on
        // `workspace_id` specifically, not a user-wide predicate, since the
        // request-time proxy gate keys off the bound workspace's allowlist.
        static GRANTED: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
            crate::routes::with_live_provider_grants(
                "SELECT EXISTS(SELECT 1 FROM (\n--{live_provider_grants}\n) wda \
                 WHERE wda.workspace_id = $1 AND wda.downstream_provider_id = $2)",
            )
        });
        let granted: bool = sqlx::query_scalar(sqlx::AssertSqlSafe(GRANTED.as_str()))
        .bind(workspace_id)
        .bind(provider_id)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("quickstart provider access check: {e}");
            ApiError::internal("internal error")
        })?;
        if !granted {
            return Err(
                ApiError::forbidden("this workspace does not grant access to that provider")
                    .code(ApiErrorCode::PermissionDenied),
            );
        }

        // A BYOK downstream is empty by default (pure pass-through). Provisioning
        // it produces a HOST-ONLY config: the `vk-` key in the base URL; native
        // auth + native model are left untouched (the template drops the token /
        // model lines under `{{#unless forward_auth}}`). No routes are required —
        // unconfigured models pass through; any route inside it just overrides one
        // model server-side, invisible to the client.
        let (is_byok, provider_label): (bool, String) =
            sqlx::query_as("SELECT byok, name FROM downstream_providers WHERE id = $1")
                .bind(provider_id)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    tracing::error!("quickstart byok check: {e}");
                    ApiError::internal("internal error")
                })?
                .unwrap_or_default();
        // Names are unique per tenant only as typed, and slugging folds case and
        // punctuation — so the OLDER providers' names decide whether this one's
        // slug alone is distinct. Only older ones: a provider added later that
        // slugs the same takes the suffix itself, so an existing key never
        // changes because another provider appeared. RLS confines the read to
        // this tenant.
        let others: Vec<String> = sqlx::query_scalar(
            "SELECT o.name FROM downstream_providers o, downstream_providers me \
             WHERE me.id = $1 AND o.id <> me.id AND (o.created_at, o.id) < (me.created_at, me.id)",
        )
        .bind(provider_id)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("quickstart provider names: {e}");
            ApiError::internal("internal error")
        })?;
        placeholders.insert(
            "provider_key".into(),
            Value::String(client_provider_key(&ctx.tenant_slug, &provider_label, provider_id, &others)),
        );

        if is_byok {
            if !forward_auth {
                return Err(ApiError::bad_request(
                    "a BYOK downstream requires a BYOK key — provision in BYOK mode",
                )
                .code(ApiErrorCode::ClientProfileNotCompatible));
            }
            // A BYOK downstream is empty (pure pass-through). Render a HOST-ONLY
            // config off a SINGLE synthetic route so every placeholder
            // (`base_url`, the `endpoint_*` forms, caps) is built consistently
            // with `forward_auth=true` — the `vk-` sentinel in the `/fwd` path,
            // the upstream-key sentinel in the header, and a fillable
            // `<your-model-name>` model. Host-only templates drop the model/token
            // under `{{#unless forward_auth}}`; clients that need a model in their
            // config get the sentinel for the user to fill.
            let provider: String = sqlx::query_scalar(
                "SELECT s.provider FROM downstream_providers dp \
                 JOIN upstream_servers s ON s.id = dp.upstream_server_id WHERE dp.id = $1",
            )
            .bind(provider_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("quickstart byok provider lookup: {e}");
                ApiError::internal("internal error")
            })?
            .unwrap_or_else(|| "custom".to_string());
            let synthetic = ResolvedRoute {
                provider_id,
                provider,
                alias: "<your-model-name>".to_string(),
                upstream_model: "<your-model-name>".to_string(),
                upstream_api_format: None,
                // This synthetic route stands for the UNCONFIGURED-model
                // pass-through a BYOK downstream is provisioned for: the
                // client's own credential and body reach the upstream on a
                // same-protocol leg, which is never token-scaled. (A curated
                // route inside a BYOK provider does translate — but it is not
                // what this placeholder renders.) Marked native so the scaled
                // window can never be advertised on this path; both windows are
                // `None` here anyway, so it states an invariant rather than
                // changing an output.
                any_target_speaks_anthropic_natively: true,
                client_context_window: None,
                context_window: None,
                max_output_tokens: None,
                preset_max_output_tokens: None,
                tags: Vec::new(),
                default_for_tags: Vec::new(),
                client_slots: Vec::new(),
                chat: true,
                resolved_supports_vision: Caps::DEFAULT_VISION,
                resolved_supports_reasoning: Caps::DEFAULT_REASONING,
                resolved_supports_function_calling: Caps::DEFAULT_FUNCTION_CALLING,
                resolved_supports_caching: Caps::DEFAULT_CACHING,
                resolved_supports_audio_input: Caps::DEFAULT_AUDIO_INPUT,
                resolved_supports_audio_output: Caps::DEFAULT_AUDIO_OUTPUT,
                resolved_supports_video_input: Caps::DEFAULT_VIDEO_INPUT,
                resolved_supports_pdf_input: Caps::DEFAULT_PDF_INPUT,
                resolved_supports_response_schema: Caps::DEFAULT_RESPONSE_SCHEMA,
                resolved_supports_system_messages: Caps::DEFAULT_SYSTEM_MESSAGES,
            };
            populate_provider_placeholders(
                &mut placeholders,
                std::slice::from_ref(&synthetic),
                public_origin,
                &ctx.key_name,
                template.route_tag.as_deref(),
                template.protocol.as_deref(),
                forward_auth,
            );
        } else {
            // LLM BYOK requires a BYOK downstream (pass-through). A normal provider
            // with forward_auth is not supported — provision a BYOK provider, or
            // mint a gateway (`sk-`) key for this provider instead.
            if forward_auth {
                return Err(ApiError::bad_request(
                    "LLM BYOK requires a BYOK downstream — pick a BYOK provider, or use a gateway key for this provider",
                )
                .code(ApiErrorCode::ClientProfileNotCompatible));
            }
            let all_routes = match route_cache.entry(provider_id) {
                std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
                std::collections::hash_map::Entry::Vacant(e) => {
                    let resolved = resolve_provider_routes_all(&mut *tx, provider_id).await?;
                    e.insert(resolved)
                }
            };
            let routes = filter_routes_by_tag(all_routes, template.route_tag.as_deref());
            if routes.is_empty() {
                return Err(
                    ApiError::bad_request("no enabled routes under that provider")
                        .code(ApiErrorCode::ClientProfileNotCompatible),
                );
            }

            populate_provider_placeholders(
                &mut placeholders,
                &routes,
                public_origin,
                &ctx.key_name,
                template.route_tag.as_deref(),
                template.protocol.as_deref(),
                forward_auth,
            );
        }
    }

    // ----- MCP branch -----
    // One render can wire several MCP virtual servers — `{{#each mcp_servers}}`
    // iterates the per-server scope. `kind = mcp` requires at least one. The
    // unified key resolved in the context serves every server; the workspace
    // allowlist gates each target at request time.
    if mcp_required && mcp_servers.is_empty() && mcp_local_servers.is_empty() {
        return Err(
            ApiError::bad_request("this template needs at least one MCP server")
                .code(ApiErrorCode::ClientProfileNotCompatible),
        );
    }
    if !mcp_servers.is_empty() || !mcp_local_servers.is_empty() {
        let mut seen: HashSet<Uuid> = HashSet::new();
        // The slug of every entry this config holds, gateway or local.
        let mut slugs: HashSet<String> = HashSet::new();
        let mut mcp_items: Vec<BTreeMap<String, Value>> = Vec::new();
        for mcp in mcp_servers {
            if !seen.insert(mcp.virtual_server_id) {
                return Err(ApiError::bad_request(
                    "the same MCP virtual server was selected twice",
                )
                .code(ApiErrorCode::ValidationFailed));
            }

            // Look up the virtual server for slug + naming. A disabled server is
            // treated as not found — the proxy rejects it at request time, so
            // the portal must not wire a snippet against it.
            let vs: Option<(String, String, Option<String>)> = sqlx::query_as(
                "SELECT slug, name, description FROM mcp_virtual_servers WHERE id = $1 AND enabled = true",
            )
            .bind(mcp.virtual_server_id)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("quickstart fetch virtual server: {e}");
                ApiError::internal("internal error")
            })?;
            let (slug, vs_name, vs_desc) = vs.ok_or_else(|| {
                ApiError::bad_request("virtual server not found")
                    .code(ApiErrorCode::McpVirtualServerNotFound)
            })?;

            // The KEY's bound workspace must grant this virtual server — gate on
            // `workspace_id` specifically (see the provider check above).
            let granted: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM workspace_mcp_access \
                 WHERE workspace_id = $1 AND virtual_server_id = $2)",
            )
            .bind(workspace_id)
            .bind(mcp.virtual_server_id)
            .fetch_one(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("quickstart mcp access check: {e}");
                ApiError::internal("internal error")
            })?;
            if !granted {
                return Err(ApiError::forbidden(
                    "this workspace does not grant access to that virtual server",
                )
                .code(ApiErrorCode::PermissionDenied));
            }

            // What the server asks of a client: the headers its upstreams read
            // from the client, and whether one is `Authorization` (then the
            // gateway key rides the `/fwd/{key}/mcp/<slug>` path).
            let facts = super::mcp_inputs::vs_client_facts(tx, &[mcp.virtual_server_id])
                .await?
                .remove(&mcp.virtual_server_id)
                .unwrap_or_default();
            match mcp_server_item(
                public_origin,
                &slug,
                vs_name,
                vs_desc,
                template.mcp_auth_mode,
                forward_auth,
                &facts,
            ) {
                Ok(item) => {
                    slugs.insert(slug.clone());
                    mcp_items.push(item);
                }
                // A sign-in template has no gateway key to put in the `/fwd`
                // path, and a pass-through key reaches only a server whose
                // client sends its own Authorization: such a server is left
                // out, and the response says so.
                Err(reason) => warnings.push(McpServerWarning::new(mcp.virtual_server_id, &slug, reason)),
            }
        }
        // Local servers are appended AFTER the gateway's — a template reads
        // "the first item is local" as "no gateway server is wired" — and only
        // into a template that declares a form for one; any other says so.
        let mut local_items = 0usize;
        // A local server left out because the template writes one only in a
        // project's own file, which this reader never gets.
        let mut project_only = false;
        for local in mcp_local_servers {
            match template.local_mcp {
                LocalMcpForm::None => {
                    warnings.push(McpServerWarning::local(local.id, &local.slug, &template.title, false));
                    continue;
                }
                // The config rendered here is the one outside a project, which
                // leaves the server out. The CLI renders the project's own
                // file from the same items, so the item travels to it; the
                // web page shows this config only, which never holds it.
                LocalMcpForm::Project => {
                    warnings.push(McpServerWarning::local(local.id, &local.slug, &template.title, true));
                    if reader == RenderReader::Web {
                        project_only = true;
                        continue;
                    }
                }
                LocalMcpForm::Config => {}
            }
            // One entry per slug in a client's config: a clash is between the
            // entries a config this reader gets can hold — a server left out
            // above, or a gateway one left out with its own warning, takes no
            // slug.
            if !slugs.insert(local.slug.clone()) {
                return Err(ApiError::bad_request(format!(
                    "two selected MCP servers share the slug '{}': a client config holds one entry per slug",
                    local.slug
                ))
                .code(ApiErrorCode::McpServerSlugClash));
            }
            mcp_items.push(mcp_local_server_item(
                &local.slug,
                &local.name,
                local.description.as_deref(),
                &local.launch.command,
                &local.launch.args,
                &local.launch.env_pairs(),
            ));
            local_items += 1;
        }
        // A `kind = mcp` template with nothing it can write: every gateway
        // server left out, and no local server in a file this reader gets.
        let local_written = local_items > 0;
        if mcp_required && mcp_items.len() == local_items && project_only && !local_written {
            return Err(ApiError::bad_request(
                "this setup writes a local MCP server only in a project's own config file, and nothing else \
                 was selected for it: run `ssai provision` inside the project, or select a gateway MCP server",
            )
            .code(ApiErrorCode::ClientProfileNotCompatible));
        }
        if mcp_required && mcp_items.len() == local_items && !local_written {
            return Err(ApiError::bad_request(
                "none of the selected MCP servers can be written with this setup: a sign-in (OAuth) \
                 template cannot reach one that reads the client's own Authorization header, a \
                 pass-through key reaches only such a server, and a local server needs a template \
                 with a form for it — pick another template or key",
            )
            .code(ApiErrorCode::ClientProfileNotCompatible));
        }
        if !mcp_items.is_empty() {
            placeholders.insert("mcp_servers".into(), Value::List(mcp_items));
        }
    }

    Ok((placeholders, warnings))
}

/// One `{{#each mcp_servers}}` item: the server's mount URL and the headers a
/// client config sends to it — the gateway key as `Authorization: Bearer` on
/// `/mcp/<slug>` (static templates), plus a fill-in sentinel for each header
/// the client itself supplies. When the client supplies `Authorization`, the
/// key moves into the `/fwd/{key}/mcp/<slug>` path instead (`forward_auth`).
/// The reason it is left out when the template's credential cannot reach it.
fn mcp_server_item(
    public_origin: &str,
    slug: &str,
    name: String,
    description: Option<String>,
    auth_mode: McpAuthMode,
    byok_key: bool,
    facts: &super::mcp_inputs::VsClientFacts,
) -> Result<BTreeMap<String, Value>, VirtualOmit> {
    let spec_oauth = matches!(auth_mode, McpAuthMode::SpecOauth);
    if spec_oauth && facts.fwd_mount {
        return Err(VirtualOmit::SignInCannotReachFwd);
    }
    // A BYOK `vk-` key reaches only a server whose every route carries just
    // what the client sends, its own `Authorization` included (the gateway
    // stamps no stored credential for it).
    if byok_key && !facts.pass_through {
        return Err(VirtualOmit::PassThroughKeyNotAccepted);
    }
    // The key rides the `/fwd` path when a client header is `Authorization`
    // (it would collide with the key). A sign-in template has no key: `/mcp`.
    let fwd = !spec_oauth && facts.fwd_mount;
    let mut item: BTreeMap<String, Value> = BTreeMap::new();
    item.insert("slug".into(), Value::String(slug.to_string()));
    item.insert("name".into(), Value::String(name));
    if let Some(d) = description {
        item.insert("description".into(), Value::String(d));
    }
    item.insert("transport_hint".into(), Value::String("streamable_http".into()));
    item.insert(
        "oauth_authorize_url".into(),
        Value::String(format!("{public_origin}/mcp/{slug}/oauth/authorize")),
    );
    let url = if fwd {
        format!("{public_origin}/fwd/{API_KEY_PLACEHOLDER}/mcp/{slug}")
    } else {
        format!("{public_origin}/mcp/{slug}")
    };
    item.insert("url".into(), Value::String(url));
    // The `/fwd/` path a template that keeps the key out of its file (in an
    // environment variable) builds the URL from: `{fwd_prefix}<key>/mcp/<slug>`.
    item.insert("fwd_prefix".into(), Value::String(format!("{public_origin}/fwd/")));
    let mut headers: Vec<BTreeMap<String, Value>> = Vec::new();
    if !spec_oauth && !fwd {
        headers.push(mcp_header_item("Authorization", format!("Bearer {API_KEY_PLACEHOLDER}")));
    }
    for name in &facts.declared_names {
        headers.push(mcp_header_item(name, mcp_client_header_placeholder(slug, name)));
    }
    item.insert("headers".into(), Value::List(headers));
    item.insert("forward_auth".into(), Value::Bool(fwd));
    if spec_oauth {
        item.insert("auth_mode".into(), Value::String("spec_oauth".into()));
    } else {
        item.insert("api_key".into(), Value::String(API_KEY_PLACEHOLDER.into()));
        item.insert("auth_mode".into(), Value::String("static".into()));
    }
    Ok(item)
}

/// Render a template's body + instructions against a placeholder map. The
/// instructions render through the engine too — `Text` format means no
/// escape and no parser-validation, so `{{api_key}}` in a setup-step string
/// substitutes the same placeholder that lands in the body.
pub(crate) fn render_template_with(
    template: &streamscope_client_templates::ClientProfileTemplate,
    placeholders: &BTreeMap<String, Value>,
) -> Result<(String, Option<String>), ApiError> {
    let body_rendered = render(&template.body, template.format, placeholders).map_err(|e| {
        tracing::warn!("quickstart render failed: {e}");
        ApiError::bad_request(format!("template render failed: {e}"))
            .code(ApiErrorCode::ClientProfileTemplateInvalid)
    })?;
    let instructions_rendered = template
        .instructions
        .as_deref()
        .map(|s| render(s, streamscope_client_templates::TemplateFormat::Text, placeholders))
        .transpose()
        .map_err(|e| {
            tracing::warn!("quickstart instructions render failed: {e}");
            ApiError::bad_request(format!("instructions render failed: {e}"))
                .code(ApiErrorCode::ClientProfileTemplateInvalid)
        })?;
    Ok((body_rendered, instructions_rendered))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

pub(crate) async fn load_profiles(conn: &mut Scoped) -> Result<Vec<ClientProfile>, ApiError> {
    // Single read path — the `client_profiles` table loader (non-suppressed rows).
    super::client_profiles_admin::load_snapshot(conn).await
}

/// The client profiles the member's workspace is offered — [`load_profiles`]
/// narrowed by client access.
async fn load_offered_profiles(conn: &mut Scoped, member: MemberOf) -> Result<Vec<ClientProfile>, ApiError> {
    let offered = super::client_access_profiles::offered_clients(conn, member).await?;
    Ok(load_profiles(conn).await?.into_iter().filter(|p| offered.contains(&p.id)).collect())
}

/// Smallest free key name for `(tenant, user)` given a base `prefix`: returns
/// `prefix` when unused, else `prefix-N` for the lowest free `N ≥ 2`. Powers
/// the wizard's auto-suffix so a user can mint `opencode`, `opencode-2`,
/// `opencode-3`, … without hand-picking a name each render.
async fn next_available_name(
    conn: &mut Scoped,
    tenant_id: Uuid,
    user_id: Uuid,
    prefix: &str,
) -> Result<String, ApiError> {
    let like = format!("{prefix}-%");
    let names: Vec<String> = sqlx::query_scalar(
        r#"SELECT name FROM api_keys
           WHERE tenant_id = $1 AND user_id = $2 AND name IS NOT NULL
             AND (name = $3 OR name LIKE $4)"#,
    )
    .bind(tenant_id)
    .bind(user_id)
    .bind(prefix)
    .bind(&like)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("quickstart next_available_name: {e}");
        ApiError::internal("internal error")
    })?;

    if !names.iter().any(|n| n == prefix) {
        return Ok(prefix.to_string());
    }
    let dash = format!("{prefix}-");
    let max_n = names
        .iter()
        .filter_map(|n| n.strip_prefix(&dash))
        .filter_map(|s| s.parse::<u32>().ok())
        .max()
        .unwrap_or(1);
    Ok(format!("{prefix}-{}", max_n + 1))
}

/// Memoizes resolved route sets per `provider_id` across a multi-template render
/// (the provision bundle reuses one LLM provider for every selected client), so
/// the join + catalog probe runs once per provider instead of once per template.
pub(crate) type RouteCache = std::collections::HashMap<Uuid, Vec<ResolvedRoute>>;

#[derive(Debug, Clone)]
pub(crate) struct ResolvedRoute {
    provider_id: Uuid,
    provider: String,
    alias: String,
    upstream_model: String,
    upstream_api_format: Option<String>,
    /// True when ANY of the alias's failover/LB targets speaks the Anthropic
    /// wire natively. Such a leg is a passthrough — its usage is re-encoded raw,
    /// never token-scaled — so an alias with even one native target must be
    /// advertised with the honest window, whichever target happens to serve the
    /// request. Folded with OR for that reason: the unscaled leg is the one that
    /// constrains the claim.
    any_target_speaks_anthropic_natively: bool,
    client_context_window: Option<i32>,
    context_window: Option<i32>,
    max_output_tokens: Option<i32>,
    /// Output-token cap set by the route's effective preset (its `preset_id`,
    /// else the model's default preset), in whichever native protocol vocabulary
    /// it was authored. The proxy force-merges the preset onto every call, so this
    /// is the alias's real per-call ceiling — it takes precedence over
    /// `max_output_tokens` (the model's absolute ceiling) when surfaced to client
    /// configs. `None` for a passthrough preset that sets no cap.
    preset_max_output_tokens: Option<i32>,
    /// Operator-supplied tag set scoping which clients a route is offered to
    /// (e.g. `["opencode", "claude-code"]`). Quickstart rendering filters by tag
    /// so each client gets only the routes it should see. The reserved tag `"*"`
    /// means "offer this route to EVERY client"; an empty set behaves the same
    /// (legacy), so prefer `"*"` for explicit intent.
    tags: Vec<String>,
    /// Subset of `tags` declaring "this route is the canonical default for that
    /// tag" — it supplies the top-level model alias in the generated config. The
    /// renderer picks the route whose `default_for_tags` contains the client's
    /// `route_tag`; the reserved tag `"*"` marks the **global default** used for
    /// any client without a more specific match (a specific client tag always
    /// wins over `"*"`). Empty here means "default for no client" (the renderer
    /// then falls back to `"*"`, else the first route).
    default_for_tags: Vec<String>,
    /// The client model slots this alias fills (one route per slot in a
    /// provider, so an alias whose targets hold both fills both).
    client_slots: Vec<ClientSlot>,
    /// Every target of the alias serves a chat model — what a client slot
    /// needs, since a client sends it chat requests.
    chat: bool,
    resolved_supports_vision: bool,
    resolved_supports_reasoning: bool,
    resolved_supports_function_calling: bool,
    resolved_supports_caching: bool,
    resolved_supports_audio_input: bool,
    resolved_supports_audio_output: bool,
    resolved_supports_video_input: bool,
    resolved_supports_pdf_input: bool,
    resolved_supports_response_schema: bool,
    resolved_supports_system_messages: bool,
}

/// Resolve EVERY enabled route under a provider in ONE query — the 3-table join
/// plus the LATERAL `model_catalog` probe, run once for the whole set rather
/// than once per route id. Capability resolution mirrors the proxy's
/// `model_catalog → upstream_models → downstream_routes` inheritance (SQL carries
/// no fallback; the `Caps::DEFAULT_*` are applied here).
async fn resolve_provider_routes_all(
    conn: &mut Scoped,
    provider_id: Uuid,
) -> Result<Vec<ResolvedRoute>, ApiError> {
    #[derive(sqlx::FromRow)]
    struct Row {
        provider_id: Uuid,
        provider: String,
        alias: String,
        upstream_model: String,
        upstream_api_format: Option<String>,
        client_context_window: Option<i32>,
        context_window: Option<i32>,
        max_output_tokens: Option<i32>,
        preset_settings: Option<serde_json::Value>,
        tags: Vec<String>,
        default_for_tags: Vec<String>,
        client_slots: Vec<String>,
        chat: bool,
        v: Option<bool>,
        r: Option<bool>,
        f: Option<bool>,
        ca: Option<bool>,
        ai: Option<bool>,
        ao: Option<bool>,
        vi: Option<bool>,
        pi: Option<bool>,
        rs: Option<bool>,
        sm: Option<bool>,
    }
    let rows: Vec<Row> = sqlx::query_as(sqlx::AssertSqlSafe(
        &*crate::routes::with_catalog_join(
        concat!(r#"
        SELECT r.provider_id, s.provider, r.alias,
               (
--{judge_capable}
               ) AS chat,
               m.upstream_model,
               COALESCE(m.upstream_api_format, s.upstream_api_format) as upstream_api_format,
               r.client_context_window,
               COALESCE(m.context_window, c.context_window) as context_window,
               "#, resolved_max_output_sql!("m", "c"), r#" as max_output_tokens,
               p.settings as preset_settings,
               r.tags,
               r.default_for_tags,
               -- The slots of the ALIAS, held by any row of it, disabled ones
               -- included: a slot names one target row, and the alias keeps it
               -- while any target still offers the alias.
               COALESCE((SELECT array_agg(cs.slot) FROM route_client_slots cs
                         JOIN downstream_routes h ON h.tenant_id = cs.tenant_id AND h.id = cs.route_id
                         WHERE cs.tenant_id = r.tenant_id AND cs.provider_id = r.provider_id
                           AND h.alias = r.alias), '{}') AS client_slots,
               COALESCE(m.supports_vision,           c.supports_vision) as v,
               COALESCE(m.supports_reasoning,        c.supports_reasoning) as r,
               COALESCE(m.supports_function_calling, c.supports_function_calling) as f,
               COALESCE(m.supports_caching,          c.supports_caching) as ca,
               COALESCE(m.supports_audio_input,      c.supports_audio_input) as ai,
               COALESCE(m.supports_audio_output,     c.supports_audio_output) as ao,
               COALESCE(m.supports_video_input,      c.supports_video_input) as vi,
               COALESCE(m.supports_pdf_input,        c.supports_pdf_input) as pi,
               COALESCE(m.supports_response_schema,  c.supports_response_schema) as rs,
               COALESCE(m.supports_system_messages,  c.supports_system_messages)  as sm
        FROM downstream_routes r
        JOIN upstream_models m  ON m.id = r.model_id
        JOIN upstream_servers s ON s.id = m.server_id
--{catalog_join}
        LEFT JOIN LATERAL (
            SELECT mp.settings
            FROM model_presets mp
            WHERE mp.model_id = m.id
              AND (mp.id = r.preset_id OR (r.preset_id IS NULL AND mp.is_default))
            LIMIT 1
        ) p ON true
        WHERE r.provider_id = $1 AND "#, live_route_sql!(), r#"
        ORDER BY r.alias, r.priority DESC, r.weight DESC
        "#),
            "m",
            "s",
        )
        .replace(crate::routes::JUDGE_CAPABLE_MARKER, crate::routes::JUDGE_CAPABLE),
    ))
    .bind(provider_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("quickstart resolve provider routes: {e}");
        ApiError::internal("internal error")
    })?;
    let resolved: Vec<ResolvedRoute> = rows
        .into_iter()
        .map(|r| {
            // Resolved before the move, and through the proxy's own derivation:
            // a row that pins no format inherits its provider's default, so the
            // question "does this leg translate?" must be asked of the EFFECTIVE
            // format, not the stored `Option`.
            let speaks_anthropic_natively =
                route_speaks_anthropic_natively(&r.provider, r.upstream_api_format.as_deref());
            ResolvedRoute {
            provider_id: r.provider_id,
            provider: r.provider,
            alias: r.alias,
            any_target_speaks_anthropic_natively: speaks_anthropic_natively,
            upstream_model: r.upstream_model,
            upstream_api_format: r.upstream_api_format,
            client_context_window: r.client_context_window,
            context_window: r.context_window,
            max_output_tokens: r.max_output_tokens,
            preset_max_output_tokens: r
                .preset_settings
                .as_ref()
                .and_then(streamscope_core::proxy::json_merge::preset_max_output_tokens)
                .and_then(|v| i32::try_from(v).ok()),
            tags: r.tags,
            default_for_tags: r.default_for_tags,
            client_slots: r.client_slots.iter().filter_map(|s| ClientSlot::parse(s)).collect(),
            chat: r.chat,
            resolved_supports_vision: r.v.unwrap_or(Caps::DEFAULT_VISION),
            resolved_supports_reasoning: r.r.unwrap_or(Caps::DEFAULT_REASONING),
            resolved_supports_function_calling: r.f.unwrap_or(Caps::DEFAULT_FUNCTION_CALLING),
            resolved_supports_caching: r.ca.unwrap_or(Caps::DEFAULT_CACHING),
            resolved_supports_audio_input: r.ai.unwrap_or(Caps::DEFAULT_AUDIO_INPUT),
            resolved_supports_audio_output: r.ao.unwrap_or(Caps::DEFAULT_AUDIO_OUTPUT),
            resolved_supports_video_input: r.vi.unwrap_or(Caps::DEFAULT_VIDEO_INPUT),
            resolved_supports_pdf_input: r.pi.unwrap_or(Caps::DEFAULT_PDF_INPUT),
            resolved_supports_response_schema: r.rs.unwrap_or(Caps::DEFAULT_RESPONSE_SCHEMA),
            resolved_supports_system_messages: r.sm.unwrap_or(Caps::DEFAULT_SYSTEM_MESSAGES),
            }
        })
        .collect();
    Ok(fold_failover_targets(resolved))
}

/// Collapse an alias's failover/load-balance targets into the ONE entry a client
/// config can express.
///
/// An alias is a list of targets — weighted round-robin at equal priority,
/// failover across priorities — stored as one `downstream_routes` row per
/// target. A client config has a single entry per model id, so emitting a row
/// each writes the same id two or more times: a duplicate key in the JSON
/// configs and a duplicate list entry in the YAML ones, where whichever copy the
/// parser keeps is its business, not ours.
///
/// The surviving entry states what holds for EVERY target, because any of them
/// may serve the request: the smallest window, the smallest output cap, and a
/// capability only where all of them have it. Identity fields come from the
/// highest-priority target (the query orders by `priority DESC, weight DESC`,
/// mirroring the edge's own fold) and the tag sets are unioned, so a route
/// offered to a client through any of its targets stays offered.
///
/// A target with no known window is skipped rather than zeroing the fold — an
/// unknown window is not evidence of a smaller one, and dropping the figure
/// entirely would send the client back to its own hardcoded default.
fn fold_failover_targets(routes: Vec<ResolvedRoute>) -> Vec<ResolvedRoute> {
    let mut folded: Vec<ResolvedRoute> = Vec::with_capacity(routes.len());
    for route in routes {
        let Some(head) = folded.iter_mut().find(|f| f.alias == route.alias) else {
            folded.push(route);
            continue;
        };
        // OR, not AND: one passthrough leg among the targets is enough to make
        // the scaled window unsafe for the alias as a whole.
        head.any_target_speaks_anthropic_natively |= route.any_target_speaks_anthropic_natively;
        head.context_window = min_opt(head.context_window, route.context_window);
        head.client_context_window =
            min_opt(head.client_context_window, route.client_context_window);
        // Fold the RESOLVED ceiling, never the two fields it is resolved from.
        // Folding them separately then applying precedence takes the winner from
        // one target and the loser from another: a target whose preset caps it at
        // 8192 beside one whose model ceiling is 1000 would keep the preset's
        // 8192 and advertise a limit the second target refuses. The resolved
        // value is folded into `max_output_tokens` and the preset field cleared,
        // so the precedence step downstream reads the answer already decided
        // here rather than re-deriving it from mixed halves.
        let folded_max_out = min_opt(route_max_output(head), route_max_output(&route));
        head.max_output_tokens = folded_max_out;
        head.preset_max_output_tokens = None;
        // Any of the targets may serve a request, so all must be chat models.
        head.chat &= route.chat;
        head.resolved_supports_vision &= route.resolved_supports_vision;
        head.resolved_supports_reasoning &= route.resolved_supports_reasoning;
        head.resolved_supports_function_calling &= route.resolved_supports_function_calling;
        head.resolved_supports_caching &= route.resolved_supports_caching;
        head.resolved_supports_audio_input &= route.resolved_supports_audio_input;
        head.resolved_supports_audio_output &= route.resolved_supports_audio_output;
        head.resolved_supports_video_input &= route.resolved_supports_video_input;
        head.resolved_supports_pdf_input &= route.resolved_supports_pdf_input;
        head.resolved_supports_response_schema &= route.resolved_supports_response_schema;
        head.resolved_supports_system_messages &= route.resolved_supports_system_messages;
        for tag in route.tags {
            if !head.tags.contains(&tag) {
                head.tags.push(tag);
            }
        }
        for tag in route.default_for_tags {
            if !head.default_for_tags.contains(&tag) {
                head.default_for_tags.push(tag);
            }
        }
    }
    folded
}

/// A route's effective per-call output ceiling: the alias's preset cap (the
/// proxy force-merges it onto every call, so it is the real ceiling), else the
/// model/catalog `max_output_tokens`. A non-positive value is not a ceiling and
/// is treated as unset.
///
/// The single place this precedence is applied — the proxy resolves it
/// per-target before folding across an alias's failover set, and this side must
/// resolve it the same way for the two surfaces to advertise the same number.
fn route_max_output(route: &ResolvedRoute) -> Option<i32> {
    route
        .preset_max_output_tokens
        .filter(|&m| m > 0)
        .or(route.max_output_tokens.filter(|&m| m > 0))
}

/// The smaller of two optional limits, treating `None` as "unknown", NOT as
/// zero: an unstated limit must not win the fold and silently shrink the
/// advertised contract to nothing.
fn min_opt(a: Option<i32>, b: Option<i32>) -> Option<i32> {
    match (a, b) {
        (Some(a), Some(b)) => Some(a.min(b)),
        (only, None) | (None, only) => only,
    }
}

/// The reserved wildcard tag — a route tagged `"*"` is offered to (and can be the
/// default for) every client, regardless of the client's `route_tag`.
pub(crate) const WILDCARD_TAG: &str = "*";

/// The `upstream_api_format` / client-protocol spelling for the Anthropic wire.
/// Named because the window advertised to a client turns on comparing the two
/// sides of a leg against it, and a typo in either comparison silently picks the
/// wrong window with nothing to report it.
const ANTHROPIC_MESSAGES_FORMAT: &str = "anthropic_messages";

/// Apply a template's `route_tag` filter to an already-resolved route set —
/// pure, in-memory. A route is offered to the client when its `tags` contain the
/// client's tag, contain the wildcard `"*"`, or are empty (legacy "all"). When
/// nothing matches the full set is returned (a client with no tag-specific routes
/// still sees the provider's models).
fn filter_routes_by_tag(all: &[ResolvedRoute], tag_filter: Option<&str>) -> Vec<ResolvedRoute> {
    if let Some(tag) = tag_filter {
        let tagged: Vec<_> = all
            .iter()
            .filter(|r| {
                r.tags.is_empty()
                    || r.tags.iter().any(|t| t == tag || t == WILDCARD_TAG)
            })
            .cloned()
            .collect();
        if !tagged.is_empty() {
            return tagged;
        }
    }
    all.to_vec()
}

/// Pick the route whose alias becomes the client's top-level default model.
/// Resolution is by specificity: a route whose `default_for_tags` contains the
/// client's exact `route_tag` wins; else the operator's **global default** (a
/// route whose `default_for_tags` contains the wildcard `"*"`); else the first
/// route. So one route tagged `default_for_tags: ["*"]` is the default for every
/// client, while a client-specific tag still overrides it. `routes` is never
/// empty here (the caller errors on an empty set first).
fn select_default_route<'a>(
    routes: &'a [ResolvedRoute],
    route_tag: Option<&str>,
) -> &'a ResolvedRoute {
    route_tag
        .and_then(|tag| {
            routes
                .iter()
                .find(|r| r.default_for_tags.iter().any(|t| t == tag))
        })
        .or_else(|| {
            routes
                .iter()
                .find(|r| r.default_for_tags.iter().any(|t| t == WILDCARD_TAG))
        })
        .unwrap_or(&routes[0])
}


/// The alias filling client model `slot` among `routes` (the template's
/// tag-filtered set), else the default route's. A holder whose targets are not
/// all chat models is skipped: the client would send it chat requests it
/// cannot answer, and a model's type can change after the slot was set.
fn slot_alias(routes: &[ResolvedRoute], default_route: &ResolvedRoute, slot: ClientSlot) -> String {
    routes
        .iter()
        .find(|r| r.chat && r.client_slots.contains(&slot))
        .unwrap_or(default_route)
        .alias
        .clone()
}

/// Build the `base_url` placeholder for a given protocol.
///
/// `byok_identity` is the URL fragment that identifies the caller on the
/// gateway's `/fwd/...` BYOK path — when `Some(sentinel)`, the URL embeds
/// `/fwd/<sentinel>` ahead of the protocol's normal suffix so the rendered
/// snippet uses BYOK semantics (gateway identity in the URL, the user's own
/// upstream key in the `Authorization` header). When `None`, the standard
/// `/v1` suffix (or bare origin for Anthropic / Gemini SDKs that append
/// their own version segment) is used.
fn compose_base_url(public_origin: &str, protocol: &str, byok_identity: Option<&str>) -> String {
    let prefix = match byok_identity {
        Some(ident) => format!("{public_origin}/fwd/{ident}"),
        None => public_origin.to_string(),
    };
    match protocol {
        // Anthropic SDKs vary on where they append the version segment:
        // - The official `anthropic` Python / TS SDK appends `/v1/messages`
        //   to baseURL, so a bare origin is correct.
        // - opencode's built-in Anthropic package appends only `/messages`
        //   and expects baseURL to already end in `/v1` — the opencode seed
        //   template handles this by writing `{{base_url}}/v1`.
        // Returning the bare origin (or BYOK prefix) here matches the SDK
        // contract; templates that need a `/v1` suffix add it themselves.
        "anthropic_messages" => prefix,
        // Gemini SDK (`@google/genai`) appends `/{apiVersion}/{path}` to
        // baseUrl with `apiVersion="v1beta"` by default — adding /v1beta
        // here would double-path to `/v1beta/v1beta/models/...` and 404.
        "google_gemini" => prefix,
        // OpenAI Chat Completions / Responses SDKs expect baseURL to end
        // at `/v1` — they append `/chat/completions`, `/responses`, etc.
        _ => format!("{prefix}/v1"),
    }
}

/// Resolve the upstream_api_format default per provider when the route doesn't pin one.
/// Resolve the protocol an upstream speaks when its route pins none.
///
/// Delegates to the proxy's own derivation rather than restating it. The two
/// used to be separate `match`es over the provider string and they did not
/// agree: this side matched `"anthropic"` and `"google"` as exact literals while
/// the proxy resolves through `Provider::from_str_relaxed`, which is
/// case-insensitive and knows the snake_case enum spellings. `provider` is free
/// text with no vocabulary check on write, so a server saved as `"Anthropic"` or
/// `"google_gemini"` was forwarded to as one protocol and described to the
/// client as another — which decides the base URL shape AND, since the units
/// rule, whether the scaled context window is advertised for a leg that is
/// really a passthrough.
fn default_upstream_api_format(provider: &str) -> &'static str {
    upstream_api_version_for_provider(provider, None).as_str()
}

/// Whether a route's upstream already speaks the Anthropic wire — i.e. whether
/// an Anthropic client's leg would be a passthrough (usage re-encoded raw) or a
/// translation (usage token-scaled). Same derivation the proxy uses to pick the
/// upstream protocol, so the two cannot answer differently for one route.
fn route_speaks_anthropic_natively(provider: &str, upstream_api_format: Option<&str>) -> bool {
    upstream_api_version_for_provider(provider, upstream_api_format)
        == ApiVersion::AnthropicMessages
}

/// Build the per-route placeholder dict: shared between (a) single-route
/// mode where these fields land on the parent map and (b) provider mode
/// where one such dict is built per route and stuffed into a
/// `Value::List(...)` keyed `routes`.
///
/// `client_protocol` is the template's `protocol` field — the protocol the
/// *client* speaks. When set it drives `{{base_url}}` so the rendered URL
/// matches what the client SDK appends to it (e.g. Gemini SDK expects
/// `/v1beta/models/...`, OpenAI SDK expects `/v1/chat/completions`,
/// Anthropic SDK appends `/v1/messages`). The route's `upstream_api_format` field
/// describes the *upstream* protocol — used by `{{upstream_api_format}}` for
/// templates that surface it, and as the fallback for `{{base_url}}` when
/// the template has no `protocol` (MCP-only templates).
/// Fallback `max_output_tokens` for client configs when a route resolves none
/// (self-hosted model, no catalog match). Capped by the context window when
/// known. Clients that require the field stay valid; the user can override.
const DEFAULT_CLIENT_MAX_OUTPUT_TOKENS: i64 = 8192;

fn build_route_scope(
    route: &ResolvedRoute,
    public_origin: &str,
    client_protocol: Option<&str>,
    forward_auth: bool,
) -> BTreeMap<String, Value> {
    let mut scope = BTreeMap::new();
    let upstream_api_format = route
        .upstream_api_format
        .clone()
        .unwrap_or_else(|| default_upstream_api_format(&route.provider).to_string());
    let base_url_protocol = client_protocol.unwrap_or(&upstream_api_format);
    // BYOK templates embed the gateway-identity sentinel (the `vk-*` plaintext
    // gets spliced in by the UI at copy time) inside the URL path. Non-BYOK
    // templates use the plain origin and identify the caller via the
    // `Authorization` header.
    let byok_identity = if forward_auth {
        Some(API_KEY_PLACEHOLDER)
    } else {
        None
    };
    let base_url = compose_base_url(public_origin, base_url_protocol, byok_identity);
    // Direct endpoint URLs used by raw-curl / SDK-env templates must follow
    // the same BYOK shape — without this, a curl-generic + BYOK render
    // produces `{origin}/v1/chat/completions` with the upstream-key sentinel
    // in the `Authorization` header, which hits the non-BYOK route and the
    // gateway can't authenticate it as a known `sk-*`. With BYOK on, the
    // endpoint host becomes `{origin}/fwd/<paste-your-api-key-here>` so the
    // proxy routes by the spliced `vk-*` and forwards the user's upstream
    // credential verbatim — Gemini included (its `?key=` query param /
    // `x-goog-api-key` header are both forwarded).
    let endpoint_host = match byok_identity {
        Some(ident) => format!("{public_origin}/fwd/{ident}"),
        None => public_origin.to_string(),
    };
    scope.insert("model_alias".into(), Value::String(route.alias.clone()));
    scope.insert("upstream_model".into(), Value::String(route.upstream_model.clone()));
    scope.insert("upstream_api_format".into(), Value::String(upstream_api_format.clone()));
    scope.insert("base_url".into(), Value::String(base_url));
    scope.insert(
        "endpoint_chat_completions".into(),
        Value::String(format!("{endpoint_host}/v1/chat/completions")),
    );
    scope.insert(
        "endpoint_responses".into(),
        Value::String(format!("{endpoint_host}/v1/responses")),
    );
    scope.insert(
        "endpoint_anthropic_messages".into(),
        Value::String(format!("{endpoint_host}/v1/messages")),
    );
    // Gemini endpoints follow the same BYOK shape: with `forward_auth` the host
    // becomes `{origin}/fwd/<sentinel>` and the client's `?key=` (or
    // `x-goog-api-key`) is forwarded to the upstream; without it they stay on the
    // bare origin.
    // Gemini is the one protocol carrying the model in the URL, so the name in
    // that path has to be the one the receiving side resolves. In gateway mode
    // the proxy reads it out of the path as `model_requested` and looks it up in
    // the ALIAS map, so an upstream model name there resolves only by the
    // coincidence of matching its alias. In BYOK the request passes through to
    // the provider, which knows only its own names.
    let gemini_path_model = if forward_auth {
        &route.upstream_model
    } else {
        &route.alias
    };
    scope.insert(
        "endpoint_gemini_generate".into(),
        Value::String(format!(
            "{endpoint_host}/v1beta/models/{gemini_path_model}:generateContent"
        )),
    );
    scope.insert(
        "endpoint_gemini_stream".into(),
        Value::String(format!(
            "{endpoint_host}/v1beta/models/{gemini_path_model}:streamGenerateContent"
        )),
    );
    // A window must be stated in the same units as the usage the client will be
    // sent. `client_context_window` is the TOKEN-SCALING channel: where it is
    // set, reported token counts are inflated by `client_cw / upstream_cw` so a
    // client working to the larger window compacts at the right real moment.
    //
    // That scaling exists ONLY where the response is BUILT as Anthropic from
    // another protocol. A same-protocol leg is a passthrough — usage is
    // re-encoded raw — so an Anthropic client on an Anthropic upstream is not
    // scaled either. Hence both halves of the test below; `client_protocol =
    // None` means the template inherits the upstream's own format, which makes
    // the two sides equal and correctly resolves to the honest window.
    //
    // Get this wrong in either direction and nothing reports it: the scaled
    // window with unscaled usage makes a client compact too LATE and overrun the
    // real limit, the honest window with scaled usage makes it compact far too
    // early and throw away context it still had.
    // An alias can carry several failover/LB targets, and the fold has already
    // recorded whether ANY of them is Anthropic-native. Every target must
    // translate for the scaled window to hold, because the request may be served
    // by any of them and a native leg is never scaled.
    let translates_to_anthropic = base_url_protocol == ANTHROPIC_MESSAGES_FORMAT
        && !route.any_target_speaks_anthropic_natively;
    let cw = if translates_to_anthropic {
        route.client_context_window.or(route.context_window)
    } else {
        route.context_window
    };
    if let Some(cw) = cw {
        scope.insert("context_window".into(), Value::Int(cw as i64));
    }
    // Always emit a positive `max_output_tokens`: some client configs REQUIRE it
    // and break when it's absent — crush sends `max_tokens: 0` (upstream 400), and
    // opencode without `limit.output` falls back to its own default cap. A
    // self-hosted route with no catalog match resolves no value, so fall back to
    // a default.
    // Precedence: the alias's preset cap (the proxy force-merges it, so it is the
    // real per-call ceiling) → the model/catalog `max_output_tokens` → the
    // default below. Without the preset a preset-only max-output
    // (no upstream/catalog value) would fall through to the 8192 default.
    // The default leaves at least half the upstream's real window free (at least
    // one token) — not the scaled client window — so a client sending it as
    // `max_tokens` on every call leaves room for its prompt.
    let max_out = route_max_output(route).map(i64::from).unwrap_or_else(|| {
        route.context_window.filter(|&c| c > 0).map_or(DEFAULT_CLIENT_MAX_OUTPUT_TOKENS, |c| {
            (i64::from(c) / 2).clamp(1, DEFAULT_CLIENT_MAX_OUTPUT_TOKENS)
        })
    });
    scope.insert("max_output_tokens".into(), Value::Int(max_out));
    scope.insert("supports_vision".into(), Value::Bool(route.resolved_supports_vision));
    scope.insert("supports_reasoning".into(), Value::Bool(route.resolved_supports_reasoning));
    scope.insert("supports_function_calling".into(), Value::Bool(route.resolved_supports_function_calling));
    scope.insert("supports_caching".into(), Value::Bool(route.resolved_supports_caching));
    scope.insert("supports_audio_input".into(), Value::Bool(route.resolved_supports_audio_input));
    scope.insert("supports_audio_output".into(), Value::Bool(route.resolved_supports_audio_output));
    scope.insert("supports_video_input".into(), Value::Bool(route.resolved_supports_video_input));
    scope.insert("supports_pdf_input".into(), Value::Bool(route.resolved_supports_pdf_input));
    scope.insert("supports_response_schema".into(), Value::Bool(route.resolved_supports_response_schema));
    scope.insert("supports_system_messages".into(), Value::Bool(route.resolved_supports_system_messages));
    scope
}

fn populate_provider_placeholders(
    placeholders: &mut BTreeMap<String, Value>,
    routes: &[ResolvedRoute],
    public_origin: &str,
    key_name: &str,
    route_tag: Option<&str>,
    client_protocol: Option<&str>,
    forward_auth: bool,
) {
    // `{{api_key}}` is consumed by the template at the `Authorization`
    // header position. Its meaning flips by mode:
    //   - non-BYOK: gateway-identity sentinel; UI splices the `sk-*`
    //     plaintext at copy time → user's request authenticates as that key.
    //   - BYOK: upstream-credential sentinel; UI leaves it untouched →
    //     user pastes their real upstream provider key (Anthropic/OpenAI)
    //     into the header before running. The gateway identity (`vk-*`)
    //     lives inside the URL path (`base_url`) instead — see
    //     `build_route_scope` where the BYOK path embeds
    //     `API_KEY_PLACEHOLDER` in `/fwd/<sentinel>/v1`.
    placeholders.insert(
        "api_key".into(),
        Value::String(if forward_auth {
            UPSTREAM_API_KEY_PLACEHOLDER.into()
        } else {
            API_KEY_PLACEHOLDER.into()
        }),
    );
    placeholders.insert("forward_auth".into(), Value::Bool(forward_auth));
    placeholders.insert("api_key_name".into(), Value::String(key_name.to_string()));
    // Choose the "default" route whose alias fills the top-level
    // `{{model_alias}}` / `{{base_url}}` etc. (so `opencode run` with no explicit
    // `--model` picks what the operator marked default). See [`select_default_route`].
    let default_route = select_default_route(routes, route_tag);
    placeholders.insert("provider_name".into(), Value::String(default_route.provider.clone()));
    placeholders.insert("provider_id".into(), Value::String(default_route.provider_id.to_string()));
    // The client model slots: `default` is the default route; `fast` and
    // `plan` are the route of the template's tag-filtered set holding that
    // slot, else the default route — so a client with several model settings
    // names one model everywhere until an admin fills a slot.
    for (placeholder, slot) in [("model_slot_fast", ClientSlot::Fast), ("model_slot_plan", ClientSlot::Plan)] {
        placeholders.insert(placeholder.into(), Value::String(slot_alias(routes, default_route, slot)));
    }
    placeholders.insert("model_slot_default".into(), Value::String(default_route.alias.clone()));
    let first_scope = build_route_scope(default_route, public_origin, client_protocol, forward_auth);
    placeholders.extend(first_scope);
    let items: Vec<BTreeMap<String, Value>> = routes
        .iter()
        .map(|r| build_route_scope(r, public_origin, client_protocol, forward_auth))
        .collect();
    placeholders.insert("routes".into(), Value::List(items));
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn a_client_read_names_its_workspace_or_is_refused() {
        let (asked, bound) = (Uuid::from_u128(1), Uuid::from_u128(2));
        // A signed-in member names it; nothing stands in for a missing one.
        assert_eq!(named_workspace(Some(asked), None).ok(), Some(asked));
        let refused = named_workspace(None, None).expect_err("no workspace named");
        assert_eq!(refused.status, axum::http::StatusCode::BAD_REQUEST);
        assert_eq!(refused.code, ApiErrorCode::ValidationFailed);
        // A key answers for the workspace it is bound to; one it names is the
        // one checked, so naming another reaches the confinement refusal.
        assert_eq!(named_workspace(None, Some(bound)).ok(), Some(bound));
        assert_eq!(named_workspace(Some(asked), Some(bound)).ok(), Some(asked));
    }

    fn route(context_window: Option<i32>, max_output_tokens: Option<i32>) -> ResolvedRoute {
        ResolvedRoute {
            provider_id: Uuid::nil(),
            provider: "custom".into(),
            alias: "m".into(),
            upstream_model: "m".into(),
            upstream_api_format: None,
            any_target_speaks_anthropic_natively: false,
            client_context_window: None,
            context_window,
            max_output_tokens,
            preset_max_output_tokens: None,
            tags: Vec::new(),
            default_for_tags: Vec::new(),
            client_slots: Vec::new(),
            chat: true,
            resolved_supports_vision: false,
            resolved_supports_reasoning: false,
            resolved_supports_function_calling: true,
            resolved_supports_caching: false,
            resolved_supports_audio_input: false,
            resolved_supports_audio_output: false,
            resolved_supports_video_input: false,
            resolved_supports_pdf_input: false,
            resolved_supports_response_schema: true,
            resolved_supports_system_messages: true,
        }
    }

    fn max_out(r: &ResolvedRoute) -> i64 {
        let scope = build_route_scope(r, "https://gw.example.com", None, false);
        match scope.get("max_output_tokens") {
            Some(Value::Int(n)) => *n,
            other => panic!("expected an integer max_output_tokens, got {other:?}"),
        }
    }

    #[test]
    fn a_provider_key_is_distinct_per_tenant_and_provider() {
        let nvidia = Uuid::parse_str("f2599e2c-d8a4-4546-aaae-3973e9ab6796").unwrap();
        let openrouter = Uuid::new_v4();
        let key = |tenant: &str, name: &str, id: Uuid, others: &[&str]| {
            let others: Vec<String> = others.iter().map(|s| s.to_string()).collect();
            client_provider_key(tenant, name, id, &others)
        };

        assert_eq!(key("globex", "NVIDIA", nvidia, &["OpenRouter free"]), "streamscope_globex_nvidia");
        // Each half of the pair separates two provisions on its own.
        assert_ne!(key("globex", "NVIDIA", nvidia, &[]), key("acme", "NVIDIA", nvidia, &[]));
        assert_ne!(
            key("globex", "NVIDIA", nvidia, &["OpenRouter free"]),
            key("globex", "OpenRouter free", openrouter, &["NVIDIA"]),
        );
        // Tenant slugs run to 50 characters; two that share their first 40 stay
        // distinct.
        let long = "acme-corporation-international-division-europe";
        assert_ne!(key(long, "NVIDIA", nvidia, &[]), key("acme-corporation-international-division-asia", "NVIDIA", nvidia, &[]));
        assert_eq!(key(long, "NVIDIA", nvidia, &[]), format!("streamscope_{long}_nvidia"));
        // Hyphenated slugs never run together across the separator.
        assert_ne!(key("acme-prod", "NVIDIA", nvidia, &[]), key("acme", "Prod NVIDIA", nvidia, &[]));
        // A re-provision of the same pair renders the same name.
        assert_eq!(key("globex", "NVIDIA", nvidia, &["x"]), key("globex", "NVIDIA", nvidia, &["x"]));
    }

    #[test]
    fn a_provider_key_stays_distinct_where_slugging_would_fold_two_names() {
        let a = Uuid::parse_str("f2599e2c-d8a4-4546-aaae-3973e9ab6796").unwrap();
        let b = Uuid::parse_str("0badc0de-0000-4000-8000-000000000000").unwrap();
        let names = |s: &[&str]| s.iter().map(|n| n.to_string()).collect::<Vec<_>>();
        // "NVIDIA" and "Nvidia!" are distinct rows but one slug: the newer one
        // (whose older names include the first) takes the suffix, and the
        // older keeps the name it already had — adding a provider renames none.
        let ka = client_provider_key("t", "NVIDIA", a, &names(&[]));
        let kb = client_provider_key("t", "Nvidia!", b, &names(&["NVIDIA"]));
        assert_eq!(ka, "streamscope_t_nvidia");
        assert_eq!(kb, "streamscope_t_nvidia-0badc0de");
        assert_ne!(ka, kb);
        // Just past the fold: a name that slugs differently keeps the bare slug.
        assert_eq!(client_provider_key("t", "NVIDIA", a, &names(&["NVIDIA 2"])), "streamscope_t_nvidia");
        // A name with nothing to slug is named by its id alone.
        assert_eq!(client_provider_key("t", "###", a, &[]), "streamscope_t_f2599e2c");
    }

    fn tagged(alias: &str, tags: &[&str], default_for_tags: &[&str]) -> ResolvedRoute {
        ResolvedRoute {
            alias: alias.into(),
            tags: tags.iter().map(|s| s.to_string()).collect(),
            default_for_tags: default_for_tags.iter().map(|s| s.to_string()).collect(),
            ..route(None, None)
        }
    }

    /// A slot names the chat alias holding it within the set the template
    /// sees; an empty slot, or one held by a non-chat alias, names the default.
    #[test]
    fn a_slot_names_its_route_and_an_empty_one_the_default() {
        let slotted = |alias: &str, slots: &[ClientSlot]| ResolvedRoute {
            client_slots: slots.to_vec(),
            ..tagged(alias, &["*"], &[])
        };
        let routes = [slotted("main", &[]), slotted("small", &[ClientSlot::Fast])];
        let default = &routes[0];
        assert_eq!(slot_alias(&routes, default, ClientSlot::Fast), "small");
        assert_eq!(slot_alias(&routes, default, ClientSlot::Plan), "main");
        // An alias whose targets hold both slots fills both.
        let both = [slotted("main", &[]), slotted("duo", &[ClientSlot::Plan, ClientSlot::Fast])];
        assert_eq!(slot_alias(&both, &both[0], ClientSlot::Fast), "duo");
        assert_eq!(slot_alias(&both, &both[0], ClientSlot::Plan), "duo");
        let without = [slotted("main", &[])];
        assert_eq!(slot_alias(&without, &without[0], ClientSlot::Fast), "main");
        // A holder that is not a chat model — on any of its targets — is skipped.
        let embed = ResolvedRoute { chat: false, ..slotted("vectors", &[ClientSlot::Fast]) };
        let skipped = [slotted("main", &[]), embed.clone()];
        assert_eq!(slot_alias(&skipped, &skipped[0], ClientSlot::Fast), "main");
        let mixed = fold_failover_targets(vec![
            slotted("small", &[ClientSlot::Fast]),
            ResolvedRoute { chat: false, ..slotted("small", &[ClientSlot::Fast]) },
        ]);
        assert!(!mixed[0].chat, "one non-chat target makes the alias non-chat");
    }

    /// Build one failover target for `alias`. `native` marks a leg whose
    /// upstream already speaks the Anthropic wire (a passthrough — never scaled).
    fn target(alias: &str, cw: Option<i32>, client_cw: Option<i32>, native: bool) -> ResolvedRoute {
        ResolvedRoute {
            alias: alias.into(),
            client_context_window: client_cw,
            any_target_speaks_anthropic_natively: native,
            ..route(cw, None)
        }
    }

    /// A client config has one entry per model id, so an alias's failover
    /// targets must collapse to one — otherwise the same id is written twice.
    #[test]
    fn failover_targets_collapse_to_one_entry_per_alias() {
        let folded = fold_failover_targets(vec![
            target("a", Some(200_000), None, false),
            target("a", Some(32_000), None, false),
            target("b", Some(8_000), None, false),
        ]);
        assert_eq!(folded.len(), 2);
        assert_eq!(folded[0].alias, "a");
        // The surviving figure must hold for whichever target serves the call.
        assert_eq!(folded[0].context_window, Some(32_000));
        assert_eq!(folded[1].context_window, Some(8_000));
    }

    /// An unstated window is unknown, not zero — it must not win the fold and
    /// erase a figure we do know.
    #[test]
    fn an_unknown_window_does_not_win_the_failover_fold() {
        let folded = fold_failover_targets(vec![
            target("a", Some(128_000), None, false),
            target("a", None, None, false),
        ]);
        assert_eq!(folded[0].context_window, Some(128_000));
        // …from either side, so the result cannot depend on target order.
        let reversed = fold_failover_targets(vec![
            target("a", None, None, false),
            target("a", Some(128_000), None, false),
        ]);
        assert_eq!(reversed[0].context_window, Some(128_000));
    }

    /// One passthrough leg is enough to make the scaled window unsafe for the
    /// whole alias, so the native flag folds with OR.
    #[test]
    fn one_native_target_marks_the_whole_alias_native() {
        let folded = fold_failover_targets(vec![
            target("a", None, None, false),
            target("a", None, None, true),
        ]);
        assert!(folded[0].any_target_speaks_anthropic_natively);
        // Positive control: an all-translating set stays translating, so this
        // cannot pass by marking everything native.
        let all_translating =
            fold_failover_targets(vec![target("a", None, None, false), target("a", None, None, false)]);
        assert!(!all_translating[0].any_target_speaks_anthropic_natively);
    }

    /// A capability survives the fold only where every target has it; the tag
    /// sets union, so a route offered through any target stays offered.
    #[test]
    fn the_fold_intersects_capabilities_and_unions_tags() {
        let mut a = target("a", None, None, false);
        a.resolved_supports_vision = true;
        a.tags = vec!["goose".into()];
        let mut b = target("a", None, None, false);
        b.resolved_supports_vision = false;
        b.tags = vec!["zed".into()];
        let folded = fold_failover_targets(vec![a.clone(), b]);
        assert!(!folded[0].resolved_supports_vision);
        assert_eq!(folded[0].tags, vec!["goose".to_string(), "zed".to_string()]);

        // Positive control on the intersection.
        let both = fold_failover_targets(vec![a.clone(), a]);
        assert!(both[0].resolved_supports_vision);
    }

    /// The output ceiling must be folded AFTER each target resolves its own
    /// preset-vs-model precedence. Folding the two fields separately and
    /// resolving afterwards takes the winner from one target and the loser from
    /// another, advertising a ceiling no single target actually offers.
    #[test]
    fn the_output_ceiling_folds_the_resolved_value_not_its_two_halves() {
        // A is capped at 8192 by its preset; B has no preset and a 1000 ceiling.
        // A request may land on B, so 1000 is the only honest claim.
        let a = ResolvedRoute {
            alias: "a".into(),
            preset_max_output_tokens: Some(8192),
            ..route(None, Some(8192))
        };
        let b = ResolvedRoute {
            alias: "a".into(),
            preset_max_output_tokens: None,
            ..route(None, Some(1000))
        };
        let folded = fold_failover_targets(vec![a, b]);
        assert_eq!(max_out(&folded[0]), 1000);
    }

    fn advertised_window(route: &ResolvedRoute, client_protocol: Option<&str>) -> Option<i64> {
        let scope = build_route_scope(route, "https://gw.example.com", client_protocol, false);
        match scope.get("context_window") {
            Some(Value::Int(n)) => Some(*n),
            _ => None,
        }
    }

    /// The scaled window is advertised ONLY where the response is built as
    /// Anthropic from another protocol — the one place token counts are inflated
    /// to match it. Every other combination gets the honest window, because its
    /// client is sent unscaled usage and would otherwise compact too late.
    #[test]
    fn the_scaled_window_is_advertised_only_where_usage_is_scaled() {
        let translating = target("a", Some(100_000), Some(1_000_000), false);
        assert_eq!(
            advertised_window(&translating, Some("anthropic_messages")),
            Some(1_000_000),
            "an Anthropic client on a translated leg IS scaled"
        );
        assert_eq!(
            advertised_window(&translating, Some("chat_completions")),
            Some(100_000),
            "an OpenAI-protocol client is never scaled"
        );

        // A same-protocol leg is a passthrough: usage is re-encoded raw, so even
        // an Anthropic client must be told the honest window.
        let native = target("a", Some(100_000), Some(1_000_000), true);
        assert_eq!(
            advertised_window(&native, Some("anthropic_messages")),
            Some(100_000),
            "an Anthropic client on an Anthropic-native upstream is a passthrough"
        );

        // A template pinning no protocol inherits the upstream's own, which
        // makes both sides of the test equal — a passthrough by construction,
        // and never scaled. The comment on the predicate reasons about this
        // case, so it is asserted rather than left to reasoning.
        assert_eq!(
            advertised_window(&native, None),
            Some(100_000),
            "an inherited protocol is a passthrough"
        );
        assert_eq!(
            advertised_window(&translating, None),
            Some(100_000),
            "…including where the upstream is not Anthropic at all"
        );
    }

    /// `upstream_servers.provider` is free text — no vocabulary check on write —
    /// so a brand arrives spelled several ways. Provisioning must resolve every
    /// spelling to the protocol the PROXY will actually forward with; a
    /// hand-written literal match agrees only for the spellings its author
    /// happened to list, and the surfaces then disagree about a live route.
    #[test]
    fn every_spelling_of_a_provider_resolves_to_the_protocol_the_proxy_forwards_with() {
        for spelling in ["anthropic", "Anthropic", "ANTHROPIC"] {
            assert_eq!(
                default_upstream_api_format(spelling),
                ANTHROPIC_MESSAGES_FORMAT,
                "spelling `{spelling}`"
            );
            assert!(route_speaks_anthropic_natively(spelling, None), "spelling `{spelling}`");
        }
        // The snake_case enum spelling is what `Provider` serialises to and what
        // `seeds/providers/providers.json` carries, so it reaches this column
        // more readily than any shorthand.
        for spelling in ["gemini", "google_gemini", "GoogleGemini"] {
            assert_eq!(
                default_upstream_api_format(spelling),
                "google_gemini",
                "spelling `{spelling}`"
            );
        }
        // Bare `"google"` is deliberately NOT a Gemini spelling: it names no
        // provider the proxy recognises, so it falls to the standard protocol
        // exactly as any unknown brand does. Provisioning must agree with that
        // rather than guess Gemini — the previous hand-written table guessed,
        // which described a server the proxy forwards to as chat_completions as
        // though it spoke Gemini, and pointed the rendered config at the wrong
        // base URL shape.
        assert_eq!(default_upstream_api_format("google"), "chat_completions");
        // An explicit format always wins over the brand…
        assert!(route_speaks_anthropic_natively("openai", Some(ANTHROPIC_MESSAGES_FORMAT)));
        // …and a brand that is not Anthropic is not native, which is the
        // positive control: the helper cannot pass by answering true always.
        assert!(!route_speaks_anthropic_natively("openai", None));
        assert!(!route_speaks_anthropic_natively("anthropic", Some("chat_completions")));
    }

    /// Gemini carries the model in the URL, and the two modes resolve that name
    /// against different maps: the gateway looks it up as an ALIAS, while a BYOK
    /// request reaches the provider, which knows only its own names.
    #[test]
    fn the_gemini_endpoint_names_what_the_receiving_side_resolves() {
        let mut r = route(None, None);
        r.alias = "fast".into();
        r.upstream_model = "gemini-2.5-flash".into();

        let gateway = build_route_scope(&r, "https://gw.example.com", None, false);
        let url = match gateway.get("endpoint_gemini_generate") {
            Some(Value::String(s)) => s.clone(),
            other => panic!("expected a URL, got {other:?}"),
        };
        assert!(url.contains("/models/fast:"), "gateway mode addresses the alias: {url}");

        let byok = build_route_scope(&r, "https://gw.example.com", None, true);
        let url = match byok.get("endpoint_gemini_generate") {
            Some(Value::String(s)) => s.clone(),
            other => panic!("expected a URL, got {other:?}"),
        };
        assert!(
            url.contains("/models/gemini-2.5-flash:"),
            "BYOK passes through to the provider's own name: {url}"
        );
    }

    #[test]
    fn filter_includes_wildcard_and_empty_for_every_client() {
        let all = vec![
            tagged("specific", &["claude-code"], &[]),
            tagged("global", &[WILDCARD_TAG], &[]),
            tagged("legacy", &[], &[]),
            tagged("other", &["cursor"], &[]),
        ];
        let aliases: Vec<_> = filter_routes_by_tag(&all, Some("claude-code"))
            .iter()
            .map(|r| r.alias.clone())
            .collect();
        // The client's own tag, the wildcard, and the empty (legacy "all") route
        // are offered; a route tagged only for another client is not.
        assert!(aliases.contains(&"specific".to_string()));
        assert!(aliases.contains(&"global".to_string()));
        assert!(aliases.contains(&"legacy".to_string()));
        assert!(!aliases.contains(&"other".to_string()));
    }

    #[test]
    fn default_route_prefers_specific_tag_over_wildcard() {
        let routes = vec![
            tagged("first", &[], &[]),
            tagged("global", &[WILDCARD_TAG], &[WILDCARD_TAG]),
            tagged("cc", &["claude-code"], &["claude-code"]),
        ];
        // A client with a specific default wins over the wildcard.
        assert_eq!(select_default_route(&routes, Some("claude-code")).alias, "cc");
        // A client without a specific default falls back to the wildcard global default.
        assert_eq!(select_default_route(&routes, Some("opencode")).alias, "global");
        // No route_tag at all still honours the wildcard global default.
        assert_eq!(select_default_route(&routes, None).alias, "global");
    }

    #[test]
    fn default_route_falls_back_to_first_without_wildcard() {
        let routes = vec![tagged("first", &[], &[]), tagged("cc", &["claude-code"], &["claude-code"])];
        // No wildcard default + no matching tag → the first route (legacy fallback).
        assert_eq!(select_default_route(&routes, Some("opencode")).alias, "first");
    }

    // A self-hosted route resolves no max_output_tokens — crush sends max_tokens:0
    // and opencode falls back to its own output cap unless we emit a positive value.
    #[test]
    fn max_output_tokens_always_positive() {
        // No max, no context → the bare default.
        assert_eq!(max_out(&route(None, None)), DEFAULT_CLIENT_MAX_OUTPUT_TOKENS);
        // No max, small context → half the context window, the prompt's share kept.
        assert_eq!(max_out(&route(Some(4096), None)), 2048);
        // No max, large context → the default cap, not the (huge) context window.
        assert_eq!(max_out(&route(Some(262_144), None)), DEFAULT_CLIENT_MAX_OUTPUT_TOKENS);
        // A real value always wins (the query already settled a catalog one,
        // an operator's is theirs).
        assert_eq!(max_out(&route(Some(262_144), Some(40_000))), 40_000);
        assert_eq!(max_out(&route(Some(65_536), Some(60_000))), 60_000);
        // No value, a window of exactly twice the default → the default; just under → half.
        assert_eq!(max_out(&route(Some(16_384), None)), DEFAULT_CLIENT_MAX_OUTPUT_TOKENS);
        assert_eq!(max_out(&route(Some(16_382), None)), 8_191);
        // Degenerate zero/absent values never leak a 0 (crush/opencode would break).
        assert_eq!(max_out(&route(Some(0), Some(0))), DEFAULT_CLIENT_MAX_OUTPUT_TOKENS);
        assert_eq!(max_out(&route(None, Some(0))), DEFAULT_CLIENT_MAX_OUTPUT_TOKENS);
        // The smallest windows still get a positive value no larger than themselves.
        assert_eq!(max_out(&route(Some(1), None)), 1);
        assert_eq!(max_out(&route(Some(3), None)), 1);
    }

    // A route whose max-output lives only in its preset (no upstream/catalog
    // value) must surface the preset cap, not the 8192 fallback — the opencode
    // `limit.output` bug.
    #[test]
    fn preset_max_output_takes_precedence() {
        let preset_only = ResolvedRoute { preset_max_output_tokens: Some(65_536), ..route(None, None) };
        assert_eq!(max_out(&preset_only), 65_536);
        // The preset wins over a model/catalog ceiling too (it is the effective
        // per-call value the proxy force-merges).
        let preset_over_model =
            ResolvedRoute { preset_max_output_tokens: Some(65_536), ..route(Some(200_000), Some(8192)) };
        assert_eq!(max_out(&preset_over_model), 65_536);
        // A zero/absent preset value falls back to the model value.
        let zero_preset =
            ResolvedRoute { preset_max_output_tokens: Some(0), ..route(None, Some(40_000)) };
        assert_eq!(max_out(&zero_preset), 40_000);
    }

    fn facts(declared: &[&str]) -> super::super::mcp_inputs::VsClientFacts {
        let declared_names: Vec<String> = declared.iter().map(|s| s.to_string()).collect();
        let client_headers: Vec<String> = declared_names.iter().map(|s| s.to_ascii_lowercase()).collect();
        let fwd_mount = client_headers.iter().any(|h| h == "authorization");
        let pass_through = fwd_mount && declared.len() == 1;
        super::super::mcp_inputs::VsClientFacts { client_headers, declared_names, fwd_mount, pass_through }
    }

    fn headers_of(item: &BTreeMap<String, Value>) -> Vec<(String, String)> {
        let Some(Value::List(list)) = item.get("headers") else { panic!("no headers list") };
        list.iter()
            .map(|h| match (h.get("name"), h.get("value")) {
                (Some(Value::String(n)), Some(Value::String(v))) => (n.clone(), v.clone()),
                _ => panic!("header item without name/value"),
            })
            .collect()
    }

    fn url_of(item: &BTreeMap<String, Value>) -> &str {
        match item.get("url") {
            Some(Value::String(u)) => u,
            _ => panic!("no url"),
        }
    }

    /// A static template sends the gateway key as a bearer on `/mcp/<slug>`
    /// and a sentinel for each header the client fills itself.
    #[test]
    fn a_static_item_carries_the_key_header_and_one_sentinel_per_client_header() {
        let item = mcp_server_item("https://gw", "jira", "Jira".into(), None, McpAuthMode::Static, false, &facts(&["X-Jira-Token"]))
            .expect("offered");
        assert_eq!(url_of(&item), "https://gw/mcp/jira");
        assert_eq!(
            headers_of(&item),
            vec![
                ("Authorization".to_string(), format!("Bearer {API_KEY_PLACEHOLDER}")),
                ("X-Jira-Token".to_string(), "<paste-your-jira-x-jira-token-here>".to_string()),
            ]
        );
        assert_matches!(item.get("forward_auth"), Some(Value::Bool(false)));
    }

    /// A client-filled `Authorization` moves the gateway key into the `/fwd`
    /// path: the header then carries the client's own value, never the key.
    #[test]
    fn a_client_authorization_moves_the_key_into_the_fwd_path() {
        let item = mcp_server_item("https://gw", "gh", "GitHub".into(), None, McpAuthMode::Static, false, &facts(&["Authorization"]))
            .expect("offered");
        assert_eq!(url_of(&item), format!("https://gw/fwd/{API_KEY_PLACEHOLDER}/mcp/gh"));
        assert_eq!(
            headers_of(&item),
            vec![("Authorization".to_string(), "<paste-your-gh-authorization-here>".to_string())]
        );
        assert_matches!(item.get("forward_auth"), Some(Value::Bool(true)));
    }

    /// A BYOK `vk-` key reaches only a server whose client sends its own
    /// `Authorization`, on `/fwd` with the key in the path; any other server
    /// is left out, naming why.
    #[test]
    fn a_byok_key_is_offered_only_the_servers_its_client_authorizes() {
        let item = mcp_server_item("https://gw", "gh", "GitHub".into(), None, McpAuthMode::Static, true, &facts(&["Authorization"]))
            .expect("offered");
        assert_eq!(url_of(&item), format!("https://gw/fwd/{API_KEY_PLACEHOLDER}/mcp/gh"));
        assert_eq!(
            headers_of(&item),
            vec![("Authorization".to_string(), "<paste-your-gh-authorization-here>".to_string())]
        );
        assert_eq!(
            mcp_server_item("https://gw", "jira", "Jira".into(), None, McpAuthMode::Static, true, &facts(&["X-Jira-Token"]))
                .err(),
            Some(VirtualOmit::PassThroughKeyNotAccepted)
        );
    }

    /// A local server stands in for a gateway one only where the caller can
    /// write it: any form for the CLI, which writes a project's own file;
    /// only `config` for the portal page, which renders the config outside a
    /// project and would refuse a `project` form.
    #[test]
    fn a_project_form_counts_as_writable_only_for_the_cli() {
        for cli in [false, true] {
            assert!(!writes_local_for(LocalMcpForm::None, cli));
            assert!(writes_local_for(LocalMcpForm::Config, cli));
        }
        assert!(writes_local_for(LocalMcpForm::Project, true));
        assert!(!writes_local_for(LocalMcpForm::Project, false));
    }

    /// A left-out server's warning carries its closed reason in snake_case
    /// and a message naming the server, one per reason.
    #[test]
    fn a_warning_names_the_server_and_its_reason() {
        let id = Uuid::new_v4();
        let w = McpServerWarning::new(id, "gh", VirtualOmit::SignInCannotReachFwd);
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["reason"], "sign_in_cannot_reach_fwd");
        assert_eq!(v["slug"], "gh");
        assert_eq!(v["virtual_server_id"], id.to_string());
        assert!(w.message.contains("'gh'") && w.message.contains("sign-in"), "{}", w.message);
        let w = McpServerWarning::new(id, "jira", VirtualOmit::PassThroughKeyNotAccepted);
        assert_eq!(serde_json::to_value(&w).unwrap()["reason"], "pass_through_key_not_accepted");
        assert!(w.message.contains("'jira'") && w.message.contains("pass-through"), "{}", w.message);

        // A local server names itself by its own id, never as a virtual one.
        let w = McpServerWarning::local(id, "fs", "Zed", false);
        let v = serde_json::to_value(&w).unwrap();
        assert_eq!(v["reason"], "local_server_not_supported");
        assert_eq!(v["local_server_id"], id.to_string());
        assert!(v["virtual_server_id"].is_null());
        assert!(w.message.contains("'fs'") && w.message.contains("Zed"), "{}", w.message);
        let w = McpServerWarning::local(id, "fs", "Claude Code", true);
        assert_eq!(serde_json::to_value(&w).unwrap()["reason"], "local_server_project_only");
        assert!(w.message.contains("'fs'") && w.message.contains("project"), "{}", w.message);
    }

    /// A sign-in template carries only the client headers, and a server that
    /// needs `/fwd` is left out of it (it has no key for the path), naming why.
    #[test]
    fn a_sign_in_item_carries_only_client_headers_and_skips_a_fwd_server() {
        let item = mcp_server_item("https://gw", "jira", "Jira".into(), None, McpAuthMode::SpecOauth, false, &facts(&["X-Jira-Token"]))
            .expect("offered");
        assert_eq!(url_of(&item), "https://gw/mcp/jira");
        assert_eq!(
            headers_of(&item),
            vec![("X-Jira-Token".to_string(), "<paste-your-jira-x-jira-token-here>".to_string())]
        );
        assert_eq!(
            mcp_server_item("https://gw", "gh", "GitHub".into(), None, McpAuthMode::SpecOauth, false, &facts(&["Authorization"]))
                .err(),
            Some(VirtualOmit::SignInCannotReachFwd)
        );
        // Positive control: no client header at all → no header line.
        let plain = mcp_server_item("https://gw", "w", "W".into(), None, McpAuthMode::SpecOauth, false, &facts(&[]))
            .expect("offered");
        assert!(headers_of(&plain).is_empty());
    }
}
