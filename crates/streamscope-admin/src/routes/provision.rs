//! CLI client-provisioning bundle — `POST /api/v1/portal/provision/actions/bundle`.
//!
//! The CLI's one-call provisioning surface: for a set of selected client
//! templates it mints (or reuses) ONE workspace gateway key, builds each
//! template's typed placeholder map, and returns the raw templates alongside
//! the server-rendered bodies. The CLI re-renders locally with the shared
//! `streamscope-client-templates` engine — the returned `rendered_body` is
//! its parity cross-check — and on later syncs compares `bundle_etag` to
//! detect drift without re-minting.
//!
//! Same contract as the web quickstart render: bodies carry the api-key
//! sentinel, plaintext rides once in `minted_secrets`, all writes share one
//! transaction (a mid-bundle failure strands no keys).

use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use axum::extract::State;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use streamscope_client_templates::{ClientProfileTemplate, Value};

use crate::AdminState;
use crate::db::tenant::TenantConn;

use super::portal_auth::PortalUser;
use super::portal_manager::confine_to_key_workspace;
use super::quickstart::{
    build_render_context, load_profiles, populate_template_placeholders, render_template_with,
    template_needs_key, KeySpec, McpServerSelection, MintedKey, MintedSecrets, RouteCache,
};
use super::{ApiError, ApiErrorCode, ApiErrorResponse};

#[derive(Deserialize, Serialize, ToSchema)]
pub struct ProvisionClientSelection {
    /// Client profile id (e.g. `claude-code`).
    pub client_id: String,
    /// Index into that profile's `templates`.
    pub template_index: usize,
}

#[derive(Deserialize, ToSchema)]
pub struct ProvisionBundleRequest {
    /// Workspace every rendered config draws on; the shared key is bound to
    /// it and the chosen provider + MCP servers must be granted by it.
    pub workspace_id: Uuid,
    /// Templates to bundle — at least one.
    pub clients: Vec<ProvisionClientSelection>,
    /// ONE gateway key shared by every selected client (mint or reuse).
    /// Required when any selected template embeds a key.
    #[serde(default)]
    pub key: Option<KeySpec>,
    /// Provider the LLM sections render against. Required when any selected
    /// template has an LLM section.
    #[serde(default)]
    pub llm_provider_id: Option<Uuid>,
    /// MCP virtual servers to wire into every MCP-capable selected template.
    #[serde(default)]
    pub mcp_servers: Vec<McpServerSelection>,
}

/// The gateway key the bundle embeds (sans plaintext — that rides once in
/// `minted_secrets` when freshly minted).
#[derive(Serialize, ToSchema)]
pub struct BundleKey {
    pub id: Uuid,
    pub name: String,
    pub key_prefix: Option<String>,
    pub forward_auth: bool,
}

#[derive(Serialize, ToSchema)]
pub struct ProvisionClientBundle {
    pub client_id: String,
    /// Display label of the client profile.
    pub label: String,
    pub template_index: usize,
    /// The RAW template — the CLI re-renders it locally on later syncs.
    pub template: ClientProfileTemplate,
    /// The values the server rendered with, by placeholder name — strings,
    /// flags and lists, as the template engine reads them. Never contains key
    /// plaintext — `api_key` resolves to the same sentinel as the body.
    pub placeholders: BTreeMap<String, Value>,
    /// Server-rendered body (sentinel intact) — the CLI cross-checks its
    /// local render against this to catch engine drift.
    pub rendered_body: String,
    pub rendered_instructions: Option<String>,
    /// Command that launches the tool (e.g. `claude`). `None` for GUI clients.
    pub launch_command: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct ProvisionBundleResponse {
    pub generated_at: chrono::DateTime<chrono::Utc>,
    /// Content hash over (selections, templates, placeholders, key id). A
    /// later `ssai sync` re-requests the bundle with `reuse_key_id`
    /// and treats an unchanged etag as "nothing to rewrite".
    pub bundle_etag: String,
    /// The shared gateway key the bundle embeds; `None` when no selected
    /// template needed one (spec-OAuth MCP-only).
    pub key: Option<BundleKey>,
    /// Key created by this call (empty on reuse). Same contract as the web
    /// quickstart render.
    pub minted_keys: Vec<MintedKey>,
    pub minted_secrets: MintedSecrets,
    pub clients: Vec<ProvisionClientBundle>,
    /// What the workspace is offered: its clients, and what its developers'
    /// sandbox may reach besides the gateway.
    pub client_access: super::client_access_profiles::WorkspaceClientAccess,
}

#[utoipa::path(
    post,
    path = "/api/v1/portal/provision/actions/bundle",
    tag = "Portal Provisioning",
    operation_id = "portal_provision_bundle",
    request_body = ProvisionBundleRequest,
    responses(
        (status = 200, description = "Raw templates + typed placeholders + rendered bodies sharing one gateway key", body = ProvisionBundleResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "No access to workspace, provider, or virtual server", body = ApiErrorResponse),
        (status = 404, description = "client_id not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn bundle(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Json(body): Json<ProvisionBundleRequest>,
) -> Result<Json<ProvisionBundleResponse>, ApiError> {
    // A portal `ak-` key (CI service account) may only provision within its
    // bound workspace — same confinement as the web quickstart render.
    confine_to_key_workspace(&user, body.workspace_id)?;
    if body.clients.is_empty() {
        return Err(ApiError::bad_request("select at least one client")
            .code(ApiErrorCode::ValidationFailed));
    }
    let tenant_uuid = db.tenant_uuid();

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("provision bundle begin tx: {e}");
        ApiError::internal("internal error")
    })?;

    // Resolve every selection against the tenant's profile snapshot up front
    // so a bad selection fails before any key is minted.
    let profiles = load_profiles(&mut tx).await?;
    let access = super::client_access_profiles::effective_client_access(&mut tx, Some(body.workspace_id)).await?;
    let mut selected: Vec<(String, String, Option<String>, usize, ClientProfileTemplate)> =
        Vec::new();
    let mut seen: HashSet<(String, usize)> = HashSet::new();
    for sel in &body.clients {
        if !seen.insert((sel.client_id.clone(), sel.template_index)) {
            return Err(ApiError::bad_request("the same client template was selected twice")
                .code(ApiErrorCode::ValidationFailed));
        }
        let profile = profiles
            .iter()
            .find(|p| p.id == sel.client_id)
            .ok_or_else(|| {
                ApiError::not_found(format!("client profile '{}' not found", sel.client_id), ApiErrorCode::ClientProfileNotFound)
            })?;
        if !access.offers(&profile.id) {
            return Err(super::client_access_profiles::client_disabled(&profile.id));
        }
        let template = profile
            .templates
            .get(sel.template_index)
            .cloned()
            .ok_or_else(|| {
                ApiError::bad_request(format!(
                    "template_index {} out of range for '{}'",
                    sel.template_index, sel.client_id
                ))
                .code(ApiErrorCode::ClientProfileNotCompatible)
            })?;
        selected.push((
            sel.client_id.clone(),
            profile.label.clone(),
            profile.launch_command.clone(),
            sel.template_index,
            template,
        ));
    }

    let needs_key = selected
        .iter()
        .any(|(_, _, _, _, t)| template_needs_key(t, !body.mcp_servers.is_empty()));
    // Auto-derived key names: a single-client bundle inherits that client's
    // id (matching the web wizard), a multi-client bundle mints under `cli`.
    let key_name_prefix = if selected.len() == 1 {
        selected[0].0.clone()
    } else {
        "cli".to_string()
    };

    let ctx = build_render_context(
        &mut tx,
        &state,
        tenant_uuid,
        &user,
        body.workspace_id,
        body.key.as_ref(),
        needs_key,
        &key_name_prefix,
        body.llm_provider_id,
    )
    .await?;

    let mut clients: Vec<ProvisionClientBundle> = Vec::with_capacity(selected.len());
    // One cache for the whole bundle: every selected client renders against the
    // same `llm_provider_id`, so the route join + catalog probe runs once, not
    // once per template.
    let mut route_cache = RouteCache::new();
    for (client_id, label, launch_command, template_index, template) in selected {
        let placeholders = populate_template_placeholders(
            &mut tx,
            &ctx,
            &template,
            body.llm_provider_id,
            &body.mcp_servers,
            body.workspace_id,
            &mut route_cache,
        )
        .await?;
        let (rendered_body, rendered_instructions) =
            render_template_with(&template, &placeholders)?;
        clients.push(ProvisionClientBundle {
            client_id,
            label,
            launch_command,
            template_index,
            template,
            placeholders,
            rendered_body,
            rendered_instructions,
        });
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("provision bundle commit: {e}");
        ApiError::internal("internal error")
    })?;

    let key = ctx.key_id.map(|id| BundleKey {
        id,
        name: ctx.key_name.clone(),
        key_prefix: match ctx.base_placeholders.get("api_key_prefix") {
            Some(Value::String(p)) => Some(p.clone()),
            _ => None,
        },
        forward_auth: ctx.forward_auth,
    });

    Ok(Json(ProvisionBundleResponse {
        generated_at: chrono::Utc::now(),
        bundle_etag: bundle_etag(&clients, ctx.key_id),
        key,
        minted_keys: ctx.minted_keys,
        minted_secrets: ctx.minted_secrets,
        clients,
        client_access: access.into_wire(),
    }))
}

/// Deterministic content hash of everything that decides what lands in the
/// client config files: the selections, raw templates, placeholder maps, and
/// the embedded key's id. Rendered bodies are derived from those inputs, so
/// hashing the inputs is equivalent and keeps the etag stable across renderer
/// releases that don't change output.
fn bundle_etag(clients: &[ProvisionClientBundle], key_id: Option<Uuid>) -> String {
    use sha2::{Digest, Sha256};
    let mut hasher = Sha256::new();
    for c in clients {
        hasher.update(c.client_id.as_bytes());
        hasher.update([0u8]);
        hasher.update(c.template_index.to_le_bytes());
        // Templates and placeholders serialize deterministically (struct
        // field order / BTreeMap key order).
        if let Ok(t) = serde_json::to_vec(&c.template) {
            hasher.update(&t);
        }
        if let Ok(p) = serde_json::to_vec(&c.placeholders) {
            hasher.update(&p);
        }
        hasher.update([0u8]);
    }
    if let Some(id) = key_id {
        hasher.update(id.as_bytes());
    }
    hex::encode(hasher.finalize())
}

#[derive(Deserialize, utoipa::IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ClientAccessQuery {
    /// The workspace the project is bound to.
    pub workspace_id: Uuid,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/client-access",
    tag = "Portal Provisioning",
    operation_id = "portal_client_access",
    params(ClientAccessQuery),
    responses(
        (status = 200, description = "The clients the workspace is offered, and what its developers' sandbox may reach besides the gateway", body = super::client_access_profiles::WorkspaceClientAccess),
        (status = 403, description = "Not a member of the workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// The provision bundle's `client_access` section on its own, for `ssai run`
/// to refresh without re-provisioning.
pub async fn client_access(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    axum::extract::Query(q): axum::extract::Query<ClientAccessQuery>,
) -> Result<Json<super::client_access_profiles::WorkspaceClientAccess>, ApiError> {
    confine_to_key_workspace(&user, q.workspace_id)?;
    let member: bool = sqlx::query_scalar(
        "SELECT EXISTS (SELECT 1 FROM workspace_members WHERE workspace_id = $1 AND user_id = $2)",
    )
    .bind(q.workspace_id)
    .bind(user.user_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("client access membership: {e}");
        ApiError::internal("internal error")
    })?;
    if !member {
        return Err(ApiError::forbidden("you are not a member of this workspace")
            .code(ApiErrorCode::WorkspaceMembershipRequired));
    }
    let access = super::client_access_profiles::effective_client_access(db.conn(), Some(q.workspace_id)).await?;
    Ok(Json(access.into_wire()))
}
