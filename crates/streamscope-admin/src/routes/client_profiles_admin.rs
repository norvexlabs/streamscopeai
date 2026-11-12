//! Admin CRUD on the per-tenant `client_profiles` table (one row per profile,
//! keyed `(tenant_id, profile_key)`).
//!
//! Operations match the existing builtin-override pattern (see
//! `seeds/apps/*` and `seeds/tool-policy/rules.json`):
//!
//! * `GET    /api/v1/admin/client-profiles`        — list (paginated).
//! * `GET    /api/v1/admin/client-profiles/{id}`   — read one.
//! * `PUT    /api/v1/admin/client-profiles/{id}`   — replace; flips
//!   `is_builtin = false` so seed sync stops overwriting.
//! * `POST   /api/v1/admin/client-profiles/{id}/actions/reset` — re-load from
//!   disk, restoring `is_builtin = true` and clearing any suppression.
//! * `POST   /api/v1/admin/client-profiles/actions/reset` — the same for every
//!   builtin at once, forced over operator edits. It is what the UI offers to
//!   recover a builtin an operator deleted: a suppressed row is filtered out of
//!   every read, so there is no row left to act on, even though the per-id reset
//!   above would still restore it by seed id.
//! * `DELETE /api/v1/admin/client-profiles/{id}`   — a profile that came from
//!   the seed (`seeded`), customised or not, is soft-deleted (`suppressed = true`)
//!   so seed-sync never resurrects it; any other profile is removed outright.
//!
//! Save-time validation covers two failures, both silent in the field:
//! a template body whose substitution + escape produces invalid output for its
//! declared format (`ApiErrorCode::ClientProfileTemplateInvalid`), and a
//! profile that renders an LLM config the gateway key cannot reach
//! (`ApiErrorCode::ClientProfileKeyUnreachable`). The second is what makes
//! companion files safe to author: a cloned profile that loses its credential
//! file is refused rather than shipping a config that cannot authenticate.


use axum::extract::{Path, Query};
use axum::Json;
use serde::Serialize;
use utoipa::ToSchema;

use crate::db::tenant::{Scoped, TenantConn};
use crate::middleware::AuditDiffSink;
use crate::seed_loader::SeedLoader;
use streamscope_client_templates::ClientProfile;

use super::{
    ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery, ResetImpact,
};

#[derive(Serialize, ToSchema)]
pub struct ClientProfileListResponse {
    pub items: Vec<ClientProfile>,
    pub limit: i64,
    pub offset: i64,
    pub has_more: bool,
}

impl From<OffsetPage<ClientProfile>> for ClientProfileListResponse {
    fn from(p: OffsetPage<ClientProfile>) -> Self {
        Self { items: p.items, limit: p.limit, offset: p.offset, has_more: p.has_more }
    }
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/client-profiles",
    tag = "Client Profiles",
    operation_id = "admin_list_client_profiles",
    params(PageQuery),
    responses(
        (status = 200, description = "Per-tenant client_profiles snapshot", body = ClientProfileListResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<ClientProfileListResponse>, ApiError> {
    let (limit, offset) = page.resolve();
    let all = load_snapshot(db.conn()).await?;
    let total = all.len() as i64;
    let items: Vec<ClientProfile> = all.into_iter().skip(offset as usize).take(limit as usize).collect();
    let has_more = offset + (items.len() as i64) < total;
    Ok(Json(ClientProfileListResponse { items, limit, offset, has_more }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/client-profiles/{id}",
    tag = "Client Profiles",
    operation_id = "admin_get_client_profile",
    params(("id" = String, Path, description = "Profile id (e.g. 'claude-code')")),
    responses(
        (status = 200, description = "Single profile", body = ClientProfile),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_one(
    mut db: TenantConn,
    Path(id): Path<String>,
) -> Result<Json<ClientProfile>, ApiError> {
    let all = load_snapshot(db.conn()).await?;
    let p = all.into_iter().find(|p| p.id == id).ok_or_else(|| {
        ApiError::not_found("client profile not found", ApiErrorCode::ClientProfileNotFound)
    })?;
    Ok(Json(p))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/client-profiles",
    tag = "Client Profiles",
    operation_id = "admin_create_client_profile",
    request_body = ClientProfile,
    responses(
        (status = 200, description = "Created profile", body = ClientProfile),
        (status = 400, description = "Template body invalid for its format", body = ApiErrorResponse),
        (status = 409, description = "Profile with this id already exists", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(mut body): Json<ClientProfile>,
) -> Result<Json<ClientProfile>, ApiError> {
    if body.id.trim().is_empty() {
        return Err(ApiError::bad_request("profile id is required")
            .code(ApiErrorCode::ValidationFailed));
    }
    if !body
        .id
        .chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_')
    {
        return Err(ApiError::bad_request(
            "profile id must match ^[a-z0-9_-]+$",
        )
        .code(ApiErrorCode::ValidationFailed));
    }
    // A static route segment under `/client-profiles` outranks `{id}` in the
    // matcher, so a profile named after one could be created and then never
    // updated or deleted — every later PUT/DELETE would hit the static route
    // and 405. Refuse the collision instead of stranding the row.
    if RESERVED_PROFILE_IDS.contains(&body.id.as_str()) {
        return Err(ApiError::bad_request(format!(
            "'{}' is reserved and cannot be used as a profile id",
            body.id
        ))
        .code(ApiErrorCode::ValidationFailed));
    }
    validate_templates(&body)?;
    body.builtin = false;

    let tenant_id = db.tenant_uuid();
    let templates = templates_json(&body)?;
    // Insert a new user profile (one statement, no lock). A suppressed row with
    // the same key is resurrected as a user profile; a live row is a 409 (the
    // `WHERE suppressed` excludes it, so the upsert returns no row).
    let restored: Option<(String,)> = sqlx::query_as(
        "INSERT INTO client_profiles \
           (tenant_id, profile_key, label, homepage, supports_llm, supports_mcp, launch_command, templates, is_builtin, suppressed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, false, false) \
         ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
           label = EXCLUDED.label, homepage = EXCLUDED.homepage, supports_llm = EXCLUDED.supports_llm, \
           supports_mcp = EXCLUDED.supports_mcp, launch_command = EXCLUDED.launch_command, \
           templates = EXCLUDED.templates, is_builtin = false, suppressed = false, updated_at = now() \
         WHERE client_profiles.suppressed \
         RETURNING profile_key",
    )
    .bind(tenant_id)
    .bind(&body.id)
    .bind(&body.label)
    .bind(&body.homepage)
    .bind(body.supports_llm)
    .bind(body.supports_mcp)
    .bind(&body.launch_command)
    .bind(&templates)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("client_profiles create: {e}");
        ApiError::internal("internal error")
    })?;
    if restored.is_none() {
        return Err(ApiError::conflict("profile with that id already exists", ApiErrorCode::ClientProfileIdExists));
    }
    // A client an admin creates is offered at once; only a client a release
    // ships later waits for an admin to enable it.
    super::client_access_profiles::offer_on_default(db.conn(), tenant_id, &body.id).await?;
    // The generic change_diff capture locates a created row by the response
    // field named after the registry's id column (`profile_key`); this
    // response serialises the key as `id`, so the create diff is stamped here.
    audit_sink.record(None::<&ClientProfile>, Some(&body));
    Ok(Json(body))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/client-profiles/{id}",
    tag = "Client Profiles",
    operation_id = "admin_update_client_profile",
    params(("id" = String, Path, description = "Profile id")),
    request_body = ClientProfile,
    responses(
        (status = 200, description = "Updated profile", body = ClientProfile),
        (status = 400, description = "Template body invalid for its format", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update(
    mut db: TenantConn,
    Path(id): Path<String>,
    Json(mut body): Json<ClientProfile>,
) -> Result<Json<ClientProfile>, ApiError> {
    if body.id != id {
        return Err(ApiError::bad_request("path id and body id must match")
            .code(ApiErrorCode::ValidationFailed));
    }
    // Validate every template renders to syntactically valid output for its
    // declared format. We feed a placeholder dictionary that resolves every
    // documented variable to a stable test value so admin edits fail fast.
    validate_templates(&body)?;

    body.builtin = false; // any save flips off the builtin flag
    let tenant_id = db.tenant_uuid();
    let templates = templates_json(&body)?;
    // Single-statement update of this profile's row (flips `is_builtin=false`).
    // A suppressed (deleted) row is not addressable → 404, matching the old
    // blob behaviour where a deleted profile wasn't present.
    let updated: Option<(String,)> = sqlx::query_as(
        "UPDATE client_profiles SET \
           label = $3, homepage = $4, supports_llm = $5, supports_mcp = $6, \
           launch_command = $7, templates = $8, is_builtin = false, updated_at = now() \
         WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed \
         RETURNING profile_key",
    )
    .bind(tenant_id)
    .bind(&id)
    .bind(&body.label)
    .bind(&body.homepage)
    .bind(body.supports_llm)
    .bind(body.supports_mcp)
    .bind(&body.launch_command)
    .bind(&templates)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("client_profiles update: {e}");
        ApiError::internal("internal error")
    })?;
    if updated.is_none() {
        return Err(ApiError::not_found("client profile not found", ApiErrorCode::ClientProfileNotFound));
    }
    Ok(Json(body))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/client-profiles/{id}/actions/reset",
    tag = "Client Profiles",
    operation_id = "admin_reset_client_profile",
    params(("id" = String, Path, description = "Profile id")),
    responses(
        (status = 200, description = "Reset to builtin from disk", body = ClientProfile),
        (status = 404, description = "No matching builtin on disk", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn reset(
    mut db: TenantConn,
    Path(id): Path<String>,
) -> Result<Json<ClientProfile>, ApiError> {
    let loader = SeedLoader::new();
    let builtin = loader
        .load_client_profiles()
        .into_iter()
        .find(|p| p.id == id)
        .ok_or_else(|| {
            ApiError::not_found("no builtin profile with that id on disk", ApiErrorCode::ClientProfileNotFound)
        })?;

    let tenant_id = db.tenant_uuid();
    let templates = templates_json(&builtin)?;
    // Force-restore from disk: re-stamp `is_builtin=true` and clear any
    // suppression in one statement (keyed by `builtin.id`, which equals `id`).
    sqlx::query(
        "INSERT INTO client_profiles \
           (tenant_id, profile_key, label, homepage, supports_llm, supports_mcp, launch_command, templates, is_builtin, suppressed) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, false) \
         ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
           label = EXCLUDED.label, homepage = EXCLUDED.homepage, supports_llm = EXCLUDED.supports_llm, \
           supports_mcp = EXCLUDED.supports_mcp, launch_command = EXCLUDED.launch_command, \
           templates = EXCLUDED.templates, is_builtin = true, suppressed = false, updated_at = now()",
    )
    .bind(tenant_id)
    .bind(&builtin.id)
    .bind(&builtin.label)
    .bind(&builtin.homepage)
    .bind(builtin.supports_llm)
    .bind(builtin.supports_mcp)
    .bind(&builtin.launch_command)
    .bind(&templates)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("client_profiles reset: {e}");
        ApiError::internal("internal error")
    })?;
    Ok(Json(builtin))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/client-profiles/actions/reset",
    tag = "Client Profiles",
    operation_id = "admin_reset_client_profiles",
    responses(
        (status = 200, description = "Builtins restored from disk", body = ActionResponse),
        (status = 500, description = "No builtin profiles on disk", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// Restore every builtin profile from disk, forced over any prior operator
/// edit and clearing every soft-deletion.
///
/// This is the one path that reclaims a user-edited builtin — seed-sync
/// deliberately leaves `is_builtin = false` rows alone — and the only route the
/// UI has back to a builtin the operator deleted, since a suppressed row is
/// filtered out of every read and so has no row to act on (the per-id reset
/// still restores one, addressing the seed id rather than the stored row).
///
/// A user-created profile is preserved UNLESS it occupies a seed key, which the
/// restore force-writes; `custom_preserved` counts only the rows that survive,
/// so the impact never reports a row both restored and kept.
pub async fn reset_all(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    let loader = SeedLoader::new();
    let builtins = loader.load_client_profiles();
    if builtins.is_empty() {
        // Never proceed on an empty seed read: the orphan prune below would
        // delete every builtin the tenant has.
        tracing::error!("client_profiles reset: no builtin profiles on disk");
        return Err(ApiError::internal("no builtin client profiles on disk"));
    }

    let tenant_id = db.tenant_uuid();
    let keys: Vec<String> = builtins.iter().map(|b| b.id.clone()).collect();
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("begin client_profiles reset tx: {e}");
        ApiError::internal("failed to begin client profile reset")
    })?;

    // Counted before the writes, which are what change them. Every statement
    // below propagates with `?`: a swallowed error aborts the transaction
    // server-side and COMMIT then rolls the whole thing back while reporting
    // success.
    // Deleted profiles the seed still ships, customised first or not: the
    // restore below brings each back.
    let deleted_builtins_cleared: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM client_profiles WHERE tenant_id = $1 AND suppressed AND profile_key = ANY($2)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("count suppressed builtin client profiles: {e}");
        ApiError::internal("failed to reset client profiles")
    })?;
    // A user row occupying a SEED key is not preserved — the restore below
    // force-writes that key, which is the whole point of a reset. Counting it
    // as preserved would report it both restored and kept.
    let custom_preserved: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM client_profiles \
         WHERE tenant_id = $1 AND NOT is_builtin AND NOT suppressed AND profile_key <> ALL($2)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("count custom client profiles: {e}");
        ApiError::internal("failed to reset client profiles")
    })?;

    for b in &builtins {
        let templates = templates_json(b)?;
        // No `WHERE is_builtin AND NOT suppressed` guard, unlike seed-sync:
        // forcing over an operator's edit and clearing suppression is the
        // whole point of a reset.
        sqlx::query(
            "INSERT INTO client_profiles \
               (tenant_id, profile_key, label, homepage, supports_llm, supports_mcp, launch_command, templates, is_builtin, suppressed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, false) \
             ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
               label = EXCLUDED.label, homepage = EXCLUDED.homepage, supports_llm = EXCLUDED.supports_llm, \
               supports_mcp = EXCLUDED.supports_mcp, launch_command = EXCLUDED.launch_command, \
               templates = EXCLUDED.templates, is_builtin = true, suppressed = false, updated_at = now()",
        )
        .bind(tenant_id)
        .bind(&b.id)
        .bind(&b.label)
        .bind(&b.homepage)
        .bind(b.supports_llm)
        .bind(b.supports_mcp)
        .bind(&b.launch_command)
        .bind(&templates)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!(id = %b.id, "client_profiles reset upsert: {e}");
            ApiError::internal("failed to reset client profiles")
        })?;
    }

    // Drop builtin rows whose seed file no longer exists, mirroring seed-sync.
    // User rows are `is_builtin = false` and are never candidates; a deleted
    // (suppressed) row stays, so its delete stays final.
    sqlx::query(
        "DELETE FROM client_profiles \
         WHERE tenant_id = $1 AND is_builtin AND NOT suppressed AND profile_key <> ALL($2)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .execute(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("client_profiles reset orphan prune: {e}");
        ApiError::internal("failed to reset client profiles")
    })?;

    tx.commit().await.map_err(|e| {
        tracing::error!("commit client_profiles reset: {e}");
        ApiError::internal("failed to reset client profiles")
    })?;

    let impact = ResetImpact {
        builtins_restored: builtins.len(),
        custom_preserved: custom_preserved as usize,
        deleted_builtins_cleared: deleted_builtins_cleared as usize,
    };
    // A collection action has no single row for the generic capture to diff
    // (`resolve_diff_target` finds no resource id), so stamp the summary.
    audit_sink.record(None::<&ResetImpact>, Some(&impact));
    Ok(Json(
        ActionResponse::ok()
            .with_message(format!(
                "Restored {} built-in client profiles.",
                impact.builtins_restored
            ))
            .with_impact(impact),
    ))
}

/// One placeholder an author may use in a template or companion body, with
/// the value save-time validation resolves it to.
#[derive(Serialize, ToSchema)]
pub struct PlaceholderRef {
    pub name: String,
    /// `string` | `bool` | `int` | `list` — a `list` is iterated with
    /// `{{#each <name>}}`, and its per-item keys are in `item_keys`.
    pub kind: String,
    /// Sample value, or `None` for a list.
    pub sample: Option<String>,
    /// For a `list`, the keys available inside its `{{#each}}` block.
    pub item_keys: Vec<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PlaceholderReference {
    pub placeholders: Vec<PlaceholderRef>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/client-profiles/placeholders",
    tag = "Client Profiles",
    operation_id = "admin_client_profile_placeholders",
    responses(
        (status = 200, description = "Placeholders a template body may use", body = PlaceholderReference),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// The placeholder vocabulary, served from the same dictionary save-time
/// validation renders against — so the editor's reference cannot drift from
/// what the API will actually accept.
pub async fn placeholders() -> Json<PlaceholderReference> {
    use streamscope_client_templates::Value;
    let mut phs = streamscope_client_templates::fixture::validation_placeholders();
    // A template that declares a local form is also handed local MCP servers,
    // after the gateway's: list their keys beside a gateway item's.
    if let Some(Value::List(servers)) = phs.get_mut("mcp_servers") {
        servers.push(streamscope_client_templates::fixture::mcp_local_item("localfs"));
    }
    // `forward_auth` is a real placeholder — the seeds branch on it — but it is
    // deliberately absent from the base dictionary because `validate_profile`
    // supplies it per pass, rendering each body under both values. Name it here
    // so the editor's reference is the whole vocabulary an author may use.
    phs.insert("forward_auth".into(), Value::Bool(false));
    let placeholders = phs
        .into_iter()
        .map(|(name, v)| match v {
            Value::String(s) => PlaceholderRef {
                name,
                kind: "string".into(),
                sample: Some(s),
                item_keys: Vec::new(),
            },
            Value::Bool(b) => PlaceholderRef {
                name,
                kind: "bool".into(),
                sample: Some(b.to_string()),
                item_keys: Vec::new(),
            },
            Value::Int(n) => PlaceholderRef {
                name,
                kind: "int".into(),
                sample: Some(n.to_string()),
                item_keys: Vec::new(),
            },
            Value::List(items) => PlaceholderRef {
                name,
                kind: "list".into(),
                sample: None,
                // Every key an item may carry: a list's items differ in kind
                // (a gateway MCP server and a local one).
                item_keys: items
                    .iter()
                    .flat_map(|i| i.keys().cloned())
                    .collect::<std::collections::BTreeSet<String>>()
                    .into_iter()
                    .collect(),
            },
            Value::None => PlaceholderRef {
                name,
                kind: "string".into(),
                sample: None,
                item_keys: Vec::new(),
            },
        })
        .collect();
    Json(PlaceholderReference { placeholders })
}

/// One rendered template (or companion) in a preview.
#[derive(Serialize, ToSchema)]
pub struct PreviewedFile {
    pub title: String,
    pub filename: Option<String>,
    pub format: streamscope_client_templates::TemplateFormat,
    pub instructions: String,
    pub body: String,
}

#[derive(Serialize, ToSchema)]
pub struct PreviewedTemplate {
    #[serde(flatten)]
    #[schema(inline)]
    pub file: PreviewedFile,
    pub companions: Vec<PreviewedFile>,
}

#[derive(Serialize, ToSchema)]
pub struct ClientProfilePreview {
    pub templates: Vec<PreviewedTemplate>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/client-profiles/actions/preview",
    tag = "Client Profiles",
    operation_id = "admin_preview_client_profile",
    request_body = ClientProfile,
    responses(
        (status = 200, description = "Rendered preview of the draft", body = ClientProfilePreview),
        (status = 400, description = "A body or companion failed to render", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// Render a draft profile against the validation placeholder dictionary,
/// without saving it.
///
/// Deliberately the same code path as save-time validation — including the
/// delivery rules — so a preview that comes back clean IS a save that will
/// pass, and a preview that 400s names exactly what a save would reject.
pub async fn preview(
    Json(body): Json<ClientProfile>,
) -> Result<Json<ClientProfilePreview>, ApiError> {
    use streamscope_client_templates::{fixture, render, TemplateFormat};
    validate_templates(&body)?;

    // Validation above already proved every one of these renders, so a failure
    // here is not reachable; map it rather than unwrap.
    let render_err = |e: streamscope_client_templates::RenderError| {
        ApiError::bad_request(format!("preview render failed: {e}"))
            .code(ApiErrorCode::ClientProfileTemplateInvalid)
    };

    let mut templates = Vec::with_capacity(body.templates.len());
    for t in &body.templates {
        // What save-time validation renders the template with: a local MCP
        // server after the gateway's for a template that declares a form.
        let mut phs = fixture::validation_placeholders_for(t);
        phs.insert(
            "forward_auth".into(),
            streamscope_client_templates::Value::Bool(false),
        );
        let instructions = match t.instructions.as_deref() {
            Some(text) => render(text, TemplateFormat::Text, &phs).map_err(render_err)?,
            None => String::new(),
        };
        let companions = streamscope_client_templates::companion_files(t, &phs)
            .map_err(render_err)?
            .into_iter()
            .map(|c| PreviewedFile {
                title: c.title,
                filename: c.path,
                format: c.format,
                instructions: c.instructions,
                body: c.body,
            })
            .collect();
        templates.push(PreviewedTemplate {
            file: PreviewedFile {
                title: t.title.clone(),
                filename: t.filename.clone(),
                format: t.format,
                instructions,
                body: render(&t.body, t.format, &phs).map_err(render_err)?,
            },
            companions,
        });
    }
    Ok(Json(ClientProfilePreview { templates }))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/client-profiles/{id}",
    tag = "Client Profiles",
    operation_id = "admin_delete_client_profile",
    params(("id" = String, Path, description = "Profile id")),
    responses(
        (status = 200, description = "Deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete(
    mut db: TenantConn,
    Path(id): Path<String>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // A row that came from the seed — edited or not — is soft-deleted
    // (`suppressed=true`) so seed-sync won't resurrect it; a user profile is
    // hard-deleted. The row decides, in the one statement that acts on it; 404
    // when it matches no live row.
    let acted: i64 = sqlx::query_scalar(
        "WITH hidden AS ( \
           UPDATE client_profiles SET suppressed = true, updated_at = now() \
           WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed AND seeded \
           RETURNING 1), \
         removed AS ( \
           DELETE FROM client_profiles \
           WHERE tenant_id = $1 AND profile_key = $2 AND NOT suppressed AND NOT seeded \
           RETURNING 1) \
         SELECT (SELECT count(*) FROM hidden) + (SELECT count(*) FROM removed)",
    )
    .bind(tenant_id)
    .bind(&id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("client_profiles delete: {e}");
        ApiError::internal("internal error")
    })?;
    if acted == 0 {
        return Err(ApiError::not_found("client profile not found", ApiErrorCode::ClientProfileNotFound));
    }
    Ok(Json(ActionResponse::ok().with_message("Client profile deleted.")))
}

// ---------------------------------------------------------------------------
// Helpers — `client_profiles` is one row per profile (`(tenant_id, profile_key)`).
// Each mutating handler is a single statement (no blob, no lock); a user edit
// flips `is_builtin=false` and a deleted builtin is a `suppressed` row that
// seed-sync skips. These take a tenant-scoped `&mut Scoped` (RLS-scoped).
// ---------------------------------------------------------------------------

/// Ids that collide with a static route segment mounted under
/// `/client-profiles`. Keep in sync with the routes in `routes/mod.rs`.
const RESERVED_PROFILE_IDS: [&str; 2] = ["placeholders", "actions"];

/// One `client_profiles` row (`templates` is the nested `Vec` as JSONB).
#[derive(sqlx::FromRow)]
struct ClientProfileRow {
    profile_key: String,
    label: String,
    homepage: String,
    supports_llm: bool,
    supports_mcp: bool,
    launch_command: Option<String>,
    templates: serde_json::Value,
    is_builtin: bool,
}

impl ClientProfileRow {
    fn into_profile(self) -> Result<ClientProfile, serde_json::Error> {
        Ok(ClientProfile {
            id: self.profile_key,
            label: self.label,
            homepage: self.homepage,
            supports_llm: self.supports_llm,
            supports_mcp: self.supports_mcp,
            launch_command: self.launch_command,
            templates: serde_json::from_value(self.templates)?,
            builtin: self.is_builtin,
        })
    }
}

/// Load the tenant's live (non-suppressed) client profiles, ordered by key.
/// The single read path — shared with the quickstart renderer. RLS-scoped via
/// the tenant connection.
pub(crate) async fn load_snapshot(
    conn: &mut Scoped,
) -> Result<Vec<ClientProfile>, ApiError> {
    let rows: Vec<ClientProfileRow> = sqlx::query_as(
        "SELECT profile_key, label, homepage, supports_llm, supports_mcp, launch_command, templates, is_builtin \
         FROM client_profiles WHERE NOT suppressed ORDER BY profile_key",
    )
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("client_profiles load: {e}");
        ApiError::internal("internal error")
    })?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let key = r.profile_key.clone();
            r.into_profile()
                .map_err(|e| tracing::warn!(profile = %key, error = %e, "dropping malformed client profile"))
                .ok()
        })
        .collect())
}

/// Serialize a profile's nested template list for the `templates` JSONB column.
fn templates_json(p: &ClientProfile) -> Result<serde_json::Value, ApiError> {
    serde_json::to_value(&p.templates).map_err(|e| {
        tracing::error!("client_profiles serialise templates: {e}");
        ApiError::internal("internal error")
    })
}

/// Validate a profile against the shared stable placeholder dictionary
/// (`streamscope_client_templates::fixture`): every template and companion
/// renders cleanly for its declared format, and every LLM-bearing template can
/// actually put the gateway key in the user's hands.
///
/// The two failures carry DIFFERENT codes on purpose. A render failure means
/// the output did not parse; a delivery failure means it parsed fine and is
/// useless. Reporting the second as the first sends an operator hunting a
/// syntax error that does not exist.
fn validate_templates(profile: &ClientProfile) -> Result<(), ApiError> {
    use streamscope_client_templates::fixture::ProfileInvalid;
    streamscope_client_templates::fixture::validate_profile(profile).map_err(|e| {
        let code = match e {
            ProfileInvalid::Render { .. }
            | ProfileInvalid::KeyedArrayInvalid { .. }
            | ProfileInvalid::LocalMcpUnwritten { .. }
            | ProfileInvalid::LocalMcpValueRetyped { .. }
            | ProfileInvalid::LocalMcpOutsideProject { .. } => ApiErrorCode::ClientProfileTemplateInvalid,
            ProfileInvalid::KeyUnreachable { .. }
            | ProfileInvalid::CompanionOutOfScope { .. }
            | ProfileInvalid::CompanionPathInvalid { .. } => {
                ApiErrorCode::ClientProfileKeyUnreachable
            }
        };
        ApiError::bad_request(e.to_string()).code(code)
    })
}
