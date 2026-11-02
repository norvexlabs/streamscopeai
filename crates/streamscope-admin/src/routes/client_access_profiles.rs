//! Client access — the CONTENT adapter for the `client_access` profile kind:
//! which client profiles a workspace is offered (`client_access_members`), the
//! destination lists its developers' sandbox attaches as allow or block
//! (`client_access_destinations`), and its sandbox settings
//! (`client_access_sandbox`).
//!
//! The kind has only its tenant **Default**: every workspace resolves to it
//! ([`effective_client_access`]). Its membership is seeded once — when the
//! profile is created, for a new tenant or an existing one — and never on
//! restart, so a trim survives a reconcile; a client added later (a new
//! release's builtin) is not offered until an admin enables it.
//!
//! Read admin-side only — by the portal quickstart and the provision bundle —
//! and never shipped in a config body (`ProfileKind::on_edge`).

use axum::extract::Path;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use super::destination_lists::DestinationMode;
use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::tenant::{Scoped, TenantConn};
use crate::middleware::AuditDiffSink;
use crate::seed_loader::SeedLoader;

/// One client profile as the Clients section shows it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientAccessClient {
    /// The client profile id (e.g. `claude-code`).
    pub id: String,
    pub label: String,
    /// Offered to the profile's workspaces.
    pub offered: bool,
    /// Not offered, and added after the profile was created — a client a later
    /// release shipped, waiting for an admin to enable it.
    pub is_new: bool,
}

/// One destination list the sandbox attaches.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct DestinationAttachment {
    pub list_id: Uuid,
    pub mode: DestinationMode,
}

/// An attachment as shown, with the list's name.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct AttachedDestinationList {
    pub list_id: Uuid,
    pub name: String,
    pub mode: DestinationMode,
}

/// The sandbox settings, resolved (an unset setting reads its default).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct SandboxSettings {
    /// Refuse `ssai run --sandbox off` (and `learn`). Default `false`.
    pub require_sandbox: bool,
    /// Allow `ssai run --sandbox docker`. Default `true`.
    pub docker_tier: bool,
}

impl Default for SandboxSettings {
    fn default() -> Self {
        Self { require_sandbox: false, docker_tier: true }
    }
}

/// `GET /api/v1/admin/profiles/{id}/client-access`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ClientAccessResponse {
    pub is_default: bool,
    /// Every live client profile, offered or not.
    pub clients: Vec<ClientAccessClient>,
    pub destinations: Vec<AttachedDestinationList>,
    pub settings: SandboxSettings,
}

/// `PATCH /api/v1/admin/profiles/{id}/client-access`. Each section absent =
/// unchanged; a section present replaces it whole.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct UpdateClientAccessRequest {
    /// The ids of the client profiles offered.
    #[serde(default)]
    pub clients: Option<Vec<String>>,
    /// The destination lists the sandbox attaches, each once.
    #[serde(default)]
    pub destinations: Option<Vec<DestinationAttachment>>,
    #[serde(default)]
    pub settings: Option<SandboxSettingsPatch>,
}

/// The sandbox settings to change; a field absent is unchanged.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct SandboxSettingsPatch {
    #[serde(default)]
    pub require_sandbox: Option<bool>,
    #[serde(default)]
    pub docker_tier: Option<bool>,
}

/// What the sandbox of a workspace's developers may reach, flattened from
/// the attached lists: the provision bundle's `sandbox` section and the
/// portal's sandbox policy. The gateway is always reachable and is not listed.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct SandboxPolicy {
    /// Canonical entries of every list attached as allow.
    pub allow: Vec<String>,
    /// Canonical entries of every list attached as block — a block wins.
    pub block: Vec<String>,
    pub settings: SandboxSettings,
    /// Content hash of the three fields above: unchanged = nothing to rewrite.
    pub revision: String,
}

/// What a workspace is offered, as the provision bundle and the portal's
/// `client-access` answer carry it.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct WorkspaceClientAccess {
    /// The ids of the client profiles the workspace is offered.
    pub clients: Vec<String>,
    pub sandbox: SandboxPolicy,
}

/// What a workspace is offered.
pub(crate) struct ClientAccess {
    /// The ids of the offered client profiles.
    pub clients: std::collections::BTreeSet<String>,
    pub sandbox: SandboxPolicy,
}

impl ClientAccess {
    pub fn offers(&self, client_id: &str) -> bool {
        self.clients.contains(client_id)
    }

    pub fn into_wire(self) -> WorkspaceClientAccess {
        WorkspaceClientAccess { clients: self.clients.into_iter().collect(), sandbox: self.sandbox }
    }
}

/// The refusal for a client the workspace is not offered.
pub(crate) fn client_disabled(client_id: &str) -> ApiError {
    ApiError::forbidden(format!("the client '{client_id}' is disabled by your administrator"))
        .code(ApiErrorCode::ClientDisabled)
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles/{id}/client-access",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Client-access profile id")),
    responses(
        (status = 200, description = "The profile's clients, sandbox destinations and settings", body = ClientAccessResponse),
        (status = 404, description = "Profile not found / not a client-access profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_profile_client_access(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ClientAccessResponse>, ApiError> {
    let is_default = ensure_client_access_profile(db.conn(), id).await?;
    Ok(Json(load_content(db.conn(), id, is_default).await?))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/profiles/{id}/client-access",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Client-access profile id")),
    request_body = UpdateClientAccessRequest,
    responses(
        (status = 200, description = "The updated content", body = ClientAccessResponse),
        (status = 400, description = "Unknown client or list, or a list attached twice", body = ApiErrorResponse),
        (status = 404, description = "Profile not found / not a client-access profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_profile_client_access(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateClientAccessRequest>,
) -> Result<Json<ClientAccessResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let is_default = ensure_client_access_profile(db.conn(), id).await?;
    let before = load_content(db.conn(), id, is_default).await?;

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update client access (begin): {e}");
        ApiError::internal("failed to update client access")
    })?;
    if let Some(clients) = &body.clients {
        let mut keys = clients.clone();
        keys.sort_unstable();
        keys.dedup();
        let ids: Vec<Uuid> =
            sqlx::query_scalar("SELECT id FROM client_profiles WHERE profile_key = ANY($1) AND NOT suppressed")
                .bind(&keys)
                .fetch_all(&mut *tx)
                .await
                .map_err(write_failed("validate clients"))?;
        if ids.len() != keys.len() {
            return Err(ApiError::bad_request("one or more client ids do not exist")
                .code(ApiErrorCode::ClientProfileNotFound));
        }
        sqlx::query("DELETE FROM client_access_members WHERE profile_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(write_failed("clear clients"))?;
        sqlx::query(
            "INSERT INTO client_access_members (tenant_id, profile_id, client_profile_id) \
             SELECT $1, $2, c FROM unnest($3::uuid[]) AS c",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&ids)
        .execute(&mut *tx)
        .await
        .map_err(write_failed("write clients"))?;
    }
    if let Some(destinations) = &body.destinations {
        super::destination_lists::validate_attachments(&mut tx, destinations).await?;
        sqlx::query("DELETE FROM client_access_destinations WHERE profile_id = $1")
            .bind(id)
            .execute(&mut *tx)
            .await
            .map_err(write_failed("clear destinations"))?;
        let modes: Vec<&str> = destinations.iter().map(|d| d.mode.as_str()).collect();
        let ids: Vec<Uuid> = destinations.iter().map(|d| d.list_id).collect();
        sqlx::query(
            "INSERT INTO client_access_destinations (tenant_id, profile_id, list_id, mode) \
             SELECT $1, $2, l, m FROM unnest($3::uuid[], $4::text[]) AS a(l, m)",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(&ids)
        .bind(&modes)
        .execute(&mut *tx)
        .await
        .map_err(write_failed("write destinations"))?;
    }
    // A field absent leaves its column as it is (a new row: NULL, the default).
    if let Some(settings) = &body.settings
        && (settings.require_sandbox.is_some() || settings.docker_tier.is_some())
    {
        sqlx::query(
            "INSERT INTO client_access_sandbox (tenant_id, profile_id, require_sandbox, docker_tier) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, profile_id) DO UPDATE SET \
               require_sandbox = CASE WHEN $3::boolean IS NULL THEN client_access_sandbox.require_sandbox \
                                      ELSE $3 END, \
               docker_tier = CASE WHEN $4::boolean IS NULL THEN client_access_sandbox.docker_tier ELSE $4 END, \
               updated_at = now()",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(settings.require_sandbox)
        .bind(settings.docker_tier)
        .execute(&mut *tx)
        .await
        .map_err(write_failed("write sandbox settings"))?;
    }
    tx.commit().await.map_err(write_failed("commit"))?;

    let after = load_content(db.conn(), id, is_default).await?;
    audit_sink.record(Some(&before), Some(&after));
    Ok(Json(after))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/profiles/{id}/actions/attach-developer-defaults",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Client-access profile id")),
    responses(
        (status = 200, description = "The seeded developer lists are attached", body = ActionResponse),
        (status = 404, description = "Profile not found / not a client-access profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// Attach every seeded destination list that carries a developer default, in
/// that mode — package registries, container registries and GitHub allowed,
/// paste sites blocked. A list already attached keeps the mode the admin gave
/// it; a list the admin deleted is skipped; other attachments are kept.
pub async fn attach_developer_defaults(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    let is_default = ensure_client_access_profile(db.conn(), id).await?;
    let before = load_content(db.conn(), id, is_default).await?;
    let (keys, modes): (Vec<String>, Vec<&str>) = SeedLoader::new()
        .load_destination_lists()
        .into_iter()
        .filter_map(|s| Some((s.key, s.sandbox_default?.as_str())))
        .unzip();
    let attached = sqlx::query(
        "INSERT INTO client_access_destinations (tenant_id, profile_id, list_id, mode) \
         SELECT $1, $2, l.id, d.mode FROM unnest($3::text[], $4::text[]) AS d(key, mode) \
         JOIN (SELECT id, seed_key FROM destination_lists WHERE NOT suppressed FOR SHARE) l ON l.seed_key = d.key \
         ON CONFLICT (tenant_id, profile_id, list_id) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(id)
    .bind(&keys)
    .bind(&modes)
    .execute(db.conn())
    .await
    .map_err(write_failed("attach developer defaults"))?
    .rows_affected();
    let after = load_content(db.conn(), id, is_default).await?;
    audit_sink.record(Some(&before), Some(&after));
    Ok(Json(ActionResponse::ok().with_message(format!("{attached} destination lists attached."))))
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// What a workspace is offered (`None`: a caller with no workspace — a person
/// across their workspaces). Client-access profiles are not assigned per
/// workspace, so every workspace resolves to the tenant's Default; a tenant
/// without one is offered nothing.
pub(crate) async fn effective_client_access(
    conn: &mut Scoped,
    _workspace_id: Option<Uuid>,
) -> Result<ClientAccess, ApiError> {
    let profile: Option<Uuid> =
        sqlx::query_scalar("SELECT id FROM profiles WHERE kind = 'client_access' AND is_default")
            .fetch_optional(&mut *conn)
            .await
            .map_err(read_failed("resolve client-access profile"))?;
    let Some(profile) = profile else {
        tracing::warn!("no Default client-access profile: no client is offered");
        return Ok(ClientAccess { clients: Default::default(), sandbox: policy(Vec::new(), Vec::new(), SandboxSettings::default()) });
    };
    let clients: Vec<String> = sqlx::query_scalar(
        "SELECT c.profile_key FROM client_access_members m \
         JOIN client_profiles c ON c.id = m.client_profile_id AND NOT c.suppressed \
         WHERE m.profile_id = $1",
    )
    .bind(profile)
    .fetch_all(&mut *conn)
    .await
    .map_err(read_failed("load offered clients"))?;
    let lists: Vec<(String, serde_json::Value)> = sqlx::query_as(
        "SELECT d.mode, l.entries FROM client_access_destinations d \
         JOIN destination_lists l ON l.id = d.list_id AND NOT l.suppressed \
         WHERE d.profile_id = $1 ORDER BY l.name, l.id",
    )
    .bind(profile)
    .fetch_all(&mut *conn)
    .await
    .map_err(read_failed("load sandbox destinations"))?;
    let flat = super::destination_lists::Flattened::from_rows(lists);
    let settings = load_settings(conn, profile).await?;
    Ok(ClientAccess { clients: clients.into_iter().collect(), sandbox: policy(flat.allow, flat.block, settings) })
}

fn policy(allow: Vec<String>, block: Vec<String>, settings: SandboxSettings) -> SandboxPolicy {
    let mut h = Sha256::new();
    for (tag, entries) in [("allow", &allow), ("block", &block)] {
        h.update(tag.as_bytes());
        for e in entries {
            h.update([0]);
            h.update(e.as_bytes());
        }
        h.update([1]);
    }
    h.update([u8::from(settings.require_sandbox), u8::from(settings.docker_tier)]);
    let revision = h.finalize().iter().take(12).map(|b| format!("{b:02x}")).collect();
    SandboxPolicy { allow, block, settings, revision }
}

// ---------------------------------------------------------------------------
// Shared helpers (also the profile adapter arms for `kind='client_access'`)
// ---------------------------------------------------------------------------

/// Validate that `id` is a client-access profile of the current tenant;
/// returns whether it is the Default.
async fn ensure_client_access_profile(conn: &mut Scoped, id: Uuid) -> Result<bool, ApiError> {
    let row: Option<(String, bool)> = sqlx::query_as("SELECT kind, is_default FROM profiles WHERE id = $1")
        .bind(id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(read_failed("validate client-access profile"))?;
    match row {
        Some((kind, is_default)) if kind == "client_access" => Ok(is_default),
        _ => Err(ApiError::not_found("client-access profile not found", ApiErrorCode::ProfileNotFound)),
    }
}

async fn load_settings(conn: &mut Scoped, profile_id: Uuid) -> Result<SandboxSettings, ApiError> {
    let row: Option<(Option<bool>, Option<bool>)> =
        sqlx::query_as("SELECT require_sandbox, docker_tier FROM client_access_sandbox WHERE profile_id = $1")
            .bind(profile_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(read_failed("load sandbox settings"))?;
    let (require_sandbox, docker_tier) = row.unwrap_or_default();
    let default = SandboxSettings::default();
    Ok(SandboxSettings {
        require_sandbox: require_sandbox.unwrap_or(default.require_sandbox),
        docker_tier: docker_tier.unwrap_or(default.docker_tier),
    })
}

async fn load_content(conn: &mut Scoped, id: Uuid, is_default: bool) -> Result<ClientAccessResponse, ApiError> {
    let clients: Vec<(String, String, bool, bool)> = sqlx::query_as(
        "SELECT c.profile_key, c.label, m.client_profile_id IS NOT NULL, \
                m.client_profile_id IS NULL AND c.created_at > p.created_at \
         FROM client_profiles c \
         JOIN profiles p ON p.id = $1 \
         LEFT JOIN client_access_members m ON m.profile_id = p.id AND m.client_profile_id = c.id \
         WHERE NOT c.suppressed ORDER BY c.label, c.profile_key",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(read_failed("load client-access clients"))?;
    let destinations: Vec<(Uuid, String, String)> = sqlx::query_as(
        "SELECT l.id, l.name, d.mode FROM client_access_destinations d \
         JOIN destination_lists l ON l.id = d.list_id AND NOT l.suppressed \
         WHERE d.profile_id = $1 ORDER BY l.name, l.id",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(read_failed("load client-access destinations"))?;
    Ok(ClientAccessResponse {
        is_default,
        clients: clients
            .into_iter()
            .map(|(id, label, offered, is_new)| ClientAccessClient { id, label, offered, is_new })
            .collect(),
        destinations: destinations
            .into_iter()
            .filter_map(|(list_id, name, mode)| {
                Some(AttachedDestinationList { list_id, name, mode: DestinationMode::parse(&mode)? })
            })
            .collect(),
        settings: load_settings(conn, id).await?,
    })
}

/// Seed a profile's content: every live client offered, no destination list
/// attached, the settings at their defaults (the seed adapter — reset-to-seed).
/// Returns the number of clients offered.
pub(crate) async fn apply_seed(conn: &mut Scoped, tenant_id: Uuid, profile_id: Uuid) -> Result<i64, ApiError> {
    for clear in [
        "DELETE FROM client_access_members WHERE profile_id = $1",
        "DELETE FROM client_access_destinations WHERE profile_id = $1",
        "DELETE FROM client_access_sandbox WHERE profile_id = $1",
    ] {
        sqlx::query(clear).bind(profile_id).execute(&mut *conn).await.map_err(write_failed("clear for seed"))?;
    }
    seed_members(conn, tenant_id, profile_id).await.map_err(write_failed("seed clients"))
}

/// Offer every live client on `profile_id`. Returns the number added.
pub(crate) async fn seed_members(conn: &mut Scoped, tenant_id: Uuid, profile_id: Uuid) -> Result<i64, sqlx::Error> {
    let res = sqlx::query(
        "INSERT INTO client_access_members (tenant_id, profile_id, client_profile_id) \
         SELECT $1, $2, c.id FROM client_profiles c WHERE c.tenant_id = $1 AND NOT c.suppressed \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(profile_id)
    .execute(&mut *conn)
    .await?;
    Ok(res.rows_affected() as i64)
}

/// Offer one client on the tenant's Default (a client an admin created).
pub(crate) async fn offer_on_default(conn: &mut Scoped, tenant_id: Uuid, profile_key: &str) -> Result<(), ApiError> {
    sqlx::query(
        "INSERT INTO client_access_members (tenant_id, profile_id, client_profile_id) \
         SELECT $1, p.id, c.id FROM profiles p, client_profiles c \
         WHERE p.tenant_id = $1 AND p.kind = 'client_access' AND p.is_default \
           AND c.tenant_id = $1 AND c.profile_key = $2 \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .bind(profile_key)
    .execute(&mut *conn)
    .await
    .map_err(write_failed("offer new client"))?;
    Ok(())
}

/// The number of clients a profile offers — for list/detail `rule_count`.
pub(crate) async fn member_count(conn: &mut Scoped, id: Uuid) -> Result<i64, ApiError> {
    sqlx::query_scalar(
        "SELECT count(*) FROM client_access_members m \
         JOIN client_profiles c ON c.id = m.client_profile_id AND NOT c.suppressed \
         WHERE m.profile_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(read_failed("count offered clients"))
}

/// Create the tenant's Default client-access profile, offering every live
/// client. Runs once, inside the tenant's creation transaction; a client added
/// by a later release is never added to an existing Default.
pub(crate) async fn create_default_profile(conn: &mut Scoped, tenant_id: Uuid) -> Result<(), sqlx::Error> {
    let profile_id: Uuid = sqlx::query_scalar(
        "INSERT INTO profiles (tenant_id, kind, name, description, is_default, standalone) \
         VALUES ($1, 'client_access', 'Default', \
                 'The tenant default client access — the clients every workspace is offered and what its developers'' sandbox may reach.', \
                 true, true) \
         RETURNING id",
    )
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await?;
    seed_members(conn, tenant_id, profile_id).await.map(drop)
}

fn read_failed(what: &'static str) -> impl Fn(sqlx::Error) -> ApiError {
    move |e| {
        tracing::error!("{what}: {e}");
        ApiError::internal("failed to load client access")
    }
}

fn write_failed(what: &'static str) -> impl Fn(sqlx::Error) -> ApiError {
    move |e| {
        tracing::error!("{what}: {e}");
        ApiError::internal("failed to update client access")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_revision_moves_with_every_field_and_only_with_them() {
        let base = policy(vec!["a.lan:443".into()], vec!["b.lan:443".into()], SandboxSettings::default());
        let same = policy(vec!["a.lan:443".into()], vec!["b.lan:443".into()], SandboxSettings::default());
        assert_eq!(base.revision, same.revision);
        let moved = [
            policy(vec!["a.lan:22".into()], vec!["b.lan:443".into()], SandboxSettings::default()),
            policy(vec!["a.lan:443".into()], vec![], SandboxSettings::default()),
            policy(vec!["a.lan:443".into(), "b.lan:443".into()], vec![], SandboxSettings::default()),
            policy(
                vec!["a.lan:443".into()],
                vec!["b.lan:443".into()],
                SandboxSettings { require_sandbox: true, ..SandboxSettings::default() },
            ),
            policy(
                vec!["a.lan:443".into()],
                vec!["b.lan:443".into()],
                SandboxSettings { docker_tier: false, ..SandboxSettings::default() },
            ),
        ];
        for p in moved {
            assert_ne!(base.revision, p.revision, "{p:?}");
        }
        // An entry moved from allow to block is a different policy.
        let swapped = policy(vec!["b.lan:443".into()], vec!["a.lan:443".into()], SandboxSettings::default());
        assert_ne!(base.revision, swapped.revision);
    }

    #[test]
    fn a_disabled_client_is_refused_with_its_code() {
        let err = client_disabled("codex");
        assert_eq!(err.code, ApiErrorCode::ClientDisabled);
        assert_eq!(err.status, axum::http::StatusCode::FORBIDDEN);
    }
}
