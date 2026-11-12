//! Client access — the CONTENT adapter for the `client_access` profile kind:
//! which client profiles a workspace is offered (`client_access_members`), the
//! destination lists its developers' sandbox attaches as allow or block
//! (`client_access_destinations`), its sandbox settings
//! (`client_access_sandbox`), and what it hides in the portal from its
//! workspaces' members (`client_access_portal`).
//!
//! Every profile of the kind is **Standalone**: it owns its whole content, and
//! an edit to the Default reaches no other profile (a destination list is
//! attached by id, so its entries are shared). A workspace resolves to the
//! profile assigned to it, else to the tenant's Default
//! ([`effective_client_access`], or [`offered_clients`] for the client set
//! alone); the Agent and Inline AI workspaces always resolve to the Default —
//! a rule the resolution itself holds, beside the assignment's refusal.
//!
//! A profile's membership is written once — the Default's when the tenant gets
//! it, another's when it is created from a copy or the seed — and never on
//! restart, so a trim survives a reconcile; a client added later (a new
//! release's builtin) is not offered on a profile until an admin enables it
//! there.
//!
//! Read admin-side only — by the portal quickstart, the provision bundle and
//! `portal_auth`, which resolves what the portal hides for each caller
//! ([`hidden_pages`]) — and never shipped in a config
//! body (`ProfileKind::on_edge`).

use axum::extract::Path;
use axum::Json;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use utoipa::ToSchema;
use uuid::Uuid;

use super::destination_lists::DestinationMode;
use super::portal_auth::PortalUser;
use super::portal_manager::MemberOf;
use super::portal_pages::{HiddenPages, PortalPage};
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
    /// What the portal hides from the members of the workspaces on this
    /// profile, `sessions` before `requests`: `sessions` is the Sessions page
    /// and every conversation's content, `requests` the Requests page. Hidden
    /// for a member only when every workspace they belong to hides it.
    pub hidden_pages: Vec<PortalPage>,
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
    /// What the portal hides for the profile's workspaces: the whole set — a
    /// key left out is shown again. A key that is not a portal page is refused
    /// (422) and nothing is written.
    #[serde(default)]
    pub hidden_pages: Option<Vec<PortalPage>>,
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
        (status = 422, description = "The body does not parse — a `hidden_pages` key that is not a portal page among them (`validation_failed`); nothing is written", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
/// Replace the sections sent — the clients offered, the destination lists, the
/// sandbox settings, the hidden portal pages — and leave the others as they
/// are.
pub async fn update_profile_client_access(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateClientAccessRequest>,
) -> Result<Json<ClientAccessResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();

    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update client access (begin): {e}");
        ApiError::internal("failed to update client access")
    })?;
    let is_default = ensure_client_access_profile(&mut tx, id).await?;
    let before = load_content(&mut tx, id, is_default).await?;
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
             SELECT $1, $2, c FROM unnest($3::uuid[]) AS c \
             ON CONFLICT DO NOTHING",
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
    // One row, written whole by one statement: of two concurrent saves the
    // later one stands — never a mix of the two.
    if let Some(pages) = &body.hidden_pages {
        let hidden = HiddenPages::from_pages(pages);
        sqlx::query(
            "INSERT INTO client_access_portal (tenant_id, profile_id, hide_sessions, hide_requests) \
             VALUES ($1, $2, $3, $4) \
             ON CONFLICT (tenant_id, profile_id) DO UPDATE SET \
               hide_sessions = EXCLUDED.hide_sessions, hide_requests = EXCLUDED.hide_requests, \
               updated_at = now()",
        )
        .bind(tenant_id)
        .bind(id)
        .bind(hidden.hides(PortalPage::Sessions))
        .bind(hidden.hides(PortalPage::Requests))
        .execute(&mut *tx)
        .await
        .map_err(write_failed("write hidden pages"))?;
    }
    // Read before the commit: the audited "after" is what this request wrote,
    // not what a later writer left.
    let after = load_content(&mut tx, id, is_default).await?;
    tx.commit().await.map_err(write_failed("commit"))?;

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
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("attach developer defaults (begin): {e}");
        ApiError::internal("failed to update client access")
    })?;
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
    .execute(&mut *tx)
    .await
    .map_err(write_failed("attach developer defaults"))?
    .rows_affected();
    // Read before the commit: the audited "after" is what this request wrote.
    let after = load_content(&mut tx, id, is_default).await?;
    tx.commit().await.map_err(write_failed("attach developer defaults (commit)"))?;
    audit_sink.record(Some(&before), Some(&after));
    Ok(Json(ActionResponse::ok().with_message(format!("{attached} destination lists attached."))))
}

// ---------------------------------------------------------------------------
// Resolution
// ---------------------------------------------------------------------------

/// The profile the workspace `$workspace` (a SQL expression for its id)
/// resolves to, as a SQL expression: the client-access profile assigned to it,
/// else the tenant's Default. Two joins narrow the assignment, so the rule
/// holds whatever wrote the row:
/// - the profile must be of the kind — a row pointing at another kind's
///   profile resolves to the Default, not to that profile's (absent) content;
/// - the workspace must not be the Agent or the Inline AI one — both always
///   resolve to the Default.
///
/// The one spelling of the resolution: a workspace's clients and sandbox
/// ([`RESOLVE_PROFILE_SQL`]) and a caller's hidden pages ([`HIDDEN_PAGES_SQL`])
/// both read it.
macro_rules! resolved_profile_sql {
    ($workspace:literal) => {
        concat!(
            "COALESCE( \
               (SELECT p.id FROM workspace_profile_assignments a \
                JOIN profiles p ON p.id = a.profile_id AND p.kind = 'client_access' \
                JOIN workspaces w ON w.id = a.workspace_id AND w.role NOT IN ('agent', 'inline') \
                WHERE a.workspace_id = ",
            $workspace,
            " AND a.kind = 'client_access'), \
               (SELECT id FROM profiles WHERE kind = 'client_access' AND is_default))"
        )
    };
}

/// The profile workspace `$1` resolves to.
const RESOLVE_PROFILE_SQL: &str = concat!("SELECT ", resolved_profile_sql!("$1"));

/// What the portal hides for a caller (`$1` the user, `$2` the workspace an
/// `ak-` key is bound to, or NULL): what the profile of EVERY workspace the
/// caller acts in hides — a person's memberships, a key's one workspace. A
/// caller in no workspace follows the Default. Each workspace is one row of
/// `effective`; a profile without a row hides nothing.
const HIDDEN_PAGES_SQL: &str = concat!(
    "WITH mine AS ( \
       SELECT wm.workspace_id AS id FROM workspace_members wm \
       WHERE wm.user_id = $1 AND $2::uuid IS NULL \
       UNION ALL \
       SELECT w.id FROM workspaces w WHERE w.id = $2), \
     effective AS ( \
       SELECT ",
    resolved_profile_sql!("mine.id"),
    " AS profile_id FROM mine \
       UNION ALL \
       SELECT id FROM profiles \
       WHERE kind = 'client_access' AND is_default AND NOT EXISTS (SELECT 1 FROM mine)) \
     SELECT COALESCE(bool_and(COALESCE(h.hide_sessions, false)), false), \
            COALESCE(bool_and(COALESCE(h.hide_requests, false)), false) \
     FROM effective e \
     LEFT JOIN client_access_portal h ON h.profile_id = e.profile_id"
);

/// What the portal hides for `user` — the ONE reader of that rule. Called
/// once per portal request, by `portal_auth`, which attaches the answer to the
/// request: the page fences, the request list, the Home and
/// `GET /portal/auth/me` read it there. One statement, never cached, so an
/// administrator's change holds from the caller's next request.
pub(crate) async fn hidden_pages(conn: &mut Scoped, user: &PortalUser) -> Result<HiddenPages, sqlx::Error> {
    let (sessions, requests): (bool, bool) = sqlx::query_as(HIDDEN_PAGES_SQL)
        .bind(user.user_id)
        .bind(user.key_workspace_id)
        .fetch_one(&mut *conn)
        .await?;
    Ok(HiddenPages::new(sessions, requests))
}

/// The one resolution behind [`offered_clients`] and
/// [`effective_client_access`]; `None` for a tenant without a Default.
async fn resolve_profile(conn: &mut Scoped, workspace_id: Uuid) -> Result<Option<Uuid>, ApiError> {
    let profile: Option<Uuid> = sqlx::query_scalar(RESOLVE_PROFILE_SQL)
        .bind(workspace_id)
        .fetch_one(&mut *conn)
        .await
        .map_err(read_failed("resolve client-access profile"))?;
    if profile.is_none() {
        tracing::warn!("no Default client-access profile: no client is offered");
    }
    Ok(profile)
}

/// The ids of the live clients `profile_id` offers.
async fn profile_clients(conn: &mut Scoped, profile_id: Uuid) -> Result<std::collections::BTreeSet<String>, ApiError> {
    let clients: Vec<String> = sqlx::query_scalar(
        "SELECT c.profile_key FROM client_access_members m \
         JOIN client_profiles c ON c.id = m.client_profile_id AND NOT c.suppressed \
         WHERE m.profile_id = $1",
    )
    .bind(profile_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(read_failed("load offered clients"))?;
    Ok(clients.into_iter().collect())
}

/// The ids of the clients the member's workspace is offered, and nothing else
/// — for a reader that only asks "is this client offered" (the quickstart's
/// list, its client read and its render). The resolution of
/// [`effective_client_access`], without the sandbox policy.
pub(crate) async fn offered_clients(
    conn: &mut Scoped,
    member: MemberOf,
) -> Result<std::collections::BTreeSet<String>, ApiError> {
    match resolve_profile(conn, member.workspace_id()).await? {
        Some(profile) => profile_clients(conn, profile).await,
        None => Ok(Default::default()),
    }
}

/// What the member's workspace is offered: the content of the client-access
/// profile assigned to it, else of the tenant's Default; a tenant without a
/// Default is offered nothing. It takes a [`MemberOf`], so it answers only a
/// caller that passed the membership gate for that workspace.
pub(crate) async fn effective_client_access(conn: &mut Scoped, member: MemberOf) -> Result<ClientAccess, ApiError> {
    let Some(profile) = resolve_profile(conn, member.workspace_id()).await? else {
        return Ok(ClientAccess { clients: Default::default(), sandbox: policy(Vec::new(), Vec::new(), SandboxSettings::default()) });
    };
    let clients = profile_clients(conn, profile).await?;
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
    Ok(ClientAccess { clients, sandbox: policy(flat.allow, flat.block, settings) })
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
        hidden_pages: load_hidden_pages(conn, id).await?,
    })
}

/// What `profile_id` hides, `sessions` before `requests`.
async fn load_hidden_pages(conn: &mut Scoped, profile_id: Uuid) -> Result<Vec<PortalPage>, ApiError> {
    let row: Option<(bool, bool)> =
        sqlx::query_as("SELECT hide_sessions, hide_requests FROM client_access_portal WHERE profile_id = $1")
            .bind(profile_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(read_failed("load hidden portal pages"))?;
    let (sessions, requests) = row.unwrap_or_default();
    Ok(HiddenPages::new(sessions, requests).into_vec())
}

/// Seed a profile's content: every live client offered, no destination list
/// attached, the settings at their defaults, no portal page hidden (the seed
/// adapter — create-from-seed and reset-to-seed).
/// Returns the number of clients offered.
pub(crate) async fn apply_seed(conn: &mut Scoped, tenant_id: Uuid, profile_id: Uuid) -> Result<i64, ApiError> {
    for clear in [
        "DELETE FROM client_access_members WHERE profile_id = $1",
        "DELETE FROM client_access_destinations WHERE profile_id = $1",
        "DELETE FROM client_access_sandbox WHERE profile_id = $1",
        "DELETE FROM client_access_portal WHERE profile_id = $1",
    ] {
        sqlx::query(clear).bind(profile_id).execute(&mut *conn).await.map_err(write_failed("clear for seed"))?;
    }
    seed_members(conn, tenant_id, profile_id).await.map_err(write_failed("seed clients"))
}

/// Copy `source_id`'s whole content onto `dest_id`, a profile with none yet
/// (the copy adapter — create-from-copy): the clients offered, the attached
/// destination lists with their modes, the hidden portal pages, and the
/// sandbox settings as stored (an unset one stays unset). Returns the number of
/// live clients offered.
///
/// ONE statement: its four inserts read the source under one snapshot, so the
/// copy is one state of it — never the clients from before an edit and the
/// sandbox from after. It copies what is live: a client or a destination list
/// already removed (or hidden) is left out rather than copied as a reference to
/// nothing.
pub(crate) async fn copy_content(
    conn: &mut Scoped,
    tenant_id: Uuid,
    source_id: Uuid,
    dest_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query(
        "WITH members AS ( \
           INSERT INTO client_access_members (tenant_id, profile_id, client_profile_id) \
           SELECT $1, $3, m.client_profile_id FROM client_access_members m \
           JOIN client_profiles c ON c.tenant_id = m.tenant_id AND c.id = m.client_profile_id AND NOT c.suppressed \
           WHERE m.tenant_id = $1 AND m.profile_id = $2), \
         destinations AS ( \
           INSERT INTO client_access_destinations (tenant_id, profile_id, list_id, mode) \
           SELECT $1, $3, d.list_id, d.mode FROM client_access_destinations d \
           JOIN destination_lists l ON l.tenant_id = d.tenant_id AND l.id = d.list_id AND NOT l.suppressed \
           WHERE d.tenant_id = $1 AND d.profile_id = $2), \
         hidden AS ( \
           INSERT INTO client_access_portal (tenant_id, profile_id, hide_sessions, hide_requests) \
           SELECT $1, $3, hide_sessions, hide_requests FROM client_access_portal \
           WHERE tenant_id = $1 AND profile_id = $2) \
         INSERT INTO client_access_sandbox (tenant_id, profile_id, require_sandbox, docker_tier) \
         SELECT $1, $3, require_sandbox, docker_tier FROM client_access_sandbox \
         WHERE tenant_id = $1 AND profile_id = $2",
    )
    .bind(tenant_id)
    .bind(source_id)
    .bind(dest_id)
    .execute(&mut *conn)
    .await
    .map_err(write_failed("copy profile content"))?;
    member_count(conn, dest_id).await
}

/// Whether `profile_id` is the tenant's Default client-access profile, read
/// for a workspace assignment about to be written in the caller's transaction;
/// 404 when it is no client-access profile of this tenant.
///
/// INVARIANT: no client-access assignment row names the Default profile — the
/// assignment stores "the Default" as no row, and a promotion deletes the rows
/// naming the profile it promotes ([`release_assignments`]). The read is
/// `FOR SHARE` so the two cannot cross: the assignment takes its share lock
/// before it writes its row, and the promotion, which updates that profile row
/// before it deletes, takes no workspace or share lock of its own.
pub(crate) async fn is_default_for_assignment(conn: &mut Scoped, profile_id: Uuid) -> Result<bool, ApiError> {
    let is_default: Option<bool> =
        sqlx::query_scalar("SELECT is_default FROM profiles WHERE id = $1 AND kind = 'client_access' FOR SHARE")
            .bind(profile_id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(read_failed("read the profile to assign"))?;
    is_default.ok_or_else(|| ApiError::not_found("profile not found", ApiErrorCode::ProfileNotFound))
}

/// Remove the assignments naming `profile_id`, the profile just promoted to
/// Default: its workspaces now reach it by inheriting. Left in place, a row
/// would pin its workspace to this profile after a later promotion of another,
/// with no matching choice in the workspace's picker. Runs after the
/// promotion's update of the profile row ([`is_default_for_assignment`]).
pub(crate) async fn release_assignments(conn: &mut Scoped, tenant_id: Uuid, profile_id: Uuid) -> Result<(), ApiError> {
    sqlx::query(
        "DELETE FROM workspace_profile_assignments \
         WHERE tenant_id = $1 AND kind = 'client_access' AND profile_id = $2",
    )
    .bind(tenant_id)
    .bind(profile_id)
    .execute(&mut *conn)
    .await
    .map_err(write_failed("release assignments of the promoted profile"))?;
    Ok(())
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

/// Offer one client an admin created on the tenant's Default as it is when
/// the client is created. Every other profile — one promoted to Default at
/// that moment included — shows it as new, not offered, for its admin to
/// enable.
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
                 'The tenant default — the clients offered to every workspace with no profile of its own, and what their developers'' sandbox may reach.', \
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
