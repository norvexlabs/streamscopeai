//! Workspace management.
//!
//! A workspace is the scope a key is minted against. It holds members, an
//! allowlist over the tenant's provider + MCP-server pool, a rate/budget pool
//! shared by its members, a default member limit with per-member exceptions,
//! and a selected tool profile. Every tenant has
//! exactly one **Default** workspace (`role = 'default'`): it cannot be deleted
//! and is the fallback every workspace resolves to. Membership is always
//! explicit — users do NOT auto-join it on creation (an admin adds them, or OIDC
//! group-sync adds them on login). Otherwise it is a normal workspace — its
//! allowlist starts empty and an operator grants providers / MCP servers
//! explicitly, and its rate-limit/budget are editable, exactly like any other
//! workspace.

use std::sync::Arc;

use axum::extract::{Path, Query};
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, OffsetPage, PageQuery};
use crate::db::tenant::{Scoped, TenantConn};
use crate::middleware::AuditDiffSink;
use crate::AdminState;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

/// A workspace's role — the single axis that governs the per-tenant singletons.
///
/// Persisted as the `workspaces.role` TEXT column (CHECK-constrained to these
/// four spellings; each non-`Standard` role is a per-tenant singleton via a
/// partial unique index). The serde/DB spelling is `lowercase`, pinned by
/// [`workspace_role_serde_matches_db_spelling`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "lowercase")]
pub enum WorkspaceRole {
    /// An ordinary workspace.
    Standard,
    /// The per-tenant Default workspace — the fallback every workspace resolves
    /// to. Undeletable.
    Default,
    /// The per-tenant Agent workspace — home of the internal agent's key.
    /// Undeletable.
    Agent,
    /// The per-tenant Inline AI workspace — home of the built-in inline-AI
    /// service account's `POST /v1/analyze` key. Undeletable.
    Inline,
}

impl WorkspaceRole {
    /// Parse a DB / wire spelling into the closed set. The column is
    /// CHECK-constrained, so an unrecognized value is corruption, not input —
    /// callers surface it as an error rather than coercing it.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "standard" => Some(WorkspaceRole::Standard),
            "default" => Some(WorkspaceRole::Default),
            "agent" => Some(WorkspaceRole::Agent),
            "inline" => Some(WorkspaceRole::Inline),
            _ => None,
        }
    }
}

// Decode the enum straight out of the TEXT column (both `FromRow` structs and
// `query_scalar` go through this). No `Encode` impl: `role` is only ever written
// as a SQL literal, never bound as a parameter.
impl sqlx::Type<sqlx::Postgres> for WorkspaceRole {
    fn type_info() -> sqlx::postgres::PgTypeInfo {
        <str as sqlx::Type<sqlx::Postgres>>::type_info()
    }
    fn compatible(ty: &sqlx::postgres::PgTypeInfo) -> bool {
        <str as sqlx::Type<sqlx::Postgres>>::compatible(ty)
    }
}

impl<'r> sqlx::Decode<'r, sqlx::Postgres> for WorkspaceRole {
    fn decode(value: sqlx::postgres::PgValueRef<'r>) -> Result<Self, sqlx::error::BoxDynError> {
        let s = <&str as sqlx::Decode<sqlx::Postgres>>::decode(value)?;
        WorkspaceRole::parse(s).ok_or_else(|| format!("invalid workspace role: {s:?}").into())
    }
}

/// DB-row projection for the workspace list (the columns the query selects).
/// Mapped into [`WorkspaceSummary`] with the per-kind assignments attached.
#[derive(sqlx::FromRow)]
struct WorkspaceSummaryRow {
    id: Uuid,
    name: String,
    description: Option<String>,
    role: WorkspaceRole,
    member_count: i64,
    provider_count: i64,
    mcp_server_count: i64,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, ToSchema)]
pub struct WorkspaceSummary {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    /// The workspace's role. `default`/`agent`/`inline` are the per-tenant
    /// singletons the UI badges (and which are undeletable); `standard` is an
    /// ordinary workspace. The Agent workspace wants the agent's provider(s)
    /// granted here (manual, like any workspace); the Inline AI workspace is the
    /// home of the built-in inline-AI service account's `POST /v1/analyze` key —
    /// its assigned profiles are the inline analysis policy, grant it no providers.
    pub role: WorkspaceRole,
    /// Per-kind profile selections for this workspace (`workspace_profile_assignments`
    /// joined to `profiles`). A kind with no entry runs that kind's tenant default.
    pub assigned_profiles: Vec<AssignedProfile>,
    pub member_count: i64,
    pub provider_count: i64,
    pub mcp_server_count: i64,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// A workspace's **explicit** profile choice for one `kind`. Present only when
/// the workspace has a row for that kind (an absent kind inherits the tenant
/// default). `profile_id`/`name` are `None` when the kind is explicitly **off**
/// (`mode = "off"`); a specific profile carries both (`mode = "profile"`). The
/// UI maps `{off}` / `{profile,id}` / absent → its three-state picker.
#[derive(Serialize, Clone, ToSchema, sqlx::FromRow)]
pub struct AssignedProfile {
    pub kind: String,
    pub profile_id: Option<Uuid>,
    pub name: Option<String>,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct Workspace {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub oidc_claim_name: Option<String>,
    pub oidc_claim_pattern: Option<String>,
    pub role: WorkspaceRole,
    /// `private` (default) — each member sees only their own usage, sessions and
    /// audit in the portal. `members` — any member sees the whole workspace's.
    pub member_visibility: String,
    /// Whether this workspace's spend rolls into the tenant's org-total budget.
    /// `false` takes it out of that bucket entirely — neither charged to the org
    /// ceiling nor blocked by it — for traffic the organisation does not fund.
    pub counts_toward_tenant_budget: bool,
    /// The QoS class this workspace's keys run as unless a key names its own.
    /// `null` = the tenant's default class.
    pub qos_class_id: Option<uuid::Uuid>,
    /// This workspace's share of a saturated model against the other
    /// workspaces backlogged on it (1–100; 1 is the default share).
    pub fairness_weight: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Current spend, in the tenant's accounting currency, for a workspace's budget
/// windows — the fleet-convergent
/// estimate from `usage_counters`, shown against the configured caps.
#[derive(Serialize, ToSchema, Default)]
pub struct WorkspaceBudgetUsage {
    pub daily_spent: f64,
    pub monthly_spent: f64,
}

#[derive(Serialize, ToSchema)]
pub struct WorkspaceDetail {
    #[serde(flatten)]
    #[schema(inline)]
    pub workspace: Workspace,
    pub member_count: i64,
    pub providers: Vec<WorkspaceProvider>,
    pub mcp_servers: Vec<WorkspaceMcpServer>,
    /// The local MCP servers (run on a member's own machine) the workspace is
    /// handed.
    pub mcp_local_servers: Vec<WorkspaceMcpLocalServer>,
    pub a2a_agents: Vec<WorkspaceA2aAgent>,
    /// Per-kind profile selections (`workspace_profile_assignments` → `profiles`).
    pub assigned_profiles: Vec<AssignedProfile>,
    #[schema(inline)]
    pub rate_limits: WorkspaceRateLimits,
    #[schema(inline)]
    pub usage: WorkspaceBudgetUsage,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateWorkspaceRequest {
    pub name: String,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub oidc_claim_name: Option<String>,
    #[serde(default)]
    pub oidc_claim_pattern: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateWorkspaceRequest {
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub description: Option<Option<String>>,
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub oidc_claim_name: Option<Option<String>>,
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub oidc_claim_pattern: Option<Option<String>>,
    /// `private` or `members` — how much of this workspace one member sees of
    /// another in the portal. Absent leaves it unchanged.
    #[serde(default)]
    pub member_visibility: Option<String>,
    /// Whether this workspace's spend rolls into the tenant's org-total budget.
    /// Absent leaves it unchanged.
    #[serde(default)]
    pub counts_toward_tenant_budget: Option<bool>,
    /// The QoS class this workspace's keys run as. Present and `null` clears it
    /// back to the tenant default; absent leaves it unchanged.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub qos_class_id: Option<Option<uuid::Uuid>>,
    /// This workspace's share of a saturated model (1–100). Absent leaves it
    /// unchanged.
    #[serde(default)]
    pub fairness_weight: Option<i32>,
    /// Per-kind profile choices to apply. A map entry sets that kind's
    /// assignment three-state; a kind **absent** from the map is left unchanged.
    /// The target profile (for `profile`) must exist in this tenant and match the
    /// kind.
    #[serde(default)]
    pub profiles: Option<std::collections::HashMap<String, ProfileAssignmentChoice>>,
}

/// A workspace's tri-state choice for one profile kind, sent in
/// [`UpdateWorkspaceRequest::profiles`]. Tagged discriminated union (`mode`):
/// - `{"mode":"inherit"}` → delete any explicit row → fall back to the tenant
///   default for that kind;
/// - `{"mode":"off"}` → upsert a NULL-profile row → the kind's policy is **fully
///   disabled** for this workspace (the proxy resolves [`EffectiveProfile::Off`]);
/// - `{"mode":"profile","id":<uuid>}` → upsert that profile id.
///
/// The `client_access` kind takes `inherit` and `profile` only, and `profile`
/// only on a workspace that is neither the Agent nor the Inline AI one.
#[derive(Deserialize, ToSchema)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ProfileAssignmentChoice {
    /// Inherit the tenant default (clear any explicit assignment).
    Inherit,
    /// Turn the kind fully off for this workspace.
    Off,
    /// Select a specific profile.
    Profile { id: Uuid },
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct MemberRow {
    pub user_id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub role: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Deserialize, ToSchema)]
pub struct AddMemberRequest {
    pub user_id: Uuid,
    #[serde(default = "default_role")]
    pub role: String,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateMemberRequest {
    pub role: String,
}

fn default_role() -> String {
    "member".to_string()
}

/// Validate a workspace member role. The workspace role plane is `member` /
/// `manager` — distinct from the console `admin_accounts.role` plane; "admin"
/// is never a workspace role.
fn validate_member_role(role: &str) -> Result<(), ApiError> {
    if role != "member" && role != "manager" {
        return Err(ApiError::bad_request("role must be 'member' or 'manager'")
            .code(ApiErrorCode::ValidationFailed));
    }
    Ok(())
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct WorkspaceProvider {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    /// A BYOK pass-through downstream.
    pub byok: bool,
    /// `false` only for a pass-through whose server is off: the grant then
    /// reaches nothing (the gateway's live-grant rule).
    pub enabled: bool,
    /// Unrevoked `vk-` keys of this workspace bound to this pass-through — what
    /// removing the grant leaves refused until it is granted again.
    pub bound_keys: i64,
}

#[derive(Deserialize, ToSchema)]
pub struct AddProviderRequest {
    pub provider_id: Uuid,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct WorkspaceMcpServer {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct AddMcpServerRequest {
    pub virtual_server_id: Uuid,
}

/// A local MCP server granted to a workspace.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct WorkspaceMcpLocalServer {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct AddMcpLocalServerRequest {
    pub local_server_id: Uuid,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct WorkspaceA2aAgent {
    pub id: Uuid,
    pub slug: String,
    pub name: String,
    pub description: Option<String>,
    pub enabled: bool,
}

#[derive(Deserialize, ToSchema)]
pub struct AddA2aAgentRequest {
    pub agent_id: Uuid,
}

/// Budget enforcement mode: block over-cap, or notify-without-blocking. Applies
/// to a scope's daily + monthly budgets together.
pub(crate) fn default_budget_mode() -> String {
    "enforce".to_string()
}

/// Normalise an inbound budget-mode string to a known value, falling back to
/// `enforce` for anything unrecognised (the DB column is plain TEXT).
pub(crate) fn norm_budget_mode(s: &str) -> String {
    if s == "alert_only" {
        "alert_only".to_string()
    } else {
        "enforce".to_string()
    }
}

#[derive(Serialize, Deserialize, ToSchema, sqlx::FromRow)]
pub struct WorkspaceRateLimits {
    pub requests_per_minute: Option<i32>,
    pub tokens_per_minute: Option<i32>,
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    /// `enforce` (block over-cap) | `alert_only` (notify but never block).
    #[serde(default = "default_budget_mode")]
    pub budget_mode: String,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct UserRateLimitOverride {
    pub user_id: Uuid,
    pub requests_per_minute: Option<i32>,
    pub tokens_per_minute: Option<i32>,
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    /// `enforce` (block over-cap) | `alert_only` (notify but never block).
    pub budget_mode: String,
    /// Who last set this exception: `admin` (the console) or `manager` (a
    /// workspace manager in the portal); `null` when unknown.
    #[sqlx(default)]
    pub set_via: Option<String>,
    /// The email of whoever last set it — withheld from the portal when that
    /// was an administrator.
    #[sqlx(default)]
    pub set_by_email: Option<String>,
    /// Current fleet-estimate spend, in the tenant's accounting currency,
    /// against this user's override caps in
    /// the active daily / monthly windows. Filled from `usage_counters`, not a
    /// stored column.
    #[sqlx(default)]
    #[serde(default)]
    pub daily_spent: f64,
    #[sqlx(default)]
    #[serde(default)]
    pub monthly_spent: f64,
}

#[derive(Deserialize, ToSchema)]
pub struct PutRateLimitOverrideRequest {
    #[serde(default)]
    pub requests_per_minute: Option<i32>,
    #[serde(default)]
    pub tokens_per_minute: Option<i32>,
    #[serde(default)]
    pub daily_budget: Option<f64>,
    #[serde(default)]
    pub monthly_budget: Option<f64>,
    /// `enforce` (block over-cap) | `alert_only` (notify but never block).
    /// Omitted ⇒ `enforce`.
    #[serde(default = "default_budget_mode")]
    pub budget_mode: String,
}

/// The default limit applied to every member of a workspace, one field per
/// metric. `null` = no default for that metric (members are limited only by
/// the workspace pool); a positive value applies to each member separately. A
/// member exception replaces it per metric.
#[derive(Serialize, Deserialize, ToSchema, Default, Clone, PartialEq, sqlx::FromRow)]
pub struct MemberLimitDefaults {
    #[serde(default)]
    pub requests_per_minute: Option<i32>,
    #[serde(default)]
    pub tokens_per_minute: Option<i32>,
    #[serde(default)]
    pub daily_budget: Option<f64>,
    #[serde(default)]
    pub monthly_budget: Option<f64>,
    /// `enforce` (block over-cap) | `alert_only` (notify but never block).
    #[serde(default = "default_budget_mode")]
    pub budget_mode: String,
}

/// Everything the workspace limits page needs to show what applies, not only
/// what was typed: the pool as stored, the tenant default an unset pool budget
/// inherits, and the member default.
#[derive(Serialize, ToSchema)]
pub struct WorkspaceLimitsOverview {
    /// The workspace pool as stored (`null` = unset).
    pub pool: WorkspaceRateLimits,
    /// The tenant default budget a pool budget left unset inherits, in the
    /// tenant's accounting currency (`0` = none).
    pub tenant_default_daily_budget: f64,
    pub tenant_default_monthly_budget: f64,
    pub member_defaults: MemberLimitDefaults,
    /// False on the Agent and Inline-AI workspaces, which take no member
    /// default.
    pub member_defaults_allowed: bool,
    pub member_count: i64,
    pub exception_count: i64,
}

/// Refuse a limit value no bucket can mean: a negative rate or budget, or a
/// budget that is not a finite number. `0` is allowed where the field allows
/// it (explicitly unlimited).
pub(crate) fn validate_limit_values(
    rpm: Option<i32>,
    tpm: Option<i32>,
    daily: Option<f64>,
    monthly: Option<f64>,
) -> Result<(), ApiError> {
    if rpm.is_some_and(|v| v < 0) || tpm.is_some_and(|v| v < 0) {
        return Err(ApiError::bad_request("a rate limit cannot be negative").code(ApiErrorCode::ValidationFailed));
    }
    if [daily, monthly].into_iter().flatten().any(|v| !v.is_finite() || v < 0.0) {
        return Err(ApiError::bad_request("a budget must be a non-negative number").code(ApiErrorCode::ValidationFailed));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Load a workspace's [`WorkspaceRole`], 404ing if it doesn't exist in this
/// tenant (RLS scopes the query). Used by every sub-resource handler as the
/// existence gate (which discards the role), and by delete to enforce the
/// singleton-protection rules.
/// `user_id`'s role in `workspace_id` (`member` | `manager`), or `None` when
/// they are not a member — the one membership read every membership and
/// manager check goes through (RLS-scoped, so a cross-tenant id is simply not
/// a member).
pub(crate) async fn member_role(
    db: &mut TenantConn,
    workspace_id: Uuid,
    user_id: Uuid,
) -> Result<Option<String>, ApiError> {
    sqlx::query_scalar("SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2")
        .bind(workspace_id)
        .bind(user_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("workspace membership read: {e}");
            ApiError::internal("internal error")
        })
}

/// Whether `user_id` is a member of `workspace_id`.
pub(crate) async fn is_member(db: &mut TenantConn, workspace_id: Uuid, user_id: Uuid) -> Result<bool, ApiError> {
    Ok(member_role(db, workspace_id, user_id).await?.is_some())
}

/// [`is_member`] for a TARGET member: 404 when they are not one.
pub(crate) async fn require_member(db: &mut TenantConn, workspace_id: Uuid, user_id: Uuid) -> Result<(), ApiError> {
    if is_member(db, workspace_id, user_id).await? {
        Ok(())
    } else {
        Err(ApiError::not_found("that user is not a member of this workspace", ApiErrorCode::WorkspaceMembershipRequired))
    }
}

pub(crate) async fn workspace_role(db: &mut TenantConn, id: Uuid) -> Result<WorkspaceRole, ApiError> {
    sqlx::query_scalar::<_, WorkspaceRole>("SELECT role FROM workspaces WHERE id = $1")
        .bind(id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("load workspace: {e}");
            ApiError::internal("failed to load workspace")
        })?
        .ok_or_else(|| ApiError::not_found("workspace not found", ApiErrorCode::WorkspaceNotFound))
}

// ---------------------------------------------------------------------------
// Workspace CRUD
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces",
    tag = "Workspaces",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of workspaces", body = OffsetPage<WorkspaceSummary>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_workspaces(
    mut db: TenantConn,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WorkspaceSummary>>, ApiError> {
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, WorkspaceSummaryRow>(
        "SELECT w.id, w.name, w.description, w.role, \
            (SELECT COUNT(*) FROM workspace_members m WHERE m.workspace_id = w.id) AS member_count, \
            (SELECT COUNT(*) FROM workspace_downstream_access a WHERE a.workspace_id = w.id) AS provider_count, \
            (SELECT COUNT(*) FROM workspace_mcp_access x WHERE x.workspace_id = w.id) AS mcp_server_count, \
            w.created_at \
         FROM workspaces w \
         ORDER BY (w.role = 'default') DESC, (w.role = 'agent') DESC, (w.role = 'inline') DESC, w.name ASC \
         LIMIT $1 OFFSET $2",
    )
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list workspaces: {e}");
        ApiError::internal("failed to list workspaces")
    })?;
    // Attach per-kind profile assignments in one query over the listed ids.
    let ids: Vec<Uuid> = rows.iter().map(|w| w.id).collect();
    let mut by_ws = load_assignments(db.conn(), &ids).await?;
    let items: Vec<WorkspaceSummary> = rows
        .into_iter()
        .map(|w| WorkspaceSummary {
            assigned_profiles: by_ws.remove(&w.id).unwrap_or_default(),
            id: w.id,
            name: w.name,
            description: w.description,
            role: w.role,
            member_count: w.member_count,
            provider_count: w.provider_count,
            mcp_server_count: w.mcp_server_count,
            created_at: w.created_at,
        })
        .collect();
    Ok(Json(OffsetPage::from_overfetched(items, limit, offset)))
}

/// Load per-kind profile assignments for a set of workspaces, grouped by
/// workspace id. RLS-scoped via the tenant connection.
async fn load_assignments(
    conn: &mut Scoped,
    workspace_ids: &[Uuid],
) -> Result<std::collections::HashMap<Uuid, Vec<AssignedProfile>>, ApiError> {
    if workspace_ids.is_empty() {
        return Ok(std::collections::HashMap::new());
    }
    // LEFT JOIN so an explicit-Off row (NULL profile_id) is still returned with a
    // NULL name — an INNER JOIN would silently drop it.
    let rows: Vec<(Uuid, String, Option<Uuid>, Option<String>)> = sqlx::query_as(
        "SELECT wpa.workspace_id, wpa.kind, wpa.profile_id, p.name \
         FROM workspace_profile_assignments wpa \
         LEFT JOIN profiles p ON p.id = wpa.profile_id \
         WHERE wpa.workspace_id = ANY($1) \
         ORDER BY wpa.kind ASC",
    )
    .bind(workspace_ids)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load workspace assignments: {e}");
        ApiError::internal("failed to load workspace assignments")
    })?;
    let mut by_ws: std::collections::HashMap<Uuid, Vec<AssignedProfile>> =
        std::collections::HashMap::new();
    for (ws, kind, profile_id, name) in rows {
        by_ws.entry(ws).or_default().push(AssignedProfile {
            kind,
            profile_id,
            name,
        });
    }
    Ok(by_ws)
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces",
    tag = "Workspaces",
    request_body = CreateWorkspaceRequest,
    responses(
        (status = 201, description = "Workspace created", body = Workspace),
        (status = 400, description = "Validation failed", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_workspace(
    mut db: TenantConn,
    Json(req): Json<CreateWorkspaceRequest>,
) -> Result<(axum::http::StatusCode, Json<Workspace>), ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("name is required").code(ApiErrorCode::ValidationFailed));
    }

    let tenant_id = db.tenant_uuid();
    let ws = sqlx::query_as::<_, Workspace>(
        "INSERT INTO workspaces (tenant_id, name, description, oidc_claim_name, oidc_claim_pattern, role) \
         VALUES ($1, $2, $3, $4, $5, 'standard') \
         RETURNING id, tenant_id, name, description, oidc_claim_name, oidc_claim_pattern, role, \
                   member_visibility, counts_toward_tenant_budget, qos_class_id, fairness_weight, \
                   created_at, updated_at",
    )
    .bind(tenant_id)
    .bind(req.name.trim())
    .bind(&req.description)
    .bind(&req.oidc_claim_name)
    .bind(&req.oidc_claim_pattern)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create workspace: {e}");
        ApiError::internal("failed to create workspace")
    })?;

    Ok((axum::http::StatusCode::CREATED, Json(ws)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "Workspace detail", body = WorkspaceDetail),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_workspace(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspaceDetail>, ApiError> {
    let workspace = sqlx::query_as::<_, Workspace>(
        "SELECT id, tenant_id, name, description, oidc_claim_name, oidc_claim_pattern, role, \
                member_visibility, counts_toward_tenant_budget, qos_class_id, fairness_weight, \
                created_at, updated_at \
         FROM workspaces WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("get workspace: {e}");
        ApiError::internal("failed to load workspace")
    })?
    .ok_or_else(|| ApiError::not_found("workspace not found", ApiErrorCode::WorkspaceNotFound))?;

    let member_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1")
        .bind(id)
        .fetch_one(db.conn())
        .await
        .unwrap_or(0);

    let providers = fetch_providers(&mut db, id, 0, 1000).await?;
    let mcp_servers = fetch_mcp_servers(&mut db, id, 0, 1000).await?;
    let mcp_local_servers = fetch_mcp_local_servers(&mut db, id, 0, 1000).await?;
    let a2a_agents = fetch_a2a_agents(&mut db, id, 0, 1000).await?;
    let rate_limits = fetch_rate_limits(&mut db, id).await?;
    let usage = fetch_workspace_usage(&mut db, id).await;
    let assigned_profiles = load_assignments(db.conn(), &[id])
        .await?
        .remove(&id)
        .unwrap_or_default();

    Ok(Json(WorkspaceDetail {
        workspace,
        member_count,
        providers,
        mcp_servers,
        mcp_local_servers,
        a2a_agents,
        assigned_profiles,
        rate_limits,
        usage,
    }))
}

/// Current daily + monthly budget spend, in the tenant's accounting currency,
/// for a workspace, from the
/// fleet-convergent `usage_counters`. Best-effort: returns zeroes on error or
/// when no spend has been recorded this window.
async fn fetch_workspace_usage(db: &mut TenantConn, id: Uuid) -> WorkspaceBudgetUsage {
    let now_ms = streamscope_core::usage::now_ms();
    let daily_start = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        streamscope_core::usage::UsageWindowKind::Daily.window_start_ms(now_ms) as i64,
    );
    let monthly_start = chrono::DateTime::<chrono::Utc>::from_timestamp_millis(
        streamscope_core::usage::UsageWindowKind::Monthly.window_start_ms(now_ms) as i64,
    );
    let row = sqlx::query_as::<_, (Option<i64>, Option<i64>)>(
        "SELECT \
            (SELECT total FROM usage_counters WHERE tenant_id = $1 AND scope_kind = 'workspace' \
               AND scope_id = $2 AND metric = 'budget_micros' AND window_kind = 'daily' AND window_start = $3), \
            (SELECT total FROM usage_counters WHERE tenant_id = $1 AND scope_kind = 'workspace' \
               AND scope_id = $2 AND metric = 'budget_micros' AND window_kind = 'monthly' AND window_start = $4)",
    )
    .bind(db.tenant_uuid())
    .bind(id)
    .bind(daily_start)
    .bind(monthly_start)
    .fetch_one(db.conn())
    .await;
    match row {
        Ok((daily, monthly)) => WorkspaceBudgetUsage {
            daily_spent: daily.unwrap_or(0) as f64 / 1_000_000.0,
            monthly_spent: monthly.unwrap_or(0) as f64 / 1_000_000.0,
        },
        Err(e) => {
            tracing::warn!("fetch workspace usage: {e}");
            WorkspaceBudgetUsage::default()
        }
    }
}

/// The choice as it is stored: one naming the kind's Default profile is
/// inherit — no assignment row names the Default.
fn stored_choice(choice: &ProfileAssignmentChoice, names_default: bool) -> &ProfileAssignmentChoice {
    const INHERIT: ProfileAssignmentChoice = ProfileAssignmentChoice::Inherit;
    if names_default { &INHERIT } else { choice }
}

/// What a workspace of `role` may be assigned for the client-access kind
/// (every other kind takes every choice). Refused before any write:
/// - **Off** — a workspace always resolves to a client-access profile; with
///   none it would be offered no client and no sandbox policy;
/// - **a profile on the Agent or Inline AI workspace** — neither has developers
///   provisioning clients, and both stay on the tenant's Default.
///
/// Inherit is always taken: it removes the assignment.
fn client_access_assignment_allowed(
    kind: streamscope_core::config::ProfileKind,
    role: WorkspaceRole,
    choice: &ProfileAssignmentChoice,
) -> Result<(), ApiError> {
    if kind != streamscope_core::config::ProfileKind::ClientAccess {
        return Ok(());
    }
    match (choice, role) {
        (ProfileAssignmentChoice::Inherit, _) => Ok(()),
        (ProfileAssignmentChoice::Off, _) => Err(super::profiles::choice_unsupported(
            "client access cannot be turned off for a workspace: assign a profile or the Default",
        )),
        (ProfileAssignmentChoice::Profile { .. }, WorkspaceRole::Agent | WorkspaceRole::Inline) => {
            Err(super::profiles::choice_unsupported(
                "the Agent and Inline AI workspaces keep the Default client-access profile",
            ))
        }
        (ProfileAssignmentChoice::Profile { .. }, WorkspaceRole::Standard | WorkspaceRole::Default) => Ok(()),
    }
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = UpdateWorkspaceRequest,
    responses(
        (status = 200, description = "Workspace updated", body = Workspace),
        (status = 400, description = "Validation failed, or a profile choice the kind does not take", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_workspace(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateWorkspaceRequest>,
) -> Result<Json<Workspace>, ApiError> {
    // Existence gate.
    workspace_role(&mut db, id).await?;
    let tenant_id = db.tenant_uuid();

    // Checked here as well as by the column CHECK, so an unknown value is a 400
    // naming the accepted set rather than a 500 from a constraint violation.
    if let Some(v) = req.member_visibility.as_deref()
        && !matches!(v, "private" | "members")
    {
        return Err(
            ApiError::bad_request("member_visibility must be 'private' or 'members'")
                .code(ApiErrorCode::ValidationFailed),
        );
    }

    // Both checked here as well as by the column constraints, so a bad value is
    // a 400 that says what is wrong rather than a 500 from the database.
    if let Some(weight) = req.fairness_weight
        && !(1..=100).contains(&weight)
    {
        return Err(ApiError::bad_request("fairness_weight must be between 1 and 100")
            .code(ApiErrorCode::ValidationFailed));
    }
    if let Some(Some(class_id)) = req.qos_class_id {
        let exists: Option<Uuid> = sqlx::query_scalar(
            "SELECT id FROM qos_classes WHERE id = $1 AND NOT suppressed",
        )
        .bind(class_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("load qos class for workspace: {e}");
            ApiError::internal("failed to load the QoS class")
        })?;
        if exists.is_none() {
            return Err(ApiError::not_found("QoS class not found", ApiErrorCode::QosClassNotFound));
        }
    }

    // One transaction: the workspace row UPDATE plus N per-kind assignment writes
    // are a single atomic change — a mid-sequence failure (e.g. a later kind's
    // profile 404s) must roll back the row edit and any earlier assignments.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update workspace (begin): {e}");
        ApiError::internal("failed to update workspace")
    })?;

    let ws = sqlx::query_as::<_, Workspace>(
        "UPDATE workspaces SET \
            name = COALESCE($2, name), \
            description = CASE WHEN $3 THEN $4 ELSE description END, \
            oidc_claim_name = CASE WHEN $5 THEN $6 ELSE oidc_claim_name END, \
            oidc_claim_pattern = CASE WHEN $7 THEN $8 ELSE oidc_claim_pattern END, \
            member_visibility = COALESCE($9, member_visibility), \
            counts_toward_tenant_budget = COALESCE($10, counts_toward_tenant_budget), \
            qos_class_id = CASE WHEN $11 THEN $12 ELSE qos_class_id END, \
            fairness_weight = COALESCE($13, fairness_weight), \
            updated_at = now() \
         WHERE id = $1 \
         RETURNING id, tenant_id, name, description, oidc_claim_name, oidc_claim_pattern, role, \
                   member_visibility, counts_toward_tenant_budget, qos_class_id, fairness_weight, \
                   created_at, updated_at",
    )
    .bind(id)
    .bind(req.name.as_deref().map(str::trim))
    .bind(req.description.is_some())
    .bind(req.description.flatten())
    .bind(req.oidc_claim_name.is_some())
    .bind(req.oidc_claim_name.flatten())
    .bind(req.oidc_claim_pattern.is_some())
    .bind(req.oidc_claim_pattern.flatten())
    .bind(req.member_visibility.as_deref())
    .bind(req.counts_toward_tenant_budget)
    .bind(req.qos_class_id.is_some())
    .bind(req.qos_class_id.flatten())
    .bind(req.fairness_weight)
    .fetch_one(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("update workspace: {e}");
        ApiError::internal("failed to update workspace")
    })?;

    // Apply per-kind profile assignment changes. Assignments live in a separate
    // table, so the generic `change_diff` (which snapshots the `workspaces` row)
    // would miss them — capture the before/after here via `AuditDiffSink`, which
    // takes precedence over the generic path.
    if let Some(profiles) = req.profiles {
        let before = load_assignments(&mut tx, &[id]).await?.remove(&id).unwrap_or_default();
        for (kind_str, sel) in &profiles {
            // Validate the kind is one we know; a profile assignment under an
            // unknown kind would never resolve on the proxy.
            let kind = streamscope_core::config::ProfileKind::parse(kind_str).ok_or_else(|| {
                ApiError::bad_request("unknown profile kind").code(ApiErrorCode::ProfileKindInvalid)
            })?;
            // The Default client-access profile is never stored as an
            // assignment: choosing it is choosing to inherit, so the workspace
            // follows a later Default (the invariant is stated on
            // `is_default_for_assignment`). Settled before the choice is
            // judged: naming the Default is inherit on every workspace, the
            // Agent and Inline AI ones included.
            let names_default = match sel {
                ProfileAssignmentChoice::Profile { id: pid }
                    if kind == streamscope_core::config::ProfileKind::ClientAccess =>
                {
                    super::client_access_profiles::is_default_for_assignment(&mut tx, *pid).await?
                }
                _ => false,
            };
            let sel = stored_choice(sel, names_default);
            client_access_assignment_allowed(kind, ws.role, sel)?;
            match sel {
                ProfileAssignmentChoice::Profile { id: pid } => {
                    // Target must exist in this tenant AND match the kind —
                    // which `is_default_for_assignment` established above for
                    // client access.
                    if kind != streamscope_core::config::ProfileKind::ClientAccess {
                        super::profiles::ensure_profile_exists(&mut tx, *pid, kind).await?;
                    }
                    sqlx::query(
                        "INSERT INTO workspace_profile_assignments (workspace_id, tenant_id, kind, profile_id) \
                         VALUES ($1, $2, $3, $4) \
                         ON CONFLICT (tenant_id, workspace_id, kind) DO UPDATE SET profile_id = EXCLUDED.profile_id",
                    )
                    .bind(id)
                    .bind(tenant_id)
                    .bind(kind.as_str())
                    .bind(*pid)
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!("assign workspace profile: {e}");
                        ApiError::internal("failed to assign profile")
                    })?;
                }
                ProfileAssignmentChoice::Off => {
                    // Explicit Off — a row with NULL profile_id (distinct from no
                    // row, which inherits the tenant default).
                    sqlx::query(
                        "INSERT INTO workspace_profile_assignments (workspace_id, tenant_id, kind, profile_id) \
                         VALUES ($1, $2, $3, NULL) \
                         ON CONFLICT (tenant_id, workspace_id, kind) DO UPDATE SET profile_id = NULL",
                    )
                    .bind(id)
                    .bind(tenant_id)
                    .bind(kind.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!("disable workspace profile: {e}");
                        ApiError::internal("failed to disable profile")
                    })?;
                }
                ProfileAssignmentChoice::Inherit => {
                    sqlx::query(
                        "DELETE FROM workspace_profile_assignments WHERE workspace_id = $1 AND kind = $2",
                    )
                    .bind(id)
                    .bind(kind.as_str())
                    .execute(&mut *tx)
                    .await
                    .map_err(|e| {
                        tracing::error!("clear workspace profile: {e}");
                        ApiError::internal("failed to clear profile")
                    })?;
                }
            }
        }
        let after = load_assignments(&mut tx, &[id]).await?.remove(&id).unwrap_or_default();
        audit_sink.record(
            Some(&serde_json::json!({ "assigned_profiles": before })),
            Some(&serde_json::json!({ "assigned_profiles": after })),
        );
    }

    tx.commit().await.map_err(|e| {
        tracing::error!("update workspace (commit): {e}");
        ApiError::internal("failed to update workspace")
    })?;

    Ok(Json(ws))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "Workspace deleted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 409, description = "Default workspace is protected", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_workspace(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Each per-tenant singleton is the home of a managed key or the tenant
    // fallback — all undeletable (their grants/budget/profiles stay editable).
    match workspace_role(&mut db, id).await? {
        WorkspaceRole::Default => {
            return Err(ApiError::conflict("the Default workspace cannot be deleted", ApiErrorCode::WorkspaceDefaultProtected));
        }
        WorkspaceRole::Agent => {
            return Err(ApiError::conflict("the Agent workspace cannot be deleted", ApiErrorCode::WorkspaceAgentProtected));
        }
        WorkspaceRole::Inline => {
            return Err(ApiError::conflict("the Inline AI workspace cannot be deleted", ApiErrorCode::WorkspaceInlineAiProtected));
        }
        WorkspaceRole::Standard => {}
    }

    // FK ON DELETE CASCADE removes members, access rows, rate limits, overrides,
    // and api_keys bound to this workspace.
    sqlx::query("DELETE FROM workspaces WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("delete workspace: {e}");
            ApiError::internal("failed to delete workspace")
        })?;

    Ok(Json(ActionResponse::ok().with_message("workspace deleted")))
}

// ---------------------------------------------------------------------------
// Members
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/members",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Members", body = OffsetPage<MemberRow>),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_members(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<MemberRow>>, ApiError> {
    workspace_role(&mut db, id).await?;
    let (limit, offset) = page.resolve();
    let rows = sqlx::query_as::<_, MemberRow>(
        "SELECT m.user_id, u.email, u.display_name, m.role, m.created_at \
         FROM workspace_members m JOIN users u ON u.id = m.user_id \
         WHERE m.workspace_id = $1 \
         ORDER BY u.email ASC LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list members: {e}");
        ApiError::internal("failed to list members")
    })?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/members",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = AddMemberRequest,
    responses(
        (status = 200, description = "Member added", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_member(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<AddMemberRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    validate_member_role(&req.role)?;
    let tenant_id = db.tenant_uuid();
    // FK validation bypasses RLS — confirm the user is in this tenant (RLS-scoped
    // SELECT) before adding, else a cross-tenant user could be enrolled.
    let user_ok: Option<Uuid> = sqlx::query_scalar("SELECT id FROM users WHERE id = $1")
        .bind(req.user_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("check user: {e}");
            ApiError::internal("failed to add member")
        })?;
    if user_ok.is_none() {
        return Err(ApiError::not_found("user not found", ApiErrorCode::UserNotFound));
    }
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, tenant_id, role) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role",
    )
    .bind(id)
    .bind(req.user_id)
    .bind(tenant_id)
    .bind(&req.role)
    .execute(db.conn())
    .await
    .map_err(|e| {
        // `workspace_members` carries THREE foreign keys — workspace, user and
        // tenant — and all three raise 23503, so the SQLSTATE says a referenced
        // row is gone without saying which. The workspace and the user are both
        // pre-checked above, leaving only a race (a concurrent delete of either)
        // to reach here, which is why the message names both rather than
        // asserting the user: answering "user not found" for a workspace deleted
        // mid-request sends the caller after the wrong thing.
        if super::is_foreign_key_violation(&e) {
            return ApiError::not_found("user or workspace no longer exists", ApiErrorCode::UserNotFound);
        }
        tracing::error!("add member: {e}");
        ApiError::internal("failed to add member")
    })?;
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({ "workspace_id": id, "user_id": req.user_id, "role": req.role }),
    );
    Ok(Json(ActionResponse::ok().with_message("member added")))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("user_id" = Uuid, Path, description = "User id"),
    ),
    request_body = UpdateMemberRequest,
    responses(
        (status = 200, description = "Member updated", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_member(
    mut db: TenantConn,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<UpdateMemberRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    validate_member_role(&req.role)?;
    let prev_role: Option<String> = sqlx::query_scalar(
        "SELECT role FROM workspace_members WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update member load before: {e}");
        ApiError::internal("failed to update member")
    })?;
    let res = sqlx::query("UPDATE workspace_members SET role = $3 WHERE workspace_id = $1 AND user_id = $2")
        .bind(id)
        .bind(user_id)
        .bind(&req.role)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("update member: {e}");
            ApiError::internal("failed to update member")
        })?;
    if res.rows_affected() == 0 {
        return Err(ApiError::not_found("member not found", ApiErrorCode::UserNotFound));
    }
    audit_sink.set(
        serde_json::json!({ "workspace_id": id, "user_id": user_id, "role": prev_role }),
        serde_json::json!({ "workspace_id": id, "user_id": user_id, "role": req.role }),
    );
    Ok(Json(ActionResponse::ok().with_message("member updated")))
}

/// Remove one membership and everything it carried in that workspace — the
/// member's keys (revoked, kept for audit linkage), their member exception, and
/// the MCP OAuth bearers its grants minted — on the caller's transaction, so
/// the removal is all-or-nothing: a partial one would leave a live key or an
/// exception behind that resurfaces when the person rejoins. Returns how many
/// keys it ended and the exception it removed, for the response and the audit.
/// Every path that ends a membership goes through here.
pub(crate) async fn remove_membership(
    tx: &mut Scoped,
    tenant_id: Uuid,
    workspace_id: Uuid,
    user_id: Uuid,
) -> Result<(u64, Option<UserRateLimitOverride>), ApiError> {
    let failed = |what: &'static str| {
        move |e: sqlx::Error| {
            tracing::error!("remove membership ({what}): {e}");
            ApiError::internal("failed to remove member")
        }
    };
    sqlx::query("DELETE FROM workspace_members WHERE workspace_id = $1 AND user_id = $2")
        .bind(workspace_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(failed("membership"))?;
    // After the membership delete: the sweep revokes bearers whose grant the
    // deleted membership carried.
    super::mcp_oauth::revoke_orphaned_mcp_tokens_conn(&mut *tx, tenant_id).await?;
    // Revoked, never deleted: the audit trail must keep resolving what the
    // keys did.
    let ended = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() \
          WHERE workspace_id = $1 AND user_id = $2 AND revoked_at IS NULL",
    )
        .bind(workspace_id)
        .bind(user_id)
        .execute(&mut *tx)
        .await
        .map_err(failed("keys"))?
        .rows_affected();
    let exception = sqlx::query_as::<_, UserRateLimitOverride>(
        "DELETE FROM workspace_user_rate_limit_overrides WHERE workspace_id = $1 AND user_id = $2 \
         RETURNING user_id, requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode, set_via, set_by_email",
    )
    .bind(workspace_id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed("exception"))?;
    Ok((ended, exception))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}/members/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("user_id" = Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "Member removed; `impact.keys_revoked` counts the keys it revoked", body = ActionResponse),
        (status = 404, description = "No such workspace, or the user is not a member of it", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_member(
    mut db: TenantConn,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    let tenant_id = db.tenant_uuid();
    let failed = |what: &'static str| {
        move |e: sqlx::Error| {
            tracing::error!("remove member ({what}): {e}");
            ApiError::internal("failed to remove member")
        }
    };
    let mut tx = db.conn().begin().await.map_err(failed("begin"))?;
    let member: Option<i32> = sqlx::query_scalar(
        "SELECT 1 FROM workspace_members WHERE workspace_id = $1 AND user_id = $2 FOR UPDATE",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(failed("membership lookup"))?;
    if member.is_none() {
        return Err(ApiError::not_found(
            "that user is not a member of this workspace",
            ApiErrorCode::WorkspaceMembershipRequired,
        ));
    }
    let (keys_revoked, exception) = remove_membership(&mut tx, tenant_id, id, user_id).await?;
    tx.commit().await.map_err(failed("commit"))?;
    // The membership as it stood, with the live keys it carried — the ones
    // the removal revoked.
    audit_sink.set(
        serde_json::json!({
            "workspace_id": id, "user_id": user_id, "member_exception": exception,
            "keys_revoked": keys_revoked,
        }),
        serde_json::Value::Null,
    );
    Ok(Json(
        ActionResponse::ok()
            .with_message("member removed")
            .with_impact(super::ActionImpact { keys_revoked: Some(keys_revoked), ..Default::default() }),
    ))
}

// ---------------------------------------------------------------------------
// Providers (allowlist)
// ---------------------------------------------------------------------------

async fn fetch_providers(
    db: &mut TenantConn,
    id: Uuid,
    offset: i64,
    limit: i64,
) -> Result<Vec<WorkspaceProvider>, ApiError> {
    // Every workspace — the Default included — shows the providers in its
    // explicit allowlist.
    let sql = concat!(
        "SELECT dp.id, dp.name, dp.description, dp.icon, dp.byok, ",
        live_passthrough_sql!("dp.byok", "s.enabled"),
        " AS enabled, ",
        bound_keys_sql!("dp.id", "AND k.workspace_id = $1"),
        " AS bound_keys \
         FROM downstream_providers dp \
         JOIN workspace_downstream_access a ON a.downstream_provider_id = dp.id AND a.workspace_id = $1 \
         LEFT JOIN upstream_servers s ON s.id = dp.upstream_server_id \
         ORDER BY dp.name ASC LIMIT $2 OFFSET $3",
    );
    sqlx::query_as::<_, WorkspaceProvider>(sql)
        .bind(id)
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("fetch workspace providers: {e}");
            ApiError::internal("failed to list providers")
        })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/providers",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Allowlisted providers", body = OffsetPage<WorkspaceProvider>),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_workspace_providers(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WorkspaceProvider>>, ApiError> {
    workspace_role(&mut db, id).await?;
    let (limit, offset) = page.resolve();
    let rows = fetch_providers(&mut db, id, offset, limit + 1).await?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/providers",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = AddProviderRequest,
    responses(
        (status = 200, description = "Provider allowlisted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_provider(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<AddProviderRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    let tenant_id = db.tenant_uuid();
    // FK validation bypasses RLS, so a cross-tenant provider_id would otherwise
    // insert silently. Confirm the provider belongs to this tenant first (this
    // SELECT is RLS-scoped) and 404 if not.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM downstream_providers WHERE id = $1")
        .bind(req.provider_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("check provider: {e}");
            ApiError::internal("failed to allowlist provider")
        })?;
    if exists.is_none() {
        return Err(ApiError::not_found("provider not found", ApiErrorCode::DownstreamNotFound));
    }
    sqlx::query(
        "INSERT INTO workspace_downstream_access (workspace_id, downstream_provider_id, tenant_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(req.provider_id)
    .bind(tenant_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("add provider: {e}");
        ApiError::internal("failed to allowlist provider")
    })?;
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({ "workspace_id": id, "downstream_provider_id": req.provider_id }),
    );
    Ok(Json(ActionResponse::ok().with_message("provider allowlisted")))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}/providers/{provider_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("provider_id" = Uuid, Path, description = "Provider id"),
    ),
    responses(
        (status = 200, description = "Provider removed", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_provider(
    mut db: TenantConn,
    Path((id, provider_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    sqlx::query("DELETE FROM workspace_downstream_access WHERE workspace_id = $1 AND downstream_provider_id = $2")
        .bind(id)
        .bind(provider_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("remove provider: {e}");
            ApiError::internal("failed to remove provider")
        })?;
    audit_sink.set(
        serde_json::json!({ "workspace_id": id, "downstream_provider_id": provider_id }),
        serde_json::Value::Null,
    );
    Ok(Json(ActionResponse::ok().with_message("provider removed")))
}

// ---------------------------------------------------------------------------
// MCP servers (allowlist)
// ---------------------------------------------------------------------------

async fn fetch_mcp_servers(
    db: &mut TenantConn,
    id: Uuid,
    offset: i64,
    limit: i64,
) -> Result<Vec<WorkspaceMcpServer>, ApiError> {
    // Every workspace — the Default included — shows the MCP servers in its
    // explicit allowlist.
    let sql = "SELECT vs.id, vs.slug, vs.name, vs.description, vs.enabled FROM mcp_virtual_servers vs \
         JOIN workspace_mcp_access a ON a.virtual_server_id = vs.id AND a.workspace_id = $1 \
         ORDER BY vs.name ASC LIMIT $2 OFFSET $3";
    sqlx::query_as::<_, WorkspaceMcpServer>(sql)
        .bind(id)
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("fetch workspace mcp servers: {e}");
            ApiError::internal("failed to list MCP servers")
        })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/mcp-servers",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Allowlisted MCP servers", body = OffsetPage<WorkspaceMcpServer>),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_workspace_mcp_servers(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WorkspaceMcpServer>>, ApiError> {
    workspace_role(&mut db, id).await?;
    let (limit, offset) = page.resolve();
    let rows = fetch_mcp_servers(&mut db, id, offset, limit + 1).await?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/mcp-servers",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = AddMcpServerRequest,
    responses(
        (status = 200, description = "MCP server allowlisted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_mcp_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<AddMcpServerRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    let tenant_id = db.tenant_uuid();
    // FK validation bypasses RLS — confirm the virtual server is in this tenant
    // (RLS-scoped SELECT) before inserting, else a cross-tenant id would take.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mcp_virtual_servers WHERE id = $1")
        .bind(req.virtual_server_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("check mcp server: {e}");
            ApiError::internal("failed to allowlist MCP server")
        })?;
    if exists.is_none() {
        return Err(ApiError::not_found("MCP server not found", ApiErrorCode::McpVirtualServerNotFound));
    }
    // An endpoint routing an incomplete per_user_oauth upstream fails every
    // portal connect — refuse to allowlist it until its OAuth client is set.
    super::mcp::ensure_endpoint_oauth_grantable(&mut db, req.virtual_server_id).await?;
    sqlx::query(
        "INSERT INTO workspace_mcp_access (workspace_id, virtual_server_id, tenant_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(req.virtual_server_id)
    .bind(tenant_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("add mcp server: {e}");
        ApiError::internal("failed to allowlist MCP server")
    })?;
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({ "workspace_id": id, "virtual_server_id": req.virtual_server_id }),
    );
    Ok(Json(ActionResponse::ok().with_message("MCP server allowlisted")))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}/mcp-servers/{server_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("server_id" = Uuid, Path, description = "Virtual server id"),
    ),
    responses(
        (status = 200, description = "MCP server removed", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_mcp_server(
    mut db: TenantConn,
    Path((id, server_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    sqlx::query("DELETE FROM workspace_mcp_access WHERE workspace_id = $1 AND virtual_server_id = $2")
        .bind(id)
        .bind(server_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("remove mcp server: {e}");
            ApiError::internal("failed to remove MCP server")
        })?;
    // The next config body cuts the `sk-` keys; only revocation withdraws an
    // OAuth bearer, which otherwise renews for thirty days. Runs in this
    // request so the revoked jtis ride the same config body.
    super::mcp_oauth::revoke_orphaned_mcp_tokens(&mut db).await?;
    audit_sink.set(
        serde_json::json!({ "workspace_id": id, "virtual_server_id": server_id }),
        serde_json::Value::Null,
    );
    Ok(Json(ActionResponse::ok().with_message("MCP server removed")))
}

// ---------------------------------------------------------------------------
// Local MCP servers (allowlist)
// ---------------------------------------------------------------------------

async fn fetch_mcp_local_servers(
    db: &mut TenantConn,
    id: Uuid,
    offset: i64,
    limit: i64,
) -> Result<Vec<WorkspaceMcpLocalServer>, ApiError> {
    sqlx::query_as::<_, WorkspaceMcpLocalServer>(
        "SELECT l.id, l.slug, l.name, l.description, l.enabled FROM mcp_local_servers l \
         JOIN workspace_mcp_local_access a ON a.local_server_id = l.id AND a.workspace_id = $1 \
         ORDER BY l.name ASC, l.id LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("fetch workspace local mcp servers: {e}");
        ApiError::internal("failed to list local MCP servers")
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/mcp-local-servers",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Granted local MCP servers", body = OffsetPage<WorkspaceMcpLocalServer>),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_workspace_mcp_local_servers(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WorkspaceMcpLocalServer>>, ApiError> {
    workspace_role(&mut db, id).await?;
    let (limit, offset) = page.resolve();
    let rows = fetch_mcp_local_servers(&mut db, id, offset, limit + 1).await?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/mcp-local-servers",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = AddMcpLocalServerRequest,
    responses(
        (status = 200, description = "Local MCP server granted", body = ActionResponse),
        (status = 400, description = "The Agent or the Inline AI workspace: it has no developers", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_mcp_local_server(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<AddMcpLocalServerRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // FK validation bypasses RLS — confirm the local server is in this tenant
    // (RLS-scoped SELECT) before inserting, else a cross-tenant id would take.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM mcp_local_servers WHERE id = $1")
        .bind(req.local_server_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("check local mcp server: {e}");
            ApiError::internal("failed to grant local MCP server")
        })?;
    if exists.is_none() {
        return Err(ApiError::not_found("local MCP server not found", ApiErrorCode::McpLocalServerNotFound));
    }
    // The workspace exists and has developers (not the Agent or Inline AI one).
    super::mcp_local::grant_to_workspaces(db.conn(), tenant_id, req.local_server_id, &[id]).await?;
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({ "workspace_id": id, "local_server_id": req.local_server_id }),
    );
    Ok(Json(ActionResponse::ok().with_message("local MCP server granted")))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}/mcp-local-servers/{server_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("server_id" = Uuid, Path, description = "Local server id"),
    ),
    responses(
        (status = 200, description = "Local MCP server removed", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_mcp_local_server(
    mut db: TenantConn,
    Path((id, server_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    sqlx::query("DELETE FROM workspace_mcp_local_access WHERE workspace_id = $1 AND local_server_id = $2")
        .bind(id)
        .bind(server_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("remove local mcp server: {e}");
            ApiError::internal("failed to remove local MCP server")
        })?;
    audit_sink.set(
        serde_json::json!({ "workspace_id": id, "local_server_id": server_id }),
        serde_json::Value::Null,
    );
    Ok(Json(ActionResponse::ok().with_message("local MCP server removed")))
}

// ---------------------------------------------------------------------------
// A2A agents (allowlist)
// ---------------------------------------------------------------------------

async fn fetch_a2a_agents(
    db: &mut TenantConn,
    id: Uuid,
    offset: i64,
    limit: i64,
) -> Result<Vec<WorkspaceA2aAgent>, ApiError> {
    sqlx::query_as::<_, WorkspaceA2aAgent>(
        "SELECT a.id, a.slug, a.name, a.description, a.enabled FROM a2a_upstream_agents a \
         JOIN workspace_a2a_access x ON x.agent_id = a.id AND x.workspace_id = $1 \
         ORDER BY a.name ASC LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(limit)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("fetch workspace a2a agents: {e}");
        ApiError::internal("failed to list A2A agents")
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/a2a-agents",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Allowlisted A2A agents", body = OffsetPage<WorkspaceA2aAgent>),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_workspace_a2a_agents(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<WorkspaceA2aAgent>>, ApiError> {
    workspace_role(&mut db, id).await?;
    let (limit, offset) = page.resolve();
    let rows = fetch_a2a_agents(&mut db, id, offset, limit + 1).await?;
    Ok(Json(OffsetPage::from_overfetched(rows, limit, offset)))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/workspaces/{id}/a2a-agents",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = AddA2aAgentRequest,
    responses(
        (status = 200, description = "A2A agent allowlisted", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn add_a2a_agent(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<AddA2aAgentRequest>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    let tenant_id = db.tenant_uuid();
    // FK validation bypasses RLS — confirm the agent is in this tenant
    // (RLS-scoped SELECT) before inserting, else a cross-tenant id would take.
    let exists: Option<Uuid> = sqlx::query_scalar("SELECT id FROM a2a_upstream_agents WHERE id = $1")
        .bind(req.agent_id)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("check a2a agent: {e}");
            ApiError::internal("failed to allowlist A2A agent")
        })?;
    if exists.is_none() {
        return Err(ApiError::not_found("A2A agent not found", ApiErrorCode::A2aAgentNotFound));
    }
    sqlx::query(
        "INSERT INTO workspace_a2a_access (workspace_id, agent_id, tenant_id) \
         VALUES ($1, $2, $3) ON CONFLICT DO NOTHING",
    )
    .bind(id)
    .bind(req.agent_id)
    .bind(tenant_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("add a2a agent: {e}");
        ApiError::internal("failed to allowlist A2A agent")
    })?;
    audit_sink.set(
        serde_json::Value::Null,
        serde_json::json!({ "workspace_id": id, "agent_id": req.agent_id }),
    );
    Ok(Json(ActionResponse::ok().with_message("A2A agent allowlisted")))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}/a2a-agents/{agent_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("agent_id" = Uuid, Path, description = "A2A agent id"),
    ),
    responses(
        (status = 200, description = "A2A agent removed", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn remove_a2a_agent(
    mut db: TenantConn,
    Path((id, agent_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    sqlx::query("DELETE FROM workspace_a2a_access WHERE workspace_id = $1 AND agent_id = $2")
        .bind(id)
        .bind(agent_id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("remove a2a agent: {e}");
            ApiError::internal("failed to remove A2A agent")
        })?;
    audit_sink.set(
        serde_json::json!({ "workspace_id": id, "agent_id": agent_id }),
        serde_json::Value::Null,
    );
    Ok(Json(ActionResponse::ok().with_message("A2A agent removed")))
}

// ---------------------------------------------------------------------------
// Rate limits
// ---------------------------------------------------------------------------

async fn fetch_rate_limits(db: &mut TenantConn, id: Uuid) -> Result<WorkspaceRateLimits, ApiError> {
    let row = sqlx::query_as::<_, WorkspaceRateLimits>(
        "SELECT requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode \
         FROM workspace_rate_limits WHERE workspace_id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("fetch rate limits: {e}");
        ApiError::internal("failed to load rate limits")
    })?;
    Ok(row.unwrap_or(WorkspaceRateLimits {
        requests_per_minute: None,
        tokens_per_minute: None,
        daily_budget: None,
        monthly_budget: None,
        budget_mode: default_budget_mode(),
    }))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/rate-limits",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "Workspace rate limits (null = inherit tenant default)", body = WorkspaceRateLimits),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_rate_limits(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspaceRateLimits>, ApiError> {
    workspace_role(&mut db, id).await?;
    Ok(Json(fetch_rate_limits(&mut db, id).await?))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/workspaces/{id}/rate-limits",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = WorkspaceRateLimits,
    responses(
        (status = 200, description = "Rate limits updated", body = WorkspaceRateLimits),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn put_rate_limits(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<WorkspaceRateLimits>,
) -> Result<Json<WorkspaceRateLimits>, ApiError> {
    workspace_role(&mut db, id).await?;
    validate_limit_values(req.requests_per_minute, req.tokens_per_minute, req.daily_budget, req.monthly_budget)?;
    let tenant_id = db.tenant_uuid();
    let before = fetch_rate_limits(&mut db, id).await?;
    sqlx::query(
        "INSERT INTO workspace_rate_limits (workspace_id, tenant_id, requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, workspace_id) DO UPDATE SET \
            requests_per_minute = EXCLUDED.requests_per_minute, \
            tokens_per_minute = EXCLUDED.tokens_per_minute, \
            daily_budget = EXCLUDED.daily_budget, \
            monthly_budget = EXCLUDED.monthly_budget, \
            budget_mode = EXCLUDED.budget_mode, \
            updated_at = now()",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(req.requests_per_minute)
    .bind(req.tokens_per_minute)
    .bind(req.daily_budget)
    .bind(req.monthly_budget)
    .bind(norm_budget_mode(&req.budget_mode))
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("put rate limits: {e}");
        ApiError::internal("failed to update rate limits")
    })?;
    let after = fetch_rate_limits(&mut db, id).await?;
    audit_sink.record(Some(&before), Some(&after));
    Ok(Json(after))
}

// ---------------------------------------------------------------------------
// Per-user rate-limit overrides
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/rate-limit-overrides",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id"), PageQuery),
    responses(
        (status = 200, description = "Per-user overrides", body = OffsetPage<UserRateLimitOverride>),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_rate_limit_overrides(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<UserRateLimitOverride>>, ApiError> {
    workspace_role(&mut db, id).await?;
    Ok(Json(list_member_exceptions(&mut db, id, page).await?))
}

/// The member exceptions of one workspace with each one's current spend — the
/// shared body of the admin and the workspace-manager listings. Only exceptions
/// of current members are listed.
pub(crate) async fn list_member_exceptions(
    db: &mut TenantConn,
    id: Uuid,
    page: PageQuery,
) -> Result<OffsetPage<UserRateLimitOverride>, ApiError> {
    let (limit, offset) = page.resolve();
    let mut rows = sqlx::query_as::<_, UserRateLimitOverride>(
        "SELECT o.user_id, o.requests_per_minute, o.tokens_per_minute, o.daily_budget, o.monthly_budget, o.budget_mode, \
                o.set_via, o.set_by_email \
         FROM workspace_user_rate_limit_overrides o \
         JOIN workspace_members m ON m.workspace_id = o.workspace_id AND m.user_id = o.user_id \
         WHERE o.workspace_id = $1 \
         ORDER BY o.user_id ASC LIMIT $2 OFFSET $3",
    )
    .bind(id)
    .bind(limit + 1)
    .bind(offset)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("list overrides: {e}");
        ApiError::internal("failed to list overrides")
    })?;
    // Fill current daily/monthly spend, in the tenant's accounting currency, so
    // the UI can show spend-vs-cap.
    let tenant = db.tenant_uuid();
    let spend = crate::routes::analytics::current_budget_spend(db.conn(), tenant, "user")
        .await
        .unwrap_or_default();
    for r in &mut rows {
        let member = streamscope_core::auth::member_limits::member_scope_id(id, r.user_id);
        if let Some((daily, monthly)) = spend.get(&member) {
            r.daily_spent = *daily;
            r.monthly_spent = *monthly;
        }
    }
    Ok(OffsetPage::from_overfetched(rows, limit, offset))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/workspaces/{id}/rate-limit-overrides/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("user_id" = Uuid, Path, description = "User id"),
    ),
    request_body = PutRateLimitOverrideRequest,
    responses(
        (status = 200, description = "Override set", body = UserRateLimitOverride),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn put_rate_limit_override(
    axum::Extension(ctx): axum::Extension<crate::db::tenant::AdminTenantCtx>,
    mut db: TenantConn,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<PutRateLimitOverrideRequest>,
) -> Result<Json<UserRateLimitOverride>, ApiError> {
    workspace_role(&mut db, id).await?;
    // The console actor: an admin account, or the service account behind an
    // `ak-` key.
    let email: Option<String> = sqlx::query_scalar(
        "SELECT COALESCE((SELECT email FROM admin_accounts WHERE id = $1), (SELECT email FROM users WHERE id = $1))",
    )
    .bind(ctx.admin_account_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("put override load actor: {e}");
        ApiError::internal("failed to set override")
    })?;
    let setter = ExceptionSetter { via: "admin", email };
    let (before, row) = upsert_member_exception(&mut db, id, user_id, &req, setter).await?;
    audit_sink.record(before.as_ref(), Some(&row));
    Ok(Json(row))
}

/// Who is setting a member exception, recorded on the row.
pub(crate) struct ExceptionSetter {
    /// `admin` (the console) or `manager` (a workspace manager in the portal).
    pub via: &'static str,
    pub email: Option<String>,
}

/// Set one member's exception (replacing the workspace default per metric:
/// `null` inherits, `0` is unlimited, a positive value is the member's own).
/// The shared body of the admin and workspace-manager writes; returns the row
/// before and after, for the audit.
pub(crate) async fn upsert_member_exception(
    db: &mut TenantConn,
    id: Uuid,
    user_id: Uuid,
    req: &PutRateLimitOverrideRequest,
    setter: ExceptionSetter,
) -> Result<(Option<UserRateLimitOverride>, UserRateLimitOverride), ApiError> {
    validate_limit_values(req.requests_per_minute, req.tokens_per_minute, req.daily_budget, req.monthly_budget)?;
    let tenant_id = db.tenant_uuid();
    let before = sqlx::query_as::<_, UserRateLimitOverride>(
        "SELECT user_id, requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode, set_via, set_by_email \
         FROM workspace_user_rate_limit_overrides WHERE workspace_id = $1 AND user_id = $2",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("put override load before: {e}");
        ApiError::internal("failed to set override")
    })?;
    // An override only makes sense for a member of this workspace; the
    // membership check is RLS-scoped, so it also rejects cross-tenant user ids.
    let is_member: Option<Uuid> =
        sqlx::query_scalar("SELECT user_id FROM workspace_members WHERE workspace_id = $1 AND user_id = $2")
            .bind(id)
            .bind(user_id)
            .fetch_optional(db.conn())
            .await
            .map_err(|e| {
                tracing::error!("check membership: {e}");
                ApiError::internal("failed to set override")
            })?;
    if is_member.is_none() {
        return Err(ApiError::not_found("user is not a member of this workspace", ApiErrorCode::WorkspaceMembershipRequired));
    }
    let row = sqlx::query_as::<_, UserRateLimitOverride>(
        "INSERT INTO workspace_user_rate_limit_overrides (workspace_id, user_id, tenant_id, requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode, set_via, set_by_email) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) \
         ON CONFLICT (tenant_id, workspace_id, user_id) DO UPDATE SET \
            requests_per_minute = EXCLUDED.requests_per_minute, \
            tokens_per_minute = EXCLUDED.tokens_per_minute, \
            daily_budget = EXCLUDED.daily_budget, \
            monthly_budget = EXCLUDED.monthly_budget, \
            budget_mode = EXCLUDED.budget_mode, \
            set_via = EXCLUDED.set_via, \
            set_by_email = EXCLUDED.set_by_email, \
            updated_at = now() \
         RETURNING user_id, requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode, set_via, set_by_email",
    )
    .bind(id)
    .bind(user_id)
    .bind(tenant_id)
    .bind(req.requests_per_minute)
    .bind(req.tokens_per_minute)
    .bind(req.daily_budget)
    .bind(req.monthly_budget)
    .bind(norm_budget_mode(&req.budget_mode))
    .bind(setter.via)
    .bind(setter.email)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("put override: {e}");
        ApiError::internal("failed to set override")
    })?;
    Ok((before, row))
}

#[utoipa::path(
    delete,
    path = "/api/v1/admin/workspaces/{id}/rate-limit-overrides/{user_id}",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("user_id" = Uuid, Path, description = "User id"),
    ),
    responses(
        (status = 200, description = "Override removed", body = ActionResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn delete_rate_limit_override(
    mut db: TenantConn,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
) -> Result<Json<ActionResponse>, ApiError> {
    workspace_role(&mut db, id).await?;
    let removed = delete_member_exception(&mut db, id, user_id).await?;
    audit_sink.record(removed.as_ref(), None::<&UserRateLimitOverride>);
    Ok(Json(ActionResponse::ok().with_message("override removed")))
}

/// Remove one member's exception, returning the removed row so the audit
/// records the values that stopped applying — not only whose they were.
pub(crate) async fn delete_member_exception(
    db: &mut TenantConn,
    id: Uuid,
    user_id: Uuid,
) -> Result<Option<UserRateLimitOverride>, ApiError> {
    sqlx::query_as::<_, UserRateLimitOverride>(
        "DELETE FROM workspace_user_rate_limit_overrides WHERE workspace_id = $1 AND user_id = $2 \
         RETURNING user_id, requests_per_minute, tokens_per_minute, daily_budget, monthly_budget, budget_mode, set_via, set_by_email",
    )
    .bind(id)
    .bind(user_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("delete override: {e}");
        ApiError::internal("failed to remove override")
    })
}

// ---------------------------------------------------------------------------
// Member limit defaults + effective limits
// ---------------------------------------------------------------------------

/// `(rpm, tpm, daily, monthly, budget_mode)` of the member-default columns.
type MemberDefaultsRow = (Option<i32>, Option<i32>, Option<f64>, Option<f64>, Option<String>);

async fn fetch_member_defaults(db: &mut TenantConn, id: Uuid) -> Result<MemberLimitDefaults, ApiError> {
    let row: Option<MemberDefaultsRow> = sqlx::query_as(
        "SELECT member_requests_per_minute, member_tokens_per_minute, member_daily_budget, \
                member_monthly_budget, member_budget_mode \
           FROM workspace_rate_limits WHERE workspace_id = $1",
    )
    .bind(id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("fetch member defaults: {e}");
        ApiError::internal("failed to load member defaults")
    })?;
    Ok(match row {
        Some((rpm, tpm, daily, monthly, mode)) => MemberLimitDefaults {
            requests_per_minute: rpm,
            tokens_per_minute: tpm,
            daily_budget: daily,
            monthly_budget: monthly,
            budget_mode: mode.unwrap_or_else(default_budget_mode),
        },
        None => MemberLimitDefaults { budget_mode: default_budget_mode(), ..Default::default() },
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/member-defaults",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "The workspace's default member limit (null = no default for that metric)", body = MemberLimitDefaults),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_member_defaults(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<MemberLimitDefaults>, ApiError> {
    workspace_role(&mut db, id).await?;
    Ok(Json(fetch_member_defaults(&mut db, id).await?))
}

/// Replace the workspace's default member limit. Its own sub-resource so a
/// client writing the pool with today's shape can never clear it.
#[utoipa::path(
    put,
    path = "/api/v1/admin/workspaces/{id}/member-defaults",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    request_body = MemberLimitDefaults,
    responses(
        (status = 200, description = "Member defaults updated", body = MemberLimitDefaults),
        (status = 400, description = "Invalid value, or a workspace that takes no member default", body = ApiErrorResponse),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn put_member_defaults(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    axum::Extension(audit_sink): axum::Extension<AuditDiffSink>,
    Json(req): Json<MemberLimitDefaults>,
) -> Result<Json<MemberLimitDefaults>, ApiError> {
    let role = workspace_role(&mut db, id).await?;
    validate_limit_values(req.requests_per_minute, req.tokens_per_minute, req.daily_budget, req.monthly_budget)?;
    // `0` and unset mean the same thing on a default — no default for that
    // metric — so they are stored one way.
    let none_if_zero_i = |v: Option<i32>| v.filter(|n| *n > 0);
    let none_if_zero_f = |v: Option<f64>| v.filter(|n| *n > 0.0);
    let (rpm, tpm, daily, monthly) = (
        none_if_zero_i(req.requests_per_minute),
        none_if_zero_i(req.tokens_per_minute),
        none_if_zero_f(req.daily_budget),
        none_if_zero_f(req.monthly_budget),
    );
    let sets_any = rpm.is_some() || tpm.is_some() || daily.is_some() || monthly.is_some();
    if sets_any && matches!(role, WorkspaceRole::Agent | WorkspaceRole::Inline) {
        return Err(ApiError::bad_request(
            "The Agent and Inline AI workspaces take no default member limit — one service member \
             carries all of their traffic. Set the workspace pool instead.",
        )
        .code(ApiErrorCode::MemberDefaultsNotAllowed));
    }
    let tenant_id = db.tenant_uuid();
    let before = fetch_member_defaults(&mut db, id).await?;
    sqlx::query(
        "INSERT INTO workspace_rate_limits (workspace_id, tenant_id, member_requests_per_minute, \
            member_tokens_per_minute, member_daily_budget, member_monthly_budget, member_budget_mode) \
         VALUES ($1, $2, $3, $4, $5, $6, $7) \
         ON CONFLICT (tenant_id, workspace_id) DO UPDATE SET \
            member_requests_per_minute = EXCLUDED.member_requests_per_minute, \
            member_tokens_per_minute = EXCLUDED.member_tokens_per_minute, \
            member_daily_budget = EXCLUDED.member_daily_budget, \
            member_monthly_budget = EXCLUDED.member_monthly_budget, \
            member_budget_mode = EXCLUDED.member_budget_mode, \
            updated_at = now()",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(rpm)
    .bind(tpm)
    .bind(daily)
    .bind(monthly)
    .bind(norm_budget_mode(&req.budget_mode))
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("put member defaults: {e}");
        ApiError::internal("failed to update member defaults")
    })?;
    let after = fetch_member_defaults(&mut db, id).await?;
    audit_sink.record(Some(&before), Some(&after));
    Ok(Json(after))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/limits",
    tag = "Workspaces",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "Pool, inherited tenant default, member default and counts", body = WorkspaceLimitsOverview),
        (status = 404, description = "Not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_limits_overview(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<WorkspaceLimitsOverview>, ApiError> {
    let role = workspace_role(&mut db, id).await?;
    Ok(Json(limits_overview(&mut db, id, role).await?))
}

/// The limits overview of one workspace (whose `role` the caller has read) —
/// the shared body of the admin and the workspace-manager reads.
pub(crate) async fn limits_overview(
    db: &mut TenantConn,
    id: Uuid,
    role: WorkspaceRole,
) -> Result<WorkspaceLimitsOverview, ApiError> {
    let pool = fetch_rate_limits(db, id).await?;
    let member_defaults = fetch_member_defaults(db, id).await?;
    let internal = |e: sqlx::Error| {
        tracing::error!("limits overview: {e}");
        ApiError::internal("failed to load limits")
    };
    let default = crate::limits::load_tenant_budget_default(db.conn()).await.map_err(internal)?;
    let (member_count, exception_count): (i64, i64) = sqlx::query_as(
        "SELECT (SELECT COUNT(*) FROM workspace_members WHERE workspace_id = $1), \
                (SELECT COUNT(*) FROM workspace_user_rate_limit_overrides o \
                   JOIN workspace_members m ON m.workspace_id = o.workspace_id AND m.user_id = o.user_id \
                  WHERE o.workspace_id = $1)",
    )
    .bind(id)
    .fetch_one(db.conn())
    .await
    .map_err(internal)?;
    Ok(WorkspaceLimitsOverview {
        pool,
        tenant_default_daily_budget: default.daily,
        tenant_default_monthly_budget: default.monthly,
        member_defaults,
        member_defaults_allowed: !matches!(role, WorkspaceRole::Agent | WorkspaceRole::Inline),
        member_count,
        exception_count,
    })
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/workspaces/{id}/members/{user_id}/effective-limits",
    tag = "Workspaces",
    params(
        ("id" = Uuid, Path, description = "Workspace id"),
        ("user_id" = Uuid, Path, description = "Member user id"),
    ),
    responses(
        (status = 200, description = "Every limit that applies to this member, widest first", body = crate::limits::EffectiveLimitStack),
        (status = 404, description = "Not a member / not found", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_member_effective_limits(
    mut db: TenantConn,
    Path((id, user_id)): Path<(Uuid, Uuid)>,
) -> Result<Json<crate::limits::EffectiveLimitStack>, ApiError> {
    workspace_role(&mut db, id).await?;
    let internal = |e: sqlx::Error| {
        tracing::error!("effective limits: {e}");
        ApiError::internal("failed to load limits")
    };
    require_member(&mut db, id, user_id).await?;
    let tenant_id = db.tenant_uuid();
    Ok(Json(crate::limits::effective_stack(db.conn(), tenant_id, id, user_id, crate::limits::StackViewer::Admin).await.map_err(internal)?))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

pub fn workspaces_router() -> axum::Router<Arc<AdminState>> {
    use axum::routing::{delete, get, post, put};

    axum::Router::new()
        .route("/", post(create_workspace).get(list_workspaces))
        .route("/{id}", get(get_workspace).patch(update_workspace).delete(delete_workspace))
        .route("/{id}/members", get(list_members).post(add_member))
        .route("/{id}/members/{user_id}", axum::routing::patch(update_member).delete(remove_member))
        .route("/{id}/providers", get(list_workspace_providers).post(add_provider))
        .route("/{id}/providers/{provider_id}", delete(remove_provider))
        .route("/{id}/mcp-servers", get(list_workspace_mcp_servers).post(add_mcp_server))
        .route("/{id}/mcp-servers/{server_id}", delete(remove_mcp_server))
        .route("/{id}/mcp-local-servers", get(list_workspace_mcp_local_servers).post(add_mcp_local_server))
        .route("/{id}/mcp-local-servers/{server_id}", delete(remove_mcp_local_server))
        .route("/{id}/a2a-agents", get(list_workspace_a2a_agents).post(add_a2a_agent))
        .route("/{id}/a2a-agents/{agent_id}", delete(remove_a2a_agent))
        .route("/{id}/rate-limits", get(get_rate_limits).put(put_rate_limits))
        .route("/{id}/member-defaults", get(get_member_defaults).put(put_member_defaults))
        .route("/{id}/limits", get(get_limits_overview))
        .route("/{id}/members/{user_id}/effective-limits", get(get_member_effective_limits))
        .route("/{id}/rate-limit-overrides", get(list_rate_limit_overrides))
        .route(
            "/{id}/rate-limit-overrides/{user_id}",
            put(put_rate_limit_override).delete(delete_rate_limit_override),
        )
}

#[cfg(test)]
mod tests {
    use super::WorkspaceRole;

    /// The serde spelling and `parse` (which backs the sqlx `Decode`) must both
    /// agree with the exact text the DB `workspaces.role` column stores (its
    /// CHECK constraint). If either drifts, decode/serialize silently disagree
    /// with the persisted value.
    #[test]
    fn workspace_role_serde_matches_db_spelling() {
        for (role, text) in [
            (WorkspaceRole::Standard, "standard"),
            (WorkspaceRole::Default, "default"),
            (WorkspaceRole::Agent, "agent"),
            (WorkspaceRole::Inline, "inline"),
        ] {
            assert_eq!(WorkspaceRole::parse(text), Some(role));
            assert_eq!(
                serde_json::to_value(role).unwrap(),
                serde_json::Value::String(text.to_owned())
            );
            assert_eq!(
                serde_json::from_value::<WorkspaceRole>(serde_json::json!(text)).unwrap(),
                role
            );
        }
        assert_eq!(WorkspaceRole::parse("bogus"), None);
    }

    #[test]
    fn client_access_is_never_off_and_stays_the_default_on_the_built_in_service_workspaces() {
        use super::{client_access_assignment_allowed as allowed, stored_choice, ProfileAssignmentChoice as Choice};
        use crate::routes::ApiErrorCode;
        use streamscope_core::config::ProfileKind;

        let profile = Choice::Profile { id: uuid::Uuid::nil() };
        let roles = [WorkspaceRole::Standard, WorkspaceRole::Default, WorkspaceRole::Agent, WorkspaceRole::Inline];
        let refused = |kind, role, choice: &Choice| match allowed(kind, role, choice) {
            Ok(()) => false,
            Err(e) => {
                assert_eq!(e.code, ApiErrorCode::ProfileChoiceUnsupported);
                assert_eq!(e.status, axum::http::StatusCode::BAD_REQUEST);
                true
            }
        };
        for role in roles {
            assert!(refused(ProfileKind::ClientAccess, role, &Choice::Off), "{role:?}: Off");
            assert!(!refused(ProfileKind::ClientAccess, role, &Choice::Inherit), "{role:?}: Inherit");
            let service = matches!(role, WorkspaceRole::Agent | WorkspaceRole::Inline);
            assert_eq!(refused(ProfileKind::ClientAccess, role, &profile), service, "{role:?}: a profile");
            // The Default named by id is inherit, so it is taken everywhere —
            // the service workspaces included — while any other profile is
            // judged as itself.
            assert!(!refused(ProfileKind::ClientAccess, role, stored_choice(&profile, true)), "{role:?}: the Default");
            assert_eq!(
                refused(ProfileKind::ClientAccess, role, stored_choice(&profile, false)),
                service,
                "{role:?}: not the Default"
            );
            // Every other kind takes every choice on every workspace.
            for kind in [ProfileKind::Tools, ProfileKind::Guardrail, ProfileKind::Transform, ProfileKind::Expert] {
                for choice in [&Choice::Off, &Choice::Inherit, &profile] {
                    assert!(!refused(kind, role, choice), "{role:?} {}", kind.as_str());
                }
            }
        }
    }
}

#[cfg(test)]
mod limit_value_tests {
    use super::validate_limit_values;

    /// Both sides of every boundary: 0 is a stored value (explicitly
    /// unlimited on an inheriting field), a negative is refused, and a budget
    /// must be a finite number.
    #[test]
    fn zero_is_a_limit_value_and_a_negative_or_non_finite_one_is_refused() {
        assert!(validate_limit_values(Some(0), Some(0), Some(0.0), Some(0.0)).is_ok());
        assert!(validate_limit_values(Some(60), None, Some(5.0), None).is_ok());
        assert!(validate_limit_values(None, None, None, None).is_ok());
        assert!(validate_limit_values(Some(-1), None, None, None).is_err());
        assert!(validate_limit_values(None, Some(-1), None, None).is_err());
        assert!(validate_limit_values(None, None, Some(-0.01), None).is_err());
        assert!(validate_limit_values(None, None, None, Some(-0.01)).is_err());
        for bad in [f64::NAN, f64::INFINITY] {
            assert!(validate_limit_values(None, None, Some(bad), None).is_err(), "{bad}");
            assert!(validate_limit_values(None, None, None, Some(bad)).is_err(), "{bad}");
        }
    }
}
