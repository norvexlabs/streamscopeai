//! User self-service portal — personal key management and usage stats.
//!
//! Portal routes are scoped to the authenticated portal user (not admin).
//! Users mint/revoke their own API keys within a workspace they belong to,
//! view their usage statistics, and manage their profile. All queries are
//! filtered by the portal user's `user_id`, enforced at the query level (not
//! just RLS).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::{Extension, Json};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use streamscope_core::auth::virtual_key::{generate_forward_key, generate_virtual_key, hash_key};

use crate::AdminState;
use crate::db::tenant::{Scoped, TenantConn};

use super::{ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery, TotalPage};
use super::portal_auth::PortalUser;
use super::portal_manager::confine_to_key_workspace;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

#[derive(Serialize, ToSchema)]
pub struct PortalMeResponse {
    pub user: PortalUserDetail,
    pub workspaces: Vec<PortalWorkspaceInfo>,
    pub downstream_providers: Vec<PortalProviderInfo>,
    pub tenant_slug: String,
    pub tenant_name: String,
    /// Currency this tenant keeps its books in — every budget cap and spend
    /// figure the portal shows is expressed in it. Sent here so the portal has
    /// one authoritative source, the way the console reads it from the settings
    /// endpoint it is not allowed to call.
    #[schema(value_type = String, example = "USD")]
    pub accounting_currency: streamscope_core::pricing::Currency,
}

#[derive(Serialize, ToSchema)]
pub struct PortalUserDetail {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalWorkspaceInfo {
    pub id: Uuid,
    pub name: String,
    pub role: String,
    /// True when this workspace shares members' usage, sessions and audit with
    /// one another. The portal offers the workspace-wide view only here — the
    /// server refuses to widen elsewhere regardless, so this is what the client
    /// shows, not what enforces it.
    pub shares_with_members: bool,
}

#[derive(Serialize, ToSchema)]
pub struct PortalProviderInfo {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub icon: Option<String>,
    /// `true` when this is a BYOK pass-through downstream — provision a `vk-`
    /// (BYOK) key against it; the client forwards its own upstream credential
    /// and unconfigured models pass through. `false` for a normal gateway
    /// provider (provision an `sk-` key + curated routes).
    #[serde(default)]
    pub byok: bool,
    /// For a BYOK pass-through, the protocol its server speaks
    /// (`chat_completions` · `responses` · `anthropic_messages` ·
    /// `google_gemini`) — the one a forwarded credential works on, so the
    /// client template speaking it is the default. `None` for a gateway
    /// provider, which translates, or a pass-through with no server.
    pub upstream_protocol: Option<String>,
}

#[derive(Deserialize, ToSchema)]
pub struct CreatePortalKeyRequest {
    /// Workspace the key is bound to. The caller must be a member.
    pub workspace_id: Uuid,
    pub name: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When true, generate a `vk-` prefix key for BYOK (forward client auth).
    pub forward_auth: Option<bool>,
    /// For a BYOK (`forward_auth`) key, the BYOK downstream it is bound to.
    /// Unconfigured models pass through to that downstream's upstream with the
    /// client's own forwarded credential; routes inside the downstream override
    /// individual models. Must be a `byok` downstream granted to `workspace_id`.
    /// Optional (a `vk-` key is also valid for MCP bring-your-own-token with no
    /// LLM binding); ignored for `sk-` keys.
    #[serde(default)]
    pub downstream_provider_id: Option<Uuid>,
    /// The key's priority class under load. Omitted takes the workspace's own
    /// default for a person's tool; a class MORE important than the workspace's
    /// is refused — only a tenant admin can grant one.
    #[serde(default)]
    pub qos_class_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct CreatePortalKeyResponse {
    pub id: Uuid,
    pub key: String,
    pub name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The tenant's configured gateway public origin (no trailing slash), for
    /// rendering the BYOK connection URL (`{proxy_base_url}/fwd/{key}`). `None`
    /// when `proxy_public_url` is unset — the UI falls back to a relative hint.
    pub proxy_base_url: Option<String>,
}

#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalKeyInfo {
    pub id: Uuid,
    pub name: Option<String>,
    pub key_prefix: String,
    pub workspace_id: Uuid,
    pub workspace_name: String,
    pub forward_auth: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-key budget ceiling (read-only here; settable by admin/manager only).
    pub daily_budget: Option<f64>,
    pub monthly_budget: Option<f64>,
    pub budget_mode: String,
    /// Current fleet-estimate spend, in the tenant's accounting currency,
    /// against this key's per-key budget in
    /// the active daily / monthly windows. Filled from `usage_counters`, not a
    /// stored column; `0` when the key carries no budget.
    #[sqlx(default)]
    #[serde(default)]
    pub daily_spent: f64,
    #[sqlx(default)]
    #[serde(default)]
    pub monthly_spent: f64,
    /// The key's own priority class under load (`null` = the workspace's).
    pub qos_class_id: Option<Uuid>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct StatsQuery {
    /// Read this workspace's activity instead of only your own, when the
    /// workspace shares with its members. Absent = your own rows.
    pub workspace_id: Option<Uuid>,
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339).
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<chrono::DateTime<chrono::Utc>>,
}

impl StatsQuery {
    pub(crate) fn time_window(&self) -> super::TimeWindow {
        super::TimeWindow { days: self.days, start: self.start, end: self.end }
    }
}

#[derive(Serialize, ToSchema)]
pub struct PortalStats {
    pub active_keys: i64,
    pub expiring_soon: i64,
    pub total_requests: i64,
    pub total_tokens: i64,
    /// What the window spent, and in which currency. `null` when the window
    /// straddles a change of the tenant's accounting currency — its rows are
    /// then in different denominations and no single figure states them. The
    /// same holds for every `spend` below.
    pub spend: Option<super::SpendTotal>,
    pub per_key: Vec<PortalKeyStats>,
}

#[derive(Serialize, ToSchema)]
pub struct PortalKeyStats {
    pub key_id: Uuid,
    pub prefix: String,
    pub name: Option<String>,
    pub workspace: String,
    pub requests: i64,
    pub tokens: i64,
    pub spend: Option<super::SpendTotal>,
    pub last_used: Option<chrono::DateTime<chrono::Utc>>,
}

// ---------------------------------------------------------------------------
// GET /auth/me — current user + workspace memberships + accessible providers
// ---------------------------------------------------------------------------

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct MeQuery {
    /// Scope `downstream_providers` to a single workspace's grants. Ignored for
    /// a workspace-bound `ak-` key (its bound workspace always wins). A
    /// workspace the user isn't a member of yields no providers (not a leak).
    pub workspace_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/auth/me",
    tag = "Portal",
    operation_id = "portal_me",
    params(MeQuery),
    responses(
        (status = 200, description = "Current portal user profile with workspaces and providers", body = PortalMeResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn me(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(q): Query<MeQuery>,
) -> Result<Json<PortalMeResponse>, ApiError> {
    let user_id = user.user_id;
    let tenant_uuid = db.tenant_uuid();

    // Fetch user detail.
    let detail: (String, Option<String>) = sqlx::query_as(
        "SELECT email, display_name FROM users WHERE id = $1",
    )
    .bind(user_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal me user: {e}");
        ApiError::internal("internal error")
    })?;

    // Fetch tenant name + slug for header display.
    let tenant: (String, String) = sqlx::query_as(
        "SELECT slug, name FROM tenants WHERE id = $1",
    )
    .bind(tenant_uuid)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal me tenant: {e}");
        ApiError::internal("internal error")
    })?;

    // Workspace memberships with role. A portal `ak-` key (`key_workspace_id`
    // Some) sees only its bound workspace; a human session (None) sees all.
    let workspaces: Vec<(Uuid, String, String, String)> = sqlx::query_as(
        r#"SELECT w.id, w.name, wm.role, w.member_visibility
           FROM workspaces w
           JOIN workspace_members wm ON wm.workspace_id = w.id AND wm.user_id = $1
           WHERE ($2::uuid IS NULL OR w.id = $2)
           ORDER BY w.name"#,
    )
    .bind(user_id)
    .bind(user.key_workspace_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal me workspaces: {e}");
        ApiError::internal("internal error")
    })?;

    // A workspace-bound `ak-` key's binding is authoritative; otherwise the
    // optional query param scopes the provider list to the selected workspace.
    let provider_scope = user.key_workspace_id.or(q.workspace_id);
    let providers = accessible_providers(db.conn(), user_id, provider_scope).await?;
    let accounting_currency = crate::routes::pricing::accounting_currency(db.conn()).await;

    Ok(Json(PortalMeResponse {
        accounting_currency,
        user: PortalUserDetail {
            id: user_id,
            email: detail.0,
            display_name: detail.1,
        },
        workspaces: workspaces
            .into_iter()
            .map(|(id, name, role, member_visibility)| PortalWorkspaceInfo {
                id,
                name,
                role,
                shares_with_members: member_visibility == "members",
            })
            .collect(),
        downstream_providers: providers,
        tenant_slug: tenant.0,
        tenant_name: tenant.1,
    }))
}

// ---------------------------------------------------------------------------
// GET /keys — list my keys
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/portal/keys",
    tag = "Portal",
    operation_id = "portal_list_keys",
    params(PageQuery),
    responses(
        (status = 200, description = "Paginated list of portal user's API keys", body = TotalPage<PortalKeyInfo>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_keys(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(page): Query<PageQuery>,
) -> Result<Json<TotalPage<PortalKeyInfo>>, ApiError> {
    let (limit, offset) = page.resolve();
    // A portal `ak-` key (`key_workspace_id` Some) lists only keys in its bound
    // workspace; a human session (None) lists all of its own keys.
    let total: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM api_keys WHERE user_id = $1 AND ($2::uuid IS NULL OR workspace_id = $2)",
    )
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal count keys: {e}");
        ApiError::internal("internal error")
    })?;

    let mut keys = sqlx::query_as::<_, PortalKeyInfo>(
        r#"SELECT k.id, k.name,
                  COALESCE(k.key_prefix, LEFT(k.key_hash, 8)) as key_prefix,
                  k.workspace_id, w.name as workspace_name, k.forward_auth,
                  k.created_at, k.expires_at, k.revoked_at,
                  k.daily_budget, k.monthly_budget, k.budget_mode, k.qos_class_id
           FROM api_keys k
           JOIN workspaces w ON w.id = k.workspace_id
           WHERE k.user_id = $1 AND ($4::uuid IS NULL OR k.workspace_id = $4)
           ORDER BY k.created_at DESC LIMIT $2 OFFSET $3"#,
    )
    .bind(user.user_id)
    .bind(limit)
    .bind(offset)
    .bind(user.key_workspace_id)
    .fetch_all(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal list keys: {e}");
        ApiError::internal("internal error")
    })?;

    // Fill current per-key spend, in the tenant's accounting currency, so a
    // budgeted key shows spend-vs-cap.
    let tenant = db.tenant_uuid();
    let spend = crate::routes::analytics::current_budget_spend(db.conn(), tenant, "key")
        .await
        .unwrap_or_default();
    for k in &mut keys {
        if let Some((daily, monthly)) = spend.get(&k.id) {
            k.daily_spent = *daily;
            k.monthly_spent = *monthly;
        }
    }

    Ok(Json(TotalPage::new(keys, limit, offset, total)))
}

// ---------------------------------------------------------------------------
// POST /keys — create a key in a workspace I belong to
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/portal/keys",
    tag = "Portal",
    operation_id = "portal_create_key",
    request_body = CreatePortalKeyRequest,
    responses(
        (status = 201, description = "API key created (plaintext returned once)", body = CreatePortalKeyResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 403, description = "Not a member of the workspace", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_key(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Json(body): Json<CreatePortalKeyRequest>,
) -> Result<(StatusCode, Json<CreatePortalKeyResponse>), ApiError> {
    if body.name.trim().is_empty() {
        return Err(ApiError::bad_request("key name is required"));
    }

    // A portal `ak-` key may only mint within its bound workspace.
    confine_to_key_workspace(&user, body.workspace_id)?;

    // The caller must be a member of the target workspace.
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id = $1 AND user_id = $2)",
    )
    .bind(body.workspace_id)
    .bind(user.user_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal create key membership check: {e}");
        ApiError::internal("internal error")
    })?;
    if !is_member {
        return Err(ApiError::forbidden("you are not a member of this workspace")
            .code(ApiErrorCode::WorkspaceMembershipRequired));
    }

    let id = Uuid::new_v4();
    let forward_auth = body.forward_auth.unwrap_or(false);

    // BYOK binding (optional): a forward-auth (`vk-`) key MAY bind to one BYOK
    // downstream to get LLM pass-through. Optional because a `vk-` key is also
    // valid for MCP bring-your-own-token (no LLM downstream). Validate the
    // binding when supplied — it must be a `byok` downstream granted to the key's
    // workspace (mirror the admin key path). LLM provisioning enforces a binding
    // at render time.
    let bound_downstream_id = if forward_auth { body.downstream_provider_id } else { None };
    if let Some(dp) = bound_downstream_id {
        let ok: bool = crate::routes::byok_downstream_bindable(db.conn(), dp, body.workspace_id)
        .await
        .map_err(|e| {
            tracing::error!("portal create key validate byok downstream: {e}");
            ApiError::internal("internal error")
        })?;
        if !ok {
            return Err(crate::routes::byok_binding_refused());
        }
    }

    let plaintext_key = if forward_auth {
        generate_forward_key()
    } else {
        generate_virtual_key()
    };
    let key_hash = hash_key(&plaintext_key);
    let key_prefix = &plaintext_key[..plaintext_key.len().min(12)];
    let now = chrono::Utc::now();

    // A person minting their own tool's key. Naming a class is allowed within
    // what they are entitled to; naming none takes the tenant's class for
    // interactive tools, clamped to what their workspace itself runs as.
    let qos_class_id = match body.qos_class_id {
        Some(_) => {
            crate::routes::qos_classes::resolve_key_class(
                db.conn(),
                body.workspace_id,
                body.qos_class_id,
                crate::routes::qos_classes::ClassAuthority::Delegated,
            )
            .await?
            .0
        }
        None => {
            crate::routes::qos_classes::default_class_for_mint(
                db.conn(),
                body.workspace_id,
                crate::routes::qos_classes::MintPrincipal::Person,
            )
            .await?
        }
    };

    sqlx::query(
        r#"INSERT INTO api_keys (id, tenant_id, workspace_id, user_id, key_hash, key_prefix, name, forward_auth, expires_at, created_at, downstream_provider_id, qos_class_id)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)"#,
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .bind(body.workspace_id)
    .bind(user.user_id)
    .bind(&key_hash)
    .bind(key_prefix)
    .bind(&body.name)
    .bind(forward_auth)
    .bind(body.expires_at)
    .bind(now)
    .bind(bound_downstream_id)
    .bind(qos_class_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        if crate::routes::bound_passthrough_gone(&e) {
            return crate::routes::byok_binding_refused();
        }
        tracing::error!("portal create key: {e}");
        ApiError::internal("internal error")
    })?;


    tracing::info!(
        user_id = %user.user_id,
        workspace_id = %body.workspace_id,
        "portal key created"
    );

    // Every gateway key is exercised against the proxy origin — a standard key on
    // `/v1/...`, a BYOK key on `/fwd/{key}/v1/...`. Carry the configured public
    // URL so the reveal-card curl never falls back to the console origin.
    let proxy_base_url = crate::tenant_public_url::try_resolve_public_url(
        &state.db,
        db.tenant_uuid(),
        crate::tenant_public_url::PublicUrlKey::Proxy,
    )
    .await?;

    Ok((
        StatusCode::CREATED,
        Json(CreatePortalKeyResponse {
            id,
            key: plaintext_key,
            name: Some(body.name),
            created_at: now,
            proxy_base_url,
        }),
    ))
}

// ---------------------------------------------------------------------------
// POST /keys/{id}/actions/revoke — revoke my key
// ---------------------------------------------------------------------------

#[utoipa::path(
    post,
    path = "/api/v1/portal/keys/{id}/actions/revoke",
    tag = "Portal",
    operation_id = "portal_revoke_key",
    params(("id" = Uuid, Path, description = "API key ID")),
    responses(
        (status = 200, description = "Key revoked", body = ActionResponse),
        (status = 404, description = "Key not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn revoke_key(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(key_id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Only revoke keys owned by this user — and, for a portal `ak-` key, only
    // within its bound workspace (cross-workspace key → 0 rows → 404).
    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL AND ($3::uuid IS NULL OR workspace_id = $3)",
    )
    .bind(key_id)
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal revoke key: {e}");
        ApiError::internal("internal error")
    })?;

    if result.rows_affected() == 0 {
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }

    Ok(Json(ActionResponse::ok().with_message("Key revoked.")))
}

// ---------------------------------------------------------------------------
// GET /workspaces/{id}/my-limits — what limits the caller in one workspace
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/portal/workspaces/{id}/my-limits",
    tag = "Portal",
    params(("id" = Uuid, Path, description = "Workspace id")),
    responses(
        (status = 200, description = "Every limit that applies to the caller in this workspace, widest first", body = crate::limits::EffectiveLimitStack),
        (status = 403, description = "Not a member of this workspace, or a key bound to another one", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_limits(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(workspace_id): Path<Uuid>,
) -> Result<Json<crate::limits::EffectiveLimitStack>, ApiError> {
    confine_to_key_workspace(&user, workspace_id)?;
    let internal = |e: sqlx::Error| {
        tracing::error!("portal my limits: {e}");
        ApiError::internal("internal error")
    };
    let Some(role) = crate::routes::workspaces::member_role(&mut db, workspace_id, user.user_id).await? else {
        return Err(ApiError::forbidden("you are not a member of this workspace")
            .code(ApiErrorCode::WorkspaceMembershipRequired));
    };
    let tenant_id = db.tenant_uuid();
    let viewer = crate::limits::StackViewer::for_member_role(&role);
    crate::limits::effective_stack(db.conn(), tenant_id, workspace_id, user.user_id, viewer)
        .await
        .map(Json)
        .map_err(internal)
}

// ---------------------------------------------------------------------------
// GET /stats — my usage stats
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/portal/stats",
    tag = "Portal",
    params(StatsQuery),
    responses(
        (status = 200, description = "Personal usage statistics", body = PortalStats),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_stats(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(query): Query<StatsQuery>,
) -> Result<Json<PortalStats>, ApiError> {
    let (start_ts, end_ts) = query.time_window().resolve(30)?;
    // One scope for the whole payload: when it widens, EVERY figure below is
    // the workspace's rather than the caller's, so the numbers in one response
    // always describe the same population.
    let scope = PortalDataScope::resolve(db.conn(), &user, query.workspace_id).await?;

    // Key counts. A portal `ak-` key (`key_workspace_id` Some) reports only its
    // bound workspace; a human session (None) reports across all its workspaces.
    let active_keys: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*)::bigint FROM api_keys WHERE ($1::uuid IS NULL OR user_id = $1) AND {} AND ($2::uuid IS NULL OR workspace_id = $2)",
        super::keys::KEY_LIVE
    )))
    .bind(scope.user_id())
    .bind(scope.workspace_id())
    .fetch_one(db.conn())
    .await
    .map_err(|e| { tracing::error!("portal stats active keys: {e}"); ApiError::internal("internal error") })?;

    // Still ahead: an expired key is no longer "expiring soon".
    let expiring_soon: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(format!(
        "SELECT COUNT(*)::bigint FROM api_keys WHERE ($1::uuid IS NULL OR user_id = $1) AND {} AND expires_at > NOW() AND ($2::uuid IS NULL OR workspace_id = $2)",
        super::keys::KEY_EXPIRY_NOTICE
    )))
    .bind(scope.user_id())
    .bind(scope.workspace_id())
    .fetch_one(db.conn())
    .await
    .map_err(|e| { tracing::error!("portal stats expiring: {e}"); ApiError::internal("internal error") })?;

    let window = (start_ts, end_ts);
    let totals =
        crate::audit_store::usage::portal_totals(db.conn(), &scope, window)
            .await
            .map_err(|e| { tracing::error!("portal stats usage: {e}"); ApiError::internal("internal error") })?;

    // Per-key stats.
    let per_key = crate::audit_store::usage::portal_per_key(db.conn(), &scope, window)
        .await
        .map_err(|e| { tracing::error!("portal stats per key: {e}"); ApiError::internal("internal error") })?;

    // Every figure below that priced nothing still has to name a denomination
    // for its zero, and a key with no traffic at all is the common case here —
    // so the tenant's current currency is read once, unconditionally.
    let fallback = super::pricing::accounting_currency(db.conn()).await;

    Ok(Json(PortalStats {
        active_keys,
        expiring_soon,
        total_requests: totals.requests,
        total_tokens: totals.tokens,
        spend: super::spend_total(totals.currency_count, totals.currency, totals.amount, fallback),
        per_key: per_key
            .into_iter()
            .map(|k| PortalKeyStats {
                key_id: k.id,
                prefix: k.key_prefix,
                name: k.name,
                workspace: k.workspace,
                requests: k.usage.requests,
                tokens: k.usage.tokens,
                spend: super::spend_total(k.usage.currency_count, k.usage.currency, k.usage.amount, fallback),
                last_used: k.last_used,
            })
            .collect(),
    }))
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Resolve the downstream providers a user can reach across all their
/// workspaces — the union of each workspace's provider allowlist. Membership in
/// a workspace grants only the providers that workspace allowlists (no Default
/// exception).
async fn accessible_providers(
    conn: &mut Scoped,
    user_id: Uuid,
    key_workspace_id: Option<Uuid>,
) -> Result<Vec<PortalProviderInfo>, ApiError> {
    // A portal `ak-` key (`key_workspace_id` Some) resolves providers only from
    // its bound workspace; a human session (None) gets the union across all its
    // workspaces.
    // (id, name, description, icon, byok, server provider, server upstream_api_format)
    // — aliased to dodge clippy::type_complexity.
    type ProviderRow = (Uuid, String, Option<String>, Option<String>, bool, Option<String>, Option<String>);
    // Granted-only, with NO Default-workspace exception: a provider is reachable
    // solely through a live grant on a workspace the caller belongs to (the
    // Default workspace has no wildcard). Live, as the gateway reads grants: a
    // pass-through whose server is off is not offered, so no key form or
    // quickstart picker can bind to it.
    static SQL: std::sync::LazyLock<String> = std::sync::LazyLock::new(|| {
        super::with_live_provider_grants(
            r#"SELECT DISTINCT dp.id, dp.name, dp.description, dp.icon, dp.byok,
                  s.provider, s.upstream_api_format
           FROM downstream_providers dp
           LEFT JOIN upstream_servers s ON s.id = dp.upstream_server_id
           WHERE dp.id IN (
                   SELECT wda.downstream_provider_id
                   FROM (
--{live_provider_grants}
                   ) wda
                   JOIN workspace_members wm ON wm.workspace_id = wda.workspace_id
                   WHERE wm.user_id = $1
                     AND ($2::uuid IS NULL OR wm.workspace_id = $2)
                 )
           ORDER BY dp.name"#,
        )
    });
    let rows: Vec<ProviderRow> = sqlx::query_as(sqlx::AssertSqlSafe(SQL.as_str()))
    .bind(user_id)
    .bind(key_workspace_id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("portal accessible providers: {e}");
        ApiError::internal("internal error")
    })?;

    Ok(rows
        .into_iter()
        .map(|(id, name, description, icon, byok, provider, format)| PortalProviderInfo {
            id,
            name,
            description,
            icon,
            byok,
            // The protocol the proxy forwards a pass-through in — the one
            // derivation of it. Only live pass-throughs are listed above.
            upstream_protocol: provider.filter(|_| byok).map(|p| {
                streamscope_core::proxy::routing::upstream_api_version_for_provider(&p, format.as_deref())
                    .as_str()
                    .to_string()
            }),
        })
        .collect())
}

// ===========================================================================
// Self-service: my sessions / my requests (audit) / my trace / my media
//
// Member-tier read surface. Whose rows every query reads is the resolved
// `PortalDataScope` alone (RLS scopes by tenant only): the caller's own, or a
// sharing workspace's. Detail/media endpoints pre-gate ownership via
// `audit_store::ownership::assert_*_owned` (404, never 403). For an `ak-`
// portal key, `key_workspace_id` additionally confines the result to that
// workspace. The query structs below carry the console's filters but never a
// user id or a workspace set, so a client cannot widen the scope; a teammate
// email only narrows a shared view. Every body passes through
// `portal_view::MemberView` before it is sent.
// ===========================================================================

use super::audit::{
    get_session_conversation_impl, get_trace_impl, AuditKind, AuditLogRow,
    AuditQuery, SessionLinkage, SessionSort, ConversationResponse, LinkedSessions, ResponseFormat,
    SessionListQuery, SessionNotFound, SessionSummary, ToolDefinitionBlobResponse, TraceResponse,
};
use crate::audit_store::AuditScope;
use crate::audit_store::logs::list_audit_rows;
use super::portal_view::MemberView;
use crate::audit_store::ownership::{
    assert_media_owned, assert_request_owned, assert_session_owned, assert_tool_definition_owned,
};
use crate::audit_store::sessions::{linked_sessions_in_portal_scope, list_sessions_impl};
use super::OffsetPage;
use streamscope_core::audit::BlobType;

const PORTAL_AUDIT_DEFAULT_LIMIT: i64 = 100;

/// The workspace a portal read is being made within, for the detail endpoints
/// that carry no other filters.
///
/// One struct rather than a `workspace_id` copy-pasted onto each handler, so
/// every surface spells the parameter the same way and resolves it through the
/// same [`PortalDataScope`].
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalScopeQuery {
    /// Read within this workspace, which widens the read to the whole workspace
    /// when it shares with its members. Absent = your own rows only.
    pub workspace_id: Option<Uuid>,
}

/// Whose rows a portal request may read.
///
/// **The fields are private and the only constructor is
/// [`PortalDataScope::resolve`].** That is the guard, not a convention: the pair
/// `(user_id: None, workspace_id: None)` means "every row in the tenant", and a
/// handler that assembled two loose `Option`s could produce it by forgetting a
/// branch. Held as one value it cannot be built by accident — `resolve` never
/// returns that combination, and the accessors are read-only.
#[derive(Debug, Clone, Copy)]
pub struct PortalDataScope {
    user_id: Option<Uuid>,
    workspace_id: Option<Uuid>,
}

#[cfg(test)]
impl PortalDataScope {
    /// A scope as `resolve` returns one, for tests of what consumes it.
    pub(crate) fn for_test(user_id: Option<Uuid>, workspace_id: Option<Uuid>) -> Self {
        Self { user_id, workspace_id }
    }
}

impl PortalDataScope {
    /// `None` widens the read to every member of the workspace, which is only
    /// ever paired with a `Some` [`Self::workspace_id`].
    pub fn user_id(&self) -> Option<Uuid> {
        self.user_id
    }

    pub fn workspace_id(&self) -> Option<Uuid> {
        self.workspace_id
    }

    /// Resolve what the caller asked for against what the workspace allows.
    ///
    /// The default — and the answer to every request that does not name a
    /// workspace — is the caller's own rows. Widening requires all three of: an
    /// explicit `workspace_id`, that workspace set to `members`, and the caller
    /// being a member of it. A portal `ak-` key is additionally confined to the
    /// one workspace it is bound to, exactly as it is everywhere else.
    ///
    /// Membership is re-read here on every request rather than trusted from the
    /// session, so removing someone from a workspace takes their view away on
    /// their next call rather than at their next login.
    pub async fn resolve(
        conn: &mut Scoped,
        user: &PortalUser,
        requested_workspace_id: Option<Uuid>,
    ) -> Result<Self, ApiError> {
        let own = Self {
            user_id: Some(user.user_id),
            workspace_id: user.key_workspace_id,
        };
        let Some(workspace_id) = requested_workspace_id else {
            return Ok(own);
        };
        if let Some(bound) = user.key_workspace_id
            && bound != workspace_id
        {
            return Err(ApiError::forbidden(
                "this key is bound to a different workspace",
            )
            .code(ApiErrorCode::PermissionDenied));
        }

        // One statement, so a workspace that shares but excludes this caller is
        // indistinguishable from one that does not share — neither widens.
        let shared: Option<i32> = sqlx::query_scalar(
            "SELECT 1 FROM workspaces w \
              WHERE w.id = $1 AND w.member_visibility = 'members' \
                AND EXISTS (SELECT 1 FROM workspace_members m \
                             WHERE m.workspace_id = w.id AND m.user_id = $2) \
              LIMIT 1",
        )
        .bind(workspace_id)
        .bind(user.user_id)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("portal scope resolve: {e}");
            ApiError::internal("internal error")
        })?;

        if shared.is_none() {
            // Not an error: the caller may legitimately be asking for their own
            // rows within a workspace that does not share. Narrow rather than
            // refuse, and confine to the workspace they named.
            return Ok(Self {
                user_id: Some(user.user_id),
                workspace_id: Some(workspace_id),
            });
        }
        Ok(Self {
            user_id: None,
            workspace_id: Some(workspace_id),
        })
    }
}

/// The console's session filters a member may send. Whose rows: only the
/// resolved [`PortalDataScope`] — no field here names a user id or a workspace
/// set, so none can widen it. `user_email` narrows a shared-workspace view and
/// is ignored on the caller's own rows.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalSessionQuery {
    /// Read this workspace's sessions instead of only your own, when the
    /// workspace shares with its members. Absent = your own rows.
    pub workspace_id: Option<Uuid>,
    pub model: Option<String>,
    /// At least 3 characters once trimmed (`search_term_too_short`).
    pub search: Option<String>,
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// Default `newest`. While expert findings are withheld from members,
    /// `alerts` is read as `newest`.
    pub sort: Option<SessionSort>,
    /// Sessions whose alert is exactly this level. Ignored while expert
    /// findings are withheld from members.
    pub alert_level: Option<streamscope_core::audit::AlertLevel>,
    /// Filter by app_id (agent type, e.g. "opencode", "claude-code").
    pub app_id: Option<String>,
    /// Filter by linkage.
    pub linked: Option<SessionLinkage>,
    /// A teammate's email (substring), in a shared-workspace view only.
    pub user_email: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// The console's audit filters a member may send — every one except those
/// naming whose rows (`user_id`, `workspace_ids`) and the console's token
/// deep-link (`jti`). Whose rows: only the resolved [`PortalDataScope`].
/// `user_email` narrows a shared-workspace view and is ignored on the caller's
/// own rows.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalAuditQuery {
    /// Read this workspace's audit rows instead of only your own, when the
    /// workspace shares with its members. Absent = your own rows.
    pub workspace_id: Option<Uuid>,
    /// Row family to return. Default `llm`.
    pub kind: Option<AuditKind>,
    /// At least 3 characters once trimmed (`search_term_too_short`).
    pub search: Option<String>,
    /// Inclusive window start (RFC3339).
    pub start: Option<chrono::DateTime<chrono::Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<chrono::DateTime<chrono::Utc>>,
    /// One request: still filtered by the scope; it bypasses the window only.
    pub request_id: Option<Uuid>,
    /// A teammate's email (substring), in a shared-workspace view only.
    pub user_email: Option<String>,
    pub app_id: Option<String>,
    pub error_category: Option<String>,
    pub has_guardrail: Option<bool>,
    pub model: Option<String>,
    pub finish_reason: Option<String>,
    pub upstream_server: Option<String>,
    pub api_version: Option<String>,
    pub media_type: Option<String>,
    pub has_blocked: Option<bool>,
    pub surface: Option<String>,
    pub operation: Option<String>,
    pub tool_id: Option<String>,
    pub resource_uri: Option<String>,
    pub prompt_id: Option<String>,
    pub virtual_server_id: Option<Uuid>,
    pub upstream_server_id: Option<Uuid>,
    pub agent_slug: Option<String>,
    pub task_state: Option<String>,
    /// Comma-separated MCP or A2A methods.
    pub methods: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

/// A teammate filter applies only where teammates' rows are in view: on the
/// caller's own rows it is ignored — narrowing never widens, and a filter that
/// emptied the caller's own list would say nothing useful.
fn teammate_filter(scope: &PortalDataScope, user_email: Option<String>) -> Option<String> {
    user_email.filter(|_| scope.user_id().is_none())
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/sessions",
    tag = "Portal",
    params(PortalSessionQuery),
    responses(
        (status = 200, description = "The session summaries the caller may read", body = OffsetPage<SessionSummary>),
        (status = 400, description = "`start` is not before `end`, or a search term under 3 characters", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_sessions(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(q): Query<PortalSessionQuery>,
) -> Result<Json<OffsetPage<SessionSummary>>, ApiError> {
    super::check_bounds(q.start, q.end)?;
    super::check_search(q.search.as_deref())?;
    // Expert findings are withheld from members (`portal_view`): the alert
    // filter and the alert order are accepted and NOT applied, or the rows
    // returned would reveal the alerts. Dropped first, so `alerts` with a
    // search term is read as the default order rather than refused.
    let _withheld = q.alert_level;
    let sort = q.sort.filter(|s| *s != SessionSort::Alerts);
    let limit = q
        .limit
        .unwrap_or(crate::audit_store::sessions::SESSIONS_DEFAULT_LIMIT)
        .clamp(1, crate::settings::admin_settings().sessions_max_limit().max(1));
    let offset = crate::routes::resolve_offset(q.offset);

    // Identity scope: own user_id, plus the `ak-` key's workspace if any —
    // widened to the whole workspace only when that workspace shares.
    let data_scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    let scope = AuditScope::portal(&data_scope);
    let mut query = SessionListQuery::default();
    query.model = q.model;
    query.search = q.search;
    query.start = q.start;
    query.end = q.end;
    query.app_id = q.app_id;
    query.linked = q.linked;
    query.user_email = teammate_filter(&data_scope, q.user_email);
    query.sort = sort;
    // Overfetch +1 for cheap has_more (impl trusts the passed limit).
    query.limit = Some(limit + 1);
    query.offset = Some(offset);

    let found = list_sessions_impl(db.conn(), query, &scope).await.map_err(|e| {
        tracing::error!("portal my_sessions: {e}");
        ApiError::internal("Failed to list sessions")
    })?;

    Ok(Json(
        OffsetPage::from_overfetched(found.rows.for_member(), limit, offset).with_scan_cut(found.scan_cut),
    ))
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/sessions/{id}/conversation",
    tag = "Portal",
    params(("id" = Uuid, Path, description = "Session id"), PortalScopeQuery),
    responses(
        (status = 200, description = "Full conversation for the caller's own session", body = ConversationResponse),
        (status = 404, description = "Session not found or not owned", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_session_conversation(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(session_id): Path<Uuid>,
    Query(q): Query<PortalScopeQuery>,
) -> Result<Json<ConversationResponse>, ApiError> {
    let scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    assert_session_owned(db.conn(), session_id, &scope).await?;
    let tenant_id = db.tenant_uuid();
    let conv = get_session_conversation_impl(db.conn(), tenant_id, session_id, ResponseFormat::Parsed, &AuditScope::portal(&scope))
        .await
        .map_err(|e| SessionNotFound::into_api_error(e, "portal my_session_conversation"))?;
    Ok(Json(conv.for_member()))
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/sessions/{id}/linked",
    tag = "Portal",
    params(("id" = Uuid, Path, description = "Session id"), PortalScopeQuery),
    responses(
        (status = 200, description = "Parent/child sessions linked to the caller's own session", body = LinkedSessions),
        (status = 404, description = "Session not found or not owned", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_session_linked(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(session_id): Path<Uuid>,
    Query(q): Query<PortalScopeQuery>,
) -> Result<Json<LinkedSessions>, ApiError> {
    let scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    // Gate the root session, then confine the parent/child summaries to the
    // caller: a linked parent or child can belong to another member of the
    // tenant, or of a shared workspace.
    assert_session_owned(db.conn(), session_id, &scope).await?;
    linked_sessions_in_portal_scope(db.conn(), session_id, &scope).await.map(|l| Json(l.for_member()))
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/audit",
    tag = "Portal",
    params(PortalAuditQuery),
    responses(
        (status = 200, description = "The audit rows the caller may read, kind-discriminated", body = OffsetPage<AuditLogRow>),
        (status = 400, description = "`start` is not before `end`, a search term under 3 characters, or a `kind=all` page is too deep", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_audit(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Query(q): Query<PortalAuditQuery>,
) -> Result<Json<OffsetPage<AuditLogRow>>, ApiError> {
    super::check_bounds(q.start, q.end)?;
    super::check_search(q.search.as_deref())?;
    let limit = q
        .limit
        .unwrap_or(PORTAL_AUDIT_DEFAULT_LIMIT)
        .clamp(1, crate::settings::admin_settings().audit_max_limit.max(1));
    let offset = crate::routes::resolve_offset(q.offset);

    // The caller's own rows (+ `ak-` workspace), widened to the whole
    // workspace only when that workspace shares.
    let data_scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    let scope = AuditScope::portal(&data_scope);
    let mut query = AuditQuery::default();
    query.kind = q.kind;
    query.search = q.search;
    query.start = q.start;
    query.end = q.end;
    query.request_id = q.request_id;
    query.user_email = teammate_filter(&data_scope, q.user_email);
    query.app_id = q.app_id;
    query.error_category = q.error_category;
    query.has_guardrail = q.has_guardrail;
    query.model = q.model;
    query.finish_reason = q.finish_reason;
    query.upstream_server = q.upstream_server;
    query.api_version = q.api_version;
    query.media_type = q.media_type;
    query.has_blocked = q.has_blocked;
    query.surface = q.surface;
    query.operation = q.operation;
    query.tool_id = q.tool_id;
    query.resource_uri = q.resource_uri;
    query.prompt_id = q.prompt_id;
    query.virtual_server_id = q.virtual_server_id;
    query.upstream_server_id = q.upstream_server_id;
    query.agent_slug = q.agent_slug;
    query.task_state = q.task_state;
    query.methods = q.methods;

    let mut page = list_audit_rows(db.conn(), &query, &scope, limit, offset).await?;
    page.items = page.items.for_member();
    Ok(Json(page))
}

/// One option of a member's audit filter: its id and display name.
#[derive(Serialize, ToSchema, sqlx::FromRow)]
pub struct PortalFilterOption {
    pub id: String,
    pub name: String,
}

/// The audit filter options a member may pick from: configuration only, never
/// a scan of the traffic. Apps and QoS classes are the tenant's; MCP servers,
/// MCP upstreams and A2A agents are those the caller's workspaces are granted
/// (a portal `ak-` key: its one workspace).
#[derive(Serialize, ToSchema)]
pub struct PortalAuditFilterOptions {
    /// Apps by `app_id` (the key an audit row records).
    pub apps: Vec<PortalFilterOption>,
    /// Virtual servers by id.
    pub mcp_virtual_servers: Vec<PortalFilterOption>,
    /// Upstream servers reachable through those virtual servers, by id.
    pub mcp_upstream_servers: Vec<PortalFilterOption>,
    /// A2A agents by slug (the filter's key).
    pub a2a_agents: Vec<PortalFilterOption>,
    /// QoS classes by id, to name the class an audit row records.
    pub qos_classes: Vec<PortalFilterOption>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/audit/filter-options",
    tag = "Portal",
    responses(
        (status = 200, description = "The audit filter options the caller may pick from", body = PortalAuditFilterOptions),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_audit_filter_options(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
) -> Result<Json<PortalAuditFilterOptions>, ApiError> {
    use super::portal_mcp::VISIBLE_VS;
    let failed = |e: sqlx::Error| {
        tracing::error!("portal audit filter options: {e}");
        ApiError::internal("internal error")
    };
    // `$1` the caller, `$2` the portal key's bound workspace or NULL — the
    // binds `VISIBLE_VS` reads.
    let granted = |sql: String| sqlx::query_as::<_, PortalFilterOption>(sqlx::AssertSqlSafe(sql));
    let mcp_virtual_servers = granted(format!(
        "SELECT vs.id::text AS id, vs.name FROM mcp_virtual_servers vs WHERE {VISIBLE_VS} ORDER BY vs.name"
    ))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;
    let mcp_upstream_servers = granted(format!(
        "SELECT us.id::text AS id, us.name FROM mcp_upstream_servers us \
          WHERE us.id IN (SELECT vr.upstream_server_id FROM mcp_virtual_routes vr \
                            JOIN mcp_virtual_servers vs ON vs.id = vr.virtual_server_id \
                           WHERE vr.enabled AND {VISIBLE_VS}) \
            AND us.enabled \
          ORDER BY us.name"
    ))
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;
    let a2a_agents = granted(
        "SELECT ag.slug AS id, ag.name FROM a2a_upstream_agents ag \
          WHERE ag.id IN (SELECT waa.agent_id FROM workspace_a2a_access waa \
                            JOIN workspace_members wm ON wm.workspace_id = waa.workspace_id \
                           WHERE wm.user_id = $1 AND ($2::uuid IS NULL OR wm.workspace_id = $2)) \
            AND ag.enabled \
          ORDER BY ag.name"
            .to_string(),
    )
    .bind(user.user_id)
    .bind(user.key_workspace_id)
    .fetch_all(db.conn())
    .await
    .map_err(failed)?;
    let apps = granted("SELECT app_key AS id, name FROM apps WHERE NOT suppressed ORDER BY app_key".to_string())
        .fetch_all(db.conn())
        .await
        .map_err(failed)?;
    let qos_classes =
        granted("SELECT id::text AS id, name FROM qos_classes WHERE NOT suppressed ORDER BY rank".to_string())
            .fetch_all(db.conn())
            .await
            .map_err(failed)?;
    Ok(Json(PortalAuditFilterOptions { apps, mcp_virtual_servers, mcp_upstream_servers, a2a_agents, qos_classes }))
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/audit/{request_id}",
    tag = "Portal",
    params(("request_id" = Uuid, Path, description = "Request id"), PortalScopeQuery),
    responses(
        (status = 200, description = "Full trace for the caller's own request", body = TraceResponse),
        (status = 404, description = "Request not found or not owned", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_trace(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(request_id): Path<Uuid>,
    Query(q): Query<PortalScopeQuery>,
) -> Result<Json<TraceResponse>, ApiError> {
    let scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    assert_request_owned(db.conn(), request_id, &scope).await?;
    let tenant_id = db.tenant_uuid();
    let Json(trace) = get_trace_impl(db.conn(), tenant_id, request_id, ResponseFormat::Parsed).await?;
    Ok(Json(trace.for_member()))
}

/// The web calls an LLM request of the caller's dispatched (its substitution
/// children) — the portal twin of [`super::audit::list_web_calls_for_request`].
/// The parent is ownership-gated (404), and the children are read under the
/// same scope.
#[utoipa::path(
    get,
    path = "/api/v1/portal/audit/{request_id}/web",
    tag = "Portal",
    params(("request_id" = Uuid, Path, description = "Orchestrating LLM request id"), PortalScopeQuery, PageQuery),
    responses(
        (status = 200, description = "Paginated web child calls", body = OffsetPage<super::audit::WebAuditLogEntry>),
        (status = 404, description = "Request not found or not owned", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_web_calls_for_request(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(request_id): Path<Uuid>,
    Query(q): Query<PortalScopeQuery>,
    Query(page): Query<PageQuery>,
) -> Result<Json<OffsetPage<super::audit::WebAuditLogEntry>>, ApiError> {
    let scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    assert_request_owned(db.conn(), request_id, &scope).await?;
    let limit = page
        .limit
        .unwrap_or(PORTAL_AUDIT_DEFAULT_LIMIT)
        .clamp(1, crate::settings::admin_settings().audit_max_limit.max(1));
    let offset = crate::routes::resolve_offset(page.offset);
    let rows = crate::audit_store::logs::list_audit_logs_web(
        db.conn(),
        &AuditQuery::default(),
        &AuditScope::portal(&scope),
        limit,
        offset,
        Some(request_id),
    )
    .await?;
    Ok(Json(OffsetPage::from_overfetched(rows.for_member(), limit, offset)))
}

/// Media-blob fetch — requires the owning `request_id` so ownership is a single
/// indexed row check (`assert_media_owned`) rather than a tenant-wide hash scan.
#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct PortalMediaQuery {
    /// The request that references this blob — the caller's own, or any in a
    /// workspace that shares with its members.
    pub request_id: Uuid,
    /// Blob-type discriminator (canonical `BlobType` value). Defaults to
    /// `response_body`.
    pub blob_type: Option<String>,
    /// Read within this workspace, which widens the read to the whole workspace
    /// when it shares with its members. Absent = your own rows only.
    pub workspace_id: Option<Uuid>,
}

#[utoipa::path(
    get,
    path = "/api/v1/portal/audit/media/{hash}",
    tag = "Portal",
    params(
        ("hash" = String, Path, description = "SHA-256 content hash"),
        PortalMediaQuery,
    ),
    responses(
        (status = 200, description = "Binary blob data", content_type = "application/octet-stream"),
        (status = 404, description = "Blob not found or not owned", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_media(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(hash): Path<String>,
    Query(params): Query<PortalMediaQuery>,
) -> Result<impl axum::response::IntoResponse, ApiError> {
    let blob_type = match params.blob_type.as_deref() {
        Some(s) => s.parse::<BlobType>().map_err(|_| {
            ApiError::bad_request("invalid blob_type").code(ApiErrorCode::MediaBlobTypeInvalid)
        })?,
        None => BlobType::ResponseBody,
    };

    // Ownership: the hash must be referenced by a request inside the scope.
    let scope = PortalDataScope::resolve(db.conn(), &user, params.workspace_id).await?;
    assert_media_owned(db.conn(), params.request_id, &hash, &scope).await?;

    let tenant_id = db.tenant_uuid();
    let row = crate::content_store::media_blobs::get(db.conn(), tenant_id, &hash, blob_type)
        .await
        .map_err(|e| {
            tracing::error!("portal my_media query: {e}");
            ApiError::internal("Failed to query media blob")
        })?;

    let Some((media_type, data)) = row else {
        return Err(
            ApiError::not_found("Media blob not found", ApiErrorCode::MediaBlobNotFound)
        );
    };

    Ok(super::audit::media_blob_response(media_type, data))
}

/// Tool-definition JSON fetch — the portal twin of
/// [`super::audit::get_tool_definition_blob`]. The session-view "tools changed"
/// expander lazy-fetches the previous/current tool blobs to render the diff.
/// Ownership is proven transitively: the hash must appear on a conversation turn
/// the caller owns (`assert_tool_definition_owned`), so a portal user can only
/// read tool schemas from their own traffic.
#[utoipa::path(
    get,
    path = "/api/v1/portal/audit/tool-definitions/{hash}",
    tag = "Portal",
    params(
        PortalScopeQuery,
        ("hash" = String, Path, description = "SHA-256 content hash of the tool-definition blob"),
    ),
    responses(
        (status = 200, description = "Tool-definition JSON blob", body = ToolDefinitionBlobResponse),
        (status = 404, description = "Hash not found or not owned", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn my_tool_definition_blob(
    mut db: TenantConn,
    Extension(user): Extension<PortalUser>,
    Path(hash): Path<String>,
    Query(q): Query<PortalScopeQuery>,
) -> Result<Json<ToolDefinitionBlobResponse>, ApiError> {
    let scope = PortalDataScope::resolve(db.conn(), &user, q.workspace_id).await?;
    assert_tool_definition_owned(db.conn(), &hash, &scope).await?;

    let tenant_id = db.tenant_uuid();
    let row = crate::content_store::tool_definitions::get(db.conn(), tenant_id, &hash)
        .await
        .map_err(|e| {
            tracing::error!("portal tool definition blob query: {e}");
            ApiError::internal("Failed to query tool definition")
        })?;

    let Some((definition, size_bytes)) = row else {
        return Err(
            ApiError::not_found("Tool definition not found", ApiErrorCode::AuditRecordNotFound),
        );
    };

    Ok(Json(ToolDefinitionBlobResponse { hash, definition, size_bytes: size_bytes as i64 }))
}
