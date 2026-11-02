//! API key lifecycle — create, list, get, update, revoke.
//!
//! Keys are generated with `sk-` (proxy-issued) or `vk-` (BYOK forward-auth)
//! prefixes. The plaintext key is returned exactly once at creation; only the
//! SHA-256 hash is stored. A key is bound to a `(user, workspace)` pair — the
//! workspace allowlist gates which providers and MCP servers the key can reach,
//! evaluated per request at the proxy. One key spans both `/v1/*` and
//! `/mcp/<slug>` (or `/fwd/{key}/...` when `forward_auth`).

use std::sync::Arc;

use axum::extract::{Path, Query, State};
use axum::http::StatusCode;
use axum::Json;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;

use streamscope_core::auth::virtual_key::{generate_forward_key, generate_virtual_key, hash_key};

use super::analytics::DEFAULT_USAGE_DAYS;
use super::{
    ActionResponse, ApiError, ApiErrorCode, ApiErrorResponse, PageQuery,
    TimeWindow, TotalPage,
};
use crate::AdminState;
use crate::db::tenant::TenantConn;

/// An `api_keys` row that authenticates now: not revoked, not expired. Spliced
/// unqualified into a query on `api_keys` (the portal's key counts, the
/// effective-limit stack's key layers); a query on an aliased `api_keys k`
/// spells the same predicate out on `k.` — keep the two in step.
pub(crate) const KEY_LIVE: &str = "(revoked_at IS NULL AND (expires_at IS NULL OR expires_at > NOW()))";

/// An `api_keys` row whose expiry warrants a notice: unrevoked, ending within
/// 7 days or already ended, and not created to live 7 days or less (the CLI's
/// per-run keys — expiring is their design). The expiry notifications, the
/// portal Home and the portal's "expiring soon" count all read it; each adds
/// its own lower bound on `expires_at`. Spliced unqualified into a query on
/// `api_keys`.
pub(crate) const KEY_EXPIRY_NOTICE: &str = "(revoked_at IS NULL AND expires_at IS NOT NULL \
      AND expires_at < NOW() + INTERVAL '7 days' \
      AND created_at < expires_at - INTERVAL '7 days')";

/// Optional per-key budget ceiling. Enforced as a third "stricter wins" bucket
/// (workspace, per-user, key) keyed by the key id — budget only, no RPM/TPM.
/// Settable by tenant admins and workspace managers; not self-service.
#[derive(Deserialize, Serialize, ToSchema)]
pub struct KeyBudget {
    /// Daily budget in the tenant's accounting currency. `null` = no daily cap.
    #[serde(default)]
    pub daily_budget: Option<f64>,
    /// Monthly budget in the tenant's accounting currency. `null` = no monthly cap.
    #[serde(default)]
    pub monthly_budget: Option<f64>,
    /// `enforce` (block over-cap) | `alert_only` (notify but never block).
    #[serde(default = "crate::routes::workspaces::default_budget_mode")]
    pub budget_mode: String,
}

#[derive(Deserialize, ToSchema)]
pub struct CreateKeyRequest {
    pub user_id: Uuid,
    /// Workspace the key is bound to. The user must be a member; the workspace
    /// allowlist gates which providers / MCP servers the key can reach.
    pub workspace_id: Uuid,
    pub name: String,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    /// When true, generate a `vk-` prefix key for BYOK (forward client auth on
    /// `/fwd/{key}/...`). Otherwise a proxy-issued `sk-` key.
    #[serde(default)]
    pub forward_auth: bool,
    /// Optional per-key budget ceiling (omitted ⇒ no per-key cap).
    #[serde(default)]
    pub budget: Option<KeyBudget>,
    /// For a BYOK (`forward_auth`) key, the BYOK downstream it is bound to.
    /// Unconfigured models pass through to that downstream's upstream with the
    /// client's own forwarded credential; routes inside the downstream override
    /// individual models. Must be a `byok` downstream granted to `workspace_id`.
    /// Ignored for `sk-` keys.
    #[serde(default)]
    pub downstream_provider_id: Option<Uuid>,
    /// The key's priority class under load. Omitted means the workspace's own
    /// class; a class more important than the workspace's is an elevation, and
    /// only a tenant admin may make one.
    #[serde(default)]
    pub qos_class_id: Option<Uuid>,
}

#[derive(Serialize, ToSchema)]
pub struct CreateKeyResponse {
    pub id: Uuid,
    /// The plaintext key — returned ONCE, never again.
    pub key: String,
    pub name: Option<String>,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// The tenant's configured gateway public origin (no trailing slash), for
    /// rendering the BYOK connection URL (`{proxy_base_url}/fwd/{key}`). `None`
    /// when `proxy_public_url` is unset — the UI falls back to a relative hint.
    pub proxy_base_url: Option<String>,
}

/// One row of the unified key inventory — gateway keys (`api_keys`) and
/// automation keys (`automation_keys`) in a single shape. `kind` discriminates;
/// per-family fields are `null` where they don't apply.
#[derive(Serialize, sqlx::FromRow, ToSchema)]
pub struct KeyListItem {
    pub id: Uuid,
    /// The owning principal (a human user or a service account).
    pub user_id: Uuid,
    /// `null` for `ak_admin` keys (tenant-wide, never workspace-bound).
    pub workspace_id: Option<Uuid>,
    pub workspace_name: Option<String>,
    pub name: Option<String>,
    /// Masked display of key hash prefix.
    pub key_prefix: String,
    /// `sk` (gateway) | `vk` (gateway BYOK) | `ak_admin` (admin control plane)
    /// | `ak_portal` (portal control plane). The single discriminator — BYOK is
    /// `kind == "vk"`, not a separate flag.
    pub kind: String,
    /// `read_only` | `admin` | `super_admin` — `ak_admin` keys only.
    pub admin_scope: Option<String>,
    /// `user` (human) | `service` (service account) | `agent` (the built-in
    /// agent service account).
    pub owner_kind: String,
    pub owner_email: String,
    pub owner_display_name: Option<String>,
    pub owner_is_active: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub expires_at: Option<chrono::DateTime<chrono::Utc>>,
    pub revoked_at: Option<chrono::DateTime<chrono::Utc>>,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
    /// Per-key daily budget in the tenant's accounting currency (`null` = no
    /// per-key daily cap; always `null` for automation keys, which carry no
    /// budget).
    pub daily_budget: Option<f64>,
    /// Per-key monthly budget in the tenant's accounting currency (`null` = no
    /// per-key monthly cap).
    pub monthly_budget: Option<f64>,
    /// `enforce` | `alert_only` — gateway keys only, meaningful when a budget is
    /// set.
    pub budget_mode: Option<String>,
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
    /// The key's own priority class under load (`null` = the workspace's
    /// class; always `null` for automation keys, which carry none).
    pub qos_class_id: Option<Uuid>,
    /// Whether that class is more important than the workspace's — granted by
    /// a tenant admin. `null` for automation keys.
    pub qos_class_elevated: Option<bool>,
}

#[derive(Deserialize, ToSchema)]
pub struct UpdateKeyRequest {
    /// New name for the key. Present and `null` clears it; absent leaves it.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<String>)]
    pub name: Option<Option<String>>,
    /// New expiry. Present and `null` clears it; absent leaves it unchanged.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    #[schema(value_type = Option<chrono::DateTime<chrono::Utc>>)]
    pub expires_at: Option<Option<chrono::DateTime<chrono::Utc>>>,
    /// When present, replaces the key's budget triple (daily/monthly/mode);
    /// omit to leave the budget untouched. A present object with null caps
    /// clears the per-key budget.
    #[serde(default)]
    pub budget: Option<KeyBudget>,
    /// The key's priority class under load. Present and `null` puts the key
    /// back on its workspace's class; absent leaves it unchanged.
    #[serde(default, deserialize_with = "crate::routes::double_option::deserialize")]
    pub qos_class_id: Option<Option<Uuid>>,
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct ListKeysQuery {
    /// Filter by owning principal (user or service account).
    pub user_id: Option<Uuid>,
    /// Filter by workspace. `null` returns keys across all workspaces.
    pub workspace_id: Option<Uuid>,
    /// `all` (default) | `gateway` (sk-/vk-) | `automation` (ak-, both control
    /// planes).
    pub plane: Option<String>,
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/keys",
    tag = "API Keys",
    request_body = CreateKeyRequest,
    responses(
        (status = 201, description = "API key created (plaintext returned once)", body = CreateKeyResponse),
        (status = 400, description = "Bad request", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn create_key(
    State(state): State<Arc<AdminState>>,
    mut db: TenantConn,
    Json(req): Json<CreateKeyRequest>,
) -> Result<(StatusCode, Json<CreateKeyResponse>), ApiError> {
    if req.name.trim().is_empty() {
        return Err(ApiError::bad_request("key name is required").code(ApiErrorCode::ValidationFailed));
    }
    // The SYSTEM tenant runs no workloads: no gateway keys there, ever (its only
    // key shape is the Operator ak-, minted via /service-accounts).
    if db.tenant_id() == crate::db::tenant::TenantId::SYSTEM {
        return Err(ApiError::bad_request("the SYSTEM tenant mints no gateway keys")
            .code(ApiErrorCode::ValidationFailed));
    }
    let id = Uuid::new_v4();
    let forward_auth = req.forward_auth;

    // The workspace must exist in this tenant (RLS scopes the lookup).
    let workspace_exists: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workspaces WHERE id = $1)",
    )
    .bind(req.workspace_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create key validate workspace: {e}");
        ApiError::internal("failed to validate workspace")
    })?;
    if !workspace_exists {
        return Err(ApiError::bad_request("workspace not found")
            .code(ApiErrorCode::WorkspaceNotFound));
    }

    // The user must be a member of the workspace — keys bill against the
    // workspace budget and a non-member must not mint one.
    let is_member: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM workspace_members WHERE workspace_id = $1 AND user_id = $2)",
    )
    .bind(req.workspace_id)
    .bind(req.user_id)
    .fetch_one(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("create key validate membership: {e}");
        ApiError::internal("failed to validate membership")
    })?;
    if !is_member {
        return Err(ApiError::bad_request("user is not a member of the workspace")
            .code(ApiErrorCode::WorkspaceMembershipRequired));
    }

    // BYOK binding (optional): a forward-auth (`vk-`) key MAY bind to one BYOK
    // downstream to get LLM pass-through. It's optional because a `vk-` key is
    // also valid for MCP bring-your-own-token (no LLM downstream). Validate the
    // binding when supplied. (LLM provisioning enforces a binding at render time.)
    let bound_downstream_id = if forward_auth { req.downstream_provider_id } else { None };
    if let Some(dp) = bound_downstream_id {
        let ok: bool = crate::routes::byok_downstream_bindable(db.conn(), dp, req.workspace_id)
        .await
        .map_err(|e| {
            tracing::error!("create key validate byok downstream: {e}");
            ApiError::internal("failed to validate BYOK downstream")
        })?;
        if !ok {
            return Err(crate::routes::byok_binding_refused());
        }
    }

    let plaintext_key = if forward_auth { generate_forward_key() } else { generate_virtual_key() };
    let key_hash = hash_key(&plaintext_key);
    let key_prefix = &plaintext_key[..plaintext_key.len().min(12)];
    let now = chrono::Utc::now();

    let (daily_budget, monthly_budget, budget_mode) = match &req.budget {
        Some(b) => (
            b.daily_budget,
            b.monthly_budget,
            crate::routes::workspaces::norm_budget_mode(&b.budget_mode),
        ),
        None => (None, None, crate::routes::workspaces::default_budget_mode()),
    };

    // The console is the tenant admin's surface, so a class above the workspace
    // is allowed here and recorded as an elevation.
    let (qos_class_id, qos_class_elevated) = crate::routes::qos_classes::resolve_key_class(
        db.conn(),
        req.workspace_id,
        req.qos_class_id,
        crate::routes::qos_classes::ClassAuthority::TenantAdmin,
    )
    .await?;

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, workspace_id, user_id, key_hash, key_prefix, name, forward_auth, expires_at, created_at, daily_budget, monthly_budget, budget_mode, downstream_provider_id, qos_class_id, qos_class_elevated) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16)",
    )
    .bind(id)
    .bind(db.tenant_uuid())
    .bind(req.workspace_id)
    .bind(req.user_id)
    .bind(&key_hash)
    .bind(key_prefix)
    .bind(&req.name)
    .bind(forward_auth)
    .bind(req.expires_at)
    .bind(now)
    .bind(daily_budget)
    .bind(monthly_budget)
    .bind(budget_mode)
    .bind(bound_downstream_id)
    .bind(qos_class_id)
    .bind(qos_class_elevated)
    .execute(db.conn())
    .await
    .map_err(|e| {
        if crate::routes::bound_passthrough_gone(&e) {
            return crate::routes::byok_binding_refused();
        }
        tracing::error!("create key: {e}");
        ApiError::internal("failed to create key")
    })?;


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
        Json(CreateKeyResponse {
            id,
            key: plaintext_key,
            name: Some(req.name),
            created_at: now,
            proxy_base_url,
        }),
    ))
}

/// Owner classification shared by both branches. `$AGENT` is replaced with a
/// bound parameter position by the query builders below.
fn owner_kind_sql(agent_param: &'static str) -> String {
    format!(
        "CASE WHEN u.auth_source = 'service' THEN \
              CASE WHEN u.email = {agent_param} THEN 'agent' ELSE 'service' END \
         ELSE 'user' END as owner_kind"
    )
}

/// Canonical gateway-key SELECT used by list/get/update. Joins the owning
/// workspace and principal so the UI can render both chips on each row. The
/// trailing parameter is the agent email (owner classification).
fn gateway_select_base(agent_param: &'static str) -> String {
    format!(
        r#"SELECT k.id, k.user_id,
        k.workspace_id, w.name as workspace_name,
        k.name,
        COALESCE(k.key_prefix, LEFT(k.key_hash, 8)) as key_prefix,
        CASE WHEN k.forward_auth THEN 'vk' ELSE 'sk' END as kind,
        NULL::text as admin_scope,
        {owner_kind},
        u.email as owner_email, u.display_name as owner_display_name,
        u.is_active as owner_is_active,
        k.created_at, k.expires_at, k.revoked_at, k.last_used_at,
        k.daily_budget, k.monthly_budget, k.budget_mode,
        k.qos_class_id, k.qos_class_elevated
    FROM api_keys k
    JOIN users u ON u.id = k.user_id
    JOIN workspaces w ON w.id = k.workspace_id"#,
        owner_kind = owner_kind_sql(agent_param),
    )
}

/// Automation-key (`ak-`) branch with the same column list — `ak_admin` rows
/// carry no workspace; `ak_portal` rows carry their bound workspace.
fn automation_select_base(agent_param: &'static str) -> String {
    format!(
        r#"SELECT k.id, k.service_account_id as user_id,
        k.workspace_id, w.name as workspace_name,
        k.name,
        COALESCE(k.key_prefix, LEFT(k.key_hash, 8)) as key_prefix,
        CASE WHEN k.plane = 'admin' THEN 'ak_admin' ELSE 'ak_portal' END as kind,
        k.admin_scope,
        {owner_kind},
        u.email as owner_email, u.display_name as owner_display_name,
        u.is_active as owner_is_active,
        k.created_at, k.expires_at, k.revoked_at, k.last_used_at,
        NULL::double precision as daily_budget,
        NULL::double precision as monthly_budget,
        NULL::text as budget_mode,
        NULL::uuid as qos_class_id,
        NULL::boolean as qos_class_elevated
    FROM automation_keys k
    JOIN users u ON u.id = k.service_account_id
    LEFT JOIN workspaces w ON w.id = k.workspace_id"#,
        owner_kind = owner_kind_sql(agent_param),
    )
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/keys",
    tag = "API Keys",
    params(ListKeysQuery),
    responses(
        (status = 200, description = "Paginated list of API keys", body = TotalPage<KeyListItem>),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn list_keys(
    mut db: TenantConn,
    Query(query): Query<ListKeysQuery>,
) -> Result<Json<TotalPage<KeyListItem>>, ApiError> {
    let page = PageQuery { limit: query.limit, offset: query.offset };
    let (limit, offset) = page.resolve();

    // Fail-closed on the plane filter: a typo must error, never silently widen
    // the result set to every plane.
    let plane = query.plane.as_deref().unwrap_or("all");
    if !matches!(plane, "all" | "gateway" | "automation") {
        return Err(ApiError::bad_request("plane must be all, gateway, or automation")
            .code(ApiErrorCode::ValidationFailed));
    }

    // NULL-tolerant owner/workspace filters keep one bind layout for every plane
    // combination: $1 owner, $2 workspace, $3 agent email, $4 limit, $5 offset.
    let gw_branch = format!(
        "{} WHERE ($1::uuid IS NULL OR k.user_id = $1) \
           AND ($2::uuid IS NULL OR k.workspace_id = $2)",
        gateway_select_base("$3"),
    );
    let ak_branch = format!(
        "{} WHERE ($1::uuid IS NULL OR k.service_account_id = $1) \
           AND ($2::uuid IS NULL OR k.workspace_id = $2)",
        automation_select_base("$3"),
    );
    let union_sql = match plane {
        "gateway" => gw_branch,
        "automation" => ak_branch,
        _ => format!("{gw_branch} UNION ALL {ak_branch}"),
    };
    // The count never needs the users/workspaces joins (inner joins on FKs don't
    // change the row count) — count each table bare so it stays index-cheap.
    let gw_count = "(SELECT COUNT(*) FROM api_keys k \
         WHERE ($1::uuid IS NULL OR k.user_id = $1) \
           AND ($2::uuid IS NULL OR k.workspace_id = $2))";
    let ak_count = "(SELECT COUNT(*) FROM automation_keys k \
         WHERE ($1::uuid IS NULL OR k.service_account_id = $1) \
           AND ($2::uuid IS NULL OR k.workspace_id = $2))";
    let count_sql = match plane {
        "gateway" => format!("SELECT {gw_count}"),
        "automation" => format!("SELECT {ak_count}"),
        _ => format!("SELECT {gw_count} + {ak_count}"),
    };
    let list_sql =
        format!("SELECT * FROM ({union_sql}) x ORDER BY x.created_at DESC LIMIT $4 OFFSET $5");

    let total: i64 = sqlx::query_scalar(sqlx::AssertSqlSafe(&*count_sql))
        .bind(query.user_id)
        .bind(query.workspace_id)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("count keys: {e}");
            ApiError::internal("failed to list keys")
        })?;

    let mut rows = sqlx::query_as::<_, KeyListItem>(sqlx::AssertSqlSafe(&*list_sql))
        .bind(query.user_id)
        .bind(query.workspace_id)
        .bind(crate::agent::AGENT_EMAIL)
        .bind(limit)
        .bind(offset)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("list keys: {e}");
            ApiError::internal("failed to list keys")
        })?;

    // Fill current per-key spend, in the tenant's accounting currency, so a
    // budgeted key shows spend-vs-cap.
    let tenant = db.tenant_uuid();
    let spend = crate::routes::analytics::current_budget_spend(db.conn(), tenant, "key")
        .await
        .unwrap_or_default();
    for r in &mut rows {
        if let Some((daily, monthly)) = spend.get(&r.id) {
            r.daily_spent = *daily;
            r.monthly_spent = *monthly;
        }
    }

    Ok(Json(TotalPage::new(rows, limit, offset, total)))
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/keys/{id}",
    tag = "API Keys",
    params(("id" = Uuid, Path, description = "API key ID")),
    responses(
        (status = 200, description = "Key details", body = KeyListItem),
        (status = 404, description = "Key not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_key(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<KeyListItem>, ApiError> {
    // Every id the unified list returns must resolve here — union both tables.
    let sql = format!(
        "SELECT * FROM ({} WHERE k.id = $1 UNION ALL {} WHERE k.id = $1) x",
        gateway_select_base("$2"),
        automation_select_base("$2"),
    );
    let row = sqlx::query_as::<_, KeyListItem>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(crate::agent::AGENT_EMAIL)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("get key: {e}");
            ApiError::internal("failed to get key")
        })?
        .ok_or_else(|| ApiError::not_found("key not found", ApiErrorCode::KeyNotFound))?;

    Ok(Json(row))
}

#[utoipa::path(
    patch,
    path = "/api/v1/admin/keys/{id}",
    tag = "API Keys",
    params(("id" = Uuid, Path, description = "API key ID")),
    request_body = UpdateKeyRequest,
    responses(
        (status = 200, description = "Key updated", body = KeyListItem),
        (status = 404, description = "Key not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_key(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Json(req): Json<UpdateKeyRequest>,
) -> Result<Json<KeyListItem>, ApiError> {
    // Update name and/or expires_at and/or the budget triple. The budget is
    // replaced as a group only when `req.budget` is present (null caps clear it),
    // so a rename-only PATCH never clobbers an existing budget.
    let budget_provided = req.budget.is_some();
    let (daily_budget, monthly_budget, budget_mode) = match &req.budget {
        Some(b) => (
            b.daily_budget,
            b.monthly_budget,
            crate::routes::workspaces::norm_budget_mode(&b.budget_mode),
        ),
        None => (None, None, crate::routes::workspaces::default_budget_mode()),
    };
    // A class edit needs the key's workspace: the rule is about the class's rank
    // against that workspace's, not against the tenant.
    let (qos_class_id, qos_class_elevated) = match req.qos_class_id {
        None => (None, false),
        Some(requested) => {
            let workspace_id: Option<Uuid> =
                sqlx::query_scalar("SELECT workspace_id FROM api_keys WHERE id = $1")
                    .bind(id)
                    .fetch_optional(db.conn())
                    .await
                    .map_err(|e| {
                        tracing::error!("load key workspace: {e}");
                        ApiError::internal("failed to update key")
                    })?;
            let Some(workspace_id) = workspace_id else {
                return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
            };
            crate::routes::qos_classes::resolve_key_class(
                db.conn(),
                workspace_id,
                requested,
                crate::routes::qos_classes::ClassAuthority::TenantAdmin,
            )
            .await?
        }
    };

    let result = sqlx::query(
        r#"UPDATE api_keys SET
            name = CASE WHEN $12 THEN $2 ELSE name END,
            expires_at = CASE WHEN $3 THEN $4 ELSE expires_at END,
            daily_budget = CASE WHEN $5 THEN $6 ELSE daily_budget END,
            monthly_budget = CASE WHEN $5 THEN $7 ELSE monthly_budget END,
            budget_mode = CASE WHEN $5 THEN $8 ELSE budget_mode END,
            qos_class_id = CASE WHEN $9 THEN $10 ELSE qos_class_id END,
            qos_class_elevated = CASE WHEN $9 THEN $11 ELSE qos_class_elevated END
        WHERE id = $1"#,
    )
    .bind(id)
    .bind(req.name.as_ref().and_then(|n| n.as_deref()))
    .bind(req.expires_at.is_some()) // flag: was expires_at provided?
    .bind(req.expires_at.flatten())
    .bind(budget_provided)
    .bind(daily_budget)
    .bind(monthly_budget)
    .bind(budget_mode)
    .bind(req.qos_class_id.is_some())
    .bind(qos_class_id)
    .bind(qos_class_elevated)
    .bind(req.name.is_some()) // $12
    .execute(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("update key: {e}");
        ApiError::internal("failed to update key")
    })?;

    if result.rows_affected() == 0 {
        // Automation keys appear in the same inventory but are immutable here —
        // say so instead of a misleading 404.
        let is_automation: bool =
            sqlx::query_scalar("SELECT EXISTS(SELECT 1 FROM automation_keys WHERE id = $1)")
                .bind(id)
                .fetch_one(db.conn())
                .await
                .unwrap_or(false);
        if is_automation {
            return Err(ApiError::bad_request(
                "automation keys have no editable fields — rotate or revoke instead",
            )
            .code(ApiErrorCode::ValidationFailed));
        }
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }


    let sql = format!("{} WHERE k.id = $1", gateway_select_base("$2"));
    let row = sqlx::query_as::<_, KeyListItem>(sqlx::AssertSqlSafe(&*sql))
        .bind(id)
        .bind(crate::agent::AGENT_EMAIL)
        .fetch_one(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("update key fetch: {e}");
            ApiError::internal("failed to fetch updated key")
        })?;

    Ok(Json(row))
}

#[derive(Deserialize, IntoParams)]
#[into_params(parameter_in = Query)]
pub struct KeyUsageQuery {
    /// Rolling lookback in days. Mutually exclusive with `start`/`end`.
    pub days: Option<i32>,
    /// Inclusive window start (RFC3339). Mutually exclusive with `days`.
    pub start: Option<DateTime<Utc>>,
    /// Exclusive window end (RFC3339).
    pub end: Option<DateTime<Utc>>,
}

impl KeyUsageQuery {
    fn time_window(&self) -> TimeWindow {
        TimeWindow { days: self.days, start: self.start, end: self.end }
    }
}

#[derive(Serialize, ToSchema)]
pub struct KeyUsageSummary {
    pub total_requests: i64,
    pub total_prompt_tokens: i64,
    pub total_completion_tokens: i64,
    pub total_cache_creation_tokens: i64,
    pub total_cache_read_tokens: i64,
    pub total_reasoning_tokens: i64,
    /// What this key spent over the window, and in which currency. `null`
    /// when the window straddles a change of the tenant's accounting currency
    /// — the rows are then in different denominations and no single figure
    /// states them.
    pub spend: Option<super::SpendTotal>,
    pub avg_latency_ms: f64,
    pub last_used_at: Option<chrono::DateTime<chrono::Utc>>,
}

#[utoipa::path(
    get,
    path = "/api/v1/admin/keys/{id}/usage",
    tag = "API Keys",
    params(
        ("id" = Uuid, Path, description = "API key ID"),
        KeyUsageQuery,
    ),
    responses(
        (status = 200, description = "Key usage summary", body = KeyUsageSummary),
        (status = 400, description = "Invalid time window", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_key_usage(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
    Query(params): Query<KeyUsageQuery>,
) -> Result<Json<KeyUsageSummary>, ApiError> {
    let window = params.time_window().resolve(DEFAULT_USAGE_DAYS)?;
    let row = crate::audit_store::usage::key_usage(db.conn(), id, window)
        .await
        .map_err(|e| {
            tracing::error!("failed to query key usage: {e}");
            ApiError::internal("failed to query key usage")
        })?;
    let spend = super::denominated_spend(db.conn(), row.currency_count, row.currency, row.amount).await;
    Ok(Json(KeyUsageSummary {
        total_requests: row.requests,
        total_prompt_tokens: row.prompt_tokens,
        total_completion_tokens: row.completion_tokens,
        total_cache_creation_tokens: row.cache_creation_tokens,
        total_cache_read_tokens: row.cache_read_tokens,
        total_reasoning_tokens: row.reasoning_tokens,
        spend,
        avg_latency_ms: row.avg_latency_ms,
        last_used_at: row.last_used_at,
    }))
}

#[utoipa::path(
    post,
    path = "/api/v1/admin/keys/{id}/actions/revoke",
    tag = "API Keys",
    responses(
        (status = 200, description = "Key revoked (row retained with revoked_at for audit linkage)", body = ActionResponse),
        (status = 404, description = "Key not found", body = ApiErrorResponse),
        (status = 401, description = "Unauthorized", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    params(("id" = Uuid, Path, description = "API key ID")),
    security(("bearer_auth" = []))
)]
pub async fn revoke_key(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ActionResponse>, ApiError> {
    // Revoke in database. The audit before/after diff — key metadata with the
    // hash redacted — is captured generically by the audit middleware.
    let revoked = sqlx::query("UPDATE api_keys SET revoked_at = NOW() WHERE id = $1")
        .bind(id)
        .execute(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("revoke key: {e}");
            ApiError::internal("failed to revoke key")
        })?
        .rows_affected();

    if revoked == 0 {
        return Err(ApiError::not_found("key not found", ApiErrorCode::KeyNotFound));
    }


    Ok(Json(ActionResponse::ok().with_message("Key revoked.")))
}
