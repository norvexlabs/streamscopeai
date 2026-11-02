//! Per-profile expert membership — which agent experts a `kind='expert'` profile
//! enables. This is the CONTENT adapter for the expert profile domain.
//!
//! Default-as-base model: EVERY expert profile carries explicit
//! `expert_profile_members` rows, the editable DEFAULT included (seeded with all
//! enabled experts — the shared base). A Layered profile's effective set is the
//! Default's experts ∪ its own; a Standalone profile's is its own only; an Off
//! assignment runs none.
//!
//! Consumed admin-side by the analysis cycle (`agent::analysis`); never shipped
//! to the proxy, so mutations do **not** mark the tenant config dirty.

use axum::extract::Path;
use axum::Json;
use serde::{Deserialize, Serialize};
use utoipa::ToSchema;
use uuid::Uuid;

use super::{ApiError, ApiErrorCode, ApiErrorResponse};
use crate::db::tenant::{Scoped, TenantConn};

/// Response for `GET /api/v1/admin/profiles/{id}/expert`.
#[derive(Debug, Clone, Serialize, ToSchema)]
pub struct ExpertMembershipResponse {
    /// Expert ids enabled on this profile (its explicit membership rows). The
    /// Default is seeded with all enabled experts but is editable like any profile.
    pub expert_ids: Vec<Uuid>,
    /// True for the tenant default expert profile (the shared base). Drives the
    /// UI's "Reset to seed" affordance; no longer implies read-only.
    pub is_default: bool,
}

/// Body for `PUT /api/v1/admin/profiles/{id}/expert`. Full replace: the listed
/// experts become the profile's exact member set.
#[derive(Debug, Clone, Default, Deserialize, ToSchema)]
pub struct UpdateExpertMembershipRequest {
    pub expert_ids: Vec<Uuid>,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

#[utoipa::path(
    get,
    path = "/api/v1/admin/profiles/{id}/expert",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Expert profile id")),
    responses(
        (status = 200, description = "Profile expert membership", body = ExpertMembershipResponse),
        (status = 404, description = "Profile not found / not an expert profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn get_profile_expert_membership(
    mut db: TenantConn,
    Path(id): Path<Uuid>,
) -> Result<Json<ExpertMembershipResponse>, ApiError> {
    let is_default = ensure_expert_profile(db.conn(), id).await?;
    let expert_ids = effective_member_ids(db.conn(), id).await?;
    Ok(Json(ExpertMembershipResponse { expert_ids, is_default }))
}

#[utoipa::path(
    put,
    path = "/api/v1/admin/profiles/{id}/expert",
    tag = "Profiles",
    params(("id" = Uuid, Path, description = "Expert profile id")),
    request_body = UpdateExpertMembershipRequest,
    responses(
        (status = 200, description = "Updated membership", body = ExpertMembershipResponse),
        (status = 400, description = "Unknown expert id", body = ApiErrorResponse),
        (status = 404, description = "Profile not found / not an expert profile", body = ApiErrorResponse),
        (status = 500, description = "Internal server error", body = ApiErrorResponse),
    ),
    security(("bearer_auth" = []))
)]
pub async fn update_profile_expert_membership(
    mut db: TenantConn,
    axum::Extension(audit_sink): axum::Extension<crate::middleware::AuditDiffSink>,
    Path(id): Path<Uuid>,
    Json(body): Json<UpdateExpertMembershipRequest>,
) -> Result<Json<ExpertMembershipResponse>, ApiError> {
    let tenant_id = db.tenant_uuid();
    // Every expert profile is editable, the Default included (it is the shared
    // base whose membership a Layered profile inherits). `ensure_expert_profile`
    // still validates kind/tenant.
    let is_default = ensure_expert_profile(db.conn(), id).await?;

    // Dedup the requested set and validate every id is an expert in this tenant
    // (RLS scopes `agent_experts`, so this also rejects cross-tenant ids).
    let mut unique: Vec<Uuid> = body.expert_ids.clone();
    unique.sort_unstable();
    unique.dedup();
    let valid: Vec<Uuid> = sqlx::query_scalar("SELECT id FROM agent_experts WHERE id = ANY($1) AND NOT suppressed")
        .bind(&unique)
        .fetch_all(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("validate expert ids: {e}");
            ApiError::internal("failed to validate experts")
        })?;
    if valid.len() != unique.len() {
        return Err(ApiError::bad_request("one or more expert ids do not exist")
            .code(ApiErrorCode::ValidationFailed));
    }

    // Sorted to match the `unique` (UUID-sorted) after-set, so an unchanged save
    // produces an empty audit diff rather than a spurious reordering.
    let mut before = effective_member_ids(db.conn(), id).await?;
    before.sort_unstable();

    // Replace the member set atomically.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("update expert membership (begin): {e}");
        ApiError::internal("failed to update membership")
    })?;
    sqlx::query("DELETE FROM expert_profile_members WHERE profile_id = $1")
        .bind(id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("clear expert membership: {e}");
            ApiError::internal("failed to update membership")
        })?;
    if !unique.is_empty() {
        sqlx::query(
            "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
             SELECT $1, e, $3 FROM unnest($2::uuid[]) AS e",
        )
        .bind(id)
        .bind(&unique)
        .bind(tenant_id)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("insert expert membership: {e}");
            ApiError::internal("failed to update membership")
        })?;
    }
    tx.commit().await.map_err(|e| {
        tracing::error!("update expert membership (commit): {e}");
        ApiError::internal("failed to update membership")
    })?;

    audit_sink.record(Some(&before), Some(&unique));
    Ok(Json(ExpertMembershipResponse { expert_ids: unique, is_default }))
}

// ---------------------------------------------------------------------------
// Shared helpers (also the create/delete content adapters for `kind='expert'`)
// ---------------------------------------------------------------------------

/// Validate that `id` is an expert-kind profile in the current tenant; returns
/// whether it is the tenant default.
async fn ensure_expert_profile(conn: &mut Scoped, id: Uuid) -> Result<bool, ApiError> {
    let row: Option<(String, bool)> =
        sqlx::query_as("SELECT kind, is_default FROM profiles WHERE id = $1")
            .bind(id)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| {
                tracing::error!("validate expert profile: {e}");
                ApiError::internal("failed to validate profile")
            })?;
    match row {
        Some((kind, is_default)) if kind == "expert" => Ok(is_default),
        _ => Err(ApiError::not_found("expert profile not found", ApiErrorCode::ProfileNotFound)),
    }
}

/// The profile's member ids — its explicit `expert_profile_members` rows (every
/// expert profile, the Default included, carries explicit rows). Suppressed
/// experts are filtered out.
async fn effective_member_ids(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<Vec<Uuid>, ApiError> {
    sqlx::query_scalar::<_, Uuid>(
        "SELECT e.id FROM expert_profile_members m \
         JOIN agent_experts e ON e.id = m.expert_id AND NOT e.suppressed \
         WHERE m.profile_id = $1 ORDER BY e.axis",
    )
    .bind(id)
    .fetch_all(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("load expert membership: {e}");
        ApiError::internal("failed to load membership")
    })
}

/// Copy a source expert profile's explicit members onto a freshly-created profile
/// (the per-kind copy adapter). Returns the number of rows created.
pub(crate) async fn copy_members(
    conn: &mut Scoped,
    tenant_id: Uuid,
    source_id: Uuid,
    dest_id: Uuid,
) -> Result<i64, ApiError> {
    let res = sqlx::query(
        "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
         SELECT $1, expert_id, $3 FROM expert_profile_members WHERE profile_id = $2 \
         ON CONFLICT DO NOTHING",
    )
    .bind(dest_id)
    .bind(source_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("copy expert membership: {e}");
        ApiError::internal("failed to copy membership")
    })?;
    Ok(res.rows_affected() as i64)
}

/// Seed an expert profile's membership with all enabled experts (the "seed"
/// content adapter — used by reset-to-seed and create-from-seed). Replaces any
/// existing rows. Returns the number of members.
pub(crate) async fn apply_seed_members(
    conn: &mut Scoped,
    tenant_id: Uuid,
    profile_id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query("DELETE FROM expert_profile_members WHERE profile_id = $1")
        .bind(profile_id)
        .execute(&mut *conn)
        .await
        .map_err(|e| {
            tracing::error!("clear expert membership for seed: {e}");
            ApiError::internal("failed to seed membership")
        })?;
    let res = sqlx::query(
        "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
         SELECT $1, e.id, $2 FROM agent_experts e WHERE e.enabled = true AND NOT e.suppressed \
         ON CONFLICT DO NOTHING",
    )
    .bind(profile_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("seed expert membership: {e}");
        ApiError::internal("failed to seed membership")
    })?;
    Ok(res.rows_affected() as i64)
}

/// Count of a profile's explicit members — for list/detail `rule_count`.
pub(crate) async fn member_count(
    conn: &mut Scoped,
    id: Uuid,
) -> Result<i64, ApiError> {
    sqlx::query_scalar::<_, i64>(
        "SELECT count(*) FROM expert_profile_members m \
         JOIN agent_experts e ON e.id = m.expert_id AND NOT e.suppressed \
         WHERE m.profile_id = $1",
    )
    .bind(id)
    .fetch_one(&mut *conn)
    .await
    .map_err(|e| {
        tracing::error!("count expert membership: {e}");
        ApiError::internal("failed to count membership")
    })
}
