//! Key lifecycle helpers — impact checks for destructive endpoints.
//!
//! Used by delete-user to preview impact (`dry_run=true`). Keys are bound to a
//! `(user, workspace)` pair and gated per request by the workspace allowlist,
//! so changing a workspace's providers/MCP servers never orphans a key. Two
//! deletes end keys: the owning user's, and a provider's — a BYOK `vk-` key
//! bound to it is revoked with it ([`revoke_keys_bound_to`]).

use serde::Serialize;
use utoipa::{IntoParams, ToSchema};
use uuid::Uuid;
use crate::db::tenant::Scoped;

/// Returned on `?dry_run=true` — preview of how many users/keys are affected.
#[derive(Serialize, ToSchema)]
pub struct ImpactCheck {
    pub affected_users: i64,
    pub affected_keys: i64,
}

/// Returned after a destructive operation — how many keys were revoked.
#[derive(Serialize, ToSchema)]
pub struct MutationResult {
    pub revoked_keys: i64,
}

/// Unified response for destructive endpoints.
/// Dry-run returns `dry_run: true` with impact preview.
/// Execute returns `dry_run: false` with mutation result.
#[derive(Serialize, ToSchema)]
pub struct DeletionResponse {
    pub dry_run: bool,
    pub affected_keys: i64,
    pub affected_users: i64,
    /// Live OAuth grants the deletion ends — MCP client authorizations and
    /// signed-in CLI machines. Distinct from `affected_keys`, which counts
    /// `sk-` keys: a user can hold none of one and several of the other, and a
    /// preview that mentioned only keys read as "nothing else to lose".
    #[serde(default)]
    pub affected_oauth_sessions: i64,
}

/// The OpenAPI shape of [`crate::middleware::DryRun`]'s query, for a route's
/// `params(...)`. It does not deserialize: a handler reads the flag only
/// through `DryRun`, which marks the audit row.
#[derive(IntoParams)]
#[into_params(parameter_in = Query)]
pub struct DryRunQuery {
    /// When true, return impact preview without mutating.
    #[allow(dead_code, reason = "documentation only; `DryRun` parses the flag")]
    pub dry_run: Option<bool>,
}

/// The keys bound to provider `provider_id` that are not revoked — a BYOK
/// `vk-` key's pass-through. What [`revoke_keys_bound_to`] revokes.
pub async fn count_keys_bound_to(conn: &mut Scoped, provider_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query_scalar(concat!("SELECT ", bound_keys_sql!("$1", "")))
    .bind(provider_id)
    .fetch_one(&mut *conn)
    .await
}

/// Revoke every key bound to provider `provider_id`, before the provider is
/// deleted. Never leave one unbound: the FK would null its binding, and an
/// unbound forward-auth key passes through to EVERY pass-through its workspace
/// is granted — a delete would widen the key instead of ending it. Returns how
/// many were revoked.
///
/// Call it inside the transaction that deletes the provider. It locks the
/// provider row first: a key minted meanwhile takes a share lock on that row
/// through its foreign key, so it either committed before (and is revoked here)
/// or waits for the delete and then fails on the missing provider — never
/// slips in between to be unbound by the delete.
pub async fn revoke_keys_bound_to(conn: &mut Scoped, provider_id: Uuid) -> Result<i64, sqlx::Error> {
    sqlx::query("SELECT 1 FROM downstream_providers WHERE id = $1 FOR UPDATE")
        .bind(provider_id)
        .fetch_optional(&mut *conn)
        .await?;
    let done = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() WHERE downstream_provider_id = $1 AND revoked_at IS NULL",
    )
    .bind(provider_id)
    .execute(&mut *conn)
    .await?;
    Ok(i64::try_from(done.rows_affected()).unwrap_or(i64::MAX))
}

/// Count active keys for a user.
pub async fn count_keys_for_user(
    conn: &mut Scoped,
    user_id: Uuid,
) -> Result<ImpactCheck, sqlx::Error> {
    let count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM api_keys WHERE user_id = $1 AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_one(conn)
    .await?;

    Ok(ImpactCheck {
        affected_users: if count > 0 { 1 } else { 0 },
        affected_keys: count,
    })
}

