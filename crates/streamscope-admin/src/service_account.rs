//! Service-account principal — the non-human identity that long-lived automation
//! keys hang off of.
//!
//! A service account is an ordinary `users` row marked `auth_source='service'`.
//! Because it is a real row with a real `user_id`, every `NOT NULL user_id`
//! column (audit, sessions) and every `INNER JOIN users` analytics query keeps
//! working unchanged — a non-human principal need not be a special case. It is
//! never a login identity (no password, not OIDC), so it survives employee
//! offboarding and tenant auth-mode switches: the API-key auth path gates only on
//! `is_active` + `revoked_at`, never `auth_mode`.
//!
//! Authority is NOT carried by the principal — it comes from the keys minted on
//! it (an `ak-` admin key's scope) and, for gateway keys, the account's workspace
//! membership/grants. A workspace is a DATA-PLANE concept: an admin-only service
//! account needs none. Membership is added lazily, only when a gateway key is
//! minted in a workspace (see `ensure_workspace_membership`). The built-in agent
//! (`agent@streamscope.internal`) is the canonical instance; its provider-wildcard
//! + `source='agent'` behaviour stays keyed off the agent email constant.

use uuid::Uuid;
use crate::db::tenant::Scoped;

/// The `auth_source` marker that identifies a non-human service-account `users`
/// row. Kept distinct from `'oidc'`/`'header'`/NULL human provenance so human
/// surfaces can filter it out and the OIDC upsert can leave it sticky.
pub const SERVICE_AUTH_SOURCE: &str = "service";

/// The built-in Inline AI service account — the principal external content
/// analyzers (a gateway's in-line AI-traffic inspection calling
/// `POST /v1/analyze`) authenticate as. Provisioned per tenant beside the
/// Inline AI workspace with a managed key, exactly like the agent
/// (`provision_inline_ai_for_tenant`); guarded against deletion like the agent
/// account.
pub const INLINE_AI_EMAIL: &str = "inline-ai@streamscope.internal";

/// Lowercase, collapse non-alphanumeric runs to a single `-`, trim, cap length —
/// the local part of an auto-derived service-account email. Shared by the admin
/// and portal automation surfaces.
pub fn slugify(s: &str) -> String {
    let mut out = String::new();
    let mut prev_dash = false;
    for c in s.chars() {
        if c.is_ascii_alphanumeric() {
            out.push(c.to_ascii_lowercase());
            prev_dash = false;
        } else if !prev_dash && !out.is_empty() {
            out.push('-');
            prev_dash = true;
        }
    }
    out.trim_matches('-').chars().take(40).collect()
}

/// Create a service-account `users` row. No workspace — a service account is a
/// tenant-level principal; workspace membership is a data-plane concern added
/// only when a gateway key is minted.
///
/// Create-only: an address some row already holds — another service account or
/// a human — fails with the unique violation (SQLSTATE 23505), which callers map
/// to 409 `user_email_taken`. It never answers with the existing row's id: a
/// create that lost a race would otherwise hand the caller someone else's
/// principal (and the portal path would make it a workspace manager).
///
/// Runs on a tenant-scoped connection (RLS confines reads/writes to `tenant_id`),
/// but binds `tenant_id` explicitly since column DEFAULTs are unsafe for
/// non-SYSTEM tenants. Returns the service account's `user_id`.
pub async fn create_service_account(
    conn: &mut Scoped,
    tenant_id: Uuid,
    email: &str,
    display_name: &str,
) -> Result<Uuid, sqlx::Error> {
    let id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, display_name, auth_source, is_active) \
         VALUES ($1, $2, $3, $4, $5, true)",
    )
    .bind(id)
    .bind(tenant_id)
    .bind(email)
    .bind(display_name)
    .bind(SERVICE_AUTH_SOURCE)
    .execute(&mut *conn)
    .await?;
    Ok(id)
}

/// Ensure a platform-owned service account exists at `email`, creating it on
/// first call and leaving any existing row untouched. For the reserved
/// addresses the platform provisions on every pass (the inline-AI account),
/// never for an operator-chosen address — that goes through
/// [`create_service_account`], which refuses a taken one.
pub async fn ensure_service_account(
    conn: &mut Scoped,
    tenant_id: Uuid,
    email: &str,
    display_name: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO users (id, tenant_id, email, display_name, auth_source, is_active) \
         VALUES ($1, $2, $3, $4, $5, true) \
         ON CONFLICT (tenant_id, email) DO NOTHING",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(email)
    .bind(display_name)
    .bind(SERVICE_AUTH_SOURCE)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Ensure the service account is a member of `workspace_id` — required before a
/// gateway key can bind to that workspace (budgets/allowlists bill against it).
/// Idempotent. Adds as a plain `member`.
pub async fn ensure_workspace_membership(
    conn: &mut Scoped,
    tenant_id: Uuid,
    user_id: Uuid,
    workspace_id: Uuid,
) -> Result<(), sqlx::Error> {
    ensure_workspace_membership_role(conn, tenant_id, user_id, workspace_id, "member").await
}

/// Ensure the service account is a member of `workspace_id` with the given
/// `role` (`member` | `manager`). Idempotent; upgrades the role on conflict so a
/// portal automation account always reaches `manager`. Used when a workspace
/// manager provisions a portal automation account that must carry manager
/// authority over exactly that one workspace.
pub async fn ensure_workspace_membership_role(
    conn: &mut Scoped,
    tenant_id: Uuid,
    user_id: Uuid,
    workspace_id: Uuid,
    role: &str,
) -> Result<(), sqlx::Error> {
    // Upgrade-only on conflict: a `manager` is never silently downgraded to
    // `member` (e.g. when a gateway key is later minted for an SA that already
    // manages the workspace). Only an explicit promotion to `manager` updates.
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, tenant_id, role) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (tenant_id, workspace_id, user_id) DO UPDATE SET role = EXCLUDED.role \
            WHERE workspace_members.role <> 'manager' AND EXCLUDED.role = 'manager'",
    )
    .bind(workspace_id)
    .bind(user_id)
    .bind(tenant_id)
    .bind(role)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
