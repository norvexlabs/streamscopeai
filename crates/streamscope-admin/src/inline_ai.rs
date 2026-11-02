//! Inline AI provisioning — the built-in service account + managed key an
//! external content analyzer (a gateway's in-line AI-traffic
//! inspection) presents to the proxy.
//!
//! Mirrors the agent's provisioning (`crate::agent`): a non-human `users` row
//! (`auth_source='service'`, [`INLINE_AI_EMAIL`]), one managed key named
//! `inline-ai-key` bound to the per-tenant **Inline AI** workspace
//! (`role = 'inline'`), plaintext encrypted at rest in `system_settings`
//! under `inline_ai_api_key`. The one divergence from the agent is who reads
//! the plaintext: the agent consumes its own key internally, while the
//! inline-AI key is handed to the OPERATOR (the rotate route re-provisions and
//! returns the fresh key once) to configure the external analyzer.
//!
//! The inline key is a forward (BYOK) key (`forward_auth = true`), usable on
//! both `/fwd/{key}/…` — multi-provider BYOK pass-through to the endpoints of
//! its workspace's granted built-in downstreams (Anthropic / OpenAI / Gemini),
//! funded by the client's own forwarded credential — and `POST /v1/analyze`
//! (scoped by the baked `inline_ai` flag on its `UserContext`). Its workspace's
//! guardrail / tool / transform profiles are the inline enforcement policy.

use crate::db::tenant::Scoped;
use crate::service_account::INLINE_AI_EMAIL;

/// Provision the inline-AI service account + managed key for a single tenant
/// (called at tenant creation and from the startup seed sync — idempotent).
/// Returns whether provisioning is complete for this tenant. The startup seed
/// reconcile folds this into the tenant's seed stamp, so an incomplete pass is
/// retried on the next boot rather than skipped until the next release.
pub async fn provision_inline_ai_for_tenant(
    pool: &crate::db::Db,
    tenant_id: crate::db::tenant::TenantId,
) -> bool {
    use crate::db::tenant::TenantConn;

    match TenantConn::acquire(pool, tenant_id).await {
        Ok(mut db) => {
            // No inline-AI workloads in the SYSTEM platform tenant — nothing to
            // provision, so this is complete, not a failure.
            if db.tenant_uuid() == crate::db::tenant::TenantId::SYSTEM.as_uuid() {
                return true;
            }
            provision_inline_ai_for_conn(db.tenant_uuid(), db.conn()).await
        }
        Err(e) => {
            tracing::error!(%tenant_id, "provision_inline_ai_for_tenant TenantConn acquire: {e}");
            false
        }
    }
}

/// Inner helper: idempotently create the inline-AI service account on a scoped
/// connection, then ensure its managed key. Returns whether both landed.
async fn provision_inline_ai_for_conn(tenant_id: uuid::Uuid, conn: &mut Scoped) -> bool {
    if let Err(e) = crate::service_account::ensure_service_account(
        &mut *conn,
        tenant_id,
        INLINE_AI_EMAIL,
        "Inline AI",
    )
    .await
    {
        tracing::error!(%tenant_id, "failed to create inline-ai service account: {e}");
        return false;
    }

    // Ensure the managed key exists in the Inline AI workspace. No-ops when a
    // key with a stored plaintext is already present; a missing Inline AI
    // workspace (pre-seed) is logged and retried on the next provisioning pass.
    if let Err(e) = provision_inline_ai_key(conn).await {
        tracing::warn!(%tenant_id, "provision inline-ai key: {e}");
        return false;
    }
    true
}

/// Create the inline-AI API key, bound to the tenant's Inline AI workspace.
/// Mirrors `provision_agent_key`, but mints a forward (BYOK) key
/// (`forward_auth = true`) so it doubles as the `/fwd/` pass-through credential.
///
/// Takes a tenant-scoped `&mut Scoped` so RLS confines the read.
///
/// - If no key exists: generates one and stores the encrypted plaintext in
///   `system_settings` (`inline_ai_api_key`).
/// - If a key exists with its plaintext present: no-op.
/// - If a key exists but the plaintext is missing: revokes it and recreates.
pub async fn provision_inline_ai_key(conn: &mut Scoped) -> Result<(), String> {
    // Find the inline-AI service account.
    let Some((user_id,)): Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM users WHERE email = $1")
            .bind(INLINE_AI_EMAIL)
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| format!("db error: {e}"))?
    else {
        return Err("inline-ai user not found — restart admin service".into());
    };

    // tenant_id is set on the connection via RLS, but we bind it explicitly
    // since column DEFAULTs are unsafe for non-SYSTEM tenants.
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT current_tenant_id()")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("get tenant_id: {e}"))?;

    // Resolve the tenant's Inline AI workspace to bind the key. Its granted
    // built-in BYOK downstreams are the key's `/fwd/` pass-through targets.
    let Some((workspace_id,)): Option<(uuid::Uuid,)> =
        sqlx::query_as("SELECT id FROM workspaces WHERE role = 'inline'")
            .fetch_optional(&mut *conn)
            .await
            .map_err(|e| format!("db error: {e}"))?
    else {
        return Err("inline-ai workspace not found — restart admin service".into());
    };

    // Ensure the service account belongs to the workspace (keys can only be
    // minted for members).
    sqlx::query(
        "INSERT INTO workspace_members (workspace_id, user_id, tenant_id, role) \
         VALUES ($1, $2, $3, 'member') ON CONFLICT (tenant_id, workspace_id, user_id) DO NOTHING",
    )
    .bind(workspace_id)
    .bind(user_id)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("add inline-ai to inline-ai workspace: {e}"))?;

    // Check for an existing managed key.
    let existing: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM api_keys WHERE user_id = $1 AND name = 'inline-ai-key' AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    if let Some((key_id,)) = existing {
        // Key present — keep it iff its plaintext is still stored.
        let stored: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT value FROM system_settings WHERE key = 'inline_ai_api_key'",
        )
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| format!("db error: {e}"))?;

        if stored
            .as_ref()
            .and_then(|(v,)| v.as_str())
            .is_some_and(|s| !s.is_empty())
        {
            let _ = key_id;
            return Ok(());
        }

        // Plaintext missing — revoke and recreate.
        sqlx::query("UPDATE api_keys SET revoked_at = now() WHERE id = $1")
            .bind(key_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("revoke old key: {e}"))?;
        tracing::warn!("inline-ai key plaintext missing in system_settings — recreating");
    }

    // Generate new key.
    let virtual_key = streamscope_core::auth::virtual_key::generate_forward_key();
    let key_hash = streamscope_core::auth::virtual_key::hash_key(&virtual_key);
    let key_prefix = &virtual_key[..std::cmp::min(12, virtual_key.len())];

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, workspace_id, user_id, name, key_hash, key_prefix, forward_auth) \
         VALUES ($1, $2, $3, $4, $5, $6, $7, true)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(user_id)
    .bind("inline-ai-key")
    .bind(&key_hash)
    .bind(key_prefix)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("create inline-ai key: {e}"))?;

    // Encrypt before storing in system_settings (ENCRYPTION_KEY validated at
    // startup).
    let enc_key = streamscope_core::crypto::get_encryption_key()
        .expect("ENCRYPTION_KEY validated at startup");
    let encrypted = streamscope_core::crypto::encrypt(&virtual_key, &enc_key)
        .map_err(|e| format!("encrypt inline-ai key: {e}"))?;
    let stored_value = serde_json::json!(encrypted);

    sqlx::query(
        "INSERT INTO system_settings (key, value, tenant_id) VALUES ('inline_ai_api_key', $1, $2) \
         ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(stored_value)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("store inline-ai key: {e}"))?;

    tracing::info!(key_prefix = %key_prefix, workspace_id = %workspace_id, "provisioned inline-ai API key");
    Ok(())
}

/// Read + decrypt the stored inline-AI key plaintext for this tenant, for the
/// operator-facing reveal (the rotate route). `None` when absent/undecryptable.
pub async fn stored_inline_ai_key(conn: &mut Scoped) -> Option<String> {
    let stored: Option<(serde_json::Value,)> =
        sqlx::query_as("SELECT value FROM system_settings WHERE key = 'inline_ai_api_key'")
            .fetch_optional(&mut *conn)
            .await
            .ok()
            .flatten();
    let raw = stored?.0.as_str()?.to_string();
    let enc_key = streamscope_core::crypto::get_encryption_key()?;
    streamscope_core::crypto::decrypt(&raw, &enc_key).ok()
}
