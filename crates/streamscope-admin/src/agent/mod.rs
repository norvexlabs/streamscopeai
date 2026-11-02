//! LLM Driver Agent — background service that analyzes session data through
//! expert lenses.
//!
//! Each cycle: fetches recent sessions via direct DB queries, runs each session
//! through relevant experts (security, compliance, cost, quality, anomaly, tool
//! policy), and produces three outputs: transform program suggestions (Rhai scripts),
//! per-session alerts (severity + note), and updated expert memory. Experts are
//! loaded from seed files and execute via LLM tool calling (`submit_analysis`).

mod analysis;
pub mod experts;
pub(crate) mod suggestion;

use std::sync::Arc;
use std::time::Duration;

use chrono::Timelike;

use crate::db::tenant::Scoped;
use crate::AdminState;
use crate::db::tenant::for_each_tenant;

/// Delay before the agent starts its first analysis cycle after startup.
const AGENT_STARTUP_DELAY: Duration = Duration::from_secs(30);
/// Poll interval when the agent is disabled, waiting for config change.
const AGENT_DISABLED_POLL: Duration = Duration::from_secs(60);

// Agent config defaults — shared with routes/settings.rs for UI defaults.
/// Built-in fallback judge model when the Default expert profile carries none
/// (the profile's `model` column is the authoritative per-tenant value).
pub const DEFAULT_AGENT_MODEL: &str = "gpt-4o";
pub const DEFAULT_AGENT_INTERVAL_SECS: u64 = 3600;
/// Floor for the global inter-cycle sleep. The single agent loop wakes at the
/// *most frequent* enabled tenant's configured interval; this floor stops a
/// misconfigured tiny value from busy-looping the worker. (The settings UI
/// already constrains the per-tenant interval to >= 60s.)
pub const AGENT_MIN_INTERVAL_SECS: u64 = 30;

/// Resolve the global inter-cycle sleep from the `fetch_min` accumulator. The
/// sentinel `u64::MAX` (no enabled tenant set an interval) falls back to the
/// default; otherwise the shortest configured interval wins, floored at
/// `AGENT_MIN_INTERVAL_SECS`.
fn resolve_interval_secs(min_raw: u64) -> u64 {
    match min_raw {
        u64::MAX => DEFAULT_AGENT_INTERVAL_SECS,
        secs => secs.max(AGENT_MIN_INTERVAL_SECS),
    }
}
pub const DEFAULT_AGENT_PROXY_URL: &str = "http://proxy:8080";
pub const DEFAULT_AGENT_SESSION_COOLDOWN_MINS: i64 = 30;
/// `tool_choice` for agent expert calls — always forced: a model that produces
/// only text fails loudly with an upstream 4xx instead of silently dropping
/// the analysis. A model that rejects forced tool choice is handled per call
/// by the `agent_analysis_call` auto-fallback, and an operator can relax it
/// per model via a model preset (native vocab, force-merged post-translation).
pub const AGENT_TOOL_CHOICE: &str = "required";

/// Agent service account email. Stamped onto `gateway_audit.source` /
/// `sessions.source` as `'agent'` at ingestion; the agent-traffic filter reads
/// that column rather than resolving this account per query.
pub const AGENT_EMAIL: &str = "agent@streamscope.internal";

/// Agent configuration — read from DB (system_settings) each cycle.
#[derive(Debug, Clone)]
pub struct AgentConfig {
    pub proxy_url: String,
    pub api_key: String,
    pub app_id: String,
    pub interval_secs: u64,
    /// Minutes of inactivity before a session is eligible for agent analysis.
    pub session_cooldown_mins: i64,
    /// Optional run-window restriction. When set, the agent only runs cycles
    /// whose current UTC hour is inside the window — outside, cycles skip
    /// with a log line. Lets operators reserve agent load for off-hours on
    /// shared on-premise LLMs.
    pub run_window: Option<RunWindow>,
}

/// A UTC-hour window during which the agent is allowed to run.
#[derive(Debug, Clone, Copy)]
pub struct RunWindow {
    pub start_hour_utc: u32,
    pub end_hour_utc: u32,
}

impl RunWindow {
    /// Returns true if `hour_utc` (0..=23) is inside `[start, end)`. When
    /// `start > end` the window wraps midnight; `start == end` is empty.
    pub fn contains(&self, hour_utc: u32) -> bool {
        if self.start_hour_utc == self.end_hour_utc {
            false
        } else if self.start_hour_utc < self.end_hour_utc {
            hour_utc >= self.start_hour_utc && hour_utc < self.end_hour_utc
        } else {
            hour_utc >= self.start_hour_utc || hour_utc < self.end_hour_utc
        }
    }
}


impl AgentConfig {
    /// Read agent config from system_settings using a tenant-scoped connection.
    /// Returns `None` if disabled.
    pub async fn from_conn(conn: &mut Scoped) -> Option<Self> {
        let rows: Vec<(String, serde_json::Value)> = sqlx::query_as(
            "SELECT key, value FROM system_settings WHERE key LIKE 'agent_%'",
        )
        .fetch_all(&mut *conn)
        .await
        .ok()?;

        let get = |key: &str| -> Option<String> {
            rows.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| {
                    v.as_str().map(|s| s.to_string())
                        .or_else(|| Some(v.to_string().trim_matches('"').to_string()))
                })
        };

        let get_bool = |key: &str| -> bool {
            rows.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_bool().or_else(|| v.as_str().map(|s| s == "true")))
                .unwrap_or(false)
        };

        if !get_bool("agent_enabled") {
            return None;
        }

        let raw_key = get("agent_api_key").unwrap_or_default();
        if raw_key.is_empty() {
            tracing::warn!("agent enabled but no API key available");
            return None;
        }

        // Decrypt agent key (encrypted at rest). Requires ENCRYPTION_KEY.
        let api_key = match streamscope_core::crypto::get_encryption_key() {
            Some(enc_key) => match streamscope_core::crypto::decrypt(&raw_key, &enc_key) {
                Ok(decrypted) => decrypted,
                Err(e) => {
                    tracing::error!("failed to decrypt agent API key: {e}");
                    return None;
                }
            },
            None => {
                tracing::error!("ENCRYPTION_KEY not set — cannot decrypt agent API key");
                return None;
            }
        };

        let get_i32 = |key: &str| -> Option<i32> {
            rows.iter()
                .find(|(k, _)| k == key)
                .and_then(|(_, v)| v.as_i64().or_else(|| v.as_str().and_then(|s| s.parse().ok())))
                .and_then(|n| i32::try_from(n).ok())
        };

        let run_window = if get_bool("agent_run_window_enabled") {
            let start = get_i32("agent_run_window_start_hour_utc").unwrap_or(22);
            let end = get_i32("agent_run_window_end_hour_utc").unwrap_or(6);
            if (0..24).contains(&start) && (0..24).contains(&end) {
                Some(RunWindow {
                    start_hour_utc: start as u32,
                    end_hour_utc: end as u32,
                })
            } else {
                tracing::warn!(
                    start, end,
                    "agent_run_window_(start|end)_hour_utc out of range [0,23]; treating as no window"
                );
                None
            }
        } else {
            None
        };

        Some(Self {
            proxy_url: get("agent_proxy_url")
                .unwrap_or_else(|| crate::settings::admin_settings().agent_proxy_url.clone()),
            api_key,
            app_id: "streamscope-agent".to_string(),
            interval_secs: get("agent_interval_secs")
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_AGENT_INTERVAL_SECS),
            session_cooldown_mins: get("agent_session_cooldown_mins")
                .and_then(|v| v.parse().ok())
                .unwrap_or(DEFAULT_AGENT_SESSION_COOLDOWN_MINS),
            run_window,
        })
    }
}

/// Idempotently create the agent service account and its API key for every
/// tenant. Skips the SYSTEM tenant (no workloads there).
///
/// The agent key is a single unified key bound to the tenant's **Agent**
/// workspace (`role = 'agent'`); it reaches only the providers granted to that
/// workspace, like any key (no wildcard). Key provisioning no-ops once a key with
/// a stored plaintext exists.
pub async fn provision_agent_account(pool: &crate::db::Db) {
    let _ = for_each_tenant(pool, |mut db| async move {
        // Skip SYSTEM tenant — no agent workloads in the platform tenant.
        if db.tenant_uuid() == crate::db::tenant::TenantId::SYSTEM.as_uuid() {
            return Ok(());
        }

        provision_agent_for_conn(db.tenant_uuid(), db.conn()).await;
        Ok(())
    }).await;
}

/// Provision agent service account for a single tenant (called at tenant creation).
///
/// Returns whether the account and its key are in place.
pub async fn provision_agent_for_tenant(pool: &crate::db::Db, tenant_id: crate::db::tenant::TenantId) -> bool {
    use crate::db::tenant::TenantConn;

    match TenantConn::acquire(pool, tenant_id).await {
        Ok(mut db) => provision_agent_for_conn(db.tenant_uuid(), db.conn()).await,
        Err(e) => {
            tracing::error!(%tenant_id, "provision_agent_for_tenant TenantConn acquire: {e}");
            false
        }
    }
}

/// Inner helper: idempotently create agent service account on a scoped connection.
///
/// Returns whether the account and its key are in place.
async fn provision_agent_for_conn(tenant_id: uuid::Uuid, conn: &mut Scoped) -> bool {
    let agent_email = AGENT_EMAIL;

    // Check if agent user already exists.
    let existing: Option<(uuid::Uuid,)> = match sqlx::query_as(
        "SELECT id FROM users WHERE email = $1 AND tenant_id = $2",
    )
    .bind(agent_email)
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(row) => row,
        Err(e) => {
            tracing::error!(%tenant_id, "read agent service account: {e}");
            return false;
        }
    };

    if existing.is_none() {
        let id = uuid::Uuid::new_v4();
        // The agent is the built-in instance of the generic service-account
        // principal: a non-human `users` row marked `auth_source='service'`. The
        // marker keeps it out of human surfaces and immune to the OIDC upsert
        // (see portal_auth OIDC `ON CONFLICT` guard); agent-specific behaviour
        // (`source='agent'` audit provenance) stays keyed off AGENT_EMAIL.
        if sqlx::query(
            "INSERT INTO users (id, tenant_id, email, display_name, auth_source, is_active) VALUES ($1, $2, $3, $4, 'service', true)"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(agent_email)
        .bind("Streamscope Agent")
        .execute(&mut *conn)
        .await
        .is_err()
        {
            tracing::error!(%tenant_id, "failed to create agent service account");
            return false;
        }
        tracing::info!(%tenant_id, "created agent service account");
    } else {
        // Existing agent row from before the service-account marker: make it
        // sticky. Idempotent — no-op once already 'service'.
        if let Err(e) = sqlx::query(
            "UPDATE users SET auth_source = 'service' \
             WHERE email = $1 AND tenant_id = $2 AND auth_source IS DISTINCT FROM 'service'",
        )
        .bind(agent_email)
        .bind(tenant_id)
        .execute(&mut *conn)
        .await
        {
            tracing::error!(%tenant_id, "mark agent service account: {e}");
            return false;
        }
    }

    // Ensure the agent key exists in the Agent workspace. No-ops when a key
    // with a stored plaintext is already present; a missing Agent workspace
    // (pre-seed) is logged and retried on the next provisioning pass.
    if let Err(e) = provision_agent_key(conn).await {
        tracing::warn!(%tenant_id, "provision agent key: {e}");
        return false;
    }
    true
}

/// Create the agent API key, bound to the tenant's Agent workspace.
///
/// Takes a tenant-scoped `&mut Scoped` so RLS confines the read.
///
/// The agent key is a single unified `sk-` key in the per-tenant **Agent**
/// workspace (`role = 'agent'`). It reaches only the providers granted to that
/// workspace (no wildcard) and its spend counts against the workspace budget; the
/// agent's judge model comes from the expert profile, whose route must be one
/// the Agent workspace is granted (`resolve_agent_routing` warns otherwise).
///
/// - If no key exists: generates one and stores the plaintext in system_settings.
/// - If a key exists with its plaintext present: no-op.
/// - If a key exists but the plaintext is missing: revokes it and recreates.
pub async fn provision_agent_key(conn: &mut Scoped) -> Result<(), String> {
    let agent_email = AGENT_EMAIL;

    // Find agent user.
    let Some((user_id,)): Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM users WHERE email = $1",
    )
    .bind(agent_email)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("db error: {e}"))?
    else {
        return Err("agent user not found — restart admin service".into());
    };

    // tenant_id is set on the connection via RLS, but we bind it explicitly
    // since column DEFAULTs are unsafe for non-SYSTEM tenants.
    let tenant_id: uuid::Uuid = sqlx::query_scalar("SELECT current_tenant_id()")
        .fetch_one(&mut *conn)
        .await
        .map_err(|e| format!("get tenant_id: {e}"))?;

    // Resolve the tenant's Agent workspace to bind the agent key. The agent is
    // governed like any workspace — its reach comes from the Agent workspace's
    // downstream grants (bootstrapped at seed, narrowed by the operator), not a
    // wildcard. Budget / rate-limit / guardrail apply per that workspace.
    let Some((workspace_id,)): Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM workspaces WHERE role = 'agent'",
    )
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("db error: {e}"))?
    else {
        return Err("agent workspace not found — restart admin service".into());
    };

    // Ensure the agent user belongs to the Agent workspace (keys can only be
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
    .map_err(|e| format!("add agent to agent workspace: {e}"))?;

    // Check for an existing agent key.
    let existing: Option<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM api_keys WHERE user_id = $1 AND name = 'agent-key' AND revoked_at IS NULL",
    )
    .bind(user_id)
    .fetch_optional(&mut *conn)
    .await
    .map_err(|e| format!("db error: {e}"))?;

    if let Some((key_id,)) = existing {
        // Key present — keep it iff its plaintext is still stored.
        let stored: Option<(serde_json::Value,)> = sqlx::query_as(
            "SELECT value FROM system_settings WHERE key = 'agent_api_key'",
        )
        .fetch_optional(&mut *conn)
        .await
        .map_err(|e| format!("db error: {e}"))?;

        if stored
            .as_ref()
            .and_then(|(v,)| v.as_str())
            .is_some_and(|s| !s.is_empty())
        {
            // Key valid, plaintext stored — but re-point its workspace to the
            // Agent workspace (a key provisioned before the agent had its own
            // workspace sits in Default; idempotent once moved).
            sqlx::query(
                "UPDATE api_keys SET workspace_id = $1 WHERE id = $2 AND tenant_id = $3 AND workspace_id <> $1",
            )
                .bind(workspace_id)
                .bind(key_id)
                .bind(tenant_id)
                .execute(&mut *conn)
                .await
                .map_err(|e| format!("repoint agent key workspace: {e}"))?;
            return Ok(());
        }

        // Plaintext missing — revoke and recreate.
        sqlx::query("UPDATE api_keys SET revoked_at = now() WHERE id = $1")
            .bind(key_id)
            .execute(&mut *conn)
            .await
            .map_err(|e| format!("revoke old key: {e}"))?;
        tracing::warn!("agent key plaintext missing in system_settings — recreating");
    }

    // Generate new key.
    let virtual_key = streamscope_core::auth::virtual_key::generate_virtual_key();
    let key_hash = streamscope_core::auth::virtual_key::hash_key(&virtual_key);
    let key_prefix = &virtual_key[..std::cmp::min(12, virtual_key.len())];

    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, workspace_id, user_id, name, key_hash, key_prefix) \
         VALUES ($1, $2, $3, $4, $5, $6, $7)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(tenant_id)
    .bind(workspace_id)
    .bind(user_id)
    .bind("agent-key")
    .bind(&key_hash)
    .bind(key_prefix)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("create agent key: {e}"))?;

    // Encrypt agent key before storing in system_settings (ENCRYPTION_KEY validated at startup).
    let enc_key = streamscope_core::crypto::get_encryption_key()
        .expect("ENCRYPTION_KEY validated at startup");
    let encrypted = streamscope_core::crypto::encrypt(&virtual_key, &enc_key)
        .map_err(|e| format!("encrypt agent key: {e}"))?;
    let stored_value = serde_json::json!(encrypted);

    sqlx::query(
        "INSERT INTO system_settings (key, value, tenant_id) VALUES ('agent_api_key', $1, $2) \
         ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(stored_value)
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map_err(|e| format!("store agent key: {e}"))?;

    tracing::info!(key_prefix = %key_prefix, workspace_id = %workspace_id, "provisioned agent API key");
    Ok(())
}

/// Spawn the background agent analysis task.
///
/// Leader-elected via advisory lock. Re-reads config from DB each cycle.
/// When disabled, sleeps and re-checks. Can be triggered via `agent_trigger_requests` table.
/// Iterates all tenants each cycle, running per-tenant analysis.
pub fn spawn_agent_task(
    state: Arc<AdminState>,
    token: tokio_util::sync::CancellationToken,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        // Let system stabilize after startup.
        tokio::select! {
            _ = token.cancelled() => return,
            _ = tokio::time::sleep(AGENT_STARTUP_DELAY) => {}
        }

        // Invariant: never fall back to a default client. It would carry none of
        // the imported CAs, so every analysis call to an upstream behind a
        // private CA would fail TLS for the whole process lifetime with no
        // visible cause. A worker that cannot build its client cannot work.
        let client = match streamscope_core::tls::add_custom_roots(
            reqwest::Client::builder().timeout(crate::settings::admin_settings().agent_http_timeout),
            crate::custom_ca::current().as_deref(),
        )
        .build()
        {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("agent worker: could not build HTTPS client ({e}); agent disabled");
                return;
            }
        };

        loop {
            use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};

            if token.is_cancelled() {
                tracing::info!("agent worker: shutdown signalled, exiting");
                break;
            }

            let any_enabled = Arc::new(AtomicBool::new(false));
            // Sleep the SHORTEST configured interval across enabled tenants, so a
            // tenant asking for a fast cadence is honored (extra wakeups for
            // slower tenants are cheap no-ops — their own watermark/cooldown gate
            // work). Seeded with the sentinel so "no enabled tenant" falls back
            // to the default below.
            let min_interval = Arc::new(AtomicU64::new(u64::MAX));

            // Try to acquire leader lock. Non-leaders sleep and retry.
            // Hold the connection only during the analysis work, not during inter-cycle sleep.
            {
                let Some(leader_conn) = crate::leader::try_acquire_leader(&state.db, crate::leader::LOCK_AGENT).await else {
                    tokio::select! {
                        _ = token.cancelled() => break,
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                    }
                    continue;
                };

                // Check for manual triggers (drain them). Trigger entries are
                // either `Some(tenant_id)` for tenant-targeted runs or `None`
                // for "all tenants" — collect both into the set so the
                // per-tenant closure can bypass the run-window restriction
                // for explicitly triggered tenants.
                let triggers = crate::leader::drain_agent_triggers(&state.db).await;
                let triggered_all = triggers.iter().any(|t| t.is_none());
                let triggered_tenants: std::collections::HashSet<uuid::Uuid> =
                    triggers.into_iter().flatten().collect();
                let triggered_all = std::sync::Arc::new(triggered_all);
                let triggered_tenants = std::sync::Arc::new(triggered_tenants);

                // Run per-tenant analysis cycle
                let _ = for_each_tenant(&state.db, |mut db| {
                    let state = state.clone();
                    let client = client.clone();
                    let any_enabled = any_enabled.clone();
                    let min_interval = min_interval.clone();
                    let triggered_all = triggered_all.clone();
                    let triggered_tenants = triggered_tenants.clone();
                    async move {
                        let tenant_id = db.tenant_uuid();

                        // Skip SYSTEM tenant — it has no workload data, users, or sessions.
                        if tenant_id == crate::db::tenant::TenantId::SYSTEM.as_uuid() {
                            return Ok(());
                        }

                        // Re-read config from DB each cycle (tenant-scoped via RLS)
                        let config = match AgentConfig::from_conn(db.conn()).await {
                            Some(c) => c,
                            None => {
                                // Agent disabled for this tenant
                                return Ok(());
                            }
                        };

                        any_enabled.store(true, Ordering::Relaxed);
                        min_interval.fetch_min(config.interval_secs, Ordering::Relaxed);

                        // Manual "Run Now" triggers bypass the run window —
                        // operators clicking the button explicitly want a cycle
                        // regardless of off-hours scheduling.
                        let manually_triggered =
                            *triggered_all || triggered_tenants.contains(&tenant_id);

                        if let Some(window) = config.run_window
                            && !manually_triggered
                        {
                            let now_hour = chrono::Utc::now().hour();
                            if !window.contains(now_hour) {
                                tracing::info!(
                                    %tenant_id,
                                    now_hour,
                                    start = window.start_hour_utc,
                                    end = window.end_hour_utc,
                                    "agent skipping cycle — outside configured run window (UTC)"
                                );
                                return Ok(());
                            }
                        }

                        tracing::info!(%tenant_id, "starting agent analysis cycle");

                        if let Err(e) = analysis::run_analysis_cycle(&state, &client, &config, tenant_id).await {
                            tracing::error!(%tenant_id, "agent analysis cycle failed: {e}");
                        }

                        // Record last cycle time
                        let _ = sqlx::query(
                            "INSERT INTO system_settings (key, value, tenant_id) VALUES ('agent_last_cycle_at', $1, $2) \
                             ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
                        )
                        .bind(serde_json::json!(chrono::Utc::now().to_rfc3339()))
                        .bind(db.tenant_uuid())
                        .execute(db.conn())
                        .await;

                        Ok(())
                    }
                }).await;

                // Explicitly release the advisory lock before inter-cycle sleep.
                crate::leader::release_leader(leader_conn, crate::leader::LOCK_AGENT).await;
            }

            if !any_enabled.load(Ordering::Relaxed) {
                // No tenant has agent enabled — check for DB trigger or poll.
                let mut waited = 0u64;
                let mut cancelled = false;
                while waited < AGENT_DISABLED_POLL.as_secs() {
                    if crate::leader::has_agent_triggers(&state.db).await {
                        tracing::info!("agent triggered while disabled — checking config");
                        break;
                    }
                    tokio::select! {
                        _ = token.cancelled() => { cancelled = true; break; }
                        _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                    }
                    waited += 10;
                }
                if cancelled {
                    tracing::info!("agent worker: shutdown signalled, exiting");
                    break;
                }
                continue;
            }

            // Wait for interval OR DB trigger (lock released, pool connection freed).
            // A `for_each_tenant` analysis cycle already in flight is not
            // interrupted mid-tenant — cancellation is observed here, at the
            // inter-cycle boundary; the shutdown drain timeout is the backstop.
            let interval_secs =
                resolve_interval_secs(min_interval.load(std::sync::atomic::Ordering::Relaxed));
            let mut waited = 0u64;
            let mut cancelled = false;
            while waited < interval_secs {
                if crate::leader::has_agent_triggers(&state.db).await {
                    tracing::info!("agent cycle triggered manually");
                    break;
                }
                tokio::select! {
                    _ = token.cancelled() => { cancelled = true; break; }
                    _ = tokio::time::sleep(Duration::from_secs(10)) => {}
                }
                waited += 10;
            }
            if cancelled {
                tracing::info!("agent worker: shutdown signalled, exiting");
                break;
            }
        }
    })
}

#[cfg(test)]
mod run_window_tests {
    use super::{
        resolve_interval_secs, RunWindow, AGENT_MIN_INTERVAL_SECS, DEFAULT_AGENT_INTERVAL_SECS,
    };

    #[test]
    fn non_wrap_window() {
        let w = RunWindow { start_hour_utc: 9, end_hour_utc: 17 };
        assert!(!w.contains(8));
        assert!(w.contains(9));
        assert!(w.contains(13));
        assert!(!w.contains(17));
        assert!(!w.contains(20));
    }

    #[test]
    fn wrap_window() {
        let w = RunWindow { start_hour_utc: 22, end_hour_utc: 6 };
        assert!(w.contains(22));
        assert!(w.contains(23));
        assert!(w.contains(0));
        assert!(w.contains(5));
        assert!(!w.contains(6));
        assert!(!w.contains(12));
        assert!(!w.contains(21));
    }

    #[test]
    fn empty_window_when_start_equals_end() {
        let w = RunWindow { start_hour_utc: 6, end_hour_utc: 6 };
        for h in 0..24 {
            assert!(!w.contains(h), "expected empty at hour {h}");
        }
    }

    #[test]
    fn interval_uses_shortest_configured_with_floor() {
        // The loop accumulates the per-tenant intervals via fetch_min; resolve
        // turns the accumulator into the actual sleep.
        // {600, 7200} -> 600 (the most frequent tenant wins).
        let mut acc = u64::MAX;
        for v in [7200u64, 600] {
            acc = acc.min(v);
        }
        assert_eq!(resolve_interval_secs(acc), 600);
        // No enabled tenant set an interval -> default.
        assert_eq!(resolve_interval_secs(u64::MAX), DEFAULT_AGENT_INTERVAL_SECS);
        // A too-small configured value is floored.
        assert_eq!(resolve_interval_secs(5), AGENT_MIN_INTERVAL_SECS);
        // A normal value passes through.
        assert_eq!(resolve_interval_secs(600), 600);
    }
}
