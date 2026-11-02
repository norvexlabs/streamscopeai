//! Seed built-in data for tenants.
//!
//! All seed data is loaded from disk via `SeedLoader` — no hardcoded data in Rust.
//!
//! Entry points, all writing the seed types of [`SEED_GROUPS`]:
//! - `seed_new_tenant()` + `finish_new_tenant()` — at tenant creation: every
//!   seed type inside the creation transaction, then the steps the startup
//!   passes repeat.
//! - `sync_seeds_for_tenant()` — called at startup for existing tenants, merges
//!   seed updates (overwrites builtins, skips user-edited entries, adds new ones).
//! - `sync_all_tenants()` — convenience wrapper that syncs all non-SYSTEM tenants.

use crate::db::tenant::{Scoped, TenantConn, TenantId};
use crate::db::Global;
use crate::seed_loader::SeedLoader;

/// Which pass is writing the seed types.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Seeding {
    /// The tenant is being created: every type is written inside the creation
    /// transaction, including the Default expert profile's membership and the
    /// Default client-access profile.
    Create,
    /// The startup reconcile of an existing tenant, one transaction per type.
    Reconcile,
}

/// The seed types, in the order they are written. Later types read earlier
/// ones: the client-access Default offers the client profiles, the expert
/// membership names the experts.
#[derive(Clone, Copy)]
enum SeedGroup {
    Scripts,
    Catalog,
    McpCatalog,
    Experts,
    Snippets,
    QosClasses,
    AppRegistry,
    ClientProfiles,
    DestinationLists,
    ToolRules,
    ToolFieldProfiles,
    Workspaces,
}

const SEED_GROUPS: [SeedGroup; 12] = [
    SeedGroup::Scripts,
    SeedGroup::Catalog,
    SeedGroup::McpCatalog,
    SeedGroup::Experts,
    SeedGroup::Snippets,
    SeedGroup::QosClasses,
    SeedGroup::AppRegistry,
    SeedGroup::ClientProfiles,
    SeedGroup::DestinationLists,
    SeedGroup::ToolRules,
    SeedGroup::ToolFieldProfiles,
    SeedGroup::Workspaces,
];

impl SeedGroup {
    fn name(self) -> &'static str {
        match self {
            Self::Scripts => "scripts",
            Self::Catalog => "catalog",
            Self::McpCatalog => "mcp_catalog",
            Self::Experts => "experts",
            Self::Snippets => "snippets",
            Self::QosClasses => "qos_classes",
            Self::AppRegistry => "app_registry",
            Self::ClientProfiles => "client_profiles",
            Self::DestinationLists => "destination_lists",
            Self::ToolRules => "tool_rules",
            Self::ToolFieldProfiles => "tool_field_profiles",
            Self::Workspaces => "workspaces",
        }
    }

    /// Write this seed type. **Every write must propagate with `?`**: it runs
    /// inside a transaction (see [`run_seed_group`]).
    async fn write(
        self,
        c: &mut Scoped,
        tid: uuid::Uuid,
        loader: &SeedLoader,
        seeding: Seeding,
    ) -> Result<(), sqlx::Error> {
        match self {
            Self::Scripts => sync_scripts(tid, c, loader).await.map(drop),
            Self::Catalog => sync_catalog(tid, c, loader).await.map(drop),
            Self::McpCatalog => sync_mcp_catalog(tid, c, loader).await.map(drop),
            Self::Experts => sync_experts(tid, c, loader).await.map(drop),
            Self::Snippets => sync_snippets(tid, c, loader).await.map(drop),
            Self::QosClasses => sync_qos_classes(tid, c, loader).await.map(drop),
            Self::AppRegistry => sync_app_registry(tid, c, loader).await.map(drop),
            Self::ClientProfiles => sync_client_profiles(tid, c, loader).await.map(drop),
            Self::DestinationLists => sync_destination_lists(tid, c, loader).await.map(drop),
            Self::ToolRules => sync_tool_rules(tid, c, loader).await.map(drop),
            Self::ToolFieldProfiles => sync_tool_field_profiles(tid, c, loader).await.map(drop),
            Self::Workspaces => write_workspaces(c, tid, seeding).await,
        }
    }
}

/// The workspaces and Default profiles: created for a new tenant, backfilled
/// for one that pre-dates a feature.
async fn write_workspaces(
    c: &mut Scoped,
    tid: uuid::Uuid,
    seeding: Seeding,
) -> Result<(), sqlx::Error> {
    // Must precede agent provisioning — the agent key binds to a workspace.
    ensure_default_workspace(&mut *c, tid).await?;
    // Default guardrail + transform + expert profiles.
    ensure_default_guardrail_profile(&mut *c, tid).await?;
    ensure_default_transform_profile(&mut *c, tid).await?;
    ensure_default_expert_profile(&mut *c, tid).await?;
    // The Default expert profile's membership is seeded ONCE, at tenant
    // creation, never on restart sync — the Default is admin-editable, and
    // re-seeding would silently revert a trim. A builtin expert shipped after a
    // tenant exists is added to the Default by an explicit "Reset to seed" (or
    // by editing the profile), not automatically. At creation every type is in
    // the one transaction, so the experts it names are all there or the tenant
    // is not created.
    // The Default client-access profile, offering every client: created with
    // the tenant (this type is written after the client profiles) and never
    // re-seeded, so a client a later release adds is not offered until an
    // admin enables it.
    if seeding == Seeding::Create {
        seed_default_expert_membership(&mut *c, tid).await?;
        seed_default_expert_watermarks(&mut *c, tid).await?;
        crate::routes::client_access_profiles::create_default_profile(&mut *c, tid).await?;
    }
    // The Agent workspace — must precede agent provisioning (the agent key binds
    // here). Creating it also pins its QoS class; an existing one is left alone,
    // so an admin who moved it off the automation class keeps that choice.
    ensure_agent_workspace(&mut *c, tid).await?;
    // The built-in BYOK pass-through providers (one per `byok_builtin` provider
    // in the seed), seeded disabled and granted nowhere.
    seed_byok_downstreams(tid, &mut *c).await?;
    // The Inline AI workspace — must precede inline-AI provisioning (its managed
    // key binds here).
    ensure_inline_ai_workspace(&mut *c, tid).await?;
    Ok(())
}

/// Write every seed type for a tenant being created, inside its creation
/// transaction: the tenant is created seeded or not at all.
///
/// One commit for the whole creation. Every commit that writes a config table
/// takes the config-bump commit-order lock and flushes the WAL while holding
/// it, so a creation committing per row serialises every concurrent creation
/// behind it. Follow the commit with [`finish_new_tenant`].
pub async fn seed_new_tenant(tx: &mut Scoped, tenant_id: TenantId) -> Result<(), sqlx::Error> {
    let loader = SeedLoader::new();
    let tid = tenant_id.as_uuid();
    for group in SEED_GROUPS {
        group
            .write(tx, tid, &loader, Seeding::Create)
            .await
            .inspect_err(|e| tracing::error!(%tenant_id, group = group.name(), "seed new tenant: {e}"))?;
    }
    Ok(())
}

/// The steps of a new tenant's seeding that run after its creation committed:
/// each keeps its own connection, and the startup passes repeat them (the
/// reconcile, and the agent account's provisioning), so a failure here is
/// retried on the next boot. A clean finish stamps the tenant.
pub async fn finish_new_tenant(pool: &crate::db::Db, tenant_id: TenantId) {
    let mut ok = seed_tail(pool, tenant_id).await;
    ok &= crate::agent::provision_agent_for_tenant(pool, tenant_id).await;
    if ok && let Some(stamp) = process_stamp() {
        write_seed_stamp(pool, tenant_id, stamp).await;
    }
}

/// This process's seed stamp, hashed once it could be read: the seed tree and
/// the build version it covers do not change while the process runs.
fn process_stamp() -> Option<&'static str> {
    static STAMP: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    if let Some(stamp) = STAMP.get() {
        return Some(stamp);
    }
    let stamp = SeedLoader::new().content_stamp()?;
    Some(STAMP.get_or_init(|| stamp))
}

/// Sync seed data for a single existing tenant. Called at startup.
///
/// For each seed type:
/// - Builtin entries in DB → overwrite with disk seed
/// - New entries not in DB → insert
/// - User-edited entries (is_builtin=false) → skip
///
/// `loader` is shared across the whole pass (the seed tree is read once per
/// boot, not once per tenant) and `stamp` is its fingerprint from
/// [`SeedLoader::content_stamp`]. A tenant already stamped with that value is
/// skipped outright; `None` disables the skip and reconciles unconditionally.
///
/// Each seed type runs in one transaction, so a type costs a single commit
/// rather than one per row. The invariant that keeps that safe: **every write
/// inside a group must propagate its error** — see [`run_seed_group`].
pub async fn sync_seeds_for_tenant(
    pool: &crate::db::Db,
    tenant_id: TenantId,
    loader: &SeedLoader,
    stamp: Option<&str>,
) {
    // Skip a tenant whose seed tree and binary version are both unchanged since
    // its last fully-successful pass: every write below is an idempotent
    // UPSERT of that same seed content, so it would land zero net changes while
    // still paying for the round-trips. A tenant is stamped only after a clean
    // pass (see the end of this function), so a partial failure — or a stamp we
    // could not compute — always reconciles again on the next boot.
    if let Some(stamp) = stamp
        && read_seed_stamp(pool, tenant_id).await.as_deref() == Some(stamp)
    {
        tracing::debug!(%tenant_id, "seed stamp unchanged, skipping reconcile");
        return;
    }

    let tid = tenant_id.as_uuid();
    // `&=` and not `&&=`: every group must run even after one fails. `ok` gates
    // only the stamp write, so a failed group is retried on the next boot.
    let mut ok = true;
    for group in SEED_GROUPS {
        ok &= run_seed_group(pool, tenant_id, group.name(), async |c| {
            group.write(c, tid, loader, Seeding::Reconcile).await
        })
        .await;
    }
    ok &= seed_tail(pool, tenant_id).await;
    // Record what this tenant is now reconciled to, so an unchanged next boot
    // can skip the whole pass. Only on a clean run: stamping after a partial
    // failure would make the gap permanent until the next seed or version change.
    if let Some(stamp) = stamp
        && ok
    {
        write_seed_stamp(pool, tenant_id, stamp).await;
    }
}

/// The seed steps outside any seed type's transaction, each on its own
/// connection; returns whether all of them completed.
async fn seed_tail(pool: &crate::db::Db, tenant_id: TenantId) -> bool {
    // Expert enhancements keep their own connection: the helper reads the
    // tenant's experts and tolerates a per-axis failure, a shape that cannot be
    // expressed inside a transaction (an aborted transaction fails every later
    // statement, so tolerating one row would silently discard the rest).
    let mut ok = match TenantConn::acquire(pool, tenant_id).await {
        Ok(mut db) => seed_expert_enhancements(db.conn()).await,
        Err(e) => {
            tracing::error!(%tenant_id, "seed expert enhancements: acquire failed: {e}");
            false
        }
    };
    // The inline-AI service account + managed key (idempotent, like the
    // workspace it binds to).
    ok &= crate::inline_ai::provision_inline_ai_for_tenant(pool, tenant_id).await;
    // The built-in `/mcp/web` rows: synthetic upstream + virtual server +
    // route, unconfigured until an operator picks a search backend.
    // Idempotent: ON CONFLICT DO NOTHING on every insert.
    ok &= match TenantConn::acquire(pool, tenant_id).await {
        Ok(mut db) => {
            let tid = db.tenant_uuid();
            seed_builtin_web(tid, db.conn()).await
        }
        Err(e) => {
            tracing::error!(%tenant_id, "seed builtin web: acquire failed: {e}");
            false
        }
    };
    ok
}

/// Run one seed group in its own transaction, returning whether it committed.
///
/// One commit per group, not one per row. A tenant's seed pass is ~830
/// statements; outside a transaction each autocommits and pays its own WAL
/// flush, which dominates the pass. Keep every seed write inside a group.
///
/// **Every write inside `f` must propagate with `?`.** A swallowed error would
/// abort the transaction server-side, leaving every later statement to fail and
/// `COMMIT` to roll back silently while reporting success — the whole group
/// would vanish while the logs claimed it synced.
async fn run_seed_group<F>(
    pool: &crate::db::Db,
    tenant_id: TenantId,
    group: &'static str,
    f: F,
) -> bool
where
    F: AsyncFnOnce(&mut Scoped) -> Result<(), sqlx::Error>,
{
    let mut tx = match pool.begin_tenant(tenant_id).await {
        Ok(tx) => tx,
        Err(e) => {
            tracing::error!(%tenant_id, group, "seed group: begin failed: {e}");
            return false;
        }
    };
    match f(&mut tx).await {
        Ok(()) => match tx.commit().await {
            Ok(()) => true,
            Err(e) => {
                tracing::error!(%tenant_id, group, "seed group: commit failed: {e}");
                false
            }
        },
        Err(e) => {
            // Already aborted server-side; roll back explicitly so the pooled
            // connection goes back clean rather than in a failed transaction.
            if let Err(re) = tx.rollback().await {
                tracing::warn!(%tenant_id, group, "seed group: rollback failed: {re}");
            }
            tracing::error!(%tenant_id, group, "seed group failed, rolled back: {e}");
            false
        }
    }
}

/// The seed stamp this tenant was last fully reconciled at, if any.
///
/// A read failure returns `None` — "unknown", which reconciles. The stamp is a
/// skip optimisation, so every uncertain path must fall through to doing the work.
async fn read_seed_stamp(pool: &crate::db::Db, tenant_id: TenantId) -> Option<String> {
    let mut db = TenantConn::acquire(pool, tenant_id).await.ok()?;
    sqlx::query_scalar::<_, serde_json::Value>(
        "SELECT value FROM system_settings WHERE key = 'seed_stamp' AND tenant_id = $1",
    )
    .bind(tenant_id.as_uuid())
    .fetch_optional(db.conn())
    .await
    .ok()?
    .and_then(|v| v.as_str().map(str::to_string))
}

/// Record the stamp this tenant is now reconciled to.
///
/// A scalar only the seed pass writes (at tenant creation and in the startup
/// reconcile), always the whole stamp of the build that ran it, so a
/// whole-value replace is correct here — there is no sibling field to clobber.
/// Two passes racing on one tenant each write a stamp they fully applied.
async fn write_seed_stamp(pool: &crate::db::Db, tenant_id: TenantId, stamp: &str) {
    let Ok(mut db) = TenantConn::acquire(pool, tenant_id).await else {
        tracing::warn!(%tenant_id, "seed stamp: acquire failed, not stamping");
        return;
    };
    if let Err(e) = sqlx::query(
        "INSERT INTO system_settings (key, tenant_id, value) VALUES ('seed_stamp', $1, $2) \
         ON CONFLICT (tenant_id, key) DO UPDATE SET value = EXCLUDED.value, updated_at = now()",
    )
    .bind(tenant_id.as_uuid())
    .bind(serde_json::Value::String(stamp.to_string()))
    .execute(db.conn())
    .await
    {
        // Non-fatal: the pass itself succeeded, this only costs a redundant
        // pass next boot.
        tracing::warn!(%tenant_id, "seed stamp write failed: {e}");
    }
}

/// Sync seeds for all non-SYSTEM tenants. Called at startup.
pub async fn sync_all_tenants(pool: &crate::db::Db) {
    let tenants: Vec<(uuid::Uuid,)> = sqlx::query_as(
        "SELECT id FROM tenants WHERE id != '00000000-0000-0000-0000-000000000001'"
    )
    .fetch_all(pool.global(Global::TenantRegistry))
    .await
    .unwrap_or_default();

    // One loader and one stamp for the whole pass: the seed tree is read from
    // disk once per boot, not once per tenant.
    // `content_stamp` returning `None` (unreadable tree) disables the skip for
    // this pass rather than risking a stale match — see `content_stamp`.
    let loader = SeedLoader::new();
    let stamp = process_stamp();
    if stamp.is_none() {
        tracing::warn!("seed stamp unavailable, reconciling every tenant unconditionally");
    }

    tracing::info!(count = tenants.len(), "syncing seeds for existing tenants");
    for (tid,) in tenants {
        sync_seeds_for_tenant(pool, TenantId::from_row(tid), &loader, stamp).await;
    }
    tracing::info!("seed sync complete");
}

// ---------------------------------------------------------------------------
// Default workspace provisioning
// ---------------------------------------------------------------------------

/// Ensure the tenant's **Default** workspace exists and return its id.
///
/// The Default workspace is `role = 'default'` and undeletable. It is a
/// *normal* workspace — users join only when explicitly added (no auto-join),
/// its allowlist starts empty, and an operator grants providers / MCP servers
/// explicitly, exactly like any other workspace (no wildcard, no auto-grant). It
/// carries no budget ceiling unless one is configured. Every tenant has exactly
/// one (enforced by the
/// partial-unique index on `role = 'default'`). Keys can only be minted against a
/// workspace, so this must exist before the first user or the agent service
/// account is provisioned.
///
/// Idempotent: `ON CONFLICT DO NOTHING`, safe to call on every tenant-create,
/// user-create, and startup sync.
pub(crate) async fn ensure_default_workspace(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<uuid::Uuid, sqlx::Error> {
    // Idempotent on `role = 'default'` (one default workspace per tenant), so the
    // re-runnable seed never inserts a duplicate.
    sqlx::query(
        "INSERT INTO workspaces (tenant_id, name, description, role) \
         SELECT $1, 'Default', 'The built-in workspace. Add members and grant it providers and MCP servers like any other.', 'default' \
         WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE tenant_id = $1 AND role = 'default')",
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;

    sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM workspaces WHERE tenant_id = $1 AND role = 'default'",
    )
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await
}

/// Provision the tenant's **Agent** workspace (`role = 'agent'`) — the home of
/// the internal analysis agent's key and self-traffic, governed like any
/// workspace (no wildcard). Idempotent on `role = 'agent'` (one per tenant).
///
/// On **first creation only** it bootstraps the workspace so the agent works the
/// instant it loses the old identity-wildcard reach:
/// - grants `workspace_downstream_access` to every downstream provider that
///   exists at that point (none on a brand-new tenant — providers are added
///   later, and the operator then grants the agent's one in the Access tab; the
///   backfill path on an existing tenant picks up its current pool), and
/// - sets **all four policy kinds to Off** (NULL-profile assignment rows) so the
///   agent's own analysis traffic is governed by nothing:
///   - **guardrail = Off** — sees raw PII; its prompts are never screened/mutated,
///   - **transform = Off** — its prompts/responses reach the model unmodified,
///   - **tools = Off** — its `submit_analysis` tool call is never blocked by a
///     restrictive tenant tool policy,
///   - **expert = Off** — no expert analyzes the Agent workspace (belt-and-braces
///     with the cycle's standing `AGENT_EMAIL` self-exclusion).
///
/// It needs no MCP grant: the agent calls only the LLM (`submit_analysis`), never
/// an MCP virtual server. Re-runs preserve any operator changes (grants/profile).
/// Returns the Agent workspace id.
pub(crate) async fn ensure_agent_workspace(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<uuid::Uuid, sqlx::Error> {
    // Insert iff absent; RETURNING tells us whether THIS call created it, so the
    // one-time bootstrap (grants + all-policy-kinds-off) doesn't clobber later
    // operator edits on a re-run.
    let created: Option<uuid::Uuid> = sqlx::query_scalar(
        "INSERT INTO workspaces (tenant_id, name, description, role) \
         SELECT $1, 'Agent', 'The internal analysis agent runs here. Grant it the providers its model needs and set a budget like any workspace; policy, guardrail, transforms, and expert analysis are off so it sees and forwards raw conversation content.', 'agent' \
         WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE tenant_id = $1 AND role = 'agent') \
         ON CONFLICT DO NOTHING \
         RETURNING id",
    )
    .bind(tenant_id)
    .fetch_optional(&mut *conn)
    .await?;

    let ws_id = match created {
        Some(id) => {
            // First creation — bootstrap reach + guardrail-off.
            sqlx::query(
                "INSERT INTO workspace_downstream_access (workspace_id, downstream_provider_id, tenant_id) \
                 SELECT $1, dp.id, $2 FROM downstream_providers dp WHERE dp.tenant_id = $2 \
                 ON CONFLICT DO NOTHING",
            )
            .bind(id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

            // Turn every policy kind Off for the Agent workspace (NULL-profile
            // assignment rows, distinct from "no row" which inherits the tenant
            // default): guardrail-off → raw PII, never screens its own prompts;
            // transform-off → prompts/responses reach the model unmodified (no
            // baseline either); tools-off → its `submit_analysis` call is never
            // blocked by a restrictive tenant tool policy; expert-off → no expert
            // analyzes the Agent workspace.
            sqlx::query(
                "INSERT INTO workspace_profile_assignments (workspace_id, tenant_id, kind, profile_id) \
                 SELECT $1, $2, k, NULL FROM unnest(ARRAY['guardrail','transform','tools','expert']) AS k \
                 ON CONFLICT (tenant_id, workspace_id, kind) DO NOTHING",
            )
            .bind(id)
            .bind(tenant_id)
            .execute(&mut *conn)
            .await?;

            // Pin it off the automation star. The pair is placed once, by
            // whichever half is created LAST: a tenant that predates the classes
            // is pinned when they arrive (`sync_qos_classes`), and one whose
            // Agent workspace arrives afterwards is pinned here. Neither can
            // re-pin, so an admin who deliberately puts it back on the tenant
            // default keeps that choice across restarts.
            ensure_agent_workspace_qos_class(&mut *conn, tenant_id).await?;
            id
        }
        None => {
            sqlx::query_scalar::<_, uuid::Uuid>(
                "SELECT id FROM workspaces WHERE tenant_id = $1 AND role = 'agent'",
            )
            .bind(tenant_id)
            .fetch_one(&mut *conn)
            .await?
        }
    };
    Ok(ws_id)
}

/// Provision the tenant's **Inline AI** workspace (`role = 'inline'`) — the
/// home of the built-in inline-AI service account's forward (BYOK) key, which an
/// external content analyzer (a gateway's in-line AI-traffic
/// inspection) presents to both `POST /v1/analyze` and the `/fwd/{key}/…`
/// pass-through. It is granted nothing: to intercept a provider, the operator
/// enables its pass-through server and grants it here. Its policy kinds stay
/// ASSIGNABLE (unlike [`ensure_agent_workspace`], no Off rows are seeded), so the
/// guardrail / tool-policy / transform profiles resolved for this workspace
/// (tenant defaults until the operator assigns) ARE the inline enforcement
/// policy. Idempotent on `role = 'inline'` (one per tenant); the service account +
/// managed key are provisioned separately
/// (`inline_ai::provision_inline_ai_for_tenant`), like the agent's.
pub(crate) async fn ensure_inline_ai_workspace(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    // `counts_toward_tenant_budget = false`: an intercepted call is funded on
    // the end user's own provider account, so the organisation's budget is not
    // what pays for it. Seeded only on creation — an operator who turns it back
    // on keeps that choice across restarts, like every other workspace setting.
    sqlx::query(
        "INSERT INTO workspaces (tenant_id, name, description, role, counts_toward_tenant_budget) \
         SELECT $1, 'Inline AI', 'External content analyzers (e.g. a gateway inspecting AI traffic in-line) authenticate here with the built-in inline-AI service account''s key. Its key passes through, with the client''s own credential, to the pass-through providers enabled and granted here, and calls the analyze API. The guardrail, tool-policy, and transform profiles assigned here are the inline enforcement policy.', 'inline', false \
         WHERE NOT EXISTS (SELECT 1 FROM workspaces WHERE tenant_id = $1 AND role = 'inline') \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await
    .map(drop)
}

/// Provision the tenant's default profile for one `kind` (`is_default = true`).
/// Idempotent — the one-default-per-(tenant, kind) index makes a second insert a
/// no-op. Returns the default profile id.
pub(crate) async fn ensure_default_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    kind: &str,
    name: &str,
    description: &str,
) -> Result<uuid::Uuid, sqlx::Error> {
    // The Default profile is the base — it inherits nothing, so it is itself
    // standalone (its bucket is its own content).
    sqlx::query(
        "INSERT INTO profiles (tenant_id, kind, name, description, is_default, standalone) \
         VALUES ($1, $2, $3, $4, true, true) \
         ON CONFLICT (tenant_id, kind, name) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(kind)
    .bind(name)
    .bind(description)
    .execute(&mut *conn)
    .await?;

    sqlx::query_scalar::<_, uuid::Uuid>(
        "SELECT id FROM profiles WHERE tenant_id = $1 AND kind = $2 AND is_default = true",
    )
    .bind(tenant_id)
    .bind(kind)
    .fetch_one(&mut *conn)
    .await
}

/// Provision the tenant's default **tool** profile. Returns its id so the rule
/// seeder can stamp each seeded rule's `profile_id`.
pub(crate) async fn ensure_default_tool_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<uuid::Uuid, sqlx::Error> {
    ensure_default_profile(
        conn,
        tenant_id,
        "tools",
        "Default",
        "The tenant default tool policy — applied to every workspace that has not selected another profile.",
    )
    .await
}

/// Provision the tenant's default **guardrail** profile. Its policy content lives
/// in `system_settings.guardrail_profiles` keyed by this id; an absent entry
/// resolves to the default policy, so no content seed is required.
pub(crate) async fn ensure_default_guardrail_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<uuid::Uuid, sqlx::Error> {
    ensure_default_profile(
        conn,
        tenant_id,
        "guardrail",
        "Default",
        "The tenant default guardrail policy — applied to every workspace that has not selected another profile.",
    )
    .await
}

/// Provision the tenant's default **transform** profile (the shared base) — the
/// fallback for workspaces with no explicit transform selection. Builtin programs
/// seed onto it (`profile_id` NOT NULL); a Layered profile inherits them, a
/// Standalone owns its own. Returns its id so the seeder can stamp each program.
pub(crate) async fn ensure_default_transform_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<uuid::Uuid, sqlx::Error> {
    ensure_default_profile(
        conn,
        tenant_id,
        "transform",
        "Default",
        "The tenant default transform profile — applied to every workspace that has not selected another profile.",
    )
    .await
}

/// Provision the tenant's default **expert** profile (the shared base). Its
/// membership is seeded with all enabled experts via
/// [`seed_default_expert_membership`]; a Layered profile inherits this set, a
/// Standalone profile owns its own. Returns its id.
pub(crate) async fn ensure_default_expert_profile(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<uuid::Uuid, sqlx::Error> {
    let id = ensure_default_profile(
        conn,
        tenant_id,
        "expert",
        "Default",
        "The tenant default expert profile — the experts applied to every workspace that has not selected another profile.",
    )
    .await?;

    // The Default carries the tenant's baseline judge model (other expert
    // profiles inherit it while their own `model` is NULL). Set only while
    // unset — never overwrite an admin's choice on restart.
    sqlx::query("UPDATE profiles SET model = $2 WHERE id = $1 AND model IS NULL")
        .bind(id)
        .bind(crate::agent::DEFAULT_AGENT_MODEL)
        .execute(&mut *conn)
        .await?;

    Ok(id)
}

/// Seed the Default expert profile's membership with every enabled, non-suppressed
/// expert (the shared base). Called ONCE at tenant creation — NOT on restart sync,
/// because the Default is admin-editable and re-seeding would silently revert a
/// trim. Idempotent (`ON CONFLICT DO NOTHING`). To stop an expert everywhere,
/// disable it (`agent_experts.enabled = false`); a builtin shipped after a tenant
/// exists joins the Default via an explicit "Reset to seed".
pub(crate) async fn seed_default_expert_membership(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO expert_profile_members (profile_id, expert_id, tenant_id) \
         SELECT p.id, e.id, $1 FROM profiles p, agent_experts e \
         WHERE p.tenant_id = $1 AND p.kind = 'expert' AND p.is_default \
           AND e.tenant_id = $1 AND e.enabled AND NOT e.suppressed \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// The Default's (profile, expert) pairs at tenant creation start with a NULL
/// cursor — scan from the beginning — so an agent turned on after the tenant
/// has traffic analyses what is already there. Every pair live later (a new
/// profile, an expert added to one, a builtin a later release ships) is seeded
/// at first sight from "now" (`seed_profile_watermark`).
async fn seed_default_expert_watermarks(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "INSERT INTO expert_profile_watermarks \
            (profile_id, expert_id, tenant_id, last_processed_at, sessions_analyzed) \
         SELECT m.profile_id, m.expert_id, $1, NULL, 0 \
           FROM expert_profile_members m JOIN profiles p \
             ON p.tenant_id = m.tenant_id AND p.id = m.profile_id \
          WHERE m.tenant_id = $1 AND p.kind = 'expert' AND p.is_default \
         ON CONFLICT DO NOTHING",
    )
    .bind(tenant_id)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Built-in `/mcp/web` provisioning
// ---------------------------------------------------------------------------

/// The seeded description of the built-in `web` virtual server.
const BUILTIN_WEB_VS_DESCRIPTION: &str =
    "Gateway-provided web tools — web_fetch, and web_search once a search backend is configured — audited end-to-end.";

/// Insert (or backfill) the synthetic `builtin-web` MCP upstream + virtual
/// server + route for one tenant. Idempotent — every insert uses ON CONFLICT
/// DO NOTHING. The tenant has no search backend until an operator picks one in
/// the admin UI; until then the virtual server serves `web_fetch` alone, to the
/// workspaces granted it.
///
/// Stable identifiers:
/// - upstream `id` — `Uuid::new_v5(NAMESPACE_WEB, tenant_id)`
///   (see [`streamscope_core::web::builtin_upstream_id`]).
/// - upstream `name` — [`streamscope_core::web::BUILTIN_WEB_UPSTREAM_NAME`]
///   (`"builtin-web"`); tool-policy stamps `mcp_server` from this.
/// - upstream `upstream_url` —
///   [`streamscope_core::web::BUILTIN_WEB_UPSTREAM_URL`]
///   (`"internal://web"`); proxy MCP dispatch short-circuits on the
///   `internal://` scheme.
/// - virtual server `slug` —
///   [`streamscope_core::web::BUILTIN_WEB_VIRTUAL_SERVER_SLUG`]
///   (`"web"`); tenant-overridable via the standard PATCH endpoint later.
async fn seed_builtin_web(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
) -> bool {
    use streamscope_core::web::{
        builtin_upstream_id, BUILTIN_WEB_UPSTREAM_NAME, BUILTIN_WEB_UPSTREAM_URL,
        BUILTIN_WEB_VIRTUAL_SERVER_SLUG,
    };

    let upstream_id = builtin_upstream_id(tenant_id);

    // 1. Upstream row.
    if let Err(e) = sqlx::query(
        "INSERT INTO mcp_upstream_servers (
            id, tenant_id, name, description, upstream_url,
            transport, auth_mode, cred_version, enabled, built_in
         ) VALUES (
            $1, $2, $3, $4, $5,
            'streamable_http', 'no_auth', 1, true, true
         )
         ON CONFLICT (tenant_id, id) DO NOTHING",
    )
    .bind(upstream_id)
    .bind(tenant_id)
    .bind(BUILTIN_WEB_UPSTREAM_NAME)
    .bind("Gateway-internal web search and fetch.")
    .bind(BUILTIN_WEB_UPSTREAM_URL)
    .execute(&mut *conn)
    .await
    {
        tracing::warn!(%tenant_id, "seed builtin-web upstream insert failed: {e}");
        return false;
    }

    // 2. Virtual server row. We can't use a deterministic UUID on this one
    //    because the slug is the operator-facing identity (and may be
    //    renamed). Use the unique-on-(tenant_id, slug) constraint to make
    //    the insert idempotent. Empty SELECT lets us return the existing
    //    row's id when the slug already exists.
    let vs_id: Option<(uuid::Uuid,)> = match sqlx::query_as(
        "INSERT INTO mcp_virtual_servers (tenant_id, slug, name, description, enabled)
         VALUES ($1, $2, $3, $4, true)
         ON CONFLICT (tenant_id, slug) DO NOTHING
         RETURNING id",
    )
    .bind(tenant_id)
    .bind(BUILTIN_WEB_VIRTUAL_SERVER_SLUG)
    .bind("Built-in Web")
    .bind(BUILTIN_WEB_VS_DESCRIPTION)
    .fetch_optional(&mut *conn)
    .await
    {
        Ok(opt) => opt,
        Err(e) => {
            tracing::warn!(%tenant_id, "seed builtin-web virtual server insert failed: {e}");
            return false;
        }
    };
    let vs_id: uuid::Uuid = match vs_id {
        Some((id,)) => id,
        None => {
            // Existing row — look it up.
            match sqlx::query_as::<_, (uuid::Uuid,)>(
                "SELECT id FROM mcp_virtual_servers
                 WHERE tenant_id = $1 AND slug = $2",
            )
            .bind(tenant_id)
            .bind(BUILTIN_WEB_VIRTUAL_SERVER_SLUG)
            .fetch_one(&mut *conn)
            .await
            {
                Ok((id,)) => id,
                Err(e) => {
                    tracing::warn!(%tenant_id, "lookup builtin-web virtual server id failed: {e}");
                    return false;
                }
            }
        }
    };

    // 3. Route — empty prefix so tools surface as `web_search` / `web_fetch`
    //    rather than `web__web_search`.
    if let Err(e) = sqlx::query(
        "INSERT INTO mcp_virtual_routes (
            tenant_id, virtual_server_id, upstream_server_id, prefix, enabled, position
         ) VALUES ($1, $2, $3, '', true, 0)
         ON CONFLICT (tenant_id, virtual_server_id, prefix) DO NOTHING",
    )
    .bind(tenant_id)
    .bind(vs_id)
    .bind(upstream_id)
    .execute(&mut *conn)
    .await
    {
        tracing::warn!(%tenant_id, "seed builtin-web route insert failed: {e}");
        return false;
    }

    true
}

// ---------------------------------------------------------------------------
// Built-in BYOK pass-through downstreams
// ---------------------------------------------------------------------------

/// Stable namespace for deterministic per-tenant BYOK upstream ids.
const BYOK_UPSTREAM_NAMESPACE: uuid::Uuid =
    uuid::Uuid::from_u128(0x6279_6f6b_5f75_7073_7472_6561_6d5f_6e73);

/// Insert (or backfill) the built-in BYOK pass-through providers from the
/// canonical provider seed (every `byok_builtin` provider). Each is a **keyless**
/// upstream (the client forwards its own credential; nothing stored) with
/// `auto_sync_enabled=false`, linked to a `byok=true` downstream that is **empty
/// by default** — pure pass-through to the official endpoint. The server is
/// seeded **disabled** and the provider granted nowhere: a disabled pass-through
/// is not sent to the gateways (`config_builder`), so each reaches nothing until the
/// operator turns it on and grants it to a workspace. Idempotent
/// (`ON CONFLICT DO NOTHING`, so an operator's on/off choice survives every
/// startup sync); called on tenant-create and on every startup sync.
async fn seed_byok_downstreams(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
) -> Result<(), sqlx::Error> {
    for p in crate::seed_loader::provider_catalog().iter().filter(|p| p.byok_builtin) {
        let (Some(url), Some(name)) = (p.default_url.as_deref(), p.byok_display_name.as_deref())
        else {
            // Guaranteed present for byok rows by the seed consistency test; skip defensively.
            continue;
        };
        let upstream_id = uuid::Uuid::new_v5(
            &BYOK_UPSTREAM_NAMESPACE,
            format!("{tenant_id}:{}", p.provider).as_bytes(),
        );

        // 1. Keyless upstream — no credential, no auto-sync (the downstream stays
        //    empty = pure pass-through), disabled until the operator turns it on.
        //    Idempotent; it's created before the downstream so the FK link exists.
        sqlx::query(
            "INSERT INTO upstream_servers (
                id, tenant_id, name, provider, upstream_api_format,
                chat_endpoint_path, enabled, auto_sync_enabled, is_builtin, transport
             ) VALUES ($1, $2, $3, $4, $5, $6, false, false, true, COALESCE($7, 'default'))
             ON CONFLICT (tenant_id, id) DO NOTHING",
        )
        .bind(upstream_id)
        .bind(tenant_id)
        .bind(name)
        .bind(&p.provider)
        .bind(p.effective_byok_api_format())
        .bind(p.chat_endpoint_path.as_deref())
        .bind(p.default_transport.as_deref())
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::warn!(%tenant_id, provider = %p.provider, "seed BYOK upstream insert failed: {e}")
        })?;
        // Its one endpoint: the provider's URL. Only when it has none — an
        // operator's edit to the server's URL moves that endpoint, and the
        // next sync must not add the provider's URL back beside it.
        sqlx::query(
            "INSERT INTO upstream_server_endpoints (tenant_id, server_id, url)
             SELECT $1, s.id, $3 FROM upstream_servers s
              WHERE s.id = $2
                AND NOT EXISTS (SELECT 1 FROM upstream_server_endpoints e WHERE e.server_id = s.id)",
        )
        .bind(tenant_id)
        .bind(upstream_id)
        .bind(url)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::warn!(%tenant_id, provider = %p.provider, "seed BYOK upstream endpoint insert failed: {e}")
        })?;

        // 2. The BYOK downstream linked to it. The `icon` column carries the
        //    provider key so the UI renders the brand glyph.
        sqlx::query(
            "INSERT INTO downstream_providers ( \
                 tenant_id, name, description, icon, upstream_server_id, is_builtin, byok \
             ) VALUES ($1, $2, $3, $4, $5, true, true) \
             ON CONFLICT (tenant_id, name) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(name)
        .bind("Bring-your-own-key pass-through. Empty by default: every model passes through to the provider with the client's own credential. Add a route to override a specific model with your own (e.g. on-prem) upstream.")
        .bind(&p.provider)
        .bind(upstream_id)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::warn!(%tenant_id, provider = %p.provider, "seed BYOK downstream insert failed: {e}")
        })?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Expert enhancements
// ---------------------------------------------------------------------------

/// Seed expert enhancements (colors, prompt_snippets) for a single tenant connection.
/// Backfill per-expert colours and prompt-snippet keys.
///
/// Returns whether the pass was complete. Per-axis tolerance is deliberate — one
/// expert's failed UPDATE must not stop the others — which is exactly why this
/// runs on its own connection rather than inside a seed group: an aborted
/// transaction would fail every later statement anyway. The caller folds the
/// returned flag into the tenant's stamp, so a partial pass is retried next boot
/// instead of being skipped until the next release.
async fn seed_expert_enhancements(conn: &mut Scoped) -> bool {
    use crate::agent::experts::{default_snippet_keys, EXPERT_COLORS};

    let rows = sqlx::query_as::<_, (uuid::Uuid, String, Vec<String>, Vec<String>, Option<String>, Vec<String>, bool)>(
        "SELECT id, axis, input_types, output_types, color, prompt_snippets, is_builtin FROM agent_experts ORDER BY axis"
    )
    .fetch_all(&mut *conn)
    .await;

    let Ok(experts) = rows else {
        tracing::error!("failed to fetch experts for enhancement seeding");
        return false;
    };
    let mut complete = true;

    let used_colors: Vec<String> = experts.iter().filter_map(|e| e.4.clone()).collect();
    let mut color_idx = 0;

    for (id, axis, input_types, output_types, color, prompt_snippets, is_builtin) in &experts {
        let mut snippets_changed = false;
        let mut new_snippets = prompt_snippets.clone();
        let mut color_changed = false;
        let mut new_color = color.clone();

        // Only update prompt_snippets for builtins — user-created experts keep theirs
        if *is_builtin {
            let expected = default_snippet_keys(input_types, output_types);
            let has_unknown = prompt_snippets.iter().any(|k| !expected.contains(k));
            if prompt_snippets.is_empty() || has_unknown {
                new_snippets = expected;
                snippets_changed = true;
            }
        }

        // Color assignment is safe for all experts (only sets if missing)
        if color.is_none() {
            while color_idx < EXPERT_COLORS.len() && used_colors.contains(&EXPERT_COLORS[color_idx].to_string()) {
                color_idx += 1;
            }
            if color_idx < EXPERT_COLORS.len() {
                new_color = Some(EXPERT_COLORS[color_idx].to_string());
                color_idx += 1;
                color_changed = true;
            }
        }

        // Update builtins: both snippets and color. User-created: color only.
        if snippets_changed || color_changed {
            let result = if *is_builtin {
                sqlx::query(
                    "UPDATE agent_experts SET prompt_snippets = $2, color = $3 WHERE id = $1 AND is_builtin = true"
                )
                .bind(id)
                .bind(&new_snippets)
                .bind(&new_color)
                .execute(&mut *conn)
                .await
            } else if color_changed {
                sqlx::query(
                    "UPDATE agent_experts SET color = $2 WHERE id = $1"
                )
                .bind(id)
                .bind(&new_color)
                .execute(&mut *conn)
                .await
            } else {
                continue;
            };

            match result {
                Ok(_) => tracing::debug!(axis = %axis, "updated expert enhancements"),
                Err(e) => {
                    tracing::error!(axis = %axis, error = %e, "failed to update expert enhancements");
                    complete = false;
                }
            }
        }
    }
    complete
}

// ---------------------------------------------------------------------------
// Seed-type writers (overwrite builtins, skip user-edited). They run inside a
// transaction — a new tenant's creation, or one reconcile group — so every
// write propagates its error.
// ---------------------------------------------------------------------------

/// The builtin upsert for `transform_programs`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const SCRIPT_UPSERT: &str = "INSERT INTO transform_programs (tenant_id, name, description, source, phase, scope, priority, enabled, model_filter, app_filter, trigger_regex, match_mode, is_builtin, profile_id) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, true, $13) \
             ON CONFLICT (tenant_id, name) DO UPDATE SET \
               description = EXCLUDED.description, \
               source = EXCLUDED.source, \
               phase = EXCLUDED.phase, \
               scope = EXCLUDED.scope, \
               priority = EXCLUDED.priority, \
               model_filter = EXCLUDED.model_filter, \
               app_filter = EXCLUDED.app_filter, \
               trigger_regex = EXCLUDED.trigger_regex, \
               match_mode = EXCLUDED.match_mode, \
               updated_at = now() \
             WHERE transform_programs.is_builtin = true AND NOT transform_programs.suppressed \
               AND (transform_programs.description, transform_programs.source, transform_programs.phase, transform_programs.scope, transform_programs.priority, transform_programs.model_filter, transform_programs.app_filter, transform_programs.trigger_regex, transform_programs.match_mode) \
                   IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.source, EXCLUDED.phase, EXCLUDED.scope, EXCLUDED.priority, EXCLUDED.model_filter, EXCLUDED.app_filter, EXCLUDED.trigger_regex, EXCLUDED.match_mode)";

async fn sync_scripts(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let mut synced = 0usize;

    // Builtin transform programs live on the Default transform profile (the shared
    // base); profile_id is NOT NULL, so the Default must exist first.
    let default_transform_id = ensure_default_transform_profile(&mut *conn, tenant_id)
        .await
        .inspect_err(|e| {
            tracing::error!(%tenant_id, "sync scripts: ensure default transform profile failed: {e}")
        })?;

    for script in loader.load_scripts() {
        let engine = streamscope_core::scripting::ScriptEngine::new();
        if engine.validate(&script.source).is_err() {
            tracing::warn!(name = %script.name, "seed script failed validation, skipping sync");
            continue;
        }
        // Upsert: insert new, update existing builtins, skip user-edited.
        // Note: `enabled` is deliberately excluded from updates — operators may have
        // toggled scripts on/off, and we don't want to override that choice on restart.
        // `profile_id` is set only on INSERT (a fresh builtin lands on the Default);
        // it is intentionally NOT updated, so a user who moved a builtin keeps it.
        sqlx::query(SCRIPT_UPSERT)
        .bind(tenant_id)
        .bind(&script.name)
        .bind(&script.description)
        .bind(&script.source)
        .bind(&script.phase)
        .bind(&script.scope)
        .bind(script.priority)
        .bind(script.enabled)
        .bind(&script.model_filter)
        .bind(&script.app_filter)
        .bind(&script.trigger_regex)
        .bind(&script.match_mode)
        .bind(default_transform_id)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| tracing::error!(name = %script.name, error = %e, "failed to sync script"))?;
        synced += 1;
    }
    tracing::debug!(%tenant_id, synced, "synced scripts");
    Ok(synced)
}

/// Columns the catalog seed writes, in the order the UNNEST arrays are bound.
/// The INSERT list, the UNNEST alias and the DO UPDATE set must all stay in step —
/// keeping the names in one place is what makes that checkable by eye.
const CATALOG_COLUMNS: &str = "provider, model, rates, context_window, max_output_tokens, \
     supports_caching, supports_reasoning, supports_vision, supports_function_calling, \
     supports_audio_input, supports_audio_output, supports_video_input, supports_pdf_input, \
     supports_response_schema, supports_system_messages, deprecation_date, model_type, \
     output_vector_size";

/// `CATALOG_COLUMNS` prefixed with a table alias, for the row-comparison that
/// makes an unchanged row a no-op. Derived from the same constant as the INSERT
/// list and the UNNEST alias, so the three cannot drift apart.
fn qualified_columns(alias: &'static str) -> String {
    CATALOG_COLUMNS
        .split(',')
        .map(|c| format!("{alias}.{}", c.trim()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// The builtin catalog upsert behind [`upsert_catalog_batch`]; `$1..$18` are the
/// per-column arrays, `$19` the tenant.
fn catalog_upsert_sql() -> String {
    format!(
        "INSERT INTO model_catalog ({cols}, tenant_id, is_builtin) \
         SELECT u.*, $19::uuid, true FROM UNNEST( \
             $1::text[], $2::text[], $3::jsonb[], $4::int4[], $5::int4[], \
             $6::bool[], $7::bool[], $8::bool[], $9::bool[], $10::bool[], $11::bool[], \
             $12::bool[], $13::bool[], $14::bool[], $15::bool[], \
             $16::text[], $17::text[], $18::int4[] \
         ) AS u({cols}) \
         LEFT JOIN model_catalog mc ON mc.tenant_id = $19::uuid AND mc.server_id IS NULL \
           AND mc.provider_key = canonical_provider_key(u.provider) \
           AND mc.model = u.model \
         ORDER BY mc.id NULLS LAST, canonical_provider_key(u.provider), u.model \
         ON CONFLICT (tenant_id, server_id, provider_key, model) DO UPDATE SET \
           provider = EXCLUDED.provider, \
           rates = EXCLUDED.rates, \
           context_window = EXCLUDED.context_window, \
           max_output_tokens = EXCLUDED.max_output_tokens, \
           supports_caching = EXCLUDED.supports_caching, \
           supports_reasoning = EXCLUDED.supports_reasoning, \
           supports_vision = EXCLUDED.supports_vision, \
           supports_function_calling = EXCLUDED.supports_function_calling, \
           supports_audio_input = EXCLUDED.supports_audio_input, \
           supports_audio_output = EXCLUDED.supports_audio_output, \
           supports_video_input = EXCLUDED.supports_video_input, \
           supports_pdf_input = EXCLUDED.supports_pdf_input, \
           supports_response_schema = EXCLUDED.supports_response_schema, \
           supports_system_messages = EXCLUDED.supports_system_messages, \
           deprecation_date = EXCLUDED.deprecation_date, \
           model_type = EXCLUDED.model_type, \
           output_vector_size = EXCLUDED.output_vector_size, \
           is_builtin = true, \
           updated_at = now() \
         WHERE model_catalog.is_builtin AND NOT model_catalog.suppressed \
           AND ({mine}) IS DISTINCT FROM ({theirs})",
        cols = CATALOG_COLUMNS,
        mine = qualified_columns("model_catalog"),
        theirs = qualified_columns("EXCLUDED"),
    )
}

/// Upsert the whole builtin catalog for one tenant in a single statement.
///
/// One statement rather than one per entry: the catalog is ~1.6k rows and is
/// re-applied per tenant on every seed-version change, so a per-row loop is that
/// many round trips per tenant. The arrays are bound one-per-COLUMN (18 binds), not
/// one-per-ROW — a per-row tuple form would be ~30k parameters against Postgres's
/// 65,535 ceiling, which would break the reconcile outright the next time the
/// catalog grew.
///
/// `ON CONFLICT ... WHERE is_builtin AND NOT suppressed` is evaluated per conflicting
/// row exactly as it was in the loop, so a tenant's edited or suppressed entries
/// still survive the refresh.
///
/// The guard also compares VALUES, so a row whose content is unchanged is not
/// rewritten. Provenance alone is not enough: without the comparison every builtin
/// row is physically updated on every reconcile, which at ~1.6k rows across N
/// tenants is a burst of tens of thousands of dead tuples and index churn landing
/// exactly at startup — enough, measured, to delay config sync and time out
/// unrelated tests. A no-op reconcile should touch nothing. The conflict target carries `canonical_provider_key`
/// because provider is part of row identity: the same model name under two providers
/// is two rows, and without it one silently overwrites the other.
///
/// The source rows are fed in the existing rows' id order (new rows last): the
/// conflict arm row-locks each existing entry as it reaches it, and every other
/// writer that locks several catalog entries — removals, and a model's link write
/// (`catalog::require_live_entries`) — takes them in id order, so a reconcile
/// racing one of them waits instead of deadlocking. Keep that `ORDER BY` (locked
/// by `the_catalog_upsert_locks_existing_rows_in_id_order`).
async fn upsert_catalog_batch(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    entries: &[crate::seed_loader::CatalogEntry],
) -> Result<u64, sqlx::Error> {
    if entries.is_empty() {
        return Ok(0);
    }

    let providers: Vec<&str> = entries.iter().map(|e| e.provider.as_str()).collect();
    let models: Vec<&str> = entries.iter().map(|e| e.model.as_str()).collect();
    // `model_catalog.rates` is NOT NULL: an entry the feed publishes no price for
    // carries an empty rate map, which reads as *unknown*, never as NULL.
    let rates: Vec<sqlx::types::Json<&streamscope_core::pricing::Rates>> =
        entries.iter().map(|e| sqlx::types::Json(&e.rates)).collect();
    let context_window: Vec<Option<i32>> = entries.iter().map(|e| e.context_window).collect();
    let max_output: Vec<Option<i32>> = entries.iter().map(|e| e.max_output_tokens).collect();
    let caching: Vec<Option<bool>> = entries.iter().map(|e| e.supports_caching).collect();
    let reasoning: Vec<Option<bool>> = entries.iter().map(|e| e.supports_reasoning).collect();
    let vision: Vec<Option<bool>> = entries.iter().map(|e| e.supports_vision).collect();
    let functions: Vec<Option<bool>> = entries.iter().map(|e| e.supports_function_calling).collect();
    let audio_in: Vec<Option<bool>> = entries.iter().map(|e| e.supports_audio_input).collect();
    let audio_out: Vec<Option<bool>> = entries.iter().map(|e| e.supports_audio_output).collect();
    let video_in: Vec<Option<bool>> = entries.iter().map(|e| e.supports_video_input).collect();
    let pdf_in: Vec<Option<bool>> = entries.iter().map(|e| e.supports_pdf_input).collect();
    let schema: Vec<Option<bool>> = entries.iter().map(|e| e.supports_response_schema).collect();
    let system_msgs: Vec<Option<bool>> = entries.iter().map(|e| e.supports_system_messages).collect();
    let deprecation: Vec<Option<&str>> =
        entries.iter().map(|e| e.deprecation_date.as_deref()).collect();
    let model_type: Vec<Option<&str>> = entries.iter().map(|e| e.model_type.as_deref()).collect();
    let vector_size: Vec<Option<i32>> = entries.iter().map(|e| e.output_vector_size).collect();

    let sql = catalog_upsert_sql();

    // Every fragment spliced above is a compile-time constant: the column list and
    // the parameter placeholders. No caller-supplied text reaches the SQL — the
    // entries are bound.
    let result = sqlx::query(sqlx::AssertSqlSafe(&*sql))
        .bind(&providers)
        .bind(&models)
        .bind(&rates)
        .bind(&context_window)
        .bind(&max_output)
        .bind(&caching)
        .bind(&reasoning)
        .bind(&vision)
        .bind(&functions)
        .bind(&audio_in)
        .bind(&audio_out)
        .bind(&video_in)
        .bind(&pdf_in)
        .bind(&schema)
        .bind(&system_msgs)
        .bind(&deprecation)
        .bind(&model_type)
        .bind(&vector_size)
        .bind(tenant_id)
        .execute(conn)
        .await?;

    Ok(result.rows_affected())
}

pub(crate) async fn sync_catalog(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let entries = loader.load_catalog();
    let synced = upsert_catalog_batch(conn, tenant_id, &entries).await? as usize;
    tracing::debug!(%tenant_id, synced, "synced catalog");
    Ok(synced)
}

/// The builtin upsert for `mcp_catalog`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const MCP_CATALOG_UPSERT: &str = "INSERT INTO mcp_catalog (tenant_id, source, source_name, name, display_title, description, \
             category, featured, website_url, repository_url, icon_url, upstream_url, transport, auth_mode, \
             oauth_issuer_url, oauth_authorization_url, oauth_token_url, oauth_revocation_url, \
             oauth_default_scopes, tools, tool_count, liveness, is_builtin) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, $19, $20, $21, $22, true) \
             ON CONFLICT (tenant_id, source_name) DO UPDATE SET \
               source = EXCLUDED.source, \
               name = EXCLUDED.name, \
               display_title = EXCLUDED.display_title, \
               description = EXCLUDED.description, \
               category = EXCLUDED.category, \
               featured = EXCLUDED.featured, \
               website_url = EXCLUDED.website_url, \
               repository_url = EXCLUDED.repository_url, \
               icon_url = EXCLUDED.icon_url, \
               upstream_url = EXCLUDED.upstream_url, \
               transport = EXCLUDED.transport, \
               auth_mode = EXCLUDED.auth_mode, \
               oauth_issuer_url = EXCLUDED.oauth_issuer_url, \
               oauth_authorization_url = EXCLUDED.oauth_authorization_url, \
               oauth_token_url = EXCLUDED.oauth_token_url, \
               oauth_revocation_url = EXCLUDED.oauth_revocation_url, \
               oauth_default_scopes = EXCLUDED.oauth_default_scopes, \
               tools = EXCLUDED.tools, \
               tool_count = EXCLUDED.tool_count, \
               liveness = EXCLUDED.liveness, \
               is_builtin = true, \
               updated_at = now() \
             WHERE mcp_catalog.is_builtin = true AND NOT mcp_catalog.suppressed \
               AND (mcp_catalog.source, mcp_catalog.name, mcp_catalog.display_title, mcp_catalog.description, mcp_catalog.category, mcp_catalog.featured, mcp_catalog.website_url, mcp_catalog.repository_url, mcp_catalog.icon_url, mcp_catalog.upstream_url, mcp_catalog.transport, mcp_catalog.auth_mode, mcp_catalog.oauth_issuer_url, mcp_catalog.oauth_authorization_url, mcp_catalog.oauth_token_url, mcp_catalog.oauth_revocation_url, mcp_catalog.oauth_default_scopes, mcp_catalog.tools, mcp_catalog.tool_count, mcp_catalog.liveness) \
                   IS DISTINCT FROM (EXCLUDED.source, EXCLUDED.name, EXCLUDED.display_title, EXCLUDED.description, EXCLUDED.category, EXCLUDED.featured, EXCLUDED.website_url, EXCLUDED.repository_url, EXCLUDED.icon_url, EXCLUDED.upstream_url, EXCLUDED.transport, EXCLUDED.auth_mode, EXCLUDED.oauth_issuer_url, EXCLUDED.oauth_authorization_url, EXCLUDED.oauth_token_url, EXCLUDED.oauth_revocation_url, EXCLUDED.oauth_default_scopes, EXCLUDED.tools, EXCLUDED.tool_count, EXCLUDED.liveness)";

/// Sync the MCP server catalog seed into `mcp_catalog` for one tenant.
///
/// Builtins (`is_builtin = true`) are UPSERTed by `(tenant_id, source_name)` and
/// overwritten from disk. A user-edited row (`is_builtin = false`) is preserved —
/// the `WHERE mcp_catalog.is_builtin = true AND NOT suppressed` guard on the
/// UPDATE makes the upsert a no-op against it — so a user-edited or soft-deleted
/// (suppressed) builtin is never overwritten or resurrected.
pub(crate) async fn sync_mcp_catalog(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let entries = loader.load_mcp_catalog();
    let mut synced = 0usize;

    for entry in &entries {
        let tools = serde_json::to_value(&entry.tools).unwrap_or_else(|_| serde_json::json!([]));
        sqlx::query(MCP_CATALOG_UPSERT)
        .bind(tenant_id)
        .bind(&entry.source)
        .bind(&entry.source_name)
        .bind(&entry.name)
        .bind(&entry.display_title)
        .bind(&entry.description)
        .bind(&entry.category)
        .bind(entry.featured)
        .bind(&entry.website_url)
        .bind(&entry.repository_url)
        .bind(&entry.icon_url)
        .bind(&entry.upstream_url)
        .bind(&entry.transport)
        .bind(&entry.auth_mode)
        .bind(&entry.oauth_issuer_url)
        .bind(&entry.oauth_authorization_url)
        .bind(&entry.oauth_token_url)
        .bind(&entry.oauth_revocation_url)
        .bind(&entry.oauth_default_scopes)
        .bind(&tools)
        .bind(entry.tool_count)
        .bind(&entry.liveness)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::error!(server = %entry.source_name, error = %e, "failed to sync MCP catalog")
        })?;
        synced += 1;
    }
    tracing::debug!(%tenant_id, synced, "synced MCP catalog");
    Ok(synced)
}

/// The builtin upsert for `agent_experts`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const EXPERT_UPSERT: &str = "INSERT INTO agent_experts (tenant_id, axis, description, prompt, enabled, is_builtin, input_types, output_types, merge_enabled) \
             VALUES ($1, $2, $3, $4, true, true, $5, $6, $7) \
             ON CONFLICT (tenant_id, axis) DO UPDATE SET \
               description = EXCLUDED.description, \
               prompt = EXCLUDED.prompt, \
               input_types = EXCLUDED.input_types, \
               output_types = EXCLUDED.output_types \
             WHERE agent_experts.is_builtin = true AND NOT agent_experts.suppressed \
               AND (agent_experts.description, agent_experts.prompt, agent_experts.input_types, agent_experts.output_types) \
                   IS DISTINCT FROM (EXCLUDED.description, EXCLUDED.prompt, EXCLUDED.input_types, EXCLUDED.output_types)";

async fn sync_experts(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let mut synced = 0usize;

    for expert in loader.load_experts() {
        // `merge_enabled` is set on INSERT only — it is admin state the sync
        // must never revert (same treatment as `enabled` / `memory`).
        sqlx::query(EXPERT_UPSERT)
        .bind(tenant_id)
        .bind(&expert.axis)
        .bind(&expert.description)
        .bind(&expert.raw_prompt)
        .bind(&expert.input_types)
        .bind(&expert.output_types)
        .bind(expert.merge_enabled)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| tracing::error!(axis = %expert.axis, error = %e, "failed to sync expert"))?;
        synced += 1;
    }
    tracing::debug!(%tenant_id, synced, "synced experts");
    Ok(synced)
}

/// The builtin upsert for `prompt_snippets`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const SNIPPET_UPSERT: &str = "INSERT INTO prompt_snippets \
               (tenant_id, snippet_key, label, content, is_builtin, suppressed) \
             VALUES ($1, $2, $3, $4, true, false) \
             ON CONFLICT (tenant_id, snippet_key) DO UPDATE SET \
               label = EXCLUDED.label, content = EXCLUDED.content, updated_at = now() \
             WHERE prompt_snippets.is_builtin AND NOT prompt_snippets.suppressed \
               AND (prompt_snippets.label, prompt_snippets.content) \
                   IS DISTINCT FROM (EXCLUDED.label, EXCLUDED.content)";

async fn sync_snippets(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let seed_snippets = loader.load_snippets();
    if seed_snippets.is_empty() {
        return Ok(0);
    }

    // Per-row UPSERT of each builtin snippet. The `WHERE is_builtin AND NOT
    // suppressed` guard overwrites builtins, preserves a user-edited row
    // (`is_builtin=false`), and never resurrects a suppressed one; a fresh row
    // inserts. Builtins removed from disk are left in place (no create endpoint
    // exists, so every row is a builtin or a future user snippet) — same as the
    // old blob sync.
    let mut synced = 0usize;
    for s in &seed_snippets {
        sqlx::query(SNIPPET_UPSERT)
        .bind(tenant_id)
        .bind(&s.key)
        .bind(&s.label)
        .bind(&s.content)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::error!(%tenant_id, key = %s.key, "failed to sync prompt snippet: {e}")
        })?;
        synced += 1;
    }
    tracing::debug!(%tenant_id, synced, "synced prompt snippets");
    Ok(synced)
}

/// The builtin upsert for `qos_classes`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const QOS_CLASS_UPSERT: &str = "INSERT INTO qos_classes \
               (tenant_id, class_key, name, description, rank, sheddable, queue_ttl_ms, is_builtin, suppressed) \
             SELECT $1, $2, $3, $4, $5, $6, $7, true, false \
             WHERE NOT EXISTS (SELECT 1 FROM qos_classes q \
                               WHERE q.tenant_id = $1 AND q.name = $3 AND q.class_key <> $2) \
             ON CONFLICT (tenant_id, class_key) DO UPDATE SET \
               name = EXCLUDED.name, description = EXCLUDED.description, rank = EXCLUDED.rank, \
               sheddable = EXCLUDED.sheddable, queue_ttl_ms = EXCLUDED.queue_ttl_ms, updated_at = now() \
             WHERE qos_classes.is_builtin AND NOT qos_classes.suppressed \
               AND (qos_classes.name, qos_classes.description, qos_classes.rank, qos_classes.sheddable, qos_classes.queue_ttl_ms) \
                   IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.description, EXCLUDED.rank, EXCLUDED.sheddable, EXCLUDED.queue_ttl_ms)";

/// Per-row UPSERT of each builtin QoS class, plus the tenant's stars.
///
/// Only the seed-owned columns are written. The stars (`is_default`,
/// `mint_default_for`) are tenant state an admin may move, so they are placed by
/// `ensure_qos_class_stars` only where the tenant has none — writing them here
/// would either put a moved star back on the next boot, or collide with the
/// partial unique index and fail the whole seed group.
///
/// The insert stands down when another class already holds the name: the name is
/// unique per tenant, and a tenant that predates a builtin may have created a
/// class of its own with that name. Skipping one builtin is a far better outcome
/// than aborting the seed group, which would leave the tenant unstamped.
async fn sync_qos_classes(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let classes = loader.load_qos_classes();
    if classes.is_empty() {
        return Ok(0);
    }
    // Two questions, because the stars answer to two different rules.
    //
    // The mint stars are tenant STATE an admin may move, and may take off
    // entirely (new keys then inherit their workspace), so placing one whenever
    // none is held would put a REMOVED one back on the next boot. What cannot
    // legitimately be absent is the DEFAULT: the API refuses to delete it, and a
    // tenant without one resolves no class for any workspace — no rank, no
    // deadline, no mint default, silently and for ever. So the stars are placed
    // whenever the tenant holds no default, which covers the first pass and a
    // tenant that predates the classes.
    let has_default: bool = sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (SELECT 1 FROM qos_classes \
         WHERE tenant_id = $1 AND is_default AND NOT suppressed)",
    )
    .bind(tenant_id)
    .fetch_one(&mut *conn)
    .await?;
    // The Agent workspace's pin is the other rule: it is placed once, when the
    // tenant first gets classes at all, so a repair pass cannot re-pin a
    // workspace an admin deliberately put back on the tenant default.
    let first_time: bool =
        sqlx::query_scalar::<_, i64>("SELECT count(*) FROM qos_classes WHERE tenant_id = $1")
            .bind(tenant_id)
            .fetch_one(&mut *conn)
            .await?
            == 0;
    let mut synced = 0usize;
    for c in &classes {
        sqlx::query(QOS_CLASS_UPSERT)
        .bind(tenant_id)
        .bind(&c.key)
        .bind(&c.name)
        .bind(&c.description)
        .bind(c.rank)
        .bind(c.sheddable)
        .bind(c.queue_ttl_ms)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::error!(%tenant_id, key = %c.key, "failed to sync QoS class: {e}")
        })?;
        synced += 1;
    }
    if !has_default {
        ensure_qos_class_stars(&mut *conn, tenant_id, loader).await?;
    }
    if first_time {
        ensure_agent_workspace_qos_class(&mut *conn, tenant_id).await?;
    }
    tracing::debug!(%tenant_id, synced, first_time, "synced QoS classes");
    Ok(synced)
}

/// Give the tenant a default class and one mint default per kind.
///
/// Called only where the tenant holds no default class — its first pass, or a
/// pass that repairs one left without. Each statement is still guarded by the
/// absence of that star, so running it twice cannot move one; the caller's own
/// guard is what keeps a mint star an admin REMOVED from coming back.
pub(crate) async fn ensure_qos_class_stars(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
    loader: &SeedLoader,
) -> Result<(), sqlx::Error> {
    for c in loader.load_qos_classes() {
        if c.is_default {
            sqlx::query(
                "UPDATE qos_classes SET is_default = true, updated_at = now() \
                 WHERE tenant_id = $1 AND class_key = $2 AND NOT suppressed \
                   AND NOT EXISTS (SELECT 1 FROM qos_classes q \
                                   WHERE q.tenant_id = $1 AND q.is_default)",
            )
            .bind(tenant_id)
            .bind(&c.key)
            .execute(&mut *conn)
            .await?;
        }
        if let Some(kind) = &c.mint_default_for {
            sqlx::query(
                "UPDATE qos_classes SET mint_default_for = $3, updated_at = now() \
                 WHERE tenant_id = $1 AND class_key = $2 AND NOT suppressed \
                   AND NOT EXISTS (SELECT 1 FROM qos_classes q \
                                   WHERE q.tenant_id = $1 AND q.mint_default_for = $3)",
            )
            .bind(tenant_id)
            .bind(&c.key)
            .bind(kind)
            .execute(&mut *conn)
            .await?;
        }
    }
    Ok(())
}

/// Put the Agent workspace on the class that unattended traffic defaults to.
///
/// Only while it has none, and only on the pass that creates the tenant's
/// classes: the agent analyses other people's traffic and must not be served
/// ahead of them, but an admin who deliberately puts it back on the tenant
/// default must not find it pinned again after a restart.
pub(crate) async fn ensure_agent_workspace_qos_class(
    conn: &mut Scoped,
    tenant_id: uuid::Uuid,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        "UPDATE workspaces SET qos_class_id = q.id \
         FROM qos_classes q \
         WHERE workspaces.tenant_id = $1 AND workspaces.role = 'agent' \
           AND workspaces.qos_class_id IS NULL \
           AND q.tenant_id = $1 AND q.mint_default_for = 'automation' AND NOT q.suppressed",
    )
    .bind(tenant_id)
    .execute(conn)
    .await
    .map(drop)
}

/// The builtin upsert for `apps`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const APP_UPSERT: &str = "INSERT INTO apps \
               (tenant_id, app_key, name, description, url, is_builtin, ua_patterns, referer_patterns, prompt_patterns, suppressed) \
             VALUES ($1, $2, $3, $4, $5, true, $6, $7, $8, false) \
             ON CONFLICT (tenant_id, app_key) DO UPDATE SET \
               name = EXCLUDED.name, description = EXCLUDED.description, url = EXCLUDED.url, \
               ua_patterns = EXCLUDED.ua_patterns, referer_patterns = EXCLUDED.referer_patterns, \
               prompt_patterns = EXCLUDED.prompt_patterns, updated_at = now() \
             WHERE apps.is_builtin AND NOT apps.suppressed \
               AND (apps.name, apps.description, apps.url, apps.ua_patterns, apps.referer_patterns, apps.prompt_patterns) \
                   IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.description, EXCLUDED.url, EXCLUDED.ua_patterns, EXCLUDED.referer_patterns, EXCLUDED.prompt_patterns)";

async fn sync_app_registry(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let builtins = loader.load_apps();
    if builtins.is_empty() {
        return Ok(0);
    }

    // Per-row UPSERT of each builtin into the `apps` table. The
    // `WHERE is_builtin AND NOT suppressed` guard overwrites builtins, preserves
    // a user-edited row (`is_builtin=false`), and never resurrects a soft-deleted
    // (`suppressed=true`) builtin; a fresh row inserts. Orphan builtins (seed
    // removed from disk) are left in place, matching the old blob sync.
    let mut synced = 0usize;
    for b in &builtins {
        sqlx::query(APP_UPSERT)
        .bind(tenant_id)
        .bind(&b.id)
        .bind(&b.name)
        .bind(&b.description)
        .bind(&b.url)
        .bind(&b.ua_patterns)
        .bind(&b.referer_patterns)
        .bind(&b.prompt_patterns)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| tracing::error!(%tenant_id, id = %b.id, "failed to sync app: {e}"))?;
        synced += 1;
    }
    tracing::debug!(%tenant_id, synced, "synced app registry");
    Ok(synced)
}

/// The builtin upsert for `client_profiles`: it rewrites only a builtin the
/// user has not edited or suppressed, and only when a seeded column differs —
/// the `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked
/// by `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const CLIENT_PROFILE_UPSERT: &str = "INSERT INTO client_profiles \
               (tenant_id, profile_key, label, homepage, supports_llm, supports_mcp, launch_command, templates, is_builtin, suppressed) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, true, false) \
             ON CONFLICT (tenant_id, profile_key) DO UPDATE SET \
               label = EXCLUDED.label, homepage = EXCLUDED.homepage, supports_llm = EXCLUDED.supports_llm, \
               supports_mcp = EXCLUDED.supports_mcp, launch_command = EXCLUDED.launch_command, \
               templates = EXCLUDED.templates, updated_at = now() \
             WHERE client_profiles.is_builtin AND NOT client_profiles.suppressed \
               AND (client_profiles.label, client_profiles.homepage, client_profiles.supports_llm, client_profiles.supports_mcp, client_profiles.launch_command, client_profiles.templates) \
                   IS DISTINCT FROM (EXCLUDED.label, EXCLUDED.homepage, EXCLUDED.supports_llm, EXCLUDED.supports_mcp, EXCLUDED.launch_command, EXCLUDED.templates)";

async fn sync_client_profiles(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let builtins = loader.load_client_profiles();
    if builtins.is_empty() {
        return Ok(0);
    }

    // Per-row UPSERT of each builtin. The `WHERE is_builtin AND NOT suppressed`
    // guard means a user edit (`is_builtin=false`) is preserved and a deleted
    // builtin (`suppressed=true`) is never resurrected; a fresh row inserts.
    let mut synced = 0usize;
    for b in &builtins {
        let templates = match serde_json::to_value(&b.templates) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(%tenant_id, id = %b.id, "skipping client profile with bad templates: {e}");
                continue;
            }
        };
        sqlx::query(CLIENT_PROFILE_UPSERT)
        .bind(tenant_id)
        .bind(&b.id)
        .bind(&b.label)
        .bind(&b.homepage)
        .bind(b.supports_llm)
        .bind(b.supports_mcp)
        .bind(&b.launch_command)
        .bind(&templates)
        .execute(&mut *conn)
        .await
        .inspect_err(|e| {
            tracing::error!(%tenant_id, id = %b.id, "failed to sync client profile: {e}")
        })?;
        synced += 1;
    }

    // Orphan cleanup: drop builtin rows whose seed file no longer exists on disk
    // (a builtin the user never customised — `is_builtin` still true). User rows
    // (`is_builtin=false`) and deleted (suppressed) rows are untouched: a delete
    // is final, so a key the seed ships again later must not come back.
    let keys: Vec<String> = builtins.iter().map(|b| b.id.clone()).collect();
    sqlx::query(
        "DELETE FROM client_profiles \
         WHERE tenant_id = $1 AND is_builtin AND NOT suppressed AND profile_key <> ALL($2)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .execute(&mut *conn)
    .await
    .inspect_err(|e| {
        tracing::error!(%tenant_id, "failed to prune orphan builtin client profiles: {e}")
    })?;
    tracing::debug!(%tenant_id, synced, "synced client profiles");
    Ok(synced)
}

/// The builtin upsert for `destination_lists`: it rewrites only a builtin the
/// user has not edited or deleted, and only when a seeded column differs — the
/// `IS DISTINCT FROM` tuples list exactly the columns `SET` writes (locked by
/// `every_builtin_upsert_compares_exactly_the_columns_it_sets`).
pub(crate) const DESTINATION_LIST_UPSERT: &str = "INSERT INTO destination_lists \
               (tenant_id, seed_key, name, description, entries, is_builtin, suppressed) \
             VALUES ($1, $2, $3, $4, $5, true, false) \
             ON CONFLICT (tenant_id, seed_key) DO UPDATE SET \
               name = EXCLUDED.name, description = EXCLUDED.description, entries = EXCLUDED.entries, updated_at = now() \
             WHERE destination_lists.is_builtin AND NOT destination_lists.suppressed \
               AND (destination_lists.name, destination_lists.description, destination_lists.entries) \
                   IS DISTINCT FROM (EXCLUDED.name, EXCLUDED.description, EXCLUDED.entries)";

async fn sync_destination_lists(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let (seeds, complete) = loader.load_destination_lists_checked();
    if seeds.is_empty() {
        return Ok(0);
    }
    let mut synced = 0usize;
    for s in &seeds {
        // A list the admin created under the seed's name keeps it: the seed
        // row is not written (the name is unique per tenant).
        let taken: bool = sqlx::query_scalar(
            "SELECT EXISTS (SELECT 1 FROM destination_lists \
             WHERE tenant_id = $1 AND name = $2 AND seed_key IS DISTINCT FROM $3)",
        )
        .bind(tenant_id)
        .bind(&s.name)
        .bind(&s.key)
        .fetch_one(&mut *conn)
        .await?;
        if taken {
            tracing::warn!(%tenant_id, key = %s.key, "a destination list holds the seed's name: seed skipped");
            continue;
        }
        sqlx::query(DESTINATION_LIST_UPSERT)
            .bind(tenant_id)
            .bind(&s.key)
            .bind(&s.name)
            .bind(&s.description)
            .bind(serde_json::json!(s.entries))
            .execute(&mut *conn)
            .await
            .inspect_err(|e| tracing::error!(%tenant_id, key = %s.key, "failed to sync destination list: {e}"))?;
        synced += 1;
    }
    // Orphan cleanup, as the other seeded collections: a builtin the seed no
    // longer ships goes; an edited or deleted one stays, and so does one a
    // consumer attaches — removing it would silently drop the attachment (a
    // block among them) with no admin action. Only after a complete
    // load: a seed file that failed to read is not a list the seed dropped.
    if !complete {
        tracing::warn!(%tenant_id, "a destination list seed did not load: orphan cleanup skipped");
        return Ok(synced);
    }
    let keys: Vec<String> = seeds.iter().map(|s| s.key.clone()).collect();
    // The candidates are locked first, in a statement of their own: an attach
    // in flight share-locks its lists, so the delete's own statement — a fresh
    // snapshot once the lock is held — sees an attachment that committed while
    // it waited.
    let mut tx = conn.begin().await?;
    sqlx::query(
        "SELECT 1 FROM destination_lists \
         WHERE tenant_id = $1 AND is_builtin AND NOT suppressed AND seed_key <> ALL($2) FOR UPDATE",
    )
    .bind(tenant_id)
    .bind(&keys)
    .execute(&mut *tx)
    .await?;
    sqlx::query(
        "DELETE FROM destination_lists l \
         WHERE l.tenant_id = $1 AND l.is_builtin AND NOT l.suppressed AND l.seed_key <> ALL($2) \
           AND NOT EXISTS (SELECT 1 FROM web_destination_lists w WHERE w.tenant_id = l.tenant_id AND w.list_id = l.id) \
           AND NOT EXISTS (SELECT 1 FROM client_access_destinations d \
                           WHERE d.tenant_id = l.tenant_id AND d.list_id = l.id)",
    )
    .bind(tenant_id)
    .bind(&keys)
    .execute(&mut *tx)
    .await
    .inspect_err(|e| tracing::error!(%tenant_id, "failed to prune orphan builtin destination lists: {e}"))?;
    tx.commit().await?;
    tracing::debug!(%tenant_id, synced, "synced destination lists");
    Ok(synced)
}

async fn sync_tool_rules(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    let seed_rules = loader.load_tool_rules();
    if seed_rules.is_empty() {
        return Ok(0);
    }

    // Ensure the default tool profile exists — the shared base. Builtins live on
    // it (profile_id is NOT NULL), so its id stamps every seeded rule.
    let default_tool_id = ensure_default_tool_profile(&mut *conn, tenant_id)
        .await
        .inspect_err(|e| {
            tracing::error!(%tenant_id, "ensure default tool profile (sync) failed: {e}")
        })?;

    // Per-row UPSERT of each builtin. Each statement is independent and idempotent
    // (`upsert_builtin_rule`'s `WHERE is_builtin AND NOT suppressed` guard refreshes
    // a pristine builtin, no-ops a user-edited or user-deleted one), so there is no
    // whole-collection read-modify-write to lock or to clobber a concurrent admin
    // edit. `seq` spaces builtins in seed order on first insert (preserved on
    // refresh). A seed row that fails to deserialize is skipped, never treated as
    // empty (which would otherwise reseed nothing / drop content).
    let mut seq: i64 = 0;
    let mut synced = 0usize;
    for seed in &seed_rules {
        let rule: streamscope_core::config::tool_rules::Rule =
            match serde_json::from_value(seed.clone()) {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        seed_id = ?seed.get("id").and_then(|v| v.as_str()),
                        error = %e,
                        "skipping malformed builtin tool rule seed"
                    );
                    continue;
                }
            };
        crate::routes::tool_rules::upsert_builtin_rule(
            &mut *conn,
            tenant_id,
            &rule,
            seq,
            default_tool_id,
        )
        .await
        .inspect_err(|e| tracing::error!(%tenant_id, error = %e, "failed to sync tool rule"))?;
        synced += 1;
        seq += crate::routes::tool_rules::SEQ_STEP;
    }
    tracing::debug!(%tenant_id, synced, "synced tool risk rules");
    Ok(synced)
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Tool field profiles — per-(tool, field) normaliser registry
// ---------------------------------------------------------------------------
//
// Same provenance / sync pattern as `tool_rules`: one row per profile in the
// `tool_field_profiles` table, per-row `is_builtin` lets startup sync overwrite
// untouched builtins without clobbering operator edits, and a `suppressed` row
// (set on delete) keeps a deleted builtin from resurrecting on restart.

async fn sync_tool_field_profiles(
    tenant_id: uuid::Uuid,
    conn: &mut Scoped,
    loader: &SeedLoader,
) -> Result<usize, sqlx::Error> {
    use streamscope_core::config::tool_rules::FieldProfile;

    let seed_profiles = loader.load_tool_field_profiles();
    if seed_profiles.is_empty() {
        return Ok(0);
    }

    // Per-row UPSERT of each builtin, in seed order (gap-spaced `seq`). The
    // canonical `upsert_builtin_profile` guards `WHERE is_builtin AND NOT
    // suppressed` so user edits and soft-deleted builtins are preserved.
    let step = crate::routes::tool_field_profiles::SEQ_STEP;
    let mut seq = step;
    let mut synced = 0usize;
    for raw in &seed_profiles {
        let profile: FieldProfile = match serde_json::from_value(raw.clone()) {
            Ok(p) => p,
            Err(e) => {
                tracing::warn!(%tenant_id, error = %e, "skipping malformed tool field profile seed");
                continue;
            }
        };
        if profile.id.is_none() {
            tracing::warn!(%tenant_id, "skipping tool field profile seed with no id");
            continue;
        }
        crate::routes::tool_field_profiles::upsert_builtin_profile(
            &mut *conn, tenant_id, &profile, seq,
        )
        .await
        .inspect_err(|e| tracing::error!(%tenant_id, "failed to sync tool field profile: {e}"))?;
        synced += 1;
        seq += step;
    }
    tracing::debug!(%tenant_id, synced, "synced tool field profiles");
    Ok(synced)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routes::{tool_field_profiles::TOOL_FIELD_PROFILE_UPSERT, tool_rules::TOOL_RULE_UPSERT};

    /// The columns a statement writes from `EXCLUDED` (`col = EXCLUDED.col`),
    /// and the two tuples its `IS DISTINCT FROM` guard compares, in order.
    fn guard_columns(table: &str, sql: &str) -> (Vec<String>, Vec<String>, Vec<String>) {
        let sql = sql.split_whitespace().collect::<Vec<_>>().join(" ");
        let update = sql.split("DO UPDATE SET ").nth(1).unwrap_or_default();
        let set = update.split(" WHERE ").next().unwrap_or_default();
        // Every SET item is a seeded column copied from EXCLUDED, or one of the
        // two constants an upsert stamps; any other form is a column the guard
        // could not be checked against.
        let set_cols = set
            .split(", ")
            .filter_map(|item| {
                let (col, value) = item.split_once(" = ").unwrap_or((item, ""));
                if value == format!("EXCLUDED.{col}") {
                    Some(col.to_string())
                } else {
                    assert!(
                        matches!(item, "updated_at = now()" | "is_builtin = true"),
                        "{table}: unrecognised SET item `{item}`"
                    );
                    None
                }
            })
            .collect();
        let guard = update.split(" WHERE ").nth(1).unwrap_or_default();
        let tuple = |s: &str, prefix: &str| -> Vec<String> {
            s.split(", ").map(|c| c.strip_prefix(prefix).unwrap_or("<unprefixed>").to_string()).collect()
        };
        let left = guard
            .split(" AND (")
            .nth(1)
            .and_then(|s| s.split(") IS DISTINCT FROM (").next())
            .map(|s| tuple(s, &format!("{table}.")))
            .unwrap_or_default();
        let right = guard
            .split(") IS DISTINCT FROM (")
            .nth(1)
            .and_then(|s| s.strip_suffix(')'))
            .map(|s| tuple(s, "EXCLUDED."))
            .unwrap_or_default();
        (set_cols, left, right)
    }

    #[test]
    fn every_builtin_upsert_compares_exactly_the_columns_it_sets() {
        for (table, sql) in [
            ("transform_programs", SCRIPT_UPSERT),
            ("mcp_catalog", MCP_CATALOG_UPSERT),
            ("agent_experts", EXPERT_UPSERT),
            ("prompt_snippets", SNIPPET_UPSERT),
            ("qos_classes", QOS_CLASS_UPSERT),
            ("apps", APP_UPSERT),
            ("client_profiles", CLIENT_PROFILE_UPSERT),
            ("destination_lists", DESTINATION_LIST_UPSERT),
            ("tool_policy_rules", TOOL_RULE_UPSERT),
            ("tool_field_profiles", TOOL_FIELD_PROFILE_UPSERT),
        ] {
            let (set, left, right) = guard_columns(table, sql);
            assert!(!set.is_empty(), "{table}: no seeded column found in SET");
            assert_eq!(left, set, "{table}: the row tuple must list exactly the SET columns, in order");
            assert_eq!(right, set, "{table}: the EXCLUDED tuple must list exactly the SET columns, in order");
        }
    }

    /// The conflict arm row-locks each existing entry in the order the SELECT
    /// feeds it, so the feed must be the existing rows' id order — the order
    /// every other multi-entry catalog writer locks in — and the join that
    /// supplies the id must name the conflict target's identity, or the order
    /// is the seed file's again.
    #[test]
    fn the_catalog_upsert_locks_existing_rows_in_id_order() {
        let sql = catalog_upsert_sql().split_whitespace().collect::<Vec<_>>().join(" ");
        let feed = sql
            .split(" ON CONFLICT ")
            .next()
            .unwrap_or_default();
        let conflict = sql.split(" ON CONFLICT ").nth(1).unwrap_or_default();
        assert!(
            conflict.starts_with("(tenant_id, server_id, provider_key, model) "),
            "the conflict target is the identity the join below must match: {conflict}"
        );
        assert!(
            feed.ends_with(" ORDER BY mc.id NULLS LAST, canonical_provider_key(u.provider), u.model"),
            "the source rows must reach the conflict arm in existing-row id order, new rows by identity: {feed}"
        );
        for clause in [
            "LEFT JOIN model_catalog mc ON mc.tenant_id = $19::uuid",
            "AND mc.server_id IS NULL",
            "AND mc.provider_key = canonical_provider_key(u.provider)",
            "AND mc.model = u.model",
        ] {
            assert!(feed.contains(clause), "the id join must match the conflict target: missing `{clause}`");
        }
    }
}
