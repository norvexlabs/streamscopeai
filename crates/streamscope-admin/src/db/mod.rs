//! Database access, with tenant isolation enforced by the type system.
//!
//! [`Db`] owns the connection pools and keeps them **private to this module**, and
//! the crate's `clippy.toml` makes naming a raw pool, connection or transaction
//! anywhere outside it a build failure. Every query therefore goes through one of
//! these doors, each explicit about tenancy:
//!
//! * [`Db::tenant`] — the 99% path. A [`tenant::TenantConn`] whose connection has
//!   `app.tenant_id` set for the session, so PostgreSQL RLS confines every query
//!   on it to that tenant. No transaction.
//! * [`Db::begin_tenant`] / [`tenant::TenantConn::begin`] — a
//!   [`tenant::TenantTx`], the same scoping for a multi-statement transaction,
//!   including tenant creation, where the `tenants` row and its RLS-protected
//!   children must land atomically. Only `commit()` persists it.
//! * [`Db::global`] / [`Db::begin_global`] — the global tables, which takes a
//!   [`Global`] reason: the caller names *why* the tenant dimension does not
//!   apply, so every exception is explicit in the source and greppable by variant.
//!   These connections run as `streamscope_global`, which holds no privilege on
//!   any tenant table: a tenant query issued here is `permission denied`.
//! * [`Db::begin_ingest`] — an [`tenant::IngestTx`], the edge ingest writer's
//!   transaction, as `streamscope_ingest`: it writes the ingest tables of every
//!   tenant of one request, each statement naming its rows' `tenant_id`.
//! * [`listener`] — a `LISTEN` connection outside the pool, for notifications.
//! * [`Db::maintenance`] — a dedicated runtime-role connection for work that needs
//!   one held outside a transaction: partition DDL and its `VACUUM`, a leader's session
//!   advisory lock. Takes a [`Maintenance`] reason.
//!
//! Both tenant doors hand out a [`tenant::Scoped`] connection, which only this
//! module can make: a repository function taking `&mut Scoped` cannot be given an
//! unscoped connection.
//!
//! # RLS is fail-closed, and the special roles are reached only on purpose
//!
//! The runtime role is `NOBYPASSRLS` and every tenant-scoped table is `ENABLE` +
//! `FORCE ROW LEVEL SECURITY` (FORCE is what strips the table owner's implicit
//! bypass), with a policy of `tenant_id = current_tenant_id()` — the single
//! predicate every tenant policy uses (see `001_init.sql`), which returns NULL
//! for an unscoped, empty, or malformed tenant GUC and so matches zero rows.
//! On top of that, the pool's `after_release` hook RESETs `app.tenant_id` and the
//! role, and releases every session advisory lock, when a connection goes back —
//! and drops the connection outright if that fails. A connection never carries a
//! session-level lock or setting across a return to the pool.
//!
//! The runtime role is granted `streamscope_global` and `streamscope_ingest`
//! WITH INHERIT FALSE: it holds their privileges only after a `SET ROLE`, which
//! only the global pool and [`tenant::IngestTx`] issue. [`Db::check_roles`]
//! refuses to start on a database where it inherits either, or is a member of
//! `streamscope_lookup` at all. There is deliberately **no** door that reads a
//! tenant table across tenants: iterate with a `TenantConn` per tenant (see
//! [`tenant::for_each_tenant`]), or call a lookup function (`001_init.sql`).

// The one module that may name the raw pool, connection and transaction types.
#![allow(clippy::disallowed_types, clippy::disallowed_methods)]

pub mod migrations;
pub mod tenant;

#[cfg(test)]
mod conflict_targets;

use sqlx::pool::PoolConnection;
use sqlx::{PgConnection, PgPool, Postgres, Transaction};

use tenant::{IngestTx, TenantConn, TenantId, TenantTx};

/// The application database handle.
///
/// Wraps the pools so that tenant scoping is a property of the *type*, not of
/// reviewer discipline. See the module docs for the access doors.
#[derive(Clone)]
pub struct Db {
    pool: PgPool,
    /// Connections that run as `streamscope_global` for their whole life.
    global: PgPool,
    /// The setting `pool`'s URL was read from, as a refusal names it.
    url_setting: &'static str,
}

/// Why a query runs on the global pool, outside the tenant dimension.
///
/// Each variant is a claim that the tenant dimension does not apply to the query.
/// Anything that does not fit one of them belongs on [`Db::tenant`]: a tenant
/// table read through the global door is refused (`permission denied`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Global {
    /// No tenant is known yet — this query is what resolves it: login, an OAuth
    /// token exchange, or mapping a slug / credential to its tenant (through a
    /// lookup function where the credential lives in a tenant table).
    PreAuth,
    /// The `tenants` table itself: the root registry, which carries no RLS because
    /// it is what tenancy is defined *by*.
    TenantRegistry,
    /// A deliberate iteration over all tenants, which acquires a tenant-scoped
    /// connection per tenant for the actual reads.
    TenantIteration,
    /// `pg_catalog` introspection — server-level stats with no tenant dimension.
    CatalogStats,
    /// A table that carries no RLS policy because it has no tenant dimension —
    /// marked `-- intentional: no RLS, <reason>` in its migration.
    Infra,
}

/// Why a dedicated runtime-role connection is held outside a transaction.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Maintenance {
    /// `CREATE` / `DETACH` / `DROP` of a partitioned table's child partitions, the
    /// `pg_catalog` reads that find them, and the `VACUUM` before a detach (which
    /// cannot run inside a transaction).
    PartitionDdl,
    /// A leader's session-level advisory lock, held on the connection for as long
    /// as the leader works (see `crate::leader`).
    LeaderLock,
}

impl Db {
    /// A handle over pools whose every acquire fails fast (port 1 never
    /// listens): for router tests that must not reach a database.
    #[cfg(test)]
    pub fn unreachable_for_test() -> Self {
        let lazy = || {
            sqlx::postgres::PgPoolOptions::new()
                .max_connections(1)
                // Bound the failed-connect wait: a test asserting 503-on-readiness must
                // not sit on the default multi-second acquire timeout.
                .acquire_timeout(std::time::Duration::from_millis(250))
                .connect_lazy("postgres://absent:absent@127.0.0.1:1/absent")
                .expect("lazy pool from a well-formed URL")
        };
        Self { pool: lazy(), global: lazy(), url_setting: "DATABASE_URL" }
    }

    /// Acquire a connection scoped to `tenant_id`, activating RLS for its lifetime.
    ///
    /// This is the path virtually all query code should take.
    pub async fn tenant(&self, tenant_id: TenantId) -> Result<TenantConn, sqlx::Error> {
        TenantConn::acquire(self, tenant_id).await
    }

    /// Begin a transaction on a fresh connection, scoped to `tenant_id` for the
    /// transaction's lifetime.
    ///
    /// Use when several writes must be atomic and no [`TenantConn`] is held yet
    /// (with one, call [`TenantConn::begin`] — one connection per request path).
    /// This also covers tenant *creation*, where the `tenants` row and its
    /// RLS-protected children are inserted in one transaction: the scope is set
    /// before the row it names exists, which is exactly what those inserts need.
    pub async fn begin_tenant(&self, tenant_id: TenantId) -> Result<TenantTx<'static>, sqlx::Error> {
        TenantTx::begin(self, tenant_id).await
    }

    /// The global pool, for a query to which the tenant dimension does not apply.
    ///
    /// `why` documents the exception at the call site. Its connections run as
    /// `streamscope_global`, which may read and write only the global tables:
    /// a tenant table here is `permission denied` — you want [`Db::tenant`].
    pub fn global(&self, why: Global) -> &PgPool {
        let _ = why;
        &self.global
    }

    /// Begin a transaction on the global pool — [`Db::global`]'s rules, for
    /// several statements that must land together.
    pub async fn begin_global(&self, why: Global) -> Result<GlobalTx<'static>, sqlx::Error> {
        let _ = why;
        Ok(GlobalTx { tx: self.global.begin().await? })
    }

    /// Begin the edge ingest writer's transaction (see [`IngestTx`]).
    pub async fn begin_ingest(&self) -> Result<IngestTx<'static>, sqlx::Error> {
        IngestTx::begin(self).await
    }

    /// A dedicated runtime-role connection, held by the caller until dropped (or,
    /// for a leader lock, until `crate::leader::release_leader`).
    pub async fn maintenance(&self, why: Maintenance) -> Result<MaintenanceConn, sqlx::Error> {
        let _ = why;
        Ok(MaintenanceConn { conn: self.pool.acquire().await? })
    }

    /// Open connections, for the `/metrics` gauge. A pool statistic, not a query.
    pub fn open_connections(&self) -> u32 {
        self.pool.size() + self.global.size()
    }

    /// Idle connections, for the `/metrics` gauge. A pool statistic, not a query.
    pub fn idle_connections(&self) -> usize {
        self.pool.num_idle() + self.global.num_idle()
    }

    /// A connectivity probe on both pools (`SELECT 1`, which touches no table):
    /// the tenant pool every tenant request and the ingest draw from, and the
    /// global pool edge sync, edge auth and sign-in draw from — a replica one of
    /// them cannot serve is not ready.
    pub async fn ping(&self) -> Result<(), sqlx::Error> {
        sqlx::query("SELECT 1").execute(&self.pool).await?;
        sqlx::query("SELECT 1").execute(&self.global).await.map(|_| ())
    }

    /// Refuse a database whose role grants would let the runtime role read across
    /// tenants without asking: it must not be a superuser or bypass RLS, must hold
    /// `streamscope_global` and `streamscope_ingest` only as roles it may SET
    /// (never inherit, directly or through another role), and be no member of
    /// `streamscope_lookup` at all. Run once at startup, before anything serves —
    /// after the runtime pool's server and database pass the same version and
    /// locale check as the migration pool's (`migrations::check_server`): the
    /// two URLs are separate settings and may name different databases.
    pub async fn check_roles(&self) -> anyhow::Result<()> {
        migrations::check_server(&self.pool, self.url_setting).await?;
        let (login, unconfined): (String, bool) = sqlx::query_as(
            "SELECT session_user::text, rolsuper OR rolbypassrls FROM pg_roles WHERE rolname = session_user",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reading the runtime role failed: {e}"))?;
        if unconfined {
            anyhow::bail!(
                "the runtime role '{login}' is a superuser or has BYPASSRLS — every tenant's rows would be \
                 visible to it: set DATABASE_URL to a NOBYPASSRLS role (streamscope_app)"
            );
        }
        let (inherits, lookup, can_set): (Vec<String>, bool, bool) = sqlx::query_as(
            "SELECT                  ARRAY(SELECT r FROM unnest(ARRAY['streamscope_global', 'streamscope_ingest', 'streamscope_lookup']) r                         WHERE pg_has_role(current_user, r, 'USAGE')),                  pg_has_role(current_user, 'streamscope_lookup', 'MEMBER'),                  pg_has_role(current_user, 'streamscope_global', 'SET')                      AND pg_has_role(current_user, 'streamscope_ingest', 'SET')",
        )
        .fetch_one(&self.pool)
        .await
        .map_err(|e| anyhow::anyhow!("reading the runtime role's grants failed: {e}"))?;
        if !inherits.is_empty() {
            anyhow::bail!(
                "the runtime role inherits the privileges of {}: grant streamscope_global and \
                 streamscope_ingest WITH INHERIT FALSE, SET TRUE, and streamscope_lookup only to the \
                 migration role",
                inherits.join(", ")
            );
        }
        if lookup {
            anyhow::bail!("the runtime role is a member of streamscope_lookup: grant it only to the migration role");
        }
        if !can_set {
            anyhow::bail!(
                "the runtime role may not SET ROLE streamscope_global and streamscope_ingest: grant both \
                 WITH INHERIT FALSE, SET TRUE"
            );
        }
        Ok(())
    }

    /// The tenant-door pool, unconditionally. Visible only inside `db` (and its
    /// children), so that `db::tenant` can acquire the connection it is about to
    /// scope. Everything outside this module goes through the doors — that is the
    /// whole point of the newtype.
    fn pool(&self) -> &PgPool {
        &self.pool
    }
}

/// A transaction on the global pool (see [`Db::begin_global`]).
/// Nothing it writes persists until [`commit`](GlobalTx::commit).
#[must_use = "a GlobalTx persists nothing until commit() — dropping it rolls back"]
pub struct GlobalTx<'c> {
    tx: Transaction<'c, Postgres>,
}

impl GlobalTx<'_> {
    /// Persist the transaction, refusing one a failed statement aborted (see
    /// [`refuse_aborted`]).
    pub async fn commit(mut self) -> Result<(), sqlx::Error> {
        refuse_aborted(&mut self.tx).await?;
        self.tx.commit().await
    }

}

impl std::ops::Deref for GlobalTx<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &PgConnection {
        &self.tx
    }
}

impl std::ops::DerefMut for GlobalTx<'_> {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
}

/// Fail if the transaction on `conn` is aborted.
///
/// A statement that fails inside a transaction aborts it, and PostgreSQL answers
/// the COMMIT that follows with a rollback, not an error — so a caller that
/// discarded that statement's error would report success for writes that never
/// landed. In an aborted transaction this probe fails (`25P02`), and the commit
/// with it. A failure undone by rolling back to a savepoint leaves the transaction
/// healthy, and the probe passes. Every transaction door's `commit` runs it.
async fn refuse_aborted(conn: &mut PgConnection) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT 1").execute(conn).await.map(|_| ())
}

/// A dedicated runtime-role connection (see [`Db::maintenance`]).
pub struct MaintenanceConn {
    conn: PoolConnection<Postgres>,
}

impl MaintenanceConn {
    /// Begin a transaction on this connection, e.g. a partition detach.
    pub async fn begin(&mut self) -> Result<MaintenanceTx<'_>, sqlx::Error> {
        Ok(MaintenanceTx { tx: sqlx::Connection::begin(&mut *self.conn).await? })
    }
}

/// A transaction on a [`MaintenanceConn`]. Nothing it writes persists until
/// [`commit`](MaintenanceTx::commit).
#[must_use = "a MaintenanceTx persists nothing until commit() — dropping it rolls back"]
pub struct MaintenanceTx<'c> {
    tx: Transaction<'c, Postgres>,
}

impl MaintenanceTx<'_> {
    /// Persist the transaction, refusing one a failed statement aborted (see
    /// [`refuse_aborted`]).
    pub async fn commit(mut self) -> Result<(), sqlx::Error> {
        refuse_aborted(&mut self.tx).await?;
        self.tx.commit().await
    }
}

impl std::ops::Deref for MaintenanceTx<'_> {
    type Target = PgConnection;
    fn deref(&self) -> &PgConnection {
        &self.tx
    }
}

impl std::ops::DerefMut for MaintenanceTx<'_> {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.tx
    }
}

impl std::ops::Deref for MaintenanceConn {
    type Target = PgConnection;
    fn deref(&self) -> &PgConnection {
        &self.conn
    }
}

impl std::ops::DerefMut for MaintenanceConn {
    fn deref_mut(&mut self) -> &mut PgConnection {
        &mut self.conn
    }
}

/// How long a connection of the runtime pool may sit idle inside an open
/// transaction before PostgreSQL ends its session. Well past any legitimate pause
/// (an outbound call belongs outside a transaction); its job is to free the locks
/// of a transaction a bug left open, instead of holding them until a restart.
const IDLE_IN_TRANSACTION_TIMEOUT: &str = "SET idle_in_transaction_session_timeout = '5min'";

/// What `after_release` runs on every returned connection, in one round trip:
/// clear the tenant scope, any role assumed with `SET ROLE`, and any session
/// advisory lock — a leader's [`MaintenanceConn`] dropped without
/// `crate::leader::release_leader` (a panic, a cancelled task) must not carry its
/// lock back into the pool, where no other replica could win it.
const RELEASE_RESET: &str = "RESET app.tenant_id; RESET ROLE; SELECT pg_advisory_unlock_all()";

/// [`RELEASE_RESET`] for the global pool, in the same one round trip: its
/// connections go back to `streamscope_global` rather than to the login role.
const GLOBAL_RELEASE_RESET: &str = "RESET app.tenant_id; SET ROLE streamscope_global; SELECT pg_advisory_unlock_all()";

/// What the global pool's connections run once connected (and, within
/// [`GLOBAL_RELEASE_RESET`], on every return): they are `streamscope_global`
/// for life.
const GLOBAL_ROLE: &str = "SET ROLE streamscope_global";

/// Create the runtime connection pools: the tenant-door pool, and the smaller
/// global pool whose connections run as `streamscope_global`.
///
/// The `after_release` callback runs [`RELEASE_RESET`] when a connection returns to
/// a pool — the safety net beneath the doors. Even if a handler panics before its
/// `TenantConn` drops, the next user of that connection sees zero rows
/// (fail-closed). If the RESET fails, the connection is dropped rather than risk
/// carrying one request's context into another's.
pub async fn create_pool() -> Result<Db, sqlx::Error> {
    let (url_setting, url) = database_url_source();

    let settings = crate::settings::admin_settings();

    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(settings.db_max_connections)
        .acquire_timeout(settings.db_acquire_timeout)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query(IDLE_IN_TRANSACTION_TIMEOUT).execute(conn).await.map(|_| ())
            })
        })
        .after_release(|conn, _meta| {
            Box::pin(async move { Ok(release_reset(conn).await) })
        })
        .connect(&url)
        .await?;

    let global = sqlx::postgres::PgPoolOptions::new()
        .max_connections((settings.db_max_connections / 2).max(4))
        .acquire_timeout(settings.db_acquire_timeout)
        .after_connect(|conn, _meta| {
            Box::pin(async move {
                sqlx::query(IDLE_IN_TRANSACTION_TIMEOUT).execute(&mut *conn).await?;
                sqlx::query(GLOBAL_ROLE).execute(conn).await.map(|_| ())
            })
        })
        .after_release(|conn, _meta| {
            Box::pin(async move {
                Ok(sqlx::raw_sql(GLOBAL_RELEASE_RESET).execute(conn).await.is_ok())
            })
        })
        // Lazy: its first connection switches role, so a missing grant would
        // otherwise read as an unreachable database before `check_roles` can
        // name it.
        .connect_lazy(&url)?;

    Ok(Db { pool, global, url_setting })
}

/// A dedicated `LISTEN` connection as the runtime role, outside the pool: held for
/// a replica's lifetime, it would otherwise pin a pooled connection.
pub async fn listener() -> Result<Listener, sqlx::Error> {
    Ok(Listener(sqlx::postgres::PgListener::connect(&database_url()).await?))
}

/// A [`listener`] connection. It only subscribes and receives — it runs no query,
/// so it cannot serve as an unscoped connection.
pub struct Listener(sqlx::postgres::PgListener);

impl Listener {
    /// Subscribe to `channel`.
    pub async fn listen(&mut self, channel: &str) -> Result<(), sqlx::Error> {
        self.0.listen(channel).await
    }

    /// The next notification, reconnecting on a lost connection.
    pub async fn recv(&mut self) -> Result<sqlx::postgres::PgNotification, sqlx::Error> {
        self.0.recv().await
    }

    /// The next notification, or `None` when the connection was lost (the next
    /// call reconnects).
    pub async fn try_recv(&mut self) -> Result<Option<sqlx::postgres::PgNotification>, sqlx::Error> {
        self.0.try_recv().await
    }
}

/// Run [`RELEASE_RESET`]: `true` keeps the connection, `false` drops it.
async fn release_reset(conn: &mut PgConnection) -> bool {
    sqlx::raw_sql(RELEASE_RESET).execute(conn).await.is_ok()
}

/// The runtime role's connection URL: the pool's, and a [`listener`]'s.
fn database_url() -> String {
    database_url_source().1
}

/// The runtime URL, and the setting it came from (named in a refusal).
fn database_url_source() -> (&'static str, String) {
    match std::env::var("DATABASE_URL") {
        Ok(url) => ("DATABASE_URL", url),
        Err(_) => (
            "the built-in default database URL",
            "postgres://streamscope_app:streamscope@postgres:5432/streamscope".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    /// No tier can fail one statement inside an otherwise healthy request, so what
    /// holds the probe is the source: every transaction door's `commit` must run
    /// `refuse_aborted` before it commits.
    #[test]
    fn every_transaction_commit_refuses_an_aborted_transaction() {
        // Spelled in two halves so this test's own text is not a match.
        let needle = concat!("pub async fn ", "commit(");
        let mut doors = 0;
        for (file, src) in [("db/mod.rs", include_str!("mod.rs")), ("db/tenant.rs", include_str!("tenant.rs"))] {
            for rest in src.split(needle).skip(1) {
                let body = &rest[..rest.find("\n    }\n").expect("a commit body ends")];
                let probe = body.find("refuse_aborted(");
                let commit = body.find(".commit()");
                assert_matches!(
                    (probe, commit),
                    (Some(p), Some(c)) if p < c,
                    "{file}: a commit does not run refuse_aborted before committing:\n{body}"
                );
                doors += 1;
            }
        }
        // Positive control: every door (`TenantTx`, `IngestTx`, `GlobalTx`,
        // `MaintenanceTx`) was found.
        assert_eq!(doors, 4, "expected the four transaction doors' commits");

        // The probe is skipped only for a savepoint, and only `Scoped::begin` on a
        // connection already in a transaction opens one.
        let tenant = include_str!("tenant.rs");
        assert!(tenant.contains(concat!("if !self.", "savepoint {\n            super::refuse_aborted(")), "the savepoint skip is inverted or gone");
        assert!(tenant.contains(concat!("let savepoint = sqlx::Connection::", "is_in_transaction(&self.0);")), "a savepoint is recorded from the connection's own state");
        assert_eq!(
            tenant.matches(concat!("savepoint: ", "false")).count(),
            2,
            "only `TenantTx::begin` and `IngestTx::begin` (fresh connections) state they are not a savepoint"
        );
        assert_eq!(
            tenant.matches(concat!("if !self.", "savepoint {\n            super::refuse_aborted(")).count(),
            2,
            "both `TenantTx` and `IngestTx` probe unless a savepoint"
        );
    }
}
