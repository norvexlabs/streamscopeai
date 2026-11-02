//! Tenant isolation primitives for admin-API database access.
//!
//! # Design
//!
//! Tenant data is reached through two doors, both handing out a [`Scoped`]
//! connection whose `app.tenant_id` this module set — activating PostgreSQL
//! Row-Level Security:
//!
//! * [`TenantConn`] — a pooled connection scoped for the session, no transaction.
//! * [`TenantTx`] — a transaction, scoped for its own lifetime; `commit()` is the
//!   only way its writes persist.
//!
//! Repository functions take `&mut Scoped`, so they cannot be handed an unscoped
//! connection. When a connection returns to the pool, the `after_release`
//! callback in `db::create_pool()` RESETs the variable. If `app.tenant_id` is not
//! set, RLS policies return zero rows (fail-closed).

use std::future::Future;
use std::sync::Arc;

use axum::extract::{FromRef, FromRequestParts};
use axum::http::request::Parts;
use sqlx::pool::PoolConnection;
use sqlx::postgres::Postgres;
use sqlx::{PgConnection, Transaction};
use uuid::Uuid;

use crate::AdminState;
use crate::db::{Db, Global};
use crate::routes::portal_auth::PortalUser;

// ---------------------------------------------------------------------------
// TenantId
// ---------------------------------------------------------------------------

/// Strongly-typed tenant identifier for admin-API database access: the value a
/// connection's RLS scope is set from.
///
/// The field is private, so every tenant id is minted by a constructor that names
/// where it came from — a database row, a credential this process verified, an
/// edge's authenticated record — and review reads that claim at the call site.
/// Prevents mixing tenant UUIDs with user UUIDs at compile time.
///
/// `streamscope_core::config::TenantId` is the proxy's routing key with serde
/// derives for the config-sync wire; both define `SYSTEM = UUID(1)`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct TenantId(Uuid);

impl TenantId {
    /// The built-in system tenant (single-tenant default).
    pub const SYSTEM: TenantId = TenantId(Uuid::from_u128(1));

    /// A tenant id read from the database: a `tenants` row, or a row's
    /// `tenant_id` column, which its foreign key ties to one.
    pub fn from_row(id: Uuid) -> Self {
        Self(id)
    }

    /// A tenant id carried by a credential this process verified: a signed
    /// session or token claim, or the row of a key, code or token it resolved.
    pub fn from_credential(id: Uuid) -> Self {
        Self(id)
    }

    /// A tenant id an authenticated edge named for its own record (ingest, sync,
    /// replay). The edge is trusted for the tenants it serves; the record still
    /// lands under RLS for exactly that tenant.
    pub fn from_edge(id: Uuid) -> Self {
        Self(id)
    }

    /// A fresh id for a tenant about to be created: its `tenants` row is inserted
    /// in the transaction this id scopes.
    pub fn mint() -> Self {
        Self(Uuid::new_v4())
    }

    /// The UUID, for a bind or a log line.
    pub fn as_uuid(self) -> Uuid {
        self.0
    }
}

impl std::fmt::Display for TenantId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

// ---------------------------------------------------------------------------
// AdminTenantCtx
// ---------------------------------------------------------------------------

/// Tenant context for admin routes.
/// Inserted into request extensions by the `admin_auth` middleware.
#[derive(Debug, Clone)]
pub struct AdminTenantCtx {
    pub tenant_id: TenantId,
    /// For a human session: `admin_accounts.id`. For an `ak-` automation key:
    /// the owning service-account `users.id` (there is no `admin_accounts` row).
    pub admin_account_id: Uuid,
    pub is_super_admin: bool,
    /// The account's role, parsed fail-closed from the JWT `role` claim (human) or
    /// projected from the key's `admin_scope` (`ak-`). Drives the `authz`
    /// chokepoint (`ReadOnly` → no mutations). See `crate::authz`.
    pub role: crate::authz::AdminRole,
    /// `Some(automation_keys.id)` when the request authenticated via an `ak-`
    /// automation key; `None` for a human session. Stamped onto the audit row as
    /// `actor_key_id` so the log answers "which automation did this?".
    pub actor_key_id: Option<Uuid>,
    /// The raw `admin_scope` of the authenticating `ak-` key (`read_only` |
    /// `full` | `super_admin`); `None` for humans. Carried into `AccessContext`
    /// so `authz::evaluate` can grow fine-grained rules without re-plumbing — the
    /// `role` projection above is only the step-1 coarse mapping.
    pub key_scope: Option<String>,
}

// ---------------------------------------------------------------------------
// Scoped, TenantConn, TenantTx
// ---------------------------------------------------------------------------

/// Point a connection's RLS scope at `tenant_id` — for the session, or (`local`)
/// for the current transaction only.
async fn set_tenant_guc(
    conn: &mut PgConnection,
    tenant_id: TenantId,
    local: bool,
) -> Result<(), sqlx::Error> {
    set_scope_value(conn, &tenant_id.0.to_string(), local).await
}

/// Set `app.tenant_id` to `value` (empty = no tenant, which matches zero rows).
///
/// This is the ONLY place in the crate that sets `app.tenant_id`. Keep it that
/// way: a hand-rolled `set_config` elsewhere is how a connection ends up scoped to
/// the wrong tenant. The value is a bound parameter, never formatted into the SQL.
async fn set_scope_value(conn: &mut PgConnection, value: &str, local: bool) -> Result<(), sqlx::Error> {
    sqlx::query("SELECT set_config('app.tenant_id', $1, $2)")
        .bind(value)
        .bind(local)
        .execute(conn)
        .await
        .map(|_| ())
}

/// A connection whose RLS scope is a tenant: what every tenant query runs on.
///
/// Only this module can produce one — from a [`TenantConn`] or a [`TenantTx`]
/// (both deref to it) — so a function taking `&mut Scoped` cannot be handed an
/// unscoped connection, whose queries on tenant tables would silently match zero
/// rows. It is an [`sqlx::Executor`], so a query runs on it exactly as on a
/// connection: `.fetch_one(&mut *conn)`.
#[derive(Debug)]
#[repr(transparent)]
pub struct Scoped(PgConnection);

impl Scoped {
    /// View a connection whose GUC this module has just set as `Scoped`.
    fn from_conn(conn: &mut PgConnection) -> &mut Scoped {
        // SAFETY: `Scoped` is `#[repr(transparent)]` over `PgConnection`, so the two
        // references have the same layout, and the borrow's lifetime is carried over.
        unsafe { &mut *std::ptr::from_mut(conn).cast::<Scoped>() }
    }

    /// [`Scoped::from_conn`], for a shared borrow.
    fn from_conn_ref(conn: &PgConnection) -> &Scoped {
        // SAFETY: as in `from_conn`.
        unsafe { &*std::ptr::from_ref(conn).cast::<Scoped>() }
    }

    /// Begin a transaction on this connection — a savepoint when it already is
    /// one. It keeps the connection's tenant scope.
    pub async fn begin(&mut self) -> Result<TenantTx<'_>, sqlx::Error> {
        let savepoint = sqlx::Connection::is_in_transaction(&self.0);
        Ok(TenantTx { tx: sqlx::Connection::begin(&mut self.0).await?, savepoint })
    }
}

/// Implement [`sqlx::Executor`] for a `#[repr(transparent)]` newtype over
/// `PgConnection` by delegating to the connection it wraps.
macro_rules! delegate_executor {
    ($ty:ty) => {
        impl<'c> sqlx::Executor<'c> for &'c mut $ty {
            type Database = Postgres;

            fn fetch_many<'e, 'q: 'e, E>(
                self,
                query: E,
            ) -> futures::stream::BoxStream<
                'e,
                Result<sqlx::Either<sqlx::postgres::PgQueryResult, sqlx::postgres::PgRow>, sqlx::Error>,
            >
            where
                'c: 'e,
                E: 'q + sqlx::Execute<'q, Postgres>,
            {
                (&mut self.0).fetch_many(query)
            }

            fn fetch_optional<'e, 'q: 'e, E>(
                self,
                query: E,
            ) -> futures::future::BoxFuture<'e, Result<Option<sqlx::postgres::PgRow>, sqlx::Error>>
            where
                'c: 'e,
                E: 'q + sqlx::Execute<'q, Postgres>,
            {
                (&mut self.0).fetch_optional(query)
            }

            fn prepare_with<'e>(
                self,
                sql: sqlx::SqlStr,
                parameters: &'e [sqlx::postgres::PgTypeInfo],
            ) -> futures::future::BoxFuture<'e, Result<sqlx::postgres::PgStatement, sqlx::Error>>
            where
                'c: 'e,
            {
                (&mut self.0).prepare_with(sql, parameters)
            }

            fn describe<'e>(
                self,
                sql: sqlx::SqlStr,
            ) -> futures::future::BoxFuture<'e, Result<sqlx::Describe<Postgres>, sqlx::Error>>
            where
                'c: 'e,
            {
                (&mut self.0).describe(sql)
            }
        }
    };
}

delegate_executor!(Scoped);

/// The connection of an [`IngestTx`]: it runs as `streamscope_ingest`, which
/// sees and writes the ingest tables of EVERY tenant, so each statement on it
/// names its rows' `tenant_id` (the `lint-edge-batch-writes.sh` lint). A distinct
/// type from [`Scoped`], so a repository function written for one tenant's
/// connection can never be handed it.
#[derive(Debug)]
#[repr(transparent)]
pub struct IngestConn(PgConnection);

impl IngestConn {
    fn from_conn(conn: &mut PgConnection) -> &mut IngestConn {
        // SAFETY: `IngestConn` is `#[repr(transparent)]` over `PgConnection`, so the
        // two references have the same layout, and the borrow's lifetime is carried over.
        unsafe { &mut *std::ptr::from_mut(conn).cast::<IngestConn>() }
    }

    /// Open a savepoint on the ingest transaction: a part of a request written
    /// alone, whose failure must not abort the rest.
    pub async fn savepoint(&mut self) -> Result<IngestTx<'_>, sqlx::Error> {
        Ok(IngestTx { tx: sqlx::Connection::begin(&mut self.0).await?, savepoint: true })
    }
}

delegate_executor!(IngestConn);

/// The edge ingest writer's transaction ([`Db::begin_ingest`]): `SET LOCAL ROLE
/// streamscope_ingest`, so it writes every tenant's ingest tables in one
/// transaction, and the role ends with it. Nothing it writes persists until
/// [`commit`](IngestTx::commit).
#[must_use = "an IngestTx persists nothing until commit() — dropping it rolls back"]
pub struct IngestTx<'c> {
    tx: Transaction<'c, Postgres>,
    /// A savepoint ([`IngestConn::savepoint`]): its commit is a `RELEASE`,
    /// which PostgreSQL itself refuses in an aborted transaction.
    savepoint: bool,
}

impl IngestTx<'_> {
    /// The connection the transaction runs on.
    pub fn conn(&mut self) -> &mut IngestConn {
        IngestConn::from_conn(&mut self.tx)
    }

    /// Persist the transaction, refusing one a failed statement aborted (see
    /// [`super::refuse_aborted`]). A savepoint needs no probe: its `RELEASE`
    /// already fails there.
    pub async fn commit(mut self) -> Result<(), sqlx::Error> {
        if !self.savepoint {
            super::refuse_aborted(&mut self.tx).await?;
        }
        self.tx.commit().await
    }
}

impl IngestTx<'static> {
    pub(crate) async fn begin(db: &Db) -> Result<Self, sqlx::Error> {
        let mut tx = db.pool().begin().await?;
        sqlx::query("SET LOCAL ROLE streamscope_ingest").execute(&mut *tx).await?;
        Ok(Self { tx, savepoint: false })
    }
}

/// A pooled connection scoped to one tenant for its lifetime: RLS confines every
/// query on it to that tenant. No transaction — each statement commits on its own.
///
/// # Usage in handlers
///
/// ```ignore
/// async fn get_user(mut db: TenantConn, Path(id): Path<Uuid>) -> ... {
///     let row = sqlx::query_as("SELECT ... FROM users WHERE id = $1")
///         .bind(id)
///         .fetch_optional(db.conn())
///         .await?;
///     // RLS ensures only this tenant's rows are visible
/// }
/// ```
pub struct TenantConn {
    conn: PoolConnection<Postgres>,
    tenant_id: TenantId,
}

impl TenantConn {
    /// Acquire a connection and scope it to `tenant_id` for the session. The pool's
    /// `after_release` RESETs the scope when the connection goes back.
    pub(crate) async fn acquire(db: &Db, tenant_id: TenantId) -> Result<Self, sqlx::Error> {
        let mut conn = db.pool().acquire().await?;
        set_tenant_guc(&mut conn, tenant_id, false).await?;
        Ok(Self { conn, tenant_id })
    }

    /// The scoped connection, to run a query on or hand to a repository function.
    pub fn conn(&mut self) -> &mut Scoped {
        Scoped::from_conn(&mut self.conn)
    }

    /// The tenant this connection is scoped to.
    pub fn tenant_id(&self) -> TenantId {
        self.tenant_id
    }

    /// The raw tenant UUID (convenience for SQL binds).
    pub fn tenant_uuid(&self) -> Uuid {
        self.tenant_id.0
    }
}

impl std::ops::Deref for TenantConn {
    type Target = Scoped;
    fn deref(&self) -> &Scoped {
        Scoped::from_conn_ref(&self.conn)
    }
}

impl std::ops::DerefMut for TenantConn {
    fn deref_mut(&mut self) -> &mut Scoped {
        self.conn()
    }
}

/// A tenant-scoped transaction. Nothing it writes persists until [`commit`]:
/// dropping it rolls back.
///
/// [`commit`]: TenantTx::commit
#[must_use = "a TenantTx persists nothing until commit() — dropping it rolls back"]
pub struct TenantTx<'c> {
    tx: Transaction<'c, Postgres>,
    /// Opened inside another transaction: commit is a `RELEASE SAVEPOINT`, which
    /// PostgreSQL itself refuses in an aborted transaction.
    savepoint: bool,
}

impl TenantTx<'_> {
    /// The scoped connection the transaction runs on.
    pub fn conn(&mut self) -> &mut Scoped {
        Scoped::from_conn(&mut self.tx)
    }

    /// Persist the transaction. The only way anything written in it lands.
    ///
    /// Refuses a transaction a failed statement aborted (see
    /// [`super::refuse_aborted`]) instead of reporting its silent rollback as a
    /// commit. A savepoint needs no probe: its `RELEASE` already fails there.
    pub async fn commit(mut self) -> Result<(), sqlx::Error> {
        if !self.savepoint {
            super::refuse_aborted(&mut self.tx).await?;
        }
        self.tx.commit().await
    }

    /// Discard the transaction explicitly (dropping it does the same, lazily).
    pub async fn rollback(self) -> Result<(), sqlx::Error> {
        self.tx.rollback().await
    }
}

impl TenantTx<'static> {
    /// Begin a transaction on a fresh connection, scoped to `tenant_id` for the
    /// transaction only (`set_config(…, true)`).
    pub(crate) async fn begin(db: &Db, tenant_id: TenantId) -> Result<Self, sqlx::Error> {
        let mut tx = db.pool().begin().await?;
        set_tenant_guc(&mut tx, tenant_id, true).await?;
        Ok(Self { tx, savepoint: false })
    }
}

impl std::ops::Deref for TenantTx<'_> {
    type Target = Scoped;
    fn deref(&self) -> &Scoped {
        Scoped::from_conn_ref(&self.tx)
    }
}

impl std::ops::DerefMut for TenantTx<'_> {
    fn deref_mut(&mut self) -> &mut Scoped {
        self.conn()
    }
}

/// Run `f` with `conn` temporarily scoped to the SYSTEM tenant, then restore the
/// scope it had — on the error path too.
///
/// The layered-settings case: a value is read from a tenant, falling back to the
/// SYSTEM row. `system_settings` is RLS-scoped, so the two layers sit under different
/// GUCs, and inside an open transaction (a config snapshot) the fallback cannot move
/// to a second connection without leaving the snapshot's view.
///
/// The scope to restore is read from the connection itself, never taken from the
/// caller: a wrong "owner" would silently leave the connection scoped to another
/// tenant. Inside a transaction both changes are transaction-local, so the commit
/// leaves the connection's session scope exactly as it was. Never hand-roll this
/// with a bare `set_config`.
pub async fn with_system_scope<T, F>(conn: &mut Scoped, f: F) -> Result<T, sqlx::Error>
where
    F: AsyncFnOnce(&mut Scoped) -> Result<T, sqlx::Error>,
{
    let local = sqlx::Connection::is_in_transaction(&conn.0);
    let owner: Option<String> = sqlx::query_scalar("SELECT current_setting('app.tenant_id', true)")
        .fetch_one(&mut conn.0)
        .await?;
    set_tenant_guc(&mut conn.0, TenantId::SYSTEM, local).await?;
    let out = f(&mut *conn).await;
    // Restore unconditionally — an early return from `f` must not leak the SYSTEM
    // scope to whatever runs next on this connection. When both fail, `f`'s error
    // is the cause (the restore failed only because `f` aborted the transaction).
    let restored = set_scope_value(&mut conn.0, owner.as_deref().unwrap_or_default(), local).await;
    let out = out?;
    restored?;
    Ok(out)
}

// ---------------------------------------------------------------------------
// Axum FromRequestParts impl
// ---------------------------------------------------------------------------

impl<S> FromRequestParts<S> for TenantConn
where
    S: Send + Sync,
    Arc<AdminState>: axum::extract::FromRef<S>,
{
    type Rejection = crate::routes::ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let admin_state = Arc::<AdminState>::from_ref(state);

        // Try portal user context first (portal routes).
        if let Some(portal_user) = parts.extensions.get::<PortalUser>() {
            return TenantConn::acquire(&admin_state.db, TenantId::from_credential(portal_user.tenant_id))
                .await
                .map_err(|e| {
                    tracing::error!("TenantConn acquire failed (portal): {e}");
                    crate::routes::db_read_error(&e, "database unavailable")
                });
        }

        // Try admin tenant context (admin routes).
        if let Some(admin_ctx) = parts.extensions.get::<AdminTenantCtx>() {
            return TenantConn::acquire(&admin_state.db, admin_ctx.tenant_id)
                .await
                .map_err(|e| {
                    tracing::error!("TenantConn acquire failed (admin): {e}");
                    crate::routes::db_read_error(&e, "database unavailable")
                });
        }

        // No tenant context found — programming error (middleware not applied).
        tracing::error!("TenantConn extractor: no tenant context in request extensions. \
            Ensure admin_auth or portal_auth middleware is applied.");
        Err(crate::routes::ApiError::internal("internal error"))
    }
}

// ---------------------------------------------------------------------------
// for_each_tenant — background task helper
// ---------------------------------------------------------------------------

/// Iterate all tenants and run a closure with a tenant-scoped connection.
///
/// The `tenants` table has NO RLS — it is the root table, always readable.
/// For each tenant, a `TenantConn` connection is acquired (SETs `app.tenant_id`),
/// the closure runs, and the connection returns to the pool (RESET via callback).
///
/// Errors in individual tenants are logged but do not abort the iteration.
pub async fn for_each_tenant<F, Fut>(db: &Db, f: F) -> Result<(), sqlx::Error>
where
    F: Fn(TenantConn) -> Fut,
    Fut: Future<Output = Result<(), anyhow::Error>>,
{
    let tenants: Vec<(Uuid,)> = sqlx::query_as("SELECT id FROM tenants")
        .fetch_all(db.global(Global::TenantIteration))
        .await?;

    for (tid,) in tenants {
        let db = TenantConn::acquire(db, TenantId::from_row(tid)).await?;
        if let Err(e) = f(db).await {
            tracing::error!(tenant_id = %tid, "for_each_tenant error: {e}");
        }
    }
    Ok(())
}
