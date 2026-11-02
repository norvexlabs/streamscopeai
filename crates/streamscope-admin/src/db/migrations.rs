//! Applies the embedded migrations, including against a database a NEWER
//! release has already moved on.
//!
//! Every deploy shape rolls back by starting the previous release's images
//! against the database the newer release left behind: the appliance's A/B
//! fallback (by hand or from the post-upgrade health gate), the Docker
//! deployment's `--rollback`, a `helm rollback`. The migration policy makes that
//! schema readable by the previous release — every migration is additive — so
//! this build reads PAST applied migrations it does not carry instead of
//! refusing them. Refusing would turn every rollback across a schema change into
//! an outage on the very path meant to recover from one.
//!
//! The single exception is a **rollback barrier**: the phase-2 terminus of the
//! two-phase recipe (a DROP / RENAME / type change the lint admits only behind
//! an explicit marker), named `NNN_rollback_barrier_<what>.sql`. It removes
//! something an older release may still use, so a build that does not carry it
//! refuses to start rather than serve errors from a schema it cannot read. The
//! name is the channel because it is what reaches the database: sqlx stores it
//! as the row's `description` ("rollback barrier <what>"), and an older build
//! can read that row without knowing the file.
//!
//! Keep the token in sync with every reader of it: the `lint-migrations.sh` lint
//! (which requires it exactly when a rollback-breaking marker is present) and
//! `stowage.yaml`'s `database.schema_compat.barrier_after` query, which every
//! deploy shape's rollback asks before going back.

use std::collections::BTreeSet;

use sqlx::PgPool;

/// The `description` sqlx records for a `NNN_rollback_barrier_<what>.sql` file
/// starts with this (sqlx turns the filename's underscores into spaces).
pub(crate) const ROLLBACK_BARRIER: &str = "rollback barrier";

/// One successfully applied row of `_sqlx_migrations`.
#[derive(Debug, Clone, PartialEq, Eq, sqlx::FromRow)]
pub(crate) struct AppliedMigration {
    pub version: i64,
    pub description: String,
}

impl AppliedMigration {
    fn is_rollback_barrier(&self) -> bool {
        self.description == ROLLBACK_BARRIER
            || self
                .description
                .strip_prefix(ROLLBACK_BARRIER)
                .is_some_and(|rest| rest.starts_with(' '))
    }
}

/// Splits the applied migrations this build does not embed into the ones it
/// can read past (returned) and the barriers it cannot (the error).
pub(crate) fn assess_unknown(
    embedded: &BTreeSet<i64>,
    applied: &[AppliedMigration],
) -> Result<Vec<AppliedMigration>, anyhow::Error> {
    let unknown: Vec<AppliedMigration> = applied
        .iter()
        .filter(|m| !embedded.contains(&m.version))
        .cloned()
        .collect();
    let barriers: Vec<String> = unknown
        .iter()
        .filter(|m| m.is_rollback_barrier())
        .map(|m| format!("{} ({})", m.version, m.description))
        .collect();
    if !barriers.is_empty() {
        anyhow::bail!(
            "the database carries migration {}, which removed something this release \
             still uses, so this release cannot serve it. Run a release that includes it, \
             or restore the backup taken before the upgrade.",
            barriers.join(", ")
        );
    }
    Ok(unknown)
}

async fn applied_migrations(pool: &PgPool) -> anyhow::Result<Vec<AppliedMigration>> {
    // A fresh database has no bookkeeping table until the first run creates it.
    // Unqualified on purpose: sqlx creates it unqualified, on the search_path.
    let exists: bool = sqlx::query_scalar("SELECT to_regclass('_sqlx_migrations') IS NOT NULL")
        .fetch_one(pool)
        .await
        .map_err(|e| anyhow::anyhow!("reading the migration history failed: {e}"))?;
    if !exists {
        return Ok(Vec::new());
    }
    sqlx::query_as::<_, AppliedMigration>(
        "SELECT version, description FROM _sqlx_migrations WHERE success ORDER BY version",
    )
    .fetch_all(pool)
    .await
    .map_err(|e| anyhow::anyhow!("reading the migration history failed: {e}"))
}

/// Runs the embedded migrations on `pool` (the migration role's pool).
pub(crate) async fn run(pool: &PgPool) -> anyhow::Result<()> {
    let mut migrator = sqlx::migrate!("../../migrations");
    let embedded: BTreeSet<i64> = migrator.iter().map(|m| m.version).collect();

    let unknown = assess_unknown(&embedded, &applied_migrations(pool).await?)?;
    if !unknown.is_empty() {
        let names: Vec<String> = unknown
            .iter()
            .map(|m| format!("{} ({})", m.version, m.description))
            .collect();
        tracing::warn!(
            migrations = %names.join(", "),
            "the database is ahead of this release — a newer release applied migrations this \
             build does not carry; reading past them, as the migration policy allows"
        );
    }

    migrator.set_ignore_missing(true);
    migrator
        .run(pool)
        .await
        .map_err(|e| anyhow::anyhow!("migration failed: {e}"))?;

    // Judge the history again now that the migrator has held its advisory lock:
    // a newer release migrating concurrently (a rollback racing an upgrade) may
    // have committed a barrier after the read above, and this build must not
    // start against what it removed.
    assess_unknown(&embedded, &applied_migrations(pool).await?)?;
    Ok(())
}

/// Connect as the migration role, check the server's version and the database's
/// locale (`check_server`), apply the embedded
/// migrations, then hand the runtime role its grants and settings.
///
/// The migration role's pool lives only here, for the length of this call: it is
/// a different role from the runtime pool behind [`super::Db`].
pub(crate) async fn migrate() -> anyhow::Result<()> {
    // Run migrations as superuser (needs CREATE TABLE, ALTER TABLE, CREATE POLICY).
    // MIGRATION_DATABASE_URL defaults to superuser; DATABASE_URL defaults to app role (RLS-enforced).
    //
    // A migration script error bubbles up to `main()`'s wrap → degraded mode →
    // structured 503 on /ready. sqlx wraps each migration file in a single
    // transaction, so a failed migration leaves the DB at version N-1 — Kairos OS
    // A/B rollback or fix-forward is the path from there. (Postgres being
    // unreachable at startup is handled separately by `connect_with_retry`,
    // which retries then exits for an orchestrator restart.)
    // The URL, and the setting it came from (named in a refusal).
    let (migration_url_setting, migration_url) = std::env::var("MIGRATION_DATABASE_URL")
        .ok()
        .filter(|s| !s.is_empty())
        .map(|url| ("MIGRATION_DATABASE_URL", url))
        .or_else(|| std::env::var("DATABASE_URL").ok().map(|url| ("DATABASE_URL", url)))
        .unwrap_or_else(|| {
            (
                "the built-in default database URL",
                "postgres://streamscope:streamscope@postgres:5432/streamscope".to_string(),
            )
        });
    tracing::info!("running database migrations");
    let migration_pool = crate::connect_with_retry("migration pool", || sqlx::PgPool::connect(&migration_url)).await;

    // Pre-flight, before the heavy migration step so a misconfigured server
    // fails fast; the runtime pool's database is checked the same way
    // (`Db::check_roles`).
    check_server(&migration_pool, migration_url_setting).await?;

    run(&migration_pool).await?;
    // Grant permissions to app role on any newly created tables.
    if let Err(e) = sqlx::query("GRANT ALL ON ALL TABLES IN SCHEMA public TO streamscope_app")
        .execute(&migration_pool).await {
        tracing::warn!("GRANT on tables failed (app role may lack permissions): {e}");
    }
    if let Err(e) = sqlx::query("GRANT ALL ON ALL SEQUENCES IN SCHEMA public TO streamscope_app")
        .execute(&migration_pool).await {
        tracing::warn!("GRANT on sequences failed (app role may lack permissions): {e}");
    }

    // Sync the app role's password to match DATABASE_URL so a freshly created
    // role (migration 001 bakes a placeholder password when it creates the role)
    // ends up with the injected credential — the appliance generates a per-deploy
    // app password, so the placeholder never survives first boot.
    //
    // Operators who manage `streamscope_app` out-of-band set DB_MANAGE_APP_ROLE
    // =false to skip the sync: on managed Postgres the migration role often
    // can't ALTER a role it didn't create, and IAM-auth / external-rotation
    // setups own the credential themselves. With the role pre-created (migration
    // 001 skips creation when it already exists), the placeholder literal never
    // executes and no default credential reaches the cluster.
    let settings = crate::settings::admin_settings();
    if !settings.db_manage_app_role {
        tracing::info!(
            "DB_MANAGE_APP_ROLE=false — skipping app-role password sync (role managed by operator)"
        );
    } else {
        // Parse password from postgres://user:PASSWORD@host/db format.
        let app_url = super::database_url();
        if let Some(password) = app_url
            .strip_prefix("postgres://")
            .or_else(|| app_url.strip_prefix("postgresql://"))
            .and_then(|s| s.split_once('@'))
            .and_then(|(userinfo, _)| userinfo.split_once(':'))
            .map(|(_, pwd)| pwd.to_string())
        {
            // ALTER ROLE doesn't support $1 binds — password is from trusted env var, not user input.
            let alter = format!("ALTER ROLE streamscope_app PASSWORD '{}'", password.replace('\'', "''"));
            if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(&*alter)).execute(&migration_pool).await {
                tracing::warn!("ALTER ROLE password sync failed (app connections may fail): {e}");
            }
        }

        // Defensive backstop (PG17 `transaction_timeout`): bound any single
        // app-role transaction so a wedged/runaway one can't pin a connection
        // indefinitely. Default 1h — comfortably above the longest legitimate
        // app-role work (retention sweeps, heavy analytics), so it never aborts
        // real work; `0` disables. Tunable via DB_APP_TRANSACTION_TIMEOUT. Only
        // applied when we manage the role — operators who own it
        // (DB_MANAGE_APP_ROLE=false) set it themselves. A fired timeout closes
        // the connection (FATAL); sqlx just reconnects. Takes effect on the
        // role's next session (admin-api + proxy connect as streamscope_app).
        let txn_timeout = &settings.db_app_transaction_timeout;
        // ALTER ROLE doesn't support $1 binds — value is from a trusted env var.
        let alter = format!(
            "ALTER ROLE streamscope_app SET transaction_timeout = '{}'",
            txn_timeout.replace('\'', "''")
        );
        if let Err(e) = sqlx::query(sqlx::AssertSqlSafe(&*alter)).execute(&migration_pool).await {
            tracing::warn!(
                value = %txn_timeout,
                "ALTER ROLE transaction_timeout failed (check DB_APP_TRANSACTION_TIMEOUT format, e.g. '1h' / '0'): {e}"
            );
        } else {
            tracing::info!(transaction_timeout = %txn_timeout, "app-role transaction_timeout set");
        }
    }

    migration_pool.close().await;
    tracing::info!("migrations complete");
    Ok(())
}

/// Refuse a server older than PostgreSQL 18, the release's PostgreSQL on every
/// shape, and a database whose locale is not the one every shape creates
/// (`DATABASE_LOCALE`). `url` names the setting the pool was opened from.
pub(crate) async fn check_server(pool: &sqlx::PgPool, url: &str) -> anyhow::Result<()> {
    // `server_version_num` is an integer GUC (e.g. 180006) readable by any role.
    const MIN_SERVER_VERSION_NUM: i32 = 180000;
    let server_version_num: i32 =
        sqlx::query_scalar("SELECT current_setting('server_version_num')::int")
            .fetch_one(pool)
            .await
            .map_err(|e| anyhow::anyhow!("PostgreSQL version pre-flight check failed: {e}"))?;
    if server_version_num < MIN_SERVER_VERSION_NUM {
        anyhow::bail!(
            "FATAL: PostgreSQL {}.{} is too old — Streamscope requires PostgreSQL 18 or newer. \
             Point {url} at an 18+ server.",
            server_version_num / 10000,
            server_version_num % 10000
        );
    }
    let locale: DatabaseLocale = sqlx::query_as(
        "SELECT pg_encoding_to_char(encoding)::text AS encoding, datlocprovider::text AS provider, \
                datlocale AS locale, datcollate AS lc_collate, datctype AS lc_ctype \
         FROM pg_database WHERE datname = current_database()",
    )
    .fetch_one(pool)
    .await
    .map_err(|e| anyhow::anyhow!("PostgreSQL locale pre-flight check failed: {e}"))?;
    if let Some(problem) = locale.mismatch() {
        let (encoding, _, builtin, collate, ctype) = DATABASE_LOCALE;
        anyhow::bail!(
            "FATAL: the database's locale is not Streamscope's: {problem} ({url}). Every deploy shape \
             creates it with ENCODING '{encoding}' LOCALE_PROVIDER builtin BUILTIN_LOCALE '{builtin}' \
             LC_COLLATE '{collate}' LC_CTYPE '{ctype}'; a database's locale is fixed when it is created, \
             so create the database again with it."
        );
    }
    tracing::info!(server_version_num, url, "PostgreSQL 18+ and the database locale verified");
    Ok(())
}

/// A database's locale, as `pg_database` records it.
#[derive(sqlx::FromRow)]
struct DatabaseLocale {
    encoding: String,
    /// `datlocprovider`: `b` builtin, `c` libc, `i` ICU.
    provider: String,
    locale: Option<String>,
    lc_collate: String,
    lc_ctype: String,
}

/// The locale every deploy shape creates the database with: the built-in
/// provider's `PG_UNICODE_FAST` (code-point order, full Unicode case mapping,
/// no libc or ICU version behind it), UTF-8, and LC_CTYPE `C.UTF-8` — the
/// character classification pg_trgm reads, which under `C` drops every
/// non-ASCII letter from a trigram. Keep equal to the compose file's and the
/// chart's `POSTGRES_INITDB_ARGS` and the chart's CloudNativePG `initdb`.
const DATABASE_LOCALE: (&str, &str, &str, &str, &str) = ("UTF8", "b", "PG_UNICODE_FAST", "C", "C.UTF-8");

impl DatabaseLocale {
    /// What differs from `DATABASE_LOCALE`, or `None` when nothing does.
    fn mismatch(&self) -> Option<String> {
        let (encoding, provider, locale, collate, ctype) = DATABASE_LOCALE;
        let mut out = Vec::new();
        if self.encoding != encoding {
            out.push(format!("encoding {} (want {encoding})", self.encoding));
        }
        if self.provider != provider || self.locale.as_deref() != Some(locale) {
            out.push(format!(
                "locale provider {} with locale {} (want the builtin provider with {locale})",
                match self.provider.as_str() {
                    "b" => "builtin",
                    "c" => "libc",
                    "i" => "icu",
                    other => other,
                },
                self.locale.as_deref().unwrap_or("none"),
            ));
        }
        if self.lc_collate != collate {
            out.push(format!("LC_COLLATE {} (want {collate})", self.lc_collate));
        }
        if self.lc_ctype != ctype {
            out.push(format!("LC_CTYPE {} (want {ctype})", self.lc_ctype));
        }
        (!out.is_empty()).then(|| out.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use std::assert_matches;

    use super::*;

    fn row(version: i64, description: &str) -> AppliedMigration {
        AppliedMigration { version, description: description.to_string() }
    }

    fn embedded(versions: &[i64]) -> BTreeSet<i64> {
        versions.iter().copied().collect()
    }

    #[test]
    fn a_database_this_build_fully_knows_has_nothing_to_read_past() {
        let applied = [row(1, "init"), row(2, "add foo")];
        assert_eq!(assess_unknown(&embedded(&[1, 2]), &applied).unwrap(), vec![]);
        assert_eq!(assess_unknown(&embedded(&[1, 2]), &[]).unwrap(), vec![]);
    }

    #[test]
    fn a_newer_additive_migration_is_read_past_and_named() {
        let applied = [row(1, "init"), row(2, "add foo"), row(3, "add bar")];
        assert_eq!(
            assess_unknown(&embedded(&[1]), &applied).unwrap(),
            vec![row(2, "add foo"), row(3, "add bar")],
        );
    }

    #[test]
    fn a_newer_rollback_barrier_refuses_and_names_the_migration() {
        let applied = [row(1, "init"), row(2, "add foo"), row(3, "rollback barrier drop foo")];
        let err = assess_unknown(&embedded(&[1]), &applied).unwrap_err().to_string();
        assert!(err.contains("3 (rollback barrier drop foo)"), "{err}");
        assert!(!err.contains("add foo"), "only the barrier is named: {err}");
    }

    #[test]
    fn a_barrier_this_build_carries_is_not_a_refusal() {
        let applied = [row(1, "init"), row(3, "rollback barrier drop foo"), row(4, "add bar")];
        assert_eq!(
            assess_unknown(&embedded(&[1, 3]), &applied).unwrap(),
            vec![row(4, "add bar")],
        );
    }

    #[test]
    fn the_barrier_token_is_a_whole_word_prefix() {
        // Both sides of the token boundary: the bare token and a described
        // barrier refuse; a description merely starting with the same letters,
        // or naming it anywhere but the front, does not.
        for barrier in ["rollback barrier", "rollback barrier drop foo"] {
            assert_matches!(assess_unknown(&embedded(&[1]), &[row(2, barrier)]), Err(_), "{barrier}");
        }
        for ordinary in ["rollback barriers index", "add rollback barrier notes", "rollback"] {
            assert_matches!(assess_unknown(&embedded(&[1]), &[row(2, ordinary)]), Ok(_), "{ordinary}");
        }
    }

    fn shipped_locale() -> DatabaseLocale {
        let (encoding, provider, locale, collate, ctype) = DATABASE_LOCALE;
        DatabaseLocale {
            encoding: encoding.into(),
            provider: provider.into(),
            locale: Some(locale.into()),
            lc_collate: collate.into(),
            lc_ctype: ctype.into(),
        }
    }

    #[test]
    fn the_locale_every_shape_creates_passes() {
        assert_eq!(shipped_locale().mismatch(), None);
    }

    #[test]
    fn every_locale_field_that_differs_is_refused_and_named() {
        // One case per field, each against the shipped locale: the defaults of
        // common images and managed services, and the builtin provider's other
        // locales. Each needle ends where the message's own text goes on, so
        // `C` is not read as the start of `C.UTF-8`.
        type Change = fn(&mut DatabaseLocale);
        let cases: [(&str, Change); 7] = [
            ("encoding SQL_ASCII", |l| l.encoding = "SQL_ASCII".into()),
            ("locale provider libc with locale none", |l| {
                l.provider = "c".into();
                l.locale = None;
            }),
            ("locale provider icu with locale und", |l| {
                l.provider = "i".into();
                l.locale = Some("und".into());
            }),
            ("locale provider builtin with locale C.UTF-8", |l| l.locale = Some("C.UTF-8".into())),
            ("locale provider builtin with locale C (want", |l| l.locale = Some("C".into())),
            ("LC_COLLATE en_US.utf8", |l| l.lc_collate = "en_US.utf8".into()),
            ("LC_CTYPE C (want C.UTF-8)", |l| l.lc_ctype = "C".into()),
        ];
        for (named, change) in cases {
            let mut locale = shipped_locale();
            change(&mut locale);
            let problem = locale.mismatch().unwrap_or_else(|| panic!("{named}: accepted"));
            assert!(problem.contains(named), "{named}: {problem}");
        }
    }

    #[test]
    fn the_file_name_is_what_reaches_the_description() {
        // The barrier is detected from the recorded description, so pin the
        // convention it depends on: `001_init.sql` is recorded as "init" — the
        // version prefix and the `.sql` suffix stripped, the rest verbatim with
        // underscores as spaces, the token therefore at the front.
        let migrator = sqlx::migrate!("../../migrations");
        let baseline = migrator.iter().find(|m| m.version == 1).expect("001_init is embedded");
        assert_eq!(baseline.description, "init");
    }
}
