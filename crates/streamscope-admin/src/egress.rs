//! admin-api's copy of the platform's internal-egress allowlists
//! (`platform_egress`), installed in the shared guard
//! ([`streamscope_mcp_auth::egress`]) every admin outbound call reads.
//!
//! Loaded at startup, re-read every [`REFRESH`] by every replica, and at once
//! by the replica that handles a write — so a list change reaches admin-api's
//! own calls (probes, discovery, OIDC, card and CIMD fetches) within that
//! interval, without a restart. Refreshes run one at a time ([`refresh`]). Gateways receive the same rows through the
//! config-sync `global` body.

use std::collections::BTreeMap;
use std::time::Duration;

use crate::db::{Db, Global};

/// How often each replica re-reads the lists.
const REFRESH: Duration = Duration::from_secs(1);

/// The stored lists, surface key → entries (a surface without a row is empty).
pub async fn read(db: &Db) -> Result<BTreeMap<String, Vec<String>>, sqlx::Error> {
    let rows: Vec<(String, Vec<String>)> =
        sqlx::query_as("SELECT surface, entries FROM platform_egress ORDER BY surface")
            .fetch_all(db.global(Global::Infra))
            .await?;
    Ok(rows.into_iter().collect())
}

/// Re-read the lists and install them. A failed read or a set that does not
/// parse leaves the lists in force as they were: a transient failure must
/// never widen or narrow what this process may reach.
pub async fn refresh(db: &Db) -> Result<(), String> {
    // One refresh at a time — the loop's and a write's — read and install
    // under one lock, so a read made before a write's commit never installs
    // after the read made after it.
    static ONE_AT_A_TIME: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
    static FAILING: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    use std::sync::atomic::Ordering;
    let _one = ONE_AT_A_TIME.lock().await;
    let lists = match read(db).await {
        Ok(map) => streamscope_mcp_auth::egress::Lists::from_entries(&map)
            .map_err(|(surface, e)| format!("the stored lists do not parse ({}: {e})", surface.as_str())),
        Err(e) => Err(e.to_string()),
    };
    match lists {
        Ok(lists) => {
            if FAILING.swap(false, Ordering::Relaxed) {
                tracing::info!("egress lists refresh: applying again");
            }
            streamscope_mcp_auth::egress::install(lists);
            Ok(())
        }
        Err(e) => {
            // Once per failure streak: the loop runs every second.
            if !FAILING.swap(true, Ordering::Relaxed) {
                tracing::warn!("egress lists refresh: {e} — the lists in force stay until a refresh succeeds");
            }
            Err(e)
        }
    }
}

/// The refresh loop every replica runs until `token` is cancelled.
pub fn spawn_refresh(db: Db, token: tokio_util::sync::CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(REFRESH);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            tokio::select! {
                _ = token.cancelled() => return,
                _ = tick.tick() => { let _ = refresh(&db).await; }
            }
        }
    })
}
