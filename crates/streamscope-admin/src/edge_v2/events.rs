//! Events for edges, delivered on the sync poll.
//!
//! [`append`] writes each event in its own short transaction holding
//! `LOCK_EDGE_EVENTS` until commit, so ids are assigned in commit order: a
//! reader's `id > cursor` never passes over a row that commits later with a
//! smaller id. Call it only after whatever the event reports has committed.
//! Each append notifies [`CHANNEL`] at commit; every replica listens, so an
//! answer it holds is sent the event at once (see [`spawn_listener`]).

use streamscope_edge_api::sync::{Event, EventId};

use crate::db::{Db, Global};

/// The `LISTEN`/`NOTIFY` channel an appended event is announced on.
const CHANNEL: &str = "edge_events";

const EVENTS_PER_POLL: i64 = streamscope_edge_api::sync::EVENTS_PER_POLL as i64;

/// Append one event for `tenant`'s edges. `source_instance` (the edge's own
/// instance id) is never sent the event back.
pub async fn append(
    db: &Db,
    tenant: uuid::Uuid,
    source_instance: Option<uuid::Uuid>,
    body: &serde_json::Value,
) -> Result<EventId, sqlx::Error> {
    let mut tx = db.begin_global(Global::Infra).await?;
    sqlx::query("SELECT pg_advisory_xact_lock($1)")
        .bind(crate::leader::LOCK_EDGE_EVENTS)
        .execute(&mut *tx)
        .await?;
    let id: EventId = sqlx::query_scalar(
        "INSERT INTO edge_events (tenant_id, source_instance, body) VALUES ($1, $2, $3) RETURNING id",
    )
    .bind(tenant)
    .bind(source_instance)
    .bind(body)
    .fetch_one(&mut *tx)
    .await?;
    sqlx::query("SELECT pg_notify($1, '')").bind(CHANNEL).execute(&mut *tx).await?;
    tx.commit().await?;
    Ok(id)
}

/// Listen on [`CHANNEL`] for this replica's lifetime, waking its held sync
/// answers on every event appended anywhere. A lost connection is reopened,
/// and wakes them once it is: an event may have landed while it was down.
/// The listener holds a connection of its own, outside the runtime pool, for
/// the replica's lifetime.
pub fn spawn_listener(token: tokio_util::sync::CancellationToken) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        loop {
            tokio::select! {
                () = token.cancelled() => return,
                outcome = listen() => {
                    if let Err(e) = outcome {
                        tracing::warn!("edge event listener: {e} — reconnecting");
                    }
                }
            }
            super::sync::wake();
            tokio::select! {
                () = token.cancelled() => return,
                () = tokio::time::sleep(std::time::Duration::from_secs(1)) => {}
            }
        }
    })
}

async fn listen() -> Result<(), sqlx::Error> {
    let mut listener = crate::db::listener().await?;
    listener.listen(CHANNEL).await?;
    super::sync::wake();
    loop {
        // `None`: the connection was lost — the next call reopens it, and an
        // event may have landed meanwhile, so it wakes all the same.
        listener.try_recv().await?;
        super::sync::wake();
    }
}

/// The newest event id (0 when there is none).
pub async fn head(db: &Db) -> Result<EventId, sqlx::Error> {
    sqlx::query_scalar("SELECT COALESCE(MAX(id), 0) FROM edge_events")
        .fetch_one(db.global(Global::Infra))
        .await
}

/// The events in `(after, upto]` for the tenants an instance holds, oldest
/// first, excluding those the instance itself raised, and the cursor the
/// instance sends next. `upto` is a [`head`] read before this call: ids are
/// committed in order, so every event up to it is visible here.
pub async fn after(
    db: &Db,
    after: EventId,
    upto: EventId,
    instance: uuid::Uuid,
    tenants: &[uuid::Uuid],
) -> Result<(Vec<Event>, EventId), sqlx::Error> {
    let rows: Vec<(EventId, uuid::Uuid, serde_json::Value)> = if tenants.is_empty() {
        Vec::new()
    } else {
        sqlx::query_as(
            "SELECT id, tenant_id, body FROM edge_events \
              WHERE id > $1 AND id <= $5 AND tenant_id = ANY($2) AND source_instance IS DISTINCT FROM $3 \
              ORDER BY id LIMIT $4",
        )
        .bind(after)
        .bind(tenants)
        .bind(instance)
        .bind(EVENTS_PER_POLL)
        .bind(upto)
        .fetch_all(db.global(Global::Infra))
        .await?
    };
    let events: Vec<Event> = rows.into_iter().map(|(id, tenant, body)| Event { id, tenant, body }).collect();
    let next = cursor(upto, &events);
    Ok((events, next))
}

/// The cursor after an answer carrying `events`, read up to `upto`: the last
/// event of a full page (more may follow), else `upto` — nothing up to it is
/// left for this instance, and a cursor past it (a restored database) comes
/// back down to it.
fn cursor(upto: EventId, events: &[Event]) -> EventId {
    match events.last() {
        Some(last) if events.len() as i64 >= EVENTS_PER_POLL => last.id,
        _ => upto,
    }
}

/// Run [`janitor`] every minute on this replica, from start. Every config
/// write appends a change bump whether or not an edge reads them, so this
/// bounds the table on every deployment.
pub fn spawn_janitor(db: Db) {
    tokio::spawn(async move {
        let ttl = crate::settings::admin_settings().edge_event_ttl_secs;
        loop {
            if let Err(e) = janitor(&db, ttl).await {
                tracing::warn!("edge sync housekeeping failed: {e}");
            }
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
        }
    });
}

/// How long an applied one-shot instance event's key is kept. An edge restates
/// an event only until a request carrying it is answered, so a key is needed
/// only while such a request can still arrive.
const INSTANCE_EVENT_KEY_TTL_SECS: f64 = 24.0 * 3600.0;

/// Housekeeping any replica may run at any time: drop expired events and
/// instance-event keys, every change bump that is not its resource's newest (a
/// counter is `MAX(id)`, which deleting older rows never changes), and the
/// bumps of tenants that no longer exist (a tenant row and its bump commit
/// together, so none is in flight).
pub async fn janitor(db: &Db, event_ttl_secs: u64) -> Result<(), sqlx::Error> {
    let pool = db.global(Global::Infra);
    sqlx::query("DELETE FROM edge_events WHERE created_at < now() - make_interval(secs => $1)")
        .bind(event_ttl_secs as f64)
        .execute(pool)
        .await?;
    sqlx::query("DELETE FROM edge_instance_events WHERE applied_at < now() - make_interval(secs => $1)")
        .bind(INSTANCE_EVENT_KEY_TTL_SECS)
        .execute(pool)
        .await?;
    sqlx::query(
        "DELETE FROM config_bumps b USING \
            (SELECT resource, MAX(id) AS newest FROM config_bumps GROUP BY resource) k \
          WHERE b.resource = k.resource AND b.id < k.newest",
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "DELETE FROM config_bumps b \
          WHERE b.resource LIKE 'tenant:%' \
            AND NOT EXISTS (SELECT 1 FROM tenants t WHERE 'tenant:' || t.id::text = b.resource)",
    )
    .execute(pool)
    .await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn events(ids: impl IntoIterator<Item = EventId>) -> Vec<Event> {
        ids.into_iter().map(|id| Event { id, tenant: uuid::Uuid::nil(), body: serde_json::Value::Null }).collect()
    }

    #[test]
    fn a_short_page_moves_the_cursor_to_the_head_and_a_full_one_to_its_last_event() {
        assert_eq!(cursor(50, &events([])), 50, "nothing for this instance: skip to the head");
        assert_eq!(cursor(50, &events([10, 20])), 50);
        let full = events(1..=EVENTS_PER_POLL);
        assert_eq!(cursor(5000, &full), EVENTS_PER_POLL, "a full page: the rest come next poll");
        let one_short = events(1..EVENTS_PER_POLL);
        assert_eq!(cursor(5000, &one_short), 5000);
    }
}
