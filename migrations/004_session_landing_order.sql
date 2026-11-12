-- The expert agent reads sessions in the order their turns landed, not by the
-- time a gateway stamped on them: a turn that waits in a gateway's outbox lands
-- with an older timestamp than turns already analyzed, and must still be read.
--
-- `landed_xid` is the id of the ingest transaction that last added a turn to the
-- session (`pg_current_xact_id()`, 64-bit, never wraps). It is NULL on a session
-- no ingest has added a turn to since this column exists.

-- migration-lint: allow cross_migration, an additive nullable column on sessions (001) — the previous release neither reads it nor names it in a write
ALTER TABLE sessions ADD COLUMN landed_xid BIGINT;

-- The agent's scan: one tenant's sessions in landing order, from a position.
-- Partial: every session that exists when this runs is unstamped, so the build
-- reads the table once and writes nothing.
-- migration-lint: allow cross_migration, a new partial index on sessions (001) over a column the previous release never writes
CREATE INDEX idx_sessions_landed ON sessions (tenant_id, landed_xid, session_id)
    WHERE landed_xid IS NOT NULL;

-- An (expert, profile) position per path in that order: the landing id and the
-- session id of the last session passed. NULL = from the first session landed.
-- `last_processed_at` / `cluster_processed_at` stay what the console shows: the
-- newest activity analyzed. `starts_after` is the instant an admin restarted the
-- profile's analysis from: activity at or before it is not analyzed.

-- migration-lint: allow cross_migration, additive nullable columns on expert_profile_watermarks (001) — the previous release neither reads them nor names them in a write
ALTER TABLE expert_profile_watermarks
    ADD COLUMN session_xid  BIGINT,
    ADD COLUMN session_sid  UUID,
    ADD COLUMN cluster_xid  BIGINT,
    ADD COLUMN cluster_sid  UUID,
    ADD COLUMN starts_after TIMESTAMPTZ;
