-- The distinct badge codes the LLM turns of a session carried: what the
-- Sessions list filters on and shows as chips. Written by the turn's own
-- session upsert as the union of what it held and the turn's codes; empty on
-- every session no turn has landed on since this column exists (no backfill).
-- Not indexed: the list's overlap test (`&&`) is not leakproof, so under FORCE
-- RLS no index could serve it (and no GIN index goes on a FORCE-RLS table);
-- the list reads it on the window's rows.

-- A metadata-only change (a constant default), but it needs the table's
-- exclusive lock: give up rather than queue behind a long transaction. A
-- failed migration rolls back whole and the previous release still fits the
-- database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive column on sessions (001) with a constant default — the previous release neither reads it nor names it in a write, and every row it inserts takes the empty default
ALTER TABLE sessions ADD COLUMN badge_codes TEXT[] NOT NULL DEFAULT '{}';
