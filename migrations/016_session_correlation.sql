-- A conversation records the client session id its turns came under
-- (`gateway_audit.session_id`) when it is keyed by another id — its content.
-- A client that sends its session id on its MCP or A2A calls too has those
-- calls in a session keyed by that id, with no turn; the Sessions list folds
-- that session under the conversation naming it, which links to it. NULL on a
-- conversation keyed by its client session id (a media call with no history),
-- on one under no client session id, and on every session no turn has landed
-- on since this column exists.

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue behind a long transaction. A failed migration rolls back
-- whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive nullable column on sessions (001) — the previous release neither reads it nor names it in a write
ALTER TABLE sessions ADD COLUMN correlation_id UUID;

-- What the Sessions list asks of each session with no turn: does a
-- conversation name it. Partial: most sessions name none, and every session
-- that exists when this runs names none, so the build writes no entry — but it
-- reads the table once, under the ALTER's lock, which every reader and writer
-- of `sessions` waits behind until this migration commits.
-- migration-lint: allow cross_migration, a new partial index on sessions (001) over a column the previous release never writes
CREATE INDEX idx_sessions_correlation ON sessions (tenant_id, correlation_id)
    WHERE correlation_id IS NOT NULL;
