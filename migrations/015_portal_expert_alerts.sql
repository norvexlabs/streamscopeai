-- Whether the portal shows the experts' alerts on the sessions of the
-- workspaces on a Portal & clients profile: the session's alert, the
-- `session_alert` badge of its requests and its sub-agents' alerts on the
-- parent. Decided per session, by the profile of the session's own workspace.
-- NOT NULL DEFAULT false: every profile, existing or new, shows them until an
-- administrator hides them.

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue behind a long transaction. A failed migration rolls back
-- whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive column with a constant default on client_access_portal (008) — the previous release neither reads it nor names it in a write, and withholds every alert from members
ALTER TABLE client_access_portal ADD COLUMN hide_alerts BOOLEAN NOT NULL DEFAULT false;
