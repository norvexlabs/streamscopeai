-- What a developer's sandbox may reach besides the gateway, before any
-- destination list is read: `gateway` (nothing), `listed` (what an allow list
-- names, unless a block list names it) or `open` (everything a block list does
-- not name). NULL reads `listed`, so a profile written before this column keeps
-- the reach it had; a profile created from the seed is written `open`.

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue behind a long transaction. A failed migration rolls back
-- whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive nullable column on client_access_sandbox (001) — the previous release neither reads it nor names it in a write, and reads every profile as `listed`
ALTER TABLE client_access_sandbox ADD COLUMN network_posture TEXT
    CHECK (network_posture IN ('gateway', 'listed', 'open'));
