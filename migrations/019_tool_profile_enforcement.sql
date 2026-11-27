-- Whether a tool-policy profile applies its block and rewrite rules
-- (`enforce`) or only records what they would have done (`observe`). Only a
-- `tools` profile carries one. NULL is a profile no administrator has
-- switched: a Layered profile then follows the Default, and the Default or a
-- Standalone profile observes — so every organisation's tool policy observes
-- until an administrator switches it to Enforce, with no row to rewrite here.

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue behind a long transaction. A failed migration rolls back
-- whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive nullable column on profiles (001) — the previous release neither reads it nor names it in a write, and enforces every profile as it did
ALTER TABLE profiles ADD COLUMN tool_enforcement TEXT
    CHECK (tool_enforcement IN ('enforce', 'observe'))
    CHECK (kind = 'tools' OR tool_enforcement IS NULL);
