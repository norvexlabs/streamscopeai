-- A turn's history is named twice. Its chain (`history_head`) names each message
-- by the hash of the message as stored, so a stored body is only ever read back
-- for the request that sent those exact bytes. `link_head` is the digest a chain
-- built over the session-link hashes would end in — only the digest is stored,
-- never that chain's chunks — the link hashes leaving out what a client
-- injects and withdraws between turns (a `<system-reminder>`, a moved cache
-- breakpoint): the next turn of the session compares its own link chain with
-- this head to tell which leading messages it repeats (`added_from`), so a
-- reminder that changed in an old message does not make the turn a baseline.
--
-- NULL when the writer had no link hashes for the turn. On a turn written before
-- this column existed, `history_head` was built over the link hashes and stands
-- in for it. Any other NULL — a record with no link hashes, or a turn a previous
-- release wrote after this migration — leaves a `history_head` over stored keys,
-- which no link chain matches: the next turn is then written as a baseline, the
-- conservative reading, never as continuing the wrong history.

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue every ingest and read behind a long transaction. A failed
-- migration rolls back whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive nullable column on conversation_turns (001) — the previous release neither reads it nor names it in a write
ALTER TABLE conversation_turns ADD COLUMN link_head TEXT;

-- The view lists `ct.*` last, so re-creating it picks the new column up at its
-- end and keeps every column before it in place (what `CREATE OR REPLACE`
-- requires). Same definition as 001's.
-- migration-lint: allow cross_migration, re-creates conversation_turns_resolved (001) with its definition unchanged, so ct.* covers the new column
CREATE OR REPLACE VIEW conversation_turns_resolved WITH (security_invoker = true) AS
    SELECT turn_message_hashes(ct.history_head) AS message_hashes,
           sp.prompt AS system_prompt,
           turn_added_hashes(ct.history_head, ct.added_from, ct.message_count) AS added_hashes,
           ct.*
      FROM conversation_turns ct
      LEFT JOIN system_prompts sp
        ON sp.tenant_id = ct.tenant_id AND sp.hash = ct.system_prompt_hash;
