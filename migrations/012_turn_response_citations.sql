-- The sources a turn's answer cites (an Anthropic answer's text `citations`),
-- beside the answer's text and calls: each as the console shows a source (its
-- kind, quote, title, URL or source, and place), not the upstream's wire
-- object. NULL when the answer cites none, or its client was sent none. Content, like `response_content`, and it goes with its
-- row (a weekly partition dropped, or the purge).

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue every ingest and read behind a long transaction. A failed
-- migration rolls back whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, an additive nullable column on conversation_turns (001) — the previous release neither reads it nor names it in a write
ALTER TABLE conversation_turns ADD COLUMN response_citations JSONB;

-- The view lists `ct.*` last, so re-creating it picks the new column up at its
-- end and keeps every column before it in place (what `CREATE OR REPLACE`
-- requires). Same definition as 001's and 009's.
-- migration-lint: allow cross_migration, re-creates conversation_turns_resolved (001) with its definition unchanged, so ct.* covers the new column
CREATE OR REPLACE VIEW conversation_turns_resolved WITH (security_invoker = true) AS
    SELECT turn_message_hashes(ct.history_head) AS message_hashes,
           sp.prompt AS system_prompt,
           turn_added_hashes(ct.history_head, ct.added_from, ct.message_count) AS added_hashes,
           ct.*
      FROM conversation_turns ct
      LEFT JOIN system_prompts sp
        ON sp.tenant_id = ct.tenant_id AND sp.hash = ct.system_prompt_hash;
