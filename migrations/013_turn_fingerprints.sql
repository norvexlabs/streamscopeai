-- What lets the ingest tell that a new conversation QUOTES an earlier turn of
-- the same user: the agent's compaction re-sending an answer (a continuation),
-- a subagent opening with its parent's tool-call argument (a child). One row
-- per segment — a line of prose, named by 8 bytes of its SHA-256 — of a landed
-- turn's answer (`answer`), of each string argument of its tool calls
-- (`argument`, `part` = the argument's place in the call), and of a session's
-- opening message (`opening`, the quoting side only). `part_size` is how many
-- segments that text has, so a lookup can tell a whole quote from a stray line.
--
-- Written only by the edge ingest, in the request's transaction, for a turn it
-- inserts for the first time; read by the same ingest. Kept for a day: a quote
-- is looked for only that far back, and the retention purge deletes older rows.
CREATE TABLE turn_fingerprints (
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    user_id        UUID NOT NULL,
    kind           TEXT NOT NULL CHECK (kind IN ('answer', 'argument', 'opening')),
    fp             BIGINT NOT NULL,
    request_id     UUID NOT NULL,
    session_id     UUID NOT NULL,
    turn_number    INT,
    tool_call_id   TEXT NOT NULL,   -- '' unless kind = 'argument'
    part           SMALLINT NOT NULL,
    part_size      SMALLINT NOT NULL,
    -- When the text came to exist: an answer or an argument at its turn's
    -- end, an opening at its turn's start. Only a later turn quotes it.
    timestamp      TIMESTAMPTZ NOT NULL,
    -- `kind` before `fp`: a lookup reads one kind's rows of a line, never the
    -- others sharing it.
    PRIMARY KEY (tenant_id, user_id, kind, fp, request_id, tool_call_id, part)
);

-- One opening's segments, by its request: what a link is decided from.
CREATE INDEX idx_turn_fingerprints_request ON turn_fingerprints (tenant_id, request_id);
CREATE INDEX idx_turn_fingerprints_purge ON turn_fingerprints (tenant_id, timestamp);

ALTER TABLE turn_fingerprints ENABLE ROW LEVEL SECURITY;
ALTER TABLE turn_fingerprints FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON turn_fingerprints TO streamscope_app
    USING (tenant_id = current_tenant_id());
GRANT SELECT, INSERT, UPDATE, DELETE ON turn_fingerprints TO streamscope_ingest;
CREATE POLICY ingest_all ON turn_fingerprints TO streamscope_ingest USING (true) WITH CHECK (true);

ALTER TABLE turn_fingerprints OWNER TO streamscope_app;

-- A session is linked to at most one other — the child of one parent or the
-- successor of one predecessor, never both: the one guard every link writer
-- (the ingest's content links, the agent's linkage) writes under, `ON
-- CONFLICT DO NOTHING`, so two writers racing on one session leave one link.
-- Builds on any earlier data: a session has at most one `child` row (the
-- one-parent index), and no earlier release writes `successor`; one that
-- writes a `child` beside such a link meets its own `ON CONFLICT DO NOTHING`.
-- migration-lint: allow cross_migration, a new partial unique index on cross_session_relation_members (001); existing rows satisfy it and every writer conflicts quietly
CREATE UNIQUE INDEX idx_cross_session_members_one_link
    ON cross_session_relation_members (tenant_id, session_id)
    WHERE role IN ('child', 'successor');
