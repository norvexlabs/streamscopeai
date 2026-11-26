-- A workspace's own agent loop guard: what the gateway does when a request's
-- history repeats a tool-call cycle, and the two repetition counts it acts at.
-- All three NULL inherit the tenant default whole; all three set are the
-- workspace's own. The tenant default lives in `system_settings`.

-- Nullable columns add without a rewrite, but the CHECKs are validated
-- against every row under the table's exclusive lock (one row per workspace,
-- so a short scan): give up rather than queue behind a long transaction. A
-- failed migration rolls back whole and the previous release still fits the
-- database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, additive nullable columns and CHECKs on workspace_rate_limits (001) — the previous release neither reads them nor names them in a write, and every row it writes leaves them NULL
ALTER TABLE workspace_rate_limits
    ADD COLUMN loop_guard_mode TEXT
        CONSTRAINT workspace_rate_limits_loop_guard_mode_known
        CHECK (loop_guard_mode IN ('off', 'observe', 'nudge', 'stop')),
    ADD COLUMN loop_guard_nudge_at INTEGER,
    ADD COLUMN loop_guard_stop_at INTEGER,
    ADD CONSTRAINT workspace_rate_limits_loop_guard_whole
        CHECK ((loop_guard_mode IS NULL) = (loop_guard_nudge_at IS NULL)
           AND (loop_guard_mode IS NULL) = (loop_guard_stop_at IS NULL)),
    ADD CONSTRAINT workspace_rate_limits_loop_guard_bounds
        CHECK (loop_guard_mode IS NULL
            OR (loop_guard_nudge_at >= 2
                AND loop_guard_stop_at >= loop_guard_nudge_at + 2
                AND loop_guard_stop_at <= 50));
