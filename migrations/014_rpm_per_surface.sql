-- Requests per minute are capped per surface: the existing columns cap LLM
-- requests (chat, media, `/v1/analyze`), the new `*_mcp` columns MCP requests
-- (the built-in Web server included) and the `*_a2a` columns A2A requests. Each
-- level that carried a request rate carries all three, with the same meaning:
-- on the pool and the member default NULL is no cap; on a member exception NULL
-- inherits the default, 0 is unlimited, a positive value is the member's own.

-- Metadata-only additions, but they need each table's exclusive lock: give up
-- rather than queue behind a long transaction. A failed migration rolls back
-- whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, additive nullable columns on workspace_rate_limits (001) — the previous release neither reads them nor names them in a write
ALTER TABLE workspace_rate_limits
    ADD COLUMN requests_per_minute_mcp INTEGER,
    ADD COLUMN requests_per_minute_a2a INTEGER,
    ADD COLUMN member_requests_per_minute_mcp INTEGER,
    ADD COLUMN member_requests_per_minute_a2a INTEGER;

-- migration-lint: allow cross_migration, additive nullable columns on workspace_user_rate_limit_overrides (001) — the previous release neither reads them nor names them in a write
ALTER TABLE workspace_user_rate_limit_overrides
    ADD COLUMN requests_per_minute_mcp INTEGER,
    ADD COLUMN requests_per_minute_a2a INTEGER;

-- Every request rate set before this release capped every surface's requests,
-- so each new column starts as a copy of it: no surface an install capped
-- becomes unlimited. (NULL stays NULL, 0 stays 0.)
--
-- Once per tenant under that tenant's GUC: both tables are FORCE RLS, so a
-- non-superuser migrator sees no row without it. The per-tenant assertion reads
-- through the same RLS as the updates, so it catches an update that missed a
-- row it could see.
DO $$
DECLARE
    t UUID;
    left_over BIGINT;
BEGIN
    FOR t IN SELECT id FROM tenants LOOP
        PERFORM set_config('app.tenant_id', t::text, true);

        UPDATE workspace_rate_limits
           SET requests_per_minute_mcp = requests_per_minute,
               requests_per_minute_a2a = requests_per_minute,
               member_requests_per_minute_mcp = member_requests_per_minute,
               member_requests_per_minute_a2a = member_requests_per_minute
         WHERE tenant_id = t;

        UPDATE workspace_user_rate_limit_overrides
           SET requests_per_minute_mcp = requests_per_minute,
               requests_per_minute_a2a = requests_per_minute
         WHERE tenant_id = t;

        SELECT (SELECT count(*) FROM workspace_rate_limits
                 WHERE tenant_id = t
                   AND (requests_per_minute_mcp IS DISTINCT FROM requests_per_minute
                        OR requests_per_minute_a2a IS DISTINCT FROM requests_per_minute
                        OR member_requests_per_minute_mcp IS DISTINCT FROM member_requests_per_minute
                        OR member_requests_per_minute_a2a IS DISTINCT FROM member_requests_per_minute))
             + (SELECT count(*) FROM workspace_user_rate_limit_overrides
                 WHERE tenant_id = t
                   AND (requests_per_minute_mcp IS DISTINCT FROM requests_per_minute
                        OR requests_per_minute_a2a IS DISTINCT FROM requests_per_minute))
          INTO left_over;
        IF left_over <> 0 THEN
            RAISE EXCEPTION 'request-rate copy left % row(s) unchanged in tenant %', left_over, t;
        END IF;
    END LOOP;
END
$$;
