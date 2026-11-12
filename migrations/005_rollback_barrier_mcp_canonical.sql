-- The MCP catalog stores canonical `server.json` documents, and an upstream's
-- credentials are the header inputs its adopted remote declares, each filled by
-- the administrator, the user or the calling client. The previous upstream
-- modes (`no_auth`, `service_account`, `byot`) and the catalog's descriptive
-- columns are gone, so this release resets every tenant's MCP configuration:
-- the catalog (it is seeded again at boot), every upstream, virtual server and
-- route, and every user connection — except the built-in web upstream and the
-- virtual server routed to it, which are kept and moved to the new shape.
--
-- A rollback barrier: the previous release reads the dropped columns.

-- The old CHECK refuses the value the built-in rows move to below.
-- migration-lint: allow cross_migration, the auth_mode CHECK swap of a rollback barrier
ALTER TABLE mcp_upstream_servers DROP CONSTRAINT mcp_upstream_servers_auth_mode_check;

-- The reset runs once per tenant under that tenant's GUC: every MCP table is
-- FORCE RLS, so a non-superuser migrator sees no row without it. Order follows
-- the foreign keys: a route RESTRICTs its upstream's delete, and a virtual
-- server's delete cascades to its grants, sessions, pending authorizations and
-- spec-OAuth codes and tokens; an upstream's to its user credentials.
--
-- The per-tenant assertion reads through the same RLS as the deletes, so it
-- catches a delete that missed rows it could see. A row the loop could not see
-- at all (a GUC that did not take) is caught after it: the new auth_mode CHECK,
-- the built-in-only credential CHECK and the catalog's NOT NULL document are
-- each validated over every row, whatever RLS shows.
DO $$
DECLARE
    t UUID;
    left_over BIGINT;
BEGIN
    FOR t IN SELECT id FROM tenants LOOP
        PERFORM set_config('app.tenant_id', t::text, true);

        -- An admin may have routed the built-in web server to an upstream of
        -- its own; those routes go with their upstream.
        DELETE FROM mcp_virtual_routes r
         USING mcp_upstream_servers u
         WHERE u.tenant_id = r.tenant_id AND u.id = r.upstream_server_id
           AND r.tenant_id = t AND NOT u.built_in;

        -- The built-in web server is the one still routed to a built-in
        -- upstream (its slug is editable, so it is not the key).
        DELETE FROM mcp_virtual_servers v
         WHERE v.tenant_id = t
           AND NOT EXISTS (
               SELECT 1 FROM mcp_virtual_routes r
                 JOIN mcp_upstream_servers u
                   ON u.tenant_id = r.tenant_id AND u.id = r.upstream_server_id
                WHERE r.tenant_id = v.tenant_id AND r.virtual_server_id = v.id AND u.built_in);

        DELETE FROM mcp_upstream_servers WHERE tenant_id = t AND NOT built_in;

        UPDATE mcp_upstream_servers SET auth_mode = 'headers' WHERE tenant_id = t AND built_in;

        DELETE FROM mcp_catalog WHERE tenant_id = t;

        SELECT (SELECT count(*) FROM mcp_upstream_servers WHERE tenant_id = t AND NOT built_in)
             + (SELECT count(*) FROM mcp_virtual_servers v
                 WHERE v.tenant_id = t
                   AND NOT EXISTS (
                       SELECT 1 FROM mcp_virtual_routes r
                         JOIN mcp_upstream_servers u
                           ON u.tenant_id = r.tenant_id AND u.id = r.upstream_server_id
                        WHERE r.tenant_id = v.tenant_id AND r.virtual_server_id = v.id AND u.built_in))
             + (SELECT count(*) FROM mcp_catalog WHERE tenant_id = t)
          INTO left_over;
        IF left_over <> 0 THEN
            RAISE EXCEPTION 'MCP configuration reset left % row(s) in tenant %', left_over, t;
        END IF;
    END LOOP;
END
$$;

-- ── Upstreams ──────────────────────────────────────────────────────────────

-- migration-lint: allow cross_migration, the auth_mode CHECK swap of a rollback barrier
ALTER TABLE mcp_upstream_servers
    ADD CONSTRAINT mcp_upstream_servers_auth_mode_check CHECK (auth_mode IN ('headers', 'per_user_oauth'));
-- migration-lint: allow cross_migration, the auth_mode default follows the new CHECK
ALTER TABLE mcp_upstream_servers ALTER COLUMN auth_mode SET DEFAULT 'headers';

-- The adopted `server.json` remote: declared headers and, in its `_meta`, the
-- filler of each input. `{}` declares nothing (the built-in web upstream).
-- migration-lint: allow cross_migration, an additive column with a default
ALTER TABLE mcp_upstream_servers ADD COLUMN remote JSONB NOT NULL DEFAULT '{}';
-- Admin-filled input id → AES-256-GCM ciphertext (base64), one per input.
-- migration-lint: allow cross_migration, an additive column with a default
ALTER TABLE mcp_upstream_servers ADD COLUMN encrypted_admin_inputs JSONB NOT NULL DEFAULT '{}';
-- The user-filled inputs a user must fill before the upstream is usable
-- (required, no default), so a connection's status is one SQL predicate.
-- migration-lint: allow cross_migration, an additive column with a default
ALTER TABLE mcp_upstream_servers ADD COLUMN required_user_input_ids TEXT[] NOT NULL DEFAULT '{}';
-- `encrypted_credential` now holds only the built-in web upstream's search key.
-- migration-lint: allow cross_migration, every row left after the reset satisfies it
ALTER TABLE mcp_upstream_servers
    ADD CONSTRAINT mcp_upstream_servers_credential_built_in CHECK (encrypted_credential IS NULL OR built_in);

-- ── Users' filled inputs ──────────────────────────────────────────────────

-- One row per (user, upstream): input id → AES-256-GCM ciphertext (base64).
-- Only the ids the upstream declares as user-filled are ever read from it.
CREATE TABLE mcp_user_inputs (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL,
    upstream_server_id  UUID NOT NULL,
    encrypted_values    JSONB NOT NULL DEFAULT '{}',
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, user_id, upstream_server_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, upstream_server_id) REFERENCES mcp_upstream_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_mcp_user_inputs_upstream ON mcp_user_inputs (tenant_id, upstream_server_id);

ALTER TABLE mcp_user_inputs ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_user_inputs FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_user_inputs TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_user_inputs OWNER TO streamscope_app;

-- The config body ships the rows to every edge, so a change bumps the tenant
-- (`config_builder::BODY_TABLES` lists it).
DO $$
DECLARE
    config_body_tables text[] := ARRAY[
        'mcp_user_inputs'
    ];
    t text;
BEGIN
    FOREACH t IN ARRAY config_body_tables LOOP
        EXECUTE format(
            'CREATE TRIGGER config_bump_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS new_rows '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, 'tenant_id');
        EXECUTE format(
            'CREATE TRIGGER config_bump_upd AFTER UPDATE ON %I REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, 'tenant_id');
        EXECUTE format(
            'CREATE TRIGGER config_bump_del AFTER DELETE ON %I REFERENCING OLD TABLE AS old_rows '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, 'tenant_id');
        EXECUTE format(
            'CREATE TRIGGER config_bump_trunc AFTER TRUNCATE ON %I '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, 'tenant_id');
    END LOOP;
END
$$;

-- ── Catalog ────────────────────────────────────────────────────────────────
-- The entry is its `server.json` document; the descriptive, transport, auth
-- and OAuth-hint columns are read from it (`_meta."ai.streamscope/catalog"`).
-- The table is empty here (reset above), so the new NOT NULL needs no default.

-- migration-lint: allow drop_column, the catalog entry is its server.json document
ALTER TABLE mcp_catalog DROP COLUMN name;
-- migration-lint: allow drop_column, read from server_json.title
ALTER TABLE mcp_catalog DROP COLUMN display_title;
-- migration-lint: allow drop_column, read from server_json.description
ALTER TABLE mcp_catalog DROP COLUMN description;
-- migration-lint: allow drop_column, read from server_json._meta (its index goes with it)
ALTER TABLE mcp_catalog DROP COLUMN category;
-- migration-lint: allow drop_column, read from server_json._meta
ALTER TABLE mcp_catalog DROP COLUMN featured;
-- migration-lint: allow drop_column, read from server_json.websiteUrl
ALTER TABLE mcp_catalog DROP COLUMN website_url;
-- migration-lint: allow drop_column, read from server_json.repository
ALTER TABLE mcp_catalog DROP COLUMN repository_url;
-- migration-lint: allow drop_column, read from server_json.icons
ALTER TABLE mcp_catalog DROP COLUMN icon_url;
-- migration-lint: allow drop_column, read from server_json.remotes
ALTER TABLE mcp_catalog DROP COLUMN upstream_url;
-- migration-lint: allow drop_column, read from server_json.remotes
ALTER TABLE mcp_catalog DROP COLUMN transport;
-- migration-lint: allow drop_column, the remote's headers and _meta OAuth hints replace it
ALTER TABLE mcp_catalog DROP COLUMN auth_mode;
-- migration-lint: allow drop_column, read from server_json._meta OAuth hints
ALTER TABLE mcp_catalog DROP COLUMN oauth_issuer_url;
-- migration-lint: allow drop_column, read from server_json._meta OAuth hints
ALTER TABLE mcp_catalog DROP COLUMN oauth_authorization_url;
-- migration-lint: allow drop_column, read from server_json._meta OAuth hints
ALTER TABLE mcp_catalog DROP COLUMN oauth_token_url;
-- migration-lint: allow drop_column, read from server_json._meta OAuth hints
ALTER TABLE mcp_catalog DROP COLUMN oauth_revocation_url;
-- migration-lint: allow drop_column, read from server_json._meta OAuth hints
ALTER TABLE mcp_catalog DROP COLUMN oauth_default_scopes;
-- migration-lint: allow drop_column, read from server_json._meta
ALTER TABLE mcp_catalog DROP COLUMN tools;
-- migration-lint: allow drop_column, read from server_json._meta
ALTER TABLE mcp_catalog DROP COLUMN tool_count;
-- migration-lint: allow drop_column, read from server_json._meta
ALTER TABLE mcp_catalog DROP COLUMN liveness;
-- The whole `server.json` document (schema 2025-12-11).
-- migration-lint: allow add_not_null, the table is empty after the reset
ALTER TABLE mcp_catalog ADD COLUMN server_json JSONB NOT NULL;
