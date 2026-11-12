-- Local MCP servers: MCP servers that run on the developer's machine. An
-- administrator stores the command line that starts one, grants it to
-- workspaces, and client provisioning writes it into a member's client
-- config. The gateway never connects to one and no edge reads these tables:
-- they are not config body tables.
--
-- Additive: two new tables the previous release neither reads nor writes.

CREATE TABLE mcp_local_servers (
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id               UUID NOT NULL DEFAULT gen_random_uuid(),

    -- slug-justified: the server's key in a client's MCP config and the prefix
    -- of its tool names (`mcp__<slug>__…`), which tool rules match. Addressed
    -- BY it (not a mere label).
    slug             TEXT NOT NULL,
    name             TEXT NOT NULL,
    description      TEXT,

    -- What a client config is written with:
    -- { "command": ..., "args": [...], "env": [{ "name": ..., "value": ..., "secret": ... }] }.
    -- An env entry with no value is filled by the developer; a secret one
    -- holds no value.
    launch           JSONB NOT NULL,

    -- The catalog entry an adopt created the server from. Deleting the entry
    -- forgets the link and keeps the server.
    catalog_entry_id UUID,

    enabled          BOOLEAN NOT NULL DEFAULT true,

    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, slug),
    FOREIGN KEY (tenant_id, catalog_entry_id) REFERENCES mcp_catalog (tenant_id, id)
        ON DELETE SET NULL (catalog_entry_id)
);

-- The catalog list's "adopted as" read, and the foreign key's delete action.
CREATE INDEX idx_mcp_local_servers_catalog_entry
    ON mcp_local_servers (tenant_id, catalog_entry_id) WHERE catalog_entry_id IS NOT NULL;

ALTER TABLE mcp_local_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_local_servers FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_local_servers TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_local_servers OWNER TO streamscope_app;

-- ── Local-server allowlist: which workspaces are handed a local server ───────
CREATE TABLE workspace_mcp_local_access (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id    UUID NOT NULL,
    local_server_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, local_server_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, local_server_id) REFERENCES mcp_local_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_workspace_mcp_local_access_server
    ON workspace_mcp_local_access (tenant_id, local_server_id);

ALTER TABLE workspace_mcp_local_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_mcp_local_access FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_mcp_local_access TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_mcp_local_access OWNER TO streamscope_app;
