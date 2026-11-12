-- An MCP upstream keeps the values its URL was finished with, so an edit of
-- one variable keeps the others, and names the catalog entry it was adopted
-- from, so the catalog can say which of its entries are in use.
--
-- Both are additive: the previous release neither reads nor writes them, and
-- every row it inserts takes the defaults (no values, no catalog entry).

-- URL variable name → the value the finished URL was built from. URL
-- variables are never secret.
-- migration-lint: allow cross_migration, an additive column with a DEFAULT on mcp_upstream_servers (001) — the previous release neither reads it nor names it in a write
ALTER TABLE mcp_upstream_servers
    ADD COLUMN url_variables JSONB NOT NULL DEFAULT '{}';

-- The catalog entry an adopt created the upstream from. Deleting the entry
-- forgets the link and keeps the upstream.
-- migration-lint: allow cross_migration, an additive nullable column on mcp_upstream_servers (001) — the previous release neither reads it nor names it in a write
ALTER TABLE mcp_upstream_servers
    ADD COLUMN catalog_entry_id UUID;

-- migration-lint: allow cross_migration, an additive composite foreign key on mcp_upstream_servers (001) over a column only this release writes
ALTER TABLE mcp_upstream_servers
    ADD CONSTRAINT mcp_upstream_servers_catalog_entry_fk
    FOREIGN KEY (tenant_id, catalog_entry_id) REFERENCES mcp_catalog (tenant_id, id)
    ON DELETE SET NULL (catalog_entry_id);

-- The catalog list's "adopted as" read, and the foreign key's delete action.
-- migration-lint: allow cross_migration, a new partial index on mcp_upstream_servers (001) over a column the previous release never writes
CREATE INDEX idx_mcp_upstream_servers_catalog_entry
    ON mcp_upstream_servers (tenant_id, catalog_entry_id) WHERE catalog_entry_id IS NOT NULL;

-- What the `ssai` CLI holding a CLI access token says it is, from its
-- `User-Agent` (`ssai/<version> (<os>; <host>)`): stamped with `last_used_at`
-- on the CLI provisioning auth path, so the portal Home can name each host
-- whose CLI is older than the one the gateway serves. Self-reported, never
-- an authorisation input. NULL = not reported (an older CLI, another client,
-- or not seen since).
-- migration-lint: allow cross_migration, additive nullable columns on oauth_issued_tokens (001) — the previous release neither reads them nor names them in a write
ALTER TABLE oauth_issued_tokens
    ADD COLUMN cli_version TEXT,
    ADD COLUMN cli_os TEXT,
    ADD COLUMN cli_host TEXT;
