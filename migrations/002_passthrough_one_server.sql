-- A pass-through is one unit: a keyless upstream server and the one `byok`
-- downstream provider linked to it. The delete that removes either half removes
-- both (and revokes the keys bound to the provider); these two guards make any
-- other write that would split the pair, or pair one server twice, fail instead
-- of leaving a half behind.
--
-- Neither changes what the previous release writes: it creates a `byok`
-- provider only together with a new server, deletes a server only after the
-- pass-through linked to it, and never links a second one.

-- At most one pass-through per server.
-- migration-lint: allow cross_migration, a new partial unique index on downstream_providers (001) — the previous release never links two byok providers to one server
CREATE UNIQUE INDEX idx_downstream_providers_one_passthrough
    ON downstream_providers (tenant_id, upstream_server_id) WHERE byok;

-- A pass-through always has its server: deleting the server alone (the foreign
-- key would null the link) now fails. NOT VALID checks every new or updated row
-- without scanning the existing ones.
-- migration-lint: allow cross_migration, an additive CHECK on downstream_providers (001) that every row the previous release writes satisfies
ALTER TABLE downstream_providers
    ADD CONSTRAINT downstream_providers_passthrough_has_server
    CHECK (NOT byok OR upstream_server_id IS NOT NULL) NOT VALID;
