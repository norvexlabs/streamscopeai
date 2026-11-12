-- What a client-access profile hides in the portal from the members of the
-- workspaces on it: one row per profile, one column per switch. A switch a
-- later release adds is a new column defaulting to shown.
--
-- Additive: the previous release neither reads nor writes the table, and a
-- profile without a row hides nothing.
CREATE TABLE client_access_portal (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id    UUID NOT NULL,
    -- The Sessions page and every conversation's content.
    hide_sessions BOOLEAN NOT NULL DEFAULT false,
    -- The Requests page (the per-request list).
    hide_requests BOOLEAN NOT NULL DEFAULT false,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, profile_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE client_access_portal ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_access_portal FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client_access_portal TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE client_access_portal OWNER TO streamscope_app;
