-- Baseline schema, epoch 4 — the whole database in one file.
--
-- sqlx tracks every migration by file checksum, and every deployed database has
-- already applied this one, so ANY edit here — a column, a comment, whitespace —
-- changes that checksum and makes the next deploy fail its migration check.
-- A schema change is a new additive migration (`002_*.sql`, …) alongside it.
--
-- An epoch is the schema together with what a database is created with — its
-- PostgreSQL major and its locale, which admin-api's start-up pre-flight
-- requires: `stowage.yaml`'s `database.schema_compat.baseline` names the epoch,
-- and an install moves across it only by a fresh install, never an in-place
-- migration.
--
-- Shape rules every table here follows (held by `test_schema_shape.py` and
-- `lint-migrations.sh`):
--   R1  a tenant table carries `tenant_id UUID NOT NULL REFERENCES tenants ON
--       DELETE CASCADE` with no DEFAULT, ENABLE + FORCE row-level security and
--       the one policy `tenant_isolation … TO streamscope_app USING (tenant_id =
--       current_tenant_id())`;
--   R2  its keys lead with `tenant_id` — the primary key, every unique and every
--       secondary index — except the global credential / pre-auth lookups named
--       where they are declared;
--   R3  a reference to another tenant table is composite, `(tenant_id, x)`, so
--       a row can never point into another tenant; ON DELETE SET NULL names the
--       column it nulls;
--   R4  no GIN / GiST / SP-GiST index, except those read only by the lookup
--       functions at the end of this file;
--   R5  no expression index over a non-leakproof function: a derived key is a
--       stored generated column with a btree index;
--   R6  a content-addressed store is stamped with `last_referenced_at` and
--       purged by range, never by reference scan;
--   R7  audit and turn tables are partitioned by week (retention.rs creates the
--       partitions; only `_default` is declared here);
--   R8  the special roles below are reached only by `SET LOCAL ROLE` — the
--       runtime role never inherits their privileges.

-- ============ Roles ============
-- The runtime role (`streamscope_app`) connects from admin-api and does NOT
-- bypass row-level security. Three NOLOGIN roles widen it for one transaction
-- at a time, each reached by `SET LOCAL ROLE` from a named door in `db/`:
--   * streamscope_global — global tables and `tenants` only: a query on a
--     tenant table under it is `permission denied`, never a silently empty
--     result (`Db::global`);
--   * streamscope_ingest — the edge ingest writer: DML on the tables it writes,
--     across tenants, in one transaction per request (`IngestTx`);
--   * streamscope_lookup — owns the SECURITY DEFINER lookup functions; it reads
--     across tenants, and only those functions run as it.
--
-- The runtime role is granted global and ingest WITH INHERIT FALSE, SET TRUE
-- (it may switch to them, never holds their rights implicitly) and is never a
-- member of lookup; admin-api refuses to start otherwise (`check_roles`).
--
-- On a superuser migrator (the VM, Docker, embedded Kubernetes) this block
-- creates what is missing. A managed migrator has no CREATEROLE: the operator
-- creates the roles and grants first (docs/OPERATOR_GUIDE.md), and the block
-- then only verifies — a missing role or grant fails here, loudly.
DO $$
DECLARE
    r TEXT;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'streamscope_app') THEN
        CREATE ROLE streamscope_app LOGIN PASSWORD 'streamscope' NOBYPASSRLS;
    END IF;
    IF current_user = 'streamscope_app' THEN
        RAISE EXCEPTION 'migrations run as streamscope_app: the migration role must be a separate role (it owns the lookup functions, which the runtime role must never reach)';
    END IF;
    FOREACH r IN ARRAY ARRAY['streamscope_global', 'streamscope_ingest', 'streamscope_lookup'] LOOP
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
            EXECUTE format('CREATE ROLE %I NOLOGIN', r);
        END IF;
    END LOOP;
    FOREACH r IN ARRAY ARRAY['streamscope_global', 'streamscope_ingest'] LOOP
        IF NOT pg_has_role('streamscope_app', r, 'SET') THEN
            EXECUTE format('GRANT %I TO streamscope_app WITH INHERIT FALSE, SET TRUE', r);
        END IF;
    END LOOP;
    IF NOT pg_has_role(current_user, 'streamscope_lookup', 'SET') THEN
        EXECUTE format('GRANT streamscope_lookup TO %I', current_user);
    END IF;
END $$;

GRANT USAGE, CREATE ON SCHEMA public TO streamscope_app;
GRANT USAGE ON SCHEMA public TO streamscope_global, streamscope_ingest;
-- The lookup role owns functions in this schema.
GRANT USAGE, CREATE ON SCHEMA public TO streamscope_lookup;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES    TO streamscope_app;
ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON SEQUENCES TO streamscope_app;

CREATE EXTENSION IF NOT EXISTS pg_trgm;
CREATE EXTENSION IF NOT EXISTS btree_gin;

-- The epoch this schema is: what `stowage.yaml`'s schema baseline names.
-- intentional: no RLS, a single global marker row
CREATE TABLE schema_epoch (
    epoch       INTEGER PRIMARY KEY,
    applied_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO schema_epoch (epoch) VALUES (4);
ALTER TABLE schema_epoch OWNER TO streamscope_app;

-- ============ The tenant predicate ============
-- The ONE expression every row-level-security policy is written against. Every
-- tenant-scoped table's policy is exactly `USING (tenant_id = current_tenant_id())`
-- and nothing else — one name, one shape, so a policy cannot be subtly wrong.
--
-- Returns the tenant bound to this connection, or NULL when there isn't one.
-- NULL compares as NULL, so a query on an unscoped connection matches **zero
-- rows**: RLS is fail-closed. Three inputs must all reach that same NULL, and
-- each is reachable in production:
--   * the GUC was never set (a fresh pooled connection);
--   * the GUC is the empty string — what `RESET` leaves behind, so this is the
--     steady state of every connection the pool hands back, not an edge case;
--   * the GUC holds something that is not a UUID, which only a hand-rolled
--     setter could produce (`db/tenant.rs` is the only writer and binds a real
--     `Uuid`).
--
-- Every word of the signature is load-bearing; do not relax any of them:
--   * STABLE, never IMMUTABLE — IMMUTABLE would let the planner fold one
--     tenant's id into a cached plan and serve it to the next tenant on that
--     connection. STABLE re-reads per statement, which is what makes
--     `SET LOCAL` scoping and the borrow/restore in `with_system_scope` work.
--   * PARALLEL SAFE — a function defaults to PARALLEL UNSAFE, which would
--     silently disable parallel plans for every query touching an RLS table.
--     GUC values propagate to parallel workers, so this is genuinely safe.
--   * SECURITY INVOKER (stated, not merely defaulted) — the function needs no
--     elevated rights, and DEFINER would only add attack surface.
--   * a pinned `search_path` plus a schema-qualified body — a plpgsql body
--     resolves its references at call time under the CALLER's search_path, so
--     without both, a shadowing `current_setting` could capture it.
--   * the narrow `invalid_text_representation` handler, never `WHEN OTHERS` —
--     22P02 is exactly the malformed-UUID class, while OTHERS would swallow an
--     out-of-memory or similar into a silent empty result, which is the very
--     failure mode this codebase treats as the dangerous one.
--
-- Keep it owned by the migration role: `CREATE OR REPLACE` then requires that
-- ownership, and the policies bind the function by OID, so a later same-named
-- function created by the runtime role cannot redirect them.
CREATE FUNCTION current_tenant_id() RETURNS uuid
LANGUAGE plpgsql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    RETURN NULLIF(pg_catalog.current_setting('app.tenant_id', true), '')::uuid;
EXCEPTION WHEN invalid_text_representation THEN
    RETURN NULL;
END $$;

-- intentional: no RLS, global registry (every tenant_id FK targets this).
CREATE TABLE tenants (
    id          UUID PRIMARY KEY,
    name        TEXT NOT NULL,
    -- slug-justified: the tenant URL handle — routes (`/t/<slug>`, `/portal/t/<slug>`,
    -- `/mcp/<slug>` mounts), forward-auth selector, and bookmark-stable. Addressed BY it.
    slug        TEXT NOT NULL,
    is_active   BOOLEAN NOT NULL DEFAULT true,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$')
);

CREATE UNIQUE INDEX idx_tenants_slug ON tenants(slug);
CREATE INDEX idx_tenants_name ON tenants(name);

ALTER TABLE tenants OWNER TO streamscope_app;
GRANT SELECT ON tenants TO streamscope_global, streamscope_ingest, streamscope_lookup;

-- SYSTEM tenant — platform-operator tenant for super-admins.
INSERT INTO tenants (id, name, slug) VALUES
    ('00000000-0000-0000-0000-000000000001', 'System', 'system');

-- ============ Users ============
-- End users (LLM/MCP callers). Portal login columns inline.

CREATE TABLE users (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL,
    email           TEXT NOT NULL,
    display_name    TEXT,
    role            TEXT NOT NULL DEFAULT 'user',
    settings        JSONB NOT NULL DEFAULT '{}',
    -- Portal credentials (set only when auth_mode='internal').
    password_hash   TEXT,
    auth_source     TEXT,
    last_login_at   TIMESTAMPTZ,
    is_active       BOOLEAN NOT NULL DEFAULT true,
    -- Portal sessions issued at or before this instant are refused. Signing out
    -- stamps it, so a token captured earlier stops working at once rather than
    -- living out the rest of its eight hours. NULL means nothing was revoked.
    --
    -- A watermark rather than a deny-list because a session token carries no
    -- `jti`: there would be nothing to list, and giving it one means a row per
    -- login and a sweeper to retire them. The per-request check already reads
    -- this row to re-derive role and liveness, so the comparison rides a query
    -- that was happening anyway and costs no write on the hot path.
    --
    -- Compared against the token's `iat` using the APPLICATION clock, never
    -- `NOW()`: on managed Postgres the database clock can run ahead of the
    -- app's, and a watermark stamped from the fast clock would sit in the
    -- future and refuse every session minted after it.
    --
    -- The grain is the account within this tenant, not the device — signing out
    -- ends that account's sessions on this deployment, and a row here can never
    -- reach the same person's account in another tenant.
    sessions_valid_after TIMESTAMPTZ,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX idx_users_email ON users(tenant_id, email);

ALTER TABLE users ENABLE ROW LEVEL SECURITY;
ALTER TABLE users FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON users TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE users OWNER TO streamscope_app;

-- ============ Admin Accounts ============
-- Admin/operator accounts (admin UI login). Distinct from `users` (LLM/MCP callers).

CREATE TABLE admin_accounts (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                 UUID NOT NULL DEFAULT gen_random_uuid(),
    email              TEXT NOT NULL,
    -- Human-friendly name. Kept equal to `users.display_name` for the same email
    -- by the cross-plane identity sync (like password_hash / email renames).
    display_name       TEXT,
    password_hash      TEXT,
    auth_source        TEXT NOT NULL DEFAULT 'local',
    role               TEXT NOT NULL DEFAULT 'admin',
    oidc_sub           TEXT,
    oidc_issuer        TEXT,
    is_super_admin     BOOLEAN NOT NULL DEFAULT false,
    is_active          BOOLEAN NOT NULL DEFAULT true,
    -- Whether the account was switched off by the group sync (its identity
    -- matched no console group at sign-in) rather than by an admin. Only a
    -- group-revoked account is switched back on by a later sign-in that matches
    -- a console group again; an admin's Disable holds whatever the identity
    -- provider or the auth proxy says.
    revoked_by_group   BOOLEAN NOT NULL DEFAULT false,
    -- Console sessions issued at or before this instant are refused, stamped by
    -- sign-out. The same mechanism as `users.sessions_valid_after` — see there
    -- for why it is a watermark and why it compares against the app clock.
    sessions_valid_after TIMESTAMPTZ,
    -- Last changelog version this admin has acknowledged in the UI.
    last_seen_version  TEXT,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_login         TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    -- Only SYSTEM-tenant accounts can be super-admin (prevents privilege escalation).
    CONSTRAINT chk_super_admin_system_only
        CHECK (is_super_admin = false OR tenant_id = '00000000-0000-0000-0000-000000000001')
);

CREATE UNIQUE INDEX idx_admin_accounts_tenant_email ON admin_accounts(tenant_id, email);
CREATE UNIQUE INDEX idx_admin_accounts_oidc
    ON admin_accounts(tenant_id, oidc_issuer, oidc_sub)
    WHERE oidc_sub IS NOT NULL;

ALTER TABLE admin_accounts ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_accounts FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON admin_accounts TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE admin_accounts OWNER TO streamscope_app;

-- ============ Upstream Servers ============
-- Real upstream LLM/embedding/media servers and their per-model overrides.

CREATE TABLE upstream_servers (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    provider            TEXT NOT NULL,
    encrypted_key       TEXT,
    credential_nonce    TEXT,
    upstream_api_format TEXT NOT NULL DEFAULT 'chat_completions',
    -- How the gateway CARRIES a request to this server, orthogonal to the
    -- protocol it speaks (`upstream_api_format`). It decides two things and
    -- nothing else: the URL path prefix, and which header the credential rides
    -- in. `default` is every ordinary bearer-auth endpoint. The Azure variants
    -- serve the OpenAI surface under `/openai/v1/...` and authenticate with an
    -- `api-key` header (`azure_openai`) or a Microsoft Entra ID bearer token
    -- minted from a client-credentials document (`azure_openai_entra`).
    -- `aws_bedrock` / `google_vertex` are reserved so those transports land as
    -- additive code with no schema change.
    transport           TEXT NOT NULL DEFAULT 'default'
                            CHECK (transport IN ('default', 'azure_openai', 'azure_openai_entra',
                                                 'aws_bedrock', 'google_vertex')),
    -- Override for the appended chat-completions endpoint path when a provider's
    -- OpenAI-compatible chat endpoint isn't `{endpoint url}/v1/chat/completions`
    -- (e.g. Writer `/chat`, DeepInfra `/chat/completions` with no `/v1`). NULL =
    -- the canonical path. Applies only to the `chat_completions` protocol.
    chat_endpoint_path  TEXT,
    enabled             BOOLEAN NOT NULL DEFAULT true,
    -- Automatic model sync: when on, a background worker periodically discovers
    -- this server's models and keeps the mirror downstream exactly in sync
    -- (add + refresh + remove). Default on. last_auto_sync_status holds the last
    -- run's outcome ({ok|error, ...summary}) for the admin UI.
    auto_sync_enabled    BOOLEAN NOT NULL DEFAULT true,
    last_auto_sync_at    TIMESTAMPTZ,
    last_auto_sync_status JSONB,
    -- Seed-provisioned (builtin) BYOK server vs an admin-created one: metadata,
    -- not a merge driver.
    is_builtin          BOOLEAN NOT NULL DEFAULT false,
    -- How this engine expresses a QoS class, and how much of it the gateway may
    -- use. The dialect is an explicit opt-in because it must match how the
    -- engine was started: vLLM documents a non-zero `priority` as an error
    -- unless it runs `--scheduling-policy priority`.
    --
    -- `max_in_flight` is how many requests the gateway keeps at one endpoint at
    -- once and `waiting_threshold` how long that engine's own queue may grow
    -- before the gateway stops releasing to it; both NULL mean the gate does not
    -- apply to this server. Server-wide defaults, overridden per endpoint,
    -- because replicas of one server are rarely identical machines.
    scheduling_dialect  TEXT NOT NULL DEFAULT 'none'
                            CHECK (scheduling_dialect IN ('none', 'vllm_priority')),
    max_in_flight       INTEGER CHECK (max_in_flight IS NULL OR max_in_flight > 0),
    waiting_threshold   INTEGER CHECK (waiting_threshold IS NULL OR waiting_threshold >= 0),
    -- Whether the gateway reads each endpoint's `/metrics` (also read when an
    -- endpoint declares a waiting-queue bound, which cannot apply unread). A
    -- new vLLM server is created with it on.
    engine_metrics      BOOLEAN NOT NULL DEFAULT false,
    -- The gateways LEARN each endpoint's in-flight limit from the engine's own
    -- readings instead of holding to a fixed one; `max_in_flight` is then the
    -- ceiling.
    adaptive_concurrency BOOLEAN NOT NULL DEFAULT false,
    -- The token-latency target a learned limit keeps each engine within, in
    -- milliseconds, under `adaptive_itl_target_mode = 'fixed'`.
    adaptive_itl_target_ms INTEGER
                            CHECK (adaptive_itl_target_ms IS NULL OR adaptive_itl_target_ms BETWEEN 1 AND 60000),
    -- How a learned limit sets its token-latency target: 'auto' holds each
    -- engine to a multiple of its own time per token at low load, as the
    -- gateways learn it; 'fixed' to `adaptive_itl_target_ms`; 'off' to none (the
    -- limit grows as far as memory holds). Read only while
    -- `adaptive_concurrency` is on.
    adaptive_itl_target_mode TEXT NOT NULL DEFAULT 'auto'
                            CHECK (adaptive_itl_target_mode IN ('auto', 'fixed', 'off')),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE UNIQUE INDEX idx_upstream_servers_name ON upstream_servers(tenant_id, name);

ALTER TABLE upstream_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_servers FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_servers TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_servers OWNER TO streamscope_app;

-- ============ Model Catalog ============
-- Canonical model catalog: pricing + capability defaults. Resolution order:
-- downstream_routes → upstream_models → model_catalog → default.
--
-- Capabilities and pricing resolve on DIFFERENT ladders, because they belong to
-- different things. Capabilities (context window, modalities, tool calling) are
-- properties of the model weights, so a catalog row for the same model under any
-- provider is a valid source — a self-hosted gemma-4 legitimately inherits the
-- capabilities published for a hosted one. Pricing is a property of whoever
-- serves the model, so it resolves ONLY from a row whose provider matches the
-- upstream server's; with no such row the price is NULL (unknown), never
-- borrowed from another vendor. Keep that split when touching any resolution
-- site — a borrowed price is invisible once it lands in an audit row.

-- Single canonical provider key. MUST stay byte-for-byte equivalent to the Rust
-- canonical_provider_key() (pinned by a unit test). Squash to alphanumerics +
-- lowercase, then fold the known aliases onto the provider vocabulary in
-- seeds/providers/providers.json; an unrecognised token passes through squashed
-- so a provider we don't model keeps a distinct identity instead of colliding
-- with every other unknown. Both sides of a comparison run through this, so the
-- squashed form only has to be self-consistent.
--
-- Invariant when editing: every value emitted here must be reachable from BOTH
-- the provider vocabulary AND the catalog seed's own provider column, or a
-- catalog row can never price-match a server. `google` is the live example —
-- it is an icon_only vendor row, never a selectable upstream, so catalog rows
-- carrying it fold onto `google_gemini`.
--
-- Invariant when REPLACING: `model_catalog.provider_key` is a stored generated
-- column over this function. A later `CREATE OR REPLACE` — which extending the
-- fold table requires — does NOT recompute stored values, so uniqueness, ON
-- CONFLICT inference and every lookup go quietly wrong against rows written
-- under the old body. Any migration that replaces this function MUST rewrite
-- the column in the same migration (`UPDATE model_catalog SET provider =
-- provider`, per tenant).
CREATE FUNCTION canonical_provider_key(name text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT CASE regexp_replace(lower(coalesce(name, '')), '[^a-z0-9]+', '', 'g')
        WHEN 'openai'                  THEN 'openai'
        WHEN 'anthropic'               THEN 'anthropic'
        WHEN 'googlegemini'            THEN 'google_gemini'
        WHEN 'gemini'                  THEN 'google_gemini'
        WHEN 'google'                  THEN 'google_gemini'
        WHEN 'googlevertex'            THEN 'google_vertex'
        WHEN 'googlevertexanthropic'   THEN 'google_vertex'
        WHEN 'vertex'                  THEN 'google_vertex'
        WHEN 'vertexai'                THEN 'google_vertex'
        WHEN 'azureopenai'             THEN 'azure_openai'
        WHEN 'azure'                   THEN 'azure_openai'
        WHEN 'awsbedrock'              THEN 'aws_bedrock'
        WHEN 'amazonbedrock'           THEN 'aws_bedrock'
        WHEN 'bedrock'                 THEN 'aws_bedrock'
        WHEN 'openrouter'              THEN 'openrouter'
        WHEN 'deepseek'                THEN 'deepseek'
        WHEN 'together'                THEN 'together'
        WHEN 'togetherai'              THEN 'together'
        WHEN 'fireworks'               THEN 'fireworks'
        WHEN 'fireworksai'             THEN 'fireworks'
        WHEN 'moonshot'                THEN 'moonshot'
        WHEN 'moonshotai'              THEN 'moonshot'
        WHEN 'nvidia'                  THEN 'nvidia'
        WHEN 'nim'                     THEN 'nvidia'
        WHEN 'nvidianim'               THEN 'nvidia'
        WHEN 'ollama'                  THEN 'ollama'
        WHEN 'ollamacloud'             THEN 'ollama'
        WHEN 'groq'                    THEN 'groq'
        WHEN 'mistral'                 THEN 'mistral'
        WHEN 'xai'                     THEN 'xai'
        WHEN 'vllm'                    THEN 'vllm'
        WHEN 'custom'                  THEN 'custom'
        -- Meta's own API is the `llama` provider; `meta` is the icon-only
        -- vendor row, so fold it there rather than leaving it unreachable.
        WHEN 'meta'                    THEN 'llama'
        WHEN 'metallama'               THEN 'llama'
        WHEN 'llama'                   THEN 'llama'
        ELSE regexp_replace(lower(coalesce(name, '')), '[^a-z0-9]+', '', 'g')
    END
$$;

-- Single canonical catalog key. MUST stay byte-for-byte equivalent to the Rust
-- canonical_catalog_key() (pinned by a unit test): strip provider prefix (up to
-- the last '/'), strip ':variant' suffix, lowercase, '.'→'-', then strip a
-- trailing '-YYYYMMDD' date stamp. Every read join and write-time link uses it.
--
-- Replacing it has the same hazard as canonical_provider_key:
-- `model_catalog.model_key` is a stored generated column over it, which a
-- CREATE OR REPLACE does not recompute.
CREATE FUNCTION canonical_catalog_key(name text) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE AS $$
    SELECT regexp_replace(replace(lower(base), '.', '-'), '-20[0-9]{6}$', '')
    FROM (
        SELECT CASE
                 -- OpenAI fine-tunes are `ft:<base>:<org>[::<suffix>]`. Key on
                 -- `ft:<base>`, keeping BOTH halves. Splitting on the first ':'
                 -- collapses every fine-tune onto the bare token `ft`, so one
                 -- arbitrary row prices them all; keying on the base alone is just
                 -- as wrong in the other direction, because a fine-tuned deployment
                 -- costs more than its base (gpt-4o: $3.75/$15 against $2.50/$10).
                 WHEN lower(stripped) LIKE 'ft:%' THEN 'ft:' || split_part(stripped, ':', 2)
                 ELSE split_part(stripped, ':', 1)
               END AS base
        FROM (
            -- Vendor path, then the Bedrock cross-region inference-profile prefix
            -- (`us.anthropic.claude-…`), which the model id carries but the catalog
            -- row does not. Regions of one model share a key deliberately:
            -- capabilities are identical, and per-region pricing is a per-server
            -- concern, not a per-model one.
            --
            -- The path strip is greedy to the LAST '/', not the first: Fireworks
            -- ids are `accounts/fireworks/models/<name>`, so stopping at the first
            -- would leave `fireworks/models/<name>` and the model would match
            -- nothing but itself.
            SELECT regexp_replace(
                     regexp_replace(name, '^.*/', ''),
                     '^(us|eu|apac|us-gov|global)\.', '', 'i') AS stripped
        ) a
    ) b
$$;

CREATE TABLE model_catalog (
    tenant_id                           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                                  UUID NOT NULL DEFAULT gen_random_uuid(),
    -- NULL = global price for this model (applies to all servers).
    server_id                           UUID,
    provider                            TEXT NOT NULL,
    model                               TEXT NOT NULL,
    -- The canonical keys every catalog match reads (`routes::catalog_join`).
    -- Stored, so their btree indexes are plain column indexes: an expression
    -- index over a function that is not LEAKPROOF is no index condition under
    -- FORCE row-level security, and marking a function LEAKPROOF needs a
    -- superuser the managed shape does not have.
    provider_key                        TEXT NOT NULL GENERATED ALWAYS AS (canonical_provider_key(provider)) STORED,
    model_key                           TEXT NOT NULL GENERATED ALWAYS AS (canonical_catalog_key(model)) STORED,
    -- Published price list for this (provider, model), in the shape described on
    -- `upstream_models.rates`. An absent unit is a price we do not know, which
    -- stays distinct from a rate of 0: unknown bills at a floor of zero AND
    -- badges the row, where a 0 would silently report the request as free and —
    -- because budget accrual skips a zero cost — turn an enforcing budget into a
    -- no-op cap. An empty map is therefore a catalog row that carries
    -- capabilities but no pricing, which is common and legitimate.
    rates                               JSONB NOT NULL DEFAULT '{}',
    context_window                      INT,
    max_output_tokens                   INT,
    supports_caching                    BOOLEAN,
    supports_reasoning                  BOOLEAN,
    supports_vision                     BOOLEAN,
    supports_function_calling           BOOLEAN,
    supports_audio_input                BOOLEAN,
    supports_audio_output               BOOLEAN,
    supports_video_input                BOOLEAN,
    supports_pdf_input                  BOOLEAN,
    supports_response_schema            BOOLEAN,
    supports_system_messages            BOOLEAN,
    model_type                          TEXT DEFAULT 'text',
    output_vector_size                  INTEGER,
    deprecation_date                    TEXT,
    is_builtin                          BOOLEAN NOT NULL DEFAULT false,
    -- Soft-delete for a user-removed builtin catalog entry; seed-sync skips it.
    suppressed                          BOOLEAN NOT NULL DEFAULT false,
    -- Whether the row came from the seed (`keep_seeded`): a delete hides a
    -- seeded row, edited or not, and removes any other.
    seeded                              BOOLEAN NOT NULL DEFAULT false,
    updated_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, server_id) REFERENCES upstream_servers(tenant_id, id) ON DELETE CASCADE
);

-- Pricing uniqueness per tenant: one row per (server_id, provider, model), where
-- a NULL server_id is the global/applies-to-all-servers row. NULLS NOT DISTINCT
-- makes the single NULL-server row unique per (tenant, provider, model) —
-- server-specific rows (non-NULL server_id) stay unique per
-- (tenant, server_id, provider, model) and coexist with the global row.
--
-- The provider is part of row identity because the same model name legitimately
-- exists under several providers at different prices (gpt-4o under openai and
-- azure_openai, every claude under anthropic and aws_bedrock, every gemini under
-- google_gemini and google_vertex). Without it the seed's own dedup key
-- (provider, model) emits rows that collide here: the per-row upsert silently
-- overwrites one provider's price with another's — winner decided by seed file
-- order — and a batched upsert raises "ON CONFLICT DO UPDATE cannot affect row a
-- second time", which aborts the seed group and leaves the tenant unstamped, so
-- it retries and fails identically on every boot.
CREATE UNIQUE INDEX idx_model_catalog_unique
    ON model_catalog(tenant_id, server_id, provider_key, model)
    NULLS NOT DISTINCT;

-- Live catalog inheritance resolves an upstream model to its catalog row by
-- `mc.model_key = canonical_catalog_key(<model>)` at every read site — the
-- per-route config body build, the model list/detail joins, and the
-- create/sync upserts — all filtered `server_id IS NULL`. Column order is
-- load-bearing: the model key comes FIRST so that both a provider-scoped lookup
-- (pricing, which never falls back across providers) and a provider-blind one
-- (capabilities, which do) prefix-seek the same index.
CREATE INDEX idx_model_catalog_canonical_key
    ON model_catalog (tenant_id, model_key, provider_key)
    WHERE server_id IS NULL;
CREATE INDEX idx_model_catalog_server ON model_catalog (tenant_id, server_id) WHERE server_id IS NOT NULL;

ALTER TABLE model_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_catalog FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON model_catalog TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE model_catalog OWNER TO streamscope_app;

-- Per-model overrides: capability flags + pricing. `user_overridden_caps` records
-- which inheritable fields the operator has explicitly set — capabilities, the
-- `rates` map AND token limits alike — so a catalog change or a provider re-sync
-- updates only the fields NOT in the array. That array is the only thing
-- separating a value an operator chose from one a provider published, because
-- both are stored in the same column: everything unpinned takes the provider's
-- current value on every refresh, and everything pinned is left alone.
--
-- Catalog inheritance is live: a row stores only what an operator explicitly set
-- or a provider discovered; everything else inherits from the linked (or
-- canonically-matched) model_catalog row at read time.
CREATE TABLE upstream_models (
    tenant_id                           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                                  UUID NOT NULL DEFAULT gen_random_uuid(),
    server_id                           UUID NOT NULL,
    upstream_model                      TEXT NOT NULL,
    context_window                      INT,
    max_output_tokens                   INT,
    -- Override server's native upstream API format (NULL = inherit).
    upstream_api_format                 TEXT,
    model_type                          TEXT DEFAULT 'text',
    -- JSON healing for this backend model (NULL = inherit tenant `healing_enabled`).
    -- Repairs malformed JSON in responses from models that emit broken output;
    -- a backend-reliability property of the model, not a per-alias knob.
    healing_enabled                     BOOLEAN,
    -- Capability overrides (NULL = inherit from model_catalog).
    supports_vision                     BOOLEAN,
    supports_reasoning                  BOOLEAN,
    supports_function_calling           BOOLEAN,
    supports_caching                    BOOLEAN,
    supports_audio_input                BOOLEAN,
    supports_audio_output               BOOLEAN,
    supports_video_input                BOOLEAN,
    supports_pdf_input                  BOOLEAN,
    supports_response_schema            BOOLEAN,
    supports_system_messages            BOOLEAN,
    -- Price override for this model. NULL = inherit the catalog's map whole.
    --
    -- Deliberately one map rather than a column per billing dimension: a price
    -- list is a set quoted by one provider in one currency, and letting half of
    -- it come from the catalog and half from an operator is the same borrowed-
    -- price hazard the provider-matched pricing ladder exists to prevent. The
    -- override is therefore all-or-nothing, and `user_overridden_caps` carries
    -- the single entry `rates` rather than one per price.
    --
    -- Shape: {"currency":"USD","units":{"<unit>":<rate>|{"rate":…,"tiers":[…]}}}
    -- where `<unit>` is a key from the pricing vocabulary and the rate is in
    -- that unit's natural scale (per million for token units, per unit
    -- otherwise). An empty `units` map means the price is UNKNOWN, which is not
    -- the same as free: unknown bills at a floor of zero AND badges the row,
    -- where a genuine zero would silently report the traffic as costing nothing
    -- and — because budget accrual skips a zero cost — turn an enforcing budget
    -- into a no-op cap.
    rates                               JSONB,
    -- Capability fields the operator has explicitly set. Catalog re-sync skips
    -- anything in this array. Exposed as `user_overridden_fields` in the API:
    -- it pins caps, pricing and token limits alike.
    user_overridden_caps                TEXT[] NOT NULL DEFAULT '{}',
    enabled                             BOOLEAN NOT NULL DEFAULT true,
    -- Explicit catalog link. NULL = fall back to the canonical name match.
    -- Removing a catalog entry reverts the model to auto-match, never a cascade
    -- delete of the model itself. A link names a live row of the same tenant:
    -- the write path refuses a suppressed entry, the key refuses another
    -- tenant's.
    catalog_model_id                    UUID,
    created_at                          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, server_id) REFERENCES upstream_servers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, catalog_model_id) REFERENCES model_catalog(tenant_id, id) ON DELETE SET NULL (catalog_model_id)
);

CREATE UNIQUE INDEX idx_upstream_models_server_model ON upstream_models(tenant_id, server_id, upstream_model);
-- Composite key target for upstream_model_endpoints: keeps a membership's
-- endpoint and model on the same server.
CREATE UNIQUE INDEX idx_upstream_models_id_server ON upstream_models (tenant_id, id, server_id);
CREATE INDEX idx_upstream_models_catalog_model ON upstream_models(tenant_id, catalog_model_id) WHERE catalog_model_id IS NOT NULL;

ALTER TABLE upstream_models ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_models FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_models TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_models OWNER TO streamscope_app;

-- Named invocation profiles attached to a real upstream model. A preset is a
-- partial request body authored in the model's OWN native protocol
-- (`upstream_api_format`) — e.g. an Anthropic model's preset sets `thinking` +
-- temperature/top_p/top_k; a Gemini model's preset nests under
-- `generationConfig`. The proxy force-merges the fragment onto the already
-- translated upstream body (preset wins; unset fields pass through), so the
-- same model can be invoked many ways ("think" / "non-think" / "default").
-- One model has many presets + exactly one default. Discovery NEVER authors a
-- preset's settings — it only seeds the empty `default`.
CREATE TABLE model_presets (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    model_id        UUID NOT NULL,
    name            TEXT NOT NULL,
    is_default      BOOLEAN NOT NULL DEFAULT false,
    -- Native partial request body in the model's `upstream_api_format` vocabulary.
    -- Single-writer-per-row document (one preset = one settings document edited
    -- as a unit), so a JSON blob is the right shape here — not a shared collection.
    settings        JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, model_id) REFERENCES upstream_models(tenant_id, id) ON DELETE CASCADE
);

-- Exactly one default preset per model.
CREATE UNIQUE INDEX idx_model_presets_default ON model_presets(tenant_id, model_id) WHERE is_default;
-- Unique preset name per model.
CREATE UNIQUE INDEX idx_model_presets_name ON model_presets(tenant_id, model_id, name);

ALTER TABLE model_presets ENABLE ROW LEVEL SECURITY;
ALTER TABLE model_presets FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON model_presets TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE model_presets OWNER TO streamscope_app;

-- The URLs an upstream server is reached at. One row per replica of the same
-- engine (for example one vLLM process per GPU): every endpoint shares the
-- server's credential, provider, protocol and transport, so a replica with a
-- different credential is a different server, not an endpoint.
--
-- This table is the only place a server's URLs are stored: a server has no URL
-- column of its own. `position` orders the endpoints; the first ENABLED one by
-- `(position, created_at, id)` is the server's primary, and its URL is the one
-- the server API states as the server's.
--
-- `listed` is true once discovery against this endpoint has answered. Until
-- then the endpoint is assumed to serve every model of its server and has no
-- membership rows; from then on its rows in `upstream_model_endpoints` are
-- what it serves. `last_discovery_at` / `last_discovery_status` record the
-- last attempt (`{ok, …}`), whether or not it answered; `last_answer_at` the
-- last one that answered — what supersedes a "model not found" report.
--
-- `position` carries no unique constraint so a reorder can never collide;
-- `created_at` breaks a tie. `max_in_flight` / `waiting_threshold` override the
-- server's (NULL = the server's value).
CREATE TABLE upstream_server_endpoints (
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                      UUID NOT NULL DEFAULT gen_random_uuid(),
    server_id               UUID NOT NULL,
    url                     TEXT NOT NULL,
    enabled                 BOOLEAN NOT NULL DEFAULT true,
    weight                  INTEGER NOT NULL DEFAULT 1 CHECK (weight >= 1),
    position                INTEGER NOT NULL DEFAULT 0,
    listed                  BOOLEAN NOT NULL DEFAULT false,
    last_discovery_at       TIMESTAMPTZ,
    last_discovery_status   JSONB,
    last_answer_at          TIMESTAMPTZ,
    max_in_flight           INTEGER CHECK (max_in_flight IS NULL OR max_in_flight > 0),
    waiting_threshold       INTEGER CHECK (waiting_threshold IS NULL OR waiting_threshold >= 0),
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, server_id, url),
    -- Target of the membership table's composite key, which is what keeps a
    -- membership's endpoint and model on the same server.
    UNIQUE (tenant_id, id, server_id),
    FOREIGN KEY (tenant_id, server_id) REFERENCES upstream_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_upstream_server_endpoints_server
    ON upstream_server_endpoints (tenant_id, server_id, position, created_at);

ALTER TABLE upstream_server_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_server_endpoints FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_server_endpoints TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_server_endpoints OWNER TO streamscope_app;

-- Which models a LISTED endpoint serves.
--
-- `kind` 'listed': the endpoint's last answer named the model. 'assumed': the
-- model is kept on the endpoint without that evidence — a model added by hand,
-- or one the endpoint's FIRST answer did not name (a first answer adds, it
-- never removes). The next answer that omits an assumed model removes it.
--
-- An endpoint that has never answered (`listed = false`) has NO rows here: it
-- is taken to serve every model of its server. The `discovered_*` columns hold
-- what this endpoint last reported for the model, so the model's own values
-- can be folded across its members (the smallest window, a capability only
-- where no member denies it); NULL on an assumed row the endpoint never
-- listed, kept on one it listed before.
CREATE TABLE upstream_model_endpoints (
    tenant_id                   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    model_id                    UUID NOT NULL,
    endpoint_id                 UUID NOT NULL,
    server_id                   UUID NOT NULL,
    kind                        TEXT NOT NULL CHECK (kind IN ('listed', 'assumed')),
    -- What the endpoint reported (context window, output cap, capabilities),
    -- as the discovery parser read it.
    discovered                  JSONB,
    -- The engine's own name for what it serves (vLLM `root`: the weights path
    -- or the adapter path). Compared across members, never used to route.
    discovered_identity         TEXT,
    -- The base model of an adapter (vLLM `parent`).
    discovered_parent           TEXT,
    last_listed_at              TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, model_id, endpoint_id),
    FOREIGN KEY (tenant_id, model_id, server_id)
        REFERENCES upstream_models (tenant_id, id, server_id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, endpoint_id, server_id)
        REFERENCES upstream_server_endpoints (tenant_id, id, server_id) ON DELETE CASCADE
);

CREATE INDEX idx_upstream_model_endpoints_endpoint ON upstream_model_endpoints (tenant_id, endpoint_id);
CREATE INDEX idx_upstream_model_endpoints_server   ON upstream_model_endpoints (tenant_id, server_id);

ALTER TABLE upstream_model_endpoints ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_model_endpoints FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_model_endpoints TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_model_endpoints OWNER TO streamscope_app;

-- ============ Downstream Routes ============
-- Client-facing virtual providers and their alias→upstream routes.

CREATE TABLE downstream_providers (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    name                TEXT NOT NULL,
    description         TEXT,
    icon                TEXT,
    -- Mirror link: provider auto-created from an upstream-server sync.
    -- NULL = custom (operator-created) provider.
    upstream_server_id  UUID,
    -- Seed-provisioned (builtin) BYOK provider vs an admin-created one.
    is_builtin          BOOLEAN NOT NULL DEFAULT false,
    -- BYOK / pass-through gate. When true, a request for a model that has no
    -- route in this downstream passes through to the linked keyless upstream
    -- with the client's forwarded credential. Explicit flag — pass-through is
    -- never inferred from a keyless upstream, so a misconfigured keyless
    -- upstream cannot silently forward.
    --
    -- A "BYOK downstream" is a provider with byok=true linked to a KEYLESS
    -- upstream_server (encrypted_key NULL): the client forwards its own
    -- credential, nothing is stored. Empty (no routes) ⇒ pure pass-through to
    -- the bound upstream; a route added inside it OVERRIDES that one model.
    byok                BOOLEAN NOT NULL DEFAULT false,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, upstream_server_id) REFERENCES upstream_servers(tenant_id, id) ON DELETE SET NULL (upstream_server_id)
);

CREATE UNIQUE INDEX idx_downstream_providers_name ON downstream_providers(tenant_id, name);
CREATE INDEX idx_downstream_providers_upstream_server
    ON downstream_providers(tenant_id, upstream_server_id) WHERE upstream_server_id IS NOT NULL;

ALTER TABLE downstream_providers ENABLE ROW LEVEL SECURITY;
ALTER TABLE downstream_providers FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON downstream_providers TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE downstream_providers OWNER TO streamscope_app;

-- Named, reusable response-cache policies. A `downstream_routes` row references
-- one; NULL means the alias is uncached. The knobs live here, not on the route,
-- so a tenant tunes one place and every referencing alias follows — the same
-- relationship `model_presets` has with invocation settings.
CREATE TABLE cache_presets (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    -- Human label only. Nothing is addressed by it, so there is no slug.
    name            TEXT NOT NULL,
    -- `exact`   — hash-identical requests only.
    -- `semantic`— exact prefix + embedding-similar last user message.
    -- `observe` — record would-have-hit in audit, never serve from cache.
    mode            TEXT NOT NULL DEFAULT 'exact',
    ttl_seconds     INTEGER NOT NULL DEFAULT 3600,
    -- Cosine-similarity floor for a semantic hit.
    threshold       REAL NOT NULL DEFAULT 0.9,
    -- Partition grain. `workspace` keeps a computed response inside the
    -- workspace that paid for it; `tenant` shares it tenant-wide (a
    -- data-disclosure decision); `user` is the strictest posture.
    share_scope     TEXT NOT NULL DEFAULT 'workspace',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    CONSTRAINT cache_presets_mode_check
        CHECK (mode IN ('exact', 'semantic', 'observe')),
    CONSTRAINT cache_presets_share_scope_check
        CHECK (share_scope IN ('workspace', 'user', 'tenant')),
    CONSTRAINT cache_presets_ttl_check
        CHECK (ttl_seconds > 0 AND ttl_seconds <= 2592000),
    CONSTRAINT cache_presets_threshold_check
        CHECK (threshold > 0 AND threshold <= 1)
);

-- Unique preset name per tenant.
CREATE UNIQUE INDEX idx_cache_presets_name ON cache_presets(tenant_id, name);

ALTER TABLE cache_presets ENABLE ROW LEVEL SECURITY;
ALTER TABLE cache_presets FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cache_presets TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE cache_presets OWNER TO streamscope_app;

-- Route: alias → upstream model within a downstream provider.
-- One alias can bind to multiple upstreams (LB/failover via priority/weight).
CREATE TABLE downstream_routes (
    tenant_id                   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                          UUID NOT NULL DEFAULT gen_random_uuid(),
    provider_id                 UUID NOT NULL,
    alias                       TEXT NOT NULL,
    -- Nullable + SET NULL so a curated route SURVIVES deletion of its upstream
    -- model (operator deletes a model or the whole server): the row is kept as
    -- an ORPHAN (model_id NULL, disabled_reason 'upstream_model_deleted') for
    -- the operator to clean up, never silently destroyed. A vanish (provider
    -- dropped the model) keeps the model row instead, so that path stays soft +
    -- reinstatable. Orphaned (NULL) routes are excluded from the routing snapshot.
    model_id                    UUID,
    -- Invocation preset for this (alias → model) target. NULL = the model's
    -- default preset. The route is a pure POINTER: it never redefines what the
    -- upstream IS (capabilities / window / protocol / type / healing — those are
    -- upstream-model truth) or HOW it is invoked beyond selecting a preset.
    preset_id                   UUID,
    -- Response-cache policy for this alias. NULL = uncached (the default for
    -- every mirror-created route). SET NULL is the fail-safe direction: losing
    -- the policy stops caching, it can never serve wrongly.
    cache_preset_id             UUID,
    priority                    INT NOT NULL DEFAULT 0,
    weight                      INT NOT NULL DEFAULT 1,
    -- Client-facing advertised context window (token-scaling for compaction).
    -- NOT an upstream override: it is confined to `model_info`/provisioning and
    -- never sent upstream — the one legitimately alias-scoped client knob.
    client_context_window       INT,
    -- Track auto-synced routes vs operator-customised. Auto-sync updates
    -- only auto_synced=true rows; manually edited routes are preserved.
    auto_synced                 BOOLEAN NOT NULL DEFAULT false,
    -- Why a route was auto-disabled (NULL = not auto-disabled).
    --   'upstream_model_vanished' — autosync found the model gone from the
    --       provider; SOFT (model kept, route reinstated if it reappears).
    --   'upstream_model_deleted'  — operator deleted the model/server; HARD
    --       (model_id nulled → orphan, surfaced for cleanup, never reinstated).
    disabled_reason             TEXT,
    -- Operator labels for quickstart filtering (e.g. 'opencode', 'cli').
    tags                        TEXT[] NOT NULL DEFAULT '{}',
    -- Subset of `tags` indicating "canonical choice for that tag".
    default_for_tags            TEXT[] NOT NULL DEFAULT '{}',
    enabled                     BOOLEAN NOT NULL DEFAULT true,
    -- The route's response-cache generation: raising it tells every edge
    -- holding the route to drop the route's cached responses.
    cache_generation            BIGINT NOT NULL DEFAULT 0,
    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, provider_id) REFERENCES downstream_providers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, model_id) REFERENCES upstream_models(tenant_id, id) ON DELETE SET NULL (model_id),
    FOREIGN KEY (tenant_id, preset_id) REFERENCES model_presets(tenant_id, id) ON DELETE SET NULL (preset_id),
    FOREIGN KEY (tenant_id, cache_preset_id) REFERENCES cache_presets(tenant_id, id) ON DELETE SET NULL (cache_preset_id)
);

CREATE INDEX idx_downstream_routes_model    ON downstream_routes(tenant_id, model_id) WHERE model_id IS NOT NULL;
CREATE INDEX idx_downstream_routes_preset   ON downstream_routes(tenant_id, preset_id) WHERE preset_id IS NOT NULL;
CREATE INDEX idx_downstream_routes_cache_preset ON downstream_routes(tenant_id, cache_preset_id) WHERE cache_preset_id IS NOT NULL;
-- The key a route client slot's foreign key names (a route id is unique on
-- its own, so it lets the reference carry the provider too); it also serves
-- every per-provider route lookup and the cascade from the provider.
CREATE UNIQUE INDEX idx_downstream_routes_provider_id ON downstream_routes (tenant_id, provider_id, id);
-- One alias may LB across presets of a model, so the natural key includes
-- preset_id, and a NULL preset (= the model's default) is a value here: the
-- default-preset route is unique and mirror's ON CONFLICT detects it. model_id
-- is NOT a value-NULL: all-NULL orphans (SET NULL) must never collide, so the
-- index is partial on a present model.
CREATE UNIQUE INDEX idx_downstream_routes_unique ON downstream_routes(
    tenant_id, provider_id, alias, model_id, preset_id
) NULLS NOT DISTINCT WHERE model_id IS NOT NULL;

ALTER TABLE downstream_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE downstream_routes FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON downstream_routes TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE downstream_routes OWNER TO streamscope_app;

-- ============ QoS Classes ============
-- The tenant's priority bands. `rank` is abstract and never reaches a wire on
-- its own: lower is more important, and the target server's scheduling dialect
-- decides how (or whether) it is expressed upstream.
--
-- `class_key` is the seed identity — builtins are upserted by it and a user edit
-- flips `is_builtin` false, exactly as every other seeded per-row collection.
-- The row is addressed by UUID everywhere else, so this is not a slug.
--
-- `sheddable` refuses a request at once when no endpoint has headroom instead of
-- holding it; `queue_ttl_ms` overrides the operator's default hold for the class
-- and is clamped to the operator maximum when it is resolved, so a tenant admin
-- cannot ask for a wait the deployment will not honour.
--
-- `is_default` and `mint_default_for` are tenant STATE, not seeded content: they
-- are set once at tenant creation and never written by the restart reconcile, or
-- moving a star would be undone on the next boot.
CREATE TABLE qos_classes (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                UUID NOT NULL DEFAULT gen_random_uuid(),
    class_key         TEXT NOT NULL,
    name              TEXT NOT NULL,
    description       TEXT NOT NULL DEFAULT '',
    rank              INTEGER NOT NULL,
    sheddable         BOOLEAN NOT NULL DEFAULT false,
    queue_ttl_ms      INTEGER CHECK (queue_ttl_ms IS NULL OR (queue_ttl_ms > 0 AND queue_ttl_ms <= 600000)),
    is_default        BOOLEAN NOT NULL DEFAULT false,
    mint_default_for  TEXT CHECK (mint_default_for IN ('interactive', 'automation')),
    is_builtin        BOOLEAN NOT NULL DEFAULT false,
    suppressed        BOOLEAN NOT NULL DEFAULT false,
    seeded            BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, class_key),
    UNIQUE (tenant_id, name)
);

-- Exactly one default class per tenant, and at most one star of each kind.
CREATE UNIQUE INDEX idx_qos_classes_one_default_per_tenant
    ON qos_classes (tenant_id) WHERE is_default;
CREATE UNIQUE INDEX idx_qos_classes_one_mint_default_per_tenant
    ON qos_classes (tenant_id, mint_default_for) WHERE mint_default_for IS NOT NULL;
CREATE INDEX idx_qos_classes_tenant_rank
    ON qos_classes (tenant_id, rank) WHERE NOT suppressed;

ALTER TABLE qos_classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE qos_classes FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON qos_classes TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE qos_classes OWNER TO streamscope_app;

-- Which classes may be served by a route target. NO ROWS FOR A ROUTE MEANS EVERY
-- CLASS — the restriction is opt-in, so an operator who never opens this screen
-- keeps the unrestricted behaviour. RESTRICT: deleting a class must not
-- silently widen a target that was restricted to it.
CREATE TABLE route_qos_classes (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    route_id      UUID NOT NULL,
    qos_class_id  UUID NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, route_id, qos_class_id),
    FOREIGN KEY (tenant_id, route_id) REFERENCES downstream_routes(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, qos_class_id) REFERENCES qos_classes(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX idx_route_qos_classes_class ON route_qos_classes (tenant_id, qos_class_id);

ALTER TABLE route_qos_classes ENABLE ROW LEVEL SECURITY;
ALTER TABLE route_qos_classes FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON route_qos_classes TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE route_qos_classes OWNER TO streamscope_app;

-- ============ Route Client Slots ============
-- The client model slots a provider's routes fill.
--
-- A client config is rendered for one provider and names its main model by
-- the route marked default for the client's tag. A client with more than one
-- model setting also names a `fast` model (background work: titles, search,
-- commit messages) and a `plan` model (planning); this table names the route
-- that fills each slot of a provider — at most one per slot (the key), while
-- one route may fill several. A slot without a row falls back to the default
-- route. The route is one of the provider's: the foreign key names both.

CREATE TABLE route_client_slots (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    provider_id  UUID NOT NULL,
    slot         TEXT NOT NULL CHECK (slot IN ('fast', 'plan')),
    route_id     UUID NOT NULL,
    PRIMARY KEY (tenant_id, provider_id, slot),
    FOREIGN KEY (tenant_id, provider_id) REFERENCES downstream_providers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, provider_id, route_id)
        REFERENCES downstream_routes(tenant_id, provider_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_route_client_slots_route ON route_client_slots (tenant_id, route_id);

ALTER TABLE route_client_slots ENABLE ROW LEVEL SECURITY;
ALTER TABLE route_client_slots FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON route_client_slots TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE route_client_slots OWNER TO streamscope_app;

-- ============ Route Policies ============
-- Per-downstream path-level controls used by the catch-all `/v1/*` handler.
-- Disabled by default; operators enable per (downstream, path) pair.

CREATE TABLE route_policies (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    downstream_id   UUID NOT NULL,
    path_pattern    TEXT NOT NULL,
    enabled         BOOLEAN NOT NULL DEFAULT false,
    rate_limit_rpm  INTEGER,
    max_body_bytes  BIGINT DEFAULT 10485760,
    audit_body      BOOLEAN NOT NULL DEFAULT false,
    description     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, downstream_id, path_pattern),
    FOREIGN KEY (tenant_id, downstream_id) REFERENCES downstream_providers(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE route_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE route_policies FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON route_policies TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE route_policies OWNER TO streamscope_app;

-- ============ Edge Nodes ============
-- Edge proxy registration. Each edge serves all tenants.

-- intentional: no RLS, global infrastructure (one edge serves all tenants).
CREATE TABLE edge_nodes (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name                  TEXT NOT NULL,
    endpoint              TEXT NOT NULL,
    last_seen             TIMESTAMPTZ,
    status                TEXT NOT NULL DEFAULT 'active',
    metadata              JSONB NOT NULL DEFAULT '{}',
    token_hash            TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX idx_edge_nodes_name ON edge_nodes(name);

ALTER TABLE edge_nodes OWNER TO streamscope_app;

-- A single running proxy process under a logical edge node. One `edge_nodes`
-- row (the bearer of the registration token) fans out to N proxy replicas:
-- each presents the shared token plus a stable per-process `instance_key`
-- (hostname / pod name) and registers its own row here. All per-process
-- runtime state — telemetry samples (`edge_stats_samples`), the fleet-counter
-- watermark (`usage_counter_watermarks`), the per-tenant state claim
-- (`edge_instance_tenant_state`) and the one-shot event keys
-- (`edge_instance_events`) — keys on `edge_instances.id`, so N replicas never
-- collide on one identity. The VM appliance runs exactly one instance per edge.
--
-- What each instance holds, as the admin last answered it: the resource →
-- digest map it predicts the instance applied (`held`) and its digest, the
-- digests the instance refused (`nacked`, not sent to it again while it runs the
-- same `sync_epoch` — a restarted, possibly upgraded edge may read them), when
-- it last synced, and how many rows it still had buffered. Shared by every admin
-- replica, so any replica can serve the instance's next poll. `confirmed` is
-- what the instance itself last reported holding, as its request stated it:
-- status reads it, since a prediction can run ahead of an answer in flight.
--
-- What the ingest endpoint keys its writes on: `process_epoch` is the edge
-- process's own counter, persisted by the edge and incremented at every start,
-- so "older" is defined; `epoch_started_at` is when admin-api first saw that
-- epoch (the stands of the epoch carry it). `last_seen_at` is the database
-- time of the instance's last ingest: within a live instance an older epoch is
-- refused, a lapsed one accepts any epoch (its store may have been lost with
-- its pod). `state_seq` is the instance's latest applied state report within
-- the epoch; `state_beat_id` / `state_written_at` mark the beat whose load
-- samples are its live load and relative to which its stands lapse.
-- `usage_merged_at` is when admin-api last merged a usage report from it: the
-- edge reports every counter every usage interval, so two stamps after a
-- moment prove every counter accrued before it has merged.

-- intentional: no RLS, global infrastructure (one edge serves all tenants).
CREATE TABLE edge_instances (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    edge_node_id       UUID NOT NULL REFERENCES edge_nodes(id) ON DELETE CASCADE,
    instance_key       TEXT NOT NULL,
    endpoint           TEXT,
    held               JSONB,
    held_digest        TEXT,
    nacked             JSONB,
    confirmed          JSONB,
    last_sync_at       TIMESTAMPTZ,
    outbox_pending     BIGINT,
    sync_epoch         BIGINT,
    process_epoch      BIGINT,
    epoch_started_at   TIMESTAMPTZ,
    last_seen_at       TIMESTAMPTZ,
    state_seq          BIGINT,
    state_beat_id      UUID,
    state_written_at   TIMESTAMPTZ,
    usage_merged_at    TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (edge_node_id, instance_key)
);

ALTER TABLE edge_instances OWNER TO streamscope_app;

-- Append-only per-instance operational telemetry. Each state report lands one
-- sample row, keyed by the report that carried it (a report delivered twice is
-- sampled once); the system-tenant Platform Overview graphs request
-- throughput, platform-induced latency, and resource usage over time from it.
--
-- `requests_total` / `errors_total` are cumulative proxy counters (monotonic,
-- reset only on proxy restart) — per-interval values are deltas between
-- consecutive samples. `cpu_percent` / `memory_rss_bytes` / `memory_limit_bytes`
-- / `active_streams` / `pending_audit_count` are point-in-time gauges. The
-- working-set / limit pair yields container memory pressure.

-- intentional: no RLS, global infrastructure (per-instance operational telemetry).
CREATE TABLE edge_stats_samples (
    id                   BIGSERIAL PRIMARY KEY,
    edge_instance_id     UUID NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    sampled_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    process_epoch        BIGINT,
    state_seq            BIGINT,
    requests_total       BIGINT NOT NULL,
    errors_total         BIGINT NOT NULL,
    active_streams       BIGINT NOT NULL,
    cpu_percent          DOUBLE PRECISION NOT NULL,
    memory_rss_bytes     BIGINT NOT NULL,
    -- cgroup memory ceiling (`memory.max`) the working-set is measured against —
    -- the "% of limit" denominator. NULL off-cgroup or when unconstrained.
    memory_limit_bytes   BIGINT,
    uptime_secs          BIGINT NOT NULL,
    -- Proxy-overhead histogram as CUMULATIVE per-bucket counts (monotonic since
    -- proxy start, like `requests_total`): 12 slots on the shared power-of-two
    -- bounds (256µs..262ms + overflow), with sum/count. Windowed percentiles are
    -- derived at read time by differencing consecutive samples per edge instance.
    overhead_buckets     BIGINT[] NOT NULL,
    overhead_sum_us      BIGINT NOT NULL,
    overhead_count       BIGINT NOT NULL,
    pending_audit_count  BIGINT NOT NULL
);

CREATE INDEX idx_edge_stats_samples_instance_time ON edge_stats_samples(edge_instance_id, sampled_at DESC);
CREATE INDEX idx_edge_stats_samples_time ON edge_stats_samples(sampled_at);
CREATE UNIQUE INDEX idx_edge_stats_samples_report
    ON edge_stats_samples (edge_instance_id, process_epoch, state_seq);

ALTER TABLE edge_stats_samples OWNER TO streamscope_app;
ALTER SEQUENCE edge_stats_samples_id_seq OWNER TO streamscope_app;

-- Events for edges (MCP user events today), served to every instance holding
-- the event's tenant except the instance it came from. Ids are taken under an
-- advisory lock held to commit, so they are assigned in commit order and a
-- reader's `id > cursor` never skips a later-committing row. Expired by age.
--
-- intentional: no RLS, global infra every admin replica reads across tenants to answer an edge's poll; delivery is scoped to the tenants the polling instance holds
CREATE TABLE edge_events (
    id               BIGSERIAL PRIMARY KEY,
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    source_instance  UUID,
    body             JSONB NOT NULL,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE edge_events OWNER TO streamscope_app;
ALTER SEQUENCE edge_events_id_seq OWNER TO streamscope_app;
CREATE INDEX idx_edge_events_created_at ON edge_events (created_at);

-- The one-shot events an edge instance reported (breaker transitions, "model
-- not found" answers), by the id the edge numbered each with in its process
-- epoch. The edge restates an event in every report until one is answered,
-- so the ingest writer applies an event only when its key is new here — in
-- the transaction that applies it. Rows outlive any report that can still
-- carry their event by far and are then pruned.
-- intentional: no RLS, global infra keyed by edge instance like edge_instances; it holds ids only, no tenant data
CREATE TABLE edge_instance_events (
    edge_instance_id UUID        NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    process_epoch    BIGINT      NOT NULL,
    event_id         BIGINT      NOT NULL,
    applied_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (edge_instance_id, process_epoch, event_id)
);

CREATE INDEX idx_edge_instance_events_applied ON edge_instance_events (applied_at);

ALTER TABLE edge_instance_events OWNER TO streamscope_app;

-- The latest instance-state report applied for each (edge instance, tenant):
-- the claim the ingest writer takes before it writes that tenant's stands,
-- load samples, breaker states and "model not found" counts. A report not
-- newer than the claim — a redelivery, or a late one — writes none of them, so
-- each is applied once and none moves backwards. A claim of another epoch is a
-- previous process's and is replaced.
CREATE TABLE edge_instance_tenant_state (
    tenant_id         UUID   NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    edge_instance_id  UUID   NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    process_epoch     BIGINT NOT NULL,
    state_seq         BIGINT NOT NULL,
    applied_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, edge_instance_id)
);

CREATE INDEX idx_edge_instance_tenant_state_instance ON edge_instance_tenant_state (edge_instance_id);

ALTER TABLE edge_instance_tenant_state ENABLE ROW LEVEL SECURITY;
ALTER TABLE edge_instance_tenant_state FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON edge_instance_tenant_state TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE edge_instance_tenant_state OWNER TO streamscope_app;

-- ============ Config change bumps ============
-- Config change bumps for the edge config sync.
--
-- Every write to a table the tenant config body reads appends one row per
-- affected resource: `tenant:<uuid>` for a tenant's rows, `global` for rows
-- of no tenant or of the SYSTEM tenant (platform overrides) — a tenant body
-- embeds those, so it is rebuilt when `global` moves. A resource's counter is
-- MAX(id) of its rows. A bump's id is taken when its transaction COMMITS,
-- under an advisory lock held to the end of that commit
-- (`config_bump_commit`), so ids follow commit order: a body labelled with a
-- counter contains every change whose bump is at or below it. (An id taken at
-- statement time could commit after a larger one, and the change would never
-- move the counter.) A transaction bumps each resource once however many
-- statements and rows it touched. A bump says only that something changed:
-- whether a tenant still exists is read from `tenants` in the snapshot that
-- serves it (a tenant's cascaded deletes bump it after its own row is gone). A
-- bump that changes nothing in the body costs a rebuild, never a push.
--
-- intentional: no RLS, global infra read by every admin replica across tenants
CREATE TABLE config_bumps (
    id        BIGSERIAL PRIMARY KEY,
    resource  TEXT NOT NULL,
    at        TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE config_bumps OWNER TO streamscope_app;
ALTER SEQUENCE config_bumps_id_seq OWNER TO streamscope_app;
CREATE INDEX idx_config_bumps_resource ON config_bumps (resource, id DESC);

-- The resources a transaction in progress has bumped. Written by the statement
-- triggers, turned into `config_bumps` rows at that transaction's commit and
-- deleted in the same transaction — no other session ever sees a row.
--
-- intentional: no RLS, global infra private to the writing transaction
CREATE TABLE config_bumps_pending (
    xid       xid8 NOT NULL DEFAULT pg_current_xact_id(),
    resource  TEXT NOT NULL,
    PRIMARY KEY (xid, resource)
);
ALTER TABLE config_bumps_pending OWNER TO streamscope_app;

-- The resource a row of tenant `t` belongs to.
--
-- Owned by the migration role, like `current_tenant_id`: `CREATE OR REPLACE`
-- then requires that ownership, and the triggers bind it by OID.
CREATE FUNCTION config_bump_resource(t uuid) RETURNS text
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
    SELECT CASE
        WHEN t IS NULL OR t = '00000000-0000-0000-0000-000000000001'::uuid THEN 'global'
        ELSE 'tenant:' || t::text
    END
$$;

-- The `system_settings` keys only admin-api reads: bookkeeping it rewrites (the
-- agent's cycle clock on a timer, the seed stamp on every release) and keys no
-- edge may hold. They are in no tenant body: the body builder leaves them
-- out, the bump trigger attributes no bump to them, and the settings API never
-- returns them.
CREATE FUNCTION config_admin_only_setting(k text) RETURNS boolean
LANGUAGE sql
IMMUTABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
    SELECT k = ANY (ARRAY[
        'agent_api_key',
        'agent_last_cycle_at',
        'auth_secret',
        'encryption_key',
        'inline_ai_api_key',
        'internal_service_secret',
        'seed_stamp'
    ])
$$;

-- The statement trigger behind every config table. TG_ARGV[0] says how a row
-- names its resource: `tenant_id` (the column), `global` (no tenant column),
-- or `tenants` (the row IS the tenant).
-- Attribution reads columns of the transition rows only — never a join, which
-- RLS or a cascade could hide. An UPDATE bumps the tenants of the old AND new
-- rows, so a row moved between tenants bumps both. TRUNCATE bumps everything.
-- An admin-only `system_settings` row (`config_admin_only_setting`) bumps
-- nothing: it is in no body.
CREATE FUNCTION config_bump() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    IF TG_OP = 'TRUNCATE' THEN
        INSERT INTO public.config_bumps_pending (resource)
        SELECT public.config_bump_resource(id) FROM public.tenants
        UNION SELECT 'global'
        ON CONFLICT DO NOTHING;
    ELSIF TG_ARGV[0] = 'global' THEN
        -- Only a statement that changed a row: a no-op update or a skipped
        -- upsert would otherwise stale every tenant body.
        -- (Each operation names only its own transition tables.)
        IF TG_OP = 'DELETE' THEN
            IF EXISTS (SELECT 1 FROM old_rows) THEN
                INSERT INTO public.config_bumps_pending (resource) VALUES ('global') ON CONFLICT DO NOTHING;
            END IF;
        ELSIF EXISTS (SELECT 1 FROM new_rows) THEN
            INSERT INTO public.config_bumps_pending (resource) VALUES ('global') ON CONFLICT DO NOTHING;
        END IF;
    ELSIF TG_ARGV[0] = 'tenants' THEN
        IF TG_OP = 'INSERT' THEN
            INSERT INTO public.config_bumps_pending (resource)
            SELECT DISTINCT public.config_bump_resource(id) FROM new_rows
            ON CONFLICT DO NOTHING;
        ELSIF TG_OP = 'DELETE' THEN
            INSERT INTO public.config_bumps_pending (resource)
            SELECT DISTINCT public.config_bump_resource(id) FROM old_rows
            ON CONFLICT DO NOTHING;
        ELSE
            INSERT INTO public.config_bumps_pending (resource)
            SELECT public.config_bump_resource(id) FROM old_rows
            UNION SELECT public.config_bump_resource(id) FROM new_rows
            ON CONFLICT DO NOTHING;
        END IF;
    ELSIF TG_TABLE_NAME = 'system_settings' THEN
        IF TG_OP = 'INSERT' THEN
            INSERT INTO public.config_bumps_pending (resource)
            SELECT DISTINCT public.config_bump_resource(tenant_id) FROM new_rows
             WHERE NOT public.config_admin_only_setting(key)
                ON CONFLICT DO NOTHING;
        ELSIF TG_OP = 'DELETE' THEN
            INSERT INTO public.config_bumps_pending (resource)
            SELECT DISTINCT public.config_bump_resource(tenant_id) FROM old_rows
             WHERE NOT public.config_admin_only_setting(key)
                ON CONFLICT DO NOTHING;
        ELSE
            INSERT INTO public.config_bumps_pending (resource)
            SELECT public.config_bump_resource(tenant_id) FROM old_rows
             WHERE NOT public.config_admin_only_setting(key)
            UNION SELECT public.config_bump_resource(tenant_id) FROM new_rows
             WHERE NOT public.config_admin_only_setting(key)
                ON CONFLICT DO NOTHING;
        END IF;
    ELSIF TG_OP = 'INSERT' THEN
        INSERT INTO public.config_bumps_pending (resource)
        SELECT DISTINCT public.config_bump_resource(tenant_id) FROM new_rows
            ON CONFLICT DO NOTHING;
    ELSIF TG_OP = 'DELETE' THEN
        INSERT INTO public.config_bumps_pending (resource)
        SELECT DISTINCT public.config_bump_resource(tenant_id) FROM old_rows
            ON CONFLICT DO NOTHING;
    ELSE
        INSERT INTO public.config_bumps_pending (resource)
        SELECT public.config_bump_resource(tenant_id) FROM old_rows
        UNION SELECT public.config_bump_resource(tenant_id) FROM new_rows
            ON CONFLICT DO NOTHING;
    END IF;
    RETURN NULL;
END
$$;

-- At commit, each pending bump becomes a `config_bumps` row. The lock is the
-- events' pattern: held from here to the end of the commit, so the next
-- committer's id is larger and is visible after this one's. Owned by the
-- migration role, like the other trigger functions.
CREATE FUNCTION config_bump_commit() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
BEGIN
    PERFORM pg_advisory_xact_lock(737011);
    INSERT INTO public.config_bumps (resource) VALUES (NEW.resource);
    DELETE FROM public.config_bumps_pending WHERE xid = NEW.xid AND resource = NEW.resource;
    RETURN NULL;
END
$$;

CREATE CONSTRAINT TRIGGER config_bump_commit AFTER INSERT ON config_bumps_pending
    DEFERRABLE INITIALLY DEFERRED
    FOR EACH ROW EXECUTE FUNCTION config_bump_commit();

-- ============ Platform Setting Overrides ============
-- Operator-set values for centrally-managed edge/proxy environment-variable
-- settings (the `overridable` entries in the settings catalog). One global
-- override set is pushed to every edge node inside the config body; the
-- edge persists it and applies it on its next restart.
--
-- `token` is the environment-variable name. `value` is the env-var-style
-- string the edge parses, exactly as if it were set in the process env.

-- intentional: no RLS, global infrastructure (one override set for all edges).
CREATE TABLE platform_setting_overrides (
    token       TEXT PRIMARY KEY,
    value       TEXT NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- updated_by: no FK to admin_accounts — attribution only; the override
    -- row must outlive the account that last touched it.
    updated_by  UUID
);

ALTER TABLE platform_setting_overrides OWNER TO streamscope_app;

-- intentional: no RLS, global infrastructure (agent manual-trigger queue;
-- HTTP handlers insert, leader drains each cycle).
CREATE TABLE agent_trigger_requests (
    id          BIGSERIAL PRIMARY KEY,
    tenant_id   UUID,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

ALTER TABLE agent_trigger_requests             OWNER TO streamscope_app;
ALTER SEQUENCE agent_trigger_requests_id_seq   OWNER TO streamscope_app;

-- ============ Platform Egress ============
-- The deployment's internal-egress allowlists: for each outbound surface
-- (`llm`, `mcp`, `a2a`, `oidc`, `web`, `cimd`, `upstream_token`,
-- `extensions`), the private destinations it may reach. A surface with no row
-- reaches none. The platform super-admin edits them; admin-api reads them on
-- every replica, and they ride the config-sync `global` body to every edge,
-- which applies them without a restart.
--
-- `surface` is the surface key the application validates (an unknown key is
-- never written); `entries` are `*`, IP addresses, CIDR prefixes or host
-- names, validated by the application before they are stored.

-- intentional: no RLS, global infrastructure (one egress policy for the whole deployment).
CREATE TABLE platform_egress (
    surface     TEXT PRIMARY KEY,
    entries     TEXT[] NOT NULL DEFAULT '{}',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    -- updated_by: no FK to admin_accounts — attribution only; the row must
    -- outlive the account that last touched it.
    updated_by  UUID
);

ALTER TABLE platform_egress OWNER TO streamscope_app;

-- ============ System Settings ============
-- Free-form per-tenant settings (typed in Rust via the SystemSettings struct).

CREATE TABLE system_settings (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    key         TEXT NOT NULL,
    value       JSONB NOT NULL,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, key)
);

ALTER TABLE system_settings ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_settings FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system_settings TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE system_settings OWNER TO streamscope_app;

-- ============ Sessions ============
-- Materialized per-session rollup (small; not partitioned).
CREATE TABLE sessions (
    tenant_id                    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id                   UUID NOT NULL,
    user_id                      UUID NOT NULL,
    user_email                   TEXT,
    -- Origin axis (mirrors gateway_audit.source): 'agent' = the built-in expert
    -- agent's own sessions, 'user' = everything else. Stamped at ingestion so
    -- the agent-traffic filter is a constant `source <> 'agent'` predicate.
    -- 'external' is forward-declared for non-proxy ingest (OpenTelemetry GenAI).
    source                       TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'agent', 'external')),
    key_id                       UUID,
    -- Issuing workspace, stamped at ingestion from the request's own audit row
    -- rather than derived from `key_id` at read time. An MCP session
    -- authenticated by a spec-OAuth token carries that token's jti here, not an
    -- `api_keys` row, so resolving the workspace through a key join drops such a
    -- session from every workspace-filtered listing. Nil UUID = not attributed.
    -- No FK: like the audit tables, the row outlives the workspace it names.
    workspace_id                 UUID NOT NULL DEFAULT '00000000-0000-0000-0000-000000000000',
    app_id                       TEXT,
    model_used                   TEXT,
    turn_count                   INT NOT NULL DEFAULT 1,
    total_prompt_tokens          BIGINT NOT NULL DEFAULT 0,
    total_completion_tokens      BIGINT NOT NULL DEFAULT 0,
    total_cache_creation_tokens  BIGINT NOT NULL DEFAULT 0,
    total_cache_read_tokens      BIGINT NOT NULL DEFAULT 0,
    total_reasoning_tokens       BIGINT NOT NULL DEFAULT 0,
    -- Session spend — the sum of its turns' `llm_audit.cost`, a figure only in
    -- the one currency `cost_currency` names (below).
    total_cost                   DOUBLE PRECISION NOT NULL DEFAULT 0.0,
    -- Each charge is booked in the tenant's accounting currency in force when
    -- it was written, so a session whose turns straddle a change of that
    -- setting holds a sum in no currency. `cost_currency_count` is how many
    -- currencies its LLM and media turns were booked in: 0 — no LLM turn (a
    -- gateway-only session); 1 — one, named in `cost_currency`; 2 — more than
    -- one: no single figure. The ingest states it on every row it inserts and
    -- moves it one step per LLM or media turn.
    cost_currency                TEXT,
    cost_currency_count          SMALLINT NOT NULL
        CONSTRAINT sessions_cost_currency_count_range CHECK (cost_currency_count IN (0, 1, 2)),
    first_user_prompt            TEXT,
    created_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_latency_ms              BIGINT,
    alert_level                  TEXT,
    alert_expert_axis            TEXT,
    alert_note                   TEXT,
    -- When the session's own "first" and "last" LLM facts were taken, so a turn
    -- landing out of order (an edge resends an older one) cannot overwrite them:
    -- `model_used` / `last_latency_ms` follow the latest turn by its timestamp
    -- (`last_llm_at`), `first_user_prompt` the earliest turn that carried a
    -- prompt (`first_prompt_at`). `updated_at` cannot serve — the gateway upsert
    -- moves it for MCP and A2A records too.
    last_llm_at                  TIMESTAMPTZ,
    first_prompt_at              TIMESTAMPTZ,
    -- Parent-child linkage lives in cross_session_relations (kind='linkage'),
    -- not on this row.
    PRIMARY KEY (tenant_id, session_id),
    CONSTRAINT sessions_cost_currency_named_once CHECK ((cost_currency IS NOT NULL) = (cost_currency_count = 1)),
    -- Spend is added only by an LLM or media turn, which moves the count off 0.
    CONSTRAINT sessions_charge_is_classified CHECK (total_cost = 0 OR cost_currency_count > 0)
);

CREATE INDEX idx_sessions_tenant_updated ON sessions (tenant_id, updated_at DESC);
CREATE INDEX idx_sessions_workspace      ON sessions (tenant_id, workspace_id, updated_at DESC);
CREATE INDEX idx_sessions_user           ON sessions (tenant_id, user_id, updated_at DESC);
CREATE INDEX idx_sessions_created        ON sessions (tenant_id, created_at);
CREATE INDEX idx_sessions_alert          ON sessions (tenant_id, alert_level) WHERE alert_level IN ('minor', 'major');
CREATE INDEX idx_sessions_app_id         ON sessions (tenant_id, app_id)      WHERE app_id IS NOT NULL;

ALTER TABLE sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE sessions FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON sessions TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE sessions OWNER TO streamscope_app;

-- ============ Conversation Storage ============
-- Session replay storage. Message bodies, tool sets and system prompts are
-- content-addressed (one row per distinct body per tenant); a turn names its
-- history by the head of a chain of fixed-size chunks of message hashes, so a
-- turn costs its own chunk, not its whole history (the chunks before it are
-- shared with the session's earlier turns).
--
-- Every content store is stamped, never reference-scanned: a write that names
-- a body renews `last_referenced_at` — rewriting the row only where the stamp
-- is a day old — and the retention sweep deletes a tenant's rows whose stamp is
-- older than its cutoff less a two-day margin. A turn inside the window
-- therefore never loses a body, provided the edge clock that timestamped the
-- turn runs ahead of the database's by less than the margin less that day.

-- Immutable content-addressed message store.
CREATE TABLE conversation_messages (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hash               TEXT NOT NULL,
    message            JSONB NOT NULL,
    content_size       INT NOT NULL DEFAULT 0,
    last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hash)
);

CREATE INDEX idx_conversation_messages_stamp ON conversation_messages (tenant_id, last_referenced_at);

ALTER TABLE conversation_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversation_messages FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON conversation_messages TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE conversation_messages OWNER TO streamscope_app;

-- Immutable content-addressed tool-definition store. Tool sets barely change
-- across turns within a session (clients re-send the same array each request),
-- so the deduplication wins here exceed the per-turn-message savings. A turn
-- references at most two entries: `tools_available_hash` (the wire-protocol
-- tools array as the client sent it) and `tools_effective_hash` (post-policy
-- effective set when tool policy modified it).
CREATE TABLE tool_definitions (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hash               TEXT NOT NULL,
    definition         JSONB NOT NULL,
    content_size       INT NOT NULL DEFAULT 0,
    last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hash)
);

CREATE INDEX idx_tool_definitions_stamp ON tool_definitions (tenant_id, last_referenced_at);

ALTER TABLE tool_definitions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_definitions FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tool_definitions TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE tool_definitions OWNER TO streamscope_app;

-- Immutable content-addressed system-prompt store. An agent repeats one long
-- system prompt on every turn; a turn names it by `system_prompt_hash`.
CREATE TABLE system_prompts (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hash               TEXT NOT NULL,
    prompt             TEXT NOT NULL,
    content_size       INT NOT NULL DEFAULT 0,
    last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hash)
);

CREATE INDEX idx_system_prompts_stamp ON system_prompts (tenant_id, last_referenced_at);

ALTER TABLE system_prompts ENABLE ROW LEVEL SECURITY;
ALTER TABLE system_prompts FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON system_prompts TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE system_prompts OWNER TO streamscope_app;

-- A turn's history as a chain of chunks. A history of n message hashes is cut
-- at fixed boundaries of 16 (`HISTORY_CHUNK`): chunk k holds hashes
-- [16k, 16k+16), the last one possibly fewer. A chunk's `hash` is
-- sha256(parent_hash ‖ hashes), so two turns sharing a prefix share every full
-- chunk of it, and a turn stores at most one new chunk per 16 messages it
-- added. `parent_hash` is NULL on the first chunk. `turn_message_hashes`
-- walks a chain back into the ordered array.
CREATE TABLE turn_history_chunks (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    hash               TEXT NOT NULL,
    parent_hash        TEXT,
    hashes             TEXT[] NOT NULL,
    last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, hash)
);

CREATE INDEX idx_turn_history_chunks_stamp ON turn_history_chunks (tenant_id, last_referenced_at);

ALTER TABLE turn_history_chunks ENABLE ROW LEVEL SECURITY;
ALTER TABLE turn_history_chunks FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON turn_history_chunks TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE turn_history_chunks OWNER TO streamscope_app;

-- Which messages a session carried: one row per (session, distinct message),
-- written at ingest for the messages each turn added (the whole history of a
-- baseline turn). Session search and per-session message reads go through it
-- instead of re-reading every turn's history. Deleted with its session.
CREATE TABLE conversation_session_messages (
    tenant_id     UUID NOT NULL,
    session_id    UUID NOT NULL,
    hash          TEXT NOT NULL,
    PRIMARY KEY (tenant_id, session_id, hash),
    FOREIGN KEY (tenant_id, session_id) REFERENCES sessions(tenant_id, session_id) ON DELETE CASCADE
);

CREATE INDEX idx_conversation_session_messages_hash ON conversation_session_messages (tenant_id, hash);

ALTER TABLE conversation_session_messages ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversation_session_messages FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON conversation_session_messages TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE conversation_session_messages OWNER TO streamscope_app;

-- The elements of a JSON array as one searchable text, space-separated: a
-- string as itself (not JSON-escaped, so a term holding a quote, a backslash
-- or a newline matches it), anything else as its JSON text. IMMUTABLE, so the
-- generated `tool_call_search_blob` below may call it.
CREATE FUNCTION json_array_search_text(arr jsonb) RETURNS text
LANGUAGE sql IMMUTABLE PARALLEL SAFE
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT string_agg(e #>> '{}', ' ') FROM jsonb_array_elements(arr) AS e
$$;

-- Per-turn link table, partitioned by week. `event_type` separates chat turns
-- from media-API turns (media turns have no history — render off
-- `llm_audit.media_call`).
--
-- `history_head` names the last chunk of the turn's history (NULL for a media
-- turn); `message_count` is the history's length and `message_bytes` the
-- stored size of its distinct messages. `added_from` is how many leading
-- messages the turn's parent (the previous turn the edge's session detector
-- named) already carried: the turn added `hashes[added_from:]`. Admin sets it
-- at ingest, from the parent's history when it is known; 0 — the whole history
-- added — on a baseline turn or a parent not landed yet. `system_prompt_hash`
-- names the turn's system prompt.
--
-- `tool_call_search_blob` is a STORED generated column: lower-cased concat of
-- everything the tool-call list's text search reads from the turn — the calls'
-- names, and every scalar value of their arguments (a raw argument string, a
-- string `input`, nested values) across all five upstream-protocol shapes, and the name,
-- description and scalar argument values of each call response policy removed
-- (`transform_diff.response_blocked_tools`), each a value's own text
-- (`json_array_search_text`), each once (`strict`: lax mode would also unwrap
-- every array `.**` reaches and list its elements twice). The expression freezes with the schema; an index
-- or a lookup serving it does not. See
-- `decode_stored_tool_call` for the shape catalogue.
CREATE TABLE conversation_turns (
    tenant_id               UUID NOT NULL,
    request_id              UUID NOT NULL,
    timestamp               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_id, timestamp),

    session_id              UUID,
    turn_number             INT NOT NULL DEFAULT 0,
    parent_request_id       UUID,
    is_baseline             BOOLEAN NOT NULL DEFAULT true,

    history_head            TEXT,
    message_count           INT NOT NULL DEFAULT 0,
    message_bytes           BIGINT NOT NULL DEFAULT 0,
    added_from              INT NOT NULL DEFAULT 0 CHECK (added_from >= 0 AND added_from <= message_count),

    -- Distinguishes chat turns (default) from media RPC turns.
    event_type              TEXT NOT NULL DEFAULT 'chat',
    -- The inbound protocol the history and response are stored in (their
    -- client's own wire shape), stamped at ingest: a turn renders by it,
    -- without its audit row.
    api_version             TEXT NOT NULL,

    -- Hash references into tool_definitions. NULL when the request had no
    -- tools. `tools_available_hash` is the client-sent set; `tools_effective_hash`
    -- is the post-policy effective set (different from available iff tool policy
    -- modified it).
    tools_available_hash    TEXT,
    tools_effective_hash    TEXT,

    request_params          JSONB,
    system_prompt_hash      TEXT,

    transform_diff          JSONB,

    response_content        TEXT,
    response_tool_calls     JSONB,

    request_size_bytes      INT,
    response_size_bytes     INT,

    tool_call_search_blob   TEXT GENERATED ALWAYS AS (
        lower(
            COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls, '$[*].name')), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls, '$[*].function_name')), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls, '$[*].function.name')), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls, '$[*].functionCall.name')), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls,
                   'strict $[*].arguments.** ? (@.type() == "string" || @.type() == "number" || @.type() == "boolean")', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls,
                   'strict $[*].function.arguments.** ? (@.type() == "string" || @.type() == "number" || @.type() == "boolean")', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls,
                   'strict $[*].input.** ? (@.type() == "string" || @.type() == "number" || @.type() == "boolean")', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls,
                   'strict $[*].args.** ? (@.type() == "string" || @.type() == "number" || @.type() == "boolean")', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(response_tool_calls,
                   'strict $[*].functionCall.args.** ? (@.type() == "string" || @.type() == "number" || @.type() == "boolean")', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(transform_diff, '$.response_blocked_tools[*].name', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(transform_diff, '$.response_blocked_tools[*].description', '{}', true)), '')
            || ' '
            || COALESCE(public.json_array_search_text(jsonb_path_query_array(transform_diff,
                   'strict $.response_blocked_tools[*].arguments.** ? (@.type() == "string" || @.type() == "number" || @.type() == "boolean")', '{}', true)), '')
        )
    ) STORED,
    CHECK ((event_type = 'chat') OR history_head IS NULL)
) PARTITION BY RANGE (timestamp);

CREATE TABLE conversation_turns_default PARTITION OF conversation_turns DEFAULT;

CREATE INDEX idx_turns_session_ts              ON conversation_turns (tenant_id, session_id, timestamp DESC);
CREATE INDEX idx_turns_session                 ON conversation_turns (tenant_id, session_id, turn_number);
CREATE INDEX idx_turns_tenant                  ON conversation_turns (tenant_id, timestamp DESC);
CREATE INDEX idx_turns_parent                  ON conversation_turns (tenant_id, parent_request_id) WHERE parent_request_id IS NOT NULL;
CREATE INDEX idx_turns_tools_available_hash    ON conversation_turns (tenant_id, tools_available_hash) WHERE tools_available_hash IS NOT NULL;
CREATE INDEX idx_turns_tools_effective_hash    ON conversation_turns (tenant_id, tools_effective_hash) WHERE tools_effective_hash IS NOT NULL;
-- Session search finds a matching system prompt's sessions through this.
CREATE INDEX idx_turns_system_prompt_hash     ON conversation_turns (tenant_id, system_prompt_hash) WHERE system_prompt_hash IS NOT NULL;

ALTER TABLE conversation_turns ENABLE ROW LEVEL SECURITY;
ALTER TABLE conversation_turns FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON conversation_turns TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE conversation_turns          OWNER TO streamscope_app;
ALTER TABLE conversation_turns_default  OWNER TO streamscope_app;

-- The ordered message hashes of the history whose last chunk is `head`, in the
-- caller's tenant (an invoker function: row-level security confines the walk).
-- NULL for NULL.
CREATE FUNCTION turn_message_hashes(head text) RETURNS text[]
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, public
AS $$
    WITH RECURSIVE chain(hash, parent_hash, hashes, depth) AS (
        SELECT c.hash, c.parent_hash, c.hashes, 0
          FROM public.turn_history_chunks c
         WHERE c.tenant_id = public.current_tenant_id() AND c.hash = head
        UNION ALL
        SELECT c.hash, c.parent_hash, c.hashes, chain.depth + 1
          FROM chain
          JOIN public.turn_history_chunks c
            ON c.tenant_id = public.current_tenant_id() AND c.hash = chain.parent_hash
    )
    SELECT CASE WHEN head IS NULL THEN NULL
                ELSE COALESCE((SELECT array_agg(h ORDER BY depth DESC, ord)
                                 FROM chain, unnest(chain.hashes) WITH ORDINALITY AS u(h, ord)),
                              '{}'::text[])
           END
$$;

-- The messages a turn ADDED to its session, read without its whole history.
--
-- A turn's history is a chain of 16-hash chunks walked back from its head
-- (`turn_message_hashes`). The turn added `hashes[added_from:]` — the tail
-- its parent had not carried — and that tail lies in the last chunks of the
-- chain: `turn_added_hashes_walk` walks back only until it has covered
-- `message_count - added_from` hashes, so its cost is the slice's size, not
-- the history's. It equals `turn_message_hashes(head)[added_from + 1:]` for
-- every complete chain (locked by
-- `test_the_added_slice_is_the_whole_history_sliced_at_added_from`). NULL for
-- NULL; empty when nothing was added. It is the one walk: `turn_added_hashes`
-- calls it for the caller's tenant, and the search lookup functions with the
-- tenant they search. An invoker function, executable by any
-- role: it confers no reach of its own — as the runtime role row-level
-- security confines it to the scoped tenant whatever `p_tenant` says; only
-- a role whose own policy reads across tenants (the lookup and ingest
-- roles) reaches another tenant's chain through it.
CREATE FUNCTION turn_added_hashes_walk(p_tenant uuid, head text, added_from int, message_count int) RETURNS text[]
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY INVOKER
SET search_path = pg_catalog, pg_temp
AS $$
    WITH RECURSIVE chain(parent_hash, hashes, depth, covered) AS (
        SELECT c.parent_hash, c.hashes, 0, cardinality(c.hashes)
          FROM public.turn_history_chunks c
         WHERE c.tenant_id = p_tenant AND c.hash = head
           AND added_from < message_count
        UNION ALL
        SELECT c.parent_hash, c.hashes, chain.depth + 1, chain.covered + cardinality(c.hashes)
          FROM chain
          JOIN public.turn_history_chunks c
            ON c.tenant_id = p_tenant AND c.hash = chain.parent_hash
         -- The bound: a chunk is read only while the slice is not yet covered.
         WHERE chain.covered < message_count - added_from
    )
    SELECT CASE WHEN head IS NULL THEN NULL
                ELSE COALESCE((SELECT a[cardinality(a) - (message_count - added_from) + 1:]
                                 FROM (SELECT array_agg(h ORDER BY depth DESC, ord) AS a
                                         FROM chain, unnest(chain.hashes) WITH ORDINALITY AS u(h, ord)) s
                                WHERE a IS NOT NULL),
                              '{}'::text[])
           END
$$;

-- The caller's tenant (an invoker function: row-level security confines the
-- walk as well). No `SET` clause, deliberately: a SQL function with none is
-- inlined into the query that calls it, so a per-turn read pays one function
-- call (the walk's), not two; every name in it is schema-qualified.
CREATE FUNCTION turn_added_hashes(head text, added_from int, message_count int) RETURNS text[]
LANGUAGE sql
STABLE
PARALLEL SAFE
SECURITY INVOKER
AS $$
    SELECT public.turn_added_hashes_walk(public.current_tenant_id(), head, added_from, message_count)
$$;

-- Turns with their history resolved: every reader that needs a turn's message
-- hashes reads them here. `security_invoker`: the view adds no privilege, so
-- row-level security confines it as it confines the tables.
-- The derived columns come first and `ct.*` last, so a later migration that
-- adds a column to the table re-creates the view with `CREATE OR REPLACE`
-- (Postgres accepts new columns only at the end of a view). A new derived
-- column cannot keep that order: its migration re-creates the view, dropping
-- it and listing every column.
CREATE VIEW conversation_turns_resolved WITH (security_invoker = true) AS
    SELECT turn_message_hashes(ct.history_head) AS message_hashes,
           sp.prompt AS system_prompt,
           turn_added_hashes(ct.history_head, ct.added_from, ct.message_count) AS added_hashes,
           ct.*
      FROM conversation_turns ct
      LEFT JOIN system_prompts sp
        ON sp.tenant_id = ct.tenant_id AND sp.hash = ct.system_prompt_hash;

ALTER VIEW conversation_turns_resolved OWNER TO streamscope_app;

-- ============ Transform Programs ============
-- Rhai scripts that modify request/response contexts. Priority + phase + scope
-- live directly on the program (no separate policies table).

-- ── Profiles: generic named policy bundles, one per domain (`kind`) ──────────
-- A profile is a named, selectable bundle of policy for ONE domain — `kind` is
-- the discriminator ('tools', 'guardrail', 'transform', 'expert'). The profile
-- row carries identity, the one-default invariant, and its inheritance mode;
-- the bundle's CONTENT lives per-domain (tool rules / transform programs tagged
-- by profile_id; guardrail policy in guardrail_policies; expert membership in
-- expert_profile_members).
--
-- DEFAULT-AS-BASE MODEL. There is no separate "shared baseline". Each (tenant,
-- kind) has exactly one DEFAULT profile (is_default = true) that holds the
-- shared/seeded content (where builtins live). Every OTHER profile is one of:
--   • Layered  (standalone = false) — inherits the Default and stores only its
--     own diff; effective content = Default ⊕ own. For 'tools' a Layered rule
--     may override a Default rule via forked_from; transform/expert Layered is
--     additive (∪). Tracks Default edits.
--   • Standalone (standalone = true) — owns its full content and ignores the
--     Default; seeded by forking the seed or blank.
-- The Default itself is seeded standalone = true (it inherits nothing).
--
-- Selection is per (workspace, kind) via workspace_profile_assignments: a
-- workspace with no assignment for a kind runs that kind's Default profile.
--
-- `kind` is open TEXT (no CHECK) so a NEW domain is purely additive — a new kind
-- value, never a schema migration. The closed set the binary knows lives in the
-- Rust `ProfileKind` enum.
CREATE TABLE profiles (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    kind        TEXT NOT NULL,
    name        TEXT NOT NULL,
    description TEXT,
    -- Expert judge model (meaningful only on kind='expert' rows): the Default
    -- expert profile carries the tenant baseline; a non-default profile's NULL
    -- model inherits the Default's.
    model       TEXT,
    is_default  BOOLEAN NOT NULL DEFAULT false,
    -- false = Layered (inherits the Default + own diff); true = Standalone
    -- (owns its full content, ignores the Default). The Default profile is
    -- itself seeded standalone = true (it is the base; it inherits nothing).
    standalone  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, kind, name)
);

-- Exactly one default profile per (tenant, kind).
CREATE UNIQUE INDEX idx_profiles_one_default_per_tenant_kind
    ON profiles (tenant_id, kind) WHERE is_default;

ALTER TABLE profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE profiles FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON profiles TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE profiles OWNER TO streamscope_app;

-- Every program belongs to a profile: builtins live on the kind's DEFAULT
-- profile (the shared base). A Layered profile's effective set = the Default's
-- programs ∪ its own; a Standalone profile's = its own only; an Off workspace
-- runs no programs at all.
CREATE TABLE transform_programs (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id           UUID NOT NULL DEFAULT gen_random_uuid(),
    profile_id   UUID NOT NULL,
    name         TEXT NOT NULL,
    description  TEXT,
    source       TEXT NOT NULL,
    phase        TEXT NOT NULL DEFAULT 'request',
    scope        TEXT NOT NULL DEFAULT 'global',
    priority     INTEGER NOT NULL DEFAULT 100,
    version      INTEGER NOT NULL DEFAULT 1,
    enabled      BOOLEAN NOT NULL DEFAULT false,
    model_filter TEXT,
    app_filter   TEXT,
    -- Optional fast-find regex trigger: when set, the program runs only if the
    -- in-scope content matches this pattern — a cheap native pre-find that
    -- gates the Rhai script. NULL: the program always runs for matching context.
    trigger_regex TEXT,
    -- Execution mode. NULL/'full' runs the script once over the whole in-scope
    -- content; 'span' runs it once per match of `trigger_regex` on just the
    -- matched span + context, splicing each returned replacement back. 'span'
    -- requires a non-blank `trigger_regex`: the trigger is the span finder.
    match_mode   TEXT,
    is_builtin   BOOLEAN NOT NULL DEFAULT false,
    -- A user-deleted builtin is a soft-deleted row, not a separate tombstone
    -- list. Seed-sync UPSERT skips a row that exists and is suppressed, so a
    -- deleted builtin never resurrects on restart.
    suppressed   BOOLEAN NOT NULL DEFAULT false,
    seeded       BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by   UUID,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT transform_programs_span_has_trigger
        CHECK (match_mode IS DISTINCT FROM 'span'
               OR (trigger_regex IS NOT NULL AND btrim(trigger_regex) <> ''))
);

CREATE INDEX idx_programs_tenant_enabled ON transform_programs (tenant_id, enabled, phase);
CREATE INDEX idx_programs_profile ON transform_programs (tenant_id, profile_id);

ALTER TABLE transform_programs ENABLE ROW LEVEL SECURITY;
ALTER TABLE transform_programs FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON transform_programs TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE transform_programs OWNER TO streamscope_app;

-- ============ Program Suggestions ============
-- LLM-proposed transform programs for admin review.

CREATE TABLE program_suggestions (
    tenant_id              UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                     UUID NOT NULL DEFAULT gen_random_uuid(),
    expert_axis            TEXT NOT NULL,
    title                  TEXT NOT NULL,
    rationale              TEXT NOT NULL,
    proposed_source        TEXT NOT NULL,
    proposed_phase         TEXT NOT NULL DEFAULT 'request',
    proposed_scope         TEXT NOT NULL DEFAULT 'global',
    proposed_model_filter  TEXT,
    proposed_app_filter    TEXT,
    -- Span/regex transform fields, carried verbatim onto the promoted program.
    -- `proposed_match_mode`: NULL/'full' = `fn transform(ctx)` over the scope;
    -- 'span' = `fn transform(m)` per `proposed_trigger_regex` match. Trigger is
    -- the fast-find gate (full) / span finder (span); NULL = always run.
    proposed_trigger_regex TEXT,
    proposed_match_mode    TEXT,
    status                 TEXT NOT NULL DEFAULT 'pending',
    program_id             UUID,
    source_sessions        JSONB,
    -- Multi-cycle confirmation gate: a proposal counts toward operator
    -- attention only after it has been seen ≥ `agent_suggestion_min_seen`
    -- cycles. Re-proposing the same pending entry increments seen_count
    -- via ON CONFLICT.
    seen_count             INTEGER NOT NULL DEFAULT 1,
    first_seen_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at             TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at            TIMESTAMPTZ,
    reviewed_by            UUID,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, program_id) REFERENCES transform_programs(tenant_id, id) ON DELETE SET NULL (program_id)
);

CREATE INDEX idx_program_suggestions_status ON program_suggestions(tenant_id, status);
CREATE INDEX idx_program_suggestions_program ON program_suggestions(tenant_id, program_id) WHERE program_id IS NOT NULL;

-- Signature for ON CONFLICT incrementing seen_count on re-proposal. Scoped
-- to pending so an approved/rejected entry doesn't block a later re-proposal.
CREATE UNIQUE INDEX uniq_pending_program_suggestion
    ON program_suggestions (tenant_id, expert_axis, title)
    WHERE status = 'pending';

ALTER TABLE program_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE program_suggestions FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON program_suggestions TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE program_suggestions OWNER TO streamscope_app;

-- ============ Agent Experts ============
-- LLM analysis axes (experts) with prompts + per-expert watermark.

CREATE TABLE agent_experts (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                 UUID NOT NULL DEFAULT gen_random_uuid(),
    axis               TEXT NOT NULL,
    description        TEXT,
    prompt             TEXT NOT NULL,
    enabled            BOOLEAN NOT NULL DEFAULT true,
    is_builtin         BOOLEAN NOT NULL DEFAULT false,
    -- Soft-delete for a user-removed builtin expert; seed-sync skips it.
    suppressed         BOOLEAN NOT NULL DEFAULT false,
    seeded             BOOLEAN NOT NULL DEFAULT false,
    last_processed_at  TIMESTAMPTZ,
    sessions_analyzed  BIGINT NOT NULL DEFAULT 0,
    memory             TEXT NOT NULL DEFAULT '',
    input_types        TEXT[] NOT NULL DEFAULT '{session}',
    output_types       TEXT[] NOT NULL DEFAULT '{transform_suggestion}',
    model_override     TEXT,
    -- Visual identity (hex e.g. '#6366f1').
    color              TEXT,
    -- Ordered array of prompt-snippet keys appended to the expert's raw prompt.
    prompt_snippets    TEXT[] NOT NULL DEFAULT '{}',
    -- Per-expert merge opt-in: experts sharing an input path (session/cluster)
    -- and routing pool into one LLM call when true; false always runs solo.
    -- Admin state — seed-sync sets it on INSERT only, never overwriting an
    -- operator's choice.
    merge_enabled      BOOLEAN NOT NULL DEFAULT true,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, axis)
);

ALTER TABLE agent_experts ENABLE ROW LEVEL SECURITY;
ALTER TABLE agent_experts FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON agent_experts TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE agent_experts OWNER TO streamscope_app;

-- ============ Cross-Session Relations ============
-- The single, generic home for EVERY cross-session relationship — a typed
-- hyperedge from one relation to its N member sessions (each with a role).
-- Two kinds today:
--   'issue'   — a cluster/anomaly finding spanning subject sessions (axis/level/note).
--   'linkage' — a parent→child spawn relationship (confidence/spawn_turn/origin).
-- Cluster-path experts resolve members from S-index refs (never a hand-copied
-- UUID) and write here instead of stamping one arbitrary session's alert_*. A
-- future relation kind is additive (new `kind` value + role vocabulary) — no
-- schema change.
CREATE TABLE cross_session_relations (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                 UUID NOT NULL DEFAULT gen_random_uuid(),
    kind               TEXT NOT NULL,   -- 'issue' | 'linkage' (open; future kinds additive)
    -- Issue payload (NULL for linkage):
    axis               TEXT,            -- emitting expert axis, e.g. 'anomaly'
    level              TEXT CHECK (level IS NULL OR level IN ('info','minor','major')),
    note               TEXT,
    -- Linkage payload (NULL for issue):
    confidence         TEXT,            -- 'header' (header origin) | 'high' | 'medium' (agent)
    -- Spawn anchor for the inline child card. `spawn_turn` is the PARENT turn the
    -- child was spawned from — the code-detected turn once a spawn call is
    -- confirmed, else the model's estimate. `spawn_tool_call_id` is the id of the
    -- `Agent`/`Task`-style tool call in that turn, detected deterministically in
    -- the parent conversation; the UI anchors on the composite (spawn_turn,
    -- spawn_tool_call_id) because a synthesized tool-call id is only turn-unique.
    -- NULL for header-origin linkage (no spawn call) — the reader then content-
    -- matches on read, else falls back to spawn_turn, else the linked-sessions list.
    spawn_turn         INT,
    spawn_tool_call_id TEXT,
    origin             TEXT NOT NULL DEFAULT 'agent',  -- 'agent' | 'header' (X-Parent-Session-Id)
    -- Provenance (best-effort). The workspace comes from the subject sessions'
    -- own workspace_id, and is NULL when they carry none or span more than one.
    -- It is never resolved through key_id: on the spec-OAuth path that column
    -- holds an access token's jti, which matches no api_keys row, so a key join
    -- would leave every such issue unscoped and therefore absent from each
    -- workspace-filtered listing rather than merely unlabelled.
    key_id             UUID,
    workspace_id       UUID,
    expert_profile_id  UUID,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_cross_session_relations_tenant_kind
    ON cross_session_relations (tenant_id, kind, created_at DESC);
CREATE INDEX idx_cross_session_relations_ws
    ON cross_session_relations (tenant_id, workspace_id, created_at DESC)
    WHERE workspace_id IS NOT NULL;

ALTER TABLE cross_session_relations ENABLE ROW LEVEL SECURITY;
ALTER TABLE cross_session_relations FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cross_session_relations TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE cross_session_relations OWNER TO streamscope_app;

-- Member sessions of a relation, each with a role. The session is referenced by
-- value: its row may not exist yet.
CREATE TABLE cross_session_relation_members (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    relation_id  UUID NOT NULL,
    session_id   UUID NOT NULL,
    role         TEXT NOT NULL,   -- 'subject' (issue) | 'parent' | 'child' (linkage)
    seq          INT NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, relation_id, session_id, role),
    FOREIGN KEY (tenant_id, relation_id) REFERENCES cross_session_relations(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_cross_session_members_session
    ON cross_session_relation_members (tenant_id, session_id, role);
-- One-parent-per-child invariant. Only linkage uses role='child'; a FUTURE
-- relation kind MUST NOT reuse 'child' or it would collide with this guard.
CREATE UNIQUE INDEX idx_cross_session_members_one_parent
    ON cross_session_relation_members (tenant_id, session_id)
    WHERE role = 'child';

ALTER TABLE cross_session_relation_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE cross_session_relation_members FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON cross_session_relation_members TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE cross_session_relation_members OWNER TO streamscope_app;

-- ============ Tool Rule Suggestions ============
-- Agent-proposed tool-risk rules for admin review
-- (phase / scope / match[] / action / priority / filters + framework_refs).

CREATE TABLE tool_rule_suggestions (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    expert_axis         TEXT NOT NULL,
    -- Agent-minted stable rule id (e.g. `ASI06-01`, `CUSTOM-SLACK`). Copied
    -- verbatim onto the active rule on approval so the blocked-tool banner
    -- has a stable code to render. Every proposal carries one.
    proposed_rule_id    TEXT NOT NULL,
    risk                TEXT NOT NULL,
    title               TEXT NOT NULL,
    description         TEXT,
    rationale           TEXT NOT NULL,
    phase               TEXT NOT NULL DEFAULT 'response',
    scope               TEXT NOT NULL DEFAULT 'tool_calls',
    match_conditions    JSONB NOT NULL DEFAULT '[]'::jsonb,
    action              JSONB NOT NULL DEFAULT '{"kind":"classify"}'::jsonb,
    priority            INTEGER NOT NULL DEFAULT 100,
    model_filter        TEXT,
    app_filter          TEXT,
    mcp_server_filter   TEXT,
    -- External framework citations (OWASP LLM Top-10, MITRE ATLAS, CWE).
    framework_refs      JSONB,
    status              TEXT NOT NULL DEFAULT 'pending',
    source_sessions     JSONB,
    -- Multi-cycle confirmation gate: a proposal counts toward operator
    -- attention only after it has been seen ≥ `agent_suggestion_min_seen`
    -- cycles. Re-proposing the same pending entry increments seen_count
    -- via ON CONFLICT.
    seen_count          INTEGER NOT NULL DEFAULT 1,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at         TIMESTAMPTZ,
    reviewed_by         UUID,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_tool_rule_suggestions_status ON tool_rule_suggestions (tenant_id, status);

-- Signature for ON CONFLICT incrementing seen_count on re-proposal. Keyed
-- on `(proposed_rule_id, title)` so the same `(axis, title)` with two
-- different `proposed_rule_id`s remain distinct proposals. The write side
-- stores the trimmed id, never an empty one.
CREATE UNIQUE INDEX uniq_pending_tool_rule_suggestion
    ON tool_rule_suggestions (tenant_id, expert_axis, proposed_rule_id, title)
    WHERE status = 'pending';

ALTER TABLE tool_rule_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_rule_suggestions FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tool_rule_suggestions TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE tool_rule_suggestions OWNER TO streamscope_app;

-- Agent-proposed tool FIELD PROFILES — map a wire (tool, arg) onto a canonical
-- (tool_id, field) + normaliser so `arg.<field>`/`tool_id` rules can target it.
-- Mirrors tool_rule_suggestions; on approval the row becomes a
-- tool_field_profiles row. Field profiles are flat/tenant-level (NOT
-- profile-scoped), so there is no profile_id here.
CREATE TABLE field_profile_suggestions (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    expert_axis         TEXT NOT NULL,
    -- Agent-suggested stable profile id (e.g. `TFP-slack-postMessage-channel`).
    -- Copied onto the registered profile on approval; nullable.
    proposed_profile_id TEXT,
    description         TEXT,
    -- Provenance tag carried onto the profile (display-only).
    source              TEXT,
    tool_id             TEXT NOT NULL,
    tool_pattern        TEXT NOT NULL,
    app_filter          TEXT,
    mcp_server          TEXT,
    server_type         TEXT,
    field               TEXT NOT NULL,
    wire_field          TEXT,
    normalizer          TEXT NOT NULL,
    priority            INTEGER NOT NULL DEFAULT 100,
    rationale           TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'pending',
    source_sessions     JSONB,
    -- Multi-cycle confirmation gate (see tool_rule_suggestions).
    seen_count          INTEGER NOT NULL DEFAULT 1,
    first_seen_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    reviewed_at         TIMESTAMPTZ,
    reviewed_by         UUID,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_field_profile_suggestions_status ON field_profile_suggestions (tenant_id, status);

-- ON CONFLICT key: same (axis, tool_pattern, field) is one proposal. Profiles
-- have no title, so dedup on the (tool_pattern, field) it canonicalises.
CREATE UNIQUE INDEX uniq_pending_field_profile_suggestion
    ON field_profile_suggestions (tenant_id, expert_axis, tool_pattern, field)
    WHERE status = 'pending';

ALTER TABLE field_profile_suggestions ENABLE ROW LEVEL SECURITY;
ALTER TABLE field_profile_suggestions FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON field_profile_suggestions TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE field_profile_suggestions OWNER TO streamscope_app;

-- ============ Tenant Management ============
-- Per-tenant auth configuration + one-time invite tokens.

CREATE TABLE tenant_auth_configs (
    tenant_id                       UUID PRIMARY KEY REFERENCES tenants(id) ON DELETE CASCADE,
    auth_mode                       TEXT NOT NULL DEFAULT 'internal',
    oidc_issuer_url                 TEXT,
    oidc_client_id                  TEXT,
    encrypted_oidc_client_secret    TEXT,
    oidc_scopes                     TEXT NOT NULL DEFAULT 'openid email profile',
    -- IdP group → console role mapping. A user whose groups claim contains
    -- `admin_group` logs in as Admin; `readonly_group` → ReadOnly; neither →
    -- no console access. Recomputed on every OIDC login (authoritative).
    admin_group                     TEXT,
    readonly_group                  TEXT,
    allowed_domains                 TEXT[],
    -- When true, MCP OAuth /authorize delegates user-auth to the tenant's
    -- OIDC IdP (reuses portal OIDC config). JWT is still minted locally.
    mcp_oauth_delegate_to_oidc      BOOLEAN NOT NULL DEFAULT false,
    -- Whether this tenant accepts CIMD (Client ID Metadata Document) clients —
    -- an OAuth client that publishes its metadata at an HTTPS URL and presents
    -- that URL as its `client_id`, with no registration step at all. That is the
    -- one path on which an unregistered caller can name a URL this deployment
    -- fetches, once per authorization. Turning it off makes the tenant's RFC 8414
    -- document advertise it as unsupported, refuses a URL-shaped `client_id` at
    -- /authorize, and refuses a `client_id_metadata_url` at /register.
    mcp_oauth_cimd_enabled          BOOLEAN NOT NULL DEFAULT true,
    -- Which ID-token claims an OIDC login reads. Identity providers disagree on
    -- claim names: AD FS names a claim by the short name in its Claim
    -- Descriptions list (`group`, `upn`), Entra and Keycloak send `groups`, and
    -- a directory account without a mailbox has no `email` at all.
    --
    -- `oidc_groups_claim` drives the console role (`admin_group` /
    -- `readonly_group`); workspace auto-join names its own claim per workspace.
    -- `oidc_email_claim` names the claim the account is keyed on; the IdP's
    -- `email_verified` only ever describes the standard `email` claim, so any
    -- other choice has no verification statement at all.
    -- `oidc_allow_unverified_email` accepts an address the provider did not
    -- state as verified; it never overrides an explicit `email_verified: false`.
    -- `oidc_response_mode` is how the provider returns the authorization code:
    -- `query` (the OAuth default) or `form_post` — AD FS puts claims issued by
    -- its rules into the ID token only for a form_post authorization.
    oidc_groups_claim               TEXT NOT NULL DEFAULT 'groups'
        CONSTRAINT chk_oidc_groups_claim_nonempty CHECK (btrim(oidc_groups_claim) <> ''),
    oidc_email_claim                TEXT NOT NULL DEFAULT 'email'
        CONSTRAINT chk_oidc_email_claim_nonempty CHECK (btrim(oidc_email_claim) <> ''),
    oidc_allow_unverified_email     BOOLEAN NOT NULL DEFAULT false,
    oidc_response_mode              TEXT NOT NULL DEFAULT 'query'
        CONSTRAINT chk_oidc_response_mode CHECK (oidc_response_mode IN ('query', 'form_post')),
    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT chk_auth_mode CHECK (auth_mode IN ('internal', 'oidc')),
    -- A claim other than `email` never carries a verification statement, so
    -- keying on one without accepting unstated addresses would refuse every
    -- sign-in. The pair is refused at save time instead of at every login.
    CONSTRAINT chk_oidc_email_claim_needs_opt_in
        CHECK (oidc_email_claim = 'email' OR oidc_allow_unverified_email)
);

ALTER TABLE tenant_auth_configs ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_auth_configs FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_auth_configs TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE tenant_auth_configs OWNER TO streamscope_app;

-- One-time invite tokens. `token_hash` is unique across tenants: accepting an
-- invite resolves its tenant from the token alone (`resolve_invite`).
CREATE TABLE tenant_invites (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    -- SHA-256 hash of the invite token (plaintext never stored).
    token_hash    TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'admin',
    email         TEXT,
    is_emergency  BOOLEAN NOT NULL DEFAULT false,
    used_by       UUID,
    used_at       TIMESTAMPTZ,
    expires_at    TIMESTAMPTZ NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, used_by) REFERENCES admin_accounts(tenant_id, id) ON DELETE SET NULL (used_by)
);

-- Global by design: the pre-auth invite lookup.
CREATE UNIQUE INDEX idx_tenant_invites_token_hash ON tenant_invites(token_hash);

ALTER TABLE tenant_invites ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenant_invites FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tenant_invites TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE tenant_invites OWNER TO streamscope_app;

-- ============ Audit Log ============
-- Gateway-wide partitioned audit trail. Parent `gateway_audit` holds the
-- common columns; per-kind child tables hold the protocol-specific payload
-- (`llm_audit`, `mcp_audit`, `web_audit`, `a2a_audit`). Children reference the
-- parent on (tenant_id, request_id, timestamp) so deletes cascade in lockstep
-- with the partition manager (drops children before parents).
--
-- `kind` is intentionally forward-declared to include every planned child —
-- 'otel' is reserved for the OpenTelemetry GenAI ingest. Reserving a value here
-- keeps the parent CHECK append-only: a new domain adds a child table + code
-- with no ALTER of this constraint on the partitioned parent. A value MUST be
-- listed here before any row can carry it. The PK is on the partitioned parent
-- (required for cross-partition FKs).

CREATE TABLE gateway_audit (
    tenant_id         UUID NOT NULL,
    request_id        UUID NOT NULL,
    timestamp         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_id, timestamp),

    workspace_id      UUID NOT NULL,
    user_id           UUID NOT NULL,
    key_id            UUID,
    app_id            TEXT,
    -- The hashed session (`session_id_from_client`), the same UUID as
    -- `sessions.session_id`; NULL on untracked traffic.
    session_id        UUID,
    user_agent        TEXT,
    -- Source IP as seen by the gateway (the immediate peer). Populated by the
    -- MCP path; the LLM path leaves it NULL.
    ip                TEXT,
    -- Forwarded end-client identity, present only for inline-gateway traffic: a
    -- trusted inline key forwards it, a normal key can never set it. For inline
    -- traffic `ip` is the gateway's own address, so the real end client is here.
    -- NULL / empty for a direct request, whose principal is the key's user_id.
    client_ip         TEXT,
    end_user          TEXT,
    end_user_groups   TEXT[] NOT NULL DEFAULT '{}',
    detection_method  TEXT,

    -- Discriminator: which child table holds the rest of the row.
    kind              TEXT NOT NULL CHECK (kind IN ('llm', 'mcp', 'web', 'a2a', 'otel')),

    -- Origin axis, orthogonal to `kind`: who produced the row. 'agent' is the
    -- built-in expert agent's own traffic; 'user' is everything else. Stamped
    -- once at ingestion as provenance — agent traffic is filtered by workspace
    -- (the Agent workspace), not by this column; the expert dashboard's own-
    -- traffic query reads `source = 'agent'`. A non-proxy ingest origin is a new
    -- value here, NOT a new `kind`: 'external' is forward-declared for the
    -- OpenTelemetry GenAI ingest (rows the gateway didn't proxy).
    source            TEXT NOT NULL DEFAULT 'user' CHECK (source IN ('user', 'agent', 'external')),

    latency_total_ms  BIGINT NOT NULL DEFAULT 0,
    status_code       SMALLINT,
    error_category    TEXT,
    error_detail      TEXT,
    -- Which limit refused a request (`organisation` | `workspace` | `member` |
    -- `key`), on a row refused by one. NULL on every other row.
    limit_bucket      TEXT
) PARTITION BY RANGE (timestamp);

CREATE TABLE gateway_audit_default PARTITION OF gateway_audit DEFAULT;

CREATE INDEX idx_gateway_audit_tenant      ON gateway_audit (tenant_id, timestamp DESC);
CREATE INDEX idx_gateway_audit_workspace   ON gateway_audit (tenant_id, workspace_id, timestamp DESC);
CREATE INDEX idx_gateway_audit_tenant_user ON gateway_audit (tenant_id, user_id, timestamp DESC);
CREATE INDEX idx_gateway_audit_app_id      ON gateway_audit (tenant_id, app_id, timestamp DESC) WHERE app_id IS NOT NULL;
CREATE INDEX idx_gateway_audit_key         ON gateway_audit (tenant_id, key_id, timestamp DESC) WHERE key_id IS NOT NULL;
CREATE INDEX idx_gateway_audit_error       ON gateway_audit (tenant_id, error_category, timestamp DESC) WHERE error_category IS NOT NULL;
CREATE INDEX idx_gateway_audit_kind        ON gateway_audit (tenant_id, kind, timestamp DESC);

ALTER TABLE gateway_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE gateway_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON gateway_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE gateway_audit          OWNER TO streamscope_app;
ALTER TABLE gateway_audit_default  OWNER TO streamscope_app;

-- LLM-specific child.
CREATE TABLE llm_audit (
    tenant_id               UUID NOT NULL,
    request_id              UUID NOT NULL,
    timestamp               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_id, timestamp),
    -- Denormalized so tenant scans by workspace skip the parent join.
    workspace_id            UUID NOT NULL,

    -- Request shape.
    model_requested         TEXT NOT NULL,
    model_used              TEXT NOT NULL,
    provider                TEXT NOT NULL,
    api_version             TEXT NOT NULL,
    stream                  BOOLEAN NOT NULL DEFAULT true,

    -- Token usage.
    prompt_tokens           INT NOT NULL DEFAULT 0,
    completion_tokens       INT NOT NULL DEFAULT 0,
    reasoning_tokens        INT,
    cache_creation_tokens   INT,
    cache_read_tokens       INT,
    finish_reason           TEXT NOT NULL DEFAULT '',
    native_finish_reason    TEXT,

    -- Cost. `cost` is the row's true total and what every spend aggregate reads,
    -- expressed in `cost_currency` — the tenant's accounting currency AS IT WAS
    -- when the row was written. Stamped per row rather than joined from the
    -- tenant's current setting, because changing that setting must not silently
    -- restate last month's spend.
    --
    --   cost = (sum of billed_units[*].cost) + embedding_cost
    --
    -- `billed_units` decomposes the total per pricing unit:
    --   {"input_token":{"count":1200,"cost":0.0036}, …}
    -- where `count` is what was CHARGED — the provider's reported count less
    -- anything that partitions out of it (cached tokens, audio tokens), each of
    -- which appears on its own line. Keep the identity above true when adding
    -- any further component.
    --
    -- `source_cost`/`source_currency` are what the provider charges, in the
    -- currency it quotes, and `fx_rate` is the multiplier that took one to the
    -- other. All three are stamped so a row stays auditable against the
    -- provider's own invoice even after the operator's conversion table moves.
    -- With no conversion needed or configured, `fx_rate` is 1 and the two
    -- amounts agree.
    --
    -- `embedding_cost` is the response cache's own embedding call, charged to
    -- the request that triggered it (a Semantic preset embeds on every exact
    -- miss). It is not a pricing unit of the model, so it sits outside
    -- `billed_units`.
    cost                    DOUBLE PRECISION NOT NULL DEFAULT 0,
    cost_currency           TEXT NOT NULL DEFAULT 'USD',
    source_cost             DOUBLE PRECISION NOT NULL DEFAULT 0,
    source_currency         TEXT NOT NULL DEFAULT 'USD',
    fx_rate                 DOUBLE PRECISION NOT NULL DEFAULT 1,
    billed_units            JSONB NOT NULL DEFAULT '{}',
    embedding_cost          DOUBLE PRECISION NOT NULL DEFAULT 0,
    -- Prompt tokens the embedding call consumed. Deliberately NOT folded into
    -- `prompt_tokens`: that column feeds zero-completion detection, TPM accrual
    -- and token analytics, all of which describe the completion only.
    embedding_tokens        INT NOT NULL DEFAULT 0,
    zero_completion         BOOLEAN NOT NULL DEFAULT false,

    -- Response-cache accounting. All three are NULL/0 on an alias that binds no
    -- cache preset, so `cache_mode IS NOT NULL` is exactly "this request went
    -- through a cached alias" — the denominator of the hit rate.
    --   cache_mode    'exact' | 'semantic' | 'observe' — the policy IN FORCE at
    --                 the time of the request. Stamped here rather than joined
    --                 live through the route, because a preset edit would
    --                 otherwise retroactively rewrite history.
    --   cache_outcome 'hit' | 'observe_hit' | 'miss' | 'bypass'.
    -- `avoided_cost` is the counterfactual: what the upstream call this
    -- request did NOT make would have cost, at the alias's rates, in
    -- `cost_currency`. It is deliberately NOT part of `cost` — no money changed
    -- hands. Under observe mode the match is recorded but still billed
    -- upstream, so the figure means "what enforcing would have saved" and must
    -- be summed only for `cache_outcome = 'hit'`. It is a column and not just
    -- the `cache_hit` badge because the badge cannot be summed cheaply, and
    -- because a hit on an unpriced model avoids $0 — so hits are counted from
    -- `cache_outcome`, never from a non-zero cost.
    cache_mode              TEXT,
    cache_outcome           TEXT,
    avoided_cost            DOUBLE PRECISION NOT NULL DEFAULT 0,

    -- TTFT meaningful only for stream=true.
    latency_ttft_ms         BIGINT NOT NULL DEFAULT 0,

    -- Typed audit signal — see streamscope_core::audit::AuditBadge.
    badges                  JSONB NOT NULL DEFAULT '[]',

    -- Internal pipeline tag (`fastpath` | `buffered`). Analytics-only.
    pipeline_path           TEXT,

    -- Catch-all proxy hit metadata.
    catchall_path           TEXT,
    catchall_method         TEXT,

    -- LLM upstream tracking.
    upstream_server_id      UUID,
    upstream_model_id       UUID,

    -- Canonical media RPC turn + chat-message media summary.
    media_call              JSONB,
    chat_media_summary      JSONB,

    -- The endpoint that answered a request: its id, and its URL at the time.
    -- No foreign key, so a row keeps naming the endpoint after it is removed.
    -- NULL on a row with no upstream call.
    endpoint_id             UUID,
    endpoint_url            TEXT,

    -- What the request waited for capacity, and the class it waited as. No
    -- foreign key on the class: an audit row records what happened, and must
    -- neither hold a class back from deletion nor lose the row when one goes.
    queue_wait_ms           INTEGER,
    qos_class_id            UUID,

    -- How the dispatch gate treated a request, for the server dashboard.
    -- `gate_refusal` is set only on a request that ENDED refused, by the pool of
    -- the server the row names: why (`shed`, `queue_timeout`,
    -- `gateway_saturated`, `shutting_down`). `pool_wait_ms` is what the request
    -- waited at that server's pool before the attempt it ended with.
    -- `moved_on_from` lists, in order, every attempt the request moved on from
    -- before that one — `[{"server_id"?, "endpoint_id"?, "outcome", "reason",
    -- "status"?, "wait_ms", "elapsed_ms"}]` (no server for a pass-through
    -- target, whose time still counts): `outcome` `refused` (reason: the
    -- refusal's) or `failed` (reason and status: the failure's error category
    -- and audited status), `elapsed_ms` how long the attempt took; NULL when
    -- none — because each is its server's to count, whatever became of the
    -- request after. `queue_wait_ms` (everything the caller waited) is
    -- `pool_wait_ms` plus every `wait_ms` here. `error_detail` is prose and is
    -- never parsed.
    gate_refusal            TEXT,
    pool_wait_ms            INTEGER,
    moved_on_from           JSONB,

    FOREIGN KEY (tenant_id, request_id, timestamp)
        REFERENCES gateway_audit (tenant_id, request_id, timestamp)
        ON DELETE CASCADE
) PARTITION BY RANGE (timestamp);

CREATE TABLE llm_audit_default PARTITION OF llm_audit DEFAULT;

CREATE INDEX idx_llm_audit_tenant          ON llm_audit (tenant_id, timestamp DESC);
-- Per-model analytics over a window (model_used + time, tenant-scoped).
CREATE INDEX idx_llm_audit_model_used      ON llm_audit (tenant_id, model_used, timestamp);
-- Cache analytics scan only rows that went through a cached alias, which is a
-- small slice of traffic on a tenant that caches a few aliases — so the partial
-- index keeps that aggregate off a full tenant-window scan.
CREATE INDEX idx_llm_audit_cache           ON llm_audit (tenant_id, timestamp DESC) WHERE cache_mode IS NOT NULL;
-- One server's rows in a window, for the per-server dashboard. Partial: a row
-- that reached no upstream names no server and is never read by server.
CREATE INDEX idx_llm_audit_server
    ON llm_audit (tenant_id, upstream_server_id, timestamp DESC)
    WHERE upstream_server_id IS NOT NULL;
-- The requests that ended refused, and the ones that moved on from an attempt,
-- in a window. Partial: both are rare.
CREATE INDEX idx_llm_audit_gate_refusal
    ON llm_audit (tenant_id, timestamp DESC)
    WHERE gate_refusal IS NOT NULL;
CREATE INDEX idx_llm_audit_moved_on_from
    ON llm_audit (tenant_id, timestamp DESC)
    WHERE moved_on_from IS NOT NULL;
-- The media rows of one tenant in a window, for the audit list's media filter:
-- the endpoint is a filter over this tenant's media rows only.
CREATE INDEX idx_llm_audit_media
    ON llm_audit (tenant_id, timestamp DESC)
    WHERE media_call IS NOT NULL;

ALTER TABLE llm_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE llm_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON llm_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE llm_audit          OWNER TO streamscope_app;
ALTER TABLE llm_audit_default  OWNER TO streamscope_app;

-- ============ Audit Media Blobs ============
-- SHA-256 content-addressed binary storage for audit media. Stores DECODED
-- final binary only (never intermediate base64 or raw multipart); identical
-- content shared across audits stays a single row. A content store like the
-- conversation stores: an edge ships a blob ahead of the records that name it,
-- and every ingest that delivers or names a blob stamps `last_referenced_at`,
-- so the range purge removes only blobs no record in the window names. A
-- stored blob is never rewritten.

CREATE TABLE audit_media_blobs (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    content_hash  TEXT NOT NULL,
    -- Closed discriminator set — the canonical `BlobType` enum
    -- (streamscope-core `audit::blob_type`). Storage, the `blob_ref` audit
    -- references and the serving endpoint all pivot on these exact strings.
    blob_type     TEXT NOT NULL
        CHECK (blob_type IN (
            'request_upload', 'response_body', 'chat_image', 'chat_audio',
            'chat_document', 'chat_file', 'image_generation_output',
            -- forward-declared for async video (Sora/Veo) content capture.
            'video_generation_output'
        )),
    media_type    TEXT NOT NULL,            -- MIME
    data          BYTEA NOT NULL,
    size_bytes    BIGINT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_referenced_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, content_hash, blob_type)
);

CREATE INDEX idx_audit_media_blobs_stamp ON audit_media_blobs (tenant_id, last_referenced_at);

ALTER TABLE audit_media_blobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_media_blobs FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON audit_media_blobs TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE audit_media_blobs OWNER TO streamscope_app;

-- ============ Control-plane Audit ============
-- Append-only control-plane audit log family.
--
-- Three sibling tables capture every mutating call to a non-data-plane API
-- surface, so "no mutating API surface without an audit row" holds:
--   * admin_audit    — authenticated admin (operator) mutations on /api/v1/admin/*
--   * portal_audit   — authenticated portal (end-user) mutations on /api/v1/portal/*
--   * security_audit — pre-auth / public security events (login, setup,
--                      oidc-exchange, invite-accept, MCP-OAuth grant/register)
-- The data plane (gateway_audit + llm/mcp/web/a2a children) is audited separately.
--
-- request_body captures the operator's INTENT — what they sent on the wire
-- (redacted). change_diff captures the EFFECT — the before/after snapshot of
-- the row(s) the handler actually mutated. response_error captures the FAILURE
-- REASON — the typed {code, message} body of any non-2xx response, so a logged
-- 4xx/5xx shows why it failed (NULL on success). Follows the CloudTrail / GCP
-- Audit Log / k8s audit pattern: record the API call AND the row delta.
--
-- Non-partitioned by design: control-plane mutations are low-volume (<10k/day
-- on a busy install) so a plain table handles years of data, and retention is
-- a single DELETE inside the retention worker.

CREATE TABLE admin_audit (
    tenant_id       UUID NOT NULL,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- Who/what acted. 'human' = an admin_accounts session (JWT / header / OIDC);
    -- 'admin_key' = an ak- automation key (actor_id then carries the owning
    -- service-account user_id, actor_email its email, actor_key_id the key).
    actor_kind      TEXT NOT NULL DEFAULT 'human',
    actor_id        UUID,
    actor_email     TEXT,
    -- The ak- key id (automation_keys.id, plane='admin') when
    -- actor_kind='admin_key'; NULL for humans. Answers "which automation did
    -- this?" independently of the account.
    actor_key_id    UUID,
    actor_ip        TEXT,
    is_super_admin  BOOLEAN NOT NULL DEFAULT FALSE,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    route_template  TEXT,
    action          TEXT NOT NULL,
    resource_kind   TEXT NOT NULL,
    resource_id     TEXT,
    request_body    JSONB,
    change_diff     JSONB,
    response_error  JSONB,
    status_code     SMALLINT NOT NULL,
    request_id      UUID NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_admin_audit_tenant_at ON admin_audit (tenant_id, at DESC);
CREATE INDEX idx_admin_audit_actor_at  ON admin_audit (tenant_id, actor_id, at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_admin_audit_action_at ON admin_audit (tenant_id, action, at DESC);
CREATE INDEX idx_admin_audit_key_at    ON admin_audit (tenant_id, actor_key_id, at DESC) WHERE actor_key_id IS NOT NULL;

ALTER TABLE admin_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE admin_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON admin_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE admin_audit OWNER TO streamscope_app;

-- Portal (end-user) action audit log. Mirrors admin_audit but the actor is a
-- `users` row (portal session), not an `admin_accounts` row.
--   workspace_id   — best-effort: the request's workspace when one is in scope
--                    (e.g. key creation / quickstart render carry it in the
--                    body). NULL when the mutation isn't workspace-bound.
--   target_user_id — the member a manager operates on (mint/revoke a key for
--                    someone else). NULL for self-service mutations.
CREATE TABLE portal_audit (
    tenant_id       UUID NOT NULL,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    actor_id        UUID,
    actor_email     TEXT,
    actor_ip        TEXT,
    -- 'human' (portal session JWT) | 'portal_key' (an `ak-` portal automation
    -- key — actor_id/actor_email are then the owning service account, and
    -- actor_key_id the key id below).
    actor_kind      TEXT NOT NULL DEFAULT 'human',
    -- The automation_keys.id (plane='portal') when actor_kind='portal_key';
    -- NULL for a human.
    actor_key_id    UUID,
    workspace_id    UUID,
    target_user_id  UUID,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    route_template  TEXT,
    action          TEXT NOT NULL,
    resource_kind   TEXT NOT NULL,
    resource_id     TEXT,
    request_body    JSONB,
    change_diff     JSONB,
    response_error  JSONB,
    status_code     SMALLINT NOT NULL,
    request_id      UUID NOT NULL,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_portal_audit_tenant_at    ON portal_audit (tenant_id, at DESC);
CREATE INDEX idx_portal_audit_actor_at     ON portal_audit (tenant_id, actor_id, at DESC) WHERE actor_id IS NOT NULL;
CREATE INDEX idx_portal_audit_workspace_at ON portal_audit (tenant_id, workspace_id, at DESC) WHERE workspace_id IS NOT NULL;
CREATE INDEX idx_portal_audit_action_at    ON portal_audit (tenant_id, action, at DESC);
CREATE INDEX idx_portal_audit_key_at       ON portal_audit (tenant_id, actor_key_id, at DESC) WHERE actor_key_id IS NOT NULL;

ALTER TABLE portal_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE portal_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON portal_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE portal_audit OWNER TO streamscope_app;

-- Pre-auth / public security event log. Records login, account setup,
-- OIDC exchange, invite acceptance, and MCP-OAuth grant/register attempts —
-- successes AND failures — with the attempted identity + source IP.
--
-- intentional: no RLS, global pre-auth security log — a failed login can abort
-- before any tenant is resolved (rate-limit short-circuit, unknown slug), and
-- brute-force against an unknown tenant must stay loggable. tenant_id and
-- tenant_slug are nullable + best-effort (resolved from the request when
-- available). Written through the global door by the security-audit middleware.
CREATE TABLE security_audit (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    tenant_id       UUID,
    tenant_slug     TEXT,
    actor_identity  TEXT,
    actor_ip        TEXT,
    method          TEXT NOT NULL,
    path            TEXT NOT NULL,
    route_template  TEXT,
    action          TEXT NOT NULL,
    succeeded       BOOLEAN NOT NULL,
    status_code     SMALLINT NOT NULL,
    request_body    JSONB,
    response_error  JSONB,
    request_id      UUID NOT NULL
);

CREATE INDEX idx_security_audit_at          ON security_audit (at DESC);
CREATE INDEX idx_security_audit_identity_at ON security_audit (actor_identity, at DESC) WHERE actor_identity IS NOT NULL;
CREATE INDEX idx_security_audit_ip_at       ON security_audit (actor_ip, at DESC) WHERE actor_ip IS NOT NULL;
CREATE INDEX idx_security_audit_action_at   ON security_audit (action, at DESC);

ALTER TABLE security_audit OWNER TO streamscope_app;

-- ============ Workspaces ============
-- Workspaces: the issuance + budget grain inside a tenant.
--
-- A tenant registers providers (downstream_providers) and MCP virtual servers
-- (mcp_virtual_servers) once in its pool. Each workspace allowlists a subset of
-- that pool, sets a rate/budget ceiling, and holds members. API keys are bound
-- to (user, workspace); the key carries its workspace forever and every request
-- is gated by the workspace's allowlist.
--
-- Workspace kind is the single `role` column ('standard' | 'default' | 'agent' |
-- 'inline'), not a set of booleans. The Default workspace (role = 'default', one
-- per tenant) is an ordinary workspace: its access is governed by the allowlist
-- tables like any other, and it carries its own rate/budget caps. Its only
-- special trait is that it cannot be deleted — there is **no auto-join**. A user
-- joins a workspace only when explicitly added, by an admin or by OIDC group
-- sync, so minting a key for a non-member fails `workspace_membership_required`.
--
-- Budgets are DOUBLE PRECISION (USD) to match the proxy's RateLimitConfig; all
-- cap columns are nullable, where NULL = no cap on that dimension.
CREATE TABLE workspaces (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    name            TEXT NOT NULL,
    description     TEXT,
    -- Optional OIDC-claim auto-membership: a user whose `oidc_claim_name` claim
    -- matches `oidc_claim_pattern` is added to this workspace at login.
    oidc_claim_name    TEXT,
    oidc_claim_pattern TEXT,
    -- 'standard' is an ordinary user workspace (many per tenant). The other
    -- three are per-tenant singletons (partial unique indexes below), each
    -- seeded and undeletable:
    --   • 'default' — the tenant catch-all workspace;
    --   • 'agent'   — the internal analysis agent's home (its key + self-traffic),
    --                 governed like any workspace (grants/budget/rate-limit);
    --   • 'inline'  — the inline gateway's home: multi-provider BYOK passthrough for
    --                 /fwd/{key}/… and the /v1/analyze target. Its assigned
    --                 profiles ARE the inline enforcement policy.
    role            TEXT NOT NULL DEFAULT 'standard'
                        CHECK (role IN ('standard', 'default', 'agent', 'inline')),
    -- How much of this workspace one member may see of another, in the portal.
    --
    --   • 'private' — each member sees only their own usage, sessions and audit.
    --   • 'members' — any member sees the whole workspace's activity.
    --
    -- The grain is the workspace because the workspace is already the issuance,
    -- budget and access boundary; a separate "group" would be a second grouping
    -- of the same people. Default 'private' — widening what a colleague can see
    -- is an explicit choice an admin makes, never an upgrade side effect.
    member_visibility TEXT NOT NULL DEFAULT 'private'
                        CHECK (member_visibility IN ('private', 'members')),
    -- Whether this workspace's spend rolls into the tenant's org-total budget.
    --
    -- On for an ordinary workspace: the org ceiling exists to cap the
    -- organisation, and every team's spend belongs in it. Off for a workspace
    -- the organisation is not paying for — inline AI, whose intercepted calls
    -- are funded on the end user's own provider account, and any workspace an
    -- operator bills elsewhere.
    --
    -- Off removes the workspace from the tenant bucket ENTIRELY, not just from
    -- the total: its requests are neither charged to the org ceiling nor blocked
    -- by it. Accruing without enforcing would be defensible, but enforcing
    -- without accruing is not — it would stop traffic against a counter that
    -- traffic can never move, leaving no way out but raising a cap the workspace
    -- does not consume.
    counts_toward_tenant_budget BOOLEAN NOT NULL DEFAULT true,
    -- The workspace's QoS class (NULL = the tenant's default class) and its
    -- share of the pool when several workspaces are backlogged at once. RESTRICT
    -- so a class in use cannot disappear under the workspaces pointing at it —
    -- the admin is shown what references it and moves them first.
    qos_class_id    UUID,
    fairness_weight INTEGER NOT NULL DEFAULT 1
                        CHECK (fairness_weight >= 1 AND fairness_weight <= 100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, qos_class_id) REFERENCES qos_classes(tenant_id, id) ON DELETE RESTRICT
);

-- Each special role is a per-tenant singleton.
CREATE UNIQUE INDEX idx_workspaces_one_default_per_tenant
    ON workspaces (tenant_id) WHERE role = 'default';
CREATE UNIQUE INDEX idx_workspaces_one_agent_per_tenant
    ON workspaces (tenant_id) WHERE role = 'agent';
CREATE UNIQUE INDEX idx_workspaces_one_inline_per_tenant
    ON workspaces (tenant_id) WHERE role = 'inline';
CREATE INDEX idx_workspaces_qos_class ON workspaces (tenant_id, qos_class_id) WHERE qos_class_id IS NOT NULL;

ALTER TABLE workspaces ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspaces FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspaces TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspaces OWNER TO streamscope_app;

-- ── Per-(workspace, kind) profile selection ──────────────────────────────────
-- One row = the workspace's EXPLICIT choice for this domain. Three states:
--   • no row              → inherit the tenant default profile for that kind;
--   • row, profile_id SET → use that profile;
--   • row, profile_id NULL → the kind is explicitly OFF (no policy at all) — e.g.
--     the Agent workspace defaults guardrail to NULL so the agent sees raw PII.
-- A workspace has at most one choice per domain, and a NEW domain slots in with
-- a new `kind` value — no schema change. Deleting a profile drops its
-- assignments, so the workspace transparently falls back to the tenant default.
CREATE TABLE workspace_profile_assignments (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    kind         TEXT NOT NULL,
    profile_id   UUID,  -- NULL = explicit Off
    PRIMARY KEY (tenant_id, workspace_id, kind),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_wpa_profile ON workspace_profile_assignments (tenant_id, profile_id) WHERE profile_id IS NOT NULL;

ALTER TABLE workspace_profile_assignments ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_profile_assignments FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_profile_assignments TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_profile_assignments OWNER TO streamscope_app;

-- ── Expert-profile membership (kind='expert') ────────────────────────────────
-- Which agent experts an expert profile enables — one row per (profile, expert).
-- EVERY expert profile carries explicit rows, the DEFAULT included: the Default
-- is seeded with all enabled experts (the shared base). A Layered profile's
-- effective set = Default's experts ∪ its own rows; a Standalone profile's = its
-- own rows only. A workspace assigned a profile is analyzed by that profile's
-- effective set; an explicit Off assignment runs no expert at all. Consumed
-- admin-side by the analysis cycle only — never shipped to the proxy. To stop
-- an expert everywhere, disable it (agent_experts.enabled = false).
CREATE TABLE expert_profile_members (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL,
    expert_id  UUID NOT NULL,
    PRIMARY KEY (tenant_id, profile_id, expert_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, expert_id) REFERENCES agent_experts(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_epm_expert ON expert_profile_members (tenant_id, expert_id);

ALTER TABLE expert_profile_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE expert_profile_members FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON expert_profile_members TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE expert_profile_members OWNER TO streamscope_app;

-- Per-(expert, profile) analysis watermarks: an expert reachable through several
-- profiles analyzes disjoint workspace partitions (possibly on different models),
-- so one shared cursor would pin or skip across profiles.
CREATE TABLE expert_profile_watermarks (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id        UUID NOT NULL,
    expert_id         UUID NOT NULL,
    last_processed_at TIMESTAMPTZ,
    sessions_analyzed BIGINT NOT NULL DEFAULT 0,
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, profile_id, expert_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, expert_id) REFERENCES agent_experts(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_epw_expert ON expert_profile_watermarks (tenant_id, expert_id);

ALTER TABLE expert_profile_watermarks ENABLE ROW LEVEL SECURITY;
ALTER TABLE expert_profile_watermarks FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON expert_profile_watermarks TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE expert_profile_watermarks OWNER TO streamscope_app;

-- ── Membership ───────────────────────────────────────────────────────────────
CREATE TABLE workspace_members (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    user_id      UUID NOT NULL,
    -- Workspace role plane (distinct from the console `admin_accounts.role`):
    -- `member` (default) or `manager` (manages this workspace's team — view
    -- members + their usage, mint/revoke their workspace keys). "admin" is
    -- reserved for the console plane and is never a workspace role.
    role         TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('member', 'manager')),
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, user_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_workspace_members_user ON workspace_members (tenant_id, user_id);

ALTER TABLE workspace_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_members FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_members TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_members OWNER TO streamscope_app;

-- ── Provider allowlist ───────────────────────────────────────────────────────
CREATE TABLE workspace_downstream_access (
    tenant_id              UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id           UUID NOT NULL,
    downstream_provider_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, downstream_provider_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, downstream_provider_id) REFERENCES downstream_providers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_workspace_downstream_access_provider ON workspace_downstream_access (tenant_id, downstream_provider_id);

ALTER TABLE workspace_downstream_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_downstream_access FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_downstream_access TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_downstream_access OWNER TO streamscope_app;

-- ── Workspace rate/budget ceiling (one row per workspace) ────────────────────
-- A `member_*` value is the workspace's DEFAULT per-member limit: it applies to
-- EVERY member, in the member bucket (keyed by the membership, not the user
-- alone). A row of `workspace_user_rate_limit_overrides` is a member EXCEPTION
-- that replaces the default per metric: a NULL exception column inherits the
-- default for that metric, 0 is explicitly unlimited, a positive value is the
-- member's own limit. The workspace pool, the organisation ceiling and a key's
-- own budget still always apply. NULL `member_*` = no default for that metric;
-- `member_budget_mode` NULL means enforce.
CREATE TABLE workspace_rate_limits (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id        UUID NOT NULL,
    requests_per_minute INTEGER,
    tokens_per_minute   INTEGER,
    daily_budget        DOUBLE PRECISION,
    monthly_budget      DOUBLE PRECISION,
    -- 'enforce' (block over-cap) | 'alert_only' (notify but never block). Covers
    -- both this scope's daily and monthly budgets.
    budget_mode         TEXT NOT NULL DEFAULT 'enforce',
    member_requests_per_minute INTEGER,
    member_tokens_per_minute   INTEGER,
    member_daily_budget        DOUBLE PRECISION,
    member_monthly_budget      DOUBLE PRECISION,
    member_budget_mode         TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE workspace_rate_limits ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_rate_limits FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_rate_limits TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_rate_limits OWNER TO streamscope_app;

-- ── Per-(user, workspace) member exception ──────────────────────────────────
-- `set_via` 'admin' (the console) or 'manager' (a workspace manager in the
-- portal), and their email: who last set the exception. The audit logs hold
-- the full history; this answers "who set this?" on the row the limits page
-- lists.
CREATE TABLE workspace_user_rate_limit_overrides (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id        UUID NOT NULL,
    user_id             UUID NOT NULL,
    requests_per_minute INTEGER,
    tokens_per_minute   INTEGER,
    daily_budget        DOUBLE PRECISION,
    monthly_budget      DOUBLE PRECISION,
    -- 'enforce' (block over-cap) | 'alert_only' (notify but never block). Covers
    -- both this scope's daily and monthly budgets.
    budget_mode         TEXT NOT NULL DEFAULT 'enforce',
    set_via             TEXT,
    set_by_email        TEXT,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, workspace_id, user_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_wurlo_user ON workspace_user_rate_limit_overrides (tenant_id, user_id);

ALTER TABLE workspace_user_rate_limit_overrides ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_user_rate_limit_overrides FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_user_rate_limit_overrides TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_user_rate_limit_overrides OWNER TO streamscope_app;

-- ── API keys — bound to (user, workspace) ────────────────────────────────────
-- One unified key. The route grammar (/v1/* vs /mcp/<slug> vs /fwd/*) implies
-- protocol; auth resolves user + workspace; the workspace allowlist gates the
-- requested target per request. `forward_auth` keys (vk- prefix) forward
-- the client's own upstream credential via /fwd/{key}/...
CREATE TABLE api_keys (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id           UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL,
    user_id      UUID NOT NULL,
    -- Key provenance: who minted this key. NULL = self-service (the owner minted
    -- their own key). Set = a workspace manager minted it on behalf of `user_id`
    -- (the member). Removing the manager keeps the member's key but drops the
    -- dangling provenance.
    minted_by_user_id UUID,
    key_hash     TEXT NOT NULL,
    key_prefix   TEXT,
    name         TEXT,
    forward_auth BOOLEAN NOT NULL DEFAULT false,
    -- Per-key budget ceiling (NULL = no per-key cap; the key inherits only its
    -- workspace + per-user buckets). Enforced as a third "stricter wins" bucket
    -- keyed by the key id. `budget_mode`: 'enforce' (block over-cap) |
    -- 'alert_only' (notify but never block).
    daily_budget       DOUBLE PRECISION,
    monthly_budget     DOUBLE PRECISION,
    budget_mode  TEXT NOT NULL DEFAULT 'enforce',
    expires_at   TIMESTAMPTZ,
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ,
    -- A forward-auth (vk-) key binds to ONE BYOK downstream; NULL = unbound.
    -- Deleting the bound downstream keeps the key row but unbinds it, so the
    -- proxy refuses the key (kept, not revoked) until it is re-granted.
    downstream_provider_id UUID,
    -- The key's own QoS class (NULL = inherit the workspace).
    -- `qos_class_elevated` records that a tenant admin deliberately put the key
    -- ABOVE its workspace's class: it is the only thing that lets a key sit
    -- above its workspace, so demoting a workspace clamps every key that was
    -- not elevated.
    qos_class_id       UUID,
    qos_class_elevated BOOLEAN NOT NULL DEFAULT false,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, minted_by_user_id) REFERENCES users(tenant_id, id) ON DELETE SET NULL (minted_by_user_id),
    FOREIGN KEY (tenant_id, downstream_provider_id) REFERENCES downstream_providers(tenant_id, id) ON DELETE SET NULL (downstream_provider_id),
    FOREIGN KEY (tenant_id, qos_class_id) REFERENCES qos_classes(tenant_id, id) ON DELETE RESTRICT
);

-- Global by design: a key's hash is unique across every tenant.
CREATE UNIQUE INDEX idx_api_keys_hash           ON api_keys (key_hash);
CREATE INDEX        idx_api_keys_user_workspace ON api_keys (tenant_id, user_id, workspace_id);
CREATE INDEX        idx_api_keys_workspace      ON api_keys (tenant_id, workspace_id);
CREATE INDEX        idx_api_keys_minted_by      ON api_keys (tenant_id, minted_by_user_id) WHERE minted_by_user_id IS NOT NULL;
CREATE INDEX        idx_api_keys_downstream     ON api_keys (tenant_id, downstream_provider_id) WHERE downstream_provider_id IS NOT NULL;
CREATE INDEX        idx_api_keys_qos_class      ON api_keys (tenant_id, qos_class_id) WHERE qos_class_id IS NOT NULL;

ALTER TABLE api_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE api_keys FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON api_keys TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE api_keys OWNER TO streamscope_app;

-- Automation keys (`ak-…`) — ONE table for both CONTROL planes. DELIBERATELY a
-- separate table from `api_keys`: these never authenticate to the proxy data
-- plane, and the edge config body never carries this table — an `ak-` key can
-- never be presented to the proxy as a gateway credential. Owned by a
-- service-account `users` row (auth_source='service'). The `plane` column is the
-- authority model:
--   'admin'  → /api/v1/admin/*; authority = `admin_scope`; never workspace-bound.
--   'portal' → /api/v1/portal/*; confined to exactly `workspace_id`, with the
--              owning account's `manager` role there as the authority — no scope.
-- Each auth path MUST filter on its own plane (fail-closed); the CHECK keeps the
-- two shapes structural, not advisory. A key names its tenant by its hash
-- alone (`resolve_automation_key`).
CREATE TABLE automation_keys (
    tenant_id          UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                 UUID NOT NULL DEFAULT gen_random_uuid(),
    -- The owning service account (a non-human `users` row). Deleting the
    -- principal drops its keys.
    service_account_id UUID NOT NULL,
    plane              TEXT NOT NULL,
    -- Admin plane only — manage-right within the admin plane: 'read_only' (safe
    -- methods only) | 'admin' (tenant mutations) | 'super_admin' (SYSTEM-tenant
    -- operator key, cross-tenant + tenant create). Open TEXT (no value CHECK) so
    -- finer scopes stay additive; validated in Rust at write time.
    admin_scope        TEXT,
    -- Portal plane only — the workspace this key is confined to (manager
    -- authority is checked against it per request). Dropping the workspace
    -- drops its keys.
    workspace_id       UUID,
    key_hash           TEXT NOT NULL,
    key_prefix         TEXT,
    name               TEXT,
    expires_at         TIMESTAMPTZ,
    last_used_at       TIMESTAMPTZ,
    revoked_at         TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id, service_account_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    CONSTRAINT automation_keys_plane_shape CHECK (
        (plane = 'admin'  AND admin_scope IS NOT NULL AND workspace_id IS NULL) OR
        (plane = 'portal' AND admin_scope IS NULL     AND workspace_id IS NOT NULL)
    )
);

-- Global by design: the pre-auth key lookup.
CREATE UNIQUE INDEX idx_automation_keys_hash      ON automation_keys (key_hash);
CREATE INDEX        idx_automation_keys_account   ON automation_keys (tenant_id, service_account_id);
CREATE INDEX        idx_automation_keys_workspace ON automation_keys (tenant_id, workspace_id)
    WHERE workspace_id IS NOT NULL;

ALTER TABLE automation_keys ENABLE ROW LEVEL SECURITY;
ALTER TABLE automation_keys FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON automation_keys TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE automation_keys OWNER TO streamscope_app;

-- ============ MCP Core ============
-- MCP gateway core: real upstream servers, virtual server bundles exposed at
-- /mcp/<slug>, route fan-out, per-session state, and the audit child of
-- gateway_audit. Workspace allowlisting of virtual servers lives in
-- workspace_mcp_access.

CREATE TABLE mcp_upstream_servers (
    tenant_id                       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                              UUID NOT NULL DEFAULT gen_random_uuid(),

    name                            TEXT NOT NULL,
    description                     TEXT,
    -- `internal://...` for synthetic gateway-internal upstreams (e.g.
    -- builtin-web). `built_in` distinguishes them in admin UI.
    upstream_url                    TEXT NOT NULL,
    built_in                        BOOLEAN NOT NULL DEFAULT false,

    -- 'stdio' is forward-declared for launching a stdio upstream MCP server as a
    -- subprocess; only HTTP transports (streamable_http / sse) are wired today.
    transport                       TEXT NOT NULL DEFAULT 'streamable_http'
                                        CHECK (transport IN ('streamable_http', 'sse', 'stdio')),

    auth_mode                       TEXT NOT NULL DEFAULT 'no_auth'
                                        CHECK (auth_mode IN ('no_auth', 'service_account', 'per_user_oauth', 'byot')),

    -- AES-256-GCM ciphertext (HKDF-derived key, same as upstream_servers).
    encrypted_credential            BYTEA,

    -- Per-user OAuth — populated when auth_mode='per_user_oauth'.
    oauth_issuer_url                TEXT,
    oauth_client_id                 TEXT,
    encrypted_oauth_client_secret   BYTEA,
    oauth_default_scopes            TEXT[],
    -- Explicit OAuth endpoints (lets operators target IdPs without RFC 8414
    -- metadata + avoids a discovery hop on every connect).
    oauth_authorization_url         TEXT,
    oauth_token_url                 TEXT,
    oauth_revocation_url            TEXT,

    cred_version                    BIGINT NOT NULL DEFAULT 1,

    enabled                         BOOLEAN NOT NULL DEFAULT true,
    connect_timeout_ms              INT NOT NULL DEFAULT 10000,
    request_timeout_ms              INT NOT NULL DEFAULT 60000,

    created_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                      TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, name)
);

CREATE INDEX idx_mcp_upstream_servers_built_in ON mcp_upstream_servers (tenant_id) WHERE built_in;

ALTER TABLE mcp_upstream_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_upstream_servers FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_upstream_servers TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_upstream_servers OWNER TO streamscope_app;

-- Virtual server bundle exposed at /mcp/<slug>.
CREATE TABLE mcp_virtual_servers (
    tenant_id                   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                          UUID NOT NULL DEFAULT gen_random_uuid(),

    -- slug-justified: the `/mcp/<slug>` mount handle — proxy MCP dispatch resolves
    -- it via `virtual_server_by_slug`. Addressed BY it (not a mere label).
    slug                        TEXT NOT NULL,
    name                        TEXT NOT NULL,
    description                 TEXT,

    -- MCP 2025-11-25 serverInfo metadata. display_title is the UI-facing
    -- variant of name (clients fall back to name when null); website_url
    -- rides serverInfo when set. Bounds are belt-and-suspenders alongside
    -- the admin write path so seeders / direct SQL can't bypass them.
    display_title               TEXT
                                    CHECK (display_title IS NULL OR length(display_title) <= 256),
    website_url                 TEXT
                                    CHECK (website_url IS NULL OR (length(website_url) <= 2048 AND website_url ~ '^https?://')),

    enabled                     BOOLEAN NOT NULL DEFAULT true,

    -- Per-VS opt-in to spec-OAuth 2.1 (RFC 9728/8707/8414). When false the
    -- proxy returns plain `-32401` on unauthenticated requests; when true
    -- the 401 carries `WWW-Authenticate: Bearer resource_metadata=...`.
    oauth_enabled               BOOLEAN NOT NULL DEFAULT false,

    -- Sampling intercept toggle. When ON, server-initiated sampling/createMessage
    -- runs through Streamscope's LLM pipeline on the tenant's behalf instead
    -- of being forwarded to the connected agent.
    sampling_intercept_enabled  BOOLEAN NOT NULL DEFAULT false,
    -- AES-256-GCM ciphertext: LLM-family bearer used for the loopback call.
    sampling_credential         BYTEA,
    -- Model alias to request on the synthetic LLM call.
    sampling_model_alias        TEXT,

    created_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at                  TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, slug)
);

-- Global by design: the unauthenticated protected-resource-metadata endpoint is
-- slug-only, so two tenants flipping oauth_enabled=true on the same slug would
-- create an unresolvable lookup.
CREATE UNIQUE INDEX mcp_virtual_servers_oauth_slug_unique
    ON mcp_virtual_servers (slug) WHERE oauth_enabled = true;

ALTER TABLE mcp_virtual_servers ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_virtual_servers FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_virtual_servers TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_virtual_servers OWNER TO streamscope_app;

-- One virtual server may fan out to N real upstreams.
CREATE TABLE mcp_virtual_routes (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    virtual_server_id   UUID NOT NULL,
    upstream_server_id  UUID NOT NULL,

    -- Applied as `<prefix>__<tool|prompt>`. Empty = no prefix (only valid
    -- for single-route virtual servers).
    prefix              TEXT NOT NULL DEFAULT '',

    -- `{ "allow": ["x", "y"], "deny": ["z"] }`. NULL = allow all.
    tools_filter        JSONB,
    resources_filter    JSONB,
    prompts_filter      JSONB,

    enabled             BOOLEAN NOT NULL DEFAULT true,
    position            INT NOT NULL DEFAULT 0,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, virtual_server_id, prefix),
    FOREIGN KEY (tenant_id, virtual_server_id) REFERENCES mcp_virtual_servers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, upstream_server_id) REFERENCES mcp_upstream_servers(tenant_id, id) ON DELETE RESTRICT
);

CREATE INDEX idx_mcp_virtual_routes_virtual  ON mcp_virtual_routes (tenant_id, virtual_server_id, position);
CREATE INDEX idx_mcp_virtual_routes_upstream ON mcp_virtual_routes (tenant_id, upstream_server_id);

ALTER TABLE mcp_virtual_routes ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_virtual_routes FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_virtual_routes TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_virtual_routes OWNER TO streamscope_app;

-- Per-Mcp-Session-Id state. Reverse-routing columns (upstream_server_id,
-- upstream_url) let any proxy replica answer server-initiated reply lookups
-- without a per-process DashMap hit.
CREATE TABLE mcp_sessions (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    session_id          TEXT NOT NULL,

    virtual_server_id   UUID NOT NULL,
    user_id             UUID NOT NULL,
    key_id              UUID,

    client_info         JSONB,
    protocol_version    TEXT NOT NULL,
    -- Merged (ours ∩ each upstream's, filtered by route allow/deny).
    capabilities        JSONB NOT NULL DEFAULT '{}',

    -- Reverse-path pin for server-initiated requests.
    upstream_server_id  UUID,
    upstream_url        TEXT,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, session_id),
    FOREIGN KEY (tenant_id, virtual_server_id) REFERENCES mcp_virtual_servers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, upstream_server_id) REFERENCES mcp_upstream_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_mcp_sessions_tenant_user ON mcp_sessions (tenant_id, user_id, last_seen_at DESC);
CREATE INDEX idx_mcp_sessions_virtual     ON mcp_sessions (tenant_id, virtual_server_id, last_seen_at DESC);
CREATE INDEX idx_mcp_sessions_last_seen   ON mcp_sessions (tenant_id, last_seen_at DESC);
CREATE INDEX idx_mcp_sessions_upstream    ON mcp_sessions (tenant_id, upstream_server_id, last_seen_at DESC);

ALTER TABLE mcp_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_sessions FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_sessions TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_sessions OWNER TO streamscope_app;

-- mcp_audit — child of gateway_audit (kind='mcp').
CREATE TABLE mcp_audit (
    tenant_id           UUID NOT NULL,
    request_id          UUID NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_id, timestamp),
    workspace_id        UUID NOT NULL,

    virtual_server_id   UUID NOT NULL,
    upstream_server_id  UUID,
    mcp_session_id      TEXT,

    method              TEXT NOT NULL,

    tool_id             TEXT,
    prompt_id           TEXT,
    resource_uri        TEXT,

    params              JSONB,
    result              JSONB,

    error_code          INT,
    error_message       TEXT,

    upstream_latency_ms BIGINT NOT NULL DEFAULT 0,
    request_bytes       INT,
    response_bytes      INT,

    protocol_version    TEXT,

    badges              JSONB NOT NULL DEFAULT '[]',
    transform_diff      JSONB NOT NULL DEFAULT '{}',

    FOREIGN KEY (tenant_id, request_id, timestamp)
        REFERENCES gateway_audit (tenant_id, request_id, timestamp)
        ON DELETE CASCADE
) PARTITION BY RANGE (timestamp);

CREATE TABLE mcp_audit_default PARTITION OF mcp_audit DEFAULT;

CREATE INDEX idx_mcp_audit_tenant     ON mcp_audit (tenant_id, timestamp DESC);
CREATE INDEX idx_mcp_audit_virtual    ON mcp_audit (tenant_id, virtual_server_id, timestamp DESC);
CREATE INDEX idx_mcp_audit_upstream   ON mcp_audit (tenant_id, upstream_server_id, timestamp DESC) WHERE upstream_server_id IS NOT NULL;
CREATE INDEX idx_mcp_audit_method     ON mcp_audit (tenant_id, method, timestamp DESC);
CREATE INDEX idx_mcp_audit_tool_id    ON mcp_audit (tenant_id, tool_id, timestamp DESC) WHERE tool_id IS NOT NULL;
CREATE INDEX idx_mcp_audit_session    ON mcp_audit (tenant_id, mcp_session_id, timestamp DESC) WHERE mcp_session_id IS NOT NULL;

ALTER TABLE mcp_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_audit          OWNER TO streamscope_app;
ALTER TABLE mcp_audit_default  OWNER TO streamscope_app;

-- ── MCP virtual-server allowlist ─────────────────────────────────────────────
CREATE TABLE workspace_mcp_access (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id      UUID NOT NULL,
    virtual_server_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, virtual_server_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, virtual_server_id) REFERENCES mcp_virtual_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_workspace_mcp_access_vs ON workspace_mcp_access (tenant_id, virtual_server_id);

ALTER TABLE workspace_mcp_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_mcp_access FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_mcp_access TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_mcp_access OWNER TO streamscope_app;

-- ── Access predicates — the single source of truth for the workspace gate ─────
-- A user reaches a provider / MCP virtual server iff they belong to a workspace
-- whose explicit allowlist grants it. Every workspace — the Default included —
-- gates on its allowlist rows (the Default is a normal workspace; nothing is
-- auto-granted to it). SECURITY INVOKER (the default) keeps RLS in force, so
-- the predicate is tenant-scoped automatically.
CREATE FUNCTION workspace_grants_provider(p_user_id UUID, p_provider_id UUID)
    RETURNS BOOLEAN
    LANGUAGE sql STABLE
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM workspace_members wm
            JOIN workspace_downstream_access wda
              ON wda.tenant_id = wm.tenant_id AND wda.workspace_id = wm.workspace_id
            WHERE wm.user_id = p_user_id
              AND wda.downstream_provider_id = p_provider_id
        )
    $$;

ALTER FUNCTION workspace_grants_provider(UUID, UUID) OWNER TO streamscope_app;

CREATE FUNCTION workspace_grants_mcp(p_user_id UUID, p_virtual_server_id UUID)
    RETURNS BOOLEAN
    LANGUAGE sql STABLE
    AS $$
        SELECT EXISTS (
            SELECT 1 FROM workspace_members wm
            JOIN workspace_mcp_access wma
              ON wma.tenant_id = wm.tenant_id AND wma.workspace_id = wm.workspace_id
            WHERE wm.user_id = p_user_id
              AND wma.virtual_server_id = p_virtual_server_id
        )
    $$;

ALTER FUNCTION workspace_grants_mcp(UUID, UUID) OWNER TO streamscope_app;

-- ============ MCP OAuth ============
-- OAuth storage: per-user upstream MCP credentials, pending authorization
-- flows, the gateway's role as OAuth 2.1 Authorization Server (RFC 9728 /
-- 8707 / 8414), and the surface-discriminated code/token tables shared by
-- every first-party OAuth surface (MCP spec-OAuth, CLI provisioning).

-- Per-(user, upstream) tokens. AES-256-GCM ciphertext using process ENCRYPTION_KEY.
CREATE TABLE mcp_user_credentials (
    tenant_id                UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                       UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id                  UUID NOT NULL,
    upstream_server_id       UUID NOT NULL,

    encrypted_access_token   BYTEA NOT NULL,
    encrypted_refresh_token  BYTEA,
    expires_at               TIMESTAMPTZ,
    scope                    TEXT,

    created_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at               TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at             TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, user_id, upstream_server_id),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, upstream_server_id) REFERENCES mcp_upstream_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_mcp_user_credentials_upstream    ON mcp_user_credentials (tenant_id, upstream_server_id);
CREATE INDEX idx_mcp_user_credentials_expiring    ON mcp_user_credentials (tenant_id, expires_at) WHERE expires_at IS NOT NULL;

ALTER TABLE mcp_user_credentials ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_user_credentials FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_user_credentials TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_user_credentials OWNER TO streamscope_app;

-- Short-lived OAuth flow state (~10 min). Swept by the leader-elected job.
CREATE TABLE mcp_pending_authorizations (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                  UUID NOT NULL DEFAULT gen_random_uuid(),
    user_id             UUID NOT NULL,
    upstream_server_id  UUID NOT NULL,
    virtual_server_id   UUID,

    state               TEXT NOT NULL,
    -- PKCE S256 plaintext verifier. NEVER logged.
    code_verifier       TEXT NOT NULL,
    scope               TEXT,
    redirect_uri        TEXT NOT NULL,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    -- Single-use marker. The callback CLAIMS the row (UPDATE … WHERE
    -- consumed_at IS NULL … RETURNING) before doing anything with it, so two
    -- concurrent callbacks bearing the same `state` cannot both reach the
    -- token endpoint, and a `state` whose exchange FAILED cannot be replayed
    -- for the remainder of its TTL.
    consumed_at         TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, state),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, upstream_server_id) REFERENCES mcp_upstream_servers(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, virtual_server_id) REFERENCES mcp_virtual_servers(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_mcp_pending_authorizations_tenant_user ON mcp_pending_authorizations (tenant_id, user_id);
CREATE INDEX idx_mcp_pending_authorizations_expires     ON mcp_pending_authorizations (tenant_id, expires_at);

ALTER TABLE mcp_pending_authorizations ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_pending_authorizations FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_pending_authorizations TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_pending_authorizations OWNER TO streamscope_app;

-- Registered OAuth clients (manual, RFC 7591 DCR, or CIMD-resolved).
CREATE TABLE mcp_oauth_clients (
    tenant_id               UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                      UUID NOT NULL DEFAULT gen_random_uuid(),

    client_id               TEXT NOT NULL,
    name                    TEXT NOT NULL,
    redirect_uris           JSONB NOT NULL DEFAULT '[]'::jsonb,

    registration_method     TEXT NOT NULL DEFAULT 'manual'
                                CHECK (registration_method IN ('manual', 'dcr', 'cimd')),

    client_id_metadata_url  TEXT,

    created_by_user_id      UUID,
    created_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at              TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, client_id)
);

ALTER TABLE mcp_oauth_clients ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_oauth_clients FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_oauth_clients TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_oauth_clients OWNER TO streamscope_app;

-- Single-use short-TTL authz codes (~60s), shared by every first-party OAuth
-- surface: `surface = 'mcp'` (spec-OAuth, bound to a virtual server) or
-- `surface = 'cli'` (CLI provisioning, portal-plane); `'a2a'` is forward-
-- declared for the A2A gateway, which reuses this per_user_oauth code path. The
-- key's second half is the random opaque code itself. The CHECKs pin the
-- per-surface column shape so a consumer filtering on its own surface can rely
-- on NOT NULL semantics.
CREATE TABLE oauth_authorization_codes (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    code                TEXT NOT NULL,
    surface             TEXT NOT NULL CHECK (surface IN ('mcp', 'cli', 'a2a')),

    client_id           TEXT NOT NULL,
    user_id             UUID NOT NULL,
    -- MCP-only: the virtual server the token is being minted for.
    virtual_server_id   UUID,
    audience            TEXT,
    -- CLI-only: self-reported device label shown on the consent page and in
    -- token listings.
    device_name         TEXT,

    code_challenge      TEXT NOT NULL,
    redirect_uri        TEXT NOT NULL,

    scope               TEXT NOT NULL,

    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,

    consumed_at         TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, code),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE RESTRICT,
    FOREIGN KEY (tenant_id, virtual_server_id) REFERENCES mcp_virtual_servers(tenant_id, id) ON DELETE CASCADE,
    CHECK ((surface = 'mcp') = (virtual_server_id IS NOT NULL)),
    CHECK ((surface = 'mcp') = (audience IS NOT NULL))
);

CREATE INDEX idx_oauth_authorization_codes_expires ON oauth_authorization_codes (tenant_id, expires_at);
CREATE INDEX idx_oauth_authorization_codes_user    ON oauth_authorization_codes (tenant_id, user_id);
CREATE INDEX idx_oauth_authorization_codes_vs      ON oauth_authorization_codes (tenant_id, virtual_server_id) WHERE virtual_server_id IS NOT NULL;

ALTER TABLE oauth_authorization_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_authorization_codes FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_authorization_codes TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE oauth_authorization_codes OWNER TO streamscope_app;

-- Issued JWT tracking (jti + revocation), surface-discriminated like the
-- codes table. Access AND refresh jtis are rows; the JWT `typ` claim (not a
-- column) separates the roles. One revoke/rotate/janitor path serves every
-- surface.
CREATE TABLE oauth_issued_tokens (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    jti                 UUID NOT NULL,
    surface             TEXT NOT NULL CHECK (surface IN ('mcp', 'cli', 'a2a')),

    -- Nullable, and SET NULL rather than RESTRICT: the row must outlive its
    -- subject. The proxy verifies MCP bearers without touching the database, so
    -- what stops a revoked one is the revoked-jti set in the config body —
    -- and that set is DERIVED from surviving rows. Deleting the row would make a
    -- revoked token indistinguishable from one that was never revoked, and
    -- RESTRICT would have made deleting the user fail outright. Keeping the row
    -- also preserves what the token was: its client, scope, audience and
    -- lifetime survive the account it was issued to.
    user_id             UUID,
    client_id           TEXT NOT NULL,
    virtual_server_id   UUID,
    audience            TEXT,
    device_name         TEXT,
    scope               TEXT NOT NULL,

    -- One grant, as a durable identity — on every surface.
    --
    -- A login mints an access/refresh PAIR (two rows), and every refresh
    -- rotation mints a further pair, so "the thing that logged in" is a CHAIN of
    -- rows, not a row. The chain id is stamped at first consent and carried
    -- through every rotation, which is what lets a revoke reach the grant rather
    -- than one row of it: retiring the chain kills the live access token AND
    -- blocks the refresh that would otherwise mint a replacement pair. Without
    -- it a revoke reaches one row of the live pair and the client silently
    -- returns on its next rotation.
    --
    -- It is also what makes RFC 9700 §4.14.2 reuse detection work: a replayed
    -- refresh token must retire the whole lineage, because refusing only the
    -- replayed row leaves the other holder's rotated descendants alive.
    --
    -- NOT NULL on every surface. A row without one is unreachable from a revoke,
    -- and that fails SILENTLY — the operator is told the grant is cut off when it
    -- is not. Enforced here rather than trusted to every writer.
    login_chain         UUID NOT NULL,
    issued_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    -- When the holder last presented this token, stamped on the CLI
    -- provisioning auth path and throttled to roughly one write a minute — the
    -- shape `automation_keys.last_used_at` uses, for the same reason: a CLI
    -- polls, so 59 of every 60 checks must cost a no-op UPDATE, not a write.
    --
    -- Read it as "active around then", never as an exact last-request time, and
    -- NULL as "not seen since this was recorded". The CLI-session listing
    -- aggregates MAX across a login chain rather than reading one row: rotation
    -- mints a new generation, and the machine's last call belongs to the
    -- machine, not to whichever generation was holding its access at the time.
    last_used_at        TIMESTAMPTZ,

    revoked_at          TIMESTAMPTZ,
    revoked_by_user_id  UUID,

    PRIMARY KEY (tenant_id, jti),
    FOREIGN KEY (tenant_id, user_id) REFERENCES users(tenant_id, id) ON DELETE SET NULL (user_id),
    FOREIGN KEY (tenant_id, virtual_server_id) REFERENCES mcp_virtual_servers(tenant_id, id) ON DELETE CASCADE,
    CHECK ((surface = 'mcp') = (virtual_server_id IS NOT NULL)),
    CHECK ((surface = 'mcp') = (audience IS NOT NULL))
);

CREATE INDEX idx_oauth_issued_tokens_user    ON oauth_issued_tokens (tenant_id, user_id, issued_at DESC);
CREATE INDEX idx_oauth_issued_tokens_vs      ON oauth_issued_tokens (tenant_id, virtual_server_id, issued_at DESC);
CREATE INDEX idx_oauth_issued_tokens_expires ON oauth_issued_tokens (tenant_id, expires_at) WHERE revoked_at IS NULL;
-- Serves both chain reads: the per-grant listing and the revoke that retires
-- every row of one chain.
CREATE INDEX idx_oauth_issued_tokens_chain   ON oauth_issued_tokens (tenant_id, login_chain);

ALTER TABLE oauth_issued_tokens ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_issued_tokens FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_issued_tokens TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE oauth_issued_tokens OWNER TO streamscope_app;

-- RFC 8628 device-authorization grant state for the CLI provisioning OAuth
-- surface (`streamscope login --device` — headless/SSH logins where the
-- browser is on another machine). Short-lived rows (~10 min TTL), swept by
-- the leader-elected OAuth housekeeping job.
CREATE TABLE oauth_device_codes (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    -- The device's polling secret: random opaque, carried only by the device
    -- that initiated the flow (over TLS). Never shown to the user.
    device_code         TEXT NOT NULL,

    -- The short human-typeable code (XXXX-XXXX) shown on the device and
    -- entered on the portal approval page.
    user_code           TEXT NOT NULL,

    client_id           TEXT NOT NULL,
    scope               TEXT NOT NULL,
    -- Self-reported device label shown on the approval page.
    device_name         TEXT,

    status              TEXT NOT NULL DEFAULT 'pending'
                            CHECK (status IN ('pending', 'approved', 'denied')),
    -- The portal user who approved — becomes the subject of the minted
    -- token pair. Set if and only if approved.
    approved_user_id    UUID,

    -- Minimum seconds between token-endpoint polls; polling faster gets
    -- `slow_down` (RFC 8628 §3.5).
    poll_interval_secs  INTEGER NOT NULL DEFAULT 5,
    last_polled_at      TIMESTAMPTZ,

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL,
    -- Stamped when the approved code is exchanged for tokens (single-use).
    consumed_at         TIMESTAMPTZ,

    PRIMARY KEY (tenant_id, device_code),
    FOREIGN KEY (tenant_id, approved_user_id) REFERENCES users(tenant_id, id) ON DELETE CASCADE,
    CHECK ((status = 'approved') = (approved_user_id IS NOT NULL)),

    -- The approval page looks codes up by what the user typed.
    UNIQUE (tenant_id, user_code)
);

CREATE INDEX idx_oauth_device_codes_expires ON oauth_device_codes (tenant_id, expires_at);

ALTER TABLE oauth_device_codes ENABLE ROW LEVEL SECURITY;
ALTER TABLE oauth_device_codes FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON oauth_device_codes TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE oauth_device_codes OWNER TO streamscope_app;

-- ============ MCP SSE Events ============
-- Durable replay buffer for MCP `Last-Event-ID` resumption. Persists encoded
-- SSE wire bytes for every server-initiated event flowing through the
-- long-lived GET /mcp/<slug> channel so any proxy replica can replay on
-- reconnect — no proxy↔proxy sync.
--
-- Hourly partitions on `created_at` (not the weekly audit grain), best-effort
-- durability (~1h retention). The long-term record is the corresponding
-- `mcp_audit` row.

CREATE TABLE mcp_sse_events (
    tenant_id          UUID NOT NULL,
    user_id            UUID NOT NULL,
    mcp_session_id     TEXT NOT NULL,
    virtual_server_id  UUID,
    event_id           TEXT NOT NULL,
    sequence           BIGINT NOT NULL,
    event_data         BYTEA NOT NULL,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, mcp_session_id, sequence, created_at)
) PARTITION BY RANGE (created_at);

CREATE TABLE mcp_sse_events_default PARTITION OF mcp_sse_events DEFAULT;

ALTER TABLE mcp_sse_events ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_sse_events FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_sse_events TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_sse_events          OWNER TO streamscope_app;
ALTER TABLE mcp_sse_events_default  OWNER TO streamscope_app;

-- ============ Web Audit ============
-- Built-in web (search + fetch) audit. Sibling of `llm_audit` / `mcp_audit`
-- under the partitioned `gateway_audit` parent (kind='web'). The
-- `parent_request_id` column links a per-call audit row to the orchestrating
-- LLM request that ran the substitution loop (or the inbound MCP tools/call
-- for direct /mcp/web dispatch).

CREATE TABLE web_audit (
    tenant_id            UUID NOT NULL,
    request_id           UUID NOT NULL,
    timestamp            TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_id, timestamp),
    workspace_id         UUID NOT NULL,

    -- Built-in upstream (always the `builtin-web` synthetic
    -- mcp_upstream_servers id for now).
    upstream_server_id   UUID NOT NULL,

    operation            TEXT NOT NULL CHECK (operation IN ('search', 'fetch')),
    -- Configured backend ('searxng' | 'brave' | 'tavily' | 'google_cse' | 'serper').
    backend              TEXT NOT NULL,

    -- search: query string. fetch: post-policy, pre-SSRF URL.
    query                TEXT,

    -- search: post-filter hit count (what the model saw). fetch: 0/1 or NULL.
    result_count         INTEGER,

    bytes_in             BIGINT,
    bytes_out            BIGINT,

    upstream_latency_ms  BIGINT NOT NULL DEFAULT 0,
    upstream_status      INTEGER,

    error_category       TEXT,
    error_detail         TEXT,

    -- 'mcp' (direct /mcp/web), 'substitution' (agent loop), 'admin_test' (operator probe).
    surface              TEXT NOT NULL DEFAULT 'mcp'
                            CHECK (surface IN ('mcp', 'substitution', 'admin_test')),

    url_results          JSONB,
    filter_chain         JSONB,

    request_args         JSONB,
    response_summary     JSONB,
    provider_request     JSONB,
    provider_response    JSONB,
    fetch_content_summary JSONB,

    -- Orchestrating LLM / MCP request id. Powers session-replay drill-down.
    parent_request_id    UUID,
    -- For substitution dispatches: the id of the model tool_use the agent loop
    -- intercepted. Joins this row to the LLM turn's
    -- transform_diff.intercepted_tool_calls + guardrail_steps so the session
    -- view can place + screen the web call. NULL for direct /mcp/web traffic.
    tool_use_id          TEXT,

    badges               JSONB NOT NULL DEFAULT '[]',
    transform_diff       JSONB NOT NULL DEFAULT '{}',

    FOREIGN KEY (tenant_id, request_id, timestamp)
        REFERENCES gateway_audit (tenant_id, request_id, timestamp)
        ON DELETE CASCADE
) PARTITION BY RANGE (timestamp);

CREATE TABLE web_audit_default PARTITION OF web_audit DEFAULT;

CREATE INDEX idx_web_audit_tenant     ON web_audit (tenant_id, timestamp DESC);
CREATE INDEX idx_web_audit_upstream   ON web_audit (tenant_id, upstream_server_id, timestamp DESC);
CREATE INDEX idx_web_audit_operation  ON web_audit (tenant_id, operation, timestamp DESC);
CREATE INDEX idx_web_audit_backend    ON web_audit (tenant_id, backend, timestamp DESC);
CREATE INDEX idx_web_audit_parent_request
    ON web_audit (tenant_id, parent_request_id, timestamp DESC)
    WHERE parent_request_id IS NOT NULL;

ALTER TABLE web_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON web_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE web_audit          OWNER TO streamscope_app;
ALTER TABLE web_audit_default  OWNER TO streamscope_app;

-- ============ A2A (Agent2Agent) gateway ============
-- Registered remote A2A agents exposed at /a2a/<slug>, workspace allowlisting,
-- and the audit child of gateway_audit (kind='a2a').

-- ── Upstream agent registry ──────────────────────────────────────────────────
CREATE TABLE a2a_upstream_agents (
    tenant_id            UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                   UUID NOT NULL DEFAULT gen_random_uuid(),

    name                 TEXT NOT NULL,
    description          TEXT,

    -- slug-justified: the `/a2a/<slug>` mount handle — proxy A2A dispatch and the
    -- pre-auth agent-card endpoint resolve it. Addressed BY it (not a mere label).
    slug                 TEXT NOT NULL,

    -- Upstream JSON-RPC endpoint, derived from the card's JSONRPC/1.0 interface.
    agent_url            TEXT NOT NULL,
    -- Where the agent card was fetched from (the upstream well-known URL).
    card_url             TEXT NOT NULL,
    -- Cached upstream card, raw as fetched (size-capped at registration; the
    -- proxy rewrites it per request — never served verbatim).
    agent_card           JSONB NOT NULL,
    card_fetched_at      TIMESTAMPTZ,

    -- 'per_user_oauth' and 'byot' are future modes; adding a
    -- value widens this CHECK via a new migration on this not-partitioned
    -- table — cheap and additive.
    auth_mode            TEXT NOT NULL DEFAULT 'no_auth'
                             CHECK (auth_mode IN ('no_auth', 'service_account')),

    -- AES-256-GCM ciphertext (HKDF-derived key, same as upstream_servers).
    encrypted_credential BYTEA,
    -- Header carrying the credential upstream. NULL = `Authorization: Bearer`.
    credential_header    TEXT,

    enabled              BOOLEAN NOT NULL DEFAULT true,

    created_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    PRIMARY KEY (tenant_id, id),
    CONSTRAINT chk_a2a_slug_format CHECK (slug ~ '^[a-z0-9]([a-z0-9-]{0,48}[a-z0-9])?$')
);

-- Global by design: the agent-card endpoint is unauthenticated (pre-auth
-- tenant resolution is BY slug alone), so a per-tenant unique key would make
-- two tenants' same-slug mounts unresolvable.
CREATE UNIQUE INDEX idx_a2a_agents_slug_global ON a2a_upstream_agents (slug);

ALTER TABLE a2a_upstream_agents ENABLE ROW LEVEL SECURITY;
ALTER TABLE a2a_upstream_agents FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON a2a_upstream_agents TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE a2a_upstream_agents OWNER TO streamscope_app;

-- ── A2A agent allowlist (workspace access grain) ─────────────────────────────
CREATE TABLE workspace_a2a_access (
    tenant_id    UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    agent_id     UUID NOT NULL,
    PRIMARY KEY (tenant_id, workspace_id, agent_id),
    FOREIGN KEY (tenant_id, workspace_id) REFERENCES workspaces(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, agent_id) REFERENCES a2a_upstream_agents(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_workspace_a2a_access_agent ON workspace_a2a_access (tenant_id, agent_id);

ALTER TABLE workspace_a2a_access ENABLE ROW LEVEL SECURITY;
ALTER TABLE workspace_a2a_access FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON workspace_a2a_access TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE workspace_a2a_access OWNER TO streamscope_app;

-- ── a2a_audit — child of gateway_audit (kind='a2a') ──────────────────────────
CREATE TABLE a2a_audit (
    tenant_id           UUID NOT NULL,
    request_id          UUID NOT NULL,
    timestamp           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, request_id, timestamp),
    workspace_id        UUID NOT NULL,

    agent_id            UUID NOT NULL,

    -- A2A operation name (SendMessage / GetTask / ...), 1.0 vocabulary.
    method              TEXT NOT NULL,

    -- Per-protocol correlators from the wire (the mcp_session_id analog):
    -- contextId groups a multi-task conversation, taskId one unit of work.
    a2a_context_id      TEXT,
    a2a_task_id         TEXT,
    -- Last observed TASK_STATE_* (streaming: the terminal/interrupted state).
    task_state          TEXT,

    params              JSONB,
    result              JSONB,
    -- Streaming calls: accumulated StreamResponse envelopes (bounded; overflow
    -- leaves a truncation marker — never a silent drop).
    stream_events       JSONB,

    error_code          INT,
    error_message       TEXT,

    upstream_latency_ms BIGINT NOT NULL DEFAULT 0,
    request_bytes       INT,
    response_bytes      INT,

    -- Negotiated A2A dialect ('1.0').
    protocol_version    TEXT,

    badges              JSONB NOT NULL DEFAULT '[]',
    transform_diff      JSONB NOT NULL DEFAULT '{}',

    FOREIGN KEY (tenant_id, request_id, timestamp)
        REFERENCES gateway_audit (tenant_id, request_id, timestamp)
        ON DELETE CASCADE
) PARTITION BY RANGE (timestamp);

CREATE TABLE a2a_audit_default PARTITION OF a2a_audit DEFAULT;

CREATE INDEX idx_a2a_audit_tenant     ON a2a_audit (tenant_id, timestamp DESC);
CREATE INDEX idx_a2a_audit_agent      ON a2a_audit (tenant_id, agent_id, timestamp DESC);
CREATE INDEX idx_a2a_audit_method     ON a2a_audit (tenant_id, method, timestamp DESC);
CREATE INDEX idx_a2a_audit_context    ON a2a_audit (tenant_id, a2a_context_id, timestamp DESC) WHERE a2a_context_id IS NOT NULL;
CREATE INDEX idx_a2a_audit_task       ON a2a_audit (tenant_id, a2a_task_id, timestamp DESC) WHERE a2a_task_id IS NOT NULL;

ALTER TABLE a2a_audit ENABLE ROW LEVEL SECURITY;
ALTER TABLE a2a_audit FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON a2a_audit TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE a2a_audit         OWNER TO streamscope_app;
ALTER TABLE a2a_audit_default OWNER TO streamscope_app;

-- ============ Usage Counters ============
-- Fleet-convergent usage counters.
--
-- Edges enforce budgets locally but no single edge sees the fleet's total
-- spend. This pair of tables makes spend converge: each edge reports its own
-- monotonic *cumulative* per counter; admin merges them into a global total
-- here (a grow-only / G-Counter), then pushes the authoritative total back
-- down. Edges enforce against `authoritative_total + their own unreported
-- delta`. The merge is a SUM (budget spend in integer micro-dollars, plus the
-- per-minute request/token rates); the (scope_kind, metric, window_kind) shape
-- generalises to other metrics later.
--
-- `total` is in the unit its `metric` names, and the name carries the unit for
-- exactly that reason: changing the resolution means changing the metric string,
-- so existing rows are left behind rather than silently reinterpreted by a
-- factor. Budget spend is micro-dollars because the counter is whole units and
-- an ordinary request costs a fraction of a cent — at cent resolution such a
-- request rounds to zero and a budget made of them never advances.
--
-- Enforcement is intentionally an estimate, not precise accounting: convergence
-- lags one report and overshoot is bounded by one interval of one edge's
-- spend. This is "slow-track + alert", matching that upstream pricing is itself
-- an estimate.

-- ── usage_counters: the global merged total per counter (tenant-scoped) ───────
CREATE TABLE usage_counters (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    scope_kind    TEXT NOT NULL,          -- 'tenant' | 'workspace' | 'user' | 'key'
    scope_id      UUID NOT NULL,          -- the tenant/workspace/user/key id
    metric        TEXT NOT NULL,          -- 'budget_micros' | 'rpm' | 'tpm'
    window_kind   TEXT NOT NULL,          -- 'minute' | 'daily' | 'monthly'
    window_start  TIMESTAMPTZ NOT NULL,   -- UTC-aligned window start
    total         BIGINT NOT NULL DEFAULT 0,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, scope_kind, scope_id, metric, window_kind, window_start)
);

-- Worst-offender scan for the budget attention tile + window GC by the janitor.
CREATE INDEX idx_usage_counters_window ON usage_counters (tenant_id, window_kind, window_start);

ALTER TABLE usage_counters ENABLE ROW LEVEL SECURITY;
ALTER TABLE usage_counters FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON usage_counters TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE usage_counters OWNER TO streamscope_app;

-- ── usage_counter_watermarks: per-instance last-seen cumulative (idempotent merge) ─
-- intentional: no RLS — edge-keyed convergence bookkeeping written by the global
-- edge-sync path (one row per edge instance × counter), not customer-tenant data.
-- Carries tenant_id only to mirror the counter key, never queried on the tenant
-- surface. Keyed per *proxy process* (`edge_instance_id`): each replica reports
-- its own monotonic cumulative, so N replicas of one logical edge never share a
-- watermark — which would otherwise thrash the restart-rebase and double-count.
-- `process_epoch` is the epoch the watermark was reported under: a watermark of
-- another epoch (or none) is a previous process's, so the new cumulative is
-- all new.
CREATE TABLE usage_counter_watermarks (
    edge_instance_id  UUID NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    tenant_id     UUID NOT NULL,
    scope_kind    TEXT NOT NULL,
    scope_id      UUID NOT NULL,
    metric        TEXT NOT NULL,
    window_kind   TEXT NOT NULL,
    window_start  TIMESTAMPTZ NOT NULL,
    last_seen     BIGINT NOT NULL DEFAULT 0,  -- last cumulative reported by this instance
    process_epoch BIGINT,
    PRIMARY KEY (edge_instance_id, tenant_id, scope_kind, scope_id, metric, window_kind, window_start)
);

ALTER TABLE usage_counter_watermarks OWNER TO streamscope_app;

CREATE INDEX idx_usage_watermarks_window ON usage_counter_watermarks (window_kind, window_start);

-- ============ Notifications ============
-- Generic operator notifications.
--
-- A push layer over the "needs operator attention" signals that otherwise only
-- surface passively as dashboard tiles (budget breach/approach, agent
-- major-session alerts, …). Producers INSERT a row; one leader-elected
-- dispatcher delivers pending rows to the configured channels (operator log
-- today; webhook / email later) and marks them.
--
-- The `UNIQUE (tenant_id, dedup_key)` constraint IS the "fire once per crossing"
-- debounce: a producer encodes the crossing identity into `dedup_key` and
-- INSERTs ON CONFLICT DO NOTHING, so re-evaluating the same condition is a
-- no-op while a genuinely new crossing (next band, next window) is a fresh row.

CREATE TABLE notifications (
    tenant_id      UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id             UUID NOT NULL DEFAULT gen_random_uuid(),
    workspace_id   UUID,                              -- nullable: budget/session carry it; others may not
    kind           TEXT NOT NULL,                     -- 'budget_breach' | 'budget_approaching' | 'session_major_alert'
    severity       SMALLINT NOT NULL,                 -- 0 info | 1 warning | 2 critical
    dedup_key      TEXT NOT NULL,                     -- crossing identity; the "fire once" key
    title          TEXT NOT NULL,
    summary        TEXT NOT NULL,
    target_kind    TEXT,                              -- 'workspace' | 'user' | 'session' | 'api_key' (deep-link)
    target_id      UUID,
    payload        JSONB NOT NULL DEFAULT '{}'::jsonb,
    delivery_state TEXT NOT NULL DEFAULT 'pending',   -- 'pending' | 'delivered' | 'failed'
    attempts       SMALLINT NOT NULL DEFAULT 0,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    delivered_at   TIMESTAMPTZ,
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, dedup_key)
);

-- The dispatcher's `WHERE tenant_id = $1 AND delivery_state = 'pending' ORDER
-- BY created_at` scan; it stays small (only the pending subset).
CREATE INDEX idx_notifications_pending ON notifications (tenant_id, created_at)
    WHERE delivery_state = 'pending';

-- Tenant-scoped feed / GC ordering.
CREATE INDEX idx_notifications_tenant_created ON notifications (tenant_id, created_at DESC);

ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
ALTER TABLE notifications FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON notifications TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE notifications OWNER TO streamscope_app;

-- ============ MCP Catalog ============
-- MCP server catalog: a curated, browsable list of remote MCP servers a tenant
-- admin can adopt in one click.
--
-- A tenant-scoped SEED catalog, mirroring `model_catalog`: every tenant gets
-- the shipped catalog seeded as builtins (`is_builtin = true`); an admin may
-- edit a builtin (which flips it to `is_builtin = false` so seed-sync stops
-- overwriting it) or create their own entries. Deleting a seeded row hides it
-- (`suppressed = true`) so seed-sync skips it and every live read filters it
-- out; any other entry is removed.
--
-- Adopting an entry (handled by the admin API) provisions the real wiring
-- (mcp_upstream_servers + mcp_virtual_servers + mcp_virtual_routes + optional
-- workspace grants); the catalog row itself is only the source metadata.
CREATE TABLE mcp_catalog (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    -- Provenance from the offline seed (e.g. source = 'awesome-remote-mcp-servers',
    -- source_name = the server's stable display name). source_name is the dedupe /
    -- seed-sync key within a tenant.
    source          TEXT,
    source_name     TEXT NOT NULL,
    name            TEXT NOT NULL,
    display_title   TEXT,
    description     TEXT,
    category        TEXT,
    featured        BOOLEAN NOT NULL DEFAULT false,
    website_url     TEXT,
    repository_url  TEXT,
    icon_url        TEXT,
    upstream_url    TEXT NOT NULL,
    transport       TEXT NOT NULL DEFAULT 'streamable_http'
        CHECK (transport IN ('streamable_http', 'sse', 'stdio')),
    auth_mode       TEXT NOT NULL DEFAULT 'no_auth'
        CHECK (auth_mode IN ('no_auth', 'service_account', 'per_user_oauth', 'byot')),
    oauth_issuer_url        TEXT,
    oauth_authorization_url TEXT,
    oauth_token_url         TEXT,
    oauth_revocation_url    TEXT,
    oauth_default_scopes    TEXT[] NOT NULL DEFAULT '{}',
    -- [{ "name": ..., "description": ... }] discovered via tools/list at import time.
    tools           JSONB NOT NULL DEFAULT '[]',
    tool_count      INT,
    -- 'alive' | 'auth_required' | NULL (unknown) as probed at import time.
    liveness        TEXT,
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    -- Soft-delete for a user-removed builtin MCP catalog entry; seed-sync skips it.
    suppressed      BOOLEAN NOT NULL DEFAULT false,
    seeded          BOOLEAN NOT NULL DEFAULT false,
    enabled         BOOLEAN NOT NULL DEFAULT true,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, source_name)
);

CREATE INDEX idx_mcp_catalog_category ON mcp_catalog (tenant_id, category);

ALTER TABLE mcp_catalog ENABLE ROW LEVEL SECURITY;
ALTER TABLE mcp_catalog FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON mcp_catalog TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE mcp_catalog OWNER TO streamscope_app;

-- ============ Normalized Settings Collections ============
-- One row per item per logical settings collection (not a single JSON document
-- in a `system_settings (tenant_id, key)` row). Each write is then a single-row
-- mutation, so concurrent edits to *different* items touch *different* rows and
-- never contend — the lost-update window a whole-document read-modify-write
-- would open cannot exist. The shape mirrors `transform_programs`: tenant_id +
-- RLS + OWNER, a stable natural key the API addresses by, real columns for
-- scalar fields, JSONB only for genuinely-nested structures, and a `suppressed`
-- flag (a deleted seeded row is a soft-deleted row that seed-sync skips and
-- every live read filters out — never a side list).

-- Unified tool-policy rules (LLM + MCP tool/resource/prompt calls). `rule_id` is
-- the stable operator-visible id (e.g. 'ASI02-06'), unique per tenant.
-- Default-as-base model: every rule belongs to a profile; builtins live on the
-- kind's DEFAULT profile (the shared base). A Layered profile's effective set =
-- the Default's rules ∪ its own; a Standalone profile's = its own only. A fork
-- ("Customize here") is a Layered-profile row with its own distinct `rule_id`,
-- its `profile_id`, and `forked_from` pointing at a DEFAULT rule's id — it
-- suppresses that Default rule within the profile. `seq` is the
-- evaluation/display order within a context (a single per-tenant ordering the
-- proxy buckets by profile); it is intentionally NON-unique and gap-spaced so a
-- reorder is a single-row UPDATE, broken by `id` as the deterministic tiebreaker.
CREATE TABLE tool_policy_rules (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                UUID NOT NULL DEFAULT gen_random_uuid(),
    rule_id           TEXT NOT NULL,
    profile_id        UUID NOT NULL,
    seq               BIGINT NOT NULL DEFAULT 0,
    title             TEXT,
    description       TEXT,
    risk              TEXT NOT NULL,
    phase             TEXT NOT NULL,
    scope             TEXT NOT NULL,
    conditions        JSONB NOT NULL DEFAULT '[]',
    action            JSONB NOT NULL,
    priority          INTEGER NOT NULL DEFAULT 100,
    model_filter      TEXT,
    app_filter        TEXT,
    mcp_server_filter TEXT,
    -- A2A rule pivot: matched against the agent slug (the mcp_server_filter
    -- analog). NULL = not an A2A rule.
    a2a_agent_filter  TEXT,
    enabled           BOOLEAN NOT NULL DEFAULT true,
    framework_refs    TEXT[] NOT NULL DEFAULT '{}',
    forked_from       TEXT,
    is_builtin        BOOLEAN NOT NULL DEFAULT false,
    suppressed        BOOLEAN NOT NULL DEFAULT false,
    seeded            BOOLEAN NOT NULL DEFAULT false,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, rule_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE
);

-- Snapshot read: WHERE tenant_id=$1 AND NOT suppressed ORDER BY seq, id — an
-- index-ordered scan with no sort.
CREATE INDEX idx_tool_rules_tenant_seq
    ON tool_policy_rules (tenant_id, seq) WHERE NOT suppressed;
-- FK cascade target (Postgres does not auto-index FK columns).
CREATE INDEX idx_tool_rules_tenant_profile ON tool_policy_rules (tenant_id, profile_id);
-- A shared rule may be forked at most once per profile: the authoritative guard
-- against two concurrent "Customize here".
CREATE UNIQUE INDEX uq_tool_rule_fork_per_profile
    ON tool_policy_rules (tenant_id, profile_id, forked_from)
    WHERE forked_from IS NOT NULL;

ALTER TABLE tool_policy_rules ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_policy_rules FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tool_policy_rules TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE tool_policy_rules OWNER TO streamscope_app;

-- Per-profile guardrail policy (the tenant-wide guardrail *backend* stays a single
-- `system_settings['guardrail']` row; only the per-profile *policy* normalizes).
-- One row per Tools/guardrail profile, created and deleted with the profile —
-- no builtin/suppressed concept. `pii` is the nested PiiSettings struct.
CREATE TABLE guardrail_policies (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    profile_id    UUID NOT NULL,
    enabled       BOOLEAN NOT NULL DEFAULT true,
    mode          TEXT NOT NULL DEFAULT 'observe',
    scan_inbound  BOOLEAN NOT NULL DEFAULT false,
    threshold     REAL NOT NULL DEFAULT 0.9,
    fail_mode     TEXT NOT NULL DEFAULT 'open',
    pii           JSONB NOT NULL DEFAULT '{}',
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, profile_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE guardrail_policies ENABLE ROW LEVEL SECURITY;
ALTER TABLE guardrail_policies FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON guardrail_policies TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE guardrail_policies OWNER TO streamscope_app;

-- CLI client provisioning profiles. `profile_key` is ClientProfile.id (e.g.
-- 'claude-code'). `templates` is the nested Vec<ClientProfileTemplate>.
CREATE TABLE client_profiles (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id              UUID NOT NULL DEFAULT gen_random_uuid(),
    profile_key     TEXT NOT NULL,
    label           TEXT NOT NULL,
    homepage        TEXT NOT NULL DEFAULT '',
    supports_llm    BOOLEAN NOT NULL DEFAULT false,
    supports_mcp    BOOLEAN NOT NULL DEFAULT false,
    launch_command  TEXT,
    templates       JSONB NOT NULL DEFAULT '[]',
    is_builtin      BOOLEAN NOT NULL DEFAULT false,
    suppressed      BOOLEAN NOT NULL DEFAULT false,
    seeded          BOOLEAN NOT NULL DEFAULT false,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, profile_key)
);

ALTER TABLE client_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_profiles FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client_profiles TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE client_profiles OWNER TO streamscope_app;

-- Tool field profiles (canonical arg-field extraction for the tool-policy engine).
-- `profile_key` is FieldProfile.id. All fields are scalar (normalizer is an enum
-- string). `seq` mirrors tool_policy_rules ordering semantics.
CREATE TABLE tool_field_profiles (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    profile_key   TEXT NOT NULL,
    description   TEXT,
    source        TEXT,
    tool_id       TEXT NOT NULL,
    tool_pattern  TEXT NOT NULL,
    app_filter    TEXT,
    mcp_server    TEXT,
    server_type   TEXT,
    field         TEXT NOT NULL,
    wire_field    TEXT,
    normalizer    TEXT NOT NULL,
    priority      INTEGER NOT NULL DEFAULT 100,
    seq           BIGINT NOT NULL DEFAULT 0,
    is_builtin    BOOLEAN NOT NULL DEFAULT false,
    suppressed    BOOLEAN NOT NULL DEFAULT false,
    seeded        BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, profile_key)
);

CREATE INDEX idx_field_profiles_tenant_seq
    ON tool_field_profiles (tenant_id, seq) WHERE NOT suppressed;

ALTER TABLE tool_field_profiles ENABLE ROW LEVEL SECURITY;
ALTER TABLE tool_field_profiles FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON tool_field_profiles TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE tool_field_profiles OWNER TO streamscope_app;

-- Expert prompt snippets appended to an expert's prompt. `snippet_key` is the
-- stable key referenced in `agent_experts.prompt_snippets[]`.
CREATE TABLE prompt_snippets (
    tenant_id     UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id            UUID NOT NULL DEFAULT gen_random_uuid(),
    snippet_key   TEXT NOT NULL,
    label         TEXT NOT NULL,
    content       TEXT NOT NULL,
    is_builtin    BOOLEAN NOT NULL DEFAULT false,
    suppressed    BOOLEAN NOT NULL DEFAULT false,
    seeded        BOOLEAN NOT NULL DEFAULT false,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, snippet_key)
);

ALTER TABLE prompt_snippets ENABLE ROW LEVEL SECURITY;
ALTER TABLE prompt_snippets FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON prompt_snippets TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE prompt_snippets OWNER TO streamscope_app;

-- Client app registry (User-Agent / Referer / system-prompt detection →
-- app_id). `app_key` is AppInfo.id. `prompt_patterns` are substrings of the
-- opening of a request's system prompt, tried only when no header named the
-- app (Goose sends no User-Agent; the Continue CLI sends a generic one).
-- Lowercased and trimmed by the proxy's config fold like the other two lists.
CREATE TABLE apps (
    tenant_id        UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id               UUID NOT NULL DEFAULT gen_random_uuid(),
    app_key          TEXT NOT NULL,
    name             TEXT NOT NULL DEFAULT '',
    description      TEXT NOT NULL DEFAULT '',
    url              TEXT NOT NULL DEFAULT '',
    is_builtin       BOOLEAN NOT NULL DEFAULT false,
    ua_patterns      TEXT[] NOT NULL DEFAULT '{}',
    referer_patterns TEXT[] NOT NULL DEFAULT '{}',
    prompt_patterns  TEXT[] NOT NULL DEFAULT '{}',
    suppressed       BOOLEAN NOT NULL DEFAULT false,
    seeded           BOOLEAN NOT NULL DEFAULT false,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, app_key)
);

ALTER TABLE apps ENABLE ROW LEVEL SECURITY;
ALTER TABLE apps FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON apps TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE apps OWNER TO streamscope_app;

-- ============ Upstream endpoint state ============
-- What the gateways report about each replica endpoint, written by the ingest
-- writer from each instance's state reports.

-- The last breaker state each proxy replica reported for an endpoint: `down`
-- when its circuit breaker took the endpoint out of rotation, `up` when it
-- came back. One row per (endpoint, proxy replica), because each replica runs
-- its own breaker; the server page reads the rows as "down on 1 of 3
-- gateways since …". `changed_at` is when the state began; `reported_at` the
-- last time the replica said so. A replica that is gone takes its rows with it.
CREATE TABLE upstream_endpoint_health (
    tenant_id           UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id         UUID NOT NULL,
    edge_instance_id    UUID NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    status              TEXT NOT NULL CHECK (status IN ('up', 'down')),
    reason              TEXT,
    changed_at          TIMESTAMPTZ NOT NULL,
    reported_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id, edge_instance_id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES upstream_server_endpoints(tenant_id, id) ON DELETE CASCADE
);

-- The cascade from a global edge instance.
CREATE INDEX idx_upstream_endpoint_health_instance ON upstream_endpoint_health (edge_instance_id);

ALTER TABLE upstream_endpoint_health ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_endpoint_health FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_endpoint_health TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_endpoint_health OWNER TO streamscope_app;

-- An endpoint answering that it does not serve a model it was sent — the
-- engine's "model not found". The request moved on to another endpoint; this
-- records that the endpoint was assumed or listed to serve a model it does
-- not, so the server page can flag the mismatch. `reports` counts reports,
-- not requests: a gateway reports one (endpoint, model) at most once per few
-- minutes.
CREATE TABLE upstream_endpoint_mismatches (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id     UUID NOT NULL,
    upstream_model  TEXT NOT NULL,
    reports         BIGINT NOT NULL DEFAULT 1,
    last_seen_at    TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id, upstream_model),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES upstream_server_endpoints(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE upstream_endpoint_mismatches ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_endpoint_mismatches FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_endpoint_mismatches TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_endpoint_mismatches OWNER TO streamscope_app;

-- The live load of each gated endpoint, as one proxy replica saw it at one
-- state report. A reader takes each gauge as it is and never differences it.
--
-- `in_flight` is this replica's own count at the endpoint; the fleet's is the
-- sum over replicas. `gated` says whether `in_flight` is a count: an endpoint
-- read only for its engine metrics is never counted, so its 0 means nothing.
-- `server_held` is what this replica is holding for want of capacity on the
-- endpoint's SERVER, repeated on every endpoint row of that server: a held
-- request waits for the server's pool, not one replica, so a reader takes it
-- once per (replica, server) and never sums it across a server's endpoints;
-- `server_held_by_class` breaks it down the same way: `[{"class_id":
-- uuid|null, "held": n, "held_peak": n}]`. The engine gauges are the engine's own — one
-- engine, read by every replica — so a reader takes the freshest, never a sum.
-- `engine_read` false means this replica does not read that engine (no queue
-- bound); true with NULL gauges means the engine went quiet.
--
-- The engine counters (`engine_preemptions` … `engine_itl_count`) and the
-- learned limit's decision counters (`adaptive_grew`, `adaptive_cut_*`,
-- `adaptive_stepped_down`) are CUMULATIVE: they only rise until the engine or
-- the gateway process restarts; a reader differences consecutive samples of
-- one replica and skips an interval over which one fell. `adaptive_limit` is
-- the limit the replica applied (NULL = not learned, or unbounded while the
-- engine is not heard and no ceiling is set), `adaptive_state` the
-- controller's state, `adaptive_low_load_itl_us` the engine's mean time
-- between tokens, in microseconds, over the intervals in which it ran one or
-- two requests, as the replica learned it. NULL = not published by the engine,
-- or a limit that is not learned.
--
-- The `*_peak` columns are the highest value each gauge reached since the
-- replica's previous report (a burst between two reports is kept rather than
-- lost); `engine_running_queued_peak` is the most running in one engine
-- reading that also had a queue — where the engine is full (NULL when no
-- reading in the interval queued).
--
-- No foreign key on the server or the endpoint: a replica can report one in the
-- instant after it is deleted, and the row is dropped by age like every other.
CREATE TABLE upstream_load_samples (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id                BIGSERIAL NOT NULL,
    edge_instance_id  UUID NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    server_id         UUID NOT NULL,
    endpoint_id       UUID NOT NULL,
    sampled_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    -- The state report that carried it; see `edge_instances.state_beat_id`.
    beat_id           UUID NOT NULL,
    in_flight         INTEGER NOT NULL,
    gated             BOOLEAN NOT NULL,
    server_held       INTEGER NOT NULL,
    server_held_by_class JSONB NOT NULL,
    engine_read       BOOLEAN NOT NULL,
    engine_waiting    INTEGER,
    engine_running    INTEGER,
    engine_kv_usage   DOUBLE PRECISION,
    engine_age_ms     INTEGER,
    engine_preemptions       DOUBLE PRECISION,
    engine_prompt_tokens     DOUBLE PRECISION,
    engine_generation_tokens DOUBLE PRECISION,
    engine_prefix_queries    DOUBLE PRECISION,
    engine_prefix_hits       DOUBLE PRECISION,
    engine_queue_time_sum    DOUBLE PRECISION,
    engine_queue_time_count  DOUBLE PRECISION,
    engine_ttft_sum          DOUBLE PRECISION,
    engine_ttft_count        DOUBLE PRECISION,
    engine_itl_sum           DOUBLE PRECISION,
    engine_itl_count         DOUBLE PRECISION,
    adaptive_limit           INTEGER,
    adaptive_state           TEXT,
    adaptive_low_load_itl_us INTEGER,
    adaptive_grew            BIGINT,
    adaptive_cut_preemption  BIGINT,
    adaptive_cut_kv_full     BIGINT,
    adaptive_stepped_down    BIGINT,
    in_flight_peak           INTEGER NOT NULL,
    server_held_peak         INTEGER NOT NULL,
    engine_waiting_peak      INTEGER,
    engine_running_peak      INTEGER,
    engine_kv_usage_peak     DOUBLE PRECISION,
    engine_running_queued_peak INTEGER,
    PRIMARY KEY (tenant_id, id)
);

CREATE INDEX idx_upstream_load_samples_server ON upstream_load_samples (tenant_id, server_id, sampled_at DESC);
CREATE INDEX idx_upstream_load_samples_time   ON upstream_load_samples (tenant_id, sampled_at);
-- The cascade from a global edge instance.
CREATE INDEX idx_upstream_load_samples_instance ON upstream_load_samples (edge_instance_id);

ALTER TABLE upstream_load_samples ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_load_samples FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_load_samples TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_load_samples OWNER TO streamscope_app;
ALTER SEQUENCE upstream_load_samples_id_seq OWNER TO streamscope_app;

-- Each gateway's stand on each replica endpoint, restated on every state
-- report: it routes there (an attempt within the last few minutes) and whether
-- its breaker holds the endpoint out. This — not the breaker events in
-- `upstream_endpoint_health`, which keep when an outage began and why — is
-- what decides whether a server is down: a stand is current only while it is
-- restated, so a lost or late event, a reconnect or a URL edit is corrected by
-- the next report. A report deletes its gateway's stands on the endpoints of a
-- tenant it no longer states; `stated_at` is the database's time of the write
-- that last restated one, and a stand lapses relative to its gateway's LATEST
-- written report (`edge_instances.state_written_at`), never the wall clock.
-- The ingest writer is the table's only writer.
CREATE TABLE upstream_endpoint_stands (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    endpoint_id       UUID NOT NULL,
    edge_instance_id  UUID NOT NULL REFERENCES edge_instances(id) ON DELETE CASCADE,
    out_of_rotation   BOOLEAN NOT NULL,
    -- The gateway process epoch that stated it (`edge_instances
    -- .epoch_started_at`), matched by equality: a stand counts only for the
    -- process it was stated by, however its write raced a restart.
    session_started_at TIMESTAMPTZ NOT NULL,
    stated_at         TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (tenant_id, endpoint_id, edge_instance_id),
    FOREIGN KEY (tenant_id, endpoint_id) REFERENCES upstream_server_endpoints(tenant_id, id) ON DELETE CASCADE
);

-- The cascade from a global edge instance.
CREATE INDEX idx_upstream_endpoint_stands_instance ON upstream_endpoint_stands (edge_instance_id);

ALTER TABLE upstream_endpoint_stands ENABLE ROW LEVEL SECURITY;
ALTER TABLE upstream_endpoint_stands FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON upstream_endpoint_stands TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE upstream_endpoint_stands OWNER TO streamscope_app;

-- ============ Client Access and Destination Lists ============
-- A destination list is a named set of network destinations (host names,
-- `*.suffix`, addresses, CIDR prefixes, each with ports), validated and
-- canonicalised by the application before it is stored. It means nothing by
-- itself: a consumer attaches it as `allow` or `block` — the sandbox through a
-- client-access profile, the built-in Web tool through `web_destination_lists`.
-- It is not the platform's internal-egress list (`platform_egress`) and never
-- widens it.
--
-- Client access is a profile kind (`profiles.kind = 'client_access'`): which
-- client profiles a workspace is offered (`client_access_members`), the
-- destination lists its sandbox attaches (`client_access_destinations`), and
-- its sandbox settings (`client_access_sandbox`). Every table is keyed by the
-- profile, so a per-workspace profile adds rows, never columns.

-- A seeded collection (`seeded` / `suppressed` + `keep_seeded`, below): a user edit
-- clears `is_builtin`, a delete of a seeded row only hides it. `seed_key` is
-- the seed's stable handle (NULL on a list an admin created).
CREATE TABLE destination_lists (
    tenant_id   UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    id          UUID NOT NULL DEFAULT gen_random_uuid(),
    seed_key    TEXT,
    name        TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    -- The canonical entries, as a JSON array of strings.
    entries     JSONB NOT NULL DEFAULT '[]',
    is_builtin  BOOLEAN NOT NULL DEFAULT false,
    seeded      BOOLEAN NOT NULL DEFAULT false,
    suppressed  BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, id),
    UNIQUE (tenant_id, seed_key)
);

-- A name is unique among the lists an admin sees: a hidden (deleted) seeded
-- list does not hold its name.
CREATE UNIQUE INDEX destination_lists_live_name ON destination_lists (tenant_id, name) WHERE NOT suppressed;

ALTER TABLE destination_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE destination_lists FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON destination_lists TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE destination_lists OWNER TO streamscope_app;

-- The lists the built-in Web tool attaches, each as `allow` (only these pass)
-- or `block` (these never pass).
CREATE TABLE web_destination_lists (
    tenant_id UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    list_id   UUID NOT NULL,
    mode      TEXT NOT NULL CHECK (mode IN ('allow', 'block')),
    PRIMARY KEY (tenant_id, list_id),
    FOREIGN KEY (tenant_id, list_id) REFERENCES destination_lists(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE web_destination_lists ENABLE ROW LEVEL SECURITY;
ALTER TABLE web_destination_lists FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON web_destination_lists TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE web_destination_lists OWNER TO streamscope_app;

-- The client profiles a client-access profile offers: membership is the switch.
CREATE TABLE client_access_members (
    tenant_id         UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id        UUID NOT NULL,
    client_profile_id UUID NOT NULL,
    PRIMARY KEY (tenant_id, profile_id, client_profile_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, client_profile_id) REFERENCES client_profiles(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_cam_client ON client_access_members (tenant_id, client_profile_id);

ALTER TABLE client_access_members ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_access_members FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client_access_members TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE client_access_members OWNER TO streamscope_app;

-- The destination lists a client-access profile's sandbox attaches, each as
-- `allow` or `block` (a block wins).
CREATE TABLE client_access_destinations (
    tenant_id  UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id UUID NOT NULL,
    list_id    UUID NOT NULL,
    mode       TEXT NOT NULL CHECK (mode IN ('allow', 'block')),
    PRIMARY KEY (tenant_id, profile_id, list_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, list_id) REFERENCES destination_lists(tenant_id, id) ON DELETE CASCADE
);

CREATE INDEX idx_cad_list ON client_access_destinations (tenant_id, list_id);

ALTER TABLE client_access_destinations ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_access_destinations FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client_access_destinations TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE client_access_destinations OWNER TO streamscope_app;

-- A client-access profile's sandbox settings, one column each. NULL = the
-- setting's default (on a non-default profile: inherit the Default's).
CREATE TABLE client_access_sandbox (
    tenant_id       UUID NOT NULL REFERENCES tenants(id) ON DELETE CASCADE,
    profile_id      UUID NOT NULL,
    -- Refuse `ssai run --sandbox off`.
    require_sandbox BOOLEAN,
    -- Allow `ssai run --sandbox docker`.
    docker_tier     BOOLEAN,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (tenant_id, profile_id),
    FOREIGN KEY (tenant_id, profile_id) REFERENCES profiles(tenant_id, id) ON DELETE CASCADE
);

ALTER TABLE client_access_sandbox ENABLE ROW LEVEL SECURITY;
ALTER TABLE client_access_sandbox FORCE  ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON client_access_sandbox TO streamscope_app
    USING (tenant_id = current_tenant_id());

ALTER TABLE client_access_sandbox OWNER TO streamscope_app;

-- ============ Seeded rows ============
-- Whether a row came from the seed — independent of `is_builtin`, which an edit
-- clears. A delete reads it alone: a seeded row is hidden (`suppressed`) so seed
-- sync never brings it back, edited or not; only a row that never came from the
-- seed is removed outright. The trigger sets it on every builtin insert and
-- never lets a write clear it, so no write path can lose it.
--
-- Owned by the migration role, like `config_bump`; the triggers bind it by OID.
CREATE FUNCTION keep_seeded() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    -- A builtin came from the seed; once set, no write clears it.
    NEW.seeded := NEW.seeded OR NEW.is_builtin;
    IF TG_OP = 'UPDATE' THEN
        NEW.seeded := NEW.seeded OR OLD.seeded;
    END IF;
    RETURN NEW;
END
$$;

DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['model_catalog', 'mcp_catalog', 'transform_programs', 'agent_experts',
                              'prompt_snippets', 'qos_classes', 'apps', 'client_profiles',
                              'tool_policy_rules', 'tool_field_profiles', 'destination_lists'] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE INSERT OR UPDATE OF is_builtin, seeded ON %I '
            'FOR EACH ROW EXECUTE FUNCTION keep_seeded()', t || '_keep_seeded', t);
    END LOOP;
END $$;

-- ============ Live QoS class references ============
-- A workspace, a key or a route target may point only at a QoS class that is
-- live (not suppressed), checked in the statement that writes the reference.
--
-- The foreign keys refuse a reference to a DELETED class, but a seeded class
-- is hidden (`suppressed`), never deleted, and the foreign key's lock does not
-- conflict with the plain UPDATE that hides it. So a writer that checked the
-- class in a statement of its own, then wrote the reference after a concurrent
-- delete had committed, pointed at a class no read resolves. Here the check
-- takes the class row FOR SHARE: the delete's `SELECT … FOR UPDATE` then
-- either waits for this write and counts it as a reference, or commits first
-- and this write sees the class hidden and is refused.

CREATE FUNCTION qos_class_must_be_live() RETURNS trigger
LANGUAGE plpgsql
SECURITY INVOKER
SET search_path = pg_catalog
AS $$
BEGIN
    IF NEW.qos_class_id IS NULL THEN
        RETURN NEW;
    END IF;
    PERFORM 1 FROM public.qos_classes c
     WHERE c.tenant_id = NEW.tenant_id AND c.id = NEW.qos_class_id AND NOT c.suppressed
       FOR SHARE;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'QoS class % is not a live class of this tenant', NEW.qos_class_id
            USING ERRCODE = 'foreign_key_violation', CONSTRAINT = 'qos_class_live';
    END IF;
    RETURN NEW;
END
$$;

-- Left with the migration role, like the other trigger functions, so that
-- where the migrator is not the runtime role, the runtime role cannot
-- `CREATE OR REPLACE` it into a no-op.

-- Only a write that sets or changes the reference: an unrelated edit of a row
-- whose class is unchanged is not a new reference.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY['workspaces', 'api_keys', 'route_qos_classes'] LOOP
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE INSERT ON %I '
            'FOR EACH ROW EXECUTE FUNCTION qos_class_must_be_live()', t || '_qos_class_live_ins', t);
        EXECUTE format(
            'CREATE TRIGGER %I BEFORE UPDATE OF qos_class_id ON %I '
            'FOR EACH ROW WHEN (NEW.qos_class_id IS DISTINCT FROM OLD.qos_class_id) '
            'EXECUTE FUNCTION qos_class_must_be_live()', t || '_qos_class_live_upd', t);
    END LOOP;
END $$;

-- ============ Config body triggers ============
-- One INSERT, one UPDATE and one DELETE statement trigger per table (Postgres
-- refuses transition tables on a multi-event trigger) plus a TRUNCATE trigger.
-- The array is every table the config body reads; it MUST equal
-- `config_builder::BODY_TABLES` (`lint-config-builder.sh`).
DO $$
DECLARE
    config_body_tables text[] := ARRAY[
        'a2a_upstream_agents',
        'api_keys',
        'apps',
        'cache_presets',
        'destination_lists',
        'downstream_providers',
        'downstream_routes',
        'guardrail_policies',
        'mcp_upstream_servers',
        'mcp_user_credentials',
        'mcp_virtual_routes',
        'mcp_virtual_servers',
        'model_catalog',
        'model_presets',
        'oauth_issued_tokens',
        'platform_egress',
        'platform_setting_overrides',
        'profiles',
        'qos_classes',
        'route_policies',
        'route_qos_classes',
        'system_settings',
        'tenants',
        'tool_field_profiles',
        'tool_policy_rules',
        'transform_programs',
        'upstream_model_endpoints',
        'upstream_models',
        'upstream_server_endpoints',
        'upstream_servers',
        'users',
        'web_destination_lists',
        'workspace_a2a_access',
        'workspace_downstream_access',
        'workspace_mcp_access',
        'workspace_profile_assignments',
        'workspace_rate_limits',
        'workspace_user_rate_limit_overrides',
        'workspaces'
    ];
    t text;
    attribution text;
BEGIN
    FOREACH t IN ARRAY config_body_tables LOOP
        IF t = 'tenants' THEN
            attribution := 'tenants';
        ELSIF EXISTS (
            SELECT 1 FROM information_schema.columns
             WHERE table_schema = 'public' AND table_name = t AND column_name = 'tenant_id'
        ) THEN
            attribution := 'tenant_id';
        ELSE
            attribution := 'global';
        END IF;
        EXECUTE format(
            'CREATE TRIGGER config_bump_ins AFTER INSERT ON %I REFERENCING NEW TABLE AS new_rows '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, attribution);
        EXECUTE format(
            'CREATE TRIGGER config_bump_upd AFTER UPDATE ON %I REFERENCING OLD TABLE AS old_rows NEW TABLE AS new_rows '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, attribution);
        EXECUTE format(
            'CREATE TRIGGER config_bump_del AFTER DELETE ON %I REFERENCING OLD TABLE AS old_rows '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, attribution);
        EXECUTE format(
            'CREATE TRIGGER config_bump_trunc AFTER TRUNCATE ON %I '
            'FOR EACH STATEMENT EXECUTE FUNCTION config_bump(%L)', t, attribution);
    END LOOP;
END
$$;

-- ============ The special roles' reach ============
-- Each special role sees only its own policy on a tenant table (a policy names
-- its role), so no tenant policy carries a `true OR …` variant. Every
-- `USING (true)` policy below names exactly one of `streamscope_ingest` /
-- `streamscope_lookup` (locked by `test_only_the_special_roles_see_across_tenants`).

-- streamscope_global: the global tables only. A tenant table grants it nothing,
-- so a query on one under `Db::global` is `permission denied`, never a silently
-- empty result.
GRANT SELECT, INSERT, UPDATE, DELETE ON
    tenants, edge_nodes, edge_instances, edge_stats_samples, edge_events, edge_instance_events,
    config_bumps, config_bumps_pending, platform_setting_overrides, platform_egress,
    agent_trigger_requests, security_audit, usage_counter_watermarks
    TO streamscope_global;
GRANT SELECT ON schema_epoch TO streamscope_global;
GRANT USAGE ON SEQUENCE edge_stats_samples_id_seq, edge_events_id_seq, config_bumps_id_seq,
    agent_trigger_requests_id_seq
    TO streamscope_global;

-- streamscope_ingest: what the edge ingest writer writes, across the tenants of
-- one request, in one transaction (`edge_v2/writers.rs`): the audit family and
-- its sessions, the conversation stores, the media blobs, the MCP session pins,
-- rotated per-user credentials and header linkage — plus the reads its writes
-- check against (users, the MCP servers). The tenant tables among them carry
-- its policy; the config-bump tables, which a rotated credential's trigger
-- writes, need only the grant.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'gateway_audit', 'llm_audit', 'mcp_audit', 'web_audit', 'a2a_audit', 'mcp_sse_events',
        'conversation_turns', 'conversation_messages', 'tool_definitions', 'system_prompts',
        'turn_history_chunks', 'conversation_session_messages', 'sessions',
        'audit_media_blobs', 'mcp_sessions', 'mcp_user_credentials',
        'cross_session_relations', 'cross_session_relation_members'
    ] LOOP
        EXECUTE format('GRANT SELECT, INSERT, UPDATE, DELETE ON %I TO streamscope_ingest', t);
        EXECUTE format('CREATE POLICY ingest_all ON %I TO streamscope_ingest USING (true) WITH CHECK (true)', t);
    END LOOP;
    FOREACH t IN ARRAY ARRAY['users', 'mcp_virtual_servers', 'mcp_upstream_servers'] LOOP
        EXECUTE format('GRANT SELECT ON %I TO streamscope_ingest', t);
        EXECUTE format('CREATE POLICY ingest_read ON %I FOR SELECT TO streamscope_ingest USING (true)', t);
    END LOOP;
END $$;
GRANT SELECT, INSERT, UPDATE, DELETE ON config_bumps, config_bumps_pending TO streamscope_ingest;
GRANT USAGE ON SEQUENCE config_bumps_id_seq TO streamscope_ingest;

-- streamscope_lookup: what the lookup functions read, across tenants. Only
-- those functions run as it (SECURITY DEFINER, owned by it); no login role is a
-- member it can inherit from, and the runtime role is no member at all.
DO $$
DECLARE
    t TEXT;
BEGIN
    FOREACH t IN ARRAY ARRAY[
        'automation_keys', 'tenant_invites', 'system_settings',
        'sessions', 'conversation_session_messages', 'conversation_messages', 'system_prompts',
        'conversation_turns', 'llm_audit', 'gateway_audit'
    ] LOOP
        EXECUTE format('GRANT SELECT ON %I TO streamscope_lookup', t);
        EXECUTE format('CREATE POLICY lookup_read ON %I FOR SELECT TO streamscope_lookup USING (true)', t);
    END LOOP;
END $$;

-- ============ Lookup functions ============
-- The reads that must cross the tenant boundary, or use an index row-level
-- security makes unusable, each as one SECURITY DEFINER function owned by
-- `streamscope_lookup`:
--   * pre-auth resolution — a credential or invite names its tenant
--     (`resolve_automation_key`, `resolve_invite`), the CORS allowlist and the
--     widest retention window are read across every tenant
--     (`cors_origins_all`, `retention_days_max`). Each returns the minimum
--     columns its caller needs;
--   * search — a trigram GIN index is an index condition only where the policy
--     qual is leakproof, which `tenant_id = current_tenant_id()` is not under
--     FORCE row-level security, so the runtime role's `ILIKE` would scan. The
--     search functions run as the lookup role (whose policy is `true`) and
--     confine themselves to the caller's tenant: each returns NOTHING when the
--     caller has no tenant bound, and only candidate keys; the caller joins
--     them back under its own policy with its filters, order and page.
--
-- Every function pins `search_path` and schema-qualifies its body, EXECUTE is
-- revoked from PUBLIC and granted to the runtime role (and to global for the
-- pre-auth ones), and each is proven against a cross-tenant negative and a
-- positive control in `test_rls_isolation.py`.

-- The trigram indexes only the search functions read (the R4 allowlist,
-- `LOOKUP_ONLY_GIN` in test_schema_shape.py and lint-migrations.sh).
CREATE INDEX idx_lookup_messages_trgm ON conversation_messages USING GIN (tenant_id, (message::text) gin_trgm_ops);
CREATE INDEX idx_lookup_system_prompts_trgm ON system_prompts USING GIN (tenant_id, prompt gin_trgm_ops);
CREATE INDEX idx_lookup_turns_response_trgm ON conversation_turns USING GIN (tenant_id, response_content gin_trgm_ops);
CREATE INDEX idx_lookup_llm_audit_trgm ON llm_audit USING GIN (tenant_id, model_requested gin_trgm_ops, model_used gin_trgm_ops);
CREATE INDEX idx_lookup_gateway_audit_trgm ON gateway_audit USING GIN (tenant_id, user_agent gin_trgm_ops);

-- An automation key's tenant, from its hash alone (the key is unique across
-- tenants). The caller then authenticates it under that tenant's scope.
CREATE FUNCTION resolve_automation_key(p_hash text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT k.tenant_id FROM public.automation_keys k WHERE k.key_hash = p_hash
$$;

-- An invite's tenant, from its token hash alone.
CREATE FUNCTION resolve_invite(p_token_hash text) RETURNS uuid
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT i.tenant_id FROM public.tenant_invites i WHERE i.token_hash = p_token_hash
$$;

-- Every tenant's own `admin_public_url` setting (the raw value: the caller
-- trims it), for the active tenants and the SYSTEM tenant, whose value is the
-- default the others inherit. A tenant with none is absent.
CREATE FUNCTION cors_origins_all() RETURNS TABLE (tenant_id uuid, admin_public_url jsonb)
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT s.tenant_id, s.value
      FROM public.system_settings s
      JOIN public.tenants t ON t.id = s.tenant_id
     WHERE s.key = 'admin_public_url'
       AND (t.is_active OR t.id = '00000000-0000-0000-0000-000000000001'::uuid)
$$;

-- The widest audit retention any tenant configures (NULL when none does): the
-- partition sweep keeps every week the widest tenant still needs. A value that
-- is not a whole number of days in 1..36500 (`retention::RETENTION_DAYS_MAX`) is
-- ignored, as the tenant's own read ignores it.
CREATE FUNCTION retention_days_max() RETURNS bigint
LANGUAGE sql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
    SELECT max(d.days)
      FROM (SELECT CASE WHEN (s.value #>> '{}') ~ '^[0-9]{1,5}$'
                        THEN (s.value #>> '{}')::bigint END AS days
              FROM public.system_settings s
             WHERE s.key = 'retention_days' AND jsonb_typeof(s.value) = 'number') d
     WHERE d.days BETWEEN 1 AND 36500
$$;

-- The search lookups share one contract, and its parameters are a CLOSED set:
-- the text `q` (an ILIKE pattern the caller builds), the window [p_from, p_to)
-- (either bound may be NULL), the direction (`oldest_first`), a keyset cursor
-- (`cursor_ts`, `cursor_id`; both NULL for the first page), the page size `lim`
-- and the access scope (`p_user`, `p_workspaces`; NULL: any). Each returns at
-- most `lim` keys of the caller's tenant, in the asked direction, strictly past
-- the cursor — a tuple, because rows share timestamps. Every other filter, order
-- or rank is the caller's: it joins the keys back under RLS, applies them, and
-- calls again from the last key returned until its page is full; fewer than
-- `lim` keys means the window is exhausted. The scope is applied here, before
-- the cap, so a narrowed caller is never handed a tenant-wide list it filters
-- down to nothing.
--
-- Two passes, so a common term stops early and a rare one never scans: the
-- first `recent` rows of the window past the cursor are checked one by one;
-- only when they give fewer than `lim` do the trigram indexes find the rows
-- beyond them.
--
-- The hits are collected in variables, never in a table: these functions run
-- with the lookup role's rights, and a table the caller could have created
-- first (a temp table with a trigger) would run the caller's code with them.
--
-- Sessions: the session's model and first prompt, the model a turn requested,
-- a turn's response, a message it carried, or a system prompt it used, among
-- sessions whose `updated_at` lies in the window. The key is
-- `(updated_at, session_id)`, and `updated_at` moves with every ingest: a
-- session updated between two calls of one walk moves past the cursor — newest
-- first it jumps above it and that walk does not list it (the next one lists
-- it first), oldest first it can come back again, and the caller dedupes by
-- `session_id`.
CREATE FUNCTION search_sessions(q text, p_from timestamptz, p_to timestamptz, oldest_first boolean,
                                cursor_ts timestamptz, cursor_id uuid, lim int,
                                p_user uuid, p_workspaces uuid[])
RETURNS TABLE (session_id uuid, updated_at timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    t uuid := public.current_tenant_id();
    recent constant int := 2000;
    rec_ids uuid[];
    rec_ts timestamptz[];
    prompt_hits text[];
    hit_ids uuid[];
    hit_ts timestamptz[];
    more_ids uuid[];
    more_ts timestamptz[];
    edge_ts timestamptz;
    edge_id uuid;
BEGIN
    IF t IS NULL OR q IS NULL OR oldest_first IS NULL OR lim <= 0
       OR (cursor_ts IS NULL) <> (cursor_id IS NULL) THEN
        RETURN;
    END IF;

    -- The window's first sessions past the cursor, and the system prompts that
    -- match, each found once. Every arm of the first pass is restricted to
    -- those sessions, so its cost is bounded by `recent` whatever plan it gets.
    IF oldest_first THEN
        SELECT COALESCE(array_agg(r.session_id ORDER BY r.updated_at, r.session_id), '{}'),
               COALESCE(array_agg(r.updated_at ORDER BY r.updated_at, r.session_id), '{}')
          INTO rec_ids, rec_ts
          FROM (SELECT s0.session_id, s0.updated_at
                  FROM public.sessions s0
                 WHERE s0.tenant_id = t
                   AND (p_from IS NULL OR s0.updated_at >= p_from)
                   AND (p_to IS NULL OR s0.updated_at < p_to)
                   AND (cursor_ts IS NULL OR (s0.updated_at >= cursor_ts
                        AND (s0.updated_at, s0.session_id) > (cursor_ts, cursor_id)))
                   AND (p_user IS NULL OR s0.user_id = p_user)
                   AND (p_workspaces IS NULL OR s0.workspace_id = ANY (p_workspaces))
                 ORDER BY s0.updated_at, s0.session_id
                 LIMIT recent) r;
    ELSE
        SELECT COALESCE(array_agg(r.session_id ORDER BY r.updated_at DESC, r.session_id DESC), '{}'),
               COALESCE(array_agg(r.updated_at ORDER BY r.updated_at DESC, r.session_id DESC), '{}')
          INTO rec_ids, rec_ts
          FROM (SELECT s0.session_id, s0.updated_at
                  FROM public.sessions s0
                 WHERE s0.tenant_id = t
                   AND (p_from IS NULL OR s0.updated_at >= p_from)
                   AND (p_to IS NULL OR s0.updated_at < p_to)
                   AND (cursor_ts IS NULL OR (s0.updated_at <= cursor_ts
                        AND (s0.updated_at, s0.session_id) < (cursor_ts, cursor_id)))
                   AND (p_user IS NULL OR s0.user_id = p_user)
                   AND (p_workspaces IS NULL OR s0.workspace_id = ANY (p_workspaces))
                 ORDER BY s0.updated_at DESC, s0.session_id DESC
                 LIMIT recent) r;
    END IF;
    SELECT COALESCE(array_agg(sp.hash), '{}') INTO prompt_hits
      FROM public.system_prompts sp
     WHERE sp.tenant_id = t AND sp.prompt ILIKE q;

    SELECT COALESCE(array_agg(h.sid ORDER BY h.ord), '{}'),
           COALESCE(array_agg(h.ts ORDER BY h.ord), '{}')
      INTO hit_ids, hit_ts
      FROM (SELECT u.sid, u.ts, u.ord
              FROM unnest(rec_ids, rec_ts) WITH ORDINALITY AS u(sid, ts, ord)
             WHERE u.sid IN (
                     SELECT s1.session_id FROM public.sessions s1
                      WHERE s1.tenant_id = t AND s1.session_id = ANY (rec_ids)
                        AND (s1.model_used ILIKE q OR s1.first_user_prompt ILIKE q)
                     UNION
                     SELECT ct.session_id FROM public.conversation_turns ct
                      WHERE ct.tenant_id = t AND ct.session_id = ANY (rec_ids)
                        AND (ct.response_content ILIKE q OR ct.system_prompt_hash = ANY (prompt_hits))
                     UNION
                     SELECT ct.session_id FROM public.conversation_turns ct
                       JOIN public.llm_audit a
                         ON a.tenant_id = t AND a.request_id = ct.request_id AND a.timestamp = ct.timestamp
                      WHERE ct.tenant_id = t AND ct.session_id = ANY (rec_ids)
                        AND a.model_requested ILIKE q
                     UNION
                     SELECT m.session_id FROM public.conversation_session_messages m
                       JOIN public.conversation_messages cm ON cm.tenant_id = t AND cm.hash = m.hash
                      WHERE m.tenant_id = t AND m.session_id = ANY (rec_ids)
                        AND cm.message::text ILIKE q)
             ORDER BY u.ord
             LIMIT lim) h;

    -- Fewer than `recent` sessions past the cursor: the first pass read them all.
    IF cardinality(hit_ids) < lim AND cardinality(rec_ids) = recent THEN
        edge_ts := rec_ts[recent];
        edge_id := rec_ids[recent];
        -- Two plain orders, so the second pass walks the (tenant_id, updated_at)
        -- index and stops at its limit.
        IF oldest_first THEN
            SELECT COALESCE(array_agg(h.sid ORDER BY h.ts, h.sid), '{}'),
                   COALESCE(array_agg(h.ts ORDER BY h.ts, h.sid), '{}')
              INTO more_ids, more_ts
              FROM (SELECT s.session_id AS sid, s.updated_at AS ts
                      FROM public.sessions s
                     WHERE s.tenant_id = t
                       AND s.updated_at >= edge_ts
                       AND (p_to IS NULL OR s.updated_at < p_to)
                       AND (s.updated_at, s.session_id) > (edge_ts, edge_id)
                       AND (p_user IS NULL OR s.user_id = p_user)
                       AND (p_workspaces IS NULL OR s.workspace_id = ANY (p_workspaces))
                       AND s.session_id IN (
                             SELECT s1.session_id FROM public.sessions s1
                              WHERE s1.tenant_id = t AND (s1.model_used ILIKE q OR s1.first_user_prompt ILIKE q)
                             UNION
                             SELECT ct.session_id FROM public.conversation_turns ct
                              WHERE ct.tenant_id = t AND ct.response_content ILIKE q AND ct.session_id IS NOT NULL
                             UNION
                             SELECT ct.session_id FROM public.llm_audit a
                               JOIN public.conversation_turns ct
                                 ON ct.tenant_id = t AND ct.request_id = a.request_id AND ct.timestamp = a.timestamp
                              WHERE a.tenant_id = t AND a.model_requested ILIKE q AND ct.session_id IS NOT NULL
                             UNION
                             SELECT m.session_id FROM public.conversation_session_messages m
                              WHERE m.tenant_id = t AND m.hash IN (
                                    SELECT cm.hash FROM public.conversation_messages cm
                                     WHERE cm.tenant_id = t AND cm.message::text ILIKE q)
                             UNION
                             SELECT ct.session_id FROM public.conversation_turns ct
                              WHERE ct.tenant_id = t AND ct.session_id IS NOT NULL
                                AND ct.system_prompt_hash = ANY (prompt_hits))
                     ORDER BY s.updated_at, s.session_id
                     LIMIT lim - cardinality(hit_ids)) h;
        ELSE
            SELECT COALESCE(array_agg(h.sid ORDER BY h.ts DESC, h.sid DESC), '{}'),
                   COALESCE(array_agg(h.ts ORDER BY h.ts DESC, h.sid DESC), '{}')
              INTO more_ids, more_ts
              FROM (SELECT s.session_id AS sid, s.updated_at AS ts
                      FROM public.sessions s
                     WHERE s.tenant_id = t
                       AND (p_from IS NULL OR s.updated_at >= p_from)
                       AND s.updated_at <= edge_ts
                       AND (s.updated_at, s.session_id) < (edge_ts, edge_id)
                       AND (p_user IS NULL OR s.user_id = p_user)
                       AND (p_workspaces IS NULL OR s.workspace_id = ANY (p_workspaces))
                       AND s.session_id IN (
                             SELECT s1.session_id FROM public.sessions s1
                              WHERE s1.tenant_id = t AND (s1.model_used ILIKE q OR s1.first_user_prompt ILIKE q)
                             UNION
                             SELECT ct.session_id FROM public.conversation_turns ct
                              WHERE ct.tenant_id = t AND ct.response_content ILIKE q AND ct.session_id IS NOT NULL
                             UNION
                             SELECT ct.session_id FROM public.llm_audit a
                               JOIN public.conversation_turns ct
                                 ON ct.tenant_id = t AND ct.request_id = a.request_id AND ct.timestamp = a.timestamp
                              WHERE a.tenant_id = t AND a.model_requested ILIKE q AND ct.session_id IS NOT NULL
                             UNION
                             SELECT m.session_id FROM public.conversation_session_messages m
                              WHERE m.tenant_id = t AND m.hash IN (
                                    SELECT cm.hash FROM public.conversation_messages cm
                                     WHERE cm.tenant_id = t AND cm.message::text ILIKE q)
                             UNION
                             SELECT ct.session_id FROM public.conversation_turns ct
                              WHERE ct.tenant_id = t AND ct.session_id IS NOT NULL
                                AND ct.system_prompt_hash = ANY (prompt_hits))
                     ORDER BY s.updated_at DESC, s.session_id DESC
                     LIMIT lim - cardinality(hit_ids)) h;
        END IF;
        hit_ids := hit_ids || more_ids;
        hit_ts := hit_ts || more_ts;
    END IF;

    RETURN QUERY SELECT u.sid, u.ts FROM unnest(hit_ids, hit_ts) WITH ORDINALITY AS u(sid, ts, ord)
                  ORDER BY u.ord LIMIT lim;
END
$$;

-- LLM audit rows matching `q`: the requested or used model, the client's user
-- agent, or a message the request ADDED to its session (`added_from` onwards —
-- the history before it was matched on the turn that added it), keyed
-- `(timestamp, request_id)`; the contract of `search_sessions` above. A turn's
-- added messages are read by `turn_added_hashes_walk`, which walks only the
-- chunks they lie in, never the turn's whole history.
--
-- The matching messages, and the sessions that carried one, are found first,
-- once per call, through the trigram index: a turn's added messages are read
-- only when its session carried a match, and the first pass reads its rows' audit
-- parent and turn by key, so its cost is bounded by `recent`, never by the
-- tenant's turns. A term matching more than `common_at` messages is COMMON and
-- builds no such set: each candidate turn's added messages are checked
-- directly instead — in the second pass that walks every turn beyond the first
-- `recent`, the price of a common term searched that deep. Each call of a walk
-- classifies the term again (the class is not a parameter: the set is closed).
CREATE FUNCTION search_llm_audit(q text, p_from timestamptz, p_to timestamptz, oldest_first boolean,
                                 cursor_ts timestamptz, cursor_id uuid, lim int,
                                 p_user uuid, p_workspaces uuid[])
RETURNS TABLE (request_id uuid, "timestamp" timestamptz)
LANGUAGE plpgsql STABLE SECURITY DEFINER
SET search_path = pg_catalog, pg_temp
AS $$
DECLARE
    t uuid := public.current_tenant_id();
    recent constant int := 5000;
    common_at constant int := 50000;
    is_common boolean;
    msg_hits text[];
    msg_sessions uuid[];
    rec_ids uuid[];
    rec_ts timestamptz[];
    rec_ua text[];
    hit_ids uuid[];
    hit_ts timestamptz[];
    more_ids uuid[];
    more_ts timestamptz[];
    edge_ts timestamptz;
    edge_id uuid;
BEGIN
    IF t IS NULL OR q IS NULL OR oldest_first IS NULL OR lim <= 0
       OR (cursor_ts IS NULL) <> (cursor_id IS NULL) THEN
        RETURN;
    END IF;

    SELECT COALESCE(array_agg(m.hash), '{}') INTO msg_hits
      FROM (SELECT cm.hash FROM public.conversation_messages cm
             WHERE cm.tenant_id = t AND cm.message::text ILIKE q
             LIMIT common_at + 1) m;
    is_common := cardinality(msg_hits) > common_at;
    IF is_common THEN
        msg_hits := '{}';
    END IF;
    SELECT COALESCE(array_agg(DISTINCT m.session_id), '{}') INTO msg_sessions
      FROM public.conversation_session_messages m
     WHERE m.tenant_id = t AND m.hash IN (SELECT unnest(msg_hits));

    IF oldest_first THEN
        SELECT COALESCE(array_agg(r.request_id ORDER BY r.timestamp, r.request_id), '{}'),
               COALESCE(array_agg(r.timestamp ORDER BY r.timestamp, r.request_id), '{}'),
               COALESCE(array_agg(r.user_agent ORDER BY r.timestamp, r.request_id), '{}')
          INTO rec_ids, rec_ts, rec_ua
          FROM (SELECT g0.request_id, g0.timestamp, g0.user_agent
                  FROM public.gateway_audit g0
                 WHERE g0.tenant_id = t AND g0.kind = 'llm'
                   AND (p_from IS NULL OR g0.timestamp >= p_from)
                   AND (p_to IS NULL OR g0.timestamp < p_to)
                   AND (cursor_ts IS NULL OR (g0.timestamp >= cursor_ts
                        AND (g0.timestamp, g0.request_id) > (cursor_ts, cursor_id)))
                   AND (p_user IS NULL OR g0.user_id = p_user)
                   AND (p_workspaces IS NULL OR g0.workspace_id = ANY (p_workspaces))
                 ORDER BY g0.timestamp, g0.request_id
                 LIMIT recent) r;
    ELSE
        SELECT COALESCE(array_agg(r.request_id ORDER BY r.timestamp DESC, r.request_id DESC), '{}'),
               COALESCE(array_agg(r.timestamp ORDER BY r.timestamp DESC, r.request_id DESC), '{}'),
               COALESCE(array_agg(r.user_agent ORDER BY r.timestamp DESC, r.request_id DESC), '{}')
          INTO rec_ids, rec_ts, rec_ua
          FROM (SELECT g0.request_id, g0.timestamp, g0.user_agent
                  FROM public.gateway_audit g0
                 WHERE g0.tenant_id = t AND g0.kind = 'llm'
                   AND (p_from IS NULL OR g0.timestamp >= p_from)
                   AND (p_to IS NULL OR g0.timestamp < p_to)
                   AND (cursor_ts IS NULL OR (g0.timestamp <= cursor_ts
                        AND (g0.timestamp, g0.request_id) < (cursor_ts, cursor_id)))
                   AND (p_user IS NULL OR g0.user_id = p_user)
                   AND (p_workspaces IS NULL OR g0.workspace_id = ANY (p_workspaces))
                 ORDER BY g0.timestamp DESC, g0.request_id DESC
                 LIMIT recent) r;
    END IF;

    SELECT COALESCE(array_agg(h.rid ORDER BY h.ord), '{}'),
           COALESCE(array_agg(h.ts ORDER BY h.ord), '{}')
      INTO hit_ids, hit_ts
      FROM (SELECT u.rid, u.ts, u.ord
              FROM unnest(rec_ids, rec_ts, rec_ua) WITH ORDINALITY AS u(rid, ts, ua, ord)
              JOIN public.llm_audit a
                ON a.tenant_id = t AND a.request_id = u.rid AND a.timestamp = u.ts
              LEFT JOIN public.conversation_turns ct
                ON ct.tenant_id = t AND ct.request_id = u.rid AND ct.timestamp = u.ts
             WHERE a.model_requested ILIKE q OR a.model_used ILIKE q OR u.ua ILIKE q
                -- A turn of no session has no membership to find it through:
                -- its added messages are checked directly, as for a common term.
                OR CASE WHEN is_common OR ct.session_id IS NULL
                        THEN EXISTS (SELECT 1 FROM unnest(public.turn_added_hashes_walk(t, ct.history_head, ct.added_from, ct.message_count)) AS x(hash)
                                       JOIN public.conversation_messages cm ON cm.tenant_id = t AND cm.hash = x.hash
                                      WHERE cm.message::text ILIKE q)
                        WHEN ct.session_id IN (SELECT unnest(msg_sessions))
                        THEN EXISTS (SELECT 1 FROM unnest(public.turn_added_hashes_walk(t, ct.history_head, ct.added_from, ct.message_count)) AS x(hash)
                                      WHERE x.hash IN (SELECT unnest(msg_hits)))
                        ELSE false END
             ORDER BY u.ord
             LIMIT lim) h;

    -- Fewer than `recent` rows past the cursor: the first pass read them all.
    -- The arms below are bounded by the edge's timestamp (each arm's own index
    -- and partition pruning); the exact tuple bound applies after the union.
    IF cardinality(hit_ids) < lim AND cardinality(rec_ids) = recent THEN
        edge_ts := rec_ts[recent];
        edge_id := rec_ids[recent];
        SELECT COALESCE(array_agg(h.rid ORDER BY h.k1, h.k2, h.k3 DESC, h.k4 DESC), '{}'),
               COALESCE(array_agg(h.ts ORDER BY h.k1, h.k2, h.k3 DESC, h.k4 DESC), '{}')
          INTO more_ids, more_ts
          FROM (SELECT c.rid, c.ts,
                       CASE WHEN oldest_first THEN c.ts END AS k1,
                       CASE WHEN oldest_first THEN c.rid END AS k2,
                       CASE WHEN NOT oldest_first THEN c.ts END AS k3,
                       CASE WHEN NOT oldest_first THEN c.rid END AS k4
                  FROM (
                    SELECT a.request_id AS rid, a.timestamp AS ts FROM public.llm_audit a
                     WHERE a.tenant_id = t
                       AND a.timestamp >= COALESCE(CASE WHEN oldest_first THEN edge_ts END, p_from, '-infinity')
                       AND a.timestamp <= COALESCE(CASE WHEN NOT oldest_first THEN edge_ts END, 'infinity')
                       AND (p_to IS NULL OR a.timestamp < p_to)
                       AND (a.model_requested ILIKE q OR a.model_used ILIKE q)
                    UNION
                    SELECT g.request_id, g.timestamp FROM public.gateway_audit g
                     WHERE g.tenant_id = t AND g.kind = 'llm'
                       AND g.timestamp >= COALESCE(CASE WHEN oldest_first THEN edge_ts END, p_from, '-infinity')
                       AND g.timestamp <= COALESCE(CASE WHEN NOT oldest_first THEN edge_ts END, 'infinity')
                       AND (p_to IS NULL OR g.timestamp < p_to)
                       AND g.user_agent ILIKE q
                    UNION
                    SELECT ct.request_id, ct.timestamp FROM public.conversation_turns ct
                     WHERE ct.tenant_id = t
                       AND ct.timestamp >= COALESCE(CASE WHEN oldest_first THEN edge_ts END, p_from, '-infinity')
                       AND ct.timestamp <= COALESCE(CASE WHEN NOT oldest_first THEN edge_ts END, 'infinity')
                       AND (p_to IS NULL OR ct.timestamp < p_to)
                       AND CASE WHEN is_common OR ct.session_id IS NULL
                                THEN EXISTS (SELECT 1 FROM unnest(public.turn_added_hashes_walk(t, ct.history_head, ct.added_from, ct.message_count)) AS x(hash)
                                               JOIN public.conversation_messages cm ON cm.tenant_id = t AND cm.hash = x.hash
                                              WHERE cm.message::text ILIKE q)
                                ELSE ct.session_id IN (SELECT unnest(msg_sessions))
                                     AND EXISTS (SELECT 1 FROM unnest(public.turn_added_hashes_walk(t, ct.history_head, ct.added_from, ct.message_count)) AS x(hash)
                                                  WHERE x.hash IN (SELECT unnest(msg_hits))) END
                ) c
                JOIN public.gateway_audit g
                  ON g.tenant_id = t AND g.request_id = c.rid AND g.timestamp = c.ts
                WHERE CASE WHEN oldest_first
                           THEN (c.ts, c.rid) > (edge_ts, edge_id)
                           ELSE (c.ts, c.rid) < (edge_ts, edge_id) END
                  AND (p_user IS NULL OR g.user_id = p_user)
                  AND (p_workspaces IS NULL OR g.workspace_id = ANY (p_workspaces))
                ORDER BY k1, k2, k3 DESC, k4 DESC
                LIMIT lim - cardinality(hit_ids)) h;
        hit_ids := hit_ids || more_ids;
        hit_ts := hit_ts || more_ts;
    END IF;

    RETURN QUERY SELECT u.rid, u.ts
                   FROM unnest(hit_ids, hit_ts) WITH ORDINALITY AS u(rid, ts, ord)
                  ORDER BY u.ord LIMIT lim;
END
$$;

GRANT SELECT ON turn_history_chunks TO streamscope_lookup;
CREATE POLICY lookup_read ON turn_history_chunks FOR SELECT TO streamscope_lookup USING (true);

DO $$
DECLARE
    f TEXT;
BEGIN
    FOREACH f IN ARRAY ARRAY[
        'resolve_automation_key(text)', 'resolve_invite(text)', 'cors_origins_all()',
        'retention_days_max()', 'search_sessions(text,timestamptz,timestamptz,boolean,timestamptz,uuid,integer,uuid,uuid[])',
        'search_llm_audit(text,timestamptz,timestamptz,boolean,timestamptz,uuid,integer,uuid,uuid[])'
    ] LOOP
        EXECUTE format('ALTER FUNCTION %s OWNER TO streamscope_lookup', f);
        EXECUTE format('REVOKE EXECUTE ON FUNCTION %s FROM PUBLIC', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'search_sessions(text,timestamptz,timestamptz,boolean,timestamptz,uuid,integer,uuid,uuid[])',
        'search_llm_audit(text,timestamptz,timestamptz,boolean,timestamptz,uuid,integer,uuid,uuid[])'
    ] LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO streamscope_app', f);
    END LOOP;
    FOREACH f IN ARRAY ARRAY[
        'resolve_automation_key(text)', 'resolve_invite(text)', 'cors_origins_all()', 'retention_days_max()'
    ] LOOP
        EXECUTE format('GRANT EXECUTE ON FUNCTION %s TO streamscope_app, streamscope_global', f);
    END LOOP;
END $$;
