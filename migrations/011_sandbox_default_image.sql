-- A Portal & clients profile's default for the container sandbox: the image a
-- project with no `.streamscopeai/sandbox.json` runs in, whether it has a
-- Docker engine inside, and its memory and CPU limits. NULL image = no
-- default (such a project is refused); the other three are set only beside
-- an image. The CHECKs hold the rules the API and the CLI apply
-- (an image reference from a registry, a podman size, a CPU count).

-- A metadata-only change, but it needs the table's exclusive lock: give up
-- rather than queue behind a long transaction. A failed migration rolls back
-- whole and the previous release still fits the database.
SET LOCAL lock_timeout = '15s';

-- migration-lint: allow cross_migration, additive nullable columns on client_access_sandbox (001) — the previous release neither reads them nor names them in a write, and keeps refusing a project without sandbox.json
ALTER TABLE client_access_sandbox
    ADD COLUMN default_image TEXT
        CHECK (length(default_image) BETWEEN 1 AND 512
               AND default_image !~ '[[:space:][:cntrl:]]'
               AND default_image !~ '^-'
               AND default_image !~ '^(docker://)?(dir|oci|oci-archive|docker-archive|containers-storage|docker-daemon|sif|tarball|ostree):'),
    ADD COLUMN default_docker BOOLEAN,
    ADD COLUMN default_memory TEXT CHECK (default_memory ~ '^[0-9]{1,18}[bkmgBKMG]?$'),
    ADD COLUMN default_cpus DOUBLE PRECISION CHECK (default_cpus > 0 AND default_cpus <= 1024),
    ADD CONSTRAINT client_access_sandbox_default_needs_image
        CHECK (default_image IS NOT NULL OR (default_docker IS NULL AND default_memory IS NULL AND default_cpus IS NULL));
