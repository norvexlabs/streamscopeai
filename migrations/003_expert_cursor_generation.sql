-- A restart of an expert profile's analysis moves its cursors while a cycle may
-- be running. Each restart bumps this counter, and a cycle's advance applies only
-- while the counter it read still stands, so the cycle cannot undo the restart.

-- migration-lint: allow cross_migration, an additive column with a DEFAULT on expert_profile_watermarks (001) — the previous release neither reads it nor names it in a write
ALTER TABLE expert_profile_watermarks
    ADD COLUMN cursor_generation BIGINT NOT NULL DEFAULT 0;

-- An expert reading both single sessions and clusters keeps one position per path,
-- so neither passes what the other has yet to analyze. This is the cluster path's;
-- NULL for an expert reading one path, whose position is last_processed_at.

-- migration-lint: allow cross_migration, an additive nullable column on expert_profile_watermarks (001) — the previous release neither reads it nor names it in a write
ALTER TABLE expert_profile_watermarks
    ADD COLUMN cluster_processed_at TIMESTAMPTZ;
