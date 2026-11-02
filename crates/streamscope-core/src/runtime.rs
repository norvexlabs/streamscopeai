//! Canonical Tokio runtime sizing, shared by the proxy and admin-api binaries.
//!
//! Tokio's multi-thread runtime defaults its worker-thread pool to the host
//! core count (`available_parallelism()`) and is **not** cgroup-aware, so inside
//! a container it spawns one worker per *host* core regardless of the CPU the
//! orchestrator actually granted. Both binaries build their runtime through this
//! module instead, so the pool is sized by one canonical policy:
//!
//! - **Isolated host** — a cgroup CPU quota is present (e.g. a Kubernetes pod
//!   with a CPU limit): size to the quota; the orchestrator already partitioned
//!   CPU, so the role does not matter.
//! - **Shared host** — no quota (the VM appliance, or a Kubernetes pod with no
//!   CPU limit): the data plane (proxy) takes the majority (`total − reserve`)
//!   and the control plane (admin-api) takes the reserve (`≈total/4`). The split
//!   sums to `total`, so the two runtimes never oversubscribe the box, and the
//!   control plane keeps enough threads to drive config sync + audit ingestion
//!   under load. Postgres (a separate process we cannot size) shares CPU with the
//!   control plane via the OS scheduler — both are IO/DB-bound and bursty — and
//!   the proxy is capped at `total − reserve`, so the hot path never monopolizes
//!   the host: whenever the proxy parks on upstream IO (most of its time, being a
//!   gateway) those cores serve postgres.
//!
//! Overrides (read once at boot via [`crate::settings`]):
//! - `WORKER_THREADS` (>0) replaces the resolved count outright.
//! - `CONTROL_PLANE_CPU_RESERVE` (>0) replaces the shared-host reserve.

use crate::settings::core_settings;

/// Which plane this process serves — selects the shared-host CPU policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The proxy: the hot request path. Gets the majority of cores on a shared
    /// host (`total − reserve`).
    DataPlane,
    /// The admin-api: control plane. Gets the reserve (`≈total/4`) on a shared
    /// host — enough to drive config sync + audit ingestion, while leaving the
    /// data plane the majority and never oversubscribing the box.
    ControlPlane,
}

/// How the worker-thread count was decided — surfaced in the startup log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Source {
    Override,
    CgroupQuota,
    SharedHost,
}

impl Source {
    fn as_str(self) -> &'static str {
        match self {
            Source::Override => "override",
            Source::CgroupQuota => "cgroup-quota",
            Source::SharedHost => "shared-host",
        }
    }
}

/// Host logical-CPU count, clamped to at least 1.
fn available() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

/// Pure policy — the single source of truth, exercised directly by the tests.
///
/// `override_threads` / `reserve_override` are `0` when unset.
fn resolve(
    role: Role,
    override_threads: usize,
    quota_cpus: Option<usize>,
    total: usize,
    reserve_override: usize,
) -> (usize, Source) {
    if override_threads > 0 {
        return (override_threads, Source::Override);
    }
    if let Some(quota) = quota_cpus {
        return (quota.max(1), Source::CgroupQuota);
    }

    // Shared host: the proxy takes the majority, the control plane takes the
    // reserve. The split sums to `total` (no oversubscription); the reserve is
    // never the whole box, so the data plane always keeps the majority.
    let total = total.max(1);
    let reserve_ceiling = total.saturating_sub(1).max(1);
    let reserve = if reserve_override > 0 {
        reserve_override.clamp(1, reserve_ceiling)
    } else {
        total.div_ceil(4).clamp(1, reserve_ceiling)
    };

    let threads = match role {
        // The majority — the hot path.
        Role::DataPlane => total.saturating_sub(reserve).max(1),
        // The reserve — enough for the control plane not to be starved; postgres
        // shares these cores with it via the OS scheduler.
        Role::ControlPlane => reserve,
    };
    (threads, Source::SharedHost)
}

/// Resolve the Tokio worker-thread count for this process and role.
pub fn worker_threads(role: Role) -> usize {
    let s = core_settings();
    resolve(role, s.worker_threads, crate::cgroup::quota_cpus(), available(), s.control_plane_cpu_reserve).0
}

/// Build the process's multi-thread Tokio runtime, sized by [`worker_threads`].
/// Called from a synchronous `main()` before `block_on`.
pub fn build_runtime(role: Role) -> std::io::Result<tokio::runtime::Runtime> {
    let threads = worker_threads(role);
    tokio::runtime::Builder::new_multi_thread()
        .worker_threads(threads)
        .enable_all()
        .build()
}

/// Log the resolved worker-thread count and how it was decided. Call from inside
/// the async entrypoint, after the tracing subscriber is initialized (the
/// runtime itself is built before tracing exists, so it cannot log there).
pub fn log_sizing(role: Role) {
    let s = core_settings();
    let (threads, source) =
        resolve(role, s.worker_threads, crate::cgroup::quota_cpus(), available(), s.control_plane_cpu_reserve);
    tracing::info!(
        worker_threads = threads,
        source = source.as_str(),
        host_cpus = available(),
        role = ?role,
        "tokio runtime sized"
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn override_wins_over_everything() {
        // Override beats a cgroup quota and the shared-host policy alike.
        assert_eq!(resolve(Role::DataPlane, 3, Some(8), 16, 0), (3, Source::Override));
        assert_eq!(resolve(Role::ControlPlane, 3, None, 16, 9), (3, Source::Override));
    }

    #[test]
    fn cgroup_quota_used_for_both_roles() {
        // v2 "200000 100000" => ceil(2) = 2; isolated host ignores the role.
        assert_eq!(resolve(Role::DataPlane, 0, Some(2), 64, 0), (2, Source::CgroupQuota));
        assert_eq!(resolve(Role::ControlPlane, 0, Some(2), 64, 0), (2, Source::CgroupQuota));
        // Sub-core quota still yields at least one worker.
        assert_eq!(resolve(Role::DataPlane, 0, Some(1), 64, 0), (1, Source::CgroupQuota));
    }

    #[test]
    fn shared_host_splits_majority_to_data_plane_reserve_to_control_plane() {
        // (total) -> (proxy, admin); the split sums to total (no oversubscription),
        // the data plane keeps the majority, and the control plane is never starved.
        let cases = [
            (1usize, 1usize, 1usize),
            (2, 1, 1),
            (4, 3, 1),
            (8, 6, 2),
            (16, 12, 4),
            (32, 24, 8),
        ];
        for (total, want_proxy, want_admin) in cases {
            let (proxy, src) = resolve(Role::DataPlane, 0, None, total, 0);
            let (admin, _) = resolve(Role::ControlPlane, 0, None, total, 0);
            assert_eq!(src, Source::SharedHost);
            assert_eq!(proxy, want_proxy, "data-plane threads for total={total}");
            assert_eq!(admin, want_admin, "control-plane threads for total={total}");
            assert!(proxy >= 1 && admin >= 1, "both roles get at least one worker");
            assert!(proxy + admin <= total.max(2), "no oversubscription for total={total}");
            if total > 2 {
                assert!(proxy >= admin, "data plane keeps the majority for total={total}");
                assert!(proxy < total, "data plane leaves the box headroom for total={total}");
            }
        }
    }

    #[test]
    fn reserve_override_clamps_within_bounds() {
        // An explicit reserve larger than the box is clamped to total-1.
        let (proxy, src) = resolve(Role::DataPlane, 0, None, 8, 99);
        assert_eq!((proxy, src), (1, Source::SharedHost));
        // A normal reserve override is honored verbatim.
        assert_eq!(resolve(Role::DataPlane, 0, None, 8, 3).0, 5);
    }
}
