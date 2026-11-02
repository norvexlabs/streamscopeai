//! Cgroup (v2 and v1) resource accounting — pure `std::fs`, no dependency.
//!
//! In a container the kernel still reports the *host's* CPU count and memory to
//! ordinary syscalls, so process- or system-level readings misrepresent what the
//! orchestrator granted. These helpers read the process's own cgroup instead, so
//! the figures match what Kubernetes accounts (`kubectl top`, the OOM killer) and
//! what `docker stats` shows on the VM appliance. Each returns `None` when not
//! running under a cgroup (e.g. local dev on bare metal / macOS), so callers fall
//! back to host/process readings.

use std::fs;
use std::sync::OnceLock;

/// Value of `key` from a cgroup `*.stat` file (`"key value"` per line).
fn stat_value(content: &str, key: &str) -> Option<u64> {
    content.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        (parts.next() == Some(key)).then(|| parts.next()?.parse().ok())?
    })
}

/// Parse a cgroup v2 `cpu.max` body (`"<quota> <period>"` or `"max <period>"`)
/// into the effective whole-CPU count. `None` when unconstrained.
fn parse_cpu_max(content: &str) -> Option<usize> {
    let mut parts = content.split_whitespace();
    match (parts.next(), parts.next()) {
        (Some("max"), _) | (None, _) => None,
        (Some(quota), Some(period)) => {
            let (q, p) = (quota.parse::<u64>().ok()?, period.parse::<u64>().ok()?);
            (q > 0 && p > 0).then(|| (q.div_ceil(p) as usize).max(1))
        }
        _ => None,
    }
}

/// Effective whole-CPU count from the cgroup CPU quota, if one is set. `None`
/// when unconstrained (no quota, `max`, or unreadable).
pub fn quota_cpus() -> Option<usize> {
    // cgroup v2
    if let Ok(raw) = fs::read_to_string("/sys/fs/cgroup/cpu.max") {
        return parse_cpu_max(&raw);
    }
    // cgroup v1: cpu.cfs_quota_us / cpu.cfs_period_us (quota -1 == unconstrained)
    let quota: i64 = fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_quota_us").ok()?.trim().parse().ok()?;
    let period: i64 = fs::read_to_string("/sys/fs/cgroup/cpu/cpu.cfs_period_us").ok()?.trim().parse().ok()?;
    if quota <= 0 || period <= 0 {
        return None;
    }
    Some(((quota as u64).div_ceil(period as u64) as usize).max(1))
}

/// Memory limit charged to this cgroup, in bytes, if one is set. `None` when
/// unlimited (the host root, or an unconstrained container) — pair it with
/// [`memory_working_set_bytes`] to derive a "% of limit" pressure figure. Read
/// only at snapshot time, never on the hot path.
pub fn memory_limit_bytes() -> Option<u64> {
    // cgroup v2: memory.max is "max" (unlimited) or a byte count.
    if let Ok(raw) = fs::read_to_string("/sys/fs/cgroup/memory.max") {
        let t = raw.trim();
        return if t == "max" { None } else { t.parse().ok() };
    }
    // cgroup v1: memory.limit_in_bytes reports a near-u64::MAX sentinel when
    // unlimited (the root); a real limit is far below it.
    let v: u64 = fs::read_to_string("/sys/fs/cgroup/memory/memory.limit_in_bytes")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    (v < 0x7000_0000_0000_0000).then_some(v)
}

/// Whether this process runs in a resource-constrained (delegated) cgroup — a
/// container or pod — rather than the host root, where the accounting files would
/// report host-wide figures. A set CPU quota or memory limit is the signal: the
/// VM appliance (Docker) and Kubernetes pods always run with at least a memory
/// limit. Ambiguous cases (an unconstrained container) report `false`, so callers
/// fall back to per-process sysinfo — which is also correct. Cached: a process's
/// cgroup limits do not change at runtime.
pub fn is_containerized() -> bool {
    static CACHED: OnceLock<bool> = OnceLock::new();
    *CACHED.get_or_init(|| quota_cpus().is_some() || memory_limit_bytes().is_some())
}

/// Cumulative CPU time charged to this cgroup, in microseconds. `None` when not
/// in a constrained cgroup (use per-process sysinfo there — the root cgroup's
/// figures are host-wide, not this process's). Take the delta over a wall-clock
/// interval to derive a utilization percentage.
pub fn cpu_usage_usec() -> Option<u64> {
    if !is_containerized() {
        return None;
    }
    // cgroup v2: cpu.stat carries "usage_usec <n>".
    if let Ok(raw) = fs::read_to_string("/sys/fs/cgroup/cpu.stat")
        && let Some(usec) = stat_value(&raw, "usage_usec")
    {
        return Some(usec);
    }
    // cgroup v1: cpuacct.usage is cumulative nanoseconds.
    let ns: u64 = fs::read_to_string("/sys/fs/cgroup/cpuacct/cpuacct.usage").ok()?.trim().parse().ok()?;
    Some(ns / 1000)
}

/// Working-set memory charged to this cgroup, in bytes — charged memory minus
/// reclaimable file cache, the figure `kubectl top` shows and the OOM killer
/// acts on. `None` when not in a constrained cgroup (the root figures are
/// host-wide; use per-process sysinfo there).
pub fn memory_working_set_bytes() -> Option<u64> {
    if !is_containerized() {
        return None;
    }
    // cgroup v2
    if let Ok(raw) = fs::read_to_string("/sys/fs/cgroup/memory.current") {
        let current: u64 = raw.trim().parse().ok()?;
        let inactive = fs::read_to_string("/sys/fs/cgroup/memory.stat")
            .ok()
            .and_then(|s| stat_value(&s, "inactive_file"))
            .unwrap_or(0);
        return Some(current.saturating_sub(inactive));
    }
    // cgroup v1
    let current: u64 = fs::read_to_string("/sys/fs/cgroup/memory/memory.usage_in_bytes")
        .ok()?
        .trim()
        .parse()
        .ok()?;
    let inactive = fs::read_to_string("/sys/fs/cgroup/memory/memory.stat")
        .ok()
        .and_then(|s| stat_value(&s, "total_inactive_file"))
        .unwrap_or(0);
    Some(current.saturating_sub(inactive))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stat_value_picks_the_right_line() {
        let body = "usage_usec 123456\nuser_usec 100000\nsystem_usec 23456\n";
        assert_eq!(stat_value(body, "usage_usec"), Some(123456));
        assert_eq!(stat_value(body, "system_usec"), Some(23456));
        assert_eq!(stat_value(body, "missing"), None);
        // "user_usec" must not match a prefix query for "user".
        assert_eq!(stat_value(body, "user"), None);
    }

    #[test]
    fn cpu_max_parses_quota_and_unconstrained() {
        assert_eq!(parse_cpu_max("200000 100000"), Some(2));
        assert_eq!(parse_cpu_max("150000 100000"), Some(2)); // ceil(1.5)
        assert_eq!(parse_cpu_max("50000 100000"), Some(1)); // sub-core floors to 1
        assert_eq!(parse_cpu_max("max 100000"), None);
        assert_eq!(parse_cpu_max("0 100000"), None);
    }
}
