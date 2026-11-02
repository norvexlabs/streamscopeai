//! The docker tier's host preflight: what rootless Podman must offer before a
//! run starts, each missing piece refused with its fix. Fail closed — above
//! all, a ROOTFUL podman is refused: its `--privileged` is host root.

use anyhow::{bail, Context, Result};
use serde::Deserialize;

/// The oldest podman whose `--userns=keep-id:uid=,gid=` the run relies on.
const MIN_VERSION: (u32, u32) = (4, 4);

/// What the run learns from the host.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostFacts {
    pub version: String,
    /// The host ids podman maps into a container, `(first, count)`: the
    /// developer's own id and their subordinate range.
    pub uid_ranges: Vec<(u32, u32)>,
}

#[derive(Deserialize)]
struct Info {
    host: InfoHost,
    version: InfoVersion,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct InfoHost {
    security: InfoSecurity,
    #[serde(default)]
    cgroup_version: String,
    #[serde(default)]
    cgroup_controllers: Vec<String>,
    #[serde(default)]
    id_mappings: Option<InfoMappings>,
}

#[derive(Deserialize)]
struct InfoSecurity {
    #[serde(default)]
    rootless: bool,
}

#[derive(Deserialize)]
struct InfoMappings {
    #[serde(default)]
    uidmap: Vec<InfoMapping>,
    #[serde(default)]
    gidmap: Vec<InfoMapping>,
}

#[derive(Deserialize)]
struct InfoMapping {
    host_id: u32,
    size: u32,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct InfoVersion {
    version: String,
}

/// Assess `podman info --format json` (`info`). `docker`: the project runs an
/// engine inside, which needs `/dev/fuse` (`fuse`: whether it exists).
/// `cpus`: the project sets a cpu limit, which needs the `cpu` controller.
pub fn assess(info: &str, docker: bool, cpus: bool, fuse: bool) -> Result<HostFacts> {
    let info: Info = serde_json::from_str(info).context("read `podman info`")?;
    if !info.host.security.rootless {
        bail!(
            "podman runs rootful here — the docker sandbox refuses it (a rootful container's --privileged \
             is host root). Run `ssai` as your own user, not root, with rootless podman"
        );
    }
    let version = info.version.version;
    if !at_least(&version, MIN_VERSION) {
        bail!(
            "podman {version} is too old for the docker sandbox — it needs {}.{} or later",
            MIN_VERSION.0,
            MIN_VERSION.1
        );
    }
    if info.host.cgroup_version != "v2" {
        bail!("the docker sandbox needs cgroup v2 (this host runs {:?})", info.host.cgroup_version);
    }
    let needed: &[&str] = if cpus { &["memory", "pids", "cpu"] } else { &["memory", "pids"] };
    for &controller in needed {
        if !info.host.cgroup_controllers.iter().any(|c| c == controller) {
            bail!(
                "the `{controller}` cgroup controller is not delegated to your user — the sandbox cannot \
                 limit the container. Enable systemd user delegation \
                 (`Delegate=cpu cpuset io memory pids` for user@.service) and log in again"
            );
        }
    }
    let ranges = |map: Vec<InfoMapping>| -> Vec<(u32, u32)> {
        map.into_iter().map(|e| (e.host_id, e.size)).filter(|&(_, n)| n > 0).collect()
    };
    let (uid_ranges, gid_ranges) = match info.host.id_mappings {
        Some(m) => (ranges(m.uidmap), ranges(m.gidmap)),
        None => (Vec::new(), Vec::new()),
    };
    let ids = |r: &[(u32, u32)]| r.iter().map(|&(_, n)| u64::from(n)).sum::<u64>();
    // Only the developer's own id mapped: no subordinate range, so a
    // container's root would be the developer and its other users unmapped
    // (keep-id needs both a uid and a gid range).
    if ids(&uid_ranges) < 2 || ids(&gid_ranges) < 2 {
        bail!(
            "your user has no subordinate uid or gid range — add one to /etc/subuid and /etc/subgid \
             (`sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 $USER`), \
             then run `podman system migrate`"
        );
    }
    if docker && !fuse {
        bail!("`\"docker\": true` needs /dev/fuse on this host (the inner engine's storage) — load the fuse module");
    }
    Ok(HostFacts { version, uid_ranges })
}

/// `version` (`4.9.3`, `5.0.0-dev`) is at least `min`.
fn at_least(version: &str, min: (u32, u32)) -> bool {
    let mut parts = version.split(['.', '-']).map(|p| p.parse::<u32>());
    match (parts.next(), parts.next()) {
        (Some(Ok(major)), Some(Ok(minor))) => (major, minor) >= min,
        _ => false,
    }
}

/// Run `podman info` on this host and assess it.
pub fn run(docker: bool, cpus: bool) -> Result<HostFacts> {
    let out = std::process::Command::new("podman")
        .args(["info", "--format", "json"])
        .stdin(std::process::Stdio::null())
        .output();
    let out = match out {
        Ok(out) => out,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => bail!(
            "the docker sandbox needs rootless podman, which is not installed — `sudo apt install podman` \
             (or your distribution's package)"
        ),
        Err(e) => return Err(e).context("run `podman info`"),
    };
    if !out.status.success() {
        bail!(
            "`podman info` failed — rootless podman is not usable for your user: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    assess(&String::from_utf8_lossy(&out.stdout), docker, cpus, std::path::Path::new("/dev/fuse").exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mapping(map: &[(u32, u32)]) -> Vec<serde_json::Value> {
        map.iter().enumerate().map(|(i, (h, n))| serde_json::json!({"container_id": i, "host_id": h, "size": n})).collect()
    }

    fn info(rootless: bool, version: &str, cgroup: &str, controllers: &[&str], uidmap: &[(u32, u32)]) -> String {
        serde_json::json!({
            "host": {
                "security": {"rootless": rootless},
                "cgroupVersion": cgroup,
                "cgroupControllers": controllers,
                "idMappings": {"uidmap": mapping(uidmap), "gidmap": mapping(uidmap)},
            },
            "version": {"Version": version},
        })
        .to_string()
    }

    const MAP: &[(u32, u32)] = &[(1000, 1), (100_000, 65_536)];

    #[test]
    fn a_usable_host_yields_its_version_and_ranges() {
        let facts = assess(&info(true, "4.9.3", "v2", &["cpu", "memory", "pids"], MAP), false, false, false).unwrap();
        assert_eq!(facts, HostFacts { version: "4.9.3".into(), uid_ranges: MAP.to_vec() });
    }

    #[test]
    fn a_rootful_podman_is_refused() {
        let err = assess(&info(false, "4.9.3", "v2", &["memory", "pids"], MAP), false, false, true).unwrap_err();
        assert!(format!("{err}").contains("rootful"), "{err}");
    }

    #[test]
    fn the_version_is_held_at_four_four_on_both_sides() {
        for (v, ok) in [("4.4.0", true), ("4.3.9", false), ("5.0.0-dev", true), ("3.9.9", false), ("4.10.1", true), ("dev", false)] {
            let r = assess(&info(true, v, "v2", &["memory", "pids"], MAP), false, false, false);
            assert_eq!(r.is_ok(), ok, "{v}: {r:?}");
        }
    }

    #[test]
    fn cgroup_v1_and_an_undelegated_controller_are_refused() {
        assert!(assess(&info(true, "4.9.3", "v1", &["memory", "pids"], MAP), false, false, false).is_err());
        assert!(assess(&info(true, "4.9.3", "v2", &["cpu", "pids"], MAP), false, false, false).is_err());
        assert!(assess(&info(true, "4.9.3", "v2", &["cpu", "memory"], MAP), false, false, false).is_err());
    }

    #[test]
    fn a_user_without_a_subordinate_range_is_refused() {
        let err = assess(&info(true, "4.9.3", "v2", &["memory", "pids"], &[(1000, 1)]), false, false, false).unwrap_err();
        assert!(format!("{err}").contains("/etc/subuid"), "{err}");
        assert!(assess(&info(true, "4.9.3", "v2", &["memory", "pids"], &[]), false, false, false).is_err());
        // Positive control: one more id mapped is a range.
        assert!(assess(&info(true, "4.9.3", "v2", &["memory", "pids"], &[(1000, 1), (100_000, 1)]), false, false, false).is_ok());
    }

    #[test]
    fn a_user_without_a_subordinate_gid_range_is_refused() {
        let mut v: serde_json::Value = serde_json::from_str(&info(true, "4.9.3", "v2", &["memory", "pids"], MAP)).unwrap();
        v["host"]["idMappings"]["gidmap"] = serde_json::json!(mapping(&[(1000, 1)]));
        let err = assess(&v.to_string(), false, false, false).unwrap_err();
        assert!(format!("{err}").contains("--add-subgids"), "{err}");
        // Positive control: the same host with its gid range passes.
        assert!(assess(&info(true, "4.9.3", "v2", &["memory", "pids"], MAP), false, false, false).is_ok());
    }

    #[test]
    fn an_engine_inside_needs_fuse() {
        let ok = info(true, "4.9.3", "v2", &["memory", "pids"], MAP);
        assert!(assess(&ok, true, false, false).is_err());
        assert!(assess(&ok, true, false, true).is_ok());
        assert!(assess(&ok, false, false, false).is_ok());
    }

    #[test]
    fn a_cpu_limit_needs_the_cpu_controller() {
        let without = info(true, "4.9.3", "v2", &["memory", "pids"], MAP);
        let err = assess(&without, false, true, false).unwrap_err();
        assert!(format!("{err}").contains("`cpu`"), "{err}");
        assert!(assess(&without, false, false, false).is_ok(), "no limit, no need");
        assert!(assess(&info(true, "4.9.3", "v2", &["cpu", "memory", "pids"], MAP), false, true, false).is_ok());
    }
}
