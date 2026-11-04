//! The `podman run` argv for one docker-tier run — a pure function of facts
//! the launcher resolved (ids, image, paths, volumes), so every flag that
//! decides what the container reaches is unit-tested here.
//!
//! What the container is given, and nothing more: the project at its
//! workspace path, the `ssai` binary (its init) and the run dir (the agent's
//! start file) read-only, the socket dir (the guard's socket, the exit-code
//! file), the agent's home volume, single files read-only (the CA bundles, a
//! home-scoped client's provisioned config), and —
//! only with an engine inside — the engine's cache volume, `/dev/fuse` and
//! `--privileged` (bounded by the user namespace). No network: the guard's
//! socket is the only way out. Never the host's podman or docker socket, the
//! developer's `$HOME`, or `~/.ssh`.

use std::path::{Path, PathBuf};

/// The label every docker-tier container carries, valued with the run's
/// owner (the `ssai` pid) — how a stale container of a killed run is found.
pub const RUN_LABEL: &str = "ai.streamscope.sandbox-run";

/// Where the run dir (read-only) and the socket dir (read-write) appear in
/// the container.
pub const RUN_MOUNT: &str = "/run/ssai";
pub const SOCK_MOUNT: &str = "/run/ssai-sock";
/// Where the `ssai` binary is mounted, a file of its own: the container's
/// init, and `ssai __connect` for git over SSH.
pub const INIT_BINARY: &str = "/run/ssai-bin/ssai";
/// The agent's start file inside the run dir (env, argv, user).
pub const START_FILE: &str = "start.json";

/// Everything the argv is built from.
#[derive(Debug, Clone)]
pub struct RunFacts {
    /// The image to run (the agent layer), by id or tag.
    pub image: String,
    /// The container's name.
    pub name: String,
    /// The value of [`RUN_LABEL`].
    pub owner: String,
    /// The agent user's ids inside the image: keep-id maps the developer to
    /// them, so files the agent writes are the developer's on the host.
    pub uid: u32,
    pub gid: u32,
    pub project: PathBuf,
    /// The project's path in the container.
    pub workspace: String,
    /// The working directory in the container (under `workspace`).
    pub cwd: String,
    /// The `ssai` binary on the host.
    pub binary: PathBuf,
    pub run_dir: PathBuf,
    pub sock_dir: PathBuf,
    /// Single files mounted read-only: `(host path, container path)`.
    pub files: Vec<(PathBuf, String)>,
    /// The agent's home: a named volume and where it is mounted.
    pub home_volume: String,
    pub home: String,
    /// An engine inside: its cache volume (`/var/lib/docker`).
    pub engine_volume: Option<String>,
    pub limits: super::config::Limits,
    /// Stdin is a terminal: allocate one in the container.
    pub tty: bool,
    /// The project's own mounts ([`project_mounts`]), after the project's.
    pub project_mounts: Vec<ProjectMount>,
}

/// One mount the project's grants add: `(host path, container path, read-only)`.
pub type ProjectMount = (PathBuf, String, bool);

/// The mounts that carry the project's grants and holds
/// ([`crate::sandbox::protect`]) into the container, in mount order (a parent
/// before what is mounted inside it): a linked worktree's git dirs at their
/// host paths (its `.git` file names them absolutely), each held folder bound
/// onto itself (a mount point cannot be renamed or removed), and each held
/// tree or file read-only. `None` when a path podman would split must be
/// mounted ([`mountable`]).
pub fn project_mounts(grants: &crate::sandbox::protect::ProjectGrants, root: &Path, workspace: &str) -> Option<Vec<ProjectMount>> {
    use crate::sandbox::protect::Guard;
    let inside = |p: &Path| -> String {
        match p.strip_prefix(root) {
            Ok(rest) if rest.as_os_str().is_empty() => workspace.to_string(),
            Ok(rest) => format!("{}/{}", workspace.trim_end_matches('/'), rest.to_string_lossy()),
            Err(_) => p.to_string_lossy().into_owned(),
        }
    };
    let mut out: Vec<ProjectMount> = grants.extra_rw.iter().map(|p| (p.clone(), inside(p), false)).collect();
    for held in grants.held() {
        let read_only = held.guard != Guard::Node;
        let at = inside(&held.path);
        // A git dir outside the project is already a mount of its own.
        if !out.iter().any(|(_, c, _)| *c == at) {
            out.push((held.path.clone(), at, read_only));
        }
    }
    out.sort_by_key(|(_, c, _)| Path::new(c).components().count());
    out.iter().all(|(h, c, _)| mountable(&h.to_string_lossy()) && mountable(c)).then_some(out)
}

/// The argv after `podman`.
pub fn run_argv(f: &RunFacts) -> Vec<String> {
    let mut a: Vec<String> = ["run", "--rm", "-i", "--pull=never", "--log-driver=none", "--network=none", "--cgroupns=private"]
        .iter()
        .map(|s| s.to_string())
        .collect();
    if f.tty {
        a.push("-t".into());
    }
    a.push(format!("--name={}", f.name));
    a.push(format!("--label={RUN_LABEL}={}", f.owner));
    // keep-id maps the developer to the agent user. An agent that is the
    // container's root needs no option: rootless podman's own map makes the
    // container's root the developer.
    if !agent_is_root(f) {
        a.push(format!("--userns=keep-id:uid={},gid={}", f.uid, f.gid));
    }
    // Init runs as the container's root (the user namespace's, never the
    // host's) and starts the agent as `uid:gid`.
    a.push("--user=0:0".into());
    // SELinux would deny the container every bind mount below (they keep
    // their host labels); relabeling with `:z` would rewrite the labels of
    // the developer's own files, the `ssai` binary included. The user
    // namespace and the absent network are the boundary; a no-op elsewhere.
    a.push("--security-opt=label=disable".into());
    a.push(format!("--pids-limit={}", f.limits.pids));
    if let Some(m) = &f.limits.memory {
        a.push(format!("--memory={m}"));
    }
    if let Some(c) = f.limits.cpus {
        a.push(format!("--cpus={c}"));
    }
    a.push(volume(&f.project, &f.workspace, ""));
    for (host, container, read_only) in &f.project_mounts {
        a.push(volume(host, container, if *read_only { ":ro" } else { "" }));
    }
    a.push(volume(&f.binary, INIT_BINARY, ":ro"));
    a.push(volume(&f.run_dir, RUN_MOUNT, ":ro"));
    a.push(volume(&f.sock_dir, SOCK_MOUNT, ""));
    a.push(format!("--volume={}:{}", f.home_volume, f.home));
    // After the home volume: a file under the home is mounted on top of it.
    for (host, container) in &f.files {
        a.push(volume(host, container, ":ro"));
    }
    if let Some(engine) = &f.engine_volume {
        a.push("--privileged".into());
        a.push("--device=/dev/fuse".into());
        a.push(format!("--volume={engine}:/var/lib/docker"));
    }
    a.push(format!("--workdir={}", f.cwd));
    a.push(format!("--entrypoint={INIT_BINARY}"));
    a.push(f.image.clone());
    a.push("__sandbox-init".into());
    a.push(format!("{RUN_MOUNT}/{START_FILE}"));
    a
}

/// The agent runs as the container's root, which is then the developer.
pub fn agent_is_root(f: &RunFacts) -> bool {
    f.uid == 0
}

/// `--volume=<host>:<container><opts>`. A host path holding `:` or `,` would
/// be split by podman: the launcher refuses such a project first
/// ([`mountable`]).
fn volume(host: &Path, container: &str, opts: &str) -> String {
    format!("--volume={}:{container}{opts}", host.display())
}

/// Whether podman can mount `path` as given (`:` and `,` separate its volume
/// options).
pub fn mountable(path: &str) -> bool {
    !path.is_empty() && !path.contains([':', ',']) && !path.chars().any(char::is_control)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::podman::config::Limits;

    fn facts() -> RunFacts {
        RunFacts {
            image: "ssai-agent/claude-code:abc".into(),
            name: "ssai-run-42".into(),
            owner: "42".into(),
            uid: 1000,
            gid: 1001,
            project: "/home/dev/app".into(),
            workspace: "/workspaces/app".into(),
            cwd: "/workspaces/app/src".into(),
            binary: "/usr/local/bin/ssai".into(),
            run_dir: "/run/user/1000/ssai/r1".into(),
            sock_dir: "/run/user/1000/ssai/r1s".into(),
            files: vec![("/home/dev/.codex/config.toml".into(), "/home/vscode/.codex/config.toml".into())],
            home_volume: "ssai-home-x".into(),
            home: "/home/vscode".into(),
            engine_volume: None,
            limits: Limits { memory: Some("6g".into()), cpus: Some(3.0), pids: 4096 },
            tty: false,
            project_mounts: vec![],
        }
    }

    /// A linked worktree under `/home/dev/app` whose main checkout is
    /// `/home/dev/main`: its common git dir mounted at its host path, the
    /// held git dirs bound onto themselves, the rest read-only, parents first.
    #[test]
    fn the_projects_holds_become_mounts_parents_first() {
        use crate::sandbox::protect::{Guard, ProjectGrants, Protected};
        let held = |p: &str, guard| Protected { path: PathBuf::from(p), guard };
        let grants = ProjectGrants {
            extra_rw: vec!["/home/dev/main/.git".into()],
            stat_only: vec!["/home/dev/main".into()],
            protected: vec![
                held("/home/dev/main/.git/hooks", Guard::Tree),
                held("/home/dev/app/.streamscopeai", Guard::Tree),
                held("/home/dev/main/.git/worktrees/app", Guard::Node),
                held("/home/dev/main/.git", Guard::Node),
            ],
        };
        let mounts = project_mounts(&grants, Path::new("/home/dev/app"), "/workspaces/app").unwrap();
        assert_eq!(
            mounts,
            vec![
                (PathBuf::from("/home/dev/app/.streamscopeai"), "/workspaces/app/.streamscopeai".to_string(), true),
                (PathBuf::from("/home/dev/main/.git"), "/home/dev/main/.git".to_string(), false),
                (PathBuf::from("/home/dev/main/.git/hooks"), "/home/dev/main/.git/hooks".to_string(), true),
                (PathBuf::from("/home/dev/main/.git/worktrees/app"), "/home/dev/main/.git/worktrees/app".to_string(), false),
            ]
        );
        let mut f = facts();
        f.project_mounts = mounts;
        let a = run_argv(&f);
        let project = a.iter().position(|x| x == "--volume=/home/dev/app:/workspaces/app").unwrap();
        let hooks = a.iter().position(|x| x == "--volume=/home/dev/main/.git/hooks:/home/dev/main/.git/hooks:ro").unwrap();
        assert!(project < hooks, "{a:?}");
        // A path podman would split refuses the mounts.
        let split = ProjectGrants { protected: vec![held("/home/dev/app/a,b", Guard::Tree)], ..Default::default() };
        assert_eq!(project_mounts(&split, Path::new("/home/dev/app"), "/workspaces/app"), None);
    }

    fn has(a: &[String], flag: &str) -> bool {
        a.iter().any(|x| x == flag)
    }

    #[test]
    fn the_container_has_no_network_and_maps_the_developer_to_the_agent_user() {
        let a = run_argv(&facts());
        for flag in ["--network=none", "--userns=keep-id:uid=1000,gid=1001", "--user=0:0", "--rm", "--pull=never", "--cgroupns=private", "--security-opt=label=disable"] {
            assert!(has(&a, flag), "{flag}: {a:?}");
        }
        assert!(has(&a, &format!("--label={RUN_LABEL}=42")));
    }

    #[test]
    fn a_root_agent_keeps_rootless_podmans_own_map() {
        let a = run_argv(&RunFacts { uid: 0, gid: 0, ..facts() });
        assert!(!a.iter().any(|x| x.starts_with("--userns")), "{a:?}");
        assert!(has(&a, "--user=0:0") && has(&a, "--network=none"));
    }

    #[test]
    fn only_the_project_the_run_dirs_and_the_home_are_mounted() {
        let a = run_argv(&facts());
        let mounts: Vec<&String> = a.iter().filter(|x| x.starts_with("--volume=") || x.starts_with("-v")).collect();
        assert_eq!(
            mounts,
            [
                "--volume=/home/dev/app:/workspaces/app",
                "--volume=/usr/local/bin/ssai:/run/ssai-bin/ssai:ro",
                "--volume=/run/user/1000/ssai/r1:/run/ssai:ro",
                "--volume=/run/user/1000/ssai/r1s:/run/ssai-sock",
                "--volume=ssai-home-x:/home/vscode",
                "--volume=/home/dev/.codex/config.toml:/home/vscode/.codex/config.toml:ro",
            ]
        );
        assert!(!a.iter().any(|x| x.contains("podman.sock") || x.contains("docker.sock") || x.contains(".ssh")));
    }

    #[test]
    fn privilege_and_fuse_come_only_with_an_engine_inside() {
        let plain = run_argv(&facts());
        assert!(!has(&plain, "--privileged") && !has(&plain, "--device=/dev/fuse"));
        let engine = run_argv(&RunFacts { engine_volume: Some("ssai-engine-x".into()), ..facts() });
        assert!(has(&engine, "--privileged") && has(&engine, "--device=/dev/fuse"));
        assert!(has(&engine, "--volume=ssai-engine-x:/var/lib/docker"));
    }

    #[test]
    fn the_limits_and_the_terminal_follow_the_facts() {
        let a = run_argv(&facts());
        for flag in ["--pids-limit=4096", "--memory=6g", "--cpus=3"] {
            assert!(has(&a, flag), "{flag}");
        }
        assert!(!has(&a, "-t"));
        let bare = run_argv(&RunFacts { limits: Limits { memory: None, cpus: None, pids: 64 }, tty: true, ..facts() });
        assert!(has(&bare, "-t") && has(&bare, "--pids-limit=64"));
        assert!(!bare.iter().any(|x| x.starts_with("--memory") || x.starts_with("--cpus")));
    }

    #[test]
    fn init_is_the_entrypoint_and_reads_the_start_file() {
        let a = run_argv(&facts());
        let image_at = a.iter().position(|x| x == "ssai-agent/claude-code:abc").unwrap();
        assert_eq!(a[image_at + 1..], ["__sandbox-init", "/run/ssai/start.json"]);
        assert!(has(&a, "--entrypoint=/run/ssai-bin/ssai"));
        assert!(has(&a, "--workdir=/workspaces/app/src"));
        // Every option precedes the image: nothing after it is read by podman.
        assert!(a[..image_at].iter().all(|x| x.starts_with('-') || x == "run"), "{a:?}");
    }

    #[test]
    fn a_path_podman_would_split_is_not_mountable() {
        for bad in ["/a:b", "/a,b", "", "/a\nb"] {
            assert!(!mountable(bad), "{bad:?}");
        }
        assert!(mountable("/home/dev/my app"));
    }
}
