//! What a confined run may reach on the filesystem — the allow-list the
//! Linux backend hands Landlock and the FreeBSD jail mounts: the project, the
//! run's scratch dir, the client's state and caches read-write; the system,
//! the user's tools and toolchains read-only; never a `SECRET_DENY` path.
//! Built from the shared profile tables (`profiles.rs`, `state_dirs.rs`), so a
//! profile change reaches every backend.

use std::path::{Path, PathBuf};

use super::state_dirs::{dir_touches_secret, is_real_in_home, package_caches, resolve_in, secret_deny};
use super::{profiles, LaunchSpec};

/// The paths a run is granted. Absent paths are listed too: Landlock skips
/// them, the jail drops them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AllowList {
    pub rw: Vec<PathBuf>,
    pub ro: Vec<PathBuf>,
    /// The secret prefixes ([`secret_deny`]): kept out of every grant.
    pub deny: Vec<PathBuf>,
}

/// Whether `dir` — a client's install folder, or the one `PATH` finds it in —
/// is too broad to grant: the home or `~/.local`, or a folder touching a
/// secret. Compared with the home as given AND as it really is: the folder
/// comes from a resolved program path, which names the home by its real
/// path (`/usr/home/u` where `/home` is a link).
pub(super) fn too_broad_or_secret(home: &Path, dir: &Path) -> bool {
    let real = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
    [home, real.as_path()]
        .iter()
        .any(|h| dir == *h || dir == h.join(".local") || dir_touches_secret(dir, &secret_deny(h)))
}

/// The allow-list of `spec`'s run for the user whose home is `home`: every
/// `~/` entry of every profile list resolves against it. `scratch` is the
/// run's private temp dir ([`super::scratch`]).
pub fn build_in(home: &Path, spec: &LaunchSpec, scratch: &Path) -> AllowList {

    // ---- read+write ----
    // `/tmp` is always writable (clients that hardcode `/tmp/...` paths — lock /
    // socket files — must not regress), but no temp variable names it. The
    // run's scratch dir is where every temp variable points
    // (`ScratchDir::pin_env`); Bun/pnpm/etc. extract native addons there then
    // `dlopen`/`mmap PROT_EXEC` them, so it MUST be both write- and
    // execute-allowed (`from_all` covers both). That the mount itself allows
    // exec is checked when the dir is created (`ScratchDir::create`).
    let deny = secret_deny(home);
    let mut rw: Vec<PathBuf> = vec![spec.project_root.clone(), PathBuf::from("/tmp"), scratch.to_path_buf()];
    for d in ["/dev/null", "/dev/tty", "/dev/zero", "/dev/full", "/dev/shm"] {
        rw.push(PathBuf::from(d));
    }
    // Profile grants are resolved and filtered against SECRET_DENY: Landlock is
    // allow-only, so a secret inside a granted tree cannot be taken back by any
    // deny — it has to be kept out of the grant. (The project root and `/tmp`
    // are the user's own choice and are not filtered: a project at `$HOME`
    // would otherwise be refused outright. The scratch dir is one the run
    // created empty.)
    if let Some(agent) = profiles::agent_for(&spec.command) {
        rw.extend(granted_dirs(home, agent.state_dirs, &deny));
    }
    // A client the agent may run as a tool reads (and writes) its own state
    // as the launched client does: the same grant, filtered the same way.
    for tool in &spec.tool_clients {
        rw.extend(granted_dirs(home, tool.profile.state_dirs, &deny));
    }
    // Every package cache, whatever the client's own runtime: an `npx` or
    // `uvx` child inherits this domain.
    // Re-judged here: a cache made a link since it was created is not granted.
    rw.extend(package_caches(home, &deny).into_iter().map(|(dir, _)| dir));
    if let Some(tc) = profiles::toolchain_for(&runtime_of(&spec.command)) {
        rw.extend(granted_dirs(home, tc.dirs, &deny));
    }
    // Paths a prior `--sandbox learn` pass taught the global profile. Re-filtered
    // against SECRET_DENY here so a stale/edited profile can never widen the
    // sandbox onto a secret, even if one slipped into the file.
    rw.extend(learned_override_dirs(home));

    // ---- read-only ----
    let mut ro: Vec<PathBuf> = [
        "/usr", "/lib", "/lib64", "/bin", "/sbin", "/etc", "/opt", "/proc", "/sys",
        "/dev/urandom", "/dev/random", "/usr/local",
    ]
    .iter()
    .map(PathBuf::from)
    .collect();
    // resolv.conf is frequently a symlink into /run (systemd-resolved) — allow
    // the real target so DNS resolution paths that touch it still work.
    if let Ok(target) = std::fs::canonicalize("/etc/resolv.conf")
        && let Some(parent) = target.parent()
    {
        ro.push(parent.to_path_buf());
    }
    ro.extend(granted_dirs(home, profiles::BASE_READ, &deny));
    // The user's own toolchain, read + execute: `from_read` carries Landlock's
    // EXECUTE right, and these are never writable.
    ro.extend(user_tool_dirs(home, &deny));
    if let (Some(rel), Ok(real_home)) = (profiles::UV_PYTHONS.strip_prefix("~/"), std::fs::canonicalize(home)) {
        let pythons = home.join(rel);
        if is_real_in_home(home, &real_home, &pythons) && !dir_touches_secret(&pythons, &deny) {
            ro.push(pythons);
        }
    }
    ro.extend(spec.ca_files.iter().cloned());
    // This binary, read + execute: `ssai __connect` is the ProxyCommand that
    // takes `ssh` through the guard (`GIT_SSH_COMMAND`).
    if let Ok(exe) = std::env::current_exe().and_then(std::fs::canonicalize) {
        ro.push(exe);
    }
    // The client binary + its install tree (so the interpreter/package loads).
    // The grandparent gives e.g. `…/lib/node_modules` next to `…/bin`, but never
    // widen to `$HOME` or `~/.local`, nor to a folder touching a secret (that
    // would re-expose keyrings/token stores — the per-agent/toolchain profiles
    // already grant the specific dirs needed).
    let too_broad = |p: &std::path::Path| too_broad_or_secret(home, p);
    if let Some(bin) = resolve_binary(&spec.command)
        && let Ok(real) = std::fs::canonicalize(&bin)
        && let Some(dir) = real.parent()
    {
        if !too_broad(dir) {
            ro.push(dir.to_path_buf());
        }
        if let Some(up) = dir.parent()
            && !too_broad(up)
        {
            ro.push(up.to_path_buf());
        }
    }

    // ---- deny (carried for macOS; Landlock is allow-only, so on Linux
    // secrets are kept out by simply not allow-listing them) ----

    AllowList { rw: dedup(rw), ro: dedup(ro), deny }
}

/// The runtime command behind an agent (for the toolchain overlay). Cheap
/// heuristic: a few clients are known Node CLIs; otherwise fall back to the
/// command name itself (so `python`/`node` invoked directly still match).
pub(super) fn runtime_of(command: &str) -> String {
    match command {
        "claude" | "opencode" | "gemini" | "qwen" | "cn" | "continue" | "ocr" | "open-code-review" => "node".to_string(),
        "aider" | "vibe" => "python".to_string(),
        other => other.to_string(),
    }
}

/// Resolve a command to a path: an explicit path as-is, else the executable
/// `PATH` finds — the same lookup detection uses ([`crate::program::find`]).
pub(super) fn resolve_binary(command: &str) -> Option<PathBuf> {
    if command.contains('/') {
        return Some(PathBuf::from(command));
    }
    crate::program::find(command)
}

pub(super) fn dedup(mut v: Vec<PathBuf>) -> Vec<PathBuf> {
    v.sort();
    v.dedup();
    v
}

// ── Learn-mode global profile override ──────────────────────────────────────
//
// A `--sandbox learn` pass writes the client-specific directories it observed to
// a single JSON file under the user's config dir. `build_policy` folds them back
// in as read-write allowances on the next confined run. The file is the ONLY
// runtime widening of the built-in profile — everything in it is re-filtered
// against SECRET_DENY at both write and read, so it can never expose a secret.

/// The global learned-profile file, in the CLI's own config folder
/// ([`crate::state::config_dir`]): `sandbox-profile.json`.
pub(super) fn override_file_path() -> Option<PathBuf> {
    Some(crate::state::config_dir().ok()?.join("sandbox-profile.json"))
}

/// Directories a prior learn pass recorded, kept only if still under `$HOME` and
/// not under any SECRET_DENY prefix (defense-in-depth against a hand-edited file).
pub(super) fn learned_override_dirs(home: &Path) -> Vec<PathBuf> {
    let Some(path) = override_file_path() else { return Vec::new() };
    let Ok(bytes) = std::fs::read(&path) else { return Vec::new() };
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(&bytes) else { return Vec::new() };
    let deny = secret_deny(home);
    let own = own_trees(None);
    value
        .get("fs_rw")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str())
                .map(PathBuf::from)
                .filter(|p| p.is_absolute() && p.starts_with(home) && !dir_touches_secret(p, &deny))
                // Never a grant on or above the CLI's own trees, whatever the file says.
                .filter(|p| !dir_touches_secret(p, &own))
                .collect()
        })
        .unwrap_or_default()
}


/// The user-installed tool directories granted read + execute
/// ([`profiles::USER_TOOL_READ`]), minus any whose grant would touch a
/// `SECRET_DENY` entry.
pub(super) fn user_tool_dirs(home: &Path, deny: &[PathBuf]) -> Vec<PathBuf> {
    granted_dirs(home, profiles::USER_TOOL_READ, deny)
}

/// Profile entries resolved against `home` ([`resolve_in`], so `*` expands to
/// what is installed), minus any whose grant would touch an entry of `deny`
/// ([`secret_deny`]). The single path by which a built-in profile list becomes
/// a grant.
pub(super) fn granted_dirs(home: &Path, entries: &[&str], deny: &[PathBuf]) -> Vec<PathBuf> {
    entries
        .iter()
        .flat_map(|entry| resolve_in(home, entry))
        .filter(|dir| !dir_touches_secret(dir, deny))
        .collect()
}

/// The CLI's own trees, never granted by a learned entry: the scratch root
/// (`scratch_root`, else the one the environment names; granted to each run
/// as its own dir only), its cache (engine logs) and its config (login tokens,
/// and the learned profile itself — a grant on it would let a run widen its
/// own sandbox).
pub(super) fn own_trees(scratch_root: Option<&Path>) -> Vec<PathBuf> {
    let mut own: Vec<PathBuf> = match scratch_root {
        Some(r) => vec![r.to_path_buf()],
        None => super::scratch::scratch_root().ok().into_iter().collect(),
    };
    own.extend(crate::state::cache_dir().ok());
    own.extend(crate::state::config_dir().ok());
    own.retain(|p| p.is_absolute());
    own
}
