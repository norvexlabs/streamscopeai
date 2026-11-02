//! The client's own state directories, shared by both native backends: which
//! profile entries are a client's to create before it is confined, and the
//! `SECRET_DENY` overlap test every grant is filtered by.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use super::{profiles, LaunchSpec};
use crate::state::home_dir;

/// Before a client is launched confined: create what its own state
/// directories need to exist (see [`create_state_dirs`]). Kept out of policy
/// building, which reads HOME and never changes it.
pub(super) fn prepare_state_dirs(spec: &LaunchSpec) -> Result<()> {
    let Some(agent) = profiles::agent_for(&spec.command) else {
        return Ok(());
    };
    let home = home_dir().context(
        "the native sandbox needs HOME to create the client's state directories — \
         set HOME, or pass `--sandbox off` to launch unconfined",
    )?;
    create_state_dirs(&home, agent.state_dirs, &secret_deny(&home), BACKEND_CREATES);
    Ok(())
}

/// What this platform's backend needs created: Landlock grants only a path
/// that exists, so Linux creates the client's directory itself; Seatbelt
/// grants a missing path, so macOS creates only the XDG base above it and
/// leaves the client's own directory to the client.
const BACKEND_CREATES: Create = if cfg!(target_os = "linux") { Create::Dir } else { Create::Base };

/// How much of a state-directory entry [`create_state_dirs`] creates.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Create {
    /// The client's directory itself (`~/.local/share/<x>`).
    Dir,
    /// Only the XDG base above it (`~/.local/share`).
    Base,
}

/// Would allow-listing `dir` (a grant covers its whole subtree) touch a secret?
/// True when the grant's subtree and the paths a `SECRET_DENY` entry names
/// overlap: `dir` sits under the entry, or the entry sits under `dir`.
///
/// The two directions are asked differently, because an entry is a FILENAME
/// prefix (`~/.ssh/id_` names `id_rsa`, `id_ed25519`, …):
/// - `dir` under the entry is a **string** prefix — `~/.ssh/id_rsa.d` is under
///   `~/.ssh/id_` although no path component equals it. Conservative: it also
///   refuses a directory that merely extends a secret's name (`~/.aws-cli`).
/// - the entry under `dir` is a **component** prefix — every path the entry
///   names lies under `dir` exactly when the entry itself does, so `~/.ssh` and
///   `$HOME` are refused while `~/.npm` (npm's cache, beside `~/.npmrc`) is not.
///   A string test here would refuse every directory whose name a secret's
///   name begins with.
pub(super) fn dir_touches_secret(dir: &Path, deny: &[PathBuf]) -> bool {
    let d = dir.to_string_lossy();
    deny.iter().any(|s| d.starts_with(&*s.to_string_lossy()) || s.starts_with(dir))
}

/// A profile entry resolved against `home` — `~/`-relative ones under it,
/// absolute ones as they are — with each `*` component matching every
/// directory present at that level, so a per-version layout is granted as the
/// versions installed when the policy is built. An entry naming nothing that
/// exists resolves to nothing.
pub(super) fn resolve_in(home: &Path, entry: &str) -> Vec<PathBuf> {
    let base = match entry.strip_prefix("~/") {
        Some(rest) => home.join(rest),
        None => PathBuf::from(entry),
    };
    let mut out = vec![PathBuf::new()];
    for component in base.components() {
        if component.as_os_str() == "*" {
            out = out
                .iter()
                .filter_map(|dir| std::fs::read_dir(dir).ok())
                .flat_map(|entries| entries.flatten().map(|e| e.path()))
                .filter(|p| p.is_dir())
                .collect();
        } else {
            for p in &mut out {
                p.push(component);
            }
        }
    }
    out
}

/// `SECRET_DENY` resolved against `home` — the one list every grant is
/// filtered by.
pub(super) fn secret_deny(home: &Path) -> Vec<PathBuf> {
    profiles::SECRET_DENY.iter().flat_map(|s| resolve_in(home, s)).collect()
}

/// Create what the client's own state directories need and lack. On a
/// client's first run in a fresh HOME (no `~/.local` at all) a grant alone does
/// not let it create one: Landlock grants only a path that exists, and Seatbelt,
/// which can grant a path that does not, still refuses the `mkdir` of the
/// ungranted parent (`~/.local`). `upto` says which of the two is created.
/// Only an entry one level under an
/// XDG base directory (`~/.config/<x>`, `~/.cache/<x>`, `~/.local/share/<x>`,
/// `~/.local/state/<x>`) — a directory by that convention, never a file the
/// client creates itself — and never a wildcard entry or one touching
/// SECRET_DENY. Best effort: a directory that cannot be created is not granted.
pub(super) fn create_state_dirs(home: &Path, entries: &[&str], deny: &[PathBuf], upto: Create) {
    const XDG_BASES: [&str; 4] = [".config/", ".cache/", ".local/share/", ".local/state/"];
    for entry in entries {
        let Some(rel) = entry.strip_prefix("~/") else { continue };
        let under_base = XDG_BASES
            .iter()
            .any(|b| rel.strip_prefix(b).is_some_and(|name| !name.is_empty() && !name.contains('/')));
        if !under_base || rel.contains('*') {
            continue;
        }
        let dir = home.join(rel);
        if dir.exists() || dir_touches_secret(&dir, deny) {
            continue;
        }
        let target = match upto {
            Create::Dir => dir.as_path(),
            Create::Base => dir.parent().unwrap_or(&dir),
        };
        let _ = std::fs::create_dir_all(target);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fresh_home(tag: &str) -> PathBuf {
        let home = std::env::temp_dir().join(format!("ss-state-dirs-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&home);
        std::fs::create_dir_all(&home).unwrap();
        home
    }

    const ENTRIES: &[&str] = &["~/.local/share/opencode", "~/.config/opencode", "~/.opencode", "~/.opencode.json"];

    /// Linux: the client's directories themselves, so Landlock can grant them.
    #[test]
    fn dir_mode_creates_the_clients_own_xdg_directories() {
        let home = fresh_home("dir");
        create_state_dirs(&home, ENTRIES, &secret_deny(&home), Create::Dir);
        assert!(home.join(".local/share/opencode").is_dir());
        assert!(home.join(".config/opencode").is_dir());
        // Outside the XDG bases nothing is created.
        assert!(!home.join(".opencode").exists() && !home.join(".opencode.json").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// macOS: only the missing XDG base, never a directory named for the
    /// client — Seatbelt lets the client make that one itself.
    #[test]
    fn base_mode_creates_only_the_missing_xdg_base() {
        let home = fresh_home("base");
        create_state_dirs(&home, ENTRIES, &secret_deny(&home), Create::Base);
        assert!(home.join(".local/share").is_dir());
        assert!(home.join(".config").is_dir());
        assert!(!home.join(".local/share/opencode").exists());
        assert!(!home.join(".config/opencode").exists());
        assert!(!home.join(".opencode").exists() && !home.join(".opencode.json").exists());
        let _ = std::fs::remove_dir_all(&home);
    }

    /// Each backend is handed the mode its grant needs.
    #[test]
    fn each_backend_creates_what_its_grant_needs() {
        #[cfg(target_os = "linux")]
        assert!(BACKEND_CREATES == Create::Dir);
        #[cfg(target_os = "macos")]
        assert!(BACKEND_CREATES == Create::Base);
    }
}
