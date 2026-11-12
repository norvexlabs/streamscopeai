//! One run of the Windows sandbox, before the launch: adjust the run for the
//! sandbox account, refuse a project the grant would reach too far from,
//! then grant the account the project (and what the client needs) and hold
//! what it must not change.

use anyhow::{Context, Result, bail};

use std::path::{Path, PathBuf};

use super::grants::{RunDirs, plan, refused_root, walled_to_report};
use super::{acl, prepare};
use crate::sandbox::{LaunchSpec, profiles};
use crate::sandbox::protect::{self, ProjectGrants};

/// Adjust `spec` for the sandbox account and return what [`grant`] must give
/// it ([`prepare::prepare`]). The client's program is found as the
/// unconfined launch finds it: on the PATH and PATHEXT the run gives it.
pub fn prepare(spec: &mut LaunchSpec) -> Result<RunDirs> {
    let profile = profile_dir()?;
    let own_dir = std::env::current_exe()
        .ok()
        .and_then(|exe| dunce::canonicalize(exe).ok())
        .and_then(|exe| exe.parent().map(Path::to_path_buf));
    let program = if Path::new(&spec.command).is_absolute() {
        Some(PathBuf::from(&spec.command))
    } else {
        let child = |name: &str| spec.env.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str());
        crate::program::find_on(&spec.command, child("PATH").map(std::ffi::OsStr::new), child("PATHEXT"))
    };
    let agent = profiles::agent_for(&spec.command);
    // Where provision writes a client that keeps its config in `%APPDATA%`,
    // spelled real as the profile is.
    let appdata = crate::state::UserDirs::current()?.appdata.map(|d| dunce::canonicalize(&d).unwrap_or(d));
    let node_ca = std::env::var_os("NODE_EXTRA_CA_CERTS").map(PathBuf::from);
    let host = prepare::Host {
        profile: &profile,
        appdata: appdata.as_deref(),
        node_ca: node_ca.as_deref(),
        own_dir: own_dir.as_deref(),
        program: program.as_deref(),
    };
    prepare::prepare(spec, agent, &host)
}

/// The developer's profile folder as the project root is spelled: real
/// (a junction or a short name followed), since the root is.
fn profile_dir() -> Result<PathBuf> {
    let profile = crate::state::home_dir()?;
    Ok(dunce::canonicalize(&profile).unwrap_or(profile))
}

/// The folders above `dirs` (below the drive's root and the profile, the
/// dirs themselves left out) that a group every local account belongs to
/// may write. A folder whose list cannot be read is left out: it is only
/// named, never decided on.
fn open_parents(dirs: &[&Path], profile_text: &str) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = Vec::new();
    for dir in dirs {
        for folder in dir.ancestors().skip(1) {
            if refused_root(&folder.to_string_lossy(), profile_text).is_some() {
                break;
            }
            let same = |a: &Path| a.to_string_lossy().to_lowercase() == folder.to_string_lossy().to_lowercase();
            if dirs.iter().any(|d| same(d)) || out.iter().any(|o| same(o)) {
                continue;
            }
            if acl::broad_writers(folder).is_ok_and(|w| !w.is_empty()) {
                out.push(folder.to_path_buf());
            }
        }
    }
    out
}

/// Refuse to grant `dir` while a group every local account belongs to may
/// write it (a folder made under a drive's root inherits "Authenticated
/// Users: Modify"): the sandbox account would write it whatever it is
/// granted, and revoke could not take that back. With `make_private` (or
/// the developer's yes at a terminal) the folder is made private to them
/// instead; otherwise the run stops, saying why. A folder whose making
/// private was cut short counts as not private: its root already reads as
/// private, the files below it may not be.
fn ensure_private(dir: &Path, make_private: bool, account_sid: &str) -> Result<()> {
    use std::io::IsTerminal as _;
    let record = acl::record_path()?;
    let pending = acl::private_pending(&record, dir)?;
    let writers = acl::broad_writers(dir)?;
    if writers.is_empty() && !pending {
        return Ok(());
    }
    let who = if writers.is_empty() {
        "every account on this computer (making it private to you was started and did not finish)".to_string()
    } else {
        format!("{} — every account on this computer", writers.join(", "))
    };
    let why = format!(
        "{} may be written by {}, the sandbox's included, whatever the sandbox grants (a folder made \
         under a drive's root inherits that; an entry of the folder's own may say so too), so the sandbox \
         cannot confine its writes there. It runs once \
         the folder is private to you: it then stops inheriting from its parent, those groups keep reading \
         it, and SYSTEM and the administrators keep their access",
        dir.display(),
        who
    );
    if !make_private {
        if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
            bail!("{why}. Pass --private-project to make it so.");
        }
        crate::ui::warn("", &why);
        if !crate::commands::session::confirm_no(&format!("Make {} private to you?", dir.display()))? {
            bail!("the Windows sandbox did not run: {} stays writable by every account", dir.display());
        }
    }
    acl::make_private(&record, dir, &crate::win_acl::current_user_sid()?, account_sid)?;
    crate::ui::note(
        "",
        format_args!(
            "{} is private to you now (revoke keeps it so); `icacls \"{}\" /inheritance:e` makes it inherit \
             from its parent again",
            dir.display(),
            dir.display()
        ),
    );
    Ok(())
}

/// A `--ca-file` trust bundle where the sandbox account can read it: in the
/// developer's cache, named for its content (the same CAs, the same file —
/// so the grant record does not grow by a file per run), never removed: it
/// holds only public certificates. Shared rather than private, so the
/// account's read entry on it applies.
pub fn shared_ca_bundle(pem: &[u8]) -> Result<PathBuf> {
    use sha2::Digest as _;
    let dir = crate::state::cache_dir()?.join("sandbox-ca");
    std::fs::create_dir_all(&dir).with_context(|| format!("create {}", dir.display()))?;
    let name = hex::encode(&sha2::Sha256::digest(pem)[..12]);
    let path = dir.join(format!("{name}.pem"));
    if path.exists() {
        return Ok(path);
    }
    // Written aside, then renamed into place: a run reading the bundle never
    // sees one half written. Two runs writing it rename the same content.
    let mut suffix = [0u8; 8];
    rand::Rng::fill_bytes(&mut rand::rng(), &mut suffix);
    let part = dir.join(format!("{name}.{}.part", hex::encode(suffix)));
    std::fs::write(&part, pem).with_context(|| format!("write {}", part.display()))?;
    std::fs::rename(&part, &path).with_context(|| format!("place {}", path.display()))?;
    Ok(path)
}

/// Grant the account `account_sid` this run's project and `dirs`, recorded
/// so `ssai sandbox revoke` can take them back. Idempotent: what is already
/// granted is not written again.
pub fn grant(spec: &LaunchSpec, account_sid: &str, dirs: &RunDirs) -> Result<ProjectGrants> {
    let profile = profile_dir()?;
    let root = &spec.project_root;
    let (root_text, profile_text) = (root.to_string_lossy(), profile.to_string_lossy());
    if let Some(why) = refused_root(&root_text, &profile_text) {
        bail!("the Windows sandbox refuses this project: {why}");
    }
    let project = protect::resolve(root);
    // A linked worktree's main git folder is granted like the project, so it
    // meets the project's conditions; a client's own folder (one an `--env`
    // may name) must not hold the profile or a drive.
    for dir in &project.extra_rw {
        if let Some(why) = refused_root(&dir.to_string_lossy(), &profile_text) {
            bail!("the Windows sandbox refuses this worktree's main git folder: {why}");
        }
    }
    for dir in &dirs.state {
        if let Some(why) = refused_root(&dir.to_string_lossy(), &profile_text) {
            bail!("the Windows sandbox refuses the client's folder {}: {why}", dir.display());
        }
    }
    // The main checkout of a linked worktree too: code planted there (a
    // hook manager's script, a build script) runs outside the sandbox.
    // The main checkout before its git folder: made private, it is what
    // the git folder inherits from, so the developer is asked once.
    let granted: Vec<&Path> = std::iter::once(root.as_path())
        .chain(project.stat_only.iter().map(PathBuf::as_path))
        .chain(project.extra_rw.iter().map(PathBuf::as_path))
        .filter(|d| refused_root(&d.to_string_lossy(), &profile_text).is_none())
        .collect();
    for dir in &granted {
        ensure_private(dir, spec.private_project, account_sid)?;
    }
    // An open folder above them is named, never changed: it may be shared
    // by every account (`C:\Users\Public`), and the drive's root, which
    // every account may create folders in, stays open whatever is changed.
    let open = open_parents(&granted, &profile_text);
    if !open.is_empty() {
        let shown: Vec<String> = open.iter().map(|p| p.display().to_string()).collect();
        crate::ui::warn(
            "",
            format_args!(
                "{} above the project may be written by every account on this computer: the agent can leave \
                 there what a tool looking upward finds (a node_modules folder, a .git); make it private to \
                 you, or move the project",
                shown.join(", ")
            ),
        );
    }
    if !super::grants::inside(root, &profile) {
        crate::ui::warn(
            "",
            format_args!(
                "{root_text} is outside your profile: the agent can change who may open the files it creates \
                 there, and giving them back to you may need an administrator"
            ),
        );
    }
    project.prepare().context("prepare the project's protected git folders")?;
    let aces = plan(root, &project, dirs, &profile);
    let applied = acl::apply(&acl::record_path()?, account_sid, root, &aces)?;
    // A folder whose access list inherits nothing is out of the grant's
    // reach: reported once, when the project is first granted.
    if applied.changed.iter().any(|p| p == root) {
        let walled = walled_to_report(acl::protected_folders(root), &project);
        if !walled.is_empty() {
            let shown: Vec<String> = walled.iter().take(5).map(|p| p.display().to_string()).collect();
            crate::ui::warn(
                "",
                format_args!(
                    "{} folder(s) in the project keep an access list of their own, which the sandbox's grant \
                     does not reach into: {}{}",
                    walled.len(),
                    shown.join(", "),
                    if walled.len() > shown.len() { ", …" } else { "" }
                ),
            );
        }
    }
    Ok(project)
}
