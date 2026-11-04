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
    if let Some(why) = refused_root(&root_text, &profile_text, spec.allow_outside_profile) {
        bail!("the Windows sandbox refuses this project: {why}");
    }
    if refused_root(&root_text, &profile_text, false).is_some() {
        crate::ui::warn(
            "",
            format_args!(
                "{root_text} is outside your profile: every account on this computer may write it, the sandbox \
                 account included, whatever it is granted (--allow-outside-profile)"
            ),
        );
    }
    let project = protect::resolve(root);
    // A linked worktree's main git folder is granted like the project, so it
    // meets the project's conditions; a client's own folder (one an `--env`
    // may name) must not hold the profile or a drive.
    for dir in &project.extra_rw {
        if let Some(why) = refused_root(&dir.to_string_lossy(), &profile_text, spec.allow_outside_profile) {
            bail!("the Windows sandbox refuses this worktree's main git folder: {why}");
        }
    }
    for dir in &dirs.state {
        if let Some(why) = refused_root(&dir.to_string_lossy(), &profile_text, true) {
            bail!("the Windows sandbox refuses the client's folder {}: {why}", dir.display());
        }
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
                    "{} folder(s) in the project keep an access list of their own, so the sandbox cannot write \
                     in them: {}{}",
                    walled.len(),
                    shown.join(", "),
                    if walled.len() > shown.len() { ", …" } else { "" }
                ),
            );
        }
    }
    Ok(project)
}
