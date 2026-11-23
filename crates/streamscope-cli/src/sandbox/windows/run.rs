//! One run of the Windows sandbox, before the launch: adjust the run for the
//! sandbox account, refuse a project the grant would reach too far from,
//! then grant the account the project (and what the client needs) and hold
//! what it must not change.

use anyhow::{Context, Result, bail};

use std::path::{Path, PathBuf};

use super::grants::{RunDirs, plan, private_root_of, refused_root, walled_to_report};
use super::{acl, prepare};
use crate::sandbox::{LaunchSpec, profiles};
use crate::progress::{Progress, grouped};
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
    // The run's private roots — the ones its grant makes private (or stops
    // on) and opens the way down: read by no other account, so a tool there
    // is granted as one in the profile is.
    let project = protect::resolve(&spec.project_root);
    let roots = run_roots(&granted_dirs(&spec.project_root, &project, &profile), &profile, &acl::record_path()?)?;
    let private = |p: &Path| roots.roots.iter().any(|r| within(p, r));
    // The developer's global git identity as git gives it in the project
    // (an `includeIf` for its folder applies), which the account's global
    // configuration then holds.
    let git_identity: Vec<(&'static str, String)> = ["user.name", "user.email"]
        .into_iter()
        .filter_map(|key| global_git_config(&spec.project_root, key).map(|v| (key, v)))
        .collect();
    // Not essential to the run: without a config folder, no identity.
    let git_global = crate::state::config_dir().ok().map(|d| d.join("sandbox-git"));
    let host = prepare::Host {
        profile: &profile,
        appdata: appdata.as_deref(),
        node_ca: node_ca.as_deref(),
        own_dir: own_dir.as_deref(),
        program: program.as_deref(),
        private: &private,
        git_identity: &git_identity,
        git_global: git_global.as_deref(),
    };
    prepare::prepare(spec, agent, &host)
}

/// The developer's global git configuration's value for `key` in `cwd`, its
/// includes followed (git reads none for `--global` unless asked), a
/// conditional one as it applies there; `None` when unset or git cannot be
/// run.
fn global_git_config(cwd: &Path, key: &str) -> Option<String> {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["config", "--global", "--includes", "--get", key])
        .current_dir(cwd)
        .stdin(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    for var in ["GIT_DIR", "GIT_WORK_TREE", "GIT_COMMON_DIR", "GIT_CONFIG_PARAMETERS", "GIT_CONFIG_COUNT"] {
        cmd.env_remove(var);
    }
    let out = cmd.output().ok()?;
    let v = String::from_utf8(out.stdout).ok()?.trim_end_matches(['\r', '\n']).to_string();
    (out.status.success() && !v.is_empty()).then_some(v)
}

/// The private roots of a run: for each folder its grant reaches outside the
/// profile ([`granted_dirs`]), the folder under the drive's root it sits in
/// ([`private_root_of`]) — the folder itself where the developer may not
/// re-permission that one (an administrator's) — which [`grant`] makes
/// private or stops on, and whose way down the plan opens; but a folder an
/// earlier `ssai` made private on its own keeps running as it did (`alone`,
/// with the root the doctor offers). One list, read by [`prepare`] (a tool
/// under one is granted) and [`grant`].
#[derive(Default)]
pub(super) struct RunRoots {
    pub roots: Vec<PathBuf>,
    pub alone: Vec<(PathBuf, PathBuf)>,
}

pub(super) fn run_roots(granted: &[&Path], profile: &Path, record: &Path) -> Result<RunRoots> {
    let mut out = RunRoots::default();
    for dir in granted {
        let Some(private) = private_root_of(dir, profile) else { continue };
        // Private already (one an administrator made so included): the root.
        // Else one the developer may not re-permission leaves the project
        // folder its own.
        // One whose list cannot even be read is the same.
        let state = acl::root_state(record, &private);
        let private = match state {
            Ok(acl::RootState::Private | acl::RootState::Pending) => private,
            _ if private.as_path() != *dir && (state.is_err() || acl::can_change(&private).is_err()) => dir.to_path_buf(),
            _ => private,
        };
        if out.roots.iter().any(|r| same_path(r, &private)) {
            continue;
        }
        // A takeover cut short is finished, whatever it left beneath.
        let state = acl::root_state(record, &private)?;
        if matches!(state, acl::RootState::Open(_)) && acl::private_alone(record, dir)? {
            out.alone.push((dir.to_path_buf(), private));
            continue;
        }
        out.roots.push(private);
    }
    // A root another granted folder makes private is no longer one left alone.
    let roots = out.roots.clone();
    out.alone.retain(|(_, root)| !roots.iter().any(|r| same_path(r, root)));
    Ok(out)
}

/// The folders a grant of the project at `root` reaches and checks: the
/// project, a linked worktree's main checkout (whose hooks and scripts run
/// outside the sandbox) and its git folder — but what [`refused_root`] refuses.
pub(super) fn granted_dirs<'a>(root: &'a Path, project: &'a ProjectGrants, profile: &Path) -> Vec<&'a Path> {
    let profile_text = profile.to_string_lossy();
    std::iter::once(root)
        .chain(project.stat_only.iter().map(PathBuf::as_path))
        .chain(project.extra_rw.iter().map(PathBuf::as_path))
        .filter(|d| refused_root(&d.to_string_lossy(), &profile_text).is_none())
        .collect()
}

fn same_path(a: &Path, b: &Path) -> bool {
    a.to_string_lossy().eq_ignore_ascii_case(&b.to_string_lossy())
}

/// `path` is `root` or under it, compared without case.
pub(super) fn within(path: &Path, root: &Path) -> bool {
    let (p, r) = (path.to_string_lossy().to_lowercase(), root.to_string_lossy().to_lowercase());
    let r = r.trim_end_matches('\\');
    p == r || p.starts_with(&format!("{r}\\"))
}

/// How a takeover is agreed to.
#[derive(Clone, Copy)]
pub(super) enum Consent<'a> {
    /// Asked at a terminal; refused with no terminal to ask at.
    Ask,
    /// Agreed by `--private-root`: what it changes is printed, then done.
    Flag,
    /// Agreed to the items a report already listed (the doctor's): those,
    /// and nothing found since, are changed.
    Listed(&'a [PathBuf]),
}

/// The developer's profile folder as the project root is spelled: real
/// (a junction or a short name followed), since the root is.
pub(super) fn profile_dir() -> Result<PathBuf> {
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

/// How many paths a list shown before a question names.
const SHOWN_PATHS: usize = 10;

/// Make sure the private root `root` (one of [`run_roots`], or a granted
/// folder every account may still write) is the developer's alone, as their
/// profile is. A folder every account may open or write — reading included:
/// the sandbox account belongs to those groups whatever it is granted — is
/// made so as `consent` says (asked at a terminal, `--private-root`, or the
/// doctor's confirmed list); otherwise the run stops, saying why. A takeover
/// cut short counts as not done. What a takeover changes is shown before it
/// is done, unless the doctor's report showed it: the protected folders and
/// files under the root inherit again, keeping their own entries but every
/// account's.
pub(super) fn ensure_private_root(record: &Path, root: &Path, consent: Consent<'_>, account_sid: &str, progress: &Progress) -> Result<()> {
    use std::io::IsTerminal as _;
    let why = match acl::root_state(record, root)? {
        acl::RootState::Private => return Ok(()),
        acl::RootState::Pending => "making it private to you was started and did not finish".to_string(),
        acl::RootState::Open(names) => format!(
            "its access list gives {} access — every account on this computer, or whoever creates a file there",
            names.join(", ")
        ),
    };
    if let Consent::Listed(items) = consent {
        let me = crate::win_acl::current_user_sid()?;
        let refused = acl::make_private_root(record, root, &me, account_sid, items, progress)?;
        return report_takeover(root, &refused, progress);
    }
    let found = acl::scan(root, None, progress)?;
    progress.pause();
    let mut text = format!(
        "{} is not private to you: {why}, the sandbox's account included, so the sandbox cannot confine the \
         agent there. It runs once {} is private to you, as your home folder is: it then stops inheriting from \
         the folder above it and keeps no access for every account (reading included); you, SYSTEM and the \
         administrators keep yours, and every project in it is private at once",
        root.display(),
        root.display()
    );
    if !found.protected.is_empty() {
        text.push_str(&format!(
            ". {} folder(s) and file(s) in it inherit nothing; they will inherit again, keeping their own entries \
             but every account's: {}",
            grouped(found.protected.len() as u64),
            shown(&found.protected)
        ));
    }
    if !found.broad.is_empty() {
        text.push_str(&format!(
            ". {} folder(s) and file(s) in it give every account access by an entry of their own; that entry is \
             removed: {}",
            grouped(found.broad.len() as u64),
            shown(&found.broad)
        ));
    }
    for (dir, error) in &found.skipped {
        text.push_str(&format!(
            ". Under {} no item that inherits nothing is changed (its project's record cannot be read: {error}); \
             what inherits there follows {} as everything else does",
            dir.display(),
            root.display()
        ));
    }
    if matches!(consent, Consent::Flag) {
        crate::ui::note("", &text);
    }
    if matches!(consent, Consent::Ask) {
        if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
            bail!("{text}. Pass --private-root to make it so.");
        }
        crate::ui::warn("", &text);
        if !crate::commands::session::confirm_no(&format!("Make {} private to you?", root.display()))? {
            bail!("the Windows sandbox did not run: {} stays open to every account", root.display());
        }
    }
    let me = crate::win_acl::current_user_sid()?;
    let items: Vec<PathBuf> = found.protected.into_iter().chain(found.broad).collect();
    let refused = acl::make_private_root(record, root, &me, account_sid, &items, progress)?;
    report_takeover(root, &refused, progress)
}

/// After a takeover of `root`: the summary, the items Windows refused, and
/// how to undo it.
fn report_takeover(root: &Path, refused: &[(PathBuf, String)], progress: &Progress) -> Result<()> {
    progress.finish(format!("✓ {} is private to you", root.display()));
    if !refused.is_empty() {
        let names: Vec<PathBuf> = refused.iter().map(|(p, _)| p.clone()).collect();
        crate::ui::warn(
            "",
            format_args!(
                "{} item(s) kept a list of their own (yours may not change it — the first: {}): {}",
                grouped(refused.len() as u64),
                refused[0].1,
                shown(&names)
            ),
        );
    }
    crate::ui::note(
        "",
        format_args!(
            "{} is private to you now (revoke keeps it so); `icacls \"{}\" /inheritance:e` makes it inherit from \
             the folder above it again",
            root.display(),
            root.display()
        ),
    );
    Ok(())
}

/// The first paths of `paths`, then how many more.
pub(super) fn shown(paths: &[PathBuf]) -> String {
    let mut out: Vec<String> = paths.iter().take(SHOWN_PATHS).map(|p| p.display().to_string()).collect();
    if paths.len() > SHOWN_PATHS {
        out.push(format!("and {} more", grouped((paths.len() - SHOWN_PATHS) as u64)));
    }
    out.join(", ")
}

/// A `--ca-file` trust bundle where the sandbox account can read it: in the
/// developer's cache, named for its content (the same CAs, the same file —
/// so the grant record does not grow by a file per run), never removed: it
/// holds only public certificates. Shared rather than private, so the
/// account's read entry on it applies.
pub fn shared_ca_bundle(pem: &[u8]) -> Result<PathBuf> {
    prepare::place_named(&crate::state::cache_dir()?.join("sandbox-ca"), "pem", pem)
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
    let granted = granted_dirs(root, &project, &profile);
    let record = acl::record_path()?;
    let progress = Progress::stderr();
    let consent = if spec.private_root { Consent::Flag } else { Consent::Ask };
    // Each granted folder outside the profile under its private root, made
    // the developer's alone once for every project under it.
    let RunRoots { roots: mut private_roots, alone } = run_roots(&granted, &profile, &record)?;
    for private in &private_roots {
        ensure_private_root(&record, private, consent, account_sid, &progress)?;
    }
    // A granted folder every account may still write — by an entry of its
    // own, or one inherited from a folder above it in the profile — is made
    // private on its own, the same way: the sandbox account would write there
    // whatever it is granted.
    for dir in &granted {
        // Its own entry for every account or a creator's, too: under a root
        // already private, nothing above removes it.
        let pending = acl::root_state(&record, dir)? == acl::RootState::Pending;
        if alone.iter().any(|(d, _)| d.as_path() == *dir)
            || (!pending && acl::broad_writers(dir)?.is_empty() && !acl::names_own_broad(dir)?)
        {
            continue;
        }
        ensure_private_root(&record, dir, consent, account_sid, &progress)?;
        private_roots.push(dir.to_path_buf());
    }
    // A folder made private on its own by an earlier `ssai` holds no
    // `OWNER RIGHTS` entry: the agent, owner of what it creates there, can
    // still change who may open it.
    for (dir, private) in &alone {
        let fix = if same_path(dir, private) {
            "makes it private to you as your home folder is".to_string()
        } else {
            format!("makes {} private to you instead", private.display())
        };
        crate::ui::warn(
            "",
            format_args!(
                "{} is private to you on its own, and every account may still read it; the agent can change who may \
                 open the files it creates there — `ssai sandbox doctor --fix` {fix}",
                dir.display()
            ),
        );
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
    project.prepare().context("prepare the project's protected git folders")?;
    let aces = plan(root, &project, dirs, &profile, &private_roots);
    let applied = acl::apply(&record, account_sid, root, &aces, &progress)?;
    if applied.walked > 0 {
        progress.finish(format!("✓ the sandbox's access applied ({} items)", grouped(applied.walked)));
    }
    // What the grant does not reach — an item that inherits nothing, one
    // whose list was written before the grant — and an item giving every
    // account access by an entry of its own, reported when the project is
    // first granted; the doctor repairs both.
    if applied.changed.iter().any(|p| p == root) {
        let found = acl::scan(root, Some(account_sid), &progress)?;
        progress.pause();
        let walled = walled_to_report(found.protected, &project);
        let missed: Vec<PathBuf> = walled.into_iter().chain(found.stale).collect();
        if !found.broad.is_empty() {
            crate::ui::warn(
                "",
                format_args!(
                    "{} item(s) in the project give every account access (or whoever creates a file there full \
                     control) by an entry of their own: {} — `ssai sandbox doctor --fix` removes those entries",
                    grouped(found.broad.len() as u64),
                    shown(&found.broad)
                ),
            );
        }
        if !missed.is_empty() {
            crate::ui::warn(
                "",
                format_args!(
                    "{} item(s) in the project keep an access list the sandbox's grant does not reach, so the \
                     agent cannot open them: {} — `ssai sandbox doctor --fix` gives them what the project grants",
                    grouped(missed.len() as u64),
                    shown(&missed)
                ),
            );
        }
    }
    Ok(project)
}
