//! Local state under `${XDG_CONFIG_HOME:-~/.config}/streamscopeai/`
//! (`%LOCALAPPDATA%\streamscopeai\config\` on Windows):
//! `hosts.json` (token pairs per gateway), `manifest.json` (what we wrote
//! where, with per-leaf ownership), and `backups/` (pre-write copies).
//! Directory is 0700, files 0600 (owner-only access lists on Windows) — they
//! hold tokens and key plaintext
//! (the same plaintext the provisioned tool configs themselves hold).

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

pub fn config_dir() -> Result<PathBuf> {
    // Windows: the LOCAL AppData, never the roaming one a domain profile
    // copies to its server — these files hold tokens and gateway keys.
    // On Windows `…\streamscopeai\config`, beside (never around) its cache.
    Ok(match xdg_dir("XDG_CONFIG_HOME", !cfg!(windows)) {
        Some(x) => x.join("streamscopeai"),
        None => match windows_appdata(AppData::Local)? {
            Some(local) => local.join("streamscopeai").join("config"),
            None => home_dir()?.join(".config").join("streamscopeai"),
        },
    })
}

/// The CLI's own cache, `${XDG_CACHE_HOME:-~/.cache}/streamscopeai`
/// (`%LOCALAPPDATA%\streamscopeai\cache` on Windows). A relative
/// `XDG_CACHE_HOME` is ignored, as the XDG spec requires.
pub fn cache_dir() -> Result<PathBuf> {
    let default_dir = match windows_appdata(AppData::Local)? {
        Some(local) => local.join("streamscopeai").join("cache"),
        None => home_dir()?.join(".cache").join("streamscopeai"),
    };
    Ok(cache_dir_in(std::env::var_os("XDG_CACHE_HOME"), &default_dir))
}

/// The folder an XDG variable names, when it names one: a non-empty value,
/// absolute unless `relative_ok`. A relative `XDG_CONFIG_HOME` is taken on
/// Unix — keep it so: the shell installer reads it the same way, and the two
/// must agree on where the gateway roots are — never on Windows, where a Git
/// Bash `/c/Users/…` has no drive and is relative.
fn xdg_dir(var: &str, relative_ok: bool) -> Option<PathBuf> {
    xdg_value(std::env::var_os(var), relative_ok)
}

/// [`xdg_dir`] for a value.
fn xdg_value(value: Option<std::ffi::OsString>, relative_ok: bool) -> Option<PathBuf> {
    let dir = PathBuf::from(value.filter(|v| !v.is_empty())?);
    (relative_ok || dir.is_absolute()).then_some(dir)
}

/// [`cache_dir`] for an `XDG_CACHE_HOME` value and the platform's default
/// cache folder (used when the value is absent or relative).
pub fn cache_dir_in(xdg_cache_home: Option<std::ffi::OsString>, default_dir: &Path) -> PathBuf {
    match xdg_value(xdg_cache_home, false) {
        Some(xdg) => xdg.join("streamscopeai"),
        None => default_dir.to_path_buf(),
    }
}

/// The two AppData folders of a Windows profile.
#[derive(Clone, Copy)]
enum AppData {
    Roaming,
    Local,
}

/// The AppData folder `which` on Windows — its variable (`%APPDATA%`,
/// `%LOCALAPPDATA%`), else where Windows puts it in the profile (an
/// environment stripped of the variable still names the same folder);
/// `None` off Windows. The one place these folders are read.
fn windows_appdata(which: AppData) -> Result<Option<PathBuf>> {
    if !cfg!(windows) {
        return Ok(None);
    }
    let (var, under_profile) = match which {
        AppData::Roaming => ("APPDATA", "AppData/Roaming"),
        AppData::Local => ("LOCALAPPDATA", "AppData/Local"),
    };
    Ok(Some(match std::env::var_os(var).filter(|v| !v.is_empty()) {
        Some(v) => PathBuf::from(v),
        None => join_relative(&home_dir()?, under_profile),
    }))
}

/// The user's home: `$HOME`, `%USERPROFILE%` on Windows (where the tools the
/// CLI provisions keep their `~\.<tool>` folders).
pub fn home_dir() -> Result<PathBuf> {
    #[cfg(windows)]
    const HOME_VAR: &str = "USERPROFILE";
    #[cfg(not(windows))]
    const HOME_VAR: &str = "HOME";
    std::env::var_os(HOME_VAR)
        .filter(|h| !h.is_empty())
        .map(PathBuf::from)
        .with_context(|| format!("{HOME_VAR} is not set"))
}

/// Path to the captured gateway CA bundle — written by the installer (and
/// re-usable by provisioning) when the gateway presents a private/self-signed
/// certificate. Returns the path only when the file exists.
pub fn gateway_ca_file() -> Option<PathBuf> {
    let p = config_dir().ok()?.join("gateway-ca.pem");
    p.is_file().then_some(p)
}

/// Where the installer keeps each private gateway's root, one `.pem` file per
/// gateway (a reinstall from it replaces its own); `gateway-ca.pem` is all of
/// them together, for the tools that take one file.
pub fn gateway_ca_dir() -> Result<PathBuf> {
    Ok(config_dir()?.join("gateway-ca.d"))
}

/// The root files the CLI trusts: every `.pem` in [`gateway_ca_dir`] (none
/// while that folder does not exist).
pub fn gateway_ca_files() -> Vec<PathBuf> {
    let Ok(dir) = gateway_ca_dir() else { return Vec::new() };
    match std::fs::read_dir(&dir) {
        Ok(entries) => entries
            .filter_map(|e| e.ok().map(|e| e.path()))
            .filter(|p| p.extension().is_some_and(|x| x == "pem"))
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Additive trust bundle: the system CA set PLUS the captured gateway chain,
/// written by the installer alongside `gateway-ca.pem`. `SSL_CERT_FILE` /
/// `REQUESTS_CA_BUNDLE` point here — never the gateway-only file, which would
/// REPLACE the whole trust store and break every other CA (e.g. a corporate
/// root that already validates the gateway). Returns None when no gateway CA
/// was captured (public gateway).
pub fn gateway_bundle_file() -> Option<PathBuf> {
    let p = config_dir().ok()?.join("gateway-bundle.pem");
    p.is_file().then_some(p)
}

/// Where a command reads/writes its provisioning state. Login tokens, the
/// gateway CA, and the update-check stay GLOBAL (machine-level, `config_dir()`);
/// only the manifest + pre-write backups follow the scope, so a project can be
/// provisioned and fully managed locally.
#[derive(Debug, Clone)]
pub enum ManifestScope {
    Global,
    /// `root` is the project directory that holds (or will hold) `.streamscopeai/`.
    Project(PathBuf),
}

/// Resolved base + project root for a [`ManifestScope`].
#[derive(Debug, Clone)]
pub struct Paths {
    /// Holds `manifest.json` + `backups/` — `config_dir()` (global) or
    /// `<root>/.streamscopeai` (project).
    base: PathBuf,
    /// The project root (where project-local configs are written). `None` for
    /// the global scope.
    root: Option<PathBuf>,
}

impl Paths {
    pub fn for_scope(scope: &ManifestScope) -> Result<Self> {
        Ok(match scope {
            ManifestScope::Global => Self { base: config_dir()?, root: None },
            ManifestScope::Project(root) => {
                Self { base: root.join(".streamscopeai"), root: Some(root.clone()) }
            }
        })
    }
    pub fn base(&self) -> &Path {
        &self.base
    }
    /// The project root, or `None` for the global scope.
    pub fn project_root(&self) -> Option<&Path> {
        self.root.as_deref()
    }
    pub fn manifest(&self) -> PathBuf {
        self.base.join("manifest.json")
    }
    /// Create the state dir before the first write. For a project scope, also
    /// drop a `.gitignore` (`*`) — the manifest holds key plaintext, so the
    /// directory must never be committed.
    pub fn ensure(&self) -> Result<()> {
        ensure_dir(&self.base)?;
        if self.root.is_some() {
            let gi = self.base.join(".gitignore");
            if !gi.exists() {
                std::fs::write(&gi, "*\n")
                    .with_context(|| format!("write {}", gi.display()))?;
            }
        }
        Ok(())
    }
}

/// Git-ignore the provisioned tool configs in a project — they can carry the
/// gateway key (a gateway-mode `ANTHROPIC_AUTH_TOKEN`, a `GEMINI_API_KEY` env
/// companion, …), so a `git add .` must not commit a live credential. Appends
/// each path (relative to `root`) to the project's root `.gitignore` under a
/// marker header, idempotently; creates the file if absent. Returns the paths
/// it newly added (for a one-line notice). A plain file (not 0600) — it carries
/// no secret itself.
pub fn ensure_gitignored(root: &Path, entries: &[String]) -> Result<Vec<String>> {
    if entries.is_empty() {
        return Ok(Vec::new());
    }
    let gi = root.join(".gitignore");
    let existing = std::fs::read_to_string(&gi).unwrap_or_default();
    let have: Vec<&str> = existing.lines().map(str::trim).collect();
    let missing: Vec<String> = entries
        .iter()
        .filter(|e| !have.contains(&e.as_str()))
        .cloned()
        .collect();
    if missing.is_empty() {
        return Ok(Vec::new());
    }
    const HEADER: &str = "# streamscope-provisioned tool configs (may contain credentials)";
    let has_header = have.contains(&HEADER);
    let mut out = existing;
    if !out.is_empty() && !out.ends_with('\n') {
        out.push('\n');
    }
    if !has_header {
        out.push_str(HEADER);
        out.push('\n');
    }
    for m in &missing {
        out.push_str(m);
        out.push('\n');
    }
    std::fs::write(&gi, out).with_context(|| format!("write {}", gi.display()))?;
    Ok(missing)
}

/// What a commit in the repository holding `target` would do with it.
#[derive(Debug, PartialEq, Eq)]
pub enum GitExposure {
    /// No repository above it.
    Outside,
    /// Untracked and ignored: no commit picks it up.
    Ignored,
    /// Untracked and not ignored: `git add -A` would commit it.
    Exposed,
    /// Tracked: its next commit carries what is written into it. A
    /// `.gitignore` line does nothing for it.
    Tracked,
    /// Tracked, and every tracked path it names marked `skip-worktree` or
    /// `assume-unchanged` in this clone's index (by the user, a sparse
    /// checkout or `core.ignoreStat`). Refused like [`Self::Tracked`]: git's
    /// own FAQ says neither mark keeps a change out of git — only the refusal
    /// names the mark.
    Marked,
    /// A repository is above it, but git could not say (git missing, a
    /// repository git refuses).
    Unknown(String),
}

/// A file the CLI writes a secret into, or one of its state directories with
/// the entries it writes there — a name ending in `/` a directory of its own
/// (the backups). A state directory is judged by those entries, never by a
/// stand-in: an ignore rule may treat names differently (`!*.json`), and a
/// file of the user's beside them (a certificate kept in a dotfiles
/// repository) is not ours to judge.
#[derive(Clone, Copy)]
pub enum GitTarget<'a> {
    File(&'a Path),
    State { dir: &'a Path, entries: &'a [&'a str] },
}

/// What the CLI writes in its global state directory (the installer's
/// certificates beside them are not its to judge).
const GLOBAL_STATE: &[&str] = &[
    "hosts.json",
    "tool-keys.json",
    "tool-keys.json.lock",
    "manifest.json",
    "manifest.json.old",
    "backups/",
    "sandbox-user.json",
    "sandbox-grants.json",
    "sandbox-profile.json",
    "update-check.json",
    "sandbox-run.lock",
];
/// What it writes in a project's.
const PROJECT_STATE: &[&str] = &["manifest.json", "manifest.json.old", "backups/"];

impl GitTarget<'_> {
    fn path(&self) -> &Path {
        match self {
            Self::File(p) | Self::State { dir: p, .. } => p,
        }
    }
}

/// The directory to run git in for `path` (its nearest existing ancestor —
/// itself included — symlinks resolved: a directory or file linked into a
/// repository is in it) and `path` re-rooted there — or `None` when no `.git`
/// is above it, so no git is started (a stub git would offer to install
/// itself). A repository named only by `GIT_DIR` (a bare dotfiles repository
/// used through an alias) has no `.git` above the file and is not seen.
fn git_location(path: &Path) -> Option<(PathBuf, PathBuf)> {
    let existing = path.ancestors().find(|d| d.exists())?;
    let rest = path.strip_prefix(existing).ok()?;
    let canonical = dunce::canonicalize(existing).ok()?;
    // `join("")` would add a trailing separator, which names a directory.
    let resolved = if rest.as_os_str().is_empty() { canonical } else { canonical.join(rest) };
    // Git runs in the target itself when it is a directory — a state
    // directory may be a repository's own top level — else in its parent.
    let dir = resolved.ancestors().find(|d| d.is_dir())?.to_path_buf();
    dir.ancestors().any(|d| d.join(".git").exists()).then_some((dir, resolved))
}

/// Every variable git reads to pick a repository, an index, an object store
/// or a configuration instead of discovering them (`git rev-parse
/// --local-env-vars`, plus the ceiling): a probe run from a git hook, or under
/// a user's own settings, must answer for the repository above the file.
pub(crate) const GIT_REPOSITORY_VARS: &[&str] = &[
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_CEILING_DIRECTORIES",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_COUNT",
    "GIT_CONFIG_PARAMETERS",
    "GIT_DIR",
    "GIT_GRAFT_FILE",
    "GIT_IMPLICIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_NO_REPLACE_OBJECTS",
    "GIT_OBJECT_DIRECTORY",
    "GIT_PREFIX",
    "GIT_REPLACE_REF_BASE",
    "GIT_SHALLOW_FILE",
    "GIT_WORK_TREE",
];

/// A git probe in `dir`: no fsmonitor (a repository's own config would run
/// it), so it may answer for a repository another user owns; and the
/// repository the walk above found — across a mount, never one this process
/// was handed.
fn git_in(dir: &Path) -> std::process::Command {
    let mut cmd = std::process::Command::new("git");
    cmd.args(["-c", "core.fsmonitor=false", "-c", "safe.directory=*"])
        .current_dir(dir)
        .env("GIT_DISCOVERY_ACROSS_FILESYSTEM", "1")
        .stdin(std::process::Stdio::null());
    for var in GIT_REPOSITORY_VARS {
        cmd.env_remove(var);
    }
    cmd
}

/// Why git failed, in its own words (its first line names the fix).
fn git_failure(what: &str, out: &std::process::Output) -> String {
    let said = String::from_utf8_lossy(&out.stderr);
    match said.lines().find(|l| !l.trim().is_empty()) {
        Some(line) => format!("git {what} exited with {}: {}", out.status, line.trim()),
        None => format!("git {what} exited with {}", out.status),
    }
}

/// Each entry git tracks of `paths` — for a directory, of what is in it —
/// as whether this clone's index marks it `skip-worktree` or
/// `assume-unchanged`.
fn git_tracked(dir: &Path, paths: &[PathBuf]) -> Result<Vec<bool>, String> {
    // Taken literally, never as globs (`check-ignore` below reads path names,
    // not pathspecs, and refuses the flag). `-v` tags each entry: `S` for
    // skip-worktree, a lowercase letter for assume-unchanged.
    match git_in(dir).args(["--literal-pathspecs", "ls-files", "-v", "-z", "--"]).args(paths).output() {
        Ok(out) if out.status.success() => Ok(out
            .stdout
            .split(|b| *b == 0)
            .filter(|e| !e.is_empty())
            .map(|e| e[0] == b'S' || e[0].is_ascii_lowercase())
            .collect()),
        Ok(out) => Err(git_failure("ls-files", &out)),
        Err(e) => Err(format!("git could not be run: {e}")),
    }
}

/// Whether git ignores every one of `paths`.
fn git_ignores_all(dir: &Path, paths: &[PathBuf]) -> Result<bool, String> {
    // It names each ignored path once, on a line of its own (a name holding a
    // newline comes back quoted on one); exit 1 is "none".
    match git_in(dir).args(["check-ignore", "--"]).args(paths).output() {
        Ok(out) if out.status.code() == Some(0) => {
            Ok(out.stdout.split(|b| *b == b'\n').filter(|l| !l.is_empty()).count() == paths.len())
        }
        Ok(out) if out.status.code() == Some(1) => Ok(false),
        Ok(out) => Err(git_failure("check-ignore", &out)),
        Err(e) => Err(format!("git could not be run: {e}")),
    }
}

/// Ask git what a commit would do with `target`: two git runs, whatever it
/// holds.
pub fn git_exposure(target: GitTarget) -> GitExposure {
    let Some((dir, full)) = git_location(target.path()) else {
        return GitExposure::Outside;
    };
    // What git is asked about: the file, or each entry of the state directory
    // — a directory entry through two names inside it, as an ignore rule may
    // tell names apart by their extension.
    let (tracked, probes): (Vec<PathBuf>, Vec<PathBuf>) = match target {
        GitTarget::File(_) => (vec![full.clone()], vec![full]),
        GitTarget::State { entries, .. } => {
            let mut tracked = Vec::new();
            let mut probes = Vec::new();
            for e in entries {
                match e.strip_suffix('/') {
                    Some(sub) => {
                        let d = full.join(sub);
                        probes.push(d.join("streamscopeai-probe.json"));
                        probes.push(d.join("streamscopeai-probe"));
                        tracked.push(d);
                    }
                    None => {
                        tracked.push(full.join(e));
                        probes.push(full.join(e));
                    }
                }
            }
            (tracked, probes)
        }
    };
    let tracked = match git_tracked(&dir, &tracked) {
        Ok(t) => t,
        Err(why) => return GitExposure::Unknown(why),
    };
    if tracked.iter().any(|marked| !marked) {
        return GitExposure::Tracked;
    }
    if !tracked.is_empty() {
        return GitExposure::Marked;
    }
    match git_ignores_all(&dir, &probes) {
        Ok(true) => GitExposure::Ignored,
        Ok(false) => GitExposure::Exposed,
        Err(why) => GitExposure::Unknown(why),
    }
}

/// One line of an ignore file matching exactly `rel` (a path relative to the
/// work tree, `/`-separated): anchored, every wildcard and the characters git
/// reads specially escaped, a directory with its trailing `/`.
fn exclude_pattern(rel: &str, dir: bool) -> String {
    let mut out = String::from("/");
    for (i, c) in rel.chars().enumerate() {
        if matches!(c, '\\' | '*' | '?' | '[' | ' ') || (i == 0 && matches!(c, '!' | '#')) {
            out.push('\\');
        }
        out.push(c);
    }
    if dir {
        out.push('/');
    }
    out
}

/// Ignore `target` in its repository's own `info/exclude` — read by this
/// clone alone, never committed — and check that git now reads it ignored.
fn exclude_locally(target: GitTarget) -> Result<()> {
    let (dir, full) = git_location(target.path()).context("no repository above it")?;
    let ask = |args: &[&str]| -> Result<String> {
        let out = git_in(&dir).args(args).output().context("git could not be run")?;
        anyhow::ensure!(out.status.success(), "{}", git_failure(&args.join(" "), &out));
        Ok(String::from_utf8_lossy(&out.stdout).trim_end_matches(['\r', '\n']).to_string())
    };
    let top = dunce::canonicalize(ask(&["rev-parse", "--show-toplevel"])?)?;
    let exclude = dir.join(ask(&["rev-parse", "--git-path", "info/exclude"])?);
    let rel = full.strip_prefix(&top).with_context(|| format!("{} is outside {}", full.display(), top.display()))?;
    let rel = rel.components().map(|c| c.as_os_str().to_string_lossy()).collect::<Vec<_>>().join("/");
    // A state directory is excluded entry by entry, never whole: a file of the
    // user's beside them stays theirs to commit.
    let lines: Vec<String> = match target {
        GitTarget::File(_) => vec![exclude_pattern(&rel, false)],
        GitTarget::State { entries, .. } => entries
            .iter()
            .map(|e| {
                let name = e.trim_end_matches('/');
                let path = if rel.is_empty() { name.to_string() } else { format!("{rel}/{name}") };
                exclude_pattern(&path, e.ends_with('/'))
            })
            .collect(),
    };
    let existing = match std::fs::read_to_string(&exclude) {
        Ok(s) => s,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => String::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", exclude.display())),
    };
    let missing: Vec<&String> = lines.iter().filter(|line| !existing.lines().any(|l| l == line.as_str())).collect();
    if !missing.is_empty() {
        // Appended, never rewritten: another process adding its own lines at
        // the same time keeps them (a header written twice is harmless).
        const HEADER: &str = "# streamscope: files holding a credential, kept out of this clone's commits";
        let mut out = String::new();
        if !existing.is_empty() && !existing.ends_with('\n') {
            out.push('\n');
        }
        if !existing.lines().any(|l| l == HEADER) {
            out.push_str(HEADER);
            out.push('\n');
        }
        for line in missing {
            out.push_str(line);
            out.push('\n');
        }
        if let Some(parent) = exclude.parent() {
            std::fs::create_dir_all(parent).with_context(|| format!("create {}", parent.display()))?;
        }
        use std::io::Write;
        std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&exclude)
            .and_then(|mut f| f.write_all(out.as_bytes()))
            .with_context(|| format!("write {}", exclude.display()))?;
    }
    match git_exposure(target) {
        GitExposure::Ignored => Ok(()),
        // Most often an ignore file of the repository re-includes it (`!…`),
        // which git reads over `info/exclude`.
        GitExposure::Exposed => bail!(
            "git still reads it as one a commit would pick up after {} — a rule in the repository's \
             .gitignore that re-includes it (`!…`) overrides that file: ignore it there",
            exclude.display()
        ),
        other => bail!("git reads it {other:?} after {}", exclude.display()),
    }
}

/// Whether the project's own `.gitignore` reaches `file`: it is under `root`
/// and no repository begins between them (a nested clone or a submodule
/// reads its own ignore files, not the project's).
pub fn covered_by_project_gitignore(root: &Path, file: &Path) -> bool {
    // No repository above the file: there is nothing to be covered from.
    let (Ok(root), Some((_, file))) = (dunce::canonicalize(root), git_location(file)) else {
        return false;
    };
    file.starts_with(&root)
        && !file
            .ancestors()
            .skip(1)
            .take_while(|d| *d != root)
            .any(|d| d.join(".git").exists())
}

/// Keep `target` — a file the CLI is about to write a secret into, or one of
/// its state directories — out of every commit, before anything is written:
/// refuse one git tracks or cannot answer for, and ignore an exposed one in
/// its repository's `info/exclude`. `left_to_gitignore` is a file the run
/// adds to its project's `.gitignore` once written, which covers it for
/// everyone ([`covered_by_project_gitignore`]), so it is not excluded
/// locally. A dry run only says what it would exclude. `remedy` ends a refusal: what the user can do instead.
pub fn keep_out_of_git(target: GitTarget, what: &str, remedy: &str, left_to_gitignore: bool, dry_run: bool) -> Result<()> {
    let shown = target.path().display();
    match git_exposure(target) {
        GitExposure::Outside | GitExposure::Ignored => Ok(()),
        GitExposure::Marked => bail!(
            "{shown} is tracked by git, so {what} could reach a commit — this clone's index marks it \
             skip-worktree or assume-unchanged, which git does not promise keeps a change out of one — \
             {remedy}"
        ),
        GitExposure::Tracked => {
            bail!("{shown} is tracked by git, so {what} would reach its next commit — {remedy}")
        }
        GitExposure::Unknown(why) => bail!(
            "{shown} is in a git repository git could not answer for ({why}), so {what} could not be \
             kept out of a commit — fix git there, or {remedy}"
        ),
        GitExposure::Exposed if left_to_gitignore => Ok(()),
        GitExposure::Exposed if dry_run => {
            // stderr: a config printed on stdout is what a user redirects.
            eprintln!("would add {shown} to its repository's .git/info/exclude (it would hold {what})");
            Ok(())
        }
        GitExposure::Exposed => {
            exclude_locally(target).with_context(|| format!("could not keep {shown} out of git, so {what} would reach its next commit"))?;
            eprintln!("Added {shown} to its repository's .git/info/exclude (it holds {what}).");
            Ok(())
        }
    }
}

/// Keep the CLI's global state directory — sign-in tokens, the device's
/// gateway keys, the global manifest and its backups — out of every commit.
/// `login`, `provision` and `sync` call it before they ask the gateway for
/// anything and refuse on its error; opening a session, which rotates the
/// tokens, calls it too and only warns, since refusing there would lose a
/// token the gateway already rotated.
pub fn keep_global_state_out_of_git() -> Result<()> {
    // Once per process: a command checking it before it opens its session
    // does not pay for it twice.
    static KEPT_OUT: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if KEPT_OUT.get().is_some() {
        return Ok(());
    }
    // No home to resolve it from (a CI runner): nothing can be written there.
    let Ok(dir) = config_dir() else {
        return Ok(());
    };
    keep_out_of_git(
        GitTarget::State { dir: &dir, entries: GLOBAL_STATE },
        "your sign-in tokens and gateway keys",
        &format!("take them out of the repository (`git rm -r --cached` the CLI's files in {})", dir.display()),
        false,
        false,
    )?;
    let _ = KEPT_OUT.set(());
    Ok(())
}

/// The same for a project's state directory (`.streamscopeai/`), created with
/// its `.gitignore` first, so a fresh project's needs nothing more. In every
/// mode: a dry run still records the keys it was given.
pub fn keep_project_state_out_of_git(paths: &Paths) -> Result<()> {
    if paths.project_root().is_none() {
        return Ok(());
    }
    paths.ensure()?;
    keep_out_of_git(
        GitTarget::State { dir: paths.base(), entries: PROJECT_STATE },
        "your gateway keys",
        &format!("take it out of the repository (`git rm -r --cached {}`)", paths.base().display()),
        false,
        false,
    )
}

/// Resolve this invocation's manifest scope. An explicit `--global` forces the
/// home-dir scope even inside a provisioned project; `--dir`/`--local` force a
/// project; otherwise walk up from the cwd for an existing `.streamscopeai/` (so
/// `sync`, `status`, … "just work" inside a provisioned project); else global.
pub fn resolve_scope(dir: Option<&Path>, local: bool, global: bool) -> Result<ManifestScope> {
    if global {
        return Ok(ManifestScope::Global);
    }
    if let Some(d) = dir {
        return Ok(ManifestScope::Project(project_root_path(d)?));
    }
    if local {
        return Ok(ManifestScope::Project(project_root_path(&std::env::current_dir()?)?));
    }
    let mut cur = std::env::current_dir()?;
    loop {
        if cur.join(".streamscopeai").is_dir() {
            return Ok(ManifestScope::Project(project_root_path(&cur)?));
        }
        if !cur.pop() {
            return Ok(ManifestScope::Global);
        }
    }
}

/// A project root as every path under it is recorded: canonical (symlinks
/// resolved) when it exists, else absolute. One spelling per directory, so
/// `--dir proj`, `--dir ./proj` and a `cd` into it name the same files.
fn project_root_path(dir: &Path) -> Result<PathBuf> {
    match dunce::canonicalize(dir) {
        Ok(p) => Ok(p),
        Err(_) => Ok(std::path::absolute(dir)?),
    }
}

/// Whether `a` and `b` name the same file: by canonical path when both exist
/// (a path recorded through a symlink still matches), else by spelling.
pub fn same_file(a: &Path, b: &Path) -> bool {
    match (dunce::canonicalize(a), dunce::canonicalize(b)) {
        (Ok(a), Ok(b)) => a == b,
        _ => a == b,
    }
}

/// Expand a leading `~/` (also `~\` on Windows) against the home directory.
/// On Windows a client that keeps its config in `%APPDATA%` there is found
/// there ([`windows_appdata_relocation`]): templates and the manifest carry
/// the Unix spelling on every platform.
pub fn expand_tilde(path: &str) -> Result<PathBuf> {
    if path == "~" {
        return home_dir();
    }
    // Only a path anchored at a user folder needs those folders (and HOME);
    // one anchored at a folder this platform lacks stays as written.
    if !UserDirs::anchored(path) {
        return Ok(PathBuf::from(path));
    }
    Ok(UserDirs::current()?.resolve(path).unwrap_or_else(|| PathBuf::from(path)))
}

/// The folders a client's files are found under: the home directory and, on
/// Windows only, the roaming and local AppData folders.
#[derive(Debug, Clone)]
pub(crate) struct UserDirs {
    pub(crate) home: PathBuf,
    /// `%APPDATA%`; `None` off Windows.
    pub(crate) appdata: Option<PathBuf>,
    /// `%LOCALAPPDATA%`; `None` off Windows.
    pub(crate) local_appdata: Option<PathBuf>,
}

impl UserDirs {
    /// This user's.
    pub fn current() -> Result<Self> {
        Ok(Self {
            home: home_dir()?,
            appdata: windows_appdata(AppData::Roaming)?,
            local_appdata: windows_appdata(AppData::Local)?,
        })
    }

    /// `rel`, a path relative to the home directory, as the file it names:
    /// under `%APPDATA%` for a client that keeps its config there on Windows
    /// ([`windows_appdata_relocation`]), else under the home directory.
    pub fn in_home(&self, rel: &str) -> PathBuf {
        if let Some(appdata) = &self.appdata
            && let Some(plain) = plain_relative(rel)
            && let Some(moved) = windows_appdata_relocation(&plain)
        {
            return join_relative(appdata, &moved);
        }
        join_relative(&self.home, rel)
    }

    /// Whether `path` is anchored at a user folder: `~/`, and on Windows
    /// `%APPDATA%/` and `%LOCALAPPDATA%/` (also with `\`). Elsewhere a `%…%`
    /// path names no folder and stays as written.
    pub(crate) fn anchored(path: &str) -> bool {
        strip_folder(path, "~").is_some()
            || (cfg!(windows) && ["%APPDATA%", "%LOCALAPPDATA%"].iter().any(|name| strip_folder(path, name).is_some()))
    }

    /// The file a client path names: `~/…` through [`Self::in_home`],
    /// `%APPDATA%/…` and `%LOCALAPPDATA%/…` under those folders (`None` where
    /// there are none), anything else as written.
    pub fn resolve(&self, path: &str) -> Option<PathBuf> {
        if let Some(rel) = strip_folder(path, "~") {
            Some(self.in_home(rel))
        } else if let Some(rel) = strip_folder(path, "%APPDATA%") {
            self.appdata.as_deref().map(|base| join_relative(base, rel))
        } else if let Some(rel) = strip_folder(path, "%LOCALAPPDATA%") {
            self.local_appdata.as_deref().map(|base| join_relative(base, rel))
        } else {
            Some(PathBuf::from(path))
        }
    }
}

/// `path` past the leading folder `name` and its separator (`/`, also `\\` on
/// Windows).
fn strip_folder<'a>(path: &'a str, name: &str) -> Option<&'a str> {
    // A variable name matches in any case on Windows, as Windows reads it.
    let head = path.get(..name.len())?;
    let same = if cfg!(windows) { head.eq_ignore_ascii_case(name) } else { head == name };
    let rest = &path[name.len()..];
    let mut chars = rest.chars();
    (same && chars.next().is_some_and(std::path::is_separator)).then_some(chars.as_str())
}


/// The clients that keep under `~/.config/<dir>` on Linux what Windows keeps
/// under `%APPDATA%`: their Unix folder, and the folder under `%APPDATA%`.
/// Each is that tool's documented Windows location. A client absent here
/// uses the same folder under the user's profile — checked on Windows 11 for
/// the two often taken for AppData clients: OpenCode 2 (`opencode debug
/// paths`: `%USERPROFILE%\.config\opencode`) and Crush (loads
/// `%USERPROFILE%\.config\crush\crush.json` FIRST, then `crushrc`, then
/// `%LOCALAPPDATA%\crush\crush.json`, its own data file).
const WINDOWS_APPDATA_DIRS: &[(&str, &str)] = &[
    (".config/goose", "Block/goose/config"),
    (".config/zed", "Zed"),
    (".config/Code/User", "Code/User"),
    (".config/Claude", "Claude"),
];

/// `rest` (a path relative to the home directory, `/`-separated) as a path
/// relative to `%APPDATA%`, when it is one of [`WINDOWS_APPDATA_DIRS`] or lies
/// in one.
fn windows_appdata_relocation(rest: &str) -> Option<String> {
    let rest = rest.trim_end_matches('/');
    // Folder names compare as Windows does: case aside.
    WINDOWS_APPDATA_DIRS.iter().find_map(|(unix, windows)| {
        let head = rest.get(..unix.len()).filter(|head| head.eq_ignore_ascii_case(unix))?;
        match &rest[head.len()..] {
            "" => Some((*windows).to_string()),
            tail => tail.strip_prefix('/').map(|tail| format!("{windows}/{tail}")),
        }
    })
}

/// `rel` with one spelling: `/`-separated (also from `\` on Windows), empty
/// and `.` parts dropped — so `~/.config//zed` and `~/./.config/zed` match
/// the same relocation as `~/.config/zed`. `None` for a path with a `..`
/// part: where it lands depends on more than its text, so it moves nowhere.
fn plain_relative(rel: &str) -> Option<String> {
    let parts: Vec<&str> =
        rel.split(std::path::is_separator).filter(|p| !p.is_empty() && *p != ".").collect();
    (!parts.contains(&"..")).then(|| parts.join("/"))
}

/// `base` joined with a relative path as templates and seeds write it (`/`
/// separators, also `\` on Windows), one component at a time — so on Windows
/// the result is spelled with `\` throughout rather than a mixed `C:\x\a/b`.
pub fn join_relative(base: &Path, rel: &str) -> PathBuf {
    // A part that would replace `base` rather than extend it — a root, a drive
    // (`C:`) — is dropped, as is an empty one; `.` and `..` keep their meaning.
    rel.split(std::path::is_separator)
        .filter(|part| {
            let mut parts = Path::new(part).components();
            matches!(
                (parts.next(), parts.next()),
                (Some(std::path::Component::Normal(_) | std::path::Component::CurDir | std::path::Component::ParentDir), None)
            )
        })
        .fold(base.to_path_buf(), |path, part| path.join(part))
}

/// Create `dir` (and its parents) and make it the owner's alone: 0700 on
/// Unix, an owner-only access list everything in it inherits on Windows.
fn ensure_dir(dir: &Path) -> Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    #[cfg(windows)]
    crate::win_acl::restrict_dir_to_owner(dir)?;
    Ok(())
}

/// Create `path` afresh for writing, readable by its owner alone before a
/// byte is written: mode 0600 at creation on Unix (no umask window); on
/// Windows opened exclusively (no other handle can open it meanwhile) and
/// given an owner-only access list through that handle. A file already there
/// (a leftover temp file) is removed first and the creation refuses one that
/// reappears — never written through, since whoever made it could read it.
/// For every file that holds a token or a gateway key.
pub fn create_private_file(path: &Path) -> Result<std::fs::File> {
    match std::fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("remove the leftover {}", path.display())),
    }
    create_new_private_file(path)
}

/// [`create_private_file`], refusing a file that already exists.
pub fn create_new_private_file(path: &Path) -> Result<std::fs::File> {
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt;
        // GENERIC_WRITE | WRITE_DAC: write the file and set its access list;
        // no other handle may open it meanwhile.
        opts.access_mode(0x4000_0000 | 0x0004_0000).share_mode(0);
    }
    let file = opts.open(path).with_context(|| format!("create {}", path.display()))?;
    #[cfg(windows)]
    if let Err(e) = crate::win_acl::restrict_file_to_owner(&file, path) {
        drop(file);
        let _ = std::fs::remove_file(path);
        return Err(e);
    }
    Ok(file)
}

/// Write a state file atomically, created owner-only ([`create_private_file`]
/// — these files hold tokens and key plaintext).
pub fn write_private(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().context("state path has no parent")?;
    ensure_dir(dir)?;
    let tmp = dir.join(format!(
        ".{}.tmp-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("state"),
        std::process::id()
    ));
    {
        use std::io::Write;
        let mut f = create_private_file(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)?;
    Ok(())
}

// ---------------------------------------------------------------------------
// hosts.json
// ---------------------------------------------------------------------------

/// Key: `"{origin}#{slug}"`.
pub type HostKey = String;

pub fn host_key(origin: &str, slug: &str) -> HostKey {
    format!("{origin}#{slug}")
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostEntry {
    /// Origin the user logged in with (any portal URL) — display + selector.
    pub origin: String,
    /// Canonical admin-API origin from OAuth discovery — every API call
    /// (refresh, revoke, portal provisioning, downloads) targets this.
    pub api_origin: String,
    pub tenant_slug: String,
    pub access_token: String,
    pub refresh_token: String,
    pub access_expires_at: chrono::DateTime<chrono::Utc>,
    pub user_email: Option<String>,
    pub device_name: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct HostsFile {
    #[serde(default)]
    pub hosts: BTreeMap<HostKey, HostEntry>,
}

impl HostsFile {
    pub fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("hosts.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("corrupt state file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Self::path()?, &serde_json::to_vec_pretty(self)?)
    }

    /// Resolve which gateway to act on: an explicit `--host` /
    /// `STREAMSCOPE_URL` selector (origin, origin#slug, or any portal URL),
    /// or the single stored entry.
    pub fn select(&self, selector: Option<&str>) -> Result<(HostKey, HostEntry)> {
        let selector = match selector {
            Some(s) => Some(s.to_string()),
            None => std::env::var("STREAMSCOPE_URL").ok().filter(|s| !s.is_empty()),
        };
        match selector {
            None => match self.hosts.len() {
                0 => bail!(crate::AuthRequired(
                    "not logged in — run: ssai login <portal-url>".into()
                )),
                1 => {
                    let (k, v) = self.hosts.iter().next().expect("len checked");
                    Ok((k.clone(), v.clone()))
                }
                _ => bail!(
                    "logged into several gateways — pick one with --host: {}",
                    self.hosts.keys().cloned().collect::<Vec<_>>().join(", ")
                ),
            },
            Some(sel) => {
                // Accept the exact key, a bare origin, or any URL whose
                // origin(+slug) matches a stored entry.
                if let Some(v) = self.hosts.get(&sel) {
                    return Ok((sel.clone(), v.clone()));
                }
                let parsed = crate::oauth::parse_portal_url(&sel).ok();
                let matches: Vec<(&HostKey, &HostEntry)> = self
                    .hosts
                    .iter()
                    .filter(|(_, v)| match &parsed {
                        Some((origin, Some(slug))) => {
                            v.origin == *origin && v.tenant_slug == *slug
                        }
                        Some((origin, None)) => v.origin == *origin,
                        None => v.origin == sel || v.tenant_slug == sel,
                    })
                    .collect();
                match matches.len() {
                    0 => bail!(crate::AuthRequired(format!(
                        "no stored login matches {sel:?} — run: ssai login <portal-url>"
                    ))),
                    1 => Ok((matches[0].0.clone(), matches[0].1.clone())),
                    _ => bail!("selector {sel:?} matches several logins — use origin#slug"),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// manifest.json — what we wrote where
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManifestKey {
    pub id: uuid::Uuid,
    pub name: String,
    /// Plaintext of the gateway key the configs embed — required to
    /// re-render offline (`sync`) without minting a replacement. Same
    /// exposure as the tool config files themselves; 0600.
    pub plaintext: String,
    pub forward_auth: bool,
}

/// One leaf the render contributed to a file: a format-specific path
/// (JSON pointer / dotted TOML path / env var name) plus the hash of the
/// value we wrote — used to remove only-unmodified leaves on a later run.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OwnedLeaf {
    pub path: String,
    /// Set when this records ONE entry of a keyed array (the template's
    /// `keyed_arrays`): `path` is the array, and this names the entry. Absent,
    /// `path` names a leaf — for a keyed array's path, the whole array, as a
    /// manifest written before the array was keyed recorded it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<OwnedEntry>,
    pub value_hash: String,
}

/// The entry of a keyed array a record owns. The identity FIELD is kept
/// beside its value so the entry can still be found — and removed while
/// unedited — once the template no longer declares the array keyed.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OwnedEntry {
    pub key: String,
    pub id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedFile {
    pub path: String,
    pub format: String,
    pub owned: Vec<OwnedLeaf>,
    /// Hash of the whole file right after our write — `status` reports
    /// "edited since provisioning" when it no longer matches.
    pub file_hash: String,
}

/// Where one config entry stands in a file, in the writer's own path grammar
/// for that file's format: the subtree at `path`, or — with `entry` — the one
/// entry of the keyed array at `path`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntryRoot {
    pub path: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub entry: Option<OwnedEntry>,
}

/// The entry a local MCP server was written as in one file.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalMcpEntry {
    /// The file, as its [`ManagedFile`] names it.
    pub file: String,
    #[serde(flatten)]
    pub root: EntryRoot,
    /// Whether nothing stood at `root` when the server was first written
    /// there: the entry is then ours whole, and goes whole — with whatever
    /// the developer pasted into it — when the server is withdrawn. An entry
    /// the file already held is the developer's: only the leaves we wrote and
    /// they left unchanged ever leave it.
    pub created: bool,
}

/// A local MCP server selected for a client, and the entries it was written
/// as (none where the client's config does not carry it).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ManagedLocalMcp {
    pub id: uuid::Uuid,
    pub slug: String,
    pub entries: Vec<LocalMcpEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ManagedClient {
    pub client_id: String,
    pub template_index: usize,
    /// Integration mode this client was provisioned in: `"gateway"` (a
    /// proxy-issued `sk-` key + curated routes) or `"byok"` (a `vk-` key bound
    /// to a BYOK downstream, native auth/model passed through). One provision
    /// run can mix modes across clients.
    pub mode: String,
    /// The LLM provider (gateway) or BYOK downstream (byok) this client's
    /// config renders against. `None` for MCP-only clients.
    pub provider_id: Option<uuid::Uuid>,
    /// Which key in the workspace `keys` pool this client embeds — a shared
    /// gateway `sk-` across gateway clients, or a per-downstream `vk-`.
    pub key_id: Option<uuid::Uuid>,
    /// The MCP virtual servers wired into THIS client's config, as a set —
    /// `sync` re-requests the same one for it. It belongs to the client, like its
    /// template index: a run naming other clients chooses for those and leaves
    /// this one's alone.
    pub mcp_server_ids: Vec<uuid::Uuid>,
    /// The local MCP servers (started by this machine) selected for THIS
    /// client, as a set — `sync` re-requests the ones the workspace is still
    /// handed, and names by its slug one it no longer is.
    pub mcp_local_servers: Vec<ManagedLocalMcp>,
    /// The whole launch each local MCP server was last written with, by slug
    /// (the administrator's environment values, the command, its arguments):
    /// what `sync` compares the gateway's answer to, so a launch an
    /// administrator changed is printed when it is applied. Empty for a client
    /// whose config carries none.
    pub mcp_local_commands: BTreeMap<String, String>,
    pub files: Vec<ManagedFile>,
    pub last_provisioned: chrono::DateTime<chrono::Utc>,
    /// The command that launches this client (e.g. `claude`) — persisted so
    /// `ssai run` resolves the binary fully offline, without a profile
    /// round-trip. `None` for GUI/curl clients with no launch command.
    pub launch_command: Option<String>,
    /// Its template's `usable_as_tool`, as the gateway last handed it: `ssai
    /// run --sandbox` of another client of the same manifest and workspace
    /// then reaches this client's config. A record written before the field
    /// reads `false` until the next `sync` rewrites it.
    #[serde(default)]
    pub usable_as_tool: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct WorkspaceManifest {
    pub workspace_id: Option<uuid::Uuid>,
    /// Keys the managed clients embed, by key id: each tool its own — a
    /// gateway `sk-`, or a `vk-` bound to its BYOK downstream (an out-of-band
    /// `STREAMSCOPE_GATEWAY_KEY` is the one key several tools share). Each
    /// holds the plaintext needed to re-render offline (`sync`) without
    /// re-minting.
    pub keys: BTreeMap<uuid::Uuid, ManifestKey>,
    /// SHA-256 of the out-of-band key (`STREAMSCOPE_GATEWAY_KEY`) the last
    /// run spliced — `sync` rewrites when the env var rotates even though the
    /// server-side bundle etag (which never sees an external key) is
    /// unchanged. `None` when the key is gateway-minted.
    pub external_key_sha256: Option<String>,
    /// Per-group bundle etag for no-op detection — keyed by a group signature
    /// (`mode:provider`). A group whose etag is unchanged is skipped.
    pub group_etags: BTreeMap<String, String>,
    /// Distinct gateway-proxy origins (`scheme://host[:port]`) the provisioned
    /// client configs point at — the egress allowlist `ssai run` permits.
    /// Normally exactly one (`proxy_public_url`); derived from each client's
    /// `base_url` at provision/sync time. Empty when no client recorded one →
    /// `run` asks the user to re-sync.
    pub proxy_origins: Vec<String>,
    /// What the workspace was last answered to offer: the clients `ssai run`
    /// may launch and what their sandbox may reach besides the gateway. `None`
    /// until a provision, sync or run has asked.
    pub client_access: Option<ClientAccessRecord>,
    pub clients: Vec<ManagedClient>,
}

/// A gateway's answer about what a workspace is offered, and when it came.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct ClientAccessRecord {
    #[serde(flatten)]
    pub access: crate::api::ClientAccess,
    pub fetched_at: chrono::DateTime<chrono::Utc>,
}

impl ClientAccessRecord {
    pub fn now(access: crate::api::ClientAccess) -> Self {
        Self { access, fetched_at: chrono::Utc::now() }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Manifest {
    /// Keyed like hosts.json (`origin#slug`).
    #[serde(default)]
    pub hosts: BTreeMap<HostKey, WorkspaceManifest>,
    /// The record at the manifest's path did not read as this version's: the
    /// first [`Self::save`] moves it to `manifest.json.old` before writing.
    #[serde(skip)]
    replaces_unreadable: std::cell::Cell<bool>,
}

impl Manifest {
    /// The scope's manifest; one that does not read as this version's stops
    /// the command ([`unreadable_manifest`]) and is left as it is.
    pub fn load(paths: &Paths) -> Result<Self> {
        let path = paths.manifest();
        Self::read(&path)?.map_err(|e| unreadable_manifest(&path, &e))
    }

    /// [`Self::load`] for `provision`, which starts a fresh record in place of
    /// one that does not read as this version's. The old one stays where it is
    /// until this run saves: [`Self::save`] then moves it to `manifest.json.old`
    /// (replacing an earlier one there), so a run that fails before saving
    /// leaves it for the next one. The warning says the clients it recorded and
    /// this run does not provision are no longer managed; their files stay as
    /// they are, and this run takes back over the files of the clients it
    /// provisions. A run that only previews (`writes` false: `--dry-run`,
    /// `--print`) still records keys in the manifest, so it does not replace an
    /// unreadable one: it stops like every other command.
    pub fn load_for_provision(paths: &Paths, writes: bool) -> Result<Self> {
        let path = paths.manifest();
        match Self::read(&path)? {
            Ok(manifest) => Ok(manifest),
            Err(e) if !writes => Err(unreadable_manifest(&path, &e)),
            Err(e) => {
                crate::ui::warn("  ", format_args!(
                    "{} could not be read ({e}) — a run that saves moves it to {}; a client it \
                     recorded that this run does not provision is no longer managed by ssai (its \
                     files stay as they are), and a key it recorded stays valid until you revoke it \
                     in the portal",
                    path.display(),
                    set_aside_path(&path).display()
                ));
                Ok(Self { replaces_unreadable: std::cell::Cell::new(true), ..Self::default() })
            }
        }
    }

    /// The manifest at `path` — empty when there is none — or why its bytes do
    /// not parse; an error reading the file is the outer one.
    fn read(path: &Path) -> Result<std::result::Result<Self, serde_json::Error>> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Ok(Self::default())),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self, paths: &Paths) -> Result<()> {
        let path = paths.manifest();
        if self.replaces_unreadable.get() {
            let aside = set_aside_path(&path);
            match std::fs::rename(&path, &aside) {
                Ok(()) => {}
                // Already moved by an earlier save of this scope's record.
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => {
                    return Err(e)
                        .with_context(|| format!("move {} to {}", path.display(), aside.display()));
                }
            }
            self.replaces_unreadable.set(false);
        }
        write_private(&path, &serde_json::to_vec_pretty(self)?)
    }

    /// The files every gateway but `host` manages from this manifest: one
    /// config two gateways provision (a project's OpenCode config, each
    /// gateway's run rendering the same policy entry) records some entries in
    /// both, and neither may take out what the other still records.
    pub fn files_of_other_hosts(&self, host: &str) -> Vec<ManagedFile> {
        self.hosts
            .iter()
            .filter(|(k, _)| k.as_str() != host)
            .flat_map(|(_, ws)| ws.clients.iter().flat_map(|c| c.files.iter().cloned()))
            .collect()
    }
}

/// Where `provision` moves a manifest that does not read as this version's.
fn set_aside_path(path: &Path) -> PathBuf {
    path.with_extension("json.old")
}

/// The error every command but `provision` stops on for a manifest that does
/// not read as this version's — one an earlier `ssai` wrote, or a damaged one.
/// None rewrites the file, the only record of what the CLI wrote where;
/// `provision` sets it aside and starts afresh ([`Manifest::load_for_provision`]).
fn unreadable_manifest(path: &Path, e: &serde_json::Error) -> anyhow::Error {
    anyhow::anyhow!(
        "{} cannot be read ({e}): it was written by an earlier ssai, or is damaged — run `ssai provision` \
         again for your clients (not a --dry-run or --print run): it moves this record to {} and starts a \
         fresh one",
        path.display(),
        set_aside_path(path).display()
    )
}

/// What a provisioning run reads about the files it writes: the workspace
/// record of its own gateway, and every file another gateway in the same
/// manifest manages ([`Manifest::files_of_other_hosts`]).
pub struct FileRecords<'a> {
    pub ws: &'a WorkspaceManifest,
    pub others: &'a [ManagedFile],
}

/// `owned`, recorded for the file at `path`, less what a record in `others`
/// also holds for that file with the same value — those entries are not this
/// record's alone to remove. A path both write with different values stays
/// this record's: whichever value is live, the removal takes it only when it
/// is this record's own, unedited.
pub fn owned_alone(owned: &[OwnedLeaf], path: &Path, others: &[ManagedFile]) -> Vec<OwnedLeaf> {
    let shared: Vec<&OwnedLeaf> = others
        .iter()
        .filter(|f| expand_tilde(&f.path).is_ok_and(|p| same_file(&p, path)))
        .flat_map(|f| f.owned.iter())
        .collect();
    owned
        .iter()
        .filter(|o| !shared.iter().any(|s| s.path == o.path && s.entry == o.entry && s.value_hash == o.value_hash))
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// tool-keys.json — one gateway key per tool, shared by every project
// ---------------------------------------------------------------------------

/// The key one tool uses on one gateway workspace, wherever it is provisioned.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ToolKey {
    pub workspace_id: uuid::Uuid,
    pub client_id: String,
    /// `"gateway"` or `"byok"`.
    pub mode: String,
    /// The BYOK downstream a `vk-` is bound to; `None` for a gateway `sk-`,
    /// which serves any provider.
    #[serde(default)]
    pub provider_id: Option<uuid::Uuid>,
    pub key: ManifestKey,
}

/// Device-wide record of each tool's key, so a tool provisioned into a second
/// project reuses the key it already holds instead of minting `<tool>-N`. The
/// gateway stores only a key's hash, so only this device can hand the
/// plaintext to the next project. Same exposure as the manifests; 0600.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ToolKeys {
    #[serde(default)]
    pub hosts: BTreeMap<HostKey, Vec<ToolKey>>,
}

impl ToolKeys {
    pub fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("tool-keys.json"))
    }

    pub fn load() -> Result<Self> {
        let path = Self::path()?;
        match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .with_context(|| format!("corrupt state file {}", path.display())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
        }
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Self::path()?, &serde_json::to_vec_pretty(self)?)
    }

    /// [`Self::load`], but a store that cannot be read only costs reuse: warn
    /// and start empty rather than block provisioning (the store is best
    /// effort — keys stay recorded in each manifest).
    pub fn load_or_warn() -> Self {
        Self::load().unwrap_or_else(|e| {
            crate::ui::warn("  ", format_args!("the per-tool key store could not be read ({e:#}) — tools mint fresh keys this run"));
            Self::default()
        })
    }

    /// The key `client_id` holds on `host`'s `workspace_id` in `mode` (and, for
    /// BYOK, bound to `provider_id`).
    pub fn find(
        &self,
        host: &str,
        workspace_id: uuid::Uuid,
        client_id: &str,
        mode: &str,
        provider_id: Option<uuid::Uuid>,
    ) -> Option<&ManifestKey> {
        self.hosts.get(host)?.iter().find(|t| t.matches(workspace_id, client_id, mode, provider_id)).map(|t| &t.key)
    }

    /// Record `key` as the key `client_id` holds on `host`'s `workspace_id` in
    /// `mode` — `provider_id` kept only for a BYOK `vk-`, which is bound to one
    /// downstream — and save at once: the gateway keeps only the hash, so a
    /// later failure in the run must not lose a key minted here. The one place
    /// `provision` and `sync` record a tool's key.
    pub fn record_and_save(
        &mut self,
        host: &str,
        workspace_id: uuid::Uuid,
        client_id: &str,
        byok_provider: Option<uuid::Uuid>,
        key: ManifestKey,
    ) -> Result<()> {
        let mode = if key.forward_auth { "byok" } else { "gateway" };
        let tool = ToolKey {
            workspace_id,
            client_id: client_id.to_string(),
            mode: mode.to_string(),
            provider_id: byok_provider.filter(|_| key.forward_auth),
            key,
        };
        // Read-modify-write under an exclusive lock: another `provision`/`sync`
        // running at the same time may record a key, and rewriting a stale copy
        // would drop that key's only plaintext. The lock is released on drop.
        let lock_path = Self::path()?.with_extension("json.lock");
        if let Some(dir) = lock_path.parent() {
            ensure_dir(dir)?;
        }
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .with_context(|| format!("open {}", lock_path.display()))?;
        lock.lock().with_context(|| format!("lock {}", lock_path.display()))?;
        // A store that does not PARSE (a bad write) is set aside as `.corrupt`
        // and started afresh, so one bad write does not stop reuse for good; a
        // read error is returned — a transient one must not drop every key.
        let path = Self::path()?;
        let mut current = match std::fs::read(&path) {
            Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|_| {
                let _ = std::fs::rename(&path, path.with_extension("json.corrupt"));
                Self::default()
            }),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Self::default(),
            Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
        };
        current.record(host, tool);
        current.save()?;
        *self = current;
        Ok(())
    }

    /// Record (or replace) the key `client_id` holds.
    pub fn record(&mut self, host: &str, tool: ToolKey) {
        let list = self.hosts.entry(host.to_string()).or_default();
        list.retain(|t| !t.matches(tool.workspace_id, &tool.client_id, &tool.mode, tool.provider_id));
        list.push(tool);
    }
}

impl ToolKey {
    fn matches(&self, workspace_id: uuid::Uuid, client_id: &str, mode: &str, provider_id: Option<uuid::Uuid>) -> bool {
        self.workspace_id == workspace_id
            && self.client_id == client_id
            && self.mode == mode
            && (mode != "byok" || self.provider_id == provider_id)
    }
}

// ---------------------------------------------------------------------------
// update-check.json — passive new-version notice bookkeeping
// ---------------------------------------------------------------------------

/// Last time `sync` asked each gateway (by origin) for its shipped CLI
/// version — the notice is checked at most once a day per gateway.
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct UpdateCheckFile {
    #[serde(default)]
    pub last_checked: BTreeMap<String, chrono::DateTime<chrono::Utc>>,
}

impl UpdateCheckFile {
    pub fn path() -> Result<PathBuf> {
        Ok(config_dir()?.join("update-check.json"))
    }

    pub fn load() -> Self {
        // Scratch state — corrupt or missing just means "check again".
        Self::path()
            .ok()
            .and_then(|p| std::fs::read(p).ok())
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        write_private(&Self::path()?, &serde_json::to_vec_pretty(self)?)
    }
}

// ---------------------------------------------------------------------------
// backups/ — pre-write copies, one timestamped run dir per provision/sync
// ---------------------------------------------------------------------------

/// One file a backup run recorded: the absolute path it came from (the
/// flattening is lossy, so `restore` reads the original from here rather than
/// reversing the stored name) and the flattened name its pre-run copy is
/// stored under — `None` when the file did not exist before the run, which
/// `restore` undoes by removing it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BackupEntry {
    pub original: String,
    #[serde(default)]
    pub stored: Option<String>,
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BackupIndex {
    #[serde(default)]
    files: Vec<BackupEntry>,
}

/// A backup run: its timestamp, its directory, and the files it holds.
#[derive(Debug, Clone)]
pub struct BackupRun {
    pub stamp: String,
    pub dir: PathBuf,
    pub files: Vec<BackupEntry>,
}

fn backups_dir(base: &Path) -> Result<PathBuf> {
    Ok(base.join("backups"))
}

fn read_backup_index(run_dir: &Path) -> Result<BackupIndex> {
    let path = run_dir.join("index.json");
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("corrupt backup index {}", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(BackupIndex::default()),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// A backup run's name: its UTC time to the millisecond plus this process's
/// pid, so two runs — a `provision` then a `sync` in one second, or two
/// restores — never share a run (a run keeps each path's FIRST state, so a
/// shared one would silently drop the second run's). Sorts by time.
pub fn new_run_stamp(suffix: &str) -> String {
    format!("{}{suffix}-{}", chrono::Utc::now().format("%Y%m%dT%H%M%S%.3fZ"), std::process::id())
}

/// Record `path`'s state before the run writes it — a copy, or that it did not
/// exist — in a timestamped backup folder and the run's `index.json`, so
/// `restore` can put it back (or remove it). Keeps the 5 most recent runs.
pub fn backup_file(base: &Path, run_stamp: &str, path: &Path) -> Result<()> {
    // Already recorded in this run: its first state stands — skip the read.
    let original = path.to_string_lossy();
    if read_backup_index(&backups_dir(base)?.join(run_stamp))?.files.iter().any(|e| e.original == original) {
        return Ok(());
    }
    match std::fs::read(path) {
        Ok(bytes) => backup_bytes(base, run_stamp, path, Some(&bytes)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => backup_bytes(base, run_stamp, path, None),
        Err(e) => Err(e).with_context(|| format!("read {}", path.display())),
    }
}

/// The file name a backup of `original` is stored under: a hash of the path,
/// then the path flattened to one name. Every character a file name may not
/// hold on some platform becomes `_` — `:` included, which every Windows path
/// carries after its drive letter (`C:\…`). The hash keeps the name one-to-one
/// with `original` whatever the flattening merges.
fn stored_name(original: &str) -> String {
    let flat: String = original
        .chars()
        .map(|c| if c.is_control() || matches!(c, '/' | '\\' | ':' | '<' | '>' | '"' | '|' | '?' | '*') { '_' } else { c })
        .collect();
    // Its end at most (the file's own name, the folders nearest it): a file
    // name holds 255 bytes (characters on Windows), a deep path flattened more.
    let mut start = flat.len().saturating_sub(STORED_NAME_TAIL);
    while !flat.is_char_boundary(start) {
        start += 1;
    }
    format!("{}-{}", &sha256_hex(original.as_bytes())[..16], &flat[start..])
}

/// How many bytes of the flattened path a stored backup name keeps.
const STORED_NAME_TAIL: usize = 120;

/// Record `bytes` (`None`: the file did not exist) in `run_stamp`'s backup run
/// as what `path` is restored to. The FIRST record of a path in a run wins: it
/// is the state before the run, and a later write of the same file in the run
/// must not replace it with an intermediate one.
fn backup_bytes(base: &Path, run_stamp: &str, path: &Path, bytes: Option<&[u8]>) -> Result<()> {
    let backups = backups_dir(base)?;
    let run_dir = backups.join(run_stamp);
    ensure_dir(&run_dir)?;
    let original = path.to_string_lossy().to_string();
    let mut index = read_backup_index(&run_dir)?;
    if index.files.iter().any(|e| e.original == original) {
        return Ok(());
    }
    // The flattened path alone isn't unique (two distinct paths can flatten to
    // the same name), and `restore` reads these back onto their originals — so
    // a collision would write one file's bytes over another's path. Prefix a
    // hash of the original to keep `stored` one-to-one with `original` (a
    // re-backup of the same path within the run reuses the name, overwriting
    // its own older copy, which the index dedup below expects).
    let stored = match bytes {
        Some(bytes) => {
            let stored = stored_name(&original);
            write_private(&run_dir.join(&stored), bytes)?;
            Some(stored)
        }
        None => None,
    };
    index.files.push(BackupEntry { original, stored });
    write_private(
        &run_dir.join("index.json"),
        &serde_json::to_vec_pretty(&index)?,
    )?;

    // Prune old runs.
    let mut runs: Vec<PathBuf> = std::fs::read_dir(&backups)?
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.is_dir())
        .collect();
    runs.sort();
    while runs.len() > 5 {
        let oldest = runs.remove(0);
        let _ = std::fs::remove_dir_all(oldest);
    }
    Ok(())
}

/// Store `before` — the scope's manifest as the run LOADED it, before any of
/// its groups saved — in `run_stamp`'s backup run when that run backed up a
/// file, so `restore` can put back the record of those files (their hashes,
/// the key they embed) with them. A scope with no manifest yet loads as an
/// empty one: restoring the run then stops managing the clients whose files it
/// puts back. A run that backed up nothing has no run to join.
pub fn backup_manifest_into_run(paths: &Paths, run_stamp: &str, before: &Manifest) -> Result<()> {
    if backups_dir(paths.base())?.join(run_stamp).is_dir() {
        let bytes = serde_json::to_vec_pretty(before)?;
        backup_bytes(paths.base(), run_stamp, &paths.manifest(), Some(&bytes))?;
    }
    Ok(())
}

/// All backup runs, newest first. A run that recorded no file (one cut short
/// before its index was written) holds nothing to put back and is not listed.
pub fn list_backup_runs(base: &Path) -> Result<Vec<BackupRun>> {
    let backups = backups_dir(base)?;
    let read = match std::fs::read_dir(&backups) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e).with_context(|| format!("read {}", backups.display())),
    };
    let mut runs = Vec::new();
    for entry in read.flatten() {
        let dir = entry.path();
        if !dir.is_dir() {
            continue;
        }
        let stamp = dir
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or_default()
            .to_string();
        let files = read_backup_index(&dir)?.files;
        if files.is_empty() {
            continue;
        }
        runs.push(BackupRun { stamp, dir, files });
    }
    runs.sort_by(|a, b| b.stamp.cmp(&a.stamp));
    Ok(runs)
}

/// Read every file recorded in `run` fully into memory. Done before a restore
/// touches the live files: snapshotting the current state (itself a backup)
/// can evict the oldest run — possibly the very one being restored — so its
/// bytes must already be in hand.
/// `None` for a file the run created (restore removes it).
pub fn load_backup_run_contents(run: &BackupRun) -> Result<Vec<(PathBuf, Option<Vec<u8>>)>> {
    let mut out = Vec::with_capacity(run.files.len());
    for entry in &run.files {
        let bytes = match &entry.stored {
            Some(stored) => {
                let stored = run.dir.join(stored);
                Some(std::fs::read(&stored).with_context(|| format!("read backup file {}", stored.display()))?)
            }
            None => None,
        };
        out.push((PathBuf::from(&entry.original), bytes));
    }
    Ok(out)
}

/// Atomically write `contents` back to `path` (same-dir temp + rename),
/// creating parent dirs. Preserves an existing file's mode; a file we create
/// fresh gets 0600 (the configs embed gateway keys). On Windows the file is
/// owner-only either way.
pub fn restore_file(path: &Path, contents: &[u8]) -> Result<()> {
    let dir = path.parent().context("restore path has no parent")?;
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    let mode: u32 = {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path)
            .map(|m| m.permissions().mode() & 0o777)
            .unwrap_or(0o600)
    };
    let tmp = dir.join(format!(
        ".{}.streamscope-restore-{}",
        path.file_name().and_then(|n| n.to_str()).unwrap_or("config"),
        std::process::id()
    ));
    {
        use std::io::Write;
        let mut f = create_private_file(&tmp)?;
        f.write_all(contents)?;
        f.sync_all()?;
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&tmp, std::fs::Permissions::from_mode(mode))?;
    }
    std::fs::rename(&tmp, path).with_context(|| format!("install {}", path.display()))?;
    Ok(())
}

pub fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    hex::encode(h.finalize())
}

#[cfg(test)]
mod path_tests {
    use super::*;
    use proptest::prelude::*;

    /// Text a gateway's template could hold for a path: names, dots,
    /// separators of both kinds, drive colons, tildes.
    const PATH_TEXT: &str = "[a-zA-Z0-9._:/\\\\ ~-]{0,40}";

    proptest! {
        /// Whatever its text, a template path extends the folder it is joined
        /// to: the result starts with that folder and holds no part (a root,
        /// a drive) that would replace it. Deliberately NOT claimed: that it
        /// stays inside lexically — `..` keeps its meaning on every platform.
        #[test]
        fn a_joined_path_never_replaces_its_base(rel in PATH_TEXT) {
            let base = Path::new("base_dir");
            let joined = join_relative(base, &rel);
            prop_assert!(joined.starts_with(base), "{rel:?} -> {}", joined.display());
            prop_assert!(
                joined.components().all(|c| matches!(
                    c,
                    std::path::Component::Normal(_) | std::path::Component::CurDir | std::path::Component::ParentDir
                )),
                "{rel:?} -> {}", joined.display()
            );
        }

        /// A home-relative path lands under the home or, relocated, under
        /// AppData — and a path with a `..` part is never relocated.
        #[test]
        fn a_home_path_lands_under_its_folders(rel in PATH_TEXT) {
            let dirs = UserDirs {
                home: PathBuf::from("home"),
                appdata: Some(PathBuf::from("roaming")),
                local_appdata: None,
            };
            let at = dirs.in_home(&rel);
            prop_assert!(at.starts_with("home") || at.starts_with("roaming"), "{rel:?} -> {}", at.display());
            let climbs = rel.split(std::path::is_separator).any(|p| p == "..");
            if climbs {
                prop_assert!(at.starts_with("home"), "{rel:?} -> {}", at.display());
            }
        }
    }

    #[test]
    fn only_the_listed_clients_move_to_appdata() {
        assert_eq!(windows_appdata_relocation(".config/goose/config.yaml").as_deref(), Some("Block/goose/config/config.yaml"));
        assert_eq!(windows_appdata_relocation(".config/goose/secrets.yaml").as_deref(), Some("Block/goose/config/secrets.yaml"));
        assert_eq!(windows_appdata_relocation(".config/zed/settings.json").as_deref(), Some("Zed/settings.json"));
        assert_eq!(windows_appdata_relocation(".config/Code/User/settings.json").as_deref(), Some("Code/User/settings.json"));
        assert_eq!(windows_appdata_relocation(".config/Claude/claude_desktop_config.json").as_deref(), Some("Claude/claude_desktop_config.json"));
        // Folder names compare case aside.
        assert_eq!(windows_appdata_relocation(".config/Zed/settings.json").as_deref(), Some("Zed/settings.json"));
        // The folder itself moves with the files in it.
        assert_eq!(windows_appdata_relocation(".config/goose").as_deref(), Some("Block/goose/config"));
        assert_eq!(windows_appdata_relocation(".config/zed/").as_deref(), Some("Zed"));
        // Same folder under the profile: tools that read `~/.config` on Windows too.
        for kept in [".config/opencode/opencode.json", ".config/crush/crush.json", ".codex/config.toml", ".config/zedx/a", ".config"] {
            assert_eq!(windows_appdata_relocation(kept), None, "{kept}");
        }
    }


    /// The AppData folders are given, not read from the machine: with them a
    /// moved client resolves under `%APPDATA%`, without them (off Windows)
    /// under the home; `%LOCALAPPDATA%/…` names nothing where there is none.
    #[test]
    fn a_client_path_resolves_under_the_folders_given() {
        let windows = UserDirs {
            home: PathBuf::from("home"),
            appdata: Some(PathBuf::from("roaming")),
            local_appdata: Some(PathBuf::from("local")),
        };
        assert_eq!(windows.resolve("~/.config/zed/settings.json"), Some(Path::new("roaming").join("Zed").join("settings.json")));
        assert_eq!(windows.resolve("~/.codex/config.toml"), Some(Path::new("home").join(".codex").join("config.toml")));
        assert_eq!(windows.resolve("%LOCALAPPDATA%/Programs/Zed"), Some(Path::new("local").join("Programs").join("Zed")));
        // One file, one answer, however it is spelled.
        if cfg!(windows) {
            assert_eq!(windows.resolve(r"%LOCALAPPDATA%\Programs\Zed"), Some(Path::new("local").join("Programs").join("Zed")));
        }
        for spelling in ["~/.config//zed/settings.json", "~/./.config/zed/settings.json"] {
            assert_eq!(windows.resolve(spelling), Some(Path::new("roaming").join("Zed").join("settings.json")), "{spelling}");
        }
        let unix = UserDirs { home: PathBuf::from("home"), appdata: None, local_appdata: None };
        assert_eq!(unix.resolve("~/.config/zed/settings.json"), Some(Path::new("home").join(".config").join("zed").join("settings.json")));
        assert_eq!(unix.resolve("%LOCALAPPDATA%/Programs/Zed"), None);
        assert_eq!(unix.resolve("/etc/x"), Some(PathBuf::from("/etc/x")));
    }

    #[test]
    fn a_relative_path_joins_one_component_at_a_time() {
        let base = Path::new("base");
        assert_eq!(join_relative(base, ".tool/sub//f.json"), base.join(".tool").join("sub").join("f.json"));
        // A leading separator never makes the result absolute, nor (on
        // Windows) a drive replace the base; `.` and `..` keep their meaning.
        assert_eq!(join_relative(base, "/x"), base.join("x"));
        assert_eq!(join_relative(base, "../up/./x"), base.join("..").join("up").join(".").join("x"));
        if cfg!(windows) {
            assert_eq!(join_relative(base, "C:/Users/x"), base.join("Users").join("x"));
        }
    }

    /// On Windows a moved client expands under `%APPDATA%`, every other one
    /// under the profile.
    #[cfg(windows)]
    #[test]
    fn a_moved_client_expands_under_appdata_on_windows() {
        let appdata = PathBuf::from(std::env::var_os("APPDATA").unwrap());
        assert_eq!(expand_tilde("~/.config/zed/settings.json").unwrap(), appdata.join("Zed").join("settings.json"));
        assert_eq!(
            expand_tilde("~/.config/opencode/opencode.json").unwrap(),
            home_dir().unwrap().join(".config").join("opencode").join("opencode.json")
        );
        assert_eq!(expand_tilde(r"~\.codex\config.toml").unwrap(), home_dir().unwrap().join(".codex").join("config.toml"));
        // Every spelling of one file has one answer.
        assert_eq!(expand_tilde(r"~\.config\zed\settings.json").unwrap(), appdata.join("Zed").join("settings.json"));
        assert_eq!(expand_tilde("~/.config/zed").unwrap().join("settings.json"), appdata.join("Zed").join("settings.json"));
    }
}

#[cfg(test)]
mod scope_tests {
    use super::{resolve_scope, ManifestScope};
    use std::path::Path;

    #[test]
    fn global_flag_wins_over_dir_and_project() {
        // `--global` forces the home-dir scope regardless of `--dir` (and, by
        // short-circuit, regardless of an ambient `.streamscopeai/` on the cwd).
        assert!(matches!(resolve_scope(None, false, true).unwrap(), ManifestScope::Global));
        assert!(matches!(
            resolve_scope(Some(Path::new("/tmp/proj")), false, true).unwrap(),
            ManifestScope::Global
        ));
    }

    #[test]
    fn dir_and_local_force_project() {
        match resolve_scope(Some(Path::new("/tmp/proj")), false, false).unwrap() {
            // An absent directory is recorded absolute: on Windows a rooted
            // path without a drive gets the current one.
            ManifestScope::Project(root) => assert_eq!(root, std::path::absolute("/tmp/proj").unwrap()),
            other => panic!("expected project, got {other:?}"),
        }
        assert!(matches!(
            resolve_scope(None, true, false).unwrap(),
            ManifestScope::Project(_)
        ));
    }
}

#[cfg(test)]
mod manifest_tests {
    use super::*;

    fn paths_in(dir: &Path) -> Paths {
        Paths { base: dir.to_path_buf(), root: None }
    }

    /// A manifest this version cannot read stops every command but
    /// `provision` with the way out, and is left exactly as it was: it is the
    /// only record of the files the CLI wrote. `provision` moves it aside and
    /// starts a fresh record.
    #[test]
    fn a_manifest_this_version_cannot_read_is_named_and_left_untouched() {
        let dir = std::env::temp_dir().join(format!("ss-manifest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // A client record without its own MCP selection.
        let client = serde_json::json!({
            "client_id": "cursor",
            "template_index": 0,
            "mode": "gateway",
            "provider_id": null,
            "key_id": null,
            "files": [],
            "last_provisioned": "2026-09-01T00:00:00Z",
            "launch_command": null
        });
        let ws = |client: serde_json::Value| serde_json::json!({
            "hosts": { "https://gw#acme": {
                "workspace_id": null, "keys": {}, "external_key_sha256": null, "group_etags": {},
                "proxy_origins": [], "client_access": null, "clients": [client]
            } }
        });
        let body = ws(client.clone()).to_string();
        let path = dir.join("manifest.json");
        let aside = dir.join("manifest.json.old");
        std::fs::write(&path, &body).unwrap();

        let err = format!("{:#}", Manifest::load(&paths_in(&dir)).unwrap_err());
        assert!(err.contains(&path.display().to_string()), "{err}");
        assert!(err.contains("mcp_server_ids"), "{err}");
        assert!(err.contains("run `ssai provision`"), "{err}");
        assert!(err.contains(&aside.display().to_string()), "{err}");
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
        assert!(!aside.exists());

        // `provision` starts afresh and moves nothing until it saves, so a
        // run that fails leaves the record where it is.
        // A preview run stops like every other command and moves nothing.
        assert!(Manifest::load_for_provision(&paths_in(&dir), false).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);

        let fresh = Manifest::load_for_provision(&paths_in(&dir), true).unwrap();
        assert!(fresh.hosts.is_empty());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), body);
        assert!(!aside.exists());

        // Its save sets the old record aside, byte for byte, then writes.
        fresh.save(&paths_in(&dir)).unwrap();
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), body);
        assert!(Manifest::load(&paths_in(&dir)).unwrap().hosts.is_empty());
        // A second save of the same record keeps the set-aside one.
        fresh.save(&paths_in(&dir)).unwrap();
        assert_eq!(std::fs::read_to_string(&aside).unwrap(), body);
        std::fs::remove_file(&aside).unwrap();

        // Control: the same record with its selection reads, on both paths,
        // and `provision` moves nothing.
        let mut fixed = client;
        fixed["mcp_server_ids"] = serde_json::json!([]);
        fixed["mcp_local_servers"] = serde_json::json!([]);
        fixed["mcp_local_commands"] = serde_json::json!({});
        std::fs::write(&path, ws(fixed).to_string()).unwrap();
        let manifest = Manifest::load(&paths_in(&dir)).unwrap();
        assert_eq!(manifest.hosts["https://gw#acme"].clients[0].client_id, "cursor");
        let manifest = Manifest::load_for_provision(&paths_in(&dir), true).unwrap();
        assert_eq!(manifest.hosts["https://gw#acme"].clients[0].client_id, "cursor");
        manifest.save(&paths_in(&dir)).unwrap();
        assert!(!aside.exists());
        std::fs::remove_dir_all(&dir).ok();
    }
}

#[cfg(test)]
mod backup_tests {
    use super::*;

    #[test]
    fn a_run_records_a_created_file_as_absent_and_keeps_its_first_record() {
        let dir = std::env::temp_dir().join(format!("ss-backup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let base = dir.join("state");
        let created = dir.join("new.json");
        let existing = dir.join("old.json");
        std::fs::write(&existing, "before").unwrap();

        backup_file(&base, "R", &created).unwrap();
        std::fs::write(&created, "first write").unwrap();
        // A second write of the same file in the run must not replace the record.
        backup_file(&base, "R", &created).unwrap();
        backup_file(&base, "R", &existing).unwrap();
        std::fs::write(&existing, "after").unwrap();
        backup_file(&base, "R", &existing).unwrap();

        let run = list_backup_runs(&base).unwrap().into_iter().next().unwrap();
        let contents = load_backup_run_contents(&run).unwrap();
        let of = |p: &Path| contents.iter().find(|(q, _)| q == p).map(|(_, c)| c.clone()).unwrap();
        assert_eq!(of(&created), None, "created by the run: restore removes it");
        assert_eq!(of(&existing).as_deref(), Some(&b"before"[..]), "the pre-run copy, not a later one");
        let _ = std::fs::remove_dir_all(&dir);
    }


    /// A stored name is a valid file name on every platform: a Windows path
    /// (drive colon included) and a Unix one carrying a reserved character
    /// both flatten to a name with none of them, and two paths the flattening
    /// merges keep distinct names.
    #[test]
    fn a_stored_backup_name_holds_no_character_a_platform_refuses() {
        for original in [r"C:\Users\me\.codex\config.toml", "/home/me/a:b<c>|d?e*\"f\u{1}.json"] {
            let name = stored_name(original);
            assert!(
                !name.chars().any(|c| c.is_control() || r#"/\:<>"|?*"#.contains(c)),
                "{original} → {name}"
            );
        }
        assert_ne!(stored_name("/a/b"), stored_name("/a_b"));
        // However deep the path, the name fits a file name, and two paths that
        // share their end keep distinct names.
        let deep = format!("C:\\Users\\{}\\settings.json", "a-long-folder\\".repeat(40));
        let other = format!("D:{deep}");
        assert!(stored_name(&deep).len() <= 17 + STORED_NAME_TAIL);
        // Counted in bytes, cut on a character boundary.
        let wide = format!("/home/{}/x.json", "日本語".repeat(60));
        assert!(stored_name(&wide).len() <= 17 + STORED_NAME_TAIL);
        assert!(stored_name(&deep).ends_with("settings.json"));
        assert_ne!(stored_name(&deep), stored_name(&other));
    }
}

#[cfg(test)]
mod git_exposure_tests {
    use super::*;

    /// A fresh directory under the system temp dir (outside any repository),
    /// removed when dropped.
    struct Scratch(PathBuf);
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn scratch(name: &str) -> Scratch {
        let dir = std::env::temp_dir().join(format!("ss-git-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dunce::canonicalize(&dir).unwrap())
    }

    /// Git in `dir`, whatever repository this test run was handed (a hook's
    /// `GIT_DIR` would otherwise stage into it).
    fn git(dir: &Path, args: &[&str]) {
        let mut cmd = std::process::Command::new("git");
        for var in GIT_REPOSITORY_VARS {
            cmd.env_remove(var);
        }
        let ok = cmd.args(args).current_dir(dir).output().unwrap();
        assert!(ok.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&ok.stderr));
    }

    fn repo(name: &str) -> Scratch {
        let dir = scratch(name);
        git(&dir.0, &["init", "-q"]);
        dir
    }

    fn file(path: &Path) -> GitExposure {
        git_exposure(GitTarget::File(path))
    }

    /// The temp dir may itself sit in a repository (a `TMPDIR` under a
    /// checkout, a Windows `%TEMP%` in a home repository): only then is
    /// "outside any repository" not a thing a test can make there.
    fn temp_is_outside_any_repository() -> bool {
        git_location(&std::env::temp_dir().join("x")).is_none()
    }

    fn state(dir: &Path) -> GitExposure {
        git_exposure(GitTarget::State { dir, entries: GLOBAL_STATE })
    }

    #[test]
    fn each_answer_git_can_give_about_a_file_is_told_apart() {
        let r = repo("classes");
        let r = &r.0;
        std::fs::write(r.join("tracked.json"), "{}").unwrap();
        std::fs::write(r.join(".gitignore"), "ignored.json\n").unwrap();
        git(r, &["add", "tracked.json"]);
        assert_eq!(file(&r.join("tracked.json")), GitExposure::Tracked);
        assert_eq!(file(&r.join("ignored.json")), GitExposure::Ignored);
        assert_eq!(file(&r.join("untracked.json")), GitExposure::Exposed);
        // Not written yet, in a directory not created yet.
        assert_eq!(file(&r.join("a/b/new.json")), GitExposure::Exposed);
        if temp_is_outside_any_repository() {
            let outside = scratch("outside");
            assert_eq!(file(&outside.0.join("x.json")), GitExposure::Outside);
        }
    }

    /// A tracked file a clone marks skip-worktree or assume-unchanged is
    /// refused like any tracked one (git does not promise the mark keeps a
    /// change out), and the refusal names the mark; an unmarked one keeps the
    /// plain refusal.
    #[test]
    fn a_tracked_file_marked_skip_worktree_is_refused_naming_the_mark() {
        let r = repo("marks");
        let r = &r.0;
        for f in ["skip.json", "assume.json", "plain.json"] {
            std::fs::write(r.join(f), "{}").unwrap();
            git(r, &["add", f]);
        }
        git(r, &["update-index", "--skip-worktree", "skip.json"]);
        git(r, &["update-index", "--assume-unchanged", "assume.json"]);
        assert_eq!(file(&r.join("skip.json")), GitExposure::Marked);
        assert_eq!(file(&r.join("assume.json")), GitExposure::Marked);
        let e = keep_out_of_git(GitTarget::File(&r.join("skip.json")), "a key", "do X", false, false).unwrap_err();
        assert!(format!("{e:#}").contains("marks it skip-worktree or assume-unchanged"), "{e:#}");
        assert!(format!("{e:#}").ends_with("— do X"), "{e:#}");
        // The control: the same file without a mark gets the plain refusal.
        assert_eq!(file(&r.join("plain.json")), GitExposure::Tracked);
        let e = keep_out_of_git(GitTarget::File(&r.join("plain.json")), "a key", "do X", false, false).unwrap_err();
        assert!(!format!("{e:#}").contains("skip-worktree"), "{e:#}");
        // A state directory with one marked and one unmarked tracked entry is
        // plainly tracked.
        let g = r.join("state");
        std::fs::create_dir_all(&g).unwrap();
        std::fs::write(g.join("manifest.json"), "{}").unwrap();
        std::fs::write(g.join("hosts.json"), "{}").unwrap();
        git(r, &["add", "state"]);
        git(r, &["update-index", "--skip-worktree", "state/manifest.json"]);
        assert_eq!(state(&g), GitExposure::Tracked);
        git(r, &["update-index", "--skip-worktree", "state/hosts.json"]);
        assert_eq!(state(&g), GitExposure::Marked);
    }

    #[test]
    fn a_repository_git_cannot_answer_for_is_refused_and_no_repository_is_not() {
        let r = scratch("broken");
        // A `.git` git refuses: a gitfile pointing nowhere.
        std::fs::write(r.0.join(".git"), "gitdir: /nonexistent/streamscope-test\n").unwrap();
        assert!(matches!(file(&r.0.join("k.json")), GitExposure::Unknown(_)));
        let e = keep_out_of_git(GitTarget::File(&r.0.join("k.json")), "a key", "do X", false, false).unwrap_err();
        assert!(format!("{e:#}").contains("could not answer"), "{e:#}");
        // In git's own words, which name the fix (worded per platform).
        assert!(format!("{e:#}").contains("fatal:"), "{e:#}");
        // The positive control: the same file in a repository git answers for.
        let free = repo("answered");
        keep_out_of_git(GitTarget::File(&free.0.join("k.json")), "a key", "do X", false, false).unwrap();
    }

    #[test]
    fn a_tracked_file_is_refused_and_an_exposed_one_is_excluded_exactly() {
        let r = repo("exclude");
        let r = &r.0;
        std::fs::write(r.join("t.json"), "{}").unwrap();
        git(r, &["add", "t.json"]);
        let e = keep_out_of_git(GitTarget::File(&r.join("t.json")), "a key", "do X", false, false).unwrap_err();
        assert!(format!("{e:#}").contains("tracked by git"), "{e:#}");

        // A name holding every character an ignore line reads specially (`*`
        // and `?` are no file-name characters on Windows).
        let odd = r.join("sub dir").join(if cfg!(windows) { "[k] #.json" } else { "[k]*?.json" });
        keep_out_of_git(GitTarget::File(&odd), "a key", "do X", false, false).unwrap();
        assert_eq!(file(&odd), GitExposure::Ignored);
        // Exactly that file: a sibling the wildcards would have matched is not.
        assert_eq!(file(&r.join("sub dir").join("k-other.json")), GitExposure::Exposed);
        // Idempotent: a second run adds no second line.
        keep_out_of_git(GitTarget::File(&odd), "a key", "do X", false, false).unwrap();
        let exclude = std::fs::read_to_string(r.join(".git/info/exclude")).unwrap();
        assert_eq!(exclude.lines().filter(|l| l.contains("k]")).count(), 1, "{exclude}");
        // Nothing reaches what the repository commits.
        assert!(!r.join(".gitignore").exists());
    }

    #[test]
    fn a_dry_run_and_a_file_left_to_the_projects_gitignore_exclude_nothing() {
        let r = repo("noexclude");
        let f = r.0.join("k.json");
        keep_out_of_git(GitTarget::File(&f), "a key", "do X", false, true).unwrap();
        keep_out_of_git(GitTarget::File(&f), "a key", "do X", true, false).unwrap();
        assert_eq!(file(&f), GitExposure::Exposed);
    }

    #[test]
    fn a_state_directory_is_judged_by_the_files_the_cli_writes_there() {
        let r = repo("statedir");
        let r = &r.0;
        let project = r.join(".streamscopeai");
        std::fs::create_dir_all(&project).unwrap();
        std::fs::write(project.join(".gitignore"), "*\n").unwrap();
        git(r, &["add", "-f", ".streamscopeai/.gitignore"]);
        // A committed `.gitignore` of `*` keeps it out for everyone.
        let judged = |d: &Path| git_exposure(GitTarget::State { dir: d, entries: PROJECT_STATE });
        assert_eq!(judged(&project), GitExposure::Ignored);
        // One of its files committed is the leak.
        std::fs::write(project.join("manifest.json"), "{}").unwrap();
        git(r, &["add", "-f", ".streamscopeai/manifest.json"]);
        assert_eq!(judged(&project), GitExposure::Tracked);
        // So is a backup.
        let other = r.join("other-state");
        std::fs::create_dir_all(other.join("backups/run")).unwrap();
        std::fs::write(other.join("backups/run/settings.json"), "{}").unwrap();
        git(r, &["add", "-f", "other-state/backups/run/settings.json"]);
        assert_eq!(judged(&other), GitExposure::Tracked);

        // A directory nothing ignores has its entries excluded, and only them
        // — before it exists, as on a first sign-in.
        let global = r.join(".config").join("streamscopeai");
        assert_eq!(state(&global), GitExposure::Exposed);
        keep_out_of_git(GitTarget::State { dir: &global, entries: GLOBAL_STATE }, "tokens", "do X", false, false)
            .unwrap();
        assert_eq!(state(&global), GitExposure::Ignored);
        assert_eq!(file(&r.join(".config").join("other.json")), GitExposure::Exposed);
    }

    #[test]
    fn a_file_of_the_users_beside_the_state_is_not_ours_to_judge() {
        // A certificate kept in a dotfiles repository does not put the tokens
        // in a commit; the tokens beside it are still kept out.
        let r = repo("usersfile");
        let global = r.0.join(".config").join("streamscopeai");
        std::fs::create_dir_all(&global).unwrap();
        std::fs::write(global.join("gateway-ca.pem"), "cert").unwrap();
        git(&r.0, &["add", ".config/streamscopeai/gateway-ca.pem"]);
        assert_eq!(state(&global), GitExposure::Exposed);
        keep_out_of_git(GitTarget::State { dir: &global, entries: GLOBAL_STATE }, "tokens", "do X", false, false)
            .unwrap();
        assert_eq!(file(&global.join("hosts.json")), GitExposure::Ignored);
        // A file of the user's added there later is still theirs to commit.
        assert_eq!(file(&global.join("gateway-ca.d").join("extra.pem")), GitExposure::Exposed);
    }

    #[test]
    fn a_rule_that_re_includes_the_state_is_refused_with_what_to_do() {
        // A whitelist-style repository re-including the token file by name: a
        // stand-in name would read ignored while the tokens are not.
        let r = repo("whitelist");
        std::fs::write(r.0.join(".gitignore"), "*\n!*/\n!hosts.json\n").unwrap();
        let global = r.0.join(".config").join("streamscopeai");
        assert_eq!(state(&global), GitExposure::Exposed);
        let e = keep_out_of_git(GitTarget::State { dir: &global, entries: GLOBAL_STATE }, "tokens", "do X", false, false)
            .unwrap_err();
        assert!(format!("{e:#}").contains("re-includes it"), "{e:#}");
    }

    #[test]
    fn a_state_directory_that_is_a_repositorys_top_level_has_its_entries_excluded() {
        let r = repo("toplevel");
        keep_out_of_git(GitTarget::State { dir: &r.0, entries: GLOBAL_STATE }, "tokens", "do X", false, false).unwrap();
        assert_eq!(state(&r.0), GitExposure::Ignored);
    }

    #[test]
    fn a_file_in_a_nested_repository_is_excluded_in_that_repository() {
        // A project's `.gitignore` does not reach a repository nested in it.
        let outer = repo("nested-outer");
        let inner = outer.0.join("vendor").join("tool");
        std::fs::create_dir_all(&inner).unwrap();
        git(&inner, &["init", "-q"]);
        let key_file = inner.join(".env");
        assert!(!covered_by_project_gitignore(&outer.0, &key_file));
        assert!(covered_by_project_gitignore(&outer.0, &outer.0.join("vendor").join(".env")));
        keep_out_of_git(GitTarget::File(&key_file), "a key", "do X", false, false).unwrap();
        assert_eq!(file(&key_file), GitExposure::Ignored);
        assert!(std::fs::read_to_string(inner.join(".git/info/exclude")).unwrap().contains("/.env"));
    }

    #[cfg(unix)]
    #[test]
    fn a_state_directory_linked_into_a_repository_is_judged_there() {
        // GNU stow links `~/.config/streamscopeai` into a dotfiles worktree.
        let dotfiles = repo("stow-dotfiles");
        let home = scratch("stow-home");
        let real = dotfiles.0.join("ssai");
        std::fs::create_dir_all(&real).unwrap();
        std::fs::create_dir_all(home.0.join(".config")).unwrap();
        let linked = home.0.join(".config").join("streamscopeai");
        std::os::unix::fs::symlink(&real, &linked).unwrap();
        assert_eq!(state(&linked), GitExposure::Exposed);
    }

    #[test]
    fn an_exclude_file_is_created_or_extended_on_a_line_of_its_own_under_one_header() {
        // No exclude file yet.
        let r = repo("excludefile");
        let exclude = r.0.join(".git/info/exclude");
        let _ = std::fs::remove_file(&exclude);
        keep_out_of_git(GitTarget::File(&r.0.join("a.json")), "a key", "do X", false, false).unwrap();
        assert_eq!(file(&r.0.join("a.json")), GitExposure::Ignored);
        // One with no final newline: the next line must not join its last one.
        std::fs::write(&exclude, "mine").unwrap();
        keep_out_of_git(GitTarget::File(&r.0.join("b.json")), "a key", "do X", false, false).unwrap();
        keep_out_of_git(GitTarget::File(&r.0.join("c.json")), "a key", "do X", false, false).unwrap();
        let text = std::fs::read_to_string(&exclude).unwrap();
        assert!(text.starts_with("mine\n"), "{text}");
        assert!(text.lines().any(|l| l == "/b.json") && text.lines().any(|l| l == "/c.json"), "{text}");
        assert_eq!(text.lines().filter(|l| l.starts_with("# streamscope")).count(), 1, "{text}");
    }

    #[test]
    fn a_projects_state_is_kept_out_with_its_gitignore_and_refused_when_committed() {
        let r = repo("projectstate");
        let paths = Paths::for_scope(&ManifestScope::Project(r.0.clone())).unwrap();
        keep_project_state_out_of_git(&paths).unwrap();
        assert_eq!(std::fs::read_to_string(r.0.join(".streamscopeai/.gitignore")).unwrap(), "*\n");
        std::fs::write(r.0.join(".streamscopeai/manifest.json"), "{}").unwrap();
        git(&r.0, &["add", "-f", ".streamscopeai/manifest.json"]);
        let e = keep_project_state_out_of_git(&paths).unwrap_err();
        assert!(format!("{e:#}").contains("tracked by git"), "{e:#}");
    }

    #[test]
    fn an_exclude_line_escapes_what_git_reads_specially() {
        assert_eq!(exclude_pattern("a/b.json", false), "/a/b.json");
        assert_eq!(exclude_pattern("d", true), "/d/");
        assert_eq!(exclude_pattern("x y/[k]*?\\", false), "/x\\ y/\\[k]\\*\\?\\\\");
        assert_eq!(exclude_pattern("!a#", false), "/\\!a#");
    }
}
