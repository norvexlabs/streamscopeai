//! One run's setup for the sandbox account, before its grant: what the
//! client needs changed to run as another account — its configuration
//! folder, its first-run state, its own switches, git's ownership check —
//! and the folders and files the grant then gives the account. It writes no
//! access entry; [`super::run::grant`] does, with what this returns. Pure but
//! for the folders and the seed it writes in the developer's profile, so it
//! is tested on every host.

// Off Windows this module is compiled for its tests only.
#![cfg_attr(not(windows), allow(dead_code))]

use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};

use super::grants::{RunDirs, refused_root};
use crate::sandbox::LaunchSpec;
use crate::sandbox::profiles::AgentProfile;
use crate::sandbox::protect;

/// What the host tells the setup.
pub struct Host<'a> {
    /// The developer's profile folder.
    pub profile: &'a Path,
    /// The developer's roaming folder (`%APPDATA%`), where a column value
    /// anchored there lives; `None` when it is not known.
    pub appdata: Option<&'a Path>,
    /// The developer's own `NODE_EXTRA_CA_CERTS`, when set.
    pub node_ca: Option<&'a Path>,
    /// The folder of the running `ssai`.
    pub own_dir: Option<&'a Path>,
    /// The file the client's command runs as, found as the launch finds it.
    pub program: Option<&'a Path>,
}

/// Adjust `spec` for the sandbox account and return what it must be granted:
/// - each configuration variable of `agent`'s Windows column is set to its
///   value among the developer's folders, ahead of the run's own variables,
///   so a `--env` naming another value wins; the entry's folder under that
///   value (created when absent) is the one granted and seeded;
/// - the seed: each `(file, key)` in the first of those folders gets `key`
///   set to `true` when absent;
/// - the column's arguments go before the client's own;
/// - git trusts the project root and a linked worktree's common git folder
///   (`safe.directory`, appended after any `GIT_CONFIG_COUNT` the run sets);
/// - `tools`: the folder of `ssai` and of the client's program (and the
///   folder it resolves to, when another); `files`: the CA files and the
///   files the client was provisioned with (readable by the developer alone,
///   so the grant on their folder misses them). Each only
///   inside the profile: outside it, only an administrator could grant one,
///   and what is there is readable by every account already — but for a
///   provisioned file in the project, which is the developer's own to grant
///   wherever the project is.
pub fn prepare(spec: &mut LaunchSpec, agent: Option<&AgentProfile>, host: &Host) -> Result<RunDirs> {
    let mut dirs = RunDirs::default();
    if let Some(agent) = agent {
        let mut defaults: Vec<(String, String)> = Vec::new();
        for c in agent.windows_config {
            let var = c.var;
            let value = match last(&spec.env, var) {
                Some(given) => {
                    let given = PathBuf::from(given);
                    if !given.is_absolute() {
                        bail!("{var}={} must name an absolute folder under the Windows sandbox", given.display());
                    }
                    given
                }
                None => {
                    let Some(value) = anchored(c.value, host) else {
                        bail!("{var}: the folder {} is not known on this computer", c.value);
                    };
                    defaults.push((var.to_string(), value.to_string_lossy().into_owned()));
                    value
                }
            };
            let folder = in_folder(&value, c.granted);
            // Refused before anything is created or seeded there, as the
            // grant would refuse it.
            if let Some(why) = refused_root(&folder.to_string_lossy(), &host.profile.to_string_lossy()) {
                bail!("the Windows sandbox refuses the client's folder {}: {why}", folder.display());
            }
            std::fs::create_dir_all(&folder).with_context(|| format!("create {}", folder.display()))?;
            dirs.state.push(folder);
        }
        spec.env.splice(0..0, defaults);
        if let Some(first) = dirs.state.first() {
            for (file, key) in agent.windows_seed {
                seed(&first.join(file), key)?;
            }
        }
        spec.args.splice(0..0, agent.windows_args.iter().map(|a| a.to_string()));
    }
    trust_in_git(spec)?;
    carry_node_ca(spec, host);
    let found = host.own_dir.map(Path::to_path_buf).into_iter().chain(host.program.into_iter().flat_map(program_dirs));
    for dir in found {
        if under(&dir, host.profile) && !dirs.tools.contains(&dir) {
            dirs.tools.push(dir);
        }
    }
    // Each file as it is on disk (a junction or a short name followed), as
    // the profile and the root are.
    let real = |f: &PathBuf| dunce::canonicalize(f).ok().filter(|r| r.is_file());
    let ca = spec.ca_files.iter().filter_map(real).filter(|f| under(f, host.profile));
    // A client file is the canonical path the run resolved: one that now
    // resolves elsewhere (a link swapped in since) is not granted.
    let provisioned = spec
        .client_files
        .iter()
        .filter_map(|f| real(f).filter(|r| r == f))
        .filter(|f| under(f, host.profile) || under(f, &spec.project_root));
    for file in ca.chain(provisioned) {
        if !dirs.files.contains(&file) {
            dirs.files.push(file);
        }
    }
    Ok(dirs)
}

/// The developer's `NODE_EXTRA_CA_CERTS` (the Windows advice for a private
/// CA), which the account's own environment lacks, is carried — additive, so
/// it never replaces a store — when the run's variables set none (a
/// `--ca-file` bundle and a gateway bundle each set it), and its file joins
/// the CA files, granted to read like them when inside the profile.
fn carry_node_ca(spec: &mut LaunchSpec, host: &Host) {
    const VAR: &str = "NODE_EXTRA_CA_CERTS";
    if last(&spec.env, VAR).is_some() {
        return;
    }
    let Some(file) = host.node_ca.and_then(|f| dunce::canonicalize(f).ok()).filter(|f| f.is_file()) else {
        return;
    };
    spec.env.push((VAR.to_string(), file.to_string_lossy().into_owned()));
    if !spec.ca_files.contains(&file) {
        spec.ca_files.push(file);
    }
}

/// The last value the run gives the variable `name`; Windows compares names
/// without case.
fn last<'a>(env: &'a [(String, String)], name: &str) -> Option<&'a str> {
    env.iter().rev().find(|(k, _)| k.eq_ignore_ascii_case(name)).map(|(_, v)| v.as_str())
}

/// A value of the profile table's Windows column: `~` or `~/…` in the
/// profile, `%APPDATA%/…` in the roaming folder (`None` when it is not known).
fn anchored(value: &str, host: &Host) -> Option<PathBuf> {
    if let Some(rest) = value.strip_prefix("%APPDATA%/") {
        return host.appdata.map(|base| in_folder(base, rest));
    }
    Some(in_folder(host.profile, value.trim_start_matches('~')))
}

/// `rel` (`/`-separated) under `base`.
fn in_folder(base: &Path, rel: &str) -> PathBuf {
    rel.split('/').filter(|p| !p.is_empty()).fold(base.to_path_buf(), |at, p| at.join(p))
}

/// Set the top-level `key` of the JSON file at `path` to `true` when absent,
/// creating the file when absent. A file that is not a JSON object is left
/// as it is, with a warning: it is the client's, and the client then asks
/// its first-run questions itself.
fn seed(path: &Path, key: &str) -> Result<()> {
    let mut doc = match std::fs::read(path) {
        Ok(bytes) => match serde_json::from_slice::<serde_json::Value>(&bytes) {
            Ok(serde_json::Value::Object(map)) => map,
            _ => {
                crate::ui::warn(
                    "",
                    format_args!("{} is not a JSON object: left as it is, without `{key}`", path.display()),
                );
                return Ok(());
            }
        },
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::Map::new(),
        Err(e) => return Err(e).with_context(|| format!("read {}", path.display())),
    };
    if doc.contains_key(key) {
        return Ok(());
    }
    doc.insert(key.to_string(), serde_json::Value::Bool(true));
    let text = serde_json::to_vec_pretty(&doc).context("encode the client's first-run state")?;
    // Written beside it and renamed over it: a client reading it meanwhile
    // sees the old file or the new one, never half of one.
    let mut name = path.file_name().unwrap_or_default().to_os_string();
    name.push(".ssai-tmp");
    let tmp = path.with_file_name(name);
    std::fs::write(&tmp, text).with_context(|| format!("write {}", tmp.display()))?;
    std::fs::rename(&tmp, path).with_context(|| format!("write {}", path.display()))
}

/// Git refuses a repository another account owns ("dubious ownership"):
/// trust the project root and a linked worktree's common git folder for this
/// run, through the `GIT_CONFIG_*` variables — no gitconfig is written —
/// appended after the entries the run already sets.
fn trust_in_git(spec: &mut LaunchSpec) -> Result<()> {
    let project = protect::resolve(&spec.project_root);
    let trusted: Vec<String> =
        std::iter::once(&spec.project_root).chain(&project.extra_rw).map(|p| git_path(p)).collect();
    let start = match last(&spec.env, "GIT_CONFIG_COUNT").map(str::trim) {
        None | Some("") => 0,
        Some(n) => n.parse::<usize>().with_context(|| format!("GIT_CONFIG_COUNT={n:?} is not a count"))?,
    };
    for (i, dir) in trusted.iter().enumerate() {
        spec.env.push((format!("GIT_CONFIG_KEY_{}", start + i), "safe.directory".to_string()));
        spec.env.push((format!("GIT_CONFIG_VALUE_{}", start + i), dir.clone()));
    }
    spec.env.push(("GIT_CONFIG_COUNT".to_string(), (start + trusted.len()).to_string()));
    Ok(())
}

/// A folder as git writes it, which is what `safe.directory` is compared
/// with: forward slashes, no `\\?\` prefix.
fn git_path(p: &Path) -> String {
    let text = p.to_string_lossy();
    let text = match text.strip_prefix(r"\\?\UNC\") {
        Some(rest) => format!(r"\\{rest}"),
        None => text.strip_prefix(r"\\?\").unwrap_or(&text).to_string(),
    };
    text.replace('\\', "/")
}

/// The folder of the client's program, and the folder it resolves to when
/// that is another (a link).
fn program_dirs(program: &Path) -> Vec<PathBuf> {
    let mut out: Vec<PathBuf> = program.parent().map(Path::to_path_buf).into_iter().collect();
    if let Some(real) = dunce::canonicalize(program).ok().and_then(|p| p.parent().map(Path::to_path_buf))
        && !out.contains(&real)
    {
        out.push(real);
    }
    out
}

/// `path` is inside the folder `profile`, compared without case and either
/// slash, as Windows compares paths.
fn under(path: &Path, profile: &Path) -> bool {
    let norm = |p: &Path| p.to_string_lossy().replace('\\', "/").trim_end_matches('/').to_lowercase();
    let profile = norm(profile);
    !profile.is_empty() && norm(path).starts_with(&format!("{profile}/"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sandbox::profiles::agent_for;

    fn scratch(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("ssai-prepare-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dunce::canonicalize(&dir).unwrap()
    }

    /// A profile holding a project, and a spec for `command` in it.
    fn setup(name: &str, command: &str, env: &[(&str, &str)]) -> (PathBuf, LaunchSpec) {
        let profile = scratch(name);
        let root = profile.join("project");
        std::fs::create_dir_all(&root).unwrap();
        let spec = LaunchSpec {
            command: command.into(),
            args: vec!["--resume".into()],
            project_root: root.clone(),
            cwd: root,
            proxy_origins: vec![],
            destinations: Default::default(),
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_project: false,
        };
        (profile, spec)
    }

    fn run(spec: &mut LaunchSpec, profile: &Path) -> RunDirs {
        let agent = agent_for(&spec.command);
        prepare(spec, agent, &Host { profile, appdata: None, node_ca: None, own_dir: None, program: None }).unwrap()
    }

    fn json(path: &Path) -> serde_json::Value {
        serde_json::from_slice(&std::fs::read(path).unwrap()).unwrap()
    }

    #[test]
    fn claude_gets_its_config_folder_first_and_its_onboarding_seeded() {
        let (profile, mut spec) = setup("claude", "claude", &[("FOO", "1")]);
        let dirs = run(&mut spec, &profile);
        let folder = profile.join(".claude");
        assert!(folder.is_dir());
        assert_eq!(spec.env[0], ("CLAUDE_CONFIG_DIR".to_string(), folder.to_string_lossy().into_owned()));
        assert_eq!(spec.env[1], ("FOO".to_string(), "1".to_string()));
        assert_eq!(dirs.state, vec![folder.clone()]);
        assert_eq!(json(&folder.join(".claude.json")), serde_json::json!({"hasCompletedOnboarding": true}));
        assert!(!folder.join(".claude.json.ssai-tmp").exists());
        // Claude has no Windows arguments.
        assert_eq!(spec.args, ["--resume"]);
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// The developer's `NODE_EXTRA_CA_CERTS` reaches the run when the run sets
    /// none, its file granted when inside the profile; the run's own (any
    /// case, as a `--ca-file` or gateway bundle sets it) wins.
    #[test]
    fn the_developers_node_ca_is_carried_only_where_nothing_else_sets_trust() {
        // One case: a fresh profile holding a root, the run changed by
        // `adjust`, the developer's variable naming the root (or one outside).
        let case = |name: &str, adjust: &dyn Fn(&mut LaunchSpec), inside: bool| {
            let (profile, mut spec) = setup(name, "gemini", &[]);
            let outside = scratch(&format!("{name}-outside"));
            let root = if inside { profile.join("certs").join("root.pem") } else { outside.join("root.pem") };
            std::fs::create_dir_all(root.parent().unwrap()).unwrap();
            std::fs::write(&root, "pem").unwrap();
            adjust(&mut spec);
            let host = Host { profile: &profile, appdata: None, node_ca: Some(&root), own_dir: None, program: None };
            let dirs = prepare(&mut spec, None, &host).unwrap();
            let carried = last(&spec.env, "NODE_EXTRA_CA_CERTS").map(str::to_string);
            let granted = dirs.files.contains(&root);
            for dir in [profile, outside] {
                let _ = std::fs::remove_dir_all(dir);
            }
            (carried, granted, root)
        };
        let (carried, granted, root) = case("nodeca-set", &|_| {}, true);
        assert_eq!(carried.as_deref(), Some(root.to_str().unwrap()));
        assert!(granted);
        let (carried, granted, _) =
            case("nodeca-run", &|s| s.env.push(("node_extra_ca_certs".into(), "C:/run.pem".into())), true);
        assert_eq!(carried.as_deref(), Some("C:/run.pem"));
        assert!(!granted);
        // Outside the profile: carried, not granted (every account reads there).
        let (carried, granted, root) = case("nodeca-away", &|_| {}, false);
        assert_eq!(carried.as_deref(), Some(root.to_str().unwrap()));
        assert!(!granted);
    }

    /// Gemini CLI's variable names the home it keeps `.gemini` in: set to
    /// the profile, with `.gemini` the folder granted; a `--env` home moves
    /// the granted folder with it.
    #[test]
    fn gemini_gets_the_profile_as_its_home_and_its_gemini_folder_granted() {
        let (profile, mut spec) = setup("gemini", "gemini", &[]);
        let dirs = run(&mut spec, &profile);
        assert_eq!(spec.env[0], ("GEMINI_CLI_HOME".to_string(), profile.to_string_lossy().into_owned()));
        assert_eq!(dirs.state, vec![profile.join(".gemini")]);
        assert!(profile.join(".gemini").is_dir());
        let mine = scratch("gemini-elsewhere");
        let (profile2, mut spec) = setup("gemini-env", "gemini", &[("GEMINI_CLI_HOME", mine.to_str().unwrap())]);
        let dirs = run(&mut spec, &profile2);
        assert_eq!(dirs.state, vec![mine.join(".gemini")]);
        assert_eq!(spec.env.iter().filter(|(k, _)| k == "GEMINI_CLI_HOME").count(), 1);
        for dir in [profile, profile2, mine] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// Goose's root is in the roaming folder, where provision writes its
    /// config: the variable and the granted folder are both there; a host
    /// that does not know the roaming folder refuses by name.
    #[test]
    fn goose_gets_its_root_in_the_roaming_folder() {
        let (profile, mut spec) = setup("goose", "goose", &[]);
        let appdata = profile.join("Roaming");
        let dirs = prepare(&mut spec, agent_for("goose"), &Host { profile: &profile, appdata: Some(&appdata), node_ca: None, own_dir: None, program: None })
            .unwrap();
        let root = appdata.join("Block").join("goose");
        assert_eq!(spec.env[0], ("GOOSE_PATH_ROOT".to_string(), root.to_string_lossy().into_owned()));
        assert_eq!(dirs.state, vec![root.clone()]);
        assert!(root.is_dir());
        let (profile2, mut spec) = setup("goose-noappdata", "goose", &[]);
        let err = prepare(&mut spec, agent_for("goose"), &Host { profile: &profile2, appdata: None, node_ca: None, own_dir: None, program: None })
            .unwrap_err();
        assert!(err.to_string().contains("GOOSE_PATH_ROOT"), "{err}");
        for dir in [profile, profile2] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn the_seed_keeps_the_clients_state_and_never_overrides_a_set_key() {
        let (profile, mut spec) = setup("seedkeep", "claude", &[]);
        let folder = profile.join(".claude");
        std::fs::create_dir_all(&folder).unwrap();
        std::fs::write(folder.join(".claude.json"), r#"{"theme":"dark","numStartups":3}"#).unwrap();
        run(&mut spec, &profile);
        assert_eq!(
            json(&folder.join(".claude.json")),
            serde_json::json!({"theme": "dark", "numStartups": 3, "hasCompletedOnboarding": true})
        );
        // Set, even to false: the client's answer, kept.
        std::fs::write(folder.join(".claude.json"), r#"{"hasCompletedOnboarding":false}"#).unwrap();
        run(&mut spec, &profile);
        assert_eq!(json(&folder.join(".claude.json")), serde_json::json!({"hasCompletedOnboarding": false}));
        // Not an object: left as it is.
        std::fs::write(folder.join(".claude.json"), "[1]").unwrap();
        run(&mut spec, &profile);
        assert_eq!(std::fs::read_to_string(folder.join(".claude.json")).unwrap(), "[1]");
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn codex_gets_its_home_and_its_own_sandbox_off_before_the_users_arguments() {
        let (profile, mut spec) = setup("codex", "codex", &[]);
        let dirs = run(&mut spec, &profile);
        let folder = profile.join(".codex");
        assert!(folder.is_dir());
        assert_eq!(spec.env[0], ("CODEX_HOME".to_string(), folder.to_string_lossy().into_owned()));
        assert_eq!(dirs.state, vec![folder.clone()]);
        assert_eq!(spec.args, ["-c", "sandbox_mode=danger-full-access", "--resume"]);
        // No seed for Codex.
        assert_eq!(std::fs::read_dir(&folder).unwrap().count(), 0);
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn a_users_env_wins_and_names_the_folder_granted_and_seeded() {
        let mine = scratch("mine-elsewhere").join("cfg");
        let mine_text = mine.to_string_lossy().into_owned();
        let (profile, mut spec) = setup("userenv", "claude", &[("CLAUDE_CONFIG_DIR", &mine_text)]);
        let dirs = run(&mut spec, &profile);
        assert_eq!(last(&spec.env, "CLAUDE_CONFIG_DIR"), Some(mine_text.as_str()));
        assert_eq!(spec.env.iter().filter(|(k, _)| k == "CLAUDE_CONFIG_DIR").count(), 1);
        assert_eq!(dirs.state, vec![mine.clone()]);
        assert_eq!(json(&mine.join(".claude.json"))["hasCompletedOnboarding"], serde_json::json!(true));
        assert!(!profile.join(".claude").exists());
        // A relative folder is refused, by name.
        let (profile2, mut spec) = setup("userenv-rel", "claude", &[("claude_config_dir", "cfg")]);
        let err = prepare(&mut spec, agent_for("claude"), &Host { profile: &profile2, appdata: None, node_ca: None, own_dir: None, program: None })
            .unwrap_err();
        assert!(err.to_string().contains("CLAUDE_CONFIG_DIR"), "{err}");
        for dir in [profile, profile2, mine.parent().unwrap().to_path_buf()] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// A config folder the grant would refuse (the whole profile) is refused
    /// before anything is created or seeded in it.
    #[test]
    fn a_refused_config_folder_is_never_seeded() {
        let (profile, mut spec) = setup("refused-cfg", "claude", &[]);
        spec.env.push(("CLAUDE_CONFIG_DIR".into(), profile.to_string_lossy().into_owned()));
        let err = prepare(&mut spec, agent_for("claude"), &Host { profile: &profile, appdata: None, node_ca: None, own_dir: None, program: None })
            .unwrap_err();
        assert!(err.to_string().contains("refuses the client's folder"), "{err}");
        assert!(!profile.join(".claude.json").exists(), "the profile was seeded before the refusal");
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn a_client_without_a_windows_column_is_changed_only_for_git() {
        let (profile, mut spec) = setup("plain", "opencode", &[]);
        let dirs = run(&mut spec, &profile);
        assert!(dirs.state.is_empty());
        assert_eq!(spec.args, ["--resume"]);
        assert!(spec.env.iter().all(|(k, _)| k.starts_with("GIT_CONFIG_")), "{:?}", spec.env);
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn git_trusts_the_root_after_the_entries_the_run_already_sets() {
        let (profile, mut spec) = setup("gitcount", "opencode", &[("GIT_CONFIG_COUNT", "2")]);
        run(&mut spec, &profile);
        let root = git_path(&spec.project_root);
        assert_eq!(last(&spec.env, "GIT_CONFIG_KEY_2"), Some("safe.directory"));
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_2"), Some(root.as_str()));
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("3"));
        assert_eq!(last(&spec.env, "GIT_CONFIG_KEY_0"), None);
        // None set: from 0.
        let (profile2, mut spec) = setup("gitzero", "opencode", &[]);
        run(&mut spec, &profile2);
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_0"), Some(git_path(&spec.project_root).as_str()));
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("1"));
        // Not a count: refused.
        let (profile3, mut spec) = setup("gitbad", "opencode", &[("GIT_CONFIG_COUNT", "x")]);
        let err = prepare(&mut spec, None, &Host { profile: &profile3, appdata: None, node_ca: None, own_dir: None, program: None }).unwrap_err();
        assert!(err.to_string().contains("GIT_CONFIG_COUNT"), "{err}");
        for dir in [profile, profile2, profile3] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn git_trusts_a_linked_worktrees_common_git_folder() {
        let (profile, mut spec) = setup("gitwt", "opencode", &[]);
        let common = profile.join("main/.git");
        let wt_git = common.join("worktrees/feature");
        std::fs::create_dir_all(common.join("hooks")).unwrap();
        std::fs::write(common.join("HEAD"), "ref: refs/heads/main\n").unwrap();
        std::fs::create_dir_all(common.join("objects")).unwrap();
        std::fs::create_dir_all(&wt_git).unwrap();
        std::fs::write(wt_git.join("commondir"), "../..\n").unwrap();
        std::fs::write(wt_git.join("gitdir"), format!("{}\n", spec.project_root.join(".git").display())).unwrap();
        std::fs::write(spec.project_root.join(".git"), format!("gitdir: {}\n", wt_git.display())).unwrap();
        run(&mut spec, &profile);
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_0"), Some(git_path(&spec.project_root).as_str()));
        assert_eq!(last(&spec.env, "GIT_CONFIG_KEY_1"), Some("safe.directory"));
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_1"), Some(git_path(&common).as_str()));
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("2"));
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn a_git_path_has_forward_slashes_and_no_verbatim_prefix() {
        assert_eq!(git_path(Path::new(r"C:\Users\dev\proj")), "C:/Users/dev/proj");
        assert_eq!(git_path(Path::new(r"\\?\C:\Users\dev\proj")), "C:/Users/dev/proj");
        assert_eq!(git_path(Path::new(r"\\?\UNC\srv\share\proj")), "//srv/share/proj");
    }

    /// A provisioned config holds the gateway key and is written readable by
    /// the developer alone, so the account reads it only through a grant of
    /// its own: a project's and a home's alike, each once; one outside both
    /// the profile and the project is not granted, one in a project outside
    /// the profile is.
    #[test]
    fn every_file_the_client_was_provisioned_with_is_granted_to_read() {
        let (profile, mut spec) = setup("client-files", "claude", &[]);
        let outside = scratch("client-files-outside");
        let project = spec.project_root.join(".claude/settings.json");
        let home = profile.join(".codex/config.toml");
        let ca = profile.join("ca.pem");
        for f in [&project, &home, &ca] {
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, "{}").unwrap();
        }
        let away = outside.join("settings.json");
        std::fs::write(&away, "{}").unwrap();
        spec.ca_files = vec![ca.clone()];
        spec.client_files = vec![project.clone(), home.clone(), away.clone(), ca.clone(), profile.join("gone.json")];
        let dirs = prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: None, program: None }).unwrap();
        assert_eq!(dirs.files, vec![ca, project, home.clone()]);
        // A project outside the profile: its
        // provisioned file is the developer's to grant; a CA file beside it
        // is not granted.
        let outside_project = outside.join("proj");
        let in_project = outside_project.join(".claude/settings.json");
        std::fs::create_dir_all(in_project.parent().unwrap()).unwrap();
        std::fs::write(&in_project, "{}").unwrap();
        spec.project_root = outside_project;
        spec.ca_files = vec![away.clone()];
        spec.client_files = vec![in_project.clone(), home.clone(), away];
        let dirs = prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: None, program: None }).unwrap();
        assert_eq!(dirs.files, vec![in_project, home]);
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn tools_and_files_are_granted_only_inside_the_profile() {
        let (profile, mut spec) = setup("tools", "opencode", &[]);
        let outside = scratch("tools-outside");
        let bin = profile.join("AppData/Roaming/npm");
        std::fs::create_dir_all(&bin).unwrap();
        let ca = profile.join("ca.pem");
        std::fs::write(&ca, "pem").unwrap();
        let outside_ca = outside.join("ca.pem");
        std::fs::write(&outside_ca, "pem").unwrap();
        // A folder is not a CA file.
        spec.ca_files = vec![ca.clone(), outside_ca, bin.clone()];
        let own = profile.join("ssai");
        let program = bin.join("opencode.cmd");
        std::fs::write(&program, "").unwrap();
        let dirs = prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: Some(&own), program: Some(&program) })
            .unwrap();
        assert_eq!(dirs.tools, vec![own.clone(), bin.clone()]);
        assert_eq!(dirs.files, vec![ca]);
        // Outside the profile: neither.
        let dirs =
            prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: Some(&outside), program: None }).unwrap();
        assert!(dirs.tools.is_empty());
        for dir in [profile, outside] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_program_linked_to_another_folder_grants_both() {
        let profile = scratch("link");
        let (shims, real) = (profile.join("shims"), profile.join("pkg/bin"));
        std::fs::create_dir_all(&shims).unwrap();
        std::fs::create_dir_all(&real).unwrap();
        std::fs::write(real.join("claude"), "").unwrap();
        std::os::unix::fs::symlink(real.join("claude"), shims.join("claude")).unwrap();
        assert_eq!(program_dirs(&shims.join("claude")), vec![shims.clone(), real.clone()]);
        // Not a link: its folder once.
        assert_eq!(program_dirs(&real.join("claude")), vec![real]);
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn under_compares_without_case_or_slash_kind() {
        assert!(under(Path::new(r"C:\Users\Dev\AppData\npm"), Path::new("c:/users/dev")));
        assert!(!under(Path::new(r"C:\Users\Dev"), Path::new(r"C:\Users\Dev")));
        assert!(!under(Path::new(r"C:\Users\Devil\x"), Path::new(r"C:\Users\Dev")));
        assert!(!under(Path::new(r"C:\Program Files\nodejs"), Path::new(r"C:\Users\Dev")));
    }
}
