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
    /// Whether a private folder of the developer's other than the profile
    /// holds `path` — a private root, which no other account reads — so a
    /// tool or file there is granted as one in the profile is.
    pub private: &'a dyn Fn(&Path) -> bool,
    /// The developer's global git identity (`user.name`, `user.email`,
    /// each when set), as their global configuration and its includes give
    /// it in the project.
    pub git_identity: &'a [(&'static str, String)],
    /// The folder the account's global git configuration holding that
    /// identity is placed in; `None`: none is.
    pub git_global: Option<&'a Path>,
}

/// Adjust `spec` for the sandbox account and return what it must be granted:
/// - each configuration variable of `agent`'s Windows column is set to its
///   value among the developer's folders, ahead of the run's own variables,
///   so a `--env` naming another value wins; the entry's folder under that
///   value (created when absent) is the one granted and seeded;
/// - the seed: each `(file, key)` in the first of those folders gets `key`
///   set to `true` when absent;
/// - the column's arguments go before the client's own;
/// - each client the agent may run as a tool gets its folder and files, or
///   its endpoint in its variables ([`reach_tools`]);
/// - git trusts the project root and a linked worktree's common git folder
///   and every repository under the root, a submodule's checkout included
///   (`safe.directory`, appended after any `GIT_CONFIG_COUNT` the run sets);
/// - git commits as the developer: their global identity, handed to the
///   account as its global configuration ([`commit_as_developer`]);
/// - `tools`: the folder of `ssai` and of the client's program (and the
///   folder it resolves to, when another), and the cross-agent skills store
///   when it exists; `files`: the CA files, the git identity file and the
///   files the client was provisioned with (readable by the developer alone,
///   so the grant on their folder misses them). Each only
///   inside the developer's private folders — the profile, a private root
///   (`Host::private`) — which no other account reads: elsewhere what is
///   there is readable by every account already, and only an administrator
///   could grant one — but for a provisioned file in the project, which is
///   the developer's own to grant wherever the project is.
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
    let tool_files = reach_tools(spec, host, &mut dirs)?;
    trust_in_git(spec)?;
    commit_as_developer(spec, host, &mut dirs);
    carry_node_ca(spec, host);
    let found = host
        .own_dir
        .map(Path::to_path_buf)
        .into_iter()
        .chain(host.program.into_iter().flat_map(program_dirs))
        .chain(host.program.into_iter().flat_map(|p| tool_environments(p, host)));
    // The cross-agent skills store, read by every client: the skills CLI
    // keeps a skill installed for several clients there once, and links each
    // client's own skills folder entry to it (a junction the grant on that
    // folder does not follow). Granted as it is on disk, and only when it
    // exists and lies inside the profile.
    let skills = dunce::canonicalize(host.profile.join(SHARED_SKILLS)).ok().filter(|d| d.is_dir());
    let mine = |p: &Path| under(p, host.profile) || (host.private)(p);
    for dir in found.chain(skills) {
        if mine(&dir) && !dirs.tools.contains(&dir) {
            dirs.tools.push(dir);
        }
    }
    // Each file as it is on disk (a junction or a short name followed), as
    // the profile and the root are.
    let real = |f: &PathBuf| dunce::canonicalize(f).ok().filter(|r| r.is_file());
    let ca = spec.ca_files.iter().filter_map(real).filter(|f| mine(f));
    // A client file is the canonical path the run resolved: one that now
    // resolves elsewhere (a link swapped in since) is not granted.
    let provisioned = spec
        .client_files
        .iter()
        .chain(&tool_files)
        .filter_map(|f| real(f).filter(|r| r == f))
        .filter(|f| mine(f) || under(f, &spec.project_root));
    for file in ca.chain(provisioned) {
        if !dirs.files.contains(&file) {
            dirs.files.push(file);
        }
    }
    Ok(dirs)
}

/// The cross-agent skills store, below the profile; the Linux sandbox reads
/// the same folder (`profiles::BASE_READ`).
const SHARED_SKILLS: &str = ".agents/skills";

/// The client id whose endpoint [`ocr_env`] carries.
const OCR_CLIENT_ID: &str = "open-code-review";

/// The variables Open Code Review reads its endpoint from when it finds no
/// config file; a run that sets any of them is left to its own.
const OCR_ENDPOINT_VARS: [&str; 4] = ["OCR_LLM_URL", "OCR_LLM_TOKEN", "OCR_LLM_MODEL", "OCR_LLM_PROTOCOL"];

/// Reach each client the agent may run as a tool (`spec.tool_clients`), and
/// return its provisioned files for the grant to give the account to read.
/// Where the run points every variable of the tool's Windows column where the
/// tool's own run would (the launched client's column sets `USERPROFILE` to
/// the developer's profile, as the tool's does), the tool reads its own
/// config there: its folder is granted as a state folder, its files as files.
/// Elsewhere the tool would read the sandbox account's profile, and Open Code
/// Review is handed its endpoint in its variables instead ([`ocr_env`]),
/// unless the run sets one; any other tool is named in a warning.
fn reach_tools(spec: &mut LaunchSpec, host: &Host, dirs: &mut RunDirs) -> Result<Vec<PathBuf>> {
    let mut files = Vec::new();
    let mut carried: Vec<(String, String)> = Vec::new();
    for tool in &spec.tool_clients {
        let column = tool.profile.windows_config;
        let shared: Option<Vec<PathBuf>> = (!column.is_empty())
            .then(|| {
                column
                    .iter()
                    .map(|c| {
                        let own = anchored(c.value, host)?;
                        let run = PathBuf::from(last(&spec.env, c.var)?);
                        same_folder(&run, &own).then(|| in_folder(&own, c.granted))
                    })
                    .collect()
            })
            .flatten();
        if let Some(folders) = shared {
            // A tool the grant would refuse is left out, never the run.
            let profile = host.profile.to_string_lossy();
            if let Some((folder, why)) =
                folders.iter().find_map(|f| refused_root(&f.to_string_lossy(), &profile).map(|why| (f, why)))
            {
                crate::ui::warn(
                    "",
                    format_args!("{} is not given its folder {}: {why}", tool.client_id, folder.display()),
                );
                continue;
            }
            if let Some((folder, e)) = folders.iter().find_map(|f| std::fs::create_dir_all(f).err().map(|e| (f, e))) {
                crate::ui::warn("", format_args!("{} is not given its folder {}: {e}", tool.client_id, folder.display()));
                continue;
            }
            for folder in folders {
                if !dirs.state.contains(&folder) {
                    dirs.state.push(folder);
                }
            }
            files.extend(tool.files.iter().cloned());
            continue;
        }
        if tool.client_id != OCR_CLIENT_ID {
            crate::ui::warn(
                "",
                format_args!("{} is not given its config under the Windows sandbox for this client", tool.client_id),
            );
            continue;
        }
        if OCR_ENDPOINT_VARS.iter().any(|v| last(&spec.env, v).is_some()) {
            continue;
        }
        let Some(config) = tool.files.first() else { continue };
        match std::fs::read(config).map_err(|e| e.to_string()).and_then(|bytes| ocr_env(&bytes)) {
            Ok(env) => carried.extend(env.into_iter().filter(|(k, _)| last(&spec.env, k).is_none())),
            Err(why) => crate::ui::warn(
                "",
                format_args!(
                    "{}: {} is not the config ssai provisioned ({why}) — Open Code Review is not handed its \
                     endpoint under the Windows sandbox",
                    tool.client_id,
                    config.display()
                ),
            ),
        }
    }
    // Ahead of the run's own variables, as a column's defaults are.
    spec.env.splice(0..0, carried);
    Ok(files)
}

/// Open Code Review's endpoint as the variables it reads when it finds no
/// config file, from the config its template writes: the literal `provider`
/// naming an entry of `custom_providers` that holds a string `url`,
/// `api_key`, `model` and `protocol` (and its `models` list) and nothing
/// else; plus `OCR_NO_UPDATE`. Any other provider shape — a command producing
/// the key, a preset provider, the legacy `llm` section, a provider setting
/// the variables cannot carry — is refused with why: carried half, the run
/// would use another endpoint than the file names. The file's other
/// top-level settings (its gateway `mcp_servers`) have no variable form and
/// are not carried: the tool reaches the model, not its MCP servers.
fn ocr_env(config: &[u8]) -> std::result::Result<Vec<(String, String)>, String> {
    use serde_json::Value;
    let doc: Value = serde_json::from_slice(config).map_err(|e| format!("not JSON: {e}"))?;
    let provider = doc.get("provider").and_then(Value::as_str).ok_or("no `provider` names the endpoint")?;
    let Some(entry) = doc.get("custom_providers").and_then(|p| p.get(provider)).and_then(Value::as_object) else {
        return Err(format!("`{provider}` is not one of its `custom_providers`"));
    };
    if let Some(other) = entry.keys().find(|k| !["url", "api_key", "model", "protocol", "models"].contains(&k.as_str())) {
        return Err(format!("its provider sets `{other}`"));
    }
    let field = |name: &str| {
        entry
            .get(name)
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| format!("its provider has no `{name}`"))
    };
    let (url, token, model, protocol) = (field("url")?, field("api_key")?, field("model")?, field("protocol")?);
    if !["anthropic", "openai", "openai-responses"].contains(&protocol) {
        return Err(format!("its provider speaks `{protocol}`"));
    }
    // Its file names a base its reader completes, its variable the address it
    // posts to (unless it already ends with the messages path): carried as
    // the file would resolve it.
    let url = if protocol == "anthropic" { anthropic_messages_url(url) } else { url.to_string() };
    Ok([
        ("OCR_LLM_URL", url.as_str()),
        ("OCR_LLM_TOKEN", token),
        ("OCR_LLM_MODEL", model),
        ("OCR_LLM_PROTOCOL", protocol),
        ("OCR_NO_UPDATE", "1"),
    ]
    .into_iter()
    .map(|(k, v)| (k.to_string(), v.to_string()))
    .collect())
}

/// An Anthropic endpoint as Open Code Review completes the one its config
/// file names: a URL ending with the messages path is kept, one ending with
/// `/v1` gets `/messages`, one with `/v1/` inside it is kept, and any other
/// gets `/v1/messages`.
fn anthropic_messages_url(url: &str) -> String {
    let trimmed = url.trim_end_matches('/');
    if trimmed.ends_with("/v1/messages") || (trimmed.contains("/v1/") && !trimmed.ends_with("/v1")) {
        url.to_string()
    } else if trimmed.ends_with("/v1") {
        format!("{trimmed}/messages")
    } else {
        format!("{trimmed}/v1/messages")
    }
}

/// `a` and `b` name the same folder, compared without case and either slash,
/// as Windows compares paths.
fn same_folder(a: &Path, b: &Path) -> bool {
    norm(a) == norm(b)
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
/// trust the project root, every repository under it (`<root>/*`: a
/// submodule's checkout — git 2.46 and later read the wildcard) and a linked
/// worktree's common git folder for this run, through the `GIT_CONFIG_*`
/// variables — no gitconfig is written for it — appended after the entries the run
/// already sets. The trust is the sandbox account's alone, in a project it
/// may write.
fn trust_in_git(spec: &mut LaunchSpec) -> Result<()> {
    let project = protect::resolve(&spec.project_root);
    let root = git_path(&spec.project_root);
    let trusted: Vec<String> = std::iter::once(root.clone())
        .chain(project.extra_rw.iter().map(|p| git_path(p)))
        .chain(std::iter::once(format!("{}/*", root.trim_end_matches('/'))))
        .collect();
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

/// The account's own global git configuration is empty, so git would make
/// its commits' identity from the account's name and the host's, or refuse
/// to commit: the developer's global identity (`Host::git_identity`) is
/// written to a file in `Host::git_global` and handed to the account as its
/// global configuration (`GIT_CONFIG_GLOBAL`), granted to read — an empty
/// one when they have none, so the account's global configuration is a
/// read-only file for every developer. Global, so every repository's own
/// identity is read over it, as on the host. Nothing when the run names its
/// own global configuration.
///
/// The file is named by its text and never rewritten: a run's agent reads
/// git's configuration again on every command, so another run — another
/// project, another identity — must neither change the file it holds nor
/// replace it (and with it the entry granting it). Not essential to the run:
/// a file that cannot be placed is warned of, and the run goes on without it.
fn commit_as_developer(spec: &mut LaunchSpec, host: &Host, dirs: &mut RunDirs) {
    let Some(dir) = host.git_global else { return };
    if last(&spec.env, "GIT_CONFIG_GLOBAL").is_some() {
        return;
    }
    match host.git_identity {
        [] => crate::ui::warn(
            "",
            "your global git configuration sets no user.name or user.email: where the repository sets none either, git makes the agent's identity up from the sandbox account and this computer, or refuses to commit",
        ),
        [(key, _)] => crate::ui::warn(
            "",
            format_args!("your global git configuration sets {key} alone: git makes up the other from the sandbox account and this computer"),
        ),
        _ => {}
    }
    if !(under(dir, host.profile) || (host.private)(dir)) {
        crate::ui::warn(
            "",
            format_args!(
                "{} is outside your profile, where the sandbox account is not granted it: the agent commits under the account's own git identity",
                dir.display()
            ),
        );
        return;
    }
    let placed = place_named(dir, "gitconfig", gitconfig(host.git_identity).as_bytes())
        .and_then(|f| dunce::canonicalize(&f).with_context(|| format!("resolve {}", f.display())));
    let real = match placed {
        Ok(file) => file,
        Err(e) => {
            crate::ui::warn("", format_args!("{e:#}: the agent commits under the sandbox account's git identity"));
            return;
        }
    };
    // Only inside the developer's private folders, as every other file of
    // the run is granted.
    if !(under(&real, host.profile) || (host.private)(&real)) {
        crate::ui::warn(
            "",
            format_args!(
                "{} is outside your profile, where the sandbox account is not granted it: the agent commits under the account's own git identity",
                real.display()
            ),
        );
        return;
    }
    spec.env.push(("GIT_CONFIG_GLOBAL".to_string(), real.to_string_lossy().into_owned()));
    if !dirs.files.contains(&real) {
        dirs.files.push(real);
    }
}

/// The file in `dir` named by `bytes` (`<sha>.<ext>`) and holding them,
/// placed when absent: written aside and hard-linked into place, which fails
/// rather than replace a file another run placed first — a replaced file
/// would lose the read entry that run granted on it, while it reads on. One
/// found holding anything else (a write cut short) is refused, never used.
pub(super) fn place_named(dir: &Path, ext: &str, bytes: &[u8]) -> Result<PathBuf> {
    use sha2::Digest as _;
    let name = hex::encode(&sha2::Sha256::digest(bytes)[..12]);
    let file = dir.join(format!("{name}.{ext}"));
    if !file.is_file() {
        std::fs::create_dir_all(dir).with_context(|| format!("create {}", dir.display()))?;
        let part = dir.join(format!("{name}.{}.part", std::process::id()));
        let placed = std::fs::write(&part, bytes).and_then(|()| std::fs::hard_link(&part, &file));
        let _ = std::fs::remove_file(&part);
        if let Err(e) = placed
            && !file.is_file()
        {
            return Err(e).with_context(|| format!("write {}", file.display()));
        }
    }
    let held = std::fs::read(&file).with_context(|| format!("read {}", file.display()))?;
    if held != bytes {
        bail!("{} does not hold what its name says (remove it)", file.display());
    }
    Ok(file)
}

/// `entries` (`section.name`, value) as a git configuration file, each value
/// quoted and escaped as git reads it back.
fn gitconfig(entries: &[(&'static str, String)]) -> String {
    let mut out = String::new();
    let mut section = "";
    for (key, value) in entries {
        let (sec, name) = key.split_once('.').unwrap_or(("user", key));
        if sec != section {
            out.push_str(&format!("[{sec}]\n"));
            section = sec;
        }
        let quoted = value.replace('\\', r"\\").replace('"', r#"\""#).replace('\n', r"\n");
        out.push_str(&format!("\t{name} = \"{quoted}\"\n"));
    }
    out
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

/// The Python environments a launcher in `~/.local/bin` (where uv and pipx
/// put theirs) starts the client from: uv's (`%APPDATA%\uv\tools\<tool>`) and pipx's
/// (`~\pipx\venvs\<tool>`, `~\.local\pipx\venvs\<tool>`) environment
/// whose `Scripts` folder holds a program of the same name, and the Python
/// its `pyvenv.cfg` names as `home` — what the launcher runs, which the
/// program's folder alone does not reach.
fn tool_environments(program: &Path, host: &Host) -> Vec<PathBuf> {
    // Only a launcher in the folder both put theirs in: a program found
    // elsewhere (`python`, a tool's own `Scripts`) names no one environment.
    let launchers = host.profile.join(".local").join("bin");
    let in_launchers = program.parent().is_some_and(|dir| {
        norm(dir) == norm(&launchers)
    });
    let Some(name) = program.file_name().filter(|_| in_launchers) else { return Vec::new() };
    let roots = host
        .appdata
        .map(|a| a.join("uv").join("tools"))
        .into_iter()
        .chain([host.profile.join("pipx").join("venvs"), host.profile.join(".local").join("pipx").join("venvs")]);
    let mut out = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else { continue };
        for env in entries.filter_map(|e| e.ok()).map(|e| e.path()) {
            if !env.join("Scripts").join(name).is_file() {
                continue;
            }
            let home = std::fs::read_to_string(env.join("pyvenv.cfg")).ok().and_then(|cfg| {
                cfg.lines().find_map(|l| {
                    let (k, v) = l.split_once('=')?;
                    (k.trim() == "home").then(|| PathBuf::from(v.trim()))
                })
            });
            out.push(env);
            // As it is on disk (`..`, a junction or a short name followed), as
            // the profile is, so the caller's inside-the-profile check holds;
            // and only a folder holding the interpreter: the file is the
            // developer's, but a `home` naming a broad folder must not widen
            // the grant.
            let home = home.filter(|h| h.is_absolute()).and_then(|h| dunce::canonicalize(h).ok());
            out.extend(home.filter(|h| h.join("python.exe").is_file()));
        }
    }
    out
}

/// `path` is inside the folder `profile`, compared without case and either
/// slash, as Windows compares paths.
/// A path as Windows compares paths: either slash, no trailing one, no case.
fn norm(p: &Path) -> String {
    p.to_string_lossy().replace('\\', "/").trim_end_matches('/').to_lowercase()
}

fn under(path: &Path, profile: &Path) -> bool {
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
            network: None,
            default_image: None,
            env: env.iter().map(|(k, v)| (k.to_string(), v.to_string())).collect(),
            ca_files: vec![],
            ca_bundle: None,
            home_files: vec![],
            client_files: vec![],
            private_root: false,
            opencode: None,
            tool_clients: Vec::new(),
        };
        (profile, spec)
    }

    fn run(spec: &mut LaunchSpec, profile: &Path) -> RunDirs {
        let agent = agent_for(&spec.command);
        prepare(spec, agent, &Host { profile, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None }).unwrap()
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
            let host = Host { profile: &profile, appdata: None, node_ca: Some(&root), own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None };
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
        let dirs = prepare(&mut spec, agent_for("goose"), &Host { profile: &profile, appdata: Some(&appdata), node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None })
            .unwrap();
        let root = appdata.join("Block").join("goose");
        assert_eq!(spec.env[0], ("GOOSE_PATH_ROOT".to_string(), root.to_string_lossy().into_owned()));
        assert_eq!(dirs.state, vec![root.clone()]);
        assert!(root.is_dir());
        let (profile2, mut spec) = setup("goose-noappdata", "goose", &[]);
        let err = prepare(&mut spec, agent_for("goose"), &Host { profile: &profile2, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None })
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
        let err = prepare(&mut spec, agent_for("claude"), &Host { profile: &profile2, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None })
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
        let err = prepare(&mut spec, agent_for("claude"), &Host { profile: &profile, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None })
            .unwrap_err();
        assert!(err.to_string().contains("refuses the client's folder"), "{err}");
        assert!(!profile.join(".claude.json").exists(), "the profile was seeded before the refusal");
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn a_client_without_a_profile_is_changed_only_for_git() {
        let (profile, mut spec) = setup("plain", "my-own-agent", &[]);
        let dirs = run(&mut spec, &profile);
        assert!(dirs.state.is_empty());
        assert_eq!(spec.args, ["--resume"]);
        assert!(spec.env.iter().all(|(k, _)| k.starts_with("GIT_CONFIG_")), "{:?}", spec.env);
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// OpenCode is pointed at the folder provision writes its configuration
    /// into, by its own variable, and that folder alone is granted; in a
    /// project the run's own value (the project's folder) wins.
    #[test]
    fn opencode_reads_the_developers_config_folder_and_only_its_own_is_granted() {
        let (profile, mut spec) = setup("opencode", "opencode", &[]);
        let dirs = run(&mut spec, &profile);
        let config = profile.join(".config").join("opencode");
        assert_eq!(spec.env[0], ("OPENCODE_CONFIG_DIR".to_string(), config.to_string_lossy().into_owned()));
        assert_eq!(dirs.state, vec![config.clone()]);
        assert!(config.is_dir());
        let _ = std::fs::remove_dir_all(&profile);

        let (profile, mut spec) = setup("opencode-project", "opencode", &[]);
        let project = profile.join("project").join(".opencode");
        spec.env.push(("OPENCODE_CONFIG_DIR".into(), project.to_string_lossy().into_owned()));
        let dirs = run(&mut spec, &profile);
        assert_eq!(dirs.state, vec![project]);
        assert_eq!(spec.env.iter().filter(|(k, _)| k == "OPENCODE_CONFIG_DIR").count(), 1);
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// A client that reads no variable but the home: `USERPROFILE` is the
    /// developer's profile, and only the client's folder in it is granted.
    #[test]
    fn a_home_only_client_is_given_the_profile_and_granted_its_folder_alone() {
        let (profile, mut spec) = setup("ocr", "ocr", &[]);
        let dirs = run(&mut spec, &profile);
        assert_eq!(spec.env[0], ("USERPROFILE".to_string(), profile.to_string_lossy().into_owned()));
        assert_eq!(dirs.state, vec![profile.join(".opencodereview")]);
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// Open Code Review's config as its template writes it, for `protocol`.
    fn ocr_config(protocol: &str) -> String {
        serde_json::json!({
            "provider": "streamscope",
            "custom_providers": { "streamscope": {
                "protocol": protocol, "url": "https://gw.example/v1", "api_key": "sk-ocr",
                "model": "review", "models": ["review"],
            }},
            "mcp_servers": { "web": { "type": "remote", "url": "https://gw.example/mcp/web" } },
        })
        .to_string()
    }

    /// A profile holding a project and Open Code Review's provisioned config,
    /// and a spec for `command` that may run it as a tool.
    fn with_ocr(name: &str, command: &str, env: &[(&str, &str)]) -> (PathBuf, LaunchSpec, PathBuf) {
        let (profile, mut spec) = setup(name, command, env);
        let config = profile.join(".opencodereview").join("config.json");
        std::fs::create_dir_all(config.parent().unwrap()).unwrap();
        std::fs::write(&config, ocr_config("anthropic")).unwrap();
        spec.tool_clients.push(crate::sandbox::ToolClient {
            client_id: OCR_CLIENT_ID.into(),
            profile: agent_for(OCR_CLIENT_ID).unwrap(),
            files: vec![config.clone()],
        });
        (profile, spec, config)
    }

    /// Under a client whose run already reads the developer's profile as its
    /// home (Aider), the tool reads its own config there: its folder and file
    /// are granted, no variable is carried.
    #[test]
    fn a_tool_sharing_the_launched_clients_home_is_granted_its_folder_and_files() {
        let (profile, mut spec, config) = with_ocr("tool-aider", "aider", &[]);
        let dirs = run(&mut spec, &profile);
        assert!(dirs.state.contains(&profile.join(".opencodereview")), "{:?}", dirs.state);
        assert!(dirs.files.contains(&config), "{:?}", dirs.files);
        assert!(last(&spec.env, "OCR_LLM_TOKEN").is_none(), "{:?}", spec.env);
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// Under a client whose run keeps the account's own home (Claude Code),
    /// Open Code Review is handed its endpoint in its variables, and given
    /// none of its files; a run without the tool carries none (the control),
    /// and a run naming one of the endpoint variables itself is left alone.
    #[test]
    fn a_tool_outside_the_launched_clients_home_is_handed_its_endpoint() {
        let (profile, mut spec, config) = with_ocr("tool-claude", "claude", &[]);
        let dirs = run(&mut spec, &profile);
        for (k, v) in [
            ("OCR_LLM_URL", "https://gw.example/v1/messages"),
            ("OCR_LLM_TOKEN", "sk-ocr"),
            ("OCR_LLM_MODEL", "review"),
            ("OCR_LLM_PROTOCOL", "anthropic"),
            ("OCR_NO_UPDATE", "1"),
        ] {
            assert_eq!(last(&spec.env, k), Some(v), "{k}: {:?}", spec.env);
        }
        assert!(!dirs.files.contains(&config) && !dirs.state.contains(&profile.join(".opencodereview")));
        let _ = std::fs::remove_dir_all(&profile);

        let (profile, mut spec) = setup("tool-none", "claude", &[]);
        run(&mut spec, &profile);
        assert!(OCR_ENDPOINT_VARS.iter().all(|v| last(&spec.env, v).is_none()), "{:?}", spec.env);
        let _ = std::fs::remove_dir_all(&profile);

        let (profile, mut spec, _) = with_ocr("tool-own", "claude", &[("OCR_LLM_URL", "https://mine.example")]);
        run(&mut spec, &profile);
        assert_eq!(last(&spec.env, "OCR_LLM_URL"), Some("https://mine.example"));
        assert!(last(&spec.env, "OCR_LLM_TOKEN").is_none(), "{:?}", spec.env);
        let _ = std::fs::remove_dir_all(&profile);
    }

    /// The endpoint is read only from the shape the template writes, each of
    /// its protocols as Open Code Review names it; any other shape carries
    /// nothing.
    #[test]
    fn only_the_provisioned_config_shape_becomes_the_endpoint_variables() {
        for protocol in ["anthropic", "openai", "openai-responses"] {
            let env = ocr_env(ocr_config(protocol).as_bytes()).unwrap();
            assert!(env.contains(&("OCR_LLM_PROTOCOL".to_string(), protocol.to_string())), "{env:?}");
            assert!(env.contains(&("OCR_LLM_TOKEN".to_string(), "sk-ocr".to_string())), "{env:?}");
        }
        let edited = |edit: &dyn Fn(&mut serde_json::Value)| {
            let mut doc: serde_json::Value = serde_json::from_str(&ocr_config("openai")).unwrap();
            edit(&mut doc);
            ocr_env(doc.to_string().as_bytes())
        };
        let entry = |doc: &mut serde_json::Value| doc["custom_providers"]["streamscope"].as_object_mut().unwrap().clone();
        type Edit<'a> = &'a dyn Fn(&mut serde_json::Value);
        let refused: [(&str, Edit); 6] = [
            ("api_key_cmd", &|d| {
                let mut e = entry(d);
                e.remove("api_key");
                e.insert("api_key_cmd".into(), "pass show gw".into());
                d["custom_providers"]["streamscope"] = e.into();
            }),
            ("a preset provider", &|d| d["provider"] = "anthropic".into()),
            ("the legacy llm section", &|d| {
                d.as_object_mut().unwrap().remove("provider");
                d["llm"] = serde_json::json!({ "url": "https://x", "auth_token": "t", "model": "m" });
            }),
            ("bedrock", &|d| d["custom_providers"]["streamscope"]["protocol"] = "anthropic-bedrock".into()),
            ("a timeout", &|d| d["custom_providers"]["streamscope"]["timeout_sec"] = 30.into()),
            ("an empty key", &|d| d["custom_providers"]["streamscope"]["api_key"] = "".into()),
        ];
        for (what, edit) in refused {
            assert!(edited(edit).is_err(), "{what} was accepted");
        }
        assert!(ocr_env(b"not json").is_err());
    }

    /// The variable carries the address Open Code Review would post to from
    /// its file: an Anthropic base is completed as its file reader completes
    /// it (its variable reader would append the messages path to `/v1`
    /// again); an OpenAI one travels as written.
    #[test]
    fn an_anthropic_endpoint_is_carried_as_the_file_would_resolve_it() {
        for (base, posted) in [
            ("https://gw.example", "https://gw.example/v1/messages"),
            ("https://gw.example/", "https://gw.example/v1/messages"),
            ("https://gw.example/v1", "https://gw.example/v1/messages"),
            ("https://gw.example/v1/", "https://gw.example/v1/messages"),
            ("https://gw.example/v1/messages", "https://gw.example/v1/messages"),
            ("https://gw.example/api/v1", "https://gw.example/api/v1/messages"),
            ("https://gw.example/v1/anthropic", "https://gw.example/v1/anthropic"),
            ("https://gw.example/v2", "https://gw.example/v2/v1/messages"),
        ] {
            assert_eq!(anthropic_messages_url(base), posted, "{base}");
        }
        let env = ocr_env(ocr_config("openai").as_bytes()).unwrap();
        assert!(env.contains(&("OCR_LLM_URL".to_string(), "https://gw.example/v1".to_string())), "{env:?}");
    }

    /// A uv or pipx launcher: its environment and the Python it was made
    /// with are granted when in the profile; another tool's environment, a
    /// Python outside the profile, and a `home` holding no interpreter are not.
    #[test]
    fn a_python_tool_launcher_reaches_its_environment_and_its_python() {
        let (profile, mut spec) = setup("venv", "aider", &[]);
        let appdata = profile.join("AppData").join("Roaming");
        let bin = profile.join(".local").join("bin");
        let python = appdata.join("uv").join("python").join("cpython-3.12");
        let aider = appdata.join("uv").join("tools").join("aider-chat");
        let other = appdata.join("uv").join("tools").join("other");
        let pipx = profile.join("pipx").join("venvs").join("aider-chat");
        for d in [&bin, &python, &aider.join("Scripts"), &other.join("Scripts"), &pipx.join("Scripts")] {
            std::fs::create_dir_all(d).unwrap();
        }
        for f in [python.join("python.exe"), bin.join("aider.exe"), aider.join("Scripts").join("aider.exe"), other.join("Scripts").join("vibe.exe"), pipx.join("Scripts").join("aider.exe")] {
            std::fs::write(f, b"").unwrap();
        }
        std::fs::write(aider.join("pyvenv.cfg"), format!("home = {}\nversion = 3.12\n", python.display())).unwrap();
        std::fs::write(pipx.join("pyvenv.cfg"), "home = C:\\Program Files\\Python312\n").unwrap();
        let program = bin.join("aider.exe");
        let host = Host { profile: &profile, appdata: Some(&appdata), node_ca: None, own_dir: None, program: Some(&program), private: &|_| false, git_identity: &[], git_global: None };
        let dirs = prepare(&mut spec, agent_for("aider"), &host).unwrap();
        assert_eq!(dirs.tools, vec![bin.clone(), aider.clone(), python.clone(), pipx.clone()]);
        // A `home` without the interpreter in it is not granted.
        std::fs::remove_file(python.join("python.exe")).unwrap();
        let (other, mut again) = setup("venv-again", "aider", &[]);
        let dirs = prepare(&mut again, agent_for("aider"), &host).unwrap();
        assert_eq!(dirs.tools, vec![bin.clone(), aider.clone(), pipx.clone()]);
        // A `home` spelled inside the profile that resolves outside it is not.
        let outside = scratch("venv-outside");
        std::fs::write(outside.join("python.exe"), b"").unwrap();
        let dotted = profile.join("x").join("..").join("..").join(outside.file_name().unwrap());
        std::fs::create_dir_all(profile.join("x")).unwrap();
        std::fs::write(aider.join("pyvenv.cfg"), format!("home = {}\n", dotted.display())).unwrap();
        let dirs = prepare(&mut again, agent_for("aider"), &host).unwrap();
        assert_eq!(dirs.tools, vec![bin, aider.clone(), pipx]);
        // A program found anywhere else names no environment, whatever its name.
        let elsewhere = aider.join("Scripts").join("aider.exe");
        let host = Host { program: Some(&elsewhere), ..host };
        let dirs = prepare(&mut again, agent_for("aider"), &host).unwrap();
        assert_eq!(dirs.tools, vec![aider.join("Scripts")]);
        let _ = std::fs::remove_dir_all(&other);
        let _ = std::fs::remove_dir_all(&outside);
        let _ = std::fs::remove_dir_all(&profile);
    }

    #[test]
    fn git_trusts_the_root_after_the_entries_the_run_already_sets() {
        let (profile, mut spec) = setup("gitcount", "opencode", &[("GIT_CONFIG_COUNT", "2")]);
        run(&mut spec, &profile);
        let root = git_path(&spec.project_root);
        assert_eq!(last(&spec.env, "GIT_CONFIG_KEY_2"), Some("safe.directory"));
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_2"), Some(root.as_str()));
        // Then every repository under it (a submodule's checkout).
        assert_eq!(last(&spec.env, "GIT_CONFIG_KEY_3"), Some("safe.directory"));
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_3"), Some(format!("{root}/*").as_str()));
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("4"));
        assert_eq!(last(&spec.env, "GIT_CONFIG_KEY_0"), None);
        // None set: from 0.
        let (profile2, mut spec) = setup("gitzero", "opencode", &[]);
        run(&mut spec, &profile2);
        assert_eq!(last(&spec.env, "GIT_CONFIG_VALUE_0"), Some(git_path(&spec.project_root).as_str()));
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("2"));
        // Not a count: refused.
        let (profile3, mut spec) = setup("gitbad", "opencode", &[("GIT_CONFIG_COUNT", "x")]);
        let err = prepare(&mut spec, None, &Host { profile: &profile3, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None }).unwrap_err();
        assert!(err.to_string().contains("GIT_CONFIG_COUNT"), "{err}");
        for dir in [profile, profile2, profile3] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    #[test]
    fn git_commits_as_the_developer_through_a_global_config_of_their_identity() {
        let identity = [("user.name", r#"Dev "Q" Eloper\x"#.to_string()), ("user.email", "dev@example.com".to_string())];
        let host = |profile: &'static Path, dir: &'static Path, identity: &'static [(&'static str, String)]| Host {
            profile,
            appdata: None,
            node_ca: None,
            own_dir: None,
            program: None,
            private: &|_| false,
            git_identity: identity,
            git_global: Some(dir),
        };
        let leak = |p: PathBuf| -> &'static Path { Box::leak(p.into_boxed_path()) };
        let identity: &'static [(&'static str, String)] = Box::leak(Box::new(identity));
        let handed = |spec: &LaunchSpec| last(&spec.env, "GIT_CONFIG_GLOBAL").map(PathBuf::from);
        // Placed, handed as the account's global configuration, granted to read;
        // the trust entries are untouched.
        let (profile, mut spec) = setup("gitid", "opencode", &[]);
        let profile = leak(profile);
        let dir = leak(profile.join("cfg").join("sandbox-git"));
        let dirs = prepare(&mut spec, None, &host(profile, dir, identity)).unwrap();
        let file = handed(&spec).unwrap();
        assert_eq!(file.parent(), Some(dunce::canonicalize(dir).unwrap().as_path()));
        assert!(dirs.files.contains(&file), "{:?}", dirs.files);
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("2"));
        assert_eq!(std::fs::read_to_string(&file).unwrap(), "[user]\n\tname = \"Dev \\\"Q\\\" Eloper\\\\x\"\n\temail = \"dev@example.com\"\n");
        // Git reads each value back as it was.
        let read = |key: &str| {
            let out = std::process::Command::new("git").args(["config", "--file"]).arg(&file).args(["--get", key]).output().unwrap();
            String::from_utf8(out.stdout).unwrap().trim_end().to_string()
        };
        assert_eq!(read("user.name"), identity[0].1);
        assert_eq!(read("user.email"), identity[1].1);
        // The same identity: the same file. Another: a file of its own, the
        // first left as it was (a run holding it reads it on).
        let (other, mut again) = setup("gitid-again", "opencode", &[]);
        prepare(&mut again, None, &host(profile, dir, identity)).unwrap();
        assert_eq!(handed(&again).as_ref(), Some(&file));
        let (other2, mut third) = setup("gitid-third", "opencode", &[]);
        let new_email: &'static [(&'static str, String)] = Box::leak(Box::new([("user.email", "new@example.com".to_string())]));
        prepare(&mut third, None, &host(profile, dir, new_email)).unwrap();
        let second = handed(&third).unwrap();
        assert_ne!(second, file);
        assert_eq!(std::fs::read_to_string(&second).unwrap(), "[user]\n\temail = \"new@example.com\"\n");
        assert_eq!(read("user.email"), identity[1].1);
        assert_eq!(std::fs::read_dir(dir).unwrap().count(), 2, "nothing left beside them");
        // One holding anything but what its name says (a write cut short) is not handed.
        std::fs::write(&second, "").unwrap();
        let (other3, mut cut) = setup("gitid-cut", "opencode", &[]);
        let dirs = prepare(&mut cut, None, &host(profile, dir, new_email)).unwrap();
        assert_eq!(handed(&cut), None);
        assert!(!dirs.files.contains(&second));
        // None: an empty one, still the account's global configuration.
        let (profile2, mut spec) = setup("gitidnone", "opencode", &[]);
        let profile2 = leak(profile2);
        let dirs = prepare(&mut spec, None, &host(profile2, leak(profile2.join("g")), &[])).unwrap();
        let none = handed(&spec).unwrap();
        assert_eq!(std::fs::read_to_string(&none).unwrap(), "");
        assert!(dirs.files.contains(&none));
        // A run naming its own global configuration keeps it.
        let (profile3, mut spec) = setup("gitidown", "opencode", &[("GIT_CONFIG_GLOBAL", "C:/bot.gitconfig")]);
        let profile3 = leak(profile3);
        let own = leak(profile3.join("g"));
        let dirs = prepare(&mut spec, None, &host(profile3, own, identity)).unwrap();
        assert_eq!(last(&spec.env, "GIT_CONFIG_GLOBAL"), Some("C:/bot.gitconfig"));
        assert!(!own.exists() && dirs.files.is_empty());
        // Outside the developer's private folders: not handed, as it would not be granted.
        let outside = leak(scratch("gitid-outside"));
        let (profile4, mut spec) = setup("gitidout", "opencode", &[]);
        let profile4 = leak(profile4);
        let dirs = prepare(&mut spec, None, &host(profile4, outside, identity)).unwrap();
        assert_eq!(last(&spec.env, "GIT_CONFIG_GLOBAL"), None);
        assert!(dirs.files.is_empty(), "{:?}", dirs.files);
        for dir in [profile, profile2, profile3, profile4, outside, other.as_path(), other2.as_path(), other3.as_path()] {
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
        assert_eq!(last(&spec.env, "GIT_CONFIG_COUNT"), Some("3"));
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
        let dirs = prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None }).unwrap();
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
        let dirs = prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: None, program: None, private: &|_| false, git_identity: &[], git_global: None }).unwrap();
        assert_eq!(dirs.files, vec![in_project, home]);
        let _ = std::fs::remove_dir_all(&profile);
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn tools_and_files_are_granted_only_inside_the_developers_private_folders() {
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
        let dirs = prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: Some(&own), program: Some(&program), private: &|_| false, git_identity: &[], git_global: None })
            .unwrap();
        assert_eq!(dirs.tools, vec![own.clone(), bin.clone()]);
        assert_eq!(dirs.files, vec![ca]);
        // Outside the profile: neither.
        let dirs =
            prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: Some(&outside), program: None, private: &|_| false, git_identity: &[], git_global: None }).unwrap();
        assert!(dirs.tools.is_empty());
        // Under a private root (no other account reads it): both, as in the
        // profile.
        let outside_ca = outside.join("ca.pem");
        spec.ca_files = vec![outside_ca.clone()];
        let private = |p: &Path| p.starts_with(&outside);
        let dirs =
            prepare(&mut spec, None, &Host { profile: &profile, appdata: None, node_ca: None, own_dir: Some(&outside), program: None, private: &private, git_identity: &[], git_global: None }).unwrap();
        assert_eq!(dirs.tools, vec![outside.clone()]);
        assert_eq!(dirs.files, vec![dunce::canonicalize(&outside_ca).unwrap()]);
        for dir in [profile, outside] {
            let _ = std::fs::remove_dir_all(dir);
        }
    }

    /// The cross-agent skills store is read by the account when it exists
    /// inside the profile, as it is on disk; absent, or linked out of the
    /// profile, it is not granted.
    #[test]
    fn the_shared_skills_store_is_granted_only_when_it_exists_inside_the_profile() {
        let (profile, mut spec) = setup("skills", "claude", &[]);
        let skills = profile.join(".agents/skills");
        assert!(!run(&mut spec, &profile).tools.contains(&skills), "absent: nothing granted");
        std::fs::create_dir_all(skills.join("writing-guidelines")).unwrap();
        assert!(run(&mut spec, &profile).tools.contains(&skills));
        #[cfg(unix)]
        {
            let outside = scratch("skills-outside");
            std::fs::remove_dir_all(&skills).unwrap();
            std::os::unix::fs::symlink(&outside, &skills).unwrap();
            let dirs = run(&mut spec, &profile);
            assert!(!dirs.tools.iter().any(|d| d == &skills || d == &outside), "{:?}", dirs.tools);
            let _ = std::fs::remove_dir_all(outside);
        }
        let _ = std::fs::remove_dir_all(&profile);
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
