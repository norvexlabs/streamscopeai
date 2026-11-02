//! Per-agent + per-toolchain sandbox profiles — the backend-agnostic knowledge of
//! which paths and env each client needs to run confined. One table feeds both
//! backends (the Landlock allowlist on Linux, the Seatbelt profile on macOS).
//!
//! Paths use a leading `~/` for the home dir (expanded at apply time). The
//! lists are intentionally a curated superset: a path that doesn't exist is
//! skipped, so listing a dir a given client never creates is harmless.

/// A client's extra filesystem needs beyond the shared base + project dir.
pub struct AgentProfile {
    /// Match keys: the client's `launch_command` and/or `client_id`.
    pub names: &'static [&'static str],
    /// Config/cache/state dirs the client reads AND writes (`~/`-relative).
    #[cfg_attr(not(unix), expect(dead_code, reason = "only the Unix sandbox backends read it"))]
    pub state_dirs: &'static [&'static str],
    /// Extra env to set for the child (e.g. keyring/home overrides).
    pub env: &'static [(&'static str, &'static str)],
    /// The client contacts a vendor hub before any LLM call, which the
    /// gateway-only sandbox egress guard blocks — so `ssai run <client>`
    /// under a sandbox can't produce a turn. `run` prints an up-front notice.
    pub hub_dependent: bool,
    /// The client is a front end to a separate server process (its "engine")
    /// that runs the tools. Under a sandbox, `run` starts a private engine
    /// inside the same confinement and points the client at it — see
    /// [`EngineSpec`]. `None` for a client that runs its tools in-process.
    pub engine: Option<&'static EngineSpec>,
    /// Variable naming the directory the client reads as its USER (global)
    /// configuration. For a client provisioned into a project, `run` points it
    /// at the directory holding the provisioned config, so a user-level
    /// setting that outranks the project (OpenCode's global provider policies
    /// and per-agent model pins) cannot send the run to another provider. The
    /// user's own global config is then not read inside `run`. `None` for a
    /// client whose project config already wins.
    pub config_dir_env: Option<&'static str>,
    /// The npm package that installs the client, for the docker tier's agent
    /// layer (`npm install -g <package>` on the project's image). `None`: not
    /// installed by npm, so the project's image must already carry it.
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    pub npm_package: Option<&'static str>,
}

/// How to run an engine-backed client confined: a private engine per run,
/// listening on a loopback port the sandbox picks, and the client attached to
/// it. Data only, so any client with the same shape (a `serve` subcommand, a
/// flag naming the server URL, a password in the environment) reuses the
/// launcher unchanged.
///
/// Why not let the client start its own: such clients share one engine per
/// user on a fixed port and spawn it detached. Inside the sandbox that engine
/// either cannot listen or outlives the run; outside it, an engine the user
/// already runs would execute the agent's tools unconfined.
pub struct EngineSpec {
    /// Arguments that start the engine in the foreground. `{port}` is the
    /// loopback port the sandbox picked.
    pub serve: &'static [&'static str],
    /// Arguments inserted into the client's argv to attach it to that engine,
    /// right after the subcommand path that matched in `attach_paths`.
    /// `{port}` as above.
    pub attach: &'static [&'static str],
    /// Flags that ask the client for a private engine of its own, which the
    /// sandbox's engine already is — removed from the argv so they do not
    /// clash with `attach`.
    pub private_flags: &'static [&'static str],
    /// Subcommand paths whose invocation talks to an engine; `&[]` is the bare
    /// invocation (no subcommand, or a first argument that is none of
    /// `subcommands` — the bare invocation's own positional). Any other
    /// subcommand runs confined without an engine.
    pub attach_paths: &'static [&'static [&'static str]],
    /// Every top-level subcommand the client knows, to tell a subcommand from
    /// the bare invocation's positional argument.
    pub subcommands: &'static [&'static str],
    /// Flags that may precede the subcommand and take a value as the next
    /// argument, so the value is not read as a subcommand.
    pub value_flags: &'static [&'static str],
    /// Variable carrying the engine's password, set for both processes to a
    /// fresh random value per run, so nothing else on the host can drive it.
    pub secret_env: &'static str,
    /// Readiness probe: `GET <path>` with HTTP Basic auth (`basic_user`, the
    /// secret) must answer 200 before the client starts.
    pub ready_path: &'static str,
    pub basic_user: &'static str,
    /// Extra env for both processes: switches off engine egress the guard
    /// would refuse anyway (catalog refresh, self-update) so it fails nothing.
    pub env: &'static [(&'static str, &'static str)],
    /// The oldest major version that has this engine shape; an older client
    /// is refused under a sandbox, because it would not honour `attach`.
    pub min_major: u32,
    /// What to tell the user who has an older one.
    pub upgrade_hint: &'static str,
}

impl EngineSpec {
    /// Where to insert `attach` in the client argv `args`, or `None` when this
    /// invocation runs without an engine — a subcommand outside
    /// `attach_paths`, or an argv that already names its own server.
    pub fn attach_at(&self, args: &[String]) -> Option<usize> {
        let args = &args[..args.iter().position(|a| a == "--").unwrap_or(args.len())];
        let names_its_own_server = |a: &String| {
            let flag = a.split('=').next().unwrap_or(a);
            self.attach.first().is_some_and(|ours| flag == *ours)
        };
        if args.iter().any(names_its_own_server) {
            return None;
        }
        // Global flags may precede the subcommand; one that takes a value
        // consumes the next argument too.
        let mut first = 0;
        while let Some(a) = args.get(first).filter(|a| a.starts_with('-')) {
            first += if !a.contains('=') && self.value_flags.contains(&a.as_str()) { 2 } else { 1 };
        }
        let rest = args.get(first..).unwrap_or_default();
        let bare = rest.first().is_none_or(|a| !self.subcommands.contains(&a.as_str()));
        if bare {
            return self.attach_paths.iter().any(|p| p.is_empty()).then_some(0);
        }
        self.attach_paths
            .iter()
            .filter(|p| !p.is_empty() && p.len() <= rest.len() && p.iter().zip(rest).all(|(w, a)| w == a))
            .map(|p| first + p.len())
            .max()
    }
}

/// OpenCode 2 (`@opencode/cli`): the TUI, `run` and the other session
/// commands are clients of an engine; `--server` attaches to a given one.
pub const OPENCODE_ENGINE: EngineSpec = EngineSpec {
    serve: &["serve", "--hostname", "127.0.0.1", "--port", "{port}"],
    attach: &["--server", "http://127.0.0.1:{port}"],
    private_flags: &["--standalone"],
    attach_paths: &[
        &[],
        &["run"],
        &["mini"],
        &["models"],
        &["stats"],
        &["api"],
        &["reload"],
        &["session", "list"],
        &["session", "delete"],
        &["session", "export"],
        &["session", "import"],
        &["auth", "list"],
        &["auth", "login"],
        &["auth", "logout"],
        &["auth", "export"],
        &["auth", "import"],
        &["auth", "switch"],
    ],
    subcommands: &[
        "upgrade", "update", "uninstall", "acp", "api", "debug", "auth", "mcp", "plugin", "models",
        "stats", "mini", "run", "session", "service", "reload", "pair", "serve", "help",
    ],
    value_flags: &["--log-level", "--completions", "--session", "-s", "--prompt"],
    secret_env: "OPENCODE_PASSWORD",
    ready_path: "/api/info",
    basic_user: "opencode",
    env: &[("OPENCODE_DISABLE_MODELS_FETCH", "1"), ("OPENCODE_DISABLE_AUTOUPDATE", "1")],
    min_major: 2,
    upgrade_hint: "npm install -g @opencode/cli",
};

/// Built-in per-agent profiles. Derived from the clients Streamscope provisions
/// (`seeds/client_profiles/`) and cross-checked against
/// the per-OS profiles. Network is NOT here — every client's single allowed
/// destination is the gateway proxy origin, supplied at runtime.
pub const AGENTS: &[AgentProfile] = &[
    AgentProfile {
        names: &["claude", "claude-code"],
        state_dirs: &[
            "~/.claude",
            "~/.claude.json",
            "~/.claude.json.lock",
            "~/.config/claude",
            "~/.cache/claude",
            "~/.local/share/claude",
            "~/.local/state/claude",
            "~/.mcp.json",
        ],
        env: &[],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: Some("@anthropic-ai/claude-code"),
    },
    AgentProfile {
        names: &["codex"],
        state_dirs: &["~/.codex", "~/.cache/codex"],
        env: &[],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: Some("@openai/codex"),
    },
    AgentProfile {
        names: &["gemini", "gemini-cli"],
        state_dirs: &["~/.gemini", "~/.cache/gemini"],
        env: &[],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: Some("@google/gemini-cli"),
    },
    AgentProfile {
        names: &["qwen", "qwen-code"],
        state_dirs: &["~/.qwen", "~/.cache/qwen"],
        env: &[("QWEN_CODE_SUPPRESS_YOLO_WARNING", "1")],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: Some("@qwen-code/qwen-code"),
    },
    AgentProfile {
        names: &["opencode"],
        state_dirs: &[
            "~/.opencode",
            "~/.opencode.json",
            "~/.config/opencode",
            "~/.cache/opencode",
            "~/.local/share/opencode",
            "~/.local/share/opentui",
            "~/.local/state/opencode",
        ],
        env: &[],
        hub_dependent: false,
        engine: Some(&OPENCODE_ENGINE),
        config_dir_env: Some("OPENCODE_CONFIG_DIR"),
        npm_package: Some("@opencode/cli"),
    },
    AgentProfile {
        names: &["goose"],
        // Goose reads secrets from a file (not the OS keyring) only when this is
        // set — and the file lives under ~/.config/goose, allowed below.
        state_dirs: &[
            "~/.goose",
            "~/.config/goose",
            "~/.cache/goose",
            "~/.local/share/goose",
            "~/.local/state/goose",
        ],
        env: &[("GOOSE_DISABLE_KEYRING", "true")],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: None,
    },
    AgentProfile {
        names: &["aider"],
        state_dirs: &["~/.aider", "~/.aider.conf.yml", "~/.config/aider", "~/.cache/aider"],
        env: &[],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: None,
    },
    AgentProfile {
        // The Continue CLI (`cn`) bootstraps against its hub (api.continue.dev)
        // before any LLM call; the gateway-only egress guard blocks that.
        names: &["cn", "continue"],
        state_dirs: &["~/.continue", "~/.config/continue", "~/.cache/continue"],
        env: &[],
        hub_dependent: true,
        engine: None,
        config_dir_env: None,
        npm_package: Some("@continuedev/cli"),
    },
    AgentProfile {
        names: &["crush"],
        state_dirs: &["~/.config/crush", "~/.cache/crush", "~/.local/share/crush"],
        env: &[],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: Some("@charmland/crush"),
    },
    AgentProfile {
        names: &["vibe"],
        state_dirs: &["~/.vibe", "~/.config/vibe", "~/.cache/vibe"],
        env: &[],
        hub_dependent: false,
        engine: None,
        config_dir_env: None,
        npm_package: None,
    },
];

/// A language toolchain's dirs, applied on top of the agent profile when the
/// agent's runtime is detected (by the launch command and/or PATH probing).
/// Consumed by the Linux native-sandbox path (Landlock-only); the macOS Seatbelt
/// profile already grants `~/` read via the broader `file-read*` allow and
/// re-denies SECRET_DENY on top, so the per-toolchain dir list isn't needed
/// there.
#[cfg(target_os = "linux")]
pub struct ToolchainProfile {
    pub names: &'static [&'static str],
    pub dirs: &'static [&'static str],
}

#[cfg(target_os = "linux")]
pub const TOOLCHAINS: &[ToolchainProfile] = &[
    ToolchainProfile {
        names: &["node", "npm", "npx", "yarn", "pnpm", "bun", "deno"],
        // A version manager is granted per installed version, `bin`, `lib`
        // and `share` — what `npm i -g` writes (`lib/node_modules`, the `bin`
        // links, a package's man pages under `share/man`). npm keeps its GLOBAL
        // config in `<version>/etc/npmrc`, which can carry a registry token, so
        // neither the version root nor the manager's tree is granted whole;
        // `~/.npmrc` is left to `SECRET_DENY`. Volta is the exception, granted
        // whole: its shims resolve through its entire tree.
        dirs: &[
            "~/.nvm/versions/node/*/bin",
            "~/.nvm/versions/node/*/lib",
            "~/.nvm/versions/node/*/share",
            "~/.fnm/node-versions/*/installation/bin",
            "~/.fnm/node-versions/*/installation/lib",
            "~/.fnm/node-versions/*/installation/share",
            "~/.local/share/fnm/node-versions/*/installation/bin",
            "~/.local/share/fnm/node-versions/*/installation/lib",
            "~/.local/share/fnm/node-versions/*/installation/share",
            "~/.npm",
            "~/.config/npm",
            "~/.cache/npm",
            "~/.cache/node",
            "~/.node-gyp",
            "~/.cache/node-gyp",
            "~/.pnpm-store",
            "~/.config/pnpm",
            "~/.local/share/pnpm",
            "~/.local/state/pnpm",
            "~/.yarn",
            "~/.config/yarn",
            "~/.cache/yarn",
            "~/.cache/turbo",
            "~/.cache/prisma",
            "~/.volta",
            "~/.bun",
            "~/.deno",
            "~/.cache/deno",
        ],
    },
    ToolchainProfile {
        names: &["python", "python3", "pip", "pip3", "uv", "uvx", "pipx"],
        dirs: &[
            "~/.cache/pip",
            "~/.config/pip",
            "~/.cache/uv",
            "~/.config/uv",
            "~/.local/share/uv",
            "~/.local/state/uv",
            "~/.local/pipx",
            "~/.pyenv",
            "~/.virtualenvs",
            "~/.cache/pre-commit",
            "~/.cache/mypy",
            "~/.cache/ruff",
        ],
    },
];

/// Shared read-only allowlist beyond the runtime base — git + SCM CLI config a
/// coding agent commonly needs (NOT credentials; secrets are denied below).
/// Read by the Linux backend when it builds the Landlock ruleset; the macOS
/// Seatbelt profile is generated from its own clauses.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub const BASE_READ: &[&str] = &[
    "~/.gitconfig",
    "~/.config/git",
    "~/.ssh/config",
    "~/.ssh/known_hosts",
    "~/.config/gh/config.yml", // not the directory: its `hosts.yml` holds the OAuth token
    "~/CLAUDE.md",
    "~/AGENTS.md",
    // The cross-agent skills store: clients link their own skills dir into it
    // (`~/.gemini/skills/<name>` → `~/.agents/skills/<name>`), and Landlock
    // checks the link's target.
    "~/.agents/skills",
];

/// User-installed tool directories every confined client may READ and EXECUTE
/// from, on Linux. A coding agent drives the user's own toolchain — `uv`,
/// `cargo`, a version manager's `node` — and a tool on the PATH under `$HOME` is
/// otherwise refused at `execve` (Bun reports it as `posix_spawn '<tool>'
/// failed`, `EACCES`), even though the same command runs unconfined. The same
/// set the greywall sandbox grants, narrowed where a tree also holds a secret.
/// `bin` directories alone where nothing else is needed beside the binary (so
/// `~/.cargo`'s registry credentials stay out); the whole tree for `~/.rustup`,
/// pyenv, pipx, rbenv and RVM, whose runtimes load their own libraries from it.
/// A Node version manager is granted `bin` + `lib` only — per installed version
/// (`*`, expanded when the policy is built) for nvm and fnm, the active prefix
/// for n: npm keeps its GLOBAL config in `<prefix>/etc/npmrc`, which can carry
/// a registry token — the reason
/// `~/.npmrc` is in `SECRET_DENY`. Volta is not listed: its shims resolve
/// through its whole tree, npm config included. Never writable, and filtered
/// against `SECRET_DENY` like every other grant. macOS needs no list:
/// its Seatbelt profile already allows reads and exec everywhere outside the
/// denied secrets.
#[cfg(target_os = "linux")]
pub const USER_TOOL_READ: &[&str] = &[
    "~/.local/bin",
    "~/bin",
    "~/.cargo/bin",
    "~/.rustup",
    "~/go/bin",
    "~/.go",
    "~/.bun/bin",
    "~/.deno/bin",
    "~/.nvm/versions/node/*/bin",
    "~/.nvm/versions/node/*/lib",
    "~/.fnm/node-versions/*/installation/bin",
    "~/.fnm/node-versions/*/installation/lib",
    "~/.local/share/fnm/node-versions/*/installation/bin",
    "~/.local/share/fnm/node-versions/*/installation/lib",
    "~/.n/bin",
    "~/.n/lib",
    "~/.pyenv",
    "~/.local/pipx",
    "~/.rbenv",
    "~/.rvm",
    "/nix",
    "/snap",
];

/// Secrets denied even when a broader allow would expose them. Glob-ish: an
/// entry ending in a non-slash is treated as a path prefix at apply time, and
/// a `*` matches a single directory level — npm keeps the GLOBAL config of a
/// version-managed Node under that version's own directory, so the entry has
/// to name every installed version at once.
#[cfg_attr(all(not(unix), not(test)), expect(dead_code, reason = "only the Unix sandbox backends read it"))]
pub const SECRET_DENY: &[&str] = &[
    "~/.ssh/id_",   // private keys (id_rsa, id_ed25519, …) — prefix match
    "~/.gnupg",
    "~/.aws",
    "~/.config/gcloud",
    "~/.netrc",
    "~/.npmrc",     // may carry a registry token; the agent doesn't need it to read deps
    "~/.config/npm/npmrc", // the same file where npm is pointed at XDG (`NPM_CONFIG_USERCONFIG`)
    "~/.yarnrc",    // prefix: `.yarnrc` and `.yarnrc.yml`, whose `npmAuthToken` is a registry token
    "~/.config/pnpm/rc", // pnpm's global config, where `pnpm config set --global` stores a registry token
    "~/.config/configstore", // CLI state store (firebase-tools keeps its refresh token here)
    "~/.config/gh/hosts.yml", // the GitHub CLI's OAuth token; egress is gateway-only, so gh can't use it
    // `npm config set --location=global` writes `<node prefix>/etc/npmrc`, which
    // is per installed version under a version manager, and `~/.n/etc/npmrc` for
    // `n` (whose prefix is its root). Linux grants a managed version only its
    // `bin`/`lib`/`share`, so these are its second line; on macOS they are the
    // only one.
    "~/.nvm/versions/node/*/etc/npmrc",
    "~/.fnm/node-versions/*/installation/etc/npmrc",
    "~/.local/share/fnm/node-versions/*/installation/etc/npmrc",
    "~/Library/Application Support/fnm/node-versions/*/installation/etc/npmrc",
    "~/.n/etc/npmrc",
];

/// Secrets denied on macOS only, where Seatbelt's last-match-wins ordering can
/// carve a hole inside an allowed tree.
///
/// Landlock cannot: a grant is allow-only, so an entry here would instead make
/// [`granted_dirs`](super::linux) drop the whole tree that contains it — and
/// each of these sits inside one a tool needs whole. Volta resolves its shims
/// through its entire directory, and a Homebrew prefix holds the `node` binary
/// itself. On Linux the npm config inside those trees stays readable, which is
/// documented in the admin guide.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub const SEATBELT_ONLY_DENY: &[&str] = &[
    "~/.volta/tools/image/node/*/etc/npmrc",
    "/opt/homebrew/etc/npmrc",
    "/usr/local/etc/npmrc",
];

/// A deny entry as a POSIX-regex **prefix** pattern for Seatbelt's
/// `(regex #"^…")` clause: every literal character that means something to the
/// regex engine is escaped, and each `*` component matches exactly one path
/// segment (`[^/]+`).
///
/// A `*` cannot be expanded against the filesystem here the way Linux expands
/// a grant — the profile is built once and a version installed afterwards must
/// be covered too — so the wildcard has to survive into the pattern.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub fn seatbelt_deny_regex(path: &str) -> String {
    let mut out = String::with_capacity(path.len() + 8);
    for (i, segment) in path.split('*').enumerate() {
        if i > 0 {
            out.push_str("[^/]+");
        }
        for c in segment.chars() {
            if matches!(
                c,
                '.' | '[' | ']' | '^' | '$' | '*' | '+' | '?' | '{' | '}' | '|' | '(' | ')' | '\\' | '"'
            ) {
                out.push('\\');
            }
            out.push(c);
        }
    }
    out
}

/// Look up the agent profile for a launch command or client id.
pub fn agent_for(name: &str) -> Option<&'static AgentProfile> {
    AGENTS.iter().find(|p| p.names.contains(&name))
}

/// Toolchain profile for a runtime command name.
#[cfg(target_os = "linux")]
pub fn toolchain_for(name: &str) -> Option<&'static ToolchainProfile> {
    TOOLCHAINS.iter().find(|p| p.names.contains(&name))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(a: &[&str]) -> Vec<String> {
        a.iter().map(|s| s.to_string()).collect()
    }

    /// Every AgentProfile has the `engine` field set explicitly; this lists the
    /// ones that use it, so a new engine-backed client is a visible decision.
    #[test]
    fn only_opencode_is_engine_backed() {
        let engined: Vec<_> = AGENTS.iter().filter(|a| a.engine.is_some()).map(|a| a.names[0]).collect();
        assert_eq!(engined, ["opencode"]);
    }

    /// The bare invocation attaches at the front — with no argument, with a
    /// leading flag, and with its positional (a directory) — and each session
    /// subcommand attaches after its own path.
    #[test]
    fn opencode_attaches_after_the_subcommand_path_that_talks_to_the_engine() {
        let e = &OPENCODE_ENGINE;
        assert_eq!(e.attach_at(&argv(&[])), Some(0));
        assert_eq!(e.attach_at(&argv(&["--continue"])), Some(0));
        assert_eq!(e.attach_at(&argv(&["./src"])), Some(0));
        assert_eq!(e.attach_at(&argv(&["run", "hello", "--model", "p/m"])), Some(1));
        assert_eq!(e.attach_at(&argv(&["session", "list"])), Some(2));
        assert_eq!(e.attach_at(&argv(&["auth", "login", "x"])), Some(2));
        // Global flags before the subcommand, with and without a value.
        assert_eq!(e.attach_at(&argv(&["--print-logs", "run", "hi"])), Some(2));
        assert_eq!(e.attach_at(&argv(&["--log-level", "debug", "run", "hi"])), Some(3));
        assert_eq!(e.attach_at(&argv(&["--log-level=debug", "session", "list"])), Some(3));
        // A value that happens to be a subcommand name is still a value.
        assert_eq!(e.attach_at(&argv(&["--prompt", "run"])), Some(0));
    }

    /// A subcommand that does not talk to an engine runs without one, and so
    /// does an argv that already chose its own server — never two `--server`s.
    #[test]
    fn opencode_runs_without_an_engine_where_none_is_used() {
        let e = &OPENCODE_ENGINE;
        for args in [
            &["mcp", "list"][..],
            &["upgrade"],
            &["serve", "--port", "1"],
            &["session"],
            &["auth"],
            &["run", "--server", "http://elsewhere"],
            &["run", "--server=http://elsewhere"],
            &["--print-logs", "mcp", "list"],
            &["--log-level", "debug", "upgrade"],
        ] {
            assert_eq!(e.attach_at(&argv(args)), None, "{args:?}");
        }
    }

    /// The pattern is a prefix regex whose `*` stops at the path separator, so
    /// one entry names every installed version and nothing below it. Seatbelt
    /// parses this string itself — `sandbox_native_macos.sh` drives the
    /// real `sandbox-exec` with it.
    #[test]
    fn a_wildcard_deny_entry_matches_one_directory_level() {
        assert_eq!(
            seatbelt_deny_regex("/Users/x/.nvm/versions/node/*/etc/npmrc"),
            "/Users/x/\\.nvm/versions/node/[^/]+/etc/npmrc"
        );
    }

    /// Every other character is matched as itself: a `.` in a dotfile name is
    /// not a one-character wildcard, and a filename prefix (`~/.ssh/id_`) stays
    /// a prefix.
    #[test]
    fn a_plain_deny_entry_is_escaped_and_keeps_its_prefix_meaning() {
        assert_eq!(seatbelt_deny_regex("/Users/x/.ssh/id_"), "/Users/x/\\.ssh/id_");
    }

    /// The pattern is embedded in an SBPL string literal, so a quote or
    /// backslash in a path must not close it early.
    #[test]
    fn a_quote_in_a_path_cannot_close_the_pattern() {
        assert_eq!(seatbelt_deny_regex("/tmp/a\"b\\c"), "/tmp/a\\\"b\\\\c");
    }

    /// Both lists are applied to the Seatbelt profile; the Linux grant filter
    /// reads only the first. An entry that would refuse a whole toolchain grant
    /// therefore belongs in the macOS-only list — `~/.volta` is granted whole.
    #[test]
    fn a_seatbelt_only_entry_stays_out_of_the_shared_list() {
        assert!(SECRET_DENY.iter().all(|s| !s.starts_with("~/.volta")));
        assert!(SEATBELT_ONLY_DENY.iter().any(|s| s.starts_with("~/.volta")));
    }
}
