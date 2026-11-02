//! Rhai scripting engine for transform programs.
//!
//! Transform programs are Rhai scripts that operate on a `RequestContext` — a normalized,
//! text-only projection of `ApiRequest`. Scripts run in a sandboxed Rhai engine with
//! execution limits and helper functions.
//!
//! Scripts are grouped by scope and run in fixed order:
//! **global → system_prompt → messages → tools**
//! Within each scope, scripts run by priority (lower number = first).

pub mod cache;
pub mod context;
pub mod engine;
pub mod regex_cache;
pub mod response_context;

use std::sync::Arc;

use self::cache::AstCache;
use self::context::RequestContext;
use self::response_context::{ResponseBlockContext, scope_matches_block_type};
use crate::audit::Phase;
use crate::error::AppError;
use crate::proxy::content::{TransformProgramOutcome, TransformProgramRef, TransformStepDiff};

/// Execution order for request-phase scopes.
const SCOPE_ORDER: &[&str] = &["global", "system_prompt", "messages", "tools"];

/// Execution order for response-phase scopes.
const RESPONSE_SCOPE_ORDER: &[&str] = &["global", "text", "tool", "thinking"];

/// Bytes of surrounding context (each side) handed to a span-mode script as
/// `before`/`after`. Bounded so a large field isn't copied wholesale per match.
const SPAN_CONTEXT_WINDOW: usize = 200;

/// How the transform engine should react when a Rhai script errors.
///
/// **Open** (default): the failed script is logged and skipped; the remaining
/// scripts still run and the request/response proceeds with the unmodified
/// content for that script. This is the historical behavior and is appropriate
/// for non-critical enrichment scripts.
///
/// **Closed**: the failing script short-circuits the entire chain with an
/// `AppError::Internal`. The request phase surfaces this as HTTP 500 to the
/// client; the response phase suppresses the affected block and replaces it
/// with an operator notice (`[Response block suppressed: ...]`) plus a
/// `script_error` audit badge. Use this when scripts enforce security
/// or compliance invariants that must not be bypassed by a script bug.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ScriptFailMode {
    #[default]
    Open,
    Closed,
}

impl ScriptFailMode {
    /// Parse from a config string. Unknown values fall back to `Open`.
    pub fn parse(s: &str) -> Self {
        match s.trim().to_ascii_lowercase().as_str() {
            "closed" | "fail_closed" | "fail-closed" => Self::Closed,
            _ => Self::Open,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Open => "open",
            Self::Closed => "closed",
        }
    }
}

/// Generate a unified-diff-style text showing what a response script changed.
fn generate_response_diff(
    before: &response_context::ResponseBlockContext,
    after: &response_context::ResponseBlockContext,
) -> String {
    let mut lines = Vec::new();

    if before.content != after.content {
        lines.push(format!("@@ {}.content @@", before.block_type));
        for l in before.content.lines().take(10) {
            lines.push(format!("-{l}"));
        }
        if before.content.lines().count() > 10 {
            lines.push(format!("-... ({} more lines)", before.content.lines().count() - 10));
        }
        for l in after.content.lines().take(10) {
            lines.push(format!("+{l}"));
        }
        if after.content.lines().count() > 10 {
            lines.push(format!("+... ({} more lines)", after.content.lines().count() - 10));
        }
    }

    if before.tool_name != after.tool_name {
        lines.push("@@ tool_name @@".to_string());
        lines.push(format!("-{}", before.tool_name.as_deref().unwrap_or("(none)")));
        lines.push(format!("+{}", after.tool_name.as_deref().unwrap_or("(none)")));
    }

    if before.arguments != after.arguments {
        lines.push("@@ arguments @@".to_string());
        lines.push(format!("-{}", before.arguments.as_deref().unwrap_or("(none)")));
        lines.push(format!("+{}", after.arguments.as_deref().unwrap_or("(none)")));
    }

    lines.join("\n")
}

/// A `tool_use` block's arguments must decode to a JSON **object** — the shape
/// every one of the four wire protocols requires (Chat Completions
/// `function.arguments` JSON string, Anthropic `tool_use.input`, Gemini
/// `functionCall.args`, Responses `function_call.arguments` JSON string). A
/// `tool`-scope response script writes `ctx.arguments` as a free-form string;
/// a scalar, array, or syntactically broken value would otherwise be silently
/// dropped on the object-field protocols or spliced onto the wire malformed.
fn tool_arguments_decode_to_object(arguments: &str) -> bool {
    serde_json::from_str::<serde_json::Value>(arguments)
        .map(|v| v.is_object())
        .unwrap_or(false)
}

/// A transform program — a compiled Rhai script with metadata.
#[derive(Debug, Clone)]
pub struct TransformProgram {
    pub id: String,
    pub name: String,
    pub source: String,
    pub phase: String,
    pub scope: String,
    pub priority: i32,
    pub enabled: bool,
    pub version_hash: String,
    pub model_filter: Option<String>,
    pub app_filter: Option<String>,
    /// Optional fast-find trigger. When `Some` and non-blank, the program runs
    /// only if the in-scope content matches this regex — a cheap native pre-find
    /// gating the Rhai script. `None`/blank ⇒ always run for matching context.
    pub trigger_regex: Option<String>,
    /// Execution mode. `None`/`"full"` runs the script once over the whole
    /// in-scope content (the default). `"span"` runs the script once per match of
    /// `trigger_regex` on just the matched span + context, splicing each returned
    /// replacement back — `trigger_regex` is the span finder and is required.
    pub match_mode: Option<String>,
    /// Profile scope. `None` → **shared**: the program applies to every transform
    /// profile's effective set (the baseline; builtins live here). `Some(P)` →
    /// **specific** to profile P. The snapshot bucketer fans shared programs into
    /// every reachable profile's bucket; a workspace assigned transform=Off gets
    /// no programs at all (not even the baseline).
    pub profile_id: Option<uuid::Uuid>,
}

impl TransformProgram {
    /// Check if a comma-separated filter matches a value.
    ///
    /// Filter syntax — each comma-separated token is either positive (no prefix)
    /// or negative (`!` prefix). Whitespace around tokens and around the `!` is
    /// trimmed. Semantics:
    /// - `None` or `Some("")` → match all
    /// - any negative matches → no match (deny wins)
    /// - any positive present + none matches → no match (allowlist unsatisfied)
    /// - `value = None`: matches only if the filter is purely-negative (no
    ///   positives to satisfy); if positives are present an unknown value
    ///   can't be confirmed in the allowlist, so no match
    fn matches_filter(filter: &Option<String>, value: Option<&str>) -> bool {
        let f = match filter {
            None => return true,
            Some(s) if s.trim().is_empty() => return true,
            Some(s) => s,
        };
        let mut positives = 0usize;
        let mut positive_hit = false;
        for raw in f.split(',') {
            let token = raw.trim();
            if let Some(neg) = token.strip_prefix('!') {
                let neg = neg.trim();
                if neg.is_empty() {
                    continue;
                }
                if value.is_some_and(|v| v == neg) {
                    return false;
                }
            } else {
                if token.is_empty() {
                    continue;
                }
                positives += 1;
                if value.is_some_and(|v| v == token) {
                    positive_hit = true;
                }
            }
        }
        positives == 0 || positive_hit
    }

    /// Does this program apply to the given model alias?
    /// Pass `None` if the request has no resolved model yet.
    pub fn applies_to_model(&self, alias: Option<&str>) -> bool {
        Self::matches_filter(&self.model_filter, alias)
    }

    /// Does this program apply to the given app_id?
    /// Pass `None` if the request has no app_id stamped.
    pub fn applies_to_app(&self, app_id: Option<&str>) -> bool {
        Self::matches_filter(&self.app_filter, app_id)
    }

    /// Does [`ScriptEngine::execute_chain`] run this program on a request for
    /// `model_alias` from `app_id`? Its `trigger_regex`, which reads the
    /// request's content, is checked in the chain.
    pub fn runs_on_request(&self, model_alias: Option<&str>, app_id: Option<&str>) -> bool {
        self.enabled
            && self.phase == "request"
            && SCOPE_ORDER.contains(&self.scope.as_str())
            && self.applies_to_model(model_alias)
            && self.applies_to_app(app_id)
    }

    /// Does this request program read the conversation's messages? Only the
    /// `global` and `messages` scopes see them (`project_for_scope`,
    /// `scope_searchable_text`, `apply_text_transform`).
    pub fn reads_conversation(&self) -> bool {
        matches!(self.scope.as_str(), "global" | "messages")
    }

    /// Does this program have a non-empty app filter?
    pub fn has_app_filter(&self) -> bool {
        self.app_filter.as_ref().is_some_and(|f| !f.trim().is_empty())
    }

    /// Does this program have a non-empty model filter?
    pub fn has_model_filter(&self) -> bool {
        self.model_filter.as_ref().is_some_and(|f| !f.trim().is_empty())
    }

    /// Does this program declare a non-blank `trigger_regex`? When false the
    /// fast-find gate is skipped entirely (no searchable-text allocation).
    pub fn has_trigger(&self) -> bool {
        self.trigger_regex.as_ref().is_some_and(|p| !p.trim().is_empty())
    }

    /// Does this program run in per-match span mode? In span mode the engine
    /// splits the in-scope text by `trigger_regex` and runs the script once per
    /// match on the matched span (`has_trigger()` is an invariant — enforced at
    /// the admin layer). `None`/`"full"`/anything else ⇒ full-context mode.
    pub fn is_span(&self) -> bool {
        self.match_mode.as_deref() == Some("span")
    }

    /// Does this program's `trigger_regex` match the given in-scope text? A
    /// `None`/blank trigger always matches (the program is not gated). A trigger
    /// that fails to compile is treated as never-matching (the script is skipped)
    /// via the shared regex cache's never-match fallback. Only call when
    /// `has_trigger()` is true to avoid computing the searchable text needlessly.
    pub fn trigger_matches(&self, in_scope_text: &str) -> bool {
        match self.trigger_regex.as_deref() {
            None => true,
            Some(p) if p.trim().is_empty() => true,
            Some(p) => regex_cache::get(p).is_match(in_scope_text),
        }
    }
}

/// The script execution engine — holds a Rhai engine and AST cache.
pub struct ScriptEngine {
    engine: rhai::Engine,
    ast_cache: AstCache,
}

impl Default for ScriptEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl ScriptEngine {
    pub fn new() -> Self {
        Self {
            engine: engine::create_engine(),
            ast_cache: AstCache::new(),
        }
    }

    /// Compile a script source to AST without executing. Returns error description on failure.
    pub fn validate(&self, source: &str) -> Result<(), String> {
        self.engine
            .compile(source)
            .map(|_| ())
            .map_err(|e| e.to_string())
    }

    /// Compile and execute a script on a sample context. Returns the modified context.
    pub fn test_execute(
        &self,
        source: &str,
        ctx: RequestContext,
    ) -> Result<RequestContext, String> {
        let ast = self.engine.compile(source).map_err(|e| e.to_string())?;
        let ctx_dynamic = ctx.to_dynamic();

        let mut scope = rhai::Scope::new();
        let result: rhai::Dynamic = self
            .engine
            .call_fn(&mut scope, &ast, "transform", (ctx_dynamic,))
            .map_err(|e| e.to_string())?;

        RequestContext::from_dynamic(&result)
            .ok_or_else(|| "failed to parse script output as RequestContext".to_string())
    }

    /// Span-mode preview for the admin test panel: compile `source`, then run the
    /// per-match splice over every writable text field of the sample context
    /// (`global` scope), exactly as the runtime would. `trigger_regex` is the span
    /// finder. Returns the rewritten context.
    pub fn test_execute_span(
        &self,
        source: &str,
        trigger_regex: &str,
        mut ctx: RequestContext,
    ) -> Result<RequestContext, String> {
        let ast = self.engine.compile(source).map_err(|e| e.to_string())?;
        let re = regex_cache::get(trigger_regex);
        ctx.apply_text_transform("global", |t| self.splice_spans(&ast, &re, t))?;
        Ok(ctx)
    }

    /// Execute a chain of transform programs on a RequestContext.
    ///
    /// Programs are grouped by scope and run in fixed order:
    /// global → system_prompt → messages → tools.
    /// Within each scope, programs run by priority (lower = first).
    /// Disabled programs are skipped. Failed scripts log a warning and are skipped (fail-open).
    ///
    /// Each scope receives a **projected** context with only its writable fields.
    /// After execution, only writable fields are merged back (enforced scope isolation).
    ///
    /// Returns the modified context plus per-program structured outcomes
    /// (`Vec<TransformProgramRef>`), per-step diffs, and structured injection blocks.
    /// Per-program user-facing badges are emitted by the caller from these outcomes.
    #[allow(clippy::type_complexity)]
    pub fn execute_chain(
        &self,
        programs: &[TransformProgram],
        mut ctx: RequestContext,
        capture_diffs: bool,
        model_alias: Option<&str>,
        fail_mode: ScriptFailMode,
    ) -> Result<(RequestContext, Vec<TransformProgramRef>, Vec<TransformStepDiff>, Vec<crate::proxy::content::InjectionBlock>), AppError> {
        let mut program_outcomes: Vec<TransformProgramRef> = Vec::new();
        let mut step_diffs = Vec::new();
        let mut injection_blocks = Vec::new();

        for &scope_name in SCOPE_ORDER {
            // Collect request-phase programs for this scope, sorted by priority
            let mut scope_programs: Vec<&TransformProgram> = programs
                .iter()
                // A program whose filter excludes this request is skipped
                // (deny-first semantics — see `TransformProgram::matches_filter`).
                .filter(|p| p.scope == scope_name && p.runs_on_request(model_alias, ctx.app_id.as_deref()))
                .collect();
            scope_programs.sort_by_key(|p| p.priority);

            for program in scope_programs {
                // Fast-find trigger: skip the script unless its `trigger_regex`
                // (if any) matches this scope's content. A skipped script records
                // no outcome, exactly like a filter miss. The searchable text is
                // computed only when a trigger is present.
                if program.has_trigger()
                    && !program.trigger_matches(&ctx.scope_searchable_text(scope_name)) {
                    continue;
                }

                // Snapshot before execution (for change detection + optional diff)
                let before = ctx.snapshot();

                // Execute. Span mode rewrites each writable text field of the
                // scope in place (once per `trigger_regex` match); full mode runs
                // the script once over the projected scope and merges back.
                let exec: Result<(), String> = if program.is_span() {
                    ctx.apply_text_transform(scope_name, |t| self.execute_span_text(program, t))
                        .map(|_| ())
                } else {
                    let projected = ctx.project_for_scope(scope_name);
                    self.execute_single_dynamic(program, projected)
                        .map(|result| ctx.merge_from_scope(scope_name, &result))
                };

                match exec {
                    Ok(()) => {
                        // Drain labels added by this script (no longer
                        // surfaced in audit; kept clear for next program).
                        ctx.labels.clear();

                        // Auto-detect modification → record outcome
                        let after = ctx.snapshot();
                        let modified = before != after;
                        program_outcomes.push(TransformProgramRef {
                            name: program.name.clone(),
                            phase: Phase::Request,
                            outcome: if modified {
                                TransformProgramOutcome::Modified
                            } else {
                                TransformProgramOutcome::Passed
                            },
                        });
                        if modified {
                            // Capture unified diff if enabled
                            if capture_diffs
                                && let Some(diff_text) = before.diff(&after) {
                                    step_diffs.push(TransformStepDiff {
                                        name: program.name.clone(),
                                        diff: diff_text,
                                    });
                                }

                            // Capture structured injection blocks
                            if before.system_prompt != after.system_prompt {
                                let action_content = match (&before.system_prompt, &after.system_prompt) {
                                    (None, Some(new)) => Some(("create", new.clone())),
                                    (Some(old), Some(new)) if new.starts_with(old.as_str()) => {
                                        Some(("append", new[old.len()..].to_string()))
                                    }
                                    (Some(old), Some(new)) if new.ends_with(old.as_str()) => {
                                        Some(("prepend", new[..new.len() - old.len()].to_string()))
                                    }
                                    (Some(_), Some(new)) => Some(("replace", new.clone())),
                                    (Some(_), None) => Some(("remove", String::new())),
                                    _ => None,
                                };
                                if let Some((action, content)) = action_content {
                                    injection_blocks.push(crate::proxy::content::InjectionBlock {
                                        transform: program.name.clone(),
                                        scope: scope_name.to_string(),
                                        field: "system_prompt".to_string(),
                                        action: action.to_string(),
                                        content,
                                    });
                                }
                            }
                            if before.messages != after.messages {
                                injection_blocks.push(crate::proxy::content::InjectionBlock {
                                    transform: program.name.clone(),
                                    scope: scope_name.to_string(),
                                    field: "messages".to_string(),
                                    action: if after.messages.len() != before.messages.len() { "resize" } else { "modify" }.to_string(),
                                    content: format!("{} → {} messages", before.messages.len(), after.messages.len()),
                                });
                            }
                            if before.tools != after.tools {
                                // Snapshot tools are `(name, description, parameters_json)` —
                                // bag-diff by name only so a description-only mutation
                                // doesn't read as both a removal AND an add of the
                                // same tool.
                                let before_names: std::collections::HashSet<&str> =
                                    before.tools.iter().map(|(n, _, _)| n.as_str()).collect();
                                let after_names: std::collections::HashSet<&str> =
                                    after.tools.iter().map(|(n, _, _)| n.as_str()).collect();
                                let removed: Vec<String> = before
                                    .tools
                                    .iter()
                                    .filter(|(n, _, _)| !after_names.contains(n.as_str()))
                                    .map(|(n, _, _)| n.clone())
                                    .collect();
                                let added: Vec<String> = after
                                    .tools
                                    .iter()
                                    .filter(|(n, _, _)| !before_names.contains(n.as_str()))
                                    .map(|(n, _, _)| n.clone())
                                    .collect();
                                if !removed.is_empty() {
                                    injection_blocks.push(crate::proxy::content::InjectionBlock {
                                        transform: program.name.clone(),
                                        scope: scope_name.to_string(),
                                        field: "tools".to_string(),
                                        action: "remove".to_string(),
                                        content: removed.join(", "),
                                    });
                                }
                                if !added.is_empty() {
                                    injection_blocks.push(crate::proxy::content::InjectionBlock {
                                        transform: program.name.clone(),
                                        scope: scope_name.to_string(),
                                        field: "tools".to_string(),
                                        action: "add".to_string(),
                                        content: added.join(", "),
                                    });
                                }
                            }
                        }
                    }
                    Err(e) => {
                        match fail_mode {
                            ScriptFailMode::Open => {
                                tracing::warn!(
                                    program_id = %program.id,
                                    program_name = %program.name,
                                    error = %e,
                                    "transform script failed, skipping (fail-open)"
                                );
                                program_outcomes.push(TransformProgramRef {
                                    name: program.name.clone(),
                                    phase: Phase::Request,
                                    outcome: TransformProgramOutcome::Errored,
                                });
                            }
                            ScriptFailMode::Closed => {
                                tracing::error!(
                                    program_id = %program.id,
                                    program_name = %program.name,
                                    error = %e,
                                    "transform script failed, aborting request (fail-closed)"
                                );
                                return Err(AppError::Internal(format!(
                                    "rhai request script `{}` failed in fail-closed mode: {e}",
                                    program.name
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok((ctx, program_outcomes, step_diffs, injection_blocks))
    }

    /// Execute a chain of response-phase transform programs on a ResponseBlockContext.
    ///
    /// Programs are grouped by scope and run in fixed order:
    /// global → text → tool → thinking.
    /// Programs whose scope doesn't match the block type are skipped.
    /// Within each scope, programs run by priority (lower = first).
    ///
    /// Returns (modified context, per-program outcomes, step diffs).
    /// Per-program user-facing badges are emitted by the caller from the outcomes.
    #[allow(clippy::type_complexity)]
    pub fn execute_response_chain(
        &self,
        programs: &[TransformProgram],
        mut ctx: ResponseBlockContext,
        model_alias: Option<&str>,
        capture_diffs: bool,
        fail_mode: ScriptFailMode,
    ) -> Result<(ResponseBlockContext, Vec<TransformProgramRef>, Vec<TransformStepDiff>), AppError>
    {
        let mut program_outcomes: Vec<TransformProgramRef> = Vec::new();
        let mut step_diffs = Vec::new();

        // A `tool`-scope script writes `ctx.arguments` as a free-form string;
        // each write is validated below so a malformed value is never carried
        // into the next program or the protocol merge-back.
        let is_tool_block = ctx.block_type == "tool_use";

        for &scope_name in RESPONSE_SCOPE_ORDER {
            // Collect programs for this scope, sorted by priority
            let mut scope_programs: Vec<&TransformProgram> = programs
                .iter()
                .filter(|p| p.enabled && p.phase == "response" && p.scope == scope_name)
                .collect();
            scope_programs.sort_by_key(|p| p.priority);

            for program in scope_programs {
                // Skip programs whose filter excludes this request (deny-first
                // semantics — see `TransformProgram::matches_filter`).
                if !program.applies_to_model(model_alias) {
                    continue;
                }
                if !program.applies_to_app(ctx.app_id.as_deref()) {
                    continue;
                }

                // Skip programs whose scope doesn't match the block type
                if !scope_matches_block_type(scope_name, &ctx.block_type) {
                    continue;
                }
                // Fast-find trigger: skip unless `trigger_regex` (if any) matches
                // this block's in-scope content (computed only when present).
                if program.has_trigger()
                    && !program.trigger_matches(&ctx.scope_searchable_text(scope_name)) {
                    continue;
                }

                // Snapshot before execution (for change detection + diff)
                let before = ctx.clone();

                // Execute. Span mode rewrites the scope's writable text in place
                // (once per `trigger_regex` match); full mode runs the script once
                // over the projected scope and merges writable fields back.
                let exec: Result<(), String> = if program.is_span() {
                    ctx.apply_text_transform(scope_name, |t| self.execute_span_text(program, t))
                        .map(|_| ())
                } else {
                    let projected = ctx.project_for_scope(scope_name);
                    self.execute_single_dynamic(program, projected)
                        .map(|result| ctx.merge_from_scope(scope_name, &result))
                };

                match exec {
                    Ok(()) => {
                        ctx.labels.clear();

                        // Validate a tool-scope script's `arguments` write at
                        // the moment it happens — this is the single check
                        // both the streaming (`BlockAccumulator`) and
                        // non-streaming (`apply_response_scripts_json`) paths
                        // funnel through. Tool-call arguments must decode to a
                        // JSON object on every wire protocol; a malformed
                        // value would otherwise be silently dropped (Anthropic
                        // / Gemini object fields) or spliced onto the wire
                        // unchecked (Chat Completions / Responses string
                        // fields). On reject, `rhai_fail_mode` decides: open
                        // reverts to the pre-script value and marks the
                        // program errored; closed aborts the block.
                        let arguments_rejected = is_tool_block
                            && ctx.arguments != before.arguments
                            && ctx
                                .arguments
                                .as_deref()
                                .is_some_and(|a| !tool_arguments_decode_to_object(a));
                        if arguments_rejected {
                            match fail_mode {
                                ScriptFailMode::Open => {
                                    tracing::warn!(
                                        program_id = %program.id,
                                        program_name = %program.name,
                                        "response transform script wrote invalid JSON \
                                         tool arguments, reverting to the pre-script \
                                         value (fail-open)"
                                    );
                                    ctx.arguments = before.arguments.clone();
                                }
                                ScriptFailMode::Closed => {
                                    tracing::error!(
                                        program_id = %program.id,
                                        program_name = %program.name,
                                        "response transform script wrote invalid JSON \
                                         tool arguments, aborting block (fail-closed)"
                                    );
                                    return Err(AppError::Internal(format!(
                                        "rhai response script `{}` produced invalid \
                                         JSON tool arguments",
                                        program.name
                                    )));
                                }
                            }
                        }

                        // Auto-detect modification → record outcome + optional diff.
                        // After a fail-open revert `arguments` matches `before`, so a
                        // rejected-only program reports `Errored` with no spurious diff.
                        let modified = ctx.was_modified(&before);
                        program_outcomes.push(TransformProgramRef {
                            name: program.name.clone(),
                            phase: Phase::Response,
                            outcome: if arguments_rejected {
                                TransformProgramOutcome::Errored
                            } else if modified {
                                TransformProgramOutcome::Modified
                            } else {
                                TransformProgramOutcome::Passed
                            },
                        });
                        if modified && capture_diffs {
                            let diff_text = generate_response_diff(&before, &ctx);
                            step_diffs.push(TransformStepDiff {
                                name: program.name.clone(),
                                diff: diff_text,
                            });
                        }
                    }
                    Err(e) => {
                        match fail_mode {
                            ScriptFailMode::Open => {
                                tracing::warn!(
                                    program_id = %program.id,
                                    program_name = %program.name,
                                    error = %e,
                                    "response transform script failed, skipping (fail-open)"
                                );
                                program_outcomes.push(TransformProgramRef {
                                    name: program.name.clone(),
                                    phase: Phase::Response,
                                    outcome: TransformProgramOutcome::Errored,
                                });
                            }
                            ScriptFailMode::Closed => {
                                tracing::error!(
                                    program_id = %program.id,
                                    program_name = %program.name,
                                    error = %e,
                                    "response transform script failed, aborting block (fail-closed)"
                                );
                                return Err(AppError::Internal(format!(
                                    "rhai response script `{}` failed in fail-closed mode: {e}",
                                    program.name
                                )));
                            }
                        }
                    }
                }
            }
        }

        Ok((ctx, program_outcomes, step_diffs))
    }

    /// Clear the AST cache (e.g. on config sync).
    pub fn clear_cache(&self) {
        self.ast_cache.clear();
    }

    /// Execute a single transform program on a projected Dynamic context.
    /// Fetch the program's compiled AST from the cache, compiling + caching on a
    /// miss. Keyed by `id:version_hash` so an edited program recompiles.
    fn get_ast(&self, program: &TransformProgram) -> Result<Arc<rhai::AST>, String> {
        let cache_key = format!("{}:{}", program.id, program.version_hash);
        if let Some(cached) = self.ast_cache.get(&cache_key) {
            return Ok(cached);
        }
        let compiled = self
            .engine
            .compile(&program.source)
            .map_err(|e| format!("compile error: {e}"))?;
        let arc = Arc::new(compiled);
        self.ast_cache.insert(cache_key, arc.clone());
        Ok(arc)
    }

    fn execute_single_dynamic(
        &self,
        program: &TransformProgram,
        ctx_dynamic: rhai::Dynamic,
    ) -> Result<rhai::Dynamic, String> {
        let ast = self.get_ast(program)?;
        let mut scope = rhai::Scope::new();
        self.engine
            .call_fn(&mut scope, &ast, "transform", (ctx_dynamic,))
            .map_err(|e| format!("runtime error: {e}"))
    }

    /// Run a span-mode program over a single text field: for each match of the
    /// program's `trigger_regex`, call `transform(m)` with a per-match map
    /// `#{ match, groups, start, end, before, after }` and splice the returned
    /// replacement back. Matches are non-overlapping and spliced right-to-left so
    /// the regex byte offsets stay valid. Returns `Some(new_text)` when any span
    /// changed, `None` otherwise. A string return ⇒ replacement; a map
    /// `#{ replace, drop }` ⇒ replace / remove; `()` or an unchanged string ⇒
    /// leave the span untouched. Errors propagate so the caller applies fail-mode.
    fn execute_span_text(
        &self,
        program: &TransformProgram,
        text: &str,
    ) -> Result<Option<String>, String> {
        // span mode without a trigger is a no-op; the admin layer enforces the
        // invariant, so this is purely defensive.
        let pattern = match program.trigger_regex.as_deref() {
            Some(p) if !p.trim().is_empty() => p,
            _ => return Ok(None),
        };
        let re = regex_cache::get(pattern);
        let ast = self.get_ast(program)?;
        self.splice_spans(&ast, &re, text)
    }

    /// Core of span mode: for each non-overlapping match of `re` in `text`, call
    /// the AST's `transform(m)` with `#{ match, groups, start, end, before, after }`
    /// and splice the replacement back right-to-left. Shared by the runtime
    /// (`execute_span_text`) and the admin test preview (`test_execute_span`).
    fn splice_spans(
        &self,
        ast: &rhai::AST,
        re: &regex::Regex,
        text: &str,
    ) -> Result<Option<String>, String> {
        let mut edits: Vec<(usize, usize, String)> = Vec::new();
        for caps in re.captures_iter(text) {
            let whole = caps.get(0).expect("capture group 0 is always present");
            let (start, end) = (whole.start(), whole.end());
            // Zero-width-match guard: never rewrite an empty span (a pattern like
            // `a*` would otherwise fire at every position and never converge).
            if start == end {
                continue;
            }
            let matched = &text[start..end];

            // Bounded context windows (char-boundary-safe) so a large field
            // doesn't copy wholesale into Rhai per match.
            let before_start = text.floor_char_boundary(start.saturating_sub(SPAN_CONTEXT_WINDOW));
            let after_end = text.floor_char_boundary((end + SPAN_CONTEXT_WINDOW).min(text.len()));

            let groups: rhai::Array = caps
                .iter()
                .skip(1)
                .map(|g| g.map_or(rhai::Dynamic::UNIT, |m| m.as_str().into()))
                .collect();

            // Key is `matched` (not `match`) — `match` is a reserved word in Rhai,
            // so `m.match` would fail to parse; `m.matched` is the script-facing name.
            let mut m = rhai::Map::new();
            m.insert("matched".into(), matched.into());
            m.insert("groups".into(), groups.into());
            m.insert("start".into(), (start as i64).into());
            m.insert("end".into(), (end as i64).into());
            m.insert("before".into(), text[before_start..start].into());
            m.insert("after".into(), text[end..after_end].into());

            let mut scope = rhai::Scope::new();
            let ret: rhai::Dynamic = self
                .engine
                .call_fn(&mut scope, ast, "transform", (rhai::Dynamic::from_map(m),))
                .map_err(|e| format!("runtime error: {e}"))?;

            let replacement: Option<String> = if ret.is_string() {
                ret.into_string().ok()
            } else if let Some(map) = ret.try_cast::<rhai::Map>() {
                if map.get("drop").is_some_and(|d| d.as_bool().unwrap_or(false)) {
                    Some(String::new())
                } else {
                    map.get("replace").and_then(|r| r.clone().into_string().ok())
                }
            } else {
                None
            };

            if let Some(rep) = replacement
                && rep != matched
            {
                edits.push((start, end, rep));
            }
        }

        if edits.is_empty() {
            return Ok(None);
        }
        let mut result = text.to_string();
        for (bs, be, rep) in edits.into_iter().rev() {
            result.replace_range(bs..be, &rep);
        }
        Ok(Some(result))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scripting::context::{RhaiMessage, RhaiTool};
    use std::collections::HashMap;

    fn sample_ctx() -> RequestContext {
        RequestContext {
            system_prompt: Some("Be helpful.".to_string()),
            messages: vec![
                RhaiMessage {
                    role: "assistant".to_string(),
                    content: "How can I help?".to_string(),
                    tool_call_id: None,
                    tool_calls: vec![],
                },
                RhaiMessage {
                    role: "user".to_string(),
                    content: "Hello!".to_string(),
                    tool_call_id: None,
                    tool_calls: vec![],
                },
            ],
            tools: vec![
                RhaiTool {
                    name: "web_search".to_string(),
                    description: Some("Search the web".to_string()),
                    parameters_json: None,
                    is_gateway_substituted: false, kind: None, config_json: None,
                },
                RhaiTool {
                    name: "get_weather".to_string(),
                    description: Some("Get weather".to_string()),
                    parameters_json: Some(r#"{"type":"object"}"#.to_string()),
                    is_gateway_substituted: false, kind: None, config_json: None,
                },
            ],
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("test-app".to_string()),
            api_version: "chat_completions".to_string(),
            metadata: HashMap::new(),
            labels: vec![],
        }
    }

    fn make_program(name: &str, source: &str, scope: &str, priority: i32) -> TransformProgram {
        TransformProgram {
            id: name.to_string(),
            name: name.to_string(),
            source: source.to_string(),
            phase: "request".to_string(),
            scope: scope.to_string(),
            priority,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }
    }

    fn make_span_program(name: &str, source: &str, trigger: &str) -> TransformProgram {
        let mut p = make_program(name, source, "messages", 100);
        p.trigger_regex = Some(trigger.to_string());
        p.match_mode = Some("span".to_string());
        p
    }

    #[test]
    fn span_single_match_replaces() {
        let engine = ScriptEngine::new();
        let p = make_span_program("redact", r#"fn transform(m) { "X" }"#, "secret");
        assert_eq!(
            engine.execute_span_text(&p, "a secret here").unwrap().as_deref(),
            Some("a X here")
        );
    }

    #[test]
    fn span_multi_match_right_to_left() {
        let engine = ScriptEngine::new();
        let p = make_span_program("up", r#"fn transform(m) { m.matched.to_upper() }"#, "[a-z]+@[a-z]+");
        assert_eq!(
            engine.execute_span_text(&p, "x a@b y c@d z").unwrap().as_deref(),
            Some("x A@B y C@D z")
        );
    }

    #[test]
    fn span_no_match_returns_none() {
        let engine = ScriptEngine::new();
        let p = make_span_program("noop", r#"fn transform(m) { "X" }"#, "zzz");
        assert_eq!(engine.execute_span_text(&p, "nothing here").unwrap(), None);
    }

    #[test]
    fn span_unchanged_return_records_nothing() {
        let engine = ScriptEngine::new();
        // Returning the match itself is a no-op (no edit recorded).
        let p = make_span_program("id", r#"fn transform(m) { m.matched }"#, "foo");
        assert_eq!(engine.execute_span_text(&p, "foo bar foo").unwrap(), None);
    }

    #[test]
    fn span_drop_removes_span() {
        let engine = ScriptEngine::new();
        let p = make_span_program("drop", r#"fn transform(m) { #{ drop: true } }"#, "X+");
        assert_eq!(engine.execute_span_text(&p, "aXXb").unwrap().as_deref(), Some("ab"));
    }

    #[test]
    fn span_capture_groups_and_replace_map() {
        let engine = ScriptEngine::new();
        // Swap `a=b` → `b=a` using capture groups, returned via `#{ replace }`.
        let p = make_span_program(
            "swap",
            r#"fn transform(m) { #{ replace: m.groups[1] + "=" + m.groups[0] } }"#,
            "([a-z]+)=([a-z]+)",
        );
        assert_eq!(engine.execute_span_text(&p, "foo=bar").unwrap().as_deref(), Some("bar=foo"));
    }

    #[test]
    fn span_utf8_multibyte_splice() {
        let engine = ScriptEngine::new();
        // Multibyte chars around the ASCII match must survive the byte-offset splice.
        let p = make_span_program("r", r#"fn transform(m) { "Z" }"#, "cat");
        assert_eq!(
            engine.execute_span_text(&p, "héllo cat wörld 🦀 cat").unwrap().as_deref(),
            Some("héllo Z wörld 🦀 Z")
        );
    }

    #[test]
    fn span_zero_width_match_guard() {
        let engine = ScriptEngine::new();
        // `a*` matches empty positions everywhere; zero-width matches are skipped
        // (no rewrite, no runaway) — only the non-empty run is replaced.
        let p = make_span_program("z", r#"fn transform(m) { "X" }"#, "a*");
        assert_eq!(engine.execute_span_text(&p, "baaab").unwrap().as_deref(), Some("bXb"));
    }

    #[test]
    fn identity_transform() {
        let engine = ScriptEngine::new();
        let program = make_program("identity", "fn transform(ctx) { ctx }", "global", 100);

        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.system_prompt.as_deref(), Some("Be helpful."));
        assert_eq!(result.messages.len(), 2);
        assert_eq!(outcomes.len(), 1);
        assert_eq!(outcomes[0].name, "identity");
        assert_eq!(outcomes[0].outcome, TransformProgramOutcome::Passed);
    }

    #[test]
    fn system_prompt_injection() {
        let engine = ScriptEngine::new();
        let program = make_program(
            "guardrail",
            r#"
                fn transform(ctx) {
                    let prompt = ctx.system_prompt;
                    if prompt == () {
                        ctx.system_prompt = "Safety first.";
                    } else {
                        ctx.system_prompt = "Safety first.\n\n" + prompt;
                    }
                    ctx
                }
            "#,
            "system_prompt",
            10,
        );

        let (result, _, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(result.system_prompt.unwrap().starts_with("Safety first."));
    }

    #[test]
    fn tool_removal_script() {
        let engine = ScriptEngine::new();
        let program = make_program(
            "tool_filter",
            r#"
                fn transform(ctx) {
                    let unsupported = ["web_search"];
                    ctx.tools = ctx.tools.filter(|t| !unsupported.contains(t.name));
                    ctx
                }
            "#,
            "tools",
            50,
        );

        let (result, _, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.tools.len(), 1);
        assert_eq!(result.tools[0].name, "get_weather");
    }

    #[test]
    fn message_filtering_script() {
        let engine = ScriptEngine::new();
        let program = make_program(
            "compression",
            r#"
                fn transform(ctx) {
                    let max = 1;
                    if ctx.messages.len() > max {
                        let result = [];
                        result.push(ctx.messages[ctx.messages.len() - 1]);
                        ctx.messages = result;
                    }
                    ctx
                }
            "#,
            "messages",
            900,
        );

        let (result, _, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0].content, "Hello!");
    }

    #[test]
    fn scope_ordering_global_before_scoped() {
        let engine = ScriptEngine::new();

        // Global script sets metadata
        let global_prog = make_program(
            "first",
            r#"
                fn transform(ctx) {
                    ctx.metadata["order"] = "global";
                    ctx
                }
            "#,
            "global",
            10,
        );

        // Tools-scoped script appends
        let tools_prog = make_program(
            "second",
            r#"
                fn transform(ctx) {
                    let prev = ctx.metadata.get("order");
                    if prev != () {
                        ctx.metadata["order"] = prev + ",tools";
                    } else {
                        ctx.metadata["order"] = "tools";
                    }
                    ctx
                }
            "#,
            "tools",
            10,
        );

        let (result, outcomes, _, _) =
            engine.execute_chain(&[tools_prog, global_prog], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        // Global runs first regardless of input order
        assert_eq!(result.metadata.get("order").unwrap(), "global,tools");
        assert_eq!(outcomes.len(), 2);
        assert_eq!(outcomes[0].name, "first");
        assert_eq!(outcomes[1].name, "second");
    }

    #[test]
    fn priority_within_scope() {
        let engine = ScriptEngine::new();

        let prog_a = make_program(
            "first",
            r#"
                fn transform(ctx) {
                    ctx.metadata["order"] = "first";
                    ctx
                }
            "#,
            "global",
            10,
        );

        let prog_b = make_program(
            "second",
            r#"
                fn transform(ctx) {
                    let prev = ctx.metadata.get("order");
                    if prev != () {
                        ctx.metadata["order"] = prev + ",second";
                    } else {
                        ctx.metadata["order"] = "second";
                    }
                    ctx
                }
            "#,
            "global",
            20,
        );

        let (result, outcomes, _, _) =
            engine.execute_chain(&[prog_a, prog_b], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("order").unwrap(), "first,second");
        assert_eq!(outcomes.len(), 2);
    }

    #[test]
    fn scope_isolation_tools_cannot_see_messages() {
        let engine = ScriptEngine::new();

        // Tools-scoped script tries to read messages — should not see them
        let program = make_program(
            "tools_only",
            r#"
                fn transform(ctx) {
                    // messages should not be in scope
                    if ctx.messages != () {
                        ctx.metadata["saw_messages"] = "true";
                    } else {
                        ctx.metadata["saw_messages"] = "false";
                    }
                    ctx
                }
            "#,
            "tools",
            10,
        );

        let (result, _, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("saw_messages").unwrap(), "false");
        // Messages should be unchanged
        assert_eq!(result.messages.len(), 2);
    }

    #[test]
    fn scope_isolation_messages_cannot_see_tools() {
        let engine = ScriptEngine::new();

        // Messages-scoped script tries to read tools — should not see them
        let program = make_program(
            "messages_only",
            r#"
                fn transform(ctx) {
                    if ctx.tools != () {
                        ctx.metadata["saw_tools"] = "true";
                    } else {
                        ctx.metadata["saw_tools"] = "false";
                    }
                    ctx
                }
            "#,
            "messages",
            10,
        );

        let (result, _, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("saw_tools").unwrap(), "false");
        // Tools should be unchanged
        assert_eq!(result.tools.len(), 2);
    }

    #[test]
    fn disabled_program_skipped() {
        let engine = ScriptEngine::new();
        let mut program = make_program("disabled", "fn transform(ctx) { ctx }", "global", 100);
        program.enabled = false;

        let (_, outcomes, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(outcomes.is_empty());
    }

    #[test]
    fn failed_script_is_skipped_fail_open() {
        let engine = ScriptEngine::new();
        let bad_program = make_program(
            "broken",
            r#"
                fn transform(ctx) {
                    let x = 1 / 0;
                    ctx
                }
            "#,
            "global",
            10,
        );

        let good_program = make_program("identity", "fn transform(ctx) { ctx }", "global", 20);

        let (result, outcomes, _, _) = engine
            .execute_chain(&[bad_program, good_program], sample_ctx(), false, None, ScriptFailMode::Open)
            .unwrap();
        assert!(outcomes.iter().any(|o| o.name == "broken" && o.outcome == TransformProgramOutcome::Errored));
        assert!(outcomes.iter().any(|o| o.name == "identity" && o.outcome == TransformProgramOutcome::Passed));
        assert_eq!(result.messages.len(), 2);
    }

    #[test]
    fn ast_cache_hit() {
        let engine = ScriptEngine::new();
        let program = make_program("test", "fn transform(ctx) { ctx }", "global", 100);

        let _ = engine.execute_chain(std::slice::from_ref(&program), sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(engine.ast_cache.len(), 1);

        let _ = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(engine.ast_cache.len(), 1);
    }

    #[test]
    fn validate_valid_script() {
        let engine = ScriptEngine::new();
        assert!(engine.validate("fn transform(ctx) { ctx }").is_ok());
    }

    #[test]
    fn validate_invalid_script() {
        let engine = ScriptEngine::new();
        assert!(engine.validate("fn transform(ctx { broken").is_err());
    }

    #[test]
    fn test_execute_runs_script() {
        let engine = ScriptEngine::new();
        let result = engine
            .test_execute(
                r#"
                fn transform(ctx) {
                    ctx.model = "modified";
                    ctx
                }
            "#,
                sample_ctx(),
            )
            .unwrap();
        assert_eq!(result.model, "modified");
    }

    #[test]
    fn execution_limit_enforced() {
        let engine = ScriptEngine::new();
        let program = make_program(
            "infinite",
            r#"
                fn transform(ctx) {
                    let i = 0;
                    loop { i += 1; }
                    ctx
                }
            "#,
            "global",
            100,
        );

        let (_, outcomes, _, _) = engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(outcomes.iter().any(|o| o.outcome == TransformProgramOutcome::Errored));
    }

    #[test]
    fn pii_redaction_from_script() {
        let engine = ScriptEngine::new();
        let result = engine
            .test_execute(
                r#"
                fn transform(ctx) {
                    for i in range(0, ctx.messages.len()) {
                        ctx.messages[i].content = redact_pii(ctx.messages[i].content);
                    }
                    ctx
                }
            "#,
                RequestContext {
                    messages: vec![RhaiMessage {
                        role: "user".to_string(),
                        content: "Email me at test@example.com".to_string(),
                        tool_call_id: None,
                        tool_calls: vec![],
                    }],
                    ..sample_ctx()
                },
            )
            .unwrap();
        assert!(result.messages[0].content.contains("[REDACTED:EMAIL_ADDRESS]"));
        assert!(!result.messages[0].content.contains("test@example.com"));
    }

    #[test]
    fn compression_script() {
        let engine = ScriptEngine::new();
        let mut ctx = sample_ctx();
        // Create messages with long content to exceed 80% of a small context window
        // Each message ~100 chars → ~25 tokens. 10 messages → ~250 tokens.
        // Set context_window = 200 so 250 > 160 (80%) triggers compression.
        ctx.messages = (0..10)
            .map(|i| RhaiMessage {
                role: if i % 2 == 0 { "user" } else { "assistant" }.to_string(),
                content: format!("message {i} with some padding text to make it longer for token estimation purposes here"),
                tool_call_id: None,
                tool_calls: vec![],
            })
            .collect();
        ctx.metadata
            .insert("context_window".to_string(), "200".to_string());

        let result = engine
            .test_execute(
                r#"
                fn transform(ctx) {
                    let cw = ctx.metadata["context_window"];
                    if cw == () { return ctx; }
                    let cw = parse_int(cw);
                    if cw == () || cw <= 0 { return ctx; }
                    let total_chars = 0;
                    for i in range(0, ctx.messages.len()) {
                        total_chars += ctx.messages[i].content.len();
                    }
                    let estimated_tokens = total_chars / 4;
                    let threshold = cw * 80 / 100;
                    if estimated_tokens <= threshold { return ctx; }
                    if ctx.messages.len() < 2 { return ctx; }
                    let last_user_idx = -1;
                    for i in range(0, ctx.messages.len()) {
                        if ctx.messages[i].role == "user" { last_user_idx = i; }
                    }
                    if last_user_idx < 0 { return ctx; }
                    let last_user_content = ctx.messages[last_user_idx].content;
                    let prior = "";
                    for i in range(0, last_user_idx) {
                        prior += "[" + ctx.messages[i].role + "]: " + ctx.messages[i].content + "\n";
                    }
                    let compressed = "CONTEXT:\n" + prior + "\nREQUEST:\n" + last_user_content;
                    ctx.messages = [];
                    ctx.messages.push(#{role: "user", content: compressed, tool_call_id: ()});
                    ctx.metadata["compression"] = "applied";
                    ctx
                }
            "#,
                ctx,
            )
            .unwrap();
        // Should be compressed to a single user message
        assert_eq!(result.messages.len(), 1);
        assert_eq!(result.messages[0].role, "user");
        assert!(result.messages[0].content.contains("CONTEXT:"));
        assert!(result.messages[0].content.contains("REQUEST:"));
        assert_eq!(
            result.metadata.get("compression").unwrap(),
            "applied"
        );
    }

    #[test]
    fn model_filter_skips_non_matching() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "gpt_only",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.model_filter = Some("gpt-4o, gpt-4o-mini".to_string());

        // sample_ctx() has model = "gpt-4o" — should match
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program.clone()], sample_ctx(), false, Some("gpt-4o"), ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
        assert!(outcomes.iter().any(|o| o.name == "gpt_only"));

        // Different model alias — should be skipped
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], sample_ctx(), false, Some("claude-3"), ScriptFailMode::Open).unwrap();
        assert!(!result.metadata.contains_key("ran"));
        assert!(outcomes.is_empty());
    }

    #[test]
    fn app_filter_skips_non_matching() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "opencode_only",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.app_filter = Some("opencode".to_string());

        // sample_ctx() has app_id = Some("test-app") — should NOT match
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program.clone()], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(!result.metadata.contains_key("ran"));
        assert!(outcomes.is_empty());

        // Context with matching app_id
        let mut ctx = sample_ctx();
        ctx.app_id = Some("opencode".to_string());
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], ctx, false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
        assert!(outcomes.iter().any(|o| o.name == "opencode_only"));
    }

    #[test]
    fn trigger_regex_gates_request_script() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "redact_on_at",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.trigger_regex = Some("@".to_string());

        // sample_ctx content has no "@" → script is skipped, no outcome recorded.
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program.clone()], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(!result.metadata.contains_key("ran"));
        assert!(outcomes.is_empty());

        // A message containing an email → trigger matches → script runs.
        let mut ctx = sample_ctx();
        ctx.messages[1].content = "Email me at a@b.com".to_string();
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], ctx, false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
        assert!(outcomes.iter().any(|o| o.name == "redact_on_at"));
    }

    #[test]
    fn blank_trigger_always_runs() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "always",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        // A blank trigger is treated as "no trigger" — runs unconditionally.
        program.trigger_regex = Some("   ".to_string());
        let (result, _, _, _) =
            engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
    }

    #[test]
    fn invalid_trigger_skips_script() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "never",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        // An invalid pattern degrades to never-match — the script is skipped,
        // never a panic or a compile error at run time.
        program.trigger_regex = Some("[unterminated".to_string());
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(!result.metadata.contains_key("ran"));
        assert!(outcomes.is_empty());
    }

    #[test]
    fn empty_filter_matches_all() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "test",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.model_filter = Some(String::new());
        program.app_filter = Some(String::new());

        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], sample_ctx(), false, Some("anything"), ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
        assert!(!outcomes.is_empty());
    }

    #[test]
    fn matches_filter_unit() {
        fn check(filter: Option<&str>, value: Option<&str>, expected: bool, label: &str) {
            let f = filter.map(|s| s.to_string());
            assert_eq!(
                TransformProgram::matches_filter(&f, value),
                expected,
                "{label}: filter={filter:?} value={value:?}"
            );
        }
        // Empty / None filter — match all
        check(None, Some("x"), true, "none-filter matches");
        check(None, None, true, "none-filter + none-value matches");
        check(Some(""), Some("anything"), true, "empty-filter matches");
        check(Some("   "), Some("anything"), true, "whitespace-only filter matches");

        // Pure positive (allowlist)
        check(Some("gpt-4o"), Some("gpt-4o"), true, "positive hit");
        check(Some("gpt-4o"), Some("claude-3"), false, "positive miss");
        check(Some("gpt-4o,claude-3"), Some("claude-3"), true, "positive list hit");
        check(Some(" gpt-4o , claude-3 "), Some("gpt-4o"), true, "whitespace tolerated");
        check(Some("librechat"), None, false, "positive list + unknown value");

        // Pure negative (denylist)
        check(Some("!x"), Some("x"), false, "negative hit");
        check(Some("!x"), Some("y"), true, "negative miss");
        check(Some("!streamscope-agent"), None, true, "purely-negative + unknown value");
        check(Some(" ! streamscope-agent "), Some("streamscope-agent"), false, "negative w/ space");

        // Mixed
        check(Some("librechat,!streamscope-agent"), Some("librechat"), true, "mixed: positive hit, negative miss");
        check(Some("librechat,!streamscope-agent"), Some("streamscope-agent"), false, "mixed: negative wins");
        check(Some("librechat,!streamscope-agent"), Some("opencode"), false, "mixed: positive list unsatisfied");
        check(Some("librechat,!agent"), None, false, "mixed + unknown");

        // Contradictory — negative wins (deny-first)
        check(Some("x,!x"), Some("x"), false, "contradictory: deny wins");
    }

    // ── Response-phase execute_response_chain tests ──

    fn make_response_program(
        name: &str,
        source: &str,
        scope: &str,
        priority: i32,
    ) -> TransformProgram {
        TransformProgram {
            id: name.to_string(),
            name: name.to_string(),
            source: source.to_string(),
            phase: "response".to_string(),
            scope: scope.to_string(),
            priority,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }
    }

    fn sample_text_block() -> response_context::ResponseBlockContext {
        response_context::ResponseBlockContext {
            block_type: "text".to_string(),
            content: "Hello world with secret data".to_string(),
            tool_name: None,
            tool_id: None,
            arguments: None,
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("test-app".to_string()),
            api_version: "chat_completions".to_string(),
            metadata: HashMap::new(),
            labels: vec![],
        }
    }

    fn sample_tool_block() -> response_context::ResponseBlockContext {
        response_context::ResponseBlockContext {
            block_type: "tool_use".to_string(),
            content: String::new(),
            tool_name: Some("Bash".to_string()),
            tool_id: Some("call_1".to_string()),
            arguments: Some(r#"{"command":"rm -rf /"}"#.to_string()),
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("test-app".to_string()),
            api_version: "chat_completions".to_string(),
            metadata: HashMap::new(),
            labels: vec![],
        }
    }

    #[test]
    fn response_chain_text_script_modifies_content() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "redact",
            r#"fn transform(ctx) { ctx.content = "[FILTERED] " + ctx.content; ctx }"#,
            "text",
            10,
        );

        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert!(result.content.starts_with("[FILTERED] "));
        assert!(result.content.contains("Hello world"));
        assert!(outcomes
            .iter()
            .any(|o| o.name == "redact" && o.outcome == TransformProgramOutcome::Modified));
    }

    #[test]
    fn trigger_regex_gates_response_script() {
        let engine = ScriptEngine::new();
        let mut program = make_response_program(
            "tag_on_secret",
            r#"fn transform(ctx) { ctx.content = "[X] " + ctx.content; ctx }"#,
            "text",
            10,
        );
        program.trigger_regex = Some("secret".to_string());

        // sample_text_block content contains "secret" → trigger matches → runs.
        let (result, outcomes, _) = engine
            .execute_response_chain(&[program.clone()], sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert!(result.content.starts_with("[X] "));
        assert!(!outcomes.is_empty());

        // A block without the pattern → script skipped, content untouched.
        let mut block = sample_text_block();
        block.content = "nothing sensitive here".to_string();
        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], block, None, false, ScriptFailMode::Open)
            .unwrap();
        assert_eq!(result.content, "nothing sensitive here");
        assert!(outcomes.is_empty());
    }

    #[test]
    fn response_chain_text_script_skips_tool_blocks() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "text_only",
            r#"fn transform(ctx) { ctx.labels.push("should_not_run"); ctx }"#,
            "text",
            10,
        );

        let (_, outcomes, _) = engine
            .execute_response_chain(&[program], sample_tool_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        // Script should not have run on a tool block
        assert!(outcomes.is_empty());
    }

    #[test]
    fn response_chain_tool_script_modifies_arguments() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "sanitize",
            r#"fn transform(ctx) { ctx.arguments = "{\"command\":\"echo safe\"}"; ctx }"#,
            "tool",
            10,
        );

        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], sample_tool_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert!(result.arguments.as_ref().unwrap().contains("echo safe"));
        assert!(!outcomes.is_empty());
    }

    #[test]
    fn response_chain_tool_script_invalid_arguments_reverted_fail_open() {
        // A `tool`-scope script that writes syntactically broken JSON must not
        // reach the merge-back unchanged. Under fail-open the chain reverts
        // `arguments` to the pre-script value and marks the offending program
        // `Errored` so a `script_error` badge fires.
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "break_args",
            r#"fn transform(ctx) { ctx.arguments = "{not valid json"; ctx }"#,
            "tool",
            10,
        );

        let original = sample_tool_block().arguments;
        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], sample_tool_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        // Reverted to the pre-script value, not the malformed string.
        assert_eq!(result.arguments, original);
        // The offending program is surfaced as Errored, not Modified.
        assert!(outcomes
            .iter()
            .any(|o| o.name == "break_args" && o.outcome == TransformProgramOutcome::Errored));
    }

    #[test]
    fn response_chain_tool_script_non_object_arguments_reverted_fail_open() {
        // Valid JSON that is not an object (an array here) is still malformed
        // for every wire protocol's tool-argument field — treated the same as
        // a syntax error.
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "array_args",
            r#"fn transform(ctx) { ctx.arguments = "[1,2,3]"; ctx }"#,
            "tool",
            10,
        );

        let original = sample_tool_block().arguments;
        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], sample_tool_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert_eq!(result.arguments, original);
        assert!(outcomes
            .iter()
            .any(|o| o.name == "array_args" && o.outcome == TransformProgramOutcome::Errored));
    }

    #[test]
    fn response_chain_tool_script_invalid_arguments_aborts_fail_closed() {
        // Under fail-closed the malformed edit aborts the whole block — the
        // caller turns the Err into a suppressed block + operator notice.
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "break_args",
            r#"fn transform(ctx) { ctx.arguments = "{not valid json"; ctx }"#,
            "tool",
            10,
        );

        let result = engine.execute_response_chain(
            &[program],
            sample_tool_block(),
            None,
            false,
            ScriptFailMode::Closed,
        );
        assert!(result.is_err(), "expected fail-closed abort on invalid JSON arguments");
    }

    #[test]
    fn response_chain_tool_script_valid_object_arguments_pass_validation() {
        // The merge-back validation must not interfere with a well-formed
        // rewrite — valid JSON object arguments survive untouched.
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "rewrite",
            r#"fn transform(ctx) { ctx.arguments = "{\"command\":\"echo ok\"}"; ctx }"#,
            "tool",
            10,
        );

        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], sample_tool_block(), None, false, ScriptFailMode::Closed)
            .unwrap();
        assert!(result.arguments.as_ref().unwrap().contains("echo ok"));
        assert!(outcomes
            .iter()
            .any(|o| o.name == "rewrite" && o.outcome == TransformProgramOutcome::Modified));
    }

    #[test]
    fn tool_call_repair_seed_coerces_stringified_values() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "tool_call_repair",
            include_str!("../../../../seeds/scripts/tool_call_repair.rhai"),
            "tool",
            100,
        );

        let mut block = sample_tool_block();
        block.arguments =
            Some(r#"{"command":"ls","items":"[1,2,3]","recursive":"true"}"#.to_string());

        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], block, None, false, ScriptFailMode::Open)
            .unwrap();

        let args: serde_json::Value =
            serde_json::from_str(result.arguments.as_ref().unwrap()).unwrap();
        // Stringified array → real array; string bool → real bool; plain string kept.
        assert_eq!(args["items"], serde_json::json!([1, 2, 3]));
        assert_eq!(args["recursive"], serde_json::json!(true));
        assert_eq!(args["command"], serde_json::json!("ls"));
        // The repair surfaces as a Modified outcome on the transform trail.
        assert!(outcomes
            .iter()
            .any(|o| o.name == "tool_call_repair" && o.outcome == TransformProgramOutcome::Modified));
    }

    #[test]
    fn tool_call_repair_seed_noop_on_clean_arguments() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "tool_call_repair",
            include_str!("../../../../seeds/scripts/tool_call_repair.rhai"),
            "tool",
            100,
        );

        let mut block = sample_tool_block();
        block.arguments = Some(r#"{"command":"ls","items":[1,2,3]}"#.to_string());

        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], block, None, false, ScriptFailMode::Open)
            .unwrap();

        // Already well-typed → no rewrite → Passed, not Modified.
        let args: serde_json::Value =
            serde_json::from_str(result.arguments.as_ref().unwrap()).unwrap();
        assert_eq!(args["items"], serde_json::json!([1, 2, 3]));
        assert!(outcomes
            .iter()
            .any(|o| o.name == "tool_call_repair" && o.outcome == TransformProgramOutcome::Passed));
    }

    #[test]
    fn response_chain_tool_script_skips_text_blocks() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "tool_only",
            r#"fn transform(ctx) { ctx.labels.push("should_not_run"); ctx }"#,
            "tool",
            10,
        );

        let (_, outcomes, _) = engine
            .execute_response_chain(&[program], sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert!(outcomes.is_empty());
    }

    #[test]
    fn response_chain_global_runs_on_all_types() {
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "global_tag",
            r#"fn transform(ctx) { ctx.labels.push("tagged"); ctx }"#,
            "global",
            10,
        );

        // Text block
        let (_, outcomes1, _) = engine
            .execute_response_chain(std::slice::from_ref(&program), sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert!(!outcomes1.is_empty());

        // Tool block
        let (_, outcomes2, _) = engine
            .execute_response_chain(std::slice::from_ref(&program), sample_tool_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert!(!outcomes2.is_empty());
    }

    #[test]
    fn response_chain_scope_isolation_text_hides_tool_fields() {
        // ctx.labels is no longer surfaced from the engine. Replace by checking
        // that the script ran on a text block (program outcome present).
        let engine = ScriptEngine::new();
        let program = make_response_program(
            "text_check",
            r#"
                fn transform(ctx) {
                    if ctx.tool_name == () {
                        ctx.metadata["saw"] = "no_tool_name";
                    }
                    ctx
                }
            "#,
            "text",
            10,
        );

        let (result, outcomes, _) = engine
            .execute_response_chain(&[program], sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert_eq!(result.metadata.get("saw").map(String::as_str), Some("no_tool_name"));
        assert!(!outcomes.is_empty());
    }

    #[test]
    fn response_chain_scope_ordering() {
        let engine = ScriptEngine::new();
        let global_prog = make_response_program(
            "global_first",
            r#"fn transform(ctx) { ctx.metadata["order"] = "global"; ctx }"#,
            "global",
            10,
        );
        let text_prog = make_response_program(
            "text_second",
            r#"
                fn transform(ctx) {
                    let prev = ctx.metadata.get("order");
                    if prev != () {
                        ctx.metadata["order"] = prev + ",text";
                    } else {
                        ctx.metadata["order"] = "text";
                    }
                    ctx
                }
            "#,
            "text",
            10,
        );

        let (result, _, _) = engine
            .execute_response_chain(&[text_prog, global_prog], sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        assert_eq!(result.metadata.get("order").unwrap(), "global,text");
    }

    #[test]
    fn response_chain_fail_open_on_script_error() {
        let engine = ScriptEngine::new();
        let bad_prog = make_response_program(
            "broken",
            r#"fn transform(ctx) { let x = 1/0; ctx }"#,
            "text",
            10,
        );
        let good_prog = make_response_program(
            "good",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "text",
            20,
        );

        let (result, outcomes, _) = engine
            .execute_response_chain(&[bad_prog, good_prog], sample_text_block(), None, false, ScriptFailMode::Open)
            .unwrap();
        // Broken script logged error, good script still ran
        assert!(outcomes
            .iter()
            .any(|o| o.name == "broken" && o.outcome == TransformProgramOutcome::Errored));
        assert!(outcomes.iter().any(|o| o.name == "good"));
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
    }

    // ── Filter correctness tests ──

    #[test]
    fn has_filter_helpers() {
        let mut p = make_program("t", "fn transform(ctx) { ctx }", "global", 10);
        assert!(!p.has_app_filter());
        assert!(!p.has_model_filter());

        p.app_filter = Some(String::new());
        p.model_filter = Some(String::new());
        assert!(!p.has_app_filter());
        assert!(!p.has_model_filter());

        p.app_filter = Some("claude-code".to_string());
        p.model_filter = Some("gpt-4o".to_string());
        assert!(p.has_app_filter());
        assert!(p.has_model_filter());
    }

    #[test]
    fn phase_filter_blocks_response_programs_in_request_chain() {
        let engine = ScriptEngine::new();
        // response-phase program with scope "global" — must NOT run in execute_chain
        let prog = make_response_program(
            "rsp_global",
            r#"fn transform(ctx) { ctx.metadata["leaked"] = "yes"; ctx }"#,
            "global",
            10,
        );
        let (result, outcomes, _, _) =
            engine.execute_chain(&[prog], sample_ctx(), false, Some("gpt-4o"), ScriptFailMode::Open).unwrap();
        assert!(outcomes.is_empty(), "response-phase program should not run in request chain");
        assert!(!result.metadata.contains_key("leaked"));
    }

    #[test]
    fn app_filter_skips_when_app_id_is_none() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "cc_only",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.app_filter = Some("claude-code".to_string());

        // Context with app_id = None — program should NOT run
        let mut ctx = sample_ctx();
        ctx.app_id = None;
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], ctx, false, Some("gpt-4o"), ScriptFailMode::Open).unwrap();
        assert!(outcomes.is_empty(), "app-filtered program should not run when app_id is None");
        assert!(!result.metadata.contains_key("ran"));
    }

    #[test]
    fn model_filter_skips_when_model_alias_is_none() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "gpt_only",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.model_filter = Some("gpt-4o".to_string());

        // model_alias = None — program should NOT run
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], sample_ctx(), false, None, ScriptFailMode::Open).unwrap();
        assert!(outcomes.is_empty(), "model-filtered program should not run when model_alias is None");
        assert!(!result.metadata.contains_key("ran"));
    }

    #[test]
    fn no_filter_programs_run_when_values_are_none() {
        let engine = ScriptEngine::new();
        let program = make_program(
            "always",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        // No filters + None values — program should still run
        let mut ctx = sample_ctx();
        ctx.app_id = None;
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], ctx, false, None, ScriptFailMode::Open).unwrap();
        assert!(!outcomes.is_empty(), "unfiltered program should run even with None values");
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
    }

    #[test]
    fn response_chain_app_filter_skips_when_app_id_is_none() {
        let engine = ScriptEngine::new();
        let mut prog = make_response_program(
            "cc_rsp",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "text",
            10,
        );
        prog.app_filter = Some("claude-code".to_string());

        let mut block = sample_text_block();
        block.app_id = None;
        let (result, outcomes, _) =
            engine.execute_response_chain(&[prog], block, Some("gpt-4o"), false, ScriptFailMode::Open).unwrap();
        assert!(outcomes.is_empty(), "app-filtered response program should not run when app_id is None");
        assert!(!result.metadata.contains_key("ran"));
    }

    #[test]
    fn response_chain_model_filter_skips_when_model_alias_is_none() {
        let engine = ScriptEngine::new();
        let mut prog = make_response_program(
            "gpt_rsp",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "text",
            10,
        );
        prog.model_filter = Some("gpt-4o".to_string());

        let (result, outcomes, _) =
            engine.execute_response_chain(&[prog], sample_text_block(), None, false, ScriptFailMode::Open).unwrap();
        assert!(outcomes.is_empty(), "model-filtered response program should not run when model_alias is None");
        assert!(!result.metadata.contains_key("ran"));
    }

    #[test]
    fn app_filter_matches_when_app_id_present() {
        let engine = ScriptEngine::new();
        let mut program = make_program(
            "cc_only",
            r#"fn transform(ctx) { ctx.metadata["ran"] = "yes"; ctx }"#,
            "global",
            10,
        );
        program.app_filter = Some("claude-code".to_string());

        let mut ctx = sample_ctx();
        ctx.app_id = Some("claude-code".to_string());
        let (result, outcomes, _, _) =
            engine.execute_chain(&[program], ctx, false, Some("gpt-4o"), ScriptFailMode::Open).unwrap();
        assert!(!outcomes.is_empty(), "app-filtered program should run when app_id matches");
        assert_eq!(result.metadata.get("ran").unwrap(), "yes");
    }

    // ── ScriptFailMode ──

    #[test]
    fn script_fail_mode_from_str_parses_variants() {
        assert_eq!(ScriptFailMode::parse("open"), ScriptFailMode::Open);
        assert_eq!(ScriptFailMode::parse("closed"), ScriptFailMode::Closed);
        assert_eq!(ScriptFailMode::parse("fail-closed"), ScriptFailMode::Closed);
        assert_eq!(ScriptFailMode::parse("fail_closed"), ScriptFailMode::Closed);
        assert_eq!(ScriptFailMode::parse("CLOSED"), ScriptFailMode::Closed);
        // Unknown / typo → Open (safer default, preserves request flow).
        assert_eq!(ScriptFailMode::parse("nonsense"), ScriptFailMode::Open);
        assert_eq!(ScriptFailMode::parse(""), ScriptFailMode::Open);
    }

    #[test]
    fn chain_fail_open_continues_past_broken_script() {
        let engine = ScriptEngine::new();
        let bad = make_program("broken", "fn transform(ctx) { undefined_fn(); ctx }", "global", 10);
        let good = make_program(
            "after_broken",
            r#"fn transform(ctx) { ctx.metadata["after"] = "ran"; ctx }"#,
            "global",
            20,
        );
        let (ctx, outcomes, _, _) = engine
            .execute_chain(&[bad, good], sample_ctx(), false, None, ScriptFailMode::Open)
            .expect("fail-open chain must not return Err on script error");
        assert!(outcomes
            .iter()
            .any(|o| o.name == "broken" && o.outcome == TransformProgramOutcome::Errored));
        assert_eq!(ctx.metadata.get("after").map(String::as_str), Some("ran"),
            "subsequent scripts must still run in fail-open mode");
    }

    #[test]
    fn chain_fail_closed_short_circuits_on_script_error() {
        let engine = ScriptEngine::new();
        let bad = make_program("broken", "fn transform(ctx) { undefined_fn(); ctx }", "global", 10);
        let good = make_program(
            "after_broken",
            r#"fn transform(ctx) { ctx.metadata["after"] = "ran"; ctx }"#,
            "global",
            20,
        );
        let err = engine
            .execute_chain(&[bad, good], sample_ctx(), false, None, ScriptFailMode::Closed)
            .expect_err("fail-closed chain must return Err on script error");
        let msg = format!("{err:?}");
        assert!(msg.contains("broken"), "error must name the failing script, got: {msg}");
        assert!(msg.contains("fail-closed"), "error must mention fail-closed mode, got: {msg}");
    }

    #[test]
    fn response_chain_fail_closed_short_circuits_on_script_error() {
        let engine = ScriptEngine::new();
        let bad = TransformProgram {
            id: "p-bad".to_string(),
            version_hash: "v".to_string(),
            name: "broken_resp".to_string(),
            source: "fn transform(ctx) { undefined_fn(); ctx }".to_string(),
            phase: "response".to_string(),
            scope: "text".to_string(),
            priority: 10,
            enabled: true,
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        };
        let err = engine
            .execute_response_chain(
                &[bad],
                sample_text_block(),
                None,
                false,
                ScriptFailMode::Closed,
            )
            .expect_err("fail-closed response chain must return Err");
        let msg = format!("{err:?}");
        assert!(msg.contains("broken_resp"));
        assert!(msg.contains("fail-closed"));
    }
}
