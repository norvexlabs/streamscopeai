//! Request-phase transform chain.
//!
//! Executes transforms in order: tool policy (`phase=request,
//! scope=tool_definitions, action=block` rules — drops disallowed tool
//! definitions before forwarding), tool-result redaction (`phase=request,
//! scope=tool_results, action=replace` rules — regex/wholesale/drop rewrite
//! against the joined-text view of each tool_result body), Rhai script
//! chain (grouped by scope: global → system_prompt → messages → tools,
//! sorted by priority within each scope), stream options injection, and
//! tool name sanitization.
//! When `capture_diffs` is enabled, each step's before/after is recorded
//! as a [`TransformStepDiff`](crate::proxy::content::TransformStepDiff)
//! for the audit trail.

use crate::api::ApiRequest;
use crate::audit::{BadgeBuilder, Phase};
use crate::auth::UserContext;
use crate::config::tool_rules::{
    self, ActionKind, Rule, RuleAction, Scope, ToolDefinitionResolver, ToolResultResolver,
};
use crate::error::AppError;
use crate::proxy::content::{TransformProgramOutcome, TransformProgramRef, TransformStepDiff};
use crate::scripting::context;
use crate::scripting::{ScriptEngine, ScriptFailMode, TransformProgram};

/// Truncate a string to at most `max` chars on char boundaries for diff previews.
fn preview(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_string();
    }
    let end = s.floor_char_boundary(max);
    format!("{}…", &s[..end])
}

/// Internal flow-control flags computed by the request-phase chain. Not surfaced
/// in the audit record directly — drives session-baseline detection (compression),
/// `transform_diff.system_prompt_modified`, and `transform_diff` effective-tools
/// capture. User-facing chips are conveyed via `TransformResult::badges`.
#[derive(Debug, Default, Clone)]
pub struct TransformFlags {
    pub compression_applied: bool,
    pub system_prompt_modified: bool,
    pub tools_modified: bool,
    pub messages_modified: bool,
}

/// Result of transform_request: typed badges + per-program outcomes + diff data.
pub struct TransformResult {
    /// User-facing audit badges (drained into `AuditRecord::badges`).
    pub badges: BadgeBuilder,
    /// Per-program outcomes (drained into `transform_diff.transform_programs`).
    pub program_outcomes: Vec<TransformProgramRef>,
    /// Internal flags driving downstream pipeline decisions.
    pub flags: TransformFlags,
    pub step_diffs: Option<Vec<TransformStepDiff>>,
    pub injection_blocks: Vec<crate::proxy::content::InjectionBlock>,
    /// The tools tool policy withheld from this request — a declaration it
    /// removed, or a tool the client lists as deferred — each with its rule.
    pub blocked_tools: Vec<crate::proxy::content::BlockedToolInfo>,
    /// The `blocked_tools` the forwarded request does not declare again (a
    /// later step — a script, a substitution — may declare a tool under a
    /// withheld name on purpose). The answer refuses a call by one of these
    /// names: the client may still run a tool it does not declare.
    pub withheld_tools: Vec<crate::proxy::content::BlockedToolInfo>,
    pub redacted_tool_results: Vec<crate::proxy::content::RedactedToolResultInfo>,
    /// Tool-definition rewrites produced by `Substitute` / `InterceptOnly`
    /// rules at `Request × ToolDefinitions`. Empty when no such rules fired.
    /// Carried to the response side so the agent loop can recognise echoes
    /// of substituted tool names and route them through the bound intercept
    /// handler instead of forwarding to the client.
    pub intercept_bindings: Vec<crate::proxy::content::InterceptBinding>,
}

/// Apply all request-phase transforms and return a list of transform names applied.
///
/// Called AFTER routing has resolved the upstream target. The model in the request
/// body is force-set to `upstream_target.model` by the caller after this returns.
///
/// Execution order:
/// 0. Remove the gateway-owned body fields the client set
///    ([`crate::api::GATEWAY_OWNED_WIRE_FIELDS`]) — first, so no later step,
///    target or cache key sees the client's value
/// 0b. Tool policy — block tools matching name-only block rules
/// 1. Rhai script chain (active programs by scope/priority)
/// 2. Inject stream_options.include_usage for streaming ChatCompletions
/// 3. Sanitize request (tool names, etc.)
/// 4. Point the history's `tool_reference`s at the final declarations — last,
///    after every step that renames or removes one
#[allow(clippy::too_many_arguments)]
pub async fn transform_request(
    request: &mut ApiRequest,
    user: &UserContext,
    script_engine: &ScriptEngine,
    active_programs: &[TransformProgram],
    app_id: Option<&str>,
    context_window: Option<i32>,
    upstream_provider: Option<&str>,
    needs_translation: bool,
    capture_diffs: bool,
    tool_rules: &[Rule],
    field_profiles: Option<&tool_rules::FieldProfileSet>,
    mcp_config: Option<&crate::config::mcp::McpConfig>,
    sanitize_tool_names: bool,
    rhai_fail_mode: ScriptFailMode,
) -> Result<TransformResult, AppError> {
    let field_profiles_arg = field_profiles;
    let mut badges = BadgeBuilder::new();
    let mut program_outcomes: Vec<TransformProgramRef> = Vec::new();
    let mut flags = TransformFlags::default();
    let mut step_diffs: Vec<TransformStepDiff> = Vec::new();
    let mut injection_blocks: Vec<crate::proxy::content::InjectionBlock> = Vec::new();
    let mut blocked_tools: Vec<crate::proxy::content::BlockedToolInfo> = Vec::new();
    let mut redacted_tool_results: Vec<crate::proxy::content::RedactedToolResultInfo> = Vec::new();
    let mut intercept_bindings: Vec<crate::proxy::content::InterceptBinding> = Vec::new();

    // 0. Gateway-owned fields. The caller captured the client's body for the
    //    audit before this runs, so the record keeps what was sent; the marker
    //    below says what was removed. Scripts and presets run after this, so an
    //    operator can still set one of these fields deliberately.
    for (field, value) in request.strip_gateway_owned_fields() {
        injection_blocks.push(crate::proxy::forward_body::removed_field_block(
            field,
            &crate::proxy::forward_body::capture_json(&value),
        ));
    }

    let resolved_model = request.model().to_string();

    // The tools the client declared, and every rename the steps below make to
    // a declaration, one list per step in the order they run: the history's
    // `tool_reference`s are pointed at the final declarations at the end.
    let client_declared = anthropic_declared_names(request);
    let mut rename_steps: Vec<Vec<(String, String)>> = Vec::new();

    // 0b. Tool policy — drop tool definitions matching `phase=request,
    //    scope=tool_definitions, action=block` rules. The unified evaluator
    //    walks rules ordered by `(priority, position)` and stops at the first
    //    `block` hit per tool name. Classify-only rules at this scope are
    //    surfaced via the response-phase classify path on the resulting tool
    //    calls — request-phase classify on definitions is a no-op (no audit
    //    surface for "model was offered tool X"). The answer refuses a call
    //    to any tool this step names (`TransformResult::withheld_tools`): a
    //    client can run a tool it does not declare.
    let def_rules = tool_rules::extract_for(
        tool_rules,
        tool_rules::Phase::Request,
        Scope::ToolDefinitions,
        tool_rules::RuleAxes {
            model: Some(&resolved_model),
            app_id,
            ..Default::default()
        },
    );
    let blocking_def_rules: Vec<&Rule> = def_rules
        .iter()
        .copied()
        .filter(|r| matches!(r.action.kind(), ActionKind::Block))
        .collect();
    if !blocking_def_rules.is_empty() {
        // Resolve tool_id once per name from the per-tenant field-profile
        // registry so the rule evaluator can match `target: "tool_id"`. Tools
        // with no profile resolve to `None` and skip every tool_id rule —
        // the operator sees them as "unclassified" elsewhere.
        let field_profiles = field_profiles_arg;
        let resolve_tool_id = |name: &str| -> Option<String> {
            // Strip MCP namespace before resolving so `mcp__filesystem__read_file`
            // routes to the filesystem-server profile when the operator
            // declared one. Also try the tenant's virtual-prefix
            // index — when a declared tool is `gh__create_issue` and `gh` is
            // configured as an MCP virtual server prefix, resolve through
            // the upstream's profiles as if the call had arrived via MCP.
            let (effective, mcp_server) = match tool_rules::parse_mcp_namespace(name) {
                Some((srv, local)) => (local, Some(srv)),
                None => match mcp_config.and_then(|cfg| cfg.parse_virtual_namespace(name)) {
                    Some((local, srv)) => (local, Some(srv)),
                    None => (name, None),
                },
            };
            field_profiles
                .and_then(|set| set.resolve_tool_id(effective, app_id, mcp_server))
                .map(|s| s.to_string())
        };
        let find_block_rule = |name: &str| -> Option<&Rule> {
            let tool_id = resolve_tool_id(name);
            let resolver = ToolDefinitionResolver {
                tool_id: tool_id.as_deref(),
            };
            blocking_def_rules
                .iter()
                .copied()
                .find(|r| tool_rules::evaluate(r, &resolver))
        };
        // Each name's matching rule, recorded as the removal decides it, so the
        // notice and the audit below name the rule that removed it.
        let mut matched: std::collections::HashMap<String, &Rule> = std::collections::HashMap::new();
        let removed = request.remove_tools(|name| match find_block_rule(name) {
            Some(rule) => {
                matched.insert(name.to_string(), rule);
                true
            }
            None => false,
        });
        // A tool the client lists as deferred is not declared yet, so the
        // removal above cannot reach it: the notice names it too. Never in a
        // request that declares no tools, which offers the model nothing to
        // call. The answer refuses a call to any tool named here
        // (`TransformResult::withheld_tools`).
        let deferred: Vec<String> = match &*request {
            ApiRequest::AnthropicMessages(req) if !client_declared.is_empty() => req
                .deferred_tool_names()
                .into_iter()
                .filter(|name| {
                    !removed.contains(name)
                        && find_block_rule(name).inspect(|rule| {
                            matched.insert(name.clone(), rule);
                        }).is_some()
                })
                .collect(),
            _ => Vec::new(),
        };
        if !removed.is_empty() || !deferred.is_empty() {
            let mut notice =
                "\n\n[Tool Policy] The following tools have been blocked by your administrator:"
                    .to_string();
            for name in removed.iter().chain(&deferred) {
                // Every removed or deferred name was recorded with its rule
                // above, under the name the removal reports.
                let Some(rule) = matched.get(name).copied() else {
                    tracing::error!(tool = %name, "a tool removed by policy has no matching block rule");
                    continue;
                };
                let title = rule.title.as_deref().unwrap_or("Blocked by policy");
                let desc = rule.description.as_deref().unwrap_or("Blocked by policy");
                let rule_id = rule.id.clone();
                notice.push_str(&format!("\n- {name}: {desc}"));
                badges.add_tool_blocked(Phase::Request, name.clone());
                blocked_tools.push(crate::proxy::content::BlockedToolInfo {
                    not_applied: false,
                    name: name.clone(),
                    title: title.to_string(),
                    description: desc.to_string(),
                    rule_id,
                    tool_use_id: None,
                    call_index: None,
                    arguments: None,
                });
            }
            flags.tools_modified = true;
            request.append_system_prompt(&notice);

            if capture_diffs {
                let diff_text = removed
                    .iter()
                    .map(|n| format!("- Removed: {n}"))
                    .chain(deferred.iter().map(|n| format!("- Withheld: {n} (deferred)")))
                    .collect::<Vec<_>>()
                    .join("\n");
                step_diffs.push(TransformStepDiff {
                    name: "tool_policy".to_string(),
                    diff: format!("{diff_text}\n+ System prompt notice injected"),
                });
            }

            injection_blocks.push(crate::proxy::content::InjectionBlock {
                transform: "tool_policy".to_string(),
                scope: "system_prompt".to_string(),
                field: "system_prompt".to_string(),
                action: "append".to_string(),
                content: notice,
            });
            for content in removed.iter().cloned().chain(deferred.iter().map(|n| format!("{n} (deferred)"))) {
                injection_blocks.push(crate::proxy::content::InjectionBlock {
                    transform: "tool_policy".to_string(),
                    scope: "tools".to_string(),
                    field: "tools".to_string(),
                    action: "remove".to_string(),
                    content,
                });
            }
        }
    }

    // 0a-bis. Tool-definition substitution — `Substitute` / `InterceptOnly`
    //         rules at `Request × ToolDefinitions`. The substitute action
    //         wholesale replaces a matched tool definition with the canonical
    //         `web_search` / `web_fetch` shape (or any other ToolDefValue an
    //         operator authors), while `intercept_only` leaves the wire
    //         definition untouched. Both emit an `InterceptBinding` that
    //         tells the response-side agent loop to capture echoes of the
    //         substituted (or unchanged) tool name and route them through
    //         the bound intercept handler instead of forwarding to the
    //         client. The bindings list is the request → response contract.
    //
    //         At runtime: scoping (`model_filter`, `app_filter`,
    //         `is_builtin`, `enabled`) is enforced exactly like every other
    //         tool-policy rule via `extract_for`. Predicates evaluate
    //         against the per-tool resolved `tool_id` from the field-profile
    //         registry, so a single seed rule covers every client variant
    //         (Claude Code `WebFetch` and Cursor `web_fetch` and Cline
    //         `fetch` all canonicalise to `tool_id="web_fetch"`).
    let rewrite_rules: Vec<&Rule> = def_rules
        .iter()
        .copied()
        .filter(|r| matches!(
            r.action.kind(),
            ActionKind::Substitute | ActionKind::InterceptOnly
        ))
        .collect();
    if !rewrite_rules.is_empty() {
        // Per-tool rule lookup pivots on (name, server_type) — server-tools
        // canonicalise to `tool_id="web_search"` via the field-profile
        // ServerType tier, while function-tools fall back through Mcp / App /
        // Generic. Captured once and reused by the substitute + intercept_only
        // passes below.
        let resolve_for = |name: &str, server_type: Option<&str>| -> Option<String> {
            let (effective, mcp_server) = match tool_rules::parse_mcp_namespace(name) {
                Some((srv, local)) => (local, Some(srv)),
                None => match mcp_config.and_then(|cfg| cfg.parse_virtual_namespace(name)) {
                    Some((local, srv)) => (local, Some(srv)),
                    None => (name, None),
                },
            };
            field_profiles_arg
                .and_then(|set| {
                    set.resolve_tool_id_for_definition(effective, app_id, mcp_server, server_type)
                })
                .map(|m| m.tool_id)
        };
        let find_rewrite_rule = |name: &str, server_type: Option<&str>| -> Option<&Rule> {
            let tool_id = resolve_for(name, server_type);
            let resolver = ToolDefinitionResolver {
                tool_id: tool_id.as_deref(),
            };
            rewrite_rules
                .iter()
                .copied()
                .find(|r| tool_rules::evaluate(r, &resolver))
        };

        let tool_defs = request.tool_definitions_with_server_type();
        let mut name_to_rule: std::collections::HashMap<String, (&Rule, &RuleAction)> =
            std::collections::HashMap::new();
        // Capture the wire `server_type` per tool name so substitute/intercept_only
        // bindings can carry it as the visible-mode discriminator (server-tool
        // ⇒ visible, client-tool ⇒ invisible). Built from the same walk as
        // `name_to_rule` so it sees the pre-mutation tool list.
        let mut name_to_server_type: std::collections::HashMap<String, Option<String>> =
            std::collections::HashMap::new();
        for (name, server_type) in &tool_defs {
            if let Some(rule) = find_rewrite_rule(name, server_type.as_deref()) {
                name_to_rule.insert(name.clone(), (rule, &rule.action));
                name_to_server_type.insert(name.clone(), server_type.clone());
            }
        }

        // First pass: SUBSTITUTE. Wholesale-replace the tool def via the wire
        // mutation primitive on `ApiRequest`.
        let substitutions = request.substitute_tools(|name| {
            name_to_rule
                .get(name)
                .and_then(|(_, action)| match action {
                    RuleAction::Substitute { with, .. } => Some(with.clone()),
                    _ => None,
                })
        });
        rename_steps.push(substitutions.clone());
        for (original, replaced) in &substitutions {
            // `name_to_rule` was built from the same `tool_defs` walk that
            // `substitute_tools` mutated, so a hit must exist — but guard
            // defensively (e.g. if the closure logic above ever drifts) and
            // skip rather than panic on the request hot path.
            let Some((rule, action)) = name_to_rule.get(original).copied() else {
                tracing::warn!(
                    tool = %original,
                    "substitute_tools mutated a tool with no matching rule entry; skipping binding"
                );
                continue;
            };
            let RuleAction::Substitute { intercept, .. } = action else {
                tracing::warn!(
                    tool = %original,
                    "substitute_tools mutated a tool whose rule action is not Substitute; skipping binding"
                );
                continue;
            };
            let intercept = intercept.clone();
            let original_server_type = name_to_server_type
                .get(original)
                .cloned()
                .unwrap_or(None);
            intercept_bindings.push(crate::proxy::content::InterceptBinding {
                original_name: original.clone(),
                replaced_name: replaced.clone(),
                rule_id: rule.id.clone(),
                intercept,
                action: "substitute".to_string(),
                original_server_type,
            });
            injection_blocks.push(crate::proxy::content::InjectionBlock {
                transform: "tool_policy".to_string(),
                scope: "tools".to_string(),
                field: "tools".to_string(),
                action: "substitute".to_string(),
                content: format!("{original} → {replaced}"),
            });
            flags.tools_modified = true;
        }
        if capture_diffs && !substitutions.is_empty() {
            let diff_text = substitutions
                .iter()
                .map(|(o, n)| format!("- Substituted: {o} → {n}"))
                .collect::<Vec<_>>()
                .join("\n");
            step_diffs.push(TransformStepDiff {
                name: "tool_policy".to_string(),
                diff: diff_text,
            });
        }

        // Second pass: INTERCEPT_ONLY. Wire definition stays intact; only the
        // response-side handler is bound. No substitute_tools call needed —
        // emit the binding from the original name directly.
        for (name, server_type) in &tool_defs {
            if let Some((rule, action)) = name_to_rule.get(name).copied()
                && let RuleAction::InterceptOnly { handler } = action
            {
                intercept_bindings.push(crate::proxy::content::InterceptBinding {
                    original_name: name.clone(),
                    replaced_name: name.clone(),
                    rule_id: rule.id.clone(),
                    intercept: handler.clone(),
                    action: "intercept_only".to_string(),
                    original_server_type: server_type.clone(),
                });
            }
        }

        // Third pass: a tool the client lists as deferred and has not
        // declared yet (Claude Code declares one only once the model looks it
        // up) can still be called by name. A substitute rule matching it
        // declares the substitute, loaded, and binds the listed name, so a
        // call under either name runs through the gateway. Only a name the
        // client lists: a request that withheld the tool lists none. Never in
        // a request that declares no tools (it offers the model nothing to
        // call), nor for a name a block rule matches — a block wins over a
        // substitution, as on a declared tool, so a declared tool the block
        // removed is not brought back either.
        if let ApiRequest::AnthropicMessages(req) = request
            && !client_declared.is_empty()
        {
            for name in req.deferred_tool_names() {
                let tool_id = resolve_for(&name, None);
                let resolver = ToolDefinitionResolver { tool_id: tool_id.as_deref() };
                if blocking_def_rules.iter().any(|r| tool_rules::evaluate(r, &resolver)) {
                    continue;
                }
                let Some(rule) = find_rewrite_rule(&name, None) else { continue };
                let RuleAction::Substitute { with, intercept } = &rule.action else { continue };
                let tools = req.tools.get_or_insert_with(Vec::new);
                if tools.iter().any(|t| t.name == with.name) {
                    continue;
                }
                tools.push(crate::api::messages::AnthropicTool {
                    name: with.name.clone(),
                    description: with.description.clone(),
                    input_schema: Some(with.parameters.clone()),
                    cache_control: None,
                    extra: Default::default(),
                });
                intercept_bindings.push(crate::proxy::content::InterceptBinding {
                    original_name: name.clone(),
                    replaced_name: with.name.clone(),
                    rule_id: rule.id.clone(),
                    intercept: intercept.clone(),
                    action: "substitute".to_string(),
                    original_server_type: None,
                });
                injection_blocks.push(crate::proxy::content::InjectionBlock {
                    transform: "tool_policy".to_string(),
                    scope: "tools".to_string(),
                    field: "tools".to_string(),
                    action: "substitute".to_string(),
                    content: format!("{name} (deferred) → {}", with.name),
                });
                if capture_diffs {
                    step_diffs.push(TransformStepDiff {
                        name: "tool_policy".to_string(),
                        diff: format!("+ Declared: {} for the deferred {name}", with.name),
                    });
                }
                flags.tools_modified = true;
            }
        }
    }

    // 0b. Tool-result redaction — rewrite tool_result blocks on the request
    // side before Rhai and upstream forwarding. The unified evaluator walks
    // `phase=request, scope=tool_results, action=replace` rules and runs each
    // hit's `Replace` payload (regex + with, wholesale, or drop) against the
    // joined-text view of the result body. Rhai scripts running next see
    // already-redacted content. Matching is done by the per-protocol walker
    // in `ApiRequest::redact_tool_results`, which produces the
    // `(tool_name, tool_use_id, content_text)` triples that drive the
    // resolver — same code path for all four inbound protocols including
    // Gemini (no longer a silent no-op).
    let result_rules = tool_rules::extract_for(
        tool_rules,
        tool_rules::Phase::Request,
        Scope::ToolResults,
        tool_rules::RuleAxes {
            model: Some(&resolved_model),
            app_id,
            ..Default::default()
        },
    );
    let replace_result_rules: Vec<&Rule> = result_rules
        .iter()
        .copied()
        .filter(|r| matches!(r.action.kind(), ActionKind::Replace))
        .collect();
    if !replace_result_rules.is_empty() {
        let rules_for_walk = replace_result_rules.clone();
        let redactions = request.redact_tool_results(|name_hint, _id, content, args| {
            // Try each rule in order — stop at the first hit that produces
            // an actual rewrite (regex non-match returns None and lets a
            // later rule have a shot).
            let (effective_name, mcp_server) = match tool_rules::parse_mcp_namespace(name_hint) {
                Some((srv, local)) => (local, Some(srv)),
                None => (name_hint, None),
            };
            let tool_id = field_profiles_arg
                .and_then(|set| set.resolve_tool_id(effective_name, app_id, mcp_server))
                .map(|s| s.to_string());
            for rule in &rules_for_walk {
                let resolver = ToolResultResolver {
                    name: effective_name,
                    arguments: args,
                    content,
                    field_profiles: field_profiles_arg,
                    app_id,
                    mcp_server,
                    tool_id: tool_id.as_deref(),
                };
                if !tool_rules::evaluate(rule, &resolver) {
                    continue;
                }
                let new_content = match tool_rules::apply_replacement(&rule.action, content) {
                    Some(s) => s,
                    None => continue,
                };
                let title = rule
                    .title
                    .clone()
                    .unwrap_or_else(|| "Redacted by policy".to_string());
                let description = rule.description.clone().unwrap_or_else(|| {
                    "Tool result redacted by administrator policy".to_string()
                });
                return Some((new_content, title, description, rule.id.clone()));
            }
            None
        });
        if !redactions.is_empty() {
            // Redaction is a "content rewritten by a transform" event — use
            // the umbrella `Modified` badge. Per-rule detail lives in
            // `transform_diff.redacted_tool_results` + `injection_blocks[]`.
            badges.add_modified();
            flags.messages_modified = true;
            // Emit injection_blocks for each redaction so the audit UI surfaces
            // the change alongside existing transform records.
            for info in &redactions {
                injection_blocks.push(crate::proxy::content::InjectionBlock {
                    transform: "tool_result_redact".to_string(),
                    scope: "messages".to_string(),
                    field: format!("tool_result[{}]", info.tool_use_id),
                    action: "redact".to_string(),
                    content: format!(
                        "{} → {}",
                        preview(&info.original_content, 80),
                        preview(&info.redacted_content, 80)
                    ),
                });
            }
            if capture_diffs {
                let diff_text = redactions
                    .iter()
                    .map(|r| {
                        format!(
                            "- {} ({}): {} → {}",
                            r.tool_name.as_deref().unwrap_or("?"),
                            r.rule_name,
                            preview(&r.original_content, 60),
                            preview(&r.redacted_content, 60)
                        )
                    })
                    .collect::<Vec<_>>()
                    .join("\n");
                step_diffs.push(TransformStepDiff {
                    name: "tool_result_redact".to_string(),
                    diff: diff_text,
                });
            }
            redacted_tool_results.extend(redactions);
        }
    }

    // Model alias for script filtering (original name before routing resolved the upstream).
    let requested_model = request.model().to_string();

    // 1. Rhai script chain (if any program runs on this request). The
    // projection converts the conversation only when a running program reads
    // it: a chain of `tools` and `system_prompt` programs is handed a context
    // without the conversation's messages, so a long history is not converted
    // on every request for it.
    let running: Vec<&TransformProgram> = active_programs
        .iter()
        .filter(|p| p.runs_on_request(Some(&requested_model), app_id))
        .collect();
    if !running.is_empty() {
        // Tool defs the request-phase Substitute pass rewrote — wire-side
        // tool name is now the *replaced* name. Pass through to the Rhai
        // projection so scripts can gate on `tool.is_gateway_substituted`
        // instead of inferring from schema presence.
        let substituted_tool_names: std::collections::HashSet<String> = intercept_bindings
            .iter()
            .filter(|b| b.action == "substitute")
            .map(|b| b.replaced_name.clone())
            .collect();
        let project = if running.iter().any(|p| p.reads_conversation()) {
            context::from_api_request
        } else {
            context::without_conversation
        };
        let ctx = project(
            request,
            user,
            app_id,
            context_window,
            upstream_provider,
            needs_translation,
            &substituted_tool_names,
        );

        // Snapshot Rhai messages before script execution to detect actual changes.
        // The domain conversion may produce more messages than the native request
        // (e.g. Anthropic ToolResult splitting), so we compare against the Rhai
        // projection — not the native count — to avoid spurious diffs.
        // Include tool_calls in the snapshot so scripts that mutate only the
        // `tool_calls` array (drop/rename/rewrite args) still trigger message sync.
        let snapshot_msgs = |msgs: &[crate::scripting::context::RhaiMessage]| {
            msgs.iter()
                .map(|m| {
                    let tcs: Vec<(String, String, String)> = m
                        .tool_calls
                        .iter()
                        .map(|t| (t.id.clone(), t.name.clone(), t.arguments_json.clone()))
                        .collect();
                    (m.role.clone(), m.content.clone(), tcs)
                })
                .collect::<Vec<_>>()
        };
        let original_msg_snapshot = snapshot_msgs(&ctx.messages);
        let original_system_prompt = ctx.system_prompt.clone();
        let original_tools = ctx.tools.clone();

        let (modified_ctx, script_program_outcomes, script_step_diffs, script_injection_blocks) =
            script_engine.execute_chain(active_programs, ctx, capture_diffs, Some(&requested_model), rhai_fail_mode)?;

        let changed = context::ChangedFields {
            system_prompt: modified_ctx.system_prompt != original_system_prompt,
            messages: snapshot_msgs(&modified_ctx.messages) != original_msg_snapshot,
            tools: modified_ctx.tools != original_tools,
        };

        // Apply modifications back to the request
        // A script edits the tool list as a whole and keeps no identity, so
        // a tool in the same place, the same in all but a name no tool had
        // before, is read as renamed: a reference follows it rather than
        // being dropped as a removal. Anything else that changed name is a
        // removal, so a reference never lands on a different tool.
        if changed.tools && modified_ctx.tools.len() == original_tools.len() {
            rename_steps.push(
                original_tools
                    .iter()
                    .zip(&modified_ctx.tools)
                    .filter(|(before, after)| {
                        before.name != after.name
                            && !original_tools.iter().any(|t| t.name == after.name)
                            && before.description == after.description
                            && before.parameters_json == after.parameters_json
                            && before.kind == after.kind
                            && before.config_json == after.config_json
                    })
                    .map(|(before, after)| (before.name.clone(), after.name.clone()))
                    .collect(),
            );
        }
        let change_descriptions = context::apply_to_api_request(&modified_ctx, request, changed);

        // Convert per-program outcomes into ScriptError badges (errored-only)
        // and accumulate them in `program_outcomes` for the trace viewer.
        for outcome in &script_program_outcomes {
            if matches!(outcome.outcome, TransformProgramOutcome::Errored) {
                badges.add_script_error(Phase::Request, outcome.name.clone());
            }
        }
        program_outcomes.extend(script_program_outcomes);
        step_diffs.extend(script_step_diffs);
        injection_blocks.extend(script_injection_blocks);

        // Translate ctx-level change descriptions into typed flags.
        for change in change_descriptions {
            match change.as_str() {
                "system_prompt" | "system_prompt_removed" => flags.system_prompt_modified = true,
                "tools" => flags.tools_modified = true,
                c if c.starts_with("message") => flags.messages_modified = true,
                _ => {}
            }
        }

        // Check if compression was applied (for session detection)
        if modified_ctx
            .metadata
            .get("compression")
            .is_some_and(|v| v == "applied")
        {
            flags.compression_applied = true;
            badges.add_compressed();
        }
    }

    // 2. Inject stream_options.include_usage for streaming ChatCompletions.
    // Internal-only — not surfaced as a badge (operator-irrelevant).
    if request.is_streaming()
        && let ApiRequest::ChatCompletions(req) = request
    {
        req.stream_options = Some(serde_json::json!({"include_usage": true}));
    }

    // 3. Sanitize request (tool names, etc.)
    let sanitize_result =
        super::sanitize::sanitize_request(request, sanitize_tool_names, capture_diffs);
    if sanitize_result.renamed_count > 0 {
        badges.add_sanitized_tool_names(sanitize_result.renamed_count);
        flags.tools_modified = true;
    }
    if let Some(diff) = sanitize_result.step_diff {
        step_diffs.push(diff);
    }
    // Capture tool name renames as injection blocks
    for (original, sanitized) in &sanitize_result.renames {
        injection_blocks.push(crate::proxy::content::InjectionBlock {
            transform: "sanitize_tool_names".to_string(),
            scope: "tools".to_string(),
            field: "tools".to_string(),
            action: "rename".to_string(),
            content: format!("{original} → {sanitized}"),
        });
    }

    // Re-validate intercept bindings against the post-Rhai / post-sanitize tool
    // set. Rules earlier in this function may have emitted a binding whose
    // `replaced_name` was the wire name at that moment; subsequent steps (Rhai
    // scripts removing or renaming a tool def, sanitize_tool_names rewriting
    // the wire name) can leave the binding pointing at a name the upstream
    // will never echo, breaking the substitution invariant. Three adjustments:
    // (1) apply sanitize_request's known rename map to bindings — single-pass
    // lookup via a HashMap, so a `(a,b),(b,c)` rename list can't chain a
    // binding from `a` through `b` to `c`; (2) drop any binding whose
    // `replaced_name` no longer appears in the request's tool set (Rhai
    // removal or rename-without-mapping); (3) when sanitize collapses two
    // distinct wire names onto the same sanitized form, the second binding
    // would be silently shadowed by `intercept_binding_for`'s first-match
    // lookup — dedup on `replaced_name` and drop the later-positioned ones
    // with a `post_rewrite_collision` reason. Each drop emits one
    // `InjectionBlock` so audit surfaces *which* call was orphaned/shadowed
    // rather than silently letting the upstream's echo flow to the client.
    if !intercept_bindings.is_empty() {
        let rename_map: std::collections::HashMap<&str, &str> = sanitize_result
            .renames
            .iter()
            .map(|(o, s)| (o.as_str(), s.as_str()))
            .collect();
        for binding in &mut intercept_bindings {
            if let Some(sanitized) = rename_map.get(binding.replaced_name.as_str()) {
                binding.replaced_name = (*sanitized).to_string();
            }
        }
        let current_tool_names: std::collections::HashSet<String> = request
            .tool_definitions_with_server_type()
            .into_iter()
            .map(|(name, _)| name)
            .collect();
        // Pass 1: drop orphans (binding's `replaced_name` no longer in wire).
        let mut dropped: Vec<(crate::proxy::content::InterceptBinding, &'static str)> = Vec::new();
        intercept_bindings.retain(|b| {
            if current_tool_names.contains(&b.replaced_name) {
                true
            } else {
                dropped.push((b.clone(), "post_rewrite_orphan"));
                false
            }
        });
        // Pass 2: dedup on `replaced_name` — keep the first occurrence,
        // drop the rest with `post_rewrite_collision`. `intercept_binding_for`
        // returns the first match, so a shadowed binding is silently
        // unreachable; surface it in audit.
        let mut seen: std::collections::HashSet<String> = std::collections::HashSet::new();
        intercept_bindings.retain(|b| {
            if seen.insert(b.replaced_name.clone()) {
                true
            } else {
                dropped.push((b.clone(), "post_rewrite_collision"));
                false
            }
        });
        for (b, reason) in &dropped {
            tracing::warn!(
                original = %b.original_name,
                replaced = %b.replaced_name,
                rule_id = ?b.rule_id,
                binding_action = %b.action,
                reason = %reason,
                tool_count = current_tool_names.len(),
                "intercept binding dropped by post-emission revalidation"
            );
            let payload = serde_json::json!({
                "original_name": b.original_name,
                "replaced_name": b.replaced_name,
                "rule_id": b.rule_id,
                "binding_action": b.action,
                "reason": reason,
            });
            injection_blocks.push(crate::proxy::content::InjectionBlock {
                transform: "tool_policy".to_string(),
                scope: "tools".to_string(),
                field: "intercept_binding".to_string(),
                action: "drop".to_string(),
                content: payload.to_string(),
            });
        }
    }

    // 4. The history's tool references, against the tools as now declared:
    //    one pass, after every step that renames or removes a declaration.
    rename_steps.push(sanitize_result.renames.clone());
    for edit in retarget_tool_references(request, &client_declared, &rename_steps) {
        let (action, content, diff) = match &edit.renamed_to {
            Some(to) => ("rename", format!("{} → {to}", edit.name), format!("~ Tool reference: {} → {to}", edit.name)),
            None => ("remove", edit.name.clone(), format!("- Tool reference: {}", edit.name)),
        };
        injection_blocks.push(crate::proxy::content::InjectionBlock {
            transform: "tool_policy".to_string(),
            scope: "messages".to_string(),
            field: "tool_reference".to_string(),
            action: action.to_string(),
            content,
        });
        if capture_diffs {
            step_diffs.push(TransformStepDiff { name: "tool_policy".to_string(), diff });
        }
        flags.messages_modified = true;
    }

    // Emit unified Modified badge once if any setter recorded a content change
    // through `injection_blocks`.
    if !injection_blocks.is_empty() {
        badges.add_modified();
    }

    let declared: Vec<String> =
        request.tool_definitions_with_server_type().into_iter().map(|(name, _)| name).collect();
    let withheld_tools =
        blocked_tools.iter().filter(|b| !declared.contains(&b.name)).cloned().collect();

    Ok(TransformResult {
        badges,
        program_outcomes,
        flags,
        step_diffs: if capture_diffs && !step_diffs.is_empty() {
            Some(step_diffs)
        } else {
            None
        },
        injection_blocks,
        blocked_tools,
        withheld_tools,
        redacted_tool_results,
        intercept_bindings,
    })
}

/// The tools an Anthropic request declares, by name; empty on any other
/// protocol, which carries no `tool_reference`.
fn anthropic_declared_names(request: &ApiRequest) -> std::collections::HashSet<String> {
    match request {
        ApiRequest::AnthropicMessages(req) => req.tools.iter().flatten().map(|t| t.name.clone()).collect(),
        _ => std::collections::HashSet::new(),
    }
}

/// Point the history's `tool_reference`s at the tools as declared now. A name
/// still declared, or one the client never declared (its own reference, not
/// the gateway's to repair), is kept; any other follows `rename_steps` — one
/// lookup per step, so `(a, b), (b, c)` within one step does not chain — to
/// the name it is declared under, or is removed when it is declared under none.
fn retarget_tool_references(
    request: &mut ApiRequest,
    client_declared: &std::collections::HashSet<String>,
    rename_steps: &[Vec<(String, String)>],
) -> Vec<crate::api::messages::ReferenceEdit> {
    use crate::api::messages::ReferenceFate;
    let declared = anthropic_declared_names(request);
    let ApiRequest::AnthropicMessages(req) = request else { return Vec::new() };
    if client_declared.is_subset(&declared) {
        return Vec::new();
    }
    let steps: Vec<std::collections::HashMap<&str, &str>> = rename_steps
        .iter()
        .map(|step| step.iter().map(|(from, to)| (from.as_str(), to.as_str())).collect())
        .collect();
    req.retarget_tool_references(
        |name| {
            if declared.contains(name) || !client_declared.contains(name) {
                return ReferenceFate::Keep;
            }
            let now = steps.iter().fold(name, |n, step| step.get(n).copied().unwrap_or(n));
            if now != name && declared.contains(now) {
                ReferenceFate::Rename(now.to_string())
            } else {
                ReferenceFate::Remove
            }
        },
        |removed| {
            format!(
                "[Tool Policy] No longer available, so not loaded: {}.",
                removed.join(", ")
            )
        },
    )
}

/// Outcome of the inbound-prompt guardrail hop ([`scan_inbound_request`]).
pub struct InboundGuardrailOutcome {
    /// Audit badges to merge onto the request-side row — a `Guardrail`
    /// aggregate when content flagged, and/or a `GuardrailError` on a detector
    /// outage. Empty when the hop was inert or nothing flagged.
    pub badges: Vec<crate::audit::badge::AuditBadge>,
    /// Whether enforce mode mutated the request (a flagged input was replaced
    /// with a placeholder). The caller stamps a `Modified` chip when set.
    pub messages_modified: bool,
    /// One trace step per flagged/errored inbound message, anchored by the
    /// **domain message index** (`tool_use_id`) so the session / audit trace can
    /// render a guardrail banner on the exact flagged message. Empty when the
    /// hop was inert or every input scanned clean.
    pub steps: Vec<crate::proxy::content::GuardrailStepDiff>,
}

/// How many texts one inbound classifier round-trip carries.
const INBOUND_BATCH: usize = 32;

/// How many inbound classifier round-trips one request has in flight.
const INBOUND_BATCHES_IN_FLIGHT: usize = 4;

/// How many bytes of text the in-process PII detector reads on the request's
/// own worker; more runs on a blocking thread.
const PII_INLINE_BYTES: usize = 64 * 1024;

/// Inbound-prompt guardrail — the request-phase injection classifier hop
/// (P1/P2, the sibling of the web surface in
/// [`response_pipeline`](crate::pipeline::response_pipeline)) and the PII hop
/// (P5).
///
/// Screens the conversation's untrusted text — the user's messages (P2: direct
/// injection / jailbreak; P5: the user's own data leaving) and the tool-result
/// content the client folds in (P1: indirect injection via RAG / tool output,
/// the output of a Responses built-in tool the client ran included) —
/// through the same classifier transport ([`crate::guardrail::run_observe`] /
/// [`run_enforce`](crate::guardrail::run_enforce)) the web surface uses. The
/// injection pass runs only when the guardrail
/// [`is_active`](crate::guardrail::GuardrailSettings::is_active) **and** the
/// opt-in `scan_inbound` flag is set, the PII pass when PII request scanning
/// is on.
///
/// **What is screened.** Every message the hop has not screened before,
/// wherever it sits — a client resends its whole conversation, and only the
/// record of what was screened ([`crate::guardrail::screened`], keyed by
/// `screen_keys`, one per conversation item) decides what is new; nothing the
/// client controls in the conversation's shape does. The items from the first
/// unscreened one on are converted ([`context::scan_messages`]); the history
/// before it is not. An item an enforce check edited is recorded with what it
/// wrote, and the client's own copy of it, sent back as history, goes out with
/// that edit written again, not read again. `screen_keys` is `None` when no
/// key names the items as they now stand, and every item is screened.
///
/// **Observe** mode badges only — content is untouched. **Enforce** mode
/// replaces a flagged input (injection) with a placeholder, or masks it (PII),
/// before the request is forwarded; `fail_mode` decides detector-outage
/// behaviour — identical semantics to the web hop, shared via
/// [`crate::guardrail::run_enforce`]. Runs before the forward — the verdict
/// must settle so enforce can strip; the classifier reads the texts in batches
/// of `INBOUND_BATCH`, `INBOUND_BATCHES_IN_FLIGHT` at a time over a warm
/// keep-alive client, each round bounded by `timeout_ms` — one round for the
/// new messages of a request, a few for a conversation screened whole.
pub async fn scan_inbound_request(
    request: &mut ApiRequest,
    guardrail: &crate::guardrail::GuardrailSettings,
    tenant: uuid::Uuid,
    conversation: Option<uuid::Uuid>,
    screen_keys: Option<&[String]>,
) -> Result<InboundGuardrailOutcome, AppError> {
    use crate::guardrail::{screened, GuardrailFailMode, GuardrailInput, GuardrailSurface};
    use crate::proxy::content::GuardrailStepOutcome;
    use futures::StreamExt;

    let mut out = InboundGuardrailOutcome {
        badges: Vec::new(),
        messages_modified: false,
        steps: Vec::new(),
    };
    // Injection (P1/P2 — folded tool-results + the user's messages) and PII
    // (P5 — the user's own messages, DLP egress) are gated independently: a
    // tenant can run either, both, or neither. The introspection agent analyses
    // tenant conversations that may legitimately *contain* an injection or PII —
    // screening (and in enforce, mutating) its prompts would corrupt that
    // analysis. The agent gets this for free: its Agent workspace assigns
    // guardrail = Off, so the resolved `guardrail` here is inert (both flags
    // below false) and the request returns un-screened — governed by workspace
    // policy, not a special-cased identity bypass.
    let injection_on = guardrail.is_active() && guardrail.scan_inbound;
    let pii_on = guardrail.pii.enabled && guardrail.pii.scan_request;
    if !guardrail.screens_inbound() {
        return Ok(out);
    }

    let items = crate::api::domain_request::DomainRequest::conversation_len(request);
    let keys = screen_keys.filter(|k| k.len() == items);
    let fingerprint = screened::fingerprint(guardrail);
    let protocol = request.api_version().as_str();
    let mut verdicts: Vec<Option<std::sync::Arc<screened::Screened>>> = Vec::with_capacity(items);
    for item in 0..items {
        verdicts.push(match keys {
            Some(k) => screened::get(tenant, &fingerprint, protocol, &k[item], conversation).await,
            None => None,
        });
    }
    // An item screened and edited before is edited again — the client sends
    // back its own original — with the badges its edit carries.
    // (The request's badges are merged into one per kind where the row is
    // built.)
    for (item, verdict) in verdicts.iter().enumerate() {
        if let Some(screened) = verdict.as_deref() {
            for (part, text) in &screened.texts {
                context::set_item_text(request, item, *part, text);
            }
            out.badges.extend(screened.badges.iter().cloned());
            out.messages_modified |= !screened.texts.is_empty();
        }
    }
    let Some(start) = verdicts.iter().position(Option::is_none) else {
        return Ok(out);
    };
    let is_screened = |item: usize| verdicts[item].is_some();
    let closed = |mode: &GuardrailFailMode| matches!(mode, GuardrailFailMode::Closed);
    let Some(mut messages) = context::scan_messages(request, start) else {
        // The conversation cannot be read message by message: a detector that
        // read nothing, as its fail mode says.
        tracing::warn!("the inbound guardrail could not pair the conversation's messages with its items — not screened");
        // The PII check, in process, has no fail mode of its own: it fails
        // open.
        if injection_on && guardrail.enforces() && closed(&guardrail.fail_mode) {
            return Err(AppError::Internal("the inbound guardrail could not read the request".to_string()));
        }
        out.badges.push(crate::audit::badge::AuditBadge::GuardrailError { reason: "unreadable".to_string() });
        return Ok(out);
    };
    // A message of an item screened before is not screened again.
    let unscreened = |m: &context::ScanMessage| !is_screened(m.item);

    // A recorded step is anchored by its **reverse** index — distance from the
    // end of the system-free domain message list — not by a forward one. The
    // admin's session-conversation view rebuilds each turn from a
    // dedup-filtered message subset (leading history + response echoes
    // dropped), so a forward index would point at the wrong row there; a
    // message's distance from the end survives that filtering and resolves
    // correctly in both the full single-turn trace and the filtered session
    // view. An input's id is its index in `messages`. INVARIANT: keep this
    // reverse-anchor in lockstep with the `n - 1 - reverse` resolution in
    // `build_events`.
    // A finding about a tool output held in an assistant turn also names the
    // call it answers: that turn may hold several.
    let anchors: Vec<(usize, Option<String>)> = messages.iter().map(|m| (m.reverse, m.held_call.clone())).collect();
    let to_reverse = |steps: Vec<crate::proxy::content::GuardrailStepDiff>| {
        steps
            .into_iter()
            .map(|mut s| {
                if let Some((r, held_call)) = s.tool_use_id.parse::<usize>().ok().and_then(|i| anchors.get(i)) {
                    s.tool_use_id = r.to_string();
                    s.call_id.clone_from(held_call);
                }
                s
            })
            .collect::<Vec<_>>()
    };
    // Each step by the message it is about — what decides what is recorded.
    let mut steps_of: std::collections::HashMap<usize, Vec<crate::proxy::content::GuardrailStepDiff>> =
        std::collections::HashMap::new();
    let mut note = |steps: &[crate::proxy::content::GuardrailStepDiff]| {
        for s in steps {
            if let Ok(i) = s.tool_use_id.parse::<usize>() {
                steps_of.entry(i).or_default().push(s.clone());
            }
        }
    };
    // The messages a detector failed on as a batch — read by nothing.
    let mut failed: std::collections::HashSet<usize> = std::collections::HashSet::new();
    let mut failed_batch = |batch: &[GuardrailInput]| {
        failed.extend(batch.iter().filter_map(|inp| inp.id.parse::<usize>().ok()));
    };
    let mut edited: Vec<usize> = Vec::new();

    // --- Injection pass (P1/P2) — the user's messages + folded tool-results. ---
    if injection_on {
        // One classifier input per untrusted text, `id` = its index in
        // `messages` so an enforce strip maps back to its item. On the single
        // `Inbound` surface, in batches of `INBOUND_BATCH` — a conversation
        // screened whole for the first time is many inputs, each batch one
        // round-trip under the detector timeout.
        let inputs: Vec<GuardrailInput> = messages
            .iter()
            .enumerate()
            .filter(|(_, m)| unscreened(m) && !m.message.content.trim().is_empty())
            .map(|(i, m)| GuardrailInput { id: i.to_string(), classifiable: m.message.content.clone(), target: String::new() })
            .collect();
        // The batches run `INBOUND_BATCHES_IN_FLIGHT` at a time: a conversation
        // screened whole waits a few detector round-trips, not one per batch,
        // and asks the detector for no more than that at once.
        let batches: Vec<&[GuardrailInput]> = inputs.chunks(INBOUND_BATCH).collect();
        // A check on whose settings no classifier can be built reads nothing:
        // what it was to read is not recorded as screened.
        if crate::guardrail::ClassifierConfig::from_settings(guardrail).is_none() {
            for batch in &batches {
                failed_batch(batch);
            }
        }
        if guardrail.enforces() {
            let calls: Vec<_> =
                batches.iter().map(|batch| crate::guardrail::run_enforce(guardrail, batch, GuardrailSurface::Inbound)).collect();
            let outcomes: Vec<_> = futures::stream::iter(calls).buffered(INBOUND_BATCHES_IN_FLIGHT).collect().await;
            // A failed enforce batch gives each input an error or withhold
            // step, which the record reads as a failure.
            for eo in outcomes.into_iter().flatten() {
                // Replace each withheld input's content with its placeholder
                // before the forward.
                for (id, placeholder) in &eo.strips {
                    if let Ok(i) = id.parse::<usize>()
                        && let Some(m) = messages.get_mut(i)
                    {
                        m.message.content = placeholder.clone();
                        edited.push(i);
                    }
                }
                note(&eo.steps);
                out.steps.extend(to_reverse(eo.steps));
                out.badges.extend(eo.badges);
            }
        } else {
            let calls: Vec<_> =
                batches.iter().map(|batch| crate::guardrail::run_observe(guardrail, batch, GuardrailSurface::Inbound)).collect();
            let outcomes: Vec<_> = futures::stream::iter(calls).buffered(INBOUND_BATCHES_IN_FLIGHT).collect().await;
            for (batch, outcome) in batches.iter().zip(outcomes) {
                // No outcome is a clean batch.
                let Some(oo) = outcome else { continue };
                // A batch the detector failed on whole says so with a failure
                // badge and no step: nothing in it was read.
                if oo.steps.is_empty()
                    && oo.badges.iter().any(|b| matches!(b, crate::audit::badge::AuditBadge::GuardrailError { .. }))
                {
                    failed_batch(batch);
                }
                note(&oo.steps);
                out.steps.extend(to_reverse(oo.steps));
                out.badges.extend(oo.badges);
            }
        }
    }

    // --- PII pass (P5 — DLP egress). Scans ONLY the user's own messages, never
    // folded tool-results / RAG (those are third-party content, not the user's
    // data leaving the tenant). Framework-injected volatile blocks inside a
    // message (Claude Code's `<system-reminder>`, etc.) are excluded — the user
    // did not author them, so PII there is not their disclosure (the exclusion
    // is offset-aware, so prose PII still redacts while the injected block is
    // forwarded intact). Reads `messages` after the injection pass, so a
    // message the injection hop already withheld scans as its placeholder (no
    // PII) rather than the original. ---
    if pii_on {
        let inputs: Vec<GuardrailInput> = messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.message.role == "user" && unscreened(m) && !m.message.content.trim().is_empty())
            .map(|(i, m)| GuardrailInput { id: i.to_string(), classifiable: m.message.content.clone(), target: String::new() })
            .collect();
        if !inputs.is_empty() {
            // The detector runs in this process: a large read — a conversation
            // screened whole — runs off the async workers.
            let ids: Vec<usize> = inputs.iter().filter_map(|inp| inp.id.parse().ok()).collect();
            let large = inputs.iter().map(|inp| inp.classifiable.len()).sum::<usize>() > PII_INLINE_BYTES;
            let pii = guardrail.pii.clone();
            let enforces = pii.enforces();
            let run = move || {
                if enforces {
                    (crate::guardrail::run_pii_enforce(&pii, &inputs, GuardrailSurface::Inbound), None)
                } else {
                    (None, crate::guardrail::run_pii_observe(&pii, &inputs, GuardrailSurface::Inbound))
                }
            };
            let outcome = if large {
                match tokio::task::spawn_blocking(run).await {
                    Ok(outcome) => Some(outcome),
                    Err(e) => {
                        tracing::warn!(error = %e, "the PII detector did not finish — its inputs are not screened");
                        None
                    }
                }
            } else {
                Some(run())
            };
            match outcome {
                None => {
                    failed.extend(ids);
                    out.badges.push(crate::audit::badge::AuditBadge::GuardrailError { reason: "pii_unfinished".to_string() });
                }
                Some((Some(eo), _)) => {
                    for (id, redacted) in &eo.redactions {
                        if let Ok(i) = id.parse::<usize>()
                            && let Some(m) = messages.get_mut(i)
                        {
                            m.message.content = redacted.clone();
                            edited.push(i);
                        }
                    }
                    note(&eo.steps);
                    out.steps.extend(to_reverse(eo.steps));
                    out.badges.extend(eo.badges);
                }
                Some((None, Some(oo))) => {
                    note(&oo.steps);
                    out.steps.extend(to_reverse(oo.steps));
                    out.badges.extend(oo.badges);
                }
                Some((None, None)) => {}
            }
        }
    }

    // Each edited text lands on the item it came from; the rest of the request
    // goes out as sent.
    edited.sort_unstable();
    edited.dedup();
    for &i in &edited {
        let m = &messages[i];
        context::set_item_text(request, m.item, m.part, &m.message.content);
    }
    out.messages_modified |= !edited.is_empty();

    // Record each item from `start` on that was not screened before, to its
    // verdict — clean, or the texts an enforce check wrote, with the badge
    // the steps that edited it make — but one a detector failed on, alone or
    // with its batch.
    if let Some(keys) = keys {
        let mut by_item: std::collections::BTreeMap<usize, Vec<usize>> = std::collections::BTreeMap::new();
        for (i, m) in messages.iter().enumerate() {
            by_item.entry(m.item).or_default().push(i);
        }
        for (item, key) in keys.iter().enumerate().skip(start) {
            if is_screened(item) {
                continue;
            }
            let of_item = by_item.get(&item).map(Vec::as_slice).unwrap_or_default();
            let steps: Vec<&crate::proxy::content::GuardrailStepDiff> =
                of_item.iter().filter_map(|i| steps_of.get(i)).flatten().collect();
            // A step with no verdict — an error, or a closed-mode withhold of
            // what the detector could not read — is a failure, not an edit to
            // keep; but an incomplete scan (a text past the detector's window
            // budget) is the same every time, and is recorded as it came out.
            let incomplete = |s: &&crate::proxy::content::GuardrailStepDiff| {
                s.error.as_deref() == Some(crate::guardrail::INCOMPLETE_SCAN_REASON)
            };
            if of_item.iter().any(|i| failed.contains(i))
                || steps.iter().any(|s| {
                    !incomplete(s) && (matches!(s.outcome, GuardrailStepOutcome::Error) || s.category.is_none())
                })
            {
                continue;
            }
            let texts: Vec<(usize, String)> = of_item
                .iter()
                .filter(|i| edited.contains(i))
                .map(|&i| (messages[i].part, messages[i].message.content.clone()))
                .collect();
            // The badges every later request carrying the item carries again:
            // the edits' finding, and an incomplete scan's — what was not read
            // stays visible. An observe finding was recorded once, on the
            // request it was first seen in.
            let edits: Vec<_> = steps.iter().filter(|s| matches!(s.outcome, GuardrailStepOutcome::Blocked)).collect();
            let mut categories: Vec<crate::guardrail::GuardrailCategory> = Vec::new();
            for c in edits.iter().filter_map(|s| s.category) {
                if !categories.contains(&c) {
                    categories.push(c);
                }
            }
            let max_confidence = edits.iter().filter_map(|s| s.confidence).fold(0.0f32, f32::max);
            let mut badges = Vec::new();
            if !texts.is_empty() && !categories.is_empty() {
                badges.push(crate::audit::badge::AuditBadge::Guardrail {
                    categories,
                    max_confidence,
                    action: crate::audit::badge::GuardrailAction::Block,
                });
            }
            if steps.iter().any(incomplete) {
                badges.push(crate::audit::badge::AuditBadge::GuardrailError {
                    reason: crate::guardrail::INCOMPLETE_SCAN_REASON.to_string(),
                });
            }
            let verdict = screened::Screened { texts, badges, found: !steps.is_empty() };
            screened::record(tenant, &fingerprint, protocol, key, conversation, verdict).await;
        }
    }

    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::{RateLimitConfig, UserContext};
    use crate::config::model_map::ModelMap;
    use crate::scripting::ScriptEngine;
    use bytes::Bytes;

    fn make_user_context_with_map(model_map: ModelMap) -> UserContext {
        UserContext {
            inline_ai: false,
            qos_class_id: None,
            qos_class_elevated: false,
            user_id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            email: None,
            display_name: None,
            real_api_key: "sk-key".to_string(),
            model_map: model_map.into(),
            rate_limit: RateLimitConfig::default(),
            user_rate_override: None,
            key_budget: None,
            tenant_budget: None,
            expires_at: None,
            key_id: None,
            app_id: None,
            session_id: None,
            workspace_id: uuid::Uuid::nil(),
            allowed_provider_ids: Vec::new(),
            allowed_virtual_server_ids: Vec::new(),
            allowed_a2a_agent_ids: Vec::new(),
            mcp_scope: None,
            forward_auth: false,
            byok_passthrough: Vec::new(),
        }
    }

    fn make_chat_request(model: &str, stream: bool) -> ApiRequest {
        let json = format!(
            r#"{{"model":"{model}","messages":[{{"role":"user","content":"hello"}}],"stream":{stream}}}"#
        );
        ApiRequest::parse(
            crate::api::sse::ApiVersion::ChatCompletions,
            &Bytes::from(json),
        )
        .unwrap()
    }

    fn empty_engine_and_programs() -> (ScriptEngine, Vec<TransformProgram>) {
        (ScriptEngine::new(), vec![])
    }

    /// The client's `priority` / `kv_transfer_params` never survive the request
    /// phase on any protocol that keeps unknown fields, the removal is recorded,
    /// and an engine extra the client may set (`chat_template_kwargs`) still
    /// travels — the positive control.
    #[tokio::test]
    async fn gateway_owned_fields_are_removed_on_every_protocol() {
        use crate::api::sse::ApiVersion;
        let cases = [
            (ApiVersion::ChatCompletions, r#"{"model":"m","messages":[{"role":"user","content":"hi"}],"priority":-100,"kv_transfer_params":{"remote_host":"10.0.0.9"},"chat_template_kwargs":{"enable_thinking":false}}"#),
            (ApiVersion::Responses, r#"{"model":"m","input":"hi","priority":-100,"kv_transfer_params":{"remote_host":"10.0.0.9"},"chat_template_kwargs":{"enable_thinking":false}}"#),
            (ApiVersion::AnthropicMessages, r#"{"model":"m","max_tokens":16,"messages":[{"role":"user","content":"hi"}],"priority":-100,"kv_transfer_params":{"remote_host":"10.0.0.9"},"chat_template_kwargs":{"enable_thinking":false}}"#),
        ];
        let user = make_user_context_with_map(ModelMap::default());
        let (engine, programs) = empty_engine_and_programs();
        for (version, body) in cases {
            let mut request = ApiRequest::parse(version, &Bytes::from(body)).unwrap();
            let result = transform_request(&mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, true, ScriptFailMode::Open)
                .await
                .unwrap();
            let wire = match &request {
                ApiRequest::ChatCompletions(r) => serde_json::to_value(r).unwrap(),
                ApiRequest::Responses(r) => serde_json::to_value(r).unwrap(),
                ApiRequest::AnthropicMessages(r) => serde_json::to_value(r).unwrap(),
                ApiRequest::GoogleGemini(r) => serde_json::to_value(r).unwrap(),
            };
            assert!(wire.get("priority").is_none(), "{version:?}: {wire}");
            assert!(wire.get("kv_transfer_params").is_none(), "{version:?}: {wire}");
            assert_eq!(wire["chat_template_kwargs"]["enable_thinking"], false, "{version:?}");
            let removed: Vec<&str> = result
                .injection_blocks
                .iter()
                .filter(|b| b.transform == "gateway_owned_field")
                .map(|b| b.field.as_str())
                .collect();
            assert_eq!(removed, vec!["priority", "kv_transfer_params"], "{version:?}");
            assert!(result.badges.is_modified(), "{version:?}");
        }
    }

    /// A client `priority` does not fragment the response cache: once removed,
    /// the request's cache key equals the same request sent without it (the
    /// identity half reads nothing of the request).
    #[tokio::test]
    async fn a_client_priority_does_not_change_the_cache_identity() {
        let user = make_user_context_with_map(ModelMap::default());
        let (engine, programs) = empty_engine_and_programs();
        let mut identities = Vec::new();
        for body in [
            r#"{"model":"m","messages":[{"role":"user","content":"hi"}],"priority":-100}"#,
            r#"{"model":"m","messages":[{"role":"user","content":"hi"}],"priority":7}"#,
            r#"{"model":"m","messages":[{"role":"user","content":"hi"}]}"#,
        ] {
            let mut request = ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(body)).unwrap();
            transform_request(&mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, true, ScriptFailMode::Open)
                .await
                .unwrap();
            identities.push(crate::proxy::response_cache::tests::content_hash(&request));
        }
        assert_eq!(identities[0], identities[2]);
        assert_eq!(identities[1], identities[2]);
    }

    #[tokio::test]
    async fn stream_options_injected_for_streaming() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request("gpt-4o", true);
        let (engine, programs) = empty_engine_and_programs();

        let _result =
            transform_request(&mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, true, ScriptFailMode::Open)
                .await
                .unwrap();
        // stream_options injection is internal — verified via the request body, not a badge.
        if let ApiRequest::ChatCompletions(chat) = &request {
            let opts = chat.stream_options.as_ref().unwrap();
            assert_eq!(opts["include_usage"], true);
        }
    }

    #[tokio::test]
    async fn stream_options_not_injected_for_non_streaming() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request("gpt-4o", false);
        let (engine, programs) = empty_engine_and_programs();

        let _result =
            transform_request(&mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, true, ScriptFailMode::Open)
                .await
                .unwrap();
        if let ApiRequest::ChatCompletions(chat) = &request {
            assert!(chat.stream_options.is_none());
        }
    }

    #[tokio::test]
    async fn script_chain_applies_transforms() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request("gpt-4o", false);
        let engine = ScriptEngine::new();
        let programs = vec![TransformProgram {
            id: "test".to_string(),
            name: "guardrail".to_string(),
            source: r#"
                fn transform(ctx) {
                    ctx.system_prompt = "Be safe.";
                    ctx
                }
            "#
            .to_string(),
            phase: "request".to_string(),
            scope: "global".to_string(),
            priority: 10,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }];

        let result =
            transform_request(&mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, true, ScriptFailMode::Open)
                .await
                .unwrap();
        // Ensure script ran successfully (Modified outcome present).
        assert!(
            result.program_outcomes.iter().any(|o| o.name == "guardrail"
                && o.outcome == TransformProgramOutcome::Modified),
            "expected guardrail to be recorded as Modified, got: {:?}",
            result.program_outcomes
        );

        // Verify system prompt was injected
        if let ApiRequest::ChatCompletions(chat) = &request {
            assert!(
                chat.messages.len() >= 2,
                "expected at least 2 messages (system + user), got {}",
                chat.messages.len()
            );
            let first = &chat.messages[0];
            assert_eq!(first.role, "system");
            match &first.content {
                Some(crate::api::domain::MessageContent::Text(t)) => {
                    assert!(t.contains("Be safe."));
                }
                other => panic!("expected text, got {other:?}"),
            }
        }
    }

    fn make_chat_request_with_tools(model: &str) -> ApiRequest {
        let json = format!(
            r#"{{
                "model": "{model}",
                "messages": [{{"role": "user", "content": "hello"}}],
                "stream": false,
                "tools": [
                    {{"type": "function", "function": {{"name": "web_search", "parameters": {{}}}}}},
                    {{"type": "function", "function": {{"name": "Read", "parameters": {{}}}}}},
                    {{"type": "function", "function": {{"name": "Write", "parameters": {{}}}}}}
                ]
            }}"#
        );
        ApiRequest::parse(
            crate::api::sse::ApiVersion::ChatCompletions,
            &Bytes::from(json),
        )
        .unwrap()
    }

    fn rule_from_json(v: serde_json::Value) -> Rule {
        serde_json::from_value(v).expect("rule JSON must deserialize")
    }

    #[tokio::test]
    async fn tool_policy_blocks_matching_tools() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request_with_tools("gpt-4o");
        let (engine, programs) = empty_engine_and_programs();

        // Stage C: rules pivot on tool_id, so we need a field profile that
        // resolves `web_search` to a known id before the rule can match.
        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: Some("test-web_search".into()),
            description: None,
            source: None,
            tool_id: "web_search".into(),
            tool_pattern: "web_search".into(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: "query".into(),
            wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100,
            is_builtin: false,
        }]);
        let block_rules = vec![rule_from_json(serde_json::json!({
            "id": "T-1568",
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{ "target": "tool_id", "op": "equals", "value": "web_search" }],
            "action": { "kind": "block" },
            "risk": "danger",
            "title": "Web search",
            "description": "Web search disabled by admin"
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, true, &block_rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // web_search should be blocked → ToolBlocked badge with phase=request, name=web_search
        let badges = result.badges.clone().finish();
        assert!(
            badges.iter().any(|b| matches!(b,
                crate::audit::AuditBadge::ToolBlocked { phase, names, .. }
                    if *phase == crate::audit::Phase::Request
                    && names.iter().any(|n| n == "web_search")
            )),
            "expected ToolBlocked badge for web_search, got: {badges:?}"
        );

        // Tool list should still have Read and Write, but not web_search.
        let tool_names = request.tool_names();
        assert!(!tool_names.contains(&"web_search"), "web_search should be removed");
        assert!(tool_names.contains(&"Read"), "Read should remain");
        assert!(tool_names.contains(&"Write"), "Write should remain");

        // System prompt should contain block notice.
        if let ApiRequest::ChatCompletions(chat) = &request {
            let system_msg = &chat.messages[0];
            assert_eq!(system_msg.role, "system");
            match &system_msg.content {
                Some(crate::api::domain::MessageContent::Text(t)) => {
                    assert!(t.contains("[Tool Policy]"), "missing tool policy notice");
                    assert!(t.contains("web_search"), "missing blocked tool name in notice");
                }
                other => panic!("expected text, got {other:?}"),
            }
        } else {
            panic!("expected ChatCompletions");
        }

        // Step diffs should include tool_policy entry.
        let diffs = result.step_diffs.unwrap();
        assert!(diffs.iter().any(|d| d.name == "tool_policy"));
    }

    #[tokio::test]
    async fn response_phase_block_rule_does_not_fire_at_request_time() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request_with_tools("gpt-4o");
        let (engine, programs) = empty_engine_and_programs();

        // Arg-aware blocks live on `phase=response, scope=tool_calls` —
        // they evaluate against an emitted tool_use call. The request-phase
        // pipeline must not pick them up: the tool definition should remain
        // in the outbound request and no ToolBlocked badge should fire.
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "T-1632",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "read_file" },
                { "target": "arg.file_path", "op": "glob", "value": "/etc/*" }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, false, &rules, None, None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        let badges = result.badges.clone().finish();
        assert!(
            !badges
                .iter()
                .any(|b| matches!(b, crate::audit::AuditBadge::ToolBlocked { .. })),
            "response-phase rules must not fire request-side"
        );
        assert!(request.tool_names().contains(&"Read"));
    }

    #[tokio::test]
    async fn tool_policy_no_rules_is_noop() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request_with_tools("gpt-4o");
        let (engine, programs) = empty_engine_and_programs();

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, false, &[], None, None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        let badges = result.badges.clone().finish();
        assert!(
            !badges
                .iter()
                .any(|b| matches!(b, crate::audit::AuditBadge::ToolBlocked { .. })),
            "no tools should be blocked"
        );
        assert_eq!(request.tool_names().len(), 3);
    }

    fn web_search_function_def() -> serde_json::Value {
        serde_json::json!({
            "name": "web_search",
            "description": "Search the web for the given query.",
            "parameters": {
                "type": "object",
                "properties": {"query": {"type": "string"}},
                "required": ["query"]
            }
        })
    }

    #[tokio::test]
    async fn substitute_action_rewrites_tool_def_and_emits_binding() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request_with_tools("gpt-4o");
        let (engine, programs) = empty_engine_and_programs();

        // Field profile canonicalises `web_search` (the wire name) to
        // `tool_id="web_search"` so the rule predicate hits.
        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: Some("test-ws".into()),
            description: None,
            source: None,
            tool_id: "web_search".into(),
            tool_pattern: "web_search".into(),
            app_filter: None,
            mcp_server: None,
            server_type: None,
            field: "query".into(),
            wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100,
            is_builtin: false,
        }]);
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "WS-SUB-TEST",
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "substitute",
                "with": {
                    "name": "gateway_web_search",
                    "description": "Gateway-filtered search.",
                    "parameters": {"type": "object", "properties": {"query": {"type": "string"}}, "required": ["query"]}
                },
                "intercept": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution",
            "title": "Web search via gateway"
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, true, &rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // Tool definition swapped: `web_search` → `gateway_web_search`.
        let names = request.tool_names();
        assert!(!names.contains(&"web_search"), "original name should be gone");
        assert!(names.contains(&"gateway_web_search"), "replacement name should be present");
        assert!(names.contains(&"Read"));
        assert!(names.contains(&"Write"));

        // Binding emitted on TransformResult.
        assert_eq!(result.intercept_bindings.len(), 1);
        let b = &result.intercept_bindings[0];
        assert_eq!(b.original_name, "web_search");
        assert_eq!(b.replaced_name, "gateway_web_search");
        assert_eq!(b.action, "substitute");
        assert_eq!(b.rule_id, "WS-SUB-TEST");
        // Client function-tool substitution stays invisible to the client —
        // `original_server_type` is `None` so the agent loop discards
        // synthesised events for this binding (Decision #1).
        assert_eq!(b.original_server_type, None);
        match &b.intercept {
            tool_rules::InterceptKind::WebExecutor { kind } => {
                assert_eq!(*kind, tool_rules::WebInterceptKind::Search);
            }
        }

        // Audit injection_blocks records the substitute event.
        assert!(
            result.injection_blocks.iter().any(|b| b.transform == "tool_policy"
                && b.action == "substitute"
                && b.content.contains("web_search → gateway_web_search")),
            "expected substitute injection block, got: {:?}",
            result.injection_blocks
        );
    }

    #[tokio::test]
    async fn intercept_only_emits_binding_without_rewriting_def() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request_with_tools("gpt-4o");
        let (engine, programs) = empty_engine_and_programs();

        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: None, description: None, source: None,
            tool_id: "web_search".into(), tool_pattern: "web_search".into(),
            app_filter: None, mcp_server: None, server_type: None,
            field: "query".into(), wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100, is_builtin: false,
        }]);
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "WS-IO-TEST",
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "intercept_only",
                "handler": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution"
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, false, &rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // Tool def kept intact — binding still emitted.
        assert!(request.tool_names().contains(&"web_search"));
        assert_eq!(result.intercept_bindings.len(), 1);
        let b = &result.intercept_bindings[0];
        assert_eq!(b.original_name, "web_search");
        assert_eq!(b.replaced_name, "web_search");
        assert_eq!(b.action, "intercept_only");
    }

    #[tokio::test]
    async fn substitute_claude_code_websearch_seeded_shape() {
        // Mirrors the seeded `WS-SUB-CC-WEB-SEARCH` rule + `TFP-claude-WebSearch`
        // field profile end-to-end: Anthropic Messages request from a Claude
        // Code-attributed call, tool name `WebSearch` (mixed case as the
        // client emits), `app_id="claude-code"`. The substitution must fire,
        // rewriting the def to `web_search` and emitting a binding.
        let user = make_user_context_with_map(ModelMap::default());
        let json = r#"{
            "model": "claude-3-5-sonnet",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "search please"}],
            "stream": true,
            "tools": [
                {"name": "WebSearch", "description": "Search the web.",
                 "input_schema": {"type": "object",
                   "properties": {"query": {"type": "string"}},
                   "required": ["query"]}}
            ]
        }"#;
        let mut request = ApiRequest::parse(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &Bytes::from(json.to_string()),
        )
        .unwrap();
        let (engine, programs) = empty_engine_and_programs();

        // Seeded TFP-claude-WebSearch shape verbatim.
        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: Some("TFP-claude-WebSearch".into()),
            description: None,
            source: Some("claude-code:builtin".into()),
            tool_id: "web_search".into(),
            tool_pattern: "WebSearch".into(),
            app_filter: Some("claude-code|claude*".into()),
            mcp_server: None,
            server_type: None,
            field: "query".into(),
            wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100,
            is_builtin: true,
        }]);

        // Seeded WS-SUB-CC-WEB-SEARCH shape verbatim.
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "WS-SUB-CC-WEB-SEARCH",
            "phase": "request",
            "scope": "tool_definitions",
            "app_filter": "claude-code|claude*",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "substitute",
                "with": {
                    "name": "web_search",
                    "description": "Search the web for the given query.",
                    "parameters": {"type": "object",
                        "properties": {"query": {"type": "string", "description": "The search query."}},
                        "required": ["query"]}
                },
                "intercept": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution",
            "title": "Web search via gateway (Claude Code WebSearch)",
            "enabled": true,
            "is_builtin": true
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            Some("claude-code"), // <-- app_id propagated from the X-App-Id header
            None, None, false, true, &rules, Some(&profiles), None, true,
            ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // Expected: tool def renamed and binding emitted.
        assert!(
            result.intercept_bindings.iter().any(|b| {
                b.original_name == "WebSearch"
                    && b.replaced_name == "web_search"
                    && b.action == "substitute"
                    && b.rule_id == "WS-SUB-CC-WEB-SEARCH"
            }),
            "expected substitute binding (WebSearch → web_search), got bindings={:?}",
            result.intercept_bindings,
        );
        assert!(
            request.tool_names().contains(&"web_search"),
            "tool def should be renamed to web_search; got {:?}",
            request.tool_names(),
        );
        assert!(
            !request.tool_names().contains(&"WebSearch"),
            "original WebSearch name should be gone after substitute"
        );
    }

    #[tokio::test]
    async fn substitute_binding_dropped_when_rhai_removes_tool() {
        // Same substitute setup as `substitute_claude_code_websearch_seeded_shape`,
        // but a Rhai script runs after substitute and removes the resulting
        // `web_search` tool def. The binding's `replaced_name="web_search"`
        // would otherwise point at a tool the upstream will never echo, and
        // any matching `tool_use` in conversation history would silently flow
        // to the client. Post-rewrite revalidation must drop the orphan.
        let user = make_user_context_with_map(ModelMap::default());
        let json = r#"{
            "model": "claude-3-5-sonnet",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "tools": [
                {"name": "WebSearch", "description": "Search.",
                 "input_schema": {"type": "object",
                   "properties": {"query": {"type": "string"}},
                   "required": ["query"]}}
            ]
        }"#;
        let mut request = ApiRequest::parse(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &Bytes::from(json.to_string()),
        )
        .unwrap();
        let engine = ScriptEngine::new();
        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: Some("TFP-claude-WebSearch".into()),
            description: None,
            source: Some("claude-code:builtin".into()),
            tool_id: "web_search".into(),
            tool_pattern: "WebSearch".into(),
            app_filter: Some("claude-code|claude*".into()),
            mcp_server: None,
            server_type: None,
            field: "query".into(),
            wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100,
            is_builtin: true,
        }]);
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "WS-SUB-CC-WEB-SEARCH",
            "phase": "request",
            "scope": "tool_definitions",
            "app_filter": "claude-code|claude*",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "substitute",
                "with": {
                    "name": "web_search",
                    "description": "Search the web.",
                    "parameters": {"type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]}
                },
                "intercept": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution",
            "title": "ws",
            "enabled": true,
            "is_builtin": true
        }))];
        let programs = vec![TransformProgram {
            id: "remove-ws".to_string(),
            name: "remove_web_search".to_string(),
            source: r#"
                fn transform(ctx) {
                    if ctx.tools != () {
                        ctx.tools = ctx.tools.filter(|t| t.name != "web_search");
                    }
                    ctx
                }
            "#
            .to_string(),
            phase: "request".to_string(),
            scope: "tools".to_string(),
            priority: 10,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            Some("claude-code"),
            None, None, false, true, &rules, Some(&profiles), None, true,
            ScriptFailMode::Open,
        )
        .await
        .unwrap();

        assert!(
            result.intercept_bindings.is_empty(),
            "orphan binding should have been dropped, got {:?}",
            result.intercept_bindings,
        );
        let orphan_block = result
            .injection_blocks
            .iter()
            .find(|b| b.field == "intercept_binding" && b.action == "drop")
            .expect("orphan injection block should be emitted");
        let payload: serde_json::Value =
            serde_json::from_str(&orphan_block.content).unwrap();
        assert_eq!(payload["replaced_name"], "web_search");
        assert_eq!(payload["original_name"], "WebSearch");
        assert_eq!(payload["rule_id"], "WS-SUB-CC-WEB-SEARCH");
        assert_eq!(payload["binding_action"], "substitute");
        assert_eq!(payload["reason"], "post_rewrite_orphan");
    }

    fn scoped_program(scope: &str, source: &str) -> TransformProgram {
        TransformProgram {
            id: format!("{scope}-program"),
            name: format!("{scope}_program"),
            source: source.to_string(),
            phase: "request".to_string(),
            scope: scope.to_string(),
            priority: 10,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        }
    }

    /// A chain of `tools` programs is projected without the conversation: the
    /// tool edit lands, and the messages and the system prompt — which the
    /// projection never read — go out exactly as the client sent them, on a
    /// shape a resync would have rewritten (two leading system messages, an
    /// image part, a multi-block system prompt with a cache breakpoint).
    #[tokio::test]
    async fn a_tools_chain_edits_the_tools_and_leaves_the_conversation_as_sent() {
        let user = make_user_context_with_map(ModelMap::default());
        let engine = ScriptEngine::new();
        let programs = vec![scoped_program(
            "tools",
            r#"fn transform(ctx) { ctx.tools = ctx.tools.filter(|t| t.name != "drop_me"); ctx }"#,
        )];
        let tools = |version| match version {
            crate::api::sse::ApiVersion::AnthropicMessages => serde_json::json!([
                {"name": "keep", "input_schema": {"type": "object"}},
                {"name": "drop_me", "input_schema": {"type": "object"}},
            ]),
            _ => serde_json::json!([
                {"type": "function", "function": {"name": "keep", "parameters": {"type": "object"}}},
                {"type": "function", "function": {"name": "drop_me", "parameters": {"type": "object"}}},
            ]),
        };
        let cases = [
            (crate::api::sse::ApiVersion::ChatCompletions, serde_json::json!({
                "model": "m",
                "messages": [
                    {"role": "system", "content": "one"},
                    {"role": "system", "content": "two"},
                    {"role": "user", "content": [
                        {"type": "text", "text": "look"},
                        {"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}},
                    ]},
                    {"role": "assistant", "content": null, "tool_calls": [
                        {"id": "c1", "type": "function", "function": {"name": "keep", "arguments": "{}"}},
                    ]},
                    {"role": "tool", "tool_call_id": "c1", "content": "done"},
                ],
            })),
            (crate::api::sse::ApiVersion::AnthropicMessages, serde_json::json!({
                "model": "m",
                "max_tokens": 16,
                "system": [
                    {"type": "text", "text": "one"},
                    {"type": "text", "text": "two", "cache_control": {"type": "ephemeral"}},
                ],
                "messages": [
                    {"role": "user", "content": "go"},
                    {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "keep", "input": {}}]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": "done"}]},
                ],
            })),
        ];
        for (version, mut body) in cases {
            body["tools"] = tools(version);
            let parse = || ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
            let sent: serde_json::Value = serde_json::from_slice(&parse().serialize().unwrap()).unwrap();
            let mut request = parse();
            let result = transform_request(
                &mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, false,
                ScriptFailMode::Open,
            )
            .await
            .unwrap();
            let wire: serde_json::Value = serde_json::from_slice(&request.serialize().unwrap()).unwrap();
            assert_eq!(request.tool_names(), ["keep"], "{version:?}");
            assert_eq!(wire["messages"], sent["messages"], "{version:?}");
            assert_eq!(wire.get("system"), sent.get("system"), "{version:?}");
            assert!(result.flags.tools_modified, "{version:?}");
            assert!(!result.flags.messages_modified && !result.flags.system_prompt_modified, "{version:?}");
        }
    }

    /// The positive control for the history-free projection: a
    /// `system_prompt` program on Chat Completions, whose system prompt rides
    /// the messages, still reads it, and its edit lands.
    #[tokio::test]
    async fn a_system_prompt_program_reads_the_chat_system_message() {
        let user = make_user_context_with_map(ModelMap::default());
        let engine = ScriptEngine::new();
        let programs = vec![scoped_program(
            "system_prompt",
            r#"fn transform(ctx) { ctx.system_prompt = ctx.system_prompt + " and more"; ctx }"#,
        )];
        let body = r#"{"model":"m","messages":[{"role":"system","content":"base"},{"role":"user","content":"hi"}]}"#;
        let mut request =
            ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(body)).unwrap();
        transform_request(
            &mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, false,
            ScriptFailMode::Open,
        )
        .await
        .unwrap();
        let wire: serde_json::Value = serde_json::from_slice(&request.serialize().unwrap()).unwrap();
        assert_eq!(wire["messages"][0]["content"], "base and more");
        assert_eq!(wire["messages"][1]["content"], "hi");
    }

    /// A script's system-prompt edit is reported as one, on Gemini as on every
    /// protocol; it replaces the whole instruction.
    #[tokio::test]
    async fn a_gemini_system_prompt_edit_is_reported() {
        let user = make_user_context_with_map(ModelMap::default());
        let engine = ScriptEngine::new();
        let programs = vec![scoped_program(
            "system_prompt",
            r#"fn transform(ctx) { ctx.system_prompt = "new"; ctx }"#,
        )];
        let body = r#"{"systemInstruction":{"parts":[{"text":"old"},{"inlineData":{"mimeType":"image/png","data":"iVBO"}},{"text":"rules"}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;
        let mut request =
            ApiRequest::parse(crate::api::sse::ApiVersion::GoogleGemini, &Bytes::from(body)).unwrap();
        let result = transform_request(
            &mut request, &user, &engine, &programs, None, None, None, false, false, &[], None, None, false,
            ScriptFailMode::Open,
        )
        .await
        .unwrap();
        assert!(result.flags.system_prompt_modified);
        assert_eq!(request.wire_value().unwrap()["systemInstruction"]["parts"], serde_json::json!([{"text": "new"}]));
    }

    /// With no record of what was screened, the inbound scan reads every user
    /// message, history included, and its enforce write-back lands on each
    /// message carrying the address, on every protocol — every text part of
    /// it, a non-text part kept — while the system and developer messages, an
    /// empty message, a tool result and an assistant prefill go out as sent;
    /// each step is anchored at its message's distance from the end of the
    /// system-free message list.
    #[tokio::test]
    async fn an_inbound_mask_lands_on_every_message_carrying_it() {
        use crate::api::sse::ApiVersion;
        let mut guardrail = crate::guardrail::GuardrailSettings::default();
        guardrail.pii.mode = crate::guardrail::GuardrailMode::Enforce;
        let masked = |body: &serde_json::Value| {
            serde_json::from_str::<serde_json::Value>(
                &body.to_string().replace("jane.doe@example.com", "[REDACTED:EMAIL_ADDRESS]"),
            )
            .unwrap()
        };
        let image = serde_json::json!({"type": "image_url", "image_url": {"url": "data:image/png;base64,AAAA"}});
        let chat = serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "system", "content": "be brief"},
                {"role": "developer", "content": "rules"},
                {"role": "user", "content": "mail jane.doe@example.com"},
                {"role": "assistant", "content": ""},
                {"role": "user", "content": "go on"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "c1", "type": "function", "function": {"name": "send", "arguments": "{}"}},
                ]},
                {"role": "tool", "tool_call_id": "c1", "content": "sent"},
                {"role": "user", "content": [
                    {"type": "text", "text": "now tell jane.doe@example.com"},
                    image,
                    {"type": "text", "text": "and bob@example.org"},
                ]},
            ],
        });
        let mut chat_masked = chat.clone();
        chat_masked["messages"][2]["content"] = serde_json::json!("mail [REDACTED:EMAIL_ADDRESS]");
        chat_masked["messages"][7]["content"] = serde_json::json!([
            {"type": "text", "text": "now tell [REDACTED:EMAIL_ADDRESS]\nand [REDACTED:EMAIL_ADDRESS]"},
            image,
        ]);
        let anthropic = serde_json::json!({
            "model": "m",
            "max_tokens": 16,
            "system": "be brief",
            "messages": [
                {"role": "user", "content": "mail jane.doe@example.com"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "t1", "name": "send", "input": {}}]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": "sent"},
                    {"type": "text", "text": "now tell jane.doe@example.com"},
                ]},
                {"role": "assistant", "content": "Sure,"},
            ],
        });
        let gemini = serde_json::json!({
            "systemInstruction": {"parts": [{"text": "be brief"}]},
            "contents": [
                {"role": "user", "parts": [{"text": "mail jane.doe@example.com"}]},
                {"role": "model", "parts": [{"functionCall": {"name": "send", "args": {}}}]},
                {"role": "user", "parts": [
                    {"functionResponse": {"name": "send", "response": {"r": "sent"}}},
                    {"text": "now tell jane.doe@example.com"},
                ]},
            ],
        });
        let responses_raw = serde_json::json!({
            "model": "m",
            "instructions": "be brief",
            "input": [
                {"type": "message", "role": "user", "content": "mail jane.doe@example.com"},
                {"type": "reasoning", "summary": []},
                {"type": "function_call", "call_id": "c1", "name": "send", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "c1", "output": "sent"},
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "now tell jane.doe@example.com"}]},
            ],
        });
        let responses_messages = serde_json::json!({
            "model": "m",
            "input": [
                {"role": "user", "content": "mail jane.doe@example.com"},
                {"role": "assistant", "content": "done"},
                {"role": "user", "content": "now tell jane.doe@example.com"},
            ],
        });
        let responses_text = serde_json::json!({"model": "m", "input": "now tell jane.doe@example.com"});
        // A blank user message after the one carrying the address hides nothing.
        let mut chat_blank = chat.clone();
        chat_blank["messages"].as_array_mut().unwrap().push(serde_json::json!({"role": "user", "content": " "}));
        let mut chat_blank_masked = chat_masked.clone();
        chat_blank_masked["messages"].as_array_mut().unwrap().push(serde_json::json!({"role": "user", "content": " "}));
        let cases = [
            (ApiVersion::ChatCompletions, chat, chat_masked, vec!["4", "0"]),
            (ApiVersion::ChatCompletions, chat_blank, chat_blank_masked, vec!["5", "1"]),
            (ApiVersion::AnthropicMessages, anthropic.clone(), masked(&anthropic), vec!["4", "1"]),
            (ApiVersion::GoogleGemini, gemini.clone(), masked(&gemini), vec!["3", "1"]),
            (ApiVersion::Responses, responses_raw.clone(), masked(&responses_raw), vec!["3", "0"]),
            (ApiVersion::Responses, responses_messages.clone(), masked(&responses_messages), vec!["2", "0"]),
            (ApiVersion::Responses, responses_text.clone(), masked(&responses_text), vec!["0"]),
        ];
        let wire = |version, body: &serde_json::Value| -> serde_json::Value {
            let request = ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
            serde_json::from_slice(&request.serialize().unwrap()).unwrap()
        };
        for (version, body, expected, anchor) in cases {
            let mut request = ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
            let out = scan_inbound_request(&mut request, &guardrail, uuid::Uuid::nil(), None, None).await.unwrap();
            assert!(out.messages_modified, "{version:?}: {body}");
            let sent: serde_json::Value = serde_json::from_slice(&request.serialize().unwrap()).unwrap();
            assert_eq!(sent, wire(version, &expected), "{version:?}");
            let anchors: Vec<&str> = out.steps.iter().map(|s| s.tool_use_id.as_str()).collect();
            assert_eq!(anchors, anchor, "{version:?}: each masked message's distance from the end");
        }
    }

    /// What the scan screened is not screened again, and what it masked is
    /// masked again: a resent conversation is read only for its new messages,
    /// while the message it masked, sent back as the client keeps it, goes out
    /// masked from the record; a change of settings screens everything again;
    /// another conversation finds the masked message, and reports it, anew.
    #[tokio::test]
    async fn the_scan_reads_what_is_new_and_masks_again_what_it_masked() {
        use crate::api::sse::ApiVersion;
        let mut guardrail = crate::guardrail::GuardrailSettings::default();
        guardrail.pii.mode = crate::guardrail::GuardrailMode::Enforce;
        let tenant = uuid::Uuid::new_v4();
        let conversation = uuid::Uuid::new_v4();
        let body = |items: serde_json::Value| serde_json::json!({"model": "m", "max_tokens": 16, "messages": items});
        let scan = |items: serde_json::Value, guardrail: crate::guardrail::GuardrailSettings| async move {
            let mut request = ApiRequest::parse(ApiVersion::AnthropicMessages, &Bytes::from(body(items).to_string())).unwrap();
            let keys = crate::proxy::content::extract_request_content(&request, 0).screen_keys();
            let out = scan_inbound_request(&mut request, &guardrail, tenant, Some(conversation), Some(&keys)).await.unwrap();
            assert_eq!(
                out.messages_modified,
                String::from_utf8(request.serialize().unwrap().to_vec()).unwrap().contains("REDACTED"),
                "a mask written is a mask reported"
            );
            let anchors: Vec<String> = out.steps.iter().map(|s| s.tool_use_id.clone()).collect();
            let wire: serde_json::Value = serde_json::from_slice(&request.serialize().unwrap()).unwrap();
            let blocks = out
                .badges
                .iter()
                .filter(|b| matches!(b, crate::audit::badge::AuditBadge::Guardrail { action: crate::audit::badge::GuardrailAction::Block, .. }))
                .count();
            (anchors, wire, blocks)
        };
        let first = serde_json::json!([{"role": "user", "content": "mail jane.doe@example.com"}]);
        let (anchors, wire, _) = scan(first.clone(), guardrail.clone()).await;
        assert_eq!(anchors, ["0"]);
        assert_eq!(wire["messages"][0]["content"], "mail [REDACTED:EMAIL_ADDRESS]");

        let second = serde_json::json!([
            {"role": "user", "content": "mail jane.doe@example.com"},
            {"role": "assistant", "content": "done"},
            {"role": "user", "content": "thanks"},
        ]);
        let (anchors, wire, blocks) = scan(second.clone(), guardrail.clone()).await;
        assert!(anchors.is_empty(), "nothing read again, the clean new message gives nothing: {anchors:?}");
        assert_eq!(blocks, 1, "the replayed edit carries its badge");
        assert_eq!(wire["messages"][0]["content"], "mail [REDACTED:EMAIL_ADDRESS]", "masked again from the record");

        let third = serde_json::json!([
            {"role": "user", "content": "mail jane.doe@example.com"},
            {"role": "assistant", "content": "done"},
            {"role": "user", "content": "thanks"},
            {"role": "assistant", "content": "ok"},
            {"role": "user", "content": "and bob@example.org"},
        ]);
        let (anchors, wire, blocks) = scan(third.clone(), guardrail.clone()).await;
        assert_eq!(anchors, ["0"], "only the new address is read");
        assert_eq!(blocks, 2, "the replayed edit's badge and the new mask's");
        assert_eq!(wire["messages"][0]["content"], "mail [REDACTED:EMAIL_ADDRESS]");
        assert_eq!(wire["messages"][4]["content"], "and [REDACTED:EMAIL_ADDRESS]");

        // Observe under other settings: everything is read again, and a
        // finding observe only records is not read a second time.
        let mut observe = guardrail.clone();
        observe.pii.mode = crate::guardrail::GuardrailMode::Observe;
        let (anchors, wire, _) = scan(third.clone(), observe.clone()).await;
        assert_eq!(anchors, ["4", "0"]);
        assert_eq!(wire["messages"][0]["content"], "mail jane.doe@example.com", "observe leaves it");
        let (anchors, _, _) = scan(third, observe).await;
        assert!(anchors.is_empty(), "{anchors:?}");

        // The masked message sent again in another conversation is found, and
        // reported, there again; the clean one is a fact of its text.
        let mut request = ApiRequest::parse(
            ApiVersion::AnthropicMessages,
            &Bytes::from(body(second).to_string()),
        )
        .unwrap();
        let keys = crate::proxy::content::extract_request_content(&request, 0).screen_keys();
        let out = scan_inbound_request(&mut request, &guardrail, tenant, Some(uuid::Uuid::new_v4()), Some(&keys))
            .await
            .unwrap();
        let anchors: Vec<&str> = out.steps.iter().map(|s| s.tool_use_id.as_str()).collect();
        assert_eq!(anchors, ["2"], "found again in a new conversation; \"thanks\" not read again");
    }

    /// A verdict holds for the protocol it was read on: the same bytes, which
    /// Anthropic reads as no text and Gemini as an address, are recorded clean
    /// on the one and still screened on the other.
    #[tokio::test]
    async fn a_verdict_read_on_one_protocol_does_not_skip_another() {
        use crate::api::sse::ApiVersion;
        let mut guardrail = crate::guardrail::GuardrailSettings::default();
        guardrail.pii.mode = crate::guardrail::GuardrailMode::Enforce;
        let tenant = uuid::Uuid::new_v4();
        let conversation = uuid::Uuid::new_v4();
        let part = serde_json::json!([{"text": "mail jane.doe@example.com"}]);
        let cases = [
            (ApiVersion::AnthropicMessages, serde_json::json!({"model": "m", "max_tokens": 16, "messages": [{"role": "user", "content": part}]})),
            (ApiVersion::GoogleGemini, serde_json::json!({"contents": [{"role": "user", "parts": part}]})),
        ];
        let mut keys_seen = Vec::new();
        let mut masked = Vec::new();
        for (version, body) in cases {
            let mut request = ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
            let content = crate::proxy::content::extract_request_content(&request, 0);
            keys_seen.push(content.link_hashes[0].clone());
            let keys = content.screen_keys();
            let out = scan_inbound_request(&mut request, &guardrail, tenant, Some(conversation), Some(&keys)).await.unwrap();
            masked.push(out.messages_modified);
        }
        assert_eq!(keys_seen[0], keys_seen[1], "one item key on both protocols — the case under test");
        assert_eq!(masked, [false, true], "Anthropic reads no text there; Gemini is screened and masked");
    }

    #[tokio::test]
    async fn substitute_binding_follows_sanitize_rename() {
        // When sanitize_request renames a substituted tool's wire name (e.g.
        // because the substitute output uses a name with characters the
        // sanitizer rewrites), the binding's `replaced_name` must follow the
        // rename so the response-side lookup still matches the upstream's
        // echoed `tool_use`. Construct a substitute rule whose `with.name`
        // contains a character (`.`) the sanitizer rewrites.
        let user = make_user_context_with_map(ModelMap::default());
        let json = r#"{
            "model": "claude-3-5-sonnet",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "tools": [
                {"name": "WebSearch", "description": "Search.",
                 "input_schema": {"type": "object",
                   "properties": {"query": {"type": "string"}},
                   "required": ["query"]}}
            ]
        }"#;
        let mut request = ApiRequest::parse(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &Bytes::from(json.to_string()),
        )
        .unwrap();
        let (engine, programs) = empty_engine_and_programs();
        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: Some("TFP-claude-WebSearch".into()),
            description: None,
            source: Some("claude-code:builtin".into()),
            tool_id: "web_search".into(),
            tool_pattern: "WebSearch".into(),
            app_filter: Some("claude-code|claude*".into()),
            mcp_server: None,
            server_type: None,
            field: "query".into(),
            wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100,
            is_builtin: true,
        }]);
        // `web.search` — the dot is sanitized to `_`.
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "WS-SUB-CC-WEB-SEARCH",
            "phase": "request",
            "scope": "tool_definitions",
            "app_filter": "claude-code|claude*",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "substitute",
                "with": {
                    "name": "web.search",
                    "description": "Search.",
                    "parameters": {"type": "object",
                        "properties": {"query": {"type": "string"}},
                        "required": ["query"]}
                },
                "intercept": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution",
            "title": "ws",
            "enabled": true,
            "is_builtin": true
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            Some("claude-code"),
            None, None, false, true, &rules, Some(&profiles), None, true,
            ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // Binding survives, `replaced_name` follows the sanitize rename.
        assert_eq!(result.intercept_bindings.len(), 1);
        let b = &result.intercept_bindings[0];
        assert_eq!(b.original_name, "WebSearch");
        // Sanitize rewrote `web.search` → `websearch` (dot stripped).
        assert_eq!(
            b.replaced_name, "websearch",
            "binding's replaced_name must follow sanitize_tool_names rename",
        );
        // Wire tool def reflects the sanitized name.
        assert!(request.tool_names().contains(&"websearch"));
        // No orphan-drop block (binding survived).
        assert!(
            !result
                .injection_blocks
                .iter()
                .any(|ib| ib.field == "intercept_binding" && ib.action == "drop"),
            "no orphan drop expected, got {:?}",
            result.injection_blocks,
        );
    }

    #[tokio::test]
    async fn substitute_binding_collision_drops_shadowed() {
        // Two substitute rules whose `with.name` differ pre-sanitize but
        // collapse to the same wire name post-sanitize. Without dedup, the
        // second binding is silently shadowed by the first via
        // `intercept_binding_for`'s first-match lookup. The dedup pass must
        // drop the second with `post_rewrite_collision`.
        let user = make_user_context_with_map(ModelMap::default());
        let json = r#"{
            "model": "claude-3-5-sonnet",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "hi"}],
            "stream": true,
            "tools": [
                {"name": "WebSearch", "description": "Search.",
                 "input_schema": {"type": "object",
                   "properties": {"query": {"type": "string"}},
                   "required": ["query"]}},
                {"name": "WebFetch", "description": "Fetch.",
                 "input_schema": {"type": "object",
                   "properties": {"url": {"type": "string"}},
                   "required": ["url"]}}
            ]
        }"#;
        let mut request = ApiRequest::parse(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &Bytes::from(json.to_string()),
        )
        .unwrap();
        let (engine, programs) = empty_engine_and_programs();
        let profiles = tool_rules::FieldProfileSet::new(vec![
            tool_rules::FieldProfile {
                id: Some("TFP-claude-WebSearch".into()),
                description: None,
                source: Some("test".into()),
                tool_id: "web_search".into(),
                tool_pattern: "WebSearch".into(),
                app_filter: Some("claude-code|claude*".into()),
                mcp_server: None,
                server_type: None,
                field: "query".into(),
                wire_field: None,
                normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
                priority: 100,
                is_builtin: true,
            },
            tool_rules::FieldProfile {
                id: Some("TFP-claude-WebFetch".into()),
                description: None,
                source: Some("test".into()),
                tool_id: "web_fetch".into(),
                tool_pattern: "WebFetch".into(),
                app_filter: Some("claude-code|claude*".into()),
                mcp_server: None,
                server_type: None,
                field: "url".into(),
                wire_field: None,
                normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
                priority: 100,
                is_builtin: true,
            },
        ]);
        // Both rules' `with.name` use distinct dot-prefixed forms that
        // sanitize collapses to the same `wstool` wire name (sanitize strips
        // `.` so `w.s.tool` and `ws.tool` both → `wstool`).
        let rules = vec![
            rule_from_json(serde_json::json!({
                "id": "WS-COL-A",
                "phase": "request",
                "scope": "tool_definitions",
                "app_filter": "claude-code|claude*",
                "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
                "action": {
                    "kind": "substitute",
                    "with": {
                        "name": "w.s.tool",
                        "description": "x",
                        "parameters": {"type": "object", "properties": {}}
                    },
                    "intercept": {"type": "web_executor", "kind": "search"}
                },
                "risk": "caution", "title": "a", "enabled": true, "is_builtin": true
            })),
            rule_from_json(serde_json::json!({
                "id": "WS-COL-B",
                "phase": "request",
                "scope": "tool_definitions",
                "app_filter": "claude-code|claude*",
                "match": [{"target": "tool_id", "op": "equals", "value": "web_fetch"}],
                "action": {
                    "kind": "substitute",
                    "with": {
                        "name": "ws.tool",
                        "description": "x",
                        "parameters": {"type": "object", "properties": {}}
                    },
                    "intercept": {"type": "web_executor", "kind": "fetch"}
                },
                "risk": "caution", "title": "b", "enabled": true, "is_builtin": true
            })),
        ];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            Some("claude-code"),
            None, None, false, true, &rules, Some(&profiles), None, true,
            ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // Exactly one binding survives; the second is dropped as a collision.
        assert_eq!(
            result.intercept_bindings.len(),
            1,
            "expected one binding to survive after collision dedup, got {:?}",
            result.intercept_bindings,
        );
        // Survivor identity locked: first-emitted (rule WS-COL-A) wins.
        assert_eq!(
            result.intercept_bindings[0].rule_id,
            "WS-COL-A",
            "first-emitted binding must survive (intercept_binding_for is first-match)",
        );
        let collision_drop = result
            .injection_blocks
            .iter()
            .find(|b| {
                b.field == "intercept_binding"
                    && b.action == "drop"
                    && b.content.contains("post_rewrite_collision")
            })
            .expect("collision drop block expected");
        let payload: serde_json::Value =
            serde_json::from_str(&collision_drop.content).unwrap();
        assert_eq!(payload["reason"], "post_rewrite_collision");
        assert_eq!(payload["replaced_name"], "wstool");
        assert_eq!(payload["rule_id"], "WS-COL-B");
    }

    #[tokio::test]
    async fn substitute_disabled_rule_does_nothing() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_chat_request_with_tools("gpt-4o");
        let (engine, programs) = empty_engine_and_programs();

        let profiles = tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: None, description: None, source: None,
            tool_id: "web_search".into(), tool_pattern: "web_search".into(),
            app_filter: None, mcp_server: None, server_type: None,
            field: "query".into(), wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100, is_builtin: false,
        }]);
        let rules = vec![rule_from_json(serde_json::json!({
            "id": "WS-SUB-DISABLED",
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "substitute",
                "with": web_search_function_def(),
                "intercept": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution",
            "enabled": false
        }))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, false, &rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        assert!(request.tool_names().contains(&"web_search"));
        assert!(result.intercept_bindings.is_empty());
    }

    fn make_anthropic_request_with_server_tool() -> ApiRequest {
        // Anthropic native server-tool shape: {type: web_search_20250305, name: web_search}.
        let json = r#"{
            "model": "claude-3-5-sonnet-20241022",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {"type": "web_search_20250305", "name": "web_search", "max_uses": 5},
                {"name": "Read", "description": "Read file", "input_schema": {"type": "object"}}
            ]
        }"#;
        ApiRequest::parse(
            crate::api::sse::ApiVersion::AnthropicMessages,
            &Bytes::from(json),
        )
        .unwrap()
    }

    fn make_responses_request_with_server_tool() -> ApiRequest {
        // OpenAI Responses native server-tool shape — no `function` block.
        let json = r#"{
            "model": "gpt-4.1",
            "input": [{"role": "user", "content": "hi"}],
            "tools": [
                {"type": "web_search_preview"},
                {"type": "function", "function": {"name": "Read", "parameters": {}}}
            ]
        }"#;
        ApiRequest::parse(
            crate::api::sse::ApiVersion::Responses,
            &Bytes::from(json),
        )
        .unwrap()
    }

    fn server_type_profiles() -> tool_rules::FieldProfileSet {
        tool_rules::FieldProfileSet::new(vec![
            tool_rules::FieldProfile {
                id: Some("server-anth-ws".into()),
                description: None,
                source: None,
                tool_id: "web_search".into(),
                tool_pattern: "web_search".into(),
                app_filter: None,
                mcp_server: None,
                server_type: Some("web_search_20250305".into()),
                field: "query".into(),
                wire_field: None,
                normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
                priority: 100,
                is_builtin: false,
            },
            tool_rules::FieldProfile {
                id: Some("server-or-ws".into()),
                description: None,
                source: None,
                tool_id: "web_search".into(),
                tool_pattern: "web_search_preview|web_search".into(),
                app_filter: None,
                mcp_server: None,
                server_type: Some("web_search_preview".into()),
                field: "query".into(),
                wire_field: None,
                normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
                priority: 100,
                is_builtin: false,
            },
        ])
    }

    fn substitute_rule_for_web_search(rule_id: &str) -> serde_json::Value {
        serde_json::json!({
            "id": rule_id,
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_search"}],
            "action": {
                "kind": "substitute",
                "with": web_search_function_def(),
                "intercept": {"type": "web_executor", "kind": "search"}
            },
            "risk": "caution"
        })
    }

    #[tokio::test]
    async fn substitute_anthropic_server_tool_canonicalises_via_server_type() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_anthropic_request_with_server_tool();
        let (engine, programs) = empty_engine_and_programs();
        let profiles = server_type_profiles();
        let rules = vec![rule_from_json(substitute_rule_for_web_search("WS-SUB-AC"))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, false, &rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // Server-tool shape (`type: web_search_20250305`) → function-tool
        // shape (`name: web_search`, `input_schema` set, `extra` cleared).
        let ApiRequest::AnthropicMessages(req) = &request else {
            panic!("expected Anthropic");
        };
        let ws = req.tools.as_ref().unwrap().iter().find(|t| t.name == "web_search").unwrap();
        assert!(ws.input_schema.is_some(), "input_schema must be set after substitute");
        assert!(!ws.extra.contains_key("type"), "server-tool `type` must be cleared");
        assert!(!ws.extra.contains_key("max_uses"), "server-tool extras must be cleared");

        // Read tool untouched.
        assert!(req.tools.as_ref().unwrap().iter().any(|t| t.name == "Read"));

        assert_eq!(result.intercept_bindings.len(), 1);
        assert_eq!(result.intercept_bindings[0].original_name, "web_search");
        assert_eq!(result.intercept_bindings[0].replaced_name, "web_search");
        assert_eq!(result.intercept_bindings[0].rule_id, "WS-SUB-AC");
        // Server-tool path captures `original_server_type` so the agent loop's
        // visible-mode renderer knows to synthesise native `server_tool_use`
        // / `web_search_tool_result` blocks instead of staying invisible.
        assert_eq!(
            result.intercept_bindings[0].original_server_type.as_deref(),
            Some("web_search_20250305"),
        );
    }

    #[tokio::test]
    async fn substitute_responses_server_tool_promotes_to_function_block() {
        let user = make_user_context_with_map(ModelMap::default());
        let mut request = make_responses_request_with_server_tool();
        let (engine, programs) = empty_engine_and_programs();
        let profiles = server_type_profiles();
        let rules = vec![rule_from_json(substitute_rule_for_web_search("WS-SUB-OR"))];

        let result = transform_request(
            &mut request, &user, &engine, &programs,
            None, None, None, false, false, &rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap();

        // OpenAI Responses native server-tool ships as
        // `{"type": "web_search_preview"}` (no `function` block). After
        // substitute the entry is a Responses function tool, which is FLAT:
        // `{"type": "function", "name": "web_search", "parameters": …}` — a
        // nested `function` block is Chat's shape, refused by Responses.
        let ApiRequest::Responses(req) = &request else {
            panic!("expected Responses");
        };
        let tools = req.tools.as_ref().unwrap();
        let ws = tools
            .iter()
            .find(|t| t.r#type == "function" && t.extra.get("name").and_then(|n| n.as_str()) == Some("web_search"))
            .unwrap();
        assert!(ws.function.is_none(), "no Chat-shaped function block on the Responses wire");
        assert!(ws.extra.contains_key("parameters"), "parameters must be set after substitute");
        assert!(
            ws.extra.keys().all(|k| matches!(k.as_str(), "name" | "description" | "parameters")),
            "server-tool extras must be cleared: {:?}",
            ws.extra
        );

        // The other function tool (Read) untouched.
        assert!(tools.iter().any(|t| t.function.as_ref().is_some_and(|f| f.name == "Read")));

        assert_eq!(result.intercept_bindings.len(), 1);
        let b = &result.intercept_bindings[0];
        assert_eq!(b.original_name, "web_search_preview");
        assert_eq!(b.replaced_name, "web_search");
        assert_eq!(b.rule_id, "WS-SUB-OR");
        assert_eq!(b.original_server_type.as_deref(), Some("web_search_preview"));
    }

    /// A Claude Code turn after the model looked WebFetch up: its `ToolSearch`
    /// result references WebFetch (with a cache breakpoint), and an earlier
    /// server search referenced WebFetch alone and WebFetch beside Read.
    fn looked_up_web_fetch_request(also_references: &str) -> ApiRequest {
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "fetch it"},
                {"role": "assistant", "content": [
                    {"type": "server_tool_use", "id": "srvtoolu_1", "name": "tool_search_tool_regex", "input": {"pattern": "fetch"}},
                    {"type": "tool_search_tool_result", "tool_use_id": "srvtoolu_1",
                     "content": {"type": "tool_search_tool_search_result",
                                 "tool_references": [{"type": "tool_reference", "tool_name": "WebFetch"}]}},
                    {"type": "server_tool_use", "id": "srvtoolu_2", "name": "tool_search_tool_regex", "input": {"pattern": "read|fetch"}},
                    {"type": "tool_search_tool_result", "tool_use_id": "srvtoolu_2",
                     "content": {"type": "tool_search_tool_search_result",
                                 "tool_references": [{"type": "tool_reference", "tool_name": "WebFetch"},
                                                     {"type": "tool_reference", "tool_name": "Read"}]}},
                    {"type": "tool_use", "id": "toolu_1", "name": "ToolSearch", "input": {"query": "select:WebFetch"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "toolu_1", "content": [
                        {"type": "tool_reference", "tool_name": "WebFetch", "cache_control": {"type": "ephemeral"}},
                        {"type": "tool_reference", "tool_name": also_references}
                    ]},
                    {"type": "text", "text": "Tool loaded."}
                ]}
            ],
            "tools": [
                {"type": "tool_search_tool_regex_20251119", "name": "tool_search_tool_regex"},
                {"name": "ToolSearch", "description": "Load deferred tools.", "input_schema": {"type": "object"}},
                {"name": "Read", "description": "Read a file.", "input_schema": {"type": "object"}},
                {"name": "WebFetch", "description": "Fetch a URL.", "defer_loading": true,
                 "input_schema": {"type": "object", "properties": {"url": {"type": "string"}, "prompt": {"type": "string"}}}}
            ]
        });
        ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &Bytes::from(body.to_string())).unwrap()
    }

    fn web_fetch_profiles() -> tool_rules::FieldProfileSet {
        tool_rules::FieldProfileSet::new(vec![tool_rules::FieldProfile {
            id: Some("TFP-claude-WebFetch".into()),
            description: None,
            source: None,
            tool_id: "web_fetch".into(),
            tool_pattern: "WebFetch".into(),
            app_filter: Some("claude-code|claude*".into()),
            mcp_server: None,
            server_type: None,
            field: "url".into(),
            wire_field: None,
            normalizer: crate::config::tool_rules_normalize::Normalizer::Raw,
            priority: 100,
            is_builtin: true,
        }])
    }

    fn web_fetch_rule(action: serde_json::Value) -> Rule {
        rule_from_json(serde_json::json!({
            "id": "R-FETCH",
            "phase": "request",
            "scope": "tool_definitions",
            "match": [{"target": "tool_id", "op": "equals", "value": "web_fetch"}],
            "action": action,
            "risk": "caution",
            "title": "Web fetch",
            "description": "Web fetch is the gateway's",
        }))
    }

    fn substitute_web_fetch() -> serde_json::Value {
        serde_json::json!({
            "kind": "substitute",
            "with": {"name": "web_fetch", "description": "Fetch the contents of a URL.",
                     "parameters": {"type": "object", "properties": {"url": {"type": "string"}}, "required": ["url"]}},
            "intercept": {"type": "web_executor", "kind": "fetch"}
        })
    }

    async fn transform_claude_code(
        request: &mut ApiRequest,
        rules: &[Rule],
        programs: &[TransformProgram],
    ) -> TransformResult {
        let user = make_user_context_with_map(ModelMap::default());
        let engine = ScriptEngine::new();
        let profiles = web_fetch_profiles();
        transform_request(
            request, &user, &engine, programs, Some("claude-code"), None, None, false, true,
            rules, Some(&profiles), None, true, ScriptFailMode::Open,
        )
        .await
        .unwrap()
    }

    fn wire(request: &ApiRequest) -> serde_json::Value {
        let ApiRequest::AnthropicMessages(req) = request else { panic!("expected Anthropic") };
        serde_json::to_value(req).unwrap()
    }

    fn reference_edits(result: &TransformResult) -> Vec<(String, String)> {
        result
            .injection_blocks
            .iter()
            .filter(|b| b.field == "tool_reference")
            .map(|b| (b.action.clone(), b.content.clone()))
            .collect()
    }

    /// A substituted tool's references follow it to its new name, so the API
    /// still finds every one; the substitute is declared loaded, since a tool
    /// search would not find it under that name.
    #[tokio::test]
    async fn a_substituted_tool_s_references_follow_it_and_the_substitute_is_loaded() {
        let mut request = looked_up_web_fetch_request("Read");
        let result = transform_claude_code(&mut request, &[web_fetch_rule(substitute_web_fetch())], &[]).await;
        let body = wire(&request);

        let fetch = body["tools"].as_array().unwrap().iter().find(|t| t["name"] == "web_fetch").unwrap();
        assert!(fetch.get("defer_loading").is_none(), "{fetch}");
        let messages = &body["messages"];
        assert_eq!(messages[1]["content"][1]["content"]["tool_references"][0]["tool_name"], "web_fetch");
        assert_eq!(messages[1]["content"][3]["content"]["tool_references"][0]["tool_name"], "web_fetch");
        assert_eq!(messages[1]["content"][3]["content"]["tool_references"][1]["tool_name"], "Read");
        let result_parts = &messages[2]["content"][0]["content"];
        assert_eq!(result_parts[0]["tool_name"], "web_fetch");
        assert_eq!(result_parts[0]["cache_control"]["type"], "ephemeral");
        assert_eq!(result_parts[1]["tool_name"], "Read");

        assert_eq!(reference_edits(&result), vec![("rename".to_string(), "WebFetch → web_fetch".to_string()); 3]);
        assert!(result.flags.messages_modified);
    }

    /// A blocked tool's references are removed. A tool search left with none
    /// is told why — in a text part of its result, or a text block after a
    /// server search, never beside a reference that remains — and the
    /// breakpoint a removed reference carried moves to the block that held it.
    #[tokio::test]
    async fn a_blocked_tool_s_references_are_removed_and_the_model_told() {
        let mut request = looked_up_web_fetch_request("WebFetch");
        let result = transform_claude_code(&mut request, &[web_fetch_rule(serde_json::json!({"kind": "block"}))], &[]).await;
        let body = wire(&request);
        let assistant = body["messages"][1]["content"].as_array().unwrap();

        // The search that found WebFetch alone is emptied and followed by the notice.
        assert_eq!(assistant[1]["content"]["tool_references"], serde_json::json!([]));
        assert_eq!(assistant[2]["type"], "text");
        assert!(assistant[2]["text"].as_str().unwrap().contains("WebFetch"), "{}", assistant[2]);
        // The search that also found Read keeps Read, with no notice beside it.
        assert_eq!(assistant[3]["type"], "server_tool_use");
        assert_eq!(
            assistant[4]["content"]["tool_references"],
            serde_json::json!([{"type": "tool_reference", "tool_name": "Read"}])
        );
        assert_eq!(assistant[5]["type"], "tool_use");

        let tool_result = &body["messages"][2]["content"][0];
        assert_eq!(tool_result["cache_control"]["type"], "ephemeral");
        let parts = tool_result["content"].as_array().unwrap();
        assert_eq!(parts.len(), 1, "{parts:?}");
        assert_eq!(parts[0]["type"], "text");
        assert_eq!(parts[0]["text"], "[Tool Policy] No longer available, so not loaded: WebFetch.");

        assert_eq!(reference_edits(&result), vec![("remove".to_string(), "WebFetch".to_string()); 4]);
        assert!(result.flags.messages_modified);
    }

    /// The gateway repairs only what it changed: beside a blocked tool's
    /// reference, one to a tool the client never declared is the client's and
    /// goes as sent — and, remaining, takes no notice beside it.
    #[tokio::test]
    async fn a_reference_to_a_tool_the_client_never_declared_is_left_as_sent() {
        let mut request = looked_up_web_fetch_request("Grep");
        let result = transform_claude_code(&mut request, &[web_fetch_rule(serde_json::json!({"kind": "block"}))], &[]).await;
        assert_eq!(
            wire(&request)["messages"][2]["content"][0]["content"],
            serde_json::json!([{"type": "tool_reference", "tool_name": "Grep"}])
        );
        assert_eq!(reference_edits(&result), vec![("remove".to_string(), "WebFetch".to_string()); 3]);
    }

    /// A script renaming a tool in place keeps it declared under another
    /// name: its references follow, rather than being dropped as a removal.
    #[tokio::test]
    async fn a_script_renamed_tool_s_references_follow_it() {
        let mut request = looked_up_web_fetch_request("Read");
        let program = scoped_program(
            "tools",
            r#"fn transform(ctx) { for i in 0..ctx.tools.len() { if ctx.tools[i].name == "Read" { ctx.tools[i].name = "read_file"; } } ctx }"#,
        );
        let result = transform_claude_code(&mut request, &[], &[program]).await;
        let body = wire(&request);
        assert_eq!(body["messages"][1]["content"][3]["content"]["tool_references"][1]["tool_name"], "read_file");
        assert_eq!(body["messages"][2]["content"][0]["content"][1]["tool_name"], "read_file");
        assert_eq!(body["messages"][2]["content"][0]["content"][0]["tool_name"], "WebFetch");
        assert_eq!(reference_edits(&result), vec![("rename".to_string(), "Read → read_file".to_string()); 2]);
    }

    /// A script replacing a tool with a different one, keeping the list's
    /// length, has removed it: its references go, never onto the newcomer.
    #[tokio::test]
    async fn a_tool_a_script_replaced_is_not_read_as_renamed() {
        let mut request = looked_up_web_fetch_request("Read");
        let program = scoped_program(
            "tools",
            r#"fn transform(ctx) { for i in 0..ctx.tools.len() { if ctx.tools[i].name == "Read" { ctx.tools[i].name = "grep"; ctx.tools[i].description = "Search files."; } } ctx }"#,
        );
        let result = transform_claude_code(&mut request, &[], &[program]).await;
        let body = wire(&request);
        assert_eq!(
            body["messages"][1]["content"][3]["content"]["tool_references"],
            serde_json::json!([{"type": "tool_reference", "tool_name": "WebFetch"}])
        );
        assert_eq!(reference_edits(&result), vec![("remove".to_string(), "Read".to_string()); 2]);
    }

    /// A Claude Code request before the model looked anything up: the
    /// deferred tools are only listed, in a system-role message, the way
    /// Claude Code 2.1.308 writes the list.
    fn deferred_list_request(listed: &[&str]) -> ApiRequest {
        let list = format!(
            "# Environment\nYou are powered by a model.\n\nThe following deferred tools are now available via ToolSearch. \
             Their schemas are NOT loaded — calling them directly will fail with InputValidationError. Use ToolSearch \
             with query \"select:<name>[,<name>...]\" to load tool schemas before calling them:\nCronCreate\n{}\n\n\
             Available agent types for the Agent tool:\n- claude: Catch-all.",
            listed.join("\n")
        );
        let body = serde_json::json!({
            "model": "claude-opus-4-8",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "fetch https://example.com"}]},
                {"role": "system", "content": [{"type": "text", "text": list}]}
            ],
            "tools": [
                {"name": "ToolSearch", "description": "Load deferred tools.", "input_schema": {"type": "object"}},
                {"name": "DeferredToolPlaceholder", "description": "Never call.", "defer_loading": true,
                 "input_schema": {"type": "object", "properties": {}}}
            ]
        });
        ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &Bytes::from(body.to_string())).unwrap()
    }

    /// A tool the client lists as deferred and has not declared can be called
    /// by name; a substitute rule matching it declares the substitute, loaded,
    /// and binds the listed name, so a call under either name is the gateway's.
    #[tokio::test]
    async fn a_listed_deferred_tool_is_bound_to_its_substitute() {
        let mut request = deferred_list_request(&["WebFetch", "WebSearch"]);
        let result = transform_claude_code(&mut request, &[web_fetch_rule(substitute_web_fetch())], &[]).await;

        let body = wire(&request);
        let fetch: Vec<_> = body["tools"].as_array().unwrap().iter().filter(|t| t["name"] == "web_fetch").collect();
        assert_eq!(fetch.len(), 1, "{}", body["tools"]);
        assert!(fetch[0].get("defer_loading").is_none(), "{}", fetch[0]);
        assert_eq!(fetch[0]["input_schema"]["required"], serde_json::json!(["url"]));
        assert_eq!(result.intercept_bindings.len(), 1, "{:?}", result.intercept_bindings);
        let binding = &result.intercept_bindings[0];
        assert_eq!((binding.original_name.as_str(), binding.replaced_name.as_str()), ("WebFetch", "web_fetch"));
        assert_eq!(binding.rule_id, "R-FETCH");
        assert!(result.injection_blocks.iter().any(|b| b.action == "substitute" && b.content == "WebFetch (deferred) → web_fetch"));
    }

    /// A request that withheld the tool does not list it, so nothing is
    /// declared in its place; and once the client declares the tool, the
    /// ordinary substitution handles it, declaring the substitute once.
    #[tokio::test]
    async fn only_a_listed_undeclared_tool_is_bound() {
        let mut withheld = deferred_list_request(&["WebSearch"]);
        let result = transform_claude_code(&mut withheld, &[web_fetch_rule(substitute_web_fetch())], &[]).await;
        assert!(result.intercept_bindings.is_empty(), "{:?}", result.intercept_bindings);
        assert!(!wire(&withheld)["tools"].as_array().unwrap().iter().any(|t| t["name"] == "web_fetch"));

        let mut looked_up = looked_up_web_fetch_request("Read");
        let ApiRequest::AnthropicMessages(req) = &mut looked_up else { unreachable!() };
        req.messages.push(crate::api::messages::AnthropicMessage {
            role: "system".into(),
            content: crate::api::messages::AnthropicContent::Text(
                "The following deferred tools are now available via ToolSearch:\nWebFetch\n".into(),
            ),
        });
        let result = transform_claude_code(&mut looked_up, &[web_fetch_rule(substitute_web_fetch())], &[]).await;
        let names: Vec<_> = wire(&looked_up)["tools"].as_array().unwrap().iter().map(|t| t["name"].clone()).collect();
        assert_eq!(names.iter().filter(|n| **n == "web_fetch").count(), 1, "{names:?}");
        assert_eq!(result.intercept_bindings.len(), 1, "{:?}", result.intercept_bindings);
    }

    /// A listed tool is never bound where the client offers no tool, nor
    /// where a block denies it — whether the block removed the client's
    /// declaration or would have matched the listed name: a block wins over a
    /// substitution, as on a declared tool.
    #[tokio::test]
    async fn a_deferred_tool_is_not_bound_where_no_tool_is_offered_or_a_block_denies_it() {
        let block = || {
            let mut rule = web_fetch_rule(serde_json::json!({"kind": "block"}));
            rule.id = "R-BLOCK".into();
            rule
        };
        let fetch_declared = |request: &ApiRequest| {
            wire(request)["tools"].as_array().into_iter().flatten().any(|t| t["name"] == "web_fetch")
        };

        let mut no_tools = deferred_list_request(&["WebFetch"]);
        let ApiRequest::AnthropicMessages(req) = &mut no_tools else { unreachable!() };
        req.tools = None;
        let result = transform_claude_code(&mut no_tools, &[web_fetch_rule(substitute_web_fetch())], &[]).await;
        assert!(result.intercept_bindings.is_empty() && !fetch_declared(&no_tools), "{:?}", result.intercept_bindings);

        let mut listed = deferred_list_request(&["WebFetch"]);
        let result = transform_claude_code(&mut listed, &[block(), web_fetch_rule(substitute_web_fetch())], &[]).await;
        assert!(result.intercept_bindings.is_empty() && !fetch_declared(&listed), "{:?}", result.intercept_bindings);

        let mut declared_and_listed = looked_up_web_fetch_request("Read");
        let ApiRequest::AnthropicMessages(req) = &mut declared_and_listed else { unreachable!() };
        req.messages.push(crate::api::messages::AnthropicMessage {
            role: "system".into(),
            content: crate::api::messages::AnthropicContent::Text(
                "The following deferred tools are now available via ToolSearch:\nWebFetch\n".into(),
            ),
        });
        let result =
            transform_claude_code(&mut declared_and_listed, &[block(), web_fetch_rule(substitute_web_fetch())], &[]).await;
        assert!(result.intercept_bindings.is_empty(), "{:?}", result.intercept_bindings);
        assert!(!fetch_declared(&declared_and_listed));
        assert!(result.blocked_tools.iter().any(|b| b.name == "WebFetch"));
    }

    /// A block matching a tool the client only lists as deferred names it in
    /// the notice and among the blocked tools, with its rule — the list the
    /// answer refuses calls by; a listed tool no block matches is left alone,
    /// a declared tool the block removed is named once, and a request that
    /// declares no tools is left alone.
    #[tokio::test]
    async fn a_blocked_deferred_tool_is_named_and_its_rule_reaches_the_answer() {
        let block = || web_fetch_rule(serde_json::json!({"kind": "block"}));
        let blocked = |result: &TransformResult| {
            result.blocked_tools.iter().map(|b| b.name.clone()).collect::<Vec<_>>()
        };

        let mut listed = deferred_list_request(&["WebFetch", "WebSearch"]);
        let result = transform_claude_code(&mut listed, &[block()], &[]).await;
        assert_eq!(blocked(&result), ["WebFetch"]);
        assert_eq!(result.blocked_tools[0].rule_id, "R-FETCH");
        assert_eq!(result.withheld_tools.iter().map(|b| b.name.as_str()).collect::<Vec<_>>(), ["WebFetch"]);
        let body = wire(&listed).to_string();
        assert!(body.contains("- WebFetch: Web fetch is the gateway's"), "{body}");
        assert!(!body.contains("- WebSearch:"), "{body}");
        assert!(result.injection_blocks.iter().any(|b| b.action == "remove" && b.content == "WebFetch (deferred)"));

        // Positive control: with no block, nothing is named or withheld.
        let mut unblocked = deferred_list_request(&["WebFetch", "WebSearch"]);
        let result = transform_claude_code(&mut unblocked, &[], &[]).await;
        assert!(blocked(&result).is_empty());
        assert!(!wire(&unblocked).to_string().contains("[Tool Policy]"));

        let mut no_tools = deferred_list_request(&["WebFetch"]);
        let ApiRequest::AnthropicMessages(req) = &mut no_tools else { unreachable!() };
        req.tools = None;
        let result = transform_claude_code(&mut no_tools, &[block()], &[]).await;
        assert!(blocked(&result).is_empty());
        assert!(!wire(&no_tools).to_string().contains("[Tool Policy]"));

        let mut declared_and_listed = looked_up_web_fetch_request("Read");
        let ApiRequest::AnthropicMessages(req) = &mut declared_and_listed else { unreachable!() };
        req.messages.push(crate::api::messages::AnthropicMessage {
            role: "system".into(),
            content: crate::api::messages::AnthropicContent::Text(
                "The following deferred tools are now available via ToolSearch:\nWebFetch\n".into(),
            ),
        });
        let result = transform_claude_code(&mut declared_and_listed, &[block()], &[]).await;
        assert_eq!(blocked(&result), ["WebFetch"]);
    }
}
