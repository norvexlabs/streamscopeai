//! Request-phase policy evaluation for MCP traffic.
//!
//! Hooks the unified rule evaluator (in `streamscope_core::config::risk`) into
//! the MCP dispatcher so the same `tool_id`-pivoted rules that gate the LLM
//! path also gate `tools/call`, `resources/read`, and `prompts/get` on the
//! MCP path. The unification proof: one rule with `tool_id=read_file` fires
//! identically whether the call arrives as an LLM-emitted tool_use block or
//! as an MCP `tools/call`.
//!
//! `mcp_server` is stamped from the route mapping (the
//! upstream's `name` column) — NEVER from the wire prefix the agent supplied
//! — so an agent can't impersonate a different upstream by spoofing a
//! namespace prefix.
//!
//! Scope mapping per inbound JSON-RPC method:
//!
//! | Method            | Scope used for rule eval        | Lifecycle |
//! |-------------------|---------------------------------|-----------|
//! | `tools/call`      | `tool_calls`                    | response  |
//! | `resources/read`  | `resource_reads`                | request   |
//! | `prompts/get`     | `prompt_invocations`            | request   |
//!
//! `tools/call` shares the rule scope with the LLM path's `(response,
//! tool_calls)` rules — same evaluator, same canonical `tool_id`, same
//! action semantics. The "phase" axis is the lifecycle anchor for the
//! existing rule shape, not the wire-direction of this specific request.

use serde_json::Value;
use streamscope_core::config::mcp::McpVirtualRoute;
use streamscope_core::config::tool_rules::{
    self, FieldProfileSet, Phase, PromptInvocationResolver, ResourceReadResolver, RiskResult,
    Rule, RuleAxes, Scope, ToolCallResolver,
};

use super::jsonrpc::{JsonRpcRequest, McpScope, classify_method};
use super::virtualize;

/// Outcome of running policy on an inbound MCP request. The handler dispatches
/// based on the variant.
#[derive(Debug)]
pub enum PolicyDecision {
    /// No matching rule, or only a `Classify` rule fired. The carried
    /// [`RiskResult`] surfaces in the audit row when its action is
    /// `"classify"`; for fully-unmatched requests it's the synthetic
    /// `"allow"` fallback (still useful for `tool_id` capture).
    Allow(Option<RiskResult>),
    /// A `Block` rule matched. The handler returns JSON-RPC
    /// [`MCP_BLOCKED_BY_POLICY`](super::jsonrpc::MCP_BLOCKED_BY_POLICY) with
    /// `message`, and stamps the audit row with the rule id from `result`.
    Block { result: RiskResult, message: String },
    /// A `Replace` rule matched. The dispatcher rewrites `params` to the
    /// supplied `mutated_params` before calling the upstream. The audit
    /// row stamps the rule id from `result`.
    Replace {
        result: RiskResult,
        mutated_params: Value,
    },
}

/// Per-call inputs the dispatcher already has on hand. Bundled for the policy
/// evaluator so the call site stays one line.
pub struct PolicyContext<'a> {
    /// Resolved field-profile registry (the same snapshot the LLM proxy
    /// uses). `None` would skip every `tool_id`/`arg.<f>` resolution and is
    /// only sensible for unit tests.
    pub field_profiles: Option<&'a FieldProfileSet>,
    /// Operator-curated rule snapshot.
    pub rules: &'a [Rule],
    /// Authoritative upstream identifier — stamped from the resolved route's
    /// upstream name. Using the wire prefix the agent supplied is explicitly
    /// forbidden: an agent can't spoof an `mcp_server` they aren't actually
    /// talking to.
    pub mcp_server: &'a str,
    /// Resolved app_id (Claude Desktop / Cursor / Cline / Continue MCP / ...).
    /// `None` when attribution didn't recognise the User-Agent.
    pub app_id: Option<&'a str>,
}

/// Evaluate the inbound request against the rule set. Caller dispatches on
/// the returned [`PolicyDecision`].
pub fn evaluate_request(
    ctx: &PolicyContext<'_>,
    request: &JsonRpcRequest,
    routes: &[McpVirtualRoute],
) -> PolicyDecision {
    let scope = classify_method(&request.method);
    match scope {
        McpScope::ToolCall => evaluate_tool_call(ctx, request, routes),
        // Subscribe/unsubscribe carry `params.uri` in the same shape as
        // resources/read and target the same resources, so the same
        // `Scope::ResourceReads` rules apply. Without this, an operator's
        // `Scope::ResourceReads` block rule (e.g. blocking `file:///etc/passwd`)
        // would be ineffective against an agent that subscribes instead of
        // reading. Audit identity is preserved — the resolved upstream and
        // the decoded `resource_uri` round-trip through the same audit row.
        McpScope::ResourceRead
        | McpScope::ResourceSubscribe
        | McpScope::ResourceUnsubscribe => evaluate_resource_read(ctx, request),
        McpScope::PromptGet => evaluate_prompt_get(ctx, request, routes),
        // `completion/complete` is per-ref-type: a ref/resource targets a
        // resource URI (same gating surface as resources/read), and a
        // ref/prompt targets a prompt name (same gating surface as
        // prompts/get). Synthesize the per-scope params shape from the ref
        // and reuse the existing evaluators rather than maintaining two
        // duplicate code paths. Without this, agents could probe denied
        // resources/prompts via completion/* and observe argument-completion
        // suggestions even when the underlying read/get is blocked.
        McpScope::CompletionComplete => evaluate_completion_complete(ctx, request, routes),
        _ => PolicyDecision::Allow(None),
    }
}

/// Synthesize a `{uri: ...}` or `{name: ...}` params shape from the
/// completion ref and delegate to the matching evaluator. ref types other
/// than `ref/prompt` and `ref/resource` allow through — the dispatcher
/// rejects them with `-32600` before they reach this code path, so this
/// fallback only matters if someone re-orders dispatch in the future.
fn evaluate_completion_complete(
    ctx: &PolicyContext<'_>,
    request: &JsonRpcRequest,
    routes: &[McpVirtualRoute],
) -> PolicyDecision {
    let Some(ref_obj) = request
        .params
        .as_ref()
        .and_then(|p| p.get("ref"))
        .and_then(Value::as_object)
    else {
        return PolicyDecision::Allow(None);
    };
    let ref_type = ref_obj.get("type").and_then(Value::as_str).unwrap_or("");
    let decision = match ref_type {
        "ref/resource" => {
            let Some(uri) = ref_obj.get("uri").and_then(Value::as_str) else {
                return PolicyDecision::Allow(None);
            };
            let synthetic = JsonRpcRequest {
                jsonrpc: request.jsonrpc.clone(),
                id: request.id.clone(),
                method: "resources/read".into(),
                params: Some(serde_json::json!({"uri": uri})),
            };
            evaluate_resource_read(ctx, &synthetic)
        }
        "ref/prompt" => {
            let Some(name) = ref_obj.get("name").and_then(Value::as_str) else {
                return PolicyDecision::Allow(None);
            };
            let synthetic = JsonRpcRequest {
                jsonrpc: request.jsonrpc.clone(),
                id: request.id.clone(),
                method: "prompts/get".into(),
                params: Some(serde_json::json!({"name": name})),
            };
            evaluate_prompt_get(ctx, &synthetic, routes)
        }
        _ => PolicyDecision::Allow(None),
    };
    // A rewrite names the params of the read or the get it was written for;
    // a completion carries a `ref` and a partial `argument` instead, so the
    // synthesized params cannot stand in for its own. A rewrite may be a
    // drop, so the completion is refused rather than let through unrewritten
    // — whether the rewrite applied to the synthesized params or failed on
    // them. The refusal is a block on the audit row too: it carries `block`,
    // which is what the blocked badge and the blocked-by-rule panel read.
    match decision {
        PolicyDecision::Replace { mut result, .. } | PolicyDecision::Block { mut result, .. }
            if result.action == "replace" =>
        {
            let summary = result
                .title
                .as_deref()
                .or(result.description.as_deref())
                .unwrap_or("a rewrite rule");
            let message = block_message(
                "completion",
                result.id.as_deref(),
                &format!("{summary} (a rewrite rule; a completion cannot be rewritten)"),
            );
            result.action = "block".to_string();
            PolicyDecision::Block { message, result }
        }
        other => other,
    }
}

fn evaluate_tool_call(
    ctx: &PolicyContext<'_>,
    request: &JsonRpcRequest,
    routes: &[McpVirtualRoute],
) -> PolicyDecision {
    let Some(params) = request.params.as_ref() else {
        return PolicyDecision::Allow(None);
    };
    let Some(wire_name) = params.get("name").and_then(Value::as_str) else {
        return PolicyDecision::Allow(None);
    };
    let arguments = params.get("arguments");

    // The wire tool name on `/mcp/<slug>` carries the namespace prefix when
    // the route stamped one. Resolve it exactly as the dispatcher does, so the
    // rules judge the name the upstream will receive.
    let local_name =
        virtualize::route_for_name(routes, wire_name).map_or(wire_name, |(_, local)| local);

    // Stage C precedence: rule eval needs the canonical tool_id (resolved via
    // field profile), the wire/effective name (for `arg.<f>` lookups inside
    // the resolver), and the authoritative `mcp_server`.
    let lookup = ctx.field_profiles.and_then(|set| {
        set.resolve_tool_id_with_profile(local_name, ctx.app_id, Some(ctx.mcp_server))
    });
    let tool_id = lookup.as_ref().map(|m| m.tool_id.clone());
    let profile_id = lookup.as_ref().and_then(|m| m.profile_id.clone());

    // MCP traffic carries no `model` axis (the MCP server isn't an LLM), so
    // we pass `None` for `model`. By the contract of `extract_for`, any rule
    // with `model_filter` set is silently filtered out. Operators authoring
    // `(response, tool_calls)` rules that should fire on BOTH paths must
    // leave `model_filter = null`. The rule editor surfaces this in copy.
    let scoped = tool_rules::extract_for(
        ctx.rules,
        Phase::Response,
        Scope::ToolCalls,
        RuleAxes {
            app_id: ctx.app_id,
            mcp_server: Some(ctx.mcp_server),
            ..Default::default()
        },
    );
    if scoped.is_empty() {
        return PolicyDecision::Allow(synthetic_unknown_opt(tool_id, profile_id));
    }
    let tool_id_for_resolver = tool_id.clone();
    let resolver = ToolCallResolver {
        name: local_name,
        arguments,
        field_profiles: ctx.field_profiles,
        app_id: ctx.app_id,
        mcp_server: Some(ctx.mcp_server),
        tool_id: tool_id_for_resolver.as_deref(),
    };
    finish_tool_decision(&scoped, &resolver, tool_id, profile_id, params, arguments)
}

fn evaluate_resource_read(
    ctx: &PolicyContext<'_>,
    request: &JsonRpcRequest,
) -> PolicyDecision {
    let Some(params) = request.params.as_ref() else {
        return PolicyDecision::Allow(None);
    };
    let Some(raw_uri) = params.get("uri").and_then(Value::as_str) else {
        return PolicyDecision::Allow(None);
    };
    // Operators write rules against upstream URIs (`file://`, `notion://`, …)
    // — the gateway-internal `stsmcp://` envelope is just transport. Decode
    // first so profile lookups + rule matches see the real URI. Verbatim
    // pass-through when the URI is not virtualized (legacy agents, internal
    // probes, tests).
    let decoded = streamscope_core::mcp::tokens::decode_resource_uri(raw_uri).ok();
    let virt_prefix = decoded.as_ref().map(|(p, _)| p.clone());
    let uri_decoded = decoded.map(|(_, original)| original);
    let uri = uri_decoded.as_deref().unwrap_or(raw_uri);
    let arguments = params.get("arguments");

    let lookup = ctx.field_profiles.and_then(|set| {
        set.resolve_tool_id_with_profile(uri, ctx.app_id, Some(ctx.mcp_server))
    });
    let resource_id = lookup.as_ref().map(|m| m.tool_id.clone());
    let profile_id = lookup.as_ref().and_then(|m| m.profile_id.clone());

    let scoped = tool_rules::extract_for(
        ctx.rules,
        Phase::Request,
        Scope::ResourceReads,
        RuleAxes {
            app_id: ctx.app_id,
            mcp_server: Some(ctx.mcp_server),
            ..Default::default()
        },
    );
    if scoped.is_empty() {
        return PolicyDecision::Allow(synthetic_unknown_opt(resource_id, profile_id));
    }
    let resource_id_for_resolver = resource_id.clone();
    let resolver = ResourceReadResolver {
        resource_id: resource_id_for_resolver.as_deref(),
        uri,
        arguments,
        content: "",
        field_profiles: ctx.field_profiles,
        app_id: ctx.app_id,
        mcp_server: Some(ctx.mcp_server),
    };
    finish_uri_decision(
        &scoped,
        &resolver,
        resource_id,
        profile_id,
        params,
        arguments,
        uri,
        virt_prefix.as_deref(),
    )
}

fn evaluate_prompt_get(
    ctx: &PolicyContext<'_>,
    request: &JsonRpcRequest,
    routes: &[McpVirtualRoute],
) -> PolicyDecision {
    let Some(params) = request.params.as_ref() else {
        return PolicyDecision::Allow(None);
    };
    let Some(wire_name) = params.get("name").and_then(Value::as_str) else {
        return PolicyDecision::Allow(None);
    };
    // Judged under the name the upstream receives, as a tool call is.
    let name = virtualize::route_for_name(routes, wire_name).map_or(wire_name, |(_, local)| local);
    let arguments = params.get("arguments");

    let lookup = ctx.field_profiles.and_then(|set| {
        set.resolve_tool_id_with_profile(name, ctx.app_id, Some(ctx.mcp_server))
    });
    let prompt_id = lookup.as_ref().map(|m| m.tool_id.clone());
    let profile_id = lookup.as_ref().and_then(|m| m.profile_id.clone());

    let scoped = tool_rules::extract_for(
        ctx.rules,
        Phase::Request,
        Scope::PromptInvocations,
        RuleAxes {
            app_id: ctx.app_id,
            mcp_server: Some(ctx.mcp_server),
            ..Default::default()
        },
    );
    if scoped.is_empty() {
        return PolicyDecision::Allow(synthetic_unknown_opt(prompt_id, profile_id));
    }
    let prompt_id_for_resolver = prompt_id.clone();
    let resolver = PromptInvocationResolver {
        prompt_id: prompt_id_for_resolver.as_deref(),
        name,
        arguments,
        field_profiles: ctx.field_profiles,
        app_id: ctx.app_id,
        mcp_server: Some(ctx.mcp_server),
    };
    finish_prompt_decision(&scoped, &resolver, prompt_id, profile_id, params, arguments)
}

// ─── Decision finalizers ────────────────────────────────────────────

/// Walk `scoped` rules until one fires; convert the firing rule to a
/// [`PolicyDecision`] using the supplied resolver and the original `params`
/// shape. Replace rewrites the joined-text content for tool_calls (the args
/// JSON) — Block surfaces a JSON-RPC error message; Classify lifts the rule
/// id into the audit row without mutating dispatch.
///
/// A shell tool's call that only applies a patch is also read as the patch
/// tool, and that reading can only add a block to the call's own decision
/// (`tool_rules::patch_block`).
fn finish_tool_decision(
    scoped: &[&Rule],
    resolver: &ToolCallResolver<'_>,
    tool_id: Option<String>,
    profile_id: Option<String>,
    params: &Value,
    arguments: Option<&Value>,
) -> PolicyDecision {
    let own = own_tool_decision(scoped, resolver, tool_id.clone(), profile_id.clone(), params, arguments);
    if matches!(own, PolicyDecision::Block { .. }) {
        return own;
    }
    match tool_rules::patch_block(scoped, resolver) {
        Some(rule) => PolicyDecision::Block {
            message: format_block_message(rule, "tool"),
            result: rule_to_result(rule, tool_id, profile_id),
        },
        _ => own,
    }
}

/// The call's own decision: the first of `scoped` that fires.
fn own_tool_decision(
    scoped: &[&Rule],
    resolver: &ToolCallResolver<'_>,
    tool_id: Option<String>,
    profile_id: Option<String>,
    params: &Value,
    arguments: Option<&Value>,
) -> PolicyDecision {
    for rule in scoped {
        if !tool_rules::evaluate(rule, resolver) {
            continue;
        }
        return match &rule.action {
            tool_rules::RuleAction::Block => PolicyDecision::Block {
                message: format_block_message(rule, "tool"),
                result: rule_to_result(rule, tool_id, profile_id),
            },
            tool_rules::RuleAction::Replace { .. } => match mutate_tool_call_args(params, arguments, &rule.action) {
                ArgsMutation::Mutated(mutated_params) => PolicyDecision::Replace {
                    mutated_params,
                    result: rule_to_result(rule, tool_id, profile_id),
                },
                ArgsMutation::RewriteFailed(reason) => PolicyDecision::Block {
                    message: format!("policy replace failed ({reason}); blocking to avoid silent data loss"),
                    result: rule_to_result(rule, tool_id, profile_id),
                },
            },
            tool_rules::RuleAction::Classify => PolicyDecision::Allow(Some(rule_to_result(
                rule,
                tool_id.clone(),
                profile_id.clone(),
            ))),
            // Tool-definition rewrite actions don't apply at the MCP
            // tools/call evaluation phase.
            tool_rules::RuleAction::Substitute { .. }
            | tool_rules::RuleAction::InterceptOnly { .. } => continue,
        };
    }
    PolicyDecision::Allow(if tool_id.is_some() {
        Some(synthetic_unknown(tool_id, profile_id))
    } else {
        None
    })
}

#[allow(clippy::too_many_arguments)]
fn finish_uri_decision(
    scoped: &[&Rule],
    resolver: &ResourceReadResolver<'_>,
    resource_id: Option<String>,
    profile_id: Option<String>,
    params: &Value,
    arguments: Option<&Value>,
    uri: &str,
    virt_prefix: Option<&str>,
) -> PolicyDecision {
    for rule in scoped {
        if !tool_rules::evaluate(rule, resolver) {
            continue;
        }
        return match &rule.action {
            tool_rules::RuleAction::Block => PolicyDecision::Block {
                message: format_block_message(rule, "resource"),
                result: rule_to_result(rule, resource_id, profile_id),
            },
            tool_rules::RuleAction::Replace { .. } => {
                // For resource_reads, Replace rewrites the URI itself by
                // default — the URI carries the resource identity, and the
                // `with`/`drop` semantics map cleanly onto a wholesale URI
                // rewrite. `arg.<f>` rewrites are also surfaced through the
                // params object so a regex-Replace targeting an arg field
                // doesn't silently disappear.
                let mutated_params =
                    mutate_resource_read(params, arguments, uri, virt_prefix, &rule.action);
                PolicyDecision::Replace {
                    mutated_params,
                    result: rule_to_result(rule, resource_id, profile_id),
                }
            }
            tool_rules::RuleAction::Classify => PolicyDecision::Allow(Some(rule_to_result(
                rule,
                resource_id.clone(),
                profile_id.clone(),
            ))),
            tool_rules::RuleAction::Substitute { .. }
            | tool_rules::RuleAction::InterceptOnly { .. } => continue,
        };
    }
    PolicyDecision::Allow(if resource_id.is_some() {
        Some(synthetic_unknown(resource_id, profile_id))
    } else {
        None
    })
}

fn finish_prompt_decision(
    scoped: &[&Rule],
    resolver: &PromptInvocationResolver<'_>,
    prompt_id: Option<String>,
    profile_id: Option<String>,
    params: &Value,
    arguments: Option<&Value>,
) -> PolicyDecision {
    for rule in scoped {
        if !tool_rules::evaluate(rule, resolver) {
            continue;
        }
        return match &rule.action {
            tool_rules::RuleAction::Block => PolicyDecision::Block {
                message: format_block_message(rule, "prompt"),
                result: rule_to_result(rule, prompt_id, profile_id),
            },
            tool_rules::RuleAction::Replace { .. } => match mutate_prompt_args(params, arguments, &rule.action) {
                ArgsMutation::Mutated(mutated_params) => PolicyDecision::Replace {
                    mutated_params,
                    result: rule_to_result(rule, prompt_id, profile_id),
                },
                ArgsMutation::RewriteFailed(reason) => PolicyDecision::Block {
                    message: format!("policy replace failed ({reason}); blocking to avoid silent data loss"),
                    result: rule_to_result(rule, prompt_id, profile_id),
                },
            },
            tool_rules::RuleAction::Classify => PolicyDecision::Allow(Some(rule_to_result(
                rule,
                prompt_id.clone(),
                profile_id.clone(),
            ))),
            tool_rules::RuleAction::Substitute { .. }
            | tool_rules::RuleAction::InterceptOnly { .. } => continue,
        };
    }
    PolicyDecision::Allow(if prompt_id.is_some() {
        Some(synthetic_unknown(prompt_id, profile_id))
    } else {
        None
    })
}

// ─── Helpers ────────────────────────────────────────────────────────

fn rule_to_result(rule: &Rule, tool_id: Option<String>, profile_id: Option<String>) -> RiskResult {
    RiskResult {
        id: Some(rule.id.clone()),
        risk: rule.risk.clone(),
        title: rule.title.clone(),
        description: rule.description.clone(),
        action: action_str(&rule.action),
        pattern: None,
        profile_id,
        tool_id,
    }
}

fn synthetic_unknown(tool_id: Option<String>, profile_id: Option<String>) -> RiskResult {
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

/// Same as [`synthetic_unknown`] but returns `None` when there's no
/// tool/resource/prompt id to capture — used by the fast-path "no rules in
/// scope" branch where building the synthetic result has no audit value.
fn synthetic_unknown_opt(
    tool_id: Option<String>,
    profile_id: Option<String>,
) -> Option<RiskResult> {
    if tool_id.is_some() {
        Some(synthetic_unknown(tool_id, profile_id))
    } else {
        None
    }
}

fn action_str(a: &tool_rules::RuleAction) -> String {
    match a {
        tool_rules::RuleAction::Classify => "classify".to_string(),
        tool_rules::RuleAction::Block => "block".to_string(),
        tool_rules::RuleAction::Replace { .. } => "replace".to_string(),
        tool_rules::RuleAction::Substitute { .. } => "substitute".to_string(),
        tool_rules::RuleAction::InterceptOnly { .. } => "intercept_only".to_string(),
    }
}

/// Compose the `message` field surfaced in the JSON-RPC error body. The
/// rule's `title` (or `description`) feeds the operator-visible reason;
/// without either, fall back to a generic "blocked by tool policy".
fn format_block_message(rule: &Rule, kind: &str) -> String {
    let summary = rule
        .title
        .as_deref()
        .or(rule.description.as_deref())
        .unwrap_or("blocked by tool policy");
    block_message(kind, Some(rule.id.as_str()), summary)
}

/// The one grammar of a policy refusal's message.
fn block_message(kind: &str, rule_id: Option<&str>, summary: &str) -> String {
    match rule_id {
        Some(id) => format!("{kind} blocked by policy ({id}): {summary}"),
        None => format!("{kind} blocked by policy: {summary}"),
    }
}

/// Outcome of applying a Replace action to a tool_call / prompt_get
/// arguments object. The dispatcher branches on this — `Mutated` proceeds
/// with the rewritten params; `RewriteFailed` becomes a Block (fail-closed:
/// nothing is silently discarded).
enum ArgsMutation {
    Mutated(Value),
    /// The rule's regex/with/drop didn't round-trip through JSON. We refuse
    /// to silently empty the args (data loss) and refuse to silently send
    /// the un-rewritten original (operator intent ignored).
    RewriteFailed(&'static str),
}

/// For `tools/call`: rewrite `params.arguments` per the rule's Replace
/// action. Wholesale `with`/`drop` actions replace the whole arguments
/// object; regex-bearing actions stringify the arguments JSON, run the
/// regex, and parse the result back. Drop returns an empty object (the
/// rule explicitly opted into that). Failure to parse the regex result as
/// JSON returns [`ArgsMutation::RewriteFailed`] — the caller converts that
/// into a Block so the operator's broken regex never silently corrupts a
/// dispatch.
fn mutate_tool_call_args(
    params: &Value,
    arguments: Option<&Value>,
    action: &tool_rules::RuleAction,
) -> ArgsMutation {
    let original_args = arguments.cloned().unwrap_or(Value::Object(Default::default()));
    let original_text = original_args.to_string();
    let Some(rewritten) = tool_rules::apply_replacement(action, &original_text) else {
        return ArgsMutation::RewriteFailed("rule.replace produced no output");
    };
    if rewritten.is_empty()
        && matches!(action, tool_rules::RuleAction::Replace { drop: true, .. })
    {
        // Drop semantics — empty args is the explicit operator intent.
        return ArgsMutation::Mutated(rewrite_params_args(
            params,
            Value::Object(Default::default()),
        ));
    }
    match serde_json::from_str::<Value>(&rewritten) {
        Ok(parsed) => ArgsMutation::Mutated(rewrite_params_args(params, parsed)),
        Err(_) => ArgsMutation::RewriteFailed(
            "rule.replace output is not valid JSON — refusing to drop original args",
        ),
    }
}

fn rewrite_params_args(params: &Value, new_args: Value) -> Value {
    let mut new_params = params.clone();
    if let Some(obj) = new_params.as_object_mut() {
        obj.insert("arguments".to_string(), new_args);
    }
    new_params
}

/// For `resources/read`: rewrite the URI per the rule's Replace action.
/// `original_uri` is the **decoded** upstream URI the rule operated on.
/// When the inbound request carried a virtualized `stsmcp://<prefix>/<…>`
/// URI, `virt_prefix` carries the route prefix so we can re-encode the
/// mutated URI; the dispatcher's strict `decode_resource_uri` would
/// otherwise reject the rewritten params with `-32001`.
fn mutate_resource_read(
    params: &Value,
    _arguments: Option<&Value>,
    original_uri: &str,
    virt_prefix: Option<&str>,
    action: &tool_rules::RuleAction,
) -> Value {
    let mutated_uri =
        tool_rules::apply_replacement(action, original_uri).unwrap_or_else(|| original_uri.to_string());
    let wire_uri = match virt_prefix {
        Some(prefix) => streamscope_core::mcp::tokens::encode_resource_uri(prefix, &mutated_uri),
        None => mutated_uri,
    };
    let mut new_params = params.clone();
    if let Some(obj) = new_params.as_object_mut() {
        obj.insert("uri".to_string(), Value::String(wire_uri));
    }
    new_params
}

/// For `prompts/get`: rewrite `params.arguments` (template args). Same
/// shape and fail-closed contract as the tool_call mutator.
fn mutate_prompt_args(
    params: &Value,
    arguments: Option<&Value>,
    action: &tool_rules::RuleAction,
) -> ArgsMutation {
    mutate_tool_call_args(params, arguments, action)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use super::super::virtualize::tests::route;
    use serde_json::json;
    use streamscope_core::config::tool_rules::{
        FieldProfile, MatchCondition, Op, RuleAction,
    };
    use streamscope_core::config::tool_rules_normalize::Normalizer;

    fn rule_block_tool_id(id: &str, tool_id: &str) -> Rule {
        Rule {
            id: id.into(),
            title: Some("test block".into()),
            description: Some("test".into()),
            risk: "danger".into(),
            phase: Phase::Response,
            scope: Scope::ToolCalls,
            conditions: vec![MatchCondition {
                target: "tool_id".into(),
                op: Op::Equals,
                value: json!(tool_id),
            }],
            action: RuleAction::Block,
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

    fn rule_block_resource(id: &str, uri_glob: &str) -> Rule {
        Rule {
            id: id.into(),
            title: Some("test block resource".into()),
            description: None,
            risk: "danger".into(),
            phase: Phase::Request,
            scope: Scope::ResourceReads,
            conditions: vec![MatchCondition {
                target: "uri".into(),
                op: Op::Glob,
                value: json!(uri_glob),
            }],
            action: RuleAction::Block,
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

    fn rule_block_prompt(id: &str, prompt_id: &str) -> Rule {
        Rule {
            id: id.into(),
            title: Some("test block prompt".into()),
            description: None,
            risk: "danger".into(),
            phase: Phase::Request,
            scope: Scope::PromptInvocations,
            conditions: vec![MatchCondition {
                target: "prompt_id".into(),
                op: Op::Equals,
                value: json!(prompt_id),
            }],
            action: RuleAction::Block,
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

    fn fp(tool_id: &str, tool_pattern: &str, mcp_server: Option<&str>) -> FieldProfile {
        FieldProfile {
            id: Some(format!("p-{tool_id}")),
            description: None,
            source: None,
            tool_id: tool_id.into(),
            tool_pattern: tool_pattern.into(),
            app_filter: None,
            mcp_server: mcp_server.map(str::to_string),
            server_type: None,
            field: "command".into(),
            wire_field: None,
            normalizer: Normalizer::Raw,
            priority: 100,
            is_builtin: false,
        }
    }

    fn make_request(method: &str, params: Value) -> JsonRpcRequest {
        JsonRpcRequest {
            jsonrpc: "2.0".into(),
            id: Some(super::super::jsonrpc::RpcId::Number(serde_json::Number::from(1))),
            method: method.into(),
            params: Some(params),
        }
    }

    #[test]
    fn unification_proof_tools_call_blocks_via_response_scope() {
        // The cornerstone of policy unification: a (response, tool_calls) rule
        // with `tool_id=read_file` must fire when an MCP `tools/call` arrives,
        // proving the same rule covers both LLM and MCP paths.
        let profile = fp("read_file", "read_file", Some("github"));
        let profiles = FieldProfileSet::new(vec![profile]);
        let rules = vec![rule_block_tool_id("ASI-RF-1", "read_file")];
        let req = make_request(
            "tools/call",
            json!({"name": "read_file", "arguments": {"path": "/etc/passwd"}}),
        );
        let ctx = PolicyContext {
            field_profiles: Some(&profiles),
            rules: &rules,
            mcp_server: "github",
            app_id: None,
        };
        match evaluate_request(&ctx, &req, &[]) {
            PolicyDecision::Block { result, .. } => {
                assert_eq!(result.id.as_deref(), Some("ASI-RF-1"));
                assert_eq!(result.tool_id.as_deref(), Some("read_file"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    /// A rule names the tool its upstream knows. The stamped name may carry
    /// more `_` and `__` than the prefix's own separator; the rule must judge
    /// the name the dispatcher forwards — and leave a sibling tool alone.
    #[test]
    fn a_rule_judges_the_name_the_route_forwards_under_any_prefix() {
        let profiles = FieldProfileSet::new(vec![fp("read_file", "read_file", Some("github"))]);
        let rules = vec![rule_block_tool_id("ASI-RF-1", "read_file")];
        let ctx = PolicyContext {
            field_profiles: Some(&profiles),
            rules: &rules,
            mcp_server: "github",
            app_id: None,
        };
        for prefix in ["", "gh", "g_h"] {
            let routes = vec![route(prefix)];
            let call = |tool: &str| {
                let name = if prefix.is_empty() { tool.to_string() } else { format!("{prefix}__{tool}") };
                make_request("tools/call", json!({"name": name, "arguments": {"path": "/etc/passwd"}}))
            };
            assert_matches!(
                evaluate_request(&ctx, &call("read_file"), &routes),
                PolicyDecision::Block { .. },
                "prefix {prefix:?}"
            );
            assert_matches!(
                evaluate_request(&ctx, &call("list_files"), &routes),
                PolicyDecision::Allow(_),
                "prefix {prefix:?}"
            );
        }
    }

    /// A prompt rule, like a tool rule, judges the name the upstream knows —
    /// on `prompts/get` and on a `completion/complete` `ref/prompt` alike.
    #[test]
    fn a_prompt_rule_judges_the_name_the_route_forwards_under_any_prefix() {
        let profiles = FieldProfileSet::new(vec![fp("guide", "guide", Some("docs"))]);
        let rules = vec![rule_block_prompt("ASI-PR-2", "guide")];
        let ctx = PolicyContext {
            field_profiles: Some(&profiles),
            rules: &rules,
            mcp_server: "docs",
            app_id: None,
        };
        for prefix in ["", "gh", "g_h"] {
            let routes = vec![route(prefix)];
            let requests = |prompt: &str| {
                let name = if prefix.is_empty() { prompt.to_string() } else { format!("{prefix}__{prompt}") };
                [
                    make_request("prompts/get", json!({"name": name})),
                    make_request(
                        "completion/complete",
                        json!({"ref": {"type": "ref/prompt", "name": name}, "argument": {"name": "a", "value": ""}}),
                    ),
                ]
            };
            for req in requests("guide") {
                assert_matches!(
                    evaluate_request(&ctx, &req, &routes),
                    PolicyDecision::Block { .. },
                    "prefix {prefix:?} {}",
                    req.method
                );
            }
            for req in requests("other") {
                assert_matches!(
                    evaluate_request(&ctx, &req, &routes),
                    PolicyDecision::Allow(_),
                    "prefix {prefix:?} {}",
                    req.method
                );
            }
        }
    }

    /// A rewrite rule that covers a prompt rewrites `prompts/get`, but a
    /// completion has no params it could rewrite: it is refused, never
    /// handed the get's synthesized params in place of its own.
    #[test]
    fn a_completion_a_rewrite_rule_covers_is_refused_not_rewritten() {
        let profiles = FieldProfileSet::new(vec![fp("guide", "guide", Some("docs"))]);
        let routes = vec![route("gh")];
        // A drop applies to the synthesized params; a regex that matches
        // nothing in them fails — both must come out as the same block.
        for action in [
            RuleAction::Replace { regex: None, with: None, drop: true },
            RuleAction::Replace { regex: Some("secret".into()), with: None, drop: false },
        ] {
            let mut rule = rule_block_prompt("ASI-PR-3", "guide");
            rule.action = action;
            let rules = vec![rule];
            let ctx = PolicyContext {
                field_profiles: Some(&profiles),
                rules: &rules,
                mcp_server: "docs",
                app_id: None,
            };
            let get = make_request("prompts/get", json!({"name": "gh__guide", "arguments": {"topic": "secret"}}));
            assert_matches!(evaluate_request(&ctx, &get, &routes), PolicyDecision::Replace { .. });
            let complete = make_request(
                "completion/complete",
                json!({"ref": {"type": "ref/prompt", "name": "gh__guide"}, "argument": {"name": "topic", "value": "x"}}),
            );
            match evaluate_request(&ctx, &complete, &routes) {
                PolicyDecision::Block { result, message } => {
                    assert_eq!(result.action, "block");
                    assert!(message.starts_with("completion blocked by policy (ASI-PR-3)"), "{message}");
                }
                other => panic!("expected Block, got {other:?}"),
            }
        }
    }

    #[test]
    fn resources_read_blocks_via_uri_glob() {
        let rules = vec![rule_block_resource("ASI-FILE-1", "file://etc/*")];
        let req = make_request(
            "resources/read",
            json!({"uri": "file://etc/passwd"}),
        );
        let ctx = PolicyContext {
            field_profiles: None,
            rules: &rules,
            mcp_server: "filesystem",
            app_id: None,
        };
        match evaluate_request(&ctx, &req, &[]) {
            PolicyDecision::Block { result, .. } => {
                assert_eq!(result.id.as_deref(), Some("ASI-FILE-1"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn prompts_get_blocks_via_prompt_id() {
        let profile = FieldProfile {
            id: Some("pp-coding-rules".into()),
            description: None,
            source: None,
            tool_id: "coding_rules".into(),
            tool_pattern: "coding-*".into(),
            app_filter: None,
            mcp_server: Some("rules".into()),
            server_type: None,
            field: "noop".into(),
            wire_field: None,
            normalizer: Normalizer::Raw,
            priority: 100,
            is_builtin: false,
        };
        let profiles = FieldProfileSet::new(vec![profile]);
        let rules = vec![rule_block_prompt("ASI-PR-1", "coding_rules")];
        let req = make_request(
            "prompts/get",
            json!({"name": "coding-strict", "arguments": {}}),
        );
        let ctx = PolicyContext {
            field_profiles: Some(&profiles),
            rules: &rules,
            mcp_server: "rules",
            app_id: None,
        };
        match evaluate_request(&ctx, &req, &[]) {
            PolicyDecision::Block { result, .. } => {
                assert_eq!(result.id.as_deref(), Some("ASI-PR-1"));
                assert_eq!(result.tool_id.as_deref(), Some("coding_rules"));
            }
            other => panic!("expected Block, got {other:?}"),
        }
    }

    #[test]
    fn allow_when_no_rules_fire() {
        let req = make_request("tools/call", json!({"name": "ping"}));
        let ctx = PolicyContext {
            field_profiles: None,
            rules: &[],
            mcp_server: "noop",
            app_id: None,
        };
        match evaluate_request(&ctx, &req, &[]) {
            PolicyDecision::Allow(_) => {}
            other => panic!("expected Allow, got {other:?}"),
        }
    }

    #[test]
    fn classify_only_rule_does_not_block() {
        let mut rule = rule_block_tool_id("ASI-CL-1", "read_file");
        rule.action = RuleAction::Classify;
        rule.risk = "caution".into();
        let profile = fp("read_file", "read_file", Some("fs"));
        let profiles = FieldProfileSet::new(vec![profile]);
        let req = make_request("tools/call", json!({"name": "read_file"}));
        let ctx = PolicyContext {
            field_profiles: Some(&profiles),
            rules: &[rule],
            mcp_server: "fs",
            app_id: None,
        };
        match evaluate_request(&ctx, &req, &[]) {
            PolicyDecision::Allow(Some(result)) => {
                assert_eq!(result.action, "classify");
                assert_eq!(result.id.as_deref(), Some("ASI-CL-1"));
            }
            other => panic!("expected classify Allow, got {other:?}"),
        }
    }
}
