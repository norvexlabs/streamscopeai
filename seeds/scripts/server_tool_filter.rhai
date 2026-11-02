// name = "server_tool_filter"
// description = "Filters server-defined tools that the upstream does not support — drops any tool whose parameter schema is absent or is not a valid JSON object (the shape of an Anthropic-style server-defined tool such as web_search or code_execution). Tools the gateway's tool-policy substitution path has rewritten into proper function-tools (marked is_gateway_substituted) pass through unchanged. Only active when the upstream is not Anthropic."
// phase = "request"
// scope = "tools"
// priority = 50
// enabled = true
// app_filter = "claude-code"

fn transform(ctx) {
    // Skip filtering when upstream is Anthropic — server tools are natively supported.
    let provider = ctx.metadata["upstream_provider"];
    if provider == () || contains_ci(provider, "anthropic") {
        return ctx;
    }

    let before = ctx.tools.len();
    ctx.tools = ctx.tools.filter(|tool| {
        // Tools the gateway's tool-policy substitution path rewrote into
        // proper function-tools carry a typed `is_gateway_substituted`
        // marker — pass them through even when their name matches a
        // server-defined original.
        if tool.is_gateway_substituted {
            return true;
        }
        // A genuine function-tool exposes a JSON-object parameter schema. A
        // missing schema — or one that fails to parse or is not an object —
        // is the shape of a server-defined tool (web_search, code_execution,
        // …) with no equivalent on a non-Anthropic backend; drop it.
        if tool.parameters_json == () {
            return false;
        }
        type_of(parse_json(tool.parameters_json)) == "map"
    });

    if ctx.tools.len() < before {
        ctx.labels.push("tools_filtered");
    }

    ctx
}
