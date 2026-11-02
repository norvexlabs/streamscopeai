// name = "thinking_redactor"
// description = "Redacts thinking/reasoning blocks from LLM responses before the client receives them. Prevents exposure of internal chain-of-thought which may contain PII, business logic, or sensitive reasoning traces ('leaky thoughts'). Replaces content with a placeholder. Disabled by default."
// phase = "response"
// scope = "thinking"
// priority = 50
// enabled = false
// app_filter = "!streamscope-agent"

fn transform(ctx) {
    // Replace the entire thinking block content with a placeholder.
    // The block structure is preserved (clients that expect thinking blocks
    // still receive one), but the internal reasoning is not exposed.
    ctx.content = "[internal reasoning redacted by policy]";
    ctx.labels.push("thinking_redacted");
    ctx
}
