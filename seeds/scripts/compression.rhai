// name = "compression"
// description = "Context window compression — when estimated tokens exceed 80% of the upstream context window, compresses the conversation into a summarization+execution prompt. Preserves the system prompt and wraps the last user message with instructions to internally summarize prior context before responding."
// phase = "request"
// scope = "global"
// priority = 900
// enabled = false
// app_filter = "!streamscope-agent"

fn transform(ctx) {
    let cw = ctx.metadata["context_window"];
    if cw == () { return ctx; }
    let cw = parse_int(cw);
    if cw == () || cw <= 0 { return ctx; }

    // Estimate total tokens from character count (~4 chars/token)
    let total_chars = 0;
    for i in range(0, ctx.messages.len()) {
        total_chars += ctx.messages[i].content.len();
    }
    if ctx.system_prompt != () {
        total_chars += ctx.system_prompt.len();
    }
    let estimated_tokens = total_chars / 4;

    let threshold = cw * 80 / 100;
    if estimated_tokens <= threshold {
        return ctx;
    }

    // Need at least 2 messages to compress
    if ctx.messages.len() < 2 {
        return ctx;
    }

    // Find the last user message
    let last_user_idx = -1;
    for i in range(0, ctx.messages.len()) {
        if ctx.messages[i].role == "user" {
            last_user_idx = i;
        }
    }
    if last_user_idx < 0 { return ctx; }

    let last_user_content = ctx.messages[last_user_idx].content;

    // Build the prior conversation transcript
    let prior = "";
    for i in range(0, last_user_idx) {
        let msg = ctx.messages[i];
        prior += "[" + msg.role + "]: " + msg.content + "\n---\n";
    }

    // Build the compressed prompt (inspired by context compaction techniques)
    let compressed_prompt = [
        "Your task is to internally create a detailed summary of the conversation so far, then execute the user's request below.",
        "",
        "Pay close attention to the user's explicit requests and your previous actions in the conversation history. Your internal summary should capture technical details, code patterns, and decisions that are essential for continuing the work without losing context.",
        "",
        "When building your internal summary, ensure you identify:",
        "- The user's explicit requests and intents throughout the conversation",
        "- Key decisions, technical concepts, and code patterns",
        "- Specific details like file names, code snippets, function signatures",
        "- Any errors encountered and how they were resolved",
        "- User feedback, especially when they asked for something to be done differently",
        "",
        "## Prior conversation:",
        "",
    ].join("\n") + prior + "\n" + [
        "## Instructions:",
        "1. Internally summarize the prior conversation above to understand the full context. Do NOT output this summary.",
        "2. Then execute the following user request as if you had the complete conversation history.",
        "3. Do NOT mention the compression, summarization, or context limits to the user. Respond naturally.",
        "",
        "## Current user request:",
        "",
    ].join("\n") + last_user_content;

    // Replace all messages with a single compressed user message
    ctx.messages = [];
    ctx.messages.push(#{
        role: "user",
        content: compressed_prompt,
        tool_call_id: ()
    });

    ctx.metadata["compression"] = "applied";
    ctx.labels.push("compressed");
    ctx.labels.push("window_compression:" + estimated_tokens + "/" + cw);
    ctx
}
