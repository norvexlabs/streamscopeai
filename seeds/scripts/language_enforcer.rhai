// name = "language_enforcer"
// description = "Enforces response language by instructing the model to respond in the same language as the user's message. Falls back to English for ambiguous or code-only inputs. Note: multilingual prompt injection can bypass language enforcement — this is a best-effort guardrail, not a hard filter. Disabled by default."
// phase = "request"
// scope = "system_prompt"
// priority = 30
// enabled = false
// app_filter = "!streamscope-agent"

fn transform(ctx) {
    let instruction = [
        "",
        "",
        "[Language Policy]",
        "Always respond in the same language as the user's most recent message. If the user writes in French, respond in French. If in German, respond in German. If the user's language is ambiguous (e.g., code-only input, single words common across languages), default to English.",
        "Do not switch languages mid-response unless the user explicitly requests it.",
    ].join("\n");

    if ctx.system_prompt == () {
        ctx.system_prompt = instruction;
    } else {
        ctx.system_prompt += instruction;
    }

    ctx.labels.push("language_enforcer");
    ctx
}
