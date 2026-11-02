// name = "secure_coding_guardrails"
// description = "Security-focused guardrail for AI coding assistants based on OpenSSF guidelines. Enforces secure coding practices: no secrets in code, parameterized queries, input validation, safe dependencies, OWASP Top 10 compliance. Targets coding assistant apps. Disabled by default."
// phase = "request"
// scope = "system_prompt"
// priority = 15
// enabled = false
// app_filter = "claude-code,opencode,aider,cline,cursor,copilot,windsurf,codex"

fn transform(ctx) {
    let rules = [
        "",
        "",
        "[Secure Coding Policy]",
        "Apply these security rules to all code you write or modify.",
        "",
        // Input validation & injection prevention (OWASP A03)
        "Input & queries:",
        "- Always use parameterized queries or prepared statements for database access. Never concatenate user input into SQL.",
        "- Validate and sanitize all external inputs (user data, API responses, file contents) before use.",
        "- Use allowlists over denylists for input validation when possible.",
        "",
        // Secrets management (OpenSSF core)
        "Secrets:",
        "- Never include API keys, passwords, tokens, or credentials in code. Use environment variables or secure vault references.",
        "- Never commit .env files, private keys, or credential files.",
        "",
        // Output encoding & XSS (OWASP A07)
        "Output:",
        "- Escape or encode all user-generated content before rendering in HTML, logs, or shell commands.",
        "- Use Content Security Policy headers and framework-provided XSS protections.",
        "",
        // Authentication & crypto
        "Auth & crypto:",
        "- Use established libraries for authentication, encryption, and hashing. Never implement custom crypto.",
        "- Use constant-time comparison for tokens, API keys, and session identifiers.",
        "- Default to HTTPS, strong TLS, and encrypted storage.",
        "",
        // Dependencies (supply chain)
        "Dependencies:",
        "- Only suggest well-known, actively maintained packages from official registries.",
        "- Never suggest packages you are uncertain exist — hallucinated package names are a supply chain attack vector.",
        "- Pin dependency versions and prefer the latest stable release.",
        "",
        // Error handling
        "Errors:",
        "- Handle errors gracefully. Never expose stack traces, internal paths, or credentials in error messages.",
        "- Log security-relevant events but sanitize sensitive data from logs.",
    ].join("\n");

    let wrapped = "<organization-policy priority=\"mandatory\">\n" + rules + "\n</organization-policy>\n\n";

    if ctx.system_prompt == () {
        ctx.system_prompt = wrapped;
    } else {
        // Prepend: policies at the start of the system prompt carry more weight
        // than content appended after long client system prompts.
        ctx.system_prompt = wrapped + ctx.system_prompt;
    }

    ctx.labels.push("secure_coding_guardrails");
    ctx
}
