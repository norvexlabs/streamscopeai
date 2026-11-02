//! Tool name sanitization for OpenAI API compliance.
//!
//! OpenAI requires tool/function names to match `[a-zA-Z0-9_-]{1,64}`. This
//! module strips invalid characters from tool definitions, tool calls in messages,
//! and tool result references across all three API formats. Applied as the last
//! request-phase transform step.

use crate::api::ApiRequest;
use crate::api::domain::DomainEvent;
use crate::api::sse::SseEvent;
use crate::proxy::content::TransformStepDiff;

/// Max tool/function name length per OpenAI spec.
const MAX_TOOL_NAME_LEN: usize = 64;

/// Sanitize a tool/function name to match OpenAI's `[a-zA-Z0-9_-]{1,64}` constraint.
///
/// Returns `(sanitized_name, was_modified)`. Invalid characters are stripped.
/// Empty results after stripping are replaced with `_unknown_`.
pub fn sanitize_name(name: &str) -> (String, bool) {
    let cleaned: String = name
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || *c == '_' || *c == '-')
        .take(MAX_TOOL_NAME_LEN)
        .collect();

    if cleaned.is_empty() {
        return ("_unknown_".to_string(), name != "_unknown_");
    }

    let changed = cleaned != name;
    (cleaned, changed)
}

/// Sanitize all tool-related names in the request.
///
/// Returns `(count_fixed, renames)` where renames is a deduped list of `original → sanitized` pairs.
/// Walks tool definitions, tool calls in messages, and tool result references
/// across all three API formats.
pub fn sanitize_tool_names(request: &mut ApiRequest) -> (usize, Vec<(String, String)>) {
    let mut fixed = 0;
    let mut renames: Vec<(String, String)> = Vec::new();

    // Helper: record a rename pair (deduped)
    let mut record = |original: &str, clean: &str| {
        if !renames.iter().any(|(o, _)| o == original) {
            renames.push((original.to_string(), clean.to_string()));
        }
    };

    match request {
        ApiRequest::ChatCompletions(req) => {
            // Tool definitions — a function nests its name under `function`,
            // a custom tool under `custom`.
            if let Some(tools) = &mut req.tools {
                for tool in tools.iter_mut() {
                    if let Some(name) = tool.function_name().map(str::to_string) {
                        let (clean, changed) = sanitize_name(&name);
                        if changed {
                            tracing::debug!(original = %name, sanitized = %clean, "sanitized tool definition name");
                            record(&name, &clean);
                            tool.set_function_name(clean);
                            fixed += 1;
                        }
                    }
                }
            }

            // Messages: tool_calls (assistant) and name (tool role)
            for msg in &mut req.messages {
                if let Some(tool_calls) = &mut msg.tool_calls {
                    for tc in tool_calls.iter_mut() {
                        let Some(name) = tc.name().map(str::to_string) else { continue };
                        let (clean, changed) = sanitize_name(&name);
                        if changed {
                            tracing::debug!(original = %name, sanitized = %clean, "sanitized tool_call name");
                            record(&name, &clean);
                            tc.set_name(clean);
                            fixed += 1;
                        }
                    }
                }
                if let Some(name) = &mut msg.name
                    && msg.role == "tool"
                {
                    let (clean, changed) = sanitize_name(name);
                    if changed {
                        tracing::debug!(original = %name, sanitized = %clean, "sanitized tool message name");
                        record(name, &clean);
                        *name = clean;
                        fixed += 1;
                    }
                }
            }
        }

        ApiRequest::Responses(req) => {
            // Tool definitions — flat (`name` beside `type`) or nested alike.
            if let Some(tools) = &mut req.tools {
                for tool in tools.iter_mut() {
                    if let Some(name) = tool.function_name().map(str::to_string) {
                        let (clean, changed) = sanitize_name(&name);
                        if changed {
                            tracing::debug!(original = %name, sanitized = %clean, "sanitized tool definition name");
                            record(&name, &clean);
                            tool.set_function_name(clean);
                            fixed += 1;
                        }
                    }
                }
            }

            // Input items naming a tool: function and custom tool calls
            if let crate::api::domain::ResponseInput::Raw(items) = &mut req.input {
                for item in items.iter_mut() {
                    if let Some(name) = item.get("name").and_then(|n| n.as_str()).map(String::from)
                    {
                        let item_type = item.get("type").and_then(|t| t.as_str()).unwrap_or("");
                        if matches!(item_type, "function_call" | "function_call_output" | "custom_tool_call") {
                            let (clean, changed) = sanitize_name(&name);
                            if changed {
                                tracing::debug!(original = %name, sanitized = %clean, "sanitized responses input name");
                                record(&name, &clean);
                                item["name"] = serde_json::Value::String(clean);
                                fixed += 1;
                            }
                        }
                    }
                }
            }
        }

        ApiRequest::AnthropicMessages(req) => {
            // Tool definitions
            if let Some(tools) = &mut req.tools {
                for tool in tools.iter_mut() {
                    let (clean, changed) = sanitize_name(&tool.name);
                    if changed {
                        tracing::debug!(original = %tool.name, sanitized = %clean, "sanitized anthropic tool name");
                        record(&tool.name, &clean);
                        tool.name = clean;
                        fixed += 1;
                    }
                }
            }

            // Messages: tool_use content blocks
            for msg in &mut req.messages {
                if let crate::api::messages::AnthropicContent::Blocks(blocks) = &mut msg.content {
                    for block in blocks.iter_mut() {
                        if let crate::api::messages::ContentBlock::ToolUse { name, .. } = block {
                            let (clean, changed) = sanitize_name(name);
                            if changed {
                                tracing::debug!(original = %name, sanitized = %clean, "sanitized tool_use name");
                                record(name, &clean);
                                *name = clean;
                                fixed += 1;
                            }
                        }
                    }
                }
            }
        }

        ApiRequest::GoogleGemini(req) => {
            // Tool definitions: functionDeclarations[].name
            if let Some(tools) = &mut req.tools {
                for tool in tools.iter_mut() {
                    if let Some(decls) = &mut tool.function_declarations {
                        for decl in decls.iter_mut() {
                            let (clean, changed) = sanitize_name(&decl.name);
                            if changed {
                                tracing::debug!(original = %decl.name, sanitized = %clean, "sanitized gemini tool name");
                                record(&decl.name, &clean);
                                decl.name = clean;
                                fixed += 1;
                            }
                        }
                    }
                }
            }
            // Messages: functionCall parts in contents
            for content in &mut req.contents {
                for part in &mut content.parts {
                    if let crate::api::gemini::GeminiPart::FunctionCall { function_call, .. } = part {
                        let (clean, changed) = sanitize_name(&function_call.name);
                        if changed {
                            tracing::debug!(original = %function_call.name, sanitized = %clean, "sanitized gemini functionCall name");
                            record(&function_call.name, &clean);
                            function_call.name = clean;
                            fixed += 1;
                        }
                    }
                }
            }
        }
    }

    // A choice naming a renamed declaration follows it, or it forces a tool
    // that is no longer declared.
    request.follow_tool_renames(&renames, crate::api::Became::Renamed);

    (fixed, renames)
}

/// Result of request sanitization.
pub struct SanitizeResult {
    /// Number of tool names rewritten. Drives the `SanitizedToolNames` badge.
    pub renamed_count: u32,
    pub step_diff: Option<TransformStepDiff>,
    /// Tool name renames: (original, sanitized).
    pub renames: Vec<(String, String)>,
}

/// Entry point for request sanitization. Returns the rename count and optional diff for audit.
pub fn sanitize_request(
    request: &mut ApiRequest,
    sanitize_tool_names_enabled: bool,
    capture_diffs: bool,
) -> SanitizeResult {
    let mut renamed_count: u32 = 0;
    let mut diff_lines: Vec<String> = Vec::new();
    let mut all_renames: Vec<(String, String)> = Vec::new();

    if sanitize_tool_names_enabled {
        let (count, renames) = sanitize_tool_names(request);
        if count > 0 {
            renamed_count = count as u32;
            if capture_diffs {
                for (original, sanitized) in &renames {
                    diff_lines.push(format!("- {original}"));
                    diff_lines.push(format!("+ {sanitized}"));
                }
            }
            all_renames = renames;
        }
    }

    let step_diff = if capture_diffs && !diff_lines.is_empty() {
        Some(TransformStepDiff {
            name: "sanitize".to_string(),
            diff: diff_lines.join("\n"),
        })
    } else {
        None
    };

    SanitizeResult {
        renamed_count,
        step_diff,
        renames: all_renames,
    }
}

// ---- Response-side sanitization ----
//
// Counterpart to the request-side `sanitize_tool_names` pass: rewrite tool
// names emitted by the model **before** they reach the client or audit. The
// request-side pass remains as a safety net for clients that arrive with
// already-corrupted state; this pass prevents fresh corruption at the source.

/// Sanitize `function_name` on each `DomainEvent::ToolCallDelta` in place.
/// Returns one `(original, sanitized)` pair per *distinct* rewrite — the
/// caller projects this into the raw-SSE patch list and the
/// `transform_diff.response_tool_renames`-style chips.
pub fn sanitize_domain_events(events: &mut [DomainEvent]) -> Vec<(String, String)> {
    let mut renames: Vec<(String, String)> = Vec::new();
    for event in events.iter_mut() {
        if let DomainEvent::ToolCallDelta {
            function_name: Some(name),
            ..
        } = event
        {
            let (clean, changed) = sanitize_name(name);
            if changed {
                if !renames.iter().any(|(o, _)| o == name) {
                    renames.push((name.clone(), clean.clone()));
                }
                *name = clean;
            }
        }
    }
    renames
}

/// Rewrite tool names inside the JSON payload of a passthrough SSE event so
/// the bytes forwarded to the client match the sanitized `DomainEvent`. Walks
/// the parsed value looking for `"name"` keys whose string value matches an
/// entry in `renames`, replacing in place. Returns `true` if any value was
/// rewritten (caller re-encodes when so).
///
/// Safe across the four streaming SSE shapes — ChatCompletions
/// `delta.tool_calls[*].function.name`, Anthropic `content_block.name`,
/// Responses `item.name`, Gemini `parts[*].functionCall.name` — because all
/// four use a `"name"` JSON key whose value is exactly the tool name string.
/// Coarser than the request-side pass on purpose: every `"name"` key whose
/// value matches a rename is rewritten, regardless of surrounding role/key
/// context. Tool-call delta frames don't carry unrelated `"name"` fields in
/// practice, so the broader match is correct. Per-frame cost is only paid
/// when a rename was detected.
pub fn apply_renames_to_sse_event(event: &mut SseEvent, renames: &[(String, String)]) -> bool {
    if renames.is_empty() {
        return false;
    }
    let mut value: serde_json::Value = match serde_json::from_str(&event.data) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                "passthrough SSE data not valid JSON, leaving raw bytes unchanged: {e}"
            );
            return false;
        }
    };
    if !walk_and_rename_name_fields(&mut value, renames) {
        return false;
    }
    if let Ok(reencoded) = serde_json::to_string(&value) {
        event.data = reencoded;
        true
    } else {
        false
    }
}

fn walk_and_rename_name_fields(value: &mut serde_json::Value, renames: &[(String, String)]) -> bool {
    let mut any = false;
    match value {
        serde_json::Value::Object(map) => {
            // Rewrite the immediate `"name"` field if its string value matches.
            if let Some(serde_json::Value::String(s)) = map.get_mut("name")
                && let Some((_, new)) = renames.iter().find(|(o, _)| o == s)
            {
                *s = new.clone();
                any = true;
            }
            // Recurse into all values (covers nested `function.name`,
            // `content_block.name`, `item.name`, `functionCall.name`).
            for v in map.values_mut() {
                if walk_and_rename_name_fields(v, renames) {
                    any = true;
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                if walk_and_rename_name_fields(v, renames) {
                    any = true;
                }
            }
        }
        _ => {}
    }
    any
}

/// Walk a non-streaming response JSON tree and sanitize any tool name found
/// under a `"name"` key (same shape rule as the streaming patcher). Returns
/// the deduped rename pairs so the audit / badge layer can report them.
pub fn sanitize_response_json(value: &mut serde_json::Value) -> Vec<(String, String)> {
    let mut renames: Vec<(String, String)> = Vec::new();
    sanitize_response_json_inner(value, &mut renames);
    renames
}

fn sanitize_response_json_inner(value: &mut serde_json::Value, renames: &mut Vec<(String, String)>) {
    match value {
        serde_json::Value::Object(map) => {
            if let Some(serde_json::Value::String(s)) = map.get_mut("name") {
                let (clean, changed) = sanitize_name(s);
                if changed {
                    if !renames.iter().any(|(o, _)| o == s) {
                        renames.push((s.clone(), clean.clone()));
                    }
                    *s = clean;
                }
            }
            for v in map.values_mut() {
                sanitize_response_json_inner(v, renames);
            }
        }
        serde_json::Value::Array(arr) => {
            for v in arr.iter_mut() {
                sanitize_response_json_inner(v, renames);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::sse::ApiVersion;
    use bytes::Bytes;

    #[test]
    fn sanitize_name_valid_unchanged() {
        let (result, changed) = sanitize_name("Read");
        assert_eq!(result, "Read");
        assert!(!changed);
    }

    #[test]
    fn sanitize_name_strips_brackets() {
        let (result, changed) = sanitize_name("Read[TOOL_CALLS]");
        assert_eq!(result, "ReadTOOL_CALLS");
        assert!(changed);
    }

    #[test]
    fn sanitize_name_strips_spaces_and_special() {
        let (result, changed) = sanitize_name("my tool!@#name");
        assert_eq!(result, "mytoolname");
        assert!(changed);
    }

    #[test]
    fn sanitize_name_preserves_hyphens_underscores() {
        let (result, changed) = sanitize_name("my-tool_name");
        assert_eq!(result, "my-tool_name");
        assert!(!changed);
    }

    #[test]
    fn sanitize_name_truncates_to_64() {
        let long = "a".repeat(100);
        let (result, changed) = sanitize_name(&long);
        assert_eq!(result.len(), 64);
        assert!(changed);
    }

    #[test]
    fn sanitize_name_empty_becomes_unknown() {
        let (result, changed) = sanitize_name("[]{}()");
        assert_eq!(result, "_unknown_");
        assert!(changed);
    }

    #[test]
    fn sanitize_name_empty_string() {
        let (result, changed) = sanitize_name("");
        assert_eq!(result, "_unknown_");
        assert!(changed);
    }

    #[test]
    fn chat_completions_tool_calls_sanitized() {
        let json = r#"{
            "model": "test",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read[TOOL_CALLS]", "arguments": "{}"}
                    }]
                },
                {
                    "role": "tool",
                    "name": "Read[TOOL_CALLS]",
                    "tool_call_id": "call_1",
                    "content": "result"
                }
            ],
            "tools": [
                {"type": "function", "function": {"name": "Read[TOOL_CALLS]", "parameters": {}}}
            ],
            "stream": false
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();

        let (count, renames) = sanitize_tool_names(&mut req);
        assert_eq!(count, 3); // definition + tool_call + tool message name
        assert_eq!(renames.len(), 1); // deduped to one unique rename
        assert_eq!(renames[0].0, "Read[TOOL_CALLS]");
        assert_eq!(renames[0].1, "ReadTOOL_CALLS");

        if let ApiRequest::ChatCompletions(chat) = &req {
            assert_eq!(
                chat.tools.as_ref().unwrap()[0]
                    .function
                    .as_ref()
                    .unwrap()
                    .name,
                "ReadTOOL_CALLS"
            );
            assert_eq!(
                chat.messages[1].tool_calls.as_ref().unwrap()[0].name().unwrap(),
                "ReadTOOL_CALLS"
            );
            assert_eq!(
                chat.messages[2].name.as_deref().unwrap(),
                "ReadTOOL_CALLS"
            );
        } else {
            panic!("expected ChatCompletions");
        }
    }

    #[test]
    fn chat_completions_clean_names_noop() {
        let json = r#"{
            "model": "test",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read", "arguments": "{}"}
                    }]
                }
            ],
            "tools": [
                {"type": "function", "function": {"name": "Read", "parameters": {}}}
            ],
            "stream": false
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();

        let (count, renames) = sanitize_tool_names(&mut req);
        assert_eq!(count, 0);
        assert!(renames.is_empty());
    }

    #[test]
    fn anthropic_messages_tool_use_sanitized() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "tools": [{"name": "Read[TOOL_CALLS]", "input_schema": {"type": "object"}}],
            "messages": [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "tool_use", "id": "tu_1", "name": "Read[TOOL_CALLS]", "input": {}}
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "tu_1", "content": "ok"}
                    ]
                }
            ]
        }"#;
        let mut req =
            ApiRequest::parse(ApiVersion::AnthropicMessages, &Bytes::from(json)).unwrap();

        let (count, _) = sanitize_tool_names(&mut req);
        assert_eq!(count, 2); // definition + tool_use block

        if let ApiRequest::AnthropicMessages(msg) = &req {
            assert_eq!(msg.tools.as_ref().unwrap()[0].name, "ReadTOOL_CALLS");
            if let crate::api::messages::AnthropicContent::Blocks(blocks) = &msg.messages[1].content
            {
                if let crate::api::messages::ContentBlock::ToolUse { name, .. } = &blocks[0] {
                    assert_eq!(name, "ReadTOOL_CALLS");
                } else {
                    panic!("expected tool_use block");
                }
            }
        }
    }

    #[test]
    fn responses_input_items_sanitized() {
        let json = r#"{
            "model": "gpt-4o",
            "input": [
                {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "hi"}]},
                {"type": "function_call", "name": "Read[TOOL_CALLS]", "call_id": "c1", "arguments": "{}"},
                {"type": "function_call_output", "name": "Read[TOOL_CALLS]", "call_id": "c1", "output": "ok"}
            ],
            "tools": [
                {"type": "function", "function": {"name": "Read[TOOL_CALLS]", "parameters": {}}}
            ]
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();

        let (count, _) = sanitize_tool_names(&mut req);
        assert_eq!(count, 3); // definition + function_call + function_call_output

        if let ApiRequest::Responses(resp) = &req {
            assert_eq!(
                resp.tools.as_ref().unwrap()[0]
                    .function
                    .as_ref()
                    .unwrap()
                    .name,
                "ReadTOOL_CALLS"
            );
            if let crate::api::domain::ResponseInput::Raw(items) = &resp.input {
                assert_eq!(items[1]["name"].as_str().unwrap(), "ReadTOOL_CALLS");
                assert_eq!(items[2]["name"].as_str().unwrap(), "ReadTOOL_CALLS");
            }
        }
    }

    /// A custom (freeform) tool is renamed everywhere its name appears — its
    /// declaration (nested under `custom` on Chat, flat on Responses), the
    /// history's calls to it, and a choice forcing it, which stays a custom
    /// choice. Left behind, the history names a tool the request no longer
    /// declares and the choice forces one that does not exist.
    #[test]
    fn a_custom_tool_is_renamed_wherever_it_is_named() {
        let chat = serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "hi"},
                {"role": "assistant", "tool_calls": [
                    {"id": "c1", "type": "custom", "custom": {"name": "apply patch", "input": "x"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "ok"},
            ],
            "tools": [{"type": "custom", "custom": {"name": "apply patch"}}],
            "tool_choice": {"type": "custom", "custom": {"name": "apply patch"}},
        });
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(chat.to_string())).unwrap();
        let (count, renames) = sanitize_tool_names(&mut req);
        assert_eq!(renames, [("apply patch".to_string(), "applypatch".to_string())]);
        assert_eq!(count, 2);
        let body: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(body["tools"][0], serde_json::json!({"type": "custom", "custom": {"name": "applypatch"}}));
        assert_eq!(body["messages"][1]["tool_calls"][0]["custom"]["name"], "applypatch");
        assert_eq!(body["tool_choice"], serde_json::json!({"type": "custom", "custom": {"name": "applypatch"}}));

        let responses = serde_json::json!({
            "model": "m",
            "input": [
                {"type": "message", "role": "user", "content": "hi"},
                {"type": "custom_tool_call", "call_id": "c1", "name": "apply patch", "input": "x"},
                {"type": "custom_tool_call_output", "call_id": "c1", "output": "ok"},
            ],
            "tools": [{"type": "custom", "name": "apply patch"}],
            "tool_choice": {"type": "custom", "name": "apply patch"},
        });
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(responses.to_string())).unwrap();
        let (count, _) = sanitize_tool_names(&mut req);
        assert_eq!(count, 2);
        let body: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(body["tools"][0], serde_json::json!({"type": "custom", "name": "applypatch"}));
        assert_eq!(body["input"][1]["name"], "applypatch");
        assert_eq!(body["tool_choice"], serde_json::json!({"type": "custom", "name": "applypatch"}));
    }

    #[test]
    fn sanitize_request_disabled_is_noop() {
        let json = r#"{
            "model": "test",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read[TOOL_CALLS]", "arguments": "{}"}
                    }]
                }
            ],
            "stream": false
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();

        let result = sanitize_request(&mut req, false, false);
        assert_eq!(result.renamed_count, 0);
        assert!(result.step_diff.is_none());

        if let ApiRequest::ChatCompletions(chat) = &req {
            assert_eq!(
                chat.messages[1].tool_calls.as_ref().unwrap()[0].name().unwrap(),
                "Read[TOOL_CALLS]"
            );
        }
    }

    #[test]
    fn sanitize_request_returns_tag_with_count() {
        let json = r#"{
            "model": "test",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read[TOOL_CALLS]", "arguments": "{}"}
                    }]
                }
            ],
            "stream": false
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();

        let result = sanitize_request(&mut req, true, false);
        assert_eq!(result.renamed_count, 1);
        assert!(result.step_diff.is_none()); // capture_diffs=false
    }

    #[test]
    fn sanitize_request_produces_diff_when_enabled() {
        let json = r#"{
            "model": "test",
            "messages": [
                {"role": "user", "content": "hello"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "Read[TOOL_CALLS]", "arguments": "{}"}
                    }]
                }
            ],
            "stream": false
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();

        let result = sanitize_request(&mut req, true, true);
        assert_eq!(result.renamed_count, 1);
        let diff = result.step_diff.unwrap();
        assert_eq!(diff.name, "sanitize");
        assert!(diff.diff.contains("Read[TOOL_CALLS]"));
        assert!(diff.diff.contains("ReadTOOL_CALLS"));
    }

    #[test]
    fn sanitize_request_no_diff_when_clean() {
        let json = r#"{
            "model": "test",
            "messages": [{"role": "user", "content": "hello"}],
            "stream": false
        }"#;
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();

        let result = sanitize_request(&mut req, true, true);
        assert_eq!(result.renamed_count, 0);
        assert!(result.step_diff.is_none());
    }

    #[test]
    fn sanitize_domain_events_rewrites_function_name() {
        let mut events = vec![
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_string()),
                function_name: Some("Read[TOOL_CALLS]".to_string()),
                arguments_delta: String::new(),
                form: crate::api::domain::CallArguments::Json,
            },
            // Second delta in the same call carries no name — leave alone.
            DomainEvent::ToolCallDelta {
                index: 0,
                id: None,
                function_name: None,
                arguments_delta: "{\"path\":\"/tmp\"}".to_string(),
                form: crate::api::domain::CallArguments::Json,
            },
        ];
        let renames = sanitize_domain_events(&mut events);
        assert_eq!(renames, vec![("Read[TOOL_CALLS]".to_string(), "ReadTOOL_CALLS".to_string())]);
        if let DomainEvent::ToolCallDelta { function_name, .. } = &events[0] {
            assert_eq!(function_name.as_deref(), Some("ReadTOOL_CALLS"));
        } else {
            panic!("expected ToolCallDelta");
        }
    }

    #[test]
    fn sanitize_domain_events_noop_when_clean() {
        let mut events = vec![DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".to_string()),
            function_name: Some("Read".to_string()),
            arguments_delta: String::new(),
            form: crate::api::domain::CallArguments::Json,
        }];
        let renames = sanitize_domain_events(&mut events);
        assert!(renames.is_empty());
    }

    #[test]
    fn sanitize_domain_events_dedupes_repeated_renames() {
        let mut events = vec![
            DomainEvent::ToolCallDelta {
                index: 0,
                id: Some("call_1".to_string()),
                function_name: Some("Read[!]".to_string()),
                arguments_delta: String::new(),
                form: crate::api::domain::CallArguments::Json,
            },
            DomainEvent::ToolCallDelta {
                index: 1,
                id: Some("call_2".to_string()),
                function_name: Some("Read[!]".to_string()),
                arguments_delta: String::new(),
                form: crate::api::domain::CallArguments::Json,
            },
        ];
        let renames = sanitize_domain_events(&mut events);
        assert_eq!(renames.len(), 1);
    }

    #[test]
    fn apply_renames_to_sse_event_rewrites_chat_shape() {
        let mut event = SseEvent {
            event_type: None,
            data: r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"Read[!]","arguments":""}}]}}]}"#.to_string(),
            id: None,
        };
        let renames = vec![("Read[!]".to_string(), "Read".to_string())];
        assert!(apply_renames_to_sse_event(&mut event, &renames));
        assert!(event.data.contains("\"name\":\"Read\""));
        assert!(!event.data.contains("Read[!]"));
    }

    #[test]
    fn apply_renames_to_sse_event_rewrites_anthropic_shape() {
        let mut event = SseEvent {
            event_type: Some("content_block_start".to_string()),
            data: r#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_1","name":"Read[!]","input":{}}}"#.to_string(),
            id: None,
        };
        let renames = vec![("Read[!]".to_string(), "Read".to_string())];
        assert!(apply_renames_to_sse_event(&mut event, &renames));
        assert!(event.data.contains("\"name\":\"Read\""));
    }

    #[test]
    fn apply_renames_to_sse_event_noop_when_no_match() {
        let mut event = SseEvent {
            event_type: None,
            data: r#"{"choices":[{"delta":{"tool_calls":[{"index":0,"function":{"name":"Other","arguments":""}}]}}]}"#.to_string(),
            id: None,
        };
        let renames = vec![("Read[!]".to_string(), "Read".to_string())];
        assert!(!apply_renames_to_sse_event(&mut event, &renames));
        assert!(event.data.contains("\"name\":\"Other\""));
    }

    #[test]
    fn apply_renames_to_sse_event_noop_when_renames_empty() {
        let mut event = SseEvent {
            event_type: None,
            data: r#"{"choices":[]}"#.to_string(),
            id: None,
        };
        assert!(!apply_renames_to_sse_event(&mut event, &[]));
    }

    #[test]
    fn sanitize_response_json_walks_chat_completions_shape() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"tool_calls":[{"function":{"name":"Read[!]","arguments":"{}"}}]}}]}"#,
        )
        .unwrap();
        let renames = sanitize_response_json(&mut value);
        assert_eq!(renames, vec![("Read[!]".to_string(), "Read".to_string())]);
        assert_eq!(
            value["choices"][0]["message"]["tool_calls"][0]["function"]["name"]
                .as_str()
                .unwrap(),
            "Read"
        );
    }

    #[test]
    fn sanitize_response_json_walks_anthropic_shape() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"content":[{"type":"tool_use","id":"tu_1","name":"Read[!]","input":{}}]}"#,
        )
        .unwrap();
        let renames = sanitize_response_json(&mut value);
        assert_eq!(renames.len(), 1);
        assert_eq!(value["content"][0]["name"].as_str().unwrap(), "Read");
    }

    #[test]
    fn sanitize_response_json_walks_responses_shape() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"output":[{"type":"function_call","id":"fc_1","name":"Read[!]","arguments":"{}"}]}"#,
        )
        .unwrap();
        let renames = sanitize_response_json(&mut value);
        assert_eq!(renames.len(), 1);
        assert_eq!(value["output"][0]["name"].as_str().unwrap(), "Read");
    }

    #[test]
    fn sanitize_response_json_walks_gemini_shape() {
        let mut value: serde_json::Value = serde_json::from_str(
            r#"{"candidates":[{"content":{"parts":[{"functionCall":{"name":"Read[!]","args":{}}}]}}]}"#,
        )
        .unwrap();
        let renames = sanitize_response_json(&mut value);
        assert_eq!(renames.len(), 1);
        assert_eq!(
            value["candidates"][0]["content"]["parts"][0]["functionCall"]["name"]
                .as_str()
                .unwrap(),
            "Read"
        );
    }
}
