//! JSON response healing for malformed upstream output.
//!
//! Some models emit malformed JSON — trailing commas, unclosed brackets — that
//! downstream clients cannot parse. Healing repairs the *syntax* so the client
//! always sees well-formed output. It does not fix schema adherence (wrong
//! field names, wrong value types) — only the bytes.
//!
//! Gated by the per-route healing flag (resolved from `downstream_routes`,
//! falling back to the tenant-wide `healing_enabled` setting). When active it
//! covers the full protocol matrix: structured-output (`json_schema`) response
//! text and tool-call argument strings, on both streaming and non-streaming
//! paths, across all four inbound protocols.

use crate::api::sse::ApiVersion;
use serde_json::Value;

/// JSON syntax repair — fix common malformed-JSON issues.
///
/// Fixes: trailing commas before `}` / `]`, unterminated strings, and missing
/// closing brackets — the malformations a truncated stream produces.
/// Does NOT fix schema adherence (wrong field names, wrong types) — only syntax.
/// Valid JSON is returned byte-identical.
pub fn heal_json(input: &str) -> String {
    let mut output = String::with_capacity(input.len());
    let chars = input.chars().peekable();
    let mut bracket_stack: Vec<char> = Vec::new();
    let mut in_string = false;
    let mut prev_was_escape = false;

    for ch in chars {
        if in_string {
            if prev_was_escape {
                output.push(ch);
                prev_was_escape = false;
                continue;
            }
            if ch == '\\' {
                prev_was_escape = true;
                output.push(ch);
                continue;
            }
            if ch == '"' {
                in_string = false;
            }
            output.push(ch);
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                output.push(ch);
            }
            '{' | '[' => {
                bracket_stack.push(ch);
                output.push(ch);
            }
            '}' => {
                // Remove trailing comma before closing brace.
                remove_trailing_comma(&mut output);
                bracket_stack.pop();
                output.push(ch);
            }
            ']' => {
                remove_trailing_comma(&mut output);
                bracket_stack.pop();
                output.push(ch);
            }
            _ => {
                output.push(ch);
            }
        }
    }

    // Close an unterminated string before balancing brackets — otherwise a
    // synthesized `}` / `]` would land *inside* the open string. Truncated
    // streaming output (a tool-call value cut off mid-string) hits this.
    if in_string {
        if prev_was_escape {
            // Dangling backslash with nothing to escape — drop it so the
            // closing quote isn't consumed as an escaped quote.
            output.pop();
        }
        output.push('"');
    }

    // Close unclosed brackets. Strip a trailing comma before each synthesized
    // close — truncated streaming output (e.g. a tool-call arguments object cut
    // off mid-key) commonly ends on a `,`, and the close-bracket would
    // otherwise leave `{"a":1,}` invalid.
    for bracket in bracket_stack.into_iter().rev() {
        match bracket {
            '{' => {
                remove_trailing_comma(&mut output);
                output.push('}');
            }
            '[' => {
                remove_trailing_comma(&mut output);
                output.push(']');
            }
            _ => {}
        }
    }

    output
}

fn remove_trailing_comma(s: &mut String) {
    let trimmed = s.trim_end();
    if trimmed.ends_with(',') {
        let new_len = trimmed.len() - 1;
        s.truncate(new_len);
    }
}

/// Heal a JSON value that is expected to hold a string. Returns true if the
/// string was a `str` and healing actually changed it.
fn heal_str_field(v: &mut Value) -> bool {
    let Some(s) = v.as_str() else {
        return false;
    };
    let healed = heal_json(s);
    if healed != s {
        *v = Value::String(healed);
        true
    } else {
        false
    }
}

/// Heal structured-output (`json_schema`) text content in a non-streaming
/// response body, in place. `upstream` is the protocol the body is shaped in.
/// Callers gate this on "the request asked for `json_schema`". Returns true if
/// any text block changed.
///
/// Walks the protocol-native text-content location: ChatCompletions
/// `choices[].message.content`, Responses `output[].content[]` `output_text`
/// parts, Anthropic `content[]` `text` blocks, Gemini
/// `candidates[].content.parts[].text` (non-thought parts).
pub fn heal_structured_output_json(response: &mut Value, upstream: ApiVersion) -> bool {
    let mut changed = false;
    match upstream {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response.get_mut("choices").and_then(Value::as_array_mut) {
                for choice in choices {
                    // The whole text — the string, or the `text` chunks of a
                    // chunk array joined — since one JSON answer may span
                    // several chunks.
                    if let Some(message) = choice.get_mut("message")
                        && let Some(text) = crate::api::chat::content_text(message.get("content"))
                            .map(std::borrow::Cow::into_owned)
                    {
                        let healed = heal_json(&text);
                        if healed != text {
                            crate::api::chat::set_content_text(message, healed);
                            changed = true;
                        }
                    }
                }
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response.get_mut("output").and_then(Value::as_array_mut) {
                for item in output {
                    if let Some(parts) = item.get_mut("content").and_then(Value::as_array_mut) {
                        for part in parts {
                            if part.get("type").and_then(Value::as_str) == Some("output_text")
                                && let Some(text) = part.get_mut("text")
                            {
                                changed |= heal_str_field(text);
                            }
                        }
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages => {
            if let Some(content) = response.get_mut("content").and_then(Value::as_array_mut) {
                for item in content {
                    if item.get("type").and_then(Value::as_str) == Some("text")
                        && let Some(text) = item.get_mut("text")
                    {
                        changed |= heal_str_field(text);
                    }
                }
            }
        }
        ApiVersion::GoogleGemini => {
            if let Some(candidates) = response.get_mut("candidates").and_then(Value::as_array_mut) {
                for cand in candidates {
                    if let Some(parts) = cand
                        .get_mut("content")
                        .and_then(|c| c.get_mut("parts"))
                        .and_then(Value::as_array_mut)
                    {
                        for part in parts {
                            // Skip thought parts — chain-of-thought, not the JSON answer.
                            if part.get("thought").and_then(Value::as_bool) == Some(true) {
                                continue;
                            }
                            if let Some(text) = part.get_mut("text") {
                                changed |= heal_str_field(text);
                            }
                        }
                    }
                }
            }
        }
    }
    changed
}

/// Heal tool-call argument strings in a non-streaming response body, in place.
/// `upstream` is the protocol the body is shaped in. Returns true if any
/// argument string changed.
///
/// Only ChatCompletions (`function.arguments`) and Responses
/// (`function_call.arguments`) carry tool-call arguments as JSON strings.
/// Anthropic (`input`) and Gemini (`args`) deliver them as JSON objects — there
/// is no syntax to heal — so those protocols are no-ops.
pub fn heal_tool_call_arguments_json(response: &mut Value, upstream: ApiVersion) -> bool {
    let mut changed = false;
    match upstream {
        ApiVersion::ChatCompletions => {
            if let Some(choices) = response.get_mut("choices").and_then(Value::as_array_mut) {
                for choice in choices {
                    if let Some(tool_calls) = choice
                        .get_mut("message")
                        .and_then(|m| m.get_mut("tool_calls"))
                        .and_then(Value::as_array_mut)
                    {
                        for tc in tool_calls {
                            if let Some(args) = tc
                                .get_mut("function")
                                .and_then(|f| f.get_mut("arguments"))
                            {
                                changed |= heal_str_field(args);
                            }
                        }
                    }
                }
            }
        }
        ApiVersion::Responses => {
            if let Some(output) = response.get_mut("output").and_then(Value::as_array_mut) {
                for item in output {
                    if item.get("type").and_then(Value::as_str) == Some("function_call")
                        && let Some(args) = item.get_mut("arguments")
                    {
                        changed |= heal_str_field(args);
                    }
                }
            }
        }
        ApiVersion::AnthropicMessages | ApiVersion::GoogleGemini => {}
    }
    changed
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn test_trailing_comma_object() {
        let input = r#"{"a": 1, "b": 2,}"#;
        let healed = heal_json(input);
        assert!(serde_json::from_str::<serde_json::Value>(&healed).is_ok());
    }

    #[test]
    fn test_trailing_comma_array() {
        let input = r#"[1, 2, 3,]"#;
        let healed = heal_json(input);
        assert!(serde_json::from_str::<serde_json::Value>(&healed).is_ok());
    }

    #[test]
    fn test_unclosed_bracket() {
        let input = r#"{"a": [1, 2"#;
        let healed = heal_json(input);
        assert!(serde_json::from_str::<serde_json::Value>(&healed).is_ok());
    }

    #[test]
    fn test_unclosed_bracket_with_trailing_comma() {
        // Truncated streaming output: object cut off right after a comma.
        let healed = heal_json(r#"{"command": "ls","#);
        assert_eq!(healed, r#"{"command": "ls"}"#);
        assert!(serde_json::from_str::<serde_json::Value>(&healed).is_ok());
    }

    #[test]
    fn test_unterminated_string() {
        // Truncated mid-string value — close the string, then the object.
        let healed = heal_json(r#"{"command": "ls -la /tmp"#);
        assert!(serde_json::from_str::<serde_json::Value>(&healed).is_ok());
        assert_eq!(healed, r#"{"command": "ls -la /tmp"}"#);
    }

    #[test]
    fn test_unterminated_string_trailing_backslash() {
        // Dangling escape with nothing to escape — drop it, then close.
        let healed = heal_json(r#"{"path": "C:\"#);
        assert!(serde_json::from_str::<serde_json::Value>(&healed).is_ok());
    }

    #[test]
    fn test_valid_json_unchanged() {
        let input = r#"{"a": 1, "b": [2, 3]}"#;
        let healed = heal_json(input);
        assert_eq!(healed, input);
    }

    // ── Structured-output healing — per protocol ──

    #[test]
    fn structured_output_chat_completions() {
        let mut v = json!({
            "choices": [{"message": {"role": "assistant", "content": "{\"a\": 1,}"}}]
        });
        assert!(heal_structured_output_json(&mut v, ApiVersion::ChatCompletions));
        let content = v["choices"][0]["message"]["content"].as_str().unwrap();
        assert!(serde_json::from_str::<Value>(content).is_ok());

        // A chunk-array content heals in its `text` chunk, keeping the array.
        let mut v = json!({"choices": [{"message": {"role": "assistant", "content": [
            {"type": "thinking", "thinking": [{"type": "text", "text": "why"}]},
            {"type": "text", "text": "{\"a\": 1,}"}
        ]}}]});
        assert!(heal_structured_output_json(&mut v, ApiVersion::ChatCompletions));
        let content = &v["choices"][0]["message"]["content"];
        assert_eq!(content[0]["thinking"][0]["text"], "why");
        assert!(serde_json::from_str::<Value>(content[1]["text"].as_str().unwrap()).is_ok());

        // One JSON answer spanning two `text` chunks heals as one.
        let mut v = json!({"choices": [{"message": {"role": "assistant", "content": [
            {"type": "text", "text": "{\"a\": "},
            {"type": "text", "text": "[1, 2"}
        ]}}]});
        assert!(heal_structured_output_json(&mut v, ApiVersion::ChatCompletions));
        let message = &v["choices"][0]["message"];
        let text = crate::api::chat::content_text(message.get("content")).unwrap();
        assert!(serde_json::from_str::<Value>(&text).is_ok(), "{text}");
    }

    #[test]
    fn structured_output_responses() {
        let mut v = json!({
            "output": [{
                "type": "message",
                "content": [{"type": "output_text", "text": "{\"a\": [1, 2"}]
            }]
        });
        assert!(heal_structured_output_json(&mut v, ApiVersion::Responses));
        let text = v["output"][0]["content"][0]["text"].as_str().unwrap();
        assert!(serde_json::from_str::<Value>(text).is_ok());
    }

    #[test]
    fn structured_output_gemini_skips_thought_parts() {
        let mut v = json!({
            "candidates": [{
                "content": {"parts": [
                    {"text": "reasoning {", "thought": true},
                    {"text": "{\"a\": 1,}"}
                ]}
            }]
        });
        assert!(heal_structured_output_json(&mut v, ApiVersion::GoogleGemini));
        // Thought part left untouched, answer part healed.
        assert_eq!(v["candidates"][0]["content"]["parts"][0]["text"], "reasoning {");
        let text = v["candidates"][0]["content"]["parts"][1]["text"].as_str().unwrap();
        assert!(serde_json::from_str::<Value>(text).is_ok());
    }

    #[test]
    fn structured_output_anthropic() {
        let mut v = json!({
            "content": [{"type": "text", "text": "{\"a\": 1,}"}]
        });
        assert!(heal_structured_output_json(&mut v, ApiVersion::AnthropicMessages));
        let text = v["content"][0]["text"].as_str().unwrap();
        assert!(serde_json::from_str::<Value>(text).is_ok());
    }

    #[test]
    fn structured_output_valid_json_reports_no_change() {
        let mut v = json!({
            "choices": [{"message": {"content": "{\"a\": 1}"}}]
        });
        assert!(!heal_structured_output_json(&mut v, ApiVersion::ChatCompletions));
    }

    // ── Tool-call argument healing — per protocol ──

    #[test]
    fn tool_args_chat_completions() {
        let mut v = json!({
            "choices": [{"message": {"tool_calls": [
                {"function": {"name": "f", "arguments": "{\"x\": 1,}"}}
            ]}}]
        });
        assert!(heal_tool_call_arguments_json(&mut v, ApiVersion::ChatCompletions));
        let args = v["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"]
            .as_str()
            .unwrap();
        assert!(serde_json::from_str::<Value>(args).is_ok());
    }

    #[test]
    fn tool_args_responses() {
        let mut v = json!({
            "output": [{"type": "function_call", "name": "f", "arguments": "{\"x\": [1, 2"}]
        });
        assert!(heal_tool_call_arguments_json(&mut v, ApiVersion::Responses));
        let args = v["output"][0]["arguments"].as_str().unwrap();
        assert!(serde_json::from_str::<Value>(args).is_ok());
    }

    #[test]
    fn tool_args_anthropic_object_is_noop() {
        // Anthropic tool input is a JSON object, never a string — nothing to heal.
        let mut v = json!({
            "content": [{"type": "tool_use", "name": "f", "input": {"x": 1}}]
        });
        assert!(!heal_tool_call_arguments_json(&mut v, ApiVersion::AnthropicMessages));
    }

    #[test]
    fn tool_args_gemini_object_is_noop() {
        let mut v = json!({
            "candidates": [{"content": {"parts": [
                {"functionCall": {"name": "f", "args": {"x": 1}}}
            ]}}]
        });
        assert!(!heal_tool_call_arguments_json(&mut v, ApiVersion::GoogleGemini));
    }

    #[test]
    fn tool_args_valid_json_reports_no_change() {
        let mut v = json!({
            "choices": [{"message": {"tool_calls": [
                {"function": {"name": "f", "arguments": "{\"x\": 1}"}}
            ]}}]
        });
        assert!(!heal_tool_call_arguments_json(&mut v, ApiVersion::ChatCompletions));
    }
}
