//! Google Gemini API wire-format types.
//!
//! Serde structs for the Gemini `generateContent` / `streamGenerateContent` API.
//! Uses camelCase field naming per the Gemini REST API convention.
//! The `model` and `stream` fields are `#[serde(skip)]` — they come from the URL
//! path (model in `/v1beta/models/{model}:...`, streaming from `:streamGenerateContent`),
//! not the request body.

use serde::{Deserialize, Serialize};
use serde_json::Value;

// ─── Request Types ──────────────────────────────────────────────────────────

/// Top-level Gemini generateContent request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiRequest {
    /// Model name — extracted from URL path, not serialized into body.
    #[serde(skip)]
    pub model: String,
    /// Whether streaming — determined by URL path, not body field.
    #[serde(skip)]
    pub stream: Option<bool>,

    pub contents: Vec<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_instruction: Option<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<GeminiTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_config: Option<GeminiToolConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generation_config: Option<GeminiGenerationConfig>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_settings: Option<Vec<GeminiSafetySetting>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_content: Option<String>,
}

/// A content block with role and parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiContent {
    /// `"user"` or `"model"`. Absent on `systemInstruction`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,
    pub parts: Vec<GeminiPart>,
}

/// A single content part — text, inline media, function call/response. Proto3
/// JSON accepts a field's original name beside its camelCase one, so the members
/// that carry media read both: an unread spelling would pass every capability gate.
///
/// Uses untagged deserialization: the first variant whose fields are present wins.
/// Order matters — more specific variants (FunctionCall, InlineData) must come
/// before the generic Text fallback.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum GeminiPart {
    /// Thinking/reasoning part — has `thought: true` flag.
    /// Must be before Text so `{"thought": true, "text": "..."}` matches here.
    ThoughtText {
        thought: bool,
        text: String,
        /// Opaque signature for thought reuse in subsequent requests.
        #[serde(rename = "thoughtSignature", default, skip_serializing_if = "Option::is_none")]
        thought_signature: Option<String>,
    },
    /// Function call emitted by the model. `thoughtSignature` is a field of
    /// the part, not of the call: a thinking model signs the call part, and a
    /// stateless request must send it back exactly as received.
    FunctionCall {
        #[serde(rename = "functionCall")]
        function_call: GeminiFunctionCallData,
        #[serde(rename = "thoughtSignature", default, skip_serializing_if = "Option::is_none")]
        thought_signature: Option<String>,
    },
    /// Function response from the client.
    FunctionResponse {
        #[serde(rename = "functionResponse", alias = "function_response")]
        function_response: GeminiFunctionResponseData,
    },
    /// Inline binary data (images, audio, video, PDF).
    InlineData {
        #[serde(rename = "inlineData", alias = "inline_data")]
        inline_data: GeminiInlineData,
    },
    /// File reference (Files API or Cloud Storage URI).
    FileData {
        #[serde(rename = "fileData", alias = "file_data")]
        file_data: GeminiFileData,
    },
    /// Plain text part.
    Text {
        text: String,
    },
    /// Unrecognized part type — preserved as raw JSON for lossless pass-through.
    /// Catches executableCode, codeExecutionResult, toolCall, toolResponse, etc.
    Unknown(serde_json::Value),
}

/// Inline binary data payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiInlineData {
    #[serde(alias = "mime_type")]
    pub mime_type: String,
    pub data: String,
}

/// File reference payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiFileData {
    #[serde(alias = "mime_type", skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
    #[serde(alias = "file_uri")]
    pub file_uri: String,
}

/// Function call data (model → client).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiFunctionCallData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub args: Value,
}

/// Function response data (client → model).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiFunctionResponseData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub response: Value,
    /// The response's media, each part an `inlineData` blob or a `fileData`
    /// reference.
    #[serde(default, deserialize_with = "camel_case_media_parts", skip_serializing_if = "Vec::is_empty")]
    pub parts: Vec<Value>,
    /// The response's other members (`willContinue`, `scheduling`), sent on as
    /// the client wrote them on a same-protocol forward.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

// ─── Tools ──────────────────────────────────────────────────────────────────

/// A tool definition: function declarations, or one of Gemini's built-in
/// tools (`googleSearch`, `codeExecution`, `urlContext`, …).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiTool {
    /// Gemini also accepts the snake_case spelling; read as declarations, it is
    /// seen by every tool rule rather than passed on as an unknown member.
    #[serde(skip_serializing_if = "Option::is_none", alias = "function_declarations")]
    pub function_declarations: Option<Vec<GeminiFunctionDecl>>,
    /// Every other member — a built-in tool — kept so a same-protocol forward,
    /// which re-serializes this struct, sends it on rather than an empty `{}`.
    #[serde(flatten)]
    pub extra: std::collections::BTreeMap<String, Value>,
}

/// A single function declaration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiFunctionDecl {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
}

/// Tool configuration (function calling mode).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiToolConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function_calling_config: Option<GeminiFunctionCallingConfig>,
}

/// Function calling mode configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiFunctionCallingConfig {
    /// `"AUTO"`, `"ANY"`, `"NONE"`, or `"VALIDATED"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub allowed_function_names: Option<Vec<String>>,
}

// ─── Generation Config ──────────────────────────────────────────────────────

/// Generation parameters.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiGenerationConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub presence_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub frequency_penalty: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seed: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidate_count: Option<u32>,
    /// `"text/plain"` or `"application/json"`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_mime_type: Option<String>,
    /// JSON Schema for structured output (primary documented field).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_schema: Option<Value>,
    /// JSON Schema for structured output (alternative field name).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_json_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_config: Option<GeminiThinkingConfig>,
}

/// Thinking/reasoning configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiThinkingConfig {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub include_thoughts: Option<bool>,
    /// `"minimal"`, `"low"`, `"medium"`, `"high"` (Gemini 3.x).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_level: Option<String>,
    /// Budget in tokens (Gemini 2.5). 0 = disabled, -1 = dynamic.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking_budget: Option<i32>,
}

// ─── Safety ─────────────────────────────────────────────────────────────────

/// Safety setting — harm category and blocking threshold.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiSafetySetting {
    pub category: String,
    pub threshold: String,
}

// ─── Response Types ─────────────────────────────────────────────────────────

/// Top-level Gemini generateContent response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiResponse {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates: Option<Vec<GeminiCandidate>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_metadata: Option<GeminiUsageMetadata>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_version: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_feedback: Option<Value>,
}

/// A single response candidate.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiCandidate {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<GeminiContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finish_reason: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub safety_ratings: Option<Vec<Value>>,
}

/// Token usage metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GeminiUsageMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt_token_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub candidates_token_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_token_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thoughts_token_count: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cached_content_token_count: Option<u32>,
}

// ─── Function names ─────────────────────────────────────────────────────────
//
// Gemini refuses a function name that does not start with a letter or an
// underscore ("Invalid function name. Must start with a letter or an
// underscore"), although its API reference states only the characters (`a-z
// A-Z 0-9 _ : . -`, up to 128). Chat Completions and Anthropic allow a leading
// digit or dash and a Responses function name is unconstrained, so a name from
// another protocol is prefixed on its way to Gemini, and only a name the
// request sent that way is restored on the way back ([`encoded_function_names`],
// read off the client's own tools): a client function literally named `_fn_1x`
// is legal on Gemini, sent as it is, and comes back as it is. A name Gemini
// accepts is never changed on either way.
//
// Invariants to preserve (locked by the `function_names` properties and
// `only_a_name_the_request_encoded_is_decoded`): a name the request encoded
// comes back as the client's, `encode` leaves a legal name untouched, and
// `encode` always yields a legal start. Deliberately NOT a property: a client
// declaring both `1x` and `_fn_1x` sends two tools Gemini sees as one.

/// The prefix a name Gemini would refuse is sent under.
pub const FUNCTION_NAME_PREFIX: &str = "_fn_";

/// A function response's raw parts with their media members under the one
/// spelling every reader reads: proto3 JSON accepts a field's original name too.
fn camel_case_media_parts<'de, D: serde::Deserializer<'de>>(deserializer: D) -> Result<Vec<Value>, D::Error> {
    fn rename(object: &mut serde_json::Map<String, Value>, from: &str, to: &str) {
        if let Some(value) = object.remove(from) {
            object.entry(to.to_string()).or_insert(value);
        }
    }
    let mut parts = Vec::<Value>::deserialize(deserializer)?;
    for part in parts.iter_mut().filter_map(Value::as_object_mut) {
        rename(part, "inline_data", "inlineData");
        rename(part, "file_data", "fileData");
        for member in ["inlineData", "fileData"] {
            if let Some(media) = part.get_mut(member).and_then(Value::as_object_mut) {
                rename(media, "mime_type", "mimeType");
                rename(media, "file_uri", "fileUri");
                rename(media, "display_name", "displayName");
            }
        }
    }
    Ok(parts)
}

/// Whether Gemini accepts `name`'s first character.
fn starts_legally(name: &str) -> bool {
    name.chars().next().is_none_or(|c| c.is_ascii_alphabetic() || c == '_')
}

/// The name a function is declared, called and answered under on Gemini.
pub fn encode_function_name(name: &str) -> std::borrow::Cow<'_, str> {
    if starts_legally(name) {
        std::borrow::Cow::Borrowed(name)
    } else {
        std::borrow::Cow::Owned(format!("{FUNCTION_NAME_PREFIX}{name}"))
    }
}

/// The names a request with these function `names` sends encoded, each
/// mapped to the client's own — what a response's names are restored from.
pub fn encoded_function_names<'a>(names: impl IntoIterator<Item = &'a str>) -> std::collections::HashMap<String, String> {
    names
        .into_iter()
        .filter_map(|name| match encode_function_name(name) {
            std::borrow::Cow::Owned(sent) => Some((sent, name.to_string())),
            std::borrow::Cow::Borrowed(_) => None,
        })
        .collect()
}

impl GeminiRequest {
    /// Every function name this request states — declarations, the
    /// history's calls and answers, and the allowlist — in the form Gemini
    /// accepts (see [`encode_function_name`]). Run on every request the
    /// gateway renders for Gemini.
    pub fn encode_function_names(&mut self) {
        let encode = |name: &mut String| {
            if let std::borrow::Cow::Owned(encoded) = encode_function_name(name) {
                *name = encoded;
            }
        };
        for decl in self.tools.iter_mut().flatten().filter_map(|t| t.function_declarations.as_mut()).flatten() {
            encode(&mut decl.name);
        }
        for part in self.contents.iter_mut().flat_map(|c| c.parts.iter_mut()) {
            match part {
                GeminiPart::FunctionCall { function_call, .. } => encode(&mut function_call.name),
                GeminiPart::FunctionResponse { function_response } => encode(&mut function_response.name),
                _ => {}
            }
        }
        let allowed = self
            .tool_config
            .as_mut()
            .and_then(|c| c.function_calling_config.as_mut())
            .and_then(|f| f.allowed_function_names.as_mut());
        for name in allowed.into_iter().flatten() {
            encode(name);
        }
    }
}

/// Restore the client's function names in a Gemini `generateContent`
/// response body — only the ones the request sent encoded
/// ([`encoded_function_names`]).
pub fn decode_function_names_in_response(body: &mut Value, encoded: &std::collections::HashMap<String, String>) {
    if encoded.is_empty() {
        return;
    }
    let parts = body
        .get_mut("candidates")
        .and_then(Value::as_array_mut)
        .into_iter()
        .flatten()
        .filter_map(|c| c.pointer_mut("/content/parts").and_then(Value::as_array_mut))
        .flatten();
    for part in parts {
        if let Some(Value::String(name)) = part.pointer_mut("/functionCall/name")
            && let Some(client) = encoded.get(name.as_str())
        {
            name.clone_from(client);
        }
    }
}

/// Restore the client's function names on the tool calls parsed from a
/// Gemini stream — only the ones the request sent encoded
/// ([`encoded_function_names`]).
pub fn decode_function_names_in_events(
    events: &mut [crate::api::domain::DomainEvent],
    encoded: &std::collections::HashMap<String, String>,
) {
    for event in events {
        if let crate::api::domain::DomainEvent::ToolCallDelta { function_name: Some(name), .. } = event
            && let Some(client) = encoded.get(name.as_str())
        {
            name.clone_from(client);
        }
    }
}

// ─── Tests ──────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn deserialize_simple_text_request() {
        let json = r#"{
            "contents": [{"role": "user", "parts": [{"text": "Hello"}]}]
        }"#;
        let req: GeminiRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.contents.len(), 1);
        assert_eq!(req.contents[0].role.as_deref(), Some("user"));
        assert_matches!(&req.contents[0].parts[0], GeminiPart::Text { text } if text == "Hello");
    }

    #[test]
    fn deserialize_function_call_response() {
        let json = r#"{
            "candidates": [{
                "content": {
                    "role": "model",
                    "parts": [{"functionCall": {"name": "get_weather", "args": {"city": "Paris"}}}]
                },
                "finishReason": "STOP"
            }],
            "usageMetadata": {"promptTokenCount": 10, "candidatesTokenCount": 5, "totalTokenCount": 15}
        }"#;
        let resp: GeminiResponse = serde_json::from_str(json).unwrap();
        let candidate = &resp.candidates.unwrap()[0];
        assert_eq!(candidate.finish_reason.as_deref(), Some("STOP"));
        let parts = &candidate.content.as_ref().unwrap().parts;
        assert_matches!(&parts[0], GeminiPart::FunctionCall { function_call, .. } if function_call.name == "get_weather");
    }

    #[test]
    fn deserialize_thinking_part() {
        let json = r#"{"thought": true, "text": "Let me think..."}"#;
        let part: GeminiPart = serde_json::from_str(json).unwrap();
        assert_matches!(&part, GeminiPart::ThoughtText { thought: true, text, .. } if text == "Let me think...");
    }

    #[test]
    fn a_function_responses_media_reads_under_one_spelling() {
        let data: GeminiFunctionResponseData = serde_json::from_value(serde_json::json!({
            "name": "shot",
            "parts": [
                {"inline_data": {"mime_type": "image/png", "data": "AAAA"}},
                {"file_data": {"mime_type": "image/png", "file_uri": "gs://b/o", "display_name": "o"}},
                {"inlineData": {"mimeType": "image/png", "data": "BBBB"}},
            ],
        }))
        .unwrap();
        assert_eq!(data.parts[0], serde_json::json!({"inlineData": {"mimeType": "image/png", "data": "AAAA"}}));
        assert_eq!(data.parts[1], serde_json::json!({"fileData": {"mimeType": "image/png", "fileUri": "gs://b/o", "displayName": "o"}}));
        assert_eq!(data.parts[2], serde_json::json!({"inlineData": {"mimeType": "image/png", "data": "BBBB"}}));
    }

    #[test]
    fn deserialize_inline_data_part() {
        let json = r#"{"inlineData": {"mimeType": "image/png", "data": "iVBOR..."}}"#;
        let part: GeminiPart = serde_json::from_str(json).unwrap();
        assert_matches!(&part, GeminiPart::InlineData { inline_data } if inline_data.mime_type == "image/png");
    }

    #[test]
    fn serialize_request_skips_model_and_stream() {
        let req = GeminiRequest {
            model: "gemini-2.5-pro".to_string(),
            stream: Some(true),
            contents: vec![GeminiContent {
                role: Some("user".to_string()),
                parts: vec![GeminiPart::Text { text: "Hi".to_string() }],
            }],
            system_instruction: None,
            tools: None,
            tool_config: None,
            generation_config: None,
            safety_settings: None,
            cached_content: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(!json.contains("model"));
        assert!(!json.contains("stream"));
        assert!(json.contains("contents"));
    }

    #[test]
    fn deserialize_system_instruction() {
        let json = r#"{
            "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
            "systemInstruction": {"parts": [{"text": "You are helpful."}]}
        }"#;
        let req: GeminiRequest = serde_json::from_str(json).unwrap();
        let sys = req.system_instruction.unwrap();
        assert!(sys.role.is_none());
        assert_matches!(&sys.parts[0], GeminiPart::Text { text } if text == "You are helpful.");
    }

    #[test]
    fn deserialize_generation_config_with_thinking() {
        let json = r#"{
            "contents": [{"role": "user", "parts": [{"text": "Hi"}]}],
            "generationConfig": {
                "temperature": 0.7,
                "maxOutputTokens": 1024,
                "thinkingConfig": {"thinkingBudget": 8000}
            }
        }"#;
        let req: GeminiRequest = serde_json::from_str(json).unwrap();
        let gc = req.generation_config.unwrap();
        assert_eq!(gc.temperature, Some(0.7));
        assert_eq!(gc.max_output_tokens, Some(1024));
        let tc = gc.thinking_config.unwrap();
        assert_eq!(tc.thinking_budget, Some(8000));
    }

    #[test]
    fn roundtrip_request() {
        let req = GeminiRequest {
            model: String::new(),
            stream: None,
            contents: vec![GeminiContent {
                role: Some("user".to_string()),
                parts: vec![
                    GeminiPart::Text { text: "Describe this image".to_string() },
                    GeminiPart::InlineData {
                        inline_data: GeminiInlineData {
                            mime_type: "image/jpeg".to_string(),
                            data: "abc123".to_string(),
                        },
                    },
                ],
            }],
            system_instruction: Some(GeminiContent {
                role: None,
                parts: vec![GeminiPart::Text { text: "Be concise.".to_string() }],
            }),
            tools: Some(vec![GeminiTool {
                extra: Default::default(),
                function_declarations: Some(vec![GeminiFunctionDecl {
                    name: "search".to_string(),
                    description: Some("Search the web".to_string()),
                    parameters: Some(serde_json::json!({"type": "object", "properties": {"q": {"type": "string"}}})),
                }]),
            }]),
            tool_config: None,
            generation_config: Some(GeminiGenerationConfig {
                temperature: Some(0.5),
                top_p: None,
                top_k: None,
                max_output_tokens: Some(2048),
                stop_sequences: None,
                presence_penalty: None,
                frequency_penalty: None,
                seed: None,
                candidate_count: None,
                response_mime_type: None,
                response_schema: None,
                response_json_schema: None,
                thinking_config: None,
            }),
            safety_settings: None,
            cached_content: None,
        };
        let json = serde_json::to_vec(&req).unwrap();
        let req2: GeminiRequest = serde_json::from_slice(&json).unwrap();
        assert_eq!(req2.contents.len(), 1);
        assert_eq!(req2.contents[0].parts.len(), 2);
        assert!(req2.system_instruction.is_some());
        assert!(req2.tools.is_some());
    }
    /// The request walk states every function name Gemini would refuse in
    /// the form it accepts; the response names come back as the client's.
    #[test]
    fn a_refused_name_is_encoded_in_the_request_and_decoded_in_the_response() {
        let mut body = serde_json::json!({"candidates": [{"content": {"role": "model", "parts": [
            {"functionCall": {"name": "_fn_1password", "args": {}}},
            {"functionCall": {"name": "lookup", "args": {}}},
            {"functionCall": {"name": "_fn_legal", "args": {}}},
        ]}}]});
        let encoded = encoded_function_names(["1password", "lookup", "_fn_legal", "-dash"]);
        decode_function_names_in_response(&mut body, &encoded);
        let names: Vec<_> = body["candidates"][0]["content"]["parts"].as_array().unwrap().iter()
            .map(|p| p["functionCall"]["name"].as_str().unwrap()).collect();
        assert_eq!(names, ["1password", "lookup", "_fn_legal"]);

        let mut events = vec![crate::api::domain::DomainEvent::ToolCallDelta {
            index: 0,
            id: None,
            function_name: Some("_fn_-dash".into()),
            arguments_delta: "{}".into(),
            form: crate::api::domain::CallArguments::Json,
        }];
        decode_function_names_in_events(&mut events, &encoded);
        assert_matches!(&events[0], crate::api::domain::DomainEvent::ToolCallDelta { function_name: Some(n), .. } if n == "-dash");
    }

    /// A name the request did not encode is the client's own, whatever it
    /// looks like: a function literally named `_fn_1x` is legal on Gemini, sent
    /// as it is, and must come back as it is.
    #[test]
    fn only_a_name_the_request_encoded_is_decoded() {
        let mut body = serde_json::json!({"candidates": [{"content": {"role": "model", "parts": [
            {"functionCall": {"name": "_fn_1x", "args": {}}}]}}]});
        decode_function_names_in_response(&mut body, &encoded_function_names(["_fn_1x"]));
        assert_eq!(body["candidates"][0]["content"]["parts"][0]["functionCall"]["name"], "_fn_1x");
    }

    mod function_names {
        use super::super::*;
        use proptest::prelude::*;

        proptest! {
            /// Every name the request declared comes back as the client's —
            /// one it had to encode and one it sent as it is, including one
            /// that reads like an encoding.
            #[test]
            fn a_name_round_trips(name in prop_oneof!["[a-zA-Z0-9_:.\\- ]{0,40}", "_fn_[a-zA-Z0-9_:.\\- ]{0,20}"]) {
                let encoded = encoded_function_names([name.as_str()]);
                let mut body = serde_json::json!({"candidates": [{"content": {"parts": [
                    {"functionCall": {"name": encode_function_name(&name), "args": {}}}]}}]});
                decode_function_names_in_response(&mut body, &encoded);
                prop_assert_eq!(body["candidates"][0]["content"]["parts"][0]["functionCall"]["name"].as_str(), Some(name.as_str()));
            }

            /// A name Gemini accepts is sent as it is.
            #[test]
            fn a_legal_name_is_untouched(name in "[a-zA-Z_][a-zA-Z0-9_:.\\-]{0,40}") {
                prop_assert_eq!(encode_function_name(&name), name.as_str());
            }

            /// Whatever the client named it, Gemini is sent a legal start.
            #[test]
            fn the_encoded_name_starts_legally(name in ".{1,40}") {
                let encoded = encode_function_name(&name);
                let first = encoded.chars().next().unwrap();
                prop_assert!(first.is_ascii_alphabetic() || first == '_', "{}", encoded);
            }
        }
    }

    #[test]
    fn a_same_protocol_forward_keeps_a_function_responses_parts_and_members() {
        let body = serde_json::json!({"contents": [{"role": "user", "parts": [{"functionResponse": {
            "id": "c1", "name": "shot", "response": {"image": {"$ref": "a.png"}},
            "parts": [{"inlineData": {"mimeType": "image/png", "data": "iVBO", "displayName": "a.png"}}],
            "willContinue": true, "scheduling": "SILENT",
        }}]}]});
        let req: GeminiRequest = serde_json::from_value(body.clone()).unwrap();
        assert_eq!(serde_json::to_value(&req).unwrap()["contents"], body["contents"]);
    }
}
