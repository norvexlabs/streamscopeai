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
/// Read by [`GeminiPart::from_value`]: the first variant, in declaration order,
/// whose data member is present and well-formed wins — more specific variants
/// (ThoughtText, FunctionCall, InlineData) before the generic Text fallback —
/// and anything else is kept whole as `Unknown`. Written untagged.
#[derive(Debug, Clone, Serialize)]
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
        #[serde(rename = "functionResponse")]
        function_response: GeminiFunctionResponseData,
    },
    /// Inline binary data (images, audio, video, PDF).
    InlineData {
        #[serde(rename = "inlineData")]
        inline_data: GeminiInlineData,
        /// The part's members beside its blob, of [`PART_MEMBERS`] only, under
        /// their camelCase name: sent on as the client wrote them on a
        /// same-protocol forward.
        #[serde(flatten)]
        members: std::collections::BTreeMap<String, Value>,
    },
    /// File reference (Files API or Cloud Storage URI).
    FileData {
        #[serde(rename = "fileData")]
        file_data: GeminiFileData,
        /// The part's members beside its reference, as for [`Self::InlineData`].
        #[serde(flatten)]
        members: std::collections::BTreeMap<String, Value>,
    },
    /// Plain text part.
    Text {
        text: String,
    },
    /// Unrecognized part type — preserved as raw JSON for lossless pass-through.
    /// Catches executableCode, codeExecutionResult, toolCall, toolResponse, etc.
    Unknown(serde_json::Value),
}

/// The members a media part may carry beside its blob and send on: the spec's
/// non-data `Part` members that steer how the model reads the media, by their
/// camelCase name. Closed, because what a part carries beyond them — a second
/// data member (`text`, `fileData`), a transcription's `text`, `partMetadata`, a
/// blob's `displayName` — is content no capability gate or screen reads, and
/// must never ride a forward unread. (Their values are sent as written.)
pub const PART_MEMBERS: &[&str] = &["thought", "thoughtSignature", "mediaResolution", "mediaProcessing", "videoMetadata"];

/// Each member's proto3 snake_case spelling, read as its camelCase one.
const PART_MEMBER_SPELLINGS: &[(&str, &str)] = &[
    ("thought_signature", "thoughtSignature"),
    ("media_resolution", "mediaResolution"),
    ("media_processing", "mediaProcessing"),
    ("video_metadata", "videoMetadata"),
];

/// A part member's camelCase name, for either of its two proto3 spellings;
/// `None` for any other name.
pub(crate) fn part_member_name(name: &str) -> Option<&'static str> {
    PART_MEMBERS
        .iter()
        .find(|m| **m == name)
        .or_else(|| PART_MEMBER_SPELLINGS.iter().find(|(snake, _)| *snake == name).map(|(_, camel)| camel))
        .copied()
}

/// Whether `name` is one of the spec's non-data `Part` members, under either
/// proto3 spelling — the kept [`PART_MEMBERS`] or the free text a part may carry
/// beside its data — never what kind of part it is.
pub(crate) fn is_part_member(name: &str) -> bool {
    const FREE_TEXT: &[&str] =
        &["partMetadata", "part_metadata", "audioTranscription", "audio_transcription", "speechMetadata", "speech_metadata"];
    part_member_name(name).is_some() || FREE_TEXT.contains(&name)
}

/// A part's [`PART_MEMBERS`]; `part` is already under the camelCase spelling
/// ([`camel_case_part_members`]).
fn part_members(part: &serde_json::Map<String, Value>) -> std::collections::BTreeMap<String, Value> {
    PART_MEMBERS.iter().filter_map(|&m| part.get(m).map(|v| (m.to_string(), v.clone()))).collect()
}

/// A part with each member's snake_case spelling read as its camelCase one,
/// the spelling every reader (and every variant's shape) reads; a part naming
/// a member both ways keeps the camelCase value. Untouched — no copy — when
/// the part spells no member in snake_case.
fn camel_case_part_members(value: Value) -> Value {
    let Value::Object(mut part) = value else { return value };
    for (snake, camel) in PART_MEMBER_SPELLINGS {
        if let Some(v) = part.remove(*snake) {
            part.entry(camel.to_string()).or_insert(v);
        }
    }
    Value::Object(part)
}

/// The shapes [`GeminiPart::from_value`] reads a part as, one per variant.
mod shape {
    use super::{GeminiFileData, GeminiFunctionCallData, GeminiFunctionResponseData, GeminiInlineData};
    use serde::Deserialize;

    #[derive(Deserialize)]
    pub struct ThoughtText {
        pub thought: bool,
        pub text: String,
        #[serde(rename = "thoughtSignature", default)]
        pub thought_signature: Option<String>,
    }
    #[derive(Deserialize)]
    pub struct FunctionCall {
        #[serde(rename = "functionCall", alias = "function_call")]
        pub function_call: GeminiFunctionCallData,
        #[serde(rename = "thoughtSignature", default)]
        pub thought_signature: Option<String>,
    }
    #[derive(Deserialize)]
    pub struct FunctionResponse {
        #[serde(rename = "functionResponse", alias = "function_response")]
        pub function_response: GeminiFunctionResponseData,
    }
    #[derive(Deserialize)]
    pub struct InlineData {
        #[serde(rename = "inlineData", alias = "inline_data")]
        pub inline_data: GeminiInlineData,
    }
    #[derive(Deserialize)]
    pub struct FileData {
        #[serde(rename = "fileData", alias = "file_data")]
        pub file_data: GeminiFileData,
    }
    #[derive(Deserialize)]
    pub struct Text {
        pub text: String,
    }
}

impl GeminiContent {
    /// The text of a `systemInstruction` — its text parts, a part marked
    /// `thought: false` among them (a system instruction holds no thoughts),
    /// one line each; `None` when it has none. Every reader of a Gemini system
    /// prompt reads it here, so the domain, the audit and a script agree on
    /// what it says.
    pub fn system_text(&self) -> Option<String> {
        let texts: Vec<&str> = self.parts.iter().filter_map(GeminiPart::system_text).collect();
        (!texts.is_empty()).then(|| texts.join("\n"))
    }
}

impl GeminiPart {
    /// The part's text as a `systemInstruction` part ([`GeminiContent::system_text`]).
    pub(crate) fn system_text(&self) -> Option<&str> {
        match self {
            Self::Text { text } | Self::ThoughtText { thought: false, text, .. } => Some(text),
            _ => None,
        }
    }

    /// An `inlineData` part carrying nothing beside its bytes.
    pub fn inline(mime_type: String, data: String) -> Self {
        Self::InlineData { inline_data: GeminiInlineData { mime_type, data }, members: Default::default() }
    }

    /// A `fileData` part carrying nothing beside its reference.
    pub fn file(mime_type: Option<String>, file_uri: String) -> Self {
        Self::FileData { file_data: GeminiFileData { mime_type, file_uri }, members: Default::default() }
    }

    /// Read a part: each variant is tried, in declaration order, only when the
    /// member its shape requires is present — a shape without it can never
    /// match — and the first that reads wins; a part none reads, or that is not
    /// an object, is kept whole as `Unknown`. Every variant reads a member under
    /// either proto3 spelling (`thought_signature` on a call too); a media part
    /// keeps its [`PART_MEMBERS`], and every other member beside a variant's
    /// data is dropped.
    pub fn from_value(value: Value) -> Self {
        fn read<'a, T: Deserialize<'a>>(value: &'a Value) -> Option<T> {
            T::deserialize(value).ok()
        }
        let value = camel_case_part_members(value);
        let Value::Object(map) = &value else {
            return Self::Unknown(value);
        };
        let has = |a: &str, b: &str| map.contains_key(a) || map.contains_key(b);
        if map.contains_key("thought")
            && map.contains_key("text")
            && let Some(p) = read::<shape::ThoughtText>(&value)
        {
            return Self::ThoughtText { thought: p.thought, text: p.text, thought_signature: p.thought_signature };
        }
        if has("functionCall", "function_call")
            && let Some(p) = read::<shape::FunctionCall>(&value)
        {
            return Self::FunctionCall { function_call: p.function_call, thought_signature: p.thought_signature };
        }
        if has("functionResponse", "function_response")
            && let Some(p) = read::<shape::FunctionResponse>(&value)
        {
            return Self::FunctionResponse { function_response: p.function_response };
        }
        if has("inlineData", "inline_data")
            && let Some(p) = read::<shape::InlineData>(&value)
        {
            return Self::InlineData { inline_data: p.inline_data, members: part_members(map) };
        }
        if has("fileData", "file_data")
            && let Some(p) = read::<shape::FileData>(&value)
        {
            return Self::FileData { file_data: p.file_data, members: part_members(map) };
        }
        if map.contains_key("text")
            && let Some(p) = read::<shape::Text>(&value)
        {
            return Self::Text { text: p.text };
        }
        Self::Unknown(value)
    }
}

impl<'de> Deserialize<'de> for GeminiPart {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        Value::deserialize(deserializer).map(Self::from_value)
    }
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
    fn a_media_parts_members_beside_its_blob_are_kept_under_either_spelling() {
        let part: GeminiPart = serde_json::from_value(serde_json::json!({
            "inline_data": {"mime_type": "video/mp4", "data": "AAAA", "displayName": "unread"},
            "videoMetadata": {"fps": 2.0},
            "thoughtSignature": "sig",
            // Content no screen reads never rides along: a second data member,
            // free text (a transcription's, custom metadata), an unknown key.
            "audioTranscription": {"text": "unread"},
            "partMetadata": {"note": "unread"},
            "futureMember": "unread",
            // Neither proto3 spelling of a member is no member.
            "thought__signature": "unread",
            "mediaresolution": "unread",
        }))
        .unwrap();
        let GeminiPart::InlineData { inline_data, members } = &part else { panic!("inline data: {part:?}") };
        assert_eq!(inline_data.mime_type, "video/mp4");
        // The blob's own spellings are its fields, never a member beside it.
        assert_eq!(members.keys().collect::<Vec<_>>(), ["thoughtSignature", "videoMetadata"]);
        assert!(!serde_json::to_string(&part).unwrap().contains("unread"));
        let file: GeminiPart = serde_json::from_value(serde_json::json!({
            "file_data": {"file_uri": "gs://b/o", "displayName": "unread"}, "media_processing": "STATIC",
            "text": "unread",
            // One member in both spellings travels once, camelCase, whatever the order.
            "thought_signature": "b", "thoughtSignature": "a", "video_metadata": {"fps": 1.0},
        }))
        .unwrap();
        assert_eq!(
            serde_json::to_value(&file).unwrap(),
            serde_json::json!({
                "fileData": {"fileUri": "gs://b/o"},
                "mediaProcessing": "STATIC",
                "thoughtSignature": "a",
                "videoMetadata": {"fps": 1.0},
            })
        );
    }

    #[test]
    fn a_part_is_read_as_the_first_variant_its_members_make() {
        let read = |v: Value| serde_json::from_value::<GeminiPart>(v).unwrap();
        assert_matches!(read(serde_json::json!({"thought": true, "text": "t"})), GeminiPart::ThoughtText { thought: true, .. });
        // A malformed `thought` is no thought: the text is still read as text.
        assert_matches!(read(serde_json::json!({"thought": "yes", "text": "t"})), GeminiPart::Text { text } if text == "t");
        assert_matches!(
            read(serde_json::json!({"text": "t", "functionCall": {"name": "f"}, "thoughtSignature": "s"})),
            GeminiPart::FunctionCall { thought_signature: Some(s), .. } if s == "s"
        );
        // A call's snake_case spelling is read, as a response's is.
        assert_matches!(read(serde_json::json!({"function_call": {"name": "f"}})), GeminiPart::FunctionCall { .. });
        // A member's snake_case spelling is read on a call too.
        assert_matches!(
            read(serde_json::json!({"functionCall": {"name": "f"}, "thought_signature": "s"})),
            GeminiPart::FunctionCall { thought_signature: Some(s), .. } if s == "s"
        );
        assert_matches!(
            read(serde_json::json!({"function_response": {"name": "f", "response": {}}})),
            GeminiPart::FunctionResponse { .. }
        );
        // A call before media, media before text.
        assert_matches!(
            read(serde_json::json!({"inlineData": {"mimeType": "image/png", "data": "AA"}, "functionCall": {"name": "f"}})),
            GeminiPart::FunctionCall { .. }
        );
        assert_matches!(
            read(serde_json::json!({"text": "t", "fileData": {"fileUri": "gs://b/o"}})),
            GeminiPart::FileData { .. }
        );
        // A data member given both ways, a malformed one, an unknown one and a
        // non-object are each kept whole.
        for whole in [
            serde_json::json!({"inlineData": {"mimeType": "image/png", "data": "AA"}, "inline_data": {"mimeType": "image/png", "data": "BB"}}),
            serde_json::json!({"inlineData": {"data": "AA"}}),
            serde_json::json!({"executableCode": {"code": "1"}, "thoughtSignature": "s"}),
            serde_json::json!("text"),
        ] {
            assert_matches!(read(whole.clone()), GeminiPart::Unknown(v) if v == whole);
        }
    }

    proptest::proptest! {
        /// Whatever members a media part carries, only a `PART_MEMBERS` name
        /// rides beside its blob, under its camelCase spelling, each once.
        #[test]
        fn only_a_part_member_rides_beside_a_blob(
            members in proptest::collection::btree_map(
                proptest::prop_oneof![
                    proptest::strategy::Strategy::prop_map(proptest::sample::select(vec![
                        "thought", "thoughtSignature", "thought_signature", "mediaResolution", "media_resolution",
                        "mediaProcessing", "media_processing", "videoMetadata", "video_metadata", "partMetadata",
                        "displayName", "text", "fileData", "audioTranscription", "speechMetadata", "thought_",
                    ]), str::to_string),
                    "[a-zA-Z_]{1,20}",
                ],
                proptest::prelude::any::<u8>(),
                0..12,
            )
        ) {
            let mut part = serde_json::Map::new();
            part.insert("inlineData".into(), serde_json::json!({"mimeType": "image/png", "data": "AAAA"}));
            for (name, value) in &members {
                part.entry(name.clone()).or_insert(serde_json::json!(value));
            }
            let parsed: GeminiPart = serde_json::from_value(Value::Object(part)).unwrap();
            let GeminiPart::InlineData { members: kept, .. } = &parsed else { panic!("inline data: {parsed:?}") };
            for name in kept.keys() {
                proptest::prop_assert!(PART_MEMBERS.contains(&name.as_str()), "{name}");
            }
            // Every member the part named either way is kept.
            for name in members.keys() {
                if let Some(camel) = part_member_name(name) {
                    proptest::prop_assert!(kept.contains_key(camel), "{name}");
                }
            }
            let sent = serde_json::to_value(&parsed).unwrap();
            proptest::prop_assert_eq!(sent.as_object().unwrap().len(), kept.len() + 1);
        }
    }

    #[test]
    fn deserialize_inline_data_part() {
        let json = r#"{"inlineData": {"mimeType": "image/png", "data": "iVBOR..."}}"#;
        let part: GeminiPart = serde_json::from_str(json).unwrap();
        assert_matches!(&part, GeminiPart::InlineData { inline_data, .. } if inline_data.mime_type == "image/png");
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
                    GeminiPart::inline("image/jpeg".to_string(), "abc123".to_string()),
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
