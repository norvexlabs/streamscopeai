//! Anthropic Messages API wire types (`/v1/messages`).
//!
//! Key structural differences from OpenAI Chat Completions: `max_tokens` is
//! required (not optional), system prompt is a top-level field (not a message),
//! and content is always structured blocks (not plain strings). Tool definitions
//! use `input_schema` instead of `parameters`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Anthropic Messages API request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesRequest {
    pub model: String,
    pub messages: Vec<AnthropicMessage>,
    pub max_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system: Option<SystemPrompt>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<AnthropicTool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_k: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_sequences: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub thinking: Option<ThinkingConfig>,
    /// Forward-compat: capture unknown fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// System prompt — can be a plain string or an array of blocks with cache_control.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum SystemPrompt {
    Text(String),
    Blocks(Vec<SystemBlock>),
}

impl SystemPrompt {
    /// Flatten to a single string (joining blocks with `\n\n`).
    pub fn to_text(&self) -> String {
        match self {
            Self::Text(s) => s.clone(),
            Self::Blocks(blocks) => blocks
                .iter()
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join("\n\n"),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemBlock {
    pub r#type: String,
    pub text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
}

/// Anthropic's cache breakpoint as the client sent it: `{"type": "ephemeral",
/// "ttl"?: "5m" | "1h"}`.
// Held as sent, so a re-serialised request keeps the lifetime the client pays
// for; any value reads, because a breakpoint the gateway does not understand
// must not make the block holding it unreadable (an unread block escapes the
// screens that read its text).
#[derive(Debug, Clone, Serialize, utoipa::ToSchema)]
#[serde(transparent)]
pub struct CacheControl(pub Value);

/// `null` is no breakpoint: it reads as an error, so an optional field and a
/// parse of a raw value both take it as absent.
impl<'de> Deserialize<'de> for CacheControl {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        match Value::deserialize(d)? {
            Value::Null => Err(serde::de::Error::custom("a null cache_control is no breakpoint")),
            value => Ok(Self(value)),
        }
    }
}

/// The breakpoint a raw block carries, if any (`null` is none).
fn breakpoint_of(block: &Value) -> Option<&Value> {
    block.get("cache_control").filter(|c| !c.is_null())
}

impl CacheControl {
    /// A breakpoint of the default lifetime.
    pub fn ephemeral() -> Self {
        Self(serde_json::json!({"type": "ephemeral"}))
    }
}

/// Anthropic message — role + content.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicMessage {
    pub role: String,
    pub content: AnthropicContent,
}

/// Message content — can be a plain string or an array of content blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum AnthropicContent {
    Text(String),
    Blocks(Vec<ContentBlock>),
}

/// Anthropic content block — tagged by `type`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "image")]
    Image {
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
        /// The block's other members (`transformations`), sent on as the
        /// client wrote them on a same-protocol forward.
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "tool_result")]
    ToolResult {
        tool_use_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        content: Option<ToolResultContent>,
        #[serde(skip_serializing_if = "Option::is_none")]
        is_error: Option<bool>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
        /// The block's other members (`toolset_name`), sent on as the client
        /// wrote them on a same-protocol forward.
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    #[serde(rename = "document")]
    Document {
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        title: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        context: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        citations: Option<Value>,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "thinking")]
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
    /// Catch-all for unrecognized block types (forward compat).
    /// Preserves full JSON so unknown types survive round-trips.
    #[serde(untagged)]
    Unknown(Value),
}

impl ToolResultBlock {
    /// A plain text block the gateway writes.
    pub fn text(text: String) -> Self {
        Self::Text { text, cache_control: None }
    }

    /// Make `new` a tool result's whole text, its other blocks (an image, a
    /// document) kept: the text goes into one of its text blocks and the
    /// others are dropped. The block kept is the last one carrying a cache
    /// breakpoint (else the first), so the breakpoint a client most likely
    /// ends its cached prefix with stays where it was; a dropped block's
    /// breakpoint goes with it — moved, a 5-minute breakpoint could come
    /// before a 1-hour one, which the API refuses. With no text block, one
    /// is added first.
    pub fn set_text(blocks: &mut Vec<Self>, new: &str) {
        let is_text = |b: &Self| matches!(b, Self::Text { .. });
        let keep = blocks
            .iter()
            .rposition(|b| is_text(b) && b.has_breakpoint())
            .or_else(|| blocks.iter().position(is_text));
        let Some(keep) = keep else {
            blocks.insert(0, Self::text(new.to_string()));
            return;
        };
        if let Self::Text { text, .. } = &mut blocks[keep] {
            *text = new.to_string();
        }
        let mut i = 0;
        blocks.retain(|b| {
            let drop = i != keep && is_text(b);
            i += 1;
            !drop
        });
    }

    /// Empty a tool result's text: its text blocks go — the API refuses an
    /// empty one — and its other blocks stay. The last text breakpoint moves
    /// to the last image or document left when no block left carries one, so
    /// the client's cached prefix still ends at the result. Answers whether
    /// any block is left.
    pub fn clear_text(blocks: &mut Vec<Self>) -> bool {
        let breakpoint = blocks.iter().rev().find_map(|b| match b {
            Self::Text { cache_control: Some(c), .. } => Some(c.clone()),
            _ => None,
        });
        blocks.retain(|b| !matches!(b, Self::Text { .. }));
        if let Some(c) = breakpoint
            && !blocks.iter().any(Self::has_breakpoint)
            && let Some(Self::Image { cache_control, .. } | Self::Document { cache_control, .. }) = blocks.last_mut()
        {
            *cache_control = Some(c);
        }
        !blocks.is_empty()
    }

    /// Whether the block carries a cache breakpoint.
    fn has_breakpoint(&self) -> bool {
        match self {
            Self::Text { cache_control, .. }
            | Self::Image { cache_control, .. }
            | Self::Document { cache_control, .. } => cache_control.is_some(),
            Self::Unknown(value) => breakpoint_of(value).is_some(),
        }
    }
}

/// Tool result content — can be text or blocks.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ToolResultContent {
    Text(String),
    Blocks(Vec<ToolResultBlock>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ToolResultBlock {
    #[serde(rename = "text")]
    Text {
        text: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    #[serde(rename = "image")]
    Image {
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
        /// The block's other members (`transformations`), sent on as the
        /// client wrote them on a same-protocol forward.
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    #[serde(rename = "document")]
    Document {
        source: ImageSource,
        #[serde(skip_serializing_if = "Option::is_none")]
        cache_control: Option<CacheControl>,
    },
    /// Catch-all for unrecognized tool result block types.
    #[serde(untagged)]
    Unknown(Value),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageSource {
    pub r#type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub media_type: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub data: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    /// File reference ID — for `source.type = "file"` (Anthropic Files API).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub file_id: Option<String>,
    /// Nested content blocks — for `source.type = "content"` (Anthropic document source).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub content: Option<Vec<ContentBlock>>,
}

/// Anthropic tool definition.
///
/// Custom tools have `input_schema` with a JSON Schema object.
/// Server-defined tools (e.g. `web_search`) omit `input_schema` and use a
/// `type` field instead, which lands in the `extra` map via `#[serde(flatten)]`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnthropicTool {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input_schema: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_control: Option<CacheControl>,
    /// Forward-compat: capture unknown fields (includes `type` for server-defined tools).
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl AnthropicTool {
    /// The server tool this declares (`web_search_20250305`, …), if it is one.
    /// The spec's optional `type: "custom"` marks an ordinary client tool, so
    /// it names no server tool.
    pub fn server_type(&self) -> Option<&str> {
        self.extra.get("type").and_then(Value::as_str).filter(|t| *t != "custom")
    }
}

/// Thinking configuration: `{type: "enabled", budget_tokens}` (manual),
/// `{type: "adaptive"}` (the model decides; depth rides `output_config.effort`)
/// or `{type: "disabled"}`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ThinkingConfig {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub budget_tokens: Option<u32>,
    /// `summarized` (default) or `omitted` — whether thinking text is returned.
    /// Typed so a same-protocol forward, which re-serializes this struct, keeps it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<String>,
    /// Forward-compat: a member this struct does not name still travels.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Non-streaming Messages API response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MessagesResponse {
    pub id: String,
    pub r#type: String,
    pub role: String,
    pub model: String,
    pub content: Vec<ResponseContentBlock>,
    pub stop_reason: Option<String>,
    pub stop_sequence: Option<String>,
    pub usage: AnthropicUsage,
}

/// Content block in a response.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ResponseContentBlock {
    #[serde(rename = "text")]
    Text { text: String },
    #[serde(rename = "tool_use")]
    ToolUse {
        id: String,
        name: String,
        input: Value,
    },
    #[serde(rename = "thinking")]
    Thinking {
        thinking: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        signature: Option<String>,
    },
}

/// Anthropic-format usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AnthropicUsage {
    pub input_tokens: u32,
    pub output_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_input_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_input_tokens: Option<u32>,
}

/// The `upstream_adapted` badge's name for a request fitted to what
/// Anthropic verifies.
pub const ANTHROPIC_DIALECT: &str = "anthropic";

/// A request forwarded to Anthropic in its own protocol. The client's history
/// goes as it sent it — what an Anthropic-protocol server accepts back of its
/// own thinking is that server's call — except a thinking block the gateway
/// BUILT for this client from another upstream's reasoning: its placeholder
/// signature (`synth_…`) is the gateway's own and no server decrypts it, so the
/// block is removed and named, as the translated walk leaves it out. Prior
/// thinking may be omitted, and the block is removed on every replay, so the
/// history Anthropic signed later blocks against is the one it is sent. A
/// manual budget is refused on a tool-loop turn that opens with no signed
/// thinking, so where the removal may leave the turn so, the budget is
/// dropped and named too — unless the turn is shown sealed
/// ([`crate::api::domain_request::DomainRequest::final_assistant_turn_is_sealed`]).
/// An assistant message this pass empties is removed (Anthropic combines the
/// consecutive turns around it).
pub fn conform_anthropic_body(body: bytes::Bytes) -> (bytes::Bytes, Option<crate::api::mistral::Conformed>) {
    use crate::api::domain_request::{
        DomainRequest, SYNTHETIC_SIGNATURE_PREFIX, UNSEALED_TURN_REASONING, is_synthetic_signature,
        placeholder_thinking_label,
    };
    // The placeholder as a JSON string's start: `"synth_`.
    static PLACEHOLDER: std::sync::LazyLock<memchr::memmem::Finder<'static>> = std::sync::LazyLock::new(|| {
        memchr::memmem::Finder::new(format!("\"{SYNTHETIC_SIGNATURE_PREFIX}").as_bytes()).into_owned()
    });
    if PLACEHOLDER.find(&body).is_none() {
        return (body, None);
    }
    let Ok(mut value) = serde_json::from_slice::<Value>(&body) else {
        return (body, None);
    };
    let placeholder = |block: &Value| {
        block.get("type").and_then(Value::as_str) == Some("thinking")
            && block.get("signature").and_then(Value::as_str).is_some_and(is_synthetic_signature)
    };
    let mut removed = 0;
    if let Some(messages) = value.get_mut("messages").and_then(Value::as_array_mut) {
        messages.retain_mut(|message| {
            if message.get("role").and_then(Value::as_str) != Some("assistant") {
                return true;
            }
            let Some(content) = message.get_mut("content").and_then(Value::as_array_mut) else {
                return true;
            };
            let before = content.len();
            content.retain(|block| !placeholder(block));
            removed += before - content.len();
            before == content.len() || !content.is_empty()
        });
    }
    if removed == 0 {
        return (body, None);
    }
    let mut conformed = crate::api::mistral::Conformed {
        dialect: ANTHROPIC_DIALECT,
        not_carried: vec![placeholder_thinking_label(removed)],
        ..Default::default()
    };
    let manual = value.get("thinking").and_then(|t| t.get("type")).and_then(Value::as_str) == Some("enabled");
    // Read as this pass sends the turn: the client's thinking as written.
    let sealed = || {
        MessagesRequest::deserialize(&value).is_ok_and(|request| {
            let mut domain = DomainRequest::from_anthropic(&request);
            domain.upstream.rerenders_client_request = true;
            domain.final_assistant_turn_is_sealed()
        })
    };
    if manual && !sealed() {
        if let Some(object) = value.as_object_mut() {
            crate::api::drop_manual_thinking(object);
        }
        conformed.not_carried.push(UNSEALED_TURN_REASONING.to_string());
    }
    match serde_json::to_vec(&value) {
        Ok(bytes) => (bytes::Bytes::from(bytes), Some(conformed)),
        Err(_) => (body, None),
    }
}

impl MessagesRequest {
    /// The tools the client names as deferred but has not declared: Claude
    /// Code lists them in a text (a system block, or a message) and declares
    /// one only once the model looks it up, so until then the model may call
    /// a listed tool the request does not declare. Read from either spelling
    /// it uses — the lines of an `<available-deferred-tools>` element, or the
    /// tool-name lines right after a line naming "deferred tools" that ends
    /// in a colon — in the order the texts come, a list of tools "no longer"
    /// available withdrawing the names it lists.
    pub fn deferred_tool_names(&self) -> Vec<String> {
        let declared: std::collections::HashSet<&str> =
            self.tools.iter().flatten().map(|t| t.name.as_str()).collect();
        let mut names: Vec<String> = Vec::new();
        let mut read = |text: &str| {
            for (listed, name) in deferred_list(text) {
                names.retain(|n| n != name);
                if listed && !declared.contains(name) {
                    names.push(name.to_string());
                }
            }
        };
        match &self.system {
            Some(SystemPrompt::Text(text)) => read(text),
            Some(SystemPrompt::Blocks(blocks)) => blocks.iter().for_each(|b| read(&b.text)),
            None => {}
        }
        // Only what the client wrote for the model: a system-role message, or
        // a reminder it adds to a user turn — never text a person or a tool
        // put in the conversation, nor the model's own.
        let from_client = |role: &str, text: &str| {
            role == "system"
                || (role == "user" && {
                    let text = text.trim_start();
                    text.starts_with("<system-reminder>") || text.starts_with("<available-deferred-tools>")
                })
        };
        for message in &self.messages {
            match &message.content {
                AnthropicContent::Text(text) if from_client(&message.role, text) => read(text),
                AnthropicContent::Text(_) => {}
                AnthropicContent::Blocks(blocks) => {
                    for block in blocks {
                        if let ContentBlock::Text { text, .. } = block
                            && from_client(&message.role, text)
                        {
                            read(text);
                        }
                    }
                }
            }
        }
        names
    }
}

/// The tool names one text lists as deferred, in order, each `true` when
/// listed as available and `false` when listed as no longer available (see
/// [`MessagesRequest::deferred_tool_names`]).
fn deferred_list(text: &str) -> Vec<(bool, &str)> {
    const OPEN: &str = "<available-deferred-tools>";
    const CLOSE: &str = "</available-deferred-tools>";
    // Most texts hold no list: skip them before walking their lines.
    let names_deferred = text.as_bytes().windows(14).any(|w| w.eq_ignore_ascii_case(b"deferred tools"));
    if !names_deferred && !text.contains(OPEN) {
        return Vec::new();
    }
    let mut names = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let trimmed = line.trim();
        if let Some(after_open) = trimmed.strip_prefix(OPEN) {
            // The element's lines, up to its end.
            let first = after_open.trim();
            if is_tool_name(first) {
                names.push((true, first));
            }
            if !trimmed.contains(CLOSE) {
                for line in lines.by_ref() {
                    let line = line.trim();
                    if line.starts_with(CLOSE) {
                        break;
                    }
                    if is_tool_name(line) {
                        names.push((true, line));
                    }
                }
            }
            continue;
        }
        let lower = line.to_ascii_lowercase();
        if lower.contains("deferred tools") && line.trim_end().ends_with(':') {
            let listed = !lower.contains("no longer");
            while let Some(name) = lines.next_if(|l| is_tool_name(l.trim())) {
                names.push((listed, name.trim()));
            }
        }
    }
    names
}

/// A line that can be a tool's name: the characters the API allows in one.
fn is_tool_name(line: &str) -> bool {
    !line.is_empty() && line.len() <= 128 && line.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
}

/// What becomes of a `tool_reference` in the history whose tool is no longer
/// declared under the name it carries.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReferenceFate {
    /// The name is still declared (or was never the gateway's to change).
    Keep,
    /// The tool is declared under this name now.
    Rename(String),
    /// The tool is no longer declared.
    Remove,
}

/// One `tool_reference` the walk changed: `renamed_to` is `None` for a removal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReferenceEdit {
    pub name: String,
    pub renamed_to: Option<String>,
}

impl MessagesRequest {
    /// Point every `tool_reference` in the history — in a client tool search's
    /// `tool_result` and in a server tool search's `tool_search_tool_result` —
    /// at the tool as it is declared now. The API expands each reference
    /// against `tools` and refuses the request when one names no declared
    /// tool, so a reference whose tool is gone is removed:
    ///
    /// - a `tool_result` left with no reference is told why in a text part
    ///   (`notice`), never written beside a reference that remains;
    /// - a server search left with no reference is followed by a text block
    ///   carrying the same notice: its result is typed and holds no text;
    /// - a cache breakpoint on a removed reference moves to the block that
    ///   held it, unless that block, or anything left inside it, carries one
    ///   already: moved past another breakpoint, a 1-hour one could follow a
    ///   5-minute one, which the API refuses.
    pub fn retarget_tool_references(
        &mut self,
        fate: impl Fn(&str) -> ReferenceFate,
        notice: impl Fn(&[String]) -> String,
    ) -> Vec<ReferenceEdit> {
        let mut edits = Vec::new();
        for message in &mut self.messages {
            let AnthropicContent::Blocks(blocks) = &mut message.content else { continue };
            let mut i = 0;
            while i < blocks.len() {
                let mut follow_with = None;
                match &mut blocks[i] {
                    ContentBlock::ToolResult { content: Some(ToolResultContent::Blocks(parts)), cache_control, .. } => {
                        let list = retarget_list(parts, tool_result_reference, &fate, &mut edits);
                        if cache_control.is_none()
                            && !parts.iter().any(ToolResultBlock::has_breakpoint)
                            && let Some(breakpoint) = list.breakpoint
                        {
                            *cache_control = serde_json::from_value(breakpoint).ok();
                        }
                        if !list.removed.is_empty() && list.kept == 0 {
                            parts.push(ToolResultBlock::text(notice(&list.removed)));
                        }
                    }
                    ContentBlock::Unknown(result)
                        if result.get("type").and_then(Value::as_str) == Some("tool_search_tool_result") =>
                    {
                        let Some(references) = result
                            .get_mut("content")
                            .and_then(|c| c.get_mut("tool_references"))
                            .and_then(Value::as_array_mut)
                        else {
                            i += 1;
                            continue;
                        };
                        let list = retarget_list(references, search_reference, &fate, &mut edits);
                        let inner_breakpoint = references.iter().any(|r| breakpoint_of(r).is_some());
                        if let Some(breakpoint) = list.breakpoint
                            && !inner_breakpoint
                            && breakpoint_of(result).is_none()
                            && let Some(object) = result.as_object_mut()
                        {
                            object.insert("cache_control".into(), breakpoint);
                        }
                        if !list.removed.is_empty() && list.kept == 0 {
                            follow_with = Some(ContentBlock::Text { text: notice(&list.removed), cache_control: None });
                        }
                    }
                    _ => {}
                }
                i += 1;
                if let Some(block) = follow_with {
                    blocks.insert(i, block);
                    i += 1;
                }
            }
        }
        edits
    }
}

enum Retargeted {
    NotAReference,
    Kept,
    /// The removed tool's name, and the breakpoint its reference carried.
    Removed(String, Option<Value>),
}

/// What [`retarget_list`] left of one list of references.
struct RetargetedList {
    /// The tools whose references were removed, each named once.
    removed: Vec<String>,
    /// How many references remain.
    kept: usize,
    /// The last breakpoint a removed reference carried: the one nearest the
    /// end of the block it moves to.
    breakpoint: Option<Value>,
}

/// Apply `fate` to every reference in `items` — the entries `reference`
/// reads as one — dropping the removed ones.
fn retarget_list<T>(
    items: &mut Vec<T>,
    reference: fn(&mut T) -> Option<&mut Value>,
    fate: &impl Fn(&str) -> ReferenceFate,
    edits: &mut Vec<ReferenceEdit>,
) -> RetargetedList {
    let mut list = RetargetedList { removed: Vec::new(), kept: 0, breakpoint: None };
    items.retain_mut(|item| {
        let Some(value) = reference(item) else { return true };
        match retarget(value, fate, edits) {
            Retargeted::NotAReference => true,
            Retargeted::Kept => {
                list.kept += 1;
                true
            }
            Retargeted::Removed(name, breakpoint) => {
                if !list.removed.contains(&name) {
                    list.removed.push(name);
                }
                list.breakpoint = breakpoint.or(list.breakpoint.take());
                false
            }
        }
    });
    list
}

fn search_reference(reference: &mut Value) -> Option<&mut Value> {
    Some(reference)
}

fn tool_result_reference(part: &mut ToolResultBlock) -> Option<&mut Value> {
    match part {
        ToolResultBlock::Unknown(value) => Some(value),
        _ => None,
    }
}

/// Apply `fate` to one entry of a reference list, recording what changed.
fn retarget(
    reference: &mut Value,
    fate: &impl Fn(&str) -> ReferenceFate,
    edits: &mut Vec<ReferenceEdit>,
) -> Retargeted {
    if reference.get("type").and_then(Value::as_str) != Some("tool_reference") {
        return Retargeted::NotAReference;
    }
    let Some(name) = reference.get("tool_name").and_then(Value::as_str).map(str::to_string) else {
        return Retargeted::NotAReference;
    };
    match fate(&name) {
        ReferenceFate::Keep => Retargeted::Kept,
        ReferenceFate::Rename(to) => {
            reference["tool_name"] = Value::from(to.clone());
            edits.push(ReferenceEdit { name, renamed_to: Some(to) });
            Retargeted::Kept
        }
        ReferenceFate::Remove => {
            let breakpoint = breakpoint_of(reference).cloned();
            edits.push(ReferenceEdit { name: name.clone(), renamed_to: None });
            Retargeted::Removed(name, breakpoint)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    /// Every breakpoint the client wrote survives a re-serialisation as
    /// written: its `ttl`, and one on each kind of block a `tool_result`
    /// carries (Anthropic Messages: `cache_control` is `{type, ttl?}`, and a
    /// tool result's text, image and document blocks each accept one).
    /// A removed reference's breakpoint moves to the end of the block that
    /// held it only when nothing left inside carries one: moved past a
    /// 5-minute breakpoint, a 1-hour one would break the API's ordering rule.
    #[test]
    fn a_removed_references_breakpoint_never_moves_past_another() {
        let hour = serde_json::json!({"type": "ephemeral", "ttl": "1h"});
        let five = serde_json::json!({"type": "ephemeral", "ttl": "5m"});
        let request = |result_inner: Value, search_kept: Value| -> MessagesRequest {
            serde_json::from_value(serde_json::json!({
                "model": "m",
                "max_tokens": 16,
                "messages": [{"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "t1", "content": [
                        {"type": "tool_reference", "tool_name": "Gone", "cache_control": hour},
                        result_inner,
                    ]},
                    {"type": "tool_search_tool_result", "tool_use_id": "s1", "content": {
                        "type": "tool_search_tool_search_result",
                        "tool_references": [
                            {"type": "tool_reference", "tool_name": "Gone", "cache_control": hour},
                            search_kept,
                        ],
                    }},
                ]}],
            }))
            .unwrap()
        };
        let fate = |name: &str| if name == "Gone" { ReferenceFate::Remove } else { ReferenceFate::Keep };
        let outer = |r: &MessagesRequest| {
            let wire = serde_json::to_value(r).unwrap();
            let blocks = wire["messages"][0]["content"].as_array().unwrap().clone();
            (blocks[0].get("cache_control").cloned(), blocks[1].get("cache_control").cloned())
        };

        let mut guarded = request(
            serde_json::json!({"type": "text", "text": "kept", "cache_control": five}),
            serde_json::json!({"type": "tool_reference", "tool_name": "Kept", "cache_control": five}),
        );
        guarded.retarget_tool_references(fate, |_| "gone".into());
        assert_eq!(outer(&guarded), (None, None), "a breakpoint is left inside: nothing moves");

        // The positive control: with nothing inside carrying one, it moves.
        let mut free = request(
            serde_json::json!({"type": "text", "text": "kept"}),
            serde_json::json!({"type": "tool_reference", "tool_name": "Kept"}),
        );
        free.retarget_tool_references(fate, |_| "gone".into());
        assert_eq!(outer(&free), (Some(hour.clone()), Some(hour)));
    }

    /// A tool result's text stays a text block — read by the screens that
    /// read a result's text — whatever breakpoint it carries, which goes
    /// back as sent; a `null` one is none.
    #[test]
    fn a_tool_results_text_reads_whole_whatever_its_breakpoint() {
        let sent = serde_json::json!([
            {"type": "text", "text": "a", "cache_control": {}},
            {"type": "text", "text": "b", "cache_control": {"type": "ephemeral", "ttl": 3600, "scope": "x"}},
        ]);
        let blocks: Vec<ToolResultBlock> = serde_json::from_value(sent.clone()).unwrap();
        for block in &blocks {
            assert_matches!(block, ToolResultBlock::Text { .. });
        }
        assert_eq!(serde_json::to_value(&blocks).unwrap(), sent);

        let null: ToolResultBlock =
            serde_json::from_value(serde_json::json!({"type": "text", "text": "c", "cache_control": null})).unwrap();
        assert_matches!(null, ToolResultBlock::Text { cache_control: None, .. });
        assert!(serde_json::from_value::<CacheControl>(Value::Null).is_err());
    }

    /// A rewritten tool result's text lands in its last text block carrying a
    /// breakpoint — which stays where the client put it, after a block with
    /// a 1-hour one — else in its first text block, else in a new one first.
    #[test]
    fn a_rewritten_tool_results_text_keeps_its_last_breakpoint_in_place() {
        let read = |v: Value| -> Vec<ToolResultBlock> { serde_json::from_value(v).unwrap() };
        let image = serde_json::json!({"type": "base64", "media_type": "image/png", "data": "iVBO"});
        let mut blocks = read(serde_json::json!([
            {"type": "text", "text": "a"},
            {"type": "image", "source": image, "cache_control": {"type": "ephemeral", "ttl": "1h"}},
            {"type": "text", "text": "b", "cache_control": {"type": "ephemeral", "ttl": "5m"}},
        ]));
        ToolResultBlock::set_text(&mut blocks, "new");
        assert_eq!(serde_json::to_value(&blocks).unwrap(), serde_json::json!([
            {"type": "image", "source": image, "cache_control": {"type": "ephemeral", "ttl": "1h"}},
            {"type": "text", "text": "new", "cache_control": {"type": "ephemeral", "ttl": "5m"}},
        ]));

        let mut plain = read(serde_json::json!([{"type": "text", "text": "a"}, {"type": "text", "text": "b"}]));
        ToolResultBlock::set_text(&mut plain, "new");
        assert_eq!(serde_json::to_value(&plain).unwrap(), serde_json::json!([{"type": "text", "text": "new"}]));

        let mut no_text = read(serde_json::json!([{"type": "image", "source": image}]));
        ToolResultBlock::set_text(&mut no_text, "new");
        assert_eq!(serde_json::to_value(&no_text).unwrap(), serde_json::json!([
            {"type": "text", "text": "new"},
            {"type": "image", "source": image},
        ]));
    }

    #[test]
    fn a_reserialised_request_keeps_every_breakpoint_as_sent() {
        let hour = serde_json::json!({"type": "ephemeral", "ttl": "1h"});
        let image = serde_json::json!({"type": "base64", "media_type": "image/png", "data": "iVBORw0K"});
        let pdf = serde_json::json!({"type": "base64", "media_type": "application/pdf", "data": "JVBERi0x"});
        let messages = serde_json::json!([{
            "role": "user",
            "content": [
                {"type": "tool_result", "tool_use_id": "t1", "cache_control": hour, "content": [
                    {"type": "text", "text": "body", "cache_control": hour},
                    {"type": "image", "source": image, "cache_control": hour},
                    {"type": "document", "source": pdf, "cache_control": hour},
                ]},
                {"type": "text", "text": "next", "cache_control": {"type": "ephemeral"}},
            ],
        }]);
        let sent = serde_json::json!({
            "model": "m",
            "max_tokens": 16,
            "system": [{"type": "text", "text": "sys", "cache_control": hour}],
            "messages": messages,
        });
        let request: MessagesRequest = serde_json::from_value(sent.clone()).unwrap();
        let wire = serde_json::to_value(&request).unwrap();
        assert_eq!(wire["system"], sent["system"]);
        assert_eq!(wire["messages"], sent["messages"], "a breakpoint without a ttl stays without one");
    }

    /// Flattened passthrough (`extra`) fields use `BTreeMap`, so the serialized
    /// request prefix (tools/system/messages) is byte-identical across identical
    /// requests regardless of the order unknown fields were inserted — a
    /// prerequisite for upstream provider prompt caching to hit. A `HashMap` here
    /// would randomize key order per instance and silently break the cache.
    #[test]
    fn extra_fields_serialize_deterministically() {
        let build = |order_ab: bool| {
            let mut extra = BTreeMap::new();
            if order_ab {
                extra.insert("type".to_string(), Value::String("web_search_20250305".into()));
                extra.insert("max_uses".to_string(), Value::from(5));
            } else {
                extra.insert("max_uses".to_string(), Value::from(5));
                extra.insert("type".to_string(), Value::String("web_search_20250305".into()));
            }
            MessagesRequest {
                model: "claude-opus-4-8".into(),
                messages: vec![],
                max_tokens: 1024,
                stream: None,
                system: None,
                tools: Some(vec![AnthropicTool {
                    name: "web_search".into(),
                    description: None,
                    input_schema: None,
                    cache_control: Some(CacheControl::ephemeral()),
                    extra,
                }]),
                tool_choice: None,
                temperature: None,
                top_p: None,
                top_k: None,
                stop_sequences: None,
                metadata: None,
                thinking: None,
                extra: BTreeMap::new(),
            }
        };
        let a = serde_json::to_string(&build(true)).unwrap();
        let b = serde_json::to_string(&build(false)).unwrap();
        assert_eq!(a, b, "extra-field key order must not affect serialized bytes");
    }

    #[test]
    fn parse_simple_messages_request() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Hello, Claude!"}
            ]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.model, "claude-sonnet-4-20250514");
        assert_eq!(req.max_tokens, 1024);
        assert_eq!(req.messages.len(), 1);
        assert_eq!(req.messages[0].role, "user");
        match &req.messages[0].content {
            AnthropicContent::Text(t) => assert_eq!(t, "Hello, Claude!"),
            _ => panic!("expected text content"),
        }
    }

    #[test]
    fn parse_system_prompt_string() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": "You are a helpful assistant.",
            "messages": [{"role": "user", "content": "Hi"}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        match req.system.as_ref().unwrap() {
            SystemPrompt::Text(t) => assert_eq!(t, "You are a helpful assistant."),
            _ => panic!("expected text system prompt"),
        }
    }

    #[test]
    fn parse_system_prompt_blocks() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "system": [
                {"type": "text", "text": "You are helpful.", "cache_control": {"type": "ephemeral"}},
                {"type": "text", "text": "Be concise."}
            ],
            "messages": [{"role": "user", "content": "Hi"}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        match req.system.as_ref().unwrap() {
            SystemPrompt::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                assert_eq!(blocks[0].text, "You are helpful.");
                assert!(blocks[0].cache_control.is_some());
            }
            _ => panic!("expected blocks system prompt"),
        }
    }

    #[test]
    fn system_prompt_to_text() {
        let text = SystemPrompt::Text("Hello".to_string());
        assert_eq!(text.to_text(), "Hello");

        let blocks = SystemPrompt::Blocks(vec![
            SystemBlock {
                r#type: "text".to_string(),
                text: "First".to_string(),
                cache_control: None,
            },
            SystemBlock {
                r#type: "text".to_string(),
                text: "Second".to_string(),
                cache_control: None,
            },
        ]);
        assert_eq!(blocks.to_text(), "First\n\nSecond");
    }

    #[test]
    fn parse_tool_use_message() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "tools": [
                {
                    "name": "get_weather",
                    "description": "Get weather for a location",
                    "input_schema": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}},
                        "required": ["location"]
                    }
                }
            ],
            "messages": [
                {"role": "user", "content": "What's the weather in SF?"},
                {
                    "role": "assistant",
                    "content": [
                        {"type": "text", "text": "Let me check."},
                        {"type": "tool_use", "id": "call_123", "name": "get_weather", "input": {"location": "SF"}}
                    ]
                },
                {
                    "role": "user",
                    "content": [
                        {"type": "tool_result", "tool_use_id": "call_123", "content": "72°F and sunny"}
                    ]
                }
            ]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.messages.len(), 3);
        assert_eq!(req.tools.as_ref().unwrap().len(), 1);
        assert_eq!(req.tools.as_ref().unwrap()[0].name, "get_weather");

        // Check assistant message has tool_use block
        match &req.messages[1].content {
            AnthropicContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                match &blocks[1] {
                    ContentBlock::ToolUse { id, name, input, .. } => {
                        assert_eq!(id, "call_123");
                        assert_eq!(name, "get_weather");
                        assert_eq!(input["location"], "SF");
                    }
                    _ => panic!("expected tool_use block"),
                }
            }
            _ => panic!("expected blocks content"),
        }
    }

    #[test]
    fn parse_thinking_config() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 16000,
            "thinking": {"type": "enabled", "budget_tokens": 10000},
            "messages": [{"role": "user", "content": "Think hard"}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        let thinking = req.thinking.as_ref().unwrap();
        assert_eq!(thinking.r#type, "enabled");
        assert_eq!(thinking.budget_tokens, Some(10000));
    }

    #[test]
    fn parse_image_content() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "messages": [{
                "role": "user",
                "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "abc123"}},
                    {"type": "text", "text": "What's in this image?"}
                ]
            }]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        match &req.messages[0].content {
            AnthropicContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                match &blocks[0] {
                    ContentBlock::Image { source, .. } => {
                        assert_eq!(source.media_type, "image/png");
                        assert_eq!(source.data, "abc123");
                    }
                    _ => panic!("expected image block"),
                }
            }
            _ => panic!("expected blocks content"),
        }
    }

    #[test]
    fn serialize_roundtrip() {
        let json = r#"{"model":"test","max_tokens":100,"messages":[{"role":"user","content":"hi"}]}"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        let serialized = serde_json::to_string(&req).unwrap();
        let req2: MessagesRequest = serde_json::from_str(&serialized).unwrap();
        assert_eq!(req2.model, "test");
        assert_eq!(req2.max_tokens, 100);
    }

    #[test]
    fn parse_messages_response() {
        let json = r#"{
            "id": "msg_123",
            "type": "message",
            "role": "assistant",
            "model": "claude-sonnet-4-20250514",
            "content": [{"type": "text", "text": "Hello!"}],
            "stop_reason": "end_turn",
            "stop_sequence": null,
            "usage": {"input_tokens": 10, "output_tokens": 5}
        }"#;
        let resp: MessagesResponse = serde_json::from_str(json).unwrap();
        assert_eq!(resp.id, "msg_123");
        assert_eq!(resp.stop_reason.as_deref(), Some("end_turn"));
        assert_eq!(resp.usage.input_tokens, 10);
        assert_eq!(resp.usage.output_tokens, 5);
    }

    #[test]
    fn parse_streaming_request() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "stream": true,
            "messages": [{"role": "user", "content": "Hello"}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        assert_eq!(req.stream, Some(true));
    }

    #[test]
    fn parse_server_defined_tool() {
        let json = r#"{
            "model": "claude-sonnet-4-20250514",
            "max_tokens": 1024,
            "tools": [
                {
                    "type": "web_search_20250305",
                    "name": "web_search"
                },
                {
                    "name": "get_weather",
                    "description": "Get weather",
                    "input_schema": {
                        "type": "object",
                        "properties": {"location": {"type": "string"}},
                        "required": ["location"]
                    }
                }
            ],
            "messages": [{"role": "user", "content": "Search for Rust news"}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        let tools = req.tools.as_ref().unwrap();
        assert_eq!(tools.len(), 2);

        // Server-defined tool: no input_schema, type in extra
        assert_eq!(tools[0].name, "web_search");
        assert!(tools[0].input_schema.is_none());
        assert_eq!(
            tools[0].extra.get("type").and_then(|v| v.as_str()),
            Some("web_search_20250305")
        );

        // Custom tool: has input_schema
        assert_eq!(tools[1].name, "get_weather");
        assert!(tools[1].input_schema.is_some());

        // Roundtrip: server-defined tool preserves type field
        let serialized = serde_json::to_string(&tools[0]).unwrap();
        assert!(serialized.contains("web_search_20250305"));
        assert!(!serialized.contains("input_schema"));
    }

    #[test]
    fn parse_unknown_content_block() {
        let json = r#"{
            "model": "claude-3", "max_tokens": 1024,
            "messages": [{"role": "user", "content": [
                {"type": "search_result", "title": "Test", "source": "https://example.com", "content": [{"type": "text", "text": "found"}]},
                {"type": "text", "text": "What?"}
            ]}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        match &req.messages[0].content {
            AnthropicContent::Blocks(blocks) => {
                assert_eq!(blocks.len(), 2);
                // Unknown block preserves JSON
                match &blocks[0] {
                    ContentBlock::Unknown(v) => {
                        assert_eq!(v["type"], "search_result");
                        assert_eq!(v["title"], "Test");
                    }
                    other => panic!("expected Unknown, got {other:?}"),
                }
                // Known block still works
                assert_matches!(&blocks[1], ContentBlock::Text { text, .. } if text == "What?");
            }
            _ => panic!("expected blocks"),
        }

        // Re-serialize preserves the unknown block
        let serialized = serde_json::to_string(&req).unwrap();
        assert!(serialized.contains("search_result"));
        assert!(serialized.contains("Test"));
    }

    #[test]
    fn parse_url_image() {
        let json = r#"{
            "model": "claude-3", "max_tokens": 1024,
            "messages": [{"role": "user", "content": [
                {"type": "image", "source": {"type": "url", "url": "https://example.com/img.jpg"}}
            ]}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        match &req.messages[0].content {
            AnthropicContent::Blocks(blocks) => {
                match &blocks[0] {
                    ContentBlock::Image { source, .. } => {
                        assert_eq!(source.r#type, "url");
                        assert_eq!(source.url.as_deref(), Some("https://example.com/img.jpg"));
                        assert!(source.data.is_empty());
                    }
                    other => panic!("expected Image, got {other:?}"),
                }
            }
            _ => panic!("expected blocks"),
        }
    }

    #[test]
    fn parse_document_block() {
        let json = r#"{
            "model": "claude-3", "max_tokens": 1024,
            "messages": [{"role": "user", "content": [
                {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": "JVBERi0="}, "title": "Report"}
            ]}]
        }"#;
        let req: MessagesRequest = serde_json::from_str(json).unwrap();
        match &req.messages[0].content {
            AnthropicContent::Blocks(blocks) => {
                match &blocks[0] {
                    ContentBlock::Document { source, title, .. } => {
                        assert_eq!(source.r#type, "base64");
                        assert_eq!(source.media_type, "application/pdf");
                        assert_eq!(source.data, "JVBERi0=");
                        assert_eq!(title.as_deref(), Some("Report"));
                    }
                    other => panic!("expected Document, got {other:?}"),
                }
            }
            _ => panic!("expected blocks"),
        }
    }

    #[test]
    fn test_image_source_file_deserialization() {
        let src: ImageSource = serde_json::from_str(r#"{
            "type": "file",
            "file_id": "file_abc123",
            "media_type": "image/png"
        }"#).unwrap();
        assert_eq!(src.r#type, "file");
        assert_eq!(src.file_id.as_deref(), Some("file_abc123"));
        assert_eq!(src.media_type, "image/png");
        assert!(src.content.is_none());
    }

    #[test]
    fn test_image_source_content_deserialization() {
        let src: ImageSource = serde_json::from_str(r#"{
            "type": "content",
            "content": [
                {"type": "text", "text": "Hello"},
                {"type": "text", "text": "World"}
            ]
        }"#).unwrap();
        assert_eq!(src.r#type, "content");
        assert!(src.file_id.is_none());
        let blocks = src.content.as_ref().unwrap();
        assert_eq!(blocks.len(), 2);
        assert_matches!(&blocks[0], ContentBlock::Text { text, .. } if text == "Hello");
    }

    #[test]
    fn test_image_source_base64_no_new_fields() {
        // Existing base64 sources should deserialize without new fields
        let src: ImageSource = serde_json::from_str(r#"{
            "type": "base64",
            "media_type": "image/png",
            "data": "iVBORw0="
        }"#).unwrap();
        assert_eq!(src.r#type, "base64");
        assert!(src.file_id.is_none());
        assert!(src.content.is_none());
    }

    /// A same-protocol forward to Anthropic carries the client's history as
    /// sent — Anthropic's own signature, an empty one, none: the server's call,
    /// and the body is returned untouched — except a block signed with the
    /// gateway's own placeholder, which no server decrypts: it is removed and
    /// named. A message the pass empties goes; one the client sent empty stays.
    /// Where the turn a manual budget continues may then open with no signed
    /// thinking, the budget goes too, and is named.
    #[test]
    fn a_same_protocol_forward_sends_anthropic_no_placeholder_signature() {
        let conform = |v: Value| {
            let (body, conformed) = conform_anthropic_body(bytes::Bytes::from(serde_json::to_vec(&v).unwrap()));
            (serde_json::from_slice::<Value>(&body).unwrap(), conformed)
        };
        let history = |thinking: Value, thinking_config: Option<Value>| {
            let mut body = serde_json::json!({"model": "m", "max_tokens": 9000, "messages": [
                {"role": "user", "content": "q"},
                {"role": "assistant", "content": [thinking, {"type": "tool_use", "id": "c1", "name": "f", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "r"}]}]});
            if let Some(config) = thinking_config {
                body["thinking"] = config;
            }
            body
        };
        let block = |signature: &str| serde_json::json!({"type": "thinking", "thinking": "t", "signature": signature});

        // Positive control: the client's own blocks go as written, the body
        // untouched, whatever thinking config they ride with.
        let manual = serde_json::json!({"type": "enabled", "budget_tokens": 4000});
        for own in [block("EqQBCkY"), block(""), serde_json::json!({"type": "thinking", "thinking": "t"})] {
            for config in [None, Some(manual.clone())] {
                let sent = history(own.clone(), config);
                assert_eq!(conform(sent.clone()), (sent, None));
            }
        }

        // The placeholder goes, and is named.
        let (sent, conformed) = conform(history(block("synth_19a2b"), None));
        assert_eq!(sent["messages"][1]["content"], serde_json::json!([{"type": "tool_use", "id": "c1", "name": "f", "input": {}}]));
        let conformed = conformed.unwrap();
        assert_eq!((conformed.dialect, conformed.not_carried), ("anthropic", vec!["thinking the gateway built from another provider".to_string()]));

        // Beside the placeholder, the client's own blocks still go as written.
        let mixed = serde_json::json!({"model": "m", "max_tokens": 10, "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [block("synth_1"), {"type": "text", "text": "a"}]},
            {"role": "user", "content": "next"},
            {"role": "assistant", "content": [block(""), block("EqQBCkY"), {"type": "thinking", "thinking": "t"},
                                              {"type": "text", "text": "b"}]},
            {"role": "user", "content": "more"}]});
        let (sent, _) = conform(mixed.clone());
        assert_eq!(sent["messages"][1]["content"], serde_json::json!([{"type": "text", "text": "a"}]));
        assert_eq!(sent["messages"][3], mixed["messages"][3]);

        // A manual budget continuing that tool loop goes with it; adaptive
        // thinking needs no block and stays.
        let (sent, conformed) = conform(history(block("synth_19a2b"), Some(manual.clone())));
        assert!(sent.get("thinking").is_none(), "{sent}");
        assert_eq!(
            conformed.unwrap().not_carried,
            ["thinking the gateway built from another provider", "reasoning (the turn it continues opens with no signed thinking)"]
        );
        // The turn is read as this pass sends it: one the client's own block
        // still opens (an empty signature an engine wrote) keeps its budget
        // when an older placeholder goes.
        let mut older = history(block(""), Some(manual.clone()));
        older["messages"].as_array_mut().unwrap().splice(0..0, [
            serde_json::json!({"role": "user", "content": "before"}),
            serde_json::json!({"role": "assistant", "content": [block("synth_1"), {"type": "text", "text": "a"}]}),
        ]);
        let (sent, conformed) = conform(older);
        assert_eq!(sent["thinking"], manual, "{sent}");
        assert_eq!(conformed.unwrap().not_carried, ["thinking the gateway built from another provider"]);
        let adaptive = serde_json::json!({"type": "adaptive"});
        let (sent, conformed) = conform(history(block("synth_19a2b"), Some(adaptive.clone())));
        assert_eq!(sent["thinking"], adaptive);
        assert_eq!(conformed.unwrap().not_carried.len(), 1);

        // A message the pass empties goes whole; the client's own empty final
        // assistant message (a prefill Anthropic allows) stays.
        let only = serde_json::json!({"model": "m", "max_tokens": 10, "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": [block("synth_1"), block("synth_2")]},
            {"role": "user", "content": "next"},
            {"role": "assistant", "content": []}]});
        let (sent, conformed) = conform(only);
        assert_eq!(
            sent["messages"],
            serde_json::json!([{"role": "user", "content": "q"}, {"role": "user", "content": "next"},
                               {"role": "assistant", "content": []}])
        );
        assert_eq!(conformed.unwrap().not_carried, ["thinking the gateway built from another provider (×2)"]);
    }

    /// Both spellings of Claude Code's deferred-tool list are read, each up to
    /// its end; a list of tools no longer available, and a line that cannot
    /// be a tool name, name none.
    #[test]
    fn a_deferred_list_is_read_in_either_spelling_and_only_to_its_end() {
        let paragraph = "Intro.\nThe following deferred tools are now available via ToolSearch. Use it to load them:\nWebFetch\nmcp__srv__tool\n\nAvailable agent types:\nExplore\n";
        assert_eq!(deferred_list(paragraph), vec![(true, "WebFetch"), (true, "mcp__srv__tool")]);
        let element = "<available-deferred-tools>\nWebSearch\nNotebookEdit\n</available-deferred-tools>\nRead\n";
        assert_eq!(deferred_list(element), vec![(true, "WebSearch"), (true, "NotebookEdit")]);
        let gone = "The following deferred tools are no longer available:\nWebFetch\n";
        assert_eq!(deferred_list(gone), vec![(false, "WebFetch")]);
        let prose = "Some deferred tools can be loaded:\n- WebFetch: fetch a page\nWebSearch\n";
        assert!(deferred_list(prose).is_empty());
        let unended = "Deferred tools, load before calling them:\nCronCreate\n</system-reminder>\nWebFetch\n";
        assert_eq!(deferred_list(unended), vec![(true, "CronCreate")]);
        let shouting = "DEFERRED TOOLS:\nWebFetch\n";
        assert_eq!(deferred_list(shouting), vec![(true, "WebFetch")]);
        let in_order = "The deferred tools are no longer available:\nWebFetch\n\n<available-deferred-tools>\nWebFetch\n</available-deferred-tools>";
        assert_eq!(deferred_list(in_order), vec![(false, "WebFetch"), (true, "WebFetch")]);
    }

    /// The list is read in the order the texts come: a tool listed and later
    /// withdrawn is not deferred, one withdrawn and listed again is.
    #[test]
    fn a_withdrawn_deferred_tool_is_no_longer_listed() {
        let request = |texts: &[&str]| MessagesRequest {
            model: "m".into(),
            messages: texts
                .iter()
                .map(|t| AnthropicMessage { role: "user".into(), content: AnthropicContent::Text(t.to_string()) })
                .collect(),
            max_tokens: 1,
            stream: None,
            system: None,
            tools: None,
            tool_choice: None,
            temperature: None,
            top_p: None,
            top_k: None,
            stop_sequences: None,
            metadata: None,
            thinking: None,
            extra: BTreeMap::new(),
        };
        let listed = "<system-reminder>The following deferred tools are now available via ToolSearch:\nWebFetch\nWebSearch\n";
        let gone = "<system-reminder>The following deferred tools are no longer available:\nWebFetch\n";
        assert_eq!(request(&[listed, gone]).deferred_tool_names(), vec!["WebSearch"]);
        assert_eq!(request(&[gone, listed]).deferred_tool_names(), vec!["WebFetch", "WebSearch"]);
        // A list a person pasted into their turn is not the client's.
        let pasted = gone.trim_start_matches("<system-reminder>");
        assert_eq!(request(&[listed, pasted]).deferred_tool_names(), vec!["WebFetch", "WebSearch"]);
    }

    // The spec's `toolset_name` (a toolset member's result) and an image's
    // `transformations` are members the typed blocks do not name.
    #[test]
    fn a_same_protocol_forward_keeps_a_blocks_members_the_types_do_not_name() {
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "f", "input": {}}]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "c1", "toolset_name": "browser", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}, "transformations": {"oversized_image": "error"}},
                ]},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}, "transformations": {"oversized_image": "downsize"}},
            ]},
        ]});
        let req: MessagesRequest = serde_json::from_value(body.clone()).unwrap();
        let sent = serde_json::to_value(&req).unwrap();
        assert_eq!(sent["messages"], body["messages"]);
        let AnthropicContent::Blocks(blocks) = &req.messages[1].content else {
            panic!("blocks");
        };
        let ContentBlock::ToolResult { extra, content: Some(ToolResultContent::Blocks(inner)), .. } = &blocks[0] else {
            panic!("a typed tool result");
        };
        assert_eq!(extra.keys().collect::<Vec<_>>(), ["toolset_name"]);
        assert_matches!(&inner[0], ToolResultBlock::Image { extra, .. } if extra.contains_key("transformations"));
    }
}
