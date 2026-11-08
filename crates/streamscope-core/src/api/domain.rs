//! Provider-neutral domain types shared across all API protocols.
//!
//! These types represent the common vocabulary (messages, tools, content parts,
//! finish reasons, usage counters, streaming events) independent of any specific
//! wire format. Protocol-specific modules ([`super::chat`], [`super::messages`],
//! [`super::responses`]) handle serialization; this module holds the shared semantics.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

/// Canonical finish reason — normalized across providers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum FinishReason {
    Stop,
    Length,
    ToolCalls,
    ContentFilter,
    Error,
}

impl FinishReason {
    /// Normalize provider-specific finish reason strings to canonical set.
    pub fn normalize(raw: &str) -> Self {
        match raw {
            "stop" | "end_turn" | "stop_sequence" | "STOP" => Self::Stop,
            // Mistral's `model_length` is a stop at the model's context limit:
            // the output was cut short, exactly what `length` reports.
            "length" | "model_length" | "max_tokens" | "MAX_TOKENS" => Self::Length,
            "tool_calls" | "tool_use" | "function_call" => Self::ToolCalls,
            // A stop made by a safety filter or classifier, in each vendor's
            // spelling: Chat `content_filter`, Anthropic `refusal`, Gemini's
            // safety family.
            "content_filter" | "safety" | "refusal" | "SAFETY" | "RECITATION" | "LANGUAGE" | "BLOCKLIST"
            | "PROHIBITED_CONTENT" | "SPII" | "IMAGE_SAFETY" => Self::ContentFilter,
            _ => Self::Error,
        }
    }

    /// A Responses answer's `status` as a finish, `incomplete_reason` being its
    /// `incomplete_details.reason` — the one reading every Responses
    /// translation makes, streaming or not. `in_progress` and `queued` state
    /// no finish; `failed`, `cancelled` and any other status are an error; an
    /// `incomplete` answer is a filter when its reason is `content_filter`, and
    /// otherwise — whatever reason it states, or none — cut short.
    pub fn of_responses_status(status: &str, incomplete_reason: Option<&str>) -> Option<Self> {
        match status {
            "completed" => Some(Self::Stop),
            "incomplete" if incomplete_reason == Some("content_filter") => Some(Self::ContentFilter),
            "incomplete" => Some(Self::Length),
            "in_progress" | "queued" => None,
            _ => Some(Self::Error),
        }
    }

    /// Human-readable label for display in admin UI and logs.
    pub fn display_name(&self) -> &'static str {
        match self {
            Self::Stop => "completed",
            Self::Length => "truncated",
            Self::ToolCalls => "tool_call",
            Self::ContentFilter => "filtered",
            Self::Error => "error",
        }
    }
}

/// A chat message.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Message {
    pub role: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<MessageContent>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_calls: Option<Vec<ToolCall>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_call_id: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// Message content — can be a string or an array of content parts.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum MessageContent {
    Text(String),
    Parts(Vec<ContentPart>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputAudioData {
    pub data: String,
    pub format: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum ContentPart {
    #[serde(rename = "text")]
    Text {
        text: String,
        /// The part's members beside its text (a `cache_control` some
        /// clients send), which the domain does not model: kept for a
        /// same-protocol forward, named on a translation.
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    #[serde(rename = "image_url")]
    ImageUrl {
        image_url: ImageUrl,
        /// The part's members beside its image (a `cache_control`), kept
        /// for a same-protocol forward and named on a translation.
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    #[serde(rename = "input_audio")]
    InputAudio {
        input_audio: InputAudioData,
        /// The part's members beside its audio, as an image part's.
        #[serde(flatten)]
        extra: BTreeMap<String, Value>,
    },
    /// Catch-all for unrecognized content parts.
    #[serde(untagged)]
    Unknown(Value),
}

impl ContentPart {
    /// A text part with nothing beside its text.
    pub fn text(text: impl Into<String>) -> Self {
        Self::Text { text: text.into(), extra: BTreeMap::new() }
    }

    /// Set `text` as the text of the first of `parts` that `is_text` reads as
    /// text, and remove the others: the text parts become one, at the first
    /// one's place. A kept typed text part takes every member a removed typed
    /// text part carried beside its text (a later part's winning), so a merge
    /// drops no `cache_control`; a removed untyped part's members (a Responses
    /// `output_text`'s `annotations`, offsets into its own text) describe text
    /// that is gone and go with it. A kept untyped part keeps its own, which
    /// its protocol may require. Returns whether a text part was there to keep.
    pub fn merge_text_parts(parts: &mut Vec<ContentPart>, text: &str, is_text: impl Fn(&ContentPart) -> bool) -> bool {
        let members = |part: &ContentPart| -> Vec<(String, Value)> {
            match part {
                Self::Text { extra, .. } => extra.iter().map(|(k, v)| (k.clone(), v.clone())).collect(),
                _ => Vec::new(),
            }
        };
        let Some(first) = parts.iter().position(&is_text) else {
            return false;
        };
        let merged: Vec<(String, Value)> = parts[first + 1..].iter().filter(|p| is_text(p)).flat_map(members).collect();
        let mut at = 0;
        parts.retain(|p| {
            let keep = at <= first || !is_text(p);
            at += 1;
            keep
        });
        match &mut parts[first] {
            Self::Text { text: t, extra } => {
                *t = text.to_string();
                extra.extend(merged);
            }
            // An untyped part's protocol defines its own members: it takes
            // none of a typed text part's.
            Self::Unknown(Value::Object(m)) => {
                m.insert("text".into(), Value::String(text.to_string()));
            }
            _ => {}
        }
        true
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageUrl {
    pub url: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Tool definition.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Tool {
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionDef>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

impl Tool {
    /// The function name this tool declares, in either spelling: Chat nests it
    /// under `function`; Responses declares a function FLAT (`name` beside
    /// `type`). Every reader of a Chat or Responses tool's name goes through
    /// here — one that reads only `function` never sees a Responses function
    /// (Codex's tools, for one), so a rule keyed on the name silently skips it.
    ///
    /// A custom (freeform) tool is named the same way — flat on Responses,
    /// nested under `custom` on Chat — so a rule keyed on its name reaches it.
    pub fn function_name(&self) -> Option<&str> {
        match &self.function {
            Some(f) => Some(f.name.as_str()),
            None if matches!(self.r#type.as_str(), "function" | "custom") => self
                .extra
                .get("name")
                .or_else(|| self.extra.get("custom").and_then(|c| c.get("name")))
                .and_then(Value::as_str),
            None => None,
        }
    }

    /// Rename the declared function, in whichever spelling it uses.
    pub fn set_function_name(&mut self, name: String) {
        match &mut self.function {
            Some(f) => f.name = name,
            None if matches!(self.r#type.as_str(), "function" | "custom") => {
                if let Some(custom) = self.extra.get_mut("custom").and_then(Value::as_object_mut) {
                    custom.insert("name".to_string(), Value::from(name));
                } else {
                    self.extra.insert("name".to_string(), Value::from(name));
                }
            }
            None => {}
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionDef {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,
    /// Whether the call's arguments must follow `parameters` exactly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub strict: Option<bool>,
}

/// Tool call in an assistant message: a function call (`type: "function"`),
/// or a call to a custom (freeform) tool (`type: "custom"`), whose input is
/// free text rather than JSON arguments. Exactly one of the two bodies is set.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolCall {
    pub id: String,
    pub r#type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub function: Option<FunctionCall>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom: Option<CustomToolCall>,
}

impl ToolCall {
    /// A function call.
    pub fn function(id: String, name: String, arguments: String) -> Self {
        Self {
            id,
            r#type: "function".to_string(),
            function: Some(FunctionCall { name, arguments }),
            custom: None,
        }
    }

    /// The tool this call names, whichever kind it is.
    pub fn name(&self) -> Option<&str> {
        match (&self.function, &self.custom) {
            (Some(f), _) => Some(f.name.as_str()),
            (None, Some(c)) => Some(c.name.as_str()),
            (None, None) => None,
        }
    }

    /// Rename the tool this call names, in whichever body it uses.
    pub fn set_name(&mut self, name: String) {
        if let Some(f) = &mut self.function {
            f.name = name;
        } else if let Some(c) = &mut self.custom {
            c.name = name;
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FunctionCall {
    pub name: String,
    pub arguments: String,
}

/// A tool call in either OpenAI grammar, read the one way every reader of a
/// response or a history needs it:
/// - Chat Completions nests the definition under its kind — `{id, type:
///   "function", function: {name, arguments}}`, `{id, type: "custom", custom:
///   {name, input}}`;
/// - Responses declares it flat — `{type: "function_call", call_id, name,
///   arguments}`, `{type: "custom_tool_call", call_id, name, input}`.
///
/// A custom (freeform) call's free text is given as the domain reads it,
/// `{"input": <text>}`, so a rule keyed on a field reaches both kinds alike.
pub struct ToolCallItem<'a> {
    pub name: &'a str,
    /// Chat's `id`; Responses' `call_id`, or the item's `id` where it names none.
    pub call_id: Option<&'a str>,
    /// The call's arguments as a JSON string.
    pub arguments: String,
    pub custom: bool,
    /// The Responses built-in tool the call is to, where it is one.
    pub builtin: Option<ClientBuiltin>,
}

/// Whether a Responses output item of type `kind` is a call the CLIENT runs —
/// a function call, a custom tool call, or a call to a built-in tool
/// ([`ClientBuiltin`]).
pub fn is_client_call_item(kind: &str) -> bool {
    matches!(kind, "function_call" | "custom_tool_call") || ClientBuiltin::of_item_type(kind).is_some()
}

/// A Responses built-in tool the CLIENT runs — its call is an output item of
/// the tool's own type, not a `function_call`: `local_shell_call` and
/// `shell_call` (commands to run), `apply_patch_call` (a file to create,
/// update or delete), `computer_call` (an input action on a screen). The
/// domain reads such a call like any other: named by its item type
/// ([`Self::tool_name`]), its arguments the item's payload (`action`, or
/// `operation`), so tool policy and the audit read it as they read a function
/// call's arguments. Only a Responses client has the item to run: any other
/// client is told the call was not carried.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClientBuiltin {
    LocalShell,
    Shell,
    ApplyPatch,
    Computer,
}

impl ClientBuiltin {
    /// The built-in tool an output item of type `item_type` calls.
    pub fn of_item_type(item_type: &str) -> Option<Self> {
        match item_type {
            "local_shell_call" => Some(Self::LocalShell),
            "shell_call" => Some(Self::Shell),
            "apply_patch_call" => Some(Self::ApplyPatch),
            "computer_call" => Some(Self::Computer),
            _ => None,
        }
    }

    /// Every field a built-in tool's call states its payload in.
    pub const PAYLOAD_FIELDS: [&'static str; 3] = ["action", "actions", "operation"];

    /// Clear every payload field of `item` but the one it is read by
    /// ([`Self::payload_field`]): a computer call stating both `action` and
    /// `actions` is read by `action`, and a batch no policy read must not ride
    /// along with it. Whether anything was cleared.
    pub fn keep_read_payload_only(self, item: &mut Value) -> bool {
        let read = self.payload_field(item);
        let mut cleared = false;
        for field in Self::PAYLOAD_FIELDS.into_iter().filter(|field| *field != read) {
            if item.get(field).is_some_and(|v| !v.is_null()) {
                item[field] = Value::Null;
                cleared = true;
            }
        }
        cleared
    }

    /// `arguments` as the payload field `field` takes it: JSON of that
    /// field's kind, holding something — a non-empty list for a computer
    /// call's batched `actions`, a non-empty object for every other — or
    /// nothing, which a payload cannot be rewritten to. An emptied payload (a
    /// `drop` rule's `{}`) is no call a client can be given: a strict client
    /// cannot parse it and a lenient one runs a default action.
    pub fn payload_for(field: &str, arguments: &str) -> Option<Value> {
        let payload = serde_json::from_str::<Value>(arguments).ok()?;
        let fits = if field == "actions" {
            payload.as_array().is_some_and(|a| !a.is_empty())
        } else {
            payload.as_object().is_some_and(|o| !o.is_empty())
        };
        fits.then_some(payload)
    }

    /// The built-in tool `item` calls for the CLIENT to run. A shell call in a
    /// hosted environment (`container_auto`, `container_reference`) is run by
    /// the server, in its container, before the response is written — no call
    /// of the client's ([`Self::is_hosted_shell`]).
    pub fn of_item(item: &Value) -> Option<Self> {
        let builtin = Self::of_item_type(item.get("type")?.as_str()?)?;
        (!Self::is_hosted_shell(item)).then_some(builtin)
    }

    /// Whether `item` is a shell call the server runs in a hosted container:
    /// one whose `environment` names any type but `local`.
    pub fn is_hosted_shell(item: &Value) -> bool {
        item.get("type").and_then(Value::as_str) == Some("shell_call")
            && item
                .pointer("/environment/type")
                .and_then(Value::as_str)
                .is_some_and(|kind| kind != "local")
    }

    /// The name a call to this tool is read under — by policy, the field
    /// profiles and the audit: the type of the output item that carries it.
    /// Never the tool's own `type` in the request (`shell`, `apply_patch`):
    /// clients name functions and custom tools that way (Codex's `shell`
    /// function, its `apply_patch` custom tool), and a field profile is keyed
    /// by name, so one written for the built-in call would be read for theirs.
    pub fn tool_name(self) -> &'static str {
        match self {
            Self::LocalShell => "local_shell_call",
            Self::Shell => "shell_call",
            Self::ApplyPatch => "apply_patch_call",
            Self::Computer => "computer_call",
        }
    }

    /// The field of `item` that holds the call's payload: a shell call's
    /// `action`, a patch's `operation`, a computer call's `action` — or its
    /// batched `actions` where it states no single one.
    pub fn payload_field(self, item: &Value) -> &'static str {
        match self {
            Self::LocalShell | Self::Shell => "action",
            Self::ApplyPatch => "operation",
            Self::Computer
                if item.get("action").is_none_or(Value::is_null) && item.get("actions").is_some_and(|a| !a.is_null()) =>
            {
                "actions"
            }
            Self::Computer => "action",
        }
    }

    /// The call's arguments as a JSON string: the payload of `item`, or
    /// nothing where the item states none yet.
    pub fn arguments(self, item: &Value) -> String {
        item.get(self.payload_field(item))
            .filter(|payload| !payload.is_null())
            .map(Value::to_string)
            .unwrap_or_default()
    }

    /// What a client that cannot run this tool is told in the call's place.
    pub fn not_carried_notice(self) -> &'static str {
        match self {
            Self::LocalShell => "\n[The model called the Responses built-in tool `local_shell`, which this client cannot run; the call was not carried.]\n",
            Self::Shell => "\n[The model called the Responses built-in tool `shell`, which this client cannot run; the call was not carried.]\n",
            Self::ApplyPatch => "\n[The model called the Responses built-in tool `apply_patch`, which this client cannot run; the call was not carried.]\n",
            Self::Computer => "\n[The model called the Responses built-in tool `computer`, which this client cannot run; the call was not carried.]\n",
        }
    }
}

/// The tool call `item` makes, if it makes one.
pub fn tool_call_item(item: &Value) -> Option<ToolCallItem<'_>> {
    fn str_of<'a>(v: &'a Value, key: &str) -> Option<&'a str> {
        v.get(key).and_then(Value::as_str)
    }
    let freeform = |text: Option<&str>| crate::api::domain_request::freeform_call_input(text.unwrap_or_default()).to_string();
    // Chat Completions: the definition sits under its kind.
    if let Some(f) = item.get("function").filter(|f| f.is_object()) {
        return Some(ToolCallItem {
            name: str_of(f, "name").unwrap_or_default(),
            call_id: str_of(item, "id"),
            arguments: str_of(f, "arguments").unwrap_or_default().to_string(),
            custom: false,
            builtin: None,
        });
    }
    if let Some(c) = item.get("custom").filter(|c| c.is_object()) {
        return Some(ToolCallItem {
            name: str_of(c, "name").unwrap_or_default(),
            call_id: str_of(item, "id"),
            arguments: freeform(str_of(c, "input")),
            custom: true,
            builtin: None,
        });
    }
    // Responses: a built-in tool's call is named by its tool, its arguments
    // the item's payload.
    if let Some(builtin) = ClientBuiltin::of_item(item) {
        return Some(ToolCallItem {
            name: builtin.tool_name(),
            call_id: str_of(item, "call_id").or_else(|| str_of(item, "id")),
            arguments: builtin.arguments(item),
            custom: false,
            builtin: Some(builtin),
        });
    }
    // Responses: flat, named by its type — and a Chat call some servers write
    // flat (`{type: "function", name, arguments}`), read the same way.
    let custom = match str_of(item, "type")? {
        "function_call" | "function" => false,
        "custom_tool_call" => true,
        _ => return None,
    };
    Some(ToolCallItem {
        name: str_of(item, "name").unwrap_or_default(),
        call_id: str_of(item, "call_id").or_else(|| str_of(item, "id")),
        arguments: if custom {
            freeform(str_of(item, "input"))
        } else {
            str_of(item, "arguments").unwrap_or_default().to_string()
        },
        custom,
        builtin: None,
    })
}

/// Write `arguments` (a JSON string, as [`tool_call_item`] reads them) back
/// into the call `item` makes, in whichever grammar it is written. A custom
/// call takes the free text of `{"input": <text>}`; arguments of any other
/// shape are its text as they stand, so a rewrite is never lost. A built-in
/// tool's call takes them as its structured payload, which arguments that are
/// not JSON of the payload's kind cannot be ([`ClientBuiltin::payload_for`]):
/// then nothing is written and the answer is `false` — the caller must not
/// leave the call standing as if rewritten.
#[must_use]
pub fn set_tool_call_arguments(item: &mut Value, arguments: &str) -> bool {
    let text = || {
        serde_json::from_str::<Value>(arguments)
            .ok()
            .and_then(|v| crate::api::domain_request::freeform_call_text(&v).map(str::to_string))
            .unwrap_or_else(|| arguments.to_string())
    };
    if let Some(Value::Object(f)) = item.get_mut("function") {
        f.insert("arguments".to_string(), Value::from(arguments));
    } else if let Some(Value::Object(c)) = item.get_mut("custom") {
        c.insert("input".to_string(), Value::from(text()));
    } else if let Some(builtin) = ClientBuiltin::of_item(item) {
        let field = builtin.payload_field(item);
        let Some(payload) = ClientBuiltin::payload_for(field, arguments) else {
            tracing::warn!(tool = builtin.tool_name(), "rewritten arguments do not fit a built-in tool call's payload; not written");
            return false;
        };
        item[field] = payload;
    } else if let Some(obj) = item.as_object_mut() {
        if obj.get("type").and_then(Value::as_str) == Some("custom_tool_call") {
            obj.insert("input".to_string(), Value::from(text()));
        } else {
            obj.insert("arguments".to_string(), Value::from(arguments));
        }
    }
    true
}

/// The body of a call to a custom (freeform) tool.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CustomToolCall {
    pub name: String,
    pub input: String,
}

/// Token usage.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Usage {
    #[serde(alias = "input_tokens")]
    pub prompt_tokens: u32,
    #[serde(alias = "output_tokens")]
    pub completion_tokens: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_creation_tokens: Option<u32>,
    /// The part of `cache_creation_tokens` written to a 1-hour cache, which
    /// Anthropic bills apart from the 5-minute default (its usage's
    /// `cache_creation.ephemeral_1h_input_tokens`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cache_creation_1h_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cache_read_tokens: Option<u32>,
    /// Prompt tokens that carried audio, reported by providers that price audio
    /// apart from text. Part of `prompt_tokens`, not additional to it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_prompt_tokens: Option<u32>,
    /// Completion tokens that carried audio. Part of `completion_tokens`.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub audio_completion_tokens: Option<u32>,
    /// Seconds of input audio, reported by a provider that counts audio in
    /// seconds rather than as prompt tokens (Mistral's `prompt_audio_seconds`).
    /// Not part of `prompt_tokens`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub audio_prompt_seconds: Option<u32>,
    /// Total tokens. Anthropic responses omit this field — `default` ensures
    /// deserialization succeeds and `total_tokens` is computed in `process_event`.
    #[serde(default)]
    pub total_tokens: u32,
}

impl Usage {
    /// State this measurement as billing units.
    ///
    /// Counts are passed through exactly as the provider reported them, which
    /// means `prompt_tokens` still contains its cache and audio portions; the
    /// pricing fold is what subtracts them. Reasoning tokens are deliberately
    /// not a unit — every provider bills them at the output rate and reports
    /// them inside the completion count.
    pub fn billed_units(&self) -> crate::pricing::Units {
        use crate::pricing::{Unit, Units};
        // The cache writes split by lifetime: each lifetime is its own unit,
        // carved out of the prompt count, so the 1-hour part is never billed
        // at the 5-minute rate.
        // The two lifetimes sum to the whole write count, which is what the
        // prompt count includes: a 1-hour count is held to it, so a partition
        // never takes out of the prompt more than the prompt holds.
        let writes = self.cache_creation_tokens.unwrap_or(0);
        let hourly = self.cache_creation_1h_tokens.unwrap_or(0).min(writes);
        Units::new()
            .with(Unit::InputToken, u64::from(self.prompt_tokens))
            .with(Unit::OutputToken, u64::from(self.completion_tokens))
            .with(Unit::CacheWriteToken, u64::from(writes - hourly))
            .with(Unit::CacheWrite1hToken, u64::from(hourly))
            .with(
                Unit::CacheReadToken,
                u64::from(self.cache_read_tokens.unwrap_or(0)),
            )
            .with(
                Unit::AudioInputToken,
                u64::from(self.audio_prompt_tokens.unwrap_or(0)),
            )
            .with(
                Unit::AudioOutputToken,
                u64::from(self.audio_completion_tokens.unwrap_or(0)),
            )
            .with(Unit::AudioSecond, u64::from(self.audio_prompt_seconds.unwrap_or(0)))
    }
}

/// How a streamed tool call's `arguments_delta` reads. The stream parser is the
/// one reader that knows a call is custom (freeform) — it read the wire's own
/// word for it — so it says so here, and every reader downstream acts on this
/// rather than on what the arguments look like: a function call cut off inside
/// a string reads exactly like an unclosed freeform call.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum CallArguments {
    /// A piece of a function call's JSON arguments.
    #[default]
    Json,
    /// A piece of a custom (freeform) call's text, escaped as it sits inside
    /// the domain's `{"input": <text>}`: the call's first piece opens that
    /// object (`FREEFORM_ARGS_OPEN`) and [`DomainEvent::FreeformCallEnd`]
    /// closes it.
    FreeformPiece,
    /// A custom call's whole arguments, `{"input": <text>}`, in one delta — a
    /// call the gateway wrote whole (a policy rewrite, a script).
    FreeformWhole,
    /// A piece of a custom call's text that arrived after the call's end (a
    /// lax server re-sending after its own done event, a call continued after
    /// other content). The call's arguments are closed, so no reader appends
    /// it: the block accumulator withholds it and says so, as it does late
    /// bytes of a call policy read, and every other reader does not write it.
    FreeformLate,
    /// A server tool's input (an Anthropic `server_tool_use` / `mcp_tool_use`
    /// block): a call the upstream runs itself. The audit records it as that
    /// server tool's call; policy does not hold it, and no emitter writes it
    /// (a pass-through client is sent the upstream's own frames).
    ServerTool,
    /// A piece of a call to a Responses built-in tool the client runs (see
    /// [`ClientBuiltin`]): JSON arguments, held and read by policy and
    /// recorded by the audit like a function call's. A Responses client is
    /// sent the item; any other client is told the call was not carried.
    ClientBuiltin(ClientBuiltin),
}

impl CallArguments {
    /// Whether the call is a custom (freeform) one.
    pub fn is_freeform(self) -> bool {
        matches!(self, Self::FreeformPiece | Self::FreeformWhole | Self::FreeformLate)
    }
}

/// Domain events produced by the SSE decoder — provider-neutral.
#[derive(Debug, Clone)]
pub enum DomainEvent {
    /// Incremental text content.
    TextDelta(String),
    /// Incremental reasoning/thinking content (from thinking models).
    ReasoningDelta(String),
    /// Incremental tool call. `index` is the stream's own number for the call
    /// — 0, 1, 2 … in the order calls open — once `sse::StreamParser` has read
    /// it (every production stream); the per-frame parse alone gives the
    /// upstream's index, which a Responses upstream sets to 0 for every call.
    ToolCallDelta {
        index: usize,
        id: Option<String>,
        function_name: Option<String>,
        arguments_delta: String,
        /// How `arguments_delta` reads — set by the parser that read the call,
        /// so no reader has to guess a freeform call from its text.
        form: CallArguments,
    },
    /// The end of a custom (freeform) tool call's streamed text, written by
    /// the gateway where the upstream's stream says the call is over but
    /// carries no piece of it — a Chat call followed by anything else, a
    /// Responses item closed by `output_item.done` alone, a stream cut short.
    /// It is the arguments' closing piece
    /// ([`crate::api::domain_request::FREEFORM_ARGS_CLOSE`], read as a
    /// `ToolCallDelta` by [`Self::as_tool_call_delta`]) and has no bytes of its
    /// own on the wire: a pass-through client already has every piece the
    /// upstream sent, so a pass-through emitter writes nothing for it.
    /// `index` is the call's number, as on `ToolCallDelta`.
    FreeformCallEnd { index: usize },
    /// Image generation result from Responses API `image_generation` tool.
    ImageGeneration {
        index: usize,
        /// Final base64 image data (only on `output_item.done`).
        result_base64: Option<String>,
    },
    /// Final usage information.
    Usage(Usage),
    /// Stream finished.
    Done {
        finish_reason: Option<FinishReason>,
        native_finish_reason: Option<String>,
    },
    /// Error from upstream.
    Error { message: String, code: Option<String> },

    /// Synthesised server-tool call (visible-mode substitution emulation).
    /// Emitted by the substitution loop when a server-side server-tool the
    /// client requested (Anthropic `web_search_20250305`, OpenAI Responses
    /// `web_search_preview`, Gemini `google_search`) is being executed by the
    /// gateway. Per-protocol streaming renderers translate this into the
    /// protocol's native server-tool wire shape (`server_tool_use` for
    /// Anthropic, `web_search_call` for Responses, `groundingMetadata` for
    /// Gemini). No emitter today — wiring lands with the agent loop.
    ServerToolCallDelta {
        index: usize,
        /// Stable id correlating this call to the eventual `ServerToolResult`
        /// / `ServerToolError`. The agent loop allocates one id per pending
        /// intercept (preferring the upstream's `tool_use.id` when known,
        /// falling back to `tu_sub_<request_id>_<call_index>`) and
        /// uses the same value on both events; per-protocol renderers
        /// project it into the protocol-native `id` slot
        /// (Anthropic `server_tool_use.id`, Responses `web_search_call.id`).
        tool_use_id: String,
        /// The original `server_type` the client requested
        /// (`web_search_20250305`, `web_search_preview`, `google_search`).
        server_type: String,
        /// Canonical executor tool name (`web_search` / `web_fetch`).
        name: String,
        /// Incremental input arguments JSON.
        input_delta: String,
    },
    /// Result for a synthesised server-tool call. Carries the executor's
    /// filtered output (`SearchResult` / `FetchResult` from `WebService`)
    /// re-rendered into the protocol's native result-block shape by the
    /// per-protocol streaming renderer.
    ServerToolResult {
        index: usize,
        tool_use_id: String,
        /// Protocol-agnostic result payload — renderer projects to native
        /// shape per inbound protocol.
        content: serde_json::Value,
    },
    /// Error result for a substitution-loop executor call. Carries the
    /// failure reason; rendered as a protocol-native error block.
    ServerToolError {
        index: usize,
        tool_use_id: String,
        error_kind: String,
    },
}

impl DomainEvent {
    /// The number of a call event that belongs to no call — a nameless piece
    /// the upstream sent when no call was open to take it (after every call
    /// retired, or before any opened). No call is ever given it, so no reader
    /// keyed on a call's number attributes the delta to one: every emitter
    /// and policy set it aside ([`Self::not_a_client_call`]), and the audit
    /// records its bytes as withheld.
    pub const NO_CALL: usize = usize::MAX;

    /// Whether this is a call delta that belongs to no call.
    pub fn of_no_call(&self) -> bool {
        matches!(self, Self::ToolCallDelta { index, .. } if *index == Self::NO_CALL)
    }

    /// Whether this is a call delta no client is given: one of no call, or a
    /// server tool's input the upstream runs itself.
    pub fn not_a_client_call(&self) -> bool {
        self.of_no_call() || matches!(self, Self::ToolCallDelta { form: CallArguments::ServerTool, .. })
    }

    /// Whether this is a call delta whose bytes no call may take — a custom
    /// call's text after its end, or a delta of no call: the stream parser's
    /// one word that a delta is late. No client is sent it, raw or rendered;
    /// every reader withholds its bytes, the audit records them withheld, and
    /// the client is told.
    pub fn is_withheld_piece(&self) -> bool {
        matches!(self, Self::ToolCallDelta { index, form, .. }
            if *index == Self::NO_CALL || *form == CallArguments::FreeformLate)
    }

    /// A [`Self::FreeformCallEnd`] as the arguments piece it stands for, so a
    /// consumer building a call's arguments reads it like any other piece;
    /// every other event as it is.
    pub fn as_tool_call_delta(&self) -> std::borrow::Cow<'_, DomainEvent> {
        match self {
            Self::FreeformCallEnd { index } => std::borrow::Cow::Owned(Self::ToolCallDelta {
                index: *index,
                id: None,
                function_name: None,
                arguments_delta: crate::api::domain_request::FREEFORM_ARGS_CLOSE.to_string(),
                form: CallArguments::FreeformPiece,
            }),
            other => std::borrow::Cow::Borrowed(other),
        }
    }
}

/// Responses API input format.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ResponseInput {
    Text(String),
    Messages(Vec<ResponseInputMessage>),
    /// Heterogeneous array of raw JSON items (messages + function_call + function_call_output etc.)
    Raw(Vec<Value>),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponseInputMessage {
    pub role: String,
    pub content: MessageContent,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[cfg(test)]
mod tests {
    #[test]
    fn a_computer_calls_payload_is_its_action_unless_it_states_only_a_batch() {
        use serde_json::json;
        let field = |item| ClientBuiltin::Computer.payload_field(&item);
        assert_eq!(field(json!({"action": {"type": "wait"}})), "action");
        assert_eq!(field(json!({"actions": [{"type": "wait"}]})), "actions");
        // Both stated: the single action is the payload; neither: `action`,
        // where a rewrite would write it.
        assert_eq!(field(json!({"action": {"type": "wait"}, "actions": []})), "action");
        assert_eq!(field(json!({})), "action");
        // A null action states nothing: the batch is the payload.
        assert_eq!(field(json!({"action": null, "actions": [{"type": "wait"}]})), "actions");
    }

    #[test]
    fn a_built_in_payload_is_rewritten_only_to_json_of_its_own_kind() {
        use serde_json::json;
        let mut call = json!({"type": "shell_call", "call_id": "c", "action": {"commands": ["rm -rf /"]}});
        for unfit in ["echo safe", "\"echo safe\"", "42", "[\"echo\"]"] {
            assert!(!set_tool_call_arguments(&mut call, unfit), "{unfit} was written");
        }
        assert_eq!(call["action"], json!({"commands": ["rm -rf /"]}), "an unfit rewrite left the call changed");
        assert!(set_tool_call_arguments(&mut call, r#"{"commands": ["ls"]}"#));
        assert_eq!(call["action"], json!({"commands": ["ls"]}));
        let mut batch = json!({"type": "computer_call", "call_id": "c", "actions": [{"type": "wait"}]});
        assert!(!set_tool_call_arguments(&mut batch, r#"{"type": "wait"}"#), "a batch takes a list");
        assert!(!set_tool_call_arguments(&mut batch, r#"[]"#), "an emptied batch is no call");
        assert!(!set_tool_call_arguments(&mut call, r#"{}"#), "an emptied payload is no call");
        assert!(set_tool_call_arguments(&mut batch, r#"[{"type": "wait"}]"#));
    }

    use super::*;

    #[test]
    fn usage_deserializes_from_chat_completions_fields() {
        let json = r#"{"prompt_tokens":10,"completion_tokens":20,"total_tokens":30}"#;
        let usage: Usage = serde_json::from_str(json).unwrap();
        assert_eq!(usage.prompt_tokens, 10);
        assert_eq!(usage.completion_tokens, 20);
        assert_eq!(usage.total_tokens, 30);
    }

    #[test]
    fn usage_deserializes_from_responses_api_fields() {
        let json = r#"{"input_tokens":15,"output_tokens":25,"total_tokens":40}"#;
        let usage: Usage = serde_json::from_str(json).unwrap();
        assert_eq!(usage.prompt_tokens, 15);
        assert_eq!(usage.completion_tokens, 25);
        assert_eq!(usage.total_tokens, 40);
    }

    #[test]
    fn usage_serializes_with_canonical_field_names() {
        let usage = Usage {
            prompt_tokens: 10,
            completion_tokens: 20,
            reasoning_tokens: None,
            cache_creation_tokens: None,
            cache_creation_1h_tokens: None,
            cache_read_tokens: None,
            total_tokens: 30,
            audio_prompt_tokens: None,
            audio_completion_tokens: None,
            audio_prompt_seconds: None,
        };
        let json = serde_json::to_value(&usage).unwrap();
        assert!(json.get("prompt_tokens").is_some());
        assert!(json.get("completion_tokens").is_some());
        // Aliases are input-only; output always uses canonical names
        assert!(json.get("input_tokens").is_none());
        assert!(json.get("output_tokens").is_none());
    }

    #[test]
    fn finish_reason_normalize_covers_all_variants() {
        assert_eq!(FinishReason::normalize("stop"), FinishReason::Stop);
        assert_eq!(FinishReason::normalize("end_turn"), FinishReason::Stop);
        assert_eq!(FinishReason::normalize("length"), FinishReason::Length);
        assert_eq!(FinishReason::normalize("max_tokens"), FinishReason::Length);
        assert_eq!(FinishReason::normalize("model_length"), FinishReason::Length);
        assert_eq!(FinishReason::normalize("error"), FinishReason::Error);
        assert_eq!(FinishReason::normalize("tool_calls"), FinishReason::ToolCalls);
        assert_eq!(FinishReason::normalize("tool_use"), FinishReason::ToolCalls);
        assert_eq!(FinishReason::normalize("function_call"), FinishReason::ToolCalls);
        assert_eq!(FinishReason::normalize("content_filter"), FinishReason::ContentFilter);
        assert_eq!(FinishReason::normalize("safety"), FinishReason::ContentFilter);
        assert_eq!(FinishReason::normalize("unknown_thing"), FinishReason::Error);
    }
}
