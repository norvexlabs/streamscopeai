//! OpenAI Responses API wire types (`/v1/responses`).
//!
//! Newer OpenAI format where `instructions` replaces the system message and
//! `input` is a flexible multi-format field (string, array, or message list).
//! Supports server-side conversation state via `previous_response_id`.

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::domain::{ResponseInput, Tool};

/// OpenAI Responses API request body.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResponsesRequest {
    pub model: String,
    pub input: ResponseInput,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub previous_response_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instructions: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tools: Option<Vec<Tool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub temperature: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_output_tokens: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub top_p: Option<f64>,
    /// Context overflow control: "auto" | "disabled".
    #[serde(skip_serializing_if = "Option::is_none")]
    pub truncation: Option<Value>,
    /// Reasoning configuration: { effort: "low"|"medium"|"high", summary: ... }.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reasoning: Option<Value>,
    /// Tool choice: "auto" | "required" | "none" | { type, name } | an
    /// allowlist or hosted-tool choice (see `api::tool_choice`).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tool_choice: Option<Value>,
    /// Whether the model may run tool calls in parallel (`bool | null`,
    /// default `true`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parallel_tool_calls: Option<bool>,
    /// Whether responses are stored server-side by the provider.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub store: Option<bool>,
    /// Arbitrary key-value metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Value>,
    /// Forward-compat: capture unknown fields.
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

/// A Responses message part's text: an `output_text`'s `text`, a `refusal`
/// part's `refusal` — each the spec's member for it. The one reading every
/// reader of a part (the record, the translators, the pass-through) shares.
pub fn part_text(part: &Value) -> Option<&str> {
    let key = if part.get("type").and_then(Value::as_str) == Some("refusal") { "refusal" } else { "text" };
    part.get(key).and_then(Value::as_str)
}

/// The refusal a Responses answer's `refusal` part holds
/// (`ResponseOutputRefusal { refusal, type }`), when it is a non-empty string
/// — the reader of a part as the answer's refusal ([`part_text`] reads any
/// part's text, a refusal's included, where the two are one text).
pub fn refusal_part_text(part: &Value) -> Option<&str> {
    (part.get("type").and_then(Value::as_str) == Some("refusal"))
        .then(|| part_text(part))
        .flatten()
        .filter(|r| !r.is_empty())
}
