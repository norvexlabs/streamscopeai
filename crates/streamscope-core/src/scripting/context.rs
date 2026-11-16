//! RequestContext — the Rhai-visible data model.
//!
//! Text + tool-call projection of `ApiRequest`. Images, thinking blocks, cache_control,
//! and other structured content are opaque to scripts and pass through unchanged.
//! Scripts can read and mutate message text and assistant tool calls
//! (`id`, `name`, `arguments_json`); mutations are reconciled back into the native
//! protocol representation on apply.

use std::collections::{BTreeMap, HashMap};

use rhai::Dynamic;

use serde_json::Value;

use crate::api::domain::{FunctionDef, Message, MessageContent, Tool};
use crate::api::domain_request::{
    chat_system_lead, DomainContentBlock, DomainMessage, DomainRequest, DomainRole, DomainSystemPrompt,
};
use crate::api::messages::{
    AnthropicContent, AnthropicMessage, AnthropicTool, ContentBlock, SystemPrompt,
};
use crate::api::gemini::{GeminiContent, GeminiPart};
use crate::api::ApiRequest;
use crate::auth::UserContext;

/// Rhai-visible tool call on an assistant message.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct RhaiToolCall {
    pub id: String,
    pub name: String,
    /// Arguments as a JSON string. Scripts read/write the raw JSON.
    pub arguments_json: String,
}

impl RhaiToolCall {
    pub fn to_dynamic(&self) -> Dynamic {
        let mut map = rhai::Map::new();
        map.insert("id".into(), self.id.clone().into());
        map.insert("name".into(), self.name.clone().into());
        map.insert(
            "arguments_json".into(),
            self.arguments_json.clone().into(),
        );
        Dynamic::from_map(map)
    }

    pub fn from_dynamic(val: &Dynamic) -> Option<Self> {
        let map = val.read_lock::<rhai::Map>()?;
        Some(Self {
            id: map
                .get("id")
                .and_then(|v| v.clone().into_string().ok())
                .unwrap_or_default(),
            name: map
                .get("name")
                .and_then(|v| v.clone().into_string().ok())
                .unwrap_or_default(),
            arguments_json: map
                .get("arguments_json")
                .and_then(|v| v.clone().into_string().ok())
                .unwrap_or_default(),
        })
    }
}

/// Rhai-visible message. Text + tool-call projection.
#[derive(Debug, Clone, Default)]
pub struct RhaiMessage {
    pub role: String,
    pub content: String,
    pub tool_call_id: Option<String>,
    /// Assistant tool calls (ToolUse / FunctionCall). Empty on non-assistant messages.
    /// Mutations are reconciled back to the native protocol on apply.
    pub tool_calls: Vec<RhaiToolCall>,
    /// Which message of the request this one was read as (its index in the
    /// messages the script was given): it travels with the message wherever
    /// the script keeps or moves it, and is what the write-back writes it
    /// over. `None` on a message the script made.
    pub origin: Option<usize>,
}

impl RhaiMessage {
    pub fn to_dynamic(&self) -> Dynamic {
        let mut map = rhai::Map::new();
        map.insert("role".into(), self.role.clone().into());
        map.insert("content".into(), self.content.clone().into());
        map.insert(
            "tool_call_id".into(),
            self.tool_call_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        let tc_array: rhai::Array = self.tool_calls.iter().map(|t| t.to_dynamic()).collect();
        map.insert("tool_calls".into(), Dynamic::from_array(tc_array));
        if let Some(origin) = self.origin.and_then(|o| rhai::INT::try_from(o).ok()) {
            map.insert("origin".into(), origin.into());
        }
        Dynamic::from_map(map)
    }

    pub fn from_dynamic(val: &Dynamic) -> Option<Self> {
        let map = val.read_lock::<rhai::Map>()?;
        let tool_calls = map
            .get("tool_calls")
            .and_then(|v| v.read_lock::<rhai::Array>().map(|a| a.clone()))
            .map(|arr| {
                arr.iter()
                    .filter_map(RhaiToolCall::from_dynamic)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Some(Self {
            role: map
                .get("role")
                .and_then(|v| v.clone().into_string().ok())
                .unwrap_or_default(),
            content: map
                .get("content")
                .and_then(|v| v.clone().into_string().ok())
                .unwrap_or_default(),
            tool_call_id: map
                .get("tool_call_id")
                .and_then(|v| {
                    if v.is_unit() {
                        None
                    } else {
                        v.clone().into_string().ok()
                    }
                }),
            tool_calls,
            origin: map.get("origin").and_then(|v| v.as_int().ok()).and_then(|o| usize::try_from(o).ok()),
        })
    }
}

/// Rhai-visible tool definition — text-only projection.
///
/// `is_gateway_substituted` is set to `true` when the tool-policy
/// `Substitute` action rewrote a native server-tool definition into a
/// function-tool with the gateway's replacement schema. Operator scripts
/// (e.g. `server_tool_filter`) gate on this typed flag instead of the
/// brittle `parameters_json == ()` heuristic.
///
/// A provider-hosted tool (a Responses `web_search`, `file_search`, `mcp`, …)
/// names no function, so every one reads to a script with the empty name;
/// `kind` (its wire type) and `config_json` (its configuration) are what it
/// IS, and a tool the script keeps is matched back to it by them — never by
/// the name it shares with every other hosted tool.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct RhaiTool {
    pub name: String,
    pub description: Option<String>,
    pub parameters_json: Option<String>,
    pub is_gateway_substituted: bool,
    /// A hosted tool's wire type (`web_search`, …); `None` for a function.
    pub kind: Option<String>,
    /// A hosted tool's configuration, as JSON; `None` for a function.
    pub config_json: Option<String>,
}

impl RhaiTool {
    pub fn to_dynamic(&self) -> Dynamic {
        let mut map = rhai::Map::new();
        map.insert("name".into(), self.name.clone().into());
        map.insert(
            "description".into(),
            self.description
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert(
            "parameters_json".into(),
            self.parameters_json
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert(
            "is_gateway_substituted".into(),
            self.is_gateway_substituted.into(),
        );
        for (key, value) in [("kind", &self.kind), ("config_json", &self.config_json)] {
            map.insert(key.into(), value.as_ref().map_or(Dynamic::UNIT, |s| s.clone().into()));
        }
        Dynamic::from_map(map)
    }

    pub fn from_dynamic(val: &Dynamic) -> Option<Self> {
        let map = val.read_lock::<rhai::Map>()?;
        Some(Self {
            name: map
                .get("name")
                .and_then(|v| v.clone().into_string().ok())
                .unwrap_or_default(),
            description: map
                .get("description")
                .and_then(|v| {
                    if v.is_unit() {
                        None
                    } else {
                        v.clone().into_string().ok()
                    }
                }),
            parameters_json: map
                .get("parameters_json")
                .and_then(|v| {
                    if v.is_unit() {
                        None
                    } else {
                        v.clone().into_string().ok()
                    }
                }),
            is_gateway_substituted: map
                .get("is_gateway_substituted")
                .and_then(|v| v.as_bool().ok())
                .unwrap_or(false),
            kind: map.get("kind").filter(|v| !v.is_unit()).and_then(|v| v.clone().into_string().ok()),
            config_json: map.get("config_json").filter(|v| !v.is_unit()).and_then(|v| v.clone().into_string().ok()),
        })
    }
}

/// The Rhai-visible request context.
#[derive(Debug, Clone)]
pub struct RequestContext {
    pub system_prompt: Option<String>,
    pub messages: Vec<RhaiMessage>,
    pub tools: Vec<RhaiTool>,
    pub model: String,
    pub user_id: String,
    pub app_id: Option<String>,
    pub api_version: String,
    pub metadata: HashMap<String, String>,
    pub labels: Vec<String>,
}

/// Lightweight text snapshot of a RequestContext for change detection and diff generation.
#[derive(Clone, PartialEq)]
pub struct ContextSnapshot {
    pub system_prompt: Option<String>,
    pub messages: Vec<(String, String)>,            // (role, content)
    pub tools: Vec<(String, Option<String>, Option<String>)>, // (name, description, parameters_json)
    pub model: String,
}

impl RequestContext {
    /// The text a `trigger_regex` fast-find is tested against for a given scope.
    /// Concatenates only the fields a script of that scope can read, so a trigger
    /// is matched against the same content the script would operate on.
    /// `global` sees everything (it can read all scopes).
    pub fn scope_searchable_text(&self, scope: &str) -> String {
        let mut out = String::new();
        let want_system = scope == "system_prompt" || scope == "global";
        let want_messages = scope == "messages" || scope == "global";
        let want_tools = scope == "tools" || scope == "global";
        if want_system && let Some(sp) = &self.system_prompt {
            out.push_str(sp);
            out.push('\n');
        }
        if want_messages {
            for m in &self.messages {
                out.push_str(&m.content);
                out.push('\n');
            }
        }
        if want_tools {
            for t in &self.tools {
                out.push_str(&t.name);
                if let Some(d) = &t.description {
                    out.push(' ');
                    out.push_str(d);
                }
                if let Some(p) = &t.parameters_json {
                    out.push(' ');
                    out.push_str(p);
                }
                out.push('\n');
            }
        }
        out
    }

    /// Apply a text transform to each writable text field of the given scope, in
    /// place, for span-mode transforms. `f` receives a field's text and returns
    /// `Some(new)` to replace it or `None` to leave it. Returns whether any field
    /// changed; the first `Err` short-circuits so the caller can apply fail-mode.
    /// Mirrors the read scopes of [`scope_searchable_text`](Self::scope_searchable_text)
    /// so a span runs over exactly the text its `trigger_regex` was matched against.
    /// Tool `name` is left untouched (it is a routing identifier, not free text).
    pub fn apply_text_transform<F>(&mut self, scope: &str, mut f: F) -> Result<bool, String>
    where
        F: FnMut(&str) -> Result<Option<String>, String>,
    {
        let mut changed = false;
        let want_system = scope == "system_prompt" || scope == "global";
        let want_messages = scope == "messages" || scope == "global";
        let want_tools = scope == "tools" || scope == "global";
        if want_system
            && let Some(sp) = self.system_prompt.clone()
            && let Some(new) = f(&sp)?
        {
            self.system_prompt = Some(new);
            changed = true;
        }
        if want_messages {
            for m in self.messages.iter_mut() {
                if let Some(new) = f(&m.content)? {
                    m.content = new;
                    changed = true;
                }
            }
        }
        if want_tools {
            for t in self.tools.iter_mut() {
                if let Some(desc) = t.description.clone()
                    && let Some(new) = f(&desc)?
                {
                    t.description = Some(new);
                    changed = true;
                }
                if let Some(p) = t.parameters_json.clone()
                    && let Some(new) = f(&p)?
                {
                    t.parameters_json = Some(new);
                    changed = true;
                }
            }
        }
        Ok(changed)
    }

    /// Capture a lightweight snapshot for change detection / diff.
    pub fn snapshot(&self) -> ContextSnapshot {
        ContextSnapshot {
            system_prompt: self.system_prompt.clone(),
            messages: self
                .messages
                .iter()
                .map(|m| (m.role.clone(), m.content.clone()))
                .collect(),
            tools: self
                .tools
                .iter()
                .map(|t| (t.name.clone(), t.description.clone(), t.parameters_json.clone()))
                .collect(),
            model: self.model.clone(),
        }
    }
}

impl ContextSnapshot {
    /// Generate a unified-diff-style text comparing `self` (before) to `other` (after).
    /// Returns `None` if no changes detected.
    pub fn diff(&self, other: &ContextSnapshot) -> Option<String> {
        if self == other {
            return None;
        }
        let mut lines = Vec::new();

        // System prompt
        if self.system_prompt != other.system_prompt {
            lines.push("@@ system_prompt @@".to_string());
            match (&self.system_prompt, &other.system_prompt) {
                (Some(old), Some(new)) => {
                    for l in old.lines() {
                        lines.push(format!("-{l}"));
                    }
                    for l in new.lines() {
                        lines.push(format!("+{l}"));
                    }
                }
                (None, Some(new)) => {
                    for l in new.lines() {
                        lines.push(format!("+{l}"));
                    }
                }
                (Some(old), None) => {
                    for l in old.lines() {
                        lines.push(format!("-{l}"));
                    }
                }
                _ => {}
            }
        }

        // Model
        if self.model != other.model {
            lines.push("@@ model @@".to_string());
            lines.push(format!("-{}", self.model));
            lines.push(format!("+{}", other.model));
        }

        // Messages
        let max_len = self.messages.len().max(other.messages.len());
        for i in 0..max_len {
            let old = self.messages.get(i);
            let new = other.messages.get(i);
            match (old, new) {
                (Some((or, oc)), Some((nr, nc))) if or != nr || oc != nc => {
                    lines.push(format!("@@ messages[{i}] @@"));
                    if or != nr {
                        lines.push(format!("-role: {or}"));
                        lines.push(format!("+role: {nr}"));
                    }
                    if oc != nc {
                        for l in oc.lines().take(10) {
                            lines.push(format!("-{l}"));
                        }
                        if oc.lines().count() > 10 {
                            lines.push(format!("-... ({} more lines)", oc.lines().count() - 10));
                        }
                        for l in nc.lines().take(10) {
                            lines.push(format!("+{l}"));
                        }
                        if nc.lines().count() > 10 {
                            lines.push(format!("+... ({} more lines)", nc.lines().count() - 10));
                        }
                    }
                }
                (Some((or, oc)), None) => {
                    lines.push(format!("@@ messages[{i}] @@"));
                    lines.push(format!("-[{or}] {}", &oc[..oc.floor_char_boundary(100)]));
                }
                (None, Some((nr, nc))) => {
                    lines.push(format!("@@ messages[{i}] @@"));
                    lines.push(format!("+[{nr}] {}", &nc[..nc.floor_char_boundary(100)]));
                }
                _ => {}
            }
        }

        // Tools — render each tool as a single key for diff. Description /
        // parameters_json round-trip into the snapshot so per-field changes
        // surface as a remove+add pair (rather than going silently undetected
        // when only names match).
        if self.tools != other.tools {
            lines.push("@@ tools @@".to_string());
            let fmt = |t: &(String, Option<String>, Option<String>)| {
                let (n, d, p) = t;
                format!(
                    "{}|{}|{}",
                    n,
                    d.as_deref().unwrap_or(""),
                    p.as_deref().unwrap_or(""),
                )
            };
            for t in &self.tools {
                if !other.tools.contains(t) {
                    lines.push(format!("-{}", fmt(t)));
                }
            }
            for t in &other.tools {
                if !self.tools.contains(t) {
                    lines.push(format!("+{}", fmt(t)));
                }
            }
        }

        if lines.is_empty() {
            None
        } else {
            Some(lines.join("\n"))
        }
    }
}

impl RequestContext {
    /// Convert to a Rhai `Dynamic` map.
    pub fn to_dynamic(&self) -> Dynamic {
        let mut map = rhai::Map::new();

        map.insert(
            "system_prompt".into(),
            self.system_prompt
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );

        let msgs: rhai::Array = self.messages.iter().map(|m| m.to_dynamic()).collect();
        map.insert("messages".into(), Dynamic::from_array(msgs));

        let tools: rhai::Array = self.tools.iter().map(|t| t.to_dynamic()).collect();
        map.insert("tools".into(), Dynamic::from_array(tools));

        map.insert("model".into(), self.model.clone().into());
        map.insert("user_id".into(), self.user_id.clone().into());
        map.insert(
            "app_id".into(),
            self.app_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert("api_version".into(), self.api_version.clone().into());

        let meta: rhai::Map = self
            .metadata
            .iter()
            .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
            .collect();
        map.insert("metadata".into(), Dynamic::from_map(meta));

        let labels: rhai::Array = self.labels.iter().map(|l| Dynamic::from(l.clone())).collect();
        map.insert("labels".into(), Dynamic::from_array(labels));

        Dynamic::from_map(map)
    }

    /// Build a projected Dynamic map for a specific scope.
    ///
    /// Only writable fields for the scope are included, plus read-only context.
    /// - `global`: all fields
    /// - `system_prompt`: system_prompt, metadata, labels + read-only
    /// - `messages`: messages, metadata, labels + read-only
    /// - `tools`: tools, metadata, labels + read-only
    pub fn project_for_scope(&self, scope: &str) -> Dynamic {
        let mut map = rhai::Map::new();

        // Read-only context (always included)
        map.insert("user_id".into(), self.user_id.clone().into());
        map.insert(
            "app_id".into(),
            self.app_id
                .as_ref()
                .map_or(Dynamic::UNIT, |s| s.clone().into()),
        );
        map.insert("api_version".into(), self.api_version.clone().into());

        // Metadata and labels (always writable)
        let meta: rhai::Map = self
            .metadata
            .iter()
            .map(|(k, v)| (k.clone().into(), Dynamic::from(v.clone())))
            .collect();
        map.insert("metadata".into(), Dynamic::from_map(meta));

        let labels: rhai::Array = self.labels.iter().map(|l| Dynamic::from(l.clone())).collect();
        map.insert("labels".into(), Dynamic::from_array(labels));

        match scope {
            "global" => {
                // Full context — same as to_dynamic()
                map.insert(
                    "system_prompt".into(),
                    self.system_prompt
                        .as_ref()
                        .map_or(Dynamic::UNIT, |s| s.clone().into()),
                );
                let msgs: rhai::Array = self.messages.iter().map(|m| m.to_dynamic()).collect();
                map.insert("messages".into(), Dynamic::from_array(msgs));
                let tools: rhai::Array = self.tools.iter().map(|t| t.to_dynamic()).collect();
                map.insert("tools".into(), Dynamic::from_array(tools));
                map.insert("model".into(), self.model.clone().into());
            }
            "system_prompt" => {
                map.insert(
                    "system_prompt".into(),
                    self.system_prompt
                        .as_ref()
                        .map_or(Dynamic::UNIT, |s| s.clone().into()),
                );
            }
            "messages" => {
                let msgs: rhai::Array = self.messages.iter().map(|m| m.to_dynamic()).collect();
                map.insert("messages".into(), Dynamic::from_array(msgs));
            }
            "tools" => {
                let tools: rhai::Array = self.tools.iter().map(|t| t.to_dynamic()).collect();
                map.insert("tools".into(), Dynamic::from_array(tools));
            }
            _ => {
                // Unknown scope — treat as global
                return self.to_dynamic();
            }
        }

        Dynamic::from_map(map)
    }

    /// Merge writable fields from a scoped execution result back into this context.
    ///
    /// Only fields writable for the given scope are read back.
    pub fn merge_from_scope(&mut self, scope: &str, result: &Dynamic) {
        let Some(map) = result.read_lock::<rhai::Map>() else {
            return;
        };

        // Always merge metadata and labels
        if let Some(meta) = map.get("metadata").and_then(|v| v.read_lock::<rhai::Map>()) {
            self.metadata = meta
                .iter()
                .filter_map(|(k, v)| v.clone().into_string().ok().map(|s| (k.to_string(), s)))
                .collect();
        }
        if let Some(arr) = map.get("labels").and_then(|v| v.read_lock::<rhai::Array>()) {
            self.labels = arr
                .iter()
                .filter_map(|v| v.clone().into_string().ok())
                .collect();
        }

        match scope {
            "global" => {
                // Merge everything
                self.system_prompt = map.get("system_prompt").and_then(|v| {
                    if v.is_unit() { None } else { v.clone().into_string().ok() }
                });
                self.messages = map
                    .get("messages")
                    .and_then(|v| v.read_lock::<rhai::Array>())
                    .map(|arr| arr.iter().filter_map(RhaiMessage::from_dynamic).collect())
                    .unwrap_or_default();
                self.tools = map
                    .get("tools")
                    .and_then(|v| v.read_lock::<rhai::Array>())
                    .map(|arr| arr.iter().filter_map(RhaiTool::from_dynamic).collect())
                    .unwrap_or_default();
                if let Some(model) = map.get("model").and_then(|v| v.clone().into_string().ok()) {
                    self.model = model;
                }
            }
            "system_prompt" => {
                self.system_prompt = map.get("system_prompt").and_then(|v| {
                    if v.is_unit() { None } else { v.clone().into_string().ok() }
                });
            }
            "messages" => {
                self.messages = map
                    .get("messages")
                    .and_then(|v| v.read_lock::<rhai::Array>())
                    .map(|arr| arr.iter().filter_map(RhaiMessage::from_dynamic).collect())
                    .unwrap_or_default();
            }
            "tools" => {
                self.tools = map
                    .get("tools")
                    .and_then(|v| v.read_lock::<rhai::Array>())
                    .map(|arr| arr.iter().filter_map(RhaiTool::from_dynamic).collect())
                    .unwrap_or_default();
            }
            _ => {
                // Unknown scope — merge all (defensive)
                if let Some(full) = RequestContext::from_dynamic(result) {
                    *self = full;
                }
            }
        }
    }

    /// Convert from a Rhai `Dynamic` map back to RequestContext.
    pub fn from_dynamic(val: &Dynamic) -> Option<Self> {
        let map = val.read_lock::<rhai::Map>()?;

        let system_prompt = map
            .get("system_prompt")
            .and_then(|v| {
                if v.is_unit() {
                    None
                } else {
                    v.clone().into_string().ok()
                }
            });

        let messages = map
            .get("messages")
            .and_then(|v| v.read_lock::<rhai::Array>())
            .map(|arr| {
                arr.iter()
                    .filter_map(RhaiMessage::from_dynamic)
                    .collect()
            })
            .unwrap_or_default();

        let tools = map
            .get("tools")
            .and_then(|v| v.read_lock::<rhai::Array>())
            .map(|arr| {
                arr.iter()
                    .filter_map(RhaiTool::from_dynamic)
                    .collect()
            })
            .unwrap_or_default();

        let model = map
            .get("model")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let user_id = map
            .get("user_id")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let app_id = map
            .get("app_id")
            .and_then(|v| {
                if v.is_unit() {
                    None
                } else {
                    v.clone().into_string().ok()
                }
            });

        let api_version = map
            .get("api_version")
            .and_then(|v| v.clone().into_string().ok())
            .unwrap_or_default();

        let metadata = map
            .get("metadata")
            .and_then(|v| v.read_lock::<rhai::Map>())
            .map(|meta_map| {
                meta_map
                    .iter()
                    .filter_map(|(k, v)| {
                        v.clone().into_string().ok().map(|s| (k.to_string(), s))
                    })
                    .collect()
            })
            .unwrap_or_default();

        let labels = map
            .get("labels")
            .and_then(|v| v.read_lock::<rhai::Array>())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.clone().into_string().ok())
                    .collect()
            })
            .unwrap_or_default();

        Some(Self {
            system_prompt,
            messages,
            tools,
            model,
            user_id,
            app_id,
            api_version,
            metadata,
            labels,
        })
    }
}

/// Extract a `RequestContext` from an `ApiRequest` + user context.
///
/// Uses `DomainRequest` for unified extraction of system prompt, tools, and messages:
/// the system prompt is `system_prompt` alone on every protocol, never a message
/// (on Chat Completions, the leading system and developer messages).
///
/// `substituted_tool_names` carries the wire `name`s of tool defs the
/// request-phase tool-policy rewrote via `Substitute` — used to mark each
/// projected `RhaiTool` so operator scripts can gate on the typed
/// `is_gateway_substituted` flag.
pub fn from_api_request(
    req: &ApiRequest,
    user: &UserContext,
    app_id: Option<&str>,
    context_window: Option<i32>,
    upstream_provider: Option<&str>,
    needs_translation: bool,
    substituted_tool_names: &std::collections::HashSet<String>,
) -> RequestContext {
    let domain = DomainRequest::from_api_request(req);
    project(req, domain, user, app_id, context_window, upstream_provider, needs_translation, substituted_tool_names)
}

/// [`from_api_request`] without the conversation
/// ([`DomainRequest::without_conversation`]): no messages, the system prompt
/// kept — the projection a chain of programs that read no messages gets, which
/// so never converts a long history. On Chat Completions the system prompt is
/// read from the leading system messages alone.
#[allow(clippy::too_many_arguments)]
pub fn without_conversation(
    req: &ApiRequest,
    user: &UserContext,
    app_id: Option<&str>,
    context_window: Option<i32>,
    upstream_provider: Option<&str>,
    needs_translation: bool,
    substituted_tool_names: &std::collections::HashSet<String>,
) -> RequestContext {
    let domain = DomainRequest::without_conversation(req);
    project(req, domain, user, app_id, context_window, upstream_provider, needs_translation, substituted_tool_names)
}

/// The flat system prompt a script sees, read from `domain`.
fn system_prompt_text(req: &ApiRequest, domain: &DomainRequest) -> Option<String> {
    let inbound_target = match req {
        ApiRequest::AnthropicMessages(_) => {
            crate::api::domain_request::ConversionTarget::Anthropic
        }
        ApiRequest::ChatCompletions(_) => {
            crate::api::domain_request::ConversionTarget::OpenAiChat
        }
        ApiRequest::Responses(_) => {
            crate::api::domain_request::ConversionTarget::OpenAiResponses
        }
        ApiRequest::GoogleGemini(_) => {
            crate::api::domain_request::ConversionTarget::Gemini
        }
    };
    domain.system_prompt.as_ref().map(|sp| match sp {
        DomainSystemPrompt::Text(t) => t.clone(),
        // Join blocks with `\n\n` to match `SystemPrompt::to_text()` exactly.
        // `apply_to_api_request` compares this flat string against the wire
        // `system.to_text()`; any separator mismatch makes an *unmodified*
        // multi-block system prompt (e.g. Claude Code's) read as changed,
        // triggering a phantom `system_prompt_modified` and a needless rewrite.
        DomainSystemPrompt::Blocks(blocks) => blocks
            .iter()
            .map(|b| {
                crate::api::domain_request::render_system_block(b, inbound_target).0
            })
            .collect::<Vec<_>>()
            .join("\n\n"),
    })
}

#[allow(clippy::too_many_arguments)]
fn project(
    req: &ApiRequest,
    domain: DomainRequest,
    user: &UserContext,
    app_id: Option<&str>,
    context_window: Option<i32>,
    upstream_provider: Option<&str>,
    needs_translation: bool,
    substituted_tool_names: &std::collections::HashSet<String>,
) -> RequestContext {
    let api_version = req.api_version().as_str();

    // Extract system prompt text.
    //
    // Render blocks for the **inbound** target so any `client_metadata`
    // lifted by `from_api_request` is re-inlined in the flat string Rhai
    // scripts see. Without this, the view the script gets ("You are a
    // helper.") would differ from `apply_to_api_request`'s own reading of
    // the raw request (`"x-anthropic-billing-header: …\nYou are a
    // helper."`), and the writeback would destroy the original Blocks
    // structure — breaking Anthropic BYOK telemetry passthrough and the
    // downstream `compute_telemetry_drops` audit.
    let system_prompt = system_prompt_text(req, &domain);

    let messages: Vec<RhaiMessage> = domain
        .messages
        .iter()
        .enumerate()
        .map(|(i, m)| RhaiMessage { origin: Some(i), ..domain_msg_to_rhai(m) })
        .collect();

    // Build tools from domain tools. Mark tools whose wire `name` was
    // rewritten by the request-phase tool-policy `Substitute` action so
    // scripts can distinguish gateway-rewritten function-tools from
    // genuinely server-defined ones without relying on the brittle
    // schema-presence proxy.
    let tools = domain
        .tools
        .as_deref()
        .unwrap_or_default()
        .iter()
        .map(|t| {
            // A Responses hosted tool: its wire type and configuration are its
            // identity (see `RhaiTool`), read the way `openai_tool_to_rhai`
            // reads them off the wire.
            let hosted = t
                .original_type
                .as_ref()
                .filter(|k| !matches!(k.as_str(), "function" | "custom"))
                .zip(t.original_extra.as_ref());
            RhaiTool {
                name: t.name.clone(),
                description: t.description.clone(),
                parameters_json: t.parameters.as_ref().map(|p| p.to_string()),
                is_gateway_substituted: substituted_tool_names.contains(&t.name),
                kind: hosted.map(|(k, _)| k.clone()),
                config_json: hosted.and_then(|(_, extra)| serde_json::to_string(extra).ok()),
            }
        })
        .collect();

    let mut metadata = HashMap::new();
    if let Some(cw) = context_window {
        metadata.insert("context_window".to_string(), cw.to_string());
        let max_messages = (cw as usize / 1000).clamp(10, 1000);
        metadata.insert("max_messages".to_string(), max_messages.to_string());
    }
    if let Some(provider) = upstream_provider {
        metadata.insert("upstream_provider".to_string(), provider.to_string());
    }
    metadata.insert(
        "needs_translation".to_string(),
        needs_translation.to_string(),
    );

    RequestContext {
        system_prompt,
        messages,
        tools,
        model: req.model().to_string(),
        user_id: user.user_id.to_string(),
        app_id: app_id.map(|s| s.to_string()),
        api_version: api_version.to_string(),
        metadata,
        labels: vec![],
    }
}

/// One user or tool message of a request's conversation, as the inbound
/// guardrail reads it: the item it came from and its place among that item's
/// messages (where an edit is written, [`set_item_text`]), and its distance
/// from the end of the whole domain message list (where a finding is
/// anchored).
pub struct ScanMessage {
    pub item: usize,
    pub part: usize,
    pub reverse: usize,
    pub message: RhaiMessage,
    /// A tool output the conversation holds inside an assistant turn (a
    /// Responses built-in tool's output, [`crate::api::BuiltinOutput`]): the
    /// call it answers — empty when it names none — which names the result a
    /// finding is about among that turn's.
    pub held_call: Option<String>,
}

/// What the inbound guardrail reads of a document in a user or tool message:
/// a text file's body or a content source's text, and — with `names`, where
/// the protocol carries them as text to the model (Anthropic's `title` and
/// `context`) — its name and context, by line. A file name elsewhere names a
/// file and stays as sent ([`set_item_text`] could not take it away). Only a
/// type the client labels `text/*` is a text body, as the parser settles it: the
/// bytes of any other (a PDF, an image, a relabelled text file) are read by no
/// detector. `None` with nothing to read.
fn document_screen_text(block: &DomainContentBlock, names: bool) -> Option<String> {
    let DomainContentBlock::Document { data, media_type, title, context, nested_content, .. } = block else {
        return None;
    };
    let mut read: Vec<&str> = Vec::new();
    if names {
        read.extend(title.as_deref());
        read.extend(context.as_deref());
    }
    if media_type.starts_with("text/") {
        read.push(data);
    }
    if let Some(Value::Array(blocks)) = nested_content {
        // A text block alone, what the spec gives such a source and the one kind
        // an edit can land on ([`set_source_text`]).
        read.extend(blocks.iter().filter(|b| b.get("type").and_then(Value::as_str) == Some("text")).filter_map(|b| b.get("text").and_then(Value::as_str)));
    }
    let text = read.join("\n");
    (!text.trim().is_empty()).then_some(text)
}

/// Whether the inbound guardrail reads a message: a user's or a tool
/// result's, never the assistant's or a system message.
fn is_scanned(m: &DomainMessage) -> bool {
    matches!(m.role, DomainRole::User | DomainRole::Tool { .. })
}

/// The user and tool messages of the conversation items from `start` on, as
/// [`ScanMessage`]s — only those items are converted
/// ([`DomainRequest::conversation_from`]). Each is paired with the item it came
/// from by converting each item on its own
/// ([`DomainRequest::item_conversation`]): a user or tool message converts the
/// same wherever the conversion starts (the state a conversion carries across
/// items — a Responses item joining the assistant message before it, a Chat
/// Completions system message folded into the prompt — touches only assistant
/// and system messages), and no message after one joins it, so its distance
/// from the end is the whole list's. `None` when the two readings do not pair,
/// role for role and text for text. Followed by the client's built-in tool
/// outputs among those items ([`held_outputs`]) and, each as a message of its
/// own, by the documents of its messages and the results of tools the server
/// ran, each in its item's place. A piece's `part` is past the item's messages
/// and its held output: [`set_item_text`] counts pieces by their place in the
/// item, whatever their text, so an edit never moves another's.
/// Locked by `every_scanned_message_pairs_with_the_whole_projection` and
/// `every_text_the_model_reads_is_read_and_written_in_place`.
pub fn scan_messages(req: &ApiRequest, start: usize) -> Option<Vec<ScanMessage>> {
    let tail = DomainRequest::conversation_from(req, start);
    let read: Vec<(usize, RhaiMessage)> = tail
        .iter()
        .enumerate()
        .filter(|(_, m)| is_scanned(m))
        .map(|(k, m)| (tail.len() - 1 - k, domain_msg_to_rhai(m)))
        .collect();
    let names = matches!(req, ApiRequest::AnthropicMessages(_));
    let mut paired = Vec::with_capacity(read.len());
    // Documents: (the message's place in `paired`, the item, the piece, its text).
    let mut documents: Vec<(usize, usize, usize, String)> = Vec::new();
    let mut results = Vec::new();
    let mut result_from = 0;
    for item in start..DomainRequest::conversation_len(req) {
        let own = DomainRequest::item_conversation(req, item);
        let mut piece = own.len() + 1;
        for (part, m) in own.iter().enumerate() {
            if is_scanned(m) {
                for block in m.content.iter().filter(|b| matches!(b, DomainContentBlock::Document { .. })) {
                    if let Some(text) = document_screen_text(block, names) {
                        documents.push((paired.len(), item, piece, text));
                    }
                    piece += 1;
                }
                paired.push((item, part, domain_msg_to_rhai(m)));
            }
        }
        match req {
            ApiRequest::AnthropicMessages(r) => results.extend(anthropic_pieces(&r.messages[item], item, piece, &tail, &mut result_from)),
            ApiRequest::GoogleGemini(r) => results.extend(gemini_pieces(&r.contents[item], item, piece, &tail, &mut result_from)),
            _ => {}
        }
    }
    if paired.len() != read.len() {
        return None;
    }
    let reverses: Vec<usize> = read.iter().map(|(reverse, _)| *reverse).collect();
    let document_messages: Vec<ScanMessage> = documents
        .into_iter()
        .map(|(at, item, part, content)| ScanMessage {
            item,
            part,
            reverse: reverses[at],
            message: RhaiMessage { content, tool_calls: Vec::new(), ..paired[at].2.clone() },
            held_call: None,
        })
        .collect();
    let mut messages: Vec<ScanMessage> = paired
        .into_iter()
        .zip(read)
        .map(|((item, part, own), (reverse, message))| {
            (own.role == message.role && own.content == message.content)
                .then_some(ScanMessage { item, part, reverse, message, held_call: None })
        })
        .collect::<Option<_>>()?;
    messages.extend(held_outputs(req, start, &tail));
    messages.extend(document_messages);
    messages.extend(results);
    messages.sort_by_key(|m| m.item);
    Some(messages)
}

/// Whether a domain block is the one a piece came from.
type BlockTest<'a> = dyn Fn(&DomainContentBlock) -> bool + 'a;

/// Where a piece sits: the message of `tail` holding a block `holds` accepts,
/// in order from `from` on (a result sent twice lands on each; a conversion
/// places an item's tool messages first, so a block after one may sit before
/// it), as its distance from the end; 0 when no message holds it.
fn anchor_piece(tail: &[DomainMessage], from: &mut usize, holds: &BlockTest) -> usize {
    let holding = |m: &DomainMessage| m.content.iter().any(holds);
    let at = tail.iter().skip(*from).position(holding).map(|at| *from + at).or_else(|| tail.iter().position(holding));
    if let Some(at) = at {
        *from = at;
    }
    at.map_or(0, |at| tail.len() - 1 - at)
}

/// A result of a tool the server ran, `value` as the conversion keeps it (an
/// unknown block), read as a tool message — piece `piece`, which it takes
/// whether it holds text or not. `read` is the result's text and the call it
/// answers, as its protocol's reader reads them; `None` when `value` is no such
/// result, which takes no piece.
fn server_run_piece(
    value: &Value,
    read: Option<(Option<String>, String)>,
    item: usize,
    piece: &mut usize,
    tail: &[DomainMessage],
    from: &mut usize,
    out: &mut Vec<ScanMessage>,
) {
    let Some((text, call)) = read else {
        return;
    };
    let reverse = anchor_piece(tail, from, &|b| matches!(b, DomainContentBlock::Unknown { value: v } if v == value));
    if let Some(content) = text {
        out.push(ScanMessage {
            item,
            part: *piece,
            reverse,
            message: RhaiMessage { role: "tool".to_string(), content, tool_call_id: Some(call.clone()), tool_calls: Vec::new(), origin: None },
            // Named even when it names no call (a Gemini result's `id` is
            // optional): a finding on it then gets a stub of its own rather
            // than landing on the prose of the message it sits in.
            held_call: Some(call),
        });
    }
    *piece += 1;
}

/// An item's server-run result as [`server_run_piece`] takes it.
fn item_result(value: &Value) -> Option<(Option<String>, String)> {
    crate::api::is_server_run_result(value).then(|| (crate::api::server_run_text(value), crate::api::server_run_call_id(value)))
}

/// A Gemini part's server-run result as [`server_run_piece`] takes it.
fn gemini_result(part: &Value) -> Option<(Option<String>, String)> {
    crate::api::is_gemini_server_run_result(part)
        .then(|| (crate::api::gemini_server_run_text(part), crate::api::gemini_server_run_call_id(part)))
}

/// The pieces of a Gemini content past its documents: each part holding a
/// result of a tool the server ran (a `codeExecutionResult`, a
/// `toolResponse`), in part order, as a tool message. Pieces count from `piece`
/// by their place ([`set_gemini_piece_text`] walks them alike).
fn gemini_pieces(content: &GeminiContent, item: usize, mut piece: usize, tail: &[DomainMessage], from: &mut usize) -> Vec<ScanMessage> {
    let mut out = Vec::new();
    for part in &content.parts {
        if let GeminiPart::Unknown(value) = part {
            server_run_piece(value, gemini_result(value), item, &mut piece, tail, from, &mut out);
        }
    }
    out
}

/// The pieces of an Anthropic message past its documents, in block order: each
/// result of a tool the server ran or of a search a client supplies, at the top
/// or inside a tool result, as a tool message; and the name and context of a
/// document by file reference, which the domain keeps as no document — as a
/// user message, or inside a tool result as that result's. Each is
/// anchored at the message of `tail` holding it, from `from` on. Pieces count
/// from `piece` by their place ([`set_anthropic_piece_text`] walks them alike).
fn anthropic_pieces(message: &AnthropicMessage, item: usize, mut piece: usize, tail: &[DomainMessage], from: &mut usize) -> Vec<ScanMessage> {
    let AnthropicContent::Blocks(blocks) = &message.content else {
        return Vec::new();
    };
    let mut out = Vec::new();
    // (piece, reverse, text, the tool result holding it).
    let mut files: Vec<(usize, usize, String, Option<String>)> = Vec::new();
    // A file reference's name and context, read where the model reads them.
    let mut file = |source: &crate::api::messages::ImageSource,
                    title: &Option<String>,
                    context: &Option<String>,
                    result: Option<&String>,
                    piece: &mut usize,
                    from: &mut usize| {
        let read: Vec<&str> = title.iter().chain(context).map(String::as_str).collect();
        let id = source.file_id.clone();
        let reverse = anchor_piece(tail, from, &|b| matches!(b, DomainContentBlock::File { file_id, .. } if *file_id == id));
        if message.role != "assistant" && read.iter().any(|t| !t.trim().is_empty()) {
            files.push((*piece, reverse, read.join("\n"), result.cloned()));
        }
        *piece += 1;
    };
    for block in blocks {
        match block {
            ContentBlock::Unknown(value) => server_run_piece(value, item_result(value), item, &mut piece, tail, from, &mut out),
            ContentBlock::ToolResult {
                tool_use_id,
                content: Some(crate::api::messages::ToolResultContent::Blocks(inner)),
                ..
            } => {
                for inner in inner {
                    match inner {
                        crate::api::messages::ToolResultBlock::Unknown(value) => {
                            server_run_piece(value, item_result(value), item, &mut piece, tail, from, &mut out)
                        }
                        crate::api::messages::ToolResultBlock::Document { source, title, context, .. } if source.r#type == "file" => {
                            file(source, title, context, Some(tool_use_id), &mut piece, from)
                        }
                        _ => {}
                    }
                }
            }
            ContentBlock::Document { source, title, context, .. } if source.r#type == "file" => {
                file(source, title, context, None, &mut piece, from)
            }
            _ => {}
        }
    }
    out.extend(files.into_iter().map(|(part, reverse, content, result)| ScanMessage {
        item,
        part,
        reverse,
        message: RhaiMessage {
            role: if result.is_some() { "tool" } else { "user" }.to_string(),
            content,
            tool_call_id: result,
            tool_calls: Vec::new(),
            origin: None,
        },
        held_call: None,
    }));
    out
}

/// The outputs of the built-in tools the client ran, among the Responses
/// items from `start` on, as tool messages: the domain has no meaning for such
/// an item and carries it as it came, in the assistant message it sits in
/// ([`DomainRequest::conversation_from`] — one block per item, in item order),
/// so each is anchored at the message of `tail` holding a block equal to it.
/// Read as [`crate::api::BuiltinOutput::screen_text`] reads it — its text when
/// the item is exactly its spec form, else the whole item as its JSON —
/// whoever ran it: no other item (a hosted shell call) decides what goes
/// unread; one with nothing to read is not read.
fn held_outputs(req: &ApiRequest, start: usize, tail: &[DomainMessage]) -> Vec<ScanMessage> {
    let ApiRequest::Responses(r) = req else {
        return Vec::new();
    };
    let crate::api::domain::ResponseInput::Raw(items) = &r.input else {
        return Vec::new();
    };
    let held: Vec<(usize, &Value)> = tail
        .iter()
        .enumerate()
        .flat_map(|(k, m)| {
            m.content.iter().filter_map(move |b| match b {
                DomainContentBlock::Unknown { value } if matches!(m.role, DomainRole::Assistant) => Some((k, value)),
                _ => None,
            })
        })
        .collect();
    let mut next = 0;
    let mut out = Vec::new();
    for (item, value) in items.iter().enumerate().skip(start) {
        // A client-run tool's output, or the result of one the server ran.
        let (call_id, read, role) = match crate::api::BuiltinOutput::of(value) {
            Some(output) => {
                let read = output.screen_text(value);
                (output.call_id, read, "tool")
            }
            None if crate::api::is_server_run_result(value) => {
                // An approval's reason is the user's own words.
                let role = if value.get("type").and_then(Value::as_str) == Some("mcp_approval_response") { "user" } else { "tool" };
                (crate::api::server_run_call_id(value), crate::api::server_run_text(value), role)
            }
            None => continue,
        };
        let Some(content) = read else {
            continue;
        };
        // One the conversion read as a message, by a `role` it carries, is
        // held by no block: it is still read, its finding anchored at the last
        // message — pinned in a view only on a result of the call it names.
        let held_at = if value.get("role").is_some() { None } else { held[next..].iter().position(|(_, block)| *block == value) };
        let reverse = match held_at {
            Some(at) => {
                let k = held[next + at].0;
                next += at + 1;
                tail.len() - 1 - k
            }
            None => 0,
        };
        out.push(ScanMessage {
            item,
            // Past the item's own messages: the output is none of them.
            part: DomainRequest::item_conversation(req, item).len(),
            reverse,
            message: RhaiMessage {
                role: role.to_string(),
                content,
                tool_call_id: Some(call_id.clone()),
                tool_calls: Vec::new(),
                origin: None,
            },
            held_call: Some(call_id),
        });
    }
    out
}

/// Sets the text of the `part`-th message conversation item `item` converts
/// to ([`DomainRequest::item_conversation`]): its text lands in one text part
/// of the item, and the other text parts — the projection reads them joined —
/// go; every other part, item and field is kept. Locked by
/// `an_edit_lands_on_its_message_alone`.
pub fn set_item_text(req: &mut ApiRequest, item: usize, part: usize, text: &str) {
    let own = DomainRequest::item_conversation(req, item);
    // The part past the item's messages is an output it holds ([`held_outputs`]),
    // read whole and so written whole: a built-in tool's, or a server-run
    // tool's result.
    if part == own.len()
        && let ApiRequest::Responses(r) = req
        && let crate::api::domain::ResponseInput::Raw(items) = &mut r.input
        && let Some(output) = items.get_mut(item)
    {
        if crate::api::BuiltinOutput::of(output).is_some() {
            crate::api::replace_builtin_output(output, text.to_string());
        } else {
            crate::api::set_server_run_text(output, text);
        }
        return;
    }
    // Past that, one of its pieces ([`scan_messages`]).
    if part > own.len() {
        set_item_piece_text(req, item, &own, part - own.len() - 1, text);
        return;
    }
    let Some(message) = own.get(part) else {
        return;
    };
    match req {
        ApiRequest::ChatCompletions(r) => {
            let m = &mut r.messages[item];
            match &mut m.content {
                Some(content) => set_message_content_text(content, text),
                None => m.content = Some(MessageContent::Text(text.to_string())),
            }
        }
        ApiRequest::AnthropicMessages(r) => {
            let m = &mut r.messages[item];
            match &message.role {
                // The k-th tool message is the k-th tool result block — by
                // place, never by id: two results may share one.
                DomainRole::Tool { .. } if m.role != "tool" => {
                    let k = own[..part].iter().filter(|m| matches!(m.role, DomainRole::Tool { .. })).count();
                    if let AnthropicContent::Blocks(blocks) = &mut m.content
                        && let Some(ContentBlock::ToolResult { content, .. }) =
                            blocks.iter_mut().filter(|b| matches!(b, ContentBlock::ToolResult { .. })).nth(k)
                    {
                        set_tool_result_text(content, text);
                    }
                }
                _ => set_anthropic_item_text(m, text),
            }
        }
        ApiRequest::GoogleGemini(r) => {
            let content = &mut r.contents[item];
            if matches!(message.role, DomainRole::Tool { .. }) {
                // The k-th tool message is the k-th function response.
                let k = own[..part].iter().filter(|m| matches!(m.role, DomainRole::Tool { .. })).count();
                if let Some(GeminiPart::FunctionResponse { function_response }) = content
                    .parts
                    .iter_mut()
                    .filter(|p| matches!(p, GeminiPart::FunctionResponse { .. }))
                    .nth(k)
                {
                    function_response.response = gemini_response_as_written(&function_response.response, text);
                }
            } else {
                // Text and non-thought text both read as text: the first of
                // them holds the text where it is, with its signature.
                let mut replaced = false;
                content.parts.retain_mut(|p| match p {
                    GeminiPart::Text { text: t } | GeminiPart::ThoughtText { thought: false, text: t, .. } => {
                        if replaced {
                            return false;
                        }
                        *t = text.to_string();
                        replaced = true;
                        true
                    }
                    _ => true,
                });
                if !replaced {
                    content.parts.push(GeminiPart::Text { text: text.to_string() });
                }
            }
        }
        ApiRequest::Responses(r) => match &mut r.input {
            crate::api::domain::ResponseInput::Text(t) => *t = text.to_string(),
            crate::api::domain::ResponseInput::Messages(msgs) => set_message_content_text(&mut msgs[item].content, text),
            crate::api::domain::ResponseInput::Raw(items) => set_responses_item_text(&mut items[item], text),
        },
    }
}

/// Write `text` over the `piece`-th piece of an item: the documents of its
/// scanned messages in order, then its results of tools the server ran.
fn set_item_piece_text(req: &mut ApiRequest, item: usize, own: &[DomainMessage], piece: usize, text: &str) {
    let mut left = piece;
    for (part, m) in own.iter().enumerate().filter(|(_, m)| is_scanned(m)) {
        let documents = m.content.iter().filter(|b| matches!(b, DomainContentBlock::Document { .. })).count();
        if left < documents {
            set_document_text(req, item, own, part, left, text);
            return;
        }
        left -= documents;
    }
    match req {
        ApiRequest::AnthropicMessages(r) => set_anthropic_piece_text(&mut r.messages[item], left, text),
        ApiRequest::GoogleGemini(r) => set_gemini_piece_text(&mut r.contents[item], left, text),
        _ => {}
    }
}

/// Write `text` over the `n`-th piece [`gemini_pieces`] counts: a server-run
/// result's strings, the part and its result's other members kept.
fn set_gemini_piece_text(content: &mut GeminiContent, n: usize, text: &str) {
    if let Some(value) = content
        .parts
        .iter_mut()
        .filter_map(|p| match p {
            GeminiPart::Unknown(value) if crate::api::is_gemini_server_run_result(value) => Some(value),
            _ => None,
        })
        .nth(n)
    {
        crate::api::set_gemini_server_run_text(value, text);
    }
}

/// Write `text` over the `n`-th piece [`anthropic_pieces`] counts: a result's
/// strings, or a file document's context, its name gone with what was read.
fn set_anthropic_piece_text(message: &mut AnthropicMessage, mut n: usize, text: &str) {
    let AnthropicContent::Blocks(blocks) = &mut message.content else {
        return;
    };
    let mut take = || {
        let hit = n == 0;
        n = n.wrapping_sub(1);
        hit
    };
    for block in blocks.iter_mut() {
        match block {
            ContentBlock::Unknown(value) if crate::api::is_server_run_result(value) && take() => {
                return crate::api::set_server_run_text(value, text);
            }
            ContentBlock::ToolResult { content: Some(crate::api::messages::ToolResultContent::Blocks(inner)), .. } => {
                for inner in inner {
                    match inner {
                        crate::api::messages::ToolResultBlock::Unknown(value)
                            if crate::api::is_server_run_result(value) && take() =>
                        {
                            return crate::api::set_server_run_text(value, text);
                        }
                        crate::api::messages::ToolResultBlock::Document { source, title, context, .. }
                            if source.r#type == "file" && take() =>
                        {
                            *title = None;
                            *context = (!text.is_empty()).then(|| text.to_string());
                            return;
                        }
                        _ => {}
                    }
                }
            }
            ContentBlock::Document { source, title, context, .. } if source.r#type == "file" && take() => {
                *title = None;
                *context = (!text.is_empty()).then(|| text.to_string());
                return;
            }
            _ => {}
        }
    }
}

/// Write `text` over the `n`-th document of message `part` of an item, in the
/// protocol's own shape: a document stays a document, its text in the channel it
/// came in.
fn set_document_text(req: &mut ApiRequest, item: usize, own: &[DomainMessage], part: usize, n: usize, text: &str) {
    // A tool message is the k-th result of its item (as [`set_item_text`]).
    let is_tool = matches!(own[part].role, DomainRole::Tool { .. });
    let k = own[..part].iter().filter(|m| matches!(m.role, DomainRole::Tool { .. })).count();
    match req {
        ApiRequest::ChatCompletions(r) => {
            if let Some(content) = &mut r.messages[item].content {
                set_parts_document_text(content, n, text);
            }
        }
        ApiRequest::AnthropicMessages(r) => {
            let m = &mut r.messages[item];
            let role_is_tool = m.role == "tool";
            let AnthropicContent::Blocks(blocks) = &mut m.content else {
                return;
            };
            if is_tool && !role_is_tool {
                if let Some(ContentBlock::ToolResult { content: Some(crate::api::messages::ToolResultContent::Blocks(inner)), .. }) =
                    blocks.iter_mut().filter(|b| matches!(b, ContentBlock::ToolResult { .. })).nth(k)
                    && let Some(crate::api::messages::ToolResultBlock::Document { source, title, context, .. }) = inner
                        .iter_mut()
                        .filter(|b| matches!(b, crate::api::messages::ToolResultBlock::Document { source, .. } if source.r#type != "file"))
                        .nth(n)
                {
                    set_document_parts_text(source, title, context, text);
                }
            } else if let Some(ContentBlock::Document { source, title, context, .. }) =
                // The domain reads a file reference as no document: counted as it counts.
                blocks.iter_mut().filter(|b| matches!(b, ContentBlock::Document { source, .. } if source.r#type != "file")).nth(n)
            {
                set_document_parts_text(source, title, context, text);
            }
        }
        ApiRequest::GoogleGemini(r) => {
            let content = &mut r.contents[item];
            if is_tool {
                if let Some(GeminiPart::FunctionResponse { function_response }) =
                    content.parts.iter_mut().filter(|p| matches!(p, GeminiPart::FunctionResponse { .. })).nth(k)
                    && let Some(blob) = function_response
                        .parts
                        .iter_mut()
                        .filter(|p| crate::api::domain_request::gemini_response_part_is_document(p))
                        .nth(n)
                {
                    blob["inlineData"]["data"] = Value::String(crate::api::domain_request::gemini_text_data(text));
                }
            } else if let Some(GeminiPart::InlineData { inline_data, .. }) = content
                .parts
                .iter_mut()
                .filter(|p| {
                    matches!(p, GeminiPart::InlineData { inline_data, .. }
                        if crate::api::domain_request::gemini_blob_is_document(&inline_data.mime_type, &inline_data.data))
                })
                .nth(n)
            {
                inline_data.data = crate::api::domain_request::gemini_text_data(text);
            }
        }
        ApiRequest::Responses(r) => match &mut r.input {
            crate::api::domain::ResponseInput::Text(_) => {}
            crate::api::domain::ResponseInput::Messages(msgs) => set_parts_document_text(&mut msgs[item].content, n, text),
            crate::api::domain::ResponseInput::Raw(items) => {
                let key = if is_tool { "output" } else { "content" };
                if let Some(Value::Array(parts)) = items[item].get_mut(key)
                    && let Some(file) = parts.iter_mut().filter(|p| crate::api::domain_request::part_is_document(p)).nth(n)
                {
                    set_file_part_text(file, text);
                }
            }
        },
    }
}

/// Write `text` over what [`document_screen_text`] read of an Anthropic
/// document — its name and context with its body, so they go with it. A body
/// no text can land in keeps the text in the context the model reads beside it.
fn set_document_parts_text(
    source: &mut crate::api::messages::ImageSource,
    title: &mut Option<String>,
    context: &mut Option<String>,
    text: &str,
) {
    *title = None;
    if set_source_text(source, text) {
        *context = None;
    } else {
        *context = (!text.is_empty()).then(|| text.to_string());
    }
}

/// Write `text` as an Anthropic document source's text, where
/// [`document_screen_text`] read it: a content source's text blocks, its images
/// kept, or a text body, which becomes the spec's text source whatever spelled
/// it. `false` when the source holds bytes or a reference no text can land in.
fn set_source_text(source: &mut crate::api::messages::ImageSource, text: &str) -> bool {
    match source.r#type.as_str() {
        "content" => {
            let mut blocks = source.content.take().unwrap_or_default();
            let mut written = false;
            blocks.retain_mut(|block| {
                if !matches!(block, ContentBlock::Text { .. }) {
                    return true;
                }
                if written {
                    return false;
                }
                written = block.write_text(text);
                true
            });
            if !written {
                blocks.insert(0, ContentBlock::Text { text: text.to_string(), cache_control: None, extra: BTreeMap::new() });
            }
            source.content = Some(blocks);
        }
        _ if source.r#type == "text" || source.media_type.starts_with("text/") => {
            source.r#type = "text".to_string();
            source.media_type = "text/plain".to_string();
            source.data = text.to_string();
        }
        _ => return false,
    }
    true
}

fn set_parts_document_text(content: &mut MessageContent, n: usize, text: &str) {
    use crate::api::domain::ContentPart;
    if let MessageContent::Parts(parts) = content
        && let Some(file) = parts
            .iter_mut()
            .filter_map(|p| match p {
                ContentPart::Unknown(v) if crate::api::domain_request::part_is_document(v) => Some(v),
                _ => None,
            })
            .nth(n)
    {
        set_file_part_text(file, text);
    }
}

/// Write `text` over a Chat `file` or a Responses `input_file` part's data URL,
/// its media type and name kept.
fn set_file_part_text(part: &mut Value, text: &str) {
    let chat = part.get("type").and_then(Value::as_str) == Some("file");
    let file = if chat { &mut part["file"] } else { part };
    if let Some(url) = file.get("file_data").and_then(Value::as_str)
        && let Some(written) = crate::api::domain_request::text_data_url(url, text)
    {
        file["file_data"] = Value::String(written);
    }
}

/// A Gemini function response's `response` after a write of `text`: the text
/// as JSON when it still is an object, and otherwise an object holding it (a
/// placeholder) — the protocol's response is an object — except where the
/// client sent a string, which is left a string.
fn gemini_response_as_written(response: &Value, text: &str) -> Value {
    match response {
        Value::String(_) => Value::String(text.to_string()),
        _ => crate::api::domain_request::gemini_response(text.to_string(), None),
    }
}

/// Sets an Anthropic message's text for the guardrail's write: it lands
/// in the text block carrying the message's cache breakpoint (the last text
/// block when none does) and the other text blocks go, so the prompt cache's
/// prefix ends where the client put it; every other block is kept.
fn set_anthropic_item_text(msg: &mut AnthropicMessage, new_text: &str) {
    let AnthropicContent::Blocks(blocks) = &mut msg.content else {
        msg.content = AnthropicContent::Text(new_text.to_string());
        return;
    };
    let texts: Vec<usize> = (0..blocks.len()).filter(|&i| matches!(blocks[i], ContentBlock::Text { .. })).collect();
    let Some(&last) = texts.last() else {
        blocks.push(ContentBlock::Text { text: new_text.to_string(), cache_control: None, extra: BTreeMap::new() });
        return;
    };
    let keep = texts
        .iter()
        .rev()
        .copied()
        .find(|&i| matches!(&blocks[i], ContentBlock::Text { cache_control: Some(_), .. }))
        .unwrap_or(last);
    blocks[keep].write_text(new_text);
    let mut index = 0;
    blocks.retain(|_| {
        let kept = index == keep || !texts.contains(&index);
        index += 1;
        kept
    });
}

/// Sets a Chat Completions or Responses message's text: the first text part
/// holds it, and the other text parts — the projection reads them joined — are
/// dropped; a non-text part is kept.
fn set_message_content_text(content: &mut MessageContent, text: &str) {
    use crate::api::domain::ContentPart;
    match content {
        MessageContent::Parts(parts) => {
            // A text part is a typed one, or an untyped one the projection reads
            // as text (a Responses `input_text`).
            let replaced = ContentPart::merge_text_parts(parts, text, |part| match part {
                ContentPart::Text { .. } => true,
                ContentPart::Unknown(v) => crate::api::domain_request::unknown_part_is_text(v),
                _ => false,
            });
            if !replaced {
                parts.push(crate::api::domain::ContentPart::text(text.to_string()));
            }
        }
        MessageContent::Text(t) => *t = text.to_string(),
    }
}

/// Sets a raw Responses item's text: a message's `content`, or a call
/// output's `output` — a string, or its first text part (as the projection
/// reads parts), the other text parts dropped (the projection reads them
/// joined) and every other part (an image) kept.
fn set_responses_item_text(item: &mut Value, text: &str) {
    let kind = item.get("type").and_then(Value::as_str).unwrap_or("").to_string();
    // A tool result's output array holds typed parts, as a message's content.
    let (key, typed) = if matches!(kind.as_str(), "function_call_output" | "custom_tool_call_output") {
        ("output", true)
    } else {
        ("content", kind == "message")
    };
    match item.get_mut(key) {
        Some(Value::Array(parts)) => {
            // A typed part reads as the protocol types it; an untyped item's,
            // by its `text`. An output part with no `type` reads as its JSON
            // text.
            let is_text = |part: &Value| {
                if typed {
                    crate::api::domain_request::unknown_part_is_text(part) || (key == "output" && part.get("type").is_none())
                } else {
                    part.get("text").is_some_and(Value::is_string)
                }
            };
            let Some(first) = parts.iter().position(is_text) else {
                parts.push(serde_json::json!({"type": "input_text", "text": text}));
                return;
            };
            // A removed text part's prompt-cache breakpoint (the latest) moves
            // onto the part the text is written in, so the prefix still ends
            // there.
            let breakpoint = parts[first + 1..]
                .iter()
                .filter(|p| is_text(p))
                .filter_map(|p| p.get("prompt_cache_breakpoint").filter(|b| !b.is_null()).cloned())
                .next_back();
            let mut at = 0;
            parts.retain(|p| {
                let keep = at <= first || !is_text(p);
                at += 1;
                keep
            });
            let part = &mut parts[first];
            if part.get("type").is_none() {
                // Read whole as its JSON, so written whole.
                *part = serde_json::json!({"type": "input_text", "text": text});
            } else {
                part["text"] = Value::String(text.to_string());
            }
            if let Some(b) = breakpoint {
                part["prompt_cache_breakpoint"] = b;
            }
        }
        _ => item[key] = Value::String(text.to_string()),
    }
}

/// Convert a `DomainMessage` to a text-only `RhaiMessage`.
fn domain_msg_to_rhai(dm: &DomainMessage) -> RhaiMessage {
    let role = match &dm.role {
        DomainRole::User => "user",
        DomainRole::Assistant => "assistant",
        DomainRole::System => "system",
        DomainRole::Tool { .. } => "tool",
    };
    // A tool result's text blocks read as one text, as every walk sends a
    // text-only result: a script that changes nothing must read as no change.
    let separator = if matches!(dm.role, DomainRole::Tool { .. }) { "" } else { "\n" };
    let content = dm
        .content
        .iter()
        .filter_map(|b| match b {
            DomainContentBlock::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join(separator);
    let tool_call_id = match &dm.role {
        DomainRole::Tool { tool_call_id, .. } => Some(tool_call_id.clone()),
        _ => None,
    };
    let tool_calls: Vec<RhaiToolCall> = dm
        .content
        .iter()
        .filter_map(|b| match b {
            DomainContentBlock::ToolUse {
                id, name, input, ..
            } => Some(RhaiToolCall {
                id: id.clone(),
                name: name.clone(),
                arguments_json: serde_json::to_string(input).unwrap_or_default(),
            }),
            _ => None,
        })
        .collect();
    RhaiMessage {
        role: role.to_string(),
        content,
        tool_call_id,
        tool_calls,
        origin: None,
    }
}

// ── Helpers for apply_to_api_request ──

/// Sets a tool result's text: its text blocks become one holding it, a
/// non-text block (an image) kept.
fn set_tool_result_text(content: &mut Option<crate::api::messages::ToolResultContent>, new_text: &str) {
    match content {
        Some(crate::api::messages::ToolResultContent::Blocks(result_blocks)) if new_text.is_empty() => {
            if !crate::api::messages::ToolResultBlock::clear_text(result_blocks) {
                *content = None;
            }
        }
        Some(crate::api::messages::ToolResultContent::Blocks(result_blocks)) => {
            crate::api::messages::ToolResultBlock::set_text(result_blocks, new_text);
        }
        _ => {
            *content = if new_text.is_empty() {
                None
            } else {
                Some(crate::api::messages::ToolResultContent::Text(new_text.to_string()))
            };
        }
    }
}

/// A group of Rhai messages that maps to one native Anthropic message.
#[derive(Debug)]
enum RhaiGroup<'a> {
    /// Consecutive tool messages + optional trailing user text.
    /// Maps to: `user([tool_result_blocks..., optional_text])`
    ToolGroup {
        tool_msgs: Vec<&'a RhaiMessage>,
        text_msg: Option<&'a RhaiMessage>,
    },
    /// Standalone user/assistant message.
    Single(&'a RhaiMessage),
}

/// Group Rhai messages into native Anthropic message equivalents.
///
/// Consecutive `{role:"tool"}` messages + an optional trailing `{role:"user"}`
/// are grouped into a single native `user([tool_result_blocks, text])` message.
fn group_rhai_for_anthropic(rhai_msgs: &[RhaiMessage]) -> Vec<RhaiGroup<'_>> {
    let mut groups = Vec::new();
    let mut i = 0;

    while i < rhai_msgs.len() {
        if rhai_msgs[i].role == "tool" {
            let mut tool_msgs = vec![&rhai_msgs[i]];
            i += 1;
            while i < rhai_msgs.len() && rhai_msgs[i].role == "tool" {
                tool_msgs.push(&rhai_msgs[i]);
                i += 1;
            }
            let text_msg = if i < rhai_msgs.len() && rhai_msgs[i].role == "user" {
                let msg = &rhai_msgs[i];
                i += 1;
                Some(msg)
            } else {
                None
            };
            groups.push(RhaiGroup::ToolGroup {
                tool_msgs,
                text_msg,
            });
        } else {
            groups.push(RhaiGroup::Single(&rhai_msgs[i]));
            i += 1;
        }
    }

    groups
}

/// Build a native Anthropic message from a group of messages the script wrote
/// (no original item holds them as they are), an assistant's calls included.
fn build_anthropic_from_group(group: &RhaiGroup<'_>) -> AnthropicMessage {
    match group {
        RhaiGroup::ToolGroup {
            tool_msgs,
            text_msg,
        } => {
            let mut blocks: Vec<ContentBlock> = tool_msgs
                .iter()
                .map(|m| ContentBlock::ToolResult {
                    tool_use_id: m.tool_call_id.clone().unwrap_or_default(),
                    content: if m.content.is_empty() {
                        None
                    } else {
                        Some(crate::api::messages::ToolResultContent::Text(
                            m.content.clone(),
                        ))
                    },
                    is_error: None,
                    cache_control: None,
                    extra: Default::default(),
                })
                .collect();
            if let Some(tm) = text_msg {
                blocks.push(ContentBlock::Text {
                    text: tm.content.clone(),
                    cache_control: None,
                    extra: BTreeMap::new(),
                });
            }
            AnthropicMessage {
                role: "user".to_string(),
                content: AnthropicContent::Blocks(blocks),
            }
        }
        RhaiGroup::Single(rm) if rm.tool_calls.is_empty() => AnthropicMessage {
            role: rm.role.clone(),
            content: AnthropicContent::Text(rm.content.clone()),
        },
        RhaiGroup::Single(rm) => {
            let text = (!rm.content.is_empty())
                .then(|| ContentBlock::Text { text: rm.content.clone(), cache_control: None, extra: BTreeMap::new() });
            AnthropicMessage {
                role: rm.role.clone(),
                content: AnthropicContent::Blocks(
                    text.into_iter().chain(rhai_tool_calls_to_anthropic_blocks(&rm.tool_calls)).collect(),
                ),
            }
        }
    }
}

/// The request's tools by name, by kind — `true` for a custom (freeform)
/// tool. What a call names decides what kind of call it is.
fn declared_tool_kinds(tools: Option<&Vec<Tool>>) -> HashMap<String, bool> {
    tools
        .into_iter()
        .flatten()
        .filter_map(|t| Some((t.function_name()?.to_string(), t.r#type == "custom")))
        .collect()
}

/// Convert Rhai tool_calls to native ChatCompletions `ToolCall`s.
/// Entries with empty names are dropped. Entries missing an `id` get a
/// synthesized `call_{idx}` so upstream never sees an empty id (OpenAI rejects
/// subsequent tool-result turns that reference an empty-id call). A call is
/// the kind of the tool it names in `declared` — a custom (freeform) tool's
/// call is a custom call, its free text read back from the script's
/// arguments — and, for a tool the request no longer declares, the kind of
/// the call in `originals` with its id. Locked by
/// `a_script_call_without_an_id_keeps_its_tools_kind`.
fn rhai_tool_calls_to_cc(
    rhai_tcs: &[RhaiToolCall],
    originals: &[crate::api::domain::ToolCall],
    declared: &HashMap<String, bool>,
) -> Option<Vec<crate::api::domain::ToolCall>> {
    if rhai_tcs.is_empty() {
        return None;
    }
    let tcs: Vec<_> = rhai_tcs
        .iter()
        .filter(|t| !t.name.is_empty())
        .enumerate()
        .map(|(i, t)| {
            let id = if t.id.is_empty() { format!("call_{i}") } else { t.id.clone() };
            let custom = declared
                .get(&t.name)
                .copied()
                .unwrap_or_else(|| originals.iter().any(|o| o.id == id && o.custom.is_some()));
            if !custom {
                return crate::api::domain::ToolCall::function(id, t.name.clone(), t.arguments_json.clone());
            }
            let input = crate::api::domain_request::freeform_whole_text(&t.arguments_json);
            crate::api::domain::ToolCall {
                id,
                r#type: "custom".to_string(),
                function: None,
                custom: Some(crate::api::domain::CustomToolCall { name: t.name.clone(), input }),
            }
        })
        .collect();
    if tcs.is_empty() { None } else { Some(tcs) }
}

/// Convert Rhai tool_calls to Anthropic `ToolUse` content blocks.
/// `arguments_json` that fails to parse is logged as a warning and substituted
/// with an empty object so the request is still well-formed.
fn rhai_tool_calls_to_anthropic_blocks(rhai_tcs: &[RhaiToolCall]) -> Vec<ContentBlock> {
    rhai_tcs
        .iter()
        .filter(|t| !t.name.is_empty())
        .enumerate()
        .map(|(i, t)| ContentBlock::ToolUse {
            // A call with no id is named by its place: Anthropic refuses an empty one.
            id: if t.id.is_empty() { format!("call_{i}") } else { t.id.clone() },
            name: t.name.clone(),
            input: parse_rhai_args(&t.name, &t.arguments_json),
            cache_control: None,
            extra: BTreeMap::new(),
        })
        .collect()
}

/// Parse a script-provided `arguments_json` string, logging a warning on
/// parse failure rather than silently substituting an empty object.
fn parse_rhai_args(name: &str, raw: &str) -> Value {
    match serde_json::from_str(raw) {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(
                tool = name,
                error = %e,
                "rhai tool_call arguments_json failed to parse; substituting empty object"
            );
            Value::Object(Default::default())
        }
    }
}

// ── Writing a script's messages back ──
//
// A script reads the conversation as the domain view's messages
// ([`from_api_request`]); one wire item may hold several of them (an Anthropic
// user turn's tool results and text, a Gemini turn's function responses). Each
// message is written back to the item and the part it was read from — the
// pairing the inbound guardrail writes its edits by ([`set_item_text`]) — so
// whatever the script does not see (images, a message's `name`, a call's
// signature, items with no message) stays as the client sent it.

/// One message the script read: as it read it, and the pieces it is read
/// from — each `(item, part, that part as its item reads on its own)`. A
/// message is one item's part, or several items in a row where the whole
/// conversation joins them (a Responses call or reasoning item joins the
/// assistant message before it).
struct Place {
    read: RhaiMessage,
    pieces: Vec<(usize, usize, RhaiMessage)>,
}

/// Each message the script read, with the pieces it is read from, as the
/// conversion records them. `None` when the items' own conversions do not
/// add up to the whole conversation's, so no message can be placed.
fn conversation_places(req: &ApiRequest) -> Option<Vec<Place>> {
    let whole = DomainRequest::from_api_request(req).messages;
    let own = |item: usize| -> Vec<RhaiMessage> {
        DomainRequest::item_conversation(req, item).iter().map(domain_msg_to_rhai).collect()
    };
    let mut pieces: Vec<Vec<(usize, usize, RhaiMessage)>> = vec![Vec::new(); whole.len()];
    if let ApiRequest::Responses(r) = req
        && let crate::api::domain::ResponseInput::Raw(items) = &r.input
    {
        for (item, messages) in crate::api::domain_request::responses_item_messages(items).into_iter().enumerate() {
            let parts = own(item);
            if parts.len() != messages.len() {
                return None;
            }
            for (part, (at, m)) in messages.into_iter().zip(parts).enumerate() {
                pieces.get_mut(at)?.push((item, part, m));
            }
        }
    } else {
        let mut at = 0;
        for item in conversation_start(req)..DomainRequest::conversation_len(req) {
            for (part, m) in own(item).into_iter().enumerate() {
                pieces.get_mut(at)?.push((item, part, m));
                at += 1;
            }
        }
    }
    if pieces.iter().any(Vec::is_empty) {
        return None;
    }
    let places: Vec<Place> =
        whole.iter().zip(pieces).map(|(m, pieces)| Place { read: domain_msg_to_rhai(m), pieces }).collect();
    // Each message reads as the role its first piece does, or the pairing
    // went wrong somewhere and no message is placed.
    places.iter().all(|p| p.read.role == p.pieces[0].2.role).then_some(places)
}

/// The first conversation item: on Chat Completions, the first after the
/// system prompt's channel ([`chat_system_lead`]).
fn conversation_start(req: &ApiRequest) -> usize {
    match req {
        ApiRequest::ChatCompletions(r) => chat_system_lead(&r.messages),
        _ => 0,
    }
}

/// The calls `script` names, each one left as it was read (equal to an
/// unclaimed `read[k]`) kept as the client's own `natives[k]` — its id,
/// signature and breakpoint with it — and any other built from its place
/// among the calls named. `natives` and `read` are one item's calls in order;
/// when their counts differ, every call is built.
fn keep_or_build_calls<T: Clone>(
    script: &[RhaiToolCall],
    read: &[RhaiToolCall],
    natives: &[T],
    build: impl Fn(usize, &RhaiToolCall) -> T,
) -> Vec<T> {
    let mut taken = vec![false; read.len()];
    script
        .iter()
        .filter(|t| !t.name.is_empty())
        .enumerate()
        .map(|(i, t)| {
            let kept = (natives.len() == read.len())
                .then(|| (0..read.len()).find(|&k| !taken[k] && read[k] == *t))
                .flatten();
            match kept {
                Some(k) => {
                    taken[k] = true;
                    natives[k].clone()
                }
                None => build(i, t),
            }
        })
        .collect()
}

/// A Gemini function call the script wrote, unsigned (a signature covers the
/// call as the model produced it). An id the gateway made up for a call the
/// client sent without one (`made_up`) is not one the client knows, so it is
/// not written.
fn gemini_call_part(t: &RhaiToolCall, made_up: &HashMap<String, String>) -> GeminiPart {
    GeminiPart::FunctionCall {
        function_call: crate::api::gemini::GeminiFunctionCallData {
            id: (!t.id.is_empty() && !made_up.contains_key(&t.id)).then(|| t.id.clone()),
            name: t.name.clone(),
            args: parse_rhai_args(&t.name, &t.arguments_json),
        },
        thought_signature: None,
    }
}

/// The ids the gateway made up reading a Gemini request (calls the client
/// sent without one, responses answering none), each with its function —
/// never written back to the client. Empty on any other protocol.
fn made_up_ids(req: &ApiRequest) -> HashMap<String, String> {
    match req {
        ApiRequest::GoogleGemini(r) => crate::api::domain_request::GeminiCallIds::of(&r.contents).generated(),
        _ => HashMap::new(),
    }
}

/// `parts` with the calls in it (`is_call`) replaced by `calls`, in place:
/// each call slot takes the next call, a slot left over goes, and calls
/// left over follow the last call slot (the end, where there was none) — so
/// text, thinking and the calls' order stay where they were.
fn replace_calls_in_place<T>(parts: &mut Vec<T>, calls: Vec<T>, is_call: impl Fn(&T) -> bool) {
    let mut calls = calls.into_iter();
    let mut out = Vec::with_capacity(parts.len());
    let mut after_last_call = None;
    for part in parts.drain(..) {
        if is_call(&part) {
            if let Some(call) = calls.next() {
                out.push(call);
            }
            after_last_call = Some(out.len());
        } else {
            out.push(part);
        }
    }
    let at = after_last_call.unwrap_or(out.len());
    out.splice(at..at, calls);
    *parts = out;
}

/// Write the calls a script gave the message of `item` it read as `read`.
/// False where the item has no form for them (a Responses item but a lone
/// function call).
fn set_item_tool_calls(
    req: &mut ApiRequest,
    item: usize,
    read: &[RhaiToolCall],
    script: &[RhaiToolCall],
    made_up: &HashMap<String, String>,
) -> bool {
    match req {
        ApiRequest::ChatCompletions(r) => {
            let declared = declared_tool_kinds(r.tools.as_ref());
            let m = &mut r.messages[item];
            let natives = m.tool_calls.clone().unwrap_or_default();
            // A call the script could not see (neither a function nor a
            // custom call) has no place in what it wrote: nothing is written.
            if natives.len() != read.len() {
                return false;
            }
            // Every call named, as a new one: an id the script left empty is
            // its place among them, as a rebuilt message's.
            let fresh = rhai_tool_calls_to_cc(script, &natives, &declared).unwrap_or_default();
            let built = keep_or_build_calls(script, read, &natives, |i, t| {
                fresh.get(i).cloned().unwrap_or_else(|| {
                    crate::api::domain::ToolCall::function(t.id.clone(), t.name.clone(), t.arguments_json.clone())
                })
            });
            m.tool_calls = (!built.is_empty()).then_some(built);
            true
        }
        ApiRequest::AnthropicMessages(r) => {
            let m = &mut r.messages[item];
            let natives: Vec<ContentBlock> = match &m.content {
                AnthropicContent::Blocks(blocks) => {
                    blocks.iter().filter(|b| matches!(b, ContentBlock::ToolUse { .. })).cloned().collect()
                }
                AnthropicContent::Text(_) => Vec::new(),
            };
            // A call the script read that is no `tool_use` block has no slot
            // here: nothing is written.
            if natives.len() != read.len() {
                return false;
            }
            // An edited call keeps the breakpoint of the call it edits, by id:
            // where the prompt cache's prefix ends is the client's. Its other
            // members (a `caller`, a `toolset_name`) say what made a call to
            // THAT tool, so they stay only while the call names it.
            let native = |id: &str, name: &str| {
                natives.iter().find_map(|b| match b {
                    ContentBlock::ToolUse { id: native, name: native_name, cache_control, extra, .. } if native == id => {
                        Some((cache_control.clone(), if native_name == name { extra.clone() } else { BTreeMap::new() }))
                    }
                    _ => None,
                })
            };
            let built = keep_or_build_calls(script, read, &natives, |i, t| {
                let (cache_control, extra) = native(&t.id, &t.name).unwrap_or_default();
                ContentBlock::ToolUse {
                    id: if t.id.is_empty() { format!("call_{i}") } else { t.id.clone() },
                    name: t.name.clone(),
                    input: parse_rhai_args(&t.name, &t.arguments_json),
                    cache_control,
                    extra,
                }
            });
            if let AnthropicContent::Text(text) = &mut m.content {
                let text = std::mem::take(text);
                m.content = AnthropicContent::Blocks(
                    (!text.is_empty()).then_some(ContentBlock::Text { text, cache_control: None, extra: BTreeMap::new() }).into_iter().collect(),
                );
            }
            if let AnthropicContent::Blocks(blocks) = &mut m.content {
                replace_calls_in_place(blocks, built, |b| matches!(b, ContentBlock::ToolUse { .. }));
            }
            true
        }
        ApiRequest::GoogleGemini(r) => {
            let content = &mut r.contents[item];
            let natives: Vec<GeminiPart> =
                content.parts.iter().filter(|p| matches!(p, GeminiPart::FunctionCall { .. })).cloned().collect();
            let built = keep_or_build_calls(script, read, &natives, |_, t| gemini_call_part(t, made_up));
            replace_calls_in_place(&mut content.parts, built, |p| matches!(p, GeminiPart::FunctionCall { .. }));
            true
        }
        ApiRequest::Responses(r) => {
            let crate::api::domain::ResponseInput::Raw(items) = &mut r.input else { return false };
            let item = &mut items[item];
            let ([_], [call]) = (read, script) else { return false };
            let (key, value) = match item.get("type").and_then(Value::as_str) {
                Some("function_call") => ("arguments", call.arguments_json.clone()),
                // A freeform call's input is its free text.
                Some("custom_tool_call") => ("input", crate::api::domain_request::freeform_whole_text(&call.arguments_json)),
                _ => return false,
            };
            if !call.id.is_empty() {
                item["call_id"] = Value::String(call.id.clone());
            }
            item["name"] = Value::String(call.name.clone());
            item[key] = Value::String(value);
            true
        }
    }
}

/// Whether `item` can hold a message's text: on the Responses API, a
/// message item or a call's output (a call or a reasoning item has no place
/// for it).
fn item_takes_text(req: &ApiRequest, item: usize) -> bool {
    match req {
        ApiRequest::Responses(r) => match &r.input {
            crate::api::domain::ResponseInput::Raw(items) => items.get(item).is_some_and(|v| match v.get("type") {
                Some(t) => t == "message" || t == "function_call_output" || t == "custom_tool_call_output",
                None => v.get("role").is_some(),
            }),
            _ => true,
        },
        _ => true,
    }
}

/// Write one script message over the message it read, in place: its text
/// into the piece that holds text (else the first, where it can hold text),
/// its calls into the pieces that hold them — split as read where several
/// do, which needs as many calls as were read. What has no place is named
/// `…_not_applied`.
fn write_message_in_place(
    req: &mut ApiRequest,
    place: &Place,
    script: &RhaiMessage,
    i: usize,
    made_up: &HashMap<String, String>,
    changes: &mut Vec<String>,
) {
    let read = &place.read;
    if script.content != read.content {
        let target = place
            .pieces
            .iter()
            .find(|(.., m)| !m.content.is_empty())
            .or_else(|| place.pieces.first().filter(|(item, ..)| item_takes_text(req, *item)));
        match target {
            Some((item, part, _)) => {
                set_item_text(req, *item, *part, &script.content);
                changes.push(format!("message_{i}"));
            }
            None => changes.push(format!("message_{i}_not_applied")),
        }
    }
    if script.tool_calls != read.tool_calls {
        // Only an assistant message makes calls: on any other there is no place for them.
        let written = read.role == "assistant"
            && match place.pieces.as_slice() {
            [(item, ..)] => set_item_tool_calls(req, *item, &read.tool_calls, &script.tool_calls, made_up),
            pieces if script.tool_calls.len() == read.tool_calls.len() => {
                let mut from = 0;
                let mut all = true;
                for (item, _, m) in pieces {
                    let calls = from..from + m.tool_calls.len();
                    match (read.tool_calls.get(calls.clone()), script.tool_calls.get(calls.clone())) {
                        (Some(read), Some(script)) if read != script => {
                            all &= set_item_tool_calls(req, *item, read, script, made_up);
                        }
                        (Some(_), Some(_)) => {}
                        // The pieces read more calls than the message: no place
                        // to say which is which.
                        _ => all = false,
                    }
                    from = calls.end;
                }
                all && from == read.tool_calls.len()
            }
                _ => false,
            };
        changes.push(if written { format!("message_{i}_tool_calls") } else { format!("message_{i}_tool_calls_not_applied") });
    }
}

/// Each script message's place — the message it was read as — when it is
/// that message: it keeps its `origin`, with the role and answered result
/// read. A map left as read claims an origin before an edited copy does, so
/// the copy is the new one. A map without an `origin` is a message the
/// script made.
fn claim_places(places: &[Place], script: &[RhaiMessage]) -> Vec<Option<usize>> {
    let mut claimed = vec![false; places.len()];
    let mut sources: Vec<Option<usize>> = vec![None; script.len()];
    let identity = |o: usize, m: &RhaiMessage| {
        places.get(o).is_some_and(|p| p.read.role == m.role && p.read.tool_call_id == m.tool_call_id)
    };
    for unchanged in [true, false] {
        for (i, m) in script.iter().enumerate() {
            let Some(o) = m.origin.filter(|&o| sources[i].is_none() && identity(o, m) && !claimed[o]) else {
                continue;
            };
            let read = &places[o].read;
            if unchanged == (read.content == m.content && read.tool_calls == m.tool_calls) {
                claimed[o] = true;
                sources[i] = Some(o);
            }
        }
    }
    sources
}

/// Whether `items` hold something a script cannot see, which a turn
/// rebuilt from what the script reads would lose: a block that is neither
/// text nor a call (an image, a document, thinking, a reasoning or shell
/// item), a breakpoint, a call's signature, a result's error flag — or a
/// member the domain does not model that carries something (on Chat
/// Completions a message's `name` and other members, on the Responses API
/// an item's or a part's).
fn turn_holds_unseen(req: &ApiRequest, items: &[usize]) -> bool {
    // A member that carries nothing (`refusal: null`, `annotations: []`) is
    // not something lost.
    let carries = |v: &Value| !(v.is_null() || v.as_array().is_some_and(Vec::is_empty) || v.as_str() == Some(""));
    let members = |item: usize| match req {
        ApiRequest::ChatCompletions(r) => {
            r.messages.get(item).is_some_and(|m| m.name.is_some() || m.extra.values().any(carries))
        }
        // A Responses item rebuilt keeps its type, role, text, call id, name,
        // arguments and output: any other member (`id`, `status`, `phase`, a
        // part's `annotations`) it would lose.
        ApiRequest::Responses(r) => match &r.input {
            crate::api::domain::ResponseInput::Raw(items) => items.get(item).is_some_and(|v| {
                const KEPT: &[&str] = &["type", "role", "content", "call_id", "name", "arguments", "input", "output"];
                const PART: &[&str] = &["type", "text"];
                let own = v.as_object().is_some_and(|o| o.iter().any(|(k, v)| !KEPT.contains(&k.as_str()) && carries(v)));
                let parts = ["content", "output"].iter().filter_map(|k| v.get(*k)?.as_array()).flatten().any(|part| {
                    part.as_object().is_some_and(|o| o.iter().any(|(k, v)| !PART.contains(&k.as_str()) && carries(v)))
                });
                own || parts
            }),
            crate::api::domain::ResponseInput::Messages(msgs) => {
                msgs.get(item).is_some_and(|m| m.extra.values().any(carries))
            }
            crate::api::domain::ResponseInput::Text(_) => false,
        },
        // A block's members the typed block does not name (a text's
        // `citations`, a call's `caller`, a tool result's `toolset_name`, an
        // image's `transformations`, a file reference's context): what a
        // translation names (`anthropic_history_parts`), a rebuild drops.
        ApiRequest::AnthropicMessages(r) => {
            r.messages.get(item).is_some_and(|m| !crate::api::domain_request::anthropic_history_parts(m).is_empty())
        }
        // A function response's other members, a text part's signature.
        ApiRequest::GoogleGemini(r) => r.contents.get(item).is_some_and(|c| {
            c.parts.iter().any(|p| match p {
                GeminiPart::FunctionResponse { function_response } => function_response.extra.values().any(carries),
                GeminiPart::ThoughtText { thought_signature, .. } => thought_signature.is_some(),
                _ => false,
            })
        }),
    };
    items.iter().any(|&item| {
        members(item)
            || DomainRequest::item_conversation(req, item).iter().any(|m| {
                matches!(&m.role, DomainRole::Tool { is_error: Some(_), .. } | DomainRole::Tool { cache_control: Some(_), .. })
                    || m.content.iter().any(|b| match b {
                        DomainContentBlock::Text { cache_control, .. } => cache_control.is_some(),
                        DomainContentBlock::ToolUse { cache_control, thought_signature, .. } => {
                            cache_control.is_some() || thought_signature.is_some()
                        }
                        _ => true,
                    })
            })
    })
}

/// A Chat Completions message the script wrote, built new.
fn chat_fresh_message(m: &RhaiMessage, declared: &HashMap<String, bool>) -> Message {
    Message {
        role: m.role.clone(),
        content: Some(MessageContent::Text(m.content.clone())),
        name: None,
        tool_calls: rhai_tool_calls_to_cc(&m.tool_calls, &[], declared),
        tool_call_id: m.tool_call_id.clone(),
        extra: BTreeMap::new(),
    }
}

/// Write a script's messages back onto `req`'s conversation (see above).
///
/// A script that kept every message where it was ([`claim_places`]: each
/// map is the message read at its place, in order) has its edits written in
/// place, each in its own item and part, so nothing the script cannot see
/// changes. Any other script reshaped the conversation, and is written turn
/// by turn: a turn whose every message the script kept, in a row and in
/// order, is kept, its edits written in place; every other message (a turn
/// the script split or partly dropped, a message it made) is built new where
/// the script put it, and a turn rebuilt that way that held something the
/// script cannot see (an image, a `name`, thinking, a signature) is named
/// `…_not_applied`. Items a message spans are one turn (a Responses call
/// item joins the assistant message before it, a reasoning item the item
/// after it); an item the script could not see (no message read from it)
/// goes before the turn after it, and one after every turn follows the last.
fn write_messages(req: &mut ApiRequest, script: &[RhaiMessage], changes: &mut Vec<String>) {
    let Some(places) = conversation_places(req) else {
        tracing::warn!("a script's messages were not written back: the conversation's items could not be paired with them");
        changes.push("messages_not_applied".to_string());
        return;
    };
    let made_up = made_up_ids(req);
    let sources = claim_places(&places, script);
    if sources.iter().copied().eq((0..places.len()).map(Some)) {
        for (i, (place, m)) in places.iter().zip(script).enumerate() {
            write_message_in_place(req, place, m, i, &made_up, changes);
        }
        return;
    }

    let start = conversation_start(req);
    let len = DomainRequest::conversation_len(req);
    // The turns: items joined where one message spans them, each with its
    // places in order. An item no message is read from is a turn of none.
    let mut joined = vec![false; len];
    for place in &places {
        // Every item from the message's first to its last, an unseen one
        // between included, is one turn.
        let first = place.pieces[0].0;
        let last = place.pieces.iter().map(|p| p.0).max().unwrap_or(first);
        for item in joined.iter_mut().take(last + 1).skip(first + 1) {
            *item = true;
        }
    }
    // A Responses reasoning item belongs to the item after it, which must
    // follow it: the two are one turn.
    let leads_next = |item: usize| match &*req {
        ApiRequest::Responses(r) => match &r.input {
            crate::api::domain::ResponseInput::Raw(items) => {
                items.get(item).and_then(|v| v.get("type")).is_some_and(|t| t == "reasoning")
            }
            _ => false,
        },
        _ => false,
    };
    let mut turns: Vec<Vec<usize>> = Vec::new();
    let mut turn_of = vec![0usize; len];
    for item in start..len {
        let follows = item > start && leads_next(item - 1);
        if !((joined[item] || follows) && !turns.is_empty()) {
            turns.push(Vec::new());
        }
        if let Some(turn) = turns.last_mut() {
            turn.push(item);
        }
        turn_of[item] = turns.len() - 1;
    }
    let mut reads: Vec<Vec<usize>> = vec![Vec::new(); turns.len()];
    for (o, place) in places.iter().enumerate() {
        reads[turn_of[place.pieces[0].0]].push(o);
    }
    // Where each place's message stands in the script.
    let mut at_of: Vec<Option<usize>> = vec![None; places.len()];
    for (i, source) in sources.iter().enumerate() {
        if let Some(o) = source {
            at_of[*o] = Some(i);
        }
    }
    // A turn kept: all its messages, in a row, in order — their edits are
    // written in place below, before the turns move.
    let kept: Vec<bool> = reads
        .iter()
        .map(|r| {
            let Some(first) = r.first().and_then(|&o| at_of[o]) else { return false };
            r.iter().enumerate().all(|(k, &o)| at_of[o] == Some(first + k))
        })
        .collect();
    for (t, r) in reads.iter().enumerate() {
        if kept[t] {
            for &o in r {
                if let Some(i) = at_of[o] {
                    write_message_in_place(req, &places[o], &script[i], i, &made_up, changes);
                }
            }
        }
    }
    // A turn rebuilt that held something the script cannot see is named.
    for (t, r) in reads.iter().enumerate() {
        if !kept[t] && r.iter().any(|&o| at_of[o].is_some()) && turn_holds_unseen(req, &turns[t]) {
            let i = r.iter().find_map(|&o| at_of[o]).unwrap_or_default();
            changes.push(format!("message_{i}_not_applied"));
        }
    }

    enum Out {
        Item(usize),
        New(std::ops::Range<usize>),
    }
    let mut out: Vec<Out> = Vec::new();
    // An unseen turn goes before the turn after it, wherever that turn's
    // first message lands; those after every turn follow the last one read.
    let last_read = (0..turns.len()).rev().find(|&t| !reads[t].is_empty());
    let mut placed = vec![false; turns.len()];
    let place_unseen = |t: usize, out: &mut Vec<Out>, placed: &mut Vec<bool>| {
        for u in (0..t).rev().take_while(|&u| reads[u].is_empty()).collect::<Vec<_>>().into_iter().rev() {
            if !placed[u] {
                placed[u] = true;
                out.extend(turns[u].iter().map(|&item| Out::Item(item)));
            }
        }
    };
    // The last script message of the last turn read: what follows every turn
    // goes after it.
    let last_of_last_read = (0..script.len())
        .rev()
        .find(|&i| sources[i].is_some_and(|o| Some(turn_of[places[o].pieces[0].0]) == last_read));
    let mut i = 0;
    while i < script.len() {
        let turn = sources[i].map(|o| turn_of[places[o].pieces[0].0]);
        if let Some(t) = turn {
            place_unseen(t, &mut out, &mut placed);
        }
        if let Some(t) = turn.filter(|&t| kept[t] && reads[t].first() == sources[i].as_ref()) {
            out.extend(turns[t].iter().map(|&item| Out::Item(item)));
            i += reads[t].len();
        } else {
            match out.last_mut() {
                Some(Out::New(run)) if run.end == i => run.end = i + 1,
                _ => out.push(Out::New(i..i + 1)),
            }
            i += 1;
        }
        // `i` is past the messages just written.
        if turn.is_some() && turn == last_read && last_of_last_read.is_some_and(|last| i > last) {
            place_unseen(turns.len(), &mut out, &mut placed);
        }
    }
    // Unseen turns left either went with the turn after them, which the
    // script dropped, or close the conversation.
    for t in 0..turns.len() {
        if reads[t].is_empty() && !placed[t] && last_read.is_none_or(|l| t > l) {
            out.extend(turns[t].iter().map(|&item| Out::Item(item)));
        }
    }

    match req {
        ApiRequest::ChatCompletions(chat) => {
            let declared = declared_tool_kinds(chat.tools.as_ref());
            let original = std::mem::take(&mut chat.messages);
            chat.messages = original[..start].to_vec();
            for piece in out {
                match piece {
                    Out::Item(item) => chat.messages.push(original[item].clone()),
                    Out::New(run) => chat.messages.extend(script[run].iter().map(|m| chat_fresh_message(m, &declared))),
                }
            }
        }
        ApiRequest::AnthropicMessages(msg) => {
            let original = std::mem::take(&mut msg.messages);
            for piece in out {
                match piece {
                    Out::Item(item) => msg.messages.push(original[item].clone()),
                    Out::New(run) => msg
                        .messages
                        .extend(group_rhai_for_anthropic(&script[run]).iter().map(build_anthropic_from_group)),
                }
            }
        }
        ApiRequest::GoogleGemini(gemini) => {
            let original = std::mem::take(&mut gemini.contents);
            // Each response the client sent, by the id the script read it
            // under: what a rebuilt response is named.
            let mut names: HashMap<String, String> = HashMap::new();
            for place in &places {
                let (item, part, _) = &place.pieces[0];
                let (Some(id), Some(content)) = (&place.read.tool_call_id, original.get(*item)) else { continue };
                let k = places
                    .iter()
                    .filter(|p| p.pieces[0].0 == *item && p.pieces[0].1 < *part && p.read.tool_call_id.is_some())
                    .count();
                if let Some(GeminiPart::FunctionResponse { function_response }) =
                    content.parts.iter().filter(|p| matches!(p, GeminiPart::FunctionResponse { .. })).nth(k)
                {
                    names.insert(id.clone(), function_response.name.clone());
                }
            }
            for piece in out {
                match piece {
                    Out::Item(item) => gemini.contents.push(original[item].clone()),
                    Out::New(run) => gemini.contents.extend(gemini_fresh_contents(&script[run], script, &made_up, &names)),
                }
            }
        }
        ApiRequest::Responses(resp) => {
            use crate::api::domain::{ResponseInput, ResponseInputMessage};
            let declared = declared_tool_kinds(resp.tools.as_ref());
            let plain = |m: &RhaiMessage| m.role != "tool" && m.tool_calls.is_empty();
            let original = std::mem::replace(&mut resp.input, ResponseInput::Raw(Vec::new()));
            let items: Vec<Value> = match original {
                ResponseInput::Raw(items) => items,
                // A string or a message list stays one while what the script
                // wrote is plain messages.
                ResponseInput::Text(_) | ResponseInput::Messages(_)
                    if out.iter().all(|p| match p {
                        Out::New(run) => script[run.clone()].iter().all(plain),
                        Out::Item(_) => true,
                    }) =>
                {
                    let original: Vec<ResponseInputMessage> = match original {
                        ResponseInput::Messages(msgs) => msgs,
                        ResponseInput::Text(text) => vec![ResponseInputMessage {
                            role: "user".to_string(),
                            content: MessageContent::Text(text),
                            extra: BTreeMap::new(),
                        }],
                        ResponseInput::Raw(_) => Vec::new(),
                    };
                    resp.input = ResponseInput::Messages(
                        out.into_iter()
                            .flat_map(|piece| match piece {
                                Out::Item(item) => original.get(item).cloned().into_iter().collect::<Vec<_>>(),
                                Out::New(run) => script[run]
                                    .iter()
                                    .map(|m| ResponseInputMessage {
                                        role: m.role.clone(),
                                        content: MessageContent::Text(m.content.clone()),
                                        extra: BTreeMap::new(),
                                    })
                                    .collect(),
                            })
                            .collect(),
                    );
                    changes.push("messages".to_string());
                    return;
                }
                ResponseInput::Messages(msgs) => msgs.iter().map(|m| serde_json::to_value(m).unwrap_or_default()).collect(),
                ResponseInput::Text(text) => vec![serde_json::json!({"role": "user", "content": text})],
            };
            resp.input = ResponseInput::Raw(
                out.into_iter()
                    .flat_map(|piece| match piece {
                        Out::Item(item) => items.get(item).cloned().into_iter().collect::<Vec<_>>(),
                        Out::New(run) => {
                            run.clone().zip(&script[run]).flat_map(|(j, m)| responses_fresh_items(j, m, script, &declared)).collect()
                        }
                    })
                    .collect(),
            );
        }
    }
    changes.push("messages".to_string());
}

/// The Responses items a message the script wrote makes: a tool message is a
/// call's output; any other is a message, and each of its calls a call item
/// after it (no message when it carries only calls). A call to a custom
/// (freeform) tool — by the request's tools (`declared`) — is a custom call
/// with its free text, and the output answering it a custom call's output.
fn responses_fresh_items(at: usize, m: &RhaiMessage, script: &[RhaiMessage], declared: &HashMap<String, bool>) -> Vec<Value> {
    // A call with no id is named by its place: its message's, then its own.
    let call_id = |i: usize, id: &str| if id.is_empty() { format!("call_{at}_{i}") } else { id.to_string() };
    let custom = |name: &str| declared.get(name).copied().unwrap_or(false);
    if m.role == "tool" {
        let id = m.tool_call_id.clone().unwrap_or_default();
        let answers_custom =
            script.iter().flat_map(|s| &s.tool_calls).find(|c| c.id == id).is_some_and(|c| custom(&c.name));
        let kind = if answers_custom { "custom_tool_call_output" } else { "function_call_output" };
        return vec![serde_json::json!({"type": kind, "call_id": id, "output": m.content})];
    }
    let message = (!m.content.is_empty() || m.tool_calls.is_empty())
        .then(|| serde_json::json!({"type": "message", "role": m.role, "content": m.content}));
    message
        .into_iter()
        .chain(m.tool_calls.iter().filter(|t| !t.name.is_empty()).enumerate().map(|(i, t)| {
            if custom(&t.name) {
                serde_json::json!({
                    "type": "custom_tool_call",
                    "call_id": call_id(i, &t.id),
                    "name": t.name,
                    "input": crate::api::domain_request::freeform_whole_text(&t.arguments_json),
                })
            } else {
                serde_json::json!({"type": "function_call", "call_id": call_id(i, &t.id), "name": t.name, "arguments": t.arguments_json})
            }
        }))
        .collect()
}

/// The Gemini contents a run of messages the script wrote makes: consecutive
/// tool messages are one user turn of function responses, any other message
/// a turn of its text and calls. A response is named as the client's was
/// (`names`, by the id the script read), else by its call; an id the
/// gateway made up (`made_up`) is not written.
fn gemini_fresh_contents(
    run: &[RhaiMessage],
    script: &[RhaiMessage],
    made_up: &HashMap<String, String>,
    names: &HashMap<String, String>,
) -> Vec<GeminiContent> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < run.len() {
        if run[i].role != "tool" {
            let m = &run[i];
            let role = if m.role == "assistant" { "model" } else { "user" };
            let text = (!m.content.is_empty()).then(|| GeminiPart::Text { text: m.content.clone() });
            out.push(GeminiContent {
                role: Some(role.to_string()),
                parts: text
                    .into_iter()
                    .chain(m.tool_calls.iter().filter(|t| !t.name.is_empty()).map(|t| gemini_call_part(t, made_up)))
                    .collect(),
            });
            i += 1;
            continue;
        }
        let mut parts = Vec::new();
        while i < run.len() && run[i].role == "tool" {
            let m = &run[i];
            let id = m.tool_call_id.clone().unwrap_or_default();
            let name = names
                .get(&id)
                .or_else(|| made_up.get(&id))
                .cloned()
                .or_else(|| script.iter().flat_map(|s| &s.tool_calls).find(|c| c.id == id).map(|c| c.name.clone()))
                .unwrap_or_else(|| id.clone());
            parts.push(GeminiPart::FunctionResponse {
                function_response: crate::api::gemini::GeminiFunctionResponseData {
                    id: (!id.is_empty() && !made_up.contains_key(&id)).then_some(id),
                    name,
                    response: crate::api::domain_request::gemini_response(m.content.clone(), None),
                    parts: Vec::new(),
                    extra: Default::default(),
                },
            });
            i += 1;
        }
        out.push(GeminiContent { role: Some("user".to_string()), parts });
    }
    out
}

/// Whether a script left the tool list as it found it. `is_gateway_substituted`
/// annotates a tool for the script and is not part of the tool, so a
/// substituted tool does not read as an edit.
fn same_tools(script: &[RhaiTool], original: &[RhaiTool]) -> bool {
    let view = |t: &RhaiTool| (t.name.clone(), t.description.clone(), t.parameters_json.clone());
    script.iter().map(view).eq(original.iter().map(view))
}

/// Apply Rhai tool changes to any protocol's tool vector.
fn apply_tool_changes<T>(
    rhai_tools: &[RhaiTool],
    original_tools: &mut Option<Vec<T>>,
    from_rhai: impl Fn(&RhaiTool) -> T,
    to_rhai: impl Fn(&T) -> RhaiTool,
    changes: &mut Vec<String>,
) {
    // Round-trip the original tools through RhaiTool so we can detect any
    // per-field change (description, parameters_json, name) the script made
    // — not just a count mismatch. Without this comparison a script that
    // appends to `ctx.tools[i].description` would silently leave the
    // outgoing tool list unchanged.
    let original_as_rhai: Vec<RhaiTool> = original_tools
        .as_ref()
        .map(|tools| tools.iter().map(&to_rhai).collect())
        .unwrap_or_default();

    if same_tools(rhai_tools, &original_as_rhai) {
        return;
    }

    if rhai_tools.is_empty() {
        *original_tools = None;
    } else {
        *original_tools = Some(rhai_tools.iter().map(&from_rhai).collect());
    }
    changes.push("tools".to_string());
}

/// Where a protocol writes a function tool's definition: Chat nests it under
/// `function`, Responses declares it flat beside `type`.
#[derive(Clone, Copy)]
enum FunctionSpelling {
    Nested,
    Flat,
}

/// The script's view of a Chat or Responses tool — what the domain gives a
/// script (name, description, parameters), read from whichever spelling the
/// tool uses: nested under `function` or `custom` (Chat), or flat (Responses).
/// A hosted tool names no function, so the script sees it with an empty name.
fn openai_tool_to_rhai(t: &Tool) -> RhaiTool {
    let nested = t.extra.get(t.r#type.as_str()).filter(|d| d.is_object());
    let field = |key: &str| nested.and_then(|d| d.get(key)).or_else(|| t.extra.get(key));
    let function = t.function.as_ref();
    let hosted = function.is_none() && !matches!(t.r#type.as_str(), "function" | "custom");
    RhaiTool {
        kind: hosted.then(|| t.r#type.clone()),
        config_json: if hosted { serde_json::to_string(&t.extra).ok() } else { None },
        name: t.function_name().unwrap_or_default().to_string(),
        description: function
            .and_then(|f| f.description.clone())
            .or_else(|| field("description").and_then(Value::as_str).map(String::from)),
        parameters_json: function
            .and_then(|f| f.parameters.as_ref())
            .or_else(|| field("parameters"))
            .and_then(|p| serde_json::to_string(p).ok()),
        is_gateway_substituted: false,
    }
}

/// Apply a script's tool list to a Chat Completions or Responses request.
///
/// A script sees every tool as a name, a description and a schema, so only a
/// function is rebuilt from that view — in the protocol's own spelling, and
/// keeping the fields the view does not carry (`strict`). A custom (freeform)
/// tool keeps its kind and its `format`, taking the script's name and
/// description; a hosted tool, which the script sees with no name, is kept as
/// the client declared it. Each script tool is matched to the tool it came
/// from BY NAME — a reorder moves tools, it never swaps their kinds or fields
/// — and a nameless (hosted) one by what it is, its `kind` and `config_json`,
/// never by the empty name every hosted tool shares. A name no original has
/// is a rename only where the tool in its position was renamed away (its own
/// name no longer listed) and names a function or custom tool; anything else
/// is a new function. Locked by `a_script_reordering_tools_keeps_each_ones_kind`,
/// `a_script_removing_a_hosted_tool_keeps_the_others` and
/// `a_script_sees_and_keeps_a_chat_custom_tool`.
fn apply_openai_tool_changes(
    rhai_tools: &[RhaiTool],
    tools: &mut Option<Vec<Tool>>,
    spelling: FunctionSpelling,
    changes: &mut Vec<String>,
) {
    let original: Vec<RhaiTool> = tools.iter().flatten().map(openai_tool_to_rhai).collect();
    if same_tools(rhai_tools, &original) {
        return;
    }
    changes.push("tools".to_string());
    let prior = tools.take().unwrap_or_default();
    if rhai_tools.is_empty() {
        return;
    }
    let names_kept: std::collections::HashSet<&str> = rhai_tools.iter().map(|t| t.name.as_str()).collect();
    let mut taken = vec![false; prior.len()];
    // The original each script tool came from: the first unused one of its
    // name, else — a rename — the one in its position if that was renamed away.
    let prior_view: Vec<RhaiTool> = prior.iter().map(openai_tool_to_rhai).collect();
    let mut origin: Vec<Option<usize>> = rhai_tools
        .iter()
        .map(|t| {
            // A named tool by its name; a nameless (hosted) one by what it is.
            let same = |o: &RhaiTool| match t.name.as_str() {
                "" => t.kind.is_some() && o.name.is_empty() && o.kind == t.kind && o.config_json == t.config_json,
                name => o.name == name,
            };
            let i = prior_view.iter().enumerate().position(|(i, o)| !taken[i] && same(o))?;
            taken[i] = true;
            Some(i)
        })
        .collect();
    for (pos, t) in rhai_tools.iter().enumerate() {
        if origin[pos].is_some() || t.name.is_empty() {
            continue;
        }
        if let Some(o) = prior.get(pos)
            && !taken[pos]
            && o.function_name().is_some_and(|n| !n.is_empty() && !names_kept.contains(n))
        {
            taken[pos] = true;
            origin[pos] = Some(pos);
        }
    }
    *tools = Some(
        rhai_tools
            .iter()
            .zip(origin)
            .map(|(t, origin)| {
                let orig = origin.map(|i| prior[i].clone());
                match orig {
                    Some(orig) if orig.r#type == "custom" => custom_tool_from_rhai(orig, t),
                    Some(orig) if orig.r#type != "function" && orig.function.is_none() => orig,
                    orig => function_tool_from_rhai(orig, t, spelling),
                }
            })
            .collect(),
    );
}

/// A custom tool with the script's name and description, its kind and
/// `format` kept.
fn custom_tool_from_rhai(mut tool: Tool, t: &RhaiTool) -> Tool {
    tool.set_function_name(t.name.clone());
    let description = t.description.clone().map(Value::from);
    match tool.extra.get_mut("custom") {
        Some(Value::Object(def)) => {
            match description {
                Some(d) => def.insert("description".into(), d),
                None => def.remove("description"),
            };
        }
        _ => {
            match description {
                Some(d) => tool.extra.insert("description".into(), d),
                None => tool.extra.remove("description"),
            };
        }
    }
    tool
}

/// A function tool from the script's view, in `spelling`, keeping the fields
/// of the function it replaces that the view does not carry.
fn function_tool_from_rhai(orig: Option<Tool>, t: &RhaiTool, spelling: FunctionSpelling) -> Tool {
    let parameters = t.parameters_json.as_ref().and_then(|p| serde_json::from_str::<Value>(p).ok());
    let strict = orig.as_ref().and_then(|o| o.function.as_ref()).and_then(|f| f.strict);
    let mut extra = orig.map(|o| o.extra).unwrap_or_default();
    match spelling {
        FunctionSpelling::Nested => Tool {
            r#type: "function".to_string(),
            function: Some(FunctionDef { name: t.name.clone(), description: t.description.clone(), parameters, strict }),
            extra,
        },
        FunctionSpelling::Flat => {
            extra.insert("name".into(), Value::from(t.name.clone()));
            for (key, value) in [("description", t.description.clone().map(Value::from)), ("parameters", parameters)] {
                match value {
                    Some(v) => extra.insert(key.into(), v),
                    None => extra.remove(key),
                };
            }
            Tool { r#type: "function".to_string(), function: None, extra }
        }
    }
}

/// Apply Rhai tool changes to Gemini's tool structure.
///
/// Gemini wraps N function declarations in a single `GeminiTool`, so the
/// generic `apply_tool_changes` (which assumes 1:1 rhai↔native mapping) does
/// not fit. The script's functions are compared against the flattened
/// declarations and, when they differ, rebuilt into one entry beside the
/// client's built-in tools.
fn apply_gemini_tool_changes(
    rhai_tools: &[RhaiTool],
    original_tools: &mut Option<Vec<crate::api::gemini::GeminiTool>>,
    changes: &mut Vec<String>,
) {
    // Project the flattened original function declarations into the RhaiTool
    // shape so per-field changes (description, parameters) surface alongside
    // count mismatches — count-only checks miss description-only mutations.
    let original_as_rhai: Vec<RhaiTool> = original_tools
        .as_ref()
        .map(|tools| {
            tools
                .iter()
                .flat_map(|t| t.function_declarations.as_ref().map(|d| d.iter()).into_iter().flatten())
                .map(|d| RhaiTool {
                    name: d.name.clone(),
                    description: d.description.clone(),
                    parameters_json: d
                        .parameters
                        .as_ref()
                        .and_then(|p| serde_json::to_string(p).ok()),
                    is_gateway_substituted: false, kind: None, config_json: None,
                })
                .collect()
        })
        .unwrap_or_default();

    if same_tools(rhai_tools, &original_as_rhai) {
        return;
    }

    // The built-ins (`googleSearch`, `codeExecution`, …) a script does not
    // see stay where the client put them; the declarations are rebuilt into
    // the first entry that held any.
    let decls: Vec<crate::api::gemini::GeminiFunctionDecl> = rhai_tools
        .iter()
        .map(|t| crate::api::gemini::GeminiFunctionDecl {
            name: t.name.clone(),
            description: t.description.clone(),
            parameters: t
                .parameters_json
                .as_ref()
                .and_then(|p| serde_json::from_str(p).ok()),
        })
        .collect();
    let mut decls = (!decls.is_empty()).then_some(decls);
    let mut rebuilt: Vec<crate::api::gemini::GeminiTool> = Vec::new();
    for mut tool in original_tools.take().into_iter().flatten() {
        if tool.function_declarations.is_some() {
            tool.function_declarations = decls.take();
        }
        if tool.function_declarations.is_some() || !tool.extra.is_empty() {
            rebuilt.push(tool);
        }
    }
    if let Some(decls) = decls {
        rebuilt.push(crate::api::gemini::GeminiTool { extra: Default::default(), function_declarations: Some(decls) });
    }
    *original_tools = (!rebuilt.is_empty()).then_some(rebuilt);
    changes.push("tools".to_string());
}

/// Which fields of a [`RequestContext`] a writer changed, so
/// [`apply_to_api_request`] syncs only those back to the request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChangedFields {
    pub system_prompt: bool,
    pub messages: bool,
    pub tools: bool,
}

/// Apply modifications from a `RequestContext` back to an `ApiRequest`.
/// Returns a list of change descriptions for audit.
///
/// `changed` names the fields a writer actually modified; a field it did not
/// is never synced, so the native request keeps it untouched. A projection
/// differs from its wire field in ways a sync would destroy — the domain→Rhai
/// message list can differ in count (ToolResult splitting) and drops non-text
/// content, and a projection that read no history carries none — so an
/// unmodified field is never compared, let alone rewritten. The model is
/// always compared.
pub fn apply_to_api_request(
    ctx: &RequestContext,
    req: &mut ApiRequest,
    changed: ChangedFields,
) -> Vec<String> {
    let mut changes = Vec::new();
    let messages_changed = changed.messages;

    match req {
        ApiRequest::ChatCompletions(chat) => {
            // System prompt: the leading messages `chat_system_lead` names are
            // its channel, read joined, so a change (`changed.system_prompt`:
            // the script's value differs from the one it read) leaves one
            // prompt message — the run's first, keeping its role and fields,
            // its text replaced, or a new `system` one in front — and a
            // removal drops them all: never a message beside a run that still
            // carries the old text. A message in the run that carries nothing
            // stays where it is.
            let is_prompt = |m: &Message| m.role == "system" || m.role == "developer";
            let lead = if changed.system_prompt { chat_system_lead(&chat.messages) } else { 0 };
            if changed.system_prompt
                && (ctx.system_prompt.is_some() || chat.messages[..lead].iter().any(is_prompt))
            {
                let tail = chat.messages.split_off(lead);
                let at = chat.messages.iter().position(is_prompt);
                let first = at.map(|i| chat.messages.remove(i));
                chat.messages.retain(|m| !is_prompt(m));
                if let Some(prompt) = &ctx.system_prompt {
                    let mut message = first.unwrap_or_else(|| Message {
                        role: "system".to_string(),
                        content: None,
                        name: None,
                        tool_calls: None,
                        tool_call_id: None,
                        extra: BTreeMap::new(),
                    });
                    message.content = Some(MessageContent::Text(prompt.clone()));
                    chat.messages.insert(at.unwrap_or(0), message);
                    changes.push("system_prompt".to_string());
                } else {
                    changes.push("system_prompt_removed".to_string());
                }
                chat.messages.extend(tail);
            }


            if changed.tools {
                apply_openai_tool_changes(&ctx.tools, &mut chat.tools, FunctionSpelling::Nested, &mut changes);
            }

            if ctx.model != chat.model {
                chat.model = ctx.model.clone();
                changes.push("model".to_string());
            }
        }
        ApiRequest::AnthropicMessages(msg) => {
            // System prompt
            if changed.system_prompt && let Some(new_prompt) = &ctx.system_prompt {
                let current = msg.system.as_ref().map(|s| s.to_text());
                if current.as_deref() != Some(new_prompt) {
                    msg.system = Some(SystemPrompt::Text(new_prompt.clone()));
                    changes.push("system_prompt".to_string());
                }
            } else if changed.system_prompt && ctx.system_prompt.is_none() && msg.system.is_some() {
                msg.system = None;
                changes.push("system_prompt_removed".to_string());
            }


            if changed.tools {
                // A tool edit forces a full rebuild of the list; index the prior
                // tools by name so per-tool fields the RhaiTool round-trip can't
                // carry — the `cache_control` breakpoint and the server-tool `type`
                // in `extra` — are restored on tools the script left unchanged.
                // Without this, editing one tool strips cache breakpoints off the
                // others (cache miss) and drops a server tool's `type` (corruption).
                let prior_tools: HashMap<String, AnthropicTool> = msg
                    .tools
                    .as_ref()
                    .map(|tools| tools.iter().map(|t| (t.name.clone(), t.clone())).collect())
                    .unwrap_or_default();

                apply_tool_changes(
                    &ctx.tools,
                    &mut msg.tools,
                    |t| AnthropicTool {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        input_schema: t
                            .parameters_json
                            .as_ref()
                            .and_then(|p| serde_json::from_str(p).ok()),
                        cache_control: prior_tools
                            .get(&t.name)
                            .and_then(|o| o.cache_control.clone()),
                        extra: prior_tools
                            .get(&t.name)
                            .map(|o| o.extra.clone())
                            .unwrap_or_default(),
                    },
                    |t| RhaiTool {
                        name: t.name.clone(),
                        description: t.description.clone(),
                        parameters_json: t
                            .input_schema
                            .as_ref()
                            .and_then(|p| serde_json::to_string(p).ok()),
                        is_gateway_substituted: false, kind: None, config_json: None,
                    },
                    &mut changes,
                );
            }

            if ctx.model != msg.model {
                msg.model = ctx.model.clone();
                changes.push("model".to_string());
            }
        }
        ApiRequest::Responses(resp) => {
            // System prompt (instructions)
            if changed.system_prompt && ctx.system_prompt != resp.instructions {
                resp.instructions = ctx.system_prompt.clone();
                changes.push("system_prompt".to_string());
            }


            if changed.tools {
                apply_openai_tool_changes(&ctx.tools, &mut resp.tools, FunctionSpelling::Flat, &mut changes);
            }

            if ctx.model != resp.model {
                resp.model = ctx.model.clone();
                changes.push("model".to_string());
            }
        }
        ApiRequest::GoogleGemini(gemini) => {
            // System prompt
            // A script's prompt is the whole instruction: its edit replaces
            // every part with its text, and its removal drops the instruction.
            // It is compared with the text it read (`GeminiContent::system_text`),
            // so a prompt left as read is not written.
            if changed.system_prompt
                && gemini.system_instruction.as_ref().and_then(crate::api::gemini::GeminiContent::system_text)
                    != ctx.system_prompt
            {
                match &ctx.system_prompt {
                    Some(prompt) => {
                        gemini.system_instruction = Some(crate::api::gemini::GeminiContent {
                            role: None,
                            parts: vec![crate::api::gemini::GeminiPart::Text { text: prompt.clone() }],
                        });
                        changes.push("system_prompt".to_string());
                    }
                    None => {
                        gemini.system_instruction = None;
                        changes.push("system_prompt_removed".to_string());
                    }
                }
            }


            // Tool sync
            if changed.tools {
                apply_gemini_tool_changes(&ctx.tools, &mut gemini.tools, &mut changes);
            }

            // Model override
            if ctx.model != gemini.model {
                gemini.model = ctx.model.clone();
                changes.push("model".to_string());
            }
        }
    }

    // The messages after the system prompt: a Chat Completions prompt edit
    // above has settled which leading messages are its channel.
    if messages_changed {
        write_messages(req, &ctx.messages, &mut changes);
    }

    changes
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;
    use crate::auth::RateLimitConfig;
    use bytes::Bytes;

    /// A writer that may have edited the system prompt and the tools, and the
    /// messages when `messages` is set.
    fn edited(messages: bool) -> ChangedFields {
        ChangedFields { system_prompt: true, messages, tools: true }
    }

    fn test_user() -> UserContext {
        UserContext {
            inline_ai: false,
            qos_class_id: None,
            qos_class_elevated: false,
            user_id: uuid::Uuid::nil(),
            tenant_id: uuid::Uuid::nil(),
            email: Some("test@example.com".to_string()),
            display_name: None,
            real_api_key: "sk-key".to_string(),
            model_map: Default::default(),
            rate_limit: RateLimitConfig::default(),
            user_rate_override: None,
            key_budget: None,
            tenant_budget: None,
            expires_at: None,
            key_id: None,
            app_id: None,
            session_id: None,
            workspace_id: uuid::Uuid::nil(),
            allowed_provider_ids: Vec::new(),
            allowed_virtual_server_ids: Vec::new(),
            allowed_a2a_agent_ids: Vec::new(),
            mcp_scope: None,
            forward_auth: false,
            byok_passthrough: Vec::new(),
        }
    }

    fn no_subs() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    /// A Chat Completions message's text, its text parts joined.
    fn chat_msg_text(msg: &Message) -> String {
        match &msg.content {
            Some(MessageContent::Text(t)) => t.clone(),
            Some(MessageContent::Parts(parts)) => parts
                .iter()
                .filter_map(|p| match p {
                    crate::api::domain::ContentPart::Text { text, .. } => Some(text.as_str()),
                    _ => None,
                })
                .collect::<Vec<_>>()
                .join("\n"),
            None => String::new(),
        }
    }

    /// The messages a script reads of a request.
    fn script_view(req: &ApiRequest) -> Vec<RhaiMessage> {
        from_api_request(req, &test_user(), None, None, None, false, &no_subs()).messages
    }

    fn anthropic_request(native: &[AnthropicMessage]) -> ApiRequest {
        ApiRequest::AnthropicMessages(
            serde_json::from_value(serde_json::json!({"model": "m", "max_tokens": 1, "messages": native})).unwrap(),
        )
    }

    fn gemini_request(contents: &[GeminiContent]) -> ApiRequest {
        ApiRequest::GoogleGemini(serde_json::from_value(serde_json::json!({"contents": contents})).unwrap())
    }

    /// The messages a script reads of an Anthropic conversation.
    fn anthropic_view(native: &[AnthropicMessage]) -> Vec<RhaiMessage> {
        script_view(&anthropic_request(native))
    }

    /// The messages a script reads of a Gemini conversation.
    fn gemini_view(contents: &[GeminiContent]) -> Vec<RhaiMessage> {
        script_view(&gemini_request(contents))
    }

    /// Write a script's messages back onto an Anthropic conversation, as a
    /// script's result is written.
    fn anthropic_write(native: &mut Vec<AnthropicMessage>, script: &[RhaiMessage], changes: &mut Vec<String>) {
        let mut req = anthropic_request(native);
        write_messages(&mut req, script, changes);
        let ApiRequest::AnthropicMessages(r) = req else { unreachable!() };
        *native = r.messages;
    }

    /// Write a script's messages back onto a Gemini conversation.
    fn gemini_write(contents: &mut Vec<GeminiContent>, script: &[RhaiMessage], changes: &mut Vec<String>) {
        let mut req = gemini_request(contents);
        write_messages(&mut req, script, changes);
        let ApiRequest::GoogleGemini(r) = req else { unreachable!() };
        *contents = r.contents;
    }

    #[test]
    fn roundtrip_chat_completions() {
        let json = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"Be helpful"},{"role":"user","content":"Hello"}]}"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), Some("test-app"), Some(8000), Some("openai"), false, &no_subs());

        assert_eq!(ctx.system_prompt.as_deref(), Some("Be helpful"));
        // The system prompt is its own channel, never a message.
        assert_eq!(ctx.messages.len(), 1);
        assert_eq!(ctx.messages[0].role, "user");
        assert_eq!(ctx.api_version, "chat_completions");
        assert_eq!(ctx.metadata.get("max_messages").unwrap(), "10"); // 8000/1000=8, clamped to min 10
        assert_eq!(ctx.metadata.get("needs_translation").unwrap(), "false");

        // Modify and apply back
        let mut ctx = ctx;
        ctx.system_prompt = Some("Modified prompt".to_string());
        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(changes.contains(&"system_prompt".to_string()));

        if let ApiRequest::ChatCompletions(chat) = &req {
            match &chat.messages[0].content {
                Some(MessageContent::Text(t)) => assert_eq!(t, "Modified prompt"),
                other => panic!("expected text, got {other:?}"),
            }
        }
    }

    /// On Chat Completions `ctx.messages` is the conversation after the
    /// leading system and developer messages: an edit lands on the message it
    /// names, a resize keeps that lead in front, and the system prompt is
    /// never read or written through it.
    #[test]
    fn chat_completions_messages_start_after_the_system_prompt() {
        let json = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"Be helpful"},{"role":"developer","content":"Be brief"},{"role":"user","content":"Hello"},{"role":"assistant","content":"Hi"}]}"#;
        let parse = || ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();
        let texts = |req: &ApiRequest| -> Vec<(String, String)> {
            let ApiRequest::ChatCompletions(chat) = req else { panic!("chat") };
            chat.messages.iter().map(|m| (m.role.clone(), chat_msg_text(m))).collect()
        };
        let pair = |r: &str, t: &str| (r.to_string(), t.to_string());
        // The messages alone: a system prompt write is another channel's.
        let messages = ChangedFields { system_prompt: false, messages: true, tools: false };

        let mut req = parse();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        assert_eq!(ctx.messages.iter().map(|m| m.role.as_str()).collect::<Vec<_>>(), ["user", "assistant"]);
        ctx.messages[0].content = "Hello there".to_string();
        let changes = apply_to_api_request(&ctx, &mut req, messages);
        assert_eq!(changes, ["message_0"]);
        assert_eq!(
            texts(&req),
            [pair("system", "Be helpful"), pair("developer", "Be brief"), pair("user", "Hello there"), pair("assistant", "Hi")]
        );

        // A resize rebuilds the conversation behind the lead.
        let mut req = parse();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        ctx.messages.remove(1);
        let changes = apply_to_api_request(&ctx, &mut req, messages);
        assert!(changes.contains(&"messages".to_string()), "{changes:?}");
        assert_eq!(texts(&req), [pair("system", "Be helpful"), pair("developer", "Be brief"), pair("user", "Hello")]);

        // Control: unchanged messages write nothing.
        let mut req = parse();
        let ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        assert!(apply_to_api_request(&ctx, &mut req, messages).is_empty());
        assert_eq!(texts(&req), texts(&parse()));
    }

    /// Run a script's edit of the messages over `body` and return the body
    /// the request then carries, with the changes it recorded.
    fn messages_edit(
        version: crate::api::sse::ApiVersion,
        body: Value,
        edit: impl FnOnce(&mut Vec<RhaiMessage>),
    ) -> (Value, Vec<String>) {
        let mut req = ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        edit(&mut ctx.messages);
        let changes = apply_to_api_request(&ctx, &mut req, ChangedFields { system_prompt: false, messages: true, tools: false });
        let out = match &req {
            ApiRequest::ChatCompletions(r) => serde_json::to_value(r).unwrap(),
            ApiRequest::AnthropicMessages(r) => serde_json::to_value(r).unwrap(),
            ApiRequest::Responses(r) => serde_json::to_value(r).unwrap(),
            ApiRequest::GoogleGemini(r) => serde_json::to_value(r).unwrap(),
        };
        (out, changes)
    }

    /// A Chat Completions edit lands on the message it was read from, the
    /// rest as sent: several leading system messages stay once each, a
    /// message the script cannot see (no content) stays, and the edited
    /// message keeps its image and its `name`; a script that adds a message
    /// keeps every other as sent.
    #[test]
    fn a_chat_completions_edit_keeps_what_the_script_does_not_see() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "system", "content": "S1"},
            {"role": "system", "content": "S2"},
            {"role": "user", "name": "bob", "content": [
                {"type": "text", "text": "look"},
                {"type": "image_url", "image_url": {"url": "https://x/i.png"}},
            ]},
            {"role": "assistant", "content": ""},
            {"role": "user", "content": "more"},
        ]});
        let edited_user = serde_json::json!({"role": "user", "name": "bob", "content": [
            {"type": "text", "text": "LOOK"},
            {"type": "image_url", "image_url": {"url": "https://x/i.png"}},
        ]});

        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            let at = m.iter().position(|m| m.content == "look").unwrap();
            m[at].content = "LOOK".to_string();
        });
        assert!(!changes.is_empty());
        let mut want = body.clone();
        want["messages"][2] = edited_user.clone();
        assert_eq!(out["messages"], want["messages"]);

        // A message added: every message the script kept is the client's own.
        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m.push(RhaiMessage { role: "user".to_string(), content: "added".to_string(), ..Default::default() });
        });
        assert!(changes.contains(&"messages".to_string()), "{changes:?}");
        let mut want = body["messages"].as_array().unwrap().clone();
        want.push(serde_json::json!({"role": "user", "content": "added"}));
        assert_eq!(out["messages"], Value::Array(want));

        // Control: a script that changes nothing writes nothing.
        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |_| {});
        assert!(changes.is_empty(), "{changes:?}");
        assert_eq!(out["messages"], body["messages"]);
    }

    /// A Responses edit that keeps the count lands in its item; one that
    /// drops a message keeps every other item as sent — calls, their
    /// outputs and reasoning — and an added message is a message item.
    #[test]
    fn a_responses_edit_keeps_calls_outputs_and_reasoning() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "first"}]},
            {"type": "reasoning", "id": "rs_1", "summary": []},
            {"type": "function_call", "call_id": "c1", "name": "ls", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": "a.txt"},
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "next"}]},
        ]});

        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            let at = m.iter().position(|m| m.content == "next").unwrap();
            m[at].content = "NEXT".to_string();
        });
        assert!(!changes.is_empty());
        let mut want = body["input"].clone();
        want[4]["content"][0]["text"] = Value::from("NEXT");
        assert_eq!(out["input"], want);

        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            m.remove(0);
            for text in ["added", "more"] {
                m.push(RhaiMessage { role: "user".to_string(), content: text.to_string(), ..Default::default() });
            }
        });
        assert!(changes.contains(&"messages".to_string()), "{changes:?}");
        let input = body["input"].as_array().unwrap();
        assert_eq!(
            out["input"],
            serde_json::json!([
                input[1], input[2], input[3], input[4],
                {"type": "message", "role": "user", "content": "added"},
                {"type": "message", "role": "user", "content": "more"},
            ])
        );
    }

    /// A Gemini call the client sent without an id is shown to the script
    /// under one the gateway made up; that id never reaches the wire, whether
    /// the script edits the call in place or also reshapes the conversation,
    /// and a call left as it was keeps its signature.
    #[test]
    fn a_gemini_call_without_an_id_is_written_back_without_one() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"contents": [
            {"role": "user", "parts": [{"text": "go"}]},
            {"role": "model", "parts": [
                {"functionCall": {"name": "ls", "args": {"p": "."}}, "thoughtSignature": "SIG"},
                {"functionCall": {"name": "cat", "args": {"f": "a"}}},
            ]},
            {"role": "user", "parts": [
                {"functionResponse": {"name": "ls", "response": {"r": "a"}}},
                {"functionResponse": {"name": "cat", "response": {"r": "x"}}},
            ]},
            {"role": "user", "parts": [{"text": "and?"}]},
        ]});
        let edit_cat = |m: &mut Vec<RhaiMessage>| {
            let calls = &mut m.iter_mut().find(|m| !m.tool_calls.is_empty()).unwrap().tool_calls;
            assert!(calls.iter().all(|c| !c.id.is_empty()), "the script sees an id on every call");
            calls[1].arguments_json = r#"{"f":"b"}"#.to_string();
        };
        let want_model = serde_json::json!({"role": "model", "parts": [
            {"functionCall": {"name": "ls", "args": {"p": "."}}, "thoughtSignature": "SIG"},
            {"functionCall": {"name": "cat", "args": {"f": "b"}}},
        ]});

        let (out, changes) = messages_edit(ApiVersion::GoogleGemini, body.clone(), edit_cat);
        assert!(!changes.is_empty());
        assert_eq!(out["contents"][1], want_model);
        assert_eq!(out["contents"][2], body["contents"][2]);

        // Reshaped as well, the edited turn is kept whole and edited in place.
        let (out, changes) = messages_edit(ApiVersion::GoogleGemini, body.clone(), |m| {
            edit_cat(m);
            m.pop();
        });
        assert!(changes.contains(&"messages".to_string()), "{changes:?}");
        assert_eq!(out["contents"], serde_json::json!([body["contents"][0], want_model, body["contents"][2]]));
    }

    /// A Codex-shaped Responses input — reasoning and a shell call joined to
    /// the assistant message before them — pairs with what the script read:
    /// an edit lands, and a script that drops a message keeps the rest.
    #[test]
    fn a_responses_edit_lands_beside_reasoning_and_shell_items() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "run it"}]},
            {"type": "reasoning", "id": "rs_1", "summary": []},
            {"type": "local_shell_call", "id": "ls_1", "call_id": "s1", "status": "completed", "action": {"type": "exec", "command": ["ls"]}},
            {"type": "local_shell_call_output", "id": "s1", "output": "a.txt"},
            {"type": "message", "role": "user", "content": [{"type": "input_text", "text": "a@b.com"}]},
        ]});
        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            let at = m.iter().position(|m| m.content == "a@b.com").unwrap();
            m[at].content = "[email]".to_string();
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
        let mut want = body["input"].clone();
        want[4]["content"][0]["text"] = Value::from("[email]");
        assert_eq!(out["input"], want);

        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            m.remove(0);
        });
        assert!(changes.contains(&"messages".to_string()), "{changes:?}");
        let input = body["input"].as_array().unwrap();
        assert_eq!(out["input"], serde_json::json!([input[1], input[2], input[3], input[4]]));
    }

    /// A script that keeps the count but moves messages (a sliding window: the
    /// first dropped, one added) is rebuilt, never written over the messages
    /// that stood there: a call stays on its assistant turn, a result on its.
    #[test]
    fn a_sliding_window_of_the_same_length_moves_no_text_onto_another_message() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": [{"type": "text", "text": "b"}, {"type": "tool_use", "id": "c1", "name": "ls", "input": {}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "out"}]},
            {"role": "assistant", "content": "done"},
        ]});
        let (out, _) = messages_edit(ApiVersion::AnthropicMessages, body.clone(), |m| {
            m.remove(0);
            m.push(RhaiMessage { role: "user".to_string(), content: "next".to_string(), ..Default::default() });
        });
        let msgs = body["messages"].as_array().unwrap();
        assert_eq!(
            out["messages"],
            serde_json::json!([msgs[1], msgs[2], msgs[3], {"role": "user", "content": "next"}])
        );
    }

    /// Text a script gives a Responses assistant message read only from call
    /// items has no item to go in: it is named not applied, and the items stay
    /// as sent. Control: the call's own edit lands.
    #[test]
    fn text_for_a_responses_call_only_message_is_named_not_applied() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": "go"},
            {"type": "function_call", "call_id": "c1", "name": "ls", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": "a"},
        ]});
        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            m[1].content = "Running ls".to_string();
        });
        assert_eq!(changes, ["message_1_not_applied"]);
        assert_eq!(out["input"], body["input"]);

        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            m[1].tool_calls[0].arguments_json = r#"{"p":"/"}"#.to_string();
        });
        assert_eq!(changes, ["message_1_tool_calls"]);
        assert_eq!(out["input"][1]["arguments"], Value::from(r#"{"p":"/"}"#));
    }

    /// Calls a script adds without ids are numbered by their place, as a
    /// rebuilt message's are — never two with one id.
    #[test]
    fn calls_a_script_adds_without_ids_get_distinct_ids() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "ok"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body, |m| {
            let call = |name: &str| RhaiToolCall { id: String::new(), name: name.to_string(), arguments_json: "{}".to_string() };
            m[1].tool_calls = vec![call("ls"), call("cat")];
        });
        let ids: Vec<&Value> = out["messages"][1]["tool_calls"].as_array().unwrap().iter().map(|c| &c["id"]).collect();
        assert_eq!(ids, [&Value::from("call_0"), &Value::from("call_1")]);
    }

    /// Gemini ids on a rebuild: a call the client named keeps its id even
    /// where the response answering it has none, and a call sent with an
    /// empty id is not written back with a made-up one.
    #[test]
    fn a_gemini_rebuild_keeps_the_clients_call_ids_and_makes_up_none() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"contents": [
            {"role": "user", "parts": [{"text": "go"}]},
            {"role": "model", "parts": [
                {"text": "calling"},
                {"functionCall": {"id": "abc", "name": "ls", "args": {}}},
                {"functionCall": {"id": "", "name": "cat", "args": {}}},
            ]},
            {"role": "user", "parts": [
                {"functionResponse": {"name": "ls", "response": {"r": "a"}}},
                {"functionResponse": {"name": "cat", "response": {"r": "b"}}},
            ]},
        ]});
        let (out, changes) = messages_edit(ApiVersion::GoogleGemini, body.clone(), |m| {
            m.remove(0);
            let at = m.iter().position(|m| m.content == "calling").unwrap();
            m[at].content = "CALLING".to_string();
            m[at].tool_calls[1].arguments_json = r#"{"f":"x"}"#.to_string();
        });
        assert!(changes.contains(&"messages".to_string()), "{changes:?}");
        let parts = &out["contents"][0]["parts"];
        assert_eq!(parts[0], serde_json::json!({"text": "CALLING"}));
        assert_eq!(parts[1]["functionCall"]["id"], Value::from("abc"));
        assert_eq!(parts[2]["functionCall"].get("id"), None, "{parts}");
        assert_eq!(out["contents"][1], body["contents"][2]);
    }

    /// A Responses call a script writes to a custom (freeform) tool is a
    /// custom call with its free text, and the output answering it a custom
    /// call's output.
    #[test]
    fn a_rebuilt_responses_call_to_a_custom_tool_stays_custom() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m",
            "tools": [{"type": "custom", "name": "apply_patch"}],
            "input": [
                {"type": "message", "role": "user", "content": "first"},
                {"type": "message", "role": "user", "content": "patch it"},
            ]});
        let (out, _) = messages_edit(ApiVersion::Responses, body, |m| {
            m.remove(0);
            m.push(RhaiMessage {
                role: "assistant".to_string(),
                tool_calls: vec![RhaiToolCall { id: "p1".to_string(), name: "apply_patch".to_string(), arguments_json: r#"{"input":"*** Begin"}"#.to_string() }],
                ..Default::default()
            });
            m.push(RhaiMessage { role: "tool".to_string(), content: "done".to_string(), tool_call_id: Some("p1".to_string()), ..Default::default() });
        });
        let input = out["input"].as_array().unwrap();
        assert_eq!(input[1]["type"], Value::from("custom_tool_call"), "{input:?}");
        assert_eq!(input[1]["input"], Value::from("*** Begin"));
        assert_eq!(input[2]["type"], Value::from("custom_tool_call_output"));
    }

    /// Messages of the same roles shifted by a script (two dropped at the
    /// front, two added at the end) keep their own items: no text lands on
    /// another message's image or name.
    #[test]
    fn a_shift_of_same_role_messages_writes_no_text_over_another() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "name": "bob", "content": [
                {"type": "text", "text": "a"},
                {"type": "image_url", "image_url": {"url": "https://x/i.png"}},
            ]},
            {"role": "assistant", "content": "b"},
            {"role": "user", "content": "c"},
            {"role": "assistant", "content": "d"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m.drain(0..2);
            for (role, text) in [("user", "e"), ("assistant", "f")] {
                m.push(RhaiMessage { role: role.to_string(), content: text.to_string(), ..Default::default() });
            }
        });
        assert_eq!(out["messages"], serde_json::json!([
            body["messages"][2], body["messages"][3],
            {"role": "user", "content": "e"}, {"role": "assistant", "content": "f"},
        ]));
    }

    /// An item the script could not see goes with the item after it: kept
    /// when that item is kept, edited or not.
    #[test]
    fn an_unseen_item_goes_with_the_item_after_it() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": "", "audio": {"id": "au_1"}},
            {"role": "user", "content": "b"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m.remove(0);
            m[0].content = "B".to_string();
        });
        assert_eq!(out["messages"], serde_json::json!([body["messages"][1], {"role": "user", "content": "B"}]));
    }

    /// A message is the message it was read as once: a copy the script makes
    /// is a new message, and so is one whose role it changed.
    #[test]
    fn a_copy_or_a_changed_role_is_a_new_message() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "name": "bob", "content": "hi"},
            {"role": "assistant", "content": "yo"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            let copy = m[0].clone();
            m.push(copy);
            m[1].role = "user".to_string();
        });
        assert_eq!(out["messages"], serde_json::json!([
            body["messages"][0],
            {"role": "user", "content": "yo"},
            {"role": "user", "content": "hi"},
        ]));
    }

    /// A call edited in place keeps its place among the turn's parts: text
    /// and calls stay in the order sent, so results paired by position still
    /// answer their own call; the id the gateway made up for it is not
    /// written.
    #[test]
    fn an_edited_call_keeps_its_place_in_the_turn() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [
                {"type": "text", "text": "first"},
                {"type": "tool_use", "id": "A", "name": "ls", "input": {}},
                {"type": "text", "text": "then"},
                {"type": "tool_use", "id": "B", "name": "cat", "input": {}},
            ]},
        ]});
        let (out, _) = messages_edit(ApiVersion::AnthropicMessages, body.clone(), |m| {
            m[1].tool_calls[0].arguments_json = r#"{"p":"/"}"#.to_string();
        });
        let mut want = body["messages"][1].clone();
        want["content"][1]["input"] = serde_json::json!({"p": "/"});
        assert_eq!(out["messages"][1], want);

        let gemini = serde_json::json!({"contents": [
            {"role": "user", "parts": [{"text": "go"}]},
            {"role": "model", "parts": [
                {"functionCall": {"name": "f", "args": {"n": 1}}},
                {"functionCall": {"name": "f", "args": {"n": 2}}},
            ]},
            {"role": "user", "parts": [
                {"functionResponse": {"name": "f", "response": {"r": 1}}},
                {"functionResponse": {"name": "f", "response": {"r": 2}}},
            ]},
        ]});
        let (out, _) = messages_edit(ApiVersion::GoogleGemini, gemini.clone(), |m| {
            m[1].tool_calls[0].arguments_json = r#"{"n":10}"#.to_string();
        });
        assert_eq!(out["contents"][1]["parts"], serde_json::json!([
            {"functionCall": {"name": "f", "args": {"n": 10}}},
            {"functionCall": {"name": "f", "args": {"n": 2}}},
        ]));
        assert_eq!(out["contents"][2], gemini["contents"][2]);
    }

    /// A Responses freeform call's edit lands in its `input`.
    #[test]
    fn a_responses_custom_calls_edit_lands_in_its_input() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "tools": [{"type": "custom", "name": "apply_patch"}], "input": [
            {"type": "message", "role": "user", "content": "go"},
            {"type": "custom_tool_call", "call_id": "p1", "name": "apply_patch", "input": "old"},
        ]});
        let (out, changes) = messages_edit(ApiVersion::Responses, body, |m| {
            m[1].tool_calls[0].arguments_json = r#"{"input":"new"}"#.to_string();
        });
        assert_eq!(changes, ["message_1_tool_calls"]);
        assert_eq!(out["input"][1]["input"], Value::from("new"));
    }

    /// An item the script could not see at the end stays right after the item
    /// before it, ahead of a message the script appends.
    #[test]
    fn a_trailing_unseen_item_stays_ahead_of_an_appended_message() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "a"},
            {"role": "assistant", "content": "", "audio": {"id": "au_1"}},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m.push(RhaiMessage { role: "user".to_string(), content: "b".to_string(), ..Default::default() });
        });
        assert_eq!(out["messages"], serde_json::json!([body["messages"][0], body["messages"][1], {"role": "user", "content": "b"}]));
    }

    /// Emptying the first conversation message while adding one moves
    /// nothing into the system prompt's lead: no message is sent twice.
    #[test]
    fn emptying_the_first_message_sends_no_message_twice() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "system", "content": "S"},
            {"role": "user", "content": [{"type": "text", "text": "secret"}]},
            {"role": "system", "content": "S2"},
            {"role": "assistant", "content": "A"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m[0].content = String::new();
            m.push(RhaiMessage { role: "user".to_string(), content: "note".to_string(), ..Default::default() });
        });
        assert_eq!(out["messages"], serde_json::json!([
            body["messages"][0],
            {"role": "user", "content": [{"type": "text", "text": ""}]},
            body["messages"][2],
            body["messages"][3],
            {"role": "user", "content": "note"},
        ]));
    }

    /// An unseen item at the end stays when the script drops the item before
    /// it: it closes the conversation.
    #[test]
    fn a_trailing_unseen_item_stays_when_the_item_before_it_goes() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "a"},
            {"role": "user", "content": "b"},
            {"role": "assistant", "content": "", "audio": {"id": "au_1"}},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m.pop();
        });
        assert_eq!(out["messages"], serde_json::json!([body["messages"][0], body["messages"][2]]));
    }

    /// A Chat call the script could not see (neither a function nor a custom
    /// call) is never dropped by an edit of the calls beside it: the edit is
    /// named not applied and the calls stay as sent.
    #[test]
    fn a_call_the_script_cannot_see_stays_and_the_edit_is_named() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "ok", "tool_calls": [
                {"id": "c1", "type": "function", "function": {"name": "ls", "arguments": "{}"}},
                {"id": "x1", "type": "browser"},
            ]},
        ]});
        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m[1].tool_calls[0].arguments_json = r#"{"p":"/"}"#.to_string();
        });
        assert_eq!(changes, ["message_1_tool_calls_not_applied"]);
        assert_eq!(out["messages"], body["messages"]);
    }

    /// A message the script copies to an earlier place keeps its own item
    /// where it was; the copy is a new message.
    #[test]
    fn a_copy_placed_earlier_leaves_the_original_in_place() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "a"},
            {"role": "user", "name": "bob", "content": "rule"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            let mut copy = m[1].clone();
            copy.content = "rule (repeated)".to_string();
            m.insert(0, copy);
        });
        assert_eq!(out["messages"], serde_json::json!([
            {"role": "user", "content": "rule (repeated)"}, body["messages"][0], body["messages"][1],
        ]));
    }

    /// A message the script builds in place of one it removed is a new
    /// message: the removed one's image and `name` do not come back with it.
    #[test]
    fn a_replacement_message_takes_nothing_from_the_one_removed() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "name": "bob", "content": [
                {"type": "text", "text": "x"},
                {"type": "image_url", "image_url": {"url": "https://x/i.png"}},
            ]},
            {"role": "assistant", "content": "y"},
        ]});
        let (out, _) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m.remove(0);
            m.insert(0, RhaiMessage { role: "user".to_string(), content: "[image removed]".to_string(), ..Default::default() });
        });
        assert_eq!(out["messages"], serde_json::json!([{"role": "user", "content": "[image removed]"}, body["messages"][1]]));
    }

    /// A reshaped conversation keeps every turn whose messages the script
    /// kept whole, edited in place: the result beside the edited text keeps
    /// its image, error flag and breakpoint.
    #[test]
    fn a_whole_turn_in_a_reshaped_conversation_is_edited_in_place() {
        use crate::api::sse::ApiVersion;
        let result = serde_json::json!({"type": "tool_result", "tool_use_id": "c1", "is_error": true,
            "cache_control": {"type": "ephemeral"}, "content": [
                {"type": "text", "text": "shot"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}},
            ]});
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "start"},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "shot", "input": {}}]},
            {"role": "user", "content": [result, {"type": "text", "text": "mail a@b.com"}]},
        ]});
        let (out, changes) = messages_edit(ApiVersion::AnthropicMessages, body.clone(), |m| {
            m.remove(0);
            let at = m.iter().position(|m| m.content == "mail a@b.com").unwrap();
            m[at].content = "mail [email]".to_string();
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
        let mut want = body["messages"][2].clone();
        want["content"][1]["text"] = Value::from("mail [email]");
        assert_eq!(out["messages"], serde_json::json!([body["messages"][1], want]));
    }

    /// A turn the script reshapes that holds nothing it cannot see is
    /// rebuilt as the script wrote it, unnamed: two results swapped go in
    /// the new order.
    #[test]
    fn a_reorder_within_a_turn_of_plain_results_is_written() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "a", "name": "ls", "input": {}},
                {"type": "tool_use", "id": "b", "name": "ls", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "a", "content": "1"},
                {"type": "tool_result", "tool_use_id": "b", "content": "2"},
            ]},
        ]});
        let (out, changes) = messages_edit(ApiVersion::AnthropicMessages, body.clone(), |m| {
            m.swap(1, 2);
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
        assert_eq!(out["messages"], serde_json::json!([body["messages"][0], {"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "b", "content": "2"},
            {"type": "tool_result", "tool_use_id": "a", "content": "1"},
        ]}]));
    }

    /// A call dropped from a thinking turn, with its result: the turn keeps
    /// its thinking and the other call, edited in place, and the results'
    /// turn the script split is rebuilt from what it kept.
    #[test]
    fn dropping_a_call_keeps_the_turns_thinking() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "plan", "signature": "SIG"},
                {"type": "tool_use", "id": "c1", "name": "ls", "input": {}},
                {"type": "tool_use", "id": "c2", "name": "cat", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "c1", "content": "a"},
                {"type": "tool_result", "tool_use_id": "c2", "content": "b"},
            ]},
        ]});
        let (out, changes) = messages_edit(ApiVersion::AnthropicMessages, body.clone(), |m| {
            let turn = m.iter().position(|m| m.tool_calls.len() == 2).unwrap();
            m[turn].tool_calls.retain(|c| c.id == "c1");
            m.retain(|m| m.tool_call_id.as_deref() != Some("c2"));
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
        assert_eq!(out["messages"], serde_json::json!([
            body["messages"][0],
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": "plan", "signature": "SIG"},
                {"type": "tool_use", "id": "c1", "name": "ls", "input": {}},
            ]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "content": "a"}]},
        ]));
    }

    /// A map the script built (no `origin`) is a new message, even in place
    /// of the one it was made from: the script replaced the message, so the
    /// conversation is sent as it wrote it, nothing named. Control: the same
    /// edit made on the map itself lands in place, the image kept.
    #[test]
    fn a_map_without_an_origin_is_a_new_message() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": [
                {"type": "text", "text": "a@b.com"},
                {"type": "image_url", "image_url": {"url": "https://x/i.png"}},
            ]},
            {"role": "assistant", "content": "ok"},
        ]});
        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            *m = m
                .iter()
                .map(|m| RhaiMessage { role: m.role.clone(), content: m.content.replace("a@b.com", "[email]"), ..Default::default() })
                .collect();
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
        assert_eq!(out["messages"], serde_json::json!([{"role": "user", "content": "[email]"}, {"role": "assistant", "content": "ok"}]));

        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m[0].content = m[0].content.replace("a@b.com", "[email]");
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
        let mut want = body["messages"].clone();
        want[0]["content"][0]["text"] = Value::from("[email]");
        assert_eq!(out["messages"], want);
    }

    /// A Responses reasoning item goes with the item after it: a script that
    /// drops the assistant message after it never leaves the reasoning item
    /// without what must follow it — the turn is rebuilt from what the
    /// script kept, and the reasoning it could not see is named.
    #[test]
    fn a_reasoning_item_goes_with_the_message_after_it() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": "q"},
            {"type": "reasoning", "id": "rs_1", "summary": []},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "secret"}]},
            {"type": "message", "role": "user", "content": "next"},
        ]});
        let (out, changes) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            m.retain(|m| !m.content.contains("secret"));
        });
        assert!(changes.iter().any(|c| c.ends_with("_not_applied")), "{changes:?}");
        let input = out["input"].as_array().unwrap();
        assert!(input.iter().all(|i| i["type"] != "reasoning"), "{input:?}");
        assert_eq!(input.first(), Some(&body["input"][0]));
        assert_eq!(input.last(), Some(&body["input"][3]));
    }

    /// A Gemini response rebuilt after the script dropped the call it answers
    /// is still named by its function, as the client sent it.
    #[test]
    fn a_rebuilt_gemini_response_keeps_its_functions_name() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"contents": [
            {"role": "user", "parts": [{"text": "go"}]},
            {"role": "model", "parts": [{"functionCall": {"id": "fc_9", "name": "search", "args": {}}}]},
            {"role": "user", "parts": [{"functionResponse": {"id": "fc_9", "name": "search", "response": {"r": "a@b.com"}}}]},
        ]});
        let (out, _) = messages_edit(ApiVersion::GoogleGemini, body, |m| {
            m.remove(1);
            let at = m.iter().position(|m| m.role == "tool").unwrap();
            m[at].content = r#"{"r":"[email]"}"#.to_string();
        });
        let response = &out["contents"][1]["parts"][0]["functionResponse"];
        assert_eq!(response["name"], Value::from("search"), "{out}");
        assert_eq!(response["id"], Value::from("fc_9"));
    }

    /// The seeded compression script keeps the last user message's own map,
    /// so the compressed prompt goes with that message's image.
    #[test]
    fn the_compression_seed_keeps_the_last_user_messages_image() {
        use crate::api::sse::ApiVersion;
        use crate::scripting::{ScriptEngine, ScriptFailMode, TransformProgram};
        let body = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "old ".repeat(200)},
            {"role": "assistant", "content": "a"},
            {"role": "user", "content": [
                {"type": "text", "text": "now"},
                {"type": "image_url", "image_url": {"url": "https://x/i.png"}},
            ]},
        ]});
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(body.to_string())).unwrap();
        let ctx = from_api_request(&req, &test_user(), None, Some(100), None, false, &no_subs());
        let program = TransformProgram {
            id: "compression".to_string(),
            name: "compression".to_string(),
            source: include_str!("../../../../seeds/scripts/compression.rhai").to_string(),
            phase: "request".to_string(),
            scope: "global".to_string(),
            priority: 900,
            enabled: true,
            version_hash: "v1".to_string(),
            model_filter: None,
            app_filter: None,
            trigger_regex: None,
            match_mode: None,
            profile_id: None,
        };
        let (result, ..) =
            ScriptEngine::new().execute_chain(&[program], ctx, false, None, ScriptFailMode::Open).unwrap();
        assert_eq!(result.metadata.get("compression").map(String::as_str), Some("applied"));
        apply_to_api_request(&result, &mut req, ChangedFields { system_prompt: false, messages: true, tools: false });
        let ApiRequest::ChatCompletions(chat) = &req else { unreachable!() };
        let out = serde_json::to_value(&chat.messages).unwrap();
        assert_eq!(out.as_array().unwrap().len(), 1, "{out}");
        let parts = &out[0]["content"];
        assert!(parts.to_string().contains("https://x/i.png"), "{out}");
        assert!(parts[0]["text"].as_str().is_some_and(|t| t.contains("old") && t.ends_with("now")), "{out}");
    }

    /// A Responses call joined to the assistant message before it across an
    /// item that reads as nothing is one turn with it: dropping the message
    /// drops the call too, never leaving it behind.
    #[test]
    fn a_call_joined_across_an_empty_item_goes_with_its_message() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": "q"},
            {"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": "x"}]},
            {"type": "message", "role": "user", "content": []},
            {"type": "function_call", "call_id": "c1", "name": "ls", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": "a"},
            {"type": "message", "role": "user", "content": "next"},
        ]});
        let (out, _) = messages_edit(ApiVersion::Responses, body.clone(), |m| {
            m.retain(|m| m.role != "assistant");
        });
        let input = out["input"].as_array().unwrap();
        assert!(input.iter().all(|i| i["type"] != "function_call"), "{input:?}");
        assert_eq!(input.first(), Some(&body["input"][0]));
        assert_eq!(input.last(), Some(&body["input"][5]));
    }

    /// A Responses call the script writes without an id is named by its
    /// place (its message's, then its own), never sent with an empty one.
    #[test]
    fn a_responses_call_without_an_id_gets_one() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "input": [{"type": "message", "role": "user", "content": "q"}]});
        let (out, _) = messages_edit(ApiVersion::Responses, body, |m| {
            m.push(RhaiMessage {
                role: "assistant".to_string(),
                tool_calls: vec![RhaiToolCall { id: String::new(), name: "ls".to_string(), arguments_json: "{}".to_string() }],
                ..Default::default()
            });
        });
        let call = out["input"].as_array().unwrap().iter().find(|i| i["type"] == "function_call").cloned();
        assert_eq!(call.map(|c| c["call_id"].clone()), Some(Value::from("call_1_0")), "{out}");
    }

    /// A rebuilt Responses turn whose item carried a member the rebuild
    /// drops (`phase`) is named not applied; a Chat member that carries
    /// nothing (`refusal: null`) is no loss.
    #[test]
    fn a_rebuild_names_a_lost_member_and_not_an_empty_one() {
        use crate::api::sse::ApiVersion;
        let responses = serde_json::json!({"model": "m", "input": [
            {"type": "message", "role": "user", "content": "q"},
            {"type": "message", "role": "assistant", "phase": "final_answer", "content": [{"type": "output_text", "text": "a"}]},
            {"type": "function_call", "call_id": "c1", "name": "ls", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": "x"},
        ]});
        let parse = |v: Value| ApiRequest::parse(ApiVersion::Responses, &Bytes::from(v.to_string())).unwrap();
        assert!(turn_holds_unseen(&parse(responses.clone()), &[1]));
        let mut plain = responses;
        plain["input"][1].as_object_mut().unwrap().remove("phase");
        assert!(!turn_holds_unseen(&parse(plain), &[1]));

        let chat = serde_json::json!({"model": "m", "messages": [
            {"role": "user", "content": "q"},
            {"role": "assistant", "content": "a", "refusal": null},
            {"role": "user", "content": "b"},
        ]});
        let (_, changes) = messages_edit(ApiVersion::ChatCompletions, chat, |m| {
            m.remove(0);
            m[0].content = "A".to_string();
            m.swap(0, 1);
        });
        assert!(changes.iter().all(|c| !c.ends_with("_not_applied")), "{changes:?}");
    }

    /// An edited Anthropic call keeps its breakpoint.
    #[test]
    fn an_edited_call_keeps_its_breakpoint() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "c1", "name": "ls", "input": {}, "cache_control": {"type": "ephemeral"}},
            ]},
        ]});
        let (out, _) = messages_edit(ApiVersion::AnthropicMessages, body, |m| {
            m[1].tool_calls[0].arguments_json = r#"{"p":"/"}"#.to_string();
        });
        assert_eq!(out["messages"][1]["content"][0]["cache_control"], serde_json::json!({"type": "ephemeral"}), "{out}");
        assert_eq!(out["messages"][1]["content"][0]["input"], serde_json::json!({"p": "/"}));
    }

    /// An item after every turn follows the last turn read whole, even when
    /// that turn is rebuilt: never between its messages.
    #[test]
    fn a_trailing_unseen_item_follows_a_rebuilt_last_turn_whole() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": [
                {"type": "tool_use", "id": "a", "name": "ls", "input": {}},
                {"type": "tool_use", "id": "b", "name": "ls", "input": {}},
            ]},
            {"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "a", "content": "1"},
                {"type": "tool_result", "tool_use_id": "b", "content": "2"},
                {"type": "text", "text": "more"},
            ]},
            {"role": "assistant", "content": []},
        ]});
        let (out, _) = messages_edit(ApiVersion::AnthropicMessages, body.clone(), |m| {
            m.retain(|m| m.tool_call_id.as_deref() != Some("a"));
        });
        let msgs = out["messages"].as_array().unwrap();
        assert_eq!(msgs.last(), Some(&body["messages"][3]), "{out}");
        assert_eq!(msgs.iter().filter(|m| m["content"] == serde_json::json!([])).count(), 1, "{out}");
    }

    /// Calls a script gives a message that is not an assistant's have no place
    /// on the wire: named not applied, the message as sent.
    #[test]
    fn calls_on_a_user_message_are_named_not_applied() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "go"}]});
        let (out, changes) = messages_edit(ApiVersion::ChatCompletions, body.clone(), |m| {
            m[0].tool_calls = vec![RhaiToolCall { id: "c1".to_string(), name: "ls".to_string(), arguments_json: "{}".to_string() }];
        });
        assert_eq!(changes, ["message_0_tool_calls_not_applied"]);
        assert_eq!(out["messages"], body["messages"]);
    }

    /// An Anthropic call the script adds without an id is named by its place,
    /// never sent with an empty one.
    #[test]
    fn an_anthropic_call_without_an_id_gets_one() {
        use crate::api::sse::ApiVersion;
        let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
            {"role": "user", "content": "go"},
            {"role": "assistant", "content": "ok"},
        ]});
        let (out, _) = messages_edit(ApiVersion::AnthropicMessages, body, |m| {
            m[1].tool_calls = vec![RhaiToolCall { id: String::new(), name: "ls".to_string(), arguments_json: "{}".to_string() }];
        });
        let call = out["messages"][1]["content"].as_array().unwrap().iter().find(|b| b["type"] == "tool_use").cloned();
        assert_eq!(call.map(|c| c["id"].clone()), Some(Value::from("call_0")), "{out}");
    }

    /// A turn whose Anthropic result or Gemini response carries a member a
    /// rebuild drops holds something the script cannot see; without it, not.
    #[test]
    fn anthropic_and_gemini_members_a_rebuild_drops_are_seen_as_lost() {
        use crate::api::sse::ApiVersion;
        let anthropic = |extra: bool| {
            let mut result = serde_json::json!({"type": "tool_result", "tool_use_id": "c1", "content": "a"});
            if extra {
                result["toolset_name"] = Value::from("files");
            }
            let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
                {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "ls", "input": {}}]},
                {"role": "user", "content": [result]},
            ]});
            ApiRequest::parse(ApiVersion::AnthropicMessages, &Bytes::from(body.to_string())).unwrap()
        };
        assert!(turn_holds_unseen(&anthropic(true), &[1]));
        assert!(!turn_holds_unseen(&anthropic(false), &[1]));
        // A call's `caller` from inside code execution, and a text's
        // citations, a rebuild drops too; a call's default caller loses nothing.
        let assistant = |block: Value| {
            let body = serde_json::json!({"model": "m", "max_tokens": 1, "messages": [
                {"role": "user", "content": "go"},
                {"role": "assistant", "content": [block]},
            ]});
            ApiRequest::parse(ApiVersion::AnthropicMessages, &Bytes::from(body.to_string())).unwrap()
        };
        let call = |caller: Value| serde_json::json!({"type": "tool_use", "id": "c1", "name": "ls", "input": {}, "caller": caller});
        assert!(turn_holds_unseen(&assistant(call(serde_json::json!({"type": "code_execution_20250825", "tool_id": "srvtoolu_1"}))), &[1]));
        assert!(!turn_holds_unseen(&assistant(call(serde_json::json!({"type": "direct"}))), &[1]));
        let cited = serde_json::json!({"type": "text", "text": "a", "citations": [{"type": "char_location", "cited_text": "a",
            "document_index": 0, "document_title": null, "start_char_index": 0, "end_char_index": 1}]});
        assert!(turn_holds_unseen(&assistant(cited), &[1]));
        assert!(!turn_holds_unseen(&assistant(serde_json::json!({"type": "text", "text": "a", "citations": null})), &[1]));
        let gemini = |extra: bool| {
            let mut response = serde_json::json!({"name": "ls", "response": {"r": "a"}});
            if extra {
                response["willContinue"] = Value::from(true);
            }
            let body = serde_json::json!({"contents": [
                {"role": "model", "parts": [{"functionCall": {"name": "ls", "args": {}}}]},
                {"role": "user", "parts": [{"functionResponse": response}]},
            ]});
            ApiRequest::parse(ApiVersion::GoogleGemini, &Bytes::from(body.to_string())).unwrap()
        };
        assert!(turn_holds_unseen(&gemini(true), &[1]));
        assert!(!turn_holds_unseen(&gemini(false), &[1]));
    }

    #[test]
    fn a_chat_completions_system_prompt_write_replaces_the_whole_lead() {
        let json = r#"{"model":"gpt-4o","messages":[{"role":"developer","content":"Be brief"},{"role":"system","content":"Be kind"},{"role":"user","content":"Hello"}]}"#;
        let parse = || ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(json)).unwrap();
        let texts = |req: &ApiRequest| -> Vec<(String, String)> {
            let ApiRequest::ChatCompletions(chat) = req else { panic!("chat") };
            chat.messages.iter().map(|m| (m.role.clone(), chat_msg_text(m))).collect()
        };
        let pair = |r: &str, t: &str| (r.to_string(), t.to_string());
        let prompt = ChangedFields { system_prompt: true, messages: false, tools: false };

        // A prefix lands once, in one message keeping the first lead's role.
        let mut req = parse();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        assert_eq!(ctx.system_prompt.as_deref(), Some("Be brief\n\nBe kind"));
        ctx.system_prompt = Some(format!("W. {}", ctx.system_prompt.as_deref().unwrap_or_default()));
        assert_eq!(apply_to_api_request(&ctx, &mut req, prompt), ["system_prompt"]);
        assert_eq!(texts(&req), [pair("developer", "W. Be brief\n\nBe kind"), pair("user", "Hello")]);

        // A removal drops the whole lead.
        let mut req = parse();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        ctx.system_prompt = None;
        assert_eq!(apply_to_api_request(&ctx, &mut req, prompt), ["system_prompt_removed"]);
        assert_eq!(texts(&req), [pair("user", "Hello")]);

        // With no lead, a prompt is a new system message in front.
        let bare = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Hello"}]}"#;
        let mut req = ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(bare)).unwrap();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        ctx.system_prompt = Some("W.".to_string());
        assert_eq!(apply_to_api_request(&ctx, &mut req, prompt), ["system_prompt"]);
        assert_eq!(texts(&req), [pair("system", "W."), pair("user", "Hello")]);

        // The run's first message stays, its own fields kept.
        let named = r#"{"model":"gpt-4o","messages":[{"role":"system","name":"policy","content":"S"},{"role":"user","content":"Hi"}]}"#;
        let mut req = ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(named)).unwrap();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        ctx.system_prompt = Some("X".to_string());
        apply_to_api_request(&ctx, &mut req, prompt);
        let ApiRequest::ChatCompletions(chat) = &req else { panic!("chat") };
        assert_eq!(chat.messages[0].name.as_deref(), Some("policy"));
        assert_eq!(texts(&req), [pair("system", "X"), pair("user", "Hi")]);

        // Control: a prompt the script left as it read it is not written.
        let mut req = parse();
        let ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        let unchanged = ChangedFields { system_prompt: false, messages: false, tools: false };
        assert!(apply_to_api_request(&ctx, &mut req, unchanged).is_empty());
        assert_eq!(texts(&req), texts(&parse()));
    }

    /// A Gemini system instruction's text is what a script reads — every text
    /// part, a `thought: false` one too — and its prompt is the whole
    /// instruction: an edit replaces every part, a removal drops it, and a
    /// prompt read back unchanged is not written, however many parts hold it.
    #[test]
    fn a_gemini_system_prompt_is_read_and_written_as_its_text() {
        let body = r#"{"systemInstruction":{"parts":[{"text":"A"},{"inlineData":{"mimeType":"image/png","data":"iVBO"}},{"thought":false,"text":"B"}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;
        let parse = || ApiRequest::parse(crate::api::sse::ApiVersion::GoogleGemini, &Bytes::from(body)).unwrap();
        let prompt = ChangedFields { system_prompt: true, messages: false, tools: false };

        let mut req = parse();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        assert_eq!(ctx.system_prompt.as_deref(), Some("A\nB"));
        assert!(apply_to_api_request(&ctx, &mut req, prompt).is_empty());
        assert_eq!(req.wire_value(), parse().wire_value());

        ctx.system_prompt = Some("C".to_string());
        assert_eq!(apply_to_api_request(&ctx, &mut req, prompt), ["system_prompt"]);
        assert_eq!(req.wire_value().unwrap()["systemInstruction"], serde_json::json!({"parts": [{"text": "C"}]}));

        // A prompt cut to its first part is an edit too.
        let mut req = parse();
        ctx.system_prompt = Some("A".to_string());
        assert_eq!(apply_to_api_request(&ctx, &mut req, prompt), ["system_prompt"]);
        assert_eq!(req.wire_value().unwrap()["systemInstruction"], serde_json::json!({"parts": [{"text": "A"}]}));

        for body in [body, r#"{"systemInstruction":{"parts":[{"text":""}]},"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#] {
            let mut req = ApiRequest::parse(crate::api::sse::ApiVersion::GoogleGemini, &Bytes::from(body)).unwrap();
            ctx.system_prompt = None;
            assert_eq!(apply_to_api_request(&ctx, &mut req, prompt), ["system_prompt_removed"], "{body}");
            assert!(req.wire_value().unwrap().get("systemInstruction").is_none());
        }
    }

    #[test]
    fn roundtrip_anthropic_messages() {
        let json = r#"{"model":"claude-3","max_tokens":1024,"system":"Be helpful","messages":[{"role":"user","content":"Hello"}]}"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, Some("anthropic"), true, &no_subs());

        assert_eq!(ctx.system_prompt.as_deref(), Some("Be helpful"));
        assert_eq!(ctx.messages.len(), 1);
        assert_eq!(ctx.api_version, "anthropic_messages");
        assert_eq!(ctx.metadata.get("needs_translation").unwrap(), "true");

        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(changes.is_empty()); // no changes
    }

    #[test]
    fn multiblock_anthropic_system_prompt_round_trips_without_phantom_change() {
        // A multi-block Anthropic system prompt (the shape Claude Code sends).
        // With no transform touching it, the flat string the scripts see must
        // equal the wire `SystemPrompt::to_text()` exactly — both join blocks
        // with `\n\n`. A separator mismatch made `apply_to_api_request` read an
        // unmodified prompt as changed, flagging a phantom `system_prompt`
        // change and needlessly collapsing the blocks into one.
        let json = r#"{"model":"claude-3","max_tokens":1024,"system":[{"type":"text","text":"You are Claude Code."},{"type":"text","text":"You are an interactive agent."}],"messages":[{"role":"user","content":"Hello"}]}"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let wire_text = match &req {
            ApiRequest::AnthropicMessages(m) => m.system.as_ref().map(|s| s.to_text()),
            _ => None,
        };
        assert_eq!(wire_text.as_deref(), Some("You are Claude Code.\n\nYou are an interactive agent."));

        let ctx =
            from_api_request(&req, &test_user(), None, None, Some("anthropic"), true, &no_subs());
        // The script-visible flat string matches the wire flattening exactly.
        assert_eq!(ctx.system_prompt, wire_text);

        // No transform ran → apply is a no-op; no phantom system_prompt change.
        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(
            !changes.contains(&"system_prompt".to_string()),
            "unmodified multi-block system prompt flagged as changed: {changes:?}"
        );
    }

    #[test]
    fn rhai_tool_is_gateway_substituted_round_trips_through_dynamic() {
        let tool = RhaiTool {
            name: "web_search".to_string(),
            description: Some("Search".to_string()),
            parameters_json: Some(r#"{"type":"object"}"#.to_string()),
            is_gateway_substituted: true, kind: None, config_json: None,
        };
        let dyn_val = tool.to_dynamic();
        let parsed = RhaiTool::from_dynamic(&dyn_val).expect("from_dynamic round-trip");
        assert!(parsed.is_gateway_substituted);
        assert_eq!(parsed.name, "web_search");

        // Unset round-trip
        let plain = RhaiTool {
            name: "weather".to_string(),
            description: None,
            parameters_json: None,
            is_gateway_substituted: false, kind: None, config_json: None,
        };
        let parsed_plain =
            RhaiTool::from_dynamic(&plain.to_dynamic()).expect("from_dynamic round-trip");
        assert!(!parsed_plain.is_gateway_substituted);
    }

    #[test]
    fn from_api_request_marks_substituted_tool_names() {
        // Anthropic request with a server-defined `web_search` tool that the
        // gateway's tool-policy `Substitute` action would rewrite into a
        // function-tool. Simulate that by passing the wire `name` in the
        // `substituted_tool_names` set.
        let json = r#"{
            "model":"claude-3","max_tokens":1024,
            "messages":[{"role":"user","content":"Hi"}],
            "tools":[
                {"name":"web_search","description":"search","input_schema":{"type":"object"}},
                {"name":"weather","description":"weather","input_schema":{"type":"object"}}
            ]
        }"#;
        let body = Bytes::from(json);
        let req = ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();
        let mut subs: std::collections::HashSet<String> = std::collections::HashSet::new();
        subs.insert("web_search".to_string());
        let ctx =
            from_api_request(&req, &test_user(), None, None, Some("openai"), false, &subs);
        let by_name: std::collections::HashMap<&str, &RhaiTool> =
            ctx.tools.iter().map(|t| (t.name.as_str(), t)).collect();
        assert!(by_name["web_search"].is_gateway_substituted);
        assert!(!by_name["weather"].is_gateway_substituted);
    }

    #[test]
    fn roundtrip_responses() {
        let json = r#"{"model":"gpt-4o","input":"Hello","instructions":"Be helpful"}"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::Responses, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());

        assert_eq!(ctx.system_prompt.as_deref(), Some("Be helpful"));
        assert_eq!(ctx.messages.len(), 1);
        assert_eq!(ctx.messages[0].content, "Hello");
        assert_eq!(ctx.api_version, "responses");

        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(changes.is_empty());
    }

    #[test]
    fn tool_removal_applied() {
        let json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hi"}],"tools":[{"type":"function","function":{"name":"web_search","description":"Search"}},{"type":"function","function":{"name":"get_weather","description":"Weather"}}]}"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &body).unwrap();

        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        assert_eq!(ctx.tools.len(), 2);

        // Remove web_search
        ctx.tools.retain(|t| t.name != "web_search");
        assert_eq!(ctx.tools.len(), 1);

        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(changes.contains(&"tools".to_string()));

        if let ApiRequest::ChatCompletions(chat) = &req {
            assert_eq!(chat.tools.as_ref().unwrap().len(), 1);
            assert_eq!(
                chat.tools.as_ref().unwrap()[0]
                    .function
                    .as_ref()
                    .unwrap()
                    .name,
                "get_weather"
            );
        }
    }

    #[test]
    fn dynamic_roundtrip() {
        let ctx = RequestContext {
            system_prompt: Some("test".to_string()),
            messages: vec![RhaiMessage {
                role: "user".to_string(),
                content: "hello".to_string(),
                tool_call_id: None,
                tool_calls: vec![],
                origin: None,
            }],
            tools: vec![RhaiTool {
                name: "search".to_string(),
                description: Some("Search tool".to_string()),
                parameters_json: None,
                is_gateway_substituted: false, kind: None, config_json: None,
            }],
            model: "gpt-4o".to_string(),
            user_id: "user-123".to_string(),
            app_id: Some("app-1".to_string()),
            api_version: "chat_completions".to_string(),
            metadata: [("key".to_string(), "val".to_string())]
                .into_iter()
                .collect(),
            labels: vec!["tag1".to_string(), "tag2".to_string()],
        };

        let dyn_val = ctx.to_dynamic();
        let restored = RequestContext::from_dynamic(&dyn_val).unwrap();

        assert_eq!(restored.system_prompt, ctx.system_prompt);
        assert_eq!(restored.messages.len(), 1);
        assert_eq!(restored.messages[0].content, "hello");
        assert_eq!(restored.tools.len(), 1);
        assert_eq!(restored.tools[0].name, "search");
        assert_eq!(restored.model, "gpt-4o");
        assert_eq!(restored.app_id, Some("app-1".to_string()));
        assert_eq!(restored.metadata.get("key").unwrap(), "val");
        assert_eq!(restored.labels, vec!["tag1", "tag2"]);
    }

    // ── Round-trip preservation tests ──
    // Verify that non-text content survives the transform pipeline when no
    // script modifies messages (the messages are not marked changed).

    #[test]
    fn anthropic_tool_result_preserved_when_messages_unchanged() {
        // Anthropic user message with [ToolResult, Text] — domain conversion splits this
        // into 2 domain messages, causing a count mismatch with the native 1 message.
        // With the messages not marked changed, sync must be skipped entirely.
        let json = r#"{
            "model": "claude-3",
            "max_tokens": 1024,
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "text", "text": "I'll search for that"},
                    {"type": "tool_use", "id": "call_1", "name": "search", "input": {"q": "test"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "call_1", "content": "Found 3 results"},
                    {"type": "text", "text": "What did you find?"}
                ]}
            ]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, Some("anthropic"), false, &no_subs());
        // Domain expansion: assistant(1) + tool(1) + user(1) = 3 Rhai messages from 2 native
        assert!(ctx.messages.len() > 2, "domain should expand ToolResult into separate message");

        // Apply with the messages not marked changed — must NOT corrupt native messages
        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(
            !changes.iter().any(|c| c.starts_with("message")),
            "no message changes expected, got: {changes:?}"
        );

        // Verify native structure is intact
        if let ApiRequest::AnthropicMessages(msg) = &req {
            assert_eq!(msg.messages.len(), 2, "native message count must be unchanged");

            // Assistant message must still have ToolUse block
            match &msg.messages[0].content {
                AnthropicContent::Blocks(blocks) => {
                    assert!(
                        blocks.iter().any(|b| matches!(b, ContentBlock::ToolUse { .. })),
                        "ToolUse block must be preserved"
                    );
                }
                other => panic!("expected Blocks, got {other:?}"),
            }

            // User message must still have ToolResult block
            match &msg.messages[1].content {
                AnthropicContent::Blocks(blocks) => {
                    assert!(
                        blocks.iter().any(|b| matches!(b, ContentBlock::ToolResult { .. })),
                        "ToolResult block must be preserved"
                    );
                }
                other => panic!("expected Blocks, got {other:?}"),
            }
        } else {
            panic!("expected AnthropicMessages");
        }
    }

    #[test]
    fn anthropic_thinking_blocks_preserved_when_messages_unchanged() {
        let json = r#"{
            "model": "claude-3",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Think about this"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "Let me reason...", "signature": "sig123"},
                    {"type": "text", "text": "Here is my answer"}
                ]}
            ]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, Some("anthropic"), false, &no_subs());
        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(!changes.iter().any(|c| c.starts_with("message")));

        if let ApiRequest::AnthropicMessages(msg) = &req {
            match &msg.messages[1].content {
                AnthropicContent::Blocks(blocks) => {
                    assert!(
                        blocks.iter().any(|b| matches!(b, ContentBlock::Thinking { .. })),
                        "Thinking block must be preserved"
                    );
                }
                other => panic!("expected Blocks, got {other:?}"),
            }
        }
    }

    #[test]
    fn chat_completions_image_parts_preserved_when_messages_unchanged() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": [
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc123"}},
                    {"type": "text", "text": "Describe this image"}
                ]}
            ]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, Some("openai"), false, &no_subs());
        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(!changes.iter().any(|c| c.starts_with("message")));

        if let ApiRequest::ChatCompletions(chat) = &req {
            match &chat.messages[0].content {
                Some(MessageContent::Parts(parts)) => {
                    assert!(
                        parts.iter().any(|p| matches!(p, crate::api::domain::ContentPart::ImageUrl { .. })),
                        "Image part must be preserved"
                    );
                }
                other => panic!("expected Parts, got {other:?}"),
            }
        }
    }

    #[test]
    fn chat_completions_tool_calls_preserved_when_messages_unchanged() {
        let json = r#"{
            "model": "gpt-4o",
            "messages": [
                {"role": "user", "content": "What's the weather?"},
                {"role": "assistant", "content": null, "tool_calls": [
                    {"id": "call_1", "type": "function", "function": {"name": "get_weather", "arguments": "{\"city\":\"Paris\"}"}}
                ]},
                {"role": "tool", "tool_call_id": "call_1", "content": "22°C sunny"}
            ]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, Some("openai"), false, &no_subs());
        let changes = apply_to_api_request(&ctx, &mut req, edited(false));
        assert!(!changes.iter().any(|c| c.starts_with("message")));

        if let ApiRequest::ChatCompletions(chat) = &req {
            assert_eq!(chat.messages.len(), 3, "message count must be unchanged");
            // Assistant message must still have tool_calls
            let assistant = &chat.messages[1];
            assert!(
                assistant.tool_calls.is_some(),
                "tool_calls must be preserved on assistant message"
            );
        }
    }

    #[test]
    fn anthropic_messages_modified_by_script_applies_changes() {
        // When the messages are marked changed, sync should apply text changes
        let json = r#"{
            "model": "claude-3",
            "max_tokens": 1024,
            "messages": [{"role": "user", "content": "Hello"}]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let mut ctx = from_api_request(&req, &test_user(), None, None, Some("anthropic"), false, &no_subs());
        ctx.messages[0].content = "Modified hello".to_string();

        let changes = apply_to_api_request(&ctx, &mut req, edited(true));
        assert!(
            changes.iter().any(|c| c.starts_with("message")),
            "message change expected, got: {changes:?}"
        );

        if let ApiRequest::AnthropicMessages(msg) = &req {
            match &msg.messages[0].content {
                AnthropicContent::Text(t) => assert_eq!(t, "Modified hello"),
                other => panic!("expected Text, got {other:?}"),
            }
        }
    }

    #[test]
    fn anthropic_tool_result_rebuilt_as_valid_when_messages_changed() {
        // When the messages are marked changed, the write-back must never
        // produce role="tool" (Anthropic rejects it with 400).
        // Same-count path: tool_result blocks are updated in-place.
        let json = r#"{
            "model": "claude-3",
            "max_tokens": 1024,
            "messages": [
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "call_1", "name": "bash", "input": {"cmd": "ls"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "call_1", "content": "file1.txt\nfile2.txt"}
                ]}
            ]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let ctx = from_api_request(&req, &test_user(), None, None, Some("anthropic"), false, &no_subs());
        let _changes = apply_to_api_request(&ctx, &mut req, edited(true));

        if let ApiRequest::AnthropicMessages(msg) = &req {
            // Must not produce any message with role="tool"
            for m in &msg.messages {
                assert_ne!(m.role, "tool", "AnthropicMessage must never have role='tool'");
            }
            // Structure preserved: assistant with ToolUse, user with ToolResult
            assert_eq!(msg.messages.len(), 2);
            assert_matches!(
                &msg.messages[0].content,
                AnthropicContent::Blocks(b) if b.iter().any(|bl| matches!(bl, ContentBlock::ToolUse { .. }))
            );
            assert_matches!(
                &msg.messages[1].content,
                AnthropicContent::Blocks(b) if b.iter().any(|bl| matches!(bl, ContentBlock::ToolResult { .. }))
            );
        }
    }

    // ── Anthropic sync-back tests ──

    #[test]
    fn group_rhai_for_anthropic_groups_correctly() {
        let msgs = vec![
            RhaiMessage { role: "user".to_string(), content: "hello".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
            RhaiMessage { role: "assistant".to_string(), content: "I'll search".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
            RhaiMessage { role: "tool".to_string(), content: "r1".to_string(), tool_call_id: Some("c1".to_string()), tool_calls: vec![], origin: None },
            RhaiMessage { role: "tool".to_string(), content: "r2".to_string(), tool_call_id: Some("c2".to_string()), tool_calls: vec![], origin: None },
            RhaiMessage { role: "user".to_string(), content: "what next?".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
            RhaiMessage { role: "assistant".to_string(), content: "done".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
        ];

        let groups = group_rhai_for_anthropic(&msgs);
        assert_eq!(groups.len(), 4, "user + assistant + tool_group(c1,c2,text) + assistant");

        // Group 0: single user
        assert_matches!(&groups[0], RhaiGroup::Single(m) if m.role == "user");
        // Group 1: single assistant
        assert_matches!(&groups[1], RhaiGroup::Single(m) if m.role == "assistant");
        // Group 2: tool group with 2 tools + trailing user text
        match &groups[2] {
            RhaiGroup::ToolGroup { tool_msgs, text_msg } => {
                assert_eq!(tool_msgs.len(), 2);
                assert!(text_msg.is_some());
                assert_eq!(text_msg.unwrap().content, "what next?");
            }
            other => panic!("expected ToolGroup, got {other:?}"),
        }
        // Group 3: single assistant
        assert_matches!(&groups[3], RhaiGroup::Single(m) if m.role == "assistant");

        // Edge case: tool messages at end (no trailing user)
        let msgs2 = vec![
            RhaiMessage { role: "tool".to_string(), content: "r1".to_string(), tool_call_id: Some("c1".to_string()), tool_calls: vec![], origin: None },
        ];
        let groups2 = group_rhai_for_anthropic(&msgs2);
        assert_eq!(groups2.len(), 1);
        match &groups2[0] {
            RhaiGroup::ToolGroup { tool_msgs, text_msg } => {
                assert_eq!(tool_msgs.len(), 1);
                assert!(text_msg.is_none(), "no trailing user → text_msg is None");
            }
            other => panic!("expected ToolGroup, got {other:?}"),
        }
    }

    /// A script reads a tool result's text blocks joined — an image among
    /// them included — and a script that changes nothing writes nothing.
    #[test]
    fn a_script_that_changes_nothing_in_a_tool_result_writes_nothing() {
        let msg: AnthropicMessage = serde_json::from_value(serde_json::json!({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": "c1", "content": [
                {"type": "text", "text": "a"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}},
                {"type": "text", "text": "b"},
            ]},
            {"type": "text", "text": "next"},
        ]}))
        .unwrap();
        let req: crate::api::messages::MessagesRequest =
            serde_json::from_value(serde_json::json!({"model": "m", "max_tokens": 1, "messages": [msg.clone()]})).unwrap();
        let domain = DomainRequest::from_anthropic(&req).messages;
        let from_domain: Vec<String> = domain.iter().map(|m| domain_msg_to_rhai(m).content).collect();
        assert_eq!(from_domain, ["ab", "next"]);

        let mut contents = vec![msg];
        let modified = anthropic_view(&contents);
        let mut changes = Vec::new();
        anthropic_write(&mut contents, &modified, &mut changes);
        assert!(changes.is_empty(), "{changes:?}");
    }

    /// A script reads no citation, so a text it rewrites loses them — in a
    /// message and in a tool result — and one it leaves keeps them.
    #[test]
    fn a_script_rewritten_text_drops_the_citations_it_never_read() {
        let cite = serde_json::json!([{"type": "char_location", "cited_text": "ssn 1", "document_index": 0, "document_title": null,
            "start_char_index": 0, "end_char_index": 1}]);
        let msg = |text: &str, result: &str| -> AnthropicMessage {
            serde_json::from_value(serde_json::json!({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "c1", "content": [{"type": "text", "text": result, "citations": cite}]},
                {"type": "text", "text": text, "citations": cite},
            ]}))
            .unwrap()
        };
        let mut contents = vec![msg("ssn 1", "found")];
        let mut script = anthropic_view(&contents);
        let prose = script.iter().position(|m| m.content == "ssn 1").unwrap();
        script[prose].content = "[X]".to_string();
        let mut changes = Vec::new();
        anthropic_write(&mut contents, &script, &mut changes);
        let wire = serde_json::to_value(&contents[0]).unwrap();
        assert_eq!(wire["content"][1], serde_json::json!({"type": "text", "text": "[X]"}));
        assert_eq!(wire["content"][0]["content"][0]["citations"], cite, "the result the script left keeps its own");
        let mut contents = vec![msg("next", "ssn 1")];
        let mut script = anthropic_view(&contents);
        let result = script.iter().position(|m| m.content == "ssn 1").unwrap();
        script[result].content = "[X]".to_string();
        anthropic_write(&mut contents, &script, &mut changes);
        let wire = serde_json::to_value(&contents[0]).unwrap();
        assert!(wire["content"][0]["content"].to_string().contains("[X]") && !wire["content"][0]["content"].to_string().contains("citations"), "{wire}");
        assert_eq!(wire["content"][1]["citations"], cite);
    }

    #[test]
    fn sync_anthropic_same_count_updates_text_preserves_tool_result() {
        use crate::api::messages::*;
        let mut native = vec![
            AnthropicMessage {
                role: "assistant".to_string(),
                content: AnthropicContent::Blocks(vec![
                    ContentBlock::Text {
                        text: "I'll search".to_string(),
                        cache_control: None,
                        extra: BTreeMap::new(),
                    },
                    ContentBlock::ToolUse {
                        id: "c1".to_string(),
                        name: "bash".to_string(),
                        input: serde_json::json!({}),
                        cache_control: None,
                        extra: BTreeMap::new(),
                    },
                ]),
            },
            AnthropicMessage {
                role: "user".to_string(),
                content: AnthropicContent::Blocks(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "c1".to_string(),
                        content: Some(ToolResultContent::Text(
                            "user@email.com found".to_string(),
                        )),
                        is_error: Some(false),
                        cache_control: None,
                        extra: Default::default(),
                    },
                    ContentBlock::Text {
                        text: "Tell me about user@email.com".to_string(),
                        cache_control: None,
                        extra: BTreeMap::new(),
                    },
                ]),
            },
        ];

        // Simulate email anonymizer: modify text content
        let mut modified_rhai = anthropic_view(&native);
        assert_eq!(modified_rhai.len(), 3);
        modified_rhai[1].content = "[REDACTED] found".to_string();
        modified_rhai[2].content = "Tell me about [REDACTED]".to_string();

        let mut changes = Vec::new();
        anthropic_write(&mut native, &modified_rhai, &mut changes);

        assert!(!changes.is_empty(), "should report changes");
        assert_eq!(native.len(), 2, "native count unchanged");

        // Assistant message: ToolUse preserved, text unchanged
        match &native[0].content {
            AnthropicContent::Blocks(blocks) => {
                assert!(
                    blocks
                        .iter()
                        .any(|b| matches!(b, ContentBlock::ToolUse { .. })),
                    "ToolUse preserved"
                );
            }
            other => panic!("expected Blocks, got {other:?}"),
        }

        // User message: ToolResult content updated, text updated, metadata preserved
        match &native[1].content {
            AnthropicContent::Blocks(blocks) => {
                let tr = blocks
                    .iter()
                    .find_map(|b| match b {
                        ContentBlock::ToolResult {
                            content, is_error, ..
                        } => Some((content, is_error)),
                        _ => None,
                    })
                    .expect("ToolResult must exist");
                assert_matches!(tr.0, Some(ToolResultContent::Text(t)) if t == "[REDACTED] found",
                    "tool_result text updated"
                );
                assert_eq!(*tr.1, Some(false), "is_error preserved");

                let text = blocks
                    .iter()
                    .find_map(|b| match b {
                        ContentBlock::Text { text, .. } => Some(text.as_str()),
                        _ => None,
                    })
                    .expect("Text block must exist");
                assert_eq!(text, "Tell me about [REDACTED]", "text block updated");
            }
            other => panic!("expected Blocks, got {other:?}"),
        }
    }

    #[test]
    fn sync_anthropic_count_changed_rebuilds_with_tool_results() {
        use crate::api::messages::*;
        let mut native = vec![
            AnthropicMessage {
                role: "user".to_string(),
                content: AnthropicContent::Text("start".to_string()),
            },
            AnthropicMessage {
                role: "assistant".to_string(),
                content: AnthropicContent::Blocks(vec![ContentBlock::ToolUse {
                    id: "c1".to_string(),
                    name: "bash".to_string(),
                    input: serde_json::json!({}),
                    cache_control: None,
                    extra: BTreeMap::new(),
                }]),
            },
            AnthropicMessage {
                role: "user".to_string(),
                content: AnthropicContent::Blocks(vec![
                    ContentBlock::ToolResult {
                        tool_use_id: "c1".to_string(),
                        content: Some(ToolResultContent::Text("output".to_string())),
                        is_error: None,
                        cache_control: None,
                        extra: Default::default(),
                    },
                    ContentBlock::Text {
                        text: "ok what next?".to_string(),
                        cache_control: None,
                        extra: BTreeMap::new(),
                    },
                ]),
            },
            AnthropicMessage {
                role: "assistant".to_string(),
                content: AnthropicContent::Text("done".to_string()),
            },
            AnthropicMessage {
                role: "user".to_string(),
                content: AnthropicContent::Text("thanks".to_string()),
            },
        ];

        // Compression removed middle 3 messages
        let modified_rhai = vec![
            RhaiMessage {
                role: "user".to_string(),
                content: "start".to_string(),
                tool_call_id: None,
                tool_calls: vec![],
                origin: None,
            },
            RhaiMessage {
                role: "user".to_string(),
                content: "thanks".to_string(),
                tool_call_id: None,
                tool_calls: vec![],
                origin: None,
            },
        ];

        let mut changes = Vec::new();
        anthropic_write(&mut native, &modified_rhai, &mut changes);

        assert_eq!(native.len(), 2, "should have 2 messages after compression");
        assert!(
            changes.contains(&"messages".to_string()),
            "should report message change"
        );
        // First message matched to original (preserving native structure)
        assert_matches!(
            &native[0].content,
            AnthropicContent::Text(t) if t == "start"
        );
    }

    #[test]
    fn anthropic_email_anonymizer_with_tool_results_roundtrip() {
        // Full scenario: email anonymizer modifies text in a conversation with tool calls.
        let json = r#"{
            "model": "claude-3",
            "max_tokens": 1024,
            "messages": [
                {"role": "user", "content": "Find info about admin@company.com"},
                {"role": "assistant", "content": [
                    {"type": "thinking", "thinking": "I need to search for admin@company.com", "signature": "sig1"},
                    {"type": "text", "text": "Let me search for admin@company.com"},
                    {"type": "tool_use", "id": "c1", "name": "search", "input": {"q": "admin@company.com"}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "c1", "content": "Found: admin@company.com is the system admin"},
                    {"type": "text", "text": "What did you find about admin@company.com?"}
                ]},
                {"role": "assistant", "content": "admin@company.com is the system administrator."}
            ]
        }"#;
        let body = Bytes::from(json);
        let mut req =
            ApiRequest::parse(crate::api::sse::ApiVersion::AnthropicMessages, &body).unwrap();

        let mut ctx =
            from_api_request(&req, &test_user(), None, None, Some("anthropic"), false, &no_subs());

        // Simulate email anonymizer: replace all emails
        for msg in &mut ctx.messages {
            msg.content = msg.content.replace("admin@company.com", "[REDACTED]");
        }

        let changes = apply_to_api_request(&ctx, &mut req, edited(true));
        assert!(!changes.is_empty(), "should report changes");

        if let ApiRequest::AnthropicMessages(msg) = &req {
            assert_eq!(msg.messages.len(), 4, "message count preserved");

            // No role="tool" in output
            for m in &msg.messages {
                assert_ne!(m.role, "tool");
            }

            // Message 0: user text updated
            match &msg.messages[0].content {
                AnthropicContent::Text(t) => {
                    assert_eq!(t, "Find info about [REDACTED]");
                }
                AnthropicContent::Blocks(b) => {
                    let text = b
                        .iter()
                        .find_map(|bl| match bl {
                            ContentBlock::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(text, "Find info about [REDACTED]");
                }
            }

            // Message 1: assistant — Thinking preserved, text updated, ToolUse preserved
            match &msg.messages[1].content {
                AnthropicContent::Blocks(blocks) => {
                    assert!(
                        blocks
                            .iter()
                            .any(|b| matches!(b, ContentBlock::Thinking { .. })),
                        "Thinking block preserved"
                    );
                    assert!(
                        blocks
                            .iter()
                            .any(|b| matches!(b, ContentBlock::ToolUse { .. })),
                        "ToolUse block preserved"
                    );
                    let text = blocks
                        .iter()
                        .find_map(|b| match b {
                            ContentBlock::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(text, "Let me search for [REDACTED]");
                }
                other => panic!("expected Blocks, got {other:?}"),
            }

            // Message 2: user — ToolResult content updated, text updated
            match &msg.messages[2].content {
                AnthropicContent::Blocks(blocks) => {
                    let tr = blocks
                        .iter()
                        .find_map(|b| match b {
                            ContentBlock::ToolResult { content, .. } => Some(content),
                            _ => None,
                        })
                        .expect("ToolResult must exist");
                    match tr {
                        Some(crate::api::messages::ToolResultContent::Text(t)) => {
                            assert_eq!(t, "Found: [REDACTED] is the system admin");
                        }
                        other => panic!("expected Text tool_result, got {other:?}"),
                    }
                    let text = blocks
                        .iter()
                        .find_map(|b| match b {
                            ContentBlock::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(text, "What did you find about [REDACTED]?");
                }
                other => panic!("expected Blocks, got {other:?}"),
            }

            // Message 3: assistant text updated
            match &msg.messages[3].content {
                AnthropicContent::Text(t) => {
                    assert_eq!(t, "[REDACTED] is the system administrator.");
                }
                AnthropicContent::Blocks(b) => {
                    let text = b
                        .iter()
                        .find_map(|bl| match bl {
                            ContentBlock::Text { text, .. } => Some(text.as_str()),
                            _ => None,
                        })
                        .unwrap();
                    assert_eq!(text, "[REDACTED] is the system administrator.");
                }
            }
        }
    }

    // ─── Gemini message sync tests ───

    #[test]
    fn gemini_sync_text_modification_in_place() {
        let mut contents = vec![
            GeminiContent {
                role: Some("user".to_string()),
                parts: vec![
                    GeminiPart::Text { text: "Hello".to_string() },
                    GeminiPart::inline("image/png".to_string(), "base64data".to_string()),
                ],
            },
            GeminiContent {
                role: Some("model".to_string()),
                parts: vec![GeminiPart::Text { text: "World".to_string() }],
            },
        ];

        let modified = vec![
            RhaiMessage { role: "user".to_string(), content: "Modified hello".to_string(), tool_call_id: None, tool_calls: vec![], origin: Some(0) },
            RhaiMessage { role: "assistant".to_string(), content: "World".to_string(), tool_call_id: None, tool_calls: vec![], origin: Some(1) },
        ];

        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);

        assert_eq!(changes, vec!["message_0"]);
        // Text updated
        assert_matches!(&contents[0].parts[0], GeminiPart::Text { text } if text == "Modified hello");
        // InlineData preserved
        assert_matches!(&contents[0].parts[1], GeminiPart::InlineData { .. });
        // Second message unchanged
        assert_matches!(&contents[1].parts[0], GeminiPart::Text { text } if text == "World");
    }

    #[test]
    fn gemini_sync_preserves_func_response() {
        let mut contents = vec![
            GeminiContent {
                role: Some("model".to_string()),
                parts: vec![
                    GeminiPart::Text { text: "Checking".to_string() },
                    GeminiPart::FunctionCall {
                        function_call: crate::api::gemini::GeminiFunctionCallData {
                            id: Some("call_1".to_string()),
                            name: "search".to_string(),
                            args: serde_json::json!({"q": "test"}),
                        },
                        thought_signature: None,
                    },
                ],
            },
            GeminiContent {
                role: Some("user".to_string()),
                parts: vec![GeminiPart::FunctionResponse {
                    function_response: crate::api::gemini::GeminiFunctionResponseData {
                        id: Some("call_1".to_string()),
                        name: "search".to_string(),
                        response: serde_json::json!({"result": "found"}),
                        parts: Vec::new(), extra: Default::default(),
                    },
                }],
            },
        ];

        let mut modified = gemini_view(&contents);
        modified[1].content = r#"{"result":"updated"}"#.to_string();

        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);

        assert!(changes.contains(&"message_1".to_string()));
        // FunctionResponse updated
        if let GeminiPart::FunctionResponse { function_response } = &contents[1].parts[0] {
            assert_eq!(function_response.response, serde_json::json!({"result": "updated"}));
        } else {
            panic!("expected FunctionResponse");
        }
    }

    /// Responses with no call id that share their function's name are told
    /// apart by the place each was read from: when a script prunes one, every
    /// other keeps its own media, and none another's.
    #[test]
    fn a_gemini_rebuild_gives_each_response_its_own_media() {
        let response = |name: &str, n: u8| serde_json::json!({"functionResponse": {
            "name": name, "response": {"n": n}, "parts": [{"inlineData": {"mimeType": "image/png", "data": format!("IMG{n}")}}],
        }});
        let mut contents: Vec<GeminiContent> = serde_json::from_value(serde_json::json!([
            {"role": "model", "parts": [{"functionCall": {"name": "shot", "args": {}}}]},
            {"role": "user", "parts": [response("shot", 1)]},
            {"role": "model", "parts": [{"functionCall": {"name": "shot", "args": {}}}]},
            {"role": "user", "parts": [response("shot", 2)]},
            {"role": "model", "parts": [{"functionCall": {"name": "read", "args": {}}}]},
            {"role": "user", "parts": [response("read", 3)]},
        ]))
        .unwrap();
        // The script prunes the first call and its response.
        let mut modified: Vec<RhaiMessage> = gemini_view(&contents);
        modified.drain(0..2);

        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);

        let parts: Vec<Value> = contents
            .iter()
            .flat_map(|c| &c.parts)
            .filter_map(|p| match p {
                GeminiPart::FunctionResponse { function_response } => Some(serde_json::json!(function_response.parts)),
                _ => None,
            })
            .collect();
        assert_eq!(
            parts,
            [response("shot", 2)["functionResponse"]["parts"].clone(), response("read", 3)["functionResponse"]["parts"].clone()]
        );
    }

    /// A script's text written into a function response in place is the
    /// object the protocol requires, as on every other write.
    #[test]
    fn a_gemini_in_place_write_sends_an_object_response() {
        let mut contents: Vec<GeminiContent> = serde_json::from_value(serde_json::json!([
            {"role": "model", "parts": [{"functionCall": {"id": "c1", "name": "f", "args": {}}}]},
            {"role": "user", "parts": [{"functionResponse": {"id": "c1", "name": "f", "response": {"email": "a@b"}}}]},
        ]))
        .unwrap();
        let mut modified: Vec<RhaiMessage> = gemini_view(&contents);
        modified[1].content = "[REDACTED]".to_string();
        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);
        assert_matches!(&contents[1].parts[0], GeminiPart::FunctionResponse { function_response }
            if function_response.response == serde_json::json!({"output": "[REDACTED]"}));
    }

    /// A write lands on the text the projection read: an output part with no
    /// `type`, read as its JSON, is replaced — never left beside the new text.
    #[test]
    fn a_write_replaces_an_untyped_output_part_it_read_as_text() {
        let mut req = ApiRequest::Responses(serde_json::from_value(serde_json::json!({"model": "m", "input": [
            {"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{}"},
            {"type": "function_call_output", "call_id": "c1", "output": [
                {"email": "a@b.com"},
                {"type": "input_image", "image_url": "data:image/png;base64,iVBO"},
            ]},
        ]}))
        .unwrap());
        let own = DomainRequest::item_conversation(&req, 1);
        assert_eq!(domain_msg_to_rhai(&own[0]).content, "{\"email\":\"a@b.com\"}");
        set_item_text(&mut req, 1, 0, "[REDACTED]");
        let ApiRequest::Responses(r) = &req else { unreachable!() };
        let crate::api::domain::ResponseInput::Raw(items) = &r.input else { unreachable!() };
        assert_eq!(items[1]["output"], serde_json::json!([
            {"type": "input_text", "text": "[REDACTED]"},
            {"type": "input_image", "image_url": "data:image/png;base64,iVBO"},
        ]));
    }

    /// A rebuild sends a response the script left as it was exactly as sent,
    /// a client's string included.
    #[test]
    fn a_gemini_rebuild_sends_an_untouched_string_response_as_sent() {
        let mut contents: Vec<GeminiContent> = serde_json::from_value(serde_json::json!([
            {"role": "model", "parts": [{"functionCall": {"id": "c1", "name": "f", "args": {}}}]},
            {"role": "user", "parts": [{"functionResponse": {"id": "c1", "name": "f", "response": "ok"}}]},
            {"role": "model", "parts": [{"text": "done"}]},
        ]))
        .unwrap();
        let mut modified: Vec<RhaiMessage> = gemini_view(&contents);
        modified.pop();
        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);
        assert_matches!(&contents[1].parts[0], GeminiPart::FunctionResponse { function_response }
            if function_response.response == serde_json::json!("ok"));
    }

    #[test]
    fn an_emptied_tool_result_keeps_its_media_and_no_empty_text() {
        let image = crate::api::messages::ToolResultBlock::Image {
            source: serde_json::from_value(serde_json::json!({"type": "base64", "media_type": "image/png", "data": "iVBO"})).unwrap(),
            cache_control: None,
            extra: Default::default(),
        };
        let mut content = Some(crate::api::messages::ToolResultContent::Blocks(vec![
            crate::api::messages::ToolResultBlock::text("x".into()),
            image.clone(),
        ]));
        set_tool_result_text(&mut content, "");
        assert_eq!(serde_json::to_value(&content).unwrap(), serde_json::json!([
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}},
        ]));
        // The text's breakpoint stays at the end of the result.
        let mut cached = Some(crate::api::messages::ToolResultContent::Blocks(vec![
            serde_json::from_value(serde_json::json!({"type": "text", "text": "x", "cache_control": {"type": "ephemeral"}})).unwrap(),
            image,
        ]));
        set_tool_result_text(&mut cached, "");
        assert_eq!(serde_json::to_value(&cached).unwrap(), serde_json::json!([
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"}, "cache_control": {"type": "ephemeral"}},
        ]));
        let mut only_text = Some(crate::api::messages::ToolResultContent::Blocks(vec![
            crate::api::messages::ToolResultBlock::text("x".into()),
        ]));
        set_tool_result_text(&mut only_text, "");
        assert!(only_text.is_none());
    }

    /// The same on Gemini: a function response the script kept keeps its
    /// blobs and other members.
    #[test]
    fn a_gemini_rebuild_keeps_a_function_responses_parts_and_members() {
        let response = serde_json::json!({"functionResponse": {
            "id": "c1", "name": "shot", "response": {"r": 1},
            "parts": [{"inlineData": {"mimeType": "image/png", "data": "iVBO"}}], "willContinue": false,
        }});
        let mut contents: Vec<GeminiContent> = serde_json::from_value(serde_json::json!([
            {"role": "user", "parts": [{"text": "start"}]},
            {"role": "model", "parts": [{"functionCall": {"id": "c1", "name": "shot", "args": {}}}]},
            {"role": "user", "parts": [response.clone()]},
            {"role": "model", "parts": [{"text": "done"}]},
        ]))
        .unwrap();
        let mut modified: Vec<RhaiMessage> = gemini_view(&contents);
        modified.pop();

        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);

        assert_eq!(changes, ["messages"]);
        let rebuilt = contents.iter().flat_map(|c| &c.parts).find(|p| matches!(p, GeminiPart::FunctionResponse { .. })).unwrap();
        assert_eq!(serde_json::to_value(rebuilt).unwrap(), response);
    }

    #[test]
    fn gemini_sync_count_change_rebuilds() {
        let mut contents = vec![
            GeminiContent {
                role: Some("user".to_string()),
                parts: vec![GeminiPart::Text { text: "Hello".to_string() }],
            },
            GeminiContent {
                role: Some("model".to_string()),
                parts: vec![GeminiPart::Text { text: "World".to_string() }],
            },
        ];

        // Add a new message
        let modified = vec![
            RhaiMessage { role: "user".to_string(), content: "Hello".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
            RhaiMessage { role: "assistant".to_string(), content: "World".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
            RhaiMessage { role: "user".to_string(), content: "New message".to_string(), tool_call_id: None, tool_calls: vec![], origin: None },
        ];

        let mut changes = Vec::new();
        gemini_write(&mut contents, &modified, &mut changes);

        assert_eq!(changes, vec!["messages"]);
        assert_eq!(contents.len(), 3);
        // Original messages preserved (matched by role + text)
        assert_eq!(contents[0].role.as_deref(), Some("user"));
        assert_eq!(contents[1].role.as_deref(), Some("model"));
        // New message added
        assert_eq!(contents[2].role.as_deref(), Some("user"));
        assert_matches!(&contents[2].parts[0], GeminiPart::Text { text } if text == "New message");
    }

    /// A signature covers a call as the model produced it: a script that
    /// drops one call keeps the signature on the calls it left alone, and an
    /// edited call goes without.
    #[test]
    fn gemini_call_sync_keeps_the_signature_of_an_unchanged_call() {
        let call = |id: &str, q: &str, sig: Option<&str>| GeminiPart::FunctionCall {
            function_call: crate::api::gemini::GeminiFunctionCallData {
                id: Some(id.to_string()),
                name: "search".to_string(),
                args: serde_json::json!({"q": q}),
            },
            thought_signature: sig.map(str::to_string),
        };
        let mut contents = vec![GeminiContent {
            role: Some("model".to_string()),
            parts: vec![call("c1", "a", Some("Sig1")), call("c2", "b", None), call("c3", "c", Some("Sig3"))],
        }];
        let rhai = |id: &str, q: &str| RhaiToolCall {
            id: id.to_string(),
            name: "search".to_string(),
            arguments_json: serde_json::json!({"q": q}).to_string(),
        };
        let msgs = vec![RhaiMessage {
            role: "assistant".to_string(),
            content: String::new(),
            tool_call_id: None,
            tool_calls: vec![rhai("c1", "a"), rhai("c3", "edited")],
            origin: Some(0),
        }];
        let mut changes = Vec::new();
        gemini_write(&mut contents, &msgs, &mut changes);
        assert_eq!(changes, ["message_0_tool_calls"]);
        let signed: Vec<(Option<&str>, Option<&str>)> = contents[0]
            .parts
            .iter()
            .map(|p| match p {
                GeminiPart::FunctionCall { function_call, thought_signature } => {
                    (function_call.id.as_deref(), thought_signature.as_deref())
                }
                _ => (None, None),
            })
            .collect();
        assert_eq!(signed, [(Some("c1"), Some("Sig1")), (Some("c3"), None)]);
    }

    // ─── Gemini tool sync tests ───

    #[test]
    fn gemini_tool_add() {
        let mut tools: Option<Vec<crate::api::gemini::GeminiTool>> = None;
        let rhai_tools = vec![RhaiTool {
            name: "get_weather".to_string(),
            description: Some("Get weather".to_string()),
            parameters_json: Some(r#"{"type":"object","properties":{"city":{"type":"string"}}}"#.to_string()),
            is_gateway_substituted: false, kind: None, config_json: None,
        }];
        let mut changes = Vec::new();
        apply_gemini_tool_changes(&rhai_tools, &mut tools, &mut changes);
        assert_eq!(changes, vec!["tools"]);
        let decls = &tools.unwrap()[0].function_declarations.clone().unwrap();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0].name, "get_weather");
    }

    #[test]
    fn gemini_tool_remove_all() {
        let mut tools: Option<Vec<crate::api::gemini::GeminiTool>> = Some(vec![crate::api::gemini::GeminiTool {
            extra: Default::default(),
            function_declarations: Some(vec![
                crate::api::gemini::GeminiFunctionDecl {
                    name: "f1".to_string(),
                    description: None,
                    parameters: None,
                },
            ]),
        }]);
        let mut changes = Vec::new();
        apply_gemini_tool_changes(&[], &mut tools, &mut changes);
        assert_eq!(changes, vec!["tools"]);
        assert!(tools.is_none());
    }

    #[test]
    fn gemini_tool_count_change_rebuilds_wrapper() {
        // Starting with 1 tool across possibly-multiple wrapper entries
        let mut tools: Option<Vec<crate::api::gemini::GeminiTool>> = Some(vec![crate::api::gemini::GeminiTool {
            extra: Default::default(),
            function_declarations: Some(vec![
                crate::api::gemini::GeminiFunctionDecl {
                    name: "f1".to_string(),
                    description: None,
                    parameters: None,
                },
            ]),
        }]);
        let rhai_tools = vec![
            RhaiTool { name: "f1".to_string(), description: None, parameters_json: None, is_gateway_substituted: false, kind: None, config_json: None },
            RhaiTool { name: "f2".to_string(), description: None, parameters_json: None, is_gateway_substituted: false, kind: None, config_json: None },
        ];
        let mut changes = Vec::new();
        apply_gemini_tool_changes(&rhai_tools, &mut tools, &mut changes);
        assert_eq!(changes, vec!["tools"]);
        let t = tools.unwrap();
        assert_eq!(t.len(), 1, "rebuild should produce single GeminiTool wrapper");
        let decls = t[0].function_declarations.clone().unwrap();
        assert_eq!(decls.len(), 2);
        assert_eq!(decls[0].name, "f1");
        assert_eq!(decls[1].name, "f2");
    }

    // ─── Rhai tool_calls (read + mutate) tests ───

    #[test]
    fn domain_msg_to_rhai_populates_tool_calls() {
        use crate::api::domain_request::{DomainContentBlock, DomainMessage, DomainRole};
        let dm = DomainMessage {
            role: DomainRole::Assistant,
            content: vec![
                DomainContentBlock::Text {
                    text: "Looking it up".to_string(),
                    cache_control: None,
                    citations: Vec::new(),
                },
                DomainContentBlock::ToolUse {
                    id: "call_1".to_string(),
                    name: "search".to_string(),
                    input: serde_json::json!({"q": "fabric"}),
                    input_raw: None,
                    cache_control: None,
                    thought_signature: None,
                },
                DomainContentBlock::Thinking {
                    thinking: "hmm".to_string(),
                    signature: None,
                    signed_by: None,
                },
            ],
        };
        let rm = super::domain_msg_to_rhai(&dm);
        assert_eq!(rm.role, "assistant");
        assert_eq!(rm.content, "Looking it up");
        assert_eq!(rm.tool_calls.len(), 1);
        assert_eq!(rm.tool_calls[0].id, "call_1");
        assert_eq!(rm.tool_calls[0].name, "search");
        assert_eq!(rm.tool_calls[0].arguments_json, r#"{"q":"fabric"}"#);
    }

    #[test]
    fn anthropic_tool_call_mutation_preserves_thinking() {
        // Build an Anthropic assistant message with thinking + tool_use.
        let mut msgs = vec![AnthropicMessage {
            role: "assistant".to_string(),
            content: AnthropicContent::Blocks(vec![
                ContentBlock::Thinking {
                    thinking: "reasoning".to_string(),
                    signature: None,
                },
                ContentBlock::Text {
                    text: "Let me search.".to_string(),
                    cache_control: None,
                    extra: BTreeMap::new(),
                },
                ContentBlock::ToolUse {
                    id: "tu_1".to_string(),
                    name: "search".to_string(),
                    input: serde_json::json!({"q": "secret"}),
                    cache_control: None,
                    extra: BTreeMap::new(),
                },
            ]),
        }];

        // Rhai projection mimics what scripts see.
        let rhai_msgs = vec![RhaiMessage {
            role: "assistant".to_string(),
            content: "Let me search.".to_string(),
            tool_call_id: None,
            tool_calls: vec![RhaiToolCall {
                id: "tu_1".to_string(),
                name: "search".to_string(),
                arguments_json: r#"{"q":"[redacted]"}"#.to_string(),
            }],
            origin: Some(0),
        }];

        let mut changes = Vec::new();
        anthropic_write(&mut msgs, &rhai_msgs, &mut changes);

        assert_eq!(changes, vec!["message_0_tool_calls"]);
        let blocks = match &msgs[0].content {
            AnthropicContent::Blocks(b) => b,
            _ => panic!("expected Blocks"),
        };
        // Thinking must survive.
        assert!(blocks.iter().any(|b| matches!(b, ContentBlock::Thinking { .. })));
        // ToolUse args updated.
        let tu = blocks
            .iter()
            .find_map(|b| match b {
                ContentBlock::ToolUse { input, .. } => Some(input.clone()),
                _ => None,
            })
            .unwrap();
        assert_eq!(tu, serde_json::json!({"q": "[redacted]"}));
    }

    #[test]
    fn cc_tool_call_drop_updates_native() {
        use crate::api::domain::{Message, MessageContent, ToolCall};

        let chat_msgs = vec![Message {
            role: "assistant".to_string(),
            content: Some(MessageContent::Text("ok".to_string())),
            name: None,
            tool_calls: Some(vec![ToolCall::function(
                "c1".to_string(),
                "search".to_string(),
                r#"{"q":"a"}"#.to_string(),
            )]),
            tool_call_id: None,
            extra: BTreeMap::new(),
        }];

        // Rhai dropped the tool call.
        let rhai_msgs = vec![RhaiMessage {
            role: "assistant".to_string(),
            content: "ok".to_string(),
            tool_call_id: None,
            tool_calls: vec![],
            origin: Some(0),
        }];

        let mut req = ApiRequest::ChatCompletions(
            serde_json::from_value(serde_json::json!({"model": "m", "messages": chat_msgs})).unwrap(),
        );
        let mut changes = Vec::new();
        write_messages(&mut req, &rhai_msgs, &mut changes);

        assert_eq!(changes, vec!["message_0_tool_calls"]);
        let ApiRequest::ChatCompletions(chat) = req else { unreachable!() };
        assert!(chat.messages[0].tool_calls.is_none());
    }

    #[test]
    fn gemini_tool_same_count_no_change() {
        let mut tools: Option<Vec<crate::api::gemini::GeminiTool>> = Some(vec![crate::api::gemini::GeminiTool {
            extra: Default::default(),
            function_declarations: Some(vec![
                crate::api::gemini::GeminiFunctionDecl {
                    name: "f1".to_string(),
                    description: None,
                    parameters: None,
                },
            ]),
        }]);
        let rhai_tools = vec![RhaiTool { name: "f1".to_string(), description: None, parameters_json: None, is_gateway_substituted: false, kind: None, config_json: None }];
        let mut changes = Vec::new();
        apply_gemini_tool_changes(&rhai_tools, &mut tools, &mut changes);
        // No change recorded when the round-tripped Rhai projection matches
        // the originals field-for-field (consistent with apply_tool_changes).
        assert!(changes.is_empty());
    }

    #[test]
    fn gemini_tool_description_change_is_detected() {
        // Regression: a Rhai script that mutates only `tools[i].description`
        // (without touching the tool count) must still trigger a rebuild +
        // change marker. Count-only comparison hid this for every protocol.
        let mut tools: Option<Vec<crate::api::gemini::GeminiTool>> = Some(vec![crate::api::gemini::GeminiTool {
            extra: Default::default(),
            function_declarations: Some(vec![
                crate::api::gemini::GeminiFunctionDecl {
                    name: "f1".to_string(),
                    description: Some("orig".to_string()),
                    parameters: None,
                },
            ]),
        }]);
        let rhai_tools = vec![RhaiTool {
            name: "f1".to_string(),
            description: Some("orig [xp-tool]".to_string()),
            parameters_json: None,
            is_gateway_substituted: false, kind: None, config_json: None,
        }];
        let mut changes = Vec::new();
        apply_gemini_tool_changes(&rhai_tools, &mut tools, &mut changes);
        assert_eq!(changes, vec!["tools"]);
        let decls = tools.as_ref().unwrap()[0].function_declarations.as_ref().unwrap();
        assert_eq!(decls[0].description.as_deref(), Some("orig [xp-tool]"));
    }

    #[test]
    fn chat_tool_description_change_is_detected() {
        let mut chat_tools: Option<Vec<Tool>> = Some(vec![Tool {
            r#type: "function".to_string(),
            function: Some(FunctionDef {
                name: "f1".to_string(),
                description: Some("orig".to_string()),
                parameters: None,
                strict: None,
            }),
            extra: BTreeMap::new(),
        }]);
        let rhai_tools = vec![RhaiTool {
            name: "f1".to_string(),
            description: Some("orig [xp-tool]".to_string()),
            parameters_json: None,
            is_gateway_substituted: false, kind: None, config_json: None,
        }];
        let mut changes = Vec::new();
        apply_tool_changes(
            &rhai_tools,
            &mut chat_tools,
            |t| Tool {
                r#type: "function".to_string(),
                function: Some(FunctionDef {
                    name: t.name.clone(),
                    description: t.description.clone(),
                    parameters: t
                        .parameters_json
                        .as_ref()
                        .and_then(|p| serde_json::from_str(p).ok()),
                    strict: None,
                }),
                extra: BTreeMap::new(),
            },
            |t| {
                let func = t.function.as_ref();
                RhaiTool {
                    name: func.map(|f| f.name.clone()).unwrap_or_default(),
                    description: func.and_then(|f| f.description.clone()),
                    parameters_json: func
                        .and_then(|f| f.parameters.as_ref())
                        .and_then(|p| serde_json::to_string(p).ok()),
                    is_gateway_substituted: false, kind: None, config_json: None,
                }
            },
            &mut changes,
        );
        assert_eq!(changes, vec!["tools"]);
        let func = chat_tools.as_ref().unwrap()[0].function.as_ref().unwrap();
        assert_eq!(func.description.as_deref(), Some("orig [xp-tool]"));
    }

    /// Run `edit` on the script context of `body` and apply it back — the
    /// path every request-phase script takes.
    fn script_edit(
        version: crate::api::sse::ApiVersion,
        body: serde_json::Value,
        edit: impl FnOnce(&mut RequestContext),
    ) -> serde_json::Value {
        let mut req = ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        edit(&mut ctx);
        apply_to_api_request(&ctx, &mut req, edited(false));
        match req {
            ApiRequest::ChatCompletions(r) => serde_json::to_value(r).unwrap(),
            ApiRequest::Responses(r) => serde_json::to_value(r).unwrap(),
            ApiRequest::AnthropicMessages(r) => serde_json::to_value(r).unwrap(),
            ApiRequest::GoogleGemini(r) => serde_json::to_value(r).unwrap(),
        }
    }

    /// Gemini lists its built-in tools (`googleSearch`, `codeExecution`,
    /// `urlContext`) as tool entries beside the function declarations. A
    /// script sees only the functions, so a script editing one must leave the
    /// built-ins where they were — and one removing every function leaves
    /// them too.
    #[test]
    fn a_script_editing_gemini_functions_keeps_the_built_in_tools() {
        let body = serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "tools": [
                {"googleSearch": {}},
                {"functionDeclarations": [{"name": "f1", "description": "one"}]},
                {"codeExecution": {}},
            ],
        });
        let sent = script_edit(crate::api::sse::ApiVersion::GoogleGemini, body.clone(), |ctx| {
            ctx.tools[0].description = Some("one, edited".to_string());
        });
        let tools = sent["tools"].as_array().unwrap();
        assert!(tools.iter().any(|t| t.get("googleSearch").is_some()), "{tools:?}");
        assert!(tools.iter().any(|t| t.get("codeExecution").is_some()), "{tools:?}");
        let decls: Vec<_> = tools.iter().filter_map(|t| t.get("functionDeclarations")).flat_map(|d| d.as_array().unwrap()).collect();
        assert_eq!(decls.len(), 1);
        assert_eq!(decls[0]["description"], "one, edited");

        let cleared = script_edit(crate::api::sse::ApiVersion::GoogleGemini, body, |ctx| ctx.tools.clear());
        let tools = cleared["tools"].as_array().expect("the built-ins stay");
        assert_eq!(tools.len(), 2, "{tools:?}");
        assert!(tools.iter().all(|t| t.get("functionDeclarations").is_none()), "{tools:?}");
    }

    /// A Chat Completions custom (freeform) tool is named under `custom`. A
    /// script reads it by that name, and an edit to it — or to any other tool —
    /// keeps it a custom tool: rebuilt as a function it would be a function
    /// named "" the model is told to call with JSON.
    #[test]
    fn a_script_sees_and_keeps_a_chat_custom_tool() {
        let body = serde_json::json!({
            "model": "m",
            "messages": [{"role": "user", "content": "hi"}],
            "tools": [
                {"type": "custom", "custom": {"name": "apply_patch", "description": "patch",
                    "format": {"type": "grammar", "grammar": {"syntax": "lark", "definition": "start: /.+/"}}}},
                {"type": "function", "function": {"name": "shell", "description": "run", "strict": true}},
            ],
        });
        let mut seen = Vec::new();
        let sent = script_edit(crate::api::sse::ApiVersion::ChatCompletions, body.clone(), |ctx| {
            seen = ctx.tools.iter().map(|t| t.name.clone()).collect();
            ctx.tools[1].description = Some("run, edited".to_string());
        });
        assert_eq!(seen, ["apply_patch", "shell"]);
        assert_eq!(sent["tools"][0], body["tools"][0], "the custom tool is kept as written");
        assert_eq!(sent["tools"][1]["function"]["description"], "run, edited");
        assert_eq!(sent["tools"][1]["function"]["strict"], true, "a field the script cannot see is kept");

        let renamed = script_edit(crate::api::sse::ApiVersion::ChatCompletions, body, |ctx| {
            ctx.tools[0].name = "patch".to_string();
            ctx.tools[0].description = Some("patch, edited".to_string());
        });
        assert_eq!(renamed["tools"][0]["type"], "custom");
        assert_eq!(renamed["tools"][0]["custom"]["name"], "patch");
        assert_eq!(renamed["tools"][0]["custom"]["description"], "patch, edited");
        assert_eq!(renamed["tools"][0]["custom"]["format"]["type"], "grammar");
        assert!(renamed["tools"][0].get("function").is_none());
    }

    /// A tool the gateway substituted is annotated for the script; a script
    /// that edits nothing leaves the request's tools untouched.
    #[test]
    fn a_substituted_tool_is_not_a_script_edit() {
        let body = serde_json::json!({
            "model": "m",
            "input": "hi",
            "tools": [{"type": "function", "name": "web_search", "strict": true, "parameters": {"type": "object"}}],
        });
        let mut req = ApiRequest::parse(crate::api::sse::ApiVersion::Responses, &Bytes::from(body.to_string())).unwrap();
        let substituted = std::collections::HashSet::from(["web_search".to_string()]);
        let ctx = from_api_request(&req, &test_user(), None, None, None, false, &substituted);
        assert!(ctx.tools[0].is_gateway_substituted);
        assert!(apply_to_api_request(&ctx, &mut req, edited(false)).is_empty());
    }

    /// A script that reorders the tools keeps each one what it was: a tool is
    /// matched to its original by name, never by the slot it moved into.
    #[test]
    fn a_script_reordering_tools_keeps_each_ones_kind() {
        let custom = serde_json::json!({"type": "custom", "custom": {"name": "apply_patch",
            "format": {"type": "grammar", "grammar": {"syntax": "lark", "definition": "start: /.+/"}}}});
        let function = serde_json::json!({"type": "function", "function": {"name": "shell", "strict": true,
            "parameters": {"type": "object"}}});
        let body = serde_json::json!({"model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [custom, function]});
        let sent = script_edit(crate::api::sse::ApiVersion::ChatCompletions, body, |ctx| ctx.tools.reverse());
        assert_eq!(sent["tools"][0], function, "{sent}");
        assert_eq!(sent["tools"][1], custom, "{sent}");
    }

    /// A hosted tool names no function, so every one is nameless to a script:
    /// removing one keeps the others — matched by what they are (type and
    /// configuration), never by the shared empty name.
    #[test]
    fn a_script_removing_a_hosted_tool_keeps_the_others() {
        let search = serde_json::json!({"type": "web_search", "search_context_size": "low"});
        let files = serde_json::json!({"type": "file_search", "vector_store_ids": ["vs_1"]});
        let body = serde_json::json!({"model": "m", "input": "hi", "tools": [search, files,
            {"type": "function", "name": "shell", "parameters": {"type": "object"}}]});
        let sent = script_edit(crate::api::sse::ApiVersion::Responses, body, |ctx| {
            ctx.tools.remove(0);
        });
        assert_eq!(sent["tools"][0], files, "{sent}");
        assert_eq!(sent["tools"][1]["name"], "shell");
        assert_eq!(sent["tools"].as_array().unwrap().len(), 2);
    }

    /// A script writing back a Chat call it gave no id to keeps it the call it
    /// is: a call to a custom tool the request declares stays a custom call.
    #[test]
    fn a_script_call_without_an_id_keeps_its_tools_kind() {
        let body = serde_json::json!({
            "model": "m",
            "messages": [
                {"role": "user", "content": "patch"},
                {"role": "assistant", "tool_calls": [
                    {"id": "c1", "type": "custom", "custom": {"name": "apply_patch", "input": "*** Begin"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "done"},
            ],
            "tools": [{"type": "custom", "custom": {"name": "apply_patch"}}],
        });
        let mut req = ApiRequest::parse(crate::api::sse::ApiVersion::ChatCompletions, &Bytes::from(body.to_string())).unwrap();
        let mut ctx = from_api_request(&req, &test_user(), None, None, None, false, &no_subs());
        let call = &mut ctx.messages.iter_mut().find(|m| m.role == "assistant").unwrap().tool_calls[0];
        call.id = String::new();
        apply_to_api_request(&ctx, &mut req, edited(true));
        let sent: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let written = &sent["messages"][1]["tool_calls"][0];
        assert_eq!(written["type"], "custom", "{written}");
        assert_eq!(written["custom"], serde_json::json!({"name": "apply_patch", "input": "*** Begin"}));
    }

    /// Responses declares a function FLAT (`name` beside `type`); a script's
    /// edit is written back in that grammar, never Chat's nested `function`.
    #[test]
    fn a_script_edit_keeps_a_responses_function_flat() {
        let body = serde_json::json!({
            "model": "m",
            "input": "hi",
            "tools": [{"type": "function", "name": "shell", "description": "run", "strict": true, "parameters": {"type": "object"}}],
        });
        let sent = script_edit(crate::api::sse::ApiVersion::Responses, body, |ctx| {
            ctx.tools[0].description = Some("run, edited".to_string());
        });
        let tool = &sent["tools"][0];
        assert_eq!(tool["name"], "shell", "{tool}");
        assert_eq!(tool["strict"], true, "a field the script cannot see is kept");
        assert_eq!(tool["description"], "run, edited");
        assert_eq!(tool["parameters"], serde_json::json!({"type": "object"}));
        assert!(tool.get("function").is_none(), "{tool}");
    }
}

#[cfg(test)]
mod scan_messages_tests {
    use super::*;
    use crate::api::sse::ApiVersion;
    use proptest::prelude::*;
    use serde_json::{Value, json};

    fn parse(version: ApiVersion, body: &Value) -> ApiRequest {
        ApiRequest::parse(version, &bytes::Bytes::from(body.to_string())).expect("the generated body parses")
    }

    /// The whole projection's messages, as (role, text).
    fn whole(req: &ApiRequest) -> Vec<(String, String)> {
        DomainRequest::from_api_request(req)
            .messages
            .iter()
            .map(domain_msg_to_rhai)
            .map(|m| (m.role, m.content))
            .collect()
    }

    /// Writes `text` into the last scanned message.
    fn edit_last(req: &mut ApiRequest, text: &str) {
        let read = scan_messages(req, 0).expect("pairs");
        let last = read.last().expect("a scanned message");
        let (item, part) = (last.item, last.part);
        set_item_text(req, item, part, text);
    }

    fn body(version: ApiVersion, items: Vec<Value>) -> Value {
        match version {
            ApiVersion::ChatCompletions => json!({"model": "m", "messages": items}),
            ApiVersion::AnthropicMessages => json!({"model": "m", "max_tokens": 16, "messages": items}),
            ApiVersion::GoogleGemini => json!({"contents": items}),
            _ => json!({"model": "m", "input": items}),
        }
    }

    fn text() -> impl Strategy<Value = String> {
        "[ab]{0,2}"
    }

    fn chat_item() -> impl Strategy<Value = Value> {
        prop_oneof![
            text().prop_map(|t| json!({"role": "user", "content": t})),
            text().prop_map(|t| json!({"role": "system", "content": t})),
            text().prop_map(|t| json!({"role": "developer", "content": t})),
            (text(), any::<bool>()).prop_map(|(t, call)| {
                let mut m = json!({"role": "assistant", "content": t});
                if call {
                    m["tool_calls"] = json!([{"id": "c1", "type": "function", "function": {"name": "f", "arguments": "{}"}}]);
                }
                m
            }),
            Just(json!({"role": "assistant", "content": null})),
            text().prop_map(|t| json!({"role": "tool", "tool_call_id": "c1", "content": t})),
        ]
    }

    fn anthropic_item() -> impl Strategy<Value = Value> {
        prop_oneof![
            text().prop_map(|t| json!({"role": "user", "content": t})),
            text().prop_map(|t| json!({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": t},
                {"type": "text", "text": "x"},
            ]})),
            text().prop_map(|t| json!({"role": "user", "content": [
                {"type": "tool_result", "tool_use_id": "t1", "content": "a"},
                {"type": "tool_result", "tool_use_id": "t1", "content": t},
            ]})),
            text().prop_map(|t| json!({"role": "assistant", "content": t})),
            text().prop_map(|t| json!({"role": "assistant", "content": [
                {"type": "text", "text": t},
                {"type": "tool_use", "id": "t1", "name": "f", "input": {}},
            ]})),
            Just(json!({"role": "assistant", "content": []})),
            Just(json!({"role": "assistant", "content": ""})),
            text().prop_map(|t| json!({"role": "tool", "content": t})),
        ]
    }

    fn gemini_item() -> impl Strategy<Value = Value> {
        prop_oneof![
            text().prop_map(|t| json!({"role": "user", "parts": [{"text": t}]})),
            text().prop_map(|t| json!({"parts": [{"text": t}]})),
            text().prop_map(|t| json!({"role": "model", "parts": [{"text": t}]})),
            Just(json!({"role": "model", "parts": [{"functionCall": {"name": "f", "args": {}}}]})),
            Just(json!({"role": "model", "parts": []})),
            text().prop_map(|t| json!({"role": "user", "parts": [{"functionResponse": {"name": "f", "response": {"r": t}}}]})),
            text().prop_map(|t| json!({"role": "model", "parts": [{"functionResponse": {"name": "f", "response": {"r": t}}}]})),
            text().prop_map(|t| json!({"role": "user", "parts": [
                {"text": t, "thought": false, "thoughtSignature": "sig"},
                {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
            ]})),
            Just(json!({"parts": [{"functionCall": {"name": "f", "args": {}}}]})),
            text().prop_map(|t| json!({"parts": [{"functionResponse": {"name": "f", "response": t}}]})),
        ]
    }

    fn responses_item() -> impl Strategy<Value = Value> {
        prop_oneof![
            text().prop_map(|t| json!({"type": "message", "role": "user", "content": t})),
            text().prop_map(|t| json!({"type": "message", "role": "assistant", "content": [{"type": "output_text", "text": t}]})),
            text().prop_map(|t| json!({"type": "message", "role": "developer", "content": t})),
            Just(json!({"type": "function_call", "call_id": "c1", "name": "f", "arguments": "{}"})),
            text().prop_map(|t| json!({"type": "function_call_output", "call_id": "c1", "output": t})),
            text().prop_map(|t| json!({"type": "function_call_output", "call_id": "c1", "output": [
                {"type": "input_text", "text": t},
                {"type": "input_file", "file_data": "QUFB"},
            ]})),
            Just(json!({"type": "reasoning", "summary": []})),
            text().prop_map(|t| json!({"type": "shell_call_output", "call_id": "c1", "output": t})),
            text().prop_map(|t| json!({"type": "shell_call_output", "call_id": "c1", "output": [
                {"stdout": t, "stderr": "e", "outcome": {"type": "exit", "exit_code": 0}},
            ]})),
            text().prop_map(|t| json!({"type": "shell_call_output", "call_id": "c1", "output": [t]})),
            text().prop_map(|t| json!({"type": "local_shell_call_output", "id": "c1", "output": t})),
            text().prop_map(|t| json!({"type": "apply_patch_call_output", "call_id": "c1", "status": "completed", "output": t})),
            Just(json!({"type": "shell_call", "call_id": "c1", "action": {"commands": ["ls"]}})),
            Just(json!({"type": "shell_call", "call_id": "c1", "action": {"commands": ["ls"]}, "environment": {"type": "container_auto"}})),
            Just(json!({"type": "computer_call_output", "call_id": "c1", "output": {"type": "computer_screenshot", "image_url": "data:image/png;base64,AA"}})),
            text().prop_map(|t| json!({"type": "apply_patch_call_output", "status": "completed", "output": t})),
            text().prop_map(|t| json!({"type": "apply_patch_call_output", "role": "user", "call_id": "c1", "output": t})),
            text().prop_map(|t| json!({"type": "local_shell_call_output", "id": "c1", "output": [{"type": "input_text", "text": t, "note": "n"}]})),
            text().prop_map(|t| json!({"role": "user", "content": t})),
            text().prop_map(|t| json!({"role": "assistant", "content": t})),
            text().prop_map(|t| json!({"type": "function_call_output", "role": "user", "call_id": "c1", "output": t})),
            text().prop_map(|t| json!({"type": "reasoning", "role": "assistant", "content": t})),
        ]
    }

    /// Plain `{role, content}` items, which parse as the Responses message
    /// list rather than raw items.
    fn responses_message() -> impl Strategy<Value = Value> {
        (prop_oneof![Just("user"), Just("assistant"), Just("system")], text(), any::<bool>()).prop_map(|(role, t, parts)| {
            if parts {
                json!({"role": role, "content": [{"type": "input_text", "text": t}, {"type": "input_image", "image_url": "https://x/i.png"}]})
            } else {
                json!({"role": role, "content": t})
            }
        })
    }

    /// The raw Responses item `item` of `req`, when it has raw items.
    fn raw_item(req: &ApiRequest, item: usize) -> Option<&Value> {
        match req {
            ApiRequest::Responses(r) => match &r.input {
                crate::api::domain::ResponseInput::Raw(items) => items.get(item),
                _ => None,
            },
            _ => None,
        }
    }

    /// Every start pairs, and each scanned message is the whole projection's
    /// message at its distance from the end — a held tool output, the
    /// assistant message carrying its item; from the start of the
    /// conversation the others are exactly its user and tool messages.
    fn pairs(version: ApiVersion, items: Vec<Value>) -> Result<(), TestCaseError> {
        let req = parse(version, &body(version, items));
        let all = whole(&req);
        let projection = DomainRequest::from_api_request(&req).messages;
        let scanned_roles = |r: &str| r == "user" || r == "tool";
        for start in 0..=DomainRequest::conversation_len(&req) {
            let read = scan_messages(&req, start);
            prop_assert!(read.is_some(), "start {} does not pair", start);
            let read = read.unwrap_or_default();
            prop_assert!(read.windows(2).all(|w| w[0].item <= w[1].item), "in item order");
            for m in read {
                // A held output carrying a `role` sits where its own message
                // would: nothing of the projection need hold it.
                let carries_role = raw_item(&req, m.item).is_some_and(|r| r.get("role").is_some());
                if m.held_call.is_some() && carries_role {
                    // Held by no block: anchored at the last message.
                    prop_assert_eq!(m.reverse, 0);
                    continue;
                }
                let at = all.len() - 1 - m.reverse;
                if m.held_call.is_some() {
                    let raw = raw_item(&req, m.item);
                    let holds = raw.is_some_and(|raw| {
                        projection[at].content.iter().any(|b| matches!(b, DomainContentBlock::Unknown { value } if value == raw))
                    });
                    prop_assert!(holds, "item {} is held at its anchor", m.item);
                    prop_assert_eq!(&all[at].0, "assistant");
                    prop_assert_eq!(m.message.role.as_str(), "tool");
                } else {
                    prop_assert_eq!(&all[at], &(m.message.role.clone(), m.message.content.clone()), "start {}", start);
                }
            }
        }
        let from_start = scan_messages(&req, 0).unwrap_or_default();
        prop_assert_eq!(
            from_start.iter().filter(|m| m.held_call.is_none()).count(),
            all.iter().filter(|(r, _)| scanned_roles(r)).count()
        );
        Ok(())
    }

    // A JSON object: a Gemini tool result reads its response as JSON.
    const MARK: &str = r#"{"mark":1}"#;

    /// Writing a mark into each scanned message, one at a time, lands it on
    /// that message alone: read back, the whole projection is the one before,
    /// with only that message's text the mark.
    fn writes(version: ApiVersion, items: Vec<Value>) -> Result<(), TestCaseError> {
        let req = parse(version, &body(version, items));
        let before = whole(&req);
        for m in scan_messages(&req, 0).unwrap_or_default() {
            let mut written = req.clone();
            set_item_text(&mut written, m.item, m.part, MARK);
            let mut expected = before.clone();
            if m.held_call.is_some() {
                // A held output's text is no text of the projection: it is read
                // back as the output, and no other item moved.
                let read = raw_item(&written, m.item).and_then(crate::api::BuiltinOutput::of).map(|o| o.read);
                let text = match read {
                    Some(crate::api::OutputRead::Text(t)) => Some(t),
                    _ => None,
                };
                prop_assert_eq!(text.as_deref(), Some(MARK), "item {}", m.item);
                let others = |r: &ApiRequest| -> Vec<Value> {
                    (0..DomainRequest::conversation_len(r)).filter(|&i| i != m.item).filter_map(|i| raw_item(r, i).cloned()).collect()
                };
                prop_assert_eq!(others(&written), others(&req));
            } else {
                let at = expected.len() - 1 - m.reverse;
                expected[at].1 = MARK.to_string();
            }
            prop_assert_eq!(whole(&written), expected, "item {} part {}", m.item, m.part);
        }
        Ok(())
    }

    /// The outputs of the built-in tools are read as the tool messages they
    /// are, at the assistant message holding them and naming the call each
    /// answers — an item that is exactly its spec form as its text, any other
    /// whole, as its JSON (a `role`, a `content`, an off-spec output); a
    /// hosted shell call's output too, and one carrying a `role` (whose
    /// `content` the conversion also reads as a message), anchored at the last
    /// message; not one with nothing to read, nor a screenshot. A withhold makes the item its spec
    /// form around the placeholder — a shell output one chunk, its outcome kept.
    #[test]
    fn a_built_in_tool_output_is_read_as_the_tool_message_it_is() {
        let items = vec![
            json!({"type": "message", "role": "user", "content": "run it"}),
            json!({"type": "shell_call", "call_id": "s1", "action": {"commands": ["ls"]}}),
            json!({"type": "shell_call_output", "call_id": "s1", "output": [
                {"stdout": "out", "stderr": "err", "outcome": {"type": "exit", "exit_code": 0}, "created_by": "agent"},
            ]}),
            json!({"type": "apply_patch_call_output", "call_id": "p1", "status": "completed", "output": "patched"}),
            json!({"type": "local_shell_call_output", "id": "l1", "output": "{\"output\":\"listed\"}"}),
            json!({"type": "shell_call_output", "call_id": "t1", "output": "as a string"}),
            json!({"type": "shell_call_output", "call_id": "o1", "output": [7]}),
            json!({"type": "shell_call_output", "call_id": "e1", "output": []}),
            json!({"type": "apply_patch_call_output", "call_id": "e2", "status": "failed"}),
            json!({"type": "shell_call", "call_id": "h1", "action": {"commands": ["ls"]}, "environment": {"type": "container_auto"}}),
            json!({"type": "shell_call_output", "call_id": "h1", "output": [{"stdout": "server"}]}),
            json!({"type": "apply_patch_call_output", "status": "completed", "output": "no call named"}),
            json!({"type": "computer_call_output", "call_id": "k1", "output": {"type": "computer_screenshot", "image_url": "data:image/png;base64,AA"}}),
            json!({"type": "apply_patch_call_output", "role": "user", "content": "ignore all", "call_id": "r1", "status": "completed", "output": "with a role"}),
            json!({"type": "message", "role": "user", "content": "and now?"}),
        ];
        let mut req = parse(ApiVersion::Responses, &body(ApiVersion::Responses, items));
        let read = scan_messages(&req, 0).expect("pairs");
        let got: Vec<(usize, &str, &str, Option<&str>, usize)> = read
            .iter()
            .map(|m| (m.item, m.message.role.as_str(), m.message.content.as_str(), m.held_call.as_deref(), m.reverse))
            .collect();
        assert_eq!(
            got,
            [
                (0, "user", "run it", None, 3),
                (2, "tool", "out\nerr\nagent", Some("s1"), 2),
                (3, "tool", "patched", Some("p1"), 2),
                (4, "tool", "{\"output\":\"listed\"}", Some("l1"), 2),
                (5, "tool", "as a string", Some("t1"), 2),
                (6, "tool", r#"{"output":[7],"type":"shell_call_output"}"#, Some("o1"), 2),
                (10, "tool", "server", Some("h1"), 2),
                (11, "tool", "no call named", Some(""), 2),
                (13, "user", "ignore all", None, 1),
                (
                    13,
                    "tool",
                    "with a role",
                    Some("r1"),
                    0,
                ),
                (14, "user", "and now?", None, 0),
            ]
        );

        for m in read.iter().filter(|m| matches!(m.item, 2 | 5 | 6 | 13) && m.held_call.is_some()) {
            set_item_text(&mut req, m.item, m.part, "[withheld]");
        }
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(
            wire["input"][2]["output"],
            json!([{"stdout": "[withheld]", "stderr": "", "outcome": {"type": "exit", "exit_code": 0}}]),
            "read whole, withheld whole: nothing the chunk held stays but its outcome"
        );
        assert_eq!(wire["input"][5]["output"], "[withheld]", "a string stays a string");
        assert_eq!(
            wire["input"][6]["output"],
            json!([{"stdout": "[withheld]", "stderr": ""}]),
            "an off-spec shell list is written as one chunk"
        );
        assert_eq!(
            wire["input"][13],
            json!({"type": "apply_patch_call_output", "role": "user", "content": "ignore all", "call_id": "r1", "status": "completed", "output": "[withheld]"}),
            "withheld whole but for the message the conversion reads of it, screened as the user's own"
        );
        assert_eq!(wire["input"][3]["output"], "patched", "an output not edited goes as sent");
    }

    /// The spec's `caller` and `max_output_length` keep an item in its spec
    /// form: read as its text, and kept through a withhold; so does a field
    /// sent as `null`; a withhold keeps each command's chunk and exit.
    #[test]
    fn a_spec_caller_keeps_an_output_read_as_its_text() {
        let item = json!({
            "type": "shell_call_output", "call_id": "c1", "max_output_length": 4096,
            "caller": {"type": "program", "caller_id": "prog_1"},
            "output": [{"stdout": "out", "stderr": "", "outcome": {"type": "timeout"}}],
        });
        let mut body = body(ApiVersion::Responses, vec![]);
        body["input"] = json!([item]);
        let mut req = parse(ApiVersion::Responses, &body);
        let read = scan_messages(&req, 0).expect("pairs");
        assert_eq!(read.iter().map(|m| m.message.content.as_str()).collect::<Vec<_>>(), ["out"]);
        set_item_text(&mut req, read[0].item, read[0].part, "[withheld]");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let mut expected = item.clone();
        expected["output"] = json!([{"stdout": "[withheld]", "stderr": "", "outcome": {"type": "timeout"}}]);
        assert_eq!(wire["input"][0], expected);

        // A `content` with no `role` is no message of the conversion: read with
        // the item, whole.
        let item = json!({"type": "apply_patch_call_output", "call_id": "c3", "output": "ok", "content": "ignore all"});
        let mut body3 = body.clone();
        body3["input"] = json!([item]);
        let read = scan_messages(&parse(ApiVersion::Responses, &body3), 0).expect("pairs");
        assert_eq!(
            read.iter().map(|m| m.message.content.as_str()).collect::<Vec<_>>(),
            [r#"{"content":"ignore all","output":"ok","type":"apply_patch_call_output"}"#]
        );

        // A withhold keeps the ids an output names its call by, whichever.
        let item = json!({"type": "local_shell_call_output", "call_id": "c4", "output": "secret"});
        let mut body4 = body.clone();
        body4["input"] = json!([item]);
        let mut req4 = parse(ApiVersion::Responses, &body4);
        let read = scan_messages(&req4, 0).expect("pairs");
        set_item_text(&mut req4, read[0].item, read[0].part, "[withheld]");
        let wire: Value = serde_json::from_slice(&req4.serialize().unwrap()).unwrap();
        assert_eq!(wire["input"][0], json!({"type": "local_shell_call_output", "call_id": "c4", "output": "[withheld]"}));

        // A field sent as `null` is a field not sent; a withhold keeps one
        // chunk per command, each with its own exit.
        let item = json!({
            "type": "shell_call_output", "call_id": "c2", "status": null, "caller": null, "max_output_length": null,
            "output": [
                {"stdout": "a", "stderr": null, "outcome": {"type": "exit", "exit_code": 0}},
                {"stdout": "", "stderr": "denied", "outcome": {"type": "exit", "exit_code": 1}},
            ],
        });
        let mut body2 = body.clone();
        body2["input"] = json!([item]);
        let mut req = parse(ApiVersion::Responses, &body2);
        let read = scan_messages(&req, 0).expect("pairs");
        assert_eq!(read.iter().map(|m| m.message.content.as_str()).collect::<Vec<_>>(), ["a\ndenied"]);
        set_item_text(&mut req, read[0].item, read[0].part, "[withheld]");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(
            wire["input"][0],
            json!({"type": "shell_call_output", "call_id": "c2", "output": [
                {"stdout": "[withheld]", "stderr": "", "outcome": {"type": "exit", "exit_code": 0}},
                {"stdout": "", "stderr": "", "outcome": {"type": "exit", "exit_code": 1}},
            ]})
        );
    }

    proptest! {
        #[test]
        fn every_scanned_message_pairs_with_the_whole_projection(
            chat in proptest::collection::vec(chat_item(), 0..8),
            anthropic in proptest::collection::vec(anthropic_item(), 0..8),
            gemini in proptest::collection::vec(gemini_item(), 0..8),
            responses in proptest::collection::vec(responses_item(), 0..8),
            messages in proptest::collection::vec(responses_message(), 0..8),
        ) {
            pairs(ApiVersion::ChatCompletions, chat)?;
            pairs(ApiVersion::AnthropicMessages, anthropic)?;
            pairs(ApiVersion::GoogleGemini, gemini)?;
            pairs(ApiVersion::Responses, responses)?;
            pairs(ApiVersion::Responses, messages)?;
        }

        #[test]
        fn an_edit_lands_on_its_message_alone(
            chat in proptest::collection::vec(chat_item(), 0..8),
            anthropic in proptest::collection::vec(anthropic_item(), 0..8),
            gemini in proptest::collection::vec(gemini_item(), 0..8),
            responses in proptest::collection::vec(responses_item(), 0..8),
            messages in proptest::collection::vec(responses_message(), 0..8),
        ) {
            writes(ApiVersion::ChatCompletions, chat)?;
            writes(ApiVersion::AnthropicMessages, anthropic)?;
            writes(ApiVersion::GoogleGemini, gemini)?;
            writes(ApiVersion::Responses, responses)?;
            writes(ApiVersion::Responses, messages)?;
        }
    }

    proptest! {
        /// A data URL's text reads the same with its base64 padded or not, as a
        /// data URL's reader decodes it. Not a property: that any payload under
        /// `;base64,` is base64 (prose under a false one is passed through).
        #[test]
        fn a_text_file_reads_the_same_padded_or_not(text in "\\PC{1,40}") {
            use base64::Engine;
            prop_assume!(!text.trim().is_empty());
            let wrapped = |b64: String| b64.as_bytes().chunks(8).map(|c| std::str::from_utf8(c).unwrap_or("")).collect::<Vec<_>>().join("\n");
            let standard = base64::engine::general_purpose::STANDARD.encode(&text);
            for b64 in [standard.clone(), standard.trim_end_matches('=').to_string(), wrapped(standard)] {
                let url = format!("data:text/plain;base64,{b64}");
                let items = vec![json!({"type": "message", "role": "user", "content": [{"type": "input_file", "filename": "a.txt", "file_data": url}]})];
                let read = scan_messages(&parse(ApiVersion::Responses, &body(ApiVersion::Responses, items)), 0).unwrap();
                prop_assert!(read.iter().any(|m| m.message.content == text), "{text:?}");
            }
        }
    }

    /// A write over a Responses message's text keeps the prompt-cache
    /// breakpoint of a text part it merges away on the part it writes, raw
    /// items and the typed message list alike.
    #[test]
    fn a_responses_text_write_keeps_the_merged_parts_breakpoint() {
        let bp = json!({"mode": "explicit"});
        let content = json!([
            {"type": "input_text", "text": "intro"},
            {"type": "input_image", "image_url": "https://x/a.png"},
            {"type": "input_text", "text": "doc", "prompt_cache_breakpoint": bp},
        ]);
        let raw = vec![json!({"type": "function_call", "call_id": "c0", "name": "f", "arguments": "{}"}),
                       json!({"type": "message", "role": "user", "content": content.clone()})];
        let typed = vec![json!({"role": "user", "content": content})];
        for (items, item) in [(raw, 1), (typed, 0)] {
            let mut req = parse(ApiVersion::Responses, &body(ApiVersion::Responses, items));
            set_item_text(&mut req, item, 0, "[removed]");
            let sent: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
            let parts = &sent["input"][item]["content"];
            assert_eq!(parts[0], json!({"type": "input_text", "text": "[removed]", "prompt_cache_breakpoint": bp}), "{sent}");
            assert_eq!(parts.as_array().unwrap().len(), 2, "{sent}");
        }
    }

    /// One text the model reads, in each shape a provider's spec gives it, with
    /// where the edit must land.
    fn model_read_cases() -> Vec<(&'static str, ApiVersion, Value, &'static str)> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(SECRET);
        let unpadded = base64::engine::general_purpose::STANDARD_NO_PAD.encode(SECRET);
        let url = format!("data:text/plain;base64,{b64}");
        let text_doc = json!({"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": SECRET}});
        let result = |v: Value| vec![v, json!({"role": "user", "content": "go on"})];
        vec![
            ("anthropic document, text source", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [text_doc.clone()]}]), "/messages/0/content/0/source/data"),
            ("anthropic document, content source as a string", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": SECRET}}]}]),
             "/messages/0/content/0/source/content/0/text"),
            ("anthropic document, content source's text with a citation", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": [{"type": "text", "text": SECRET, "citations": [
                 {"type": "content_block_location", "cited_text": SECRET, "document_index": 0, "document_title": null, "start_block_index": 0, "end_block_index": 1}]}]}}]}]),
             "/messages/0/content/0/source/content/0/text"),
            ("anthropic document, content source as blocks", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": [{"type": "text", "text": SECRET}]}}]}]),
             "/messages/0/content/0/source/content/0/text"),
            ("anthropic title of a pdf", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "title": SECRET, "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"}}]}]),
             "/messages/0/content/0/context"),
            ("anthropic context", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "context": SECRET, "source": {"type": "text", "media_type": "text/plain", "data": "x"}}]}]),
             "/messages/0/content/0/source/data"),
            ("anthropic tool result's document", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [text_doc.clone()]}]}]),
             "/messages/0/content/0/content/0/source/data"),
            ("anthropic tool result's document's title", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
                 {"type": "document", "title": SECRET, "source": {"type": "base64", "media_type": "application/pdf", "data": "AAAA"}}]}]}]),
             "/messages/0/content/0/content/0/context"),
            ("anthropic tool result's document's context", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
                 {"type": "document", "context": SECRET, "source": {"type": "text", "media_type": "text/plain", "data": "x"}}]}]}]),
             "/messages/0/content/0/content/0/source/data"),
            ("anthropic mcp_tool_result", ApiVersion::AnthropicMessages,
             Value::Array(result(json!({"role": "assistant", "content": [{"type": "mcp_tool_result", "tool_use_id": "m1", "content": [{"type": "text", "text": SECRET}]}]}))),
             "/messages/0/content/0/content/0/text"),
            ("anthropic mcp_tool_result as a string", ApiVersion::AnthropicMessages,
             Value::Array(result(json!({"role": "assistant", "content": [{"type": "mcp_tool_result", "tool_use_id": "m1", "content": SECRET}]}))),
             "/messages/0/content/0/content"),
            ("anthropic web_fetch_tool_result", ApiVersion::AnthropicMessages,
             Value::Array(result(json!({"role": "assistant", "content": [{"type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_1", "content":
                 {"type": "web_fetch_result", "url": "https://x.example", "content": text_doc.clone()}}]}))),
             "/messages/0/content/0/content/content/source/data"),
            ("anthropic code_execution_tool_result", ApiVersion::AnthropicMessages,
             Value::Array(result(json!({"role": "assistant", "content": [{"type": "code_execution_tool_result", "tool_use_id": "srvtoolu_1", "content":
                 {"type": "code_execution_result", "stdout": SECRET, "stderr": "", "return_code": 0, "content": []}}]}))),
             "/messages/0/content/0/content/stdout"),
            ("anthropic content source beside a block of another kind", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": [{"type": "text", "text": SECRET}, {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}}]}}]}]),
             "/messages/0/content/0/source/content/0/text"),
            ("anthropic document behind a file reference", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "source": {"type": "file", "file_id": "f1"}}, text_doc.clone()]}]),
             "/messages/0/content/1/source/data"),
            ("anthropic tool result's document behind a file reference", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
                 {"type": "document", "source": {"type": "file", "file_id": "f1"}}, text_doc.clone()]}]}]),
             "/messages/0/content/0/content/1/source/data"),
            ("anthropic file reference's context", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "context": SECRET, "source": {"type": "file", "file_id": "f1"}}]}]),
             "/messages/0/content/0/context"),
            ("anthropic tool result's file reference's context", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
                 {"type": "text", "text": "see"}, {"type": "document", "title": SECRET, "source": {"type": "file", "file_id": "f1"}}]}]}]),
             "/messages/0/content/0/content/1/context"),
            ("anthropic text body spelled as base64", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "document", "source": {"type": "base64", "media_type": "text/plain", "data": SECRET}}]}]),
             "/messages/0/content/0/source/data"),
            ("anthropic search_result", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "search_result", "source": "https://x.example", "title": "t", "content": [{"type": "text", "text": SECRET}]}]}]),
             "/messages/0/content/0/content/0/text"),
            ("anthropic search_result in a tool result", ApiVersion::AnthropicMessages,
             json!([{"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [
                 {"type": "search_result", "source": "https://x.example", "title": "t", "content": [{"type": "text", "text": SECRET}]}]}]}]),
             "/messages/0/content/0/content/0/content/0/text"),
            ("responses input_file beside a stray file member", ApiVersion::Responses,
             json!([{"type": "message", "role": "user", "content": [{"type": "input_file", "filename": "a.txt", "file_data": url, "file": {}}]}]), ""),
            ("responses input_file", ApiVersion::Responses,
             json!([{"type": "message", "role": "user", "content": [{"type": "input_file", "filename": "a.txt", "file_data": url}]}]), ""),
            ("responses input_file, unpadded", ApiVersion::Responses,
             json!([{"type": "message", "role": "user", "content": [{"type": "input_file", "filename": "a.txt", "file_data": format!("data:text/plain;base64,{unpadded}")}]}]), ""),
            ("responses message without its optional type, among other items", ApiVersion::Responses,
             json!([{"type": "function_call", "call_id": "c0", "name": "f", "arguments": "{}"}, {"role": "user", "content": [{"type": "input_file", "filename": "a.txt", "file_data": url}]}]), ""),
            ("responses message list", ApiVersion::Responses,
             json!([{"role": "user", "content": [{"type": "input_file", "filename": "a.txt", "file_data": url}]}]), ""),
            ("responses tool output's input_file", ApiVersion::Responses,
             json!([{"type": "function_call_output", "call_id": "c1", "output": [{"type": "input_file", "filename": "a.txt", "file_data": url}]}]), ""),
            ("responses mcp_call output", ApiVersion::Responses,
             json!([{"type": "mcp_call", "id": "m1", "name": "x", "server_label": "s", "arguments": "{}", "output": SECRET}]), "/input/0/output"),
            ("responses mcp_call error", ApiVersion::Responses,
             json!([{"type": "mcp_call", "id": "m1", "name": "x", "server_label": "s", "arguments": "{}", "error": {"type": "http_error", "code": 500, "message": SECRET}}]), "/input/0/error/message"),
            ("responses code_interpreter logs", ApiVersion::Responses,
             json!([{"type": "code_interpreter_call", "id": "ci1", "container_id": "c", "code": "x", "status": "completed", "outputs": [{"type": "logs", "logs": SECRET}]}]), "/input/0/outputs/0/logs"),
            ("responses file_search result", ApiVersion::Responses,
             json!([{"type": "file_search_call", "id": "fs1", "status": "completed", "queries": ["q"], "results": [{"text": SECRET, "filename": "a"}]}]), "/input/0/results/0/text"),
            ("responses approval reason", ApiVersion::Responses,
             json!([{"type": "mcp_approval_response", "approval_request_id": "a1", "approve": false, "reason": SECRET}]), "/input/0/reason"),
            ("responses computer safety check message", ApiVersion::Responses,
             json!([{"type": "computer_call_output", "call_id": "k1", "output": {"type": "computer_screenshot", "image_url": "data:image/png;base64,AA"},
                     "acknowledged_safety_checks": [{"id": "s", "code": "c", "message": SECRET}]}]), "/input/0/acknowledged_safety_checks/0/message"),
            ("responses computer output off spec", ApiVersion::Responses,
             json!([{"type": "computer_call_output", "call_id": "k1", "output": SECRET}]), "/input/0/output"),
            ("chat file part", ApiVersion::ChatCompletions,
             json!([{"role": "user", "content": [{"type": "file", "file": {"filename": "a.txt", "file_data": url}}]}]), ""),
            ("gemini text blob", ApiVersion::GoogleGemini,
             json!([{"role": "user", "parts": [{"inlineData": {"mimeType": "text/plain", "data": b64}}]}]), ""),
            ("gemini function response's text blob", ApiVersion::GoogleGemini,
             json!([{"role": "user", "parts": [{"functionResponse": {"name": "f", "response": {"ok": true}, "parts": [{"inlineData": {"mimeType": "text/plain", "data": b64}}]}}]}]), ""),
            ("gemini code execution result", ApiVersion::GoogleGemini,
             json!([{"role": "model", "parts": [{"executableCode": {"language": "PYTHON", "code": "print(1)", "id": "e1"}},
                     {"codeExecutionResult": {"outcome": "OUTCOME_OK", "id": "e1", "output": SECRET}}]},
                    {"role": "user", "parts": [{"text": "go on"}]}]),
             "/contents/0/parts/1/codeExecutionResult/output"),
            ("gemini code execution result, snake_case", ApiVersion::GoogleGemini,
             json!([{"role": "model", "parts": [{"code_execution_result": {"outcome": "OUTCOME_FAILED", "output": SECRET}}]},
                    {"role": "user", "parts": [{"text": "go on"}]}]),
             "/contents/0/parts/0/code_execution_result/output"),
            ("gemini tool response", ApiVersion::GoogleGemini,
             json!([{"role": "model", "parts": [{"toolCall": {"toolType": "URL_CONTEXT", "id": "u1", "args": {"url": "https://x.example"}}}]},
                    {"role": "user", "parts": [{"toolResponse": {"toolType": "URL_CONTEXT", "id": "u1", "response": {"pages": [{"text": SECRET}]}}}]}]),
             "/contents/1/parts/0/toolResponse/response/pages/0/text"),
        ]
    }

    const SECRET: &str = "THE-SECRET-TEXTS";

    /// The bytes of a request's wire, text and the base64 of it alike, with what
    /// a data URL or a blob holds decoded.
    fn wire_holds(wire: &Value, needle: &str) -> bool {
        use base64::Engine;
        let decoded = |s: &str| {
            let b64 = s.rsplit(";base64,").next().unwrap_or(s);
            base64::engine::general_purpose::STANDARD_NO_PAD
                .decode(b64.trim_end_matches('='))
                .ok()
                .and_then(|b| String::from_utf8(b).ok())
                .is_some_and(|t| t.contains(needle))
        };
        match wire {
            Value::String(s) => s.contains(needle) || decoded(s),
            Value::Array(a) => a.iter().any(|v| wire_holds(v, needle)),
            Value::Object(o) => o.values().any(|v| wire_holds(v, needle)),
            _ => false,
        }
    }

    #[test]
    fn every_text_the_model_reads_is_read_and_written_in_place() {
        for (name, version, items, landing) in model_read_cases() {
            let Value::Array(items) = items else { panic!() };
            let mut req = parse(version, &body(version, items));
            let read = scan_messages(&req, 0).unwrap_or_else(|| panic!("{name}: pairs"));
            let at: Vec<_> = read.iter().filter(|m| m.message.content.contains(SECRET)).collect();
            assert_eq!(at.len(), 1, "{name}: read once, in {:?}", read.iter().map(|m| &m.message.content).collect::<Vec<_>>());
            let (item, part) = (at[0].item, at[0].part);
            set_item_text(&mut req, item, part, "[withheld]");
            let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
            assert!(!wire_holds(&wire, SECRET), "{name}: nothing of the original stays: {wire}");
            assert!(wire_holds(&wire, "[withheld]"), "{name}: the edit is on the wire: {wire}");
            if !landing.is_empty() {
                assert_eq!(wire.pointer(landing), Some(&json!("[withheld]")), "{name}: {wire}");
            }
            let again = scan_messages(&parse(version, &wire), 0).unwrap();
            assert!(again.iter().any(|m| m.message.content.contains("[withheld]")), "{name}: reads as written");
            assert_eq!(again.len(), read.len(), "{name}: the shape survives: {wire}");
        }
    }

    /// A Gemini result names no call when its optional `id` is absent: its
    /// piece still names one, empty, so a finding on it lands on a stub of its
    /// own — never on the prose of the user turn it sits in.
    #[test]
    fn an_id_less_gemini_result_is_held_apart_from_its_turns_prose() {
        let items = vec![json!({"role": "user", "parts": [{"text": "go on"}, {"codeExecutionResult": {"outcome": "OUTCOME_OK", "output": SECRET}}]})];
        let read = scan_messages(&parse(ApiVersion::GoogleGemini, &body(ApiVersion::GoogleGemini, items)), 0).unwrap();
        let result = read.iter().find(|m| m.message.content == SECRET).unwrap();
        assert_eq!(result.held_call.as_deref(), Some(""));
        let prose = read.iter().find(|m| m.message.content == "go on").unwrap();
        assert_eq!(prose.held_call, None);
    }

    /// What the guardrail does not read, and why: bytes no detector reads, the
    /// ids that pair a result with its call, a file's name, what the call says
    /// (the model's own). The positive control is the case above.
    #[test]
    fn what_is_deliberately_not_read_stays_unread_and_as_sent() {
        let cases = vec![
            (ApiVersion::AnthropicMessages, json!([{"role": "user", "content": [{"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": SECRET}}]}])),
            (ApiVersion::AnthropicMessages, json!([{"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": [{"type": "x", "text": SECRET}]}}]}])),
            // A cited source's quote and title: the guardrail reads none — a
            // user's or a tool result's travel as sent (rare, client-sent), as an
            // assistant's do, unread as its text is.
            (ApiVersion::AnthropicMessages, json!([{"role": "user", "content": [{"type": "text", "text": "see", "citations": [
                {"type": "char_location", "cited_text": SECRET, "document_index": 0, "document_title": SECRET, "start_char_index": 0, "end_char_index": 4}]}]}])),
            (ApiVersion::AnthropicMessages, json!([{"role": "assistant", "content": [{"type": "text", "text": "see", "citations": [
                {"type": "char_location", "cited_text": SECRET, "document_index": 0, "document_title": SECRET, "start_char_index": 0, "end_char_index": 4}]}]},
                {"role": "user", "content": "go"}])),
            (ApiVersion::AnthropicMessages, json!([{"role": "assistant", "content": [{"type": "web_search_tool_result", "tool_use_id": "srvtoolu_1", "content": [{"type": "web_search_result", "encrypted_content": SECRET, "title": "t", "url": "https://x.example"}]}]}, {"role": "user", "content": "go"}])),
            (ApiVersion::AnthropicMessages, json!([{"role": "assistant", "content": [{"type": "web_fetch_tool_result", "tool_use_id": "srvtoolu_1", "content": {"type": "web_fetch_result", "url": "https://x.example", "content": {"type": "document", "source": {"type": "base64", "media_type": "application/pdf", "data": SECRET}}}}]}, {"role": "user", "content": "go"}])),
            (ApiVersion::Responses, json!([{"type": "message", "role": "user", "content": [{"type": "input_file", "filename": SECRET, "file_data": "data:text/plain;base64,aGVsbG8="}]}])),
            (ApiVersion::Responses, json!([{"type": "mcp_call", "id": SECRET, "name": SECRET, "server_label": "s", "arguments": SECRET}])),
            (ApiVersion::Responses, json!([{"type": "code_interpreter_call", "id": "c", "container_id": "c", "code": SECRET, "status": "completed", "outputs": [{"type": "image", "url": SECRET}]}])),
            (ApiVersion::Responses, json!([{"type": "computer_call_output", "call_id": SECRET, "output": {"type": "computer_screenshot", "image_url": SECRET}}])),
            (ApiVersion::Responses, json!([{"type": "web_search_call", "id": SECRET, "status": "completed", "action": {"type": "search", "query": SECRET}}])),
            (ApiVersion::Responses, json!([{"type": "mcp_list_tools", "id": SECRET, "server_label": SECRET, "tools": [{"name": SECRET, "input_schema":
                {"type": "object", "properties": {"mode": {"type": "string", "enum": [SECRET], "default": SECRET}}}}]}])),
            (ApiVersion::GoogleGemini, json!([{"role": "model", "parts": [{"executableCode": {"language": "PYTHON", "code": SECRET, "id": SECRET}},
                {"codeExecutionResult": {"outcome": "OUTCOME_OK", "id": SECRET}}]}, {"role": "user", "parts": [{"text": "go"}]}])),
            (ApiVersion::GoogleGemini, json!([{"role": "model", "parts": [{"toolCall": {"toolType": "URL_CONTEXT", "id": SECRET, "toolName": SECRET, "args": {"q": SECRET}}}]},
                {"role": "user", "parts": [{"toolResponse": {"toolType": "URL_CONTEXT", "id": SECRET, "response": {}}}]}])),
        ];
        for (version, items) in cases {
            let Value::Array(items) = items.clone() else { panic!() };
            let read = scan_messages(&parse(version, &body(version, items.clone())), 0).unwrap();
            assert!(read.iter().all(|m| !m.message.content.contains(SECRET)), "{items:?}");
        }
    }

    /// Pieces are counted by their place, whatever their text: a blank document,
    /// read by nothing, still holds its place, and a verdict replayed in any
    /// order lands the same.
    #[test]
    fn an_edit_of_one_piece_leaves_every_other_where_it_is() {
        let doc = |t: &str| json!({"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": t}});
        let items = vec![json!({"role": "user", "content": [
            {"type": "text", "text": "prose"},
            doc("   "),
            doc("first"),
            {"type": "tool_result", "tool_use_id": "t1", "content": [doc("in result"), {"type": "text", "text": "beside"}]},
            doc("second"),
            {"type": "mcp_tool_result", "tool_use_id": "m1", "content": "from a server"},
        ]})];
        let mut req = parse(ApiVersion::AnthropicMessages, &body(ApiVersion::AnthropicMessages, items));
        let read = scan_messages(&req, 0).unwrap();
        let part_of = |text: &str| read.iter().find(|m| m.message.content == text).unwrap_or_else(|| panic!("{text}")).part;
        let (first, second, in_result, server) = (part_of("first"), part_of("second"), part_of("in result"), part_of("from a server"));
        set_item_text(&mut req, 0, server, "M");
        set_item_text(&mut req, 0, second, "S");
        set_item_text(&mut req, 0, first, "F");
        set_item_text(&mut req, 0, in_result, "R");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let blocks = &wire["messages"][0]["content"];
        assert_eq!(blocks[0]["text"], "prose");
        assert_eq!(blocks[1]["source"]["data"], "   ");
        assert_eq!(blocks[2]["source"]["data"], "F");
        assert_eq!(blocks[3]["content"][0]["source"]["data"], "R");
        assert_eq!(blocks[3]["content"][1]["text"], "beside");
        assert_eq!(blocks[3]["tool_use_id"], "t1");
        assert_eq!(blocks[4]["source"]["data"], "S");
        assert_eq!(blocks[5]["content"], "M");
        assert_eq!(blocks[5]["tool_use_id"], "m1");
        // Nothing else changed its place in the read either.
        let again = scan_messages(&parse(ApiVersion::AnthropicMessages, &wire), 0).unwrap();
        assert_eq!(again.iter().find(|m| m.message.content == "S").map(|m| m.part), Some(second));
    }

    /// Several pieces across a conversation: each read once, under the call it
    /// answers, anchored at its own message, counted past what is no piece, and
    /// written alone. An empty string stays empty: no field gains a placeholder.
    #[test]
    fn pieces_across_messages_keep_their_calls_anchors_and_places() {
        let result = |call: &str, text: &str| json!({"type": "mcp_tool_result", "tool_use_id": call, "content": text});
        let items = vec![
            json!({"role": "assistant", "content": [
                result("m1", "first result"),
                {"type": "a_block_of_no_kind", "text": "not a result"},
                {"type": "bash_code_execution_tool_result", "tool_use_id": "b1", "content":
                    {"type": "bash_code_execution_result", "stdout": "bash output", "stderr": "", "return_code": 0, "content": []}},
                {"type": "document", "context": "the model's own", "source": {"type": "file", "file_id": "f1"}},
                result("m2", "second result"),
            ]}),
            json!({"role": "user", "content": [
                {"type": "document", "context": "a user's context", "source": {"type": "file", "file_id": "f2"}},
                {"type": "text", "text": "go on"},
            ]}),
            json!({"role": "assistant", "content": [result("m3", "later result")]}),
            json!({"role": "user", "content": "last"}),
        ];
        let mut req = parse(ApiVersion::AnthropicMessages, &body(ApiVersion::AnthropicMessages, items));
        let read = scan_messages(&req, 0).unwrap();
        let piece = |text: &str| read.iter().find(|m| m.message.content == text).unwrap_or_else(|| panic!("{text}"));
        // Domain: assistant, user, assistant, user, so from the end 3, 2, 1, 0.
        for (text, call, reverse) in [("first result", "m1", 3), ("bash output", "b1", 3), ("second result", "m2", 3), ("later result", "m3", 1)] {
            let at = piece(text);
            assert_eq!(at.message.role, "tool", "{text}");
            assert_eq!(at.held_call.as_deref(), Some(call), "{text}");
            assert_eq!(at.message.tool_call_id.as_deref(), Some(call), "{text}");
            assert_eq!(at.reverse, reverse, "{text}");
        }
        let user = piece("a user's context");
        assert_eq!((user.message.role.as_str(), user.reverse, user.held_call.as_deref()), ("user", 2, None));
        assert!(read.iter().all(|m| m.message.content != "the model's own"), "an assistant's document is not read");
        assert!(read.iter().all(|m| m.message.content != "not a result"));

        let (item, part) = (piece("second result").item, piece("second result").part);
        let (bash_item, bash_part) = (piece("bash output").item, piece("bash output").part);
        set_item_text(&mut req, item, part, "S");
        set_item_text(&mut req, bash_item, bash_part, "B");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let blocks = &wire["messages"][0]["content"];
        assert_eq!(blocks[0]["content"], "first result");
        assert_eq!(blocks[1]["text"], "not a result");
        assert_eq!(blocks[2]["content"]["stdout"], "B");
        assert_eq!(blocks[2]["content"]["stderr"], "", "an empty field stays empty");
        assert_eq!(blocks[3]["context"], "the model's own");
        assert_eq!(blocks[4]["content"], "S");
        assert_eq!(wire["messages"][2]["content"][0]["content"], "later result");
    }

    /// An edit of a content source's text keeps the images beside it: nothing is
    /// dropped without a marker.
    #[test]
    fn an_edit_of_a_content_source_keeps_its_images() {
        let image = json!({"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}});
        let items = vec![json!({"role": "user", "content": [{"type": "document", "source": {"type": "content", "content": [
            image.clone(), {"type": "text", "text": SECRET}, {"type": "text", "text": "more"},
        ]}}]})];
        let mut req = parse(ApiVersion::AnthropicMessages, &body(ApiVersion::AnthropicMessages, items));
        let read = scan_messages(&req, 0).unwrap();
        let at = read.iter().find(|m| m.message.content.contains(SECRET)).unwrap();
        let (item, part) = (at.item, at.part);
        set_item_text(&mut req, item, part, "[withheld]");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let held = &wire["messages"][0]["content"][0]["source"]["content"];
        assert_eq!(held[0]["type"], "image", "{held}");
        assert_eq!(held[1]["text"], "[withheld]", "{held}");
        assert_eq!(held.as_array().map(Vec::len), Some(2), "{held}");
    }

    /// A finding on a piece is anchored at the message holding it, so the
    /// console pins it there; a document's role is its message's, which is what
    /// keeps the PII pass off a tool's document and on a user's.
    #[test]
    fn a_piece_is_anchored_at_its_message_with_its_role() {
        let doc = json!({"type": "document", "source": {"type": "text", "media_type": "text/plain", "data": "body"}});
        let items = vec![
            json!({"role": "user", "content": [doc.clone()]}),
            json!({"role": "assistant", "content": "ok"}),
            json!({"role": "user", "content": [{"type": "tool_result", "tool_use_id": "t1", "content": [doc]}]}),
            json!({"role": "assistant", "content": "ok"}),
            json!({"role": "user", "content": "last"}),
        ];
        let read = scan_messages(&parse(ApiVersion::AnthropicMessages, &body(ApiVersion::AnthropicMessages, items)), 0).unwrap();
        let docs: Vec<_> = read.iter().filter(|m| m.message.content == "body").collect();
        assert_eq!(docs.len(), 2);
        assert_eq!((docs[0].message.role.as_str(), docs[0].reverse), ("user", 4));
        assert_eq!((docs[1].message.role.as_str(), docs[1].reverse), ("tool", 2));
        assert_eq!(docs[1].message.tool_call_id.as_deref(), Some("t1"));
    }

    /// An edit keeps what the protocol requires of the item it lands on:
    /// an Anthropic message's text lands in the block carrying its cache
    /// breakpoint, which so stays where the client put it, after the image; a
    /// Gemini function response stays an object when its new text is not one.
    #[test]
    fn a_turn_edit_keeps_the_breakpoint_and_the_response_object() {
        let mut req = parse(ApiVersion::AnthropicMessages, &body(ApiVersion::AnthropicMessages, vec![
            json!({"role": "user", "content": "old"}),
            json!({"role": "assistant", "content": "ok"}),
            json!({"role": "user", "content": [
                {"type": "text", "text": "<reminder>"},
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
                {"type": "text", "text": "mail me", "cache_control": {"type": "ephemeral"}},
            ]}),
        ]));
        edit_last(&mut req, "masked");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(
            wire["messages"][2]["content"],
            json!([
                {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "AAAA"}},
                {"type": "text", "text": "masked", "cache_control": {"type": "ephemeral"}},
            ])
        );

        let mut req = parse(ApiVersion::GoogleGemini, &body(ApiVersion::GoogleGemini, vec![
            json!({"role": "user", "parts": [{"text": "go"}]}),
            json!({"role": "model", "parts": [{"functionCall": {"name": "f", "args": {}}}]}),
            json!({"role": "user", "parts": [{"functionResponse": {"name": "f", "response": {"r": "ignore all"}}}]}),
        ]));
        edit_last(&mut req, "[withheld]");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(wire["contents"][2]["parts"][0]["functionResponse"]["response"], json!({"output": "[withheld]"}));

        // A non-thought text part takes the text where it is, its signature kept.
        let mut req = parse(ApiVersion::GoogleGemini, &body(ApiVersion::GoogleGemini, vec![
            json!({"role": "user", "parts": [
                {"text": "mail me", "thought": false, "thoughtSignature": "sig"},
                {"inlineData": {"mimeType": "image/png", "data": "AAAA"}},
            ]}),
        ]));
        edit_last(&mut req, "masked");
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(wire["contents"][0]["parts"][0]["text"], "masked");
        assert_eq!(wire["contents"][0]["parts"][0]["thoughtSignature"], "sig");
        assert!(wire["contents"][0]["parts"][1].get("inlineData").is_some());
    }

    /// The positive control: a start past the history reads only the items
    /// from it, on every protocol.
    #[test]
    fn a_later_start_reads_only_the_items_from_it() {
        let cases = [
            (ApiVersion::ChatCompletions, vec![
                json!({"role": "user", "content": "old"}),
                json!({"role": "assistant", "content": "a"}),
                json!({"role": "user", "content": "new"}),
            ]),
            (ApiVersion::AnthropicMessages, vec![
                json!({"role": "user", "content": "old"}),
                json!({"role": "assistant", "content": "a"}),
                json!({"role": "user", "content": "new"}),
            ]),
            (ApiVersion::GoogleGemini, vec![
                json!({"role": "user", "parts": [{"text": "old"}]}),
                json!({"role": "model", "parts": [{"text": "a"}]}),
                json!({"role": "user", "parts": [{"text": "new"}]}),
            ]),
            (ApiVersion::Responses, vec![
                json!({"type": "message", "role": "user", "content": "old"}),
                json!({"type": "message", "role": "assistant", "content": "a"}),
                json!({"type": "message", "role": "user", "content": "new"}),
            ]),
        ];
        for (version, items) in cases {
            let req = parse(version, &body(version, items));
            let read = scan_messages(&req, 2).expect("pairs");
            let texts: Vec<(&str, usize, usize)> = read.iter().map(|m| (m.message.content.as_str(), m.item, m.reverse)).collect();
            assert_eq!(texts, [("new", 2, 0)], "{version:?}");
        }
    }
}
