//! Mistral's own API speaking Chat Completions.
//!
//! Mistral's request schema is CLOSED: every request object is
//! `additionalProperties: false`, and the live API refuses an unknown key with
//! a 422 `extra_forbidden` — so a field another server ignores fails the whole
//! request there. A body bound for Mistral therefore goes through
//! [`conform_chat_request`] after it is built, on every forward (primary,
//! failover, substitution round), whichever protocol the client spoke: each
//! field Mistral spells differently is renamed, and each it has no channel for
//! is removed and named.
//!
//! The field lists below are Mistral's published schema
//! (`https://docs.mistral.ai/openapi.yaml`, `ChatCompletionRequest` and the
//! message / chunk / tool objects it references). Keep them in step with that
//! document, never with what the code happens to send.

use bytes::Bytes;
use serde_json::{Map, Value, json};

/// Which Chat Completions server a request goes to, where servers differ on the
/// wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum ChatDialect {
    /// An OpenAI-compatible server: the body goes as built.
    #[default]
    Compatible,
    /// Mistral's API: the body is conformed by [`conform_chat_request`].
    Mistral,
}

impl ChatDialect {
    /// The dialect's name on the audit badge.
    pub fn label(self) -> &'static str {
        match self {
            Self::Compatible => "openai_compatible",
            Self::Mistral => "mistral",
        }
    }

    /// Mistral's API: the `mistral` provider, or any upstream at a `mistral.ai`
    /// host (a `custom` provider pointed there speaks the same wire). A Mistral
    /// model served by another engine (vLLM, Ollama) under another provider is
    /// a compatible server.
    pub fn for_upstream(provider: &str, url: &str) -> Self {
        use crate::config::model_map::Provider;
        let on_mistral_host = url::Url::parse(url)
            .ok()
            .and_then(|u| u.host_str().map(str::to_ascii_lowercase))
            .is_some_and(|h| h == "mistral.ai" || h.ends_with(".mistral.ai"));
        if on_mistral_host || matches!(Provider::from_str_relaxed(provider), Provider::Mistral) {
            Self::Mistral
        } else {
            Self::Compatible
        }
    }
}

/// What a conform pass changed ([`conform_chat_request`], the compatible
/// server's pass, [`crate::api::messages::conform_anthropic_body`]).
/// `adapted` names each rewrite that kept the meaning (a rename, a narrowed
/// choice); `not_carried` each part of the request the upstream has no channel
/// for, which was removed.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Conformed {
    /// The API the request was fitted to, as the `upstream_adapted` badge
    /// names it — set by the pass that produced this.
    pub dialect: &'static str,
    pub adapted: Vec<String>,
    pub not_carried: Vec<String>,
    /// The text of a trailing assistant message this pass made a `prefix`.
    /// Mistral's answer to a prefix begins with the prefix itself, where every
    /// other protocol's prefill is answered with the continuation alone, so a
    /// translated client's answer has it stripped ([`PrefixEcho`]).
    pub prefix_echo: Option<String>,
}

impl Conformed {
    pub fn is_empty(&self) -> bool {
        self.adapted.is_empty() && self.not_carried.is_empty()
    }

    /// Fold in what another conforming changed, without repeats.
    pub fn merge(&mut self, other: Conformed) {
        if self.dialect.is_empty() {
            self.dialect = other.dialect;
        }
        other.adapted.into_iter().for_each(|a| self.adapt(a));
        other.not_carried.into_iter().for_each(|n| self.drop(n));
    }

    fn adapt(&mut self, what: impl Into<String>) {
        let what = what.into();
        if !self.adapted.contains(&what) {
            self.adapted.push(what);
        }
    }

    fn drop(&mut self, what: impl Into<String>) {
        let what = what.into();
        if !self.not_carried.contains(&what) {
            self.not_carried.push(what);
        }
    }
}

/// `ChatCompletionRequest`'s properties.
const REQUEST_FIELDS: &[&str] = &[
    "model",
    "temperature",
    "top_p",
    "max_tokens",
    "stream",
    "stop",
    "random_seed",
    "metadata",
    "messages",
    "response_format",
    "tools",
    "tool_choice",
    "presence_penalty",
    "frequency_penalty",
    "n",
    "prediction",
    "parallel_tool_calls",
    "reasoning_effort",
    "prompt_mode",
    "guardrails",
    "prompt_cache_key",
    "service_tier",
    "safe_prompt",
];

/// The hosted tools `ChatCompletionRequest.tools` lists beside `function`
/// (`WebSearchTool`, `WebSearchPremiumTool`, `CodeInterpreterTool`,
/// `ImageGenerationTool`, `DocumentLibraryTool`, `CustomConnector`): a Mistral
/// client's own, sent as it wrote them.
const HOSTED_TOOLS: &[&str] =
    &["web_search", "web_search_premium", "code_interpreter", "image_generation", "document_library", "connector"];

/// `RequestedServiceTier`.
const SERVICE_TIERS: &[&str] = &["auto", "standard_only"];

/// The properties of each message object, by role.
fn message_fields(role: &str) -> &'static [&'static str] {
    match role {
        "assistant" => &["role", "content", "tool_calls", "prefix"],
        "tool" => &["role", "content", "tool_call_id", "name"],
        // `SystemMessage`, `UserMessage`.
        _ => &["role", "content"],
    }
}

/// The properties of each `ContentChunk` kind; `None` for a kind Mistral does
/// not have. A system message takes only `text` and `thinking`
/// (`SystemMessageContentChunks`).
fn chunk_fields(kind: &str, role: &str) -> Option<&'static [&'static str]> {
    let fields: &'static [&'static str] = match kind {
        "text" => &["type", "text"],
        "thinking" => &["type", "thinking", "signature", "closed"],
        _ if role == "system" => return None,
        "image_url" => &["type", "image_url"],
        "document_url" => &["type", "document_url", "document_name"],
        "reference" => &["type", "reference_ids"],
        "file" => &["type", "file_id"],
        "input_audio" => &["type", "input_audio"],
        _ => return None,
    };
    Some(fields)
}

use crate::api::domain_request::asks_nothing;

/// `a` or `an`, for a label naming a role or a part kind.
pub(crate) fn a(word: &str) -> &'static str {
    // By sound: "a user", "an untyped".
    if word.starts_with(['a', 'e', 'i', 'o']) || word.starts_with("un") { "an" } else { "a" }
}

/// What the target model is known to do with reasoning.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ModelReasoning {
    /// The target's `accepts_reasoning`: false only for a model KNOWN not to
    /// reason, which refuses `reasoning_effort` and a `thinking` chunk in
    /// history ("Reasoning input is not enabled for this model").
    pub accepts: bool,
    /// The model is DECLARED to reason. Mistral refuses even
    /// `reasoning_effort: "none"` on a model that does not reason (live: "reasoning_effort
    /// is not enabled for this model"), so "do not reason" goes only where the
    /// model is known to take it.
    pub declared: bool,
}

/// Mistral's `ReasoningEffort` (`none | minimal | low | medium | high | xhigh`).
const EFFORTS: &[&str] = &["none", "minimal", "low", "medium", "high", "xhigh"];

/// `reasoning_effort` as Mistral takes it: a depth only where the model is not
/// known not to reason, `none` only where it is declared to reason, a value
/// outside Mistral's enum narrowed (OpenAI's `max` → `xhigh`, never deeper) or
/// removed — each change named.
fn conform_effort(body: &mut Map<String, Value>, model: ModelReasoning, out: &mut Conformed) {
    let Some(effort) = body.get("reasoning_effort").cloned() else { return };
    let Some(word) = effort.as_str() else {
        body.remove("reasoning_effort");
        if !effort.is_null() {
            out.drop(format!("reasoning_effort {effort}"));
        }
        return;
    };
    if word == "none" {
        if !model.declared {
            body.remove("reasoning_effort");
            // A model that does not reason needs no switch to stop.
            if model.accepts {
                out.drop("reasoning_effort none (not confirmed for this model)");
            }
        }
        return;
    }
    if !model.accepts {
        body.remove("reasoning_effort");
        out.drop(format!("reasoning_effort {word} (the model does not reason)"));
        return;
    }
    if EFFORTS.contains(&word) {
        return;
    }
    if word == "max" {
        body.insert("reasoning_effort".into(), Value::from("xhigh"));
        out.adapt("reasoning_effort max sent as xhigh");
    } else {
        body.remove("reasoning_effort");
        out.drop(format!("reasoning_effort {word}"));
    }
}

/// Conform a Chat Completions body to Mistral's API.
pub fn conform_chat_request(body: &mut Map<String, Value>, model: ModelReasoning, prefill: bool) -> Conformed {
    let model_reasons = model.accepts;
    let mut out = Conformed::default();

    // Renames.
    if let Some(seed) = body.remove("seed") {
        match seed.as_u64() {
            Some(n) if body.get("random_seed").is_none_or(Value::is_null) => {
                body.insert("random_seed".into(), Value::from(n));
                out.adapt("seed sent as random_seed");
            }
            // Mistral's seed is non-negative.
            _ if !seed.is_null() => out.drop(format!("seed {seed}")),
            _ => {}
        }
    }
    if let Some(cap) = body.remove("max_completion_tokens") {
        match cap.as_u64() {
            Some(cap) => {
                // Both stated: the smaller cap, so the rename never lets the answer run longer.
                let cap = match body.get("max_tokens").and_then(Value::as_u64) {
                    Some(existing) => existing.min(cap),
                    None => cap,
                };
                body.insert("max_tokens".into(), Value::from(cap));
                out.adapt("max_completion_tokens sent as max_tokens");
            }
            None if !cap.is_null() => out.drop(format!("max_completion_tokens {cap}")),
            None => {}
        }
    }
    if let Some(tier) = body.get("service_tier")
        && !tier.is_null()
        && !tier.as_str().is_some_and(|t| SERVICE_TIERS.contains(&t))
    {
        let tier = body.remove("service_tier").unwrap_or_default();
        out.drop(format!("service_tier {}", tier.as_str().unwrap_or("(not a string)")));
    }
    conform_effort(body, model, &mut out);
    // Mistral reports usage on a stream's last chunk unasked, so what
    // `stream_options.include_usage` asks for is carried without it.
    body.remove("stream_options");

    // Every other top-level key Mistral does not have.
    let unknown: Vec<String> = body.keys().filter(|k| !REQUEST_FIELDS.contains(&k.as_str())).cloned().collect();
    for key in unknown {
        if let Some(v) = body.remove(&key)
            && !asks_nothing(&v)
        {
            out.drop(format!("parameter {key}"));
        }
    }

    if let Some(Value::Array(messages)) = body.get_mut("messages") {
        conform_messages(messages, model_reasons, prefill, &mut out);
    }
    conform_tools(body, &mut out);
    out
}

/// `prefill`: the request was translated from a protocol whose trailing
/// assistant message is a prefill (Anthropic), so it is sent as Mistral's
/// `prefix`. A Chat client's own trailing assistant message goes as it wrote
/// it — Mistral's answer to it is Mistral's, not a semantics the gateway adds.
fn conform_messages(messages: &mut Vec<Value>, model_reasons: bool, prefill: bool, out: &mut Conformed) {
    let mut history_reasoning = 0usize;
    messages.retain_mut(|msg| {
        let Some(obj) = msg.as_object_mut() else { return true };
        let role = match obj.get("role").and_then(Value::as_str) {
            // OpenAI's `developer` role is its system channel for newer models.
            Some("developer") => {
                obj.insert("role".into(), Value::from("system"));
                out.adapt("developer message sent as system");
                "system".to_string()
            }
            Some("function") => {
                out.drop("legacy function message");
                return false;
            }
            Some(r) => r.to_string(),
            None => return true,
        };

        if role == "assistant" {
            // The keys other servers use for reasoning the model wrote. Mistral
            // has none: its reasoning rides a `thinking` chunk in `content`.
            let mut reasoning: Vec<String> = Vec::new();
            for key in crate::api::chat::REASONING_KEYS {
                match obj.remove(key) {
                    // Servers that write both keys write the same text twice.
                    Some(Value::String(s)) if !s.is_empty() => {
                        if !reasoning.contains(&s) {
                            reasoning.push(s);
                        }
                    }
                    Some(v) if !asks_nothing(&v) => out.drop(format!("{key} on an assistant message")),
                    _ => {}
                }
            }
            if !reasoning.is_empty() {
                if model_reasons {
                    let chunk = json!({"type": "thinking", "thinking": [{"type": "text", "text": reasoning.join("")}]});
                    let mut chunks = content_as_chunks(obj.remove("content"));
                    chunks.insert(0, chunk);
                    obj.insert("content".into(), Value::Array(chunks));
                    out.adapt("history reasoning sent as a thinking chunk");
                } else {
                    history_reasoning += 1;
                }
            }
        }

        let allowed = message_fields(&role);
        let extra: Vec<String> = obj.keys().filter(|k| !allowed.contains(&k.as_str())).cloned().collect();
        for key in extra {
            if let Some(v) = obj.remove(&key)
                && !asks_nothing(&v)
            {
                out.drop(format!("{key} on {} {role} message", a(&role)));
            }
        }

        if let Some(Value::Array(chunks)) = obj.get_mut("content") {
            history_reasoning += conform_chunks(chunks, &role, model_reasons, out);
        }
        if role == "assistant" {
            if let Some(Value::Array(calls)) = obj.get_mut("tool_calls") {
                calls.iter_mut().for_each(|c| conform_tool_call(c, out));
            }
            let has_calls = obj.get("tool_calls").and_then(Value::as_array).is_some_and(|c| !c.is_empty());
            let empty = match obj.get("content") {
                None | Some(Value::Null) => true,
                Some(Value::String(s)) => s.is_empty(),
                Some(Value::Array(a)) => a.is_empty(),
                Some(_) => false,
            };
            // Mistral refuses an assistant turn with neither ("must have either
            // content or tool_calls"); an empty one carries nothing.
            if empty && !has_calls {
                return false;
            }
        }
        true
    });
    if history_reasoning > 0 {
        out.drop(match history_reasoning {
            1 => "reasoning in history (the model does not reason)".to_string(),
            n => format!("reasoning in history (×{n}, the model does not reason)"),
        });
    }

    // A trailing assistant message is a prefill; Mistral serves one only when
    // it says so ("Expected last role User or Tool (or Assistant with prefix True)").
    if prefill
        && let Some(last) = messages.last_mut().and_then(Value::as_object_mut)
        && last.get("role").and_then(Value::as_str) == Some("assistant")
        && last.get("tool_calls").and_then(Value::as_array).is_none_or(|c| c.is_empty())
        && last.get("prefix") != Some(&Value::Bool(true))
    {
        out.prefix_echo = crate::api::chat::content_text(last.get("content")).map(|t| t.into_owned());
        last.insert("prefix".into(), Value::Bool(true));
        out.adapt("trailing assistant message sent as a prefix");
    }
}

/// `content` as a chunk list: a string becomes one `text` chunk.
fn content_as_chunks(content: Option<Value>) -> Vec<Value> {
    match content {
        Some(Value::Array(a)) => a,
        Some(Value::String(s)) if !s.is_empty() => vec![json!({"type": "text", "text": s})],
        _ => Vec::new(),
    }
}

/// Conform one message's chunks; returns how many `thinking` chunks were
/// removed because the model does not reason.
fn conform_chunks(chunks: &mut Vec<Value>, role: &str, model_reasons: bool, out: &mut Conformed) -> usize {
    let mut reasoning_removed = 0;
    let mut i = 0;
    while i < chunks.len() {
        let Some(obj) = chunks[i].as_object_mut() else {
            i += 1;
            continue;
        };
        let kind = obj.get("type").and_then(Value::as_str).unwrap_or("").to_string();
        if kind == "thinking" && !model_reasons {
            chunks.remove(i);
            reasoning_removed += 1;
            continue;
        }
        // OpenAI's file part nests its fields under `file`; Mistral's names an
        // uploaded file by id and has no inline form.
        if kind == "file"
            && obj.get("file").is_some_and(Value::is_object)
            && let Some(Value::Object(file)) = obj.remove("file")
        {
            match file.get("file_id").and_then(Value::as_str) {
                Some(id) => {
                    obj.insert("file_id".into(), Value::from(id));
                    out.adapt("file part sent by file_id");
                }
                None => {
                    let name = file.get("filename").and_then(Value::as_str).unwrap_or("unnamed");
                    chunks[i] = json!({"type": "text", "text": format!("[File {name}: not carried to this model]")});
                    out.drop(format!("inline file {name}"));
                    i += 1;
                    continue;
                }
            }
        }
        // Mistral's `AudioChunk.input_audio` is a string: OpenAI's
        // `{data, format}` goes as a data URL, which carries the format.
        if kind == "input_audio"
            && let Some(Value::Object(audio)) = obj.get("input_audio")
            && let Some(data) = audio.get("data").and_then(Value::as_str)
        {
            let media_type = match audio.get("format").and_then(Value::as_str) {
                Some("mp3") => "audio/mpeg".to_string(),
                Some(format) => format!("audio/{format}"),
                None => "application/octet-stream".to_string(),
            };
            let url = format!("data:{media_type};base64,{data}");
            obj.insert("input_audio".into(), Value::from(url));
            out.adapt("input_audio sent as a data URL");
        }
        match chunk_fields(&kind, role) {
            Some(fields) => {
                let extra: Vec<String> = obj.keys().filter(|k| !fields.contains(&k.as_str())).cloned().collect();
                for key in extra {
                    if let Some(v) = obj.remove(&key)
                        && !asks_nothing(&v)
                    {
                        out.drop(format!("{key} on {} {kind} part", a(&kind)));
                    }
                }
            }
            None => {
                // A visible marker where the part was, never a silent gap.
                let label = if kind.is_empty() { "untyped".to_string() } else { kind };
                chunks[i] = json!({"type": "text", "text": format!("[{label} part: not carried to this model]")});
                out.drop(format!("{label} part on {} {role} message", a(role)));
            }
        }
        i += 1;
    }
    reasoning_removed
}

/// A history tool call as Mistral's `ToolCall`: `id`, `type`, `function`,
/// `index`. A custom (freeform) call has no Mistral form; it goes as the
/// function call the gateway's own domain makes of one (`{"input": <text>}`).
fn conform_tool_call(call: &mut Value, out: &mut Conformed) {
    let Some(obj) = call.as_object_mut() else { return };
    if obj.get("type").and_then(Value::as_str) == Some("custom")
        && let Some(Value::Object(custom)) = obj.remove("custom")
    {
        let name = custom.get("name").cloned().unwrap_or(Value::from(""));
        let input = custom.get("input").and_then(Value::as_str).unwrap_or("");
        obj.insert("type".into(), Value::from("function"));
        obj.insert(
            "function".into(),
            json!({"name": name, "arguments": json!({"input": input}).to_string()}),
        );
        out.adapt("freeform tool call in history sent as a function call");
    }
    let extra: Vec<String> =
        obj.keys().filter(|k| !matches!(k.as_str(), "id" | "type" | "function" | "index")).cloned().collect();
    for key in extra {
        if let Some(v) = obj.remove(&key)
            && !asks_nothing(&v)
        {
            out.drop(format!("{key} on a tool call"));
        }
    }
    if let Some(Value::Object(f)) = obj.get_mut("function") {
        let extra: Vec<String> = f.keys().filter(|k| !matches!(k.as_str(), "name" | "arguments")).cloned().collect();
        for key in extra {
            if let Some(v) = f.remove(&key)
                && !asks_nothing(&v)
            {
                out.drop(format!("{key} on a tool call"));
            }
        }
    }
}

fn conform_tools(body: &mut Map<String, Value>, out: &mut Conformed) {
    let mut removed: Vec<String> = Vec::new();
    if let Some(Value::Array(tools)) = body.get_mut("tools") {
        tools.retain_mut(|tool| {
            let Some(obj) = tool.as_object_mut() else {
                out.drop("a tool that is not an object");
                return false;
            };
            let kind = obj.get("type").and_then(Value::as_str).unwrap_or("function").to_string();
            if HOSTED_TOOLS.contains(&kind.as_str()) {
                return true;
            }
            if kind != "function" || !obj.get("function").is_some_and(Value::is_object) {
                let name = obj
                    .get(&kind)
                    .and_then(|t| t.get("name"))
                    .and_then(Value::as_str)
                    .unwrap_or(&kind)
                    .to_string();
                out.drop(if kind == "custom" { format!("freeform tool {name}") } else { format!("hosted tool {kind}") });
                removed.push(name);
                return false;
            }
            let name = obj
                .get("function")
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let extra: Vec<String> = obj.keys().filter(|k| !matches!(k.as_str(), "type" | "function")).cloned().collect();
            for key in extra {
                if let Some(v) = obj.remove(&key)
                    && !asks_nothing(&v)
                {
                    out.drop(format!("{key} on tool {name}"));
                }
            }
            if let Some(Value::Object(f)) = obj.get_mut("function") {
                let extra: Vec<String> = f
                    .keys()
                    .filter(|k| !matches!(k.as_str(), "name" | "description" | "strict" | "parameters"))
                    .cloned()
                    .collect();
                for key in extra {
                    if let Some(v) = f.remove(&key)
                        && !asks_nothing(&v)
                    {
                        out.drop(format!("{key} on tool {name}"));
                    }
                }
                // Mistral requires `parameters`; a function that takes none
                // says so with the empty object schema.
                if f.get("parameters").is_none_or(Value::is_null) {
                    f.insert("parameters".into(), json!({"type": "object", "properties": {}}));
                    out.adapt(format!("tool {name} sent with an empty parameters schema"));
                }
            }
            true
        });
    }

    // `tool_choice`, rendered only over the tools Mistral was given, and never
    // wider than the client's: a choice Mistral cannot state becomes "none".
    let none_instead = |out: &mut Conformed, why: String| {
        out.drop(why);
        Value::from("none")
    };
    if let Some(choice) = body.remove("tool_choice") {
        let choice = match &choice {
            Value::String(s) if matches!(s.as_str(), "auto" | "none" | "any" | "required") => Some(choice.clone()),
            Value::Null => None,
            Value::String(s) => Some(none_instead(out, format!("tool_choice {s} (no counterpart here; sent as none)"))),
            Value::Object(o) => match o.get("type").and_then(Value::as_str) {
                Some("function") | None => {
                    let name = o.get("function").and_then(|f| f.get("name")).and_then(Value::as_str);
                    match name {
                        Some(n) if removed.iter().any(|r| r == n) => Some(none_instead(
                            out,
                            format!("tool_choice {n} (forces a tool this protocol cannot declare; sent as none)"),
                        )),
                        Some(n) => Some(json!({"type": "function", "function": {"name": n}})),
                        None => Some(none_instead(out, "tool_choice function without a name (sent as none)".into())),
                    }
                }
                // The allowlist narrows the offered tools; its mode is the choice.
                Some("allowed_tools") => {
                    let spec = o.get("allowed_tools").unwrap_or(&choice);
                    let entries: Vec<&Value> = spec.get("tools").and_then(Value::as_array).into_iter().flatten().collect();
                    let allowed: Vec<&str> = entries
                        .iter()
                        .filter_map(|t| t.get("function").and_then(|f| f.get("name")).and_then(Value::as_str))
                        .collect();
                    // A hosted tool is allowed by its type.
                    let hosted: Vec<&str> = entries
                        .iter()
                        .filter_map(|t| t.get("type").and_then(Value::as_str))
                        .filter(|k| HOSTED_TOOLS.contains(k))
                        .collect();
                    if let Some(Value::Array(tools)) = body.get_mut("tools") {
                        tools.retain(|t| {
                            let kind = t.get("type").and_then(Value::as_str).unwrap_or("function");
                            if HOSTED_TOOLS.contains(&kind) {
                                return hosted.contains(&kind);
                            }
                            t.get("function")
                                .and_then(|f| f.get("name"))
                                .and_then(Value::as_str)
                                .is_some_and(|n| allowed.contains(&n))
                        });
                    }
                    out.adapt("tool_choice allowed_tools sent as the narrowed tool list");
                    match spec.get("mode").and_then(Value::as_str) {
                        Some("required") => Some(Value::from("required")),
                        _ => Some(Value::from("auto")),
                    }
                }
                Some(kind) => {
                    let name = o.get(kind).and_then(|t| t.get("name")).and_then(Value::as_str).unwrap_or(kind);
                    Some(none_instead(out, format!("tool_choice {name} (no counterpart here; sent as none)")))
                }
            },
            _ => Some(none_instead(out, "tool_choice (unreadable; sent as none)".into())),
        };
        if let Some(choice) = choice {
            body.insert("tool_choice".into(), choice);
        }
    }

    // With no tool left, a choice over tools asks nothing.
    if body.get("tools").and_then(Value::as_array).is_some_and(Vec::is_empty) {
        body.remove("tools");
    }
    if !body.contains_key("tools") {
        body.remove("tool_choice");
        body.remove("parallel_tool_calls");
    }
}

/// Strips the prefix Mistral repeats at the start of its answer to a
/// `prefix` the gateway set (see [`Conformed::prefix_echo`]) — from a whole
/// answer's text, or across a stream's text deltas. An answer that does not
/// begin with the prefix is left as it is.
#[derive(Debug, Clone)]
pub struct PrefixEcho {
    /// What of the prefix the stream has yet to repeat.
    remaining: String,
    /// The text deltas held while they matched it.
    held: String,
    done: bool,
}

impl PrefixEcho {
    pub fn new(prefix: String) -> Self {
        let done = prefix.is_empty();
        Self { remaining: prefix, held: String::new(), done }
    }

    /// The stream ended inside the prefix: what it held is the repeat of the
    /// client's own prefill (cut short), never answer text, so it is dropped.
    pub fn finish(&mut self) {
        self.done = true;
        self.held.clear();
    }

    /// A whole answer's text without the repeated prefix.
    pub fn strip<'a>(prefix: &str, text: &'a str) -> Option<&'a str> {
        text.strip_prefix(prefix).filter(|_| !prefix.is_empty())
    }

    /// Drop the repeated prefix from the stream's text deltas. Every other
    /// event passes untouched; held text is given back only when a later
    /// delta shows the answer does not repeat the prefix.
    pub fn filter(&mut self, events: &mut Vec<crate::api::domain::DomainEvent>) {
        use crate::api::domain::DomainEvent;
        if self.done {
            return;
        }
        let mut out = Vec::with_capacity(events.len());
        for event in events.drain(..) {
            if self.done {
                out.push(event);
                continue;
            }
            match event {
                DomainEvent::TextDelta(text) => {
                    if let Some(rest) = self.remaining.strip_prefix(text.as_str()) {
                        self.remaining = rest.to_string();
                        self.held.push_str(&text);
                        self.done = self.remaining.is_empty();
                    } else {
                        self.done = true;
                        let after = match text.strip_prefix(self.remaining.as_str()) {
                            Some(after) => after.to_string(),
                            None => format!("{}{text}", std::mem::take(&mut self.held)),
                        };
                        if !after.is_empty() {
                            out.push(DomainEvent::TextDelta(after));
                        }
                    }
                }
                // Text the answer has not gone on to contradict is still the
                // repeat: another event (the finish, usage, a call) neither
                // confirms nor ends it — the stream's end drops it (`finish`).
                other => out.push(other),
            }
        }
        *events = out;
    }
}

/// A Mistral client's spellings the OpenAI grammar has its own word for, on
/// any other Chat Completions server: `tool_choice: "any"` is `required`
/// (OpenAI's enum has no `any`; OpenAI refuses it), `random_seed` is `seed`.
/// `None` when the body names neither, which is read without parsing it.
pub fn conform_compatible_body(body: Bytes) -> (Bytes, Option<Conformed>) {
    // One pass, comparing only at a quote: a body naming neither is never parsed.
    let named = body
        .iter()
        .enumerate()
        .filter(|(_, b)| **b == b'"')
        .any(|(i, _)| body[i..].starts_with(b"\"any\"") || body[i..].starts_with(b"\"random_seed\""));
    if !named {
        return (body, None);
    }
    let Ok(Value::Object(mut map)) = serde_json::from_slice::<Value>(&body) else {
        return (body, None);
    };
    let mut out = Conformed::default();
    if map.get("tool_choice").and_then(Value::as_str) == Some("any") {
        map.insert("tool_choice".into(), Value::from("required"));
        out.adapt("tool_choice any sent as required");
    }
    if let Some(seed) = map.remove("random_seed") {
        if map.get("seed").is_none_or(Value::is_null) && seed.is_u64() {
            map.insert("seed".into(), seed);
            out.adapt("random_seed sent as seed");
        } else if !seed.is_null() {
            map.insert("random_seed".into(), seed);
        }
    }
    if out.is_empty() {
        return (body, None);
    }
    match serde_json::to_vec(&Value::Object(map)) {
        Ok(b) => (Bytes::from(b), Some(out)),
        Err(_) => (body, None),
    }
}

/// [`conform_chat_request`] over serialized bytes. A body that is not a JSON
/// object is returned as it is: there is nothing to conform, and the upstream
/// is the one to refuse it.
pub fn conform_chat_body(body: Bytes, model: ModelReasoning, prefill: bool) -> (Bytes, Conformed) {
    let Ok(Value::Object(mut map)) = serde_json::from_slice::<Value>(&body) else {
        return (body, Conformed::default());
    };
    let conformed = conform_chat_request(&mut map, model, prefill);
    match serde_json::to_vec(&Value::Object(map)) {
        Ok(b) => (Bytes::from(b), conformed),
        Err(_) => (body, Conformed::default()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn conform(body: Value, reasons: bool) -> (Value, Conformed) {
        let Value::Object(mut map) = body else { panic!("object") };
        let c = conform_chat_request(&mut map, ModelReasoning { accepts: reasons, declared: reasons }, true);
        (Value::Object(map), c)
    }

    fn user(text: &str) -> Value {
        json!({"role": "user", "content": text})
    }

    /// Each top-level field the live API refused with a 422 or a 400 is
    /// renamed or removed, and a removal is named; each it accepted stays as
    /// sent — the positive control, so the pass cannot pass by emptying bodies.
    #[test]
    fn a_body_keeps_only_mistrals_request_fields() {
        let (body, c) = conform(
            json!({
                "model": "ministral-3b-latest", "messages": [user("hi")],
                "seed": 7, "max_completion_tokens": 50, "user": "u1", "store": true,
                "logprobs": true, "top_logprobs": 2, "logit_bias": {"1": 1}, "verbosity": "low",
                "web_search_options": {}, "functions": [{"name": "f"}], "safety_identifier": "s",
                "prompt_cache_retention": "24h", "stream_options": {"include_usage": true},
                "stream": true, "temperature": 0.2, "top_p": 0.9, "stop": ["x"], "n": 1,
                "prediction": {"type": "content", "content": "hi"}, "prompt_cache_key": "k",
                "metadata": {"a": "b"}, "parallel_tool_calls": true, "service_tier": "auto",
                "random_seed_extra_typo": null
            }),
            true,
        );
        let keys: Vec<&str> = body.as_object().unwrap().keys().map(String::as_str).collect();
        for k in keys.iter() {
            assert!(REQUEST_FIELDS.contains(k), "{k} reached Mistral");
        }
        for k in ["stream", "temperature", "top_p", "stop", "n", "prediction", "prompt_cache_key", "metadata", "service_tier"] {
            assert!(keys.contains(&k), "{k} was accepted live and must stay");
        }
        assert_eq!(body["random_seed"], 7);
        assert_eq!(body["max_tokens"], 50);
        assert_eq!(c.adapted, ["seed sent as random_seed", "max_completion_tokens sent as max_tokens"]);
        for named in ["parameter user", "parameter store", "parameter logprobs", "parameter top_logprobs",
            "parameter logit_bias", "parameter verbosity", "parameter web_search_options",
            "parameter functions", "parameter safety_identifier", "parameter prompt_cache_retention"]
        {
            assert!(c.not_carried.iter().any(|n| n == named), "{named} not named: {:?}", c.not_carried);
        }
        // `stream_options` is carried in effect (usage arrives unasked); a null asks nothing.
        assert!(!c.not_carried.iter().any(|n| n.contains("stream_options") || n.contains("typo")));
    }

    /// The renamed cap never runs longer than either cap the client stated, and
    /// a seed Mistral cannot take (negative) is named, not sent.
    #[test]
    fn a_renamed_cap_takes_the_smaller_and_a_negative_seed_is_named() {
        for (max_tokens, mct, want) in [(Some(10), 50, 10), (Some(90), 50, 50), (None, 50, 50)] {
            let mut b = json!({"model": "m", "messages": [user("hi")], "max_completion_tokens": mct});
            if let Some(m) = max_tokens {
                b["max_tokens"] = m.into();
            }
            assert_eq!(conform(b, true).0["max_tokens"], want);
        }
        let (body, c) = conform(json!({"model": "m", "messages": [user("hi")], "seed": -1}), true);
        assert!(body.get("random_seed").is_none() && body.get("seed").is_none());
        assert_eq!(c.not_carried, ["seed -1"]);
        // An explicit `random_seed` is the client's own and wins.
        let (body, _) = conform(json!({"model": "m", "messages": [user("hi")], "seed": 1, "random_seed": 2}), true);
        assert_eq!(body["random_seed"], 2);
    }

    /// Live: `service_tier` takes `auto` or `standard_only`; OpenAI's other
    /// values are a 422.
    #[test]
    fn only_mistrals_service_tiers_pass() {
        for tier in ["auto", "standard_only"] {
            let (body, c) = conform(json!({"model": "m", "messages": [user("hi")], "service_tier": tier}), true);
            assert_eq!(body["service_tier"], tier);
            assert!(c.is_empty());
        }
        for tier in ["default", "flex", "scale", "priority"] {
            let (body, c) = conform(json!({"model": "m", "messages": [user("hi")], "service_tier": tier}), true);
            assert!(body.get("service_tier").is_none(), "{tier}");
            assert_eq!(c.not_carried, [format!("service_tier {tier}")]);
        }
    }

    /// A model known not to reason refuses `reasoning_effort` and a `thinking`
    /// chunk in history; one that reasons (or is not known not to) keeps both.
    #[test]
    fn reasoning_reaches_only_a_model_not_known_not_to_reason() {
        let body = json!({"model": "m", "reasoning_effort": "high", "messages": [
            user("hi"),
            {"role": "assistant", "content": [
                {"type": "thinking", "thinking": [{"type": "text", "text": "t"}]},
                {"type": "text", "text": "hello"}]},
            {"role": "assistant", "content": "again", "reasoning_content": "more"},
            user("again")]});
        let (kept, c) = conform(body.clone(), true);
        assert_eq!(kept["reasoning_effort"], "high");
        assert_eq!(kept["messages"][1]["content"][0]["type"], "thinking");
        // A `reasoning_content` key becomes Mistral's thinking chunk before the text.
        assert_eq!(kept["messages"][2]["content"][0]["thinking"][0]["text"], "more");
        assert_eq!(kept["messages"][2]["content"][1]["text"], "again");
        assert!(kept["messages"][2].get("reasoning_content").is_none());
        assert!(c.not_carried.is_empty());

        let (dropped, c) = conform(body, false);
        assert!(dropped.get("reasoning_effort").is_none());
        assert_eq!(dropped["messages"][1]["content"], json!([{"type": "text", "text": "hello"}]));
        assert_eq!(dropped["messages"][2]["content"], "again");
        assert_eq!(
            c.not_carried,
            ["reasoning_effort high (the model does not reason)", "reasoning in history (×2, the model does not reason)"]
        );
        // A reasoning key in another shape has no Mistral form: named, not lost.
        let (body, c) = conform(
            json!({"model": "m", "messages": [user("hi"), {"role": "assistant", "content": "ok", "reasoning": {"summary": "s"}}, user("again")]}),
            true,
        );
        assert!(body["messages"][1].get("reasoning").is_none());
        assert_eq!(c.not_carried, ["reasoning on an assistant message"]);
        // `none` asks for no reasoning, which a model that does not reason gives.
        let (_, c) = conform(json!({"model": "m", "messages": [user("hi")], "reasoning_effort": "none"}), false);
        assert!(c.not_carried.is_empty());
    }

    /// Mistral's effort enum is `none | minimal | low | medium | high | xhigh`,
    /// and it refuses even `none` on a model that does not reason (live). A
    /// value outside the enum is narrowed or removed, never deepened; each
    /// change is named.
    #[test]
    fn reasoning_effort_takes_mistrals_enum_and_the_models_capability() {
        let effort = |value: Value, accepts: bool, declared: bool| {
            let Value::Object(mut map) = json!({"model": "m", "messages": [user("hi")], "reasoning_effort": value}) else {
                unreachable!()
            };
            let c = conform_chat_request(&mut map, ModelReasoning { accepts, declared }, true);
            (map.get("reasoning_effort").cloned(), c)
        };
        for word in EFFORTS {
            let (kept, c) = effort(Value::from(*word), true, true);
            assert_eq!(kept, Some(Value::from(*word)), "{word}");
            assert!(c.is_empty(), "{word}");
        }
        let (sent, c) = effort(Value::from("max"), true, true);
        assert_eq!(sent, Some(Value::from("xhigh")));
        assert_eq!(c.adapted, ["reasoning_effort max sent as xhigh"]);
        let (sent, c) = effort(Value::from("ultra"), true, true);
        assert_eq!((sent, c.not_carried), (None, vec!["reasoning_effort ultra".to_string()]));
        // `none` only where the model is declared to reason.
        let (sent, c) = effort(Value::from("none"), true, false);
        assert_eq!((sent, c.not_carried), (None, vec!["reasoning_effort none (not confirmed for this model)".to_string()]));
        let (sent, c) = effort(Value::from("none"), false, false);
        assert_eq!(sent, None);
        assert!(c.is_empty(), "a model that does not reason needs no switch");
        // A cap that is not a count is named, not lost silently.
        let Value::Object(mut map) = json!({"model": "m", "messages": [user("hi")], "max_completion_tokens": "50"}) else {
            unreachable!()
        };
        let c = conform_chat_request(&mut map, ModelReasoning { accepts: true, declared: true }, true);
        assert_eq!(c.not_carried, ["max_completion_tokens \"50\""]);
    }

    /// Live: `name` on a user message is a 422, an empty assistant turn a 400,
    /// a trailing assistant a 400 unless `prefix: true`; `""` beside tool calls
    /// and `name` on a tool message are accepted.
    #[test]
    fn messages_take_mistrals_shape() {
        let (body, c) = conform(
            json!({"model": "m", "messages": [
                {"role": "developer", "content": "be terse"},
                {"role": "user", "content": "hi", "name": "bob"},
                {"role": "assistant", "content": ""},
                {"role": "assistant", "content": null, "refusal": null},
                user("time?"),
                {"role": "assistant", "content": "", "tool_calls": [
                    {"id": "toolu_01", "type": "function", "function": {"name": "t", "arguments": "{}"}, "extra": 1}]},
                {"role": "tool", "tool_call_id": "toolu_01", "name": "t", "content": "12:00"},
                {"role": "function", "name": "old", "content": "x"},
                {"role": "assistant", "content": "It is"}]}),
            true,
        );
        let msgs = body["messages"].as_array().unwrap();
        let roles: Vec<&str> = msgs.iter().map(|m| m["role"].as_str().unwrap()).collect();
        assert_eq!(roles, ["system", "user", "user", "assistant", "tool", "assistant"]);
        assert!(msgs[1].get("name").is_none());
        assert_eq!(msgs[3]["content"], "");
        assert_eq!(msgs[3]["tool_calls"][0], json!({"id": "toolu_01", "type": "function", "function": {"name": "t", "arguments": "{}"}}));
        assert_eq!(msgs[4]["name"], "t");
        assert_eq!(msgs[5]["prefix"], true);
        assert_eq!(c.not_carried, ["name on a user message", "extra on a tool call", "legacy function message"]);
        assert_eq!(
            c.adapted,
            ["developer message sent as system", "trailing assistant message sent as a prefix"]
        );
        // A Chat client's own trailing assistant message goes as written:
        // only a protocol with prefill semantics is sent as a prefix.
        let Value::Object(mut map) = json!({"model": "m", "messages": [user("x"), {"role": "assistant", "content": "It"}]}) else {
            unreachable!()
        };
        let c = conform_chat_request(&mut map, ModelReasoning { accepts: true, declared: true }, false);
        assert!(map["messages"][1].get("prefix").is_none());
        assert!(c.prefix_echo.is_none());
        // A trailing assistant turn that CALLS tools is not a prefill.
        let (body, _) = conform(
            json!({"model": "m", "messages": [user("x"), {"role": "assistant", "tool_calls": [
                {"id": "a", "type": "function", "function": {"name": "t", "arguments": "{}"}}]}]}),
            true,
        );
        assert!(body["messages"][1].get("prefix").is_none());
    }

    /// Parts Mistral has: kept, stray keys removed. Parts it has not: a visible
    /// text marker in their place, and named.
    #[test]
    fn content_parts_take_mistrals_chunk_kinds() {
        let (body, c) = conform(
            json!({"model": "m", "messages": [{"role": "user", "content": [
                {"type": "text", "text": "a", "cache_control": {"type": "ephemeral"}},
                {"type": "image_url", "image_url": {"url": "https://x/y.png", "detail": "low"}},
                {"type": "input_audio", "input_audio": {"data": "AAAA", "format": "wav"}},
                {"type": "input_audio", "input_audio": "AAAA"},
                {"type": "file", "file": {"file_id": "f-1"}},
                {"type": "file", "file": {"file_data": "data:application/pdf;base64,AA", "filename": "a.pdf"}},
                {"type": "document_url", "document_url": "https://x/a.pdf"},
                {"type": "refusal", "refusal": "no"}]},
                {"role": "system", "content": [{"type": "image_url", "image_url": "https://x/y.png"}]},
                user("go")]}),
            true,
        );
        let parts = body["messages"][0]["content"].as_array().unwrap();
        assert_eq!(parts[0], json!({"type": "text", "text": "a"}));
        assert_eq!(parts[1]["image_url"]["detail"], "low");
        // Mistral's `AudioChunk.input_audio` is a string; the object goes as a data URL.
        assert_eq!(parts[2]["input_audio"], "data:audio/wav;base64,AAAA");
        assert_eq!(parts[3]["input_audio"], "AAAA");
        assert_eq!(parts[4], json!({"type": "file", "file_id": "f-1"}));
        assert_eq!(parts[5], json!({"type": "text", "text": "[File a.pdf: not carried to this model]"}));
        assert_eq!(parts[6]["document_url"], "https://x/a.pdf");
        assert_eq!(parts[7], json!({"type": "text", "text": "[refusal part: not carried to this model]"}));
        assert_eq!(body["messages"][1]["content"][0]["type"], "text");
        assert_eq!(
            c.not_carried,
            ["cache_control on a text part", "inline file a.pdf", "refusal part on a user message", "image_url part on a system message"]
        );
    }

    /// Live: a function without `parameters`, a `custom` tool and an
    /// `allowed_tools` choice are each a 422. The choice is never widened: an
    /// allowlist narrows the tools, a choice forcing a removed tool is `none`.
    #[test]
    fn tools_and_the_choice_over_them_take_mistrals_shape() {
        let f = |name: &str| json!({"type": "function", "function": {"name": name, "parameters": {"type": "object"}}});
        let (body, c) = conform(
            json!({"model": "m", "messages": [user("x")],
                "tools": [f("a"), f("b"), {"type": "function", "function": {"name": "c"}},
                    {"type": "custom", "custom": {"name": "patch"}}, {"type": "file_search"}, {"type": "web_search"}],
                "tool_choice": {"type": "allowed_tools", "allowed_tools": {"mode": "required",
                    "tools": [{"type": "function", "function": {"name": "a"}}, {"type": "function", "function": {"name": "c"}}]}}}),
            true,
        );
        // OpenAI's hosted tool has no Mistral form.
        let names: Vec<&str> = body["tools"]
            .as_array()
            .unwrap()
            .iter()
            .map(|t| t["function"]["name"].as_str().or(t["type"].as_str()).unwrap())
            .collect();
        // The client's allowlist narrows to `a` and `c`.
        assert_eq!(names, ["a", "c"]);
        assert_eq!(body["tools"][1]["function"]["parameters"], json!({"type": "object", "properties": {}}));
        assert_eq!(body["tool_choice"], "required");
        assert_eq!(c.not_carried, ["freeform tool patch", "hosted tool file_search"]);

        let (body, c) = conform(
            json!({"model": "m", "messages": [user("x")], "tools": [f("a"), {"type": "custom", "custom": {"name": "patch"}}],
                "tool_choice": {"type": "custom", "custom": {"name": "patch"}}}),
            true,
        );
        assert_eq!(body["tool_choice"], "none");
        assert!(c.not_carried.iter().any(|n| n.starts_with("tool_choice patch")));
        let (body, _) = conform(
            json!({"model": "m", "messages": [user("x")], "tools": [f("a"), {"type": "custom", "custom": {"name": "patch"}}],
                "tool_choice": {"type": "function", "function": {"name": "patch"}}}),
            true,
        );
        assert_eq!(body["tool_choice"], "none");
        // An allowlist naming a hosted tool by its type keeps it.
        let (body, _) = conform(
            json!({"model": "m", "messages": [user("x")], "tools": [{"type": "web_search"}, f("a"), f("b")],
                "tool_choice": {"type": "allowed_tools", "allowed_tools": {"mode": "auto",
                    "tools": [{"type": "web_search"}, {"type": "function", "function": {"name": "a"}}]}}}),
            true,
        );
        let kinds: Vec<&str> = body["tools"].as_array().unwrap().iter()
            .map(|t| t["function"]["name"].as_str().or(t["type"].as_str()).unwrap()).collect();
        assert_eq!(kinds, ["web_search", "a"]);
        // Without an allowlist Mistral's own hosted tool goes as written.
        let (body, c) = conform(json!({"model": "m", "messages": [user("x")], "tools": [{"type": "web_search"}, f("a")]}), true);
        assert_eq!(body["tools"][0], json!({"type": "web_search"}));
        assert!(c.is_empty(), "{c:?}");
        // Mistral's own words pass, and a named function stays named.
        for choice in ["auto", "none", "any", "required"] {
            let (body, c) = conform(json!({"model": "m", "messages": [user("x")], "tools": [f("a")], "tool_choice": choice}), true);
            assert_eq!(body["tool_choice"], choice);
            assert!(c.is_empty());
        }
        // No tool left: nothing to choose over.
        let (body, _) = conform(
            json!({"model": "m", "messages": [user("x")], "tools": [{"type": "file_search"}], "tool_choice": "required", "parallel_tool_calls": false}),
            true,
        );
        assert!(body.get("tools").is_none() && body.get("tool_choice").is_none() && body.get("parallel_tool_calls").is_none());
    }

    /// A freeform call in history has no Mistral form; it goes as the function
    /// call the gateway's domain makes of one.
    #[test]
    fn a_freeform_call_in_history_goes_as_a_function_call() {
        let (body, c) = conform(
            json!({"model": "m", "messages": [user("x"),
                {"role": "assistant", "tool_calls": [{"id": "c1", "type": "custom", "custom": {"name": "patch", "input": "*** diff"}}]},
                {"role": "tool", "tool_call_id": "c1", "content": "ok"}]}),
            true,
        );
        assert_eq!(
            body["messages"][1]["tool_calls"][0],
            json!({"id": "c1", "type": "function", "function": {"name": "patch", "arguments": "{\"input\":\"*** diff\"}"}})
        );
        assert_eq!(c.adapted, ["freeform tool call in history sent as a function call"]);
    }

    /// Mistral answers a prefix with the prefix repeated (live: `Hel` → `Hello!`).
    /// A translated client's prefill expects the continuation alone, so the
    /// repeat is stripped — across text deltas cut anywhere, reasoning passing
    /// first — and an answer that does not repeat it is left whole.
    #[test]
    fn the_repeated_prefix_is_stripped_however_the_stream_cuts_it() {
        use crate::api::domain::DomainEvent;
        let text = |events: &[DomainEvent]| -> String {
            events
                .iter()
                .filter_map(|e| match e {
                    DomainEvent::TextDelta(t) => Some(t.as_str()),
                    _ => None,
                })
                .collect()
        };
        let run = |pieces: &[&str]| -> (String, usize) {
            let mut echo = PrefixEcho::new("The document".into());
            let mut all = vec![DomainEvent::ReasoningDelta("why".into())];
            echo.filter(&mut all);
            for p in pieces {
                let mut evs = vec![DomainEvent::TextDelta((*p).to_string())];
                echo.filter(&mut evs);
                all.extend(evs);
            }
            let mut end = vec![DomainEvent::Done { finish_reason: None, native_finish_reason: None }];
            echo.filter(&mut end);
            all.extend(end);
            let reasoning = all.iter().filter(|e| matches!(e, DomainEvent::ReasoningDelta(_))).count();
            (text(&all), reasoning)
        };
        assert_eq!(run(&["The document says X."]), (" says X.".to_string(), 1));
        assert_eq!(run(&["The ", "doc", "ument", " says X."]), (" says X.".to_string(), 1));
        assert_eq!(run(&["The doc", "ument says", " X."]), (" says X.".to_string(), 1));
        // Not repeated: the answer whole, the held text given back in order.
        assert_eq!(run(&["The ", "answer is X."]), ("The answer is X.".to_string(), 1));
        assert_eq!(run(&["Sure."]), ("Sure.".to_string(), 1));
        // Cut off inside the prefix (the finish arrives in the same chunk):
        // what was held is the repeat of the client's own prefill — dropped.
        assert_eq!(run(&["The doc"]), (String::new(), 1));
        let mut echo = PrefixEcho::new("The document".into());
        let mut evs = vec![crate::api::domain::DomainEvent::TextDelta("The doc".into())];
        echo.filter(&mut evs);
        echo.finish();
        assert!(evs.is_empty());
        assert_eq!(PrefixEcho::strip("The document", "The document says X."), Some(" says X."));
        assert_eq!(PrefixEcho::strip("The document", "Sure."), None);
        assert_eq!(PrefixEcho::strip("", "Sure."), None);
    }

    /// A Mistral client's `any` and `random_seed` reach any other Chat server in
    /// the OpenAI grammar; a body naming neither is not touched.
    #[test]
    fn a_mistral_clients_spellings_reach_a_compatible_server_in_openais() {
        let (body, c) = conform_compatible_body(Bytes::from(
            json!({"model": "m", "tool_choice": "any", "random_seed": 3, "messages": [user("x")]}).to_string(),
        ));
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!((body["tool_choice"].clone(), body["seed"].clone()), (json!("required"), json!(3)));
        assert!(body.get("random_seed").is_none());
        assert_eq!(c.unwrap().adapted, ["tool_choice any sent as required", "random_seed sent as seed"]);
        // The client's own `seed` wins; the word "any" in a message is not a choice.
        let raw = Bytes::from(json!({"model": "m", "seed": 1, "random_seed": 2, "messages": [user("\"any\"")]}).to_string());
        let (body, c) = conform_compatible_body(raw);
        let body: Value = serde_json::from_slice(&body).unwrap();
        assert_eq!((body["seed"].clone(), body["random_seed"].clone()), (json!(1), json!(2)));
        assert!(c.is_none());
        let plain = Bytes::from_static(br#"{"model":"m","tool_choice":"auto"}"#);
        assert_eq!(conform_compatible_body(plain.clone()), (plain, None));
    }

    #[test]
    fn the_dialect_is_mistrals_api_by_provider_or_host() {
        assert_eq!(ChatDialect::for_upstream("mistral", "https://api.mistral.ai/v1"), ChatDialect::Mistral);
        assert_eq!(ChatDialect::for_upstream("custom", "https://api.mistral.ai/v1"), ChatDialect::Mistral);
        assert_eq!(ChatDialect::for_upstream("mistral", "https://my-proxy.example/v1"), ChatDialect::Mistral);
        assert_eq!(ChatDialect::for_upstream("custom", "http://vllm:8000/v1"), ChatDialect::Compatible);
        assert_eq!(ChatDialect::for_upstream("openai", "https://evil-mistral.ai.example.com/v1"), ChatDialect::Compatible);
    }

    fn arb_json() -> impl Strategy<Value = Value> {
        let key = prop_oneof![
            Just("role".to_string()), Just("content".to_string()), Just("type".to_string()),
            Just("text".to_string()), Just("tools".to_string()), Just("tool_choice".to_string()),
            Just("messages".to_string()), Just("function".to_string()), Just("tool_calls".to_string()),
            Just("name".to_string()), Just("seed".to_string()), "[a-z_]{1,8}",
        ];
        let leaf = prop_oneof![
            Just(Value::Null), any::<bool>().prop_map(Value::from), any::<i64>().prop_map(Value::from),
            prop_oneof![Just("user"), Just("assistant"), Just("system"), Just("tool"), Just("developer"),
                Just("function"), Just("text"), Just("thinking"), Just("custom"), Just("allowed_tools"), Just("any")]
                .prop_map(Value::from),
            "[a-z]{0,6}".prop_map(Value::from),
        ];
        leaf.prop_recursive(4, 48, 6, move |inner| {
            prop_oneof![
                prop::collection::vec(inner.clone(), 0..5).prop_map(Value::Array),
                prop::collection::btree_map(key.clone(), inner, 0..6)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// Whatever a client sends, what reaches Mistral names only fields its
        /// schema has, at the top level, on each message and on each tool; and
        /// conforming a conformed body changes nothing. Not claimed: that the
        /// VALUES are valid (a string where Mistral wants a number goes on to
        /// be refused upstream — the gateway does not re-validate the client).
        #[test]
        fn a_conformed_body_names_only_mistrals_fields(body in prop::collection::btree_map(
            prop_oneof![Just("messages".to_string()), Just("tools".to_string()), Just("tool_choice".to_string()),
                Just("seed".to_string()), Just("service_tier".to_string()), "[a-z_]{1,10}"],
            arb_json(), 0..8), reasons in any::<bool>())
        {
            let mut map: Map<String, Value> = body.into_iter().collect();
            let model = ModelReasoning { accepts: reasons, declared: reasons };
            conform_chat_request(&mut map, model, reasons);
            for k in map.keys() {
                prop_assert!(REQUEST_FIELDS.contains(&k.as_str()), "top-level {}", k);
            }
            for m in map.get("messages").and_then(Value::as_array).into_iter().flatten() {
                if let Some(o) = m.as_object()
                    && let Some(role) = o.get("role").and_then(Value::as_str)
                {
                    for k in o.keys() {
                        prop_assert!(message_fields(role).contains(&k.as_str()), "{} on {}", k, role);
                    }
                    prop_assert!(role != "developer" && role != "function");
                }
            }
            for t in map.get("tools").and_then(Value::as_array).into_iter().flatten() {
                let kind = t.get("type").and_then(Value::as_str).unwrap_or("function");
                if HOSTED_TOOLS.contains(&kind) {
                    continue;
                }
                prop_assert_eq!(kind, "function");
                prop_assert!(t.get("function").and_then(|f| f.get("parameters")).is_some_and(|p| !p.is_null()));
            }
            let once = map.clone();
            conform_chat_request(&mut map, model, reasons);
            prop_assert_eq!(map, once);
        }
    }
}
