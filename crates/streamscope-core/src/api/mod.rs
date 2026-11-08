//! API protocol types and request dispatch.
//!
//! Supports four LLM API protocols: OpenAI Chat Completions (`/v1/chat/completions`),
//! OpenAI Responses (`/v1/responses`), Anthropic Messages (`/v1/messages`),
//! and Google Gemini (`/v1beta/models/{model}:generateContent`).
//! [`ApiRequest`] is the dispatch enum — inbound requests are parsed into the
//! appropriate variant and all downstream processing is protocol-aware.
//!
//! The [`media`] module handles non-chat endpoints: embeddings, audio (TTS/STT),
//! image generation, and video generation. All media types go through the same
//! domain abstraction layer as text for transforms, rules, and audit.
//!
//! For cross-protocol translation, requests convert through the canonical
//! [`domain_request::DomainRequest`] form (O(n) conversions, not O(n²)).

pub mod call_ids;
pub mod chat;
pub mod domain;
pub mod domain_request;
pub mod gemini;
pub mod media;
pub mod messages;
pub mod mistral;
pub mod responses;
pub mod sse;
pub mod tool_choice;

use bytes::Bytes;
use serde_json::Value;

use self::chat::ChatCompletionsRequest;
use self::gemini::GeminiRequest;
use self::messages::MessagesRequest;
use self::messages::{AnthropicContent, ContentBlock, ToolResultBlock, ToolResultContent};
use self::responses::ResponsesRequest;
use self::sse::ApiVersion;
use crate::error::AppError;
use crate::proxy::content::RedactedToolResultInfo;

/// A Responses `shell_call_output`'s text as a result rule reads it: each
/// chunk's `stdout`, then its `stderr`, the non-empty ones joined by lines.
fn shell_output_text(chunks: &[serde_json::Value]) -> String {
    chunks
        .iter()
        .flat_map(|chunk| ["stdout", "stderr"].map(|stream| chunk.get(stream).and_then(|v| v.as_str())))
        .flatten()
        .filter(|text| !text.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Write a result rule's rewrite of a `shell_call_output` back: the whole text
/// into the first chunk's `stdout`, every other `stdout` and `stderr` emptied,
/// each chunk's `outcome` kept — the text was read joined
/// ([`shell_output_text`]), so no part of the original may remain beside it.
fn set_shell_output_text(chunks: &mut [serde_json::Value], text: String) {
    let mut text = Some(text);
    for chunk in chunks.iter_mut() {
        if let Some(obj) = chunk.as_object_mut() {
            obj.insert("stdout".to_string(), serde_json::Value::String(text.take().unwrap_or_default()));
            obj.insert("stderr".to_string(), serde_json::Value::String(String::new()));
        }
    }
}

/// A Responses input item answering a built-in tool the client ran — a
/// `local_shell_call_output`, `shell_call_output` or `apply_patch_call_output`
/// — as the result rules ([`ApiRequest::redact_tool_results`]) read it
/// ([`OutputRead`]), and as the inbound guardrail reads it
/// ([`BuiltinOutput::screen_text`]) and withholds it
/// ([`replace_builtin_output`]). A `computer_call_output` is a screenshot, no
/// text.
pub struct BuiltinOutput {
    pub builtin: domain::ClientBuiltin,
    /// The call it answers: its `call_id`, or — a local shell output's — its
    /// `id`; empty when it names none.
    pub call_id: String,
    pub read: OutputRead,
}

/// What a [`BuiltinOutput`]'s `output` holds for a result rule.
pub enum OutputRead {
    /// Its text: a string, a shell output's chunks' `stdout` then `stderr`
    /// joined by lines ([`shell_output_text`]), or a list of parts' text.
    Text(String),
    /// No text: none sent, or shell chunks that are all empty.
    Empty,
    /// A shape no rewrite could reach — a shell chunk that is not an object of
    /// string streams, an object where text belongs: a result rule does not
    /// read it (the inbound guardrail reads it whole,
    /// [`BuiltinOutput::screen_text`]).
    OffSpec,
}

impl BuiltinOutput {
    /// `item` read as a built-in tool's output; `None` when it is not one.
    pub fn of(item: &Value) -> Option<Self> {
        let kind = item.get("type").and_then(Value::as_str)?;
        let builtin = domain::ClientBuiltin::of_item_type(kind.strip_suffix("_output")?)
            .filter(|b| *b != domain::ClientBuiltin::Computer)?;
        let id_field = |key: &str| item.get(key).and_then(Value::as_str).filter(|id| !id.is_empty());
        let call_id = id_field("call_id")
            .or_else(|| (builtin == domain::ClientBuiltin::LocalShell).then(|| id_field("id")).flatten())
            .unwrap_or("")
            .to_string();
        let read = match item.get("output") {
            Some(Value::String(text)) => OutputRead::Text(text.clone()),
            // A shell chunk list is read when every chunk is an object whose
            // `stdout` / `stderr` are strings — what the reader and the writer
            // ([`set_shell_output_text`]) handle — and some chunk holds text.
            Some(Value::Array(chunks)) if builtin == domain::ClientBuiltin::Shell => {
                let readable = chunks.iter().all(|chunk| {
                    chunk.as_object().is_some_and(|o| {
                        ["stdout", "stderr"].iter().all(|f| o.get(*f).is_none_or(|v| v.is_string() || v.is_null()))
                    })
                });
                match shell_output_text(chunks) {
                    _ if !readable => OutputRead::OffSpec,
                    text if text.is_empty() => OutputRead::Empty,
                    text => OutputRead::Text(text),
                }
            }
            Some(Value::Array(parts)) => OutputRead::Text(parts_text(parts)),
            None | Some(Value::Null) => OutputRead::Empty,
            Some(_) => OutputRead::OffSpec,
        };
        Some(Self { builtin, call_id, read })
    }

    /// `item`'s output text when the item is exactly its spec form
    /// ([`canonical_builtin_output`]); `None` when it is not.
    fn spec_text(item: &Value) -> Option<String> {
        let spec = canonical_builtin_output(item)?;
        if spec != without_nulls(item) {
            return None;
        }
        Some(match spec.get("output") {
            Some(Value::String(text)) => text.clone(),
            Some(Value::Array(chunks)) => shell_output_text(chunks),
            _ => String::new(),
        })
    }

    /// What the inbound guardrail reads of `item`: a spec-form item's output
    /// text, with each chunk's `created_by` (the console shows the text alone);
    /// any other
    /// item whole, as its JSON — but for its ids, and for the `role` and
    /// `content` of one carrying a `role`, which the conversion reads as a message of their
    /// own, screened or not by that role as any message is — so no field
    /// beyond the spec form goes unread. `None` when a spec-form item holds no
    /// text. Deliberately NOT read, in any form: its ids (`call_id`, `id`, a
    /// program `caller_id`). The
    /// model or the client writes them, not the tool, and a withhold could
    /// not take them away without unpairing the output from its call: a
    /// finding there would be recorded as withheld and still be sent. Locked
    /// by `a_field_beyond_the_spec_form_is_read_whole`.
    pub fn screen_text(&self, item: &Value) -> Option<String> {
        let mut own = without_message(item);
        let Some(text) = Self::spec_text(&own) else {
            // Read whole — but for what a withhold keeps as it came.
            if let Some(obj) = own.as_object_mut() {
                for field in kept_fields(item) {
                    obj.remove(field);
                }
                if let Some(caller) = obj.get_mut("caller").and_then(Value::as_object_mut)
                    && caller.get("caller_id").is_some_and(Value::is_string)
                {
                    caller.remove("caller_id");
                }
            }
            return Some(own.to_string());
        };
        // A chunk's `created_by` is no part of the pairing, and a withhold
        // drops it: it is read with the streams.
        let created_by = own
            .get("output")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .filter_map(|c| c.get("created_by").and_then(Value::as_str));
        let read: Vec<&str> = std::iter::once(text.as_str()).chain(created_by).filter(|s| !s.is_empty()).collect();
        (!read.is_empty()).then(|| read.join("\n"))
    }

    /// Whether `item` is exactly its spec form, so the inbound guardrail reads
    /// its output's text and not the whole item ([`Self::screen_text`]).
    pub fn is_spec_form(item: &Value) -> bool {
        Self::spec_text(&without_message(item)).is_some()
    }

    /// Whether it answers a shell call the server ran in its hosted container
    /// (`hosted`: [`hosted_shell_call_ids`]) — like that call, not the
    /// client's.
    pub fn is_hosted(&self, hosted: &std::collections::HashSet<String>) -> bool {
        self.builtin == domain::ClientBuiltin::Shell && hosted.contains(&self.call_id)
    }
}

/// The fields of a built-in output `item` a withhold keeps as they came, and
/// the inbound guardrail so does not read: its string ids (`call_id`, `id`),
/// which pair it with its call, and a string `role` with a string `content`,
/// which the conversion reads as a message of their own, screened or not by
/// that role as any message is.
fn kept_fields(item: &Value) -> Vec<&'static str> {
    let string = |field: &str| item.get(field).is_some_and(Value::is_string);
    let mut kept: Vec<&'static str> = ["call_id", "id"].into_iter().filter(|id| string(id)).collect();
    if string("role") {
        kept.push("role");
        if string("content") {
            kept.push("content");
        }
    }
    kept
}

/// `item` without the message the conversion reads of it ([`kept_fields`]: a
/// string `role` and a string `content`).
fn without_message(item: &Value) -> Value {
    let mut own = item.clone();
    if let Some(obj) = own.as_object_mut() {
        for field in kept_fields(item).into_iter().filter(|f| matches!(*f, "role" | "content")) {
            obj.remove(field);
        }
    }
    own
}

/// The call ids of the shell calls among `items` the server runs in a hosted
/// container ([`domain::ClientBuiltin::is_hosted_shell`]); the last shell call
/// under an id decides.
pub(crate) fn hosted_shell_call_ids(items: &[Value]) -> std::collections::HashSet<String> {
    let mut hosted = std::collections::HashSet::new();
    for item in items {
        let Some(id) = item.get("call_id").and_then(Value::as_str).filter(|id| !id.is_empty()) else {
            continue;
        };
        if domain::ClientBuiltin::is_hosted_shell(item) {
            hosted.insert(id.to_string());
        } else if domain::ClientBuiltin::of_item(item) == Some(domain::ClientBuiltin::Shell) {
            hosted.remove(id);
        }
    }
    hosted
}

/// A list of output parts' text, joined (`input_text`, …; a part with no text
/// is not read).
fn parts_text(parts: &[Value]) -> String {
    parts.iter().filter_map(|p| p.get("text").and_then(Value::as_str)).collect()
}

/// A built-in tool's output `item` in its spec form, holding nothing else: its
/// `type`, its `call_id` and `id` when strings, its
/// `status` when one its tool's spec gives, its `caller` (direct, or a program
/// by its id) where its tool has one, a shell output's `max_output_length`,
/// and an `output` that is a string, a shell output's list of chunks holding
/// only string `stdout` / `stderr` / `created_by` and an `outcome` that is an
/// exit with its code or a timeout, or absent; `None` when the output has no
/// spec form.
fn canonical_builtin_output(item: &Value) -> Option<Value> {
    let output = item.get("output").cloned();
    let kind = item.get("type").and_then(Value::as_str)?;
    let shell = kind == "shell_call_output";
    let mut out = serde_json::Map::new();
    out.insert("type".to_string(), item.get("type")?.clone());
    // A local shell output names its call by `id` alone.
    let ids: &[&str] = if kind == "local_shell_call_output" { &["id"] } else { &["call_id", "id"] };
    for id in ids {
        if let Some(v) = item.get(*id).filter(|v| v.is_string()) {
            out.insert(id.to_string(), v.clone());
        }
    }
    let statuses: &[&str] = if kind == "apply_patch_call_output" {
        &["completed", "failed"]
    } else {
        &["in_progress", "completed", "incomplete"]
    };
    if let Some(status) = item.get("status").filter(|s| s.as_str().is_some_and(|s| statuses.contains(&s))) {
        out.insert("status".to_string(), status.clone());
    }
    // Who called it — directly, or a program by its id — on the tools whose
    // output names one.
    let caller = item.get("caller").filter(|_| kind != "local_shell_call_output").and_then(|c| {
        match c.get("type").and_then(Value::as_str)? {
            "direct" => Some(serde_json::json!({"type": "direct"})),
            "program" => Some(serde_json::json!({"type": "program", "caller_id": c.get("caller_id").filter(|id| id.is_string())?})),
            _ => None,
        }
    });
    if let Some(caller) = caller {
        out.insert("caller".to_string(), caller);
    }
    if shell && let Some(max) = item.get("max_output_length").filter(|m| m.is_u64()) {
        out.insert("max_output_length".to_string(), max.clone());
    }
    match output {
        None | Some(Value::Null) => {}
        Some(Value::String(text)) => {
            out.insert("output".to_string(), Value::String(text));
        }
        Some(Value::Array(chunks)) if shell => {
            let spec = chunks.iter().map(spec_chunk).collect::<Option<Vec<_>>>()?;
            out.insert("output".to_string(), Value::Array(spec));
        }
        Some(_) => return None,
    }
    Some(Value::Object(out))
}

/// A shell output chunk in its spec form: its string `stdout`, `stderr` and
/// `created_by` (on OpenAI's own output chunks, which a stateless client
/// echoes) and its spec `outcome` ([`spec_outcome`]), holding nothing else;
/// `None` when it is not an object or its `outcome` has no spec form.
fn spec_chunk(chunk: &Value) -> Option<Value> {
    chunk.as_object()?;
    let mut c = serde_json::Map::new();
    for field in ["stdout", "stderr", "created_by"] {
        if let Some(v) = chunk.get(field).filter(|v| v.is_string()) {
            c.insert(field.to_string(), v.clone());
        }
    }
    if let Some(o) = chunk.get("outcome").filter(|o| !o.is_null()) {
        c.insert("outcome".to_string(), spec_outcome(o)?);
    }
    Some(Value::Object(c))
}

/// `value` with every `null` member dropped, at every depth: a field the spec
/// lets be `null` is a field not sent.
fn without_nulls(value: &Value) -> Value {
    match value {
        Value::Object(o) => Value::Object(
            o.iter().filter(|(_, v)| !v.is_null()).map(|(k, v)| (k.clone(), without_nulls(v))).collect(),
        ),
        Value::Array(a) => Value::Array(a.iter().map(without_nulls).collect()),
        other => other.clone(),
    }
}

/// A shell chunk's `outcome` in its spec form — an exit with its code, or a
/// timeout — holding nothing else; `None` when it is neither.
fn spec_outcome(o: &Value) -> Option<Value> {
    match o.get("type").and_then(Value::as_str)? {
        "exit" => Some(serde_json::json!({"type": "exit", "exit_code": o.get("exit_code").filter(|c| c.is_number())?})),
        "timeout" => Some(serde_json::json!({"type": "timeout"})),
        _ => None,
    }
}

/// Write `text` as a built-in tool's whole `output`: a string where it was a
/// string or is not a shell list; a shell list keeps one chunk per chunk it had
/// — `text` in the first chunk's `stdout`, every other stream empty, each
/// chunk's spec `outcome` kept (none is made up) — and nothing else.
fn write_whole_output(item: &mut Value, text: String) {
    let shell_list = item.get("type").and_then(Value::as_str) == Some("shell_call_output")
        && item.get("output").is_some_and(Value::is_array);
    item["output"] = if shell_list {
        let mut text = Some(text);
        let chunks = item["output"].as_array().map(Vec::as_slice).unwrap_or_default();
        let written: Vec<Value> = chunks
            .iter()
            .map(|c| {
                let mut chunk = serde_json::json!({"stdout": text.take().unwrap_or_default(), "stderr": ""});
                if let Some(outcome) = c.get("outcome").and_then(spec_outcome) {
                    chunk["outcome"] = outcome;
                }
                chunk
            })
            .collect();
        match text {
            Some(text) => serde_json::json!([{"stdout": text, "stderr": ""}]),
            None => Value::Array(written),
        }
    } else {
        Value::String(text)
    };
}

/// Withhold a built-in tool's whole output `item` as the inbound guardrail
/// does, with `text` in its place ([`write_whole_output`]), the item becoming
/// its spec form ([`canonical_builtin_output`]) with what the guardrail did
/// not read ([`kept_fields`]) — every other field gone.
pub(crate) fn replace_builtin_output(item: &mut Value, text: String) {
    write_whole_output(item, text);
    if let Some(mut spec) = canonical_builtin_output(item) {
        // What was not read stays as it came: the ids, so the output still
        // answers its call, and the conversion's message, so the request's
        // other messages keep their anchors.
        for field in kept_fields(item) {
            spec[field] = item[field].clone();
        }
        *item = spec;
    }
}

/// A result a tool the SERVER ran left in a request's history — what a stateless
/// client sends back, and a client can forge: the model reads it as the
/// tool's. A closed list by item type; no claim about any other (a Gemini
/// `codeExecutionResult`, a Responses `mcp_list_tools`). The fields of a Responses item or an Anthropic block that hold it,
/// the call beside it left out (`arguments`, `code`, `queries`): that is the
/// model's. `None` for anything else, a client-run tool's result among them
/// ([`BuiltinOutput`], a `tool_result`).
fn server_run_fields(item: &Value) -> Option<&'static [&'static str]> {
    let kind = item.get("type").and_then(Value::as_str)?;
    Some(match kind {
        "mcp_call" => &["output", "error"],
        "code_interpreter_call" => &["outputs"],
        "file_search_call" => &["results"],
        "mcp_approval_response" => &["reason"],
        "computer_call_output" => &["output", "acknowledged_safety_checks"],
        // Anthropic's server tools, each `<tool>_tool_result` with a `content`
        // (a client tool's plain `tool_result` is no such type).
        // A search a client supplies as a block, the model reading it as text.
        "search_result" => &["content", "title"],
        other if other.ends_with("_tool_result") => &["content"],
        _ => return None,
    })
}

/// Whether a key of a server-run result names no text: an id, a kind, a link,
/// a status, or bytes the model does not read as text.
fn is_structural_key(key: &str) -> bool {
    key.starts_with("encrypted_")
        || matches!(
            key,
            "type" | "id" | "call_id" | "tool_use_id" | "tool_name" | "file_id" | "file_type" | "url" | "image_url" | "media_type" | "error_code"
                | "code" | "page_age" | "retrieved_at" | "status" | "cache_control"
        )
}

/// Every string a server-run result holds as text, in order. A base64 source's
/// `data` is bytes, not text. Deliberately NOT a claim about those fields, ids
/// or links: a withhold could not take them away without breaking the item.
fn visit_text_leaves(value: &mut Value, visit: &mut impl FnMut(&mut String)) {
    match value {
        Value::String(text) if !text.is_empty() => visit(text),
        Value::Array(items) => items.iter_mut().for_each(|v| visit_text_leaves(v, visit)),
        Value::Object(obj) => {
            let bytes = obj.get("type").and_then(Value::as_str) == Some("base64");
            for (key, v) in obj.iter_mut() {
                if !is_structural_key(key) && !(bytes && key == "data") {
                    visit_text_leaves(v, visit);
                }
            }
        }
        _ => {}
    }
}

/// The result [`server_run_fields`] names, as the inbound guardrail reads it:
/// its strings, by line. `None` when `item` holds none, or is no such result.
pub fn server_run_text(item: &Value) -> Option<String> {
    let fields = server_run_fields(item)?;
    let mut own = item.clone();
    let mut read = Vec::new();
    for field in fields {
        if let Some(v) = own.get_mut(*field) {
            visit_text_leaves(v, &mut |text| read.push(text.clone()));
        }
    }
    (!read.is_empty()).then(|| read.join("\n"))
}

/// Write `text` over every string [`server_run_text`] read: none of the original
/// stays, and no field the spec requires goes empty. Everything else — the ids,
/// the call — stays as it came.
pub(crate) fn set_server_run_text(item: &mut Value, text: &str) {
    let Some(fields) = server_run_fields(item) else {
        return;
    };
    for field in fields {
        if let Some(v) = item.get_mut(*field) {
            visit_text_leaves(v, &mut |leaf| *leaf = text.to_string());
        }
    }
}

/// Whether `item` is a server-run result ([`server_run_fields`]).
pub fn is_server_run_result(item: &Value) -> bool {
    server_run_fields(item).is_some()
}

/// The call a server-run result answers, for the finding that names it.
pub fn server_run_call_id(item: &Value) -> String {
    ["call_id", "tool_use_id", "approval_request_id", "id"]
        .into_iter()
        .find_map(|key| item.get(key).and_then(Value::as_str))
        .unwrap_or("")
        .to_string()
}

/// Write `text` over a call output's `output` as a result rule writes it: a
/// shell output's chunks through [`set_shell_output_text`]; a list of parts —
/// the first text part takes it, the other text parts go, every part with no
/// text is kept; anything else becomes the string.
fn set_output_text(item: &mut Value, text: String) {
    let shell = item.get("type").and_then(Value::as_str) == Some("shell_call_output");
    match item.get_mut("output") {
        Some(Value::Array(chunks)) if shell => set_shell_output_text(chunks, text),
        Some(Value::Array(parts)) => {
            let mut text = Some(text);
            parts.retain_mut(|p| match p.get("text").and_then(Value::as_str) {
                None => true,
                Some(_) => text.take().is_some_and(|text| {
                    p["text"] = Value::String(text);
                    true
                }),
            });
            if let Some(text) = text {
                parts.insert(0, serde_json::json!({"type": "input_text", "text": text}));
            }
        }
        _ => {
            if let Some(obj) = item.as_object_mut() {
                obj.insert("output".to_string(), Value::String(text));
            }
        }
    }
}

/// Extract tool_result content as a single text string for redaction.
/// For block-list content, concatenates all text blocks (image/document blocks
/// are ignored by the redactor — regex rules only apply to text).
fn tool_result_content_as_text(c: Option<&ToolResultContent>) -> String {
    match c {
        Some(ToolResultContent::Text(t)) => t.clone(),
        Some(ToolResultContent::Blocks(blocks)) => blocks
            .iter()
            .filter_map(|b| match b {
                ToolResultBlock::Text { text, .. } => Some(text.as_str()),
                _ => None,
            })
            .collect::<Vec<_>>()
            .join("\n"),
        None => String::new(),
    }
}

/// Request-body fields only the gateway may set on an upstream request.
///
/// `priority` is vLLM's scheduling priority (lower runs first): a client that
/// sets it jumps every other caller's queue on a server started with
/// `--scheduling-policy priority`. `kv_transfer_params` steers vLLM's
/// disaggregated KV transfer and may name a remote host to pull from. Both are
/// removed from every client body, on every forward path, and never
/// reintroduced from the client's copy.
///
/// A DENYlist on purpose: an allowlist would break the legitimate engine
/// extras clients do send (`chat_template_kwargs`, …). `cache_salt` is not
/// here — a client salt only isolates the client's own prefix cache.
pub const GATEWAY_OWNED_WIRE_FIELDS: &[&str] = &["priority", "kv_transfer_params"];

/// Remove every [`GATEWAY_OWNED_WIRE_FIELDS`] member from a JSON object body,
/// returning what was removed. A non-object leaves nothing to remove.
pub fn strip_gateway_owned_json(body: &mut Value) -> Vec<(&'static str, Value)> {
    let Some(obj) = body.as_object_mut() else {
        return Vec::new();
    };
    GATEWAY_OWNED_WIRE_FIELDS
        .iter()
        .filter_map(|&field| obj.remove(field).map(|v| (field, v)))
        .collect()
}

/// A client request's own conversation, kept ahead of the turns the gateway
/// appends when it re-renders that request in the client's own protocol (a
/// substitution round, the mixed-pending splice).
///
/// The re-render goes through the domain, which has no field for what a
/// block carries beyond what it models (a Gemini clip's `videoMetadata`, a
/// tool result's `toolset_name`). The client's items are sent instead of their
/// rendering — exactly what a same-protocol forward of the request sends — and
/// only the appended turns come from the domain. `rendered` holds a digest of
/// each item of the domain read from the request, rendered before anything was
/// appended: the items of a later rendering past its length are the appended
/// turns.
pub struct OwnConversation {
    conversation: &'static str,
    system: Option<&'static str>,
    items: Vec<Value>,
    system_value: Option<Value>,
    rendered: Vec<String>,
}

impl OwnConversation {
    /// The conversation `client` sent, beside `rendered` — the domain read from
    /// it, rendered for the client's own protocol. `None` when either side has
    /// no conversation array (a Responses `input` given as one string carries
    /// nothing a rendering loses).
    pub fn of(client: &ApiRequest, rendered: &[u8]) -> Option<Self> {
        let (conversation, system) = client.conversation_keys();
        let Some(Value::Object(mut own)) = client.wire_value() else { return None };
        let Value::Array(mut items) = own.remove(conversation)? else { return None };
        // A Gemini content may leave its role unset in a single-turn request;
        // once the gateway's turns follow it, it is the user's turn it was read as.
        if let ApiRequest::GoogleGemini(_) = client {
            for item in items.iter_mut().filter_map(Value::as_object_mut) {
                item.entry("role").or_insert_with(|| Value::from("user"));
            }
        }
        let Ok(Value::Object(mut from_domain)) = serde_json::from_slice::<Value>(rendered) else { return None };
        let Value::Array(rendered) = from_domain.remove(conversation)? else { return None };
        let rendered = rendered.iter().map(crate::api::domain_request::json_digest::Hashable::sha256_hex).collect();
        Some(Self { conversation, system, items, system_value: system.and_then(|k| own.remove(k)), rendered })
    }

    /// `body` — a later rendering of the same domain, with the gateway's turns
    /// appended — with the client's own items (and system channel, which goes
    /// with them) in place of their rendering. `None` when `body` does not open
    /// with the rendering [`Self::of`] was given: an appended turn was merged
    /// into the client's last item, which then cannot be sent as the client
    /// wrote it, and the domain's rendering stands (logged: what the domain does
    /// not model is then not sent).
    pub fn keep_in(&self, body: &[u8]) -> Option<Bytes> {
        use crate::api::domain_request::json_digest::Hashable;
        let Ok(Value::Object(mut body)) = serde_json::from_slice::<Value>(body) else { return None };
        let Some(Value::Array(all)) = body.get_mut(self.conversation) else { return None };
        if all.len() < self.rendered.len() || all.iter().zip(&self.rendered).any(|(item, digest)| item.sha256_hex() != *digest) {
            tracing::warn!(
                conversation = self.conversation,
                "re-render: an appended turn changed the client's own items; they go as the domain renders them"
            );
            return None;
        }
        let appended = all.split_off(self.rendered.len());
        *all = self.items.iter().cloned().chain(appended).collect();
        if let Some(key) = self.system {
            match &self.system_value {
                Some(v) => {
                    body.insert(key.to_string(), v.clone());
                }
                None => {
                    body.remove(key);
                }
            }
        }
        serde_json::to_vec(&Value::Object(body)).ok().map(Bytes::from)
    }
}

/// Top-level API request — dispatched by API version.
#[derive(Debug, Clone)]
pub enum ApiRequest {
    ChatCompletions(ChatCompletionsRequest),
    Responses(ResponsesRequest),
    AnthropicMessages(MessagesRequest),
    GoogleGemini(GeminiRequest),
}

impl ApiRequest {
    /// The request as its wire JSON — what a same-protocol forward sends.
    pub fn wire_value(&self) -> Option<Value> {
        match self {
            Self::ChatCompletions(r) => serde_json::to_value(r),
            Self::Responses(r) => serde_json::to_value(r),
            Self::AnthropicMessages(r) => serde_json::to_value(r),
            Self::GoogleGemini(r) => serde_json::to_value(r),
        }
        .ok()
    }

    /// The key holding this request's conversation, and the key of its system
    /// channel where that is not a conversation item. One table, read by every
    /// re-render that keeps the client's own conversation or parameters.
    pub fn conversation_keys(&self) -> (&'static str, Option<&'static str>) {
        match self {
            Self::ChatCompletions(_) => ("messages", None),
            Self::Responses(_) => ("input", Some("instructions")),
            Self::AnthropicMessages(_) => ("messages", Some("system")),
            Self::GoogleGemini(_) => ("contents", Some("systemInstruction")),
        }
    }

    /// Parse a raw request body into the appropriate domain type.
    pub fn parse(api_version: ApiVersion, body: &Bytes) -> Result<Self, AppError> {
        match api_version {
            ApiVersion::ChatCompletions => {
                let req: ChatCompletionsRequest = serde_json::from_slice(body)
                    .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;
                Ok(Self::ChatCompletions(req))
            }
            ApiVersion::Responses => {
                let req: ResponsesRequest = serde_json::from_slice(body)
                    .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;
                Ok(Self::Responses(req))
            }
            ApiVersion::AnthropicMessages => {
                let req: MessagesRequest = serde_json::from_slice(body)
                    .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;
                Ok(Self::AnthropicMessages(req))
            }
            ApiVersion::GoogleGemini => {
                let req: GeminiRequest = serde_json::from_slice(body)
                    .map_err(|e| AppError::BadRequest(format!("invalid JSON: {e}")))?;
                Ok(Self::GoogleGemini(req))
            }
        }
    }

    /// Serialize the domain request back to JSON bytes.
    pub fn serialize(&self) -> Result<Bytes, AppError> {
        let json = match self {
            Self::ChatCompletions(req) => serde_json::to_vec(req),
            Self::Responses(req) => serde_json::to_vec(req),
            Self::AnthropicMessages(req) => serde_json::to_vec(req),
            Self::GoogleGemini(req) => serde_json::to_vec(req),
        }
        .map_err(|e| AppError::Internal(format!("serialize error: {e}")))?;
        Ok(Bytes::from(json))
    }

    /// Get the model name from the request.
    pub fn model(&self) -> &str {
        match self {
            Self::ChatCompletions(req) => &req.model,
            Self::Responses(req) => &req.model,
            Self::AnthropicMessages(req) => &req.model,
            Self::GoogleGemini(req) => &req.model,
        }
    }

    /// Set the model name on the request.
    pub fn set_model(&mut self, model: String) {
        match self {
            Self::ChatCompletions(req) => req.model = model,
            Self::Responses(req) => req.model = model,
            Self::AnthropicMessages(req) => req.model = model,
            Self::GoogleGemini(req) => req.model = model,
        }
    }

    /// Get the max output tokens requested by the client.
    pub fn max_tokens(&self) -> Option<u32> {
        match self {
            Self::ChatCompletions(req) => req.max_tokens,
            Self::Responses(req) => req.max_output_tokens,
            Self::AnthropicMessages(req) => Some(req.max_tokens),
            Self::GoogleGemini(req) => req
                .generation_config
                .as_ref()
                .and_then(|gc| gc.max_output_tokens),
        }
    }

    /// Set the max output tokens on the request (clamp to upstream limit).
    pub fn set_max_tokens(&mut self, val: u32) {
        match self {
            Self::ChatCompletions(req) => req.max_tokens = Some(val),
            Self::Responses(req) => req.max_output_tokens = Some(val),
            Self::AnthropicMessages(req) => req.max_tokens = val,
            Self::GoogleGemini(req) => {
                req.generation_config
                    .get_or_insert_with(Default::default)
                    .max_output_tokens = Some(val);
            }
        }
    }

    /// Collect tool function names from the request (if any tools are defined).
    pub fn tool_names(&self) -> Vec<&str> {
        match self {
            Self::ChatCompletions(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(crate::api::domain::Tool::function_name)
                .collect(),
            Self::Responses(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(crate::api::domain::Tool::function_name)
                .collect(),
            Self::AnthropicMessages(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|t| t.name.as_str())
                .collect(),
            Self::GoogleGemini(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .flat_map(|t| {
                    t.function_declarations
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|f| f.name.as_str())
                })
                .collect(),
        }
    }

    /// Walk the tool definitions and return `(name, server_type)` tuples in
    /// source-position order. `server_type` is `Some(...)` only for native
    /// server-tool definitions (Anthropic `web_search_20250305`, OpenAI
    /// Responses `web_search_preview`, etc.) — function-tools always return
    /// `None`. Used by the tool-policy walker to pivot the field-profile
    /// resolver onto the `ServerType` tier so server-tools canonicalise to
    /// `tool_id="web_search"` regardless of the wire `name`.
    ///
    /// OpenAI Responses native server-tools ship without a `function` block
    /// (`{"type": "web_search_preview", "max_uses": 5}`). For those, the
    /// reported wire "name" is the `type` string itself — that's what
    /// `substitute_tools` will key the rewrite on.
    pub fn tool_definitions_with_server_type(&self) -> Vec<(String, Option<String>)> {
        match self {
            Self::ChatCompletions(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|t| {
                    let server_type = if t.r#type != "function" && !t.r#type.is_empty() {
                        Some(t.r#type.clone())
                    } else {
                        None
                    };
                    let name = match t.function_name() {
                        Some(f) => f.to_string(),
                        None => server_type.clone()?,
                    };
                    Some((name, server_type))
                })
                .collect(),
            Self::Responses(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .filter_map(|t| {
                    let server_type = if t.r#type != "function" && !t.r#type.is_empty() {
                        Some(t.r#type.clone())
                    } else {
                        None
                    };
                    let name = match t.function_name() {
                        Some(f) => f.to_string(),
                        None => server_type.clone()?,
                    };
                    Some((name, server_type))
                })
                .collect(),
            Self::AnthropicMessages(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .map(|t| (t.name.clone(), t.server_type().map(String::from)))
                .collect(),
            Self::GoogleGemini(req) => req
                .tools
                .as_deref()
                .unwrap_or_default()
                .iter()
                .flat_map(|t| {
                    t.function_declarations
                        .as_deref()
                        .unwrap_or_default()
                        .iter()
                        .map(|f| (f.name.clone(), None))
                })
                .collect(),
        }
    }

    /// The client protocol the request is in.
    pub fn api_version(&self) -> ApiVersion {
        match self {
            Self::ChatCompletions(_) => ApiVersion::ChatCompletions,
            Self::Responses(_) => ApiVersion::Responses,
            Self::AnthropicMessages(_) => ApiVersion::AnthropicMessages,
            Self::GoogleGemini(_) => ApiVersion::GoogleGemini,
        }
    }

    /// Whether streaming is requested.
    pub fn is_streaming(&self) -> bool {
        match self {
            Self::ChatCompletions(req) => req.stream.unwrap_or(false),
            Self::Responses(req) => req.stream.unwrap_or(false),
            Self::AnthropicMessages(req) => req.stream.unwrap_or(false),
            Self::GoogleGemini(req) => req.stream.unwrap_or(false),
        }
    }

    /// Whether the request asked for `json_schema`-constrained structured
    /// output. Drives JSON healing of the response's text content. Mirrors the
    /// per-protocol normalization in `DomainRequest`'s `response_format` field.
    /// Anthropic Messages has no native structured-output format, so it is
    /// always false.
    pub fn wants_json_schema(&self) -> bool {
        match self {
            Self::ChatCompletions(req) => req
                .response_format
                .as_ref()
                .is_some_and(|rf| rf.r#type == "json_schema"),
            Self::Responses(req) => {
                req.extra
                    .get("text")
                    .and_then(|t| t.get("format"))
                    .and_then(|f| f.get("type"))
                    .and_then(|t| t.as_str())
                    == Some("json_schema")
            }
            Self::AnthropicMessages(_) => false,
            Self::GoogleGemini(req) => req
                .generation_config
                .as_ref()
                .is_some_and(|gc| {
                    gc.response_mime_type.as_deref() == Some("application/json")
                        && (gc.response_schema.is_some() || gc.response_json_schema.is_some())
                }),
        }
    }

    /// Remove every [`GATEWAY_OWNED_WIRE_FIELDS`] member the client put in the
    /// body, returning what was removed (for the audit record).
    ///
    /// Runs once, at the start of the request phase: after the audit has
    /// captured what the client sent and before scripts, presets or any target
    /// is chosen, so every forward built from this request — the primary, a
    /// failover, a substitution round — and the response-cache key see the
    /// body without them. Gemini's wire struct keeps no unknown field, so there
    /// is nothing to remove there.
    pub fn strip_gateway_owned_fields(&mut self) -> Vec<(&'static str, Value)> {
        let extra = match self {
            Self::ChatCompletions(req) => &mut req.extra,
            Self::Responses(req) => &mut req.extra,
            Self::AnthropicMessages(req) => &mut req.extra,
            Self::GoogleGemini(_) => return Vec::new(),
        };
        GATEWAY_OWNED_WIRE_FIELDS
            .iter()
            .filter_map(|&field| extra.remove(field).map(|v| (field, v)))
            .collect()
    }

    /// Restore this client request's own parameters onto `translated` — a body
    /// the substitution agent loop re-translated from the domain for `target`.
    ///
    /// The domain carries the conversation (which is where the loop splices the
    /// intercepted tool call and its result) but not every parameter the client
    /// set: the `extra` catch-all and the typed knobs it lifts (`seed`, `n`,
    /// `logit_bias`, …) are not re-emitted by a translation. Round 1 forwarded them, so without this every later round
    /// would be answered under different settings. The result is the client's
    /// request with only the conversation-carrying keys (and `model`,
    /// `stream`) taken from the translation.
    ///
    /// Call it on the POST-phase request, so what the request phase removed
    /// (the gateway-owned fields) stays removed. Returns `None` when `target`
    /// is not the client's protocol — a translated pair carries no client
    /// extra on any round — or either side is not a JSON object.
    pub fn carry_knobs_onto(&self, translated: &[u8], target: ApiVersion) -> Option<Bytes> {
        self.carry_knobs_onto_with(translated, target, |_| {})
    }

    /// [`Self::carry_knobs_onto`], letting the caller adjust the restored body
    /// in the same pass, before it is serialized.
    pub fn carry_knobs_onto_with(
        &self,
        translated: &[u8],
        target: ApiVersion,
        adjust: impl FnOnce(&mut serde_json::Map<String, Value>),
    ) -> Option<Bytes> {
        // A Gemini request has no parameter the domain does not carry back.
        if target != self.api_version() || target == ApiVersion::GoogleGemini {
            return None;
        }
        let (messages, system) = self.conversation_keys();
        let conversation = [Some(messages), system, Some("model"), Some("stream")];
        let Some(Value::Object(mut body)) = self.wire_value() else { return None };
        let Ok(Value::Object(from_domain)) = serde_json::from_slice::<Value>(translated) else {
            return None;
        };
        for key in conversation.into_iter().flatten() {
            match from_domain.get(key) {
                Some(v) => {
                    body.insert(key.to_string(), v.clone());
                }
                None => {
                    body.remove(key);
                }
            }
        }
        adjust(&mut body);
        serde_json::to_vec(&Value::Object(body)).ok().map(Bytes::from)
    }

    /// Remove tools whose names match the predicate. Returns names of removed tools.
    pub fn remove_tools(&mut self, mut should_remove: impl FnMut(&str) -> bool) -> Vec<String> {
        let mut removed = Vec::new();
        match self {
            Self::ChatCompletions(req) => {
                if let Some(tools) = &mut req.tools {
                    let mut i = 0;
                    while i < tools.len() {
                        let name = tools[i].function_name().unwrap_or("");
                        if should_remove(name) {
                            removed.push(name.to_string());
                            tools.remove(i);
                        } else {
                            i += 1;
                        }
                    }
                    if tools.is_empty() {
                        req.tools = None;
                    }
                }
            }
            Self::Responses(req) => {
                if let Some(tools) = &mut req.tools {
                    let mut i = 0;
                    while i < tools.len() {
                        let name = tools[i].function_name().unwrap_or("");
                        if should_remove(name) {
                            removed.push(name.to_string());
                            tools.remove(i);
                        } else {
                            i += 1;
                        }
                    }
                    if tools.is_empty() {
                        req.tools = None;
                    }
                }
            }
            Self::AnthropicMessages(req) => {
                if let Some(tools) = &mut req.tools {
                    let mut i = 0;
                    while i < tools.len() {
                        let name = tools[i].name.as_str();
                        if should_remove(name) {
                            removed.push(name.to_string());
                            tools.remove(i);
                        } else {
                            i += 1;
                        }
                    }
                    if tools.is_empty() {
                        req.tools = None;
                    }
                }
            }
            Self::GoogleGemini(req) => {
                if let Some(tools) = &mut req.tools {
                    for tool in tools.iter_mut() {
                        if let Some(decls) = &mut tool.function_declarations {
                            let mut i = 0;
                            while i < decls.len() {
                                let name = decls[i].name.as_str();
                                if should_remove(name) {
                                    removed.push(name.to_string());
                                    decls.remove(i);
                                } else {
                                    i += 1;
                                }
                            }
                        }
                    }
                    // Drop an entry whose declarations were all removed; a
                    // built-in tool entry (`google_search`, …) declares no
                    // functions and is not this pass's to remove.
                    tools.retain(|t| t.function_declarations.as_ref().is_none_or(|d| !d.is_empty()));
                    if tools.is_empty() {
                        req.tools = None;
                    }
                }
            }
        }
        if !removed.is_empty() {
            self.retire_tool_choice(&removed);
        }
        removed
    }

    /// Point a `tool_choice` naming a renamed or substituted tool at its new
    /// name — see [`follow_substitution`]. Every path that renames a declared
    /// tool calls it: left naming the old name, the choice forces a tool that
    /// is no longer declared, which every protocol refuses.
    pub(crate) fn follow_tool_renames(&mut self, renames: &[(String, String)], became: Became) {
        if renames.is_empty() {
            return;
        }
        match self {
            Self::ChatCompletions(ChatCompletionsRequest { tool_choice: Some(c), .. }) => {
                follow_substitution(c, renames, ApiVersion::ChatCompletions, became);
            }
            Self::Responses(ResponsesRequest { tool_choice: Some(c), .. }) => {
                follow_substitution(c, renames, ApiVersion::Responses, became);
            }
            Self::AnthropicMessages(MessagesRequest { tool_choice: Some(c), .. }) => {
                follow_substitution(c, renames, ApiVersion::AnthropicMessages, became);
            }
            Self::GoogleGemini(req) => {
                let names = req
                    .tool_config
                    .as_mut()
                    .and_then(|t| t.function_calling_config.as_mut())
                    .and_then(|f| f.allowed_function_names.as_mut());
                for name in names.into_iter().flatten() {
                    if let Some((_, replaced)) = renames.iter().find(|(original, _)| original == name) {
                        name.clone_from(replaced);
                    }
                }
            }
            _ => {}
        }
    }

    /// A `tool_choice` naming a tool that was removed from the declarations:
    /// a forced call to it becomes "call nothing" (the model may not call
    /// what the client did not allow, and forcing an undeclared tool is
    /// refused), an allowlist loses the entry, and an allowlist left empty
    /// becomes "call nothing" too.
    fn retire_tool_choice(&mut self, removed: &[String]) {
        use crate::api::tool_choice::{allowlist_spec_mut, wire_choice_name};
        // With no tool left the choice governs nothing, and every protocol
        // refuses a `tool_choice` beside no `tools` — so it goes, with the
        // parallel switch it carried.
        match self {
            Self::ChatCompletions(req) if req.tools.is_none() => {
                req.tool_choice = None;
                req.parallel_tool_calls = None;
                return;
            }
            Self::Responses(req) if req.tools.is_none() => {
                req.tool_choice = None;
                req.parallel_tool_calls = None;
                return;
            }
            Self::AnthropicMessages(req) if req.tools.is_none() => {
                req.tool_choice = None;
                return;
            }
            // Gemini keeps built-in tools (`googleSearch`) in `tools`: the
            // function-calling config governs declarations, so it goes when
            // none remain.
            Self::GoogleGemini(req)
                if req.tools.iter().flatten().all(|t| t.function_declarations.as_ref().is_none_or(Vec::is_empty)) =>
            {
                req.tool_config = None;
                return;
            }
            _ => {}
        }
        let names_removed = |entry: &Value| wire_choice_name(entry).is_some_and(|n| removed.iter().any(|r| r == n));
        let retire = |choice: &mut Value, protocol: ApiVersion| {
            let none = || match protocol {
                ApiVersion::AnthropicMessages => serde_json::json!({"type": "none"}),
                _ => Value::from("none"),
            };
            if let Some(spec) = allowlist_spec_mut(choice, protocol) {
                let emptied = spec.get_mut("tools").and_then(Value::as_array_mut).is_some_and(|entries| {
                    entries.retain(|e| !names_removed(e));
                    entries.is_empty()
                });
                if emptied {
                    *choice = none();
                }
            } else if names_removed(choice) {
                *choice = none();
            }
        };
        match self {
            Self::ChatCompletions(ChatCompletionsRequest { tool_choice: Some(c), .. }) => {
                retire(c, ApiVersion::ChatCompletions);
            }
            Self::Responses(ResponsesRequest { tool_choice: Some(c), .. }) => retire(c, ApiVersion::Responses),
            Self::AnthropicMessages(MessagesRequest { tool_choice: Some(c), .. }) => {
                retire(c, ApiVersion::AnthropicMessages);
            }
            Self::GoogleGemini(req) => {
                if let Some(fc) = req.tool_config.as_mut().and_then(|t| t.function_calling_config.as_mut())
                    && let Some(names) = fc.allowed_function_names.as_mut()
                {
                    names.retain(|n| !removed.contains(n));
                    if names.is_empty() {
                        fc.allowed_function_names = None;
                        fc.mode = Some("NONE".to_string());
                    }
                }
            }
            _ => {}
        }
    }

    /// Substitute tool definitions whose names match `lookup`'s closure. For
    /// each tool, the closure receives the wire name and returns either
    /// `Some(replacement)` to rewrite the definition or `None` to leave it
    /// alone. Returns the list of `(original_name, replaced_name)` pairs that
    /// were actually swapped (in source-position order).
    ///
    /// Per-protocol semantics:
    /// - **Anthropic**: replaces `name`, `description`, `input_schema`; clears
    ///   `extra` so server-tool-only fields (`type`, `max_uses`, ...) are
    ///   dropped on conversion to a function tool. `cache_control` is preserved.
    /// - **OpenAI Chat Completions / Responses**: replaces `function.name`,
    ///   `function.description`, `function.parameters`. A function or custom
    ///   tool is matched by its name, any other entry by its type.
    ///   `type = "function"` is forced.
    /// - **Gemini**: replaces the matched `function_declarations[].name` /
    ///   `description` / `parameters` in place.
    ///
    /// A `tool_choice` naming a substituted tool follows it, in the same
    /// protocol's grammar (see [`follow_substitution`]): left naming the
    /// original, it would force a tool that is no longer declared.
    pub fn substitute_tools(
        &mut self,
        mut lookup: impl FnMut(&str) -> Option<crate::config::tool_rules::ToolDefValue>,
    ) -> Vec<(String, String)> {
        let mut substituted = Vec::new();
        match self {
            Self::ChatCompletions(req) => {
                if let Some(tools) = &mut req.tools {
                    for tool in tools.iter_mut() {
                        // A function or custom tool by its own name; any other
                        // type by the type.
                        let original = match tool.function_name() {
                            Some(name) => name.to_string(),
                            None if !tool.r#type.is_empty() && tool.r#type != "function" => {
                                tool.r#type.clone()
                            }
                            None => continue,
                        };
                        if let Some(replacement) = lookup(&original) {
                            tool.function = Some(crate::api::domain::FunctionDef {
                                name: replacement.name.clone(),
                                description: replacement.description.clone(),
                                parameters: Some(replacement.parameters.clone()),
                                strict: None,
                            });
                            tool.r#type = "function".to_string();
                            tool.extra.clear();
                            substituted.push((original, replacement.name));
                        }
                    }
                }
            }
            Self::Responses(req) => {
                if let Some(tools) = &mut req.tools {
                    for tool in tools.iter_mut() {
                        // Responses declares a function FLAT (`name` beside
                        // `type`); a hosted tool is named by its `type`.
                        let original = match tool.function_name() {
                            Some(name) => name.to_string(),
                            None if tool.r#type == "function" || tool.r#type.is_empty() => continue,
                            None => tool.r#type.clone(),
                        };
                        if let Some(replacement) = lookup(&original) {
                            // Written in Responses' own flat grammar: a
                            // same-protocol forward re-serializes this struct,
                            // and a nested `function` block is Chat's shape.
                            tool.function = None;
                            tool.r#type = "function".to_string();
                            tool.extra.clear();
                            tool.extra.insert("name".into(), Value::from(replacement.name.clone()));
                            if let Some(d) = &replacement.description {
                                tool.extra.insert("description".into(), Value::from(d.clone()));
                            }
                            tool.extra.insert("parameters".into(), replacement.parameters.clone());
                            substituted.push((original, replacement.name));
                        }
                    }
                }
            }
            Self::AnthropicMessages(req) => {
                if let Some(tools) = &mut req.tools {
                    for tool in tools.iter_mut() {
                        let original = tool.name.clone();
                        if let Some(replacement) = lookup(&original) {
                            tool.name = replacement.name.clone();
                            tool.description = replacement.description.clone();
                            tool.input_schema = Some(replacement.parameters.clone());
                            tool.extra.clear();
                            substituted.push((original, replacement.name));
                        }
                    }
                }
            }
            Self::GoogleGemini(req) => {
                if let Some(tools) = &mut req.tools {
                    for tool in tools.iter_mut() {
                        let Some(decls) = tool.function_declarations.as_mut() else {
                            continue;
                        };
                        for decl in decls.iter_mut() {
                            let original = decl.name.clone();
                            if let Some(replacement) = lookup(&original) {
                                decl.name = replacement.name.clone();
                                decl.description = replacement.description.clone();
                                decl.parameters = Some(replacement.parameters.clone());
                                substituted.push((original, replacement.name));
                            }
                        }
                    }
                }
            }
        }
        self.follow_tool_renames(&substituted, Became::Function);
        substituted
    }

    /// Rewrite tool_result content blocks across all protocols. For every
    /// tool_result encountered, `rewrite(tool_name_hint, tool_use_id, content)`
    /// is invoked — a `Some((new, rule_name, reason, rule_id))` return
    /// triggers the rewrite and is recorded; `None` leaves the block
    /// untouched.
    ///
    /// Coverage: Anthropic Messages (ContentBlock::ToolResult — mixed
    /// content preserves non-text sub-blocks), OpenAI Responses Raw input
    /// (type="function_call_output" / "custom_tool_call_output", and the
    /// outputs of the built-in tools a client runs — `local_shell_call_output`,
    /// `shell_call_output`, `apply_patch_call_output` — named by the built-in
    /// call they answer, [`domain::ClientBuiltin::tool_name`]; a
    /// `computer_call_output` is a screenshot, no text a rule could read or
    /// rewrite, and is left as it is), OpenAI Chat Completions (role="tool"
    /// messages — non-text Parts preserved), Google Gemini
    /// (functionResponse parts in user-role contents — named by the call each
    /// answers as the request's parse reads it, `GeminiCallIds`; response is
    /// rewritten to a JSON string).
    ///
    /// The returned Vec is a complete audit record — the closure carries
    /// the matching rule's name, description, and stable id through alongside
    /// the rewritten content, populating `rule_name`, `reason`, and `rule_id`
    /// in a single pass. Closure args: `(name_hint, tool_use_id, content,
    /// originating_arguments)`. `originating_arguments` is the input JSON of
    /// the matching `tool_use` / `function_call` from earlier in the message
    /// history, looked up by id — `None` when no matching call is present.
    /// Closure return tuple: `(new_content, rule_name, reason, rule_id)`.
    pub fn redact_tool_results(
        &mut self,
        mut rewrite: impl FnMut(
            &str,
            &str,
            &str,
            Option<&serde_json::Value>,
        ) -> Option<(String, String, String, String)>,
    ) -> Vec<RedactedToolResultInfo> {
        let mut out = Vec::new();
        match self {
            Self::AnthropicMessages(req) => {
                // Pass 1: build tool_use_id → (tool_name, input) map.
                let mut id_to_name: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                let mut id_to_input: std::collections::HashMap<String, serde_json::Value> =
                    std::collections::HashMap::new();
                for msg in &req.messages {
                    if let AnthropicContent::Blocks(blocks) = &msg.content {
                        for b in blocks {
                            if let ContentBlock::ToolUse { id, name, input, .. } = b {
                                id_to_name.insert(id.to_string(), name.to_string());
                                id_to_input.insert(id.to_string(), input.clone());
                            }
                        }
                    }
                }
                // Pass 2: walk ToolResult blocks, rewrite content.
                for msg in &mut req.messages {
                    if let AnthropicContent::Blocks(blocks) = &mut msg.content {
                        for b in blocks.iter_mut() {
                            if let ContentBlock::ToolResult { tool_use_id, content, .. } = b {
                                let name_hint = id_to_name
                                    .get(tool_use_id)
                                    .map(String::as_str)
                                    .unwrap_or("");
                                let originating_args = id_to_input.get(tool_use_id);
                                let original = tool_result_content_as_text(content.as_ref());
                                if let Some((new, rule_name, reason, rule_id)) =
                                    rewrite(name_hint, tool_use_id, &original, originating_args)
                                {
                                    out.push(RedactedToolResultInfo {
                                        tool_use_id: tool_use_id.clone(),
                                        tool_name: id_to_name.get(tool_use_id).cloned(),
                                        original_content: original,
                                        redacted_content: new.clone(),
                                        rule_name,
                                        reason,
                                        rule_id,
                                    });
                                    // Preserve non-text blocks (image/document)
                                    // when content is Blocks — only rewrite the
                                    // joined-text portion. For Text content,
                                    // replace in place. For None, create a
                                    // Text block with the redacted content.
                                    match content {
                                        Some(ToolResultContent::Blocks(sub)) => {
                                            ToolResultBlock::set_text(sub, &new);
                                        }
                                        _ => {
                                            *content = Some(ToolResultContent::Text(new));
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            Self::Responses(req) => {
                use self::domain::ResponseInput;
                if let ResponseInput::Raw(items) = &mut req.input {
                    // Pass 1: build call_id → (name, parsed arguments) map, over
                    // function calls, custom (freeform) tool calls and the
                    // built-in tools' calls alike.
                    let mut id_to_name: std::collections::HashMap<String, String> =
                        std::collections::HashMap::new();
                    let mut id_to_input: std::collections::HashMap<String, serde_json::Value> =
                        std::collections::HashMap::new();
                    // Built-in calls pair by (tool, id), apart from function and
                    // custom calls, so an id another call reuses never names or
                    // feeds this one's output. A hosted shell call ran on the
                    // server: like its call, its output is not the client's.
                    let mut builtin_calls: std::collections::HashMap<(&'static str, String), Option<serde_json::Value>> =
                        std::collections::HashMap::new();
                    let hosted_shell_ids = hosted_shell_call_ids(items);
                    for item in items.iter() {
                        let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                        if t == "custom_tool_call"
                            && let (Some(call_id), Some(name)) = (
                                item.get("call_id").and_then(|v| v.as_str()).filter(|id| !id.is_empty()),
                                item.get("name").and_then(|v| v.as_str()),
                            )
                        {
                            // Its free text, in the domain's input shape.
                            id_to_name.insert(call_id.to_string(), name.to_string());
                            let text = item.get("input").and_then(|v| v.as_str()).unwrap_or("");
                            id_to_input.insert(
                                call_id.to_string(),
                                crate::api::domain_request::freeform_call_input(text),
                            );
                        } else if let Some(builtin) = domain::ClientBuiltin::of_item(item)
                            .filter(|b| *b != domain::ClientBuiltin::Computer)
                        {
                            // Read as the call is policed: its payload. Indexed by
                            // `call_id`; a local shell call also by its own `id`,
                            // since its output names the call by an `id` field.
                            let payload = serde_json::from_str::<serde_json::Value>(&builtin.arguments(item)).ok();
                            let keys: &[&str] = if t == "local_shell_call" { &["call_id", "id"] } else { &["call_id"] };
                            for key in keys {
                                if let Some(id) = item.get(*key).and_then(|v| v.as_str()).filter(|id| !id.is_empty()) {
                                    builtin_calls.insert((builtin.tool_name(), id.to_string()), payload.clone());
                                }
                            }
                        } else if t == "function_call" {
                            let call_id = item
                                .get("call_id")
                                .or_else(|| item.get("id"))
                                .and_then(|v| v.as_str())
                                .unwrap_or("");
                            let name = item.get("name").and_then(|v| v.as_str()).unwrap_or("");
                            if !call_id.is_empty() && !name.is_empty() {
                                id_to_name.insert(call_id.to_string(), name.to_string());
                                // `arguments` arrives as a JSON-encoded string;
                                // parse to Value so the resolver can index it.
                                if let Some(args_str) =
                                    item.get("arguments").and_then(|v| v.as_str())
                                    && let Ok(parsed) = serde_json::from_str::<serde_json::Value>(
                                        args_str,
                                    )
                                {
                                    id_to_input.insert(call_id.to_string(), parsed);
                                } else {
                                    id_to_input.remove(call_id);
                                }
                            }
                        }
                    }
                    // Pass 2: rewrite the outputs of every kind of call.
                    for item in items.iter_mut() {
                        // A built-in tool's output names its tool by its own
                        // type, whether or not its call is in this request (a
                        // `previous_response_id` continuation sends the output
                        // alone); its call's payload is read only from a call of
                        // that same tool. One with no text to read is not
                        // asked about, and a hosted shell call's output is not
                        // the client's.
                        let (call_id, original, name_hint, originating_args) = match BuiltinOutput::of(item) {
                            Some(output) if output.is_hosted(&hosted_shell_ids) => continue,
                            // An output in a shape the spec does not give it holds
                            // parts a rewrite could not reach: the inbound guardrail
                            // reads it whole, a rule does not.
                            Some(BuiltinOutput { builtin, call_id, read: OutputRead::Text(text) }) => {
                                let name = builtin.tool_name();
                                let args = builtin_calls.get(&(name, call_id.clone())).and_then(Option::as_ref);
                                (call_id, text, name, args)
                            }
                            Some(_) => continue,
                            None => {
                                let t = item.get("type").and_then(|v| v.as_str()).unwrap_or("");
                                if !matches!(t, "function_call_output" | "custom_tool_call_output") {
                                    continue;
                                }
                                let call_id = item.get("call_id").and_then(|v| v.as_str()).unwrap_or("").to_string();
                                // `output` is a string, or a list of parts
                                // (`input_text`, `input_image`, `input_file`)
                                // whose text is read joined.
                                let original = match item.get("output") {
                                    Some(serde_json::Value::Array(parts)) => parts_text(parts),
                                    other => other.and_then(|v| v.as_str()).unwrap_or("").to_string(),
                                };
                                let name = id_to_name.get(&call_id).map(String::as_str).unwrap_or("");
                                (call_id.clone(), original, name, id_to_input.get(&call_id))
                            }
                        };
                        if let Some((new, rule_name, reason, rule_id)) =
                            rewrite(name_hint, &call_id, &original, originating_args)
                        {
                            out.push(RedactedToolResultInfo {
                                tool_use_id: call_id.clone(),
                                tool_name: (!name_hint.is_empty()).then(|| name_hint.to_string()),
                                original_content: original,
                                redacted_content: new.clone(),
                                rule_name,
                                reason,
                                rule_id,
                            });
                            set_output_text(item, new);
                        }
                    }
                }
            }
            Self::ChatCompletions(req) => {
                // Pass 1: assistant tool_calls → (id→name, id→parsed arguments).
                let mut id_to_name: std::collections::HashMap<String, String> =
                    std::collections::HashMap::new();
                let mut id_to_input: std::collections::HashMap<String, serde_json::Value> =
                    std::collections::HashMap::new();
                for msg in &req.messages {
                    if let Some(tcs) = &msg.tool_calls {
                        for tc in tcs {
                            if let Some(name) = tc.name() {
                                id_to_name.insert(tc.id.clone(), name.to_string());
                            }
                            // `function.arguments` is a JSON-encoded string,
                            // parsed to Value for the resolver; a custom call's
                            // free text takes the domain's input shape.
                            let input = match (&tc.function, &tc.custom) {
                                (Some(f), _) => serde_json::from_str::<serde_json::Value>(&f.arguments).ok(),
                                (None, Some(c)) => Some(crate::api::domain_request::freeform_call_input(&c.input)),
                                (None, None) => None,
                            };
                            if let Some(parsed) = input {
                                id_to_input.insert(tc.id.clone(), parsed);
                            }
                        }
                    }
                }
                // Pass 2: walk role="tool" messages, rewrite content.
                for msg in &mut req.messages {
                    if msg.role != "tool" {
                        continue;
                    }
                    let tool_use_id = msg
                        .tool_call_id
                        .clone()
                        .unwrap_or_default();
                    let name_hint = msg
                        .name
                        .clone()
                        .or_else(|| id_to_name.get(&tool_use_id).cloned())
                        .unwrap_or_default();
                    let originating_args = id_to_input.get(&tool_use_id);
                    let original = match &msg.content {
                        Some(self::domain::MessageContent::Text(t)) => t.clone(),
                        Some(self::domain::MessageContent::Parts(parts)) => parts
                            .iter()
                            .filter_map(|p| match p {
                                self::domain::ContentPart::Text { text, .. } => Some(text.as_str()),
                                _ => None,
                            })
                            .collect::<Vec<_>>()
                            .join(""),
                        None => String::new(),
                    };
                    if let Some((new, rule_name, reason, rule_id)) =
                        rewrite(&name_hint, &tool_use_id, &original, originating_args)
                    {
                        // Preserve non-text Parts (rare but possible) when
                        // rewriting — only replace text parts, leave audio /
                        // image / unknown parts untouched.
                        match &mut msg.content {
                            Some(self::domain::MessageContent::Parts(parts)) => {
                                let no_text = !self::domain::ContentPart::merge_text_parts(parts, &new, |p| {
                                    matches!(p, self::domain::ContentPart::Text { .. })
                                });
                                if no_text {
                                    parts.insert(
                                        0,
                                        self::domain::ContentPart::text(new.clone()),
                                    );
                                }
                            }
                            _ => {
                                msg.content =
                                    Some(self::domain::MessageContent::Text(new.clone()));
                            }
                        }
                        out.push(RedactedToolResultInfo {
                            tool_use_id: tool_use_id.clone(),
                            tool_name: if name_hint.is_empty() {
                                None
                            } else {
                                Some(name_hint.clone())
                            },
                            original_content: original,
                            redacted_content: new.clone(),
                            rule_name,
                            reason,
                            rule_id,
                        });
                    }
                }
            }
            Self::GoogleGemini(req) => {
                // Gemini's request-side tool results live in user-role
                // contents as `functionResponse` parts. Each is named by the
                // call it answers as the request's parse reads it
                // (`GeminiCallIds`): its own `id`, else the earliest
                // unanswered call of its name — the id its result event
                // carries.
                use self::gemini::GeminiPart;
                let ids = domain_request::GeminiCallIds::of(&req.contents);
                let args_at = |(c, p): (usize, usize), contents: &[gemini::GeminiContent]| match contents.get(c).and_then(|c| c.parts.get(p)) {
                    Some(GeminiPart::FunctionCall { function_call, .. }) => Some(function_call.args.clone()),
                    _ => None,
                };
                // The call a response answers, else — a response naming a call
                // already answered (a result sent twice) — the call of its id.
                let call_of_id = |id: &str| {
                    req.contents.iter().enumerate().find_map(|(turn, content)| {
                        (0..content.parts.len()).find(|&idx| ids.call(turn, idx) == id).map(|idx| (turn, idx))
                    })
                };
                let originating: std::collections::HashMap<(usize, usize), serde_json::Value> = req
                    .contents
                    .iter()
                    .enumerate()
                    .flat_map(|(turn, content)| (0..content.parts.len()).map(move |idx| (turn, idx)))
                    .filter_map(|at| {
                        let call = ids.answered(at.0, at.1).or_else(|| {
                            matches!(req.contents[at.0].parts[at.1], GeminiPart::FunctionResponse { .. })
                                .then(|| call_of_id(ids.response(at.0, at.1)))
                                .flatten()
                        })?;
                        Some((at, args_at(call, &req.contents)?))
                    })
                    .collect();
                for (turn, content) in req.contents.iter_mut().enumerate() {
                    for (idx, part) in content.parts.iter_mut().enumerate() {
                        if let GeminiPart::FunctionResponse { function_response } = part {
                            let name_hint = function_response.name.clone();
                            let id_surrogate = ids.response(turn, idx).to_string();
                            let originating_args = originating.get(&(turn, idx));
                            let original = if function_response.response.is_string() {
                                function_response
                                    .response
                                    .as_str()
                                    .unwrap_or("")
                                    .to_string()
                            } else {
                                serde_json::to_string(&function_response.response)
                                    .unwrap_or_default()
                            };
                            if let Some((new, rule_name, reason, rule_id)) =
                                rewrite(&name_hint, &id_surrogate, &original, originating_args)
                            {
                                out.push(RedactedToolResultInfo {
                                    tool_use_id: id_surrogate,
                                    tool_name: Some(name_hint),
                                    original_content: original,
                                    redacted_content: new.clone(),
                                    rule_name,
                                    reason,
                                    rule_id,
                                });
                                function_response.response = serde_json::Value::String(new);
                            }
                        }
                    }
                }
            }
        }
        out
    }

    /// Append text to the system prompt (separated by double newline).
    ///
    /// Creates a system prompt if none exists.
    pub fn append_system_prompt(&mut self, text: &str) {
        match self {
            Self::ChatCompletions(req) => {
                // Appended to the prompt's last message, system or developer, in
                // the run `chat_system_lead` names — its own text kept whatever
                // its shape.
                let lead = domain_request::chat_system_lead(&req.messages);
                let last = req.messages[..lead]
                    .iter()
                    .rposition(|m| m.role == "system" || m.role == "developer");
                if let Some(at) = last {
                    if let Some(content) = &mut req.messages[at].content {
                        match content {
                            domain::MessageContent::Text(existing) => {
                                existing.push_str("\n\n");
                                existing.push_str(text);
                            }
                            domain::MessageContent::Parts(parts) => {
                                parts.push(domain::ContentPart::text(format!("\n\n{text}")));
                            }
                        }
                    } else {
                        req.messages[at].content =
                            Some(domain::MessageContent::Text(text.to_string()));
                    }
                } else {
                    req.messages.insert(
                        0,
                        domain::Message {
                            role: "system".to_string(),
                            content: Some(domain::MessageContent::Text(text.to_string())),
                            name: None,
                            tool_calls: None,
                            tool_call_id: None,
                            extra: std::collections::BTreeMap::new(),
                        },
                    );
                }
            }
            Self::Responses(req) => {
                if let Some(existing) = &mut req.instructions {
                    existing.push_str("\n\n");
                    existing.push_str(text);
                } else {
                    req.instructions = Some(text.to_string());
                }
            }
            Self::AnthropicMessages(req) => {
                use messages::SystemPrompt;
                match &req.system {
                    Some(SystemPrompt::Text(existing)) => {
                        req.system =
                            Some(SystemPrompt::Text(format!("{existing}\n\n{text}")));
                    }
                    Some(SystemPrompt::Blocks(_)) => {
                        let existing_text = req.system.as_ref().unwrap().to_text();
                        req.system =
                            Some(SystemPrompt::Text(format!("{existing_text}\n\n{text}")));
                    }
                    None => {
                        req.system = Some(SystemPrompt::Text(text.to_string()));
                    }
                }
            }
            Self::GoogleGemini(req) => {
                if let Some(sys) = &mut req.system_instruction {
                    // Append to existing system instruction text parts
                    sys.parts.push(gemini::GeminiPart::Text {
                        text: text.to_string(),
                    });
                } else {
                    req.system_instruction = Some(gemini::GeminiContent {
                        role: None,
                        parts: vec![gemini::GeminiPart::Text {
                            text: text.to_string(),
                        }],
                    });
                }
            }
        }
    }

    /// Inject a system prompt into the request.
    ///
    /// - ChatCompletions: prepend a system message at index 0 (or merge if first message is system).
    /// - Responses: set/merge the `instructions` field.
    pub fn inject_system_prompt(&mut self, prompt: &str) {
        match self {
            Self::ChatCompletions(req) => {
                // If the first message is already a system message, prepend our prompt.
                if req
                    .messages
                    .first()
                    .is_some_and(|m| m.role == "system")
                {
                    if let Some(content) = &mut req.messages[0].content {
                        match content {
                            domain::MessageContent::Text(text) => {
                                *text = format!("{prompt}\n\n{text}");
                            }
                            _ => {
                                // Replace with merged text
                                *content = domain::MessageContent::Text(prompt.to_string());
                            }
                        }
                    } else {
                        req.messages[0].content =
                            Some(domain::MessageContent::Text(prompt.to_string()));
                    }
                } else {
                    // Prepend a new system message.
                    req.messages.insert(
                        0,
                        domain::Message {
                            role: "system".to_string(),
                            content: Some(domain::MessageContent::Text(prompt.to_string())),
                            name: None,
                            tool_calls: None,
                            tool_call_id: None,
                            extra: std::collections::BTreeMap::new(),
                        },
                    );
                }
            }
            Self::Responses(req) => {
                if let Some(existing) = &req.instructions {
                    req.instructions = Some(format!("{prompt}\n\n{existing}"));
                } else {
                    req.instructions = Some(prompt.to_string());
                }
            }
            Self::AnthropicMessages(req) => {
                use messages::SystemPrompt;
                match &req.system {
                    Some(SystemPrompt::Text(existing)) => {
                        req.system =
                            Some(SystemPrompt::Text(format!("{prompt}\n\n{existing}")));
                    }
                    Some(SystemPrompt::Blocks(_)) => {
                        // Prepend as text, keep existing blocks text
                        let existing_text = req.system.as_ref().unwrap().to_text();
                        req.system =
                            Some(SystemPrompt::Text(format!("{prompt}\n\n{existing_text}")));
                    }
                    None => {
                        req.system = Some(SystemPrompt::Text(prompt.to_string()));
                    }
                }
            }
            Self::GoogleGemini(req) => {
                if let Some(sys) = &mut req.system_instruction {
                    // Prepend our prompt before existing parts
                    sys.parts.insert(
                        0,
                        gemini::GeminiPart::Text {
                            text: prompt.to_string(),
                        },
                    );
                } else {
                    req.system_instruction = Some(gemini::GeminiContent {
                        role: None,
                        parts: vec![gemini::GeminiPart::Text {
                            text: prompt.to_string(),
                        }],
                    });
                }
            }
        }
    }
}

/// Remove an Anthropic body's manual thinking budget (`thinking: {type:
/// "enabled"}`) from a request whose history the GATEWAY spliced into a turn
/// that does not open with a thinking block its model sealed — a mixed-pending
/// splice always, a substitution round when its turn is unsealed
/// (`DomainRequest::final_assistant_turn_is_sealed`). Manual thinking refuses
/// such a turn ("the final assistant turn … begins with a thinking block"),
/// while turning thinking off mid-turn degrades as the spec describes. Adaptive
/// thinking needs no block and stays. A no-op on the other protocols' bodies.
pub(crate) fn drop_manual_thinking(body: &mut serde_json::Map<String, Value>) {
    if body.get("thinking").and_then(|t| t.get("type")).and_then(Value::as_str) == Some("enabled") {
        body.remove("thinking");
    }
}

/// What a renamed tool is after the rename — the form a choice naming it must
/// take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Became {
    /// The same kind of tool under a new name (a sanitized name): a choice
    /// naming it keeps its own form, custom or function.
    Renamed,
    /// A function (a substitution rule replaced the declaration).
    Function,
}

/// Point a `tool_choice` naming a renamed or substituted tool at its new
/// name. A substituted tool is an ordinary function, so a choice forcing or
/// allowing the original becomes one naming the function: Chat
/// `{type:function, function:{name}}`, Responses `{type:function, name}`,
/// Anthropic `{type:tool, name}`, and the same inside an `allowed_tools` list.
/// A renamed tool keeps its kind, so the choice keeps its form (a custom
/// choice stays custom) with the new name. Each entry is resolved ONCE
/// against the original choice, so a replacement named like another
/// substituted tool is not renamed again. A Responses hosted-type choice
/// matches its tool by FAMILY (`hosted_family`): the spec's choice enum spells
/// `web_search_preview` for a tool declared `web_search_preview_2025_03_11` or
/// `web_search`.
fn follow_substitution(choice: &mut Value, substituted: &[(String, String)], protocol: ApiVersion, became: Became) {
    use crate::api::tool_choice::{allowlist_spec_mut, wire_choice_name};
    let renamed = |entry: &Value, name: &str| match (became, protocol) {
        (Became::Renamed, _) => {
            let mut entry = entry.clone();
            // The name sits flat (Responses, Anthropic) or under the kind (Chat).
            let nested = entry
                .get("type")
                .and_then(Value::as_str)
                .filter(|kind| matches!(*kind, "function" | "custom") && entry.get(*kind).is_some())
                .map(str::to_string);
            let slot = match nested {
                Some(kind) => entry.get_mut(&kind),
                None => Some(&mut entry),
            };
            if let Some(Value::Object(m)) = slot {
                m.insert("name".into(), Value::from(name));
            }
            entry
        }
        (Became::Function, ApiVersion::ChatCompletions) => {
            serde_json::json!({"type": "function", "function": {"name": name}})
        }
        (Became::Function, _) => serde_json::json!({"type": "function", "name": name}),
    };
    let replacement_for = |entry: &Value| -> Option<String> {
        let replaced = |name: &str| substituted.iter().find(|(original, _)| original == name).map(|(_, r)| r.clone());
        match wire_choice_name(entry) {
            Some(name) => replaced(name),
            // A hosted tool is named by its type — matched by family. Only a
            // substitution replaces one; a rename is always of a named tool.
            None if became == Became::Function => {
                let kind = entry.get("type").and_then(Value::as_str)?;
                substituted
                    .iter()
                    .find(|(original, _)| hosted_family(original) == hosted_family(kind))
                    .map(|(_, r)| r.clone())
            }
            None => None,
        }
    };
    if protocol == ApiVersion::AnthropicMessages {
        if choice.get("type").and_then(Value::as_str) == Some("tool")
            && let Some(replaced) = replacement_for(choice)
        {
            choice["name"] = Value::from(replaced);
        }
        return;
    }
    if let Some(spec) = allowlist_spec_mut(choice, protocol) {
        for entry in spec.get_mut("tools").and_then(Value::as_array_mut).into_iter().flatten() {
            if let Some(replaced) = replacement_for(entry) {
                *entry = renamed(entry, &replaced);
            }
        }
    } else if choice.is_object()
        && let Some(replaced) = replacement_for(choice)
    {
        *choice = renamed(choice, &replaced);
    }
}

/// A hosted tool's family: its type without a `_YYYY_MM_DD` date or a
/// `_preview` suffix, so every spelling of one tool compares equal
/// (`web_search_preview_2025_03_11`, `web_search_preview`, `web_search`).
fn hosted_family(kind: &str) -> &str {
    let is_date = |s: &str| {
        s.len() == 10 && s.char_indices().all(|(i, c)| if i == 4 || i == 7 { c == '_' } else { c.is_ascii_digit() })
    };
    let undated = match kind.len().checked_sub(11) {
        Some(cut) if kind.as_bytes()[cut] == b'_' && is_date(&kind[cut + 1..]) => &kind[..cut],
        _ => kind,
    };
    undated.strip_suffix("_preview").unwrap_or(undated)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use sse::ApiVersion;

    #[test]
    fn own_items_replace_only_a_rendering_that_opens_with_their_own() {
        let client = ApiRequest::parse(
            ApiVersion::ChatCompletions,
            &Bytes::from(r#"{"model":"m","messages":[{"role":"user","content":"hi","name":"own"}]}"#),
        )
        .unwrap();
        let rendered = br#"{"messages":[{"role":"user","content":"hi"}]}"#;
        let own = OwnConversation::of(&client, rendered).unwrap();
        let tail = serde_json::json!({"role": "assistant", "content": "ok"});
        let kept = own
            .keep_in(serde_json::json!({"messages": [{"role": "user", "content": "hi"}, tail]}).to_string().as_bytes())
            .unwrap();
        let kept: Value = serde_json::from_slice(&kept).unwrap();
        assert_eq!(kept["messages"], serde_json::json!([{"role": "user", "content": "hi", "name": "own"}, tail]));
        // A rendering whose opening an appended turn changed keeps the domain's.
        let merged = serde_json::json!({"messages": [{"role": "user", "content": "hi\nmore"}, tail]});
        assert!(own.keep_in(merged.to_string().as_bytes()).is_none());
        assert!(own.keep_in(br#"{"messages":[]}"#).is_none());
    }

    mod built_in_output_reads {
        use super::super::*;
        use proptest::prelude::*;

        fn text() -> impl Strategy<Value = String> {
            "[a-z ]{0,6}"
        }

        /// A spec-form built-in output: a shell output's chunks of string
        /// streams and an exit or a timeout, with or without a program caller;
        /// a patch's or a local shell's string output.
        fn spec_item() -> impl Strategy<Value = Value> {
            let chunk = (text(), text(), prop_oneof![
                Just(serde_json::json!({"type": "timeout"})),
                (0i64..3).prop_map(|c| serde_json::json!({"type": "exit", "exit_code": c})),
            ])
                .prop_map(|(o, e, outcome)| serde_json::json!({"stdout": o, "stderr": e, "outcome": outcome}));
            let shell = (proptest::collection::vec(chunk, 1..3), any::<bool>()).prop_map(|(chunks, caller)| {
                let mut item = serde_json::json!({"type": "shell_call_output", "call_id": "c1", "output": chunks});
                if caller {
                    item["caller"] = serde_json::json!({"type": "program", "caller_id": "p1"});
                    item["max_output_length"] = serde_json::json!(100);
                }
                item
            });
            prop_oneof![
                shell,
                text().prop_map(|t| serde_json::json!({"type": "apply_patch_call_output", "call_id": "c1", "status": "failed", "output": t})),
                text().prop_map(|t| serde_json::json!({"type": "local_shell_call_output", "id": "c1", "status": "completed", "output": t})),
            ]
        }

        /// The text a spec-form item's output holds.
        fn spec_output_text(item: &Value) -> String {
            match &item["output"] {
                Value::String(t) => t.clone(),
                Value::Array(chunks) => shell_output_text(chunks),
                _ => String::new(),
            }
        }

        proptest! {
            /// An item is read as its text only in its spec form; a field the
            /// spec does not give it — at the top, in a chunk, in an outcome or
            /// a caller — has it read whole, so that field's text reaches the
            /// classifier. The positive control: the spec form reads as text.
            #[test]
            fn a_field_beyond_the_spec_form_is_read_whole(item in spec_item(), payload in "[A-Z]{4,8}", at in 0usize..5) {
                let read = |item: &Value| BuiltinOutput::of(item).and_then(|o| o.screen_text(item));
                let text = spec_output_text(&item);
                prop_assert_eq!(read(&item), (!text.is_empty()).then_some(text), "the spec form reads as its text");
                prop_assert!(BuiltinOutput::is_spec_form(&item));
                let shell = item["type"] == "shell_call_output";
                let mut extra = item.clone();
                match at {
                    1 if shell => extra["output"][0]["note"] = Value::String(payload.clone()),
                    2 if shell => extra["output"][0]["outcome"]["note"] = Value::String(payload.clone()),
                    3 => extra["caller"] = serde_json::json!({"type": "program", "caller_id": "p1", "note": payload.clone()}),
                    // A status the tool's spec does not give it is itself beyond
                    // the spec form.
                    4 => extra["status"] = Value::String(payload.clone()),
                    _ => extra["note"] = Value::String(payload.clone()),
                }
                prop_assert!(!BuiltinOutput::is_spec_form(&extra));
                let whole = read(&extra);
                // Whole, but for its ids.
                let mut extra_read = extra.clone();
                if let Some(o) = extra_read.as_object_mut() {
                    o.remove("call_id");
                    o.remove("id");
                }
                if let Some(c) = extra_read.get_mut("caller").and_then(Value::as_object_mut) {
                    c.remove("caller_id");
                }
                let extra_json = extra_read.to_string();
                prop_assert_eq!(whole.as_deref(), Some(extra_json.as_str()));
                prop_assert!(whole.is_some_and(|w| w.contains(&payload)));
            }

            /// A withhold leaves the item in its spec form, nothing it read
            /// remaining, whatever the item carried.
            #[test]
            fn a_withheld_output_is_its_spec_form(item in spec_item(), payload in "[A-Z]{4,8}") {
                let mut item = item;
                if item["type"] == "shell_call_output" {
                    item["output"][0]["note"] = Value::String(payload.clone());
                }
                item["note"] = Value::String(payload.clone());
                // A `content` the conversion does not read whole was read with
                // the item, so it goes with it; the role it rode beside stays.
                item["role"] = Value::String("user".to_string());
                item["content"] = serde_json::json!([{"type": "refusal", "refusal": payload.clone()}]);
                replace_builtin_output(&mut item, "[withheld]".to_string());
                prop_assert!(!item.to_string().contains(&payload));
                prop_assert!(BuiltinOutput::is_spec_form(&item));
            }
        }
    }

    #[test]
    fn a_hosted_tools_family_ignores_its_date_and_preview_suffixes() {
        for kind in ["web_search_preview_2025_03_11", "web_search_preview", "web_search"] {
            assert_eq!(hosted_family(kind), "web_search", "{kind}");
        }
        assert_eq!(hosted_family("file_search"), "file_search");
        assert_eq!(hosted_family("computer_use_preview"), "computer_use");
        // Not a date: kept whole.
        assert_eq!(hosted_family("tool_2025_03_1x"), "tool_2025_03_1x");
        assert_eq!(hosted_family("é_2025_03_11"), "é");
    }

    /// Each substitution is resolved against the ORIGINAL choice: a
    /// replacement named like another substituted tool is not renamed again.
    #[test]
    fn a_tool_choice_follows_one_substitution_not_a_chain_of_them() {
        let mut choice = serde_json::json!({"type": "function", "name": "web_search"});
        let pairs = [("web_search".to_string(), "search".to_string()), ("search".to_string(), "gw_search".to_string())];
        follow_substitution(&mut choice, &pairs, ApiVersion::Responses, Became::Function);
        assert_eq!(choice, serde_json::json!({"type": "function", "name": "search"}));
    }

    /// Responses declares a function FLAT; every name reader sees it, so a
    /// rule keyed on the name reaches Codex-style tools too.
    #[test]
    fn a_flat_responses_function_tool_is_seen_by_every_name_reader() {
        let parse = || {
            ApiRequest::parse(
                ApiVersion::Responses,
                &Bytes::from(
                    serde_json::json!({
                        "model": "m", "input": "hi",
                        "tools": [{"type": "function", "name": "shell", "parameters": {"type": "object"}},
                                  {"type": "web_search_preview"}],
                    })
                    .to_string(),
                ),
            )
            .unwrap()
        };
        assert_eq!(parse().tool_names(), ["shell"]);
        let mut req = parse();
        assert_eq!(req.remove_tools(|n| n == "shell"), ["shell"]);
        assert_eq!(req.tool_names(), Vec::<&str>::new());

        let mut odd = ApiRequest::parse(
            ApiVersion::Responses,
            &Bytes::from(
                serde_json::json!({
                    "model": "m", "input": "hi",
                    "tools": [{"type": "function", "name": "my tool!", "parameters": {"type": "object"}}],
                })
                .to_string(),
            ),
        )
        .unwrap();
        let (fixed, renames) = crate::pipeline::sanitize::sanitize_tool_names(&mut odd);
        assert_eq!(fixed, 1, "{renames:?}");
        assert_ne!(odd.tool_names(), ["my tool!"]);
    }

    fn parsed(version: ApiVersion, body: serde_json::Value) -> ApiRequest {
        ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap()
    }

    #[test]
    fn an_appended_notice_keeps_the_clients_own_chat_prompt() {
        let messages_of = |req: &ApiRequest| -> serde_json::Value {
            serde_json::from_slice::<serde_json::Value>(&req.serialize().unwrap()).unwrap()["messages"].clone()
        };
        // A multi-part prompt keeps its parts, the notice added after them.
        let mut parts = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m",
            "messages": [{"role": "system", "content": [{"type": "text", "text": "You are X"}]},
                         {"role": "user", "content": "hi"}],
        }));
        parts.append_system_prompt("N");
        let m = messages_of(&parts);
        assert_eq!(m[0]["content"][0]["text"], "You are X");
        assert_eq!(m[0]["content"][1]["text"], "\n\nN");
        // A developer-led prompt is appended to, not preceded.
        let mut dev = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m",
            "messages": [{"role": "developer", "content": "Be brief"}, {"role": "user", "content": "hi"}],
        }));
        dev.append_system_prompt("N");
        let m = messages_of(&dev);
        assert_eq!(m[0], serde_json::json!({"role": "developer", "content": "Be brief\n\nN"}));
        assert_eq!(m.as_array().map(Vec::len), Some(2));
        // A prompt over several messages gets the notice at its end.
        let mut run = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m",
            "messages": [{"role": "system", "content": "A"}, {"role": "developer", "content": "B"},
                         {"role": "user", "content": "hi"}],
        }));
        run.append_system_prompt("N");
        let m = messages_of(&run);
        assert_eq!(m[0]["content"], "A");
        assert_eq!(m[1]["content"], "B\n\nN");
        // Control: with no prompt the notice is a system message in front.
        let mut bare = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m", "messages": [{"role": "user", "content": "hi"}],
        }));
        bare.append_system_prompt("N");
        assert_eq!(messages_of(&bare)[0], serde_json::json!({"role": "system", "content": "N"}));
    }

    fn choice_of(req: &ApiRequest) -> serde_json::Value {
        serde_json::from_slice::<serde_json::Value>(&req.serialize().unwrap()).unwrap()["tool_choice"].clone()
    }

    /// A block rule reaches a custom (freeform) tool by name, and a removal
    /// pass leaves a Gemini built-in tool it has no rule about.
    #[test]
    fn removal_reaches_custom_tools_and_spares_gemini_built_ins() {
        let mut codex = parsed(ApiVersion::Responses, serde_json::json!({
            "model": "m", "input": "hi",
            "tools": [{"type": "custom", "name": "apply_patch"}, {"type": "function", "name": "shell", "parameters": {}}],
            "tool_choice": {"type": "custom", "name": "apply_patch"},
        }));
        assert_eq!(codex.remove_tools(|n| n == "apply_patch"), ["apply_patch"]);
        assert_eq!(codex.tool_names(), ["shell"]);
        assert_eq!(choice_of(&codex), serde_json::json!("none"));

        let mut gemini = parsed(ApiVersion::GoogleGemini, serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "tools": [{"googleSearch": {}}, {"functionDeclarations": [{"name": "bash"}]}],
        }));
        gemini.remove_tools(|n| n == "bash");
        let body: serde_json::Value = serde_json::from_slice(&gemini.serialize().unwrap()).unwrap();
        assert_eq!(body["tools"].as_array().map(Vec::len), Some(1), "{body}");
        assert!(body["tools"][0].get("googleSearch").is_some(), "{body}");

        // With the last declaration gone, the function-calling config governs
        // nothing and goes; the built-in stays.
        let mut configured = parsed(ApiVersion::GoogleGemini, serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "tools": [{"googleSearch": {}}, {"functionDeclarations": [{"name": "bash"}]}],
            "toolConfig": {"functionCallingConfig": {"mode": "ANY"}},
        }));
        configured.remove_tools(|n| n == "bash");
        let body: serde_json::Value = serde_json::from_slice(&configured.serialize().unwrap()).unwrap();
        assert!(body.get("toolConfig").is_none(), "{body}");
        assert!(body["tools"][0].get("googleSearch").is_some(), "{body}");

        // The snake_case spelling Gemini also accepts is read as declarations,
        // so a block rule reaches it.
        let mut snake = parsed(ApiVersion::GoogleGemini, serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "tools": [{"function_declarations": [{"name": "bash"}, {"name": "read"}]}],
        }));
        assert_eq!(snake.remove_tools(|n| n == "bash"), ["bash"]);
        assert_eq!(snake.tool_names(), ["read"]);

        // A built-in tool survives the domain round trip a substitution round
        // takes.
        let with = parsed(ApiVersion::GoogleGemini, serde_json::json!({
            "contents": [{"role": "user", "parts": [{"text": "hi"}]}],
            "tools": [{"googleSearch": {}}],
        }));
        let domain = crate::api::domain_request::DomainRequest::from_api_request(&with);
        assert!(domain.extra.contains_key("gemini_builtin_tools"));
        let rendered = serde_json::to_value(domain.to_gemini()).unwrap();
        assert_eq!(rendered["tools"], serde_json::json!([{"googleSearch": {}}]));
        // Elsewhere it has no counterpart, and the row says so.
        assert_eq!(domain.not_carried_to(ApiVersion::ChatCompletions, "m", true), ["built-in tool googleSearch"]);
        assert!(domain.not_carried_to(ApiVersion::GoogleGemini, "m", true).is_empty());
    }

    #[test]
    fn only_a_manual_thinking_budget_is_dropped_from_a_spliced_request() {
        let mut manual = serde_json::json!({"thinking": {"type": "enabled", "budget_tokens": 2048}, "model": "m"});
        drop_manual_thinking(manual.as_object_mut().unwrap());
        assert!(manual.get("thinking").is_none());
        let mut adaptive = serde_json::json!({"thinking": {"type": "adaptive"}});
        drop_manual_thinking(adaptive.as_object_mut().unwrap());
        assert_eq!(adaptive["thinking"]["type"], "adaptive");
    }

    /// A sanitized tool name carries the choice that forces it.
    #[test]
    fn a_sanitized_tool_name_carries_its_tool_choice() {
        let mut req = parsed(ApiVersion::Responses, serde_json::json!({
            "model": "m", "input": "hi",
            "tools": [{"type": "function", "name": "my tool!", "parameters": {"type": "object"}}],
            "tool_choice": {"type": "function", "name": "my tool!"},
        }));
        let (_, renames) = crate::pipeline::sanitize::sanitize_tool_names(&mut req);
        let (_, clean) = renames.iter().find(|(o, _)| o == "my tool!").unwrap();
        assert_eq!(choice_of(&req), serde_json::json!({"type": "function", "name": clean}));
    }

    /// A tool removed by policy retires the choice that named it: a forced
    /// call becomes "call nothing", an allowlist loses the entry.
    #[test]
    fn a_removed_tool_retires_the_choice_that_named_it() {
        let blocked = |name: &str| name == "bash";
        let mut forced = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "bash", "parameters": {"type": "object"}}},
                      {"type": "function", "function": {"name": "read", "parameters": {"type": "object"}}}],
            "tool_choice": {"type": "function", "function": {"name": "bash"}},
        }));
        assert_eq!(forced.remove_tools(blocked), ["bash"]);
        assert_eq!(choice_of(&forced), serde_json::json!("none"));

        let mut anthropic = parsed(ApiVersion::AnthropicMessages, serde_json::json!({
            "model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"name": "bash", "input_schema": {"type": "object"}}, {"name": "read", "input_schema": {"type": "object"}}],
            "tool_choice": {"type": "tool", "name": "bash"},
        }));
        anthropic.remove_tools(blocked);
        assert_eq!(choice_of(&anthropic), serde_json::json!({"type": "none"}));

        let mut allowlist = parsed(ApiVersion::Responses, serde_json::json!({
            "model": "m", "input": "hi",
            "tools": [{"type": "function", "name": "bash", "parameters": {"type": "object"}},
                      {"type": "function", "name": "read", "parameters": {"type": "object"}}],
            "tool_choice": {"type": "allowed_tools", "mode": "required",
                            "tools": [{"type": "function", "name": "bash"}, {"type": "function", "name": "read"}]},
        }));
        allowlist.remove_tools(blocked);
        assert_eq!(choice_of(&allowlist)["tools"], serde_json::json!([{"type": "function", "name": "read"}]));

        // With no tool left the choice governs nothing, and a `tool_choice`
        // beside no `tools` is refused: it goes, with the parallel switch.
        let mut only = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "bash", "parameters": {"type": "object"}}}],
            "tool_choice": "required", "parallel_tool_calls": false,
        }));
        only.remove_tools(blocked);
        let body: serde_json::Value = serde_json::from_slice(&only.serialize().unwrap()).unwrap();
        assert!(body.get("tools").is_none() && body.get("tool_choice").is_none(), "{body}");
        assert!(body.get("parallel_tool_calls").is_none(), "{body}");

        // Positive control: a choice naming a tool that stays is untouched.
        let mut other = parsed(ApiVersion::ChatCompletions, serde_json::json!({
            "model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "bash", "parameters": {"type": "object"}}},
                      {"type": "function", "function": {"name": "read", "parameters": {"type": "object"}}}],
            "tool_choice": {"type": "function", "function": {"name": "read"}},
        }));
        other.remove_tools(blocked);
        assert_eq!(choice_of(&other), serde_json::json!({"type": "function", "function": {"name": "read"}}));
    }

    /// A substituted Responses tool is declared in Responses' own FLAT
    /// grammar, and a flat function tool can itself be substituted by name.
    #[test]
    fn a_substituted_responses_tool_keeps_the_responses_shape() {
        let mut req = ApiRequest::parse(
            ApiVersion::Responses,
            &Bytes::from(
                serde_json::json!({
                    "model": "m", "input": "hi",
                    "tools": [{"type": "web_search_preview"}, {"type": "function", "name": "lookup", "parameters": {"type": "object"}}],
                })
                .to_string(),
            ),
        )
        .unwrap();
        let swapped = req.substitute_tools(|name| {
            matches!(name, "web_search_preview" | "lookup").then(|| crate::config::tool_rules::ToolDefValue {
                name: format!("gw_{name}"),
                description: Some("d".into()),
                parameters: serde_json::json!({"type": "object"}),
            })
        });
        assert_eq!(swapped.len(), 2);
        let body: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(
            body["tools"],
            serde_json::json!([
                {"type": "function", "name": "gw_web_search_preview", "description": "d", "parameters": {"type": "object"}},
                {"type": "function", "name": "gw_lookup", "description": "d", "parameters": {"type": "object"}},
            ])
        );
    }

    /// A same-protocol forward re-serializes the parsed request, so a field
    /// the struct does not model is gone from the wire.
    #[test]
    fn a_chat_function_keeps_strict_on_a_forward() {
        let body = serde_json::json!({
            "model": "m", "messages": [{"role": "user", "content": "hi"}],
            "tools": [{"type": "function", "function": {"name": "f", "strict": true, "parameters": {"type": "object"}}}],
        });
        let req = ApiRequest::parse(ApiVersion::ChatCompletions, &Bytes::from(body.to_string())).unwrap();
        let sent: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(sent["tools"], body["tools"]);
    }

    /// A Chat Completions custom tool is keyed by its own name (nested under
    /// `custom`), like every other tool a substitution rule can name — never by
    /// its `type`.
    #[test]
    fn a_chat_custom_tool_is_substituted_by_its_name() {
        let mut req = ApiRequest::parse(
            ApiVersion::ChatCompletions,
            &Bytes::from(
                serde_json::json!({
                    "model": "m", "messages": [{"role": "user", "content": "hi"}],
                    "tools": [{"type": "custom", "custom": {"name": "apply_patch"}}],
                    "tool_choice": {"type": "custom", "custom": {"name": "apply_patch"}},
                })
                .to_string(),
            ),
        )
        .unwrap();
        let mut asked = Vec::new();
        let swapped = req.substitute_tools(|name| {
            asked.push(name.to_string());
            (name == "apply_patch").then(|| crate::config::tool_rules::ToolDefValue {
                name: "gw_patch".into(),
                description: Some("d".into()),
                parameters: serde_json::json!({"type": "object"}),
            })
        });
        assert_eq!(asked, ["apply_patch"]);
        assert_eq!(swapped, [("apply_patch".to_string(), "gw_patch".to_string())]);
        let body: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(
            body["tools"],
            serde_json::json!([{"type": "function", "function": {"name": "gw_patch", "description": "d", "parameters": {"type": "object"}}}])
        );
        assert_eq!(body["tool_choice"], serde_json::json!({"type": "function", "function": {"name": "gw_patch"}}));
    }

    /// A choice naming a substituted tool follows it, in each grammar —
    /// otherwise it forces a tool that is no longer declared.
    #[test]
    fn a_tool_choice_follows_the_tool_substitution_replaced() {
        let replace = |name: &str| {
            (name.starts_with("web_search")).then(|| crate::config::tool_rules::ToolDefValue {
                name: "gw_search".into(),
                description: None,
                parameters: serde_json::json!({"type": "object"}),
            })
        };
        let choice_after = |version: ApiVersion, body: serde_json::Value| {
            let mut req = ApiRequest::parse(version, &Bytes::from(body.to_string())).unwrap();
            req.substitute_tools(replace);
            serde_json::to_value(req.serialize().map(|b| serde_json::from_slice::<serde_json::Value>(&b).unwrap()).unwrap())
                .unwrap()["tool_choice"]
                .clone()
        };
        assert_eq!(
            choice_after(ApiVersion::Responses, serde_json::json!({
                "model": "m", "input": "hi", "tools": [{"type": "web_search_preview"}],
                "tool_choice": {"type": "web_search_preview"},
            })),
            serde_json::json!({"type": "function", "name": "gw_search"})
        );
        assert_eq!(
            choice_after(ApiVersion::Responses, serde_json::json!({
                "model": "m", "input": "hi", "tools": [{"type": "web_search_preview"}, {"type": "function", "name": "f"}],
                "tool_choice": {"type": "allowed_tools", "mode": "required", "tools": [{"type": "web_search_preview"}, {"type": "function", "name": "f"}]},
            }))["tools"],
            serde_json::json!([{"type": "function", "name": "gw_search"}, {"type": "function", "name": "f"}])
        );
        assert_eq!(
            choice_after(ApiVersion::AnthropicMessages, serde_json::json!({
                "model": "m", "max_tokens": 8, "messages": [{"role": "user", "content": "hi"}],
                "tools": [{"type": "web_search_20250305", "name": "web_search"}],
                "tool_choice": {"type": "tool", "name": "web_search"},
            })),
            serde_json::json!({"type": "tool", "name": "gw_search"})
        );
        // The choice's spelling of a hosted tool need not match its declaration's.
        assert_eq!(
            choice_after(ApiVersion::Responses, serde_json::json!({
                "model": "m", "input": "hi", "tools": [{"type": "web_search_preview_2025_03_11"}],
                "tool_choice": {"type": "web_search_preview"},
            })),
            serde_json::json!({"type": "function", "name": "gw_search"})
        );
        // Positive control: a choice naming another tool is untouched.
        assert_eq!(
            choice_after(ApiVersion::Responses, serde_json::json!({
                "model": "m", "input": "hi", "tools": [{"type": "web_search_preview"}, {"type": "function", "name": "f"}],
                "tool_choice": {"type": "function", "name": "f"},
            })),
            serde_json::json!({"type": "function", "name": "f"})
        );
    }

    fn make_chat_json(model: &str, stream: Option<bool>) -> String {
        let stream_str = match stream {
            Some(true) => "true",
            Some(false) => "false",
            None => "null",
        };
        // null stream will be deserialized as None since it's Option<bool>
        if stream.is_none() {
            format!(
                r#"{{"model":"{model}","messages":[{{"role":"user","content":"hi"}}]}}"#
            )
        } else {
            format!(
                r#"{{"model":"{model}","messages":[{{"role":"user","content":"hi"}}],"stream":{stream_str}}}"#
            )
        }
    }

    #[test]
    fn parse_chat_completions_valid() {
        let json = make_chat_json("gpt-4o", None);
        let body = Bytes::from(json);
        let req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();
        assert_eq!(req.model(), "gpt-4o");
        assert!(!req.is_streaming());
    }

    #[test]
    fn parse_chat_completions_streaming() {
        let json = make_chat_json("gpt-4o", Some(true));
        let body = Bytes::from(json);
        let req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();
        assert!(req.is_streaming());
    }

    #[test]
    fn parse_invalid_json_returns_bad_request() {
        let body = Bytes::from("not valid json");
        let result = ApiRequest::parse(ApiVersion::ChatCompletions, &body);
        assert!(result.is_err());
        match result.unwrap_err() {
            crate::error::AppError::BadRequest(msg) => {
                assert!(msg.contains("invalid JSON"));
            }
            other => panic!("expected BadRequest, got {other:?}"),
        }
    }

    #[test]
    fn serialize_roundtrip_chat() {
        let json = make_chat_json("gpt-4o", Some(false));
        let body = Bytes::from(json);
        let req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();

        let serialized = req.serialize().unwrap();
        let req2 = ApiRequest::parse(ApiVersion::ChatCompletions, &serialized).unwrap();
        assert_eq!(req2.model(), "gpt-4o");
    }

    #[test]
    fn set_model_changes_model() {
        let json = make_chat_json("gpt-4o", None);
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();
        assert_eq!(req.model(), "gpt-4o");

        req.set_model("gpt-4o-mini".to_string());
        assert_eq!(req.model(), "gpt-4o-mini");
    }

    #[test]
    fn is_streaming_defaults_to_false() {
        let json = make_chat_json("gpt-4o", None);
        let body = Bytes::from(json);
        let req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();
        assert!(!req.is_streaming());
    }

    #[test]
    fn inject_system_prompt_into_empty_messages() {
        let json = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"hello"}]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();

        req.inject_system_prompt("You are helpful.");

        if let ApiRequest::ChatCompletions(chat) = &req {
            assert_eq!(chat.messages.len(), 2);
            assert_eq!(chat.messages[0].role, "system");
            match &chat.messages[0].content {
                Some(domain::MessageContent::Text(text)) => {
                    assert_eq!(text, "You are helpful.");
                }
                other => panic!("expected Text content, got {other:?}"),
            }
        } else {
            panic!("expected ChatCompletions variant");
        }
    }

    #[test]
    fn inject_system_prompt_merges_with_existing_system() {
        let json = r#"{"model":"gpt-4o","messages":[{"role":"system","content":"Original prompt"},{"role":"user","content":"hello"}]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();

        req.inject_system_prompt("Injected prefix.");

        if let ApiRequest::ChatCompletions(chat) = &req {
            assert_eq!(chat.messages.len(), 2); // no new message added
            match &chat.messages[0].content {
                Some(domain::MessageContent::Text(text)) => {
                    assert!(text.starts_with("Injected prefix."));
                    assert!(text.contains("Original prompt"));
                }
                other => panic!("expected Text content, got {other:?}"),
            }
        } else {
            panic!("expected ChatCompletions variant");
        }
    }

    #[test]
    fn inject_system_prompt_responses_api() {
        let json = r#"{"model":"gpt-4o","input":"hello"}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::Responses, &body).unwrap();

        req.inject_system_prompt("Be helpful.");

        if let ApiRequest::Responses(resp) = &req {
            assert_eq!(resp.instructions.as_deref(), Some("Be helpful."));
        } else {
            panic!("expected Responses variant");
        }
    }

    #[test]
    fn inject_system_prompt_responses_merges_existing() {
        let json = r#"{"model":"gpt-4o","input":"hello","instructions":"Existing."}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::Responses, &body).unwrap();

        req.inject_system_prompt("Injected.");

        if let ApiRequest::Responses(resp) = &req {
            let instructions = resp.instructions.as_deref().unwrap();
            assert!(instructions.starts_with("Injected."));
            assert!(instructions.contains("Existing."));
        } else {
            panic!("expected Responses variant");
        }
    }

    #[test]
    fn parse_responses_api_valid() {
        let json = r#"{"model":"gpt-4o","input":"hello world"}"#;
        let body = Bytes::from(json);
        let req = ApiRequest::parse(ApiVersion::Responses, &body).unwrap();
        assert_eq!(req.model(), "gpt-4o");
    }

    // ── redact_tool_results per-protocol round-trip tests ────────────────

    #[test]
    fn redact_tool_results_anthropic_text_content() {
        let json = r#"{"model":"claude","max_tokens":10,"messages":[
            {"role":"assistant","content":[
                {"type":"tool_use","id":"t1","name":"secret_lookup","input":{}}
            ]},
            {"role":"user","content":[
                {"type":"tool_result","tool_use_id":"t1","content":"key sk-abc123xyz987"}
            ]}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::AnthropicMessages, &body).unwrap();
        let redactions = req.redact_tool_results(|name, _id, content, _args| {
            if name == "secret_lookup" {
                Some((
                    content.replace("sk-abc123xyz987", "[REDACTED]"),
                    "secret-filter".to_string(),
                    "Strip vendor keys".to_string(),
                    "TEST-01".to_string(),
                ))
            } else { None }
        });
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].tool_name.as_deref(), Some("secret_lookup"));
        assert!(redactions[0].redacted_content.contains("[REDACTED]"));
        assert_eq!(redactions[0].rule_name, "secret-filter");
        assert_eq!(redactions[0].reason, "Strip vendor keys");
        assert_eq!(redactions[0].rule_id, "TEST-01");
        // Round-trip — make sure serialization succeeds and the wire form
        // carries the redacted text.
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(wire_str.contains("[REDACTED]"), "wire missing redacted content: {wire_str}");
        assert!(!wire_str.contains("sk-abc123xyz987"), "wire still contains secret: {wire_str}");
    }

    #[test]
    fn redact_tool_results_anthropic_preserves_nontext_blocks() {
        // Mixed-content tool_result: text + image. Redaction should rewrite
        // the text sub-block while leaving the image sub-block intact.
        let json = r#"{"model":"claude","max_tokens":10,"messages":[
            {"role":"assistant","content":[
                {"type":"tool_use","id":"t1","name":"fetch_screenshot","input":{}}
            ]},
            {"role":"user","content":[
                {"type":"tool_result","tool_use_id":"t1","content":[
                    {"type":"text","text":"sensitive key sk-xyz"},
                    {"type":"image","source":{"type":"base64","media_type":"image/png","data":"iVBORw0"}}
                ]}
            ]}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::AnthropicMessages, &body).unwrap();
        let redactions = req.redact_tool_results(|_name, _id, content, _args| {
            Some((
                content.replace("sk-xyz", "[REDACTED]"),
                String::new(),
                String::new(),
                "T".to_string(),
            ))
        });
        assert_eq!(redactions.len(), 1);
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(wire_str.contains("[REDACTED]"), "text rewrite lost: {wire_str}");
        assert!(!wire_str.contains("sk-xyz"), "original secret leaked: {wire_str}");
        // Image block must survive the redaction round-trip.
        assert!(wire_str.contains("iVBORw0"), "image block was silently dropped: {wire_str}");
        assert!(wire_str.contains("image/png"), "image media_type was silently dropped: {wire_str}");
    }

    #[test]
    fn redact_tool_results_responses_function_call_output() {
        let json = r#"{"model":"gpt-4o","input":[
            {"type":"function_call","call_id":"c1","name":"secret_lookup","arguments":"{}"},
            {"type":"function_call_output","call_id":"c1","output":"key sk-abc"}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::Responses, &body).unwrap();
        let redactions = req.redact_tool_results(|name, _id, content, _args| {
            if name == "secret_lookup" {
                Some((
                    content.replace("sk-abc", "[REDACTED]"),
                    String::new(),
                    String::new(),
                    "T".to_string(),
                ))
            } else { None }
        });
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].tool_name.as_deref(), Some("secret_lookup"));
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(wire_str.contains("[REDACTED]"), "wire missing redacted: {wire_str}");
        assert!(!wire_str.contains("sk-abc"), "wire still contains secret: {wire_str}");
    }

    /// A custom tool's answer is a tool result like a function's: a result
    /// redaction rule reaches it, keyed on the tool it answers, and reads the
    /// call's free text as the originating input.
    #[test]
    fn a_result_rule_reaches_a_custom_tool_output() {
        let json = r#"{"model":"gpt-4o","input":[
            {"type":"custom_tool_call","call_id":"c1","name":"secret_lookup","input":"vault"},
            {"type":"custom_tool_call_output","call_id":"c1","output":"key sk-abc"}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();
        let mut seen_args = None;
        let redactions = req.redact_tool_results(|name, _id, content, args| {
            seen_args = args.cloned();
            (name == "secret_lookup")
                .then(|| (content.replace("sk-abc", "[REDACTED]"), String::new(), String::new(), "T".to_string()))
        });
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].tool_name.as_deref(), Some("secret_lookup"));
        assert_eq!(seen_args, Some(serde_json::json!({"input": "vault"})));
        let wire: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(wire["input"][1]["output"], "key [REDACTED]");
    }

    /// The outputs of the built-in tools a client runs are tool results: a
    /// result rule reaches each, keyed on the built-in call it answers (its item
    /// type) and reading that call's payload as the originating input.
    #[test]
    fn a_result_rule_reaches_every_built_in_tool_output() {
        let json = r#"{"model":"gpt-5","input":[
            {"type":"local_shell_call","id":"ls_1","call_id":"l1","status":"completed","action":{"type":"exec","command":["cat",".env"],"env":{}}},
            {"type":"local_shell_call_output","id":"l1","output":"{\"output\":\"KEY=sk-abc\"}"},
            {"type":"shell_call","call_id":"s1","action":{"commands":["env"]},"status":"completed"},
            {"type":"shell_call_output","call_id":"s1","output":[
                {"stdout":"HOME=/root","stderr":"","outcome":{"type":"exit","exit_code":0}},
                {"stdout":"","stderr":"warn sk-abc","outcome":{"type":"exit","exit_code":1}}]},
            {"type":"apply_patch_call","call_id":"p1","status":"completed","operation":{"type":"create_file","path":"a.txt","diff":"+x"}},
            {"type":"apply_patch_call_output","call_id":"p1","status":"completed","output":"wrote sk-abc"}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();
        let mut seen = Vec::new();
        let redactions = req.redact_tool_results(|name, id, content, args| {
            seen.push((name.to_string(), id.to_string(), content.to_string(), args.cloned()));
            content.contains("sk-abc").then(|| (content.replace("sk-abc", "[REDACTED]"), String::new(), String::new(), "T".to_string()))
        });
        assert_eq!(
            seen,
            [
                (
                    "local_shell_call".to_string(),
                    "l1".to_string(),
                    r#"{"output":"KEY=sk-abc"}"#.to_string(),
                    Some(serde_json::json!({"type": "exec", "command": ["cat", ".env"], "env": {}})),
                ),
                (
                    "shell_call".to_string(),
                    "s1".to_string(),
                    "HOME=/root\nwarn sk-abc".to_string(),
                    Some(serde_json::json!({"commands": ["env"]})),
                ),
                (
                    "apply_patch_call".to_string(),
                    "p1".to_string(),
                    "wrote sk-abc".to_string(),
                    Some(serde_json::json!({"type": "create_file", "path": "a.txt", "diff": "+x"})),
                ),
            ]
        );
        assert_eq!(redactions.len(), 3);
        let wire: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(wire["input"][1]["output"], r#"{"output":"KEY=[REDACTED]"}"#);
        assert_eq!(
            wire["input"][3]["output"],
            serde_json::json!([
                {"stdout": "HOME=/root\nwarn [REDACTED]", "stderr": "", "outcome": {"type": "exit", "exit_code": 0}},
                {"stdout": "", "stderr": "", "outcome": {"type": "exit", "exit_code": 1}}])
        );
        assert_eq!(wire["input"][5]["output"], "wrote [REDACTED]");
        assert!(!wire.to_string().contains("sk-abc"));
    }

    /// A built-in output is named by its own type: sent without its call (a
    /// `previous_response_id` continuation), or under an id a function call
    /// also holds, it still reaches the built-in tool's rules — and reads only a
    /// payload of that tool, even when another tool's call reuses its id; a
    /// function's output keeps its function's name and arguments when a later
    /// built-in call reuses its id. An output with nothing to read, one in a
    /// shape the spec does not give it (a part a rewrite could not reach), and
    /// a hosted shell call's output are not asked about; the last shell call
    /// under an id decides which it is. A string shell output is read as a
    /// string, and a local shell output finds its call by the call's own `id`
    /// too.
    #[test]
    fn a_built_in_output_is_named_by_its_type_whatever_its_call() {
        let json = r#"{"model":"gpt-5","input":[
            {"type":"function_call","call_id":"x","name":"read_secrets","arguments":"{\"path\":\"/etc\"}"},
            {"type":"shell_call","call_id":"x","action":{"commands":["env"]},"status":"completed"},
            {"type":"apply_patch_call","call_id":"x","status":"completed","operation":{"type":"create_file","path":".env","diff":"+k"}},
            {"type":"apply_patch_call_output","call_id":"p0","status":"failed"},
            {"type":"shell_call","call_id":"h1","environment":{"type":"container_auto"},"action":{"commands":["ls"]},"status":"completed"},
            {"type":"shell_call_output","call_id":"h1","output":[{"stdout":"sk-abc","stderr":"","outcome":{"type":"exit","exit_code":0}}]},
            {"type":"local_shell_call","id":"ls_2","call_id":"l2","status":"completed","action":{"type":"exec","command":["env"],"env":{}}},
            {"type":"shell_call_output","call_id":"orphan","output":[{"stdout":"KEY=sk-abc","stderr":"","outcome":{"type":"exit","exit_code":0}}]},
            {"type":"apply_patch_call_output","call_id":"x","status":"completed","output":"sk-abc"},
            {"type":"shell_call_output","call_id":"s9","output":"sk-abc as a string"},
            {"type":"local_shell_call_output","id":"ls_2","output":"sk-abc"},
            {"type":"function_call_output","call_id":"x","output":"sk-abc"},
            {"type":"shell_call","call_id":"h2","environment":{"type":"container_auto"},"action":{"commands":["ls"]},"status":"completed"},
            {"type":"shell_call","call_id":"h2","action":{"commands":["env"]},"status":"completed"},
            {"type":"shell_call_output","call_id":"h2","output":[{"stdout":"sk-h2","stderr":""}]},
            {"type":"shell_call_output","call_id":"m1","output":["sk-abc",{"stdout":"","stderr":""}]},
            {"type":"shell_call_output","call_id":"e1","output":[{"stdout":"","stderr":""}]},
            {"type":"shell_call_output","call_id":"n1","output":[{"stdout":"ok","outcome":{"type":"exit","exit_code":0,"note":"sk-n1"}}]},
            {"type":"shell_call_output","call_id":"z1","output":[{"stdout":"sk-z1","stderr":null}]}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();
        let mut seen = Vec::new();
        req.redact_tool_results(|name, id, content, args| {
            seen.push((name.to_string(), id.to_string(), content.to_string(), args.cloned()));
            None
        });
        assert_eq!(
            seen,
            [
                ("shell_call".to_string(), "orphan".to_string(), "KEY=sk-abc".to_string(), None),
                (
                    "apply_patch_call".to_string(),
                    "x".to_string(),
                    "sk-abc".to_string(),
                    Some(serde_json::json!({"type": "create_file", "path": ".env", "diff": "+k"})),
                ),
                ("shell_call".to_string(), "s9".to_string(), "sk-abc as a string".to_string(), None),
                (
                    "local_shell_call".to_string(),
                    "ls_2".to_string(),
                    "sk-abc".to_string(),
                    Some(serde_json::json!({"type": "exec", "command": ["env"], "env": {}})),
                ),
                (
                    "read_secrets".to_string(),
                    "x".to_string(),
                    "sk-abc".to_string(),
                    Some(serde_json::json!({"path": "/etc"})),
                ),
                (
                    "shell_call".to_string(),
                    "h2".to_string(),
                    "sk-h2".to_string(),
                    Some(serde_json::json!({"commands": ["env"]})),
                ),
                ("shell_call".to_string(), "n1".to_string(), "ok".to_string(), None),
                ("shell_call".to_string(), "z1".to_string(), "sk-z1".to_string(), None),
            ]
        );
    }

    /// A computer call's output is a screenshot: no text a result rule could
    /// read or rewrite, so even a rule replacing every result whole leaves it a
    /// screenshot — while the same walk rewrites a function's output beside it.
    #[test]
    fn a_result_rule_leaves_a_computer_screenshot_whole() {
        let json = r#"{"model":"gpt-5","input":[
            {"type":"computer_call","call_id":"k1","status":"completed","action":{"type":"screenshot"},"pending_safety_checks":[]},
            {"type":"computer_call_output","call_id":"k1","output":{"type":"computer_screenshot","image_url":"data:image/png;base64,iVBORw0"}},
            {"type":"function_call","call_id":"f1","name":"lookup","arguments":"{}"},
            {"type":"function_call_output","call_id":"f1","output":"secret"}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();
        let mut names = Vec::new();
        let redactions = req.redact_tool_results(|name, _id, _content, _args| {
            names.push(name.to_string());
            Some(("[gone]".to_string(), String::new(), String::new(), "T".to_string()))
        });
        assert_eq!(names, ["lookup"]);
        assert_eq!(redactions.len(), 1);
        let wire: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(
            wire["input"][1]["output"],
            serde_json::json!({"type": "computer_screenshot", "image_url": "data:image/png;base64,iVBORw0"})
        );
        assert_eq!(wire["input"][3]["output"], "[gone]");
    }

    /// A shell output with no chunk carries nothing to read: no rule is asked
    /// about it, and its empty list is not turned into text.
    #[test]
    fn a_result_rule_is_not_asked_about_an_empty_shell_output() {
        let json = r#"{"model":"gpt-5","input":[
            {"type":"shell_call","call_id":"s1","action":{"commands":["true"]},"status":"completed"},
            {"type":"shell_call_output","call_id":"s1","output":[]}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();
        let redactions = req.redact_tool_results(|_, _, _, _| Some(("x".to_string(), String::new(), String::new(), "T".to_string())));
        assert!(redactions.is_empty());
        let wire: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(wire["input"][1]["output"], serde_json::json!([]));
    }

    /// A Responses tool output may be a list of parts (`input_text`,
    /// `input_image`, `input_file`). A result rule reads the parts' text and its
    /// redaction is written back into them, leaving every other part.
    #[test]
    fn a_result_rule_reads_and_rewrites_an_output_made_of_parts() {
        let json = r#"{"model":"gpt-4o","input":[
            {"type":"function_call","call_id":"c1","name":"secret_lookup","arguments":"{}"},
            {"type":"function_call_output","call_id":"c1","output":[
                {"type":"input_text","text":"key "},
                {"type":"input_image","image_url":"data:image/png;base64,iVBORw0"},
                {"type":"input_text","text":"sk-abc"}]}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::Responses, &Bytes::from(json)).unwrap();
        let mut seen = String::new();
        let redactions = req.redact_tool_results(|name, _id, content, _args| {
            seen = content.to_string();
            (name == "secret_lookup")
                .then(|| (content.replace("sk-abc", "[REDACTED]"), String::new(), String::new(), "T".to_string()))
        });
        assert_eq!(seen, "key sk-abc");
        assert_eq!(redactions.len(), 1);
        let wire: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let parts = wire["input"][1]["output"].as_array().expect("still a list of parts");
        assert_eq!(parts[0], serde_json::json!({"type": "input_text", "text": "key [REDACTED]"}));
        assert_eq!(parts[1]["type"], "input_image", "a part with no text is kept");
        assert_eq!(parts.len(), 2, "{parts:?}");
    }

    #[test]
    fn redact_tool_results_chat_completions_role_tool() {
        let json = r#"{"model":"gpt-4o","messages":[
            {"role":"assistant","content":null,"tool_calls":[
                {"id":"t1","type":"function","function":{"name":"secret_lookup","arguments":"{}"}}
            ]},
            {"role":"tool","tool_call_id":"t1","content":"key sk-xyz"}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();
        let redactions = req.redact_tool_results(|name, _id, content, _args| {
            if name == "secret_lookup" {
                Some((
                    content.replace("sk-xyz", "[REDACTED]"),
                    String::new(),
                    String::new(),
                    "T".to_string(),
                ))
            } else { None }
        });
        assert_eq!(redactions.len(), 1);
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(wire_str.contains("[REDACTED]"), "wire missing redacted: {wire_str}");
        assert!(!wire_str.contains("sk-xyz"), "wire still contains secret: {wire_str}");
    }

    #[test]
    fn redact_tool_results_gemini_no_function_response_is_noop() {
        // No functionResponse parts → walker returns empty Vec.
        let json = r#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &body).unwrap();
        let redactions = req.redact_tool_results(|_name, _id, content, _args| {
            Some((
                content.replace("anything", "[REDACTED]"),
                String::new(),
                String::new(),
                "T".to_string(),
            ))
        });
        assert!(redactions.is_empty());
    }

    #[test]
    fn redact_tool_results_gemini_function_response_string() {
        // functionResponse.response as JSON string → walker rewrites it.
        let json = r#"{"contents":[{"role":"user","parts":[{"functionResponse":{"name":"read_file","response":"the secret is sk-xyz"}}]}]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &body).unwrap();
        let redactions = req.redact_tool_results(|name, id, content, _args| {
            assert_eq!(name, "read_file");
            assert_eq!(id, "read_file"); // id surrogate when no explicit id
            Some((
                content.replace("sk-xyz", "[REDACTED]"),
                "Secret keys".to_string(),
                "API key pattern".to_string(),
                "ASI02-99".to_string(),
            ))
        });
        assert_eq!(redactions.len(), 1);
        assert_eq!(redactions[0].tool_use_id, "read_file");
        assert_eq!(redactions[0].tool_name.as_deref(), Some("read_file"));
        assert!(redactions[0].redacted_content.contains("[REDACTED]"));
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(wire_str.contains("[REDACTED]"), "wire missing redacted: {wire_str}");
        assert!(!wire_str.contains("sk-xyz"), "wire still contains secret: {wire_str}");
    }

    #[test]
    fn redact_tool_results_gemini_function_response_object() {
        // functionResponse.response as JSON object → walker stringifies for the
        // closure and writes the redacted text back as a JSON string value.
        let json = r#"{"contents":[{"role":"user","parts":[{"functionResponse":{"id":"call_42","name":"shell","response":{"stdout":"token=sk-xyz","stderr":""}}}]}]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &body).unwrap();
        let redactions = req.redact_tool_results(|name, id, content, _args| {
            assert_eq!(name, "shell");
            assert_eq!(id, "call_42"); // explicit id wins over name surrogate
            assert!(content.contains("sk-xyz"));
            Some((
                content.replace("sk-xyz", "[REDACTED]"),
                String::new(),
                String::new(),
                "T".to_string(),
            ))
        });
        assert_eq!(redactions.len(), 1);
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(!wire_str.contains("sk-xyz"));
        assert!(wire_str.contains("[REDACTED]"));
    }

    // ── originating arguments are forwarded to the closure ──────────────

    #[test]
    fn redact_tool_results_anthropic_forwards_tool_use_input() {
        // Anthropic: a tool_use precedes a tool_result; the closure must
        // receive the originating `input` JSON via the args parameter so
        // request-side `arg.<field>` / `any_arg` rules can evaluate.
        let json = r#"{"model":"claude","max_tokens":10,"messages":[
            {"role":"assistant","content":[
                {"type":"tool_use","id":"t1","name":"db_query",
                 "input":{"sql":"SELECT * FROM users WHERE id=1"}}
            ]},
            {"role":"user","content":[
                {"type":"tool_result","tool_use_id":"t1","content":"row data"}
            ]}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::AnthropicMessages, &body).unwrap();
        let mut captured: Option<serde_json::Value> = None;
        let redactions = req.redact_tool_results(|_name, _id, content, args| {
            captured = args.cloned();
            Some((
                content.to_string(),
                String::new(),
                String::new(),
                "T".to_string(),
            ))
        });
        assert_eq!(redactions.len(), 1);
        let args = captured.expect("originating args forwarded");
        assert_eq!(
            args.get("sql").and_then(|v| v.as_str()),
            Some("SELECT * FROM users WHERE id=1")
        );
    }

    #[test]
    fn redact_tool_results_chat_completions_parses_arguments_string() {
        // Chat Completions: `function.arguments` is a JSON-encoded STRING on
        // the wire. The walker must parse it to a Value so `arg.<field>`
        // resolution sees structured data, not a string blob.
        let json = r#"{"model":"gpt","messages":[
            {"role":"assistant","tool_calls":[
                {"id":"call_1","type":"function","function":{
                    "name":"fetch","arguments":"{\"url\":\"https://example.com\"}"
                }}
            ]},
            {"role":"tool","tool_call_id":"call_1","content":"<html/>"}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::ChatCompletions, &body).unwrap();
        let mut captured: Option<serde_json::Value> = None;
        let _ = req.redact_tool_results(|_name, _id, content, args| {
            captured = args.cloned();
            Some((content.to_string(), String::new(), String::new(), "T".to_string()))
        });
        let args = captured.expect("arguments parsed and forwarded");
        assert_eq!(
            args.get("url").and_then(|v| v.as_str()),
            Some("https://example.com")
        );
    }

    #[test]
    fn redact_tool_results_responses_parses_arguments_string() {
        // OpenAI Responses: `arguments` is a JSON-encoded STRING on the
        // wire (same as Chat Completions). Parse to Value before forwarding.
        let json = r#"{"model":"gpt","input":[
            {"type":"function_call","call_id":"c1","name":"shell",
             "arguments":"{\"command\":\"ls /etc\"}"},
            {"type":"function_call_output","call_id":"c1","output":"file list"}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::Responses, &body).unwrap();
        let mut captured: Option<serde_json::Value> = None;
        let _ = req.redact_tool_results(|_name, _id, content, args| {
            captured = args.cloned();
            Some((content.to_string(), String::new(), String::new(), "T".to_string()))
        });
        let args = captured.expect("arguments parsed and forwarded");
        assert_eq!(
            args.get("command").and_then(|v| v.as_str()),
            Some("ls /etc")
        );
    }

    #[test]
    fn redact_tool_results_gemini_forwards_function_call_args() {
        // Gemini: functionCall parts carry `args` as a JSON object directly,
        // read for the call the response answers (`GeminiCallIds`).
        let json = r#"{"contents":[
            {"role":"model","parts":[
                {"functionCall":{"name":"shell","args":{"command":"echo hi"}}}
            ]},
            {"role":"user","parts":[
                {"functionResponse":{"name":"shell","response":"hi"}}
            ]}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &body).unwrap();
        let mut captured: Option<serde_json::Value> = None;
        let _ = req.redact_tool_results(|_name, _id, content, args| {
            captured = args.cloned();
            Some((content.to_string(), String::new(), String::new(), "T".to_string()))
        });
        let args = captured.expect("functionCall args forwarded");
        assert_eq!(
            args.get("command").and_then(|v| v.as_str()),
            Some("echo hi")
        );
    }

    /// A Gemini response with no `id` is recorded under the call it answers
    /// as the request's parse pairs them — the id its result event carries —
    /// with that call's arguments, never its function's name or another call
    /// of that name.
    #[test]
    fn a_gemini_redaction_names_the_call_its_response_answers() {
        // Calls with no id, and calls whose id is empty — which names nothing.
        for id in ["", r#""id":"","#] {
            let json = format!(r#"{{"contents":[
                {{"role":"model","parts":[
                    {{"functionCall":{{{id}"name":"shell","args":{{"command":"one"}}}}}},
                    {{"functionCall":{{{id}"name":"shell","args":{{"command":"two"}}}}}}
                ]}},
                {{"role":"user","parts":[
                    {{"functionResponse":{{"name":"shell","response":"first"}}}},
                    {{"functionResponse":{{"name":"shell","response":"second"}}}}
                ]}}
            ]}}"#);
            let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &Bytes::from(json)).unwrap();
            let results: Vec<String> = crate::api::domain_request::DomainRequest::from_api_request(&req)
                .messages
                .iter()
                .filter_map(|m| match &m.role {
                    crate::api::domain_request::DomainRole::Tool { tool_call_id, .. } => Some(tool_call_id.clone()),
                    _ => None,
                })
                .collect();
            let mut args = Vec::new();
            let redactions = req.redact_tool_results(|_name, _id, content, call_args| {
                args.push(call_args.and_then(|a| a["command"].as_str()).map(str::to_string));
                Some((content.to_string(), String::new(), String::new(), "T".to_string()))
            });
            let named: Vec<&str> = redactions.iter().map(|r| r.tool_use_id.as_str()).collect();
            assert_eq!(results.len(), 2, "{id}");
            assert!(results.iter().all(|r| !r.is_empty()) && results[0] != results[1], "{id}: {results:?}");
            assert_eq!(named, results.iter().map(String::as_str).collect::<Vec<_>>(), "{id}");
            assert_eq!(args, [Some("one".to_string()), Some("two".to_string())], "{id}");
        }
    }

    /// A response sent again under the id of a call already answered reads
    /// that call's arguments too.
    #[test]
    fn a_gemini_result_sent_twice_reads_its_calls_arguments_both_times() {
        let json = r#"{"contents":[
            {"role":"model","parts":[{"functionCall":{"id":"c1","name":"shell","args":{"command":"rm"}}}]},
            {"role":"user","parts":[
                {"functionResponse":{"id":"c1","name":"shell","response":"one"}},
                {"functionResponse":{"id":"c1","name":"shell","response":"two"}}]}
        ]}"#;
        let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &Bytes::from(json)).unwrap();
        let mut args = Vec::new();
        let _ = req.redact_tool_results(|_name, _id, content, call_args| {
            args.push(call_args.and_then(|a| a["command"].as_str()).map(str::to_string));
            Some((content.to_string(), String::new(), String::new(), "T".to_string()))
        });
        assert_eq!(args, [Some("rm".to_string()), Some("rm".to_string())]);
    }

    /// An id generated for a Gemini call with none is never one the request
    /// states: a call the client named `call_0` and a later id-less call are
    /// two calls, each answered by its own response.
    #[test]
    fn a_generated_gemini_call_id_never_takes_one_the_client_wrote() {
        let json = r#"{"contents":[
            {"role":"model","parts":[{"functionCall":{"id":"call_0","name":"a","args":{}}}]},
            {"role":"user","parts":[{"functionResponse":{"id":"call_0","name":"a","response":"ra"}}]},
            {"role":"model","parts":[{"functionCall":{"name":"b","args":{}}}]},
            {"role":"user","parts":[{"functionResponse":{"name":"b","response":"rb"}}]}
        ]}"#;
        let req = ApiRequest::parse(ApiVersion::GoogleGemini, &Bytes::from(json)).unwrap();
        let domain = crate::api::domain_request::DomainRequest::from_api_request(&req);
        let calls: Vec<&str> = domain
            .messages
            .iter()
            .flat_map(|m| &m.content)
            .filter_map(|b| match b {
                crate::api::domain_request::DomainContentBlock::ToolUse { id, .. } => Some(id.as_str()),
                _ => None,
            })
            .collect();
        let results: Vec<&str> = domain
            .messages
            .iter()
            .filter_map(|m| match &m.role {
                crate::api::domain_request::DomainRole::Tool { tool_call_id, .. } => Some(tool_call_id.as_str()),
                _ => None,
            })
            .collect();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0], "call_0");
        assert_ne!(calls[1], "call_0", "{calls:?}");
        assert_eq!(results, calls);
    }

    #[test]
    fn redact_tool_results_anthropic_no_originating_tool_use() {
        // Orphaned tool_result (no matching tool_use in history): closure
        // receives `None` for args — rule evaluator falls back gracefully.
        let json = r#"{"model":"claude","max_tokens":10,"messages":[
            {"role":"user","content":[
                {"type":"tool_result","tool_use_id":"orphan","content":"body"}
            ]}
        ]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::AnthropicMessages, &body).unwrap();
        let mut saw_none = false;
        let _ = req.redact_tool_results(|_name, _id, content, args| {
            if args.is_none() {
                saw_none = true;
            }
            Some((content.to_string(), String::new(), String::new(), "T".to_string()))
        });
        assert!(saw_none, "orphaned tool_result must yield args=None");
    }

    #[test]
    fn redact_tool_results_gemini_preserves_other_parts() {
        // Mixed content with text + functionResponse — only the
        // functionResponse should be touched; the surrounding text part
        // stays intact.
        let json = r#"{"contents":[{"role":"user","parts":[{"text":"keep me"},{"functionResponse":{"name":"x","response":"old"}},{"text":"and me"}]}]}"#;
        let body = Bytes::from(json);
        let mut req = ApiRequest::parse(ApiVersion::GoogleGemini, &body).unwrap();
        let redactions = req.redact_tool_results(|_name, _id, _content, _args| {
            Some(("new".to_string(), String::new(), String::new(), "T".to_string()))
        });
        assert_eq!(redactions.len(), 1);
        let wire = req.serialize().unwrap();
        let wire_str = std::str::from_utf8(&wire).unwrap();
        assert!(wire_str.contains("keep me"));
        assert!(wire_str.contains("and me"));
        assert!(wire_str.contains("\"new\""));
        assert!(!wire_str.contains("\"old\""));
    }
}

#[cfg(test)]
mod server_run_result_properties {
    use super::{is_server_run_result, server_run_text, set_server_run_text};
    use proptest::prelude::*;
    use serde_json::{Value, json};

    const KINDS: [(&str, &[&str]); 7] = [
        ("mcp_call", &["output", "error"]),
        ("code_interpreter_call", &["outputs"]),
        ("file_search_call", &["results"]),
        ("mcp_approval_response", &["reason"]),
        ("computer_call_output", &["output", "acknowledged_safety_checks"]),
        ("mcp_tool_result", &["content"]),
        ("web_fetch_tool_result", &["content"]),
    ];

    /// Any JSON an attacker can put under a result's field, keyed only by what
    /// is no structural key.
    fn tree() -> impl Strategy<Value = Value> {
        let leaf = prop_oneof!["[A-Z]{4,8}".prop_map(Value::String), any::<i32>().prop_map(|n| json!(n)), Just(Value::Null)];
        leaf.prop_recursive(3, 24, 4, |inner| {
            prop_oneof![
                proptest::collection::vec(inner.clone(), 0..4).prop_map(Value::Array),
                proptest::collection::btree_map("[a-z]{3,6}x", inner, 0..4)
                    .prop_map(|m| Value::Object(m.into_iter().collect())),
            ]
        })
    }

    proptest! {
        /// Every string under a result's field is read, wherever it hides, and
        /// a write leaves none of them; what pairs the result with its call
        /// stays. Not a property: that a read is meaningful text, or that a
        /// write is idempotent in the wire's order of keys.
        #[test]
        fn no_string_under_a_result_is_unread_or_survives_a_write(
            kind in 0..KINDS.len(),
            field in 0usize..2,
            payload in tree(),
            path in proptest::collection::vec("[a-z]{3,6}x", 0..4),
            hidden in "[A-Z]{9,12}",
        ) {
            let (kind, fields) = KINDS[kind];
            let field = fields[field % fields.len()];
            let mut nested = json!({"keep": payload, "hidden": hidden});
            for key in path.iter().rev() {
                nested = json!({ key: [nested] });
            }
            let mut item = json!({"type": kind, "id": "the-id", "call_id": "the-call", "tool_use_id": "the-use", field: nested});
            prop_assert!(is_server_run_result(&item));
            let read = server_run_text(&item).unwrap_or_default();
            prop_assert!(read.contains(&hidden), "{read} of {item}");

            set_server_run_text(&mut item, "W");
            let written = server_run_text(&item).unwrap_or_default();
            prop_assert!(written.split('\n').all(|line| line == "W"), "{written}");
            prop_assert_eq!(written.split('\n').count(), read.split('\n').count());
            prop_assert!(!item.to_string().contains(&hidden));
            for (key, want) in [("type", kind), ("id", "the-id"), ("call_id", "the-call"), ("tool_use_id", "the-use")] {
                prop_assert_eq!(item[key].as_str(), Some(want));
            }
        }

        /// What names no text is read by nothing, and left as sent: an id, a
        /// link, encrypted bytes, a base64 source's data. The positive control
        /// is the property above.
        #[test]
        fn a_structural_key_is_neither_read_nor_written(secret in "[A-Z]{9,12}", kind in 0..KINDS.len()) {
            let (kind, fields) = KINDS[kind];
            let held = json!({
                "url": secret, "image_url": secret, "file_id": secret, "encrypted_content": secret,
                "encrypted_stdout": secret, "tool_use_id": secret, "code": secret, "media_type": secret,
                "source": {"type": "base64", "data": secret},
            });
            let mut item = json!({"type": kind, "id": secret, fields[0]: held});
            let sent = item.clone();
            prop_assert_eq!(server_run_text(&item), None);
            set_server_run_text(&mut item, "W");
            prop_assert_eq!(item, sent);
        }
    }

    /// A client-run tool's result and everything else is not this reader's: the
    /// names the two kinds differ by, on both sides.
    #[test]
    fn only_a_server_run_result_is_one() {
        for kind in ["tool_result", "function_call_output", "shell_call_output", "web_search_call", "reasoning", "message", "text", "image"] {
            assert!(!is_server_run_result(&json!({"type": kind})), "{kind}");
        }
        for kind in ["mcp_tool_result", "code_execution_tool_result", "bash_code_execution_tool_result", "a_future_tool_result"] {
            assert!(is_server_run_result(&json!({"type": kind})), "{kind}");
        }
        assert!(!is_server_run_result(&json!({"content": "no type"})));
    }
}
