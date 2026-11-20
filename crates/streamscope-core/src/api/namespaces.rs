//! Responses `namespace` tools: a group of function/custom tools under one
//! name (`{type: "namespace", name, description, tools: [...]}`), whose calls
//! carry the group's name beside the member's (`function_call.namespace`).
//! Codex declares every MCP server's tools this way (`mcp__<server>`).
//!
//! The gateway reads a namespace FLAT: right after a Responses request is
//! parsed, [`flatten`] turns each member into a top-level tool named
//! `<namespace>__<member>` and folds the namespace of every call in the
//! history into its name, so every reader — policy, transforms, the four
//! protocol walks, audit — sees plain functions, and a Chat, Anthropic or
//! Gemini model is offered every member. The map it returns rides on the
//! request ([`crate::api::responses::ResponsesRequest::namespaced`]):
//! - [`regroup`] puts the namespaces back on every body sent to a Responses
//!   upstream, so it sees what the client declared;
//! - [`NamespacedTools::split`] names a call to the client as the member of
//!   its namespace, wherever a Responses call item is built from a flat name;
//! - [`call_item_name`] reads a Responses call item's flat name, namespace
//!   folded, wherever the gateway reads one off the upstream's wire.
//!
//! Spec: the request's `tools[]` accepts `namespace` (members `function` or
//! `custom`, at least one); `function_call` items carry an optional
//! `namespace` (fetched 2026-11-19).

use std::borrow::Cow;
use std::collections::HashMap;

use serde_json::{Map, Value};

use crate::api::domain::{ResponseInput, Tool};
use crate::api::responses::ResponsesRequest;

/// The name a member of `namespace` is read by everywhere in the gateway.
pub fn flat_name(namespace: &str, member: &str) -> String {
    format!("{namespace}__{member}")
}

/// The call item types that carry a tool `name` (and so may carry a
/// `namespace`).
fn is_named_call(kind: &str) -> bool {
    matches!(kind, "function_call" | "custom_tool_call")
}

/// A Responses call item's name as the gateway reads it: `<namespace>__<name>`
/// when the item states a namespace, else its `name`. `None` when the item
/// has no string `name`.
pub fn call_item_name(item: &Value) -> Option<Cow<'_, str>> {
    let name = item.get("name")?.as_str()?;
    if name.is_empty() {
        return Some(Cow::Borrowed(name));
    }
    match item.get("namespace").and_then(Value::as_str).filter(|ns| !ns.is_empty()) {
        Some(ns) => Some(Cow::Owned(flat_name(ns, name))),
        None => Some(Cow::Borrowed(name)),
    }
}

/// The namespaces a Responses request declared, and every flat name read as a
/// member of one.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct NamespacedTools {
    /// Flat name → `(namespace, member)`.
    members: HashMap<String, (String, String)>,
    /// Each declared namespace's own object without its `tools`
    /// (`description`, `defer_loading`, …), in declaration order.
    declared: Vec<(String, Map<String, Value>)>,
}

impl NamespacedTools {
    pub fn is_empty(&self) -> bool {
        self.members.is_empty()
    }

    /// `(namespace, member)` for a flat name read as a namespace's member, or
    /// `(None, flat)` for any other name.
    pub fn split<'a>(&'a self, flat: &'a str) -> (Option<&'a str>, &'a str) {
        match self.members.get(flat) {
            Some((ns, member)) => (Some(ns.as_str()), member.as_str()),
            None => (None, flat),
        }
    }

    /// Name the member of a call item built from a flat name: `name` becomes
    /// the member's and `namespace` is set. A name of no namespace is left as
    /// it is.
    pub fn split_item(&self, item: &mut Value) {
        let Some(obj) = item.as_object_mut() else { return };
        if !obj.get("type").and_then(Value::as_str).is_some_and(is_named_call) || obj.contains_key("namespace") {
            return;
        }
        let Some((ns, member)) = obj.get("name").and_then(Value::as_str).and_then(|n| self.members.get(n)) else {
            return;
        };
        let (ns, member) = (ns.clone(), member.clone());
        obj.insert("name".into(), Value::String(member));
        obj.insert("namespace".into(), Value::String(ns));
    }

    fn record(&mut self, namespace: &str, member: &str) -> String {
        let flat = flat_name(namespace, member);
        self.members.entry(flat.clone()).or_insert_with(|| (namespace.to_string(), member.to_string()));
        flat
    }
}

/// Why a request's namespaces cannot be read flat.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FlattenError {
    /// Two of the client's tools would be offered to the model under one name
    /// — a namespace member and a top-level tool, or members of two
    /// namespaces whose joined names meet. A call to it could not be told
    /// apart, so the client might run the wrong tool.
    Collision(String),
    /// A `namespace` tool without a name or without a member tool.
    Malformed,
}

/// Read `req`'s namespaces flat (see the module doc) and record them on it.
/// A request with no namespace is untouched.
pub fn flatten(req: &mut ResponsesRequest) -> Result<(), FlattenError> {
    let mut map = std::mem::take(&mut req.namespaced);
    if let Some(tools) = &mut req.tools {
        let mut flat_tools: Vec<Tool> = Vec::with_capacity(tools.len());
        // Only a name a namespace member takes can collide: two top-level
        // tools of one name are the client's own affair, passed on as sent.
        let top_level: std::collections::HashSet<String> = tools
            .iter()
            .filter(|t| t.r#type != "namespace")
            .filter_map(|t| t.function_name().map(str::to_string))
            .collect();
        let mut taken: std::collections::HashSet<String> = std::collections::HashSet::new();
        for tool in tools.drain(..) {
            if tool.r#type != "namespace" {
                flat_tools.push(tool);
                continue;
            }
            let mut own = tool.extra;
            let ns = own.remove("name").and_then(|v| v.as_str().map(str::to_string)).filter(|n| !n.is_empty());
            let members = own.remove("tools");
            let (Some(ns), Some(Value::Array(members))) = (ns, members) else {
                return Err(FlattenError::Malformed);
            };
            if members.is_empty() {
                return Err(FlattenError::Malformed);
            }
            for mut member in members {
                let Some(name) = member.get("name").and_then(Value::as_str).map(str::to_string) else {
                    return Err(FlattenError::Malformed);
                };
                let flat = map.record(&ns, &name);
                if top_level.contains(&flat) || !taken.insert(flat.clone()) {
                    return Err(FlattenError::Collision(flat));
                }
                member["name"] = Value::String(flat);
                flat_tools.push(serde_json::from_value(member).map_err(|_| FlattenError::Malformed)?);
            }
            map.declared.push((ns, own.into_iter().collect()));
        }
        *tools = flat_tools;
    }
    if let ResponseInput::Raw(items) = &mut req.input {
        for item in items.iter_mut() {
            fold_call_namespace(item, &mut map);
        }
    }
    // A choice naming a member by its own name — forced, or an entry of an
    // `allowed_tools` list — names its flat tool, only when one namespace has
    // a member of that name and no top-level tool does.
    if let Some(choice) = &mut req.tool_choice {
        let top_level: std::collections::HashSet<&str> =
            req.tools.iter().flatten().filter_map(|t| t.function_name()).collect();
        for entry in named_choices(choice) {
            let Some(name) = entry.get("name").and_then(Value::as_str) else { continue };
            if map.members.contains_key(name) || top_level.contains(name) {
                continue;
            }
            let mut hits = map.members.iter().filter(|(_, (_, member))| member == name);
            if let (Some((flat, _)), None) = (hits.next(), hits.next()) {
                entry.insert("name".into(), Value::String(flat.clone()));
            }
        }
    }
    req.namespaced = map;
    Ok(())
}

/// Fold a history call item's `namespace` into its name, recording the member
/// (a namespace loaded by tool search is not in `tools`).
fn fold_call_namespace(item: &mut Value, map: &mut NamespacedTools) {
    let Some(obj) = item.as_object_mut() else { return };
    if !obj.get("type").and_then(Value::as_str).is_some_and(is_named_call) {
        return;
    }
    let ns = match obj.get("namespace").and_then(Value::as_str) {
        Some(ns) if !ns.is_empty() => ns.to_string(),
        _ => return,
    };
    let Some(name) = obj.get("name").and_then(Value::as_str).map(str::to_string) else { return };
    let flat = map.record(&ns, &name);
    obj.insert("name".into(), Value::String(flat));
    obj.remove("namespace");
}

/// Put `map`'s namespaces back on a serialised Responses request body: each
/// declared namespace's members, as policy and transforms left them, are
/// nested again at the first one's position (a namespace left with none is
/// dropped — the spec wants at least one); each history call of a member
/// carries its namespace and member name again; a forced choice of a member
/// names the member.
pub fn regroup(body: &mut Map<String, Value>, map: &NamespacedTools) {
    if map.is_empty() {
        return;
    }
    if let Some(Value::Array(tools)) = body.get_mut("tools") {
        let mut out: Vec<Value> = Vec::with_capacity(tools.len());
        let mut slot: HashMap<&str, usize> = HashMap::new();
        for mut tool in tools.drain(..) {
            let member = tool
                .get("name")
                .and_then(Value::as_str)
                .and_then(|n| map.members.get(n))
                .filter(|(ns, _)| map.declared.iter().any(|(d, _)| d == ns));
            let Some((ns, member)) = member else {
                out.push(tool);
                continue;
            };
            tool["name"] = Value::String(member.clone());
            let at = *slot.entry(ns.as_str()).or_insert_with(|| {
                let own = map.declared.iter().find(|(d, _)| d == ns).map(|(_, o)| o.clone()).unwrap_or_default();
                let mut group = Map::new();
                group.insert("type".into(), Value::String("namespace".into()));
                group.insert("name".into(), Value::String(ns.clone()));
                group.extend(own);
                group.insert("tools".into(), Value::Array(Vec::new()));
                out.push(Value::Object(group));
                out.len() - 1
            });
            if let Some(Value::Array(members)) = out[at].get_mut("tools") {
                members.push(tool);
            }
        }
        *tools = out;
    }
    if let Some(Value::Array(items)) = body.get_mut("input") {
        for item in items.iter_mut() {
            map.split_item(item);
        }
    }
    if let Some(choice) = body.get_mut("tool_choice") {
        for entry in named_choices(choice) {
            if let Some((_, member)) = entry.get("name").and_then(Value::as_str).and_then(|n| map.members.get(n)) {
                entry.insert("name".into(), Value::String(member.clone()));
            }
        }
    }
}

/// The parts of a Responses `tool_choice` that name a tool by a `name`
/// member: the choice itself when it forces a tool, or each entry of an
/// allowlist — read through the one reader of the choice grammar
/// ([`crate::api::tool_choice::allowlist_spec_mut`],
/// [`crate::api::tool_choice::wire_choice_name`]).
fn named_choices(choice: &mut Value) -> Vec<&mut Map<String, Value>> {
    use crate::api::sse::ApiVersion;
    use crate::api::tool_choice::{allowlist_spec_mut, wire_choice_name};
    let names_a_tool = |v: &Value| wire_choice_name(v).is_some() && v.get("name").is_some_and(Value::is_string);
    if allowlist_spec_mut(choice, ApiVersion::Responses).is_some() {
        return match allowlist_spec_mut(choice, ApiVersion::Responses).and_then(|spec| spec.get_mut("tools")) {
            Some(Value::Array(entries)) => {
                entries.iter_mut().filter(|e| names_a_tool(e)).filter_map(Value::as_object_mut).collect()
            }
            _ => Vec::new(),
        };
    }
    if names_a_tool(choice) { choice.as_object_mut().into_iter().collect() } else { Vec::new() }
}

/// Name every call of a buffered Responses response (`output[]`) as the member
/// of its namespace ([`NamespacedTools::split_item`]).
pub fn split_calls_in_response(body: &mut Value, map: &NamespacedTools) {
    if map.is_empty() {
        return;
    }
    if let Some(Value::Array(items)) = body.get_mut("output") {
        for item in items.iter_mut() {
            map.split_item(item);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn codex_request() -> ResponsesRequest {
        serde_json::from_value(json!({
            "model": "gpt-5",
            "input": [
                {"type": "message", "role": "user", "content": "fetch it"},
                {"type": "function_call", "call_id": "c1", "namespace": "mcp__web", "name": "web_fetch", "arguments": "{}"},
                {"type": "function_call_output", "call_id": "c1", "output": "ok"}
            ],
            "tools": [
                {"type": "function", "name": "shell", "parameters": {"type": "object"}},
                {"type": "namespace", "name": "mcp__web", "description": "Web tools", "defer_loading": false,
                 "tools": [
                    {"type": "function", "name": "web_fetch", "parameters": {"type": "object"}},
                    {"type": "function", "name": "web_search", "parameters": {"type": "object"}}
                 ]}
            ],
            "tool_choice": {"type": "function", "name": "web_fetch"}
        }))
        .expect("a Codex-shaped request")
    }

    #[test]
    fn a_namespace_is_read_flat_and_put_back_as_declared() {
        let original = serde_json::to_value(codex_request()).unwrap();
        let mut req = codex_request();
        flatten(&mut req).unwrap();
        let names: Vec<_> = req.tools.iter().flatten().filter_map(|t| t.function_name()).collect();
        assert_eq!(names, ["shell", "mcp__web__web_fetch", "mcp__web__web_search"]);
        let ResponseInput::Raw(items) = &req.input else { panic!("raw input") };
        assert_eq!(items[1]["name"], "mcp__web__web_fetch");
        assert!(items[1].get("namespace").is_none());
        assert_eq!(req.tool_choice.as_ref().unwrap()["name"], "mcp__web__web_fetch");

        let Value::Object(mut body) = serde_json::to_value(&req).unwrap() else { panic!() };
        regroup(&mut body, &req.namespaced);
        assert_eq!(Value::Object(body), original, "flatten then regroup gives back the client's request");
    }

    /// An `allowed_tools` list names a member's flat tool as a forced choice
    /// does, and its member again on a Responses upstream.
    #[test]
    fn an_allowed_tools_list_names_the_members_flat_tool() {
        let allowed = json!({"type": "allowed_tools", "mode": "required",
            "tools": [{"type": "function", "name": "web_fetch"}, {"type": "function", "name": "shell"}]});
        let mut req = codex_request();
        req.tool_choice = Some(allowed.clone());
        let original = serde_json::to_value(&req).unwrap();
        flatten(&mut req).unwrap();
        let choice = req.tool_choice.as_ref().unwrap();
        assert_eq!(choice["tools"][0]["name"], "mcp__web__web_fetch");
        assert_eq!(choice["tools"][1]["name"], "shell");
        let Value::Object(mut body) = serde_json::to_value(&req).unwrap() else { panic!() };
        regroup(&mut body, &req.namespaced);
        assert_eq!(Value::Object(body), original);
    }

    #[test]
    fn a_member_policy_removed_leaves_its_namespace_and_an_emptied_one_is_dropped() {
        let mut req = codex_request();
        flatten(&mut req).unwrap();
        req.tools.as_mut().unwrap().retain(|t| t.function_name() != Some("mcp__web__web_search"));
        let Value::Object(mut body) = serde_json::to_value(&req).unwrap() else { panic!() };
        regroup(&mut body, &req.namespaced);
        assert_eq!(body["tools"][1]["tools"].as_array().unwrap().len(), 1);
        assert_eq!(body["tools"][1]["tools"][0]["name"], "web_fetch");

        req.tools.as_mut().unwrap().retain(|t| t.function_name() == Some("shell"));
        let Value::Object(mut body) = serde_json::to_value(&req).unwrap() else { panic!() };
        regroup(&mut body, &req.namespaced);
        assert_eq!(body["tools"].as_array().unwrap().len(), 1, "no empty namespace is sent");
    }

    #[test]
    fn two_tools_under_one_model_visible_name_are_refused() {
        let mut req = codex_request();
        req.tools.as_mut().unwrap().push(
            serde_json::from_value(json!({"type": "function", "name": "mcp__web__web_fetch"})).unwrap(),
        );
        assert_eq!(flatten(&mut req), Err(FlattenError::Collision("mcp__web__web_fetch".into())));

        let mut joined: ResponsesRequest = serde_json::from_value(json!({
            "model": "m", "input": "hi",
            "tools": [
                {"type": "namespace", "name": "a__b", "tools": [{"type": "function", "name": "c"}]},
                {"type": "namespace", "name": "a", "tools": [{"type": "function", "name": "b__c"}]}
            ]
        }))
        .unwrap();
        assert_eq!(flatten(&mut joined), Err(FlattenError::Collision("a__b__c".into())));

        let mut empty: ResponsesRequest = serde_json::from_value(json!({
            "model": "m", "input": "hi", "tools": [{"type": "namespace", "name": "a", "tools": []}]
        }))
        .unwrap();
        assert_eq!(flatten(&mut empty), Err(FlattenError::Malformed));
    }

    #[test]
    fn a_call_is_named_to_the_client_as_its_namespaces_member() {
        let mut req = codex_request();
        flatten(&mut req).unwrap();
        let mut answer = json!({"output": [
            {"type": "function_call", "call_id": "c2", "name": "mcp__web__web_fetch", "arguments": "{}"},
            {"type": "function_call", "call_id": "c3", "name": "shell", "arguments": "{}"},
            {"type": "message", "role": "assistant", "content": []}
        ]});
        split_calls_in_response(&mut answer, &req.namespaced);
        assert_eq!(answer["output"][0]["name"], "web_fetch");
        assert_eq!(answer["output"][0]["namespace"], "mcp__web");
        assert_eq!(answer["output"][1]["name"], "shell");
        assert!(answer["output"][1].get("namespace").is_none());
        // An item the upstream already named is left as it is.
        let mut raw = json!({"type": "function_call", "namespace": "mcp__web", "name": "web_fetch"});
        req.namespaced.split_item(&mut raw);
        assert_eq!(raw, json!({"type": "function_call", "namespace": "mcp__web", "name": "web_fetch"}));
        assert_eq!(call_item_name(&raw).as_deref(), Some("mcp__web__web_fetch"));
    }

    #[test]
    fn a_namespace_loaded_by_tool_search_is_still_split_back() {
        let mut req: ResponsesRequest = serde_json::from_value(json!({
            "model": "m",
            "input": [{"type": "function_call", "call_id": "c1", "namespace": "mcp__gh", "name": "list", "arguments": "{}"}]
        }))
        .unwrap();
        flatten(&mut req).unwrap();
        assert_eq!(req.namespaced.split("mcp__gh__list"), (Some("mcp__gh"), "list"));
        let Value::Object(mut body) = serde_json::to_value(&req).unwrap() else { panic!() };
        regroup(&mut body, &req.namespaced);
        assert_eq!(body["input"][0]["namespace"], "mcp__gh");
        assert_eq!(body["input"][0]["name"], "list");
    }

    #[test]
    fn a_request_without_a_namespace_is_untouched() {
        let mut req: ResponsesRequest = serde_json::from_value(json!({
            "model": "m", "input": "hi",
            "tools": [{"type": "function", "name": "a__b"}],
            "tool_choice": {"type": "function", "name": "a__b"}
        }))
        .unwrap();
        let before = serde_json::to_value(&req).unwrap();
        flatten(&mut req).unwrap();
        assert!(req.namespaced.is_empty());
        let Value::Object(mut body) = serde_json::to_value(&req).unwrap() else { panic!() };
        regroup(&mut body, &req.namespaced);
        assert_eq!(Value::Object(body), before);
    }
}

/// A Codex request through the gateway's own parse and walks: every target is
/// offered the namespace's members, and a Responses upstream is sent them
/// nested as the client declared them.
#[cfg(test)]
mod per_target {
    use crate::api::ApiRequest;
    use crate::api::domain_request::DomainRequest;
    use bytes::Bytes;
    use serde_json::{Value, json};

    fn codex_body() -> Value {
        json!({
            "model": "gpt-5",
            "input": [
                {"type": "message", "role": "user", "content": "fetch it"},
                {"type": "function_call", "call_id": "c1", "namespace": "mcp__web", "name": "web_fetch", "arguments": "{\"url\":\"https://a.example\"}"},
                {"type": "function_call_output", "call_id": "c1", "output": "ok"}
            ],
            "tools": [
                {"type": "namespace", "name": "mcp__web", "description": "Web tools",
                 "tools": [{"type": "function", "name": "web_fetch", "description": "Fetch", "parameters": {"type": "object", "properties": {"url": {"type": "string"}}}}]}
            ]
        })
    }

    fn parsed() -> (ApiRequest, DomainRequest) {
        let req = ApiRequest::parse(crate::api::sse::ApiVersion::Responses, &Bytes::from(codex_body().to_string())).expect("parses");
        let ApiRequest::Responses(r) = &req else { panic!("a Responses request") };
        let domain = DomainRequest::from_responses(r);
        (req, domain)
    }

    #[test]
    fn a_chat_upstream_is_offered_each_member_as_a_function() {
        let chat = serde_json::to_value(parsed().1.to_chat_completions()).unwrap();
        assert_eq!(chat["tools"][0]["type"], "function");
        assert_eq!(chat["tools"][0]["function"]["name"], "mcp__web__web_fetch");
        let call = chat["messages"].as_array().unwrap().iter().find_map(|m| m.get("tool_calls")).expect("the history call");
        assert_eq!(call[0]["function"]["name"], "mcp__web__web_fetch");
    }

    #[test]
    fn an_anthropic_upstream_is_offered_each_member_as_a_tool() {
        let msgs = serde_json::to_value(parsed().1.to_anthropic()).unwrap();
        assert_eq!(msgs["tools"][0]["name"], "mcp__web__web_fetch");
        assert!(msgs["tools"][0].get("type").is_none_or(|t| t == "custom"), "a client tool, not a server tool: {}", msgs["tools"][0]);
        let uses: Vec<_> = msgs["messages"].as_array().unwrap().iter()
            .flat_map(|m| m["content"].as_array().cloned().unwrap_or_default())
            .filter(|b| b["type"] == "tool_use").collect();
        assert_eq!(uses[0]["name"], "mcp__web__web_fetch");
    }

    #[test]
    fn a_gemini_upstream_is_offered_each_member_as_a_function_declaration() {
        let gem = serde_json::to_value(parsed().1.to_gemini()).unwrap();
        let decls = gem["tools"][0]["functionDeclarations"].as_array().expect("declarations");
        assert_eq!(decls[0]["name"], "mcp__web__web_fetch");
    }

    #[test]
    fn a_responses_upstream_is_sent_the_namespace_as_declared() {
        let (req, domain) = parsed();
        let wire: Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        assert_eq!(wire["tools"], codex_body()["tools"]);
        assert_eq!(wire["input"][1]["namespace"], "mcp__web");
        assert_eq!(wire["input"][1]["name"], "web_fetch");
        assert_eq!(req.wire_value().unwrap()["tools"], codex_body()["tools"]);
        // Nothing of the client's namespace is lost on the way.
        assert!(domain.not_carried_to(crate::api::sse::ApiVersion::ChatCompletions, "gpt-4o", false).is_empty());
    }
}

/// The answer: an upstream's call to a member is read by its flat name, and a
/// call built for a Responses client names the member of its namespace.
#[cfg(test)]
mod answer {
    use super::*;
    use crate::api::domain::{CallArguments, DomainEvent};
    use crate::api::sse::{ApiVersion, SseEvent, StreamParser};
    use serde_json::json;

    fn map() -> std::sync::Arc<NamespacedTools> {
        let mut req: ResponsesRequest = serde_json::from_value(json!({
            "model": "m", "input": "hi",
            "tools": [{"type": "namespace", "name": "mcp__web", "tools": [{"type": "function", "name": "web_fetch"}]}]
        }))
        .unwrap();
        flatten(&mut req).unwrap();
        std::sync::Arc::new(req.namespaced)
    }

    #[test]
    fn a_streamed_upstream_call_to_a_member_is_read_by_its_flat_name() {
        let mut parser = StreamParser::new(ApiVersion::Responses);
        let events = parser.parse(&SseEvent {
            event_type: Some("response.output_item.added".into()),
            data: json!({"output_index": 0, "item": {"id": "fc_1", "type": "function_call", "call_id": "call_1",
                "namespace": "mcp__web", "name": "web_fetch", "arguments": ""}})
            .to_string(),
            id: None,
        });
        let names: Vec<_> = events
            .iter()
            .filter_map(|e| match e {
                DomainEvent::ToolCallDelta { function_name, .. } => function_name.clone(),
                _ => None,
            })
            .collect();
        assert_eq!(names, ["mcp__web__web_fetch"]);
        let item = json!({"type": "function_call", "namespace": "mcp__web", "name": "web_fetch", "arguments": "{}"});
        assert_eq!(crate::api::domain::tool_call_item(&item).unwrap().name, "mcp__web__web_fetch");
    }

    #[test]
    fn a_translated_stream_names_the_member_of_its_namespace_to_a_responses_client() {
        let mut builder = crate::pipeline::translate::ResponsesResponseBuilder::new("resp_1".into(), "m".into())
            .with_namespaced_tools(map());
        let mut frames = builder.process_event(&DomainEvent::ToolCallDelta {
            index: 0,
            id: Some("call_1".into()),
            function_name: Some("mcp__web__web_fetch".into()),
            arguments_delta: "{}".into(),
            form: CallArguments::Json,
        });
        frames.extend(builder.process_event(&DomainEvent::Done { finish_reason: None, native_finish_reason: None }));
        frames.extend(builder.flush_pending());
        let items: Vec<Value> = frames
            .iter()
            .flat_map(|f| f.lines())
            .filter_map(|l| l.strip_prefix("data: "))
            .filter_map(|d| serde_json::from_str::<Value>(d).ok())
            .filter_map(|e| e.get("item").cloned())
            .filter(|i| i["type"] == "function_call")
            .collect();
        assert!(items.len() >= 2, "added and done: {items:?}");
        for item in items {
            assert_eq!((item["namespace"].as_str(), item["name"].as_str()), (Some("mcp__web"), Some("web_fetch")), "{item}");
        }
    }
}

/// What the module claims of any request whose namespaces collide nowhere —
/// its tools, the history's calls of them, a forced choice or an allowlist —:
/// it reaches the model with every name once and no namespace left, and a
/// Responses upstream gets it back as the client sent it. Not claimed: that a request flattened twice is
/// unchanged by the second pass — the parser runs once per body.
#[cfg(test)]
mod properties {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn namespaces() -> impl Strategy<Value = Vec<(String, Vec<String>)>> {
        // Lower-case names hold no `__`, so no two joined names can meet.
        proptest::collection::btree_map("[a-z]{1,6}", proptest::collection::btree_set("[a-z]{1,6}", 1..4), 0..4)
            .prop_map(|m| m.into_iter().map(|(ns, members)| (ns, members.into_iter().collect())).collect())
    }

    proptest! {
        #[test]
        fn a_request_without_a_collision_is_flat_once_and_comes_back_as_sent(
            groups in namespaces(),
            top in proptest::collection::btree_set("[A-Z]{1,6}", 0..3),
            forced in proptest::option::of(0usize..8),
            allowlist in any::<bool>(),
        ) {
            let mut tools: Vec<Value> = top.iter().map(|n| json!({"type": "function", "name": n})).collect();
            for (ns, members) in &groups {
                tools.push(json!({"type": "namespace", "name": ns, "description": "d",
                    "tools": members.iter().map(|m| json!({"type": "function", "name": m})).collect::<Vec<_>>()}));
            }
            let all_members: Vec<&String> = groups.iter().flat_map(|(_, m)| m).collect();
            // The history calls each namespace's first member, as Codex sends it.
            let mut input = vec![json!({"type": "message", "role": "user", "content": "hi"})];
            for (i, (ns, members)) in groups.iter().enumerate() {
                input.push(json!({"type": "function_call", "call_id": format!("c{i}"), "namespace": ns, "name": members[0], "arguments": "{}"}));
                input.push(json!({"type": "function_call_output", "call_id": format!("c{i}"), "output": "ok"}));
            }
            let mut body = json!({"model": "m", "input": input, "tools": tools});
            if allowlist {
                let entries: Vec<Value> = all_members.iter().map(|m| json!({"type": "function", "name": m})).collect();
                body["tool_choice"] = json!({"type": "allowed_tools", "mode": "auto", "tools": entries});
            } else if let Some(i) = forced.filter(|_| !all_members.is_empty()) {
                body["tool_choice"] = json!({"type": "function", "name": all_members[i % all_members.len()]});
            }
            let mut req: ResponsesRequest = serde_json::from_value(body).unwrap();
            let original = serde_json::to_value(&req).unwrap();
            flatten(&mut req).unwrap();

            let names: Vec<&str> = req.tools.iter().flatten().filter_map(|t| t.function_name()).collect();
            let unique: std::collections::HashSet<&str> = names.iter().copied().collect();
            prop_assert_eq!(unique.len(), names.len());
            prop_assert_eq!(names.len(), top.len() + all_members.len());
            prop_assert!(req.tools.iter().flatten().all(|t| t.r#type != "namespace"));
            // A history of only a message reads as messages, with no call to fold.
            if let ResponseInput::Raw(items) = &req.input {
                prop_assert!(items.iter().all(|i| i.get("namespace").is_none()));
            }

            let Value::Object(mut wire) = serde_json::to_value(&req).unwrap() else { unreachable!() };
            regroup(&mut wire, &req.namespaced);
            prop_assert_eq!(Value::Object(wire), original);
        }
    }
}
