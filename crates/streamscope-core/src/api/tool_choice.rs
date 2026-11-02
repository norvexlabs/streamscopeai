//! The client's tool-use instruction, settled once at the parser.
//!
//! Every protocol spells "may / must / must not call a tool, and which" in its
//! own grammar. Carried through the domain as the INBOUND JSON, each outbound
//! walk had to re-interpret every grammar, and one it did not know passed
//! through untouched — so a foreign shape reached an upstream that does not
//! define it. The meaning is therefore fixed here, once per inbound protocol,
//! and each target renders it from this one type.
//!
//! The grammars, per each provider's published spec:
//! - **Chat Completions** — `"none" | "auto" | "required"`,
//!   `{type:"function", function:{name}}`, `{type:"allowed_tools",
//!   allowed_tools:{mode:"auto"|"required", tools:[{type:"function",
//!   function:{name}}]}}`, `{type:"custom", custom:{name}}`. Parallel calls are
//!   a separate top-level `parallel_tool_calls` boolean.
//! - **Responses** — the same three strings, `{type:"function", name}` (flat),
//!   `{type:"allowed_tools", mode, tools:[{type:"function", name}]}` (flat),
//!   plus hosted-tool, `mcp`, `custom`, `shell`, `apply_patch` choices that name
//!   no function. `parallel_tool_calls` is a top-level boolean.
//! - **Anthropic Messages** — `{type:"auto"|"any"|"none"}`, `{type:"tool",
//!   name}`. The parallel switch rides INSIDE the choice as
//!   `disable_parallel_tool_use` (on `auto`, `any`, `tool`). There is no
//!   allowed-subset form.
//! - **Gemini** `functionCallingConfig` — `mode` `AUTO | ANY | NONE |
//!   VALIDATED` (unset = `AUTO`) with `allowedFunctionNames`, which limits the
//!   call to those names under `ANY` and `VALIDATED`. No parallel switch.
//!
//! Invariant to preserve: **a rendering never widens what the client
//! allowed.** An allowlist narrows every target's declared `tools` (the one
//! grammar every server reads) and a forced call keeps its name; a choice with
//! no meaning on the target becomes "call nothing" when it confined the model
//! to tools the target does not have, and is omitted only when it restricted
//! no function (see [`DomainToolChoice::Native`]). Locked by
//! `no_target_ever_widens_the_client_choice` and
//! `a_native_choice_never_widens_on_another_protocol`.

use serde_json::Value;

use super::domain_request::SourceProtocol;
use super::gemini::{GeminiFunctionCallingConfig, GeminiToolConfig};
use super::sse::ApiVersion;

/// What the client asked the model to do with its tools.
#[derive(Debug, Clone, PartialEq)]
pub enum DomainToolChoice {
    /// The model decides — the default on every protocol whenever tools exist.
    Auto,
    /// The model must not call a tool.
    None,
    /// The model must call at least one tool (Chat/Responses `required`,
    /// Anthropic `any`, Gemini `ANY`).
    Required,
    /// The model must call exactly this function.
    Function(String),
    /// Only these functions may be called; `required` = one of them must be.
    /// Never holds a single name with `required` (that is [`Self::Function`])
    /// and never an empty list.
    Allowed { names: Vec<String>, required: bool },
    /// A choice with no cross-protocol meaning — forcing a hosted tool, an MCP
    /// server or a Chat custom tool, an allowlist of only such tools, Gemini's
    /// `VALIDATED` with no names. Rendered verbatim for the protocol that sent
    /// it. Elsewhere, one that [`confines`](Self::confines) the model to tools
    /// that protocol does not have becomes "call nothing" — omitting it would
    /// let the model call any declared function, which the client did not
    /// allow — and one that restricts no function is omitted.
    Native { source: SourceProtocol, value: Value },
}

impl DomainToolChoice {
    /// The canonical form an allowlist settles to. An empty list names nothing
    /// representable. One required name IS a forced function — but only when
    /// the list named functions and nothing else (`exhaustive`): a list that
    /// also allowed a hosted or MCP tool let the model pick that instead, so it
    /// stays an allowlist.
    fn allowed(names: Vec<String>, required: bool, exhaustive: bool) -> Option<Self> {
        match names.as_slice() {
            [] => None,
            [only] if required && exhaustive => Some(Self::Function(only.clone())),
            _ => Some(Self::Allowed { names, required }),
        }
    }

    /// The three strings OpenAI's two protocols share.
    fn from_openai_str(s: &str) -> Option<Self> {
        match s {
            "auto" => Some(Self::Auto),
            "none" => Some(Self::None),
            "required" => Some(Self::Required),
            _ => None,
        }
    }

    /// `mode` of an allowlist on either OpenAI protocol.
    fn allowlist_required(mode: Option<&Value>) -> Option<bool> {
        match mode.and_then(Value::as_str) {
            Some("required") => Some(true),
            Some("auto") => Some(false),
            _ => None,
        }
    }

    /// Parse a Chat Completions `tool_choice`.
    pub fn from_chat(v: &Value) -> Self {
        let native = || Self::Native { source: SourceProtocol::OpenAiChat, value: v.clone() };
        if let Some(s) = v.as_str() {
            // Mistral's Chat Completions spells `required` as `any` too, and
            // its SDKs send `any`.
            if s == "any" {
                return Self::Required;
            }
            return Self::from_openai_str(s).unwrap_or_else(native);
        }
        match v.get("type").and_then(Value::as_str) {
            // A custom tool is carried into the domain by name, so forcing it
            // is forcing that tool (rendered in the custom form where it is
            // declared, as "call nothing" where it is not).
            Some(kind @ ("function" | "custom")) => v
                .get(kind)
                .and_then(|f| f.get("name"))
                .and_then(Value::as_str)
                .map(|n| Self::Function(n.to_string()))
                .unwrap_or_else(native),
            Some("allowed_tools") => {
                let spec = v.get("allowed_tools");
                // A custom tool is carried into the domain by name like a
                // function, so the allowlist keeps it where it is declared.
                let (names, exhaustive) = function_names(spec.and_then(|s| s.get("tools")), |t| {
                    match t.get("type").and_then(Value::as_str) {
                        Some(kind @ ("function" | "custom")) => t.get(kind).and_then(|f| f.get("name")),
                        _ => None,
                    }
                });
                Self::allowlist_required(spec.and_then(|s| s.get("mode")))
                    .and_then(|required| Self::allowed(names, required, exhaustive))
                    .unwrap_or_else(native)
            }
            _ => native(),
        }
    }

    /// Parse a Responses `tool_choice`.
    pub fn from_responses(v: &Value) -> Self {
        let native = || Self::Native { source: SourceProtocol::OpenAiResponses, value: v.clone() };
        if let Some(s) = v.as_str() {
            return Self::from_openai_str(s).unwrap_or_else(native);
        }
        match v.get("type").and_then(Value::as_str) {
            // A custom tool is declared as an ordinary function on every other
            // protocol, so forcing it is forcing that function.
            Some("function" | "custom") => v
                .get("name")
                .and_then(Value::as_str)
                .map(|n| Self::Function(n.to_string()))
                .unwrap_or_else(native),
            Some("allowed_tools") => {
                let (names, exhaustive) = function_names(v.get("tools"), |t| {
                    match t.get("type").and_then(Value::as_str) {
                        Some("function" | "custom") => t.get("name"),
                        _ => None,
                    }
                });
                Self::allowlist_required(v.get("mode"))
                    .and_then(|required| Self::allowed(names, required, exhaustive))
                    .unwrap_or_else(native)
            }
            _ => native(),
        }
    }

    /// Parse an Anthropic `tool_choice` into the choice and the parallel switch
    /// it carries (`disable_parallel_tool_use: true` ⇒ `Some(false)`).
    pub fn from_anthropic(v: &Value) -> (Self, Option<bool>) {
        let native = || Self::Native { source: SourceProtocol::Anthropic, value: v.clone() };
        let parallel = v
            .get("disable_parallel_tool_use")
            .and_then(Value::as_bool)
            .map(|disabled| !disabled);
        let choice = match v.get("type").and_then(Value::as_str) {
            Some("auto") => Self::Auto,
            Some("any") => Self::Required,
            Some("none") => Self::None,
            Some("tool") => v
                .get("name")
                .and_then(Value::as_str)
                .map(|n| Self::Function(n.to_string()))
                .unwrap_or_else(native),
            _ => native(),
        };
        (choice, parallel)
    }

    /// Parse a Gemini `toolConfig`. `None` when it carries no function-calling
    /// config at all.
    pub fn from_gemini(cfg: &GeminiToolConfig) -> Option<Self> {
        let fc = cfg.function_calling_config.as_ref()?;
        let native = || Self::Native {
            source: SourceProtocol::Gemini,
            value: serde_json::to_value(fc).unwrap_or(Value::Null),
        };
        let names = fc.allowed_function_names.clone().unwrap_or_default();
        Some(match fc.mode.as_deref().unwrap_or("AUTO") {
            "NONE" => Self::None,
            "ANY" => Self::allowed(names, true, true).unwrap_or(Self::Required),
            // `allowedFunctionNames` is specified for ANY and VALIDATED; under
            // AUTO it is honoured as the narrower reading rather than dropped.
            "AUTO" | "MODE_UNSPECIFIED" => Self::allowed(names, false, true).unwrap_or(Self::Auto),
            // VALIDATED = call or answer, calls constrained-decoded. With names
            // it is "auto among these"; without, the constrained decoding is
            // Gemini's own and has no counterpart elsewhere.
            "VALIDATED" => Self::allowed(names, false, true).unwrap_or_else(native),
            _ => native(),
        })
    }

    /// Whether a [`Self::Native`] choice confined the model to tools only its own
    /// protocol has. Every one does except Gemini's `VALIDATED` with no names,
    /// which is `AUTO` with constrained decoding and restricts no function.
    pub fn confines(&self) -> bool {
        match self {
            Self::Native { source: SourceProtocol::Gemini, value } => !(value.get("mode").and_then(Value::as_str)
                == Some("VALIDATED")
                && value
                    .get("allowedFunctionNames")
                    .and_then(Value::as_array)
                    .is_none_or(Vec::is_empty)),
            Self::Native { .. } => true,
            _ => false,
        }
    }

    /// The function names every target narrows its declared `tools` to. The
    /// declarations say what the model may call in the one grammar every
    /// server reads; a target's own allowlist form, where one is rendered, only
    /// restates it.
    pub fn allowed_names(&self) -> Option<&[String]> {
        match self {
            Self::Allowed { names, .. } => Some(names),
            _ => None,
        }
    }

    /// Render for Chat Completions. An allowlist renders as `required`/`auto`
    /// over a `tools` list the caller narrows with [`Self::allowed_names`]: the
    /// Chat target is every OpenAI-compatible server, and narrowing the declared
    /// list says the same thing in the grammar all of them read.
    pub fn to_chat(&self) -> Option<Value> {
        match self {
            Self::Auto => Some(Value::from("auto")),
            Self::None => Some(Value::from("none")),
            Self::Required | Self::Allowed { required: true, .. } => Some(Value::from("required")),
            Self::Allowed { required: false, .. } => Some(Value::from("auto")),
            Self::Function(n) => Some(serde_json::json!({"type": "function", "function": {"name": n}})),
            Self::Native { source: SourceProtocol::OpenAiChat, value } => Some(value.clone()),
            Self::Native { .. } => self.confines().then(|| Value::from("none")),
        }
    }

    /// Render for Responses (allowlist narrowing as for Chat).
    pub fn to_responses(&self) -> Option<Value> {
        match self {
            Self::Auto => Some(Value::from("auto")),
            Self::None => Some(Value::from("none")),
            Self::Required | Self::Allowed { required: true, .. } => Some(Value::from("required")),
            Self::Allowed { required: false, .. } => Some(Value::from("auto")),
            Self::Function(n) => Some(serde_json::json!({"type": "function", "name": n})),
            Self::Native { source: SourceProtocol::OpenAiResponses, value } => Some(value.clone()),
            Self::Native { .. } => self.confines().then(|| Value::from("none")),
        }
    }

    /// Render for Anthropic Messages, folding the parallel switch into the
    /// choice where Anthropic carries it. `none` is sent as `{type:"none"}` —
    /// omitting it would mean `auto` whenever tools are present. Anthropic has
    /// no allowlist form, so the caller narrows `tools` (see
    /// [`Self::allowed_names`]).
    pub fn to_anthropic(choice: Option<&Self>, parallel: Option<bool>) -> Option<Value> {
        let mut rendered = match choice {
            Some(Self::Auto) => Some(serde_json::json!({"type": "auto"})),
            Some(Self::None) => Some(serde_json::json!({"type": "none"})),
            Some(Self::Required | Self::Allowed { required: true, .. }) => {
                Some(serde_json::json!({"type": "any"}))
            }
            Some(Self::Allowed { required: false, .. }) => Some(serde_json::json!({"type": "auto"})),
            Some(Self::Function(n)) => Some(serde_json::json!({"type": "tool", "name": n})),
            Some(Self::Native { source: SourceProtocol::Anthropic, value }) => Some(value.clone()),
            Some(native @ Self::Native { .. }) => {
                native.confines().then(|| serde_json::json!({"type": "none"}))
            }
            None => None,
        };
        if parallel == Some(false) {
            let obj = rendered.get_or_insert_with(|| serde_json::json!({"type": "auto"}));
            let carries_switch = matches!(
                obj.get("type").and_then(Value::as_str),
                Some("auto" | "any" | "tool")
            );
            if carries_switch && let Some(map) = obj.as_object_mut() {
                map.insert("disable_parallel_tool_use".into(), Value::Bool(true));
            }
        }
        rendered
    }

    /// Render for Gemini, over declarations the caller narrows like every
    /// target. A required allowlist also names its functions on `ANY` —
    /// `allowedFunctionNames` under `ANY` is long-standing Gemini grammar; an
    /// unforced one is plain `AUTO`, never the newer `VALIDATED` mode, which
    /// an older model or a Gemini-compatible server may refuse.
    pub fn to_gemini(&self) -> Option<GeminiToolConfig> {
        let config = |mode: &str, names: Option<Vec<String>>| GeminiToolConfig {
            function_calling_config: Some(GeminiFunctionCallingConfig {
                mode: Some(mode.to_string()),
                allowed_function_names: names,
            }),
        };
        match self {
            Self::Auto => Some(config("AUTO", None)),
            Self::None => Some(config("NONE", None)),
            Self::Required => Some(config("ANY", None)),
            Self::Function(n) => Some(config("ANY", Some(vec![n.clone()]))),
            Self::Allowed { names, required: true } => Some(config("ANY", Some(names.clone()))),
            Self::Allowed { required: false, .. } => Some(config("AUTO", None)),
            Self::Native { source: SourceProtocol::Gemini, value } => serde_json::from_value(value.clone())
                .ok()
                .map(|fc| GeminiToolConfig { function_calling_config: Some(fc) }),
            Self::Native { .. } => self.confines().then(|| config("NONE", None)),
        }
    }

    /// A canonical JSON form for the response cache's identity hash: two
    /// requests meaning the same choice hash alike whichever grammar spelled it.
    pub fn identity(&self) -> Value {
        match self {
            Self::Auto => Value::from("auto"),
            Self::None => Value::from("none"),
            Self::Required => Value::from("required"),
            Self::Function(n) => serde_json::json!({"function": n}),
            Self::Allowed { names, required } => serde_json::json!({"allowed": names, "required": required}),
            Self::Native { source, value } => serde_json::json!({"native": format!("{source:?}"), "value": value}),
        }
    }

    /// The choice for a continuation turn the GATEWAY issues — a substitution
    /// round answering a tool call the gateway executed itself. A forced choice
    /// governed the request whose call has now been made; re-sending it forces
    /// the model to call again on every round until the round cap, the loop
    /// agent frameworks avoid by resetting `tool_choice` after a call. So a
    /// forced choice relaxes to the unforced form of the same allowance (an
    /// allowlist keeps its names), `auto` and `none` are unchanged, and a native
    /// choice — one forcing a hosted/custom tool — drops to the default.
    pub fn for_continuation(self) -> Option<Self> {
        match self {
            Self::Auto | Self::Required | Self::Function(_) => Some(Self::Auto),
            Self::None => Some(Self::None),
            Self::Allowed { names, .. } => Some(Self::Allowed { names, required: false }),
            Self::Native { .. } => None,
        }
    }
}

/// The function names an allowlist names, and whether it named functions and
/// nothing else. A custom, hosted or MCP entry cannot exist on another
/// protocol, so the function names are exactly the client's allowance there;
/// on the client's own protocol a hosted tool is never narrowed away (see
/// `DomainRequest::tool_is_allowed`).
fn function_names(tools: Option<&Value>, name_of: impl Fn(&Value) -> Option<&Value>) -> (Vec<String>, bool) {
    let entries = tools.and_then(Value::as_array).map(Vec::as_slice).unwrap_or_default();
    let names: Vec<String> = entries
        .iter()
        .filter_map(|t| name_of(t).and_then(Value::as_str).map(str::to_string))
        .collect();
    let exhaustive = names.len() == entries.len();
    (names, exhaustive)
}

/// The allowlist object of an `allowed_tools` wire choice — Chat nests it under
/// `allowed_tools`, Responses keeps it flat — holding `mode` and `tools`.
/// `None` for any other choice. The one reader of that grammar: every rewrite
/// of a wire choice (relaxing, following a rename, retiring a removed tool)
/// goes through here, so a new shape is taught in one place.
pub(crate) fn allowlist_spec_mut(choice: &mut Value, protocol: ApiVersion) -> Option<&mut serde_json::Map<String, Value>> {
    if choice.get("type").and_then(Value::as_str) != Some("allowed_tools") {
        return None;
    }
    match protocol {
        ApiVersion::ChatCompletions => choice.get_mut("allowed_tools")?.as_object_mut(),
        ApiVersion::Responses => choice.as_object_mut(),
        _ => None,
    }
}

/// The tool a wire choice (or an allowlist entry) names, in any protocol's
/// grammar: Chat `{type:function, function:{name}}`, Responses
/// `{type:function, name}`, Anthropic `{type:tool, name}`, and a custom tool on
/// either OpenAI protocol.
pub(crate) fn wire_choice_name(entry: &Value) -> Option<&str> {
    match entry.get("type").and_then(Value::as_str)? {
        "function" | "custom" | "tool" => entry
            .get("name")
            .or_else(|| entry.get("function").and_then(|f| f.get("name")))
            .or_else(|| entry.get("custom").and_then(|c| c.get("name")))
            .and_then(Value::as_str),
        _ => None,
    }
}

/// The client's OWN `tool_choice`, relaxed for a continuation the gateway
/// issues, in the client's own grammar. A same-protocol round restores the
/// client's body — its `tools` included, un-narrowed — so the allowance must
/// stay in the choice itself: a forced call (a named function, a custom or
/// hosted tool, `required`, Anthropic `any` / `tool`) becomes `auto`, an
/// allowlist keeps its entries under mode `auto`, and Anthropic's parallel
/// switch rides the relaxed choice. What forces nothing is returned unchanged.
/// The domain's counterpart is [`DomainToolChoice::for_continuation`].
pub fn relax_wire_for_continuation(protocol: ApiVersion, v: &Value) -> Value {
    let auto = || Value::from("auto");
    match protocol {
        ApiVersion::ChatCompletions | ApiVersion::Responses => {
            // `any` is Mistral's Chat spelling of `required` (`from_chat`).
            if matches!((protocol, v.as_str()), (_, Some("required")) | (ApiVersion::ChatCompletions, Some("any"))) {
                return auto();
            }
            match v.get("type").and_then(Value::as_str) {
                Some("allowed_tools") => {
                    let mut relaxed = v.clone();
                    if let Some(spec) = allowlist_spec_mut(&mut relaxed, protocol) {
                        spec.insert("mode".into(), auto());
                    }
                    relaxed
                }
                // Any other object names one tool to force.
                Some(_) => auto(),
                None => v.clone(),
            }
        }
        ApiVersion::AnthropicMessages => match v.get("type").and_then(Value::as_str) {
            Some("any" | "tool") => {
                let mut relaxed = serde_json::json!({"type": "auto"});
                if let Some(switch) = v.get("disable_parallel_tool_use") {
                    relaxed["disable_parallel_tool_use"] = switch.clone();
                }
                relaxed
            }
            _ => v.clone(),
        },
        // A Gemini round is always rendered from the domain.
        ApiVersion::GoogleGemini => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use serde_json::json;

    fn gemini(mode: &str, names: Option<&[&str]>) -> GeminiToolConfig {
        GeminiToolConfig {
            function_calling_config: Some(GeminiFunctionCallingConfig {
                mode: Some(mode.to_string()),
                allowed_function_names: names.map(|n| n.iter().map(|s| s.to_string()).collect()),
            }),
        }
    }

    fn fc(cfg: &GeminiToolConfig) -> (String, Option<Vec<String>>) {
        let f = cfg.function_calling_config.as_ref().unwrap();
        (f.mode.clone().unwrap(), f.allowed_function_names.clone())
    }

    // ── Parsing: each protocol's own grammar ────────────────────────────────

    /// The three strings both OpenAI protocols share are the domain's own
    /// modes, never an opaque value that another target would omit.
    #[test]
    fn the_shared_openai_strings_are_domain_modes_on_both_protocols() {
        for (s, mode) in [
            ("auto", DomainToolChoice::Auto),
            ("none", DomainToolChoice::None),
            ("required", DomainToolChoice::Required),
        ] {
            assert_eq!(DomainToolChoice::from_chat(&json!(s)), mode, "chat {s}");
            assert_eq!(DomainToolChoice::from_responses(&json!(s)), mode, "responses {s}");
        }
        // An explicit `auto` is carried as one, not dropped as foreign.
        assert_eq!(
            DomainToolChoice::to_anthropic(Some(&DomainToolChoice::from_chat(&json!("auto"))), None),
            Some(json!({"type": "auto"}))
        );
    }

    #[test]
    fn a_responses_named_function_is_a_forced_function() {
        let c = DomainToolChoice::from_responses(&json!({"type": "function", "name": "get_weather"}));
        assert_eq!(c, DomainToolChoice::Function("get_weather".into()));
    }

    #[test]
    fn a_chat_named_function_is_a_forced_function() {
        let c = DomainToolChoice::from_chat(&json!({"type": "function", "function": {"name": "get_weather"}}));
        assert_eq!(c, DomainToolChoice::Function("get_weather".into()));
    }

    /// Mistral's Chat Completions enum is `auto | none | any | required`, `any`
    /// meaning `required`. Read as anything else it would reach Anthropic and
    /// Gemini as an unknown choice — "call nothing" — a forced call turned
    /// into no call. `any` is Chat's only: Responses has no such word.
    #[test]
    fn mistrals_any_is_required_and_reaches_every_target_as_a_forced_call() {
        let c = DomainToolChoice::from_chat(&json!("any"));
        assert_eq!(c, DomainToolChoice::Required);
        assert_eq!(c.to_chat(), Some(json!("required")));
        assert_eq!(c.to_responses(), Some(json!("required")));
        assert_eq!(DomainToolChoice::to_anthropic(Some(&c), None), Some(json!({"type": "any"})));
        assert_eq!(fc(&c.to_gemini().unwrap()), ("ANY".into(), None));
        assert_ne!(DomainToolChoice::from_responses(&json!("any")), DomainToolChoice::Required);
        // A round the gateway continues relaxes it as it relaxes `required`,
        // or every round is forced to call again until the round cap.
        assert_eq!(relax_wire_for_continuation(ApiVersion::ChatCompletions, &json!("any")), json!("auto"));
        assert_eq!(relax_wire_for_continuation(ApiVersion::ChatCompletions, &json!("none")), json!("none"));
    }

    #[test]
    fn each_openai_allowlist_grammar_parses_to_the_same_allowlist() {
        let chat = DomainToolChoice::from_chat(&json!({
            "type": "allowed_tools",
            "allowed_tools": {"mode": "required", "tools": [
                {"type": "function", "function": {"name": "a"}},
                {"type": "function", "function": {"name": "b"}},
            ]}
        }));
        let responses = DomainToolChoice::from_responses(&json!({
            "type": "allowed_tools", "mode": "required",
            "tools": [{"type": "function", "name": "a"}, {"type": "function", "name": "b"}]
        }));
        let expected = DomainToolChoice::Allowed { names: vec!["a".into(), "b".into()], required: true };
        assert_eq!(chat, expected);
        assert_eq!(responses, expected);
    }

    /// A non-function entry (MCP, hosted, custom) cannot exist on another
    /// protocol, so the allowance there is its function names — never "all".
    #[test]
    fn an_allowlist_keeps_its_function_names_and_never_widens() {
        let c = DomainToolChoice::from_responses(&json!({
            "type": "allowed_tools", "mode": "auto",
            "tools": [{"type": "mcp", "server_label": "deepwiki"}, {"type": "function", "name": "a"},
                      {"type": "function", "name": "b"}]
        }));
        assert_eq!(c, DomainToolChoice::Allowed { names: vec!["a".into(), "b".into()], required: false });
        // With no function in it there is nothing representable: it stays native.
        let only_hosted = json!({"type": "allowed_tools", "mode": "auto", "tools": [{"type": "image_generation"}]});
        assert!(matches!(DomainToolChoice::from_responses(&only_hosted), DomainToolChoice::Native { .. }));
    }

    /// An allowlist that also allowed a hosted/MCP tool let the model pick it:
    /// its single function is NOT a forced call.
    #[test]
    fn a_mixed_allowlist_never_collapses_into_a_forced_function() {
        let c = DomainToolChoice::from_responses(&json!({
            "type": "allowed_tools", "mode": "required",
            "tools": [{"type": "mcp", "server_label": "x"}, {"type": "function", "name": "a"}]
        }));
        assert_eq!(c, DomainToolChoice::Allowed { names: vec!["a".into()], required: true });
        // Positive control: a list of that one function alone IS a forced call.
        let only = DomainToolChoice::from_responses(&json!({
            "type": "allowed_tools", "mode": "required", "tools": [{"type": "function", "name": "a"}]
        }));
        assert_eq!(only, DomainToolChoice::Function("a".into()));
        // …and the same one-function list in `auto` mode forces nothing: the
        // model may still answer without calling it.
        let optional = DomainToolChoice::from_responses(&json!({
            "type": "allowed_tools", "mode": "auto", "tools": [{"type": "function", "name": "a"}]
        }));
        assert_eq!(optional, DomainToolChoice::Allowed { names: vec!["a".into()], required: false });
    }

    #[test]
    fn a_continuation_relaxes_the_clients_own_choice_in_its_own_grammar() {
        use ApiVersion as V;
        assert_eq!(relax_wire_for_continuation(V::ChatCompletions, &json!("required")), json!("auto"));
        assert_eq!(
            relax_wire_for_continuation(V::ChatCompletions, &json!({"type": "function", "function": {"name": "f"}})),
            json!("auto")
        );
        // An allowlist keeps its entries — the round's tools are the client's, un-narrowed.
        assert_eq!(
            relax_wire_for_continuation(V::ChatCompletions, &json!({"type": "allowed_tools",
                "allowed_tools": {"mode": "required", "tools": [{"type": "function", "function": {"name": "a"}}]}})),
            json!({"type": "allowed_tools", "allowed_tools": {"mode": "auto",
                "tools": [{"type": "function", "function": {"name": "a"}}]}})
        );
        assert_eq!(
            relax_wire_for_continuation(V::Responses, &json!({"type": "allowed_tools", "mode": "required",
                "tools": [{"type": "function", "name": "a"}]})),
            json!({"type": "allowed_tools", "mode": "auto", "tools": [{"type": "function", "name": "a"}]})
        );
        assert_eq!(relax_wire_for_continuation(V::Responses, &json!({"type": "web_search_preview"})), json!("auto"));
        assert_eq!(
            relax_wire_for_continuation(V::AnthropicMessages, &json!({"type": "tool", "name": "t", "disable_parallel_tool_use": true})),
            json!({"type": "auto", "disable_parallel_tool_use": true})
        );
        // What forces nothing is kept exactly.
        for (v, choice) in [(V::ChatCompletions, json!("none")), (V::Responses, json!("auto")),
                            (V::AnthropicMessages, json!({"type": "none"}))] {
            assert_eq!(relax_wire_for_continuation(v, &choice), choice);
        }
    }

    /// A choice forcing a tool only Responses has is verbatim there and "call
    /// nothing" on Chat, which has no such tool: omitting it would let the
    /// model call any declared function.
    #[test]
    fn a_hosted_choice_stays_native_to_its_protocol() {
        for v in [json!({"type": "web_search_preview"}), json!({"type": "mcp", "server_label": "x"}),
                  json!({"type": "shell"})] {
            let c = DomainToolChoice::from_responses(&v);
            assert_eq!(c, DomainToolChoice::Native { source: SourceProtocol::OpenAiResponses, value: v.clone() });
            assert_eq!(c.to_responses(), Some(v), "verbatim for its own protocol");
            assert_eq!(c.to_chat(), Some(json!("none")), "no counterpart elsewhere");
        }
    }

    #[test]
    fn anthropic_choices_and_their_parallel_switch_parse() {
        assert_eq!(DomainToolChoice::from_anthropic(&json!({"type": "auto"})), (DomainToolChoice::Auto, None));
        assert_eq!(DomainToolChoice::from_anthropic(&json!({"type": "any"})).0, DomainToolChoice::Required);
        assert_eq!(DomainToolChoice::from_anthropic(&json!({"type": "none"})).0, DomainToolChoice::None);
        assert_eq!(
            DomainToolChoice::from_anthropic(&json!({"type": "tool", "name": "t", "disable_parallel_tool_use": true})),
            (DomainToolChoice::Function("t".into()), Some(false))
        );
        assert_eq!(
            DomainToolChoice::from_anthropic(&json!({"type": "any", "disable_parallel_tool_use": false})).1,
            Some(true)
        );
    }

    #[test]
    fn gemini_modes_and_allowed_names_parse() {
        assert_eq!(DomainToolChoice::from_gemini(&gemini("AUTO", None)), Some(DomainToolChoice::Auto));
        assert_eq!(DomainToolChoice::from_gemini(&gemini("NONE", None)), Some(DomainToolChoice::None));
        assert_eq!(DomainToolChoice::from_gemini(&gemini("ANY", None)), Some(DomainToolChoice::Required));
        assert_eq!(
            DomainToolChoice::from_gemini(&gemini("ANY", Some(&["a"]))),
            Some(DomainToolChoice::Function("a".into()))
        );
        assert_eq!(
            DomainToolChoice::from_gemini(&gemini("ANY", Some(&["a", "b"]))),
            Some(DomainToolChoice::Allowed { names: vec!["a".into(), "b".into()], required: true })
        );
        assert_eq!(
            DomainToolChoice::from_gemini(&gemini("VALIDATED", Some(&["a", "b"]))),
            Some(DomainToolChoice::Allowed { names: vec!["a".into(), "b".into()], required: false })
        );
        assert!(matches!(
            DomainToolChoice::from_gemini(&gemini("VALIDATED", None)),
            Some(DomainToolChoice::Native { source: SourceProtocol::Gemini, .. })
        ));
        assert_eq!(DomainToolChoice::from_gemini(&GeminiToolConfig { function_calling_config: None }), None);
    }

    // ── Rendering: the spec's shape per target ──────────────────────────────

    #[test]
    fn a_forced_function_renders_in_each_targets_own_shape() {
        let c = DomainToolChoice::Function("f".into());
        assert_eq!(c.to_chat(), Some(json!({"type": "function", "function": {"name": "f"}})));
        assert_eq!(c.to_responses(), Some(json!({"type": "function", "name": "f"})));
        assert_eq!(DomainToolChoice::to_anthropic(Some(&c), None), Some(json!({"type": "tool", "name": "f"})));
        assert_eq!(fc(&c.to_gemini().unwrap()), ("ANY".into(), Some(vec!["f".into()])));
    }

    /// Omitting `tool_choice` on Anthropic means `auto` when tools are present,
    /// so a client's "no tool" must travel as the spec's `{type:"none"}`.
    #[test]
    fn none_is_sent_to_anthropic_not_dropped() {
        assert_eq!(
            DomainToolChoice::to_anthropic(Some(&DomainToolChoice::None), None),
            Some(json!({"type": "none"}))
        );
        assert_eq!(DomainToolChoice::None.to_chat(), Some(json!("none")));
        assert_eq!(fc(&DomainToolChoice::None.to_gemini().unwrap()), ("NONE".into(), None));
    }

    #[test]
    fn required_renders_as_each_targets_must_call_form() {
        let c = DomainToolChoice::Required;
        assert_eq!(c.to_chat(), Some(json!("required")));
        assert_eq!(c.to_responses(), Some(json!("required")));
        assert_eq!(DomainToolChoice::to_anthropic(Some(&c), None), Some(json!({"type": "any"})));
        assert_eq!(fc(&c.to_gemini().unwrap()), ("ANY".into(), None));
    }

    #[test]
    fn an_allowlist_narrows_every_target_and_a_forced_one_names_itself_on_gemini() {
        let c = DomainToolChoice::Allowed { names: vec!["a".into(), "b".into()], required: false };
        // Never the newer VALIDATED mode: plain AUTO over narrowed declarations.
        assert_eq!(fc(&c.to_gemini().unwrap()), ("AUTO".into(), None));
        assert_eq!(c.to_chat(), Some(json!("auto")));
        assert_eq!(c.allowed_names(), Some(&["a".to_string(), "b".to_string()][..]));
        let required = DomainToolChoice::Allowed { names: vec!["a".into(), "b".into()], required: true };
        assert_eq!(fc(&required.to_gemini().unwrap()), ("ANY".into(), Some(vec!["a".into(), "b".into()])));
        assert_eq!(DomainToolChoice::to_anthropic(Some(&required), None), Some(json!({"type": "any"})));
    }

    #[test]
    fn a_disabled_parallel_switch_rides_inside_the_anthropic_choice() {
        assert_eq!(
            DomainToolChoice::to_anthropic(Some(&DomainToolChoice::Required), Some(false)),
            Some(json!({"type": "any", "disable_parallel_tool_use": true}))
        );
        // With no choice set, the switch still needs a carrier: `auto`.
        assert_eq!(
            DomainToolChoice::to_anthropic(None, Some(false)),
            Some(json!({"type": "auto", "disable_parallel_tool_use": true}))
        );
        // `none` has no switch — there is nothing to parallelise.
        assert_eq!(
            DomainToolChoice::to_anthropic(Some(&DomainToolChoice::None), Some(false)),
            Some(json!({"type": "none"}))
        );
        // Positive control: parallel allowed (the default) adds nothing.
        assert_eq!(DomainToolChoice::to_anthropic(Some(&DomainToolChoice::Auto), Some(true)), Some(json!({"type": "auto"})));
        assert_eq!(DomainToolChoice::to_anthropic(None, None), None);
    }

    #[test]
    fn the_identity_is_the_meaning_not_the_spelling() {
        let chat = DomainToolChoice::from_chat(&json!({"type": "function", "function": {"name": "f"}}));
        let responses = DomainToolChoice::from_responses(&json!({"type": "function", "name": "f"}));
        let anthropic = DomainToolChoice::from_anthropic(&json!({"type": "tool", "name": "f"})).0;
        assert_eq!(chat.identity(), responses.identity());
        assert_eq!(chat.identity(), anthropic.identity());
        assert_ne!(chat.identity(), DomainToolChoice::Function("g".into()).identity());
    }

    #[test]
    fn a_continuation_never_re_forces_a_call() {
        use DomainToolChoice as C;
        assert_eq!(C::Required.for_continuation(), Some(C::Auto));
        assert_eq!(C::Function("f".into()).for_continuation(), Some(C::Auto));
        assert_eq!(
            C::Allowed { names: vec!["a".into(), "b".into()], required: true }.for_continuation(),
            Some(C::Allowed { names: vec!["a".into(), "b".into()], required: false })
        );
        assert_eq!(
            C::Native { source: SourceProtocol::OpenAiResponses, value: json!({"type": "web_search_preview"}) }
                .for_continuation(),
            None
        );
        // What forces nothing is kept exactly — `none` still forbids tools.
        assert_eq!(C::None.for_continuation(), Some(C::None));
        assert_eq!(C::Auto.for_continuation(), Some(C::Auto));
    }

    /// On a foreign target a native choice that confined the model to tools
    /// that target lacks becomes "call nothing"; one that restricted no
    /// function (Gemini `VALIDATED` without names) is omitted. On its own
    /// protocol either is verbatim.
    #[test]
    fn a_native_choice_never_widens_on_another_protocol() {
        use DomainToolChoice as C;
        let hosted = C::from_responses(&json!({"type": "web_search_preview"}));
        let only_hosted = C::from_responses(&json!({"type": "allowed_tools", "mode": "required", "tools": [{"type": "mcp", "server_label": "x"}]}));
        for confining in [&hosted, &only_hosted] {
            assert!(confining.confines(), "{confining:?}");
            assert_eq!(C::to_anthropic(Some(confining), Some(false)), Some(json!({"type": "none"})));
            assert_eq!(fc(&confining.to_gemini().unwrap()), ("NONE".to_string(), None));
        }
        assert_eq!(hosted.to_chat(), Some(json!("none")));
        assert_eq!(hosted.to_responses(), Some(json!({"type": "web_search_preview"})), "verbatim at home");
        // A Chat custom tool is carried by name, so forcing it forces that
        // tool; where it is not declared the request renders "call nothing".
        assert_eq!(C::from_chat(&json!({"type": "custom", "custom": {"name": "grammar_tool"}})), C::Function("grammar_tool".into()));

        let validated = C::from_gemini(&gemini("VALIDATED", None)).unwrap();
        assert!(!validated.confines());
        assert_eq!(validated.to_chat(), None);
        assert_eq!(validated.to_responses(), None);
        assert_eq!(C::to_anthropic(Some(&validated), None), None);
        assert_eq!(fc(&validated.to_gemini().unwrap()), ("VALIDATED".to_string(), None), "verbatim at home");
    }

    /// A Responses custom tool is declared as a function on every other
    /// protocol: forcing it forces that function, and an allowlist keeps it.
    #[test]
    fn a_responses_custom_tool_choice_is_a_function_elsewhere() {
        use DomainToolChoice as C;
        assert_eq!(C::from_responses(&json!({"type": "custom", "name": "apply_patch"})), C::Function("apply_patch".into()));
        let allowed = C::from_responses(&json!({
            "type": "allowed_tools", "mode": "required",
            "tools": [{"type": "custom", "name": "apply_patch"}, {"type": "function", "name": "shell"}]
        }));
        assert_eq!(allowed, C::Allowed { names: vec!["apply_patch".into(), "shell".into()], required: true });
    }

    // ── Property: no rendering widens the client's choice ──────────────────

    fn choice() -> impl Strategy<Value = DomainToolChoice> {
        let name = "[a-z]{1,6}";
        prop_oneof![
            Just(DomainToolChoice::Auto),
            Just(DomainToolChoice::None),
            Just(DomainToolChoice::Required),
            name.prop_map(DomainToolChoice::Function),
            (proptest::collection::vec(name, 2..5), any::<bool>())
                .prop_map(|(names, required)| DomainToolChoice::Allowed { names, required }),
        ]
    }

    /// What a rendered choice lets the model do, read back through the TARGET's
    /// own grammar: (must not call, must call, callable names or None = any).
    type Allowance = (bool, bool, Option<Vec<String>>);

    fn allowance(c: &DomainToolChoice) -> Allowance {
        match c {
            DomainToolChoice::Auto => (false, false, None),
            DomainToolChoice::None => (true, false, None),
            DomainToolChoice::Required => (false, true, None),
            DomainToolChoice::Function(n) => (false, true, Some(vec![n.clone()])),
            DomainToolChoice::Allowed { names, required } => (false, *required, Some(names.clone())),
            DomainToolChoice::Native { .. } => unreachable!("not generated"),
        }
    }

    fn narrowed(c: &DomainToolChoice, target_names: Option<Vec<String>>) -> Option<Vec<String>> {
        target_names.or_else(|| c.allowed_names().map(<[String]>::to_vec))
    }

    proptest! {
        #[test]
        fn no_target_ever_widens_the_client_choice(c in choice()) {
            let want = allowance(&c);

            // Chat: a forced name is in the choice, an allowlist in the narrowed tools.
            let chat = c.to_chat().unwrap();
            let chat_names = chat.get("function").and_then(|f| f.get("name")).and_then(Value::as_str)
                .map(|n| vec![n.to_string()]);
            let got = (chat == json!("none"), chat == json!("required") || chat_names.is_some(), narrowed(&c, chat_names));
            prop_assert_eq!(&got, &want, "chat rendered {}", chat);

            // Responses: the same, flat.
            let resp = c.to_responses().unwrap();
            let resp_names = resp.get("name").and_then(Value::as_str).map(|n| vec![n.to_string()]);
            let got = (resp == json!("none"), resp == json!("required") || resp_names.is_some(), narrowed(&c, resp_names));
            prop_assert_eq!(&got, &want, "responses rendered {}", resp);

            // Anthropic: `any`/`tool` force a call, `tool` names it.
            let anth = DomainToolChoice::to_anthropic(Some(&c), None).unwrap();
            let kind = anth["type"].as_str().unwrap().to_string();
            let anth_names = anth.get("name").and_then(Value::as_str).map(|n| vec![n.to_string()]);
            let got = (kind == "none", kind == "any" || kind == "tool", narrowed(&c, anth_names));
            prop_assert_eq!(&got, &want, "anthropic rendered {}", anth);

            // Gemini: narrowed declarations, a forced allowlist also named on ANY.
            let (mode, names) = fc(&c.to_gemini().unwrap());
            let got = (mode == "NONE", mode == "ANY", narrowed(&c, names));
            prop_assert_eq!(&got, &want, "gemini rendered {}", mode);
        }
    }
}
