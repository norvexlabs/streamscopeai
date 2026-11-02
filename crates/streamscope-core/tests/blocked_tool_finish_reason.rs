//! One property over the four wires: **a response never claims a tool call it
//! does not carry.**
//!
//! A finish reason is not decoration, it is a promise about the content.
//! Anthropic documents `stop_reason: "tool_use"` as "one or more `tool_use`
//! blocks" that the caller executes and answers with a `tool_result`; OpenAI's
//! `finish_reason: "tool_calls"` says the same thing. Response-phase tool policy
//! deletes tool calls out of an already-finished response, so it is the one
//! thing in the pipeline that can falsify that promise — and it does so
//! silently: the body still parses, the audit row still renders, and the only
//! visible symptom is at the client, which is handed a turn it cannot act on.
//! Claude Code discards the whole message, operator block notice included, and
//! spends a round trip retrying.
//!
//! Examples cannot hold this. The defect is per-wire and per-suppression-path,
//! so the case that breaks it is whichever combination nobody wrote down: the
//! second of two calls blocked rather than the first, every call blocked on the
//! wire whose settle was forgotten, a finish reason that was never about tools
//! in the first place. The generator walks those on purpose.
//!
//! Three claims, and the second is what stops the first being satisfied by
//! always answering "stop":
//!
//! 1. **No blocked call survives** — policy actually removed what it matched.
//! 2. **The claim holds iff a call does** — a tool-call finish reason is present
//!    exactly when at least one tool call is still in the content.
//! 3. **Nothing is silently discarded** — every removal leaves a notice in the
//!    content, on every wire.
//!
//! What is deliberately NOT asserted, because the code does not claim it:
//!
//! * **Which value replaces the retracted claim, beyond it not being a tool-call
//!   one.** `stop` / `end_turn` is pinned by example in `response_blocks.rs`;
//!   restating the mapping here would be the implementation written twice.
//! * **A finish reason the settle does not own.** `length` / `max_tokens` are
//!   asserted unchanged (claim 2 covers it), not re-derived.
//! * **Gemini or Responses carrying a settled finish reason.** Neither wire has
//!   a finish value meaning "the model called a function" — Gemini reads a call
//!   from the parts, the Responses API states completion in `status` — so there
//!   is nothing there to retract, and asserting one would invent a vocabulary
//!   the wire does not have. What IS asserted for those two is that the field
//!   comes back untouched.
//! * **An upstream that arrived self-contradictory.** A `finish_reason:
//!   "tool_calls"` with an empty tool-call list is an upstream defect, not one
//!   this pass created; the generator therefore always produces at least one
//!   call. The claim here is that a consistent response stays consistent.

use proptest::prelude::*;
use serde_json::{json, Value};
use streamscope_core::api::sse::ApiVersion;
use streamscope_core::config::tool_rules::{FieldProfile, FieldProfileSet, Rule};
use streamscope_core::config::tool_rules_normalize::Normalizer;
use streamscope_core::pipeline::response_blocks::apply_response_policy_json;

/// The command a generated call runs. `BLOCKED` is what the rule below matches;
/// anything else must survive untouched.
const BLOCKED: &str = "rm -rf /";
const ALLOWED: &str = "ls -la";

fn profiles() -> FieldProfileSet {
    FieldProfileSet::new(vec![FieldProfile {
        id: Some("prop-Bash".into()),
        description: None,
        source: None,
        tool_id: "shell_exec".into(),
        tool_pattern: "Bash".into(),
        app_filter: None,
        mcp_server: None,
        server_type: None,
        field: "command".into(),
        wire_field: None,
        normalizer: Normalizer::Raw,
        priority: 100,
        is_builtin: false,
    }])
}

fn block_rule() -> Vec<Rule> {
    vec![
        serde_json::from_value(json!({
            "id": "T-80",
            "phase": "response",
            "scope": "tool_calls",
            "match": [
                { "target": "tool_id", "op": "equals", "value": "shell_exec" },
                { "target": "arg.command", "op": "contains_any", "value": [BLOCKED] }
            ],
            "action": { "kind": "block" },
            "risk": "danger"
        }))
        .expect("rule JSON must deserialize"),
    ]
}

fn command_of(blocked: bool) -> &'static str {
    if blocked { BLOCKED } else { ALLOWED }
}

/// Build the upstream response each wire would have produced for `mask`, where
/// `mask[i] == true` means call `i` runs the command the rule blocks.
/// `tool_claim` decides whether the wire's finish reason claims a tool call at
/// all — false generates the "stopped for an unrelated reason" case.
fn response_for(wire: ApiVersion, mask: &[bool], tool_claim: bool) -> Value {
    match wire {
        ApiVersion::ChatCompletions => json!({
            "choices": [{
                "finish_reason": if tool_claim { "tool_calls" } else { "length" },
                "message": {
                    "content": "",
                    "tool_calls": mask.iter().enumerate().map(|(i, b)| json!({
                        "id": format!("c{i}"),
                        "type": "function",
                        "function": {
                            "name": "Bash",
                            "arguments": json!({"command": command_of(*b)}).to_string(),
                        }
                    })).collect::<Vec<_>>()
                }
            }]
        }),
        ApiVersion::AnthropicMessages => json!({
            "id": "msg_1", "type": "message", "role": "assistant",
            "stop_reason": if tool_claim { "tool_use" } else { "max_tokens" },
            "content": mask.iter().enumerate().map(|(i, b)| json!({
                "type": "tool_use",
                "id": format!("tu{i}"),
                "name": "Bash",
                "input": {"command": command_of(*b)}
            })).collect::<Vec<_>>()
        }),
        ApiVersion::Responses => json!({
            "id": "resp_1",
            "status": "completed",
            "output": mask.iter().enumerate().map(|(i, b)| json!({
                "type": "function_call",
                "id": format!("fc{i}"),
                "call_id": format!("fc{i}"),
                "name": "Bash",
                "arguments": json!({"command": command_of(*b)}).to_string(),
            })).collect::<Vec<_>>()
        }),
        ApiVersion::GoogleGemini => json!({
            "candidates": [{
                "finishReason": "STOP",
                "content": {"parts": mask.iter().map(|b| json!({
                    "functionCall": {"name": "Bash", "args": {"command": command_of(*b)}}
                })).collect::<Vec<_>>()}
            }]
        }),
    }
}

/// The commands still reachable by a client after the policy pass, and whether
/// the response's finish reason still claims a tool call.
struct Delivered {
    commands: Vec<String>,
    /// `Some` only on the wires that have a finish value meaning "a tool was
    /// called" — Chat Completions and Anthropic Messages. `None` says the wire
    /// has no such vocabulary, which is a different fact from "it claims
    /// nothing", and collapsing the two would let a missing settle read as a
    /// wire that never needed one.
    claims_tool_call: Option<bool>,
    /// The finish/status field verbatim, so the wires with no claim to retract
    /// can be asserted untouched rather than tautologically.
    finish_field: String,
    text: String,
}

fn read_back(wire: ApiVersion, response: &Value) -> Delivered {
    let arguments_command = |args: &Value| -> String {
        args.as_str()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .unwrap_or_else(|| args.clone())
            .get("command")
            .and_then(|c| c.as_str())
            .unwrap_or_default()
            .to_string()
    };
    match wire {
        ApiVersion::ChatCompletions => {
            let choice = &response["choices"][0];
            Delivered {
                commands: choice["message"]["tool_calls"]
                    .as_array()
                    .map(|a| {
                        a.iter()
                            .map(|tc| arguments_command(&tc["function"]["arguments"]))
                            .collect()
                    })
                    .unwrap_or_default(),
                claims_tool_call: Some(choice["finish_reason"] == "tool_calls"),
                finish_field: choice["finish_reason"].as_str().unwrap_or("").to_string(),
                text: choice["message"]["content"].as_str().unwrap_or("").to_string(),
            }
        }
        ApiVersion::AnthropicMessages => {
            let content = response["content"].as_array().cloned().unwrap_or_default();
            Delivered {
                commands: content
                    .iter()
                    .filter(|b| b["type"] == "tool_use")
                    .map(|b| arguments_command(&b["input"]))
                    .collect(),
                claims_tool_call: Some(response["stop_reason"] == "tool_use"),
                finish_field: response["stop_reason"].as_str().unwrap_or("").to_string(),
                text: content
                    .iter()
                    .filter_map(|b| b["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            }
        }
        ApiVersion::Responses => {
            let output = response["output"].as_array().cloned().unwrap_or_default();
            Delivered {
                commands: output
                    .iter()
                    .filter(|i| i["type"] == "function_call")
                    .map(|i| arguments_command(&i["arguments"]))
                    .collect(),
                claims_tool_call: None,
                finish_field: response["status"].as_str().unwrap_or("").to_string(),
                text: output
                    .iter()
                    .filter(|i| i["type"] == "message")
                    .flat_map(|i| i["content"].as_array().cloned().unwrap_or_default())
                    .filter_map(|c| c["text"].as_str().map(str::to_string))
                    .collect::<Vec<_>>()
                    .join("\n"),
            }
        }
        ApiVersion::GoogleGemini => {
            let parts = response["candidates"][0]["content"]["parts"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            Delivered {
                commands: parts
                    .iter()
                    .filter(|p| p.get("functionCall").is_some())
                    .map(|p| arguments_command(&p["functionCall"]["args"]))
                    .collect(),
                claims_tool_call: None,
                finish_field: response["candidates"][0]["finishReason"]
                    .as_str().unwrap_or("").to_string(),
                text: parts
                    .iter()
                    .filter_map(|p| p["text"].as_str())
                    .collect::<Vec<_>>()
                    .join("\n"),
            }
        }
    }
}

const WIRES: [ApiVersion; 4] = [
    ApiVersion::ChatCompletions,
    ApiVersion::AnthropicMessages,
    ApiVersion::Responses,
    ApiVersion::GoogleGemini,
];

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    /// The three claims, on every wire, for every mix of blocked and allowed
    /// calls — all-blocked, none-blocked, and every arrangement between.
    #[test]
    fn a_response_never_claims_a_tool_call_it_does_not_carry(
        mask in prop::collection::vec(any::<bool>(), 1..5),
        tool_claim in any::<bool>(),
    ) {
        for wire in WIRES {
            let mut response = response_for(wire, &mask, tool_claim);
            let (blocked, _, _) = apply_response_policy_json(
                &mut response, wire, &block_rule(), &profiles(), None, None, &[],
            );

            let expected_blocked = mask.iter().filter(|b| **b).count();
            prop_assert_eq!(
                blocked.len(), expected_blocked,
                "{:?}: policy matched the wrong number of calls in {}", wire, response
            );

            let got = read_back(wire, &response);

            // 1. No blocked call survives.
            prop_assert!(
                !got.commands.iter().any(|c| c == BLOCKED),
                "{:?}: a blocked command reached the client in {}", wire, response
            );
            prop_assert_eq!(
                got.commands.len(), mask.len() - expected_blocked,
                "{:?}: an allowed call was removed too in {}", wire, response
            );

            // 2. The claim holds iff a call does. This is the whole defect: a
            //    tool-call finish reason surviving an emptied response. On the
            //    two wires with no such vocabulary, the field is asserted
            //    untouched instead — inventing one would be the mirror bug.
            let survivors = !got.commands.is_empty();
            match got.claims_tool_call {
                Some(claims) => prop_assert_eq!(
                    claims, survivors && tool_claim,
                    "{:?}: finish reason and content disagree in {}", wire, response
                ),
                None => {
                    let untouched = read_back(wire, &response_for(wire, &mask, tool_claim));
                    prop_assert_eq!(
                        got.finish_field.as_str(), untouched.finish_field.as_str(),
                        "{:?}: a wire with no tool-call finish value had one settled in {}",
                        wire, response
                    );
                }
            }

            // 3. Nothing is silently discarded.
            if expected_blocked > 0 {
                prop_assert!(
                    got.text.contains("blocked by policy"),
                    "{:?}: {} call(s) vanished with no notice in {}",
                    wire, expected_blocked, response
                );
            }
        }
    }
}
