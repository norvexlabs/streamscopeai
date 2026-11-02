//! Properties of the protocol walks' system channel, not examples of them.
//!
//! Every target protocol has exactly ONE system channel and renders it at the
//! front: Anthropic's `system`, Gemini's `systemInstruction`, the leading Chat
//! Completions `system` message, the Responses `instructions`. A client can put
//! system-class content somewhere else — Claude Code sends a `role:"system"`
//! message *inside* the Anthropic messages array, for its Skill catalog and for
//! mid-conversation notes — and the strict Jinja chat templates vLLM renders
//! reject a `system` message that follows conversational content outright:
//! `raise_exception('System message must be at the beginning.')`.
//!
//! So the walk has to fold, and the shape that breaks a fold is never the one
//! someone wrote a case for: an empty System, a run of them, one at the very end,
//! a conversation that is nothing *but* system messages. The generator emits all
//! of those on purpose — a generator that can only produce well-formed
//! conversations can only prove the walk handles well-formed conversations.
//!
//! Two claims: the channel is **single and leading**, and **nothing is lost** —
//! the second is what stops the first being satisfied by a delete.
//!
//! What is deliberately NOT asserted, because the code does not claim it:
//!
//! * **The ORDER of the folded parts.** Presence is the property; the join order
//!   (system prompt first, then in-array messages in sequence) is pinned by
//!   example in `domain_request.rs`. A property restating the join would just be
//!   the implementation written twice, and would pass for the same reason it was
//!   wrong.
//! * **Round-tripping.** Translation is one-way, domain → wire; there is no
//!   `from_x(to_x(d)) == d` contract anywhere in the code, so asserting one here
//!   would pin a promise nothing makes.
//!
//! `to_anthropic` and `to_gemini` held these claims before the Chat and Responses
//! walks did, and they are asserted here as the **positive control**. If the
//! generator degenerates to inputs carrying no in-array system content, all four
//! claims go green for the wrong reason; keeping the two known-good walks in the
//! same file is what makes that visible rather than reassuring.

use proptest::prelude::*;
use streamscope_core::api::domain::{MessageContent, ResponseInput};
use streamscope_core::api::domain_request::{
    DomainContentBlock, DomainMessage, DomainRequest, DomainRole, DomainSystemBlock,
    DomainSystemPrompt,
};
use streamscope_core::api::gemini::GeminiPart;
use streamscope_core::api::messages::SystemPrompt;

// ── Generators ────────────────────────────────────────────────────────────────

/// Includes the empty string and a whitespace-only string: "is this text empty"
/// is the decision every fold makes, and both sides of it must be reachable.
fn text_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        Just(String::new()),
        Just("   ".to_string()),
        "[a-zA-Z][a-zA-Z ]{0,20}",
    ]
}

fn role_strategy() -> impl Strategy<Value = DomainRole> {
    prop_oneof![
        // System is weighted equally with the conversational roles rather than
        // sprinkled in, so runs of them, and all-System conversations, actually
        // occur at this vector length.
        Just(DomainRole::User),
        Just(DomainRole::Assistant),
        Just(DomainRole::System),
        Just(DomainRole::System),
        "[a-z]{1,6}".prop_map(|id| DomainRole::Tool {
            tool_call_id: id,
            is_error: None,
            cache_control: None,
        }),
    ]
}

fn message_strategy() -> impl Strategy<Value = DomainMessage> {
    (role_strategy(), text_strategy()).prop_map(|(role, text)| DomainMessage {
        role,
        content: vec![DomainContentBlock::Text {
            text,
            cache_control: None,
        }],
    })
}

fn system_prompt_strategy() -> impl Strategy<Value = Option<DomainSystemPrompt>> {
    prop_oneof![
        Just(None),
        text_strategy().prop_map(|t| Some(DomainSystemPrompt::Text(t))),
        prop::collection::vec(text_strategy(), 1..3).prop_map(|ts| Some(
            DomainSystemPrompt::Blocks(
                ts.into_iter()
                    .map(|text| DomainSystemBlock {
                        text,
                        cache_control: None,
                        client_metadata: Vec::new(),
                    })
                    .collect()
            )
        )),
    ]
}

/// Every field is named — `DomainRequest` has no `Default`, and that is right:
/// a new field must be considered here rather than silently defaulting.
fn domain_request_strategy() -> impl Strategy<Value = DomainRequest> {
    (
        system_prompt_strategy(),
        prop::collection::vec(message_strategy(), 0..8),
    )
        .prop_map(|(system_prompt, messages)| DomainRequest {
            model: "test-model".to_string(),
            system_prompt,
            messages,
            tools: None,
            tool_choice: None,
            parallel_tool_calls: None,
            stream: None,
            max_output_tokens: None,
            temperature: None,
            top_p: None,
            reasoning: None,
            upstream: Default::default(),
            history_parts: Vec::new(),
            stop_sequences: None,
            response_format: None,
            metadata: None,
            store: None,
            extra: Default::default(),
        })
}

// ── Readers for each target's system channel ──────────────────────────────────

fn block_text(content: &[DomainContentBlock]) -> String {
    content
        .iter()
        .filter_map(|b| match b {
            DomainContentBlock::Text { text, .. } => Some(text.as_str()),
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("")
}

fn message_content_text(c: &MessageContent) -> String {
    match c {
        MessageContent::Text(t) => t.clone(),
        MessageContent::Parts(_) => String::new(),
    }
}

/// Every non-empty in-array System text, in order — what each target's system
/// channel must still contain after the fold.
fn expected_folded(dr: &DomainRequest) -> Vec<String> {
    dr.messages
        .iter()
        .filter(|m| matches!(m.role, DomainRole::System))
        .map(|m| block_text(&m.content))
        .filter(|t| !t.is_empty())
        .collect()
}

// ── Claim 1: the system channel is single and leading ─────────────────────────

proptest! {
    #[test]
    fn chat_completions_emits_at_most_one_system_message_and_it_leads(
        dr in domain_request_strategy()
    ) {
        let cc = dr.to_chat_completions();
        let at: Vec<usize> = cc
            .messages
            .iter()
            .enumerate()
            .filter(|(_, m)| m.role == "system" || m.role == "developer")
            .map(|(i, _)| i)
            .collect();
        prop_assert!(
            at.is_empty() || at == vec![0],
            "a strict chat template rejects any system message past the leading \
             run; found system messages at {at:?} in {:?}",
            cc.messages.iter().map(|m| m.role.as_str()).collect::<Vec<_>>()
        );
    }

    #[test]
    fn responses_input_never_carries_a_system_item(dr in domain_request_strategy()) {
        let r = dr.to_responses();
        let ResponseInput::Raw(items) = &r.input else {
            return Err(TestCaseError::fail("to_responses must emit Raw input"));
        };
        for (i, it) in items.iter().enumerate() {
            let role = it.get("role").and_then(|v| v.as_str()).unwrap_or("");
            prop_assert!(
                role != "system" && role != "developer",
                "the Responses system channel is `instructions`; item {i} carries \
                 role {role:?}"
            );
        }
    }

    /// Positive control — held before the Chat/Responses walks did.
    #[test]
    fn anthropic_messages_never_carry_a_system_role(dr in domain_request_strategy()) {
        let ar = dr.to_anthropic();
        prop_assert!(
            ar.messages.iter().all(|m| m.role != "system"),
            "the Messages API has no in-array system role; got {:?}",
            ar.messages.iter().map(|m| m.role.as_str()).collect::<Vec<_>>()
        );
    }

    /// Positive control — held before the Chat/Responses walks did.
    #[test]
    fn gemini_contents_never_carry_a_system_role(dr in domain_request_strategy()) {
        let gr = dr.to_gemini();
        for c in &gr.contents {
            let role = c.role.as_deref().unwrap_or("user");
            prop_assert!(
                role == "user" || role == "model",
                "Gemini `contents` roles are user/model only; got {role:?}"
            );
        }
    }
}

// ── Claim 2: nothing is lost ──────────────────────────────────────────────────

proptest! {
    #[test]
    fn no_in_array_system_text_is_lost_by_any_walk(dr in domain_request_strategy()) {
        let expected = expected_folded(&dr);
        if expected.is_empty() {
            return Ok(());
        }

        let cc = dr.to_chat_completions();
        let chat_channel = cc
            .messages
            .iter()
            .find(|m| m.role == "system")
            .and_then(|m| m.content.as_ref())
            .map(message_content_text)
            .unwrap_or_default();

        let resp = dr.to_responses();
        let responses_channel = resp.instructions.clone().unwrap_or_default();

        let anthropic_channel = match dr.to_anthropic().system {
            None => String::new(),
            Some(SystemPrompt::Text(t)) => t,
            Some(SystemPrompt::Blocks(bs)) => bs
                .iter()
                .map(|b| b.text.as_str())
                .collect::<Vec<_>>()
                .join("\n\n"),
        };

        let gemini_channel = dr
            .to_gemini()
            .system_instruction
            .map(|si| {
                si.parts
                    .iter()
                    .filter_map(|p| match p {
                        GeminiPart::Text { text } => Some(text.as_str()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("\n")
            })
            .unwrap_or_default();

        for text in &expected {
            for (target, channel) in [
                ("chat_completions", &chat_channel),
                ("responses", &responses_channel),
                ("anthropic", &anthropic_channel),
                ("gemini", &gemini_channel),
            ] {
                prop_assert!(
                    channel.contains(text.as_str()),
                    "{target} dropped in-array system text {text:?} instead of \
                     folding it; channel was {channel:?}"
                );
            }
        }
    }
}
