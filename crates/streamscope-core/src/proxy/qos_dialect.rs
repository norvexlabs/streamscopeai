//! Expressing a request's QoS class on the upstream's own wire.
//!
//! Dispatch order is the gateway's decision; a dialect only tells the engine
//! what a request it has already been handed is worth. It is applied to a target
//! whose server opted in and nowhere else, so a mixed alias — a vLLM replica and
//! a hosted fallback — expresses the class on the vLLM leg and sends nothing to
//! the hosted one.
//!
//! The value OVERWRITES whatever is in the field: the client's own `priority` is
//! stripped in the request phase, and on a server with a dialect a preset may
//! not set one, so nothing legitimate is being replaced.

use crate::api::sse::ApiVersion;
use crate::config::qos::SchedulingDialect;

/// The header vLLM reads a priority from. It overrides the body field wherever
/// both exist, which is why it is the right channel for a protocol that has no
/// field at all.
pub const VLLM_PRIORITY_HEADER: &str = "x-vllm-priority";

/// Where a class's rank goes on one forwarded request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PriorityWire {
    /// Nothing to express on this leg.
    None,
    /// The protocol carries the field itself.
    Body(i32),
    /// The protocol has no field; the engine reads a header instead.
    Header(i32),
}

/// How this target's protocol carries the rank, if it does.
pub fn priority_wire(
    dialect: SchedulingDialect,
    rank: Option<i32>,
    target: ApiVersion,
) -> PriorityWire {
    let Some(rank) = rank else {
        return PriorityWire::None;
    };
    match dialect {
        SchedulingDialect::None => PriorityWire::None,
        SchedulingDialect::VllmPriority => match target {
            // vLLM's OpenAI surfaces all declare `priority` on the request body.
            ApiVersion::ChatCompletions | ApiVersion::Responses => PriorityWire::Body(rank),
            // vLLM's Anthropic surface declares no such field.
            ApiVersion::AnthropicMessages => PriorityWire::Header(rank),
            // vLLM serves no Gemini surface, so there is nowhere to put it.
            ApiVersion::GoogleGemini => PriorityWire::None,
        },
    }
}

/// Write the rank into a prepared body where the protocol has a field for it.
///
/// Returns the header to set instead when it does not, and `None` when this leg
/// expresses nothing. The body is left untouched unless it is a JSON object —
/// there is no field to set on anything else.
pub fn apply_priority(
    dialect: SchedulingDialect,
    rank: Option<i32>,
    target: ApiVersion,
    body: &mut serde_json::Value,
) -> Option<(&'static str, i32)> {
    match priority_wire(dialect, rank, target) {
        PriorityWire::None => None,
        PriorityWire::Header(rank) => Some((VLLM_PRIORITY_HEADER, rank)),
        PriorityWire::Body(rank) => {
            if let Some(obj) = body.as_object_mut() {
                obj.insert("priority".to_string(), serde_json::json!(rank));
            }
            None
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn a_server_without_a_dialect_expresses_nothing() {
        let mut body = json!({"model": "m"});
        assert_eq!(
            apply_priority(SchedulingDialect::None, Some(0), ApiVersion::ChatCompletions, &mut body),
            None
        );
        assert_eq!(body, json!({"model": "m"}));
    }

    #[test]
    fn a_request_with_no_class_expresses_nothing() {
        let mut body = json!({"model": "m"});
        assert_eq!(
            apply_priority(
                SchedulingDialect::VllmPriority,
                None,
                ApiVersion::ChatCompletions,
                &mut body
            ),
            None
        );
        assert_eq!(body, json!({"model": "m"}));
    }

    #[test]
    fn the_openai_surfaces_carry_the_rank_in_the_body() {
        for version in [ApiVersion::ChatCompletions, ApiVersion::Responses] {
            let mut body = json!({"model": "m"});
            assert_eq!(
                apply_priority(SchedulingDialect::VllmPriority, Some(20), version, &mut body),
                None
            );
            assert_eq!(body["priority"], json!(20));
        }
    }

    #[test]
    fn the_anthropic_surface_carries_the_rank_in_a_header() {
        let mut body = json!({"model": "m"});
        assert_eq!(
            apply_priority(
                SchedulingDialect::VllmPriority,
                Some(-5),
                ApiVersion::AnthropicMessages,
                &mut body
            ),
            Some((VLLM_PRIORITY_HEADER, -5))
        );
        // The body has no field for it, so nothing is invented there.
        assert_eq!(body, json!({"model": "m"}));
    }

    #[test]
    fn gemini_expresses_nothing_because_vllm_serves_no_gemini_surface() {
        let mut body = json!({"contents": []});
        assert_eq!(
            apply_priority(
                SchedulingDialect::VllmPriority,
                Some(0),
                ApiVersion::GoogleGemini,
                &mut body
            ),
            None
        );
        assert_eq!(body, json!({"contents": []}));
    }

    #[test]
    fn a_value_already_in_the_body_is_replaced_not_merged() {
        let mut body = json!({"model": "m", "priority": -100});
        apply_priority(SchedulingDialect::VllmPriority, Some(10), ApiVersion::ChatCompletions, &mut body);
        assert_eq!(body["priority"], json!(10));
    }

    #[test]
    fn a_body_that_is_not_an_object_is_left_alone() {
        let mut body = json!(["not", "an", "object"]);
        apply_priority(SchedulingDialect::VllmPriority, Some(10), ApiVersion::ChatCompletions, &mut body);
        assert_eq!(body, json!(["not", "an", "object"]));
    }
}
