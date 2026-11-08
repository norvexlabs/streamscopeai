//! Inbound mixed-pending splice.
//!
//! Drains parked entries from the cross-request
//! [`crate::web::MixedPendingCache`] for the current
//! `(tenant_id, session_id)` and folds them into the inbound `ApiRequest`'s
//! conversation history as a synthesised
//! `assistant tool_use → user tool_result` pair. Strict reading of
//! Decision #4 — the previous request emitted both real and intercepted
//! `tool_use` blocks in one round; the agent loop dispatched the intercepted
//! call, parked the result, and forwarded only the real call to the client.
//! This request is the client's continuation: the cache is drained, the
//! synthesised pair is appended to the upstream-bound conversation so the
//! model sees the dispatched call as historical context.
//!
//! Append target: end of `DomainRequest.messages`. Each cached entry
//! produces:
//!
//! - one `assistant` message containing a single `tool_use` block
//!   (`id = entry.tool_use_id`, `name = entry.original_tool_name`,
//!   `input = entry.arguments`)
//! - one `tool` message keyed on the same `tool_use_id` with the cached
//!   result text (with `is_error = entry.is_error`)
//!
//! Per-protocol `to_*()` walks pack the tool messages back into the wire
//! shape each provider expects.
//!
//! The spliced `result_text` is delivered **verbatim**: it was already
//! guardrail-screened and spotlight-wrapped at park time
//! (`record_mixed_pending_into_cache` in the response pipeline) — this
//! synchronous request-phase fold must never be the place a scan runs.

use uuid::Uuid;

use crate::api::ApiRequest;
use crate::api::sse::ApiVersion;
use crate::web::MixedPendingCache;

/// Outcome returned to the caller for audit-trail wiring.
#[derive(Debug, Clone)]
pub struct MixedPendingSpliceOutcome {
    /// Number of cache entries actually folded into history. `0` when the
    /// cache had no entries for this session (the typical case).
    pub spliced_count: u32,
    /// Number of cache entries that were drained from the cache but
    /// dropped before reaching the upstream — translation or re-parse
    /// failed. Surfaced via the
    /// `WebSubstitutionMixedPendingSpliceFailed { count }` badge so
    /// operators can spot the data-loss.
    pub failed_count: u32,
    /// Per-entry summary for `transform_diff.injection_blocks[]`. On the
    /// success path: one `action="append"` block per spliced entry,
    /// capturing tool name + tool_use_id + result-byte-count. On the
    /// failure path: one `action="drop_on_translation_failure"` block
    /// per dropped entry plus a final block recording the underlying
    /// error.
    pub injection_blocks: Vec<crate::proxy::content::InjectionBlock>,
}

impl MixedPendingSpliceOutcome {
    fn empty() -> Self {
        Self {
            spliced_count: 0,
            failed_count: 0,
            injection_blocks: Vec::new(),
        }
    }
}

/// Apply the inbound mixed-pending splice to `api_request`. Returns the
/// outcome so the handler can attach the badge + injection blocks to its
/// audit row.
///
/// `client_session_id` — the client's `X-Session-Id` header. `None`
/// short-circuits to a no-op (no cross-request continuity possible).
///
/// `client_api_version` — the protocol the client sent on. The splice
/// re-serialises the modified `DomainRequest` back to this protocol so the
/// downstream pipeline (`transform_request`, routing, etc.) sees the same
/// wire shape it expected.
pub fn apply_inbound_mixed_pending_splice(
    api_request: &mut ApiRequest,
    cache: &MixedPendingCache,
    tenant_id: Uuid,
    user_id: Uuid,
    client_session_id: Option<&str>,
    client_api_version: ApiVersion,
) -> MixedPendingSpliceOutcome {
    let Some(client_sid) = client_session_id else {
        return MixedPendingSpliceOutcome::empty();
    };
    if cache.ttl().is_zero() {
        return MixedPendingSpliceOutcome::empty();
    }
    let session_uuid = crate::proxy::content::session_id_from_client(
        client_sid, tenant_id, user_id,
    );
    let entries = cache.drain_for_session(tenant_id, session_uuid);
    if entries.is_empty() {
        return MixedPendingSpliceOutcome::empty();
    }

    // Convert wire request → domain.
    let mut domain = crate::api::domain_request::DomainRequest::from_api_request(api_request);

    // Build splice tuples.
    let assistant_calls: Vec<crate::api::domain_request::RoundCall> = entries
        .iter()
        .map(|e| crate::api::domain_request::RoundCall {
            id: e.tool_use_id.clone(),
            name: e.original_tool_name.clone(),
            input: e.arguments.clone(),
            thought_signature: e.thought_signature.clone(),
        })
        .collect();
    let tool_results: Vec<(String, String, bool)> = entries
        .iter()
        .map(|e| (e.tool_use_id.clone(), e.result_text.clone(), e.is_error))
        .collect();

    // The client's own request, re-rendered in its own protocol: its thinking
    // goes as sent, for the forward (wherever it is routed) to settle.
    domain.upstream.rerenders_client_request = true;

    // Re-serialise to client api version. Model and reasoning_effort do not
    // change; we keep the existing model on the api_request (the splice is
    // pre-routing-finalisation and pre-model-clamp). The client's own cap
    // field is restored from its wire request below.
    let model = api_request.model().to_string();
    let render = |domain: &crate::api::domain_request::DomainRequest| {
        domain.translate_to(client_api_version, &model, crate::api::domain_request::ChatCapField::default())
    };
    // The client's items are sent as it wrote them, ahead of the spliced pair
    // (see `OwnConversation`): read before the splice, rendered as after it.
    let own = render(&domain).ok().and_then(|(rendered, _)| crate::api::OwnConversation::of(api_request, &rendered));
    domain.append_assistant_tool_calls(None, &assistant_calls);
    domain.append_tool_results(&tool_results);

    let translated = match render(&domain).map(|(bytes, v)| (own.as_ref().and_then(|own| own.keep_in(&bytes)).unwrap_or(bytes), v)) {
        // This is the client's own request with history spliced in, rendered in
        // the client's own protocol: every parameter the client set — including
        // WHICH cap field it used (`max_completion_tokens` is the only one an
        // OpenAI reasoning model accepts) — is restored from its wire request,
        // so only the spliced pair comes from the domain.
        //
        // A manual thinking budget cannot go with it: the spliced assistant
        // turn carries no thinking block, which manual thinking refuses.
        Ok((bytes, _)) => api_request
            .carry_knobs_onto_with(&bytes, client_api_version, crate::api::drop_manual_thinking)
            .unwrap_or(bytes),
        Err(e) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                error = %e,
                dropped = entries.len(),
                "mixed-pending splice: domain → wire translation failed; entries dropped"
            );
            return failure_outcome(&entries, "translate_failed", &e.to_string());
        }
    };
    let parsed = match parse_api_request_bytes(&translated, client_api_version) {
        Ok(r) => r,
        Err(e) => {
            tracing::warn!(
                tenant_id = %tenant_id,
                error = %e,
                dropped = entries.len(),
                "mixed-pending splice: re-parse to ApiRequest failed; entries dropped"
            );
            return failure_outcome(&entries, "reparse_failed", &e);
        }
    };
    *api_request = parsed;

    // Build per-entry injection blocks for audit visibility.
    let injection_blocks = entries
        .iter()
        .map(|e| {
            let mut payload = serde_json::json!({
                "reason": "cross_request_mixed_pending_splice",
                "tool_name": e.original_tool_name,
                "tool_use_id": e.tool_use_id,
                "is_error": e.is_error,
                "result_bytes": e.result_text.len(),
            });
            // The splice is rendered in the client's protocol, and only
            // Gemini's has a channel for the call's signature.
            if e.thought_signature.is_some() && client_api_version != ApiVersion::GoogleGemini {
                payload["thought_signature"] = serde_json::Value::from("not_carried");
            }
            crate::proxy::content::InjectionBlock {
                transform: "mixed_pending_splice".to_string(),
                scope: "messages".to_string(),
                field: "messages".to_string(),
                action: "append".to_string(),
                content: payload.to_string(),
            }
        })
        .collect();

    MixedPendingSpliceOutcome {
        spliced_count: entries.len() as u32,
        failed_count: 0,
        injection_blocks,
    }
}

/// Build a failure outcome when entries were drained from the cache but
/// could not be folded into the wire request. Each dropped entry produces
/// one `drop_on_translation_failure` injection_block plus a summary block
/// carrying the underlying error reason. Caller surfaces these on the
/// audit row alongside the
/// `WebSubstitutionMixedPendingSpliceFailed` badge.
fn failure_outcome(
    entries: &[crate::web::MixedPendingEntry],
    failure_reason: &str,
    error_detail: &str,
) -> MixedPendingSpliceOutcome {
    let mut injection_blocks: Vec<crate::proxy::content::InjectionBlock> = entries
        .iter()
        .map(|e| {
            let payload = serde_json::json!({
                "reason": "cross_request_mixed_pending_splice_dropped",
                "tool_name": e.original_tool_name,
                "tool_use_id": e.tool_use_id,
                "is_error": e.is_error,
                "result_bytes": e.result_text.len(),
                "failure": failure_reason,
            });
            crate::proxy::content::InjectionBlock {
                transform: "mixed_pending_splice".to_string(),
                scope: "messages".to_string(),
                field: "messages".to_string(),
                action: "drop_on_translation_failure".to_string(),
                content: payload.to_string(),
            }
        })
        .collect();
    let summary = serde_json::json!({
        "reason": "cross_request_mixed_pending_splice_failed",
        "dropped_count": entries.len(),
        "failure": failure_reason,
        "error": error_detail,
    });
    injection_blocks.push(crate::proxy::content::InjectionBlock {
        transform: "mixed_pending_splice".to_string(),
        scope: "messages".to_string(),
        field: "messages".to_string(),
        action: "splice_failed".to_string(),
        content: summary.to_string(),
    });
    MixedPendingSpliceOutcome {
        spliced_count: 0,
        failed_count: entries.len() as u32,
        injection_blocks,
    }
}

fn parse_api_request_bytes(
    bytes: &[u8],
    api_version: ApiVersion,
) -> Result<ApiRequest, String> {
    match api_version {
        ApiVersion::AnthropicMessages => serde_json::from_slice(bytes)
            .map(ApiRequest::AnthropicMessages)
            .map_err(|e| e.to_string()),
        ApiVersion::ChatCompletions => serde_json::from_slice(bytes)
            .map(ApiRequest::ChatCompletions)
            .map_err(|e| e.to_string()),
        ApiVersion::Responses => serde_json::from_slice(bytes)
            .map(ApiRequest::Responses)
            .map_err(|e| e.to_string()),
        ApiVersion::GoogleGemini => serde_json::from_slice(bytes)
            .map(ApiRequest::GoogleGemini)
            .map_err(|e| e.to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::messages::MessagesRequest;
    use crate::web::MixedPendingEntry;
    use std::time::{Duration, Instant};

    fn make_anthropic_request(stream: Option<bool>) -> ApiRequest {
        let json = serde_json::json!({
            "model": "claude-sonnet-4-5",
            "max_tokens": 1024,
            "stream": stream,
            "messages": [
                {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": [
                    {"type": "tool_use", "id": "tu_real", "name": "list_files", "input": {"path": "."}}
                ]},
                {"role": "user", "content": [
                    {"type": "tool_result", "tool_use_id": "tu_real", "content": "[ok]"}
                ]}
            ]
        });
        let req: MessagesRequest = serde_json::from_value(json).unwrap();
        ApiRequest::AnthropicMessages(req)
    }

    fn make_entry(tenant: Uuid) -> MixedPendingEntry {
        MixedPendingEntry {
            tenant_id: tenant,
            tool_use_id: "tu_intercepted".to_string(),
            original_tool_name: "web_search".to_string(),
            arguments: serde_json::json!({"query": "rust async"}),
            result_text: r#"{"hits":[{"url":"https://x","title":"X"}]}"#.to_string(),
            is_error: false,
            recorded_at: Instant::now(),
            thought_signature: None,
        }
    }

    #[test]
    fn no_session_id_is_noop() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            Uuid::new_v4(),
            Uuid::new_v4(),
            None,
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 0);
        assert_eq!(out.failed_count, 0);
        // Original request untouched (3 messages).
        if let ApiRequest::AnthropicMessages(r) = &req {
            assert_eq!(r.messages.len(), 3);
        }
    }

    #[test]
    fn empty_cache_is_noop() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            Uuid::new_v4(),
            Uuid::new_v4(),
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 0);
        assert_eq!(out.failed_count, 0);
        if let ApiRequest::AnthropicMessages(r) = &req {
            assert_eq!(r.messages.len(), 3);
        }
    }

    #[test]
    fn ttl_zero_disables_splice() {
        let cache = MixedPendingCache::new(Duration::from_secs(0));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid = crate::proxy::content::session_id_from_client(
            "client-session-1",
            tenant,
            user,
        );
        cache.record(session_uuid, make_entry(tenant));
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 0);
        assert_eq!(out.failed_count, 0);
    }

    #[test]
    fn anthropic_splice_appends_assistant_and_tool_messages() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid = crate::proxy::content::session_id_from_client(
            "client-session-1",
            tenant,
            user,
        );
        cache.record(session_uuid, make_entry(tenant));
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 1);
        assert_eq!(out.injection_blocks.len(), 1);
        assert_eq!(out.injection_blocks[0].transform, "mixed_pending_splice");
        if let ApiRequest::AnthropicMessages(r) = &req {
            // Original 3 messages + 1 assistant + 1 user (tool_result lives
            // on a `user` message in Anthropic wire form).
            assert_eq!(r.messages.len(), 5);
            // 4th message (index 3) — assistant with tool_use.
            assert_eq!(r.messages[3].role, "assistant");
            // 5th message (index 4) — user with tool_result block.
            assert_eq!(r.messages[4].role, "user");
        }
    }

    /// A parked call's Gemini signature is spliced back on a Gemini client's
    /// request, on the call's own part; any other client's protocol has no
    /// channel for it, and the splice's record says so.
    #[test]
    fn a_parked_calls_signature_reaches_only_a_gemini_client() {
        let splice = |client: ApiVersion, body: serde_json::Value| {
            let cache = MixedPendingCache::new(Duration::from_secs(60));
            let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
            let session = crate::proxy::content::session_id_from_client("s", tenant, user);
            cache.record(session, MixedPendingEntry { thought_signature: Some("Sig1".into()), ..make_entry(tenant) });
            let mut req = ApiRequest::parse(client, &bytes::Bytes::from(body.to_string())).unwrap();
            let out = apply_inbound_mixed_pending_splice(&mut req, &cache, tenant, user, Some("s"), client);
            (req, out)
        };
        let (req, out) = splice(
            ApiVersion::GoogleGemini,
            serde_json::json!({"contents": [{"role": "user", "parts": [{"text": "q"}]}]}),
        );
        let sent: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
        let call = sent["contents"]
            .as_array()
            .unwrap()
            .iter()
            .flat_map(|c| c["parts"].as_array().cloned().unwrap_or_default())
            .find(|p| p.get("functionCall").is_some())
            .expect("the parked call was spliced");
        assert_eq!(call["thoughtSignature"], "Sig1", "{sent}");
        assert!(!out.injection_blocks[0].content.contains("thought_signature"));

        let (_, out) = splice(
            ApiVersion::AnthropicMessages,
            serde_json::json!({"model": "m", "max_tokens": 10, "messages": [{"role": "user", "content": "q"}]}),
        );
        assert!(out.injection_blocks[0].content.contains(r#""thought_signature":"not_carried""#), "{:?}", out.injection_blocks);
    }

    /// The splice re-renders the client's own request in its own protocol, so
    /// the client's thinking goes as it sent it — Anthropic's signature and the
    /// gateway's placeholder alike — for the forward to settle wherever it is
    /// routed (the conform pass removes the placeholder on Anthropic, a
    /// translation renders only what its target verifies).
    #[test]
    fn a_splice_keeps_the_clients_thinking_as_sent() {
        for signature in ["EqQBCkY", "synth_1", ""] {
            let cache = MixedPendingCache::new(Duration::from_secs(60));
            let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
            cache.record(crate::proxy::content::session_id_from_client("s", tenant, user), make_entry(tenant));
            let mut req = ApiRequest::AnthropicMessages(
                serde_json::from_value(serde_json::json!({"model": "m", "max_tokens": 10, "messages": [
                    {"role": "user", "content": "Hi"},
                    {"role": "assistant", "content": [
                        {"type": "thinking", "thinking": "t", "signature": signature},
                        {"type": "tool_use", "id": "tu_real", "name": "list_files", "input": {}}]},
                    {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "tu_real", "content": "ok"}]}]}))
                .unwrap(),
            );
            let out = apply_inbound_mixed_pending_splice(&mut req, &cache, tenant, user, Some("s"), ApiVersion::AnthropicMessages);
            assert_eq!(out.spliced_count, 1);
            let ApiRequest::AnthropicMessages(r) = &req else { unreachable!() };
            let kept = serde_json::to_value(&r.messages[1]).unwrap();
            assert_eq!(kept["content"][0], serde_json::json!({"type": "thinking", "thinking": "t", "signature": signature}), "{kept}");
        }
    }

    #[test]
    fn a_same_protocol_splice_sends_the_clients_items_as_written() {
        // The splice re-renders the client's request in its own protocol, and
        // the domain it goes through has no field for some of what a client
        // item carries — nor keeps a mid-array Chat `system` message in place.
        // The client's items go as a forward of the request sends them, and
        // only the spliced pair comes from the domain.
        let cases = [
            (ApiVersion::ChatCompletions, "messages", serde_json::json!({"model": "m", "messages": [
                {"role": "system", "content": "Base."},
                {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": "ok"},
                {"role": "system", "content": "Skills."},
                {"role": "user", "content": "go on"}]})),
            (ApiVersion::AnthropicMessages, "messages", serde_json::json!({"model": "m", "max_tokens": 10, "messages": [
                {"role": "user", "content": "Hi"},
                {"role": "assistant", "content": [{"type": "tool_use", "id": "c1", "name": "shot", "input": {}}]},
                {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "c1", "toolset_name": "browser", "content": [
                    {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBO"},
                     "transformations": {"oversized_image": "error"}}]}]}]})),
            (ApiVersion::Responses, "input", serde_json::json!({"model": "m", "input": [
                {"type": "message", "role": "user", "content": [
                    {"type": "input_text", "text": "Hi", "prompt_cache_breakpoint": {"ttl": "1h"}}]}]})),
            (ApiVersion::GoogleGemini, "contents", serde_json::json!({"contents": [{"role": "user", "parts": [
                {"text": "look"},
                {"inlineData": {"mimeType": "image/png", "data": "iVBO"}, "mediaResolution": {"level": "MEDIA_RESOLUTION_HIGH"}},
                {"fileData": {"mimeType": "video/mp4", "fileUri": "gs://b/v.mp4"}, "videoMetadata": {"startOffset": "2s"}}]}]})),
        ];
        for (version, key, body) in cases {
            let client = ApiRequest::parse(version, &bytes::Bytes::from(body.to_string())).unwrap();
            let own = client.wire_value().unwrap()[key].as_array().unwrap().clone();
            // Control: a rendering through the domain alone does not send them so.
            let (rendered, _) = crate::api::domain_request::DomainRequest::from_api_request(&client)
                .translate_to(version, "m", Default::default())
                .unwrap();
            let rendered: serde_json::Value = serde_json::from_slice(&rendered).unwrap();
            assert_ne!(rendered[key].as_array().unwrap(), &own, "{version:?}: the control renders the items as sent");

            let cache = MixedPendingCache::new(Duration::from_secs(60));
            let (tenant, user) = (Uuid::new_v4(), Uuid::new_v4());
            cache.record(crate::proxy::content::session_id_from_client("s", tenant, user), make_entry(tenant));
            let mut req = client.clone();
            let out = apply_inbound_mixed_pending_splice(&mut req, &cache, tenant, user, Some("s"), version);
            assert_eq!(out.spliced_count, 1, "{version:?}");
            let sent: serde_json::Value = serde_json::from_slice(&req.serialize().unwrap()).unwrap();
            let sent = sent[key].as_array().unwrap();
            assert_eq!(sent[..own.len()], own[..], "{version:?}: {sent:?}");
            // The spliced call and its result follow.
            assert_eq!(sent.len(), own.len() + 2, "{version:?}: {sent:?}");
            assert!(serde_json::to_string(&sent[own.len()..]).unwrap().contains("rust async"), "{version:?}: {sent:?}");
        }
    }

    #[test]
    fn cache_is_drained_single_use() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid = crate::proxy::content::session_id_from_client(
            "client-session-1",
            tenant,
            user,
        );
        cache.record(session_uuid, make_entry(tenant));
        let mut req1 = make_anthropic_request(None);
        let out1 = apply_inbound_mixed_pending_splice(
            &mut req1,
            &cache,
            tenant,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out1.spliced_count, 1);
        // Second request in the same session sees no entries.
        let mut req2 = make_anthropic_request(None);
        let out2 = apply_inbound_mixed_pending_splice(
            &mut req2,
            &cache,
            tenant,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out2.spliced_count, 0);
    }

    #[test]
    fn cross_session_isolation() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_a = crate::proxy::content::session_id_from_client(
            "session-a",
            tenant,
            user,
        );
        cache.record(session_a, make_entry(tenant));
        // Different client session id → different gateway UUID → no splice.
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant,
            user,
            Some("session-b"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 0);
        assert_eq!(out.failed_count, 0);
        // session-a still has its entry.
        let drained = cache.drain_for_session(tenant, session_a);
        assert_eq!(drained.len(), 1);
    }

    #[test]
    fn cross_tenant_isolation() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant_a = Uuid::new_v4();
        let tenant_b = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid_a = crate::proxy::content::session_id_from_client(
            "client-session-1",
            tenant_a,
            user,
        );
        cache.record(session_uuid_a, make_entry(tenant_a));
        // Tenant B querying with the same client_session_id: the UUID derives
        // differently (tenant_id is part of the hash) so no match.
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant_b,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 0);
        assert_eq!(out.failed_count, 0);
    }

    #[test]
    fn streaming_flag_preserved_through_translate_round_trip() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid = crate::proxy::content::session_id_from_client(
            "client-session-1",
            tenant,
            user,
        );
        cache.record(session_uuid, make_entry(tenant));
        let mut req = make_anthropic_request(Some(true));
        let _ = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        if let ApiRequest::AnthropicMessages(r) = &req {
            assert_eq!(r.stream, Some(true), "streaming flag must round-trip");
        }
    }

    fn make_chat_request(stream: Option<bool>) -> ApiRequest {
        let json = serde_json::json!({
            "model": "gpt-4o-mini",
            "stream": stream,
            "messages": [
                {"role": "user", "content": "Hi"}
            ]
        });
        let req: crate::api::chat::ChatCompletionsRequest =
            serde_json::from_value(json).unwrap();
        ApiRequest::ChatCompletions(req)
    }

    #[test]
    fn chat_completions_round_trip_preserves_stream_flag() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid = crate::proxy::content::session_id_from_client(
            "client-session-cc",
            tenant,
            user,
        );
        cache.record(session_uuid, make_entry(tenant));
        let mut req = make_chat_request(Some(true));
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant,
            user,
            Some("client-session-cc"),
            ApiVersion::ChatCompletions,
        );
        assert_eq!(out.spliced_count, 1);
        if let ApiRequest::ChatCompletions(r) = &req {
            assert_eq!(r.stream, Some(true));
            // Splice produces an assistant message carrying the tool_call
            // plus a `tool` role message with the cached result. The
            // exact wire shape varies per protocol; what matters is that
            // both new messages landed on the request.
            assert!(
                r.messages.len() >= 3,
                "splice must append at least 2 messages (assistant tool_call + tool result)"
            );
        } else {
            panic!("expected ChatCompletions");
        }
    }

    #[test]
    fn cancelled_dispatch_outcome_path_via_failure_outcome() {
        // failure_outcome is the helper that fires when translate / re-parse
        // dies mid-flight. Build it directly to verify the badge-counting
        // hook + per-entry injection_blocks shape.
        let entries = vec![make_entry(Uuid::new_v4())];
        let outcome = failure_outcome(&entries, "translate_failed", "boom");
        assert_eq!(outcome.spliced_count, 0);
        assert_eq!(outcome.failed_count, 1);
        // 1 per-entry drop + 1 summary block.
        assert_eq!(outcome.injection_blocks.len(), 2);
        assert_eq!(
            outcome.injection_blocks[0].action,
            "drop_on_translation_failure"
        );
        assert_eq!(outcome.injection_blocks[1].action, "splice_failed");
        assert!(outcome.injection_blocks[1].content.contains("translate_failed"));
        assert!(outcome.injection_blocks[1].content.contains("boom"));
    }

    #[test]
    fn error_outcome_carries_is_error_flag() {
        let cache = MixedPendingCache::new(Duration::from_secs(60));
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let session_uuid = crate::proxy::content::session_id_from_client(
            "client-session-1",
            tenant,
            user,
        );
        let mut entry = make_entry(tenant);
        entry.is_error = true;
        entry.result_text = r#"{"error":"upstream timeout"}"#.to_string();
        cache.record(session_uuid, entry);
        let mut req = make_anthropic_request(None);
        let out = apply_inbound_mixed_pending_splice(
            &mut req,
            &cache,
            tenant,
            user,
            Some("client-session-1"),
            ApiVersion::AnthropicMessages,
        );
        assert_eq!(out.spliced_count, 1);
        assert!(out.injection_blocks[0].content.contains("\"is_error\":true"));
    }
}
