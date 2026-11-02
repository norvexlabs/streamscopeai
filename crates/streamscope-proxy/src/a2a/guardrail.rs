//! Inline guardrail hops for A2A traffic — the same classifier + PII detector
//! the LLM and web surfaces use, on the two places an agent call carries
//! content.
//!
//! **Request** (`screen_request`) — the message the caller is about to send to a
//! third party. Injection screening rides the tenant's `scan_inbound` flag and
//! PII rides `pii.scan_request`, exactly as on the LLM inbound hop: the same
//! toggles, the same fail-mode, the same placeholder wording. This is the DLP
//! surface — an agent about to hand a customer's data to an outside agent.
//!
//! **Reply** (`screen_reply`) — the remote agent's answer and the artifacts it
//! produced. This is the surface A2A exists to defend: the caller will fold that
//! reply straight into its own model's context, so a hostile (or itself-
//! compromised) peer agent gets a prompt-injection channel into the caller's LLM.
//! It is screened whenever the guardrail is active — like fetched web content,
//! and for the same reason — on its own [`GuardrailSurface::A2aAgent`] surface so
//! a finding names the agent it came from.
//!
//! **Streaming enforces nothing.** The pump forwards each chunk the moment it
//! arrives, so by the time a verdict on the reply exists those bytes are already
//! on their way to the client and cannot be recalled. A streamed reply is
//! therefore screened in observe mode only — flagged on the audit row, never
//! rewritten on the wire. This is the PII P3 precedent, and the honest one: the
//! alternative is buffering the whole stream, which would make streaming
//! pointless. Operators who need enforcement on agent replies use the
//! non-streaming method.

use streamscope_core::a2a::domain::{self, PartsSlot, TextSlot};
use streamscope_core::a2a::model::A2aPart;
use streamscope_core::audit::badge::AuditBadge;
use streamscope_core::guardrail::{
    run_enforce, run_observe, run_pii_enforce, run_pii_observe, GuardrailInput, GuardrailSettings,
    GuardrailSurface,
};
use streamscope_core::proxy::content::GuardrailStepDiff;

/// What one guardrail hop produced. `modified` is true only when a strip /
/// redaction actually rewrote a part — the caller then writes the slots back and
/// stamps a modified chip.
#[derive(Default)]
pub struct GuardrailOutcome {
    pub badges: Vec<AuditBadge>,
    pub steps: Vec<GuardrailStepDiff>,
    pub modified: bool,
}

/// The anchor a strip writes back through. `p:<slot>:<part>` names a message
/// part, `t:<index>` a non-part string (a metadata leaf, an agent card's prose).
/// Both passes address content by these ids, so a finding always lands on the
/// exact string it was found in.
fn part_id(slot: usize, part: usize) -> String {
    format!("p:{slot}:{part}")
}

fn text_id(index: usize) -> String {
    format!("t:{index}")
}

enum Anchor {
    Part(usize, usize),
    Text(usize),
}

fn parse_id(id: &str) -> Option<Anchor> {
    let (kind, rest) = id.split_once(':')?;
    match kind {
        "p" => {
            let (slot, part) = rest.split_once(':')?;
            Some(Anchor::Part(slot.parse().ok()?, part.parse().ok()?))
        }
        "t" => Some(Anchor::Text(rest.parse().ok()?)),
        _ => None,
    }
}

/// What each pass screens.
///
/// - **Prose** — a message's text parts plus an agent card's own descriptions:
///   natural language, so the injection classifier reads it.
/// - **Every string** — the above plus each leaf of a free-form `metadata` map.
///   A metadata leaf is a machine value; sending it to an injection classifier
///   produces noise, not signal, but PII hides there just as well as anywhere,
///   and policy matches it through the `data` target.
fn inputs(
    slots: &[PartsSlot],
    texts: &[TextSlot],
    target: &str,
    prose_only: bool,
) -> Vec<GuardrailInput> {
    let mut inputs = Vec::new();
    for (si, slot) in slots.iter().enumerate() {
        for (pi, part) in slot.parts.iter().enumerate() {
            if let A2aPart::Text { text, .. } = part
                && !text.trim().is_empty()
            {
                inputs.push(GuardrailInput {
                    id: part_id(si, pi),
                    classifiable: text.clone(),
                    target: target.to_string(),
                });
            }
        }
    }
    for (ti, slot) in texts.iter().enumerate() {
        if prose_only && !slot.prose {
            continue;
        }
        inputs.push(GuardrailInput {
            id: text_id(ti),
            classifiable: slot.text.clone(),
            target: target.to_string(),
        });
    }
    inputs
}

/// Replace each string named in `rewrites` with its new content. Returns whether
/// anything changed.
fn apply_rewrites(
    slots: &mut [PartsSlot],
    texts: &mut [TextSlot],
    rewrites: &std::collections::HashMap<String, String>,
) -> bool {
    let mut modified = false;
    for (id, new_text) in rewrites {
        match parse_id(id) {
            Some(Anchor::Part(si, pi)) => {
                if let Some(A2aPart::Text { text, .. }) =
                    slots.get_mut(si).and_then(|s| s.parts.get_mut(pi))
                {
                    *text = new_text.clone();
                    modified = true;
                }
            }
            Some(Anchor::Text(ti)) => {
                if let Some(slot) = texts.get_mut(ti) {
                    slot.text = new_text.clone();
                    modified = true;
                }
            }
            None => {}
        }
    }
    modified
}

/// Screen the caller's outbound message. `slots` are rewritten in place when
/// enforce strips or redacts a part; the caller writes them back into the
/// forwarded body.
pub async fn screen_request(
    settings: &GuardrailSettings,
    slots: &mut [PartsSlot],
    texts: &mut [TextSlot],
    agent_slug: &str,
) -> GuardrailOutcome {
    let injection_on = settings.is_active() && settings.scan_inbound;
    let pii_on = settings.pii.enabled && settings.pii.scan_request;
    screen(
        settings,
        slots,
        texts,
        agent_slug,
        injection_on,
        GuardrailSurface::Inbound,
        pii_on,
        GuardrailSurface::Inbound,
        settings.enforces(),
        settings.pii.enforces(),
    )
    .await
}

/// Screen the remote agent's reply. `enforce_allowed` is false on the streamed
/// path — the bytes are gone; the verdict can only be recorded.
pub async fn screen_reply(
    settings: &GuardrailSettings,
    slots: &mut [PartsSlot],
    texts: &mut [TextSlot],
    agent_slug: &str,
    enforce_allowed: bool,
) -> GuardrailOutcome {
    let injection_on = settings.is_active();
    let pii_on = settings.pii.enabled && settings.pii.scan_response;
    screen(
        settings,
        slots,
        texts,
        agent_slug,
        injection_on,
        GuardrailSurface::A2aAgent,
        pii_on,
        GuardrailSurface::Response,
        enforce_allowed && settings.enforces(),
        enforce_allowed && settings.pii.enforces(),
    )
    .await
}

/// The shared body of both hops: one batched injection round-trip, then the
/// in-process PII pass, folding both into a single outcome.
#[allow(clippy::too_many_arguments)]
async fn screen(
    settings: &GuardrailSettings,
    slots: &mut [PartsSlot],
    texts: &mut [TextSlot],
    agent_slug: &str,
    injection_on: bool,
    injection_surface: GuardrailSurface,
    pii_on: bool,
    pii_surface: GuardrailSurface,
    injection_enforces: bool,
    pii_enforces: bool,
) -> GuardrailOutcome {
    let mut out = GuardrailOutcome::default();
    if !injection_on && !pii_on {
        return out;
    }

    if injection_on {
        // Prose only: the classifier reads natural language.
        let prose = inputs(slots, texts, agent_slug, true);
        if !prose.is_empty() {
            if injection_enforces {
                if let Some(eo) = run_enforce(settings, &prose, injection_surface).await {
                    out.modified |= apply_rewrites(slots, texts, &eo.strips);
                    out.steps.extend(eo.steps);
                    out.badges.extend(eo.badges);
                }
            } else if let Some(oo) = run_observe(settings, &prose, injection_surface).await {
                out.steps.extend(oo.steps);
                out.badges.extend(oo.badges);
            }
        }
    }

    if pii_on {
        // Every string, metadata leaves included — a customer's details are just
        // as gone whether they left in the prose or in a metadata field. Re-read
        // after the injection pass: a withheld part now carries its placeholder,
        // and scanning that is both harmless and correct — it is what the peer
        // will see.
        let all = inputs(slots, texts, agent_slug, false);
        if !all.is_empty() {
            if pii_enforces {
                if let Some(eo) = run_pii_enforce(&settings.pii, &all, pii_surface) {
                    out.modified |= apply_rewrites(slots, texts, &eo.redactions);
                    out.steps.extend(eo.steps);
                    out.badges.extend(eo.badges);
                }
            } else if let Some(oo) = run_pii_observe(&settings.pii, &all, pii_surface) {
                out.steps.extend(oo.steps);
                out.badges.extend(oo.badges);
            }
        }
    }

    out
}

/// The text a streamed reply carried, as slots — the observe-mode input for the
/// streaming path, assembled from the events the pump captured.
///
/// Envelope shape is resolved through `domain::stream_envelope_payload`, never by
/// reaching for `result` directly: the **peer** picks the shape, so an agent that
/// streams bare `StreamResponse` objects instead of JSON-RPC envelopes must not
/// thereby skip the screen.
pub fn slots_from_stream_events(events: &[serde_json::Value]) -> Vec<PartsSlot> {
    events
        .iter()
        .filter_map(domain::stream_envelope_payload)
        .flat_map(domain::stream_event_slots)
        .collect()
}

/// The non-part strings a streamed reply carried: the metadata and prose riding
/// the same events, **plus the message of any in-stream JSON-RPC `error`** — the
/// agent wrote that string too, and the buffered path screens it.
pub fn text_slots_from_stream_events(events: &[serde_json::Value]) -> Vec<TextSlot> {
    events
        .iter()
        .flat_map(|envelope| match domain::stream_envelope_payload(envelope) {
            Some(payload) => domain::stream_event_text_slots(payload),
            None => domain::error_text_slots(envelope),
        })
        .collect()
}

/// Whether the capture holds an event the screen could not read — a `data:` line
/// that wasn't JSON (retained as `{"unparsed": …}`), or an envelope carrying
/// none of the shapes we know.
///
/// Such an event was forwarded to the client but contributes no slot, so a scan
/// over the rest would report clean on a reply nobody fully read. The streamed
/// path raises `incomplete_capture` for it, exactly as it does for a truncated
/// capture — the two are the same lie.
pub fn capture_has_unreadable_event(events: &[serde_json::Value]) -> bool {
    events.iter().any(|envelope| {
        domain::stream_envelope_payload(envelope).is_none()
            && domain::error_text_slots(envelope).is_empty()
    })
}

/// Whether the guardrail would look at a reply at all. The streamed path asks
/// before reporting an incomplete scan — a tenant that screens nothing should not
/// be told its scan was incomplete.
pub fn screens_reply(settings: &GuardrailSettings) -> bool {
    settings.is_active() || (settings.pii.enabled && settings.pii.scan_response)
}

/// The finding that says "the scan did not see all of this".
///
/// A streamed reply is captured under a byte cap; past it the pump stops
/// retaining events, so the classifier is handed a prefix. Reporting a clean scan
/// of a truncated capture would tell the operator the reply was screened when it
/// wasn't — and would hand a hostile agent a free channel: pad the reply past the
/// cap, then say anything.
pub fn incomplete_capture(agent_slug: &str) -> GuardrailOutcome {
    use streamscope_core::proxy::content::GuardrailStepOutcome;

    let reason = streamscope_core::guardrail::INCOMPLETE_SCAN_REASON;
    GuardrailOutcome {
        badges: vec![AuditBadge::GuardrailError {
            reason: reason.to_string(),
        }],
        steps: vec![GuardrailStepDiff {
            call_id: None,
            tool_use_id: String::new(),
            name: "guardrail:classifier".to_string(),
            phase: streamscope_core::audit::Phase::Response,
            target: agent_slug.to_string(),
            category: None,
            confidence: None,
            outcome: GuardrailStepOutcome::Error,
            error: Some(reason.to_string()),
            entities: None,
        }],
        modified: false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use streamscope_core::a2a::domain;

    fn slots(text: &str) -> Vec<PartsSlot> {
        let params = serde_json::json!({"message": {"parts": [{"text": text}]}});
        domain::request_slots(&params)
    }

    #[test]
    fn an_anchor_round_trips() {
        assert!(matches!(parse_id(&part_id(2, 5)), Some(Anchor::Part(2, 5))));
        assert!(matches!(parse_id(&text_id(7)), Some(Anchor::Text(7))));
        assert!(parse_id("bogus").is_none());
    }

    #[test]
    fn the_classifier_reads_prose_and_the_pii_pass_reads_every_string() {
        let params = serde_json::json!({"message": {
            "parts": [
                {"text": "prose"},
                {"data": {"k": "v"}},
                {"text": "   "},
                {"raw": "AAAA", "mediaType": "image/png"}
            ],
            "metadata": {"note": "ssn 123-45-6789", "count": 3}
        }});
        let slots = domain::request_slots(&params);
        let texts = domain::request_text_slots(&params);

        // Prose pass: the text part only — a metadata leaf is a machine value.
        let prose = inputs(&slots, &texts, "agent-x", true);
        assert_eq!(prose.len(), 1);
        assert_eq!(prose[0].classifiable, "prose");
        assert_eq!(prose[0].id, "p:0:0");
        assert_eq!(prose[0].target, "agent-x");

        // PII pass: the metadata leaf AND the `data` part's string leaf too —
        // data is just as gone whether it left in the prose, in a metadata
        // field, or in a structured payload. The non-string leaf is skipped.
        let all = inputs(&slots, &texts, "agent-x", false);
        assert_eq!(all.len(), 3);
        assert!(all.iter().any(|i| i.classifiable == "ssn 123-45-6789"));
        assert!(all.iter().any(|i| i.classifiable == "v"));
    }

    #[test]
    fn a_rewrite_lands_on_the_string_it_was_found_in() {
        let params = serde_json::json!({"message": {
            "parts": [{"text": "original"}],
            "metadata": {"note": "also original"}
        }});
        let mut s = domain::request_slots(&params);
        let mut t = domain::request_text_slots(&params);
        let mut rewrites = std::collections::HashMap::new();
        rewrites.insert("p:0:0".to_string(), "[withheld]".to_string());
        rewrites.insert("t:0".to_string(), "[redacted]".to_string());
        assert!(apply_rewrites(&mut s, &mut t, &rewrites));
        assert_eq!(
            s[0].parts[0],
            A2aPart::Text {
                text: "[withheld]".into(),
                media_type: None
            }
        );
        assert_eq!(t[0].text, "[redacted]");
        assert_eq!(t[0].pointer, "/message/metadata/note");
    }

    #[tokio::test]
    async fn an_inert_guardrail_is_a_no_op() {
        let settings = GuardrailSettings::default();
        let mut s = slots("anything");
        let mut t = Vec::new();
        // No classifier URL configured ⇒ `is_active()` is false; PII default-on
        // scans the request but finds nothing in this prose.
        let out = screen_request(&settings, &mut s, &mut t, "agent-x").await;
        assert!(out.badges.is_empty());
        assert!(out.steps.is_empty());
        assert!(!out.modified);
    }

    #[test]
    fn streamed_events_yield_the_text_the_agent_streamed() {
        let events = vec![
            serde_json::json!({"result": {"statusUpdate": {"taskId": "t", "status": {"message": {"parts": [{"text": "working"}]}}}}}),
            serde_json::json!({"result": {"artifactUpdate": {"taskId": "t", "artifact": {"parts": [{"text": "the answer"}]}}}}),
        ];
        let slots = slots_from_stream_events(&events);
        let text = domain::slots_text(&slots);
        assert!(text.contains("working") && text.contains("the answer"));
    }
}
