//! The id of a Gemini function call the upstream left unidentified.
//!
//! A client pairs a call with its result by the call's id, and the audit row
//! records the id the client was given. A Gemini `functionCall`'s `id` is
//! optional — the Gemini API usually leaves it out, and its spec asks a client
//! to return the matching id only "if populated" — so the gateway gives such a
//! call one where it reads a Gemini answer: a stream's call as it opens
//! ([`crate::api::sse::StreamParser::identifying_calls`], with the frame a
//! pass-through client reads given it by [`give_call_ids`]), a whole answer
//! before anything reads it ([`settle_call_ids`]). Policy, the audit and every
//! client walk then read one id, and the session view pairs the call with the
//! result that names it.
//!
//! The other protocols' specs require every call's id, so their answers are
//! left as the upstream wrote them.
//!
//! The id is the gateway's alone: a body bound for a Gemini upstream goes
//! without it ([`without_gateway_call_ids`]), so a Gemini model is sent its
//! calls as it wrote them. Its prefix says it is the gateway's on the row.

use serde_json::Value;

/// What every id the gateway gives a call starts with.
const PREFIX: &str = "ssai_call_";

/// The id the gateway gives call `n` of request `request_id`'s answer — the
/// stream's number for the call, or its place among a whole answer's calls.
/// The whole request id, in URL-safe base64, keeps it unique and short: a
/// conversation carrying it on to an OpenAI model must stay within the 40
/// characters OpenAI takes for a tool call's id (`ssai_call_` + 22 + `_n`).
pub fn gateway_call_id(request_id: uuid::Uuid, n: usize) -> String {
    use base64::Engine;
    format!("{PREFIX}{}_{n}", base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(request_id.as_bytes()))
}

/// Whether `id` is one the gateway gave a call.
fn is_gateway_call_id(id: &str) -> bool {
    id.starts_with(PREFIX)
}

/// Give a Gemini stream frame's calls the ids the stream's reader settled for
/// them. `minted` holds `(k, id)` for each call the frame opened with no id:
/// `k` is the call's place among the frame's calls, as the stream's parse
/// reads them ([`crate::api::sse::gemini_stream_part_is_call`]).
pub fn give_call_ids(event: &mut crate::api::sse::SseEvent, minted: &[(usize, String)]) {
    if minted.is_empty() {
        return;
    }
    let Ok(mut data) = serde_json::from_str::<Value>(&event.data) else {
        return;
    };
    let Some(parts) = data.pointer_mut("/candidates/0/content/parts").and_then(Value::as_array_mut) else {
        return;
    };
    let calls = parts
        .iter_mut()
        .filter(|p| crate::api::sse::gemini_stream_part_is_call(p))
        .filter_map(|p| p.get_mut("functionCall"));
    for (k, call) in calls.enumerate() {
        if !call.is_object() {
            continue;
        }
        if let Some((_, id)) = minted.iter().find(|(at, _)| *at == k) {
            call["id"] = Value::String(id.clone());
        }
    }
    if let Ok(rewritten) = serde_json::to_string(&data) {
        event.data = rewritten;
    }
}

/// Give each function call of a whole Gemini answer that has no id (or an
/// empty one) the gateway's, numbered by its place among the answer's calls
/// from `from` — after an agent loop's earlier rounds'. A call is a part
/// holding a `functionCall`, as every whole-answer reader — the audit's, tool
/// policy's — reads one. Returns the number the next round's calls start from.
pub fn settle_call_ids(answer: &mut Value, request_id: uuid::Uuid, from: usize) -> usize {
    let mut n = from;
    for candidate in answer.get_mut("candidates").and_then(Value::as_array_mut).into_iter().flatten() {
        let parts = candidate.pointer_mut("/content/parts").and_then(Value::as_array_mut);
        for call in parts.into_iter().flatten().filter_map(|p| p.get_mut("functionCall")).filter(|c| c.is_object()) {
            // No id, or an empty one: a call with an id of another type is
            // left to the readers that refuse it, as the stream's parse does.
            let unidentified = match call.get("id") {
                None | Some(Value::Null) => true,
                Some(Value::String(id)) => id.is_empty(),
                Some(_) => false,
            };
            if unidentified {
                call["id"] = Value::String(gateway_call_id(request_id, n));
            }
            n += 1;
        }
    }
    n
}

/// A Gemini request body as the upstream is sent it: without an id the
/// gateway gave a call — on the call, and on the response that names it. The
/// body is read only when it holds one.
pub fn without_gateway_call_ids(body: bytes::Bytes) -> bytes::Bytes {
    if memchr::memmem::find(&body, PREFIX.as_bytes()).is_none() {
        return body;
    }
    let Ok(mut request) = serde_json::from_slice::<Value>(&body) else {
        return body;
    };
    let mut stripped = false;
    for content in request.get_mut("contents").and_then(Value::as_array_mut).into_iter().flatten() {
        for part in content.get_mut("parts").and_then(Value::as_array_mut).into_iter().flatten() {
            let Some(part) = part.as_object_mut() else { continue };
            for key in ["functionCall", "function_call", "functionResponse", "function_response"] {
                if let Some(member) = part.get_mut(key).and_then(Value::as_object_mut)
                    && member.get("id").and_then(Value::as_str).is_some_and(is_gateway_call_id)
                {
                    member.remove("id");
                    stripped = true;
                }
            }
        }
    }
    if !stripped {
        return body;
    }
    serde_json::to_vec(&request).map(bytes::Bytes::from).unwrap_or(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::sse::SseEvent;
    use serde_json::json;

    const RID: uuid::Uuid = uuid::Uuid::from_u128(0x0190_a0b0_c0d0_7000_8000_0000_0000_0001);

    fn id(n: usize) -> String {
        gateway_call_id(RID, n)
    }

    /// The id stays within the 40 characters OpenAI takes for a tool call's
    /// id, for any call number a request reaches, and names the request whole.
    #[test]
    fn a_gateway_id_is_short_enough_for_every_protocol_and_unique_per_request() {
        let longest = gateway_call_id(uuid::Uuid::max(), 9_999_999);
        assert!(longest.len() <= 40, "{longest} is {} characters", longest.len());
        assert!(longest.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'), "{longest}");
        assert_ne!(gateway_call_id(RID, 0), gateway_call_id(uuid::Uuid::from_u128(RID.as_u128() + 1), 0));
        assert_ne!(gateway_call_id(RID, 1), gateway_call_id(RID, 11));
    }

    #[test]
    fn a_whole_answer_gives_each_unidentified_client_call_the_gateways_id_by_its_place() {
        let mut answer = json!({"candidates": [{"content": {"role": "model", "parts": [
            {"text": "t"},
            {"functionCall": {"name": "a", "args": {}}},
            {"functionCall": {"id": "own", "name": "b", "args": {}}},
            {"functionCall": {"id": "", "name": "c", "args": {}}, "thoughtSignature": "s"},
            {"functionCall": {"id": 7, "name": "e", "args": {}}}]}},
            {"content": {"role": "model", "parts": [{"functionCall": {"name": "d", "args": {}}}]}}]});
        let next = settle_call_ids(&mut answer, RID, 0);
        assert_eq!(answer, json!({"candidates": [{"content": {"role": "model", "parts": [
            {"text": "t"},
            {"functionCall": {"id": id(0), "name": "a", "args": {}}},
            {"functionCall": {"id": "own", "name": "b", "args": {}}},
            {"functionCall": {"id": id(2), "name": "c", "args": {}}, "thoughtSignature": "s"},
            {"functionCall": {"id": 7, "name": "e", "args": {}}}]}},
            {"content": {"role": "model", "parts": [{"functionCall": {"id": id(4), "name": "d", "args": {}}}]}}]}));
        assert_eq!(next, 5);
        // An agent loop's later round numbers its calls after the earlier ones'.
        let mut later = json!({"candidates": [{"content": {"parts": [{"functionCall": {"name": "a"}}]}}]});
        assert_eq!(settle_call_ids(&mut later, RID, 4), 5);
        assert_eq!(later["candidates"][0]["content"]["parts"][0]["functionCall"]["id"], id(4));
    }

    #[test]
    fn a_frame_gives_each_call_it_opened_with_no_id_the_settled_one() {
        let frame = |data: Value| SseEvent { event_type: None, data: data.to_string(), id: None };
        let mut event = frame(json!({"candidates": [{"content": {"parts": [
            {"text": "t"},
            // A thought is no call, whatever else the part carries.
            {"thought": true, "text": "planned", "functionCall": {"name": "x"}},
            {"functionCall": {"name": "a"}}, {"functionCall": {"id": "own", "name": "b"}},
            {"functionCall": {"name": "c"}}]}}]}));
        give_call_ids(&mut event, &[(0, id(4)), (2, id(5))]);
        assert_eq!(serde_json::from_str::<Value>(&event.data).unwrap(), json!({"candidates": [{"content": {"parts": [
            {"text": "t"},
            {"thought": true, "text": "planned", "functionCall": {"name": "x"}},
            {"functionCall": {"id": id(4), "name": "a"}}, {"functionCall": {"id": "own", "name": "b"}},
            {"functionCall": {"id": id(5), "name": "c"}}]}}]}));
        // A `functionCall` that is no object is given nothing, never a panic.
        let mut odd = frame(json!({"candidates": [{"content": {"parts": [{"functionCall": [null, "a", {}]}]}}]}));
        give_call_ids(&mut odd, &[(0, id(0))]);
        // Positive control: a frame no call opened in is left byte for byte.
        let mut untouched = frame(json!({"candidates": [{"content": {"parts": [{"text": "x"}]}}]}));
        let before = untouched.data.clone();
        give_call_ids(&mut untouched, &[]);
        assert_eq!(untouched.data, before);
    }

    #[test]
    fn a_gemini_upstream_is_sent_its_calls_without_the_gateways_ids() {
        let body = json!({"contents": [
            {"role": "model", "parts": [
                {"functionCall": {"id": id(0), "name": "a", "args": {}}, "thoughtSignature": "s"},
                {"functionCall": {"id": "own", "name": "b", "args": {}}}]},
            {"role": "user", "parts": [
                {"functionResponse": {"id": id(0), "name": "a", "response": {}}},
                {"function_response": {"id": "own", "name": "b", "response": {}}}]}]});
        let sent: Value = serde_json::from_slice(&without_gateway_call_ids(body.to_string().into())).unwrap();
        assert_eq!(sent, json!({"contents": [
            {"role": "model", "parts": [
                {"functionCall": {"name": "a", "args": {}}, "thoughtSignature": "s"},
                {"functionCall": {"id": "own", "name": "b", "args": {}}}]},
            {"role": "user", "parts": [
                {"functionResponse": {"name": "a", "response": {}}},
                {"function_response": {"id": "own", "name": "b", "response": {}}}]}]}));
        // Positive control: a body with no gateway id goes as it came, byte for byte.
        let own = bytes::Bytes::from(r#"{"contents":[{"role":"model","parts":[{"functionCall":{"id":"own","name":"b"}}]}]}"#);
        assert_eq!(without_gateway_call_ids(own.clone()), own);
    }
}
