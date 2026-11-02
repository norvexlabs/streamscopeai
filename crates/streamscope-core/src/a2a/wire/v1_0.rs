//! A2A 1.0.1 JSON codec (ProtoJSON shapes: camelCase fields,
//! SCREAMING_SNAKE_CASE enums, member-presence oneofs — no `kind`
//! discriminators). Parsing is tolerant per spec § 5.7: unrecognized fields
//! are ignored on typed reads, and unrecognizable oneof shapes degrade to
//! `Unknown(value)` — never a silent drop. Emit produces spec-shaped JSON
//! (used by round-trips and the future dialect translation).

use serde_json::{json, Map, Value};

use crate::a2a::model::{
    A2aArtifact, A2aMessage, A2aPart, A2aRole, A2aStreamEvent, A2aTask, A2aTaskState,
    A2aTaskStatus,
};

// ── enums ────────────────────────────────────────────────────────────────────

pub fn parse_role(s: &str) -> Option<A2aRole> {
    match s {
        "ROLE_USER" => Some(A2aRole::User),
        "ROLE_AGENT" => Some(A2aRole::Agent),
        _ => None,
    }
}

pub fn emit_role(role: A2aRole) -> &'static str {
    match role {
        A2aRole::User => "ROLE_USER",
        A2aRole::Agent => "ROLE_AGENT",
    }
}

pub fn parse_task_state(s: &str) -> A2aTaskState {
    match s {
        "TASK_STATE_SUBMITTED" => A2aTaskState::Submitted,
        "TASK_STATE_WORKING" => A2aTaskState::Working,
        "TASK_STATE_COMPLETED" => A2aTaskState::Completed,
        "TASK_STATE_FAILED" => A2aTaskState::Failed,
        "TASK_STATE_CANCELED" => A2aTaskState::Canceled,
        "TASK_STATE_REJECTED" => A2aTaskState::Rejected,
        "TASK_STATE_INPUT_REQUIRED" => A2aTaskState::InputRequired,
        "TASK_STATE_AUTH_REQUIRED" => A2aTaskState::AuthRequired,
        other => A2aTaskState::Other(other.to_string()),
    }
}

pub fn emit_task_state(state: &A2aTaskState) -> String {
    match state {
        A2aTaskState::Submitted => "TASK_STATE_SUBMITTED".into(),
        A2aTaskState::Working => "TASK_STATE_WORKING".into(),
        A2aTaskState::Completed => "TASK_STATE_COMPLETED".into(),
        A2aTaskState::Failed => "TASK_STATE_FAILED".into(),
        A2aTaskState::Canceled => "TASK_STATE_CANCELED".into(),
        A2aTaskState::Rejected => "TASK_STATE_REJECTED".into(),
        A2aTaskState::InputRequired => "TASK_STATE_INPUT_REQUIRED".into(),
        A2aTaskState::AuthRequired => "TASK_STATE_AUTH_REQUIRED".into(),
        A2aTaskState::Other(s) => s.clone(),
    }
}

// ── small access helpers ─────────────────────────────────────────────────────

fn str_field(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}

fn str_vec(v: &Value, key: &str) -> Vec<String> {
    v.get(key)
        .and_then(Value::as_array)
        .map(|a| {
            a.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

// ── Part (oneof text | raw | url | data) ─────────────────────────────────────

/// The oneof member is identified by presence. Exactly one content member
/// must be present; zero or several ⇒ the whole value is preserved as
/// `Unknown` (spec-invalid shapes must survive into audit, not vanish).
pub fn parse_part(v: &Value) -> A2aPart {
    let media_type = str_field(v, "mediaType");
    let filename = str_field(v, "filename");
    let members = [
        v.get("text").is_some(),
        v.get("raw").is_some(),
        v.get("url").is_some(),
        v.get("data").is_some(),
    ];
    if members.iter().filter(|m| **m).count() != 1 {
        return A2aPart::Unknown(v.clone());
    }
    if let Some(text) = v.get("text").and_then(Value::as_str) {
        A2aPart::Text {
            text: text.to_string(),
            media_type,
        }
    } else if let Some(raw) = v.get("raw").and_then(Value::as_str) {
        A2aPart::Raw {
            base64: raw.to_string(),
            media_type,
            filename,
        }
    } else if let Some(url) = v.get("url").and_then(Value::as_str) {
        A2aPart::Url {
            url: url.to_string(),
            media_type,
            filename,
        }
    } else if let Some(data) = v.get("data") {
        A2aPart::Data {
            data: data.clone(),
            media_type,
        }
    } else {
        // A present member of the wrong JSON type (e.g. numeric `text`).
        A2aPart::Unknown(v.clone())
    }
}

pub fn emit_part(part: &A2aPart) -> Value {
    fn base(media_type: &Option<String>, filename: &Option<String>) -> Map<String, Value> {
        let mut m = Map::new();
        if let Some(mt) = media_type {
            m.insert("mediaType".into(), json!(mt));
        }
        if let Some(f) = filename {
            m.insert("filename".into(), json!(f));
        }
        m
    }
    match part {
        A2aPart::Text { text, media_type } => {
            let mut m = base(media_type, &None);
            m.insert("text".into(), json!(text));
            Value::Object(m)
        }
        A2aPart::Raw {
            base64,
            media_type,
            filename,
        } => {
            let mut m = base(media_type, filename);
            m.insert("raw".into(), json!(base64));
            Value::Object(m)
        }
        A2aPart::Url {
            url,
            media_type,
            filename,
        } => {
            let mut m = base(media_type, filename);
            m.insert("url".into(), json!(url));
            Value::Object(m)
        }
        A2aPart::Data { data, media_type } => {
            let mut m = base(media_type, &None);
            m.insert("data".into(), data.clone());
            Value::Object(m)
        }
        A2aPart::Unknown(v) => v.clone(),
    }
}

// ── Message ──────────────────────────────────────────────────────────────────

/// `None` when required fields (`messageId`, `role`, `parts`) are missing or
/// malformed — the caller decides between an `InvalidParams` reply (inbound
/// client message) and `Unknown` preservation (upstream stream event).
pub fn parse_message(v: &Value) -> Option<A2aMessage> {
    let message_id = str_field(v, "messageId")?;
    let role = parse_role(v.get("role").and_then(Value::as_str)?)?;
    let parts = v
        .get("parts")
        .and_then(Value::as_array)?
        .iter()
        .map(parse_part)
        .collect();
    Some(A2aMessage {
        message_id,
        context_id: str_field(v, "contextId"),
        task_id: str_field(v, "taskId"),
        role,
        parts,
        extensions: str_vec(v, "extensions"),
        reference_task_ids: str_vec(v, "referenceTaskIds"),
        metadata: v.get("metadata").cloned(),
    })
}

pub fn emit_message(m: &A2aMessage) -> Value {
    let mut obj = Map::new();
    obj.insert("messageId".into(), json!(m.message_id));
    obj.insert("role".into(), json!(emit_role(m.role)));
    obj.insert(
        "parts".into(),
        Value::Array(m.parts.iter().map(emit_part).collect()),
    );
    if let Some(cid) = &m.context_id {
        obj.insert("contextId".into(), json!(cid));
    }
    if let Some(tid) = &m.task_id {
        obj.insert("taskId".into(), json!(tid));
    }
    if !m.extensions.is_empty() {
        obj.insert("extensions".into(), json!(m.extensions));
    }
    if !m.reference_task_ids.is_empty() {
        obj.insert("referenceTaskIds".into(), json!(m.reference_task_ids));
    }
    if let Some(md) = &m.metadata {
        obj.insert("metadata".into(), md.clone());
    }
    Value::Object(obj)
}

// ── Artifact / TaskStatus / Task ─────────────────────────────────────────────

pub fn parse_artifact(v: &Value) -> Option<A2aArtifact> {
    let artifact_id = str_field(v, "artifactId")?;
    let parts = v
        .get("parts")
        .and_then(Value::as_array)?
        .iter()
        .map(parse_part)
        .collect();
    Some(A2aArtifact {
        artifact_id,
        name: str_field(v, "name"),
        description: str_field(v, "description"),
        parts,
        extensions: str_vec(v, "extensions"),
        metadata: v.get("metadata").cloned(),
    })
}

pub fn emit_artifact(a: &A2aArtifact) -> Value {
    let mut obj = Map::new();
    obj.insert("artifactId".into(), json!(a.artifact_id));
    obj.insert(
        "parts".into(),
        Value::Array(a.parts.iter().map(emit_part).collect()),
    );
    if let Some(name) = &a.name {
        obj.insert("name".into(), json!(name));
    }
    if let Some(d) = &a.description {
        obj.insert("description".into(), json!(d));
    }
    if !a.extensions.is_empty() {
        obj.insert("extensions".into(), json!(a.extensions));
    }
    if let Some(md) = &a.metadata {
        obj.insert("metadata".into(), md.clone());
    }
    Value::Object(obj)
}

pub fn parse_task_status(v: &Value) -> Option<A2aTaskStatus> {
    let state = parse_task_state(v.get("state").and_then(Value::as_str)?);
    Some(A2aTaskStatus {
        state,
        message: v.get("message").and_then(parse_message).map(Box::new),
        timestamp: str_field(v, "timestamp"),
    })
}

pub fn emit_task_status(s: &A2aTaskStatus) -> Value {
    let mut obj = Map::new();
    obj.insert("state".into(), json!(emit_task_state(&s.state)));
    if let Some(m) = &s.message {
        obj.insert("message".into(), emit_message(m));
    }
    if let Some(ts) = &s.timestamp {
        obj.insert("timestamp".into(), json!(ts));
    }
    Value::Object(obj)
}

pub fn parse_task(v: &Value) -> Option<A2aTask> {
    let id = str_field(v, "id")?;
    let status = parse_task_status(v.get("status")?)?;
    let artifacts = v
        .get("artifacts")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(parse_artifact).collect())
        .unwrap_or_default();
    let history = v
        .get("history")
        .and_then(Value::as_array)
        .map(|a| a.iter().filter_map(parse_message).collect())
        .unwrap_or_default();
    Some(A2aTask {
        id,
        context_id: str_field(v, "contextId"),
        status,
        artifacts,
        history,
        metadata: v.get("metadata").cloned(),
    })
}

pub fn emit_task(t: &A2aTask) -> Value {
    let mut obj = Map::new();
    obj.insert("id".into(), json!(t.id));
    obj.insert("status".into(), emit_task_status(&t.status));
    if let Some(cid) = &t.context_id {
        obj.insert("contextId".into(), json!(cid));
    }
    if !t.artifacts.is_empty() {
        obj.insert(
            "artifacts".into(),
            Value::Array(t.artifacts.iter().map(emit_artifact).collect()),
        );
    }
    if !t.history.is_empty() {
        obj.insert(
            "history".into(),
            Value::Array(t.history.iter().map(emit_message).collect()),
        );
    }
    if let Some(md) = &t.metadata {
        obj.insert("metadata".into(), md.clone());
    }
    Value::Object(obj)
}

// ── StreamResponse (oneof task | message | statusUpdate | artifactUpdate) ────

/// Also parses the non-streaming `SendMessage` result (its `task`/`message`
/// members are the same oneof prefix). Unrecognizable ⇒ `Unknown` (lossless).
pub fn parse_stream_response(v: &Value) -> A2aStreamEvent {
    let members = [
        v.get("task").is_some(),
        v.get("message").is_some(),
        v.get("statusUpdate").is_some(),
        v.get("artifactUpdate").is_some(),
    ];
    if members.iter().filter(|m| **m).count() != 1 {
        return A2aStreamEvent::Unknown(v.clone());
    }
    if let Some(t) = v.get("task") {
        return match parse_task(t) {
            Some(task) => A2aStreamEvent::Task(task),
            None => A2aStreamEvent::Unknown(v.clone()),
        };
    }
    if let Some(m) = v.get("message") {
        return match parse_message(m) {
            Some(msg) => A2aStreamEvent::Message(msg),
            None => A2aStreamEvent::Unknown(v.clone()),
        };
    }
    if let Some(su) = v.get("statusUpdate") {
        if let (Some(task_id), Some(status)) = (
            str_field(su, "taskId"),
            su.get("status").and_then(parse_task_status),
        ) {
            return A2aStreamEvent::StatusUpdate {
                task_id,
                context_id: str_field(su, "contextId"),
                status,
            };
        }
        return A2aStreamEvent::Unknown(v.clone());
    }
    if let Some(au) = v.get("artifactUpdate") {
        if let (Some(task_id), Some(artifact)) = (
            str_field(au, "taskId"),
            au.get("artifact").and_then(parse_artifact),
        ) {
            return A2aStreamEvent::ArtifactUpdate {
                task_id,
                context_id: str_field(au, "contextId"),
                artifact,
                append: au.get("append").and_then(Value::as_bool).unwrap_or(false),
                last_chunk: au
                    .get("lastChunk")
                    .and_then(Value::as_bool)
                    .unwrap_or(false),
            };
        }
        return A2aStreamEvent::Unknown(v.clone());
    }
    A2aStreamEvent::Unknown(v.clone())
}

pub fn emit_stream_response(e: &A2aStreamEvent) -> Value {
    match e {
        A2aStreamEvent::Task(t) => json!({ "task": emit_task(t) }),
        A2aStreamEvent::Message(m) => json!({ "message": emit_message(m) }),
        A2aStreamEvent::StatusUpdate {
            task_id,
            context_id,
            status,
        } => {
            let mut su = Map::new();
            su.insert("taskId".into(), json!(task_id));
            if let Some(cid) = context_id {
                su.insert("contextId".into(), json!(cid));
            }
            su.insert("status".into(), emit_task_status(status));
            json!({ "statusUpdate": Value::Object(su) })
        }
        A2aStreamEvent::ArtifactUpdate {
            task_id,
            context_id,
            artifact,
            append,
            last_chunk,
        } => {
            let mut au = Map::new();
            au.insert("taskId".into(), json!(task_id));
            if let Some(cid) = context_id {
                au.insert("contextId".into(), json!(cid));
            }
            au.insert("artifact".into(), emit_artifact(artifact));
            if *append {
                au.insert("append".into(), json!(true));
            }
            if *last_chunk {
                au.insert("lastChunk".into(), json!(true));
            }
            json!({ "artifactUpdate": Value::Object(au) })
        }
        A2aStreamEvent::Unknown(v) => v.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn part_oneof_by_member_presence() {
        assert_matches!(
            parse_part(&json!({"text": "Hello", "mediaType": "text/plain"})),
            A2aPart::Text { text, media_type: Some(mt) } if text == "Hello" && mt == "text/plain"
        );
        assert_matches!(
            parse_part(&json!({"raw": "aGk=", "filename": "x.bin", "mediaType": "application/octet-stream"})),
            A2aPart::Raw { base64, .. } if base64 == "aGk="
        );
        assert_matches!(
            parse_part(&json!({"url": "https://example.com/doc.pdf", "mediaType": "application/pdf"})),
            A2aPart::Url { url, .. } if url == "https://example.com/doc.pdf"
        );
        assert_matches!(
            parse_part(&json!({"data": {"k": "v"}, "mediaType": "application/json"})),
            A2aPart::Data { .. }
        );
    }

    #[test]
    fn ambiguous_or_empty_part_is_preserved_as_unknown() {
        // Two content members present — spec-invalid; must survive losslessly.
        let both = json!({"text": "hi", "data": {"k": 1}});
        assert_matches!(parse_part(&both), A2aPart::Unknown(v) if v == both);
        let none = json!({"mediaType": "text/plain"});
        assert_matches!(parse_part(&none), A2aPart::Unknown(_));
        // Wrong JSON type in the sole member.
        assert_matches!(parse_part(&json!({"text": 42})), A2aPart::Unknown(_));
    }

    #[test]
    fn message_round_trip() {
        let wire = json!({
            "messageId": "msg-1",
            "role": "ROLE_USER",
            "contextId": "ctx-1",
            "taskId": "task-1",
            "parts": [{"text": "Analyze this"}, {"data": {"depth": 3}, "mediaType": "application/json"}],
            "extensions": ["https://example.com/ext/v1"],
            "referenceTaskIds": ["task-0"],
            "metadata": {"k": "v"}
        });
        let msg = parse_message(&wire).expect("parses");
        assert_eq!(msg.role, A2aRole::User);
        assert_eq!(msg.parts.len(), 2);
        let re = emit_message(&msg);
        assert_eq!(parse_message(&re), Some(msg));
    }

    #[test]
    fn message_missing_required_fields_is_none() {
        assert_eq!(parse_message(&json!({"role": "ROLE_USER", "parts": []})), None);
        assert_eq!(
            parse_message(&json!({"messageId": "m", "role": "ROLE_OTHER", "parts": []})),
            None
        );
        assert_eq!(parse_message(&json!({"messageId": "m", "role": "ROLE_USER"})), None);
    }

    #[test]
    fn task_states_parse_and_unknown_is_preserved() {
        assert_eq!(parse_task_state("TASK_STATE_COMPLETED"), A2aTaskState::Completed);
        assert!(parse_task_state("TASK_STATE_FAILED").is_terminal());
        assert!(!parse_task_state("TASK_STATE_INPUT_REQUIRED").is_terminal());
        assert_matches!(
            parse_task_state("TASK_STATE_SOMETHING_NEW"),
            A2aTaskState::Other(s) if s == "TASK_STATE_SOMETHING_NEW"
        );
    }

    #[test]
    fn stream_response_oneof_round_trip() {
        let status = json!({
            "statusUpdate": {
                "taskId": "t1",
                "contextId": "c1",
                "status": {"state": "TASK_STATE_WORKING", "timestamp": "2026-03-15T10:15:00.000Z"}
            }
        });
        let ev = parse_stream_response(&status);
        assert_matches!(&ev, A2aStreamEvent::StatusUpdate { task_id, .. } if task_id == "t1");
        assert_eq!(parse_stream_response(&emit_stream_response(&ev)), ev);

        let artifact = json!({
            "artifactUpdate": {
                "taskId": "t1",
                "artifact": {"artifactId": "a1", "parts": [{"text": "result"}]},
                "append": true,
                "lastChunk": true
            }
        });
        let ev = parse_stream_response(&artifact);
        assert_matches!(
            &ev,
            A2aStreamEvent::ArtifactUpdate { append: true, last_chunk: true, .. }
        );
        assert_eq!(parse_stream_response(&emit_stream_response(&ev)), ev);

        let task = json!({
            "task": {
                "id": "t1",
                "contextId": "c1",
                "status": {"state": "TASK_STATE_SUBMITTED"}
            }
        });
        assert_matches!(parse_stream_response(&task), A2aStreamEvent::Task(t) if t.id == "t1");
    }

    #[test]
    fn stream_response_ambiguous_is_unknown() {
        let both = json!({"task": {"id": "t"}, "message": {"messageId": "m"}});
        assert_matches!(parse_stream_response(&both), A2aStreamEvent::Unknown(v) if v == both);
        assert_matches!(parse_stream_response(&json!({})), A2aStreamEvent::Unknown(_));
    }

    #[test]
    fn correlators_extracted_from_events() {
        let ev = parse_stream_response(&json!({
            "statusUpdate": {"taskId": "t9", "contextId": "c9",
                             "status": {"state": "TASK_STATE_COMPLETED"}}
        }));
        let (ctx, task, state) = ev.correlators();
        assert_eq!(ctx, Some("c9"));
        assert_eq!(task, Some("t9"));
        assert_eq!(state, Some(&A2aTaskState::Completed));
    }
}
