//! `mcp_sse_events` row record — serialized over the proxy→admin-api
//! `mcp_sse_event_batch` envelope and inserted into the partitioned
//! `mcp_sse_events` table.
//!
//! One row per server-initiated MCP event surfaced on the long-lived
//! `GET /mcp/<slug>` channel. The proxy mints a stable `ssevt.…` event id
//! at the SSE pump and persists `(tenant_id, mcp_session_id, sequence,
//! event_data)` here; on `Last-Event-ID` reconnect any proxy replica
//! `SELECT … WHERE sequence > X` and replays the rows verbatim.

use serde::{Deserialize, Serialize};

/// One SSE event row. `event_data` is the encoded SSE frame
/// (`event: …\nid: …\ndata: …\n\n`) ready to forward verbatim on a resumed
/// connection. Bytes are base64-encoded over the wire (serde default for
/// `Vec<u8>` is a JSON array; explicit base64 keeps the envelope compact).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct McpSseEventRecord {
    pub tenant_id: uuid::Uuid,
    pub user_id: uuid::Uuid,
    pub mcp_session_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub virtual_server_id: Option<uuid::Uuid>,
    pub event_id: String,
    pub sequence: i64,
    /// Encoded SSE wire bytes. Serialized as base64 to keep the JSON
    /// envelope compact (the wire frame is mostly ASCII but may contain
    /// embedded newlines and `\` bytes).
    #[serde(with = "base64_bytes")]
    pub event_data: Vec<u8>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

mod base64_bytes {
    use base64::Engine;
    use serde::{Deserialize, Deserializer, Serializer};

    const B64: base64::engine::GeneralPurpose = base64::engine::general_purpose::STANDARD;

    pub fn serialize<S: Serializer>(bytes: &[u8], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&B64.encode(bytes))
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(d)?;
        B64.decode(s.as_bytes()).map_err(serde::de::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(event_data: Vec<u8>) -> McpSseEventRecord {
        McpSseEventRecord {
            tenant_id: uuid::Uuid::nil(),
            user_id: uuid::Uuid::nil(),
            mcp_session_id: "sess-1".to_string(),
            virtual_server_id: None,
            event_id: "ssevt.7".to_string(),
            sequence: 7,
            event_data,
            created_at: chrono::DateTime::from_timestamp(0, 0).unwrap(),
        }
    }

    /// `event_data` is an encoded SSE frame that gets forwarded VERBATIM on a
    /// `Last-Event-ID` resume, so the envelope has to carry arbitrary bytes
    /// unchanged — embedded newlines, backslashes, and sequences that are not
    /// valid UTF-8 at all. Base64 is what makes that true; serde's default for
    /// `Vec<u8>` would emit a JSON array of numbers instead, which round-trips
    /// but multiplies the envelope.
    #[test]
    fn an_sse_event_round_trips_bytes_that_are_not_text() {
        let raw = b"event: message\nid: ssevt.7\ndata: {\"a\":\"\\\\ \xff\xfe\"}\n\n".to_vec();
        let wire = serde_json::to_value(record(raw.clone())).unwrap();

        assert!(
            wire["event_data"].is_string(),
            "the bytes ride as one base64 string, not a JSON array"
        );

        let back: McpSseEventRecord = serde_json::from_value(wire).unwrap();
        assert_eq!(back.event_data, raw);
        assert_eq!(back.sequence, 7);
        assert_eq!(back.event_id, "ssevt.7");
        assert_eq!(back.mcp_session_id, "sess-1");
    }

    /// An empty frame is a legitimate value, and the optional virtual-server id
    /// is omitted rather than sent as null — both halves of the `skip_serializing_if`.
    #[test]
    fn an_absent_virtual_server_is_omitted_from_the_envelope() {
        let wire = serde_json::to_value(record(Vec::new())).unwrap();
        assert!(wire.get("virtual_server_id").is_none());
        let back: McpSseEventRecord = serde_json::from_value(wire).unwrap();
        assert!(back.virtual_server_id.is_none());
        assert!(back.event_data.is_empty());

        let vs = uuid::Uuid::from_u128(42);
        let with_vs = McpSseEventRecord {
            virtual_server_id: Some(vs),
            ..record(b"x".to_vec())
        };
        let wire = serde_json::to_value(&with_vs).unwrap();
        assert_eq!(wire["virtual_server_id"], serde_json::json!(vs));
    }

    /// A corrupt payload must FAIL the decode. Falling back to empty bytes
    /// would replay a resumed client an empty frame in place of the event it
    /// asked for, and nothing downstream can tell those apart.
    #[test]
    fn a_corrupt_payload_fails_rather_than_decoding_to_nothing() {
        let mut wire = serde_json::to_value(record(b"hello".to_vec())).unwrap();
        wire["event_data"] = serde_json::json!("!!!not base64!!!");
        assert!(serde_json::from_value::<McpSseEventRecord>(wire).is_err());
    }
}
