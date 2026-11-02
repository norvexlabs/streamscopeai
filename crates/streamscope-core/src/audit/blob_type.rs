//! Canonical blob-type taxonomy for `audit_media_blobs`.
//!
//! [`BlobType`] is the single source of truth for the `blob_type` discriminator
//! that keys every row in `audit_media_blobs` and every `blob_ref` audit block.
//! Four layers pivot on this exact value and MUST agree:
//!
//! 1. **Storage** — the proxy edge sync UPSERTs each blob row under `blob_type`.
//! 2. **Reference** — `media_call` / `chat_media_summary` `blob_ref` blocks
//!    carry it so the UI can build a fetch URL.
//! 3. **Serving** — `GET /audit/media/{hash}` looks the row up by
//!    `(content_hash, blob_type)`.
//! 4. **Retention** — each ingest renews the stamp of the `(content_hash,
//!    blob_type)` its records' `blob_ref`s name; the purge removes what was not
//!    renewed inside the window.
//!
//! When these disagree a referenced blob's stamp is never renewed and the purge
//! deletes it while an audit row still points at it. Routing the value through one typed enum makes the agreement
//! structural: a variant that does not exist cannot be emitted by one layer
//! and rejected by another.

use std::fmt;
use std::str::FromStr;

/// Discriminator for a row in `audit_media_blobs` and its `blob_ref` references.
///
/// Wire form is the `snake_case` of the variant — the strings stored in the DB
/// `blob_type` column, embedded in `blob_ref` JSON, and accepted by the
/// `?blob_type=` query param of the media-serving endpoint.
#[derive(
    Debug,
    Clone,
    Copy,
    PartialEq,
    Eq,
    Hash,
    serde::Serialize,
    serde::Deserialize,
    utoipa::ToSchema,
)]
#[serde(rename_all = "snake_case")]
pub enum BlobType {
    /// Media uploaded with a media-RPC request: audio for transcription /
    /// translation, the source image for an edit / variation.
    RequestUpload,
    /// Media produced by a media-RPC response: TTS audio, a generated image,
    /// a generated video.
    ResponseBody,
    /// Image embedded inline in a chat message.
    ChatImage,
    /// Audio embedded inline in a chat message.
    ChatAudio,
    /// Document embedded inline in a chat message.
    ChatDocument,
    /// Generic file embedded inline in a chat message.
    ChatFile,
    /// Image produced by the Responses `image_generation` built-in tool.
    ImageGenerationOutput,
}

impl BlobType {
    /// Every variant — the closed set the DB `CHECK` constraint enforces and
    /// the serving endpoint accepts.
    pub const ALL: [BlobType; 7] = [
        BlobType::RequestUpload,
        BlobType::ResponseBody,
        BlobType::ChatImage,
        BlobType::ChatAudio,
        BlobType::ChatDocument,
        BlobType::ChatFile,
        BlobType::ImageGenerationOutput,
    ];

    /// Wire form — the exact string stored in the `blob_type` column.
    pub const fn as_str(self) -> &'static str {
        match self {
            BlobType::RequestUpload => "request_upload",
            BlobType::ResponseBody => "response_body",
            BlobType::ChatImage => "chat_image",
            BlobType::ChatAudio => "chat_audio",
            BlobType::ChatDocument => "chat_document",
            BlobType::ChatFile => "chat_file",
            BlobType::ImageGenerationOutput => "image_generation_output",
        }
    }
}

impl fmt::Display for BlobType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Parse a wire string into a [`BlobType`]. The error carries the offending
/// value so callers can surface it (the serving endpoint's 400 response).
impl FromStr for BlobType {
    type Err = UnknownBlobType;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        BlobType::ALL
            .into_iter()
            .find(|bt| bt.as_str() == s)
            .ok_or_else(|| UnknownBlobType(s.to_string()))
    }
}

/// Names one stored blob: its content hash and type, the pair it is stored
/// under within its tenant.
#[derive(Clone, Debug, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize, utoipa::ToSchema)]
pub struct BlobRef {
    pub content_hash: String,
    pub blob_type: BlobType,
}

/// Returned by [`BlobType::from_str`] for an unrecognized wire string.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnknownBlobType(pub String);

impl fmt::Display for UnknownBlobType {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "unknown blob_type: {}", self.0)
    }
}

impl std::error::Error for UnknownBlobType {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_form_round_trips_through_from_str() {
        for bt in BlobType::ALL {
            assert_eq!(BlobType::from_str(bt.as_str()), Ok(bt));
        }
    }

    #[test]
    fn serde_form_matches_as_str() {
        for bt in BlobType::ALL {
            let json = serde_json::to_string(&bt).unwrap();
            assert_eq!(json, format!("\"{}\"", bt.as_str()));
            let back: BlobType = serde_json::from_str(&json).unwrap();
            assert_eq!(back, bt);
        }
    }

    #[test]
    fn legacy_media_names_are_rejected() {
        // `media_request` / `media_response` were divergent strings: a blob
        // stored under one and referenced under another is purged while still
        // referenced. They must never resolve to a variant again.
        assert!(BlobType::from_str("media_request").is_err());
        assert!(BlobType::from_str("media_response").is_err());
        assert!(BlobType::from_str("media_output").is_err());
    }
}
