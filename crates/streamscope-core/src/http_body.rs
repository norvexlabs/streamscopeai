//! Bounded response-body reader shared by every proxy egress path.
//!
//! A hostile, buggy, or compromised upstream (LLM provider, BYOK backend,
//! search engine, guardrail classifier) can return an arbitrarily large body.
//! Reading it whole with `reqwest::Response::bytes()`/`.text()`/`.json()` lets
//! that body OOM the shared edge process and take down every tenant on the
//! replica. [`read_body_capped`] streams the body instead, aborting the moment
//! the cumulative length crosses the caller's per-surface cap and dropping the
//! response (cancelling the underlying TCP connection) — so a target
//! advertising a huge `Content-Length` never makes the gateway buffer it.
//!
//! Every caller passes a cap appropriate to its surface (LLM responses, media,
//! error bodies, search, classifier); there is deliberately no single global
//! cap, because the right bound differs by an order of magnitude across them.

use bytes::{Bytes, BytesMut};

/// Failure reading a capped response body.
#[derive(Debug, thiserror::Error)]
pub enum CappedReadError {
    /// The body crossed the byte cap before the stream ended.
    #[error("response body exceeds the {limit_bytes}-byte cap")]
    Oversized { limit_bytes: u64 },
    /// A transport error surfaced while streaming the body.
    #[error("failed to read response body: {0}")]
    Transport(#[from] reqwest::Error),
}

/// Stream `resp`'s body, accumulating up to `cap` bytes. The moment the
/// cumulative length would exceed `cap` the read aborts with
/// [`CappedReadError::Oversized`] and `resp` is dropped, cancelling the TCP
/// connection instead of finishing the download.
pub async fn read_body_capped(
    resp: reqwest::Response,
    cap: u64,
) -> Result<Bytes, CappedReadError> {
    let mut buf = BytesMut::with_capacity(
        resp.content_length()
            .map(|n| n.min(cap.saturating_add(1)) as usize)
            .unwrap_or(8192),
    );
    let mut stream = resp;
    while let Some(chunk) = stream.chunk().await? {
        if buf.len() as u64 + chunk.len() as u64 > cap {
            return Err(CappedReadError::Oversized { limit_bytes: cap });
        }
        buf.extend_from_slice(&chunk);
    }
    Ok(buf.freeze())
}
