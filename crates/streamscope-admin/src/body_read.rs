//! Reading a request body under a limit — shared by the edge endpoints and the
//! audit layers, so "read under a limit" and "read through, discarding" each
//! have one implementation.

use axum::body::BodyDataStream;
use futures::StreamExt;

/// The body read so far plus the rest, or `None` once it passes `limit`
/// (`expected` sizes the buffer). A body that fails to arrive is an error,
/// never "too large".
pub async fn read_capped(stream: &mut BodyDataStream, limit: usize, expected: usize) -> Result<Option<Vec<u8>>, axum::Error> {
    let mut data = Vec::with_capacity(expected.min(limit));
    while let Some(chunk) = stream.next().await {
        let chunk = chunk?;
        if data.len() + chunk.len() > limit {
            return Ok(None);
        }
        data.extend_from_slice(&chunk);
    }
    Ok(Some(data))
}

/// Read a body on to its end, up to `limit` more bytes, keeping none of it.
pub async fn read_through(stream: &mut BodyDataStream, limit: usize) -> Result<(), axum::Error> {
    let mut read = 0usize;
    while let Some(chunk) = stream.next().await {
        read += chunk?.len();
        if read > limit {
            break;
        }
    }
    Ok(())
}
