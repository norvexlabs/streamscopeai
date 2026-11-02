//! The listeners the binaries serve on.

use axum::serve::{ListenerExt, TapIo};

/// A TCP listener whose every accepted connection sends without waiting
/// (`TCP_NODELAY`). A gateway answers in small writes — a streamed reply's
/// events, a short JSON body — and with Nagle's algorithm each one after the
/// first waits for the client's delayed ACK, some 40 ms on Linux, so every
/// request a client makes one at a time pays it. Every listener a binary
/// serves HTTP on goes through this. Locked by
/// `an_accepted_connection_sends_without_waiting`.
pub fn without_nagle(listener: tokio::net::TcpListener) -> TapIo<tokio::net::TcpListener, fn(&mut tokio::net::TcpStream)> {
    listener.tap_io(no_delay)
}

/// The type is named so a router's connection info (`SocketAddr`) still reads
/// the peer address through it.
fn no_delay(tcp: &mut tokio::net::TcpStream) {
    if let Err(e) = tcp.set_nodelay(true) {
        tracing::warn!(error = %e, "could not turn Nagle's algorithm off on an accepted connection");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::serve::Listener;

    #[tokio::test]
    async fn an_accepted_connection_sends_without_waiting() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let mut listener = without_nagle(listener);
        let client = tokio::spawn(async move { tokio::net::TcpStream::connect(addr).await.unwrap() });
        let (accepted, _) = listener.accept().await;
        let _client = client.await.unwrap();
        assert!(accepted.nodelay().unwrap());
    }
}
