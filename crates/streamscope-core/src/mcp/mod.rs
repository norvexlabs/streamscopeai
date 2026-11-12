//! Shared MCP gateway primitives used by both proxy and admin-api.
//!
//! Two concerns live here. Stateless cross-instance virtualization: signed
//! opaque session ids, request ids, and resource URIs, which the proxy mints
//! on outbound and decodes on inbound so any sibling instance can route a
//! request correctly without consulting per-session state. And the upstream
//! OAuth hop: the guarded transport and client shape that admin-api's
//! authorization-code exchange and the proxy's token refresh both use.

pub mod header_inputs;
pub mod local_server;
pub mod oauth_client;
pub mod oauth_http;
pub mod sse_events;
pub mod tokens;

/// Streaming size cap for a response body read from an MCP server.
///
/// For a `per_user_oauth` / `byot` upstream the server is a third party, so an
/// unbounded read lets it return a multi-GB body and OOM whichever of our
/// processes made the call — the proxy replica serving every tenant's traffic,
/// or the admin-api replica serving every tenant's control plane. 32 MiB
/// comfortably covers any realistic `tools/call` / `resources/read` payload.
///
/// **Invariant:** both callers of an MCP server share this bound — the proxy's
/// data-plane egress and admin-api's connection test. A test that could buffer
/// more than the gateway would make the control plane the softer target.
pub const MCP_MAX_RESPONSE_BYTES: u64 = 32 * 1024 * 1024;
