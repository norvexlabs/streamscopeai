//! MCP gateway — transport, virtualization, and multiplexer.
//!
//! Layout:
//! - [`jsonrpc`] — JSON-RPC 2.0 framing, error codes, scope classification.
//! - [`virtualize`] — namespace prefix strip-and-stamp, capability merging,
//!   per-route filter logic. Resource URIs are virtualized statelessly via
//!   `streamscope_core::mcp::tokens` (`stsmcp://<prefix>/<b64>`) so any proxy
//!   replica can decode without consulting per-session state.
//! - [`upstream`] — outbound HTTP client to upstream MCP servers.
//! - [`handler`] — Axum entry point + dispatcher. Mounted at
//!   `/mcp/<slug>` in `main.rs`.
//!
//! The multiplexer streams `tools/call` responses and passes through
//! server-initiated `sampling/createMessage` and `elicitation/create`, plus
//! `notifications/message` log forwarding. The reverse path (the agent's
//! response to a server-initiated request) is routed back to the originating
//! upstream via [`session::McpSessionMap`].

pub mod cache;
pub mod event_bus;
pub mod handler;
pub mod jsonrpc;
pub mod legacy_sse;
pub mod modern;
pub mod multiplex;
pub mod oauth;
pub mod policy;
pub mod sampling;
pub mod session;
pub mod spec_oauth;
pub mod sse_seq;
pub mod upstream;
pub mod upstream_listen;
pub mod virtual_servers;
pub mod virtualize;

pub use handler::{McpAppState, McpRouterState, mcp_fwd_handler, mcp_handler};
pub use handler::{mcp_delete_handler, mcp_get_handler};
