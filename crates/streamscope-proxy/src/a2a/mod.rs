//! A2A gateway surface: `/a2a/<slug>` (JSON-RPC 2.0 binding) plus the
//! pre-auth rewritten agent card at the mount's well-known paths. The third
//! protocol pillar next to `/v1/*` (LLM) and `/mcp/<slug>` (MCP).

pub mod guardrail;
pub mod handler;
pub mod policy;
pub mod upstream;

pub use handler::{a2a_handler, agent_card_handler, A2aRouterState};
