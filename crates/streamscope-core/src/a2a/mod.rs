//! A2A (Agent2Agent) protocol support — 1.0.1 wire.
//!
//! Layering: `model` holds the protocol-agnostic internal types the
//! dispatcher, policy, guardrail, and audit layers operate on; `wire::v1_0`
//! is the 1.0.1 JSON-RPC serde surface (a future 0.3 dialect is a sibling
//! `wire::v0_3` translation — the dispatcher never sees dialect specifics);
//! `card` handles AgentCard parsing + the gateway rewrite; `errors` carries
//! the A2A error taxonomy and JSON-RPC envelope helpers; `domain` projects a
//! message's parts into the canonical block vocabulary shared with the LLM
//! protocols — the one place policy, guardrail, and rendering read content from.

pub mod card;
pub mod domain;
pub mod errors;
pub mod model;
pub mod wire;
