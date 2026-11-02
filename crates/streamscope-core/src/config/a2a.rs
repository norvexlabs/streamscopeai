//! Per-tenant A2A gateway config: registered upstream agents exposed at
//! `/a2a/<slug>`, snapshot-built and indexed for the proxy hot path
//! (mirrors `config::mcp`).

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Authentication mode at the upstream agent. `per_user_oauth` / `byot`
/// analogs of the MCP modes would be additive values.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum A2aAuthMode {
    #[default]
    NoAuth,
    ServiceAccount,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct A2aUpstreamAgent {
    pub id: Uuid,
    pub tenant_id: Uuid,
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    /// The `/a2a/<slug>` mount handle — globally unique across tenants (the
    /// pre-auth agent-card endpoint resolves the tenant BY slug).
    pub slug: String,
    /// Upstream JSON-RPC endpoint (derived from the card's JSONRPC/1.0
    /// interface at registration/refresh).
    pub agent_url: String,
    /// Cached upstream agent card, raw as fetched. The proxy rewrites it per
    /// request (`a2a::card::rewrite_card`) — never served verbatim.
    pub agent_card: serde_json::Value,
    /// When the cached card was last fetched from the upstream — drives the
    /// mount's `Last-Modified` header on the served (rewritten) card.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub card_fetched_at: Option<chrono::DateTime<chrono::Utc>>,
    #[serde(default)]
    pub auth_mode: A2aAuthMode,
    /// AES-256-GCM ciphertext, base64-encoded (matches `crypto::encrypt`
    /// output; same shape as MCP's `encrypted_credential`). Populated when
    /// `auth_mode = ServiceAccount`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub encrypted_credential: Option<String>,
    /// Header carrying the decrypted credential upstream.
    /// `None` = `Authorization: Bearer <credential>`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub credential_header: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
}

fn default_true() -> bool {
    true
}

/// Per-tenant A2A config snapshot — agents indexed for `/a2a/<slug>` lookup.
/// Workspace access is NOT here: A2A grants ride each key's baked
/// `allowed_a2a_agent_ids` (`UserContext::allows_a2a_agent`), the same
/// mechanism as MCP's `allowed_virtual_server_ids`.
#[derive(Debug, Clone, Default)]
pub struct A2aConfig {
    pub agents: HashMap<Uuid, A2aUpstreamAgent>,
    /// `slug -> agent_id` for `/a2a/<slug>` dispatch.
    pub agent_by_slug: HashMap<String, Uuid>,
}

impl A2aConfig {
    pub fn from_rows(agents: Vec<A2aUpstreamAgent>) -> Self {
        let mut cfg = A2aConfig::default();
        for agent in agents {
            // Disabled agents are dropped on entry (mirrors McpConfig's
            // "drop dependent rows" semantics) — the mount 404s.
            if !agent.enabled {
                continue;
            }
            cfg.agent_by_slug.insert(agent.slug.clone(), agent.id);
            cfg.agents.insert(agent.id, agent);
        }
        cfg
    }

    pub fn lookup_by_slug(&self, slug: &str) -> Option<&A2aUpstreamAgent> {
        self.agent_by_slug
            .get(slug)
            .and_then(|id| self.agents.get(id))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn agent(slug: &str, enabled: bool) -> A2aUpstreamAgent {
        A2aUpstreamAgent {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: slug.to_string(),
            description: None,
            slug: slug.to_string(),
            agent_url: format!("https://{slug}.example.com/a2a"),
            agent_card: serde_json::json!({"name": slug}),
            card_fetched_at: None,
            auth_mode: A2aAuthMode::NoAuth,
            encrypted_credential: None,
            credential_header: None,
            enabled,
        }
    }

    #[test]
    fn disabled_agents_are_dropped() {
        let on = agent("on", true);
        let off = agent("off", false);
        let cfg = A2aConfig::from_rows(vec![on.clone(), off.clone()]);
        assert!(cfg.lookup_by_slug("on").is_some());
        assert!(cfg.lookup_by_slug("off").is_none());
        assert_eq!(cfg.lookup_by_slug("on").unwrap().id, on.id);
    }
}
