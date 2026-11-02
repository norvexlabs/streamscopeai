//! AgentCard handling: interface extraction (admin-side validation of a
//! fetched card) and the gateway rewrite (the card served at
//! `/a2a/<slug>/.well-known/agent-card.json`).
//!
//! The rewritten card is built from an **allowlist**, never by editing the
//! upstream card in place.
//!
//! The card is served **pre-auth**, to anyone. A denylist ("strip the fields we
//! know are dangerous") leaks by default: A2A 1.0 folded the 0.3 `url` /
//! `preferredTransport` / `additionalInterfaces` fields into
//! `supportedInterfaces`, and real cards carry both during the migration window
//! — so pinning `supportedInterfaces` while passing the rest through publishes
//! the agent's real endpoint to the internet, and a 0.3-tolerant client library
//! *prefers* `url` and routes around the gateway: no policy, no guardrail, no
//! audit, no budget. Every other endpoint-bearing field (`provider.url`,
//! `documentationUrl`, `iconUrl`, any vendor extension) is the same hazard.
//!
//! So: copy the descriptive fields we can name, and emit the rest ourselves —
//! `supportedInterfaces` pinned to the single gateway JSONRPC/1.0 entry,
//! `securitySchemes`/`securityRequirements` replaced with the gateway's own
//! bearer-key scheme, `pushNotifications: false` (v1 rejects the push-config
//! methods), `streaming` gated on gateway support, and no `signatures` (a
//! rewritten card can no longer match a JWS over the upstream original —
//! serving a stale signature would be actively misleading).
//!
//! **Adding a field to either allowlist is a security decision**: it must carry
//! no URL, host, or credential of the upstream agent.

use serde_json::{json, Value};

/// Scheme name advertised on the rewritten card.
pub const GATEWAY_SCHEME_NAME: &str = "gatewayApiKey";

/// The upstream card's JSON-RPC 1.0 interface, resolved by the admin at
/// registration/refresh: `(url, tenant)` — `tenant` is the opaque routing
/// value the client must echo per request (forwarded verbatim upstream).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JsonRpcInterface {
    pub url: String,
    pub tenant: Option<String>,
}

/// Find the preferred JSONRPC/1.0 entry in `supportedInterfaces` (entries are
/// in preference order; the first match wins). `protocolVersion` compares on
/// the `major.minor` pair — patch levels never participate in negotiation.
pub fn extract_jsonrpc_interface(card: &Value) -> Option<JsonRpcInterface> {
    card.get("supportedInterfaces")?
        .as_array()?
        .iter()
        .find(|iface| {
            iface.get("protocolBinding").and_then(Value::as_str) == Some("JSONRPC")
                && iface
                    .get("protocolVersion")
                    .and_then(Value::as_str)
                    .is_some_and(|v| v == "1.0" || v.starts_with("1.0."))
        })
        .and_then(|iface| {
            Some(JsonRpcInterface {
                url: iface.get("url")?.as_str()?.to_string(),
                tenant: iface
                    .get("tenant")
                    .and_then(Value::as_str)
                    .map(str::to_string),
            })
        })
}

/// Rewrite an upstream card for serving at the gateway mount.
///
/// `mount_url` is the full public gateway endpoint
/// (`<proxy_public_url>/a2a/<slug>`); `allow_streaming` gates the advertised
/// `streaming` capability on gateway support (upstream value AND gateway
/// support — never advertise what either side can't deliver).
pub fn rewrite_card(upstream_card: &Value, mount_url: &str, allow_streaming: bool) -> Value {
    let Some(upstream) = upstream_card.as_object() else {
        // A non-object "card" can't be rewritten; serve a minimal valid one
        // rather than leaking the upstream value.
        return minimal_card(mount_url);
    };

    let mut card = serde_json::Map::new();
    for field in CARD_DESCRIPTIVE_FIELDS {
        if let Some(v) = upstream.get(*field) {
            card.insert((*field).to_string(), v.clone());
        }
    }
    // No `provider` block: the spec requires BOTH `organization` and `url` on
    // it, and the upstream's `url` must never be served — an incomplete
    // provider is spec-invalid to strict clients, and a fabricated gateway URL
    // would be dishonest metadata. The block is optional on the card; vendor
    // branding is not worth an unscreened prose field.
    if let Some(skills) = upstream.get("skills").and_then(Value::as_array) {
        card.insert(
            "skills".into(),
            Value::Array(skills.iter().map(rewrite_skill).collect()),
        );
    }

    // Preserve the upstream interface's tenant routing value, if any.
    let tenant = extract_jsonrpc_interface(upstream_card).and_then(|i| i.tenant);
    let mut iface = json!({
        "url": mount_url,
        "protocolBinding": "JSONRPC",
        "protocolVersion": "1.0",
    });
    if let Some(t) = &tenant {
        iface["tenant"] = json!(t);
    }
    card.insert("supportedInterfaces".into(), json!([iface]));

    // The gateway terminates client auth with its own key scheme; upstream
    // schemes are the gateway's business, never the client's.
    card.insert(
        "securitySchemes".into(),
        json!({
            GATEWAY_SCHEME_NAME: {
                "httpAuthSecurityScheme": {
                    "scheme": "bearer",
                    "description": "Gateway API key (Authorization: Bearer <key>)"
                }
            }
        }),
    );
    // Spec field is `securityRequirements`; published sample cards render
    // `security` — serve both so either reader authenticates correctly.
    let requirement = json!([{ GATEWAY_SCHEME_NAME: [] }]);
    card.insert("securityRequirements".into(), requirement.clone());
    card.insert("security".into(), requirement);

    let upstream_streaming = upstream_card
        .pointer("/capabilities/streaming")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let mut capabilities = serde_json::Map::new();
    for field in CARD_CAPABILITY_FIELDS {
        if let Some(v) = upstream_card.pointer(&format!("/capabilities/{field}")) {
            capabilities.insert((*field).to_string(), v.clone());
        }
    }
    capabilities.insert("pushNotifications".into(), json!(false));
    capabilities.insert(
        "streaming".into(),
        json!(upstream_streaming && allow_streaming),
    );
    card.insert("capabilities".into(), Value::Object(capabilities));

    Value::Object(card)
}

/// Upstream card fields copied verbatim onto the served card. Descriptive only
/// — none may carry a URL, host, or credential of the upstream agent (that is
/// what makes the allowlist a security boundary, not a convenience).
///
/// Deliberately absent: `url` / `preferredTransport` / `additionalInterfaces`
/// (the 0.3 endpoint fields — the whole reason this is an allowlist),
/// `provider.url`, `documentationUrl`, `iconUrl`, `signatures`, and every vendor
/// extension.
const CARD_DESCRIPTIVE_FIELDS: &[&str] = &[
    "name",
    "description",
    "version",
    "protocolVersion",
    "defaultInputModes",
    "defaultOutputModes",
];

/// Capability flags copied from the upstream card. `streaming` and
/// `pushNotifications` are NOT here — the gateway decides those. Neither is
/// `extensions`: an `AgentExtension` carries a free `params` Struct (arbitrary
/// vendor JSON — endpoints, tokens) plus `uri`/`description` prose nothing
/// screens, so serving it pre-auth would reopen exactly the channel this
/// allowlist closes. Declared extensions therefore don't ride the rewritten
/// card.
const CARD_CAPABILITY_FIELDS: &[&str] = &["extendedAgentCard"];

/// Skill fields copied verbatim. A skill is pure documentation — it addresses
/// nothing — but it is still allowlisted, because a vendor field on a skill
/// reaches the client exactly like one on the card.
const SKILL_FIELDS: &[&str] = &[
    "id",
    "name",
    "description",
    "tags",
    "examples",
    "inputModes",
    "outputModes",
];

fn rewrite_skill(skill: &Value) -> Value {
    let Some(obj) = skill.as_object() else {
        return json!({});
    };
    let mut out = serde_json::Map::new();
    for field in SKILL_FIELDS {
        if let Some(v) = obj.get(*field) {
            out.insert((*field).to_string(), v.clone());
        }
    }
    Value::Object(out)
}

fn minimal_card(mount_url: &str) -> Value {
    json!({
        "name": "unavailable",
        "description": "Upstream agent card unavailable",
        "version": "0",
        "supportedInterfaces": [{
            "url": mount_url,
            "protocolBinding": "JSONRPC",
            "protocolVersion": "1.0",
        }],
        "capabilities": { "streaming": false, "pushNotifications": false },
        "defaultInputModes": [],
        "defaultOutputModes": [],
        "skills": [],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn upstream_card() -> Value {
        json!({
            "name": "Recipe Agent",
            "description": "Cooks up recipes",
            "version": "2.1.0",
            "supportedInterfaces": [
                {"url": "grpc://agent.internal:9000", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
                {"url": "https://agent.example.com/a2a", "protocolBinding": "JSONRPC", "protocolVersion": "1.0", "tenant": "kitchen"},
                {"url": "https://agent.example.com/a2a-legacy", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
            ],
            "provider": {"organization": "Acme", "url": "https://agent.example.com"},
            "capabilities": {"streaming": true, "pushNotifications": true, "extendedAgentCard": true},
            "securitySchemes": {"agentOauth": {"oauth2SecurityScheme": {"flows": {}}}},
            "securityRequirements": [{"agentOauth": ["read"]}],
            "skills": [{
                "id": "cook", "name": "Cook", "description": "…", "tags": ["food"],
                "examples": ["Cook me dinner"],
                "vendorEndpoint": "https://agent.example.com/skills/cook"
            }],
            "signatures": [{"protected": "eyJh", "signature": "sig"}],
            "customVendorField": {"keep": "me"}
        })
    }

    #[test]
    fn extracts_first_jsonrpc_10_interface() {
        let iface = extract_jsonrpc_interface(&upstream_card()).expect("found");
        assert_eq!(iface.url, "https://agent.example.com/a2a");
        assert_eq!(iface.tenant.as_deref(), Some("kitchen"));
    }

    #[test]
    fn no_jsonrpc_interface_is_none() {
        let card = json!({"supportedInterfaces": [
            {"url": "grpc://x", "protocolBinding": "GRPC", "protocolVersion": "1.0"},
            {"url": "https://x", "protocolBinding": "JSONRPC", "protocolVersion": "0.3"}
        ]});
        assert_eq!(extract_jsonrpc_interface(&card), None);
    }

    #[test]
    fn rewrite_pins_interface_auth_and_capabilities() {
        let card = rewrite_card(&upstream_card(), "https://gw.example.com/a2a/recipes", true);

        let ifaces = card["supportedInterfaces"].as_array().unwrap();
        assert_eq!(ifaces.len(), 1);
        assert_eq!(ifaces[0]["url"], "https://gw.example.com/a2a/recipes");
        assert_eq!(ifaces[0]["protocolBinding"], "JSONRPC");
        assert_eq!(ifaces[0]["protocolVersion"], "1.0");
        assert_eq!(ifaces[0]["tenant"], "kitchen");

        // Gateway auth replaces upstream schemes, on both requirement keys.
        assert!(card["securitySchemes"][GATEWAY_SCHEME_NAME]["httpAuthSecurityScheme"].is_object());
        assert!(card["securitySchemes"].get("agentOauth").is_none());
        assert_eq!(card["securityRequirements"][0][GATEWAY_SCHEME_NAME], json!([]));
        assert_eq!(card["security"][0][GATEWAY_SCHEME_NAME], json!([]));

        assert_eq!(card["capabilities"]["pushNotifications"], false);
        assert_eq!(card["capabilities"]["streaming"], true);
        assert_eq!(card["capabilities"]["extendedAgentCard"], true);

        assert!(card.get("signatures").is_none());
        assert_eq!(card["skills"][0]["id"], "cook");
        // The allowlist keeps the descriptive fields.
        assert_eq!(card["name"], "Recipe Agent");
        assert_eq!(card["version"], "2.1.0");
        // No provider: the spec requires `url` on it, and the upstream's url
        // must never be served — the whole block is dropped.
        assert!(card.get("provider").is_none());
    }

    #[test]
    fn nothing_that_addresses_the_upstream_agent_survives_the_rewrite() {
        // The card is served pre-auth to anyone. Every field that could carry the
        // agent's real endpoint must be absent — including the 0.3 fields a card
        // in the migration window still carries, which a 0.3-tolerant client
        // would PREFER over `supportedInterfaces`, routing around the gateway
        // entirely (no policy, no guardrail, no audit, no budget).
        let mut upstream = upstream_card();
        upstream["url"] = json!("https://agent.internal-partner.com/a2a");
        upstream["preferredTransport"] = json!("JSONRPC");
        upstream["additionalInterfaces"] =
            json!([{"url": "https://agent.internal-partner.com/a2a", "transport": "JSONRPC"}]);
        upstream["documentationUrl"] = json!("https://agent.internal-partner.com/docs");
        upstream["iconUrl"] = json!("https://agent.internal-partner.com/icon.png");
        // An extension's `params` is an arbitrary vendor Struct — the classic
        // place to smuggle the real endpoint past a field-name denylist.
        upstream["capabilities"]["extensions"] = json!([{
            "uri": "https://agent.internal-partner.com/ext/direct",
            "description": "connect directly for lower latency",
            "required": true,
            "params": {"endpoint": "https://agent.internal-partner.com/a2a"}
        }]);

        let card = rewrite_card(&upstream, "https://gw.example.com/a2a/recipes", true);
        let served = serde_json::to_string(&card).unwrap();
        assert!(
            !served.contains("agent.internal-partner.com"),
            "the upstream endpoint leaked onto the public card: {served}"
        );
        assert!(!served.contains("agent.example.com"), "{served}");
        // An unrecognized vendor field is dropped, card-level and skill-level:
        // the allowlist cannot know what a future field addresses.
        assert!(card.get("customVendorField").is_none());
        assert!(card["skills"][0].get("vendorEndpoint").is_none());
    }

    #[test]
    fn streaming_is_anded_with_gateway_support() {
        let card = rewrite_card(&upstream_card(), "https://gw/a2a/r", false);
        assert_eq!(card["capabilities"]["streaming"], false);

        let mut upstream = upstream_card();
        upstream["capabilities"]["streaming"] = json!(false);
        let card = rewrite_card(&upstream, "https://gw/a2a/r", true);
        assert_eq!(card["capabilities"]["streaming"], false);
    }

    #[test]
    fn non_object_card_degrades_to_minimal() {
        let card = rewrite_card(&json!("garbage"), "https://gw/a2a/x", true);
        assert_eq!(card["supportedInterfaces"][0]["url"], "https://gw/a2a/x");
        assert_eq!(card["capabilities"]["pushNotifications"], false);
    }
}
