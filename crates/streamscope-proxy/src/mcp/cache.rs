//! Per-upstream capability cache.
//!
//! `tools/list`, `prompts/list`, `resources/list`, and
//! `resources/templates/list` are idempotent reads against an upstream MCP
//! server — every concurrent agent receives the same answer. Caching them
//! per-instance saves a round-trip per call and dampens upstream load when
//! many agents share the same virtual server.
//!
//! `initialize` is intentionally NOT cached. Stateful upstreams issue a
//! fresh `Mcp-Session-Id` from each initialize response, and the cache
//! stores only the JSON body — a cache hit would silently strip the
//! session-id and every follow-up call would be rejected as
//! `Missing session ID`.
//!
//! ## Invalidation
//!
//! The cache key is `(upstream_id, cred_version, method)`. `cred_version`
//! is bumped at admin-api on every PATCH / DELETE of an `mcp_upstream_servers`
//! row. The new version arrives at the proxy in the tenant's config body (the
//! change triggers on `mcp_upstream_servers`), and the next request resolves a
//! different cache key — old entries become unreachable and fall out of the
//! bounded map.
//!
//! No separate invalidation channel is needed: config sync already carries
//! the bumped `cred_version` within a sync interval, and the
//! cred_version-keyed cache is self-invalidating when the body lands.
//!
//! ## Safety
//!
//! Cached responses are stored as raw `JsonRpcResponse` values *without* any
//! per-user filtering. This is correct only for an upstream every caller
//! reaches with the same headers: `auth_mode = headers` with every declared
//! input admin-filled. A user- or client-filled input, or a per-user OAuth
//! token, makes the catalog per-caller, and such an upstream MUST NOT cache.
//! The [`is_cacheable`] helper enforces this at the edge.

use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use streamscope_core::config::mcp::{McpAuthMode, McpUpstreamServer};
use uuid::Uuid;

use super::jsonrpc::JsonRpcResponse;

/// Default entry-count fallback (4096) — used by the test-only
/// `with_ttl` constructor so unit tests don't need a live `ProxySettings`.
/// Production (`CapabilityCache::new`) reads
/// `mcp_capability_cache_max_entries` from settings; operators tune via
/// the `MCP_CAPABILITY_CACHE_MAX_ENTRIES` env var. LRU is approximated via
/// "drop oldest by inserted_at when over capacity" on insert; the entry
/// count is small in practice (one per `(tenant, upstream, cred_version,
/// method)` quadruple), so this is mostly a backstop against unbounded
/// `cred_version` growth from rapid admin rotations.
#[cfg(test)]
const DEFAULT_MAX_ENTRIES: usize = 4096;

/// Composite cache key. `cred_version` participates so a credential rotation
/// renders every cached entry unreachable without an explicit purge.
///
/// `tenant_id` is in the key for defense-in-depth: `upstream_id` UUIDs are
/// already tenant-bound by RLS and globally unique, so a collision across
/// tenants is structurally impossible — but every per-process cache that
/// holds tenant-derived data must include `tenant_id` explicitly so future code paths that take
/// an `upstream_id` from any partially-trusted source can't silently cross
/// the boundary.
#[derive(Hash, Eq, PartialEq, Clone, Debug)]
pub struct CacheKey {
    pub tenant_id: Uuid,
    pub upstream_id: Uuid,
    pub cred_version: i64,
    /// JSON-RPC method, e.g. `"tools/list"`. `&'static str` would be ideal
    /// but the handler builds method names dynamically.
    pub method: String,
    /// Which of the upstream's two legs produced the entry.
    ///
    /// **Load-bearing: a dual-era upstream serves a DIFFERENT catalog on each
    /// leg.** Its modern leg may expose tools that only exist there, and its
    /// legacy leg may expose tools the modern revision removed. The two share
    /// no state — which is why `upstream_handshakes` is keyed on the era too
    /// — so an entry earned on one leg is not an answer for the other.
    ///
    /// Without this field the cache is order-dependent and silently wrong in
    /// both directions: whichever era asked first wins, and the other is
    /// handed a catalog naming tools its leg cannot invoke, or missing tools
    /// its leg does serve. Nothing about the response looks wrong — it is a
    /// well-formed catalog for the wrong half of the server.
    pub upstream_is_modern: bool,
}

#[derive(Clone)]
struct CacheEntry {
    inserted_at: Instant,
    response: JsonRpcResponse,
}

/// Per-instance, in-memory capability cache.
pub struct CapabilityCache {
    map: DashMap<CacheKey, CacheEntry>,
    ttl: Duration,
    max_entries: usize,
}

impl CapabilityCache {
    pub fn new() -> Arc<Self> {
        let s = crate::settings::proxy_settings();
        Self::with_settings(
            Duration::from_secs(s.mcp_capability_cache_ttl_secs),
            s.mcp_capability_cache_max_entries,
        )
    }

    /// Test-only: build with a bespoke TTL and the default max-entries cap.
    #[cfg(test)]
    pub fn with_ttl(ttl: Duration) -> Arc<Self> {
        Self::with_settings(ttl, DEFAULT_MAX_ENTRIES)
    }

    fn with_settings(ttl: Duration, max_entries: usize) -> Arc<Self> {
        Arc::new(Self {
            map: DashMap::new(),
            ttl,
            max_entries: max_entries.max(1),
        })
    }

    /// Read a cached response if present and not expired.
    pub fn get(&self, key: &CacheKey) -> Option<JsonRpcResponse> {
        let entry = self.map.get(key)?;
        if entry.inserted_at.elapsed() > self.ttl {
            // Stale — best-effort drop. The next reader will re-fetch.
            drop(entry);
            self.map.remove(key);
            return None;
        }
        Some(entry.response.clone())
    }

    /// Store a fresh response under `key`. Evicts the oldest entries when
    /// over capacity — defensively bounded against runaway `cred_version`
    /// growth, not a hot-path concern.
    pub fn insert(&self, key: CacheKey, response: JsonRpcResponse) {
        if self.map.len() >= self.max_entries {
            self.evict_oldest(self.max_entries.max(8) / 8);
        }
        self.map.insert(
            key,
            CacheEntry {
                inserted_at: Instant::now(),
                response,
            },
        );
    }

    fn evict_oldest(&self, count: usize) {
        let mut victims: Vec<(CacheKey, Instant)> = self
            .map
            .iter()
            .map(|e| (e.key().clone(), e.value().inserted_at))
            .collect();
        victims.sort_by_key(|(_, t)| *t);
        for (k, _) in victims.into_iter().take(count) {
            self.map.remove(&k);
        }
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }
}

/// Cacheability gate: an upstream every caller reaches with the same headers
/// — `headers` mode, every declared input admin-filled (none declared
/// included) — shares one identity across all agents and is safe to cache.
/// A user- or client-filled input or a per-user OAuth token is per-caller;
/// caching would leak one caller's catalog to another. Disabled upstreams
/// shouldn't be reached at all but we double-gate here.
pub fn is_cacheable(upstream: &McpUpstreamServer) -> bool {
    upstream.enabled
        && upstream.auth_mode == McpAuthMode::Headers
        && super::upstream_auth::every_input_is_admin(upstream)
}

/// Cacheability gate by method — only idempotent *list* methods are
/// cached. `initialize` is intentionally NOT cached: a stateful upstream
/// returns a fresh `Mcp-Session-Id` from every initialize, and the cache
/// stores only the JSON body (not the response header), so a cache hit
/// would silently strip the session-id and every subsequent request from
/// that agent would be rejected as `Missing session ID`.
///
/// Methods that mutate upstream state, return per-call data
/// (`tools/call`, `prompts/get`, `resources/read`), or don't have a
/// structured response (`notifications/*`, `sampling/createMessage`)
/// are also uncacheable.
pub fn is_cacheable_method(method: &str) -> bool {
    matches!(
        method,
        "tools/list" | "prompts/list" | "resources/list" | "resources/templates/list"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mcp::jsonrpc::{JsonRpcResponse, RpcId};

    fn upstream(auth: McpAuthMode, fillers: &[&str], enabled: bool) -> McpUpstreamServer {
        let headers: Vec<serde_json::Value> = (0..fillers.len())
            .map(|i| serde_json::json!({ "name": format!("X-In-{i}"), "isRequired": true }))
            .collect();
        let filler_map: serde_json::Map<String, serde_json::Value> = fillers
            .iter()
            .enumerate()
            .map(|(i, f)| (format!("X-In-{i}"), serde_json::json!(f)))
            .collect();
        let mut u = crate::mcp::upstream_auth::test_support::upstream(
            auth,
            serde_json::Value::Array(headers),
            serde_json::Value::Object(filler_map),
        );
        u.enabled = enabled;
        u
    }

    fn key(upstream_id: Uuid, cred_version: i64, method: &str) -> CacheKey {
        CacheKey {
            tenant_id: Uuid::new_v4(),
            upstream_id,
            cred_version,
            method: method.into(),
            upstream_is_modern: false,
        }
    }

    fn key_t(tenant_id: Uuid, upstream_id: Uuid, cred_version: i64, method: &str) -> CacheKey {
        CacheKey {
            tenant_id,
            upstream_id,
            cred_version,
            method: method.into(),
            upstream_is_modern: false,
        }
    }

    fn ok_resp(value: serde_json::Value) -> JsonRpcResponse {
        JsonRpcResponse::ok(RpcId::Number(serde_json::Number::from(1)), value)
    }

    #[test]
    fn get_returns_inserted() {
        let cache = CapabilityCache::new();
        let k = key(Uuid::new_v4(), 1, "tools/list");
        let resp = ok_resp(serde_json::json!({"tools": []}));
        cache.insert(k.clone(), resp.clone());
        let hit = cache.get(&k).expect("cached");
        assert_eq!(hit.id, resp.id);
    }

    #[test]
    fn cred_version_bump_misses() {
        let cache = CapabilityCache::new();
        let tenant = Uuid::new_v4();
        let upstream_id = Uuid::new_v4();
        cache.insert(
            key_t(tenant, upstream_id, 1, "tools/list"),
            ok_resp(serde_json::json!({})),
        );
        assert!(
            cache
                .get(&key_t(tenant, upstream_id, 2, "tools/list"))
                .is_none()
        );
    }

    #[test]
    fn the_two_eras_of_one_upstream_do_not_share_an_entry() {
        // A dual-era upstream answers `tools/list` differently on each leg —
        // the modern leg can expose tools that exist only there. Sharing one
        // entry makes the catalog order-dependent: whichever era asked first
        // wins and the other client is handed the wrong half of the server,
        // in a response that looks perfectly well-formed.
        let cache = CapabilityCache::new();
        let tenant = Uuid::new_v4();
        let upstream_id = Uuid::new_v4();
        let legacy = key_t(tenant, upstream_id, 1, "tools/list");
        let modern = CacheKey { upstream_is_modern: true, ..legacy.clone() };

        cache.insert(legacy.clone(), ok_resp(serde_json::json!({ "tools": [] })));
        assert!(
            cache.get(&modern).is_none(),
            "a modern client was served the catalog the legacy leg returned"
        );
        // The positive control: the leg that stored it still reads it back,
        // or this test would pass just as well against a cache that never
        // returns anything at all.
        assert!(cache.get(&legacy).is_some(), "the storing leg lost its own entry");
    }

    #[test]
    fn cross_tenant_isolation() {
        // Two tenants holding entries for the same upstream UUID + cred_version
        // + method must not collide. UUIDs don't collide in practice, but the
        // cache key includes `tenant_id` for defense-in-depth — this gate
        // catches future regressions if someone removes `tenant_id` from the
        // key while an upstream_id collision could be engineered.
        let cache = CapabilityCache::new();
        let upstream_id = Uuid::new_v4();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        let v1 = ok_resp(serde_json::json!({"src": "tenant_1"}));
        let v2 = ok_resp(serde_json::json!({"src": "tenant_2"}));
        cache.insert(key_t(t1, upstream_id, 1, "tools/list"), v1.clone());
        cache.insert(key_t(t2, upstream_id, 1, "tools/list"), v2.clone());
        assert_eq!(cache.len(), 2);
        let hit_t1 = cache.get(&key_t(t1, upstream_id, 1, "tools/list")).unwrap();
        let hit_t2 = cache.get(&key_t(t2, upstream_id, 1, "tools/list")).unwrap();
        assert_eq!(
            hit_t1.result.as_ref().and_then(|v| v.get("src")),
            Some(&serde_json::json!("tenant_1"))
        );
        assert_eq!(
            hit_t2.result.as_ref().and_then(|v| v.get("src")),
            Some(&serde_json::json!("tenant_2"))
        );
    }

    #[test]
    fn ttl_expiry() {
        let cache = CapabilityCache::with_ttl(Duration::from_millis(10));
        let k = key(Uuid::new_v4(), 1, "tools/list");
        cache.insert(k.clone(), ok_resp(serde_json::json!({})));
        std::thread::sleep(Duration::from_millis(25));
        assert!(cache.get(&k).is_none());
    }

    /// Cacheable only when every caller sends the same headers: `headers`
    /// mode with every input admin-filled (none at all included). One user-
    /// or client-filled input, or a per-user OAuth token, makes it per-caller.
    #[test]
    fn cacheability_gate_by_who_fills_the_inputs() {
        assert!(is_cacheable(&upstream(McpAuthMode::Headers, &[], true)));
        assert!(is_cacheable(&upstream(McpAuthMode::Headers, &["admin", "admin"], true)));
        assert!(!is_cacheable(&upstream(McpAuthMode::Headers, &["admin", "user"], true)));
        assert!(!is_cacheable(&upstream(McpAuthMode::Headers, &["admin", "client"], true)));
        assert!(!is_cacheable(&upstream(McpAuthMode::PerUserOauth, &[], true)));
        assert!(!is_cacheable(&upstream(McpAuthMode::PerUserOauth, &["admin"], true)));
        assert!(!is_cacheable(&upstream(McpAuthMode::Headers, &[], false)));
        // An input with no filler is an invalid declaration: never cached.
        let mut no_filler = upstream(McpAuthMode::Headers, &["admin"], true);
        no_filler.remote.meta = None;
        assert!(!is_cacheable(&no_filler));
    }

    #[test]
    fn cacheability_gate_by_method() {
        assert!(is_cacheable_method("tools/list"));
        assert!(is_cacheable_method("prompts/list"));
        assert!(is_cacheable_method("resources/list"));
        assert!(is_cacheable_method("resources/templates/list"));
        // initialize is intentionally uncacheable — each agent must get a
        // fresh upstream `Mcp-Session-Id`, and the cache stores only the
        // JSON body.
        assert!(!is_cacheable_method("initialize"));
        assert!(!is_cacheable_method("tools/call"));
        assert!(!is_cacheable_method("logging/setLevel"));
        assert!(!is_cacheable_method("completion/complete"));
        assert!(!is_cacheable_method("resources/read"));
        assert!(!is_cacheable_method("prompts/get"));
        assert!(!is_cacheable_method("notifications/initialized"));
    }
}
