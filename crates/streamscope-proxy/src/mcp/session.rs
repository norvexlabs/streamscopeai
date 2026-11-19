//! In-process MCP session cache.
//!
//! Caches the negotiated MCP `protocolVersion` captured at `initialize` time
//! so subsequent in-process audit rows can attribute traffic by spec revision
//! without a DB round-trip. Reverse-path routing rides on `ssrid.…` tokens
//! and never consults this map.
//!
//! The cache is per-process and not persisted: an instance restart drops
//! every entry. That's acceptable because admin-api `COALESCE`s missing
//! `protocol_version` values from `mcp_sessions.protocol_version` at audit
//! ingest time, so a sibling miss only loses the fast-path stamp — the
//! version still lands on the row before it's queryable.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use uuid::Uuid;

use super::modern::{UpstreamEra, UpstreamEraSupport};

/// What we remember per `(tenant_id, mcp_session_id)`.
///
/// The session map caches the negotiated MCP protocol version for
/// in-process audit emission. `last_activity` drives the idle sweeper.
#[derive(Debug, Clone)]
pub struct SessionEntry {
    last_activity: Instant,
    /// Negotiated MCP protocol version, captured from the upstream's
    /// `initialize` response and stamped on every subsequent `mcp_audit` row
    /// for this session so operators can attribute traffic by spec revision.
    /// `None` when the proxy did not see this session's `initialize` (sibling
    /// instance handled it, pre-`initialize` traffic, etc.) — handlers fall
    /// back to `MCP_DEFAULT_PROTOCOL_VERSION` when they need a value.
    pub protocol_version: Option<String>,
}

/// How often a per-upstream session id's lookup records its use: once a
/// minute, or a quarter of the idle TTL when that is shorter, so a recorded
/// use is never old enough for the sweep to take an id in use.
fn use_refresh() -> Duration {
    Duration::from_secs(60).min(idle_ttl() / 4)
}

/// Resolve the idle-eviction window from settings (`MCP_SESSION_IDLE_TTL_SECS`,
/// default 30 min). Keep in lockstep with the legacy-SSE map's window.
fn idle_ttl() -> Duration {
    Duration::from_secs(crate::settings::proxy_settings().mcp_session_idle_ttl_secs)
}

/// Resolve the entry cap from settings.
fn max_entries() -> usize {
    crate::settings::proxy_settings().mcp_session_max_entries
}

/// The maps [`McpSessionMap`]'s entry cap bounds, each on its own: the cap is
/// compared with each map's own length.
#[derive(Debug, Clone, Copy)]
pub enum CappedMap {
    Sessions,
    LogLevels,
    UpstreamEras,
    UpstreamHandshakes,
}

/// The handshake map holds a quarter of `MCP_SESSION_MAX_ENTRIES`: a handshake
/// carries the upstream's capabilities and instructions (1.7–3.5 KB measured,
/// against ~0.1–0.2 KB for an entry of the other maps), so a quarter keeps a
/// full map near 30–60 MB at the default beside a 512 MiB gateway.
const HANDSHAKE_CAP_DIVISOR: usize = 4;

impl CappedMap {
    pub const ALL: [Self; 4] = [Self::Sessions, Self::LogLevels, Self::UpstreamEras, Self::UpstreamHandshakes];

    /// The `map` label of `streamscope_proxy_mcp_session_cap_drops_total`.
    pub fn label(self) -> &'static str {
        match self {
            Self::Sessions => "sessions",
            Self::LogLevels => "log_levels",
            Self::UpstreamEras => "upstream_eras",
            Self::UpstreamHandshakes => "upstream_handshakes",
        }
    }
}

/// New entries refused at the cap, per map ([`CappedMap`] order): a
/// CUMULATIVE count, and whether a refusal was logged since the last sweep —
/// one warning per map per sweep interval, since a full map refuses on every
/// request until a sweep frees room.
#[derive(Debug, Default)]
struct CapDrops {
    dropped: [AtomicU64; 4],
    warned: [AtomicBool; 4],
}

/// How many entries the maps hold now (scrape-time gauges).
#[derive(Debug, Clone, Copy)]
pub struct McpSessionCounts {
    pub sessions: usize,
    pub upstream_sessions: usize,
    pub upstream_handshakes: usize,
    pub upstream_eras: usize,
}

#[derive(Debug)]
pub struct McpSessionMap {
    map: DashMap<(Uuid, String), SessionEntry>,
    /// Per-upstream `Mcp-Session-Id` map.
    ///
    /// Key: `(tenant_id, downstream_session_id, upstream_server_id)` —
    /// the *downstream* session-id is the one the agent sends in
    /// subsequent requests. The *upstream* session-id stored as the
    /// value is what each upstream returned from its own `initialize`
    /// response.
    ///
    /// Without this, a virtual-server with two stateful upstreams
    /// would receive one upstream's session-id stamped onto requests
    /// destined for the other and be rejected with JSON-RPC
    /// `-32600 Session not found`.
    ///
    /// Each value carries its last use (set, or looked up — recorded at most
    /// once per [`use_refresh`]): the sweep keeps it while its session is in
    /// `map` or that use is recent, since a fan-out's parent need not be in
    /// `map`.
    upstream_sessions: DashMap<(Uuid, String, Uuid), (String, Instant)>,
    /// Gateway-owned upstream handshakes, for serving **modern** clients.
    ///
    /// A modern (`2026-07-28`) client sends no `initialize`, so there is
    /// nothing to forward: the gateway must open each upstream connection
    /// itself and remember that it did. Key is
    /// `(tenant_id, user_id, upstream_server_id)`.
    ///
    /// **Deliberately a separate map from [`Self::upstream_sessions`], not a
    /// reserved key inside it.** That map is keyed by a *client-supplied*
    /// downstream session id; a tenant member who guessed a sibling's key
    /// would be handed that sibling's upstream session id and would then
    /// address the upstream inside another user's session context. Keying
    /// this map on the authenticated `user_id` — never on anything off the
    /// wire — removes the guess.
    /// Keyed `(tenant, user, upstream, is_modern)`. The era belongs in the key
    /// because a dual-era upstream is addressed in **both** — a modern client
    /// natively, a legacy one natively — and the two connections are unrelated:
    /// one holds a session and a live stream, the other holds nothing at all.
    /// Sharing one slot would make whichever client arrived second replace the
    /// other's connection state on every alternating request.
    /// Each entry holds the inputs fingerprint it was opened under: a lookup
    /// under another one misses, and the next handshake replaces the entry —
    /// one entry per `(tenant, user, upstream, era)`, never a caller riding a
    /// session another credential opened.
    upstream_handshakes: DashMap<(Uuid, Uuid, Uuid, bool), (UpstreamHandshake, u64)>,
    /// Which protocol eras each upstream implements. Key is `(tenant_id,
    /// upstream_server_id)` — **not** the user.
    ///
    /// The era is a property of the *server*, and resolving it costs a probe
    /// round trip. Keying it per user would re-probe the same server once per
    /// caller for an answer that cannot differ between them: the probe is a
    /// `server/discover`, and whether a server implements that RPC does not
    /// depend on whose credential asked.
    ///
    /// Deliberately separate from [`Self::upstream_handshakes`] rather than a
    /// field on it, because a legacy client's traffic needs the era and never
    /// creates a handshake — it owns its own. Folding the two would make the
    /// common legacy-to-legacy path pay for a gateway-owned `initialize` it
    /// has no use for, on top of the one the client already sent.
    upstream_eras: DashMap<(Uuid, Uuid), UpstreamEraEntry>,
    /// The `logging/setLevel` a legacy client last asked for, keyed on the
    /// authenticated `(tenant_id, user_id)` — see [`Self::set_log_level`].
    client_log_levels: DashMap<(Uuid, Uuid), (String, Instant)>,
    /// The entry cap of each map above but `upstream_sessions`, a quarter of
    /// it for `upstream_handshakes`; `None` reads `MCP_SESSION_MAX_ENTRIES`.
    ///
    /// `upstream_sessions` has no cap: one client session writes an id per
    /// upstream it reaches, and a refused id would send its calls to another
    /// upstream's session. The sweep keeps only the ids of held sessions and
    /// those used within the idle TTL.
    cap: Option<usize>,
    drops: CapDrops,
}

/// What one probe learned about an upstream, plus the clock that expires it.
#[derive(Debug, Clone, Copy)]
struct UpstreamEraEntry {
    support: UpstreamEraSupport,
    resolved_at: Instant,
}

/// What the gateway learned when it opened an upstream connection on its own
/// behalf.
#[derive(Debug, Clone)]
pub struct UpstreamHandshake {
    /// Which era the gateway is speaking to this upstream.
    ///
    /// A modern connection is not a handshake at all — there is nothing to
    /// shake hands with — but it produces the same three facts (capabilities,
    /// version, instructions) from `server/discover`, and every caller wants
    /// them through one accessor rather than two.
    pub era: UpstreamEra,
    /// The upstream's `Mcp-Session-Id`, when it minted one. `None` is a
    /// perfectly good outcome — a stateless upstream mints nothing — and is
    /// why the presence of an *entry* rather than of a session id is what
    /// records "already initialized". Without that distinction the gateway
    /// would re-handshake a stateless upstream on every single request.
    pub session_id: Option<String>,
    /// The `capabilities` object from the upstream's `initialize` result.
    /// Feeds `server/discover` and the `subscriptions/listen` acknowledgement,
    /// both of which must report only what an upstream can actually deliver.
    pub capabilities: serde_json::Value,
    /// The version the upstream negotiated down to.
    pub protocol_version: String,
    /// The upstream's `instructions` — natural-language guidance for an LLM
    /// on using that server. `server/discover` concatenates these so a modern
    /// client gets the same guidance a legacy client reads off `initialize`.
    pub instructions: Option<String>,
    established_at: Instant,
}

impl UpstreamHandshake {
    /// Stamp a freshly-completed **legacy** handshake. `established_at` is set
    /// here and nowhere else, so no caller can mint one that is born stale —
    /// or immortal.
    pub fn legacy(
        session_id: Option<String>,
        capabilities: serde_json::Value,
        protocol_version: String,
        instructions: Option<String>,
    ) -> Self {
        Self {
            era: UpstreamEra::Legacy,
            session_id,
            capabilities,
            protocol_version,
            instructions,
            established_at: Instant::now(),
        }
    }

    /// Record what `server/discover` told us about a **modern** upstream.
    ///
    /// There is no `session_id` parameter and there never can be: a modern
    /// server neither mints nor accepts one, so the type refuses to hold a
    /// value that would then be stamped onto every outbound request.
    pub fn modern(
        capabilities: serde_json::Value,
        instructions: Option<String>,
    ) -> Self {
        Self {
            era: UpstreamEra::Modern,
            session_id: None,
            capabilities,
            protocol_version: crate::mcp::modern::MODERN_PROTOCOL_VERSION.to_string(),
            instructions,
            established_at: Instant::now(),
        }
    }
}

impl McpSessionMap {
    pub fn new() -> Arc<Self> {
        Self::build(None)
    }

    /// A map capped at `cap` entries per map (the handshakes at a quarter),
    /// whatever the setting says.
    #[cfg(test)]
    pub fn with_cap(cap: usize) -> Arc<Self> {
        Self::build(Some(cap))
    }

    fn build(cap: Option<usize>) -> Arc<Self> {
        Arc::new(Self {
            map: DashMap::new(),
            upstream_sessions: DashMap::new(),
            upstream_handshakes: DashMap::new(),
            upstream_eras: DashMap::new(),
            client_log_levels: DashMap::new(),
            cap,
            drops: CapDrops::default(),
        })
    }

    /// The cap `which` is held to: the setting, or a quarter of it for the
    /// handshakes ([`HANDSHAKE_CAP_DIVISOR`]), never below one.
    fn cap_of(&self, which: CappedMap) -> usize {
        let cap = self.cap.unwrap_or_else(max_entries);
        match which {
            CappedMap::UpstreamHandshakes => (cap / HANDSHAKE_CAP_DIVISOR).max(1),
            _ => cap,
        }
    }

    /// Whether a write of a NEW key to a map holding `len` entries is refused
    /// at the cap — counting and (once per sweep interval) logging the
    /// refusal. A write to a key the map already holds is never refused: it
    /// keeps a live entry alive or updates it, and refusing it would let the
    /// sweeper reap an entry in use.
    ///
    /// A full map drops the new write rather than evict: evicting at random
    /// would surprise some other in-flight caller, while a dropped write costs
    /// only the fast path (a re-handshake, a re-probe, an unstamped version)
    /// until a sweep frees room. `len` then the write is not atomic across
    /// DashMap shards, so concurrent writers may pass the cap by at most their
    /// number.
    fn refuses_new(&self, which: CappedMap, len: usize, existing: impl FnOnce() -> bool, tenant_id: Uuid) -> bool {
        let cap = self.cap_of(which);
        if len < cap || existing() {
            return false;
        }
        let i = which as usize;
        self.drops.dropped[i].fetch_add(1, Ordering::Relaxed);
        if !self.drops.warned[i].swap(true, Ordering::Relaxed) {
            tracing::warn!(
                tenant_id = %tenant_id,
                cap,
                map = which.label(),
                "MCP session map at capacity; dropping new entries until a sweep frees room \
                 (counted in streamscope_proxy_mcp_session_cap_drops_total)"
            );
        }
        true
    }

    /// New entries each map refused at the cap since the process started.
    pub fn cap_drops(&self) -> [(CappedMap, u64); 4] {
        CappedMap::ALL.map(|m| (m, self.drops.dropped[m as usize].load(Ordering::Relaxed)))
    }

    /// How many entries the maps hold now.
    pub fn counts(&self) -> McpSessionCounts {
        McpSessionCounts {
            sessions: self.map.len(),
            upstream_sessions: self.upstream_sessions.len(),
            upstream_handshakes: self.upstream_handshakes.len(),
            upstream_eras: self.upstream_eras.len(),
        }
    }

    /// Touch a session id so the sweeper doesn't reap it and a subsequent
    /// `set_protocol_version` has an entry to land on. Called from the
    /// dispatch path right after a successful upstream call.
    pub fn upsert(&self, tenant_id: Uuid, mcp_session_id: &str) {
        if mcp_session_id.is_empty() {
            return;
        }
        let key = (tenant_id, mcp_session_id.to_string());
        if self.refuses_new(CappedMap::Sessions, self.map.len(), || self.map.contains_key(&key), tenant_id) {
            return;
        }
        // Preserve any previously captured `protocol_version` — `upsert` is
        // called on every dispatch but `initialize` only fires once per
        // session, so non-initialize callers must not blank the field.
        // The DashMap `entry` API holds the shard guard for the duration of
        // both branches, so a concurrent `set_protocol_version` on the same
        // key cannot interleave between read-old / write-new.
        self.map
            .entry(key)
            .and_modify(|e| {
                e.last_activity = Instant::now();
                // protocol_version intentionally untouched — `set_protocol_version`
                // is the only writer for that field.
            })
            .or_insert_with(|| SessionEntry {
                last_activity: Instant::now(),
                protocol_version: None,
            });
    }

    /// Stamp the negotiated `protocolVersion` on an existing session entry.
    /// Called from the `initialize` dispatch path right after `upsert` so
    /// every subsequent `mcp_audit` row for the session can carry it.
    /// No-op when the session id is empty or the entry isn't present.
    pub fn set_protocol_version(
        &self,
        tenant_id: Uuid,
        mcp_session_id: &str,
        version: &str,
    ) {
        if mcp_session_id.is_empty() || version.is_empty() {
            return;
        }
        if let Some(mut entry) = self
            .map
            .get_mut(&(tenant_id, mcp_session_id.to_string()))
        {
            entry.protocol_version = Some(version.to_string());
        }
    }

    // ── Client log level ─────────────────────────────────────────────────

    /// Remember the level a legacy client set with `logging/setLevel`, so its
    /// later requests can opt their upstream calls into the same level.
    ///
    /// **Keyed on the authenticated `(tenant, user)`, never on the client's
    /// `Mcp-Session-Id`.** A session id is a client-supplied hint, so keying
    /// on it would let one tenant member turn upstream logging on or off for
    /// a colleague's calls by guessing — the same class of mistake the
    /// user-keyed handshake map exists to avoid, for a smaller prize. The
    /// cost is that a user's concurrent sessions share one level, which is a
    /// user surprising only themselves.
    pub fn set_log_level(&self, tenant_id: Uuid, user_id: Uuid, level: &str) {
        if level.is_empty() {
            return;
        }
        let key = (tenant_id, user_id);
        if self.refuses_new(
            CappedMap::LogLevels,
            self.client_log_levels.len(),
            || self.client_log_levels.contains_key(&key),
            tenant_id,
        ) {
            return;
        }
        self.client_log_levels
            .insert(key, (level.to_string(), Instant::now()));
    }

    /// The level this caller last asked for, if it has not gone idle.
    pub fn log_level(&self, tenant_id: Uuid, user_id: Uuid) -> Option<String> {
        let key = (tenant_id, user_id);
        let entry = self.client_log_levels.get(&key)?;
        if entry.1.elapsed() > idle_ttl() {
            drop(entry);
            self.client_log_levels.remove(&key);
            return None;
        }
        Some(entry.0.clone())
    }

    /// Convenience: look up the protocol version captured for this session.
    /// `None` when the entry doesn't exist or the version was never stamped
    /// (sibling instance handled `initialize`, etc.).
    pub fn protocol_version(&self, tenant_id: Uuid, mcp_session_id: &str) -> Option<String> {
        if mcp_session_id.is_empty() {
            return None;
        }
        self.map
            .get(&(tenant_id, mcp_session_id.to_string()))
            .and_then(|e| e.protocol_version.clone())
    }

    /// Test-only lookup — structural assertion that `upsert` writes the value
    /// the map's documented invariants promise. Production reverse-path uses
    /// `ssrid.…` tokens, not this map.
    #[cfg(test)]
    pub fn lookup(&self, tenant_id: Uuid, mcp_session_id: &str) -> Option<SessionEntry> {
        let key = (tenant_id, mcp_session_id.to_string());
        let mut entry = self.map.get_mut(&key)?;
        entry.last_activity = Instant::now();
        Some(entry.clone())
    }

    /// Record the upstream-side `Mcp-Session-Id` returned from a specific
    /// upstream's `initialize` (or any stateful re-issue). Looked up on
    /// subsequent fan-out / per-route calls so each upstream receives
    /// *its own* session-id rather than the one the agent sees.
    pub fn set_upstream_session(
        &self,
        tenant_id: Uuid,
        downstream_session_id: &str,
        upstream_id: Uuid,
        upstream_session_id: &str,
    ) {
        if downstream_session_id.is_empty() || upstream_session_id.is_empty() {
            return;
        }
        self.upstream_sessions.insert(
            (tenant_id, downstream_session_id.to_string(), upstream_id),
            (upstream_session_id.to_string(), Instant::now()),
        );
    }

    /// Look up the per-upstream session-id captured at initialize. Returns
    /// `None` when no mapping exists (sibling instance handled
    /// `initialize`, stateless upstream, etc.) — callers fall back to
    /// passing the downstream session-id, which works for single-route
    /// VS where downstream and upstream session-ids coincide.
    pub fn upstream_session(
        &self,
        tenant_id: Uuid,
        downstream_session_id: &str,
        upstream_id: Uuid,
    ) -> Option<String> {
        if downstream_session_id.is_empty() {
            return None;
        }
        let key = (tenant_id, downstream_session_id.to_string(), upstream_id);
        let (sid, used) = self.upstream_sessions.get(&key).map(|v| v.clone())?;
        // A use is recorded at most once a minute: a lookup otherwise takes
        // the shard's write lock on every call.
        if used.elapsed() > use_refresh()
            && let Some(mut entry) = self.upstream_sessions.get_mut(&key)
        {
            entry.1 = Instant::now();
        }
        Some(sid)
    }

    /// Remove every entry idle longer than the configured idle TTL
    /// ([`crate::settings::ProxySettings::mcp_session_idle_ttl_secs`],
    /// default 30 min). Run by the periodic sweeper; safe to call from
    /// anywhere because DashMap takes internal locks per shard.
    pub fn sweep(&self) -> usize {
        self.sweep_at(Instant::now())
    }

    /// [`Self::sweep`] as of `now`.
    fn sweep_at(&self, now: Instant) -> usize {
        let cutoff = now - idle_ttl();
        let stale: Vec<_> = self
            .map
            .iter()
            .filter(|kv| kv.value().last_activity < cutoff)
            .map(|kv| kv.key().clone())
            .collect();
        let n = stale.len();
        for key in stale {
            self.map.remove(&key);
        }
        // Gateway-owned handshakes age on their own clock: they are keyed by
        // `(tenant, user, upstream)` and never appear in `map`, so the loop
        // above cannot reach them. Missing this is a pure leak — one entry
        // per user per upstream, held for the process's lifetime.
        self.upstream_handshakes
            .retain(|_, v| v.0.established_at >= cutoff);
        // Same reasoning for the era map, on the same clock: it is keyed by
        // `(tenant, upstream)` and never appears in `map` either. Expiring it
        // is also what lets an upstream upgraded in place be re-probed
        // without a restart.
        self.upstream_eras.retain(|_, v| v.resolved_at >= cutoff);
        self.client_log_levels.retain(|_, v| v.1 >= cutoff);
        // A per-upstream session id is kept while its session is held or it
        // was itself used within the TTL — one pass, after the sessions above
        // were removed: an id of a session `map` refused at its cap, or of a
        // fan-out `initialize` whose parent was never touched, has no parent.
        self.upstream_sessions
            .retain(|k, v| v.1 >= cutoff || self.map.contains_key(&(k.0, k.1.clone())));
        // A map still full after this sweep warns once more.
        for warned in &self.drops.warned {
            warned.store(false, Ordering::Relaxed);
        }
        n
    }

    // ── Upstream protocol era ────────────────────────────────────────────

    /// The era we already resolved for `upstream_id`, if it is still fresh.
    ///
    /// Freshness reuses the session idle TTL so there is one clock in this
    /// map to reason about. It also bounds how long a wrong answer can
    /// persist: an operator who upgrades an upstream to a modern-only build
    /// gets it re-probed on the next call after the window, with no restart.
    pub fn upstream_era_support(
        &self,
        tenant_id: Uuid,
        upstream_id: Uuid,
    ) -> Option<UpstreamEraSupport> {
        let key = (tenant_id, upstream_id);
        let entry = *self.upstream_eras.get(&key)?;
        if entry.resolved_at.elapsed() > idle_ttl() {
            self.upstream_eras.remove(&key);
            return None;
        }
        Some(entry.support)
    }

    /// Record a resolved era.
    ///
    /// Callers MUST only record an era the upstream actually *answered* —
    /// never one inferred from a timeout or an auth failure. A transport blip
    /// cached as `Legacy` would keep a modern upstream mis-addressed for the
    /// whole TTL, and the symptom (every call failing at the handshake) looks
    /// nothing like its cause.
    pub fn set_upstream_era_support(
        &self,
        tenant_id: Uuid,
        upstream_id: Uuid,
        support: UpstreamEraSupport,
    ) {
        let key = (tenant_id, upstream_id);
        if self.refuses_new(
            CappedMap::UpstreamEras,
            self.upstream_eras.len(),
            || self.upstream_eras.contains_key(&key),
            tenant_id,
        ) {
            return;
        }
        self.upstream_eras.insert(
            key,
            UpstreamEraEntry {
                support,
                resolved_at: Instant::now(),
            },
        );
    }

    /// Forget a resolved era so the next call re-probes. Called when a cached
    /// assumption fails, which § Backward Compatibility names as the one
    /// trigger for re-probing.
    pub fn forget_upstream_era(&self, tenant_id: Uuid, upstream_id: Uuid) {
        self.upstream_eras.remove(&(tenant_id, upstream_id));
    }

    // ── Gateway-owned upstream handshakes (modern clients) ───────────────

    /// The handshake the gateway already performed against `upstream_id` for
    /// this `(tenant, user)`, if it is still fresh.
    ///
    /// Expiry reuses the session idle TTL: an upstream that has heard nothing
    /// for that long may well have swept its own session, and presenting a
    /// stale `Mcp-Session-Id` earns a `-32600` that looks to the client like
    /// the tool is broken. Re-handshaking costs one round trip.
    pub fn handshake(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        upstream_id: Uuid,
        inputs: u64,
        era: UpstreamEra,
    ) -> Option<UpstreamHandshake> {
        let key = (tenant_id, user_id, upstream_id, era.is_modern());
        let (stale, same_inputs) = {
            let entry = self.upstream_handshakes.get(&key)?;
            (entry.0.established_at.elapsed() > idle_ttl(), entry.1 == inputs)
        };
        if stale {
            self.upstream_handshakes.remove(&key);
            return None;
        }
        if !same_inputs {
            return None;
        }
        self.upstream_handshakes.get(&key).map(|e| e.0.clone())
    }

    /// Record a completed gateway-owned handshake.
    /// Returns the handshake it recorded, so the caller can use it without a
    /// read-back — and still gets a usable value when the map is at capacity
    /// and the entry was not stored.
    pub fn set_handshake(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        upstream_id: Uuid,
        inputs: u64,
        handshake: UpstreamHandshake,
    ) -> UpstreamHandshake {
        // The era comes off the handshake itself, so a caller cannot file a
        // modern connection under the legacy slot.
        let key = (tenant_id, user_id, upstream_id, handshake.era.is_modern());
        if self.refuses_new(
            CappedMap::UpstreamHandshakes,
            self.upstream_handshakes.len(),
            || self.upstream_handshakes.contains_key(&key),
            tenant_id,
        ) {
            // Dropping the write costs a re-handshake on the next request,
            // which is correct-but-slow. Evicting a live entry at random
            // would instead hand some other in-flight caller a stale session
            // id, which is correct-looking and wrong.
            return handshake;
        }
        self.upstream_handshakes.insert(key, (handshake.clone(), inputs));
        handshake
    }

    /// Forget a gateway-owned handshake so the next request re-establishes
    /// it. Called when an upstream rejects our session id — the honest
    /// recovery for "the upstream swept the session out from under us".
    pub fn forget_handshake(
        &self,
        tenant_id: Uuid,
        user_id: Uuid,
        upstream_id: Uuid,
        era: UpstreamEra,
    ) {
        self.upstream_handshakes
            .remove(&(tenant_id, user_id, upstream_id, era.is_modern()));
    }

    /// Test-only — current entry count.
    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.map.len()
    }

    /// Test-only — current gateway-handshake count.
    #[cfg(test)]
    pub fn handshake_len(&self) -> usize {
        self.upstream_handshakes.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_gateway_handshake_round_trips_and_is_scoped_to_its_user() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        let alice = Uuid::new_v4();
        let bob = Uuid::new_v4();
        let upstream = Uuid::new_v4();

        m.set_handshake(
            tenant,
            alice,
            upstream,
            0,
            UpstreamHandshake::legacy(
                Some("up-sid-1".into()),
                serde_json::json!({"tools": {}}),
                "2025-11-25".into(),
                None,
            ),
        );

        let got = m.handshake(tenant, alice, upstream, 0, UpstreamEra::Legacy).unwrap();
        assert_eq!(got.session_id.as_deref(), Some("up-sid-1"));
        assert_eq!(got.protocol_version, "2025-11-25");

        // The key includes the authenticated user, so a tenant-mate cannot
        // reach Alice's upstream session context.
        assert!(m.handshake(tenant, bob, upstream, 0, UpstreamEra::Legacy).is_none());
        // Nor can another tenant.
        assert!(m.handshake(Uuid::new_v4(), alice, upstream, 0, UpstreamEra::Legacy).is_none());
    }

    #[test]
    fn a_stateless_upstream_is_still_recorded_as_handshaken() {
        // A stateless upstream mints no session id. If the *presence of a
        // session id* were what recorded the handshake, the gateway would
        // re-`initialize` such an upstream on every single request.
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstream = Uuid::new_v4();
        m.set_handshake(
            tenant,
            user,
            upstream,
            0,
            UpstreamHandshake::legacy(None, serde_json::json!({}), "2025-11-25".into(), None),
        );
        let got = m.handshake(tenant, user, upstream, 0, UpstreamEra::Legacy).unwrap();
        assert!(got.session_id.is_none());
    }

    /// A handshake is found only under the inputs it was opened with; one
    /// opened under other inputs replaces it, so the map holds one entry per
    /// (tenant, user, upstream, era) and no caller rides another's session.
    #[test]
    fn a_handshake_is_found_only_under_the_inputs_it_was_opened_with() {
        let m = McpSessionMap::new();
        let (tenant, user, upstream) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        let handshake =
            |sid: &str| UpstreamHandshake::legacy(Some(sid.into()), serde_json::json!({}), "x".into(), None);
        m.set_handshake(tenant, user, upstream, 1, handshake("a"));
        assert_eq!(
            m.handshake(tenant, user, upstream, 1, UpstreamEra::Legacy).unwrap().session_id.as_deref(),
            Some("a")
        );
        assert!(m.handshake(tenant, user, upstream, 2, UpstreamEra::Legacy).is_none());
        m.set_handshake(tenant, user, upstream, 2, handshake("b"));
        assert!(m.handshake(tenant, user, upstream, 1, UpstreamEra::Legacy).is_none());
        assert_eq!(
            m.handshake(tenant, user, upstream, 2, UpstreamEra::Legacy).unwrap().session_id.as_deref(),
            Some("b")
        );
        assert_eq!(m.handshake_len(), 1);
    }

    #[test]
    fn forgetting_a_handshake_forces_a_re_establish() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstream = Uuid::new_v4();
        m.set_handshake(
            tenant,
            user,
            upstream,
            0,
            UpstreamHandshake::legacy(Some("s".into()), serde_json::json!({}), "x".into(), None),
        );
        assert!(m.handshake(tenant, user, upstream, 0, UpstreamEra::Legacy).is_some());
        m.forget_handshake(tenant, user, upstream, UpstreamEra::Legacy);
        assert!(m.handshake(tenant, user, upstream, 0, UpstreamEra::Legacy).is_none());
        assert_eq!(m.handshake_len(), 0);
    }

    #[test]
    fn an_upstream_era_is_shared_by_every_caller_but_not_across_tenants() {
        // The era is a property of the server: a probe one user paid for
        // answers the question for the next. Keying it per user would
        // re-probe the same server once per caller.
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        let other_tenant = Uuid::new_v4();
        let upstream = Uuid::new_v4();

        assert!(m.upstream_era_support(tenant, upstream).is_none());
        m.set_upstream_era_support(tenant, upstream, UpstreamEraSupport::MODERN_ONLY);
        assert_eq!(
            m.upstream_era_support(tenant, upstream),
            Some(UpstreamEraSupport::MODERN_ONLY)
        );
        // A different tenant's row for the same upstream id is a different
        // upstream — ids are tenant-scoped.
        assert!(m.upstream_era_support(other_tenant, upstream).is_none());

        m.forget_upstream_era(tenant, upstream);
        assert!(m.upstream_era_support(tenant, upstream).is_none());
    }

    #[test]
    fn a_modern_handshake_can_never_carry_a_session_id() {
        // A modern server neither mints nor accepts one. The constructor
        // takes no parameter for it, so there is no way to reach a state
        // where one is stamped onto an outbound modern request.
        let h = UpstreamHandshake::modern(serde_json::json!({"tools": {}}), None);
        assert!(h.session_id.is_none());
        assert_eq!(h.era, UpstreamEra::Modern);
        assert_eq!(h.protocol_version, crate::mcp::modern::MODERN_PROTOCOL_VERSION);

        let l = UpstreamHandshake::legacy(
            Some("s".into()),
            serde_json::json!({}),
            "2025-11-25".into(),
            None,
        );
        assert_eq!(l.era, UpstreamEra::Legacy);
    }

    #[test]
    fn upsert_and_lookup_round_trip() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        m.upsert(tenant, "abc");
        assert!(m.lookup(tenant, "abc").is_some());
    }

    #[test]
    fn empty_session_id_is_a_noop() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        m.upsert(tenant, "");
        assert_eq!(m.len(), 0);
    }

    #[test]
    fn cross_tenant_isolation() {
        let m = McpSessionMap::new();
        let t1 = Uuid::new_v4();
        let t2 = Uuid::new_v4();
        m.upsert(t1, "shared");
        assert!(m.lookup(t1, "shared").is_some());
        assert!(m.lookup(t2, "shared").is_none());
    }

    #[test]
    fn protocol_version_round_trip_and_preserve_on_reupsert() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        m.upsert(tenant, "s1");
        // Initially absent.
        assert!(m.protocol_version(tenant, "s1").is_none());
        m.set_protocol_version(tenant, "s1", "2025-11-25");
        assert_eq!(
            m.protocol_version(tenant, "s1").as_deref(),
            Some("2025-11-25")
        );
        // Re-upsert (e.g., a follow-up tools/call) must preserve the version.
        m.upsert(tenant, "s1");
        assert_eq!(
            m.protocol_version(tenant, "s1").as_deref(),
            Some("2025-11-25")
        );
    }

    #[test]
    fn upstream_session_per_upstream() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        let up_a = Uuid::new_v4();
        let up_b = Uuid::new_v4();
        m.set_upstream_session(tenant, "ds", up_a, "sid_a");
        m.set_upstream_session(tenant, "ds", up_b, "sid_b");
        assert_eq!(m.upstream_session(tenant, "ds", up_a).as_deref(), Some("sid_a"));
        assert_eq!(m.upstream_session(tenant, "ds", up_b).as_deref(), Some("sid_b"));
        // Unknown downstream session → None.
        assert!(m.upstream_session(tenant, "other", up_a).is_none());
        // Empty downstream session → None.
        assert!(m.upstream_session(tenant, "", up_a).is_none());
        // Empty upstream session is a no-op (no insert).
        m.set_upstream_session(tenant, "ds", up_a, "");
        assert_eq!(m.upstream_session(tenant, "ds", up_a).as_deref(), Some("sid_a"));
    }

    /// A minute ago: older than the cutoff of [`sweep_a_minute_later`], with
    /// no need for a clock older than the idle TTL.
    fn a_minute_ago() -> Instant {
        Instant::now().checked_sub(Duration::from_secs(61)).expect("the clock is a minute old")
    }

    /// A sweep whose cutoff is a minute before now.
    fn sweep_a_minute_later(m: &McpSessionMap) {
        m.sweep_at(Instant::now() + idle_ttl() - Duration::from_secs(60));
    }

    /// An idle id goes with its session, and stays while the session is held.
    #[test]
    fn upstream_sessions_evicted_with_parent() {
        let m = McpSessionMap::new();
        let tenant = Uuid::new_v4();
        let up = Uuid::new_v4();
        m.upsert(tenant, "ds");
        m.set_upstream_session(tenant, "ds", up, "sid");
        assert!(m.upstream_session(tenant, "ds", up).is_some());
        let old = a_minute_ago();
        for mut e in m.upstream_sessions.iter_mut() {
            e.value_mut().1 = old;
        }
        sweep_a_minute_later(&m);
        assert!(m.upstream_session(tenant, "ds", up).is_some(), "kept while its session is held");
        for mut e in m.upstream_sessions.iter_mut() {
            e.value_mut().1 = old;
        }
        m.map.get_mut(&(tenant, "ds".to_string())).expect("held").last_activity = old;
        sweep_a_minute_later(&m);
        assert!(m.upstream_session(tenant, "ds", up).is_none(), "gone with its session");
    }

    /// A per-upstream session id whose parent is not in `map` (refused at
    /// the cap, or a fan-out's) is swept once idle; one in use, or of a held
    /// session, is kept.
    #[test]
    fn an_upstream_session_without_its_parent_is_swept_once_idle() {
        let m = McpSessionMap::with_cap(3);
        let tenant = Uuid::new_v4();
        let up = Uuid::new_v4();
        for sid in ["held", "a", "b"] {
            m.upsert(tenant, sid);
        }
        m.upsert(tenant, "refused");
        assert_eq!(dropped(&m, CappedMap::Sessions), 1, "the session map is full");
        m.set_upstream_session(tenant, "refused", up, "idle");
        m.set_upstream_session(tenant, "used", up, "live");
        let old = a_minute_ago();
        m.set_upstream_session(tenant, "held", up, "parented");
        for mut e in m.upstream_sessions.iter_mut() {
            e.value_mut().1 = old;
        }
        assert_eq!(m.upstream_session(tenant, "used", up).as_deref(), Some("live"), "a lookup is a use");
        sweep_a_minute_later(&m);
        assert!(m.upstream_session(tenant, "refused", up).is_none(), "the idle id is swept");
        assert_eq!(m.upstream_session(tenant, "used", up).as_deref(), Some("live"));
        assert_eq!(m.upstream_session(tenant, "held", up).as_deref(), Some("parented"), "an id of a held session is kept, used or not");
    }

    fn dropped(m: &McpSessionMap, which: CappedMap) -> u64 {
        m.cap_drops()[which as usize].1
    }

    fn last_activity(m: &McpSessionMap, tenant: Uuid, sid: &str) -> Instant {
        m.map.get(&(tenant, sid.to_string())).expect("the session is held").last_activity
    }

    /// At the cap a session the map already holds is still touched: its
    /// activity moves, so the sweeper does not reap a session in use.
    #[test]
    fn a_live_session_at_the_cap_is_still_touched() {
        let m = McpSessionMap::with_cap(3);
        let tenant = Uuid::new_v4();
        for sid in ["a", "b", "c"] {
            m.upsert(tenant, sid);
        }
        let before = last_activity(&m, tenant, "a");
        std::thread::sleep(Duration::from_millis(5));
        m.upsert(tenant, "a");
        assert!(last_activity(&m, tenant, "a") > before, "the touch at the cap landed");
        m.set_protocol_version(tenant, "a", "2025-11-25");
        assert_eq!(m.protocol_version(tenant, "a").as_deref(), Some("2025-11-25"));
        assert_eq!(dropped(&m, CappedMap::Sessions), 0, "a touch is not a refusal");
    }

    /// One below the cap a new session is stored; at the cap a new one is
    /// refused and counted, and nothing held is evicted for it.
    #[test]
    fn a_new_session_is_stored_below_the_cap_and_refused_and_counted_at_it() {
        let m = McpSessionMap::with_cap(3);
        let tenant = Uuid::new_v4();
        m.upsert(tenant, "a");
        m.upsert(tenant, "b");
        m.upsert(tenant, "c");
        assert_eq!(m.len(), 3, "the third (at cap - 1 held) is stored");
        assert_eq!(dropped(&m, CappedMap::Sessions), 0);

        m.upsert(tenant, "d");
        m.upsert(tenant, "e");
        assert_eq!(m.len(), 3);
        assert!(m.lookup(tenant, "d").is_none());
        for sid in ["a", "b", "c"] {
            assert!(m.lookup(tenant, sid).is_some(), "{sid} is still held");
        }
        assert_eq!(dropped(&m, CappedMap::Sessions), 2, "each refused write is counted");
        assert_eq!(dropped(&m, CappedMap::UpstreamHandshakes), 0, "per map");
    }

    /// The handshake map is held to a quarter of the cap: one below it a new
    /// handshake is stored; at it an existing key is replaced in place and a
    /// new one is refused, counted, and still returned for this one call.
    #[test]
    fn the_handshake_map_is_held_to_a_quarter_of_the_cap() {
        let m = McpSessionMap::with_cap(12);
        let tenant = Uuid::new_v4();
        let user = Uuid::new_v4();
        let upstreams: Vec<Uuid> = (0..4).map(|_| Uuid::new_v4()).collect();
        let handshake =
            |sid: &str| UpstreamHandshake::legacy(Some(sid.into()), serde_json::json!({}), "x".into(), None);

        for (i, up) in upstreams[..3].iter().enumerate() {
            m.set_handshake(tenant, user, *up, 0, handshake(&i.to_string()));
        }
        assert_eq!(m.handshake_len(), 3, "the third (at cap - 1 held) is stored");
        assert_eq!(dropped(&m, CappedMap::UpstreamHandshakes), 0);

        m.set_handshake(tenant, user, upstreams[0], 0, handshake("0b"));
        assert_eq!(
            m.handshake(tenant, user, upstreams[0], 0, UpstreamEra::Legacy).and_then(|h| h.session_id).as_deref(),
            Some("0b")
        );
        let returned = m.set_handshake(tenant, user, upstreams[3], 0, handshake("3"));
        assert_eq!(returned.session_id.as_deref(), Some("3"));
        assert!(m.handshake(tenant, user, upstreams[3], 0, UpstreamEra::Legacy).is_none());
        assert_eq!(m.handshake_len(), 3);
        assert_eq!(dropped(&m, CappedMap::UpstreamHandshakes), 1);
    }

    /// The era and log-level maps: at the cap an existing key is replaced in
    /// place, a new one is refused and counted; below it a new one is stored.
    #[test]
    fn the_other_capped_maps_replace_an_existing_key_and_refuse_a_new_one_at_the_cap() {
        let m = McpSessionMap::with_cap(2);
        let tenant = Uuid::new_v4();
        let (u1, u2, u3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());

        m.set_upstream_era_support(tenant, u1, UpstreamEraSupport::BOTH);
        m.set_upstream_era_support(tenant, u2, UpstreamEraSupport::BOTH);
        m.set_upstream_era_support(tenant, u1, UpstreamEraSupport::BOTH);
        m.set_upstream_era_support(tenant, u3, UpstreamEraSupport::BOTH);
        assert!(m.upstream_era_support(tenant, u2).is_some());
        assert!(m.upstream_era_support(tenant, u3).is_none());
        assert_eq!(dropped(&m, CappedMap::UpstreamEras), 1);

        let (v1, v2, v3) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
        m.set_log_level(tenant, v1, "info");
        m.set_log_level(tenant, v2, "info");
        m.set_log_level(tenant, v1, "debug");
        m.set_log_level(tenant, v3, "info");
        assert_eq!(m.log_level(tenant, v1).as_deref(), Some("debug"));
        assert!(m.log_level(tenant, v3).is_none());
        assert_eq!(dropped(&m, CappedMap::LogLevels), 1);
    }

    /// A full map warns once per sweep interval, not once per request; the
    /// count goes on.
    #[test]
    fn a_full_map_warns_once_until_the_next_sweep() {
        let m = McpSessionMap::with_cap(1);
        let tenant = Uuid::new_v4();
        let warned = |m: &McpSessionMap| m.drops.warned[CappedMap::Sessions as usize].load(Ordering::Relaxed);
        m.upsert(tenant, "a");
        assert!(!warned(&m));
        m.upsert(tenant, "b");
        assert!(warned(&m));
        m.sweep();
        assert!(!warned(&m), "the sweep re-arms the warning");
        m.upsert(tenant, "c");
        assert!(warned(&m), "a map still full warns again");
        assert_eq!(dropped(&m, CappedMap::Sessions), 2);
    }
}
