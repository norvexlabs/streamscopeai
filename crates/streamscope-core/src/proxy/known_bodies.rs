//! The conversation messages and tool sets this process knows the content
//! store holds: buffered in the edge's outbox, or stored by admin-api from a
//! share it committed.
//!
//! A captured history message whose stored key is here is named by its key
//! alone ([`CapturedMessage::Known`]), and so is a tool set
//! ([`CapturedTools::json`] `None`): neither is held in flight nor shipped
//! again. Without this, every turn would carry, parse and buffer its whole
//! history and tool catalog, and a writer falling behind would hold a channel
//! of them.
//!
//! Invariants to preserve:
//! - **An entry is a stored key: the hash of the whole stored value**
//!   ([`super::content::stored_message_key`], [`super::content::hash_tools_blob`]),
//!   never a link or exact hash, which leave parts out — a key computed over
//!   less would name another body. Its [`Kind`] is part of it: the stores
//!   are different tables.
//! - **A key is added only for a body the outbox committed with a record
//!   naming it** (`OutboxV2::enqueue`'s committed keys), and **removed once
//!   anyone says it is held nowhere**: the outbox naming it unavailable in a
//!   share, admin-api asking for it again, the tenant deleted. A key held
//!   nowhere then costs the turns captured before its removal an
//!   "unavailable" mark — visible, never another body.
//! - **An entry lives [`LIFETIME`] from when it was added**, whatever its
//!   hits. Once the outbox has shipped a body, the entry rests on admin-api
//!   holding it, not on the outbox's ack: a forgotten ack (the cap sweep, a
//!   failed ack write) only stops the outbox from carrying the body again, and
//!   a key admin-api holds but no share carries lands whole. The lifetime
//!   bounds how long an entry outlives a body admin-api later purged (24 h
//!   acks, retention days).

use std::sync::LazyLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// How long an entry is trusted after it was added.
pub const LIFETIME: Duration = Duration::from_secs(3600);

/// The most entries held: an entry is a tenant and a 32-byte key (48 B) with
/// the cache's own per-entry overhead, ~100 B in all, so ~16 MiB.
const CAPACITY: u64 = 160_000;

/// Which content store a key names.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Kind {
    Message,
    ToolDefinition,
}

impl Kind {
    /// The kind named by the outbox's content kind, if it is one of these.
    pub fn of_outbox_kind(kind: &str) -> Option<Self> {
        match kind {
            "message" => Some(Self::Message),
            "tool_definition" => Some(Self::ToolDefinition),
            _ => None,
        }
    }
}

/// A tenant's stored key of one kind, as bytes (the 64 hex digits of the
/// store's hash, decoded).
type Key = (uuid::Uuid, Kind, [u8; 32]);

static KNOWN: LazyLock<moka::sync::Cache<Key, ()>> = LazyLock::new(|| {
    moka::sync::Cache::builder()
        .eviction_policy(moka::policy::EvictionPolicy::lru())
        .max_capacity(CAPACITY)
        // Counted from the insert; a read does not extend it.
        .time_to_live(LIFETIME)
        .build()
});

/// Cumulative counts (`/metrics`): captured messages found, not found, and
/// keys removed.
static HITS: AtomicU64 = AtomicU64::new(0);
static MISSES: AtomicU64 = AtomicU64::new(0);
static REMOVED: AtomicU64 = AtomicU64::new(0);

/// One message of a request's history as captured for the audit record, aligned
/// with its link hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CapturedMessage {
    /// The message as sent, serialised from the typed request: stored and
    /// keyed by the edge writer.
    Body(String),
    /// A message the content store holds: named by its stored key, not carried.
    Known { key: String },
}

impl CapturedMessage {
    /// The message's JSON, when it is carried.
    pub fn body(&self) -> Option<&str> {
        match self {
            Self::Body(json) => Some(json),
            Self::Known { .. } => None,
        }
    }
}

fn key_bytes(hex_key: &str) -> Option<[u8; 32]> {
    let mut out = [0u8; 32];
    hex::decode_to_slice(hex_key, &mut out).ok()?;
    Some(out)
}

/// Whether the content store holds the body of `kind` stored under `key` for `tenant`.
pub fn holds(tenant: uuid::Uuid, kind: Kind, key: &str) -> bool {
    // `get`, not `contains_key`: a hit is a use, so the set evicts the least
    // recently used.
    let found = key_bytes(key).is_some_and(|k| KNOWN.get(&(tenant, kind, k)).is_some());
    if found { &HITS } else { &MISSES }.fetch_add(1, Ordering::Relaxed);
    found
}

/// The content store now holds these bodies of `tenant`'s (the outbox
/// committed them with a record that names them).
pub fn add<'a>(tenant: uuid::Uuid, keys: impl IntoIterator<Item = (Kind, &'a str)>) {
    for (kind, key) in keys {
        if let Some(k) = key_bytes(key) {
            KNOWN.insert((tenant, kind, k), ());
        }
    }
}

/// These bodies of `tenant`'s are held nowhere any more.
pub fn remove<'a>(tenant: uuid::Uuid, keys: impl IntoIterator<Item = (Kind, &'a str)>) {
    for (kind, key) in keys {
        if let Some(k) = key_bytes(key)
            && KNOWN.remove(&(tenant, kind, k)).is_some()
        {
            REMOVED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// `tenant` was deleted: none of its bodies is held.
pub fn remove_tenant(tenant: uuid::Uuid) {
    // An invalidation predicate would need moka's `support_invalidation_closures`;
    // the set is small enough to walk.
    let keys: Vec<Key> = KNOWN.iter().filter(|(k, _)| k.0 == tenant).map(|(k, _)| *k).collect();
    for k in keys {
        if KNOWN.remove(&k).is_some() {
            REMOVED.fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// What the set holds and has done, for the scrape.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct KnownBodiesStats {
    pub entries: u64,
    pub hits: u64,
    pub misses: u64,
    pub removed: u64,
}

pub fn stats() -> KnownBodiesStats {
    KNOWN.run_pending_tasks();
    KnownBodiesStats {
        entries: KNOWN.entry_count(),
        hits: HITS.load(Ordering::Relaxed),
        misses: MISSES.load(Ordering::Relaxed),
        removed: REMOVED.load(Ordering::Relaxed),
    }
}

/// The captured history of a request, each message either carried or named by
/// its stored key. `keep` are the messages read again after capture by their
/// JSON (the conversation's opening, for the turn's fingerprints): always
/// carried. `tenant` is `None` when nothing may be named by key (a request
/// whose media the finalize pass rewrites and summarises over its whole
/// history): every message is carried, as sent.
pub fn capture(messages: Vec<String>, tenant: Option<uuid::Uuid>, keep: Option<usize>) -> Vec<CapturedMessage> {
    let Some(tenant) = tenant else {
        return messages.into_iter().map(CapturedMessage::Body).collect();
    };
    messages
        .into_iter()
        .enumerate()
        .map(|(i, json)| {
            if Some(i) == keep {
                return CapturedMessage::Body(json);
            }
            // The key the edge writer stores the body under: the hash of the
            // value this JSON reads as — computed the same way here, so a hit
            // names exactly the body a miss would have stored.
            let Ok(value) = serde_json::from_str::<serde_json::Value>(&json) else {
                return CapturedMessage::Body(json);
            };
            let (key, _) = super::content::stored_message_key(&value);
            if holds(tenant, Kind::Message, &key) {
                CapturedMessage::Known { key }
            } else {
                CapturedMessage::Body(json)
            }
        })
        .collect()
}

/// A request's tool set as captured for the audit record: its content-store
/// key, and its JSON unless the store holds it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapturedTools {
    /// [`super::content::hash_tools_blob`] of the set.
    pub hash: String,
    /// The set as stored — the very bytes the hash covers; `None` when the
    /// content store holds it, so it is named by its hash alone.
    pub json: Option<String>,
}

/// A tool set as captured: its tree, read once into the stored JSON and its
/// key and then dropped. `tenant` is `None` when nothing may be named by key:
/// the set is carried.
pub fn capture_tools(tools: Option<serde_json::Value>, tenant: Option<uuid::Uuid>) -> Option<CapturedTools> {
    let json = serde_json::to_string(&tools?).ok()?;
    let hash = super::content::hash_tools_json(&json);
    let known = tenant.is_some_and(|t| holds(t, Kind::ToolDefinition, &hash));
    Some(CapturedTools { hash, json: (!known).then_some(json) })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    fn key_of(json: &str) -> String {
        super::super::content::stored_message_key(&serde_json::from_str(json).unwrap()).0
    }

    #[test]
    fn a_known_message_is_named_by_the_key_its_body_is_stored_under() {
        let tenant = uuid::Uuid::new_v4();
        let old = r#"{"role":"user","content":"first"}"#.to_string();
        let new = r#"{"role":"assistant","content":"second"}"#.to_string();
        add(tenant, [(Kind::Message, key_of(&old).as_str())]);
        let captured = capture(vec![old.clone(), new.clone()], Some(tenant), None);
        assert_eq!(captured, vec![CapturedMessage::Known { key: key_of(&old) }, CapturedMessage::Body(new)]);
    }

    #[test]
    fn a_kept_message_and_a_request_with_no_tenant_carry_every_body() {
        let tenant = uuid::Uuid::new_v4();
        let old = r#"{"role":"user","content":"opening"}"#.to_string();
        add(tenant, [(Kind::Message, key_of(&old).as_str())]);
        assert_eq!(capture(vec![old.clone()], Some(tenant), Some(0)), vec![CapturedMessage::Body(old.clone())]);
        assert_eq!(capture(vec![old.clone()], None, None), vec![CapturedMessage::Body(old.clone())]);
        // Positive control: the same message, neither kept nor withheld, is named.
        assert_matches!(capture(vec![old], Some(tenant), None)[0], CapturedMessage::Known { .. });
    }

    #[test]
    fn a_body_is_known_to_its_own_tenant_alone_and_until_removed() {
        let (a, b) = (uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
        let key = key_of(r#"{"role":"user","content":"x"}"#);
        fn msg(k: &str) -> [(Kind, &str); 1] {
            [(Kind::Message, k)]
        }
        add(a, msg(&key));
        assert!(holds(a, Kind::Message, &key));
        assert!(!holds(b, Kind::Message, &key), "another tenant's store never holds it");
        assert!(!holds(a, Kind::ToolDefinition, &key), "nor another store");
        remove(a, msg(&key));
        assert!(!holds(a, Kind::Message, &key));
        add(a, msg(&key));
        add(b, msg(&key));
        remove_tenant(a);
        assert!(!holds(a, Kind::Message, &key));
        assert!(holds(b, Kind::Message, &key), "a tenant's deletion leaves another's keys");
    }

    #[test]
    fn a_known_tool_set_is_named_by_the_key_the_writer_stores_it_under() {
        let tenant = uuid::Uuid::new_v4();
        let tools = serde_json::json!([{"name": "read", "input_schema": {"type": "object", "properties": {"path": {"type": "string"}}}}]);
        let carried = capture_tools(Some(tools.clone()), Some(tenant)).unwrap();
        assert_eq!(carried.hash, super::super::content::hash_tools_blob(&tools));
        assert_eq!(carried.json.as_deref(), Some(serde_json::to_string(&tools).unwrap().as_str()));
        add(tenant, [(Kind::ToolDefinition, carried.hash.as_str())]);
        let named = capture_tools(Some(tools.clone()), Some(tenant)).unwrap();
        assert_eq!(named, CapturedTools { hash: carried.hash.clone(), json: None });
        assert!(capture_tools(Some(tools), None).unwrap().json.is_some(), "with no tenant it is carried");
        assert_eq!(capture_tools(None, Some(tenant)), None);
    }
}
