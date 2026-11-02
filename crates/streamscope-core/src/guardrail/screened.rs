//! What the inbound guardrail has screened, and what it did to it.
//!
//! A client resends its whole conversation on every request, so the inbound
//! hop screens only what it has not screened before: a conversation item is
//! recorded here once every check read it to a settled verdict, under the
//! tenant, the settings that decide an inbound verdict ([`fingerprint`]), the
//! client protocol and the item's exact text (`RequestContent::screen_keys`).
//! A verdict of no finding is a fact about its text, held for every
//! conversation of the tenant; one with a finding — an edit, an observe flag —
//! or an incomplete scan is held for the conversation it was found in alone,
//! so the same text in another conversation is screened, and reported, there
//! again. The record keeps what
//! every later request carrying the item must carry again ([`Screened`]): the
//! texts an enforce check wrote into it (a placeholder, a mask) — the client
//! keeps its own original, so an edited item it sends back is edited again
//! from the record, never sent as the client has it — and the badges that say
//! so, or that its scan was incomplete. An item with neither (no finding, or
//! one an observe check only recorded) goes out as sent. An item a detector
//! failed on is not recorded.
//!
//! The record is this process's own, bounded in bytes (the least recently used
//! entry goes first) and forgotten after a day: what it does not hold is screened again — a missing entry costs a
//! scan, never a skipped one.

use std::sync::{Arc, LazyLock};
use std::time::Duration;

use sha2::{Digest, Sha256};

use super::GuardrailSettings;
use crate::audit::badge::AuditBadge;

/// How many bytes the record holds — its keys and the texts an edit keeps,
/// weighed per entry.
const CAPACITY_BYTES: u64 = 64 * 1024 * 1024;

/// How long an entry is kept, read or not: a verdict outlives no detector
/// change behind the same settings (a model upgraded at the same endpoint) by
/// more than this.
const LIFETIME: Duration = Duration::from_secs(24 * 3600);

/// What the guardrail did to a screened item, for every later request carrying
/// it to do again.
#[derive(Debug, Clone, PartialEq, Default)]
pub struct Screened {
    /// Its messages' texts, by their place among the item's messages, as an
    /// enforce check wrote them; none when it goes out as sent.
    pub texts: Vec<(usize, String)>,
    /// The badges those texts carry, and an incomplete scan's.
    pub badges: Vec<AuditBadge>,
    /// Whether a check found something in it — reported in the conversation
    /// it was found in, so the record holds it for that conversation alone,
    /// even when nothing about it is done again (an observe finding).
    pub found: bool,
}

static SCREENED: LazyLock<moka::future::Cache<String, Arc<Screened>>> = LazyLock::new(|| {
    // Least recently used goes first: a new conversation's items are always
    // taken in, never refused for being seen once.
    moka::future::Cache::builder()
        .eviction_policy(moka::policy::EvictionPolicy::lru())
        .max_capacity(CAPACITY_BYTES)
        .weigher(|key: &String, screened: &Arc<Screened>| {
            let texts: usize = screened.texts.iter().map(|(_, t)| t.len()).sum();
            u32::try_from(key.len() + texts + 64).unwrap_or(u32::MAX)
        })
        .time_to_live(LIFETIME)
        .build()
});

/// The settings that decide an inbound verdict, as one key part: a check
/// turned on or off, its mode, its detector, threshold or entities — any of
/// them changed screens everything again. Settings that decide nothing about
/// an inbound verdict (a detection notice, response scanning, the detector's
/// timeout, the web surface's spotlighting and window cap) are not part of it.
pub fn fingerprint(settings: &GuardrailSettings) -> String {
    let mut inbound = settings.clone();
    inbound.notify_on_detection = false;
    inbound.timeout_ms = 0;
    inbound.pii.scan_response = false;
    // The web surface's own knobs.
    inbound.spotlight = false;
    inbound.max_windows_content = 0;
    let json = serde_json::to_vec(&inbound).unwrap_or_default();
    hex::encode(&Sha256::digest(&json)[..16])
}

/// One entry's key: the conversation's for a verdict held for it alone, none
/// for one held for the tenant. The protocol is part of it: the same bytes
/// read as different text on two protocols (a part one protocol reads as text,
/// another does not), so a verdict holds for the protocol it was read on alone.
fn entry(tenant: uuid::Uuid, fingerprint: &str, protocol: &str, item_key: &str, conversation: Option<uuid::Uuid>) -> String {
    match conversation {
        Some(c) => format!("{tenant}|{fingerprint}|{protocol}|{item_key}|{c}"),
        None => format!("{tenant}|{fingerprint}|{protocol}|{item_key}"),
    }
}

/// What was done to this item, screened under these settings for this tenant
/// on this client protocol: in this conversation, or as a fact of its text.
pub async fn get(
    tenant: uuid::Uuid,
    fingerprint: &str,
    protocol: &str,
    item_key: &str,
    conversation: Option<uuid::Uuid>,
) -> Option<Arc<Screened>> {
    if conversation.is_some()
        && let Some(found) = SCREENED.get(&entry(tenant, fingerprint, protocol, item_key, conversation)).await
    {
        return Some(found);
    }
    SCREENED.get(&entry(tenant, fingerprint, protocol, item_key, None)).await
}

/// Records what was done to an item: as a fact of its text when nothing was
/// found in it, else for this conversation — not at all without one.
pub async fn record(
    tenant: uuid::Uuid,
    fingerprint: &str,
    protocol: &str,
    item_key: &str,
    conversation: Option<uuid::Uuid>,
    screened: Screened,
) {
    let held_for = if screened == Screened::default() {
        None
    } else if conversation.is_some() {
        conversation
    } else {
        return;
    };
    SCREENED.insert(entry(tenant, fingerprint, protocol, item_key, held_for), Arc::new(screened)).await;
}
