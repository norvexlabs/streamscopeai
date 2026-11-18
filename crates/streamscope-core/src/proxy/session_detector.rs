//! Session detection: which recorded turn a request continues.
//!
//! Every turn this replica served recently is kept per `(user, key)` with the
//! link hashes of its history. A turn holds only the hashes its parent turn
//! does not ([`Turn::own`]) and points at that parent, so a session's turns
//! share one chain instead of each repeating every hash before it; matching
//! walks the chain and stays exact. What the detector holds is weighed in
//! bytes ([`Turn::charge`]), counted exactly as turns are created and dropped,
//! and capped ([`SessionDetector::with_capacity`]).

use sha2::{Digest, Sha256};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use uuid::Uuid;

use super::content::session_id_from_client;

/// A message's link hash in its 32 bytes, not its 64-character hex text: the
/// detector keeps one per message of every recent turn. A lowercase hex hash
/// (what the link hashes are) is its own bytes; any other text is held as a
/// domain-separated SHA-256 of it, which no hex hash's bytes can equal short of
/// a preimage. Written (the restart snapshot) as hex.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkHash([u8; 32]);

impl LinkHash {
    pub fn of(hash: &str) -> Self {
        if let Some(bytes) = Self::from_canonical_hex(hash) {
            return bytes;
        }
        let mut digest = Sha256::new();
        digest.update(b"streamscope-link-hash\0");
        digest.update(hash.as_bytes());
        Self(digest.finalize().into())
    }

    /// The hash whose text is `hex`: 64 lowercase hex characters, else none.
    fn from_canonical_hex(hex: &str) -> Option<Self> {
        let mut bytes = [0u8; 32];
        let canonical = hex.len() == 64 && hex.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'));
        (canonical && hex::decode_to_slice(hex, &mut bytes).is_ok()).then_some(Self(bytes))
    }
}

impl serde::Serialize for LinkHash {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut text = [0u8; 64];
        hex::encode_to_slice(self.0, &mut text).map_err(serde::ser::Error::custom)?;
        serializer.serialize_str(std::str::from_utf8(&text).map_err(serde::ser::Error::custom)?)
    }
}

/// Read back only as written: 64 lowercase hex characters. Anything else is
/// a damaged snapshot, refused rather than read as another hash.
impl<'de> serde::Deserialize<'de> for LinkHash {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let text = <&'de str>::deserialize(deserializer)?;
        Self::from_canonical_hex(text).ok_or_else(|| serde::de::Error::custom("a link hash is 64 lowercase hex characters"))
    }
}

/// Session detection result.
#[derive(Debug, Clone)]
pub struct SessionInfo {
    pub session_id: Uuid,
    pub parent_request_id: Option<Uuid>,
    pub turn_number: i32,
    pub is_baseline: bool,
}

/// One recorded turn. Immutable once made: it is shared by the user's list,
/// the turns whose parent it is, and a snapshot being written.
struct Turn {
    request_id: Uuid,
    session_id: Uuid,
    turn_number: i32,
    client_session_id: Option<Box<str>>,
    recorded_at: Instant,
    /// The number of hashes in the turn's whole history.
    len: usize,
    /// The hashes `parent.len..len` of the history (all of it without a parent).
    own: Box<[LinkHash]>,
    /// A recorded turn whose whole history begins this one's.
    parent: Option<Arc<Turn>>,
    /// The detector's live weight: this turn's [`Turn::charge`] is added when
    /// it is made and taken off when it drops.
    held: Arc<AtomicUsize>,
}

/// What one turn costs beside its own hashes: the turn, the `Arc` around it
/// and its slot in its user's list.
const TURN_OVERHEAD_BYTES: usize = std::mem::size_of::<Turn>() + 2 * std::mem::size_of::<usize>() + std::mem::size_of::<Arc<Turn>>();

impl Turn {
    #[allow(clippy::too_many_arguments)]
    fn new(
        request_id: Uuid,
        session_id: Uuid,
        turn_number: i32,
        client_session_id: Option<Box<str>>,
        recorded_at: Instant,
        own: Box<[LinkHash]>,
        parent: Option<Arc<Turn>>,
        held: &Arc<AtomicUsize>,
    ) -> Self {
        let turn = Self {
            request_id,
            session_id,
            turn_number,
            client_session_id,
            recorded_at,
            len: parent.as_ref().map_or(0, |p| p.len) + own.len(),
            own,
            parent,
            held: held.clone(),
        };
        held.fetch_add(turn.charge(), Ordering::Relaxed);
        turn
    }

    /// The bytes this turn holds of its own.
    fn charge(&self) -> usize {
        TURN_OVERHEAD_BYTES
            + self.own.len() * std::mem::size_of::<LinkHash>()
            + self.client_session_id.as_ref().map_or(0, |c| c.len())
    }

    /// Whether `hashes` begins with this turn's whole history.
    fn begins(&self, hashes: &[LinkHash]) -> bool {
        if hashes.len() < self.len {
            return false;
        }
        let mut turn = self;
        loop {
            let start = turn.len - turn.own.len();
            if hashes[start..turn.len] != turn.own[..] {
                return false;
            }
            match &turn.parent {
                Some(parent) => turn = parent,
                None => return true,
            }
        }
    }

    /// Whether `pair` stands side by side in this turn's history, reading only
    /// the parts of its chain not in `walked` (a part a turn already read
    /// holds it for that turn first) and adding those it reads.
    fn holds_side_by_side(&self, pair: [LinkHash; 2], walked: &mut std::collections::HashSet<*const Turn>) -> bool {
        let mut turn = self;
        while walked.insert(std::ptr::from_ref(turn)) {
            if turn.own.windows(2).any(|w| w == pair) {
                return true;
            }
            // The pair across this part's start: the last message before it.
            let mut before = turn.parent.as_deref();
            while let Some(p) = before.filter(|p| p.own.is_empty()) {
                before = p.parent.as_deref();
            }
            if let (Some(last), Some(first)) = (before.and_then(|p| p.own.last()), turn.own.first())
                && [*last, *first] == pair
            {
                return true;
            }
            match turn.parent.as_deref() {
                Some(parent) => turn = parent,
                None => break,
            }
        }
        false
    }

    /// A turn the request with `hashes` continues: some history it strictly extends.
    fn continued_by(&self, hashes: &[LinkHash]) -> bool {
        self.len > 0 && hashes.len() > self.len && self.begins(hashes)
    }
}

impl Drop for Turn {
    /// Unlinks the chain in a loop: a long session's chain dropped by
    /// recursion would overflow the stack.
    fn drop(&mut self) {
        self.held.fetch_sub(self.charge(), Ordering::Relaxed);
        let mut next = self.parent.take();
        while let Some(parent) = next {
            next = match Arc::try_unwrap(parent) {
                Ok(mut alone) => alone.parent.take(),
                Err(_) => None,
            };
        }
    }
}

/// What makes a request the same one sent again: its caller, the key it came
/// on, its client session id, its protocol, model and streaming mode (a Gemini
/// request names the last two in its URL), and its body exactly as sent. The
/// session hashes are not enough — they leave out a Responses
/// `previous_response_id`, an Anthropic `system`, tools and sampling
/// parameters — so two different requests could share them. Read by the
/// session detector ([`SessionDetector::detect_serving`]) and the dispatch gate
/// (`GateRequest::resend_key`).
pub fn request_key(
    user_id: Uuid,
    key_id: Uuid,
    client_session_id: Option<&str>,
    protocol: &str,
    model: &str,
    stream: bool,
    body: &[u8],
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(user_id.as_bytes());
    hasher.update(key_id.as_bytes());
    // Length-prefixed, so no two field splits hash alike.
    for field in [client_session_id.unwrap_or("").as_bytes(), protocol.as_bytes(), model.as_bytes()] {
        hasher.update((field.len() as u64).to_le_bytes());
        hasher.update(field);
    }
    hasher.update([u8::from(client_session_id.is_some()), u8::from(stream)]);
    hasher.update(body);
    hasher.finalize().into()
}

/// The session of a thread opened under a client session id: its tenant,
/// user, client session id and opening message ([`RequestContent::thread_root`]).
/// Every replica gives a thread the same id, and two threads under one client
/// session id two ids.
///
/// [`RequestContent::thread_root`]: super::content::RequestContent::thread_root
pub fn thread_session_id(client_id: &str, root: LinkHash, tenant_id: Uuid, user_id: Uuid) -> Uuid {
    let mut hasher = Sha256::new();
    hasher.update(b"thread:");
    hasher.update(tenant_id.as_bytes());
    hasher.update(user_id.as_bytes());
    hasher.update(root.0);
    hasher.update(client_id.as_bytes());
    let hash = hasher.finalize();
    let mut bytes = [0u8; 16];
    bytes.copy_from_slice(&hash[..16]);
    bytes[6] = (bytes[6] & 0x0f) | 0x40; // version 4
    bytes[8] = (bytes[8] & 0x3f) | 0x80; // variant 1
    Uuid::from_bytes(bytes)
}

/// The requests this process is serving now, by [`request_key`], each with the
/// turn its detection gave it and how many copies of it are being served.
type InFlight = dashmap::DashMap<[u8; 32], (SessionInfo, usize)>;

/// A request's place among those being served ([`SessionDetector::detect_serving`]).
/// Dropped when the request is over by any path — answered, refused, failed or
/// abandoned — which is when a copy of it stops being a re-send.
pub struct ServingGuard {
    in_flight: Arc<InFlight>,
    key: [u8; 32],
    released: AtomicBool,
}

impl ServingGuard {
    /// The client has the whole answer: from now on the same request is the
    /// conversation asking again, though the audit of this one may still be
    /// running (it holds the guard until it ends). Idempotent, and the drop
    /// releases whatever was not.
    pub fn release(&self) {
        if self.released.swap(true, Ordering::AcqRel) {
            return;
        }
        if let dashmap::mapref::entry::Entry::Occupied(mut e) = self.in_flight.entry(self.key) {
            e.get_mut().1 -= 1;
            if e.get().1 == 0 {
                e.remove();
            }
        }
    }
}

impl Drop for ServingGuard {
    fn drop(&mut self) {
        self.release();
    }
}

impl std::fmt::Debug for ServingGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ServingGuard").finish_non_exhaustive()
    }
}

/// The newest stamp of a user's turns (concurrent records may push out of
/// stamp order, so not necessarily the last one's).
fn newest(turns: &[Arc<Turn>]) -> Option<Instant> {
    turns.iter().map(|t| t.recorded_at).max()
}

/// What a user's turns hold: each turn of their chains once.
fn list_weight(turns: &[Arc<Turn>]) -> usize {
    let mut seen: std::collections::HashSet<*const Turn> = std::collections::HashSet::new();
    let mut weight = 0;
    for turn in turns {
        let mut at: Option<&Turn> = Some(turn);
        while let Some(t) = at {
            if !seen.insert(t as *const Turn) {
                break;
            }
            weight += t.charge();
            at = t.parent.as_deref();
        }
    }
    weight
}

/// The detector's shard: a user and the key it came on.
type UserKey = (Uuid, Uuid);

/// What one session counter costs: its key and value, and a word for its slot
/// in the map.
const COUNTER_BYTES: usize = std::mem::size_of::<(Uuid, (i32, Instant))>() + std::mem::size_of::<usize>();

/// Clears its flag however a pass ends: a flag left set would turn the pass
/// off for good.
struct Running<'a>(&'a AtomicBool);

impl Drop for Running<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Current time as epoch milliseconds (for atomic dirty-tracking).
fn epoch_millis() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::SystemTime::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

/// In-memory session detector using message prefix matching.
///
/// Sharded by `(user_id, key_id)` via DashMap — concurrent requests for
/// different users or different API keys never contend, and a session of one
/// key is never matched or continued by another.
///
/// The content decides the session; a client's `X-Session-Id` only narrows
/// which recorded turns a request may continue, and names a thread nothing
/// continues ([`Self::detect`]).
///
/// Memory: each user's list holds its recent turns ([`Turn`]), sharing their
/// history through parent links; the weight of every live turn is counted
/// exactly (`held`) and capped (`max_bytes`). Beside them, one small counter
/// per session (`next_turn`, weighed too) numbers its turns in arrival order
/// and outlives the turns until the entry TTL, so a session whose turns were
/// evicted goes on numbering where it was.
///
/// Persistence across restarts is provided by periodic snapshots to disk
/// (managed by the proxy binary). Zero per-request I/O — the DashMap is
/// the only hot-path data structure.
pub struct SessionDetector {
    recent_turns: dashmap::DashMap<(Uuid, Uuid), Vec<Arc<Turn>>>,
    max_entries_per_user: usize,
    /// The weight past which [`Self::shrink_to_low_water`] runs; 0 for none.
    max_bytes: usize,
    /// A [`Self::shrink_to_low_water`] pass is running.
    shrinking: AtomicBool,
    /// The bytes every live turn holds (each [`Turn::charge`]), exact.
    held: Arc<AtomicUsize>,
    entry_ttl: Duration,
    /// Set to true by `record()`, cleared by `export()`.
    dirty: AtomicBool,
    /// Epoch millis of last `record()` call (for idle detection).
    last_record_ms: AtomicU64,
    /// Epoch millis of last successful snapshot export.
    last_snapshot_ms: AtomicU64,
    /// Per session: the number its next turn takes, and when one was last
    /// taken. Weighed in `held` ([`COUNTER_BYTES`] each) and kept within a
    /// tenth of the ceiling ([`Self::forget_counters_past_their_share`]).
    next_turn: dashmap::DashMap<Uuid, (i32, Instant)>,
    /// A [`Self::forget_counters_past_their_share`] pass is running.
    forgetting_counters: AtomicBool,
    /// The requests this process is serving now ([`Self::detect_serving`]): an
    /// identical one arriving meanwhile is a re-send. Never persisted — a
    /// restart ends every request it was serving.
    in_flight: Arc<InFlight>,
}

impl SessionDetector {
    pub fn new(max_entries_per_user: usize, entry_ttl: Duration) -> Self {
        Self::with_capacity(max_entries_per_user, entry_ttl, 0)
    }

    /// Create a session detector capped at `max_bytes` held (0 for no cap):
    /// past it, [`Self::shrink_to_low_water`].
    pub fn with_capacity(max_entries_per_user: usize, entry_ttl: Duration, max_bytes: usize) -> Self {
        let now_ms = epoch_millis();
        Self {
            recent_turns: dashmap::DashMap::new(),
            max_entries_per_user,
            max_bytes,
            shrinking: AtomicBool::new(false),
            held: Arc::default(),
            entry_ttl,
            dirty: AtomicBool::new(false),
            last_record_ms: AtomicU64::new(now_ms),
            last_snapshot_ms: AtomicU64::new(now_ms),
            next_turn: dashmap::DashMap::new(),
            forgetting_counters: AtomicBool::new(false),
            in_flight: Arc::default(),
        }
    }

    /// The bytes the detector's turns hold now.
    pub fn held_bytes(&self) -> usize {
        self.held.load(Ordering::Relaxed)
    }

    /// The turns listed now, across every user.
    pub fn entries(&self) -> usize {
        self.recent_turns.iter().map(|user| user.value().len()).sum()
    }

    /// [`Self::detect`], for a request this process then serves until the
    /// returned guard drops. A request with the same [`request_key`] still
    /// being served is a re-send: its client gave up waiting and sent it again.
    /// It is that turn again — same session, turn number, parent and baseline
    /// — never a new session (a first turn would otherwise open a second one,
    /// which the conversation's next turn joins) nor, under a client session
    /// id, the next turn. Once every copy is over, by any path, the same request
    /// is the conversation asking again.
    ///
    /// Two copies arriving together get one turn between them: each detects
    /// outside the entry's lock (a prefix scan, not to be held under it), and
    /// the first to register wins — a later one takes its info.
    #[allow(clippy::too_many_arguments)]
    pub fn detect_serving(
        &self,
        user_id: Uuid,
        key_id: Uuid,
        tenant_id: Uuid,
        current_hashes: &[LinkHash],
        thread_root: Option<LinkHash>,
        client_session_id: Option<&str>,
        request_key: [u8; 32],
    ) -> (SessionInfo, ServingGuard) {
        let original = self.in_flight.get_mut(&request_key).map(|mut entry| {
            entry.1 += 1;
            entry.0.clone()
        });
        let info = match original {
            Some(info) => info,
            None => {
                let found = self.find(user_id, key_id, tenant_id, current_hashes, thread_root, client_session_id);
                match self.in_flight.entry(request_key) {
                    dashmap::mapref::entry::Entry::Occupied(mut first) => {
                        first.get_mut().1 += 1;
                        first.get().0.clone()
                    }
                    dashmap::mapref::entry::Entry::Vacant(slot) => {
                        // Only the copy that registers takes a number.
                        let detected = self.numbered(found, client_session_id);
                        slot.insert((detected.clone(), 1));
                        detected
                    }
                }
            }
        };
        (info, ServingGuard { in_flight: self.in_flight.clone(), key: request_key, released: Default::default() })
    }

    /// Drop every expired turn, and every session counter not used for the
    /// entry TTL. Call periodically to prevent unbounded growth of the user and
    /// session key sets.
    pub fn prune_expired_users(&self) {
        let now = Instant::now();
        let ttl = self.entry_ttl;
        let live = |t: &Arc<Turn>| now.duration_since(t.recorded_at) < ttl;
        let keys: Vec<UserKey> = self.recent_turns.iter().map(|user| *user.key()).collect();
        for key in keys {
            // A list expired whole is dropped once the map's lock is released.
            drop(self.recent_turns.remove_if(&key, |_, turns| !turns.iter().any(live)));
            if let Some(mut turns) = self.recent_turns.get_mut(&key) {
                turns.retain(live);
            }
        }
        self.retain_counters(|&(_, last)| now.duration_since(last) < ttl);
    }

    /// Keep the session counters `keep` holds to, taking the others' weight
    /// off.
    fn retain_counters(&self, mut keep: impl FnMut(&(i32, Instant)) -> bool) {
        let mut gone = 0;
        self.next_turn.retain(|_session, counter| {
            let kept = keep(counter);
            gone += usize::from(!kept);
            kept
        });
        self.held.fetch_sub(gone * COUNTER_BYTES, Ordering::Relaxed);
    }

    /// Hold the session counters to a tenth of the ceiling: past it, the
    /// least recently used go, down to nine tenths of that share (a session
    /// whose counter went numbers its next turn from its parent's again). One
    /// caller at a time; none without a ceiling.
    fn forget_counters_past_their_share(&self) {
        if self.max_bytes == 0 {
            return;
        }
        let share = (self.max_bytes / 10 / COUNTER_BYTES).max(1);
        if self.next_turn.len() <= share || self.forgetting_counters.swap(true, Ordering::Acquire) {
            return;
        }
        let _running = Running(&self.forgetting_counters);
        let mut stamps: Vec<Instant> = self.next_turn.iter().map(|counter| counter.value().1).collect();
        let keep = share - share / 10;
        if stamps.len() <= keep {
            return;
        }
        let cut = stamps.len() - keep;
        let (_, &mut cutoff, _) = stamps.select_nth_unstable(cut - 1);
        // Exactly `cut` go: every counter used before the cutoff, then as
        // many used at it as are still to go (a restore stamps its counters
        // alike). One used since the walk is newer and stays.
        let mut at_cutoff = cut - stamps.iter().filter(|&&stamp| stamp < cutoff).count();
        self.retain_counters(|&(_, last)| {
            if last < cutoff {
                return false;
            }
            if last == cutoff && at_cutoff > 0 {
                at_cutoff -= 1;
                return false;
            }
            true
        });
    }

    /// Bring the weight back to [`Self::low_water`]: every expired turn goes
    /// ([`Self::prune_expired_users`]), then whole users' lists, the least
    /// recently active first (by their newest turn), a tenth of the users at a
    /// time (by selection, not a sort) until the weight is under it. A user's
    /// turns share their history only with each other, so a list dropped
    /// whole frees its chains; dropping only a list's older turns would free
    /// nothing while its newest turn holds them. `keep` (the user recording)
    /// goes last: its conversation keeps the link to its next turn — unless it
    /// holds more than half the ceiling itself, when it is forgotten first
    /// rather than every other user. One caller at a time: another one past
    /// the cap meanwhile records and goes on.
    ///
    /// Each step reads or writes the map in its own statement, with no guard of
    /// it alive across another call on it: a guard held there waits on its own
    /// lock and parks the worker for good.
    fn shrink_to_low_water(&self, keep: Option<UserKey>) {
        if self.shrinking.swap(true, Ordering::Acquire) {
            return;
        }
        let _running = Running(&self.shrinking);
        self.prune_expired_users();
        let low_water = self.low_water();
        if self.held_bytes() <= low_water {
            return;
        }
        let mut keep = keep;
        if let Some(key) = keep {
            let heavy = self.recent_turns.get(&key).is_some_and(|turns| list_weight(&turns) > self.max_bytes / 2);
            if heavy {
                drop(self.recent_turns.remove(&key));
                keep = None;
                if self.held_bytes() <= low_water {
                    return;
                }
            }
        }
        let mut users: Vec<(Instant, UserKey)> = self
            .recent_turns
            .iter()
            .filter(|user| Some(*user.key()) != keep)
            .filter_map(|user| newest(user.value()).map(|stamp| (stamp, *user.key())))
            .collect();
        let batch = (users.len() / 10).max(1);
        let mut rest = &mut users[..];
        while !rest.is_empty() {
            let count = batch.min(rest.len());
            if count < rest.len() {
                rest.select_nth_unstable_by_key(count - 1, |&(newest, _)| newest);
            }
            let (chosen, tail) = rest.split_at_mut(count);
            for (newest, key) in chosen.iter() {
                // A user who recorded since the pass looked keeps its list. The
                // list is dropped once the map's lock is released.
                drop(self.recent_turns.remove_if(key, |_, turns| self::newest(turns).is_none_or(|stamp| stamp <= *newest)));
            }
            if self.held_bytes() <= low_water {
                break;
            }
            rest = tail;
        }
    }

    /// What a pass past the cap leaves: nine tenths of it.
    fn low_water(&self) -> usize {
        self.max_bytes - self.max_bytes / 10
    }

    /// A snapshot could not be saved: the next cycle tries again.
    pub fn mark_dirty(&self) {
        self.dirty.store(true, Ordering::Relaxed);
    }

    /// Check if a snapshot should be saved now.
    ///
    /// Uses idle-aware scheduling: saves during idle periods (1s after last
    /// write) or forces a save when `max_interval_secs` has elapsed.
    /// Returns `false` if nothing has changed since the last snapshot.
    pub fn should_snapshot(&self, max_interval_secs: u64) -> bool {
        if !self.dirty.load(Ordering::Relaxed) {
            return false;
        }
        let now = epoch_millis();
        let last_record = self.last_record_ms.load(Ordering::Relaxed);
        let last_snapshot = self.last_snapshot_ms.load(Ordering::Relaxed);

        // Save if idle for ≥1 second (quiet window)
        let idle_ms = now.saturating_sub(last_record);
        if idle_ms >= 1000 {
            return true;
        }
        // Force save if max interval exceeded (sustained traffic)
        let since_snapshot = now.saturating_sub(last_snapshot);
        since_snapshot >= max_interval_secs * 1000
    }

    /// Take the number of a session's next turn: at least `at_least`, and
    /// after every number taken before it — arrival order, never one number
    /// for two turns of a session served here.
    fn take_turn_number(&self, session_id: Uuid, at_least: i32) -> i32 {
        let now = Instant::now();
        let mut added = false;
        let number = {
            let mut next = self.next_turn.entry(session_id).or_insert_with(|| {
                added = true;
                (0, now)
            });
            let number = next.0.max(at_least);
            *next = (number.saturating_add(1), now);
            number
        };
        // The entry's guard is released: the pass walks the map.
        if added {
            self.held.fetch_add(COUNTER_BYTES, Ordering::Relaxed);
            self.forget_counters_past_their_share();
        }
        number
    }

    /// The turn a request continues, else a new session: what `detect`
    /// decides, before its turn number is taken.
    fn find(
        &self,
        user_id: Uuid,
        key_id: Uuid,
        tenant_id: Uuid,
        current: &[LinkHash],
        thread_root: Option<LinkHash>,
        client_session_id: Option<&str>,
    ) -> SessionInfo {
        let fresh = |session_id| SessionInfo { session_id, parent_request_id: None, turn_number: 0, is_baseline: true };
        let now = Instant::now();
        // A request with no thread has no content to decide by. With no
        // history at all (a media call) it is a turn of the session its client
        // session id names — the same on every replica, shown beside the
        // conversations like their MCP calls — else a session of its own. A
        // history held elsewhere (a Responses turn chained by
        // `previous_response_id`, which names its predecessor) joins the
        // latest turn under its client session id: the one case the header
        // decides, and only where that turn is held.
        let Some(root) = thread_root else {
            let Some(csid) = client_session_id else {
                return fresh(Uuid::new_v4());
            };
            if current.is_empty() {
                return fresh(session_id_from_client(csid, tenant_id, user_id));
            }
            let latest = self.recent_turns.get(&(user_id, key_id)).and_then(|turns| {
                turns
                    .iter()
                    .rev()
                    .find(|t| now.duration_since(t.recorded_at) < self.entry_ttl && t.client_session_id.as_deref() == Some(csid))
                    .map(|turn| SessionInfo {
                        session_id: turn.session_id,
                        parent_request_id: Some(turn.request_id),
                        turn_number: turn.turn_number + 1,
                        is_baseline: !current.is_empty() && !turn.continued_by(current),
                    })
            });
            return latest.unwrap_or_else(|| fresh(session_id_from_client(csid, tenant_id, user_id)));
        };
        let continued = self.recent_turns.get(&(user_id, key_id)).and_then(|turns| {
            // The longest recorded history this request extends, among the
            // turns of the same client session id (or of none): the header
            // narrows the candidates, the content decides.
            let mut best: Option<&Arc<Turn>> = None;
            for turn in turns.iter().rev() {
                if now.duration_since(turn.recorded_at) < self.entry_ttl
                    && turn.client_session_id.as_deref() == client_session_id
                    && turn.len > best.map_or(0, |b| b.len)
                    && turn.continued_by(current)
                {
                    best = Some(turn);
                }
            }
            best.map(|turn| SessionInfo {
                session_id: turn.session_id,
                parent_request_id: Some(turn.request_id),
                turn_number: turn.turn_number + 1,
                is_baseline: false,
            })
        });
        continued
            .or_else(|| self.window_of(user_id, key_id, current, root, client_session_id, now))
            .unwrap_or_else(|| {
                // A thread nothing continues: under a client session id, the
                // thread's own id (the same opening under the same id is the
                // same session — a rewind, a replay); without one, a new session.
                fresh(client_session_id.map_or_else(Uuid::new_v4, |csid| thread_session_id(csid, root, tenant_id, user_id)))
            })
    }

    /// A history its client cut the oldest messages off (a sliding window, a
    /// hand-truncated history): it continues no turn, but its first two
    /// messages from the thread's opening on stand side by side in a recorded
    /// turn of the same client session id. It is a baseline of the most recent
    /// such turn's session. A conversation's first turn has one message from
    /// its opening on, so two conversations under one constant id never meet
    /// here. Reads the histories the detector holds, each shared part once,
    /// and only for a request that continues nothing under a client session id.
    fn window_of(
        &self,
        user_id: Uuid,
        key_id: Uuid,
        current: &[LinkHash],
        root: LinkHash,
        client_session_id: Option<&str>,
        now: Instant,
    ) -> Option<SessionInfo> {
        client_session_id?;
        let at = current.iter().position(|h| *h == root)?;
        let pair = [*current.get(at)?, *current.get(at + 1)?];
        let turns = self.recent_turns.get(&(user_id, key_id))?;
        let mut walked: std::collections::HashSet<*const Turn> = std::collections::HashSet::new();
        let found = turns.iter().rev().find(|turn| {
            now.duration_since(turn.recorded_at) < self.entry_ttl
                && turn.client_session_id.as_deref() == client_session_id
                && turn.holds_side_by_side(pair, &mut walked)
        })?;
        Some(SessionInfo {
            session_id: found.session_id,
            parent_request_id: None,
            turn_number: found.turn_number + 1,
            is_baseline: true,
        })
    }

    /// Detect whether a request with these message hashes continues an
    /// existing session, and take its turn number.
    ///
    /// The content decides; the client session id (`X-Session-Id`) only
    /// narrows (a re-send of a request still being served comes first:
    /// [`Self::detect_serving`]):
    /// 1. **Continuation** — the request's history extends a recorded turn
    ///    with the same client session id (or both without one); the longest
    ///    such history is the turn it continues, in that turn's session.
    /// 2. **A cut history** — nothing continued, under a client session id: a
    ///    history whose first two messages from its opening on stand side by
    ///    side in a recorded turn of the same id is a baseline of that turn's
    ///    session (a sliding window, a truncation; [`Self::window_of`]).
    /// 3. **A new thread** — nothing continued: under a client session id, the
    ///    session of that id and the thread's opening message
    ///    ([`thread_session_id`]), else a new random session. A constant or
    ///    shared client session id therefore keeps apart two conversations
    ///    that open differently; two opening with the same message under one
    ///    id are one session (a rewind, a replay — and, accepted, two
    ///    subagents given the same prompt).
    /// 4. **No thread** (`thread_root` `None`) — with no history (a media
    ///    request), the session the client session id names
    ///    ([`session_id_from_client`]); with a history held elsewhere (a
    ///    Responses `previous_response_id`), the latest turn under that id,
    ///    else that same session; without a client session id, a new random
    ///    one.
    ///
    /// The turn number is the session's next in arrival order
    /// ([`Self::take_turn_number`]); a new random session's is 0.
    pub fn detect(
        &self,
        user_id: Uuid,
        key_id: Uuid,
        tenant_id: Uuid,
        current_hashes: &[LinkHash],
        thread_root: Option<LinkHash>,
        client_session_id: Option<&str>,
    ) -> SessionInfo {
        self.numbered(self.find(user_id, key_id, tenant_id, current_hashes, thread_root, client_session_id), client_session_id)
    }

    /// `info` with its turn number taken ([`Self::detect`]).
    fn numbered(&self, mut info: SessionInfo, client_session_id: Option<&str>) -> SessionInfo {
        // A new random session is turn 0 and needs no counter: no other request
        // can name it before this one is recorded (a request that never is,
        // such as a media call without a session id, leaves nothing behind).
        if info.parent_request_id.is_some() || client_session_id.is_some() {
            info.turn_number = self.take_turn_number(info.session_id, info.turn_number);
        }
        info
    }

    /// Record a turn for future session detection.
    pub fn record(
        &self,
        user_id: Uuid,
        key_id: Uuid,
        request_id: Uuid,
        info: &SessionInfo,
        message_hashes: &[LinkHash],
        client_session_id: Option<&str>,
    ) {
        // A turn with no history is no request's prefix: nothing could
        // continue it.
        if message_hashes.is_empty() {
            return;
        }

        let now = Instant::now();
        let ttl = self.entry_ttl;
        let key = (user_id, key_id);

        self.dirty.store(true, Ordering::Relaxed);
        self.last_record_ms.store(epoch_millis(), Ordering::Relaxed);

        // The parent shares its history with this turn: the longest recorded
        // history this one begins with (the turn it continues when there is
        // one), found under a read guard released at the end of the statement.
        let parent = self.recent_turns.get(&key).and_then(|turns| {
            let mut best: Option<&Arc<Turn>> = None;
            for turn in turns.iter().rev().filter(|t| now.duration_since(t.recorded_at) < ttl) {
                // Strictly shorter: a turn repeating another's history whole
                // shares that turn's parent, never chains onto the repeat (an
                // identical request sent again and again would grow one chain
                // no eviction frees).
                if turn.len > best.map_or(0, |b| b.len) && turn.len < message_hashes.len() && turn.begins(message_hashes) {
                    best = Some(turn);
                }
            }
            best.cloned()
        });
        let own = message_hashes[parent.as_ref().map_or(0, |p| p.len)..].into();
        let turn = Arc::new(Turn::new(
            request_id,
            info.session_id,
            info.turn_number,
            client_session_id.map(Into::into),
            now,
            own,
            parent,
            &self.held,
        ));

        let mut turns = self.recent_turns.entry(key).or_default();
        turns.retain(|t| now.duration_since(t.recorded_at) < ttl);
        turns.push(turn);
        // Evict the oldest turns past the per-user limit.
        if turns.len() > self.max_entries_per_user {
            let excess = turns.len() - self.max_entries_per_user;
            turns.drain(..excess);
        }
        drop(turns);

        // Past the cap, one pass takes the weight back to its low-water mark,
        // the least recently active users first.
        if self.max_bytes > 0 && self.held_bytes() > self.max_bytes {
            self.shrink_to_low_water(Some(key));
        }
    }

    /// The listed turns as they are now, for [`SessionExport::write_to`] off
    /// the request path: a weak reference to each, one shard at a time — the
    /// export keeps no turn alive, so the ceiling and its passes go on while it
    /// is written, and a turn dropped meanwhile is not written. Clears the
    /// dirty flag and records the snapshot time.
    pub fn export(&self) -> SessionExport {
        let users = self
            .recent_turns
            .iter()
            .map(|user| (*user.key(), newest(user.value()), user.value().iter().map(Arc::downgrade).collect()))
            .collect();
        // Cleared AFTER collecting — a record during the walk sets it again,
        // and the next cycle saves it.
        self.dirty.store(false, Ordering::Relaxed);
        self.last_snapshot_ms.store(epoch_millis(), Ordering::Relaxed);
        SessionExport { users }
    }

    /// Restore the turns a snapshot wrote ([`SessionExport::write_to`]), at
    /// startup, each stamped as long ago as it was recorded before the write
    /// (its TTL and the users' recency go on). Users are read most recent
    /// first; reading stops once the ceiling is reached, and each user keeps at
    /// most its per-user count of turns, so a ceiling lowered since the write
    /// never restores more than it allows. Every live session's counter is
    /// read, its user's turns built or not, and kept within the counters'
    /// share. A line that does not read, or names
    /// a turn not written before it, fails the whole restore and leaves the
    /// detector as it was.
    pub fn import_from(&self, reader: impl std::io::BufRead) -> Result<RestoreCounts, SnapshotError> {
        let restored_at = Instant::now();
        let now_ms = epoch_millis();
        let ttl_ms = u64::try_from(self.entry_ttl.as_millis()).unwrap_or(u64::MAX);
        // Each turn line read, by index, with whether it is past the TTL; a
        // user's entries are let go once its list is read (a chain is its
        // user's alone), so what the ceiling reads is what is kept.
        let mut turns: Vec<Option<(Arc<Turn>, bool)>> = Vec::new();
        let mut user_start = 0;
        let mut users: Vec<(UserKey, Vec<Arc<Turn>>)> = Vec::new();
        let mut next_turns: std::collections::HashMap<Uuid, i32> = std::collections::HashMap::new();
        let mut full = false;
        for (number, line) in reader.lines().enumerate() {
            let line = line?;
            if line.trim().is_empty() {
                continue;
            }
            let bad = |what: &'static str| SnapshotError::Malformed { line: number + 1, what };
            match serde_json::from_str::<SnapshotLine>(&line).map_err(|_| bad("not a snapshot line"))? {
                SnapshotLine::Turn(t) => {
                    let expired = now_ms.saturating_sub(t.recorded_ms) >= ttl_ms;
                    // Every live session's counter, whether its turns fit or not.
                    if !expired {
                        let next = next_turns.entry(t.session_id).or_insert(0);
                        *next = (*next).max(t.turn_number.saturating_add(1));
                    }
                    if full {
                        turns.push(None);
                        continue;
                    }
                    let parent = match t.parent {
                        Some(i) => Some(turns.get(i).cloned().flatten().ok_or_else(|| bad("a parent not written before it"))?.0),
                        None => None,
                    };
                    let age = Duration::from_millis(now_ms.saturating_sub(t.recorded_ms));
                    let recorded_at = restored_at.checked_sub(age).unwrap_or(restored_at);
                    turns.push(Some((
                        Arc::new(Turn::new(
                            t.request_id,
                            t.session_id,
                            t.turn_number,
                            t.client_session_id,
                            recorded_at,
                            t.own.into(),
                            parent,
                            &self.held,
                        )),
                        expired,
                    )));
                }
                SnapshotLine::User(u) => {
                    if full {
                        continue;
                    }
                    let listed = u
                        .turns
                        .iter()
                        .map(|&i| turns.get(i).cloned().flatten().ok_or_else(|| bad("a turn not written before it")))
                        .collect::<Result<Vec<_>, _>>()?;
                    let live: Vec<Arc<Turn>> = listed.into_iter().filter(|(_, expired)| !expired).map(|(t, _)| t).collect();
                    let first = live.len().saturating_sub(self.max_entries_per_user);
                    if first < live.len() {
                        users.push(((u.user_id, u.key_id), live[first..].to_vec()));
                    }
                    drop(live);
                    for entry in &mut turns[user_start..] {
                        *entry = None;
                    }
                    user_start = turns.len();
                    full = self.max_bytes > 0 && self.held_bytes() > self.max_bytes;
                }
            }
        }
        drop(turns);
        let now = Instant::now();
        for (session, next) in next_turns {
            let mut added = false;
            let mut counter = self.next_turn.entry(session).or_insert_with(|| {
                added = true;
                (0, now)
            });
            counter.0 = counter.0.max(next);
            drop(counter);
            if added {
                self.held.fetch_add(COUNTER_BYTES, Ordering::Relaxed);
            }
        }
        self.forget_counters_past_their_share();
        for (key, listed) in users {
            self.recent_turns.insert(key, listed);
        }
        self.prune_expired_users();
        if self.max_bytes > 0 && self.held_bytes() > self.max_bytes {
            self.shrink_to_low_water(None);
        }
        Ok(RestoreCounts { users: self.recent_turns.len(), turns: self.entries() })
    }
}

/// The detector's listed turns at one moment ([`SessionDetector::export`]).
pub struct SessionExport {
    users: Vec<(UserKey, Option<Instant>, Vec<std::sync::Weak<Turn>>)>,
}

/// What a snapshot held: the users and the turns listed for them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RestoreCounts {
    pub users: usize,
    pub turns: usize,
}

#[derive(Debug, thiserror::Error)]
pub enum SnapshotError {
    #[error("session snapshot I/O: {0}")]
    Io(#[from] std::io::Error),
    #[error("session snapshot line {line}: {what}")]
    Malformed { line: usize, what: &'static str },
}

/// One line of the snapshot: a turn (before any turn naming it as parent and
/// any user listing it), or a user's list of turns, each by its line's index
/// among the turns.
#[derive(serde::Deserialize)]
#[serde(rename_all = "snake_case")]
enum SnapshotLine {
    Turn(SnapshotTurn),
    User(SnapshotUser),
}

/// [`SnapshotLine`] as written: borrowed from the turns, nothing copied.
#[derive(serde::Serialize)]
#[serde(rename_all = "snake_case")]
enum SnapshotLineRef<'a> {
    Turn(SnapshotTurnRef<'a>),
    User(&'a SnapshotUser),
}

#[derive(serde::Serialize)]
struct SnapshotTurnRef<'a> {
    request_id: Uuid,
    session_id: Uuid,
    turn_number: i32,
    client_session_id: Option<&'a str>,
    parent: Option<usize>,
    recorded_ms: u64,
    own: &'a [LinkHash],
}

#[derive(serde::Deserialize)]
struct SnapshotTurn {
    request_id: Uuid,
    session_id: Uuid,
    turn_number: i32,
    client_session_id: Option<Box<str>>,
    parent: Option<usize>,
    /// When the turn was recorded, in epoch milliseconds: a restore counts
    /// the time the gateway was down into its age.
    recorded_ms: u64,
    own: Vec<LinkHash>,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SnapshotUser {
    user_id: Uuid,
    key_id: Uuid,
    turns: Vec<usize>,
}

impl SessionExport {
    /// Write the snapshot, one line at a time, the most recently active users
    /// first (a restore that stops at the ceiling keeps them): each user's
    /// turns still alive, each once and after its parent (a turn's chain is
    /// its user's alone) with its age, then the user's list. Only the user
    /// being written is held alive. Blocking I/O — run it off the runtime's
    /// workers.
    pub fn write_to(&mut self, mut out: impl std::io::Write) -> Result<RestoreCounts, SnapshotError> {
        self.users.sort_unstable_by_key(|(_, newest, _)| std::cmp::Reverse(*newest));
        let mut index = 0usize;
        let now_ms = epoch_millis();
        let mut line = Vec::new();
        let mut emit = |out: &mut dyn std::io::Write, value: &SnapshotLineRef<'_>| -> Result<(), SnapshotError> {
            line.clear();
            serde_json::to_writer(&mut line, value).map_err(std::io::Error::from)?;
            line.push(b'\n');
            out.write_all(&line)?;
            Ok(())
        };
        let mut counts = RestoreCounts { users: 0, turns: 0 };
        for ((user_id, key_id), _, listed) in &self.users {
            let listed: Vec<Arc<Turn>> = listed.iter().filter_map(std::sync::Weak::upgrade).collect();
            if listed.is_empty() {
                continue;
            }
            // The line index of each turn of this user written; the pointers
            // stay valid while `listed` holds the chains.
            let mut written: std::collections::HashMap<*const Turn, usize> = std::collections::HashMap::new();
            for turn in &listed {
                // The chain not written yet, oldest first.
                let mut pending: Vec<&Turn> = Vec::new();
                let mut at: Option<&Turn> = Some(turn);
                while let Some(t) = at {
                    if written.contains_key(&(t as *const Turn)) {
                        break;
                    }
                    pending.push(t);
                    at = t.parent.as_deref();
                }
                for t in pending.into_iter().rev() {
                    let parent = t.parent.as_deref().map(|p| written[&(p as *const Turn)]);
                    emit(
                        &mut out,
                        &SnapshotLineRef::Turn(SnapshotTurnRef {
                            request_id: t.request_id,
                            session_id: t.session_id,
                            turn_number: t.turn_number,
                            client_session_id: t.client_session_id.as_deref(),
                            parent,
                            recorded_ms: now_ms.saturating_sub(u64::try_from(t.recorded_at.elapsed().as_millis()).unwrap_or(u64::MAX)),
                            own: &t.own,
                        }),
                    )?;
                    written.insert(t as *const Turn, index);
                    index += 1;
                }
            }
            let turns = listed.iter().map(|t| written[&Arc::as_ptr(t)]).collect::<Vec<_>>();
            counts.users += 1;
            counts.turns += turns.len();
            emit(&mut out, &SnapshotLineRef::User(&SnapshotUser { user_id: *user_id, key_id: *key_id, turns }))?;
        }
        out.flush()?;
        Ok(counts)
    }
}

#[cfg(test)]
#[path = "session_detector_tests.rs"]
mod tests;
