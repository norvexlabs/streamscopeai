use super::*;
use std::time::Duration;

const HOUR: Duration = Duration::from_secs(1800);

fn h(names: &[&str]) -> Vec<LinkHash> {
    names.iter().map(|n| LinkHash::of(n)).collect()
}

/// The thread a history named by `names` opens: its first message.
fn root(names: &[&str]) -> Option<LinkHash> {
    names.first().map(|n| LinkHash::of(n))
}

fn baseline() -> SessionInfo {
    SessionInfo { session_id: Uuid::new_v4(), parent_request_id: None, turn_number: 0, is_baseline: true }
}

/// The hashes a listed turn holds, rebuilt from its chain.
fn history(turn: &Turn) -> Vec<LinkHash> {
    let mut parts = Vec::new();
    let mut at = Some(turn);
    while let Some(t) = at {
        parts.push(&t.own[..]);
        at = t.parent.as_deref();
    }
    parts.into_iter().rev().flatten().copied().collect()
}

fn listed(d: &SessionDetector, user: Uuid, key: Uuid) -> Vec<Vec<LinkHash>> {
    d.recent_turns.get(&(user, key)).map(|t| t.iter().map(|t| history(t)).collect()).unwrap_or_default()
}

/// Runs `f` on its own thread and fails if it has not returned within 10 s:
/// a self-deadlock parks that thread for good instead of failing.
fn returns_in_time<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> T {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let _ = tx.send(f());
    });
    match rx.recv_timeout(Duration::from_secs(10)) {
        Ok(v) => v,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => panic!("the call did not return: it waits on a lock it holds"),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => panic!("the call panicked (its own message is above)"),
    }
}

/// The weight of one turn holding `own` hashes and no client session id.
fn weight(own: usize) -> usize {
    TURN_OVERHEAD_BYTES + own * 32
}

#[test]
fn session_detector_new_session_for_first_turn() {
    let detector = SessionDetector::new(20, HOUR);
    let info = detector.detect(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), &h(&["hash1"]), root(&["hash1"]), None);
    assert!(info.is_baseline);
    assert_eq!(info.turn_number, 0);
    assert!(info.parent_request_id.is_none());
}

#[test]
fn session_detector_continues_session_on_prefix_match() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id, req1) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info1 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), None);
    detector.record(user_id, key_id, req1, &info1, &h(&["hash1"]), None);
    let info2 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2", "hash3"]), root(&["hash1", "hash2", "hash3"]), None);
    assert_eq!(info2.session_id, info1.session_id);
    assert_eq!(info2.parent_request_id, Some(req1));
    assert_eq!(info2.turn_number, 1);
    assert!(!info2.is_baseline);
}

#[test]
fn session_detector_new_session_when_no_prefix_match() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info1 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), None);
    detector.record(user_id, key_id, Uuid::new_v4(), &info1, &h(&["hash1"]), None);
    let info2 = detector.detect(user_id, key_id, tenant_id, &h(&["hash_x"]), root(&["hash_x"]), None);
    assert_ne!(info2.session_id, info1.session_id);
    assert!(info2.parent_request_id.is_none());
    assert_eq!(info2.turn_number, 0);
    assert!(info2.is_baseline);
}

#[test]
fn session_detector_evicts_old_entries() {
    let detector = SessionDetector::new(2, HOUR);
    let (user_id, key_id) = (Uuid::new_v4(), Uuid::new_v4());
    for i in 0..3 {
        detector.record(user_id, key_id, Uuid::new_v4(), &baseline(), &h(&[&format!("hash_{i}")]), None);
    }
    assert_eq!(detector.recent_turns.get(&(user_id, key_id)).unwrap().len(), 2);
}

#[test]
fn a_client_session_id_and_an_opening_name_one_thread() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info1 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), Some("my-session-abc"));
    let info2 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), Some("my-session-abc"));
    assert_eq!(info1.session_id, info2.session_id);
    assert_eq!(info1.session_id, thread_session_id("my-session-abc", LinkHash::of("hash1"), tenant_id, user_id));
    // Another client session id, or another opening: another session.
    let info3 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), Some("other-session"));
    assert_ne!(info1.session_id, info3.session_id);
    let info4 = detector.detect(user_id, key_id, tenant_id, &h(&["hash2"]), root(&["hash2"]), Some("my-session-abc"));
    assert_ne!(info1.session_id, info4.session_id);
    // Every replica gives a thread the same id.
    let other_replica = SessionDetector::new(20, HOUR);
    assert_eq!(other_replica.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), Some("my-session-abc")).session_id, info1.session_id);
}

#[test]
fn a_constant_client_session_id_never_merges_two_conversations() {
    // A client sending one id for everything it does: each conversation is a
    // session of its own, each continued by its own turns.
    let detector = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let mut sessions = Vec::new();
    for conversation in ["a", "b"] {
        let first = h(&[conversation]);
        let info = detector.detect(user, key, Uuid::nil(), &first, root(&[conversation]), Some("constant"));
        detector.record(user, key, Uuid::new_v4(), &info, &first, Some("constant"));
        sessions.push(info.session_id);
    }
    assert_ne!(sessions[0], sessions[1]);
    for (i, conversation) in ["a", "b"].into_iter().enumerate() {
        let next = detector.detect(user, key, Uuid::nil(), &h(&[conversation, "reply"]), root(&[conversation]), Some("constant"));
        assert_eq!((next.session_id, next.turn_number, next.is_baseline), (sessions[i], 1, false));
    }
}

#[test]
fn under_one_client_session_id_a_new_opening_is_a_session_of_its_own_and_a_rewind_is_not() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let csid = "conv-42";
    let (req1, req2) = (Uuid::new_v4(), Uuid::new_v4());
    let info1 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2"]), root(&["hash1", "hash2"]), Some(csid));
    assert!(info1.is_baseline);
    assert_eq!(info1.turn_number, 0);
    detector.record(user_id, key_id, req1, &info1, &h(&["hash1", "hash2"]), Some(csid));
    let info2 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2", "hash3"]), root(&["hash1", "hash2", "hash3"]), Some(csid));
    assert_eq!(info2.session_id, info1.session_id);
    assert_eq!(info2.parent_request_id, Some(req1));
    assert_eq!(info2.turn_number, 1);
    assert!(!info2.is_baseline);
    detector.record(user_id, key_id, req2, &info2, &h(&["hash1", "hash2", "hash3"]), Some(csid));
    // The client compacts: another opening under the same id — a session of
    // its own, nothing in its content naming the one it follows.
    let info3 = detector.detect(user_id, key_id, tenant_id, &h(&["summary_hash", "new_user_hash"]), root(&["summary_hash", "new_user_hash"]), Some(csid));
    assert_ne!(info3.session_id, info1.session_id);
    assert_eq!((info3.parent_request_id, info3.turn_number, info3.is_baseline), (None, 0, true));
    // The client rewinds: the same opening, an edited turn — the same
    // session, a baseline numbered after its turns.
    let info4 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "edited"]), root(&["hash1", "edited"]), Some(csid));
    assert_eq!((info4.session_id, info4.parent_request_id, info4.turn_number, info4.is_baseline), (info1.session_id, None, 2, true));
}

#[test]
fn a_request_continues_only_turns_of_its_own_client_session_id() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info1 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), Some("sess-1"));
    detector.record(user_id, key_id, Uuid::new_v4(), &info1, &h(&["hash1"]), Some("sess-1"));
    let next = h(&["hash1", "hash2"]);
    for other in [None, Some("sess-2")] {
        let info = detector.detect(user_id, key_id, tenant_id, &next, root(&["hash1"]), other);
        assert_ne!(info.session_id, info1.session_id);
        assert!(info.is_baseline && info.parent_request_id.is_none());
    }
    // The control: the same id continues it.
    let info2 = detector.detect(user_id, key_id, tenant_id, &next, root(&["hash1"]), Some("sess-1"));
    assert_eq!((info2.session_id, info2.turn_number, info2.is_baseline), (info1.session_id, 1, false));
}

#[test]
fn the_longest_history_a_request_extends_is_the_turn_it_continues() {
    // A fork continues the turn it was forked from; the conversation's next
    // turn continues its own latest, not the fork point.
    let detector = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let mut requests = Vec::new();
    for names in [&["u1"][..], &["u1", "a1", "u2"], &["u1", "a1", "u2", "a2", "u3"]] {
        let hashes = h(names);
        let info = detector.detect(user, key, Uuid::nil(), &hashes, root(names), Some("cs"));
        let request = Uuid::new_v4();
        detector.record(user, key, request, &info, &hashes, Some("cs"));
        requests.push((request, info.session_id));
    }
    let fork = detector.detect(user, key, Uuid::nil(), &h(&["u1", "a1", "u2", "fork"]), root(&["u1"]), Some("cs"));
    assert_eq!((fork.parent_request_id, fork.session_id), (Some(requests[1].0), requests[1].1));
    let next = detector.detect(user, key, Uuid::nil(), &h(&["u1", "a1", "u2", "a2", "u3", "a3", "u4"]), root(&["u1"]), Some("cs"));
    assert_eq!(next.parent_request_id, Some(requests[2].0));
}

#[test]
fn a_request_with_no_thread_joins_the_latest_turn_under_its_client_session_id() {
    // A history held elsewhere (a Responses `previous_response_id`) or the
    // gateway's MCP sampling loopback: the conversation its client session id
    // is having — its latest turn — else the session that id names.
    let detector = SessionDetector::new(20, HOUR);
    let (user, key, tenant) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let alone = detector.detect(user, key, tenant, &h(&["a", "b"]), None, Some("cs"));
    assert_eq!((alone.session_id, alone.parent_request_id, alone.is_baseline), (session_id_from_client("cs", tenant, user), None, true));
    let first = detector.detect(user, key, tenant, &h(&["a"]), root(&["a"]), Some("cs"));
    let first_request = Uuid::new_v4();
    detector.record(user, key, first_request, &first, &h(&["a"]), Some("cs"));
    assert_ne!(first.session_id, alone.session_id);
    let info = detector.detect(user, key, tenant, &h(&["a", "b"]), None, Some("cs"));
    assert_eq!((info.session_id, info.parent_request_id, info.is_baseline), (first.session_id, Some(first_request), false));
    // A history the latest turn does not begin is a baseline of it.
    let other = detector.detect(user, key, tenant, &h(&["z"]), None, Some("cs"));
    assert_eq!((other.session_id, other.is_baseline), (first.session_id, true));
    // Another client session id, or none, finds nothing.
    assert_ne!(detector.detect(user, key, tenant, &h(&["a", "b"]), None, Some("cs-2")).session_id, first.session_id);
    let none = detector.detect(user, key, tenant, &h(&["a", "b"]), None, None);
    assert!(none.parent_request_id.is_none() && none.session_id != first.session_id);
}

#[test]
fn session_detector_ttl_expires_entries() {
    let detector = SessionDetector::new(20, Duration::from_millis(50));
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info1 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), None);
    detector.record(user_id, key_id, Uuid::new_v4(), &info1, &h(&["hash1"]), None);
    let info2 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2"]), root(&["hash1", "hash2"]), None);
    assert_eq!(info2.session_id, info1.session_id, "should match before TTL");
    std::thread::sleep(Duration::from_millis(60));
    let info3 = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2", "hash3"]), root(&["hash1", "hash2", "hash3"]), None);
    assert_ne!(info3.session_id, info1.session_id, "should not match after TTL");
}

#[test]
fn session_detector_ttl_pruned_on_record() {
    let detector = SessionDetector::new(20, Duration::from_millis(50));
    let (user_id, key_id) = (Uuid::new_v4(), Uuid::new_v4());
    for i in 0..3 {
        detector.record(user_id, key_id, Uuid::new_v4(), &baseline(), &h(&[&format!("h{i}")]), None);
    }
    assert_eq!(detector.recent_turns.get(&(user_id, key_id)).unwrap().len(), 3);
    std::thread::sleep(Duration::from_millis(60));
    detector.record(user_id, key_id, Uuid::new_v4(), &baseline(), &h(&["fresh"]), None);
    assert_eq!(detector.recent_turns.get(&(user_id, key_id)).unwrap().len(), 1, "expired entries pruned");
    // What the expired turns held went with them.
    assert_eq!(detector.held_bytes(), weight(1));
}

#[test]
fn session_detector_empty_hashes_no_false_prefix_match() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let empty_info = baseline();
    // Empty hashes and no client session id: nothing is recorded.
    detector.record(user_id, key_id, Uuid::new_v4(), &empty_info, &[], None);
    let info = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2"]), root(&["hash1", "hash2"]), None);
    assert_ne!(info.session_id, empty_info.session_id, "must not match empty-hash entry");
    assert!(info.is_baseline);
    assert_eq!(info.turn_number, 0);
}

#[test]
fn a_media_request_is_a_turn_of_the_session_its_client_session_id_names() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let csid = "media-session-1";
    // A media request under a client session id: no history.
    let media = detector.detect(user_id, key_id, tenant_id, &[], None, Some(csid));
    assert_eq!(media.session_id, session_id_from_client(csid, tenant_id, user_id));
    detector.record(user_id, key_id, Uuid::new_v4(), &media, &[], Some(csid));
    assert!(detector.recent_turns.is_empty(), "no request continues an empty history");
    // A second media request is that session's next turn.
    let again = detector.detect(user_id, key_id, tenant_id, &[], None, Some(csid));
    assert_eq!((again.session_id, again.turn_number, again.is_baseline), (media.session_id, 1, true));
    // A chat under the same id is a thread of its own.
    let info = detector.detect(user_id, key_id, tenant_id, &h(&["hash1", "hash2"]), root(&["hash1", "hash2"]), Some(csid));
    assert_ne!(info.session_id, media.session_id);
    // A media request made during that chat is still the id's session: no
    // content says which thread it belongs to.
    detector.record(user_id, key_id, Uuid::new_v4(), &info, &h(&["hash1", "hash2"]), Some(csid));
    let during = detector.detect(user_id, key_id, tenant_id, &[], None, Some(csid));
    assert_eq!(during.session_id, media.session_id);
}

#[test]
fn an_empty_history_is_never_recorded() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_id) = (Uuid::new_v4(), Uuid::new_v4());
    for csid in [None, Some("cs")] {
        detector.record(user_id, key_id, Uuid::new_v4(), &baseline(), &[], csid);
    }
    assert!(detector.recent_turns.get(&(user_id, key_id)).is_none());
    assert_eq!(detector.held_bytes(), 0);
}

#[test]
fn session_detector_different_users_independent() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_a, user_b, key_id, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info_a = detector.detect(user_a, key_id, tenant_id, &h(&["hash1"]), root(&["hash1"]), None);
    detector.record(user_a, key_id, Uuid::new_v4(), &info_a, &h(&["hash1"]), None);
    let info_b = detector.detect(user_b, key_id, tenant_id, &h(&["hash1", "hash2"]), root(&["hash1", "hash2"]), None);
    assert_ne!(info_b.session_id, info_a.session_id);
    assert!(info_b.is_baseline);
}

#[test]
fn session_detector_different_keys_independent() {
    let detector = SessionDetector::new(20, HOUR);
    let (user_id, key_a, key_b, tenant_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let info_a = detector.detect(user_id, key_a, tenant_id, &h(&["hash1"]), root(&["hash1"]), None);
    detector.record(user_id, key_a, Uuid::new_v4(), &info_a, &h(&["hash1"]), None);
    let info_b = detector.detect(user_id, key_b, tenant_id, &h(&["hash1", "hash2"]), root(&["hash1", "hash2"]), None);
    assert_ne!(info_b.session_id, info_a.session_id);
    assert!(info_b.is_baseline);
}

// --- What the detector holds ----------------------------------------------

#[test]
fn a_session_holds_each_hash_once() {
    // Fifty turns of one conversation, three messages a turn: the turns share
    // one chain, so it holds 150 hashes, not the 3 825 a copy per turn holds.
    let detector = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let mut history: Vec<String> = Vec::new();
    for turn in 0..50 {
        history.extend((0..3).map(|m| format!("{turn}-{m}")));
        let hashes = h(&history.iter().map(String::as_str).collect::<Vec<_>>());
        let info = detector.detect(user, key, Uuid::nil(), &hashes, hashes.first().copied(), None);
        assert_eq!(info.turn_number, turn);
        detector.record(user, key, Uuid::new_v4(), &info, &hashes, None);
    }
    // Beside them, the session's one counter.
    assert_eq!(detector.held_bytes(), 50 * weight(3) + COUNTER_BYTES);
    // Every listed turn still reads back its whole history.
    let turns = listed(&detector, user, key);
    assert_eq!(turns.len(), 50);
    assert_eq!(turns[49].len(), 150);
    assert_eq!(turns[10].len(), 33);
}

#[test]
fn a_turn_shares_the_longest_history_it_begins_with_even_when_it_continues_nothing() {
    // A turn continuing another client session id's history continues
    // nothing; the memory link is still the longest recorded prefix.
    let detector = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let conv = h(&["s", "u1", "a1", "u2"]);
    let first = detector.detect(user, key, Uuid::nil(), &conv[..2], root(&["s"]), Some("cs"));
    detector.record(user, key, Uuid::new_v4(), &first, &conv[..2], Some("cs"));
    let next = detector.detect(user, key, Uuid::nil(), &conv, root(&["s"]), Some("other"));
    assert!(next.is_baseline, "another client session id");
    detector.record(user, key, Uuid::new_v4(), &next, &conv, Some("other"));
    assert_eq!(detector.held_bytes(), weight(2) + weight(2) + "cs".len() + "other".len() + 2 * COUNTER_BYTES);
    assert_eq!(listed(&detector, user, key)[1], conv);
}

#[test]
fn every_turn_dropped_leaves_nothing_held() {
    let detector = SessionDetector::new(50, HOUR);
    let user = Uuid::new_v4();
    for key in [Uuid::new_v4(), Uuid::new_v4()] {
        let mut history = Vec::new();
        for turn in 0..20 {
            history.push(format!("{turn}"));
            let hashes = h(&history.iter().map(String::as_str).collect::<Vec<_>>());
            let info = detector.detect(user, key, Uuid::nil(), &hashes, hashes.first().copied(), Some("cs"));
            detector.record(user, key, Uuid::new_v4(), &info, &hashes, Some("cs"));
        }
    }
    assert!(detector.held_bytes() > 0);
    let mut export = detector.export();
    detector.recent_turns.clear();
    assert_eq!(detector.held_bytes(), detector.next_turn.len() * COUNTER_BYTES, "a snapshot being written keeps no turn alive");
    let mut out = Vec::new();
    assert_eq!(export.write_to(&mut out).unwrap(), RestoreCounts { users: 0, turns: 0 });
}

#[test]
fn a_deep_chain_drops_without_recursion() {
    let detector = SessionDetector::new(1, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let mut hashes = Vec::new();
    let mut parent = None;
    for i in 0..200_000u32 {
        hashes.push(LinkHash::of(&i.to_string()));
        parent = Some(Arc::new(Turn::new(Uuid::new_v4(), Uuid::nil(), 0, None, Instant::now(), Box::new([hashes[i as usize]]), parent, &detector.held)));
    }
    detector.recent_turns.insert((user, key), vec![parent.take().unwrap()]);
    assert!(detector.held_bytes() >= 200_000 * weight(1));
    returns_in_time({
        let d = std::sync::Arc::new(detector);
        move || {
            d.recent_turns.clear();
            assert_eq!(d.held_bytes(), 0);
        }
    });
}

proptest::proptest! {
    /// Matching through the shared chain is matching the whole history:
    /// over random conversation trees (branches, rewinds, re-sends), the
    /// detector chained finds exactly the turn a flat list of copies finds —
    /// with turns evicted from the list while a later one still holds them as
    /// its parent (each keeps 5).
    #[test]
    fn chained_matching_is_flat_matching(steps in proptest::collection::vec((0usize..8, 0usize..4, 0u8..6, 0usize..3), 1..60)) {
        const KEPT: usize = 5;
        const IDS: [Option<&str>; 3] = [None, Some("a"), Some("b")];
        let detector = SessionDetector::new(KEPT, HOUR);
        let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
        let mut flat: Vec<(Uuid, Vec<LinkHash>, Option<&str>)> = Vec::new();
        for (from, add, vocabulary, id) in steps {
            let csid = IDS[id];
            // Extend (a prefix of) an earlier history, or start one.
            let mut hashes = flat.len().checked_sub(1 + from).map(|i| flat[i].1.clone()).unwrap_or_default();
            hashes.truncate(hashes.len().saturating_sub(usize::from(vocabulary == 0)));
            hashes.extend((0..add).map(|i| LinkHash::of(&format!("{}", (i as u8 + vocabulary) % 6))));
            // The longest history this one extends under the same client
            // session id, the newest of equals; with no history, none.
            let expected = if hashes.is_empty() {
                None
            } else {
                flat.iter()
                    .filter(|(_, held, held_csid)| *held_csid == csid && !held.is_empty() && hashes.len() > held.len() && hashes[..held.len()] == held[..])
                    .max_by_key(|(_, held, _)| held.len())
                    .map(|(request, _, _)| *request)
            };
            let info = detector.detect(user, key, Uuid::nil(), &hashes, hashes.first().copied(), csid);
            proptest::prop_assert_eq!(info.parent_request_id, expected);
            if hashes.is_empty() {
                continue;
            }
            let request = Uuid::new_v4();
            detector.record(user, key, request, &info, &hashes, csid);
            flat.push((request, hashes, csid));
            if flat.len() > KEPT {
                flat.remove(0);
            }
        }
        let held: Vec<Vec<LinkHash>> = flat.into_iter().map(|(_, hashes, _)| hashes).collect();
        proptest::prop_assert_eq!(listed(&detector, user, key), held);
    }
}

// --- The cap ----------------------------------------------------------------

#[test]
fn at_the_cap_nothing_goes_and_one_turn_past_it_a_pass_runs() {
    // Ten single-hash turns of ten users: exactly at the cap, all stay.
    let cap = 10 * weight(1);
    let detector = SessionDetector::with_capacity(50, HOUR, cap);
    let key = Uuid::new_v4();
    let users: Vec<Uuid> = (0..10).map(|_| Uuid::new_v4()).collect();
    for (i, &u) in users.iter().enumerate() {
        std::thread::sleep(Duration::from_millis(1));
        detector.record(u, key, Uuid::new_v4(), &baseline(), &h(&[&format!("{i}")]), None);
    }
    assert_eq!(detector.held_bytes(), cap);
    assert_eq!(detector.entries(), 10, "at the cap, nothing goes");
    // One more: past the cap, the pass leaves at most nine tenths of it,
    // forgetting the least recently active users whole.
    std::thread::sleep(Duration::from_millis(1));
    detector.record(users[0], key, Uuid::new_v4(), &baseline(), &h(&["new"]), None);
    assert!(detector.held_bytes() <= cap - cap / 10, "{} held", detector.held_bytes());
    assert_eq!(detector.entries(), 9);
    assert!(listed(&detector, users[1], key).is_empty());
    assert!(listed(&detector, users[2], key).is_empty());
    assert_eq!(listed(&detector, users[0], key), vec![h(&["0"]), h(&["new"])]);
    assert_eq!(listed(&detector, users[9], key), vec![h(&["9"])]);
}

#[test]
fn the_cap_evicts_a_whole_user_and_returns() {
    // Each record past the cap empties the oldest users' lists, removing them
    // from the map — and returns (a guard held across a call on the map
    // would park the thread).
    let detector = std::sync::Arc::new(SessionDetector::with_capacity(1, HOUR, 2 * weight(1)));
    let (first, middle, second, key_id) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    for (i, user_id) in [first, middle, second].into_iter().enumerate() {
        std::thread::sleep(Duration::from_millis(2));
        let d = detector.clone();
        returns_in_time(move || d.record(user_id, key_id, Uuid::new_v4(), &baseline(), &h(&[&format!("hash_{i}")]), None));
    }
    assert_eq!(detector.entries(), 1);
    assert!(detector.recent_turns.get(&(first, key_id)).is_none());
    assert!(detector.recent_turns.get(&(middle, key_id)).is_none());
    assert_eq!(listed(&detector, second, key_id).len(), 1);
}

#[test]
fn a_pass_forgets_whole_conversations_least_recently_active_first() {
    // One user's long conversation and another's short one, past the cap:
    // dropping the long conversation's older turns alone would free nothing
    // (its newest turn holds the chain); its list goes whole.
    let (user, other, key) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    // Ten turns and the conversation's counter.
    let cap = 10 * weight(4) + COUNTER_BYTES;
    let detector = SessionDetector::with_capacity(50, HOUR, cap);
    let mut history = Vec::new();
    for turn in 0..10 {
        history.extend([format!("{turn}a"), format!("{turn}b"), format!("{turn}c"), format!("{turn}d")]);
        let hashes = h(&history.iter().map(String::as_str).collect::<Vec<_>>());
        let info = detector.detect(user, key, Uuid::nil(), &hashes, hashes.first().copied(), None);
        detector.record(user, key, Uuid::new_v4(), &info, &hashes, None);
        std::thread::sleep(Duration::from_millis(1));
    }
    assert_eq!(detector.held_bytes(), cap);
    detector.record(other, key, Uuid::new_v4(), &baseline(), &h(&["x"]), None);
    assert!(detector.held_bytes() <= cap - cap / 10);
    assert!(listed(&detector, user, key).is_empty(), "the conversation went whole");
    assert_eq!(listed(&detector, other, key), vec![h(&["x"])]);
}

#[test]
fn a_snapshot_being_written_does_not_hold_the_ceiling_off() {
    // The snapshot keeps no turn alive: a pass while it is written frees what
    // it forgets, and the snapshot writes only what is still alive.
    let cap = 10 * weight(1);
    let detector = SessionDetector::with_capacity(50, HOUR, cap);
    let key = Uuid::new_v4();
    let users: Vec<Uuid> = (0..11).map(|_| Uuid::new_v4()).collect();
    for (i, &u) in users[..10].iter().enumerate() {
        std::thread::sleep(Duration::from_millis(1));
        detector.record(u, key, Uuid::new_v4(), &baseline(), &h(&[&format!("{i}")]), None);
    }
    let mut export = detector.export();
    std::thread::sleep(Duration::from_millis(1));
    detector.record(users[10], key, Uuid::new_v4(), &baseline(), &h(&["during"]), None);
    assert!(detector.held_bytes() <= cap - cap / 10);
    assert_eq!(detector.entries(), 9);
    let mut out = Vec::new();
    assert_eq!(export.write_to(&mut out).unwrap(), RestoreCounts { users: 8, turns: 8 });
    let restored = SessionDetector::new(50, HOUR);
    restored.import_from(&out[..]).unwrap();
    assert!(listed(&restored, users[0], key).is_empty());
    assert_eq!(listed(&restored, users[9], key), vec![h(&["9"])]);
}

#[test]
fn a_request_nothing_can_continue_leaves_no_counter() {
    // A media call without a session id, or a first turn: a new random
    // session takes no counter (the media call is never recorded, so a
    // counter would be held for the TTL with nothing to name it).
    let detector = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    for _ in 0..3 {
        assert_eq!(detector.detect(user, key, Uuid::nil(), &[], None, None).turn_number, 0);
    }
    let first = detector.detect(user, key, Uuid::nil(), &h(&["a"]), root(&["a"]), None);
    assert!(detector.next_turn.is_empty());
    // The control: its continuation and a client session id each take one.
    detector.record(user, key, Uuid::new_v4(), &first, &h(&["a"]), None);
    assert_eq!(detector.detect(user, key, Uuid::nil(), &h(&["a", "b"]), root(&["a", "b"]), None).turn_number, 1);
    detector.detect(user, key, Uuid::nil(), &[], None, Some("cs"));
    assert_eq!(detector.next_turn.len(), 2);
}

#[test]
fn under_the_cap_every_user_keeps_its_entries() {
    let detector = SessionDetector::with_capacity(2, HOUR, 4 * weight(1));
    let key_id = Uuid::new_v4();
    for user_id in [Uuid::new_v4(), Uuid::new_v4()] {
        for i in 0..2 {
            detector.record(user_id, key_id, Uuid::new_v4(), &baseline(), &h(&[&format!("hash_{i}")]), None);
        }
    }
    assert_eq!(detector.entries(), 4);
    assert_eq!(detector.recent_turns.len(), 2);
}

#[test]
fn no_cap_keeps_everything() {
    let detector = SessionDetector::with_capacity(50, HOUR, 0);
    let key = Uuid::new_v4();
    for _ in 0..200 {
        detector.record(Uuid::new_v4(), key, Uuid::new_v4(), &baseline(), &h(&["a", "b"]), None);
    }
    assert_eq!(detector.entries(), 200);
}

#[test]
fn a_link_hash_is_its_32_bytes_and_round_trips_as_hex() {
    let hex_hash = "ab".repeat(32);
    let held = LinkHash::of(&hex_hash);
    assert_eq!(held.0, [0xab; 32]);
    assert_eq!(serde_json::to_string(&held).unwrap(), format!("\"{hex_hash}\""));
    assert_eq!(serde_json::from_str::<LinkHash>(&format!("\"{hex_hash}\"")).unwrap(), held);
    // Not a hex hash (upper case, another length, a non-hex character): its
    // digest, never its bytes.
    assert_ne!(LinkHash::of(&"AB".repeat(32)), held);
    assert_ne!(LinkHash::of(&"ab".repeat(33)).0[..], [0xab; 33][..32]);
    assert_ne!(LinkHash::of(&format!("{}zz", "ab".repeat(31))).0[..31], [0xab; 31]);
    // Never the bytes of the hex of a text's own digest.
    let digest_hex = hex::encode(Sha256::digest(b"h1"));
    assert_ne!(LinkHash::of("h1"), LinkHash::of(&digest_hex));
    assert_eq!(LinkHash::of("h1"), LinkHash::of("h1"));
    assert_ne!(LinkHash::of("h1"), LinkHash::of("h2"));
    assert_eq!(std::mem::size_of::<LinkHash>(), 32);
    // A snapshot reads back only what it writes: damaged hex is refused.
    for damaged in ["AB".repeat(32), "ab".repeat(31), format!("{}zz", "ab".repeat(31)), "h1".into()] {
        assert!(serde_json::from_str::<LinkHash>(&format!("\"{damaged}\"")).is_err(), "{damaged}");
    }
}

#[test]
fn a_request_repeated_whole_never_grows_a_chain() {
    // A probe or an eval sending one request again and again: each repeat
    // shares the repeated turn's parent, so evicted repeats free their weight.
    let detector = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let first = detector.detect(user, key, Uuid::nil(), &h(&["s", "u"]), root(&["s", "u"]), None);
    detector.record(user, key, Uuid::new_v4(), &first, &h(&["s", "u"]), None);
    let longer = detector.detect(user, key, Uuid::nil(), &h(&["s", "u", "a", "v"]), root(&["s", "u", "a", "v"]), None);
    detector.record(user, key, Uuid::new_v4(), &longer, &h(&["s", "u", "a", "v"]), None);
    for _ in 0..200 {
        let again = detector.detect(user, key, Uuid::nil(), &h(&["s", "u", "a", "v"]), root(&["s", "u", "a", "v"]), None);
        detector.record(user, key, Uuid::new_v4(), &again, &h(&["s", "u", "a", "v"]), None);
    }
    // No chain deeper than the one turn the repeats extend: 50 listed turns
    // and at most that one beside them.
    let turns = detector.recent_turns.get(&(user, key)).unwrap();
    assert!(turns.iter().all(|t| t.parent.as_ref().is_none_or(|p| p.len == 2 && p.parent.is_none())));
    drop(turns);
    assert!(detector.held_bytes() <= weight(2) + 50 * weight(4), "{} held", detector.held_bytes());
}

// --- Turn numbers -----------------------------------------------------------

#[test]
fn two_turns_continuing_one_turn_get_two_numbers() {
    // A fork, or two requests of one session served together: arrival order.
    let detector = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let first = detector.detect(user, key, Uuid::nil(), &h(&["a"]), root(&["a"]), None);
    detector.record(user, key, Uuid::new_v4(), &first, &h(&["a"]), None);
    let left = detector.detect(user, key, Uuid::nil(), &h(&["a", "b"]), root(&["a", "b"]), None);
    let right = detector.detect(user, key, Uuid::nil(), &h(&["a", "c"]), root(&["a", "c"]), None);
    assert_eq!((left.session_id, right.session_id), (first.session_id, first.session_id));
    assert_eq!((left.turn_number, right.turn_number), (1, 2));
    assert_eq!(left.parent_request_id, right.parent_request_id);
}

#[test]
fn a_session_counter_outlives_its_turns_until_the_ttl() {
    let detector = SessionDetector::new(1, Duration::from_millis(50));
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let mut history = vec!["r".to_string()];
    for turn in 0..3 {
        let names: Vec<&str> = history.iter().map(String::as_str).collect();
        let info = detector.detect(user, key, Uuid::nil(), &h(&names), root(&names), Some("cs"));
        assert_eq!(info.turn_number, turn);
        detector.record(user, key, Uuid::new_v4(), &info, &h(&names), Some("cs"));
        history.push(format!("{turn}"));
    }
    // Its turns are gone; its counter is not: the thread rewound goes on.
    detector.recent_turns.clear();
    assert_eq!(detector.detect(user, key, Uuid::nil(), &h(&["r", "x"]), root(&["r"]), Some("cs")).turn_number, 3);
    std::thread::sleep(Duration::from_millis(60));
    detector.prune_expired_users();
    assert!(detector.next_turn.is_empty(), "an idle session's counter goes with the TTL");
    assert_eq!(detector.held_bytes(), 0, "and its weight with it");
    assert_eq!(detector.detect(user, key, Uuid::nil(), &h(&["r", "x"]), root(&["r"]), Some("cs")).turn_number, 0);
}

#[test]
fn the_session_counters_keep_to_a_tenth_of_the_ceiling() {
    // A client minting a client session id per request takes a counter for
    // each: past their share, the least recently used go.
    let share = 20;
    let detector = SessionDetector::with_capacity(50, HOUR, share * 10 * COUNTER_BYTES);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let first = detector.detect(user, key, Uuid::nil(), &[], None, Some("first"));
    for i in 0..share - 1 {
        // Each a moment after the one before: the pass orders them by use.
        std::thread::sleep(Duration::from_millis(1));
        detector.detect(user, key, Uuid::nil(), &[], None, Some(&format!("id-{i}")));
    }
    std::thread::sleep(Duration::from_millis(1));
    // At the share, nothing goes.
    assert_eq!(detector.next_turn.len(), share);
    assert_eq!(detector.held_bytes(), share * COUNTER_BYTES);
    detector.detect(user, key, Uuid::nil(), &[], None, Some("one-more"));
    // One past it, the oldest go, down to nine tenths of it; the newest stays.
    assert_eq!(detector.next_turn.len(), share - share / 10);
    assert_eq!(detector.held_bytes(), (share - share / 10) * COUNTER_BYTES);
    assert!(!detector.next_turn.contains_key(&first.session_id));
    assert!(detector.next_turn.contains_key(&session_id_from_client("one-more", Uuid::nil(), user)));
    // Counters used at one instant (a restore stamps them alike): exactly the
    // excess goes, not every one of them.
    let alike = SessionDetector::with_capacity(50, HOUR, share * 10 * COUNTER_BYTES);
    let now = Instant::now();
    for _ in 0..share {
        alike.next_turn.insert(Uuid::new_v4(), (1, now));
    }
    alike.held.fetch_add(share * COUNTER_BYTES, Ordering::Relaxed);
    std::thread::sleep(Duration::from_millis(1));
    let newest = alike.detect(user, key, Uuid::nil(), &[], None, Some("newest"));
    assert_eq!(alike.next_turn.len(), share - share / 10);
    assert!(alike.next_turn.contains_key(&newest.session_id));
}

// --- Re-sends ---------------------------------------------------------------

/// The request key of a test request whose body is its messages.
fn key_of(user: Uuid, key: Uuid, names: &[&str], csid: Option<&str>) -> [u8; 32] {
    request_key(user, key, csid, "chat_completions", "m", false, names.join("|").as_bytes())
}

/// Detect and record one request, as the proxy does for every turn, and
/// keep it served until the returned guard drops.
fn arrive(d: &SessionDetector, user: Uuid, key: Uuid, names: &[&str], csid: Option<&str>) -> (SessionInfo, ServingGuard) {
    let served = d.detect_serving(user, key, Uuid::nil(), &h(names), root(names), csid, key_of(user, key, names, csid));
    d.record(user, key, Uuid::new_v4(), &served.0, &h(names), csid);
    served
}

#[test]
fn a_resent_first_turn_is_the_same_turn_and_the_next_turn_joins_it() {
    let d = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let (first, held) = arrive(&d, user, key, &["a"], None);
    let (again, resent) = arrive(&d, user, key, &["a"], None);
    assert_eq!((again.session_id, again.turn_number, again.is_baseline), (first.session_id, 0, true));
    assert_eq!(again.parent_request_id, None);
    drop((held, resent));
    // The next, longer turn joins the one session: nothing is left orphaned.
    let (next, _g) = arrive(&d, user, key, &["a", "b", "c"], None);
    assert_eq!((next.session_id, next.turn_number), (first.session_id, 1));
}

#[test]
fn a_resent_later_turn_keeps_its_number_and_parent() {
    let d = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    drop(arrive(&d, user, key, &["a"], None));
    let (second, _held) = arrive(&d, user, key, &["a", "b", "c"], None);
    let (again, _resent) = arrive(&d, user, key, &["a", "b", "c"], None);
    assert_eq!((again.session_id, again.turn_number), (second.session_id, 1));
    assert_eq!((again.parent_request_id, again.is_baseline), (second.parent_request_id, false));
    // The positive control: a longer request still advances.
    let (third, _g) = arrive(&d, user, key, &["a", "b", "c", "d", "e"], None);
    assert_eq!((third.session_id, third.turn_number), (second.session_id, 2));
}

#[test]
fn a_resend_under_a_client_session_id_is_not_the_next_turn() {
    let d = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    drop(arrive(&d, user, key, &["a"], Some("cs")));
    let (second, _held) = arrive(&d, user, key, &["a", "b", "c"], Some("cs"));
    let (again, _resent) = arrive(&d, user, key, &["a", "b", "c"], Some("cs"));
    assert_eq!((again.session_id, again.turn_number), (second.session_id, 1));
    // An identical body under ANOTHER client session id is another request.
    let (other, _o) = arrive(&d, user, key, &["a", "b", "c"], Some("other"));
    assert_ne!(other.session_id, second.session_id);
}

#[test]
fn equal_session_hashes_of_a_different_request_are_not_a_resend() {
    // A Responses turn chained by `previous_response_id`, an Anthropic
    // `system` or another model: the session hashes match, the request
    // does not.
    let d = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    drop(arrive(&d, user, key, &["a"], Some("cs")));
    let (second, _held) = arrive(&d, user, key, &["a", "b", "c"], Some("cs"));
    let other = request_key(user, key, Some("cs"), "responses", "m", false, b"previous_response_id=2");
    let (next, _g) = d.detect_serving(user, key, Uuid::nil(), &h(&["a", "b", "c"]), root(&["a", "b", "c"]), Some("cs"), other);
    assert_eq!((next.session_id, next.turn_number), (second.session_id, 2));
}

#[test]
fn the_same_body_from_another_user_or_key_is_not_a_resend() {
    let d = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let (first, _held) = arrive(&d, user, key, &["a"], None);
    assert_ne!(arrive(&d, user, Uuid::new_v4(), &["a"], None).0.session_id, first.session_id);
    assert_ne!(arrive(&d, Uuid::new_v4(), key, &["a"], None).0.session_id, first.session_id);
}

#[test]
fn the_same_request_once_the_original_is_over_is_asked_again() {
    // A test suite, a cron job, "regenerate" once the answer arrived — or
    // a copy refused or failed: once nothing serves the original, the same
    // request is the conversation asking again.
    let d = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let (first, held) = arrive(&d, user, key, &["a"], None);
    // The control: while it is served, the same request is a re-send.
    let (again, resent) = arrive(&d, user, key, &["a"], None);
    assert_eq!(again.session_id, first.session_id);
    // Every copy must end: one still served keeps the turn open. A copy
    // released early (its answer delivered, its audit still running) and
    // then dropped counts once.
    held.release();
    drop(held);
    assert_eq!(arrive(&d, user, key, &["a"], None).0.session_id, first.session_id);
    drop(resent);
    let (later, _g) = arrive(&d, user, key, &["a"], None);
    assert_ne!(later.session_id, first.session_id);
    assert_eq!(later.turn_number, 0);
}

#[test]
fn copies_arriving_together_take_one_turn_number() {
    // Under a client session id the losing copies take no number: the
    // conversation's next turn follows the one they share.
    for _ in 0..20 {
        let d = std::sync::Arc::new(SessionDetector::new(20, HOUR));
        let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
        drop(arrive(&d, user, key, &["a"], Some("cs")));
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let copies: Vec<_> = (0..8)
            .map(|_| {
                let (d, start) = (d.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    d.detect_serving(user, key, Uuid::nil(), &h(&["a", "b"]), root(&["a", "b"]), Some("cs"), key_of(user, key, &["a", "b"], Some("cs")))
                })
            })
            .collect();
        let served: Vec<_> = copies.into_iter().map(|c| c.join().expect("thread")).collect();
        assert!(served.iter().all(|(info, _)| info.turn_number == 1));
        drop(served);
        assert_eq!(arrive(&d, user, key, &["a", "b", "c"], Some("cs")).0.turn_number, 2);
    }
}

#[test]
fn copies_arriving_together_get_one_turn() {
    // Each copy detects outside the entry's lock; the first to register
    // must win, or two simultaneous first turns open two sessions.
    for _ in 0..50 {
        let d = std::sync::Arc::new(SessionDetector::new(20, HOUR));
        let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
        let start = std::sync::Arc::new(std::sync::Barrier::new(8));
        let copies: Vec<_> = (0..8)
            .map(|_| {
                let (d, start) = (d.clone(), start.clone());
                std::thread::spawn(move || {
                    start.wait();
                    d.detect_serving(user, key, Uuid::nil(), &h(&["a"]), root(&["a"]), None, key_of(user, key, &["a"], None))
                })
            })
            .collect();
        let served: Vec<_> = copies.into_iter().map(|c| c.join().expect("thread")).collect();
        let sessions: std::collections::HashSet<_> = served.iter().map(|(info, _)| info.session_id).collect();
        assert_eq!(sessions.len(), 1, "simultaneous copies split into {} sessions", sessions.len());
    }
}

// --- The snapshot -----------------------------------------------------------

fn snapshot(d: &SessionDetector) -> Vec<u8> {
    let mut out = Vec::new();
    d.export().write_to(&mut out).expect("write");
    out
}

#[test]
fn a_snapshot_restores_every_turn_once_and_matching_goes_on() {
    let d = SessionDetector::new(3, HOUR);
    let (user, other, key) = (Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4());
    let mut names: Vec<String> = Vec::new();
    let mut last = None;
    for turn in 0..6 {
        names.push(format!("m{turn}"));
        let hashes = h(&names.iter().map(String::as_str).collect::<Vec<_>>());
        let info = d.detect(user, key, Uuid::nil(), &hashes, hashes.first().copied(), Some("cs"));
        let request = Uuid::new_v4();
        d.record(user, key, request, &info, &hashes, Some("cs"));
        last = Some((info, request));
    }
    d.record(other, key, Uuid::new_v4(), &baseline(), &h(&["o"]), None);
    let held = d.held_bytes();
    let written = snapshot(&d);
    // Six turns of a chain (three listed, three only as parents) and one
    // other: each written once.
    assert_eq!(written.split(|&b| b == b'\n').filter(|l| l.starts_with(b"{\"turn\"")).count(), 7);

    let restored = SessionDetector::new(3, HOUR);
    let counts = restored.import_from(&written[..]).expect("restore");
    assert_eq!(counts, RestoreCounts { users: 2, turns: 4 });
    // The turns hold what they held; a counter is restored for each session
    // (the other user's first turn took none).
    let turns_held = |d: &SessionDetector| d.held_bytes() - d.next_turn.len() * COUNTER_BYTES;
    assert_eq!(turns_held(&restored), held - d.next_turn.len() * COUNTER_BYTES);
    assert_eq!(restored.next_turn.len(), 2);
    assert_eq!(listed(&restored, user, key), listed(&d, user, key));
    assert_eq!(listed(&restored, other, key), vec![h(&["o"])]);
    // The conversation goes on where it was, numbered after its last turn.
    let (last_info, last_request) = last.unwrap();
    names.push("m6".into());
    let next = restored.detect(user, key, Uuid::nil(), &h(&names.iter().map(String::as_str).collect::<Vec<_>>()), names.first().map(|n| LinkHash::of(n)), Some("cs"));
    assert_eq!((next.session_id, next.parent_request_id, next.turn_number, next.is_baseline), (last_info.session_id, Some(last_request), 6, false));
}

#[test]
fn a_snapshot_that_does_not_read_restores_nothing() {
    let d = SessionDetector::new(3, HOUR);
    d.record(Uuid::new_v4(), Uuid::new_v4(), Uuid::new_v4(), &baseline(), &h(&["a"]), None);
    let written = String::from_utf8(snapshot(&d)).unwrap();
    // The control: the file as written restores.
    assert!(SessionDetector::new(3, HOUR).import_from(written.as_bytes()).is_ok());
    for broken in [
        "not json\n".to_string(),
        // A user listing a turn the file never wrote.
        written.replace("\"turns\":[0]", "\"turns\":[5]"),
        // A turn naming a parent written after it.
        written.replace("\"parent\":null", "\"parent\":3"),
    ] {
        let restored = SessionDetector::new(3, HOUR);
        assert!(restored.import_from(broken.as_bytes()).is_err(), "{broken}");
        assert_eq!((restored.entries(), restored.held_bytes()), (0, 0), "{broken}");
    }
}

#[test]
fn a_restore_past_the_cap_forgets_whole_users() {
    // Restored turns share one stamp: past the cap, users go whole until the
    // weight is under nine tenths of it.
    let source = SessionDetector::new(50, HOUR);
    let key_id = Uuid::new_v4();
    let users: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    for &u in &users {
        for i in 0..4 {
            let info = SessionInfo { turn_number: i, ..baseline() };
            source.record(u, key_id, Uuid::new_v4(), &info, &h(&[&format!("{u}-{i}")]), None);
        }
    }
    let restored = SessionDetector::with_capacity(50, HOUR, 11 * weight(1));
    restored.import_from(&snapshot(&source)[..]).expect("restore");
    // 12 turns past a cap of 11: one user goes whole, the others keep all four.
    let kept: Vec<usize> = users.iter().map(|&u| listed(&restored, u, key_id).len()).collect();
    assert_eq!(kept.iter().filter(|&&n| n == 4).count(), 2, "{kept:?}");
    assert_eq!(kept.iter().filter(|&&n| n == 0).count(), 1, "{kept:?}");
    assert_eq!(restored.held_bytes(), 8 * weight(1) + restored.next_turn.len() * COUNTER_BYTES);
}

#[test]
fn a_user_holding_most_of_the_ceiling_is_forgotten_before_the_others() {
    // One key's history weighs more than half the ceiling: it goes, not
    // every other user (each pass would otherwise forget them all to keep it).
    let cap = 10 * weight(1);
    let detector = SessionDetector::with_capacity(50, HOUR, cap);
    let key = Uuid::new_v4();
    let others: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    for (i, &u) in others.iter().enumerate() {
        detector.record(u, key, Uuid::new_v4(), &baseline(), &h(&[&format!("{i}")]), None);
    }
    let heavy = Uuid::new_v4();
    let names: Vec<String> = (0..cap / 32 + 1).map(|i| format!("m{i}")).collect();
    detector.record(heavy, key, Uuid::new_v4(), &baseline(), &h(&names.iter().map(String::as_str).collect::<Vec<_>>()), None);
    assert!(listed(&detector, heavy, key).is_empty());
    for (i, &u) in others.iter().enumerate() {
        assert_eq!(listed(&detector, u, key), vec![h(&[&format!("{i}")])]);
    }
    // The control: past the ceiling, a recording user under half of it goes
    // last — the least recently active other goes.
    let detector = SessionDetector::with_capacity(50, HOUR, cap);
    let others: Vec<Uuid> = (0..9).map(|_| Uuid::new_v4()).collect();
    for (i, &u) in others.iter().enumerate() {
        std::thread::sleep(Duration::from_millis(1));
        detector.record(u, key, Uuid::new_v4(), &baseline(), &h(&[&format!("{i}")]), None);
    }
    let light = Uuid::new_v4();
    detector.record(light, key, Uuid::new_v4(), &baseline(), &h(&["l1", "l2"]), None);
    assert_eq!(listed(&detector, light, key), vec![h(&["l1", "l2"])]);
    assert!(listed(&detector, others[0], key).is_empty());
    assert_eq!(listed(&detector, others[8], key), vec![h(&["8"])]);
}

#[test]
fn a_restore_keeps_the_most_recent_users_their_age_and_the_ceiling() {
    let source = SessionDetector::new(50, HOUR);
    let key = Uuid::new_v4();
    let users: Vec<Uuid> = (0..3).map(|_| Uuid::new_v4()).collect();
    // Each user one turn of 40 messages: heavy enough beside the counters.
    let turn = |i: usize| h(&(0..40).map(|m| format!("{i}-{m}")).collect::<Vec<_>>().iter().map(String::as_str).collect::<Vec<_>>());
    for (i, &u) in users.iter().enumerate() {
        std::thread::sleep(Duration::from_millis(2));
        source.record(u, key, Uuid::new_v4(), &baseline(), &turn(i), None);
    }
    std::thread::sleep(Duration::from_millis(30));
    // Read most recent first: past 1.5 turns' weight the restore stops (the
    // oldest user is never built), and the pass forgets the least recently
    // active of the two read.
    let restored = SessionDetector::with_capacity(50, HOUR, weight(40) + weight(40) / 2);
    restored.import_from(&snapshot(&source)[..]).expect("restore");
    assert!(listed(&restored, users[0], key).is_empty());
    assert!(listed(&restored, users[1], key).is_empty());
    assert_eq!(listed(&restored, users[2], key), vec![turn(2)]);
    let age = restored.recent_turns.get(&(users[2], key)).unwrap()[0].recorded_at.elapsed();
    assert!(age >= Duration::from_millis(30), "restored as recorded {age:?} ago");
    // The users past the ceiling keep their sessions' counters.
    assert_eq!(restored.next_turn.len(), 3);
    // A per-user count lowered since the write: each user keeps its newest.
    let long = SessionDetector::new(50, HOUR);
    for i in 0..4 {
        long.record(users[0], key, Uuid::new_v4(), &baseline(), &h(&[&format!("t{i}")]), None);
    }
    let fewer = SessionDetector::new(2, HOUR);
    assert_eq!(fewer.import_from(&snapshot(&long)[..]).unwrap(), RestoreCounts { users: 1, turns: 2 });
    assert_eq!(listed(&fewer, users[0], key), vec![h(&["t2"]), h(&["t3"])]);
}

#[test]
fn a_turn_past_its_ttl_while_the_gateway_was_down_is_not_restored() {
    let source = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    source.record(user, key, Uuid::new_v4(), &baseline(), &h(&["a"]), None);
    let written = String::from_utf8(snapshot(&source)).unwrap();
    // The control: restored as written.
    assert_eq!(SessionDetector::new(50, HOUR).import_from(written.as_bytes()).unwrap().turns, 1);
    // Recorded two TTLs ago by the wall clock: the downtime counts.
    let stale = epoch_millis() - 2 * HOUR.as_millis() as u64;
    let start = written.find("\"recorded_ms\":").unwrap() + "\"recorded_ms\":".len();
    let end = start + written[start..].find(',').unwrap();
    let old = format!("{}{stale}{}", &written[..start], &written[end..]);
    let restored = SessionDetector::new(50, HOUR);
    assert_eq!(restored.import_from(old.as_bytes()).unwrap(), RestoreCounts { users: 0, turns: 0 });
    assert_eq!(restored.held_bytes(), 0);
}

#[test]
fn a_history_cut_under_its_client_session_id_stays_in_its_session() {
    // A sliding window: once full, each request drops the oldest exchange, so
    // none extends the one before; each is a baseline of the same session.
    let detector = SessionDetector::new(50, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let mut history: Vec<String> = Vec::new();
    let mut session = None;
    for step in 0..8 {
        history.push(format!("ask {step}"));
        let window: Vec<&str> = history.iter().rev().take(4).rev().map(String::as_str).collect();
        let hashes = h(&window);
        let info = detector.detect(user, key, Uuid::nil(), &hashes, root(&window), Some("window"));
        assert_eq!(*session.get_or_insert(info.session_id), info.session_id, "step {step}");
        detector.record(user, key, Uuid::new_v4(), &info, &hashes, Some("window"));
        history.push(format!("answer {step}"));
    }
    // Under another client session id, or with only its opening in common
    // (a new conversation opening with a message seen before): another session.
    let cut = h(&["ask 6", "answer 6"]);
    assert_ne!(detector.detect(user, key, Uuid::nil(), &cut, root(&["ask 6"]), Some("other")).session_id, session.unwrap());
    let lone = h(&["ask 6", "something new"]);
    assert_ne!(detector.detect(user, key, Uuid::nil(), &lone, root(&["ask 6"]), Some("window")).session_id, session.unwrap());
    assert_ne!(detector.detect(user, key, Uuid::nil(), &h(&["ask 6"]), root(&["ask 6"]), Some("window")).session_id, session.unwrap());
}

#[test]
fn a_cut_history_is_found_across_the_parts_a_chain_shares() {
    // The two messages straddle a turn and its parent: still side by side.
    let detector = SessionDetector::new(20, HOUR);
    let (user, key) = (Uuid::new_v4(), Uuid::new_v4());
    let first = h(&["a", "b"]);
    let one = detector.detect(user, key, Uuid::nil(), &first, root(&["a"]), Some("s"));
    detector.record(user, key, Uuid::new_v4(), &one, &first, Some("s"));
    let second = h(&["a", "b", "c", "d"]);
    let two = detector.detect(user, key, Uuid::nil(), &second, root(&["a"]), Some("s"));
    detector.record(user, key, Uuid::new_v4(), &two, &second, Some("s"));
    let cut = detector.detect(user, key, Uuid::nil(), &h(&["b", "c", "e"]), root(&["b"]), Some("s"));
    assert_eq!((cut.session_id, cut.is_baseline, cut.parent_request_id), (one.session_id, true, None));
}
