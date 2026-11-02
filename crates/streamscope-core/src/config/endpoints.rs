//! Replica endpoints of upstream servers, as the proxy routes to them.
//!
//! A server may be reached at several endpoints — replicas of one engine that
//! share its credential and protocol. The admin ships each server's ENABLED
//! endpoints once per tenant ([`EndpointTable`]), primary first, and, for a
//! model not every endpoint serves, the endpoints that do. A request's model
//! resolves to a route target as before; the target's endpoints are then put
//! in order for that request by [`order_endpoints`].
//!
//! The order is what keeps a conversation on one replica: weighted rendezvous
//! hashing (highest random weight) over `(session key, model, endpoint)`. Every
//! turn of a session ranks the same endpoint first, so the replica's prefix
//! cache keeps hitting; the model salts the hash so two models on the same
//! replicas spread their sessions independently; and when an endpoint leaves,
//! only the sessions it ranked first move — every other session keeps its
//! replica. A request with no session key takes round-robin instead.

use std::collections::HashMap;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicUsize, Ordering};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// One enabled endpoint of a server.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointConfig {
    pub id: Uuid,
    pub url: String,
    /// Relative share of sessions (≥ 1).
    #[serde(default = "one")]
    pub weight: u32,
    /// How many requests the gateway may have in flight here at once, already
    /// resolved (the endpoint's own value, else its server's). `None` leaves
    /// this endpoint unbounded, which is what every server without capacity
    /// knobs ships.
    #[serde(default)]
    pub max_in_flight: Option<u32>,
    /// How long the engine's OWN waiting queue may grow before the gateway
    /// stops releasing to it, resolved the same way. `None` means the gateway
    /// does not read this endpoint's queue.
    #[serde(default)]
    pub waiting_threshold: Option<u32>,
    /// Whether the gateway reads this endpoint's engine metrics for the
    /// dashboards (its server's switch). A waiting-queue bound is read whatever
    /// this says: the bound cannot apply without the reading.
    #[serde(default)]
    pub engine_metrics: bool,
    /// Whether the gateway LEARNS this endpoint's in-flight limit from its
    /// engine's readings (its server's switch), `max_in_flight` being the
    /// ceiling. The engine is read whatever `engine_metrics` says: the window
    /// cannot move without the reading. Never set together with
    /// `waiting_threshold` — the window replaces the queue bound.
    #[serde(default)]
    pub adaptive_concurrency: bool,
    /// The token-latency target that learned limit keeps the engine within
    /// (its server's setting).
    #[serde(default)]
    pub adaptive_itl_target: crate::proxy::adaptive_concurrency::ItlTarget,
}

impl EndpointConfig {
    /// Whether the dispatch gate bounds this endpoint: a fixed in-flight limit,
    /// an engine-queue bound, or a learned limit. The one definition the
    /// poller, the load report and the gate's retention agree on.
    pub fn gated(&self) -> bool {
        self.max_in_flight.is_some() || self.waiting_threshold.is_some() || self.adaptive_concurrency
    }

    /// Whether the gateway reads this endpoint's engine: its server asks for
    /// the metrics, or it declares a bound that cannot apply unread — a
    /// waiting-queue bound, or a learned in-flight limit. The one definition
    /// the poller and the admin's credential shipping agree on.
    pub fn engine_read(&self) -> bool {
        self.engine_metrics || self.waiting_threshold.is_some() || self.adaptive_concurrency
    }
}

fn one() -> u32 {
    1
}

/// Every server's enabled endpoints, and which of them serve which model.
///
/// Every field defaults. The table is the only place the gateway finds a
/// server's URLs: a route target whose server it does not know is not
/// forwarded.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct EndpointTable {
    /// Each server's ENABLED endpoints, primary first.
    #[serde(default)]
    pub servers: HashMap<Uuid, Vec<EndpointConfig>>,
    /// The endpoints serving a model, for a model NOT served by every enabled
    /// endpoint of its server. A model absent here is served by all of them —
    /// so the common single-endpoint fleet ships no entry at all.
    #[serde(default)]
    pub model_members: HashMap<Uuid, Vec<Uuid>>,
    /// The stored credential of each server whose engine the gateway reads
    /// ([`EndpointConfig::engine_read`]) and that holds one. A routed model
    /// already carries its server's credential; this reaches a server none of
    /// whose models is routed yet, so the engine poll presents the same
    /// credential the admin's engine probe does.
    #[serde(default)]
    pub read_credentials: HashMap<Uuid, ReadCredential>,
}

/// A read server's stored credential, as the snapshot ships it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ReadCredential {
    /// The at-rest ciphertext, exactly as a routed model's credential ships.
    pub encrypted: String,
    /// How the server is addressed. Admin ships only default-transport
    /// credentials, and the poll presents nothing else — every other transport
    /// mints or signs per request; the edge re-checks it all the same.
    #[serde(default)]
    pub transport: crate::config::upstream_transport::UpstreamTransport,
}

impl EndpointTable {
    /// The endpoints a model can be sent to, primary order.
    ///
    /// `None` when the table knows no endpoint for the server, `Some(empty)`
    /// when the server has endpoints but none serves the model — either way
    /// the target cannot be forwarded.
    pub fn members(&self, server_id: Uuid, model_id: Option<Uuid>) -> Option<Vec<&EndpointConfig>> {
        let eps = self.servers.get(&server_id).filter(|v| !v.is_empty())?;
        Some(match model_id.and_then(|m| self.model_members.get(&m)) {
            Some(ids) => eps.iter().filter(|e| ids.contains(&e.id)).collect(),
            None => eps.iter().collect(),
        })
    }
}

/// The order in which one request should try a model's endpoints.
///
/// With a session `key`: weighted rendezvous hashing — each endpoint scores
/// `weight / -ln(u)` for `u` a hash of `(key, salt, endpoint)` mapped into
/// (0, 1), highest first. Deterministic in every proxy process running the
/// same binary (`DefaultHasher::new()` uses fixed keys), so replicas of the
/// gateway agree without sharing state. Without a key: weighted round-robin
/// from `counter` picks the first endpoint, the rest follow in primary order.
///
/// `salt` is the model's identity, so each model spreads its sessions over the
/// replicas independently.
pub fn order_endpoints<'a>(
    members: Vec<&'a EndpointConfig>,
    key: Option<&str>,
    salt: &str,
    counter: &AtomicUsize,
) -> Vec<&'a EndpointConfig> {
    if members.len() <= 1 {
        return members;
    }
    match key {
        Some(key) => {
            let mut scored: Vec<(f64, &EndpointConfig)> =
                members.into_iter().map(|e| (rendezvous_score(key, salt, e), e)).collect();
            // Scores are finite and positive; the id breaks an exact tie so the
            // order never depends on the input order.
            scored.sort_by(|a, b| b.0.total_cmp(&a.0).then_with(|| a.1.id.cmp(&b.1.id)));
            scored.into_iter().map(|(_, e)| e).collect()
        }
        None => {
            let total: u64 = members.iter().map(|e| u64::from(e.weight.max(1))).sum();
            let mut pick = counter.fetch_add(1, Ordering::Relaxed) as u64 % total;
            let first = members
                .iter()
                .position(|e| {
                    let w = u64::from(e.weight.max(1));
                    if pick < w {
                        true
                    } else {
                        pick -= w;
                        false
                    }
                })
                .unwrap_or(0);
            let mut ordered = members;
            ordered.rotate_left(first);
            ordered
        }
    }
}

/// An endpoint's rendezvous score for a key: `weight / -ln(u)`.
fn rendezvous_score(key: &str, salt: &str, e: &EndpointConfig) -> f64 {
    let mut h = DefaultHasher::new();
    key.hash(&mut h);
    salt.hash(&mut h);
    e.id.hash(&mut h);
    // Map the 64-bit hash to the open interval (0, 1): the top 53 bits give an
    // exact f64, the half-step keeps it off both ends so ln(u) is finite and
    // strictly negative.
    let u = ((h.finish() >> 11) as f64 + 0.5) / (1u64 << 53) as f64;
    f64::from(e.weight.max(1)) / -u.ln()
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn ep(n: u128, weight: u32) -> EndpointConfig {
        EndpointConfig {
            id: Uuid::from_u128(n),
            url: format!("http://replica-{n}:8000"),
            weight,
            max_in_flight: None,
            waiting_threshold: None,
            engine_metrics: false,
            adaptive_concurrency: false,
            adaptive_itl_target: Default::default(),
        }
    }

    fn ids(v: &[&EndpointConfig]) -> Vec<Uuid> {
        v.iter().map(|e| e.id).collect()
    }

    #[test]
    fn an_endpoint_without_a_weight_weighs_one() {
        let e: EndpointConfig =
            serde_json::from_str(r#"{"id":"00000000-0000-0000-0000-000000000001","url":"http://r:8000"}"#).unwrap();
        assert_eq!(e.weight, 1);
    }

    #[test]
    fn an_unknown_server_has_no_members() {
        let t = EndpointTable::default();
        assert!(t.members(Uuid::from_u128(1), None).is_none());
    }

    #[test]
    fn a_model_absent_from_the_member_map_is_served_by_every_endpoint() {
        let server = Uuid::from_u128(9);
        let mut t = EndpointTable::default();
        t.servers.insert(server, vec![ep(1, 1), ep(2, 1)]);
        t.model_members.insert(Uuid::from_u128(100), vec![Uuid::from_u128(2)]);
        assert_eq!(ids(&t.members(server, Some(Uuid::from_u128(50))).unwrap()), vec![Uuid::from_u128(1), Uuid::from_u128(2)]);
        assert_eq!(ids(&t.members(server, Some(Uuid::from_u128(100))).unwrap()), vec![Uuid::from_u128(2)]);
        // A model whose members are all gone is known and unservable.
        t.model_members.insert(Uuid::from_u128(101), vec![Uuid::from_u128(7)]);
        assert!(t.members(server, Some(Uuid::from_u128(101))).unwrap().is_empty());
    }

    #[test]
    fn round_robin_rotates_the_first_endpoint_and_keeps_the_rest_in_order() {
        let eps = [ep(1, 1), ep(2, 1), ep(3, 1)];
        let c = AtomicUsize::new(0);
        let firsts: Vec<Uuid> = (0..3)
            .map(|_| order_endpoints(eps.iter().collect(), None, "m", &c)[0].id)
            .collect();
        assert_eq!(firsts, vec![Uuid::from_u128(1), Uuid::from_u128(2), Uuid::from_u128(3)]);
        let c = AtomicUsize::new(1);
        assert_eq!(ids(&order_endpoints(eps.iter().collect(), None, "m", &c)), vec![Uuid::from_u128(2), Uuid::from_u128(3), Uuid::from_u128(1)]);
    }

    #[test]
    fn round_robin_honours_weight() {
        let eps = [ep(1, 3), ep(2, 1)];
        let c = AtomicUsize::new(0);
        let firsts: Vec<u128> = (0..4)
            .map(|_| order_endpoints(eps.iter().collect(), None, "m", &c)[0].id.as_u128())
            .collect();
        assert_eq!(firsts, vec![1, 1, 1, 2]);
    }

    #[test]
    fn sessions_spread_by_weight() {
        let eps = [ep(1, 3), ep(2, 1)];
        let c = AtomicUsize::new(0);
        let heavy = (0..4000)
            .filter(|i| {
                let key = format!("session-{i}");
                order_endpoints(eps.iter().collect(), Some(&key), "m", &c)[0].id == Uuid::from_u128(1)
            })
            .count();
        // Expected 3000 of 4000; the band is ~10 standard deviations wide.
        assert!((2730..=3270).contains(&heavy), "weight-3 endpoint took {heavy} of 4000 sessions");
    }

    /// With two endpoints any "score grows with weight" rule splits by weight;
    /// with three only `weight / -ln(u)` still does (`weight · -ln(u)` would
    /// give the heavy one ≈ 71 % here, not 4/6). The hash is fixed-key, so the
    /// count is deterministic; the band is ±5 standard deviations.
    #[test]
    fn three_endpoints_split_by_weight() {
        let eps = [ep(1, 1), ep(2, 1), ep(3, 4)];
        let c = AtomicUsize::new(0);
        let heavy = (0..8000)
            .filter(|i| {
                let key = format!("session-{i}");
                order_endpoints(eps.iter().collect(), Some(&key), "m", &c)[0].id == Uuid::from_u128(3)
            })
            .count();
        // Expected 8000 · 4/6 = 5333; the misweighted rule lands near 5690.
        assert!((5123..=5543).contains(&heavy), "weight-4 endpoint took {heavy} of 8000 sessions");
    }

    #[test]
    fn the_model_salts_the_choice() {
        let eps: Vec<EndpointConfig> = (1..=4).map(|n| ep(n, 1)).collect();
        let c = AtomicUsize::new(0);
        let differs = (0..200).any(|i| {
            let key = format!("s{i}");
            order_endpoints(eps.iter().collect(), Some(&key), "model-a", &c)[0].id
                != order_endpoints(eps.iter().collect(), Some(&key), "model-b", &c)[0].id
        });
        assert!(differs, "two models placed every session identically");
    }

    fn endpoints() -> impl Strategy<Value = Vec<EndpointConfig>> {
        proptest::collection::btree_set(1u128..50, 1..6).prop_flat_map(|ids| {
            let n = ids.len();
            (Just(ids), proptest::collection::vec(1u32..5, n))
        })
        .prop_map(|(ids, weights)| ids.into_iter().zip(weights).map(|(id, w)| ep(id, w)).collect())
    }

    proptest! {
        #[test]
        fn the_order_is_a_permutation_and_is_deterministic(eps in endpoints(), key in "[a-z0-9]{1,12}", counter in 0usize..100) {
            let c1 = AtomicUsize::new(counter);
            let c2 = AtomicUsize::new(counter);
            let a = ids(&order_endpoints(eps.iter().collect(), Some(&key), "m", &c1));
            let b = ids(&order_endpoints(eps.iter().rev().collect(), Some(&key), "m", &c2));
            prop_assert_eq!(&a, &b, "the keyed order depends on the input order");
            let mut sorted = a.clone();
            sorted.sort();
            let mut want: Vec<Uuid> = eps.iter().map(|e| e.id).collect();
            want.sort();
            prop_assert_eq!(sorted, want);
            let rr = ids(&order_endpoints(eps.iter().collect(), None, "m", &c1));
            prop_assert_eq!(rr.len(), eps.len());
        }

        #[test]
        fn removing_an_endpoint_moves_only_the_sessions_it_led(
            eps in endpoints(), key in "[a-z0-9]{1,12}", drop_at in 0usize..6
        ) {
            prop_assume!(eps.len() >= 2);
            let drop_at = drop_at % eps.len();
            let c = AtomicUsize::new(0);
            let before = ids(&order_endpoints(eps.iter().collect(), Some(&key), "m", &c));
            let dropped = eps[drop_at].id;
            let rest: Vec<&EndpointConfig> = eps.iter().filter(|e| e.id != dropped).collect();
            let after = ids(&order_endpoints(rest, Some(&key), "m", &c));
            // Everyone else keeps their relative order, so a session whose
            // first choice survives keeps it.
            let expected: Vec<Uuid> = before.iter().copied().filter(|id| *id != dropped).collect();
            prop_assert_eq!(after, expected);
        }
    }
}
