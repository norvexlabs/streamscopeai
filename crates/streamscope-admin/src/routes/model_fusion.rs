//! Fusing the model lists of a server's replica endpoints into one model set.
//!
//! A server may be reached at several endpoints — replicas of one engine. Each
//! endpoint is asked for its model list on its own, and every endpoint either
//! ANSWERS with a list or does not answer. This module decides, from those
//! answers alone, which models the server gains, which it retires, and what
//! each endpoint serves afterwards. It is pure (names in, a plan out); the
//! caller loads the state and applies the plan in one transaction.
//!
//! The rules, each a claim [`tests`] holds as a property:
//! - **Only an answer is evidence.** An endpoint that did not answer keeps
//!   exactly what it served.
//! - **An answer adds; it removes only when trusted.** An answer names the
//!   models the endpoint serves. It may REMOVE the ones it omits only when the
//!   endpoint had answered before, the answer is not implausibly short against
//!   what the endpoint last LISTED (empty, or under half), and the server is
//!   past its first sync. Otherwise the omitted models are kept as they were
//!   (listed ones stay listed, so a repeated short answer stays short) — save
//!   an assumed one another enabled endpoint lists, which goes.
//! - **A model retires only on the word of every endpoint that listed it.**
//!   The quorum is the endpoints that had answered before and served the
//!   model; every one of them must have answered, with the right to remove,
//!   without it. An endpoint that has never answered serves every model of its
//!   server by assumption, so it can neither keep a model alive nor retire one.
//! - **No model is stranded.** A model that served somewhere before the sync
//!   either still serves somewhere after it, or is retired.
//!
//! What is deliberately NOT a property: a sync is not idempotent across two
//! runs with the same answers, because the first answer from an endpoint moves
//! it from "never answered" to "answered" and the second may then remove.

use std::collections::{BTreeMap, BTreeSet};

/// How an endpoint came to serve a model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberKind {
    /// The endpoint's last answer named the model.
    Listed,
    /// Kept without that evidence: added by hand, or omitted by an answer that
    /// was not trusted to remove (and listed by no other enabled endpoint).
    Assumed,
}

impl MemberKind {
    pub fn as_str(self) -> &'static str {
        match self {
            MemberKind::Listed => "listed",
            MemberKind::Assumed => "assumed",
        }
    }
}

/// An endpoint as the sync finds it.
#[derive(Clone, Debug)]
pub struct EndpointState {
    /// Discovery has answered before. When false the endpoint serves every
    /// model of its server and `members` is empty.
    pub listed: bool,
    /// What a listed endpoint serves, by model name.
    pub members: BTreeMap<String, MemberKind>,
}

/// Why an answering endpoint was not trusted to remove.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeptReason {
    /// The endpoint's first answer.
    FirstAnswer,
    /// The server's first sync (add-only until one succeeds).
    ServerFirstSync,
    /// The answer was empty, or under half of what the endpoint served.
    ShortAnswer,
}

impl KeptReason {
    pub fn as_str(self) -> &'static str {
        match self {
            KeptReason::FirstAnswer => "first_answer",
            KeptReason::ServerFirstSync => "server_first_sync",
            KeptReason::ShortAnswer => "short_answer",
        }
    }
}

/// What the sync decided for one endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EndpointPlan {
    /// Did not answer: nothing about it changes.
    Unchanged,
    /// Answered. `members` is what it serves from now on; `kept` says why the
    /// models its answer omitted were kept rather than removed (`None` = they
    /// were removed).
    Answered {
        members: BTreeMap<String, MemberKind>,
        kept: Option<KeptReason>,
    },
}

/// The outcome of fusing the answers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FusionPlan {
    /// Models no current row names, in name order.
    pub new_models: Vec<String>,
    /// Current models to retire, in name order.
    pub retire: Vec<String>,
    /// One entry per input endpoint, in input order.
    pub endpoints: Vec<EndpointPlan>,
}

/// The server-level plausibility gate refused the sync: every endpoint
/// answered, and together they named fewer than half the current models.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Implausible {
    pub discovered: usize,
    pub existing: usize,
}

/// The fewest names an answer may carry before it is too short to trust
/// against `count` current ones: empty is always too short, and so is fewer
/// than half.
pub fn plausibility_floor(count: usize) -> usize {
    std::cmp::max(1, count / 2)
}

/// What an endpoint's answer is judged against: the models it LISTED — its own
/// evidence. Its assumed rows are not: a replica serving 2 of a server's 6
/// models keeps the other 4 assumed after its first answer, and judged
/// against 6 every later answer of 2 would be "short" and never remove them.
/// An endpoint with NO listed row has no evidence of its own, so it is judged
/// against everything it serves: an operator's sync reads a never-answered
/// endpoint as serving every model, and one answering 3 of 20 must not be
/// trusted to remove the other 17.
pub fn listed_count(ep: &EndpointState) -> usize {
    match ep.members.values().filter(|k| **k == MemberKind::Listed).count() {
        0 => ep.members.len(),
        n => n,
    }
}

/// What discovery got from one endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Answer {
    /// It answered with this list.
    Listed(BTreeSet<String>),
    /// It was asked and did not answer.
    Failed,
    /// It was not asked (a disabled endpoint). It changes nothing, and still
    /// counts for what it serves — disabling an endpoint takes it out of
    /// traffic, not out of the models it serves.
    NotAsked,
}

impl Answer {
    fn listed(&self) -> Option<&BTreeSet<String>> {
        match self {
            Answer::Listed(l) => Some(l),
            _ => None,
        }
    }
}

/// Fuse the endpoints' answers.
///
/// `existing` is every current model name of the server; `answers[i]` is what
/// `endpoints[i]` gave. `server_first_sync` makes every answer add-only.
/// `gate` asks for the server-level plausibility gate, which fires only when
/// EVERY endpoint answered — a disabled one included: with one endpoint that
/// is the gate a single-URL server has always had, and a partial answer is
/// already held by the per-endpoint rule.
pub fn fuse(
    existing: &BTreeSet<String>,
    endpoints: &[EndpointState],
    answers: &[Answer],
    server_first_sync: bool,
    gate: bool,
) -> Result<FusionPlan, Implausible> {
    assert_eq!(endpoints.len(), answers.len(), "one answer slot per endpoint");

    let answered_union: BTreeSet<&String> = answers.iter().filter_map(Answer::listed).flatten().collect();
    // Every endpoint, asked or not: a disabled replica still serves models its
    // siblings may not list, so with one out the others' union is no measure
    // of the whole server — the per-endpoint rule guards each answer instead.
    let every_endpoint_answered = !answers.is_empty() && answers.iter().all(|a| matches!(a, Answer::Listed(_)));
    if gate && every_endpoint_answered {
        let floor = plausibility_floor(existing.len());
        if answered_union.len() < floor {
            return Err(Implausible { discovered: answered_union.len(), existing: existing.len() });
        }
    }

    let new_models: Vec<String> = answered_union
        .iter()
        .filter(|n| !existing.contains(n.as_str()))
        .map(|n| (*n).clone())
        .collect();

    // Why each answering endpoint may not remove what its answer omits.
    let kept_of: Vec<Option<KeptReason>> = endpoints
        .iter()
        .zip(answers)
        .map(|(ep, answer)| {
            let listed = answer.listed()?;
            if !ep.listed {
                Some(KeptReason::FirstAnswer)
            } else if server_first_sync {
                Some(KeptReason::ServerFirstSync)
            } else if listed.len() < plausibility_floor(listed_count(ep)) {
                Some(KeptReason::ShortAnswer)
            } else {
                None
            }
        })
        .collect();
    // What each ENABLED endpoint lists once this sync is applied: its answer,
    // plus what it listed before where its answer is untrusted or missing
    // (both keep a listed model listed). The retirement below never retires
    // such a model.
    let lists_after: Vec<BTreeSet<&String>> = endpoints
        .iter()
        .zip(answers)
        .zip(&kept_of)
        .map(|((ep, answer), kept)| {
            let before = ep.members.iter().filter(|(_, k)| **k == MemberKind::Listed).map(|(n, _)| n);
            match answer {
                Answer::NotAsked => BTreeSet::new(),
                Answer::Failed => before.collect(),
                Answer::Listed(l) if kept.is_some() => l.iter().chain(before).collect(),
                Answer::Listed(l) => l.iter().collect(),
            }
        })
        .collect();

    let mut plans = Vec::with_capacity(endpoints.len());
    // Whether each endpoint may remove what its answer omits.
    let mut removes = Vec::with_capacity(endpoints.len());
    for (i, (ep, answer)) in endpoints.iter().zip(answers).enumerate() {
        let Some(listed) = answer.listed() else {
            plans.push(EndpointPlan::Unchanged);
            removes.push(false);
            continue;
        };
        let kept = kept_of[i];
        let mut members: BTreeMap<String, MemberKind> =
            listed.iter().map(|n| (n.clone(), MemberKind::Listed)).collect();
        if kept.is_some() {
            // What the endpoint served before and its answer omitted stays —
            // AS IT WAS: a model it listed stays listed, so the evidence an
            // untrusted answer is judged against survives the answer (a short
            // answer repeated stays short). An endpoint that never answered
            // served every current model, by assumption. An ASSUMED model
            // another enabled endpoint lists goes: this endpoint says it does
            // not serve it, and the model is not stranded.
            let listed_elsewhere =
                |name: &String| lists_after.iter().enumerate().any(|(j, l)| j != i && l.contains(name));
            if ep.listed {
                for (name, kind) in &ep.members {
                    if *kind == MemberKind::Assumed && listed_elsewhere(name) {
                        continue;
                    }
                    members.entry(name.clone()).or_insert(*kind);
                }
            } else {
                for name in existing {
                    if listed_elsewhere(name) {
                        continue;
                    }
                    members.entry(name.clone()).or_insert(MemberKind::Assumed);
                }
            }
        }
        removes.push(kept.is_none());
        plans.push(EndpointPlan::Answered { members, kept });
    }

    // A model retires when the endpoints that listed-and-served it before all
    // answered, with the right to remove, without it. `quorum_seen` guards the
    // empty quorum: a model no answered-before endpoint serves is never retired
    // here (it is served by assumption, or by an endpoint that did not answer).
    let mut retire = Vec::new();
    for name in existing {
        let mut quorum_seen = false;
        let mut all_removed = true;
        for (i, ep) in endpoints.iter().enumerate() {
            if !ep.listed || !ep.members.contains_key(name) {
                continue;
            }
            quorum_seen = true;
            let omitted = answers[i].listed().is_some_and(|l| !l.contains(name));
            if !(removes[i] && omitted) {
                all_removed = false;
                break;
            }
        }
        if quorum_seen && all_removed && !answered_union.contains(name) {
            retire.push(name.clone());
        }
    }

    // With an endpoint silent (failed, or disabled) the server-level gate
    // cannot judge the union, so this does: no sync takes the server below half
    // its models on a partial answer — the promise the single-URL gate made. A
    // silent replica may be the one serving what the others do not list.
    if gate && !every_endpoint_answered && !retire.is_empty()
        && existing.len() - retire.len() < plausibility_floor(existing.len())
    {
        return Err(Implausible { discovered: answered_union.len(), existing: existing.len() });
    }

    // A retired model is served by no endpoint: an untrusted answer that kept
    // it as assumed must not hold it.
    if !retire.is_empty() {
        for plan in &mut plans {
            if let EndpointPlan::Answered { members, .. } = plan {
                for name in &retire {
                    members.remove(name);
                }
            }
        }
    }

    Ok(FusionPlan { new_models, retire, endpoints: plans })
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    /// The models an endpoint serves, given its row state: every current model
    /// when it has never answered, else its member rows.
    fn serves<'a>(ep: &'a EndpointState, existing: &'a BTreeSet<String>) -> Box<dyn Iterator<Item = &'a String> + 'a> {
        if ep.listed { Box::new(ep.members.keys()) } else { Box::new(existing.iter()) }
    }

    fn set(names: &[&str]) -> BTreeSet<String> {
        names.iter().map(|s| s.to_string()).collect()
    }

    fn listed(_id: u128, names: &[(&str, MemberKind)]) -> EndpointState {
        EndpointState {
            listed: true,
            members: names.iter().map(|(n, k)| (n.to_string(), *k)).collect(),
        }
    }

    fn fresh(_id: u128) -> EndpointState {
        EndpointState { listed: false, members: BTreeMap::new() }
    }

    /// The endpoints as the plan leaves them (what the apply step writes).
    fn apply(eps: &[EndpointState], plan: &FusionPlan) -> Vec<EndpointState> {
        eps.iter()
            .zip(&plan.endpoints)
            .map(|(e, p)| match p {
                EndpointPlan::Unchanged => e.clone(),
                EndpointPlan::Answered { members, .. } => EndpointState { listed: true, members: members.clone() },
            })
            .collect()
    }

    fn members_of(plan: &EndpointPlan) -> &BTreeMap<String, MemberKind> {
        match plan {
            EndpointPlan::Answered { members, .. } => members,
            EndpointPlan::Unchanged => panic!("endpoint did not answer"),
        }
    }

    use MemberKind::{Assumed, Listed};
    use Answer::{Failed, NotAsked};

    /// The kinds are the membership table's CHECK vocabulary and the reasons
    /// are what the API reports; a changed spelling fails a write or a client.
    #[test]
    fn the_stored_names_are_the_schemas_and_the_apis() {
        assert_eq!(Listed.as_str(), "listed");
        assert_eq!(Assumed.as_str(), "assumed");
        assert_eq!(KeptReason::FirstAnswer.as_str(), "first_answer");
        assert_eq!(KeptReason::ServerFirstSync.as_str(), "server_first_sync");
        assert_eq!(KeptReason::ShortAnswer.as_str(), "short_answer");
    }

    #[test]
    fn a_single_endpoint_reconciles_exactly_as_a_single_url_server_did() {
        let existing = set(&["a", "b", "c"]);
        let ep = listed(1, &[("a", Listed), ("b", Listed), ("c", Listed)]);
        let plan = fuse(&existing, &[ep], &[Answer::Listed(set(&["a", "b", "d"]))], false, true).unwrap();
        assert_eq!(plan.new_models, vec!["d".to_string()]);
        assert_eq!(plan.retire, vec!["c".to_string()]);
        assert_eq!(members_of(&plan.endpoints[0]).keys().cloned().collect::<Vec<_>>(), vec!["a", "b", "d"]);
    }

    #[test]
    fn the_server_gate_fires_only_when_every_endpoint_answered() {
        let existing = set(&["a", "b", "c", "d"]);
        let eps = [
            listed(1, &[("a", Listed), ("b", Listed), ("c", Listed), ("d", Listed)]),
            listed(2, &[("a", Listed), ("b", Listed), ("c", Listed), ("d", Listed)]),
        ];
        // Both answered one name: 1 < floor(4) = 2 → refused.
        let both = fuse(&existing, &eps, &[Answer::Listed(set(&["a"])), Answer::Listed(set(&["a"]))], false, true);
        assert_eq!(both, Err(Implausible { discovered: 1, existing: 4 }));
        // Two names reach the floor: accepted (positive control at the boundary).
        let at_floor = fuse(&existing, &eps, &[Answer::Listed(set(&["a", "b"])), Answer::Listed(set(&["a", "b"]))], false, true);
        assert!(at_floor.is_ok());
        // One did not answer: no server gate; the answering endpoint's own gate
        // keeps what it served, and nothing retires.
        let partial = fuse(&existing, &eps, &[Answer::Listed(set(&["a"])), Failed], false, true).unwrap();
        assert!(partial.retire.is_empty());
        assert_eq!(partial.endpoints[1], EndpointPlan::Unchanged);
    }

    #[test]
    fn the_per_endpoint_floor_holds_on_both_sides() {
        let existing = set(&["a", "b", "c", "d"]);
        let ep = listed(1, &[("a", Listed), ("b", Listed), ("c", Listed), ("d", Listed)]);
        // 1 < floor(4) = 2: omitted models are kept.
        let short = fuse(&existing, std::slice::from_ref(&ep), &[Answer::Listed(set(&["a"]))], false, false).unwrap();
        assert!(matches!(&short.endpoints[0], EndpointPlan::Answered { kept: Some(KeptReason::ShortAnswer), .. }));
        assert!(short.retire.is_empty());
        // 2 = floor: trusted, omitted models removed.
        let enough = fuse(&existing, &[ep], &[Answer::Listed(set(&["a", "b"]))], false, false).unwrap();
        assert!(matches!(&enough.endpoints[0], EndpointPlan::Answered { kept: None, .. }));
        assert_eq!(enough.retire, vec!["c".to_string(), "d".to_string()]);
    }

    #[test]
    fn a_first_answer_adds_and_keeps_everything_else_assumed() {
        let existing = set(&["a", "b"]);
        let plan = fuse(&existing, &[fresh(1)], &[Answer::Listed(set(&["a", "lora"]))], false, true).unwrap();
        assert_eq!(plan.new_models, vec!["lora".to_string()]);
        assert!(plan.retire.is_empty());
        let m = members_of(&plan.endpoints[0]);
        assert_eq!(m.get("a"), Some(&Listed));
        assert_eq!(m.get("lora"), Some(&Listed));
        assert_eq!(m.get("b"), Some(&Assumed));
    }

    /// A replica added to a server answers for the first time with 3 of its 20
    /// models: it serves those 3, because another replica lists the other 17.
    #[test]
    fn a_new_replica_drops_what_another_replica_lists() {
        let names: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        let existing: BTreeSet<String> = names.iter().cloned().chain(["hand".to_string()]).collect();
        let mut a_members: BTreeMap<String, MemberKind> = names.iter().map(|n| (n.clone(), Listed)).collect();
        a_members.insert("hand".to_string(), Assumed);
        let a = EndpointState { listed: true, members: a_members };
        let three: BTreeSet<String> = names[..3].iter().cloned().collect();
        let answers = [Answer::Listed(names.iter().cloned().collect()), Answer::Listed(three.clone())];
        // (A's trusted answer omits "hand", which retires.)
        let plan = fuse(&existing, &[a.clone(), fresh(2)], &answers, false, true).unwrap();
        assert_eq!(plan.retire, vec!["hand".to_string()]);
        assert_eq!(members_of(&plan.endpoints[1]).keys().cloned().collect::<BTreeSet<_>>(), three);
        // The same with "Sync now" reading B as serving everything by assumption.
        let stand_in = EndpointState { listed: true, members: existing.iter().map(|n| (n.clone(), Assumed)).collect() };
        // B's short answer keeps "hand" (no one lists it), and holds it alive.
        let plan = fuse(&existing, &[a.clone(), stand_in], &answers, false, true).unwrap();
        let b = members_of(&plan.endpoints[1]);
        assert!(plan.retire.is_empty());
        assert_eq!(b.len(), 4);
        assert_eq!(b.get("hand"), Some(&Assumed));
        // A replica that lists them but is disabled takes no traffic: B keeps
        // them, or they would be served by no enabled endpoint.
        let plan = fuse(&existing, &[a.clone(), fresh(2)], &[NotAsked, Answer::Listed(three.clone())], false, true).unwrap();
        assert_eq!(members_of(&plan.endpoints[1]).len(), 21);
        // A replica that lists them and failed to answer still lists them. A
        // model it is only ASSUMED to serve stays assumed on B: nobody lists it.
        let plan = fuse(&existing, &[a, fresh(2)], &[Failed, Answer::Listed(three)], false, true).unwrap();
        let b = members_of(&plan.endpoints[1]);
        assert_eq!(b.len(), 4);
        assert_eq!(b.get("hand"), Some(&Assumed));
    }

    #[test]
    fn a_model_on_two_replicas_outlives_one_of_them_dropping_it() {
        let existing = set(&["x", "y"]);
        let eps = [listed(1, &[("x", Listed)]), listed(2, &[("x", Listed), ("y", Listed)])];
        // Endpoint 1 no longer lists x; endpoint 2 still does.
        let plan = fuse(&existing, &eps, &[Answer::Listed(set(&["y"])), Answer::Listed(set(&["x", "y"]))], false, true).unwrap();
        assert!(plan.retire.is_empty());
        assert!(!members_of(&plan.endpoints[0]).contains_key("x"));
        assert!(members_of(&plan.endpoints[1]).contains_key("x"));
    }

    #[test]
    fn a_never_answering_endpoint_neither_keeps_nor_retires_a_model() {
        let existing = set(&["x", "y"]);
        let eps = [listed(1, &[("x", Listed), ("y", Listed)]), fresh(2)];
        let plan = fuse(&existing, &eps, &[Answer::Listed(set(&["y"])), Failed], false, true).unwrap();
        assert_eq!(plan.retire, vec!["x".to_string()]);
    }

    /// Judged against what it listed, a replica that serves a small part of
    /// the server drops the models it was only assumed to serve.
    #[test]
    fn a_small_replica_drops_what_it_was_only_assumed_to_serve() {
        // Two listed, six assumed: judged against the six, an answer of two
        // would be short (under half) and remove nothing.
        let existing = set(&["a", "b", "c", "d", "e", "f", "g", "h"]);
        let small = listed(
            1,
            &[("a", Listed), ("b", Listed), ("c", Assumed), ("d", Assumed), ("e", Assumed), ("f", Assumed), ("g", Assumed), ("h", Assumed)],
        );
        let plan = fuse(&existing, &[small], &[Answer::Listed(set(&["a", "b"]))], false, false).unwrap();
        assert!(matches!(&plan.endpoints[0], EndpointPlan::Answered { kept: None, .. }));
        assert_eq!(members_of(&plan.endpoints[0]).keys().cloned().collect::<Vec<_>>(), vec!["a", "b"]);
        // Its own evidence still guards it: a listed set that halves is short.
        let big = listed(1, &[("a", Listed), ("b", Listed), ("c", Listed), ("d", Listed)]);
        let plan = fuse(&existing, &[big], &[Answer::Listed(set(&["a"]))], false, false).unwrap();
        assert!(matches!(&plan.endpoints[0], EndpointPlan::Answered { kept: Some(KeptReason::ShortAnswer), .. }));
    }

    /// An operator's sync reads a never-answered endpoint as serving every
    /// model (all assumed). Its answer is judged against all of them: 3 of 20
    /// is short, and removes nothing.
    #[test]
    fn a_first_answer_with_no_evidence_of_its_own_is_judged_against_everything() {
        let names: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        let existing: BTreeSet<String> = names.iter().cloned().collect();
        let stand_in = EndpointState {
            listed: true,
            members: names.iter().map(|n| (n.clone(), Assumed)).collect(),
        };
        let answer: BTreeSet<String> = names[..3].iter().cloned().collect();
        let plan = fuse(&existing, &[stand_in, fresh(2)], &[Answer::Listed(answer), Failed], false, true).unwrap();
        assert!(plan.retire.is_empty(), "retired {:?} on a short first answer", plan.retire);
    }

    /// A never-answered primary is down and a sibling lists 3 of 20 models:
    /// no number of "Sync now" clicks retires the other 17 on its word.
    #[test]
    fn a_partial_answer_never_takes_the_server_below_half() {
        let names: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        let existing: BTreeSet<String> = names.iter().cloned().collect();
        let stand_in = |members: BTreeMap<String, MemberKind>| EndpointState { listed: true, members };
        let mut eps = vec![fresh(1), stand_in(names.iter().map(|n| (n.clone(), Assumed)).collect())];
        let three: BTreeSet<String> = names[..3].iter().cloned().collect();
        let answers = [Failed, Answer::Listed(three)];
        for sync in 0..3 {
            // A refusal (`Err`) writes nothing either.
            if let Ok(plan) = fuse(&existing, &eps, &answers, false, true) {
                assert!(plan.retire.is_empty(), "sync {sync} retired {:?}", plan.retire);
                eps = apply(&eps, &plan);
            }
        }
    }

    /// The other side of that floor: a partial answer may take the server
    /// down to exactly half.
    #[test]
    fn a_partial_answer_may_retire_down_to_half() {
        let names: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        let existing: BTreeSet<String> = names.iter().cloned().collect();
        let a = EndpointState { listed: true, members: names.iter().map(|n| (n.clone(), Listed)).collect() };
        let half: BTreeSet<String> = names[..10].iter().cloned().collect();
        let plan = fuse(&existing, &[a, fresh(2)], &[Answer::Listed(half), Failed], false, true).unwrap();
        assert_eq!(plan.retire.len(), 10);
    }

    #[test]
    fn a_retired_model_is_held_by_no_endpoint() {
        let existing = set(&["m1", "m2"]);
        let eps = [listed(1, &[("m1", Listed), ("m2", Listed)]), fresh(2)];
        // A drops m2 (trusted); B answers for the first time with m1 only.
        let plan = fuse(&existing, &eps, &[Answer::Listed(set(&["m1"])), Answer::Listed(set(&["m1"]))], false, false).unwrap();
        assert_eq!(plan.retire, vec!["m2".to_string()]);
        assert!(!members_of(&plan.endpoints[1]).contains_key("m2"));
    }

    #[test]
    fn a_disabled_endpoint_keeps_the_models_it_serves() {
        let existing = set(&["x", "y"]);
        let eps = [listed(1, &[("x", Listed), ("y", Listed)]), listed(2, &[("x", Listed), ("y", Listed)])];
        // Endpoint 2 is disabled for maintenance; endpoint 1 no longer lists x.
        let plan = fuse(&existing, &eps, &[Answer::Listed(set(&["y"])), NotAsked], false, true).unwrap();
        assert!(plan.retire.is_empty(), "a model the disabled replica serves was retired");
        assert_eq!(plan.endpoints[1], EndpointPlan::Unchanged);
    }

    /// A short answer keeps what the endpoint listed as listed, so the same
    /// short answer next sync is still short — not trusted on the second try.
    #[test]
    fn a_short_answer_repeated_stays_short() {
        let a_names: Vec<String> = (1..=10).map(|i| format!("m{i}")).collect();
        let b_names: Vec<String> = (11..=20).map(|i| format!("m{i}")).collect();
        let existing: BTreeSet<String> = a_names.iter().chain(&b_names).cloned().collect();
        let mut eps = vec![
            EndpointState { listed: true, members: a_names.iter().map(|n| (n.clone(), Listed)).collect() },
            EndpointState { listed: true, members: b_names.iter().map(|n| (n.clone(), Listed)).collect() },
        ];
        let answers = [Answer::Listed(set(&["m1", "m2"])), Answer::Listed(b_names.iter().cloned().collect())];
        for sync in 0..2 {
            let plan = fuse(&existing, &eps, &answers, false, true).unwrap();
            assert!(plan.retire.is_empty(), "sync {sync} retired {:?}", plan.retire);
            assert!(matches!(&plan.endpoints[0], EndpointPlan::Answered { kept: Some(KeptReason::ShortAnswer), .. }));
            eps = apply(&eps, &plan);
        }
    }

    #[test]
    fn a_disabled_endpoint_keeps_the_server_gate_off() {
        // A serves three models, B (disabled) the seventeen others: A's full
        // answer is not an implausible answer for the whole server.
        let names: Vec<String> = (0..20).map(|i| format!("m{i}")).collect();
        let existing: BTreeSet<String> = names.iter().cloned().collect();
        let a = EndpointState { listed: true, members: names[..3].iter().map(|n| (n.clone(), Listed)).collect() };
        let b = EndpointState { listed: true, members: names[3..].iter().map(|n| (n.clone(), Listed)).collect() };
        let answer: BTreeSet<String> = names[..3].iter().cloned().collect();
        let plan = fuse(&existing, &[a, b], &[Answer::Listed(answer), NotAsked], false, true).unwrap();
        assert!(plan.retire.is_empty());
        // Positive control: with B answering too, a short union IS gated.
        let a = EndpointState { listed: true, members: names[..3].iter().map(|n| (n.clone(), Listed)).collect() };
        let b = EndpointState { listed: true, members: names[3..].iter().map(|n| (n.clone(), Listed)).collect() };
        let gated = fuse(&existing, &[a, b], &[Answer::Listed(set(&["m0"])), Answer::Listed(set(&["m3"]))], false, true);
        assert_eq!(gated, Err(Implausible { discovered: 2, existing: 20 }));
    }

    #[test]
    fn a_model_served_only_by_assumption_is_never_retired() {
        let existing = set(&["hand-made"]);
        let plan = fuse(&existing, &[fresh(1), fresh(2)], &[Failed, Failed], false, true).unwrap();
        assert!(plan.retire.is_empty());
    }

    #[test]
    fn server_first_sync_is_add_only() {
        let existing = set(&["a", "b"]);
        let ep = listed(1, &[("a", Listed), ("b", Listed)]);
        let plan = fuse(&existing, &[ep], &[Answer::Listed(set(&["a", "c"]))], true, true).unwrap();
        assert!(plan.retire.is_empty());
        assert_eq!(plan.new_models, vec!["c".to_string()]);
        assert!(matches!(&plan.endpoints[0], EndpointPlan::Answered { kept: Some(KeptReason::ServerFirstSync), .. }));
    }

    // ---- properties ---------------------------------------------------------

    const NAMES: &[&str] = &["a", "b", "c", "d", "e", "f"];

    fn name_set() -> impl Strategy<Value = BTreeSet<String>> {
        proptest::sample::subsequence(NAMES, 0..=NAMES.len())
            .prop_map(|v| v.into_iter().map(str::to_string).collect())
    }

    fn endpoint() -> impl Strategy<Value = EndpointState> {
        (any::<bool>(), name_set(), proptest::collection::vec(any::<bool>(), NAMES.len())).prop_map(
            move |(listed, names, kinds)| EndpointState {
                listed,
                members: if listed {
                    names
                        .into_iter()
                        .enumerate()
                        .map(|(i, n)| (n, if kinds[i % kinds.len()] { Listed } else { Assumed }))
                        .collect()
                } else {
                    BTreeMap::new()
                },
            },
        )
    }

    /// (current models, endpoints, their answers, server first sync).
    type Scenario = (BTreeSet<String>, Vec<EndpointState>, Vec<Answer>, bool);

    fn scenario() -> impl Strategy<Value = Scenario> {
        (1usize..=4).prop_flat_map(|n| {
            (
                name_set(),
                (0..n).map(|_| endpoint()).collect::<Vec<_>>(),
                proptest::collection::vec(
                    prop_oneof![name_set().prop_map(Answer::Listed), Just(Failed), Just(NotAsked)],
                    n,
                ),
                any::<bool>(),
            )
        })
        .prop_map(|(mut existing, eps, answers, first)| {
            // A member row always names a current model.
            for ep in &eps {
                existing.extend(ep.members.keys().cloned());
            }
            (existing, eps, answers, first)
        })
    }

    proptest! {
        #[test]
        fn an_endpoint_that_did_not_answer_changes_nothing((existing, eps, answers, first) in scenario()) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            for (i, a) in answers.iter().enumerate() {
                if a.listed().is_none() {
                    prop_assert_eq!(&plan.endpoints[i], &EndpointPlan::Unchanged);
                }
            }
        }

        #[test]
        fn every_answered_name_is_listed_on_its_endpoint_and_known_to_the_server(
            (existing, eps, answers, first) in scenario()
        ) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            for (i, a) in answers.iter().enumerate() {
                let Some(a) = a.listed() else { continue };
                let m = members_of(&plan.endpoints[i]);
                for n in a {
                    prop_assert_eq!(m.get(n), Some(&Listed));
                    prop_assert!(existing.contains(n) || plan.new_models.contains(n));
                    prop_assert!(!plan.retire.contains(n));
                }
            }
        }

        #[test]
        fn a_model_retires_only_on_the_word_of_every_endpoint_that_listed_it(
            (existing, eps, answers, first) in scenario()
        ) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            for name in &plan.retire {
                prop_assert!(!first, "a first sync never retires");
                let quorum: Vec<usize> = eps.iter().enumerate()
                    .filter(|(_, e)| e.listed && e.members.contains_key(name))
                    .map(|(i, _)| i).collect();
                prop_assert!(!quorum.is_empty());
                for i in quorum {
                    let a = answers[i].listed();
                    prop_assert!(a.is_some(), "a quorum member that did not answer retired {}", name);
                    let a = a.unwrap();
                    prop_assert!(!a.contains(name));
                    prop_assert!(a.len() >= plausibility_floor(listed_count(&eps[i])));
                }
            }
        }

        #[test]
        fn no_model_is_stranded((existing, eps, answers, first) in scenario()) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            for name in &existing {
                let served_before = eps.iter().any(|e| serves(e, &existing).any(|n| n == name));
                if !served_before || plan.retire.contains(name) {
                    continue;
                }
                let served_after = eps.iter().zip(&plan.endpoints).any(|(e, p)| match p {
                    EndpointPlan::Unchanged => serves(e, &existing).any(|n| n == name),
                    EndpointPlan::Answered { members, .. } => members.contains_key(name),
                });
                prop_assert!(served_after, "{} lost every endpoint without being retired", name);
            }
        }

        /// Two syncs with the same answers: an answer too short to trust
        /// against the endpoint's own listed evidence is still too short in
        /// the second.
        #[test]
        fn a_short_answer_is_short_on_every_repeat((existing, eps, answers, first) in scenario()) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            let next = apply(&eps, &plan);
            let again = fuse(&existing, &next, &answers, first, false).unwrap();
            for (i, p) in plan.endpoints.iter().enumerate() {
                // Judged against listed evidence of its own (an endpoint with
                // none is judged against everything it serves, and its first
                // short answer BECOMES its evidence — a repeat of that is not
                // the claim).
                let had_evidence = eps[i].listed && eps[i].members.values().any(|k| *k == Listed);
                if had_evidence && matches!(p, EndpointPlan::Answered { kept: Some(KeptReason::ShortAnswer), .. }) {
                    prop_assert!(
                        matches!(&again.endpoints[i], EndpointPlan::Answered { kept: Some(KeptReason::ShortAnswer), .. }),
                        "endpoint {} was trusted on the repeat of a short answer", i
                    );
                }
            }
        }

        #[test]
        fn no_endpoint_holds_a_retired_model((existing, eps, answers, first) in scenario()) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            for p in &plan.endpoints {
                if let EndpointPlan::Answered { members, .. } = p {
                    for name in &plan.retire {
                        prop_assert!(!members.contains_key(name));
                    }
                }
            }
        }

        #[test]
        fn an_untrusted_answer_removes_nothing((existing, eps, answers, first) in scenario()) {
            let plan = fuse(&existing, &eps, &answers, first, false).unwrap();
            let after = apply(&eps, &plan);
            for (i, p) in plan.endpoints.iter().enumerate() {
                if let EndpointPlan::Answered { members, kept: Some(_) } = p {
                    // Except a model the sync retires on the other endpoints' word.
                    for name in serves(&eps[i], &existing).filter(|n| !plan.retire.contains(n)) {
                        if members.contains_key(name) {
                            continue;
                        }
                        // ...and an assumed one another enabled endpoint lists.
                        let was_assumed = !eps[i].listed || eps[i].members.get(name) == Some(&Assumed);
                        let listed_elsewhere = after.iter().zip(&answers).enumerate().any(|(j, (e, a))| {
                            j != i && !matches!(a, NotAsked) && e.members.get(name) == Some(&Listed)
                        });
                        prop_assert!(was_assumed && listed_elsewhere, "an untrusted answer removed {}", name);
                    }
                }
            }
        }
    }
}
