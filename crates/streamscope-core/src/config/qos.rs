//! QoS classes as the proxy reads them: the tenant's bands, which band each
//! workspace runs in, and the share of a saturated pool a workspace gets.
//!
//! The class of a request is decided entirely server-side — key, else workspace,
//! else the tenant's default — and nothing in the request influences it. A key
//! may only name a class its holder was entitled to when the key was written,
//! which is what `elevated` records: without it a key is clamped to its
//! workspace's class at every request, so demoting a workspace cannot be escaped
//! by a key minted while it was higher.
//!
//! A suppressed or deleted class never reaches this table, so a key or workspace
//! still pointing at one resolves as if it named nothing.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// How an upstream engine expresses a class, if it can.
///
/// An explicit opt-in per server, because it must match how the engine was
/// started: vLLM documents a non-zero `priority` as an error on a server that
/// does not run `--scheduling-policy priority`.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SchedulingDialect {
    /// The class is not sent upstream at all — dispatch order is the gateway's
    /// alone. Every server starts here.
    #[default]
    None,
    /// vLLM's `priority`, lowest served first, which is what a class `rank`
    /// already is.
    VllmPriority,
}

impl SchedulingDialect {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::None => "none",
            Self::VllmPriority => "vllm_priority",
        }
    }

    /// Parse a stored dialect. An unknown value — a newer admin's — is read as
    /// `None`: not expressing a class costs order, expressing it in a dialect
    /// this build does not know could have the engine refuse the request.
    pub fn parse(value: &str) -> Self {
        match value {
            "vllm_priority" => Self::VllmPriority,
            _ => Self::None,
        }
    }
}

/// Reading a stored dialect never fails — an unknown value is `None` — so this
/// is a `From`, and the blanket impl gives sqlx the `TryFrom` its
/// `#[sqlx(try_from = "String")]` asks for.
impl From<String> for SchedulingDialect {
    fn from(value: String) -> Self {
        Self::parse(&value)
    }
}

/// One priority band.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct QosClass {
    pub id: Uuid,
    pub name: String,
    /// Lower is more important. Abstract: the target server's scheduling
    /// dialect decides whether and how it is expressed upstream.
    pub rank: i32,
    /// Refused at once when no endpoint has headroom, instead of being held.
    #[serde(default)]
    pub sheddable: bool,
    /// How long a request of this class may be held. `None` = the deployment's
    /// default hold. Clamped to the operator maximum where it is applied.
    #[serde(default)]
    pub queue_ttl_ms: Option<u32>,
}

/// A tenant's classes and the per-workspace choices that select them.
///
/// Every field defaults: an empty table means no request has a class and the
/// dispatch gate stays off.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct QosTable {
    /// Every live class of the tenant, by id.
    #[serde(default)]
    pub classes: HashMap<Uuid, QosClass>,
    /// The tenant's default class — what a workspace with no class of its own
    /// runs as.
    #[serde(default)]
    pub default_class: Option<Uuid>,
    /// A workspace's own class, where it has one.
    #[serde(default)]
    pub workspace_class: HashMap<Uuid, Uuid>,
    /// A workspace's share of a saturated pool (≥ 1). Absent = 1.
    #[serde(default)]
    pub workspace_weight: HashMap<Uuid, u32>,
    /// The classes a route target accepts. A route absent here accepts every
    /// class, so the common unrestricted fleet ships no entry at all.
    #[serde(default)]
    pub route_classes: HashMap<Uuid, Vec<Uuid>>,
}

impl QosTable {
    /// The class a workspace's traffic runs as when nothing narrower applies.
    pub fn workspace_class(&self, workspace_id: Uuid) -> Option<&QosClass> {
        self.workspace_class
            .get(&workspace_id)
            .and_then(|id| self.classes.get(id))
            .or_else(|| self.default_class.and_then(|id| self.classes.get(&id)))
    }

    /// The class a request runs as.
    ///
    /// A key's own class wins only when it is at most as important as its
    /// workspace's, or when an admin elevated it deliberately. Everything else
    /// falls back to the workspace, then the tenant default.
    pub fn effective_class(
        &self,
        workspace_id: Uuid,
        key_class: Option<Uuid>,
        elevated: bool,
    ) -> Option<&QosClass> {
        let workspace = self.workspace_class(workspace_id);
        let Some(key_class) = key_class.and_then(|id| self.classes.get(&id)) else {
            return workspace;
        };
        match workspace {
            Some(ws) if !elevated && key_class.rank < ws.rank => Some(ws),
            _ => Some(key_class),
        }
    }

    /// The workspace's share of a saturated pool.
    pub fn weight(&self, workspace_id: Uuid) -> u32 {
        self.workspace_weight.get(&workspace_id).copied().unwrap_or(1).max(1)
    }

    /// Whether a route target may serve this class. A target that names no
    /// class accepts all of them.
    pub fn route_accepts(&self, route_id: Uuid, class_id: Uuid) -> bool {
        match self.route_classes.get(&route_id) {
            Some(allowed) => allowed.contains(&class_id),
            None => true,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn class(rank: i32, name: &str) -> QosClass {
        QosClass {
            id: Uuid::new_v4(),
            name: name.to_string(),
            rank,
            sheddable: false,
            queue_ttl_ms: None,
        }
    }

    /// interactive (0) / standard (10) / background (20), standard the default.
    fn table() -> (QosTable, Uuid, Uuid, Uuid) {
        let (interactive, standard, background) =
            (class(0, "Interactive"), class(10, "Standard"), class(20, "Background"));
        let (i, s, b) = (interactive.id, standard.id, background.id);
        let mut t = QosTable { default_class: Some(s), ..Default::default() };
        for c in [interactive, standard, background] {
            t.classes.insert(c.id, c);
        }
        (t, i, s, b)
    }

    #[test]
    fn a_dialect_survives_the_round_trip_through_what_is_stored() {
        // The string IS the stored value and the wire value: the column's CHECK
        // names it, the server API echoes it, and the proxy reads it back. A
        // spelling that drifts on either side turns the dialect off silently.
        for dialect in [SchedulingDialect::None, SchedulingDialect::VllmPriority] {
            assert_eq!(SchedulingDialect::parse(dialect.as_str()), dialect);
        }
        assert_eq!(SchedulingDialect::VllmPriority.as_str(), "vllm_priority");
        assert_eq!(SchedulingDialect::None.as_str(), "none");
        assert_eq!(
            SchedulingDialect::from("vllm_priority".to_string()),
            SchedulingDialect::VllmPriority
        );
        // A value this build does not know expresses nothing rather than
        // guessing — an engine may refuse a dialect it never agreed to.
        assert_eq!(SchedulingDialect::parse("sglang_priority"), SchedulingDialect::None);
    }

    #[test]
    fn a_key_naming_another_class_of_the_same_rank_keeps_it() {
        // "More important" is strictly lower rank. Two classes may share one —
        // an admin can rank a new class alongside an existing one — and a key
        // naming the sibling is not asking for a promotion, so it is not an
        // elevation and must not be clamped away.
        let (mut t, _, s, _) = table();
        let sibling = class(10, "Standard, but for the batch team");
        let sibling_id = sibling.id;
        t.classes.insert(sibling_id, sibling);
        let ws = Uuid::new_v4();
        t.workspace_class.insert(ws, s);
        assert_eq!(t.effective_class(ws, Some(sibling_id), false).map(|c| c.id), Some(sibling_id));
    }

    #[test]
    fn a_workspace_with_no_class_runs_as_the_tenant_default() {
        let (t, _, s, _) = table();
        assert_eq!(t.workspace_class(Uuid::new_v4()).map(|c| c.id), Some(s));
    }

    #[test]
    fn a_key_may_take_a_less_important_class_than_its_workspace() {
        let (mut t, i, _, b) = table();
        let ws = Uuid::new_v4();
        t.workspace_class.insert(ws, i);
        assert_eq!(t.effective_class(ws, Some(b), false).map(|c| c.id), Some(b));
    }

    #[test]
    fn a_key_is_clamped_to_its_workspace_when_it_was_not_elevated() {
        let (mut t, i, s, _) = table();
        let ws = Uuid::new_v4();
        t.workspace_class.insert(ws, s);
        // The key names the more important class; without the elevation bit the
        // workspace's class is what the request runs as.
        assert_eq!(t.effective_class(ws, Some(i), false).map(|c| c.id), Some(s));
    }

    #[test]
    fn an_elevated_key_keeps_its_class_above_its_workspace() {
        let (mut t, i, s, _) = table();
        let ws = Uuid::new_v4();
        t.workspace_class.insert(ws, s);
        assert_eq!(t.effective_class(ws, Some(i), true).map(|c| c.id), Some(i));
    }

    #[test]
    fn a_key_pointing_at_a_class_that_is_gone_inherits_its_workspace() {
        let (mut t, _, s, b) = table();
        let ws = Uuid::new_v4();
        t.workspace_class.insert(ws, b);
        t.classes.remove(&s);
        assert_eq!(t.effective_class(ws, Some(s), true).map(|c| c.id), Some(b));
    }

    #[test]
    fn an_empty_table_gives_no_request_a_class() {
        let t = QosTable::default();
        assert_eq!(t.effective_class(Uuid::new_v4(), None, false), None);
    }

    #[test]
    fn a_workspace_inheriting_the_default_is_still_what_a_key_is_clamped_to() {
        // The workspace names no class of its own, so the comparison is against
        // the tenant default — not "unranked", which would let any key through.
        let (t, i, s, _) = table();
        let ws = Uuid::new_v4();
        assert_eq!(t.effective_class(ws, Some(i), false).map(|c| c.id), Some(s));
    }

    #[test]
    fn a_route_target_accepts_every_class_until_it_names_one() {
        let (mut t, i, s, _) = table();
        let route = Uuid::new_v4();
        assert!(t.route_accepts(route, i));
        t.route_classes.insert(route, vec![i]);
        assert!(t.route_accepts(route, i));
        assert!(!t.route_accepts(route, s));
    }

    #[test]
    fn a_workspace_weight_is_one_unless_set_and_never_zero() {
        let mut t = QosTable::default();
        let ws = Uuid::new_v4();
        assert_eq!(t.weight(ws), 1);
        t.workspace_weight.insert(ws, 0);
        assert_eq!(t.weight(ws), 1);
        t.workspace_weight.insert(ws, 7);
        assert_eq!(t.weight(ws), 7);
    }
}
