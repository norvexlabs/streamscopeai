//! `POST /api/v2/edge/sync` — the edge states what config it holds and is
//! answered with every resource whose digest differs, the removals, and the
//! events after its cursor.

use std::fmt;
use std::str::FromStr;

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use utoipa::ToSchema;

use crate::digest::Digest;

/// Ordered per instance: kept in the edge's durable store and raised at every
/// process start to one more than the last, and at least the wall clock in
/// seconds (a store restored from an older backup still starts past what
/// admin-api last saw) — so "older" is defined. The instance id lives in the
/// same store, so a lost store is a new instance and an epoch is only ever
/// compared with epochs of its own store.
pub type Epoch = u64;

/// The most resource body bytes one sync response carries. Resources past it
/// go on the next poll; a single resource larger than it is still sent, alone.
pub const SYNC_BODY_BUDGET_BYTES: usize = 8 * 1024 * 1024;

/// The most events one sync answer carries; the rest come on the next poll.
pub const EVENTS_PER_POLL: usize = 1000;

/// The largest sync answer an edge reads. A resource body that cannot fit in
/// it is never sent (the admin logs it), so one oversized tenant can never
/// wedge an instance on an answer it refuses to read.
pub const SYNC_RESPONSE_MAX_BYTES: usize = 64 * 1024 * 1024;

/// Room an answer keeps for its envelope (names, digests, events) next to one
/// body.
pub const SYNC_ENVELOPE_RESERVE_BYTES: usize = 4 * 1024 * 1024;

/// An `edge_events` id. Ids are assigned in commit order, so `id > cursor` is
/// exact.
pub type EventId = i64;

/// A config resource: the deployment-wide `global` body, or one tenant's.
/// Carried as `global` / `tenant:<uuid>`; its string form is the order key of
/// [`crate::digest::held_digest`].
/// The derived order (`Global` first, tenants by id bytes) is the bytewise
/// order of the string forms.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum ResourceName {
    Global,
    Tenant(uuid::Uuid),
}

const TENANT_PREFIX: &str = "tenant:";

impl fmt::Display for ResourceName {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Global => f.write_str("global"),
            Self::Tenant(id) => write!(f, "{TENANT_PREFIX}{id}"),
        }
    }
}

impl FromStr for ResourceName {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "global" {
            return Ok(Self::Global);
        }
        // Only the canonical hyphenated lowercase form: a resource name is a
        // map key on both ends, so two spellings of one tenant would be two
        // resources.
        if let Some(rest) = s.strip_prefix(TENANT_PREFIX)
            && let Ok(id) = uuid::Uuid::parse_str(rest)
            && id.hyphenated().to_string() == rest
        {
            return Ok(Self::Tenant(id));
        }
        Err(format!("invalid resource name: {s:?}"))
    }
}

impl Serialize for ResourceName {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for ResourceName {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        s.parse().map_err(serde::de::Error::custom)
    }
}

impl utoipa::PartialSchema for ResourceName {
    fn schema() -> utoipa::openapi::RefOr<utoipa::openapi::schema::Schema> {
        utoipa::openapi::schema::ObjectBuilder::new()
            .schema_type(utoipa::openapi::schema::SchemaType::new(utoipa::openapi::schema::Type::String))
            .description(Some("`global` or `tenant:<uuid>`"))
            .into()
    }
}

impl utoipa::ToSchema for ResourceName {}

/// A resource the edge holds, and the digest of the body it applied.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Held {
    pub resource: ResourceName,
    pub digest: Digest,
}

/// A body the edge refused to apply. The admin does not send that digest to
/// this instance again; a later body for the resource is sent as usual.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
pub struct Nack {
    pub resource: ResourceName,
    pub digest: Digest,
    pub detail: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct SyncRequest {
    /// The edge instance: an id created with the edge's durable store and kept
    /// in it (`edge_instances.instance_key`).
    pub instance: uuid::Uuid,
    pub process_epoch: Epoch,
    /// [`crate::digest::held_digest`] over everything the edge holds.
    pub held_digest: Digest,
    /// The full held set — only when the previous response set
    /// [`SyncResponse::send_held`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub held: Option<Vec<Held>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nacks: Vec<Nack>,
    pub events_after: EventId,
    /// Rows still buffered for ingest, the async audit queue included.
    pub outbox_pending: u64,
    /// How long admin-api may hold an answer that would carry nothing, waiting
    /// for a body or an event to send instead. 0 answers at once.
    pub wait_ms: u64,
}

/// A resource body, already canonical (see [`crate::digest`]); the edge
/// applies it as received and records `digest` as held.
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Resource {
    pub resource: ResourceName,
    pub digest: Digest,
    /// The resource's change counter the body was built at. Larger means
    /// newer for one resource; the edge applies by digest and does not read it.
    pub counter: i64,
    /// A [`crate::config::ConfigResponse`] for a tenant, a
    /// [`crate::config::GlobalConfig`] for `global` — the canonical bytes
    /// themselves, carried verbatim.
    #[schema(value_type = Object)]
    pub body: Box<serde_json::value::RawValue>,
}

/// An event for the edge's tenants (an MCP user event today).
#[derive(Clone, Debug, Serialize, Deserialize, ToSchema)]
pub struct Event {
    pub id: EventId,
    pub tenant: uuid::Uuid,
    /// Polymorphic by event kind; the edge dispatches on its `type`.
    #[schema(value_type = Object)]
    pub body: serde_json::Value,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize, ToSchema)]
pub struct SyncResponse {
    /// The admin could not tell what this instance holds: the next request
    /// carries the full [`SyncRequest::held`]. Nothing else is set.
    #[serde(default)]
    pub send_held: bool,
    #[serde(default)]
    pub resources: Vec<Resource>,
    #[serde(default)]
    pub removed: Vec<ResourceName>,
    /// Resources whose body differs but did not fit this answer; they come on
    /// the next poll. While true, the edge does not hold the current config.
    #[serde(default)]
    pub more: bool,
    #[serde(default)]
    pub events: Vec<Event>,
    /// What the edge sends as its next `events_after`: the last event of a
    /// full page, else the newest event id when the answer was read — every
    /// event for this instance up to it is in `events` — and never beyond it
    /// (a cursor past the newest id, after a restore, comes back down).
    pub events_cursor: EventId,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_resource_name_has_exactly_one_spelling() {
        let id = uuid::Uuid::parse_str("0b6c2f0e-3c1d-4a5e-9f00-1234567890ab").unwrap();
        for r in [ResourceName::Global, ResourceName::Tenant(id)] {
            assert_eq!(r.to_string().parse::<ResourceName>().unwrap(), r);
        }
        assert_eq!(
            "tenant:0b6c2f0e-3c1d-4a5e-9f00-1234567890ab".parse::<ResourceName>().unwrap(),
            ResourceName::Tenant(id)
        );
        for bad in [
            "Global",
            "tenant:",
            "tenant:0B6C2F0E-3C1D-4A5E-9F00-1234567890AB",
            "tenant:0b6c2f0e3c1d4a5e9f001234567890ab",
            "tenant:{0b6c2f0e-3c1d-4a5e-9f00-1234567890ab}",
            "tenants:0b6c2f0e-3c1d-4a5e-9f00-1234567890ab",
        ] {
            assert!(bad.parse::<ResourceName>().is_err(), "{bad} must be refused");
        }
    }
}
