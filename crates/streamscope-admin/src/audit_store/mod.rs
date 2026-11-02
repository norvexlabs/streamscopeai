//! The audit store: every row read and row delete of a fact — `gateway_audit`,
//! its children (`llm_audit`, `mcp_audit`, `web_audit`, `a2a_audit`) and
//! `conversation_turns` — is written in this module, the deletes in
//! `purge.rs`; the one writer is the edge ingest (`edge_v2/writers.rs`). Expiry
//! by dropping whole weekly partitions is partition DDL, in `retention.rs`. A
//! new fact statement goes here, never into a route.
//!
//! The boundary: a statement and the decoding of its rows always live here,
//! returned as an `sqlx::Result` — the lists, the ownership gates and the
//! dashboards map their own errors (`ApiError`, `anyhow`), and the two wide turn
//! reads behind a trace and a conversation decode by column name into the row
//! types beside their SELECTs (`trace::TraceTurn`, `timeline::TimelineTurn`). A body that builds conversation events
//! (`conversation::build_events`) never lives here — the store hands it rows.
//! The caller always owns the HTTP surface. The lists and the tool-call feed
//! take an [`AuditScope`] the caller resolved. A dashboard whose body is one
//! composition over its reads may live here whole: it reads its own query
//! struct (window, user, workspaces) and returns its response type, and two of
//! them (`transform_stats`, `users_keys_dashboard`) fan out on connections
//! acquired for the caller's tenant (`TenantConn::acquire(pool, <that
//! tenant>)`) — each such acquire is a claim, read in review.
//!
//! Every statement runs on a tenant-scoped connection (a `Scoped`, a
//! `TenantConn`, or one acquired for the caller's tenant), so RLS confines what
//! it reads or deletes whatever its SQL says.

pub(crate) mod analytics;
pub(crate) mod filters;
pub(crate) mod guardrail;
pub(crate) mod logs;
pub(crate) mod ownership;
pub(crate) mod purge;
pub(crate) mod scope;
pub(crate) mod search;
pub(crate) mod sessions;
pub(crate) mod stats;
pub(crate) mod timeline;
pub(crate) mod tool_activity;
pub(crate) mod trace;
pub(crate) mod usage;

pub(crate) use scope::AuditScope;
