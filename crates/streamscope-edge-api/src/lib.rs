//! The admin ⇄ edge wire: the edge-called endpoints, the config body they
//! carry, and the canonical encoding both ends digest it with.

pub mod compression;
pub mod config;
pub mod digest;
pub mod ingest;
pub mod replay;
pub mod sync;
