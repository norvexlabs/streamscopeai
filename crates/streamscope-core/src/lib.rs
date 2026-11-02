//! Core library for the Streamscope AI gateway.
//!
//! Shared between the edge proxy binary and the admin API. Contains the full
//! request lifecycle: protocol parsing ([`api`]), authentication ([`auth`]),
//! tenant configuration ([`config`]), request/response transforms ([`pipeline`],
//! [`scripting`]), upstream routing ([`proxy`]), and audit recording ([`audit`]).
//!
//! All types are designed for multi-tenant isolation — tenant context flows
//! through every layer via [`config::TenantId`] and [`auth::UserContext`].

/// Application version extracted from `CHANGELOG.md` at compile time.
pub const VERSION: &str = env!("STREAMSCOPE_VERSION");

/// The internal-egress allowlists every test of this crate installs — one set,
/// because the store is process-wide and the tests share the process: every
/// surface lists every private address, except `extensions`, which lists
/// exactly `10.0.0.5` (so a test can prove an unlisted address is refused).
#[cfg(test)]
pub(crate) mod test_egress {
    pub(crate) fn install() {
        let lists: std::collections::BTreeMap<String, Vec<String>> = streamscope_mcp_auth::egress::Surface::ALL
            .iter()
            .map(|s| {
                let entry = if *s == streamscope_mcp_auth::egress::Surface::Extensions { "10.0.0.5" } else { "*" };
                (s.as_str().to_string(), vec![entry.to_string()])
            })
            .collect();
        streamscope_mcp_auth::egress::install(
            streamscope_mcp_auth::egress::Lists::from_entries(&lists).expect("the test lists parse"),
        );
    }
}

pub mod a2a;
pub mod api;
pub mod audit;
pub mod auth;
pub mod cgroup;
pub mod config;
pub mod crypto;
pub mod edge_wire;
pub mod error;
pub mod extension_http;
pub mod guardrail;
pub mod http_body;
pub mod ids;
pub mod log_throttle;
pub mod mcp;
pub mod metrics;
pub mod middleware;
pub mod net;
pub mod observability;
pub mod pg_text;
pub mod pipeline;
pub mod pricing;
pub mod proxy;
pub mod runtime;
pub mod scripting;
pub mod settings;
pub mod settings_catalog;
pub mod tls;
pub mod usage;
pub mod web;
