//! Process-global custom CA bundle for admin-api's outbound HTTPS clients.
//!
//! Unlike the proxy (which receives the `CUSTOM_CA_BUNDLE_PEM` override through
//! the pushed `runtime_overrides.json` and reads it from
//! [`streamscope_core::settings::core_settings`] at start), admin-api owns the
//! `platform_setting_overrides` table directly. The resolved bundle is held as
//! the process's trusted CA ([`streamscope_core::tls::trusted_ca`]), so every
//! admin outbound client (liveness probe, model discovery, OIDC discovery,
//! MCP-OAuth fetch, agent, internal client, the guardrail classifier, an
//! upstream's token hop) reads it from one place.
//!
//! The cache is loaded at startup and refreshed when the `runtime-config`
//! override is written. The **CA-critical paths** — every user-triggered
//! outbound TLS call: liveness probes, model and OAuth discovery, the MCP
//! OAuth hops, CIMD document fetches, OIDC login, the connection tests and the
//! agent-card guardrail scan (whose classifier client follows the bundle) —
//! additionally refresh from the request's DB connection right
//! before they build their (per-call) client, so an import takes effect
//! immediately there, and correctly even across multiple admin-api replicas (the
//! replica handling the add isn't necessarily the one that handled the import).
//! The long-lived clients built once at startup (`AdminState.http_client`, the
//! agent client) pick up a newly imported CA only on the next admin-api restart
//! — the same restart semantics the proxy has for this setting.
//!
//! Resolution: the platform DB override wins; otherwise the process env
//! (`core_settings().custom_ca_bundle`) is the fallback.

use crate::db::tenant::Scoped;
use crate::db::{Db, Global};
/// The custom CA PEM bundle currently trusted by admin outbound clients, if any.
pub fn current() -> Option<String> {
    streamscope_core::tls::trusted_ca().map(|pem| pem.to_string())
}

/// Read the platform override (env fallback) and update the cache.
fn apply(from_db: Option<String>) {
    let resolved = from_db
        .filter(|p| !p.trim().is_empty())
        .or_else(|| {
            streamscope_core::settings::core_settings()
                .custom_ca_bundle
                .clone()
        });
    streamscope_core::tls::set_trusted_ca(resolved.as_deref());
}

/// Read the platform override (`platform_setting_overrides` is global infra, so
/// any connection reads it); its result goes to [`apply_read`].
const READ_OVERRIDE: &str =
    "SELECT value FROM platform_setting_overrides WHERE token = 'CUSTOM_CA_BUNDLE_PEM'";

/// Apply a read result, leaving the cache untouched when the read failed.
///
/// `Ok(None)` means "no override is set" and `Err` means "we could not find
/// out" — keep those apart. Collapsing them would make a transient read failure
/// indistinguishable from a deliberate clear, and the cache would silently drop
/// back to the env bundle.
///
/// **Invariant to preserve when adding a refresh site:** a failed read must
/// never narrow the trust set. These refreshes run on user-triggered paths —
/// including one an unauthenticated caller can drive — so a downgrade-on-error
/// would be a way to strip an imported CA process-wide by making one query fail.
fn apply_read(read: Result<Option<String>, sqlx::Error>) {
    match read {
        Ok(value) => apply(value),
        Err(e) => tracing::warn!("custom CA refresh: failed to read platform override: {e}"),
    }
}

/// Refresh the cache from a pool (startup + after a `runtime-config` write).
pub async fn refresh_from_db(pool: &Db) {
    apply_read(sqlx::query_scalar(READ_OVERRIDE).fetch_optional(pool.global(Global::Infra)).await);
}

/// Refresh the cache from a request connection, just before a CA-critical
/// outbound call (probe / discovery / OAuth hop), so the value is fresh on this
/// replica — the cache is process-local and only the replica that handled the
/// write refreshes it on its own.
pub async fn refresh_from_conn(conn: &mut Scoped) {
    apply_read(sqlx::query_scalar(READ_OVERRIDE).fetch_optional(&mut *conn).await);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_uploaded_bundle_is_the_process_trusted_ca() {
        let uploaded = "-----BEGIN CERTIFICATE-----\nuploaded\n-----END CERTIFICATE-----\n";
        apply(Some(uploaded.to_string()));
        assert_eq!(current().as_deref(), Some(uploaded));
        assert_eq!(streamscope_core::tls::trusted_ca().as_deref(), Some(uploaded));
        // Cleared, both fall back to the environment's bundle.
        apply(None);
        let env = streamscope_core::settings::core_settings().custom_ca_bundle.clone();
        assert_eq!(current(), env);
        assert_eq!(streamscope_core::tls::trusted_ca().as_deref(), env.as_deref());
    }
}
