//! Per-source-IP throttle for the gateway's unauthenticated discovery documents.
//!
//! Two routes are served before any credential exists, because a client needs
//! them in order to learn which credential to present: the MCP
//! protected-resource metadata (RFC 9728) and the A2A agent card. Both resolve
//! their slug by scanning the tenant registry, so an anonymous caller can drive
//! that scan as fast as it can open connections.
//!
//! One limiter instance covers both surfaces — an attacker who is throttled on
//! the agent card must not simply move to the metadata endpoint for a fresh
//! budget. It reuses [`RateLimiter`] and resolves the key through
//! [`extract_client_ip`] under the deployment-wide `TRUSTED_PROXY_HOPS` trust
//! model; reading `X-Forwarded-For` directly would hand every request a
//! spoofable key of its own, which is no limiter at all.
//!
//! Mounted with `route_layer`, so it runs only on these routes — an unmatched
//! path 404s without consuming anyone's budget.
//!
//! **What this does NOT bound**: an anonymous request to the `/mcp/{slug}` and
//! `/a2a/{slug}` mounts themselves drives the same registry scan on its way to a
//! 401, and those routes are outside this layer. So the cap bounds these two
//! documents, not the scan in general — do not read it as making slug
//! enumeration unreachable. Extending it there means charging requests that may
//! turn out to be authenticated, which is a different trade-off.

use std::sync::Arc;

use axum::extract::{Request, State};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};

use streamscope_core::error::AppError;
use streamscope_core::middleware::ip_rate_limit::{extract_client_ip, RateLimiter};

/// Map-cleanup threshold. Keyed by source IP, so a distributed scan touches one
/// entry per source and the map can hold far more live keys than an
/// identity-keyed limiter; it sweeps expired entries correspondingly less often.
pub const PUBLIC_METADATA_LIMIT_CLEANUP_THRESHOLD: usize = 10_000;

pub async fn public_metadata_rate_limit_mw(
    State(limiter): State<Arc<RateLimiter>>,
    req: Request,
    next: Next,
) -> Response {
    // A cap of 0 disables the limiter — without this short-circuit every source
    // is trivially at a cap of 0 and the discovery documents would be unservable.
    if limiter.max_attempts() == 0 {
        return next.run(req).await;
    }
    // No attributable source (no `ConnectInfo`, no trusted forwarding header)
    // means no bucket to charge — pass through, as the admin pre-auth limiter
    // does. Refusing instead would take discovery down on a misconfigured
    // deployment rather than throttle an attacker.
    let Some(ip) = extract_client_ip(
        req.headers(),
        req.extensions(),
        streamscope_core::settings::core_settings().trusted_proxy_hops,
    ) else {
        return next.run(req).await;
    };

    if limiter.check_rate_limit(&streamscope_core::middleware::ip_rate_limit::limiter_key(ip)) {
        tracing::warn!(%ip, path = %req.uri().path(), "public metadata request rate limited by source IP");
        return AppError::rate_limited("too many requests — try again later")
            .into_response();
    }
    next.run(req).await
}
