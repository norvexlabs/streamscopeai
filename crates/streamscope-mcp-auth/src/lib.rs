//! MCP auth helpers — PKCE S256, per-tenant JWT, RFC 9728 / RFC 8414 / RFC 8707.
//!
//! The crate is split into small modules so the proxy and the admin API can
//! each pull what they need:
//!
//! * [`pkce`] — code verifier generation, S256 challenge derivation, verify.
//! * [`keys`] — the per-tenant signing keys every streamscope JWT is built on,
//!   and the `kid`-addressed ring that lets `AUTH_SECRET` rotate without
//!   invalidating live sessions.
//! * [`jwt`] — issue + verify MCP access tokens on top of that ring. Adds the
//!   [`McpAccessClaims`] shape.
//! * [`metadata`] — RFC 9728 protected-resource-metadata + RFC 8414 authz
//!   server metadata serialisers. Plus a helper to build the RFC 8707
//!   audience URI from a slug.
//! * [`ssrf`] — the shared SSRF guard every outbound call to a user- or
//!   upstream-influenced URL goes through, reading [`egress`]: the
//!   deployment's per-surface allowlists of internal destinations.
//!
//! No public surface beyond what's pulled into the routes that mount the OAuth
//! endpoints (admin API) and the routes that validate JWT bearers (proxy).

pub mod egress;
pub mod jwt;
pub mod keys;
pub mod metadata;
pub mod pkce;
pub mod ssrf;

pub use jwt::{McpAccessClaims, McpJwtError, SURFACE_CLI, SURFACE_MCP, TOKEN_ISSUER};
pub use keys::{KeyError, Keyring};
pub use metadata::{
    audience_for_slug, build_protected_resource_metadata, AuthorizationServerMetadata,
    ProtectedResourceMetadata, IMPLICIT_SCOPE,
};
pub use pkce::{derive_s256_challenge, generate_code_verifier, verify_s256_challenge};
pub use ssrf::{
    is_internal_address, resolve_and_pin_addrs, GuardedResolver, GuardedResolverHandle, SsrfError,
};
