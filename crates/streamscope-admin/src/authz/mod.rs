//! Admin authorization policy — the single decision point for "may this
//! authenticated admin perform this request?".
//!
//! Today the policy is **role-based**: a [`AdminRole::ReadOnly`] account may
//! issue only safe (non-mutating) requests, plus a `POST` to the closed
//! [`READ_ONLY_SELF_SERVICE`] list; an [`AdminRole::Admin`] account may do
//! anything its tenant scope already permits. (Super-admin gating for the
//! cross-tenant `/global` and tenant-management routes is orthogonal and stays
//! in `super_admin_guard`.)
//!
//! The decision is expressed as a pure function — [`evaluate`] — over an
//! [`AccessContext`], a bag of request attributes. That shape is deliberate: it
//! is the seam to grow into attribute-based access control (ABAC). A richer
//! policy (per-resource grants, time/IP conditions, field-level rules) adds
//! attributes to `AccessContext` and branches to `evaluate` **without touching
//! any call site** — the middleware just builds the context and asks for a
//! [`Decision`]. Keeping the policy as data-in → decision-out, with no I/O and
//! no framework types beyond `Method`, is what makes it cheap to unit-test
//! exhaustively and to audit as the security boundary.

use axum::http::Method;

use crate::routes::ApiErrorCode;

/// An admin account's role.
///
/// Persisted as free text in `admin_accounts.role` (and `tenant_invites.role`,
/// which seeds it on invite acceptance). Authorization NEVER pivots on the raw
/// string — it is parsed into this closed set first, so an unrecognized or
/// future value can only ever resolve to the least-privileged role.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AdminRole {
    /// Full management access within the account's tenant scope.
    Admin,
    /// May read (safe HTTP methods) but never mutate tenant state. Every
    /// mutating path is blocked at the chokepoint — changing one's own role,
    /// email or password included — except the [`READ_ONLY_SELF_SERVICE`]
    /// routes, which write a fixed value to the caller's own row and grant
    /// nothing, so a read-only account cannot self-escalate.
    ReadOnly,
}

impl AdminRole {
    /// Canonical wire/DB string for [`AdminRole::Admin`].
    pub const ADMIN: &'static str = "admin";
    /// Canonical wire/DB string for [`AdminRole::ReadOnly`].
    pub const READ_ONLY: &'static str = "read_only";

    /// Parse for **enforcement** — fail closed. An unknown, empty, or corrupt
    /// role string resolves to [`AdminRole::ReadOnly`] (least privilege), never
    /// to `Admin`. A future or garbage value can only ever *lose* privilege
    /// here, never gain it — the load-bearing invariant for the chokepoint.
    pub fn parse(s: &str) -> Self {
        Self::parse_strict(s).unwrap_or(AdminRole::ReadOnly)
    }

    /// Parse for **input validation** — reject the unknown. Used where an
    /// operator supplies a role (invite creation): a typo must surface as a
    /// `400` rather than silently minting a read-only account nobody intended.
    pub fn parse_strict(s: &str) -> Option<Self> {
        match s {
            Self::ADMIN => Some(AdminRole::Admin),
            Self::READ_ONLY => Some(AdminRole::ReadOnly),
            _ => None,
        }
    }

    /// Canonical string form for persistence.
    pub fn as_str(&self) -> &'static str {
        match self {
            AdminRole::Admin => Self::ADMIN,
            AdminRole::ReadOnly => Self::READ_ONLY,
        }
    }

    /// Project an `ak-` automation key's `admin_scope` onto the coarse role used
    /// by the v1 chokepoint. `read_only` → ReadOnly; `admin`/`super_admin` →
    /// Admin; anything else fails closed to ReadOnly. Whether `super_admin`
    /// *additionally* grants cross-tenant super-admin is decided in the auth path
    /// (SYSTEM-tenant only) — NOT here.
    pub fn from_admin_scope(scope: &str) -> Self {
        match scope {
            admin_scope::ADMIN | admin_scope::SUPER_ADMIN => AdminRole::Admin,
            _ => AdminRole::ReadOnly,
        }
    }
}

/// Allowed `admin_scope` values for an `ak-` admin automation key (the "right to
/// manage" within the admin plane). Open at the storage layer (TEXT, no CHECK)
/// so finer scopes stay additive; this is the step-1 closed validation set.
pub mod admin_scope {
    /// Safe (non-mutating) admin API only.
    pub const READ_ONLY: &str = "read_only";
    /// Full admin API within the key's tenant (configure + debug). Same word as
    /// the console `admin_accounts.role` value — one vocabulary across planes.
    pub const ADMIN: &str = "admin";
    /// SYSTEM-tenant operator key: cross-tenant + tenant create (`/global`).
    pub const SUPER_ADMIN: &str = "super_admin";

    /// True for a recognized step-1 scope value.
    pub fn is_valid(s: &str) -> bool {
        matches!(s, READ_ONLY | ADMIN | SUPER_ADMIN)
    }
}

/// Everything a policy may pivot on for a single request. v1 reads `role` and
/// `method`; the struct is the extension point for future ABAC attributes
/// (resource id/owner, request time, source IP, target field, …).
pub struct AccessContext<'a> {
    pub role: AdminRole,
    pub method: &'a Method,
    /// Raw `admin_scope` of the authenticating `ak-` key (`read_only` | `admin` |
    /// `super_admin`), `None` for a human session. Deliberately not yet read by
    /// the v1 role-based `evaluate` — it is the ABAC seam: scope-aware
    /// fine-grained rules branch on it here without touching any call site (the
    /// middleware already populates it). `allow(dead_code)` until that lands.
    #[allow(dead_code)]
    pub key_scope: Option<&'a str>,
    /// The matched route template with the `/api/v1/admin` mount prefix
    /// stripped (`changelog/actions/dismiss`), `None` when unmatched — which
    /// grants nothing.
    pub route: Option<&'a str>,
}

/// Route templates (prefix-trimmed, as [`AccessContext::route`]) a read-only
/// account may `POST`: per-account self-service that writes only the caller's
/// own account row, from no request input, and grants nothing. Every entry is a
/// claim read in review — a route that changes tenant state never belongs here.
pub const READ_ONLY_SELF_SERVICE: &[&str] = &[
    // Marks the "What's new" dialog seen for the calling account.
    "changelog/actions/dismiss",
];

/// Outcome of [`evaluate`]. `Deny` carries the typed [`ApiErrorCode`] and a
/// static, client-safe reason so the middleware can build a sanitized
/// `ApiErrorResponse` without re-deriving why the request was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny {
        code: ApiErrorCode,
        reason: &'static str,
    },
}

/// True only for HTTP methods that cannot change server state. Everything
/// else — including unknown/extension methods (`PURGE`, `LOCK`, …) — is
/// treated as mutating, so the read-only policy fails closed against any verb
/// it doesn't explicitly recognize as safe. `OPTIONS` is safe so CORS
/// preflight is never refused.
pub fn is_safe_method(method: &Method) -> bool {
    matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// The single admin-authorization decision point. Pure: no I/O, no clock, no
/// randomness — same context always yields the same decision.
pub fn evaluate(ctx: &AccessContext) -> Decision {
    match ctx.role {
        AdminRole::Admin => Decision::Allow,
        AdminRole::ReadOnly => {
            let self_service = *ctx.method == Method::POST
                && ctx.route.is_some_and(|r| READ_ONLY_SELF_SERVICE.contains(&r));
            if is_safe_method(ctx.method) || self_service {
                Decision::Allow
            } else {
                Decision::Deny {
                    code: ApiErrorCode::ReadOnlyAccount,
                    reason: "read-only account: mutating requests are not permitted",
                }
            }
        }
    }
}

/// Route templates (with the `/api/v1/admin` mount prefix stripped) the SYSTEM
/// platform tenant may **mutate**. SYSTEM runs no customer workloads, so every
/// other mutating admin route is denied to it — fail-closed: a new mutating
/// route is SYSTEM-forbidden by default until it is explicitly added here.
///
/// Safe-method reads (GET/HEAD/OPTIONS) are NOT gated by this list — they are
/// allowed for SYSTEM regardless, because every admin-router read is RLS-scoped
/// to the SYSTEM tenant's own (empty) workload and so exposes nothing
/// cross-tenant; cross-tenant data is reachable only via the separately
/// super-admin-guarded `/api/v1/admin/global/*` routers. The global admin layout
/// and the SYSTEM-visible Keys / Overview / Auth pages legitimately fire workload
/// GETs (`workspaces`, `tool-profiles`, `users`, `keys`, `analytics/users-keys`,
/// `audit`, `settings/db-stats`), so gating reads would break the SYSTEM console.
///
/// Matched against the `MatchedPath` template, so `settings` is allowed while
/// `settings/web` is not. This list is the single source of truth for "what the
/// platform (SYSTEM) tenant may change" — keep it in sync with the SYSTEM-visible
/// admin UI surface.
pub const SYSTEM_ALLOWED_MUTATIONS: &[&str] = &[
    // OIDC / auth config for super-admin login
    "config",
    "config/actions/test",
    // Super-admin console account management
    "admin-accounts",
    "admin-accounts/{id}",
    // Operator / super_admin automation principals (scope re-checked in the handler)
    "service-accounts",
    "service-accounts/{id}",
    "service-accounts/{id}/actions/disable",
    "service-accounts/{id}/actions/enable",
    "service-accounts/{id}/actions/revoke",
    "service-accounts/{id}/actions/rotate-agent-key",
    "service-accounts/{id}/keys",
    "service-accounts/{id}/keys/{key_id}/actions/revoke",
    "service-accounts/{id}/keys/{key_id}/actions/rotate",
    // Platform-default settings (PATCH is further key-restricted in settings.rs)
    "settings",
    // Per-admin "what's new" dismissal
    "changelog/actions/dismiss",
];

/// True if the SYSTEM platform tenant may issue a mutating request against this
/// prefix-trimmed route template. Pure membership test over
/// [`SYSTEM_ALLOWED_MUTATIONS`] — the enforcement lives in the
/// `system_workload_guard` middleware, which only consults this for non-safe
/// methods.
pub fn system_tenant_allows_mutation(trimmed_template: &str) -> bool {
    SYSTEM_ALLOWED_MUTATIONS.contains(&trimmed_template)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::assert_matches;

    #[test]
    fn parse_known_roles() {
        assert_eq!(AdminRole::parse("admin"), AdminRole::Admin);
        assert_eq!(AdminRole::parse("read_only"), AdminRole::ReadOnly);
    }

    #[test]
    fn parse_unknown_is_least_privilege() {
        // Fail closed: anything we don't recognize must NOT be Admin.
        assert_eq!(AdminRole::parse(""), AdminRole::ReadOnly);
        assert_eq!(AdminRole::parse("Admin"), AdminRole::ReadOnly); // case-sensitive
        assert_eq!(AdminRole::parse("superuser"), AdminRole::ReadOnly);
        assert_eq!(AdminRole::parse("read-only"), AdminRole::ReadOnly); // hyphen != underscore
    }

    #[test]
    fn parse_strict_rejects_unknown() {
        assert_eq!(AdminRole::parse_strict("admin"), Some(AdminRole::Admin));
        assert_eq!(AdminRole::parse_strict("read_only"), Some(AdminRole::ReadOnly));
        assert_eq!(AdminRole::parse_strict("nope"), None);
        assert_eq!(AdminRole::parse_strict(""), None);
    }

    #[test]
    fn as_str_round_trips() {
        for role in [AdminRole::Admin, AdminRole::ReadOnly] {
            assert_eq!(AdminRole::parse_strict(role.as_str()), Some(role));
        }
    }

    fn ctx(role: AdminRole, method: Method) -> Decision {
        ctx_on(role, method, Some("servers/{id}"))
    }

    fn ctx_on(role: AdminRole, method: Method, route: Option<&str>) -> Decision {
        evaluate(&AccessContext {
            role,
            method: &method,
            key_scope: None,
            route,
        })
    }

    #[test]
    fn read_only_may_post_only_its_own_self_service_routes() {
        let dismiss = Some("changelog/actions/dismiss");
        assert_eq!(ctx_on(AdminRole::ReadOnly, Method::POST, dismiss), Decision::Allow);
        // Only POST, only a listed route, and never without a matched route.
        for m in [Method::PUT, Method::PATCH, Method::DELETE] {
            assert_matches!(ctx_on(AdminRole::ReadOnly, m, dismiss), Decision::Deny { .. });
        }
        for route in [Some("changelog"), Some("changelog/actions/dismiss/x"), Some("settings"), None] {
            assert_matches!(
                ctx_on(AdminRole::ReadOnly, Method::POST, route),
                Decision::Deny { code: ApiErrorCode::ReadOnlyAccount, .. }
            );
        }
    }

    #[test]
    fn from_admin_scope_projection() {
        assert_eq!(AdminRole::from_admin_scope("read_only"), AdminRole::ReadOnly);
        assert_eq!(AdminRole::from_admin_scope("admin"), AdminRole::Admin);
        assert_eq!(AdminRole::from_admin_scope("super_admin"), AdminRole::Admin);
        // Fail closed on anything unrecognized.
        assert_eq!(AdminRole::from_admin_scope("nope"), AdminRole::ReadOnly);
        assert_eq!(AdminRole::from_admin_scope(""), AdminRole::ReadOnly);
        assert!(admin_scope::is_valid("super_admin"));
        assert!(!admin_scope::is_valid("root"));
    }

    #[test]
    fn admin_may_do_anything() {
        for m in [
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
        ] {
            assert_eq!(ctx(AdminRole::Admin, m), Decision::Allow);
        }
    }

    #[test]
    fn read_only_may_read() {
        for m in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert_eq!(ctx(AdminRole::ReadOnly, m), Decision::Allow);
        }
    }

    #[test]
    fn read_only_denied_on_mutations() {
        for m in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert_matches!(
                ctx(AdminRole::ReadOnly, m),
                Decision::Deny {
                    code: ApiErrorCode::ReadOnlyAccount,
                    ..
                }
            );
        }
    }

    #[test]
    fn read_only_denied_on_unknown_method() {
        // Fail closed against verbs we don't classify as safe.
        let purge = Method::from_bytes(b"PURGE").unwrap();
        assert_matches!(
            ctx(AdminRole::ReadOnly, purge),
            Decision::Deny { .. }
        );
    }

    #[test]
    fn system_mutation_whitelist_allows_platform_routes() {
        // Platform / self-management mutations SYSTEM legitimately performs.
        for t in [
            "config",
            "config/actions/test",
            "admin-accounts",
            "admin-accounts/{id}",
            "service-accounts",
            "service-accounts/{id}/keys",
            "service-accounts/{id}/keys/{key_id}/actions/rotate",
            "settings",
            "changelog/actions/dismiss",
        ] {
            assert!(
                system_tenant_allows_mutation(t),
                "expected SYSTEM mutation allowed for {t}"
            );
        }
    }

    #[test]
    fn system_mutation_whitelist_denies_customer_workload() {
        // A representative customer-workload set —
        // all fail closed. `settings/web` shares the `settings` segment but is a
        // distinct template, so the exact-template match must reject it.
        for t in [
            "servers",
            "servers/{id}",
            "downstream-providers",
            "workspaces",
            "keys",
            "users",
            "users/{id}",
            "models",
            "catalog",
            "tool-rules",
            "mcp/virtual-servers",
            "settings/web",
            "maintenance/purge-audit",
        ] {
            assert!(
                !system_tenant_allows_mutation(t),
                "expected SYSTEM mutation DENIED for {t}"
            );
        }
    }
}
