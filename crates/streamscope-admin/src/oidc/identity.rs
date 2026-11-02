//! Turning an authenticated identity into a console or portal account.
//!
//! After a login something has vouched for who someone is — an identity
//! provider's signature, or a reverse proxy in front of the deployment. What
//! remains is whether they get an account here and with what role. That answer
//! involves account linking, group-derived roles, two lockout guards and a
//! domain restriction, and getting any of it subtly wrong is a security bug.
//!
//! Invariant for new code: a plane that provisions from an authenticated
//! identity goes through this module, and a new identity *source* is a new
//! [`IdentitySource`] arm, not a new provisioning path. Never add a parallel
//! copy of these decisions — they are the kind that drift apart silently.
//!
//! A source may differ only in the three places it genuinely must: which tenant
//! auth mode admits it, which account the identity resolves to, and the shape of
//! the final write. Everything else is shared, deliberately.

use std::collections::BTreeMap;

use uuid::Uuid;

use crate::db::tenant::TenantConn;
use crate::routes::admin_auth::{
    counts_as_console_admin, derive_console_role, lock_tenant_admins, other_active_admins,
    AdminAccountResponse,
};
use crate::routes::{check_allowed_domains, ApiError, ApiErrorCode};
use crate::authz::AdminRole;

/// An identity the provider has vouched for.
///
/// Every field is taken from a verified ID token. The address's assurance is
/// carried deliberately: it is the difference between "the provider says this
/// address belongs to them" and "the provider passed along an address they
/// typed", and account linking turns on it. Build it with [`oidc_email_assurance`].
#[derive(Debug, Clone)]
pub struct VerifiedOidcIdentity {
    pub email: String,
    pub assurance: EmailAssurance,
    pub subject: String,
    pub issuer: String,
    pub groups: Vec<String>,
}

/// What the gateway knows about the address it is about to key an account on.
///
/// The two arms are not two settings of one dial — they are different sources
/// of authentication, and stating which one applies is the caller's job. Making
/// it a parameter rather than an inspection of ambient configuration is what
/// stops the guard from being silently right on one path and silently absent on
/// another.
#[derive(Debug, Clone, Copy)]
pub enum EmailAssurance {
    /// An identity provider stated whether it had verified the address.
    ///
    /// `None` means it said nothing at all, which is treated exactly like `false`:
    /// an address nobody proved they hold is what this guard exists to refuse,
    /// and email is the sole login identifier. Some providers (Entra among them)
    /// omit the claim for accounts they consider externally managed.
    IdpClaim(Option<bool>),
    /// The provider made no statement about the address, and the tenant's
    /// admin chose to accept it anyway (`oidc_allow_unverified_email`) — the
    /// position of an IdP whose directory, not the user, sets the address, which
    /// is AD FS's. Never reached from an explicit `email_verified: false`.
    TenantAcceptsUnstated,
    /// A reverse proxy in front of the deployment authenticated the request
    /// before it arrived (header auth mode). There is no claim to inspect and
    /// nothing for this process to verify — the proxy *is* the authentication,
    /// and demanding a claim here would lock out every such deployment.
    ProxyAuthenticated,
}

impl EmailAssurance {
    /// Whether the address may be used to create a new account.
    fn vouched_for(self) -> bool {
        match self {
            Self::IdpClaim(claim) => claim == Some(true),
            Self::TenantAcceptsUnstated | Self::ProxyAuthenticated => true,
        }
    }
}

/// The name of the standard OIDC address claim — the only claim the provider's
/// `email_verified` describes.
pub const STANDARD_EMAIL_CLAIM: &str = "email";

/// What an ID token establishes about the address a login is keyed on.
///
/// `email_verified` is a statement about the standard `email` claim and nothing
/// else, so when the tenant keys accounts on another claim (`upn`,
/// `preferred_username`) the provider has said nothing about that value, and it
/// is unstated whatever `email_verified` reads.
///
/// The tenant's opt-in accepts an UNSTATED address only. A provider that
/// explicitly says `false` has told us the address is unconfirmed, and no
/// setting overrides that.
pub fn oidc_email_assurance(
    email_claim: &str,
    email_verified: Option<bool>,
    allow_unverified: bool,
) -> EmailAssurance {
    let stated = if email_claim == STANDARD_EMAIL_CLAIM { email_verified } else { None };
    match stated {
        None if allow_unverified => EmailAssurance::TenantAcceptsUnstated,
        stated => EmailAssurance::IdpClaim(stated),
    }
}

/// How this process came to believe an identity, and what that lets it do.
///
/// The two arms differ only where the *source* genuinely differs — which
/// account an identity resolves to, and which tenant auth mode admits it.
/// Everything downstream of that (group-derived role, revocation, both lockout
/// guards, the domain restriction) is the same decision either way, which is
/// exactly why it must not be written twice.
#[derive(Debug, Clone, Copy)]
pub enum IdentitySource<'a> {
    /// An ID token this process verified against the tenant's configured
    /// issuer. The account binds to `oidc_sub` on first link and is recognised
    /// by that subject afterwards.
    Oidc { subject: &'a str, issuer: &'a str },
    /// A reverse proxy in front of the deployment authenticated the request
    /// before it arrived (`AUTH_MODE=header`). There is no subject to bind to,
    /// so the account is found by email — the proxy is the authentication.
    ProxyHeader,
}

impl IdentitySource<'_> {
    /// The tenant auth mode that admits this source, when the tenant gets a say.
    ///
    /// `tenant_auth_configs.auth_mode` is `internal | oidc` — it says how *this
    /// tenant's* users sign in. Proxy-header auth is not one of its values and
    /// cannot be: it is a property of the **deployment** (`AUTH_MODE=header`),
    /// which turns the whole instance over to a reverse proxy. Its gate is the
    /// `AuthMode::Header` arm the caller is already inside, so there is nothing
    /// per-tenant to check — and checking for a value the column's CHECK
    /// forbids would refuse every header login on every deployment.
    fn required_auth_mode(self) -> Option<&'static str> {
        match self {
            Self::Oidc { .. } => Some("oidc"),
            Self::ProxyHeader => None,
        }
    }

    fn auth_source_column(self) -> &'static str {
        match self {
            Self::Oidc { .. } => "oidc",
            Self::ProxyHeader => "header",
        }
    }
}

/// An identity that has been authenticated, and the questions provisioning
/// needs to ask about it.
pub struct ConsoleIdentity<'a> {
    pub email: &'a str,
    pub groups: &'a [String],
    pub source: IdentitySource<'a>,
    pub assurance: EmailAssurance,
}

impl<'a> VerifiedOidcIdentity {
    /// View this ID-token identity as a console-provisioning input.
    pub fn console(&'a self) -> ConsoleIdentity<'a> {
        ConsoleIdentity {
            email: &self.email,
            groups: &self.groups,
            source: IdentitySource::Oidc {
                subject: &self.subject,
                issuer: &self.issuer,
            },
            assurance: self.assurance,
        }
    }
}

/// Resolve an authenticated identity to a console account, creating or linking
/// it as the tenant's configuration allows.
///
/// Refuses rather than provisions when the tenant's auth mode does not admit
/// this identity source, the issuer is not the configured one, no console group
/// matched, the email domain is not allowed, or the account is already bound to
/// a different identity.
pub async fn provision_admin(
    db: &mut TenantConn,
    tenant_uuid: Uuid,
    tenant_slug: &str,
    identity: &ConsoleIdentity<'_>,
) -> Result<AdminAccountResponse, ApiError> {
    let ConsoleIdentity { email, groups, source, assurance } = *identity;
    if let IdentitySource::Oidc { subject, .. } = source {
        require_usable_subject(subject)?;
    }

    // --- Reject a login the tenant's auth mode does not admit. ---
    if let Some(required) = source.required_auth_mode() {
        let tenant_auth_mode: Option<String> = sqlx::query_scalar(
            "SELECT auth_mode FROM tenant_auth_configs WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("console provisioning auth config read: {e}");
            crate::routes::db_read_error(&e, "account could not be checked")
        })?
        .flatten();

        if tenant_auth_mode.as_deref() != Some(required) {
            tracing::warn!(
                tenant = %tenant_slug,
                auth_mode = ?tenant_auth_mode,
                required,
                "console provisioning: rejected — tenant auth mode does not admit this identity source"
            );
            return Err(ApiError::forbidden("this login method is not enabled for this tenant")
                .code(ApiErrorCode::AuthModeMismatch));
        }
    }

    // --- Validate issuer against tenant's configured OIDC issuer URL. ---
    if let IdentitySource::Oidc { issuer, .. } = source {
        let configured_issuer: Option<String> = sqlx::query_scalar(
            "SELECT oidc_issuer_url FROM tenant_auth_configs WHERE tenant_id = $1",
        )
        .bind(tenant_uuid)
        .fetch_optional(db.conn())
        .await
        .map_err(|e| {
            tracing::error!("console provisioning auth config read: {e}");
            crate::routes::db_read_error(&e, "account could not be checked")
        })?
        .flatten();

        if let Some(configured) = &configured_issuer {
            let normalized_configured = configured.trim_end_matches('/');
            let normalized_request = issuer.trim_end_matches('/');
            if !configured.is_empty() && normalized_configured != normalized_request {
                tracing::warn!(
                    configured = %configured,
                    received = %issuer,
                    "oidc provisioning: issuer mismatch with tenant config"
                );
                return Err(ApiError::forbidden("OIDC issuer mismatch")
                    .code(ApiErrorCode::OidcExchangeFailed));
            }
        }
    }

    // Addresses are stored normalized (`routes::normalize_email`), so an IdP
    // that capitalises differently still names the same account.
    let normalized = crate::routes::normalize_email(email);
    let email = normalized.as_str();
    crate::routes::require_address(email)?;

    // From here on, one transaction under the tenant's admin-row lock: the
    // account lookups, the last-admin guards and the role write or revoke they
    // decide must all read and write as one, or a sign-in's group sync racing a
    // console demotion of the tenant's other admin passes both guards and
    // leaves the tenant with no active admin (the console's update and delete
    // take the same lock). Every write below propagates with `?`, and a
    // refusal that wrote nothing rolls back on drop.
    let mut tx = db.conn().begin().await.map_err(|e| {
        tracing::error!("console provisioning (begin): {e}");
        crate::routes::db_read_error(&e, "account could not be checked")
    })?;
    lock_tenant_admins(&mut tx, tenant_uuid).await?;

    // --- Step 1: Find the account this identity already resolves to. ---
    let (linked_account, was_already_linked) = match source {
        IdentitySource::Oidc { subject, issuer } => {
            let linked = sqlx::query_as::<_, AdminAccountResponse>(
                "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
                 FROM admin_accounts WHERE oidc_sub = $1 AND oidc_issuer = $2 AND is_active = true",
            )
            .bind(subject)
            .bind(issuer)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("oidc provisioning lookup: {e}");
                crate::routes::db_read_error(&e, "account could not be checked")
            })?;
            let found = linked.is_some();
            (linked, found)
        }
        // Header mode has no subject to bind, so email is the identity on every
        // login and there is no separate "link" step to have happened already.
        IdentitySource::ProxyHeader => (None, false),
    };

    // --- Step 2: If not linked, find the account this email names. ---
    //
    // Under OIDC this is the one-time auto-link, guarded twice: the provider
    // must have verified the address, and the account must carry no `oidc_sub`
    // yet — so an account already bound to some other subject cannot be reached
    // by asserting its address.
    //
    // Header mode has **no** such guard, deliberately. There is no subject to
    // compare against: the proxy authenticated the request and email is the only
    // identifier it supplies, so "linked to a different identity" is not a
    // distinction this source can express. Applying the OIDC guard here would
    // lock out every previously-linked admin the moment a tenant switched from
    // OIDC to header auth — refusing a legitimate operator with a message about
    // an identity mismatch that never happened.
    let email_lookup_sql = match source {
        IdentitySource::Oidc { .. } => {
            "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
             FROM admin_accounts WHERE email = $1 AND is_active = true \
             AND (oidc_sub IS NULL OR oidc_sub = '')"
        }
        IdentitySource::ProxyHeader => {
            "SELECT id, email, display_name, role, is_super_admin, is_active, created_at, last_login \
             FROM admin_accounts WHERE email = $1 AND is_active = true"
        }
    };
    let existing_account = match linked_account {
        Some(acct) => Some(acct),
        None if assurance.vouched_for() => sqlx::query_as::<_, AdminAccountResponse>(email_lookup_sql)
            .bind(email)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| {
                tracing::error!("console provisioning email lookup: {e}");
                crate::routes::db_read_error(&e, "account could not be checked")
            })?,
        _ => None,
    };

    // The address must be one the provider vouched for. Creation needs it most
    // directly — email is the login identifier, so an unverified address mints
    // an account under a name nobody proved they hold — and linking requires it
    // for the same reason. A provider that omits the claim entirely is treated
    // as not having vouched. Existing accounts recognised by `oidc_sub` are past
    // this: the subject, not the address, is what identified them. Decided
    // BEFORE the role: an unvouched address with no console group would
    // otherwise be refused as "no console access", pointing the operator at
    // groups when what is missing is the address.
    if existing_account.is_none() && !assurance.vouched_for() {
        tracing::warn!(
            %email,
            assurance = ?assurance,
            "console provisioning: refused to create an account for an unverified email"
        );
        return Err(
            ApiError::forbidden("the identity provider did not verify this email address")
                .code(ApiErrorCode::OidcEmailNotVerified),
        );
    }

    // --- Step 3: console role from IdP groups (authoritative when configured). ---
    // When the tenant configures at least one console group (`admin_group` →
    // Admin, `readonly_group` → ReadOnly), the role is recomputed on EVERY login:
    // an existing account that matches no console group is revoked (falls through
    // to portal), and a ReadOnly-group member is synced down from Admin. When
    // NEITHER group is configured the tenant isn't using group-based role
    // management, so existing accounts keep their role (the pre-created-admin /
    // personal-Gmail pattern) and new accounts stay fail-closed. A change that
    // would remove the last active Admin is skipped (kept as it is) — on the
    // platform tenant the last active super-admin, the grant every platform
    // capability is (`other_active_admins`).
    // On the platform tenant with groups configured, a super-admin IS group-managed:
    // every platform capability is the super-admin grant, so it follows the admin
    // group like a role does elsewhere (`super_admin_to_apply`); the last-admin
    // guard still applies. Genuine-lockout recovery stays the emergency-invite path.
    let (admin_group, readonly_group): (Option<String>, Option<String>) = sqlx::query_as(
        "SELECT admin_group, readonly_group FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_uuid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("console provisioning auth config read: {e}");
        crate::routes::db_read_error(&e, "account could not be checked")
    })?
    .unwrap_or((None, None));

    let groups_configured = admin_group.as_deref().is_some_and(|s| !s.is_empty())
        || readonly_group.as_deref().is_some_and(|s| !s.is_empty());
    let desired_role = derive_console_role(
        groups,
        admin_group.as_deref(),
        readonly_group.as_deref(),
    );
    let is_super = existing_account.as_ref().map(|a| a.is_super_admin).unwrap_or(false);
    let is_system = tenant_uuid == crate::db::tenant::TenantId::SYSTEM.as_uuid();
    // The last-admin guard protects only an account the count includes — on the
    // platform tenant one holding the grant — so it never keeps (and so grants)
    // what an account did not hold.
    let guarded = |acct: &AdminAccountResponse| counts_as_console_admin(acct, tenant_uuid);

    // Resolve the role to persist (and handle revoke / fail-closed block).
    let role_to_apply = if let Some(acct) = &existing_account {
        if !groups_configured {
            // No group-based management: keep the current role.
            AdminRole::parse(&acct.role)
        } else {
            match desired_role {
                // Demotion lockout guard: a ReadOnly sync that would remove the
                // last active Admin is skipped (kept as Admin).
                Some(r)
                    if r != AdminRole::Admin
                        && guarded(acct)
                        && other_active_admins(&mut tx, tenant_uuid, acct.id).await? == 0 =>
                {
                    tracing::warn!(email = %acct.email, "oidc provisioning: keeping last active admin as Admin despite readonly group (lockout guard)");
                    AdminRole::Admin
                }
                Some(r) => r,
                None => {
                    // No console group matched → revoke, unless this is the last
                    // active Admin (kept to avoid lockout).
                    if guarded(acct)
                        && other_active_admins(&mut tx, tenant_uuid, acct.id).await? == 0
                    {
                        tracing::warn!(email = %acct.email, "oidc provisioning: keeping last active admin despite no matching console group (lockout guard)");
                        AdminRole::Admin
                    } else {
                        // Recorded as the group sync's revoke, so a sign-in that
                        // matches a console group again switches it back on —
                        // unlike an admin's Disable, which holds.
                        sqlx::query(
                            "UPDATE admin_accounts SET is_active = false, revoked_by_group = true \
                             WHERE id = $1",
                        )
                            .bind(acct.id)
                            .execute(&mut *tx)
                            .await
                            .map_err(|e| {
                                tracing::error!("oidc provisioning revoke: {e}");
                                crate::routes::db_read_error(&e, "account could not be checked")
                            })?;
                        // The revoke is the outcome, not a failed attempt:
                        // commit it before answering the refusal.
                        commit_provisioning(tx).await?;
                        tracing::info!(email = %acct.email, "oidc provisioning: revoked console access — no matching console group");
                        return Err(ApiError::forbidden(
                            "admin console access revoked — no matching console group",
                        ));
                    }
                }
            }
        }
    } else {
        // New account: provision only when a console group matched.
        match desired_role {
            Some(r) => r,
            None => {
                tracing::warn!(%email, "console provisioning: admin auto-provisioning blocked — no matching console group");
                return Err(ApiError::forbidden(
                    "admin auto-provisioning blocked — pre-existing admin row required, or admin_group/readonly_group must be set and matched in IdP claims",
                ));
            }
        }
    };

    // The domain restriction applies on **every** login, not only the one that
    // creates the account. It answers "whose addresses may sign in here", and an
    // answer that only ever applied at creation would let somebody keep signing
    // in from a domain the tenant has since withdrawn. Empty (the default) admits
    // everyone, so this only bites tenants that deliberately set an allowlist —
    // where it is precisely the intent. An admin who removes their own domain
    // locks themselves out at their next login; the emergency-invite path is the
    // documented recovery, as it is for the console-group guards above.
    let allowed_domains: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT allowed_domains FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_uuid)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|e| {
        tracing::error!("console provisioning auth config read: {e}");
        crate::routes::db_read_error(&e, "account could not be checked")
    })?
    .flatten();
    check_allowed_domains(email, &allowed_domains)?;

    // The write is the one place the two sources genuinely diverge: OIDC binds
    // the account to a subject, header auth has none to bind. Both clear
    // `password_hash`, so a tenant switched back to internal auth cannot be
    // entered with a credential that predates the switch. Only the OIDC arm
    // carries the `oidc_sub` guard — see Step 2 for why the header arm must not.
    let auth_source = source.auth_source_column();
    let super_to_apply = super_admin_to_apply(is_system, groups_configured, role_to_apply, is_super);
    let account = if let Some(acct) = existing_account {
        let result = match source {
            IdentitySource::Oidc { subject, issuer } => sqlx::query(
                "UPDATE admin_accounts SET last_login = NOW(), oidc_sub = $2, oidc_issuer = $3, \
                 auth_source = 'oidc', password_hash = NULL, role = $4, is_super_admin = $5 \
                 WHERE id = $1 AND (oidc_sub IS NULL OR oidc_sub = '' OR oidc_sub = $2)",
            )
            .bind(acct.id)
            .bind(subject)
            .bind(issuer)
            .bind(role_to_apply.as_str())
            .bind(super_to_apply),
            IdentitySource::ProxyHeader => sqlx::query(
                "UPDATE admin_accounts SET last_login = NOW(), \
                 auth_source = 'header', password_hash = NULL, role = $2, is_super_admin = $3 \
                 WHERE id = $1",
            )
            .bind(acct.id)
            .bind(role_to_apply.as_str())
            .bind(super_to_apply),
        }
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            if crate::routes::is_unique_violation(&e) {
                tracing::warn!("console provisioning update: {e}");
                return ApiError::forbidden("account conflict").code(ApiErrorCode::OidcIdentityConflict);
            }
            tracing::error!("console provisioning update: {e}");
            crate::routes::db_read_error(&e, "account could not be checked")
        })?;
        if result.rows_affected() == 0 {
            // WHERE clause rejected: the account is bound to a different
            // identity (a race, or an attempt to reach a linked account).
            tracing::warn!(email = %acct.email, "console provisioning: account already linked to a different identity");
            return Err(ApiError::forbidden("account already linked to different OIDC identity").code(ApiErrorCode::OidcIdentityConflict));
        }
        if !was_already_linked && matches!(source, IdentitySource::Oidc { .. }) {
            tracing::info!(email = %acct.email, "oidc provisioning: auto-linked OIDC identity to existing admin account");
        }
        Some(AdminAccountResponse {
            last_login: Some(chrono::Utc::now()),
            role: role_to_apply.as_str().to_string(),
            is_super_admin: super_to_apply,
            ..acct
        })
    } else {
        // Auto-provision with the derived role. Both arms re-activate an account
        // the group sync revoked (`revoked_by_group`) and that has since regained
        // a console group; neither touches an account an admin disabled — the
        // DO UPDATE skips it and returns nothing, and the read-back below says
        // why. The OIDC arm's guard additionally refuses to overwrite an account
        // already bound to a different subject.
        match source {
            IdentitySource::Oidc { subject, issuer } => sqlx::query_as::<_, AdminAccountResponse>(
                "INSERT INTO admin_accounts (email, auth_source, oidc_sub, oidc_issuer, role, tenant_id, last_login, is_super_admin) \
                 VALUES ($1, 'oidc', $2, $3, $4, $5, NOW(), $6) \
                 ON CONFLICT (tenant_id, email) DO UPDATE SET \
                    last_login = NOW(), oidc_sub = EXCLUDED.oidc_sub, oidc_issuer = EXCLUDED.oidc_issuer, \
                    auth_source = 'oidc', role = EXCLUDED.role, is_super_admin = EXCLUDED.is_super_admin, \
                    is_active = true, revoked_by_group = false \
                 WHERE (admin_accounts.oidc_sub IS NULL OR admin_accounts.oidc_sub = '' OR admin_accounts.oidc_sub = EXCLUDED.oidc_sub) \
                   AND (admin_accounts.is_active OR admin_accounts.revoked_by_group) \
                 RETURNING id, email, display_name, role, is_super_admin, is_active, created_at, last_login",
            )
            .bind(email)
            .bind(subject)
            .bind(issuer)
            .bind(role_to_apply.as_str())
            .bind(tenant_uuid)
            .bind(super_to_apply),
            IdentitySource::ProxyHeader => sqlx::query_as::<_, AdminAccountResponse>(
                "INSERT INTO admin_accounts (email, auth_source, role, tenant_id, last_login, is_super_admin) \
                 VALUES ($1, 'header', $2, $3, NOW(), $4) \
                 ON CONFLICT (tenant_id, email) DO UPDATE SET \
                    last_login = NOW(), auth_source = 'header', password_hash = NULL, \
                    role = EXCLUDED.role, is_super_admin = EXCLUDED.is_super_admin, \
                    is_active = true, revoked_by_group = false \
                 WHERE admin_accounts.is_active OR admin_accounts.revoked_by_group \
                 RETURNING id, email, display_name, role, is_super_admin, is_active, created_at, last_login",
            )
            .bind(email)
            .bind(role_to_apply.as_str())
            .bind(tenant_uuid)
            .bind(super_to_apply),
        }
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            if crate::routes::is_unique_violation(&e) {
                tracing::warn!("console provisioning: {e}");
                ApiError::forbidden("account conflict").code(ApiErrorCode::OidcIdentityConflict)
            } else {
                tracing::error!("console provisioning: {e}");
                crate::routes::db_read_error(&e, "account could not be checked")
            }
        })?
    };
    let Some(account) = account else {
        // The DO UPDATE's WHERE skipped the row: either an admin disabled the
        // account, or it is bound to a different identity. Read back which, so
        // the refusal names the right cause; a group-revoked row was skipped by
        // the identity guard, never by the disable.
        let disabled: bool = sqlx::query_scalar(
            "SELECT NOT is_active AND NOT revoked_by_group FROM admin_accounts WHERE email = $1",
        )
        .bind(email)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| {
            tracing::error!("console provisioning read-back: {e}");
            crate::routes::db_read_error(&e, "account could not be checked")
        })?
        .unwrap_or(false);
        if disabled {
            tracing::warn!(%email, auth_source, "console provisioning: refused — the account was disabled by an admin");
            return Err(ApiError::forbidden("account disabled").code(ApiErrorCode::PermissionDenied));
        }
        tracing::warn!(%email, auth_source, "console provisioning: account exists with a different identity");
        return Err(ApiError::forbidden("account exists with different OIDC identity")
            .code(ApiErrorCode::OidcIdentityConflict));
    };

    commit_provisioning(tx).await?;
    Ok(account)
}

/// The super-admin grant an identity-provisioned console account is written with.
/// On the platform tenant every console capability is that grant, so with console
/// groups configured the account holds it exactly while its groups make it an
/// Admin — joining the admin group grants it, the read-only group withdraws it,
/// like a role elsewhere. Anywhere else, or without group management, the stored
/// grant is kept (a new account starts without it).
fn super_admin_to_apply(is_system: bool, groups_configured: bool, role: AdminRole, current: bool) -> bool {
    if is_system && groups_configured { role == AdminRole::Admin } else { current }
}

async fn commit_provisioning(tx: crate::db::tenant::TenantTx<'_>) -> Result<(), ApiError> {
    tx.commit().await.map_err(|e| {
        tracing::error!("console provisioning (commit): {e}");
        crate::routes::db_read_error(&e, "account could not be checked")
    })
}

/// Refuse a subject an account cannot be bound to: empty, or carrying a
/// control character (Postgres cannot store U+0000, and no conforming provider
/// issues one). The provider's answer is refused as unusable rather than
/// failing the login on the write.
pub(crate) fn require_usable_subject(subject: &str) -> Result<(), ApiError> {
    if subject.is_empty() || subject.chars().any(char::is_control) {
        tracing::warn!("oidc provisioning: refused a subject that is empty or carries a control character");
        return Err(ApiError::bad_request("the identity provider released an unusable subject — cannot sign in")
            .code(ApiErrorCode::OidcExchangeFailed));
    }
    Ok(())
}

/// A portal user resolved from an authenticated identity.
pub struct ProvisionedPortalUser {
    pub id: Uuid,
    pub email: String,
    pub display_name: Option<String>,
    pub is_active: bool,
}

/// Resolve an authenticated identity to a portal user, creating it on first
/// sight and syncing the workspace memberships its claims entitle it to.
///
/// `claims` is every claim the identity carries, name → values. Each workspace
/// names the claim its rule reads (`oidc_claim_name`), so the whole map travels
/// rather than one pre-chosen list.
///
/// The portal has no role model to derive — every portal user is a user — so
/// this is smaller than [`provision_admin`]: a domain check, an upsert, and the
/// group-driven workspace join.
pub async fn provision_portal_user(
    db: &mut TenantConn,
    tenant_id: Uuid,
    email: &str,
    display_name: Option<&str>,
    claims: &BTreeMap<String, Vec<String>>,
    assurance: EmailAssurance,
) -> Result<ProvisionedPortalUser, ApiError> {
    // The platform tenant holds no workload — no users, keys or sessions — so no
    // identity source may mint a portal user in it. Refused here, the one door
    // every portal provisioning path goes through, rather than per caller.
    if tenant_id == crate::db::tenant::TenantId::SYSTEM.as_uuid() {
        tracing::warn!(%email, "portal provisioning: refused — the platform tenant has no portal users");
        return Err(ApiError::forbidden("the platform tenant has no portal")
            .code(ApiErrorCode::SystemTenantForbidden));
    }

    // Stored normalized — see `provision_admin`.
    let normalized = crate::routes::normalize_email(email);
    let email = normalized.as_str();
    crate::routes::require_address(email)?;

    // The address must be one somebody vouched for — for **every** login, not
    // only the one that creates the account.
    //
    // This is stricter than the console's rule, and deliberately so. A console
    // account binds to `oidc_sub` on first link, so afterwards it is recognised
    // by that subject and the address stops being what identifies it. A portal
    // user has no such binding: `users` is keyed by `(tenant_id, email)` alone,
    // so the address IS the identity on every login. Gating only creation would
    // leave the more valuable half of the attack open — an address the provider
    // never confirmed would still be handed an existing colleague's account,
    // with its keys, sessions and budget.
    if !assurance.vouched_for() {
        tracing::warn!(
            %email,
            assurance = ?assurance,
            "portal provisioning: refused an unverified email"
        );
        return Err(ApiError::forbidden(
            "the identity provider did not verify this email address",
        )
        .code(ApiErrorCode::OidcEmailNotVerified));
    }

    let allowed_domains: Option<Vec<String>> = sqlx::query_scalar(
        "SELECT allowed_domains FROM tenant_auth_configs WHERE tenant_id = $1",
    )
    .bind(tenant_id)
    .fetch_optional(db.conn())
    .await
    .map_err(|e| {
        tracing::error!("portal provisioning auth config read: {e}");
        crate::routes::db_read_error(&e, "account could not be checked")
    })?
    .flatten();

    check_allowed_domains(email, &allowed_domains)?;

    let db_err = |e: sqlx::Error| {
        tracing::error!("portal provisioning: {e}");
        crate::routes::db_read_error(&e, "account could not be checked")
    };

    // Atomic upsert: auto-provision or link an existing account. ON CONFLICT
    // rather than check-then-insert, so concurrent logins cannot race.
    //
    // Two kinds of existing row are never touched: a service account
    // (`auth_source='service'`) — adopting it would hand the sign-in that
    // account's session, keys and workspace authority — and a disabled account,
    // which a refused sign-in must leave exactly as it was (its password, its
    // last login). The conditional DO UPDATE skips both and RETURNS NOTHING;
    // which one it was is read back below only to say why.
    let upserted: Option<(Uuid, String, Option<String>, bool)> = sqlx::query_as(
        "INSERT INTO users (id, tenant_id, email, display_name, auth_source, is_active, created_at, last_login_at) \
         VALUES ($1, $2, $3, $4, 'oidc', true, NOW(), NOW()) \
         ON CONFLICT (tenant_id, email) DO UPDATE \
           SET auth_source = 'oidc', \
               password_hash = CASE WHEN users.auth_source = 'oidc' THEN users.password_hash ELSE NULL END, \
               last_login_at = NOW() \
           WHERE users.auth_source IS DISTINCT FROM 'service' AND users.is_active \
         RETURNING id, email, display_name, is_active",
    )
    .bind(Uuid::new_v4())
    .bind(tenant_id)
    .bind(email)
    // A display name is shown, never matched, so a U+0000 the provider put in
    // it is kept visible as U+FFFD rather than failing the login.
    .bind(display_name.map(|n| streamscope_core::pg_text::storable_str(n).into_owned()))
    .fetch_optional(db.conn())
    .await
    .map_err(db_err)?;
    let Some((user_id, user_email, user_display_name, is_active)) = upserted else {
        let is_service: bool = sqlx::query_scalar(
            "SELECT auth_source = 'service' FROM users WHERE tenant_id = $1 AND email = $2",
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(db.conn())
        .await
        .map_err(db_err)?
        .flatten()
        .unwrap_or(false);
        if is_service {
            tracing::warn!(%email, "portal provisioning: refused — the address belongs to a service account");
            return Err(ApiError::forbidden("this address belongs to a service account"));
        }
        return Err(ApiError::forbidden("account disabled"));
    };

    // Add the user to every workspace whose OIDC rule matches: the workspace
    // names a claim (`oidc_claim_name`) and a POSIX regex (`oidc_claim_pattern`)
    // matched against each of that claim's values. The claim is read by the
    // name the workspace stores — AD FS sends `group`, others `groups` or
    // `roles` — and a claim this login did not carry matches nothing.
    // Additive only — memberships are never removed here, so an operator's
    // manual grant survives a login that no longer carries the value.
    let synced = sqlx::query(
        r#"INSERT INTO workspace_members (workspace_id, user_id, tenant_id, role)
           SELECT w.id, $1, $2, 'member'
           FROM workspaces w
           WHERE w.oidc_claim_name IS NOT NULL
             AND w.oidc_claim_pattern IS NOT NULL
             AND EXISTS (
                 SELECT 1
                 FROM jsonb_array_elements_text(COALESCE($3::jsonb -> w.oidc_claim_name, '[]'::jsonb)) AS g
                 WHERE g ~ w.oidc_claim_pattern
             )
           ON CONFLICT (tenant_id, workspace_id, user_id) DO NOTHING"#,
    )
    .bind(user_id)
    .bind(tenant_id)
    .bind(sqlx::types::Json(claims))
    .execute(db.conn())
    .await;
    // A failed sync must not fail the login: the user is authenticated
    // either way, and a missing membership is visible and recoverable
    // where a refused login is neither.
    if let Err(e) = synced {
        tracing::warn!(email = %user_email, "OIDC workspace membership sync failed: {e}");
    }

    Ok(ProvisionedPortalUser {
        id: user_id,
        email: user_email,
        display_name: user_display_name,
        is_active,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vouched(a: EmailAssurance) -> bool {
        a.vouched_for()
    }

    #[test]
    fn on_the_platform_tenant_the_admin_group_is_the_super_admin_grant() {
        // Platform tenant, groups configured: the grant follows the role both ways.
        assert!(super_admin_to_apply(true, true, AdminRole::Admin, false));
        assert!(!super_admin_to_apply(true, true, AdminRole::ReadOnly, true));
        // Without group management, or on any other tenant, the stored grant stands.
        assert!(super_admin_to_apply(true, false, AdminRole::ReadOnly, true));
        assert!(!super_admin_to_apply(true, false, AdminRole::Admin, false));
        assert!(!super_admin_to_apply(false, true, AdminRole::Admin, false));
        assert!(super_admin_to_apply(false, true, AdminRole::ReadOnly, true));
    }

    #[test]
    fn a_subject_with_a_control_character_is_refused_before_any_write() {
        for bad in ["", "abc\0def", "\0", "line\nbreak", "tab\there"] {
            assert!(require_usable_subject(bad).is_err(), "{bad:?}");
        }
        // Positive control: the subjects providers actually issue.
        for good in ["248289761001", "00u1abcdEFGH", "AAAAAAAAAAAAAAAAAAAAAIkzqFVrSaSaFHy782bbtaQ", "user@corp|x"] {
            assert!(require_usable_subject(good).is_ok(), "{good:?}");
        }
    }

    /// Default tenant: only an explicit `true` on the standard claim vouches.
    #[test]
    fn without_the_opt_in_only_an_explicit_true_vouches() {
        assert!(vouched(oidc_email_assurance("email", Some(true), false)));
        assert!(!vouched(oidc_email_assurance("email", Some(false), false)));
        assert!(!vouched(oidc_email_assurance("email", None, false)));
    }

    /// The opt-in accepts an address the provider said nothing about.
    #[test]
    fn the_opt_in_accepts_an_unstated_address() {
        assert!(vouched(oidc_email_assurance("email", None, true)));
        assert!(vouched(oidc_email_assurance("email", Some(true), true)));
    }

    /// …and never one the provider explicitly called unverified.
    #[test]
    fn the_opt_in_never_overrides_an_explicit_false() {
        assert!(!vouched(oidc_email_assurance("email", Some(false), true)));
    }

    /// `email_verified` describes the `email` claim only: keyed on `upn`, a
    /// `true` there proves nothing about the address actually used.
    #[test]
    fn email_verified_does_not_vouch_for_another_claim() {
        assert!(!vouched(oidc_email_assurance("upn", Some(true), false)));
        assert!(!vouched(oidc_email_assurance("upn", None, false)));
        assert!(vouched(oidc_email_assurance("upn", None, true)));
        // An explicit `false` on `email` says nothing about `upn` either.
        assert!(vouched(oidc_email_assurance("upn", Some(false), true)));
    }
}
