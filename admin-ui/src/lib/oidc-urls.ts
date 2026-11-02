/**
 * The URLs an identity provider must have registered for this deployment's
 * sign-in and sign-out.
 *
 * Built in ONE place because two things must agree on them: the login and
 * logout handlers that SEND them to the provider, and the Authentication page
 * that tells an admin what to register. A provider compares them byte for byte
 * (query string included), so a page that shows a URL the handlers do not
 * send is a registration that fails at the first sign-in.
 */

export type OidcPlane = 'admin' | 'portal';

/** The platform operator tenant: console only — it has no portal users. */
export const SYSTEM_TENANT_SLUG = 'system';

/** Registration values for one tenant, as the Authentication page shows them. */
export interface OidcRegistration {
  redirectUri: string;
  adminPostLogoutUri: string;
  /** `null` for the SYSTEM tenant, which has no portal to return to. */
  portalPostLogoutUri: string | null;
}

function base(origin: string): string {
  return origin.replace(/\/+$/, '');
}

/** The one callback both planes return to — the plane rides the sealed flow. */
export function oidcRedirectUri(origin: string): string {
  return `${base(origin)}/auth/oidc/callback`;
}

/** The plane's login page for a tenant, relative to the origin. */
export function loginPath(plane: OidcPlane, slug: string): string {
  return plane === 'portal' ? `/portal/login/${slug}` : `/login/${slug}`;
}

/**
 * Where the provider sends the browser after RP-initiated logout: the plain
 * login page. The provider has just ended its own session, so the next sign-in
 * asks for credentials anyway — no `prompt` is needed, and none is sent to a
 * provider that may not support one (AD FS documents only `login` and `none`,
 * and OIDC Core lets a provider that cannot show an account chooser answer
 * `select_account` with an error).
 */
export function postLogoutRedirectUri(origin: string, plane: OidcPlane, slug: string): string {
  return `${base(origin)}${loginPath(plane, slug)}`;
}

/**
 * The login page after a sign-out that could NOT end the provider's session —
 * it publishes no end-session endpoint (Google) or the attempt failed. The
 * provider's session is still alive, so without `prompt=select_account` the
 * next sign-in would silently re-use the same account with no way to switch.
 */
export function switchAccountLoginPath(plane: OidcPlane, slug: string): string {
  return `${loginPath(plane, slug)}?prompt=select_account`;
}

export function oidcRegistration(origin: string, slug: string): OidcRegistration {
  return {
    redirectUri: oidcRedirectUri(origin),
    adminPostLogoutUri: postLogoutRedirectUri(origin, 'admin', slug),
    portalPostLogoutUri:
      slug === SYSTEM_TENANT_SLUG ? null : postLogoutRedirectUri(origin, 'portal', slug),
  };
}
