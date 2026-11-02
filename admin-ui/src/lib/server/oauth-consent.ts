/**
 * Shared server plumbing for the first-party OAuth consent pages
 * (`/portal/t/<slug>/mcp/authorize` and `/portal/t/<slug>/cli/authorize`):
 * tenant-slug validation, auth-info lookup, the login/OIDC-delegate redirect
 * dance with return_to preservation, and the authorize preview/approve POST
 * against the matching backend surface.
 */

import { redirect } from '@sveltejs/kit';

import { getTenantAuthInfo } from '#lib/server/tenant-auth.js';
import { adminFetch } from '#lib/server/admin-fetch.js';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';

/**
 * Tenant slugs are `[a-z0-9-]+` and capped at 63 chars by the create
 * validator. Reject anything else before making backend calls — the consent
 * pages are whitelisted in `hooks.server.ts` so any string ends up in the
 * URL, and the SvelteKit edge must not amplify junk slugs into per-request
 * admin-api round-trips.
 */
export function isValidSlug(slug: string): boolean {
  // Superset of the server's tenant-slug rule (lowercase alnum + hyphens,
  // digit-leading allowed, 2-50 chars) — must never reject a valid slug.
  return /^[a-z0-9][a-z0-9-]{1,49}$/.test(slug);
}

/**
 * Bounce an unauthenticated consent visitor to login, preserving the consent
 * URL so they land back with the OAuth params intact. When the tenant has
 * `mcp_oauth_delegate_to_oidc` (first-party consent delegates straight to
 * the IdP), we skip the credential prompt and go to OIDC — the OIDC begin
 * endpoint folds the return_to into its one-time state cookie and the callback
 * honors it after creating the portal_session cookie.
 *
 * Throws the redirect; returns an error string only when the tenant doesn't
 * resolve.
 */
export async function redirectToLogin(slug: string, returnTo: string): Promise<string> {
  const tenant = await getTenantAuthInfo(slug);
  if (tenant === 'unavailable') {
    return 'Sign-in is temporarily unavailable — try again in a moment';
  }
  if (tenant === 'not_found') {
    return 'Tenant not found';
  }
  const target =
    tenant.mcp_oauth_delegate_to_oidc && tenant.auth_mode === 'oidc'
      ? `/auth/oidc/login?tenant=${encodeURIComponent(slug)}&return_to=${encodeURIComponent(returnTo)}`
      : `/portal/login/${encodeURIComponent(slug)}?return_to=${encodeURIComponent(returnTo)}`;
  redirect(303, target);
}

export type AuthorizeResult<T> =
  | { outcome: 'ok'; data: T }
  | { outcome: 'error'; status: number; message: string; code?: string };

/**
 * Bounce the browser to a redirect URL the authorization server built, after
 * confirming it targets the URI the client asked for.
 *
 * The server already validated the URI against the client's registration —
 * that is what the `redirect` disposition *means* — so this is
 * defense-in-depth on the SvelteKit boundary, the same check the approve path
 * makes. It matters because this is the one place a URL from an API response
 * turns into a navigation.
 *
 * Throws the redirect on success; returns a render-able error otherwise.
 */
export function redirectToClient(
  redirectTo: string,
  expectedPrefix: string,
  slug: string,
): { error: string; slug: string } {
  if (!redirectTo.startsWith(expectedPrefix)) {
    return { error: 'Authorization server returned mismatched redirect URI', slug };
  }
  // The client's redirect URI is its own origin (a loopback port, a custom
  // scheme), which a redirect takes only when told so.
  redirect(303, redirectTo, { external: true });
}

/**
 * POST a consent body to the matching backend surface's portal-JWT-gated
 * consent endpoint (`authorize/{preview,approve}` for the redirect flows,
 * `device/{preview,approve,deny}` for the CLI device grant) with the portal
 * session as bearer.
 */
export async function postAuthorize<T>(
  surface: 'mcp' | 'cli',
  slug: string,
  action:
    | 'authorize/preview'
    | 'authorize/approve'
    | 'authorize/deny'
    | 'device/preview'
    | 'device/approve'
    | 'device/deny',
  portalToken: string,
  body: unknown,
): Promise<AuthorizeResult<T>> {
  try {
    const res = await adminFetch(
      `${ADMIN_API_URL}/api/v1/${surface}/oauth/${encodeURIComponent(slug)}/${action}`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${portalToken}`,
        },
        body: JSON.stringify(body),
      },
    );
    if (!res.ok) {
      const data = (await res.json().catch(() => ({}))) as {
        error?: { message?: string; code?: string };
      };
      return {
        outcome: 'error',
        status: res.status,
        message: data.error?.message || `${action} failed (${res.status})`,
        code: data.error?.code,
      };
    }
    return { outcome: 'ok', data: (await res.json()) as T };
  } catch {
    return { outcome: 'error', status: 502, message: 'Failed to contact authorization server' };
  }
}
