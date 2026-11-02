import type { LayoutServerLoad } from './$types';
import type { PortalMe } from '#lib/api-types.js';
import { portalServer } from '#lib/portal-server-client.js';

/**
 * Portal identity + memberships for the tenant shell.
 *
 * `hooks.server.ts` already called `/portal/auth/me` to validate the session
 * and kept the answer, so the normal path reads it from `locals` rather than
 * asking again — validating the session and loading the identity are the same
 * question, and asking it twice cost every portal page an extra round trip.
 *
 * The fetch remains for header auth mode, where the session is established from
 * proxy headers and no `/auth/me` body was read.
 */
export const load: LayoutServerLoad = async ({ locals }) => {
  let me: PortalMe | null = locals.portal_me ?? null;

  if (!me && locals.portal_token) {
    try {
      const { data } = await portalServer.GET('/api/v1/portal/auth/me', {
        headers: { Authorization: `Bearer ${locals.portal_token}` },
      });
      me = data ?? null;
    } catch {
      /* non-critical — the shell renders without the name */
    }
  }

  const portalUser = me
    ? {
        id: me.user?.id ?? '',
        email: me.user?.email ?? '',
        display_name: me.user?.display_name ?? null,
        tenant_name: me.tenant_name ?? '',
      }
    : null;

  return {
    portalUser,
    portalWorkspaces: me?.workspaces ?? [],
    // Rides the identity payload rather than a call of its own: the portal has
    // no access to the admin settings endpoint the console reads this from.
    accountingCurrency: me?.accounting_currency ?? null,
  };
};
