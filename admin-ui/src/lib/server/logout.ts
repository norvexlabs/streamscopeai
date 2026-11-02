/**
 * Signing out, for both planes.
 *
 * Three things have to happen and only the first is this tier's alone:
 *
 *  1. drop this browser's cookies;
 *  2. tell the gateway to stop accepting the session — without which a token
 *     that was copied before sign-out keeps working until it expires;
 *  3. where the login came from an identity provider, end the provider's own
 *     session too, or the next visit is silently signed straight back in.
 *
 * The action lives under the tenant prefix (`/t/<slug>/logout`,
 * `/portal/t/<slug>/logout`) because step 2 needs the session cookie, and that
 * cookie is path-scoped to the prefix — an action at the site root is simply
 * never sent one.
 */

import { isRedirect, redirect } from '@sveltejs/kit';

import { adminServer } from '#lib/admin-server-client.js';
import { portalServer } from '#lib/portal-server-client.js';
import { isHeaderAuth } from '#lib/server/auth-mode.js';
import { endSessionUrl } from '#lib/server/oidc-client.js';
import { ORIGIN } from '#lib/server/origin.js';
import { loginPath, postLogoutRedirectUri, switchAccountLoginPath } from '#lib/oidc-urls.js';
import {
  MAX_ID_TOKEN_CHUNKS,
  idTokenChunkName,
  idTokenCookieName,
  idTokenCookiePath,
  idTokenHint,
  joinIdToken,
  sessionCookieName,
  sessionCookiePath,
  type Plane,
} from '#lib/server/session-cookies.js';

const AUTHELIA_LOGOUT_URL = process.env.AUTHELIA_LOGOUT_URL || '';

interface LogoutArgs {
  plane: Plane;
  slug: string;
  token: string | undefined;
  cookies: {
    get(name: string): string | undefined;
    delete(name: string, opts: { path: string }): void;
  };
}

/** Ask the gateway to stop honouring this account's sessions. Best effort. */
async function revokeServerSide(plane: Plane, token: string | undefined): Promise<void> {
  if (!token) return;
  const headers = { Authorization: `Bearer ${token}` };
  try {
    if (plane === 'portal') {
      await portalServer.POST('/api/v1/portal/auth/logout', { headers });
    } else {
      await adminServer.POST('/api/v1/auth/logout', { headers });
    }
  } catch (e) {
    // The cookies still go. A sign-out that cannot reach the API is worse than
    // one that can, but far better than one that refuses to happen.
    console.warn('sign-out could not reach the gateway; cookies cleared locally:', e);
  }
}

/** Run a sign-out and throw the redirect that ends it. */
export async function performLogout({ plane, slug, token, cookies }: LogoutArgs): Promise<never> {
  // Read the ID token before anything is deleted. Only this plane+tenant's
  // slot — a shared one would hand this tenant's provider an ID token issued
  // by another (the gateway refuses such a hint, but it should not be offered).
  const idTokenName = idTokenCookieName(plane, slug);
  const chunkNames = Array.from({ length: MAX_ID_TOKEN_CHUNKS }, (_, i) => idTokenChunkName(idTokenName, i));
  const idToken = joinIdToken(chunkNames.map((name) => cookies.get(name)));

  await revokeServerSide(plane, token);

  cookies.delete(sessionCookieName(plane), { path: sessionCookiePath(plane, slug) });
  for (const name of chunkNames) cookies.delete(name, { path: idTokenCookiePath(plane, slug) });

  // Where a sign-out lands when it could not end the provider's session: after
  // an OIDC login the provider's session is still alive — it publishes no
  // end_session_endpoint (Google) or the attempt failed — so the landing asks
  // for the account chooser (the SSO button forwards the hint to the begin
  // endpoint), or the next sign-in silently re-uses the same account. A
  // provider that DID end its session sends the browser to the plain
  // `postLogoutRedirectUri` instead: it will ask for credentials anyway.
  const loginUrl = idToken ? switchAccountLoginPath(plane, slug) : loginPath(plane, slug);

  // Header auth: the proxy in front owns the session, so it owns ending it.
  if (isHeaderAuth()) {
    redirect(303, AUTHELIA_LOGOUT_URL || (plane === 'admin' ? '/admin' : '/'), { external: true });
  }

  // RP-Initiated Logout: end the provider's SSO session too. Holding this
  // tenant's ID token is what marks the login as having come from one.
  if (idToken) {
    try {
      const logoutUrl = await endSessionUrl({
        tenant_slug: slug,
        id_token_hint: idTokenHint(idToken),
        post_logout_redirect_uri: postLogoutRedirectUri(ORIGIN, plane, slug),
      });
      // The provider's end-session endpoint is another origin, which a
      // redirect takes only when told so — refused, it would read below as a
      // failed logout and quietly sign out locally only.
      if (logoutUrl) redirect(303, logoutUrl, { external: true });
    } catch (e: unknown) {
      if (isRedirect(e)) throw e;
      console.warn('RP-Initiated Logout failed, falling back to local sign-out:', e);
    }
  }

  redirect(303, loginUrl);
}
