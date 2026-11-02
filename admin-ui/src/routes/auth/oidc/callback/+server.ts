import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { completeLogin, type Plane } from '#lib/server/oidc-client.js';
import { loginPath } from '#lib/oidc-urls.js';
import type { LoginFailure } from '#lib/oidc-login-errors.js';
import { cookiesAreSecure } from '#lib/server/cookie-security.js';
import {
  MAX_ID_TOKEN_CHUNKS,
  idTokenChunkName,
  idTokenChunks,
  idTokenCookieName,
  idTokenCookiePath,
  sessionCookieName,
  sessionCookiePath,
} from '#lib/server/session-cookies.js';

const EIGHT_HOURS = 60 * 60 * 8;
const NINETY_DAYS = 60 * 60 * 24 * 90;

/**
 * GET /auth/oidc/callback — where the provider sends the browser back.
 *
 * Hands the code and state to the gateway, which verifies the ID token's
 * signature against the provider's published keys, checks the nonce it minted,
 * and provisions the account. This tier turns the answer into cookies.
 */
export const GET: RequestHandler = async ({ url, cookies }) => {
  const code = url.searchParams.get('code');
  const state = url.searchParams.get('state');
  const error = url.searchParams.get('error');

  // Only the RFC 6749 token, bounded — it is logged, never rendered.
  const providerError = error?.replace(/[^\w.-]/g, '').slice(0, 64);

  const oidcCookie = cookies.get('oidc_state');
  if (!oidcCookie) {
    // With no login state there is no login page to return to. A provider
    // refusal is still the more useful thing to say — and to log.
    if (providerError) {
      console.warn(`OIDC provider refused a sign-in with no login state: ${providerError}`);
      return new Response('The identity provider refused the sign-in — start again from the login page.', {
        status: 400,
      });
    }
    return new Response('OIDC session expired — please try again', { status: 400 });
  }

  let flowToken: string;
  // Only for choosing which login page a failure returns to. The gateway reads
  // the authoritative tenant and plane from the sealed flow token.
  let tenantSlug: string;
  let plane: Plane;
  let askedPrompt: 'select_account' | 'login' | undefined;
  let returnTo: string | undefined;
  try {
    const parsed = JSON.parse(oidcCookie);
    flowToken = parsed.flow_token;
    tenantSlug = parsed.tenant_slug || 'system';
    plane = parsed.plane === 'portal' ? 'portal' : 'admin';
    askedPrompt =
      parsed.prompt === 'select_account' || parsed.prompt === 'login' ? parsed.prompt : undefined;
    returnTo =
      typeof parsed.return_to === 'string' && parsed.return_to.startsWith('/portal/')
        ? parsed.return_to
        : undefined;
  } catch {
    return new Response('Invalid OIDC session', { status: 400 });
  }

  // Every failure lands back on the login page it started from, named by a
  // closed-vocabulary reason — never a dead-end page, and never the provider's
  // own text, which this tier cannot vouch for.
  const fail = (reason: LoginFailure, prompt?: 'login'): never => {
    const next = new URLSearchParams({ error: reason });
    if (prompt) next.set('prompt', prompt);
    if (returnTo) next.set('return_to', returnTo);
    redirect(303, `${loginPath(plane, tenantSlug)}?${next}`);
  };

  // The provider refused before issuing a code (an unregistered scope, a
  // cancelled sign-in, a prompt it cannot honour). Its RFC 6749 `error` token is
  // logged for the operator; the user is told the provider refused.
  if (error) {
    console.warn(`OIDC provider refused the sign-in for tenant ${tenantSlug}: ${providerError}`);
    // A provider that cannot show an account chooser may refuse
    // `select_account` outright (OIDC Core: `account_selection_required`; AD FS
    // documents only `login` and `none`, so it answers `invalid_request`). Only
    // THAT refusal moves the next attempt to re-authentication — the other way
    // to reach a different account. A user cancelling (`access_denied`) at a
    // provider that did show its chooser keeps the chooser.
    const refusedTheChooser =
      askedPrompt === 'select_account' &&
      (providerError === 'invalid_request' || providerError === 'account_selection_required');
    return fail('idp_refused', refusedTheChooser || askedPrompt === 'login' ? 'login' : undefined);
  }

  if (!code || !state || !flowToken) return fail('sign_in_failed');

  const outcome = await completeLogin({ flow_token: flowToken, code, state });
  // Once a provider has been asked to re-authenticate, an access denial keeps
  // asking for that rather than the chooser it may already have refused —
  // otherwise every other attempt would bounce off the provider again.
  if ('failure' in outcome) {
    return fail(outcome.failure, askedPrompt === 'login' ? 'login' : undefined);
  }
  const result = outcome.ok;

  // The login state is consumed only by a SUCCESSFUL exchange — the one outcome
  // that proves this callback came from this flow's provider (the gateway
  // matched `state` against the sealed flow). A failed one, like a provider
  // error or a callback missing its parameters, proves nothing, so a forged
  // callback cannot cancel a sign-in in progress; it expires on its own. Replay
  // is not reopened: the code a successful exchange used is spent.
  cookies.delete('oidc_state', { path: '/' });

  const secure = cookiesAreSecure();
  // The gateway decided the plane (a safe `return_to` can move a login to the
  // portal), so its answer is authoritative here — not the one this tier asked
  // for. Narrowed rather than cast: the wire type is a string.
  const authenticatedPlane: Plane = result.plane === 'portal' ? 'portal' : 'admin';

  // Path-scoped to this tenant's prefix so several tenants' sessions coexist in
  // one browser jar.
  cookies.set(sessionCookieName(authenticatedPlane), result.token, {
    path: sessionCookiePath(authenticatedPlane, result.tenant_slug),
    httpOnly: true,
    sameSite: 'lax',
    secure,
    maxAge: EIGHT_HOURS,
  });
  // Kept for RP-initiated logout, so signing out here can end the provider's
  // session too. Named per plane+tenant and scoped to the logout endpoint —
  // see `session-cookies.ts` for why neither is incidental.
  const idTokenName = idTokenCookieName(authenticatedPlane, result.tenant_slug);
  const idTokenPath = idTokenCookiePath(authenticatedPlane, result.tenant_slug);
  const chunks = idTokenChunks(result.id_token);
  for (let index = 0; index < MAX_ID_TOKEN_CHUNKS; index++) {
    const name = idTokenChunkName(idTokenName, index);
    if (index < chunks.length) {
      cookies.set(name, chunks[index], { path: idTokenPath, httpOnly: true, sameSite: 'lax', secure, maxAge: EIGHT_HOURS });
    } else {
      // A previous, longer token's tail must not be read onto this one.
      cookies.delete(name, { path: idTokenPath });
    }
  }
  // Remembers which tenant to re-authenticate against.
  cookies.set(authenticatedPlane === 'portal' ? 'portal_tenant' : 'admin_tenant', result.tenant_slug, {
    path: '/',
    httpOnly: true,
    sameSite: 'lax',
    secure,
    maxAge: NINETY_DAYS,
  });

  redirect(303, result.redirect_to);
};
