/**
 * Server-side client for the gateway's OIDC login endpoints.
 *
 * The login's cryptography lives in the gateway: it mints the PKCE verifier and
 * nonce, verifies the provider's signature on the ID token, decides which plane
 * the login authenticates, and provisions the account. This tier carries the
 * browser — it sets cookies and issues redirects, which the gateway cannot do
 * because the session cookies belong to this origin and the API answers on
 * another.
 *
 * Nothing here is a secret this tier can read: `flow_token` is sealed by the
 * gateway and opaque on the way through.
 *
 * `INTERNAL_SERVICE_SECRET` says which service is calling. It does not say who
 * is signing in — that is settled by a signature the gateway checks.
 */

import { adminServer } from '#lib/admin-server-client.js';
import type { components } from '#lib/generated/api-types.js';
import {
  classifyBeginRefusal,
  classifyCallbackRefusal,
  type LoginFailure,
} from '#lib/oidc-login-errors.js';
import { extractErrorCode } from '#lib/api-helpers.js';

const INTERNAL_SERVICE_SECRET = process.env.INTERNAL_SERVICE_SECRET || '';

export type Plane = 'admin' | 'portal';
export type BeginResult = components['schemas']['BeginResponse'];
export type CallbackResult = components['schemas']['CallbackResponse'];

/** The caller-authentication header, or `null` when this tier is misconfigured. */
function serviceAuth(): Record<string, string> | null {
  if (!INTERNAL_SERVICE_SECRET) {
    console.error('INTERNAL_SERVICE_SECRET not set — cannot reach the login endpoints');
    return null;
  }
  return { Authorization: `Bearer ${INTERNAL_SERVICE_SECRET}` };
}

/**
 * Start a login. Returns where to send the browser and the sealed flow state,
 * `'unavailable'` when the gateway could not ask its database (retry later), or
 * `null` when the tenant has no login to start.
 */
export async function beginLogin(body: {
  tenant_slug: string;
  plane: string;
  prompt?: string | null;
  return_to?: string | null;
  redirect_uri: string;
}): Promise<BeginResult | 'unavailable' | null> {
  const headers = serviceAuth();
  if (!headers) return null;
  try {
    const { data, error, response } = await adminServer.POST('/api/v1/internal/oidc/begin', {
      headers,
      body,
    });
    // The gateway logs the detail and deliberately does not return it; the
    // code and status are what separate an outage from "not configured".
    if (error) {
      return classifyBeginRefusal(extractErrorCode(error), response.status) === 'unavailable'
        ? 'unavailable'
        : null;
    }
    return data ?? null;
  } catch (e) {
    // No response at all: the gateway is not reachable, which is an outage.
    console.error('OIDC begin unreachable:', e);
    return 'unavailable';
  }
}

/** Finish a login. Returns the session to set and where to land. */
export async function completeLogin(body: {
  flow_token: string;
  code: string;
  state: string;
}): Promise<{ ok: CallbackResult } | { failure: LoginFailure }> {
  const headers = serviceAuth();
  if (!headers) return { failure: 'sign_in_failed' };
  try {
    const { data, error } = await adminServer.POST('/api/v1/internal/oidc/callback', {
      headers,
      body,
    });
    if (data && !error) return { ok: data };
    // The gateway states WHY by code; the login page names that reason rather
    // than calling every refusal "no access".
    // `extractErrorCode`, not `error.error.code`: a body that is not the API's
    // envelope (a proxy's 502 page) must classify, not throw.
    return { failure: classifyCallbackRefusal(extractErrorCode(error)) };
  } catch (e) {
    // No response at all: the gateway is not reachable, which is an outage.
    console.error('OIDC callback unreachable:', e);
    return { failure: 'unavailable' };
  }
}

/**
 * The provider's RP-initiated logout URL, or `null` when it publishes none —
 * in which case the caller has already cleared its own cookies and stops there.
 *
 * The gateway drops an `id_token_hint` its own provider did not issue, so a
 * mismatched hint yields a plain logout URL rather than an error.
 */
export async function endSessionUrl(body: {
  tenant_slug: string;
  id_token_hint?: string | null;
  post_logout_redirect_uri?: string | null;
}): Promise<string | null> {
  const headers = serviceAuth();
  if (!headers) return null;
  try {
    const { data, error } = await adminServer.POST('/api/v1/internal/oidc/end-session-url', {
      headers,
      body,
    });
    if (error || !data) return null;
    return data.url ?? null;
  } catch (e) {
    console.error('OIDC end-session unreachable:', e);
    return null;
  }
}
