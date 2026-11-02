import { redirect } from '@sveltejs/kit';
import type { RequestHandler } from './$types';
import { beginLogin } from '#lib/server/oidc-client.js';
import { cookiesAreSecure } from '#lib/server/cookie-security.js';
import { ORIGIN } from '#lib/server/origin.js';
import { oidcRedirectUri } from '#lib/oidc-urls.js';

/**
 * GET /auth/oidc/login?tenant=<slug>[&plane=portal][&prompt=…][&return_to=/portal/…]
 *
 * Asks the gateway to start a login and bounces the browser to the provider.
 * The gateway mints the PKCE verifier and nonce and seals them into
 * `flow_token`; this tier stores that blob in a one-time cookie and cannot read
 * it. `plane` and `tenant` ride alongside in the clear — not as inputs the
 * callback trusts (the sealed copy decides) but so a failed login can be routed
 * back to the login page it came from.
 *
 * The `prompt`, `return_to` and plane rules are the gateway's; anything not
 * honoured there is simply ignored.
 */
export const GET: RequestHandler = async ({ url, cookies }) => {
  const tenantSlug = url.searchParams.get('tenant') || 'system';
  const prompt = url.searchParams.get('prompt') ?? undefined;
  const returnTo = url.searchParams.get('return_to') ?? undefined;

  const begun = await beginLogin({
    tenant_slug: tenantSlug,
    plane: url.searchParams.get('plane') === 'portal' ? 'portal' : 'admin',
    prompt,
    return_to: returnTo,
    redirect_uri: oidcRedirectUri(ORIGIN),
  });

  if (begun === 'unavailable') {
    return new Response('Sign-in is temporarily unavailable — try again in a moment', {
      status: 503,
      headers: { 'Retry-After': '5' },
    });
  }
  if (!begun) {
    return new Response('OIDC not configured for this tenant', { status: 501 });
  }

  // Freshly written per login and deleted in the callback, so each flow carries
  // exactly its own intent and none of the previous one's.
  cookies.set(
    'oidc_state',
    JSON.stringify({
      flow_token: begun.flow_token,
      tenant_slug: begun.tenant_slug,
      plane: begun.plane,
      // Routing only, like `plane`: lets the callback tell a provider that
      // refused the account chooser apart from any other refusal, and keep
      // using re-authentication once it has.
      prompt: prompt === 'select_account' || prompt === 'login' ? prompt : undefined,
      // Routing only: a refused sign-in returns to a login page that still
      // carries it, so a retry resumes (say) the MCP consent it started from.
      // The gateway re-validates it on that retry, as on this one.
      return_to: returnTo?.startsWith('/portal/') ? returnTo : undefined,
    }),
    {
      path: '/',
      httpOnly: true,
      sameSite: 'lax',
      secure: cookiesAreSecure(),
      maxAge: 60 * 10,
    },
  );

  redirect(302, begun.authorization_url, { external: true });
};
