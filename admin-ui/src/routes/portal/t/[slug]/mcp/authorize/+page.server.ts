/**
 * Spec-OAuth consent page server load + actions.
 *
 * MCP clients (Claude Desktop, Cursor, ...) discover this page from the
 * tenant's authorization-server-metadata `authorization_endpoint` field. They
 * land here with the standard OAuth query params (client_id, redirect_uri,
 * state, code_challenge, code_challenge_method, resource, scope) and either:
 *
 * 1. Need to log in first — we redirect to portal login (or OIDC if the
 *    tenant has `mcp_oauth_delegate_to_oidc=true`), preserving the consent
 *    URL in a return_to cookie so the user lands back here after auth.
 * 2. Are already logged in — we call /authorize/preview server-side using
 *    the stored portal session token, and render the "X wants to access Y"
 *    consent UI.
 *
 * On approve, we call /authorize/approve, get back the redirect_to URL with
 * `?code=...&state=...` appended, and bounce the browser there.
 *
 * On deny, we call /authorize/deny and bounce to the URL it returns — the
 * authorization server builds every authorization response, refusals included.
 */

import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { components } from '#lib/generated/api-types.js';
import {
  isValidSlug,
  postAuthorize,
  redirectToClient,
  redirectToLogin,
} from '#lib/server/oauth-consent.js';

interface ConsentParams {
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  resource: string;
  scope: string;
}

type AuthorizePreview = components['schemas']['AuthorizePreviewResponse'];

/**
 * Pull the OAuth query params.
 *
 * **Only `client_id` and `redirect_uri` are required here**, and only because
 * without them there is nobody to send an error to — RFC 6749 §4.1.2.1 then
 * forces a render. Everything else is forwarded as-is (empty when absent) so
 * the authorization server classifies it: it is the only side that knows
 * whether the redirect URI is registered, and therefore whether a missing
 * `resource` or `code_challenge` should be delivered to the client instead of
 * shown here. Rejecting them at this layer is what would leave a conforming
 * client waiting on a callback that never comes.
 *
 * `state` in particular is only RECOMMENDED by §4.1.1, so a PKCE-only client
 * may legitimately omit it.
 */
function readConsentParams(url: URL): { params?: ConsentParams; error?: string } {
  const required = ['client_id', 'redirect_uri'] as const;
  const missing = required.filter((k) => !url.searchParams.get(k));
  if (missing.length > 0) {
    return { error: `Missing required OAuth parameter(s): ${missing.join(', ')}` };
  }
  return {
    params: {
      client_id: url.searchParams.get('client_id')!,
      redirect_uri: url.searchParams.get('redirect_uri')!,
      state: url.searchParams.get('state') || '',
      code_challenge: url.searchParams.get('code_challenge') || '',
      code_challenge_method: url.searchParams.get('code_challenge_method') || '',
      resource: url.searchParams.get('resource') || '',
      scope: url.searchParams.get('scope') || 'mcp:invoke',
    },
  };
}

function consentFromForm(formData: FormData): ConsentParams {
  return {
    client_id: formData.get('client_id')?.toString() || '',
    redirect_uri: formData.get('redirect_uri')?.toString() || '',
    state: formData.get('state')?.toString() || '',
    code_challenge: formData.get('code_challenge')?.toString() || '',
    code_challenge_method: formData.get('code_challenge_method')?.toString() || 'S256',
    resource: formData.get('resource')?.toString() || '',
    scope: formData.get('scope')?.toString() || 'mcp:invoke',
  };
}

export const load: PageServerLoad = async ({ params, url, locals }) => {
  const slug = params.slug;

  if (!isValidSlug(slug)) {
    return { error: 'Invalid tenant slug', slug: '' };
  }

  const { params: consent, error: parseError } = readConsentParams(url);
  if (parseError || !consent) {
    return { error: parseError || 'Invalid consent request', slug };
  }

  // Auth gate. The hook lets unauthenticated requests through to this page so
  // we can preserve the OAuth query params; the page handles login redirects
  // itself with the right return_to plumbing.
  const portalToken = locals.portal_token;
  if (!portalToken) {
    const returnTo = `/portal/t/${slug}/mcp/authorize${url.search}`;
    const error = await redirectToLogin(slug, returnTo);
    return { error, slug };
  }

  // Authenticated — call /authorize/preview server-side so the page can
  // render the consent copy. An `error` outcome means the client itself could
  // not be identified (bad client_id, unregistered redirect_uri), which RFC
  // 6749 §4.1.2.1 says we must show the user rather than bounce.
  const preview = await postAuthorize<AuthorizePreview>('mcp', slug, 'authorize/preview', portalToken, consent);
  if (preview.outcome === 'error') {
    return { error: preview.message, errorCode: preview.code, slug, consent };
  }
  // The other half of §4.1.2.1: the client and its redirect URI are registered
  // but the request is invalid, so the error belongs at that URI. Only the
  // server knows which case this is — it holds the registration — so the
  // disposition is carried, never inferred here.
  if (preview.data.disposition === 'redirect') {
    return redirectToClient(preview.data.redirect_to, consent.redirect_uri, slug);
  }
  return { slug, consent, preview: preview.data };
};

export const actions: Actions = {
  approve: async ({ params, request, locals }) => {
    const portalToken = locals.portal_token;
    if (!portalToken) {
      return fail(401, { error: 'Session expired — please log in again.' });
    }

    const consent = consentFromForm(await request.formData());
    if (!consent.client_id || !consent.redirect_uri) {
      return fail(400, { error: 'Missing client_id or redirect_uri in form submission' });
    }

    const approve = await postAuthorize<{ redirect_to: string }>(
      'mcp',
      params.slug,
      'authorize/approve',
      portalToken,
      consent,
    );
    if (approve.outcome === 'error') {
      return fail(approve.status, { error: approve.message });
    }
    // Validate the redirect URL is the same as the one the client supplied —
    // approve already enforces this server-side, but defense-in-depth on the
    // SvelteKit boundary too.
    if (!approve.data.redirect_to.startsWith(consent.redirect_uri)) {
      return fail(500, { error: 'Authorization server returned mismatched redirect URI' });
    }
    redirect(303, approve.data.redirect_to, { external: true });
  },

  deny: async ({ params, request, locals }) => {
    // The authorization server builds this redirect, exactly as it builds the
    // approval — same `authorization_error_redirect`, same byte-exact RFC 9207
    // `iss`, same re-validation of the whole parameter bundle. That last part
    // is the anti-phishing check: without it an attacker could craft
    // `…/mcp/authorize?client_id=<real>&redirect_uri=https://attacker.example/…`,
    // bait a Deny click, and bounce the visitor off a page wearing the tenant's
    // own branding. No token leaks — the bounce is the primitive.
    const portalToken = locals.portal_token;
    if (!portalToken) {
      return fail(401, { error: 'Session expired — please log in again.' });
    }
    const consent = consentFromForm(await request.formData());
    if (!consent.redirect_uri || !consent.client_id) {
      return fail(400, { error: 'Missing client_id or redirect_uri in form submission' });
    }
    const denied = await postAuthorize<{ redirect_to: string }>(
      'mcp',
      params.slug,
      'authorize/deny',
      portalToken,
      consent,
    );
    if (denied.outcome === 'error') {
      return fail(denied.status, {
        error: denied.message || 'Refusing to redirect — OAuth parameters did not validate.',
      });
    }
    return redirectToClient(denied.data.redirect_to, consent.redirect_uri, params.slug);
  },
};
