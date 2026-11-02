/**
 * CLI-provisioning OAuth consent page server load + actions.
 *
 * `ssai login` discovers this page from the tenant's CLI OAuth
 * metadata `authorization_endpoint`. The CLI lands the browser here with
 * the OAuth params (client_id, loopback redirect_uri, state, PKCE
 * challenge, scope, device_name). The auth gate and approve/deny flow
 * mirror the MCP consent page over the shared `#lib/server/oauth-consent.js`
 * plumbing — the user authenticates however the tenant dictates (password
 * or SSO), then approves the device, and the browser bounces to the CLI's
 * `http://127.0.0.1:<port>/callback` with the authorization code.
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

interface CliConsentParams {
  client_id: string;
  redirect_uri: string;
  state: string;
  code_challenge: string;
  code_challenge_method: string;
  scope: string;
  device_name?: string;
}

type CliAuthorizePreview = components['schemas']['CliAuthorizePreviewResponse'];

/**
 * Only `client_id` and `redirect_uri` are required here — see the MCP consent
 * page for why everything else is forwarded for the server to classify.
 */
function readConsentParams(url: URL): { params?: CliConsentParams; error?: string } {
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
      scope: url.searchParams.get('scope') || 'provision',
      device_name: url.searchParams.get('device_name') || undefined,
    },
  };
}

function consentFromForm(formData: FormData): CliConsentParams {
  return {
    client_id: formData.get('client_id')?.toString() || '',
    redirect_uri: formData.get('redirect_uri')?.toString() || '',
    state: formData.get('state')?.toString() || '',
    code_challenge: formData.get('code_challenge')?.toString() || '',
    code_challenge_method: formData.get('code_challenge_method')?.toString() || 'S256',
    scope: formData.get('scope')?.toString() || 'provision',
    device_name: formData.get('device_name')?.toString() || undefined,
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

  const portalToken = locals.portal_token;
  if (!portalToken) {
    const returnTo = `/portal/t/${slug}/cli/authorize${url.search}`;
    const error = await redirectToLogin(slug, returnTo);
    return { error, slug };
  }

  const preview = await postAuthorize<CliAuthorizePreview>(
    'cli',
    slug,
    'authorize/preview',
    portalToken,
    consent,
  );
  // See the MCP consent page for the RFC 6749 §4.1.2.1 split these two
  // branches implement: an `error` outcome could not be attributed to a
  // registered client, a `redirect` disposition could.
  if (preview.outcome === 'error') {
    return { error: preview.message, errorCode: preview.code, slug, consent };
  }
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
      'cli',
      params.slug,
      'authorize/approve',
      portalToken,
      consent,
    );
    if (approve.outcome === 'error') {
      return fail(approve.status, { error: approve.message });
    }
    if (!approve.data.redirect_to.startsWith(consent.redirect_uri)) {
      return fail(500, { error: 'Authorization server returned mismatched redirect URI' });
    }
    redirect(303, approve.data.redirect_to, { external: true });
  },

  deny: async ({ params, request, locals }) => {
    // Built by the authorization server, like the approval — see the MCP
    // consent page's deny action. The redirect target is loopback-only on this
    // surface, so the open-redirect reach is a port on the user's own machine,
    // but the parameter bundle is re-validated all the same.
    const portalToken = locals.portal_token;
    if (!portalToken) {
      return fail(401, { error: 'Session expired — please log in again.' });
    }
    const consent = consentFromForm(await request.formData());
    if (!consent.redirect_uri || !consent.client_id) {
      return fail(400, { error: 'Missing client_id or redirect_uri in form submission' });
    }
    const denied = await postAuthorize<{ redirect_to: string }>(
      'cli',
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
