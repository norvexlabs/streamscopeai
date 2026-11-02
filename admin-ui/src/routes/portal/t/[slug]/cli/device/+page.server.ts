/**
 * CLI device-grant approval page (RFC 8628).
 *
 * `ssai login --device` shows the user a short XXXX-XXXX code plus
 * this page's URL (usually with `?user_code=` pre-filled). The user — often
 * on a different machine from the CLI — logs into the portal (the consent
 * whitelist in hooks.server.ts lets this page run its own login redirect
 * with the return URL preserved), confirms the code matches the terminal,
 * and approves or denies. The CLI's token-endpoint poll picks the decision
 * up within its polling interval.
 */

import { fail } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import type { components } from '#lib/generated/api-types.js';
import { isValidSlug, postAuthorize, redirectToLogin } from '#lib/server/oauth-consent.js';

type DevicePreview = components['schemas']['DeviceConsentPreviewResponse'];

export const load: PageServerLoad = async ({ params, url, locals }) => {
  const slug = params.slug;
  if (!isValidSlug(slug)) {
    return { error: 'Invalid tenant slug', slug: '' };
  }

  const portalToken = locals.portal_token;
  if (!portalToken) {
    const returnTo = `/portal/t/${slug}/cli/device${url.search}`;
    const error = await redirectToLogin(slug, returnTo);
    return { error, slug };
  }

  // No code yet → render the code-entry form (the GET form below reloads
  // this page with ?user_code=).
  const userCode = url.searchParams.get('user_code')?.trim() ?? '';
  if (!userCode) {
    return { slug };
  }

  const preview = await postAuthorize<DevicePreview>('cli', slug, 'device/preview', portalToken, {
    user_code: userCode,
  });
  if (preview.outcome === 'error') {
    return { error: preview.message, errorCode: preview.code, slug, userCode };
  }
  return { slug, preview: preview.data };
};

async function postDecision(
  slug: string,
  portalToken: string | undefined,
  request: Request,
  action: 'device/approve' | 'device/deny',
) {
  if (!portalToken) {
    return fail(401, { error: 'Session expired — please log in again.' });
  }
  const userCode = (await request.formData()).get('user_code')?.toString() ?? '';
  if (!userCode) {
    return fail(400, { error: 'Missing device code in form submission' });
  }
  const result = await postAuthorize('cli', slug, action, portalToken, { user_code: userCode });
  if (result.outcome === 'error') {
    return fail(result.status, { error: result.message });
  }
  return { decided: action === 'device/approve' ? 'approved' : 'denied' };
}

export const actions: Actions = {
  approve: ({ params, request, locals }) =>
    postDecision(params.slug, locals.portal_token, request, 'device/approve'),
  deny: ({ params, request, locals }) =>
    postDecision(params.slug, locals.portal_token, request, 'device/deny'),
};
