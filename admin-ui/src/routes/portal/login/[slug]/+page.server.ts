import { fail, redirect } from '@sveltejs/kit';
import { portalHomePath } from '#lib/home.js';
import type { Actions, PageServerLoad } from './$types';
import { getTenantAuthInfo } from '#lib/server/tenant-auth.js';
import { portalServer } from '#lib/portal-server-client.js';
import { safeReturnTo } from '#lib/server/return-to.js';
import { m } from '#lib/paraglide/messages.js';
import { cookiesAreSecure } from '#lib/server/cookie-security.js';

export const load: PageServerLoad = async ({ params, cookies, url }) => {
  if (cookies.get('portal_session')) {
    const returnTo = safeReturnTo(url.searchParams.get('return_to'));
    redirect(303, returnTo ?? portalHomePath(params.slug));
  }

  const info = await getTenantAuthInfo(params.slug);
  if (info === 'unavailable') {
    return { unavailable: true, slug: params.slug };
  }
  if (info === 'not_found') {
    return { notFound: true, slug: params.slug };
  }
  return { tenant: info };
};

export const actions: Actions = {
  default: async ({ request, cookies, params, url }) => {
    const formData = await request.formData();
    const email = formData.get('email')?.toString() || '';
    const password = formData.get('password')?.toString() || '';

    if (!email || !password) {
      return fail(400, { error: m.portal_login_email_password_required(), email });
    }

    try {
      const { data, error } = await portalServer.POST('/api/v1/portal/auth/login', {
        body: { email, password, tenant_slug: params.slug },
      });

      if (error || !data) {
        const err = error as { error?: { message?: string } | string } | undefined;
        const message = typeof err?.error === 'string'
          ? err.error
          : err?.error?.message || m.portal_login_invalid_credentials();
        return fail(401, { error: message, email });
      }

      // Path-scoped to /portal/t/<slug> so multiple tenants' portal sessions
      // coexist in one browser jar.
      cookies.set('portal_session', data.token, {
        path: `/portal/t/${params.slug}`,
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 8,
      });

      // Cross-path "last tenant" hint for the `/` landing.
      cookies.set('portal_tenant', params.slug, {
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 24 * 90,
      });
    } catch (e) {
      if (e && typeof e === 'object' && 'status' in e) throw e;
      return fail(500, { error: m.portal_login_auth_service_failed(), email });
    }

    const returnTo = safeReturnTo(url.searchParams.get('return_to'));
    redirect(303, returnTo ?? portalHomePath(params.slug));
  },
};
