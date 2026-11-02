import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getTenantAuthInfo } from '#lib/server/tenant-auth.js';
import { adminServer } from '#lib/admin-server-client.js';
import { cookiesAreSecure } from '#lib/server/cookie-security.js';

export const load: PageServerLoad = async ({ params }) => {
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
  default: async ({ request, cookies, params }) => {
    const formData = await request.formData();
    const email = formData.get('email')?.toString() || '';
    const password = formData.get('password')?.toString() || '';

    if (!email || !password) {
      return fail(400, { error: 'Email and password are required', email });
    }

    try {
      const { data, error } = await adminServer.POST('/api/v1/auth/login', {
        body: { email, password, tenant_slug: params.slug },
      });

      if (error || !data) {
        const err = error as { error?: { message?: string } | string } | undefined;
        const message = typeof err?.error === 'string'
          ? err.error
          : err?.error?.message || 'Invalid credentials';
        return fail(401, { error: message, email });
      }

      // Path-scoped to /t/<slug> so multiple tenants' sessions coexist in one
      // browser jar (the browser sends only the cookie matching the URL path).
      cookies.set('session', data.token, {
        path: `/t/${params.slug}`,
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 8,
      });

      // Cross-path "last tenant" hint for the `/admin` and `/login` landings.
      cookies.set('admin_tenant', params.slug, {
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 24 * 90,
      });
    } catch (e) {
      if (e && typeof e === 'object' && 'status' in e) throw e;
      return fail(500, { error: 'Failed to connect to authentication service', email });
    }

    redirect(303, `/t/${params.slug}/`);
  },
};
