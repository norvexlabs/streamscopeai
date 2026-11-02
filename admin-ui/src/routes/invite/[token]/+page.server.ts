import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { cookiesAreSecure } from '#lib/server/cookie-security.js';
import { adminFetch } from '#lib/server/admin-fetch.js';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';

export const load: PageServerLoad = async ({ params }) => {
  try {
    const res = await adminFetch(`${ADMIN_API_URL}/api/v1/invites/${params.token}`);
    if (!res.ok) {
      return { invite: { valid: false } };
    }
    const invite = await res.json();
    return { invite, token: params.token };
  } catch {
    return { invite: { valid: false } };
  }
};

export const actions: Actions = {
  default: async ({ request, cookies, params }) => {
    const formData = await request.formData();
    const email = formData.get('email')?.toString() || '';
    const password = formData.get('password')?.toString() || '';
    const confirm = formData.get('confirm')?.toString() || '';

    if (!email || !password) {
      return fail(400, { error: 'Email and password are required', email });
    }

    if (password !== confirm) {
      return fail(400, { error: 'Passwords do not match', email });
    }

    if (password.length < 8) {
      return fail(400, { error: 'Password must be at least 8 characters', email });
    }

    try {
      const res = await adminFetch(`${ADMIN_API_URL}/api/v1/invites/${params.token}/accept`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        return fail(res.status, { error: body.error?.message || body.error || 'Failed to accept invite', email });
      }

      const { token, tenant_slug } = await res.json();

      // Path-scoped to /t/<slug> (slug from the accept response) so accepting an
      // invite in one window doesn't clobber another tenant's session.
      cookies.set('session', token, {
        path: `/t/${tenant_slug}`,
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 8,
      });
      // Remember this tenant for the `/admin` and `/login` landings.
      cookies.set('admin_tenant', tenant_slug, {
        path: '/',
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 24 * 90,
      });

      redirect(303, `/t/${tenant_slug}/`);
    } catch (e) {
      if (e && typeof e === 'object' && 'status' in e) throw e;
      return fail(500, { error: 'Failed to connect to authentication service', email });
    }
  },
};
