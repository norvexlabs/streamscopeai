import { fail, redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { checkSetupNeeded } from '#lib/server/tenant-auth.js';
import { cookiesAreSecure } from '#lib/server/cookie-security.js';
import { adminFetch } from '#lib/server/admin-fetch.js';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';

export const load: PageServerLoad = async () => {
  const needsSetup = await checkSetupNeeded();
  if (!needsSetup) {
    redirect(303, '/login/system');
  }
  return { needsSetup: true };
};

export const actions: Actions = {
  default: async ({ request, cookies }) => {
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
      const res = await adminFetch(`${ADMIN_API_URL}/api/v1/auth/setup`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password }),
      });

      if (!res.ok) {
        const body = await res.json().catch(() => ({}));
        if (body.error?.code === 'setup_already_completed') {
          redirect(303, '/login/system');
        }
        return fail(res.status, { error: body.error?.message || body.error || 'Setup failed', email });
      }

      const { token } = await res.json();

      // Setup always provisions the SYSTEM tenant — scope its session to /t/system.
      cookies.set('session', token, {
        path: '/t/system',
        httpOnly: true,
        sameSite: 'lax',
        secure: cookiesAreSecure(),
        maxAge: 60 * 60 * 8,
      });
      // Remember SYSTEM as the last tenant for the `/login` landing.
      cookies.set('admin_tenant', 'system', {
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

    redirect(303, '/t/system/');
  },
};
