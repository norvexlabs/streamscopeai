import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { getSetupStatus } from '#lib/server/tenant-auth.js';
import { safeSlug } from '#lib/server/slug.js';

export const load: PageServerLoad = async ({ cookies, url }) => {
  // `?select=1` (the "back to selection" link) forces the organization prompt,
  // skipping the remembered-tenant bounce that would otherwise make it a no-op.
  const forceSelect = url.searchParams.has('select');
  // If we remember the tenant slug, redirect to slug-specific login.
  const raw = cookies.get('admin_tenant');
  const slug = raw ? safeSlug(raw) : '';
  if (slug && !forceSelect) {
    redirect(303, `/login/${slug}`);
  }
  // On a single-organisation install, skip the unanswerable organization
  // prompt and go straight to that organisation's login. The prompt returns
  // once a second organisation exists; the platform's own console is reached
  // at `/system`.
  const status = await getSetupStatus();
  const single = safeSlug(status.single_tenant_slug);
  if (single && !forceSelect) {
    redirect(303, `/login/${single}`);
  }
};

export const actions: Actions = {
  default: async ({ request }) => {
    const formData = await request.formData();
    const slug = safeSlug(formData.get('slug')?.toString()?.trim().toLowerCase() || '');

    if (!slug) {
      return { error: 'Please enter your organization identifier' };
    }

    // Redirect to slug-specific login page.
    redirect(303, `/login/${slug}`);
  },
};
