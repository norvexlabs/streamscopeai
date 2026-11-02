import { redirect } from '@sveltejs/kit';
import type { Actions, PageServerLoad } from './$types';
import { m } from '#lib/paraglide/messages.js';
import { safeSlug } from '#lib/server/slug.js';
import { isHeaderAuth } from '#lib/server/auth-mode.js';
import { getSetupStatus } from '#lib/server/tenant-auth.js';

export const load: PageServerLoad = async ({ cookies, url }) => {
  // In header mode, portal login is handled by the IdP — redirect to portal.
  if (isHeaderAuth()) {
    redirect(303, '/');
  }
  // `?select=1` (the "back to selection" link) forces the organization prompt,
  // skipping the remembered-tenant bounce that would otherwise make it a no-op.
  const forceSelect = url.searchParams.has('select');
  // If we remember the tenant slug, redirect to slug-specific login.
  const raw = cookies.get('portal_tenant');
  const slug = raw ? safeSlug(raw) : '';
  if (slug && !forceSelect) {
    redirect(303, `/portal/login/${slug}`);
  }
  // On a single-organisation install, skip the unanswerable organization
  // prompt and go straight to that organisation's login. The prompt returns
  // once a second organisation exists.
  const status = await getSetupStatus();
  const single = safeSlug(status.single_tenant_slug);
  if (single && !forceSelect) {
    redirect(303, `/portal/login/${single}`);
  }
};

export const actions: Actions = {
  default: async ({ request }) => {
    const formData = await request.formData();
    const slug = safeSlug(formData.get('slug')?.toString()?.trim().toLowerCase() || '');

    if (!slug) {
      return { error: m.portal_login_org_identifier_required() };
    }

    // Redirect to slug-specific login page.
    redirect(303, `/portal/login/${slug}`);
  },
};
