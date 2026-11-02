import { redirect } from '@sveltejs/kit';
import { portalHomePath } from '#lib/home.js';
import { getSetupStatus } from '#lib/server/tenant-auth.js';
import { safeSlug } from '#lib/server/slug.js';

export async function load({ cookies }) {
  // `/` is the users' entry: the portal. The portal_session cookie is
  // path-scoped to /portal/t/<slug> and is NOT sent here, so the landing keys
  // on the cross-path `portal_tenant` hint, then on the install's only
  // organisation; the tenant's own auth branch validates the session, else
  // redirects to its portal login.
  const slug = safeSlug(cookies.get('portal_tenant'));
  if (slug) redirect(303, portalHomePath(slug));
  const status = await getSetupStatus();
  if (status.needs_setup) redirect(303, '/setup');
  const single = safeSlug(status.single_tenant_slug);
  if (single) redirect(303, portalHomePath(single));
  redirect(303, '/portal/login');
}
