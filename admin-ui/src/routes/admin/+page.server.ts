import { redirect } from '@sveltejs/kit';
import { getSetupStatus } from '#lib/server/tenant-auth.js';
import { safeSlug } from '#lib/server/slug.js';

export async function load({ cookies }) {
  // `/admin` is the organisation administrators' entry: an organisation's
  // console, never the platform's (that is `/system`). The session cookie is
  // path-scoped to /t/<slug> and is NOT sent here, so the landing keys on the
  // cross-path `admin_tenant` hint — unless it names `system` — then on the
  // install's only organisation; the tenant's own auth branch validates the
  // session, else redirects to its login.
  const remembered = safeSlug(cookies.get('admin_tenant'));
  if (remembered && remembered !== 'system') redirect(303, `/t/${remembered}/`);
  const status = await getSetupStatus();
  if (status.needs_setup) redirect(303, '/setup');
  const single = safeSlug(status.single_tenant_slug);
  if (single) redirect(303, `/t/${single}/`);
  // `select` skips the login page's remembered-tenant bounce, which could
  // name `system`.
  redirect(303, '/login?select=1');
}
