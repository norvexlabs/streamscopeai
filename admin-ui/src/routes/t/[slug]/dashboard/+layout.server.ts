import { redirect } from '@sveltejs/kit';
import { dashboardAdmits, homePath } from '#lib/home.js';

export function load({ locals, params }) {
  // The /dashboard tree is tenant-scoped observability. The SYSTEM tenant has
  // no customer workloads, so its accounts are sent home — this guards every
  // /dashboard/* sub-route, not just the index.
  if (!dashboardAdmits(locals.user)) {
    redirect(302, `/t/${params.slug}${homePath(locals.user)}`);
  }
}
