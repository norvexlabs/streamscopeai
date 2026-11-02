import { redirect } from '@sveltejs/kit';
import { homePath, isPlatformOperator } from '#lib/home.js';

export function load({ locals, params, url }) {
  // Reading the path makes this guard run on every Platform navigation, not
  // only on entering the tree, so a grant removed mid-session takes effect on
  // the next page.
  void url.pathname;
  // The Platform pages read cross-tenant data only a platform operator is
  // granted: anyone else reaching one by URL lands on their own home instead.
  if (!isPlatformOperator(locals.user)) {
    redirect(302, `/t/${params.slug}${homePath(locals.user)}`);
  }
}
