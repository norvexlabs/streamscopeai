import type { Actions } from './$types';
import { performLogout } from '#lib/server/logout.js';

export const actions: Actions = {
  // See the admin twin: the prefix is what makes the session cookie arrive.
  default: async ({ cookies, locals, params }) =>
    performLogout({ plane: 'portal', slug: params.slug, token: locals.portal_token, cookies }),
};
