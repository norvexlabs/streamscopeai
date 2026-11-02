import type { Actions } from './$types';
import { performLogout } from '#lib/server/logout.js';

export const actions: Actions = {
  // Under the tenant prefix so the path-scoped `session` cookie reaches us —
  // `locals.token` is what tells the gateway whose sessions to end.
  default: async ({ cookies, locals, params }) =>
    performLogout({ plane: 'admin', slug: params.slug, token: locals.token, cookies }),
};
