import type { Me } from '#lib/api-types.js';

/**
 * The console identity a request keeps from `/auth/me`, apart from the token
 * header mode is handed. `locals.user` reaches the page as layout data, where
 * script can read it, so the token never rides in it — whichever path asked.
 */
export function consoleUser(me: Me): { user: Omit<Me, 'token'>; token: string | undefined } {
  const { token, ...user } = me;
  return { user, token: token ?? undefined };
}
