/**
 * The deployment-wide authentication mode, read once.
 *
 * **Two settings in this system are spelled `auth_mode` and mean different
 * things.** This one is deployment-wide (`standard` | `header`) and says
 * whether a reverse proxy in front of everything has already authenticated the
 * request. The other is per-tenant (`internal` | `oidc`) and says how that
 * tenant's users sign in. They are unrelated, and mixing them up is not
 * hypothetical: one call site here defaulted this value to `internal` — a word
 * from the *other* vocabulary, which no comparison in this tier can ever match.
 *
 * Hence one module, one default, one comparison. The gateway keeps its own copy
 * of the same environment variable because it must decide the same thing
 * independently; every deploy shape feeds both from a single source.
 */

export type AuthMode = 'standard' | 'header';

/**
 * `header` only when explicitly set. Anything unrecognised — including the
 * per-tenant vocabulary — resolves to `standard`, which is the mode that
 * requires a credential.
 */
export function authMode(): AuthMode {
  return process.env.AUTH_MODE === 'header' ? 'header' : 'standard';
}

/** Whether a reverse proxy in front of this deployment does the authenticating. */
export function isHeaderAuth(): boolean {
  return authMode() === 'header';
}
