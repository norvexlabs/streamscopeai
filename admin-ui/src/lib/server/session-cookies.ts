/**
 * Where each authenticated cookie lives, in one place.
 *
 * Every cookie here is scoped to a path rather than to `/`, and the scoping is
 * what makes concurrent per-tenant sessions possible: the browser sends only
 * the cookie whose path matches the URL, so several tenants' sessions coexist
 * in one jar without overwriting each other.
 *
 * That property is easy to lose one call site at a time, which is why the paths
 * are computed here and not spelled at each `cookies.set`.
 */

export type Plane = 'admin' | 'portal';

/** The session cookie's name for a plane. */
export function sessionCookieName(plane: Plane): string {
  return plane === 'portal' ? 'portal_session' : 'session';
}

/** The path a plane's session cookie is scoped to. */
export function sessionCookiePath(plane: Plane, slug: string): string {
  return plane === 'portal' ? `/portal/t/${slug}` : `/t/${slug}`;
}

/**
 * An ID token is stored across up to `MAX_ID_TOKEN_CHUNKS` cookies.
 *
 * A browser silently drops a cookie past ~4 KB, and a token carrying group
 * claims (AD FS form_post, Entra) easily is. Sign-out needs the whole token:
 * AD FS returns the browser to `post_logout_redirect_uri` only when an
 * `id_token_hint` is sent, so a token dropped for size would leave the user on
 * the provider's own signed-out page. Chunks, named `<name>`, `<name>.1`, … and
 * scoped to the logout path like the single cookie, keep it whole.
 *
 * Bounded (see `ID_TOKEN_CHUNK_BYTES`). A token beyond the bound is stored as
 * `ID_TOKEN_OMITTED`: sign-out
 * still ends the provider session (with the `client_id` the gateway always
 * sends), without the hint.
 */
export const ID_TOKEN_OMITTED = '-';

/**
 * 2 × 3000 bytes. Well inside a cookie's ~4096-byte limit, and — the tighter
 * bound — small enough that sign-out's `id_token_hint`, which travels in the
 * provider's end-session URL, keeps that request under AD FS's (HTTP.sys)
 * 16 KB request limit alongside the provider's own cookies.
 */
const ID_TOKEN_CHUNK_BYTES = 3000;
export const MAX_ID_TOKEN_CHUNKS = 2;

/**
 * The cookie values an ID token is stored as. A JWT is base64url and dots —
 * ASCII — so slicing by character slices by byte.
 */
export function idTokenChunks(idToken: string): string[] {
  const chunks: string[] = [];
  for (let i = 0; i < idToken.length; i += ID_TOKEN_CHUNK_BYTES) {
    chunks.push(idToken.slice(i, i + ID_TOKEN_CHUNK_BYTES));
  }
  return chunks.length <= MAX_ID_TOKEN_CHUNKS && chunks.length > 0 ? chunks : [ID_TOKEN_OMITTED];
}

/** The name of chunk `index` of the ID-token cookie `name`. */
export function idTokenChunkName(name: string, index: number): string {
  return index === 0 ? name : `${name}.${index}`;
}

/** Reassemble a stored ID token from its chunks, in order, stopping at the first gap. */
export function joinIdToken(chunks: (string | undefined)[]): string | undefined {
  const present: string[] = [];
  for (const chunk of chunks) {
    if (chunk === undefined) break;
    present.push(chunk);
  }
  return present.length ? present.join('') : undefined;
}

/** The `id_token_hint` a stored ID-token cookie value can supply, if any. */
export function idTokenHint(stored: string | undefined): string | null {
  return stored && stored !== ID_TOKEN_OMITTED ? stored : null;
}

/**
 * The cookie holding the provider's ID token, kept solely as the
 * `id_token_hint` for RP-initiated logout.
 *
 * Named per plane and tenant, because a single shared slot means the last login
 * wins: signing out of one tenant would hand that tenant's identity provider an
 * ID token issued by another's. The gateway refuses such a hint, but the
 * browser should not be offering it in the first place.
 *
 * Scoped to the logout endpoint for a second reason: an ID token is a signed
 * statement about a person, and at path `/` it rides every request to this
 * origin — including static assets — for the life of the session.
 */
export function idTokenCookieName(plane: Plane, slug: string): string {
  return `oidc_id_token_${plane}_${slug}`;
}

/**
 * The only path that needs the ID token: this tenant's logout action.
 *
 * Logout lives *under* the tenant prefix for the same reason every other
 * authenticated route does — the session cookie is path-scoped, so an action at
 * the site root is never sent one and cannot tell the gateway whose sessions to
 * end.
 */
export function idTokenCookiePath(plane: Plane, slug: string): string {
  return `${sessionCookiePath(plane, slug)}/logout`;
}
