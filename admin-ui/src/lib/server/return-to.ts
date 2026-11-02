/**
 * Shared validator for `return_to` values carried across a login round-trip.
 *
 * Used by `routes/portal/login/[slug]/+page.server.ts`, which honors
 * `?return_to=` after a credentials login. The OIDC round-trip does not come
 * through here — its `return_to` rides inside the sealed flow token the API
 * mints, so the value never crosses the browser as a separate parameter.
 *
 * The single rule is "must be a same-origin path under /portal" — anything
 * else (external URL, protocol-relative `//`, non-/portal/ path, missing
 * leading slash) is rejected.
 */
export function safeReturnTo(raw: string | null | undefined): string | null {
  if (!raw) return null;
  if (!raw.startsWith('/')) return null;
  if (raw.startsWith('//')) return null; // protocol-relative — would escape origin
  if (!raw.startsWith('/portal/')) return null;
  return raw;
}
