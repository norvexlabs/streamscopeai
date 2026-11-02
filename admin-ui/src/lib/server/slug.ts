/**
 * A cheap guard on tenant slugs — **not** the authority on what one is.
 *
 * The gateway owns the real rule (charset, length, and a reserved-name list
 * this tier cannot see), and it applies it on every request that names a
 * tenant. What this tier needs is narrower: a slug arrives from a URL segment,
 * a cookie, or a form field, and gets interpolated into a backend URL. Without
 * a guard, junk is amplified into a round trip per request.
 *
 * So the rule here is deliberately a **superset** of the gateway's: it must
 * never reject a slug the gateway would accept, because that would be this tier
 * inventing a policy. It rejects only shapes that could not be any tenant.
 *
 * This replaced three different regexes and two `replace()`-based strippers.
 * The strippers were the dangerous shape: silently editing a slug means a
 * corrupt cookie resolves to a *different, existing* tenant rather than failing.
 */

/** Upper bound the gateway also enforces; anything longer cannot be a slug. */
const MAX_SLUG_LEN = 63;

/**
 * The slug, or `null` when the input could not be one.
 *
 * Never returns a modified string: a value is either usable as given or
 * refused.
 */
export function safeSlug(raw: string | null | undefined): string | null {
  if (!raw) return null;
  if (raw.length > MAX_SLUG_LEN) return null;
  return /^[a-z0-9][a-z0-9-]*$/.test(raw) ? raw : null;
}
