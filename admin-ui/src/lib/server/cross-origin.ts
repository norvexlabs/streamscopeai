/**
 * Cross-origin request refusal for the console's own server (CSRF).
 *
 * Every session the console holds is a cookie, and every request carrying one
 * is turned into a bearer call to the API here — so this is the only tier that
 * can tell a request the console's own pages made from one another site's page
 * made. SvelteKit's built-in check covers form submissions only; this one
 * covers every unsafe method, the JSON API passthrough included.
 *
 * The rule is token-free, from the headers browsers set themselves (Go's
 * `CrossOriginProtection`): `Sec-Fetch-Site` when present (`same-origin`, or
 * `none` for a user-initiated navigation, passes); else `Origin`, which must be
 * the console's pinned origin or name the host the request was sent to — a
 * browser sets both `Origin` and `Host`, so another site's page cannot make
 * them agree. Browsers send no `Sec-Fetch-Site` to a plain-http host other than
 * localhost, so that fallback is what serves one. A request with neither header
 * is not from a browser — it carries no ambient cookie a forger could borrow —
 * and passes.
 */

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/** Whether the request must be refused as cross-origin. `origin` is the console's pinned origin. */
export function isCrossOriginRequest(method: string, headers: Headers, origin: string): boolean {
  if (SAFE_METHODS.has(method.toUpperCase())) return false;
  const site = headers.get('sec-fetch-site');
  if (site !== null) return site !== 'same-origin' && site !== 'none';
  const from = headers.get('origin');
  if (from === null || from === origin) return false;
  const host = headers.get('host');
  let fromHost: string;
  try {
    fromHost = new URL(from).host;
  } catch {
    return true; // `null` (an opaque origin) or anything unparsable
  }
  return host === null || fromHost !== host.toLowerCase();
}
