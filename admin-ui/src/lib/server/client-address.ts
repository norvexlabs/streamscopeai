/**
 * The headers that carry a request's client address from this tier to
 * admin-api.
 *
 * Every call this server makes to admin-api is made on behalf of a browser, yet
 * reaches admin-api from this tier's own address. admin-api keys its per-IP
 * limiters and its audit `actor_ip` on the client address, so without these
 * headers every console user is one address: one limiter bucket for everybody.
 *
 * This tier behaves as one more reverse proxy: it appends the address it was
 * reached from to the `X-Forwarded-For` it received, and proves it is the
 * browser tier with a one-way derivation of `INTERNAL_SERVICE_SECRET` (never
 * the secret: this header rides every request, so it is the one most likely to
 * reach a log). admin-api grants the extra trusted hop only with that proof, so
 * the chain is read exactly as far as `TRUSTED_PROXY_HOPS` plus this tier — a
 * browser-written entry in front of those is never read.
 *
 * Keep the two constants identical to `BROWSER_TIER_HEADER` and
 * `BROWSER_TIER_PROOF_DOMAIN` in admin-api's `middleware/ip_rate_limit.rs` —
 * the `lint-admin-fetch.sh` lint fails when they differ.
 */
import { createHash } from 'node:crypto';
import { isIP } from 'node:net';

export const BROWSER_TIER_HEADER = 'x-streamscope-browser-tier';
const BROWSER_TIER_PROOF_DOMAIN = 'streamscope-browser-tier-hop';

/** The proof admin-api expects, or `null` when no secret is configured. */
export function browserTierProof(internalServiceSecret: string): string | null {
  if (!internalServiceSecret) return null;
  return createHash('sha256')
    .update(BROWSER_TIER_PROOF_DOMAIN)
    .update(Buffer.from([0]))
    .update(internalServiceSecret)
    .digest('hex');
}

/** Placeholder for a chain entry that is not an address — see `forwardingHeaders`. */
const NOT_AN_ADDRESS = 'unknown';

/** An address admin-api can parse (an IPv6 zone id dropped), or `null`. */
function asAddress(entry: string | null | undefined): string | null {
  const bare = entry?.trim().replace(/%.*$/, '') ?? '';
  return isIP(bare) ? bare : null;
}

export function forwardingHeaders(
  incomingForwardedFor: string | null,
  peerAddress: string | null,
  proof: string | null,
): Record<string, string> {
  // Without the address this tier was reached from, relaying the incoming
  // chain alone would make admin-api read one entry too far to the left — the
  // one a client can write.
  const peer = asAddress(peerAddress);
  if (!peer || !proof) return {};
  // Every entry keeps its POSITION: admin-api reads a fixed distance from the
  // right, so dropping an entry would shift that read onto one the client wrote.
  // An entry that is not an address is replaced by a placeholder admin-api
  // cannot parse — its read then falls back to the connection, as it would on a
  // direct call — and never passed on raw, where one non-ASCII byte would make
  // admin-api discard the whole header.
  const chain = (incomingForwardedFor ?? '')
    .split(',')
    .filter((entry) => entry.trim() !== '')
    .map((entry) => asAddress(entry) ?? NOT_AN_ADDRESS);
  return {
    'x-forwarded-for': [...chain, peer].join(', '),
    [BROWSER_TIER_HEADER]: proof,
  };
}
