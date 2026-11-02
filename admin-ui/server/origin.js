/**
 * The console's origin, pinned on every request.
 *
 * The adapter's handler takes a request's origin from its headers: the host
 * from `HOST_HEADER` (else `Host`), the scheme from `PROTOCOL_HEADER` (else
 * `https`). It reads no runtime origin setting, while one image serves every
 * install, each at its own `ORIGIN`. So the entry names two headers of its own
 * as those settings and writes them on every request from `ORIGIN`: the
 * handler then sees the deployment's origin — the one SvelteKit's CSRF check
 * compares a form POST's `Origin` against, and the one a page reads as
 * `url.origin` — whatever host or scheme the request arrived with.
 *
 * Invariant: a request's own value of either header never reaches the handler
 * — `pinOrigin` overwrites both, so a client cannot choose the origin.
 */

export const PROTOCOL_HEADER = 'x-streamscope-origin-protocol';
export const HOST_HEADER = 'x-streamscope-origin-host';

/**
 * The scheme and host of a deployment origin, refused unless it is exactly an
 * `http(s)://host[:port]` origin — a path or query would be dropped silently.
 * @param {string} raw
 * @returns {{ protocol: string, host: string }}
 */
export function parseOrigin(raw) {
  let url;
  try {
    url = new URL(raw);
  } catch {
    throw new Error(`invalid ORIGIN: ${raw}`);
  }
  if (
    (url.protocol !== 'https:' && url.protocol !== 'http:') ||
    url.pathname !== '/' ||
    url.search ||
    url.hash ||
    url.username ||
    url.password
  ) {
    throw new Error(`invalid ORIGIN: ${raw} — expected http(s)://host[:port]`);
  }
  return { protocol: url.protocol.slice(0, -1), host: url.host };
}

/**
 * Write the origin into the request's headers, replacing any value it carried.
 * @param {Record<string, string | string[] | undefined>} headers
 * @param {{ protocol: string, host: string }} origin
 */
export function pinOrigin(headers, origin) {
  headers[PROTOCOL_HEADER] = origin.protocol;
  headers[HOST_HEADER] = origin.host;
}
