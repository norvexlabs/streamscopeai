/**
 * The cookie→bearer boundary, in one place for both planes.
 *
 * The browser calls `/t/<slug>/api/*` (or `/portal/t/<slug>/api/*`) rather than
 * the API origin directly, and this exchanges the path-scoped session cookie
 * for the bearer the API expects. That is the whole reason the token is
 * unreachable from JavaScript: the browser holds a cookie it cannot read, and
 * the token exists only here.
 *
 * Both planes differ by exactly two things — which `locals` key holds the token
 * and which prefix the browser used — so they are one factory, not two files.
 * They were two files, and they had drifted: response headers, timeouts and
 * body handling were each decided twice.
 */

import type { RequestHandler } from '@sveltejs/kit';
import { adminFetch } from '#lib/server/admin-fetch.js';
import { notFoundJson, unauthorizedJson, upstreamErrorJson } from '#lib/server/api-errors.js';
import { apiPathOf } from '#lib/tenant.js';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';

/** A hung API must not pin a Node connection for the lifetime of the process. */
const UPSTREAM_TIMEOUT_MS = 60_000;

/** The appliance surface waits on the host daemon — up to 90 s a call, two calls
 *  for a network change, the event journal's long poll — so its bound stays
 *  above that, or the page reports a failure for a change that went through. */
const APPLIANCE_PREFIX = 'v1/admin/global/appliance/';
const APPLIANCE_TIMEOUT_MS = 200_000;

/**
 * Request headers that may cross to the API.
 *
 * An allowlist rather than a copy: everything the caller controls arrives here,
 * and the identity headers in particular must never be relayed — under header
 * auth mode the API treats them as proof of who you are, so forwarding a
 * browser-supplied one would let any visitor name themselves.
 *
 * `Authorization` is absent deliberately. It is not forwarded from the request;
 * it is set from the session, below.
 */
const FORWARD_REQUEST_HEADERS = ['content-type', 'accept', 'accept-language'] as const;

/**
 * Response headers that may cross back.
 *
 * `content-disposition` and `cache-control` matter for the audit media blobs
 * served through here, and so do `x-content-type-options` and
 * `content-security-policy`: a stored blob is served as a document that runs
 * nothing, and dropping either here would let one opened in a tab (an SVG a
 * client sent) run script on this origin. `x-request-id` is what lets a
 * browser-side report be matched to a backend trace.
 */
const FORWARD_RESPONSE_HEADERS = [
  'content-type',
  'content-disposition',
  'cache-control',
  'x-content-type-options',
  'content-security-policy',
  'x-request-id',
  // Calls are made with `redirect: 'manual'` (see admin-fetch.ts), so a 3xx
  // reaches the browser as the redirect admin-api issued.
  'location',
] as const;

/**
 * Build the proxy handler for a plane.
 *
 * `tokenOf` reads the plane's token out of `locals`, which `hooks.server.ts`
 * populated after validating it for this slug.
 */
export function createApiProxy(
  tokenOf: (locals: App.Locals) => string | undefined,
): RequestHandler {
  return async ({ request, locals }) => {
    const token = tokenOf(locals);
    if (!token) return unauthorizedJson();

    // The path is taken from the request URL as the browser sent it, still
    // percent-encoded — never from `params.path`, which SvelteKit has decoded:
    // re-joined, a `%2F` in one segment (a hash, an id) would become a real
    // `/` and a `..%2F` would climb to another API route with this viewer's
    // token. A WHATWG URL has already resolved every dot-segment.
    const url = new URL(request.url);
    const path = apiPathOf(url.pathname);
    if (path === null) return notFoundJson();
    const upstream = `${ADMIN_API_URL}/api/${path}${url.search}`;

    const headers = new Headers();
    headers.set('Authorization', `Bearer ${token}`);
    for (const name of FORWARD_REQUEST_HEADERS) {
      const v = request.headers.get(name);
      if (v) headers.set(name, v);
    }

    // Materialized, not restreamed: a streaming body would require `duplex`
    // negotiation, and `arrayBuffer` (rather than `text`) is what keeps a
    // binary or multipart upload intact — `text` decodes as UTF-8 and corrupts
    // any byte sequence that is not valid UTF-8. The browser-side client
    // materializes for the same reason.
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    const body = hasBody ? await request.arrayBuffer() : undefined;

    let res: Response;
    try {
      res = await adminFetch(upstream, {
        method: request.method,
        headers,
        body,
        // Ends with the browser's request too: a page left mid long poll must
        // not hold the connection to the API until the deadline.
        signal: AbortSignal.any([
          request.signal,
          AbortSignal.timeout(path.startsWith(APPLIANCE_PREFIX) ? APPLIANCE_TIMEOUT_MS : UPSTREAM_TIMEOUT_MS),
        ]),
      });
    } catch (e: unknown) {
      return upstreamErrorJson(e instanceof Error && e.name === 'TimeoutError');
    }

    const responseHeaders = new Headers();
    for (const name of FORWARD_RESPONSE_HEADERS) {
      const v = res.headers.get(name);
      if (v) responseHeaders.set(name, v);
    }

    return new Response(res.body, { status: res.status, headers: responseHeaders });
  };
}
