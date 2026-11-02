import type { RequestHandler } from './$types';
import { adminFetch } from '#lib/server/admin-fetch.js';
import { notFoundJson } from '#lib/server/api-errors.js';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';
const CLI_ROOT = '/api/v1/cli';

/**
 * GET-only passthrough for the public CLI surface (`/api/v1/cli/*`: OAuth
 * discovery, install.sh, binary downloads, version manifest).
 *
 * The UI and the admin-API are separate vhosts on every production deploy
 * shape, but the Quickstart page hands users commands built from the page's
 * own origin (`curl <ui-origin>/api/v1/cli/install.sh | sh`,
 * `ssai login <ui-origin>/portal/t/<slug>`). This route makes those
 * URLs work: the discovery document the CLI fetches here declares the
 * canonical admin-API origin (`api_origin`), which the CLI targets for every
 * call after discovery — only the unauthenticated GETs ride the UI origin.
 *
 * No session/cookie involvement; mutating verbs are NOT proxied (the token
 * endpoints live on the API origin the discovery document points at).
 */
export const GET: RequestHandler = async ({ url }) => {
  // The path as the browser sent it, still percent-encoded — never the decoded
  // `params.path`, whose re-joined `..%2F` would leave the CLI surface for any
  // other API route. A WHATWG URL has already resolved every dot-segment.
  // The bare surface root is its own path with an empty rest.
  const path = url.pathname === CLI_ROOT ? `${CLI_ROOT}/` : url.pathname;
  if (!path.startsWith(`${CLI_ROOT}/`)) return notFoundJson();
  const upstream = `${ADMIN_API_URL}${path}${url.search}`;
  const res = await adminFetch(upstream, {
    headers: {
      // The install.sh handler embeds the requester-facing origin into the
      // script so its download step rides this same passthrough.
      'x-forwarded-proto': url.protocol.replace(':', ''),
      'x-forwarded-host': url.host,
    },
    signal: AbortSignal.timeout(30000),
  });

  const headers: Record<string, string> = {};
  // `location`: calls are made with `redirect: 'manual'` (admin-fetch.ts), so a
  // 3xx reaches the CLI as the redirect admin-api issued.
  for (const name of ['content-type', 'content-disposition', 'cache-control', 'location']) {
    const v = res.headers.get(name);
    if (v) headers[name] = v;
  }
  return new Response(res.body, { status: res.status, headers });
};
