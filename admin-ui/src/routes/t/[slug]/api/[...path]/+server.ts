/**
 * Admin API proxy under the per-tenant prefix `/t/<slug>/api/*`.
 *
 * The admin client prepends `/t/<slug>` to its `/api/*` requests so the
 * path-scoped `session` cookie is sent here; the proxy relays the path under
 * the prefix as the browser sent it, still encoded. `locals.token` was validated for this slug in `hooks.server.ts`.
 *
 * The transport itself — header allowlists, timeout, body handling — is shared
 * with the portal plane in `#lib/server/api-proxy.js`.
 */
import { createApiProxy } from '#lib/server/api-proxy.js';

const proxy = createApiProxy((locals) => locals.token);

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
