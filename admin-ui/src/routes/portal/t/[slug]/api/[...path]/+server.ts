/**
 * Portal API proxy under the per-tenant prefix `/portal/t/<slug>/api/*`.
 *
 * The portal client prepends `/portal/t/<slug>` to its `/api/v1/portal/*`
 * requests so the path-scoped `portal_session` cookie is sent here; the proxy
 * relays the path under the prefix as the browser sent it, still encoded.
 * `locals.portal_token` was
 * validated in `hooks.server.ts`.
 *
 * The transport itself — header allowlists, timeout, body handling — is shared
 * with the admin plane in `#lib/server/api-proxy.js`.
 */
import { createApiProxy } from '#lib/server/api-proxy.js';

const proxy = createApiProxy((locals) => locals.portal_token);

export const GET = proxy;
export const POST = proxy;
export const PUT = proxy;
export const PATCH = proxy;
export const DELETE = proxy;
