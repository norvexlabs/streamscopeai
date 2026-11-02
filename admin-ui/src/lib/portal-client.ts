/**
 * Type-safe portal API client powered by openapi-fetch.
 *
 * Calls go to `/api/v1/portal/*` (same path as the OpenAPI spec) and are
 * served by `src/routes/api/v1/portal/[...path]/+server.ts`, which forwards
 * them to admin-api with the portal session token.
 *
 * Usage:
 *   import { portalApi } from '#lib/portal-client.js';
 *   const { data, error } = await portalApi.GET('/api/v1/portal/keys');
 */
import createClient from 'openapi-fetch';
import type { paths } from './generated/api-types';
import { networkErrorMiddleware } from './network-error';

export const portalApi = createClient<paths>({
  baseUrl: '',
  credentials: 'same-origin',
  headers: { 'Content-Type': 'application/json' },
});

// A rejected `fetch` (gateway down mid-upgrade, DNS/TLS failure) is rethrown by
// openapi-fetch, bypassing every `if (error)` branch in the app. Map it to a
// synthetic 503 in the server's error shape so callers keep their control flow.
// Registered FIRST so it is the last onError to run — a later middleware can
// still claim the failure before this catch-all does.
portalApi.use(networkErrorMiddleware);

// Authenticated portal routes live under /portal/t/<slug>; the `portal_session`
// cookie is path-scoped to that prefix, so portal API requests must travel under
// it. The portal tenant layout sets this from its `params.slug`.
//
// INVARIANT: read ONLY in the browser (portalApi is never called server-side), so
// a single module-level slug is safe — the layout also sets it during server
// rendering, but nothing there reads it.
let currentSlug: string | null = null;
export function setPortalSlug(slug: string): void {
  currentSlug = slug;
}

// Prepend /portal/t/<slug> to /api/v1/portal/* requests so the path-scoped
// portal_session cookie is sent to the moved proxy at
// /portal/t/<slug>/api/[...path] (which strips the prefix before forwarding to
// the canonical admin-api). Idempotent. The body is MATERIALIZED, never
// restreamed — a streaming-body restream trips a Chromium half-duplex bug that
// fails every POST/PUT/PATCH with "Failed to fetch" (e2e-verified).
portalApi.use({
  async onRequest({ request }) {
    if (!currentSlug) return undefined;
    const url = new URL(request.url);
    const prefix = `/portal/t/${currentSlug}`;
    if (!url.pathname.startsWith('/api/') || url.pathname.startsWith(`${prefix}/api/`)) {
      return undefined;
    }
    url.pathname = `${prefix}${url.pathname}`;
    const hasBody = request.method !== 'GET' && request.method !== 'HEAD';
    return new Request(url, {
      method: request.method,
      headers: request.headers,
      credentials: request.credentials,
      signal: request.signal,
      body: hasBody ? await request.arrayBuffer() : undefined,
    });
  },
});

// Redirect to portal login on 401 so the user can re-authenticate.
portalApi.use({
  async onResponse({ response }) {
    if (response.status === 401 && typeof window !== 'undefined') {
      window.location.href = currentSlug ? `/portal/login/${currentSlug}` : '/portal/login';
    }
    return undefined;
  },
});
