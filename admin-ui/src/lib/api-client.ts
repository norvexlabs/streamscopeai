/**
 * Type-safe admin API client powered by openapi-fetch.
 *
 * Generated types come from the OpenAPI spec via openapi-typescript.
 * Paths in the spec use full URLs (/api/v1/admin/...) which match
 * the SvelteKit proxy at /api/[...path].
 *
 * Usage:
 *   import { adminApi } from '#lib/api-client.js';
 *   const { data, error } = await adminApi.GET('/api/v1/admin/users');
 */
import createClient from 'openapi-fetch';
import type { paths } from './generated/api-types';
import { toast } from './toast.svelte';
import { networkErrorMiddleware } from './network-error';

export const adminApi = createClient<paths>({
  baseUrl: '',
  credentials: 'same-origin',
  headers: { 'Content-Type': 'application/json' },
});

// A rejected `fetch` (gateway down mid-upgrade, DNS/TLS failure) is rethrown by
// openapi-fetch, bypassing every `if (error)` branch in the app. Map it to a
// synthetic 503 in the server's error shape so callers keep their control flow.
// Registered FIRST so it is the last onError to run — a later middleware can
// still claim the failure before this catch-all does.
adminApi.use(networkErrorMiddleware);

// Authenticated admin routes live under /t/<slug>; the `session` cookie is
// path-scoped to that prefix, so admin API requests must travel under it for the
// cookie to be sent. The tenant root layout sets this from its `params.slug`.
//
// INVARIANT: this is read ONLY in the browser. `adminApi` is never called
// server-side (server loads use adminServer / the proxy), so a single
// module-level slug is safe — the layout also sets it during server rendering,
// but nothing there reads it. Do NOT introduce a server-side adminApi call: it
// would read another request's slug.
let currentSlug: string | null = null;
export function setApiSlug(slug: string): void {
  currentSlug = slug;
}

// Prepend /t/<slug> to /api/* requests so the path-scoped session cookie is sent
// to the moved proxy at /t/<slug>/api/[...path] (which strips the prefix before
// forwarding to the canonical admin-api). Idempotent.
//
// The body is MATERIALIZED (arrayBuffer), never restreamed: a `new Request(url,
// request)` that carries the source request's streaming body trips a Chromium
// half-duplex bug that fails the request with "Failed to fetch" on every
// POST/PUT/PATCH (e2e-verified — GETs are unaffected). Materializing the body
// into a concrete buffer sidesteps it.
adminApi.use({
  async onRequest({ request }) {
    if (!currentSlug) return undefined;
    const url = new URL(request.url);
    const prefix = `/t/${currentSlug}`;
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

// Read-only backstop: a read-only admin's mutating request is rejected by the
// server's authz chokepoint with `403 { error: { code: "read_only_account" } }`.
// The UI hides/disables most mutation controls, but this catches anything that
// slips through so the action never fails silently. The caller's own
// error-handling still runs (we return undefined → response untouched).
adminApi.use({
  async onResponse({ response }) {
    if (response.status === 403 && typeof window !== 'undefined') {
      try {
        const body = await response.clone().json();
        if (body?.error?.code === 'read_only_account') {
          toast.error('Read-only access', {
            body: 'Your account cannot make changes. Ask an administrator for write access.',
            code: 'read_only_account',
          });
        }
      } catch {
        // Non-JSON / empty 403 — not our case; let the caller handle it.
      }
    }
    return undefined;
  },
});

// Redirect to login on 401 (session expired) — matches existing api.ts behavior.
// For void 2xx responses (201 Created, 204 No Content), return a synthetic JSON body
// so openapi-fetch doesn't throw SyntaxError trying to parse an empty response.
adminApi.use({
  async onResponse({ response }) {
    if (response.status === 401 && typeof window !== 'undefined') {
      window.location.href = currentSlug ? `/login/${currentSlug}` : '/login';
    }
    // Prevent SyntaxError on empty-body 2xx responses.
    // openapi-fetch tries response.json() which fails on empty bodies.
    // 204/205 are null-body statuses per Fetch spec — the Response constructor
    // throws TypeError if given a body. Skip those entirely; openapi-fetch
    // handles them correctly when the spec declares no response content.
    if (response.ok && response.status !== 204 && response.status !== 205) {
      const cl = response.headers.get('content-length');
      const ct = response.headers.get('content-type');
      if (cl === '0' || (!cl && !ct?.includes('json'))) {
        const text = await response.clone().text();
        if (!text) {
          return new Response('{}', {
            status: response.status,
            statusText: response.statusText,
            headers: { 'Content-Type': 'application/json' },
          });
        }
      }
    }
    return undefined;
  },
});
