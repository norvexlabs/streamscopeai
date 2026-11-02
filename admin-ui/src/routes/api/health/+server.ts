import type { RequestHandler } from './$types';
import { adminFetch } from '#lib/server/admin-fetch.js';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';

/**
 * Server-side health proxy: forwards to admin-api /ready (readiness) so this
 * surface reports whether the backend can do useful work (Postgres reachable,
 * not degraded) — 503 otherwise. admin-api's /health is liveness-only (always
 * 200 while the process runs) and would mask a dependency outage here.
 * No auth required — health status is not sensitive.
 */
export const GET: RequestHandler = async () => {
  try {
    const res = await adminFetch(`${ADMIN_API_URL}/ready`, {
      signal: AbortSignal.timeout(4000),
    });
    const data = await res.json();
    return new Response(JSON.stringify(data), {
      status: res.status,
      headers: { 'Content-Type': 'application/json' },
    });
  } catch {
    return new Response(JSON.stringify({ status: 'unhealthy', components: {} }), {
      status: 503,
      headers: { 'Content-Type': 'application/json' },
    });
  }
};
