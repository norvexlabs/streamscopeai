import type { RequestHandler } from './$types';

/**
 * Liveness and readiness of the console process itself: 200 whenever the server
 * answers. Touches nothing else — no page loader, no admin-api call — so a
 * probe can run it every few seconds without spending any shared budget, and a
 * backend outage never takes the console out of rotation (it serves its own
 * "unavailable" answers then). `/api/health` is the backend's readiness, for a
 * person or a monitor, never a probe.
 */
export const GET: RequestHandler = () => new Response('ok', { headers: { 'Content-Type': 'text/plain' } });
