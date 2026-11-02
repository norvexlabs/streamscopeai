/**
 * Type-safe portal API client for server-side (SvelteKit actions, load functions).
 *
 * Calls go directly to admin-api at `ADMIN_API_URL`, unlike the browser client
 * which calls same-origin `/api/v1/portal/*` routes that proxy to admin-api.
 */
import createClient from 'openapi-fetch';
import type { paths } from './generated/api-types';
import { clientAddressMiddleware } from './server/admin-fetch';

const ADMIN_API_URL = process.env.ADMIN_API_URL || 'http://localhost:9090';

export const portalServer = createClient<paths>({
  baseUrl: ADMIN_API_URL,
  headers: { 'Content-Type': 'application/json' },
});

// Attribute every call to the browser it is made for, not to this server.
portalServer.use(clientAddressMiddleware);
