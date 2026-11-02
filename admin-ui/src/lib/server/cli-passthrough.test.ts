import { describe, expect, it, vi } from 'vitest';

const upstream = vi.hoisted(() => ({ urls: [] as string[] }));
vi.mock('#lib/server/admin-fetch.js', () => ({
  adminFetch: async (url: string) => {
    upstream.urls.push(url);
    return new Response('ok', { status: 200 });
  },
}));

import { GET } from '../../routes/api/v1/cli/[...path]/+server.js';

type CliEvent = Parameters<typeof GET>[0];

async function get(url: string): Promise<Response> {
  const event: Pick<CliEvent, 'url'> = { url: new URL(url) };
  const res = await GET(event as CliEvent);
  expect(res).toBeInstanceOf(Response);
  return res as Response;
}

/**
 * The UI origin relays only the public CLI surface. The path is relayed as the
 * browser sent it, still encoded: an encoded `/` inside a segment never
 * becomes a separator, so no request leaves `/api/v1/cli/` for another route.
 */
describe('CLI passthrough path', () => {
  it('relays a CLI path with its query', async () => {
    upstream.urls = [];
    await get('https://ui.test/api/v1/cli/install.sh?v=1');
    expect(new URL(upstream.urls[0]).pathname).toBe('/api/v1/cli/install.sh');
    expect(new URL(upstream.urls[0]).search).toBe('?v=1');
  });

  it('relays the bare surface root as its own path', async () => {
    upstream.urls = [];
    await get('https://ui.test/api/v1/cli');
    expect(new URL(upstream.urls[0]).pathname).toBe('/api/v1/cli/');
  });

  it('keeps an encoded segment inside the CLI surface', async () => {
    upstream.urls = [];
    await get('https://ui.test/api/v1/cli/..%2F..%2Fadmin%2Fsettings');
    expect(upstream.urls).toHaveLength(1);
    expect(new URL(upstream.urls[0]).pathname).toBe('/api/v1/cli/..%2F..%2Fadmin%2Fsettings');
  });
});
