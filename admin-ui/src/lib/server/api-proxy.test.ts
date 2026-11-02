import { describe, expect, it, vi } from 'vitest';

const upstream = vi.hoisted(() => ({ response: new Response(), urls: [] as string[] }));
vi.mock('#lib/server/admin-fetch.js', () => ({
  adminFetch: async (url: string) => {
    upstream.urls.push(url);
    return upstream.response;
  },
}));

import { createApiProxy } from '#lib/server/api-proxy.js';
import { apiPathOf } from '#lib/tenant.js';

type ProxyEvent = Parameters<ReturnType<typeof createApiProxy>>[0];

async function relay(url: string, headers: Record<string, string> = {}): Promise<Response> {
  upstream.response = new Response('blob', { status: 200, headers });
  const handler = createApiProxy(() => 'token');
  const event: Pick<ProxyEvent, 'request' | 'locals'> = {
    request: new Request(url),
    locals: {} as App.Locals,
  };
  const res = await handler(event as ProxyEvent);
  expect(res).toBeInstanceOf(Response);
  return res as Response;
}

const MEDIA = 'https://ui.test/portal/t/acme/api/v1/portal/audit/media/h?blob_type=chat_image';

/**
 * The proxy decides which of the API's response headers reach the browser.
 * A stored media blob is served as a document that runs nothing; the headers
 * that make it so must cross, or a blob opened in a tab (an SVG a client sent)
 * runs script on the console's origin.
 */
describe('createApiProxy response headers', () => {
  it("carries a stored blob's type and its no-script headers to the browser", async () => {
    const res = await relay(MEDIA, {
      'content-type': 'image/svg+xml',
      'x-content-type-options': 'nosniff',
      'content-security-policy': "default-src 'none'; sandbox",
    });
    expect(res.headers.get('content-type')).toBe('image/svg+xml');
    expect(res.headers.get('x-content-type-options')).toBe('nosniff');
    expect(res.headers.get('content-security-policy')).toBe("default-src 'none'; sandbox");
  });

  it('carries no header off its list', async () => {
    const res = await relay(MEDIA, { 'content-type': 'text/plain', 'set-cookie': 'a=b', 'x-internal': '1' });
    expect(res.headers.get('content-type')).toBe('text/plain');
    expect(res.headers.get('set-cookie')).toBeNull();
    expect(res.headers.get('x-internal')).toBeNull();
  });
});

/**
 * The API path is relayed as the browser sent it, still encoded: an encoded
 * `/` inside one segment (a hash, an id) never becomes a separator, so no
 * segment can climb to another API route with the viewer's token.
 */
describe('createApiProxy request path', () => {
  it('keeps an encoded segment encoded, on both planes, with its query', async () => {
    for (const base of ['https://ui.test/t/acme/api', 'https://ui.test/portal/t/acme/api']) {
      upstream.urls = [];
      await relay(`${base}/v1/admin/audit/media/..%2F..%2Fkeys%3Fx%3D?blob_type=chat_image`);
      expect(upstream.urls).toHaveLength(1);
      const sent = new URL(upstream.urls[0]);
      expect(sent.pathname).toBe('/api/v1/admin/audit/media/..%2F..%2Fkeys%3Fx%3D');
      expect(sent.search).toBe('?blob_type=chat_image');
    }
  });

  it('reads the path under either mount, and nothing off them', () => {
    expect(apiPathOf('/t/acme/api/v1/admin/users')).toBe('v1/admin/users');
    expect(apiPathOf('/portal/t/acme/api/v1/portal/keys')).toBe('v1/portal/keys');
    expect(apiPathOf('/t/acme/api/')).toBe('');
    expect(apiPathOf('/api/v1/admin/users')).toBeNull();
    expect(apiPathOf('/t/acme/sessions')).toBeNull();
  });

  it('refuses a request off the mount without calling the API', async () => {
    upstream.urls = [];
    const res = await relay('https://ui.test/elsewhere/api/v1/admin/users');
    expect(res.status).toBe(404);
    expect(upstream.urls).toHaveLength(0);
  });
});
