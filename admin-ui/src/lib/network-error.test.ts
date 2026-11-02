import { describe, expect, it, vi, afterEach } from 'vitest';
import createClient from 'openapi-fetch';
import {
  networkErrorMiddleware,
  networkErrorResponse,
  NETWORK_UNREACHABLE,
} from '#lib/network-error.js';
import { extractError, extractErrorCode } from '#lib/api-helpers.js';

/**
 * The defect this closes: `openapi-fetch` RETHROWS a rejected `fetch`, so a
 * caller destructuring `{ data, error }` never reaches its error branch when
 * the server is unreachable. On the appliance page that killed the upgrade
 * tracker outright — caddy is stopped for the whole `kairos-agent upgrade`, the
 * first poll threw out of a `void`-ed async function, and the panel sat on
 * "Upgrade in progress" until the operator reloaded by hand.
 *
 * The contract asserted here is therefore about CONTROL FLOW, not wording: a
 * transport failure must arrive as `{ error }` in the same envelope the server
 * uses, and a caller-initiated abort must still throw.
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
type AnyPaths = any;

function clientWithFetch(impl: () => Promise<Response>) {
  vi.stubGlobal('fetch', vi.fn(impl));
  const api = createClient<AnyPaths>({ baseUrl: 'https://gw.example' });
  api.use(networkErrorMiddleware);
  return api;
}

afterEach(() => vi.unstubAllGlobals());

describe('networkErrorResponse', () => {
  it('is a non-ok 503 carrying the server error envelope', async () => {
    const r = networkErrorResponse();
    expect(r.ok).toBe(false);
    expect(r.status).toBe(503);
    expect(await r.json()).toEqual({
      error: { code: NETWORK_UNREACHABLE, message: expect.any(String) },
    });
  });
});

describe('networkErrorMiddleware', () => {
  it('turns a rejected fetch into { error } instead of throwing', async () => {
    const api = clientWithFetch(() => Promise.reject(new TypeError('Failed to fetch')));

    // The whole point: this line must not throw.
    const { data, error } = await (api as any).GET('/anything');

    expect(data).toBeUndefined();
    expect(extractErrorCode(error)).toBe(NETWORK_UNREACHABLE);
    expect(extractError(error)).toMatch(/cannot reach the server/i);
  });

  it('rethrows a caller-initiated abort rather than reporting an outage', async () => {
    const abort = new DOMException('The operation was aborted.', 'AbortError');
    const api = clientWithFetch(() => Promise.reject(abort));

    // A superseded request is the caller's own doing — swallowing it into a 503
    // would raise an outage toast for a cancellation nobody experienced.
    await expect((api as any).GET('/anything')).rejects.toThrow(/aborted/i);
  });

  it('positive control: a real server error still comes back verbatim', async () => {
    // Without this the suite would keep passing if the middleware started
    // claiming EVERY response as unreachable.
    const api = clientWithFetch(async () =>
      new Response(JSON.stringify({ error: { code: 'read_only_account', message: 'nope' } }), {
        status: 403,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const { error } = await (api as any).GET('/anything');
    expect(extractErrorCode(error)).toBe('read_only_account');
  });

  it('positive control: a successful response is untouched', async () => {
    const api = clientWithFetch(async () =>
      new Response(JSON.stringify({ state: 'staged' }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    );

    const { data, error } = await (api as any).GET('/anything');
    expect(error).toBeUndefined();
    expect(data).toEqual({ state: 'staged' });
  });
});
