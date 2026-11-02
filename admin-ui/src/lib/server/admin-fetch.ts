/**
 * `fetch` for every call this server makes to admin-api: it adds the headers
 * that attribute the call to the browser it serves (see `client-address.ts`).
 * Outside a request there is no browser to attribute, and nothing is added.
 */
import { getRequestEvent } from '$app/server';
import type { Middleware } from 'openapi-fetch';
import { browserTierProof, forwardingHeaders } from './client-address';

const PROOF = browserTierProof(process.env.INTERNAL_SERVICE_SECRET || '');

function clientAddressHeaders(): Record<string, string> {
  let event: ReturnType<typeof getRequestEvent>;
  try {
    event = getRequestEvent();
  } catch {
    return {};
  }
  let peer: string | null = null;
  try {
    peer = event.getClientAddress();
  } catch {
    peer = null;
  }
  return forwardingHeaders(
    event.request.headers.get('x-forwarded-for'),
    peer,
    PROOF,
  );
}

/**
 * Redirects are never followed: they would re-send the proof and the client's
 * address to wherever admin-api points, and a redirect target can be a
 * tenant-configured URL. A 3xx is returned to the caller as it arrived.
 */
export function adminFetch(input: string | URL, init: RequestInit = {}): Promise<Response> {
  const headers = new Headers(init.headers);
  for (const [name, value] of Object.entries(clientAddressHeaders())) headers.set(name, value);
  return fetch(input, { ...init, headers, redirect: 'manual' });
}

/** The same attribution, and the same refusal to follow a redirect, for the typed server clients. */
export const clientAddressMiddleware: Middleware = {
  onRequest({ request }) {
    const headers = new Headers(request.headers);
    for (const [name, value] of Object.entries(clientAddressHeaders())) headers.set(name, value);
    return new Request(request, { headers, redirect: 'manual' });
  },
};
