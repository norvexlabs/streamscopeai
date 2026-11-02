import { describe, expect, it } from 'vitest';
import {
  CALLBACK_PATH,
  isFormPostCallback,
  relayLocation,
} from '../../../server/form-post-relay.js';

const form = { 'content-type': 'application/x-www-form-urlencoded' };

describe('isFormPostCallback', () => {
  it('takes a urlencoded POST to the callback, with or without a charset or query', () => {
    expect(isFormPostCallback({ method: 'POST', url: CALLBACK_PATH, headers: form })).toBe(true);
    expect(
      isFormPostCallback({
        method: 'POST',
        url: `${CALLBACK_PATH}?x=1`,
        headers: { 'content-type': 'Application/X-WWW-Form-Urlencoded; charset=UTF-8' },
      }),
    ).toBe(true);
  });

  // Everything else is SvelteKit's, CSRF check included.
  it('leaves every other request to SvelteKit', () => {
    expect(isFormPostCallback({ method: 'GET', url: CALLBACK_PATH, headers: form })).toBe(false);
    expect(isFormPostCallback({ method: 'POST', url: '/t/acme/logout', headers: form })).toBe(false);
    expect(isFormPostCallback({ method: 'POST', url: `${CALLBACK_PATH}/x`, headers: form })).toBe(false);
    expect(
      isFormPostCallback({ method: 'POST', url: CALLBACK_PATH, headers: { 'content-type': 'multipart/form-data' } }),
    ).toBe(false);
    expect(isFormPostCallback({ method: 'POST', url: CALLBACK_PATH, headers: {} })).toBe(false);
  });
});

describe('relayLocation', () => {
  it('carries code and state to the GET callback', () => {
    const next = new URL(relayLocation('code=abc%2B1&state=s-1'), 'https://ui.test');
    expect(next.pathname).toBe(CALLBACK_PATH);
    expect(next.searchParams.get('code')).toBe('abc+1');
    expect(next.searchParams.get('state')).toBe('s-1');
  });

  it('carries a provider error', () => {
    const next = new URL(relayLocation('error=access_denied&state=s-1'), 'https://ui.test');
    expect(next.searchParams.get('error')).toBe('access_denied');
  });

  // Only what the callback reads crosses over; the rest stays behind.
  it('drops every parameter the callback does not read', () => {
    const next = new URL(
      relayLocation('code=c&state=s&id_token=eyJ&session_state=x&error_description=%3Cb%3E'),
      'https://ui.test',
    );
    expect([...next.searchParams.keys()].sort()).toEqual(['code', 'state']);
  });

  it('never redirects anywhere but the callback on this origin', () => {
    expect(relayLocation('code=//evil.test&state=https://evil.test')).toMatch(/^\/auth\/oidc\/callback\?/);
    expect(relayLocation('')).toBe(`${CALLBACK_PATH}?`);
  });
});
