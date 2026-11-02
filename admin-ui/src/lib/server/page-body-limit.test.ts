import { describe, expect, it } from 'vitest';
import { PAGE_BODY_LIMIT, isApiForwarder, pageBodyVerdict } from './page-body-limit.js';

describe('pageBodyVerdict', () => {
  it('holds a page or form action to the limit, on both sides of it', () => {
    for (const path of ['/login/acme', '/t/acme/settings', '/portal/t/acme/keys', '/setup']) {
      expect(pageBodyVerdict(path, true, String(PAGE_BODY_LIMIT)), path).toBe('ok');
      expect(pageBodyVerdict(path, true, String(PAGE_BODY_LIMIT + 1)), path).toBe('too_large');
    }
  });

  it('leaves a body that declares no length to the server limit, and refuses a length that is not a number', () => {
    expect(pageBodyVerdict('/login/acme', true, null)).toBe('ok');
    for (const bad of ['', '-1', '1e9', ' 10', '0x10']) {
      expect(pageBodyVerdict('/login/acme', true, bad), bad).toBe('too_large');
    }
  });

  it('lets the API forwarders pass any body to admin-api, which decides', () => {
    for (const path of ['/t/acme/api/v1/admin/trusted-cas', '/portal/t/acme/api/v1/portal/keys']) {
      expect(pageBodyVerdict(path, true, String(PAGE_BODY_LIMIT + 1)), path).toBe('ok');
    }
    // The CLI passthrough takes no body: it is held to the page limit.
    expect(pageBodyVerdict('/api/v1/cli/whoami', true, String(PAGE_BODY_LIMIT + 1))).toBe('too_large');
  });

  it('has nothing to say about a request with no body', () => {
    expect(pageBodyVerdict('/login/acme', false, null)).toBe('ok');
  });
});

describe('isApiForwarder', () => {
  it('names only the forwarders, not a page whose path merely contains api', () => {
    expect(isApiForwarder('/t/acme/api/v1/x')).toBe(true);
    expect(isApiForwarder('/portal/t/acme/api/v1/x')).toBe(true);
    for (const path of ['/t/acme/settings/api', '/t/api/settings', '/api/live', '/api/v1/cli/x', '/x/t/acme/api/v1', '/t//api/v1']) {
      expect(isApiForwarder(path), path).toBe(false);
    }
  });
});
