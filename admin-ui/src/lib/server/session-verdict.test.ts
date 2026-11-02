import { describe, expect, it } from 'vitest';
import { isPresentableSessionToken, sessionVerdict } from './session-verdict';

describe('sessionVerdict', () => {
  it('ends the session on an answer about it', () => {
    for (const status of [400, 401, 403, 404, 407, 409, 410, 428, 430, 499]) {
      expect(sessionVerdict(status), String(status)).toBe('refused');
    }
  });

  it('keeps the session when the answer says nothing about it', () => {
    for (const status of [199, 300, 304, 399, 408, 429, 500, 502, 503, 504, 599]) {
      expect(sessionVerdict(status), String(status)).toBe('no_verdict');
    }
  });

  it('accepts a success, and only a success', () => {
    for (const status of [200, 204, 299]) expect(sessionVerdict(status), String(status)).toBe('accepted');
  });
});

describe('isPresentableSessionToken', () => {
  it('accepts a JWT', () => {
    expect(isPresentableSessionToken('eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sig-_')).toBe(true);
  });

  it('refuses what cannot be sent as a header', () => {
    for (const bad of ['', '€', 'a\nb', 'a b', 'x'.repeat(8193)]) {
      expect(isPresentableSessionToken(bad), JSON.stringify(bad).slice(0, 20)).toBe(false);
    }
  });
});
