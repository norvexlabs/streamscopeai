import { describe, expect, it } from 'vitest';
import { HOST_HEADER, PROTOCOL_HEADER, parseOrigin, pinOrigin } from '../../../server/origin.js';

describe('parseOrigin', () => {
  it('takes an http(s) origin, with a port or a trailing slash', () => {
    expect(parseOrigin('https://console.example.com')).toEqual({ protocol: 'https', host: 'console.example.com' });
    expect(parseOrigin('http://127.0.0.1:8080/')).toEqual({ protocol: 'http', host: '127.0.0.1:8080' });
  });

  // Each of these would otherwise pin something other than the origin it names.
  it('refuses anything that is not exactly an origin', () => {
    for (const raw of [
      'console.example.com',
      'ftp://console.example.com',
      'https://console.example.com/t/acme',
      'https://console.example.com?x=1',
      'https://console.example.com#x',
      'https://user:pw@console.example.com',
    ]) {
      expect(() => parseOrigin(raw), raw).toThrow(/invalid ORIGIN/);
    }
  });
});

describe('pinOrigin', () => {
  it('a_request_never_chooses_the_origin', () => {
    const headers: Record<string, string | string[] | undefined> = {
      host: 'attacker.example',
      [PROTOCOL_HEADER]: 'http',
      [HOST_HEADER]: 'attacker.example',
    };
    pinOrigin(headers, parseOrigin('https://console.example.com'));
    expect(headers[PROTOCOL_HEADER]).toBe('https');
    expect(headers[HOST_HEADER]).toBe('console.example.com');
  });

  it('sets both headers on a request that carried neither', () => {
    const headers: Record<string, string | string[] | undefined> = {};
    pinOrigin(headers, parseOrigin('http://127.0.0.1:8080'));
    expect(headers).toEqual({ [PROTOCOL_HEADER]: 'http', [HOST_HEADER]: '127.0.0.1:8080' });
  });
});
