import { describe, expect, it } from 'vitest';
import { isCrossOriginRequest } from './cross-origin.js';

const ORIGIN = 'https://console.example.com';
const h = (init: Record<string, string>) => new Headers(init);

describe('isCrossOriginRequest', () => {
  it('never refuses a safe method, whatever its headers say', () => {
    for (const m of ['GET', 'HEAD', 'OPTIONS', 'get']) {
      expect(isCrossOriginRequest(m, h({ 'sec-fetch-site': 'cross-site', origin: 'https://evil.example' }), ORIGIN), m).toBe(false);
    }
  });

  it('decides an unsafe method by Sec-Fetch-Site when the browser sends it', () => {
    for (const m of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      expect(isCrossOriginRequest(m, h({ 'sec-fetch-site': 'same-origin' }), ORIGIN), m).toBe(false);
      expect(isCrossOriginRequest(m, h({ 'sec-fetch-site': 'none' }), ORIGIN), m).toBe(false);
      expect(isCrossOriginRequest(m, h({ 'sec-fetch-site': 'same-site' }), ORIGIN), m).toBe(true);
      expect(isCrossOriginRequest(m, h({ 'sec-fetch-site': 'cross-site' }), ORIGIN), m).toBe(true);
    }
  });

  it('a matching Origin never rescues a cross-site Sec-Fetch-Site', () => {
    expect(isCrossOriginRequest('POST', h({ 'sec-fetch-site': 'same-site', origin: ORIGIN }), ORIGIN)).toBe(true);
  });

  it('falls back to Origin, which must be exactly the pinned origin', () => {
    expect(isCrossOriginRequest('POST', h({ origin: ORIGIN }), ORIGIN)).toBe(false);
    for (const other of [
      'https://evil.example',
      'https://sub.console.example.com',
      'http://console.example.com',
      'https://console.example.com:8443',
      'null',
    ]) {
      expect(isCrossOriginRequest('POST', h({ origin: other }), ORIGIN), other).toBe(true);
    }
  });

  it('without Sec-Fetch-Site, takes an Origin naming the host the request was sent to', () => {
    // A plain-http host other than localhost gets no Sec-Fetch-Site from a browser.
    const sent = (o: string, host: string) => isCrossOriginRequest('POST', h({ origin: o, host }), ORIGIN);
    expect(sent('http://console-direct:3001', 'console-direct:3001')).toBe(false);
    expect(sent('http://console-direct:3001', 'Console-Direct:3001')).toBe(false);
    expect(sent('https://evil.example', 'console-direct:3001')).toBe(true);
    expect(sent('http://console-direct:3002', 'console-direct:3001')).toBe(true);
    expect(sent('null', 'console-direct:3001')).toBe(true);
  });

  it('passes a request with neither header: no browser, no borrowed cookie', () => {
    expect(isCrossOriginRequest('POST', h({}), ORIGIN)).toBe(false);
  });
});
