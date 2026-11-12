import { describe, expect, it } from 'vitest';
import { keyUsageStart } from './portalKeyUsage.js';

describe('keyUsageStart', () => {
  it('starts today at 00:00 UTC, whatever the time of day', () => {
    expect(keyUsageStart('today', new Date('2026-11-11T23:59:59.999Z'))).toBe('2026-11-11T00:00:00.000Z');
    expect(keyUsageStart('today', new Date('2026-11-11T00:00:00.000Z'))).toBe('2026-11-11T00:00:00.000Z');
    // One millisecond before midnight is still the previous day.
    expect(keyUsageStart('today', new Date('2026-11-10T23:59:59.999Z'))).toBe('2026-11-10T00:00:00.000Z');
  });

  it('counts today as the last of the 7 or 30 days', () => {
    const now = new Date('2026-11-11T15:00:00Z');
    expect(keyUsageStart('last_7_days', now)).toBe('2026-11-05T00:00:00.000Z');
    expect(keyUsageStart('last_30_days', now)).toBe('2026-10-13T00:00:00.000Z');
  });

  it('crosses a month and a year boundary by calendar day', () => {
    expect(keyUsageStart('last_7_days', new Date('2026-03-02T08:00:00Z'))).toBe('2026-02-24T00:00:00.000Z');
    expect(keyUsageStart('last_30_days', new Date('2027-01-10T08:00:00Z'))).toBe('2026-12-12T00:00:00.000Z');
  });
});
