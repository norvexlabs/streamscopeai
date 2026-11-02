import { describe, expect, it } from 'vitest';
import { BROWSER_TIER_HEADER, browserTierProof, forwardingHeaders } from './client-address';

describe('browserTierProof', () => {
  it('matches the derivation admin-api checks', () => {
    // Same vector as `the_browser_tier_proof_is_a_derivation_both_tiers_agree_on`.
    expect(browserTierProof('s3cret')).toBe(
      '17aa813299fc4e86513b20e0fe3149439627026ee1e6ee2331ffa839fc9dcaee',
    );
  });

  it('proves nothing without a secret', () => {
    expect(browserTierProof('')).toBeNull();
  });
});

describe('forwardingHeaders', () => {
  it('appends the address this tier was reached from to the incoming chain', () => {
    expect(forwardingHeaders('203.0.113.7', '172.18.0.2', 'p')).toEqual({
      'x-forwarded-for': '203.0.113.7, 172.18.0.2',
      [BROWSER_TIER_HEADER]: 'p',
    });
  });

  it('starts the chain when nothing was forwarded to it', () => {
    expect(forwardingHeaders(null, '203.0.113.7', 'p')['x-forwarded-for']).toBe('203.0.113.7');
    expect(forwardingHeaders('  ', '203.0.113.7', 'p')['x-forwarded-for']).toBe('203.0.113.7');
  });

  it('replaces what is not an address in place, so one bad entry cannot void the header', () => {
    expect(
      forwardingHeaders('198.51.100.66, café, 203.0.113.7:51234', '::ffff:172.18.0.2', 'p')[
        'x-forwarded-for'
      ],
    ).toBe('198.51.100.66, unknown, unknown, ::ffff:172.18.0.2');
    expect(forwardingHeaders(null, 'fe80::1%eth0', 'p')['x-forwarded-for']).toBe('fe80::1');
  });

  // PROPERTY: every entry keeps its position. admin-api reads a fixed distance
  // from the right, so an entry dropped anywhere would move that read onto one
  // the client wrote. Deliberately NOT claimed: that a bad entry survives — it is
  // replaced, and admin-api then falls back to the connection.
  it('never moves an entry: each relayed entry is the input entry at its position, or the placeholder', () => {
    const pool = ['203.0.113.7', '::1', '198.51.100.9:443', '[2001:db8::1]:80', 'unknown', 'café', '10.0.0.1', 'x'];
    let seed = 7;
    const next = () => (seed = (seed * 1103515245 + 12345) % 2147483648);
    for (let run = 0; run < 500; run++) {
      const entries = Array.from({ length: next() % 6 }, () => pool[next() % pool.length]);
      const out = forwardingHeaders(entries.join(','), '172.18.0.2', 'p')['x-forwarded-for'].split(', ');
      expect(out.length, entries.join(',')).toBe(entries.length + 1);
      expect(out[out.length - 1]).toBe('172.18.0.2');
      entries.forEach((entry, i) => {
        expect([entry, 'unknown'], entries.join(',')).toContain(out[i]);
        expect(/^[\x20-\x7e]*$/.test(out[i])).toBe(true);
      });
    }
  });

  it('claims nothing without a usable peer address of its own', () => {
    // Relaying the chain alone would shift admin-api's read one entry left,
    // onto an entry the client wrote.
    expect(forwardingHeaders('198.51.100.66', null, 'p')).toEqual({});
    expect(forwardingHeaders('198.51.100.66', ' ', 'p')).toEqual({});
    expect(forwardingHeaders('198.51.100.66', 'not-an-ip', 'p')).toEqual({});
  });

  it('claims nothing without a proof', () => {
    expect(forwardingHeaders('203.0.113.7', '172.18.0.2', null)).toEqual({});
  });
});
