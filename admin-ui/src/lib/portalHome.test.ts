import { describe, expect, it } from 'vitest';
import type { PortalHome } from './api-types.js';
import { homeTodos, spendBars } from './portalHome.js';

const NOW = Date.parse('2026-11-11T12:00:00Z');
const usd = (amount: number) => ({ amount, currency: 'USD' });

function home(over: Partial<PortalHome> = {}): PortalHome {
  return {
    has_active_key: true,
    expiring_keys: [],
    mcp_sign_in: [],
    mcp_sign_in_total: 0,
    cli_version: '2026.11.29',
    cli_updates: [],
    today: { requests: 0, spend: usd(0) },
    last_7_days: { requests: 0, spend: usd(0) },
    daily: [],
    limits: null,
    team: null,
    recent_sessions: [],
    ...over,
  };
}

describe('homeTodos', () => {
  it('lists nothing for a member with nothing pending — the card hides', () => {
    expect(homeTodos(home(), NOW)).toEqual([]);
  });

  it('asks for a key only with no live key AND no traffic in 7 days', () => {
    expect(homeTodos(home({ has_active_key: false }), NOW)).toEqual([{ kind: 'no_key' }]);
    // Traffic without a key (an OAuth sign-in): set up, nothing to ask.
    expect(homeTodos(home({ has_active_key: false, last_7_days: { requests: 1, spend: usd(0) } }), NOW)).toEqual([]);
    // A live key and no traffic: nothing to ask either.
    expect(homeTodos(home({ has_active_key: true }), NOW)).toEqual([]);
  });

  it('puts an expired key before an expiring one, each group in the server order', () => {
    const key = (id: string, at: string) => ({ id, name: id, key_prefix: 'sk-' + id, expires_at: at });
    const todos = homeTodos(
      home({
        expiring_keys: [
          key('soon', '2026-11-12T00:00:00Z'),
          key('later', '2026-11-15T00:00:00Z'),
          key('gone', '2026-11-09T00:00:00Z'),
        ],
      }),
      NOW,
    );
    expect(todos.map((t) => (t.kind === 'key' ? [t.id, t.expired] : t.kind))).toEqual([
      ['gone', true],
      ['soon', false],
      ['later', false],
    ]);
  });

  it('calls a key expiring exactly now expired, and one a millisecond later not', () => {
    const at = (ms: number) => [{ id: 'k', name: null, key_prefix: 'sk-k', expires_at: new Date(ms).toISOString() }];
    const [now] = homeTodos(home({ expiring_keys: at(NOW) }), NOW);
    const [next] = homeTodos(home({ expiring_keys: at(NOW + 1) }), NOW);
    expect(now).toMatchObject({ kind: 'key', expired: true });
    expect(next).toMatchObject({ kind: 'key', expired: false });
  });

  it('lists the waiting MCP servers as one line counting every one of them', () => {
    const servers = [
      { slug: 'a', name: 'Alpha' },
      { slug: 'b', name: 'Beta' },
    ];
    expect(homeTodos(home({ mcp_sign_in: servers, mcp_sign_in_total: 7 }), NOW)).toEqual([
      { kind: 'mcp', names: ['Alpha', 'Beta'], count: 7 },
    ]);
    // A total below the listed names never undercounts them.
    expect(homeTodos(home({ mcp_sign_in: servers, mcp_sign_in_total: 0 }), NOW)).toEqual([
      { kind: 'mcp', names: ['Alpha', 'Beta'], count: 2 },
    ]);
  });

  it('names each out-of-date CLI host with the version to update to, last', () => {
    const cli = [
      { host: 'laptop', os: 'macos', version: '2026.11.9', last_seen_at: '2026-11-11T10:00:00Z' },
      { host: 'ci-01', os: 'linux', version: '2026.10.80', last_seen_at: '2026-11-10T10:00:00Z' },
    ];
    const todos = homeTodos(home({ has_active_key: false, cli_updates: cli }), NOW);
    expect(todos).toEqual([
      { kind: 'no_key' },
      { kind: 'cli', host: 'laptop', os: 'macos', version: '2026.11.9', latest: '2026.11.29' },
      { kind: 'cli', host: 'ci-01', os: 'linux', version: '2026.10.80', latest: '2026.11.29' },
    ]);
  });
});

describe('spendBars', () => {
  const day = (d: number, amount: number | null, requests = 1) => ({
    day: `2026-11-${String(d).padStart(2, '0')}T00:00:00Z`,
    requests,
    spend: amount == null ? null : usd(amount),
  });

  it('scales every bar to the highest-spending day and marks the last as today', () => {
    const bars = spendBars([day(9, 1), day(10, 4), day(11, 2)]);
    expect(bars.map((b) => b.ratio)).toEqual([0.25, 1, 0.5]);
    expect(bars.map((b) => b.today)).toEqual([false, false, true]);
    expect(bars[1]).toMatchObject({ amount: 4, currency: 'USD', requests: 1 });
  });

  it('draws a week that spent nothing flat, never dividing by zero', () => {
    const bars = spendBars([day(9, 0), day(10, 0)]);
    expect(bars.map((b) => b.ratio)).toEqual([0, 0]);
  });

  it('draws no bar for a day with two currencies and does not let it set the scale', () => {
    const bars = spendBars([day(9, null, 5), day(10, 2)]);
    expect(bars[0]).toMatchObject({ amount: null, currency: null, ratio: 0, requests: 5 });
    expect(bars[1].ratio).toBe(1);
  });

  it('is empty for no days', () => {
    expect(spendBars([])).toEqual([]);
  });
});
