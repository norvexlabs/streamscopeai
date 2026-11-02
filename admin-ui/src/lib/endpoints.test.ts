import { describe, expect, it } from 'vitest';
import { cellGlyph, endpointStatus, fleetOrder, isOffPassthrough, moveEndpoint, removalSummary, sentOf, serverHealthReason, upstreamAttention } from './endpoints';

const healthy = { status: 'healthy' as const, down_gateways: 0, down_since: null, reason: null };
const down = { status: 'breaker_open' as const, down_gateways: 1, down_since: '2026-09-19T10:00:00Z', reason: 'connect refused' };

describe('endpointStatus', () => {
  it('is healthy when enabled, unbroken and discovered', () => {
    expect(endpointStatus({ enabled: true, health: healthy, last_discovery: { ok: true } })).toBe('healthy');
    expect(endpointStatus({ enabled: true, health: healthy, last_discovery: null })).toBe('healthy');
  });

  it('ranks an operator disable over a breaker over a failed discovery', () => {
    const failed = { ok: false, reason: 'HTTP 404' };
    expect(endpointStatus({ enabled: false, health: down, last_discovery: failed })).toBe('disabled');
    expect(endpointStatus({ enabled: true, health: down, last_discovery: failed })).toBe('breaker_open');
    expect(endpointStatus({ enabled: true, health: healthy, last_discovery: failed })).toBe('discovery_failed');
  });
});

describe('moveEndpoint', () => {
  const ids = ['a', 'b', 'c'];

  it('swaps with the neighbour in the direction asked', () => {
    expect(moveEndpoint(ids, 'b', -1)).toEqual(['b', 'a', 'c']);
    expect(moveEndpoint(ids, 'b', 1)).toEqual(['a', 'c', 'b']);
  });

  it('refuses to move past either end or an unknown id', () => {
    expect(moveEndpoint(ids, 'a', -1)).toBeNull();
    expect(moveEndpoint(ids, 'c', 1)).toBeNull();
    expect(moveEndpoint(ids, 'x', 1)).toBeNull();
  });

  it('never mutates the input', () => {
    const input = ['a', 'b'];
    moveEndpoint(input, 'a', 1);
    expect(input).toEqual(['a', 'b']);
  });
});

describe('cellGlyph', () => {
  it('shows the membership when nothing contradicts it', () => {
    expect(cellGlyph({ state: 'listed', model_missing_reports: null })).toBe('listed');
    expect(cellGlyph({ state: 'assumed', model_missing_reports: 0 })).toBe('assumed');
    expect(cellGlyph({ state: 'not_served' })).toBe('not_served');
  });

  it('flags a model-not-found report whatever the membership claims', () => {
    expect(cellGlyph({ state: 'listed', model_missing_reports: 3 })).toBe('missing');
    expect(cellGlyph({ state: 'assumed', model_missing_reports: 1 })).toBe('missing');
  });
});

describe('removalSummary', () => {
  it('says nothing retires when every model has another endpoint', () => {
    expect(removalSummary({ retired_models: [], routes_deleted: 0, routes_disabled: 0 }, 'http://r2:8000')).toContain(
      'nothing is retired',
    );
  });

  it('names the retired models and the routes they take with them', () => {
    const s = removalSummary({ retired_models: ['sql-lora'], routes_deleted: 1, routes_disabled: 1 }, 'http://r2:8000');
    expect(s).toContain('sql-lora');
    expect(s).toContain('1 hand-built route will be disabled');
    expect(s).toContain('1 automatic route removed');
  });
});

describe('upstreamAttention', () => {
  const calm = { servers_total: 4, degraded: 0, down: 0, down_server_id: null, refused: 0, engines_silent: 0 };

  it('is ok, and says so, when every server is whole and nothing was refused', () => {
    expect(upstreamAttention(calm)).toEqual({
      count: 0,
      severity: 'ok',
      subtitle: '4 servers healthy',
      href: '/dashboard/servers',
    });
  });

  it('warns on each lesser problem on its own — one of each is enough', () => {
    expect(upstreamAttention({ ...calm, degraded: 1 }).severity).toBe('warning');
    expect(upstreamAttention({ ...calm, refused: 1 }).severity).toBe('warning');
    expect(upstreamAttention({ ...calm, engines_silent: 1 }).severity).toBe('warning');
  });

  it('is critical while any server is down, whatever else is true', () => {
    const r = upstreamAttention({ ...calm, down: 1, degraded: 2, refused: 14, down_server_id: 'abc' });
    expect(r.severity).toBe('critical');
    expect(r.count).toBe(3);
    expect(r.subtitle).toBe('1 down · 2 degraded · 14 refused');
  });

  it('opens the one down server, and the fleet when there is not exactly one', () => {
    expect(upstreamAttention({ ...calm, down: 1, down_server_id: 'abc' }).href).toBe('/dashboard/servers/abc');
    expect(upstreamAttention({ ...calm, down: 2, down_server_id: null }).href).toBe('/dashboard/servers');
  });

  it('counts only servers that are not whole — refusals are not servers', () => {
    expect(upstreamAttention({ ...calm, refused: 9 }).count).toBe(0);
  });
});

describe('fleetOrder', () => {
  const row = (name: string, health: 'healthy' | 'degraded' | 'down' | 'disabled', requests: number) => ({ name, health, requests });

  it('puts what needs acting on first, then the busiest', () => {
    const order = fleetOrder([
      row('quiet', 'healthy', 1),
      row('off', 'disabled', 500),
      row('busy', 'healthy', 90),
      row('half', 'degraded', 0),
      row('dead', 'down', 0),
    ]).map((r) => r.name);
    expect(order).toEqual(['dead', 'half', 'busy', 'quiet', 'off']);
  });

  it('breaks a tie on traffic by name, and leaves its input alone', () => {
    const input = [row('b', 'healthy', 5), row('a', 'healthy', 5)];
    expect(fleetOrder(input).map((r) => r.name)).toEqual(['a', 'b']);
    expect(input.map((r) => r.name)).toEqual(['b', 'a']);
  });
});

describe('isOffPassthrough', () => {
  it('is a pass-through that is turned off, and nothing else', () => {
    expect(isOffPassthrough({ byok: true, enabled: false })).toBe(true);
    expect(isOffPassthrough({ byok: true, enabled: true })).toBe(false);
    // A server holding its own key is never a pass-through, on or off.
    expect(isOffPassthrough({ byok: false, enabled: false })).toBe(false);
  });
});

describe('serverHealthReason', () => {
  it('says why a server is down — out everywhere, or nothing to route to', () => {
    expect(serverHealthReason({ health: 'down', endpoints_down: 2 })).toMatch(/every gateway that routes to it/);
  });

  it('counts what degrades a server, and explains nothing on a healthy one', () => {
    expect(serverHealthReason({ health: 'degraded', endpoints_down: 1 })).toMatch(/^1 endpoint out of rotation/);
    expect(serverHealthReason({ health: 'healthy', endpoints_down: 0 })).toBeNull();
  });
});

describe('sentOf', () => {
  it('leaves the refusals out: 100 attempts, 50 refused, is 50 sent', () => {
    expect(sentOf({ requests: 100, refusals: 50 })).toBe(50);
  });

  it('is every attempt when nothing was refused, and nothing when all were', () => {
    expect(sentOf({ requests: 7, refusals: 0 })).toBe(7);
    expect(sentOf({ requests: 7, refusals: 7 })).toBe(0);
  });
});
