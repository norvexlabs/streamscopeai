import { describe, expect, it } from 'vitest';
import { assignmentSummary, effectiveWait, fieldsForMode, formatWaitRange, qosModeOf, schedulerState } from './qos';

const agree = (ms: number) => ({ low_ms: ms, high_ms: ms });
const limits = { default_hold: agree(10_000), max_wait: agree(20_000) };

describe('effectiveWait', () => {
  it('is unknown while the deployment limits are', () => {
    expect(effectiveWait(5_000, null)).toBeNull();
    expect(effectiveWait(null, null)).toBeNull();
  });

  it('takes the deployment default for a class that names none', () => {
    expect(effectiveWait(null, limits)).toEqual({ low_ms: 10_000, high_ms: 10_000, source: 'default', capped: false });
  });

  it("takes the default hold as the gateways state it, never recombined from the fleet's ends", () => {
    const w = effectiveWait(null, {
      default_hold: { low_ms: 10_000, high_ms: 20_000 },
      max_wait: { low_ms: 20_000, high_ms: 60_000 },
    });
    expect(w).toEqual({ low_ms: 10_000, high_ms: 20_000, source: 'default', capped: false });
  });

  it('keeps a class wait below the maximum as it is', () => {
    expect(effectiveWait(5_000, limits)).toEqual({ low_ms: 5_000, high_ms: 5_000, source: 'class', capped: false });
  });

  it('is not capped exactly at the maximum, and is one millisecond above it', () => {
    expect(effectiveWait(20_000, limits)).toMatchObject({ high_ms: 20_000, capped: false });
    expect(effectiveWait(20_001, limits)).toMatchObject({ high_ms: 20_000, capped: true });
  });

  it('reads as capped when any gateway would cut it, and spans the gateways', () => {
    const w = effectiveWait(25_000, { default_hold: agree(10_000), max_wait: { low_ms: 20_000, high_ms: 30_000 } });
    expect(w).toEqual({ low_ms: 20_000, high_ms: 25_000, source: 'class', capped: true });
  });
});

describe('formatWaitRange', () => {
  const fmt = (ms: number) => `${ms / 1000}s`;
  it('shows one value when the gateways agree and a range when they do not', () => {
    expect(formatWaitRange(agree(10_000), fmt)).toBe('10s');
    expect(formatWaitRange({ low_ms: 10_000, high_ms: 15_000 }, fmt)).toBe('10s–15s');
  });
});

describe('assignmentSummary', () => {
  const none = { workspace_count: 0, key_count: 0, route_target_count: 0, is_default: false };
  it('names nothing for a class nothing names', () => {
    expect(assignmentSummary(none)).toEqual([]);
  });
  it('counts each kind with its own noun, singular and plural', () => {
    expect(assignmentSummary({ ...none, workspace_count: 1, key_count: 2, route_target_count: 1 })).toEqual([
      '1 workspace',
      '2 keys',
      '1 route target',
    ]);
  });
  it('states that the default class also serves everything without a class', () => {
    expect(assignmentSummary({ ...none, is_default: true })).toEqual(['everything without a class']);
    expect(assignmentSummary({ ...none, key_count: 3, is_default: true })).toEqual(['3 keys', 'and everything without a class']);
  });
});


describe('qosModeOf', () => {
  const base = { scheduling_dialect: 'none', gated: false };
  it('reads a server with no bound and no dialect as off', () => {
    expect(qosModeOf(base)).toBe('off');
  });
  it('reads a dialect with no bound as engine priority only', () => {
    expect(qosModeOf({ ...base, scheduling_dialect: 'vllm_priority' })).toBe('engine_priority');
  });
  it('reads any bound — the server\'s or one endpoint\'s — as gateway-managed, whatever the dialect', () => {
    expect(qosModeOf({ ...base, gated: true })).toBe('gateway');
    expect(qosModeOf({ scheduling_dialect: 'vllm_priority', gated: true })).toBe('gateway');
  });
});

describe('fieldsForMode', () => {
  const gw = { max_in_flight: 8, waiting_threshold: null, engine_priority: true };
  it('clears both bounds for the two modes that hold nothing', () => {
    expect(fieldsForMode('off', gw)).toEqual({ scheduling_dialect: 'none', max_in_flight: null, waiting_threshold: null, adaptive_concurrency: false });
    expect(fieldsForMode('engine_priority', { ...gw, adaptive: true })).toEqual({
      scheduling_dialect: 'vllm_priority',
      max_in_flight: null,
      waiting_threshold: null,
      adaptive_concurrency: false,
    });
  });
  it('keeps the bounds and sends priority only when the engine was started for it', () => {
    expect(fieldsForMode('gateway', gw)).toEqual({ scheduling_dialect: 'vllm_priority', max_in_flight: 8, waiting_threshold: null, adaptive_concurrency: false });
    expect(fieldsForMode('gateway', { ...gw, engine_priority: false })).toMatchObject({ scheduling_dialect: 'none' });
  });
  it('accepts gateway-managed with no server bound when an endpoint carries its own', () => {
    expect(
      fieldsForMode('gateway', { max_in_flight: null, waiting_threshold: null, engine_priority: false, endpoint_bounds: true }),
    ).toEqual({ scheduling_dialect: 'none', max_in_flight: null, waiting_threshold: null, adaptive_concurrency: false });
  });
  it('a learned limit is a bound on its own, keeps the ceiling and drops the queue bound', () => {
    expect(fieldsForMode('gateway', { max_in_flight: null, waiting_threshold: 3, engine_priority: false, adaptive: true })).toEqual({
      scheduling_dialect: 'none',
      max_in_flight: null,
      waiting_threshold: null,
      adaptive_concurrency: true,
    });
    expect(fieldsForMode('gateway', { ...gw, adaptive: true })).toMatchObject({ max_in_flight: 8, adaptive_concurrency: true });
  });
  it('refuses a learned limit while an endpoint keeps a queue bound, and not otherwise', () => {
    expect(fieldsForMode('gateway', { ...gw, adaptive: true, endpoint_queue_bounds: true })).toHaveProperty('error');
    expect(fieldsForMode('gateway', { ...gw, adaptive: false, endpoint_queue_bounds: true })).not.toHaveProperty('error');
  });
  it('refuses gateway-managed with no bound, and accepts a queue bound of zero', () => {
    expect(fieldsForMode('gateway', { max_in_flight: null, waiting_threshold: null, engine_priority: false })).toHaveProperty('error');
    expect(fieldsForMode('gateway', { max_in_flight: null, waiting_threshold: 0, engine_priority: false })).toMatchObject({
      waiting_threshold: 0,
    });
  });
  it('round-trips: every mode it writes reads back as itself', () => {
    for (const mode of ['off', 'engine_priority', 'gateway'] as const) {
      const f = fieldsForMode(mode, gw);
      const gated = !('error' in f) && (f.max_in_flight != null || f.waiting_threshold != null || f.adaptive_concurrency);
      expect('error' in f ? null : qosModeOf({ scheduling_dialect: f.scheduling_dialect, gated })).toBe(mode);
    }
  });
});

describe('schedulerState', () => {
  const quiet = { held: 0, engines_silent: 0, gated: true };
  it('says nothing without a report', () => {
    expect(schedulerState(null, 5)).toBe('unknown');
  });
  it('is idle when nothing is held or refused', () => {
    expect(schedulerState(quiet, 0)).toBe('idle');
  });
  it('is engaged from one held request', () => {
    expect(schedulerState({ ...quiet, held: 1 }, 0)).toBe('engaged');
  });
  it('ranks a refusal above a wait, and a silent engine above both', () => {
    expect(schedulerState({ ...quiet, held: 3 }, 1)).toBe('shedding');
    expect(schedulerState({ held: 3, engines_silent: 1, gated: true }, 1)).toBe('degraded');
  });
  it('says a server read only for its metrics is not gated, never idle', () => {
    expect(schedulerState({ ...quiet, gated: false }, 0)).toBe('ungated');
    expect(schedulerState({ ...quiet, gated: false }, 2)).toBe('shedding');
    expect(schedulerState({ ...quiet, gated: true }, 0)).toBe('idle');
  });
});
