import { describe, expect, it } from 'vitest';
import { connectionPlan, missingValueCount, serversNeedingConnection } from './connectionState';

const required = (filled: boolean, def: string | null = null) => ({ is_required: true, filled, default: def });

describe('connectionPlan', () => {
  it('reads a connected upstream as done, with no action', () => {
    expect(connectionPlan({ kind: 'oauth', status: 'connected', signed_in: true, inputs: [] })).toEqual({ state: 'connected', primary: null, steps: [] });
    expect(connectionPlan({ kind: 'inputs', status: 'connected', signed_in: false, inputs: [required(true)] }).primary).toBeNull();
  });

  it('asks for values when a required input is unfilled', () => {
    expect(connectionPlan({ kind: 'inputs', status: 'not_connected', signed_in: false, inputs: [required(false)] })).toMatchObject({
      state: 'needs_values',
      primary: 'values',
    });
  });

  it('counts a required input with a default as filled', () => {
    expect(missingValueCount({ kind: 'inputs', status: 'connected', signed_in: false, inputs: [required(false, 'eu')] })).toBe(0);
    // An empty default is a default, as the gateway counts it; no default is a missing value.
    expect(missingValueCount({ kind: 'inputs', status: 'connected', signed_in: false, inputs: [required(false, '')] })).toBe(0);
    expect(missingValueCount({ kind: 'inputs', status: 'not_connected', signed_in: false, inputs: [required(false, null)] })).toBe(1);
  });

  it('asks for a sign-in on an OAuth upstream without a credential', () => {
    expect(connectionPlan({ kind: 'oauth', status: 'not_connected', signed_in: false, inputs: [] })).toMatchObject({
      state: 'needs_sign_in',
      primary: 'sign_in',
    });
  });

  it('offers to reconnect an expired sign-in', () => {
    expect(connectionPlan({ kind: 'oauth', status: 'expired', signed_in: false, inputs: [] })).toMatchObject({ state: 'expired', primary: 'reconnect' });
  });

  it('orders values before the sign-in on an upstream needing both', () => {
    const both = connectionPlan({ kind: 'oauth_inputs', status: 'not_connected', signed_in: false, inputs: [required(false)] });
    expect(both.primary).toBe('values');
    expect(both.steps).toEqual([
      { step: 'values', done: false },
      { step: 'sign_in', done: false },
    ]);
    const valuesDone = connectionPlan({ kind: 'oauth_inputs', status: 'not_connected', signed_in: false, inputs: [required(true)] });
    expect(valuesDone.primary).toBe('sign_in');
    expect(valuesDone.steps[0].done).toBe(true);
    const all = connectionPlan({ kind: 'oauth_inputs', status: 'connected', signed_in: true, inputs: [required(true)] });
    expect(all.steps.every((s) => s.done)).toBe(true);
  });

  it('keeps asking for values on an expired sign-in whose values are also missing', () => {
    // Signed in, values still missing: the status is not_connected, yet the
    // sign-in step is done and the row asks for the values only.
    const signedInFirst = connectionPlan({ kind: 'oauth_inputs', status: 'not_connected', signed_in: true, inputs: [required(false)] });
    expect(signedInFirst.primary).toBe('values');
    expect(signedInFirst.steps).toEqual([
      { step: 'values', done: false },
      { step: 'sign_in', done: true },
    ]);
    expect(connectionPlan({ kind: 'oauth_inputs', status: 'expired', signed_in: false, inputs: [required(false)] }).primary).toBe('values');
  });
});

describe('serversNeedingConnection', () => {
  it('keeps only the servers that need the user', () => {
    const servers = [
      { slug: 'a', connection_status: 'needs_connection' },
      { slug: 'b', connection_status: 'connected' },
      { slug: 'c', connection_status: 'none' },
    ];
    expect(serversNeedingConnection(servers).map((s) => s.slug)).toEqual(['a']);
    expect(serversNeedingConnection([])).toEqual([]);
  });
});
