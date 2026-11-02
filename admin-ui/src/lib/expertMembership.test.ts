import { describe, expect, it } from 'vitest';
import { cardState, membershipChanged, runningCount, selectAll } from '#lib/expertMembership.js';

const set = (...ids: string[]) => new Set(ids);

describe('cardState', () => {
  it('distinguishes the four cases of own listing × the Default', () => {
    expect(cardState('a', set(), set())).toEqual({ runs: false, ownListed: false, inDefault: false, locked: false });
    expect(cardState('a', set('a'), set())).toEqual({ runs: true, ownListed: true, inDefault: false, locked: false });
    // Run through the Default alone: nothing to untick here.
    expect(cardState('a', set(), set('a'))).toEqual({ runs: true, ownListed: false, inDefault: true, locked: true });
    // Listed AND in the Default: the own listing can still be removed.
    expect(cardState('a', set('a'), set('a'))).toEqual({ runs: true, ownListed: true, inDefault: true, locked: false });
  });
});

describe('selectAll', () => {
  it('adds what the Default does not run, keeping existing own members', () => {
    const got = selectAll(['a', 'b', 'c'], set('b'), set('b', 'c'));
    // `b` is own AND in the Default: it stays listed. `c` runs through the Default: not added.
    expect([...got].sort()).toEqual(['a', 'b']);
  });
});

describe('membershipChanged', () => {
  it('ignores order and sees an add, a removal and a swap', () => {
    expect(membershipChanged(set('a', 'b'), set('b', 'a'))).toBe(false);
    expect(membershipChanged(set('a', 'b'), set('a'))).toBe(true);
    expect(membershipChanged(set('a'), set('a', 'b'))).toBe(true);
    expect(membershipChanged(set('a', 'c'), set('a', 'b'))).toBe(true);
  });
});

describe('runningCount', () => {
  it('counts experts running here and switched on, once each', () => {
    const experts = [
      { id: 'a', enabled: true },
      { id: 'b', enabled: true },
      { id: 'c', enabled: false },
      { id: 'd', enabled: true },
    ];
    // a: own + Default (counted once); b: Default; c: own but off; d: nowhere.
    expect(runningCount(experts, set('a', 'c'), set('a', 'b'))).toBe(2);
  });
});
