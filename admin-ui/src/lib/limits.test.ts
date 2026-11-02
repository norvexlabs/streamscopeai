import { describe, expect, it } from 'vitest';
import {
  allowsInherit,
  asLimitBucket,
  compareToDefault,
  decodeLimit,
  isValidLimit,
  effectiveCap,
  encodeLimit,
  exceedsPool,
  exceptionDirections,
  meterRatio,
  meterTone,
  type LimitEncoding,
  type LimitState,
} from './limits';

const ENCODINGS: LimitEncoding[] = ['exception', 'pool_budget', 'pool_rate', 'member_default'];

describe('decodeLimit / encodeLimit', () => {
  it('reads null as inherit only where the field can inherit', () => {
    expect(decodeLimit(null, 'exception')).toEqual({ kind: 'inherit' });
    expect(decodeLimit(undefined, 'pool_budget')).toEqual({ kind: 'inherit' });
    expect(decodeLimit(null, 'pool_rate')).toEqual({ kind: 'unlimited' });
    expect(decodeLimit(null, 'member_default')).toEqual({ kind: 'unlimited' });
  });

  it('reads 0 as unlimited and a positive value as that value', () => {
    for (const enc of ENCODINGS) {
      expect(decodeLimit(0, enc)).toEqual({ kind: 'unlimited' });
      expect(decodeLimit(60, enc)).toEqual({ kind: 'value', value: 60 });
    }
  });

  it('writes unlimited as 0 where null would mean inherit, else as null', () => {
    expect(encodeLimit({ kind: 'unlimited' }, 'exception')).toBe(0);
    expect(encodeLimit({ kind: 'unlimited' }, 'pool_budget')).toBe(0);
    expect(encodeLimit({ kind: 'unlimited' }, 'pool_rate')).toBeNull();
    expect(encodeLimit({ kind: 'unlimited' }, 'member_default')).toBeNull();
    expect(encodeLimit({ kind: 'inherit' }, 'exception')).toBeNull();
  });

  it('round-trips every state a field can hold', () => {
    for (const enc of ENCODINGS) {
      const states: LimitState[] = [{ kind: 'unlimited' }, { kind: 'value', value: 5 }];
      if (allowsInherit(enc)) states.push({ kind: 'inherit' });
      for (const s of states) expect(decodeLimit(encodeLimit(s, enc), enc)).toEqual(s);
    }
  });

  it('refuses to encode an invalid value rather than store it as unlimited', () => {
    for (const enc of ENCODINGS) {
      expect(() => encodeLimit({ kind: 'value', value: 0 }, enc)).toThrow();
      expect(() => encodeLimit({ kind: 'value', value: -3 }, enc)).toThrow();
      expect(() => encodeLimit({ kind: 'value', value: Number.NaN }, enc)).toThrow();
    }
    // Positive control: the smallest valid value is stored as itself.
    expect(encodeLimit({ kind: 'value', value: 0.01 }, 'exception')).toBe(0.01);
  });
});

describe('isValidLimit', () => {
  it('accepts inherit, unlimited and a positive value; refuses an empty or non-positive value', () => {
    expect(isValidLimit({ kind: 'inherit' })).toBe(true);
    expect(isValidLimit({ kind: 'unlimited' })).toBe(true);
    expect(isValidLimit({ kind: 'value', value: 0.01 })).toBe(true);
    expect(isValidLimit({ kind: 'value', value: 0 })).toBe(false);
    expect(isValidLimit({ kind: 'value', value: -1 })).toBe(false);
    expect(isValidLimit({ kind: 'value', value: Number.NaN })).toBe(false);
  });
});

describe('effectiveCap', () => {
  it('resolves inherit to the inherited cap, and to unlimited when there is none', () => {
    expect(effectiveCap({ kind: 'inherit' }, 60)).toBe(60);
    expect(effectiveCap({ kind: 'inherit' }, 0)).toBeNull();
    expect(effectiveCap({ kind: 'inherit' }, null)).toBeNull();
  });
  it('an explicit unlimited beats an inherited cap', () => {
    expect(effectiveCap({ kind: 'unlimited' }, 60)).toBeNull();
  });
  it('a value wins', () => {
    expect(effectiveCap({ kind: 'value', value: 5 }, 60)).toBe(5);
  });
  it('a half-typed value caps nothing', () => {
    expect(effectiveCap({ kind: 'value', value: Number.NaN }, 60)).toBeNull();
    expect(effectiveCap({ kind: 'value', value: 0 }, 60)).toBeNull();
  });
});

describe('exceedsPool', () => {
  it('warns only for an exception past the pool cap, both sides of it', () => {
    expect(exceedsPool({ kind: 'value', value: 101 }, 100)).toBe(true);
    expect(exceedsPool({ kind: 'value', value: 100 }, 100)).toBe(false);
    expect(exceedsPool({ kind: 'unlimited' }, 100)).toBe(true);
    // Inherit is the default's business; no pool cap, nothing to exceed.
    expect(exceedsPool({ kind: 'inherit' }, 100)).toBe(false);
    expect(exceedsPool({ kind: 'unlimited' }, null)).toBe(false);
    expect(exceedsPool({ kind: 'value', value: 5 }, 0)).toBe(false);
  });
});

describe('compareToDefault', () => {
  it('names each relation to the default, both sides of it', () => {
    expect(compareToDefault({ kind: 'inherit' }, 60)).toBe('inherits');
    expect(compareToDefault({ kind: 'value', value: 120 }, 60)).toBe('raised');
    expect(compareToDefault({ kind: 'value', value: 10 }, 60)).toBe('lowered');
    expect(compareToDefault({ kind: 'value', value: 60 }, 60)).toBe('same');
    expect(compareToDefault({ kind: 'unlimited' }, 60)).toBe('raised');
    expect(compareToDefault({ kind: 'unlimited' }, null)).toBe('same');
    expect(compareToDefault({ kind: 'value', value: 10 }, null)).toBe('lowered');
  });
});

describe('exceptionDirections', () => {
  const defaults = { requests_per_minute: 60, tokens_per_minute: 1000, daily_budget: 5, monthly_budget: 50 };
  it('sees a change on any of the four fields, in each direction', () => {
    expect(exceptionDirections({ tokens_per_minute: 5000 }, defaults)).toEqual({ raised: true, lowered: false });
    expect(exceptionDirections({ monthly_budget: 10 }, defaults)).toEqual({ raised: false, lowered: true });
    expect(exceptionDirections({ requests_per_minute: 10, monthly_budget: 0 }, defaults)).toEqual({ raised: true, lowered: true });
  });
  it('an exception inheriting every field or matching the default shows neither', () => {
    expect(exceptionDirections({}, defaults)).toEqual({ raised: false, lowered: false });
    expect(exceptionDirections({ daily_budget: 5 }, defaults)).toEqual({ raised: false, lowered: false });
  });
});

describe('meterRatio / meterTone', () => {
  it('has no ratio without a cap', () => {
    expect(meterRatio(5, null)).toBeNull();
    expect(meterRatio(5, 0)).toBeNull();
  });
  it('bands at 80% and 100%, both sides of each boundary', () => {
    expect(meterTone(meterRatio(79.99, 100))).toBe('ok');
    expect(meterTone(meterRatio(80, 100))).toBe('warning');
    expect(meterTone(meterRatio(99.99, 100))).toBe('warning');
    expect(meterTone(meterRatio(100, 100))).toBe('error');
    expect(meterTone(null)).toBe('ok');
  });
});

describe('asLimitBucket', () => {
  it('accepts the four buckets and nothing else', () => {
    expect(asLimitBucket('member')).toBe('member');
    expect(asLimitBucket('organisation')).toBe('organisation');
    expect(asLimitBucket('user')).toBeNull();
    expect(asLimitBucket(null)).toBeNull();
  });
});
