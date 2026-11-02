import { describe, expect, it } from 'vitest';
import {
  chartHasValue,
  chartYMax,
  niceMax,
  niceMaxWithMidpoint,
  niceStep,
  niceTicks,
  referencesInReach,
} from './chartHelpers';

const series = [{ key: 'a' }, { key: 'b' }];

describe('niceStep', () => {
  it('is the smallest of 1, 2, 5 × 10ⁿ at or above the raw step', () => {
    expect([0.3, 1, 1.01, 2, 2.5, 5, 6, 12, 0.07].map((v) => niceStep(v))).toEqual([0.5, 1, 2, 2, 5, 5, 10, 20, 0.1]);
  });
  it('keeps a nice number as itself despite floating-point noise', () => {
    expect(niceStep(0.1 + 0.2)).toBe(0.5);
    expect(niceStep((0.1 + 0.1) * 3 / 3)).toBe(0.2);
  });
});

describe('niceMax', () => {
  it('ends the axis on a nice multiple close above the data, not the next power of ten', () => {
    expect(niceMax(12)).toBe(15);
    expect(niceMax(3)).toBe(3);
    expect(niceMax(9)).toBe(10);
    expect(niceMax(101)).toBe(150);
    expect(niceMax(0.6)).toBe(0.6);
    expect(niceMax(1)).toBe(1);
  });
  it('with two intervals, a midpoint that is nice too', () => {
    for (const [max, top] of [[12, 20], [3, 4], [7, 10], [1, 1]] as const) {
      expect(niceMax(max, 2)).toBe(top);
      expect(niceStep(top / 2)).toBe(top / 2);
    }
  });
  it('an empty or broken maximum still gets an axis', () => {
    expect([0, -1, Number.NaN, Infinity].map((v) => niceMax(v))).toEqual([10, 10, 10, 10]);
  });
  it('never lies below the data and the top is always a tick', () => {
    for (let v = 0.01; v < 5000; v *= 1.37) {
      const top = niceMax(v);
      expect(top).toBeGreaterThanOrEqual(v);
      expect(niceTicks(top).at(-1)).toBeCloseTo(top, 9);
    }
  });
});

describe('niceTicks', () => {
  it('every multiple of one nice step, from 0 to the top', () => {
    expect(niceTicks(15)).toEqual([0, 5, 10, 15]);
    expect(niceTicks(1)).toEqual([0, 0.5, 1]);
    expect(niceTicks(0.6)).toEqual([0, 0.2, 0.4, 0.6]);
  });
  it('never places a label past the top it was given', () => {
    expect(Math.max(...niceTicks(8, 3))).toBeLessThanOrEqual(8);
  });
});

describe('chartYMax', () => {
  it('shares one scale across plots: the highest value of any plot sets it', () => {
    const recent = [{ a: 0.6 }];
    const history = [{ a: 0.002 }, { b: 3 }];
    expect(chartYMax([recent, history], series)).toBe(3);
    expect(chartYMax([recent], series)).toBe(0.6);
  });

  it('never goes below the floor, and passes it when the data does', () => {
    expect(chartYMax([[{ a: 0.002 }]], series, 1)).toBe(1);
    expect(chartYMax([[{ a: 12 }]], series, 1)).toBe(15);
  });

  it('reads only the series it is given, and a gap or junk as zero', () => {
    expect(chartYMax([[{ a: null, b: Number.NaN, c: 500 }]], series)).toBe(10);
  });
});

describe('chartHasValue', () => {
  it('a zero is not a value to draw, any positive one is', () => {
    expect(chartHasValue([{ a: 0, b: null }], series)).toBe(false);
    expect(chartHasValue([{ a: 0 }, { b: 0.001 }], series)).toBe(true);
  });
});

describe('count axes', () => {
  it('never step by less than one, so no tick reads half a request', () => {
    expect(niceTicks(niceMax(1, 4, true), 4, true)).toEqual([0, 1]);
    expect(niceTicks(niceMax(2, 4, true), 4, true)).toEqual([0, 1, 2]);
    expect(niceTicks(niceMax(12, 4, true), 4, true)).toEqual([0, 5, 10, 15]);
    // The positive control: an axis of fractions keeps its fine steps.
    expect(niceTicks(niceMax(1))).toEqual([0, 0.5, 1]);
  });
  it('a three-label axis has a nice, whole midpoint', () => {
    for (const [max, top] of [[5, 10], [1, 2], [12, 20], [3, 4]] as const) {
      const t = niceMaxWithMidpoint(max, true);
      expect(t).toBe(top);
      expect(Number.isInteger(t / 2)).toBe(true);
    }
  });
});

describe('referencesInReach', () => {
  it('keeps a limit near the data on the scale, and a far one off it', () => {
    const refs = [{ value: 12 }, { value: 512 }];
    expect(referencesInReach(refs, 20)).toEqual([{ value: 12 }]);
    expect(referencesInReach(refs, 300)).toEqual(refs);
    // No data at all: the limit is the only thing to scale to.
    expect(referencesInReach(refs, 0)).toEqual(refs);
  });
});
