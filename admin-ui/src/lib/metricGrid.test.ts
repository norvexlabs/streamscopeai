import { describe, expect, it } from 'vitest';
import { metricGridColumns } from './metricGrid';

const MIN = 200;
const GAP = 16;
// Width that fits exactly `n` cards of MIN plus the gaps between them.
const fits = (n: number) => n * MIN + (n - 1) * GAP;

describe('metricGridColumns', () => {
  it('is 0 while unmeasured or empty', () => {
    expect(metricGridColumns(4, 0, MIN, GAP)).toBe(0);
    expect(metricGridColumns(0, 1200, MIN, GAP)).toBe(0);
  });

  it('keeps the whole set on one row when it fits — at the boundary and one pixel short', () => {
    expect(metricGridColumns(7, fits(7), MIN, GAP)).toBe(7);
    expect(metricGridColumns(7, fits(7) - 1, MIN, GAP)).toBe(4);
  });

  it('never stretches a set beyond its own count without a track floor', () => {
    expect(metricGridColumns(4, fits(10), MIN, GAP)).toBe(4);
  });

  it('keeps a small set tile-sized with a track floor, but only as far as tracks fit', () => {
    expect(metricGridColumns(1, fits(10), MIN, GAP, 4)).toBe(4);
    expect(metricGridColumns(2, fits(3), MIN, GAP, 4)).toBe(3);
    expect(metricGridColumns(2, fits(1), MIN, GAP, 4)).toBe(1);
    expect(metricGridColumns(3, fits(10), MIN, GAP, 4)).toBe(4);
    // The floor never lowers a set larger than it.
    expect(metricGridColumns(6, fits(10), MIN, GAP, 4)).toBe(6);
  });

  it('wraps into equal rows whenever the count allows', () => {
    // 8 → 2 × 4, 6 → 2 × 3, 4 → 2 × 2.
    expect(metricGridColumns(8, fits(7), MIN, GAP)).toBe(4);
    expect(metricGridColumns(8, fits(5), MIN, GAP)).toBe(4);
    expect(metricGridColumns(6, fits(5), MIN, GAP)).toBe(3);
    expect(metricGridColumns(6, fits(4), MIN, GAP)).toBe(3);
    expect(metricGridColumns(4, fits(3), MIN, GAP)).toBe(2);
  });

  it('balances an odd count instead of leaving a straggler', () => {
    // 7 → 4 + 3, not 6 + 1; 5 → 3 + 2, not 4 + 1.
    expect(metricGridColumns(7, fits(6), MIN, GAP)).toBe(4);
    expect(metricGridColumns(5, fits(4), MIN, GAP)).toBe(3);
  });

  it('never exceeds maxCols, and balances within it', () => {
    expect(metricGridColumns(6, fits(10), MIN, GAP, 4, 2)).toBe(2);
    expect(metricGridColumns(5, fits(10), MIN, GAP, 4, 2)).toBe(2);
    expect(metricGridColumns(1, fits(10), MIN, GAP, 4, 2)).toBe(2);
  });

  it('falls back to one column on a container narrower than one card', () => {
    expect(metricGridColumns(5, MIN - 50, MIN, GAP)).toBe(1);
  });

  it('every layout fits the width, uses the fewest rows, and keeps rows balanced', () => {
    for (const minTracks of [1, 4]) {
      for (let count = 1; count <= 12; count++) {
        for (let w = 100; w <= 2400; w += 37) {
          const cols = metricGridColumns(count, w, MIN, GAP, minTracks);
          // Independent of the implementation: the widest column count whose
          // cards and gaps fit in `w`, found by counting up.
          let maxFit = 1;
          while ((maxFit + 1) * MIN + maxFit * GAP <= w) maxFit++;
          expect(cols).toBeGreaterThanOrEqual(1);
          expect(cols).toBeLessThanOrEqual(maxFit);
          const rows = Math.ceil(count / cols);
          expect(rows).toBe(Math.ceil(count / Math.min(count, maxFit)));
          if (rows > 1) {
            // Balanced: the narrowest columns that still fill `rows` rows, so
            // rows are equal whenever `rows` divides the count, and a straggler
            // row (6 + 1) is impossible — a `return fit` regression fails here.
            expect(cols).toBe(Math.ceil(count / rows));
          } else {
            // One row: exactly the set, or the floor when it fits.
            expect(cols).toBe(Math.max(count, Math.min(maxFit, minTracks)));
          }
        }
      }
    }
  });
});
