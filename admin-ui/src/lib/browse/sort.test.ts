import { describe, expect, it } from 'vitest';
import { FIGURE_SORT_MAX_DAYS, figureSortFits } from '#lib/browse/sort.js';

const DAY = 24 * 60 * 60 * 1000;

/** Put the process's time zone back as it was — unset included. */
function restoreZone(zone: string | undefined): void {
  if (zone === undefined) delete process.env.TZ;
  else process.env.TZ = zone;
}
const at = (ms: number) => new Date(Date.UTC(2026, 10, 1) + ms).toISOString();

describe('figureSortFits', () => {
  it('serves a rolling period up to the bound, and not past it', () => {
    // A fixed instant in a zone with no clock change: the bound alone decides.
    const zone = process.env.TZ;
    process.env.TZ = 'UTC';
    const now = new Date(Date.UTC(2026, 11, 15, 12));
    try {
      expect(figureSortFits({ kind: 'rolling', days: 1 }, now)).toBe(true);
      expect(figureSortFits({ kind: 'rolling', days: 30 }, now)).toBe(true);
      expect(figureSortFits({ kind: 'rolling', days: FIGURE_SORT_MAX_DAYS }, now)).toBe(true);
      expect(figureSortFits({ kind: 'rolling', days: FIGURE_SORT_MAX_DAYS + 1 }, now)).toBe(false);
      expect(figureSortFits({ kind: 'rolling', days: 0 }, now)).toBe(false);
    } finally {
      restoreZone(zone);
    }
  });

  it('serves an absolute range up to the bound, and not past it or reversed', () => {
    expect(figureSortFits({ kind: 'absolute', start: at(0), end: at(FIGURE_SORT_MAX_DAYS * DAY) })).toBe(true);
    expect(figureSortFits({ kind: 'absolute', start: at(0), end: at(FIGURE_SORT_MAX_DAYS * DAY + 1) })).toBe(false);
    expect(figureSortFits({ kind: 'absolute', start: at(0), end: at(1) })).toBe(true);
    expect(figureSortFits({ kind: 'absolute', start: at(0), end: at(0) })).toBe(false);
    expect(figureSortFits({ kind: 'absolute', start: at(DAY), end: at(0) })).toBe(false);
    expect(figureSortFits({ kind: 'absolute', start: 'not a date', end: at(0) })).toBe(false);
  });

  it('measures a rolling period as the request sends it, a clock change included', () => {
    // Pinned to a zone with a clock change: Europe/Paris falls back on
    // 2026-10-25, so 31 local days back from 2026-11-10 span 31 days and an
    // hour — refused by the server, so not offered — and 31 days back from
    // 2026-12-15 span exactly 31 days.
    const zone = process.env.TZ;
    process.env.TZ = 'Europe/Paris';
    try {
      expect(figureSortFits({ kind: 'rolling', days: 31 }, new Date(Date.UTC(2026, 10, 10, 12)))).toBe(false);
      expect(figureSortFits({ kind: 'rolling', days: 30 }, new Date(Date.UTC(2026, 10, 10, 12)))).toBe(true);
      expect(figureSortFits({ kind: 'rolling', days: 31 }, new Date(Date.UTC(2026, 11, 15, 12)))).toBe(true);
      // Spring forward (2026-03-29): 31 local days are an hour short — offered.
      expect(figureSortFits({ kind: 'rolling', days: 31 }, new Date(Date.UTC(2026, 3, 10, 12)))).toBe(true);
    } finally {
      restoreZone(zone);
    }
  });
});
