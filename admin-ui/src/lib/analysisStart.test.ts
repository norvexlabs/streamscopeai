import { describe, expect, it } from 'vitest';
import { analyzesAgain, leavesBehind, localDay, localInstant, startOfLocalDay } from './analysisStart.js';

describe('localDay', () => {
  it('pads the month and the day', () => {
    expect(localDay(new Date(2026, 0, 5, 23, 59))).toBe('2026-01-05');
  });
});

describe('startOfLocalDay', () => {
  it('is local midnight of that day', () => {
    expect(startOfLocalDay('2026-11-05')?.getTime()).toBe(new Date(2026, 10, 5).getTime());
  });

  it.each(['', '2026-11', '05/11/2026', '2026-13-01', '2026-02-31', '0099-01-01'])('refuses %s', (day) => {
    expect(startOfLocalDay(day)).toBeNull();
  });
});

describe('localInstant', () => {
  it('is the start of the day with no time, and that minute with one', () => {
    expect(localInstant('2026-11-05', '')?.getTime()).toBe(new Date(2026, 10, 5).getTime());
    expect(localInstant('2026-11-05', '00:00')?.getTime()).toBe(new Date(2026, 10, 5, 0, 0).getTime());
    expect(localInstant('2026-11-05', '23:59')?.getTime()).toBe(new Date(2026, 10, 5, 23, 59).getTime());
  });

  it.each([['2026-02-31', '10:00'], ['', '10:00'], ['2026-11-05', '24:00'], ['2026-11-05', '10:60'], ['2026-11-05', '1:00']])(
    'refuses %s %s',
    (day, time) => {
      expect(localInstant(day, time)).toBeNull();
    },
  );
});

describe('localInstant across a clock change', () => {
  it('refuses a minute the change skips, and takes the next one', () => {
    const zone = process.env.TZ;
    process.env.TZ = 'Europe/Paris';
    try {
      expect(localInstant('2026-03-29', '02:30')).toBeNull();
      expect(localInstant('2026-03-29', '03:00')?.toISOString()).toBe('2026-03-29T01:00:00.000Z');
    } finally {
      if (zone === undefined) delete process.env.TZ;
      else process.env.TZ = zone;
    }
  });
});

describe('leavesBehind', () => {
  const oldest = '2026-11-01T10:00:00.000Z';

  it('is true just after the oldest position, false at it and before', () => {
    expect(leavesBehind(new Date('2026-11-01T10:00:00.001Z'), oldest, oldest)).toBe(true);
    expect(leavesBehind(new Date(oldest), oldest, oldest)).toBe(false);
    expect(leavesBehind(new Date('2026-11-01T09:59:59.999Z'), oldest, oldest)).toBe(false);
  });

  it('is true while an expert has yet to start beside one that has', () => {
    expect(leavesBehind(new Date(0), null, oldest)).toBe(true);
  });

  it('is false when nothing has started', () => {
    expect(leavesBehind(new Date(0), null, null)).toBe(false);
  });
});

describe('analyzesAgain', () => {
  const cursor = '2026-11-05T10:00:00.000Z';

  it('is true just before the position, false at it and after', () => {
    expect(analyzesAgain(new Date('2026-11-05T09:59:59.999Z'), cursor)).toBe(true);
    expect(analyzesAgain(new Date(cursor), cursor)).toBe(false);
    expect(analyzesAgain(new Date('2026-11-05T10:00:00.001Z'), cursor)).toBe(false);
  });

  it('is false with no position yet', () => {
    expect(analyzesAgain(new Date(0), null)).toBe(false);
    expect(analyzesAgain(new Date(0), undefined)).toBe(false);
  });
});
