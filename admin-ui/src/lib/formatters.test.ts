import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { formatAge, formatAmount, formatTimeAgo, formatCost, formatKeyLabel, formatPrice, formatShare, formatSpend, parseAlertLines } from '#lib/formatters.js';
import { setAccountingCurrency } from '#lib/currency.svelte.js';

/**
 * The money formatters are the last step between a figure the gateway billed
 * and the number an operator reads, and their bands are where that reading goes
 * wrong quietly. Two classes have already shipped on the Rust side of the same
 * semantics — a sub-cent charge rounding to zero, and a free rate being
 * indistinguishable from an unknown one — so the boundaries are asserted on
 * BOTH sides here rather than at a single happy value.
 *
 * Locale is left at the default (`en`) throughout: these assertions are about
 * the banding and the sign, not about `Intl` output, and pinning a locale-
 * formatted string would test the runtime's CLDR data instead of this module.
 */

describe('formatCost', () => {
	beforeEach(() => setAccountingCurrency('USD'));

	it('renders an absent figure as missing, not as zero', () => {
		// The distinction that matters: no data vs a real charge of nothing.
		expect(formatCost(null)).toBe('--');
		expect(formatCost(undefined)).toBe('--');
		expect(formatCost(0)).toBe('$0.00');
	});

	it('collapses a sub-cent charge rather than rounding it away', () => {
		expect(formatCost(0.0001)).toBe('<$0.01');
		expect(formatCost(0.009999)).toBe('<$0.01');
	});

	it('pins the sub-cent boundary on both sides', () => {
		expect(formatCost(0.00999)).toBe('<$0.01');
		expect(formatCost(0.01)).toBe('$0.01');
	});

	it('pins the two-decimal / thousands boundary on both sides', () => {
		expect(formatCost(99.99)).toBe('$99.99');
		expect(formatCost(100)).toBe('$0.1K');
	});

	it('pins the one-decimal / no-decimal boundary on both sides', () => {
		expect(formatCost(9999)).toBe('$10.0K');
		expect(formatCost(10_000)).toBe('$10K');
	});

	it('signs a negative before banding it', () => {
		// Cache net savings legitimately goes negative; without sign handling
		// before the magnitude bands, a -$3.47 loss reads as "<$0.01".
		expect(formatCost(-3.47)).toBe('-$3.47');
		expect(formatCost(-0.001)).toBe('-<$0.01');
		expect(formatCost(-250)).toBe('-$0.3K');
	});

	it('renders a figure in the currency it was stated in, not the tenant default', () => {
		expect(formatCost(12.5, 'EUR')).toBe('€12.50');
		expect(formatCost(12.5, 'USD')).toBe('$12.50');
	});

	it('separates an alphabetic code from the amount with a NON-BREAKING space', () => {
		// `CHF\u00a012.50`, not `CHF12.50` — a glyph sits flush, a code does not,
		// and the separator is U+00A0 so the code never wraps away from its
		// amount in a narrow table cell. Spelled as an escape because the two
		// spaces are indistinguishable in source and a plain one would be a
		// silent regression.
		expect(formatCost(12.5, 'CHF')).toBe('CHF\u00a012.50');
	});

	it('falls back to the code itself for a currency the runtime cannot name', () => {
		// An invalid code must never take down a whole table of figures.
		expect(formatCost(12.5, 'ZZZ')).toBe('ZZZ\u00a012.50');
	});

	it('defaults to the tenant accounting currency when none is given', () => {
		setAccountingCurrency('GBP');
		expect(formatCost(12.5)).toBe('£12.50');
	});
});

describe('formatSpend', () => {
	beforeEach(() => setAccountingCurrency('USD'));

	it('states a figure in its own currency, not the accounting one', () => {
		expect(formatSpend({ amount: 1.5, currency: 'EUR' })).toBe(formatCost(1.5, 'EUR'));
	});

	it('names an absent figure with the label it is given, and "mixed" by default', () => {
		// A session's spend can be absent for more than a currency change, so its
		// caller passes a neutral label; the default must stay the window's own.
		expect(formatSpend(null)).toBe('mixed');
		expect(formatSpend(undefined, () => 'no single figure')).toBe('no single figure');
		expect(formatSpend({ amount: 0, currency: 'EUR' }, () => 'no single figure')).toBe(formatCost(0, 'EUR'));
	});
});

describe('formatAmount', () => {
	beforeEach(() => setAccountingCurrency('USD'));

	it('never collapses to a sub-cent band — it is compared against a cap', () => {
		expect(formatAmount(0.0001)).toBe('$0.00');
		expect(formatAmount(12_345.67)).toBe('$12345.67');
	});

	it('renders an absent figure as missing', () => {
		expect(formatAmount(null)).toBe('--');
	});

	it('signs a negative', () => {
		expect(formatAmount(-12.5)).toBe('-$12.50');
	});
});

describe('formatPrice', () => {
	beforeEach(() => setAccountingCurrency('USD'));

	it('keeps precision below a cent instead of collapsing it', () => {
		// A rate table's whole job is the small number.
		expect(formatPrice(0.006)).toBe('$0.0060');
		expect(formatPrice(0)).toBe('$0.00');
	});

	it('pins both band boundaries', () => {
		expect(formatPrice(0.0099)).toBe('$0.0099');
		expect(formatPrice(0.01)).toBe('$0.010');
		expect(formatPrice(0.999)).toBe('$0.999');
		expect(formatPrice(1)).toBe('$1.00');
	});

	it('renders an absent price as missing', () => {
		expect(formatPrice(null)).toBe('--');
	});
});

describe('parseAlertLines', () => {
	it('parses the tagged form and sorts major before minor before info', () => {
		const out = parseAlertLines('[cost:info] c\n[security:major] a\n[quality:minor] b');
		expect(out.map((l) => l.level)).toEqual(['major', 'minor', 'info']);
		expect(out[0]).toEqual({ axis: 'security', level: 'major', text: 'a' });
	});

	it('gives an untagged line the session severity', () => {
		const out = parseAlertLines('just prose', 'major');
		expect(out).toEqual([{ axis: '', level: 'major', text: 'just prose' }]);
	});

	it('falls back to minor when the session severity is absent', () => {
		expect(parseAlertLines('just prose')[0].level).toBe('minor');
	});

	it('drops blank lines and treats an absent note as empty', () => {
		expect(parseAlertLines('a\n\n  \nb')).toHaveLength(2);
		expect(parseAlertLines(null)).toEqual([]);
		expect(parseAlertLines('')).toEqual([]);
	});

	it('leaves an unrecognised severity tag as prose rather than trusting it', () => {
		const out = parseAlertLines('[cost:critical] x', 'info');
		expect(out[0]).toEqual({ axis: '', level: 'info', text: '[cost:critical] x' });
	});
});

describe('formatShare', () => {
  it('states a share at one decimal', () => {
    expect(formatShare(1, 8)).toBe('12.5%');
    expect(formatShare(0, 8)).toBe('0.0%');
    expect(formatShare(8, 8)).toBe('100.0%');
  });

  it('never rounds a real share down to nothing', () => {
    expect(formatShare(1, 10_000)).toBe('<0.1%');
    expect(formatShare(1, 1000)).toBe('0.1%');
  });

  it('has no share of nothing', () => {
    expect(formatShare(0, 0)).toBe('--');
    expect(formatShare(3, 0)).toBe('--');
  });
});

describe('formatAge', () => {
  // A headline figure: a number and a unit, never an "ago" sentence. Time is
  // frozen so a boundary case cannot drift across its band on a slow worker.
  const NOW = new Date('2026-09-30T12:00:00Z').getTime();
  const ago = (secs: number) => new Date(NOW - secs * 1000).toISOString();
  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });
  afterEach(() => vi.useRealTimers());

  it('is "--" with no timestamp or one that does not parse', () => {
    expect(formatAge(null)).toBe('--');
    expect(formatAge(undefined)).toBe('--');
    expect(formatAge('garbage')).toBe('--');
    expect(formatTimeAgo('garbage')).toBe('--');
  });

  it('bands on both sides of every unit boundary', () => {
    expect(formatAge(ago(59))).toBe('now');
    expect(formatAge(ago(60))).toBe('1m');
    expect(formatAge(ago(59 * 60 + 29))).toBe('59m');
    expect(formatAge(ago(59 * 60 + 30))).toBe('1h');
    expect(formatAge(ago(23 * 3600 + 29 * 60))).toBe('23h');
    expect(formatAge(ago(23 * 3600 + 30 * 60))).toBe('1d');
    expect(formatAge(ago(45 * 86400))).toBe('45d');
  });

  it('rounds each unit from the raw age, never from a rounded smaller unit', () => {
    // 1h29m30s is 1.49 h: a minutes-then-hours cascade (90 min → 2 h) overstates it.
    expect(formatAge(ago(3600 + 29 * 60 + 30))).toBe('1h');
    expect(formatAge(ago(3600 + 30 * 60))).toBe('2h');
    // 1d11h30m is 1.48 d.
    expect(formatAge(ago(86400 + 11 * 3600 + 30 * 60))).toBe('1d');
  });

  it('reads a future timestamp (clock skew) as now, never a negative age', () => {
    expect(formatAge(ago(-3600))).toBe('now');
  });

  it('names the same instant as the phrase beside it — same unit, same rounding', () => {
    // 100 min is "2 hr. ago", so the figure is 2h, never a floored 1h.
    const pairs: [number, string, string][] = [
      [100 * 60, '2h', '2 hr. ago'],
      [36 * 3600, '2d', '2 days ago'],
      [5 * 60 + 40, '6m', '6 min. ago'],
    ];
    for (const [secs, figure, phrase] of pairs) {
      expect(formatAge(ago(secs))).toBe(figure);
      expect(formatTimeAgo(ago(secs))).toBe(phrase);
    }
  });

  it('keeps the phrase directional for a future instant, rounded like a past one', () => {
    expect(formatTimeAgo(ago(-3 * 86400))).toBe('in 3 days');
    // 45 days is 1.5 months either way: both round the magnitude up.
    expect(formatTimeAgo(ago(45 * 86400))).toBe('2 mo. ago');
    expect(formatTimeAgo(ago(-45 * 86400))).toBe('in 2 mo.');
  });

  it('is never a sentence', () => {
    for (const secs of [0, 90, 5000, 200000, 5000000]) {
      expect(formatAge(ago(secs))).not.toMatch(/ago|in /);
    }
  });
});

describe('formatKeyLabel', () => {
  it('a_key_is_named_by_its_name_else_its_prefix', () => {
    expect(formatKeyLabel('ci', 'sk-abc')).toBe('ci');
    expect(formatKeyLabel(null, 'sk-abc')).toBe('sk-abc…');
    expect(formatKeyLabel('', 'sk-abc')).toBe('sk-abc…');
    expect(formatKeyLabel(null, null)).toBe('');
  });
});
