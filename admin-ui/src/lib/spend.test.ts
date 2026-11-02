import { describe, expect, it } from 'vitest';
import { amountBeside, sumSpend } from '#lib/spend.js';
import type { Spend } from '#lib/formatters.js';

/**
 * `sumSpend` states three rules in its own doc comment, and each has an
 * opposite that is easy to reach by accident:
 *
 *  - parts in DIFFERENT currencies have no sum, so the answer is `null`;
 *  - an ABSENT part means the same thing, because what it held is unknown;
 *  - a ZERO part is NOT a disagreement — a key with no traffic is reported in
 *    whatever currency the tenant keeps its books in today, which after a
 *    currency change is not the currency the window's real spend was booked in.
 *    Counting it would let one idle key turn a statable total into "mixed".
 *
 * The third is the subtle one and the reason this is a table rather than a
 * happy-path case: it is indistinguishable from the first unless the zero is
 * carried in the OTHER currency.
 */

const s = (amount: number, currency: string): Spend => ({ amount, currency });

describe('sumSpend', () => {
	it('adds parts that agree on a currency', () => {
		expect(sumSpend([s(1.5, 'USD'), s(2.25, 'USD')], 'EUR')).toEqual({
			amount: 3.75,
			currency: 'USD',
		});
	});

	it('refuses to sum parts stated in different currencies', () => {
		expect(sumSpend([s(1.5, 'USD'), s(2.25, 'EUR')], 'USD')).toBeNull();
	});

	it('refuses to sum when any part is absent', () => {
		expect(sumSpend([s(1.5, 'USD'), null], 'USD')).toBeNull();
		expect(sumSpend([undefined, s(1.5, 'USD')], 'USD')).toBeNull();
	});

	it('ignores a zero part carried in a FOREIGN currency', () => {
		// The rule that separates this function from a naive currency check:
		// an idle key reported as 0 EUR must not make a real USD total "mixed".
		expect(sumSpend([s(1.5, 'USD'), s(0, 'EUR')], 'GBP')).toEqual({
			amount: 1.5,
			currency: 'USD',
		});
	});

	it('reports nothing-was-spent in the fallback currency', () => {
		expect(sumSpend([], 'EUR')).toEqual({ amount: 0, currency: 'EUR' });
		expect(sumSpend([s(0, 'USD'), s(0, 'EUR')], 'EUR')).toEqual({
			amount: 0,
			currency: 'EUR',
		});
	});

	it('adopts the first non-zero part currency, not the fallback', () => {
		expect(sumSpend([s(0, 'EUR'), s(4, 'JPY')], 'USD')).toEqual({
			amount: 4,
			currency: 'JPY',
		});
	});

	it('still refuses when a zero part sits between two disagreeing figures', () => {
		// Positive control for the skip: skipping zeroes must not also skip the
		// disagreement check on the figures around them.
		expect(sumSpend([s(1, 'USD'), s(0, 'GBP'), s(2, 'EUR')], 'USD')).toBeNull();
	});

	it('sums negatives, which cache net savings legitimately produces', () => {
		expect(sumSpend([s(5, 'USD'), s(-2, 'USD')], 'USD')).toEqual({
			amount: 3,
			currency: 'USD',
		});
	});
});

describe('amountBeside', () => {
	it('measures a figure in the leader currency', () => {
		expect(amountBeside(s(2, 'EUR'), s(8, 'EUR'))).toBe(2);
	});

	it('draws nothing for a figure in another currency', () => {
		// The case the bar must not get wrong: 900 USD is not "longer" than
		// the 8 EUR leader.
		expect(amountBeside(s(900, 'USD'), s(8, 'EUR'))).toBe(0);
	});

	it('draws nothing for a figure the API could not state, or without a leader', () => {
		expect(amountBeside(null, s(8, 'EUR'))).toBe(0);
		expect(amountBeside(s(2, 'EUR'), null)).toBe(0);
	});
});
