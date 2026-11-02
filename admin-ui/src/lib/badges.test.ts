import { describe, expect, it } from 'vitest';
import { dedupeBadgesByCode, turnScopedBadges, type AuditBadge } from '#lib/badges.js';

/**
 * The two badge collapsers decide what an operator sees on an audit row.
 *
 * Their failure modes are both silent: `dedupeBadgesByCode` exists because a
 * repeated code throws `each_key_duplicate` in the keyed `{#each}` and blanks
 * the WHOLE chip list, and `turnScopedBadges` drops session-level facts from a
 * per-turn view — one code too many and every row repeats the session's alert,
 * one too few and the signal disappears from the plane that needs it.
 *
 * Registry completeness is deliberately NOT tested here: `BADGE_REGISTRY` is
 * typed `Record<AuditBadge['code'], BadgeRegistryEntry>` and `iconName` is
 * typed `IconName`, so a missing variant or a bogus icon fails `svelte-check`
 * already. A runtime test would only restate the compiler.
 */

const alert = (level: 'major' | 'minor' | 'info', axis: string): AuditBadge =>
	({ code: 'agent_alert', level, axis }) as AuditBadge;

const modified: AuditBadge = { code: 'modified' } as AuditBadge;
const compressed: AuditBadge = { code: 'compressed' } as AuditBadge;

describe('dedupeBadgesByCode', () => {
	it('keeps one chip per distinct code', () => {
		const out = dedupeBadgesByCode([modified, compressed, modified]);
		expect(out.map((b) => b.code)).toEqual(['modified', 'compressed']);
	});

	it('preserves first-seen order', () => {
		const out = dedupeBadgesByCode([compressed, modified]);
		expect(out.map((b) => b.code)).toEqual(['compressed', 'modified']);
	});

	it('keeps the most severe agent_alert as the representative', () => {
		const out = dedupeBadgesByCode([
			alert('info', 'cost'),
			alert('major', 'security'),
			alert('minor', 'quality'),
		]);
		expect(out).toHaveLength(1);
		expect(out[0]).toMatchObject({ level: 'major', axis: 'security' });
	});

	it('does not let a later equal-severity alert displace the first', () => {
		// The comparison is strictly greater-than; ties keep first-seen so the
		// collapsed chip is stable across re-renders of the same row.
		const out = dedupeBadgesByCode([alert('major', 'first'), alert('major', 'second')]);
		expect(out[0]).toMatchObject({ axis: 'first' });
	});

	it('promotes severity without moving the code out of its original slot', () => {
		const out = dedupeBadgesByCode([
			modified,
			alert('info', 'cost'),
			compressed,
			alert('major', 'security'),
		]);
		expect(out.map((b) => b.code)).toEqual(['modified', 'agent_alert', 'compressed']);
		expect(out[1]).toMatchObject({ level: 'major' });
	});

	it('treats null and undefined as an empty list', () => {
		expect(dedupeBadgesByCode(null)).toEqual([]);
		expect(dedupeBadgesByCode(undefined)).toEqual([]);
		expect(dedupeBadgesByCode([])).toEqual([]);
	});
});

describe('turnScopedBadges', () => {
	it('drops the session-scoped agent_alert', () => {
		expect(turnScopedBadges([modified, alert('major', 'security')])).toEqual([modified]);
	});

	it('keeps every request-scoped badge — the positive control', () => {
		// Without this, the filter could drop everything and the "drops
		// agent_alert" assertion above would still pass.
		const out = turnScopedBadges([modified, compressed]);
		expect(out.map((b) => b.code)).toEqual(['modified', 'compressed']);
	});

	it('treats null and undefined as an empty list', () => {
		expect(turnScopedBadges(null)).toEqual([]);
		expect(turnScopedBadges(undefined)).toEqual([]);
	});
});
