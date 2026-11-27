import { describe, expect, it } from 'vitest';
import fc from 'fast-check';
import {
	BADGE_REGISTRY,
	badgeFilterGroups,
	dedupeBadgesByCode,
	needsAttention,
	offeredBadgeFilter,
	parseBadgeFilter,
	turnScopedBadges,
	type AuditBadge,
	type BadgeCode,
} from '#lib/badges.js';

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

describe('needsAttention', () => {
  const loop = (action: 'detected' | 'nudged' | 'stopped', streak: number): AuditBadge => ({
    code: 'tool_loop',
    streak,
    call_streak: 4,
    cycle_len: 1,
    tools: ['bash'],
    action,
  });

  it('flags a loop that repeated with the same results, or that the gateway acted on', () => {
    expect(needsAttention(loop('detected', 2))).toBe(true);
    expect(needsAttention(loop('nudged', 3))).toBe(true);
    expect(needsAttention(loop('stopped', 8))).toBe(true);
  });

  it('does not flag the same calls with results that changed', () => {
    expect(needsAttention(loop('detected', 1))).toBe(false);
  });

  it('flags other attention codes and nothing else', () => {
    expect(needsAttention({ code: 'unpriced' })).toBe(true);
    expect(needsAttention({ code: 'spilled' })).toBe(false);
  });
});

const CODES = Object.keys(BADGE_REGISTRY) as BadgeCode[];
const FILTERABLE = CODES.filter((c) => BADGE_REGISTRY[c].family !== 'alert');

describe('parseBadgeFilter', () => {
	it('reads the known codes it names, in order, once each', () => {
		expect(parseBadgeFilter(' guardrail,,tool_blocked,guardrail ')).toEqual(['guardrail', 'tool_blocked']);
		expect(parseBadgeFilter('')).toEqual([]);
		expect(parseBadgeFilter(undefined)).toEqual([]);
	});

	it('drops what the filter never sends: an unknown code, an alert, a prototype key', () => {
		expect(parseBadgeFilter('nope,session_alert,agent_alert,constructor,toString,__proto__,tool_loop')).toEqual(['tool_loop']);
	});

	// The value comes from the URL: whatever it holds, the parse yields only
	// filterable codes, never one twice, and every filterable code it names
	// survives (positive control: the parse is not simply empty).
	it('yields exactly the filterable codes a value names', () => {
		fc.assert(
			fc.property(fc.array(fc.oneof(fc.constantFrom(...CODES), fc.string())), (tokens) => {
				const out = parseBadgeFilter(tokens.join(','));
				expect(new Set(out).size).toBe(out.length);
				for (const c of out) expect(FILTERABLE).toContain(c);
				for (const t of tokens.map((x) => x.trim())) {
					if ((FILTERABLE as string[]).includes(t)) expect(out).toContain(t);
				}
			}),
		);
	});
});

describe('badgeFilterGroups', () => {
	it('offers every filterable code once across all kinds, and no alert', () => {
		const offered = badgeFilterGroups(['llm', 'mcp', 'web', 'a2a']).flatMap((g) => g.codes);
		expect(new Set(offered).size).toBe(offered.length);
		expect([...offered].sort()).toEqual([...FILTERABLE].sort());
	});

	it('narrows to the codes a kind can carry', () => {
		const mcp = badgeFilterGroups(['mcp']).flatMap((g) => g.codes);
		expect(mcp).toContain('mcp_rpc_error');
		expect(mcp).toContain('tool_blocked');
		expect(mcp).not.toContain('cache_hit');
		const llm = badgeFilterGroups(['llm']).flatMap((g) => g.codes);
		expect(llm).toContain('cache_hit');
		expect(llm).not.toContain('mcp_rpc_error');
	});
});

describe('offeredBadgeFilter', () => {
	it('keeps only the codes the listed kinds can carry', () => {
		expect(offeredBadgeFilter('cache_hit,mcp_rpc_error', ['mcp'])).toEqual(['mcp_rpc_error']);
		expect(offeredBadgeFilter('cache_hit,mcp_rpc_error', ['llm'])).toEqual(['cache_hit']);
		expect(offeredBadgeFilter('cache_hit,mcp_rpc_error', ['llm', 'mcp'])).toEqual(['cache_hit', 'mcp_rpc_error']);
		expect(offeredBadgeFilter('session_alert,nope', ['llm', 'mcp', 'web', 'a2a'])).toEqual([]);
	});
});
