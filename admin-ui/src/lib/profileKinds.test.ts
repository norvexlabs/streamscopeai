import { describe, expect, it } from 'vitest';
import { PROFILE_KINDS, profileCount } from './profileKinds.js';

describe('profileCount', () => {
	it('a_layered_profile_counts_its_own_additions_only_where_the_kind_layers', () => {
		const layered = { rule_count: 2, is_default: false, standalone: false };
		expect(profileCount(PROFILE_KINDS.tools, layered)).toEqual({
			text: '+2 of its own',
			title: 'Its own items (on top of the Default)',
		});
		// The Default and a Standalone own their whole content.
		expect(profileCount(PROFILE_KINDS.tools, { ...layered, is_default: true })?.text).toBe('2 items');
		expect(profileCount(PROFILE_KINDS.transform, { ...layered, standalone: true })?.text).toBe('2 items');
		// A kind that does not layer counts the same whatever the mode.
		expect(profileCount(PROFILE_KINDS.expert, layered)?.text).toBe('2 experts');
	});

	it('one_is_singular_and_a_kind_with_no_count_shows_none', () => {
		const one = { rule_count: 1, is_default: true, standalone: true };
		expect(profileCount(PROFILE_KINDS.client_access, one)?.text).toBe('1 client');
		expect(profileCount(PROFILE_KINDS.client_access, { ...one, rule_count: 0 })?.text).toBe('0 clients');
		expect(profileCount(PROFILE_KINDS.guardrail, one)).toBeNull();
	});
});

describe('PROFILE_KINDS', () => {
	it('only_portal_and_clients_is_standalone_only_and_every_other_kind_names_its_off', () => {
		for (const [kind, info] of Object.entries(PROFILE_KINDS)) {
			expect(info.standaloneOnly, kind).toBe(kind === 'client_access');
			if (!info.standaloneOnly) expect(info.offRuns, kind).not.toBe('');
			expect(info.root.startsWith('/'), kind).toBe(true);
		}
	});
});
