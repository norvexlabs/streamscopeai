import { describe, expect, it } from 'vitest';
import { kindTakesOff, profileUsage, usedByLabel, type UsageWorkspace } from './profileUsage.js';

const DEFAULT = 'p-default';
const FINANCE = 'p-finance';
const PROFILES = [
	{ id: DEFAULT, is_default: true },
	{ id: FINANCE, is_default: false },
];

function ws(name: string, role: string, assigned: UsageWorkspace['assigned_profiles'] = []): UsageWorkspace {
	return { name, role, assigned_profiles: assigned };
}

describe('profileUsage', () => {
	it('an_assigned_workspace_uses_its_profile_and_every_other_the_default', () => {
		const usage = profileUsage('client_access', PROFILES, [
			ws('Default', 'default'),
			ws('Finance', 'standard', [{ kind: 'client_access', profile_id: FINANCE }]),
			ws('Platform', 'standard'),
		]);
		expect(usage.get(FINANCE)).toEqual(['Finance']);
		expect(usage.get(DEFAULT)).toEqual(['Default', 'Platform']);
	});

	it('only_the_assignment_of_the_kind_counts', () => {
		const usage = profileUsage('client_access', PROFILES, [
			ws('Finance', 'standard', [{ kind: 'tools', profile_id: FINANCE }]),
		]);
		expect(usage.get(FINANCE)).toEqual([]);
		expect(usage.get(DEFAULT)).toEqual(['Finance']);
	});

	it('a_workspace_turned_off_uses_no_profile', () => {
		const usage = profileUsage('tools', PROFILES, [ws('Quiet', 'standard', [{ kind: 'tools', profile_id: null }])]);
		expect(usage.get(DEFAULT)).toEqual([]);
		expect(usage.get(FINANCE)).toEqual([]);
	});

	it('a_kind_with_no_off_reads_an_assignment_without_a_profile_as_the_default', () => {
		const usage = profileUsage('client_access', PROFILES, [
			ws('Stray', 'standard', [{ kind: 'client_access', profile_id: null }]),
		]);
		expect(usage.get(DEFAULT)).toEqual(['Stray']);
		expect(kindTakesOff('client_access')).toBe(false);
		expect(kindTakesOff('tools')).toBe(true);
	});

	it('the_service_workspaces_are_left_out', () => {
		const usage = profileUsage('client_access', PROFILES, [ws('Agent', 'agent'), ws('Inline AI', 'inline')]);
		expect(usage.get(DEFAULT)).toEqual([]);
	});

	it('an_assignment_to_a_profile_not_listed_is_counted_nowhere', () => {
		const usage = profileUsage('client_access', PROFILES, [
			ws('Stale', 'standard', [{ kind: 'client_access', profile_id: 'p-gone' }]),
		]);
		expect([...usage.values()].flat()).toEqual([]);
	});

	it('with_no_default_an_unassigned_workspace_uses_none', () => {
		const usage = profileUsage('client_access', [{ id: FINANCE, is_default: false }], [ws('Platform', 'standard')]);
		expect(usage.get(FINANCE)).toEqual([]);
	});
});

describe('usedByLabel', () => {
	it('names_up_to_three_workspaces_and_counts_the_rest', () => {
		expect(usedByLabel([])).toBe('Used by no workspace');
		expect(usedByLabel(['A'])).toBe('Used by A');
		expect(usedByLabel(['A', 'B', 'C'])).toBe('Used by A, B, C');
		expect(usedByLabel(['A', 'B', 'C', 'D'])).toBe('Used by A, B, C and 1 more');
		expect(usedByLabel(['A', 'B', 'C', 'D', 'E'])).toBe('Used by A, B, C and 2 more');
	});
});
