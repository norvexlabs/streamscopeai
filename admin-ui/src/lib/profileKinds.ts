/**
 * What the console says and does per profile kind — one entry per kind, so a
 * kind added to `ProfileListKind` without its entry does not compile.
 */
import type { ProfileListKind } from '#lib/scope.svelte.js';

export type ProfileKindInfo = {
	/** The feature page: its profile list, and the root of its editors. */
	root: string;
	/** The feature's name in the console. */
	label: string;
	/** What one profile is called ("tool profile"). */
	noun: string;
	/** What a profile gives a workspace of its own ("tool policy"). */
	distinct: string;
	/** What a workspace turned Off runs ("no tool policy"); unused where the
	 *  kind has no Off (`standaloneOnly`). */
	offRuns: string;
	/** Where to go from the list ("Open a profile to edit its rules."). */
	openHint: string;
	/** A sample name for a new profile. */
	placeholder: string;
	/** The "seed" start in the create form. */
	seedOption: string;
	/** The "blank" start; `null` where it reads by the mode chosen. */
	blankOption: string | null;
	/** What a profile's content count counts; `null` for a kind with none. */
	count: { one: string; many: string; title: string } | null;
	/** A Layered profile's count is its own additions, on top of the Default. */
	countsOwnAdditions: boolean;
	/** Every profile is an independent copy: no Layered, no Blank, no Off —
	 *  and the list names the workspaces each profile applies to. */
	standaloneOnly: boolean;
};

export const PROFILE_KINDS: Record<ProfileListKind, ProfileKindInfo> = {
	tools: {
		root: '/policy',
		label: 'Tool policy',
		noun: 'tool profile',
		distinct: 'tool policy',
		offRuns: 'no tool policy',
		openHint: 'Open a profile to edit its rules.',
		placeholder: 'Engineering-strict',
		seedOption: 'Seed — built-in defaults',
		blankOption: null,
		count: { one: 'item', many: 'items', title: 'Items in this profile' },
		countsOwnAdditions: true,
		standaloneOnly: false,
	},
	guardrail: {
		root: '/guardrail',
		label: 'Guardrail',
		noun: 'guardrail profile',
		distinct: 'guardrail posture',
		offRuns: 'no guardrail',
		openHint: 'Open a profile to edit its posture; the shared classifier backend lives under Settings → Guardrail.',
		placeholder: 'Strict',
		seedOption: 'Seed — default posture',
		blankOption: 'Blank — default posture',
		count: null,
		countsOwnAdditions: false,
		standaloneOnly: false,
	},
	transform: {
		root: '/transforms',
		label: 'Transforms',
		noun: 'transform profile',
		distinct: 'set of transforms',
		offRuns: 'no transforms',
		openHint: 'Open a profile to edit its programs.',
		placeholder: 'Redaction-heavy',
		seedOption: 'Seed — built-in defaults',
		blankOption: null,
		count: { one: 'item', many: 'items', title: 'Items in this profile' },
		countsOwnAdditions: true,
		standaloneOnly: false,
	},
	expert: {
		root: '/experts',
		label: 'Experts',
		noun: 'expert profile',
		distinct: 'set of experts',
		offRuns: 'no expert',
		openHint: 'Open a profile to choose its experts.',
		placeholder: 'Security-only',
		seedOption: 'Seed — all experts',
		blankOption: 'Blank — no experts',
		count: { one: 'expert', many: 'experts', title: 'Experts enabled on this profile' },
		countsOwnAdditions: false,
		standaloneOnly: false,
	},
	client_access: {
		root: '/client-access',
		label: 'Portal & clients',
		noun: 'Portal & clients profile',
		distinct: 'set of clients and sandbox rules',
		offRuns: '',
		openHint: 'Open a profile to choose its clients, its sandbox and what it hides in the portal.',
		placeholder: 'Finance',
		seedOption: 'Every client, no sandbox destination',
		blankOption: null,
		count: { one: 'client', many: 'clients', title: 'Clients offered by this profile' },
		countsOwnAdditions: false,
		standaloneOnly: true,
	},
};

/** A profile's content count as its list line shows it, with its tooltip. */
export function profileCount(
	info: ProfileKindInfo,
	profile: { rule_count: number; is_default: boolean; standalone: boolean },
): { text: string; title: string } | null {
	if (!info.count) return null;
	const n = profile.rule_count;
	if (info.countsOwnAdditions && !profile.is_default && !profile.standalone) {
		return { text: `+${n} of its own`, title: 'Its own items (on top of the Default)' };
	}
	return { text: `${n} ${n === 1 ? info.count.one : info.count.many}`, title: info.count.title };
}
