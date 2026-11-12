/**
 * Which workspaces each profile of one kind applies to, read from the
 * workspaces' own assignments — the "Used by" line of a profile list.
 */

/** The part of a workspace the usage reads. */
export type UsageWorkspace = {
	name: string;
	role: string;
	assigned_profiles: { kind: string; profile_id?: string | null }[];
};

/** The part of a profile the usage reads. */
export type UsageProfile = { id: string; is_default: boolean };

/** The built-in service workspaces: no developer provisions a client there. */
const SERVICE_ROLES = new Set(['agent', 'inline']);

/** The kinds a workspace cannot be turned Off for: an assignment with no
 *  profile resolves to the Default there, as the server resolves it. */
const NEVER_OFF = new Set(['client_access']);

/** Whether a workspace can be turned Off for `kind`. */
export function kindTakesOff(kind: string): boolean {
	return !NEVER_OFF.has(kind);
}

/**
 * The names of the workspaces each profile of `kind` applies to, by profile
 * id, in the order the workspaces are given. A workspace assigned a profile
 * uses it; one with no assignment of the kind uses the Default; one turned Off
 * for the kind uses none — except for a kind that has no Off (`kindTakesOff`),
 * where an assignment with no profile is the Default too. The Agent and Inline
 * AI workspaces are left out: they hold service keys, not a team.
 */
export function profileUsage(
	kind: string,
	profiles: UsageProfile[],
	workspaces: UsageWorkspace[],
): Map<string, string[]> {
	const usage = new Map<string, string[]>(profiles.map((p) => [p.id, []]));
	const fallback = profiles.find((p) => p.is_default)?.id;
	for (const w of workspaces) {
		if (SERVICE_ROLES.has(w.role)) continue;
		const assigned = w.assigned_profiles.find((a) => a.kind === kind);
		const off = !!assigned && !assigned.profile_id && kindTakesOff(kind);
		const id = off ? undefined : (assigned?.profile_id ?? fallback);
		if (id) usage.get(id)?.push(w.name);
	}
	return usage;
}

/** The "Used by" line for one profile's workspaces. */
export function usedByLabel(names: string[]): string {
	if (names.length === 0) return 'Used by no workspace';
	if (names.length <= 3) return `Used by ${names.join(', ')}`;
	return `Used by ${names.slice(0, 3).join(', ')} and ${names.length - 3} more`;
}
