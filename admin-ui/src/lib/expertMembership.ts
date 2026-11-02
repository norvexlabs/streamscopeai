/**
 * Which experts run on an expert profile, as its editor shows and edits it.
 *
 * `own` is the profile's own member list — what the membership endpoint
 * returns and replaces. `inDefault` is the Default profile's members, which a
 * Layered profile runs as well (empty for the Default and a Standalone one).
 */

/** How one expert's card reads on a profile. */
export type CardState = {
  /** It analyzes this profile's workspaces. */
  runs: boolean;
  /** The profile lists it itself. */
  ownListed: boolean;
  /** The Default includes it (a Layered profile runs it either way). */
  inDefault: boolean;
  /** Toggling changes nothing — it runs through the Default alone. */
  locked: boolean;
};

export function cardState(id: string, own: ReadonlySet<string>, inDefault: ReadonlySet<string>): CardState {
  const ownListed = own.has(id);
  const viaDefault = inDefault.has(id);
  return { runs: ownListed || viaDefault, ownListed, inDefault: viaDefault, locked: viaDefault && !ownListed };
}

/** "Select all": every expert not already run through the Default becomes an
 *  own member; existing own members are kept. */
export function selectAll(
  ids: readonly string[],
  own: ReadonlySet<string>,
  inDefault: ReadonlySet<string>,
): Set<string> {
  return new Set([...own, ...ids.filter((id) => !inDefault.has(id))]);
}

/** Whether the own list differs from the saved one (order is not a change). */
export function membershipChanged(own: ReadonlySet<string>, saved: ReadonlySet<string>): boolean {
  return own.size !== saved.size || [...own].some((id) => !saved.has(id));
}

/** How many experts will analyze the profile's workspaces: running here and
 *  switched on. */
export function runningCount(
  experts: readonly { id: string; enabled: boolean }[],
  own: ReadonlySet<string>,
  inDefault: ReadonlySet<string>,
): number {
  return experts.filter((e) => e.enabled && (own.has(e.id) || inDefault.has(e.id))).length;
}
