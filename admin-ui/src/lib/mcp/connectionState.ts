/**
 * What a portal user has to do on one MCP upstream, read from the
 * `PortalConnectionItem` the Sign-ins page lists: the state its badge shows,
 * the one primary action, and — for an upstream that needs both — the two
 * steps in the order they are done (values first, then the sign-in).
 */

/** The fields of a connection the decision reads. */
interface ConnectionFacts {
  /** `oauth` | `inputs` | `oauth_inputs`. */
  kind: string;
  /** `connected` | `expired` | `not_connected`. */
  status: string;
  /** Whether the user's OAuth sign-in is done (credential present, unexpired). */
  signed_in: boolean;
  inputs: Array<{ is_required: boolean; filled: boolean; default?: string | null }>;
}

type ConnectionState = 'connected' | 'needs_values' | 'needs_sign_in' | 'expired';
type ConnectionAction = 'values' | 'sign_in' | 'reconnect';

interface ConnectionStep {
  step: 'values' | 'sign_in';
  done: boolean;
}

interface ConnectionPlan {
  state: ConnectionState;
  /** The action the row offers first; `null` once connected. */
  primary: ConnectionAction | null;
  /** Both steps of an upstream needing values AND a sign-in; empty otherwise. */
  steps: ConnectionStep[];
}

export const hasSignIn = (c: ConnectionFacts): boolean => c.kind === 'oauth' || c.kind === 'oauth_inputs';
export const hasValues = (c: ConnectionFacts): boolean => c.kind === 'inputs' || c.kind === 'oauth_inputs';

/** The required inputs the user has not filled. One with a default — an empty
 *  one included — counts as filled, as the gateway counts it. */
export function missingValueCount(c: ConnectionFacts): number {
  return c.inputs.filter((i) => i.is_required && !i.filled && i.default == null).length;
}

export function connectionPlan(c: ConnectionFacts): ConnectionPlan {
  const valuesMissing = hasValues(c) && missingValueCount(c) > 0;
  let state: ConnectionState;
  let primary: ConnectionAction | null;
  if (c.status === 'connected' && !valuesMissing) {
    state = 'connected';
    primary = null;
  } else if (valuesMissing) {
    state = 'needs_values';
    primary = 'values';
  } else if (c.status === 'expired' && hasSignIn(c)) {
    state = 'expired';
    primary = 'reconnect';
  } else if (hasSignIn(c)) {
    state = 'needs_sign_in';
    primary = 'sign_in';
  } else {
    state = 'needs_values';
    primary = 'values';
  }
  const steps: ConnectionStep[] =
    c.kind === 'oauth_inputs'
      ? [
          { step: 'values', done: !valuesMissing },
          { step: 'sign_in', done: c.signed_in },
        ]
      : [];
  return { state, primary, steps };
}

/** The servers of a list that need the user to sign in or fill values. */
export function serversNeedingConnection<T extends { connection_status: string }>(servers: readonly T[]): T[] {
  return servers.filter((s) => s.connection_status === 'needs_connection');
}
