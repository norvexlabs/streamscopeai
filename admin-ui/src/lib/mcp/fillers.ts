/**
 * Who fills an MCP upstream's inputs, said the same way on every console
 * surface (the header editor, the adopt dialog, the upstream card), and the
 * state of each input as the administrator sees it.
 */
import type { Filler, Remote } from './headerInputs';
import { declaredInputs, remoteFillers } from './headerInputs';

/** The filler's name. */
export const FILLER_NAME: Record<Filler, string> = {
  admin: 'Administrator',
  user: 'Each user',
  client: 'The client',
};

/** What choosing the filler means, in one line. */
export const FILLER_HELP: Record<Filler, string> = {
  admin: 'Set here and shared by everyone; users never see it.',
  user: "Each user enters it in the portal's MCP Sign-ins page.",
  client: 'Sent by the client on each request; never stored.',
};

/**
 * One declared input of an upstream as its card shows it:
 * - `set` / `missing` / `unset` — an administrator's input with a value, a
 *   required one without one (every call fails until it is set), an optional
 *   one without one;
 * - `elsewhere` — a user's or the client's input, which the console never holds.
 */
type InputState = 'set' | 'missing' | 'unset' | 'elsewhere';

interface InputRow {
  id: string;
  filler: Filler | null;
  isSecret: boolean;
  state: InputState;
  /** The administrator's non-secret value, when set. */
  value: string | null;
}

export function inputRoster(
  remote: Remote,
  values: Record<string, string>,
  secretIds: readonly string[],
): InputRow[] {
  const fillers = remoteFillers(remote);
  return declaredInputs(remote).map((d) => {
    const filler = fillers[d.id] ?? null;
    const value = !d.isSecret && Object.hasOwn(values, d.id) ? values[d.id] : null;
    let state: InputState;
    if (filler !== 'admin') state = 'elsewhere';
    else if (d.isSecret ? secretIds.includes(d.id) : value !== null) state = 'set';
    else if (d.isRequired && (d.input.default ?? '') === '') state = 'missing';
    else state = 'unset';
    return { id: d.id, filler, isSecret: d.isSecret, state, value };
  });
}
