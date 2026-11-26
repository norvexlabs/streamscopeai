/**
 * The agent loop guard as the console edits it: the tenant default (three
 * settings keys) and a workspace's own value. The admin API is the authority
 * on the bounds; `loopGuardProblem` only says why a save would be refused
 * before it is sent.
 */
import type { components } from './generated/api-types';

export type LoopGuardSettings = components['schemas']['LoopGuardSettings'];
export type LoopGuardMode = components['schemas']['LoopGuardMode'];

/** The highest repetition count at which tool calls can be refused. */
export const LOOP_GUARD_MAX_STOP_AT = 50;

/** The lowest count for the note: a step seen once did not repeat. */
export const LOOP_GUARD_MIN_NUDGE_AT = 2;

export const LOOP_GUARD_DEFAULT: LoopGuardSettings = { mode: 'observe', nudge_at: 3, stop_at: 8 };

export const LOOP_GUARD_MODES: readonly { value: LoopGuardMode; label: string }[] = [
  { value: 'off', label: 'Off' },
  { value: 'observe', label: 'Observe' },
  { value: 'nudge', label: 'Nudge' },
  { value: 'stop', label: 'Stop' },
];

export const LOOP_GUARD_HELP =
  "When a request's history repeats the same tool call with the same result, the gateway records it (Observe), " +
  'adds a note asking the model to change approach (Nudge), and at the second threshold has the model answer in ' +
  'text instead of calling a tool (Stop).';

/** Why the admin API would refuse `g`, or `null` when it would accept it. */
export function loopGuardProblem(g: LoopGuardSettings): string | null {
  const { nudge_at, stop_at } = g;
  if (!Number.isInteger(nudge_at) || !Number.isInteger(stop_at)) return 'Both thresholds are whole numbers.';
  if (nudge_at < LOOP_GUARD_MIN_NUDGE_AT) return `The note needs at least ${LOOP_GUARD_MIN_NUDGE_AT} times in a row.`;
  if (stop_at < nudge_at + 2) return 'Refusing tool calls needs at least 2 more times in a row than the note.';
  if (stop_at > LOOP_GUARD_MAX_STOP_AT) return `Refusing tool calls needs at most ${LOOP_GUARD_MAX_STOP_AT} times in a row.`;
  return null;
}

/** One line naming what `g` does, e.g. "Stop · note from 3 · refuse from 8". */
export function describeLoopGuard(g: LoopGuardSettings): string {
  const label = LOOP_GUARD_MODES.find((m) => m.value === g.mode)?.label ?? g.mode;
  switch (g.mode) {
    case 'off':
    case 'observe':
      return label;
    case 'nudge':
      return `${label} · note from ${g.nudge_at}`;
    case 'stop':
      return `${label} · note from ${g.nudge_at} · refuse from ${g.stop_at}`;
  }
}
