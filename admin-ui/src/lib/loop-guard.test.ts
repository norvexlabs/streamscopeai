import { describe, expect, it } from 'vitest';
import { LOOP_GUARD_DEFAULT, LOOP_GUARD_MAX_STOP_AT, LOOP_GUARD_MIN_NUDGE_AT, describeLoopGuard, loopGuardProblem } from './loop-guard';

const g = (nudge_at: number, stop_at: number) => ({ mode: 'stop' as const, nudge_at, stop_at });

describe('loopGuardProblem', () => {
  it('accepts the built-in default', () => {
    expect(loopGuardProblem(LOOP_GUARD_DEFAULT)).toBeNull();
  });

  it('holds nudge_at at the minimum or more', () => {
    expect(loopGuardProblem(g(LOOP_GUARD_MIN_NUDGE_AT - 1, 8))).not.toBeNull();
    expect(loopGuardProblem(g(LOOP_GUARD_MIN_NUDGE_AT, 8))).toBeNull();
  });

  it('holds stop_at two or more past nudge_at', () => {
    expect(loopGuardProblem(g(3, 4))).not.toBeNull();
    expect(loopGuardProblem(g(3, 5))).toBeNull();
  });

  it('holds stop_at at the cap or below', () => {
    expect(loopGuardProblem(g(3, LOOP_GUARD_MAX_STOP_AT + 1))).not.toBeNull();
    expect(loopGuardProblem(g(3, LOOP_GUARD_MAX_STOP_AT))).toBeNull();
  });

  it('refuses a fraction or an empty field', () => {
    expect(loopGuardProblem(g(2.5, 8))).not.toBeNull();
    expect(loopGuardProblem(g(3, Number.NaN))).not.toBeNull();
  });

  it('checks the thresholds whatever the mode', () => {
    expect(loopGuardProblem({ mode: 'off', nudge_at: 3, stop_at: 4 })).not.toBeNull();
  });
});

describe('describeLoopGuard', () => {
  it('names only the thresholds the mode acts on', () => {
    expect(describeLoopGuard({ mode: 'off', nudge_at: 3, stop_at: 8 })).toBe('Off');
    expect(describeLoopGuard(LOOP_GUARD_DEFAULT)).toBe('Observe');
    expect(describeLoopGuard({ mode: 'nudge', nudge_at: 4, stop_at: 9 })).toBe('Nudge · note from 4');
    expect(describeLoopGuard(g(3, 8))).toBe('Stop · note from 3 · refuse from 8');
  });
});
