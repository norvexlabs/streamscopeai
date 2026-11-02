// QoS: how long a class really waits, what runs as it, a server's QoS mode, and
// what its scheduler is doing now.
//
// A class's wait is never applied as stored. The gateway holds a request for
// the class's own wait, else the deployment default, and never longer than the
// deployment maximum — `min(class ?? default, max)`. Showing the stored value
// alone would promise a wait the gateway does not give, so the page shows what
// this resolves to.

import type { components } from './generated/api-types';
import type { IconName, Tone } from './icons';

/** A deployment setting as the gateways run it: equal ends when they agree. */
export interface FleetMs {
  low_ms: number;
  high_ms: number;
}

/** A wait as the gateways apply it — a range when gateways disagree. */
export interface EffectiveWait {
  low_ms: number;
  high_ms: number;
  /** `class`: the class names its own wait; `default`: the deployment's. */
  source: 'class' | 'default';
  /** The class asks for more than some gateway allows, and is cut to its maximum. */
  capped: boolean;
}

/**
 * The wait a class gets. `null` when the deployment limits are unknown: a
 * guess would read as a promise.
 */
export function effectiveWait(
  classMs: number | null | undefined,
  limits: { default_hold: FleetMs; max_wait: FleetMs } | null,
): EffectiveWait | null {
  if (!limits) return null;
  const { default_hold: hold, max_wait: max } = limits;
  // The default hold is already `min(default, max)` per gateway: combining the
  // fleet's ends of the two separately would state a hold no gateway gives.
  if (classMs == null) {
    return { low_ms: hold.low_ms, high_ms: hold.high_ms, source: 'default', capped: false };
  }
  return {
    low_ms: Math.min(classMs, max.low_ms),
    high_ms: Math.min(classMs, max.high_ms),
    source: 'class',
    capped: classMs > max.low_ms,
  };
}

/** "10s", or "10s–15s" while gateways disagree. */
export function formatWaitRange(w: { low_ms: number; high_ms: number }, fmt: (ms: number) => string): string {
  return w.low_ms === w.high_ms ? fmt(w.low_ms) : `${fmt(w.low_ms)}–${fmt(w.high_ms)}`;
}

function plural(n: number, one: string, many: string): string {
  return `${n} ${n === 1 ? one : many}`;
}

/**
 * What is assigned this class explicitly, in words. The default class also
 * serves everything that names no class, which no count can say, so it is
 * stated rather than counted.
 */
export function assignmentSummary(c: {
  workspace_count: number;
  key_count: number;
  route_target_count: number;
  is_default: boolean;
}): string[] {
  const parts: string[] = [];
  if (c.workspace_count > 0) parts.push(plural(c.workspace_count, 'workspace', 'workspaces'));
  if (c.key_count > 0) parts.push(plural(c.key_count, 'key', 'keys'));
  if (c.route_target_count > 0) parts.push(plural(c.route_target_count, 'route target', 'route targets'));
  if (c.is_default) parts.push(parts.length > 0 ? 'and everything without a class' : 'everything without a class');
  return parts;
}

// ── A server's QoS mode ──────────────────────────────────────────────────────
//
// Three stored fields decide what the gateway does with a server's traffic —
// the two capacity bounds and the scheduling dialect — but they combine into
// only three behaviours, which is what the page offers. The mode is DERIVED
// from the fields, never stored, so a server edited through the API reads back
// as whatever it now does.

/** What the gateway does with a server's traffic under load. */
export type QosMode =
  /** Straight through: no holding, no priority on the wire. */
  | 'off'
  /** No holding; the class rank rides to the engine, which orders its own queue. */
  | 'engine_priority'
  /** The gateway holds what does not fit and releases it in priority order, fairly. */
  | 'gateway';

export interface SchedulingFields {
  scheduling_dialect: string;
  max_in_flight: number | null;
  waiting_threshold: number | null;
  adaptive_concurrency: boolean;
}

/**
 * `gated` is the server's own answer — a bound on the server OR on any enabled
 * endpoint — because an endpoint's override gates on its own: reading only the
 * server's fields would call a server "Off" while one replica still holds.
 */
export function qosModeOf(f: { scheduling_dialect: string; gated: boolean }): QosMode {
  if (f.gated) return 'gateway';
  return f.scheduling_dialect !== 'none' ? 'engine_priority' : 'off';
}

/**
 * The server fields a mode writes. Gateway-managed needs at least one bound —
 * with none, nothing is ever held and the mode would read back as another —
 * so it returns the reason instead of fields. A learned (adaptive) limit is a
 * bound of its own, with `max_in_flight` as its optional ceiling, and it
 * REPLACES the engine-queue bound: the server refuses the two together, so a
 * queue bound left on an endpoint is a reason too. The two modes that hold
 * nothing must also clear every endpoint's own bounds; the caller does that.
 */
export function fieldsForMode(
  mode: QosMode,
  gateway: {
    max_in_flight: number | null;
    waiting_threshold: number | null;
    engine_priority: boolean;
    /** Learn the in-flight limit from the engine instead of fixing it. */
    adaptive?: boolean;
    /** Some endpoint carries a bound of its own, which gates it on its own. */
    endpoint_bounds?: boolean;
    /** Some endpoint carries an engine-queue bound of its own. */
    endpoint_queue_bounds?: boolean;
  },
): SchedulingFields | { error: string } {
  switch (mode) {
    case 'off':
      return { scheduling_dialect: 'none', max_in_flight: null, waiting_threshold: null, adaptive_concurrency: false };
    case 'engine_priority':
      return { scheduling_dialect: 'vllm_priority', max_in_flight: null, waiting_threshold: null, adaptive_concurrency: false };
    case 'gateway': {
      const scheduling_dialect = gateway.engine_priority ? 'vllm_priority' : 'none';
      if (gateway.adaptive) {
        if (gateway.endpoint_queue_bounds) {
          return { error: 'A learned limit replaces the engine queue bound: clear it on every endpoint first.' };
        }
        return { scheduling_dialect, max_in_flight: gateway.max_in_flight, waiting_threshold: null, adaptive_concurrency: true };
      }
      if (gateway.max_in_flight == null && gateway.waiting_threshold == null && !gateway.endpoint_bounds) {
        return { error: 'Set the requests in flight per engine, the engine queue allowed, or both.' };
      }
      return {
        scheduling_dialect,
        max_in_flight: gateway.max_in_flight,
        waiting_threshold: gateway.waiting_threshold,
        adaptive_concurrency: false,
      };
    }
  }
}

// ── A learned in-flight limit ────────────────────────────────────────────────

export type AdaptiveLiveState = components['schemas']['AdaptiveState'];

/** How each state of a learned limit is shown. */
export const ADAPTIVE_STATE: Record<AdaptiveLiveState, { label: string; icon: IconName; tone: Tone; detail: string }> = {
  unknown: { label: 'Unknown', icon: 'info', tone: 'neutral', detail: 'A newer gateway reported a state this console does not know.' },
  starting: { label: 'Starting', icon: 'info', tone: 'neutral', detail: 'Waiting for a second engine reading to compare with the first.' },
  steady: { label: 'Steady', icon: 'checkCircle', tone: 'success', detail: 'Nothing pressed against the limit, or nothing said to change it.' },
  probing: { label: 'Probing', icon: 'trendingUp', tone: 'info', detail: "Requests are held at the limit and the engine has memory to spare: the limit grows one step per engine round trip (its average time to first token), so each step's effect shows in the cache before the next." },
  backing_off: { label: 'Backing off', icon: 'arrowDown', tone: 'warning', detail: 'The engine preempted, or its KV cache reached its 97 % ceiling: the limit was cut to half of what was in flight (never below one).' },
  memory_bound: { label: 'Memory target reached', icon: 'memory', tone: 'info', detail: "Requests are held at the limit because the engine's memory is committed to its 90 % target: each running request is counted at the size requests reach by their end (their prompt and answer), not at what it holds so far, and one more would take the cache past the target. The limit holds where it is. More requests fit once running ones finish; more memory (a larger GPU) raises what fits." },
  at_ceiling: { label: 'At ceiling', icon: 'info', tone: 'info', detail: 'Requests are held at the ceiling set on the QoS tab while the engine has KV cache to spare: raise the ceiling to let the limit grow.' },
  latency_bound: { label: 'Token latency target', icon: 'clock', tone: 'info', detail: "The engine's inter-token latency is above its target — by default three times the engine's own time per token at low load, or the figure set on the QoS tab: the limit does not grow, and steps down while the latency stays above it. A higher target, or none, trades faster tokens for more work." },
  engine_queueing: { label: 'Engine is queueing', icon: 'triangleAlert', tone: 'warning', detail: "The engine keeps requests waiting although its KV cache has room. Its per-step token budget, whole-prompt admission or --max-num-seqs is the limit; the gateway holds its limit where it is. For a vLLM server, the QoS tab lists the engine settings that decide this." },
  no_reading: { label: 'Engine not heard', icon: 'blocked', tone: 'error', detail: "A gateway replica has no fresh engine reading, or one without the KV-cache gauge: it keeps the last learned limit (within the ceiling), else the ceiling, until the engine answers with it again." },
};

// ── What the scheduler is doing now ──────────────────────────────────────────

export type SchedulerState =
  /** No gateway is reporting for this server: nothing to say. */
  | 'unknown'
  /** Reported, but nothing gates the server: requests go straight to the engine. */
  | 'ungated'
  /** Reported, and nothing is held. */
  | 'idle'
  /** Requests are being held for capacity: priority and fairness are deciding. */
  | 'engaged'
  /** Requests were refused for capacity within the current hour. */
  | 'shedding'
  /** A gateway reads an engine and has stopped hearing from it: its queue bound is not applied. */
  | 'degraded';

/**
 * One word for the scheduler's state. Most serious first: a gateway that lost
 * its engine reading is not applying the bound it was given, whatever else is
 * true; a refusal outranks a wait, since a caller was turned away.
 */
export function schedulerState(
  live: { held: number; engines_silent: number; gated: boolean } | null | undefined,
  refusedNow: number,
): SchedulerState {
  if (!live) return 'unknown';
  if (live.engines_silent > 0) return 'degraded';
  // Refusals this hour outrank the present configuration: a server switched to
  // a mode that holds nothing still turned callers away earlier in the hour.
  if (refusedNow > 0) return 'shedding';
  // Read for its metrics only: nothing is held here, whatever the engine's own
  // queue says — "idle" would claim nothing is waiting.
  if (!live.gated) return 'ungated';
  if (live.held > 0) return 'engaged';
  return 'idle';
}

/** How each scheduler state is shown: an icon, a word and a tone. */
export const SCHEDULER_STATE: Record<
  SchedulerState,
  { label: string; icon: IconName; tone: Tone; detail: string }
> = {
  unknown: { label: 'No report', icon: 'info', tone: 'neutral', detail: 'No gateway reports on this server: it is not gated and its engines are not read.' },
  ungated: { label: 'Not gated', icon: 'info', tone: 'neutral', detail: 'The gateway holds nothing for this server: every request goes straight to the engine, whose own queue is shown below. Choose Gateway-managed on its QoS tab to have priority decide.' },
  idle: { label: 'Idle', icon: 'checkCircle', tone: 'success', detail: 'Nothing is waiting at the gateway: every request goes straight out, and classes decide nothing.' },
  engaged: { label: 'Queuing', icon: 'clock', tone: 'info', detail: 'Requests are waiting for capacity: they go out most important class first, and fairly within a class.' },
  shedding: { label: 'Refusing', icon: 'blocked', tone: 'error', detail: 'Requests were refused for capacity this hour: a class that is refused right away, or a wait that ran out.' },
  degraded: { label: 'Engine not heard', icon: 'triangleAlert', tone: 'warning', detail: "A gateway replica has stopped reading an engine's metrics: its queue bound or learned limit is not applied there." },
};
