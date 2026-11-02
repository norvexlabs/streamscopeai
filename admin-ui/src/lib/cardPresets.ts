/**
 * Shared headline-card presets for dashboard pages.
 *
 * Latency and reliability cards repeat across `/dashboard/llm`,
 * `/dashboard/web`, and friends. This module keeps the wording, ordering,
 * icon, and tone in sync.
 *
 * Conventions enforced here:
 *   1. **Card ordering** on a headline row goes
 *        Volume → Cost / Tokens → **Latency** → **Reliability** →
 *        Stock counters → Categorical breakdowns
 *      (latency before reliability — performance signal first, quality
 *      signal second).
 *   2. **Latency cards** always show `Latency P50` as the headline
 *      number with `P95 · P99` as the subtitle. Same icon + same
 *      tone everywhere.
 *   3. **Reliability cards** always show success rate as the headline
 *      and error count + slow request count as the subtitle. Icon tone
 *      stays `success` (category identity); the value digits ramp
 *      green → yellow → red on the underlying error rate.
 */

import { formatDuration, formatCount } from './formatters';

/** Reliability score color — green/yellow/red based on error rate (%). */
function reliabilityColor(errorRatePct: number): string {
  if (errorRatePct > 5) return 'var(--error)';
  if (errorRatePct > 1) return 'var(--warning)';
  return 'var(--success)';
}

// ---------------------------------------------------------------------------
// Card preset builders. Returned shape matches the props of
// `<MetricCard>` so they can be spread directly: `<MetricCard {...preset} />`.
// ---------------------------------------------------------------------------

export type LatencyInput = {
  p50_ms: number | null | undefined;
  p95_ms: number | null | undefined;
  p99_ms: number | null | undefined;
  /** Optional second subtitle line — passed through to MetricCard. Used
   *  by the LLM dashboard to surface TTFT alongside total latency. */
  subtitle2?: string;
  /** "30d" / "7d" — appended to the period chip. */
  periodDays?: number;
};

export function latencyCard(input: LatencyInput) {
  return {
    label: 'Latency P50',
    value: formatDuration(input.p50_ms ?? 0),
    subtitle: `P95 ${formatDuration(input.p95_ms ?? 0)} · P99 ${formatDuration(input.p99_ms ?? 0)}`,
    subtitle2: input.subtitle2,
    icon: 'clock' as const,
    // p95 drives the trend chip — more stable than p50 (catches tail-latency
    // creep) without being as noisy as p99.
    trendValue: input.p95_ms ?? undefined,
    period: input.periodDays != null ? `${input.periodDays}d` : undefined,
  };
}

export type ReliabilityInput = {
  totalRequests: number;
  errorCount: number;
  /** Count of "slow" requests — typically TTFT > 10s on LLM, or any
   *  high-latency-bucketed measure on other pages. Optional. */
  slowCount?: number;
  slowLabel?: string;
  /** Optional second subtitle line — same shape as `latencyCard`. */
  subtitle2?: string;
  periodDays?: number;
};

export function reliabilityCard(input: ReliabilityInput) {
  const errorRate = input.totalRequests > 0
    ? (input.errorCount / input.totalRequests) * 100
    : 0;
  const successRate = input.totalRequests > 0 ? 100 - errorRate : 100;
  const subtitleParts = [`${formatCount(input.errorCount)} errors`];
  if (input.slowCount != null && input.slowLabel) {
    subtitleParts.push(`${formatCount(input.slowCount)} ${input.slowLabel}`);
  }
  return {
    label: 'Reliability',
    value: input.totalRequests > 0 ? `${successRate.toFixed(1)}%` : '--',
    subtitle: subtitleParts.join(' · '),
    subtitle2: input.subtitle2,
    icon: 'reliability' as const,
    valueColor: reliabilityColor(errorRate),
    // Error count drives the trend chip — a rising arrow on a reliability
    // tile signals "more errors than last refresh" (actionable), independent
    // of the success-rate digit. No reading without traffic (the page passes
    // placeholder zeros before its summary loads).
    trendValue: input.totalRequests > 0 ? input.errorCount : undefined,
    period: input.periodDays != null ? `${input.periodDays}d` : undefined,
  };
}
