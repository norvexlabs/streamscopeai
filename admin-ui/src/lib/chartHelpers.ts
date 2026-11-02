/**
 * Shared time-bucket helpers for analytics charts. Every dashboard chart
 * resolves its period via the same `interval` discriminator ("hour" / "day")
 * the backend emits on timeseries responses; this module turns that into
 * concrete millisecond widths and a bucket-state classifier so chart code
 * doesn't reinvent the wheel.
 */

export type BucketState = 'settled' | 'partial' | 'future';

/** Width of one bucket in milliseconds. Anything that isn't `"hour"` is treated as `"day"`. */
function intervalMs(interval: string | undefined): number {
  return interval === 'hour' ? 3_600_000 : 86_400_000;
}

/**
 * Classify a bucket relative to `now`:
 * - `settled`  → bucket has fully elapsed
 * - `partial`  → bucket has started but not yet ended (today, or current hour)
 * - `future`   → bucket hasn't started yet (only possible for absolute date ranges that extend forward)
 *
 * `now` is parameterized for testability; defaults to `Date.now()`.
 */
export function bucketState(
  start: string | Date,
  interval: string | undefined,
  now: number = Date.now(),
): BucketState {
  const startMs = typeof start === 'string' ? new Date(start).getTime() : start.getTime();
  if (startMs >= now) return 'future';
  if (startMs + intervalMs(interval) > now) return 'partial';
  return 'settled';
}

/** Whether the trailing bucket in a chronological series is partial OR future (i.e. not fully settled). */
export function trailingIncomplete(
  bucketStarts: Array<string | Date>,
  interval: string | undefined,
  now: number = Date.now(),
): boolean {
  if (bucketStarts.length === 0) return false;
  return bucketState(bucketStarts[bucketStarts.length - 1], interval, now) !== 'settled';
}

/** Short, user-facing label suffix for a bucket state (empty string for settled). */
export function bucketStateLabel(state: BucketState): string {
  if (state === 'future') return ' (upcoming)';
  if (state === 'partial') return ' (partial)';
  return '';
}

/**
 * The smallest "nice" step at or above `raw`: 1, 2 or 5 × 10ⁿ — Heckbert's
 * nice numbers (Graphics Gems, 1990). Not d3's `tickStep`, which picks the
 * NEAREST such step (so an axis top built on it can fall below the data); here
 * a top is always a whole number of steps at or above the maximum, a count
 * axis never steps below one, and a midpoint can be made nice too. A
 * non-finite or non-positive `raw` gives 1 (`counts` aside).
 */
export function niceStep(raw: number, counts = false): number {
  // A count axis never steps by less than one: half a request is not a value.
  if (counts && raw <= 1) return 1;
  if (!Number.isFinite(raw) || raw <= 0) return 1;
  const magnitude = Math.pow(10, Math.floor(Math.log10(raw)));
  for (const f of [1, 2, 5, 10]) {
    // A relative tolerance, so a raw that IS a nice number is not pushed up
    // by floating-point noise (0.3 / 0.1 = 2.9999999999999996).
    if (raw <= f * magnitude * (1 + 1e-9)) return f * magnitude;
  }
  return 10 * magnitude;
}

/**
 * The top of a value axis: the next multiple of the nice step that splits
 * `max` into at most `intervals` parts, so the axis ends on a labelled tick
 * and the data fills most of it (12 → 15 in fours, 20 in twos; 0.6 → 0.6).
 * An empty or non-finite `max` gives 10, so an empty period still has an axis.
 */
export function niceMax(max: number, intervals = 4, counts = false): number {
  if (!Number.isFinite(max) || max <= 0) return 10;
  const step = niceStep(max / intervals, counts);
  return Number((step * Math.ceil(max / step - 1e-9)).toPrecision(12));
}

/**
 * The ticks of an axis from 0 to `top` (a {@link niceMax}): every multiple of
 * the same nice step, `top` included — the labels can never disagree with the
 * scale they sit on.
 */
export function niceTicks(top: number, intervals = 4, counts = false): number[] {
  if (!Number.isFinite(top) || top <= 0) return [0];
  const step = niceStep(top / intervals, counts);
  // Never past the top: a `top` from another interval count may not be a
  // multiple of this step, and a label off the scale would sit outside the plot.
  const n = Math.floor(top / step + 1e-9);
  return Array.from({ length: n + 1 }, (_, i) => Number((i * step).toPrecision(12)));
}

/** A row's plotted value, a missing or non-finite one read as 0. */
function plotted(row: Record<string, unknown>, key: string): number {
  const v = row[key];
  return typeof v === 'number' && Number.isFinite(v) ? v : 0;
}

/** The top of a y-axis shared by every plot in `plots`: the {@link niceMax} of
 *  the highest value any of `series` reaches in any of them, and never below
 *  `floor` (a capacity the data is read against). */
export function chartYMax(
  plots: ReadonlyArray<ReadonlyArray<Record<string, unknown>>>,
  series: ReadonlyArray<{ key: string }>,
  floor = 0,
  counts = false,
): number {
  let max = Math.max(floor, 0);
  for (const rows of plots) for (const r of rows) for (const s of series) max = Math.max(max, plotted(r, s.key));
  return niceMax(max, 4, counts);
}

/** The top of a three-label axis (top, midpoint, zero): twice one nice step,
 *  so the midpoint is a nice number too — for a count, a whole one. */
export function niceMaxWithMidpoint(max: number, counts = false): number {
  if (!Number.isFinite(max) || max <= 0) return 10;
  return 2 * niceStep(max / 2, counts);
}

/** The references a plot's scale should reach: those near the data (within
 *  twice its top). A limit far above it — a fleet's 512 slots over a load of
 *  20 — would flatten every line; it is shown at the top edge instead. */
export function referencesInReach<T extends { value: number }>(references: ReadonlyArray<T>, dataTop: number): T[] {
  return references.filter((r) => r.value <= Math.max(dataTop, 0) * 2 || dataTop <= 0);
}

/** Whether any of `series` plots a value above zero in `rows`. */
export function chartHasValue(
  rows: ReadonlyArray<Record<string, unknown>>,
  series: ReadonlyArray<{ key: string }>,
): boolean {
  return rows.some((r) => series.some((s) => plotted(r, s.key) > 0));
}

/** A clock tick (hours and minutes) for a short window of second-grained
 *  buckets. */
export function formatClockTick(d: Date): string {
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
}

/** The tooltip label of a second-grained bucket. */
export function formatClockTooltip(d: Date): string {
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false });
}

/** An x-axis tick for a bucket start. Hourly buckets read as a time, except
 *  the first bucket of a day, which reads as the date — otherwise two ticks
 *  24 h apart on a multi-day hourly window both read "09:00". */
export function formatBucketTick(d: Date, hourly: boolean): string {
  if (hourly && !(d.getHours() === 0 && d.getMinutes() === 0)) {
    return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
  }
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
}

/** The full bucket label a chart tooltip leads with. */
export function formatBucketTooltip(d: Date, hourly: boolean): string {
  if (hourly) {
    const date = d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    const time = d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', hour12: false });
    return `${date} · ${time}`;
  }
  return d.toLocaleDateString(undefined, { weekday: 'short', month: 'short', day: 'numeric' });
}

/** The categorical series palette — one colour per series (an edge, an
 *  endpoint), cycled. Every multi-series chart takes its colours from here. */
const CHART_PALETTE = [
  'var(--chart-1)', 'var(--chart-2)', 'var(--chart-3)', 'var(--chart-4)', 'var(--chart-5)',
  'var(--chart-6)', 'var(--chart-7)', 'var(--chart-8)', 'var(--chart-9)', 'var(--chart-10)',
] as const;

/** The palette colour of the `i`-th series. */
export function seriesColor(i: number): string {
  return CHART_PALETTE[i % CHART_PALETTE.length];
}
