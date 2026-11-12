/**
 * Shared formatting utilities for consistent number display across the admin UI.
 * All formatters auto-scale values to human-readable units while keeping
 * raw numeric values available for sorting.
 *
 * Date/number/relative-time output follows the active UI locale (the default is
 * `en` → `en-US`, so English output is unchanged unless the user picks another
 * language). Monetary values carry a currency: the money formatters take an
 * ISO 4217 code and fall back to the tenant's accounting currency, so a figure
 * is never rendered in a denomination it was not stated in.
 */
import { getLocale } from '#lib/paraglide/runtime.js';
import * as m from '#lib/paraglide/messages.js';
import { accountingCurrency } from '#lib/currency.svelte.js';

/** Map a Paraglide locale to the BCP-47 tag used by the Intl APIs. Keep in sync
 *  with the locales in project.inlang. */
const LOCALE_TAGS: Record<string, string> = {
  en: 'en-US',
  fr: 'fr-FR',
};

/** The Intl locale tag for the active UI locale. */
function localeTag(): string {
  const loc = getLocale();
  return LOCALE_TAGS[loc] ?? loc;
}

/** Format milliseconds to human-readable duration: 320ms, 2.4s, 1.5min */
export function formatDuration(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '--';
  if (ms === 0) return '0ms';
  if (ms < 1000) return `${Math.round(ms)}ms`;
  if (ms < 60_000) return `${(ms / 1000).toFixed(1)}s`;
  return `${(ms / 60_000).toFixed(1)}min`;
}

/** Format token count: 842, 12.4K, 1.2M */
export function formatTokens(n: number | null | undefined): string {
  if (n === null || n === undefined) return '--';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 1_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString(localeTag());
}

// ---------------------------------------------------------------------------
// Money
// ---------------------------------------------------------------------------
// Every monetary figure is stated in some currency, and the three formatters
// below all take one. Omitting it means "tenant money" — budgets, spend
// aggregates, live dashboards — and resolves to the accounting currency.
// A figure that carries its own denomination (an audit row's `cost_currency`,
// a rate map's `currency`) MUST pass it: the row records what the ledger said
// when it was written, which a later settings change cannot restate.

/** Cached narrow symbols, keyed by locale + code — `Intl.NumberFormat`
 *  construction is far from free and these render per table row. */
const SYMBOL_CACHE = new Map<string, string>();

/** Narrow currency symbol for an ISO 4217 code in the active locale: `$`, `€`,
 *  `£`. Falls back to the code itself (`CHF`) both for currencies the runtime
 *  spells out and for codes it doesn't recognise at all. */
function currencySymbol(code: string | null | undefined): string {
  const cur = (code || accountingCurrency()).toUpperCase();
  const cacheKey = `${localeTag()}|${cur}`;
  const hit = SYMBOL_CACHE.get(cacheKey);
  if (hit !== undefined) return hit;
  let symbol = cur;
  try {
    symbol =
      new Intl.NumberFormat(localeTag(), {
        style: 'currency',
        currency: cur,
        currencyDisplay: 'narrowSymbol',
      })
        .formatToParts(0)
        .find((p) => p.type === 'currency')?.value ?? cur;
  } catch {
    // Not a code this runtime knows — showing the code is honest, and an
    // invalid code must never take down a whole table of figures.
  }
  SYMBOL_CACHE.set(cacheKey, symbol);
  return symbol;
}

/** Join a symbol to an already-formatted magnitude. An alphabetic symbol is a
 *  bare code (`CHF 12.50`); a glyph sits flush against the digits (`$12.50`). */
function withSymbol(symbol: string, magnitude: string): string {
  return /^[A-Za-z]{2,}$/.test(symbol) ? `${symbol} ${magnitude}` : `${symbol}${magnitude}`;
}

/** Format a cost: <$0.01, $0.42, $12.50, $1.2K — and the negatives of each.
 *
 *  Sign is handled before the magnitude bands. Cache net savings is the one
 *  figure here that can legitimately go negative (a semantic alias buying
 *  embeddings on prompts nobody repeats), and without this a -$3.47 loss would
 *  fall into the sub-cent band and read as "<$0.01".
 *
 *  `currency` defaults to the tenant's accounting currency — pass the figure's
 *  own code whenever it carries one. */
export function formatCost(cost: number | null | undefined, currency?: string | null): string {
  if (cost === null || cost === undefined) return '--';
  const s = currencySymbol(currency);
  if (cost === 0) return withSymbol(s, '0.00');
  const sign = cost < 0 ? '-' : '';
  const n = Math.abs(cost);
  if (n < 0.01) return `${sign}<${withSymbol(s, '0.01')}`;
  if (n < 100) return sign + withSymbol(s, n.toFixed(2));
  if (n < 10_000) return sign + withSymbol(s, (n / 1_000).toFixed(1) + 'K');
  return sign + withSymbol(s, (n / 1_000).toFixed(0) + 'K');
}

/** Format an exact monetary amount — always two decimals, never abbreviated
 *  and never collapsed to "<$0.01". For figures compared against each other
 *  (spend vs cap) where rounding would misreport the comparison. */
export function formatAmount(amount: number | null | undefined, currency?: string | null): string {
  if (amount === null || amount === undefined) return '--';
  const s = currencySymbol(currency);
  const sign = amount < 0 ? '-' : '';
  return sign + withSymbol(s, Math.abs(amount).toFixed(2));
}

/** A money figure the API stated together with its denomination.
 *
 *  Both `SpendTotal` and `SpendBreakdown` share the `amount` + `currency` pair
 *  so one accessor renders either. */
export type Spend = { amount: number; currency: string };

/** Render a spend figure in the currency it was stated in.
 *
 *  An absent figure is **not** missing data: the API omits it when no single
 *  amount states the rows behind it. Say so, rather than showing a number in a
 *  denomination that is only right for part of it. `absent` names why: by
 *  default the rows span a change of accounting currency ("mixed"); a caller
 *  whose figure can be absent for another reason too passes a neutral label
 *  (`m.spend_not_stated_short`, a session's spend). */
export function formatSpend(
  spend: Spend | null | undefined,
  absent: () => string = m.spend_mixed_short,
): string {
  if (!spend) return absent();
  return formatCost(spend.amount, spend.currency);
}

/** Render a window's spend from its per-currency components.
 *
 *  One component is the ordinary case. Zero means nothing was spent. More than
 *  one means the window straddles a change of the tenant's accounting currency,
 *  and the components must be reported apart — adding them would give a figure
 *  in no currency at all. */
export function formatSpendList(spend: readonly Spend[] | null | undefined): string {
  if (!spend || spend.length === 0) return formatCost(0);
  if (spend.length === 1) return formatSpend(spend[0]);
  return m.spend_mixed_short();
}

/** Format byte count: 256B, 1.2KB, 4.5MB, 1.1GB */
export function formatBytes(bytes: number | null | undefined): string {
  if (bytes === null || bytes === undefined) return '--';
  if (bytes < 1024) return `${bytes}B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  return `${(bytes / (1024 * 1024 * 1024)).toFixed(1)}GB`;
}

/** How a key is named wherever it is listed: its name, else its prefix
 *  followed by an ellipsis (the key goes on past it). */
export function formatKeyLabel(name: string | null | undefined, prefix: string | null | undefined): string {
  return name || (prefix ? `${prefix}…` : '');
}

/** Format a count with auto-scaling: 42, 1.2K, 3.5M */
export function formatCount(n: number | null | undefined): string {
  if (n === null || n === undefined) return '--';
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`;
  if (n >= 10_000) return `${(n / 1_000).toFixed(1)}K`;
  return n.toLocaleString(localeTag());
}

/** A part of a whole as a percentage: "12.5%". A share of nothing is "--",
 *  never "0%" (nothing happened, which is not the same as none of it failing);
 *  a share too small to show at one decimal reads "<0.1%", never "0.0%". */
export function formatShare(part: number, total: number): string {
  if (!(total > 0)) return '--';
  const pct = (part / total) * 100;
  if (pct > 0 && pct < 0.1) return '<0.1%';
  return `${pct.toFixed(1)}%`;
}

/** A timestamp's signed distance from now (negative = past) as one rounded
 *  value in the largest unit that keeps its magnitude under the next (s < 60,
 *  min < 60, h < 24, days unbounded), or null when it does not parse. The ONE
 *  bucketing behind `formatTimeAgo` and `formatAge`, so a phrase and a figure
 *  for the same instant always agree. */
function distance(dateStr: string): { value: number; unit: 'second' | 'minute' | 'hour' | 'day' } | null {
  const t = new Date(dateStr).getTime();
  if (!Number.isFinite(t)) return null;
  // Round the MAGNITUDE, then restore the sign: `Math.round` sends a half
  // toward +∞, which would round a past and a future instant differently.
  // Each unit is rounded from the raw seconds, never from the previous
  // unit's rounded value — a cascade would round 1h29m up to 2h.
  const sign = t < Date.now() ? -1 : 1;
  const secs = Math.abs(t - Date.now()) / 1000;
  if (Math.round(secs) < 60) return { value: sign * Math.round(secs), unit: 'second' };
  const mins = Math.round(secs / 60);
  if (mins < 60) return { value: sign * mins, unit: 'minute' };
  const hours = Math.round(secs / 3600);
  if (hours < 24) return { value: sign * hours, unit: 'hour' };
  return { value: sign * Math.round(secs / 86400), unit: 'day' };
}

/** Format a timestamp relative to now in the active locale: now, 3 min. ago,
 *  2 hr. ago, in 3 days (en); à l'instant, il y a 3 min, il y a 2 h (fr). */
export function formatTimeAgo(dateStr: string | null | undefined): string {
  const d = dateStr ? distance(dateStr) : null;
  if (!d) return '--';
  // `short` (not `narrow`): narrow renders French as a bare "-3 min" instead of
  // the grammatical "il y a 3 min".
  const rtf = new Intl.RelativeTimeFormat(localeTag(), { numeric: 'auto', style: 'short' });
  if (d.unit === 'second') return rtf.format(0, 'second');
  if (d.unit === 'day' && Math.abs(d.value) >= 30) {
    return rtf.format(Math.sign(d.value) * Math.round(Math.abs(d.value) / 30), 'month');
  }
  return rtf.format(d.value, d.unit);
}

/** A compact elapsed time for a HEADLINE figure — a number and a unit in the
 *  active locale's narrow form, never a sentence (en: now, 5m, 13h, 3d). A
 *  stat card's value slot holds a figure; the phrase (`formatTimeAgo`, same
 *  instant, same rounding) goes in its caption. Days are the largest unit, so
 *  "45d" never reads as a month; a future instant (clock skew) reads "now". */
export function formatAge(dateStr: string | null | undefined): string {
  const d = dateStr ? distance(dateStr) : null;
  if (!d) return '--';
  if (d.unit === 'second' || d.value >= 0) {
    return new Intl.RelativeTimeFormat(localeTag(), { numeric: 'auto' }).format(0, 'second');
  }
  return new Intl.NumberFormat(localeTag(), { style: 'unit', unit: d.unit, unitDisplay: 'narrow' }).format(-d.value);
}

/** Format a date to a locale short string: Feb 27, 2026 (en); 27 févr. 2026 (fr) */
export function formatDate(dateStr: string | null | undefined): string {
  if (!dateStr) return '--';
  return new Date(dateStr).toLocaleDateString(localeTag(), {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
  });
}

/** A day bucket that starts at 00:00 UTC, by its short weekday ("Mon"): the
 *  UTC day, whatever the viewer's time zone. */
export function formatUtcWeekday(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString(localeTag(), { weekday: 'short', timeZone: 'UTC' });
}

/** A day bucket that starts at 00:00 UTC, as "Mon, Nov 9" in the UI locale. */
export function formatUtcDay(dateStr: string): string {
  return new Date(dateStr).toLocaleDateString(localeTag(), {
    weekday: 'short',
    day: 'numeric',
    month: 'short',
    timeZone: 'UTC',
  });
}

/** Format a datetime to a locale string: Feb 27, 2:34 PM (en); 27 févr., 14:34 (fr) */
export function formatDateTime(dateStr: string | null | undefined): string {
  if (!dateStr) return '--';
  return new Date(dateStr).toLocaleString(localeTag(), {
    month: 'short',
    day: 'numeric',
    hour: 'numeric',
    minute: '2-digit',
  });
}

/**
 * Format price with full precision (for rate tables and per-request costs).
 * Unlike formatCost, this never rounds to "<$0.01" — exact values matter.
 * Examples: $0.0060, $0.150, $2.50, $15.00 — two significant figures below a
 * cent, three decimals below a unit, two above.
 */
export function formatPrice(price: number | null | undefined, currency?: string | null): string {
  if (price === null || price === undefined) return '--';
  const s = currencySymbol(currency);
  if (price === 0) return withSymbol(s, '0.00');
  // Show enough decimal places to avoid losing precision
  if (price < 0.01) return withSymbol(s, price.toPrecision(2));
  if (price < 1) return withSymbol(s, price.toFixed(3));
  return withSymbol(s, price.toFixed(2));
}

/** Parse alert note lines into structured entries with per-line severity.
 * Format: "[axis:level] text" — sorted major > minor > info.
 * Unrecognized lines get empty axis and inherit session-level severity.
 */
type AlertSeverity = 'major' | 'minor' | 'info';

export interface AlertLine {
  axis: string;
  level: AlertSeverity;
  text: string;
}

const SEVERITY_RANK: Record<AlertSeverity, number> = { major: 0, minor: 1, info: 2 };

export function parseAlertLines(note: string | null | undefined, sessionLevel?: string | null): AlertLine[] {
  if (!note) return [];
  const lines = note.split('\n').filter(l => l.trim());
  const parsed: AlertLine[] = lines.map(line => {
    const match = line.match(/^\[([\w_]+):(major|minor|info)\]\s*(.*)$/);
    if (match) {
      return { axis: match[1], level: match[2] as AlertSeverity, text: match[3] };
    }
    return { axis: '', level: (sessionLevel as AlertSeverity) || 'minor', text: line };
  });
  parsed.sort((a, b) => SEVERITY_RANK[a.level] - SEVERITY_RANK[b.level]);
  return parsed;
}

/** Human-readable labels for finish_reason values */
const FINISH_REASON_LABELS: Record<string, string> = {
  stop: 'Completed',
  length: 'Truncated',
  tool_calls: 'Tool Call',
  content_filter: 'Filtered',
  error: 'Error',
};

/** Map raw finish_reason to human-readable display label */
export function formatFinishReason(reason: string | null | undefined): string {
  if (!reason) return '--';
  return FINISH_REASON_LABELS[reason] || reason;
}

/** CSS color for finish_reason status indicators */
export function finishReasonColor(reason: string): string {
  switch (reason) {
    case 'stop': return 'var(--success)';
    case 'length': return 'var(--warning)';
    case 'tool_calls': return 'var(--info-text)';
    case 'error': return 'var(--error)';
    case 'content_filter': return 'var(--tag-orange-text)';
    default: return 'var(--text-secondary)';
  }
}

/** Human-readable labels for error_category values */
const ERROR_CATEGORY_LABELS: Record<string, string> = {
  'upstream': 'Upstream Error',
  'auth': 'Authentication',
  'rate_limit': 'Rate Limit',
  'bad_request': 'Bad Request',
  'model_not_found': 'Model Not Found',
  'internal': 'Internal Error',
  'client_disconnect': 'Client Disconnect',
  'timeout': 'Stream Timeout',
  'stream_error': 'Stream Error',
};

/** Map raw error_category to human-readable display label */
export function formatErrorCategory(category: string | null | undefined): string {
  if (!category) return '--';
  return ERROR_CATEGORY_LABELS[category] || category.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
}

/** CSS color for error_category status indicators */
export function errorCategoryColor(category: string): string {
  switch (category) {
    case 'upstream':
    case 'internal':
    case 'timeout':
    case 'stream_error':
      return 'var(--error)';
    case 'rate_limit':
    case 'auth':
      return 'var(--warning)';
    case 'bad_request':
    case 'client_disconnect':
    case 'model_not_found':
      return 'var(--text-secondary)';
    default:
      return 'var(--text-secondary)';
  }
}

/** Convert period days to ISO date range. Output uses the canonical
 * `start`/`end` field names that every analytics-shaped endpoint accepts. */
export function daysToDateRange(days: number): { start: string; end: string } {
  const end = new Date();
  const start = new Date();
  start.setDate(start.getDate() - days);
  return { start: start.toISOString(), end: end.toISOString() };
}

/** Look up app name from registry map */
export function appName(registry: { get(key: string): { name?: string } | undefined }, id: string | null): string {
  if (!id) return '';
  return registry.get(id)?.name || id;
}

/** A2A task state (`TASK_STATE_INPUT_REQUIRED`) → display form
 * (`input required`). Unrecognized values pass through unchanged so a
 * newer protocol state is still shown rather than blanked. */
export function formatTaskState(state: string | null | undefined): string {
  if (!state) return '';
  return state.replace(/^TASK_STATE_/, '').toLowerCase().replace(/_/g, ' ');
}
