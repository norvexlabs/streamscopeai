// Whether a list may be ordered by a figure over the period the viewer picked.
// An order by figure sorts every row of the window before the first page is
// known, so the server bounds the window it accepts (`sort_needs_window`); the
// view offers the order only where it will be served.

import type { PeriodValue } from '#lib/scope.svelte.js';
import { daysToDateRange } from '#lib/formatters.js';

/** The longest window an order by figure may span, as the server bounds it. */
export const FIGURE_SORT_MAX_DAYS = 31;

const DAY_MS = 24 * 60 * 60 * 1000;

/** Whether `period` is a window an order by figure is served over. */
export function figureSortFits(period: PeriodValue, now: Date = new Date()): boolean {
  // A rolling period is measured as the request will send it: local calendar
  // days back (`daysToDateRange`), which across a clock change is a day plus
  // or minus an hour — the server bounds the span itself.
  const { start, end } =
    period.kind === 'rolling'
      ? period.days > 0
        ? daysToDateRange(period.days, now)
        : { start: '', end: '' }
      : period;
  const span = Date.parse(end) - Date.parse(start);
  return Number.isFinite(span) && span > 0 && span <= FIGURE_SORT_MAX_DAYS * DAY_MS;
}
