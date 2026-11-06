/**
 * The Analysis start control's date logic. The picker holds a local calendar
 * day and an optional minute of it, in the admin's own time zone.
 */

const pad = (n: number) => String(n).padStart(2, '0');

/** A local calendar day in the `YYYY-MM-DD` form a date input holds. */
export function localDay(at: Date): string {
  return `${at.getFullYear()}-${pad(at.getMonth() + 1)}-${pad(at.getDate())}`;
}

/** The instant a local calendar day starts, or `null` for a value that is not one. */
export function startOfLocalDay(day: string): Date | null {
  const m = /^(\d{4})-(\d{2})-(\d{2})$/.exec(day);
  if (!m) return null;
  const [year, month, date] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const at = new Date(year, month - 1, date);
  // A day that does not exist (02-31) rolls over, and a year under 100 reads as
  // 19xx: neither is the day asked for.
  return at.getFullYear() === year && at.getMonth() === month - 1 && at.getDate() === date ? at : null;
}

/**
 * The instant the Analysis start control names, or `null` for one that is not:
 * the start of `day` with no `time`, else that minute of it.
 */
export function localInstant(day: string, time: string): Date | null {
  const start = startOfLocalDay(day);
  if (!start || !time) return start;
  const m = /^(\d{2}):(\d{2})$/.exec(time);
  if (!m) return null;
  const [hours, minutes] = [Number(m[1]), Number(m[2])];
  if (hours > 23 || minutes > 59) return null;
  start.setHours(hours, minutes);
  // A minute a clock change skips rolls over: not the minute asked for.
  return start.getHours() === hours && start.getMinutes() === minutes ? start : null;
}

/**
 * Whether restarting from `from` leaves unanalyzed what an expert behind it has
 * not reached. A profile with an expert yet to start has no oldest position, and
 * `furthest` then says whether anything has started at all.
 */
export function leavesBehind(from: Date, oldest: string | null | undefined, furthest: string | null | undefined): boolean {
  if (oldest) return from.getTime() > new Date(oldest).getTime();
  return !!furthest;
}

/**
 * Whether restarting from `from` analyzes again what was already analyzed. A
 * profile with no position yet has analyzed nothing, so it re-reads nothing.
 */
export function analyzesAgain(from: Date, analyzedThrough: string | null | undefined): boolean {
  return !!analyzedThrough && from.getTime() < new Date(analyzedThrough).getTime();
}
