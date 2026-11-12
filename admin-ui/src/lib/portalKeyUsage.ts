// Portal API keys page: the periods its per-key usage table offers, as the
// window it asks `/api/v1/portal/stats` for.

/** Today, the last 7 or the last 30 UTC days — today included in each, as
 *  the portal Home counts its own "last 7 days". */
export type KeyUsagePeriod = 'today' | 'last_7_days' | 'last_30_days';

const DAYS: Record<KeyUsagePeriod, number> = { today: 1, last_7_days: 7, last_30_days: 30 };

/** The window's start: 00:00 UTC of the period's first day (the window ends
 *  now). */
export function keyUsageStart(period: KeyUsagePeriod, now: Date): string {
  const midnight = Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate());
  return new Date(midnight - (DAYS[period] - 1) * 86_400_000).toISOString();
}
