// Typography and density shared by every dashboard stat card (<StatCard> and
// the value rows of <TrendingValue> / <ProtocolCard>), and the context through
// which <MetricGrid> tells its cards to render compact.
import { getContext, setContext } from 'svelte';

/** A single line with an ellipsis where a pointer can hover for the full text
 *  (every line carries a `title`). A touch screen has no hover, so there the
 *  line wraps instead — nothing is ever cut off where it cannot be read. */
export const STAT_TEXT_FIT = 'truncate [@media(hover:none)]:whitespace-normal [@media(hover:none)]:wrap-break-word';

/** The one value typography — fixed size, never scaled with the card width.
 *  On a touch screen a value wraps at a space first, and is broken inside a
 *  token (`overflow-wrap: anywhere`) only when that token alone is wider than
 *  the card — a split figure can still be read; a clipped one cannot. */
export function statValueClass(compact: boolean): string {
  return `${compact ? 'text-xl leading-7' : 'text-2xl leading-8'} font-bold tracking-tight font-mono truncate [@media(hover:none)]:whitespace-normal [@media(hover:none)]:wrap-anywhere`;
}

const COMPACT_KEY = Symbol('stat-card-compact');

/** Called by <MetricGrid>: its cards read `compact()` to pick the dense chrome
 *  (a narrow screen, where two regular cards do not fit side by side). */
export function provideStatCompact(compact: () => boolean): void {
  setContext(COMPACT_KEY, compact);
}

/** A card outside a <MetricGrid> is never compact. */
export function useStatCompact(): () => boolean {
  return getContext<(() => boolean) | undefined>(COMPACT_KEY) ?? (() => false);
}

