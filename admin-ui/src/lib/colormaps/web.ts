import type { TagColor } from '#lib/components/TagBadge.svelte';

/** Web tool operation — `search` vs `fetch`. Used on the Web dashboard
 *  filter pill, the breakdown row badges, and the audit-detail strip so
 *  the same operation reads the same hue everywhere it's surfaced. */
export function operationColor(op: string): TagColor {
  switch (op) {
    case 'search': return 'cyan';
    case 'fetch':  return 'orange';
    default:       return 'neutral';
  }
}
