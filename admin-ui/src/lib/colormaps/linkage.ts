// Domain → tag-palette mapping for how a sub-agent session was linked to its
// parent: by the client's header, by the gateway's heuristic, or otherwise.

import type { TagColor } from '#lib/components/TagBadge.svelte';

export function linkageTag(confidence: string): TagColor {
  if (confidence === 'header') return 'teal';
  if (confidence === 'heuristic') return 'blue';
  return 'violet';
}
