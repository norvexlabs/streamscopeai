import type { TagColor } from '#lib/components/TagBadge.svelte';

/** Map a transform-program scope or content-kind string to its tag color.
 *  Used by /transforms (program list) and /transforms/[id] (diff view) so
 *  both surfaces agree on what each category looks like.
 *
 *  Aliasing rule: synonymous scopes ("tools"/"tool", "messages"/"text")
 *  collapse to the same color so the user sees the same hue regardless of
 *  the surface that emitted the label. */
export function scopeColor(scope: string): TagColor {
  switch (scope) {
    case 'global':         return 'blue';
    case 'system_prompt':  return 'violet';
    case 'thinking':       return 'violet';
    case 'messages':       return 'amber';
    case 'text':           return 'amber';
    case 'tools':          return 'teal';
    case 'tool':           return 'teal';
    default:               return 'neutral';
  }
}

/** Color for the per-program "models: …" and "apps: …" filter chips. */
export const filterChipColor = {
  models: 'blue',
  apps:   'violet',
} as const satisfies Record<string, TagColor>;
