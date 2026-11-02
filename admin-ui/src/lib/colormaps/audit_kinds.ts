// Domain → tag-palette mapping for audit kinds. Used by <TagBadge> so the
// same logical category renders the same hue across every surface that
// shows kind chips (audit list, session breadcrumbs, future analytics).

import type { TagColor } from '#lib/components/TagBadge.svelte';

export type AuditKind = 'llm' | 'mcp' | 'web' | 'a2a';

export const auditKindColor: Record<AuditKind, TagColor> = {
  llm: 'blue',
  mcp: 'teal',
  web: 'amber',
  a2a: 'violet',
};

export function auditKindLabel(k: AuditKind): string {
  switch (k) {
    case 'llm': return 'LLM';
    case 'mcp': return 'MCP';
    case 'web': return 'Web';
    case 'a2a': return 'A2A';
  }
}
