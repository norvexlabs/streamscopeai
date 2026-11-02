// Domain → tag-palette mapping for HTTP verbs on admin mutations.
// Used by <TagBadge> on the admin-audit list to make GET/POST/PUT/PATCH/DELETE
// visually distinct at a glance. GET never reaches the audit log (read-only
// verbs are skipped by the middleware), but it's mapped for completeness in
// case the column carries it later.

import type { TagColor } from '#lib/components/TagBadge.svelte';

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE';

const httpMethodColor: Record<HttpMethod, TagColor> = {
  GET: 'neutral',
  POST: 'teal',
  PUT: 'amber',
  PATCH: 'amber',
  DELETE: 'rose',
};

export function httpMethodTag(method: string): TagColor {
  return (httpMethodColor as Record<string, TagColor>)[method.toUpperCase()] ?? 'neutral';
}
