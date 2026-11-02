// Domain → tag-palette mapping for admin-audit `action` verbs. The verb
// shape is `<resource_kind>.<verb>` (e.g. `users.create`, `keys.revoke`).
// Color is keyed off the first segment so every action targeting the same
// resource family renders in the same hue across the audit list.

import type { TagColor } from '#lib/components/TagBadge.svelte';

const RESOURCE_TAG: Record<string, TagColor> = {
  users: 'blue',
  groups: 'blue',
  admin_accounts: 'indigo',
  keys: 'violet',
  servers: 'teal',
  models: 'teal',
  catalog: 'cyan',
  downstream_providers: 'cyan',
  route_policies: 'cyan',
  mcp: 'teal',
  tool_rules: 'orange',
  tool_field_profiles: 'orange',
  transforms: 'amber',
  experts: 'amber',
  client_profiles: 'pink',
  settings: 'neutral',
  maintenance: 'rose',
  tenants: 'indigo',
  edge_nodes: 'cyan',
  changelog: 'neutral',
};

export function adminActionTag(action: string): TagColor {
  const head = action.split('.', 1)[0];
  return RESOURCE_TAG[head] ?? 'neutral';
}
