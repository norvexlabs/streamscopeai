<script lang="ts">
  import { BADGE_REGISTRY, type AuditBadge, type BadgeContext } from '#lib/badges.js';
  import Icon from './Icon.svelte';

  interface Props {
    badge: AuditBadge;
    /** Optional context the tooltip can use to add concrete detail
     *  (e.g. names of programs that triggered Modified). */
    context?: BadgeContext;
  }

  let { badge, context }: Props = $props();
  const entry = $derived(BADGE_REGISTRY[badge.code]);
</script>

{#if entry}
  <span
    class="inline-flex items-center gap-1 px-2.5 py-1 rounded-full text-[11px] font-medium {entry.classes}"
    title={entry.tooltip(badge, context)}
    data-audit-badge={badge.code}
  >
    <Icon name={entry.iconName} size="xs" color="currentColor" />
    {entry.label}
  </span>
{/if}
