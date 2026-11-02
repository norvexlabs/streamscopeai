<script lang="ts" generics="T">
  import type { Snippet } from 'svelte';
  import Panel from './Panel.svelte';
  import PeriodBadge from './PeriodBadge.svelte';
  import ProviderIcon from '#lib/components/ProviderIcon.svelte';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';

  // Panel + UL of clickable key rows. The shape — name on top, `email · provider · <metaTail>`
  // underneath, a right-side affordance — is shared by the Dormant Keys and Expiring Soon
  // lists on the Users dashboard. Each row is wrapped in an `<a>` when `getHref` returns a
  // value, otherwise a plain `<div>` (no hover state).

  interface ProviderInfo {
    name: string;
    icon?: string | null;
  }

  interface Props {
    title: string;
    subtitle?: string;
    loading?: boolean;
    /** Defaults to `!loading && items.length === 0`. */
    empty?: boolean;
    emptyMessage?: string;
    /** Numeric day count (rendered as `${period}d` by PeriodBadge). */
    periodDays?: number;

    items: readonly T[];
    getKeyId: (item: T) => string;
    getName: (item: T) => string;
    getEmail: (item: T) => string | null | undefined;
    getProvider: (item: T) => ProviderInfo | null | undefined;
    getHref: (item: T) => string | null | undefined;

    /** Final segment of the meta line. The leading `·` separator is emitted
     *  by the component unconditionally — `metaTail` MUST always render
     *  non-empty content, else a dangling dot appears. */
    metaTail: Snippet<[T]>;
    /** Right-side affordance: button, chip, countdown, etc. Snippet owns its
     *  own `stopPropagation` if needed — the row wrapper bubbles clicks. Must
     *  not contain `<a>` when `getHref` returns a value (nested `<a>` is
     *  invalid HTML). */
    trailing: Snippet<[T]>;
  }

  let {
    title,
    subtitle,
    loading = false,
    empty,
    emptyMessage,
    periodDays,
    items,
    getKeyId,
    getName,
    getEmail,
    getProvider,
    getHref,
    metaTail,
    trailing,
  }: Props = $props();

  const isEmpty = $derived(empty ?? (!loading && items.length === 0));
</script>

<Panel {title} {subtitle} {loading} empty={isEmpty} {emptyMessage}>
  {#snippet headerExtra()}
    {#if periodDays != null}
      <PeriodBadge period={periodDays} />
    {/if}
  {/snippet}
  <ul class="space-y-3 -mx-1.5">
    {#each items as item (getKeyId(item))}
      {@const href = scopeHref(page.params.slug ?? '', page.url.pathname, getHref(item) ?? undefined)}
      {@const email = getEmail(item)}
      {@const provider = getProvider(item)}
      <li>
        <svelte:element
          this={href ? 'a' : 'div'}
          href={href}
          class="flex items-center gap-3 px-1.5 py-1 rounded-lg {href ? 'hover:bg-(--bg-elevated) transition-colors' : ''}"
        >
          <div class="flex-1 min-w-0">
            <p class="text-sm text-(--text-primary) truncate">{getName(item)}</p>
            <p class="text-[10px] text-(--text-secondary) mt-0.5 font-mono flex items-center gap-1.5 flex-wrap">
              <span>{email || '—'}</span>
              {#if provider}
                <span class="opacity-40">·</span>
                <span class="inline-flex items-center gap-1">
                  {#if provider.icon}<ProviderIcon name={provider.icon} />{/if}
                  {provider.name}
                </span>
              {/if}
              <span class="opacity-40">·</span>
              {@render metaTail(item)}
            </p>
          </div>
          {@render trailing(item)}
        </svelte:element>
      </li>
    {/each}
  </ul>
</Panel>
