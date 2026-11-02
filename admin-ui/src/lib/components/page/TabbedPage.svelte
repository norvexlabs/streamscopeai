<script lang="ts" generics="T extends string">
  import type { Snippet } from 'svelte';
  import Tabs from '#lib/components/Tabs.svelte';
  import Page from '#lib/components/page/Page.svelte';

  interface Tab<TId extends string> {
    id: TId;
    label: string;
  }

  let {
    title,
    subtitle,
    description,
    tabs,
    activeTab,
    onTabChange,
    filterBar,
    actions,
    children,
    badge,
  }: {
    title: string;
    /** Plain-text subtitle rendered under the title. */
    subtitle?: string;
    /** Rich description snippet — use this when the subtitle needs inline
     *  HTML (links, code spans). Mutually exclusive with `subtitle`. */
    description?: Snippet;
    tabs: Tab<T>[];
    /** The id of the currently-active tab. Caller seeds from `useTabState`
     *  or `getTabFromUrl` so refresh / deep-link works. */
    activeTab: T;
    /** Called when the user picks a different tab. The caller is
     *  responsible for storing the new id (typically via `useTabState`,
     *  which also writes `?tab=` back to the URL). */
    onTabChange: (next: T) => void;
    /** Optional filter strip rendered above the tab bar. */
    filterBar?: Snippet;
    /** Optional action area rendered to the right of the title (e.g. + Add Server). */
    actions?: Snippet;
    /** Body content; receives the active tab id so callers can render conditionally. */
    children: Snippet<[T]>;
    /** Optional badge slot forwarded to <Tabs> (per-tab indicators). */
    badge?: Snippet<[string]>;
  } = $props();

  function handleChange(next: string) {
    onTabChange(next as T);
  }
</script>

<Page {title} {subtitle} {description} {actions} {filterBar}>
  <Tabs {tabs} active={activeTab} onchange={handleChange} {badge} />

  {@render children(activeTab)}
</Page>
