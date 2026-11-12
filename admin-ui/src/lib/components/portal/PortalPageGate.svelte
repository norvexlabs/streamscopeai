<script lang="ts">
  /**
   * A portal page an administrator can hide: shows the page, or — when it is
   * hidden for the viewer's workspaces — that it is not available.
   *
   * The gateway's answer decides. While the identity the layout holds does
   * not say the page is hidden, the page renders and reads: a refusal
   * (`portal_page_hidden`) then gives way to the state. While it does say so,
   * the state shows at once and the identity is re-read, so a page an
   * administrator has shown again comes back.
   */
  import { onMount, untrack, type Snippet } from 'svelte';
  import { page as route } from '$app/state';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import { pthref } from '#lib/tenant.js';
  import { m } from '#lib/paraglide/messages.js';
  import { hiddenPages, pageHidden, type PortalPage } from '#lib/portalPages.svelte.js';

  interface Props {
    /** The page this route is. */
    page: PortalPage;
    children: Snippet;
  }

  let { page, children }: Props = $props();

  const unavailable = $derived(pageHidden(page, route.data));

  onMount(() => {
    if (untrack(() => unavailable)) void hiddenPages.recheck();
  });
</script>

{#if unavailable}
  <div data-testid="portal-page-hidden" data-page={page}>
    <EmptyState title={m.portal_page_hidden_title()} body={m.portal_page_hidden_body()}>
      {#snippet action()}
        <a href={pthref(route.params.slug ?? '', '/portal/home')} class="text-sm text-(--accent) hover:underline">
          {m.portal_page_hidden_home()}
        </a>
      {/snippet}
    </EmptyState>
  </div>
{:else}
  {@render children()}
{/if}
