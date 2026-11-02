<script lang="ts">
  import { portalWorkspace, sessionHref } from '#lib/selfScoped.js';
  // The single structured renderer for a set of session references — the
  // replacement for scraping UUIDs out of prose. Given resolved session ids
  // (e.g. a cross-session issue's `source_session_ids`), it renders each as a
  // short chip linking to that session, tenant-scoped for the active plane.
  import { page } from '$app/state';

  interface Props {
    /** Resolved session ids to render as links. */
    sessionIds: string[];
    /** Optional caption shown before the chips. */
    label?: string;
  }
  let { sessionIds, label }: Props = $props();
  let slug = $derived(page.params.slug ?? '');
  // The portal workspace being viewed rides every session link.
  const viewedWorkspace = portalWorkspace();
</script>

{#if sessionIds.length > 0}
  <div class="flex flex-wrap items-center gap-1.5">
    {#if label}
      <span class="text-[11px] text-(--text-secondary)">{label}</span>
    {/if}
    {#each sessionIds as sid (sid)}
      <a
        href={sessionHref(slug, page.url.pathname, sid, viewedWorkspace())}
        class="font-mono text-[11px] px-1.5 py-0.5 rounded-sm bg-(--bg-elevated) border border-(--border) text-(--accent) hover:border-(--accent) transition-colors"
        title={`Open session ${sid}`}
      >{sid.slice(0, 8)}…</a>
    {/each}
  </div>
{/if}
