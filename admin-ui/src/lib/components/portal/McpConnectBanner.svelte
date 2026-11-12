<script lang="ts">
  /**
   * Portal — the state banner for MCP servers waiting on the user: how many
   * need a sign-in or the user's own values, which ones, and the way to the
   * Sign-ins page. Renders nothing when none does.
   */
  import Callout from '#lib/components/Callout.svelte';
  import { pthref } from '#lib/tenant.js';
  import { m } from '#lib/paraglide/messages.js';

  /** `total`: how many servers wait, when `servers` lists only the first. */
  let {
    slug,
    servers,
    total,
  }: { slug: string; servers: ReadonlyArray<{ name: string; slug: string }>; total?: number } = $props();
  const count = $derived(Math.max(total ?? 0, servers.length));
</script>

{#if servers.length > 0}
  <div data-testid="mcp-connect-banner" data-count={count}>
    <Callout severity="warning" title={m.portal_mcp_banner_title({ count })}>
      {m.portal_mcp_banner_body({ names: servers.map((s) => s.name).join(', ') })}
      {#snippet action()}
        <a
          href={pthref(slug, '/portal/mcp/connections')}
          data-testid="mcp-connect-banner-link"
          class="inline-block px-3 py-1.5 rounded-lg border border-(--accent) text-(--accent) text-xs font-semibold hover:bg-(--bg-hover) transition-colors">{m.portal_mcp_banner_action()}</a>
      {/snippet}
    </Callout>
  </div>
{/if}
