<script lang="ts">
  /**
   * Shared shell for the first-party OAuth consent pages (MCP / CLI
   * authorize, CLI device approval): full-screen centered card with the
   * page title and the tenant chip. These pages render outside the portal
   * layout (they're consent surfaces, not portal navigation), so the shell
   * is the one piece of chrome they share.
   */
  import type { Snippet } from 'svelte';
  import { m } from '#lib/paraglide/messages.js';

  let { title, slug, children }: { title: string; slug: string; children: Snippet } = $props();
</script>

<div class="min-h-screen bg-(--bg-primary) flex items-center justify-center px-4 py-12">
  <div class="w-full max-w-md bg-(--bg-card) border border-(--border) rounded-2xl shadow-2xl p-6">
    <h1 class="text-xl font-semibold text-(--text-primary) mb-1">{title}</h1>
    <p class="text-sm text-(--text-secondary) mb-6">
      {m.portal_comp_tenant_label()} <code class="bg-(--bg-primary) px-1.5 py-0.5 rounded-sm text-(--text-primary) font-mono">{slug}</code>
    </p>
    {@render children()}
  </div>
</div>
