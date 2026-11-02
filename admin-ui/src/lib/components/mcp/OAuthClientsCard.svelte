<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import Copyable from '#lib/components/Copyable.svelte';

  type OauthClientRow = components['schemas']['OauthClientRow'];

  interface Props {
    oauthClients: OauthClientRow[];
    oauthClientsLoading: boolean;
    oauthClientsError: string;
    onOpenNew: () => void;
    onOpenEdit: (row: OauthClientRow) => void;
    onDelete: (row: OauthClientRow) => void;
  }

  let { oauthClients, oauthClientsLoading, oauthClientsError, onOpenNew, onOpenEdit, onDelete }: Props = $props();

  function formatRedirectUris(value: unknown): string[] {
    if (!Array.isArray(value)) return [];
    return value.filter((v): v is string => typeof v === 'string');
  }
  // Plan-defined tooltips per registration_method.
  function methodTooltip(method: string): string {
    switch (method) {
      case 'manual':
        return "Operator pre-registered. Use this for apps that don't support DCR.";
      case 'dcr':
        return 'Self-registered via Dynamic Client Registration (RFC 7591) on first connect.';
      case 'cimd':
        return 'Uses Client ID Metadata Document — metadata fetched live from a published URL on each /authorize call. Lets the client rotate redirect URIs without re-registering.';
      default:
        return method;
    }
  }
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <!-- Header -->
  <div class="flex items-center justify-between px-6 py-4 border-b border-(--border)">
    <div>
      <h3 class="text-lg font-semibold text-(--text-primary)">OAuth Clients</h3>
      <p class="text-sm text-(--text-secondary) mt-1">
        Most MCP clients (Cursor, Claude Desktop, ChatGPT) self-register on first connect — they appear here
        automatically. Use <strong>+ Register</strong> only for apps that don't support DCR, or to pre-set redirect URIs
        for an internal app.
      </p>
    </div>
    <button
      type="button"
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium ml-4 shrink-0"
      onclick={onOpenNew}>+ Register</button>
  </div>

  <!-- Error -->
  {#if oauthClientsError}
    <div class="m-4 bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {oauthClientsError}
    </div>
  {/if}

  <!-- Body -->
  {#if oauthClientsLoading}
    <div class="px-6 py-8 text-sm text-(--text-secondary)">Loading…</div>
  {:else if oauthClients.length === 0}
    <!-- Empty state with discoverability copy -->
    <div class="px-6 py-12 text-center">
      <h4 class="text-base font-medium text-(--text-primary) mb-2">No OAuth clients registered yet</h4>
      <p class="text-sm text-(--text-secondary) max-w-md mx-auto mb-2">
        Clients appear here automatically when a user connects an app like Cursor or Claude Desktop to one of your
        <code class="bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">/mcp/&lt;slug&gt;</code> endpoints.
      </p>
      <p class="text-sm text-(--text-secondary) max-w-md mx-auto mb-4">
        Most operators never need to register manually. Click <strong>+ Register</strong> only if your app doesn't
        support Dynamic Client Registration (DCR).
      </p>
      <button
        type="button"
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium"
        onclick={onOpenNew}>+ Register</button>
    </div>
  {:else}
    <table class="w-full text-sm">
      <thead>
        <tr class="border-b border-(--border) bg-(--bg-primary)">
          <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Name</th>
          <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">client_id</th>
          <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Type</th>
          <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Redirect URIs</th>
          <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Created</th>
          <th class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each oauthClients as c (c.id)}
          <tr class="border-b border-(--border) hover:bg-(--bg-elevated) align-top">
            <td class="px-5 py-2.5 text-(--text-primary) font-medium">{c.name}</td>
            <td class="px-5 py-2.5 font-mono text-xs">
              <Copyable value={c.client_id} />
            </td>
            <td class="px-5 py-2.5">
              <span
                class="inline-block px-1.5 py-0.5 text-[10px] rounded-sm font-medium bg-(--bg-primary) border border-(--border) text-(--text-secondary)"
                title={methodTooltip(c.registration_method)}>{c.registration_method}</span>
            </td>
            <td class="px-5 py-2.5 text-xs">
              {#if c.registration_method === 'cimd'}
                <span class="text-(--text-secondary)">resolved live from</span>
                <code class="text-xs font-mono break-all">{c.client_id_metadata_url}</code>
              {:else}
                <ul class="space-y-0.5">
                  {#each formatRedirectUris(c.redirect_uris) as uri, i (i)}
                    <li class="font-mono break-all">{uri}</li>
                  {/each}
                </ul>
              {/if}
            </td>
            <td class="px-5 py-2.5 text-xs text-(--text-secondary)">{new Date(c.created_at).toLocaleDateString()}</td>
            <td class="px-5 py-2.5 text-right whitespace-nowrap">
              <button type="button" class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium mr-3" onclick={() => onOpenEdit(c)}>Edit</button>
              <button type="button" class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm font-medium" onclick={() => onDelete(c)}>Delete</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
