<script lang="ts">
  /**
   * Clients that identify themselves by a published metadata URL.
   *
   * They never register, so they have no row in the OAuth-clients table above
   * and that table's Delete cannot reach their tokens. This card is built from
   * the issued tokens instead — the only trace such a client leaves — which is
   * why it lists activity rather than configuration.
   */
  import type { components } from '#lib/generated/api-types.js';
  import Copyable from '#lib/components/Copyable.svelte';

  type CimdClientRow = components['schemas']['CimdClientRow'];

  interface Props {
    clients: CimdClientRow[];
    loading: boolean;
    error: string;
    onRevoke: (row: CimdClientRow) => void;
  }

  let { clients, loading, error, onRevoke }: Props = $props();
</script>

<div class="bg-(--bg-card) rounded-xl border border-(--border)">
  <div class="px-6 py-4 border-b border-(--border)">
    <h3 class="text-lg font-semibold text-(--text-primary)">Metadata-document clients</h3>
    <p class="text-sm text-(--text-secondary) mt-1">
      Clients that identify themselves by a published URL instead of registering (CIMD). They have no
      entry above, so this is where their grants are visible and where they can be cut off. Revoking
      kills every token this client holds; it can consent again unless you turn CIMD off for the
      tenant under <strong>Auth</strong>.
    </p>
  </div>

  {#if error}
    <div
      class="m-4 bg-(--error-bg) border border-(--error-border) rounded-lg p-3 text-sm text-(--error-text)">
      {error}
    </div>
  {/if}

  {#if loading}
    <div class="px-6 py-8 text-sm text-(--text-secondary)">Loading…</div>
  {:else if clients.length === 0}
    <div class="px-6 py-8 text-sm text-(--text-secondary)">
      No metadata-document clients have been granted tokens in this tenant.
    </div>
  {:else}
    <table class="w-full text-sm">
      <thead>
        <tr class="border-b border-(--border) bg-(--bg-primary)">
          <th
            class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium"
            >client_id</th>
          <th
            class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium"
            >Grants</th>
          <th
            class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium"
            >Live tokens</th>
          <th
            class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium"
            >Last issued</th>
          <th
            class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium"
            >Actions</th>
        </tr>
      </thead>
      <tbody>
        {#each clients as c (c.client_id)}
          <tr class="border-b border-(--border) hover:bg-(--bg-elevated) align-top">
            <td class="px-5 py-2.5 font-mono text-xs">
              <Copyable value={c.client_id} />
            </td>
            <td class="px-5 py-2.5 text-right text-(--text-primary)">{c.grants}</td>
            <td class="px-5 py-2.5 text-right">
              <span
                class={c.tokens_active > 0
                  ? 'text-(--text-primary) font-medium'
                  : 'text-(--text-secondary)'}>{c.tokens_active}</span>
              <span class="text-(--text-tertiary) text-xs"> / {c.tokens_issued}</span>
            </td>
            <td class="px-5 py-2.5 text-xs text-(--text-secondary)"
              >{new Date(c.last_issued).toLocaleString()}</td>
            <td class="px-5 py-2.5 text-right whitespace-nowrap">
              <button
                type="button"
                class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm font-medium disabled:opacity-40 disabled:hover:bg-transparent"
                disabled={c.tokens_active === 0}
                onclick={() => onRevoke(c)}>Revoke all</button>
            </td>
          </tr>
        {/each}
      </tbody>
    </table>
  {/if}
</div>
