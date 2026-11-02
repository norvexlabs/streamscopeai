<script lang="ts">
  // The destination lists one consumer attaches, each once, as allow or
  // block. Shared by the Client access Sandbox tab and the Web settings tab;
  // the host owns saving (`onchange` hands it the whole new set).
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { attach, detach, unattached, type Attachment, type DestinationMode } from '#lib/destinationAttachments.js';
  import { thref } from '#lib/tenant.js';
  import { page } from '$app/state';
  import type { components } from '#lib/generated/api-types.js';

  type DestinationList = components['schemas']['DestinationList'];

  let {
    lists,
    value,
    disabled = false,
    emptyText,
    onchange,
  }: {
    /** Every destination list of the tenant. */
    lists: DestinationList[];
    /** The current attachments. */
    value: Attachment[];
    disabled?: boolean;
    /** Shown when nothing is attached — what that means for the consumer. */
    emptyText: string;
    onchange: (next: Attachment[]) => void;
  } = $props();

  const slug = $derived(page.params.slug ?? '');
  let pickId = $state('');
  let pickMode = $state<DestinationMode>('allow');

  const byId = $derived(new Map(lists.map((l) => [l.id, l])));
  const free = $derived(unattached(lists, value));

  function add() {
    if (!pickId) return;
    onchange(attach(value, pickId, pickMode));
    pickId = '';
  }
</script>

<div class="space-y-3" data-testid="destination-attachments">
  {#if value.length === 0}
    <p class="text-xs text-(--text-secondary)">{emptyText}</p>
  {:else}
    <div class="rounded-lg border border-(--border) divide-y divide-(--border)">
      {#each value as a (a.list_id)}
        {@const list = byId.get(a.list_id)}
        <div class="px-3 py-2 flex items-center gap-3" data-testid="attached-list">
          <span class="text-sm text-(--text-primary) truncate flex-1">{list?.name ?? a.list_id}</span>
          {#if list}
            <span class="text-xs text-(--text-tertiary)">{list.entries.length} entr{list.entries.length === 1 ? 'y' : 'ies'}</span>
          {/if}
          <SelectInput
            value={a.mode}
            fluid={false}
            {disabled}
            aria-label="Mode for {list?.name ?? a.list_id}"
            onchange={(e: Event) => onchange(attach(value, a.list_id, (e.currentTarget as HTMLSelectElement).value as DestinationMode))}
          >
            <option value="allow">Allow</option>
            <option value="block">Block</option>
          </SelectInput>
          <button
            class="text-xs text-(--error) hover:underline disabled:opacity-50"
            {disabled}
            onclick={() => onchange(detach(value, a.list_id))}
          >Detach</button>
        </div>
      {/each}
    </div>
  {/if}

  {#if free.length > 0}
    <div class="flex items-center gap-2">
      <SelectInput bind:value={pickId} fluid={false} {disabled} aria-label="Destination list to attach">
        <option value="">Attach a list…</option>
        {#each free as l (l.id)}
          <option value={l.id}>{l.name}</option>
        {/each}
      </SelectInput>
      <SelectInput bind:value={pickMode} fluid={false} {disabled} aria-label="Attach as">
        <option value="allow">as allow</option>
        <option value="block">as block</option>
      </SelectInput>
      <button
        class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors disabled:opacity-50"
        disabled={disabled || !pickId}
        onclick={add}
      >Attach</button>
    </div>
  {/if}
  <p class="text-xs text-(--text-tertiary)">
    Lists are edited under <a class="text-(--accent) hover:underline" href={thref(slug, '/destinations')}>Destinations</a>.
  </p>
</div>
