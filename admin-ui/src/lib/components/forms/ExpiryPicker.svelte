<script lang="ts">
  // Expiry preset chips — the single expiry control for every key-mint surface
  // (create form, automation mint modal, portal automation panel). Optional
  // `allowCustom` adds a Custom chip + datetime input.
  import type { ExpiryPreset } from '#lib/keyExpiry.js';

  type Choice = ExpiryPreset | 'custom';

  let {
    value = $bindable(),
    customValue = $bindable(''),
    allowCustom = false,
  }: {
    value: Choice;
    /** datetime-local string when `custom` is selected. */
    customValue?: string;
    allowCustom?: boolean;
  } = $props();

  const PRESETS: { v: Choice; label: string }[] = [
    { v: '30d', label: '30d' },
    { v: '90d', label: '90d' },
    { v: '1y', label: '1y' },
    { v: 'never', label: 'Never' },
  ];
  const choices = $derived(allowCustom ? [...PRESETS, { v: 'custom' as Choice, label: 'Custom' }] : PRESETS);
</script>

<div>
  <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider mb-1.5 block">Expiry</span>
  <div class="flex items-center gap-1 flex-wrap">
    {#each choices as c (c.v)}
      <button
        onclick={() => { value = c.v; }}
        class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {value === c.v
          ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)'
          : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
      >{c.label}</button>
    {/each}
  </div>
  {#if allowCustom && value === 'custom'}
    <input
      type="datetime-local"
      bind:value={customValue}
      class="mt-2 w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) focus:outline-hidden focus:border-(--accent)"
    />
  {/if}
</div>
