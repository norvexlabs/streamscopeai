<script lang="ts">
  // Expiry preset chips — the single expiry control for every key-mint surface
  // (create form, automation mint modal, portal automation panel). Optional
  // `allowCustom` adds a Custom chip + datetime input.
  import type { ExpiryPreset } from '#lib/keyExpiry.js';
  import DateInput from '#lib/components/forms/DateInput.svelte';
  import { localDay } from '#lib/analysisStart.js';
  import TextInput from '#lib/components/forms/TextInput.svelte';

  type Choice = ExpiryPreset | 'custom';

  let {
    value = $bindable(),
    customValue = $bindable(''),
    allowCustom = false,
  }: {
    value: Choice;
    /** `YYYY-MM-DDTHH:MM` local time when `custom` is selected, else empty. */
    customValue?: string;
    allowCustom?: boolean;
  } = $props();

  const PRESETS: { v: Choice; label: string }[] = [
    { v: '30d', label: '30d' },
    { v: '90d', label: '90d' },
    { v: '1y', label: '1y' },
    { v: 'never', label: 'Never' },
  ];
  // The custom expiry is a day and an optional time (default midnight), kept
  // in `customValue` as the `YYYY-MM-DDTHH:MM` local-time string the mint
  // forms read; an incomplete entry leaves it empty.
  let day = $state(customValue.slice(0, 10));
  let time = $state(customValue.slice(11, 16));
  $effect(() => {
    const hm = /^(\d{1,2}):(\d{2})$/.exec(time.trim() || '00:00');
    const ok = hm !== null && Number(hm[1]) < 24 && Number(hm[2]) < 60;
    const t = hm ? `${hm[1].padStart(2, '0')}:${hm[2]}` : '';
    customValue = ok && /^\d{4}-\d{2}-\d{2}$/.test(day) && !Number.isNaN(new Date(`${day}T${t}`).getTime()) ? `${day}T${t}` : '';
  });

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
    <div class="mt-2 grid grid-cols-[1fr_6rem] gap-2">
      <DateInput bind:value={day} min={localDay(new Date())} aria-label="Expiry date" />
      <TextInput bind:value={time} placeholder="HH:MM" inputmode="numeric" maxlength={5} aria-label="Expiry time" />
    </div>
  {/if}
</div>
