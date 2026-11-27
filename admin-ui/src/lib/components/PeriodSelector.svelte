<script lang="ts">
  import type { PeriodValue } from '#lib/scope.svelte.js';
  import Icon from '#lib/components/Icon.svelte';
  import DateInput from '#lib/components/forms/DateInput.svelte';
  import { m } from '#lib/paraglide/messages.js';

  const PRESET_DAYS = [1, 7, 30] as const;

  let {
    selected,
    onchange,
  }: {
    selected: PeriodValue;
    onchange: (v: PeriodValue) => void;
  } = $props();

  let pickerOpen = $state(false);
  let pickerStart = $state('');
  let pickerEnd = $state('');
  let popoverEl = $state<HTMLDivElement | undefined>();

  function isRollingActive(d: number): boolean {
    return selected.kind === 'rolling' && selected.days === d;
  }

  function pickPreset(days: number) {
    pickerOpen = false;
    onchange({ kind: 'rolling', days });
  }

  function openPicker() {
    if (selected.kind === 'absolute') {
      pickerStart = selected.start.slice(0, 10);
      pickerEnd = selected.end.slice(0, 10);
    } else {
      const today = new Date();
      const past = new Date();
      past.setDate(past.getDate() - selected.days);
      pickerStart = past.toISOString().slice(0, 10);
      pickerEnd = today.toISOString().slice(0, 10);
    }
    pickerOpen = true;
  }

  // What a typed date must look like before it is applied.
  const DAY = /^\d{4}-\d{2}-\d{2}$/;

  function applyAbsolute() {
    if (applyDisabled) return;
    const startTs = new Date(`${pickerStart}T00:00:00Z`).toISOString();
    const endTs = new Date(`${pickerEnd}T23:59:59.999Z`).toISOString();
    pickerOpen = false;
    onchange({ kind: 'absolute', start: startTs, end: endTs });
  }

  const applyDisabled = $derived.by(() => {
    if (!DAY.test(pickerStart) || !DAY.test(pickerEnd)) return true;
    if (pickerEnd < pickerStart) return true;
    const todayIso = new Date().toISOString().slice(0, 10);
    if (pickerEnd > todayIso) return true;
    return false;
  });

  function customLabel(): string {
    if (selected.kind !== 'absolute') return '';
    const fmt = (iso: string) => {
      const d = new Date(iso);
      return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric' });
    };
    return `${fmt(selected.start)} – ${fmt(selected.end)}`;
  }

  function handleClickOutside(e: MouseEvent) {
    if (!pickerOpen) return;
    const target = e.target as Node;
    if (popoverEl && !popoverEl.contains(target)) {
      pickerOpen = false;
    }
  }

  $effect(() => {
    if (pickerOpen) {
      document.addEventListener('mousedown', handleClickOutside);
      return () => document.removeEventListener('mousedown', handleClickOutside);
    }
  });
</script>

<div class="relative flex items-center gap-1">
  <span class="text-xs text-(--text-secondary) uppercase tracking-wider mr-2">{m.period_label()}</span>
  {#each PRESET_DAYS as d}
    <button
      type="button"
      onclick={() => pickPreset(d)}
      class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {isRollingActive(d) ? 'bg-(--accent) text-(--accent-fg)' : 'bg-(--bg-primary) text-(--text-secondary) hover:text-(--text-primary) border border-(--border)'}"
    >
      {m.period_days({ days: d })}
    </button>
  {/each}

  <button
    type="button"
    onclick={openPicker}
    aria-label={m.period_custom()}
    title={m.period_custom()}
    class="px-2.5 py-1.5 rounded-lg transition-colors flex items-center gap-1.5 {selected.kind === 'absolute' ? 'bg-(--accent) text-(--accent-fg)' : 'bg-(--bg-primary) text-(--text-secondary) hover:text-(--text-primary) border border-(--border)'}"
  >
    <Icon name="calendar" size="sm" color="currentColor" />
    {#if selected.kind === 'absolute'}
      <span class="text-xs font-medium whitespace-nowrap">{customLabel()}</span>
    {/if}
  </button>

  {#if pickerOpen}
    <div
      bind:this={popoverEl}
      class="absolute right-0 top-full mt-2 z-50 bg-(--bg-primary) border border-(--border) rounded-lg shadow-lg p-3 w-65"
      role="dialog"
      aria-label={m.period_custom_picker()}
    >
      <div class="flex flex-col gap-2.5">
        <label class="flex flex-col gap-1 text-xs text-(--text-secondary)">
          {m.period_start()}
          <DateInput bind:value={pickerStart} max={new Date().toISOString().slice(0, 10)} />
        </label>
        <label class="flex flex-col gap-1 text-xs text-(--text-secondary)">
          {m.period_end()}
          <DateInput bind:value={pickerEnd} max={new Date().toISOString().slice(0, 10)} />
        </label>

        <div class="flex items-center justify-between gap-2 pt-1.5 mt-1 border-t border-(--border)">
          <button
            type="button"
            onclick={() => (pickerOpen = false)}
            class="px-3 py-1.5 rounded-sm text-xs text-(--text-secondary) hover:text-(--text-primary)"
          >
            {m.period_cancel()}
          </button>
          <button
            type="button"
            onclick={applyAbsolute}
            disabled={applyDisabled}
            class="px-3 py-1.5 rounded-sm text-xs font-medium bg-(--accent) text-(--accent-fg) disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {m.period_apply()}
          </button>
        </div>
      </div>
    </div>
  {/if}
</div>
