<script lang="ts">
  // One limit against its cap: "12 of 20 · 60%" plus a bar. The status is
  // carried by text as well as colour (a reached limit says so in words), and
  // a limit with no cap shows only what was used. A `used` of null is use the
  // viewer may not see (other people's spend): the cap alone is shown.
  import { m } from '#lib/paraglide/messages.js';
  import { meterRatio, meterTone } from '#lib/limits.js';

  interface Props {
    label: string;
    used: number | null | undefined;
    cap: number | null | undefined;
    /** Renders a quantity (money, a count). */
    fmt: (n: number) => string;
    /** Where this cap comes from, when it is not the layer's own. */
    note?: string;
  }

  let { label, used, cap, fmt, note }: Props = $props();

  const ratio = $derived(used == null ? null : meterRatio(used, cap));
  const tone = $derived(meterTone(ratio));
  const TONE_VAR = { ok: 'var(--success)', warning: 'var(--warning)', error: 'var(--error)' } as const;
</script>

<div class="space-y-1 min-w-0">
  <div class="flex items-baseline justify-between gap-2 text-xs">
    <span class="text-(--text-secondary) truncate">
      {label}{#if note}<span class="text-[10px]"> · {note}</span>{/if}
    </span>
    <span class="font-mono text-(--text-primary) whitespace-nowrap">
      {#if used == null}
        {#if cap != null && cap > 0}{m.limits_cap_use_hidden({ cap: fmt(cap) })}{/if}
      {:else if cap != null && cap > 0}
        {m.limits_used_of({ used: fmt(used), cap: fmt(cap) })}
        {#if ratio != null}<span class="text-(--text-secondary)"> · {Math.round(ratio * 100)}%</span>{/if}
      {:else}
        {fmt(used)} · {m.limits_state_unlimited()}
      {/if}
    </span>
  </div>
  {#if ratio != null}
    <div class="h-1.5 rounded-full bg-(--bg-primary) overflow-hidden" role="presentation">
      <div class="h-full rounded-full" style="width: {Math.min(100, ratio * 100)}%; background: {TONE_VAR[tone]}"></div>
    </div>
    {#if tone === 'error'}<p class="text-[10px] font-medium text-(--error-text)">{m.limits_reached()}</p>{/if}
  {/if}
</div>
