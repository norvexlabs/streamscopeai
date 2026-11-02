<script module lang="ts">
  /** A single chip on the metrics line under a BreakdownRow's bar. */
  export interface RowMeta {
    /** Chip text, e.g. "1.2M tok", "$4.10", "P95 290ms". */
    text: string;
    /** Optional chip tint (e.g. "var(--error)"). Defaults to --text-secondary. */
    accent?: string;
  }
</script>

<script lang="ts">
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  // Single row inside a Panel-based breakdown list:
  //   - label (truncating, optional monospace)
  //   - right-aligned value
  //   - optional secondary right-aligned line (e.g. P95 latency, bytes)
  //   - progress bar showing this row's share of the panel max
  //   - optional rich metrics line of inline chips under the bar
  //
  // The whole row is clickable when `href` is set (drill-down to an audit/
  // tool-calls deep link). Stays a div otherwise so we don't accumulate
  // empty anchors in the DOM.
  //
  // Drop-in for hand-rolled bar+label patterns on dashboard breakdowns —
  // see /dashboard/web, /dashboard/llm, and the same shape that
  // /dashboard/mcp's DashboardView builds inline. Migrate over time.

  interface Props {
    label: string;
    /** Right-aligned headline value, e.g. formatted count or duration. */
    value: string;
    /** Optional secondary value rendered under `value` (e.g. "P95 290ms"). */
    sub?: string;
    /** Optional tint for `value` (e.g. per-category error color). Defaults
     *  to --text-secondary. */
    valueColor?: string;
    /** Rich metrics line rendered under the bar as inline mono chips.
     *  Independent of `sub`; entries with empty text are skipped so callers
     *  can splat conditional chips. */
    meta?: RowMeta[];
    /** This row's share of the panel maximum, as a percentage 0..100. */
    percent: number;
    /** Optional drill-down link. */
    href?: string;
    /** Hover tooltip on the row. */
    title?: string;
    /** Render `label` in monospace (hosts, query strings, UUIDs). */
    mono?: boolean;
    /** Color of the bar segment. Defaults to --accent. Pass any CSS color
     *  / var(--…) string so callers can theme per-panel (e.g. cyan for
     *  search, orange for fetch). */
    barColor?: string;
    /** Animate bar width on change (e.g. period switches). Off by default
     *  so static breakdowns stay static. */
    animateBar?: boolean;
  }

  let {
    label,
    value,
    sub,
    valueColor,
    meta,
    percent,
    href,
    title,
    mono = false,
    barColor = 'var(--accent)',
    animateBar = false,
  }: Props = $props();

  const scopedHref = $derived(scopeHref(page.params.slug ?? '', page.url.pathname, href));

  const pct = $derived(Math.min(100, Math.max(0, percent)));
</script>

{#snippet body()}
  <div class="flex items-start justify-between gap-2 mb-1">
    <span
      class="text-sm text-(--text-primary) truncate {mono ? 'font-mono' : ''}"
    >
      {label}
    </span>
    <div class="flex flex-col items-end shrink-0">
      <span class="text-xs font-mono" style="color: {valueColor ?? 'var(--text-secondary)'}">{value}</span>
      {#if sub}
        <span class="text-[10px] text-(--text-tertiary) font-mono">{sub}</span>
      {/if}
    </div>
  </div>
  <div class="w-full h-1.5 bg-(--bg-primary) rounded-full overflow-hidden">
    <div
      class="h-full rounded-full {animateBar ? 'transition-all duration-500' : ''}"
      style="width: {pct}%; background-color: {barColor}"
    ></div>
  </div>
  {#if meta && meta.length}
    <div class="flex flex-wrap items-center gap-x-3 gap-y-0.5 mt-1">
      {#each meta as m, i (i)}
        {#if m.text}
          <span
            class="text-[10px] font-mono"
            style="color: {m.accent ?? 'var(--text-secondary)'}">{m.text}</span>
        {/if}
      {/each}
    </div>
  {/if}
{/snippet}

{#if href}
  <a
    href={scopedHref}
    {title}
    class="block rounded-lg p-1.5 -mx-1.5 hover:bg-(--bg-elevated) transition-colors"
  >
    {@render body()}
  </a>
{:else}
  <div {title} class="p-1.5 -mx-1.5">
    {@render body()}
  </div>
{/if}
