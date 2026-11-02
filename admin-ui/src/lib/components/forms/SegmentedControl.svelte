<script lang="ts" generics="T extends string">
  // A small set of mutually exclusive views, side by side — the one control
  // for "show this OR that" toggles (Rendered / Raw, Effective / Original, Me /
  // Team, a sort key). Each option is a button carrying `aria-pressed`; the
  // group is a `role="group"` named by `label`. `tone` colours the selected
  // option: `accent` for a view, `success` for the post-transform lens.
  interface SegmentOption<V extends string> {
    value: V;
    label: string;
    title?: string;
  }

  interface Props {
    options: SegmentOption<T>[];
    value: T;
    /** Accessible name of the group. */
    label: string;
    onchange?: (value: T) => void;
    tone?: 'accent' | 'success';
    size?: 'sm' | 'xs';
    /** Draw the group's frame (border + background); off inside a dense panel header. */
    framed?: boolean;
    /** The frame's background — `secondary` where the control sits on a primary surface. */
    surface?: 'primary' | 'secondary';
  }

  let {
    options,
    value = $bindable(),
    label,
    onchange,
    tone = 'accent',
    size = 'sm',
    framed = true,
    surface = 'primary',
  }: Props = $props();

  const selectedClass = $derived(tone === 'success' ? 'bg-(--success) text-(--success-fg)' : 'bg-(--accent) text-(--accent-fg)');
  const sizeClass = $derived(size === 'xs' ? 'px-2 py-0.5 text-[10px] rounded-sm' : 'px-2.5 py-1 text-xs rounded-md');
  const frameClass = $derived(
    framed
      ? `rounded-lg border border-(--border) p-0.5 ${surface === 'secondary' ? 'bg-(--bg-secondary)' : 'bg-(--bg-primary)'}`
      : 'gap-1',
  );

  function pick(v: T) {
    if (v === value) return;
    value = v;
    onchange?.(v);
  }
</script>

<div class="flex items-center {frameClass}" role="group" aria-label={label}>
  {#each options as opt (opt.value)}
    <button
      type="button"
      aria-pressed={value === opt.value}
      title={opt.title}
      onclick={() => pick(opt.value)}
      class="font-medium transition-colors {sizeClass} {value === opt.value ? selectedClass : 'text-(--text-secondary) hover:text-(--text-primary)'}"
    >{opt.label}</button>
  {/each}
</div>
