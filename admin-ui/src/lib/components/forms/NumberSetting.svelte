<script lang="ts">
  import HelpTooltip from '#lib/components/HelpTooltip.svelte';

  /**
   * Labelled number input for settings forms. Used by every operator-facing
   * tunable that takes an integer or float — defaults are spelled out under the
   * label, units land in a small suffix chip, and the saved-confirmation pulse
   * matches the rest of the settings sections.
   */
  interface Props {
    label: string;
    description?: string;
    /** Extended explanation surfaced via a hover-revealed HelpTooltip beside
     *  the label — use for non-obvious mechanics (badge codes, cascade rules,
     *  audit-side effects) that would bloat the visible `description`. */
    help?: string;
    value: number;
    placeholder?: string;
    /** Inclusive lower bound enforced by the input. */
    min?: number;
    /** Inclusive upper bound enforced by the input. */
    max?: number;
    /** Increment step. Default 1. */
    step?: number;
    /** Optional suffix shown to the right of the input — e.g. "sec", "MB", "KB". */
    unit?: string;
    /** Mark the input as currently saving — blocks interaction. */
    saving?: boolean;
    /** Show the "Saved" pulse next to the input. */
    saved?: boolean;
    /** Disable the input outright. */
    disabled?: boolean;
    /** Two-way binding callback. */
    onValueChange?: (value: number) => void;
  }

  let {
    label,
    description,
    help,
    value = $bindable(),
    placeholder,
    min,
    max,
    step = 1,
    unit,
    saving = false,
    saved = false,
    disabled = false,
    onValueChange,
  }: Props = $props();

  function handleInput(e: Event) {
    const next = Number((e.target as HTMLInputElement).value);
    if (!Number.isFinite(next)) return;
    value = next;
    onValueChange?.(next);
  }
</script>

<label class="block">
  <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider inline-flex items-center gap-1">
    {label}
    {#if help}<HelpTooltip body={help} />{/if}
  </span>
  {#if description}
    <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">{description}</span>
  {/if}
  <div class="flex items-center gap-2 mt-1.5">
    <input
      type="number"
      {value}
      {min}
      {max}
      {step}
      {placeholder}
      disabled={disabled || saving}
      oninput={handleInput}
      class="flex-1 min-w-0 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors disabled:opacity-50"
    />
    {#if unit}
      <span class="text-xs text-(--text-secondary) shrink-0">{unit}</span>
    {/if}
    {#if saved}
      <span class="text-xs text-(--success) animate-pulse shrink-0">Saved</span>
    {/if}
  </div>
</label>
