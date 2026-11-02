<script lang="ts">
  /**
   * Labelled toggle for settings forms. Mirrors the pill-toggle styling used
   * across `/settings` and `/gateways/mcp` so the visual contract is the same
   * regardless of which section a setting lives under.
   */
  interface Props {
    label: string;
    /** Optional inline element rendered right after the label (e.g. a badge). */
    labelSuffix?: import('svelte').Snippet;
    description?: string;
    value: boolean;
    /**
     * Optional warning rendered under the description when the toggle is on.
     * Used by destructive flips so operators see the
     * implication immediately.
     */
    warningWhenOn?: string;
    saving?: boolean;
    disabled?: boolean;
    onValueChange?: (value: boolean) => void;
  }

  let {
    label,
    labelSuffix,
    description,
    value = $bindable(),
    warningWhenOn,
    saving = false,
    disabled = false,
    onValueChange,
  }: Props = $props();

  function handleToggle() {
    if (disabled || saving) return;
    value = !value;
    onValueChange?.(value);
  }
</script>

<div class="flex items-start justify-between gap-4">
  <div class="min-w-0">
    <p class="font-medium text-(--text-primary) flex items-center gap-1.5 min-w-0">
      <span class="truncate">{label}</span>
      {#if labelSuffix}{@render labelSuffix()}{/if}
    </p>
    {#if description}
      <p class="text-xs text-(--text-secondary) mt-0.5">{description}</p>
    {/if}
    {#if value && warningWhenOn}
      <p class="text-xs text-(--warning) mt-1">{warningWhenOn}</p>
    {/if}
  </div>
  <button
    type="button"
    onclick={handleToggle}
    disabled={disabled || saving}
    class="relative w-11 h-6 rounded-full transition-colors shrink-0 {value ? 'bg-(--accent)' : 'bg-(--border)'} disabled:opacity-50"
    title={value ? 'Disable' : 'Enable'}
    aria-pressed={value}
  >
    <span class="absolute top-0.5 left-0.5 w-5 h-5 bg-white ring-1 ring-(--bg-primary)/60 rounded-full shadow-sm transition-transform {value ? 'translate-x-5' : 'translate-x-0'}"></span>
  </button>
</div>
