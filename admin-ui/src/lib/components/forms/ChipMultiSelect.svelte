<script lang="ts" generics="T extends string">
  /**
   * A set of toggle chips choosing any number of values from a short closed
   * list — each chip a button whose `aria-pressed` carries its state. The
   * bound `selected` keeps the order the chips were picked in.
   */
  interface Props {
    options: { value: T; label: string }[];
    selected: T[];
    disabled?: boolean;
  }

  let { options, selected = $bindable(), disabled = false }: Props = $props();

  function toggle(value: T) {
    if (disabled) return;
    selected = selected.includes(value) ? selected.filter((v) => v !== value) : [...selected, value];
  }
</script>

<div class="flex flex-wrap gap-2 mt-1.5">
  {#each options as option (option.value)}
    {@const on = selected.includes(option.value)}
    <button
      type="button"
      aria-pressed={on}
      {disabled}
      onclick={() => toggle(option.value)}
      class="px-2.5 py-1 rounded-lg text-xs font-medium border transition-colors disabled:opacity-50
        {on
          ? 'bg-(--accent) text-(--accent-fg) border-(--accent)'
          : 'bg-(--bg-primary) text-(--text-secondary) border-(--border) hover:text-(--text-primary)'}"
    >
      {option.label}
    </button>
  {/each}
</div>
