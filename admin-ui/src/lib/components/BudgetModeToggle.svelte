<script lang="ts">
  // Enforce | alert-only selector for a budget cap, shared by the per-key
  // budget fields, the workspace ceiling, and the per-user override. `enforce`
  // blocks over-cap requests; `alert_only` notifies but never blocks.
  interface Props {
    mode: 'enforce' | 'alert_only';
  }
  let { mode = $bindable() }: Props = $props();
</script>

<div class="flex items-center gap-1">
  <button type="button" onclick={() => { mode = 'enforce'; }}
    class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
      {mode === 'enforce' ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
  >Enforce</button>
  <button type="button" onclick={() => { mode = 'alert_only'; }}
    class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors
      {mode === 'alert_only' ? 'bg-(--warning) text-(--warning-fg) border border-(--warning)' : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
  >Alert only</button>
</div>
