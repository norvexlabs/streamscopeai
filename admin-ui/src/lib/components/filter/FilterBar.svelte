<script lang="ts">
  import type { Snippet } from 'svelte';

  let { children, class: extraClass = '' }: { children: Snippet; class?: string } = $props();
</script>

<div class="bg-(--bg-card) rounded-xl p-3 border border-(--border) {extraClass}">
  <div class="flex flex-wrap items-end gap-3">
    {@render children()}
  </div>
</div>
