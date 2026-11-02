<script lang="ts">
  import Icon from './Icon.svelte';

  let { subtitle }: { subtitle: string } = $props();
</script>

<!-- The product header on the pages outside the console shell (sign-in, setup, invitation).
     The sidebars show the same `brand` icon inside their collapse button. -->
<div class="flex items-center justify-center gap-3 mb-8">
  <div class="w-10 h-10 rounded-xl bg-(--accent) flex items-center justify-center shrink-0">
    <Icon name="brand" size="lg" color="var(--accent-fg)" />
  </div>
  <div>
    <h1 class="text-xl font-bold text-(--text-primary)">Streamscope AI</h1>
    <p class="text-xs text-(--text-secondary)">{subtitle}</p>
  </div>
</div>
