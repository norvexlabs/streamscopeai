<script lang="ts">
  import LoginSlugCard from '#lib/components/LoginSlugCard.svelte';
  import LocaleSelector from '#lib/components/LocaleSelector.svelte';

  let { form } = $props();
</script>

<div class="fixed top-4 right-4 z-10">
  <LocaleSelector />
</div>
<LoginSlugCard variant="portal" {form} />
