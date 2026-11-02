<script lang="ts">
  import LoginCard from '#lib/components/LoginCard.svelte';
  import LocaleSelector from '#lib/components/LocaleSelector.svelte';

  let { data, form } = $props();
</script>

<div class="fixed top-4 right-4 z-10">
  <LocaleSelector />
</div>
<LoginCard variant="portal" tenant={data.tenant} notFound={data.notFound} unavailable={data.unavailable} {form} />
