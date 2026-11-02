<script lang="ts">
  import '../../app.css';
  import LoginSlugCard from '#lib/components/LoginSlugCard.svelte';

  let { form } = $props();
</script>

<LoginSlugCard variant="admin" {form} />
