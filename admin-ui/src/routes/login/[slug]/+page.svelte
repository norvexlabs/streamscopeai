<script lang="ts">
  import '../../../app.css';
  import LoginCard from '#lib/components/LoginCard.svelte';

  let { data, form } = $props();
</script>

<LoginCard variant="admin" tenant={data.tenant} notFound={data.notFound} unavailable={data.unavailable} {form} />
