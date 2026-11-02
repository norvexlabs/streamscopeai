<script lang="ts">
  import DashboardScaffold from '#lib/components/dashboard/DashboardScaffold.svelte';
  import MediaModalitySection from '#lib/components/dashboard/MediaModalitySection.svelte';
</script>

<DashboardScaffold
  title="Media"
  subtitle="Embeddings, audio, images, video — request volume, cost, latency"
>
  <MediaModalitySection />
</DashboardScaffold>
