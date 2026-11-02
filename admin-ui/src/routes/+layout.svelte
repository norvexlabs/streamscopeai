<script lang="ts">
  import '@fontsource-variable/archivo';
  import '../app.css';
  import ToastHost from '#lib/components/ToastHost.svelte';
  import HydrationGate from '#lib/components/HydrationGate.svelte';

  let { children } = $props();
</script>

<ToastHost />

<!-- Top-level shell: global toast host + page background. Authenticated chrome
     (sidebar/header) lives in the per-tenant layouts (t/[slug], portal/t/[slug]);
     public routes (login, setup, invite, oidc) render bare here. -->
<HydrationGate class="min-h-screen bg-(--bg-primary)">
  {@render children()}
</HydrationGate>
