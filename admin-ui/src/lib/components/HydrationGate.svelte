<script lang="ts">
  import { onMount, type Snippet } from 'svelte';

  // Marks everything inside as not ready until the app has hydrated: the server
  // render carries `data-hydrating`, and it is dropped once mounted (a parent
  // mounts after its children, so every control inside has its handler by
  // then). `app.css` turns the pointer off on script-driven controls under the
  // marker, so a click made before hydration waits for a control that works —
  // a person's and an automated one alike — instead of landing on a dead one.
  let { children, class: className = '' }: { children: Snippet; class?: string } = $props();

  let hydrated = $state(false);
  onMount(() => {
    hydrated = true;
  });
</script>

<div class={className} data-hydrating={hydrated ? undefined : ''}>
  {@render children()}
</div>
