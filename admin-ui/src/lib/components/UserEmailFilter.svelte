<script lang="ts">
  import FilterField from '#lib/components/filter/FilterField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import { m } from '#lib/paraglide/messages.js';

  let { value = $bindable(''), onfilter }: { value: string; onfilter: () => void } = $props();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Enter') onfilter();
  }
</script>

<FilterField label={m.browse_filter_user()} class="min-w-35">
  <TextInput bind:value onkeydown={handleKeydown} placeholder={m.browse_filter_user_placeholder()} />
</FilterField>
