<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';

  let {
    value = $bindable(''),
    placeholder = 'Filter...',
    matchInfo = ''
  }: {
    value: string;
    placeholder?: string;
    matchInfo?: string;
  } = $props();

  let inputEl = $state<HTMLInputElement | undefined>();

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape') {
      value = '';
      inputEl?.blur();
    }
  }

  function handleGlobalKeydown(e: KeyboardEvent) {
    if (e.key === '/' && !['INPUT', 'TEXTAREA', 'SELECT'].includes((e.target as HTMLElement)?.tagName)) {
      e.preventDefault();
      inputEl?.focus();
    }
  }
</script>

<svelte:window onkeydown={handleGlobalKeydown} />

<div class="flex flex-col gap-1">
  <div class="relative">
    <div class="absolute left-3 top-1/2 -translate-y-1/2 pointer-events-none">
      <Icon name="search" size="sm" tone="neutral" />
    </div>
    <input
      bind:this={inputEl}
      bind:value
      type="text"
      {placeholder}
      onkeydown={handleKeydown}
      class="w-full pl-9 pr-8 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors"
    />
    {#if value}
      <button
        onclick={() => { value = ''; inputEl?.focus(); }}
        class="absolute right-2.5 top-1/2 -translate-y-1/2 text-(--text-secondary) hover:text-(--text-primary) transition-colors"
        title="Clear filter"
      >
        <Icon name="close" size="sm" tone="neutral" />
      </button>
    {/if}
  </div>
  {#if value && matchInfo}
    <span class="text-xs text-(--text-secondary)">{matchInfo}</span>
  {/if}
</div>
