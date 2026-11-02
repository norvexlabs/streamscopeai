<script lang="ts">
  import { toast, type Toast } from '#lib/toast.svelte.js';
  import Icon from '#lib/components/Icon.svelte';
  import type { IconName } from '#lib/icons.js';

  function iconFor(kind: Toast['kind']): IconName {
    switch (kind) {
      case 'success': return 'check';
      case 'error':   return 'errorCircle';
      case 'warning': return 'alert';
      case 'info':    return 'info';
    }
  }

  function colorsFor(kind: Toast['kind']) {
    switch (kind) {
      case 'success': return { bg: 'var(--success-bg)', border: 'var(--success-border)', text: 'var(--success-text)' };
      case 'error':   return { bg: 'var(--error-bg)',   border: 'var(--error-border)',   text: 'var(--error-text)'   };
      case 'warning': return { bg: 'var(--warning-bg)', border: 'var(--warning-border)', text: 'var(--warning-text)' };
      case 'info':    return { bg: 'var(--info-bg)',    border: 'var(--info-border)',    text: 'var(--info-text)'    };
    }
  }

  function toneFor(kind: Toast['kind']): 'success' | 'error' | 'warning' | 'info' {
    return kind;
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && toast.toasts.length > 0) {
      toast.dismissLatest();
    }
  }
</script>

<svelte:window onkeydown={handleKeydown} />

<div
  class="fixed top-4 right-4 z-100 flex flex-col gap-2 max-w-sm pointer-events-none"
  aria-live="polite"
  aria-atomic="false"
>
  {#each toast.toasts as t (t.id)}
    {@const c = colorsFor(t.kind)}
    <div
      class="pointer-events-auto rounded-lg border shadow-(--shadow-pop) backdrop-blur-xs flex items-start gap-3 p-3 pr-2 min-w-[20rem]"
      style="background:{c.bg};border-color:{c.border};color:{c.text}"
      role={t.kind === 'error' ? 'alert' : 'status'}
    >
      <div class="mt-0.5 shrink-0">
        <Icon name={iconFor(t.kind)} tone={toneFor(t.kind)} />
      </div>
      <div class="flex-1 min-w-0">
        <p class="text-sm font-medium">{t.title}</p>
        {#if t.body}
          <p class="text-xs mt-0.5 opacity-90 wrap-break-word">{t.body}</p>
        {/if}
        {#if t.code}
          <p class="text-[10px] mt-1 font-mono opacity-70 uppercase tracking-wider">{t.code}</p>
        {/if}
      </div>
      <button
        onclick={() => toast.dismiss(t.id)}
        class="shrink-0 -mt-1 -mr-1 p-1 rounded-sm hover:bg-(--bg-elevated) transition-colors"
        aria-label="Dismiss"
      >
        <Icon name="close" size="sm" tone="neutral" />
      </button>
    </div>
  {/each}
</div>
