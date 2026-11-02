<script lang="ts" module>
  /** One before/after pair a detail view asks the panel to show. */
  export interface DiffDetail {
    title: string;
    original: string;
    effective: string;
    transform?: string;
    phase?: string;
    scope?: string;
  }
</script>

<script lang="ts">
  // The before/after side-by-side sheet at the bottom of the audit list and the
  // session view, on both planes: what the client sent (or the model returned)
  // beside what a transform made of it.
  import CopyButton from '#lib/components/CopyButton.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { m } from '#lib/paraglide/messages.js';

  interface Props {
    diff: DiffDetail | null;
    onclose: () => void;
  }

  let { diff, onclose }: Props = $props();
</script>

{#if diff?.title}
  <div class="fixed inset-x-0 bottom-0 z-50 max-h-[60vh] bg-(--bg-card) border-t border-(--border) shadow-2xl overflow-auto">
    <div class="sticky top-0 flex items-center justify-between px-4 py-2 bg-(--bg-card) border-b border-(--border)">
      <div class="flex items-center gap-3">
        <span class="text-sm font-semibold text-(--text-primary)">{diff.title}</span>
        {#if diff.transform}
          <span class="px-2 py-0.5 text-[10px] font-medium rounded-sm bg-(--tag-teal-bg) text-(--tag-teal-text) border border-(--success-border)">{diff.transform}</span>
        {/if}
        {#if diff.phase}
          <span class="text-[10px] text-(--text-secondary)">{diff.phase} · {diff.scope}</span>
        {/if}
      </div>
      <button aria-label={m.browse_close()} onclick={onclose} class="p-1.5 rounded-sm hover:bg-(--bg-elevated) text-(--text-secondary)">
        <Icon name="close" size="sm" tone="neutral" />
      </button>
    </div>
    <div class="grid grid-cols-2 divide-x divide-(--border)">
      <div class="p-4 relative group">
        <div class="flex items-center justify-between mb-2">
          <span class="text-[10px] font-semibold uppercase tracking-wider text-(--text-secondary)">{m.browse_diff_original()}</span>
          <span class="opacity-0 group-hover:opacity-100 transition-opacity"><CopyButton text={diff.original} /></span>
        </div>
        <pre class="text-xs font-mono whitespace-pre-wrap text-(--text-secondary)">{diff.original}</pre>
      </div>
      <div class="p-4 relative group">
        <div class="flex items-center justify-between mb-2">
          <span class="text-[10px] font-semibold uppercase tracking-wider text-(--success)">{m.browse_diff_effective()}</span>
          <span class="opacity-0 group-hover:opacity-100 transition-opacity"><CopyButton text={diff.effective} /></span>
        </div>
        <pre class="text-xs font-mono whitespace-pre-wrap text-(--text-primary)">{diff.effective}</pre>
      </div>
    </div>
  </div>
{/if}
