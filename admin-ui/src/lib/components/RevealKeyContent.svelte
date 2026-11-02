<script lang="ts">
  /**
   * Reveal-once key CONTENT — the single rendering of "save it now": warning,
   * plaintext, copy button, optional curl snippet, optional BYOK base-URL block.
   * `RevealKeyModal` wraps it in a Modal; `CreateKeyForm` renders it inline
   * (inside its host modal) so the reveal UX is identical on every mint path.
   */
  import Icon from '#lib/components/Icon.svelte';
  import CopyTextButton from '#lib/components/CopyTextButton.svelte';

  let {
    keyValue,
    snippet = '',
    byokUrl = '',
    byokHint = '',
    onDone,
  }: {
    keyValue: string;
    snippet?: string;
    /** BYOK connection URL block (vk- keys only). */
    byokUrl?: string;
    byokHint?: string;
    onDone: () => void;
  } = $props();
</script>

<div class="space-y-3">
  <div class="flex items-center gap-2 text-xs">
    <Icon name="errorCircle" size="sm" tone="warning" />
    <span class="font-medium text-(--warning)">Save this key now — you won't see it again</span>
  </div>
  <code class="block w-full text-sm font-mono bg-(--bg-primary) px-3 py-3 rounded-lg text-(--text-primary) break-all select-all leading-relaxed">{keyValue}</code>
  <div class="flex justify-end"><CopyTextButton value={keyValue} label="Copy key" size="lg" /></div>
  {#if byokUrl}
    <div class="bg-(--bg-primary) rounded-lg px-3 py-2">
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider block mb-1">Base URL for client</span>
      <div class="flex items-center gap-2">
        <code class="flex-1 text-xs font-mono text-(--accent) break-all">{byokUrl}</code>
        <CopyTextButton value={byokUrl} size="sm" />
      </div>
      {#if byokHint}
        <p class="text-[10px] text-(--text-secondary) mt-1">{byokHint}</p>
      {/if}
    </div>
  {/if}
  {#if snippet}
    <div class="bg-(--bg-primary) rounded-lg px-3 py-2">
      <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider block mb-1">Example</span>
      <pre class="text-xs font-mono text-(--accent) whitespace-pre-wrap break-all">{snippet}</pre>
      <div class="flex justify-end mt-1"><CopyTextButton value={snippet} size="sm" /></div>
    </div>
  {/if}
  <div class="flex justify-end">
    <button onclick={onDone} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity">Done</button>
  </div>
</div>
