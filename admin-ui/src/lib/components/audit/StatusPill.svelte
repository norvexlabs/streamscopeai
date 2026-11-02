<script lang="ts">
  import type { Snippet } from 'svelte';

  // Small inline status pill used to flag HTTP errors, JSON-RPC error codes,
  // error categories, connection state, etc. across the audit drawers,
  // AuditRowCard, and the edge dashboard. Five tones: error / warning /
  // success / info / neutral, each pair-token from `app.css` (`--<tone>-bg`,
  // `--<tone>` solid, `--<tone>-text` derivative).

  type Tone = 'error' | 'warning' | 'success' | 'info' | 'neutral';

  interface Props {
    tone?: Tone;
    children: Snippet;
    title?: string;
    /** Add a 1px solid border in the tone's own colour. Defaults true — most
     *  pills in the codebase ship the border. Pass `false` for the rarer
     *  no-border variant (e.g. raw `error_category` chips). */
    bordered?: boolean;
    /** Use the mono font. Defaults true to match the existing inline
     *  callsites. */
    mono?: boolean;
  }

  let {
    tone = 'error',
    children,
    title,
    bordered = true,
    mono = true,
  }: Props = $props();

  const toneClass = $derived(
    {
      error: bordered
        ? 'bg-(--error)/10 border border-(--error) text-(--error)'
        : 'bg-(--error)/10 text-(--error)',
      warning: bordered
        ? 'bg-(--warning)/10 border border-(--warning) text-(--warning)'
        : 'bg-(--warning)/10 text-(--warning)',
      success: bordered
        ? 'bg-(--success)/10 border border-(--success) text-(--success)'
        : 'bg-(--success)/10 text-(--success)',
      info: bordered
        ? 'bg-(--info-bg) border border-(--info-border) text-(--info-text)'
        : 'bg-(--info-bg) text-(--info-text)',
      neutral: bordered
        ? 'bg-(--bg-elevated) border border-(--border) text-(--text-secondary)'
        : 'bg-(--bg-elevated) text-(--text-secondary)',
    }[tone]
  );
</script>

<span class="inline-flex items-center px-2 py-0.5 rounded-sm {mono ? 'font-mono' : ''} {toneClass}" {title}>
  {@render children()}
</span>
