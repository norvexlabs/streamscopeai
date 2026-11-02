<script lang="ts">
  /**
   * Framework citation chip — renders an OWASP / MITRE ATLAS / CWE id as a
   * clickable pill. Clicking fires `onselect` with the id; the parent decides
   * whether to open a side panel with the full framework entry text.
   */

  interface Props {
    id: string;
    /** Optional human-readable title; falls back to the id. */
    title?: string | null;
    onselect?: (id: string) => void;
    /** Keep the pill compact (used inside dense suggestion cards). */
    compact?: boolean;
  }

  let { id, title, onselect, compact = false }: Props = $props();

  function handle() {
    onselect?.(id);
  }

  const family = $derived.by(() => {
    if (id.startsWith('OWASP-LLM')) return 'owasp';
    if (id.startsWith('MITRE-ATLAS')) return 'mitre';
    if (id.startsWith('CWE-')) return 'cwe';
    if (id.startsWith('OWASP-ASI')) return 'asi';
    return 'other';
  });

  const familyClass = $derived.by(() => {
    switch (family) {
      case 'owasp':
        return 'text-(--warning) bg-(--warning-bg) border-(--warning-border) hover:bg-(--bg-elevated)';
      case 'mitre':
        return 'text-(--tag-indigo-text) bg-(--tag-indigo-bg) border-current/30 hover:bg-(--bg-elevated)';
      case 'cwe':
        return 'text-(--tag-rose-text) bg-(--tag-rose-bg) border-current/30 hover:bg-(--bg-elevated)';
      case 'asi':
        return 'text-(--tag-teal-text) bg-(--success-bg) border-(--success-border) hover:bg-(--bg-elevated)';
      default:
        return 'text-(--text-secondary) bg-(--bg-elevated) border-(--border) hover:border-(--accent)';
    }
  });
</script>

<button
  type="button"
  onclick={handle}
  title={title ? `${id}: ${title}` : id}
  class="inline-flex items-center {compact ? 'px-1.5 py-0.5 text-[10px]' : 'px-2 py-0.5 text-xs'} rounded-sm font-mono font-medium border transition-colors {familyClass}"
>
  {id}
</button>
