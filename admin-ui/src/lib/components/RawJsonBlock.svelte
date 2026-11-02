<script lang="ts">
  // Pure-text JSON renderer for the RAW toggle, unknown content blocks, and
  // unknown media endpoints. Renders inert inside <pre> so rogue payloads
  // can't inject HTML. Collapsible over 200 characters with a byte-count label.

  let { value, label = '' }: { value: unknown; label?: string } = $props();

  function stringify(v: unknown): string {
    try {
      return JSON.stringify(v, null, 2);
    } catch {
      return String(v);
    }
  }

  const COLLAPSE_THRESHOLD = 200;
  let expanded = $state(false);
  const text = $derived(stringify(value));
  const byteLen = $derived(new TextEncoder().encode(text).length);
  const isLong = $derived(byteLen > COLLAPSE_THRESHOLD);
  const displayText = $derived(isLong && !expanded ? text.slice(0, COLLAPSE_THRESHOLD) + '…' : text);
</script>

<div class="raw-json-block">
  {#if label}
    <div class="label">{label}</div>
  {/if}
  <pre class="json">{displayText}</pre>
  {#if isLong}
    <button type="button" class="toggle" onclick={() => (expanded = !expanded)}>
      {expanded ? 'Collapse' : `Expand (${byteLen} bytes)`}
    </button>
  {/if}
</div>

<style>
  .raw-json-block {
    background: var(--bg-primary);
    border: 1px solid var(--border);
    border-radius: 0.5rem;
    padding: 0.5rem;
    font-size: 0.85rem;
    color: var(--text-primary);
  }
  .label {
    font-size: 0.7rem;
    text-transform: uppercase;
    color: var(--text-secondary);
    margin-bottom: 0.25rem;
    letter-spacing: 0.04em;
    font-weight: 600;
  }
  .json {
    margin: 0;
    white-space: pre-wrap;
    word-break: break-word;
    font-family: ui-monospace, 'SF Mono', Menlo, Monaco, Consolas, monospace;
    color: var(--text-primary);
  }
  .toggle {
    margin-top: 0.4rem;
    font-size: 0.75rem;
    background: transparent;
    border: none;
    color: var(--accent);
    cursor: pointer;
    padding: 0;
  }
  .toggle:hover { text-decoration: underline; }
</style>
