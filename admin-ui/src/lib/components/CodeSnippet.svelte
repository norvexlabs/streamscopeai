<script lang="ts">
  import CopyButton from './CopyButton.svelte';
  import { m } from '#lib/paraglide/messages.js';

  type Props = {
    /** Display body — never contains plaintext keys, only placeholder strings. */
    body: string;
    /** Suggested file path for the body, rendered as the snippet header. */
    filename?: string | null;
    /** Lexical format hint (`json` | `yaml` | `toml` | `shell` | `text`). */
    format?: string;
    /** Optional title rendered above the filename. */
    title?: string | null;
    /** Optional one-liner explanation rendered above the code. */
    instructions?: string | null;
    /**
     * Map of `placeholder string → real value` applied at copy-time only.
     * Keys are the literal strings in `body` (e.g. `<paste-your-api-key-here>`),
     * values are the plaintext to splice into the clipboard payload.
     * The display body is never rewritten.
     */
    substitutions?: Record<string, string>;
  };
  let {
    body,
    filename = null,
    format = 'text',
    title = null,
    instructions = null,
    substitutions = {},
  }: Props = $props();

  /**
   * Build the clipboard payload by applying every entry in `substitutions`
   * to the body. Returns the body verbatim when `substitutions` is empty
   * (the placeholder-only Path B case).
   */
  function buildClipboardBody(): string {
    let out = body;
    for (const [placeholder, value] of Object.entries(substitutions)) {
      // Plain string replace — placeholders are unique, simple ASCII strings
      // (`<paste-your-api-key-here>`) and values are alphanumeric+dash key
      // material, so neither side carries regex or replacement metacharacters.
      out = out.split(placeholder).join(value);
    }
    return out;
  }

  const hasSecrets = $derived(Object.keys(substitutions).length > 0);
  const copyLabel = $derived(hasSecrets ? m.portal_comp_copy_with_key() : m.portal_comp_copy());
</script>

<div class="rounded-lg border border-(--border) bg-(--bg-card) overflow-hidden">
  {#if title}
    <div class="px-3 py-2 border-b border-(--border) text-xs font-semibold text-(--text-primary)">
      {title}
    </div>
  {/if}
  <div class="px-3 py-1.5 flex items-center justify-between bg-(--bg-secondary) border-b border-(--border)">
    <div class="flex items-center gap-2 text-[10px] font-mono text-(--text-secondary)">
      {#if filename}
        <span class="truncate">{filename}</span>
        <span class="opacity-50">·</span>
      {/if}
      <span class="uppercase tracking-wider opacity-70">{format}</span>
      {#if hasSecrets}
        <span class="opacity-50">·</span>
        <span class="text-(--success)" title={m.portal_comp_plaintext_available()}>🔒 {m.portal_comp_plaintext_ready()}</span>
      {/if}
    </div>
    <CopyButton text={buildClipboardBody()} label={copyLabel} />
  </div>
  <pre class="px-3 py-2 m-0 text-[11px] leading-relaxed text-(--text-primary) overflow-x-auto whitespace-pre"><code>{body}</code></pre>
  {#if instructions}
    <div class="px-3 py-2 border-t border-(--border) text-[11px] text-(--text-secondary)">
      {instructions}
    </div>
  {/if}
</div>
