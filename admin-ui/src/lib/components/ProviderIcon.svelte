<script lang="ts">
  // Tiny wrapper around the generated LLM-provider icon registry
  // (`#lib/generated/providers.js`, built from the provider seed). Use anywhere a
  // row shows "downstream provider name + glyph" so callers stop hand-rolling
  // `<svg viewBox="0 0 24 24"><path d={getProvider(…).icon}/></svg>`.
  //
  // Sizes are tuned for inline use beside small metadata text — `sm` = 12px
  // for 10px font-mono lines, `md` = 16px to match `<Icon size="sm">` when
  // a glyph sits beside a tag label, `lg` = 20px to match `<Icon size="md">`
  // in larger callouts. Deliberately one notch smaller than the icon
  // registry's scale so provider glyphs don't tower over the metadata they
  // annotate.
  import { getProvider } from '#lib/generated/providers.js';

  let {
    name,
    size = 'sm',
    className = '',
  }: {
    /** Raw provider key (e.g. `openai`, `azure_openai`, `googlegemini`) — looked
     *  up via `getProvider()` which folds underscores/case and falls back to
     *  the `custom` glyph if nothing matches. */
    name: string;
    size?: 'sm' | 'md' | 'lg';
    /** Extra classes for caller-side spacing or color (icons render in
     *  `currentColor`, so a `text-(--text-secondary)` parent tints it). */
    className?: string;
  } = $props();

  const sizeClass = $derived(
    size === 'sm' ? 'w-3 h-3' : size === 'md' ? 'w-4 h-4' : 'w-5 h-5',
  );
  const provider = $derived(getProvider(name));
</script>

<svg class="{sizeClass} {className}" viewBox="0 0 24 24" fill="currentColor" aria-hidden="true">
  <path d={provider.icon} />
</svg>
