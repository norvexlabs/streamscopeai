<script lang="ts" module>
  export type TagColor =
    | 'blue' | 'violet' | 'teal' | 'amber' | 'pink'
    | 'cyan' | 'orange' | 'indigo' | 'rose' | 'neutral';

  /** Resolve a TagColor to its (bg, text) CSS-variable pair.
   *  Kept exported so non-Svelte callers (e.g. table-cell builders) can
   *  reuse the same mapping without duplicating string literals.
   *  Each pair is spelled out in full — Tailwind only emits arbitrary-value
   *  utilities it sees verbatim in source, so the class strings must be
   *  static, never interpolated. */
  const TAG_CLASSES: Record<TagColor, string> = {
    blue: 'bg-(--tag-blue-bg) text-(--tag-blue-text)',
    violet: 'bg-(--tag-violet-bg) text-(--tag-violet-text)',
    teal: 'bg-(--tag-teal-bg) text-(--tag-teal-text)',
    amber: 'bg-(--tag-amber-bg) text-(--tag-amber-text)',
    pink: 'bg-(--tag-pink-bg) text-(--tag-pink-text)',
    cyan: 'bg-(--tag-cyan-bg) text-(--tag-cyan-text)',
    orange: 'bg-(--tag-orange-bg) text-(--tag-orange-text)',
    indigo: 'bg-(--tag-indigo-bg) text-(--tag-indigo-text)',
    rose: 'bg-(--tag-rose-bg) text-(--tag-rose-text)',
    neutral: 'bg-(--tag-neutral-bg) text-(--tag-neutral-text)',
  };

  export function tagClasses(color: TagColor): string {
    return TAG_CLASSES[color];
  }

  /** The colour of a mark (a bar, a line, a rule) that stands for the same
   *  category as a tag — its `--tag-*-mark` token, the chart series of that hue.
   *  The `-text` shade is for text on the tag's tint and too light to fill a mark. */
  export function tagMarkColor(color: TagColor): string {
    return `var(--tag-${color}-mark)`;
  }
</script>

<script lang="ts">
  interface Props {
    color?: TagColor;
    /** Optional title attribute for hover tooltip. */
    title?: string;
    children?: import('svelte').Snippet;
    /** Optional extra classes (sizing, font, etc.). Color classes come from `color`. */
    class?: string;
  }

  let { color = 'neutral', title, children, class: extra = '' }: Props = $props();
</script>

<span
  class="inline-flex items-center px-1.5 py-0.5 text-[10px] font-medium rounded-sm {tagClasses(color)} {extra}"
  {title}
>
  {@render children?.()}
</span>
