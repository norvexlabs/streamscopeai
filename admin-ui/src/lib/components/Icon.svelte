<script lang="ts">
  import {
    ICON,
    ICON_TONE,
    ICON_SIZE_PX,
    TONE_FG,
    type IconName,
    type Tone,
  } from '#lib/icons.js';

  let {
    name,
    tone,
    color,
    size = 'md',
    class: cls = '',
  }: {
    name: IconName;
    /** Override the icon's default category tone (`ICON_TONE[name]`). */
    tone?: Tone;
    /** Raw color override (CSS value, e.g. `'var(--accent)'`, or `'var(--accent-fg)'` on an accent fill).
     *  Reserved for chrome icons that inherit a parent surface color outside
     *  the five-tone vocabulary — sparingly. `tone` is preferred. Passing
     *  `'currentColor'` makes the icon follow the parent text color (handy
     *  inside hoverable buttons / nav links). */
    color?: string;
    size?: 'xs' | 'sm' | 'md' | 'lg';
    class?: string;
  } = $props();

  const fg = $derived(color ?? (tone ? TONE_FG[tone] : TONE_FG[ICON_TONE[name]]));
  const dim = $derived(`${ICON_SIZE_PX[size]}px`);
</script>

<svg
  class={cls}
  style="color: {fg}; width: {dim}; height: {dim}"
  fill="none"
  viewBox="0 0 24 24"
  stroke="currentColor"
  stroke-width="1.75"
>
  <path stroke-linecap="round" stroke-linejoin="round" d={ICON[name]} />
</svg>
