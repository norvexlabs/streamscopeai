<script lang="ts">
  import Icon from './Icon.svelte';
  import {
    ICON_TONE,
    TONE_BG,
    TILE_SIZE_PX,
    type IconName,
    type Tone,
  } from '#lib/icons.js';

  let {
    name,
    tone,
    size = 'md',
  }: {
    name: IconName;
    /** Override the icon's default category tone (`ICON_TONE[name]`). */
    tone?: Tone;
    /** `md` → 36×36 tile with 20px glyph (default — card chrome).
     *  `sm` → 28×28 tile with 16px glyph (inline list rows). */
    size?: 'sm' | 'md';
  } = $props();

  const effectiveTone = $derived(tone ?? ICON_TONE[name]);
  const dim = $derived(`${TILE_SIZE_PX[size]}px`);
</script>

<div
  class="rounded-lg flex items-center justify-center shrink-0"
  style="background-color: {TONE_BG[effectiveTone]}; width: {dim}; height: {dim}"
>
  <Icon {name} tone={effectiveTone} {size} />
</div>
