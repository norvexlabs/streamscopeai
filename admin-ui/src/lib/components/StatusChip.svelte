<script lang="ts">
  // A state, said three ways: an icon, a word and a tone — never colour alone.
  // Callers pass an entry from a status registry (`ENDPOINT_STATUS`,
  // `SERVER_HEALTH` in `#lib/endpoints.js`), so a state reads the same wherever
  // it is shown.
  import Icon from '#lib/components/Icon.svelte';
  import type { IconName, Tone } from '#lib/icons.js';

  let {
    label,
    icon,
    tone,
    title,
    status,
  }: {
    label: string;
    icon: IconName;
    tone: Tone;
    title?: string;
    /** The machine name of the state, for tests and styling hooks. */
    status?: string;
  } = $props();

  // Each tone's chip, spelled out so the class strings stay static.
  const CLASSES: Record<Tone, string> = {
    success: 'bg-(--success-bg) text-(--success-text) border-(--success-border)',
    error: 'bg-(--error-bg) text-(--error-text) border-(--error-border)',
    warning: 'bg-(--warning-bg) text-(--warning-text) border-(--warning-border)',
    info: 'bg-(--info-bg) text-(--info-text) border-(--info-border)',
    neutral: 'bg-(--bg-elevated) text-(--text-secondary) border-(--border)',
  };
</script>

<span
  class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full border text-[11px] font-medium whitespace-nowrap {CLASSES[tone]}"
  {title}
  data-status={status}
>
  <Icon name={icon} size="xs" color="currentColor" />
  {label}
</span>
