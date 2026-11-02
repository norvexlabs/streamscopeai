<script lang="ts">
  // Full-width severity-tinted banner for inline page notices (buffered work,
  // degraded state, informational hints). Severity drives the bg/border/text
  // token triplet and the icon tint. Pass page-specific content via children.
  import type { Snippet } from 'svelte';
  import Icon from '#lib/components/Icon.svelte';
  import type { IconName, Tone } from '#lib/icons.js';

  type Severity = 'info' | 'warning' | 'error' | 'success';

  let {
    severity = 'info',
    icon,
    title,
    children,
    action,
  }: {
    severity?: Severity;
    /** Override the severity-default icon name. */
    icon?: IconName;
    title: string;
    children?: Snippet;
    /** What to do about it — a link or button, right-aligned beside the text. */
    action?: Snippet;
  } = $props();

  const TINT: Record<Severity, { bg: string; border: string; text: string }> = {
    info:    { bg: 'var(--info-bg)',    border: 'var(--info-border)',    text: 'var(--info-text)'    },
    warning: { bg: 'var(--warning-bg)', border: 'var(--warning-border)', text: 'var(--warning-text)' },
    error:   { bg: 'var(--error-bg)',   border: 'var(--error-border)',   text: 'var(--error-text)'   },
    success: { bg: 'var(--success-bg)', border: 'var(--success-border)', text: 'var(--success-text)' },
  };

  // Severity → category-identifying glyph (paired with the matching tone).
  const SEVERITY_ICON: Record<Severity, IconName> = {
    info:    'info',
    warning: 'errorCircle',
    error:   'blocked',
    success: 'checkCircle',
  };

  const t = $derived(TINT[severity]);
  const iconName = $derived(icon ?? SEVERITY_ICON[severity]);
  const iconTone = $derived(severity as Tone);
</script>

<div
  class="rounded-xl border px-5 py-4"
  style="background-color: {t.bg}; border-color: {t.border}"
  role={severity === 'error' ? 'alert' : 'status'}
  aria-live="polite"
>
  <div class="flex items-start gap-3">
    <div class="shrink-0 mt-0.5">
      <Icon name={iconName} tone={iconTone} />
    </div>
    <div class="flex-1 min-w-0" style="color: {t.text}">
      <p class="text-sm font-semibold">{title}</p>
      {#if children}
        <div class="text-xs mt-1 opacity-90">{@render children()}</div>
      {/if}
    </div>
    {#if action}
      <div class="shrink-0 self-center">{@render action()}</div>
    {/if}
  </div>
</div>
