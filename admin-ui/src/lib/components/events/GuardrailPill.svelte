<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import { guardrailIcon, guardrailTone, type GuardrailInfo } from '#lib/badges.js';

  interface Props {
    guardrail: GuardrailInfo;
  }

  let { guardrail }: Props = $props();
  let tone = $derived(guardrailTone(guardrail));
  let pii = $derived(guardrail.name === 'guardrail:pii');
  let label = $derived(
    pii
      ? guardrail.outcome === 'blocked'
        ? m.event_pill_pii_redacted()
        : 'pii'
      : guardrail.outcome === 'blocked'
        ? m.event_blocked()
        : guardrail.outcome === 'error'
          ? m.event_guardrail_error()
          : guardrail.category === 'jailbreak'
            ? m.event_jailbreak()
            : m.event_injection(),
  );
</script>

<span
  class="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full text-[9px] font-semibold uppercase"
  style="color: var(--{tone}); background: var(--{tone}-bg)"
>
  <Icon name={guardrailIcon(guardrail)} size="xs" {tone} />
  {label}
</span>
