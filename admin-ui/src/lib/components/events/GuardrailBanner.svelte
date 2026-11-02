<script lang="ts">
  import Icon from '#lib/components/Icon.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import {
    severityBucket,
    guardrailIcon,
    guardrailTone,
    GUARDRAIL_CATEGORY_LABELS,
    type GuardrailInfo,
  } from '#lib/badges.js';

  interface Props {
    guardrail: GuardrailInfo;
  }

  let { guardrail }: Props = $props();

  // Localize the Low/Med/High confidence bucket (severityBucket returns the raw
  // English bucket). Called per-render from markup, so the active locale applies.
  function confidenceLabel(confidence: number): string {
    switch (severityBucket(confidence)) {
      case 'High': return m.event_level_high();
      case 'Medium': return m.event_level_medium();
      default: return m.event_level_low();
    }
  }

  let tone = $derived(guardrailTone(guardrail));
  // The inbound surface (request phase) screens the user's own message / a
  // folded tool-result; the web surface (response phase) screens fetched
  // content. Same shield, different subject — the copy adapts so the operator
  // reads a true sentence either way.
  let inbound = $derived(guardrail.phase === 'request');
  // PII findings (`guardrail:pii`) read differently from the injection
  // classifier: the subject for a response-phase PII finding is the model's
  // reply, not fetched web content, and the entity types replace the
  // category/confidence detail.
  let pii = $derived(guardrail.name === 'guardrail:pii');
  let subject = $derived(
    inbound
      ? m.event_subject_this_message()
      : pii
        ? m.event_subject_the_response()
        : m.event_subject_fetched_content(),
  );
  let entityList = $derived((guardrail.entities ?? []).join(', '));
  let headline = $derived.by(() => {
    if (pii) {
      if (guardrail.outcome === 'blocked')
        return inbound
          ? m.event_pii_redacted_before_model()
          : m.event_pii_redacted_before_delivery();
      return m.event_pii_detected_in({ subject });
    }
    if (guardrail.outcome === 'error') return m.event_guardrail_could_not_scan({ subject });
    if (guardrail.outcome === 'blocked' && guardrail.error)
      return m.event_content_withheld_injection();
    const jailbreak = guardrail.category === 'jailbreak';
    if (guardrail.outcome === 'blocked') {
      if (jailbreak)
        return inbound
          ? m.event_jailbreak_blocked_message()
          : m.event_jailbreak_blocked_content();
      return inbound
        ? m.event_injection_blocked_message()
        : m.event_injection_blocked_content();
    }
    return jailbreak
      ? m.event_jailbreak_detected_in({ subject })
      : m.event_injection_detected_in({ subject });
  });
</script>

<div
  class="flex items-start gap-2 px-4 py-2 border-t"
  style="border-color: var(--{tone}-border); background: var(--{tone}-bg)"
>
  <Icon name={guardrailIcon(guardrail)} size="sm" {tone} />
  <div class="flex-1 text-[11px] leading-snug" style="color: var(--{tone})">
    <span class="font-semibold">{headline}</span>
    {#if pii}
      {#if entityList}
        <span class="opacity-80">— {entityList}</span>
      {/if}
    {:else if guardrail.outcome !== 'error' && !guardrail.error && guardrail.category != null && guardrail.confidence != null}
      <span class="opacity-80">
        — {GUARDRAIL_CATEGORY_LABELS[guardrail.category] ?? guardrail.category},
        {m.event_confidence({ level: confidenceLabel(guardrail.confidence) })}
      </span>
    {/if}
    {#if guardrail.target}
      <div class="text-[10px] opacity-70 mt-0.5 break-all font-mono">{guardrail.target}</div>
    {/if}
    {#if guardrail.error}
      <div class="text-[10px] opacity-70 mt-0.5 wrap-break-word">
        {guardrail.error}
        {guardrail.outcome === 'error'
          ? m.event_failed_open()
          : m.event_failed_closed()}
      </div>
    {/if}
  </div>
</div>
