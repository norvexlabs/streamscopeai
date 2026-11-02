<!--
  BYOK pass-through marker. Single source of truth for the amber "BYOK" pill
  shown wherever a bring-your-own-key downstream/server/key appears (LLM gateway
  server + downstream panes, workspace access grants, portal keys). The badge
  reflects a `byok = true` downstream; the provider's brand identity (name/icon)
  comes from the canonical provider catalog separately.
-->
<script lang="ts">
  interface Props {
    /** Hover tooltip. Left undefined by default so portal call sites don't
     *  render untranslated text; admin surfaces pass explicit copy. */
    title?: string;
    /** Extra classes for spacing at the call site (e.g. `ml-1`). */
    class?: string;
    /** Optional test id (preserved for existing e2e hooks). */
    testid?: string;
  }

  let { title, class: extra = '', testid }: Props = $props();
</script>

<span
  class="inline-flex items-center px-2 py-0.5 text-[10px] font-medium rounded-full bg-(--warning-bg) text-(--warning) {extra}"
  {title}
  data-testid={testid}
>BYOK</span>
