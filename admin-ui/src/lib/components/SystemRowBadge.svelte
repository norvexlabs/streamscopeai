<script lang="ts">
  // Small read-only marker for rows the gateway manages itself (e.g. the
  // synthetic `builtin-web` MCP upstream). Sibling components disable
  // their Edit / Delete actions on rows that mount this badge so operators
  // never click into a dead-end form.
  interface Props {
    /** Optional title override — default explains the protection. */
    title?: string;
  }
  let { title = 'System resource — managed by the gateway.' }: Props = $props();
</script>

<span
  class="inline-flex items-center px-1.5 py-0.5 rounded-sm text-[9px] font-semibold uppercase tracking-wider border bg-(--accent)/15 text-(--accent) border-(--accent)/30"
  {title}
>
  System
</span>
