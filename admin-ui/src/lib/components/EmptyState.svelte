<script lang="ts">
  import type { Snippet } from 'svelte';

  /**
   * Standard "no content here" state with consistent vertical rhythm:
   * optional icon, title, body, and a primary action. Use whenever a list
   * or panel renders no items so users get orientation and a next step.
   */
  let {
    title,
    body,
    icon,
    action,
    compact = false,
  }: {
    title: string;
    body?: string;
    icon?: Snippet;
    action?: Snippet;
    /** Tighter spacing for inline use (e.g. inside a small dashboard panel). */
    compact?: boolean;
  } = $props();
</script>

<div class="flex flex-col items-center text-center {compact ? 'gap-2 py-6' : 'gap-3 py-12'}">
  {#if icon}
    <div class="text-(--text-tertiary)">
      {@render icon()}
    </div>
  {/if}
  <h3 class="text-sm font-semibold text-(--text-primary)">{title}</h3>
  {#if body}
    <p class="text-sm text-(--text-secondary) max-w-md leading-relaxed">{body}</p>
  {/if}
  {#if action}
    <div class="mt-2">
      {@render action()}
    </div>
  {/if}
</div>
