<script lang="ts">
  // Shown on a pending suggestion whose content the agent revised after it was
  // put on screen: the row keeps saying what the admin is reading
  // (`#lib/suggestion-merge.js`) until they choose to load the new version.
  interface Props {
    onshow: () => void;
  }
  let { onshow }: Props = $props();
</script>

<div class="mt-2 flex items-center gap-2 text-xs text-(--warning)">
  <span>The agent revised this suggestion since it was shown.</span>
  <button type="button" class="underline hover:text-(--text-primary)" onclick={onshow}>Show the new version</button>
</div>
