<!--
  Provenance badge for an inherited/overridden field value: where the resolved
  value comes from. Shared by the capability and pricing editors so the wording
  and colours stay identical.
-->
<script lang="ts" module>
  export type FieldSource = 'user' | 'synced' | 'catalog' | 'default';
</script>

<script lang="ts">
  import TagBadge, { type TagColor } from '#lib/components/TagBadge.svelte';

  let { source }: { source: FieldSource } = $props();

  const META: Record<FieldSource, { color: TagColor; label: string; title: string }> = {
    user: { color: 'violet', label: 'You', title: 'Set by you — pinned, so catalog/provider sync will not overwrite it' },
    synced: { color: 'blue', label: 'Synced', title: 'Discovered from the upstream provider' },
    catalog: { color: 'teal', label: 'Catalog', title: 'Inherited from the model catalog' },
    default: { color: 'neutral', label: 'Default', title: 'Built-in default' },
  };
</script>

<TagBadge color={META[source].color} title={META[source].title}>{META[source].label}</TagBadge>
