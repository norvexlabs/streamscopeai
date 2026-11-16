<script lang="ts">
  // A Portal & clients profile's default container image: the image, the
  // Docker engine switch and the limits a project without its own
  // `.streamscopeai/sandbox.json` runs with. Edited as a draft and saved
  // whole; the server checks it with the rules the CLI applies. The parent
  // re-mounts this component when the stored value changes.
  import { untrack } from 'svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import type { components } from '#lib/generated/api-types.js';

  type DefaultImage = components['schemas']['DefaultImage'];

  interface Props {
    /** The stored default; `null` = none. */
    value: DefaultImage | null;
    disabled?: boolean;
    /** Save `next` whole, or remove the default (`null`). */
    onsave: (next: DefaultImage | null) => void;
  }

  let { value, disabled = false, onsave }: Props = $props();

  const initial = untrack(() => value);
  let image = $state(initial?.image ?? '');
  let docker = $state(initial?.docker ?? false);
  let memory = $state(initial?.memory ?? '');
  let cpus = $state<number | undefined>(initial?.cpus ?? undefined);

  const draft = $derived<DefaultImage>({
    image: image.trim(),
    docker,
    memory: memory.trim() === '' ? null : memory.trim(),
    cpus: cpus === undefined || Number.isNaN(cpus) ? null : cpus,
  });
  const changed = $derived(JSON.stringify(draft) !== JSON.stringify(value ?? { image: '', docker: false, memory: null, cpus: null }));
</script>

<div class="rounded-lg border border-(--border) bg-(--bg-card) p-5 space-y-4" data-testid="client-access-default-image">
  <div>
    <h3 class="text-sm font-semibold text-(--text-primary)">Default container image</h3>
    <p class="text-xs text-(--text-secondary)">
      What <code>ssai run --sandbox docker</code> uses in a project without its own
      <code>.streamscopeai/sandbox.json</code>; a project's file replaces all of it. The sandbox adds the agent to the
      image itself. Without a default, such a project is refused and names the file to write.
    </p>
  </div>
  <div class="grid grid-cols-1 sm:grid-cols-4 gap-3">
    <FormField label="Image" for="default-image-ref" class="sm:col-span-2" help="A registry reference, e.g. mcr.microsoft.com/devcontainers/base:ubuntu">
      <TextInput id="default-image-ref" mono bind:value={image} placeholder="mcr.microsoft.com/devcontainers/base:ubuntu" {disabled} data-testid="default-image-ref" />
    </FormField>
    <FormField label="Memory" for="default-image-memory" help="e.g. 8g; empty: no limit">
      <TextInput id="default-image-memory" mono bind:value={memory} placeholder="8g" {disabled} data-testid="default-image-memory" />
    </FormField>
    <FormField label="CPUs" for="default-image-cpus" help="Empty: no limit">
      <NumberInput id="default-image-cpus" bind:value={cpus} min="0.1" max="1024" step="0.5" {disabled} data-testid="default-image-cpus" />
    </FormField>
  </div>
  <div class="-mx-5 px-5 border-t border-(--border)">
    <ToggleSetting
      label="Docker engine inside"
      description="Run a Docker engine in the container, so the agent can build and run containers. The container then runs privileged, inside the developer's rootless Podman."
      value={docker}
      {disabled}
      onValueChange={(v: boolean) => (docker = v)}
    />
  </div>
  <div class="flex justify-end gap-2">
    {#if value}
      <button
        onclick={() => onsave(null)}
        {disabled}
        data-testid="default-image-remove"
        class="px-3 py-1.5 text-xs border border-(--border) text-(--text-secondary) hover:text-(--text-primary) rounded-lg transition-colors disabled:opacity-50"
      >Remove the default</button>
    {/if}
    <button
      onclick={() => onsave(draft)}
      disabled={disabled || !changed || draft.image === ''}
      data-testid="default-image-save"
      class="px-3 py-1.5 text-xs rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-colors disabled:opacity-50"
    >Save</button>
  </div>
</div>
