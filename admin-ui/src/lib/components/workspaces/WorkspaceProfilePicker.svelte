<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { page } from '$app/state';
  import { scopeHref } from '#lib/tenant.js';
  import type { ProfileLite } from '#lib/scope.svelte.js';
  import FormField from '#lib/components/forms/FormField.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  interface Props {
    /** Profile family this picker assigns (e.g. 'tools', 'guardrail'). */
    kind: string;
    /** Human label (e.g. "Tool policy", "Guardrail"). */
    label: string;
    workspaceId: string;
    /**
     * Current three-state assignment: `'inherit'` (tenant default — no explicit
     * row), `'off'` (policy disabled for this workspace), or a profile id.
     */
    current: string;
    /** Whether the kind can be turned off for a workspace. A kind every
     *  workspace must resolve (Portal & clients) offers no Off. */
    allowOff?: boolean;
    /** What the profile decides, for the help line. Defaults to "applies to
     *  this workspace's traffic". */
    help?: string;
    /** Selectable profiles of this kind (tenant pool). */
    profiles: ProfileLite[];
    /** Optional deep-link to manage the selected profile (tenant-relative). */
    manageHref?: (id: string) => string;
    /** Notified after a successful assignment so the parent can refresh. */
    onchanged?: () => void;
  }

  let { kind, label, workspaceId, current, profiles, manageHref, onchanged, allowOff = true, help }: Props = $props();

  // Local selection mirrors the current state; falls back to 'inherit'. A
  // kind with no Off reads a stored "off" as the Default, as the server does.
  let sel = $derived(!current || (current === 'off' && !allowOff) ? 'inherit' : current);
  let saving = $state(false);

  async function assign(value: string) {
    // Map the picker value to the tagged ProfileAssignmentChoice.
    const choice =
      value === 'inherit'
        ? ({ mode: 'inherit' } as const)
        : value === 'off'
          ? ({ mode: 'off' } as const)
          : ({ mode: 'profile', id: value } as const);
    saving = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/workspaces/{id}', {
      params: { path: { id: workspaceId } },
      body: { profiles: { [kind]: choice } },
    });
    saving = false;
    if (error) {
      toast.error(`Failed to set ${label.toLowerCase()}`, { body: extractError(error) });
      return;
    }
    toast.success(`${label} updated`);
    onchanged?.();
  }
</script>

<section class="space-y-2 max-w-xl">
  <h3 class="text-sm font-semibold text-(--text-primary)">{label}</h3>
  <FormField label="Profile" help={help ?? `Which ${label.toLowerCase()} profile applies to this workspace's traffic.`}>
    <SelectInput
      value={sel}
      disabled={saving}
      onchange={(e) => assign((e.currentTarget as HTMLSelectElement).value)}
    >
      <option value="inherit">Default (tenant default)</option>
      {#if allowOff}<option value="off">Off (no policy)</option>{/if}
      {#each profiles as p (p.id)}
        {#if !p.is_default}<option value={p.id}>{p.name}</option>{/if}
      {/each}
    </SelectInput>
  </FormField>
  {#if manageHref && sel !== 'inherit' && sel !== 'off'}
    <a
      href={scopeHref(page.params.slug ?? '', page.url.pathname, manageHref(sel))}
      class="inline-block text-xs text-(--accent) hover:underline"
    >Manage this profile →</a>
  {/if}
</section>
