<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Callout from '#lib/components/Callout.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import { formatDuration } from '#lib/formatters.js';
  import { assignmentSummary, effectiveWait, formatWaitRange } from '#lib/qos.js';
  import { onMount } from 'svelte';

  type QosClass = components['schemas']['QosClass'];
  type DeploymentLimits = components['schemas']['QosDeploymentLimits'];
  type MintKind = 'interactive' | 'automation';

  let classes = $state<QosClass[]>([]);
  let limits = $state<DeploymentLimits | null>(null);
  let loading = $state(true);

  // ── Editor ──
  let showForm = $state(false);
  let editing = $state<QosClass | null>(null);
  let formName = $state('');
  let formDescription = $state('');
  let formRank = $state<number | undefined>(10);
  let formSheddable = $state(false);
  let formTtlSeconds = $state<number | undefined>(undefined);
  let formDefault = $state(false);
  let formMintInteractive = $state(false);
  let formMintAutomation = $state(false);
  let formError = $state('');
  let saving = $state(false);

  // ── Delete + reassign ──
  let deleteTarget = $state<QosClass | null>(null);
  let reassignTo = $state('');
  let deleting = $state(false);

  function referenceCount(c: QosClass): number {
    return c.workspace_count + c.key_count + c.route_target_count;
  }

  /** The sentence under the list, generated from the live order so it stays
   *  true after an admin re-ranks or renames a class. */
  const ladder = $derived(
    classes.length === 0
      ? ''
      : classes.map((c) => c.name).join(' → ')
  );

  /** Both hold limits, or nothing: a gateway whose values could not be read
   *  states none, and a guessed wait would read as a promise. */
  const holds = $derived(
    limits?.default_hold && limits?.max_wait ? { default_hold: limits.default_hold, max_wait: limits.max_wait } : null,
  );
  const defaultWaitText = $derived(holds ? formatWaitRange(holds.default_hold, formatDuration) : null);
  const maxWaitText = $derived(holds ? formatWaitRange(holds.max_wait, formatDuration) : null);
  /** The wait being typed, as the gateway would apply it. */
  const formWait = $derived(
    effectiveWait(formTtlSeconds == null ? null : Math.round(formTtlSeconds * 1000), holds),
  );

  /** Which class holds a star now, for the editor's "currently" hint. */
  const holderOf = (pick: (c: QosClass) => boolean) => classes.find(pick)?.name ?? null;

  async function load() {
    loading = true;
    const [c, l] = await Promise.all([
      adminApi.GET('/api/v1/admin/qos-classes', {}),
      adminApi.GET('/api/v1/admin/qos-classes/deployment-limits', {}),
    ]);
    if (c.error) {
      toast.error('Failed to load priority classes', { body: extractError(c.error) });
    } else {
      classes = c.data?.items ?? [];
    }
    // Without the limits the page still works; waits read "deployment
    // default" instead of a number rather than guessing one.
    limits = l.error ? null : (l.data ?? null);
    loading = false;
  }

  function openForm(c: QosClass | null) {
    editing = c;
    formName = c?.name ?? '';
    formDescription = c?.description ?? '';
    formRank = c ? c.rank : (classes.at(-1)?.rank ?? 0) + 10;
    formSheddable = c?.sheddable ?? false;
    formTtlSeconds = c?.queue_ttl_ms == null ? undefined : Math.round(c.queue_ttl_ms / 1000);
    formDefault = c?.is_default ?? false;
    formMintInteractive = c?.mint_default_for === 'interactive';
    formMintAutomation = c?.mint_default_for === 'automation';
    formError = '';
    showForm = true;
  }

  /** Moves or clears the stars the editor changed. Each is its own action on
   *  the server; the first to fail stops the rest and says which. */
  async function applyStars(id: string, before: QosClass | null): Promise<string | null> {
    if (formDefault && !before?.is_default) {
      const { error } = await adminApi.POST('/api/v1/admin/qos-classes/{id}/actions/set-default', {
        params: { path: { id } },
      });
      if (error) return `Could not make it the default class: ${extractError(error)}`;
    }
    const wasMint = before?.mint_default_for ?? null;
    const wantMint: MintKind | null = formMintInteractive ? 'interactive' : formMintAutomation ? 'automation' : null;
    if (wantMint !== wasMint) {
      const { error } = await adminApi.POST('/api/v1/admin/qos-classes/{id}/actions/set-mint-default', {
        params: { path: { id } },
        body: { kind: wantMint },
      });
      if (error) return `Could not change which new keys start on it: ${extractError(error)}`;
    }
    return null;
  }

  async function save() {
    if (!formName.trim()) {
      formError = 'Name is required.';
      return;
    }
    if (formRank == null) {
      formError = 'Rank is required.';
      return;
    }
    saving = true;
    formError = '';
    const queue_ttl_ms = formTtlSeconds == null ? null : Math.round(formTtlSeconds * 1000);
    const body = {
      name: formName.trim(),
      description: formDescription,
      rank: formRank,
      sheddable: formSheddable,
      queue_ttl_ms,
    };
    let id = editing?.id ?? null;
    if (editing) {
      const { error } = await adminApi.PATCH('/api/v1/admin/qos-classes/{id}', {
        params: { path: { id: editing.id } },
        body,
      });
      if (error) {
        saving = false;
        formError = extractError(error);
        return;
      }
    } else {
      const { data, error } = await adminApi.POST('/api/v1/admin/qos-classes', { body });
      if (error || !data) {
        saving = false;
        formError = error ? extractError(error) : 'The class was not created.';
        return;
      }
      id = data.id;
    }
    const starError = id ? await applyStars(id, editing) : null;
    saving = false;
    await load();
    if (starError) {
      // The class itself is saved; keep the editor open on what did not land.
      editing = classes.find((c) => c.id === id) ?? editing;
      formError = starError;
      return;
    }
    showForm = false;
    toast.success(editing ? 'Class updated' : 'Class created');
  }

  async function confirmDelete() {
    if (!deleteTarget) return;
    deleting = true;
    const needsMove = referenceCount(deleteTarget) > 0;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/qos-classes/{id}', {
      params: {
        path: { id: deleteTarget.id },
        query: needsMove ? { reassign_to: reassignTo } : {},
      },
    });
    deleting = false;
    if (err) {
      const code = extractErrorCode(err);
      toast.error(
        code === 'qos_class_in_use'
          ? 'Still in use — pick a class to move its workspaces and keys to.'
          : 'Failed to delete the class',
        { body: extractError(err) },
      );
      return;
    }
    deleteTarget = null;
    toast.success('Class deleted');
    await load();
  }

  function openDelete(c: QosClass) {
    deleteTarget = c;
    reassignTo = classes.find((o) => o.id !== c.id && o.is_default)?.id ?? '';
  }

  onMount(load);
</script>

<div class="space-y-6">
  <div>
    <h3 class="text-sm font-semibold text-(--text-primary)">Priority under load</h3>
    <p class="text-xs text-(--text-secondary) mt-1 max-w-3xl">
      Which requests go first when a model has no capacity left. Nothing here applies while an
      upstream has room to spare — priority decides the order of a queue, and with capacity free
      there is no queue. Set an upstream's capacity on its server page, under Scheduling.
    </p>
    {#if ladder}
      <p class="text-xs text-(--text-secondary) mt-2">
        Served in this order: <span class="font-medium text-(--text-primary)">{ladder}</span>.
        Within one class, the caller who has used the model least goes first.
      </p>
    {/if}
    {#if defaultWaitText && maxWaitText}
      <p class="text-xs text-(--text-secondary) mt-2" data-testid="qos-deployment-limits">
        Set by the operator for this deployment: a request waits
        <span class="font-medium text-(--text-primary)">{defaultWaitText}</span> unless its class
        says otherwise, and never longer than
        <span class="font-medium text-(--text-primary)">{maxWaitText}</span>.
      </p>
    {/if}
  </div>

  <div class="flex items-center justify-between">
    <div>
      <h4 class="text-sm font-semibold text-(--text-primary)">Classes</h4>
      <p class="text-xs text-(--text-secondary) mt-0.5">
        A ★ badge marks a default: the class for anything that names none, and the class new keys
        start on. Change them in Edit.
      </p>
    </div>
    <button
      onclick={() => openForm(null)}
      class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors"
    >
      New Class
    </button>
  </div>

  {#if loading}
    <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
  {:else if classes.length === 0}
    <p class="text-xs text-(--text-secondary) px-3 py-4 text-center">
      No priority classes. Every request is treated the same when a model is busy.
    </p>
  {:else}
    <div class="overflow-x-auto">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border)">
            <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Class</th>
            <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Rank</th>
            <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">At saturation</th>
            <th class="px-3 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Waits up to</th>
            <th class="px-3 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium" title="Workspaces, keys and route targets set to this class">Assigned to</th>
            <th class="px-3 py-2"></th>
          </tr>
        </thead>
        <tbody>
          {#each classes as c (c.id)}
            {@const wait = effectiveWait(c.queue_ttl_ms, holds)}
            {@const assigned = assignmentSummary(c)}
            <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors" data-qos-class={c.name}>
              <td class="px-3 py-2">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-medium text-(--text-primary)">{c.name}</span>
                  {#if c.is_default}
                    <TagBadge color="teal" title="Workspaces and keys with no class of their own run as this">★ default</TagBadge>
                  {/if}
                  {#if c.mint_default_for === 'interactive'}
                    <TagBadge color="blue" title="New keys a person creates for their own tool start on this">★ new tool keys</TagBadge>
                  {/if}
                  {#if c.mint_default_for === 'automation'}
                    <TagBadge color="neutral" title="New keys for CI and service accounts start on this">★ new automation keys</TagBadge>
                  {/if}
                </div>
                {#if c.description}
                  <p class="text-xs text-(--text-secondary) mt-0.5">{c.description}</p>
                {/if}
              </td>
              <td class="px-3 py-2 text-right font-mono text-(--text-secondary)">{c.rank}</td>
              <td class="px-3 py-2 text-(--text-secondary)">
                {c.sheddable ? 'Refused right away' : 'Waits its turn'}
              </td>
              <td class="px-3 py-2 text-right font-mono whitespace-nowrap" data-qos-wait>
                {#if c.sheddable}
                  <span class="text-(--text-tertiary)" title="Refused right away: never waits">—</span>
                {:else if wait == null}
                  <span class="text-(--text-tertiary)">{c.queue_ttl_ms == null ? 'deployment default' : formatDuration(c.queue_ttl_ms)}</span>
                {:else if wait.source === 'default'}
                  <span class="text-(--text-tertiary)" title="The deployment default — this class names no wait of its own">{formatWaitRange(wait, formatDuration)} · default</span>
                {:else if wait.capped}
                  <span class="text-(--warning-text)" title="The class asks for {formatDuration(c.queue_ttl_ms)}; the deployment allows at most {maxWaitText}">{formatWaitRange(wait, formatDuration)} (capped)</span>
                {:else}
                  <span class="text-(--text-secondary)">{formatWaitRange(wait, formatDuration)}</span>
                {/if}
              </td>
              <td class="px-3 py-2 text-xs text-(--text-secondary)" data-qos-assigned>
                {assigned.length > 0 ? assigned.join(' · ') : 'Nothing'}
              </td>
              <td class="px-3 py-2 text-right whitespace-nowrap">
                <button onclick={() => openForm(c)} class="text-xs text-(--accent) hover:underline">Edit</button>
                {#if !c.is_default}
                  <button onclick={() => openDelete(c)} class="ml-3 text-xs text-(--error) hover:underline">Delete</button>
                {/if}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</div>

<Modal open={showForm} title={editing ? 'Edit class' : 'New class'} onclose={() => (showForm = false)} maxWidth="max-w-lg">
  <div class="space-y-4">
    <FormField label="Name" for="qos-name">
      <TextInput id="qos-name" bind:value={formName} placeholder="Interactive" />
    </FormField>
    <FormField label="Description" for="qos-description">
      <TextInput id="qos-description" bind:value={formDescription} placeholder="A person is waiting for this answer." />
    </FormField>
    <FormField label="Rank" for="qos-rank" help="Lower goes first. The numbers themselves mean nothing — only their order does.">
      <NumberInput id="qos-rank" bind:value={formRank} />
    </FormField>
    <FormField label="At saturation" for="qos-shed">
      <SelectInput
        id="qos-shed"
        bind:value={() => (formSheddable ? 'shed' : 'queue'), (v) => (formSheddable = v === 'shed')}
      >
        <option value="queue">Wait its turn</option>
        <option value="shed">Refuse right away</option>
      </SelectInput>
    </FormField>
    {#if formSheddable}
      <Callout severity="warning" title="Refused rather than delayed">
        A request of this class is turned away the moment the model is full, instead of waiting.
        Use it for traffic that is better retried later than served late.
      </Callout>
    {:else}
      <FormField
        label="Waits up to (seconds)"
        for="qos-wait"
        help={maxWaitText
          ? `How long a request of this class waits for capacity before it is refused with a retry hint. Empty uses the deployment default; the deployment never holds a request longer than ${maxWaitText}.`
          : 'How long a request of this class waits for capacity before it is refused with a retry hint. Empty uses the deployment default.'}
      >
        <NumberInput
          id="qos-wait"
          bind:value={formTtlSeconds}
          min={1}
          max={600}
          placeholder={defaultWaitText ? `${defaultWaitText} — deployment default` : 'deployment default'}
        />
      </FormField>
      {#if formWait?.capped}
        <Callout severity="info" title="Capped by the deployment">
          The gateways hold a request at most {maxWaitText}, so this class waits
          {formatWaitRange(formWait, formatDuration)}.
        </Callout>
      {/if}
    {/if}

    <div class="pt-2 border-t border-(--border) space-y-3">
      <p class="text-xs text-(--text-secondary) uppercase tracking-wider">Default for</p>
      <ToggleSetting
        label="Anything that names no class"
        description={editing?.is_default
          ? 'Workspaces and keys with no class of their own run as this. To change it, make another class the default.'
          : `Workspaces and keys with no class of their own run as this.${holderOf((c) => c.is_default) ? ` Currently: ${holderOf((c) => c.is_default)}.` : ''}`}
        bind:value={formDefault}
        disabled={editing?.is_default ?? false}
      />
      <ToggleSetting
        label="New keys for a person's own tool"
        description={`Keys created from the portal Quickstart or a CLI sign-in start on this, within what the workspace allows.${!formMintInteractive && holderOf((c) => c.mint_default_for === 'interactive') ? ` Currently: ${holderOf((c) => c.mint_default_for === 'interactive')}.` : ''}`}
        bind:value={formMintInteractive}
        onValueChange={(v) => { if (v) formMintAutomation = false; }}
      />
      <ToggleSetting
        label="New automation keys"
        description={`Keys created for CI and service accounts start on this.${!formMintAutomation && holderOf((c) => c.mint_default_for === 'automation') ? ` Currently: ${holderOf((c) => c.mint_default_for === 'automation')}.` : ''}`}
        bind:value={formMintAutomation}
        onValueChange={(v) => { if (v) formMintInteractive = false; }}
      />
    </div>

    {#if formError}
      <Callout severity="error" title="Could not save">{formError}</Callout>
    {/if}
  </div>
  {#snippet footer()}
    <button onclick={() => (showForm = false)} class="px-4 py-2 text-sm text-(--text-secondary)">Cancel</button>
    <button
      onclick={save}
      disabled={saving}
      class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50"
      data-testid="qos-class-save"
    >
      {saving ? 'Saving…' : 'Save'}
    </button>
  {/snippet}
</Modal>

<Modal open={deleteTarget !== null} title="Delete priority class" onclose={() => (deleteTarget = null)} maxWidth="max-w-md">
  {#if deleteTarget}
    <p class="text-sm text-(--text-primary)">
      Delete <strong>{deleteTarget.name}</strong>?
    </p>
    {#if referenceCount(deleteTarget) > 0}
      <p class="text-sm text-(--text-secondary) mt-2">
        {deleteTarget.workspace_count} workspace(s), {deleteTarget.key_count} key(s) and
        {deleteTarget.route_target_count} route target(s) run as this class. Pick where they go:
      </p>
      <div class="mt-3">
        <FormField label="Move them to" for="qos-reassign">
          <SelectInput id="qos-reassign" bind:value={reassignTo}>
            {#each classes.filter((c) => c.id !== deleteTarget?.id) as c (c.id)}
              <option value={c.id}>{c.name}</option>
            {/each}
          </SelectInput>
        </FormField>
      </div>
    {:else}
      <p class="text-sm text-(--text-secondary) mt-2">Nothing runs as this class.</p>
    {/if}
    <div class="flex items-center gap-3 mt-4">
      <button
        onclick={confirmDelete}
        disabled={deleting || (referenceCount(deleteTarget) > 0 && !reassignTo)}
        class="px-3 py-1.5 bg-(--error) hover:opacity-90 text-(--error-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
      >
        {deleting ? 'Deleting…' : 'Delete'}
      </button>
      <button
        onclick={() => (deleteTarget = null)}
        class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-medium rounded-lg transition-colors"
      >
        Cancel
      </button>
    </div>
  {/if}
</Modal>
