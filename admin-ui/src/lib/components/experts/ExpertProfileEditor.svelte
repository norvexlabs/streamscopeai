<script lang="ts">
  /**
   * An expert profile's content: the judge model its experts analyze with and
   * which experts run on the workspaces assigned to it, behind one Save (two
   * requests: what failed stays unsaved and the bar stays up). A Layered
   * profile also runs every expert the Default includes; those cards show as
   * inherited and cannot be removed here.
   */
  import { page } from '$app/state';
  import { beforeNavigate } from '$app/navigation';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { thref } from '#lib/tenant.js';
  import { expertTitle } from '#lib/colormaps/experts.js';
  import type { AgentExpert, AgentModelOption } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import { cardState, membershipChanged, runningCount, selectAll as allSelected } from '#lib/expertMembership.js';
  import ExpertCard from './ExpertCard.svelte';
  import ExpertAnalysisStart from './ExpertAnalysisStart.svelte';
  import JudgeModelSelect from './JudgeModelSelect.svelte';

  type Profile = components['schemas']['Profile'];

  interface Props {
    profileId: string;
    isDefault: boolean;
    standalone: boolean;
    /** Every expert in the tenant; `null` while it loads. */
    experts: AgentExpert[] | null;
    /** Why the expert list could not be loaded, if it could not. */
    expertsError?: string;
  }

  let { profileId, isDefault, standalone, experts: expertsProp, expertsError = '' }: Props = $props();
  const experts = $derived(expertsProp ?? []);

  const slug = $derived(page.params.slug ?? '');
  const layered = $derived(!isDefault && !standalone);

  let loading = $state(true);
  // Membership is the page's job; without it nothing renders.
  let loadError = $state('');
  // The picker's inputs (model list, Default's model) failing leaves the
  // membership editable and the picker saying why it cannot offer models.
  let modelsError = $state('');
  let saving = $state(false);
  // Bumped per save: the Analysis start section reads what a save changes.
  let savedCount = $state(0);

  let models = $state<AgentModelOption[]>([]);
  let defaultModel = $state('');
  // `''` encodes "inherit the Default's model" (a NULL model on the wire).
  let savedModel = $state('');
  let model = $state('');
  let savedSelected = $state<Set<string>>(new Set());
  let selected = $state<Set<string>>(new Set());
  // A Layered profile's inherited experts: the Default's members.
  let inherited = $state<Set<string>>(new Set());

  const sorted = $derived([...experts].sort((a, b) => expertTitle(a.axis).localeCompare(expertTitle(b.axis))));
  const running = $derived(runningCount(experts, selected, inherited));
  const membershipDirty = $derived(membershipChanged(selected, savedSelected));
  const dirty = $derived(model !== savedModel || membershipDirty);

  // Bumped per load: a response for an earlier profile id is dropped.
  let loadGen = 0;

  async function load() {
    const gen = ++loadGen;
    loading = true;
    loadError = '';
    modelsError = '';
    try {
      await loadInto(gen);
    } catch (e: unknown) {
      if (gen === loadGen) loadError = e instanceof Error ? e.message : String(e);
    } finally {
      if (gen === loadGen) loading = false;
    }
  }

  async function loadInto(gen: number) {
    // The whole profile list, so the Default is found however many profiles
    // sort ahead of it; a failure is kept, not thrown, like the other loads.
    // The Default's own page needs neither its id nor its model from the list.
    const noProfiles: Profile[] = [];
    const listAll = (
      isDefault
        ? Promise.resolve(noProfiles)
        : fetchAllPages((offset, limit) =>
            adminApi.GET('/api/v1/admin/profiles', { params: { query: { kind: 'expert', offset, limit } } }),
          )
    ).then(
      (items) => ({ items, error: undefined }),
      (e: unknown) => ({ items: [], error: e instanceof Error ? e.message : String(e) }),
    );
    const [prof, opts, list, members] = await Promise.all([
      adminApi.GET('/api/v1/admin/profiles/{id}', { params: { path: { id: profileId } } }),
      adminApi.GET('/api/v1/admin/experts/agent-models'),
      listAll,
      adminApi.GET('/api/v1/admin/profiles/{id}/expert', { params: { path: { id: profileId } } }),
    ]);
    if (gen !== loadGen) return;
    const err = prof.error ?? members.error ?? (layered ? list.error : undefined);
    if (err) {
      loadError = extractError(err, 'Failed to load the profile');
      return;
    }
    // Only the model list drives the picker's checks; a missing profile list
    // costs the Inherit option its model name, nothing more.
    if (opts.error) modelsError = extractError(opts.error, 'Failed to load the model list');
    const base = list.items.find((p) => p.is_default);
    if (layered && !base) {
      // Without the Default's members the page would show experts that run
      // here as not running.
      loadError = 'The Default expert profile could not be found';
      return;
    }
    if (layered && base) {
      const { data, error } = await adminApi.GET('/api/v1/admin/profiles/{id}/expert', {
        params: { path: { id: base.id } },
      });
      if (gen !== loadGen) return;
      if (error) {
        loadError = extractError(error, 'Failed to load the Default profile');
        return;
      }
      inherited = new Set(data?.expert_ids ?? []);
    } else {
      inherited = new Set();
    }
    models = opts.data?.models ?? [];
    defaultModel = base?.model ?? '';
    savedModel = model = prof.data?.model ?? '';
    savedSelected = new Set(members.data?.expert_ids ?? []);
    selected = new Set(savedSelected);
  }

  $effect(() => {
    void profileId;
    void layered;
    load();
  });

  // Leaving with unsaved changes asks first, as the bar says they are unsaved.
  beforeNavigate((nav) => {
    if (dirty && !saving && !confirm('Leave this profile without saving your changes?')) nav.cancel();
  });

  function setMember(id: string, on: boolean) {
    const next = new Set(selected);
    if (on) next.add(id);
    else next.delete(id);
    selected = next;
  }

  // "Select all" adds what the Default does not already run here; "Clear"
  // removes every listing this profile holds (the Default's experts keep
  // running on a Layered profile, as their cards say).
  function selectAll() {
    selected = allSelected(experts.map((e) => e.id), selected, inherited);
  }

  function clearAll() {
    selected = new Set();
  }

  function discard() {
    model = savedModel;
    selected = new Set(savedSelected);
  }

  async function save() {
    saving = true;
    try {
      await saveChanges();
    } catch (e: unknown) {
      toast.error('Failed to save', { body: e instanceof Error ? e.message : String(e) });
    } finally {
      saving = false;
    }
  }

  // The model and the membership are separate requests: each is tried, what
  // failed stays unsaved (the bar stays up), and the toast names it.
  async function saveChanges() {
    const failed: string[] = [];
    if (model !== savedModel) {
      const { data, error } = await adminApi.PATCH('/api/v1/admin/profiles/{id}', {
        params: { path: { id: profileId } },
        body: { model: model === '' ? null : model },
      });
      if (error) failed.push(`Could not save the judge model: ${extractError(error)}`);
      else savedModel = model = data?.model ?? '';
    }
    if (membershipDirty) {
      const { data, error } = await adminApi.PUT('/api/v1/admin/profiles/{id}/expert', {
        params: { path: { id: profileId } },
        body: { expert_ids: [...selected] },
      });
      if (error) failed.push(`Could not save the experts: ${extractError(error)}`);
      else {
        savedSelected = new Set(data?.expert_ids ?? []);
        selected = new Set(savedSelected);
      }
    }
    savedCount += 1;
    if (failed.length > 0) toast.error('Not everything was saved', { body: failed.join('\n') });
    else toast.success('Profile saved');
  }
</script>

{#if loading}
  <div class="text-sm text-(--text-secondary)">Loading…</div>
{:else if loadError}
  <div class="px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-sm text-(--error-text)">{loadError}</div>
{:else}
  <section class="bg-(--bg-card) rounded-xl p-5 border border-(--border) mb-6">
    <div class="grid gap-4 md:grid-cols-[1fr_minmax(16rem,24rem)] md:items-start">
      <div>
        <h2 class="font-medium text-(--text-primary)">Judge model</h2>
        <p class="text-xs text-(--text-secondary) mt-1 leading-relaxed">
          The LLM the analysis agent calls to run the experts below. It reads the conversations of the
          workspaces using this profile and answers once per expert; it never serves user traffic.
          {#if isDefault}
            This is the tenant baseline: every profile without its own judge model uses it.
          {:else}
            Inherit uses the Default profile's model{defaultModel ? ` (${defaultModel})` : ''}.
          {/if}
          An expert with its own model override uses that instead.
        </p>
      </div>
      <div>
      <JudgeModelSelect
        id="judge-model"
        bind:value={model}
        {models}
        loaded={!modelsError}
        disabled={saving}
        emptyLabel={isDefault ? undefined : `Inherit Default${defaultModel ? ` (${defaultModel})` : ''}`}
      />
      {#if modelsError}
        <p class="text-xs text-(--error-text) mt-1.5">{modelsError}: the list cannot be checked right now.</p>
      {/if}
      </div>
    </div>
  </section>

  <ExpertAnalysisStart {profileId} {isDefault} reloadKey={savedCount} unsaved={membershipDirty} />

  <section>
    <div class="flex items-end justify-between gap-4 mb-3 flex-wrap">
      <div>
        <h2 class="font-medium text-(--text-primary)">Experts</h2>
        <p class="text-xs text-(--text-secondary) mt-1">
          {#if isDefault}
            Every workspace without its own expert profile runs these. Layered profiles add to this set;
            standalone profiles pick their own.
          {:else if layered}
            Runs every expert of the Default profile, plus the ones you add here.
          {:else}
            Runs only the experts selected here.
          {/if}
          <span class="text-(--text-primary)">{running} of {experts.length} will run.</span>
        </p>
      </div>
      {#if experts.length > 0}
        <div class="flex items-center gap-3 text-xs">
          <button type="button" onclick={selectAll} disabled={saving} class="text-(--accent) hover:underline disabled:opacity-50">Select all</button>
          <button type="button" onclick={clearAll} disabled={saving} class="text-(--text-secondary) hover:text-(--text-primary) disabled:opacity-50">Clear</button>
          <a href={thref(slug, '/experts?tab=experts')} class="text-(--text-secondary) hover:text-(--text-primary)">Edit definitions ›</a>
        </div>
      {/if}
    </div>

    {#if expertsError}
      <div class="px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-sm text-(--error-text)">{expertsError}</div>
    {:else if expertsProp === null}
      <div class="text-sm text-(--text-secondary)">Loading experts…</div>
    {:else if experts.length === 0}
      <p class="text-sm text-(--text-secondary)">
        No experts are defined yet. <a href={thref(slug, '/experts?tab=experts')} class="text-(--accent) hover:underline">Create one</a>.
      </p>
    {:else}
      <div class="grid gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {#each sorted as e (e.id)}
          <ExpertCard
            expert={e}
            membership={cardState(e.id, selected, inherited)}
            disabled={saving}
            onselect={(on) => setMember(e.id, on)}
          />
        {/each}
      </div>
    {/if}
  </section>

  {#if dirty}
    <div class="sticky bottom-4 mt-6 flex items-center justify-between gap-4 px-4 py-3 rounded-xl border border-(--accent) bg-(--bg-secondary) shadow-lg">
      <span class="text-sm text-(--text-primary)">Unsaved changes</span>
      <div class="flex gap-2">
        <button type="button" onclick={discard} disabled={saving} class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) disabled:opacity-50">Discard</button>
        <button type="button" onclick={save} disabled={saving} class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50">{saving ? 'Saving…' : 'Save'}</button>
      </div>
    </div>
  {/if}
{/if}
