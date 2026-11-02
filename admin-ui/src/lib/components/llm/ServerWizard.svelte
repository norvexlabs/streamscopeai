<script lang="ts">
  // Adding an upstream server, one decision at a time: who serves the models,
  // where the gateway reaches them, and whether it discovers what they are.
  //
  // Creating is a different job from editing — it picks a provider and proves a
  // credential reaches it — so it is a guided flow and not the settings form.
  // The create itself carries the reachability check, so the last step IS the
  // test: an address that does not answer, or a credential the provider
  // refuses, sends the operator back to Connection with the reason, and
  // "Create anyway" is the deliberate override.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, isOverridableUpstreamError } from '#lib/api-helpers.js';
  import { providerSeeds } from '#lib/provider-seeds.js';
  import { API_FORMATS, UPSTREAM_TRANSPORTS } from '#lib/constants.js';
  import { PROVIDER_DEFAULTS } from '#lib/generated/providers.js';
  import {
    applyProvider,
    applyTransport,
    canModelSync,
    providerPublishesModelList,
    seedFor,
    transportOwnsUrl,
    urlRequired,
    type ProviderSeeds,
    type ServerForm,
  } from '#lib/server-form.js';
  import Modal from '#lib/components/Modal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import Spinner from '#lib/components/Spinner.svelte';
  import ProviderIcon from '#lib/components/ProviderIcon.svelte';
  import ByokBadge from '#lib/components/ByokBadge.svelte';
  import TransportHelp from './TransportHelp.svelte';
  import UpstreamWriteError from './UpstreamWriteError.svelte';

  let {
    open,
    onclose,
    oncreated,
  }: {
    open: boolean;
    onclose: () => void;
    /** The new server's id — the caller navigates to it. */
    oncreated: (serverId: string) => void;
  } = $props();

  const STEPS = ['provider', 'connection', 'discovery'] as const;
  type Step = (typeof STEPS)[number];
  const STEP_TITLE: Record<Step, string> = {
    provider: 'Provider',
    connection: 'Connection',
    discovery: 'Discovery',
  };

  let step = $state<Step>('provider');
  let form = $state<ServerForm>(blank());
  let authMode = $state<'managed' | 'byok'>('managed');
  let autoSync = $state(true);
  let creating = $state(false);
  let error = $state('');
  let errorCode = $state<string | null>(null);
  // The wizard owns its own catalog rather than taking one as a prop: it seeds
  // every default from it, so a half-arrived catalog is not a state it can be
  // in. The fetch is cached process-wide, so only the first open ever waits.
  let seeds = $state<ProviderSeeds>({});
  let ready = $state(false);

  function blank(): ServerForm {
    return {
      name: '',
      provider: 'openai',
      api_key: '',
      upstream_url: '',
      upstream_api_format: 'chat_completions',
      chat_endpoint_path: '',
      transport: 'default',
    };
  }

  // Each opening starts over; a half-filled server from a cancelled attempt is
  // never what the next one wants. Plain `let`s, not `$state`: the effect
  // writes them, and reactive flags would make it depend on its own writes.
  let wasOpen = false;
  let openGen = 0;
  $effect(() => {
    if (open && !wasOpen) {
      step = 'provider';
      authMode = 'managed';
      autoSync = true;
      creating = false;
      error = '';
      errorCode = null;
      ready = false;
      form = blank();
      // Seed only once the catalog is in hand, so no field is ever filled from
      // the build's compiled copy while the served one is on its way. A reopen
      // during the fetch discards the older answer.
      const gen = ++openGen;
      void providerSeeds().then((catalog) => {
        if (gen !== openGen) return;
        seeds = catalog;
        form = applyProvider(blank(), 'openai', catalog);
        ready = true;
      });
    }
    wasOpen = open;
  });

  const byok = $derived(authMode === 'byok');
  const seed = $derived(seedFor(form.provider, seeds));
  const needsUrl = $derived(urlRequired(form, seeds, byok));
  const ownsUrl = $derived(transportOwnsUrl(form.transport));
  const isEntra = $derived(form.transport === 'azure_openai_entra');
  // Whether a model list can be read at all. One question: the create-time
  // first sync, an explicit "Sync now" and the periodic worker all depend on
  // the same two facts, so the toggle promises exactly what it delivers.
  const discoverable = $derived(!byok && canModelSync(form));
  const providerLabel = $derived(
    PROVIDER_DEFAULTS.find((p) => p.value === form.provider)?.label ?? form.provider,
  );
  const formatLabel = $derived(
    API_FORMATS.find((f) => f.value === form.upstream_api_format)?.label ?? form.upstream_api_format,
  );

  const stepIndex = $derived(STEPS.indexOf(step));
  const canAdvance = $derived(
    !ready
      ? false
      : step === 'provider'
      ? form.name.trim() !== ''
      : step === 'connection'
        ? !needsUrl || form.upstream_url.trim() !== ''
        : true,
  );

  function pickProvider(next: string) {
    form = applyProvider(form, next, seeds);
  }

  function pickTransport(next: string) {
    form = applyTransport(form, next, seeds);
  }

  function back() {
    error = '';
    errorCode = null;
    if (stepIndex > 0) step = STEPS[stepIndex - 1];
  }

  function next() {
    error = '';
    errorCode = null;
    if (stepIndex < STEPS.length - 1) step = STEPS[stepIndex + 1];
  }

  async function create(opts: { force?: boolean } = {}) {
    creating = true;
    error = '';
    errorCode = null;
    const { data, error: err } = await adminApi.POST('/api/v1/admin/servers', {
      body: {
        name: form.name.trim(),
        provider: form.provider,
        upstream_url: form.upstream_url.trim() || undefined,
        upstream_api_format: form.upstream_api_format,
        chat_endpoint_path: form.chat_endpoint_path.trim() || undefined,
        transport: form.transport,
        api_key: form.api_key || undefined,
        auto_sync_enabled: autoSync,
        byok,
        force: opts.force || undefined,
      },
    });
    creating = false;
    if (err || !data) {
      error = extractError(err, 'Failed to create the server');
      errorCode = extractErrorCode(err);
      // A check the upstream failed — nothing answered, or it refused the key
      // — is a Connection problem. Show it there, beside the two fields that
      // can fix it.
      if (isOverridableUpstreamError(errorCode)) step = 'connection';
      return;
    }
    oncreated(data.id);
  }
</script>

<Modal {open} title="Add server" {onclose} maxWidth="max-w-xl">
  <ol class="flex items-center gap-2 mb-5 text-xs">
    {#each STEPS as s, i (s)}
      <li class="flex items-center gap-2">
        <span
          class="inline-flex items-center justify-center w-5 h-5 rounded-full text-[10px] font-semibold {i <= stepIndex
            ? 'bg-(--accent) text-(--accent-fg)'
            : 'bg-(--bg-elevated) text-(--text-secondary) border border-(--border)'}"
        >{i + 1}</span>
        <span class={i === stepIndex ? 'font-medium text-(--text-primary)' : 'text-(--text-secondary)'}>{STEP_TITLE[s]}</span>
        {#if i < STEPS.length - 1}
          <span class="w-6 h-px bg-(--border)"></span>
        {/if}
      </li>
    {/each}
  </ol>

  {#if !ready}
    <!-- Nothing is offered before the catalog lands: every default on every
         step comes from it, and a field filled in the meantime would either be
         seeded from the build's stale copy or wiped when the real one arrives. -->
    <div class="flex items-center gap-3 py-10 justify-center text-sm text-(--text-secondary)">
      <Spinner ariaLabel="Loading the provider catalog" /> Loading providers…
    </div>
  {:else if step === 'provider'}
    <div class="space-y-4">
      <FormField label="Name" for="wiz-name" help="How this server is named across the console — not the model names it serves.">
        <TextInput id="wiz-name" bind:value={form.name} placeholder="e.g. vllm-prod" />
      </FormField>
      <FormField label="Provider" for="wiz-provider">
        <SelectInput id="wiz-provider" value={form.provider} onchange={(e) => pickProvider((e.currentTarget as HTMLSelectElement).value)}>
          {#each PROVIDER_DEFAULTS as p (p.value)}<option value={p.value}>{p.label}</option>{/each}
        </SelectInput>
      </FormField>
      <div class="flex items-start gap-2 px-3 py-2 rounded-lg border border-(--border) bg-(--bg-primary)/50 text-xs text-(--text-secondary)">
        <ProviderIcon name={form.provider} size="lg" className="mt-0.5 shrink-0" />
        <span>
          {providerLabel} speaks <span class="text-(--text-primary)">{formatLabel}</span>.
          {#if seed.url}
            The next step starts from <span class="font-mono text-(--text-primary)">{seed.url}</span>.
          {:else}
            It has no standard address, so the next step asks for one.
          {/if}
        </span>
      </div>
      <FormField label="Authentication">
        <div class="flex items-center gap-1">
          <button
            type="button"
            onclick={() => (authMode = 'managed')}
            class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {authMode === 'managed'
              ? 'bg-(--accent) text-(--accent-fg) border border-(--accent)'
              : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
          >API key (managed)</button>
          <button
            type="button"
            onclick={() => { authMode = 'byok'; form.api_key = ''; }}
            class="px-3 py-1.5 rounded-lg text-sm font-medium transition-colors {authMode === 'byok'
              ? 'bg-(--warning) text-(--warning-fg) border border-(--warning)'
              : 'bg-(--bg-primary) text-(--text-secondary) border border-(--border) hover:text-(--text-primary)'}"
          >BYOK pass-through</button>
        </div>
        {#if byok}
          <p class="mt-1.5 text-xs text-(--text-secondary)">
            Keyless pass-through — the client forwards its own credential; unconfigured models pass through to
            the upstream URL. Creates an empty pass-through provider, and nothing is discovered.
          </p>
        {/if}
      </FormField>
    </div>
  {:else if step === 'connection'}
    <div class="space-y-4">
      <FormField
        label="First endpoint"
        for="wiz-url"
        help="Where this server answers. It becomes the server's first endpoint — add replicas of the same engine on the server's Endpoints tab afterwards."
      >
        <TextInput
          id="wiz-url"
          bind:value={form.upstream_url}
          placeholder={needsUrl ? 'e.g. http://vllm:8000' : seed.url}
          mono
        />
      </FormField>
      {#if !byok}
        <FormField label={isEntra ? 'Entra credential' : 'API key'} for="wiz-key">
          <TextInput
            id="wiz-key"
            bind:value={form.api_key}
            type="password"
            placeholder={isEntra ? '{"tenant_id":"…","client_id":"…","client_secret":"…"}' : 'Provider API key'}
          />
        </FormField>
      {:else}
        <div class="flex items-center gap-2 text-xs text-(--text-secondary)">
          <ByokBadge title="BYOK pass-through — keyless upstream; the client forwards its own credential." />
          No credential is stored — each client forwards its own.
        </div>
      {/if}
      <FormField label="Transport" for="wiz-transport">
        <SelectInput id="wiz-transport" value={form.transport} onchange={(e) => pickTransport((e.currentTarget as HTMLSelectElement).value)}>
          {#each UPSTREAM_TRANSPORTS as t (t.value)}<option value={t.value}>{t.label}</option>{/each}
        </SelectInput>
        <TransportHelp transport={form.transport} />
      </FormField>
      <FormField label="Upstream protocol" for="wiz-format" help="The wire this server speaks natively. The gateway translates every client protocol onto it.">
        <SelectInput id="wiz-format" bind:value={form.upstream_api_format}>
          {#each API_FORMATS as f (f.value)}<option value={f.value}>{f.label}</option>{/each}
        </SelectInput>
      </FormField>
      {#if !ownsUrl}
        <FormField
          label="Chat endpoint path"
          for="wiz-path"
          help="Appended to the URL for OpenAI-compatible chat requests. Blank uses the provider default (usually /v1/chat/completions)."
        >
          <TextInput id="wiz-path" bind:value={form.chat_endpoint_path} placeholder="/v1/chat/completions" mono />
        </FormField>
      {/if}
    </div>
  {:else}
    <div class="space-y-4">
      {#if byok}
        <Callout severity="info" title="A pass-through discovers nothing">
          A keyless server has no credential to ask with, so its models are not discovered. Add the models
          you want routed by name, or let unconfigured ones pass through.
        </Callout>
      {:else if !discoverable}
        <Callout severity="info" title="This upstream publishes no model list">
          {#if !providerPublishesModelList(form.provider)}
            {providerLabel} serves no model list the gateway can read, so there is nothing to discover.
          {:else}
            A {UPSTREAM_TRANSPORTS.find((t) => t.value === form.transport)?.label ?? form.transport} endpoint
            serves no model list the gateway can read, so there is nothing to discover.
          {/if}
          Add its models by name once the server exists.
        </Callout>
      {:else}
        <label class="flex items-start gap-2.5 cursor-pointer">
          <input type="checkbox" bind:checked={autoSync} class="mt-0.5 accent-(--accent)" />
          <span class="text-sm text-(--text-primary)">
            Discover and mirror this server's models
            <span class="block text-xs text-(--text-secondary)">
              Reads the model list now and keeps a same-named mirror downstream in sync. Turn off for a manual
              server — no discovery, and you build the downstream yourself.
            </span>
          </span>
        </label>
      {/if}

      <dl class="rounded-lg border border-(--border) divide-y divide-(--border) text-sm" data-testid="wizard-summary">
        {#snippet row(label: string, value: string, mono: boolean)}
          <div class="flex items-baseline gap-3 px-3 py-2">
            <dt class="w-32 shrink-0 text-xs text-(--text-secondary)">{label}</dt>
            <dd class="text-(--text-primary) break-all {mono ? 'font-mono text-xs' : ''}">{value}</dd>
          </div>
        {/snippet}
        {@render row('Name', form.name.trim() || '—', false)}
        {@render row('Provider', `${providerLabel} · ${formatLabel}`, false)}
        {@render row('First endpoint', form.upstream_url.trim() || seed.url || '—', true)}
        {@render row('Transport', UPSTREAM_TRANSPORTS.find((t) => t.value === form.transport)?.label ?? form.transport, false)}
        {@render row('Authentication', byok ? 'BYOK pass-through (keyless)' : form.api_key ? 'API key (managed)' : 'API key (managed) — none given', false)}
      </dl>
    </div>
  {/if}

  {#if error}
    <div class="mt-4">
      <UpstreamWriteError
        message={error}
        code={errorCode}
        retryLabel="Create anyway"
        busy={creating}
        onretry={() => create({ force: true })}
      />
    </div>
  {/if}

  {#snippet footer()}
    <!-- Back on the left, forward on the right: the two directions a step can
         go, placed where a wizard puts them. -->
    <div class="flex items-center justify-between">
      <button
        onclick={stepIndex === 0 ? onclose : back}
        class="px-4 py-2 text-sm text-(--text-secondary) hover:text-(--text-primary) transition-colors"
      >{stepIndex === 0 ? 'Cancel' : 'Back'}</button>
      {#if step === 'discovery'}
        <button
          onclick={() => create()}
          disabled={creating || !form.name.trim()}
          data-testid="wizard-create"
          class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50 inline-flex items-center gap-2"
        >
          {#if creating}<Spinner />{/if}
          Create server
        </button>
      {:else}
        <button
          onclick={next}
          disabled={!canAdvance}
          data-testid="wizard-next"
          class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors disabled:opacity-50"
        >Continue</button>
      {/if}
    </div>
  {/snippet}
</Modal>
