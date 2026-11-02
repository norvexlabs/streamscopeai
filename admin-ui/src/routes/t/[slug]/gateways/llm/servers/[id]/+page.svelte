<script lang="ts">
  // One upstream server: its replica endpoints and which models each serves.
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, isOverridableUpstreamError, orphanedRoutes } from '#lib/api-helpers.js';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import type { components } from '#lib/generated/api-types.js';
  import { useTabState } from '#lib/hooks.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import { formatDuration, formatTimeAgo } from '#lib/formatters.js';
  import { ENDPOINT_STATUS, endpointStatus, moveEndpoint, removalSummary } from '#lib/endpoints.js';
  import { API_FORMATS, UPSTREAM_TRANSPORTS } from '#lib/constants.js';
  import { PROVIDER_DEFAULTS } from '#lib/generated/providers.js';
  import { providerSeeds } from '#lib/provider-seeds.js';
  import { syncStatus } from '#lib/sync-status.js';
  import {
    applyProvider,
    applyTransport,
    canModelSync,
    isEmptyPatch,
    providerPublishesModelList,
    patchNeedsProbe,
    serverPatch,
    transportOwnsUrl,
    urlRequired,
    type ProviderSeeds,
    type ServerForm,
  } from '#lib/server-form.js';
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import MetricCard from '#lib/components/dashboard/MetricCard.svelte';
  import MetricGrid from '#lib/components/dashboard/MetricGrid.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import HelpTooltip from '#lib/components/HelpTooltip.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import StatusChip from '#lib/components/StatusChip.svelte';
  import MembershipMatrix from '#lib/components/endpoints/MembershipMatrix.svelte';
  import TransportHelp from '#lib/components/llm/TransportHelp.svelte';
  import UpstreamWriteError from '#lib/components/llm/UpstreamWriteError.svelte';
  import ProviderIcon from '#lib/components/ProviderIcon.svelte';
  import ByokBadge from '#lib/components/ByokBadge.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import ScopePicker from '#lib/components/forms/ScopePicker.svelte';
  import { fieldsForMode, qosModeOf, type QosMode } from '#lib/qos.js';
  import { formatShare } from '#lib/formatters.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type Server = components['schemas']['ServerDetailResponse'];
  type Endpoint = components['schemas']['EndpointResponse'];
  type Membership = components['schemas']['ServerMembershipResponse'];
  type Preview = components['schemas']['EndpointDiscoveryPreview'];
  type Probe = components['schemas']['EngineProbeResponse'];

  const id = $derived(params.id);
  const slug = $derived(params.slug);

  let server = $state<Server | null>(null);
  let endpoints = $state<Endpoint[]>([]);
  let membership = $state<Membership | null>(null);
  let loading = $state(true);
  let loadError = $state('');

  // The server itself comes first: this page is where a server is configured,
  // and its health rides above the tabs so no tab trades one for the other.
  type ServerTab = 'server' | 'endpoints' | 'models' | 'scheduling';
  const TABS = ['server', 'endpoints', 'models', 'scheduling'] as const satisfies readonly ServerTab[];
  const tab = useTabState<ServerTab>(TABS, 'server');

  // A plain counter, not $state: read before the first await, a $state would
  // make the effect below depend on it and reload in a loop.
  let loadGen = 0;
  async function load(serverId: string) {
    const gen = ++loadGen;
    const [s, e, m] = await Promise.all([
      adminApi.GET('/api/v1/admin/servers/{id}', { params: { path: { id: serverId } } }),
      adminApi.GET('/api/v1/admin/servers/{id}/endpoints', { params: { path: { id: serverId }, query: { limit: 500 } } }),
      adminApi.GET('/api/v1/admin/servers/{id}/membership', { params: { path: { id: serverId } } }),
    ]);
    if (gen !== loadGen) return;
    loading = false;
    if (s.error || !s.data) {
      loadError = extractError(s.error, 'Failed to load the server');
      return;
    }
    loadError = '';
    server = s.data;
    endpoints = e.data?.items ?? [];
    membership = m.data ?? null;
    if (e.error) toast.error('Failed to load the endpoints', { body: extractError(e.error) });
    if (m.error) toast.error('Failed to load the model membership', { body: extractError(m.error) });
  }

  $effect(() => {
    if (id) void load(id);
  });

  const healthyCount = $derived(endpoints.filter((e) => endpointStatus(e) === 'healthy').length);
  const downCount = $derived(endpoints.filter((e) => endpointStatus(e) === 'breaker_open').length);
  const assumedEndpoints = $derived(endpoints.filter((e) => e.membership === 'assumed' && e.enabled));
  const mismatchedModels = $derived(
    membership?.models.filter((m) => m.window_mismatch || m.identity_mismatch) ?? [],
  );
  const missingReports = $derived(endpoints.reduce((n, e) => n + e.mismatched_models, 0));
  const canReplicate = $derived(!!server && server.transport === 'default' && !server.byok);

  // --- Server settings ------------------------------------------------------
  // Everything about the server itself. The URL is deliberately NOT one of
  // them while the server can have replicas: there is no "the server's URL"
  // then, only endpoints, and writing one here would rewrite the primary
  // replica and reset its discovery. A server that cannot replicate has
  // exactly one endpoint whose URL the API only accepts through this form.
  let seeds = $state<ProviderSeeds>({});
  let settingsSeededId = $state('');
  let initialForm = $state<ServerForm | null>(null);
  let form = $state<ServerForm>({
    name: '', provider: '', api_key: '', upstream_url: '',
    upstream_api_format: '', chat_endpoint_path: '', transport: '',
  });
  let savingSettings = $state(false);
  let settingsError = $state('');
  let settingsErrorCode = $state<string | null>(null);
  let savingAutoSync = $state(false);
  let autoSync = $state(false);
  let deleteOpen = $state(false);
  let deleting = $state(false);

  void providerSeeds().then((s) => (seeds = s));

  // A saved server, as either shape the API answers with: the page's own read
  // (`ServerDetailResponse`) or a write's echo (`ServerResponse`).
  type StoredServer = Pick<
    Server,
    'id' | 'name' | 'provider' | 'upstream_url' | 'upstream_api_format'
      | 'chat_endpoint_path' | 'transport' | 'auto_sync_enabled'
  >;

  function formOf(s: StoredServer): ServerForm {
    return {
      name: s.name,
      provider: s.provider,
      api_key: '',
      upstream_url: s.upstream_url ?? '',
      upstream_api_format: s.upstream_api_format,
      chat_endpoint_path: s.chat_endpoint_path ?? '',
      transport: s.transport,
    };
  }

  function seedSettings(s: StoredServer) {
    settingsSeededId = s.id;
    initialForm = formOf(s);
    form = formOf(s);
    autoSync = s.auto_sync_enabled;
  }

  // Seeded once per server, so a reload triggered by a sibling action cannot
  // clobber an unsaved edit.
  $effect(() => {
    if (server && settingsSeededId !== server.id) seedSettings(server);
  });

  const ownsUrl = $derived(transportOwnsUrl(form.transport));
  // Whether the address belongs to the ENDPOINTS rather than to this form.
  // Judged on the PENDING transport, not the saved one: picking a transport
  // that owns its URL moves the address back here, and gating on the stored
  // value would leave an operator who just chose Azure with no field to put
  // the resource URL in — and a save that probes the old host.
  const addressIsEndpoints = $derived(canReplicate && !ownsUrl);
  const urlIsRequired = $derived(urlRequired(form, seeds, !!server?.byok));
  // A required address that has been blanked: the API would answer 400, or —
  // worse, where the provider has a default — silently re-derive one and
  // rewrite the primary endpoint to it.
  const addressMissing = $derived(!addressIsEndpoints && urlIsRequired && !form.upstream_url.trim());
  // The provider no longer matches the address the endpoints hold. The address
  // is not this form's to change, so say so rather than moving it silently.
  const providerLeftAddressBehind = $derived(
    addressIsEndpoints && !!initialForm && form.provider !== initialForm.provider,
  );
  const providerLabelFor = (value: string) =>
    PROVIDER_DEFAULTS.find((p) => p.value === value)?.label ?? value;
  const providerLabel = $derived(providerLabelFor(form.provider));
  // The STORED provider's label, for the sentences that describe the saved
  // server rather than the form: an unsaved pick must not relabel what
  // discovery is doing right now.
  const savedProviderLabel = $derived(server ? providerLabelFor(server.provider) : '');
  const primaryUrl = $derived(endpoints.find((e) => e.primary)?.url ?? server?.upstream_url ?? '');
  // Discovery describes the SAVED server — its toggle writes the stored row the
  // moment it is flipped — so it is judged on the stored values, never on an
  // unsaved pick in the form beside it.
  const discoverable = $derived(!!server && !server.byok && canModelSync(server));
  // What the last discovery run actually did. A run that FAILED still stamps
  // the timestamp, so a page showing only "last run 2 minutes ago" reports a
  // failure as a success.
  const lastSync = $derived(syncStatus(server));
  const pendingPatch = $derived(initialForm ? serverPatch(initialForm, form) : {});
  const settingsDirty = $derived(!isEmptyPatch(pendingPatch));

  function pickProvider(next: string) {
    // While the address belongs to the endpoints it is not this form's to
    // change; once a transport that owns its URL is pending, it is.
    form = applyProvider(form, next, seeds, addressIsEndpoints);
  }

  function pickTransport(next: string) {
    form = applyTransport(form, next, seeds);
  }

  // The fields are frozen for the duration, not just the button: a save carries
  // a reachability probe that can take seconds, and the answer re-seeds the
  // form — anything typed in the meantime would be discarded without ever
  // having been sent.
  async function saveSettings(opts: { force?: boolean } = {}) {
    if (!initialForm) return;
    savingSettings = true;
    settingsError = '';
    settingsErrorCode = null;
    const { data, error } = await adminApi.PATCH('/api/v1/admin/servers/{id}', {
      params: { path: { id } },
      // The backend probes the upstream on every write unless told not to, so a
      // rename would be refused whenever the engine happens to be down — for an
      // edit the probe could not validate either way.
      body: { ...pendingPatch, force: opts.force || !patchNeedsProbe(pendingPatch) || undefined },
    });
    savingSettings = false;
    if (error || !data) {
      settingsError = extractError(error, 'Failed to save the server');
      settingsErrorCode = extractErrorCode(error);
      return;
    }
    toast.success('Server saved');
    // Re-seed from the WRITE'S OWN ANSWER, so the next save's diff is taken
    // against what was stored rather than against what was typed, and the
    // credential box clears after a rotation. Not from the reload below: that
    // can return early to a concurrent load and leave the pre-save row in
    // place, which would silently revert the fields just saved — and the
    // seeding effect could never correct it, the server id being unchanged.
    seedSettings(data);
    await load(id);
  }

  async function saveAutoSync(next: boolean) {
    savingAutoSync = true;
    const { error } = await adminApi.PATCH('/api/v1/admin/servers/{id}', {
      params: { path: { id } },
      body: { auto_sync_enabled: next, force: true },
    });
    savingAutoSync = false;
    if (error) {
      autoSync = !next;
      toast.error('Failed to change auto-sync', { body: extractError(error) });
      return;
    }
    await load(id);
  }

  async function deleteServer() {
    deleteOpen = false;
    deleting = true;
    const { data, error } = await adminApi.DELETE('/api/v1/admin/servers/{id}', { params: { path: { id } } });
    deleting = false;
    if (error) {
      toast.error('Failed to delete the server', { body: extractError(error) });
      return;
    }
    if (orphanedRoutes(data) > 0 && data?.message) toast.warning('Routes orphaned', data.message);
    // The answer names the keys a pass-through's server delete revoked.
    else toast.success(data?.message ?? 'Server deleted.');
    await goto(thref(slug, server?.byok ? '/gateways/llm?tab=passthrough' : '/gateways/llm?tab=upstream'));
  }

  // --- QoS ------------------------------------------------------------------
  // What the gateway does with this server's traffic under load, and whether it
  // reads the engines' own metrics. Seeded once per server, so a sibling reload
  // cannot clobber an unsaved edit.
  let schedSeededId = $state('');
  let schedMode = $state<QosMode>('off');
  const QOS_MODES: { value: QosMode; label: string; description: string }[] = [
    { value: 'off', label: 'Off', description: 'Every request goes straight to the engine, which serves them first come, first served. Classes change nothing. The right choice for a hosted provider, which queues on its own side.' },
    { value: 'engine_priority', label: 'Engine priority only', description: "The gateway holds nothing; it sends each request's class to vLLM as its priority, and vLLM reorders its own waiting queue. No fairness between users, no wait limit, and nothing ever refused by the gateway." },
    { value: 'gateway', label: 'Gateway-managed (recommended for self-hosted engines)', description: 'The gateway sends each engine only what it can run, holds the rest, and releases it most important class first — and, within a class, the user who has used the least first. A request that waits too long is refused with a retry hint.' },
  ];
  let schedPriority = $state(false);
  let schedMaxInFlight = $state<number | undefined>(undefined);
  let schedWaiting = $state<number | undefined>(undefined);
  let schedEngineMetrics = $state(false);
  /** 'learned': the in-flight limit follows the engine's KV cache; 'fixed': it is the number set. */
  let schedCapacity = $state<'fixed' | 'learned'>('fixed');
  /** A learned limit's token-latency target — automatic, the figure set, or
   *  none; kept while the limit is fixed. */
  type ItlTargetMode = components['schemas']['ItlTarget']['type'];
  let schedItlMode = $state<ItlTargetMode>('auto');
  /** The figure of a fixed target, in ms; kept while another mode is shown. */
  let schedItlTarget = $state<number | undefined>(undefined);
  const ITL_TARGET_MODES = [
    { value: 'auto', label: 'Automatic', description: "Each engine is held to three times its own time per token at low load (one or two requests running), learned by every gateway replica as it goes, and learned again when the engine restarts. Until an engine has run at low load there is no target." },
    { value: 'fixed', label: 'Fixed', description: 'The figure set below, for every engine of this server.' },
    { value: 'off', label: 'Off', description: "No target: the limit grows as far as the engine's memory holds — the most work, each request slower, and the history of paused agent sessions evicted as more requests run." },
  ];
  const CAPACITY_MODES = [
    { value: 'learned', label: 'Learned from the engine', description: "Each gateway replica finds the limit on its own from the engine's /metrics (vLLM): it grows while the engine's memory has room, each running request counted at the size requests reach by their end, and is cut when the engine preempts or fills its cache." },
    { value: 'fixed', label: 'Fixed', description: 'The limits set below, whatever the engine is doing.' },
  ];
  let schedError = $state('');
  let savingSched = $state(false);
  let gatewayReplicas = $state<number | null>(null);

  $effect(() => {
    if (server && schedSeededId !== server.id) {
      schedSeededId = server.id;
      schedMode = qosModeOf(server);
      schedPriority = server.scheduling_dialect === 'vllm_priority';
      schedMaxInFlight = server.max_in_flight ?? undefined;
      schedWaiting = server.waiting_threshold ?? undefined;
      schedEngineMetrics = server.engine_metrics;
      schedCapacity = server.adaptive_concurrency ? 'learned' : 'fixed';
      schedItlMode = server.adaptive_itl_target.type;
      schedItlTarget = server.adaptive_itl_target.type === 'fixed' ? server.adaptive_itl_target.ms : undefined;
      probe = null;
      void loadReplicas();
    }
  });

  /** What the automatic token-latency target is now — the slowest engine's —
   *  read with the server (so a reload after a save brings it); `null` while
   *  learning. */
  const autoItlTarget = $derived(server?.auto_itl_target_ms ?? null);
  const isVllm = $derived(server?.vllm_engine ?? false);

  async function loadReplicas() {
    const { data } = await adminApi.GET('/api/v1/admin/qos-classes/deployment-limits', {});
    gatewayReplicas = data?.gateway_replicas ?? null;
  }

  /** Endpoints with limits of their own, which gate whatever the server says. */
  // Every endpoint with limits of its own — a disabled one's come back when it
  // is enabled — and, of those, the enabled ones, which gate now.
  const endpointOverrides = $derived(endpoints.filter((e) => e.max_in_flight != null || e.waiting_threshold != null));
  const activeOverrides = $derived(endpointOverrides.filter((e) => e.enabled));

  /** A queue bound — the server's, or an endpoint's own — cannot apply unread,
   *  so it keeps the reading on. */
  const learned = $derived(schedMode === 'gateway' && schedCapacity === 'learned');
  const metricsForced = $derived(
    learned ||
      (schedMode === 'gateway' && (schedWaiting !== undefined || activeOverrides.some((e) => e.waiting_threshold != null))),
  );

  async function saveScheduling() {
    const fields = fieldsForMode(schedMode, {
      max_in_flight: schedMaxInFlight ?? null,
      waiting_threshold: schedWaiting ?? null,
      engine_priority: schedPriority,
      adaptive: schedCapacity === 'learned',
      endpoint_bounds: activeOverrides.length > 0,
      endpoint_queue_bounds: endpointOverrides.some((e) => e.waiting_threshold != null),
    });
    if ('error' in fields) {
      schedError = fields.error;
      return;
    }
    // Refused here rather than bent into range: a 0 meant as "no target" must
    // not be saved as a 1 ms target that holds every engine at one request.
    if (learned && schedItlMode === 'fixed' && (schedItlTarget == null || schedItlTarget < 1 || schedItlTarget > 60000)) {
      schedError = 'A fixed token latency target is between 1 and 60 000 ms; choose Off for no target.';
      return;
    }
    schedError = '';
    savingSched = true;
    // One write: a mode that holds nothing also clears every endpoint's own
    // bounds, in the same transaction server-side. What the switch showed is
    // what is stored — shown on because a queue bound forces it, it stays on
    // once the bound is removed.
    const { error } = await adminApi.PATCH('/api/v1/admin/servers/{id}', {
      params: { path: { id } },
      body: {
        ...fields,
        engine_metrics: schedEngineMetrics || metricsForced,
        // Only while the limit is learned, where the picker shows: a hidden
        // control must neither refuse the save nor change what is stored.
        // Whole milliseconds: the field is an integer, and a typed fraction
        // must not fail the whole save.
        ...(learned
          ? {
              adaptive_itl_target:
                schedItlMode === 'fixed' && schedItlTarget != null
                  ? { type: 'fixed' as const, ms: Math.round(schedItlTarget) }
                  : { type: schedItlMode === 'off' ? ('off' as const) : ('auto' as const) },
            }
          : {}),
        clear_endpoint_bounds: schedMode !== 'gateway',
        force: true,
      },
    });
    savingSched = false;
    if (error) {
      schedError = extractError(error, 'Failed to save the QoS settings');
      return;
    }
    toast.success('QoS settings saved');
    schedSeededId = '';
    await load(id);
  }

  // --- Engine probe ---------------------------------------------------------
  let probe = $state<Probe | null>(null);
  /** Engines the probe has seen queueing, each with its own suggestion. */
  const probeSuggestions = $derived((probe?.endpoints ?? []).filter((p) => p.suggested_max_in_flight != null));
  /** The engines run different numbers at once while queueing (another GPU,
   *  other engine settings): one server-wide limit would hold the bigger to
   *  the smaller's batch, so limits are suggested per endpoint. */
  const probeEnginesDiffer = $derived(new Set(probeSuggestions.map((p) => p.suggested_max_in_flight)).size > 1);
  let probing = $state(false);

  async function runProbe() {
    probing = true;
    const { data, error } = await adminApi.POST('/api/v1/admin/servers/{id}/actions/probe-engine', {
      params: { path: { id } },
    });
    probing = false;
    if (error || !data) {
      toast.error('Could not probe the engines', { body: extractError(error) });
      return;
    }
    probe = data;
    gatewayReplicas = data.gateway_replicas;
  }

  // --- Add endpoint ---------------------------------------------------------
  let addOpen = $state(false);
  let addUrl = $state('');
  let addWeight = $state<number | undefined>(1);
  let addForce = $state(false);
  let adding = $state(false);
  let addError = $state('');
  let preview = $state<Preview | null>(null);
  let previewing = $state(false);

  function openAdd() {
    addUrl = '';
    addWeight = 1;
    addForce = false;
    addError = '';
    preview = null;
    addOpen = true;
  }

  async function discover() {
    previewing = true;
    preview = null;
    const { data, error } = await adminApi.POST('/api/v1/admin/servers/{id}/endpoints/actions/discover', {
      params: { path: { id } },
      body: { url: addUrl.trim() },
    });
    previewing = false;
    if (error || !data) {
      addError = extractError(error, 'Discovery failed');
      return;
    }
    addError = '';
    preview = data;
  }

  async function saveAdd() {
    adding = true;
    const { error } = await adminApi.POST('/api/v1/admin/servers/{id}/endpoints', {
      params: { path: { id } },
      body: { url: addUrl.trim(), weight: addWeight ?? 1, force: addForce },
    });
    adding = false;
    if (error) {
      addError = extractError(error, 'Failed to add the endpoint');
      // A URL the check objected to can still be saved on purpose.
      if (isOverridableUpstreamError(extractErrorCode(error))) addForce = true;
      return;
    }
    addOpen = false;
    toast.success('Endpoint added');
    await load(id);
  }

  // --- Per-endpoint actions ---------------------------------------------------
  let busyId = $state<string | null>(null);

  async function setEnabled(e: Endpoint, enabled: boolean) {
    busyId = e.id;
    const { error } = await adminApi.PATCH('/api/v1/admin/servers/{id}/endpoints/{endpoint_id}', {
      params: { path: { id, endpoint_id: e.id } },
      body: { enabled },
    });
    busyId = null;
    if (error) {
      toast.error(enabled ? 'Failed to enable the endpoint' : 'Failed to disable the endpoint', { body: extractError(error) });
      return;
    }
    await load(id);
  }

  async function move(e: Endpoint, delta: -1 | 1) {
    const order = moveEndpoint(endpoints.map((x) => x.id), e.id, delta);
    if (!order) return;
    busyId = e.id;
    const { error } = await adminApi.POST('/api/v1/admin/servers/{id}/endpoints/actions/reorder', {
      params: { path: { id } },
      body: { endpoint_ids: order },
    });
    busyId = null;
    if (error) {
      toast.error('Failed to reorder the endpoints', { body: extractError(error) });
      return;
    }
    await load(id);
  }

  let editing = $state<Endpoint | null>(null);
  let editUrl = $state('');
  let editWeight = $state<number | undefined>(1);
  let editMaxInFlight = $state<number | undefined>(undefined);
  let editWaiting = $state<number | undefined>(undefined);
  let editError = $state('');
  let editForce = $state(false);
  let saving = $state(false);

  /** Open an endpoint's editor; `suggestedInFlight` pre-fills its limit with
   *  the probe's suggestion for that engine, to review before saving. */
  function openEdit(e: Endpoint, suggestedInFlight?: number) {
    editing = e;
    editUrl = e.url;
    editWeight = e.weight;
    editMaxInFlight = suggestedInFlight ?? e.max_in_flight ?? undefined;
    editWaiting = e.waiting_threshold ?? undefined;
    editError = '';
    editForce = false;
  }

  async function saveEdit() {
    if (!editing) return;
    saving = true;
    const changedUrl = editUrl.trim() !== editing.url;
    const { error } = await adminApi.PATCH('/api/v1/admin/servers/{id}/endpoints/{endpoint_id}', {
      params: { path: { id, endpoint_id: editing.id } },
      // Only what changed: an unnamed field is left as stored, so an edit
      // opened before another save cannot write back a stale limit.
      body: {
        url: changedUrl ? editUrl.trim() : undefined,
        weight: editWeight,
        max_in_flight: (editMaxInFlight ?? null) !== (editing.max_in_flight ?? null) ? (editMaxInFlight ?? null) : undefined,
        waiting_threshold:
          (editWaiting ?? null) !== (editing.waiting_threshold ?? null) ? (editWaiting ?? null) : undefined,
        force: editForce,
      },
    });
    saving = false;
    if (error) {
      editError = extractError(error, 'Failed to save the endpoint');
      // A URL the check objected to can still be saved on purpose.
      if (isOverridableUpstreamError(extractErrorCode(error))) editForce = true;
      return;
    }
    editing = null;
    await load(id);
  }

  let removing = $state<{ endpoint: Endpoint; message: string } | null>(null);

  async function askRemove(e: Endpoint) {
    busyId = e.id;
    const { data, error } = await adminApi.DELETE('/api/v1/admin/servers/{id}/endpoints/{endpoint_id}', {
      params: { path: { id, endpoint_id: e.id }, query: { dry_run: true } },
    });
    busyId = null;
    if (error || !data) {
      toast.error('Cannot remove the endpoint', { body: extractError(error) });
      return;
    }
    removing = { endpoint: e, message: removalSummary(data, e.url) };
  }

  async function confirmRemove() {
    if (!removing) return;
    const e = removing.endpoint;
    removing = null;
    busyId = e.id;
    const { data, error } = await adminApi.DELETE('/api/v1/admin/servers/{id}/endpoints/{endpoint_id}', {
      params: { path: { id, endpoint_id: e.id } },
    });
    busyId = null;
    if (error || !data) {
      toast.error('Failed to remove the endpoint', { body: extractError(error) });
      return;
    }
    toast.success(
      'Endpoint removed',
      data.retired_models.length ? `Retired: ${data.retired_models.join(', ')}` : undefined,
    );
    await load(id);
  }
</script>

{#if loading}
  <div class="p-8 text-sm text-(--text-secondary)">Loading…</div>
{:else if loadError || !server}
  <div class="p-8">
    <EmptyState title="Server not available" body={loadError || 'This server does not exist.'} />
  </div>
{:else}
  {@const srv = server}
  <TabbedPage
    title={srv.name}
    subtitle={`${srv.provider} · ${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'} · ${srv.model_count} model${srv.model_count === 1 ? '' : 's'}`}
    tabs={[
      { id: 'server', label: 'Server' },
      { id: 'endpoints', label: 'Endpoints' },
      { id: 'models', label: 'Models' },
      { id: 'scheduling', label: 'QoS' },
    ]}
    activeTab={tab.current}
    onTabChange={(t) => (tab.current = t)}
  >
    {#snippet actions()}
      <!-- This page configures the server; its load, latency and scheduling
           live on its dashboard. -->
      <a href={thref(slug, `/dashboard/servers/${id}`)} class="text-sm text-(--accent) hover:text-(--accent-hover) inline-flex items-center gap-1" data-server-dashboard-link>
        <Icon name="edge" size="sm" color="currentColor" /> View dashboard
      </a>
      <a href={thref(slug, '/gateways/llm')} class="text-sm text-(--accent) hover:text-(--accent-hover) inline-flex items-center gap-1">
        <Icon name="arrowLeft" size="sm" color="currentColor" /> LLM gateway
      </a>
    {/snippet}

    <!-- Health rides above the tabs: configuring a server and knowing whether
         it is answering are the same visit, so neither costs the other. -->
    {#snippet filterBar()}
      {#if endpoints.length > 0 && downCount === endpoints.filter((e) => e.enabled).length}
        <!-- Above the tabs, not on one: a server with nothing left in rotation
             is the whole page's news, and which tab it is read from must not
             decide whether it is seen at all. -->
        <div class="mb-4">
          <Callout severity="error" title="Every enabled endpoint is out of rotation">
            A connected gateway's breaker is open for every enabled endpoint. Requests for this server's
            models fail over to other route targets, or fail.
          </Callout>
        </div>
      {/if}
      <MetricGrid class="mb-6" data-testid="server-health">
        <MetricCard label="Endpoints healthy" value={`${healthyCount}/${endpoints.length}`} icon="reliability" subtitle="enabled, breaker closed" />
        <MetricCard label="Breaker open" value={downCount} icon="errorCircle" iconTone={downCount > 0 ? 'error' : 'neutral'} subtitle="on a connected gateway" />
        <MetricCard label="Models" value={srv.model_count} icon="cube" subtitle="fused across endpoints" />
        <!-- Value, colour and subtitle all read ONE answer, so the tile cannot
             contradict the panel below it. The icon is category identity and
             never moves; `valueColor` is the data-driven channel. -->
        <MetricCard
          label="Last sync"
          value={lastSync ? (lastSync.age ?? '--') : 'never'}
          icon="refresh"
          valueColor={lastSync && !lastSync.ok ? 'var(--error-text)' : 'var(--text-primary)'}
          subtitle={lastSync && !lastSync.ok ? 'last run failed' : srv.auto_sync_enabled ? 'auto-sync on' : 'auto-sync off'}
        />
      </MetricGrid>
    {/snippet}

    {#snippet children(active)}
      {#if active === 'server'}
        <div class="space-y-4 max-w-2xl" data-testid="server-settings">
          <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-4">
            <div class="flex items-center gap-2">
              <ProviderIcon name={srv.provider} size="lg" className="text-(--text-secondary)" />
              <h3 class="text-sm font-semibold text-(--text-primary)">{providerLabel}</h3>
              {#if srv.byok}
                <ByokBadge title="BYOK pass-through — keyless upstream; the client forwards its own credential." />
              {:else if srv.has_credential}
                <TagBadge color="teal" title="A credential is stored for this server">Credential set</TagBadge>
              {:else}
                <TagBadge color="amber" title="No credential is stored — requests go out unauthenticated">No credential</TagBadge>
              {/if}
              {#if !srv.enabled}<TagBadge color="neutral">Disabled</TagBadge>{/if}
            </div>

            <FormField label="Name" for="srv-name">
              <TextInput id="srv-name" bind:value={form.name} disabled={savingSettings} />
            </FormField>

            <FormField label="Provider" for="srv-provider">
              <SelectInput id="srv-provider" value={form.provider} disabled={savingSettings} onchange={(e) => pickProvider((e.currentTarget as HTMLSelectElement).value)}>
                {#each PROVIDER_DEFAULTS as p (p.value)}<option value={p.value}>{p.label}</option>{/each}
              </SelectInput>
            </FormField>

            {#if addressIsEndpoints}
              <!-- Replicas make "the server's URL" meaningless: the addresses
                   are the endpoints, and the primary is simply the first. -->
              <FormField label="Address">
                <div class="flex items-baseline gap-2 flex-wrap px-2.5 py-1.5 rounded-lg border border-(--border) bg-(--bg-primary)/50">
                  <span class="font-mono text-xs text-(--text-primary) break-all">{primaryUrl || '—'}</span>
                  <TagBadge color="blue">Primary</TagBadge>
                  <button
                    onclick={() => (tab.current = 'endpoints')}
                    class="ml-auto text-xs font-medium text-(--accent) hover:text-(--accent-hover)"
                    data-testid="to-endpoints"
                  >{endpoints.length} endpoint{endpoints.length === 1 ? '' : 's'} →</button>
                </div>
              </FormField>
              {#if providerLeftAddressBehind}
                <Callout severity="warning" title="The address still points at the old provider">
                  This server answers at <span class="font-mono">{primaryUrl}</span>, which the provider
                  change does not move — the addresses belong to the endpoints. Saving will send
                  {providerLabel} requests there. Change it on the Endpoints tab, or add the new provider
                  as its own server.
                </Callout>
              {/if}
            {:else}
              <FormField
                label="Address"
                for="srv-url"
                help="This server's single endpoint. A transport that owns its URL, or a keyless pass-through, has no replicas."
              >
                <TextInput id="srv-url" bind:value={form.upstream_url} mono disabled={savingSettings} placeholder={urlIsRequired ? 'e.g. http://vllm:8000' : 'provider default'} />
              </FormField>
            {/if}

            {#if !srv.byok}
              <FormField
                label={form.transport === 'azure_openai_entra' ? 'Entra credential' : 'API key'}
                for="srv-key"
                help="Write-only. Leave empty to keep the stored credential; type a new one to rotate it."
              >
                <TextInput id="srv-key" bind:value={form.api_key} type="password" disabled={savingSettings} placeholder="Leave empty to keep the current one" />
              </FormField>
            {/if}

            <FormField label="Transport" for="srv-transport">
              <SelectInput id="srv-transport" value={form.transport} disabled={savingSettings} onchange={(e) => pickTransport((e.currentTarget as HTMLSelectElement).value)}>
                {#each UPSTREAM_TRANSPORTS as t (t.value)}<option value={t.value}>{t.label}</option>{/each}
              </SelectInput>
              <TransportHelp transport={form.transport} />
            </FormField>

            <FormField label="Upstream protocol" for="srv-format" help="The wire this server speaks natively. The gateway translates every client protocol onto it.">
              <SelectInput id="srv-format" bind:value={form.upstream_api_format} disabled={savingSettings}>
                {#each API_FORMATS as f (f.value)}<option value={f.value}>{f.label}</option>{/each}
              </SelectInput>
            </FormField>

            {#if !ownsUrl}
              <FormField
                label="Chat endpoint path"
                for="srv-path"
                help="Appended to the address for OpenAI-compatible chat requests. Blank uses the provider default (usually /v1/chat/completions)."
              >
                <TextInput id="srv-path" bind:value={form.chat_endpoint_path} mono disabled={savingSettings} placeholder="/v1/chat/completions" />
              </FormField>
            {/if}

            {#if settingsError}
              <UpstreamWriteError
                message={settingsError}
                code={settingsErrorCode}
                retryLabel="Save anyway"
                busy={savingSettings}
                onretry={() => saveSettings({ force: true })}
              />
            {/if}

            <button
              onclick={() => saveSettings()}
              disabled={savingSettings || !settingsDirty || !form.name.trim() || addressMissing}
              data-testid="save-server"
              class="px-4 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
            >{savingSettings ? 'Saving…' : settingsDirty ? 'Save server' : 'Saved'}</button>
          </div>

          <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-3">
            <h3 class="text-sm font-semibold text-(--text-primary)">Model discovery</h3>
            {#if srv.byok}
              <p class="text-xs text-(--text-secondary)">A keyless pass-through has no credential to ask with, so its models are never discovered.</p>
            {:else if !discoverable}
              <p class="text-xs text-(--text-secondary)">
                {#if !providerPublishesModelList(srv.provider)}
                  {savedProviderLabel} serves no model list the gateway can read.
                {:else}
                  A {UPSTREAM_TRANSPORTS.find((t) => t.value === srv.transport)?.label ?? srv.transport} endpoint
                  serves no model list the gateway can read.
                {/if}
                Add this server's models by name on the LLM gateway page.
              </p>
            {:else}
              <ToggleSetting
                label="Auto-sync models"
                description="Periodically re-discover this server's models and keep a same-named mirror downstream in sync. Off makes it a manual server — no discovery, and you build the downstream yourself."
                bind:value={autoSync}
                saving={savingAutoSync}
                onValueChange={saveAutoSync}
              />
              {#if lastSync && !lastSync.ok}
                <Callout severity="error" title="The last discovery run failed">
                  {lastSync.detail}. This server serves whatever models it already had; nothing new was
                  imported. Fix the cause and run a sync from the LLM gateway page.
                </Callout>
              {/if}
              <p class="text-xs text-(--text-secondary)" data-testid="server-last-sync">
                Last run: {lastSync ? lastSync.label : 'never'}.
                Review or force a run from the LLM gateway page.
              </p>
            {/if}
          </div>

          {#if !srv.is_builtin}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-3">
            <h3 class="text-sm font-semibold text-(--text-primary)">Delete this server</h3>
            <p class="text-xs text-(--text-secondary)">
              Removes the server, its {endpoints.length} endpoint{endpoints.length === 1 ? '' : 's'} and its
              {srv.model_count} model{srv.model_count === 1 ? '' : 's'}. Downstream routes pointing at them are
              left orphaned and have to be cleaned up.
              {#if srv.byok}
                It is a pass-through: its provider, its model overrides and its workspace grants go with it,
                and every key bound to it is revoked.
              {/if}
            </p>
            <button
              onclick={() => (deleteOpen = true)}
              disabled={deleting}
              data-testid="delete-server"
              class="px-4 py-1.5 text-sm font-medium rounded-lg border border-(--error-border) text-(--error-text) hover:bg-(--error)/10 transition-colors disabled:opacity-50"
            >{deleting ? 'Deleting…' : 'Delete server'}</button>
          </div>
          {/if}
        </div>
      {:else if active === 'endpoints'}
        <div class="space-y-4">
        {#if missingReports > 0}
          <Callout severity="warning" title="An endpoint answered “model not found”">
            An endpoint refused a model it was expected to serve; those requests moved to another endpoint. The next discovery answer from that endpoint settles what it serves.
          </Callout>
        {/if}
        {#if assumedEndpoints.length > 0}
          <Callout severity="info" title="{assumedEndpoints.length} endpoint{assumedEndpoints.length === 1 ? ' has' : 's have'} not listed its models">
            Until discovery answers from an endpoint, it is assumed to serve every model of this server. Replicas that serve different models need endpoints that answer the model list.
          </Callout>
        {/if}
        <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
          <div class="px-5 py-3 flex items-center gap-3 border-b border-(--border)">
            <h3 class="text-sm font-semibold text-(--text-primary)">Endpoints</h3>
            <HelpTooltip body="Replicas of one engine behind this server, sharing its credential and protocol. A conversation stays on one replica; it moves only when that replica fails or its breaker is open." />
            {#if canReplicate}
              <button onclick={openAdd} class="ml-auto text-xs font-medium text-(--accent) hover:text-(--accent-hover)" data-testid="add-endpoint">+ Add endpoint</button>
            {:else}
              <span class="ml-auto text-xs text-(--text-secondary)">
                {srv.byok ? 'A pass-through server has one endpoint.' : 'Only a server on the default transport has replicas.'}
              </span>
            {/if}
          </div>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b border-(--border) bg-(--bg-primary)/50">
                  <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Order</th>
                  <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Status</th>
                  <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">URL</th>
                  <th class="px-4 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Weight</th>
                  <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Models</th>
                  <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Last discovery</th>
                  <th class="px-4 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each endpoints as e, i (e.id)}
                  {@const status = endpointStatus(e)}
                  <tr class="border-b border-(--border)" data-endpoint-row={e.url}>
                    <td class="px-4 py-2 whitespace-nowrap">
                      <button onclick={() => move(e, -1)} disabled={i === 0 || busyId !== null} aria-label="Move up" class="disabled:opacity-30"><Icon name="chevronUp" size="sm" tone="neutral" /></button>
                      <button onclick={() => move(e, 1)} disabled={i === endpoints.length - 1 || busyId !== null} aria-label="Move down" class="disabled:opacity-30"><Icon name="chevronDown" size="sm" tone="neutral" /></button>
                    </td>
                    <td class="px-4 py-2">
                      <StatusChip
                        {...ENDPOINT_STATUS[status]}
                        {status}
                        title={status === 'breaker_open'
                          ? `Out of rotation on ${e.health.down_gateways} gateway(s) since ${formatTimeAgo(e.health.down_since)}${e.health.reason ? ` — ${e.health.reason}` : ''}`
                          : status === 'discovery_failed'
                            ? (e.last_discovery?.reason ?? undefined)
                            : undefined}
                      />
                    </td>
                    <td class="px-4 py-2">
                      <Copyable value={e.url} />
                      {#if e.primary}
                        <TagBadge color="blue" class="ml-1" title="The first enabled endpoint: its URL is the server's URL">Primary</TagBadge>
                      {/if}
                    </td>
                    <td class="px-4 py-2 text-right font-mono text-xs">{e.weight}</td>
                    <td class="px-4 py-2 text-xs text-(--text-secondary)">
                      {#if e.membership === 'assumed'}
                        <span title="Discovery has not answered from this endpoint; it is assumed to serve every model of the server">all (assumed)</span>
                      {:else}
                        {e.model_count} listed
                      {/if}
                      {#if e.mismatched_models > 0}
                        <TagBadge color="amber" class="ml-1" title="Answered “model not found” since its last discovery">{e.mismatched_models} missing</TagBadge>
                      {/if}
                    </td>
                    <td class="px-4 py-2 text-xs text-(--text-secondary)">
                      {#if e.last_discovery_at}
                        {formatTimeAgo(e.last_discovery_at)} ·
                        {#if e.last_discovery?.ok}
                          {e.last_discovery.listed ?? 0} listed{#if e.last_discovery.kept} (omitted ones kept: {e.last_discovery.kept.replaceAll('_', ' ')}){/if}
                        {:else}
                          <span class="text-(--warning-text)">{e.last_discovery?.reason ?? 'no answer'}</span>
                        {/if}
                      {:else}
                        —
                      {/if}
                    </td>
                    <td class="px-4 py-2 text-right whitespace-nowrap">
                      <div class="flex items-center justify-end gap-3">
                        <button onclick={() => setEnabled(e, !e.enabled)} disabled={busyId !== null} class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) disabled:opacity-50">{e.enabled ? 'Disable' : 'Enable'}</button>
                        {#if canReplicate}
                          <button onclick={() => openEdit(e)} disabled={busyId !== null} class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) disabled:opacity-50">Edit</button>
                          <button onclick={() => askRemove(e)} disabled={busyId !== null || endpoints.length === 1} class="text-xs font-medium text-(--error) disabled:opacity-50">Remove</button>
                        {/if}
                      </div>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        </div>
        </div>
      {:else if active === 'models'}
        <div class="space-y-4">
          {#if mismatchedModels.length > 0}
            <Callout severity="warning" title="Replicas disagree about {mismatchedModels.length} model{mismatchedModels.length === 1 ? '' : 's'}">
              Endpoints report different context windows or serve different weights under one name ({mismatchedModels.map((m) => m.upstream_model).join(', ')}). The smallest window is advertised; check the replicas run the same model.
            </Callout>
          {/if}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
            {#if membership && membership.models.length > 0}
              <MembershipMatrix {membership} />
            {:else}
              <EmptyState title="No models yet" body="Sync the server, or add its models by hand on the LLM gateway page." compact />
            {/if}
          </div>
        </div>
      {:else if active === 'scheduling'}
        <div class="space-y-4 max-w-3xl" data-qos-tab>
          <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-4">
            <div>
              <h3 class="text-sm font-semibold text-(--text-primary)">Under load</h3>
              <p class="text-xs text-(--text-secondary) mt-1">
                What happens to requests when this server's engines are full. Priority classes
                (Settings → Priority) only change anything here while requests wait.
              </p>
              <p class="text-xs text-(--text-tertiary) mt-2">
                Terms: an <strong>engine</strong> is one inference process (a vLLM instance); an
                <strong>endpoint</strong> is the URL of one engine; this <strong>server</strong> groups
                the endpoints that share a credential; the <strong>gateway</strong> is Streamscope,
                which may run as several replicas.
              </p>
            </div>
            <ScopePicker label="Mode" options={QOS_MODES} bind:value={schedMode} />

            {#if schedMode === 'engine_priority'}
              <Callout severity="warning" title="Start the engine for it">
                Every engine must run with <span class="font-mono">--scheduling-policy priority</span>;
                otherwise vLLM ignores the priority. vLLM only reorders what is still waiting — it never
                interrupts a request already running.
              </Callout>
            {:else if schedMode === 'gateway'}
              <ScopePicker label="In-flight limit" options={CAPACITY_MODES} bind:value={schedCapacity} />
              {#if learned}
                <ScopePicker label="Token latency target" options={ITL_TARGET_MODES} bind:value={schedItlMode} />
                {#if schedItlMode === 'fixed'}
                  <FormField
                    label="Target"
                    for="sched-itl-target"
                    help="The engine's time between two output tokens of a request, in milliseconds. While it is above this, the limit does not grow, and it steps down while it stays above it: fewer requests run, and each generates faster. Needs the engine to publish its time between tokens (vLLM does); without it the target does nothing."
                  >
                    <NumberInput id="sched-itl-target" bind:value={schedItlTarget} min={1} max={60000} step={1} placeholder="ms" />
                  </FormField>
                {/if}
                {#if schedItlMode === 'auto'}
                <p class="text-xs text-(--text-secondary)" data-qos-auto-itl>
                  {#if autoItlTarget != null}
                    The automatic target is <strong>{formatDuration(autoItlTarget)}</strong> now (the slowest engine's; each
                    engine is held to its own). A target keeps paused agent sessions' history cached and turns fast.
                  {:else}
                    The automatic target is still learning: no engine has yet run one or two requests long enough to teach
                    its time per token (since it, or the gateway, last started), and an engine that does not publish its
                    time between tokens (vLLM does) never will. Until then it holds nothing.
                  {/if}
                </p>
                {/if}
                <FormField
                  label="Ceiling per engine (optional)"
                  for="sched-inflight"
                  help="The learned limit never goes above this. While an engine's metrics are not heard, the last learned limit applies, within this ceiling; an engine never heard is held only to the ceiling. Empty: no ceiling. Counted by each gateway replica."
                >
                  <NumberInput id="sched-inflight" bind:value={schedMaxInFlight} min={1} placeholder="no ceiling" />
                </FormField>
              {:else}
              <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                <FormField
                  label="Requests in flight per engine"
                  for="sched-inflight"
                  help={gatewayReplicas && gatewayReplicas > 1 && schedMaxInFlight
                    ? `Counted by each gateway replica: ${gatewayReplicas} are connected, so an engine can receive up to ${gatewayReplicas * schedMaxInFlight}. Divide the engine's capacity by the replicas, or rely on the engine queue bound, which every replica reads.`
                    : "Start from what the engine sustains (the probe's suggestion); vLLM's --max-num-seqs is a cap, not a capacity. Counted by each gateway replica."}
                >
                  <NumberInput id="sched-inflight" bind:value={schedMaxInFlight} min={1} placeholder="no limit" />
                </FormField>
                <FormField
                  label="Engine queue allowed"
                  for="sched-waiting"
                  help="How many requests may wait inside the engine before the gateway stops sending more. 0 keeps every wait at the gateway, where priority applies. Read from the engine's /metrics, shared by every gateway replica."
                >
                  <NumberInput id="sched-waiting" bind:value={schedWaiting} min={0} placeholder="not read" />
                </FormField>
              </div>
              {#if probeEnginesDiffer}
                <!-- One server-wide value would hold the bigger engine to the
                     smaller one's batch: suggest per endpoint instead. -->
                <p class="text-xs text-(--text-secondary)" data-qos-engines-differ>
                  The engines are not alike: they ran {probeSuggestions.map((p) => p.observed_peak_running).join(', ')} at once
                  while queueing. Set a limit per endpoint below — each has its own suggestion — and keep this value as the
                  default for any endpoint without one.
                </p>
              {:else if probe?.suggested_max_in_flight}
                <p class="text-xs text-(--text-secondary)">
                  The engine that queues first ran {probe.observed_peak_running} at once while queueing; split across
                  {probe.gateway_replicas} gateway replica{probe.gateway_replicas === 1 ? '' : 's'}, suggest
                  <strong>{probe.suggested_max_in_flight}</strong> per replica.
                  <button class="ml-1 text-(--accent) hover:underline" onclick={() => (schedMaxInFlight = probe?.suggested_max_in_flight ?? undefined)} data-qos-use-suggestion>Use it</button>
                </p>
              {/if}
              {/if}
              <label class="flex items-start gap-2 text-sm text-(--text-primary)">
                <input type="checkbox" bind:checked={schedPriority} class="mt-1" data-qos-engine-priority />
                <span>
                  The engines run with <span class="font-mono">--scheduling-policy priority</span> — also send
                  each request's class as its vLLM priority
                  <span class="block text-xs text-(--text-secondary)">Orders the few requests the engine itself holds. Leave off for an engine started without it.</span>
                </span>
              </label>
            {/if}
            {#if isVllm && schedMode !== 'off'}
              <Callout severity="info" title="vLLM engine settings">
                <ul class="list-disc pl-4 space-y-1.5" data-qos-vllm-settings>
                  <li>
                    <span class="font-mono">--max-num-seqs</span>: make sure it never limits the engine — set it to about
                    the KV cache size (vLLM logs <em>GPU KV cache size: N tokens</em> at start-up) divided by the
                    smallest request you serve (prompt + answer, in tokens), and not far above: vLLM sizes some
                    per-request buffers by it. A cap that binds keeps requests waiting inside the engine, out of the
                    gateway's priority order.
                  </li>
                  <li>
                    <span class="font-mono">--max-num-batched-tokens</span>: the engine's token budget per step (vLLM
                    logs the value it chose at start-up). If the engine queues requests while its cache has room, this
                    budget is usually why: long prompts use it all. Higher: waiting requests start sooner, but running
                    requests generate more slowly while long prompts are computed, so a token-latency target lets fewer
                    requests run. Lower: the reverse. The best value depends on the GPU, the model and the prompts;
                    change it only after measuring your own load.
                  </li>
                  <li>
                    <span class="font-mono">--kv-offloading-size</span> (optional, suggested): a CPU KV cache tier
                    improves agent workloads — conversations evicted from GPU memory while an agent pauses are reloaded
                    from RAM instead of recomputed. It helps most with long conversations, little with short ones, and
                    uses the host RAM you give it.
                  </li>
                  {#if schedMode === 'gateway'}
                    <!-- Engine-priority mode has its own warning for it, above. -->
                    <li>
                      <span class="font-mono">--scheduling-policy priority</span>: needed to send each request's class
                      as its vLLM priority (the option above) — without it vLLM ignores the priority.
                    </li>
                  {/if}
                </ul>
              </Callout>
            {/if}
          </div>

          <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-4">
            <ToggleSetting
              label="Read engine metrics"
              description={metricsForced
                ? learned
                  ? "Required while the in-flight limit is learned: it follows the engine's /metrics."
                  : "Required while an engine queue is allowed: that bound is read from the engine's /metrics."
                : "Each gateway replica reads every endpoint's /metrics every few seconds — queue, running requests, KV cache, throughput — for the server dashboard. On by default for vLLM."}
              value={schedEngineMetrics || metricsForced}
              disabled={metricsForced}
              onValueChange={(v) => (schedEngineMetrics = v)}
            />
            <div class="flex items-center gap-3">
              <button onclick={runProbe} disabled={probing} class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-medium rounded-lg disabled:opacity-50" data-qos-probe>
                {probing ? 'Probing…' : 'Probe engines'}
              </button>
              <span class="text-xs text-(--text-secondary)">Asks every endpoint for its metrics now, as the gateways do. Nothing is saved.</span>
            </div>
            {#if probe}
              <div class="overflow-x-auto">
                <table class="w-full text-sm" data-qos-probe-result>
                  <thead>
                    <tr class="border-b border-(--border) text-xs text-(--text-secondary) uppercase tracking-wider">
                      <th class="px-3 py-2 text-left font-medium">Endpoint</th>
                      <th class="px-3 py-2 text-left font-medium">Metrics</th>
                      <th class="px-3 py-2 text-right font-medium">Waiting</th>
                      <th class="px-3 py-2 text-right font-medium">Running</th>
                      <th class="px-3 py-2 text-right font-medium">KV cache</th>
                    </tr>
                  </thead>
                  <tbody>
                    {#each probe.endpoints as p (p.endpoint_id)}
                      <tr class="border-b border-(--border) last:border-0">
                        <td class="px-3 py-2"><Copyable value={p.metrics_url} /></td>
                        <td class="px-3 py-2 text-xs">
                          {#if p.answered}
                            <span class="text-(--success-text)">vLLM answering</span>
                          {:else}
                            <span class="text-(--warning-text)">{p.reason}{p.credential_presented ? ' (credential presented)' : ''}</span>
                          {/if}
                        </td>
                        <td class="px-3 py-2 text-right font-mono">{p.waiting ?? '--'}</td>
                        <td class="px-3 py-2 text-right font-mono">{p.running ?? '--'}</td>
                        <td class="px-3 py-2 text-right font-mono text-xs">
                          {p.kv_usage != null ? formatShare(p.kv_usage, 1) : '--'}{p.kv_capacity_tokens ? ` of ${p.kv_capacity_tokens.toLocaleString()} tokens` : ''}
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {/if}
          </div>

          {#if schedMode !== 'gateway' && endpointOverrides.length > 0}
            <Callout severity="warning" title="Endpoints with limits of their own">
              {endpointOverrides.length} endpoint{endpointOverrides.length === 1 ? ' has' : 's have'} limits of
              {endpointOverrides.length === 1 ? 'its' : 'their'} own (disabled ones included), which gate whatever this
              server says. Saving this mode clears them.
            </Callout>
          {/if}
          {#if schedMode === 'gateway' && (endpoints.length > 1 || endpointOverrides.length > 0 || probeEnginesDiffer)}
            <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-3">
              <div>
                <h3 class="text-sm font-semibold text-(--text-primary)">Per endpoint</h3>
                <p class="text-xs text-(--text-secondary) mt-1">Replicas are not always identical machines: an endpoint may override the server's limits.</p>
              </div>
              <table class="w-full text-sm" data-qos-endpoint-overrides>
                <tbody>
                  {#each endpoints as e (e.id)}
                    {@const own = probe?.endpoints.find((p) => p.endpoint_id === e.id)?.suggested_max_in_flight}
                    <tr class="border-b border-(--border) last:border-0">
                      <td class="py-2 pr-3"><span class="font-mono text-xs">{e.url}</span></td>
                      <td class="py-2 px-3 text-xs text-(--text-secondary)">
                        In flight {e.max_in_flight ?? `${server?.max_in_flight ?? 'no limit'} (server)`} ·
                        engine queue {e.waiting_threshold ?? `${server?.waiting_threshold ?? 'not read'} (server)`}
                        {#if own != null && own !== (e.max_in_flight ?? server?.max_in_flight)}
                          <span class="block mt-0.5" data-qos-endpoint-suggestion>
                            Suggested {own} per gateway for this engine
                            <button class="ml-1 text-(--accent) hover:underline" onclick={() => openEdit(e, own)}>Use it</button>
                          </span>
                        {/if}
                      </td>
                      <td class="py-2 pl-3 text-right">
                        <button onclick={() => openEdit(e)} class="text-xs font-medium text-(--accent) hover:text-(--accent-hover)">Edit</button>
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          {/if}

          {#if schedError}
            <Callout severity="error" title="Could not save">{schedError}</Callout>
          {/if}
          <button
            onclick={saveScheduling}
            disabled={savingSched}
            class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
            data-testid="save-scheduling"
          >
            {savingSched ? 'Saving…' : 'Save QoS settings'}
          </button>
        </div>
      {/if}
    {/snippet}
  </TabbedPage>
{/if}

<Modal open={addOpen} title="Add endpoint" onclose={() => (addOpen = false)} maxWidth="max-w-lg">
  <div class="space-y-4">
    <FormField label="URL" for="endpoint-url">
      <TextInput id="endpoint-url" bind:value={addUrl} oninput={() => (addForce = false)} placeholder="http://vllm-2:8000" mono />
    </FormField>
    <FormField label="Weight" for="endpoint-weight" help="Relative share of new conversations. Give a larger GPU a larger weight.">
      <NumberInput id="endpoint-weight" bind:value={addWeight} min={1} max={1000} />
    </FormField>
    <button onclick={discover} disabled={previewing || !addUrl.trim()} class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) disabled:opacity-50">
      {previewing ? 'Asking…' : 'Discover — preview what it serves'}
    </button>
    {#if preview}
      {#if preview.answered}
        <div class="text-xs text-(--text-secondary) space-y-1" data-testid="discover-preview">
          <p>Lists {preview.models.length} model{preview.models.length === 1 ? '' : 's'}:</p>
          <ul class="pl-4 list-disc">
            {#each preview.models as m, i (i)}
              <li><span class="font-mono">{m.upstream_model}</span> — {m.status === 'new' ? 'new, will be added' : 'matches'}</li>
            {/each}
          </ul>
          {#if preview.not_listed.length > 0}
            <p>Does not list: <span class="font-mono">{preview.not_listed.join(', ')}</span> — those stay on the other endpoints.</p>
          {/if}
        </div>
      {:else}
        <Callout severity="info" title="Could not list models">
          {preview.reason ?? 'No answer'}. Saved anyway, it is assumed to serve every model of this server.
        </Callout>
      {/if}
    {/if}
    {#if addError}<p class="text-xs text-(--error-text)">{addError}</p>{/if}
  </div>
  {#snippet footer()}
    <button onclick={() => (addOpen = false)} class="px-4 py-2 text-sm text-(--text-secondary)">Cancel</button>
    <button onclick={saveAdd} disabled={adding || !addUrl.trim()} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">
      {adding ? 'Adding…' : addForce ? 'Save anyway' : 'Add endpoint'}
    </button>
  {/snippet}
</Modal>

<Modal open={editing !== null} title="Edit endpoint" onclose={() => (editing = null)} maxWidth="max-w-lg">
  <div class="space-y-4">
    <FormField label="URL" for="edit-endpoint-url" help="A new URL starts the endpoint over: it is assumed to serve every model until discovery answers from the new host.">
      <TextInput id="edit-endpoint-url" bind:value={editUrl} oninput={() => (editForce = false)} mono />
    </FormField>
    <FormField label="Weight" for="edit-endpoint-weight">
      <NumberInput id="edit-endpoint-weight" bind:value={editWeight} min={1} max={1000} />
    </FormField>
    <div class="grid grid-cols-2 gap-3">
      <FormField label="Requests in flight" for="edit-endpoint-inflight" help="Empty: the server's value.">
        <NumberInput id="edit-endpoint-inflight" bind:value={editMaxInFlight} min={1} placeholder={server?.max_in_flight != null ? `${server.max_in_flight} (server)` : 'server value'} />
      </FormField>
      <FormField label="Engine queue allowed" for="edit-endpoint-waiting" help="Empty: the server's value.">
        <NumberInput id="edit-endpoint-waiting" bind:value={editWaiting} min={0} placeholder={server?.waiting_threshold != null ? `${server.waiting_threshold} (server)` : 'server value'} />
      </FormField>
    </div>
    {#if editError}<p class="text-xs text-(--error-text)">{editError}</p>{/if}
  </div>
  {#snippet footer()}
    <button onclick={() => (editing = null)} class="px-4 py-2 text-sm text-(--text-secondary)">Cancel</button>
    <button onclick={saveEdit} disabled={saving || !editUrl.trim()} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">
      {saving ? 'Saving…' : editForce ? 'Save anyway' : 'Save'}
    </button>
  {/snippet}
</Modal>

<ConfirmDialog
  open={removing !== null}
  title="Remove endpoint"
  message={removing?.message ?? ''}
  confirmLabel="Remove"
  destructive
  onconfirm={confirmRemove}
  oncancel={() => (removing = null)}
/>

<ConfirmDialog
  open={deleteOpen}
  title="Delete server"
  message={`Delete ${server?.name ?? 'this server'} with its ${endpoints.length} endpoint${endpoints.length === 1 ? '' : 's'} and ${server?.model_count ?? 0} model${server?.model_count === 1 ? '' : 's'}? Downstream routes pointing at them are left orphaned.${server?.byok ? ' It is a pass-through: its provider, its model overrides and its workspace grants go with it, and every key bound to it is revoked.' : ''}`}
  confirmLabel="Delete"
  destructive
  onconfirm={deleteServer}
  oncancel={() => (deleteOpen = false)}
/>
