<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode, fetchAllPages, orphanedRoutes } from '#lib/api-helpers.js';
  import { catalogPatch } from '#lib/catalog-patch.js';
  import type { ModelResponse, ServerResponse, ModelSyncResponse, DiscoveredModel, RemovedModelInfo, CatalogEntry, DownstreamProvider, DownstreamRoute } from '#lib/api-types.js';
  import type { components } from '#lib/generated/api-types.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  // Local interfaces (not in generated types — body shapes inferred by openapi-fetch)
  const tenantSlug = $derived(params.slug);

  type RoutePolicyRow = components['schemas']['RoutePolicyRow'];
  type PresetResponse = components['schemas']['PresetResponse'];
  type CachePreset = components['schemas']['CachePreset'];
  type ClientSlot = components['schemas']['ClientSlot'];
  import { formatTokens } from '#lib/formatters.js';
  import { syncStatus } from '#lib/sync-status.js';
  import { ratesToForm, formToRates, ratesSignature, ratesAreEmpty, formatRatesInline, type Rates, type RatesForm } from '#lib/rates.js';

  /** A priced-nothing list a new catalog entry starts from. Not `null`: the
   *  catalog owns its prices outright, so its editor is never in the inheriting
   *  state a `null` map would put it in. */
  const EMPTY_RATES: Rates = { currency: 'USD', units: {} };
  import { API_FORMATS } from '#lib/constants.js';
  import {
    PROVIDERS as PROVIDER_ICONS,
    PROVIDER_DEFAULTS,
    getProvider as getProviderIcon,
  } from '#lib/generated/providers.js';
  import { canModelSync } from '#lib/server-form.js';
  import ServerWizard from '#lib/components/llm/ServerWizard.svelte';
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import Callout from '#lib/components/Callout.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import ImpactModal from '#lib/components/ImpactModal.svelte';
  import FilterInput from '#lib/components/FilterInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import ProviderIcon from '#lib/components/ProviderIcon.svelte';
  import Spinner from '#lib/components/Spinner.svelte';
  import CapabilityInheritSelect from '#lib/components/CapabilityInheritSelect.svelte';
  import RatesEditor from '#lib/components/RatesEditor.svelte';
  import { type FieldSource } from '#lib/components/SourceBadge.svelte';
  import EntityPicker, { type PickerItem } from '#lib/components/EntityPicker.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import ChipMultiSelect from '#lib/components/forms/ChipMultiSelect.svelte';
  import ByokBadge from '#lib/components/ByokBadge.svelte';
  import StatusChip from '#lib/components/StatusChip.svelte';
  import { SERVER_HEALTH, serverHealthReason } from '#lib/endpoints.js';
  import HelpTooltip from '#lib/components/HelpTooltip.svelte';
  import { usePagination, usePeriodicLoad, useTabState, type Pagination as PaginationState } from '#lib/hooks.svelte.js';
  import Pagination from '#lib/components/Pagination.svelte';
  import { pageStartFor } from '#lib/clientPaging.js';
  import { untrack } from 'svelte';
  import { useLoadView } from '#lib/loadView.svelte.js';
  import { toast } from '#lib/toast.svelte.js';

  // Tab state
  type LlmTab = 'downstream' | 'upstream' | 'passthrough';
  const LLM_TABS = ['downstream', 'upstream', 'passthrough'] as const satisfies readonly LlmTab[];
  const tab = useTabState<LlmTab>(LLM_TABS, 'upstream');
  function switchLlmTab(next: LlmTab) {
    tab.current = next;
    if (next === 'downstream') loadDownstreamProviders();
    else if (next === 'passthrough') {
      loadDownstreamProviders();
      loadConfig();
    } else if (next === 'upstream') {
      loadConfig();
      loadCatalog();
    }
  }

  // Downstream providers state
  let downstreamProviders = $state<DownstreamProvider[]>([]);
  let downstreamLoading = $state(true);
  // The skeleton on a first load or a new scope only: a refresh keeps what
  // is shown (`#lib/loadView.js`), so an auto-refresh tick never blanks it.
  const downstreamView = useLoadView(() => downstreamLoading);
  let allProviderRoutes = $state<Record<string, DownstreamRoute[]>>({});
  let collisions = $state<components['schemas']['AliasCollision'][]>([]);
  let showNewProvider = $state(false);
  let newProviderName = $state('');
  let newProviderDesc = $state('');
  let newProviderIcon = $state('');
  let creatingProvider = $state(false);
  let editingProviderId = $state<string | null>(null);
  let editProviderName = $state('');
  let editProviderDesc = $state('');
  let editProviderIcon = $state('');
  let savingProvider = $state(false);
  let showRouteModal = $state(false);
  let routeProviderId = $state<string | null>(null);
  let routeAlias = $state('');
  let routeServerId = $state('');
  let routeModel = $state('');
  let routePriority = $state(0);
  let routeWeight = $state(1);
  let routeClientCw = $state<number | undefined>(undefined);
  // Invocation preset binding ('' = the model's default preset). Capabilities,
  // window, protocol, type and healing are upstream-model truth — not editable
  // on the route, which is a pure pointer to a (model, preset) pair.
  let routePresetId = $state('');
  // Presets of the currently selected route model (loaded when the model changes).
  let routePresets = $state<PresetResponse[]>([]);
  // Response-cache preset binding ('' = the alias is uncached). The knobs live on
  // the named preset (Settings → Response cache), so the route side is one picker.
  let routeCachePresetId = $state('');
  let cachePresets = $state<CachePreset[]>([]);
  /** The tenant's priority classes, for the route modal's restriction picker. */
  let qosClasses = $state<{ id: string; name: string }[]>([]);
  /** Classes this target accepts. Empty = every class, which is the default. */
  let routeQosClassIds = $state<string[]>([]);
  // The client model slots the route fills (one route may fill both).
  let routeClientSlots = $state<ClientSlot[]>([]);
  // The slots the route held when the form opened: a save sends them only
  // when the admin changed them, so it never takes back a slot another admin
  // moved meanwhile.
  let routeClientSlotsOpened = $state<ClientSlot[]>([]);
  const CLIENT_SLOTS: { value: ClientSlot; label: string }[] = [
    { value: 'fast', label: 'Fast' },
    { value: 'plan', label: 'Plan' },
  ];
  const sameSlots = (a: ClientSlot[], b: ClientSlot[]) =>
    a.length === b.length && a.every((s) => b.includes(s));
  // Per chosen slot, the alias that holds it in this downstream today — named
  // so the admin sees what moves. Another target of the alias being edited is
  // the same alias to every client, so it is not a holder that loses anything.
  const slotHolders = $derived.by(() => {
    if (!routeProviderId) return [];
    const routes = allProviderRoutes[routeProviderId] ?? [];
    return routeClientSlots.flatMap((slot) => {
      const holder = routes.find(
        (r) => (r.client_slots ?? []).includes(slot) && r.id !== editingRouteId && r.alias !== routeAlias,
      );
      return holder ? [{ slot, alias: holder.alias }] : [];
    });
  });
  // Whether the tenant has an embedding model configured. A Semantic preset
  // without one silently degrades to word-for-word matching, and the route
  // editor is where that choice is made — so say it here, not only in Settings.
  // Observe is included: it scores by meaning too, so without an embedding model
  // it stops producing the tuning signal it exists for. Defaults to configured so
  // a slow or failed settings load never invents a warning.
  let embeddingAliasConfigured = $state(true);
  const semanticNeedsEmbedding = $derived(
    !embeddingAliasConfigured &&
      ['semantic', 'observe'].includes(
        cachePresets.find((p) => p.id === routeCachePresetId)?.mode ?? '',
      ),
  );
  // ── Model presets management (Upstream tab) ──
  let showPresetsModal = $state(false);
  let presetsModel = $state<ModelResponse | null>(null);
  let presetsList = $state<PresetResponse[]>([]);
  let presetsLoading = $state(false);
  let showPresetForm = $state(false);
  let editingPresetId = $state<string | null>(null);
  let presetName = $state('');
  let presetError = $state('');
  let savingPreset = $state(false);
  // Structured preset-form fields. Each is set-or-omit: `undefined` / empty means
  // the key is absent from the emitted native fragment (= passthrough). The
  // visible fields are chosen by the model's resolved protocol; on save they are
  // reassembled into that protocol's native partial body (formToSettings), and on
  // edit they are populated from the stored settings (settingsToForm) with any
  // unrecognized keys surfaced in the Advanced raw editor.
  type PresetProtocol = 'chat_completions' | 'responses' | 'anthropic_messages' | 'google_gemini';
  let pTemperature = $state<number | undefined>(undefined);
  let pTopP = $state<number | undefined>(undefined);
  let pTopK = $state<number | undefined>(undefined); // chat_completions / anthropic / gemini
  let pMinP = $state<number | undefined>(undefined); // chat_completions (vLLM/Ollama sampling)
  let pSeed = $state<number | undefined>(undefined); // chat_completions
  let pFreqPenalty = $state<number | undefined>(undefined);
  let pPresPenalty = $state<number | undefined>(undefined);
  let pMaxTokens = $state<number | undefined>(undefined);
  let pStop = $state(''); // comma-separated → stop / stop_sequences / stopSequences
  let pReasoning = $state(''); // '' | low | medium | high (chat_completions + responses)
  let pThinking = $state(''); // '' (inherit) | enabled | adaptive | disabled (anthropic)
  let pThinkingBudget = $state<number | undefined>(undefined);
  let pIncludeThoughts = $state(false); // gemini thinkingConfig.includeThoughts
  let pAdvanced = $state(''); // raw JSON for native extras / unrecognized keys
  let pAdvancedOpen = $state(false);
  // Comma-separated; parsed into a string[] at save time.
  let routeTags = $state('');
  let routeDefaultForTags = $state('');
  let savingRoute = $state(false);
  let editingRouteId = $state<string | null>(null);
  let providerError = $state('');
  let routeError = $state('');
  // Set when a save hits a default-tag conflict: the backend's message naming
  // the route that currently owns the default. Shown with a confirm to reassign.
  let routeConflictMsg = $state('');

  // Impact modal state
  let impactModal = $state<{ open: boolean; title: string; message: string; affectedKeys: number; affectedUsers: number; confirmLabel: string; onconfirm: () => void }>({
    open: false, title: '', message: '', affectedKeys: 0, affectedUsers: 0, confirmLabel: 'Delete', onconfirm: () => {},
  });

  // Passthrough route policies state
  let passthroughPolicies = $state<Record<string, RoutePolicyRow[]>>({});
  let passthroughExpanded = $state<Set<string>>(new Set());
  let passthroughLoading = $state<Record<string, boolean>>({});
  let passthroughNewPath = $state<Record<string, string>>({});
  let passthroughShowAdd = $state<Set<string>>(new Set());
  let passthroughError = $state<Record<string, string>>({});

  // Filter state
  let downstreamFilter = $state('');
  let upstreamFilter = $state('');

  // Pass-through (BYOK) providers live on their own tab, on or off; the
  // Downstream and Upstream tabs list only the key-managed entries.
  let visibleDownstreamProviders = $derived(downstreamProviders.filter((p) => !p.byok));
  let passthroughProviders = $derived(downstreamProviders.filter((p) => p.byok));

  // Downstream: filter providers by name/description/route alias/upstream model
  let filteredDownstreamProviders = $derived.by(() => {
    const q = downstreamFilter.toLowerCase().trim();
    if (!q) return visibleDownstreamProviders;
    return visibleDownstreamProviders.filter((p) => {
      if (p.name.toLowerCase().includes(q) || (p.description ?? '').toLowerCase().includes(q)) return true;
      const routes = allProviderRoutes[p.id] ?? [];
      return routes.some((r) => (r.alias ?? '').toLowerCase().includes(q) || (r.upstream_model ?? '').toLowerCase().includes(q));
    });
  });
  let downstreamFilterInfo = $derived.by(() => {
    const q = downstreamFilter.trim();
    if (!q) return '';
    const shown = filteredDownstreamProviders.length;
    const total = visibleDownstreamProviders.length;
    return `${shown} of ${total} provider${total !== 1 ? 's' : ''}`;
  });

  // Upstream: the operator's own servers; pass-through servers are on the
  // Pass-through tab.
  let orderedServers = $derived.by(() => servers.filter((s) => !s.byok));

  // Upstream: filter servers and models by name/provider/model. The query as
  // every upstream list matches it — and the scope a list's page is kept under.
  let upstreamQuery = $derived(upstreamFilter.toLowerCase().trim());
  let filteredServers = $derived.by(() => {
    const q = upstreamQuery;
    if (!q) return orderedServers;
    return orderedServers.filter((s) => {
      if (s.name.toLowerCase().includes(q) || s.provider.toLowerCase().includes(q)) return true;
      const models = allModels.filter((m) => m.server_id === s.id);
      return models.some((m) => m.upstream_model.toLowerCase().includes(q) || (m.model_type ?? '').toLowerCase().includes(q));
    });
  });
  let upstreamFilterInfo = $derived.by(() => {
    const q = upstreamFilter.trim().toLowerCase();
    if (!q) return '';
    const shown = filteredServers.length;
    const total = orderedServers.length;
    const matchingModels = allModels.filter((m) => m.upstream_model.toLowerCase().includes(q) || (m.model_type ?? '').toLowerCase().includes(q)).length;
    const catalogMatches = filteredCatalog.length;
    const parts = [`${shown} of ${total} server${total !== 1 ? 's' : ''}`];
    if (matchingModels > 0) parts.push(`${matchingModels} model${matchingModels !== 1 ? 's' : ''}`);
    if (catalogMatches > 0 && catalogMatches < catalog.length) parts.push(`${catalogMatches} catalog`);
    return parts.join(', ');
  });
  function modelMatchesUpstreamFilter(model: ModelResponse): boolean {
    const q = upstreamQuery;
    if (!q) return true;
    return model.upstream_model.toLowerCase().includes(q) || (model.model_type ?? '').toLowerCase().includes(q);
  }
  function routeMatchesDownstreamFilter(route: DownstreamRoute): boolean {
    const q = downstreamFilter.toLowerCase().trim();
    if (!q) return true;
    return (route.alias ?? '').toLowerCase().includes(q) || (route.upstream_model ?? '').toLowerCase().includes(q);
  }

  // Auto-expand all matching downstream providers when filter changes
  let expandedProviderIds = $state<Set<string>>(new Set());
  // Pass-through cards expand on their own: the Downstream filter never
  // collapses or opens them.
  let expandedPassthroughIds = $state<Set<string>>(new Set());
  function togglePassthroughCard(id: string) {
    const next = new Set(expandedPassthroughIds);
    if (next.has(id)) next.delete(id); else next.add(id);
    expandedPassthroughIds = next;
  }
  let prevDownstreamFilter = '';
  $effect(() => {
    const q = downstreamFilter.trim();
    if (q && q !== prevDownstreamFilter) {
      expandedProviderIds = new Set(filteredDownstreamProviders.map((p) => p.id));
    } else if (!q && prevDownstreamFilter) {
      expandedProviderIds = new Set();
    }
    prevDownstreamFilter = q;
  });

  // Auto-expand servers with matching models when upstream filter is active
  let prevUpstreamFilter = '';
  $effect(() => {
    const q = upstreamFilter.trim();
    if (q && q !== prevUpstreamFilter) {
      const toExpand = new Set(expandedServers);
      for (const s of filteredServers) {
        if ((filteredModelsByServer[s.id] ?? []).length > 0) toExpand.add(s.id);
      }
      expandedServers = toExpand;
    }
    prevUpstreamFilter = q;
  });

  function formatUpstreamApiFormat(f: string | null | undefined): string {
    if (!f) return 'Chat';
    return f === 'chat_completions' ? 'Chat' : f === 'responses' ? 'Responses' : f === 'anthropic_messages' ? 'Anthropic' : f === 'google_gemini' ? 'Gemini' : f;
  }

  const MODEL_TYPES = ['text', 'embedding', 'audio', 'image', 'video'] as const;

  // Tri-state capability helpers
  function boolToTriState(v: boolean | null | undefined): string {
    if (v === true) return 'true';
    if (v === false) return 'false';
    return '';
  }

  // Capabilities collapsible state for model modal
  let modelCapabilitiesOpen = $state(false);
  let modelPricingOpen = $state(false);

  function modelTypeBadgeClass(mt: string | null | undefined): string {
    switch (mt) {
      case 'embedding': return 'bg-(--tag-blue-bg) text-(--tag-blue-text)';
      case 'audio':     return 'bg-(--success-bg) text-(--success)';
      case 'image':     return 'bg-(--tag-violet-bg) text-(--tag-violet-text)';
      case 'video':     return 'bg-(--tag-indigo-bg) text-(--tag-indigo-text)';
      default:          return 'bg-(--text-secondary)/10 text-(--text-secondary)';
    }
  }

  // Servers + Models state
  let servers = $state<ServerResponse[]>([]);
  const serverOf = (p: DownstreamProvider) => servers.find((s) => s.id === p.upstream_server_id) ?? null;
  // The route destinations: the operator's own servers. A pass-through server
  // holds no key, so it is never where a route (or an override) sends traffic.
  // An existing route already on one keeps it listed for the whole edit, so
  // picking another server and back never loses it.
  let routeOpenedServerId = $state('');
  let routeDestinationServers = $derived(servers.filter((s) => !s.byok || s.id === routeOpenedServerId));
  // A pass-through override whose destination holds no key forwards the
  // member's own provider credential to it — said in the modal before saving.
  let routeIsOverride = $derived(downstreamProviders.find((p) => p.id === routeProviderId)?.byok ?? false);
  let routeDestinationKeyless = $derived(
    routeIsOverride && !!routeServerId && servers.find((s) => s.id === routeServerId)?.has_credential === false,
  );
  let allModels = $state<ModelResponse[]>([]);
  let configLoading = $state(true);
  // The skeleton on a first load or a new scope only: a refresh keeps what
  // is shown (`#lib/loadView.js`), so an auto-refresh tick never blanks it.
  const configView = useLoadView(() => configLoading);
  let expandedServers = $state<Set<string>>(new Set());

  // Adding a server is a guided flow of its own; EDITING one happens on that
  // server's page, where its endpoints, models and scheduling already live.
  let showWizard = $state(false);

  // Sync modal
  let showSyncModal = $state(false);
  let syncServerId = $state<string | null>(null);
  let syncServerName = $state('');
  let syncLoading = $state(false);
  let syncResult = $state<ModelSyncResponse | null>(null);
  let syncError = $state('');
  let syncSelectedNew = $state<Set<string>>(new Set());
  let syncSelectedRemoved = $state<Set<string>>(new Set());
  let syncApplying = $state(false);

  // Model modal
  let showModelModal = $state(false);
  let editingModelData = $state<ModelResponse | null>(null);
  let modelModalServerId = $state<string | null>(null);
  // Capabilities are tri-state ('' = inherit from catalog, 'true'/'false' =
  // override) so an inherited field stays inherited instead of being frozen.
  let modelModalForm = $state({
    upstream_model: '',
    context_window: undefined as number | undefined,
    max_output_tokens: undefined as number | undefined,
    upstream_api_format: 'chat_completions' as string,
    model_type: '' as string,
    enabled: true,
    // Explicit catalog link to inherit from (undefined = auto-match by name).
    catalog_model_id: undefined as string | undefined,
    supports_vision: '' as string,
    supports_reasoning: '' as string,
    supports_function_calling: '' as string,
    supports_caching: '' as string,
    supports_audio_input: '' as string,
    supports_audio_output: '' as string,
    supports_video_input: '' as string,
    supports_pdf_input: '' as string,
    supports_response_schema: '' as string,
    supports_system_messages: '' as string,
    // Self-healing override ('' = inherit tenant setting, 'true'/'false' = force).
    healing_enabled: '' as string,
  });
  // The price list is edited as one atom, so it sits beside the field-wise form
  // rather than inside it: a rate map is one provider's quote in one currency,
  // inherited or overridden whole.
  let modelRates = $state<RatesForm>(ratesToForm(null));
  let modelRatesOrig = $state('inherit');
  let modelError = $state('');
  let savingModel = $state(false);
  // The catalog entry the editor is inheriting from (link or auto-match), for
  // the picker's current-selection display.
  let selectedCatalog = $state<PickerItem | null>(null);
  // Snapshot of the inheritable fields as loaded (edit mode), so a save sends an
  // override only for fields the operator actually changed — leaving an untouched
  // synced/inherited value exactly as it was instead of re-pinning it.
  let modelOrig = $state<Record<string, string | number | undefined>>({});

  // Catalog state
  let catalog = $state<CatalogEntry[]>([]);
  let catalogLoading = $state(true);
  // The skeleton on a first load or a new scope only: a refresh keeps what
  // is shown (`#lib/loadView.js`), so an auto-refresh tick never blanks it.
  const catalogView = useLoadView(() => catalogLoading);
  let showCatalogModal = $state(false);
  let editingCatalogData = $state<CatalogEntry | null>(null);
  let catalogModalForm = $state({
    // '' = a global entry (every server); a server id scopes the entry to that
    // one server, which outranks the global row when a model on it resolves.
    server_id: '' as string,
    provider: 'openai',
    model: '',
    model_type: '' as string,
    context_window: undefined as number | undefined,
    max_output_tokens: undefined as number | undefined,
    output_vector_size: undefined as number | undefined,
    supports_vision: false,
    supports_reasoning: false,
    supports_function_calling: false,
    supports_caching: false,
    supports_audio_input: false,
    supports_audio_output: false,
    supports_video_input: false,
    supports_pdf_input: false,
    supports_response_schema: false,
    supports_system_messages: false,
  });
  // The catalog is the root of the pricing ladder — it inherits from nothing, so
  // its price list is always the entry's own and the editor runs with the
  // inherit toggle hidden.
  let catalogRates = $state<RatesForm>(ratesToForm(EMPTY_RATES));
  let catalogError = $state('');
  let filteredCatalog = $derived.by(() => {
    const q = upstreamQuery;
    if (!q) return catalog;
    return catalog.filter(e => e.model.toLowerCase().includes(q)
      || e.provider.toLowerCase().includes(q)
      || (e.server_name ?? '').toLowerCase().includes(q));
  });
  // The catalog and each server's models are loaded whole (the filter searches
  // all of them) but rendered a page at a time: the seeded catalog alone is over
  // a thousand entries, as is a server synced from a large upstream, and a table
  // of all of them holds the tab for seconds on its first layout — a sidebar
  // click made meanwhile waits on it.
  const LIST_PAGE_SIZE = 50;
  const catalogPager = usePagination({
    limit: LIST_PAGE_SIZE,
    list: { count: () => filteredCatalog.length },
  });
  let catalogPageRows = $derived(
    filteredCatalog.slice(catalogPager.offset, catalogPager.offset + catalogPager.limit),
  );
  // After a save, the page that holds the entry just created or edited — it may
  // sort onto any page. An entry not read back yet (a refresh's older read
  // landed instead) is shown once a later read has it; one the filter hides
  // leaves the page as it is.
  let pendingCatalogEntry: string | null = null;
  function showCatalogEntry(id: string | null) {
    pendingCatalogEntry = null;
    if (!id) return;
    const index = filteredCatalog.findIndex((e) => e.id === id);
    if (index >= 0) catalogPager.offset = pageStartFor(index, catalogPager.limit);
    else if (!catalog.some((e) => e.id === id)) pendingCatalogEntry = id;
  }
  // One pager per server, made where the server list is set (never during
  // render) — `setServers` is the only writer of `servers` — so a rendered
  // server always has one: a server's pager survives a reload, a removed
  // server's goes with it.
  let modelPagers = $state.raw(new Map<string, PaginationState>());
  function setServers(list: ServerResponse[]) {
    const next = new Map<string, PaginationState>();
    for (const { id } of list) {
      next.set(
        id,
        modelPagers.get(id) ??
          usePagination({
            limit: LIST_PAGE_SIZE,
            list: { count: () => (filteredModelsByServer[id] ?? []).length },
          }),
      );
    }
    modelPagers = next;
    servers = list;
  }
  // A new filter (as normalised for matching) starts every list at page 1 —
  // before the frame renders, so no stale page is ever painted.
  $effect.pre(() => {
    void upstreamQuery;
    untrack(() => {
      catalogPager.reset();
      for (const pager of modelPagers.values()) pager.reset();
    });
  });

  // Delete confirmation
  let deleteTarget = $state<{ type: 'server' | 'model' | 'catalog'; id: string; label: string; serverId?: string } | null>(null);
  let deleting = $state(false);

  // Bulk model enable/disable (per-server)
  let bulkModelConfirm = $state<{ serverId: string; serverName: string; modelCount: number } | null>(null);
  let bulkModelUpdating = $state(false);
  let bulkModelError = $state('');

  // Catalog bulk actions
  let catalogBulkAction = $state<'remove-seeded' | 'reset' | null>(null);
  let catalogBulkLoading = $state(false);
  let catalogBulkError = $state('');
  let seededCount = $derived(catalog.filter(e => e.is_builtin).length);

  // Grouped models by server
  let modelsByServer = $derived(
    allModels.reduce((acc: Record<string, ModelResponse[]>, m: ModelResponse) => {
      const sid = m.server_id || 'unknown';
      if (!acc[sid]) acc[sid] = [];
      acc[sid].push(m);
      return acc;
    }, {} as Record<string, ModelResponse[]>)
  );
  // Each server's models the upstream filter keeps — the list its table pages.
  let filteredModelsByServer = $derived.by(() => {
    if (!upstreamQuery) return modelsByServer;
    const out: Record<string, ModelResponse[]> = {};
    for (const [sid, models] of Object.entries(modelsByServer)) {
      out[sid] = models.filter((m) => modelMatchesUpstreamFilter(m));
    }
    return out;
  });

  usePeriodicLoad(
    async () => { await Promise.all([loadConfig(), loadCatalog(), loadDownstreamProviders(), loadCachePresets()]); },
  );

  // Only the latest read lands: a refresh read before a save must not put the
  // old state back after the save's own re-read.
  let downstreamGen = 0;
  async function loadDownstreamProviders() {
    const gen = ++downstreamGen;
    downstreamLoading = true;
    try {
      const providers = await fetchAllPages<DownstreamProvider>((offset, limit) =>
        adminApi.GET('/api/v1/admin/downstream-providers', { params: { query: { offset, limit } } }));
      // Pre-fetch the routes of every provider holding at least one route, for the filter
      // search and the expanded cards; one with none needs no read.
      const routeResults = await Promise.all(
        providers.filter((p) => p.route_count > 0).map(async (p) => {
          const { data: detail } = await adminApi.GET('/api/v1/admin/downstream-providers/{id}', { params: { path: { id: p.id } } });
          return [p.id, detail?.routes ?? []] as const;
        })
      );
      const { data: col } = await adminApi.GET('/api/v1/admin/downstream-routes/collisions');
      if (gen !== downstreamGen) return;
      downstreamProviders = providers;
      allProviderRoutes = Object.fromEntries(routeResults);
      collisions = col?.collisions ?? [];
    } catch (e) {
      if (gen === downstreamGen) toast.error(extractError(e));
    } finally {
      if (gen === downstreamGen) downstreamLoading = false;
    }
  }

  function toggleProvider(id: string) {
    const next = new Set(expandedProviderIds);
    if (next.has(id)) next.delete(id); else next.add(id);
    expandedProviderIds = next;
  }

  async function handleCreateProvider() {
    if (!newProviderName.trim()) return;
    creatingProvider = true;
    providerError = '';
    try {
      const { error: err } = await adminApi.POST('/api/v1/admin/downstream-providers', { body: { name: newProviderName.trim(), description: newProviderDesc.trim() || undefined, icon: newProviderIcon || undefined } });
      if (err) { providerError = extractError(err, 'Failed to create provider'); creatingProvider = false; return; }
      newProviderName = '';
      newProviderDesc = '';
      newProviderIcon = '';
      showNewProvider = false;
      await loadDownstreamProviders();
    } catch (e) {
      providerError = String(e).replace('Error: ', '');
    } finally {
      creatingProvider = false;
    }
  }

  async function handleDeleteProvider(id: string) {
    const provider = downstreamProviders.find((p: DownstreamProvider) => p.id === id);
    const routeCount = provider?.route_count ?? 0;
    const { data: impact } = await adminApi.DELETE('/api/v1/admin/downstream-providers/{id}', { params: { path: { id }, query: { dry_run: true } } });
    impactModal = {
      open: true,
      title: 'Delete Provider',
      message: `Delete "${provider?.name ?? id}" and its ${routeCount} route(s)?`,
      affectedKeys: impact?.affected_keys ?? 0,
      affectedUsers: impact?.affected_users ?? 0,
      confirmLabel: 'Delete',
      onconfirm: async () => {
        impactModal.open = false;
        providerError = '';
        try {
          const { error: err } = await adminApi.DELETE('/api/v1/admin/downstream-providers/{id}', { params: { path: { id } } });
          if (err) { providerError = extractError(err, 'Failed to delete provider'); return; }
          const next = new Set(expandedProviderIds);
          next.delete(id);
          expandedProviderIds = next;
          // A pass-through's provider takes its server with it.
          await Promise.all([loadDownstreamProviders(), loadConfig()]);
        } catch (e) {
          providerError = String(e).replace('Error: ', '');
        }
      },
    };
  }

  /** Delete a pass-through: its provider and keyless server go together, with
   *  their overrides and grants, and the keys bound to it are revoked. The
   *  confirm shows the server delete's own preview — the delete rolled back —
   *  so what it says is what the delete does. */
  async function deletePassThroughUnit(provider: DownstreamProvider, server: ServerResponse | null) {
    if (!server) { await handleDeleteProvider(provider.id); return; }
    const { data: preview, error: previewErr } = await adminApi.DELETE('/api/v1/admin/servers/{id}', {
      params: { path: { id: server.id }, query: { dry_run: true } },
    });
    if (previewErr || !preview) { toast.error(extractError(previewErr, 'Cannot delete the pass-through')); return; }
    impactModal = {
      open: true,
      title: 'Delete pass-through',
      message: `Delete "${provider.name}"? ${preview.message ?? ''}`,
      affectedKeys: preview.impact?.keys_revoked ?? 0,
      affectedUsers: 0,
      confirmLabel: 'Delete',
      onconfirm: async () => {
        impactModal.open = false;
        const { data, error: err } = await adminApi.DELETE('/api/v1/admin/servers/{id}', { params: { path: { id: server.id } } });
        if (err) { toast.error(extractError(err, 'Failed to delete the pass-through')); return; }
        toast.success(data?.message ?? 'Pass-through deleted.');
        const next = new Set(expandedPassthroughIds);
        next.delete(provider.id);
        expandedPassthroughIds = next;
        await Promise.all([loadDownstreamProviders(), loadConfig()]);
      },
    };
  }

  function openEditProvider(provider: DownstreamProvider) {
    editingProviderId = provider.id;
    editProviderName = provider.name;
    editProviderDesc = provider.description || '';
    editProviderIcon = provider.icon || '';
  }

  async function handleSaveProvider() {
    if (!editingProviderId || !editProviderName.trim()) return;
    savingProvider = true;
    providerError = '';
    try {
      const { error: err } = await adminApi.PUT('/api/v1/admin/downstream-providers/{id}', {
        params: { path: { id: editingProviderId } },
        body: {
          name: editProviderName.trim(),
          description: editProviderDesc.trim() || null,
          icon: editProviderIcon || null,
        },
      });
      if (err) { providerError = extractError(err, 'Failed to update provider'); savingProvider = false; return; }
      editingProviderId = null;
      await loadDownstreamProviders();
    } catch (e) {
      providerError = String(e).replace('Error: ', '');
    } finally {
      savingProvider = false;
    }
  }

  function openAddRoute(providerId: string) {
    routeProviderId = providerId;
    editingRouteId = null;
    routeAlias = '';
    routeServerId = '';
    routeOpenedServerId = '';
    routeModel = '';
    routePriority = 0;
    routeWeight = 1;
    routeClientCw = undefined;
    routePresetId = '';
    routePresets = [];
    routeCachePresetId = '';
    routeQosClassIds = [];
    // Every route is offered to all clients by default; the operator narrows
    // this or sets the per-downstream default by adding `*` to Default For Tags.
    routeTags = '*';
    routeDefaultForTags = '';
    routeClientSlots = [];
    routeClientSlotsOpened = [];
    routeConflictMsg = '';
    showRouteModal = true;
  }

  function openEditRoute(providerId: string, route: DownstreamRoute) {
    routeProviderId = providerId;
    editingRouteId = route.id;
    routeAlias = route.alias || '';
    routeServerId = route.server_id || '';
    routeOpenedServerId = routeServerId;
    routeModel = route.model_id || '';
    routePriority = route.priority ?? 0;
    routeWeight = route.weight ?? 1;
    routeClientCw = route.client_context_window ?? undefined;
    routePresetId = route.preset_id || '';
    routePresets = [];
    routeCachePresetId = route.cache_preset_id || '';
    routeQosClassIds = [...(route.qos_class_ids ?? [])];
    if (route.model_id) void loadRoutePresets(route.model_id);
    routeTags = (route.tags ?? []).join(', ');
    routeDefaultForTags = (route.default_for_tags ?? []).join(', ');
    routeClientSlots = [...(route.client_slots ?? [])];
    routeClientSlotsOpened = [...routeClientSlots];
    routeConflictMsg = '';
    showRouteModal = true;
  }

  // Tenant cache presets for the route modal's cache picker. Tenant-scoped and
  // small, so it loads once with the page rather than per model.
  async function loadCachePresets() {
    const { data } = await adminApi.GET('/api/v1/admin/cache-presets', {});
    cachePresets = data?.items ?? [];
    const { data: qos } = await adminApi.GET('/api/v1/admin/qos-classes', {});
    qosClasses = (qos?.items ?? []).map((c) => ({ id: c.id, name: c.name }));
    // Only a successful read may clear the flag — a transient failure must not
    // warn that an embedding model is missing on a tenant that has one.
    const { data: settings, error: settingsErr } = await adminApi.GET(
      '/api/v1/admin/settings/cache',
    );
    if (!settingsErr) embeddingAliasConfigured = !!settings?.embedding_alias;
  }

  // Drop every cached response for this alias across the fleet. Non-destructive
  // — the worst case is a recomputation — so no confirmation step.
  async function handleFlushRouteCache(providerId: string, routeId: string) {
    const { data, error: err } = await adminApi.POST(
      '/api/v1/admin/downstream-providers/{id}/routes/{route_id}/actions/flush-cache',
      { params: { path: { id: providerId, route_id: routeId } } },
    );
    if (err) {
      toast.error(extractError(err, 'Failed to flush cached responses'));
      return;
    }
    toast.success(data?.message ?? 'Cached responses dropped');
  }

  // Load the selected model's presets for the route modal's preset picker.
  async function loadRoutePresets(modelId: string) {
    const { data } = await adminApi.GET('/api/v1/admin/upstream-models/{model_id}/presets', {
      params: { path: { model_id: modelId } },
    });
    routePresets = data?.items ?? [];
  }

  // ── Model presets management ──
  async function openPresetsModal(model: ModelResponse) {
    presetsModel = model;
    showPresetsModal = true;
    showPresetForm = false;
    presetError = '';
    await loadPresets();
  }

  async function loadPresets() {
    if (!presetsModel) return;
    presetsLoading = true;
    const { data } = await adminApi.GET('/api/v1/admin/upstream-models/{model_id}/presets', {
      params: { path: { model_id: presetsModel.id } },
    });
    presetsList = data?.items ?? [];
    presetsLoading = false;
  }

  // The model's effective protocol drives which preset fields are shown and how
  // they serialize. The model column may be NULL (inherits the server's format).
  function presetProtocol(): PresetProtocol {
    const fmt =
      presetsModel?.upstream_api_format ||
      servers.find((s) => s.id === presetsModel?.server_id)?.upstream_api_format ||
      'chat_completions';
    return (['responses', 'anthropic_messages', 'google_gemini'].includes(fmt)
      ? fmt
      : 'chat_completions') as PresetProtocol;
  }

  const csvToArr = (s: string): string[] => s.split(',').map((t) => t.trim()).filter(Boolean);
  const arrToCsv = (v: unknown): string => (Array.isArray(v) ? v.map((x) => String(x)).join(', ') : '');
  const numOr = (v: unknown): number | undefined => (typeof v === 'number' ? v : undefined);
  const strOr = (v: unknown): string => (typeof v === 'string' ? v : '');

  // Populate the structured fields from a stored settings fragment; anything not
  // mapped to a known field is left in the Advanced raw editor (lossless).
  function settingsToForm(settings: Record<string, unknown>, protocol: PresetProtocol) {
    pTemperature = pTopP = pTopK = pMinP = pSeed = pFreqPenalty = pPresPenalty = pMaxTokens = pThinkingBudget = undefined;
    pStop = pReasoning = pThinking = pAdvanced = '';
    pIncludeThoughts = false;
    pAdvancedOpen = false;

    const rest: Record<string, unknown> = { ...settings };
    const take = (k: string): unknown => {
      const v = rest[k];
      delete rest[k];
      return v;
    };

    if (protocol === 'google_gemini') {
      const gc: Record<string, unknown> =
        rest.generationConfig && typeof rest.generationConfig === 'object'
          ? { ...(rest.generationConfig as Record<string, unknown>) }
          : {};
      delete rest.generationConfig;
      const gtake = (k: string): unknown => {
        const v = gc[k];
        delete gc[k];
        return v;
      };
      pTemperature = numOr(gtake('temperature'));
      pTopP = numOr(gtake('topP'));
      pTopK = numOr(gtake('topK'));
      pMaxTokens = numOr(gtake('maxOutputTokens'));
      pStop = arrToCsv(gtake('stopSequences'));
      const tc = gtake('thinkingConfig');
      if (tc && typeof tc === 'object') {
        const tcr = { ...(tc as Record<string, unknown>) };
        pThinkingBudget = numOr(tcr.thinkingBudget);
        pIncludeThoughts = tcr.includeThoughts === true;
        if (pThinkingBudget !== undefined || pIncludeThoughts) pThinking = 'enabled';
        delete tcr.thinkingBudget;
        delete tcr.includeThoughts;
        if (Object.keys(tcr).length) gc.thinkingConfig = tcr;
      }
      if (Object.keys(gc).length) rest.generationConfig = gc;
    } else {
      pTemperature = numOr(take('temperature'));
      pTopP = numOr(take('top_p'));
      pMaxTokens = numOr(take(protocol === 'responses' ? 'max_output_tokens' : 'max_tokens'));
      if (protocol === 'anthropic_messages') {
        pTopK = numOr(take('top_k'));
        pStop = arrToCsv(take('stop_sequences'));
        const th = take('thinking');
        if (th && typeof th === 'object') {
          const thr = th as Record<string, unknown>;
          pThinking =
            thr.type === 'disabled' ? 'disabled'
            : thr.type === 'adaptive' ? 'adaptive'
            : thr.type === 'enabled' ? 'enabled'
            : '';
          pThinkingBudget = numOr(thr.budget_tokens);
        }
      } else if (protocol === 'responses') {
        const r = take('reasoning');
        if (r && typeof r === 'object') {
          const rr = { ...(r as Record<string, unknown>) };
          pReasoning = strOr(rr.effort);
          delete rr.effort;
          // Surface any sibling reasoning keys (e.g. `summary`) in Advanced so
          // they round-trip; deep-merged back under `reasoning` on save.
          if (Object.keys(rr).length) rest.reasoning = rr;
        }
      } else {
        // chat_completions (OpenAI + OpenAI-compatible: vLLM/Ollama/…). top_k/min_p
        // aren't in OpenAI's spec but every compatible open-model server accepts them.
        pTopK = numOr(take('top_k'));
        pMinP = numOr(take('min_p'));
        pSeed = numOr(take('seed'));
        pFreqPenalty = numOr(take('frequency_penalty'));
        pPresPenalty = numOr(take('presence_penalty'));
        pStop = arrToCsv(take('stop'));
        pReasoning = strOr(take('reasoning_effort'));
      }
    }

    if (Object.keys(rest).length) {
      pAdvanced = JSON.stringify(rest, null, 2);
      pAdvancedOpen = true;
    }
  }

  // Reassemble the structured fields into the protocol's native partial body.
  // Throws only if the Advanced raw editor holds invalid JSON.
  function formToSettings(protocol: PresetProtocol): Record<string, unknown> {
    const out: Record<string, unknown> = {};
    // A cleared numeric input binds to null (Svelte) — treat null/undefined/NaN as
    // "omit" so a blank field stays absent from the fragment (= passthrough).
    const setNum = (obj: Record<string, unknown>, k: string, v: number | undefined) => {
      if (v != null && !Number.isNaN(v)) obj[k] = v;
    };
    const stop = csvToArr(pStop);

    if (protocol === 'google_gemini') {
      const gc: Record<string, unknown> = {};
      setNum(gc, 'temperature', pTemperature);
      setNum(gc, 'topP', pTopP);
      setNum(gc, 'topK', pTopK);
      setNum(gc, 'maxOutputTokens', pMaxTokens);
      if (stop.length) gc.stopSequences = stop;
      const tc: Record<string, unknown> = {};
      setNum(tc, 'thinkingBudget', pThinkingBudget);
      if (pIncludeThoughts) tc.includeThoughts = true;
      if (Object.keys(tc).length) gc.thinkingConfig = tc;
      if (Object.keys(gc).length) out.generationConfig = gc;
    } else {
      setNum(out, 'temperature', pTemperature);
      setNum(out, 'top_p', pTopP);
      if (protocol === 'responses') {
        setNum(out, 'max_output_tokens', pMaxTokens);
        if (pReasoning) out.reasoning = { effort: pReasoning };
      } else if (protocol === 'anthropic_messages') {
        setNum(out, 'top_k', pTopK);
        setNum(out, 'max_tokens', pMaxTokens);
        if (stop.length) out.stop_sequences = stop;
        if (pThinking === 'enabled') {
          const t: Record<string, unknown> = { type: 'enabled' };
          if (pThinkingBudget != null && !Number.isNaN(pThinkingBudget)) t.budget_tokens = pThinkingBudget;
          out.thinking = t;
        } else if (pThinking === 'adaptive') {
          out.thinking = { type: 'adaptive' };
        } else if (pThinking === 'disabled') {
          out.thinking = { type: 'disabled' };
        }
      } else {
        setNum(out, 'top_k', pTopK);
        setNum(out, 'min_p', pMinP);
        setNum(out, 'seed', pSeed);
        setNum(out, 'frequency_penalty', pFreqPenalty);
        setNum(out, 'presence_penalty', pPresPenalty);
        setNum(out, 'max_tokens', pMaxTokens);
        if (stop.length) out.stop = stop;
        if (pReasoning) out.reasoning_effort = pReasoning;
      }
    }

    const adv = pAdvanced.trim();
    if (adv) {
      const parsed = JSON.parse(adv) as Record<string, unknown>;
      // Deep-merge so Advanced extras compose with the structured fields under a
      // shared parent (e.g. `reasoning.summary` beside the form's `reasoning.effort`,
      // or `generationConfig.*` beside the Gemini fields) instead of clobbering it.
      deepMergeInto(out, parsed);
    }
    return out;
  }

  // Recursively merge `src` into `target` (plain objects recurse; scalars and
  // arrays overwrite). Used to overlay the Advanced raw-JSON extras onto the
  // structured-field output without dropping a co-parented branch.
  function deepMergeInto(target: Record<string, unknown>, src: Record<string, unknown>) {
    for (const [k, v] of Object.entries(src)) {
      const cur = target[k];
      if (v && typeof v === 'object' && !Array.isArray(v) && cur && typeof cur === 'object' && !Array.isArray(cur)) {
        deepMergeInto(cur as Record<string, unknown>, v as Record<string, unknown>);
      } else {
        target[k] = v;
      }
    }
  }

  function openAddPreset() {
    editingPresetId = null;
    presetName = '';
    settingsToForm({}, presetProtocol());
    presetError = '';
    showPresetForm = true;
  }

  function openEditPreset(preset: PresetResponse) {
    editingPresetId = preset.id;
    presetName = preset.name;
    settingsToForm((preset.settings ?? {}) as Record<string, unknown>, presetProtocol());
    presetError = '';
    showPresetForm = true;
  }

  async function savePreset() {
    if (!presetsModel) return;
    presetError = '';
    // The fragment is genuinely polymorphic JSON; the generated body type is an
    // empty-object placeholder, so cast it (request body, validated server-side).
    let settings: Record<string, never>;
    try {
      settings = formToSettings(presetProtocol()) as Record<string, never>;
    } catch {
      presetError = 'Advanced settings must be valid JSON.';
      return;
    }
    savingPreset = true;
    try {
      if (editingPresetId) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/upstream-models/{model_id}/presets/{preset_id}', {
          params: { path: { model_id: presetsModel.id, preset_id: editingPresetId } },
          body: { name: presetName.trim() || undefined, settings },
        });
        if (err) { presetError = extractError(err, 'Failed to save preset'); savingPreset = false; return; }
      } else {
        const { error: err } = await adminApi.POST('/api/v1/admin/upstream-models/{model_id}/presets', {
          params: { path: { model_id: presetsModel.id } },
          body: { name: presetName.trim(), settings },
        });
        if (err) { presetError = extractError(err, 'Failed to create preset'); savingPreset = false; return; }
      }
      showPresetForm = false;
      await loadPresets();
      toast.success('Preset saved');
    } finally {
      savingPreset = false;
    }
  }

  async function setDefaultPreset(preset: PresetResponse) {
    if (!presetsModel || preset.is_default) return;
    const { error: err } = await adminApi.POST('/api/v1/admin/upstream-models/{model_id}/presets/{preset_id}/actions/set-default', {
      params: { path: { model_id: presetsModel.id, preset_id: preset.id } },
    });
    if (err) { toast.error(extractError(err, 'Failed to set default')); return; }
    await loadPresets();
    toast.success(`"${preset.name}" is now the default preset`);
  }

  async function deletePreset(preset: PresetResponse) {
    if (!presetsModel) return;
    const { error: err } = await adminApi.DELETE('/api/v1/admin/upstream-models/{model_id}/presets/{preset_id}', {
      params: { path: { model_id: presetsModel.id, preset_id: preset.id } },
    });
    if (err) { toast.error(extractError(err, 'Failed to delete preset')); return; }
    await loadPresets();
    toast.success('Preset deleted');
  }

  // Short human summary of a preset's set fields for the list row — flattens the
  // Gemini generationConfig group and renders scalar fields as `key=value`.
  function presetSummary(settings: unknown): string {
    if (!settings || typeof settings !== 'object') return 'passthrough';
    const parts: string[] = [];
    const walk = (obj: Record<string, unknown>) => {
      for (const [k, v] of Object.entries(obj)) {
        if (v && typeof v === 'object' && !Array.isArray(v)) walk(v as Record<string, unknown>);
        else if (Array.isArray(v)) parts.push(`${k}=[${v.length}]`);
        else parts.push(`${k}=${String(v)}`);
      }
    };
    walk(settings as Record<string, unknown>);
    return parts.length ? parts.join(' · ') : 'passthrough';
  }

  async function handleSaveRoute(reassign = false) {
    if (!routeProviderId) return;
    savingRoute = true;
    routeError = '';
    if (!reassign) routeConflictMsg = '';
    try {
      const parseTags = (s: string): string[] =>
        s.split(',').map((t) => t.trim()).filter((t) => t.length > 0);
      const tags = parseTags(routeTags);
      const defaultForTags = parseTags(routeDefaultForTags);
      const orphan = defaultForTags.find((t) => !tags.includes(t));
      if (orphan) {
        routeError = `Default-for-tag "${orphan}" is not in this route's tag list.`;
        savingRoute = false;
        return;
      }
      if (editingRouteId) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/downstream-providers/{id}/routes/{route_id}', {
          params: { path: { id: routeProviderId, route_id: editingRouteId } },
          body: {
            alias: routeAlias || undefined,
            model_id: routeModel || undefined,
            // Tri-state: '' selects the model's default preset (reset to NULL);
            // a uuid binds that preset.
            preset_id: routePresetId || null,
            // Tri-state, same shape: '' clears the binding (stop caching).
            cache_preset_id: routeCachePresetId || null,
            qos_class_ids: routeQosClassIds,
            priority: routePriority,
            weight: routeWeight,
            client_context_window: routeClientCw || null,
            tags,
            default_for_tags: defaultForTags,
            reassign_default_tags: reassign,
            // Absent = unchanged; a list replaces the route's slots.
            ...(sameSlots(routeClientSlots, routeClientSlotsOpened) ? {} : { client_slots: routeClientSlots }),
          },
        });
        if (err) {
          if (extractErrorCode(err) === 'route_default_tag_conflict') {
            routeConflictMsg = extractError(err, 'Another route already owns that default.');
            savingRoute = false;
            return;
          }
          routeError = extractError(err, 'Failed to update route'); savingRoute = false; return;
        }
      } else {
        const { error: err } = await adminApi.POST('/api/v1/admin/downstream-providers/{id}/routes', {
          params: { path: { id: routeProviderId } },
          body: {
            alias: routeAlias,
            model_id: routeModel,
            preset_id: routePresetId || undefined,
            cache_preset_id: routeCachePresetId || undefined,
            priority: routePriority,
            weight: routeWeight,
            client_context_window: routeClientCw || undefined,
            tags,
            default_for_tags: defaultForTags,
            reassign_default_tags: reassign,
          },
        });
        if (err) {
          if (extractErrorCode(err) === 'route_default_tag_conflict') {
            routeConflictMsg = extractError(err, 'Another route already owns that default.');
            savingRoute = false;
            return;
          }
          routeError = extractError(err, 'Failed to create route'); savingRoute = false; return;
        }
      }
      showRouteModal = false;
      editingRouteId = null;
      // Refresh routes for the provider that was just saved
      const savedProviderId = routeProviderId;
      if (savedProviderId) {
        // Ensure this provider is expanded so user sees the updated route
        if (!expandedProviderIds.has(savedProviderId)) {
          const next = new Set(expandedProviderIds);
          next.add(savedProviderId);
          expandedProviderIds = next;
        }
      }
      await loadDownstreamProviders();
    } catch (e) {
      routeError = String(e).replace('Error: ', '');
    } finally {
      savingRoute = false;
    }
  }

  async function handleDeleteRoute(providerId: string, routeId: string) {
    if (!confirm('Delete this route?')) return;
    routeError = '';
    try {
      const { error: err } = await adminApi.DELETE('/api/v1/admin/downstream-providers/{id}/routes/{route_id}', { params: { path: { id: providerId, route_id: routeId } } });
      if (err) { routeError = extractError(err, 'Failed to delete route'); return; }
      await loadDownstreamProviders();
    } catch (e) {
      routeError = String(e).replace('Error: ', '');
    }
  }

  async function handleToggleRouteEnabled(providerId: string, route: DownstreamRoute) {
    routeError = '';
    try {
      const { error: err } = await adminApi.PATCH('/api/v1/admin/downstream-providers/{id}/routes/{route_id}', {
        params: { path: { id: providerId, route_id: route.id } },
        body: { enabled: !route.enabled },
      });
      if (err) { routeError = extractError(err, 'Failed to toggle route'); return; }
      route.enabled = !route.enabled;
    } catch (e) {
      routeError = String(e).replace('Error: ', '');
    }
  }

  // --- Passthrough route policy functions ---

  async function togglePassthroughSection(providerId: string) {
    const next = new Set(passthroughExpanded);
    if (next.has(providerId)) {
      next.delete(providerId);
    } else {
      next.add(providerId);
      if (!passthroughPolicies[providerId]) {
        await loadPassthroughPolicies(providerId);
      }
    }
    passthroughExpanded = next;
  }

  async function loadPassthroughPolicies(providerId: string) {
    passthroughLoading = { ...passthroughLoading, [providerId]: true };
    passthroughError = { ...passthroughError, [providerId]: '' };
    try {
      const items = await fetchAllPages<RoutePolicyRow>((offset, limit) =>
        adminApi.GET('/api/v1/admin/route-policies', {
          params: { query: { downstream_id: providerId, offset, limit } },
        }));
      passthroughPolicies = { ...passthroughPolicies, [providerId]: items };
    } catch (err) {
      passthroughError = { ...passthroughError, [providerId]: extractError(err, 'Failed to load') };
      passthroughPolicies = { ...passthroughPolicies, [providerId]: [] };
    } finally {
      passthroughLoading = { ...passthroughLoading, [providerId]: false };
    }
  }

  async function handleCreatePassthrough(providerId: string) {
    const pathVal = (passthroughNewPath[providerId] ?? '').trim();
    if (!pathVal) return;
    passthroughError = { ...passthroughError, [providerId]: '' };
    const { error: err } = await adminApi.POST('/api/v1/admin/route-policies', {
      body: { downstream_id: providerId, path_pattern: pathVal, enabled: true },
    });
    if (err) {
      passthroughError = { ...passthroughError, [providerId]: extractError(err, 'Failed to create') };
      return;
    }
    passthroughNewPath = { ...passthroughNewPath, [providerId]: '' };
    const nextShow = new Set(passthroughShowAdd);
    nextShow.delete(providerId);
    passthroughShowAdd = nextShow;
    await loadPassthroughPolicies(providerId);
  }

  async function handleTogglePassthrough(providerId: string, policy: RoutePolicyRow) {
    passthroughError = { ...passthroughError, [providerId]: '' };
    const { error: err } = await adminApi.PATCH('/api/v1/admin/route-policies/{id}', {
      params: { path: { id: policy.id } },
      body: { enabled: !policy.enabled },
    });
    if (err) {
      passthroughError = { ...passthroughError, [providerId]: extractError(err, 'Failed to toggle') };
      return;
    }
    const policies = passthroughPolicies[providerId] ?? [];
    passthroughPolicies = {
      ...passthroughPolicies,
      [providerId]: policies.map(p => p.id === policy.id ? { ...p, enabled: !p.enabled } : p),
    };
  }

  async function handleDeletePassthrough(providerId: string, policyId: string) {
    if (!confirm('Remove this forwarded path?')) return;
    passthroughError = { ...passthroughError, [providerId]: '' };
    const { error: err } = await adminApi.DELETE('/api/v1/admin/route-policies/{id}', {
      params: { path: { id: policyId } },
    });
    if (err) {
      passthroughError = { ...passthroughError, [providerId]: extractError(err, 'Failed to delete') };
      return;
    }
      const policies = passthroughPolicies[providerId] ?? [];
      passthroughPolicies = {
        ...passthroughPolicies,
        [providerId]: policies.filter(p => p.id !== policyId),
      };
  }

  // Only the latest read lands: a refresh read before a save must not put the
  // old state back after the save's own re-read.
  let configGen = 0;
  async function loadConfig() {
    const gen = ++configGen;
    configLoading = true;
    try {
      const [serversList, modelsList] = await Promise.all([
        fetchAllPages<ServerResponse>((offset, limit) =>
          adminApi.GET('/api/v1/admin/servers', { params: { query: { offset, limit } } })),
        fetchAllPages<ModelResponse>((offset, limit) =>
          adminApi.GET('/api/v1/admin/models', { params: { query: { offset, limit } } })),
      ]);
      if (gen !== configGen) return;
      setServers(serversList);
      allModels = modelsList;
    } catch (e) {
      if (gen === configGen) toast.error(extractError(e));
    } finally {
      if (gen === configGen) configLoading = false;
    }
  }

  function toggleServer(id: string) {
    const next = new Set(expandedServers);
    if (next.has(id)) next.delete(id); else next.add(id);
    expandedServers = next;
  }

  // -- Autosync --
  let syncingNowId = $state<string | null>(null);

  /**
   * Toggle the per-server autosync flag (force=true skips the liveness re-probe).
   *
   * PATCH, not PUT: a PUT is a full replacement, so sending only the fields this
   * toggle knows about would reset every other setting on the server to the
   * provider's defaults.
   */
  async function toggleAutoSync(server: ServerResponse) {
    const next = !server.auto_sync_enabled;
    const { data, error: err } = await adminApi.PATCH('/api/v1/admin/servers/{id}', {
      params: { path: { id: server.id } },
      body: { auto_sync_enabled: next, force: true },
    });
    if (err || !data) { toast.error(extractError(err, 'Failed to update autosync')); return; }
    // A read in flight is older than this save: it must not land after it.
    ++configGen;
    configLoading = false;
    setServers(servers.map((s) => (s.id === server.id ? data : s)));
  }

  /** Turn a server on or off: a pass-through's switch on its Pass-through
   *  card, and Enable on an own server that is off. Off, it is not sent to the
   *  gateways, and a pass-through is no longer offered to workspaces or members. */
  async function toggleServerEnabled(server: ServerResponse) {
    const next = !server.enabled;
    const { data, error: err } = await adminApi.PATCH('/api/v1/admin/servers/{id}', {
      params: { path: { id: server.id } },
      body: { enabled: next, force: true },
    });
    if (err || !data) { toast.error(extractError(err, next ? 'Failed to enable the server' : 'Failed to disable the server')); return; }
    // Reads in flight are older than this save: they must not land after it.
    ++configGen;
    ++downstreamGen;
    configLoading = false;
    downstreamLoading = false;
    setServers(servers.map((s) => (s.id === server.id ? data : s)));
    downstreamProviders = downstreamProviders.map((p) => (p.upstream_server_id === server.id ? { ...p, enabled: data.enabled } : p));
  }

  /** Immediate exact-mirror sync (add + refresh + remove) for one server. */
  async function syncNow(server: ServerResponse) {
    syncingNowId = server.id;
    try {
      const { data, error: err } = await adminApi.POST('/api/v1/admin/servers/{id}/actions/sync-now', { params: { path: { id: server.id } } });
      if (err || !data) { toast.error(extractError(err, 'Sync failed')); return; }
      const parts: string[] = [];
      if (data.added) parts.push(`${data.added} added`);
      if (data.refreshed) parts.push(`${data.refreshed} refreshed`);
      if (data.models_removed) parts.push(`${data.models_removed} removed`);
      if (data.routes_disabled) parts.push(`${data.routes_disabled} routes disabled`);
      // An endpoint that did not answer changed nothing — say so, or a sync
      // that removed less than expected reads as a bug.
      const silent = data.endpoints.filter((e) => !e.answered);
      if (silent.length) parts.push(`${silent.length} endpoint${silent.length === 1 ? '' : 's'} did not answer (their models were kept)`);
      toast.success(`Synced ${server.name}`, parts.length ? parts.join(', ') : 'Already up to date');
      await loadConfig();
    } finally {
      syncingNowId = null;
    }
  }

  // -- Sync Models --
  async function openSync(server: ServerResponse) {
    syncServerId = server.id;
    syncServerName = server.name;
    syncResult = null;
    syncError = '';
    syncSelectedNew = new Set();
    syncSelectedRemoved = new Set();
    syncApplying = false;
    showSyncModal = true;
    syncLoading = true;
    try {
      const { data, error: err } = await adminApi.POST('/api/v1/admin/servers/{id}/actions/sync', { params: { path: { id: server.id } }});
      if (err || !data) { syncError = extractError(err, 'Sync failed'); syncLoading = false; return; }
      syncResult = data;
      // Pre-select all new models
      for (const m of syncResult.new_models || []) {
        syncSelectedNew.add(m.id);
      }
      syncSelectedNew = new Set(syncSelectedNew);
    } catch (e) {
      syncError = String(e).replace('Error: ', '');
    } finally {
      syncLoading = false;
    }
  }

  function toggleSyncNew(id: string) {
    const next = new Set(syncSelectedNew);
    if (next.has(id)) next.delete(id); else next.add(id);
    syncSelectedNew = next;
  }

  function toggleSyncRemoved(id: string) {
    const next = new Set(syncSelectedRemoved);
    if (next.has(id)) next.delete(id); else next.add(id);
    syncSelectedRemoved = next;
  }

  async function applySyncChanges() {
    const result = syncResult;
    if (!syncServerId || !result) return;
    syncApplying = true;
    syncError = '';
    try {
      // Add new models
      const newModels = (result.new_models || [])
        .filter((m: DiscoveredModel) => syncSelectedNew.has(m.id))
        .map((m: DiscoveredModel) => ({
          upstream_model: m.id,
          context_window: m.context_window ?? undefined,
          max_output_tokens: m.max_output_tokens ?? undefined,
          supports_vision: m.supports_vision ?? undefined,
          supports_reasoning: m.supports_reasoning ?? undefined,
          supports_function_calling: m.supports_function_calling ?? undefined,
          supports_caching: m.supports_caching ?? undefined,
          supports_audio_input: m.supports_audio_input ?? undefined,
          supports_audio_output: m.supports_audio_output ?? undefined,
          supports_video_input: m.supports_video_input ?? undefined,
          supports_pdf_input: m.supports_pdf_input ?? undefined,
          supports_response_schema: m.supports_response_schema ?? undefined,
          supports_system_messages: m.supports_system_messages ?? undefined,
          // The discovered price list travels as one value — prices and the
          // currency they are quoted in are one provider's quote.
          rates: m.rates ?? undefined,
        }));
      if (newModels.length > 0) {
        // from_discovery: these values are the provider's, not the operator's, so
        // they must stay refreshable — pinning them here would freeze an imported
        // model at the price it happened to carry on the day it was reviewed.
        const { error: addErr } = await adminApi.POST('/api/v1/admin/servers/{id}/models', { params: { path: { id: syncServerId } }, body: { models: newModels, from_discovery: true } });
        if (addErr) { syncError = extractError(addErr, 'Failed to add models'); syncApplying = false; return; }
      }

      // Delete removed models
      const removeIds = (result.removed || [])
        .filter((m: RemovedModelInfo) => syncSelectedRemoved.has(m.id))
        .map((m: RemovedModelInfo) => m.id);
      if (removeIds.length > 0) {
        const { data: delData, error: delErr } = await adminApi.DELETE('/api/v1/admin/servers/{id}/models', { params: { path: { id: syncServerId } }, body: { ids: removeIds } });
        if (delErr) { syncError = extractError(delErr, 'Failed to remove models'); syncApplying = false; return; }
        notifyOrphanImpact(delData);
      }

      showSyncModal = false;
      await loadConfig();
    } catch (e) {
      syncError = String(e).replace('Error: ', '');
    } finally {
      syncApplying = false;
    }
  }

  // -- Model Modal CRUD --
  // Capability + pricing fields, in one place, so the modal, the save builder,
  // and the reset logic stay in sync.
  // Tri-state model overrides ('' inherit / 'true' / 'false'). Capabilities plus
  // the self-healing override — all ride the same inherit/On/Off save + reset path.
  const MODEL_CAP_FIELDS = [
    'supports_vision', 'supports_reasoning', 'supports_function_calling', 'supports_caching',
    'supports_audio_input', 'supports_audio_output', 'supports_video_input', 'supports_pdf_input',
    'supports_response_schema', 'supports_system_messages', 'healing_enabled',
  ] as const;
  // Pricing is a single inheritable field: the whole rate map, with its
  // currency inside it. Half-inherited prices are the borrowed-price hazard the
  // provider-matched resolution ladder exists to prevent, so there is nothing
  // finer-grained to pin or release than this one name.
  const MODEL_PRICE_FIELDS = ['rates'] as const;

  // Inherit with no catalog row leaves reasoning undeclared, and the gateway
  // still asks such a model to reason on a translated request (only a model
  // KNOWN not to reason is spared it). A catalog row is KNOWN when the form
  // links one, or the saved model resolved one and the form keeps its link;
  // an auto-match is decided on save, so the hint is worded conditionally.
  const catalogKnown = $derived(
    !!modelModalForm.catalog_model_id ||
      (!!editingModelData?.resolved_catalog_model_id &&
        modelModalForm.catalog_model_id === (editingModelData.catalog_model_id ?? undefined)),
  );
  const reasoningInheritHint = $derived(
    modelModalForm.supports_reasoning === '' && !catalogKnown
      ? 'Unless a catalog entry matches this model, a request translated from another protocol still asks it to reason. Choose Off to stop it.'
      : undefined,
  );

  /** Provenance badge for a field on the model being edited (undefined in add mode). */
  function modelSource(field: string): FieldSource | undefined {
    return editingModelData?.sources?.[field];
  }

  // Reflect the catalog entry resolution currently applies (link or auto-match)
  // into the picker's selection display.
  function syncSelectedCatalog() {
    const id = editingModelData?.resolved_catalog_model_id ?? modelModalForm.catalog_model_id;
    const entry = id ? catalog.find(c => c.id === id) : undefined;
    selectedCatalog = entry ? { id: entry.id, label: `${entry.provider}/${entry.model}` } : null;
  }

  function openEditModel(model: ModelResponse) {
    editingModelData = model;
    modelModalServerId = model.server_id;
    modelModalForm = {
      upstream_model: model.upstream_model,
      context_window: model.context_window ?? undefined,
      max_output_tokens: model.max_output_tokens ?? undefined,
      upstream_api_format: model.upstream_api_format || 'chat_completions',
      model_type: model.model_type || '',
      enabled: model.enabled,
      catalog_model_id: model.catalog_model_id ?? undefined,
      // Tri-state from the RAW (stored) override — '' when the field inherits, so
      // the editor shows "Inherit" and a save never freezes an inherited value.
      supports_vision: boolToTriState(model.supports_vision),
      supports_reasoning: boolToTriState(model.supports_reasoning),
      supports_function_calling: boolToTriState(model.supports_function_calling),
      supports_caching: boolToTriState(model.supports_caching),
      supports_audio_input: boolToTriState(model.supports_audio_input),
      supports_audio_output: boolToTriState(model.supports_audio_output),
      supports_video_input: boolToTriState(model.supports_video_input),
      supports_pdf_input: boolToTriState(model.supports_pdf_input),
      supports_response_schema: boolToTriState(model.supports_response_schema),
      supports_system_messages: boolToTriState(model.supports_system_messages),
      healing_enabled: boolToTriState(model.healing_enabled),
    };
    // The RAW override drives the editor — `null` means the row inherits, so a
    // save never freezes the catalog's list onto the model.
    modelRates = ratesToForm(model.rates, model.resolved_rates?.currency);
    modelRatesOrig = ratesSignature(model.rates);
    // A model with no price in force bills zero and flags every request, and
    // this modal is where that is fixed — so open on it rather than behind a
    // collapsed section the operator has no reason to expand.
    modelPricingOpen = ratesAreEmpty(model.resolved_rates);
    syncSelectedCatalog();
    modelOrig = {};
    for (const f of [...MODEL_CAP_FIELDS, 'context_window', 'max_output_tokens'] as const) {
      modelOrig[f] = modelModalForm[f];
    }
    modelError = '';
    modelCapabilitiesOpen = false;
    showModelModal = true;
  }

  function openAddModel(serverId: string) {
    editingModelData = null;
    modelModalServerId = serverId;
    modelModalForm = {
      upstream_model: '',
      context_window: undefined,
      max_output_tokens: undefined,
      upstream_api_format: 'chat_completions',
      model_type: '',
      enabled: true,
      catalog_model_id: undefined,
      supports_vision: '',
      supports_reasoning: '',
      supports_function_calling: '',
      supports_caching: '',
      supports_audio_input: '',
      supports_audio_output: '',
      supports_video_input: '',
      supports_pdf_input: '',
      supports_response_schema: '',
      supports_system_messages: '',
      healing_enabled: '',
    };
    modelRates = ratesToForm(null);
    modelRatesOrig = 'inherit';
    modelPricingOpen = false;
    selectedCatalog = null;
    modelError = '';
    modelCapabilitiesOpen = false;
    showModelModal = true;
  }

  // Catalog picker (inherited-from entry). Filters the already-loaded catalog.
  function searchCatalog(query: string): Promise<PickerItem[]> {
    const q = query.trim().toLowerCase();
    const items = catalog
      .filter(c => !q || `${c.provider}/${c.model}`.toLowerCase().includes(q))
      .slice(0, 50)
      .map(c => ({ id: c.id, label: `${c.provider}/${c.model}`, sublabel: c.model_type ?? undefined }));
    return Promise.resolve(items);
  }
  function onSelectCatalog(item: PickerItem | null) {
    selectedCatalog = item;
    modelModalForm.catalog_model_id = item?.id;
  }

  async function handleSaveModel() {
    modelError = '';
    savingModel = true;
    // ADD sends every explicit value (On/Off, an overridden price list); inherited
    // fields are simply omitted. EDIT sends only fields the operator CHANGED: a
    // value switched back to "Inherit" goes in `reset_fields` (release the
    // override), a changed value is sent as a new override, and an untouched field
    // is left alone so a synced/inherited value is never silently re-pinned.
    const editing = !!editingModelData;
    const caps: Record<string, boolean> = {};
    const limits: Record<string, number> = {};
    const reset_fields: string[] = [];
    for (const f of MODEL_CAP_FIELDS) {
      const v = modelModalForm[f];
      if (editing && v === modelOrig[f]) continue;
      if (v === 'true') caps[f] = true;
      else if (v === 'false') caps[f] = false;
      else if (editing) reset_fields.push(f);
    }
    // The whole price list is one pinnable field: send it when the operator
    // edited it, name it in `reset_fields` when they released it back to
    // inherited, and leave it out entirely when they didn't touch it.
    const ratesOverride = formToRates(modelRates);
    const ratesChanged = !editing || ratesSignature(ratesOverride) !== modelRatesOrig;
    const pricing: { rates?: components['schemas']['Rates'] } = {};
    if (ratesChanged) {
      if (ratesOverride) pricing.rates = ratesOverride;
      else if (editing) reset_fields.push(MODEL_PRICE_FIELDS[0]);
    }
    for (const f of ['context_window', 'max_output_tokens'] as const) {
      const v = modelModalForm[f];
      if (editing && v === modelOrig[f]) continue;
      if (v != null && !Number.isNaN(v)) limits[f] = v;
      else if (editing) reset_fields.push(f);
    }
    try {
      if (editingModelData) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/models/{id}', {
          params: { path: { id: editingModelData.id } },
          body: {
            ...limits,
            upstream_api_format: (modelModalForm.upstream_api_format as ModelResponse['upstream_api_format']) || undefined,
            model_type: modelModalForm.model_type || undefined,
            enabled: modelModalForm.enabled,
            // Only a changed link is sent: `null` clears one the model had, an
            // unchanged picker sends nothing (re-sending would re-check a link
            // the save is not about).
            catalog_model_id: (modelModalForm.catalog_model_id || null) === (editingModelData.catalog_model_id ?? null)
              ? undefined
              : (modelModalForm.catalog_model_id || null),
            reset_fields,
            ...caps,
            ...pricing,
          },
        });
        if (err) { modelError = extractError(err, 'Unknown error'); savingModel = false; return; }
      } else if (modelModalServerId) {
        const { error: err } = await adminApi.POST('/api/v1/admin/servers/{id}/models', {
          params: { path: { id: modelModalServerId } },
          body: { models: [{
            upstream_model: modelModalForm.upstream_model,
            context_window: modelModalForm.context_window || undefined,
            max_output_tokens: modelModalForm.max_output_tokens || undefined,
            upstream_api_format: modelModalForm.upstream_api_format || undefined,
            model_type: modelModalForm.model_type || undefined,
            catalog_model_id: modelModalForm.catalog_model_id || undefined,
            ...caps,
            ...pricing,
          }] },
        });
        if (err) { modelError = extractError(err, 'Unknown error'); savingModel = false; return; }
      }
      showModelModal = false;
      editingModelData = null;
      await loadConfig();
    } catch (e) {
      modelError = String(e).replace('Error: ', '');
    } finally {
      savingModel = false;
    }
  }

  async function handleToggleModelEnabled(model: ModelResponse) {
    modelError = '';
    try {
      const { error: err } = await adminApi.PATCH('/api/v1/admin/models/{id}', {
        params: { path: { id: model.id } },
        body: { enabled: !model.enabled },
      });
      if (err) { modelError = extractError(err, 'Failed to toggle model'); return; }
      model.enabled = !model.enabled;
    } catch (e) {
      modelError = String(e).replace('Error: ', '');
    }
  }

  // -- Catalog --
  // Only the latest read lands: a refresh read before a save must not put the
  // old state back after the save's own re-read.
  let catalogGen = 0;
  async function loadCatalog() {
    const gen = ++catalogGen;
    catalogLoading = true;
    try {
      const entries = await fetchAllPages<CatalogEntry>((offset, limit) =>
        adminApi.GET('/api/v1/admin/catalog', { params: { query: { offset, limit } } }));
      if (gen === catalogGen) {
        catalog = entries;
        if (pendingCatalogEntry) showCatalogEntry(pendingCatalogEntry);
      }
    } catch (e) {
      if (gen === catalogGen) toast.error(extractError(e));
    } finally {
      if (gen === catalogGen) catalogLoading = false;
    }
  }

  async function handleBulkUpdateModels(serverId: string, enabled: boolean) {
    bulkModelUpdating = true;
    bulkModelError = '';
    const { error: err } = await adminApi.POST('/api/v1/admin/models/actions/bulk-update', {
      body: { server_id: serverId, enabled },
    });
    if (err) {
      bulkModelError = extractError(err, 'Failed');
    } else {
      bulkModelConfirm = null;
      await loadConfig();
    }
    bulkModelUpdating = false;
  }

  async function handleCatalogBulkAction() {
    if (!catalogBulkAction) return;
    catalogBulkLoading = true;
    catalogBulkError = '';
    try {
      const { error: err } = catalogBulkAction === 'remove-seeded'
        ? await adminApi.POST('/api/v1/admin/catalog/actions/remove-seeded', {})
        : await adminApi.POST('/api/v1/admin/catalog/actions/reset', {});
      if (err) {
        catalogBulkError = extractError(err, 'Failed');
        return;
      }
      catalogBulkAction = null;
      // A removal unlinks the models pinned to its entries: reload them too.
      await Promise.all([loadCatalog(), loadConfig()]);
    } catch (e: unknown) {
      catalogBulkError = e instanceof Error ? e.message : 'Network error';
    } finally {
      catalogBulkLoading = false;
    }
  }

  function openEditCatalog(entry: CatalogEntry) {
    editingCatalogData = entry;
    catalogModalForm = {
      server_id: entry.server_id ?? '',
      provider: entry.provider,
      model: entry.model,
      model_type: entry.model_type || '',
      context_window: entry.context_window ?? undefined,
      max_output_tokens: entry.max_output_tokens ?? undefined,
      output_vector_size: entry.output_vector_size ?? undefined,
      supports_vision: entry.supports_vision === true,
      supports_reasoning: entry.supports_reasoning === true,
      supports_function_calling: entry.supports_function_calling === true,
      supports_caching: entry.supports_caching === true,
      supports_audio_input: entry.supports_audio_input === true,
      supports_audio_output: entry.supports_audio_output === true,
      supports_video_input: entry.supports_video_input === true,
      supports_pdf_input: entry.supports_pdf_input === true,
      supports_response_schema: entry.supports_response_schema === true,
      supports_system_messages: entry.supports_system_messages === true,
    };
    catalogRates = ratesToForm(entry.rates ?? EMPTY_RATES);
    catalogError = '';
    showCatalogModal = true;
  }

  function openAddCatalog() {
    editingCatalogData = null;
    catalogModalForm = {
      server_id: '',
      provider: 'openai',
      model: '',
      model_type: '',
      context_window: undefined,
      max_output_tokens: undefined,
      output_vector_size: undefined,
      supports_vision: false,
      supports_reasoning: false,
      supports_function_calling: false,
      supports_caching: false,
      supports_audio_input: false,
      supports_audio_output: false,
      supports_video_input: false,
      supports_pdf_input: false,
      supports_response_schema: false,
      supports_system_messages: false,
    };
    catalogRates = ratesToForm(EMPTY_RATES);
    catalogError = '';
    showCatalogModal = true;
  }

  async function handleSaveCatalog() {
    catalogError = '';
    const catCaps = {
      supports_vision: catalogModalForm.supports_vision || undefined,
      supports_reasoning: catalogModalForm.supports_reasoning || undefined,
      supports_function_calling: catalogModalForm.supports_function_calling || undefined,
      supports_caching: catalogModalForm.supports_caching || undefined,
      supports_audio_input: catalogModalForm.supports_audio_input || undefined,
      supports_audio_output: catalogModalForm.supports_audio_output || undefined,
      supports_video_input: catalogModalForm.supports_video_input || undefined,
      supports_pdf_input: catalogModalForm.supports_pdf_input || undefined,
      supports_response_schema: catalogModalForm.supports_response_schema || undefined,
      supports_system_messages: catalogModalForm.supports_system_messages || undefined,
    };
    // The whole price list, as one atom. The editor never leaves the overriding
    // state here (the catalog inherits from nothing), so this is always a map —
    // an empty one being the operator saying no price is known.
    const catRates = formToRates(catalogRates) ?? EMPTY_RATES;
    let savedId: string | null = null;
    try {
      if (editingCatalogData) {
        const { error: err } = await adminApi.PATCH('/api/v1/admin/catalog/{id}', {
          params: { path: { id: editingCatalogData.id } },
          body: { ...catalogPatch(editingCatalogData, catalogModalForm), rates: catRates },
        });
        if (err) { catalogError = extractError(err, 'Unknown error'); return; }
        savedId = editingCatalogData.id;
      } else {
        const { data: created, error: err } = await adminApi.POST('/api/v1/admin/catalog', {
          body: {
            server_id: catalogModalForm.server_id || undefined,
            provider: catalogModalForm.provider,
            model: catalogModalForm.model,
            model_type: catalogModalForm.model_type || undefined,
            context_window: catalogModalForm.context_window || undefined,
            max_output_tokens: catalogModalForm.max_output_tokens || undefined,
            output_vector_size: catalogModalForm.output_vector_size || undefined,
            rates: catRates,
            ...catCaps,
          },
        });
        if (err) { catalogError = extractError(err, 'Unknown error'); return; }
        savedId = created?.id ?? null;
      }
      showCatalogModal = false;
      editingCatalogData = null;
      await loadCatalog();
      showCatalogEntry(savedId);
    } catch (e) {
      catalogError = String(e).replace('Error: ', '');
    }
  }

  // -- Delete --
  function confirmDeleteServer(server: ServerResponse) {
    const modelCount = (modelsByServer[server.id] || []).length;
    deleteTarget = { type: 'server', id: server.id, label: `${server.name} (${modelCount} models)` };
  }

  function confirmDeleteModel(model: ModelResponse) {
    deleteTarget = { type: 'model', id: model.id, label: model.upstream_model, serverId: model.server_id };
  }

  function confirmDeleteCatalog(entry: CatalogEntry) {
    deleteTarget = { type: 'catalog', id: entry.id, label: `${entry.provider}/${entry.model}` };
  }

  let deleteError = $state('');

  function cancelDelete() { deleteTarget = null; deleteError = ''; }

  // Surface the orphaned-route fallout of a delete (model/server) so the operator
  // knows which downstreams now hold a dead route to clean up.
  function notifyOrphanImpact(data: { message?: string | null; impact?: components['schemas']['ActionImpact'] | null } | undefined) {
    if (orphanedRoutes(data) > 0 && data?.message) toast.warning('Routes orphaned', data.message);
  }

  async function executeDelete() {
    if (!deleteTarget) return;
    deleting = true;
    deleteError = '';
    if (deleteTarget.type === 'server') {
      const { data, error: err } = await adminApi.DELETE('/api/v1/admin/servers/{id}', { params: { path: { id: deleteTarget.id } } });
      if (err) { deleteError = extractError(err, 'Failed to delete server'); deleting = false; return; }
      notifyOrphanImpact(data);
      // A server delete may drop its downstream (a mirror, a pass-through).
      await Promise.all([loadConfig(), loadDownstreamProviders()]);
    } else if (deleteTarget.type === 'model') {
      const { data, error: err } = await adminApi.DELETE('/api/v1/admin/models/{id}', { params: { path: { id: deleteTarget.id } } });
      if (err) { deleteError = extractError(err, 'Failed to delete model'); deleting = false; return; }
      notifyOrphanImpact(data);
      await loadConfig();
    } else {
      const { error: err } = await adminApi.DELETE('/api/v1/admin/catalog/{id}', { params: { path: { id: deleteTarget.id } } });
      if (err) { deleteError = extractError(err, 'Failed to delete catalog entry'); deleting = false; return; }
      // A removal unlinks the models pinned to the entry: reload them too.
      await Promise.all([loadCatalog(), loadConfig()]);
    }
    deleteTarget = null;
    deleteError = '';
    deleting = false;
  }
</script>

<!-- ===== Delete Confirmation Modal ===== -->
{#if deleteTarget}
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4">
    <button class="absolute inset-0 bg-(--bg-scrim-strong) backdrop-blur-xs cursor-default" onclick={cancelDelete} tabindex="-1" aria-label="Close dialog"></button>
    <div class="relative bg-(--bg-secondary) border border-(--border) rounded-2xl shadow-2xl max-w-sm w-full p-6 animate-modal-in" role="dialog" aria-modal="true" tabindex="-1">
      <div class="w-12 h-12 rounded-full bg-(--error)/10 flex items-center justify-center mx-auto mb-4">
        <Icon name="triangleAlert" size="lg" tone="error" />
      </div>
      <h3 class="text-lg font-semibold text-(--text-primary) text-center">
        Delete {deleteTarget.type === 'server' ? 'Server' : deleteTarget.type === 'model' ? 'Model' : 'Catalog Entry'}?
      </h3>
      <p class="text-sm text-(--text-secondary) text-center mt-2">This will permanently remove:</p>
      <p class="text-center mt-1">
        <code class="text-sm font-mono text-(--text-primary) bg-(--bg-primary) px-2 py-0.5 rounded-sm">{deleteTarget.label}</code>
      </p>
      {#if deleteTarget.type === 'server'}
        <p class="text-xs text-(--error) text-center mt-2">All models on this server will also be deleted.</p>
      {/if}
      {#if deleteTarget.type === 'server' || deleteTarget.type === 'model'}
        <p class="text-xs text-(--text-secondary) text-center mt-2">
          Any custom downstream route using {deleteTarget.type === 'server' ? 'these models' : 'this model'} will be
          <span class="text-(--warning)">disabled (orphaned)</span> for you to clean up — never silently removed.
        </p>
      {/if}
      <p class="text-xs text-(--error) text-center mt-3">This action cannot be undone.</p>
      {#if deleteError}
        <div class="mt-3 px-3 py-2 bg-(--error)/10 border border-(--error) rounded-lg text-xs text-(--error)">{deleteError}</div>
      {/if}
      <div class="flex gap-3 mt-6">
        <button onclick={cancelDelete} class="flex-1 px-4 py-2.5 rounded-lg border border-(--border) text-sm font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors">Cancel</button>
        <button onclick={executeDelete} disabled={deleting} class="flex-1 px-4 py-2.5 rounded-lg bg-(--error) hover:bg-(--error)/85 text-(--error-fg) text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2">
          {#if deleting}<Spinner />{/if}
          Delete
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ===== Bulk Disable All Models Confirmation ===== -->
{#if bulkModelConfirm}
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4">
    <button class="absolute inset-0 bg-(--bg-scrim-strong) backdrop-blur-xs cursor-default" onclick={() => bulkModelConfirm = null} tabindex="-1" aria-label="Close dialog"></button>
    <div class="relative bg-(--bg-secondary) border border-(--border) rounded-2xl shadow-2xl max-w-sm w-full p-6 animate-modal-in" role="dialog" aria-modal="true" tabindex="-1">
      <div class="w-12 h-12 rounded-full bg-(--error)/10 flex items-center justify-center mx-auto mb-4">
        <Icon name="triangleAlert" size="lg" tone="error" />
      </div>
      <h3 class="text-lg font-semibold text-(--text-primary) text-center">Disable All Models?</h3>
      <p class="text-sm text-(--text-secondary) text-center mt-2">This will disable all <strong>{bulkModelConfirm.modelCount}</strong> models on <strong>{bulkModelConfirm.serverName}</strong>.</p>
      <p class="text-xs text-(--error) text-center mt-2">No traffic will be routed to this server until models are re-enabled.</p>
      {#if bulkModelError}
        <div class="mt-3 px-3 py-2 bg-(--error)/10 border border-(--error) rounded-lg text-xs text-(--error)">{bulkModelError}</div>
      {/if}
      <div class="flex gap-3 mt-6">
        <button onclick={() => bulkModelConfirm = null} class="flex-1 px-4 py-2.5 rounded-lg border border-(--border) text-sm font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors">Cancel</button>
        <button onclick={() => { if (bulkModelConfirm) handleBulkUpdateModels(bulkModelConfirm.serverId, false); }} disabled={bulkModelUpdating} class="flex-1 px-4 py-2.5 rounded-lg bg-(--error) hover:bg-(--error)/85 text-(--error-fg) text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2">
          {#if bulkModelUpdating}<Spinner />{/if}
          Disable All
        </button>
      </div>
    </div>
  </div>
{/if}

<!-- ===== Catalog Bulk Action Confirmation ===== -->
{#if catalogBulkAction}
  <div class="fixed inset-0 z-50 flex items-center justify-center p-4">
    <button class="absolute inset-0 bg-(--bg-scrim-strong) backdrop-blur-xs cursor-default" onclick={() => catalogBulkAction = null} tabindex="-1" aria-label="Close dialog"></button>
    <div class="relative bg-(--bg-secondary) border border-(--border) rounded-2xl shadow-2xl max-w-sm w-full p-6 animate-modal-in" role="dialog" aria-modal="true" tabindex="-1">
      <div class="w-12 h-12 rounded-full bg-(--error)/10 flex items-center justify-center mx-auto mb-4">
        <Icon name="triangleAlert" size="lg" tone="error" />
      </div>
      {#if catalogBulkAction === 'remove-seeded'}
        <h3 class="text-lg font-semibold text-(--text-primary) text-center">Remove All Seeded Entries?</h3>
        <p class="text-sm text-(--text-secondary) text-center mt-2">This will remove all <strong>{seededCount}</strong> built-in catalog entries. Custom entries will be kept.</p>
        <p class="text-xs text-(--text-secondary) text-center mt-2">Removed entries will not reappear on restart.</p>
      {:else}
        <h3 class="text-lg font-semibold text-(--text-primary) text-center">Reset Entire Catalog?</h3>
        <p class="text-sm text-(--text-secondary) text-center mt-2">This will remove all <strong>{catalog.length}</strong> entries (built-in and custom), then re-seed from the default model database.</p>
        <p class="text-xs text-(--error) text-center mt-2">Custom pricing and manually added entries will be lost.</p>
      {/if}
      {#if catalogBulkError}
        <div class="mt-3 px-3 py-2 bg-(--error)/10 border border-(--error) rounded-lg text-xs text-(--error)">{catalogBulkError}</div>
      {/if}
      <div class="flex gap-3 mt-6">
        <button onclick={() => catalogBulkAction = null} class="flex-1 px-4 py-2.5 rounded-lg border border-(--border) text-sm font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors">Cancel</button>
        <button onclick={handleCatalogBulkAction} disabled={catalogBulkLoading} class="flex-1 px-4 py-2.5 rounded-lg bg-(--error) hover:bg-(--error)/85 text-(--error-fg) text-sm font-medium transition-colors disabled:opacity-50 flex items-center justify-center gap-2">
          {#if catalogBulkLoading}<Spinner />{/if}
          {catalogBulkAction === 'remove-seeded' ? 'Remove Seeded' : 'Reset Catalog'}
        </button>
      </div>
    </div>
  </div>
{/if}

<ServerWizard
  open={showWizard}
  onclose={() => (showWizard = false)}
  oncreated={(serverId) => {
    showWizard = false;
    // Land on the new server rather than back on the table: what comes next —
    // its endpoints, its models, its capacity — all lives there.
    void goto(thref(tenantSlug, `/gateways/llm/servers/${serverId}`));
  }}
/>

<!-- ===== Sync Models Modal ===== -->
<Modal open={showSyncModal} title="Sync Models" onclose={() => showSyncModal = false}>
  <p class="text-sm text-(--text-secondary) mb-4">Discover models on <span class="font-medium text-(--text-primary)">{syncServerName}</span></p>

  {#if syncLoading}
    <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
      <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
      Discovering models...
    </div>
  {:else if syncError && !syncResult}
    <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
      <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
      <p class="text-sm text-(--error)">{syncError}</p>
    </div>
  {:else if syncResult}
    {@const sync = syncResult}
    {#if sync.endpoints.length > 1 || sync.endpoints.some((e) => !e.answered || e.kept)}
      <div class="mb-6 space-y-1" data-testid="sync-endpoints">
        <h4 class="text-sm font-semibold text-(--text-secondary) mb-1">Endpoints</h4>
        {#each sync.endpoints as ep (ep.endpoint_id)}
          <p class="text-xs text-(--text-secondary)">
            <span class="font-mono text-(--text-primary)">{ep.url}</span> —
            {#if !ep.answered}
              did not answer ({ep.reason ?? 'no reason given'}): its models were kept, nothing removed
            {:else if ep.kept}
              listed {ep.listed}; the ones it omitted were kept ({ep.kept.replaceAll('_', ' ')})
            {:else}
              listed {ep.listed}
            {/if}
          </p>
        {/each}
      </div>
    {/if}
    <!-- New models -->
    {#if (sync.new_models || []).length > 0}
      <div class="mb-6">
        <div class="flex items-center justify-between mb-2">
          <h4 class="text-sm font-semibold text-(--success)">New Models ({sync.new_models.length})</h4>
          <button onclick={() => {
            if (syncSelectedNew.size === sync.new_models.length) {
              syncSelectedNew = new Set();
            } else {
              syncSelectedNew = new Set(sync.new_models.map((m: DiscoveredModel) => m.id));
            }
          }} class="text-xs text-(--accent) hover:text-(--accent-hover)">
            {syncSelectedNew.size === sync.new_models.length ? 'Select None' : 'Select All'}
          </button>
        </div>
        <div class="space-y-1.5">
          {#each sync.new_models as model}
            <label class="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-(--bg-elevated) transition-colors cursor-pointer">
              <input type="checkbox" checked={syncSelectedNew.has(model.id)} onchange={() => toggleSyncNew(model.id)} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" />
              <span class="font-mono text-sm text-(--text-primary) flex-1">{model.id}</span>
              {#if model.context_window}
                <span class="text-xs text-(--text-secondary)">{(model.context_window / 1000).toFixed(0)}k ctx</span>
              {/if}
            </label>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Existing models -->
    {#if (sync.existing || []).length > 0}
      <div class="mb-6">
        <h4 class="text-sm font-semibold text-(--text-secondary) mb-2">Existing Models ({sync.existing.length})</h4>
        <div class="space-y-1">
          {#each sync.existing as model}
            <div class="flex items-center gap-3 px-3 py-2 rounded-lg opacity-60">
              <Icon name="check" size="sm" tone="success" />
              <span class="font-mono text-sm text-(--text-primary)">{model.upstream_model}</span>
            </div>
          {/each}
        </div>
      </div>
    {/if}

    <!-- Removed models -->
    {#if (sync.removed || []).length > 0}
      <div class="mb-6">
        <div class="flex items-center justify-between mb-2">
          <h4 class="text-sm font-semibold text-(--warning)">Removed Models ({sync.removed.length})</h4>
          <button onclick={() => {
            if (syncSelectedRemoved.size === sync.removed.length) {
              syncSelectedRemoved = new Set();
            } else {
              syncSelectedRemoved = new Set(sync.removed.map((m: RemovedModelInfo) => m.id));
            }
          }} class="text-xs text-(--accent) hover:text-(--accent-hover)">
            {syncSelectedRemoved.size === sync.removed.length ? 'Select None' : 'Select All'}
          </button>
        </div>
        <div class="space-y-1.5">
          {#each sync.removed as model}
            <label class="flex items-center gap-3 px-3 py-2 rounded-lg hover:bg-(--bg-elevated) transition-colors cursor-pointer">
              <input type="checkbox" checked={syncSelectedRemoved.has(model.id)} onchange={() => toggleSyncRemoved(model.id)} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" />
              <span class="font-mono text-sm text-(--text-primary) flex-1">{model.upstream_model}</span>
              {#if model.in_use}
                <span class="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium bg-(--error)/15 text-(--error)" title="This model has hand-built routes — removing it keeps them as orphaned (disabled, flagged) for you to clean up, never deleted">
                  <Icon name="triangleAlert" size="sm" tone="warning" />
                  In use{#if model.route_count} ({model.route_count} {model.route_count === 1 ? 'route' : 'routes'}){/if}
                </span>
              {/if}
            </label>
          {/each}
        </div>
      </div>
    {/if}

    <!-- No changes -->
    {#if (sync.new_models || []).length === 0 && (sync.removed || []).length === 0}
      <div class="py-8 text-center">
        <div class="mx-auto mb-2 inline-block"><Icon name="check" size="lg" tone="success" /></div>
        <p class="text-(--text-secondary)">All models are in sync</p>
      </div>
    {/if}

    {#if syncError}
      <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg mb-4">
        <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
        <p class="text-sm text-(--error)">{syncError}</p>
      </div>
    {/if}
  {/if}

  <div class="flex gap-3 mt-4">
    {#if syncResult && (syncSelectedNew.size > 0 || syncSelectedRemoved.size > 0)}
      <button onclick={applySyncChanges} disabled={syncApplying} class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-all disabled:opacity-50 flex items-center gap-2">
        {#if syncApplying}<Spinner />{/if}
        Apply Changes ({syncSelectedNew.size} add, {syncSelectedRemoved.size} remove)
      </button>
    {/if}
    <button onclick={() => showSyncModal = false} class="px-5 py-2 border border-(--border) rounded-lg text-(--text-secondary) text-sm hover:text-(--text-primary) transition-colors">Close</button>
  </div>
</Modal>

{#if collisions.length > 0}
  <div class="px-6 pt-4">
    <Callout
      severity="warning"
      title={`${collisions.length} model alias${collisions.length === 1 ? '' : 'es'} resolve to different upstream models across providers`}
    >
      {#snippet children()}
        <ul class="mt-1 space-y-1 text-xs">
          {#each collisions as c (c.alias)}
            <li>
              <span class="font-mono text-(--text-primary)">{c.alias}</span>
              <span class="text-(--text-secondary)">
                → {c.targets.map((t) => `${t.provider_name}:${t.upstream_model}`).join(' · ')}</span>
            </li>
          {/each}
        </ul>
        <p class="mt-1.5 text-xs text-(--text-tertiary)">
          A request for one of these aliases load-balances across the listed models. Each
          conversation is automatically pinned to one model for its whole session so the
          provider's prompt cache keeps hitting across turns; distinct conversations are spread by
          weight. If that's unintended, give the routes distinct aliases.
        </p>
      {/snippet}
    </Callout>
  </div>
{/if}

{#snippet providerBody(provider: DownstreamProvider, keepRoute: (route: DownstreamRoute) => boolean)}
              {@const providerRoutes = allProviderRoutes[provider.id] ?? []}
              {@const visibleRoutes = providerRoutes.filter(keepRoute)}
              {@const ptPolicies = passthroughPolicies[provider.id] ?? []}
              {@const ptExpanded = passthroughExpanded.has(provider.id)}
              {@const ptLoading = passthroughLoading[provider.id] ?? false}
              {@const ptError = passthroughError[provider.id] ?? ''}
              {@const ptShowAdd = passthroughShowAdd.has(provider.id)}
              <div class="border-t border-(--border)">
                  {#if provider.byok}
                    <p class="px-5 py-3 text-xs text-(--text-secondary) border-b border-(--border)">
                      BYOK pass-through. Every model not listed here passes through to the provider with the client's own credential.
                      {visibleRoutes.length > 0 ? 'The routes below override specific models with your own upstream.' : 'Add a route to override a single model (e.g. point a fast-tier model at an on-prem upstream) — the rest still pass through.'}
                    </p>
                  {/if}
                  {#if visibleRoutes.length > 0}
                    <table class="w-full text-sm">
                      <thead>
                        <tr class="border-b border-(--border) bg-(--bg-primary)/30">
                          <th class="px-5 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Alias</th>
                          <th class="px-5 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Upstream Model</th>
                          <th class="px-5 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Server</th>
                          <th class="px-5 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">CW</th>
                          <th class="px-5 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">P/W</th>
                          <th class="px-5 py-2.5 text-center text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Status</th>
                          <th class="px-5 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {#each visibleRoutes as route}
                          <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors">
                            <td class="px-5 py-2.5 font-medium text-(--text-primary) font-mono">
                              {route.alias || '--'}
                              {#if route.model_type && route.model_type !== 'text'}
                                <span class="ml-1.5 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium {modelTypeBadgeClass(route.model_type)}">{route.model_type}</span>
                              {/if}
                              {#if route.resolved_supports_vision}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-teal-bg) text-(--success)">vision</span>{/if}
                              {#if route.resolved_supports_function_calling}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--warning-bg) text-(--warning)">tools</span>{/if}
                              {#if route.resolved_supports_reasoning}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-violet-bg) text-(--tag-violet-text)">reasoning</span>{/if}
                              {#if route.resolved_supports_caching}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-blue-bg) text-(--tag-blue-text)">cache</span>{/if}
                              {#if route.resolved_supports_audio_input}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-cyan-bg) text-(--tag-cyan-text)">audio-in</span>{/if}
                              {#if route.resolved_supports_audio_output}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-cyan-bg) text-(--tag-cyan-text)">audio-out</span>{/if}
                              {#if route.resolved_supports_video_input}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-pink-bg) text-(--tag-pink-text)">video</span>{/if}
                              {#if route.resolved_supports_pdf_input}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-orange-bg) text-(--tag-orange-text)">pdf</span>{/if}
                              {#if route.resolved_supports_response_schema}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-teal-bg) text-(--tag-teal-text)">schema</span>{/if}
                              {#if !route.resolved_supports_system_messages}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--error-bg) text-(--error)">no-system</span>{/if}
                              {#if route.cache_preset_name}<span class="ml-1 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-violet-bg) text-(--tag-violet-text)" title="Responses on this alias are served from the &quot;{route.cache_preset_name}&quot; cache preset.">cached</span>{/if}
                              {#each route.client_slots ?? [] as slot (slot)}<span class="ml-1"><TagBadge color="teal" title="Clients use this alias as their {slot} model.">{slot} slot</TagBadge></span>{/each}
                            </td>
                            <td class="px-5 py-2.5 text-(--text-secondary) font-mono">{route.upstream_model || '--'}</td>
                            <td class="px-5 py-2.5">
                              <span class="inline-flex items-center gap-1.5 text-xs text-(--text-secondary)">
                                <ProviderIcon name={route.provider || 'custom'} size="sm" className="shrink-0" />
                                {route.server_name || '--'}
                              </span>
                            </td>
                            <td class="px-5 py-2.5 text-right font-mono text-(--text-secondary)">{route.client_context_window ? `${(route.client_context_window / 1000).toFixed(0)}k` : '--'}</td>
                            <td class="px-5 py-2.5 text-right font-mono text-(--text-secondary)">{route.priority ?? 0}/{route.weight ?? 1}</td>
                            <td class="px-5 py-2.5 text-center">
                              <div class="flex items-center justify-center gap-1">
                                <button
                                  onclick={() => handleToggleRouteEnabled(provider.id, route)}
                                  disabled={route.model_id === null}
                                  class="w-7 h-3.5 rounded-full relative transition-colors {route.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'} {route.model_id === null ? 'opacity-40 cursor-not-allowed' : ''}"
                                  title={route.model_id === null ? 'Orphaned — its model was deleted. Repoint (Edit) or delete this route.' : (route.enabled ? 'Enabled' : 'Disabled')}
                                >
                                  <span class="absolute top-0.5 {route.enabled ? 'right-0.5' : 'left-0.5'} w-2.5 h-2.5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all"></span>
                                </button>
                                {#if route.auto_synced}
                                  <span class="text-[9px] text-(--tag-blue-text)" title="Auto-synced from upstream">S</span>
                                {/if}
                                {#if route.disabled_reason === 'upstream_model_deleted'}
                                  <span class="inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--error-bg) text-(--error)" title="The upstream model was deleted — this route is orphaned. Delete it or repoint it to another model.">orphaned</span>
                                {:else if route.disabled_reason === 'upstream_model_vanished'}
                                  <span class="inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-orange-bg) text-(--tag-orange-text)" title="The upstream model vanished from the provider — this route is re-enabled automatically if it returns.">unavailable</span>
                                {/if}
                              </div>
                            </td>
                            <td class="px-5 py-2.5 text-right">
                              <div class="flex items-center justify-end gap-3">
                                <button onclick={() => openEditRoute(provider.id, route)} class="text-xs text-(--accent) hover:underline font-medium">Edit</button>
                                <button onclick={() => handleDeleteRoute(provider.id, route.id)} class="text-xs text-(--error) hover:underline font-medium">Delete</button>
                              </div>
                            </td>
                          </tr>
                        {/each}
                      </tbody>
                    </table>
                  {:else}
                    <div class="px-6 py-6 text-center text-sm text-(--text-secondary)">
                      No routes configured. Add a route to map model aliases to upstream servers.
                    </div>
                  {/if}
                  {#if routeError}
                    <div class="flex items-start gap-2 px-3.5 py-3 mx-4 mb-3 bg-(--error)/10 border border-(--error) rounded-lg">
                      <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
                      <p class="text-sm text-(--error)">{routeError}</p>
                    </div>
                  {/if}

                  <!-- Forwarded paths -->
                  <div class="border-t border-(--border)">
                    <button
                      onclick={() => togglePassthroughSection(provider.id)}
                      class="flex items-center gap-2 w-full px-5 py-3 text-left hover:bg-(--bg-elevated) transition-colors"
                    >
                      <span class="inline-flex transition-transform {ptExpanded ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
                      <span class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider">Forwarded paths</span>
                      <span class="px-1.5 py-0.5 text-[10px] font-mono rounded-full bg-(--bg-primary) text-(--text-secondary) border border-(--border)">{ptPolicies.length}</span>
                    </button>

                    {#if ptExpanded}
                      <div class="px-5 pb-4">
                        {#if ptLoading}
                          <div class="flex items-center gap-2 py-4 justify-center text-(--text-secondary) text-sm">
                            <div class="w-4 h-4 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
                            Loading forwarded paths…
                          </div>
                        {:else}
                          {#if ptPolicies.length > 0}
                            <table class="w-full text-sm mb-3">
                              <thead>
                                <tr class="border-b border-(--border) bg-(--bg-primary)/30">
                                  <th class="px-4 py-2 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Path</th>
                                  <th class="px-4 py-2 text-center text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Status</th>
                                  <th class="px-4 py-2 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
                                </tr>
                              </thead>
                              <tbody>
                                {#each ptPolicies as policy}
                                  <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors">
                                    <td class="px-4 py-2 font-mono text-sm text-(--text-primary)">{policy.path_pattern}</td>
                                    <td class="px-4 py-2 text-center">
                                      <button
                                        onclick={() => handleTogglePassthrough(provider.id, policy)}
                                        class="w-7 h-3.5 rounded-full relative transition-colors {policy.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'}"
                                        title={policy.enabled ? 'Enabled' : 'Disabled'}
                                      >
                                        <span class="absolute top-0.5 {policy.enabled ? 'right-0.5' : 'left-0.5'} w-2.5 h-2.5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all"></span>
                                      </button>
                                    </td>
                                    <td class="px-4 py-2 text-right">
                                      <button onclick={() => handleDeletePassthrough(provider.id, policy.id)} class="text-xs text-(--error) hover:underline font-medium">Remove</button>
                                    </td>
                                  </tr>
                                {/each}
                              </tbody>
                            </table>
                          {:else}
                            <p class="text-sm text-(--text-secondary) py-2">No forwarded paths. Add a path to forward it as-is through this downstream provider (no analysis or filtering).</p>
                          {/if}

                          {#if ptError}
                            <div class="flex items-start gap-2 px-3.5 py-3 mb-3 bg-(--error)/10 border border-(--error) rounded-lg">
                              <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
                              <p class="text-sm text-(--error)">{ptError}</p>
                            </div>
                          {/if}

                          {#if ptShowAdd}
                            <div class="flex items-center gap-2 mt-2">
                              <input
                                bind:value={passthroughNewPath[provider.id]}
                                placeholder="/v1/custom/path"
                                class="flex-1 px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono focus:outline-hidden focus:border-(--accent) transition-colors"
                                onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter') handleCreatePassthrough(provider.id); }}
                              />
                              <button
                                onclick={() => handleCreatePassthrough(provider.id)}
                                disabled={!(passthroughNewPath[provider.id] ?? '').trim()}
                                class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium disabled:opacity-50 transition-colors"
                              >
                                Save
                              </button>
                              <button
                                onclick={() => { const next = new Set(passthroughShowAdd); next.delete(provider.id); passthroughShowAdd = next; passthroughNewPath = { ...passthroughNewPath, [provider.id]: '' }; }}
                                class="px-3 py-1.5 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-xs font-medium transition-colors"
                              >
                                Cancel
                              </button>
                            </div>
                          {:else}
                            <button
                              onclick={() => { const next = new Set(passthroughShowAdd); next.add(provider.id); passthroughShowAdd = next; }}
                              class="mt-2 text-xs text-(--accent) hover:underline font-medium"
                            >
                              + Add Path
                            </button>
                          {/if}
                        {/if}
                      </div>
                    {/if}
                  </div>
              </div>
{/snippet}

<TabbedPage
  title="LLM Gateway"
  tabs={[{ id: 'downstream', label: 'Downstream' }, { id: 'upstream', label: 'Upstream' }, { id: 'passthrough', label: 'Pass-through' }]}
  activeTab={tab.current}
  onTabChange={switchLlmTab}
>
  {#snippet actions()}
    {#if tab.current === 'upstream' || tab.current === 'passthrough'}
      <button onclick={() => (showWizard = true)} data-testid="add-server" class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">+ Add Server</button>
    {:else if tab.current === 'downstream'}
      <button onclick={() => showNewProvider = !showNewProvider} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">
        {showNewProvider ? 'Cancel' : '+ New Downstream'}
      </button>
    {/if}
  {/snippet}

  {#snippet children(active: LlmTab)}
  <!-- ===== Downstream Tab ===== -->
  {#if active === 'downstream'}
    {#if showNewProvider}
      <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mb-4">
          <label class="block text-xs text-(--text-secondary) mb-1.5 uppercase tracking-wider">Provider Name <span class="text-(--error)">*</span>
            <input bind:value={newProviderName} placeholder="e.g. Internal API" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
          </label>
          <label class="block text-xs text-(--text-secondary) mb-1.5 uppercase tracking-wider">Description
            <input bind:value={newProviderDesc} placeholder="Optional description" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
          </label>
        </div>
        <div class="mb-4">
          <span class="block text-xs text-(--text-secondary) mb-1.5 uppercase tracking-wider">Icon</span>
          <div class="flex flex-wrap gap-1.5">
            {#each Object.entries(PROVIDER_ICONS) as [key, pi]}
              <button
                type="button"
                onclick={() => newProviderIcon = newProviderIcon === key ? '' : key}
                class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors border {newProviderIcon === key ? 'bg-(--accent)/15 border-(--accent) text-(--accent)' : 'bg-(--bg-primary) border-(--border) text-(--text-secondary) hover:text-(--text-primary)'}"
              >
                <ProviderIcon name={key} size="md" className="shrink-0" />
                {pi.name}
              </button>
            {/each}
          </div>
        </div>
        {#if providerError}
          <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg mb-4">
            <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
            <p class="text-sm text-(--error)">{providerError}</p>
          </div>
        {/if}
        <button onclick={handleCreateProvider} disabled={creatingProvider || !newProviderName.trim()} class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">
          {creatingProvider ? 'Creating…' : 'Create Downstream'}
        </button>
      </div>
    {/if}


    {#if providerError && !showNewProvider && !editingProviderId}
      <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
        <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
        <p class="text-sm text-(--error)">{providerError}</p>
      </div>
    {/if}

    {#if passthroughProviders.length > 0}
      <p class="text-xs text-(--text-secondary)" data-testid="passthrough-pointer">
        {passthroughProviders.length} pass-through provider{passthroughProviders.length === 1 ? '' : 's'} — clients bring their own key — on the
        <button type="button" onclick={() => switchLlmTab('passthrough')} class="text-(--accent) hover:underline font-medium">Pass-through tab</button>.
      </p>
    {/if}
    {#if downstreamView.skeleton}
      <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
        <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
        Loading downstream providers…
      </div>
    {:else if visibleDownstreamProviders.length === 0}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) py-12 text-center">
        <p class="text-(--text-secondary)">No downstream providers configured</p>
        <p class="text-sm text-(--text-secondary) mt-1">Use “+ New Downstream” above to define model routing policies for clients</p>
      </div>
    {:else}
      <div class="max-w-sm">
        <FilterInput bind:value={downstreamFilter} placeholder="Filter providers..." matchInfo={downstreamFilterInfo} />
      </div>
      <div class="space-y-4">
        {#each filteredDownstreamProviders as provider}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden hover:border-(--accent) transition-colors">
            <!-- Provider header -->
            <div class="flex items-center justify-between px-6 py-4">
              <button
                onclick={() => toggleProvider(provider.id)}
                class="flex items-center gap-3 text-left hover:opacity-80 transition-opacity"
              >
                <span class="inline-flex transition-transform {expandedProviderIds.has(provider.id) ? 'rotate-90' : ''}"><Icon name="chevronRight" tone="neutral" /></span>
                <ProviderIcon name={provider.icon || 'custom'} size="lg" className="text-(--text-secondary) shrink-0" />
                <div>
                  <span class="text-sm font-semibold text-(--text-primary)">{provider.name}</span>
                  {#if provider.description}
                    <span class="text-xs text-(--text-secondary) ml-2">{provider.description}</span>
                  {/if}
                </div>
                <span class="ml-2 px-2 py-0.5 text-[10px] font-mono rounded-full bg-(--bg-primary) text-(--text-secondary) border border-(--border)">{provider.route_count ?? 0} routes</span>
                {#if provider.upstream_server_id}
                  <span class="ml-1 px-2 py-0.5 text-[10px] font-medium rounded-full bg-(--tag-blue-bg) text-(--tag-blue-text)">mirror</span>
                {/if}
              </button>
              <div class="flex items-center gap-2">
                <button onclick={() => openEditProvider(provider)} class="px-3 py-1.5 text-xs text-(--accent) hover:underline font-medium">Edit</button>
                <button onclick={() => openAddRoute(provider.id)} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors">+ Add Route</button>
                <button onclick={() => handleDeleteProvider(provider.id)} class="px-3 py-1.5 text-xs text-(--error) hover:underline font-medium">Delete</button>
              </div>
            </div>

            <!-- Expanded content -->
            {#if expandedProviderIds.has(provider.id)}
              {@render providerBody(provider, routeMatchesDownstreamFilter)}
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  {/if}

  <!-- ===== Pass-through Tab ===== -->
  {#if active === 'passthrough'}
    <p class="text-sm text-(--text-secondary)">
      Clients bring their own provider key: a BYOK (<span class="font-mono">vk-</span>) key passes every model not overridden here
      straight to the provider with the client's own credential. Switch a provider on here, then grant it from a workspace's Access tab.
    </p>
    {#if providerError && !editingProviderId}
      <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
        <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
        <p class="text-sm text-(--error)">{providerError}</p>
      </div>
    {/if}
    <!-- A card reads its server (switch, endpoint, Delete): both lists load first. -->
    {#if downstreamView.skeleton || configView.skeleton}
      <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
        <Spinner />
        Loading pass-through providers…
      </div>
    {:else if passthroughProviders.length === 0}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) py-12 text-center">
        <p class="text-(--text-secondary)">No pass-through providers</p>
        <p class="text-sm text-(--text-secondary) mt-1">Use “+ Add Server” above and choose BYOK pass-through.</p>
      </div>
    {:else}
      <div class="space-y-4">
        {#each passthroughProviders as provider (provider.id)}
          {@const server = serverOf(provider)}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden" data-testid="passthrough-card">
            <div class="flex flex-wrap items-center justify-between gap-3 px-6 py-4">
              <button onclick={() => togglePassthroughCard(provider.id)} class="flex items-center gap-3 text-left hover:opacity-80 transition-opacity">
                <span class="inline-flex transition-transform {expandedPassthroughIds.has(provider.id) ? 'rotate-90' : ''}"><Icon name="chevronRight" tone="neutral" /></span>
                <ProviderIcon name={provider.icon || server?.provider || 'custom'} size="lg" className="text-(--text-secondary) shrink-0" />
                <span class="text-sm font-semibold text-(--text-primary)">{provider.name}</span>
                <ByokBadge />
                {#if provider.is_builtin}
                  <span class="px-2 py-0.5 text-[10px] font-medium rounded-full bg-(--bg-primary) text-(--text-secondary) border border-(--border)" title="Shipped with the product: switch it on or off and repoint it, but it cannot be renamed or deleted">built-in</span>
                {/if}
                <span class="px-2 py-0.5 text-[10px] font-mono rounded-full bg-(--bg-primary) text-(--text-secondary) border border-(--border)">{provider.route_count ?? 0} override{provider.route_count === 1 ? '' : 's'}</span>
              </button>
              <div class="flex items-center gap-3">
                {#if server}
                  <button
                    type="button"
                    role="switch"
                    aria-checked={server.enabled}
                    aria-label={server.enabled ? `Turn off ${provider.name}` : `Turn on ${provider.name}`}
                    onclick={() => toggleServerEnabled(server)}
                    data-testid="toggle-server-enabled"
                    title={server.enabled ? 'On — turn off: the gateway stops passing traffic through, and workspaces can no longer be granted it' : 'Off — turn on: it can then be granted to workspaces (including Inline AI, to intercept it)'}
                    class="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors {server.enabled ? 'bg-(--accent)' : 'bg-(--bg-elevated) border border-(--border)'}"
                  >
                    <span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-transform {server.enabled ? 'translate-x-4' : 'translate-x-1'}"></span>
                  </button>
                  <a href={thref(tenantSlug, `/gateways/llm/servers/${server.id}?tab=server`)} class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium" data-testid="edit-server" title="Endpoint, API format and the server's other settings">Server</a>
                {/if}
                {#if !provider.is_builtin}
                  <button onclick={() => openEditProvider(provider)} class="text-xs text-(--accent) hover:underline font-medium" title="Name, description and icon">Edit</button>
                {/if}
                <button onclick={() => openAddRoute(provider.id)} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-xs font-medium transition-colors">+ Override a model</button>
                {#if !provider.is_builtin}
                  <button onclick={() => deletePassThroughUnit(provider, server)} class="px-3 py-1.5 text-xs text-(--error) hover:underline font-medium" data-testid="delete-passthrough" title="Delete the pass-through and its server, with its overrides and grants; keys bound to it are revoked">Delete</button>
                {/if}
              </div>
            </div>
            <dl class="grid grid-cols-1 md:grid-cols-[auto_1fr] gap-x-6 gap-y-1.5 px-6 pb-4 text-xs">
              <dt class="text-(--text-secondary)">Endpoint</dt>
              <dd class="font-mono text-(--text-primary) break-all">{server?.upstream_url ?? '—'}</dd>
              <dt class="text-(--text-secondary)">API format</dt>
              <dd>{#if server}<span class="px-1.5 py-0.5 rounded-sm font-medium bg-(--accent)/10 text-(--accent)">{formatUpstreamApiFormat(server.upstream_api_format)}</span>{:else}—{/if}</dd>
              <dt class="text-(--text-secondary)">Granted to</dt>
              <dd class="flex flex-wrap gap-1.5" data-testid="granted-to">
                {#each provider.granted_workspaces as w (w.id)}
                  <a href={thref(tenantSlug, `/workspaces/${w.id}?tab=access`)} class="px-2 py-0.5 rounded-full bg-(--bg-primary) border border-(--border) text-(--text-primary) hover:border-(--accent)">{w.name}</a>
                {:else}
                  <span class="text-(--text-secondary)">No workspace — grant it from a workspace's Access tab.</span>
                {/each}
              </dd>
            </dl>
            {#if expandedPassthroughIds.has(provider.id)}
              {@render providerBody(provider, () => true)}
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  {/if}

  <!-- ===== Configuration Tab ===== -->
  {#if active === 'upstream'}
    {#if configView.skeleton}
      <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
        <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
        Loading configuration…
      </div>
    {:else}

      <div class="max-w-sm">
        <FilterInput bind:value={upstreamFilter} placeholder="Filter servers, models, catalog..." matchInfo={upstreamFilterInfo} />
      </div>

      <!-- ===== Section 1: Servers ===== -->
      <section>
        <div class="mb-4">
          <h3 class="text-lg font-semibold text-(--text-primary)">Servers</h3>
          <p class="text-sm text-(--text-secondary) mt-1">Upstream server connections and credentials</p>
          {#if servers.length > orderedServers.length}
            <p class="text-xs text-(--text-secondary) mt-1">
              Pass-through servers are on the
              <button type="button" onclick={() => switchLlmTab('passthrough')} class="text-(--accent) hover:underline font-medium">Pass-through tab</button>.
            </p>
          {/if}
        </div>

        {#if orderedServers.length === 0}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) py-12 text-center">
            <p class="text-(--text-secondary)">No servers configured</p>
            <p class="text-sm text-(--text-secondary) mt-1">Add a server to start routing requests to upstream LLM providers</p>
          </div>
        {:else}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
            <table class="w-full">
              <thead>
                <tr class="border-b border-(--border) bg-(--bg-primary)/50">
                  <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Name</th>
                  <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Provider</th>
                  <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">URL</th>
                  <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Format</th>
                  <th class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Models</th>
                  <th class="px-5 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Auto-sync</th>
                  <th class="px-5 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each filteredServers as server}
                  {@const models = modelsByServer[server.id] || []}
                  {@const srvPi = getProviderIcon(server.provider)}
                  {@const st = syncStatus(server)}
                  <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors">
                    <td class="px-5 py-3.5">
                      <div class="flex items-center gap-2">
                        <a href={thref(tenantSlug, `/gateways/llm/servers/${server.id}`)} class="font-semibold text-(--text-primary) hover:text-(--accent)" data-testid="server-link">{server.name}</a>
                        {#if !server.enabled}
                          <span class="px-1.5 py-0.5 rounded-sm text-xs font-medium bg-(--text-secondary)/15 text-(--text-secondary)">Disabled</span>
                        {/if}
                        {#if server.has_credential}
                          <span class="text-(--success) text-xs" title="Credential configured">&#10003;</span>
                        {/if}
                      </div>
                    </td>
                    <td class="px-5 py-3.5">
                      <span class="inline-flex items-center gap-1.5 text-xs font-medium text-(--text-primary)">
                        <ProviderIcon name={server.provider} size="md" className="text-(--text-secondary) shrink-0" />
                        {srvPi.name}
                      </span>
                    </td>
                    <td class="px-5 py-3.5">
                      <span class="font-mono text-xs text-(--text-secondary)">
                        {#if server.upstream_url}{server.upstream_url}{:else}<span class="italic">default</span>{/if}
                      </span>
                      <!-- Always shown: a server HAS endpoints from the moment
                           it exists, and a link that appears only past the
                           second one keeps replicas a feature nobody finds. -->
                      <a href={thref(tenantSlug, `/gateways/llm/servers/${server.id}?tab=endpoints`)} class="ml-1 text-[10px] font-medium text-(--accent)" title="Replica endpoints of this server">{server.endpoint_count} endpoint{server.endpoint_count === 1 ? '' : 's'}</a>
                      {#if server.health === 'degraded' || server.health === 'down'}
                        <span class="ml-1">
                          <StatusChip
                            {...SERVER_HEALTH[server.health]}
                            status={server.health}
                            title={serverHealthReason(server) ?? undefined}
                          />
                        </span>
                      {/if}
                    </td>
                    <td class="px-5 py-3.5">
                      <span class="px-1.5 py-0.5 rounded-sm text-xs font-medium bg-(--accent)/10 text-(--accent)">{formatUpstreamApiFormat(server.upstream_api_format)}</span>
                    </td>
                    <td class="px-5 py-3.5 text-right font-mono text-sm text-(--text-secondary)">{models.length}</td>
                    <td class="px-5 py-3.5">
                      <!-- The toggle needs a discoverable server with a
                           credential to offer; the STATUS is shown whenever one
                           was recorded. A keyless local engine whose first sync
                           failed is exactly the case that records one, and
                           gating the two together hid it from the one page an
                           operator scans. -->
                      {#if canModelSync(server) && server.has_credential}
                        <div class="flex flex-col gap-1">
                          <button
                            type="button"
                            role="switch"
                            aria-checked={server.auto_sync_enabled}
                            onclick={() => toggleAutoSync(server)}
                            title={server.auto_sync_enabled ? 'Auto-sync on — discovers models + keeps the mirror downstream in sync; click to disable (freezes the mirror)' : 'Auto-sync off — manual server (no discovery, no mirror); click to enable'}
                            class="relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition-colors {server.auto_sync_enabled ? 'bg-(--accent)' : 'bg-(--bg-elevated) border border-(--border)'}"
                          >
                            <span class="inline-block h-3.5 w-3.5 transform rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-transform {server.auto_sync_enabled ? 'translate-x-4' : 'translate-x-1'}"></span>
                          </button>
                          {#if st}
                            <span class="text-[10px] {st.ok ? 'text-(--text-tertiary)' : 'text-(--error-text)'}" title={st.detail}>{st.label}</span>
                          {/if}
                        </div>
                      {:else if st}
                        <span class="text-[10px] {st.ok ? 'text-(--text-tertiary)' : 'text-(--error-text)'}" title={st.detail}>{st.label}</span>
                      {:else}
                        <span class="text-xs text-(--text-tertiary)">--</span>
                      {/if}
                    </td>
                    <td class="px-5 py-3.5 text-right">
                      <div class="flex items-center justify-end gap-3">
                        {#if canModelSync(server) && server.has_credential}
                          <button onclick={() => syncNow(server)} disabled={syncingNowId === server.id} class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) bg-(--accent)/5 hover:bg-(--accent)/10 px-2.5 py-1 rounded-md transition-colors disabled:opacity-50">{syncingNowId === server.id ? 'Syncing…' : 'Sync now'}</button>
                          <button onclick={() => openSync(server)} class="text-xs font-medium text-(--accent) hover:text-(--accent-hover) transition-colors">Review</button>
                        {/if}
                        {#if !server.enabled}
                          <button
                            onclick={() => toggleServerEnabled(server)}
                            data-testid="toggle-server-enabled"
                            title="Turn on: its models serve traffic again"
                            class="text-xs font-medium px-2.5 py-1 rounded-md transition-colors text-(--accent) hover:text-(--accent-hover) bg-(--accent)/5 hover:bg-(--accent)/10"
                          >Enable</button>
                        {/if}
                        <a href={thref(tenantSlug, `/gateways/llm/servers/${server.id}?tab=server`)} class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium transition-colors" data-testid="edit-server">Edit</a>
                        <button onclick={() => confirmDeleteServer(server)} class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm font-medium transition-colors">Delete</button>
                      </div>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
          </div>
        {/if}
      </section>

      <!-- ===== Section 2: Models (grouped by server) ===== -->
      <section>
        <div class="mb-4">
          <h3 class="text-lg font-semibold text-(--text-primary)">Models</h3>
          <p class="text-sm text-(--text-secondary) mt-1">Upstream model registrations. Models must exist here before downstream routes can point to them.</p>
        </div>

        {#if allModels.length === 0}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) py-12 text-center">
            <p class="text-(--text-secondary)">No models configured</p>
            <p class="text-sm text-(--text-secondary) mt-1">Use Sync on a server to discover models, or add them manually</p>
          </div>
        {:else}
          <div class="space-y-4">
            {#each filteredServers as server}
              {@const models = modelsByServer[server.id] || []}
              {@const shownModels = filteredModelsByServer[server.id] ?? []}
              {@const msPi = getProviderIcon(server.provider)}
              {#if models.length > 0 || filteredServers.length <= 3}
                <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
                  <!-- Server subheader -->
                  <div class="px-5 py-3 flex items-center gap-3 bg-(--bg-primary)/40 border-b border-(--border) cursor-pointer hover:bg-(--bg-elevated) transition-colors" onclick={() => toggleServer(server.id)} role="button" tabindex="0" onkeydown={(e: KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); toggleServer(server.id); } }}>
                    <span class="inline-flex transition-transform {expandedServers.has(server.id) ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
                    <span class="font-medium text-(--text-primary) text-sm">{server.name}</span>
                    <span class="inline-flex items-center gap-1 text-xs font-medium text-(--text-secondary)">
                      <ProviderIcon name={server.provider} size="sm" className="shrink-0" />
                      {msPi.name}
                    </span>
                    <span class="text-xs text-(--text-secondary) ml-auto">{#if upstreamQuery}{shownModels.length} of {/if}{models.length} model{models.length !== 1 ? 's' : ''}</span>
                    <!-- svelte-ignore a11y_click_events_have_key_events -->
                    <div onclick={(e: MouseEvent) => e.stopPropagation()} role="none" class="flex items-center gap-2">
                      {#if models.length > 0}
                        <button onclick={() => { bulkModelConfirm = { serverId: server.id, serverName: server.name, modelCount: models.length }; bulkModelError = ''; }} disabled={bulkModelUpdating} class="text-[10px] font-medium text-(--text-secondary) hover:text-(--error) px-2 py-1 rounded-sm border border-(--border) transition-colors disabled:opacity-50">Disable All</button>
                        <button onclick={() => handleBulkUpdateModels(server.id, true)} disabled={bulkModelUpdating} class="text-[10px] font-medium text-(--text-secondary) hover:text-(--success) px-2 py-1 rounded-sm border border-(--border) transition-colors disabled:opacity-50">Enable All</button>
                      {/if}
                      <button onclick={() => openAddModel(server.id)} class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium transition-colors ml-1">+ Add Model</button>
                    </div>
                  </div>

                  {#if expandedServers.has(server.id)}
                    {#if shownModels.length > 0}
                      {@const pager = modelPagers.get(server.id)!}
                      {@const modelPageRows = shownModels.slice(pager.offset, pager.offset + pager.limit)}
                      <!-- `setServers` gives every listed server its pager. -->
                      <table class="w-full">
                        <thead>
                          <tr class="border-b border-(--border) bg-(--bg-primary)/20">
                            <th class="px-5 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Upstream Model</th>
                            <th class="px-5 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Context</th>
                            <th class="px-5 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Max Output</th>
                            <th class="px-5 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Format</th>
                            <th class="px-5 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Capabilities</th>
                            <th class="px-5 py-2.5 text-center text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Enabled</th>
                            <th class="px-5 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
                          </tr>
                        </thead>
                        <tbody>
                          {#each modelPageRows as model (model.id)}
                              <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors">
                                <td class="px-5 py-2.5">
                                  <span class="font-mono text-sm text-(--text-primary)">{model.upstream_model}</span>
                                  {#if model.model_type && model.model_type !== 'text'}
                                    <span class="ml-1.5 inline-flex px-1.5 py-0.5 rounded-sm text-[10px] font-medium {modelTypeBadgeClass(model.model_type)}">{model.model_type}</span>
                                  {/if}
                                </td>
                                <td class="px-5 py-2.5 text-right">
                                  {#if model.context_window}<span class="font-mono text-sm text-(--text-secondary)">{(model.context_window / 1000).toFixed(0)}k</span>
                                  {:else}<span class="text-sm text-(--text-secondary)">&mdash;</span>{/if}
                                </td>
                                <td class="px-5 py-2.5 text-right">
                                  {#if model.max_output_tokens}<span class="font-mono text-sm text-(--text-secondary)">{(model.max_output_tokens / 1000).toFixed(0)}k</span>
                                  {:else}<span class="text-sm text-(--text-secondary)">&mdash;</span>{/if}
                                </td>
                                <td class="px-5 py-2.5">
                                  <span class="px-1.5 py-0.5 rounded-sm text-xs font-medium bg-(--accent)/10 text-(--accent)">{formatUpstreamApiFormat(model.upstream_api_format)}</span>
                                </td>
                                <td class="px-5 py-2.5">
                                  <div class="flex flex-wrap gap-1">
                                    {#if model.resolved_supports_vision}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-teal-bg) text-(--success)">vision</span>{/if}
                                    {#if model.resolved_supports_function_calling}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--warning-bg) text-(--warning)">tools</span>{/if}
                                    {#if model.resolved_supports_reasoning}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-violet-bg) text-(--tag-violet-text)">reasoning</span>{/if}
                                    {#if model.resolved_supports_caching}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-blue-bg) text-(--tag-blue-text)">cache</span>{/if}
                                    {#if model.resolved_supports_audio_input}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-cyan-bg) text-(--tag-cyan-text)">audio-in</span>{/if}
                                    {#if model.resolved_supports_audio_output}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-cyan-bg) text-(--tag-cyan-text)">audio-out</span>{/if}
                                    {#if model.resolved_supports_video_input}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-pink-bg) text-(--tag-pink-text)">video</span>{/if}
                                    {#if model.resolved_supports_pdf_input}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-orange-bg) text-(--tag-orange-text)">pdf</span>{/if}
                                    {#if model.resolved_supports_response_schema}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-teal-bg) text-(--tag-teal-text)">schema</span>{/if}
                                    {#if !model.resolved_supports_system_messages}<span class="inline-block px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--error-bg) text-(--error)">no-system</span>{/if}
                                  </div>
                                </td>
                                <td class="px-5 py-2.5 text-center">
                                  <button
                                    onclick={() => handleToggleModelEnabled(model)}
                                    class="w-7 h-3.5 rounded-full relative transition-colors {model.enabled ? 'bg-(--success)' : 'bg-(--toggle-off)'}"
                                    title="{model.enabled ? 'Enabled' : 'Disabled'}"
                                  >
                                    <span class="absolute top-0.5 {model.enabled ? 'right-0.5' : 'left-0.5'} w-2.5 h-2.5 rounded-full bg-white ring-1 ring-(--bg-primary)/60 transition-all"></span>
                                  </button>
                                </td>
                                <td class="px-5 py-2.5 text-right">
                                  <div class="flex items-center justify-end gap-3">
                                    <button onclick={() => openPresetsModal(model)} class="text-xs text-(--text-secondary) hover:text-(--text-primary) font-medium transition-colors">Presets</button>
                                    <button onclick={() => openEditModel(model)} class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium transition-colors">Edit</button>
                                    <button onclick={() => confirmDeleteModel(model)} class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm font-medium transition-colors">Delete</button>
                                  </div>
                                </td>
                              </tr>
                          {/each}
                        </tbody>
                      </table>
                      <!-- Only a server with more than one page carries the bar: most fit on one. -->
                      {#if pager.hasMore || pager.offset > 0}
                        <div class="px-5 pb-3">
                          <Pagination state={pager} onchange={() => {}} itemsShown={modelPageRows.length} />
                        </div>
                      {/if}
                    {:else if models.length > 0}
                      <div class="py-6 text-center text-sm text-(--text-secondary)">
                        No model on this server matches "{upstreamFilter.trim()}".
                      </div>
                    {:else}
                      <div class="py-6 text-center text-sm text-(--text-secondary)">
                        No models on this server.
                        <button onclick={() => openAddModel(server.id)} class="text-(--accent) hover:text-(--accent-hover) font-medium ml-1">Add one</button>
                        or
                        <button onclick={() => openSync(server)} class="text-(--accent) hover:text-(--accent-hover) font-medium">Sync</button>
                      </div>
                    {/if}
                  {/if}
                </div>
              {/if}
            {/each}
          </div>
        {/if}
      </section>

      <!-- ===== Model Catalog Section ===== -->
      <section>
        <div class="flex justify-between items-center mb-6">
          <div>
            <h3 class="text-lg font-semibold text-(--text-primary)">Model Catalog</h3>
            <p class="text-sm text-(--text-secondary) mt-1">Reference capabilities and prices every upstream model inherits from</p>
          </div>
          <div class="flex gap-2 shrink-0">
            {#if seededCount > 0}
              <button onclick={() => { catalogBulkAction = 'remove-seeded'; catalogBulkError = ''; }} disabled={catalogBulkLoading} class="text-xs font-medium text-(--text-secondary) hover:text-(--text-primary) bg-(--bg-primary) hover:bg-(--bg-elevated) px-3 py-1.5 rounded-lg border border-(--border) transition-colors disabled:opacity-50">Remove Seeded</button>
            {/if}
            <button onclick={() => { catalogBulkAction = 'reset'; catalogBulkError = ''; }} disabled={catalogBulkLoading} class="text-xs font-medium text-(--warning) hover:text-(--error) bg-(--bg-primary) hover:bg-(--bg-elevated) px-3 py-1.5 rounded-lg border border-(--border) transition-colors disabled:opacity-50">Reset</button>
            <button onclick={openAddCatalog} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">+ New Entry</button>
          </div>
        </div>

        {#if catalogView.skeleton}
          <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
            <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
            Loading catalog…
          </div>
        {:else}
          <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-x-auto">
            <table class="w-full">
              <thead>
                <tr class="border-b border-(--border) bg-(--bg-primary)/50">
                  <th class="px-4 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Provider</th>
                  <th class="px-4 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Model</th>
                  <th class="px-4 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Applies to</th>
                  <th class="px-4 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Prices</th>
                  <th class="px-4 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Context</th>
                  <th class="px-4 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Max Output</th>
                  <th class="px-4 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Capabilities</th>
                  <th class="px-4 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Actions</th>
                </tr>
              </thead>
              <tbody>
                {#each catalogPageRows as entry (entry.id)}
                  {@const prPi = getProviderIcon(entry.provider)}
                  <tr class="border-b border-(--border) hover:bg-(--bg-elevated) transition-colors group">
                    <td class="px-4 py-3">
                      <span class="inline-flex items-center gap-1.5 text-xs font-medium text-(--text-primary)">
                        <ProviderIcon name={entry.provider} size="md" className="text-(--text-secondary) shrink-0" />
                        {prPi.name}
                      </span>
                    </td>
                    <td class="px-4 py-3"><span class="font-mono text-sm text-(--text-primary)">{entry.model}</span></td>
                    <td class="px-4 py-3">
                      <span class="text-xs {entry.server_id ? 'text-(--text-primary)' : 'text-(--text-secondary)'}">
                        {entry.server_id ? (entry.server_name ?? 'Unknown server') : 'All servers'}
                      </span>
                    </td>
                    <td class="px-4 py-3 max-w-md">
                      {#if ratesAreEmpty(entry.rates)}
                        <span
                          class="text-xs text-(--warning-text)"
                          title="No rate is on file, so requests against this model record a cost of zero and are flagged. That is not the same as a price of 0, which means the model is genuinely free."
                        >No price on file</span>
                      {:else}
                        <span class="font-mono text-xs text-(--text-primary)">{formatRatesInline(entry.rates)}</span>
                      {/if}
                    </td>
                    <td class="px-4 py-3 text-right"><span class="font-mono text-sm text-(--text-secondary)">{entry.context_window != null ? formatTokens(entry.context_window) : '--'}</span></td>
                    <td class="px-4 py-3 text-right"><span class="font-mono text-sm text-(--text-secondary)">{entry.max_output_tokens != null ? formatTokens(entry.max_output_tokens) : '--'}</span></td>
                    <td class="px-4 py-3">
                      <div class="flex flex-wrap gap-1">
                        {#if entry.supports_vision}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-teal-bg) text-(--success)">vision</span>{/if}
                        {#if entry.supports_function_calling}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--warning-bg) text-(--warning)">tools</span>{/if}
                        {#if entry.supports_reasoning}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-violet-bg) text-(--tag-violet-text)">reasoning</span>{/if}
                        {#if entry.supports_caching}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-blue-bg) text-(--tag-blue-text)">cache</span>{/if}
                        {#if entry.supports_audio_input}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-cyan-bg) text-(--tag-cyan-text)">audio-in</span>{/if}
                        {#if entry.supports_audio_output}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-cyan-bg) text-(--tag-cyan-text)">audio-out</span>{/if}
                        {#if entry.supports_video_input}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-pink-bg) text-(--tag-pink-text)">video</span>{/if}
                        {#if entry.supports_pdf_input}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-orange-bg) text-(--tag-orange-text)">pdf</span>{/if}
                        {#if entry.supports_response_schema}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--tag-teal-bg) text-(--tag-teal-text)">schema</span>{/if}
                        {#if entry.supports_system_messages === false}<span class="px-1.5 py-0.5 rounded-sm text-[10px] font-medium bg-(--error-bg) text-(--error)">no-system</span>{/if}
                      </div>
                    </td>
                    <td class="px-4 py-3 text-right">
                      <div class="flex items-center justify-end gap-3">
                        <button onclick={() => openEditCatalog(entry)} class="text-xs text-(--accent) hover:text-(--accent-hover) transition-colors font-medium">Edit</button>
                        <button onclick={() => confirmDeleteCatalog(entry)} class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm transition-colors font-medium">Delete</button>
                      </div>
                    </td>
                  </tr>
                {/each}
              </tbody>
            </table>
            {#if filteredCatalog.length === 0 && catalog.length > 0}
              <div class="py-12 text-center">
                <p class="text-(--text-secondary)">No models matching "{upstreamFilter}"</p>
              </div>
            {:else if catalog.length === 0}
              <div class="py-12 text-center">
                <p class="text-(--text-secondary)">No catalog entries configured</p>
                <p class="text-sm text-(--text-secondary) mt-1">Add catalog entries to enable cost tracking in audit logs</p>
              </div>
            {/if}
          </div>
          <Pagination
            state={catalogPager}
            onchange={() => {}}
            itemsShown={catalogPageRows.length}
          />
        {/if}
      </section>
    {/if}
  {/if}
  {/snippet}
</TabbedPage>

<!-- Edit Provider Modal (Downstream and Pass-through cards) -->
{#if editingProviderId}
  <Modal open={true} title="Edit Provider" onclose={() => editingProviderId = null}>
    <div class="space-y-4">
      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Provider Name <span class="text-(--error)">*</span>
        <input bind:value={editProviderName} class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
      </label>
      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Description
        <input bind:value={editProviderDesc} placeholder="Optional description" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
      </label>
      <div>
        <span class="block text-xs text-(--text-secondary) mb-1.5 uppercase tracking-wider">Icon</span>
        <div class="flex flex-wrap gap-1.5">
          {#each Object.entries(PROVIDER_ICONS) as [key, pi]}
            <button
              type="button"
              onclick={() => editProviderIcon = editProviderIcon === key ? '' : key}
              class="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-medium transition-colors border {editProviderIcon === key ? 'bg-(--accent)/15 border-(--accent) text-(--accent)' : 'bg-(--bg-primary) border-(--border) text-(--text-secondary) hover:text-(--text-primary)'}"
            >
              <ProviderIcon name={key} size="md" className="shrink-0" />
              {pi.name}
            </button>
          {/each}
        </div>
      </div>
      {#if providerError}
        <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
          <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
          <p class="text-sm text-(--error)">{providerError}</p>
        </div>
      {/if}
      <div class="flex gap-2 pt-2">
        <button onclick={handleSaveProvider} disabled={savingProvider || !editProviderName.trim()} class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50">
          {savingProvider ? 'Saving…' : 'Save'}
        </button>
        <button onclick={() => editingProviderId = null} class="px-5 py-2 bg-(--bg-secondary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-medium">Cancel</button>
      </div>
    </div>
  </Modal>
{/if}

<!-- Route Modal -->
{#if showRouteModal}
  <Modal
    open={showRouteModal}
    title={routeIsOverride ? (editingRouteId ? 'Edit Override' : 'Override a Model') : editingRouteId ? 'Edit Route' : 'Add Route'}
    onclose={() => { showRouteModal = false; editingRouteId = null; }}
  >
    <div class="space-y-4">
      {#if routeIsOverride}
        <p class="text-xs text-(--text-secondary)">
          Requests for this exact model name go to one of your own servers instead of passing through. Every other model still passes through.
        </p>
      {/if}
      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">{routeIsOverride ? 'Model the client asks for' : 'Alias'}
        <input bind:value={routeAlias} placeholder="e.g. gpt-4o" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
      </label>
      {#if routeIsOverride}
        <p class="-mt-2 text-xs text-(--text-secondary)">An exact match — no wildcard.</p>
      {/if}
      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">{routeIsOverride ? 'Send it to' : 'Server'}
        <SelectInput bind:value={routeServerId} class="mt-1">
          <option value="">-- Select server --</option>
          {#each routeDestinationServers as s}
            {@const sPi = getProviderIcon(s.provider)}
            <option value={s.id}>{s.name} ({sPi.name})</option>
          {/each}
        </SelectInput>
      </label>
      <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Model
        <SelectInput bind:value={routeModel} class="mt-1"
          onchange={() => { routePresetId = ''; routePresets = []; if (routeModel) void loadRoutePresets(routeModel); }}>
          <option value="">-- Select model --</option>
          {#each allModels.filter(m => !routeServerId || m.server_id === routeServerId) as m}
            <option value={m.id}>{m.upstream_model}</option>
          {/each}
        </SelectInput>
      </label>
      {#if routeDestinationKeyless}
        <Callout severity="warning" title="This server holds no key">
          <p class="text-xs" data-testid="override-keyless-warning">The member's own provider key is forwarded to it with the request.</p>
        </Callout>
      {/if}
      <div class="grid grid-cols-2 gap-4">
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Priority
          <input bind:value={routePriority} type="number" min="0" max="1000" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
        </label>
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Weight
          <input bind:value={routeWeight} type="number" min="0" max="100" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm" />
        </label>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Preset
          <SelectInput bind:value={routePresetId} class="mt-1" disabled={!routeModel}>
            <option value="">Default preset</option>
            {#each routePresets.filter(p => !p.is_default) as p}
              <option value={p.id}>{p.name}</option>
            {/each}
          </SelectInput>
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">How this model is invoked (sampling, reasoning, …). Manage presets on the model in the Upstream tab. Empty = the model's default preset.</span>
        </label>
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Client Context Window
          <input bind:value={routeClientCw} type="number" min="0" placeholder="Defaults to upstream model's context window" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)" />
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">Advertised window for client-side compaction. Capabilities, real window, protocol and media type are the model's — edit them on the model.</span>
        </label>
      </div>
      <div class="grid grid-cols-2 gap-4">
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Cache Preset
          <SelectInput bind:value={routeCachePresetId} class="mt-1">
            <option value="">No cache</option>
            {#each cachePresets as cp}
              <option value={cp.id}>{cp.name} ({cp.mode})</option>
            {/each}
          </SelectInput>
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">Serve repeated requests on this alias from a stored response. Modes, TTL and sharing scope live on the preset — manage them under Settings → Response cache.</span>
          {#if semanticNeedsEmbedding}
            <span class="mt-1 flex items-start gap-1.5 text-[10px] text-(--warning) font-normal normal-case tracking-normal">
              <Icon name="triangleAlert" size="xs" tone="warning" />
              <span>This preset compares questions by meaning, but no embedding model is configured — so it cannot. Set one under Settings → Response cache.</span>
            </span>
          {/if}
        </label>
        <div class="block text-xs text-(--text-secondary) uppercase tracking-wider">
          {#if editingRouteId && routeCachePresetId}
            <span>Cached Responses</span>
            <button type="button"
              onclick={() => editingRouteId && routeProviderId && handleFlushRouteCache(routeProviderId, editingRouteId)}
              class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) hover:border-(--accent) rounded-lg text-(--text-primary) text-sm transition-colors">
              Flush now
            </button>
            <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">Drops this alias's stored responses on every edge. Safe at any time — the next request recomputes.</span>
          {/if}
        </div>
      </div>
      {#if editingRouteId && qosClasses.length > 0}
        <div>
          <span class="block text-xs text-(--text-secondary) uppercase tracking-wider">Allowed Classes</span>
          <ChipMultiSelect options={qosClasses.map((c) => ({ value: c.id, label: c.name }))} bind:selected={routeQosClassIds} />
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-1 block">
            {routeQosClassIds.length === 0
              ? 'Every class may be served by this target. Pick some to restrict it — for example to keep background work off a paid fallback while your own pool is busy.'
              : 'Only the selected classes may be served by this target. Clear them all to accept every class again.'}
          </span>
        </div>
      {/if}
      <div class="grid grid-cols-2 gap-4">
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Client Tags
          <input bind:value={routeTags} type="text" placeholder="opencode, claude-code  (or *)" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)" />
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">Which clients this route is <strong>offered to</strong>. Comma-separated client ids; quickstart shows the route in those clients' configs. Use <code>*</code> for every client (empty also means all, but prefer <code>*</code>).</span>
        </label>
        <label class="block text-xs text-(--text-secondary) uppercase tracking-wider">Default For Tags
          <input bind:value={routeDefaultForTags} oninput={() => (routeConflictMsg = '')} type="text" placeholder="opencode, claude-code  (or *)" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)" />
          <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-0.5 block">Among the clients above, which get this route as their <strong>default model</strong> (fills the generated config's top-level model). Must be within Tags. Use <code>*</code> for the global default (any client without a more specific one); a specific client tag overrides <code>*</code>.</span>
        </label>
      </div>
      {#if editingRouteId}
      <div>
        <span class="block text-xs text-(--text-secondary) uppercase tracking-wider">Client Slots</span>
        <ChipMultiSelect options={CLIENT_SLOTS} bind:selected={routeClientSlots} />
        <span class="text-[10px] text-(--text-secondary) font-normal normal-case tracking-normal mt-1 block">
          Clients with more than one model setting use this alias as their <strong>fast</strong> model (titles, search, commit messages) and/or their <strong>plan</strong> model (planning). A slot no route fills uses the default model. One route per slot in this downstream: choosing a slot here takes it off the route that holds it{#each slotHolders as h (h.slot)}{' '}(<code>{h.alias}</code> holds {h.slot}){/each}.
          Pair it with a preset to offer the same model two ways, for example thinking off for fast and reasoning high for plan.
        </span>
      </div>
      {/if}
      {#if routeError}
        <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
          <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
          <p class="text-sm text-(--error)">{routeError}</p>
        </div>
      {/if}
      {#if routeConflictMsg}
        <Callout severity="warning" title="Default already assigned">
          {routeConflictMsg} Reassigning moves the default to this route and clears it from the other.
        </Callout>
      {/if}
      <div class="flex justify-end gap-2 pt-2">
        <button onclick={() => { showRouteModal = false; routeConflictMsg = ''; }} class="px-4 py-2 border border-(--border) rounded-lg text-sm text-(--text-secondary) hover:text-(--text-primary) transition-colors">Cancel</button>
        {#if routeConflictMsg}
          <button onclick={() => handleSaveRoute(true)} disabled={savingRoute} class="px-4 py-2 bg-(--warning) hover:opacity-90 rounded-lg text-(--warning-fg) text-sm font-medium disabled:opacity-50 transition-colors">
            {savingRoute ? 'Saving…' : 'Reassign default & save'}
          </button>
        {:else}
          <button onclick={() => handleSaveRoute()} disabled={savingRoute} class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50 transition-colors">
            {savingRoute ? 'Saving…' : editingRouteId ? 'Update' : 'Create'}
          </button>
        {/if}
      </div>
    </div>
  </Modal>
{/if}

<!-- ===== Model Presets Modal ===== -->
{#if showPresetsModal && presetsModel}
  <Modal open={showPresetsModal} title="Presets — {presetsModel.upstream_model}" onclose={() => { showPresetsModal = false; presetsModel = null; }} maxWidth="max-w-2xl">
    <div class="space-y-4">
      <p class="text-xs text-(--text-secondary)">
        A preset is how this model is invoked — a partial request body in the model's own protocol
        (sampling, reasoning/thinking, stop sequences, native extras). The gateway force-merges it
        onto each request just before it leaves for the upstream. Bind a preset to an alias in the
        Downstream tab.
      </p>

      {#if showPresetForm}
        {@const proto = presetProtocol()}
        <div class="border border-(--border) rounded-lg p-4 space-y-4">
          <div class="flex items-end gap-3">
            <FormField label="Name" for="preset-name" class="flex-1">
              <TextInput id="preset-name" bind:value={presetName} placeholder="e.g. non-think" />
            </FormField>
            <div class="pb-2">
              <TagBadge color="neutral">{API_FORMATS.find((f) => f.value === proto)?.label ?? proto}</TagBadge>
            </div>
          </div>
          <p class="text-[11px] text-(--text-secondary)">
            Fields are this model's native settings. Leave a field blank to pass the request value through untouched.
          </p>

          <div class="grid grid-cols-2 gap-3">
            {#if proto === 'anthropic_messages'}
              <FormField label="Thinking" for="preset-thinking">
                <SelectInput id="preset-thinking" bind:value={pThinking}>
                  <option value="">Inherit / passthrough</option>
                  <option value="enabled">Enabled (fixed budget)</option>
                  <option value="adaptive">Adaptive (Claude 4.6+)</option>
                  <option value="disabled">Disabled</option>
                </SelectInput>
              </FormField>
              {#if pThinking === 'enabled'}
                <FormField label="Thinking budget (tokens)" for="preset-thinking-budget" help="≥ 1024 and below max output tokens.">
                  <NumberInput id="preset-thinking-budget" bind:value={pThinkingBudget} min={1024} step={1} placeholder="e.g. 4096" />
                </FormField>
              {/if}
            {/if}

            {#if proto === 'chat_completions' || proto === 'responses'}
              <FormField label="Reasoning effort" for="preset-effort">
                <SelectInput id="preset-effort" bind:value={pReasoning}>
                  <option value="">Inherit / passthrough</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                </SelectInput>
              </FormField>
            {/if}

            <FormField label="Temperature" for="preset-temp">
              <NumberInput id="preset-temp" bind:value={pTemperature} min={0} max={proto === 'anthropic_messages' ? 1 : 2} step={0.1} placeholder={proto === 'anthropic_messages' ? '0 – 1' : '0 – 2'} />
            </FormField>
            <FormField label="Top P" for="preset-topp">
              <NumberInput id="preset-topp" bind:value={pTopP} min={0} max={1} step={0.05} placeholder="0 – 1" />
            </FormField>

            {#if proto !== 'responses'}
              <FormField label="Top K" for="preset-topk">
                <NumberInput id="preset-topk" bind:value={pTopK} min={1} step={1} placeholder="≥ 1" />
              </FormField>
            {/if}

            {#if proto === 'chat_completions'}
              <FormField label="Min P" for="preset-minp">
                <NumberInput id="preset-minp" bind:value={pMinP} min={0} max={1} step={0.01} placeholder="0 – 1" />
              </FormField>
              <FormField label="Frequency penalty" for="preset-freq">
                <NumberInput id="preset-freq" bind:value={pFreqPenalty} min={-2} max={2} step={0.1} placeholder="-2 – 2" />
              </FormField>
              <FormField label="Presence penalty" for="preset-pres">
                <NumberInput id="preset-pres" bind:value={pPresPenalty} min={-2} max={2} step={0.1} placeholder="-2 – 2" />
              </FormField>
              <FormField label="Seed" for="preset-seed">
                <NumberInput id="preset-seed" bind:value={pSeed} step={1} placeholder="deterministic sampling" />
              </FormField>
            {/if}

            <FormField label="Max output tokens" for="preset-maxtok">
              <NumberInput id="preset-maxtok" bind:value={pMaxTokens} min={1} step={1} placeholder="model ceiling" />
            </FormField>

            {#if proto !== 'responses'}
              <FormField label="Stop sequences" for="preset-stop" class="col-span-2" help="Comma-separated.">
                <TextInput id="preset-stop" bind:value={pStop} placeholder="e.g. ###, END" />
              </FormField>
            {/if}

            {#if proto === 'google_gemini'}
              <FormField label="Thinking budget (tokens)" for="preset-gthinking">
                <NumberInput id="preset-gthinking" bind:value={pThinkingBudget} min={0} step={1} placeholder="0 = off" />
              </FormField>
              <label class="flex items-center gap-2 self-end pb-2 text-sm text-(--text-primary)">
                <input type="checkbox" bind:checked={pIncludeThoughts} class="accent-(--accent)" />
                Include thoughts
              </label>
            {/if}
          </div>

          <details class="border-t border-(--border) pt-3" bind:open={pAdvancedOpen}>
            <summary class="cursor-pointer text-xs text-(--text-secondary) hover:text-(--text-primary) select-none">
              Advanced — native extras (raw JSON)
            </summary>
            <div class="mt-2">
              <TextArea bind:value={pAdvanced} rows={5} mono
                placeholder={'{\n  "seed": 42\n}'} />
              <span class="text-[10px] text-(--text-secondary) mt-1 block">
                Merged on top of the fields above — for native keys the form doesn't expose. Written in this model's protocol{#if proto === 'google_gemini'} (nest sampling extras under <code>generationConfig</code>){/if}.
              </span>
            </div>
          </details>

          {#if presetError}
            <div class="flex items-start gap-2 px-3 py-2 bg-(--error)/10 border border-(--error) rounded-lg">
              <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
              <p class="text-sm text-(--error)">{presetError}</p>
            </div>
          {/if}
          <div class="flex justify-end gap-2">
            <button onclick={() => { showPresetForm = false; presetError = ''; }} class="px-3 py-1.5 border border-(--border) rounded-lg text-sm text-(--text-secondary) hover:text-(--text-primary) transition-colors">Cancel</button>
            <button onclick={savePreset} disabled={savingPreset} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50 transition-colors">
              {savingPreset ? 'Saving…' : editingPresetId ? 'Update preset' : 'Add preset'}
            </button>
          </div>
        </div>
      {:else}
        <div class="flex justify-end">
          <button onclick={openAddPreset} class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-colors">+ Add preset</button>
        </div>
      {/if}

      {#if presetsLoading}
        <div class="py-6 text-center text-sm text-(--text-secondary)">Loading presets…</div>
      {:else if presetsList.length === 0}
        <div class="py-6 text-center text-sm text-(--text-secondary)">No presets yet.</div>
      {:else}
        <div class="border border-(--border) rounded-lg divide-y divide-(--border)">
          {#each presetsList as preset}
            <div class="flex items-center gap-3 px-4 py-2.5">
              <div class="min-w-0 flex-1">
                <div class="flex items-center gap-2">
                  <span class="text-sm font-medium text-(--text-primary) truncate">{preset.name}</span>
                  {#if preset.is_default}<TagBadge color="teal">default</TagBadge>{/if}
                </div>
                <span class="text-[11px] text-(--text-secondary) font-mono truncate block">{presetSummary(preset.settings)}</span>
              </div>
              <div class="flex items-center gap-3 shrink-0">
                {#if !preset.is_default}
                  <button onclick={() => setDefaultPreset(preset)} class="text-xs text-(--text-secondary) hover:text-(--text-primary) font-medium transition-colors">Set default</button>
                {/if}
                <button onclick={() => openEditPreset(preset)} class="text-xs text-(--accent) hover:text-(--accent-hover) font-medium transition-colors">Edit</button>
                {#if !preset.is_default}
                  <button onclick={() => deletePreset(preset)} class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm font-medium transition-colors">Delete</button>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  </Modal>
{/if}

<!-- ===== Model Modal (Add / Edit) ===== -->
<Modal open={showModelModal} title={editingModelData ? 'Edit Model' : 'Add Model'} onclose={() => { showModelModal = false; editingModelData = null; }} maxWidth="max-w-2xl">
  <div class="space-y-5">
    <!-- General section -->
    <div class="space-y-4">
      <h4 class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider">General</h4>
      <div class="grid grid-cols-2 gap-4">
        <div class="col-span-2">
          <label class="block text-xs text-(--text-secondary)">Upstream Model {#if !editingModelData}<span class="text-(--error)">*</span>{/if}
            <input bind:value={modelModalForm.upstream_model} disabled={!!editingModelData} placeholder="e.g. gpt-4o" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent) transition-colors disabled:opacity-50" />
          </label>
        </div>
        <label class="block text-xs text-(--text-secondary)">Context Window
          <input bind:value={modelModalForm.context_window} type="number" placeholder="e.g. 128000" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent)" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Max Output Tokens
          <input bind:value={modelModalForm.max_output_tokens} type="number" placeholder="e.g. 16384" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary) focus:outline-hidden focus:border-(--accent)" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Upstream Protocol
          <SelectInput bind:value={modelModalForm.upstream_api_format} class="mt-1">
            {#each API_FORMATS as f}<option value={f.value}>{f.label}</option>{/each}
          </SelectInput>
        </label>
        <label class="block text-xs text-(--text-secondary)">Media Type
          <SelectInput bind:value={modelModalForm.model_type} class="mt-1">
            <option value="">Auto</option>
            {#each MODEL_TYPES as mt}<option value={mt}>{mt}</option>{/each}
          </SelectInput>
        </label>
      </div>
      <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
        <input type="checkbox" bind:checked={modelModalForm.enabled} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" />
        Enabled
      </label>
      <!-- Inherited catalog entry — capabilities/pricing left to "Inherit" resolve
           from this entry (explicit link, else auto-matched by name). -->
      <div class="space-y-1.5">
        <span class="flex items-center gap-1.5 text-xs text-(--text-secondary)">
          Inherited catalog model
          <HelpTooltip body="Capabilities and pricing left to “Inherit” are taken from this catalog entry. It is matched automatically from the model name; pick one to override the match, or clear it to fall back to auto-match." />
          {#if editingModelData}
            {#if editingModelData.catalog_model_id}
              <TagBadge color="violet" title="Linked to a catalog entry you chose">Linked</TagBadge>
            {:else if editingModelData.resolved_catalog_model_id}
              <TagBadge color="teal" title="Auto-matched from the model name">Auto-matched</TagBadge>
            {:else}
              <TagBadge color="neutral" title="No catalog entry matches — capabilities and pricing fall back to defaults">No match</TagBadge>
            {/if}
          {/if}
        </span>
        <EntityPicker search={searchCatalog} value={selectedCatalog} onselect={onSelectCatalog} placeholder="Search the catalog…" emptyText="No catalog entries" />
        {#if selectedCatalog}
          <p class="text-[10px] text-(--text-secondary)">Inheriting from <span class="font-mono text-(--text-tertiary)">{selectedCatalog.label}</span></p>
        {/if}
      </div>
    </div>

    <!-- Pricing section -->
    <div class="border border-(--border) rounded-lg overflow-hidden">
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="flex items-center gap-2 w-full px-4 py-2.5 text-left hover:bg-(--bg-elevated) transition-colors cursor-pointer" onclick={() => modelPricingOpen = !modelPricingOpen}>
        <button type="button" aria-expanded={modelPricingOpen} aria-label="Toggle Pricing" onclick={(e) => { e.stopPropagation(); modelPricingOpen = !modelPricingOpen; }} class="-m-1 p-1 rounded-sm text-(--text-secondary) hover:text-(--text-primary)">
          <span class="inline-flex transition-transform {modelPricingOpen ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
        </button>
        <span class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider">Pricing</span>
      </div>
      {#if modelPricingOpen}
        <div class="px-4 pb-4">
          <RatesEditor
            bind:form={modelRates}
            resolved={editingModelData?.resolved_rates}
            source={modelSource(MODEL_PRICE_FIELDS[0])}
            idPrefix="model-rates"
          />
        </div>
      {/if}
    </div>

    <!-- Content Modalities section -->
    <div class="border border-(--border) rounded-lg overflow-hidden">
      <!-- svelte-ignore a11y_click_events_have_key_events -->
      <!-- svelte-ignore a11y_no_static_element_interactions -->
      <div class="flex items-center gap-2 w-full px-4 py-2.5 text-left hover:bg-(--bg-elevated) transition-colors cursor-pointer" onclick={() => modelCapabilitiesOpen = !modelCapabilitiesOpen}>
        <button type="button" aria-expanded={modelCapabilitiesOpen} aria-label="Toggle Capabilities" onclick={(e) => { e.stopPropagation(); modelCapabilitiesOpen = !modelCapabilitiesOpen; }} class="-m-1 p-1 rounded-sm text-(--text-secondary) hover:text-(--text-primary)">
          <span class="inline-flex transition-transform {modelCapabilitiesOpen ? 'rotate-90' : ''}"><Icon name="chevronRight" size="sm" tone="neutral" /></span>
        </button>
        <span class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider">Capabilities</span>
      </div>
      {#if modelCapabilitiesOpen}
        <div class="px-4 pb-4 space-y-4">
          <p class="text-[10px] text-(--text-secondary)">Each capability inherits the catalog's value unless you set it to On or Off. An explicit choice is pinned, so later catalog updates and provider sync will not overwrite it; switch back to “Inherit” to release the override.</p>
          <div>
            <h5 class="text-[10px] font-medium text-(--text-secondary) uppercase tracking-wider mb-2">Content Modalities</h5>
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <CapabilityInheritSelect label="Vision" bind:value={modelModalForm.supports_vision} inheritedOn={editingModelData?.resolved_supports_vision} source={modelSource('supports_vision')} />
              <CapabilityInheritSelect label="Audio Input" bind:value={modelModalForm.supports_audio_input} inheritedOn={editingModelData?.resolved_supports_audio_input} source={modelSource('supports_audio_input')} />
              <CapabilityInheritSelect label="Audio Output" bind:value={modelModalForm.supports_audio_output} inheritedOn={editingModelData?.resolved_supports_audio_output} source={modelSource('supports_audio_output')} />
              <CapabilityInheritSelect label="Video Input" bind:value={modelModalForm.supports_video_input} inheritedOn={editingModelData?.resolved_supports_video_input} source={modelSource('supports_video_input')} />
              <CapabilityInheritSelect label="PDF Input" bind:value={modelModalForm.supports_pdf_input} inheritedOn={editingModelData?.resolved_supports_pdf_input} source={modelSource('supports_pdf_input')} />
            </div>
          </div>
          <div>
            <h5 class="text-[10px] font-medium text-(--text-secondary) uppercase tracking-wider mb-2">Features</h5>
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <CapabilityInheritSelect label="Function Calling" bind:value={modelModalForm.supports_function_calling} inheritedOn={editingModelData?.resolved_supports_function_calling} source={modelSource('supports_function_calling')} />
              <CapabilityInheritSelect label="Reasoning" bind:value={modelModalForm.supports_reasoning} inheritedOn={editingModelData?.resolved_supports_reasoning} source={modelSource('supports_reasoning')} hint={reasoningInheritHint} />
              <CapabilityInheritSelect label="Caching" bind:value={modelModalForm.supports_caching} inheritedOn={editingModelData?.resolved_supports_caching} source={modelSource('supports_caching')} />
              <CapabilityInheritSelect label="Response Schema" bind:value={modelModalForm.supports_response_schema} inheritedOn={editingModelData?.resolved_supports_response_schema} source={modelSource('supports_response_schema')} />
              <CapabilityInheritSelect label="System Messages" bind:value={modelModalForm.supports_system_messages} inheritedOn={editingModelData?.resolved_supports_system_messages} source={modelSource('supports_system_messages')} />
            </div>
          </div>
          <div>
            <h5 class="text-[10px] font-medium text-(--text-secondary) uppercase tracking-wider mb-2">Reliability</h5>
            <div class="grid grid-cols-2 sm:grid-cols-3 gap-3">
              <CapabilityInheritSelect label="Self-healing" bind:value={modelModalForm.healing_enabled} />
            </div>
            <p class="text-[10px] text-(--text-secondary) mt-1.5">Overrides the tenant self-healing setting for this model only. “Inherit” follows the tenant default.</p>
          </div>
        </div>
      {/if}
    </div>

    {#if modelError}
      <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
        <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
        <p class="text-sm text-(--error)">{modelError}</p>
      </div>
    {/if}
    <div class="flex gap-3">
      <button onclick={handleSaveModel} disabled={savingModel || (!editingModelData && !modelModalForm.upstream_model)} class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-all disabled:opacity-50 flex items-center gap-2">
        {#if savingModel}<Spinner />{/if}
        {editingModelData ? 'Update Model' : 'Add Model'}
      </button>
      <button onclick={() => { showModelModal = false; editingModelData = null; }} class="px-5 py-2 border border-(--border) rounded-lg text-(--text-secondary) text-sm hover:text-(--text-primary) transition-colors">Cancel</button>
    </div>
  </div>
</Modal>

<!-- ===== Catalog Modal (Add / Edit) ===== -->
<Modal open={showCatalogModal} title={editingCatalogData ? 'Edit Catalog Entry' : 'Add Catalog Entry'} onclose={() => { showCatalogModal = false; editingCatalogData = null; }} maxWidth="max-w-3xl">
  <div class="space-y-5">
    <!-- Identity -->
    <div>
      <h4 class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider mb-3">Identity</h4>
      <div class="grid grid-cols-4 gap-4">
        <label class="block text-xs text-(--text-secondary)">Applies to
          <SelectInput bind:value={catalogModalForm.server_id} disabled={!!editingCatalogData} class="mt-1">
            <option value="">All servers</option>
            {#each servers as s}<option value={s.id}>{s.name}</option>{/each}
          </SelectInput>
        </label>
        <label class="block text-xs text-(--text-secondary)">Provider
          <SelectInput bind:value={catalogModalForm.provider} disabled={!!editingCatalogData} class="mt-1">
            {#each PROVIDER_DEFAULTS as p}<option value={p.value}>{p.label}</option>{/each}
          </SelectInput>
        </label>
        <label class="block text-xs text-(--text-secondary)">Model
          <input bind:value={catalogModalForm.model} disabled={!!editingCatalogData} placeholder="e.g. gpt-4o" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm disabled:opacity-50 placeholder:text-(--text-secondary)" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Type
          <SelectInput bind:value={catalogModalForm.model_type} class="mt-1">
            <option value="">Auto</option>
            {#each MODEL_TYPES as mt}<option value={mt}>{mt}</option>{/each}
          </SelectInput>
        </label>
      </div>
      <p class="text-[10px] text-(--text-secondary) mt-2">
        An entry for one server wins over the all-servers entry for the same model — that is where a
        self-hosted deployment's real cost or a region's own price belongs.
      </p>
    </div>

    <!-- Context -->
    <div>
      <h4 class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider mb-3">Context</h4>
      <div class="grid grid-cols-3 gap-4">
        <label class="block text-xs text-(--text-secondary)">Context Window
          <input bind:value={catalogModalForm.context_window} type="number" placeholder="e.g. 128000" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Max Output Tokens
          <input bind:value={catalogModalForm.max_output_tokens} type="number" placeholder="e.g. 16384" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)" />
        </label>
        <label class="block text-xs text-(--text-secondary)">Output Vector Size
          <input bind:value={catalogModalForm.output_vector_size} type="number" placeholder="e.g. 1536" class="w-full mt-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm placeholder:text-(--text-secondary)" />
        </label>
      </div>
    </div>

    <!-- Price list — the catalog is the root of the ladder, so there is no
         inherit toggle: this entry owns its prices outright. -->
    <div>
      <RatesEditor bind:form={catalogRates} inheritable={false} idPrefix="catalog-rates" />
      <p class="text-[10px] text-(--text-secondary) mt-2">
        Every upstream model bound to this entry bills at these prices unless it states a price list
        of its own.
      </p>
    </div>

    <!-- Capabilities -->
    <div>
      <h4 class="text-xs font-medium text-(--text-secondary) uppercase tracking-wider mb-3">Capabilities</h4>
      <div class="grid grid-cols-2 sm:grid-cols-5 gap-x-4 gap-y-2">
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_vision} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Vision
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_function_calling} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Tools
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_reasoning} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Reasoning
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_caching} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Caching
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_response_schema} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Schema
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_system_messages} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> System Msgs
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_audio_input} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Audio In
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_audio_output} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Audio Out
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_video_input} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> Video In
        </label>
        <label class="inline-flex items-center gap-2 text-xs text-(--text-secondary) cursor-pointer">
          <input type="checkbox" bind:checked={catalogModalForm.supports_pdf_input} class="rounded-sm border-(--border) text-(--accent) focus:ring-(--accent)" /> PDF In
        </label>
      </div>
    </div>

    {#if catalogError}
      <div class="flex items-start gap-2 px-3.5 py-3 bg-(--error)/10 border border-(--error) rounded-lg">
        <span class="shrink-0 mt-0.5"><Icon name="errorCircle" size="sm" tone="error" /></span>
        <p class="text-sm text-(--error)">{catalogError}</p>
      </div>
    {/if}
    <div class="flex gap-3">
      <button onclick={handleSaveCatalog} disabled={!editingCatalogData && !catalogModalForm.model} class="px-5 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium transition-all disabled:opacity-50">{editingCatalogData ? 'Update Entry' : 'Create Entry'}</button>
      <button onclick={() => { showCatalogModal = false; editingCatalogData = null; }} class="px-5 py-2 border border-(--border) rounded-lg text-(--text-secondary) text-sm hover:text-(--text-primary) transition-colors">Cancel</button>
    </div>
  </div>
</Modal>

<style>
  @keyframes modal-in {
    from { opacity: 0; transform: scale(0.95); }
    to { opacity: 1; transform: scale(1); }
  }
  .animate-modal-in {
    animation: modal-in 0.2s ease-out;
  }
</style>

<ImpactModal
  open={impactModal.open}
  title={impactModal.title}
  message={impactModal.message}
  affectedKeys={impactModal.affectedKeys}
  affectedUsers={impactModal.affectedUsers}
  confirmLabel={impactModal.confirmLabel}
  onconfirm={impactModal.onconfirm}
  oncancel={() => impactModal.open = false}
/>
