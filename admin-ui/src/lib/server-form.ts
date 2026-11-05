// The rules an upstream server's form obeys — which fields a provider fills,
// what a transport forbids, and what a save actually sends. Shared by the
// create wizard and the server's own settings tab so the two cannot drift: a
// rule stated once is a rule both surfaces keep.
import { PROVIDER_DEFAULTS, providerDefaultTransport } from '#lib/generated/providers.js';

export interface ServerForm {
  name: string;
  provider: string;
  api_key: string;
  upstream_url: string;
  upstream_api_format: string;
  chat_endpoint_path: string;
  transport: string;
}

/** What a provider's seed says a new server for it looks like. */
export interface ProviderSeed {
  url: string;
  apiFormat: string;
  chatEndpointPath: string;
  transport: string;
}

/** The catalog as the running admin-api serves it, keyed by provider. */
export type ProviderSeeds = Record<string, ProviderSeed>;

/** The provider seed compiled into this build — the fallback for a provider the
 *  running admin-api did not list, and the whole answer before its catalog
 *  arrives. */
export function seedFor(provider: string, seeds: ProviderSeeds): ProviderSeed {
  const served = seeds[provider];
  if (served) return served;
  const built = PROVIDER_DEFAULTS.find((p) => p.value === provider);
  return {
    url: built?.defaultUrl ?? '',
    apiFormat: built?.defaultApiFormat ?? 'chat_completions',
    chatEndpointPath: built?.defaultChatEndpointPath ?? '',
    transport: built?.defaultTransport ?? providerDefaultTransport(provider),
  };
}

/** A transport that owns its URL fixes the endpoint path and the credential
 *  header, so the form hides the path override rather than offering a
 *  combination the API rejects. */
export function transportOwnsUrl(transport: string): boolean {
  return transport !== 'default';
}

/** Whether a transport's endpoint publishes a model list the gateway can read
 *  at all. Kept in step with the backend's `publishes_model_list`, which is
 *  what refuses discovery and clamps auto-sync off at write time. Not exported:
 *  `canModelSync` is the whole question, and half of it is never the answer. */
const NO_MODEL_LIST_TRANSPORTS = new Set(['google_vertex']);

function transportPublishesModelList(transport: string | null | undefined): boolean {
  return !NO_MODEL_LIST_TRANSPORTS.has(transport ?? 'default');
}

/** Whether a PROVIDER publishes a model list at all. Kept in step with the
 *  backend's `PROVIDERS_WITHOUT_MODELS_ENDPOINT`, which is the one set deciding
 *  both the write-time reachability probe and which servers the periodic worker
 *  re-discovers — so a provider is here only when its list cannot be read. */
const NO_MODEL_LIST_PROVIDERS = new Set(['perplexity']);

export function providerPublishesModelList(provider: string): boolean {
  // Case-folded, as both backend halves are: a row stored as "Perplexity" —
  // which nothing normalises on the way in — would otherwise be offered a
  // discovery toggle here that the API clamps straight back off, so the switch
  // bounces instead of being absent.
  return !NO_MODEL_LIST_PROVIDERS.has(provider.trim().toLowerCase());
}

/** Whether this server's models can be discovered — at create, on an explicit
 *  "Sync now", and by the periodic worker, which are one question. Both halves
 *  must hold: the provider must publish a list, and the transport must address
 *  an endpoint that serves one. */
export function canModelSync(server: { provider: string; transport?: string | null }): boolean {
  return providerPublishesModelList(server.provider) && transportPublishesModelList(server.transport);
}

/** Whether the console offers to ask this server for its models (Sync now,
 *  Review, the auto-sync switch): it must be discoverable, and hold a key —
 *  unless it is self-hosted, where a keyless engine is normal. A keyless server
 *  at its provider's own default address is a cloud account missing its key:
 *  every ask would be refused. */
export function canAskForModels(server: {
  provider: string;
  transport?: string | null;
  upstream_url?: string | null;
  has_credential: boolean;
}): boolean {
  if (!canModelSync(server)) return false;
  if (server.has_credential) return true;
  const cloud = PROVIDER_DEFAULTS.find((p) => p.value === server.provider)?.defaultUrl ?? '';
  const bare = (url: string) => url.trim().replace(/\/+$/, '').toLowerCase();
  // No URL of its own is the provider's default address.
  return !cloud || (bare(server.upstream_url ?? '') || bare(cloud)) !== bare(cloud);
}

/** Every server forwards to a URL it states — the backend refuses one it cannot
 *  resolve. A provider with a seed default (OpenAI, Anthropic, …) fills it;
 *  vLLM, Ollama and Custom have none, and a keyless pass-through has no
 *  provider default to fall back on.
 *
 *  A transport that owns its URL needs one whatever the provider says: its
 *  address is a resource, a region or a project, and no provider default can
 *  stand in for it. Without this, picking OpenAI and then Azure passes the
 *  provider's own host to a transport that appends `/openai/v1/…` to it. */
export function urlRequired(
  form: Pick<ServerForm, 'provider' | 'transport'>,
  seeds: ProviderSeeds,
  byok: boolean,
): boolean {
  return byok || transportOwnsUrl(form.transport) || !seedFor(form.provider, seeds).url;
}

/** Picking a provider carries its seed's URL, protocol, endpoint path and
 *  transport. A field is overwritten only while it still holds the PREVIOUS
 *  provider's default or nothing at all, so a value typed by hand survives the
 *  switch — and a field left on another provider's default can never reach a
 *  probe against the wrong host.
 *
 *  `keepUrl` is for a form whose address is not its to change: a server that
 *  can have replicas is addressed by its ENDPOINTS, and letting a provider
 *  pick set the URL there would re-point the primary replica — leaving its
 *  siblings where they are — from a field that is not even on screen. */
export function applyProvider(
  form: ServerForm,
  provider: string,
  seeds: ProviderSeeds,
  keepUrl = false,
): ServerForm {
  const was = seedFor(form.provider, seeds);
  const now = seedFor(provider, seeds);
  const keep = (current: string, previousDefault: string) => current.trim() !== '' && current.trim() !== previousDefault;
  const next: ServerForm = {
    ...form,
    provider,
    upstream_url: keepUrl || keep(form.upstream_url, was.url) ? form.upstream_url : now.url,
    upstream_api_format: keep(form.upstream_api_format, was.apiFormat) ? form.upstream_api_format : now.apiFormat,
    chat_endpoint_path: keep(form.chat_endpoint_path, was.chatEndpointPath) ? form.chat_endpoint_path : now.chatEndpointPath,
  };
  // The transport is a property of the endpoint shape, so it follows the
  // provider outright: choosing Azure OpenAI selects its transport with no
  // extra step. An operator can still override it afterwards.
  return applyTransport(next, now.transport, seeds);
}

/** A transport that owns its URL fixes the endpoint path, and the API rejects a
 *  server that sets both. Clear the override as the transport changes so a
 *  value carried over from another provider cannot fail the save from a field
 *  the form no longer shows.
 *
 *  It also drops an address that is still the PROVIDER'S default, because such
 *  a transport never addresses the provider's own host — it addresses a
 *  resource, a region or a project. Without this the address stays non-empty,
 *  so `urlRequired` is satisfied by a value that cannot be right and the only
 *  objection left is the probe, which "Save anyway" exists to overrule. */
export function applyTransport(
  form: ServerForm,
  transport: string,
  seeds: ProviderSeeds = {},
): ServerForm {
  const ownsUrl = transportOwnsUrl(transport);
  const providerDefault = seedFor(form.provider, seeds).url;
  const stillProviderDefault = providerDefault !== '' && form.upstream_url.trim() === providerDefault;
  return {
    ...form,
    transport,
    upstream_url: ownsUrl && stillProviderDefault ? '' : form.upstream_url,
    chat_endpoint_path: ownsUrl ? '' : form.chat_endpoint_path,
  };
}

/** The body of a `PATCH /servers/{id}`: only what the operator actually
 *  changed. A field cleared to nothing is sent as an explicit `null`, which the
 *  API reads as "back to the provider default" — distinct from an absent field,
 *  which leaves it alone. */
export interface ServerPatch {
  name?: string;
  provider?: string;
  api_key?: string;
  upstream_url?: string | null;
  upstream_api_format?: string;
  chat_endpoint_path?: string | null;
  transport?: string;
}

export function serverPatch(initial: ServerForm, next: ServerForm): ServerPatch {
  const patch: ServerPatch = {};
  // Compared and sent TRIMMED, on both sides: a name is unique, so a stray
  // trailing space would store a second server the console renders identically
  // to the first. Trimming only what is sent would instead report a stored name
  // that already has one as an unsaved edit, forever.
  const name = next.name.trim();
  if (name !== initial.name.trim()) patch.name = name;
  if (next.provider !== initial.provider) patch.provider = next.provider;
  // A credential is write-only — an empty box keeps the stored one, so only a
  // typed value is a rotation.
  if (next.api_key) patch.api_key = next.api_key;
  // Sending an UNCHANGED URL is not free: the API reads it as the primary
  // endpoint's URL, and writing a different one there resets that replica to
  // never-answered. Omitting it while it is untouched is what keeps a server's
  // other settings editable without disturbing its replicas.
  // Trimmed on both sides, as the name is and for the same reason: a stray
  // space is not an address change, and treating one as a change rewrites the
  // primary endpoint — resetting that replica's discovery for a no-op edit.
  const url = next.upstream_url.trim();
  if (url !== initial.upstream_url.trim()) patch.upstream_url = url || null;
  if (next.upstream_api_format !== initial.upstream_api_format) patch.upstream_api_format = next.upstream_api_format;
  const path = next.chat_endpoint_path.trim();
  if (path !== initial.chat_endpoint_path.trim()) patch.chat_endpoint_path = path || null;
  if (next.transport !== initial.transport) patch.transport = next.transport;
  return patch;
}

export function isEmptyPatch(patch: ServerPatch): boolean {
  return Object.keys(patch).length === 0;
}

/** Whether this patch changes anything the backend's reachability probe is
 *  about. It probes on every write unless told not to, so a rename would
 *  otherwise be refused while the upstream happens to be down — for an edit
 *  that touches nothing the probe could validate. */
const PROBED_FIELDS = ['provider', 'api_key', 'upstream_url', 'upstream_api_format', 'chat_endpoint_path', 'transport'] as const;

export function patchNeedsProbe(patch: ServerPatch): boolean {
  return PROBED_FIELDS.some((f) => f in patch);
}
