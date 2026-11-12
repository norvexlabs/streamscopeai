<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import OauthProviderGuide from '#lib/components/mcp/OauthProviderGuide.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { FILLER_HELP, FILLER_NAME } from '#lib/mcp/fillers.js';
  import AdminInputValues from '#lib/components/mcp/AdminInputValues.svelte';
  import WorkspaceGrantChecklist from '#lib/components/mcp/WorkspaceGrantChecklist.svelte';
  import { untrack } from 'svelte';
  import {
    declaredInputs,
    defaultFillers,
    inputHeaders,
    missingAdminValues,
    splitAdminValues,
    withHeaderFiller,
    type Filler,
    type Remote,
    type SecretEdit,
  } from '#lib/mcp/headerInputs.js';
  import { catalogMeta, displayName, previewUrl, urlVariables } from '#lib/mcp/serverJson.js';

  type CatalogEntry = components['schemas']['McpCatalogEntry'];

  let {
    entry,
    onclose,
    onadopted,
  }: {
    entry: CatalogEntry | null;
    onclose: () => void;
    /** `upstreamId` is null when the answer names no upstream. */
    onadopted: (result: { slug: string; upstreamId: string | null; needsOauthConfig: boolean }) => void;
  } = $props();

  let slug = $state('');
  let remoteIndex = $state(0);
  let urlValues = $state<Record<string, string>>({});
  let fillers = $state<Record<string, Filler>>({});
  let plain = $state<Record<string, string>>({});
  let secrets = $state<Record<string, SecretEdit>>({});
  let authMode = $state<'headers' | 'per_user_oauth'>('headers');
  let oauthClientId = $state('');
  let oauthClientSecret = $state('');
  let selectedWorkspaces = $state<Set<string>>(new Set());

  let submitting = $state(false);
  let registering = $state(false);
  let registerMsg = $state('');
  let error = $state('');

  function slugify(name: string): string {
    const s = name
      .toLowerCase()
      .replace(/[^a-z0-9]+/g, '-')
      .replace(/^-+|-+$/g, '')
      .slice(0, 31)
      .replace(/-+$/g, '');
    return s || 'server';
  }

  const remotes = $derived(entry?.server_json.remotes ?? []);
  const remote = $derived<Remote>(remotes[remoteIndex] ?? {});
  const inputs = $derived(declaredInputs(remote));
  const headers = $derived(inputHeaders(inputs));
  const urlVars = $derived(urlVariables(remote));
  const hints = $derived(entry ? catalogMeta(entry.server_json).oauth : undefined);
  const adminInputs = $derived(inputs.filter((d) => fillers[d.id] === 'admin'));
  const isOauth = $derived(authMode === 'per_user_oauth');
  const authorizationDeclared = $derived(headers.some((h) => h.header.toLowerCase() === 'authorization'));
  const finishedUrl = $derived(previewUrl(remote, urlValues));
  // A per_user_oauth endpoint can't be granted to a workspace until its OAuth
  // client is supplied — so when the operator picks a workspace, the client
  // credentials become required (the server enforces this too).
  const oauthClientRequired = $derived(isOauth && selectedWorkspaces.size > 0);

  // Reset the form whenever a new entry opens the modal.
  // Before the fields render: each binds to a key this sets.
  $effect.pre(() => {
    const e = entry;
    if (!e) return;
    untrack(() => {
      const sj = e.server_json;
      slug = slugify((sj.title || sj.name.split('/').pop()) ?? sj.name);
      remoteIndex = 0;
      authMode = catalogMeta(sj).oauth ? 'per_user_oauth' : 'headers';
      oauthClientId = '';
      oauthClientSecret = '';
      registerMsg = '';
      selectedWorkspaces = new Set();
      error = '';
      pickRemote(0);
    });
  });

  /** Start a remote's fields over: URL variables at their defaults, each
   *  header with its default filler, no value typed. */
  function pickRemote(i: number) {
    remoteIndex = i;
    const r = (entry?.server_json.remotes ?? [])[i] ?? {};
    urlValues = Object.fromEntries(urlVariables(r).map((v) => [v.name, v.input.default ?? '']));
    fillers = defaultFillers(declaredInputs(r));
    plain = {};
    secrets = {};
  }

  // Redirect URI + homepage for the provider setup guide — server-derived from
  // tenant settings (never from window.location; the API origin can differ).
  // Fetched once when an OAuth entry opens the modal.
  let oauthRedirectUri = $state<string | null>(null);
  let oauthHomepage = $state<string | null>(null);
  $effect(() => {
    if (!isOauth || oauthRedirectUri !== null) return;
    adminApi.GET('/api/v1/admin/settings').then(({ data }) => {
      oauthRedirectUri = data?.mcp_oauth_redirect_uri ?? null;
      oauthHomepage = data?.admin_public_url ?? data?.api_public_url ?? null;
    });
  });

  // Self-register an OAuth client via RFC 7591 DCR using the entry's URL and
  // OAuth hints, then fill the Client ID/Secret below. Providers without DCR
  // (e.g. GitHub) return a clear "register manually" error.
  async function registerClient() {
    if (!entry) return;
    error = '';
    registerMsg = '';
    registering = true;
    const { data, error: err } = await adminApi.POST(
      '/api/v1/admin/mcp/upstream-servers/actions/register-oauth-client',
      {
        body: {
          upstream_url: finishedUrl,
          issuer_url: hints?.issuerUrl ?? undefined,
          default_scopes: hints?.defaultScopes ?? [],
        },
      },
    );
    registering = false;
    if (err) {
      error = extractError(
        err,
        'Automatic registration failed — enter the Client ID and Secret manually.',
      );
      return;
    }
    oauthClientId = data?.client_id ?? '';
    oauthClientSecret = data?.client_secret ?? '';
    registerMsg = data?.client_secret
      ? 'Registered an OAuth client and filled the fields below.'
      : 'Registered a public OAuth client (no secret) and filled the field below.';
  }

  async function adopt() {
    if (!entry) return;
    const secretValues = Object.fromEntries(Object.entries(secrets).map(([id, e]) => [id, e.value]));
    const values = { ...plain, ...secretValues };
    const missing = missingAdminValues(inputs, fillers, (id) => (values[id] ?? '') !== '');
    if (missing.length > 0) {
      error = `Enter a value for ${missing.join(', ')} — it is filled by the administrator and required.`;
      return;
    }
    if (oauthClientRequired && (!oauthClientId.trim() || !oauthClientSecret.trim())) {
      error =
        'Granting this per-user-OAuth server to a workspace needs its OAuth client ID and secret. ' +
        'Add them, or clear the workspace selection and configure the client first.';
      return;
    }
    submitting = true;
    error = '';
    const split = splitAdminValues(inputs, fillers, values);
    const { data, error: err } = await adminApi.POST('/api/v1/admin/mcp/catalog/{id}/actions/adopt', {
      params: { path: { id: entry.id } },
      body: {
        slug: slug.trim() || undefined,
        remote_index: remoteIndex,
        url_variables: Object.fromEntries(Object.entries(urlValues).filter(([, v]) => v !== '')),
        auth_mode: authMode,
        fillers,
        inputs: split.inputs,
        secret_inputs: split.secret_inputs,
        oauth_client_id: isOauth && oauthClientId.trim() ? oauthClientId.trim() : undefined,
        oauth_client_secret: isOauth && oauthClientSecret.trim() ? oauthClientSecret.trim() : undefined,
        workspace_ids: [...selectedWorkspaces],
      },
    });
    submitting = false;
    if (err) {
      error = extractError(err);
      return;
    }
    // When a per_user_oauth server was adopted without its client, send the
    // operator straight to the upstream's OAuth form to finish setup.
    const needsOauthConfig = isOauth && !(oauthClientId.trim() && oauthClientSecret.trim());
    toast.success('Server adopted', `Endpoint /mcp/${data?.slug} is ready`);
    onadopted({
      slug: data?.slug ?? slug,
      upstreamId: data?.upstream_id ?? null,
      needsOauthConfig,
    });
  }

</script>

<Modal
  open={entry !== null}
  title={`Adopt ${entry ? displayName(entry.server_json) : ''}`}
  onclose={onclose}
  maxWidth="max-w-xl"
>
  {#if entry}
    <div class="space-y-4 text-sm">
      <p class="text-(--text-secondary)">
        This creates an upstream server, an endpoint at <code class="text-(--text-primary)">/mcp/{slug || 'slug'}</code>,
        and the route connecting them. You can edit everything afterward.
      </p>

      <label class="block space-y-1">
        <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">Endpoint slug</span>
        <TextInput bind:value={slug} mono spellcheck="false" />
      </label>

      {#if remotes.length > 1}
        <label class="block space-y-1">
          <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">Endpoint</span>
          <SelectInput value={remoteIndex} onchange={(e) => pickRemote(Number(e.currentTarget.value))} data-testid="adopt-remote">
            {#each remotes as r, i (i)}
              <option value={i}>{r.url} ({r.type === 'sse' ? 'HTTP+SSE' : 'Streamable HTTP'})</option>
            {/each}
          </SelectInput>
        </label>
      {/if}

      {#if urlVars.length > 0}
        <div class="space-y-2 rounded-lg border border-(--border) p-3">
          <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">URL</span>
          {#each urlVars as v (v.name)}
            <label class="block space-y-1">
              <span class="text-xs font-mono text-(--text-primary)">{v.name}{#if v.input.isRequired}<span class="text-(--warning-text)"> *</span>{/if}</span>
              {#if v.input.description}<span class="text-xs text-(--text-secondary) ml-1">{v.input.description}</span>{/if}
              {#if (v.input.choices ?? []).length > 0}
                <SelectInput bind:value={urlValues[v.name]} data-testid="adopt-url-var">
                  {#each v.input.choices ?? [] as c}<option value={c}>{c}</option>{/each}
                </SelectInput>
              {:else}
                <TextInput mono bind:value={urlValues[v.name]} placeholder={v.input.placeholder ?? ''} data-testid="adopt-url-var" />
              {/if}
            </label>
          {/each}
          <p class="text-xs text-(--text-secondary)">Requests go to <code class="font-mono break-all">{finishedUrl}</code></p>
        </div>
      {:else}
        <p class="text-xs text-(--text-secondary)">Requests go to <code class="font-mono break-all">{finishedUrl}</code></p>
      {/if}

      <label class="block space-y-1">
        <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">User sign-in</span>
        <SelectInput bind:value={authMode} data-testid="adopt-auth-mode">
          <option value="headers">None (headers only)</option>
          <option value="per_user_oauth">Per-user OAuth{hints ? ' (recommended for this server)' : ''}</option>
        </SelectInput>
        {#if isOauth && !hints}
          <span class="text-xs text-(--text-secondary)">This entry carries no OAuth endpoints — the gateway discovers them from the server.</span>
        {/if}
      </label>

      {#if headers.length > 0}
        <div class="space-y-2 rounded-lg border border-(--border) p-3" data-testid="adopt-fillers">
          <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">Who fills each header</span>
          {#each headers as h (h.header)}
            {@const d = inputs.find((x) => x.id === h.ids[0])}
            <label class="block space-y-1">
              <span class="text-xs font-mono text-(--text-primary)">{h.header}</span>
              {#if d?.input.description}<span class="text-xs text-(--text-secondary) ml-1">{d.input.description}</span>{/if}
              <SelectInput
                value={fillers[h.ids[0]] ?? 'user'}
                onchange={(e) => {
                  const v = e.currentTarget.value;
                  fillers = withHeaderFiller(inputs, fillers, h.header, v === 'admin' ? 'admin' : v === 'client' ? 'client' : 'user');
                }}
                data-testid="adopt-filler"
                data-header={h.header}>
                <option value="admin">{FILLER_NAME.admin}</option>
                <option value="user">{FILLER_NAME.user}</option>
                {#if h.whole}<option value="client">{FILLER_NAME.client}</option>{/if}
              </SelectInput>
              <span class="block text-xs text-(--text-secondary)" data-testid="filler-help">{FILLER_HELP[fillers[h.ids[0]] ?? 'user']}</span>
            </label>
          {/each}
          <p class="text-xs text-(--text-secondary)">
            Keep URLs and host names with the administrator: a value a user fills is sent wherever it points.
          </p>
          {#if isOauth && authorizationDeclared}
            <p class="text-xs text-(--warning-text)" data-testid="oauth-authorization-conflict">
              This endpoint declares an Authorization header, which per-user OAuth uses for each user's token —
              choose "None (headers only)" or another endpoint.
            </p>
          {/if}
        </div>
      {/if}

      <AdminInputValues inputs={adminInputs} bind:plain bind:secrets />

      {#if isOauth}
        <div class="space-y-3 rounded-lg border border-(--border) p-3">
          <p class="text-xs text-(--text-secondary)">
            This server uses per-user OAuth. The Client ID/Secret is a single OAuth app you register
            once with the provider — it identifies the gateway, not any user; each portal user then
            links their own account.
            {#if oauthClientRequired}
              <span class="text-(--warning-text)">Required to grant the endpoint to a workspace.</span>
            {:else}
              Optional now — you can add it later on the upstream server (but the endpoint can't be
              granted to a workspace until you do).
            {/if}
          </p>
          <div class="flex items-center gap-2">
            <button
              type="button"
              data-testid="register-oauth-client"
              class="rounded-lg border border-(--border) px-3 py-2 text-xs hover:bg-(--bg-primary) disabled:opacity-60"
              onclick={registerClient}
              disabled={registering}
            >
              {registering ? 'Registering…' : 'Register client automatically'}
            </button>
            <span class="text-xs text-(--text-secondary)">
              For providers that support DCR. GitHub and others need a manual app.
            </span>
          </div>
          {#if registerMsg}
            <div
              data-testid="register-status"
              class="rounded-lg border border-(--success-border) bg-(--success-bg) px-3 py-2 text-xs text-(--success)"
            >
              {registerMsg}
            </div>
          {/if}
          <OauthProviderGuide
            upstreamUrl={finishedUrl}
            issuerUrl={hints?.issuerUrl ?? ''}
            redirectUri={oauthRedirectUri}
            homepage={oauthHomepage} />
          <label class="block space-y-1">
            <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">
              OAuth client ID{#if oauthClientRequired} <span class="text-(--warning-text)">*</span>{/if}
            </span>
            <TextInput bind:value={oauthClientId} autocomplete="off" />
          </label>
          <label class="block space-y-1">
            <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">
              OAuth client secret{#if oauthClientRequired} <span class="text-(--warning-text)">*</span>{/if}
            </span>
            <TextInput bind:value={oauthClientSecret} type="password" autocomplete="off" />
          </label>
        </div>
      {/if}

      <WorkspaceGrantChecklist
        bind:selected={selectedWorkspaces}
        note="Workspace members can use the endpoint once granted. Skip to grant later." />

      {#if error}
        <div class="rounded-lg border border-(--error-border) bg-(--error-bg) px-3 py-2 text-(--error-text)">
          {error}
        </div>
      {/if}
    </div>
  {/if}

  {#snippet footer()}
    <button
      type="button"
      class="rounded-lg border border-(--border) px-3 py-2 text-sm text-(--text-secondary) hover:bg-(--bg-primary)"
      onclick={onclose}
      disabled={submitting}
    >
      Cancel
    </button>
    <button
      type="button"
      class="rounded-lg bg-(--accent) px-3 py-2 text-sm font-medium text-(--accent-fg) hover:bg-(--accent-hover) disabled:opacity-50"
      onclick={adopt}
      data-testid="adopt-submit"
      disabled={submitting}
    >
      {submitting ? 'Adopting…' : 'Adopt server'}
    </button>
  {/snippet}
</Modal>
