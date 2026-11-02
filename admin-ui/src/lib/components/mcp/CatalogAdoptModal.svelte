<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import Spinner from '#lib/components/Spinner.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import OauthProviderGuide from '#lib/components/mcp/OauthProviderGuide.svelte';

  type CatalogEntry = components['schemas']['McpCatalogEntry'];
  type Workspace = components['schemas']['WorkspaceSummary'];

  let {
    entry,
    onclose,
    onadopted,
  }: {
    entry: CatalogEntry | null;
    onclose: () => void;
    onadopted: (result: { slug: string; upstreamId: string; needsOauthConfig: boolean }) => void;
  } = $props();

  let slug = $state('');
  let credential = $state('');
  let oauthClientId = $state('');
  let oauthClientSecret = $state('');
  let selectedWorkspaces = $state<Set<string>>(new Set());

  let workspaces = $state<Workspace[]>([]);
  let workspacesLoading = $state(false);
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

  // Reset the form whenever a new entry opens the modal.
  $effect(() => {
    if (entry) {
      slug = slugify(entry.name);
      credential = '';
      oauthClientId = '';
      oauthClientSecret = '';
      registerMsg = '';
      selectedWorkspaces = new Set();
      error = '';
      void loadWorkspaces();
    }
  });

  async function loadWorkspaces() {
    workspacesLoading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/workspaces', {
      params: { query: { limit: 200 } },
    });
    if (err) {
      error = extractError(err);
    } else if (data) {
      workspaces = data.items;
    }
    workspacesLoading = false;
  }

  function toggleWorkspace(id: string) {
    const next = new Set(selectedWorkspaces);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    selectedWorkspaces = next;
  }

  const needsCredential = $derived(entry?.auth_mode === 'service_account');
  const isOauth = $derived(entry?.auth_mode === 'per_user_oauth');
  const isByot = $derived(entry?.auth_mode === 'byot');
  // A per_user_oauth endpoint can't be granted to a workspace until its OAuth
  // client is supplied — so when the operator picks a workspace, the client
  // credentials become required (the server enforces this too).
  const oauthClientRequired = $derived(isOauth && selectedWorkspaces.size > 0);

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

  // Self-register an OAuth client via RFC 7591 DCR using the catalog entry's
  // own URLs, then fill the Client ID/Secret below. Providers without DCR
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
          upstream_url: entry.upstream_url,
          issuer_url: entry.oauth_issuer_url ?? undefined,
          default_scopes: entry.oauth_default_scopes ?? [],
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
    if (needsCredential && !credential.trim()) {
      error = 'This server needs a service-account token to adopt.';
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
    const { data, error: err } = await adminApi.POST('/api/v1/admin/mcp/catalog/{id}/actions/adopt', {
      params: { path: { id: entry.id } },
      body: {
        slug: slug.trim() || undefined,
        credential: needsCredential ? credential.trim() : undefined,
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
      upstreamId: data?.upstream_id ?? '',
      needsOauthConfig,
    });
  }
</script>

<Modal
  open={entry !== null}
  title={`Adopt ${entry?.display_title || entry?.name || ''}`}
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

      {#if needsCredential}
        <label class="block space-y-1">
          <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">Service-account token</span>
          <TextInput
            bind:value={credential}
            type="password"
            autocomplete="off"
            placeholder="Bearer token shared across all users"
          />
          <span class="text-xs text-(--text-secondary)">Encrypted at rest; stamped on every upstream request.</span>
        </label>
      {/if}

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
            upstreamUrl={entry.upstream_url}
            issuerUrl={entry.oauth_issuer_url ?? ''}
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

      {#if isByot}
        <p class="rounded-lg border border-(--border) p-3 text-xs text-(--text-secondary)">
          This server forwards each client's own bearer token. No credential is stored here — clients
          authenticate through the gateway with their token.
        </p>
      {/if}

      <div class="space-y-1">
        <span class="block text-xs uppercase tracking-wide text-(--text-secondary)">Grant to workspaces</span>
        {#if workspacesLoading}
          <div class="py-2"><Spinner /></div>
        {:else if workspaces.length === 0}
          <p class="text-xs text-(--text-secondary)">No workspaces yet. You can grant access later.</p>
        {:else}
          <div class="max-h-40 space-y-1 overflow-y-auto rounded-lg border border-(--border) p-2">
            {#each workspaces as ws (ws.id)}
              <label class="flex items-center gap-2 rounded-sm px-1 py-0.5 hover:bg-(--bg-primary)">
                <input
                  type="checkbox"
                  class="accent-(--accent)"
                  checked={selectedWorkspaces.has(ws.id)}
                  onchange={() => toggleWorkspace(ws.id)}
                />
                <span class="text-(--text-primary)">{ws.name}</span>
                {#if ws.role === 'default'}
                  <span class="text-xs text-(--text-secondary)">(default)</span>
                {/if}
              </label>
            {/each}
          </div>
        {/if}
        <span class="text-xs text-(--text-secondary)">
          Workspace members can use the endpoint once granted. Skip to grant later.
        </span>
      </div>

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
      disabled={submitting}
    >
      {submitting ? 'Adopting…' : 'Adopt server'}
    </button>
  {/snippet}
</Modal>
