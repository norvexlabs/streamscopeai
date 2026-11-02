<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import Modal from '#lib/components/Modal.svelte';
  import ConfirmDialog from '#lib/components/ConfirmDialog.svelte';
  import Copyable from '#lib/components/Copyable.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import OauthProviderGuide from '#lib/components/mcp/OauthProviderGuide.svelte';

  type UpstreamRow = components['schemas']['McpUpstreamServerRow'];

  interface Props {
    open: boolean;
    editing: UpstreamRow | null;
    onclose: () => void;
    onsaved: () => void;
  }

  let { open, editing, onclose, onsaved }: Props = $props();

  let form = $state({
    name: '',
    description: '',
    upstream_url: '',
    transport: 'streamable_http',
    auth_mode: 'no_auth',
    /// Empty on edit (we never echo the stored ciphertext).
    /// On create or rotate, the operator types a fresh bearer token here.
    credential: '',
    // ── Per-user OAuth client config ──
    oauth_issuer_url: '',
    oauth_authorization_url: '',
    oauth_token_url: '',
    oauth_revocation_url: '',
    oauth_client_id: '',
    /// Empty on edit — never echoed. New value rotates the secret.
    oauth_client_secret: '',
    oauth_default_scopes_csv: '',
    enabled: true,
    connect_timeout_ms: 10000,
    request_timeout_ms: 60000,
  });
  let formError = $state('');

  // OAuth endpoint discovery — the gateway probes the upstream's RFC 9728 +
  // RFC 8414/OIDC metadata and fills the URL fields for review (it persists
  // nothing). Servers without OAuth metadata fail cleanly → manual entry.
  let discovering = $state(false);
  let discoverMsg = $state<{ kind: 'ok' | 'warn'; text: string } | null>(null);

  // RFC 7591 dynamic client registration — for providers that advertise a
  // registration endpoint, the gateway self-registers an OAuth client and fills
  // the Client ID/Secret below. Providers without DCR (e.g. GitHub) return a
  // clear "register manually" error.
  let registering = $state(false);
  let registerMsg = $state<{ kind: 'ok' | 'warn'; text: string } | null>(null);

  // What the last discovery learned about DCR, tagged with the server it was
  // about. Registration re-discovers server-side and remains the authority, so
  // this only decides whether to offer the button — and tagging it means
  // editing either URL re-enables it rather than leaving another server's
  // answer in force.
  //
  // BOTH URLs identify the probe, and they are compared as separate fields
  // rather than joined into one key: an explicit issuer skips the lookup that
  // would otherwise derive it from the server URL, so the pair is what names
  // the authorization server a verdict describes — and any delimiter cheap
  // enough to write is one a URL could itself contain.
  let discovered = $state<{ upstream: string; issuer: string; dcr: boolean } | null>(null);
  const dcrUnsupported = $derived(
    discovered !== null &&
      discovered.upstream === form.upstream_url.trim() &&
      discovered.issuer === form.oauth_issuer_url.trim() &&
      !discovered.dcr,
  );

  async function registerClient() {
    formError = '';
    registerMsg = null;
    if (form.upstream_url.trim() === '') {
      formError = 'Enter the server URL first.';
      return;
    }
    registering = true;
    try {
      const scopes = form.oauth_default_scopes_csv
        .split(/[\s,]+/)
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const { data, error } = await adminApi.POST(
        '/api/v1/admin/mcp/upstream-servers/actions/register-oauth-client',
        {
          body: {
            upstream_url: form.upstream_url.trim(),
            issuer_url: form.oauth_issuer_url.trim() || undefined,
            default_scopes: scopes,
          },
        },
      );
      if (error || !data) {
        formError = extractError(
          error,
          'Automatic registration failed — enter the Client ID and Secret manually.',
        );
        return;
      }
      form.oauth_client_id = data.client_id;
      form.oauth_client_secret = data.client_secret ?? '';
      registerMsg = {
        kind: 'ok',
        text: data.client_secret
          ? 'Registered an OAuth client. Review and save to store it.'
          : 'Registered a public OAuth client (no secret). Review and save to store it.',
      };
    } finally {
      registering = false;
    }
  }

  async function discoverEndpoints() {
    formError = '';
    discoverMsg = null;
    if (form.upstream_url.trim() === '') {
      formError = 'Enter the server URL first.';
      return;
    }
    discovering = true;
    try {
      const { data, error } = await adminApi.POST(
        '/api/v1/admin/mcp/upstream-servers/actions/discover-oauth',
        {
          body: {
            upstream_url: form.upstream_url.trim(),
            issuer_url: form.oauth_issuer_url.trim() || undefined,
          },
        },
      );
      if (error || !data) {
        formError = extractError(error, 'Discovery failed — enter the endpoints manually.');
        return;
      }
      form.oauth_issuer_url = data.issuer_url;
      form.oauth_authorization_url = data.authorization_url;
      form.oauth_token_url = data.token_url;
      form.oauth_revocation_url = data.revocation_url ?? '';
      if (data.default_scopes.length > 0) {
        form.oauth_default_scopes_csv = data.default_scopes.join(', ');
      }
      // Keyed AFTER the issuer field is filled above, deliberately: that is the
      // pair a subsequent registration will send, so the verdict is tagged with
      // the server it actually describes rather than with a blank issuer field.
      discovered = {
        upstream: form.upstream_url.trim(),
        issuer: form.oauth_issuer_url.trim(),
        dcr: (data.registration_endpoint ?? '') !== '',
      };
      const warnings: string[] = [];
      if (!discovered.dcr) {
        warnings.push(
          'the server does not offer automatic client registration — create an OAuth app there and paste its Client ID and Secret below',
        );
      }
      if (data.issuer_host_mismatch) {
        warnings.push(
          `the login server (${data.issuer_url}) is on a different domain than the MCP server — verify this is expected`,
        );
      }
      if (!data.pkce_s256_supported) {
        warnings.push('the server did not advertise PKCE S256');
      }
      discoverMsg =
        warnings.length > 0
          ? { kind: 'warn', text: `Discovered, but ${warnings.join('; ')}. Review before saving.` }
          : { kind: 'ok', text: 'Discovered the OAuth endpoints. Review and save.' };
    } finally {
      discovering = false;
    }
  }

  // The exact redirect URI to register at the IdP — server-derived
  // (`GET /settings` → `mcp_oauth_redirect_uri`): it rides the tenant's
  // resolved API origin, which on split-vhost deploys differs from the
  // origin the browser sees. Never derive it from `window.location`.
  // `null` while loading or when no public URL is configured. Fetched once
  // per component lifetime (retried on reopen only while still null).
  let oauthRedirectUri = $state<string | null>(null);
  // Gateway homepage for the provider's "Homepage URL" field (admin origin,
  // API origin as fallback). Fetched alongside the redirect URI.
  let oauthHomepage = $state<string | null>(null);
  $effect(() => {
    if (!open || oauthRedirectUri !== null) return;
    adminApi.GET('/api/v1/admin/settings').then(({ data }) => {
      oauthRedirectUri = data?.mcp_oauth_redirect_uri ?? null;
      oauthHomepage = data?.admin_public_url ?? data?.api_public_url ?? null;
    });
  });

  // Unsaved-changes guard — see FieldProfile / RuleEdit / OAuthClient /
  // Downstream for the same pattern. Named `dirty` since the existing state
  // is already `form`.
  const dirty = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([
      form.name, form.description, form.upstream_url, form.transport, form.auth_mode,
      form.credential, form.oauth_issuer_url, form.oauth_authorization_url, form.oauth_token_url,
      form.oauth_revocation_url, form.oauth_client_id, form.oauth_client_secret,
      form.oauth_default_scopes_csv, form.enabled, form.connect_timeout_ms, form.request_timeout_ms,
    ]);
  }

  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    if (editing) {
      form = {
        name: editing.name,
        description: editing.description ?? '',
        upstream_url: editing.upstream_url,
        transport: editing.transport,
        auth_mode: editing.auth_mode,
        credential: '',
        oauth_issuer_url: editing.oauth_issuer_url ?? '',
        oauth_authorization_url: editing.oauth_authorization_url ?? '',
        oauth_token_url: editing.oauth_token_url ?? '',
        oauth_revocation_url: editing.oauth_revocation_url ?? '',
        oauth_client_id: editing.oauth_client_id ?? '',
        oauth_client_secret: '',
        oauth_default_scopes_csv: (editing.oauth_default_scopes ?? []).join(', '),
        enabled: editing.enabled,
        connect_timeout_ms: editing.connect_timeout_ms,
        request_timeout_ms: editing.request_timeout_ms,
      };
    } else {
      form = {
        name: '',
        description: '',
        upstream_url: '',
        transport: 'streamable_http',
        auth_mode: 'no_auth',
        credential: '',
        oauth_issuer_url: '',
        oauth_authorization_url: '',
        oauth_token_url: '',
        oauth_revocation_url: '',
        oauth_client_id: '',
        oauth_client_secret: '',
        oauth_default_scopes_csv: '',
        enabled: true,
        connect_timeout_ms: 10000,
        request_timeout_ms: 60000,
      };
    }
    formError = '';
    discoverMsg = null;
    registerMsg = null;
    // Cleared with the messages it belongs to — a verdict that outlived the
    // modal would decide the button for whichever server is opened next.
    discovered = null;
    queueMicrotask(() => {
      snapshot = fieldSignature();
      dirty.markClean();
    });
  });

  $effect(() => {
    if (!open || snapshot === null) return;
    if (fieldSignature() !== snapshot) dirty.markDirty();
    else dirty.markClean();
  });

  async function save() {
    formError = '';
    const credential = form.credential.trim() !== '' ? form.credential : undefined;
    const oauth_client_secret =
      form.oauth_client_secret.trim() !== '' ? form.oauth_client_secret : undefined;
    const isOauth = form.auth_mode === 'per_user_oauth';
    const oauth_default_scopes = isOauth
      ? form.oauth_default_scopes_csv
          .split(/[\s,]+/)
          .map((s) => s.trim())
          .filter((s) => s.length > 0)
      : undefined;
    // Send description verbatim (including empty string) so operators can
    // explicitly clear the field. The admin-api trims and treats `""` as
    // NULL; absent preserves. auth_mode is omitted on edit because it's
    // locked post-create — sending it back would still pass the equality
    // check but the field isn't bound to the form on edit anyway.
    const body = editing
      ? {
          name: form.name,
          description: form.description,
          upstream_url: form.upstream_url,
          transport: form.transport,
          credential,
          oauth_issuer_url: isOauth ? form.oauth_issuer_url || undefined : undefined,
          oauth_authorization_url: isOauth ? form.oauth_authorization_url || undefined : undefined,
          oauth_token_url: isOauth ? form.oauth_token_url || undefined : undefined,
          oauth_revocation_url: isOauth ? form.oauth_revocation_url || null : undefined,
          oauth_client_id: isOauth ? form.oauth_client_id || undefined : undefined,
          oauth_client_secret: isOauth ? oauth_client_secret : undefined,
          oauth_default_scopes,
          enabled: form.enabled,
          connect_timeout_ms: form.connect_timeout_ms,
          request_timeout_ms: form.request_timeout_ms,
        }
      : {
          name: form.name,
          description: form.description,
          upstream_url: form.upstream_url,
          transport: form.transport,
          auth_mode: form.auth_mode,
          credential,
          oauth_issuer_url: isOauth ? form.oauth_issuer_url || undefined : undefined,
          oauth_authorization_url: isOauth ? form.oauth_authorization_url || undefined : undefined,
          oauth_token_url: isOauth ? form.oauth_token_url || undefined : undefined,
          oauth_revocation_url: isOauth ? form.oauth_revocation_url || undefined : undefined,
          oauth_client_id: isOauth ? form.oauth_client_id || undefined : undefined,
          oauth_client_secret: isOauth ? oauth_client_secret : undefined,
          oauth_default_scopes,
          enabled: form.enabled,
          connect_timeout_ms: form.connect_timeout_ms,
          request_timeout_ms: form.request_timeout_ms,
        };
    if (editing) {
      const { error } = await adminApi.PATCH('/api/v1/admin/mcp/upstream-servers/{id}', {
        params: { path: { id: editing.id } },
        body,
      });
      if (error) { formError = extractError(error); return; }
    } else {
      const { error } = await adminApi.POST('/api/v1/admin/mcp/upstream-servers', { body });
      if (error) { formError = extractError(error); return; }
    }
    dirty.markClean();
    onsaved();
  }
</script>

{#if open}
  <Modal {open} title={editing ? 'Edit Upstream Server' : 'New Upstream Server'} {onclose} onCloseRequest={dirty.confirmDiscard}>
    {#if formError}
      <div class="bg-(--error-bg) border border-(--error-border) text-(--error-text) p-2 rounded-sm mb-3 text-sm">{formError}</div>
    {/if}
    <div class="space-y-3">
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Name</span>
        <TextInput bind:value={form.name} />
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Description</span>
        <TextInput bind:value={form.description} />
      </label>
      <label class="block">
        <span class="text-sm font-medium text-(--text-primary)">Upstream URL</span>
        <TextInput mono placeholder="https://example.com/mcp" bind:value={form.upstream_url} />
      </label>
      <div class="grid grid-cols-2 gap-3">
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Transport</span>
          <SelectInput bind:value={form.transport}>
            <option value="streamable_http">streamable_http</option>
            <option value="sse">sse</option>
          </SelectInput>
        </label>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">
            Auth Mode{#if editing}<span class="text-xs text-(--text-secondary) ml-2 font-normal">(locked post-create — delete and recreate to switch modes)</span>{/if}
          </span>
          {#if editing}
            <!-- Raw input, not <TextInput>: a muted, read-only mirror of the
                 locked auth_mode — TextInput hardcodes the primary text color. -->
            <input
              data-testid="auth-mode"
              readonly
              value={form.auth_mode}
              class="w-full px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-secondary) font-mono cursor-not-allowed"
            />
          {:else}
            <SelectInput bind:value={form.auth_mode} data-testid="auth-mode">
              <option value="no_auth">no_auth</option>
              <option value="service_account">service_account</option>
              <option value="per_user_oauth">per_user_oauth</option>
              <option value="byot">byot</option>
            </SelectInput>
          {/if}
        </label>
      </div>
      {#if form.auth_mode === 'service_account'}
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">
            Bearer Token
            {#if editing && editing.has_credential}
              <span class="text-xs text-(--text-secondary) ml-2">(currently set — leave blank to keep, type a new value to rotate)</span>
            {:else}
              <span class="text-xs text-(--text-secondary) ml-2">(required)</span>
            {/if}
          </span>
          <TextInput
            type="password"
            mono
            placeholder={editing && editing.has_credential
              ? '•••••••• (stored, encrypted at rest)'
              : 'paste the upstream API token'}
            autocomplete="off"
            bind:value={form.credential}
          />
          <span class="text-xs text-(--text-secondary)">
            Encrypted with AES-256-GCM at rest. Never echoed back. Rotate by typing a new value.
          </span>
        </label>
      {/if}
      {#if form.auth_mode === 'per_user_oauth'}
        <div class="border border-(--info-border) bg-(--info-bg) rounded-sm p-3 space-y-3">
          <div class="text-sm font-semibold text-(--text-primary)">Per-user OAuth client config</div>
          <p class="text-xs text-(--text-secondary)">
            Required for <code>per_user_oauth</code>. Each portal user does the OAuth dance once
            against the upstream IdP; the proxy stores their tokens encrypted and refreshes
            transparently. Register this redirect URI at the upstream IdP:
          </p>
          <div data-testid="oauth-redirect-uri" class="bg-(--bg-primary) border border-(--info-border) rounded-sm p-2 text-xs break-all">
            {#if oauthRedirectUri}
              <Copyable value={oauthRedirectUri} />
            {:else}
              <span class="text-(--text-secondary)">
                Configure your tenant's public URLs (Settings → Defaults) to see the redirect URI.
              </span>
            {/if}
          </div>
          <p class="text-xs text-(--text-secondary)">
            Built from your tenant's API origin (<code>api_public_url</code>, else
            <code>admin_public_url</code> — Settings → Defaults). Changing those
            settings changes this URI; re-register it at the IdP if it does.
          </p>
          <div class="flex items-center gap-2">
            <button
              type="button"
              data-testid="discover-oauth"
              onclick={() => void discoverEndpoints()}
              disabled={discovering}
              class="px-3 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors disabled:opacity-60">
              {discovering ? 'Discovering…' : 'Discover endpoints'}
            </button>
            <span class="text-xs text-(--text-secondary)">
              Fill the URLs below automatically from the server URL (spec-OAuth servers).
            </span>
          </div>
          {#if discoverMsg}
            <div
              data-testid="discover-status"
              class="rounded p-2 text-xs border {discoverMsg.kind === 'ok'
                ? 'border-(--success-border) bg-(--success-bg) text-(--success)'
                : 'border-(--warning-border) bg-(--warning-bg) text-(--warning)'}">
              {discoverMsg.text}
            </div>
          {/if}
          <div class="flex items-center gap-2">
            <button
              type="button"
              data-testid="register-oauth-client"
              onclick={() => void registerClient()}
              disabled={registering || dcrUnsupported}
              class="px-3 py-2 text-sm border border-(--border) rounded-lg hover:bg-(--bg-elevated) transition-colors disabled:opacity-60">
              {registering ? 'Registering…' : 'Register client automatically'}
            </button>
            <span class="text-xs text-(--text-secondary)">
              {#if dcrUnsupported}
                This server does not offer automatic registration — create an OAuth app there
                and paste its Client ID and Secret below.
              {:else}
                Self-register an OAuth client (DCR) and fill the Client ID/Secret. Providers
                without DCR (e.g. GitHub) need a manually-registered app.
              {/if}
            </span>
          </div>
          {#if registerMsg}
            <div
              data-testid="register-status"
              class="rounded p-2 text-xs border {registerMsg.kind === 'ok'
                ? 'border-(--success-border) bg-(--success-bg) text-(--success)'
                : 'border-(--warning-border) bg-(--warning-bg) text-(--warning)'}">
              {registerMsg.text}
            </div>
          {/if}
          <OauthProviderGuide
            upstreamUrl={form.upstream_url}
            issuerUrl={form.oauth_issuer_url}
            redirectUri={oauthRedirectUri}
            homepage={oauthHomepage}
            onfillScopes={(scopes) => (form.oauth_default_scopes_csv = scopes.join(', '))} />
          <label class="block">
            <span class="text-xs font-medium text-(--text-secondary)">Issuer URL <span class="text-(--text-secondary)">(optional — used to discover endpoints)</span></span>
            <TextInput
              mono
              placeholder="https://idp.example.com"
              bind:value={form.oauth_issuer_url} />
          </label>
          <div class="grid grid-cols-2 gap-2">
            <label class="block">
              <span class="text-xs font-medium text-(--text-secondary)">Authorization URL</span>
              <TextInput
                mono
                placeholder="https://idp.example.com/oauth/authorize"
                bind:value={form.oauth_authorization_url} />
            </label>
            <label class="block">
              <span class="text-xs font-medium text-(--text-secondary)">Token URL</span>
              <TextInput
                mono
                placeholder="https://idp.example.com/oauth/token"
                bind:value={form.oauth_token_url} />
            </label>
          </div>
          <label class="block">
            <span class="text-xs font-medium text-(--text-secondary)">Revocation URL <span class="text-(--text-secondary)">(optional, RFC 7009)</span></span>
            <TextInput
              mono
              placeholder="https://idp.example.com/oauth/revoke"
              bind:value={form.oauth_revocation_url} />
          </label>
          <div class="grid grid-cols-2 gap-2">
            <label class="block">
              <span class="text-xs font-medium text-(--text-secondary)">Client ID</span>
              <TextInput mono bind:value={form.oauth_client_id} />
            </label>
            <label class="block">
              <span class="text-xs font-medium text-(--text-secondary)">
                Client Secret
                {#if editing && editing.has_oauth_client_secret}
                  <span class="text-(--text-secondary) ml-1">(set — leave blank to keep)</span>
                {/if}
              </span>
              <TextInput
                type="password"
                mono
                placeholder={editing && editing.has_oauth_client_secret
                  ? '•••••••• (stored, encrypted at rest)'
                  : ''}
                autocomplete="off"
                bind:value={form.oauth_client_secret} />
            </label>
          </div>
          <label class="block">
            <span class="text-xs font-medium text-(--text-secondary)">Default Scopes <span class="text-(--text-secondary)">(comma- or space-separated)</span></span>
            <TextInput
              mono
              placeholder="read:user, repo"
              bind:value={form.oauth_default_scopes_csv} />
          </label>
        </div>
      {/if}
      {#if form.auth_mode === 'byot'}
        <div data-testid="byot-info-panel" class="border border-(--warning-border) bg-(--warning-bg) rounded-sm p-3 space-y-2">
          <div class="text-sm font-semibold text-(--text-primary)">BYOT (Bring Your Own Token)</div>
          <p class="text-xs text-(--text-secondary)">
            The proxy stores no credential here — clients supply the upstream bearer themselves
            via <code>Authorization: Bearer …</code> on
            <code class="font-mono">/fwd/{'{key}'}/mcp/&lt;slug&gt;</code>. Issue an
            <code class="font-mono">vk-*</code> key from the portal, bound to a single-route
            downstream pointed at this upstream.
          </p>
          <p class="text-xs text-(--text-secondary)">
            Multi-route downstreams (fan-in) are not supported with BYOT — the forwarded
            bearer can't be split across upstreams. Adding this upstream as a route blocks any
            additional routes on the same downstream.
          </p>
        </div>
      {/if}
      <div class="grid grid-cols-2 gap-3">
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Connect Timeout (ms)</span>
          <NumberInput bind:value={form.connect_timeout_ms} />
        </label>
        <label class="block">
          <span class="text-sm font-medium text-(--text-primary)">Request Timeout (ms)</span>
          <NumberInput bind:value={form.request_timeout_ms} />
        </label>
      </div>
      <label class="flex items-center gap-2">
        <input type="checkbox" bind:checked={form.enabled} />
        <span class="text-sm">Enabled</span>
      </label>
    </div>
    <div class="flex justify-end gap-2 mt-4">
      <button type="button" class="px-3 py-1 rounded-lg border border-(--border) text-sm text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors" onclick={async () => { if (await dirty.confirmDiscard()) onclose(); }}>Cancel</button>
      <button type="button" class="px-3 py-1 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium" onclick={save}>Save</button>
    </div>
  </Modal>
{/if}

<ConfirmDialog
  open={dirty.confirmOpen}
  title="Discard changes?"
  message="You have unsaved edits. Discard them?"
  confirmLabel="Discard"
  cancelLabel="Keep editing"
  destructive
  onconfirm={dirty.acceptDiscard}
  oncancel={dirty.rejectDiscard}
/>
