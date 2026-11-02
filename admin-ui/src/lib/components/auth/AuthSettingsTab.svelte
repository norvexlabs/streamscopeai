<script lang="ts">
  // Global auth configuration — auth mode (internal/OIDC), OIDC provider, the
  // URLs to register at it, which claims a login reads, console-role groups,
  // MCP-OAuth consent delegation. One explicit Save.
  import { toast } from '#lib/toast.svelte.js';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import type { AuthConfig, OidcTestResult } from '#lib/api-types.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';

  let slug = $derived(page.params.slug ?? '');
  import Skeleton from '#lib/components/Skeleton.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import Copyable from '#lib/components/Copyable.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import type { OidcRegistration } from '#lib/oidc-urls.js';

  // Built server-side from the same helper the login/logout handlers use, so
  // these are exactly the values the provider will be asked to match.
  let { registration }: { registration: OidcRegistration } = $props();

  let authConfig = $state<AuthConfig | null>(null);
  let authConfigLoading = $state(true);
  let authSaving = $state(false);
  let authSaved = $state(false);
  let authError = $state('');

  // Editable auth fields
  let editAuthMode = $state('internal');
  let editIssuerUrl = $state('');
  let editClientId = $state('');
  let editClientSecret = $state('');
  let editScopes = $state('openid email profile');
  let editAdminGroup = $state('');
  let editReadonlyGroup = $state('');
  let editGroupsClaim = $state('groups');
  let editEmailClaim = $state('email');
  let editAllowUnverifiedEmail = $state(false);
  let editResponseMode = $state('query');
  let editAllowedDomains = $state('');
  // When true (and auth_mode=oidc), the spec-OAuth consent step at
  // /portal/t/<slug>/mcp/authorize bypasses the credential prompt and bounces
  // straight to the tenant's IdP. Only meaningful for OIDC tenants.
  let editMcpOauthDelegateToOidc = $state(false);
  let editMcpOauthCimdEnabled = $state(true);

  // OIDC test
  let testResult = $state<OidcTestResult | null>(null);
  let testLoading = $state(false);

  async function loadAuthConfig() {
    authConfigLoading = true;
    try {
      const { data } = await adminApi.GET('/api/v1/admin/config');
      if (data) {
        authConfig = data;
        editAuthMode = authConfig.auth_mode;
        editIssuerUrl = authConfig.oidc_issuer_url || '';
        editClientId = authConfig.oidc_client_id || '';
        editClientSecret = '';
        editScopes = authConfig.oidc_scopes || 'openid email profile';
        editAdminGroup = authConfig.admin_group || '';
        editReadonlyGroup = authConfig.readonly_group || '';
        editGroupsClaim = authConfig.oidc_groups_claim;
        editEmailClaim = authConfig.oidc_email_claim;
        editAllowUnverifiedEmail = authConfig.oidc_allow_unverified_email;
        editResponseMode = authConfig.oidc_response_mode;
        editAllowedDomains = (authConfig.allowed_domains || []).join(', ');
        editMcpOauthDelegateToOidc = authConfig.mcp_oauth_delegate_to_oidc ?? false;
        editMcpOauthCimdEnabled = authConfig.mcp_oauth_cimd_enabled ?? true;
      }
    } catch (e) {
      toast.error(extractError(e));
    } finally {
      authConfigLoading = false;
    }
  }

  async function saveAuthConfig() {
    authSaving = true;
    authError = '';
    try {
      const payload: Record<string, unknown> = {
        auth_mode: editAuthMode,
        oidc_issuer_url: editIssuerUrl || null,
        oidc_client_id: editClientId || null,
        oidc_scopes: editScopes || null,
        admin_group: editAdminGroup || null,
        readonly_group: editReadonlyGroup || null,
        // Sent as typed: a blank name is the server's to refuse (400), not
        // this page's to replace with a default it would have to keep in sync.
        oidc_groups_claim: editGroupsClaim,
        oidc_email_claim: editEmailClaim,
        oidc_allow_unverified_email: editAllowUnverifiedEmail,
        oidc_response_mode: editResponseMode,
        allowed_domains: editAllowedDomains ? editAllowedDomains.split(',').map(d => d.trim()).filter(Boolean) : null,
        mcp_oauth_delegate_to_oidc: editMcpOauthDelegateToOidc,
        mcp_oauth_cimd_enabled: editMcpOauthCimdEnabled,
      };
      if (editClientSecret) {
        payload.oidc_client_secret = editClientSecret;
      }
      const { data: updatedConfig, error: configErr } = await adminApi.PATCH('/api/v1/admin/config', { body: payload });
      if (configErr) { authError = extractError(configErr, 'Failed to save'); authSaving = false; return; }
      if (updatedConfig) authConfig = updatedConfig;
      editClientSecret = '';
      authSaved = true;
      setTimeout(() => authSaved = false, 2000);
    } catch (e: unknown) {
      authError = e instanceof Error ? e.message : 'Failed to save';
      setTimeout(() => authError = '', 5000);
    } finally {
      authSaving = false;
    }
  }

  async function testOidc() {
    if (!editIssuerUrl) return;
    testLoading = true;
    testResult = null;
    try {
      const { data, error: err } = await adminApi.POST('/api/v1/admin/config/actions/test', { body: { oidc_issuer_url: editIssuerUrl } });
      if (err) {
        testResult = { success: false, message: extractError(err, 'Test failed'), authorization_endpoint: null, token_endpoint: null };
      } else {
        if (data) testResult = data;
      }
    } catch (e: unknown) {
      testResult = { success: false, message: e instanceof Error ? e.message : 'Test failed', authorization_endpoint: null, token_endpoint: null };
    } finally {
      testLoading = false;
    }
  }

  usePeriodicLoad(loadAuthConfig, async () => {});
</script>

{#if authConfigLoading}
  <Skeleton variant="card" count={1} />
{:else}
  <div class="space-y-4 max-w-2xl">
    <FormError message={authError} />

    <!-- Auth Mode -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary) mb-1">Authentication Mode</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        How users authenticate to this tenant's admin UI and portal.
      </p>
      <div class="flex items-center gap-1 bg-(--bg-primary) rounded-lg p-1 w-fit">
        <button
          onclick={() => editAuthMode = 'internal'}
          class="px-4 py-2 rounded-md text-sm font-medium transition-all {editAuthMode === 'internal'
            ? 'bg-(--accent) text-(--accent-fg) shadow-xs'
            : 'text-(--text-secondary) hover:text-(--text-primary)'}"
        >Internal</button>
        <button
          onclick={() => editAuthMode = 'oidc'}
          class="px-4 py-2 rounded-md text-sm font-medium transition-all {editAuthMode === 'oidc'
            ? 'bg-(--accent) text-(--accent-fg) shadow-xs'
            : 'text-(--text-secondary) hover:text-(--text-primary)'}"
        >OIDC</button>
      </div>
      {#if editAuthMode === 'internal'}
        <p class="text-xs text-(--text-secondary) mt-3">Users authenticate with email and password. Admin and portal each have their own login page; one password covers both.</p>
      {:else}
        <p class="text-xs text-(--text-secondary) mt-3">Users are redirected to the identity provider for login. Configure the provider below.</p>
      {/if}
    </div>

    <!-- OIDC Configuration -->
    {#if editAuthMode === 'oidc'}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-1">Register at your identity provider</h3>
        <p class="text-xs text-(--text-secondary) mb-3">
          Create a confidential web application (authorization-code flow) at the provider and register
          these URLs exactly as shown — providers compare them character for character, query string
          included.
        </p>
        <dl class="space-y-3 text-sm">
          <div>
            <dt class="text-xs text-(--text-secondary) uppercase tracking-wider mb-1">Redirect URI (sign-in callback)</dt>
            <dd><Copyable value={registration.redirectUri} block /></dd>
          </div>
          <div>
            <dt class="text-xs text-(--text-secondary) uppercase tracking-wider mb-1">Post-logout redirect URI — console</dt>
            <dd><Copyable value={registration.adminPostLogoutUri} block /></dd>
          </div>
          {#if registration.portalPostLogoutUri}
            <div>
              <dt class="text-xs text-(--text-secondary) uppercase tracking-wider mb-1">Post-logout redirect URI — portal</dt>
              <dd><Copyable value={registration.portalPostLogoutUri} block /></dd>
            </div>
          {/if}
        </dl>
        <p class="text-xs text-(--text-secondary) mt-3">
          The post-logout URIs are used only when the provider publishes an end-session endpoint.
          Microsoft Entra ID and AD FS take them as additional redirect URIs.
        </p>
      </div>

      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-3">OIDC Provider</h3>
        <div class="space-y-3">
          <div>
            <label for="oidc-issuer-url" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Issuer URL</label>
            <div class="flex items-center gap-2">
              <input id="oidc-issuer-url" bind:value={editIssuerUrl} type="url" placeholder="https://accounts.google.com"
                class="flex-1 px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) font-mono" />
              <button onclick={testOidc} disabled={testLoading || !editIssuerUrl}
                class="px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-secondary) hover:text-(--text-primary) transition-colors disabled:opacity-50">
                {testLoading ? 'Testing…' : 'Test'}
              </button>
            </div>
            {#if testResult}
              <div class="mt-2 p-2 rounded-lg text-xs {testResult.success ? 'bg-(--success)/10 text-(--success)' : 'bg-(--error-bg) text-(--error)'}">
                {testResult.message}
              </div>
            {/if}
          </div>
          <div>
            <label for="oidc-client-id" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Client ID</label>
            <input id="oidc-client-id" bind:value={editClientId} type="text" placeholder="your-client-id"
              class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) font-mono" />
          </div>
          <div>
            <label for="oidc-client-secret" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">
              Client Secret
              {#if authConfig?.oidc_client_secret_masked}
                <span class="text-(--success) font-normal normal-case">(set)</span>
              {/if}
            </label>
            <input id="oidc-client-secret" bind:value={editClientSecret} type="password" placeholder={authConfig?.oidc_client_secret_masked ? '--------  (leave empty to keep current)' : 'Enter client secret'}
              class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary)" />
          </div>
          <div>
            <label for="oidc-scopes" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Scopes</label>
            <input id="oidc-scopes" bind:value={editScopes} type="text" placeholder="openid email profile"
              class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) font-mono" />
          </div>
          <div>
            <label for="oidc-response-mode" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Response mode</label>
            <SelectInput id="oidc-response-mode" bind:value={editResponseMode}>
              <option value="query">Query (default)</option>
              <option value="form_post">Form post — required by AD FS</option>
            </SelectInput>
            <p class="text-xs text-(--text-secondary) mt-1">
              How the provider returns the sign-in. AD FS includes the claims its rules issue (email,
              groups) in the ID token only with form post. The redirect URI is the same either way.
            </p>
          </div>
          <div>
            <label for="oidc-allowed-domains" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Allowed Domains</label>
            <input id="oidc-allowed-domains" bind:value={editAllowedDomains} type="text" placeholder="example.com, corp.example.com (comma-separated, empty = all)"
              class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) font-mono" />
          </div>
        </div>
      </div>

      <!-- Claim mapping -->
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-1">Claim Mapping</h3>
        <p class="text-xs text-(--text-secondary) mb-3">
          Which ID-token claims a sign-in reads. The defaults suit most providers; AD FS sends groups as
          <code class="text-(--text-primary)">group</code> and often has no
          <code class="text-(--text-primary)">email</code> claim (use
          <code class="text-(--text-primary)">upn</code>). A claim may hold one value or a list.
        </p>
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
          <div>
            <label for="oidc-groups-claim" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Groups claim</label>
            <input id="oidc-groups-claim" bind:value={editGroupsClaim} type="text" placeholder="groups"
              class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) font-mono" />
          </div>
          <div>
            <label for="oidc-email-claim" class="block text-xs text-(--text-secondary) mb-1 uppercase tracking-wider">Email claim</label>
            <input id="oidc-email-claim" bind:value={editEmailClaim} type="text" placeholder="email"
              class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary) font-mono" />
          </div>
        </div>
        <label class="flex items-start gap-2 mt-4">
          <input type="checkbox" bind:checked={editAllowUnverifiedEmail} class="mt-0.5" />
          <span class="text-sm text-(--text-primary)">
            Accept addresses the provider does not mark as verified
            <span class="block text-xs text-(--text-secondary) mt-1">
              The address is the account's sign-in name, so this is safe only when your directory — not
              the user — sets it (AD FS, which never sends
              <code class="text-(--text-primary)">email_verified</code>). Do not turn it on for a
              provider where users or guests can set their own address (such as Microsoft Entra ID with
              guest accounts): anyone who can put a colleague's address there could sign in as them. An email claim other than
              <code class="text-(--text-primary)">email</code> is never marked verified, so it requires this
              setting. An explicit
              <code class="text-(--text-primary)">email_verified: false</code> is always refused.
            </span>
          </span>
        </label>
      </div>

      <!-- Admin Group -->
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-1">Admin Group</h3>
        <p class="text-xs text-(--text-secondary) mb-3">Members of this <code class="text-(--text-primary)">{editGroupsClaim || 'groups'}</code>-claim value get the <strong>Admin</strong> console role. Leave empty to block admin auto-provisioning — only pre-existing admin rows (matched by verified email) can sign in. The console role is recomputed from groups on every login; a user in neither group loses console access.</p>
        <input bind:value={editAdminGroup} type="text" placeholder="e.g. streamscope-admins"
          class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary)" />
      </div>

      <!-- ReadOnly Group -->
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-1">Read-only Group</h3>
        <p class="text-xs text-(--text-secondary) mb-3">Members of this <code class="text-(--text-primary)">{editGroupsClaim || 'groups'}</code>-claim value get the <strong>Read-only</strong> console role (view, no changes). <code class="text-(--text-primary)">Admin Group</code> wins if a user is in both. Leave empty to disable read-only auto-provisioning.</p>
        <input bind:value={editReadonlyGroup} type="text" placeholder="e.g. streamscope-readonly"
          class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-sm text-(--text-primary)" />
      </div>

      <!-- MCP spec-OAuth consent delegation -->
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-1">
          MCP OAuth — Consent Delegation
        </h3>
        <p class="text-xs text-(--text-secondary) mb-3">
          When enabled, the spec-OAuth consent page at
          <code class="text-(--text-primary)">/portal/t/&lt;slug&gt;/mcp/authorize</code>
          redirects unauthenticated users to this tenant's IdP instead of the
          portal credentials prompt. The IdP only proves identity — Streamscope
          still mints the access token bound to the requested virtual server.
        </p>
        <label class="flex items-start gap-2">
          <input
            type="checkbox"
            bind:checked={editMcpOauthDelegateToOidc}
            class="mt-0.5" />
          <span class="text-sm text-(--text-primary)">
            Delegate MCP OAuth consent to this tenant's OIDC IdP
          </span>
        </label>
      </div>

      <!-- OIDC Group Sync Info -->
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-1">Group Sync</h3>
        <p class="text-xs text-(--text-secondary) mb-2">On every OIDC login, workspace memberships are synced from the ID-token claims.</p>
        <ul class="text-xs text-(--text-secondary) space-y-1 list-disc ml-4">
          <li>Workspaces with an <code class="text-(--text-primary)">oidc_claim_pattern</code> are IdP-managed — users whose claim (the one the workspace names, e.g. <code class="text-(--text-primary)">groups</code>, or <code class="text-(--text-primary)">group</code> on AD FS) matches auto-join</li>
          <li>Workspaces without a pattern are manual — never touched by sync</li>
          <li>Set each workspace's pattern on its Members tab in <a href={thref(slug, '/workspaces')} class="text-(--accent) hover:underline">Workspaces</a></li>
        </ul>
      </div>
    {/if}

    <!-- MCP spec-OAuth client registration -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary) mb-1">
        MCP OAuth — Client ID Metadata Documents
      </h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        A CIMD client publishes its own metadata at an HTTPS URL and presents
        that URL as its <code class="text-(--text-primary)">client_id</code>,
        so it never registers. Convenient for spec-conforming MCP clients — and
        the one path on which an unregistered caller can name a URL this gateway
        will fetch, on every authorization. Turn it off to accept only clients
        you or they have registered; the tenant's discovery document then
        advertises that it is unsupported.
      </p>
      <label class="flex items-start gap-2">
        <input
          type="checkbox"
          bind:checked={editMcpOauthCimdEnabled}
          class="mt-0.5" />
        <span class="text-sm text-(--text-primary)">
          Accept client ID metadata documents (CIMD)
        </span>
      </label>
    </div>

    <!-- Save button -->
    <div class="flex items-center gap-3">
      <button onclick={saveAuthConfig} disabled={authSaving}
        class="px-5 py-2.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50">
        {authSaving ? 'Saving…' : 'Save Configuration'}
      </button>
      {#if authSaved}
        <span class="text-sm text-(--success)">Saved</span>
      {/if}
    </div>
  </div>
{/if}
