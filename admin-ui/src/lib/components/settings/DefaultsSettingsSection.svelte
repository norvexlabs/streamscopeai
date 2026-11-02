<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractSettings, extractError, extractErrorCode, extractInheritedDefaults, updateSettings } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { onMount } from 'svelte';

  let { isSystemTenant = false }: { isSystemTenant?: boolean } = $props();

  let proxyPublicUrl = $state('');
  let adminPublicUrl = $state('');
  let apiPublicUrl = $state('');
  let inheritedProxyUrl = $state<string | null>(null);
  let inheritedAdminUrl = $state<string | null>(null);
  let inheritedApiUrl = $state<string | null>(null);
  let proxyUrlError = $state('');
  let adminUrlError = $state('');
  let apiUrlError = $state('');
  let saving = $state(false);

  const URL_RE = /^https?:\/\/[^/?#@:\s][^/?#@\s]*$/;
  function validateUrl(value: string): string {
    if (!value) return '';
    if (!URL_RE.test(value)) return 'Must be http(s)://host[:port], no path or trailing slash.';
    return '';
  }

  async function loadConfig() {
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings');
    if (err) {
      toast.error('Failed to load config', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
      return;
    }
    if (!data) return;
    const s = extractSettings(data);
    const inh = extractInheritedDefaults(data);
    proxyPublicUrl = s.proxy_public_url ?? '';
    adminPublicUrl = s.admin_public_url ?? '';
    apiPublicUrl = s.api_public_url ?? '';
    inheritedProxyUrl = inh.proxy_public_url ?? null;
    inheritedAdminUrl = inh.admin_public_url ?? null;
    inheritedApiUrl = inh.api_public_url ?? null;
  }

  async function handleSave() {
    proxyUrlError = validateUrl(proxyPublicUrl);
    adminUrlError = validateUrl(adminPublicUrl);
    apiUrlError = validateUrl(apiPublicUrl);
    if (proxyUrlError || adminUrlError || apiUrlError) return;
    saving = true;
    const { data, error: err } = await updateSettings({
      proxy_public_url: proxyPublicUrl.trim() || null,
      admin_public_url: adminPublicUrl.trim() || null,
      api_public_url: apiPublicUrl.trim() || null,
    }, ['proxy_public_url', 'admin_public_url', 'api_public_url']);
    if (err) {
      toast.error('Failed to save public URLs', { body: extractError(err), code: extractErrorCode(err) ?? undefined });
    } else if (data) {
      const inh = extractInheritedDefaults(data);
      inheritedProxyUrl = inh.proxy_public_url ?? null;
      inheritedAdminUrl = inh.admin_public_url ?? null;
      inheritedApiUrl = inh.api_public_url ?? null;
      toast.success('Public URLs saved');
    }
    saving = false;
  }

  onMount(loadConfig);
</script>

<div class="space-y-4">
  <div>
    <h3 class="text-lg font-semibold text-(--text-primary)">Public URLs</h3>
    <p class="text-sm text-(--text-secondary) mt-1">
      {#if isSystemTenant}
        Platform defaults for every tenant. Customer tenants may override these on their own Defaults tab.
        Unset values cause dependent surfaces (Quickstart, MCP OAuth, CORS, invite links) to fail closed for any tenant that doesn't override.
      {:else}
        Per-tenant overrides layered over the platform defaults. Leave a field empty to inherit the default set on the system tenant.
      {/if}
    </p>
  </div>

  <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border) space-y-4">
    <div>
      <label for="proxy-public-url" class="block text-xs text-(--text-secondary) font-medium mb-1">
        Proxy URL
      </label>
      <input
        id="proxy-public-url"
        bind:value={proxyPublicUrl}
        oninput={() => (proxyUrlError = validateUrl(proxyPublicUrl))}
        type="url"
        placeholder={inheritedProxyUrl ? `e.g. ${inheritedProxyUrl}` : 'https://gw.example.com'}
        class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"
      />
      {#if proxyUrlError}
        <p class="text-xs text-(--error) mt-1">{proxyUrlError}</p>
      {:else if isSystemTenant}
        {#if !proxyPublicUrl}
          <p class="text-xs text-(--warning) mt-1">Platform default unset — Quickstart, MCP OAuth, and MCP CORS fail closed for any tenant without its own override.</p>
        {:else}
          <p class="text-xs text-(--text-secondary) mt-1">Platform default — applies to every tenant without its own override.</p>
        {/if}
      {:else if inheritedProxyUrl && !proxyPublicUrl}
        <p class="text-xs text-(--text-secondary) mt-1">
          Inheriting <code class="font-mono text-(--text-primary)">{inheritedProxyUrl}</code> from the platform default.
        </p>
      {:else if !inheritedProxyUrl && !proxyPublicUrl}
        <p class="text-xs text-(--warning) mt-1">No platform default set — Quickstart, MCP OAuth, and CORS will fail closed for this tenant.</p>
      {/if}
    </div>

    <div>
      <label for="admin-public-url" class="block text-xs text-(--text-secondary) font-medium mb-1">
        Admin / Portal URL
      </label>
      <input
        id="admin-public-url"
        bind:value={adminPublicUrl}
        oninput={() => (adminUrlError = validateUrl(adminPublicUrl))}
        type="url"
        placeholder={inheritedAdminUrl ? `e.g. ${inheritedAdminUrl}` : 'https://admin.example.com'}
        class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"
      />
      {#if adminUrlError}
        <p class="text-xs text-(--error) mt-1">{adminUrlError}</p>
      {:else if isSystemTenant}
        {#if !adminPublicUrl}
          <p class="text-xs text-(--warning) mt-1">Platform default unset — login links, invite emails, and admin/portal CORS fail closed for any tenant without its own override.</p>
        {:else}
          <p class="text-xs text-(--text-secondary) mt-1">Platform default — applies to every tenant without its own override.</p>
        {/if}
      {:else if inheritedAdminUrl && !adminPublicUrl}
        <p class="text-xs text-(--text-secondary) mt-1">
          Inheriting <code class="font-mono text-(--text-primary)">{inheritedAdminUrl}</code> from the platform default.
        </p>
      {:else if !inheritedAdminUrl && !adminPublicUrl}
        <p class="text-xs text-(--warning) mt-1">No platform default set — login links, invite emails, and admin CORS will fail closed for this tenant.</p>
      {/if}
    </div>

    <div>
      <label for="api-public-url" class="block text-xs text-(--text-secondary) font-medium mb-1">
        Admin-API URL
        <span class="ml-1 text-(--text-tertiary) font-normal">(public FQDN for scripts / CLIs)</span>
      </label>
      <input
        id="api-public-url"
        bind:value={apiPublicUrl}
        oninput={() => (apiUrlError = validateUrl(apiPublicUrl))}
        type="url"
        placeholder={inheritedApiUrl ? `e.g. ${inheritedApiUrl}` : 'https://api.example.com'}
        class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-(--text-primary) text-sm font-mono"
      />
      {#if apiUrlError}
        <p class="text-xs text-(--error) mt-1">{apiUrlError}</p>
      {:else if isSystemTenant}
        {#if !apiPublicUrl}
          <p class="text-xs text-(--text-secondary) mt-1">The FQDN external scripts and CLIs use to reach the admin-API. Caddy already serves it; set this so operators can copy the canonical URL.</p>
        {:else}
          <p class="text-xs text-(--text-secondary) mt-1">Platform default — the FQDN external scripts use to reach the admin-API.</p>
        {/if}
      {:else if inheritedApiUrl && !apiPublicUrl}
        <p class="text-xs text-(--text-secondary) mt-1">
          Inheriting <code class="font-mono text-(--text-primary)">{inheritedApiUrl}</code> from the platform default.
        </p>
      {:else if !inheritedApiUrl && !apiPublicUrl}
        <p class="text-xs text-(--text-secondary) mt-1">Not configured. Set on the system tenant to advertise the script-callable admin-API URL.</p>
      {/if}
    </div>

    <div class="flex items-center gap-2">
      <button
        onclick={handleSave}
        disabled={saving || !!proxyUrlError || !!adminUrlError || !!apiUrlError}
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) rounded-lg text-(--accent-fg) text-sm font-medium disabled:opacity-50"
      >
        Save URLs
      </button>
    </div>
  </div>
</div>
