<script lang="ts">
  import Tabs from '#lib/components/Tabs.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import type { components } from '#lib/generated/api-types.js';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  type TenantDetail = components['schemas']['TenantDetailResponse'];
  type AdminRow = components['schemas']['AdminAccountResponse'];
  type InviteRow = components['schemas']['InviteResponse'];
  type CreatedInvite = components['schemas']['InviteCreatedResponse'];

  // The tenant being viewed (route segment [detail]); the API calls below target
  // this tenant. `tenantSlug` is the acting super-admin's own tenant scope (the
  // /t/<slug> URL prefix) used to build same-scope links.
  let slug = $derived(params.detail);
  let tenantSlug = $derived(params.slug);
  let tenant = $state<TenantDetail | null>(null);
  let admins = $state<AdminRow[]>([]);
  let invites = $state<InviteRow[]>([]);
  let activeTab = $state('overview');
  let error = $state('');
  let success = $state('');

  // Destroy tenant
  let showDestroy = $state(false);
  let destroyConfirmSlug = $state('');
  let destroying = $state(false);

  // Invite creation
  let showInvite = $state(false);
  let inviteEmail = $state('');
  let inviteExpiry = $state(168);
  let inviteRole = $state<'admin' | 'read_only'>('admin');
  let inviteEmergency = $state(false);
  let createdInvite = $state<CreatedInvite | null>(null);

  const tabs = [
    { id: 'overview', label: 'Overview' },
    { id: 'invites', label: 'Invites' },
    { id: 'admins', label: 'Admins' },
  ];

  $effect(() => {
    loadTenant();
    loadAdmins();
    loadInvites();
  });

  async function loadTenant() {
    const { data } = await adminApi.GET('/api/v1/admin/tenants/{slug}', { params: { path: { slug } } });
    if (data) tenant = data;
  }

  async function loadAdmins() {
    admins = await fetchAllPages<AdminRow>((offset, limit) =>
      adminApi.GET('/api/v1/admin/tenants/{slug}/admins', { params: { path: { slug }, query: { offset, limit } } }));
  }

  async function loadInvites() {
    invites = await fetchAllPages<InviteRow>((offset, limit) =>
      adminApi.GET('/api/v1/admin/tenants/{slug}/invites', { params: { path: { slug }, query: { offset, limit } } }));
  }

  async function toggleActive() {
    if (!tenant) return;
    error = '';
    const wasActive = tenant.is_active;
    const { error: err } = await adminApi.PATCH('/api/v1/admin/tenants/{slug}', {
      params: { path: { slug } },
      body: { is_active: !wasActive },
    });
    if (err) {
      error = extractError(err, 'Failed to update tenant');
    } else {
      await loadTenant();
      success = wasActive ? 'Tenant suspended' : 'Tenant activated';
    }
  }

  async function createInvite() {
    error = '';
    const { data, error: err } = await adminApi.POST('/api/v1/admin/tenants/{slug}/invites', {
      params: { path: { slug } },
      body: {
        role: inviteRole,
        email: inviteEmail || undefined,
        expires_in_hours: inviteExpiry,
        emergency: inviteEmergency || undefined,
      },
    });
    if (err || !data) {
      error = extractError(err, 'Failed to create invite');
    } else {
      createdInvite = data;
      inviteEmail = '';
      await loadInvites();
    }
  }

  async function revokeInvite(id: string) {
    await adminApi.DELETE('/api/v1/admin/tenants/{slug}/invites/{id}', {
      params: { path: { slug, id } },
    });
    await loadInvites();
  }

  async function destroyTenant() {
    if (destroyConfirmSlug !== slug) return;
    destroying = true;
    error = '';
    const { error: err } = await adminApi.DELETE('/api/v1/admin/tenants/{slug}', {
      params: { path: { slug } },
    });
    if (err) {
      error = extractError(err, 'Failed to delete tenant');
      destroying = false;
    } else {
      window.location.href = thref(tenantSlug, '/admin/tenants');
    }
  }

  let inviteCopied = $state(false);

  function copyInviteLink() {
    if (!createdInvite) return;
    navigator.clipboard.writeText(createdInvite.invite_url);
    inviteCopied = true;
    setTimeout(() => inviteCopied = false, 2000);
  }

  function dismissInvite() {
    createdInvite = null;
    showInvite = false;
    inviteCopied = false;
    inviteEmergency = false;
    inviteRole = 'admin';
  }
</script>

<div class="space-y-6">
  <div class="flex items-center gap-3">
    <a href={thref(tenantSlug, '/admin/tenants')} class="text-(--text-secondary) hover:text-(--text-primary)" aria-label="Back to tenants">
      <Icon name="chevronLeft" tone="neutral" />
    </a>
    <h1 class="text-2xl font-bold text-(--text-primary)">{tenant?.name || slug}</h1>
    {#if tenant}
      <span class="px-2 py-0.5 rounded-sm text-xs font-medium {tenant.is_active ? 'bg-(--success-bg) text-(--success)' : 'bg-(--error-bg) text-(--error)'}">
        {tenant.is_active ? 'Active' : 'Suspended'}
      </span>
    {/if}
  </div>

  {#if error}
    <div class="p-3 rounded-lg bg-(--error-bg) border border-(--error)/20 text-sm text-(--error)">{error}</div>
  {/if}
  {#if success}
    <div class="p-3 rounded-lg bg-(--success-bg) border border-(--success-border) text-sm text-(--success)">{success}</div>
  {/if}

  <Tabs {tabs} active={activeTab} onchange={(t) => activeTab = t} />

  {#if activeTab === 'overview' && tenant}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6 space-y-4">
      <div class="grid grid-cols-2 gap-4">
        <div>
          <p class="text-xs text-(--text-secondary) mb-1">Name</p>
          <p class="text-sm text-(--text-primary) font-medium">{tenant.name}</p>
        </div>
        <div>
          <p class="text-xs text-(--text-secondary) mb-1">Slug</p>
          <p class="text-sm text-(--text-primary) font-mono">{tenant.slug}</p>
        </div>
        <div>
          <p class="text-xs text-(--text-secondary) mb-1">Admins</p>
          <p class="text-sm text-(--text-primary)">{tenant.admin_count}</p>
        </div>
        <div>
          <p class="text-xs text-(--text-secondary) mb-1">Created</p>
          <p class="text-sm text-(--text-primary)">{new Date(tenant.created_at).toLocaleString()}</p>
        </div>
      </div>

      {#if tenant.slug !== 'system'}
        <div class="border-t border-(--border) pt-4 flex gap-3">
          <button onclick={toggleActive}
            class="px-4 py-2 rounded-lg border text-sm font-medium transition-colors
                   {tenant.is_active ? 'border-(--error)/30 text-(--error) hover:bg-(--error-bg)' : 'border-(--success)/30 text-(--success) hover:bg-(--success-bg)'}">
            {tenant.is_active ? 'Suspend Tenant' : 'Activate Tenant'}
          </button>
          <button onclick={() => showDestroy = true}
            class="px-4 py-2 rounded-lg border border-(--error)/30 text-(--error) hover:bg-(--error-bg) text-sm font-medium transition-colors">
            Destroy Tenant
          </button>
        </div>
      {/if}
    </div>
  {/if}

  {#if activeTab === 'invites'}
    <div class="space-y-4">
      <div class="flex justify-end">
        <button onclick={() => { showInvite = true; createdInvite = null; }}
          class="px-4 py-2 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
                 hover:bg-(--accent-hover) transition-colors">
          + Create Invite
        </button>
      </div>

      <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
        <table class="w-full">
          <thead>
            <tr class="border-b border-(--border)">
              <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Role</th>
              <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Email</th>
              <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Status</th>
              <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Expires</th>
              <th class="text-right px-4 py-3"></th>
            </tr>
          </thead>
          <tbody>
            {#each invites as invite}
              <tr class="border-b border-(--border) last:border-0">
                <td class="px-4 py-3 text-sm text-(--text-primary)">{invite.role}</td>
                <td class="px-4 py-3 text-sm text-(--text-secondary)">{invite.email || '—'}</td>
                <td class="px-4 py-3">
                  <span class="px-2 py-0.5 rounded-sm text-xs font-medium {invite.used ? 'bg-(--bg-elevated) text-(--text-secondary)' : 'bg-(--tag-blue-bg) text-(--tag-blue-text)'}">
                    {invite.used ? 'Used' : 'Active'}
                  </span>
                </td>
                <td class="px-4 py-3 text-sm text-(--text-secondary)">
                  {new Date(invite.expires_at).toLocaleString()}
                </td>
                <td class="px-4 py-3 text-right">
                  {#if !invite.used}
                    <button onclick={() => revokeInvite(invite.id)}
                      class="text-xs text-(--error) hover:bg-(--error-bg) px-1.5 rounded-sm">Revoke</button>
                  {/if}
                </td>
              </tr>
            {/each}
            {#if invites.length === 0}
              <tr>
                <td colspan="5" class="px-4 py-8 text-center text-sm text-(--text-secondary)">No invites</td>
              </tr>
            {/if}
          </tbody>
        </table>
      </div>
    </div>

    {#if showInvite}
      <Modal open={showInvite} title={createdInvite ? 'Invite Created' : 'Create Invite'} onclose={dismissInvite}>
        {#if createdInvite}
          <div class="space-y-4">
            <div class="px-4 py-3 rounded-lg bg-(--warning-bg) text-sm text-(--warning)">
              Save this link now — you won't see it again.
            </div>
            <div class="p-3 bg-(--bg-primary) rounded-lg font-mono text-sm text-(--text-primary) break-all">
              {createdInvite.invite_url}
            </div>
            <p class="text-xs text-(--text-secondary)">Expires: {new Date(createdInvite.expires_at).toLocaleString()}</p>
            <div class="flex gap-2">
              <button onclick={copyInviteLink} class="flex-1 py-2 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium">
                {inviteCopied ? 'Copied!' : 'Copy Link'}
              </button>
              <button onclick={dismissInvite} class="px-4 py-2 rounded-lg border border-(--border) text-(--text-secondary) text-sm">Done</button>
            </div>
          </div>
        {:else}
          <div class="space-y-4">
            <div>
              <label for="invite-email" class="block text-sm font-medium text-(--text-secondary) mb-1.5">
                Email (optional — restrict to this email)
              </label>
              <input id="invite-email" type="email" bind:value={inviteEmail}
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                       text-(--text-primary) text-sm
                       focus:outline-hidden focus:border-(--accent)" />
            </div>
            <div>
              <label for="invite-expiry" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Expires in</label>
              <SelectInput id="invite-expiry" bind:value={inviteExpiry}>
                <option value={24}>24 hours</option>
                <option value={72}>3 days</option>
                <option value={168}>7 days</option>
              </SelectInput>
            </div>
            <div>
              <label for="invite-role" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Role</label>
              <SelectInput id="invite-role" bind:value={inviteRole}>
                <option value="admin">Admin — full management access</option>
                <option value="read_only">Read-only — view only, no changes</option>
              </SelectInput>
            </div>
            {#if slug !== 'system'}
              <div>
                <label class="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" bind:checked={inviteEmergency}
                    class="w-4 h-4 rounded-sm border-(--border) accent-(--accent)" />
                  <span class="text-sm font-medium text-(--text-secondary)">Emergency</span>
                </label>
                {#if inviteEmergency}
                  <div class="mt-2 p-3 rounded-lg bg-(--warning-bg) text-xs text-(--warning)">
                    This will temporarily reset tenant auth to password mode. OIDC configuration is preserved. The invited admin can switch back to OIDC after login.
                  </div>
                {/if}
              </div>
            {/if}
            <div class="flex justify-end gap-3 pt-2">
              <button onclick={dismissInvite}
                class="px-4 py-2 rounded-lg border border-(--border) text-(--text-secondary) text-sm
                       hover:bg-(--bg-elevated) transition-colors">Cancel</button>
              <button onclick={createInvite}
                class="px-4 py-2 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
                       hover:bg-(--accent-hover) transition-colors">Create</button>
            </div>
          </div>
        {/if}
      </Modal>
    {/if}
  {/if}

  {#if activeTab === 'admins'}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      <table class="w-full">
        <thead>
          <tr class="border-b border-(--border)">
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Email</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Status</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Last Login</th>
          </tr>
        </thead>
        <tbody>
          {#each admins as admin}
            <tr class="border-b border-(--border) last:border-0">
              <td class="px-4 py-3 text-sm text-(--text-primary) font-medium">{admin.email}</td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded-sm text-xs font-medium {admin.is_active ? 'bg-(--success-bg) text-(--success)' : 'bg-(--error-bg) text-(--error)'}">
                  {admin.is_active ? 'Active' : 'Disabled'}
                </span>
              </td>
              <td class="px-4 py-3 text-sm text-(--text-secondary)">
                {admin.last_login ? new Date(admin.last_login).toLocaleString() : 'Never'}
              </td>
            </tr>
          {/each}
          {#if admins.length === 0}
            <tr>
              <td colspan="4" class="px-4 py-8 text-center text-sm text-(--text-secondary)">No admin accounts</td>
            </tr>
          {/if}
        </tbody>
      </table>
    </div>
  {/if}
</div>

{#if showDestroy}
  <Modal open={showDestroy} title="Destroy Tenant" onclose={() => { showDestroy = false; destroyConfirmSlug = ''; }}>
    <div class="space-y-4">
      <div class="p-3 rounded-lg bg-(--error-bg) border border-(--error)/20">
        <p class="text-sm text-(--error) font-medium">This action is irreversible.</p>
        <p class="text-sm text-(--error) mt-1">All tenant data will be permanently deleted: users, keys, sessions, audit records, transforms, experts, and configuration.</p>
      </div>
      <div>
        <label for="destroy-confirm-slug" class="block text-sm font-medium text-(--text-secondary) mb-1.5">
          Type <code class="text-(--accent) font-mono">{slug}</code> to confirm
        </label>
        <input id="destroy-confirm-slug" bind:value={destroyConfirmSlug}
          placeholder={slug}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-primary) text-sm font-mono
                 focus:outline-hidden focus:border-(--error)" />
      </div>
      <div class="flex justify-end gap-3 pt-2">
        <button onclick={() => { showDestroy = false; destroyConfirmSlug = ''; }}
          class="px-4 py-2 rounded-lg border border-(--border) text-(--text-secondary) text-sm
                 hover:bg-(--bg-elevated) transition-colors">Cancel</button>
        <button onclick={destroyTenant}
          disabled={destroying || destroyConfirmSlug !== slug}
          class="px-4 py-2 rounded-lg bg-(--error) text-(--error-fg) text-sm font-medium
                 disabled:opacity-50 hover:bg-(--error)/85 transition-colors">
          {destroying ? 'Destroying…' : 'Destroy Tenant'}
        </button>
      </div>
    </div>
  </Modal>
{/if}
