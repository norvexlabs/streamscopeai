<script lang="ts">
  import Modal from '#lib/components/Modal.svelte';
  import Page from '#lib/components/page/Page.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import CopyTextButton from '#lib/components/CopyTextButton.svelte';
  import { adminApi } from '#lib/api-client.js';
  import { goto } from '$app/navigation';
  import { extractError, fetchAllPages } from '#lib/api-helpers.js';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import type { components } from '#lib/generated/api-types.js';
  type TenantResponse = components['schemas']['TenantResponse'];

  let tenants = $state<TenantResponse[]>([]);
  let loading = $state(true);
  let showCreate = $state(false);
  let newName = $state('');
  let newSlug = $state('');
  let newAdminEmail = $state('');
  let creating = $state(false);
  let error = $state('');
  let createdInviteUrl = $state('');

  $effect(() => {
    loadTenants();
  });

  async function loadTenants() {
    try {
      tenants = await fetchAllPages<TenantResponse>((offset, limit) =>
        adminApi.GET('/api/v1/admin/tenants', { params: { query: { offset, limit } } }));
    } finally {
      loading = false;
    }
  }

  function openTenant(tenantSlug: string) {
    void goto(thref(slug, `/admin/tenants/${tenantSlug}`));
  }

  async function createTenant() {
    creating = true;
    error = '';

    // Require admin email so the invite is actually sent — an empty email
    // silently skipped the invite, leaving the tenant unreachable.
    const emailTrimmed = newAdminEmail.trim();
    if (!emailTrimmed) {
      error = 'Admin email is required — needed to generate the tenant invite.';
      creating = false;
      return;
    }
    const emailPattern = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailPattern.test(emailTrimmed)) {
      error = 'Admin email is invalid.';
      creating = false;
      return;
    }

    try {
      const { data: tenant, error: err } = await adminApi.POST('/api/v1/admin/tenants', {
        body: { name: newName, slug: newSlug },
      });
      if (err || !tenant) {
        error = extractError(err, 'Failed to create tenant');
        return;
      }

      const { data: inv, error: invErr } = await adminApi.POST('/api/v1/admin/tenants/{slug}/invites', {
        params: { path: { slug: tenant.slug } },
        body: { role: 'admin', email: emailTrimmed, expires_in_hours: 168 },
      });
      if (invErr || !inv) {
        error = `Tenant created but invite failed: ${extractError(invErr, 'Unknown error')}`;
        await loadTenants();
        return;
      }
      createdInviteUrl = inv.invite_url;

      showCreate = false;
      newName = '';
      newSlug = '';
      newAdminEmail = '';
      await loadTenants();
    } finally {
      creating = false;
    }
  }

  function autoSlug() {
    newSlug = newName.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '').slice(0, 50);
  }
</script>

<Page title="Tenants">
  {#snippet actions()}
    <button onclick={() => showCreate = true}
      class="px-4 py-2 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
             hover:bg-(--accent-hover) transition-colors">
      + Create Tenant
    </button>
  {/snippet}

  {#if loading}
    <Skeleton variant="row" count={4} />
  {:else if tenants.length === 0}
    <EmptyState title="No tenants yet" body="Create a tenant to onboard an organization." />
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      <table class="w-full">
        <thead>
          <tr class="border-b border-(--border)">
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Name</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Slug</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Status</th>
            <th class="text-left px-4 py-3 text-xs font-medium text-(--text-secondary) uppercase">Created</th>
          </tr>
        </thead>
        <tbody>
          {#each tenants as tenant (tenant.slug)}
            <tr
              class="border-b border-(--border) last:border-0 hover:bg-(--bg-elevated) cursor-pointer transition-colors"
              role="button"
              tabindex="0"
              onclick={() => openTenant(tenant.slug)}
              onkeydown={(e) => {
                if ((e.key === 'Enter' || e.key === ' ') && e.target === e.currentTarget) {
                  e.preventDefault();
                  openTenant(tenant.slug);
                }
              }}
            >
              <td class="px-4 py-3 text-sm text-(--text-primary) font-medium">{tenant.name}</td>
              <td class="px-4 py-3 text-sm text-(--text-secondary) font-mono">{tenant.slug}</td>
              <td class="px-4 py-3">
                <span class="px-2 py-0.5 rounded-sm text-xs font-medium {tenant.is_active ? 'bg-(--success-bg) text-(--success)' : 'bg-(--error-bg) text-(--error)'}">
                  {tenant.is_active ? 'Active' : 'Suspended'}
                </span>
              </td>
              <td class="px-4 py-3 text-sm text-(--text-secondary)">
                {new Date(tenant.created_at).toLocaleDateString()}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Page>

{#if createdInviteUrl}
  <div class="bg-(--bg-card) rounded-xl border border-(--success)/30 p-4 space-y-2">
    <p class="text-sm font-medium text-(--success)">Tenant created! Share this invite link with the admin (shown once):</p>
    <div class="flex items-center gap-2">
      <code class="flex-1 text-xs font-mono text-(--text-primary) bg-(--bg-primary) rounded-sm px-3 py-2 overflow-x-auto">
        {createdInviteUrl}
      </code>
      <CopyTextButton value={createdInviteUrl} />
      <button onclick={() => { createdInviteUrl = ''; }}
        class="px-3 py-2 rounded-lg border border-(--border) text-(--text-secondary) text-xs">Dismiss</button>
    </div>
  </div>
{/if}

{#if showCreate}
  <Modal open={showCreate} title="Create Tenant" onclose={() => showCreate = false}>
    <div class="space-y-4">
      {#if error}
        <div class="p-3 rounded-lg bg-(--error-bg) border border-(--error)/20 text-sm text-(--error)">{error}</div>
      {/if}
      <div>
        <label for="tenant-name" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Name</label>
        <input id="tenant-name" type="text" bind:value={newName} oninput={autoSlug}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                 text-(--text-primary) text-sm
                 focus:outline-hidden focus:border-(--accent)" />
      </div>
      <div>
        <label for="admin-email" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Admin email <span class="text-(--error)">*</span></label>
        <input id="admin-email" type="email" required bind:value={newAdminEmail}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                 text-(--text-primary) text-sm
                 focus:outline-hidden focus:border-(--accent)" />
      </div>
      <div>
        <label for="tenant-slug" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Slug</label>
        <input id="tenant-slug" type="text" bind:value={newSlug}
          class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                 text-(--text-primary) text-sm font-mono
                 focus:outline-hidden focus:border-(--accent)" />
        <p class="text-xs text-(--text-secondary) mt-1">Lowercase letters, numbers, and hyphens. Used in URLs.</p>
      </div>
      <div class="flex justify-end gap-3 pt-2">
        <button onclick={() => showCreate = false}
          class="px-4 py-2 rounded-lg border border-(--border) text-(--text-secondary) text-sm
                 hover:bg-(--bg-elevated) transition-colors">Cancel</button>
        <button onclick={createTenant} disabled={creating || !newName || !newSlug || !newAdminEmail.trim()}
          class="px-4 py-2 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
                 hover:bg-(--accent-hover) transition-colors
                 disabled:opacity-50 disabled:cursor-not-allowed">
          {creating ? 'Creating…' : 'Create'}
        </button>
      </div>
    </div>
  </Modal>
{/if}
