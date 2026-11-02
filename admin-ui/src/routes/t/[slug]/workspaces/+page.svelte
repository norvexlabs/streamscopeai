<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import type { WorkspaceSummary } from '#lib/api-types.js';
  import { goto } from '$app/navigation';
  import { thref } from '#lib/tenant.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();

  let slug = $derived(params.slug);
  import Icon from '#lib/components/Icon.svelte';
  import Page from '#lib/components/page/Page.svelte';
  import Modal from '#lib/components/Modal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import TagBadge from '#lib/components/TagBadge.svelte';
  import FormError from '#lib/components/forms/FormError.svelte';

  let workspaces = $state<WorkspaceSummary[]>([]);
  let loading = $state(true);
  let loadError = $state('');

  // Create form
  let showCreate = $state(false);
  let newName = $state('');
  let newDescription = $state('');
  let creating = $state(false);
  let createError = $state('');

  async function load() {
    loading = true;
    loadError = '';
    const { data, error } = await adminApi.GET('/api/v1/admin/workspaces', {
      params: { query: { offset: 0, limit: 200 } },
    });
    if (error) {
      loadError = extractError(error, 'Failed to load workspaces');
    } else {
      workspaces = data?.items ?? [];
    }
    loading = false;
  }

  $effect(() => {
    load();
  });

  function openCreate() {
    newName = '';
    newDescription = '';
    createError = '';
    showCreate = true;
  }

  async function createWorkspace() {
    if (!newName.trim()) return;
    creating = true;
    createError = '';
    const { data, error } = await adminApi.POST('/api/v1/admin/workspaces', {
      body: {
        name: newName.trim(),
        description: newDescription.trim() || undefined,
      },
    });
    if (error) {
      createError = extractError(error, 'Failed to create workspace');
    } else {
      showCreate = false;
      if (data?.id) {
        await goto(thref(slug, `/workspaces/${data.id}`));
      } else {
        await load();
      }
    }
    creating = false;
  }
</script>

<Page
  title="Workspaces"
  subtitle="A workspace bundles members, an allowlist of providers and MCP servers, a budget and rate ceiling, and per-workspace tool-rule overrides. Keys are minted inside a workspace and billed against it."
>
  {#snippet actions()}
    <button
      onclick={openCreate}
      class="px-3 py-1.5 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium transition-colors"
    >
      + New Workspace
    </button>
  {/snippet}

  {#if loadError}
    <div class="px-3 py-2 rounded-lg bg-(--error-bg) border border-(--error-border) text-sm text-(--error-text)">
      {loadError}
    </div>
  {/if}

  {#if loading}
    <div class="space-y-2">
      <Skeleton variant="row" />
      <Skeleton variant="row" />
      <Skeleton variant="row" />
    </div>
  {:else if workspaces.length === 0}
    <EmptyState title="No workspaces" body="Create a workspace to organize access and budgets.">
      {#snippet icon()}<Icon name="building" size="lg" tone="neutral" />{/snippet}
    </EmptyState>
  {:else}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
      <table class="w-full text-sm">
        <thead>
          <tr class="border-b border-(--border) bg-(--bg-primary)/30">
            <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Name</th>
            <th class="px-6 py-2.5 text-left text-xs text-(--text-secondary) uppercase tracking-wider">Tool Profile</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Members</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">Providers</th>
            <th class="px-6 py-2.5 text-right text-xs text-(--text-secondary) uppercase tracking-wider">MCP Servers</th>
          </tr>
        </thead>
        <tbody>
          {#each workspaces as ws (ws.id)}
            {@const toolsProfile = ws.assigned_profiles?.find((p) => p.kind === 'tools')}
            <tr
              class="border-b border-(--border) last:border-0 hover:bg-(--bg-elevated) cursor-pointer"
              onclick={() => goto(thref(slug, `/workspaces/${ws.id}`))}
            >
              <td class="px-6 py-3">
                <span class="inline-flex items-center gap-2 text-(--text-primary) font-medium">
                  <Icon name="building" size="sm" tone="neutral" />
                  {ws.name}
                  {#if ws.role === 'default'}
                    <span class="px-1.5 py-0.5 text-[10px] font-medium rounded-full bg-(--accent)/10 text-(--accent) border border-(--accent)">Default</span>
                  {/if}
                  {#if ws.role === 'agent'}
                    <span class="px-1.5 py-0.5 text-[10px] font-medium rounded-full bg-(--accent)/10 text-(--accent) border border-(--accent)">Agent</span>
                  {/if}
                  {#if ws.role === 'inline'}
                    <span class="px-1.5 py-0.5 text-[10px] font-medium rounded-full bg-(--accent)/10 text-(--accent) border border-(--accent)">Inline AI</span>
                  {/if}
                </span>
              </td>
              <td class="px-6 py-3">
                {#if toolsProfile}
                  <TagBadge color="teal">{toolsProfile.name}</TagBadge>
                {:else}
                  <span class="text-xs text-(--text-tertiary)">Default</span>
                {/if}
              </td>
              <td class="px-6 py-3 text-right font-mono tabular-nums text-(--text-secondary)">{ws.member_count}</td>
              <td class="px-6 py-3 text-right font-mono tabular-nums text-(--text-secondary)">
                {ws.provider_count}
              </td>
              <td class="px-6 py-3 text-right font-mono tabular-nums text-(--text-secondary)">
                {ws.mcp_server_count}
              </td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
</Page>

<Modal open={showCreate} title="New Workspace" onclose={() => (showCreate = false)} maxWidth="max-w-md">
  <div class="space-y-4">
    <FormField label="Name *">
      <TextInput bind:value={newName} placeholder="Production" />
    </FormField>
    <FormField label="Description">
      <TextInput bind:value={newDescription} placeholder="Optional" />
    </FormField>
    {#if createError}
      <FormError message={createError} />
    {/if}
    <div class="flex items-center justify-end gap-2">
      <button
        onclick={() => (showCreate = false)}
        class="px-4 py-1.5 text-sm rounded-lg text-(--text-secondary) hover:text-(--text-primary) transition-colors"
      >
        Cancel
      </button>
      <button
        onclick={createWorkspace}
        disabled={creating || !newName.trim()}
        class="px-4 py-1.5 text-sm rounded-lg bg-(--accent) text-(--accent-fg) hover:bg-(--accent-hover) transition-opacity disabled:opacity-50"
      >
        {creating ? 'Creating…' : 'Create'}
      </button>
    </div>
  </div>
</Modal>
