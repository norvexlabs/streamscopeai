<script lang="ts">
  // Client access: which clients the portal and the CLI offer, and what the
  // developers' sandbox may reach besides the gateway. The tenant's Default
  // profile — every workspace resolves to it.
  import { onMount } from 'svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { useTabState } from '#lib/hooks.svelte.js';
  import TabbedPage from '#lib/components/page/TabbedPage.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import AttachmentsEditor from '#lib/components/destinations/AttachmentsEditor.svelte';
  import type { Attachment } from '#lib/destinationAttachments.js';
  import type { components } from '#lib/generated/api-types.js';

  type Content = components['schemas']['ClientAccessResponse'];
  type DestinationList = components['schemas']['DestinationList'];
  type Body = components['schemas']['UpdateClientAccessRequest'];

  type AccessTab = 'clients' | 'sandbox';
  const TABS = ['clients', 'sandbox'] as const satisfies readonly AccessTab[];
  const tab = useTabState<AccessTab>(TABS, 'clients');

  let profileId = $state<string | null>(null);
  let content = $state<Content | null>(null);
  let lists = $state<DestinationList[]>([]);
  let loading = $state(true);
  let saving = $state(false);

  const attachments = $derived<Attachment[]>(
    (content?.destinations ?? []).map((d) => ({ list_id: d.list_id, mode: d.mode })),
  );
  const offered = $derived((content?.clients ?? []).filter((c) => c.offered).length);

  async function load() {
    loading = true;
    const profiles = await adminApi.GET('/api/v1/admin/profiles', { params: { query: { kind: 'client_access', limit: 50 } } });
    if (profiles.error) {
      loading = false;
      toast.error('Failed to load client access', { body: extractError(profiles.error), code: extractErrorCode(profiles.error) ?? undefined });
      return;
    }
    profileId = profiles.data?.items.find((p) => p.is_default)?.id ?? null;
    const [access, all] = await Promise.all([
      profileId
        ? adminApi.GET('/api/v1/admin/profiles/{id}/client-access', { params: { path: { id: profileId } } })
        : Promise.resolve(null),
      adminApi.GET('/api/v1/admin/destination-lists', { params: { query: { limit: 500 } } }),
    ]);
    loading = false;
    if (access?.error) {
      toast.error('Failed to load client access', { body: extractError(access.error), code: extractErrorCode(access.error) ?? undefined });
    }
    content = access?.data ?? null;
    lists = all.data?.items ?? [];
  }

  async function update(body: Body, done: string) {
    if (!profileId) return;
    saving = true;
    const { data, error } = await adminApi.PATCH('/api/v1/admin/profiles/{id}/client-access', {
      params: { path: { id: profileId } },
      body,
    });
    saving = false;
    if (error) {
      toast.error('Failed to save client access', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    content = data ?? content;
    toast.success(done);
  }

  function setOffered(id: string, on: boolean) {
    if (!content) return;
    const ids = content.clients.filter((c) => (c.id === id ? on : c.offered)).map((c) => c.id);
    void update({ clients: ids }, on ? 'Client enabled' : 'Client disabled');
  }

  async function developerDefaults() {
    if (!profileId) return;
    saving = true;
    const { error } = await adminApi.POST('/api/v1/admin/profiles/{id}/actions/attach-developer-defaults', {
      params: { path: { id: profileId } },
    });
    saving = false;
    if (error) {
      toast.error('Failed to attach the developer defaults', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    toast.success('Developer defaults attached');
    await load();
  }

  onMount(load);
</script>

<TabbedPage
  title="Client access"
  subtitle="The clients the portal and the CLI offer, and what the developers' sandbox may reach besides the gateway."
  tabs={[
    { id: 'clients', label: 'Clients' },
    { id: 'sandbox', label: 'Sandbox' },
  ]}
  activeTab={tab.current}
  onTabChange={(t: AccessTab) => (tab.current = t)}
>
  {#snippet children(active: AccessTab)}
    <div class="mt-4 space-y-4 max-w-4xl">
      <div class="flex items-center gap-2 text-xs text-(--text-secondary)">
        <span class="px-1.5 py-0.5 text-[10px] rounded-sm bg-(--bg-primary) text-(--text-secondary) border border-(--border)">Default</span>
        Every workspace uses the Default profile. Per-workspace profiles are not offered yet.
      </div>
      {#if loading}
        <div class="rounded-lg border border-(--border) bg-(--bg-card) p-4"><Skeleton variant="row" /></div>
      {:else if !content}
        <EmptyState title="No client access profile" body="The tenant has no Default client access profile yet; it is created on the next start." />
      {:else if active === 'clients'}
        <div class="rounded-lg border border-(--border) bg-(--bg-card)">
          <div class="px-4 py-3 text-xs text-(--text-secondary) border-b border-(--border)">
            {offered} of {content.clients.length} clients offered. A client a later release adds arrives disabled.
          </div>
          <div class="divide-y divide-(--border)">
            {#each content.clients as c (c.id)}
              <div class="px-4" data-testid="client-access-row" data-client={c.id}>
                <ToggleSetting
                  label={c.label}
                  description={c.id}
                  value={c.offered}
                  disabled={saving}
                  onValueChange={(v: boolean) => setOffered(c.id, v)}
                >
                  {#snippet labelSuffix()}
                    {#if c.is_new}
                      <span class="ml-2 px-1.5 py-0.5 text-[10px] rounded-sm bg-(--info-bg) text-(--info-text) border border-(--info-border)">new</span>
                    {/if}
                  {/snippet}
                </ToggleSetting>
              </div>
            {/each}
          </div>
        </div>
      {:else}
        <div class="rounded-lg border border-(--border) bg-(--bg-card) p-5 space-y-3">
          <div class="flex items-start justify-between gap-3">
            <div>
              <h3 class="text-sm font-semibold text-(--text-primary)">Destinations</h3>
              <p class="text-xs text-(--text-secondary)">
                The gateway is always reachable; then a blocked destination is refused, an allowed one permitted, and
                anything else refused.
              </p>
            </div>
            <button
              onclick={developerDefaults}
              disabled={saving}
              class="shrink-0 px-3 py-1.5 text-xs border border-(--border) text-(--text-secondary) hover:text-(--text-primary) rounded-lg transition-colors disabled:opacity-50"
            >Use the developer defaults</button>
          </div>
          <AttachmentsEditor
            {lists}
            value={attachments}
            disabled={saving}
            emptyText="Nothing attached: the sandbox reaches the gateway only. The developer defaults allow the package and container registries and GitHub, and block paste sites."
            onchange={(next: Attachment[]) => update({ destinations: next }, 'Sandbox destinations saved')}
          />
        </div>
        <div class="rounded-lg border border-(--border) bg-(--bg-card) px-5 divide-y divide-(--border)">
          <ToggleSetting
            label="Require the sandbox"
            description="Refuse `ssai run --sandbox off` in this tenant's workspaces. A guard against mistakes on a developer's machine, not against its owner."
            value={content.settings.require_sandbox}
            disabled={saving}
            onValueChange={(v: boolean) => update({ settings: { require_sandbox: v } }, 'Sandbox setting saved')}
          />
          <ToggleSetting
            label="Allow the container sandbox"
            description="Let developers run `ssai run --sandbox docker`: the agent in a rootless Podman container on Linux, with no network but the guard. Off, only the native sandbox runs."
            value={content.settings.docker_tier}
            disabled={saving}
            onValueChange={(v: boolean) => update({ settings: { docker_tier: v } }, 'Sandbox setting saved')}
          />
        </div>
      {/if}
    </div>
  {/snippet}
</TabbedPage>
