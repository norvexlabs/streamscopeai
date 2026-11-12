<script lang="ts">
  /**
   * A Portal & clients profile's content — what it hides in the portal, and the
   * clients the portal and the CLI
   * offer the workspaces on this profile, and what their developers' sandbox
   * may reach besides the gateway. Every change saves at once.
   */
  import { untrack } from 'svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import { useTabState } from '#lib/hooks.svelte.js';
  import { KeyedContent } from '#lib/keyedContent.svelte.js';
  import Tabs from '#lib/components/Tabs.svelte';
  import Skeleton from '#lib/components/Skeleton.svelte';
  import EmptyState from '#lib/components/EmptyState.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import AttachmentsEditor from '#lib/components/destinations/AttachmentsEditor.svelte';
  import type { Attachment } from '#lib/destinationAttachments.js';
  import type { components } from '#lib/generated/api-types.js';

  type Content = components['schemas']['ClientAccessResponse'];
  type DestinationList = components['schemas']['DestinationList'];
  type Body = components['schemas']['UpdateClientAccessRequest'];

  interface Props {
    profileId: string;
  }

  let { profileId }: Props = $props();

  type AccessTab = 'clients' | 'sandbox' | 'pages';
  const TABS = ['clients', 'sandbox', 'pages'] as const satisfies readonly AccessTab[];
  type PortalPage = components['schemas']['PortalPage'];
  /** What a profile can hide in the portal, as the tab lists it: each switch
   *  is worded for everything it takes away. */
  const PAGES: { page: PortalPage; label: string; description: string }[] = [
    {
      page: 'sessions',
      label: 'Hide conversations',
      description:
        'The Sessions page and all conversation content: request details, media and tool definitions. The Requests page, unless hidden too, then lists each request with its model, tokens, cost and status only, and a request does not open.',
    },
    {
      page: 'requests',
      label: 'Hide the Requests page',
      description:
        'The list of requests (model, tokens, cost, status). Conversations stay readable on the Sessions page unless they are hidden too.',
    },
  ];
  const tab = useTabState<AccessTab>(TABS, 'clients');

  // INVARIANT: `content` is the profile shown (`profileId`), or `null`. It is
  // held as one visit of that profile (`KeyedContent`): a read or a save
  // issued under an earlier visit is dropped when it lands, and nothing is
  // saved while a profile loads — so a change is never computed from one
  // profile's list and written to another.
  const shown = new KeyedContent<Content>();
  const content = $derived(shown.value);
  let lists = $state<DestinationList[]>([]);
  let loading = $state(true);
  let saving = $state(false);

  const attachments = $derived<Attachment[]>(
    (content?.destinations ?? []).map((d) => ({ list_id: d.list_id, mode: d.mode })),
  );
  const offered = $derived((content?.clients ?? []).filter((c) => c.offered).length);

  async function load(id: string) {
    const visit = shown.show(id);
    loading = true;
    const [access, all] = await Promise.all([
      adminApi.GET('/api/v1/admin/profiles/{id}/client-access', { params: { path: { id } } }),
      adminApi.GET('/api/v1/admin/destination-lists', { params: { query: { limit: 500 } } }),
    ]);
    // Another profile was opened, or this one again, while it loaded.
    if (!shown.land(visit, access.data ?? null)) return;
    loading = false;
    if (access.error) {
      toast.error('Failed to load the profile', { body: extractError(access.error), code: extractErrorCode(access.error) ?? undefined });
    }
    lists = all.data?.items ?? [];
  }

  async function update(body: Body, done: string) {
    const id = shown.key;
    if (loading || saving || !id) return;
    const visit = shown.visit;
    saving = true;
    const { data, error } = await adminApi.PATCH('/api/v1/admin/profiles/{id}/client-access', {
      params: { path: { id } },
      body,
    });
    saving = false;
    // The view has moved on: this answer is an earlier visit's content.
    if (!shown.isCurrent(visit)) return;
    if (error) {
      toast.error('Failed to save the profile', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    if (data) shown.land(visit, data);
    toast.success(done);
  }

  function setOffered(id: string, on: boolean) {
    if (!content) return;
    const ids = content.clients.filter((c) => (c.id === id ? on : c.offered)).map((c) => c.id);
    void update({ clients: ids }, on ? 'Client enabled' : 'Client disabled');
  }

  /** Hide or show one of the two; the other stays as it is. */
  function setHidden(page: PortalPage, hide: boolean) {
    if (!content) return;
    const pages = content.hidden_pages.filter((p) => p !== page);
    if (hide) pages.push(page);
    void update({ hidden_pages: pages }, hide ? 'Hidden in the portal' : 'Shown in the portal');
  }

  /** Offer every client, or none, in one save. */
  function setAll(on: boolean) {
    if (!content) return;
    void update({ clients: on ? content.clients.map((c) => c.id) : [] }, on ? 'Every client offered' : 'No client offered');
  }

  async function developerDefaults() {
    const id = shown.key;
    if (loading || saving || !id) return;
    const visit = shown.visit;
    saving = true;
    const { error } = await adminApi.POST('/api/v1/admin/profiles/{id}/actions/attach-developer-defaults', {
      params: { path: { id } },
    });
    saving = false;
    if (!shown.isCurrent(visit)) return;
    if (error) {
      toast.error('Failed to attach the developer defaults', { body: extractError(error), code: extractErrorCode(error) ?? undefined });
      return;
    }
    toast.success('Developer defaults attached');
    await load(id);
  }

  // The profile shown is the only thing that reloads it.
  $effect(() => {
    const id = profileId;
    untrack(() => void load(id));
  });
</script>

<Tabs
  tabs={[
    { id: 'clients', label: 'Clients' },
    { id: 'sandbox', label: 'Sandbox' },
    { id: 'pages', label: 'Portal pages' },
  ]}
  active={tab.current}
  onchange={(t: string) => (tab.current = t as AccessTab)}
/>

<div class="mt-4 space-y-4 max-w-4xl">
  {#if loading}
    <div class="rounded-lg border border-(--border) bg-(--bg-card) p-4"><Skeleton variant="row" /></div>
  {:else if !content}
    <EmptyState title="Profile not loaded" body="The profile's clients and sandbox could not be read. Reload the page to try again." />
  {:else if tab.current === 'clients'}
    <div class="rounded-lg border border-(--border) bg-(--bg-card)">
      <div class="px-4 py-3 flex items-start justify-between gap-4 text-xs text-(--text-secondary) border-b border-(--border)">
        <span>
          {offered} of {content.clients.length} clients offered. A client marked <strong>new</strong> was added
          after this profile was created and is not offered yet: one a later release ships, on every profile
          that existed before it; one you create, on every profile but the Default of that moment, which offers it.
        </span>
        <span class="shrink-0 flex items-center gap-3">
          <button
            onclick={() => setAll(true)}
            disabled={saving || offered === content.clients.length}
            class="text-(--accent) hover:underline disabled:opacity-50 disabled:no-underline"
          >Offer all</button>
          <button
            onclick={() => setAll(false)}
            disabled={saving || offered === 0}
            class="text-(--accent) hover:underline disabled:opacity-50 disabled:no-underline"
          >Offer none</button>
        </span>
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
  {:else if tab.current === 'pages'}
    <div class="rounded-lg border border-(--border) bg-(--bg-card)" data-testid="client-access-pages">
      <div class="px-5 py-3 text-xs text-(--text-secondary) border-b border-(--border)">
        Each is hidden for a member only when <strong>every</strong> workspace they belong to is on a profile
        that hides it: someone in a workspace that shows it keeps it. A member of no workspace follows the
        Default. The gateway withholds what is hidden, not only the portal's entry for it; usage figures —
        counts, tokens, spend — stay.
      </div>
      <div class="px-5 divide-y divide-(--border)">
        {#each PAGES as p (p.page)}
          <div data-testid="client-access-page" data-page={p.page}>
            <ToggleSetting
              label={p.label}
              description={p.description}
              value={content.hidden_pages.includes(p.page)}
              disabled={saving}
              onValueChange={(v: boolean) => setHidden(p.page, v)}
            />
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
            anything else refused. A list is shared: editing its entries reaches every profile that attaches it.
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
        description="Refuse `ssai run --sandbox off` in the workspaces on this profile. On Windows a developer first runs `ssai sandbox setup` once. A guard against mistakes on a developer's machine, not against its owner."
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
