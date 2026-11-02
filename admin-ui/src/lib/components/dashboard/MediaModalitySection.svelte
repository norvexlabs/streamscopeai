<script lang="ts">
  import { useLoadView } from '#lib/loadView.svelte.js';
  import { toast } from '#lib/toast.svelte.js';
  import { goto } from '$app/navigation';
  import { adminApi } from '#lib/api-client.js';
  import { page } from '$app/state';
  import { thref } from '#lib/tenant.js';
  import { auditHref, sessionsHref } from '#lib/deeplinks.js';

  let slug = $derived(page.params.slug ?? '');
  import { extractError } from '#lib/api-helpers.js';
  import { formatDuration, formatCount, formatSpend, type Spend } from '#lib/formatters.js';
  import { sumSpend } from '#lib/spend.js';
  import { accountingCurrency } from '#lib/currency.svelte.js';
  import { consoleScope, currentWorkspaceQuery, dashboardScopeParams, currentPeriodQuery } from '#lib/scope.svelte.js';
  import { usePeriodicLoad } from '#lib/hooks.svelte.js';
  import Icon from '#lib/components/Icon.svelte';
  import type { IconName } from '#lib/icons.js';
  import { tagMarkColor } from '#lib/components/TagBadge.svelte';

  interface DirectionStat {
    category: string;
    direction: string;
    label: string;
    requests: number;
    units: number;
    spend: Spend | null;
    p95_latency: number | null;
  }

  interface MediaUserStat {
    user_email: string;
    total_requests: number;
    spend: Spend | null;
    image_requests: number;
    audio_requests: number;
    embedding_requests: number;
    video_requests: number;
  }

  let loading = $state(true);
  // Spinner on the first load and after a scope change only (`#lib/loadView.js`).
  const view = useLoadView(() => loading);
  let directions = $state<DirectionStat[]>([]);
  let userStats = $state<MediaUserStat[]>([]);

  // Deep-links carry the dashboard's live scope (header workspace pin + period)
  // so the audit list opens on exactly what this section shows.
  const linkScope = $derived(dashboardScopeParams(consoleScope.period, consoleScope.workspace));

  // `accent` is a mark (the card's left rule); `text` colours the icon and the column header.
  const categoryColors: Record<string, { accent: string; text: string; bg: string; badge: string }> = {
    image:     { accent: tagMarkColor('violet'), text: 'var(--tag-violet-text)', bg: 'var(--tag-violet-bg)',  badge: 'bg-(--tag-violet-bg) text-(--tag-violet-text)' },
    audio:     { accent: 'var(--success)', text: 'var(--success-text)', bg: 'var(--success-bg)',  badge: 'bg-(--tag-teal-bg) text-(--tag-teal-text)' },
    embedding: { accent: 'var(--accent)', text: 'var(--accent)', bg: 'var(--tag-blue-bg)',  badge: 'bg-(--tag-blue-bg) text-(--tag-blue-text)' },
    video:     { accent: tagMarkColor('indigo'), text: 'var(--tag-indigo-text)', bg: 'var(--tag-indigo-bg)',  badge: 'bg-(--tag-indigo-bg) text-(--tag-indigo-text)' },
    unknown:   { accent: 'var(--warning)', text: 'var(--warning)', bg: 'var(--tag-amber-bg)',  badge: 'bg-(--tag-amber-bg) text-(--tag-amber-text)' },
  };

  function getColor(cat: string) {
    return categoryColors[cat] ?? { accent: 'var(--text-secondary)', text: 'var(--text-secondary)', bg: 'var(--bg-elevated)', badge: 'bg-(--bg-elevated) text-(--text-secondary) border-(--border)' };
  }

  function categoryIcon(cat: string): IconName {
    switch (cat) {
      case 'embedding': return 'embedding';
      case 'audio':     return 'audio';
      case 'image':     return 'image';
      case 'video':     return 'video';
      case 'unknown':   return 'triangleAlert';
      default:          return 'book';
    }
  }

  async function loadMediaData() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/analytics/media', {
      params: { query: { ...currentPeriodQuery(), ...currentWorkspaceQuery() } },
    });
    if (err) {
      toast.error(extractError(err, 'unknown'));
      directions = [];
      userStats = [];
    } else if (data) {
      directions = (data.directions ?? []).map((d) => ({
        category: d.category,
        direction: d.direction,
        label: d.label,
        requests: d.requests,
        units: d.units,
        spend: d.spend ?? null,
        p95_latency: d.p95_latency ?? null,
      }));
      userStats = (data.users ?? []).map((u) => ({
        user_email: u.user_email,
        total_requests: u.total_requests,
        spend: u.spend ?? null,
        image_requests: u.image_requests,
        audio_requests: u.audio_requests,
        embedding_requests: u.embedding_requests,
        video_requests: u.video_requests,
      }));
    }
    loading = false;
  }

  usePeriodicLoad(loadMediaData);

  let totalRequests = $derived(directions.reduce((sum, d) => sum + d.requests, 0));
  // `null` when the directions are stated in more than one currency.
  let totalCost = $derived(sumSpend(directions.map((d) => d.spend), accountingCurrency()));
  let categoryGroups = $derived.by(() => {
    const order = ['image', 'audio', 'embedding', 'video'];
    const grouped = new Map<string, DirectionStat[]>();
    for (const cat of order) grouped.set(cat, []);
    for (const d of directions) {
      const list = grouped.get(d.category);
      if (list) list.push(d);
      else grouped.set(d.category, [d]);
    }
    return [...grouped.entries()].filter(([, dirs]) => dirs.length > 0);
  });

  function capitalize(s: string): string {
    return s.charAt(0).toUpperCase() + s.slice(1);
  }
</script>

<section class="space-y-4">
  <div class="flex items-center justify-between">
    <h2 class="text-lg font-semibold text-(--text-primary)">Media modalities</h2>
    <p class="text-xs text-(--text-secondary)">
      Image / audio / embedding / video traffic across endpoints and chat attachments
    </p>
  </div>

  <div class="grid grid-cols-2 gap-4">
    <div class="bg-(--bg-card) rounded-xl p-4 border border-(--border)">
      <div class="text-2xl font-bold text-(--text-primary)">{formatCount(totalRequests)}</div>
      <div class="text-xs text-(--text-secondary) uppercase tracking-wider mt-1">Media requests</div>
    </div>
    <div class="bg-(--bg-card) rounded-xl p-4 border border-(--border)">
      <div class="text-2xl font-bold text-(--text-primary)">{formatSpend(totalCost)}</div>
      <div class="text-xs text-(--text-secondary) uppercase tracking-wider mt-1">Media cost</div>
    </div>
  </div>

  {#if view.skeleton}
    <div class="flex items-center gap-3 py-12 justify-center text-(--text-secondary)">
      <div class="w-5 h-5 border-2 border-(--accent) border-t-transparent rounded-full animate-spin"></div>
      Loading media data…
    </div>
  {:else if totalRequests === 0}
    <div class="bg-(--bg-card) rounded-xl border border-(--border) py-8 text-center">
      <p class="text-sm text-(--text-secondary)">No media requests in this window</p>
      <p class="text-xs text-(--text-secondary) mt-1">Media usage appears when endpoints are called or images are sent in chat</p>
    </div>
  {:else}
    {#each categoryGroups as [category, dirs]}
      {@const color = getColor(category)}
      <div>
        <div class="flex items-center gap-2 mb-3">
          <Icon name={categoryIcon(category)} color={color.text} />
          <h3 class="text-sm font-semibold text-(--text-primary) uppercase tracking-wider">{capitalize(category)}</h3>
        </div>
        <div class="grid grid-cols-1 {dirs.length > 1 ? 'md:grid-cols-2' : ''} gap-4">
          {#each dirs as dir}
            <a
              href={thref(slug, auditHref({ kind: 'llm', media_type: category, ...linkScope }))}
              class="block bg-(--bg-card) rounded-xl p-5 border border-(--border) hover:bg-(--bg-elevated) hover:border-(--accent) transition-colors cursor-pointer"
              style="border-left: 3px solid {color.accent}"
            >
              <div class="flex items-center justify-between mb-3">
                <div>
                  <span class="text-xs font-semibold text-(--text-primary) uppercase">{dir.direction}</span>
                  <span class="text-xs text-(--text-secondary) ml-2">{dir.label}</span>
                </div>
              </div>
              <div class="grid grid-cols-2 gap-x-6 gap-y-2">
                <div>
                  <div class="text-xl font-bold text-(--text-primary)">{formatCount(dir.requests)}</div>
                  <div class="text-[10px] text-(--text-secondary) uppercase">requests</div>
                </div>
                <div>
                  <div class="text-xl font-bold text-(--text-primary)">{formatSpend(dir.spend)}</div>
                  <div class="text-[10px] text-(--text-secondary) uppercase">cost</div>
                </div>
                {#if dir.units > 0}
                  <div>
                    <div class="text-sm font-mono text-(--text-primary)">{formatCount(dir.units)}</div>
                    <div class="text-[10px] text-(--text-secondary) uppercase">units</div>
                  </div>
                {/if}
                {#if dir.p95_latency}
                  <div>
                    <div class="text-sm font-mono text-(--text-primary)">{formatDuration(dir.p95_latency)}</div>
                    <div class="text-[10px] text-(--text-secondary) uppercase">P95 latency</div>
                  </div>
                {/if}
              </div>
            </a>
          {/each}
        </div>
      </div>
    {/each}

    <div>
      <h3 class="text-base font-semibold text-(--text-primary) mb-3">Top users by media spend</h3>
      <div class="bg-(--bg-card) rounded-xl border border-(--border) overflow-hidden">
        <table class="w-full text-sm">
          <thead>
            <tr class="border-b border-(--border) bg-(--bg-primary)/50">
              <th class="px-4 py-3 text-left text-xs text-(--text-secondary) uppercase tracking-wider font-medium">User</th>
              <th class="px-4 py-3 text-right text-xs uppercase tracking-wider font-medium" style="color: {categoryColors.image.text}">Image</th>
              <th class="px-4 py-3 text-right text-xs uppercase tracking-wider font-medium" style="color: {categoryColors.audio.text}">Audio</th>
              <th class="px-4 py-3 text-right text-xs uppercase tracking-wider font-medium" style="color: {categoryColors.embedding.text}">Embed</th>
              <th class="px-4 py-3 text-right text-xs uppercase tracking-wider font-medium" style="color: {categoryColors.video.text}">Video</th>
              <th class="px-4 py-3 text-right text-xs text-(--text-secondary) uppercase tracking-wider font-medium">Cost</th>
            </tr>
          </thead>
          <tbody>
            {#each userStats as user}
              {@const href = user.user_email ? thref(slug, sessionsHref({ user_email: user.user_email, ...linkScope })) : null}
              <tr
                class="border-b border-(--border) {href ? 'hover:bg-(--bg-elevated) cursor-pointer' : ''} transition-colors"
                role={href ? 'link' : undefined}
                tabindex={href ? 0 : undefined}
                onclick={href ? () => goto(href) : undefined}
                onkeydown={(e) => {
                  if (!href) return;
                  if (e.target !== e.currentTarget) return;
                  if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); goto(href); }
                }}
              >
                <td class="px-4 py-3">
                  <span class="text-sm text-(--text-primary)">{user.user_email}</span>
                </td>
                <td class="px-4 py-3 text-right font-mono text-sm {user.image_requests > 0 ? 'text-(--text-primary)' : 'text-(--text-secondary)'}">{user.image_requests}</td>
                <td class="px-4 py-3 text-right font-mono text-sm {user.audio_requests > 0 ? 'text-(--text-primary)' : 'text-(--text-secondary)'}">{user.audio_requests}</td>
                <td class="px-4 py-3 text-right font-mono text-sm {user.embedding_requests > 0 ? 'text-(--text-primary)' : 'text-(--text-secondary)'}">{user.embedding_requests}</td>
                <td class="px-4 py-3 text-right font-mono text-sm {user.video_requests > 0 ? 'text-(--text-primary)' : 'text-(--text-secondary)'}">{user.video_requests}</td>
                <td class="px-4 py-3 text-right font-mono text-sm text-(--text-primary)">{formatSpend(user.spend)}</td>
              </tr>
            {/each}
          </tbody>
        </table>
        {#if userStats.length === 0}
          <div class="py-8 text-center">
            <p class="text-sm text-(--text-secondary)">No user data available</p>
          </div>
        {/if}
      </div>
    </div>
  {/if}
</section>
