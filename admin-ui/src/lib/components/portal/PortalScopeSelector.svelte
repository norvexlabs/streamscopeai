<script lang="ts">
  /**
   * "Me / Team" switch for the portal's activity views (Sessions, Requests,
   * Usage). The workspace is the one picked in the portal header — this
   * switch only chooses between the caller's own rows and that workspace's.
   *
   * Renders **nothing** unless the header workspace shares its activity with
   * members — the choice does not exist otherwise. When the header moves to
   * another workspace while Team is on, the view follows it (or falls back to
   * the caller's own rows where the new one does not share).
   *
   * The server re-checks sharing and membership on every request, so this only
   * decides what to ask for.
   */
  import { portalScope } from '#lib/scope.svelte.js';
  import { m } from '#lib/paraglide/messages.js';
  import SegmentedControl from '#lib/components/forms/SegmentedControl.svelte';

  interface Props {
    /** The workspace being viewed, or `undefined` for the caller's own rows. */
    workspaceId?: string;
    onChange: (workspaceId: string | undefined) => void;
  }

  let { workspaceId = undefined, onChange }: Props = $props();

  // The header workspace, when it shares with its members.
  const sharedActive = $derived.by(() => {
    const id = portalScope.activeWorkspace;
    return portalScope.workspaces.find((w) => w.id === id && w.shares_with_members)?.id;
  });

  // Follow the header, the portal's one workspace picker: a team view never
  // stays on a workspace the header does not show. Not before the memberships
  // have loaded: a team view opened from a link (`?workspace_id=`) would
  // otherwise fall back to Me on the first render.
  $effect(() => {
    if (!portalScope.membershipsLoaded) return;
    const target = sharedActive;
    if (workspaceId !== undefined && workspaceId !== target) onChange(target);
  });
</script>

{#if sharedActive}
  <SegmentedControl
    value={workspaceId ? 'team' : 'me'}
    label={m.portal_scope_label()}
    options={[
      { value: 'me', label: m.portal_scope_me() },
      { value: 'team', label: m.portal_scope_team() },
    ]}
    onchange={(v) => onChange(v === 'team' ? sharedActive : undefined)} />
{/if}
