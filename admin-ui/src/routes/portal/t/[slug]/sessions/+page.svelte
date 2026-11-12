<script lang="ts">
  // Portal — Sessions: the shared session list, over the caller's own rows or,
  // where the header workspace shares with its members, the team's. The
  // server decides whose rows; the plane only says which workspace is viewed.
  import SessionsBrowser from '#lib/components/browse/SessionsBrowser.svelte';
  import PortalPageGate from '#lib/components/portal/PortalPageGate.svelte';
  import { portalPlane } from '#lib/browse/planes.js';
  import { m } from '#lib/paraglide/messages.js';
</script>

<PortalPageGate page="sessions">
  <SessionsBrowser
    plane={portalPlane}
    heading={(team) =>
      team
        ? { title: m.portal_sessions_title_team(), subtitle: m.portal_sessions_subtitle_team({ workspace: team }) }
        : { title: m.portal_sessions_title(), subtitle: m.portal_sessions_subtitle() }} />
</PortalPageGate>
