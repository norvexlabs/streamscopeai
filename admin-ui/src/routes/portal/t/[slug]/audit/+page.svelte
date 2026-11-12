<script lang="ts">
  // Portal — Requests: the shared audit log, over the caller's own rows or,
  // where the header workspace shares with its members, the team's. The
  // server decides whose rows; the plane only says which workspace is viewed.
  import AuditBrowser from '#lib/components/browse/AuditBrowser.svelte';
  import PortalPageGate from '#lib/components/portal/PortalPageGate.svelte';
  import { portalPlane } from '#lib/browse/planes.js';
  import { m } from '#lib/paraglide/messages.js';
</script>

<PortalPageGate page="requests">
  <AuditBrowser
    plane={portalPlane}
    heading={(team) =>
      team
        ? { title: m.portal_audit_title_team(), subtitle: m.portal_audit_subtitle_team({ workspace: team }) }
        : { title: m.portal_audit_title(), subtitle: m.portal_audit_subtitle() }} />
</PortalPageGate>
