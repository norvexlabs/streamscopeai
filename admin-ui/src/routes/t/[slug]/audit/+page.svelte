<script lang="ts">
  // Console — Audit: the shared audit log over the whole tenant.
  import AuditBrowser from '#lib/components/browse/AuditBrowser.svelte';
  import { consolePlane } from '#lib/browse/planes.js';
  import { m } from '#lib/paraglide/messages.js';
</script>

<AuditBrowser plane={consolePlane} heading={() => ({ title: m.browse_audit_title(), subtitle: m.browse_audit_subtitle() })} />
