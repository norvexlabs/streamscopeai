<script lang="ts">
  // Console — Sessions: the shared session list over the whole tenant.
  import SessionsBrowser from '#lib/components/browse/SessionsBrowser.svelte';
  import { consolePlane } from '#lib/browse/planes.js';
  import { m } from '#lib/paraglide/messages.js';
</script>

<SessionsBrowser plane={consolePlane} heading={() => ({ title: m.browse_sessions_title(), subtitle: m.browse_sessions_subtitle() })} />
