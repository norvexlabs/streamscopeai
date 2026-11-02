<script lang="ts">
  // Portal — one session's conversation: the caller's own, or a teammate's in
  // the workspace named by `?workspace_id` where it shares. Ownership is
  // checked server-side (404 otherwise).
  import SessionView from '#lib/components/browse/SessionView.svelte';
  import { portalPlane } from '#lib/browse/planes.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();
</script>

<SessionView plane={portalPlane} sessionId={params.id} />
