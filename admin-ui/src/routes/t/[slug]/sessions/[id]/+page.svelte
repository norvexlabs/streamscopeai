<script lang="ts">
  // Console — one session's conversation.
  import SessionView from '#lib/components/browse/SessionView.svelte';
  import { consolePlane } from '#lib/browse/planes.js';
  import type { PageProps } from './$types';

  let { params }: PageProps = $props();
</script>

<SessionView plane={consolePlane} sessionId={params.id} />
