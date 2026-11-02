<script lang="ts">
  import McpConnectionsSection from '#lib/components/portal/McpConnectionsSection.svelte';
  import Page from '#lib/components/page/Page.svelte';
  import { m } from '#lib/paraglide/messages.js';
</script>

<Page title={m.portal_mcp_connections_title()} subtitle={m.portal_mcp_connections_description()}>
  <McpConnectionsSection />
</Page>
