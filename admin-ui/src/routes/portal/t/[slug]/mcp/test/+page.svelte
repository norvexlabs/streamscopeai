<script lang="ts">
  import McpTestSection from '#lib/components/portal/McpTestSection.svelte';
  import Page from '#lib/components/page/Page.svelte';
  import { m } from '#lib/paraglide/messages.js';
</script>

<Page title={m.portal_mcp_test_title()} subtitle={m.portal_mcp_test_intro()}>

  <McpTestSection />
</Page>
