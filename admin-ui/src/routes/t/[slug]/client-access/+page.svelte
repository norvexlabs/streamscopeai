<script lang="ts">
  // Portal & clients: the profiles that decide, per workspace, which clients
  // the portal and the CLI offer and what the developers' sandbox may reach.
  import Page from '#lib/components/page/Page.svelte';
  import ProfilesManager from '#lib/components/policy/ProfilesManager.svelte';
</script>

<Page
  title="Portal & clients"
  subtitle="Per workspace: the clients the portal and the CLI offer, and what the developers' sandbox may reach besides the gateway."
>
  <ProfilesManager kind="client_access" activate />
</Page>
