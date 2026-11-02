<script lang="ts">
  // What a transport means for the URL an operator types and the credential it
  // rides with. Rendered under the transport picker on both the create wizard
  // and a server's settings, which must describe it identically.
  let { transport }: { transport: string } = $props();
</script>

<p class="mt-1 text-xs text-(--text-secondary)">
  How requests reach this server — separate from the protocol, which decides the request body.
  {#if transport === 'azure_openai_entra'}
    Azure OpenAI on its v1 API, authenticated with a Microsoft Entra ID token. Paste the client-credentials
    document as the credential: <code>{'{'}"tenant_id", "client_id", "client_secret"{'}'}</code>, optionally with
    <code>scope</code> and <code>authority</code>.
  {:else if transport.startsWith('azure_openai')}
    Azure OpenAI on its v1 API: requests go to <code>{'{'}URL{'}'}/openai/v1/…</code> with the key in an
    <code>api-key</code> header. Use the resource URL (e.g. <code>https://YOUR-RESOURCE.openai.azure.com</code>),
    and give each model its <em>deployment</em> name.
  {:else if transport === 'aws_bedrock'}
    Amazon Bedrock's OpenAI-compatible surface: requests go to <code>{'{'}URL{'}'}/openai/v1/…</code> with a
    Bedrock API key as the bearer token. Use the regional runtime endpoint
    (e.g. <code>https://bedrock-runtime.us-east-1.amazonaws.com</code>), and name each model by its
    cross-Region inference profile (e.g. <code>us.openai.gpt-5.6-sol</code>).
  {:else if transport === 'google_vertex'}
    Google Vertex AI, addressed from a project and location — use
    <code>https://LOCATION-aiplatform.googleapis.com/v1/projects/PROJECT/locations/LOCATION</code> as the URL.
    Paste the service-account JSON key as the credential; the gateway exchanges it for an access token.
    Vertex publishes no model list the gateway can read, so add models by name.
  {:else}
    Standard endpoints take the canonical <code>/v1/…</code> paths with a bearer token.
  {/if}
</p>
