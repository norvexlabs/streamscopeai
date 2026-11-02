<script lang="ts">
  /**
   * Spec-OAuth consent UI.
   *
   * The +page.server.ts loads the preview server-side; this component just
   * renders the "X wants to access Y" copy and the Approve / Deny form. Both
   * actions submit back through SvelteKit form actions — no client-side
   * state, no JS-required.
   */
  import ConsentShell from '#lib/components/portal/ConsentShell.svelte';
  import ConsentError from '#lib/components/portal/ConsentError.svelte';
  import { m } from '#lib/paraglide/messages.js';

  let { data, form } = $props();

  /**
   * Human-readable label for a granted scope.
   *
   * A consent screen exists so the subject can decide, and `mcp:tools.call`
   * does not tell them what they are agreeing to. An unrecognised scope still
   * renders — as an explicit "additional permission" rather than being dropped,
   * since silently hiding part of a grant is worse than describing it vaguely.
   */
  function scopeLabel(scope: string): string {
    switch (scope) {
      case 'mcp:invoke':
        return m.portal_mcp_scope_invoke();
      case 'mcp:tools.read':
        return m.portal_mcp_scope_tools_read();
      case 'mcp:tools.call':
        return m.portal_mcp_scope_tools_call();
      case 'mcp:resources.read':
        return m.portal_mcp_scope_resources_read();
      case 'mcp:prompts.read':
        return m.portal_mcp_scope_prompts_read();
      default:
        return m.portal_mcp_scope_unknown();
    }
  }

  // `preview` is a tagged union: the load function bounces the `redirect`
  // disposition before it ever reaches this component, but the type still
  // carries both arms, so narrow on the discriminant once and render from that.
  const preview = $derived(
    data.preview && data.preview.disposition === 'ok' ? data.preview : null
  );

  const grantedScopes = $derived(
    preview ? [...new Set(preview.scope.split(/\s+/).filter((s: string) => s.length > 0))] : []
  );
</script>

<svelte:head>
  <title>{m.portal_mcp_authorize_title()}</title>
</svelte:head>

<ConsentShell title={m.portal_mcp_authorize_title()} slug={data.slug}>
    {#if data.error}
      <ConsentError error={data.error} errorCode={data.errorCode} />
    {:else if preview && data.consent}
      <div class="space-y-4">
        <p class="text-sm text-(--text-primary) leading-snug">
          <span class="font-semibold">{preview.client_name}</span>
          {m.portal_mcp_authorize_intro_connector()}
          <span class="font-semibold">{preview.virtual_server_name}</span>
          (<code class="bg-(--bg-primary) px-1.5 py-0.5 rounded-sm text-(--text-primary) font-mono">/mcp/{preview.virtual_server_slug}</code>).
        </p>
        <div class="bg-(--bg-primary) border border-(--border) rounded-lg p-3 text-xs text-(--text-secondary) space-y-1">
          <div>
            <span class="font-medium text-(--text-primary)"
              >{m.portal_mcp_authorize_grants_label()}</span>
            <ul class="mt-1 space-y-0.5 list-disc list-inside">
              {#each grantedScopes as scope (scope)}
                <li>
                  {scopeLabel(scope)}
                  <code class="font-mono text-(--text-tertiary)">({scope})</code>
                </li>
              {/each}
            </ul>
          </div>
          <div class="break-all">
            <span class="font-medium text-(--text-primary)">{m.portal_consent_redirects_to()}</span>
            <code class="font-mono">{data.consent.redirect_uri}</code>
          </div>
        </div>

        {#if form?.error}
          <div class="bg-(--error)/10 border border-(--error) text-(--error) p-2 rounded-lg text-xs">
            {form.error}
          </div>
        {/if}

        <form method="POST" action="?/approve" class="space-y-3">
          <input type="hidden" name="client_id" value={data.consent.client_id} />
          <input type="hidden" name="redirect_uri" value={data.consent.redirect_uri} />
          <input type="hidden" name="state" value={data.consent.state} />
          <input type="hidden" name="code_challenge" value={data.consent.code_challenge} />
          <input
            type="hidden"
            name="code_challenge_method"
            value={data.consent.code_challenge_method} />
          <input type="hidden" name="resource" value={data.consent.resource} />
          <input type="hidden" name="scope" value={data.consent.scope} />
          <button
            type="submit"
            class="w-full px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium transition-colors">
            {m.portal_consent_approve()}
          </button>
        </form>

        <form method="POST" action="?/deny">
          <!-- Deny re-validates the FULL params bundle (anti-phishing), so it
               needs the same fields the approve form posts. -->
          <input type="hidden" name="client_id" value={data.consent.client_id} />
          <input type="hidden" name="redirect_uri" value={data.consent.redirect_uri} />
          <input type="hidden" name="state" value={data.consent.state} />
          <input type="hidden" name="code_challenge" value={data.consent.code_challenge} />
          <input
            type="hidden"
            name="code_challenge_method"
            value={data.consent.code_challenge_method} />
          <input type="hidden" name="resource" value={data.consent.resource} />
          <input type="hidden" name="scope" value={data.consent.scope} />
          <button
            type="submit"
            class="w-full px-4 py-2 rounded-lg border border-(--border) text-sm font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors">
            {m.portal_consent_deny()}
          </button>
        </form>

        <p class="text-xs text-(--text-secondary) text-center">
          {m.portal_mcp_authorize_footer()}
        </p>
      </div>
    {/if}
</ConsentShell>
