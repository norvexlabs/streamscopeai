<script lang="ts">
  /**
   * CLI-provisioning consent UI: "Streamscope CLI on <device> wants to
   * provision AI clients as <you>". The +page.server.ts loads the preview
   * server-side; Approve / Deny submit through SvelteKit form actions — no
   * client-side state, no JS required.
   */
  import ConsentShell from '#lib/components/portal/ConsentShell.svelte';
  import ConsentError from '#lib/components/portal/ConsentError.svelte';
  import { m } from '#lib/paraglide/messages.js';

  let { data, form } = $props();
</script>

<svelte:head>
  <title>{m.portal_cli_authorize_title()}</title>
</svelte:head>

<ConsentShell title={m.portal_cli_authorize_title()} slug={data.slug}>
    {#if data.error}
      <ConsentError error={data.error} errorCode={data.errorCode} />
    {:else if data.preview && data.consent}
      <div class="space-y-4">
        <p class="text-sm text-(--text-primary) leading-snug">
          {m.portal_cli_authorize_intro_the()} <span class="font-semibold">ssai</span> {m.portal_cli_authorize_intro_cli()}<!-- i18n-ok: CLI command name -->
          {#if data.preview.device_name}
            {m.portal_cli_authorize_intro_on()} <span class="font-semibold">{data.preview.device_name}</span>
          {/if}
          {m.portal_cli_authorize_intro_provision()}
          <span class="font-semibold">{data.preview.user_email}</span>.
        </p>
        <div class="bg-(--bg-primary) border border-(--border) rounded-lg p-3 text-xs text-(--text-secondary) space-y-1">
          <div>
            <span class="font-medium text-(--text-primary)">{m.portal_consent_it_can()}</span>
            {m.portal_cli_authorize_can_detail()}
          </div>
          <div>
            <span class="font-medium text-(--text-primary)">{m.portal_consent_it_cannot()}</span>
            {m.portal_cli_authorize_cannot_detail()}
          </div>
          <div class="break-all">
            <span class="font-medium text-(--text-primary)">{m.portal_consent_returns_to()}</span>
            <code class="font-mono">{data.consent.redirect_uri}</code> {m.portal_cli_authorize_this_machine()}
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
          <input type="hidden" name="scope" value={data.consent.scope} />
          {#if data.consent.device_name}
            <input type="hidden" name="device_name" value={data.consent.device_name} />
          {/if}
          <button
            type="submit"
            class="w-full px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium transition-colors">
            {m.portal_consent_approve()}
          </button>
        </form>

        <form method="POST" action="?/deny">
          <input type="hidden" name="client_id" value={data.consent.client_id} />
          <input type="hidden" name="redirect_uri" value={data.consent.redirect_uri} />
          <input type="hidden" name="state" value={data.consent.state} />
          <input type="hidden" name="code_challenge" value={data.consent.code_challenge} />
          <input
            type="hidden"
            name="code_challenge_method"
            value={data.consent.code_challenge_method} />
          <input type="hidden" name="scope" value={data.consent.scope} />
          <button
            type="submit"
            class="w-full px-4 py-2 rounded-lg border border-(--border) text-sm font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors">
            {m.portal_consent_deny()}
          </button>
        </form>

        <p class="text-xs text-(--text-secondary) text-center">
          {m.portal_cli_authorize_footer_before()} <code class="font-mono">ssai logout</code>
          {m.portal_cli_authorize_footer_after()}
        </p>
      </div>
    {/if}
</ConsentShell>
