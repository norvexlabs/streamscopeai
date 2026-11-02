<script lang="ts">
  /**
   * Device-grant approval UI (RFC 8628): the user confirms the code their
   * terminal shows, then approves or denies. The +page.server.ts previews
   * the code server-side; Approve / Deny submit through SvelteKit form
   * actions — no client-side state, no JS required.
   */
  import ConsentShell from '#lib/components/portal/ConsentShell.svelte';
  import ConsentError from '#lib/components/portal/ConsentError.svelte';
  import { m } from '#lib/paraglide/messages.js';

  let { data, form } = $props();
</script>

<svelte:head>
  <title>{m.portal_cli_device_head_title()}</title>
</svelte:head>

<ConsentShell title={m.portal_cli_device_title()} slug={data.slug}>
  {#if form?.decided === 'approved'}
    <div data-testid="device-approved" class="space-y-3">
      <div class="bg-(--success-bg) border border-(--success-border) text-(--success) p-3 rounded-lg text-sm">
        {m.portal_cli_device_approved_message()}
      </div>
      <p class="text-xs text-(--text-secondary) text-center">
        {m.portal_cli_device_approved_footer_before()}
        <code class="font-mono">ssai logout</code>{m.portal_cli_device_approved_footer_after()}
      </p>
    </div>
  {:else if form?.decided === 'denied'}
    <div data-testid="device-denied" class="bg-(--bg-primary) border border-(--border) text-(--text-secondary) p-3 rounded-lg text-sm">
      {m.portal_cli_device_denied_message()}
    </div>
  {:else if data.preview}
    <div class="space-y-4">
      <p class="text-sm text-(--text-primary) leading-snug">
        {m.portal_cli_device_intro_a_device()}
        {#if data.preview.device_name}
          {m.portal_cli_device_intro_claiming()} <span class="font-semibold">{data.preview.device_name}</span>
        {/if}
        {m.portal_cli_device_intro_provision()}
        <span class="font-semibold">{data.preview.user_email}</span>.
      </p>

      <div class="bg-(--bg-primary) border border-(--border) rounded-lg p-4 text-center">
        <div class="text-[10px] uppercase tracking-wide text-(--text-secondary) mb-1">{m.portal_cli_device_code_label()}</div>
        <div data-testid="device-user-code" class="text-2xl font-mono font-semibold text-(--text-primary) tracking-widest">
          {data.preview.user_code}
        </div>
      </div>

      <p class="text-xs text-(--text-secondary)">
        {m.portal_cli_device_warning_before()} <code class="font-mono">ssai login</code> {m.portal_cli_device_warning_after()}
      </p>

      {#if form?.error}
        <div class="bg-(--error)/10 border border-(--error) text-(--error) p-2 rounded-lg text-xs">
          {form.error}
        </div>
      {/if}

      <form method="POST" action="?/approve">
        <input type="hidden" name="user_code" value={data.preview.user_code} />
        <button
          data-testid="device-approve"
          type="submit"
          class="w-full px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium transition-colors">
          {m.portal_consent_approve()}
        </button>
      </form>
      <form method="POST" action="?/deny">
        <input type="hidden" name="user_code" value={data.preview.user_code} />
        <button
          data-testid="device-deny"
          type="submit"
          class="w-full px-4 py-2 rounded-lg border border-(--border) text-sm font-medium text-(--text-secondary) hover:text-(--text-primary) hover:bg-(--bg-elevated) transition-colors">
          {m.portal_consent_deny()}
        </button>
      </form>
    </div>
  {:else}
    <div class="space-y-4">
      {#if data.error}
        <ConsentError error={data.error} errorCode={data.errorCode} />
      {/if}
      {#if data.slug}
        <p class="text-sm text-(--text-primary) leading-snug">
          {m.portal_cli_device_enter_code_before()}
          <code class="font-mono">ssai login --device</code>.
        </p>
        <form method="GET" class="space-y-3">
          <input
            data-testid="device-code-input"
            type="text"
            name="user_code"
            value={data.userCode ?? ''}
            placeholder="XXXX-XXXX"
            autocomplete="off"
            spellcheck="false"
            class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-center font-mono text-lg tracking-widest text-(--text-primary) placeholder-(--text-secondary) focus:outline-hidden focus:border-(--accent)" />
          <button
            data-testid="device-code-submit"
            type="submit"
            class="w-full px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) rounded-lg text-sm font-medium transition-colors">
            {m.portal_cli_device_continue()}
          </button>
        </form>
      {/if}
    </div>
  {/if}
</ConsentShell>
