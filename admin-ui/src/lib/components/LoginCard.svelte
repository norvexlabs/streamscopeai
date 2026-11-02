<script lang="ts">
  import { enhance } from '$app/forms';
  import { page } from '$app/state';
  import BrandHeader from '#lib/components/BrandHeader.svelte';
  import SourceLink from '#lib/components/SourceLink.svelte';
  import { m } from '#lib/paraglide/messages.js';
  import { forcesAccountChooser, parseLoginFailure } from '#lib/oidc-login-errors.js';

  type Tenant = {
    slug: string;
    name: string;
    auth_mode?: string;
  };

  type FormState = {
    error?: string;
    email?: string;
  };

  interface Props {
    variant: 'admin' | 'portal';
    tenant?: Tenant;
    notFound?: boolean;
    /** The gateway could not be asked about the tenant — an outage, not a missing tenant. */
    unavailable?: boolean;
    form?: FormState | null;
  }

  let { variant, tenant, notFound = false, unavailable = false, form }: Props = $props();

  let loading = $state(false);

  const subtitle = $derived(variant === 'admin' ? m.login_subtitle_admin() : m.login_subtitle_portal());
  const notFoundLabel = $derived(variant === 'admin' ? m.login_tenant_not_found() : m.login_organization_not_found());
  // `select` forces the organization-selection form: without it the landing
  // loader bounces straight back to the remembered tenant's login, so the
  // "back to selection" link would be a no-op after a mistyped slug.
  const backHref = $derived(variant === 'admin' ? '/login?select=1' : '/portal/login?select=1');
  // Preserve `return_to=/portal/...` (e.g. spec-OAuth consent page)
  // across the SSO redirect. The OIDC begin endpoint validates it and folds
  // it into its one-time state cookie, then the callback honors it after
  // token exchange.
  const returnTo = $derived(page.url.searchParams.get('return_to') ?? '');
  // The OIDC callback authenticates this exact plane and never falls back to the
  // other one: an admin login that isn't a console account is denied here (with
  // the banner below), not silently redirected into the portal. `plane` carries
  // that intent through the begin endpoint's one-time state cookie.
  // Why the last sign-in did not complete — a closed vocabulary, so the query
  // string can only ever select one of the fixed sentences below.
  const failure = $derived(parseLoginFailure(page.url.searchParams.get('error')));
  // A "switch account" landing carries `?prompt=select_account`, forwarded to
  // the OIDC begin endpoint so the IdP shows its account chooser instead of
  // silently reusing its session. Only an access denial forces the same chooser:
  // it is the one failure another account can fix. The begin endpoint
  // whitelists the value; a plain login stays canonical silent SSO.
  const promptParam = $derived(page.url.searchParams.get('prompt') ?? '');
  const prompt = $derived(promptParam || (forcesAccountChooser(failure) ? 'select_account' : ''));
  const oidcHref = $derived(
    `/auth/oidc/login?tenant=${encodeURIComponent(tenant?.slug ?? '')}` +
    `&plane=${variant}` +
    (returnTo ? `&return_to=${encodeURIComponent(returnTo)}` : '') +
    (prompt ? `&prompt=${encodeURIComponent(prompt)}` : ''),
  );
  const failureLabel = $derived.by(() => {
    switch (failure) {
      case 'access_denied':
        return variant === 'admin' ? m.login_error_no_console_access() : m.login_error_no_portal_access();
      case 'email_missing':
        return m.login_error_email_missing();
      case 'email_unverified':
        return m.login_error_email_unverified();
      case 'idp_refused':
        return m.login_error_idp_refused();
      case 'sign_in_failed':
        return m.login_error_sign_in_failed();
      case 'unavailable':
        return m.login_error_unavailable();
      default:
        return '';
    }
  });
</script>

<div class="min-h-screen flex items-center justify-center bg-(--bg-primary)">
  <div class="w-full max-w-sm">
    <BrandHeader subtitle={tenant ? tenant.name : subtitle} />

    {#if unavailable}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6 text-center">
        <p class="text-(--text-secondary)">{m.login_error_unavailable()}</p>
      </div>
    {:else if notFound}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6 text-center">
        <p class="text-(--text-secondary)">{notFoundLabel}</p>
        <a href={backHref} class="text-(--accent) text-sm mt-2 inline-block">{m.login_back_to_login()}</a>
      </div>
    {:else if tenant?.auth_mode === 'oidc'}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6">
        <h2 class="text-lg font-semibold text-(--text-primary) mb-6">{tenant.name}</h2>
        {#if failureLabel}
          <div class="mb-4 p-3 rounded-lg bg-(--error-bg) border border-(--error)/20 text-sm text-(--error)">
            {failureLabel}
          </div>
        {/if}
        <a href={oidcHref} data-sveltekit-reload
          class="block w-full py-2.5 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium text-center
                 hover:bg-(--accent-hover) transition-colors">
          {m.login_sign_in_with_sso()}
        </a>
      </div>
    {:else}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6">
        <h2 class="text-lg font-semibold text-(--text-primary) mb-6">
          {#if tenant?.name && tenant.slug !== 'system'}
            {tenant.name}
          {:else}
            {m.login_sign_in()}
          {/if}
        </h2>

        {#if form?.error}
          <div class="mb-4 p-3 rounded-lg bg-(--error-bg) border border-(--error)/20 text-sm text-(--error)">
            {form.error}
          </div>
        {/if}

        <form method="POST" use:enhance={() => {
          loading = true;
          return async ({ update }) => { loading = false; await update(); };
        }}>
          <div class="space-y-4">
            <div>
              <label for="email" class="block text-sm font-medium text-(--text-secondary) mb-1.5">{m.login_email()}</label>
              <input id="email" name="email" type="email" required autocomplete="email"
                value={form?.email || ''}
                placeholder={m.login_email_placeholder()}
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                       text-(--text-primary) text-sm
                       focus:outline-hidden focus:border-(--accent)
                       transition-colors" />
            </div>
            <div>
              <label for="password" class="block text-sm font-medium text-(--text-secondary) mb-1.5">{m.login_password()}</label>
              <input id="password" name="password" type="password" required autocomplete="current-password"
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                       text-(--text-primary) text-sm
                       focus:outline-hidden focus:border-(--accent)
                       transition-colors" />
            </div>
            <button type="submit" disabled={loading}
              class="w-full py-2.5 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
                     hover:bg-(--accent-hover) transition-colors
                     disabled:opacity-50 disabled:cursor-not-allowed">
              {#if loading}{m.login_signing_in()}{:else}{m.login_sign_in()}{/if}
            </button>
          </div>
        </form>
      </div>
    {/if}
    <div class="mt-6"><SourceLink /></div>
  </div>
</div>
