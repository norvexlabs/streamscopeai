<script lang="ts">
  import { enhance } from '$app/forms';
  import '../../../app.css';
  import BrandHeader from '#lib/components/BrandHeader.svelte';
  import SourceLink from '#lib/components/SourceLink.svelte';

  let { data, form } = $props();
  let loading = $state(false);
</script>

<div class="min-h-screen flex items-center justify-center bg-(--bg-primary)">
  <div class="w-full max-w-sm">
    <BrandHeader subtitle="Accept Invitation" />

    {#if !data.invite?.valid}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6 text-center">
        <p class="text-(--text-primary) font-medium mb-2">Invalid or expired invite</p>
        <p class="text-sm text-(--text-secondary)">This invite link is no longer valid.</p>
      </div>
    {:else}
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6">
        <h2 class="text-lg font-semibold text-(--text-primary) mb-1">
          Join {data.invite.tenant_name}
        </h2>
        <p class="text-sm text-(--text-secondary) mb-6">
          You've been invited as <span class="font-medium text-(--text-primary)">{data.invite.role}</span>
        </p>

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
              <label for="email" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Email</label>
              <input id="email" name="email" type="email" required autocomplete="email"
                value={form?.email || data.invite.email || ''}
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                       text-(--text-primary) text-sm
                       focus:outline-hidden focus:border-(--accent)
                       transition-colors" />
            </div>
            <div>
              <label for="password" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Password</label>
              <input id="password" name="password" type="password" required autocomplete="new-password"
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                       text-(--text-primary) text-sm
                       focus:outline-hidden focus:border-(--accent)
                       transition-colors" />
            </div>
            <div>
              <label for="confirm" class="block text-sm font-medium text-(--text-secondary) mb-1.5">Confirm password</label>
              <input id="confirm" name="confirm" type="password" required autocomplete="new-password"
                class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                       text-(--text-primary) text-sm
                       focus:outline-hidden focus:border-(--accent)
                       transition-colors" />
            </div>
            <button type="submit" disabled={loading}
              class="w-full py-2.5 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
                     hover:bg-(--accent-hover) transition-colors
                     disabled:opacity-50 disabled:cursor-not-allowed">
              {#if loading}Creating account…{:else}Create Account{/if}
            </button>
          </div>
        </form>
      </div>
    {/if}
    <div class="mt-6"><SourceLink /></div>
  </div>
</div>
