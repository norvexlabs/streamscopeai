<script lang="ts">
  import { enhance } from '$app/forms';
  import BrandHeader from '#lib/components/BrandHeader.svelte';
  import SourceLink from '#lib/components/SourceLink.svelte';
  import { m } from '#lib/paraglide/messages.js';

  type FormState = {
    error?: string;
    slug?: string;
  };

  interface Props {
    variant: 'admin' | 'portal';
    form?: FormState | null;
  }

  let { variant, form }: Props = $props();
  let slug = $state('');

  const subtitle = $derived(variant === 'admin' ? m.login_subtitle_admin() : m.login_subtitle_portal());
  const orgLabel = $derived(m.login_organization());
</script>

<div class="min-h-screen flex items-center justify-center bg-(--bg-primary)">
  <div class="w-full max-w-sm">
    <BrandHeader {subtitle} />

    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-6">
      <h2 class="text-lg font-semibold text-(--text-primary) mb-6">{m.login_sign_in()}</h2>

      {#if form?.error}
        <div class="mb-4 p-3 rounded-lg bg-(--error-bg) border border-(--error)/20 text-sm text-(--error)">
          {form.error}
        </div>
      {/if}

      <form method="POST" use:enhance>
        <div class="space-y-4">
          <div>
            <label for="slug" class="block text-sm font-medium text-(--text-secondary) mb-1.5">{orgLabel}</label>
            <!-- svelte-ignore a11y_autofocus -->
            <input id="slug" name="slug" type="text" required autofocus
              bind:value={slug}
              class="w-full px-3 py-2 rounded-lg bg-(--bg-primary) border border-(--border)
                     text-(--text-primary) text-sm
                     focus:outline-hidden focus:border-(--accent)
                     transition-colors"
              placeholder={m.login_org_slug_placeholder()} />
          </div>
          <button type="submit"
            class="w-full py-2.5 rounded-lg bg-(--accent) text-(--accent-fg) text-sm font-medium
                   hover:bg-(--accent-hover) transition-colors">
            {m.login_continue()}
          </button>
        </div>
      </form>
    </div>
    <div class="mt-6"><SourceLink /></div>
  </div>
</div>
