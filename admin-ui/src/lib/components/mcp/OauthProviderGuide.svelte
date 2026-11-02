<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import Copyable from '#lib/components/Copyable.svelte';
  import Icon from '#lib/components/Icon.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import {
    detectProviderRecipe,
    genericRecipe,
    type OauthProviderRecipe,
  } from '#lib/mcp/oauthProviderRecipes.js';

  interface Props {
    /** Current upstream URL — drives provider auto-detection. */
    upstreamUrl: string;
    /** Current issuer URL — detection fallback. */
    issuerUrl: string;
    /** Server-derived OAuth redirect/callback URI (null while loading/unset). */
    redirectUri: string | null;
    /** Gateway homepage URL for the provider's "Homepage URL" field. */
    homepage: string | null;
    /**
     * Fill a Scopes field with the recipe's suggested scopes. Optional — when
     * absent (e.g. the adopt flow, which carries the catalog entry's scopes),
     * the scopes are shown but the "Use these" button is hidden.
     */
    onfillScopes?: (scopes: string[]) => void;
  }

  let { upstreamUrl, issuerUrl, redirectUri, homepage, onfillScopes }: Props = $props();

  // Seed-backed recipes, fetched once. Empty until loaded → the guide renders
  // nothing (the modal's manual OAuth fields still work). The `loaded` flag
  // gates the fetch on "have we fetched", NOT on `recipes.length` — an empty
  // seed (missing/malformed file) is a supported response, and re-checking the
  // length would re-fire the effect on every empty assignment (fetch loop).
  let recipes = $state<OauthProviderRecipe[]>([]);
  let loaded = $state(false);
  $effect(() => {
    if (loaded) return;
    loaded = true;
    adminApi.GET('/api/v1/admin/mcp/oauth-provider-recipes').then(({ data }) => {
      if (data) recipes = data.recipes;
    });
  });

  // Collapsed by default: the guide is reference material, kept out of the way
  // so it doesn't swamp the OAuth input fields. One click reveals it.
  let open = $state(false);

  // The gateway's origin, derived from the redirect URI when tenant settings
  // don't carry an explicit public URL — so the "Homepage URL" field always
  // has a concrete, copyable value (it's cosmetic on the provider side).
  function originOf(url: string | null): string | null {
    if (!url) return null;
    try {
      return new URL(url).origin;
    } catch {
      return null;
    }
  }
  const homepageValue = $derived(homepage ?? originOf(redirectUri));

  // `null` = follow auto-detection; otherwise a pinned recipe id.
  let override = $state<string | null>(null);
  const detected = $derived(detectProviderRecipe(recipes, upstreamUrl, issuerUrl));
  const fallback = $derived(genericRecipe(recipes));
  const recipe = $derived<OauthProviderRecipe | null>(
    (override ? recipes.find((r) => r.id === override) : detected) ?? fallback,
  );
  const selectValue = $derived(override ?? 'auto');
</script>

{#if recipe}
  <div class="rounded-lg border border-(--border) bg-(--bg-primary)">
    <button
      type="button"
      data-testid="oauth-guide-toggle"
      aria-expanded={open}
      onclick={() => (open = !open)}
      class="flex w-full items-center justify-between gap-2 px-3 py-2 text-left">
      <span class="flex items-center gap-1.5 text-sm font-medium text-(--text-primary)">
        <Icon name="book" size="sm" tone="info" />
        How to create the OAuth app{detected ? ` on ${detected.label}` : ''}
      </span>
      <Icon name={open ? 'chevronUp' : 'chevronDown'} size="sm" tone="neutral" />
    </button>

    {#if open}
      <div class="space-y-3 border-t border-(--border) px-3 py-3">
        <div class="flex flex-wrap items-center justify-between gap-2">
          <p class="text-xs text-(--text-secondary)">
            {#if recipe.supports_dcr}
              Try <strong>Register client automatically</strong> above first; if it fails,
              register the app by hand with the values below.
            {:else}
              {recipe.label} needs a hand-registered app. Use the values below.
            {/if}
          </p>
          <label class="flex items-center gap-1.5 text-xs text-(--text-secondary)">
            Provider
            <SelectInput
              fluid={false}
              value={selectValue}
              onchange={(e: Event) => {
                const v = (e.currentTarget as HTMLSelectElement).value;
                override = v === 'auto' ? null : v;
              }}>
              <option value="auto">Auto{detected ? ` — ${detected.label}` : ''}</option>
              {#each recipes as r (r.id)}
                <option value={r.id}>{r.label}</option>
              {/each}
            </SelectInput>
          </label>
        </div>

        {#if recipe.console_url}
          <a
            href={recipe.console_url}
            target="_blank"
            rel="noopener noreferrer"
            class="inline-flex items-center gap-1.5 rounded-lg border border-(--border) px-3 py-1.5 text-sm text-(--text-primary) transition-colors hover:bg-(--bg-elevated)">
            Open {recipe.label} console
            <Icon name="externalLink" size="sm" tone="neutral" />
          </a>
        {/if}

        <!-- Field-by-field map: the provider's form field → the value to paste. -->
        <div class="space-y-2">
          {#each recipe.fields as field (field.label)}
            <div class="grid grid-cols-[minmax(0,9rem)_1fr] items-start gap-2 text-xs">
              <span class="pt-0.5 font-medium text-(--text-secondary)">{field.label}</span>
              <div class="min-w-0 break-all">
                {#if field.value.kind === 'redirect'}
                  {#if redirectUri}
                    <Copyable value={redirectUri} block />
                  {:else}
                    <span class="italic text-(--text-secondary) break-normal">
                      Set your tenant’s public URLs (Settings → Defaults) to see this value.
                    </span>
                  {/if}
                {:else if field.value.kind === 'homepage'}
                  {#if homepageValue}
                    <Copyable value={homepageValue} block />
                  {:else}
                    <span class="italic text-(--text-secondary) break-normal">
                      Set your tenant’s public URL (Settings → Defaults).
                    </span>
                  {/if}
                {:else if field.value.kind === 'literal'}
                  <Copyable value={field.value.text} block />
                {:else}
                  <span class="text-(--text-primary) break-normal">{field.value.text}</span>
                {/if}
                {#if field.hint}
                  <div class="mt-0.5 text-(--text-tertiary) break-normal">{field.hint}</div>
                {/if}
              </div>
            </div>
          {/each}
        </div>

        <ol class="list-inside list-decimal space-y-1 text-xs text-(--text-secondary)">
          {#each recipe.steps as step (step)}
            <li>{step}</li>
          {/each}
        </ol>

        {#if recipe.suggested_scopes && recipe.suggested_scopes.length > 0}
          <div class="flex flex-wrap items-center gap-2 text-xs">
            <span class="text-(--text-secondary)">Suggested scopes:</span>
            <code class="text-(--text-primary)">{recipe.suggested_scopes.join(', ')}</code>
            {#if onfillScopes}
              <button
                type="button"
                onclick={() => onfillScopes?.(recipe?.suggested_scopes ?? [])}
                class="rounded-sm border border-(--border) px-2 py-0.5 text-(--text-secondary) transition-colors hover:bg-(--bg-elevated) hover:text-(--text-primary)">
                Use these
              </button>
            {/if}
          </div>
        {/if}
      </div>
    {/if}
  </div>
{/if}
