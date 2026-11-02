<script lang="ts">
  import { getLocale, setLocale, assertIsLocale, locales } from '#lib/paraglide/runtime.js';
  import { m } from '#lib/paraglide/messages.js';
  import Icon from '#lib/components/Icon.svelte';

  // Autonyms — each language shown in its own name, independent of the active
  // UI locale. Add a line here when a locale is added to project.inlang.
  const LOCALE_LABELS: Record<string, string> = {
    en: 'English',
    fr: 'Français',
  };

  // SSR reads the request locale from the async-local context the server hook
  // set; the client reads it from the PARAGLIDE_LOCALE cookie. Both agree.
  let current = $state(getLocale());

  function onChange(event: Event) {
    const next = (event.currentTarget as HTMLSelectElement).value;
    if (next !== current) {
      // Persists the choice in the cookie and reloads so SSR re-renders in the
      // new locale (no URL change — the tenant prefix is untouched).
      setLocale(assertIsLocale(next));
    }
  }
</script>

<label
  class="flex items-center gap-1.5 px-2 py-1.5 rounded-lg bg-(--bg-primary) border border-(--border) text-(--text-secondary) hover:text-(--text-primary) transition-colors"
  title={m.locale_selector_label()}
>
  <Icon name="globe" size="sm" tone="neutral" />
  <select
    value={current}
    onchange={onChange}
    aria-label={m.locale_selector_label()}
    class="bg-transparent text-sm text-(--text-primary) focus:outline-hidden cursor-pointer"
  >
    {#each locales as loc (loc)}
      <option value={loc} class="bg-(--bg-primary) text-(--text-primary)">
        {LOCALE_LABELS[loc] ?? loc}
      </option>
    {/each}
  </select>
</label>
