<script lang="ts">
  // Standard page shell — owns the title/subtitle/actions header + optional
  // filter strip, then renders the page body. The route layout already provides
  // the padded, full-width content area (`<main class="flex-1 p-8">`), so a page
  // MUST NOT add its own width/padding wrapper (`max-w-*` / `mx-auto` / `p-6`) —
  // rendering through this shell (or <TabbedPage>, which composes it) keeps that
  // structural. Enforced by the `lint-page-container.sh` lint.
  import type { Snippet } from 'svelte';

  let {
    title,
    subtitle,
    description,
    actions,
    filterBar,
    children,
  }: {
    title: string;
    /** Plain-text subtitle rendered under the title. */
    subtitle?: string;
    /** Rich description snippet — use when the subtitle needs inline HTML
     *  (links, code spans). Mutually exclusive with `subtitle`. */
    description?: Snippet;
    /** Action area rendered to the right of the title (e.g. + Add button). */
    actions?: Snippet;
    /** Optional filter strip rendered below the header. */
    filterBar?: Snippet;
    /** Page body. */
    children: Snippet;
  } = $props();
</script>

<div class="space-y-6">
  <header class="flex items-start justify-between gap-4">
    <div class="min-w-0">
      <h1 class="text-2xl font-bold text-(--text-primary)">{title}</h1>
      {#if subtitle}
        <p class="text-sm text-(--text-secondary) mt-1">{subtitle}</p>
      {:else if description}
        <div class="text-sm text-(--text-secondary) mt-1">
          {@render description()}
        </div>
      {/if}
    </div>
    {#if actions}
      <div class="flex items-center gap-2 shrink-0">
        {@render actions()}
      </div>
    {/if}
  </header>

  {#if filterBar}
    {@render filterBar()}
  {/if}

  {@render children()}
</div>
