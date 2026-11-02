<script lang="ts">
  import { m } from '#lib/paraglide/messages.js';
  import { SOURCE_REPOSITORY } from '#lib/constants.js';

  const source = `${SOURCE_REPOSITORY}/tree/v${__APP_VERSION__}`;
  const license = `${SOURCE_REPOSITORY}/blob/v${__APP_VERSION__}/LICENSE`;
</script>

<!-- The version, and the offer of its source and licence: under the expanded
     sidebars and on the pages outside the console shell (sign-in, setup, invitation). -->
<p class="text-[10px] text-(--text-secondary) text-center">
  v{__APP_VERSION__} ·
  <a href={source} target="_blank" rel="noopener noreferrer" class="hover:text-(--text-primary) underline-offset-2 hover:underline">{m.product_source_code()}</a>
  ·
  <a href={license} target="_blank" rel="noopener noreferrer" class="hover:text-(--text-primary) underline-offset-2 hover:underline">AGPL-3.0</a><!-- i18n-ok: licence identifier -->
</p>
