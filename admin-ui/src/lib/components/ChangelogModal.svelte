<script lang="ts">
  import Modal from './Modal.svelte';
  import { adminApi } from '#lib/api-client.js';
  import { renderMarkdown } from '#lib/markdown.js';

  const STORAGE_KEY = 'streamscope_last_seen_version';
  const APP_VERSION = __APP_VERSION__;

  let showModal = $state(false);
  let changelogContent = $state('');
  let gotItButton = $state<HTMLButtonElement>();

  // Check on mount if there's a new version the admin hasn't seen.
  $effect(() => {
    const lastSeen = localStorage.getItem(STORAGE_KEY);
    if (lastSeen !== APP_VERSION) {
      loadChangelog();
    }
  });

  async function loadChangelog() {
    const { data } = await adminApi.GET('/api/v1/admin/changelog');
    if (data) {
      changelogContent = data.content ?? '';
      showModal = true;
    }
  }

  async function dismiss() {
    showModal = false;
    localStorage.setItem(STORAGE_KEY, APP_VERSION);
    // Best-effort server-side tracking — don't block on failure.
    await adminApi.POST('/api/v1/admin/changelog/actions/dismiss', {}).catch(() => {});
  }
</script>

<Modal
  open={showModal}
  title="What's New in v{APP_VERSION}"
  onclose={dismiss}
  maxWidth="max-w-xl"
  autoFocus={gotItButton}
>
  <div class="changelog-content text-sm text-(--text-secondary) leading-relaxed">
    {@html renderMarkdown(changelogContent)}
  </div>
  {#snippet footer()}
    <div class="flex justify-end">
      <button
        bind:this={gotItButton}
        onclick={dismiss}
        class="px-4 py-2 bg-(--accent) text-(--accent-fg) rounded-lg hover:bg-(--accent-hover) text-sm font-medium"
      >
        Got it
      </button>
    </div>
  {/snippet}
</Modal>
