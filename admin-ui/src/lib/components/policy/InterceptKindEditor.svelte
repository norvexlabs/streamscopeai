<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type InterceptKind = components['schemas']['InterceptKind'];
  type WebInterceptKind = components['schemas']['WebInterceptKind'];

  interface Props {
    initial: InterceptKind;
    onchange: (next: InterceptKind) => void;
    disabled?: boolean;
  }

  let { initial, onchange, disabled = false }: Props = $props();

  // `type` is a closed Rust enum with one variant today (`web_executor`).
  // Rendered as a dropdown so adding a new variant is a single <option>; the
  // shape change here would just be to widen `HandlerType` accordingly.
  type HandlerType = 'web_executor';

  let handlerType = $state<HandlerType>('web_executor');
  let mode = $state<WebInterceptKind>('search');

  let initialKey = $derived(`${initial?.type ?? ''}::${initial?.kind ?? ''}`);
  let lastSeenKey = $state('');

  $effect(() => {
    if (initialKey === lastSeenKey) return;
    lastSeenKey = initialKey;
    handlerType = initial?.type ?? 'web_executor';
    mode = initial?.kind ?? 'search';
  });

  $effect(() => {
    void handlerType;
    void mode;
    const next: InterceptKind = { type: handlerType, kind: mode };
    lastSeenKey = `${handlerType}::${mode}`;
    onchange(next);
  });

  let modeHelp = $derived.by(() => {
    if (handlerType === 'web_executor') {
      if (mode === 'search') return 'query → ranked web results (gateway-side search, URL-filtered, audited).';
      if (mode === 'fetch') return 'URL → fetched content (SSRF-guarded, content-capped, audited).';
    }
    return '';
  });
</script>

<div class="border border-(--border) rounded-lg p-3 space-y-3 bg-(--bg-primary)/30">
  <div class="grid grid-cols-2 gap-3">
    <div>
      <label for="ik-type" class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1">Handler</label>
      <SelectInput
        id="ik-type"
        bind:value={handlerType}
        {disabled}
        class="font-mono"
      >
        <option value="web_executor">web_executor</option>
      </SelectInput>
      <p class="text-[10px] text-(--text-secondary) mt-1">In-proxy handler the tool call routes to. New handler types need backend code.</p>
    </div>
    <div>
      <label for="ik-mode" class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1">Mode</label>
      <SelectInput
        id="ik-mode"
        bind:value={mode}
        {disabled}
        class="font-mono"
      >
        <option value="search">search</option>
        <option value="fetch">fetch</option>
      </SelectInput>
      <p class="text-[10px] text-(--text-secondary) mt-1">{modeHelp}</p>
    </div>
  </div>
</div>
