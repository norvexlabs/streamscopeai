<script lang="ts">
  import type { components } from '#lib/generated/api-types.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type ToolDefValue = components['schemas']['ToolDefValue'];

  interface Props {
    initial: ToolDefValue;
    onchange: (next: ToolDefValue) => void;
    /**
     * Surfaces parse-time validity so the parent form can disable Save while
     * the raw-JSON textarea contains a syntax error. Without this hook, a
     * Save during invalid input would silently emit an empty schema and ship
     * a rule that doesn't match what the operator typed.
     */
    onvalidchange?: (valid: boolean) => void;
    disabled?: boolean;
  }

  let { initial, onchange, onvalidchange, disabled = false }: Props = $props();
  let rowSeq = 0;

  type PropType = 'string' | 'number' | 'integer' | 'boolean' | 'array<string>';

  interface PropRow {
    id: number;
    name: string;
    type: PropType;
    description: string;
    required: boolean;
    enumValues: string;
  }

  let name = $state('');
  let description = $state('');
  let properties = $state<PropRow[]>([]);
  let rawMode = $state(false);
  let rawText = $state('{}');
  let rawError = $state<string | null>(null);
  let modeBanner = $state<string | null>(null);

  // Re-hydrate when the parent swaps `initial` (e.g. modal opens a different rule).
  // Use a key over identity-stable fields so we don't re-hydrate on every parent re-render.
  let initialKey = $derived(`${initial?.name ?? ''}::${JSON.stringify(initial?.parameters ?? {})}`);
  let lastSeenKey = $state('');

  $effect(() => {
    if (initialKey === lastSeenKey) return;
    lastSeenKey = initialKey;
    name = initial.name ?? '';
    description = initial.description ?? '';
    const params: unknown = initial.parameters;
    const hydrated = tryHydrateProperties(params);
    rawText = JSON.stringify(params ?? { type: 'object', properties: {} }, null, 2);
    if (hydrated === null) {
      properties = [];
      rawMode = true;
      modeBanner = 'This schema has nested structure or unsupported types — staying in raw JSON mode.';
    } else {
      properties = hydrated;
      rawMode = false;
      modeBanner = null;
    }
    rawError = null;
  });

  // Emit on any change. We compare key against lastSeenKey to avoid feeding
  // our own output back through the hydrate effect.
  $effect(() => {
    void name;
    void description;
    void rawMode;
    void rawText;
    void JSON.stringify(properties);
    const params = buildParameters();
    const next: ToolDefValue = {
      name,
      description: description || null,
      parameters: params as Record<string, never>,
    };
    lastSeenKey = `${name}::${JSON.stringify(params)}`;
    onchange(next);
  });

  function tryHydrateProperties(params: unknown): PropRow[] | null {
    if (params === null || params === undefined) return [];
    if (typeof params !== 'object') return null;
    const p = params as Record<string, unknown>;
    if (Object.keys(p).length === 0) return [];
    if (p.type !== 'object') return null;
    const propsObj = p.properties;
    const required = Array.isArray(p.required) ? (p.required as unknown[]).filter((v): v is string => typeof v === 'string') : [];
    if (!propsObj || typeof propsObj !== 'object') return [];
    const known = new Set(['type', 'properties', 'required']);
    for (const k of Object.keys(p)) {
      if (!known.has(k)) return null;
    }
    const rows: PropRow[] = [];
    for (const [key, def] of Object.entries(propsObj as Record<string, unknown>)) {
      if (!def || typeof def !== 'object') return null;
      const d = def as Record<string, unknown>;
      const t = d.type;
      let normType: PropType;
      if (t === 'string') normType = 'string';
      else if (t === 'number') normType = 'number';
      else if (t === 'integer') normType = 'integer';
      else if (t === 'boolean') normType = 'boolean';
      else if (t === 'array') {
        const items = d.items as Record<string, unknown> | undefined;
        if (!items || items.type !== 'string') return null;
        const itemKeys = new Set(['type']);
        for (const k of Object.keys(items)) {
          if (!itemKeys.has(k)) return null;
        }
        normType = 'array<string>';
      } else return null;
      const desc = typeof d.description === 'string' ? d.description : '';
      let enumStr = '';
      if (Array.isArray(d.enum)) {
        if (d.enum.some((v) => typeof v !== 'string')) return null;
        enumStr = (d.enum as string[]).join('|');
      }
      const propKnown = new Set(['type', 'description', 'enum', 'items']);
      for (const k of Object.keys(d)) {
        if (!propKnown.has(k)) return null;
      }
      rows.push({ id: ++rowSeq, name: key, type: normType, description: desc, required: required.includes(key), enumValues: enumStr });
    }
    return rows;
  }

  function buildParameters(): Record<string, unknown> {
    if (rawMode) {
      // Parse failures propagate via `rawError` / `onvalidchange` rather than
      // ship an empty schema — see Props.onvalidchange. If save still fires
      // through, surface the user's intent by echoing the literal text — the
      // server-side validator will reject it cleanly instead of silently
      // accepting an empty replacement.
      try {
        return JSON.parse(rawText) as Record<string, unknown>;
      } catch {
        return { __invalid_raw_json__: rawText } as unknown as Record<string, unknown>;
      }
    }
    const props: Record<string, unknown> = {};
    const req: string[] = [];
    for (const row of properties) {
      const key = row.name.trim();
      if (!key) continue;
      const def: Record<string, unknown> = {};
      if (row.type === 'array<string>') {
        def.type = 'array';
        def.items = { type: 'string' };
      } else {
        def.type = row.type;
      }
      if (row.description) def.description = row.description;
      if (row.type === 'string' && row.enumValues.trim()) {
        const vals = row.enumValues
          .split('|')
          .map((s) => s.trim())
          .filter(Boolean);
        if (vals.length > 0) def.enum = vals;
      }
      props[key] = def;
      if (row.required) req.push(key);
    }
    const out: Record<string, unknown> = { type: 'object', properties: props };
    if (req.length > 0) out.required = req;
    return out;
  }

  function addProperty() {
    properties = [
      ...properties,
      { id: ++rowSeq, name: '', type: 'string', description: '', required: false, enumValues: '' },
    ];
  }

  function removeProperty(id: number) {
    properties = properties.filter((p) => p.id !== id);
  }

  function setProp<K extends keyof PropRow>(id: number, key: K, val: PropRow[K]) {
    properties = properties.map((p) => (p.id === id ? { ...p, [key]: val } : p));
  }

  function validateRaw() {
    if (!rawText.trim()) {
      rawError = null;
      return;
    }
    try {
      JSON.parse(rawText);
      rawError = null;
    } catch (e) {
      rawError = (e as Error).message;
    }
  }

  $effect(() => {
    // Bubble validity up so the parent's Save button can disable while raw
    // JSON is broken. In form mode the editor is always structurally valid.
    onvalidchange?.(!rawMode || rawError === null);
  });

  function toggleRawMode() {
    if (rawMode) {
      // Raw → Form: attempt to hydrate from the current textarea.
      let parsed: unknown;
      try {
        parsed = JSON.parse(rawText);
      } catch (e) {
        rawError = (e as Error).message;
        return;
      }
      const hydrated = tryHydrateProperties(parsed);
      if (hydrated === null) {
        modeBanner = 'This schema has nested structure or unsupported types — staying in raw JSON mode.';
        return;
      }
      properties = hydrated;
      modeBanner = null;
      rawError = null;
      rawMode = false;
    } else {
      // Form → Raw: snapshot the current property list as JSON.
      rawText = JSON.stringify(buildParameters(), null, 2);
      rawError = null;
      rawMode = true;
    }
  }
</script>

<div class="border border-(--border) rounded-lg p-3 space-y-3 bg-(--bg-primary)/30">
  <div class="grid grid-cols-3 gap-3">
    <div class="col-span-1">
      <label for="td-name" class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1">Tool name</label>
      <input
        id="td-name"
        type="text"
        bind:value={name}
        {disabled}
        placeholder="web"
        class="w-full px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono focus:outline-hidden focus:border-(--accent) disabled:opacity-50"
      />
    </div>
    <div class="col-span-2">
      <label for="td-desc" class="block text-xs uppercase tracking-wider text-(--text-secondary) mb-1">Description</label>
      <input
        id="td-desc"
        type="text"
        bind:value={description}
        {disabled}
        placeholder="What the model is told this tool does"
        class="w-full px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm focus:outline-hidden focus:border-(--accent) disabled:opacity-50"
      />
    </div>
  </div>

  <div>
    <div class="flex items-center justify-between mb-2">
      <span class="text-xs uppercase tracking-wider text-(--text-secondary)">Parameters (JSON Schema)</span>
      <button
        type="button"
        onclick={toggleRawMode}
        {disabled}
        class="text-xs text-(--accent) hover:underline disabled:opacity-50"
      >
        {rawMode ? 'Form mode' : 'Edit raw JSON…'}
      </button>
    </div>

    {#if modeBanner}
      <div class="p-2 mb-2 rounded-sm bg-(--warning-bg) text-(--warning) text-[11px]">{modeBanner}</div>
    {/if}

    {#if rawMode}
      <textarea
        bind:value={rawText}
        oninput={validateRaw}
        {disabled}
        rows="8"
        spellcheck="false"
        class="w-full px-3 py-2 bg-(--bg-primary) border border-(--border) rounded-lg text-xs font-mono whitespace-pre focus:outline-hidden focus:border-(--accent) disabled:opacity-50"
      ></textarea>
      <p class="text-[10px] mt-1 {rawError ? 'text-(--error)' : 'text-(--success)'}">
        {#if rawError}✕ {rawError}{:else}✓ valid JSON{/if}
      </p>
    {:else}
      <div class="space-y-2">
        {#each properties as row (row.id)}
          <div class="grid grid-cols-12 gap-2 items-start p-2 rounded-sm bg-(--bg-primary)/40 border border-(--border)">
            <input
              type="text"
              value={row.name}
              oninput={(e) => setProp(row.id, 'name', (e.currentTarget as HTMLInputElement).value)}
              {disabled}
              aria-label="Property name"
              placeholder="property"
              class="col-span-3 px-2 py-1 bg-(--bg-primary) border border-(--border) rounded-sm text-xs font-mono focus:outline-hidden focus:border-(--accent) disabled:opacity-50"
            />
            <SelectInput
              value={row.type}
              onchange={(e) => setProp(row.id, 'type', (e.currentTarget as HTMLSelectElement).value as PropType)}
              {disabled}
              aria-label="Property type"
              class="col-span-2"
            >
              <option value="string">string</option>
              <option value="number">number</option>
              <option value="integer">integer</option>
              <option value="boolean">boolean</option>
              <option value="array<string>">array&lt;string&gt;</option>
            </SelectInput>
            <input
              type="text"
              value={row.description}
              oninput={(e) => setProp(row.id, 'description', (e.currentTarget as HTMLInputElement).value)}
              {disabled}
              aria-label="Property description"
              placeholder="description"
              class="col-span-5 px-2 py-1 bg-(--bg-primary) border border-(--border) rounded-sm text-xs focus:outline-hidden focus:border-(--accent) disabled:opacity-50"
            />
            <label class="col-span-1 flex items-center gap-1 text-[11px] text-(--text-secondary) px-1">
              <input
                type="checkbox"
                checked={row.required}
                onchange={(e) => setProp(row.id, 'required', (e.currentTarget as HTMLInputElement).checked)}
                {disabled}
                class="w-3 h-3"
              />
              req
            </label>
            <button
              type="button"
              onclick={() => removeProperty(row.id)}
              {disabled}
              aria-label="Remove property"
              class="col-span-1 p-1 text-(--text-secondary) hover:text-(--error) text-xs justify-self-end disabled:opacity-50"
            ><span aria-hidden="true">✕</span></button>
            {#if row.type === 'string'}
              <input
                type="text"
                value={row.enumValues}
                oninput={(e) => setProp(row.id, 'enumValues', (e.currentTarget as HTMLInputElement).value)}
                {disabled}
                aria-label="Property enum values (pipe-separated)"
                placeholder="enum values (pipe-separated, optional)"
                class="col-span-12 px-2 py-1 bg-(--bg-primary) border border-(--border) rounded-sm text-xs font-mono focus:outline-hidden focus:border-(--accent) disabled:opacity-50"
              />
            {/if}
          </div>
        {/each}
        {#if properties.length === 0}
          <p class="text-[10px] text-(--text-secondary) italic">No properties — this tool takes no arguments. Most useful tools declare at least one.</p>
        {/if}
        <button
          type="button"
          onclick={addProperty}
          {disabled}
          class="text-xs text-(--accent) hover:underline disabled:opacity-50"
        >+ Add property</button>
      </div>
    {/if}
  </div>
</div>
