<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  type GuardrailPolicyResponse = components['schemas']['GuardrailPolicyResponse'];
  type GuardrailMode = components['schemas']['GuardrailMode'];
  type GuardrailFailMode = components['schemas']['GuardrailFailMode'];

  interface Props {
    /** The guardrail profile whose policy is being edited. */
    profileId: string;
  }

  let { profileId }: Props = $props();

  // The threshold is presented as a Low/Med/High *sensitivity* selector — the
  // raw float never surfaces in the UI (it lives only in the audit detail).
  // Higher sensitivity = lower threshold = more content flagged.
  type Sensitivity = 'low' | 'medium' | 'high';
  const SENSITIVITY_THRESHOLD: Record<Sensitivity, number> = {
    low: 0.95,
    medium: 0.9,
    high: 0.8,
  };
  function thresholdToSensitivity(t: number): Sensitivity {
    if (t >= 0.95) return 'low';
    if (t >= 0.85) return 'medium';
    return 'high';
  }

  // PII detector sensitivity → threshold mapping. PII scores run lower than the
  // injection classifier's, so the thresholds differ.
  const PII_SENSITIVITY_THRESHOLD: Record<Sensitivity, number> = {
    low: 0.7,
    medium: 0.5,
    high: 0.4,
  };
  function piiThresholdToSensitivity(t: number): Sensitivity {
    if (t >= 0.7) return 'low';
    if (t >= 0.45) return 'medium';
    return 'high';
  }

  // Core's own default thresholds (`GuardrailPolicy` / `PiiSettings`). Named
  // because each is needed twice — to seed the control before a load lands, and
  // as the fallback when the API omits the field — and because the control holds
  // a *sensitivity band*, not the number: seeding a band that does not map back
  // from the default threshold silently rewrites it on the next save. A load
  // that fails leaves the form editable and `buildBody()` sends every field, so
  // the two must agree. Keep in step with `guardrail/settings.rs`.
  const DEFAULT_THRESHOLD = 0.9;
  const DEFAULT_PII_THRESHOLD = 0.5;

  let enabled = $state(true);
  let mode = $state<GuardrailMode>('observe');
  let scanInbound = $state(false);
  let sensitivity = $state<Sensitivity>(thresholdToSensitivity(DEFAULT_THRESHOLD));
  let failMode = $state<GuardrailFailMode>('open');

  // PII detector — independent of the injection classifier.
  let piiEnabled = $state(false);
  let piiMode = $state<GuardrailMode>('observe');
  let piiScanRequest = $state(false);
  let piiScanResponse = $state(false);
  let piiEntities = $state<string[]>([]);
  let piiSensitivity = $state<Sensitivity>(piiThresholdToSensitivity(DEFAULT_PII_THRESHOLD));
  let piiPlaceholder = $state('[REDACTED:{entity}]');
  // The closed set of recognizers the detector ships — server-owned.
  let piiEntityTypes = $state<string[]>([]);

  function togglePiiEntity(entity: string) {
    piiEntities = piiEntities.includes(entity)
      ? piiEntities.filter((e) => e !== entity)
      : [...piiEntities, entity];
  }

  // Entity types are grouped by jurisdiction for the selector — the closed set
  // spans the generic/US entities plus per-country national-ID / VAT / tax /
  // document / postcode recognizers, so a flat list is unwieldy.
  const ENTITY_GROUPS: { label: string; prefixes: string[] }[] = [
    { label: 'General', prefixes: ['EMAIL', 'CREDIT', 'IBAN', 'PHONE', 'IP_', 'CRYPTO', 'US_'] },
    { label: 'France', prefixes: ['FR_'] },
    { label: 'Germany', prefixes: ['DE_'] },
    { label: 'Italy', prefixes: ['IT_'] },
    { label: 'Spain', prefixes: ['ES_'] },
    { label: 'United Kingdom', prefixes: ['UK_'] },
  ];
  const groupedEntities = $derived(
    ENTITY_GROUPS.map((g) => ({
      label: g.label,
      entities: piiEntityTypes.filter((e) => g.prefixes.some((p) => e.startsWith(p))),
    })).filter((g) => g.entities.length > 0),
  );

  function setGroup(entities: string[], on: boolean) {
    const set = new Set(piiEntities);
    for (const e of entities) {
      if (on) set.add(e);
      else set.delete(e);
    }
    piiEntities = piiEntityTypes.filter((e) => set.has(e));
  }

  let loading = $state(true);
  let saving = $state(false);

  function applyPolicy(p: GuardrailPolicyResponse) {
    enabled = p.enabled ?? true;
    mode = p.mode ?? 'observe';
    scanInbound = p.scan_inbound ?? false;
    sensitivity = thresholdToSensitivity(p.threshold ?? DEFAULT_THRESHOLD);
    failMode = p.fail_mode ?? 'open';
    const pii = p.pii;
    piiEnabled = pii?.enabled ?? false;
    piiMode = pii?.mode ?? 'observe';
    piiScanRequest = pii?.scan_request ?? false;
    piiScanResponse = pii?.scan_response ?? false;
    piiEntities = pii?.entities ?? [];
    piiSensitivity = piiThresholdToSensitivity(pii?.threshold ?? DEFAULT_PII_THRESHOLD);
    piiPlaceholder = pii?.redaction_placeholder ?? '[REDACTED:{entity}]';
  }

  async function load() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/profiles/{id}/guardrail', {
      params: { path: { id: profileId } },
    });
    if (err) {
      toast.error('Failed to load guardrail policy', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
    } else if (data) {
      applyPolicy(data);
      piiEntityTypes = data.pii_entity_types ?? [];
    }
    loading = false;
  }

  function buildBody(): components['schemas']['UpdateGuardrailPolicyRequest'] {
    return {
      enabled,
      mode,
      scan_inbound: scanInbound,
      threshold: SENSITIVITY_THRESHOLD[sensitivity],
      fail_mode: failMode,
      pii: {
        enabled: piiEnabled,
        mode: piiMode,
        scan_request: piiScanRequest,
        scan_response: piiScanResponse,
        entities: piiEntities,
        threshold: PII_SENSITIVITY_THRESHOLD[piiSensitivity],
        redaction_placeholder: piiPlaceholder.trim() === '' ? null : piiPlaceholder.trim(),
        // The UI doesn't expose the PII fail-mode — it stays open (a request that cannot be screened
        // message by message is forwarded, flagged); null leaves it.
        fail_mode: null,
      },
    };
  }

  async function save() {
    saving = true;
    const { data, error: err } = await adminApi.PATCH('/api/v1/admin/profiles/{id}/guardrail', {
      params: { path: { id: profileId } },
      body: buildBody(),
    });
    saving = false;
    if (err) {
      toast.error('Failed to save guardrail policy', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    if (data) applyPolicy(data);
    toast.success('Guardrail policy saved');
  }

  // Reload whenever the selected profile changes.
  let loadedId = $state('');
  $effect(() => {
    if (profileId && loadedId !== profileId) {
      loadedId = profileId;
      load();
    }
  });
</script>

<section class="space-y-4 max-w-4xl">
  {#if loading}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
      <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
    </div>
  {:else}
    <!-- Enable -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Injection Guardrail</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        Screens untrusted content fetched by the built-in
        <code class="font-mono bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">web_search</code>
        /
        <code class="font-mono bg-(--bg-primary) px-1 py-0.5 rounded-sm text-xs">web_fetch</code>
        tools for prompt-injection attempts before the result is folded back into the model. Uses
        the tenant classifier backend (Settings → Guardrail).
      </p>
      <ToggleSetting
        label="Enable Guardrail"
        description="Run the classifier on untrusted web search/fetch content for this profile."
        bind:value={enabled}
      />
    </div>

    {#if enabled}
      <!-- Posture -->
      <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
        <h3 class="text-sm font-semibold text-(--text-primary) mb-3">Posture</h3>
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
          <label class="block">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Mode</span>
            <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Watch first, then block once you trust the flag rate</span>
            <SelectInput
              bind:value={mode}
              class="mt-1.5"
            >
              <option value="observe">Observe — flag &amp; audit, content untouched</option>
              <option value="enforce">Enforce — strip flagged content to a placeholder</option>
            </SelectInput>
          </label>

          <label class="block">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Sensitivity</span>
            <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Higher = flags more aggressively (more false positives)</span>
            <SelectInput
              bind:value={sensitivity}
              class="mt-1.5"
            >
              <option value="low">Low — only high-confidence injections</option>
              <option value="medium">Medium — balanced</option>
              <option value="high">High — aggressive</option>
            </SelectInput>
          </label>
        </div>

        {#if mode === 'enforce'}
          <p class="text-xs mt-3 px-3 py-2 rounded-lg bg-(--warning-bg) text-(--warning) border border-(--warning-border)">
            Enforce strips flagged content to a visible placeholder before the model sees it. The
            user's request still completes — only the malicious payload is withheld. Bake in observe
            first to validate the false-positive rate.
          </p>
        {/if}

        <div class="mt-4">
          <ToggleSetting
            label="Scan inbound prompts"
            description="Also screen the user's own message and any tool-result content the client folds into the request (RAG / tool output) for prompt-injection — in addition to the always-on web-content surface. Off by default; uses the mode and fail-mode above. Enforce replaces a flagged prompt with a placeholder."
            bind:value={scanInbound}
          />
        </div>

        <div class="mt-4">
          <label class="block max-w-sm">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">On Detector Error</span>
            <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">When the classifier times out or is unreachable</span>
            <SelectInput
              bind:value={failMode}
              class="mt-1.5"
            >
              <option value="open">Fail open — let content through (badge the error)</option>
              <option value="closed">Fail closed — treat as blocked (enforce only)</option>
            </SelectInput>
          </label>
        </div>
      </div>
    {/if}

    <!-- PII Detection (independent of the injection guardrail above) -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">PII Detection</h3>
      <p class="text-xs text-(--text-secondary) mb-3">
        Detects personally-identifiable information (emails, cards, SSNs, IBANs, phone numbers, IP
        addresses, crypto &amp; bank-account numbers) in requests and/or responses. Runs in-process —
        no classifier endpoint required. Independent of the injection guardrail above.
      </p>
      <ToggleSetting
        label="Enable PII Detection"
        description="Scan for PII with the in-process detector (card / SSN / IBAN are checksum-validated)."
        bind:value={piiEnabled}
      />

      {#if piiEnabled}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
          <label class="block">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Mode</span>
            <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Watch first, then mask once you trust the flag rate</span>
            <SelectInput
              bind:value={piiMode}
              class="mt-1.5"
            >
              <option value="observe">Observe — flag &amp; audit, content untouched</option>
              <option value="enforce">Enforce — mask findings in place</option>
            </SelectInput>
          </label>

          <label class="block">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Sensitivity</span>
            <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Higher = flags more aggressively (more false positives)</span>
            <SelectInput
              bind:value={piiSensitivity}
              class="mt-1.5"
            >
              <option value="low">Low — only high-confidence matches</option>
              <option value="medium">Medium — balanced</option>
              <option value="high">High — aggressive</option>
            </SelectInput>
          </label>
        </div>

        <div class="mt-4 space-y-3">
          <ToggleSetting
            label="Scan requests"
            description="Screen the user's own latest message before it is forwarded (DLP egress). Enforce masks the values in place."
            bind:value={piiScanRequest}
          />
          <ToggleSetting
            label="Scan responses"
            description="Screen the model's reply for leaked PII. Enforce masks non-streaming replies; streaming replies are flagged but not rewritten (bytes are already sent)."
            bind:value={piiScanResponse}
          />
        </div>

        <div class="mt-4">
          <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Entity types</span>
          <span class="block text-xs text-(--text-secondary) mt-0.5">Which entities to detect, grouped by jurisdiction. None selected behaves as all-off.</span>
          <div class="space-y-3 mt-2">
            {#each groupedEntities as group (group.label)}
              {@const allOn = group.entities.every((e) => piiEntities.includes(e))}
              <div>
                <div class="flex items-center gap-2 mb-1.5">
                  <span class="text-[11px] font-semibold text-(--text-primary)">{group.label}</span>
                  <button
                    type="button"
                    onclick={() => setGroup(group.entities, !allOn)}
                    class="text-[10px] text-(--accent) hover:underline"
                  >
                    {allOn ? 'clear' : 'all'}
                  </button>
                </div>
                <div class="flex flex-wrap gap-2">
                  {#each group.entities as entity (entity)}
                    <button
                      type="button"
                      onclick={() => togglePiiEntity(entity)}
                      class="px-2 py-1 rounded-lg text-xs font-mono border transition-colors {piiEntities.includes(entity)
                        ? 'bg-(--accent) text-(--accent-fg) border-(--accent)'
                        : 'bg-(--bg-primary) text-(--text-secondary) border-(--border) hover:border-(--accent)'}"
                    >
                      {entity}
                    </button>
                  {/each}
                </div>
              </div>
            {/each}
          </div>
        </div>

        {#if piiMode === 'enforce'}
          <div class="mt-4">
            <label class="block max-w-sm">
              <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Redaction Placeholder</span>
              <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Replaces a masked value. Must contain <code class="font-mono">{'{entity}'}</code> (the entity type).</span>
              <input
                type="text"
                bind:value={piiPlaceholder}
                placeholder="[REDACTED:{'{entity}'}]"
                class="w-full mt-1.5 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors"
              />
            </label>
          </div>
          <p class="text-xs mt-3 px-3 py-2 rounded-lg bg-(--warning-bg) text-(--warning) border border-(--warning-border)">
            Enforce masks detected PII in place. Streaming responses are flagged but not rewritten
            (their bytes are already sent) — hard response redaction requires non-streaming. Bake in
            observe first to validate the false-positive rate.
          </p>
        {/if}
      {/if}
    </div>

    <!-- Save bar -->
    <div class="flex items-center gap-3">
      <button
        onclick={save}
        disabled={saving}
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
      >
        {saving ? 'Saving…' : 'Save Policy'}
      </button>
    </div>
  {/if}
</section>
