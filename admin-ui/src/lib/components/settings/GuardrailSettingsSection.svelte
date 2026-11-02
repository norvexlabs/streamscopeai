<script lang="ts">
  import { adminApi } from '#lib/api-client.js';
  import { extractError, extractErrorCode } from '#lib/api-helpers.js';
  import { toast } from '#lib/toast.svelte.js';
  import type { components } from '#lib/generated/api-types.js';
  import NumberSetting from '#lib/components/forms/NumberSetting.svelte';
  import ToggleSetting from '#lib/components/forms/ToggleSetting.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import { onMount } from 'svelte';

  type GuardrailBackend = components['schemas']['GuardrailBackendResponse'];
  type ClassifierProtocol = components['schemas']['ClassifierProtocol'];

  let classifierUrl = $state('');
  let protocol = $state<ClassifierProtocol>('hf_text_classification');
  let positiveLabel = $state('INJECTION');
  // Core's own defaults (`GuardrailBackendSettings`), named once because they are
  // needed twice: as what the form shows before a load lands, and as the fallback
  // when the API omits an optional field. A load that fails leaves the form
  // editable, and `buildBody()` sends every field — so a value that drifts below
  // core's default here is silently written into the tenant's stored settings on
  // the next save, and an explicitly stored value never falls through to the
  // default again. Keep these in step with `guardrail/settings.rs`.
  const DEFAULT_TIMEOUT_MS = 2000;
  const DEFAULT_MAX_WINDOWS = 6;
  const DEFAULT_MAX_WINDOWS_CONTENT = 32;

  let timeoutMs = $state(DEFAULT_TIMEOUT_MS);
  let spotlight = $state(true);
  let maxWindows = $state(DEFAULT_MAX_WINDOWS);
  let maxWindowsContent = $state(DEFAULT_MAX_WINDOWS_CONTENT);
  let notifyOnDetection = $state(false);

  let loading = $state(true);
  let saving = $state(false);

  // Every field is `#[serde(default)]` on the wire, so the generated type marks
  // them optional. Fall back to the core defaults when absent so the form never
  // lands on `undefined`.
  function applyBackend(s: GuardrailBackend) {
    classifierUrl = s.classifier_url ?? '';
    protocol = s.protocol ?? 'hf_text_classification';
    positiveLabel = s.positive_label ?? 'INJECTION';
    timeoutMs = s.timeout_ms ?? DEFAULT_TIMEOUT_MS;
    spotlight = s.spotlight ?? true;
    maxWindows = s.max_windows ?? DEFAULT_MAX_WINDOWS;
    maxWindowsContent = s.max_windows_content ?? DEFAULT_MAX_WINDOWS_CONTENT;
    notifyOnDetection = s.notify_on_detection ?? false;
  }

  async function load() {
    loading = true;
    const { data, error: err } = await adminApi.GET('/api/v1/admin/settings/guardrail');
    if (err) {
      toast.error('Failed to load guardrail backend', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
    } else if (data) {
      applyBackend(data);
    }
    loading = false;
  }

  function buildBody(): components['schemas']['UpdateGuardrailBackendRequest'] {
    return {
      classifier_url: classifierUrl.trim() === '' ? null : classifierUrl.trim(),
      protocol,
      positive_label: positiveLabel.trim() === '' ? null : positiveLabel.trim(),
      timeout_ms: timeoutMs,
      spotlight,
      max_windows: maxWindows,
      max_windows_content: maxWindowsContent,
      notify_on_detection: notifyOnDetection,
    };
  }

  async function save() {
    saving = true;
    const { data, error: err } = await adminApi.PATCH('/api/v1/admin/settings/guardrail', {
      body: buildBody(),
    });
    saving = false;
    if (err) {
      toast.error('Failed to save guardrail backend', {
        body: extractError(err),
        code: extractErrorCode(err) ?? undefined,
      });
      return;
    }
    if (data) applyBackend(data);
    toast.success('Guardrail backend saved');
  }

  const hasClassifier = $derived(classifierUrl.trim() !== '');

  onMount(load);
</script>

<section class="space-y-4 max-w-4xl">
  {#if loading}
    <div class="bg-(--bg-card) rounded-xl p-5 border border-(--border)">
      <div class="w-32 h-4 bg-(--bg-primary) rounded-sm animate-pulse"></div>
    </div>
  {:else}
    <!-- Overview -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Guardrail Classifier Backend</h3>
      <p class="text-xs text-(--text-secondary) mb-2">
        The tenant-wide injection-classifier deployment shared by every guardrail profile. One
        endpoint, one alert producer — set it once here.
      </p>
      <p class="text-xs text-(--text-secondary)">
        Guardrail posture (mode, sensitivity, PII, scan-inbound) is now <strong>per-workspace</strong> —
        configure it under <span class="text-(--text-primary)">Governance → Guardrail</span>.
      </p>

      {#if !hasClassifier}
        <p class="text-xs mt-3 px-3 py-2 rounded-lg bg-(--warning-bg) text-(--warning) border border-(--warning-border)">
          No classifier endpoint set — every guardrail profile stays inert until one is set below.
        </p>
      {/if}
    </div>

    <!-- Classifier endpoint -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5">
      <h3 class="text-sm font-semibold text-(--text-primary)">Classifier</h3>
      <p class="text-xs text-(--text-secondary) mt-1 mb-3">
        The classifier endpoint: a self-hosted text-classification server or an
        OpenAI-moderations-compatible service.
      </p>

      <label class="block">
        <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">
          Endpoint URL
        </span>
        <input
          type="url"
          bind:value={classifierUrl}
          placeholder="https://classifier.example.com"
          class="w-full mt-1 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors"
        />
      </label>

      <div class="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4">
        <label class="block">
          <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Protocol</span>
          <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Wire shape the endpoint speaks</span>
          <SelectInput
            bind:value={protocol}
            class="mt-1.5"
          >
            <option value="hf_text_classification">HuggingFace text-classification (TEI / bundled)</option>
            <option value="openai_moderations">OpenAI moderations (external)</option>
          </SelectInput>
        </label>

        {#if protocol === 'hf_text_classification'}
          <label class="block">
            <span class="text-[10px] text-(--text-secondary) uppercase tracking-wider">Positive Label</span>
            <span class="block text-xs text-(--text-secondary) mt-0.5 normal-case tracking-normal">Label the model emits for an injection (e.g. INJECTION)</span>
            <input
              type="text"
              bind:value={positiveLabel}
              placeholder="INJECTION"
              class="w-full mt-1.5 px-2.5 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-sm font-mono text-(--text-primary) focus:outline-hidden focus:border-(--accent) transition-colors"
            />
          </label>
        {/if}
      </div>
    </div>

    <!-- Alerting + advanced -->
    <div class="bg-(--bg-card) rounded-xl border border-(--border) p-5 space-y-4">
      <h3 class="text-sm font-semibold text-(--text-primary)">Alerting &amp; Advanced</h3>
      <ToggleSetting
        label="Notify on Detection (observe)"
        description="Send a notification when a verdict is flagged in observe mode. Enforce blocks always notify. Keep off during the noisy false-positive bake."
        bind:value={notifyOnDetection}
      />
      <ToggleSetting
        label="Spotlight Fetched Content"
        description="Wrap fetched tool-results in datamarking delimiters before fold-in (cheap, local)."
        bind:value={spotlight}
      />
      <div class="grid grid-cols-1 md:grid-cols-2 gap-4">
        <NumberSetting
          label="Detector Timeout"
          description="Per-request budget; on expiry the per-profile fail-mode decides the outcome."
          bind:value={timeoutMs}
          min={1}
          max={10000}
          unit="ms"
        />
        <NumberSetting
          label="Max Windows (prompts)"
          description="Sliding windows a long prompt or response is split into before classification."
          bind:value={maxWindows}
          min={1}
          max={64}
        />
        <NumberSetting
          label="Max Windows (fetched content)"
          description="Same cap for web results and agent replies the gateway fetched. Higher by default — that content is the largest and the likeliest to hide an injection. Content past the cap is never classified and is reported as an incomplete scan, in observe as well as enforce."
          bind:value={maxWindowsContent}
          min={1}
          max={64}
        />
      </div>
    </div>

    <!-- Save bar -->
    <div class="flex items-center gap-3">
      <button
        onclick={save}
        disabled={saving}
        class="px-4 py-2 bg-(--accent) hover:bg-(--accent-hover) text-(--accent-fg) text-sm font-medium rounded-lg transition-colors disabled:opacity-50"
      >
        {saving ? 'Saving…' : 'Save Backend'}
      </button>
    </div>
  {/if}
</section>
