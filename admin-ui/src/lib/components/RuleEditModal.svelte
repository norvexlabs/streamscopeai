<script lang="ts">
  import FormModal from '#lib/components/forms/FormModal.svelte';
  import FormField from '#lib/components/forms/FormField.svelte';
  import TextInput from '#lib/components/forms/TextInput.svelte';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';
  import NumberInput from '#lib/components/forms/NumberInput.svelte';
  import TextArea from '#lib/components/forms/TextArea.svelte';
  import { adminApi } from '#lib/api-client.js';
  import { extractError } from '#lib/api-helpers.js';
  import { useDirtyForm } from '#lib/hooks.svelte.js';
  import type { components } from '#lib/generated/api-types.js';

  type Rule = components['schemas']['Rule'];
  // The form's draft: the create body, whose id may be left to the server.
  type DraftRule = components['schemas']['CreateToolRule'];
  type MatchCondition = components['schemas']['MatchCondition'];
  type Phase = components['schemas']['Phase'];
  type Scope = components['schemas']['Scope'];
  type ToolDefValue = components['schemas']['ToolDefValue'];
  type InterceptKind = components['schemas']['InterceptKind'];

  import ToolDefEditor from '#lib/components/policy/ToolDefEditor.svelte';
  import InterceptKindEditor from '#lib/components/policy/InterceptKindEditor.svelte';

  type ActionKind = 'classify' | 'block' | 'replace' | 'substitute' | 'intercept_only';
  const DEFAULT_TOOL_DEF: ToolDefValue = {
    name: '',
    description: null,
    // openapi-typescript types `parameters` as `Record<string, never>` for any
    // opaque JSON Schema object; cast through `unknown` per the TS hint.
    parameters: { type: 'object', properties: {} } as unknown as Record<string, never>,
  };
  const DEFAULT_INTERCEPT: InterceptKind = { type: 'web_executor', kind: 'search' };

  interface Props {
    open: boolean;
    /** When present, the form is in edit mode; when null, it's create mode. */
    initial: Rule | null;
    /** Tool names from the tenant's current inventory — drives the live "matches N" counter. */
    inventory: string[];
    /** When creating from a profile-filtered view, stamp the new rule into that
     * profile (otherwise the server assigns the tenant default profile). */
    defaultProfileId?: string;
    onclose: () => void;
    onsaved: (rule: Rule) => void;
  }

  let { open, initial, inventory, defaultProfileId, onclose, onsaved }: Props = $props();

  // ── Form state ───────────────────────────────────────────────────────
  let idField = $state('');
  let title = $state('');
  let description = $state('');
  let risk = $state('safe');
  let enabled = $state(true);
  let priority = $state(100);
  let modelFilter = $state('');
  let appFilter = $state('');
  let mcpServerFilter = $state('');
  let a2aAgentFilter = $state('');
  let phase = $state<Phase>('request');
  let scope = $state<Scope>('tool_definitions');
  let conditions = $state<MatchCondition[]>([]);
  let actionKind = $state<ActionKind>('classify');
  let replaceRegex = $state('');
  let replaceWith = $state('');
  let replaceDrop = $state(false);
  let toolDef = $state<ToolDefValue>({ ...DEFAULT_TOOL_DEF });
  let interceptKind = $state<InterceptKind>({ ...DEFAULT_INTERCEPT });
  let frameworkRefs = $state<string[]>([]);

  let saving = $state(false);
  let error = $state<string | null>(null);
  // Tracks ToolDefEditor's parse validity when in raw-JSON mode. Save is
  // disabled while this is false to prevent silently shipping a broken
  // tool def.
  let toolDefValid = $state(true);

  // Unsaved-changes guard — snapshot the form state once it's seeded from
  // `initial`, then derive `dirty` by comparing current field values to the
  // snapshot. Modal `onCloseRequest` + Cancel button prompt before discard;
  // `useDirtyForm` also catches sidebar navigation away from the form.
  const form = useDirtyForm();
  let snapshot = $state<string | null>(null);
  function fieldSignature() {
    return JSON.stringify([
      idField, title, description, risk, enabled, priority, modelFilter, appFilter,
      mcpServerFilter, a2aAgentFilter,
      phase, scope, conditions, actionKind, replaceRegex, replaceWith, replaceDrop,
      toolDef, interceptKind, frameworkRefs,
    ]);
  }

  // Sandbox preview for `replace`. The preview applies the regex/with/drop
  // pair against a sample string so operators can validate the rewrite
  // before saving — same semantics as the server-side apply_replacement.
  let sampleText = $state('');
  let replacePreview = $derived.by(() => {
    if (actionKind !== 'replace') return '';
    if (replaceDrop) return '';
    const repl = replaceWith || '[redacted]';
    if (!replaceRegex) return repl;
    try {
      const re = new RegExp(replaceRegex, 'g');
      return sampleText.replace(re, repl);
    } catch (e) {
      return `(invalid regex: ${(e as Error).message})`;
    }
  });

  // ── Phase × Scope matrix (mirrors backend `scope_allows_action`) ─────
  // `resource_reads` (request + response) and `prompt_invocations`
  // (request) cover MCP `resources/read` and `prompts/get` with the same
  // rule shape as tool calls. `agent_calls` covers A2A: the request phase
  // screens the message the caller sends to a remote agent, the response phase
  // the agent's reply. It cannot block on the response — by then the remote
  // agent has already done the work.
  const SCOPES_BY_PHASE: Record<Phase, Scope[]> = {
    request: ['tool_definitions', 'tool_results', 'resource_reads', 'prompt_invocations', 'agent_calls'],
    response: ['tool_calls', 'resource_reads', 'agent_calls'],
  };
  // Mirrors the Rust matrix in `config/tool_rules.rs::scope_allows_action`, which is
  // keyed on (phase, scope) — a scope's actions are NOT the same in both phases. The
  // two scopes that appear in both: `resource_reads` and `agent_calls` can block on the
  // request, but not on the response (the read already happened / the agent has already
  // done the work). Offering `block` there would only earn a 400 on save.
  const ACTIONS_BY_PHASE_SCOPE: Record<Phase, Partial<Record<Scope, ActionKind[]>>> = {
    request: {
      tool_definitions: ['classify', 'block', 'substitute', 'intercept_only'],
      tool_results: ['classify', 'replace'],
      resource_reads: ['classify', 'block', 'replace'],
      prompt_invocations: ['classify', 'block', 'replace'],
      agent_calls: ['classify', 'block', 'replace'],
    },
    response: {
      tool_calls: ['classify', 'block', 'replace'],
      resource_reads: ['classify', 'replace'],
      agent_calls: ['classify', 'replace'],
    },
  };
  const CLASSIFY_ONLY: ActionKind[] = ['classify'];
  let scopeActions = $derived<ActionKind[]>(ACTIONS_BY_PHASE_SCOPE[phase][scope] ?? CLASSIFY_ONLY);
  // Rules pivot on a canonical id (`tool_id` / `resource_id` / `prompt_id`)
  // instead of name globs. `any_arg` scans every canonical field the profile
  // registry knows about for the tool — use it when one rule needs to match
  // across multiple tools with different canonical fields (e.g. `shell_exec`
  // `arg.command` OR `read_file` `arg.path`). `uri` and `prompt_id` cover the
  // MCP scopes.
  const TARGETS_BY_SCOPE: Record<Scope, string[]> = {
    tool_definitions: ['tool_id'],
    tool_results: ['tool_id', 'any_arg', 'arg.<field>', 'argv', 'argv[<n>]', 'content'],
    tool_calls: ['tool_id', 'any_arg', 'arg.<field>', 'argv', 'argv[<n>]'],
    resource_reads: ['resource_id', 'uri', 'arg.<field>', 'content'],
    prompt_invocations: ['prompt_id', 'arg.<field>'],
    agent_calls: ['content', 'data'],
  };

  // Normalise scope when phase changes — pick the first valid scope if
  // the current selection no longer applies.
  $effect(() => {
    const valid = SCOPES_BY_PHASE[phase];
    if (!valid.includes(scope)) scope = valid[0];
  });
  // Normalise actionKind when scope changes.
  $effect(() => {
    const valid = scopeActions;
    if (!valid.includes(actionKind)) actionKind = valid[0];
  });

  // ── Live "matches N of inventory" — server-side test endpoint, scope=tool_definitions only.
  // For other scopes the inventory has no example args/content to evaluate, so the counter
  // is hidden.
  let inventoryMatchCount = $state<number | null>(null);
  let inventoryMatchError = $state<string | null>(null);
  let testDebounce: ReturnType<typeof setTimeout> | null = null;

  function buildRulePayload(): DraftRule {
    const cleanConditions = conditions
      .filter((c) => c.target.trim())
      .map((c) => ({
        target: c.target.trim(),
        op: c.op,
        value: c.value,
      }));
    let action: DraftRule['action'];
    if (actionKind === 'replace') {
      action = {
        kind: 'replace',
        regex: replaceRegex || null,
        with: replaceWith || null,
        drop: replaceDrop,
      };
    } else if (actionKind === 'block') {
      action = { kind: 'block' };
    } else if (actionKind === 'substitute') {
      action = { kind: 'substitute', with: toolDef, intercept: interceptKind };
    } else if (actionKind === 'intercept_only') {
      action = { kind: 'intercept_only', handler: interceptKind };
    } else {
      action = { kind: 'classify' };
    }
    return {
      id: idField || null,
      title: title || null,
      description: description || null,
      risk,
      enabled,
      phase,
      scope,
      match: cleanConditions,
      action,
      priority,
      model_filter: modelFilter || null,
      app_filter: appFilter || null,
      mcp_server_filter: mcpServerFilter || null,
      a2a_agent_filter: a2aAgentFilter || null,
      framework_refs: frameworkRefs,
    };
  }

  $effect(() => {
    // React to anything that changes the rule shape; debounce.
    const _ = [
      phase, scope, actionKind, JSON.stringify(conditions),
      replaceRegex, replaceWith, replaceDrop, modelFilter,
      JSON.stringify(toolDef), JSON.stringify(interceptKind),
    ];
    void _;
    if (testDebounce) clearTimeout(testDebounce);
    if (!open || scope !== 'tool_definitions' || inventory.length === 0) {
      inventoryMatchCount = null;
      inventoryMatchError = null;
      return;
    }
    if (!conditions.some((c) => c.target === 'tool_id')) {
      inventoryMatchCount = null;
      return;
    }
    testDebounce = setTimeout(runInventoryTest, 300);
  });

  async function runInventoryTest() {
    inventoryMatchError = null;
    try {
      const ruleBody = buildRulePayload();
      const { data, error: err } = await adminApi.POST(
        '/api/v1/admin/tool-rules/actions/test',
        {
          body: {
            rule: ruleBody,
            sample_tool_names: inventory,
            sample_args: null,
            sample_content: null,
            sample_model: null,
          },
        },
      );
      if (err) {
        inventoryMatchError = extractError(err, 'Test failed');
        inventoryMatchCount = null;
      } else if (data) {
        inventoryMatchCount = data.matches.filter((m) => m.matched).length;
      }
    } catch (e) {
      inventoryMatchError = (e as Error).message;
      inventoryMatchCount = null;
    }
  }

  // ── Reset form on open / initial change. ─────────────────────────────
  $effect(() => {
    if (!open) {
      snapshot = null;
      return;
    }
    toolDefValid = true;
    if (initial) {
      idField = initial.id ?? '';
      title = initial.title ?? '';
      description = initial.description ?? '';
      risk = initial.risk;
      enabled = initial.enabled ?? true;
      phase = initial.phase;
      scope = initial.scope;
      conditions = (initial.match ?? []).map((c) => ({ ...c }));
      const a = initial.action;
      // Reset every variant's state before hydrating so a swap between
      // action kinds across consecutive edits never leaks stale fields
      // (e.g. a substitute's toolDef bleeding into the next classify rule).
      replaceRegex = '';
      replaceWith = '';
      replaceDrop = false;
      toolDef = { ...DEFAULT_TOOL_DEF };
      interceptKind = { ...DEFAULT_INTERCEPT };
      if (a.kind === 'replace') {
        actionKind = 'replace';
        replaceRegex = ('regex' in a && a.regex) || '';
        replaceWith = ('with' in a && a.with) || '';
        replaceDrop = ('drop' in a && a.drop) || false;
      } else if (a.kind === 'block') {
        actionKind = 'block';
      } else if (a.kind === 'substitute') {
        actionKind = 'substitute';
        toolDef = a.with;
        interceptKind = a.intercept;
      } else if (a.kind === 'intercept_only') {
        actionKind = 'intercept_only';
        interceptKind = a.handler;
      } else {
        actionKind = 'classify';
      }
      priority = initial.priority ?? 100;
      modelFilter = initial.model_filter ?? '';
      appFilter = initial.app_filter ?? '';
      mcpServerFilter = initial.mcp_server_filter ?? '';
      a2aAgentFilter = initial.a2a_agent_filter ?? '';
      frameworkRefs = [...(initial.framework_refs ?? [])];
    } else {
      idField = '';
      title = '';
      description = '';
      risk = 'safe';
      enabled = true;
      phase = 'request';
      scope = 'tool_definitions';
      conditions = [{ target: 'tool_id', op: 'equals', value: '' as unknown as Record<string, never> }];
      actionKind = 'classify';
      replaceRegex = '';
      replaceWith = '';
      replaceDrop = false;
      toolDef = { ...DEFAULT_TOOL_DEF };
      interceptKind = { ...DEFAULT_INTERCEPT };
      priority = 100;
      modelFilter = '';
      appFilter = '';
      mcpServerFilter = '';
      a2aAgentFilter = '';
      frameworkRefs = [];
    }
    error = null;
    // Capture the baseline after all writes settle so the dirty-derive
    // effect below doesn't see the transient mid-seed state as a change.
    queueMicrotask(() => {
      snapshot = fieldSignature();
      form.markClean();
    });
  });

  // Derive dirty by comparing current field values to the post-seed snapshot.
  $effect(() => {
    if (!open || snapshot === null) return;
    if (fieldSignature() !== snapshot) form.markDirty();
    else form.markClean();
  });

  function addCondition() {
    conditions = [
      ...conditions,
      { target: 'tool_id', op: 'equals', value: '' as unknown as Record<string, never> },
    ];
  }
  function removeCondition(i: number) {
    conditions = conditions.filter((_, j) => j !== i);
  }

  type Detector = components['schemas']['ToolRuleDetector'];
  /** Derived from the spec, never hand-listed — the engine owns the op set. */
  type ConditionOp = components['schemas']['Op'];

  /** The detector registry, owned by the gateway — the editor holds no list of
   *  its own, so a detector added to the engine shows up here on its own. */
  let detectors = $state<Detector[]>([]);
  $effect(() => {
    if (!open || detectors.length > 0) return;
    void (async () => {
      const { data } = await adminApi.GET('/api/v1/admin/tool-rule-detectors', {});
      if (data) detectors = data.detectors;
    })();
  });

  /** `argv` / `argv[<n>]` — whole shell tokens, so they take the exact-match
   *  ops as well as the pattern ones. Mirrors `parse_argv_target` server-side;
   *  a malformed index is refused on save. */
  function isArgvTarget(target: string): boolean {
    return target === 'argv' || /^argv\[\d+\]$/.test(target);
  }

  function setOp(i: number, op: ConditionOp) {
    const c = conditions[i];
    let value: unknown = c.value;
    // Normalise value shape per op: strings for glob/regex/equals, array of
    // strings for contains_any/in, a detector name for detector.
    if (op === 'contains_any' || op === 'contains_word_any' || op === 'in') {
      if (typeof value === 'string') value = [value].filter(Boolean);
      if (!Array.isArray(value)) value = [];
    } else if (op === 'detector') {
      // A carried-over glob is never a valid detector name, so land on a real
      // one rather than a value the API will reject.
      const names = detectors.map((d) => d.name);
      if (typeof value !== 'string' || !names.includes(value)) value = names[0] ?? '';
    } else {
      if (Array.isArray(value)) value = value.join('|');
      if (value == null) value = '';
    }
    conditions[i] = { ...c, op, value: value as Record<string, never> };
  }

  /** Which ops a target accepts, mirroring the server's validation matrix. */
  function opsForTarget(target: string): ReadonlyArray<ConditionOp> {
    const isCanonicalId =
      target === 'tool_id' || target === 'resource_id' || target === 'prompt_id';
    if (isCanonicalId) return ['equals', 'in'];
    const patternOps: ConditionOp[] = [
      'glob',
      'regex',
      'contains_any',
      'contains_word_any',
      'detector',
    ];
    return isArgvTarget(target) ? ['equals', 'in', ...patternOps] : patternOps;
  }

  function setTarget(i: number, target: string) {
    const c = conditions[i];
    // Reset the op when switching target so the UI never saves an invalid
    // (target, op) pair.
    const allowed = opsForTarget(target);
    if (allowed.includes(c.op)) {
      conditions[i] = { ...c, target };
    } else {
      // Reuse setOp's value-shape coercion to avoid drift.
      conditions[i] = { ...c, target };
      setOp(i, allowed[0] ?? 'glob');
    }
  }

  function setStringValue(i: number, v: string) {
    conditions[i] = { ...conditions[i], value: v as unknown as Record<string, never> };
  }

  function setArrayValue(i: number, idx: number, v: string) {
    const arr = Array.isArray(conditions[i].value) ? [...(conditions[i].value as unknown as string[])] : [];
    arr[idx] = v;
    conditions[i] = { ...conditions[i], value: arr as unknown as Record<string, never> };
  }
  function addArrayItem(i: number) {
    const arr = Array.isArray(conditions[i].value) ? [...(conditions[i].value as unknown as string[])] : [];
    arr.push('');
    conditions[i] = { ...conditions[i], value: arr as unknown as Record<string, never> };
  }
  function removeArrayItem(i: number, idx: number) {
    const arr = Array.isArray(conditions[i].value) ? [...(conditions[i].value as unknown as string[])] : [];
    arr.splice(idx, 1);
    conditions[i] = { ...conditions[i], value: arr as unknown as Record<string, never> };
  }

  async function save() {
    saving = true;
    error = null;
    const body = buildRulePayload();
    if (initial?.id) {
      // PATCH variant — same body shape, server re-validates.
      const { data, error: err } = await adminApi.PATCH(
        '/api/v1/admin/tool-rules/{id}',
        {
          params: { path: { id: initial.id } },
          body: {
            title: body.title,
            description: body.description,
            risk: body.risk,
            enabled: body.enabled,
            phase: body.phase,
            scope: body.scope,
            match: body.match,
            action: body.action,
            priority: body.priority,
            // PATCH uses `Option<Option<T>>` semantics on the server —
            // sending the field at all (even null) clears it; omitting
            // it leaves the existing value untouched. We're a full-form
            // editor, so always send the user's current input.
            model_filter: body.model_filter,
            app_filter: body.app_filter,
            mcp_server_filter: body.mcp_server_filter,
            a2a_agent_filter: body.a2a_agent_filter,
            framework_refs: body.framework_refs,
          },
        },
      );
      if (err) {
        error = extractError(err, 'Failed to save');
      } else if (data) {
        form.markClean();
        onsaved(data);
        onclose();
      }
    } else {
      const { data, error: err } = await adminApi.POST('/api/v1/admin/tool-rules', {
        body: {
          id: body.id,
          title: body.title,
          description: body.description,
          risk: body.risk,
          enabled: body.enabled,
          phase: body.phase,
          scope: body.scope,
          match: body.match,
          action: body.action,
          priority: body.priority,
          model_filter: body.model_filter,
          app_filter: body.app_filter,
          mcp_server_filter: body.mcp_server_filter,
          a2a_agent_filter: body.a2a_agent_filter,
          framework_refs: body.framework_refs,
          profile_id: defaultProfileId,
        },
      });
      if (err) {
        error = extractError(err, 'Failed to create');
      } else if (data) {
        form.markClean();
        onsaved(data);
        onclose();
      }
    }
    saving = false;
  }

  let actionHelp = $derived.by(() => {
    if (actionKind === 'block') {
      if (scope === 'tool_definitions') {
        return 'Request-side block: matching tool definitions are stripped from the request before it reaches the upstream model.';
      }
      return 'Response-side block: matching tool calls are suppressed after the model emits them; client sees a notice in their place.';
    }
    if (actionKind === 'replace') {
      if (scope === 'tool_results') {
        return replaceDrop
          ? 'The tool_result body will be replaced with an empty string before the upstream LLM sees it.'
          : replaceRegex
            ? 'The regex will be applied to the tool_result body; matches are rewritten with the replacement text.'
            : 'The entire tool_result body will be replaced with the replacement text (default "[redacted]").';
      }
      return replaceDrop
        ? 'The tool_call args object will be cleared to `{}` (effectively a no-op call). Use sparingly.'
        : replaceRegex
          ? 'The regex applies to the serialised args JSON; matches are rewritten with the replacement text. Per-field diffs are tracked in the session.'
          : 'The entire args object will be replaced with the literal text (default "[redacted]"). Probably not what you want — set a regex to target the leaking value.';
    }
    if (actionKind === 'substitute') {
      return 'Replace the matched tool definition wholesale and bind the in-proxy handler. The model sees the new tool def; calls to it are answered by the handler instead of being forwarded upstream.';
    }
    if (actionKind === 'intercept_only') {
      return 'Leave the matched tool definition untouched on the wire but bind the in-proxy handler. The model sees the original tool; calls to it are answered locally.';
    }
    return 'Classify-only: assigns a risk level. No enforcement action.';
  });

  // True when at least one condition has a `tool_id` target — required for
  // the inventory-match counter to be meaningful (the sandbox uses the
  // wire tool name as a stand-in for tool_id).
  let hasToolIdTarget = $derived(conditions.some((c) => c.target === 'tool_id'));
</script>

<FormModal
  {open}
  title={initial?.id ? 'Edit Rule' : 'New Rule'}
  {form}
  {error}
  {saving}
  saveLabel={initial?.id ? 'Save' : 'Create rule'}
  saveDisabled={!toolDefValid}
  saveDisabledHint="Fix the raw-JSON parse error before saving."
  maxWidth="max-w-3xl"
  {onclose}
  onsave={save}
>
    <!-- Identity -->
    <div class="grid grid-cols-3 gap-3">
      <FormField
        label="Rule ID"
        for="rule-id"
        class="col-span-1"
        help={initial?.is_builtin ? 'Builtin rule IDs are immutable.' : undefined}
      >
        <TextInput
          id="rule-id"
          bind:value={idField}
          placeholder={initial?.id ? initial.id : 'auto-UUID if empty'}
          readonly={!!initial?.is_builtin}
          mono
          class="read-only:opacity-60"
        />
      </FormField>
      <FormField label="Title" for="rule-title" class="col-span-2">
        <TextInput id="rule-title" bind:value={title} placeholder="Human-readable name" />
      </FormField>
    </div>

    <FormField label="Description" for="rule-desc">
      <TextInput id="rule-desc" bind:value={description} placeholder="Shown in tooltips and banners" />
    </FormField>

    <!-- Phase / Scope / Action -->
    <div class="grid grid-cols-3 gap-3">
      <FormField label="Phase" for="rule-phase">
        <SelectInput id="rule-phase" bind:value={phase}>
          <option value="request">Request</option>
          <option value="response">Response</option>
        </SelectInput>
      </FormField>
      <FormField label="Scope" for="rule-scope">
        <SelectInput id="rule-scope" bind:value={scope}>
          {#each SCOPES_BY_PHASE[phase] as s}
            <option value={s}>{s}</option>
          {/each}
        </SelectInput>
      </FormField>
      <FormField label="Action" for="rule-action">
        <SelectInput id="rule-action" bind:value={actionKind}>
          {#each scopeActions as a}
            <option value={a}>{a}</option>
          {/each}
        </SelectInput>
      </FormField>
    </div>

    <!-- Risk + Priority + Model filter + Enabled -->
    <div class="grid grid-cols-4 gap-3">
      <FormField label="Risk" for="rule-risk">
        <SelectInput id="rule-risk" bind:value={risk}>
          <option value="safe">Safe</option>
          <option value="caution">Caution</option>
          <option value="danger">Danger</option>
          <option value="unknown">Unknown</option>
        </SelectInput>
      </FormField>
      <FormField label="Priority" for="rule-priority" help="Lower wins. Default 100.">
        <NumberInput id="rule-priority" bind:value={priority} mono />
      </FormField>
      <FormField label="Model filter" for="rule-model">
        <TextInput id="rule-model" bind:value={modelFilter} placeholder="claude-* (optional)" mono />
      </FormField>
      <FormField label="Enabled">
        <label class="flex items-center gap-2 py-1.5 cursor-pointer">
          <input type="checkbox" bind:checked={enabled} class="w-4 h-4" />
          <span class="text-sm">{enabled ? 'Active' : 'Disabled'}</span>
        </label>
      </FormField>
    </div>

    <FormField label="App filter" for="rule-app">
      {#snippet hint()}<span class="text-[10px] normal-case opacity-60">(optional — restricts to specific clients)</span>{/snippet}
      <TextInput id="rule-app" bind:value={appFilter} placeholder="cursor-* | opencode | claude*" mono />
      {#snippet help()}Pipe-separated glob over the request <code>app_id</code>. Empty = any app.{/snippet}
    </FormField>

    <!-- Upstream pivots. Each confines the rule to one protocol's traffic: a rule
         with an MCP server filter never fires on an agent call, and vice versa. -->
    <div class="grid grid-cols-2 gap-3">
      <FormField label="MCP server filter" for="rule-mcp">
        <TextInput id="rule-mcp" bind:value={mcpServerFilter} placeholder="notion-prod | internal-*" mono />
        {#snippet help()}Pipe-separated glob over the MCP upstream server name. Empty = any upstream.{/snippet}
      </FormField>
      <FormField label="A2A agent filter" for="rule-a2a">
        <TextInput id="rule-a2a" bind:value={a2aAgentFilter} placeholder="partner-* | research-prod" mono />
        {#snippet help()}Pipe-separated glob over the A2A agent slug — the pivot of the <code>agent_calls</code> scope. Empty = any agent.{/snippet}
      </FormField>
    </div>

    <div class="p-3 rounded-lg bg-(--bg-primary)/50 text-xs text-(--text-secondary) border border-(--border)">
      {actionHelp}
    </div>

    <!-- Match conditions -->
    <div class="border border-(--border) rounded-lg p-3">
      <div class="flex items-center justify-between mb-2">
        <span class="text-xs uppercase tracking-wider text-(--text-secondary)">Match conditions (AND)</span>
        <button type="button" onclick={addCondition} class="text-xs text-(--accent) hover:underline">+ Add condition</button>
      </div>
      <p class="text-[10px] text-(--text-secondary) leading-relaxed mb-2">
        All conditions must succeed. Available targets for <code>{scope}</code>:
        {#each TARGETS_BY_SCOPE[scope] as t, i}
          <code class="font-mono">{t}</code>{#if i < TARGETS_BY_SCOPE[scope].length - 1}, {/if}
        {/each}.
        Empty list = catch-all (every item in scope).
      </p>
      <div class="space-y-2">
        {#each conditions as cond, i}
          <div class="flex flex-col gap-1 p-2 rounded-sm bg-(--bg-primary)/40 border border-(--border)">
            <div class="flex gap-2 items-center">
              <TextInput value={cond.target} oninput={(e) => setTarget(i, (e.currentTarget as HTMLInputElement).value)}
                placeholder="target (e.g. tool_id, arg.command)"
                mono
                class="w-48 text-xs" />
              <SelectInput value={cond.op} onchange={(e) => setOp(i, (e.currentTarget as HTMLSelectElement).value as ConditionOp)}
                class="w-auto text-xs">
                {#each opsForTarget(cond.target) as op (op)}
                  <option value={op}>{op}</option>
                {/each}
              </SelectInput>
              <button type="button" onclick={() => removeCondition(i)} aria-label="Remove condition"
                class="ml-auto p-1 text-(--text-secondary) hover:text-(--error) text-xs">✕</button>
            </div>
            {#if cond.op === 'contains_any' || cond.op === 'contains_word_any' || cond.op === 'in'}
              <div class="flex flex-col gap-1">
                {#each (Array.isArray(cond.value) ? cond.value : []) as v, idx (idx)}
                  <div class="flex gap-2 items-center">
                    <TextInput value={v} oninput={(e) => setArrayValue(i, idx, (e.currentTarget as HTMLInputElement).value)}
                      placeholder="substring"
                      mono
                      class="flex-1 text-xs" />
                    <button type="button" onclick={() => removeArrayItem(i, idx)} aria-label="Remove substring"
                      class="p-1 text-(--text-secondary) hover:text-(--error) text-xs">✕</button>
                  </div>
                {/each}
                <button type="button" onclick={() => addArrayItem(i)}
                  class="text-xs text-(--accent) hover:underline self-start">+ Add substring</button>
              </div>
            {:else if cond.op === 'detector'}
              {@const selectedName = typeof cond.value === 'string' ? cond.value : ''}
              {@const selected = detectors.find((d) => d.name === selectedName)}
              <SelectInput
                value={selectedName}
                onchange={(e) => setStringValue(i, (e.currentTarget as HTMLSelectElement).value)}
                class="text-xs">
                {#each detectors as d (d.name)}
                  <option value={d.name}>{d.label}</option>
                {/each}
              </SelectInput>
              {#if selected}
                <p class="text-[10px] text-(--text-secondary) leading-relaxed">
                  {selected.summary}
                </p>
              {/if}
            {:else}
              <TextInput
                value={typeof cond.value === 'string' ? cond.value : ''}
                oninput={(e) => setStringValue(i, (e.currentTarget as HTMLInputElement).value)}
                placeholder={cond.op === 'glob' ? 'Bash|*execute*' : 'sk-[A-Za-z0-9]+'}
                mono
                class="text-xs" />
            {/if}
          </div>
        {/each}
        {#if conditions.length === 0}
          <p class="text-[10px] text-(--text-secondary) italic">No conditions — this rule is a catch-all.</p>
        {/if}
      </div>
      {#if scope === 'tool_definitions' && hasToolIdTarget && inventory.length > 0}
        <p class="text-[10px] text-(--text-secondary) mt-2">
          {#if inventoryMatchError}
            <span class="text-(--error)">— {inventoryMatchError}</span>
          {:else if inventoryMatchCount !== null}
            <span class="text-(--accent)">name-matches {inventoryMatchCount} of your {inventory.length} tracked tools</span>
          {/if}
        </p>
      {/if}
    </div>

    {#if actionKind === 'substitute'}
      <details class="border border-(--border) rounded-lg p-3" open>
        <summary class="text-xs uppercase tracking-wider text-(--text-secondary) cursor-pointer">
          Replacement tool definition <span class="normal-case text-[10px]">(what the model sees)</span>
        </summary>
        <div class="mt-3">
          <ToolDefEditor initial={toolDef} onchange={(v) => toolDef = v} onvalidchange={(v) => toolDefValid = v} />
        </div>
      </details>
    {/if}

    {#if actionKind === 'substitute' || actionKind === 'intercept_only'}
      <details class="border border-(--border) rounded-lg p-3" open>
        <summary class="text-xs uppercase tracking-wider text-(--text-secondary) cursor-pointer">
          Intercept handler <span class="normal-case text-[10px]">(what answers when the model calls the tool)</span>
        </summary>
        <div class="mt-3">
          <InterceptKindEditor initial={interceptKind} onchange={(v) => interceptKind = v} />
        </div>
      </details>
    {/if}

    <!-- Replace-specific fields -->
    {#if actionKind === 'replace'}
      <details class="border border-(--border) rounded-lg p-3" open>
        <summary class="text-xs uppercase tracking-wider text-(--text-secondary) cursor-pointer">
          Replace details <span class="normal-case text-[10px] text-(--text-secondary)">(regex applies to the serialised content / args string)</span>
        </summary>
        <div class="mt-3 space-y-3">
          <FormField label="Regex" for="rule-regex">
            {#snippet hint()}<span class="normal-case text-[10px] text-(--text-secondary)">(optional — empty = wholesale rewrite)</span>{/snippet}
            <TextInput id="rule-regex" bind:value={replaceRegex} placeholder="sk-[A-Za-z0-9]+"
              disabled={replaceDrop} mono class="disabled:opacity-40" />
            {#snippet help()}Validated server-side. Supports <code>$1</code>-style capture references in the replacement.{/snippet}
          </FormField>
          <FormField label="Replacement" for="rule-with">
            <TextInput id="rule-with" bind:value={replaceWith} placeholder="[redacted]"
              disabled={replaceDrop} mono class="disabled:opacity-40" />
          </FormField>
          <label class="flex items-center gap-2 cursor-pointer">
            <input type="checkbox" bind:checked={replaceDrop} class="w-4 h-4" />
            <span class="text-sm">Drop content entirely (ignores regex / replacement)</span>
          </label>

          <!-- Sandbox preview -->
          <div class="pt-2 border-t border-(--border)">
            <FormField label="Try it" for="rule-sample">
              <TextArea id="rule-sample" bind:value={sampleText}
                placeholder="Paste a sample tool_result body or args JSON to see the replace applied"
                rows={2}
                mono />
            </FormField>
            {#if sampleText}
              <p class="text-[10px] uppercase tracking-wider text-(--text-secondary) mt-2">Result</p>
              <pre class="px-3 py-1.5 bg-(--bg-primary) border border-(--border) rounded-lg text-xs font-mono whitespace-pre-wrap">{replacePreview || '(empty)'}</pre>
            {/if}
          </div>
        </div>
      </details>
    {/if}
</FormModal>
