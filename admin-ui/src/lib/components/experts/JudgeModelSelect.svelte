<script lang="ts">
  /**
   * The judge-model picker: the alias the analysis agent sends for an expert
   * profile (or one expert). One option per alias, as the agent-models list
   * returns it, with the routes behind it. Offers only what the Agent workspace
   * is granted, the routes the agent can call; a stored value that is not
   * granted stays shown with a warning, never silently replaced.
   * Shared by the expert-profile page and the expert edit form.
   */
  import type { AgentModelOption } from '#lib/api-types.js';
  import SelectInput from '#lib/components/forms/SelectInput.svelte';

  interface Props {
    /** The stored alias; `''` is the empty option (inherit / no override). */
    value: string;
    models: AgentModelOption[];
    /** Label of the `''` option; omitted when a model is required. */
    emptyLabel?: string;
    disabled?: boolean;
    id?: string;
    /** False while the model list could not be loaded: the stored value is
     *  then shown as is, never called unserved. */
    loaded?: boolean;
  }

  let { value = $bindable(), models, emptyLabel, disabled = false, id, loaded = true }: Props = $props();

  const grantedTargets = (m: AgentModelOption) => m.targets.filter((t) => t.granted_to_agent);

  function optionLabel(m: AgentModelOption): string {
    const targets = grantedTargets(m);
    if (targets.length > 1) return `${m.alias} · ${targets.length} routes`;
    const t = targets[0];
    if (!t) return m.alias;
    return t.upstream_model === m.alias ? `${m.alias} · ${t.server_name}` : `${m.alias} · ${t.upstream_model} via ${t.server_name}`;
  }

  // The agent resolves a stored value as an alias first, then as an upstream
  // model name. Only an alias match names the option the agent sends, so only
  // it carries the grant check; a model-name match lists the aliases serving it.
  // `models` stays the whole list for these lookups, so a stored value that is
  // not granted is told apart from one that no longer resolves.
  const offered = $derived(models.filter((m) => m.granted_to_agent));
  const byAlias = $derived(value ? models.find((m) => m.alias === value) : undefined);
  const servingModel = $derived(
    value && !byAlias ? models.filter((m) => m.targets.some((t) => t.upstream_model === value)) : [],
  );
  const servingOffered = $derived(servingModel.filter((m) => m.granted_to_agent));
</script>

<SelectInput bind:value {disabled} {id}>
  {#if emptyLabel !== undefined}
    <option value="">{emptyLabel}</option>
  {/if}
  {#if value && !byAlias}
    <option value={value}>{value}{servingModel.length > 0 ? ' (model name)' : loaded ? ' (no longer served)' : ''}</option>
  {/if}
  {#if byAlias && !byAlias.granted_to_agent}
    <option value={byAlias.alias}>{byAlias.alias} (not granted)</option>
  {/if}
  {#each offered as m (m.alias)}
    <option value={m.alias}>{optionLabel(m)}</option>
  {/each}
  {#if emptyLabel === undefined && !value}
    <!-- A model is required and none is stored: say so instead of a blank box. -->
    <option value="" disabled>{loaded && offered.length === 0 ? 'No model is granted yet' : 'Choose a judge model'}</option>
  {/if}
</SelectInput>

{#if !loaded}
  <!-- The caller says why the list is missing. -->
{:else if servingModel.length > 0}
  {#if servingOffered.length > 0}
    <p class="text-xs text-(--text-secondary) mt-1.5">
      A model name, not an alias: the agent calls it through an alias serving it
      ({servingOffered.map((m) => m.alias).join(', ')}). Pick the alias to choose which.
    </p>
  {:else}
    <p class="text-xs text-(--warning) mt-1.5">
      The Agent workspace has no grant on a provider serving it, so the gateway refuses the agent's
      calls. Grant one in Workspaces › Agent › Access.
    </p>
  {/if}
{:else if value && !byAlias}
  <p class="text-xs text-(--warning) mt-1.5">
    No enabled text route serves <span class="font-mono">{value}</span>: analysis calls with it fail
    until a route is added or another model is picked.
  </p>
{:else if byAlias && !byAlias.granted_to_agent}
  <p class="text-xs text-(--warning) mt-1.5">
    The Agent workspace has no grant on a provider serving <span class="font-mono">{byAlias.alias}</span>,
    so the gateway refuses the agent's calls and analysis waits. Grant one in Workspaces › Agent › Access.
  </p>
{:else if byAlias && grantedTargets(byAlias).length > 1}
  <p class="text-xs text-(--text-secondary) mt-1.5">
    Routes to {grantedTargets(byAlias).map((t) => `${t.upstream_model} via ${t.server_name}`).join(', ')}.
  </p>
{/if}
{#if loaded && offered.length === 0}
  <p class="text-xs text-(--warning) mt-1.5">
    No model is granted to the Agent workspace. Grant a provider in Workspaces › Agent › Access.
  </p>
{/if}
