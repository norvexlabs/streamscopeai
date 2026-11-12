/**
 * Which of a client profile's templates the quickstart wizard offers.
 *
 * A profile can carry several LLM-bearing templates for genuinely different
 * reasons — a native-protocol config and an OpenAI-compatible fallback, a
 * config file and the shell exports that go with it, a curl one-liner and the
 * SDK env vars. It can ALSO carry two that differ only in how the MCP half
 * authenticates (static key vs spec OAuth); those are one choice, picked later
 * on the MCP step, and listing both here would read as two clients.
 *
 * The distinguishing mark of an MCP-auth pair is its TITLE: the two are the
 * same name with `(static MCP key)` / `(MCP via OAuth)` appended. Collapsing on
 * `(kind, protocol)` instead swallows real siblings — it hid Aider's
 * `shell env for Anthropic` (the only place that render's key and base URL
 * live, and which Aider's own instructions tell the reader to look for) and
 * both of curl-generic's SDK env-var snippets, with no way to reach them.
 */

import type { McpAuthMode } from './api-types';

/** The subset of a template this module decides on. */
export interface TemplateChoice {
  /** Where the template writes a server the member's machine runs. */
  local_mcp?: 'none' | 'config' | 'project' | null;
  kind: string;
  protocol?: string | null;
  title: string;
  /** Where the config is written; absent for a print-only snippet. */
  filename?: string | null;
  /** How the MCP half authenticates; read it through `mcpAuthModeOf`. */
  mcp_auth_mode?: McpAuthMode | null;
}

/** How a template's MCP half authenticates: an absent mode is `static`, the
 *  server's default for a template that names none. */
export function mcpAuthModeOf(t: Pick<TemplateChoice, 'mcp_auth_mode'>): McpAuthMode {
  return t.mcp_auth_mode ?? 'static';
}

/**
 * Whether two templates are one picker entry: same kind, protocol and label
 * (an LLM config's MCP auth-mode pair differs only in its title suffix). The
 * one identity the picker and its selection share.
 */
export function sameGroup(a: TemplateChoice, b: TemplateChoice): boolean {
  return (
    a.kind === b.kind &&
    (a.protocol ?? '') === (b.protocol ?? '') &&
    templateLabel(a.title) === templateLabel(b.title)
  );
}

/** A config template proper — `combined` or `llm`, not UI-setup notes. */
function isLlmConfig(t: { kind: string }): boolean {
  return t.kind === 'combined' || t.kind === 'llm';
}

/**
 * The LLM template a client starts on. Against a BYOK pass-through, `native`
 * is the protocol its server speaks and the config speaking it comes first —
 * the client's own credential is forwarded, and a vendor's token for its own
 * wire works on nothing else. Otherwise its first OpenAI-compatible config,
 * which works on every upstream, else its first LLM config — the static-MCP-key
 * one of an auth-mode pair every time. The same rule as
 * the server crate's `default_llm_template_index` (both locked by a seed
 * test), plus a last fallback to UI-setup notes for a client with no config
 * template — the CLI reaches those through its own fallback. A preference over
 * the profile's order, never a reorder: an installation records its template
 * by position.
 */
export function defaultLlmTemplateIndex<T extends TemplateChoice>(
  templates: readonly T[],
  native: string | null = null,
): number {
  const chat = (t: TemplateChoice) => t.protocol === 'chat_completions';
  const fixedKey = (t: TemplateChoice) => mcpAuthModeOf(t) === 'static';
  const speaksNative = (t: TemplateChoice) => native !== null && t.protocol === native;
  const preferences: Array<(t: TemplateChoice) => boolean> = [
    (t) => isLlmConfig(t) && speaksNative(t) && fixedKey(t),
    (t) => isLlmConfig(t) && speaksNative(t),
    (t) => isLlmConfig(t) && chat(t) && fixedKey(t),
    (t) => isLlmConfig(t) && chat(t),
    (t) => isLlmConfig(t) && fixedKey(t),
    isLlmConfig,
    templateNeedsLlm,
  ];
  for (const wanted of preferences) {
    const i = templates.findIndex(wanted);
    if (i >= 0) return i;
  }
  return -1;
}

/** An LLM-bearing template kind — one that needs a provider to render. */
export function templateNeedsLlm(t: { kind: string } | null | undefined): boolean {
  return !!t && (t.kind === 'llm' || t.kind === 'combined' || t.kind === 'instructions');
}

/**
 * Strip the MCP-auth-mode suffix so the two members of such a pair collapse to
 * one label. Any other title is returned unchanged, which is what keeps
 * genuinely different templates apart.
 */
export function templateLabel(title: string): string {
  return title
    .replace(/\s*\(static MCP key\)\s*$/i, '')
    .replace(/\s*\(MCP via OAuth\)\s*$/i, '');
}

/**
 * The LLM template choices to show, one entry per distinct config, the
 * file-writing OpenAI-compatible ones first and the rest in profile order —
 * `index` addresses the profile's `templates` array.
 */
export function llmTemplateGroups<T extends TemplateChoice>(
  templates: readonly T[]
): Array<{ index: number; label: string }> {
  const out: Array<{ index: number; label: string }> = [];
  templates.forEach((t, i) => {
    if (!templateNeedsLlm(t)) return;
    if (out.some((g) => sameGroup(templates[g.index], t))) return;
    out.push({ index: i, label: templateLabel(t.title) });
  });
  const chatConfig = (t: TemplateChoice) =>
    isLlmConfig(t) && !!t.filename && t.protocol === 'chat_completions';
  const rank = (g: { index: number }) => (chatConfig(templates[g.index]) ? 0 : 1);
  return out.sort((a, b) => rank(a) - rank(b));
}

/**
 * The picker entry a selected template belongs to: the group sharing its kind,
 * protocol and label (so an MCP-auth sibling shows as its group), else the
 * first entry. `index` addresses the profile's `templates` array.
 */
export function groupIndexFor<T extends TemplateChoice>(
  templates: readonly T[],
  index: number
): number | undefined {
  const groups = llmTemplateGroups(templates);
  const sel = templates[index];
  const same = sel ? groups.find((g) => sameGroup(templates[g.index], sel)) : undefined;
  return (same ?? groups[0])?.index;
}

/**
 * Whether the client writes both an OpenAI-compatible and a native Anthropic
 * config (print-only snippets don't count — their picker entries aren't
 * named as variants) — the one choice the wizard explains (the OpenAI-compatible one,
 * listed first, works with every model; the Anthropic one keeps Claude's
 * extended thinking and prompt caching intact).
 */
export function offersOpenAiAndAnthropic<T extends TemplateChoice>(templates: readonly T[]): boolean {
  const protocols = new Set(
    templates.filter((t) => isLlmConfig(t) && !!t.filename).map((t) => t.protocol ?? '')
  );
  return protocols.has('chat_completions') && protocols.has('anthropic_messages');
}

/**
 * The template the Quickstart's "MCP servers only" setup opens: the client's
 * MCP template that can write what the workspace offers. When the workspace
 * offers local servers — ones the member's machine runs — that is the first
 * MCP template writing one into the config the page renders
 * (`local_mcp: config`): it takes gateway servers as well, so it serves a
 * workspace offering both. Otherwise, with a gateway server to offer, the
 * client's first MCP template. `-1` when none fits: nothing offered, or only
 * local servers and no template that writes one here.
 */
export function mcpOnlyTemplateIndex<T extends TemplateChoice>(
  templates: readonly T[],
  offers: { gateway: boolean; local: boolean },
): number {
  if (offers.local) {
    const writesLocal = templates.findIndex((t) => t.kind === 'mcp' && t.local_mcp === 'config');
    if (writesLocal >= 0) return writesLocal;
  }
  return offers.gateway ? templates.findIndex((t) => t.kind === 'mcp') : -1;
}
