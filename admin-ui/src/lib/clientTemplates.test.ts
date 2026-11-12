import { describe, expect, it } from 'vitest';
import {
  defaultLlmTemplateIndex,
  groupIndexFor,
  llmTemplateGroups,
  mcpAuthModeOf,
  mcpOnlyTemplateIndex,
  offersOpenAiAndAnthropic,
  templateLabel,
  templateNeedsLlm,
} from '#lib/clientTemplates.js';
import { existsSync, readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * The shipped client-profile seeds. In the image build they are copied beside
 * the app (`_seed/`); from a checkout they are read out of the repo. Resolved
 * rather than skipped — a guard that quietly finds no seeds passes for the
 * wrong reason.
 */
function seedDir(): string {
  const candidates = [
    join(import.meta.dirname, '../../_seed/client_profiles'),
    join(import.meta.dirname, '../../../seeds/client_profiles'),
  ];
  const found = candidates.find(existsSync);
  if (!found) throw new Error(`client-profile seeds not found — looked in ${candidates.join(', ')}`);
  return found;
}

/**
 * The wizard shows ONE template per entry this returns, so an entry it drops is
 * a template the web user cannot reach at all. That is how Aider's
 * `shell env for Anthropic` — the only place that render's key and base URL
 * appear — became unreachable while Aider's own instructions pointed at it.
 */

const t = (kind: string, protocol: string | null, title: string) => ({ kind, protocol, title });

describe('templateNeedsLlm', () => {
  it('covers exactly the kinds that render against a provider', () => {
    expect(['llm', 'combined', 'instructions'].map((k) => templateNeedsLlm({ kind: k }))).toEqual([
      true,
      true,
      true,
    ]);
    expect(templateNeedsLlm({ kind: 'mcp' })).toBe(false);
    expect(templateNeedsLlm(null)).toBe(false);
  });
});

describe('mcpAuthModeOf', () => {
  it('reads an absent mode as static, the server default, and a stated one as stated', () => {
    expect(mcpAuthModeOf({})).toBe('static');
    expect(mcpAuthModeOf({ mcp_auth_mode: null })).toBe('static');
    expect(mcpAuthModeOf({ mcp_auth_mode: 'static' })).toBe('static');
    expect(mcpAuthModeOf({ mcp_auth_mode: 'spec_oauth' })).toBe('spec_oauth');
  });
});

describe('templateLabel', () => {
  it('strips only the MCP auth-mode suffix', () => {
    expect(templateLabel('Claude Code (static MCP key)')).toBe('Claude Code');
    expect(templateLabel('Claude Code (MCP via OAuth)')).toBe('Claude Code');
    // A parenthesised protocol variant is NOT an auth-mode suffix.
    expect(templateLabel('Aider · .aider.conf.yml (Anthropic)')).toBe(
      'Aider · .aider.conf.yml (Anthropic)'
    );
  });
});

describe('llmTemplateGroups', () => {
  it('collapses an MCP auth-mode pair into one choice', () => {
    const groups = llmTemplateGroups([
      t('combined', 'anthropic_messages', 'Claude Code (static MCP key)'),
      t('combined', 'anthropic_messages', 'Claude Code (MCP via OAuth)'),
    ]);
    expect(groups).toEqual([{ index: 0, label: 'Claude Code' }]);
  });

  it('keeps two templates that share (kind, protocol) but are different configs', () => {
    // The regression: keying on (kind, protocol) alone dropped the second.
    const groups = llmTemplateGroups([
      t('llm', 'anthropic_messages', 'Aider · .aider.conf.yml (Anthropic)'),
      t('llm', 'anthropic_messages', 'Aider · shell env for Anthropic'),
    ]);
    expect(groups.map((g) => g.index)).toEqual([0, 1]);
  });

  it('skips MCP-only templates', () => {
    const groups = llmTemplateGroups([
      t('mcp', null, 'Cursor · MCP server (static key)'),
      t('instructions', null, 'Cursor · Custom LLM (UI setup)'),
    ]);
    expect(groups).toEqual([{ index: 1, label: 'Cursor · Custom LLM (UI setup)' }]);
  });

  it('every LLM template in every shipped seed profile is reachable', () => {
    // The unit cases above are the rule; this is the inventory. A seed that
    // adds an unreachable LLM template fails here rather than in someone's
    // half-configured client.
    const dir = seedDir();
    const files = readdirSync(dir).filter((f) => f.endsWith('.json'));
    expect(files.length).toBeGreaterThanOrEqual(8);

    for (const f of files) {
      const profile = JSON.parse(readFileSync(join(dir, f), 'utf8'));
      const llm = profile.templates.filter(templateNeedsLlm);
      // The MCP auth-mode pairs are the ONLY legitimate collapse.
      const distinct = new Set(
        llm.map(
          (x: { kind: string; protocol?: string | null; title: string }) =>
            `${x.kind}|${x.protocol ?? ''}|${templateLabel(x.title)}`
        )
      );
      expect(llmTemplateGroups(profile.templates).length, `${f} hides an LLM template`).toBe(
        distinct.size
      );
    }
  });
});

/** A template that writes a file. */
const f = (kind: string, protocol: string | null, title: string) => ({
  kind,
  protocol,
  title,
  filename: '~/.cfg',
});

describe('offersOpenAiAndAnthropic', () => {
  it('needs both protocols as configs the client writes', () => {
    expect(
      offersOpenAiAndAnthropic([
        f('combined', 'anthropic_messages', 'OpenCode (Native Anthropic)'),
        f('combined', 'chat_completions', 'OpenCode (OpenAI-compatible)'),
        f('mcp', null, 'OpenCode · MCP only'),
      ])
    ).toBe(true);
    expect(offersOpenAiAndAnthropic([f('combined', 'chat_completions', 'Goose')])).toBe(false);
    expect(
      offersOpenAiAndAnthropic([
        f('combined', 'anthropic_messages', 'Claude Code (static MCP key)'),
        f('combined', 'anthropic_messages', 'Claude Code (MCP via OAuth)'),
      ])
    ).toBe(false);
    // Print-only snippets (curl-generic) are not named variants.
    expect(
      offersOpenAiAndAnthropic([
        t('llm', 'chat_completions', 'curl · OpenAI Chat Completions'),
        t('llm', 'anthropic_messages', 'curl · Anthropic Messages'),
      ])
    ).toBe(false);
    // UI-setup notes and MCP-only templates are not config variants.
    expect(
      offersOpenAiAndAnthropic([
        f('combined', 'chat_completions', 'X'),
        f('instructions', 'anthropic_messages', 'X · UI setup'),
        f('mcp', 'anthropic_messages', 'X · MCP'),
      ])
    ).toBe(false);
  });
});

describe('defaultLlmTemplateIndex', () => {
  it('prefers the OpenAI-compatible config over the profile order', () => {
    expect(
      defaultLlmTemplateIndex([
        f('combined', 'anthropic_messages', 'A'),
        f('combined', 'chat_completions', 'B'),
      ])
    ).toBe(1);
    expect(defaultLlmTemplateIndex([f('combined', 'anthropic_messages', 'Claude Code')])).toBe(0);
    // UI-setup notes only when nothing else renders an LLM.
    expect(
      defaultLlmTemplateIndex([f('mcp', null, 'Cursor · MCP'), t('instructions', null, 'Cursor · UI')])
    ).toBe(1);
    expect(defaultLlmTemplateIndex([f('mcp', null, 'MCP only')])).toBe(-1);
  });

  it('prefers the static-MCP-key one of an auth-mode pair', () => {
    const oauthFirst = [
      { ...f('combined', 'chat_completions', 'X (MCP via OAuth)'), mcp_auth_mode: 'spec_oauth' as const },
      { ...f('combined', 'chat_completions', 'X (static MCP key)'), mcp_auth_mode: 'static' as const },
    ];
    expect(defaultLlmTemplateIndex(oauthFirst)).toBe(1);
    const anthropicOnly = [
      { ...f('combined', 'anthropic_messages', 'C (MCP via OAuth)'), mcp_auth_mode: 'spec_oauth' as const },
      f('combined', 'anthropic_messages', 'C (static MCP key)'),
    ];
    expect(defaultLlmTemplateIndex(anthropicOnly)).toBe(1);
  });

  it("prefers the template speaking a pass-through's protocol, as the server rule does", () => {
    const profile = [
      f('combined', 'chat_completions', 'Chat'),
      { ...f('combined', 'anthropic_messages', 'Native (MCP via OAuth)'), mcp_auth_mode: 'spec_oauth' as const },
      f('combined', 'anthropic_messages', 'Native (static MCP key)'),
    ];
    expect(defaultLlmTemplateIndex(profile, 'anthropic_messages')).toBe(2);
    // No template speaks it: the ordinary default.
    expect(defaultLlmTemplateIndex(profile, 'google_gemini')).toBe(0);
    expect(defaultLlmTemplateIndex(profile, null)).toBe(0);
    expect(defaultLlmTemplateIndex(profile.slice(0, 2), 'anthropic_messages')).toBe(1);
  });


  it('every multi-protocol seed client starts on its OpenAI-compatible config', () => {
    // The twin of the crate's `every_multi_protocol_client_defaults_to_chat_completions`.
    const dir = seedDir();
    let multi = 0;
    for (const file of readdirSync(dir).filter((x) => x.endsWith('.json'))) {
      const profile = JSON.parse(readFileSync(join(dir, file), 'utf8'));
      const templates: Array<{ kind: string; protocol?: string | null; title: string }> =
        profile.templates;
      const protocols = new Set(
        templates.filter((x) => x.kind === 'combined' || x.kind === 'llm').map((x) => x.protocol)
      );
      if (protocols.size < 2) continue;
      multi += 1;
      const i = defaultLlmTemplateIndex(templates);
      expect(templates[i].protocol, `${file} starts on ${templates[i].title}`).toBe(
        'chat_completions'
      );
      expect(llmTemplateGroups(templates)[0].index, `${file} lists another variant first`).toBe(i);
    }
    expect(multi).toBeGreaterThanOrEqual(6);
  });
});

describe('llmTemplateGroups order', () => {
  it('lists the file-writing OpenAI-compatible configs first, the rest in profile order', () => {
    const groups = llmTemplateGroups([
      f('llm', 'anthropic_messages', 'Aider · conf (Anthropic)'),
      t('llm', 'anthropic_messages', 'Aider · shell env'),
      f('llm', 'chat_completions', 'Aider · conf (OpenAI-compatible)'),
    ]);
    expect(groups.map((g) => g.index)).toEqual([2, 0, 1]);
  });

  it('leaves print-only snippets in profile order', () => {
    // curl-generic: every entry is a snippet, so the curl group stays together.
    const groups = llmTemplateGroups([
      t('llm', 'chat_completions', 'curl · OpenAI Chat Completions'),
      t('llm', 'responses', 'curl · OpenAI Responses'),
      t('llm', 'chat_completions', 'OpenAI Python SDK · env vars'),
    ]);
    expect(groups.map((g) => g.index)).toEqual([0, 1, 2]);
  });
});

describe('groupIndexFor', () => {
  it('shows a selected MCP-auth sibling as its own group, whatever the order', () => {
    const templates = [
      f('combined', 'anthropic_messages', 'OpenCode (Native Anthropic) (static MCP key)'),
      f('combined', 'anthropic_messages', 'OpenCode (Native Anthropic) (MCP via OAuth)'),
      f('combined', 'chat_completions', 'OpenCode (OpenAI-compatible)'),
    ];
    // The chat group is listed first; the OAuth sibling still maps to Anthropic.
    expect(llmTemplateGroups(templates)[0].index).toBe(2);
    expect(groupIndexFor(templates, 1)).toBe(0);
    expect(groupIndexFor(templates, 2)).toBe(2);
    // Nothing selected → the first entry.
    expect(groupIndexFor(templates, -1)).toBe(2);
  });

  it('keeps a print-only snippet apart from the config sharing its protocol', () => {
    const templates = [
      t('llm', 'anthropic_messages', 'Aider · .aider.conf.yml (Native Anthropic)'),
      t('llm', 'anthropic_messages', 'Aider · shell env for Anthropic'),
    ];
    expect(groupIndexFor(templates, 1)).toBe(1);
  });
});

describe('mcpOnlyTemplateIndex', () => {
  const templates = [
    { kind: 'combined', title: 'Full', local_mcp: 'config' as const },
    { kind: 'mcp', title: 'MCP (sign-in)', local_mcp: 'none' as const },
    { kind: 'mcp', title: 'MCP (project)', local_mcp: 'project' as const },
    { kind: 'mcp', title: 'MCP (file)', local_mcp: 'config' as const },
  ];

  it('opens the first MCP template when the workspace offers gateway servers only', () => {
    expect(mcpOnlyTemplateIndex(templates, { gateway: true, local: false })).toBe(1);
  });

  it('opens the MCP template that writes a local server whenever local servers are offered', () => {
    // It writes gateway servers too, so it serves a workspace offering both.
    expect(mcpOnlyTemplateIndex(templates, { gateway: true, local: true })).toBe(3);
    expect(mcpOnlyTemplateIndex(templates, { gateway: false, local: true })).toBe(3);
  });

  it('falls back to the first MCP template when none writes a local server and a gateway one is offered', () => {
    expect(mcpOnlyTemplateIndex(templates.slice(0, 3), { gateway: true, local: true })).toBe(1);
  });

  it('finds none where nothing is offered, or nothing fits what is', () => {
    expect(mcpOnlyTemplateIndex(templates, { gateway: false, local: false })).toBe(-1);
    expect(mcpOnlyTemplateIndex(templates.slice(0, 3), { gateway: false, local: true })).toBe(-1);
    expect(mcpOnlyTemplateIndex(templates.slice(0, 1), { gateway: true, local: true })).toBe(-1);
  });
});
