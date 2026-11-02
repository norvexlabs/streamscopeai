import type { TagColor } from '#lib/components/TagBadge.svelte';

/** How an expert's input or output type is shown: a chip colour, a short
 *  label, and the sentence its tooltip carries. */
export type ExpertTypeInfo = { color: TagColor; label: string; hint: string };

const INPUT_TYPES: Record<string, ExpertTypeInfo> = {
  session: { color: 'teal', label: 'one session', hint: 'Reads each conversation on its own, turn by turn.' },
  session_cluster: {
    color: 'cyan',
    label: 'related sessions',
    hint: 'Reads clusters of sessions from the same key and app in overlapping time windows.',
  },
  tool_inventory: {
    color: 'orange',
    label: 'tool inventory',
    hint: 'Reads the tools seen across sessions: call counts, current risk levels, users and apps.',
  },
  security_frameworks: {
    color: 'rose',
    label: 'security frameworks',
    hint: 'Reads the OWASP LLM Top-10, MITRE ATLAS and CWE references its rules may cite.',
  },
  memory: { color: 'violet', label: 'memory', hint: 'Reads the notes it kept from earlier analysis cycles.' },
};

const OUTPUT_TYPES: Record<string, ExpertTypeInfo> = {
  alert: { color: 'amber', label: 'alerts', hint: 'Flags a session minor or major for human review.' },
  transform_suggestion: {
    color: 'violet',
    label: 'transforms',
    hint: 'Proposes request/response transform programs for an admin to approve.',
  },
  tool_rules: { color: 'rose', label: 'tool rules', hint: 'Proposes tool-policy rules for an admin to approve.' },
  field_profile_suggestion: {
    color: 'orange',
    label: 'field profiles',
    hint: "Proposes field profiles that map a tool's arguments so rules can target them.",
  },
  session_label: {
    color: 'indigo',
    label: 'session links',
    hint: 'Links a child session to the session that started it.',
  },
  memory: { color: 'violet', label: 'memory', hint: 'Keeps notes for its next analysis cycle.' },
};

/** Every input type, in display order: the agent's `ExpertInput`, held to it
 *  by `lint-expert-types.sh`. */
export const EXPERT_INPUT_TYPES: readonly string[] = Object.keys(INPUT_TYPES);

/** Every output type, in display order: the agent's `ExpertOutput`, held to
 *  it by `lint-expert-types.sh`. */
export const EXPERT_OUTPUT_TYPES: readonly string[] = Object.keys(OUTPUT_TYPES);

function fallback(t: string): ExpertTypeInfo {
  return { color: 'neutral', label: t.replace(/_/g, ' '), hint: t };
}

/** Display info for an expert input type (what it reads). */
export function inputTypeInfo(t: string): ExpertTypeInfo {
  return INPUT_TYPES[t] ?? fallback(t);
}

/** Display info for an expert output type (what it can produce). */
export function outputTypeInfo(t: string): ExpertTypeInfo {
  return OUTPUT_TYPES[t] ?? fallback(t);
}

/** An expert's display title from its axis: `cost_efficiency` → "Cost efficiency".
 *  The axis itself stays the identifier shown beside it. */
export function expertTitle(axis: string): string {
  const words = axis.replace(/[_-]+/g, ' ').trim();
  return words.charAt(0).toUpperCase() + words.slice(1);
}
