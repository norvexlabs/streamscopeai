// Domain → tag-palette and label mapping for a session link, as the API states
// it: what the linked session is (`SessionLinkKind`) and what the link was
// read from (`SessionLinkEvidence`). Presentation only — every decision about
// a link is the API's.

import type { TagColor } from '#lib/components/TagBadge.svelte';
import type { components } from '#lib/generated/api-types.js';
import { m } from '#lib/paraglide/messages.js';

type SessionLinkKind = components['schemas']['SessionLinkKind'];
type SessionLinkEvidence = components['schemas']['SessionLinkEvidence'];

export function linkageTag(evidence: SessionLinkEvidence): TagColor {
  switch (evidence) {
    case 'quote': return 'teal';
    case 'agent_high': return 'blue';
    case 'agent_medium': return 'violet';
  }
}

/** What the evidence chip says. */
export function linkEvidenceLabel(evidence: SessionLinkEvidence): string {
  switch (evidence) {
    case 'quote': return m.conv_link_evidence_quote();
    case 'agent_high': return m.conv_link_evidence_agent_high();
    case 'agent_medium': return m.conv_link_evidence_agent_medium();
  }
}

/** What a linked session is to the one it is linked to, as a card names it. */
export function linkedSessionLabel(kind: SessionLinkKind): string {
  switch (kind) {
    case 'sub_agent': return m.conv_sub_agent_session();
    case 'continuation': return m.conv_continuation_session();
  }
}

/** The way back from a linked session to the one it is linked to. */
export function linkBackLabel(kind: SessionLinkKind): string {
  switch (kind) {
    case 'sub_agent': return m.browse_session_parent();
    case 'continuation': return m.browse_session_continues();
  }
}

/** A list row's chip naming the session it is linked to. */
export function linkChipLabel(kind: SessionLinkKind): string {
  switch (kind) {
    case 'sub_agent': return m.session_row_parent();
    case 'continuation': return m.session_row_continues();
  }
}
