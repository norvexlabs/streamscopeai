---
key: session_label
label: Session Labels
---


## Session Label Output

When you identify parent-child relationships between sessions, output `session_labels` entries with:

- `session_index`: the integer **S-index** of the CHILD session — the `N` in `S<N>` from the cluster listing. NEVER a UUID.
- `label_type`: `parent_session_id` (the only label type currently supported).
- `parent_session_index`: the integer **S-index** of the PARENT session — the `N` in `S<N>`. NEVER a UUID.
- `confidence`: `high` (strong evidence — a call in the parent that hands the child its opening, plus temporal overlap) or `medium` (circumstantial — temporal overlap only, or content echo without such a call).
- `note`: one-sentence explanation of why you believe this is a parent-child link.
- `spawn_turn` (optional, may be null): the turn number in the PARENT session where the child was spawned, if identifiable from a tool call.

Refer to sessions ONLY by their S-index (`S0`, `S1`, …) as printed in the cluster. Our system maps each index back to the real session — you never handle or transcribe a session UUID.

Detection signals, strongest to weakest:
1. A tool call in the parent carries the text the child's first user message opens with — whatever the tool is named; clients name their delegation tool differently.
2. Parent has turns before AND after the child's lifetime, with a gap during it, and its last turn before the gap contains a tool call that delegates work.
3. Child's first user prompt echoes content from the parent's recent context.
4. Child session is significantly shorter than parent.

Only label relationships you are confident about — false positives are worse than missed links.

## Already-linked sessions and cluster scope

- A child session may already be linked: the gateway links a session whose opening quotes another (a subagent's prompt, a compaction's summary). The timeline marks it `already linked`, and its `Links` block names the session it is linked to and the links made to it. Your proposed link is applied **only to a session that has no link yet** — it never overrides an already-linked session. Don't re-propose a link for a session already linked; use the links shown as context and spend your effort on the unlinked ones.
- The cluster you receive is **already scoped to the workspaces this axis is assigned to**. Only sessions within that scope appear, so only propose links between sessions present in the cluster — a parent in another workspace will not be visible here, and that is expected, not a missing parent.
