---
key: session_label
label: Session Labels
---


## Session Label Output

When you identify parent-child relationships between sessions, output `session_labels` entries with:

- `session_index`: the integer **S-index** of the CHILD session — the `N` in `S<N>` from the cluster listing. NEVER a UUID.
- `label_type`: `parent_session_id` (the only label type currently supported).
- `parent_session_index`: the integer **S-index** of the PARENT session — the `N` in `S<N>`. NEVER a UUID.
- `confidence`: `high` (strong evidence — spawn-style tool call in the parent plus temporal overlap) or `medium` (circumstantial — temporal overlap only, or content echo without a spawn tool call).
- `note`: one-sentence explanation of why you believe this is a parent-child link.
- `spawn_turn` (optional, may be null): the turn number in the PARENT session where the child was spawned, if identifiable from a tool call.
- `parent_spawn_point_index` (optional, may be null): when the PARENT session prints a `Detected spawn points` list (`[P0]`, `[P1]`, …), set this to the `P`-index whose prompt preview matches this child's first user message. This anchors the child to the EXACT spawn call — prefer it over `spawn_turn`, which our system will fill in from the confirmed point. Set it only to CONFIRM a listed spawn point; leave it null if none clearly matches (a spawn call with no matching child in the cluster must NOT be linked).

Refer to sessions ONLY by their S-index (`S0`, `S1`, …) as printed in the cluster. Our system maps each index back to the real session — you never handle or transcribe a session UUID.

Detection signals, strongest to weakest:
1. The PARENT's `Detected spawn points` block lists a spawn call (`[P<n>]`) whose prompt preview matches the child's first user message — the strongest signal; confirm it via `parent_spawn_point_index`. The block is detected deterministically from the parent's own tool calls, so you do not have to find the call yourself.
2. Parent has turns before AND after the child's lifetime, with a gap during it, and its last turn before the gap contains a spawn-style tool call (`Task`, `Agent`, `task`, `new_task`, `use_subagents`, `runSubagent`, `spawn_agent`, `delegate_to_agent`, `delegate_task`, `dispatch`, `dispatch_agent`, `subagent`).
3. Child's first user prompt echoes content from the parent's recent context.
4. Child session is significantly shorter than parent.

Only label relationships you are confident about — false positives are worse than missed links.

## Already-linked sessions and cluster scope

- A child session may already carry a parent link the client declared explicitly (the proxy records it with confidence `header` from an `X-Parent-Session-Id` header). Your proposed link is applied **only to a child that has no parent yet** — it never overrides an already-linked session. Don't re-propose a link for a child whose parent is already set; spend your effort on the unlinked ones.
- The cluster you receive is **already scoped to the workspaces this axis is assigned to**. Only sessions within that scope appear, so only propose links between sessions present in the cluster — a parent in another workspace will not be visible here, and that is expected, not a missing parent.
