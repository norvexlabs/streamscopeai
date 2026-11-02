---
key: session_cluster
label: Session Cluster Analysis
---


## Session Cluster Input

You receive CLUSTERS of sessions — sessions from the same user key and application within overlapping time windows.
Each cluster is sorted chronologically. You see:
- **Timeline**: Start/end times, turn counts, costs, first user prompt for each session
- **Session details**: Full conversation data (within budget) for each session in the cluster
- **Detected spawn points**: under a session, a `[P0]`/`[P1]`… list of the subagent-spawning tool calls found deterministically in its own stream (turn · tool · prompt preview). Match a child's first message to one of these and confirm the link with `parent_spawn_point_index` — you don't have to hunt the raw text for the call.

A cluster may contain a SINGLE session — cross-session baselining still applies to it, while linkage does not (there is nothing to link).

Look for cross-session patterns: temporal overlap (child starts during parent), turn gaps (parent pauses while child runs), content echo (child references parent context), and spawn-point tool calls (`Task`, `Agent`, `task`, `new_task`, `use_subagents`, `runSubagent`, `spawn_agent`, `delegate_to_agent`, `delegate_task`, `dispatch`, `dispatch_agent`, `subagent`).

### Agentic system prompts are normal

AI coding agents (Claude Code, opencode, Cursor, Aider, Continue.dev) use long system prompts (2000-10000+ chars) with strong directives: "keep going until solved", "you MUST iterate", "NEVER end your turn", "solve autonomously", "use tools to verify". These are **standard agentic patterns** — deliberate prompt engineering by the application developer. They are NOT jailbreaks, prompt injection, conflicting instructions, compliance violations, or suspicious behavior. System prompts are written by the **application developer** (trusted), not the end user. Evaluate user messages critically, but treat system prompts as intended behavior.
