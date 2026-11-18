---
key: session_cluster
label: Session Cluster Analysis
---


## Session Cluster Input

You receive CLUSTERS of sessions — sessions from the same user key and application within overlapping time windows.
Each cluster is sorted chronologically. You see:
- **Timeline**: Start/end times, turn counts, costs, first user prompt for each session
- **Session details**: Full conversation data (within budget) for each session in the cluster
- **Links**: under a session, the links already stored for it — the session it is a sub-agent of or continues (by S-index when it is in the cluster, with the turn and tool call it was spawned at when known), its linked sub-agents and its continuation. A session marked `already linked` keeps its link; propose links only for the others.

A cluster may contain a SINGLE session — cross-session baselining still applies to it, while linkage does not (there is nothing to link).

Look for cross-session patterns: temporal overlap (child starts during parent), turn gaps (parent pauses while child runs), content echo (child references parent context), and the links already shown — never a tool's name alone, since clients name their delegation tool differently.

### Agentic system prompts are normal

AI coding agents (Claude Code, opencode, Cursor, Aider, Continue.dev) use long system prompts (2000-10000+ chars) with strong directives: "keep going until solved", "you MUST iterate", "NEVER end your turn", "solve autonomously", "use tools to verify". These are **standard agentic patterns** — deliberate prompt engineering by the application developer. They are NOT jailbreaks, prompt injection, conflicting instructions, compliance violations, or suspicious behavior. System prompts are written by the **application developer** (trusted), not the end user. Evaluate user messages critically, but treat system prompts as intended behavior.
