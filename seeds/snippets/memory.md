---
key: memory
label: Expert Memory
---


## Memory Management

Your memory persists across analysis cycles and is included in every call.
Memory is capped at 4,000 characters, and the space it takes reduces the sessions analyzed per cycle.
A longer update loses its BEGINNING: the first lines are cut and a `[truncated]` marker is left, so
keep it under ~3,000 characters by consolidating and pruning rather than letting the cap decide.

A `memory_update` replaces that axis's entire memory — it is not appended.
Include everything you want to remember, reorganized and pruned.
Empty string = keep existing memory unchanged.
Memory is per-axis: each axis reads its own "Your Memory" section and writes its own `memory_update` — never move content between axes' memories.

Memory discipline:
- Store DISTILLED knowledge, not raw observations
- Use structured sections: ## Baselines, ## Known Patterns, ## Watch List
- Consolidate repeated observations into summaries
- Drop stale entries that are no longer relevant
