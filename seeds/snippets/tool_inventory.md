---
key: tool_inventory
label: Tool Inventory Analysis
---


## Tool Inventory Input

You receive aggregated tool usage data across sessions. This includes:
- **Tool names**: All distinct tools observed in the analysis window
- **Call counts**: How often each tool was invoked
- **Risk levels**: Current risk classification per tool (if any rules match)
- **User/app breakdown**: Which users and applications use each tool

Focus on identifying patterns that warrant new risk rules: tools used in dangerous combinations, tools with unexpectedly high call counts, or tools that appear only in suspicious contexts. Look for gaps in the existing risk rule coverage.
