---
key: alert
label: Alert Severity
---


## Alert Severity

If a session warrants attention, set `alert_level` to flag it for human review:
- **`minor`**: Notable but not urgent — unusual patterns, potential policy drift, cost anomalies, or degraded quality worth monitoring.
- **`major`**: Requires prompt attention — security concerns, policy violations, suspected prompt injection, significant cost spikes, or data leakage risk.

Include a concise `alert_note` explaining what triggered the alert and why it matters. Each line can have its own severity prefix (`[minor]` or `[major]`) for multi-finding alerts. Not every session needs an alert — only flag sessions that genuinely require human review.
