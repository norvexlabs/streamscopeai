/**
 * Diff utilities for dual-view session detail.
 * Injection blocks are computed server-side — frontend only renders them.
 */

import type { components } from "#lib/generated/api-types.js";

type TransformDiff = components["schemas"]["TransformDiff"];

/** Structured injection block from the proxy (captured at transform time). */
export type InjectionBlock = components["schemas"]["InjectionBlock"];

/** Count transforms and errors from transform_diff metadata. */
export interface TransformSummary {
  requestTransforms: number;
  requestErrors: number;
  responseTransforms: number;
  blockedTools: number;
  responseBlockedTools: number;
  telemetryDropped: number;
  hasData: boolean;
}

export function summarizeTransforms(
  transformDiff: TransformDiff | null | undefined,
): TransformSummary {
  const reqPrograms = transformDiff?.transform_programs ?? [];
  const rspPrograms = transformDiff?.response_transform_programs ?? [];
  // An entry not applied stopped nothing: it is no blocked tool.
  const blocked = (transformDiff?.blocked_tools ?? []).filter((b) => !b.not_applied);
  const rspBlocked = (transformDiff?.response_blocked_tools ?? []).filter((b) => !b.not_applied);
  const telemetry = transformDiff?.telemetry_dropped ?? [];

  const requestTransforms = reqPrograms.filter((p) => p.outcome === 'modified').length;
  const requestErrors = reqPrograms.filter((p) => p.outcome === 'errored').length;
  const responseTransforms = rspPrograms.filter((p) => p.outcome === 'modified').length;

  return {
    requestTransforms,
    requestErrors,
    responseTransforms,
    blockedTools: blocked.length,
    responseBlockedTools: rspBlocked.length,
    telemetryDropped: telemetry.length,
    hasData:
      reqPrograms.length > 0 || rspPrograms.length > 0 || telemetry.length > 0,
  };
}

/** Format the telemetry_dropped list for a tooltip: "2 × anthropic_billing_header → openai_responses". */
export function formatTelemetryDropped(
  transformDiff: TransformDiff | null | undefined,
): string {
  const telemetry = transformDiff?.telemetry_dropped ?? [];
  if (telemetry.length === 0) return '';
  const counts = new Map<string, number>();
  for (const t of telemetry) {
    const key = `${t.kind} → ${t.target}`;
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  return Array.from(counts.entries())
    .map(([k, n]) => (n > 1 ? `${n} × ${k}` : k))
    .join(', ');
}
