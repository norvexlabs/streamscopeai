// HTTP status codes carry semantic meaning, not category identity — they
// map to the success/warning/error CSS tokens, not the tag palette.

type StatusTone = 'success' | 'warning' | 'error' | 'neutral';

function statusCodeTone(code: number): StatusTone {
  if (code >= 200 && code < 300) return 'success';
  if (code >= 300 && code < 400) return 'neutral';
  if (code >= 400 && code < 500) return 'warning';
  if (code >= 500) return 'error';
  return 'neutral';
}

export function statusCodeColor(code: number): string {
  switch (statusCodeTone(code)) {
    case 'success': return 'var(--success)';
    case 'warning': return 'var(--warning)';
    case 'error': return 'var(--error)';
    default: return 'var(--text-tertiary)';
  }
}
