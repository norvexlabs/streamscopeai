// The provider catalog (labels, brand icons, default URLs, native protocols) is
// the single-source provider seed, exposed to the frontend as the generated
// module `#lib/generated/providers.js` (PROVIDER_DEFAULTS / PROVIDERS / getProvider /
// providerDefaultUrl). Do not re-add a hand-maintained provider list here.

import { m } from '#lib/paraglide/messages.js';

export const API_FORMATS = [
  { value: 'chat_completions', label: 'Chat Completions' },
  { value: 'responses', label: 'Responses' },
  { value: 'anthropic_messages', label: 'Anthropic Messages' },
  { value: 'google_gemini', label: 'Gemini' },
];

/** How the gateway carries a request to an upstream server — the URL shape and
 *  the header its credential rides in. Orthogonal to the protocol above: the
 *  transport decides addressing, `API_FORMATS` decides the body. */
export const UPSTREAM_TRANSPORTS = [
  { value: 'default', label: 'Standard (bearer token)' },
  { value: 'azure_openai', label: 'Azure OpenAI — API key' },
  { value: 'azure_openai_entra', label: 'Azure OpenAI — Microsoft Entra ID' },
  { value: 'aws_bedrock', label: 'Amazon Bedrock — API key' },
  { value: 'google_vertex', label: 'Google Vertex AI — service account' },
];

// Labels are message functions: the browse views render on the portal too.
export const FINISH_REASONS = [
  { value: 'stop', label: m.browse_finish_stop },
  { value: 'length', label: m.browse_finish_length },
  { value: 'tool_calls', label: m.browse_finish_tool_calls },
  { value: 'content_filter', label: m.browse_finish_content_filter },
  { value: 'error', label: m.browse_finish_error },
];

export const ERROR_CATEGORIES = [
  { value: 'upstream', label: m.browse_error_upstream },
  { value: 'auth', label: m.browse_error_auth },
  { value: 'rate_limit', label: m.browse_error_rate_limit },
  { value: 'bad_request', label: m.browse_error_bad_request },
  { value: 'model_not_found', label: m.browse_error_model_not_found },
  { value: 'internal', label: m.browse_error_internal },
  { value: 'client_disconnect', label: m.browse_error_client_disconnect },
  { value: 'timeout', label: m.browse_error_timeout },
  { value: 'stream_error', label: m.browse_error_stream_error },
];

/** The A2A 1.0 operations a caller addresses — the audit filter's choices. */
export const A2A_METHODS = [
  'SendMessage', 'SendStreamingMessage', 'GetTask', 'ListTasks', 'CancelTask',
  'SubscribeToTask', 'GetExtendedAgentCard',
];

/** The A2A 1.0 task lifecycle — the audit filter's choices. */
export const A2A_TASK_STATES = [
  { value: 'TASK_STATE_SUBMITTED', label: m.browse_task_submitted },
  { value: 'TASK_STATE_WORKING', label: m.browse_task_working },
  { value: 'TASK_STATE_COMPLETED', label: m.browse_task_completed },
  { value: 'TASK_STATE_FAILED', label: m.browse_task_failed },
  { value: 'TASK_STATE_CANCELED', label: m.browse_task_canceled },
  { value: 'TASK_STATE_REJECTED', label: m.browse_task_rejected },
  { value: 'TASK_STATE_INPUT_REQUIRED', label: m.browse_task_input_required },
  { value: 'TASK_STATE_AUTH_REQUIRED', label: m.browse_task_auth_required },
];

export const EXPERT_COLORS = [
  { value: '#6366f1', label: 'Indigo' },
  { value: '#ec4899', label: 'Pink' },
  { value: '#14b8a6', label: 'Teal' },
  { value: '#f97316', label: 'Orange' },
  { value: '#8b5cf6', label: 'Violet' },
  { value: '#06b6d4', label: 'Cyan' },
  { value: '#f43f5e', label: 'Rose' },
  { value: '#10b981', label: 'Emerald' },
  { value: '#eab308', label: 'Yellow' },
  { value: '#3b82f6', label: 'Blue' },
  { value: '#a855f7', label: 'Purple' },
  { value: '#ef4444', label: 'Red' }
];

// Fixed lookback for the incidental usage stats on config/management pages
// (LLM gateway, transforms, keys). These pages aren't analytics surfaces — the
// header period/workspace lens lives on dashboards only — so their usage panels
// render over a constant recent window with no interactive control.
export const CONFIG_USAGE_WINDOW_DAYS = 30;

/** Where this build's source is offered (AGPL-3.0 §13: every user of the console
 *  is offered the source of the version it runs — `SourceLink` links the
 *  release's tag, `v<version>`). A modified build points this at its own
 *  repository. */
export const SOURCE_REPOSITORY = 'https://github.com/norvexlabs/streamscopeai';
