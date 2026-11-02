/**
 * Central icon registry — all 24×24 outline SVG paths used by the admin UI.
 *
 * Source: Heroicons v2 outline (https://heroicons.com/), 1.75 stroke-width,
 * round caps/joins. Each `ICON.<name>` value is the raw `d` attribute, ready
 * to drop into `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor">`.
 *
 * Render via `<Icon name=… />` (glyph only) or `<IconTile name=… />` (glyph
 * inside a tinted square — card chrome). Never inline a new SVG path in a
 * component; add it here.
 *
 * Tones are category identity, not state. A `clock` icon for "Expiring
 * creds" is always `warning`-toned; a `clock` icon for "Latency" is always
 * `warning`-toned. The tile color never reacts to the count value displayed
 * next to it — state lives in the count text and inline trend chip.
 *
 * The five tones map to existing app.css palette pairs (`--<tone>-text` for
 * the glyph, `--<tone>-bg` for the tile):
 *   neutral · info · success · warning · error
 *
 * Set the default tone for each icon in `ICON_TONE`. Callers can override
 * per-callsite when the same glyph carries different meaning across pages.
 */

export const ICON = {
  // ── Status / category ───────────────────────────────────────────────
  alert:
    'M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z',
  blocked: 'M18.364 5.636 5.636 18.364M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
  clock: 'M12 6v6h4.5m4.5 0a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
  errorCircle:
    'M12 9v3.75m9-.75a9 9 0 1 1-18 0 9 9 0 0 1 18 0Zm-9 3.75h.008v.008H12v-.008Z',
  checkCircle: 'M9 12.75 11.25 15 15 9.75M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z',
  info: 'M13 16h-1v-4h-1m1-4h.01M21 12a9 9 0 11-18 0 9 9 0 0118 0z',

  // ── Trends ──────────────────────────────────────────────────────────
  arrowUp: 'M12 19V5m0 0l-6 6m6-6l6 6',
  arrowDown: 'M12 5v14m0 0l-6-6m6 6l6-6',
  trendingUp:
    'M2.25 18 9 11.25l4.306 4.306a11.95 11.95 0 0 1 5.814-5.518l2.74-1.22m0 0-5.94-2.281m5.94 2.28-2.28 5.941',

  // ── Dashboard cards ─────────────────────────────────────────────────
  /** Edge node / server stack — admin overview "Edge Nodes" tile. */
  edge:
    'M5.25 14.25h13.5m-13.5 0a3 3 0 0 1-3-3m3 3a3 3 0 1 0 0 6h13.5a3 3 0 1 0 0-6m-16.5-3a3 3 0 0 1 3-3h13.5a3 3 0 0 1 3 3m-19.5 0a4.5 4.5 0 0 1 .9-2.7L5.737 5.1a3.375 3.375 0 0 1 2.7-1.35h7.126c1.062 0 2.062.5 2.7 1.35l2.587 3.45a4.5 4.5 0 0 1 .9 2.7m-19.5 0h19.5',
  /** Trending rising arrow — "Requests" tile on overview / web / transforms. */
  requests: 'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6',
  /** Shield with check — every "Reliability" headline card. */
  reliability:
    'M9 12.75 11.25 15 15 9.75m-3-7.036A11.959 11.959 0 0 1 3.598 6 11.99 11.99 0 0 0 3 9.749c0 5.592 3.824 10.29 9 11.623 5.176-1.332 9-6.03 9-11.622 0-1.31-.21-2.571-.598-3.751h-.152c-3.196 0-6.1-1.248-8.25-3.285Z',
  /** Speech bubble — LLM "Tokens" tile. */
  tokens:
    'M7 8h10M7 12h4m1 8l-4-4H5a2 2 0 01-2-2V6a2 2 0 012-2h14a2 2 0 012 2v8a2 2 0 01-2 2h-3l-4 4z',
  /** Currency symbol — LLM "Cost" tile. */
  cost:
    'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1',
  /** Lightning bolt — "Anthropic Messages" protocol / "With transforms" tile. */
  bolt: 'M3.75 13.5l10.5-11.25L12 10.5h8.25L9.75 21.75 12 13.5H3.75z',
  /** Product mark — a peak over two waves (the Norvex Labs mark); the console's brand tile. */
  brand:
    'M3.36 9.6 L12 4.32 L20.64 9.6 M3.36 14.88 Q7.68 12 12 14.88 T20.64 14.88 M3.36 19.68 Q7.68 16.8 12 19.68 T20.64 19.68',
  /** Gear — settings / "Active transforms" tile / config screens. */
  settings:
    'M11 4a2 2 0 114 0v1a1 1 0 001 1h3a1 1 0 011 1v3a1 1 0 01-1 1h-1a2 2 0 100 4h1a1 1 0 011 1v3a1 1 0 01-1 1h-3a1 1 0 01-1-1v-1a2 2 0 10-4 0v1a1 1 0 01-1 1H7a1 1 0 01-1-1v-3a1 1 0 00-1-1H4a2 2 0 110-4h1a1 1 0 001-1V7a1 1 0 011-1h3a1 1 0 001-1V4z',
  /** Login / filter arrow — web "Filtered · Hosts" tile. */
  filtered:
    'M10 15l-3-3m0 0l3-3m-3 3h12m-3 3v1a2 2 0 01-2 2H6a2 2 0 01-2-2V5a2 2 0 012-2h11a2 2 0 012 2v1',
  /** Clipboard with check — experts "Analyzed" tile. */
  clipboardCheck:
    'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-6 9l2 2 4-4',
  /** Light bulb — experts "Suggestions" tile. */
  lightbulb:
    'M9.663 17h4.673M12 3v1m6.364 1.636l-.707.707M21 12h-1M4 12H3m3.343-5.657l-.707-.707m2.828 9.9a5 5 0 117.072 0l-.548.547A3.374 3.374 0 0014 18.469V19a2 2 0 11-4 0v-.531c0-.895-.356-1.754-.988-2.386l-.548-.547z',

  // ── Protocol cards (proxy dashboard) ────────────────────────────────
  /** Chat bubble with three dots — "Chat Completions". */
  chat:
    'M8 12h.01M12 12h.01M16 12h.01M21 12c0 4.418-4.03 8-9 8a9.863 9.863 0 01-4.255-.949L3 20l1.395-3.72C3.512 15.042 3 13.574 3 12c0-4.418 4.03-8 9-8s9 3.582 9 8z',
  /** Document with lines — "Responses". */
  document:
    'M9 12h6m-6 4h6m2 5H7a2 2 0 01-2-2V5a2 2 0 012-2h5.586a1 1 0 01.707.293l5.414 5.414a1 1 0 01.293.707V19a2 2 0 01-2 2z',
  /** Four-point star burst — "Google Gemini". */
  sparkles: 'M12 2l2.5 7.5L22 12l-7.5 2.5L12 22l-2.5-7.5L2 12l7.5-2.5L12 2z',

  /** Branch node with a curve — parent/child session linkage, cross-session. */
  gitBranch:
    'M6 3v12M9 18a3 3 0 11-6 0 3 3 0 016 0zM21 6a3 3 0 11-6 0 3 3 0 016 0zM18 9a9 9 0 01-9 9',

  // ── Storage / disk ──────────────────────────────────────────────────
  /** Single cylinder — disk / storage capacity tile. */
  storage:
    'M4 6c0-1.66 3.582-3 8-3s8 1.34 8 3m-16 0c0 1.66 3.582 3 8 3s8-1.34 8-3M4 6v12c0 1.66 3.582 3 8 3s8-1.34 8-3V6m-16 6c0 1.66 3.582 3 8 3s8-1.34 8-3',
  /** CPU/RAM chip — container memory-pressure tile. */
  memory:
    'M8.25 3v1.5M4.5 8.25H3m18 0h-1.5M4.5 12H3m18 0h-1.5m-15 3.75H3m18 0h-1.5M8.25 19.5V21M12 3v1.5m0 15V21m3.75-18v1.5m0 15V21m-9-1.5h10.5a2.25 2.25 0 0 0 2.25-2.25V6.75a2.25 2.25 0 0 0-2.25-2.25H6.75A2.25 2.25 0 0 0 4.5 6.75v10.5a2.25 2.25 0 0 0 2.25 2.25Zm.75-12h9v9h-9v-9Z',

  // ── Media modalities ────────────────────────────────────────────────
  /** Stacked-cylinders database — embedding modality. */
  embedding:
    'M4 7v10c0 2.21 3.582 4 8 4s8-1.79 8-4V7M4 7c0 2.21 3.582 4 8 4s8-1.79 8-4M4 7c0-2.21 3.582-4 8-4s8 1.79 8 4m0 5c0 2.21-3.582 4-8 4s-8-1.79-8-4',
  /** Musical-note speaker — audio modality. */
  audio:
    'M9 19V6l12-3v13M9 19c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zm12-3c0 1.105-1.343 2-3 2s-3-.895-3-2 1.343-2 3-2 3 .895 3 2zM9 10l12-3',
  /** Mountain landscape inside a frame — image modality. */
  image:
    'M2.25 15.75l5.159-5.159a2.25 2.25 0 013.182 0l5.159 5.159m-1.5-1.5l1.409-1.409a2.25 2.25 0 013.182 0l2.909 2.909M3.75 21h16.5A2.25 2.25 0 0022.5 18.75V5.25A2.25 2.25 0 0020.25 3H3.75A2.25 2.25 0 001.5 5.25v13.5A2.25 2.25 0 003.75 21z',
  /** Film-strip play button — video modality. */
  video:
    'M15 10l4.553-2.276A1 1 0 0121 8.618v6.764a1 1 0 01-1.447.894L15 14M5 18h8a2 2 0 002-2V8a2 2 0 00-2-2H5a2 2 0 00-2 2v8a2 2 0 002 2z',
  /** Open-book modality fallback. */
  book:
    'M12 6.253v13m0-13C10.832 5.477 9.246 5 7.5 5S4.168 5.477 3 6.253v13C4.168 18.477 5.754 18 7.5 18s3.332.477 4.5 1.253m0-13C13.168 5.477 14.754 5 16.5 5c1.747 0 3.332.477 4.5 1.253v13C19.832 18.477 18.247 18 16.5 18c-1.746 0-3.332.477-4.5 1.253',
  /** Pencil-on-paper / tool — MCP "Tool calls" tile. */
  wrench:
    'M11 5H6a2 2 0 00-2 2v11a2 2 0 002 2h11a2 2 0 002-2v-5m-1.414-9.414a2 2 0 112.828 2.828L11.828 15H9v-2.828l8.586-8.586z',
  /** Padlock — "Live tokens" / spec-OAuth tile. */
  lock:
    'M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z',
  /** Arrow down to tray — "Download" affordance. */
  download: 'M12 5v14m0 0l-4-4m4 4l4-4M4 19h16',

  // ── Navigation (sidebar leaves) ─────────────────────────────────────
  /** House with chimney — "Dashboard" parent / overview. */
  home:
    'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-4 0a1 1 0 01-1-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 01-1 1',
  /** Three horizontal bars — "LLM" gateway leaf. */
  bars3: 'M4 6h16M4 12h16M4 18h10',
  /** Document with bullet list — "Audit Log" leaf. */
  audit:
    'M9 5H7a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2V7a2 2 0 00-2-2h-2M9 5a2 2 0 002 2h2a2 2 0 002-2M9 5a2 2 0 012-2h2a2 2 0 012 2m-3 7h3m-3 4h3m-6-4h.01M9 16h.01',
  /** Shopping bag — "Tool Calls" leaf. */
  bag: 'M5 4h14l-1 5h-2.5l-1 11H7.5l-1-11H4l1-5z',
  /** Shield with check — "Policy" leaf (distinct from `reliability`). */
  policy:
    'M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z',
  /** Hex prism — "Gateways" subtree parent. */
  cube:
    'M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9',
  /** Building — "Tenants" platform leaf. */
  building:
    'M19 21V5a2 2 0 00-2-2H7a2 2 0 00-2 2v16m14 0h2m-2 0h-5m-9 0H3m2 0h5M9 7h1m-1 4h1m4-4h1m-1 4h1m-5 10v-5a1 1 0 011-1h2a1 1 0 011 1v5m-4 0h4',
  /** Globe with meridians — "Web" dashboard leaf. */
  globe:
    'M12 21a9 9 0 100-18 9 9 0 000 18zm0 0c2.485 0 4.5-4.03 4.5-9S14.485 3 12 3m0 18c-2.485 0-4.5-4.03-4.5-9S9.515 3 12 3m-9 9h18',
  /** Desktop monitor — "Clients" leaf. */
  desktop:
    'M9 17.25v1.007a3 3 0 01-.879 2.122L7.5 21h9l-.621-.621A3 3 0 0115 18.257V17.25m6-12V15a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 15V5.25m18 0A2.25 2.25 0 0018.75 3H5.25A2.25 2.25 0 003 5.25m18 0V12a2.25 2.25 0 01-2.25 2.25H5.25A2.25 2.25 0 013 12V5.25',
  /** Detailed gear (multi-tooth) — sidebar "Settings" leaf. */
  cog:
    'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065zM15 12a3 3 0 11-6 0 3 3 0 016 0z',
  /** Calendar grid — period-selector custom-range trigger. */
  calendar:
    'M6.75 3v2.25M17.25 3v2.25M3 18.75V7.5a2.25 2.25 0 0 1 2.25-2.25h13.5A2.25 2.25 0 0 1 21 7.5v11.25m-18 0A2.25 2.25 0 0 0 5.25 21h13.5A2.25 2.25 0 0 0 21 18.75m-18 0v-7.5A2.25 2.25 0 0 1 5.25 9h13.5A2.25 2.25 0 0 1 21 11.25v7.5',

  // ── Widget chrome (close, chevrons, check, search…) ─────────────────
  close: 'M6 18L18 6M6 6l12 12',
  check: 'M5 13l4 4L19 7',
  chevronUp: 'M5 15l7-7 7 7',
  chevronDown: 'M19 9l-7 7-7-7',
  chevronLeft: 'M15 19l-7-7 7-7',
  chevronRight: 'M9 5l7 7-7 7',
  arrowLeft: 'M10 19l-7-7m0 0l7-7m-7 7h18',
  arrowRight: 'M5 12h14M12 5l7 7-7 7',
  search: 'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z',
  plus: 'M12 4v16m8-8H4',
  pencil:
    'M15.232 5.232l3.536 3.536m-2.036-5.036a2.5 2.5 0 113.536 3.536L6.5 21.036H3v-3.572L16.732 3.732z',
  trash:
    'M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16',
  copy:
    'M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z',
  externalLink:
    'M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25',
  user:
    'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z',
  /** Key (api key, credential). */
  key:
    'M15 7a2 2 0 012 2m4 0a6 6 0 01-7.743 5.743L11 17H9v2H7v2H4a1 1 0 01-1-1v-2.586a1 1 0 01.293-.707l5.964-5.964A6 6 0 1121 9z',
  /** Group / team / multiple users. */
  users:
    'M15 19.128a9.38 9.38 0 0 0 2.625.372 9.337 9.337 0 0 0 4.121-.952 4.125 4.125 0 0 0-7.533-2.493M15 19.128v-.003c0-1.113-.285-2.16-.786-3.07M15 19.128v.106A12.318 12.318 0 0 1 8.624 21c-2.331 0-4.512-.645-6.374-1.766l-.001-.109a6.375 6.375 0 0 1 11.964-3.07M12 6.375a3.375 3.375 0 1 1-6.75 0 3.375 3.375 0 0 1 6.75 0Zm8.25 2.25a2.625 2.625 0 1 1-5.25 0 2.625 2.625 0 0 1 5.25 0Z',
  /** Filled triangle exclamation — destructive-action modal headers. */
  triangleAlert:
    'M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-2.5L13.732 4c-.77-.833-1.964-.833-2.732 0L3.732 16.5c-.77.833.192 2.5 1.732 2.5z',
  refresh:
    'M16.023 9.348h4.992v-.001M2.985 19.644v-4.992m0 0h4.992m-4.993 0 3.181 3.183a8.25 8.25 0 0 0 13.803-3.7M4.031 9.865a8.25 8.25 0 0 1 13.803-3.7l3.181 3.182M21.015 4.357v4.992',
  signOut:
    'M17 16l4-4m0 0l-4-4m4 4H7m6 4v1a3 3 0 01-3 3H6a3 3 0 01-3-3V7a3 3 0 013-3h4a3 3 0 013 3v1',

  // ── Audit-badge glyphs ──────────────────────────────────────────────
  /** Plain shield — `tool_blocked`, `mcp_sampling_intercepted`, SSRF refusals. */
  shield: 'M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z',
  /** Two arrows pointing in opposite directions — `protocol_translated`, substitution badges. */
  arrowsLR: 'M8 7h12m0 0l-4-4m4 4l-4 4M16 17H4m0 0l4 4m-4-4l4-4',
  /** Compass rose — `catchall` (request didn't match a dedicated route). */
  compass: 'M12 22a10 10 0 100-20 10 10 0 000 20zm3-13l-2 5-5 2 2-5 5-2z',
  /** Broom — `sanitized_tool_names`, `web_content_stripped`, `record_stripped`. */
  broom: 'M19 14l-7 7-1-1 7-7M14 9l5-5m0 0l-3 8M5 19l-2 2',
  /** Notification bell — `agent_alert`. */
  bell: 'M15 17h5l-1.405-1.405A2.032 2.032 0 0118 14.158V11a6.002 6.002 0 00-4-5.659V5a2 2 0 10-4 0v.341C7.67 6.165 6 8.388 6 11v3.159c0 .538-.214 1.055-.595 1.436L4 17h5m6 0v1a3 3 0 11-6 0v-1m6 0H9',
} as const;

export type IconName = keyof typeof ICON;

export type Tone = 'neutral' | 'info' | 'success' | 'warning' | 'error';

/** Glyph color per tone — light `-text` variant of the matching palette. */
export const TONE_FG: Record<Tone, string> = {
  neutral: 'var(--text-secondary)',
  info: 'var(--info-text)',
  success: 'var(--success-text)',
  warning: 'var(--warning-text)',
  error: 'var(--error-text)',
};

/** Tile background per tone — 10% alpha tint (`-bg`); neutral falls back
 *  to `--bg-elevated` since there's no `--neutral-bg`. */
export const TONE_BG: Record<Tone, string> = {
  neutral: 'var(--bg-elevated)',
  info: 'var(--info-bg)',
  success: 'var(--success-bg)',
  warning: 'var(--warning-bg)',
  error: 'var(--error-bg)',
};

/** Default category tone for each icon. Override per callsite when the same
 *  glyph carries different category meaning (e.g. `clock` is `info` for
 *  "Latency" but `warning` for "Expiring creds"). */
export const ICON_TONE: Record<IconName, Tone> = {
  // Status
  alert: 'warning',
  blocked: 'info',
  clock: 'warning',
  errorCircle: 'error',
  checkCircle: 'success',
  info: 'info',
  // Trends
  arrowUp: 'neutral',
  arrowDown: 'neutral',
  trendingUp: 'neutral',
  // Dashboard cards
  edge: 'info',
  requests: 'info',
  reliability: 'success',
  tokens: 'success',
  cost: 'warning',
  bolt: 'warning',
  brand: 'info',
  settings: 'info',
  filtered: 'info',
  clipboardCheck: 'info',
  lightbulb: 'info',
  // Protocol cards
  chat: 'success',
  document: 'info',
  sparkles: 'info',
  gitBranch: 'info',
  // Storage / disk
  storage: 'info',
  memory: 'info',
  // Media modalities
  embedding: 'info',
  audio: 'success',
  image: 'info',
  video: 'info',
  book: 'neutral',
  wrench: 'info',
  lock: 'info',
  download: 'neutral',
  // Navigation (all neutral — sidebar chrome, not category)
  home: 'neutral',
  bars3: 'neutral',
  audit: 'neutral',
  bag: 'neutral',
  policy: 'neutral',
  cube: 'neutral',
  building: 'neutral',
  globe: 'neutral',
  desktop: 'neutral',
  cog: 'neutral',
  calendar: 'neutral',
  // Widget chrome — neutral by default
  close: 'neutral',
  check: 'success',
  chevronUp: 'neutral',
  chevronDown: 'neutral',
  chevronLeft: 'neutral',
  chevronRight: 'neutral',
  arrowLeft: 'neutral',
  arrowRight: 'neutral',
  search: 'neutral',
  plus: 'neutral',
  pencil: 'neutral',
  trash: 'error',
  copy: 'neutral',
  externalLink: 'neutral',
  user: 'neutral',
  key: 'neutral',
  users: 'neutral',
  triangleAlert: 'error',
  refresh: 'neutral',
  signOut: 'neutral',
  // Audit-badge glyphs — `neutral` defaults; Badge entry.classes overrides color.
  shield: 'neutral',
  arrowsLR: 'neutral',
  compass: 'neutral',
  broom: 'neutral',
  bell: 'warning',
};

/** Pixel dimensions per size keyword. `xs` (12 px) is reserved for badge
 *  chips / dense inline contexts where a 16 px glyph would dominate
 *  surrounding 11 px text. */
export const ICON_SIZE_PX: Record<'xs' | 'sm' | 'md' | 'lg', number> = {
  xs: 12,
  sm: 16,
  md: 20,
  lg: 24,
};

/** Tile wrapper dimensions per icon size — tile is ~1.8× the glyph. */
export const TILE_SIZE_PX: Record<'sm' | 'md', number> = {
  sm: 28,
  md: 36,
};
