// GENERATED FILE — do not edit by hand.
// Source: seeds/providers/providers.json (the single source of provider identity).
// Regenerate: node scripts/regen-provider-catalog.mjs   (--check fails on drift).

export interface ProviderInfo {
  name: string;
  icon: string;
}

// Brand glyph + display name, keyed by the folded provider key (case/underscore
// insensitive). Includes icon-only registry entries (e.g. google, meta) surfaced
// in the downstream icon picker but not selectable as upstream providers.
export const PROVIDERS: Record<string, ProviderInfo> = {
  "openai": { name: "OpenAI", icon: "M22.28 14.37a5.86 5.86 0 00-.53-4.94 6.07 6.07 0 00-5.27-2.98 5.84 5.84 0 00-4.45-1.97 6.07 6.07 0 00-5.86 4.42 5.86 5.86 0 00-3.98 2.8 6.07 6.07 0 00.7 7.1 5.86 5.86 0 00.53 4.94 6.07 6.07 0 005.27 2.98 5.84 5.84 0 004.45 1.97 6.07 6.07 0 005.86-4.42 5.86 5.86 0 003.98-2.8 6.07 6.07 0 00-.7-7.1z" },
  "anthropic": { name: "Anthropic", icon: "M17.17 3.5h-3.4l5.75 17h3.4l-5.75-17zm-7.74 0L3.68 20.5h3.4l1.24-3.75h6.36l1.24 3.75h3.4L13.57 3.5h-4.14zm-.46 10.25L12 5.96l3.03 7.79H8.97z" },
  "googlegemini": { name: "Google Gemini", icon: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1.5 15.5l-5-5 1.41-1.41L10.5 14.67l7.09-7.09L19 9l-8.5 8.5z" },
  "groq": { name: "Groq", icon: "M13 2L3 14h8l-2 8 10-12h-8l2-8z" },
  "together": { name: "Together", icon: "M3 3h8v8H3V3zm10 0h8v8h-8V3zm-10 10h8v8H3v-8z" },
  "fireworks": { name: "Fireworks", icon: "M12 2l2.4 7.4H22l-6.2 4.5 2.4 7.4L12 17l-6.2 4.3 2.4-7.4L2 9.4h7.6L12 2z" },
  "deepseek": { name: "DeepSeek", icon: "M11 3a8 8 0 100 16A8 8 0 0011 3zm0 2a6 6 0 110 12A6 6 0 0111 5zm7.71 9.29l2 2a1 1 0 01-1.42 1.42l-2-2a1 1 0 011.42-1.42z" },
  "mistral": { name: "Mistral", icon: "M3 3h4v4H3V3zm7 0h4v4h-4V3zm7 0h4v4h-4V3zM3 10h4v4H3v-4zm14 0h4v4h-4v-4zM3 17h4v4H3v-4zm7 0h4v4h-4v-4zm7 0h4v4h-4v-4z" },
  "openrouter": { name: "OpenRouter", icon: "M12 2L2 7v10l10 5 10-5V7L12 2zm0 2.5L19 9l-7 4.5L5 9l7-4.5zM4 10.5l7 4.5v6l-7-3.5v-7zm16 0v7L13 21v-6l7-4.5z" },
  "nvidia": { name: "NVIDIA", icon: "M12 5C7 5 3 9 2 12c1 3 5 7 10 7s9-4 10-7c-1-3-5-7-10-7zm0 3a4 4 0 110 8 4 4 0 010-8zm0 1.5a2.5 2.5 0 100 5 2.5 2.5 0 000-5z" },
  "xai": { name: "xAI", icon: "M4 4l7 8-7 8h4l5-5.7L18 20h4l-7-8 7-8h-4l-5 5.7L8 4H4z" },
  "cerebras": { name: "Cerebras", icon: "M12 2a10 10 0 100 20 10 10 0 000-20zm0 4a6 6 0 016 6h-2a4 4 0 00-4-4V6zm0 12a6 6 0 01-6-6h2a4 4 0 004 4v2z" },
  "sambanova": { name: "SambaNova", icon: "M4 12a8 8 0 018-8v4a4 4 0 00-4 4H4zm8 8a8 8 0 01-8-8h4a4 4 0 004 4v4zm8-8a8 8 0 01-8 8v-4a4 4 0 004-4h4zm-8-8a8 8 0 018 8h-4a4 4 0 00-4-4V4z" },
  "moonshot": { name: "Moonshot (Kimi)", icon: "M15 3a9 9 0 100 18 7 7 0 010-18z" },
  "hyperbolic": { name: "Hyperbolic", icon: "M3 21C7 13 17 11 21 3M3 3c4 8 14 10 18 18" },
  "baseten": { name: "Baseten", icon: "M12 2l9 5v10l-9 5-9-5V7l9-5zm0 2.3L5 8v8l7 3.7 7-3.7V8l-7-3.7z" },
  "cohere": { name: "Cohere", icon: "M8 8a4 4 0 014-4h4a4 4 0 010 8h-8a4 4 0 00-4 4 4 4 0 004 4h4a4 4 0 004-4" },
  "deepinfra": { name: "DeepInfra", icon: "M12 2L3 7v10l9 5 9-5V7l-9-5zm0 2.3l6.5 3.6-6.5 3.6-6.5-3.6L12 4.3zM5 9.4l6 3.3v6.6l-6-3.3V9.4zm14 0v6.6l-6 3.3v-6.6l6-3.3z" },
  "novita": { name: "Novita", icon: "M12 2a10 10 0 100 20 10 10 0 000-20zm0 3l5 8h-3.5L12 10l-1.5 3H7l5-8z" },
  "zhipu": { name: "Zhipu (GLM)", icon: "M4 4h16v4h-6v12h-4V8H4V4z" },
  "writer": { name: "Writer", icon: "M3 17.25V21h3.75L17.8 9.94l-3.75-3.75L3 17.25zM20.7 7.04a1 1 0 000-1.41l-2.34-2.34a1 1 0 00-1.41 0l-1.83 1.83 3.75 3.75 1.83-1.83z" },
  "perplexity": { name: "Perplexity", icon: "M12 2a10 10 0 100 20 10 10 0 000-20zm0 3l7 4.5-7 4.5-7-4.5L12 5zm-7 6.7l7 4.5v4.3l-7-4.5v-4.3zm14 0v4.3l-7 4.5v-4.3l7-4.5z" },
  "huggingface": { name: "Hugging Face", icon: "M12 2C6.5 2 2 6.5 2 12s4.5 10 10 10 10-4.5 10-10S17.5 2 12 2zM8.5 9.5a1.5 1.5 0 110 3 1.5 1.5 0 010-3zm7 0a1.5 1.5 0 110 3 1.5 1.5 0 010-3zM8 14.5h8a4 4 0 01-8 0z" },
  "siliconflow": { name: "SiliconFlow", icon: "M3 6h18v3H3V6zm0 5h18v3H3v-3zm0 5h13v3H3v-3z" },
  "llama": { name: "Llama (Meta)", icon: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15H9V9h2v8zm4 0h-2V9h2v8z" },
  "nebius": { name: "Nebius", icon: "M12 2l9 5v10l-9 5-9-5V7l9-5zm0 2.3L5 8v8l7 3.7 7-3.7V8l-7-3.7z" },
  "scaleway": { name: "Scaleway", icon: "M6 4h12v4H6V4zm0 6h12v4H6v-4zm0 6h8v4H6v-4z" },
  "githubmodels": { name: "GitHub Models", icon: "M12 2a10 10 0 00-3.16 19.49c.5.09.68-.22.68-.48v-1.7c-2.78.6-3.37-1.34-3.37-1.34-.45-1.16-1.11-1.47-1.11-1.47-.91-.62.07-.6.07-.6 1 .07 1.53 1.03 1.53 1.03.9 1.53 2.36 1.09 2.94.83.09-.65.35-1.09.63-1.34-2.22-.25-4.55-1.11-4.55-4.94 0-1.09.39-1.98 1.03-2.68-.1-.25-.45-1.27.1-2.65 0 0 .84-.27 2.75 1.02a9.56 9.56 0 015 0c1.91-1.29 2.75-1.02 2.75-1.02.55 1.38.2 2.4.1 2.65.64.7 1.03 1.59 1.03 2.68 0 3.84-2.34 4.68-4.57 4.93.36.31.68.92.68 1.85v2.74c0 .27.18.58.69.48A10 10 0 0012 2z" },
  "inferencenet": { name: "Inference.net", icon: "M12 3a9 9 0 100 18 9 9 0 000-18zm0 4l5 3-5 3-5-3 5-3zm-5 6l5 3 5-3v3l-5 3-5-3v-3z" },
  "chutes": { name: "Chutes", icon: "M12 2a9 9 0 00-9 9h3a6 6 0 0112 0h3a9 9 0 00-9-9zm-6 9l6 11 6-11H6z" },
  "ollama": { name: "Ollama", icon: "M12 2a8 8 0 00-8 8v4a8 8 0 0016 0v-4a8 8 0 00-8-8zm-3 9a1.5 1.5 0 110-3 1.5 1.5 0 010 3zm6 0a1.5 1.5 0 110-3 1.5 1.5 0 010 3zm-3 4c-1.66 0-3-.67-3-1.5S10.34 12 12 12s3 .67 3 1.5-1.34 1.5-3 1.5z" },
  "vllm": { name: "vLLM", icon: "M4 4l8 16 8-16H4z" },
  "azureopenai": { name: "Azure OpenAI", icon: "M12 2L2 9l4 11h12l4-11L12 2zm0 3.6L18.7 10l-2.8 7.5H8.1L5.3 10 12 5.6z" },
  "awsbedrock": { name: "AWS Bedrock", icon: "M2 6l10-4 10 4v12l-10 4L2 18V6zm2 2v8l8 3.2 8-3.2V8l-8-3.2L4 8z" },
  "googlevertex": { name: "Google Vertex", icon: "M12 8a4 4 0 100 8 4 4 0 000-8zM6 2a3 3 0 100 6 3 3 0 000-6zm12 0a3 3 0 100 6 3 3 0 000-6zM6 16a3 3 0 100 6 3 3 0 000-6zm12 0a3 3 0 100 6 3 3 0 000-6z" },
  "custom": { name: "Custom", icon: "M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9" },
  "google": { name: "Google", icon: "M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" },
  "meta": { name: "Meta", icon: "M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2zm-1 15H9V9h2v8zm4 0h-2V9h2v8z" },
};

export function getProvider(key: string): ProviderInfo {
  const lower = key.toLowerCase().replace(/[_\s-]/g, '');
  if (PROVIDERS[lower]) return PROVIDERS[lower];
  const keys = Object.keys(PROVIDERS);
  for (let i = 0; i < keys.length; i++) {
    if (lower.indexOf(keys[i]) !== -1) return PROVIDERS[keys[i]];
  }
  return PROVIDERS.custom;
}

export interface ProviderDefault {
  value: string;
  label: string;
  defaultUrl: string;
  defaultApiFormat: string;
  defaultChatEndpointPath: string;
  /// How a new upstream for this provider is carried (URL shape + credential
  /// header). "default" is a plain bearer-auth endpoint.
  defaultTransport: string;
}

// Selectable upstream providers (icon-only entries excluded) with their default
// URL + native protocol, for the provider dropdown and URL auto-fill.
export const PROVIDER_DEFAULTS: ProviderDefault[] = [
  { value: "openai", label: "OpenAI", defaultUrl: "https://api.openai.com", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "anthropic", label: "Anthropic", defaultUrl: "https://api.anthropic.com", defaultApiFormat: "anthropic_messages", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "google_gemini", label: "Google Gemini", defaultUrl: "https://generativelanguage.googleapis.com", defaultApiFormat: "google_gemini", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "groq", label: "Groq", defaultUrl: "https://api.groq.com/openai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "together", label: "Together", defaultUrl: "https://api.together.xyz", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "fireworks", label: "Fireworks", defaultUrl: "https://api.fireworks.ai/inference", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "deepseek", label: "DeepSeek", defaultUrl: "https://api.deepseek.com", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "mistral", label: "Mistral", defaultUrl: "https://api.mistral.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "openrouter", label: "OpenRouter", defaultUrl: "https://openrouter.ai/api", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "nvidia", label: "NVIDIA", defaultUrl: "https://integrate.api.nvidia.com", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "xai", label: "xAI", defaultUrl: "https://api.x.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "cerebras", label: "Cerebras", defaultUrl: "https://api.cerebras.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "sambanova", label: "SambaNova", defaultUrl: "https://api.sambanova.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "moonshot", label: "Moonshot (Kimi)", defaultUrl: "https://api.moonshot.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "hyperbolic", label: "Hyperbolic", defaultUrl: "https://api.hyperbolic.xyz", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "baseten", label: "Baseten", defaultUrl: "https://inference.baseten.co", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "cohere", label: "Cohere", defaultUrl: "https://api.cohere.ai/compatibility", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "deepinfra", label: "DeepInfra", defaultUrl: "https://api.deepinfra.com/v1/openai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "/chat/completions", defaultTransport: "default" },
  { value: "novita", label: "Novita", defaultUrl: "https://api.novita.ai/v3/openai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "/chat/completions", defaultTransport: "default" },
  { value: "zhipu", label: "Zhipu (GLM)", defaultUrl: "https://api.z.ai/api/paas/v4", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "/chat/completions", defaultTransport: "default" },
  { value: "writer", label: "Writer", defaultUrl: "https://api.writer.com/v1", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "/chat", defaultTransport: "default" },
  { value: "perplexity", label: "Perplexity", defaultUrl: "https://api.perplexity.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "/chat/completions", defaultTransport: "default" },
  { value: "huggingface", label: "Hugging Face", defaultUrl: "https://router.huggingface.co", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "siliconflow", label: "SiliconFlow", defaultUrl: "https://api.siliconflow.com", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "llama", label: "Llama (Meta)", defaultUrl: "https://api.llama.com/compat", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "nebius", label: "Nebius", defaultUrl: "https://api.tokenfactory.nebius.com", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "scaleway", label: "Scaleway", defaultUrl: "https://api.scaleway.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "github_models", label: "GitHub Models", defaultUrl: "https://models.github.ai/inference", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "/chat/completions", defaultTransport: "default" },
  { value: "inference_net", label: "Inference.net", defaultUrl: "https://api.inference.net", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "chutes", label: "Chutes", defaultUrl: "https://llm.chutes.ai", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "ollama", label: "Ollama", defaultUrl: "", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "vllm", label: "vLLM", defaultUrl: "", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
  { value: "azure_openai", label: "Azure OpenAI", defaultUrl: "", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "azure_openai" },
  { value: "aws_bedrock", label: "AWS Bedrock", defaultUrl: "", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "aws_bedrock" },
  { value: "google_vertex", label: "Google Vertex", defaultUrl: "", defaultApiFormat: "google_gemini", defaultChatEndpointPath: "", defaultTransport: "google_vertex" },
  { value: "custom", label: "Custom", defaultUrl: "", defaultApiFormat: "chat_completions", defaultChatEndpointPath: "", defaultTransport: "default" },
];

export function providerDefaultUrl(value: string): string {
  return PROVIDER_DEFAULTS.find((p) => p.value === value)?.defaultUrl ?? '';
}

export function providerDefaultTransport(value: string): string {
  return PROVIDER_DEFAULTS.find((p) => p.value === value)?.defaultTransport ?? 'default';
}
