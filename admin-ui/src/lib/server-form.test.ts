import { describe, expect, it } from 'vitest';
import {
  applyProvider,
  applyTransport,
  canModelSync,
  isEmptyPatch,
  patchNeedsProbe,
  providerPublishesModelList,
  seedFor,
  serverPatch,
  transportOwnsUrl,
  urlRequired,
  type ProviderSeeds,
  type ServerForm,
} from './server-form';

const seeds: ProviderSeeds = {
  openai: { url: 'https://api.openai.com', apiFormat: 'chat_completions', chatEndpointPath: '', transport: 'default' },
  anthropic: { url: 'https://api.anthropic.com', apiFormat: 'anthropic_messages', chatEndpointPath: '', transport: 'default' },
  novita: { url: 'https://api.novita.ai/v3/openai', apiFormat: 'chat_completions', chatEndpointPath: '/chat/completions', transport: 'default' },
  vllm: { url: '', apiFormat: 'chat_completions', chatEndpointPath: '', transport: 'default' },
  azure_openai: { url: '', apiFormat: 'chat_completions', chatEndpointPath: '', transport: 'azure_openai' },
};

function form(over: Partial<ServerForm> = {}): ServerForm {
  return {
    name: 'srv',
    provider: 'openai',
    api_key: '',
    upstream_url: 'https://api.openai.com',
    upstream_api_format: 'chat_completions',
    chat_endpoint_path: '',
    transport: 'default',
    ...over,
  };
}

describe('seedFor', () => {
  it('prefers the catalog the running admin-api served', () => {
    expect(seedFor('openai', { openai: { url: 'http://mirror', apiFormat: 'responses', chatEndpointPath: '/c', transport: 'default' } }).url)
      .toBe('http://mirror');
  });

  it('falls back to the seed compiled into this build', () => {
    expect(seedFor('anthropic', {}).apiFormat).toBe('anthropic_messages');
  });
});

describe('applyProvider', () => {
  it('carries the new provider native protocol, not the one left over', () => {
    // A provider chosen for its own wire must arrive speaking it: leaving the
    // protocol behind builds an Anthropic server that talks Chat Completions.
    expect(applyProvider(form(), 'anthropic', seeds).upstream_api_format).toBe('anthropic_messages');
  });

  it('keeps a URL that was typed by hand', () => {
    const next = applyProvider(form({ upstream_url: 'http://my-gateway:9000' }), 'anthropic', seeds);
    expect(next.upstream_url).toBe('http://my-gateway:9000');
  });

  it('replaces a URL still holding the previous provider default', () => {
    // Otherwise the save probes the new provider's credential against the old
    // provider's host.
    expect(applyProvider(form(), 'anthropic', seeds).upstream_url).toBe('https://api.anthropic.com');
  });

  it('fills an empty URL, and empties it for a provider that has no default', () => {
    expect(applyProvider(form({ upstream_url: '' }), 'anthropic', seeds).upstream_url).toBe('https://api.anthropic.com');
    expect(applyProvider(form(), 'vllm', seeds).upstream_url).toBe('');
  });

  it('carries the seed endpoint path and drops one the new provider does not want', () => {
    expect(applyProvider(form(), 'novita', seeds).chat_endpoint_path).toBe('/chat/completions');
    expect(applyProvider(form({ provider: 'novita', chat_endpoint_path: '/chat/completions' }), 'openai', seeds).chat_endpoint_path).toBe('');
  });

  it('follows the provider transport and clears a path that transport forbids', () => {
    const next = applyProvider(form({ provider: 'novita', chat_endpoint_path: '/chat/completions' }), 'azure_openai', seeds);
    expect(next.transport).toBe('azure_openai');
    expect(next.chat_endpoint_path).toBe('');
  });

  it('leaves the address alone for a form that does not own it', () => {
    // A replicable server is addressed by its endpoints. A provider pick that
    // set the URL here would re-point the primary replica and leave its
    // siblings behind — from a field the form does not even show.
    const next = applyProvider(form(), 'anthropic', seeds, true);
    expect(next.upstream_url).toBe('https://api.openai.com');
    expect(next.provider).toBe('anthropic');
    // Everything the form DOES own still follows the provider.
    expect(next.upstream_api_format).toBe('anthropic_messages');
    // And the save carries no address, so no replica is touched.
    expect('upstream_url' in serverPatch(form(), next)).toBe(false);
  });

  it('leaves the name and the credential alone', () => {
    const next = applyProvider(form({ name: 'prod', api_key: 'sk-typed' }), 'anthropic', seeds);
    expect(next.name).toBe('prod');
    expect(next.api_key).toBe('sk-typed');
  });
});

describe('applyTransport', () => {
  it('clears the endpoint path exactly when the transport owns the URL', () => {
    expect(applyTransport(form({ chat_endpoint_path: '/chat' }), 'aws_bedrock').chat_endpoint_path).toBe('');
    expect(applyTransport(form({ chat_endpoint_path: '/chat' }), 'default').chat_endpoint_path).toBe('/chat');
  });

  it('drops an address that is only the provider default when the transport owns the URL', () => {
    // Otherwise `urlRequired` is satisfied by a value that cannot be right:
    // Azure appends `/openai/v1/…` to whatever it is given, so OpenAI's own
    // host passes every check and only the probe objects — which "Save anyway"
    // exists to overrule.
    const next = applyTransport(form(), 'azure_openai', seeds);
    expect(next.upstream_url).toBe('');
    expect(urlRequired(next, seeds, false)).toBe(true);
  });

  it('keeps an address that was typed by hand, and one under a plain transport', () => {
    expect(applyTransport(form({ upstream_url: 'https://my-resource.openai.azure.com' }), 'azure_openai', seeds).upstream_url)
      .toBe('https://my-resource.openai.azure.com');
    expect(applyTransport(form(), 'default', seeds).upstream_url).toBe('https://api.openai.com');
  });

  it('agrees with transportOwnsUrl', () => {
    expect(transportOwnsUrl('default')).toBe(false);
    for (const t of ['azure_openai', 'azure_openai_entra', 'aws_bedrock', 'google_vertex']) {
      expect(transportOwnsUrl(t)).toBe(true);
    }
  });
});

describe('urlRequired', () => {
  it('is satisfied by a provider default, demanded without one', () => {
    expect(urlRequired(form(), seeds, false)).toBe(false);
    expect(urlRequired(form({ provider: 'vllm' }), seeds, false)).toBe(true);
  });

  it('is demanded of a keyless pass-through whatever the provider', () => {
    expect(urlRequired(form(), seeds, true)).toBe(true);
  });

  it('is demanded by a transport that owns its URL, even for a provider that has one', () => {
    // Otherwise OpenAI's own host is handed to a transport that appends
    // `/openai/v1/…` to it, and only the probe ever says so.
    for (const transport of ['azure_openai', 'azure_openai_entra', 'aws_bedrock', 'google_vertex']) {
      expect(urlRequired(form({ transport }), seeds, false)).toBe(true);
    }
  });
});

describe('canModelSync', () => {
  it('needs BOTH halves — a provider that lists, on a transport that serves one', () => {
    expect(canModelSync({ provider: 'openai', transport: 'default' })).toBe(true);
    // The provider half alone is not enough…
    expect(canModelSync({ provider: 'openai', transport: 'google_vertex' })).toBe(false);
    // …and neither is the transport half.
    expect(canModelSync({ provider: 'perplexity', transport: 'default' })).toBe(false);
    expect(canModelSync({ provider: 'perplexity', transport: 'google_vertex' })).toBe(false);
    // An absent transport is the default one.
    expect(canModelSync({ provider: 'openai' })).toBe(true);
  });

  it('is one question, and Anthropic answers yes to it', () => {
    // Anthropic publishes a model list the gateway reads — at create, on an
    // explicit sync, and on the periodic re-check, which are the same read.
    // Answering no here freezes such a server on whatever it imported when it
    // was made, with no failure recorded anywhere to show for it.
    expect(providerPublishesModelList('anthropic')).toBe(true);
    expect(canModelSync({ provider: 'anthropic', transport: 'default' })).toBe(true);
    // The one provider that publishes none — however it was spelled on the
    // way in, because nothing normalises the stored value.
    expect(providerPublishesModelList('perplexity')).toBe(false);
    expect(providerPublishesModelList('Perplexity')).toBe(false);
    expect(providerPublishesModelList(' PERPLEXITY ')).toBe(false);
    expect(canModelSync({ provider: 'Perplexity', transport: 'default' })).toBe(false);
  });
});

describe('patchNeedsProbe', () => {
  it('is false for a patch the probe could not validate', () => {
    expect(patchNeedsProbe(serverPatch(form(), form({ name: 'renamed' })))).toBe(false);
    expect(patchNeedsProbe({})).toBe(false);
  });

  it('is true for every field the probe actually reads', () => {
    expect(patchNeedsProbe({ upstream_url: 'http://x' })).toBe(true);
    expect(patchNeedsProbe({ api_key: 'k' })).toBe(true);
    expect(patchNeedsProbe({ provider: 'anthropic' })).toBe(true);
    expect(patchNeedsProbe({ transport: 'aws_bedrock' })).toBe(true);
    expect(patchNeedsProbe({ upstream_api_format: 'responses' })).toBe(true);
    expect(patchNeedsProbe({ chat_endpoint_path: null })).toBe(true);
  });
});

describe('serverPatch', () => {
  it('sends nothing when nothing changed', () => {
    expect(isEmptyPatch(serverPatch(form(), form()))).toBe(true);
  });

  it('omits an untouched URL, so saving another field cannot disturb a replica', () => {
    // The API reads `upstream_url` as the primary endpoint's URL; echoing it
    // back on every save is how an unrelated edit resets a replica.
    const patch = serverPatch(form(), form({ name: 'renamed' }));
    expect(patch).toEqual({ name: 'renamed' });
    expect('upstream_url' in patch).toBe(false);
  });

  it('sends a changed URL', () => {
    expect(serverPatch(form(), form({ upstream_url: 'http://other:8000' })).upstream_url).toBe('http://other:8000');
  });

  it('clears a blanked field with an explicit null, not an empty string', () => {
    const patch = serverPatch(form({ chat_endpoint_path: '/chat' }), form({ chat_endpoint_path: '' }));
    expect(patch.chat_endpoint_path).toBeNull();
  });

  it('does not read a stray space in an address or a path as a change', () => {
    // An address "change" rewrites the primary endpoint and resets its
    // discovery, so a pasted trailing space must not count as one.
    expect(isEmptyPatch(serverPatch(form(), form({ upstream_url: 'https://api.openai.com ' })))).toBe(true);
    expect(isEmptyPatch(serverPatch(form({ chat_endpoint_path: '/chat' }), form({ chat_endpoint_path: ' /chat ' })))).toBe(true);
    expect(serverPatch(form(), form({ upstream_url: ' http://other:8000 ' })).upstream_url).toBe('http://other:8000');
  });

  it('treats an empty credential box as keep, a typed one as rotate', () => {
    expect('api_key' in serverPatch(form(), form())).toBe(false);
    expect(serverPatch(form(), form({ api_key: 'sk-new' })).api_key).toBe('sk-new');
  });

  it('trims a name, and does not report a stored one that has a space as edited', () => {
    // A name is unique: " prod" stored beside "prod" is a second server the
    // console renders identically to the first.
    expect(serverPatch(form(), form({ name: 'prod ' })).name).toBe('prod');
    expect(isEmptyPatch(serverPatch(form({ name: 'srv ' }), form({ name: 'srv' })))).toBe(true);
    expect(isEmptyPatch(serverPatch(form({ name: 'srv ' }), form({ name: 'srv ' })))).toBe(true);
  });

  it('carries a provider, protocol and transport change', () => {
    const patch = serverPatch(form(), form({ provider: 'anthropic', upstream_api_format: 'anthropic_messages', transport: 'aws_bedrock' }));
    expect(patch).toMatchObject({ provider: 'anthropic', upstream_api_format: 'anthropic_messages', transport: 'aws_bedrock' });
  });
});
