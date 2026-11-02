FROM node:24-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS builder

WORKDIR /app

COPY admin-ui/package.json admin-ui/package-lock.json ./
RUN npm ci

# Vulnerability audit — fail on high/critical advisories in production dependencies.
RUN npm audit --audit-level=high --omit=dev

COPY admin-ui/ .

# Fail build on any Svelte warning (a11y, type errors, etc.)
RUN npm run check

# Component-level unit tier for the lib/ LOGIC surface — the path scoper whose
# output decides whether a path-scoped session cookie is sent, the badge
# collapsers, and the money formatters. `npm run check` types this code but
# executes none of it, and a browser test asserts pages rather than functions.
# Runs after `check` because both need the Paraglide messages `check` compiles.
# The unit tier's seed-reachability case reads the shipped client profiles: a
# profile carrying an LLM template the wizard cannot offer is a config the user
# can never obtain. Copied here rather than with the provider seed below
# because the test that reads it runs next.
COPY seeds/client_profiles/*.json ./_seed/client_profiles/
RUN npm run test:unit

# Fail build if the generated provider catalog (src/lib/generated/providers.ts)
# has drifted from the canonical provider seed (seeds/providers/providers.json).
# The seed is the single source of provider identity; the frontend module is
# generated from it — regenerate with `node scripts/regen-provider-catalog.mjs`.
COPY seeds/providers/providers.json ./_seed/providers.json
COPY scripts/regen-provider-catalog.mjs ./_scripts/regen-provider-catalog.mjs
RUN SEED_PATH=./_seed/providers.json OUT_PATH=./src/lib/generated/providers.ts \
    node ./_scripts/regen-provider-catalog.mjs --check

# Extract version from CHANGELOG.md — single source of truth.
COPY CHANGELOG.md ./
RUN export VITE_APP_VERSION=$(sed -n 's/^## \[\([^]]*\)\].*/\1/p' CHANGELOG.md | head -1) \
    && npm run build

# The third-party licence list the image ships: what the build bundled and the
# production dependencies. The script names the licences a package may carry;
# any other fails the build. Beside it, the SBOM of what the build bundled, which
# the release's SBOM merges in: no scanner sees a package compiled into the build.
RUN APP_VERSION=$(sed -n 's/^## \[\([^]]*\)\].*/\1/p' CHANGELOG.md | head -1) \
    node scripts/third-party-licenses.mjs --sbom /streamscopeai-console.cdx.json > /THIRD_PARTY_LICENSES

# The production dependencies the server runs on, installed where npm is: the
# runtime image carries the node binary alone, no npm. Beside them, Node.js's
# own licence (with the notices of what it bundles), from the release of the
# binary the image copies; the node image ships none. The checksum is that
# release's file: a node bump changes it, and the build says so.
FROM node:24-alpine3.24@sha256:06d7adf3e0ef61a13f1d28682726366f97a15aa1888c934d3ecec86c33918b53 AS deps
WORKDIR /app
COPY admin-ui/package.json admin-ui/package-lock.json ./
RUN npm ci --omit=dev
ARG NODEJS_LICENSE_SHA256=5888dbb9a1d2b18f2c3e6c5f6af1b39de658372b402a0577b002777f14c62ace
RUN wget -qO /NODEJS_LICENSE "https://raw.githubusercontent.com/nodejs/node/$(node --version)/LICENSE" && \
    echo "$NODEJS_LICENSE_SHA256  /NODEJS_LICENSE" | sha256sum -c - || \
    { echo "Node.js $(node --version)'s LICENSE is not the one NODEJS_LICENSE_SHA256 names: check it, then update the checksum" >&2; exit 1; }

# Plain Alpine, the base every runtime image shares, with the node binary of the
# builder's own image (built for this musl) and the two libraries it links.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a

RUN apk add --no-cache libstdc++ libgcc
COPY --from=deps /usr/local/bin/node /usr/local/bin/node

# Fixed uid/gid 65532 so the runtime user is identical and numeric across every
# deployment target (compose, Kairos VM, Kubernetes runAsUser). Keep it identical
# across the images, the chart and the release spec's volume ownership.
RUN addgroup -g 65532 streamscope && adduser -D -u 65532 -G streamscope -s /sbin/nologin streamscope

# The licence, the notices and the third-party licences ship with the console.
COPY LICENSE NOTICE /usr/share/licenses/streamscopeai/
COPY --from=builder /THIRD_PARTY_LICENSES /usr/share/licenses/streamscopeai/
COPY --from=deps /NODEJS_LICENSE /usr/share/licenses/streamscopeai/NODEJS_LICENSE
COPY --from=builder /streamscopeai-console.cdx.json /usr/share/sbom/streamscopeai-console.cdx.json
LABEL org.opencontainers.image.title="Streamscope AI console" \
      org.opencontainers.image.source="https://github.com/norvexlabs/streamscopeai" \
      org.opencontainers.image.licenses="AGPL-3.0-only" \
      org.opencontainers.image.base.name="docker.io/library/alpine:3.24.3"

WORKDIR /app

COPY --from=builder /app/build ./build
# The entrypoint in front of SvelteKit's handler (OIDC form_post relay). Only the
# runtime modules — the unit tests for them live under src/.
COPY --from=builder /app/server/entry.js /app/server/form-post-relay.js /app/server/origin.js /app/server/log.js ./server/
COPY --from=builder /app/package.json ./
COPY --from=deps /app/node_modules ./node_modules

RUN chown -R streamscope:streamscope /app

USER 65532

EXPOSE 3000

ENV PORT=3000

# Session cookies are marked `Secure` only when this is `production`, so it is
# a security setting, not a performance one — and it belongs on the image
# rather than on any one deploy shape. Setting it per-deployment is how the
# Kubernetes chart ended up serving session cookies over cleartext-eligible
# connections while the VM appliance, which sets it in its compose file, did
# not. Every shape runs this image; every shape gets the flag.
ENV NODE_ENV=production

# The most this server reads of any request body: above admin-api's own console
# body limit (2 MiB), so a body sent through the API forwarders reaches
# admin-api, which refuses one over its limit with a typed, audited answer.
# Every other route refuses a body that declares more than 512 KiB
# (`hooks.server.ts`); one declaring no length is bounded by this limit alone.
ENV BODY_SIZE_LIMIT=3M

# Not `node build`: the adapter's own server cannot take a provider's cross-site
# form_post before SvelteKit's CSRF check refuses it — see server/entry.js.
CMD ["node", "server/entry.js"]
