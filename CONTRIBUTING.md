# Contributing

Thank you for considering a contribution. This page says what a contribution needs before it can be
merged: the licence agreement, a green build, and the rules a review will hold it to.

## Contributor Licence Agreement

Streamscope AI is dual-licensed: AGPL-3.0 for everyone, and a commercial licence sold by the
copyright holder ([COMMERCIAL.md](COMMERCIAL.md)). Offering both requires the copyright holder to
hold the rights to every line, so **a pull request can be merged only once its author has signed the
Contributor Licence Agreement (CLA)**. A bot asks you to sign on your first pull request; signing
once covers every later one. The CLA lets the copyright holder license your contribution under both
licences. You keep the copyright in your contribution.

**Pull requests are not open yet.** Until the CLA is published here and the bot is in place, a pull
request cannot be merged. Issues, bug reports and feature requests are welcome meanwhile.

## Reporting a security issue

Do not open a public issue for a vulnerability. Report it privately through the repository's
**Security** tab ("Report a vulnerability").

## Building from source

Everything builds in Docker; nothing else needs to be installed. From the repository root:

```bash
docker build -f docker/Dockerfile.proxy     -t streamscopeai-proxy .
docker build -f docker/Dockerfile.admin-api -t streamscopeai-admin-api .
docker build -f admin-ui/Dockerfile         -t streamscopeai-admin-ui .
docker build -f deploy/docker/Dockerfile.provision -t streamscopeai-provision .
```

Each application image builds its checks beside its binary and refuses to build when one fails:

| Image | Checks |
|---|---|
| proxy | `cargo clippy -D warnings` over the workspace, every workspace test, `cargo audit` |
| admin-api | `cargo clippy -D warnings`, `cargo audit` |
| admin-ui | `npm audit` (production dependencies), `svelte-check` with warnings fatal, the unit tests (`vitest`), the generated provider catalog against its seed |
| provision | none (a shell script on Alpine) |

A pull request is expected to build all four. The maintainers also run architectural checks and an
end-to-end suite before merging; a review may ask for a change those find.

The admin-api image bundles the `ssai` CLI for Linux and for Windows (`ssai.exe`, cross-built with
mingw-w64; the image lints its Windows-only code). Its tests run on Windows itself: on a Windows 11
x86_64 machine with the MSVC build tools and Rust, `cargo test -p streamscope-cli`; the image's mingw
build is then checked by installing it there. The macOS build of the CLI is made
separately on an Apple Silicon machine: generate its third-party licence list with
[cargo-about](https://github.com/EmbarkStudios/cargo-about) (`cargo about generate --fail --locked -m
crates/streamscope-cli/Cargo.toml -c docker/about.toml docker/about.hbs -o licenses.txt`), then
`SSAI_THIRD_PARTY_LICENSES=$PWD/licenses.txt cargo build --release -p streamscope-cli --target
aarch64-apple-darwin` (an absolute path: the build script runs in the crate's directory), and copy the binary to `artifacts/cli/ssai-darwin-arm64` before the image
build. An image built without it serves no macOS download.

A complete release (the images, the installer `ssai-stow`, the Helm chart and the VM images)
is packaged by [Stowage](https://github.com/norvexlabs/stowage) from `stowage.yaml`, pinned by
`stowage.lock`. To package your own, point the spec's `registry` at a registry you control, sign
with a key of your own, and list its public key under `signing.public_keys` in place of the
project's: the installers a release carries trust only the keys listed there.

## Versions and the changelog

`CHANGELOG.md` is the single source of the version: the build reads its first `## [` heading as
the version, so never add an `## [Unreleased]` heading, and never edit a version in `Cargo.toml` or
`package.json`. Describe a user-visible change, in product terms, in the pull request; the
maintainers write the changelog entry and set the version when they release.

## Rules a review holds a change to

**Tenant isolation** (every change that reads or writes the database)
- A tenant table carries `tenant_id UUID NOT NULL` with a foreign key to `tenants` and its
  row-level security policy, created in the same migration. Every key and index leads with
  `tenant_id`.
- Code reaches the database only through the `Db` types (`db.tenant(…)`, `db.begin_tenant(…)`, …);
  never through a raw pool, connection or transaction, which the crate's clippy configuration
  refuses. Never set the tenant setting by hand.
- Every `INSERT` binds `tenant_id` explicitly. A cross-tenant read uses one of the named global
  doors, and each use is read in review.
- An authorisation check or a tenant- or workspace-scoped query comes with a **negative** test
  (denied, other tenant, scope absent) beside the positive one.
- A read over a time window states the window on every audit table it joins (an outer-joined one
  in its join condition), through the shared window helpers: the database skips a table's old
  weeks only by a condition on that table.
- A read that renders a session turn by turn reads the messages each turn added
  (`conversation_turns_resolved.added_hashes`), never each turn's whole history: only a single
  request's trace, a session's first turn, a turn that starts a new baseline and a turn whose
  parent turn was not recorded read a whole history.

**Stored conversation content**
- A stored body — a conversation message, a tool set, a system prompt, a media blob — and the
  history chunks that list a turn's message hashes are written and deleted only in the admin
  crate's `content_store` module, and read there by tenant and key. A body may later move out of
  the database; its key, size and stamp stay database columns, and a history chunk, a list of keys,
  stays there whole.

**Database migrations**
- PostgreSQL 18 or newer, its database created with the built-in `PG_UNICODE_FAST` locale (UTF-8,
  `LC_CTYPE` `C.UTF-8`); admin-api refuses another. Both belong to the schema epoch.
- Forward-only and backward-compatible: the previous release must still run against the new schema.
  A schema change is a new numbered migration; a released migration is never edited.
- No `DROP`, `RENAME` or column-type change without a reasoned exception; never an expression
  index, and no GIN or GiST index on a table under forced row-level security.
- Every new table is owned by the application role.

**API**
- Errors use the shared error body with a typed, append-only error code; the UI branches on the
  code, never on the message.
- Lists are paged envelopes, never a bare array; an action is a `POST` to `…/actions/<verb>` and
  answers `200` with an action result (no `204`); a partial update is a `PATCH` in which an absent
  field means unchanged and `null` means cleared.
- JSON fields are `snake_case`; identifiers are UUIDs.
- Every mutating endpoint writes an audit record and has an end-to-end test.
- An endpoint is annotated for the OpenAPI spec, and the UI consumes the generated types; no
  `as any` and no `as Type` on a response. After changing an endpoint, save the output of
  `streamscopeai-admin --print-openapi` (the admin image's binary: the whole spec, minified, every
  endpoint listed) to `docs/openapi.json` and run `npm run generate-api` in `admin-ui/`; commit
  both files together.

**Security**
- API keys are stored hashed, upstream credentials encrypted; neither is ever serialised.
- Every outbound request to a URL a user or an upstream chose goes through the shared SSRF guard,
  and reaches a private address only when the platform's egress list for that kind of call lists it
  — a setting of the platform administrator, never an environment variable or a tenant's.
- Every external call has a timeout, and every response body is read through the capped reader.
- Upstream and database errors are never returned to a client.

**Rust**
- Edition 2024. No `unwrap()`/`expect()` unless provably infallible; typed errors.
- A runtime setting is read through the crate's settings module and listed in the settings
  catalog.
- A parser, matcher or canonicaliser of untrusted input comes with a property test, not only
  examples; a comparison against a limit is tested on both sides of the boundary.
- Translation onto a provider's wire format is written against the provider's current published
  specification, and tested by asserting the emitted shape for each target.

**Admin UI (SvelteKit, Svelte 5)**
- Runes only (`$state`, `$derived`, `$effect`, `$props`), shared state included — no `svelte/store`;
  typed API clients only, no raw `fetch`.
- TypeScript strict, no `any`; a `let` holding `$state` is typed on the rune (`$state<T>(…)`), never
  annotated (`let x: T = $state(…)`). Icons come from the icon registry; colours from the design tokens.
- Portal text is translated (`admin-ui/messages/en.json` and `fr.json`, identical key sets).
- Logic in `src/lib` that decides a path, an ordering, a currency or a state comes with a unit test
  beside it.

**Comments and docs**
- A comment states what the code does now and, where it is easy to break, the invariant to keep;
  never its history.
- A change to behaviour updates the Admin Guide or the Operator Guide in the same pull request.
