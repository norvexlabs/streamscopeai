# Admin Guide

How to **run the product** once the infrastructure is deployed and running
([Operator Guide](OPERATOR_GUIDE.md)). This is the handbook for the people who configure and
operate Streamscope through the web UI. It opens with what the product is and how it works, then
walks the day-2 setup in dependency order, across three roles:

- **Platform super-admin** — onboards tenants and runs the platform (section A).
- **Tenant admin** — sets up auth, providers, workspaces, users, and policy for one tenant
  (section B).
- **Workspace manager** — the elevated end-user who provisions keys for their team in the
  self-service portal (section C).

New tenant admin in a hurry? Jump to **[Getting started](#getting-started)** for the
half-hour zero-to-first-audited-request path, then dip into the sections below for depth.

## What Streamscope is

Streamscope AI is a gateway that sits between your AI applications and the upstream LLM providers
they call. Every request — from coding agents, chatbots, and autonomous pipelines — flows through
it, so you get **one place** for security, observability, governance, and automated optimization,
without changing a line of application code:

- **Credential isolation** — real provider keys never leave the server (encrypted at rest); users
  get scoped, instantly-revocable keys. Or let clients bring their own key (BYOK) and still get
  full governance.
- **One endpoint, any backend** — the gateway speaks OpenAI Chat Completions, OpenAI Responses,
  Anthropic Messages, and Google Gemini, and **translates between any pair**, so any client can
  talk to any provider. Swap models or providers without touching client config. Beyond chat, it
  also gateways embeddings, audio, image, and video endpoints.
- **Full audit trail** — every request logged with user, model, tokens, cost, latency, finish
  reason, and status — including auth failures, rate limits, and upstream errors. Optional full
  content capture for compliance.
- **Session replay** — agentic conversations are grouped into sessions and replayed turn-by-turn
  with tool calls, thinking blocks, and reasoning traces, including sub-agent linkage.
- **Cost control** — per-request cost tracking, with per-workspace, per-member, and per-key budgets
  and RPM/TPM rate limits.
- **Governance** — a tool-policy engine that classifies, blocks, or rewrites agent tool calls; Rhai
  transforms that redact, inject, or filter request/response content; and seven AI experts that
  continuously analyze traffic and propose rules and transforms.
- **MCP gateway & web tools** — the same auth, audit, policy, and budget controls extended to Model
  Context Protocol traffic, plus a built-in server-side web search/fetch.
- **A2A gateway** — the same controls extended to Agent2Agent traffic: register the remote agents
  your users delegate whole tasks to, govern and audit every call, and see agent-to-agent exchanges
  interleaved with the LLM and MCP calls that triggered them in session replay.
- **Multi-tenant** — serve many isolated customer tenants from one deployment, each with its own
  users, login page, config, and audit.

## How it works

```
client app ──▶ gateway ──▶ upstream provider
              (auth · routing + protocol
               translation · policy · audit)
                    ▲
                    │ live config sync (~2s)
              admin console ──▶ database
```

Clients point their `BASE_URL` at the **gateway** and send a Streamscope key instead of a provider
key. For each request the gateway:

1. **Authenticates the key** and resolves the **workspace** it belongs to.
2. **Enforces the workspace's limits** — provider/MCP allowlist, rate limit, and budget (when
   several budgets apply, the strictest wins).
3. **Routes and translates** — picks the upstream route for the requested model alias and
   translates the client's protocol to the upstream's, in either direction.
4. **Applies policy and transforms** — tool risk rules and Rhai scripts may tag, block, or rewrite
   the request (and later the response).
5. **Forwards** to the upstream with the real, server-held credential (or the client's own, for
   BYOK), then streams the response back.
6. **Records an audit row** — user, model, tokens, cost, latency, status — and groups the request
   into a **session** for replay.

**What translation keeps.** A client's tool instruction travels in the upstream protocol's own
form: *call this tool*, *call one of these*, *call none*, and *at most one call per turn*. Where the
upstream protocol has no "only these tools" form, the tools it is offered are narrowed to the
allowed ones instead. Tools a provider runs itself — a Responses client's hosted web search, file
search or remote MCP server, an Anthropic server tool — are offered only to that provider. A
client's output cap and its reasoning request travel separately, so a reasoning budget never caps
the answer. On a Claude 4.6-or-later upstream, reasoning becomes adaptive thinking with an effort
level; older Claude models and other Anthropic-compatible servers get a thinking budget kept within
the bounds Anthropic accepts. A translated request carries the client's reasoning to every model not KNOWN to lack it — a model
whose **reasoning** capability is set off, or one the built-in model catalog lists without it (such
as gpt-4o), is sent none, because such a model refuses the parameter outright. A model nothing
describes (a self-hosted server that publishes no capabilities) is sent it; the model editor says
so under its Reasoning control, and **Off** stops it. The reasoning level reaches a Chat Completions
model as one of OpenAI's levels (low, medium, high); a model that accepts only some of them refuses
the rest with its own error, as it would without the gateway — pin a level it accepts in the
model's invocation preset (for example `{"reasoning_effort": "medium"}`), which then applies to
every request on that route. A client that asks to reason without stating a level is sent none,
and the model's own default applies. A client that explicitly asks NOT to reason (effort `none`,
thinking disabled) is carried as such where the model is known to accept it — Claude models that
allow thinking to be disabled, and on OpenAI's own API the models documented to take effort `none`;
every other model (the newest Claude models think on every request, OpenAI-compatible servers
vary, Gemini's switch is unconfirmed) is sent nothing and the record says so. When a translated
request thinks and the client set no output cap, an Anthropic upstream is given the model's own
output limit (from its catalog entry) if the request streams, since thinking and the answer share
it, and at most the largest cap Anthropic's SDKs allow a non-streaming request (21 333 tokens on most models)
if it does not; otherwise the default cap of 4096 applies. On OpenAI's own API (OpenAI and Azure OpenAI)
a translated request states its output limit the way OpenAI's reasoning models require; other
servers get the spelling every compatible server reads. A client's explicit ask to see or hide its
reasoning is followed where the upstream has a way to say it — Claude models that hide thinking
text by default are asked to show it, an OpenAI reasoning model is asked for a summary, Gemini is
told not to include thoughts; a client that doesn't ask gets each provider's usual behaviour. A tool
whose name Gemini refuses (one starting with a digit or a dash) is sent to Gemini under a prefixed
name and handed back under its own. A Chat Completions custom (freeform) tool is offered to Chat
Completions and Responses upstreams, and a call to it comes back to the client as the custom call it
declared; elsewhere it is listed as not carried. A call the model makes to a Responses built-in tool
the client runs itself — a shell or local shell command, a patch, a computer-use action — reaches
only a Responses client; any other client is told, in the call's place, that it was not carried,
and the audit record says so — as is an Anthropic, Chat Completions or Gemini client of a
translated, streamed answer of a call that arrived without a name, which no client could run; a
turn whose only calls were withheld so ends as a plain stop. A Responses client whose translated
answer stops before the upstream finishes it (the connection closed, the stream went idle) receives that answer as incomplete, with every call it had. The audit record's
**Protocol Translated** chip names, in its tooltip, the tool and reasoning settings a translation
could not carry: a hosted tool the upstream protocol has no place for, a tool choice only the
client's own protocol understands (sent as "call no tool" when it limited the model to tools the
upstream does not have), a forced call to a tool the upstream cannot be offered (sent the same
way), a tool's parameter schema Anthropic cannot take (one that does not describe an object — the
tool is offered with an empty object schema instead), "one call per turn" on Gemini, a reasoning request to a model known not to reason or one the
output cap leaves no room for, a sampling setting that gave way to thinking, any other request
setting the upstream's protocol has no place for (a seed, a candidate count, a provider-specific
option), what an earlier assistant, system or tool message carried beside its text (another
provider's reasoning, an image in a tool result), a part of a user message only the client's own
protocol understands (the rest of the message is sent, and the model is told a part could not be
carried), an image or document in a tool result where the upstream's tool results hold text alone
(Chat Completions, a Gemini model whose name does not show it is Gemini 3 or later — the model is told in its place), the signature Gemini puts on a tool call
it made (sent back only to Gemini), and the parts of the answer the client's protocol has no place
for (a Mistral citation, for one). Where Anthropic refuses two requested settings
together, a forced tool choice wins over a thinking budget and thinking wins over a non-default
temperature or top-p; the one that gave way is on that list. The newest Claude models refuse some
settings on every request: Claude Opus 5.5, Fable 5.1 and Mythos 5.1 are sent a forced tool choice
as "may call" over the same tools, and the models that accept only default sampling are sent none
— both listed there too.

You configure all of this from the **admin console**; changes propagate to the live gateway within
about a second. The console never sees plaintext provider credentials.

### Two planes: console and portal

Streamscope has two distinct web surfaces, and keeping them straight prevents most confusion:

- **The admin console** (`/admin`) — where **admins** configure the product (auth, providers,
  workspaces, policy, experts) and **investigate** (dashboard, audit, sessions). Covered by sections
  A and B.
- **The portal** (the console host's root, `/`) — where **end users** self-serve: mint their own
  keys, run the quickstart wizard, and connect MCP accounts. A workspace **manager** is an elevated portal user
  who provisions keys for their teammates. Covered by section C. Members and managers never touch
  the admin console; admins never need the portal to do their job.

Both surfaces are **organization-scoped in the address**: once you sign in, console pages live under
`…/t/<organization>/…` and portal pages under `…/portal/t/<organization>/…`. Because each
organization keeps its own session, you can be **signed into several organizations at once in the
same browser** — open one in one window and another in a second window without either signing the
other out. Sign-in, sign-out, and invite links route you to the right place automatically; signing
out ends only the organization you signed out of. Bookmark pages from their in-app address (the
organization is part of the URL).

**Three addresses to give people**, on the console host:

| Address | For | Opens |
|---|---|---|
| `/` | users | the portal of their organization |
| `/admin` | organization administrators | their organization's console |
| `/system` | the platform administrator | the platform's console (the `system` organization) |

With a single organization, `/` and `/admin` go straight to it; with several, they ask which one
(and then remember it in that browser). `/admin` never opens the platform's console — that is
`/system`'s alone.

Both surfaces need a current browser: Chrome or Edge 111+, Safari 16.4+ or Firefox 128+. An older
browser shows the pages with wrong colours or without their styling.

## The mental model

A few concepts carry the whole product — get these and everything else follows:

- **Tenant** — an isolation boundary: its own users, login page, data, and audit, fully
  isolated from every other tenant. The **SYSTEM** tenant is reserved for platform
  operators (super-admins); it never carries customer workloads.
- **Provider** — an upstream LLM (OpenAI, Anthropic, Ollama, …). You register an upstream
  server once, sync its models, and a **downstream** provider (a set of model aliases) is
  mirrored automatically.
- **Workspace** — the unit of access, budget, and key issuance inside a tenant. It
  allowlists which providers and MCP servers its keys may reach, carries a rate-limit and
  budget ceiling, and selects a tool policy. Every API key belongs to exactly one
  workspace; the allowlist is checked **at request time**.
- **Key** — a workspace-bound credential. `sk-` keys use gateway-managed upstream
  credentials; `vk-` keys forward the client's own (BYOK). A key reaches whatever its
  workspace allowlists, across both the LLM endpoints and the MCP gateway.
- **Portal** — the end-user self-service surface (`/`): users mint their own keys
  and connect MCP accounts. A workspace **manager** is an elevated member who can mint
  keys on behalf of other members. The admin console is a separate plane.

Two rules prevent 90% of "why doesn't my key work" confusion:
1. The seeded **Default** workspace is *ordinary* — it reaches a provider only when you
   explicitly grant that provider to it. New users join **no** workspace automatically; add
   them to a workspace before they can mint a key, and that workspace must be granted a provider
   before the key does anything.
2. **Providers before keys** — a key can be minted, but a request to a model outside the
   key's workspace allowlist is rejected.

---

## Getting started

A fast path from an empty tenant to your first audited request. It assumes your organization
exists and you are its administrator — an install creates one with its administrator's password in
the operator's `credentials.txt`, and a platform super-admin can create more and send you an admin
invite (if you run the platform yourself, see section **A** first, then come back here). An install
creates nothing inside the organization: every step below is yours. Each step links to the detailed
walkthrough in section **B**; the whole path takes about half an hour and changes go live on the
gateway within a couple of seconds.

1. **Sign in.** Open the invite link and set a password — or sign in at `…/login/<organization>`
   with the password the install recorded — and you land on the dashboard at
   `…/t/<organization>/dashboard`. Bookmark it from the address bar — your organization is part of
   every URL. *(Optional, later: switch the organization to single sign-on — see step 1, **Auth &
   identity**.)*

2. **Connect a provider.** **LLM Gateway → New Upstream Server** — pick the provider (OpenAI,
   Anthropic, Gemini, Ollama, …), paste its API key, and leave **Auto-sync** on. Within a moment the
   server is reachability-checked, its models are discovered, and a matching **downstream provider**
   (your menu of model aliases) appears. The provider key is encrypted at rest and never shown to
   users again. A provider on a private network (a self-hosted vLLM or Ollama server) is refused
   until a platform super-admin lists its address on the **LLM providers** egress list — see
   section **A**, *Egress*. *(Detail: step 2, **Providers**.)*

3. **Grant the provider to a workspace.** **Governance → Workspaces** — open the seeded **Default**
   workspace and add the provider you just connected to its allowlist. This is the step new admins
   miss: a workspace reaches **nothing** until you grant it, and there is no wildcard. While you're
   here you can set an optional budget and RPM/TPM ceiling. *(Detail: step 3, **Workspaces**.)*

4. **Decide who mints keys — you, or your users.** Two patterns, pick per team:
   - **You provision** — **Keys** page: add the people who need access, put them in the workspace,
     and mint a gateway key for each. Copy each key once (it's shown only once). Best for a handful
     of service accounts or a locked-down rollout. *(Detail: step 4, **Users & keys**.)*
   - **They self-serve** — hand users the **portal** (`…/portal/login/<organization>`). Once they're
     in a workspace they mint their own keys and run the **Quickstart** wizard, which prints the exact
     config for their client (Claude Code, Cursor, opencode, Cline, …). Promote one person per team to
     **manager** so they can provision teammates. Best for onboarding a whole team. *(Detail: step 10,
     **Hand off to end users**.)*

5. **Point a client at the gateway.** In any AI client, set the base URL to your gateway and use the
   Streamscope key in place of the provider key — no other change. The Quickstart wizard gives you the
   copy-paste form per client. Send one real request.

6. **Watch it land.** Back in the console, the **Dashboard** shows the request (tokens, cost,
   latency, status); **Sessions** replays it turn-by-turn, and **Audit** holds the per-request row.
   If a request is rejected, the most common cause is step 3 — the workspace isn't granted the
   provider the model belongs to. *(Detail: step 9, **Observe & investigate**.)*

**You're set up when** a client request appears on the dashboard and replays under Sessions. From
here, layer on governance as you need it — **tool policy** to block or rewrite risky agent tool
calls (step 7), **transforms** to redact or inject content, and the **experts** that watch your
traffic and propose rules automatically (step 8). The **MCP gateway** (step 5) and **web
search/fetch** (step 6) extend the same auth, audit, and policy to Model-Context-Protocol traffic
when you want them.

---

## A. Platform super-admin (SYSTEM tenant)

These steps run once, by the operator, before tenant admins log in. An install's provisioning
does steps 1, 3 and 4 for the organization it is given (the super-admin, the organization and its
administrator, their passwords in `credentials.txt`); repeat 3–4 here for every other customer
tenant.

1. **Create the super-admin** — open the admin UI; on first visit the **setup wizard**
   creates the SYSTEM super-admin (email + password). (An install's provisioning has already
   created it.)
2. **(Optional) Configure a SYSTEM upstream** — if you want the expert/agent system or
   smoke tests to run from SYSTEM, add a provider in **LLM Gateway**.
3. **Create a customer tenant** — **Tenants** page → *New Tenant* (name + slug). Tenant
   creation auto-seeds scripts, experts, pricing, the app registry, and tool policy, and
   creates the agent account. Each tenant gets its own login page at `/login/{slug}`.
4. **Invite the tenant admin** — on the tenant detail page → **Invites** → generate an
   invite link. The tenant admin opens it, sets a password (internal auth), and becomes
   that tenant's admin.
5. **SYSTEM OIDC flip is LAST** — if you put the SYSTEM tenant itself behind OIDC, do it
   **after** all of the above. Switching SYSTEM to OIDC blocks SYSTEM password login;
   JWTs minted earlier stay valid, but new password logins are refused, so finish all
   scripted provisioning first.

> **Lockout recovery**: switching any tenant to OIDC disables its password login. If OIDC
> is misconfigured, a super-admin issues an **emergency invite** from the tenant detail
> page (Invites → *Emergency*), which resets that tenant to internal mode while preserving
> its OIDC config. The locked-out admin accepts with their OIDC email and re-fixes the
> configuration.

**Egress** (**Settings → Egress**, SYSTEM super-admin) — which private-network destinations the
platform may call, one list per kind of call: **LLM providers**, **MCP servers**, **A2A agents**,
**Identity providers** (OIDC), **Extensions** (the web-search backend and the guardrail
classifier), **Upstream token endpoints**, **Web fetch** and **Client metadata documents**. Every
list is empty at first, so a private address is refused everywhere until you list it; a public one
always passes and the cloud metadata endpoint never does. One entry per line: `*` (every private
address), an IP address, a CIDR prefix (`10.20.0.0/16`) or a host name (exactly that name). A save
applies to every gateway within seconds, without a restart, and is recorded in the platform audit
trail. No tenant can change these lists. List what your deployment calls — typically its model
servers, MCP servers, identity provider and extensions — and leave **Web fetch** and **Client
metadata documents** empty unless you mean any user, or any caller at all, to reach that network
(the Operator Guide's *Internal-egress posture* weighs each list).

**The Platform menu** (visible only inside the SYSTEM tenant) is the operator's own surface:

- **Overview** (`/admin/overview`) — platform-wide edge infrastructure: throughput, the gateway's
  own p95 latency overhead, and resource/memory pressure across edge instances.
- **Tenants** (`/admin/tenants`) — create and manage customer tenants and their invites (steps 3–4).
- **Edge Nodes** (`/admin/edge`) — the gateway (proxy) nodes, how many replicas of each are
  syncing, whether every replica holds the current config, when each last synced, and the global
  proxy log level — confirm the fleet is in sync after a config change. (The single-VM appliance
  shows one node; a scaled Kubernetes deploy shows several replicas.) Each replica keeps audit
  records, conversations and media on its own disk until the admin API has stored them, so an
  admin outage loses none; one the database cannot store (malformed content) is dropped so it
  cannot hold back the rest, and the tenant's notifications feed shows an *Edge sync dropped
  records* entry — once per day.
- **Appliance** (`/admin/appliance`) — **shown only on the VM appliance.** Operate the appliance from
  the console, organized into two tabs (live disk and memory are on the Platform **Overview**). The
  **Management** tab handles software and power: the running version and channel, **upgrade** to the
  latest version (with formatted release notes and live progress) or **roll back**, check for new
  versions on demand, and **restart** or **shut down** the appliance. An upgrade installs exactly the
  release shown: if a newer one was published in the meantime, it is refused and the page shows the
  new one to review. A notification appears when a newer version is available. Downloading and writing the new
  image does **not** interrupt anything — the gateway keeps serving and this page streams live progress
  throughout. Only restarting into the new version does, for about thirty seconds. **Upgrade** leaves
  that restart to you and prompts **Restart to finish upgrade** once the update is written;
  **Upgrade & restart** does it automatically as soon as it is, so the whole update is
  one step with one brief interruption, and the page reconnects on its own afterwards.
  **Roll back** first names the version it returns to. It also works after an upgrade that changed
  the database, but is refused, with the reason shown, when the previous version could not start
  against the database as it stands (see the Operator Guide's *Updates & rollback*). When a new
  version does not come up healthy, the appliance goes back to the previous one on its own, and the
  tab says which version failed and why. Until the new version's health check has passed, the tab
  says it is on trial.
  The same tab shows the appliance's **network settings** — the interface, its IPv4 and IPv6
  addresses, gateways and DNS servers, and whether they came from the settings supplied at install, a
  DHCP lease, or a change made here — and lets you change them. **IPv6** is a switch of its own, in
  either addressing mode: on, the appliance takes its IPv6 addresses from the network's router
  advertisements (and DHCPv6 with automatic addressing), with an optional static IPv6 address beside
  them and that address's gateway; off, it has no IPv6 at all. The form starts from the settings
  that run — a change made here, else the ones supplied at install. Because changing the address moves the appliance and cuts the
  session you are changing it from, an **addressing** change is applied on a timer: confirm it within
  the countdown and it sticks, do nothing and the previous settings come back on their own, so a
  wrong address cannot lock you out. A **DNS-only** change cannot interrupt anything and applies
  straight away. A change that cannot be applied is refused and rolled back rather than left half
  made. Settings changed here take precedence over the ones supplied at install, and
  **Reset to install settings** returns to those — confirmed the same way, since going back is an
  addressing change too, and the most likely one to leave the appliance unreachable. Remember that the DNS records for the appliance's
  hostnames still point at its old address — update them to match.
  The **Backup** tab shows the backup settings and the last and next run. The destination's
  credentials (its rclone config) are the operator's, set over SSH, and never entered here: until
  the operator has set up a first destination, the tab says so and edits nothing. Then it changes
  the destination (among the remotes the operator defined), the encryption keys, schedule,
  profile, and retention. An rclone config the appliance does not know the operator saved (one
  saved before it kept that, perhaps from this console) is shown as not run, with a warning, and
  neither **Run now** nor **Test** is offered: no backup runs with it until the operator saves it
  again over SSH. **Test** tries the saved settings against the destination, or, while
  editing, the settings in the form, without saving them; **Run now** takes an on-demand backup. Backups are encrypted to the **public**
  keys entered here; the matching private keys stay with the operator, never on the appliance, so a
  backup is unreadable without them. An operator can lock the backup settings against the console
  (Operator Guide, *Backup & restore*): the tab then says so, still shows, tests and runs the saved
  settings, but no longer saves or tests a change. Provisioning, restores, secrets, a database reset, removing the backup
  settings and an upgrade without its backup are the operator's, over SSH, and never offered here.
  On Kubernetes this page is not shown (the platform is managed with standard cluster tooling).

---

## B. Tenant admin (per tenant, via the UI)

Do these in dependency order. Each step names the UI page and what you actually do.

### 1. Auth & identity — **Auth** page

Decide how this tenant's users sign in, and manage who has access.

**Accounts are organised by person.** Each email on the **Accounts** list is one identity with two
independently grantable kinds of access:

- **Console** — sign in to the admin UI, as **Admin** (full management) or **Read-only** (sees
  everything, changes nothing).
- **Gateway** — belong to workspaces, hold API keys, and spend against a budget. The per-workspace
  **member**/**manager** role is shown inline.

One person can hold either or both. The **+ Add** button grants whichever you pick; the **Edit**
dialog on each card changes the display name, password, and access level per capability — picking
**No access** and saving removes that side permanently, after a confirmation that previews the
impact (deleted console account, deleted user and revoked keys). **Disable** on the card suspends a
capability reversibly (disabling a user also disconnects them from every MCP server they
connected: their OAuth sign-ins and the values they entered are deleted, so they connect again
after **Enable**); a disabled console account stays disabled even when your identity provider or
authentication proxy still signs the person in — only **Enable** restores it (an account switched
off because it lost its console group follows the group: it comes back on its own once the group is
regained, so keep such a person out by removing them from the group in your identity provider). Workspace membership and the member/manager role are managed on the
workspace pages. You can't delete the account you're signed in as, and you can't remove the
tenant's last remaining admin.

**Sign-in modes:**

Sign-in addresses are compared **without regard to case** in every mode: `Ada@Corp.com` signs in
to the account `ada@corp.com`, and a second account differing only in case cannot be created.
Addresses are stored in lower case (letters A–Z only; characters from other alphabets are kept
as they are).

- **Internal** (default) — email + password. One password covers both the console and the portal for
  the same email.
- **OIDC** — fill **Issuer URL, Client ID, Client Secret, Scopes**, click **Test
  Connection** (a built-in SSRF guard refuses an issuer on a private address unless a platform
  super-admin listed it on the **Identity providers** egress list, and the cloud metadata address
  always), **Save**,
  then switch **Auth Mode** to *oidc*. The Issuer URL must be **exactly** the issuer your
  IdP declares in its discovery document (a trailing slash is tolerated) — a mismatched
  issuer is rejected at login.

  - **Register at your identity provider** — the Auth page lists, ready to copy, the exact URLs
    your IdP must know, for whichever tenant you are configuring (the platform tenant included):
    the **redirect URI** `https://{ADMIN_DOMAIN}/auth/oidc/callback` (one for both console and
    portal), and the **post-logout redirect URIs**
    `https://{ADMIN_DOMAIN}/login/{tenant}` (console) and
    `https://{ADMIN_DOMAIN}/portal/login/{tenant}` (portal — not shown for the platform tenant,
    which has no portal). Providers compare them character for character. The post-logout URIs matter only when the IdP publishes an end-session
    endpoint; Entra ID and AD FS take them as additional redirect URIs.
  - **Response mode** — how the IdP returns the sign-in: *Query* (default) or *Form post*. AD FS
    needs *Form post*: it puts the claims its rules issue (email, groups) into the ID token only
    then. The redirect URI is the same in both modes.
  - **Claim Mapping** — which ID-token claims a sign-in reads:
    - **Groups claim** (default `groups`) — its values are matched against *Admin Group* and
      *Read-only Group*. It may hold one value or a list. A sign-in whose token does not carry the
      claim counts as a member of **no** group — many IdPs omit it for a user without groups — so
      a wrong name here (or AD FS left on the *Query* response mode) revokes each admin's console
      role at their next sign-in; only the last admin is kept. Check it with one account before
      your admins sign in.
    - **Email claim** (default `email`) — the claim the account is keyed on. It must carry exactly
      one address; a sign-in whose claim is absent, empty, multi-valued or not an address is
      refused. Use `upn` for a directory whose users have no mailbox. Any claim other than
      `email` requires the setting below — the IdP states verification for `email` alone — and
      saving one without it is refused.
    - **Accept addresses the provider does not mark as verified** (off by default) — see the
      email-verification rules below.

  - **Admin Group / Read-only Group** — the console role is driven by IdP group membership and
    **recomputed on every login**: a member of *Admin Group* signs in as Admin, a member of
    *Read-only Group* as Read-only (Admin Group wins if both match). A user in **neither** group has
    no console access — signing in on the **admin** login page shows an *access denied* message
    (they are not silently sent to the portal; portal users sign in on the portal login page). Leave
    both empty to block admin auto-provisioning entirely (only pre-existing admin rows, matched by
    verified email, can sign in). In OIDC mode the console role is not editable in the UI — it's
    managed by these groups. The last remaining admin is never revoked or demoted this way.
    **On the platform (SYSTEM) organization** the groups decide platform access itself: a member of
    *Admin Group* signs in as a platform super-admin, a member of *Read-only Group* as a read-only
    account without platform access, re-checked at every sign-in like the role — so there, a
    super-admin who leaves the admin group loses the grant, unless no other active super-admin
    remains (then the account is kept as it is). An account without the grant never gains it this
    way except by signing in from *Admin Group*. An account in neither group is disabled at its
    next sign-in, as in any organization.
  - On every OIDC login, each workspace's auto-membership rule is checked against the claim that
    workspace names (`oidc_claim_name` — `groups`, or `group` on AD FS) for additive workspace
    auto-membership (step 8 of the workspace setup).
  - **Accept client ID metadata documents (CIMD)** (on by default, and independent of the
    sign-in mode) controls whether an MCP client may identify itself by a web address it
    publishes rather than by registering. See step 5.4 for what that means in practice.
  - **A confirmed email address is required**, both to link a first OIDC login to an existing
    account and to create a new one. By default your IdP must send `email_verified=true`; an
    address it passes along without confirming is refused, because that address is also the name
    the account signs in with from then on. For personal Gmail (no group claims), pre-create the
    admin row while still on internal auth, using the exact sign-in address.
  - **Accept addresses the provider does not mark as verified** lifts that requirement for an IdP
    that states nothing about the address — AD FS never sends `email_verified`. Turn it on only
    when your directory, not the user, sets the address. It never overrides an explicit
    `email_verified=false`: that is always refused. `email_verified` describes the `email` claim
    alone, so with any other **Email claim** (such as `upn`) the address is always unstated and
    sign-in needs this setting. **Never** turn it on for an IdP where users or guests can set their
    own address (for example Microsoft Entra ID with guest accounts): the address is the account's
    sign-in name, so anyone able to put a colleague's address there could sign in as them.
  - **Portal sign-in requires it every time**, not just on the first login. A console account binds
    to the IdP's own user identifier once it is linked, so the address stops being what identifies
    it; a portal account is identified by address alone, with nothing else to tell two claimants
    apart. Anything less would let an unconfirmed address be handed a colleague's existing portal
    account.
  - **If your IdP does not send `email_verified` at all** and the setting above is off, no
    console account can be created or linked, and portal sign-in does not work at all — each
    attempt is refused with "the identity provider did not verify this email address". Console
    members already linked keep signing in. Release the claim at the IdP where it can (see the
    table below), or turn the setting on where the directory owns the address. To regain console
    access meanwhile, use the emergency invite, which returns the tenant to internal auth so you
    can sign in with a password.
  - **Sign out & switching accounts** — signing out also ends your session at the IdP when it
    publishes an end-session endpoint, so the next sign-in asks for credentials and any account can
    be used. An IdP without one (e.g. Google) keeps its own session alive, so the next sign-in there
    shows its account chooser instead; without it the sign-in would silently reuse the same account
    with no way to switch.

  **Per-IdP quick reference** (full field values go on the Auth page):

  | IdP | Issuer URL | Notes |
  |---|---|---|
  | Google | `https://accounts.google.com` | No group claims (personal accounts); local-only logout. |
  | Microsoft Entra ID | `https://login.microsoftonline.com/{tenant-id}/v2.0` | Map `email` as an optional claim, and release `email_verified` — Entra commonly omits it, and without it no account (console or portal) can be created or linked. Add the logout URL as a 2nd redirect. |
  | AD FS (2019 or later) | `https://{adfs-host}/adfs` | Different claim names and no `email_verified` — see *AD FS* below. |
  | Keycloak | `https://{host}/realms/{realm}` | Drop the legacy `/auth/` prefix (KC 17+). |

  **AD FS.** AD FS 2019 or later (earlier releases lack the PKCE support sign-in uses). AD FS
  names a claim by the *short name* in its Claim Descriptions list, puts only a few claims in the
  ID token by default, and never sends `email_verified`, so it needs these steps:

  1. **Application group** — create one from the *Server application accessing a web API*
     template. The server application's identifier is the **Client ID**; add the **redirect URI**
     and both **post-logout redirect URIs** from the Auth page as redirect URIs, and generate a
     **shared secret** (the **Client Secret**). Give the web API the Client ID as its identifier.
  2. **Permissions** — on the web API, permit the client the scopes `openid`, `email`, `profile`
     and `allatclaims`. `allatclaims` is what copies the claims below into the ID token.
  3. **Issuance transform rules** (on the web API) — one *Send LDAP Attributes as Claims* rule
     from Active Directory: `User-Principal-Name` → **UPN**, `E-Mail-Addresses` →
     **E-Mail Address**, `Token-Groups - Unqualified Names` → **Group**.
  4. **Streamscope Auth page** — Issuer URL `https://{adfs-host}/adfs`, Scopes
     `openid email profile allatclaims`, **Response mode** *Form post* (without it the ID token
     carries none of the claims from step 3), **Groups claim** `group`, **Email claim** `email` when
     every user has a mailbox (otherwise `upn`), and turn on **Accept addresses the provider does
     not mark as verified**. Enter *Admin Group* / *Read-only Group* exactly as AD FS sends them —
     plain group names with the rule above, case included.
  5. **Workspace auto-membership** — set a workspace's `oidc_claim_name` to `group`.

  A user who belongs to a single group arrives with that group as a plain value rather than a
  list; both shapes are read the same way.

- **Header mode** — if a reverse proxy (Authelia/Authentik) already terminates auth, the
  operator sets `AUTH_MODE=header` at deploy time and Streamscope trusts
  `X-Auth-Request-*` headers; no per-tenant OIDC config needed. Your **Console access** and
  **Read-only** group settings apply here exactly as they do under an identity provider: the role is
  recomputed on every sign-in, and somebody who no longer matches either group loses console access.
  The last remaining administrator is never locked out this way. Which tenant a header-mode
  deployment serves is fixed by the operator, not chosen per request — see the Operator Guide.

### 2. Providers — **LLM Gateway** page

1. **Add an upstream server** — **+ Add Server** opens a short wizard in three steps:
   **Provider** (name, who serves the models, and whether the gateway holds a credential or each
   client forwards its own), **Connection** (the address, credential, transport and protocol) and
   **Discovery** (whether its model list is read and mirrored), ending on a summary of exactly what
   is about to be created. Finishing takes you to the new server's own page, where its endpoints,
   models and capacity live. Credentials are stored encrypted and never shown to users. Pick from
   the built-in provider
   catalog — OpenAI, Anthropic, Google Gemini, and the common OpenAI-compatible services (Groq,
   Together, Fireworks, DeepSeek, Mistral, OpenRouter, NVIDIA, xAI, Cerebras, SambaNova, Moonshot,
   Hyperbolic, Baseten, Cohere, DeepInfra, Novita, Zhipu, Writer, Perplexity, Hugging Face,
   SiliconFlow, Llama, Nebius, Scaleway, GitHub Models, Inference.net, Chutes), plus self-hosted
   (Ollama, vLLM), the cloud platforms (Azure OpenAI, AWS Bedrock, Google Vertex), and custom.
   A self-hosted or custom server has no default address, so the wizard's **First endpoint** is
   required: every server states the URL it forwards to, and a request is never sent anywhere else.
   That one address becomes the server's first endpoint — add replicas of the same engine to it
   afterwards, on the server's **Endpoints** tab. Two request fields belong to the gateway, not the client: vLLM's scheduling
   `priority` (which would let a caller jump everyone else's queue) and `kv_transfer_params` (which
   steers KV-cache transfers between engines). They are removed from every request before it is
   forwarded — chat, media and pass-through paths alike — and the request's audit entry records
   the removal. Every other field a client sends, including engine extras such as
   `chat_template_kwargs`, is forwarded as before.
   Picking a provider fills its default address, protocol, **Transport**, and — for the few whose
   chat endpoint isn't the standard `/v1/chat/completions` — its **Chat Endpoint Path** (an advanced
   field you can override for a bespoke OpenAI-compatible endpoint; leave blank for the standard
   path). A value you typed yourself is kept; only one still holding the previous provider's
   default is replaced.
   **Transport** is how requests reach the server, which is separate from the protocol above (the
   protocol decides the request body; the transport decides the address and which header carries the
   credential). Almost every provider uses **Standard (bearer token)**; the exceptions are the
   cloud platforms — see *Azure OpenAI*, *Amazon Bedrock* and *Google Vertex AI* just below. With **Auto-sync**
   on (the default), the server is reachability-checked, its models are discovered, and its
   **mirror downstream provider** appears right away — no separate sync needed. (Perplexity
   publishes no model-listing endpoint, so sync is hidden for it; add its models manually.)
   Auto-sync is the
   single switch that owns the mirror: turn it **off** at add time for a **manual** server (no
   discovery, no mirror — wire a custom downstream yourself). The mirror takes the server's name;
   if that name is already a downstream provider the add is rejected ("name already in use"), and
   Sync now / the background worker likewise refuse to re-point an existing same-named downstream.
   Deleting the upstream later removes its mirror too. If the server's TLS certificate isn't
   trusted, the error says so and points you at **Settings → Trusted CAs** (import the CA) or
   *Save anyway* to skip the check. The check also reports a key the provider **refuses** —
   a server whose credential is rejected is not created silently — and that too is yours to
   overrule with *Save anyway*, since a provider may refuse the model list to a key that serves
   chat. If discovery fails after the server is created, the server's own page says so and why,
   beside the last-run time.
2. **Sync models** — three ways, all building the same **mirror downstream** provider
   (each upstream model becoming a route with an enable/disable toggle):
   - **Auto-sync** (toggle on the upstream row, on by default) — a background worker
     periodically re-discovers the provider's models and keeps the mirror exactly in sync:
     it adds new models, refreshes capabilities/pricing, and removes models the provider has
     retired. The re-check cadence is `MODEL_AUTOSYNC_INTERVAL_HOURS` (default 24h). The last
     run's result (added / refreshed / removed, or the failure reason) shows next to the toggle.
     Turning the toggle off **freezes** the mirror (it is kept, but no longer tracked); back on
     resumes it.
   - **Sync now** — applies that exact mirror immediately.
   - **Review** — opens the diff (new / existing / removed models) to pick what to import by hand.

   **The server's own page** — reached from its name or from **Edit** on the **LLM Gateway** page —
   is where everything about one server lives, under four tabs: **Server** (name, provider,
   credential, transport, protocol, model discovery, and deleting it), **Endpoints**, **Models** and
   **QoS**. Its health — endpoints answering, breakers open, models, last sync — sits above
   the tabs and stays visible on all of them. On a server that can have replicas the **Server** tab
   states the address read-only and points at **Endpoints**: the addresses are the endpoints, and
   the primary is simply the first of them. A server that cannot have replicas (a cloud platform, or
   a bring-your-own-key pass-through) has exactly one, and edits its address there.

   **Replica endpoints — one server, several URLs.** A self-hosted engine often runs as several
   identical replicas, for example one vLLM process per GPU. Add them as **endpoints** of ONE server
   rather than as separate servers: open the server and use **Endpoints → + Add endpoint**. Every endpoint shares the server's credential, provider,
   protocol and transport; a replica needing a different credential is a different server. Only a
   server on the standard transport has replicas — a cloud platform (Azure, Bedrock, Vertex)
   addresses one deployment, and a bring-your-own-key pass-through server has exactly one endpoint.
   - **Models are discovered per endpoint and fused.** Sync asks every enabled endpoint for its
     model list. A model is served wherever it is listed, so an adapter loaded on one replica only is
     sent to that replica only. The server page's **Models** tab shows the result as a grid: ● listed
     by the endpoint, ◌ assumed, — not served, ⚠ the endpoint answered "model not found".
   - **Only an answer counts.** An endpoint that does not answer a sync keeps everything it served,
     and the sync result says so ("did not answer — its models were kept"). A model is retired only
     when every endpoint that listed it has answered without it. An endpoint that has never answered
     (a new one, or one whose model list is not reachable — an ingress that exposes only the chat
     path, a credential scoped to inference) is **assumed** to serve every model of the server; if
     your replicas serve different models, their model lists must be reachable. A new endpoint's
     first answer takes effect at once for the models another endpoint lists: a replica that lists 3
     of the server's 20 models is sent those 3.
   - **The advertised model is the conservative one.** When replicas report different context
     windows, clients are shown the smallest, and the model is flagged *Window differs*. Replicas
     that name different weights under one model name are flagged *Identity differs*: the gateway
     treats them as the same model, so check they really are.
   - **A conversation stays on one replica.** Each session is pinned to one endpoint of its model,
     so the replica's prefix cache keeps working across turns; **weight** gives a larger replica a
     larger share of sessions. The session moves only when its replica fails or a gateway's circuit
     breaker has taken it out of rotation — then the request goes to another replica of the same
     model, which is not counted as a failover (and the answer can still be cached). A replica that
     answers "model not found" for a model it was expected to serve is skipped for that request and
     flagged on the server page until its next model list settles it.
   - **The first enabled endpoint is the primary.** Reorder with the arrows. The server's own
     **Upstream URL** is the primary's URL, and editing it moves the primary. The last enabled
     endpoint cannot be disabled or removed — disable the server instead. **Remove** first shows
     which models only that endpoint serves, and would therefore be retired.
   - The **Endpoints** tab shows each replica's state: *Healthy*, *Breaker open* (on how many
     gateways, since when, and why), *Discovery failed*, or *Disabled*; the server list shows
     "+N endpoints" and whether the server is *Degraded* (some replicas out of rotation) or *Down*
     (all of them). An audit entry records which endpoint answered the request (administrators only).
   - **View dashboard** on the server's page opens its load, latency and scheduling
     (Dashboard → **Servers**, § 9): this page is where the server is configured, that one is where
     it is watched.

   **Azure OpenAI.** Azure serves the OpenAI surface at its own address and authenticates its own
   way, so it is a **Transport** choice rather than just another URL. Pick the provider *Azure
   OpenAI* and the right transport is selected for you; you supply:

   - **Upstream URL** — the resource endpoint, e.g. `https://YOUR-RESOURCE.openai.azure.com`
     (a `…services.ai.azure.com` endpoint works the same way). Pasting the longer
     `…/openai/v1/` form Microsoft's own samples use is fine — it resolves to the same endpoint.
   - **Transport** — *Azure OpenAI — API key* uses one of the resource's keys.
     *Azure OpenAI — Microsoft Entra ID* uses no long-lived key at all: paste a client-credentials
     document as the credential — `{"tenant_id": "…", "client_id": "…", "client_secret": "…"}`,
     optionally with `scope` (default `https://cognitiveservices.azure.com/.default`; Foundry
     resources may want `https://ai.azure.com/.default`) and `authority` (for a sovereign cloud).
     Streamscope requests a token, caches it, and renews it before it expires; the service principal
     needs the *Cognitive Services OpenAI User* role on the resource. *Test connection* actually
     requests a token, so a wrong document is reported on this page rather than on someone's request.
   - **Protocol** — Chat Completions or Responses. Azure serves every model it hosts (including
     the non-OpenAI ones) through those two, so the other protocols aren't offered here.
   - **Model names are deployment names.** Whatever you called the deployment in Azure is the model
     name here. Sync discovers what the resource exposes; you can also add them by hand.

   Two things the page will refuse, rather than let them break at request time: setting a **model's**
   protocol override to Anthropic or Gemini on an Azure server (it names the models to fix if you
   switch an existing server onto Azure), and **switching between the API-key and Entra transports
   without supplying the credential again** — the two store different kinds of credential, and
   carrying the old one across would send a client secret in a key header, or hand a plain key to the
   token request.

   Everything else is unchanged: an Azure-backed alias is reached by any client protocol, and its
   traffic is audited, budgeted, screened and cached exactly like any other upstream.

   **Amazon Bedrock.** Bedrock publishes an OpenAI-compatible surface on its regional runtime
   endpoint. Pick the provider *AWS Bedrock* and the right transport is selected for you; you supply:

   - **Upstream URL** — the regional endpoint, e.g.
     `https://bedrock-runtime.us-east-1.amazonaws.com`. AWS's own documentation gives this address
     three ways (bare, with `/v1`, with `/openai/v1`); any of them resolves to the same endpoint.
   - **Credential** — an Amazon Bedrock API key. It is sent as an ordinary bearer token. AWS
     signature (SigV4) credentials are not accepted here — create a Bedrock API key instead.
   - **Protocol** — Chat Completions or Responses.
   - **Model names are inference profiles.** Bedrock generally expects a cross-Region inference
     profile rather than a bare model id — for example `us.openai.gpt-5.6-sol`. Sync discovers what
     your account can reach; you can also add models by hand.

   Not every Bedrock model is on that surface. Claude models are served through Bedrock's Anthropic
   Messages endpoint instead, which needs **no special transport at all**: add a *Standard (bearer
   token)* server with the protocol *Anthropic Messages* and the URL
   `https://bedrock-mantle.REGION.api.aws/anthropic`, using the same Bedrock API key. Models
   reachable only through Bedrock's own Converse or InvokeModel APIs — Llama, Nova, Command and
   Jamba among them — cannot be reached through the gateway.

   **Google Vertex AI.** Vertex addresses a model by project, location and publisher, and
   authenticates with a Google service account. Pick the provider *Google Vertex* and you supply:

   - **Upstream URL** — the project/location base, e.g.
     `https://us-central1-aiplatform.googleapis.com/v1/projects/YOUR-PROJECT/locations/us-central1`.
     Both the project and the location must be in it; the page refuses a bare regional host, since
     that address names no model.
   - **Credential** — the service-account JSON key file, pasted exactly as Google Cloud emitted it.
     Streamscope signs a short-lived assertion with it, exchanges that for an access token, caches
     the token and renews it before it expires. The service account needs the *Vertex AI User* role
     on the project. Saving the server performs that exchange as its reachability check — Vertex has
     no model list to check against — so a key that is malformed, revoked, or not authorised is
     reported on this page rather than on someone's request. *Save anyway* stores it regardless.
   - **Protocol** — Gemini (Vertex's native surface) or Chat Completions (its OpenAI-compatible one).
     Claude models hosted on Vertex are not offered: they need a differently-shaped request body,
     which is a protocol rather than an address.
   - **Models are added by name.** Vertex publishes no model list Streamscope can read, so *Auto-sync*
     and *Sync now* are not offered for a Vertex server — add the models you want to use.

   The same two refusals apply to every one of these platforms: a **model's** protocol override must
   be one the platform serves (the page names the models to fix if you switch an existing server onto
   a platform), and **switching between a key-based and a token-based transport requires the
   credential again** — the two store different kinds of credential, and carrying the old one across
   would send a secret in the wrong header, or hand a plain key to the token request.

   As with Azure, nothing else changes: a Bedrock- or Vertex-backed alias is reached by any client
   protocol, and its traffic is audited, budgeted, screened and cached exactly like any other
   upstream.

   Auto-sync and **Sync now** never remove models on a failed, empty, or implausibly short
   discovery (under half of what the server, or one of its endpoints, listed before) — your data stays intact and the failure is
   recorded. A server that really shrank (a router serving four models replaced by an engine
   serving one) is reconciled in **Review**: it judges no list's length and offers every model the
   server no longer lists, unticked, for you to remove (while one of the server's endpoints does not
   answer, an endpoint's own implausibly short list still removes nothing) — with a warning when Sync now would not
   make those removals, the case to check the server is fully up first. An empty list (a server
   still starting) removes nothing, even there. Anything you set by hand — a capability, a price, a
   context window — is never overwritten; everything else takes the provider's current value, so a
   provider that changes its rates reprices your models on the next sync instead of leaving them at
   whatever they cost the day you added them. A provider that simply stops publishing a field keeps
   the last known value rather than blanking it.
   **What discovery reads from a self-hosted server.** Whatever provider you pick for it, a model
   server that publishes capabilities in its model list — llama.cpp, llama-swap, vLLM, and any
   OpenAI-compatible server listing input modalities or supported parameters — has them imported:
   vision, tool calling, reasoning, structured output, audio and video input. Only what the server
   states is imported, and the context window is the one it **serves**, never the model's trained
   length. For an **Ollama** server, discovery reads Ollama's own model list: each model's
   capabilities (vision, tools, thinking, audio) and, for a model loaded at the time, the context
   window Ollama runs it with — Ollama serves a window chosen at load time that is usually far
   smaller than the model's trained length, so a model that is not loaded states none until it is
   (the window learned then is kept). A server that lists a model's details only while it is loaded
   (llama-swap) behaves the same way. Syncing a **Mistral** server likewise imports each model's
   context window and the capabilities Mistral publishes — tool calling, vision, reasoning, audio
   input and speech output — including the ones it marks unsupported, which are then off.
   Mistral's API refuses any request field it does not define, so every request to a **Mistral**
   server is fitted to it, whichever API the client spoke: settings it spells differently are
   renamed (an OpenAI client's seed and output cap, for one), an Anthropic client's prefilled reply is
   sent as the start Mistral continues from (the client gets only the continuation), and what
   Mistral has no field for is left out. A document given by URL reaches a Mistral model without
   the model having to declare document support. The
   audit record then carries an **Adapted to upstream** chip whose tooltip lists what was rewritten
   and what was not carried. A Mistral client's "call a tool" choice is understood on every other
   provider too, and its seed reaches other OpenAI-compatible servers under their own name; its
   other Mistral-only options are passed on to them as sent. Reasoning a client replays in its
   history reaches a model in another API only where that API can take it: Anthropic's accepts
   back only reasoning Anthropic signed, so any other is left out; Gemini's receives the
   reasoning's text without another provider's signature; OpenAI's receive none. A client speaking
   Anthropic's own API to a model served over it has its reasoning sent as it wrote it, except
   reasoning the gateway itself produced for it from another provider, which no server accepts and
   is left out. Each is listed on the audit record — on the **Adapted to upstream** chip in the
   last case. Voxtral's audio input is billed by the seconds Mistral reports — in
   chat and in transcription, streamed or not — so give the model a price per audio second; until
   then its audio is marked unpriced. Speech from a Mistral server is stored as the audio itself.
   A model whose capabilities aren't discovered or cataloged defaults to a **standard text-LLM**
   profile (function calling, system messages, structured output on; vision/audio/video/PDF off) —
   set richer capabilities per model if discovery didn't. **A model inherits its capabilities and
   pricing from the catalog live**: each capability is an **Inherit / On / Off** choice (Inherit
   shows the value it falls back to), and the model's **price list** inherits the catalog's unless
   you set one of your own. Every field is tagged with where its effective value comes
   from — **You** (a value you set, which is pinned and survives sync), **Synced** (from the
   provider), **Catalog**, or **Default** — and switching a field back to Inherit (or clearing your
   price list) releases your override.

   A price list is a set of rates — one per thing the provider charges for (input tokens, output
   tokens, cached tokens, characters of text-to-speech input, generated images, seconds of audio or
   video) — together with the currency they are quoted in. **You override the whole list or none of it.** That is deliberate: a price
   list is quoted by one provider in one currency, so taking half of it from the catalog and half
   from your own entry would mix rates that were never meant to be combined. An empty list means
   "this model has no price", which is not the same as free — requests against it record a cost of
   zero *and* are flagged, so they never quietly look like they cost nothing.

   Some models charge more once a prompt passes a size threshold. Those rates show as a **range**
   in the catalog listing and as a read-only step table in the editor, and the gateway bills each
   request at the step its prompt actually reaches. The catalog carries the published thresholds,
   so this needs no setup. Setting your own flat price for such a model replaces the steps — the
   whole list is yours or none of it. Because inheritance is live, editing a catalog entry updates every
   model that inherits from it with no per-model change. The editor's **Inherited catalog model**
   picker shows which catalog entry a model draws from — matched automatically from the model name,
   or pick one yourself to override the match (and clear it to return to automatic matching).
   Deleting a catalog entry — on its own, with **Remove seeded**, or by a **Reset** — returns every
   model picked onto it to automatic matching; a deleted entry cannot be picked. A shipped entry you
   delete — edited first or not — stays deleted across restarts and upgrades; only a list's own
   reset of its built-ins, where it has one, brings shipped entries back. The same holds for every built-in list (MCP catalog, transform programs,
   experts, tool rules and field profiles, client profiles, priority classes, the app registry). Creating a
   rule, profile, catalog entry or app with a deleted one's name makes it yours. A deleted expert's,
   priority class's or program's name stays taken, and a list with no reset cannot bring a deleted
   shipped entry back.

   A catalog entry's **Applies to** field is either *All servers* (the default) or one upstream
   server, shown as a column in the catalog listing. An entry for one server wins over the
   all-servers entry for the same model, and is never borrowed by a different server. That is
   where a self-hosted deployment's real cost belongs, and where a region's own price belongs for
   providers that charge differently by region — the shared catalog deliberately treats every
   region of a model as the same model, so it cannot carry both. Set it when you create the entry.

   **When a model goes away — vanish vs. delete.** A custom route (e.g. a load-balancing/failover
   route) is never silently destroyed when what it points at is removed:
   - **The provider stops listing a model** (a *vanish*, found by sync) → the route is disabled and
     flagged, and **automatically re-enabled if the model reappears**. A route you disabled by hand
     stays disabled.
   - **You delete a model or a whole upstream** → any custom route to it is kept, disabled, and
     flagged **"orphaned"** (shown in the route list) for you to clean up or repoint — never
     cascade-deleted. The delete tells you how many routes in which downstreams were orphaned.
   Disabled and orphaned routes don't serve traffic; delete a flagged route to clean it up.
3. **(Optional) Aliases & presets** — map friendly aliases (e.g. `claude-opus-4-8` →
   whatever upstream model) and pick the invocation preset for each. Pricing is set on the
   **model** (empty = inherit from the catalog), not the route.
4. **(Optional) Load balancing** — point one alias at multiple upstream targets grouped by
   **priority** (failover) and **weight** (how distinct conversations spread across a priority
   group). Each conversation is pinned to a single target for its whole session so the upstream
   provider's prompt cache keeps hitting turn after turn — load balancing happens *across*
   conversations, not within one. The gateway recognises a conversation automatically from its
   content (and from a client session id when one is sent), so this works without any special
   client headers.

**Model capabilities.** Each **model** carries capability flags (vision, function calling, structured
output, caching, audio in/out, video, PDF), edited on the model (not the route). Sync fills these from
discovery or the catalog; a model with none resolves to the **standard text-LLM** profile. These flags
gate what the gateway accepts — a request using a modality the model doesn't support is rejected with a
clear error — so set them per model when discovery didn't, especially for the media endpoints below.
On an alias with several targets, the gateway serves the request from the first model in the alias
that *can* handle it: if load balancing puts a text-only model in front of an image request, the
request goes to a vision-capable model behind it instead of failing, and the audit row shows a
**Rerouted** badge naming the model that was passed over and why. The rejection above still applies
when no model on the alias can serve the request. A
route is a **pure pointer** to a model + preset: it does not redefine the model's capabilities, real
window, protocol or media type — those are the model's, and an alias advertises the **bound model's**
real window (swap the model behind an alias and the advertised limits follow it). The separate *Client
Context Window* field on the route only adjusts when self-compacting agents trim their history, and does
not change a model's real capacity — set it for a backend-independent advertised window.

**Presets — name how a model is invoked.** A model can carry several named **presets** — bundles of
invocation settings (temperature, top-p/top-k, penalties, reasoning effort or thinking budget, stop
sequences, and any provider-native extras), written in the model's own protocol. One physical model can
then be offered several ways from a single backend — e.g. a "think" preset and a "non-think" preset on
the same model. Manage presets on the model (the **Presets** action in the Upstream tab); every model
has an editable **default** preset, and you choose which one is the default. When you add a route you
pick its preset (or leave it on the model's default); with auto-sync on, mirroring creates one alias per
preset automatically — the default keeps the bare model-name alias, others get a `<model>-<preset>`
alias. The gateway applies the chosen preset's settings to each request just before it leaves for the
upstream, so the values land correctly whatever protocol the client used; every changed parameter shows
in the request's audit trail.

**Client slots — a client's fast and plan models.** Several clients read more than one model: a
**fast** one for background work (titles, search, commit messages, thread summaries) and a **plan** one
for planning. Edit a route and pick its **Client Slots** — Fast, Plan or both — and every generated
config whose client the route is offered to (its **Client Tags**) names that alias there, as long as
every target of the alias serves a chat model (an embedding or image alias is skipped) (which client reads which: *Set up tools
with the `ssai` CLI*); a client the route is not offered to, and a slot no route fills, use the
default model, so nothing changes until you set one. Each slot belongs to one route per downstream —
choosing it on a route takes it off the route that held it, which the form names — and one route may
fill both. Pair a slot with a preset to offer one model two ways: a `-fast` alias with thinking off
and a `-think` alias with reasoning high. The preset's settings apply to every request on that alias
whatever the client sends for them — except on a pass-through (BYOK) downstream, which never applies
a preset. The route list marks a slotted route with a `fast slot` / `plan slot` chip. A disabled
route keeps its slots: while its alias is still offered through another of its targets the slot stays
with the alias, and once no enabled route offers the alias the slot uses the default model.

**Response cache — pay for a repeated answer once.** An alias can serve a request it has already
answered from a stored response instead of calling the provider again. It is off everywhere until
you turn it on, one alias at a time, and it is the single biggest lever on traffic that repeats:
evaluation runs, agentic retries, and fixed retrieval or classification prompts.

You define the policy once as a named **cache preset** under **Settings → Response cache**, then
pick that preset in the route's **Cache Preset** field. Change the preset and every alias using it
follows, so there is one place to tune. A preset carries:

- **Mode** — *Observe* records the answers that *would* have been served, without serving any;
  *Exact* serves an identical repeat request; *Semantic* also serves a question that means the same
  thing but is worded differently ("what's our refund policy?" and "how do refunds work?").
- **Similarity threshold** (Semantic only) — how close two questions must be to count as the same
  one, from 0 to 1. Higher is stricter. Leave it at the default and let an Observe run tell you what
  your own traffic actually scores before you change it.
- **Lifetime** — how long a stored answer stays reusable. Shortening it takes effect at once, on
  answers already stored as well as new ones, so cutting it is an immediate way to stop serving
  anything stale; lengthening it applies only to answers stored from then on.
- **Shared with** — who may be served an answer someone else's request produced: only the same
  **person**, the **workspace** (the default), or the whole **tenant**. A stored answer can contain
  content from the prompt that produced it, so widening this is a deliberate data-sharing decision;
  the editor warns when you pick tenant-wide.

**Start in Observe.** Requests keep going to the provider, and the audit log marks each one that
would have been a hit — so you can see the real repeat rate on your traffic before enabling it.
Observe compares questions by meaning whenever you have set an embedding model (below), and each
recorded near-hit shows its similarity score, so one Observe run answers both questions at once: how
much Exact alone would serve, and how much more Semantic would add and at what threshold. When the
numbers look right, switch the preset to Exact or Semantic once and every alias using it follows.

**Setting up Semantic.** Comparing questions by meaning needs a model that can do the comparing, so
under **Settings → Response cache** point **Embedding Alias** at one of your own embedding aliases —
the same name a client would send as the model — and it is called through the same routing and
credentials as any other request. **Embedding Time Limit** caps how long the gateway waits for it;
past that the request simply goes to the provider, because a cache must never be the slowest part of
a request. Leave the alias empty and Semantic presets keep serving exact repeats, and every affected
request carries a **No Similarity Match** badge saying why — so an alias that has quietly stopped
matching never looks like one nobody is repeating prompts on. A Semantic preset with no embedding
model set is flagged in the preset list and again on the alias itself when you pick that preset, so
the gap is visible where the choice is made rather than only in the badge afterwards.

Size the time limit from a model's **slow** responses, not its typical one. The default of 3 seconds
suits an embedding model reached over the internet, and it can be raised to 15 if yours is slower.
Setting it too low is the failure worth avoiding: comparisons then time out, nothing is ever
remembered, and the alias looks like one where matching by meaning simply does not work.

**Check the alias before you rely on it.** The field offers your own aliases as you type, marking any
already known to be an embedding model, and **Check** next to it asks that alias for a real embedding
using exactly the call the cache makes — same targets, same request, same time limit. A green result
means similarity matching will work, and reports the vector width and how long it took; a red one
names the reason, which is usually one of a few:

- the model needs extra parameters the gateway's embedding call does not send (several providers ship
  "asymmetric" embedding models that require an input-type argument — pick a plain one instead);
- the alias resolves through a **pass-through** provider, which forwards each caller's own credential
  — the cache has no caller to borrow from, so it can never embed there;
- the provider is not one the gateway can ask for embeddings in the OpenAI format;
- the model answered, but too slowly for the time limit you set.

A check that passes proves the alias is **reachable**, not that it has room to spare — it reports one
measurement, and the limit has to cover the slow ones too. Do not set the time limit from the number
the check reports.

A successful check also records that the alias *is* an embedding model, which is what marks it in the
list next time. Warnings appear alongside: a model with no price configured records every comparison
at $0, and an alias load-balanced across several embedding models keeps a separate set of remembered
answers per model, so each one fills more slowly.

**Comparing costs money, and you can see it.** The embedding model is asked to compare on every
request that is not already a word-for-word repeat — a miss and a similarity match alike, and under
*Observe* too, where nothing is ever served. That is real provider spend, so it is charged to the
request that caused it: each turn's audit entry shows what its embedding cost and how many tokens it
used, alongside the answer's own cost, and it counts toward the workspace budget. It is a small
fraction of the completion it can avoid, but on an alias whose prompts rarely repeat it buys nothing
— which is precisely what an Observe run is for.

**What you see afterwards.** A cache hit is a normal audited turn: it shows in the audit log with a
**Cached** badge naming what it saved and, when the match was by meaning, how close it was; it
records the answer's real token counts, is billed nothing for the answer itself, and still counts
against request rate
limits. Answers are matched on the entire request as the client sent it — the system prompt, the
full history with every setting on every message, the tools offered, and the model and preset behind
the alias — so a different prompt, model or preset can never be served someone else's answer. The
same conversation sent through two API formats (OpenAI and Anthropic, say) is two entries. What does
not change the answer is left out of the match: whether the answer streams, and the caller's own
bookkeeping — its end-user identifiers (`user`, `safety_identifier`), its provider prompt-cache key and
`metadata` — so under a tenant- or workspace-wide preset two users asking the same thing share one
answer. **Semantic mode relaxes only the wording of the latest
question**: everything else still has to match exactly, so a question asked under different
instructions or after a different conversation is never a match however similarly it reads. A
question that arrives with an image or a document attached, that is not the last thing in the
conversation, that shares its turn with a tool result, or that is very long is matched exactly
rather than by meaning — in each of those the
gateway cannot compare the part that decides the answer, and it would rather miss than guess.
Aliases with a preset attached show a **cached** chip in the route list.

**What is never cached.** Responses the gateway cannot reproduce faithfully are served normally and
left unstored: tool calls, generated media, errors, cut-short streams, and anything over the
tenant's maximum cached-response size. The audit row says which of these applied, so an alias that
never accumulates cached answers tells you why rather than looking silently broken.

**Clearing.** A client can skip the cache for one request with a standard `Cache-Control: no-cache`
header. You can drop stored answers for a single alias (**Flush now** in the route editor) or for
the whole tenant (**Flush All Cached Responses** under Settings → Response cache) at any time —
nothing is interrupted, the next request simply recomputes. Swapping an alias's model or editing
its invocation preset invalidates its stored answers automatically.

**Tenant settings** (Settings → Response cache) carry a master switch — one flip stops serving
stored answers on every alias without editing each preset — the **maximum cached response** size,
above which a response is served but not stored, and the **embedding alias** and **time limit**
Semantic mode uses.

**What it saved.** Once cached traffic has actually flowed, the **LLM dashboard** grows a *Response
cache* panel and the Dashboard's request-volume panel shows a running total. Both are scoped to the
period and workspace you have selected, so they appear when that window contains requests through a
cached alias — attaching a preset alone shows nothing until the first request goes through it. Read
them in this order:

- **Net** is the number that answers "is this worth it?" — the provider calls the hits replaced,
  minus what the comparisons cost. It can be **negative**, and that is a real finding rather than a
  display quirk: a Semantic alias whose prompts rarely repeat buys a comparison on almost every
  request and serves almost nothing. Switch it to Exact, or stop caching it.
- **Hit rate** counts only answers actually served, out of the requests the cache was consulted for.
  A request where the client sent `Cache-Control: no-cache` is counted separately and left out of
  both — one client opting out cannot drag down an alias that is working.
- **Observe aliases report differently, on purpose.** They serve nothing, so their net is always
  zero; what they show instead is what enforcing *would* have saved, and their comparison spend is
  reported as **tuning** rather than charged against savings. An evaluation run should not read as
  the cache losing money.

Each row is per alias, so a preset shared across several aliases still tells you which of them is
carrying it. The figures follow the period and workspace you have selected, and clicking a row opens
the audit log filtered to that alias. An alias whose mode you changed mid-period appears once per
mode it ran under — the numbers describe what the policy was at the time, not what it is now.

**Why an alias is not caching.** A low hit rate has two very different causes, and the panel
separates them so you do not tune the wrong one. Each alias row carries the commonest reason its
responses went **unstored** — most often *tool calls*, which can never be cached, but also *cache
full* or *over the entry size limit*, which you can act on. A Semantic alias additionally shows when
similarity matching could not run at all and the request fell back to exact matching, with a
**semantic degraded** count in the panel header when that was caused by the embedding provider
timing out or failing. That distinction matters: an alias that silently stopped matching
semantically looks exactly like one whose prompts nobody repeats. If you see it, raise the time
limit under Settings → Response cache or check the embedding provider.

**What each edge is holding** (super-admins). The Platform Overview carries a *Response Cache* panel
with one row per edge: how many answers it holds, how much memory they occupy **against that edge's
ceiling**, and how many entries it has had to discard to make room since it started. Read the memory
figure first — an edge sitting at its ceiling is discarding answers before anyone can hit them,
which in the savings figures above is indistinguishable from nobody repeating a prompt. Raising that
edge's cache size is the fix. The discard total is the lifetime count behind it, so it keeps rising
until the edge restarts and is history rather than current state.

### 2b. Media endpoints (embeddings, audio, images, video)

The gateway is not chat-only. Once an upstream provider and its models are configured, the same key,
workspace allowlist, budget, rate limit, and audit trail also cover the OpenAI-compatible **media**
endpoints — no extra setup beyond enabling the matching capability on the model:

- **Embeddings** — `POST /v1/embeddings`.
- **Audio** — `POST /v1/audio/speech` (text-to-speech), `/v1/audio/transcriptions`,
  `/v1/audio/translations` (multipart upload).
- **Images** — `POST /v1/images/generations`, `/v1/images/edits`, `/v1/images/variations`.
- **Video** — `POST /v1/videos/generations`.

Each request is authenticated, budgeted, rate-limited, priced by media type, and audited like any
chat call (the **Audit** view filters by media type, and analytics break cost/volume down across
text / embedding / audio / image / video).

**What each one is billed on.** Embeddings bill the tokens the provider reports. Images bill the
images produced. Text-to-speech bills the characters of text you sent, because the response is
audio and reports nothing — counted as characters, not bytes, so an accented or non-Latin script
is not charged extra for its encoding. Video generation bills the duration the request asked for,
for the same reason — unless that duration is longer than any video model could produce, in which
case the request is flagged as unmeasurable rather than charged for a length nobody rendered. Transcription bills whatever the provider reports: seconds of audio, or
tokens, or — with the plain `json` response format from a provider that reports neither — nothing
at all, in which case the request records a zero cost **and is flagged**, so an unmeasurable call
never quietly passes for a free one. **BYOK** variants forward the client's own credential at
`/fwd/{vk-key}/v1/...`. To retain the actual binaries (generated images, TTS audio, uploaded files)
for review, enable **media blob storage** in Settings (off by default; capped by a max-size setting
held to the platform's media limit — 32 MB unless your operator set another — and oversized
payloads are recorded as a stripped placeholder rather than dropped).

#### BYOK pass-through providers

Every tenant ships built-in **BYOK** (bring-your-own-key) providers for the major hosted LLM services
— **Anthropic**, **OpenAI**, **Google Gemini**, plus the common OpenAI-compatible providers (Groq,
Together, Fireworks, DeepSeek, Mistral, OpenRouter, NVIDIA, xAI, Cerebras, SambaNova, Moonshot,
Hyperbolic, Baseten, Cohere, DeepInfra, Novita, Zhipu (GLM), Writer, Perplexity, Hugging Face,
SiliconFlow, Llama, Nebius, Scaleway, GitHub Models, Inference.net, Chutes) — each listed as
**`<Provider> Pass-through`**, with **no stored key**. Every pass-through provider, built-in or your
own, lives on the LLM gateway's **Pass-through** tab — the **Downstream** and **Upstream** tabs list
only the providers and servers that hold your keys. Each card there shows the provider's on/off
switch, its endpoint and API format, the workspaces it is **granted to** (each a link to that
workspace's Access tab), its model overrides and its forwarded paths; **Server** opens the
endpoint settings, and on your own pass-throughs **Edit** renames one and **Delete** removes it.
A pass-through is deleted whole — from its card, its server page or its provider alike: the provider,
its server, its model overrides and its workspace grants go together, and every key bound to it is
revoked (deleting a pass-through never leaves a key unbound). The card's confirmation names how many
overrides, workspaces and bound keys that is. They start
**turned off**:
switch one on with its switch (and off again the same way). An off provider reaches nothing: it is
not on the **Servers** dashboard, members are not offered it (portal key forms, quickstart and
`ssai` provisioning), no key can be bound to it, and a workspace is not offered it on its Access
tab — a workspace that still holds a grant of it lists it marked **Off**, so the grant can be
removed. Once on, grant it to a workspace (like any provider) and a member can point an agentic CLI at the gateway, keep using their **own key (or OAuth
login)** and the **current models exactly as before** — only the host changes to the gateway. Every
model passes straight through to the provider with the client's own credential, fully audited and
budget/rate-limited; nothing is stored gateway-side. A provider that is on still reaches no one until you grant it,
and a normal gateway key never passes an unconfigured model through (it stays restricted to its
configured routes) — so an operator-funded key can't reach an un-curated model. The built-in
pass-throughs are managed for you and **can't be deleted or renamed** — to remove one from use,
turn it off, or un-grant it from the workspaces that hold it.

- **Override one model.** **Override a model** on a pass-through card — e.g. point a CLI's
  small/fast model at your own on-prem model — and that one model is served from your upstream while
  everything else still passes through, invisible to the client. The form asks for **the model the
  client asks for** (an exact name, no wildcard) and the server to **send it to**, chosen among your
  own servers only; when that server holds no key, it warns that the member's own provider key is
  forwarded to it. An override replaces that one model only: the
  provider's other API paths (file uploads, batches) still go to the provider itself, and the
  member's key for a different provider is never sent to an override server that has no key of its
  own.
- **Custom / self-hosted.** Create your own BYOK provider for any endpoint (Azure OpenAI, a
  self-hosted model). In the LLM gateway's **Add Server** wizard, set **Authentication** to **BYOK
  pass-through** (instead of **API key (managed)**) on the first step and give the address to forward
  to on the second — no key is needed, and there's no model discovery. This creates an empty pass-through provider you can
  grant and, optionally, add override routes to. **Authentication is set once at creation** — a
  server stays managed or BYOK for its lifetime (edit it and the mode is shown but read-only); to
  switch, delete and recreate. BYOK providers are badged **BYOK** wherever they appear (the
  Pass-through tab, a workspace's grants, and BYOK keys).
- **Forwarded paths.** A card's **Forwarded paths** section (on every downstream provider, not
  only pass-throughs) lists extra API paths forwarded as-is, without analysis or filtering.
- **How members use it.** Once granted, a member picks the BYOK provider in the portal **quickstart**
  wizard (it sets the client up host-only — only the base URL changes) or binds a **BYOK (`vk-`) key**
  to it on the **Create API Key** form. From the `ssai` CLI they choose per client:
  `--mode claude-code=byok --provider claude-code="Anthropic Pass-through"` while another client stays on a
  managed gateway key — one command, mixed modes.

### 3. Workspaces — **Governance → Workspaces** page

A workspace is where access, budget, and key issuance come together.

1. **Grant the Default workspace a provider** — open **Default** and, on its **Access** tab,
   **+ Add** the mirror provider under **LLM providers**. *Required* before any key can reach an LLM.
2. **(Optional) Create scoped workspaces** — *New Workspace* to separate a team onto a
   different provider subset, budget, or tool profile.
3. **Provider + MCP + A2A allowlists** — per workspace, grant the **LLM providers**, the
   **MCP virtual servers**, and the **A2A agents** its keys may reach. The **Access** tab lists
   what is granted, each with **Remove**; **+ Add** offers what can still be granted. Removing a
   pass-through provider that keys are bound to asks first, naming how many of the workspace's
   keys it leaves refused until it is granted again. These are independent: a
   workspace can reach 5 providers, 0 MCP servers, and 1 A2A agent. Granting/revoking takes effect
   on the next config sync (within ~2 s) and changes what existing keys reach immediately — revoking a
   provider does *not* revoke the keys.
4. **Members & roles** — add users as **member** (mint/revoke their own keys, see workspace
   usage) or **manager** (also mint/revoke on behalf of any member from the portal, and see
   the roster + per-member usage). A manager cannot change membership — that stays
   admin-only. Removing a member revokes their keys in this workspace; the keys stay listed as
   revoked, so the audit trail keeps naming the key behind each past request.
5. **Share activity between members** (off by default) — when on, members of this workspace
   see one another's usage, sessions, and request history for this workspace in the portal,
   through a **Me / Team** switch on those pages — shown while this workspace is the one picked
   in the portal header. Off, each member sees only
   their own, which is how every workspace starts. Turn this on for a team that reviews each
   other's work; leave it off wherever members' prompts should stay private to them, since
   sharing exposes the full text of requests and responses to every member. It applies to
   this workspace only — a member of two workspaces sees each under its own setting — and it
   changes nothing about who may *mint* or *revoke* keys.
6. **Limits** — four limits can apply to a request, widest first: the **organisation** ceiling,
   the workspace **pool**, the **member**'s own limit, and a **key**'s own budget. Every one that is
   set applies — **the tightest wins** — so a tightly-capped key never exceeds its own limit even
   inside a generous workspace. Each field is set to **Inherit**, **Unlimited** or a value; the page
   never asks you to leave a field blank or type 0 to mean something.
   - **Workspace pool** — the RPM/TPM and daily/monthly budget all members share. A rate you do not
     set is unlimited. A budget you do not set **inherits the tenant's default budget** (Settings →
     Budget) — and that holds for every workspace with no budget of its own, including one whose
     limits were never opened; the field shows the value it inherits.
   - **Each member — default** — a limit applied to **every member separately** (e.g. 60 requests
     a minute and $5 a day each), so one person cannot use up the whole pool. A person who belongs
     to two workspaces has a separate limit, and separate usage, in each. The Agent and Inline AI
     workspaces take no member default — one service member carries all their traffic; use the
     pool there.
   - **Member exceptions** — a member exception **replaces the workspace's default member limit for
     that member — higher or lower** — field by field: a field left on *Inherit* keeps the default.
     An exception never lifts a member above the workspace's own pool or the organisation ceiling.
     Removing a member from the workspace removes their exception too. Workspace managers can add,
     change and remove exceptions from the portal (see *Workspace managers*) for plain members; the
     pool, the member default and every manager's exception stay yours.
   - **What limits one member** — on the **Members** tab, click a member to expand them: every limit
     that applies to them, what they have used of each, and which one binds first. It answers "why
     was this person throttled?", and their exception can be added or changed from the same place.
     Each limit says where it comes from; where a workspace or an exception sets some limits and
     takes others from a default, the ones taken from the default are marked *tenant default* or
     *workspace default*.
   - An individual **API key can carry its own daily/monthly budget** (set by an admin or a
     workspace manager when the key is created, and editable afterward from the key row).

   A refused request says which limit refused it: the 429 response carries `bucket`
   (`organisation`, `workspace`, `member` or `key`) beside the message — on an MCP call, as
   `error.data.bucket` of the JSON-RPC error — and the request's audit entry records the same,
   shown in the console and in the member's **My Requests**.
   Each budget has a **mode**: *Enforce* (the default — an over-budget request is blocked) or
   *Alert only* (the request goes through, but you still get the approaching/over-budget
   notification). Alert-only is for "track and warn, don't interrupt" production workloads.
   Wherever a cap applies — the workspace pool, a member's limit, or a per-key budget — the
   current window's spend is shown against it (e.g. `$2.10 of $5.00 · 42%`), so you can see how
   close each budget is without leaving the page. A **daily** budget runs over the UTC day; a
   **monthly** budget runs over a fixed 30-day period (consecutive 30-day blocks in UTC), not the
   calendar month. The workspace pool counts every priced request, whether or not it has a budget.
   A **member limit, a key budget and the organisation ceiling count from the moment they are
   set**: spend made earlier in the same day or 30-day period does not count toward them, so the
   first period after you set one can run over its value by what was already spent. Budget notifications for members are grouped per
   workspace ("3 members of Data Science reached their daily member budget") so a default that
   applies to everyone cannot flood your notifications.
   Above all of these sits an optional **organisation ceiling** — one daily and monthly cap for
   the whole tenant, set under **Settings → Budget**. Every workspace's spend counts toward it,
   so it bounds total spend even when no single workspace is near its own budget; it applies to
   gateway keys and MCP tokens alike, and it has the same *Enforce* / *Alert only* choice. Leave
   both windows at 0 (the default) and no organisation ceiling applies. Note it is not the same
   thing as the tenant's *default* budget, which is only the value a workspace inherits when it
   sets none.

   A workspace can be taken **out of the organisation ceiling** with *Count this workspace's spend
   against the organisation budget* (workspace → **Rate Limits**, on by default). Turn it off for
   traffic your organisation does not pay for — the built-in **Inline AI** workspace ships with it
   off, because an intercepted call is funded on the end user's own provider account, and any
   workspace you bill elsewhere is the same case. Off takes that workspace out of the ceiling
   **both ways**: its spend does not add to the organisation total, and it is never refused
   because the organisation total is exhausted. Its own workspace ceiling, member overrides and
   per-key budgets still apply exactly as before.
   When the organisation, a workspace, a member, or a key crosses ~80% (approaching) or reaches 100% (breached) of its
   budget for the current window, the gateway records an operator notification — once per
   crossing, so you're alerted when a budget gets tight, not on every check. Major session
   alerts from the review agent, **API keys within 7 days of expiry** (so you can rotate
   before they break), and **MCP servers every call fails on** (an administrator value missing
   or unreadable, an incomplete OAuth client) are recorded the same way. These notifications surface in the
   **Notifications feed on the dashboard Overview** (scoped to the selected workspace, newest
   first; each row links to where you act on it) and in the operator log; deliverable channels
   (webhook, email) are on the roadmap.
7. **Priority under load** — limits decide what a caller may use; **priority** decides who goes
   first when the model itself is full. It only ever engages when an upstream has no capacity
   free: with room to spare, every request goes straight out and the setting changes nothing.
   - **Classes.** Every tenant starts with three — **Interactive** (a person is waiting),
     **Standard** (everything else) and **Background** (unattended work: CI, batch jobs, the
     analysis agent). Under **Settings → Priority** you can rename them, reorder them, change how
     long each waits before giving up, mark one as *refused rather than queued*, or add your own.
     Background is served last and waits up to two minutes for its turn; a class marked *refused
     rather than queued* is turned away at once instead. A class that waits is refused when its wait
     runs out, when a more important request needs its place in a full waiting room, or when the
     gateway shuts down (see below). Keep a class's wait under its clients' own request timeout
     (OpenAI's and Anthropic's SDKs give up after 10 minutes): a client that gives up first sees a
     timeout of its own rather than a refusal it can act on.
     The list shows the wait each class actually gets: a class that names none waits the
     deployment's default (greyed, with its value), and no class waits longer than the deployment's
     maximum — a longer wait is shown as *capped*. Both are set by the operator and stated above the
     list. **Assigned to** says what runs as the class: the workspaces, keys and route targets set to
     it, and — for the default class — everything that names no class.
   - **Defaults are edited with the class.** In a class's **Edit** dialog, *Default for* holds three
     switches: **anything that names no class** (the tenant default), **new keys for a person's own
     tool** and **new automation keys**. Each is held by exactly one class, so turning one on moves
     it from the class that held it (the dialog names that class); the tenant default can only be
     moved, never switched off.
   - **A workspace picks the class its keys run as** (workspace → **Limits & QoS**), and its
     **share** of a busy model (1–100) against the other workspaces waiting on it. A workspace that
     picks nothing runs as the tenant's default class.
   - **A key may differ from its workspace.** A key can be given a *less* important class by
     anyone who may mint it; giving one a *more* important class than its workspace is a tenant
     admin's decision, and the key is marked as elevated so a later demotion of the workspace does
     not quietly take the promotion with it.
   - **New keys get a class from who made them**: a key you or a member mint from the portal for a
     desktop tool starts as Interactive; a service account's key, or one the CLI mints in CI,
     starts as Background. Both are clamped to what the workspace itself runs as. Rotating a key
     keeps the class it had.
   - **Between two callers of the same class**, the one who has used the model less goes first,
     counted in tokens and weighted by the workspace's share — so one person's flood cannot push
     everyone else behind it, and a caller who has been quiet gains no stored-up advantage.
   - **When the gateway's waiting room is full**, a more important request still gets in: the
     request the gateway would serve last among those waiting for the same server — the least
     important class, then the caller who has used the most — is refused in its place (HTTP 429), so
     a burst of Background work cannot lock Interactive requests out. Between requests of the same
     class, the one already waiting keeps its place, and nothing waiting for another server —
     another tenant's, for one — ever gives way.
   - **When the wait is too long**, the request is refused with HTTP 429 and a `Retry-After`
     telling the client when to come back — about as long as its own class was willing to wait,
     since nobody can know when capacity returns. That refusal is about *capacity*, not a quota:
     the audit entry records it as such — with the server whose capacity ran out and why — and the
     request's own row shows how long it waited. For a request that was then served, that wait is
     part of the row's latency and time to first token, which run from when the gateway starts
     forwarding the request — on the
     audit, the LLM dashboard, and a key's or a user's figures; only Dashboard → **Servers** shows a
     server's latency without it. A request refused after waiting records the wait alone. Dashboard →
     **Servers** shows the refusals of each server by reason and class, and who waited longest.
   - **A request sent again replaces its waiting copy.** A client that gives up on a request the
     gateway is still holding usually sends it again, while the first copy keeps waiting on a
     connection nobody reads any more. When the same request — the same user, the same key, the same
     conversation, the same body — arrives while its earlier copy has been waiting for at least a
     second, the copy is refused (HTTP 429, reason *Sent again while waiting* on Dashboard →
     **Servers**) and the new one takes its place in the queue, so the model never runs an answer
     nobody will read and the retry is not sent to the back. A copy the model is already answering
     is left to finish; a refused copy is never tried on the alias's fallback target. The
     replacement happens on one gateway replica: a retry that reaches another replica, on a
     deployment that runs several, finds nothing to replace. Identical requests sent together —
     several answers sampled from one prompt — are all held; a client that keeps sending the same
     request while the model stays saturated has each earlier copy waiting more than a second
     refused the same way. A retry that reaches the same replica while its first copy is still
     waiting or being answered is also the same turn of the same conversation — not a new session,
     nor the next turn. Once the first copy is over — answered, refused or failed — the same request
     is the conversation asking again. A hold far longer than the clients' own patience still costs
     them refusals they never see, so a class's wait is best kept under their timeouts.
   - **A request waits briefly for its conversation's replica.** Where a model runs on several
     replicas under *Gateway-managed* QoS and the replica a conversation runs on is full, a request
     of that conversation — just arrived, or already waiting — waits for that replica for up to five
     seconds even while another replica has room, and never in the last moments of its wait. Sent
     elsewhere, the turn would re-read its whole history into a cold cache, and the room it takes
     there pushes out what that replica's own paused conversations had cached; a busy replica
     usually frees a slot within those seconds. When its replica frees, the request goes there;
     otherwise, after the wait, it takes whichever replica has room. Within a class, a waiting
     request whose conversation ran on the replica that frees goes first. Class order holds: a
     replica a more important request is waiting out stays free for those seconds rather than go to
     a less important one — unless that one is in the last moments of its own wait, which another
     request's wait never uses up — and a request that arrives while others are waiting takes its
     turn among them rather than the free replica. A request waits for its replica once: if the
     replica it then moved to fails it, it does not wait again. A class set to be refused rather than held does not
     wait for its replica: it takes any replica with room in its turn, or is refused.
   - **A request served by another replica says so.** When a request does go to another replica
     than its conversation's, the row carries a **Moved replica** badge. The answer is the same — it
     is still the same model on the same server, not a failover to another provider — but the
     conversation lost its warm prompt cache for that turn, so a model doing this on most requests
     is one to give more capacity.
   - **Where it applies — a server's QoS tab.** Terms first: an *engine* is one inference process
     (a vLLM instance), an *endpoint* is the URL of one engine, a *server* groups the endpoints that
     share a credential, and the *gateway* is Streamscope, which may run as several replicas. Each
     server has one of three modes:
     - **Off** (every server until you choose otherwise, and the right choice for a hosted
       provider): every request goes straight to the engine, first come, first served, and classes
       change nothing.
     - **Engine priority only**: the gateway holds nothing, and sends each request's class to vLLM
       as its priority, so vLLM reorders its own waiting queue. The engines must run with
       `--scheduling-policy priority`. There is no fairness between users, no wait limit, and
       nothing is refused by the gateway.
     - **Gateway-managed** (recommended for a self-hosted engine): the gateway sends each engine only
       what it can run, holds the rest, and releases it by class and fairly within a class, as
       described above. Set **requests in flight per engine**, **engine queue allowed**, or both.
       The in-flight limit is counted by *each* gateway replica — with two replicas, an engine can
       receive twice it — so the tab says how many replicas are connected; the engine-queue bound is
       read from the engine itself and shared by every replica. An endpoint may override either
       limit (**Edit** on its row). Saving *Off* or *Engine priority only* also clears every
       endpoint's own limits — disabled endpoints included, so enabling one later does not bring a
       limit back — in the same save. Tick *the engines run with --scheduling-policy priority* to also
       send the class to vLLM, which then orders the few requests it holds itself.

       **In-flight limit: fixed or learned.** Under *Gateway-managed*, the in-flight limit can be
       **Learned from the engine** instead of fixed. Each gateway replica then finds the limit for
       each engine on its own, the way network congestion control finds a link's capacity.

       The limit grows while requests are waiting at the gateway and the engine's memory has room —
       doubling at first, then two at a time, and no faster than the engine shows the result: one
       step per average time to first token, so what one step let through is in the cache before
       the next. It is cut to half of what is in flight (never below one) when the engine preempts
       a request, or when its KV cache reaches its 97% ceiling. This keeps the engine's batch as
       full as its memory allows without paying for preemptions, and keeps the overflow at the
       gateway, where classes and fairness apply.

       Each gateway replica raises its limit by no more requests than fit in the KV cache below 90%
       on top of what it has running (requests still waiting in the engine's queue hold nothing
       yet, but will, so they take room too), counting each request at the size it reaches by its
       END. The KV gauge counts only what running requests hold so far, and a request keeps growing
       until it ends — the rest of its prompt, then every token of its answer, thousands on a
       reasoning turn — so a raise judged on the gauge alone would let the running requests fill
       the cache on their own. What one running request holds is the engine's KV use divided by the
       requests it runs (now, or on average since the limit last moved, whichever is more; with
       data-parallel ranks, on the fullest rank): requests part-way through, holding on average
       their prompt and half their answer — and for the end size, never less than that average over
       the run, so a reading taken while just-admitted prompts are still filling does not make
       requests look smaller than they are (an engine restart starts it afresh; after a change of
       workload it follows within some sixty engine readings — two minutes at a two-second poll). The prompt and answer sizes of the requests the engine has finished say how much
       more one holds by its end — up to twice as much on a workload of all answer, nothing more on
       one of all prompt — so the end size is measured in the gauge's own terms, whatever a token
       costs that engine in memory. Until a request has finished, or for an engine that does not
       publish per-request sizes (vLLM does), the gauge alone counts. The end size is an average:
       on a mix of short and long answers the long ones still grow past it (requests the engine
       aborted are not counted). Counting every running request at its end at
       once is deliberately cautious: on a workload of long answers, the cache settles around half
       full rather than risk the requests ending together. Where not one
       more fits, the limit holds, and the dashboard shows **Memory target reached**. Replicas
       sharing an engine each take the room they see, and a request longer than the average still
       grows past it, so the cache can still pass 90% — the back-off on a full cache remains the
       safety net. More GPU memory raises what fits. vLLM's CPU KV offload (`--kv-offloading-size`)
       does not — the limit counts GPU memory only — but it keeps paused conversations' history for
       their next turn, so fewer prompts are recomputed.

       The limit also keeps each engine within a **Token latency target** (the time between two
       output tokens of a request): more requests running means more output in all, each request
       generating more slowly, and the target trades some of that work for speed. The time held to
       it is the engine's **median** time between tokens: when a new prompt is computed, the requests
       already generating pause for it, and on an engine whose prompts take seconds those few pauses
       would make the average a measure of prompts, which no limit on running requests can bound. While
       the engine's median time between tokens is above the target, the limit does not grow; it grows two at a time
       (never doubling, which could overshoot the target), and while the time between tokens
       stays above the target the limit steps down to two below what is running — never more than
       halfway at once, never by less than two, never below one. The dashboard shows **Token latency
       target** and charts the time between tokens against it. The back-offs above still apply. An
       engine that does not publish its time between tokens is run as without a target.

       The target is **Automatic** unless you choose otherwise: three times each engine's own median
       time between tokens while it runs one or two requests (per data-parallel rank) with none waiting,
       which every gateway replica measures as it goes, the most recent spells counting most — so it
       follows an engine that slows or speeds up — and measures afresh when the engine restarts (a
       change of its settings or model takes a restart). Until an engine has run at that low load
       long enough to measure, it has no target: the QoS tab and the dashboard say the target is
       still learning, and they say so until every gateway replica has measured its own, since a
       replica still measuring holds nothing. An engine that is never that lightly loaded is never held to one; choose a
       **Fixed** target in milliseconds for it, or for a target of your own. **Off** lets the limit
       grow as far as memory holds. A fixed target the engine misses even with one request running
       holds the limit at one until the target is raised.

       Without a target, an agent workload can lose more than it gains. The engine's KV-cache use
       counts only what running requests hold: the history of a session that paused between turns
       (while its agent runs a tool) is cached but counted as free, so as more requests run, that
       history is evicted at any cache level — and the next turn recomputes it. The memory target
       does not see this coming, and neither does the prefix-cache hit rate: eviction starts wherever
       the running requests and the paused history no longer fit together, and a falling hit rate
       looks the same as new conversations starting. So the limit keeps growing while paused
       sessions are pushed out. A token-latency target bounds it, since the time between tokens
       rises with that recompute as well as with the number of requests running. One deployment's
       measurement, two vLLM engines without a CPU KV tier serving agent sessions, comparing output
       until 90% of the turns were done against a fixed limit of 9 per engine:

       | Load (prompt sizes) | Fixed 9 | Learned, no target | Learned, 3× target |
       |---|---|---|---|
       | short sessions (8k–15k tokens) | baseline | +30% | +38% |
       | mixed (8k–60k tokens) | baseline | −16% | +13% |
       | long sessions (38k–62k tokens) | baseline | +5% | +16% |

       With the target, prefix-cache reuse on the mixed load stayed at 46% (27% without it), and
       interactive turns were as fast as with the fixed limit. Your GPU, model and quantization move
       these numbers; measure your own load before settling on a value.
       - A limit nothing has used for 30 seconds starts again from four (or stays lower, if it
         already was), so a burst after a quiet spell is held and ordered at the gateway instead of
         sent at the engine all at once. It doubles back up to where it was within a few round trips,
         then grows two at a time. Meanwhile the burst waits in class order, so a class whose wait
         is only a few seconds may see some of its requests refused while the limit regrows.
       - The optional **ceiling per engine** is the most the learned limit may reach.
       - A replica that stops hearing an engine's metrics keeps the limit it had (within the
         ceiling) until the readings come back — a limit just restarted after a quiet spell stays at
         its restart value — then starts again from what it has in flight, never below it. An engine
         never heard is held only to the ceiling, if one is set.
       - An engine that publishes its queue but not its KV-cache use cannot be steered. The
         dashboard shows it as not heard.
       - A learned limit replaces the **engine queue allowed** bound, so the two cannot be set
         together, on the server or on any endpoint.
       - It needs the engine's `/metrics` (vLLM), so the metrics are read whatever the
         **Read engine metrics** switch says.

       When the engine keeps requests waiting although its KV cache has room, something other than
       memory admits no more — its token budget per step, the rule that a whole prompt must fit
       before it starts, or its batch cap — and the learned limit holds where it is: more sent there
       would only wait inside the engine, out of the gateway's priority order. The server's dashboard
       shows **Engine is queueing**. The engine's metrics do not say which of the three binds; see
       **vLLM engine settings** below.

       **vLLM engine settings.** For a vLLM server, the QoS tab shows these in every mode but Off:
       - `--max-num-seqs`: make sure it never limits the engine. Set it to about the KV cache size
         (vLLM logs *GPU KV cache size: N tokens* at start-up) divided by the smallest request you
         serve (prompt + answer, in tokens), and not far above: vLLM sizes some per-request buffers by
         it. A cap that binds keeps requests waiting inside the
         engine, out of the gateway's priority order. It is a cap, not a capacity: an engine rarely
         runs as many as it allows.
       - `--max-num-batched-tokens`: the engine's token budget per step (vLLM logs the value it
         chose at start-up). If the engine queues requests while its cache has room, this budget is
         usually why: long prompts use it all. Higher: waiting requests start sooner, but running
         requests generate more slowly while long prompts are computed, so a token-latency target
         lets fewer requests run. Lower: the reverse. The best value depends on the GPU, the model
         and the prompts; change it only after measuring your own load.
       - `--kv-offloading-size` (optional, suggested): a CPU KV cache tier improves agent
         workloads — conversations evicted from GPU memory while an agent pauses are reloaded from
         RAM instead of recomputed. It helps most with long conversations, little with short ones,
         and uses the host RAM you give it. In the deployment measured above, it changed the fixed
         limit's output by −2% to +63% and the learned limit's by +12% to +74%, the most on long
         sessions.
       - `--scheduling-policy priority`: needed for engine priority, and to send each request's class
         as its vLLM priority in the gateway-managed mode.

       The learned limit raises throughput where an engine was preempting, or was held below what
       its memory holds. On an engine that is neither, it mostly steadies latency.
   - **Engine metrics.** With **Read engine metrics** on — the default for a vLLM server — every
     gateway replica reads each endpoint's `/metrics` every few seconds, whatever the mode, and the
     server's dashboard shows the engine's queue, running requests, KV cache, throughput (prompt
     tokens served and computed, generated tokens), preemptions, prefix-cache hit rate (a prompt
     loaded back from CPU KV offload counts as a hit), time in its own queue, time to first token and between tokens. An engine-queue bound or a
     learned in-flight limit needs the reading, so either keeps the switch on. **Probe engines** asks every endpoint now, as the gateways
     do, and shows what answered and why not; once an engine has been seen keeping requests waiting,
     it shows the most it was running while it did and suggests a per-replica in-flight limit: that
     count divided by the gateway replicas. It is what the engine sustained, a starting point for a
     fixed limit — not its capacity. An endpoint's own limit wins over the server's, which is the default
     for every endpoint without one. When the engines differ (another GPU, other engine
     settings), the probe says so and suggests a limit per endpoint, each with **Use it**,
     rather than holding every engine to the smallest one's batch.
   - **Restricting a target to some classes** (route editor → *Allowed classes*) keeps, for
     example, Background traffic off an expensive fallback provider when your own pool is full. A
     target that names no class accepts all of them.
8. **(OIDC) Auto-membership** — set `oidc_claim_name` (the ID-token claim to read — e.g.
   `groups`, or `group` on AD FS; one value or a list) + a POSIX `oidc_claim_pattern` so users
   with a matching value auto-join on login (additive only — never removes or demotes). A claim
   the sign-in does not carry matches nothing. Under header auth the proxy's group header is the
   `groups` claim. Name a claim your directory sets — never one users can edit themselves
   (`name`, `nickname`), or anyone could join by choosing a matching value.
9. **(Optional) Policy profiles** — the workspace **Access** tab has one selector per policy
   type (Tool policy, Guardrail, Transforms, Experts), each defaulting to **Default (tenant
   default)**. Pick a different profile to give this workspace its own tool-policy posture,
   guardrail posture, set of transforms, or set of analyzing experts — or set it **Off** to
   disable that policy for the workspace; **Manage →** opens the profile's editor. Every policy
   page works the same way: a **Profiles** card list (the first tab) where you create profiles
   and open a card to edit it — under **Governance → Policy** (tool), **Guardrail**,
   **Transforms**, and **Experts**. A fifth selector, **Portal & clients**, picks which clients the
   portal and the CLI offer this workspace's members and what their sandbox may reach
   (see [9c](#9c-portal--clients-and-destinations--governance--portal--clients--destinations)): the Default or a profile, with no **Off** — and it is not shown on the Agent and
   Inline AI workspaces, which stay on the Default.

### 3b. Inline AI — connect an inline gateway

Every tenant ships with a built-in, undeletable **Inline AI** workspace and an
**Inline AI** service account. They exist for one integration: an external
enforcement point — typically a gateway inspecting AI traffic on your
network — hands Streamscope the AI traffic it intercepts. It can do so in two
ways, with one key, and usually uses both:

- **Redirect** — for a provider's own API (OpenAI, Anthropic, …). The gateway
  sends the intercepted request on to Streamscope, which calls the provider
  itself with the client's own provider key, exactly as for a pass-through key.
  Streamscope holds both directions, so policy is **applied** as on any
  pass-through request: a blocked tool is removed before the model sees it,
  and a call the policy refuses is removed from the answer the client receives.
  A streamed answer streams through; as on every streamed reply, the PII found
  in it is recorded, not masked.
- **Analyze** — for traffic Streamscope cannot call on the client's behalf —
  the AI web and desktop apps, whose wire is private to the vendor — and for
  any provider request the gateway does not redirect. The gateway
  submits each request it intercepts to Streamscope's **analyze API** and
  enforces the verdict it gets back (allow, flag with a redacted body, or
  block). Streamscope never forwards an analyzed request anywhere; it applies
  policy, answers, and records an audit row. The model's answer has already
  reached the client, so it is only observed.

- **The policy is the workspace's policy.** The guardrail, tool-policy, and
  transform profiles assigned to the Inline AI workspace govern both tracks:
  what a redirected request is screened and changed with, and what an analyzed
  one is judged by. They inherit your tenant defaults
  until you assign something else, so tightening the inline posture is the same
  three-state picker every workspace has.
- **Analyzed responses can be observed too.** A gateway running response observation
  submits the model's *answers* (`direction: "response"`) after streaming them
  to the end client. The verdict comes from the response PII-leakage scan —
  enable **PII → Scan model responses** on the workspace's guardrail profile to
  turn it on — and is informational (allow or flag, never a block or a
  rewrite): the bytes have already been delivered, so this surface is pure
  audit. The answer's tool calls are checked against the tool policy too, as a
  proxied answer's are, including a call to a tool the request blocked: what
  the policy would have removed or rewritten is recorded on the row with the
  **Not applied** chip.
- **The credential is the managed Inline AI key.** Open the Inline AI service
  account on the **Keys** page and use **Rotate inline-AI key**: the new key is
  shown once — paste it into your gateway's configuration, which uses it for both
  tracks. Rotating
  again revokes the old key.
- **Accepting redirected traffic.** Turn on each provider's pass-through (its switch on the
  LLM gateway's **Pass-through** tab) and grant it to the Inline AI workspace. A redirecting gateway
  names the provider host the client was talking to, and Streamscope then forwards only to the
  pass-through serving that host: traffic for a provider not granted is refused, so a client's key for
  one provider never reaches another. **The gateway must name the host** (`X-Origin-Host`): a
  redirected request that names none is refused, since nothing else says which provider issued the
  client's key. Nothing is granted there by default. A redirected request lands in the audit log
  like any pass-through request, in the Inline AI workspace, with the end client's address, user and
  groups the gateway reported.
- **Least privilege by construction.** For analysis only, grant the Inline AI workspace **no
  providers**: its key cannot reach any model or spend budget, and the analyze
  API accepts **only** this key — an ordinary gateway key is refused there. A
  leaked analyzer key can then do nothing but submit content for analysis. Once
  you grant providers for redirects, the key also reaches them — with a
  provider key of its holder's own — and whoever holds it can state the end
  client's address, user and groups on the audit rows: guard it like a
  provider key, and rotate it if it leaks.
- **Audit.** A redirected request is recorded as described above. Every analysis lands in the audit log under provider
  `inline-ai`, attributed by the application, session, and user agent the
  enforcement point reported. If the analyzer declared itself verdict-only and
  policy would have rewritten the content, the row carries a distinct
  **Not applied** chip — *Modified* always means the wire actually changed. A tool call policy
  would have blocked, and that nothing stopped, carries a **Would block** chip and an amber card, and
  is counted apart from blocks. An answer that carried an error is recorded as an error, from the
  status the enforcement point reports: one the client still received also says **Not applied**. The full end-client identity and per-message
  findings are returned to the enforcement point, which records them beside the
  response's correlation id — so the two audit trails join on one key.

### 4. Users & keys — **Keys** page

The Keys page is the single key inventory: every gateway key (`sk-`/`vk-`) and
every automation key (`ak-`), grouped by owner — human users, service accounts,
and the built-in agent, each labelled. The filter bar narrows **per key** (a
"Revoked" filter hides an owner's other, still-active keys) by search, status,
key type, owner, and workspace, and the view is URL-bound so a filtered link can
be shared or bookmarked.

1. **Create a user** — on the **Auth → Accounts** tab: email, optionally a
   password (one password covers console and portal sign-in — set it once, it
   applies to both automatically), and the access levels via the picker (console
   No access / Read-only / Admin; gateway user). Each account card shows both
   capabilities with its workspace memberships, and carries Disable / Enable per
   capability right on the card (access is removed via the Edit dialog's
   **No access** pick). OIDC users are auto-provisioned on first login.
2. **Assign to workspaces** — a new user joins no workspace automatically; add them to the
   workspaces they need (Default or a scoped one) on the workspace pages — any user can be
   added there as **member** or **manager** — before they can mint a key.
3. **Mint an API key** — expand the owner on the Keys page; pick a workspace and name; the
   `sk-…` (or `vk-…` for BYOK) key is shown **once**. The key reaches every provider/MCP
   server its workspace allows. For service accounts the same flow also offers admin
   automation (`ak-…`) keys.

### 4b. Service accounts & automation — **Auth → Service Accounts** tab

A **service account** is a non-human identity for an agent, application, or
automation. Unlike a user, it never signs in and is not tied to any employee — so
it keeps working when people leave, and it survives a switch to single sign-on.
Use it whenever a script or agent needs a durable credential.

Service accounts live on the **Auth** page (Service Accounts tab); their keys are
managed on the **Keys** page alongside everyone else's.

1. **Create a service account** — give it a name; an email identity is suggested
   automatically. No key is created yet.
2. **Attach keys on the Keys page** — the account's key count links straight to
   its keys. Choose a key type when adding one:
   - **Admin automation key** (`ak-…`) — calls the **admin API** to script
     provisioning, configuration, and inspection. It needs no workspace — an
     account that belongs to no workspace can still hold one. Pick a scope
     (the same words as console roles):
     | Scope | What it can do |
     |---|---|
     | **Read-only** | read endpoints only (mutations are refused) |
     | **Admin** | manage everything in this tenant (configure + inspect) |
     | **Operator** | *system tenant only* — manage across tenants (create tenants, platform-wide actions) |

     Use it by sending `Authorization: Bearer ak-…` — the key identifies its
     own tenant, so no extra header is needed. The reveal dialog shows a
     ready-to-paste example against your real endpoint.
   - **Gateway key** (`sk-…`, or `vk-…` for BYOK) — lets the agent call the LLM
     gateway *as* the service account, with the workspace's allowlist and budget.
3. **The key is shown once** — copy it at creation; only a fingerprint is kept.
   Give it an expiry if you like.
4. **Account lifecycle** — on the Service Accounts tab:
   - **Disable** — the account's keys stop authenticating but are kept; **Enable**
     restores them exactly as they were. Use it for a temporary suspension.
   - **Revoke** — terminal: the account is disabled and **all** its keys are
     permanently revoked.
   Individual keys are rotated (mint a same-shape replacement, reveal it once,
   revoke the old) or revoked on the Keys page.

Every admin action taken with an `ak-…` key is recorded in the admin audit log
against both the service account and the specific key, so you can always see which
automation made a change. The built-in review agent appears as a built-in service
account: it can't be disabled or revoked, but its gateway key can be **rotated**
in place from the same tab — the agent picks the new key up automatically.

In the **system tenant**, service accounts mint **Operator keys only** — the
platform tenant runs no gateway workloads, so gateway keys and tenant-level
scopes are refused there.

**Workspace managers can self-serve automation keys.** A workspace manager does
not need an admin to automate their own workspace. On the portal **Team** page,
under **Automation**, a manager creates an *automation account* and mints `ak-…`
keys under it. Such a key calls the **portal API scoped to that one workspace** —
acting with the manager's authority there (manage members' keys, view the
workspace's usage) and nothing else; the same key presented against another
workspace is refused. The plaintext is shown once, keys take an optional expiry
and can be revoked, and removing an automation account revokes its keys in that
workspace. Each action is recorded in the portal audit log against the automation
account and the specific key. (Admins can manage these accounts too — they appear
on the Service Accounts page like any other service account.)

### 4c. Automation recipes (`curl`)

These show the two most common automation tasks end-to-end with an admin
automation key. Every admin-API call carries `Authorization: Bearer ak-…` — the
key identifies its own tenant and acts only within it, so no tenant header is
needed. Set these once:

```sh
BASE=https://<your-admin-api>     # admin API base URL
AK=ak-…                           # an Admin-scope automation key (mint it on the Keys page)
H=(-H "Authorization: Bearer $AK")
```

**Request a gateway (LLM) key in a specific workspace.** This mints an `sk-…` key
bound to one workspace — it reaches exactly the providers and budget that
workspace allows. The plaintext is returned **once**.

```sh
# 1. find the workspace id you want the key scoped to
curl -s "${H[@]}" "$BASE/api/v1/admin/workspaces" | jq -r '.items[] | "\(.id)  \(.name)"'
WS=<workspace-id>

# 2. create a service account to own the key (or reuse an existing one's id)
SA=$(curl -s "${H[@]}" -H 'Content-Type: application/json' \
       -X POST "$BASE/api/v1/admin/service-accounts" \
       -d '{"name":"ci-bot"}' | jq -r .id)

# 3. mint the workspace-scoped gateway key — copy it now, it is shown only once
KEY=$(curl -s "${H[@]}" -H 'Content-Type: application/json' \
        -X POST "$BASE/api/v1/admin/service-accounts/$SA/keys" \
        -d "$(jq -n --arg ws "$WS" '{type:"gateway",name:"ci-llm",workspace_id:$ws}')" \
      | jq -r .key)
echo "$KEY"     # sk-…
```

(Add `"forward_auth": true` in step 3 to mint a BYOK `vk-…` key instead; the
response then also includes a `proxy_base_url` to call.)

**Render a full opencode config from that key.** The gateway speaks the
OpenAI-compatible API, so list the models the key can reach and emit a ready
`opencode.json` pointing every model at the gateway:

```sh
GW=https://<your-gateway>      # the LLM gateway base URL (shown on the LLM Gateway page)

curl -s "$GW/v1/models" -H "Authorization: Bearer $KEY" \
| jq --arg base "$GW/v1" --arg key "$KEY" '{
    providers: { streamscope: {
      package: "@opencode/ai/providers/openai-compatible",
      name: "Streamscope AI",
      settings: { baseURL: $base, apiKey: $key },
      models: ( [ .data[].id ] | map( { (.): { name: . } } ) | add )
    } }
  }' > opencode.json
```

The result drives the `opencode` CLI (OpenCode 2) against the gateway — all traffic is then
authenticated, budgeted, and audited under that workspace's key.

### 5. MCP gateway — **MCP Gateway** page

Extend the same auth, audit, policy, and budget controls to Model Context Protocol traffic.
Agents connect to a per-tenant `/mcp/<slug>` endpoint that fans out to one or more upstream
MCP servers.

1. **Add an MCP upstream server** — a name, the server's address, the **headers** it expects,
   and whether users also sign in to it with **OAuth**. A server is described the way the MCP
   Registry describes it (a `server.json` remote): its URL, which may contain `{variables}`
   you fill once, and a list of headers, each either a value on its own (an `X-Api-Key`) or a
   template such as `Bearer {token}`. For every value, you choose **who fills it**:

   | Filled by | Where the value lives | Typical use |
   |---|---|---|
   | **Administrator** | entered here, encrypted at rest, locked — no user can see or change it | a shared token, a server URL, a region |
   | **Each user** | entered by each user in **Portal → Sign-ins**, encrypted at rest, one value per user | a personal access token |
   | **The client** | sent by the user's MCP client on every call, never stored | a token the client already holds |

   A server with no headers needs no credential. **Bearer token (shared)** is a ready-made
   setup for the common case of one shared token: an `Authorization: Bearer {token}` header
   filled by the administrator. A value marked secret is never shown again after you save it;
   you can replace it or clear it. An optional value nobody filled is simply not sent.

   **Address variables.** A variable in the server's address takes a plain value (a site or
   tenant name, a port): `/`, `?`, `#`, `@`, `\` and spaces are refused, so a value cannot add a
   path, a query or a login to the address. A variable that forms the host itself still names
   whatever host you give it — only administrators fill these. A variable you leave empty takes
   its default, where it declares one. The server keeps the values its address was built from and
   shows them in its edit form: change one and the others keep theirs. Changing the address
   template keeps the values of the variables it still has, drops those it no longer has, and
   asks for a value for any variable it adds — a default fills a variable only when the server is
   first added. When a server's address moves to another host,
   every value users entered for it is deleted: each user enters theirs again for the new server.

   **Lock addresses.** When a header carries an address the server will call (a Jira or
   Confluence URL, for example), have the administrator fill it. A user-filled address lets
   the server reach any host its user names, and the gateway's own egress controls never see
   that call.

   **Worked example — a Jira and Confluence server using personal access tokens.** The server
   expects `X-Jira-Url`, `X-Jira-Token`, `X-Confluence-Url` and `X-Confluence-Token`. Declare
   the four headers (both tokens secret), set the two URLs to **Administrator** and enter your
   company's addresses, and set the two tokens to **Each user**. Grant the endpoint to a
   workspace; each user then opens **Portal → Sign-ins**, sees only the two token fields
   (the addresses are yours: users never see them), pastes their own tokens, and their calls
   carry all four headers. Until a user has entered their tokens, the server's tools are left out
   of that user's tool list, and calling one directly answers "connect this server first" instead
   of failing. If the server runs on your own network, a
   platform super-admin adds its host to the **MCP** egress list (section **A**, *Egress*).

   **Values the client sends.** A header set to **The client** is read from the user's own MCP
   client on every call and forwarded to that server only — no other header the client sends
   ever reaches the upstream. The client calls the usual `/mcp/<slug>` address with its gateway
   key. The one exception is a client-sent `Authorization` header: it would collide with the
   gateway key, so such an endpoint is reached at `/fwd/<gateway key>/mcp/<slug>` instead, and the
   generated client configuration uses that address. Two servers attached to the same endpoint
   cannot both expect the same client header — the gateway could not tell whose it is — so
   attaching the second one is refused. For the same collision, a server that expects the
   client's own `Authorization` cannot be attached to an endpoint with **Spec OAuth** sign-in
   (step 4): a signed-in client spends its `Authorization` on the gateway's token, so it could
   never reach that server. Attaching one, turning sign-in on for an endpoint that has one, or
   editing an attached server so that its client fills `Authorization` is refused — the message
   names the endpoint and the server. The gateway keeps no long-lived connection open to such
   a server for notifications, since it cannot reconnect without the client — and for the same
   reason a legacy SSE server (transport SSE) cannot take a value from the client. A value the
   client sends that the header does not accept (outside its choices, say) is refused as missing,
   never replaced by the default.

   **OAuth** can be combined with headers: the user's OAuth token then travels as
   `Authorization: Bearer`, so on such a server you cannot also declare an `Authorization`
   header. Whether a server uses OAuth is chosen when you add it and cannot be switched later —
   remove the server and add it again to change it.

   **How per-user OAuth works.** You register **one** OAuth application with the provider
   (for example a single GitHub OAuth App) — it identifies *the gateway*, not any person, and
   you set it up once. Each portal user then links their **own** account from **Portal →
   Sign-ins**: they're sent to the provider to sign in and approve, and the gateway keeps a
   **separate token for each user**, encrypted at rest. When a user calls the endpoint the
   gateway forwards **their** token to the upstream and **refreshes it automatically** when it
   expires — no re-approval needed. So everyone acts as themselves on the upstream, under one
   shared app registration. This is *delegated per-user authorization*, not single-sign-on:
   it lets the gateway act on each user's behalf against the upstream, it doesn't federate
   login identities. The gateway always uses the standard browser sign-in (authorization-code)
   flow — a provider "device flow" option is neither used nor required, and enabling it does no
   harm.

   For OAuth, paste the server URL and click **Discover endpoints**: the gateway
   reads the server's published OAuth metadata and fills in the authorization, token and
   revocation URLs plus default scopes for you to review before saving. Most modern remote
   MCP servers publish this; for one that doesn't, enter the URLs by hand. If the server
   points its login at a different domain than the server itself, the gateway flags it so you
   can confirm it's expected.

   You then supply that app's **OAuth client ID and secret**, and set its callback to the
   redirect URI shown in the form. For providers that support it, click **Register client
   automatically** instead: the gateway asks the provider to issue a client (dynamic client
   registration) and fills the ID and secret in for you. Discovery reports whether the server
   offers this, so a provider that doesn't (such as GitHub) switches the button off and tells
   you to register the OAuth app by hand, rather than leaving you to click it and wait for a
   failure. A server advertising a registration address the gateway won't connect to — plain
   HTTP, or one that resolves inside your own network — counts as not offering it.
   To make that hand-registration foolproof, the form shows a **provider setup guide** — it
   recognises common providers (GitHub, GitLab, Google, Atlassian, Slack, Notion, Linear,
   Asana, Airtable, with a generic fallback for the rest) from the server URL, links straight
   to that provider's OAuth-app console, and lists each field the console asks for
   (application name, homepage URL, authorization callback URL, device-flow toggle, …) with
   the exact value to paste and a copy button beside it. Pick a different provider from the
   guide's selector if the auto-detected one is wrong.
   Until this client is filled in the server can't be used: the **endpoint can't be granted
   to a workspace** (the grant is refused) and no one can connect from the portal. A server
   whose client is still incomplete is flagged in the **Upstream servers** list — open
   **Edit** to add the Client ID and Secret.

   **Test** a server from the **Upstream servers** list: the gateway connects to it with the
   values you filled — no user's and no client's — and shows the tools, prompts and resources it
   offers, or why it could not connect. A server that needs a value each user or the client
   supplies is not called: the result names the values it is waiting for (users enter theirs in
   **Portal → Sign-ins**; use the portal's **Try a server** page to test as a user). An OAuth
   server is likewise reported as needing a user's sign-in. Each such result says who acts and
   where: each user enters their values, or signs in, once under **Portal → Sign-ins**; a value
   the client sends is written into its configuration by the portal Quickstart and `ssai
   provision`. A value only you can set (missing, or stored with a key the gateway can no
   longer read) is reported with an **Open settings** button. Like the portal test, it never
   follows a redirect, and it is recorded in the audit log.

   Each server's card lists every header it declares and who fills it — **Administrator**,
   **Each user** or **The client** — and flags a required administrator value that is not set:
   every call to that server fails until it is. The gateway also records an operator
   notification (*MCP server cannot be called*) for an enabled server in that state, or with
   an incomplete OAuth client, linking to the server. It waits ten minutes after the server's
   last edit, so a server you are still setting up does not notify; it fires once, and again
   only if a later change to the server's values still leaves it unusable.

2. **Create a virtual endpoint** — a short slug reachable at `/mcp/<slug>`. Attach one or
   more upstreams; give each a namespace prefix when attaching several. A prefix is up to 16
   lowercase letters, digits and single underscores, starts with a letter and does not end in an
   underscore; the endpoint then offers that upstream's tools and prompts as `<prefix>__<name>`.
   The first upstream may be attached without a prefix and keeps its own names — even ones that
   contain `__` — except a name that starts like another attached upstream's `<prefix>__`: a call
   to it would reach that other upstream, so the endpoint does not list it.
3. **Grant the endpoint to a workspace** — add it to the workspace **MCP allowlist** (step
   3.3). Keys reach an endpoint only when allowlisted. An endpoint that routes an OAuth
   server with an incomplete OAuth client can't be allowlisted until you
   finish configuring the client — it is not offered, and the Access tab says how many are left
   out and why.
4. **(Optional) Spec OAuth** — enable OAuth 2.1 on the endpoint and register OAuth clients
   for native MCP clients (Claude Desktop, Cursor, ChatGPT) that discover via
   `WWW-Authenticate`. A client may be sent back to an `https` address, a loopback address on
   the user's own machine, or a private app address of the form `com.example.app:/callback` —
   the last is how desktop and mobile apps receive a sign-in on some platforms. Most clients register themselves on first connect, so registering by
   hand is only needed for apps that don't, or to pre-set the addresses a client may be sent
   back to. A third kind needs nothing at all: a client that publishes its own details at an
   `https` web address and uses that address as its identity is accepted as-is, and its
   published list of return addresses is re-read on every sign-in — so it can change where
   users are sent back to without you touching anything. Because such a client is never
   registered, it does not appear in the OAuth clients list; it appears instead under
   **Metadata-document clients** on the same tab, which lists every one that holds tokens in
   your tenant with how many grants and how many are still live, and offers **Revoke all**
   to cut one off in a single action.
   If you would rather not accept that third kind at all, turn off **Accept client ID
   metadata documents (CIMD)** on the **Auth** page: this is the only case where a client
   nobody registered can name a web address the gateway then fetches, once per sign-in.
   Turning it off also tells clients so in the endpoint's published details, so a client
   that would have used it registers normally instead of failing.

The **Catalog** tab browses a curated, built-in list of well-known MCP servers reached at an address
(name, description, category, tools, the headers each expects and whether it uses OAuth).
Each entry is a standard MCP Registry `server.json` document — you can view it as such.
Search and filter by category or by the kind of authentication (none, API key, headers, OAuth),
and open an entry to review its endpoint, headers, tools, and OAuth scopes. An entry you have
already adopted is marked **Adopted**, with the servers created from it; each server keeps that
link until the entry is removed (resetting the catalog keeps it).

**Adopt** an entry to wire it up in one action: it creates the upstream server, an endpoint
(`/mcp/<slug>`, slug pre-filled and editable), and the route connecting them — collapsing
the four manual steps above into one action. The adopt dialog asks for what the server
needs: the values of any `{variables}` in its address, **who fills each header value**
(administrator, each user, or the client — address-like values default to the administrator)
and the administrator's values, and for an OAuth server the OAuth client ID and secret. It
lets you grant the new endpoint to workspaces right away; everything stays editable on the
other tabs afterward. For an OAuth server you can **Register client automatically** here too
(for providers that support it), or enter the client ID and secret by hand; either way they
become **required when you also pick a workspace to grant** — adopt without selecting a
workspace to stage the server and add the client later (you'll be taken straight to its OAuth
form to finish).

Use **New entry** to add your own server to the catalog — paste the server's `server.json`
document (many MCP servers publish one; the MCP Registry hosts thousands) or fill in the form —
and **Edit** to change any entry. Editing a built-in turns it into your own copy, so it's no
longer overwritten when the catalog is updated (and returns to the shipped version only if you
reset). You can also **remove** an entry (a removed built-in stays gone) or **reset** the
catalog to its shipped state — none of these affect servers you've already adopted.

**Local MCP servers** — the **Local Servers** tab. Some MCP servers do not live at an address:
they run on the developer's own machine, started by the developer's client (a browser driver, a
repository indexer, an in-house tool). You keep them in the same place as the others, with the
same lifecycle: describe one, grant it to workspaces, and it is written into each member's client
configuration.

- **What you store is a command line**: the command, its arguments, and its environment
  variables. Anything the developer's machine can start is a local server — a program on the
  `PATH`, a script, `docker run …`. Each argument is one argument: nothing goes through a shell.
  **Some clients expand variable-looking text in a value** when they read their configuration
  (`${VAR}`, `$VAR`, `{env:X}`), so what you type is not always what runs — avoid such text unless
  you mean it. **The command must be installed on each developer's machine**: `npx` comes with
  Node.js, `uvx` with uv; nothing installs them for the developer. On Windows some clients cannot
  start `npx` or `uvx` directly and need the command wrapped (`cmd` with `/c npx …`): give Windows
  developers a server of their own with that command, or have them edit the written entry.
- **Add one by hand** with **New local server** — type the command, its arguments and its
  variables row by row, or paste a whole command line (`LOG_LEVEL=info npx -y some-server
  --port 8080`) into **Paste a command line** and let the form split it into those rows, which
  stay editable. The line is ONE command, quoted where a value holds a space: one that needs a
  shell — a pipe, `&&`, `;`, a redirection, `$(…)`, a comment — is refused and changes nothing,
  because nothing goes through a shell on the developer's machine. Or add one **from the
  catalog**: a catalog entry whose
  `server.json` declares `packages` offers **Add as local server** for each package. Adopting a
  package only prefills the form, and only what is safe to derive from someone else's document.
  An npm package becomes `npx -y <package>@<version>` and a PyPI package `uvx <package>==<version>`,
  followed by the package's own fixed arguments (a flag with no value is written as the flag). Its
  environment variables are prefilled too: one with a fixed value keeps it, a required one with
  none is left for each developer, and an optional one with none is left out. Any other package
  opens the same form with the command empty and a line saying why, and you type it: a container
  image, a NuGet or MCPB package, one that pins no version, one that does not run over stdio, one
  that names its own program to run instead of `npx` / `uvx` or passes arguments to the runner
  itself (they decide what it runs), one with an argument left to the user, and one whose values
  hold text a client would expand (`$…`, `{env:…}`, a backtick). You can
  edit the name and the slug before adopting; a slug you choose that is already in use is refused,
  while one derived for you is made unique. Paste a `server.json` from the MCP Registry with **New
  entry** to get such an entry; a document may declare a remote address, packages, or both, and one
  with neither is refused. The shipped catalog lists servers reached at an address only.
- **No secret goes through the gateway to a configuration file.** An environment variable either
  holds a plain value you set (a log level, a region), or is **left for each developer**: their
  configuration is written with a `<paste-your-…-here>` placeholder, they replace it with their
  own value, and a later update keeps what they pasted. A variable marked **secret** — by you,
  with its checkbox, or by the package's own description — holds no value here, and keeps the
  mark for as long as it exists on the server: an edit cannot clear it or give it a value.
  Removing the variable removes the mark with it. The mark guards against a mistake; it does not
  stop an administrator from typing a secret into another field, so do not. Values a developer
  supplies live in the environment only; arguments are always fixed.
- **Grant it** when you create or adopt it (**Grant to workspaces**), or later on the workspace
  page under **Local MCP servers**, exactly like an MCP endpoint; the Local Servers list shows
  the workspaces each server is granted to. The Agent and Inline AI workspaces cannot be granted
  one: they have no developers. Members of a granted workspace see the server in the portal
  Quickstart, below the gateway's servers and marked as running on their machine, with its whole
  command line (your environment values included); `ssai provision` proposes it too. A setup
  that gets only local servers needs no gateway key, and none is created for it.
- **Turning one off, revoking its grant or deleting it reaches each developer at their next
  `ssai sync`**: the whole entry is removed from the client configurations the CLI wrote — the
  value the developer pasted into it included — the sync says which server was removed, and
  everything else in those configurations is kept (a client set up for MCP servers only, whose
  last server this was, simply has nothing more written for it until it is given one again). The one
  exception is an entry that was already in the developer's file under that name before the
  server was first written there: it was theirs, so the sync takes out only what it wrote and
  they did not change, leaves the rest in place and names it. A developer who
  copied the entry from the Quickstart by hand removes it by hand. Until then the server keeps
  starting on that machine — the gateway is not on its path and cannot stop it.
- **The slug** is the server's name in the client's configuration and the prefix of its tool
  names. It is fixed when the server is created — configurations already written hold the server
  under it — so the edit form shows it read-only: to change it, delete the server and add it
  again under the new slug. A local server cannot take the slug of an MCP endpoint, and a configuration is never
  written with two servers under one name: selecting an endpoint and a local server that share a
  slug for the same client is refused.
- **Which clients can be given one.** Claude Code (in a project: the server is written to the
  project's own MCP file, so provision it from inside the project), Claude Desktop, Cursor, Cline,
  Codex, Continue, Crush, Gemini CLI, Goose, Mistral Vibe, OpenCode and Qwen Code. Aider, Zed and
  the curl / SDK snippets take no MCP server; Claude Code outside a project, and its MCP-only
  setups, register servers with a command of their own rather than a file, and are not given
  local ones. For those the server is left out and the Quickstart and the CLI say so; nothing is
  dropped silently. A client template you edit yourself declares whether it writes local servers
  (**Local MCP servers** on the template).

**What the gateway does not see.** A local server talks to the client directly, on the
developer's machine. Its calls never reach the gateway: they are not in the MCP audit, the MCP
dashboard or a session's MCP timeline, and MCP-side policy (which endpoint a key may address,
resource and prompt rules) does not apply to them. What the gateway does see is the model: when
the model asks to call one of the server's tools, that request passes through the LLM gateway
like any tool call, so **tool rules still apply** — a rule with a server filter matches the
tool's `mcp__<slug>__…` name — and the call appears in the conversation. Choose a local server
for what must run beside the developer's files; prefer an MCP endpoint when you need the audit.

**A command you save runs on developers' machines.** Treat this tab like a client template:
only administrators can edit it, every change is in the admin audit log (an adopted package's
derived command included), and the developer is shown the whole launch — `ssai provision` prints
each local server's command line, with the environment values you set, before it writes anything;
`ssai sync` prints it again whenever you change the command, an argument or one of those values,
as it applies the change; and the Quickstart shows it beside the configuration the member copies.
The line is written so that it can be pasted into a shell as it stands.

**Local servers and the sandbox** (`ssai run --sandbox …`):

| Sandbox | What happens to a local server |
|---|---|
| **Native** | The server is started by the client, so it is confined with it: same files, same network rules. A server that downloads itself on first start (`npx`, `uvx`) needs the npm or PyPI destination list attached to the sandbox, or the download is refused. |
| **Container** | The command runs inside the container image: its runner must exist there (`npx` does; `uvx` is not there by default), and a path on the developer's machine does not exist inside it. |
| **Either, for a server started through a container engine** (`docker run …`) | The engine starts the server, not the client, so no sandbox confines it. |

`ssai provision` prints the lines that apply to each local server it adds.

**Test a server** from the portal's **Try a server** page (step 10): it
connects as that user — your values plus theirs — and reports the tools each upstream offers,
or why it could not connect. A server that needs a value the client sends cannot be fully
tested there, and the result says so. The test never follows a redirect: a server that answers
with one is reported as redirected, so the test never sends a header to a host you did not
configure.

### 5b. A2A gateway — **Gateways → A2A** page

Where MCP connects your users to *tools*, A2A (the Agent2Agent protocol, 1.0) connects
them to *remote agents* — services that take on a whole task and return results. The A2A
page holds the tenant's registry of remote agents, each reachable through the gateway at
`/a2a/<slug>`:

- **Register an agent** by its agent-card URL (usually
  `https://<agent-host>/.well-known/agent-card.json`). The platform fetches the card,
  checks that the agent offers a JSON-RPC protocol-version-1.0 interface, derives the
  agent's endpoint from it, and caches the card. Cards larger than 256 KB, unreachable
  URLs, or cards without a usable interface are refused.
- **Card screening.** When your guardrail is configured, the card's text — its name and
  description, and each skill's description, examples, and tags — is screened by the
  tenant's **default guardrail profile** before the card is accepted. A card carrying a
  prompt-injection attempt is refused, at registration and on every re-fetch, and is never
  stored: the published card is read by every client that discovers the agent (and
  typically pasted into the calling model's context), so a poisoned card never enters the
  system. If the classifier can't be reached, the default profile's fail mode decides
  (fail-open accepts the card unscreened; fail-closed refuses it — retry later).
- The agent's **advertised skills** (from its card) are shown on its entry — skills are
  the agent's own description of what it can do. **Refresh card** re-fetches the card
  when the remote agent changes.
- **Upstream auth**: agents that need no credential, or a **service account** credential
  stored encrypted and sent on every call — as an `Authorization: Bearer` token by
  default, or in a custom header you name (for API-key-style agents).
- The **slug** is the agent's mount handle and is unique across the whole installation.
- **Workspace access** is granted per workspace on its **Access** tab (an **A2A agents**
  allowlist next to the provider and MCP lists) — no grant, no access, same as everywhere
  else.

**How clients reach the agent.** Point the client at `https://<your-gateway>/a2a/<slug>`. It
discovers the agent the normal way — the gateway publishes an agent card at that mount's
well-known path — but the card it gets is the gateway's: the endpoint is the gateway, the
advertised way to authenticate is an ordinary **gateway key** (`Authorization: Bearer sk-…`),
and capabilities the gateway doesn't serve are advertised as unavailable. Your users never see,
and never need, the real agent's address or credential. Clients must send the `A2A-Version: 1.0`
header; an older-dialect client is refused rather than silently mis-read.

Every call is rate-limited and counted against the workspace budget like any other traffic, and
lands in the audit trail — see **Audit → A2A** for per-call method, task and conversation ids,
task state, and the full request/response payloads. A2A calls interleave with LLM and MCP calls
in the combined audit view, and a client that sends the same session id on both surfaces gets
one joined session.

**Agent calls are governed like everything else.** Tool policy has an **agent calls** scope
(§ 7) that can refuse a call before it ever reaches the remote agent, or rewrite what is sent and
what comes back. The guardrail screens both directions on the workspace's guardrail profile: what
your agent *sends* to an outside agent (the data-loss surface — a customer's details on their way
to a third party), and what that agent *replies* (the injection surface — a remote agent's answer
goes straight into your own model's context, so a hostile or compromised peer would otherwise have
a direct line to it). A streamed reply is screened and flagged but not rewritten — those bytes
have already reached the client by the time a verdict exists. Whatever is rewritten on the wire,
the audit trail keeps the original: you always see what was really said.

**A2A has its own dashboard** (Observability → Dashboard → A2A), next to the LLM, MCP and Web
ones: which agents were called and how often, which operations, how their tasks ended, who called
them, and how many calls policy refused or the guardrail flagged. Every row is a link into the
matching audit view. Agent traffic also shows up on the **Overview**: the request-volume chart
stacks A2A alongside LLM and MCP, and a **Top A2A agents** panel ranks the agents your users
reached in the period.

**The audit feed filters on what an agent call actually has.** Choose the **A2A** kind and you can
narrow to one agent, one operation (`SendMessage`, `GetTask`, `CancelTask`, …), one task state, or
just the calls policy refused — the same shape as the LLM and MCP filter rows. Searching accepts a
task or conversation id, which is how you pull up every gateway call belonging to one remote unit
of work.

**A2A calls appear in session replay, and every call reads as caller → agent.** Each agent call
names who dispatched it (the caller — a user or a client app) and the agent it reached, so you can
see at a glance which agent was asked to do what, with the operation and task ids kept to a quiet
second line. When your orchestrator sends the same session id on its LLM turns and on the agent
calls those turns trigger, the session view shows them in one timeline — the model's decision, then
the agent-to-agent exchange it caused, with the message, the reply, and any artifacts rendered
inline (attachments, structured payloads and all). Any policy or guardrail finding is shown on the
call itself. Opening a call in the audit feed shows the same message, reply, and artifacts as the
timeline — with a **JSON** toggle for the payloads exactly as they crossed the wire.

**Streaming works.** An agent that streams can be streamed through the gateway — status changes
and artifact chunks reach the client as the agent produces them. The published card advertises
streaming only when the agent itself streams. Streamed calls are audited like any other, and the
audit drawer keeps the whole event sequence in order alongside the task's final state. (Very long
streams are never cut short for the client; only the audit copy stops growing past a size the
operator sets, and it says so rather than dropping events silently.)

**What is not served yet:** push notifications. The published card declares them unavailable, so
a well-behaved client won't attempt them; one that does gets a clear protocol error rather than a
hang.

By default the platform refuses to fetch cards or call agents at private network addresses; a
platform super-admin opens them on the **A2A agents** egress list (section **A**, *Egress*), without
affecting the MCP or web-fetch lists. An agent's address must be https, unless it is a private address
on that list: the agent's credential travels with every call, so plain http is checked on every
call and never follows a redirect.

### 6. Web search & fetch — **MCP Gateway → Web** tab

Every tenant has a built-in `/mcp/web` virtual server exposing `web_search` and
`web_fetch`. Configure the backend (SearXNG is the supported backend; set `endpoint` — your installation may have set it for you, and you can change it; an endpoint you enter must be a public `http`/`https` URL, only the one your installation was given may be internal),  its
**Destination lists** (§ 9c: a list attached as **allow** narrows the URLs the tools consider — search
hits and fetch targets — to what it names, and an allowed list with no entries lets nothing through;
a list attached as **block** removes what it names, and a block always wins; with nothing attached
every public site passes), `max_results`, and a fetch byte cap. For the Web tool a destination list
never opens an internal address: the platform's web egress list still decides those. `web_fetch` needs no
backend: it is served on every tenant, through the same destination lists and SSRF guard. `web_search`
is served once a search backend is configured — choosing no backend removes it again — and the
server's description to clients names only the tools it serves. To keep a workspace's agents off the web entirely, don't grant it the
`web` virtual server — and don't enable a web-fetch substitution rule for it, which serves
`web_fetch` through the gateway without that grant. **Substitution rules** (built-in tool rules,
off until you turn one on) replace a web tool the model is offered with the gateway's own: a
provider's server-side web search (Anthropic's, OpenAI Responses'), or the web fetch or
search tool of Claude Code, OpenCode, Gemini CLI or Continue. The model calls the tool it knows, and
the gateway runs it through this tab's destination lists, the SSRF guard and the guardrail. A call the gateway runs for such a rule is first
decided by your tool-call rules, as a call your users' client receives is: a rewrite changes what
is fetched, and a blocked call is never fetched — the model is told it was blocked, and the
request's audit shows the blocked call. The Claude Code rule also covers a WebFetch that Claude Code
has not loaded yet but lists as available, and a conversation in which the model already loaded
WebFetch keeps working on an Anthropic provider once the rule is enabled — or once WebFetch is
blocked. A non-bypassable SSRF guard refuses private
targets on fetch unless the platform's **Web fetch** egress list lists them, and the cloud metadata
address always (the URL filter chain runs first, the security guard second). A search backend on a
private address needs the **Extensions** egress list. Use the
**Test Search** button to verify. The backend credential is stored encrypted at rest.

**Prompt-injection guardrail (Governance → Guardrail; classifier under Settings → Guardrail).**
Guardrail posture is a **profile** you assign per workspace — create and edit guardrail profiles
under **Governance → Guardrail** (mode, sensitivity, inbound-prompt scanning, and PII detection),
then assign one to a workspace from its **Access** tab (a workspace with none runs the tenant
default guardrail profile). The shared classifier endpoint and detection-alert toggle stay a
single tenant-wide setting under **Settings → Guardrail**. When enabled, the gateway
screens the text the assistant pulls in through these web tools for **prompt-injection
attempts** — instructions hidden inside a fetched page or search result trying to hijack
the assistant — *before* that content is handed back to the model. In the default
**observe** mode nothing is altered: a flagged result shows a shield banner on that tool
result in the session trace (with a Low/Medium/High severity) and a badge on the request,
so you can see what *would* be blocked and judge the false-positive rate before switching
on enforcement. In observe mode the check runs while the model call is already in flight,
so it adds no noticeable latency. The guardrail needs a classifier endpoint, which is your organisation's own setting
(Settings → Guardrail): your installation may have set it for you, and you can change it. Enter a
self-hosted classifier or an OpenAI-moderations-compatible service. An endpoint you enter must be an
`http`/`https` URL on a public address; only the one your installation was given may be internal. Turning the
guardrail on also wraps fetched web content in clear "treat as untrusted data" markers for
the model (spotlighting). The same screening covers web searches and fetches a client makes
**directly** (calling the built-in web tools over the MCP endpoint, not through an
assistant's tool loop): those are watched in observe mode — a flagged result is marked on
its web activity record and the content still reaches the caller — so enforcement applies to
content folded back into a model, while direct calls are always observe.

**How much of a page gets screened (and how you know).** The screening reads content in
bounded chunks, up to a limit — **Settings → Guardrail** carries two: one for prompts and
responses, and a higher one for content the gateway fetched (web results and agent replies),
which is where injections hide and where the text is longest. The default covers roughly 58 KB
of a fetched page's text, enough to read a long article or reference page end to end. When a page is bigger
than that, or yields no readable text at all, the part past the limit is **never screened** —
so the gateway never records that page as clean: the request gets a guardrail badge reading
"could not screen in full", in observe mode as well as enforce (in enforce, **on detector
error → withhold** holds that content back too). Treat those badges as coverage gaps rather
than findings: if you see them on pages you care about, raise the fetched-content limit.
Screening more of each page costs a little more time per request, which is why a limit exists
at all.

Switch **mode** to **enforce** once the observe bake has shown the false-positive rate is
acceptable. In enforce mode a flagged page is **withheld from the model**: its content is
replaced with a short, plain-language placeholder ("this page was withheld — it looked like
it contained a prompt-injection attempt"), and the assistant simply carries on without it —
the request is never failed, because the attacker controls the third-party page, not your
user. The session trace marks that result as blocked. Because the content must be settled
before the model sees it, enforce adds the (small, local) screening time to the request,
unlike observe. The **on detector error** choice decides what happens if the classifier
can't be reached: **pass through** (the request proceeds and the gap is recorded — fail-open,
the default and what observe always does) or **withhold** (unscreened web content is held
back with the same placeholder — fail-closed). Either way the request completes; nothing
hard-fails. If a legitimate page is ever mis-flagged, lower the sensitivity or flip back to
observe from the Guardrail tab — the trace shows you exactly which page tripped it.

**Scan inbound prompts (off by default).** The screening above covers untrusted content
the assistant pulls in. Switch on **Scan inbound prompts** to also check the request the
user sends — their own message and any text file attached to it, plus any tool-result content a
client folds into it (for example a RAG passage, earlier tool output, a document a tool returned, the
output of a shell command or file patch a coding agent ran on its own machine, or the result of a
tool the provider ran that the client sends back as history) — for prompt-injection and jailbreak attempts,
using the same classifier. It is independent of the web-content screening (turning it on
never changes how web content is handled) and uses the same **mode**, **sensitivity**,
**detector timeout**, and **on detector error** settings: in observe it badges a flagged
prompt and leaves it untouched; in enforce it replaces the flagged message with the same
plain-language placeholder before the model sees it, so the request still completes but the
malicious text is withheld. A gateway screens every message it has not screened before, wherever it
sits in the conversation — a text it found clean is not screened again, a flagged one is screened and
reported again in each new conversation — and a message it withheld is withheld again whenever the
client sends it back as history. Each gateway keeps that record for itself, so after a restart, or on another
gateway, a conversation is screened again in full — and on a detector error, **on detector error**
decides as for any message: fail closed withholds it or refuses the request, fail open forwards it
flagged with a guardrail error. Leave it off unless you want to screen what users send, not just
what the assistant fetches; bake it in observe first to judge the false-positive rate on
your real traffic, exactly as for the web surface.

**PII detection (on by default, observe).** Like the injection guardrail, PII detection
starts **enabled in observe mode on the inbound request** — it badges and records findings
without altering anything until you switch it to enforce (or turn it off); response scanning
stays opt-in. The
**PII Detection** section on the same Guardrail tab finds personally-identifiable information
using a built-in detector that runs entirely inside the gateway (no classifier endpoint to
deploy). It covers the **general / US** entities —
email addresses, credit-card numbers, US Social Security numbers, IBANs, phone numbers, IP
addresses, crypto wallet addresses, and bank-account numbers — plus **per-country national
identifiers for France, Germany, Italy, Spain, and the United Kingdom**: national ID /
social-security numbers, VAT and tax numbers, passports, driving licences, and postcodes
(for example the French NIR, German Steuer-IdNr, Italian Codice Fiscale, Spanish DNI/NIE/CIF,
and UK National Insurance and NHS numbers). The entity selector groups these by jurisdiction
so you can enable just the countries you care about (each group has an **all / clear**
shortcut). Numbers that carry a checksum — cards, IBANs, and the national IDs / VAT codes —
are checksum-validated to keep false positives down; the more generic shapes (passports,
postcodes, plain tax/VAT digit runs) only flag when a relevant keyword sits nearby. It is
**independent of the injection guardrail above** — run either, both, or neither. Turn it on
and choose: **mode** (observe badges and records the finding; enforce masks each value in
place, e.g. `[REDACTED:US_SSN]`); whether to **scan requests** (the user's own messages, each
the first time a gateway sees it, before it leaves for the model — in enforce a masked message is
masked again whenever the client sends it back as history; a request that cannot be screened message
by message is forwarded and flagged with a guardrail error) and/or **scan responses** (what the model sends back — every answer of a reply that holds
several, as when a client asks for more than one; a finding in another answer is named by its
place, such as `choices[1]`); which **entity
types** to look for; a **sensitivity**; and the **redaction placeholder** used in enforce. One caveat for responses: a streaming reply is flagged and
recorded but its already-sent text isn't rewritten, so hard response redaction needs
non-streaming. Detected PII shows up inline in the session and audit views — the shield
banner reads as a PII finding and lists the entity types it matched — and the request carries
a "pii" badge (or "pii redacted" in enforce). Bake it in observe first to judge the
false-positive rate on your traffic.

Detections roll up beyond the individual request. The **Overview** dashboard shows a
**Guardrail** tile counting what the screening turned up in the period — detections plus
anything it could not screen in full — with a one-click jump to exactly those requests in
the audit log (the audit list also gains the same **Flagged or unscreened** filter you can
apply directly). Counting both is deliberate: unscreened content reaches the model just as
surely as flagged content does, so a tile that showed only findings would read as calm
while pages went past it unread. And if you switch on **notify on detection** in the
Guardrail tab, the gateway raises a once-a-day operator alert when injection is caught —
naming where it was seen (an inbound prompt vs fetched web content) and linking straight
to the flagged request — so you learn an attack was caught without having to watch the
dashboard. The tile follows the Overview's workspace filter (which excludes the Agent
workspace by default); the alert deliberately does not — an injection in a page the
assistant's own agent fetched is a security event worth surfacing, not background noise to
filter out.

### 7. Tool policy — **Governance → Policy** page

A unified risk-rule engine gates LLM tool calls, MCP `tools/call` / `resources/read` /
`prompts/get`, **and A2A agent calls**. Every tenant seeds ~49 protective builtin rules
(system-file access, credential theft, destructive commands, privilege escalation, …).

- **Risk Rules tab** — review/edit rules. A rule can **classify** (tag risk), **block**
  (strip a tool before the model sees it, or refuse a call), or **replace** (rewrite
  matched arguments). A rule targets a tool by its logical identity, so one rule covers
  every client of the same conceptual tool, plus optional argument patterns.
- **Agent calls** — a rule on the **agent calls** scope governs what your agents may send to
  a *remote A2A agent*, and what those agents may send back. There is no tool to name here (an
  agent call is a message, not a tool invocation), so such a rule matches on the message's
  **content** (its text) or its **data** (structured payloads), and is aimed at a specific
  remote agent with the **A2A agent filter** — a glob over the agent's slug, the counterpart of
  the MCP server filter. On the **request** side a rule can classify, block (the call is refused
  and the remote agent is never contacted), or rewrite the message before it leaves. On the
  **response** side it can classify or rewrite the agent's reply and its artifacts — it cannot
  "block" a reply, because by then the remote agent has already done the work; rewriting (or
  dropping) the content is how you withhold it. A refused call gets a clear "blocked by policy"
  error naming the rule, and is recorded with everything else.
- **Default posture** — out of the box the highest-confidence rules ship in **block**
  mode: reads or writes of credential files (`/etc/passwd`, `/etc/shadow`, SSH / cloud /
  cluster keys), destructive commands (`rm -rf /`, `mkfs`, `DROP TABLE`), reverse shells,
  and cloud-metadata / paste-site exfiltration. Everything operationally legitimate but
  risky — package installs, ordinary file/DB writes, `sudo`, `ssh`, deployments, broad
  `/etc` reads — ships in **classify** (observe) so it's flagged but allowed; tighten any
  of these to **block** when you're ready.
- **Profiles** (the first tab) — a card list of tool-policy profiles. The **Default**
  profile is the shared base every other profile builds on; create a named profile to give a
  workspace different rules. When you create one you choose how it relates to the Default:
  **Layered** (inherits the Default and you add only what's different — a profile diverges
  from a Default rule by *forking* it; delete the fork to revert) or **Standalone**
  (independent — start from the built-in defaults or blank). **Open a card to edit its rules**
  (a full-page editor); the Default (and any Standalone) has a **Reset to seed** button to
  restore the built-in defaults. A workspace selects a profile in step 3.7 (unset = the
  Default).
- **Detectors** — a rule condition normally matches a pattern you write (a glob, a regex, a list
  of keywords). For shapes no single readable pattern captures, pick **detector** as the
  condition's comparison and choose one of the built-in detectors instead. Each reads the
  *structure* of what the tool was asked to do rather than its exact wording, so reformatting a
  command — extra spaces, different quoting, a comment in the middle of a statement — does not
  slip past it. Ten ship:

  | Detector | What it recognises |
  |---|---|
  | Reverse shell | The `/dev/tcp` redirect, netcat with an exec flag, `socat`, and the interpreter one-liners |
  | Cloud metadata request | Every provider's metadata endpoint, including the numeric spellings of the link-local address a plain text filter misses, and the headers those services require |
  | Destructive SQL | Dropping a schema object, truncating a table, or a `DELETE` / `UPDATE` with no `WHERE` — read at the start of each statement, so one statement cannot shield another |
  | Credential in the arguments | An API key, private key or token sitting in what the tool was asked to do — recognised by its issuer's format and its length, so prose that merely names a key format is left alone |
  | Container escape | Reaching the host from inside a container: entering another process's namespaces, talking to the container daemon's socket, asking for privilege or the host's own namespaces, or mounting the host's filesystem root |
  | Package install | Installing third-party code with any of the common package managers — including behind `sudo`, later in a chain of commands, when the install verb is spelled as a flag, or run through the interpreter (`python -m pip install`) |
  | Fetched or decoded code executed | Content that was downloaded or decoded and then run — the `curl … \| sh` and `base64 -d \| sh` shape, whose text contains no dangerous command at all. A decode that only writes a file, or a pipe into a formatter, is left alone |
  | Assembled SQL keywords | A statement that builds its own keywords instead of spelling them — a chain of character codes, a hex literal, a base64 decode, or short quoted fragments glued together |
  | Double-encoded URL | A web address that encodes its encoding, so a filter that decodes once sees something harmless and the destination sees the real thing |
  | Lookalike or invisible characters | Letters from another alphabet that render identically to the ones written, or zero-width characters splitting a word — both invisible to a reader and to a keyword filter |

  Two are worth a note when you place them. **Double-encoded URL** should point at the raw
  argument rather than one you have marked as a URL: marking a field as a URL already strips one
  layer of encoding, which is what defeats the trick, and also removes what this detector looks
  for. **Lookalike or invisible characters** only reports a word that mixes scripts — a word
  written entirely in another alphabet is ordinary text in that language and is never flagged.

- **Matching the command itself** — for a shell tool, a condition can target `argv[0]`, the
  command being run, rather than the command line as text. `argv[0]` **is one of** `rm`,
  `shutdown`, `mkfs` names those three commands and nothing else — where a keyword list would
  also fire on a path like `/var/log/rm.log`. Position is read per command, so chaining
  (`echo ok; rm -rf /`), a wrapper (`sudo rm`, `env FOO=1 rm`) or a shell invocation
  (`bash -c "rm -rf /"`, or `bash -lc "rm -rf /"` as Codex runs every command) all still present
  `rm` at position 0 and cannot be used to slip past the
  rule. Use a higher index (`argv[1]`, `argv[2]`) for an argument position, or plain `argv` to
  match *any* word of the command. The match is exact on a whole word, so a family of commands
  (`mkfs`, `mkfs.ext4`, `mkfs.xfs`) needs a **glob** — `mkfs*` — rather than a list. This works
  on any tool whose argument you have marked as a shell command in **Field Profiles**; a tool
  with no such field never matches an `argv` rule. A command given as a list of words
  (`["rm", "-rf", "/"]`, as Codex's `shell` tool sends it) is matched as the command line it spells.
  Codex's current shell tools, `exec_command` and `shell_command`, which take the command as one
  string, and `write_stdin`, which types into a running command, are read as shell commands by
  the shipped field profiles.
- **Responses built-in tools** — the calls a Responses client runs itself are tool calls like any
  other: rules see them under their item type — `shell_call`, `local_shell_call`,
  `apply_patch_call`, `computer_call` — never under a client tool's name, and the shipped field
  profiles map them to **shell_exec** (the commands), **edit_file** (the patched file's path) and
  **browser_action** (the computer action's kind — a batch of several actions is matched by tool
  only), so the shipped shell and file rules apply. A
  blocked call is removed and the client told why; a rewritten one reaches the client as the same
  call with its command, patch or action replaced. A Responses client receives such a call only
  once it has been read whole; one that could not be is withheld and the client told. A shell
  call that states it ran in a hosted container has already run when it arrives: it is recorded,
  never blocked. Tool-result rules read these tools' outputs under the same item type: a shell
  call's output (its stdout and stderr together) and a patch's log; a redaction of a shell output
  is returned as its first chunk's stdout, each chunk's exit status kept. A computer call's output
  is a screenshot, which no tool-result rule reads. A `shell_call` lists several commands: a
  keyword or pattern condition finds any of them, while an `argv[<n>]` position counts across the
  whole list.
- **Patch tools** — `apply_patch` (Codex's, or any agent's built on OpenAI's tool) and
  OpenCode's `patch` name the files they change inside the patch text. The shipped field profiles
  read every file such a patch adds, deletes, updates or moves a file to as the edit's **path**, so
  a file-path rule ("no edits under `.github/workflows`") fires when any one of them matches; the
  patch text itself stays readable to a rule on any argument. Codex can also apply a patch through
  its shell tools (an `apply_patch` command, or one fed a heredoc under `bash -lc` or through
  `exec_command`): such a call is
  decided by your shell-command rules as before, and a **blocking** rule on the patch tool — a path
  rule — blocks it too; no other kind of patch rule changes its outcome. A shell command that runs
  anything else beside the patch is read as a shell command only.
- **Field Profiles tab** — for custom/undocumented tools, map wire argument names to
  canonical fields so argument rules can match them. An argument holding a whole patch takes the
  **patch** normaliser, which reads the files it names as paths. A discovery panel surfaces
  `(tool_name, field)` pairs seen in recent traffic with one-click register.

### 8. Experts, transforms & settings

- **Experts** (`/experts`, dashboard at `/dashboard/experts`) — seven AI experts
  (security, tool policy, cost, compliance, quality, anomaly, session linkage) continuously
  analyze sessions, flag them with severity alerts, and propose transforms and tool rules.
  Disabled by default: configure an upstream model, then **Experts → Settings** to enable
  and set the analysis cadence; the judge model is set on the expert **profile** (below). The **quality** expert judges broad session quality —
  response relevance, instruction & format adherence, faithfulness to the context the model
  was given, multi-turn coherence, and agentic tool-use effectiveness. Each expert can also
  run on its own model (a per-expert override on its edit panel), which wins over the judge
  model of every profile, so the workspaces of a profile on another model still reach it for
  that expert; point a judging expert such
  as **quality** at a model different from the one it is evaluating so its scoring isn't
  biased toward that model's own style. Review proposals under **Transforms → Suggestions** and
  **Policy → Suggestions** (approve to activate, reject to teach the expert). An approval
  installs exactly the version the list showed when you clicked: if the expert re-proposed it
  with different content since the list loaded, the approval is refused and the list reloads
  with the new version to review. The Transforms suggestion list also refreshes on its own, so
  read a suggestion again if it changes on screen. Each expert
  keeps editable persistent memory. **Pooled analysis**: by default, compatible experts share
  one analysis call per session (and one per session group for the cross-session experts —
  anomaly and session linkage), with each expert still answering separately and every expert
  required to give a complete verdict on every analyzed item — this cuts analysis cost and
  keeps one expert's backlog from starving the others (experts take turns in fair rotation).
  Turn **Pooled analysis** off on an expert's edit panel to always give it a dedicated call
  (it then shows a **Solo** badge); an expert with its own model override is pooled only with
  experts on that same model. **Expert profiles** (the **Profiles** tab) let you choose
  which experts analyze which workspaces — and with which **judge model**: each profile
  carries the model its experts analyze with. The **Default** profile holds the tenant
  baseline model (always set); another profile left on **Inherit** uses the Default's. To
  analyze one workspace with a different model, copy the Default, change the copy's judge
  model, and assign it to that workspace. The judge model list offers each text model the
  **Agent** workspace can call, once, by the name the agent calls it with: grant a provider on
  that workspace's Access tab to add its models, and saving any other model is refused. If a
  grant is revoked later, or the provider stops serving the model, the saved model stays in place
  and analysis **waits** rather than skipping sessions: the Dashboard notifies you, and analysis
  resumes where it stopped once the model can be called again or another one is chosen. A profile's **Analysis
  start** section shows how far its analysis has reached and which workspaces it covers, and
  restarts it from a date, and optionally a time: today means from now and skips a backlog, an earlier date analyzes
  sessions with activity since then again (this spends the Agent workspace's budget, alerts are never downgraded, and
  a suggestion may surface sooner). An identical alert note or issue is stored once; one the model words differently is
  stored again, because it may be a different finding. The time is for a single session its provider refuses, which the notification
  dates: restart from the minute after it, which also skips every other session before then that the profile has not reached. It applies at
  the next analysis cycle, inside the run window, keeps a disabled expert's own position, and moves for every workspace using the profile; to move
  one workspace alone, give it its own profile. A profile's page shows every expert as a card — what it looks for, what it
  reads, what it can propose, how many sessions it has analyzed — and clicking a card adds it to
  or removes it from the profile; one **Save** saves the model and the experts. On a Layered
  profile the Default's experts are marked **From Default** and cannot be removed there.
  The Default profile is an editable expert list
  seeded with every expert (trim it, or add to it); a Layered profile builds on the Default
  while a Standalone profile picks its own set, and assigning a profile to a workspace (from
  its Access tab) scopes analysis accordingly — a workspace set to **Off** is analyzed by no
  expert. **Reset to seed** restores the Default to every expert. (This scopes conversation
  analysis only; the tenant-wide tool-inventory review is unaffected. To stop an expert
  everywhere, disable the expert itself.) The **Prompts** tab holds the prompt text included
  for each input and output an expert uses. Saving a change marks the prompt **Edited**: new
  releases then leave it as you wrote it. **Restore default** puts back the shipped text, and
  later releases update it again.
- **Transforms** (`/transforms`) — Rhai scripts that modify requests (redact PII, inject
  guardrails, filter tools, compress context) and responses (filter output, sanitize tool
  args), filterable by model/app. The **Profiles** tab (the first tab) lists transform
  profiles; the **Default** profile is the shared base. **Open a card to edit that profile's
  request and response programs** (a full-page editor). A **Layered** profile adds its own
  programs on top of the Default's (shown inherited, read-only); a **Standalone** profile runs
  only its own. Assign a profile to a workspace from its Access tab (unset = the Default); a
  workspace set to **Off** runs no transforms at all. The Default (and any Standalone) has a
  **Reset to seed** button to restore the built-in programs. Edit and test scripts in-browser;
  modified blocks produce audit diffs. One exception to a response script's rewrite: a Claude
  thinking block that the provider signed, on a Claude model reached through the Anthropic API
  format, is passed on unchanged. The provider refuses a signed block that comes back altered, so
  a rewritten one would break the next turn of any agent that uses tools. The audit row shows
  **Not applied**, so you can see the script matched. Two settings still apply to such a block,
  because each promises that nothing unscreened reaches the client: a script that fails with the
  script failure mode set to closed suppresses the block, and the PII guardrail in enforce mode
  masks it in a reply that is not streamed (a streamed reply's PII findings are recorded, not
  masked). Either one means the agent's next tool-use turn is refused by the provider. The same thinking block is
  rewritten normally when the client speaks another API format, because the signature never
  reaches that client.
- **Settings** (`/settings`) — per-tenant knobs, edited live:
  - **Defaults** — `proxy_public_url` / `admin_public_url` / `api_public_url` (used by
    quickstart snippets, OIDC callbacks, MCP OAuth metadata, CORS).
  - **Audit Retention** — how long audit rows are kept before auto-purge.
  - **Accounting** — the **currency you keep your books in**. Every budget cap, every spend
    figure on the dashboards, and every cost on an audit row is expressed in it. It is US
    dollars unless you change it.

    Models can be priced in other currencies — several European providers quote euros — so
    alongside the currency you maintain a small **conversion table**: one rate per currency
    pair, entered by you. Streamscope never fetches rates itself, because an air-gapped
    deployment has no way to and because a rate that moved on its own would silently restate
    spend you had already reported. Each request records the rate it was converted at, so
    changing the table from here on affects only new traffic; last month's figures stay as
    they were reported.

    Changing the accounting currency is a deliberate, rare act, and one consequence is worth
    knowing before you do it: the current daily and monthly spend windows restart at zero,
    because their running totals are counted in the previous currency. Past rows are not
    restated — that is the point of recording the rate each one used.

    A period that straddles such a change therefore holds figures in two currencies, and
    Streamscope will not add them: a spend figure covering that period is shown as its
    components, one per currency, and anywhere there is room for only one number — a row in
    a breakdown table, for instance — it reads **mixed** rather than a total that would be in
    neither currency. That holds for every money figure: the users and keys, media and team
    views and the response cache's savings alike. A list ranked by spend never compares
    amounts in two currencies: it ranks by what each entry spent in today's currency,
    largest first, and entries with nothing in it follow. An entry whose own period
    straddles the change reads **mixed** but keeps its place by what it spent in today's
    currency, so a top-spenders list still shows its biggest spenders.

    A session's spend in the session lists follows the same rule. A session whose requests
    were all charged in one currency shows its total in that currency; one whose
    requests span a change of the accounting currency shows **no single figure** instead of a
    total. A session that charged nothing shows no amount, whatever its history. In a
    session's conversation, each call's own cost is shown in the currency it was charged in.

    The page lists the currencies your own models are actually priced in, and flags any that
    the table cannot yet convert. **A model priced in a currency with no rate records no
    spend** — its requests are flagged rather than converted at a guess, so they show up as
    something to fix instead of quietly reading as free. The flag is visible on the request
    itself in Audit, without opening it, for exactly that reason: in a column of costs a
    floor of zero and a genuinely free request look the same. Add the missing rate and
    traffic from that point on is priced normally.
  - **Feature toggles** — JSON Healing, Message Compression, Debug Mode,
    Audit Logging, Content Logging, and **Media Blob Storage** (retain media
    binaries for review, with a max-size cap; off by default). Transform diffs
    (before/after of each policy/transform step) are always captured whenever
    Content Logging is on — there is no separate toggle.
  - **Agent** — the expert loop's cadence (interval, session cooldown) and run window; the
    judge model lives on the expert profiles (Experts → Profiles).
  - **Advanced** (super-admin) — the process-settings catalog with central edge overrides, and
    **Trusted CAs**: a PEM CA bundle trusted for all of the gateway's outbound HTTPS (upstream
    providers, the liveness probe, model discovery, OIDC, MCP, web fetch, the guardrail
    classifier) on top of the system
    roots — needed for self-hosted providers served by a private/internal CA. It applies to
    adding/validating a server immediately; running gateways pick it up on their next restart.
  - **Egress** (super-admin) — the platform's internal-egress lists (section **A**, *Egress*).

### 9. Observe & investigate — Dashboard, Audit, Sessions

Configuration is half the job; the other half is watching what flows through. These views are
admin-console only (read-only accounts see them too).

- **Dashboard** (`/dashboard`) — the at-a-glance plane, with a global period + workspace selector.
  The **Overview** sub-tab shows request volume, tokens, and cost, an error breakdown, the top users
  / clients / models, and the operator **notifications** feed (newest first; each links to where you
  act). Dedicated sub-views drill in by surface: **LLM**, **Media**, **MCP**, **Web**, and **A2A**
  traffic; **Users** and **Tools** breakdowns; **Transforms** and **Experts** activity; and **Proxy**
  (the gateway's own throughput and latency).

  **Refresh and auto-refresh.** The refresh button in the header — or the **R** key anywhere outside
  a text field — reloads what the page shows, once, on every page that shows live data; in the
  console and in the self-service portal alike. In the console, on the pages you read rather than
  edit — the dashboards, server pages, sessions, the audit and tool-call logs — the **auto** toggle
  beside it (or **Shift+R**) keeps the page current (the portal has no auto-refresh: members
  refresh by hand): a reload now, then every 30 seconds for the
  next hour, on whichever of those pages you move to. On a page where you change settings it cannot
  be switched on, and a running one holds there until you return — its hour still counting: refresh
  those pages by hand. While it runs the toggle
  reads *auto · 42m*, the time left; click it again to stop. Nothing is reloaded while the browser
  tab is hidden, and that time does not count toward the hour; coming back reloads once if a
  refresh fell due meanwhile. An automatic reload waits while you are editing — a dialog open, or
  the cursor left in a text field — and the toggle then reads *auto · paused* (click elsewhere to
  let it run). Every reload keeps what you are looking at: the same page of a list, the same open
  row; one that fails says so and leaves the page as it was. With auto-refresh off, a page's
  figures and lists change only when you refresh. A headline figure that
  moved in the latest refresh shows ↑ or ↓ before it; changing the period, the workspace or the
  page never shows an arrow.

  The Overview's attention tiles include **Upstream health**: red while an LLM server can serve
  nothing (every gateway that sends to it has taken every enabled replica out of rotation — a
  gateway that has not sent to the server in the last ten minutes has no say), amber while one is
  degraded (some gateway has some replica out, and the rest carry the traffic), requests were refused for
  want of capacity in the window (a refusal a fallback then absorbed included), or an engine whose
  queue bound depends on its metrics has stopped reporting (an engine read only for its charts shows
  as *Silent* on its server's page instead); it opens the server that is down, or the Servers view. A
  breaker opening also posts a notification — the tile is the state now, the notification the
  history.

  **Servers** (Dashboard → Servers) lists every LLM upstream server: its health, requests, the
  share that failed, how many were refused for capacity, and its P95 latency, time to first token
  and wait for capacity — latency here excludes the wait, which is shown on its own, so a busy
  queue is never mistaken for a slow engine. A refusal is not counted as a failure: it is the
  gateway declining to send a request the server had no room for. Where the gateway gates a server
  (a capacity is set on its **QoS** tab) the list also shows the requests in flight now against the
  slots the gateways may use, and any held waiting at the gateway; a server whose engines are only
  read for their metrics is not gated and shows no count. A server's own page shows, next to its
  health, one word for what its scheduler is doing now (hover it for the sentence) — *Not gated*
  (nothing is held for it: requests go straight to the engine), *Idle*, *Queuing* (requests are
  waiting and priority decides), *Refusing* (requests were refused for capacity within the current
  hour, on an hourly view) or *Engine not heard* (a gateway has stopped reading an engine, so its
  queue bound is not applied). It then shows requests and latency over the period, and where
  requests are: held at the gateway per class, in flight at each endpoint, and running and waiting
  inside each engine, with its KV cache. Each of those is one card with two plots on one scale: the
  last 15 minutes, one step per two gateway heartbeats, refreshed as they arrive whatever period is
  selected, with the value now in the card's title; and the selected period, in hours up to 8 days
  and in days beyond. Both plot each step's **peak** — the gateways report the highest value they
  saw since their previous heartbeat, not only the value at that instant — so a burst of a few
  seconds keeps its height, and the tooltip adds the step's mean. Every value axis ends on a round
  number just above the data (in steps of 1, 2 or 5). A dotted line marks the in-flight limit the
  gateways apply to each endpoint — its own, or the server's default, and the label says which —
  and a learned limit is drawn dashed instead. The running card marks the engine-queue bound and
  where each engine queues — **queueing from N running**, the most it ran while it still kept
  requests waiting in the period. That is what the engine sustained, not its capacity: an engine
  queues on its token budget per step as well as on its memory or its batch cap.
  Where the in-flight limit is learned, **Learned limit: what it did** counts,
  per step, how often the gateways raised it, stepped it down for a token latency above the target,
  and backed off (the cause — a preemption or a full KV cache — in the
  tooltip); its header names the token latency target, if
  one is set, and a **Time between tokens** card then charts each engine's average against it (the
  target is held against the median, which leaves out the pauses for new prompts that the average
  counts, so an average above the target is not by itself a miss). The engine's throughput follows — tokens
  generated, prompt tokens served and prompt tokens actually computed per second (served but found
  neither in the prefix cache nor in CPU KV offload: a history being recomputed shows as computed
  rising toward served) —
  then its own queue time and time to first token (the time between tokens in the tooltip), with
  preemptions and the prefix-cache hit rate when there is something to show. These cards too show the last 15 minutes beside the period. A period with nothing held, or no
  preemption, says so in one line instead of a card of zeros. Then requests and waits per class over time, each replica's health,
  share of traffic, failures and in-flight limit (its own, or the server's default), the priority
  classes it served with how
  many waited and why any were refused, and the users who waited longest. As on the other
  dashboards, a period with no traffic reads zero rather than leaving a hole; only an engine that
  was not heard from leaves a gap. Live load history covers the
  last 7 days, or your retention window if that is shorter; the other figures follow the
  retention window. Every figure counts each attempt at the server where it happened: a request
  that one server turned away for capacity, or that failed there, and then moved on to another
  replica or fallback counts as that server's refusal ("moved on") or failure ("failed over") — a
  server failing every request its fallback then answers reads as failing, not idle — and neither
  a wait nor the time spent on an earlier attempt lands on the server that finally served it. The
  share that failed is taken over what was actually sent, and counts only the server's own
  failures: a refusal, a client hanging up, or a model running out of room is not one. Refusals, waits and the attempts a
  request moved on from are recorded from this release on, so a window reaching further back
  shows none before it.

  The LLM sub-view's **Cost** tile breaks the period's spend down by what was actually charged
  for — input and output tokens, cache reads and writes, generated images, seconds of audio or
  video — because those are the lines a provider bills. There is no single "input vs output"
  split to show: a second of audio is an input for transcription and an output for
  speech-to-text, so it belongs to whichever one the request used, not to a fixed column.
- **Audit** (`/audit`) — every request, 100% coverage including auth failures, rate-limit rejections,
  and upstream errors. Filter by user, app/client, status, period, workspace, and **kind**
  (`llm` / `mcp` / `web` / `a2a`); open a row for the full trace. Content (request/response bodies)
  appears only when **Content Logging** is enabled. A row badged **Record Stripped** was too large
  for its gateway to deliver whole: who, when, status, tokens and cost are recorded; its structured
  payloads (parameters, results, diffs) are not, and long text may show only its size. A row badged
  **Content Unavailable** names content — a conversation message, its tool definitions, its system
  prompt or a media file — that never reached the console: its gateway could not deliver it, or the
  console could not store it. The request is recorded in full otherwise, and its trace and
  conversation show everything else; the missing content is simply absent.
- **Sessions** (`/sessions`) — agentic conversations grouped into sessions and **replayed**
  turn-by-turn: messages, tool calls, thinking/reasoning blocks, and media, rendered the same way the
  gateway saw them. Parent/child **linkage** surfaces sub-agents (Claude Code, Cursor, …). Severity
  **badges** flag sessions the experts found noteworthy.
- **Tool Calls** (`/tool-calls`) — every tool invocation (LLM and MCP) with the policy rule that
  classified, blocked, or rewrote it shown inline — the fastest way to audit what agents are doing.
- **Searching** Audit, Sessions and Tool Calls (and the portal's Requests and Sessions) takes a
  term of at least **3 characters**: a shorter one would read every request in the period, so the
  search box says so instead of searching. A search always runs within the period selected.
- **Admin Audit** (`/admin-audit`) — the control-plane trail: who changed what, every
  create/edit/delete/action with a **before → after diff** (secrets redacted) and the actor, IP, and
  request. A deletion's preview (the impact shown before you confirm a delete) is recorded under
  its own action, ending in `_dry_run`, so it never reads as the deletion itself. The portal has
  its own equivalent for manager/member actions.

Agent (expert) traffic is tagged separately and can be excluded from analytics and audit with one
toggle, so it never skews your real-usage numbers. Retention is set in Settings (§ 8).

### 9b. Clients — **Clients** page

Identifies the **AI clients/apps** hitting the gateway and serves them per-app onboarding. Three tabs:

- **Detection** — which client applications have been seen in traffic (Claude Code, Cursor, opencode,
  …), so you can recognise who's connecting and how much each app drives. The **App Registry** here
  decides how a request is recognised, in this order: an `X-App-Id` header the client sends names the
  app outright; otherwise its Referer, then its User-Agent, is matched against each app's patterns;
  and only when none of those matched is the opening of the request's system prompt matched against
  the app's **system prompt patterns**. That last signal is what recognises clients that send no
  User-Agent (Goose) or a generic one (the Continue CLI, Aider). Patterns match ignoring the case of
  plain (ASCII) letters; a system prompt pattern is one sentence per line, at least 12 characters (a shorter one would claim
  other clients' traffic), and should be a phrase only that client's prompt opens with — its name,
  typically. Add or edit an app with **+ Add App** / **Edit**; the new patterns name traffic from
  then on — an audit row keeps the app it was recorded with. A web search or fetch the gateway ran
  for a request follows that request's app.
- **Profiles** — the per-app quickstart configuration itself: the copy-paste setup the portal's
  Quickstart wizard renders for each client, editable here. Every profile ships built-in and is
  updated for you when you upgrade; edit one and it becomes **customised**, and from then on it is
  yours — upgrades leave it alone. **Reset** puts a single profile back to the shipped version, and
  **Reset built-ins** does it for all of them at once. Deleting a built-in — customised or not —
  hides it rather than destroying it, so an upgrade will not bring it back; **Reset built-ins** is
  what restores it.
  Profiles you create yourself are deleted for good — except one created under a deleted built-in's
  name, which is hidden like the built-in it replaced. A reset leaves them alone, unless one of them
  uses the same name as a built-in — then the shipped version replaces it.

  A profile holds one or more **templates** — the file a client reads, with placeholders for the
  gateway URL, the model, and the key. Some tools take their credential from a second file of their
  own instead (a secrets file, or an environment file the tool loads on start), and a tool may need a
  step the user runs because no file can carry it (Claude Code's MCP servers are added with its own
  `claude mcp add-json` command, since it keeps them in a file holding its own state); that file or
  step is part of the profile too, so a client you add or copy carries it. A second file can name
  where it goes in a project, or exist only in a project (Claude Code's `.mcp.json`), and a file or
  step with nothing to say for a render (no MCP server selected) is left out. **Preview** renders a draft against sample
  values before you save, and the placeholder reference lists everything you can use. In a YAML template, a
  value that adds fixed text to a placeholder is written `{{concat "openai/" model_alias}}`, not
  `openai/{{model_alias}}`: a model id YAML must quote (`llama3.1:8b`) would otherwise land with the quotes
  inside the value.

  Saving is refused if a template would hand the user a config with no key in it — the commonest way
  to ship something that looks right and cannot connect. If a tool genuinely reads its key only from
  a shell variable, say so with **Key delivery → environment** and the Quickstart shows the user the
  key itself instead.
- **CLI Sessions** — every machine a member has signed in on with `ssai login`, with the
  device name it reported, who it belongs to, when it was **last active**, and how long it has left.
  Last-active is recorded about once a minute rather than on every request, so it answers which
  machines are still in use — which stale laptop to cut off — rather than giving the exact time of a
  call; a device that hasn't called since this was first recorded shows a dash. **Revoke** cuts off that one
  device at its next request and leaves the same user's other machines working — the answer to a lost
  laptop that does not require disabling the person's whole account. Filter by lifecycle (active,
  revoked, expired) to audit what is still live.

### 9c. Portal & clients, and destinations — **Governance → Portal & clients** / **Destinations**

**Destinations** holds the organization's **destination lists**: named sets of network destinations
that something else attaches, each either as **allow** or as **block**. A list says nothing by itself —
the same list can be allowed for the developers' sandbox and left off (or blocked for) the Web tool.
It is not the platform's egress list, which decides what the gateway itself may reach: attached to the
Web tool, a list never opens an address that egress list refuses; attached to the sandbox, it decides
what the developer's own machine may reach, which the gateway's egress list does not cover. One entry
per line:

| Entry | Matches |
|---|---|
| `git.corp.example` | that exact name |
| `*.corp.example` | every name under it (`a.corp.example`, `a.b.corp.example`) — never `corp.example` itself; at least two labels (`*.com` is refused) |
| `10.20.0.0/16`, `10.20.1.7`, `[fd00::]/8` | addresses: an IP-literal destination, or (in the sandbox) the address a name resolves to |
| `…:443,22`, `…:8000-8100` | the ports, after a `:`. Without them, an allowed entry is port 443 only, and a blocked entry is every port — a host you block is blocked whole |

`*`, a prefix of length zero, a scheme or a path are refused when you save, naming the line. The cloud
metadata address is never reachable, whatever a list says. Lists ship **seeded** for the common
developer destinations — Docker Hub, GitHub Container Registry, GitHub, GitLab.com, npm, PyPI,
crates.io, Go modules, Maven Central and Gradle, Ubuntu, Debian and Alpine packages, Microsoft and
Quay container registries, Kubernetes downloads, Dev Container features — plus **Paste and
file-sharing sites**, meant to be blocked. A seeded list behaves like every seeded item: editing it
makes it yours (upgrades leave it alone), **Reset** puts it back, deleting it hides it, and
**Restore seeded lists** brings back every one. Each list shows where it is attached. Deleting a list
detaches it everywhere — except the Web tool's only allowed list, whose deletion is refused: without it
the Web tool would pass every public site. Detach it on the Web tab first.

**Portal & clients** decides what the portal and the CLI offer, per workspace. The page lists the
**profiles**: the **Default**, which applies to every workspace with no profile of its own, and the
profiles you create for a team. Each line says which workspaces the profile is **used by** and how
many clients it offers.

- **New profile** makes an independent copy — of the Default unless you pick another profile, or a
  fresh one that offers every client and attaches no destination list. A profile owns its whole
  content: a later change to the Default does not reach it, and a change to it does not reach the
  Default. The one thing profiles share is a destination list's entries — a profile attaches a list,
  it does not copy it, so editing the list on **Destinations** reaches every profile that attaches it.
- **Assign** a profile on the workspace's **Access** tab (**Portal & clients**: the Default or a
  profile). There is no **Off**: a workspace always has a set of clients and sandbox rules. The Agent
  and Inline AI workspaces cannot be given a profile; they stay on the Default.
- **Delete** removes a profile; the workspaces it was assigned to go back to the Default. The Default
  itself cannot be deleted.
- **Set as default** makes another profile the Default, as it stands — nothing of the previous Default
  is merged into it, and the previous Default stays in the list as an ordinary profile with its
  content. Every workspace with no profile of its own, and the Agent and Inline AI workspaces, follow
  it: the portal Quickstart the next time it loads, a developer's `ssai` at their next provision, sync
  or run. A workspace that was assigned the promoted profile is simply on the Default from then on —
  its assignment is removed, so it follows whichever profile is the Default later.

A profile presents; a workspace grants. The profile chooses which clients are offered and how the
sandbox is set; which providers and MCP servers those clients can be configured with stays the
workspace's own grants. A member of several workspaces gets, in each, that workspace's clients and
sandbox rules: the portal Quickstart works in the workspace selected in the portal header, and
`ssai provision` asks for the workspace before it lists the clients. Both then offer only what that
workspace grants — its providers and its MCP servers, not those of the member's other workspaces.
Choosing the Default in a workspace's **Portal & clients** selector is the same as leaving it on the
Default: the workspace follows whichever profile is the Default later.

For example: the Default offers every client with the sandbox optional. You create **Finance** (a copy
of the Default), keep only Claude Code, turn on **Require the sandbox**, and pick **Finance** on the
Finance workspace. A Finance member's Quickstart and `ssai provision` then offer only Claude Code, and
`ssai run --sandbox off` is refused there. Someone in both Finance and Platform gets Claude Code and
the required sandbox when working in Finance, and every client when working in Platform.

Open a profile to edit it:

- **Clients** — a switch per client. A disabled client is no longer listed in the portal Quickstart
  or offered by `ssai provision` for the workspaces on this profile, and rendering or provisioning it
  there is refused; a developer who already has it is told by `ssai sync` that it is disabled (its
  files are left alone; `ssai forget` removes them) and `ssai run` refuses to launch it. A client you
  create on the Clients page is offered on the Default as it is when you create the client, and
  arrives **disabled**, flagged **new**, on every other profile; a client a later release adds arrives **disabled** and
  **new** on every profile that existed before it — enable it on each profile that should offer it.
  **New** means exactly that: the client was added after this profile was created and is not offered
  on it. A profile created afterwards never shows it as new — a copy starts with what its source
  offers, switched on or off. **Offer all** and **Offer none** switch every client in one step.
- **Sandbox** — what `ssai run` lets an agent reach besides the gateway: the destination lists
  attached as allow or block. The gateway is always reachable; then a blocked destination is refused,
  an allowed one permitted, and anything else refused. A new organization attaches nothing (the
  gateway only); **Use the developer defaults** attaches, in one step, Docker Hub, GitHub Container
  Registry, GitHub, npm and Yarn, PyPI, crates.io, Go modules, Maven Central and Gradle and Ubuntu
  packages as allow, and the paste sites as block — each stays detachable; the other seeded lists
  (GitLab.com, Debian and Alpine packages, Microsoft and Quay registries, Kubernetes, Dev Container
  features) are yours to attach. Add your own internal services (registry, git server, artifact mirror) as a list of
  your own and attach it beside them. **Require the sandbox** refuses `ssai run --sandbox off` and `--sandbox learn`
  (which leaves the filesystem unconfined); on Windows the developer first runs `ssai sandbox setup` once
  (see *The Windows sandbox* under [Set up tools with the `ssai` CLI](#set-up-tools-with-the-ssai-cli)). **Allow the container sandbox** (on by default) lets developers
  run `ssai run --sandbox docker`, which starts the agent in a container on their Linux machine; turned
  off, that run is refused and names `--sandbox native`. Both settings apply to the workspaces on this
  profile. `ssai` enforces these on the developer's machine: a guard against an agent's mistakes and
  injected instructions, not against a developer who edits their own machine. Traffic to an allowed
  destination does not pass the gateway, so it is not in the gateway's audit.
- **Portal pages** — two switches for what members see of their own activity in the portal:
  - **Hide conversations** — the Sessions page and all conversation content: a request's details,
    its media and its tool definitions.
  - **Hide the Requests page** — the list of requests (model, tokens, cost, status).

  What each combination leaves a member:

  | | Requests page shown | Requests page hidden |
  |---|---|---|
  | **Conversations shown** | Sessions, with every conversation. Requests, and each request opens on its content. | Sessions, with every conversation — the requests of a session are read there. No Requests page. |
  | **Conversations hidden** | No Sessions page. Requests lists each request with its time, model, tokens, cost, duration and status; a request does not open, the list has no content search, and nothing of what was sent or answered is shown — no prompt, answer, tool arguments or results, searched or fetched URLs, media, or error text. An MCP call still names the tool it called. | Neither page. Home, keys, usage figures and limits only. |

  What is hidden is withheld by the gateway, not only left out of the page: opened by its address a
  hidden page says it is not available, and a script or an automation key asking for the same data is
  refused. Three things to know:
  - **Every workspace decides.** Each switch applies to a member only when *every* workspace they
    belong to is on a profile that has it on. Someone in Finance (hidden) and Platform (shown) keeps
    it — and sees there what they could see before, Finance's shared activity included. A member of no
    workspace follows the Default. To hide something from everyone, hide it on the Default and on
    every other profile.
  - **Deleting a profile returns its workspaces to the Default** — which may show what the deleted
    profile hid. Check the Default before you delete a profile that hides something.
  - **Figures stay.** Home's spend and request counts, a key's usage and a member's limits are not
    hidden; with conversations hidden, Home no longer lists recent sessions. The console's own
    Sessions and Audit pages are unaffected: this is about what members see in the portal.

  It takes effect at the member's next request: a page they have open gives way at its next refresh,
  and comes back the same way when you show it again. An automation key follows the workspace it is
  bound to.

The developers' CLI picks a change up on its next `ssai sync`, or on its next `ssai run` once its
copy is an hour old. A CLI that has never received the settings and cannot reach the gateway runs
with the gateway as its only destination, and cannot apply the client and sandbox requirements until
it reaches it — nor can the tool reach its model.

### 10. Hand off to end users — the **Portal**

Once a workspace has a provider and a user has a portal password (or OIDC access), point
them at the console host's root, `/` (or `/portal/login/{slug}`). There they:

- **Quickstart** — opens on **Set up via CLI** (the `ssai` commands that configure every
  installed tool at once, below); the **Web wizard** tab is the copy-paste alternative. In the
  wizard — which works in the workspace selected in the portal header and starts over when that
  changes; a configuration already on screen stays, under a notice, until they start over —
  they pick their client (Claude Code, opencode, Cursor, Cline, Claude Desktop,
  Continue, Aider, Gemini CLI, Codex, Mistral Vibe, Qwen Code, Goose, Zed, generic curl/SDK); the wizard mints a key bound to the chosen
  provider and renders a copy-paste config with the right base URL, model alias, and flags.
  A tool that can speak both the OpenAI and the Anthropic protocol (OpenCode, Crush, Continue,
  Cline, Aider) defaults to its **OpenAI-compatible** variant, which works with every model; its
  **Native Anthropic** variant is the one to pick for Claude
  models — extended thinking and prompt caching then pass through unchanged. Some tools read their key from a second file of their own — a secrets file, or an environment
  file the tool loads on start — and the wizard renders that file alongside the config, with the
  key filled in when you copy it. Claude Code's MCP servers come as commands to run once
  (`claude mcp add-json --scope user …`, in a POSIX shell — on Windows, Git Bash): Claude Code never
  reads them from its `settings.json`. With a gateway key the commands hold no key — each server reads
  it from `STREAMSCOPE_MCP_KEY`, which the settings file sets; a BYOK server's address carries its key. Where a tool takes its key only from a shell variable and no
  file can hold it, the wizard shows the key itself instead. Either way, **that page is the one
  time the key can be read**: the gateway keeps only a hash of it.
- **Home** (`/portal/home`) — where every member lands after signing in: their dashboard. Three
  buttons start the common tasks (**New key**, **Set up a tool**, **Try an MCP server**). Their
  own activity, over every workspace they use: spend and requests today (UTC) and over the last 7
  days (UTC days, today included), and a bar per day for those 7 days. Their 5 latest sessions.
  Beside them, only what applies:
  - **To do** — one line per thing waiting on them, each with the way to fix it: no key and no
    traffic yet (create one), a key that expires within 7 days or expired in the last 7 (a key
    created to live 7 days or less, such as the CLI's per-run keys, is not one), the MCP servers
    waiting for their sign-in or values, and each machine whose `ssai` CLI is older than the one
    the gateway serves — named by its host, with `ssai update` to copy. A machine is named from
    what its CLI reports on each call; one not seen in 30 days is not listed, and the line goes
    away on the machine's first call after the update.
  - **My limits** — every limit that applies to them in the workspace picked in the header, as on
    the team pages: the organisation, the workspace pool, their member limit and their keys'
    budgets, each meter turning to the warning colour at 80 % of its cap. It shows what they have
    used of their own member limit and keys; the pool's use (everyone's spend) only when the
    workspace shares usage among its members or they manage it, and the organisation's never.
    Nothing set, no panel.
  - **Your team** — for a manager of the header workspace: its members, and its spend today and
    in the current 30-day period against the workspace pool.
- **The workspace picker** in the portal header (shown to a member of several workspaces) sets
  the workspace the portal works in — keys, quickstart, the team page and, on the activity pages,
  the **Me / Team** switch, which appears where that workspace shares activity with its members.
- **API keys** (`/portal/keys`) — mint/revoke their own keys in any workspace they belong to,
  and see each live key's requests, tokens, spend and last use today, over the last 7 days or
  over the last 30 (UTC days, today included).
- **My Sessions** (`/portal/sessions`) and **My Requests** (`/portal/audit`) — the console's
  Sessions and Audit pages, with the same filters and details, over their own traffic — or, with
  **Team** on a workspace that shares, that workspace's, where a teammate filter also appears.
  The default period is the last 7 days. An administrator can hide conversations — the Sessions
  page and every request's content — or the Requests page for a team (**Portal pages** in
  [9c](#9c-portal--clients-and-destinations--governance--portal--clients--destinations)); with
  conversations hidden, Requests lists each request's model, tokens, cost and status, and a
  request does not open.
  - **Requests** lists every kind of request: model calls, MCP tool calls, agent (A2A) calls and
    web searches and fetches, each expandable to its full captured content. The MCP server,
    upstream and agent filters offer only what the member's workspaces are granted.
  - **A session** opens in the same conversation viewer as the console, with its linked parent
    and child sessions, the web calls a turn made, and the before/after view of a transformed
    message.
  - Every field the console shows is shown, the upstream server and endpoint that answered a
    model call included.
  - **Expert alerts are not shown to members**: a session's alert, its note and the experts that
    raised it stay in the console, and the portal ignores the alert filter and order. The
    cross-session issues an expert finds are console-only too, since they name other people's
    sessions.
- **Members & limits** (`/portal/team`, in the menu for managers only) — managers see the roster
  and per-member usage, provision on behalf of members, and manage member limit exceptions.
- **Sign-ins** (`/portal/mcp/connections`) — connect your **own** account to the MCP servers
  that need one. Each server shows its state — *Connected*, *Needs your values*, *Needs
  sign-in* or *Sign-in expired* — and one button for the next step (**Enter values**, **Sign
  in** or **Reconnect**); a server that needs both your values and a sign-in lists the two steps
  in order. While any of your servers waits, Home's To do card and the Quickstart page's banner
  name them with a link here, and an agent calling such a server is answered with this page's
  address. For an OAuth server (e.g. GitHub) you're sent to the provider to approve; the
  gateway then stores and auto-refreshes a token that is yours alone, so your agent acts as you
  on that upstream. For a server that asks each user for values (a personal access token, say),
  **Enter values** (or **Edit**, once entered) opens a form with just your fields, filled with the values you entered before —
  secret ones are never shown back (the form only says they are set), and values your
  administrator set are neither shown nor yours to change. Changes
  take effect within seconds. Each member connects once; the page shows what you've connected,
  the granted scopes, and lets you disconnect (which also deletes the values you entered).
- **Try a server** (`/portal/mcp/test`) — probe a virtual server before pointing an agent at it: runs
  `initialize` / `tools/list` / `resources/list` / `prompts/get` against each upstream the route fans
  out to and shows the merged catalog, using the same headers the gateway would (a server that needs
  a value your client sends is reported as needing it, since the test has no client). For an OAuth or
  per-user-values server you must have connected your account first; if your stored token has expired the test says so and points you back to reconnect —
  your real agent calls are unaffected, since the gateway refreshes the token on its own.

#### Set up tools with the `ssai` CLI

The `ssai` command-line tool automates the whole Quickstart flow — instead of copy-pasting
a snippet per tool, it writes each AI client's configuration directly. The gateway itself serves
the CLI (Linux x86_64, Windows x86_64, and macOS Apple Silicon when your gateway ships a macOS
build; the installers verify the download's checksum), and the Quickstart page's **Set up via CLI**
tab shows these commands pre-filled for your portal:

```bash
curl -fsSL https://<portal-host>/api/v1/cli/install.sh | sh   # installs to ~/.local/bin
ssai login https://<portal-host>/portal/t/<org>   # any portal URL works — opens your browser
ssai provision                                     # detects installed tools, mints one workspace key, writes configs
```

On Windows, install from PowerShell (Windows PowerShell 5.1 or PowerShell 7) instead; the rest is
the same:

```powershell
irm https://<portal-host>/api/v1/cli/install.ps1 | iex   # installs to %LOCALAPPDATA%\Programs\ssai, adds it to your PATH
```

On Windows the CLI keeps its own state in `%LOCALAPPDATA%\streamscopeai\config\` (never the
roaming profile a domain copies to its server), readable by your account
alone, and writes each tool's configuration where that tool reads it on Windows: in your profile
folder for most (`%USERPROFILE%\.claude`, `.codex`, `.gemini`, `.config\opencode`, …), and under
`%APPDATA%` for Goose, Zed, VS Code (Cline) and Claude Desktop. The sandbox described below runs on
Windows through a dedicated sandbox account, set up once by an administrator (**The Windows
sandbox**, below). (`--ca-file` there gives the client, for that run, the roots Windows trusts plus
the file's — it changes nothing in Windows' own trust.)

If your gateway uses a private or self-signed certificate, the installer detects that the
certificate isn't trusted, captures the gateway's CA, and prints its SHA-256 fingerprint before
offering to install it into the system trust store — compare that fingerprint against the value your
gateway operator published and only accept if they match (the certificate is captured over an
as-yet-untrusted connection, so this out-of-band check is what makes trusting it safe). It then
builds a **combined** trust bundle — your system's certificate authorities **plus** the gateway's —
and prints the environment variables that point the Node- and Python-based AI CLIs (which ignore the
OS trust store) at it: `NODE_EXTRA_CA_CERTS`, `SSL_CERT_FILE`, `REQUESTS_CA_BUNDLE`, and
`CURL_CA_BUNDLE`. Because the bundle is additive, your other certificate authorities keep working —
which matters behind a corporate CA that already trusts the gateway, where pointing the tools at the
gateway certificate alone would break everything else. The installer verifies a real connection
succeeds with the captured trust before reporting success. (`provision` writes those variables
automatically into the env-file clients it configures, such as Gemini CLI and Mistral Vibe.) The
`ssai` command itself trusts the captured certificate authority as well as the system ones,
so it reaches the gateway even if you declined the system install and set none of those variables.
Each private gateway you install from keeps its certificate authority in a file of its own under
`~/.config/streamscopeai/gateway-ca.d/`, beside the others', so the command keeps reaching every
gateway it is logged in to; installing from a gateway again replaces only its own file. When a gateway's certificate is not trusted, the error names that
gateway and tells you to install from it again — check the fingerprint the installer prints against
the one your operator publishes. A damaged file is warned about and left out without affecting the
others — remove it, or re-run that gateway's installer if your system does not otherwise trust its
certificate.

On Windows the gateway's certificate is Windows' to trust, as it is for `irm` itself: a gateway
with a private certificate authority needs its root in Windows' trusted roots before you install
(your IT department may already push it; otherwise import the root from
`https://<portal-host>/api/v1/cli/ca` with **certmgr.msc → Trusted Root Certification Authorities**,
after checking its fingerprint with the gateway's operator). The installer stops with that advice when
the certificate is not trusted. The `ssai` command trusts what Windows trusts. The Node-based AI CLIs
do not read the Windows store: point them at the root with `setx NODE_EXTRA_CA_CERTS <root file>`
(a sandboxed run carries it when it sets no trust of its own — with `--ca-file`, or a gateway
certificate the CLI captured, the run's own bundle is used instead — and gives the sandbox account
the file to read when it is in your profile).
The installer uses Windows' proxy settings, signing in to a proxy with your Windows account.

`login` sends you through the same sign-in the portal uses (password or SSO) plus a one-click
device approval; the CLI never sees your password. On a machine with no browser — an SSH session,
a remote box — use `ssai login --device` (the CLI also falls back to it automatically): it
shows a short `XXXX-XXXX` code and a portal link; open the link on any device, sign in, check the
code matches, and approve — the terminal completes the login by itself within a few seconds. Run
`ssai login` with no URL and it asks for one, refusing an address that names no tenant
before it goes any further (with no input to read, it stops with an error instead).

In a terminal the CLI's questions are interactive: a choice list moves with the arrow keys (`/`
filters it), a multiple choice starts with everything ticked and toggles with space (`a` toggles
all; the tools to provision need at least one), and a yes/no question offers two buttons. Enter answers; **Esc or Ctrl+C cancels the
command before it writes any tool config, mints a key, or restores a file** (while a filter is open, the first Esc only closes it). Each answered question folds into one line, so the run reads
as a transcript. Colours follow the portal's, stepping down to the basic terminal colours where
the terminal advertises no more; `NO_COLOR` turns them off. When input is piped, the terminal is
`TERM=dumb`, or `STREAMSCOPE_PLAIN=1` is set, the same questions are asked as numbered lines
instead (answer a multiple choice with `1,3,5`, `all`, or `none`), which also suits a script
feeding answers on standard input. A script that runs out of answers gets each question's default
— the capitalised answer of a `[Y/n]` / `[y/N]` question, `all` for a multiple choice — except a single choice, which has
none and stops the command with an error.

`provision` first asks which workspace to bill to, then offers only **that workspace's** providers,
shows the detected tools and asks which to provision in a single multiple choice, and prints a
short per-tool summary — for each tool, the file it wrote and the command to
start it (e.g. `Run: claude`); pass `--verbose` for the full per-tool setup notes. A tool counts
as installed when its program is on your `PATH`, its editor extension is installed (Continue in VS
Code or any of its forks, Cline in VS Code), or its desktop app is (Cursor, Zed, Claude Desktop); a config
folder left behind by a tool you uninstalled is listed as
such and skipped unless you name the tool with `--client`. Each tool gets **its own** gateway key,
named after the tool (`opencode`, `claude-code`, … — `-byok` appended for a BYOK provider), so usage
and audit show which tool made each request; the same tool reuses that key in every project you
provision on this machine while it stays valid (the CLI keeps it, readable only by you, in its own
state folder), and a revoked one is replaced by the next `provision` or `sync`. The CLI
merges each tool's settings **into its existing config file** — your themes, custom options, and
other providers are preserved, and re-running updates only the entries the gateway manages (your
manual edits to them are kept, with a note). That holds inside lists too: providers and models you
added yourself to Mistral Vibe's `[[providers]]` / `[[models]]` or Continue's `models` /
`mcpServers` stay where they are, beside the gateway's. A tool that's configured through its own UI (Cursor)
prints setup instructions instead of writing a file, and a tool that can only be set up with an MCP
server is skipped with a notice rather than failing the run. Supported in this release: Claude Code, Codex, Gemini CLI, OpenCode 2,
Mistral Vibe, Qwen Code, Goose, Zed, Cursor, Cline, Continue, Aider, Crush, Claude Desktop, and the curl/SDK
snippets (printed to the terminal). Your own entries in Aider's `set-env` list and Continue's `models` and `mcpServers` lists are kept beside the gateway's.
One caveat: Aider's, Continue's, and Goose's YAML config files keep all your settings but not
your comments — the other formats preserve comments too, including a JSON config with comments or
trailing commas (VS Code's `settings.json` for Cline, Gemini CLI's and Qwen Code's), which is edited in
place around your text. Zed reads the API key from a `STREAMSCOPE_API_KEY`
environment variable (or the Agent Panel) rather than its `settings.json`, so export the minted key in your shell. Qwen Code
gets the gateway in `~/.qwen/.env` with an output cap (the model alias's, else the model's, else 8 192 or its window if smaller), plus two keys merged into
`~/.qwen/settings.json`: the OpenAI sign-in type (so a Qwen account you signed in with earlier does not
take over) and, when the gateway knows the model, its context window. Aider gets
`~/.aider.model.metadata.json` beside `~/.aider.conf.yml`: its model with the output cap and, when the
gateway knows it, the context window, and its weak model by name, so Aider neither warns of an unknown
window nor downloads a public model list each time it starts. A BYOK provider gets none, since the gateway
does not know the model you name. A config file that is not valid
JSON even allowing comments and trailing commas, or one with comments that repeats a key, is not
rewritten — `provision` stops before writing anything for that tool and names the file.

**Picking a variant.** A tool that can speak both the OpenAI and the Anthropic protocol (OpenCode,
Crush, Continue, Cline, Aider) is provisioned with its OpenAI-compatible variant, which works with
every model. On a BYOK provider it gets the variant speaking that provider's own protocol instead,
when it has one: your credential is forwarded as-is, and one a vendor issues for its own protocol (a
subscription sign-in) works on nothing else. The Quickstart page picks the same, until you choose a
variant yourself. Choose `anthropic` for Claude models on a gateway provider (extended thinking and
prompt caching then pass through unchanged). When the CLI can write another variant, `provision` names the one it picked
with the flag that switches it. An installation keeps the config variant it was provisioned with —
through `sync`, and when you run `provision` for it again in the same mode (on a BYOK provider, the same
provider) — until you pass
`--template`; an MCP-only installation provisioned again without `--template` gets the full
config.

Pick a variant with `--template <tool>=<variant>` — `chat`, `responses`, `anthropic` or `gemini`
for the protocol, `mcp` for an MCP-only config, `instructions` for UI-setup notes, and an `-oauth`
suffix for the variant whose MCP servers sign in by OAuth (e.g. `--template opencode=anthropic`,
`--template claude-code=anthropic-oauth`). A name the tool doesn't ship is refused with the list of
the ones it does. `--template` picks the config a tool writes; the copy-paste snippets that go with
some of them (shell exports, SDK environment variables) are on the portal Quickstart page; no built-in config
`--template` writes depends on one of them.

**MCP servers.** When a tool you're provisioning can use MCP (every one listed above except Aider,
Zed and the curl/SDK snippets), `provision` proposes the MCP virtual servers your workspace can reach and lets you pick
which to wire in — exactly the choice the Quickstart page's MCP step offers, kept in sync with it.
Pick from the list interactively, or select them non-interactively with `--mcp <slug>` (repeatable),
`--all-mcp` (wire every reachable server), or `--no-mcp` (skip the proposal). With `--yes` (or in CI)
and none of those flags, no MCP servers are wired. A server that uses **per-user OAuth** is tagged
*connect first*: the CLI still writes it into your config, but prints a note reminding you to link
your own account under **Portal → Sign-ins** — requests through that server start working the
moment you connect (nothing to re-run). This mirrors the portal: the config can be written before you
connect; connecting makes it live. A server the tool's setup cannot reach is left out of its config,
and `provision` prints a warning naming the tool and the server: a sign-in (OAuth) setup cannot
reach a server that takes your client's own `Authorization` header, and a pass-through key reaches
only a server that carries nothing but what your client sends. The portal Quickstart shows the same
warnings for the same choice.

**Local MCP servers.** When your workspace is handed local MCP servers — servers your own machine
starts — and a tool you're provisioning can be given one, `provision` proposes them too, each with the
command line it runs. Select them non-interactively with `--local-mcp <slug>` (repeatable). A tool
you provision again keeps the MCP servers it already has — gateway servers and local servers
alike — unless you say otherwise: with no MCP flag they stay (each prompt opens with them ticked),
`--mcp` / `--all-mcp` replace the gateway servers and `--local-mcp` the local ones, `--no-local-mcp`
takes the local ones out and keeps the gateway servers, and `--no-mcp` selects none of either kind.
It also stays on the setup it has unless `--template` names another. A tool provisioned for the
first time with `--yes` and no MCP flag gets none. Before it writes
anything, `provision` prints each selected server's whole command line (your administrator's
environment values included), the environment variables you must fill in yourself (the written
config holds a `<paste-your-…-here>` placeholder for each; a later run keeps what you pasted), and
what applies to that kind of command: that its runner must be installed, what a sandboxed run
changes, and on Windows that a client may need the runner wrapped (`cmd /c npx …`). `sync` re-applies
the same selection: it prints a server's command line when your administrator changed it — the
command, an argument or an environment value — and removes, saying so, a server the workspace is no
longer offered (turned off, revoked or deleted), keeping the rest of the configuration. Nothing
else in the file is touched — the tool's provider, key, model and gateway servers stay — and the
tool stays managed. A tool set up for MCP servers only that is left with none is simply left alone:
`provision` and `sync` say there is no MCP server selected for it and nothing to write, and that is
not an error. Removing a
server — at a sync, or because you deselected it — takes its whole entry out of the file, the values
you pasted into it included; an entry your file already had under that name before the server was
added is not removed: only what was written into it and you did not change goes, and the rest is
named. A tool that
cannot be given a local server is provisioned without it and a warning names it; Claude Code is
given one only in a project (`--local` / `--dir`).

By default `provision` writes each tool's **global** configuration in your home directory. To set a
tool up for **one project** instead, run `ssai provision --local` from inside the project (or
`--dir <path>`): it writes the tool's project-local config there — for example `./.claude/settings.json`
(with your MCP servers in `./.mcp.json`, enabled by name so Claude Code loads them without asking once
you trust the folder; a home-directory run instead prints the `claude mcp add-json` command for each
server, since Claude Code keeps its own state in the one file it reads them from there — run them once,
and again when your servers change; `forget` and `restore` leave a server you added this way, which
`claude mcp remove --scope user <name>` removes), `./.gemini/settings.json`, or `./.opencode/opencode.json` — and tracks what it wrote in a
`./.streamscopeai/` folder inside the project. A project provisioning writes **only** project files: a
tool that has only a global configuration (Codex, Continue, Crush, Goose, Qwen Code, Mistral Vibe —
Continue's editor extension and CLI, for one, both read a single file in your home directory) is
skipped with the command that provisions it globally (`ssai provision --global --client …`),
unless you name it with `--client`, or tick it in the prompt and confirm writing it to your home
directory. (When neither `--local` nor `--dir` is given, `provision` offers
the global-vs-project choice only if at least one selected tool supports a project-local config.) Use
`ssai provision --global` to force the home-directory config even when you're inside a
project that has a `./.streamscopeai/` folder (which otherwise auto-selects the project).

**OpenCode and your home-directory config.** OpenCode reads your home-directory config
(`~/.config/opencode/opencode.json`) as well as the project's, and two of its settings outrank a
project's: a provider rule (`experimental.policies`, or an older `enabled_providers` list) that
leaves the gateway's provider out, and a model pinned to an agent (`agents.build.model`, …). Every
OpenCode config the CLI writes, project or home directory, therefore pins every built-in OpenCode
agent (`build`, `plan`, `general`, `explore`, `compaction`, `title`, `summary`) to one of the
gateway's models (the table under *Set up tools with the `ssai` CLI*), so a pin in your home config can't take OpenCode elsewhere. A
home-directory provisioning replaces a model you had pinned to one of those agents, and every later
`provision` or `sync` does the same to a model you pin there again — to run an agent on another
gateway model for yourself, pin it in a project config. Agents of your own, and providers and policy
entries you define yourself in that file, are kept, except a rule of your own for `opencode` (below). A home-directory provider rule still wins over any project, so
`provision` and `status` name the file and the exact line that would allow the gateway's
provider when yours leaves it out (then restart OpenCode's background service with `opencode service
restart`), and list every agent your home config, or another OpenCode config it loads, still pins to another provider it can use (one of your own, or a pin under
the older `agent` key). An agent pinned to a provider your rules deny runs on the default model, so it is not listed. A **global** OpenCode
provisioning adds that allow line itself: at the end of the file's provider rules, where OpenCode
reads it last, or — when the file already has a rule for the gateway's provider — in that rule's
place, which it then manages. Your other rules are kept, and a deny you add after it still wins. A project
provisioning never writes your home-directory config.

Every OpenCode config for the gateway's models, from the CLI or Web Quickstart, project or home
directory, also adds a provider rule denying `opencode`, OpenCode's own hosted provider. OpenCode otherwise offers that provider's free models in
its model list even without an account, and a request to one goes to OpenCode's service, so the
gateway never audits it or applies policy to it. A rule of yours for `opencode` in that same file is
replaced, and a user with their own OpenCode account loses that provider too. An MCP-only OpenCode config leaves
your providers alone and adds no such rule. A rule that allows it, `*` included, can still win: plain
`opencode` reads your home-directory config first, then a repository's own `opencode.json`, then
`.opencode/opencode.json`, and the first of those with a rule for the provider decides. Under `ssai run`
in a project, `.opencode/opencode.json` comes first. `provision` and `status` name the file that
brings the provider back, and say which launch it reaches. Edit the OpenCode client profile to allow
the provider again. A tenant whose profile was edited before this rule existed keeps its version, so
add the rule to it by hand. `ssai forget` removes the rule, so it does not bring back one of your own
that it replaced: restore that from the backup `provision` took. A provider OpenCode finds through its own API key in your environment is not
covered by this rule.

Every OpenCode config the gateway writes also
turns off OpenCode's session sharing and its own web search, so the agent searches through the
gateway's MCP web tools when the workspace has access to them (without them OpenCode has no web
search); edit the OpenCode client profile to change that default.

The configs for the other tools likewise turn off what each tool sends its own vendor besides
your requests, wherever its config file has a switch for it: usage statistics, telemetry and crash
reports, and update checks, for Claude Code, Codex, Gemini CLI, Qwen Code, Crush, Goose, Mistral
Vibe, Aider and Zed. Continue's command-line client sends no usage data of its own (its metrics go
only to a collector you configure yourself), and Cline and Cursor have no such
switch in the files the gateway writes. To turn one of these back on, edit that tool's client
profile.

Because a provisioned config can hold your gateway key, both the
`./.streamscopeai/` folder and each written tool config are added to the project's `.gitignore`
automatically, so a `git add .` never commits a credential. A file git already tracks (a team's
committed `.claude/settings.json`, or a home directory that is itself a git repository) cannot be ignored
that way, so when git reports the file tracked the CLI refuses to write your key into it and names
the file. Keep that file out of git, or provision the tool in the other scope. When you run
`sync`, `status`, `forget`, or `restore` from inside a provisioned project they act on **that
project**; run from anywhere else they act on your global setup.

`ssai status` lists every gateway you're logged in to or have provisioned tools from (one
you're no longer logged in to is marked so, with its files), and whether any managed file was edited
since provisioning; for OpenCode it also reports the settings described above, in your home-directory config
or in another OpenCode config it loads, instead of `ok`. `ssai sync` re-converges every provisioned config in one go: it does nothing
when the gateway-side setup hasn't changed, rewrites the managed entries when it has (templates,
models, MCP servers), and — for each tool whose gateway key was revoked — mints that tool a
replacement and rewrites its config; `sync --watch` keeps doing that on an interval (default 5 minutes), and a cron or
systemd timer running plain `ssai sync --yes` works just as well. To converge only some of
the managed tools in a run — for instance when you maintain Claude Code by hand but want the rest
kept in sync — use `sync --client opencode` (repeatable) or `sync --skip claude-code`; the filter
applies to that run only and doesn't change what's managed. (Each tool replaces its own revoked key,
so a tool a filtered run leaves out gets its replacement on its own next sync.) To
stop managing a tool entirely, `ssai forget <tool>` drops it from the managed set — `sync`
no longer touches it and its config file is left exactly as it is for you to take over. Nothing
changes on the gateway either: `forget` names the key the tool's config still holds, which stays
valid — other projects may use it — until you revoke it on the **Keys** page. `ssai update` self-updates the CLI from the gateway
(checksum-verified; on Windows the running `ssai.exe` is set aside as `ssai.old.exe` and removed the
next time `ssai` starts), and `sync` mentions when a newer version is available. Every call `ssai`
makes to the gateway names its version, its operating system and the machine's host name (its first
label), which the portal's Home uses to say which of your machines run an older `ssai`. `ssai logout`
revokes the device's access immediately — the keys already written into your tools keep working
(revoke those on the **Keys** page if needed). When `ssai` cannot read its record of what it wrote
— one an earlier version of `ssai` kept — every command stops and leaves the record as it is, except
`provision`: run `ssai provision` again for your tools (not a `--dry-run` or `--print` run) and, once
it saves, it moves the old record aside (the warning names where) and starts a fresh one recording
what this run writes. Entries the old record owned that this run does not write again stay in the
tools' files, unmanaged — remove them by hand — as does every file of a tool you do not provision
again, and the keys the old record held keep working until you revoke them on the **Keys** page.
`ssai licenses` prints the CLI's licence and the
licences of the third-party software it bundles.

Every provision and sync snapshots each file before it changes it, and notes each file it creates
(the five most recent runs are kept). `ssai restore` puts those back: `restore --list` shows the available runs, `restore`
rolls the latest one back into place (removing the files that run created), and
`restore --run <timestamp>` picks a specific one — the
current state is snapshotted first so a restore can itself be undone. Each tool whose file a restore
puts back is managed as it was when that run started — with the key it had then — and a tool that
run first provisioned is no longer managed, so `status` and `sync` see the restored state; tools
whose files the restore does not touch stay as they are. Inside a project, `restore` works on the project's runs and says when
home-directory runs exist too; `restore --global` reaches those. The
CLI's own session is narrowly scoped: it can read the setup catalog and mint keys in your
workspaces, and nothing else — it can never manage your team or reach the admin console. If a
device is lost, an admin can revoke that one device from **Clients → CLI Sessions** and every other
machine the user signed in on keeps working; disabling the user's account remains the blunt lever
that cuts all of them at once. Either takes effect on the device's next request. CLI sessions
otherwise expire on their own after 30 days of disuse.

`ssai run <tool>` launches a provisioned tool inside a **sandbox** so the agent can only
reach the gateway and only touch the project it's working in. Run it from a provisioned project —
for example `ssai run claude`, with any arguments for the tool placed after `--` (e.g.
`ssai run claude -- -p "summarise this repo"`); the tool starts exactly as it would
normally, in the current directory. In a project provisioned from more than one gateway, `run`
uses the one that provisioned the tool, and asks you to pick with `--host` when several did. While it runs, two things are enforced for you: **network
egress is restricted to the gateway and the destinations your administrator allows** for the
workspace (§ 9c — every other destination, a vendor API, a paste site, an arbitrary host, is
blocked; with nothing allowed, all the agent's traffic stays on the gateway and auditable), and **filesystem access
is confined to the project** while your credentials (SSH keys, cloud tokens, GnuPG, npm, Yarn and
pnpm registry tokens, the GitHub CLI's login) are kept out of reach. The tools you installed in your home directory stay usable from inside it — anything in
`~/.local/bin` or `~/bin`, Rust (`~/.cargo/bin`, `~/.rustup`), Go (`~/go/bin`), Bun and Deno, and the
common version managers (nvm, fnm and n — each installed Node version's programs and libraries —
pyenv, pipx, rbenv, RVM), plus `/nix` and `/snap` — so an agent can run `uv`, `cargo` or `npm` as
it would unconfined. This grant is read-and-run only, for every tool. A Node-based tool (OpenCode,
Claude Code, Gemini CLI, Qwen Code, Continue, Vibe) may also write where a global `npm install`
does — each installed nvm or fnm version's programs, libraries and manual pages — and to the package managers'
caches, but never to npm's configuration files (`~/.npmrc`, or the global one each Node version
keeps beside its programs), where a registry token is stored. Volta is the exception: a Node-based
tool can write its whole directory, because Volta's own launchers run from all of it. On macOS the
npm configuration inside Volta is still out of reach; on Linux it is not, so use nvm or fnm there if
a registry token is kept in it. Gemini CLI reads a project's `.gemini/.env` only in a folder you have trusted, so trust the project
folder in Gemini (or pass it `--skip-trust`). The shared skills folder `~/.agents/skills` is readable
inside the sandbox, and a tool's own state folders are created on its first run there. Each run
gets its own private temporary folder under your cache folder (`~/.cache/streamscopeai/tmp`, or
`$XDG_CACHE_HOME/streamscopeai/tmp` when you set it — or, when you set `STREAMSCOPE_TMPDIR`, a
folder of your own inside that directory), which every temporary-folder setting the tool
reads points at — your own `TMPDIR` is not used inside the sandbox — and which is deleted when the
run ends (a run that was killed leaves it to the next run to clean up); `/tmp` stays writable.
Tools load native libraries they unpack there, so that folder must be on a disk that allows
running programs: if it is mounted `noexec`, `run` stops and names the mount — set
`STREAMSCOPE_TMPDIR` to a directory of your own on a disk that allows it (not under `/tmp`, which
every sandboxed run can write). The gateway's trusted certificate is made available inside the sandbox automatically; add
more with `--ca-file <path>` or pass extra environment with `-e KEY=VALUE`. When it starts, `run`
prints a one-line summary naming the active sandbox and what it confines, including how many
destinations are allowed and blocked; blocked-egress details are kept silent while the tool runs so
they don't disturb its display — pass `--verbose` to see every decision — and once the tool exits,
`run` names the destinations it refused. Tools that speak plain HTTP through a proxy (apt) and
Java tools (through their proxy settings, added to your own `JAVA_TOOL_OPTIONS`) go through the same
rules; `git` over SSH does too: `ssh` takes its connection from `ssai` — unless you have an ssh
command of your own (`GIT_SSH_COMMAND`, `GIT_SSH` or git's `core.sshCommand` as the project sees it),
which is left as it is: route it yourself by adding `-o ProxyCommand="ssai __connect %h %p"` to it.
Inside the run, `ssai`'s command applies to every repository, a submodule's own `core.sshCommand`
included. An allowed name that resolves to this machine's own addresses
(loopback) is not reached through it: only an entry naming the address is. A
destination whose name does not resolve fails as unreachable, not as refused. A raw database
connection (`psql`, `redis-cli`) is not carried. A client your administrator has disabled is
refused, and so are `--sandbox off` and `--sandbox learn` when the administrator requires the
sandbox. The sandbox is **fail-closed**: if the machine can't enforce it, `run` refuses rather than
launch the tool unconfined — use `--sandbox off` to opt out deliberately. This works on Linux and
WSL2 (the network confinement needs a Linux kernel 6.7 or newer), on macOS (Apple Silicon, via
the system's built-in Seatbelt) and on Windows (a dedicated sandbox account, below). A tool that
runs on Node.js (the Continue CLI, Gemini CLI, Qwen Code) needs Node.js
22.21 or newer inside the sandbox: an older Node.js does not send all of its connections through the
sandbox's gateway route, and the sandbox refuses them (the Continue CLI then stops with "MCP
server(s) failed to load"). (`run` only launches already-provisioned tools; provision the project
first.)

The project's git hooks and configuration (`.git/hooks`, `.git/config`, a worktree's or a
submodule's links and configuration, a hooks folder `core.hooksPath` names) and its
`.streamscopeai/` folder are read-only to the agent, and `.git` (with its worktrees' and submodules'
git folders) cannot be renamed — so an agent cannot change the hooks and settings that will run
later, outside the sandbox, when you use git there. A
linked worktree's own git folder, which lives in its main repository outside the project, is
granted, so the agent can commit from the worktree. Git commands that write the repository's
configuration then fail inside the sandbox — `git push -u` (after the push itself succeeds), a new
branch that tracks a remote, `git remote add`, `git submodule add`, `git config`: run those yourself.
This holds on macOS, on Windows and in the
container sandbox. **On Linux the native sandbox cannot hold them** (it grants a folder whole), and
`run` says so when it starts: look at them before you run git or `ssai` there outside the sandbox,
or use `--sandbox docker`. What is held is what exists when the run starts and what git reads
there. Not held: git files the agent creates where there were none (a repository in a project that
had none; a link file git follows, except on macOS, which holds those too), a hooks folder that is a
link or is reached through one, a hooks folder only your
global git configuration names, a file the project's git configuration includes from the work tree,
and the tools' own settings that can run commands (a project's `.claude/settings.json` hooks, for
one). The sandbox guards against an agent's mistakes and the instructions injected into it, not
against an agent built to get out.

OpenCode 2 runs the agent's tools in a separate background server. Under `ssai run`,
each run gets its own private OpenCode server inside the same sandbox, used only by that run and
stopped when it ends — an OpenCode server you already run on your machine is never used, so the
agent's tools can never escape the confinement through it. In a project whose OpenCode config is at
`.opencode/opencode.json`, `run` also hands OpenCode that config **in place of** your home-directory
one, so a provider rule or agent pin there cannot send a run elsewhere — and, for the same reason,
nothing else in your home-directory OpenCode config applies under `run` there either: its agents,
plugins and commands, and its `permissions` rules (a deny you set on a shell command, say). Put a
rule you want under `run` in the project's `.opencode/opencode.json`. `~/.opencode` and a repository's own
`opencode.json` apply under `run` too (`~/.opencode` for a project under your home directory): that project file
decides a provider rule ahead of them, and a model they pin on an agent replaces the one it pins, which `provision`
and `status` report. A config in a subdirectory applies only when you start OpenCode there, and they do not read it, nor a default
model set in one of those other files, nor an agent defined in a Markdown file. Outside such a project (a global provisioning), OpenCode reads your
home-directory config as usual, and `provision` and `status` report a rule there that would keep it
off the gateway. When a run fails, `run` keeps the private
server's log and names it. The OpenCode TUI, `opencode run` and its
session commands work this way; OpenCode's built-in terminal panes are not available under the
sandbox. `run` needs OpenCode 2 or later (it says so and stops if it finds an older one).

On Linux, anything the agent leaves running in the background — a server it started from a shell
command, for instance — is stopped when the tool exits (not with `--sandbox off`). To stop a run
from a script or another terminal, send `ssai run` SIGTERM: it passes the signal on to the
tool and cleans up after it. Ctrl-C at the terminal reaches the tool directly, as without
`ssai run`.

**The Windows sandbox.** On Windows the agent runs as a dedicated local account of yours,
`ssai-sbx-<six hex digits>`: a standard user (never an administrator), hidden from the sign-in
screen, which owns nothing of yours and so reads nothing in your profile but what a run grants it
(below), and whose every
connection except to this computer is blocked by a Windows Firewall rule — the run's guard, on this
computer, lets it reach only the gateway and the destinations your administrator allows, and serves
only programs running as the sandbox account. Set it up
once with `ssai sandbox setup`, which asks for administrator rights (one UAC prompt; a standard
user enters an administrator's credentials). `ssai sandbox setup --check` checks the account, its
firewall rule and that the firewall is on for every network profile, and changes nothing; running
`ssai sandbox setup` again repairs what is missing or changed;
`ssai run --sandbox native` refuses to start while any of it is missing or changed, and names the
command. The account's password is generated by setup and kept for your account with Windows data
protection, which needs a sign-in with your password: from an SSH session signed in with a key,
`run` cannot read it and says so — sign in at the desktop, over Remote Desktop, or over SSH with
your password. `ssai sandbox uninstall` removes the account, its profile and its firewall rule,
after taking back every grant.

The first run in a project grants the sandbox account that folder (read, write, run, delete —
never its access settings), the tool's configuration folder among your folders
(`%USERPROFILE%\.claude` for Claude Code, `.codex` for Codex, `.gemini` for Gemini CLI,
`%APPDATA%\Block\goose` for Goose; or the one you name with `--env CLAUDE_CONFIG_DIR=…`,
`CODEX_HOME=…`, `GEMINI_CLI_HOME=…` — the folder holding `.gemini` — or `GOOSE_PATH_ROOT=…`; the
agent reads and writes all of that folder, the tool's own sign-ins and history in it included —
Claude Code keeps its user-scope settings there too, so an MCP server added with
`claude mcp add --scope user` outside the sandbox is not seen in it), read-and-run on the folders of `ssai` and of the tool, and read on the gateway's
certificate files — each of those inside your profile (elsewhere every account may read them
already) — and read, never write, on each file `provision` wrote for the tool (its configuration,
which holds its gateway key and is otherwise readable by you alone), inside your profile or the
project, and read on a file an `--env` value names — and keeps the git and `.streamscopeai\` holds described above. Git, which refuses a
repository another account owns, trusts the project for the run without a change to your git
configuration; Claude Code starts past its first-run screen. The grants stay between runs (granting a large project again each time would cost seconds), so
while one project runs, the sandbox account can also write every project it was granted before:
`ssai sandbox revoke [<folder>]` takes one project's back, and
`--all` every one (revoking a project that holds another granted project inside it takes that
folder's entries back too; the inner project's next run grants them again). A folder in the project
with an access list of its own (one that inherits nothing) is named on the first run: the sandbox
cannot write there. `run` refuses a drive's root,
your profile folder and any folder above it, and a project outside your profile: a folder made
directly on a drive inherits a setting that lets every account on the computer write it, the
sandbox's included, whatever it is granted — move the project into your profile, or pass
`--allow-outside-profile` to run there anyway (it warns on every run; there, the agent can also
change who may open the files it creates, and giving them back to you may need an administrator). Files the agent creates in the
project are given back to you when a run ends with no other run of yours still going (otherwise
by the next one that does), so you remain their owner. The tool runs with the
account's own profile and temporary folder: its history and caches stay there, apart from yours,
except for the configuration folder above. Codex's own sandbox is turned off inside it (it cannot
run under another account; the sandbox account confines Codex instead). Every process of the run
ends with it, and whatever the agent scheduled to run later as the account, or left running outside
the run, is removed when the run ends and before the next one starts — while you have another
sandboxed run open, this waits until the last one ends, so one run never stops another. The
Windows sandbox runs the command-line agents — Claude Code, Codex, Gemini CLI, OpenCode and Goose,
with their terminal interfaces — not OpenCode's desktop app.

What it does not hold, as on the other systems: name lookups (DNS) still resolve, a channel an
agent could use to leak data in small amounts; the agent can write where every account on the
computer may (`C:\Users\Public`, `C:\ProgramData`, `C:\Windows\Temp`, a new folder at a drive's root);
a connection to one of this computer's own network addresses counts as local and is not blocked; a
window the agent opens shares your desktop (its keyboard, clipboard and screen); Windows Credential
Manager is per account, so a tool that keeps its login there does not find it (a provisioned tool
uses the gateway key in its configuration, which the sandbox account may read but not change); and `--sandbox learn` is not available. Windows checks
whether a server's certificate was revoked, and tools using Windows' own TLS (git, `curl.exe`,
.NET) fail when that check cannot reach its servers: if your administrator allows an internal HTTPS
host (a git server, a registry), the destination list must also allow the hosts its certificate
authority publishes revocation lists on.

**The container sandbox (Linux).** `ssai run --sandbox docker <tool>` runs the agent in a container
built from your project's own image instead of on your machine — for a project whose toolchain lives in
an image, or one that needs a Docker engine of its own. Step by step:

1. **Your administrator allows it.** **Allow the container sandbox** is on by default (**Governance →
   Portal & clients**, the **Sandbox** section of the profile your workspace is on — see [9c](#9c-portal--clients-and-destinations--governance--portal--clients--destinations)). The agent reaches only the gateway and the destination lists attached there,
   so a project whose agent installs packages or pulls images needs those registries allowed (**Use the
   developer defaults** covers the public ones).
2. **Set up rootless Podman, once per machine.** You need Podman 4.4 or newer, run as your own user
   (never as root), with a subordinate id range for your user and cgroup v2 with the `memory` and
   `pids` controllers delegated to it (`cpu` too, for a `cpus` limit). On Ubuntu or Debian:

   ```sh
   sudo apt install podman
   # a subordinate id range, if `grep $USER /etc/subuid /etc/subgid` shows none: pick one that no
   # other line of /etc/subuid or /etc/subgid overlaps (200000-265535 here)
   sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 $USER
   podman system migrate
   # delegate the cgroup controllers to your user's session
   sudo mkdir -p /etc/systemd/system/user@.service.d
   printf '[Service]\nDelegate=cpu cpuset io memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/delegate.conf
   sudo systemctl daemon-reload   # then log out and in again
   ```

   `run` checks each of these before it starts, and names the fix for anything still missing.
   `"docker": true` (step 3) also needs `/dev/fuse` (the `fuse` kernel module).
3. **Name the project's image.** In the project, create `.streamscopeai/sandbox.json`. It holds named
   sandboxes under `sandboxes`; `run` starts the one named `default`, which names either a registry image
   or the project's dev container:

   ```json
   {"sandboxes": {"default": {"image": "mcr.microsoft.com/devcontainers/javascript-node:22"}}}
   ```

   ```json
   {"sandboxes": {"default": {"devcontainer": ".devcontainer/devcontainer.json", "docker": true, "memory": "6g"}}}
   ```

   A file naming another sandbox, naming one twice, or whose keys are not under `sandboxes` is refused.

   `run` installs Claude Code, Codex, Gemini CLI, Qwen Code, OpenCode, Continue and Crush into the
   image through its `npm`, so the image needs Node.js; Goose, Aider and Vibe must already be in it.
   `"docker": true` gives the agent a Docker engine of its own. Every key is in the table below.
4. **Provision the tool in the project** as for any other run: `ssai provision`.
5. **Run it:** `ssai run --sandbox docker claude` (or `codex`, `opencode`, …). The first run pulls or
   builds the image, adds the tool to it and then starts the agent; later runs start at once. `run`
   prints the image, where the project sits in the container, and the gateway the agent reaches.
6. **Keep it current.** `ssai sandbox prepare <tool>` rebuilds (or pulls again) the image — one named
   `localhost/…`, built on this machine, is used as it is — and installs the tool's latest release — the way the tool is updated in the container (an update the tool makes of itself there does
   not replace that install). `run` stops and asks you to run it when `sandbox.json` names another
   image, when the image's recipe changed (its Dockerfile or the `devcontainer.json` keys it is built from), and when `"docker": true`
   was turned on. `ssai sandbox prune` removes every image and
   volume the container sandbox made.

If a run says it refused a destination, ask your administrator to add it to an allowed list (step 1).

The keys of a sandbox in `.streamscopeai/sandbox.json` (`{"sandboxes": {"default": {…}}}`):

| Key | Meaning |
|---|---|
| `image` | an image reference from a registry, e.g. `"mcr.microsoft.com/devcontainers/base:ubuntu-24.04"` (a local archive or folder — `oci-archive:`, `dir:` — is refused). A dev container image's own metadata applies: its user, its variables, and its features' lifecycle commands (below) |
| `devcontainer` | instead of `image`: the path of a `devcontainer.json` inside the project (its `image`, or `build` with `dockerfile`, `context`, `target` and `args`; its `remoteUser` or `containerUser`; its `workspaceFolder`. `${localWorkspaceFolder}` and `${localWorkspaceFolderBasename}` are expanded in `workspaceFolder`, the users and `build.args`, and `${containerWorkspaceFolder}` in the last two; `${localEnv:…}` is refused, since it would carry your environment into the build) |
| `docker` | `true` starts a Docker engine inside the container, its image cache kept between runs (needs `/dev/fuse`) |
| `memory`, `cpus`, `pids` | the container's limits, e.g. `"6g"`, `3`; `pids` defaults to 16384, at least 64 |

A `devcontainer.json` that sets `runArgs`, `mounts`, `workspaceMount`, `privileged`, `capAdd`,
`securityOpt`, `dockerComposeFile`, `build.options` or the legacy `dockerFile`/`context` is refused, since each would widen what the
container or its build reaches — and so is a `build` whose Dockerfile or context leads outside the
project, through a symlink included;
`initializeCommand` (it would run on your machine), `forwardPorts` and `appPort` are not applied, and
`run` names each one it finds.

The lifecycle commands run inside the sandbox, as the agent's user, in the project folder, one after
another and each to its end (named commands too, in the order of their names, which a dev container tool would run side by side; and
`waitFor` is not read), before the tool starts — a command that keeps running, such as a development
server, is started in the background (`npm run dev > dev.log 2>&1 &`):
`onCreateCommand`, `updateContentCommand` and `postCreateCommand` on the tool's first run in the project,
and again when one of them, their variables, the user they run as, the project's folder in the container or
the image changes; `postStartCommand` and `postAttachCommand` on every
run. The commands of the features the image was built with (read from its dev container metadata) run
first; the commands of the `devcontainer.json` an image was built from do not — for an image built from
this project's, they are the project's own, which run once from the project (for another image, `run`
names those it leaves out). An entry of the metadata
the sandbox cannot read is skipped, and `run` names it. While one run's create commands run, another run
on the project waits for them (Ctrl-C stops it; on a filesystem that cannot lock, such as some network
mounts, they run unlocked, and `run` says so). A command that fails stops the run,
naming it, before the tool starts; when it was a create command, they all run again next time. They reach the network
only as the tool does, through the sandbox's allowed destinations, so an `npm install` needs its registry
allowed. What a create command writes outside the project and the agent's home is lost when the run
ends: the container is new on every run. It runs once per tool, since each tool has its own home.
`containerEnv` and `remoteEnv` apply to the commands and the tool, `${containerEnv:NAME}` reading the
container's own value (the image's, or `containerEnv`'s; a `PATH` that does not name it replaces the
image's, the folder the sandbox installs the tool in kept first; a `null` value leaves the image's own); the sandbox's own variables (its
proxy, the tool's gateway settings, `HOME`) win over the project's. `${localEnv:…}` is refused there too. One that uses
`features` is built with the Dev Container CLI (`npm install -g @devcontainers/cli`), and may not set
`initializeCommand` (that CLI could run it on your machine), nor `${env:…}` (that CLI would read it from
your environment, even the shell's `${env:-x}`), nor name a local feature folder (only a
published feature is taken). A `workspaceFolder` on a system path of the container (`/etc`, `/run`,
`/usr` and the like) or over the agent's home is refused, and so is a workspace, or an agent home, at or
around `/opt/ssai-agent`, where the sandbox installs the tool. On the first run,
`run` adds the tool to the image (Claude Code, Codex, Gemini CLI, Qwen Code, OpenCode, Continue and
Crush, at their latest release, through the image's `npm` — an image without Node.js is refused
naming that); Goose, Aider and Vibe must already be in the image. Only a project's first image is built (or pulled) by
`run` on its own. After that, when the image reference changed to one not on this machine yet, or
the image needs building again (its Dockerfile changed, or the `build` of its `devcontainer.json` —
any of the file when it uses `features`, which writes its lifecycle commands into the image — or the image was
removed), `run` stops and asks you to read what it would build — the agent can edit all of it, and
a pull or a build reaches the network before the sandbox does. A change to other files of the build
context is not noticed: the image already built keeps being used until you rebuild it; `ssai
sandbox prepare <tool>` then rebuilds both — also to pick up the tool's latest release — and `ssai sandbox
prune` removes every image and volume the container sandbox made (a project built from a
Dockerfile then asks for `ssai sandbox prepare` once, as for a changed recipe). Turning
`"docker": true` on in a project that ran without it also asks for `ssai sandbox prepare` first: an
engine runs privileged, and the agent can edit `sandbox.json`.

Inside, the agent runs as the image's user, as Dev Containers pick it: a `remoteUser` (the
`devcontainer.json`'s, else the one a Dev Container image names in its metadata), else a
`containerUser` (the same order), else the image's `USER` (root when it sets none) — which
is you on the host: what it writes in the project is yours. It sees the project at its `workspaceFolder` (or, without one, at the same path as on your machine), a home
of its own kept between runs of that tool in that project (filled from the image on its first run:
what a rebuilt image changes under the home reaches it only after `ssai sandbox prune`), and, for a tool provisioned in your home
directory, its provisioned configuration — read-only, so a tool that rewrites its own configuration
cannot save it there (a provisioned file `run` cannot hand over is named, and the tool runs without it). Beside these, only the files `run` hands the tool are mounted, read-only: the
CA bundles (`--ca-file` and the gateway's) and any file or directory an `-e KEY=/path` names. Nothing
else of your machine is: not your home, your SSH keys, nor the host's Podman or Docker socket. The container has no network: everything leaves through the same guard
and the same destinations as the native sandbox, the inner Docker engine's pulls included, and `run`
names what it refused. The engine's own containers have no network: one that needs it runs on the
host network with the proxy (`docker run --network host -e http_proxy="$HTTP_PROXY" …`, and for a
build `docker build --network host --build-arg http_proxy="$HTTP_PROXY" --build-arg
https_proxy="$HTTPS_PROXY" …`). When the run ends, any file in the project that the container's root made
(a setuid binary included) is given back to you, with setuid cleared — by the next run, before its
tool starts, when a run was killed before it could. A file of one of the container's other users (a
database's data directory an inner container keeps in the project) keeps its owner, so the service
still owns it next time; only its setuid and setgid bits are cleared. A project of more than two
million files is swept only that far, and `run` says so. The tool's exit code is
`run`'s; SIGTERM to `ssai run` reaches the tool, and so does Ctrl-C at its terminal.

If a tool fails when confined because it needs a directory the sandbox doesn't grant it (some tools
keep configuration or state in an unusual place), run it once with `--sandbox learn`. This launches
the tool with its **network egress still restricted to the gateway** but the filesystem left open,
watches which directories it actually uses, and remembers the ones under your home directory so
every later `ssai run` allows them — turning a "permission denied" into a one-command fix. It
never records your credentials, and prints exactly what it added. (Learn mode is available on Linux
and WSL2.)

Clients with more than one model setting get the gateway's **default**, **fast** and **plan**
models — each the default model unless a route fills that client slot (LLM Gateway → the route's
**Client Slots**; see *Client slots* there):

| Client | Default model | Fast model | Plan model |
|---|---|---|---|
| Claude Code | `ANTHROPIC_MODEL`, the `sonnet` model | the `haiku` model, background tasks | the `opus` model, `opusplan`'s plan phase |
| OpenCode | `model`; agents `build`, `general`, `summary`, `compaction` | agents `title`, `explore` | agent `plan` |
| Crush | `models.large` | `models.small` | — |
| Zed | your pick in the Agent Panel | commit messages, thread summaries | — |
| Aider | `model` | `weak-model` | — |
| Goose | `GOOSE_MODEL` | — | the `/plan` planner |

The other clients have one model setting, which gets the default model.

Clients that list providers by name (OpenCode, Crush, Codex) get the gateway under a provider named
for your organisation and the provider you chose — `streamscope_<org>_<provider>`, e.g.
`streamscope_acme_nvidia` — so OpenCode's model is addressed as `streamscope_acme_nvidia/<alias>`.
Configs provisioned for different organisations or providers therefore never blend into one
entry: OpenCode, for one, merges your home-directory config into a project's, and two entries under
one name would merge into a single provider that shows both model lists but sends every request
with one key.

##### CI / pipelines

Non-interactive runners skip the browser login entirely and authenticate with a **workspace
automation key** (`ak-…`, minted by a workspace manager on the **Team** page) — the same
credential the portal automation API uses. Two environment variables make `provision` fully
unattended:

```bash
export STREAMSCOPE_URL=https://<portal-host>/portal/t/<org>
export STREAMSCOPE_AK=ak-…                     # the workspace automation key
ssai provision --client opencode        # e.g. deploy an OpenCode config on a fresh runner
```

In this mode nothing is stored on the runner beyond the written tool configs: the workspace is
the automation key's bound workspace, no prompts are asked, and each run mints a **short-lived**
gateway key (2 hours by default; tune with `--key-ttl 30m` / `--key-ttl 8h`). Expired per-run keys
clean themselves up — they stop working at expiry and are removed with the audit data retention
window. Two refinements:

- `STREAMSCOPE_GATEWAY_KEY=sk-…` skips minting entirely — the supplied key is written into the
  configs as-is (for pipelines that manage one long-lived key themselves).
- `--key-ttl` also works interactively, for a personal key that should expire.

#### Client integration snippets

Whatever the client speaks, a refused request comes back in that API's own error format — an
Anthropic client receives an Anthropic error, a Gemini client a Google one — so the client shows the
message rather than a raw error body. When the provider behind a model refuses a request, the
message names the model, what the refusal means and the status it answered, e.g.
`google/gemma-4-26b-a4b-it:free: upstream provider is rate-limiting requests; retry later (HTTP 429)`,
followed by the provider's own error message, passed on as the provider wrote it (a provider may
mention its own account there — Anthropic's rate-limit message names the organisation). The rest of
the provider's answer is not shown to the client; it is kept in the audit log, where administrators
see the full refusal. A provider that answers with something other than a response — an HTML
maintenance page, say — is reported to a client that needs the answer translated into its own API
as `<model>: upstream provider returned a response the gateway could not read (HTTP 200)`, with
status 502, never as a success it cannot read; the start of that page is kept in the audit log.
A provider that cannot be reached at all — the connection is refused, or nothing answers in time —
is reported as `<model>: upstream provider could not be reached` with status 502, or
`<model>: upstream provider did not respond in time` with status 504: the gateway is working and
the path to the provider is not, so it is never reported as the gateway's own internal error.

**Generic (OpenAI-compatible)** — Continue, Cursor, Aider, any OpenAI client:
```bash
export OPENAI_BASE_URL=https://<proxy-host>/v1
export OPENAI_API_KEY=sk-<your-streamscope-key>
```

**Claude Code** — speaks Anthropic Messages; Streamscope translates to any upstream:
```bash
export ANTHROPIC_BASE_URL=https://<proxy-host>
export ANTHROPIC_API_KEY=sk-<your-streamscope-key>
```
Map the model names Claude Code requests (`claude-opus-4-8`, `claude-sonnet-4-6`, …) to any
upstream via aliases on the **LLM Gateway** page.

**opencode** — OpenAI Chat Completions:
```bash
export OPENAI_BASE_URL=https://<proxy-host>/v1
export STREAMSCOPE_API_KEY=sk-<your-streamscope-key>
```

**Gemini CLI** — native Gemini API:
```bash
export GEMINI_API_KEY=sk-<your-streamscope-key>
export GOOGLE_GEMINI_BASE_URL=https://<proxy-host>
```
A Gemini client may present its key either as a header or in the URL — `?key=<your-key>` —
the way Google's own REST examples write it. Both are accepted on the Gemini endpoints, so a
hand-written `curl` copied from Google's documentation works with only the host changed. The
URL form is Gemini's alone: on the OpenAI and Anthropic endpoints a key must travel in a
header, because neither of those APIs defines a URL parameter for it. Prefer a header where
you have the choice — anything that logs a request line logs the whole URL with it.

**MCP clients** — point an MCP-aware agent at the per-tenant virtual server:
```jsonc
{
  "mcpServers": {
    "gateway": {
      "type": "http",
      "url": "https://<proxy-host>/mcp/<slug>",
      "headers": { "Authorization": "Bearer sk-<your-streamscope-key>" }
    }
  }
}
```
Use `https://<proxy-host>/fwd/<vk-…>/mcp/<slug>` for BYOK, or the spec-OAuth 2.1 discovery
flow for native MCP clients.

**Protocol versions.** A virtual server answers every published revision of the Model
Context Protocol, from `2025-03-26` through `2026-07-28`, and picks per request from
what the client declares — so a mixed fleet needs no separate address and no setting.
`2026-07-28` is a deliberate break with the revisions before it (no connection setup,
no session, and catalogue-change notifications delivered on a channel the client opens
per subscription), and clients on it get that surface even when the MCP servers behind
your virtual server only speak an older one: the gateway holds its own connection to
each and translates both ways.

The same holds in the other direction: an MCP server built on `2026-07-28` — including one
that speaks nothing else — works behind a virtual server with no configuration. The gateway
works out which revision each server speaks the first time it talks to it and remembers the
answer, and clients on older revisions reach that server normally. **Where a server speaks
both revisions the gateway keeps to the older one**, on purpose: its connection to a server
is shared by every client behind it, and only the older revision leaves the server a way to
ask a question mid-call — so preferring the newer one would quietly cost your older clients
that server's interactive tools.

Two consequences worth knowing before you point a newer client at an older MCP server:

- Where the server needs to ask the user something mid-call — for a value, or for a
  model completion — a newer client cannot be interrupted the way an older one could.
  The gateway turns the question into part of the reply and the client repeats the call
  with the answer. **The server re-runs whatever it did before it asked**, so a tool
  with side effects performs them twice. Servers normally ask before doing the work, but
  if one of yours does not, prefer an older client for it.
- A server that asks for input during a *resource read* rather than a tool call reports
  an error to newer clients instead. Nothing changes for older ones.

And two that apply when the MCP server is the newer one:

- An **older** client cannot receive a mid-call question at all from such a server, so the
  gateway tells the server up front not to ask. A well-behaved server then completes the
  call without asking; a tool that insists on asking reports a clear error rather than
  hanging. Newer clients are unaffected — they get the full round trip.
- **Subscribing to a single resource** on such a server is declined at subscription time.
  That revision replaced per-resource subscriptions with a stream the gateway does not yet
  hold open, and accepting the subscription would leave the client waiting for updates that
  were never going to arrive. Re-reading the resource after a call is the reliable check.

One limit applies to change notifications on both generations. When a client subscribes to
be told that a server's tool or resource list changed, it is told about changes the gateway
observes while handling that client's own traffic. A server that announces a change
completely out of the blue — with no request in flight from anyone — is not yet noticed, so
a subscription can stay quiet even though it was accepted. In practice servers announce
changes around activity, so this is rarely visible; if you depend on out-of-band
announcements, re-listing after a call is the reliable check.

---

## C. Workspace manager (the Portal)

A **manager** is an elevated member of a workspace — an end-user, not an admin. Managers never
touch the admin console; everything they do happens in the self-service **Portal** (the console host's root, `/`).
The role exists so a team lead can hand out and reclaim keys for their team without an admin
having to mint every one.

**How someone becomes a manager.** A tenant admin sets it on the **Governance → Workspaces** page
(section B.3): add the person to the workspace and flip their role from *member* to *manager*.
The change takes effect on the manager's next portal sign-in. Managers can't promote themselves or
others — granting the role stays admin-only.

**What a manager can do** (beyond an ordinary member):

- **Provision keys for any member of the workspace** — from **Portal → Members & limits** (`/portal/team`),
  mint an `sk-`/`vk-` key on behalf of another member, optionally with a **per-key budget**
  (daily/monthly cap + enforce-or-alert-only mode). The key is shown once, the same as
  self-service minting; the member can use it immediately. (Members minting their own keys cannot
  set a budget on them — capping a key stays a manager/admin lever.)
- **Revoke any member's key** in the workspace — reclaim access when someone leaves the team or a
  key is suspected leaked.
- **See the roster and per-member usage** — who's in the workspace and how much each member has
  spent against the workspace budget, and every limit that applies to each member.
- **Give one member an exception** — raise or lower a member's limit (requests, tokens, daily or
  monthly budget), field by field, inside the pool and member default you set. A manager can't
  change **a manager's** exception — their own or a fellow manager's; that stays with an
  administrator — and a value above the workspace pool changes nothing: the pool still applies.

**What a manager cannot do** — the boundaries that keep this an end-user role, not an admin one:

- **Change membership.** Adding or removing people from the workspace, and granting/revoking the
  manager role itself, stays with the tenant admin (section B.3).
- **Change what the workspace can reach.** Provider/MCP allowlists, the workspace pool and the
  default member limit, and the tool policy profile are all admin-set; a manager works *within*
  them.
- **See or manage other workspaces.** A manager's reach is exactly the workspace(s) where they
  hold the role — never tenant-wide, never the control plane.

**The ordinary member view**, for comparison: any member can mint and revoke **their own** keys in
any workspace they belong to (**Portal → API keys**, `/portal/keys`), run the **Quickstart** wizard to
get a ready-to-paste client config, and connect MCP servers that need their own account under
**Portal → Sign-ins**. A manager has all of this plus the team controls above.

> Budget and rate limits always win. A manager can mint keys freely, but every key the manager
> creates spends against the same workspace (and per-member) budget and rate-limit ceilings the
> admin set — minting more keys never raises the ceiling.

---

## Appendix — UI pages & routes

Every left-sidebar entry, grouped by its menu cluster. The **Platform** cluster shows only inside the
SYSTEM tenant; the rest are the per-tenant admin console.

All console routes are organization-scoped: the live address is `…/t/<organization>` followed by the
path in the **Route** column below (e.g. the audit log is `…/t/<organization>/audit`). The portal
mirrors this under `…/portal/t/<organization>/…`.

| Menu | Page | Route | Purpose |
|---|---|---|---|
| Platform | Overview | `/admin/overview` | Edge throughput, gateway latency overhead, resource pressure (super-admin) |
| Platform | Tenants | `/admin/tenants` | Create/manage tenants, invites (super-admin) |
| Platform | Edge Nodes | `/admin/edge` | Proxy nodes and their syncing replicas, config convergence, proxy log level (super-admin) |
| Platform | Appliance | `/admin/appliance` | VM-appliance lifecycle (restart/shutdown/upgrade/rollback), updates, network settings, and backup config (super-admin; appliance only) |
| Observability | Dashboard | `/dashboard` | Volume/tokens/cost + per-surface sub-views (LLM, Servers, Media, MCP, Web, A2A, Users, Tools, Transforms, Experts, Proxy) |
| Observability | Sessions | `/sessions` | Conversation timelines replayed turn-by-turn, alert badges, sub-agent linkage |
| Observability | Tool Calls | `/tool-calls` | Tool invocations (LLM + MCP) with the policy rule that handled each |
| Observability | Audit Log | `/audit` | Request logs (LLM/MCP/web/A2A), full traces, error/app/status filters |
| Governance | Workspaces | `/workspaces` | Members/roles, provider+MCP+A2A allowlists, limits/budgets, OIDC, tool profile |
| Governance | Keys | `/users` | Unified key inventory — user gateway keys + service-account automation keys, filterable by status/type/owner/workspace |
| Governance | Policy | `/policy` | Tool risk rules, profiles, field profiles, suggestions |
| Governance | Transforms | `/transforms` | Rhai request/response scripts, expert suggestions |
| Governance | Experts | `/experts` | Expert definitions, prompts, memory, agent control |
| Governance | Portal & clients | `/client-access` | Per workspace: the clients the portal and CLI offer; what the developers' sandbox may reach |
| Governance | Destinations | `/destinations` | Destination lists the sandbox and the Web tool attach as allow or block |
| Configuration | Clients | `/clients` | Detect AI apps hitting the gateway; per-app quickstart profiles |
| Configuration | Gateways → LLM | `/gateways/llm` | Upstream servers, model sync, downstream routes, pricing, aliases |
| Configuration | Gateways → MCP | `/gateways/mcp` | MCP upstreams, virtual endpoints, OAuth clients, **Web** tab |
| Configuration | Gateways → A2A | `/gateways/a2a` | Remote A2A agents: registry (card URL, auth), skills, workspace access |
| Configuration | Auth | `/auth` | Three tabs: auth settings (Internal/OIDC, IdP, groups), human accounts, service accounts |
| Configuration | Audit (admin) | `/admin-audit` | Who changed what on the control plane — before → after diff (secrets redacted), actor, IP |
| Configuration | Settings | `/settings` | Defaults, retention, feature toggles, agent, advanced |
| Portal | Home / Activity / Set up / MCP tools / Team | `/portal/*` | End-user self-service: the Home page, own sessions and requests, quickstart wizard, own keys and their usage, MCP sign-ins + server test, team provisioning (managers) |

## Appendix — gotchas

- **Default is ordinary** — it needs an explicit provider/MCP grant, and users join it only
  when explicitly added (no auto-join); membership ≠ access.
- **MCP and LLM allowlists are independent** — grant each separately per workspace.
- **Tool profiles are workspace-scoped** — shared builtins apply everywhere; profile rules
  apply only to workspaces selecting that profile.
- **Key prefix encodes the mount** — `sk-` works on `/v1/*`, `/mcp/<slug>` and
  `/fwd/{key}/mcp/<slug>`; `vk-` works only on `/fwd/{key}/...`. Wrong mount → generic
  `InvalidKey` (no leak of which).
- **A header the client sends belongs to one server per endpoint** — two servers attached to one
  endpoint cannot both expect the same client header; a client-sent `Authorization` moves the
  endpoint to `/fwd/{key}/mcp/<slug>`.
- **OIDC auto-membership and `admin_group` are additive** — they never remove members or
  demote roles; revoke manually.
- **SYSTEM OIDC flip is last** — finish all provisioning first (section A).
