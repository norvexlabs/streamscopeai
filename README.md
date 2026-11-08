<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="docs/img/logo-dark.svg">
    <img src="docs/img/logo-light.svg" alt="Streamscope AI" width="392">
  </picture>
</p>

<p align="center">
  <b>The security, audit and cost-control gateway for LLM and agentic workloads.<br>
  One endpoint for every model and every agent: see every call, govern every tool, pay for every
  token, without changing a line of application code.</b>
</p>

<p align="center">
  <a href="LICENSE"><img alt="Licence: AGPL-3.0" src="https://img.shields.io/badge/licence-AGPL--3.0-2b78a8"></a>
  <a href="COMMERCIAL.md"><img alt="Commercial licence available" src="https://img.shields.io/badge/commercial-licence%20available-2b78a8"></a>
  <a href="CHANGELOG.md"><img alt="Status: alpha" src="https://img.shields.io/badge/status-alpha-b6770b"></a>
  <img alt="Protocols: OpenAI, Anthropic, Gemini, MCP, A2A" src="https://img.shields.io/badge/speaks-OpenAI%20%C2%B7%20Anthropic%20%C2%B7%20Gemini%20%C2%B7%20MCP%20%C2%B7%20A2A-2b78a8">
  <img alt="Shapes: Docker, Kubernetes, VM appliance" src="https://img.shields.io/badge/runs%20on-Docker%20%C2%B7%20Kubernetes%20%C2%B7%20VM-2b78a8">
  <a href="https://github.com/norvexlabs/stowage"><img alt="packed with Stowage" src="https://raw.githubusercontent.com/norvexlabs/stowage/main/docs/img/packed-with-stowage.svg" height="20"></a>
</p>

<p align="center">
  <img src="docs/img/how-it-works.svg" alt="A coding agent in a sandbox on Linux, macOS or Windows reaches only the Streamscope AI gateway, which applies tool policy, budgets, QoS and audit, checks the request to the model for PII and the web content coming back for prompt injection, and forwards to the Anthropic API, to internal vLLM endpoints (translating between their protocols) and to the web" width="100%">
</p>

Coding agents, chatbots and autonomous pipelines make hundreds of model calls per task, across
several providers, and run tools on your machines and your SaaS accounts. Without a control
point you cannot see what is sent, who sent it, what it cost, or which tool an agent ran.

Streamscope sits between your AI applications and the providers they call. Every request, every
MCP tool call and every agent-to-agent task passes through it, so you get **one place** for
credentials, audit, policy and spend. Point a client at Streamscope instead of the provider; nothing
else changes.

> **Alpha — not for production use.** Core features work, but this is an early release: breaking
> changes may occur between versions (they are marked in the [CHANGELOG](CHANGELOG.md)), and it has
> not been audited for production, security-critical or regulated workloads. You use it at your own
> risk; see [Disclaimer](#disclaimer).

<p align="center">
  <a href="docs/img/console-session-blocked.png"><img src="docs/img/console-session-blocked.png" alt="A coding-agent session replayed in the console: the agent's attempts to read /etc/passwd and /etc/shadow are blocked by the tool policy, with the rule that fired" width="100%"></a>
  <br><sub>A coding agent's session, replayed: it asked for <code>/etc/passwd</code>, then tried the shell.
  Each call was blocked by the tool policy before it ran, and the rule that fired is on the record.</sub>
</p>

## Why Streamscope

**Any client, any model.** The gateway speaks OpenAI Chat Completions, OpenAI Responses, Anthropic
Messages and Google Gemini, and **translates between any pair**: streaming, tool calls, reasoning,
images and documents included. Run Claude Code against a Gemini model, or an OpenAI SDK against a
local vLLM. Where a target has no channel for part of a request, the gateway says so on the audit
record instead of dropping it silently. Embeddings, audio, images and video are gatewayed too.

**35+ providers, built in.** OpenAI, Anthropic, Google, Mistral, AWS Bedrock, Azure OpenAI, Vertex,
Groq, DeepSeek, xAI, OpenRouter, Ollama, vLLM and more, with failover, load balancing and
per-workspace routing. A model served by several replicas keeps each conversation on one of them, so
its prompt cache keeps working across turns, and moves it only when that replica fails. An alias
names a model and an invocation preset — a reasoning level, a temperature, any setting in the
model's own protocol — applied after translation, to every target the alias fails over to. Model capabilities and prices come from a maintained catalog; a price the
catalog does not know is reported as unknown, never guessed.

**Provider keys stay on the server.** Provider keys are stored encrypted on the gateway, never
handed to a laptop. People and automations get scoped gateway keys that can be revoked at once.
Clients that must use their own provider key can pass it through and are governed and audited just
the same.

**Every call on the record.** Each request is recorded with its user, workspace, client
application, model, tokens, cost, latency and outcome, including refusals, rate limits and upstream
errors, with optional full content capture and a retention you set. Agentic work is grouped into
**sessions** and replayed turn by turn: tool calls, reasoning, sub-agents, and the MCP and A2A calls
they made, interleaved in the order they happened. A conversation resends its whole history on
every turn; each message is stored once however often it is resent, so full capture stays
affordable on long agent sessions. The gateway recognises which application made each call — from a
header, its user agent or its system prompt — so you see what every tool drives.

**Govern what agents do, not only what they say.** One tool-policy engine classifies, blocks or
rewrites the tool calls agents make, on the model's output and on MCP traffic alike: a `rm -rf`, a
force-push or a call to a cloud metadata address. It reads what a tool is asked to do, not only its
name: ten built-in detectors recognise a reverse shell, a cloud-metadata request, destructive SQL, a
credential in the arguments, a container escape, a package install, downloaded or decoded code being
run, lookalike characters and more, and over fifty ready-made rules put them to work. Its matchers
normalise the many ways a shell command or a path can be written, and are property-tested against
the spellings that would bypass them.

**Guardrails on what goes in and comes out.** Web pages and tool content an agent reads are screened
for prompt injection and handed to the model as untrusted data; in enforce mode a flagged page is
withheld (the classifier is an optional extension the installer connects). PII — email addresses,
cards, IBANs, phone numbers, and the national ID and tax numbers of France, Germany, Italy, Spain and
the United Kingdom, checksums verified — is found in prompts and answers, and masked in an answer
that is not streamed; a streamed answer's findings are recorded. Scripted request and response
transforms sit on the same path, each change with its before/after on the record. Already inspect AI
traffic at your network edge? An external analyzer can send what it intercepts to the gateway's
analyze API and enforce the verdict, under the same policy and the same audit.

**AI experts on your own traffic.** Seven experts (security, compliance, cost efficiency, quality,
anomaly, tool policy, session linkage) read live traffic with a model you choose, raise alerts on
sessions and propose rules and transforms for an admin to accept.

**Budgets that hold across a fleet.** Budgets and RPM/TPM limits per workspace, member and key,
enforced at the edge and converged across every gateway replica, so ten replicas never grant ten
times a budget. Spend is kept in your accounting currency: a price quoted in another is converted
at a rate you set, never fetched, and a cost with no rate is flagged rather than guessed. A
response cache, exact or semantic, serves repeated questions at no model cost, and an observe mode
shows what it would serve on your own traffic before you turn it on.

**Fair shares of your own GPUs.** A self-hosted model saturates long before a cloud API does. For
vLLM and other self-hosted servers the gateway can hold the overflow itself instead of letting the
engine queue it: requests go by priority class (a person waiting before a CI job), fairly between
callers of the same class weighted by each workspace's share, and a request whose wait runs out is
refused with a `Retry-After`. Each engine is capped at what it sustains, and the gateway reads its
queue from the engine's own metrics; vLLM's priority scheduling can be driven from the same classes.
A model served by several replicas keeps each conversation on the replica that has it cached. The
Servers dashboard shows each engine's load, waits and refusals by class.

**MCP and A2A, governed.** Publish Model Context Protocol servers to your users through virtual
servers, with per-user OAuth, per-method scopes and both protocol eras served side by side. A
catalog of 100+ remote MCP servers is a click away. A built-in web MCP server fetches pages
behind an SSRF guard, and searches the web through an optional search extension. Agent2Agent traffic gets the same authentication, policy and audit.

**One list of destinations, allowed or blocked.** Destination lists name hosts, wildcard domains,
addresses and ports, and each is attached as **allow** or **block** — to the developers' sandbox
(what an agent on a laptop may reach besides the gateway) and to the web tool (what a search may
return and a fetch may open). A block always wins, and the cloud metadata address is never
reachable whatever a list says. Package registries, Git hosts, container registries and paste
sites come as ready-made lists to attach.

**The web tools agents bring, run by the gateway.** A provider's own server-side web search
(Anthropic's, OpenAI's) and the web fetch and search tools of Claude Code, OpenCode,
Gemini CLI and Continue can each be replaced, by a rule you turn on, with the gateway's: the model
calls the same tool, and the gateway runs it — through the destination lists, the SSRF guard, your
tool rules and the prompt-injection screening, on the record like any other call — instead of the
provider or the laptop reaching the web unseen.

**Your coding agents, provisioned in one command, run in a sandbox.** The `ssai` CLI (Linux, macOS,
Windows) configures Claude Code, Codex CLI, Gemini CLI, OpenCode, Goose, Cline, Aider, Cursor, Zed,
Crush, Qwen Code, Mistral Vibe and more against the gateway: models, keys and MCP servers, merged
into each tool's own config with your other settings kept. What each tool is given comes from a
client template the admin can edit, preview and add to in the console, and the portal's quickstart
renders the same templates. `ssai run --sandbox` then confines the agent to its project. Inside, it reaches the gateway plus
only what the admin's destination lists allow, and it can commit, from a linked worktree too. The
admin chooses which clients the portal and the CLI offer — one a new release adds arrives switched
off until enabled — and can require the sandbox, so `ssai run` will not launch an agent unconfined.

| Sandbox | How it confines the agent | Git hooks, git config and `.streamscopeai/` |
|---|---|---|
| Linux, native | Landlock | writable — `ssai run` says so when it starts |
| Linux, container (`--sandbox docker`, unless an admin turns it off) | a rootless Podman container built from the project's own image or dev container, a Docker engine inside if the project needs one | read-only |
| macOS | Seatbelt | read-only |
| Windows | a dedicated local account that reads nothing in your profile but what a run grants it (the tool's folder and configuration, trusted roots, files an `--env` names); `ssai sandbox setup` creates it once, and a project stays granted to it until `ssai sandbox revoke`. Claude Code, Codex, Gemini CLI, OpenCode and Goose run there | read-only |

**Multi-tenant from the database up.** Serve many isolated organisations from one deployment, each
with its own users, sign-in (local accounts or any OIDC provider, Entra ID and AD FS included),
configuration and audit. Console accounts carry a role, read-only included, checked on every
request, and service accounts with automation keys provision CI pipelines. With an identity
provider, the console role follows its groups — admin or read-only, re-checked at every sign-in, so
someone who leaves the group loses it — and members join their workspaces from a group claim.
Isolation is enforced by PostgreSQL row-level security on a role that cannot bypass it, so a query
without a tenant scope reads nothing. A self-service portal serves each organisation's members.

**Workspaces, each with its own posture.** Inside an organisation, a workspace is where access,
budget, priority and keys come together: it grants the providers, MCP servers and A2A agents its
keys may reach, holds its members and their roles, and picks a profile for each policy — tool
policy, guardrail, transforms and AI experts. The Default profile is the shared base; a workspace's
own profile either layers on it, adding only what differs, or stands alone, and any policy can be
turned off for one workspace. The tool rules, guardrail recognisers, transforms, experts, client
templates, MCP catalog, model catalog, priority classes and destination lists ship built in and are
updated with each release; a built-in you edit becomes yours and is never overwritten, one you delete
stays deleted, and a reset brings the shipped versions back. A workspace manager — a team lead,
not an admin — runs the team from the portal: mints and revokes members' keys, puts a budget on
each, and raises or lowers one member's limit inside the pool the admin set.

## For admins: one console for every model, tool and agent

<table>
  <tr>
    <td width="50%"><a href="docs/img/console-dashboard.png"><img src="docs/img/console-dashboard.png" alt="Overview dashboard: upstream health, alerts, blocked tools, guardrail hits, errors and budget breaches across LLM, MCP and A2A traffic"></a></td>
    <td width="50%"><a href="docs/img/console-session-alert.png"><img src="docs/img/console-session-alert.png" alt="A session carrying a major alert raised by the AI experts, each finding labelled with the axis that raised it"></a></td>
  </tr>
  <tr>
    <td><b>Health at a glance.</b> Upstreams, alerts, blocked tool calls, guardrail hits, errors and
    budget breaches, across LLM, MCP and A2A traffic.</td>
    <td><b>Experts that read the traffic.</b> The AI experts raised a major alert on this session,
    each finding labelled with its axis and pointing at the turn it came from.</td>
  </tr>
  <tr>
    <td><a href="docs/img/console-tool-calls.png"><img src="docs/img/console-tool-calls.png" alt="Tool calls across protocols: LLM tool calls, MCP tools/call and built-in web search and fetch, each with its user, latency and outcome"></a></td>
    <td><a href="docs/img/console-llm.png"><img src="docs/img/console-llm.png" alt="LLM dashboard: tokens, cost by unit, latency percentiles, reliability, request volume and response-cache savings"></a></td>
  </tr>
  <tr>
    <td><b>Every tool call, one list.</b> LLM tool calls, MCP <code>tools/call</code> and the built-in
    web search and fetch, each with who made it, how long it took and how it ended.</td>
    <td><b>Spend and performance.</b> Tokens, cost by unit, latency percentiles and time to first
    token, reliability, and what the response cache saved.</td>
  </tr>
</table>

## For users: self-service, from the browser or the terminal

Members sign in to a **self-service portal** of their own: a Home page with what needs their
attention, their sessions, requests, usage and limits, their keys, and a quickstart that generates
the configuration for their tool, MCP servers included.

<p align="center">
  <a href="docs/img/portal-quickstart.png"><img src="docs/img/portal-quickstart.png" alt="Portal quickstart: a ready-to-paste Claude Code configuration pointing at the gateway, with two MCP servers wired in" width="100%"></a>
</p>

Or skip the copy-paste: **`ssai`** does it from the terminal. Sign in with a device code, let it
detect your tools and write their configuration, check what it manages, then launch the agent in
the sandbox. Here Claude Code runs with its permission prompts turned off, and still cannot reach
the internet or touch your shell profile, while the gateway's tool policy blocks its read of an SSH
key:

<p align="center">
  <img src="docs/img/ssai.gif" alt="Terminal recording: ssai login with a device code, ssai provision detecting Claude Code and wiring two MCP servers, ssai status, then ssai run claude: inside the sandbox the agent's curl to the internet and its write to ~/.bashrc are refused, and its read of the SSH key is blocked by the gateway's tool policy" width="100%">
</p>

## Built for production

- **Rust** on the request path, with an edge/control-plane split: gateway replicas hold no shared
  state, keep only a local queue of records still to deliver, and pick up a configuration change
  within seconds; the control plane scales horizontally.
- **Bounded by design**: every upstream call has a timeout, every response body a size cap, and
  liveness is separate from readiness, so a database blip never restarts the fleet.
- **Every change audited**: every mutation in the console and the API writes an audit record, with
  secrets redacted from the diff.
- **A typed REST API** with an OpenAPI spec and an interactive reference at `/api/docs`; the
  console is built on the same API.
- **Signed and scanned releases**: every image, chart, installer and VM disk is signed and carries
  its SBOM, and is scanned for known vulnerabilities before it is published — a fixable high or
  critical finding stops the release, unless a dated, reasoned exception accepts it for a while.
  Every install and upgrade verifies the signature before it runs anything, and `ssai-stow audit`
  checks a release against today's advisories.
- **Backups**: off-host and encrypted to public keys whose private halves stay with you, on the VM
  appliance and the Docker deployment; on Kubernetes, the database platform's continuous archive.
- **Prometheus metrics** for the gateway and the admin API, on hostnames of their own, open only to
  the sources you allow.

## Performance

One gateway process on **a single CPU core**, serving a coding agent's session as it really grows:
each request carries the conversation so far plus one new message, is translated between providers'
protocols (Anthropic in, an OpenAI-compatible model out), streamed back, scanned for PII, and
recorded in full — every message kept, each stored once however often it is resent.

| Conversation length | Requests per second, one core | Time the gateway adds to a request |
| --- | ---: | ---: |
| 16K tokens (a session's start) | ~900 | ~1 ms |
| 64K tokens (mid-session) | ~440 | ~2 ms |
| 160K tokens (a long session) | ~210 | ~5 ms |

A **second core gives 1.85×** the throughput (16K: ~1,660 requests per second): the gateway scales
with the cores it is given. The time added is what a client waits through the gateway beyond the same
request sent straight to the model, with two requests in flight. Measured with a stand-in model that
answers instantly, so the figures are the gateway's own cost; a real model's response time comes on
top. The model, the load generator and the database ran on other cores of the same machine (a
desktop-class x86 processor).

## Get started

Streamscope ships in **three form factors**, all running the **same container images** and installed
by the same installer, `ssai-stow`. Nothing needs to be built to install it:

- **Docker** — one command on any machine with Docker. It generates the secrets, starts the stack
  and creates the platform administrator and an organisation with its administrator; providers,
  users and keys are then added in the console. The fastest way to try it, and enough to run it.
- **VM appliance** — a ready-to-boot disk image (OS + apps + database in one box), with atomic
  upgrades that fall back on their own when a new release fails its health check, off-host
  backups, and a mirror path for sites without internet. It is operated from the console: upgrade
  or roll back with the release notes in front of you, change its network on a timer that restores
  the old settings unless you confirm, and set up and run its backups.
- **Kubernetes** — a Helm chart wrapping the same images, installed with `ssai-stow k8s
  install`: an external (PostgreSQL 18 or later), embedded or operator-managed
  Postgres, horizontal autoscaling, and Ingress + cert-manager for TLS. Hardened by default.

Full step-by-step for all three is in the **[Operator Guide](docs/OPERATOR_GUIDE.md)** (VM appliance
in sections A–E, Kubernetes in section F, Docker in section G).

## Quickstart

On your own machine, with Docker and its Compose plugin, in about five minutes. The release is public
on `ghcr.io`, so nothing needs an account, and this setup serves on your loopback address only — no
domain, no certificate:

```bash
docker run --rm ghcr.io/norvexlabs/streamscopeai-installer:latest > streamscopeai.sh
sh streamscopeai.sh
```

1. **Answer four questions** — your email (the platform administrator), the organisation's name and
   short name, and its administrator's email. Pressing Enter keeps the defaults: an organisation
   `Default`, administered from your own address.
2. **Sign in** at <http://127.0.0.1:3000/admin> as the organisation administrator. The installer saved
   both accounts' generated passwords to `streamscopeai/credentials.txt`, readable only by you.
3. **Set up the organisation in the console**, following the Admin Guide's
   **[Getting started](docs/ADMIN_GUIDE.md#getting-started)**: connect a model provider, allow the
   Default workspace to use it, create an API key, and send a request to the gateway at
   `http://127.0.0.1:8080/v1`. It appears under **Audit** a moment later.
4. **Connect a coding agent** with the `ssai` CLI, as a user you added to the workspace — install
   it from the console (`curl http://127.0.0.1:3000/api/v1/cli/install.sh | sh`; on Windows, in
   PowerShell, `irm http://127.0.0.1:3000/api/v1/cli/install.ps1 | iex`), then
   `ssai login http://127.0.0.1:3000/portal/t/default` and `ssai provision`. On this loopback setup
   clients run unsandboxed; `ssai run --sandbox` needs the gateway served over HTTPS.

A model server on your own network (vLLM, Ollama) is a private address, which the platform refuses
until you allow it: sign in at <http://127.0.0.1:3000/system> as the platform administrator and
list it under **Settings → Egress**.

For everything beyond a personal machine — real hostnames and TLS, upgrades, backups, the VM
appliance, Kubernetes, and installing without internet from a mirror — see the
**[Operator Guide](docs/OPERATOR_GUIDE.md)**: Docker in
[section G](docs/OPERATOR_GUIDE.md#g-docker-deployment), the VM appliance in
[sections B–D](docs/OPERATOR_GUIDE.md#b-install-the-vm-appliance), Kubernetes in
[section F](docs/OPERATOR_GUIDE.md#f-kubernetes-deployment) and mirrors in
[section A](docs/OPERATOR_GUIDE.md#a-how-streamscope-is-delivered).

## Documentation

- **[Operator Guide](docs/OPERATOR_GUIDE.md)** — **deploy and run the infrastructure** with
  `ssai-stow`: install, TLS, backup and restore, upgrades and rollback, recovery, and the
  settings reference.
- **[Admin Guide](docs/ADMIN_GUIDE.md)** — **configure the product through the web console.** Opens
  with how Streamscope works and a half-hour
  **[Getting started](docs/ADMIN_GUIDE.md#getting-started)**, then walks through sign-in and OIDC,
  providers, workspaces, users and keys, automation, MCP, web search, tool policy, experts,
  observability and the member portal.

## Build from source

Every image builds with Docker alone, and the application images run their checks (clippy with
warnings fatal, the unit and workspace tests, the dependency audits) as part of the build: no green
checks, no image. The commands, the
rules a contribution is reviewed against and the Contributor Licence Agreement are in
**[CONTRIBUTING.md](CONTRIBUTING.md)**.

Releases (images, installer, Helm chart, VM disks) are packaged, signed and published by
**[Stowage](https://github.com/norvexlabs/stowage)** from one spec, `stowage.yaml`.

## License

Streamscope AI is free software under the **[GNU Affero General Public License v3.0](LICENSE)**. If
you run a modified version as a network service, the AGPL requires you to offer its source to its
users. A **commercial licence** is available for uses the AGPL does not fit; see
[COMMERCIAL.md](COMMERCIAL.md). Third-party attributions and the trademark policy are in
[NOTICE](NOTICE).

## Disclaimer

THIS SOFTWARE IS AN ALPHA RELEASE AND IS NOT INTENDED FOR PRODUCTION USE. IT IS PROVIDED "AS IS",
WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. THE ENTIRE RISK AS TO
THE QUALITY, PERFORMANCE AND SECURITY OF THE SOFTWARE IS WITH YOU.

TO THE MAXIMUM EXTENT PERMITTED BY APPLICABLE LAW, IN NO EVENT SHALL THE AUTHORS, CONTRIBUTORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER DIRECT, INDIRECT,
INCIDENTAL, SPECIAL, EXEMPLARY OR CONSEQUENTIAL (INCLUDING BUT NOT LIMITED TO LOSS OF DATA, LOSS OF
PROFITS, BUSINESS INTERRUPTION, SECURITY INCIDENTS, DISCLOSURE OF INFORMATION, OR CHARGES INCURRED
WITH MODEL PROVIDERS OR OTHER THIRD-PARTY SERVICES), HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
WHETHER IN CONTRACT, STRICT LIABILITY OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE), ARISING IN ANY WAY
OUT OF THE USE OF OR INABILITY TO USE THE SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

Policy, guardrail, budget and audit features reduce risk; they do not guarantee that any request,
tool call, data disclosure or cost is prevented or recorded. You are responsible for evaluating the
software for your use, for your configuration and deployment, and for your compliance with the laws
and third-party terms that apply to you. This disclaimer complements sections 15 and 16 of the
[AGPL-3.0](LICENSE), which govern; a separate written commercial licence may provide otherwise.
