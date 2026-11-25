# Portal Guide

How to **use Streamscope as a member of a team**: sign in to your organization's portal, install the
`ssai` command-line tool, set your AI tools up to go through the gateway, run them in the sandbox, and
follow what they do. The guide follows the path most people take: the portal's **Quickstart** page
hands you the CLI, the CLI sets up your tools, and the portal is where you come back to see your
activity, connect your own accounts to MCP servers and — as a workspace manager — run your team.

What is around you is configured by others: your organization's administrators set up the
providers, workspaces, policies and what the portal offers you ([Admin Guide](ADMIN_GUIDE.md)), and
the infrastructure is run by its operators ([Operator Guide](OPERATOR_GUIDE.md)). This guide covers
what you do yourself.

## Contents

- [Before you start](#before-you-start) — [your workspace](#your-workspace),
  [your workspace's manager](#your-workspaces-manager)
- [1. Sign in to the portal](#1-sign-in-to-the-portal)
- [2. Install the `ssai` CLI](#2-install-the-ssai-cli)
- [3. Log in from the terminal](#3-log-in-from-the-terminal)
- [4. Provision your tools](#4-provision-your-tools) — [global or project](#global-or-project-provisioning),
  [per-client notes](#per-client-notes)
- [5. Run an agent in the sandbox](#5-run-an-agent-in-the-sandbox) — [what each platform needs](#what-each-platform-needs),
  [network sandboxing](#network-sandboxing),
  [natively](#the-native-sandbox),
  [on Windows](#the-windows-sandbox), [in a container (advanced)](#advanced-the-container-sandbox-linux)
- [6. Keep your setup current](#6-keep-your-setup-current) — [command reference](#command-reference)
- [7. Home — your dashboard](#7-home--your-dashboard)
- [8. Connect your accounts to MCP servers](#8-connect-your-accounts-to-mcp-servers)
- [9. Keys, and tools set up without the CLI](#9-keys-and-tools-set-up-without-the-cli)
- [10. Review your activity](#10-review-your-activity)
- [11. Run your team (workspace managers)](#11-run-your-team-workspace-managers)
- [12. CI and pipelines](#12-ci-and-pipelines)
- [13. Troubleshooting](#13-troubleshooting)

## Before you start

Three things come from your administrator:

- **The portal's address** — the console host's root, `/`, or `…/portal/login/<organization>`.
- **An account** — a password your administrator set (one password covers every place you sign in),
  or your organization's single sign-on, which creates your account on its first sign-in.
- **A workspace** — a new account joins no workspace on its own. Until an administrator adds you to
  one (or your single-sign-on groups do), the portal tells you that you are not a member of any
  workspace yet, and you cannot mint a key.

**Keys.** A key is the credential your tools send in place of a provider's. An `sk-` key uses the
credentials the gateway holds for the provider; a `vk-` (BYOK) key forwards your own provider
credential. The gateway keeps only a hash of a key, so a key is shown once, when it is made.

### Your workspace

A **workspace** is your team's unit of access, budget and keys inside your organization. Every key
belongs to exactly one workspace and reaches what that workspace allows. Your administrator decides,
per workspace:

- **What its keys reach** — the model providers, the MCP servers and the A2A agents it is granted,
  each separately: a workspace can reach models and no MCP server. A change reaches every existing
  key within seconds; a provider taken away does not revoke your key, which simply stops reaching it.
- **Its limits** — four can apply to each request, and the tightest wins: the organisation's
  ceiling, the workspace **pool** every member shares, your own **member** limit (the workspace's
  default for each member, or an exception set for you), and a key's own budget. Rates are counted
  per surface (models, MCP, A2A); budgets run over the UTC day or a 30-day period. A refused request
  names the limit that refused it (`bucket`: `organisation`, `workspace`, `member` or `key`), and
  Home's **My limits** shows each one with what you have used ([section 7](#7-home--your-dashboard)).
- **Whether members see one another's activity** — off by default: you see only your own sessions
  and requests. A workspace that shares shows a **Me / Team** switch on the activity pages, and then
  every member sees the full text of the others' requests and responses there.
- **What your tools may do** — its tool policy, the clients the portal and the CLI offer, and what
  the sandbox may reach ([Network sandboxing](#network-sandboxing)).

You can belong to several workspaces: each has its own limits and usage for you, and the portal
header's workspace picker sets the one you work in. Leaving a workspace (an administrator removes
you) revokes your keys in it; they stay listed as revoked, so past requests still name them.

### Your workspace's manager

A workspace has **members** and may have **managers**, both named by your administrator. A member
mints and revokes their own keys and sees their own usage. A **manager** is a member with team
controls — still an end user, never an administrator — who, for that workspace only, mints and
revokes keys for any member (optionally with a budget on the key), sees the roster with each
member's usage and limits, gives a plain member an exception to the member limit, and runs the
workspace's automation accounts ([section 11](#11-run-your-team-workspace-managers)).

Who to ask:

- **your manager** — a key with a budget, an exception to your limit, or an automation key for a
  pipeline ([section 12](#12-ci-and-pipelines));
- **your administrator** — joining a workspace, a provider or MCP server the workspace does not
  reach, the pool or the member default, a destination the sandbox refuses, or becoming a manager.

## 1. Sign in to the portal

Open the portal's address. With a single organization it goes straight to its sign-in page; with
several it asks which one, and remembers it in that browser. Sign in with your email and password,
or with **Sign in with SSO**. You land on **Home** ([section 7](#7-home--your-dashboard)).

Portal pages live under `…/portal/t/<organization>/…`, so bookmark a page from the address bar.
Because each organization keeps its own session, you can be signed in to several organizations at
once in the same browser, one per window; signing out ends only the organization you signed out of.
The portal needs a current browser: Chrome or Edge 111+, Safari 16.4+ or Firefox 128+.

To set up your tools, open **Set up → Quickstart**. It opens on **Set up via CLI**: the commands of
the next three sections, filled in for your portal. The **Web wizard** tab is the copy-paste
alternative ([section 9](#the-web-wizard)).

## 2. Install the `ssai` CLI

The `ssai` command-line tool automates the whole Quickstart flow — instead of copy-pasting
a snippet per tool, it writes each AI client's configuration directly. The gateway itself serves
the CLI (Linux x86_64, Windows x86_64, FreeBSD amd64 — 14.4 and newer — and macOS Apple Silicon
when your gateway ships a macOS build; the installers verify the download's checksum), and the Quickstart page's **Set up via CLI**
tab shows these commands pre-filled for your portal:

```bash
curl -fsSL https://<portal-host>/api/v1/cli/install.sh | sh   # installs to ~/.local/bin
ssai login https://<portal-host>/portal/t/<org>   # any portal URL works — opens your browser
ssai provision                                     # detects installed tools, mints one workspace key, writes configs
```

A fresh FreeBSD system has neither `curl` nor `sudo` (the installer uses `sudo` only to add a
private gateway root to the system trust store): `pkg install curl sudo` first.

#### AI clients on FreeBSD

`ssai` itself needs FreeBSD 14.4 or newer; the AI clients it provisions are another matter, because
most of them publish no FreeBSD build:

- **Clients that run natively** — Gemini CLI, Qwen Code and the Continue CLI, installed from npm on
  FreeBSD's own Node.js (`pkg install node24 npm-node24`, then `npm install -g` as on Linux; Gemini
  CLI also wants `pkg install ripgrep`), and Crush, from the FreeBSD build on its releases page (its
  npm package carries none).
- **Clients published only as Linux binaries** — OpenCode (version 2), Claude Code, Codex, Goose
  and Open Code Review. These run only under FreeBSD's **Linux binary compatibility**, and only on **FreeBSD 15.0
  or newer**: the compatibility layer of FreeBSD 14 lacks the file-change notifications (`inotify`)
  these clients watch your project with, and OpenCode never gets past its start on it. An
  administrator enables it once, as root:

  ```sh
  sysrc linux_enable=YES            # load the Linux compatibility at every boot
  service linux start               # now: the kernel modules and the /compat/linux mounts
  pkg install linux_base-rl9        # the Linux userland (Rocky Linux 9) the clients' libraries come from
  ```

  If `service linux start` reports that it cannot load a module, the installed kernel is newer
  than the running one (a base system upgrade waiting for its reboot): reboot, then run it again.
  Then put the client's **Linux x86-64** binary on your `PATH` (`~/.local/bin`):

  - OpenCode and Goose: the `linux-x64` / `x86_64-unknown-linux-gnu` archive from their releases page.
  - Claude Code, Codex and Open Code Review: `npm install -g --os=linux --cpu=x64 <package>`
    fetches the Linux binary, but the package's launcher looks for a FreeBSD one and stops; link
    the Linux binary itself instead (Claude Code's is the `@anthropic-ai/claude-code-linux-x64`
    package's `claude`, Codex's the `@openai/codex-linux-x64` package's `codex`, Open Code
    Review's the `@alibaba-group/ocr-linux-x64` package's `opencodereview`, linked as `ocr`).

  A client's next release may ask the compatibility layer for something it lacks: after an
  upgrade, check it once with `ssai run --sandbox off <client>`.
- **Not available on FreeBSD** — Aider and Mistral Vibe: dependencies they compile at install time
  do not build there.

Whichever kind it is, `ssai provision` writes the client's configuration as on Linux, and `ssai run`
launches it in a jail of its own once the sandbox is set up on the machine
([The FreeBSD sandbox](#the-freebsd-sandbox)); a client under the Linux binary compatibility runs
there too.

On Windows, install from PowerShell (Windows PowerShell 5.1 or PowerShell 7) instead; the rest is
the same:

```powershell
irm https://<portal-host>/api/v1/cli/install.ps1 | iex   # installs to %LOCALAPPDATA%\Programs\ssai, adds it to your PATH
```

The Windows `ssai.exe` is signed by **Norvex Labs** (Authenticode, SHA-256, timestamped) with a
self-signed code-signing certificate whose SHA-1 thumbprint is
`8061BA54146A8D17F22E4B5210650147C1CAB75A`. As no public certification authority issued it, the
signature alone does not quiet SmartScreen or Smart App Control, and Windows reports it as untrusted
(`Get-AuthenticodeSignature` answers `UnknownError`). An organisation that wants it to count takes the
certificate from an installed `ssai.exe`, checks its thumbprint against the one above, and deploys it
to **Trusted Root Certification Authorities** and **Trusted Publishers** (Group Policy or Intune):

```powershell
$cert = (Get-AuthenticodeSignature "$env:LOCALAPPDATA\Programs\ssai\ssai.exe").SignerCertificate
$cert.Thumbprint                                   # must read 8061BA54146A8D17F22E4B5210650147C1CAB75A
Export-Certificate -Cert $cert -FilePath norvexlabs-codesign.cer
```

`Get-AuthenticodeSignature` then answers `Valid`, signer `CN=Norvex Labs`, and an App Control for
Business (WDAC) or AppLocker publisher rule can allow the CLI across releases, where a hash rule
breaks on every update. The certificate can sign code only: it cannot issue certificates, so trusting
it trusts nothing else.

### On Windows

On Windows the CLI keeps its own state in `%LOCALAPPDATA%\streamscopeai\config\` (never the
roaming profile a domain copies to its server), readable by your account
alone, and writes each tool's configuration where that tool reads it on Windows: in your profile
folder for most (`%USERPROFILE%\.claude`, `.codex`, `.gemini`, `.config\opencode`, …), and under
`%APPDATA%` for Goose, Zed, VS Code (Cline) and Claude Desktop. The sandbox described below runs on
Windows through a dedicated sandbox account, set up once with `ssai sandbox setup`, which asks for
administrator rights on the computer (**The Windows sandbox**, below). (`--ca-file` there gives the client, for that run, the roots Windows trusts plus
the file's — it changes nothing in Windows' own trust.)

### A gateway with a private certificate

If your gateway uses a private or self-signed certificate, `curl` cannot fetch the installer itself
until it trusts that certificate: ask your gateway operator for its root certificate and fetch with
`curl -fsSL --cacert <that file> https://<portal-host>/api/v1/cli/install.sh | sh`. The installer detects that the
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

## 3. Log in from the terminal

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

### The approval page

`ssai login` opens the portal on **Authorize Streamscope CLI**, naming the machine that asks. It
says what the CLI can do — mint gateway keys in your workspaces and read the client-config catalog —
and what it cannot: manage teams, budgets, or anything in the admin console. **Approve** or **Deny**.
With `ssai login --device`, the portal's **Approve a device** page first asks for the code your
terminal shows: approve only if the code matches. An approved device signs in within a few seconds;
a denied one stops at its next poll, with nothing granted. Revoke a device at any time with
`ssai logout` on it ([section 6](#6-keep-your-setup-current)).

## 4. Provision your tools

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
Mistral Vibe, Qwen Code, Goose, Zed, Cursor, Cline, Continue, Aider, Crush, Claude Desktop, Open Code Review,
and the curl/SDK snippets (printed to the terminal). Your own entries in Aider's `set-env` list and Continue's `models` and `mcpServers` lists are kept beside the gateway's.
One caveat: Aider's, Continue's, and Goose's YAML config files keep all your settings but not
your comments — the other formats preserve comments too, including a JSON config with comments or
trailing commas (VS Code's `settings.json` for Cline, Gemini CLI's and Qwen Code's), which is edited in
place around your text. Zed reads the API key from a `STREAMSCOPE_API_KEY`
environment variable (or the Agent Panel) rather than its `settings.json`, so export the minted key in your shell. Gemini CLI
gets the model in its `settings.json` both as its own and for each built-in subagent that would otherwise call a Google model
by name (`codebase_investigator`, `cli_help`, `browser_agent`); `generalist` follows the session's model. Qwen Code
gets the gateway in `~/.qwen/.env` with an output cap (the model alias's, else the model's, else 8 192 or its window if smaller), plus two keys merged into
`~/.qwen/settings.json`: the OpenAI sign-in type (so a Qwen account you signed in with earlier does not
take over) and, when the gateway knows the model, its context window. Aider gets
`~/.aider.model.metadata.json` beside `~/.aider.conf.yml`: its model with the output cap and, when the
gateway knows it, the context window, and its weak model by name, so Aider neither warns of an unknown
window nor downloads a public model list each time it starts. A BYOK provider gets none, since the gateway
does not know the model you name. A config file that is not valid
JSON even allowing comments and trailing commas, or one with comments that repeats a key, is not
rewritten — `provision` stops before writing anything for that tool and names the file.

### Global or project provisioning

Decide first **where** `provision` writes:

| | Global (the default) | Project (`--local`, or `--dir <path>`) |
|---|---|---|
| Writes | each tool's configuration in your home directory | the tool's project-local configuration in the project, tracked in its `./.streamscopeai/` folder |
| Applies to | the tool wherever you start it | that project only |
| Tools | every detected tool | only tools with a project-local configuration; a global-only tool (Codex, Continue, Crush, Goose, Qwen Code, Mistral Vibe, Open Code Review) is skipped unless you name it, and is then written globally |
| Your key and git | a home directory that is a git repository gets the files in its `.git/info/exclude` | the files are added to the project's `.gitignore` |
| `sync`, `status`, `forget`, `restore` | run anywhere outside a provisioned project | run from inside the project (`restore --global` reaches the home-directory runs) |
| `ssai run` | confines the tool to the folder you start it in | confines the tool to the project, from any folder in it |
| Claude Code's MCP servers | printed as `claude mcp add-json` commands to run once; no local MCP server | written into `./.mcp.json`, local MCP servers included |

`ssai run` looks for the tool in the project's provisioning first, then in your home directory's,
so a tool provisioned globally runs from any folder. Choose a project provisioning for a project
with a setup of its own — and on Windows for Claude Code, whose home-directory MCP servers the
sandbox account does not see ([The Windows sandbox](#the-windows-sandbox)).

By default `provision` writes each tool's **global** configuration in your home directory. To set a
tool up for **one project** instead, run `ssai provision --local` from inside the project (or
`--dir <path>`): it writes the tool's project-local config there — for example `./.claude/settings.json`
(with your MCP servers in `./.mcp.json`, enabled by name so Claude Code loads them without asking once
you trust the folder; a home-directory run instead prints the `claude mcp add-json` command for each
server, since Claude Code keeps its own state in the one file it reads them from there — run them once,
and again when your servers change; `forget` and `restore` leave a server you added this way, which
`claude mcp remove --scope user <name>` removes), `./.gemini/settings.json`, or `./.opencode/opencode.json` — and tracks what it wrote in a
`./.streamscopeai/` folder inside the project. A project provisioning writes **only** project files: a
tool that has only a global configuration (Codex, Continue, Crush, Goose, Qwen Code, Mistral Vibe, Open Code Review —
Continue's editor extension and CLI, for one, both read a single file in your home directory) is
skipped with the command that provisions it globally (`ssai provision --global --client …`),
unless you name it with `--client`, or tick it in the prompt and confirm writing it to your home
directory. (When neither `--local` nor `--dir` is given, `provision` offers
the global-vs-project choice only if at least one selected tool supports a project-local config.) Use
`ssai provision --global` to force the home-directory config even when you're inside a
project that has a `./.streamscopeai/` folder (which otherwise auto-selects the project).

### Picking a variant

A tool that can speak both the OpenAI and the Anthropic protocol (OpenCode,
Crush, Continue, Cline, Aider, Open Code Review) is provisioned with its OpenAI-compatible variant, which works with
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

### MCP servers

When a tool you're provisioning can use MCP (every one listed above except Aider,
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

### Local MCP servers

When your workspace is handed local MCP servers — servers your own machine
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

### OpenCode and your home-directory config

OpenCode reads your home-directory config
(`~/.config/opencode/opencode.json`) as well as the project's, and two of its settings outrank a
project's: a provider rule (`policies`, `experimental.policies`, or an older `enabled_providers` list) that
leaves the gateway's provider out, and a model pinned to an agent (`agents.build.model`, …). Every
OpenCode config the CLI writes, project or home directory, therefore pins every built-in OpenCode
agent (`build`, `plan`, `general`, `explore`, `compaction`, `title`, `summary`) to one of the
gateway's models (the table under [Model slots and provider names](#model-slots-and-provider-names)), so a pin in your home config can't take OpenCode elsewhere. A
home-directory provisioning replaces a model you had pinned to one of those agents, and every later
`provision` or `sync` does the same to a model you pin there again — to run an agent on another
gateway model for yourself, pin it in a project config. Agents of your own, and providers and policy
entries you define yourself in that file, are kept, except a rule of your own for `opencode` (below). A home-directory provider rule still wins over any project, so
`provision` and `status` name the file and the exact line that would allow the gateway's
provider when yours leaves it out (then restart OpenCode's background service with `opencode service
restart`), and list every agent your home config, or another OpenCode config it loads, still pins to another provider it can use (one of your own, in a config or in a Markdown agent file, or a pin under
the older `agent` key). An agent pinned to a provider your rules deny runs on the default model, so it is not listed. They also name a config loaded after the
gateway's that sets the default `model` to another provider: every agent without a model of its own runs there. A **global** OpenCode
provisioning adds that allow line itself, in both of the file's lists of provider rules — `experimental.policies`
and the top-level `policies`, which OpenCode 2.3 reads after it (an earlier OpenCode 2 reads only the first): at
the end of each list, or — when a list already has a rule for the gateway's provider — in that rule's place, which
it then manages. Your other rules are kept, so a `deny` on `*` in either list is lifted, and a deny you add after
the allow in the top-level list still wins; `provision` and `status` name it. A project
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
brings the provider back, and say which launch it reaches. Your administrator can allow the provider
again in the OpenCode client profile ([Admin Guide § 9c](ADMIN_GUIDE.md#9c-portal--clients-and-destinations--governance--portal--clients--destinations)). `ssai forget` removes the rule, so it does not bring back one of your own
that it replaced: restore that from the backup `provision` took. A provider OpenCode finds through its own API key in your environment is not
covered by this rule.

Every OpenCode config the gateway writes also
turns off OpenCode's session sharing and its own web search, so the agent searches through the
gateway's MCP web tools when the workspace has access to them (without them OpenCode has no web
search); your administrator can change that default in the OpenCode client profile.

### What the configs turn off

The configs for the other tools likewise turn off what each tool sends its own vendor besides
your requests, wherever its config file has a switch for it: usage statistics, telemetry and crash
reports, and update checks, for Claude Code, Codex, Gemini CLI, Qwen Code, Crush, Goose, Mistral
Vibe, Aider and Zed. Continue's command-line client sends no usage data of its own (its metrics go
only to a collector you configure yourself), and Open Code Review sends none unless
`OCR_ENABLE_TELEMETRY=1` is set; its npm launcher's check for a newer release is switched off only by
the environment (`OCR_NO_UPDATE=1`, which `ssai run` sets). Cline and Cursor have no such
switch in the files the gateway writes. Your administrator turns one of these back on in that tool's
client profile.

### Your key stays out of git

Because a provisioned config can hold your gateway key, both the
`./.streamscopeai/` folder and each written tool config are added to the project's `.gitignore`
automatically, so a `git add .` never commits a credential. Where the project's `.gitignore` does
not reach — a home directory that is itself a git repository, or a repository nested in the project
(a submodule) — a file the CLI writes your key or sign-in tokens into (and the CLI's own files in
its settings folder) is instead added to that repository's `.git/info/exclude`, which only your
clone reads, and the CLI says so. A file git already tracks (a team's committed
`.claude/settings.json`) cannot be ignored either way, so the CLI refuses to write your key into it
and names the file; it refuses as well when a rule in that repository's `.gitignore` brings the file
back (git reads it over `.git/info/exclude`), or when a git repository is above the file but git
cannot answer for it (git not installed, a broken repository) — before signing in or asking for a key
when it is its own settings folder. Keep that file out of git, or provision the tool in the other scope.
A tracked file your clone marks `skip-worktree` or `assume-unchanged` (`git update-index`) is
refused too — git does not promise that either mark keeps a change out of a commit — and the CLI says
so; keep an ignored copy of a committed template instead. `ssai restore` checks the same way each
file it puts back holding a gateway key, before it puts anything back. When you run
`sync`, `status`, `forget`, or `restore` from inside a provisioned project they act on **that
project**; run from anywhere else they act on your global setup.

### Model slots and provider names

Clients with more than one model setting get the gateway's **default**, **fast** and **plan**
models — each the default model unless your administrator fills that client slot on a route
([Admin Guide § 2](ADMIN_GUIDE.md#2-providers--llm-gateway-page), *Client slots*):

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

### Per-client notes

What is particular to each tool, with where it is explained. Every tool not listed here needs nothing
beyond `ssai provision` and `ssai run`.

| Tool | Notes |
|---|---|
| Claude Code | Globally, its MCP servers are printed as `claude mcp add-json` commands to run once; in a project they go in `./.mcp.json`, local MCP servers included, which a global provisioning does not give it ([Global or project provisioning](#global-or-project-provisioning)). Under the Windows sandbox, provision it for the project: the MCP servers in its home-directory settings are not seen there ([The Windows sandbox](#the-windows-sandbox)). |
| OpenCode | Version 2 or later. A provider rule or an agent pin in your home-directory config can take it off the gateway; `provision` and `status` name the file and the line ([OpenCode and your home-directory config](#opencode-and-your-home-directory-config)). Each `ssai run` gets a private OpenCode server; in a script, close its input (`< /dev/null`); its terminal panes and its desktop app are not available in the sandbox ([OpenCode under `ssai run`](#opencode-under-ssai-run)). |
| Gemini CLI | Trust the project folder in Gemini (or pass it `--skip-trust`) so it reads the project's `.gemini/.env`. Node.js 22.21 or newer ([What each platform needs](#what-each-platform-needs)). |
| Qwen Code | Home-directory configuration only. Node.js 22.21 or newer. |
| Continue | Home-directory configuration only (its editor extension and its CLI read one file). Node.js 22.21 or newer, or the CLI stops with "MCP server(s) failed to load". Its YAML configuration keeps your settings but not your comments. |
| Codex | Home-directory configuration only. Under the Windows sandbox its own sandbox is turned off; the sandbox account confines it instead. |
| Crush | Home-directory configuration only. |
| Aider | Its YAML configuration keeps your settings but not your comments. Under the Windows sandbox it needs a git identity, global or the project's own (or `--no-git`). In the container sandbox it must already be in the image. No MCP servers. |
| Goose | Home-directory configuration only; its YAML keeps your settings but not your comments. In the container sandbox it must already be in the image. |
| Mistral Vibe | Home-directory configuration only. It stops at its first session under the Windows sandbox, and must already be in the image for the container sandbox. |
| Open Code Review | Home-directory configuration only. On Windows, keep the project outside your profile for its `review`. `ssai run` turns its update check off. |
| Zed | Export `STREAMSCOPE_API_KEY` in your shell (or set it in the Agent Panel): Zed does not read the key from its `settings.json`. No MCP servers. |
| Cursor | Configured through its own settings: `provision` prints the steps instead of writing a file. |
| Cline | Its VS Code `settings.json` is edited in place, your comments kept. |

## 5. Run an agent in the sandbox

`ssai run` confines a tool in one of two ways:

- **The native sandbox** — what `ssai run` uses by default (`--sandbox auto`, or `--sandbox native`),
  on Linux and WSL2, on macOS and on Windows. The tool runs on your machine, confined by the
  operating system: on Linux, a kernel 6.7 or newer for the network confinement; on macOS, nothing to
  install; on Windows, a one-time setup. Start here.
- **The container sandbox** — advanced sandboxing, on Linux only, used when you ask for it by name
  (`--sandbox docker`; `auto` never chooses it): the tool runs in a container built from your
  project's image, for a project whose toolchain lives in an image or that needs a Docker engine of
  its own. It needs rootless Podman ([below](#advanced-the-container-sandbox-linux)).

### What each platform needs

Check these before your first `ssai run`; each links to its detail.

**Every platform**

- The tool is provisioned first, in the project or globally ([section 4](#global-or-project-provisioning)):
  `run` only launches a provisioned tool.
- A tool that runs on Node.js (the Continue CLI, Gemini CLI, Qwen Code) needs Node.js 22.21 or newer:
  an older one does not send all of its connections through the sandbox's route to the gateway.
- What the agent reaches on the network is your workspace's setting: a registry, a git server or an
  API it needs must be allowed by your administrator ([Network sandboxing](#network-sandboxing)).

**Linux and WSL2 (native)**

- A Linux kernel 6.7 or newer, for the network confinement.
- The run's temporary folder (under `~/.cache/streamscopeai/tmp`) must be on a disk that allows
  running programs; on a `noexec` mount, set `STREAMSCOPE_TMPDIR` to a folder of your own elsewhere
  (not under `/tmp`).
- The native sandbox cannot hold the project's git hooks and configuration read-only: look at them
  before you run git outside the sandbox, or use the container sandbox
  ([What the agent cannot change in git](#what-the-agent-cannot-change-in-git)).
- With Volta, the npm configuration inside its folder is writable by a Node-based tool: keep a
  registry token in nvm's or fnm's setup instead.
- `--sandbox learn` is available here only.

**macOS (native)**

- Apple Silicon; the sandbox is the system's built-in Seatbelt, nothing to install.
- `--sandbox learn` is not available.

**Windows (native)**

- **Set up once:** `ssai sandbox setup`, with administrator rights (one UAC prompt)
  ([The Windows sandbox](#the-windows-sandbox)).
- **Sign in with your password** — at the desktop, over Remote Desktop, or over SSH with a password:
  from an SSH session signed in with a key, `run` cannot read the sandbox account's password.
- **Install programs for all users, outside your profile and outside your project folders.** The
  agent runs as the sandbox account, which reads nothing in your profile, nor in a folder made private
  to you (below), but what a run grants it: the tool's configuration folder, the folder holding the
  tool's program (and the one it links to), `ssai`'s folder, and, for a Python tool installed with uv
  or pipx, its environment and the Python it was made with — when they are in your profile or in the
  project's own private folder. A runtime or toolchain installed for you alone — a per-user Node.js
  or Python, Rust in `%USERPROFILE%\.cargo`, tools kept in a folder made private for another project —
  is out of the agent's reach. Installed for all users (under `C:\Program Files`, for example), every
  account can read and run it.
- **Where the project lives:** not a drive's root, a network share, your profile folder or a folder
  above it; on a drive that keeps access lists (not FAT or exFAT); and, outside your profile, in a
  folder private to you — `run` offers to make the folder under the drive's root private, once for
  every project in it (`--private-root`). A Go tool resolving a project inside your profile (Open Code
  Review's `review`) needs the project outside your profile.
- **When the agent cannot open a file:** `ssai sandbox doctor` says why, and `--fix` repairs it
  ([below](#when-the-agent-cannot-open-a-file)).
- **What does not run:** OpenCode's desktop app (the command-line agents do), Mistral Vibe (it stops at
  its first session), a login a tool keeps in Windows Credential Manager (it is per account), and
  `--sandbox learn`. Aider needs a git identity, global or the project's own (or `--no-git`).
- **A private certificate authority:** point the Node-based tools at its root with
  `setx NODE_EXTRA_CA_CERTS <root file>`; and when your administrator allows an internal HTTPS host,
  the hosts its certificate authority publishes revocation lists on must be allowed too.

**FreeBSD (native)**

- **Set up once per machine:** `sudo ssai sandbox setup`, which installs the service that builds each
  run's jail ([The FreeBSD sandbox](#the-freebsd-sandbox)); run it again when `run` asks, after an update.
- A kernel with `VIMAGE` (the `GENERIC` kernel has it).
- A tool published for Linux only needs FreeBSD 15.0 or newer and the Linux binary compatibility
  ([AI clients on FreeBSD](#ai-clients-on-freebsd)).
- `--sandbox learn` and the container sandbox are not available.

**Container sandbox (Linux, advanced)**

- Rootless Podman 4.4 or newer, a subordinate id range for your user, cgroup v2 with `memory` and
  `pids` (and `cpu`) delegated, and `/dev/fuse` for `"docker": true`
  ([Step 2](#step-2--set-up-rootless-podman-once-per-machine)).
- Your administrator leaves **Allow the container sandbox** on (the default).
- Goose, Aider and Vibe must already be in the image; only TCP and DNS leave the container; one run
  with a Docker engine inside per project at a time.

### Network sandboxing

Whatever the platform, a sandboxed tool has no direct way out: every connection it makes goes to a
guard that `ssai` starts for the run, which lets through the gateway — always — and what your
workspace's network setting allows, and refuses everything else. With nothing allowed, all of the
agent's traffic stays on the gateway, where it is audited and your organization's policy applies.

**The setting is your administrator's**, per workspace (the **Sandbox** section of the workspace's
**Portal & clients** profile — [Admin Guide § 9c](ADMIN_GUIDE.md#9c-portal--clients-and-destinations--governance--portal--clients--destinations)):

| Network setting | The agent reaches, besides the gateway |
|---|---|
| **Internet** | every destination a list attached as block does not name |
| **Allowed lists only** | only the destinations an attached list allows |
| **Gateway only** | nothing else |

Your CLI picks a change up on its next `ssai sync`, or on its next `ssai run` once its copy is an
hour old.

**You can narrow it, never widen it.** `ssai run --network gateway <tool>` keeps one run to the
gateway alone, in the native and the container sandbox; `"network": "gateway"` in the project's
`.streamscopeai/sandbox.json` does the same for every container-sandbox run of the project, and
`ssai run --network policy` takes the workspace's setting again (the command line wins over the file).
`--sandbox learn` keeps the network to the gateway alone, whatever the setting
([When a tool needs a folder the sandbox does not grant](#when-a-tool-needs-a-folder-the-sandbox-does-not-grant)).

**What goes through the guard.** Tools that speak plain HTTP through a proxy (apt) and
Java tools (through their proxy settings, added to your own `JAVA_TOOL_OPTIONS`) go through the same
rules; `git` over SSH does too: `ssh` takes its connection from `ssai` — unless you have an ssh
command of your own (`GIT_SSH_COMMAND`, `GIT_SSH` or git's `core.sshCommand` as the project sees it),
which is left as it is: route it yourself by adding `-o ProxyCommand="ssai __connect %h %p"` to it.
Inside the run, `ssai`'s command applies to every repository, a submodule's own `core.sshCommand`
included. An allowed name that resolves to this machine's own addresses
(loopback) is not reached through it: only an entry naming the address is. A
destination whose name does not resolve fails as unreachable, not as refused. A raw database
connection (`psql`, `redis-cli`) is not carried.

**Seeing what was refused.** When it starts, `run`
prints a one-line summary naming the active sandbox and what it confines, including how many
destinations are allowed and blocked; blocked-egress details are kept silent while the tool runs so
they don't disturb its display — pass `--verbose` to see every decision — and once the tool exits,
`run` names the destinations it refused. To get a destination the project
needs, ask your administrator to add it to an allowed list, then run `ssai sync`: the run banner names
the network setting and lists the run has.

**Per platform:**

- **Every native sandbox** — a tool that runs on Node.js needs Node.js 22.21 or newer, or some of its
  connections bypass the route to the gateway and are refused.
- **Linux and WSL2** — the network confinement needs a Linux kernel 6.7 or newer.
- **macOS** — the system's built-in Seatbelt confines the tool.
- **Windows** — every connection of the sandbox account except to this computer is blocked by a
  Windows Firewall rule; the guard, on this computer, lets it reach only the gateway and the allowed
  destinations, and serves only programs running as the sandbox account. `ssai sandbox setup --check`
  checks that rule and that the firewall is on for every network profile. A connection to one of this
  computer's own network addresses counts as local and is not blocked. Tools using Windows' own TLS
  (git, `curl.exe`, .NET) also need the hosts an internal certificate authority publishes revocation
  lists on ([The Windows sandbox](#the-windows-sandbox)).
- **FreeBSD** — the tool's jail has a network of its own; the run's guard is its only way out
  ([The FreeBSD sandbox](#the-freebsd-sandbox)).
- **Container sandbox** — the container has no network: every TCP connection made in it — the
  tool's, the Docker engine's pulls and those of the engine's own containers and builds — is taken
  to the same guard, so plain commands work without a proxy setting. Only TCP and DNS leave
  ([Container sandbox reference](#container-sandbox-reference)).

**What it does not hold:** name lookups (DNS) still resolve, a channel an agent could use to leak
data in small amounts.

### The native sandbox

`ssai run <tool>` launches a provisioned tool inside a **sandbox** so the agent can only
reach the gateway and only touch the project it's working in. Run it from the project —
for example `ssai run claude`, with any arguments for the tool placed after `--` (e.g.
`ssai run claude -- -p "summarise this repo"`); the tool starts exactly as it would
normally, in the current directory. In a project provisioned from more than one gateway, `run`
uses the one that provisioned the tool, and asks you to pick with `--host` when several did. While it runs, two things are enforced for you: **network
egress is restricted to the gateway and the destinations your administrator allows** for the
workspace ([Admin Guide § 9c](ADMIN_GUIDE.md#9c-portal--clients-and-destinations--governance--portal--clients--destinations) — every other destination, a vendor API, a paste site, an arbitrary host, is
blocked; with nothing allowed, all the agent's traffic stays on the gateway and auditable), and **filesystem access
is confined to the project** while your credentials (SSH keys, cloud tokens, GnuPG, npm, Yarn and
pnpm registry tokens, the GitHub CLI's login) are kept out of reach. The tools you installed in your home directory stay usable from inside it — anything in
`~/.local/bin` or `~/bin`, Rust (`~/.cargo/bin`, `~/.rustup`), Go (`~/go/bin`), Bun and Deno, and the
common version managers (nvm, fnm and n — each installed Node version's programs and libraries —
pyenv, pipx, rbenv, RVM), plus `/nix` and `/snap` — so an agent can run `uv`, `cargo` or `npm` as
it would unconfined. This grant is read-and-run only, for every tool. A Node-based tool (OpenCode,
Claude Code, Gemini CLI, Qwen Code, Continue, Open Code Review) may also write where a global `npm install`
does — each installed nvm or fnm version's programs, libraries and manual pages — and to the package managers'
caches, but never to npm's configuration files (`~/.npmrc`, or the global one each Node version
keeps beside its programs), where a registry token is stored. Volta is the exception: a Node-based
tool can write its whole directory, because Volta's own launchers run from all of it. On macOS the
npm configuration inside Volta is still out of reach; on Linux it is not, so use nvm or fnm there if
a registry token is kept in it. A Python-based tool (Aider, Vibe) may write to uv's and pipx's
folders and the pip cache, where a `uv tool install` or `pipx install` puts it. Every tool, whatever it
is written in, may write npm's and uv's package caches (`~/.npm`, `~/.cache/uv`) and uv's tools folder
(`~/.local/share/uv/tools`) — at those places only, not where a variable moves them, and never one
that is a link (`run` names one it leaves out) — created on a first run when npm or uv is installed,
and may read and run the Python versions uv installed (unless that folder is a link); so an `npx` or
`uvx` local MCP server, or the agent's own `npx` or `uv run`, works under any client — except an `npx`
installed by Volta, whose folder only a Node-based tool may reach. The rest of uv's folder, its
logins included, is writable by a Python-based tool only. Gemini CLI reads a project's `.gemini/.env` only in a folder you have trusted, so trust the project
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
more with `--ca-file <path>` or pass extra environment with `-e KEY=VALUE`. What reaches the network, and how a refusal is reported, is in
[Network sandboxing](#network-sandboxing). A client your administrator has disabled is
refused, and so are `--sandbox off` and `--sandbox learn` when the administrator requires the
sandbox. The sandbox is **fail-closed**: if the machine can't enforce it, `run` refuses rather than
launch the tool unconfined — use `--sandbox off` to opt out deliberately. This works on Linux and
WSL2 (the network confinement needs a Linux kernel 6.7 or newer), on macOS (Apple Silicon, via
the system's built-in Seatbelt), on Windows (a dedicated sandbox account, below) and on FreeBSD
(a jail for each run, below). A tool that
runs on Node.js (the Continue CLI, Gemini CLI, Qwen Code) needs Node.js
22.21 or newer inside the sandbox: an older Node.js does not send all of its connections through the
sandbox's gateway route, and the sandbox refuses them (the Continue CLI then stops with "MCP
server(s) failed to load"). (`run` only launches a tool already provisioned, in the project or
globally.)

#### What the agent cannot change in git

The project's git hooks and configuration (`.git/hooks`, `.git/config`, a worktree's or a
submodule's links and configuration, a hooks folder `core.hooksPath` names) and its
`.streamscopeai/` folder are read-only to the agent, and `.git` (with its worktrees' and submodules'
git folders) cannot be renamed — so an agent cannot change the hooks and settings that will run
later, outside the sandbox, when you use git there. A
linked worktree's own git folder, which lives in its main repository outside the project, is
granted, so the agent can commit from the worktree. Git commands that write the repository's
configuration then fail inside the sandbox — `git push -u` (after the push itself succeeds), a new
branch that tracks a remote, `git remote add`, `git submodule add`, `git config`: run those yourself.
This holds on macOS, on Windows, on FreeBSD and in the
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

#### OpenCode under `ssai run`

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
and `status` report, as they report a default `model` one of them sets for another provider (loaded after the project
file under `run`, it replaces the project's) and an agent a Markdown file defines. A config in a subdirectory applies
only when you start OpenCode there: `provision` and `status` do not read it. `ssai run opencode` prints the same
warnings as it starts, judged from the folder you start it in, so it names that one too — as it does, for a global
provisioning, a config in a folder outside your home directory, which `provision` and `status` (judging OpenCode as
started from your home directory) do not see. Under `--sandbox docker` the container keeps a home of its own
that your machine does not read, so the run checks the OpenCode configs it loads inside the container, with the
agent's own permissions. Under the Windows sandbox the run does not check them. Outside such a project (a global provisioning), OpenCode reads your
home-directory config as usual, and `provision` and `status` report a rule there that would keep it
off the gateway. When a run fails, `run` keeps the private
server's log and names it. From a script, give `opencode run` a stdin that ends (`ssai run opencode -- run "…" < /dev/null`):
OpenCode reads a stdin that is not a terminal into its message, and waits for it to end. The OpenCode TUI, `opencode run` and its
session commands work this way; OpenCode's built-in terminal panes are not available under the
sandbox. `run` needs OpenCode 2 or later (it says so and stops if it finds an older one).

**OpenCode's desktop app is not sandboxed.** `ssai run` starts the command-line agents only. A global
provisioning reaches the desktop app too (it reads your home-directory config), so the app's
requests go through the gateway — but the app and the agent working in it run unconfined, with your
own access to your files and network. Use the OpenCode TUI under `ssai run` where the sandbox
matters.

#### Stopping a run

On Linux, anything the agent leaves running in the background — a server it started from a shell
command, for instance — is stopped when the tool exits (not with `--sandbox off`). To stop a run
from a script or another terminal, send `ssai run` SIGTERM: it passes the signal on to the
tool and cleans up after it. Ctrl-C at the terminal reaches the tool directly, as without
`ssai run`.

#### When a tool needs a folder the sandbox does not grant

If a tool fails when confined because it needs a directory the sandbox doesn't grant it (some tools
keep configuration or state in an unusual place), run it once with `--sandbox learn`. This launches
the tool with its **network egress still restricted to the gateway** but the filesystem left open,
watches which directories it actually uses, and remembers the ones under your home directory so
every later `ssai run` allows them — turning a "permission denied" into a one-command fix. It
never records your credentials, and prints exactly what it added. (Learn mode is available on Linux
and WSL2.)

#### The Windows sandbox

On Windows the agent runs as a dedicated local account of yours,
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
(`%USERPROFILE%\.claude` for Claude Code, `.codex` for Codex, `.gemini` for Gemini CLI, `.qwen` for
Qwen Code, `.config\opencode` for OpenCode (in a project provisioned for it, the project's own
`.opencode`), `.config\crush` for Crush, `.continue` for the Continue
CLI, `.vibe` for Mistral Vibe, `.opencodereview` for Open Code Review, `.aider` for Aider,
`%APPDATA%\Block\goose` for Goose; or the one you name with `--env CLAUDE_CONFIG_DIR=…`,
`CODEX_HOME=…`, `GEMINI_CLI_HOME=…` — the folder holding `.gemini` — `QWEN_HOME=…`,
`OPENCODE_CONFIG_DIR=…`, `CRUSH_GLOBAL_CONFIG=…`,
`CONTINUE_GLOBAL_DIR=…`, `VIBE_HOME=…` or `GOOSE_PATH_ROOT=…`; Open Code Review and Aider read
only the home folder, so they run with `USERPROFILE` set to your profile, of which only their own
folder is granted; the agent reads and writes all of that folder, the tool's own sign-ins and history in it included —
Claude Code keeps its user-scope settings there too, so an MCP server added with
`claude mcp add --scope user` outside the sandbox — the gateway's own included — is not seen in it;
provision Claude Code for the project instead, which writes the gateway's servers into the project), read-and-run on the folders of `ssai` and of the tool (for a Python tool installed with uv or
pipx, also its environment and the Python it was made with), and read on the gateway's
certificate files — each of those inside your profile (elsewhere every account may read them
already) — and read, never write, on each file `provision` wrote for the tool (its configuration,
which holds its gateway key and is otherwise readable by you alone), inside your profile or the
project, and read on a file an `--env` value names — and keeps the git and `.streamscopeai\` holds described above. Git, which refuses a
repository another account owns, trusts the project for the run without a change to your git
configuration (and, with Git for Windows 2.46 or later, every repository in it — a submodule's
checkout); Claude Code starts past its first-run screen. The grants stay between runs (granting a large project again each time would cost seconds), so
while one project runs, the sandbox account can also write every project it was granted before:
`ssai sandbox status` lists them (with `-v`, every other path whose access each grant changed: the
folders above it, the tool's, the holds on its git folder), `ssai sandbox revoke [<folder>]` takes one project's back, and
`--all` every one (revoking a project that holds another granted project inside it takes that
folder's entries back too; the inner project's next run grants them again). An item in the project
the grant does not reach — one that inherits nothing, or one whose access was set before the grant —
is named on the first run (see [When the agent cannot open a file](#when-the-agent-cannot-open-a-file)).
Granting a project takes a moment the first time, as every file in it is given the account's access
(a line counts the files as it goes); the folders above a grant are opened for the account alone, so
your profile's other files are never touched. `run` refuses a drive's root, a network share (the
sandbox's account cannot reach one), your profile folder and any folder above it.

A project outside your profile must sit in a folder that is private to you, as your profile is: a
folder made directly on a drive lets every account on the computer write it (and read it), the
sandbox's account included, whatever it is granted. So the folder directly under the drive's root
that holds the project (`C:\Projects` for `C:\Projects\team\app`) is made private to you, once,
for every project in it. That folder is meant to hold only your project data — any name will do; a
short path such as `C:\Projects` also spares the tools long paths and spaces — and is made private as
a whole, so keep there nothing other accounts use (a toolchain, a shared folder): `run` explains this, lists what it will change and asks (it stops instead when nobody
can be asked), and `--private-root` makes it so without asking. The folder then stops inheriting
from the drive: you keep full control, SYSTEM and the administrators keep their access, and the
groups every account belongs to (Everyone, Authenticated Users, Users and the like) are removed from
it, reading included, as is a CREATOR OWNER entry (which would give whoever creates a file there —
the agent too — full control of it); the owner of each file is not changed. A folder or file in it
that gives every account access by an entry of its own loses that entry too. A folder whose access
list already names none of these is private as it is, and nothing is asked. A folder or file in it that inherited
nothing inherits again, keeping its own entries but those of every account — except each project's
`.streamscopeai` folder and the configuration files `ssai` provisioned, which hold your key and stay
yours alone. A folder of the system or of every account (`C:\Users`, `C:\ProgramData`, `C:\Program
Files`) is never made private: there the project folder alone is. A change stopped part-way is asked
for again on the next run. For a linked worktree, the main repository's folder is checked the same
way. A drive that keeps no access lists (FAT, exFAT) cannot hold a sandboxed project. Revoke leaves
the folder private; the run that changes it names the command that makes it inherit again
(`icacls "<folder>" /inheritance:e`). A project folder that every account may still write — by an
entry of its own, or, inside your profile, one it inherits from a folder above — is made private on
its own the same way, after asking, and so is the project folder where you may not change who may
open the folder above it (one an administrator made). A project folder an earlier `ssai` made private on its own
(every account still reading it) keeps running as it did, with a warning that the agent can change
who may open the files it creates there; `ssai sandbox doctor` reports it, and `--fix` makes its
folder private as above. A folder above the project that
every account may write by an entry of its own is named on each run and never changed. Files the
agent creates in the
project are given back to you when a run ends with no other run of yours still going (otherwise
by the next one that does), so you remain their owner. The tool runs with the
account's own profile and temporary folder: its history and caches stay there, apart from yours,
except for the configuration folder above. Codex's own sandbox is turned off inside it (it cannot
run under another account; the sandbox account confines Codex instead). Every process of the run
ends with it, and whatever the agent scheduled to run later as the account, or left running outside
the run, is removed when the run ends and before the next one starts — while you have another
sandboxed run open, this waits until the last one ends, so one run never stops another. The
Windows sandbox runs the command-line agents — Claude Code, Codex, Gemini CLI, Qwen Code, OpenCode,
Crush, the Continue CLI, Goose, Aider and Open Code Review, with their terminal interfaces — not
OpenCode's desktop app. The agent's own global git configuration holds the `user.name` and
`user.email` your global configuration gives you in the project (an `includeIf` for its folder
included), so its commits carry your identity — a repository's own wherever one sets it, as on your
computer — not the sandbox account's. Only those two values are carried, resolved once for the run
(a nested repository that an `includeIf` would give another identity gets the project's), and the agent's
`git config --global` cannot change that configuration. Aider writes an identity into the
project when git has none, which the sandbox refuses: set one, globally or in the project (or run
Aider with `--no-git`). Mistral Vibe changes the access settings of the folders it creates, which the
sandbox never allows, so it stops at its first session. A Go tool resolving a project inside your
profile (Open Code Review's `review`) needs to list your profile folder, which the sandbox account
cannot: keep such a project outside your profile. Aider and Open Code Review's `USERPROFILE` reaches every program the agent starts: one
reading its home (`gh`, git's global settings) looks in your profile, which it may not read, rather
than in the sandbox account's.

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

#### When the agent cannot open a file

The sandbox's account reaches a file in the project through what the project grants and the file
inherits. A file that inherits nothing — copied in with an access list of its own (a backup restore,
`robocopy /SEC`, an archive that keeps them), or locked by a tool — is out of its reach, and so is a
file moved into the project after the grant, which keeps the access list of the folder it came from
(a download moved in, a file a package manager links from its cache). `ssai sandbox doctor` finds
them, in the project of the current folder (the one `run` confines to), in a named one, or in every
granted one with `--all`:

```
ssai sandbox doctor                 # report only; exits 1 when it finds a problem
ssai sandbox doctor --fix           # repair what it found, after listing it and asking
ssai sandbox doctor --fix --yes     # repair without asking (read the report first)
```

It checks the sandbox account on this computer (`ssai sandbox setup` repairs it), and in each
project: that a project outside your profile sits in a folder private to you, that the project is
granted, the folders and files that inherit nothing, the items missing the account's access though
they inherit, and those giving every account access (or whoever creates a file there full control)
by an entry of their own. `--fix` makes the folder private (as `run` does, above), turns inheritance
back on for each item that has none — keeping its own entries but those of every account — and
applies the project's access again to everything below, which reaches the files moved in. Before
making a folder private it lists every item in it that inherits nothing, which it changes too. It
never changes the own access lists of a `.streamscopeai` folder or of the configuration files `ssai`
provisioned, which hold your key, nor those of a project whose record cannot be read (named in the
report). A long check or repair
shows the count of files as it goes; a file whose access list you may not change is named after
the repair.

#### The FreeBSD sandbox

On FreeBSD each `ssai run` puts the tool in a **jail** of its own, built when the run starts and
removed when it ends — or when `ssai` is killed. A service running as root builds it: set it up once
per machine with `sudo ssai sandbox setup` (it installs the service, enables it at boot and starts
it); `ssai sandbox setup --check` only checks it, and `sudo ssai sandbox uninstall` removes it.
After `ssai update`, a run may ask you to run `sudo ssai sandbox setup` again, when the new `ssai`
needs a newer service. `ssai sandbox revoke` has nothing to do on FreeBSD: no project stays granted.

The project must be yours, not under a system folder (`/usr`, `/etc`, … — the folder holding the
homes, such as `/usr/home`, excepted) and not inside a folder the
sandbox shows read-only (`~/bin`, `~/.local/bin`): `run` refuses one the jail cannot give the agent to
write. Inside the jail the tool runs as you, so the files it writes are yours. It sees the system's programs
and libraries read-only, a temporary folder `/tmp` of its own, and of your home only what a run
grants — the project, the tool's own folders and the others listed above; no other user's home is
there. Its network is the jail's own: the only way out is the gateway route, through the run's guard.
It gets a terminal of its own, which `ssai` connects to yours; your other terminals are not
there, and Ctrl-Z does not suspend the tool. A folder or file that is a link (a `~/.claude` kept
elsewhere, a `~/.gitconfig` from a dotfiles folder) is there at both places. A tool published for Linux only runs
in the jail under the Linux binary compatibility, which the jail takes from the machine.

### Advanced: the container sandbox (Linux)

For advanced sandboxing, `ssai run --sandbox docker <tool>` runs the agent in a container
built from your project's own image instead of on your machine — for a project whose toolchain lives in
an image, or one that needs a Docker engine of its own. The container runs under rootless Podman, with
your project folder mounted in it, and has no network of its own: every connection leaves through the
same guard as the native sandbox, to the gateway and to what your workspace's network setting allows.

The container is made of two layers:

1. **Your project's image** — the one you choose: an image from a registry, or one built from the
   project's dev container. It holds your toolchain.
2. **The tool layer** — added on top by `ssai`, on your machine. It holds the tool (Claude Code,
   Codex, Gemini CLI, Qwen Code, OpenCode, Continue, Crush or Open Code Review, at its latest release),
   with a Node.js runtime of the sandbox's own, so your image needs none; and, with `"docker": true`,
   a Docker engine from the image's distribution when the image has none. Goose, Aider and Vibe must
   already be in your image.

`ssai` builds both on a project's first run and reuses them afterwards; it never rebuilds them on
its own ([When the image changes](#when-the-image-changes)).

#### Step 1 — your administrator allows it

**Allow the container sandbox** is on by default (**Governance → Portal & clients**, the **Sandbox**
section of the profile your workspace is on — see [Admin Guide § 9c](ADMIN_GUIDE.md#9c-portal--clients-and-destinations--governance--portal--clients--destinations)). The agent reaches the gateway and what that section's network setting
allows ([Network sandboxing](#network-sandboxing)). With **Allowed lists only**, a project whose agent installs packages or pulls images needs those
registries allowed (**Use the developer defaults** covers the public ones).

#### Step 2 — set up rootless Podman, once per machine

You need Podman 4.4 or newer, run as your own user (never as root), with a subordinate id range for
your user and cgroup v2 with the `memory` and `pids` controllers delegated to it (`cpu` too, for a
`cpus` limit). `"docker": true` also needs `/dev/fuse` (the `fuse` kernel module). On Ubuntu or Debian:

```sh
sudo apt install podman
podman --version                       # 4.4 or newer
grep "^$USER:" /etc/subuid /etc/subgid # a line in each file: your range is there
# none: add a range that no other line of /etc/subuid or /etc/subgid overlaps (200000-265535 here)
sudo usermod --add-subuids 200000-265535 --add-subgids 200000-265535 $USER
podman system migrate
# the controllers delegated to your session must include memory and pids (and cpu)
cat /sys/fs/cgroup/user.slice/user-$(id -u).slice/user@$(id -u).service/cgroup.controllers
# one missing: delegate them to your user's session
sudo mkdir -p /etc/systemd/system/user@.service.d
printf '[Service]\nDelegate=cpu cpuset io memory pids\n' | sudo tee /etc/systemd/system/user@.service.d/delegate.conf
sudo systemctl daemon-reload           # then log out and in again
ls -l /dev/fuse || sudo modprobe fuse  # for "docker": true
```

`run` checks each of these before it starts, and names the fix for anything still missing.

#### Step 3 — name the project's image

When your workspace's profile sets a **Default container image**, a project without a
`sandbox.json` runs in it, and `run` says so. Otherwise, or to use another image, create
`.streamscopeai/sandbox.json` in the project; it replaces the default whole. It holds named sandboxes
under `sandboxes`; `run` starts the one named `default`, which names either a registry image or the
project's dev container. A file naming another sandbox, naming one twice, or whose keys are not under
`sandboxes` is refused. With neither file nor default, the run stops and asks you for the file.

An image from a registry, with a Docker engine for the agent:

```json
{"sandboxes": {"default": {"image": "mcr.microsoft.com/devcontainers/javascript-node:22", "docker": true}}}
```

Or the project's dev container (the `.devcontainer/devcontainer.json` VS Code uses):

```json
{"sandboxes": {"default": {"devcontainer": ".devcontainer/devcontainer.json", "docker": true}}}
```

A Python project, for example, could carry a `.devcontainer/Dockerfile`:

```dockerfile
FROM mcr.microsoft.com/devcontainers/base:ubuntu-24.04
RUN apt-get update && apt-get install -y --no-install-recommends python3-venv && rm -rf /var/lib/apt/lists/*
```

and a `.devcontainer/devcontainer.json` saying how to build it and what to run in it:

```json
{
  "build": { "dockerfile": "Dockerfile" },
  "containerEnv": { "APP_ENV": "dev" },
  "postCreateCommand": "python3 -m venv .venv && .venv/bin/pip install -q flask",
  "postStartCommand": "nohup .venv/bin/python -m flask --app app run --port 5000 > dev.log 2>&1 &"
}
```

`postCreateCommand` runs on the tool's first run in the project and again when you change it (here it
installs Flask); `postStartCommand` runs before every run (here it starts the app's development server
in the background, so the agent can test it with `curl http://127.0.0.1:5000/`). A dev container with
`features` is built with the Dev Container CLI (`npm install -g @devcontainers/cli`). Every key
`sandbox.json` takes, and what the sandbox reads from a `devcontainer.json`, is in the
[reference](#container-sandbox-reference) below.

To cap what the container — and every container the agent starts inside it — may use, add `memory`
and `cpus` beside `image` or `devcontainer`:

```json
{"sandboxes": {"default": {"image": "mcr.microsoft.com/devcontainers/javascript-node:22", "docker": true, "memory": "8g", "cpus": 4}}}
```

#### Step 4 — provision and run

Provision the tool as for any other run (`ssai provision`, in the project or globally), then run it:
`ssai run --sandbox docker claude` (or `codex`, `opencode`, …). The first run pulls or builds the
image, adds the tool to it and then starts the agent; later runs start at once. `run` prints the
image, where the project sits in the container, and the gateway the agent reaches. In a script, pass
the tool's own arguments after `--` and close its input:
`ssai run --sandbox docker opencode -- run "run the tests" < /dev/null`.

#### Docker inside the container

With `"docker": true`, plain Docker commands work — no proxy flag, no build argument, no
`--network host`: `docker run`, `docker build`, `docker compose up`, Testcontainers from the project's
tests, and a `kind` cluster (give its config `featureGates: { KubeletInUserNamespace: true }`). Every
connection — the agent's, the engine's pulls, and those of the containers the engine starts — goes
through the guard and follows the network setting. One such run per project at a time: a second
stops with `another --sandbox docker run is live on this project`.

#### A dev container with docker compose

A `devcontainer.json` that names `dockerComposeFile` and `service` — the shape a project with a database or
a queue beside it uses — runs as it is:

```jsonc
// .devcontainer/devcontainer.json
{ "dockerComposeFile": "docker-compose.yml", "service": "app",
  "workspaceFolder": "/workspaces/${localWorkspaceFolderBasename}" }
```

The `service` (here `app`) is the sandbox: its `image` or `build` gives the container, built on your
machine as a `build` in `devcontainer.json` is, and the agent runs in it at the `workspaceFolder`. The other
services run in a Docker engine inside the sandbox — `"docker": true` is implied when there are any — started before the
lifecycle commands, each waited for until it runs (until it is healthy, when it has a healthcheck; one
that exits 0 is done, and one `service` waits on with `condition: service_completed_successfully` — a
migration — is waited for until it has exited 0). Their images are pulled through the
sandbox's allowed destinations, so the registry needs to be one (`registry-1.docker.io`,
`auth.docker.io`, `production.cloudfront.docker.com` and `production.cloudflare.docker.com` for Docker Hub). A service the wait finds
failed (exited with another status, unhealthy), or not ready within ten minutes of being started (pulling
and building them is not timed), stops the run before the
tool starts, naming it with its last log lines (one a restart policy keeps restarting is named, restarting, when
the ten minutes are up). The wait reads each service until it runs once: one that crashes a moment after, or a
restart loop found running, is the agent's to see. If moving a
project to compose turns its engine on, the first run asks for `ssai sandbox prepare` first. Their data (a database's
volume) is kept between runs, with the engine's cache; `ssai sandbox prune --project` removes it.

- **By name.** The agent reaches a service by its name (`redis:6379`, `http://api:8080` — the service names
  are exempt from the proxy), and its own container by the name of `service`; a service reaches the agent's
  container by that name too (`app:3000`), which needs the agent's server to listen on all
  addresses (`0.0.0.0`), not only `localhost`.
- **At `localhost`.** With `network_mode: service:db` on `service` — the dev container templates' way to
  reach their database at `localhost` — `db` runs on the sandbox's own network: the agent reaches it at
  `localhost:5432`, and another service reaches it by its name too (one that `extends` another or shares another's
  network does not). `db` may not set `networks`, `network_mode` or `links` of its own. A service may not be
  named as the gateway's host.
- **Several files.** An array of files (a project's own `docker-compose.yml` and the dev container's
  additions) is read as compose reads it: a later file adds to `service`'s settings and overrides them.

Of `service`'s settings, the sandbox applies `image` (a short name such as `python:3.12` is Docker Hub's, as
compose reads it), `build` (`context`, `dockerfile`, `target`, `args`), `user`, `environment`, `env_file`
(inside the project), `depends_on` (what it names starts first), the project's own folder in `volumes`, and
`network_mode: service:…`. Variables in them are filled from the project's `.env` file and their
defaults (`${TAG:-1}`) only, never from your environment (a `.env` value may name one above it, and a value
that comes out naming `${localEnv:…}` is refused): an
`environment` value naming a variable neither sets is left unset, said, and any other setting naming one is
refused. In `volumes`, a
folder around the project (`../..:/workspaces`) mounts only the project, at the `workspaceFolder`; a named
volume (a `node_modules` cache) is not kept; `/var/run/docker.sock` and a file or folder under `~/.ssh`,
`~/.gitconfig` or `~/.aws` are not mounted, since the sandbox hands the agent none of your credentials —
`run` names each; a variable that fills a volume's name (`${NM:-nm}:/w/node_modules`) is such a volume. Any other
folder in `volumes` — of your machine, or of the project at another path (it is in the sandbox already, under the
`workspaceFolder`) — is refused, as are `devices`, `extends`,
`secrets`, `configs`, `volumes_from`, `extra_hosts`, `dns`, `sysctls`, `ulimits`, `pid`, `ipc`,
`platform`, a `network_mode` other than `service:…`, a top-level `include`, and any key the sandbox does
not know. `command`, `entrypoint`, `ports`, `restart`, `profiles`, `cap_add`, `privileged` and the like are not applied
(the sandbox starts the tool itself, and its container already has what its engine needs), and `run`
names each. The other services' settings are compose's to apply, inside the sandbox: none of them reaches
your machine. A service that names `service` in its `depends_on`, `links` or `volumes_from`, or as
`service:…` in its `network_mode`, `pid` or `ipc` — directly or through another — is
refused, since it would start `service` inside the engine: compose itself, inside the sandbox, says what
starting the services would start, every variable and `extends` resolved, before anything starts. The
compose steps talk to the sandbox's own engine, whatever `DOCKER_HOST` or a Docker context in the agent's
environment names, and read the files' variables from the project's `.env` and their defaults (and
compose's own `COMPOSE_*` settings there). What a service writes into
the project is handed back as for any container the agent starts ([below](#container-sandbox-reference)).

#### When the image changes

A run never rebuilds the image on its own — the agent works in your project, so a changed recipe may
be the agent's doing. `run` stops and asks you to run `ssai sandbox prepare <tool>` when `sandbox.json`
names another image, when the image's recipe changed (its Dockerfile or the `devcontainer.json` keys
it is built from), and when `"docker": true` was turned on. Read the change first
(`git diff .streamscopeai .devcontainer`), then:

```sh
ssai sandbox prepare opencode   # with --host, as for run, when several gateways are provisioned
```

`prepare` rebuilds (or pulls again) the image — one named `localhost/…`, built on this machine, is
used as it is — and installs the tool's latest release: it is also how the tool is updated in the
container (an update the tool makes of itself there does not replace that install). The lifecycle
commands, `containerEnv`, `memory`, `cpus` and `network` need no `prepare`: they apply on the next run.

#### Free disk space

A run never removes an image: an image replaced by a rebuild or another reference stays until you
remove it.

```sh
ssai sandbox status                       # the native sandbox's state, then each project's image, tool layers and volumes, with sizes
ssai sandbox prune --project [<folder>]   # one project's (the project at or above the folder, the current one by default)
ssai sandbox prune                        # every image and volume the container sandbox made
```

`status` lists each project's image, tool layers and volumes with their sizes (a project whose folder
was deleted is not listed), what no project uses any more, and the total a prune frees.
`prune --project` removes that project's image when the sandbox built or pulled it and no other
project uses it, its tool layers and its volumes. An image you had before, or named yourself, always
stays.

#### Container sandbox troubleshooting

| What you see | What to do |
|---|---|
| `no space left on device` | `ssai sandbox status`, then `ssai sandbox prune` |
| `the sandbox refused egress to <host>:<port>` | the network setting does not allow it: ask your administrator, then `ssai sync` |
| the banner shows an old network setting | `ssai sync` |
| the image changed, or needs a rebuild | read the change, then `ssai sandbox prepare <tool>` |
| `another --sandbox docker run is live on this project` | end the other run |
| the tool waits forever in a script, in CI or over SSH | close its input: `< /dev/null` |
| a destination allowed by name is refused to one tool | the tool ignores the container's DNS; the guard sees only the address it connects to |
| a UDP protocol other than DNS fails | only TCP and DNS leave the container |

#### Container sandbox reference

The keys of a sandbox in `.streamscopeai/sandbox.json` (`{"sandboxes": {"default": {…}}}`):

| Key | Meaning |
|---|---|
| `image` | an image reference from a registry, e.g. `"mcr.microsoft.com/devcontainers/base:ubuntu-24.04"` (a local archive or folder — `oci-archive:`, `dir:` — is refused). A dev container image's own metadata applies: its user, its variables, and its features' lifecycle commands (below) |
| `devcontainer` | instead of `image`: the path of a `devcontainer.json` inside the project (its `image`, or `build` with `dockerfile`, `context`, `target` and `args`; its `remoteUser` or `containerUser`; its `workspaceFolder`; or `dockerComposeFile` and `service`, [above](#a-dev-container-with-docker-compose). `${localWorkspaceFolder}` and `${localWorkspaceFolderBasename}` are expanded in `workspaceFolder`, the users and `build.args`, and `${containerWorkspaceFolder}` in the last two; `${localEnv:…}` is refused, since it would carry your environment into the build) |
| `docker` | `true` starts a Docker engine inside the container, its image cache kept between runs (needs `/dev/fuse`). An image without Docker Engine gets one from its distribution (Debian, Ubuntu, Alpine, Fedora) |
| `network` | `"gateway"` limits this project's container-sandbox runs to the gateway alone; `"policy"` (the default) takes the profile's network. `ssai run --network` wins over it, and narrows a native run too |
| `memory`, `cpus`, `pids` | the container's limits, e.g. `"6g"`, `3`; `pids` defaults to 16384, at least 64 |

A `devcontainer.json` that sets `runArgs`, `mounts`, `workspaceMount`, `privileged`, `capAdd`,
`securityOpt`, `build.options` or the legacy `dockerFile`/`context` is refused, since each would widen what the
container or its build reaches — and so is a `build` whose Dockerfile or context leads outside the
project, through a symlink included; the `devcontainer.json`, the compose files, `.env` and an `env_file`
are read only when they resolve inside the project, through every symlink;
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
first, then the project's own; the commands of the `devcontainer.json` another image was built from do
not, and `run` names those it leaves out. An entry of the metadata
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
`features` is built with the Dev Container CLI (`npm install -g @devcontainers/cli`), from what that build
reads alone — the image or `build`, the features and `overrideFeatureInstallOrder`, the users,
`workspaceFolder` and the features' lockfile (`devcontainer-lock.json` beside it) — so editing a lifecycle
command or a variable rebuilds nothing. Its features may not hold `${env:…}` (that CLI would read it from
your environment, even the shell's `${env:-x}`), nor name a local feature folder (only a
published feature is taken). A `workspaceFolder` on a system path of the container (`/etc`, `/run`,
`/usr` and the like) or over the agent's home is refused, and so is a workspace, or an agent home, at or
around `/opt/ssai-agent`, where the sandbox installs the tool. On the first run,
`run` adds the tool to the image (Claude Code, Codex, Gemini CLI, Qwen Code, OpenCode, Continue,
Crush and Open Code Review, at their latest release), with the Node.js runtime the tool runs on: a pinned release,
downloaded once on your machine from nodejs.org and checked against its checksum, kept apart from the image's own
`node`, which the project keeps using. With `"docker": true`, an image that has no Docker Engine also gets one, from
its own distribution's packages (the engine, `iptables`, and compose and buildx where the distribution has them); an
image with no `apt-get`, `apk` or `dnf` must bring its own. A Dev Container image that does gets it from the
`ghcr.io/devcontainers/features/docker-in-docker:2` feature (on Debian trixie images, such as
`javascript-node:22`, with `{"moby": false}`, since trixie has no Moby packages);
`docker-outside-of-docker` cannot work in the sandbox, which has no host engine to reach. Goose, Aider and Vibe must
already be in the image. Images with an engine are large: `ssai sandbox status` shows what each project
keeps, and `ssai sandbox prune` removes them. Only a project's first image is built (or pulled) by
`run` on its own. After that, when the image reference changed to one not on this machine yet, or
the image needs building again (its Dockerfile changed, or the `build` of its `devcontainer.json` —
with `features`, also what that build reads, above — or the image was removed), `run` stops and asks you to read what it would build — the agent can edit all of it, and
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
CA bundles (`--ca-file` and the gateway's) and any file or directory an `-e KEY=/path` names. When
`run` gives Node no certificate file of its own (no gateway certificate was captured — your machine
already trusts it, a corporate CA for instance — and neither `--ca-file` nor `-e NODE_EXTRA_CA_CERTS`
names one), and the image or `devcontainer.json` names none either, Node in the container also
trusts your machine's system certificate store; an image's own `NODE_EXTRA_CA_CERTS` is left as it is
(Node reads one such file). The tool's installation into the image (its `npm install`) trusts your
machine's system store beside the image's own. The other certificate variables are left to the image. Nothing
else of your machine is: not your home, your SSH keys, nor the host's Podman or Docker socket. The container has no network: everything leaves through the same guard
and the same destinations as the native sandbox, and `run` names what it refused. With `"docker": true`, nothing
needs a proxy setting: every TCP connection made in the container — the tool's, the engine's pulls, and those of
the engine's own containers and builds (`docker run`, `docker build`, compose, Testcontainers, kind) — is taken to
the guard by name, so plain commands work as they are. The proxy variables the tool is given name an address the
engine's containers reach too, so a tool that copies them into a container (kind does) still works. Limits: only TCP and DNS leave (no other UDP);
a container reaching a private address directly (one not on the engine's own networks) is not taken out; and a tool
that ignores the container's DNS (a hard-coded resolver over HTTPS, an address written in its configuration) is
decided by that address alone, so a destination allowed by name is refused to it. When the run ends, any file in the project that the container's root made
(a setuid binary included) is given back to you, with setuid cleared — by the next run, before its
tool starts, when a run was killed before it could. A file of one of the container's other users (a
database's data directory an inner container keeps in the project) keeps its owner, so the service
still owns it next time; only its setuid and setgid bits are cleared. A project of more than two
million files is swept only that far, and `run` says so. The tool's exit code is
`run`'s; SIGTERM to `ssai run` reaches the tool, and so does Ctrl-C at its terminal.

## 6. Keep your setup current

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
valid — other projects may use it — until you revoke it on the **API keys** page. `ssai update` self-updates the CLI from the gateway
(checksum-verified; on Windows the running `ssai.exe` is set aside as `ssai.old.exe` and removed the
next time `ssai` starts; on FreeBSD it refuses a build made for a newer FreeBSD release than the
machine runs, naming the release to upgrade to). When the gateway serves a newer version, `ssai provision` says so every
time and `ssai sync` once a day, naming the `ssai update` to run. Every call `ssai`
makes to the gateway names its version, its operating system and the machine's host name (its first
label), which the portal's Home uses to say which of your machines run an older `ssai`. `ssai logout`
revokes the device's access immediately — the keys already written into your tools keep working
(revoke those on the **API keys** page if needed). When `ssai` cannot read its record of what it wrote
— one an earlier version of `ssai` kept — every command stops and leaves the record as it is, except
`provision`: run `ssai provision` again for your tools (not a `--dry-run` or `--print` run) and, once
it saves, it moves the old record aside (the warning names where) and starts a fresh one recording
what this run writes. Entries the old record owned that this run does not write again stay in the
tools' files, unmanaged — remove them by hand — as does every file of a tool you do not provision
again, and the keys the old record held keep working until you revoke them on the **API keys** page.
`ssai licenses` prints the CLI's licence and the
licences of the third-party software it bundles.

### Undo a provisioning, and lost devices

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

### Command reference

Every command takes `--help`. Where you are logged in to several gateways, `--host <origin>` picks
one (on `provision`, `sync`, `status`, `forget`, `logout`, `update`, `run` and `sandbox prepare`).

| Command | What it does | Options you will reach for |
|---|---|---|
| `ssai login [<portal URL>]` | signs this machine in through the portal ([section 3](#3-log-in-from-the-terminal)) | `--device` (a code to approve from another device), `--no-browser` (print the address instead of opening it), `--device-name` (the name the approval page and the device list show; the host name by default) |
| `ssai provision` | writes your tools' configurations ([section 4](#4-provision-your-tools)) | `--local` / `--dir <path>` / `--global` (where), `--client <tool>` (which, repeatable), `--workspace` (which workspace's key, asked when you have several), `--provider` (which provider, for every tool or `<tool>=<provider>`), `--mode <tool>=byok` or `--byok` for all (your own provider credential through a `vk-` key; `--mode <tool>=gateway` for one back), `--template <tool>=<variant>`, `--mcp` / `--all-mcp` / `--no-mcp` / `--local-mcp` / `--no-local-mcp`, `--key-name`, `--key-ttl`, `--dry-run` (show, write nothing), `--print` (the configs to the terminal), `--yes`, `--verbose` |
| `ssai sync` | brings every provisioned configuration up to date ([section 6](#6-keep-your-setup-current)) | `--watch` with `--interval` (5 minutes by default), `--client` / `--skip`, `--key-ttl` for a replacement key, `--yes` |
| `ssai status` | what you are logged in to, what is provisioned, what was edited since | |
| `ssai run <tool>` | starts a provisioned tool in the sandbox ([section 5](#5-run-an-agent-in-the-sandbox)) | `--sandbox auto\|native\|docker\|learn\|off`, `--network gateway\|policy`, `--ca-file`, `-e KEY=VALUE`, `--verbose`, `--private-root` (Windows); the tool's own arguments after `--` |
| `ssai sandbox setup` · `revoke` · `uninstall` | the Windows sandbox account ([The Windows sandbox](#the-windows-sandbox)); on FreeBSD, the service that builds each run's jail, as root ([The FreeBSD sandbox](#the-freebsd-sandbox)) | `setup --check`, `revoke [<folder>]`, `revoke --all` |
| `ssai sandbox doctor` | checks what the sandbox needs on this computer and in a project, and repairs it ([When the agent cannot open a file](#when-the-agent-cannot-open-a-file)) | `[<folder>]`, `--all`, `--fix`, `--yes`, `--verbose` |
| `ssai sandbox prepare <tool>` · `status` · `prune` | the container sandbox's images ([Advanced: the container sandbox](#advanced-the-container-sandbox-linux)) | `prune --project [<folder>]` |
| `ssai forget <tool>` | stops managing a tool, leaving its files as they are | |
| `ssai restore` | puts back the files a provisioning or a sync changed | `--list`, `--run <timestamp>`, `--global`, `--yes` |
| `ssai update` | updates `ssai` from the gateway | `--yes` |
| `ssai logout` | revokes this machine's sign-in; the keys written into your tools keep working | |
| `ssai licenses` | the licences of `ssai` and of what it bundles | |

## 7. Home — your dashboard

**Home** (`/portal/home`) is where you land after signing in. Three buttons start the common tasks
(**New key**, **Set up a tool**, **Try an MCP server**). It shows your own activity, over every
workspace you use: spend and requests today (UTC) and over the last 7 days (UTC days, today
included), a bar per day for those 7 days, and your 5 latest sessions. Beside them, only what applies:

- **To do** — one line per thing waiting on you, each with the way to fix it: no key and no traffic
  yet (create one), a key that expires within 7 days or expired in the last 7 (a key created to live
  7 days or less, such as the CLI's per-run keys, is not one), the MCP servers waiting for your
  sign-in or values ([section 8](#8-connect-your-accounts-to-mcp-servers)), and each machine whose
  `ssai` CLI is older than the one the gateway serves — named by its host, with `ssai update` to copy.
  A machine is named from what its CLI reports on each call; one not seen in 30 days is not listed,
  and the line goes away on the machine's first call after the update.
- **My limits** — every limit that applies to you in the workspace picked in the header, as on the
  team pages: the organisation, the workspace pool, your member limit and your keys' budgets, each
  meter turning to the warning colour at 80 % of its cap. It shows what you have used of your own
  member limit and keys; the pool's use (everyone's spend) only when the workspace shares usage
  among its members or you manage it, and the organisation's never. Nothing set, no panel.
- **Your team** — when you manage the header's workspace: its members, and its spend today and in the
  current 30-day period against the workspace pool.

**The workspace picker** in the portal header (shown to a member of several workspaces) sets the
workspace the portal works in — keys, quickstart, the team page and, on the activity pages, the
**Me / Team** switch, which appears where that workspace shares activity with its members.

The menu groups the rest: **Activity** (Sessions, Requests — [section 10](#10-review-your-activity)),
**Set up** (Quickstart, API keys — [section 9](#9-keys-and-tools-set-up-without-the-cli)), **MCP
tools** (Sign-ins, Try a server — [section 8](#8-connect-your-accounts-to-mcp-servers)) and, for
managers, **Team** (Members & limits — [section 11](#11-run-your-team-workspace-managers)).

### The menu and the header

| Menu | Page | Section |
|---|---|---|
| — | **Home** | [7](#7-home--your-dashboard) |
| Activity | **Sessions**, **Requests** | [10](#10-review-your-activity) |
| Set up | **Quickstart** | [2](#2-install-the-ssai-cli) to [4](#4-provision-your-tools) (CLI), [9](#the-web-wizard) (Web wizard) |
| Set up | **API keys** | [9](#api-keys) |
| MCP tools | **Sign-ins**, **Try a server** | [8](#8-connect-your-accounts-to-mcp-servers) |
| Team | **Members & limits** | [11](#11-run-your-team-workspace-managers) |

The menu shows only what applies to you: **Members & limits** appears to a workspace's managers
alone, and **Sessions** or **Requests** is gone when your administrator hides that page for your
team. Every page has an address of its own, so any of them can be bookmarked. The sidebar folds to
its icons with the button holding the product's mark at its top; at its foot, unfolded, are the portal's version, a link to its
**source code** and its licence (**AGPL-3.0**).

The header carries, left to right:

- **the workspace picker** — shown when you belong to several workspaces; it sets the one the portal
  works in (above);
- **Refresh** — the portal does not refresh on its own: reload the page's figures with this button,
  or the **R** key;
- **the language** — the portal's pages in English or French, remembered in this browser;
- **your name and organization**, then **Sign out**, which ends your session in this organization
  only.

## 8. Connect your accounts to MCP servers

**Sign-ins** (`/portal/mcp/connections`) is where you connect your **own** account to the MCP servers
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

**Try a server** (`/portal/mcp/test`) lets you 
probe a virtual server before pointing an agent at it: runs
`initialize` / `tools/list` / `resources/list` / `prompts/get` against each upstream the route fans
out to and shows the merged catalog, using the same headers the gateway would (a server that needs
a value your client sends is reported as needing it, since the test has no client). For an OAuth or
per-user-values server you must have connected your account first; if your stored token has expired the test says so and points you back to reconnect —
your real agent calls are unaffected, since the gateway refreshes the token on its own.

### When an MCP client asks for access

An MCP client that signs in to the gateway by itself — rather than with a key in its configuration —
opens the portal on **Authorize MCP client** when you first connect it to one of your workspace's MCP
servers. The page names the client and the server, what the access grants — from seeing the list of
tools, running tools on your behalf, reading resources and prompts, up to full access to the server —
and the address it sends you back to. **Approve** issues the client an access token bound to that
server alone; **Deny** grants nothing. To take an approved client's access back, ask your
administrator.

## 9. Keys, and tools set up without the CLI

### API keys

**API keys** (`/portal/keys`) lists your own keys in the workspace picked in the header, with each
key's status — **Active**, the days left once it expires within 7 days, **Expired** or **Revoked** —
and, for each live key, its requests, tokens, spend and last use today, over the last 7 days or over
the last 30 (UTC days, today included).

**+ Create Key** asks for:

- a **name** (required) and the **workspace** — the key is pinned to that workspace and reaches every
  provider and MCP server it allows;
- the **key type** — **Standard (`sk-`)**, or **BYOK (`vk-`)**, for which your client supplies its own
  upstream credential through the `/fwd/{key}/` route. A BYOK key can be bound to a **BYOK provider**,
  so models the gateway does not configure pass through to it with your own credential; leave it on
  **None** for a key used only with MCP servers;
- an **expiry** — never, 30 days, 90 days, a year, or a date of your own.

The key is then shown once, with a snippet to use it. **Revoke** ends a key; it cannot be undone. A
budget on a key is set by a manager or an administrator, never on a key you mint yourself.

### The Web wizard

**Quickstart** opens on **Set up via CLI** (the `ssai` commands that configure every
installed tool at once — sections 2 to 4; under its run step, **How the sandbox works — modes and options**
opens a short reference: the run modes, what the tool can reach, keeping a container up to date,
and the other options); the **Web wizard** tab is the copy-paste alternative. In the
wizard — which works in the workspace selected in the portal header and starts over when that
changes; a configuration already on screen stays, under a notice, until you start over —
you pick your client (Claude Code, opencode, Cursor, Cline, Claude Desktop,
Continue, Aider, Gemini CLI, Codex, Mistral Vibe, Qwen Code, Goose, Zed, Open Code Review, generic curl/SDK); the wizard mints a key bound to the chosen
provider and renders a copy-paste config with the right base URL, model alias, and flags.
A tool that can speak both the OpenAI and the Anthropic protocol (OpenCode, Crush, Continue,
Cline, Aider, Open Code Review) defaults to its **OpenAI-compatible** variant, which works with every model; its
**Native Anthropic** variant is the one to pick for Claude
models — extended thinking and prompt caching then pass through unchanged. Some tools read their key from a second file of their own — a secrets file, or an environment
file the tool loads on start — and the wizard renders that file alongside the config, with the
key filled in when you copy it. Claude Code's MCP servers come as commands to run once
(`claude mcp add-json --scope user …`, in a POSIX shell — on Windows, Git Bash): Claude Code never
reads them from its `settings.json`. With a gateway key the commands hold no key — each server reads
it from `STREAMSCOPE_MCP_KEY`, which the settings file sets; a BYOK server's address carries its key. Where a tool takes its key only from a shell variable and no
file can hold it, the wizard shows the key itself instead. Either way, **that page is the one
time the key can be read**: the gateway keeps only a hash of it.

### Configure a client by hand

The snippets below are the minimal settings for common clients, for a tool the CLI and the wizard do
not cover, or an SDK of your own.

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
Your administrator maps the model names Claude Code requests (`claude-opus-4-8`, `claude-sonnet-4-6`,
…) to the models your organization offers.

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

When a request is refused, your tool receives the refusal in its own API's error format — what the
message says is described in the Admin Guide's
[What a client sees when a request is refused](ADMIN_GUIDE.md#what-a-client-sees-when-a-request-is-refused).

## 10. Review your activity

**Sessions** (`/portal/sessions`) and **Requests** (`/portal/audit`) show the console's Sessions and
Audit pages, with the same filters and details, over your own traffic — or, with **Team** on a
workspace that shares, that workspace's, where a teammate filter also appears. The default period is
the last 7 days. An administrator can hide conversations — the Sessions page and every request's
content — or the Requests page for a team; with conversations hidden, Requests lists each request's
model, tokens, cost and status, and a request does not open.

- **Requests** lists every kind of request: model calls, MCP tool calls, agent (A2A) calls and
  web searches and fetches, each expandable to its full captured content. The MCP server,
  upstream and agent filters offer only what the member's workspaces are granted.
- **A session** opens in the same conversation viewer as the console, with its linked parent
  and child sessions, the web calls a turn made, and the before/after view of a transformed
  message.
- Every field the console shows is shown, the upstream server and endpoint that answered a
  model call included.
- **Expert alerts** show as in the console — a session's alert and its note, the alert filter
  and order — on the sessions whose workspace's profile shows them (**Show expert alerts**,
  on by default); on the others none is shown, filtered or ranked. The cross-session issues an
  expert finds are console-only, since they name other people's sessions.
- The list is the console's tree: a sub-agent opens under its parent, and only a parent the
  member may see folds one — another member's session never does.

## 11. Run your team (workspace managers)

A **manager** is an elevated member of a workspace — an end-user, not an admin. Managers never
touch the admin console; everything they do happens in the self-service **Portal** (the console host's root, `/`).
The role exists so a team lead can hand out and reclaim keys for their team without an admin
having to mint every one.

**How someone becomes a manager.** An administrator sets it on the **Governance → Workspaces** page
([Admin Guide § 3](ADMIN_GUIDE.md#3-workspaces--governance--workspaces-page)): add the person to the workspace and flip their role from *member* to *manager*.
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
  monthly budget), field by field, inside the pool and member default your administrator set. A manager can't
  change **a manager's** exception — their own or a fellow manager's; that stays with an
  administrator — and a value above the workspace pool changes nothing: the pool still applies.

**What a manager cannot do** — the boundaries that keep this an end-user role, not an admin one:

- **Change membership.** Adding or removing people from the workspace, and granting/revoking the
  manager role itself, stays with the administrator.
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

### Automation accounts

A workspace manager does
not need an admin to automate their own workspace. On **Members & limits**,
under **Automation**, a manager creates an *automation account* and mints `ak-…`
keys under it. Such a key calls the **portal API scoped to that one workspace** —
acting with the manager's authority there (manage members' keys, view the
workspace's usage) and nothing else; the same key presented against another
workspace is refused. The plaintext is shown once, keys take an optional expiry
and can be revoked, and removing an automation account revokes its keys in that
workspace. Each action is recorded in the portal audit log against the automation
account and the specific key. (Admins can manage these accounts too — they appear
on the Service Accounts page like any other service account.)

## 12. CI and pipelines

Non-interactive runners skip the browser login entirely and authenticate with a **workspace
automation key** (`ak-…`, minted by a workspace manager on the **Members & limits** page) — the same
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

## 13. Troubleshooting

| What you see | What to do |
|---|---|
| *You are not a member of any workspace yet* | an administrator adds you to a workspace (or your sign-on groups do) |
| a request to a model is refused | the key's workspace may not be granted that model's provider: ask your administrator |
| an MCP server answers with the **Sign-ins** page's address | connect your account there ([section 8](#8-connect-your-accounts-to-mcp-servers)) |
| Home's **To do** names a machine with an older `ssai` | run `ssai update` on it |
| `ssai run` refuses to launch the tool | the machine cannot enforce the sandbox, and `run` never launches a tool unconfined; `--sandbox off` and `--sandbox learn` are refused when your administrator requires the sandbox ([section 5](#5-run-an-agent-in-the-sandbox)) |
| `ssai run` stops on a `noexec` mount | set `STREAMSCOPE_TMPDIR` to a folder of your own on a disk that allows running programs |
| the sandbox refused a destination | ask your administrator to allow it, then `ssai sync` |
| a tool fails confined with "permission denied" on a folder | `ssai run --sandbox learn <tool>` once (Linux and WSL2) |
| a lost or stolen machine | an administrator revokes that one device; `ssai logout` on a machine you still have |
