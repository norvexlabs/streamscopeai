# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Calendar Versioning](https://calver.org/) (`YYYY.M.MICRO`).

## [2026.11.35]

- **A more confined installation, on every shape.** The front that terminates TLS runs as an
  unprivileged user; provisioning, the schema check and the backup runner run with a read-only
  root and only the capabilities they need; on the VM appliance the firewall also drops traffic
  forwarded between its own interfaces, IPv6 as IPv4. The front's web server, the backup tool and
  the release scanner are updated. An existing install is moved over at its upgrade, nothing to do.
- **The installer says more about itself.** `ssai-stow --version` prints the release it carries;
  `ssai-stow describe` lists what that release offers without an install; `ssai-stow status --json`
  also lists every setting the install records.

## [2026.11.34]

- **Hide conversations or the Requests page for a team.** A Portal & clients profile gains a **Portal pages**
  tab with two switches. **Hide conversations** removes the Sessions page and all conversation content from the
  member's portal — a request's details, media and tool definitions; the Requests page, if still shown, then
  lists each request with its time, model, tokens, cost and status only, without a content search, and a
  request does not open. **Hide the Requests page** removes that list. What is hidden is withheld by the
  gateway, for scripts and automation keys too, not only left out of the page; a page a member has open gives
  way at its next refresh and comes back the same way. Each switch applies to a member only when every
  workspace they belong to has it on; a member of no workspace follows the Default. Usage figures and limits
  stay visible; with conversations hidden, Home no longer lists recent sessions.

## [2026.11.33]

- **Local MCP servers.** An MCP server that runs on the developer's own machine can now be managed like the
  others: store its command line on the MCP Gateway page's new **Local servers** tab — typed by hand, or
  prefilled from a catalog entry's package (npm and PyPI packages derive their `npx` / `uvx` command; any other
  package opens the form with the reason the command is yours to type) — grant it to workspaces, and the portal
  Quickstart and `ssai provision --local-mcp <slug>` write it into the member's client configuration (Claude
  Code in a project, Claude Desktop, Cursor, Cline, Codex, Continue, Crush, Gemini CLI, Goose, Mistral Vibe,
  OpenCode, Qwen Code; a client that cannot take one says the server was left out). A secret never goes through
  the gateway: an environment variable holds a plain value or is left for each developer to paste, and a
  variable marked secret holds no value for as long as it exists. A setup that gets only local servers needs no
  gateway key. `ssai provision` shows each whole command line before writing; `ssai sync` shows one that
  changed, and removes — whole, pasted values included — a server that was turned off, revoked or deleted;
  nothing else in the file is touched and the tool stays managed. A server's slug is fixed once it is created. The
  gateway does not see a local server's own traffic; tool rules still apply to the model's calls to its tools.
- **BREAKING** (API): a catalog document may declare packages and no remote (one with neither is refused);
  the adopt action's result carries `local_server_id`, and its `upstream_id` / `virtual_server_id` are empty for
  a package; a Quickstart or provision warning names its server by `virtual_server_id` or `local_server_id`.
  **BREAKING** (CLI): the CLI's record of what it provisioned changed shape — after updating, run `ssai
  provision` once in each place you provisioned before.
- **Changed:** `ssai provision` run again on a tool keeps the MCP servers it already has. With no MCP flag a
  tool's gateway MCP servers used to be dropped under `--yes` (and re-proposed otherwise); they are now kept,
  like its local ones, while still offered to the workspace. `--mcp` / `--all-mcp` replace the gateway servers,
  `--local-mcp` the local ones, the new `--no-local-mcp` takes the local ones out, and `--no-mcp` selects none
  of either kind. A tool also stays on the setup it was provisioned with unless `--template` names another. A
  first provision is unchanged. A tool set up for MCP servers only with none selected is left as it is, with a
  line saying so, and one tool refused by the gateway no longer stops the others from being written.

## [2026.11.32]

- **Portal & clients profiles per workspace.** **Governance → Client access** is now **Portal & clients**, a
  list of profiles: the Default, and the ones you create for a team — each an independent copy that a later
  change to the Default does not reach. Assign one on the workspace's **Access** tab and that workspace's
  members get its clients in the portal Quickstart and `ssai provision`, and its sandbox rules (required
  sandbox, container sandbox, destination lists) in `ssai run`; a member of several workspaces gets each
  workspace's own. Deleting a profile sends its workspaces back to the Default; **Set as default** promotes a
  profile as it stands, and developers follow it at their next provision, sync or run. A workspace is never
  without a profile, and the Agent and Inline AI workspaces stay on the Default. A profile's Clients tab has
  **Offer all** and **Offer none**.
- The portal Quickstart wizard works in the workspace selected in the header: it lists that workspace's
  clients and starts over when you switch. A configuration already on screen stays — its key is shown only
  once — under a notice naming both workspaces, until you start over. A workspace offered no client says so,
  and a failed load can be retried. The wizard and `ssai provision` offer only the providers and MCP servers
  the chosen workspace grants, not those of your other workspaces
  (`GET /api/v1/portal/mcp/virtual-servers` takes an optional `workspace_id`).
- **BREAKING:** reading the Quickstart's clients now names the workspace: `GET /api/v1/portal/quickstart/clients`
  and `GET /api/v1/portal/quickstart/clients/{id}` take a required `workspace_id` for a signed-in member (400
  without it, 403 for a workspace you are not a member of); an automation key answers for the workspace it is
  bound to, and one aimed at another workspace is refused with `workspace_membership_required` — on these
  reads and now also on the Quickstart render and the provision bundle, which answered
  `workspace_manager_required`. Update `ssai` (`ssai update`): an earlier `ssai provision` is refused. The Quickstart marks a
  client compatible from the selected workspace's grants alone. The error code `profile_kind_default_only` is
  gone; a profile choice a kind does not take answers `profile_choice_unsupported`.

## [2026.11.31]

- The portal Home's To do line for an MCP server waiting on you reads **Connect**, whether the server needs a
  sign-in or your own values; the API keys page no longer repeats it with its own banner.

## [2026.11.30]

- **Portal Home is your dashboard.** Today's and the last 7 days' spend and requests with a spend-per-day strip,
  your recent sessions, and beside them a **To do** card that appears only when something waits for you: an MCP
  server that needs your sign-in or values, an API key about to expire, a first key to create, and each machine
  whose `ssai` is out of date (named by its host, with the `ssai update` to run). **My limits** shows only the
  limits that are set, and nothing when none is. The start actions are a row of buttons in the header.
- **BREAKING:** the portal **Usage** page is removed: its figures are on Home, its limits under **My limits**, and
  the usage of each key (requests, tokens, spend, last used, for today or the last 7 or 30 days) on **API keys**.
  The portal Home API no longer returns `limit_warnings`; it returns the daily figures, the limits that apply and
  the out-of-date CLI hosts instead.
- `ssai` names its version, operating system and host on each call to the gateway, so the portal can tell you
  which machine to update.
- The portal **Quickstart** opens on **Set up via CLI**; the web wizard is the second tab. A banner above both
  names the MCP servers waiting for your sign-in or values.
- A missing MCP value or sign-in now says who acts and where. The console's **Test** result tells the
  administrator whether each user enters a value in **Portal → Sign-ins**, the client sends it, or the
  administrator must set it (with a button to the server's settings), and each server's card lists every header
  with who fills it and flags a required administrator value that is not set. **Portal → Sign-ins** shows each
  server's state and one button for the next step. An agent calling a server that waits for the user's value or
  sign-in is answered with the address of the portal's sign-ins page.
- The console records a notification (**MCP server cannot be called**) for an enabled MCP server every call to
  which fails — a required administrator value missing or unreadable, or an incomplete OAuth client — linking to
  the server.
- The console's **Test** button calls an MCP server with the administrator's values and lists its tools, prompts
  and resources, or names the values it waits for — a user's, the client's, or a user's sign-in.
- An MCP server keeps the values its address was finished with: the editor shows them, and changing one keeps
  the others. A catalog entry shows which servers were adopted from it, and the link survives a catalog reset.
- Quickstart and `ssai provision` say which MCP servers they left out of a tool's configuration, and why.
- Binding an upstream that reads the client's own `Authorization` to an endpoint that signs its clients in with
  OAuth is refused: such a client could never reach it.
- The portal **Sign-ins** form is prefilled with the values you entered before, except secret ones.
- A pasted `server.json` keeps the `_meta` of other vendors, in the catalog and on the adopted server.
- An MCP server's short secret (under 8 characters) is hidden in error messages only where it stands as a whole
  word, so it no longer blanks every matching letter.
- The Continue CLI runs under the native sandbox on Linux; a Node.js tool needs Node.js 22.21 or newer there.

## [2026.11.29]

- **BREAKING:** MCP servers are described the way the MCP Registry describes them, and their credentials are the
  headers they declare. A catalog entry is a `server.json` document: paste one to add your own, or view any
  entry as one. An upstream server declares the headers it expects — a value on its own, or a template such as
  `Bearer {token}` — and each value is filled by the administrator (locked, never shown to users), by each user
  in **Portal → Sign-ins** (stored encrypted per user), or by the user's MCP client on every call (never
  stored). This sets up servers such as a Jira and Confluence server that takes personal access tokens in its
  own headers: the administrator locks the addresses, each user enters their own tokens. OAuth sign-in combines
  with declared headers on one server. Adopting a catalog entry asks who fills each value, and the values of
  any variables in its address.
- **BREAKING:** the upstream modes `no_auth`, `service_account` and `byot` are gone, with the `credential`
  field. A server with no headers needs no credential; a shared bearer token is an administrator-filled
  `Authorization: Bearer {token}` header (offered as **Bearer token (shared)**); a token the client sends is a
  client-filled header. Such a header is forwarded to that server only; the client reaches it on `/mcp/<slug>`
  with its usual gateway key — except a client-sent `Authorization`, which uses `/fwd/<gateway key>/mcp/<slug>`
  (a pass-through `vk-` key reaches only an endpoint whose every server takes just that client token). Two
  servers attached to one endpoint cannot expect the same client header. The MCP admin and portal API shapes
  change accordingly.
- **BREAKING:** this release resets every organisation's MCP configuration: the catalog (it is restored from
  the shipped list, so entries you removed reappear and your own entries are gone), every upstream server,
  endpoint and route, the workspace grants of the endpoints removed, and every user's MCP sign-ins. The
  built-in Web endpoint is kept with its grants, but no longer routes to any server you attached to it. API keys,
  audit records and sessions are untouched. Rolling back across this release is refused: back up before
  upgrading, and restore that backup to go back. Until every gateway runs this release, one still on the
  previous release calls MCP servers without their declared headers.
- **Portal → Sign-ins** lists every server that needs your own account or values, and opens a form with just
  your fields; disconnecting also deletes the values you entered. **Try a server** reports a server that needs a
  value your client sends, and a server that answers with a redirect, instead of failing.
- The gateway no longer follows an MCP server's redirect to another address: a header it declares could reach a
  host nobody configured.
- Client configurations generated by the Quickstart and the CLI write every header each MCP server needs, with a
  placeholder for each value the client sends.
- The MCP catalog's built-in list is refreshed: 118 servers.

## [2026.11.28]

- The container sandbox runs a dev container's lifecycle commands and applies its environment. `onCreateCommand`,
  `updateContentCommand` and `postCreateCommand` run before each tool's first run in the project, and again when
  they, their environment or the image change; `postStartCommand` and `postAttachCommand` run before it on every run. They run as the
  tool's user in the project folder, one after another and each to its end, through the same sandbox as the tool;
  a command that fails stops the run before the tool starts. The commands of the features an image was built
  with run first, and the variables its dev container metadata sets apply, for an image named in `sandbox.json` too. `containerEnv` and `remoteEnv` apply to the commands and the tool (`${containerEnv:PATH}` reads the image's
  value); the sandbox's own variables, such as its proxy, still win.
- A dev container built from a Dockerfile is rebuilt only when what it is built from changes (the Dockerfile, and
  the `build` keys of `devcontainer.json`), no longer for an edit to another key such as a lifecycle command; one
  that uses `features` is still rebuilt for any edit.

## [2026.11.27]

- **BREAKING:** the container sandbox's `.streamscopeai/sandbox.json` holds named sandboxes:
  `{"sandboxes": {"default": {"image": "…"}}}`, with the keys of the earlier form inside a named entry.
  `ssai run --sandbox docker` starts the one named `default`; a file in the earlier form is refused naming the form to
  use, and one naming another sandbox, or one sandbox twice, is refused.

## [2026.11.26]

- The container sandbox (`ssai run --sandbox docker`) installs a tool where a rebuilt image's newer release always
  reaches it: `ssai sandbox prepare` now picks up the tool's latest release for an image whose npm installs under
  the user's home, which the sandbox keeps between runs and which used to hide every later install. The first
  run of each tool after the update installs it again; the earlier image stays until `ssai sandbox prune`,
  which also removes every agent home the container sandbox keeps.
- `ssai sandbox prepare` works for a project whose `sandbox.json` names an image built on this machine
  (`localhost/…`): it uses that image as it is, where it used to fail trying to pull it from a registry.
- A dev container that uses `features` is told that the Dev Container CLI building it pulls its `build.cacheFrom`
  from this machine's network, where it used to be told that cache is not used.

## [2026.11.25]

- Expert analysis reads a turn that reaches the console late. A gateway that could not deliver its records for a
  while delivers them with the time they happened; when that was further back than the session cooldown, analysis
  had already passed that time and never read the turn unless the session got more traffic. Analysis now reads
  sessions in the order their turns arrive. It starts over from the upgrade: a turn that arrived before it and was
  not yet analyzed is not read, and restarting a profile's analysis from a date reads the sessions active after
  that date that a turn has reached since the upgrade.

## [2026.11.24]

- **BREAKING** for an inline gateway that redirects traffic without naming the provider host: a request sent with
  the Inline AI key on the redirect path must now carry `X-Origin-Host`, and one without it is refused. A request
  naming no host used to go to the workspace's only pass-through, or the one pass-through speaking the request's
  API format, whichever provider had issued the client's key: a client's key for one provider could reach another.
  The model list on the redirect path follows the same rule.
- An analyzed request whose policy changes were not applied no longer shows them as sent. The conversation view
  showed a blocked tool removed (beside the **Would block** chip), an injected system prompt or rewritten messages,
  though the inline gateway forwarded the client's request as it was; the turn now records what the model was sent,
  and the steps still show what policy would have changed. A request the inline gateway refused records no change
  either.

## [2026.11.23]

- A server's automatic token-latency target is shown only once every gateway replica has learned its own. Each
  replica holds the limit to the target it learned itself, so while one was still learning, the QoS tab and the
  dashboard showed a target that replica did not apply, and its limit could grow past it. Until every replica has
  learned, both now say the target is still learning.

## [2026.11.22]

- **BREAKING** for an `ssai` older than this release, which cannot render the new Aider configs: `ssai update`
  first. Aider works with every model alias. Its config named a model whose alias holds a character YAML must
  quote (an Ollama tag such as `llama3.1:8b`, or the `<your-model-name>` a BYOK config leaves to fill in) as
  `openai/"llama3.1:8b"`, a model the gateway does not serve; it is now written as one value. Re-run `ssai
  provision` (or copy the Quickstart again) to rewrite an existing config. An Aider profile edited in the
  console keeps its own templates: reset it, or write its model values as `{{concat "openai/" model_alias}}`
  rather than `openai/{{model_alias}}`.
- Aider's config file is set up with `~/.aider.model.metadata.json` beside it, giving its model the gateway's
  output cap and, when known, context window, and naming its weak model: on a gateway provider it no longer warns
  of an unknown window, or tries to download a public model list, on every start — under the Linux and macOS
  sandbox (`ssai run --sandbox`), a download the egress guard refused and printed. The Quickstart's shell
  variant, which writes no file, now names the model too (`AIDER_MODEL`, `AIDER_WEAK_MODEL`). Under that sandbox
  Aider can also read its `~/.aider.model.settings.yml`.
- Aider traffic is recognised as Aider. Aider calls models through generic SDK User-Agents, so its requests were
  attributed to no app. The App Registry's Aider entry now matches the opening of Aider's system prompt in each of
  its edit modes, and of its commit-message and chat-summary calls. An Aider entry edited in the console keeps
  its own patterns: reset it to get these.

## [2026.11.21]

- Inline AI documentation: the Admin Guide now covers both ways an inline gateway hands over intercepted traffic.
  - **Redirect**, for a provider's own API: Streamscope calls the provider with the client's own key, and policy
    is applied in both directions.
  - **Analyze API**, for the AI web and desktop apps and any request the gateway does not redirect: answers are
    only observed.

  It also covers what an operator turns on to accept a redirect — the provider's pass-through, granted to the
  Inline AI workspace — and states that a redirected request naming its host reaches only the pass-through
  serving that host.

## [2026.11.20]

- The settings a Gemini message part carries beside its media — a video clip's interval, frame rate and processing
  mode, an image's or document's media resolution, a model turn's thought signature — reach a Gemini model as the
  client sent them. A request translated to another protocol names on its row the settings that protocol cannot
  carry. A Gemini system instruction's image or file reaches no other protocol, and a request translated to one
  now names it on its row. A system instruction's text marked `thought: false` is read as part of the system
  prompt — by a translation, the audit and a transform script — and a transform script that shortens a system
  prompt of several text parts to its first one now has its edit applied. A cached answer for a message's media is reused only for the same settings on the same part.
- The response cache matches a request on what the client sent: the conversation with every setting on every
  message and part — another provider's reasoning, a message's `name`, a text part's `cache_control`, an image's
  `detail` or `transformations`, a tool result's `toolset_name` — wherever it sits. Two requests the gateway read
  alike but the model would read differently were served one answer. The same conversation sent through two API
  formats is now cached separately, a question that shares its turn with a tool result is matched exactly, not by
  meaning, and a client's per-user bookkeeping (`safety_identifier`, `prompt_cache_key`) splits no shared cache.
  A Chat Completions text, image or audio part's settings beside its data now reach a Chat Completions upstream
  as the client wrote them, and a request translated to another protocol names them and a message's `name` on
  its row.
- When the gateway continues a conversation itself — answering a tool call it ran, or completing a call parked by an
  earlier request — a model on the client's own protocol receives the client's messages as an ordinary request of
  the client's would send them, followed by the gateway's turns, rather than rebuilt with what the gateway models
  of them. A Chat Completions system message in the middle of a conversation now stays where the client put it, as
  it does on every other request.
- The Tool Calls page lists each call of a turn on its own row with its own policy record when a Gemini model calls
  one tool twice without call ids, and every call policy removed is listed. A blocked or would-block banner lands on
  the call the policy read, even when its arguments were repaired first, and a Gemini call's id is recorded with its
  policy record. A call is shown with the result that names its id — calls repeating an id take its results in turn,
  and a call without an id or one policy removed shows none rather than another call's; the session view pairs them
  the same way. A link to one call from an earlier release opens its turn without expanding the call.
- A Gemini model's function call without an id — the Gemini API usually leaves it out — is given one by the gateway,
  whatever the client's protocol, streamed or not: the client returns it with the call's result, and the audit records
  the same id, so the session view and the Tool Calls page show each such call with its result. A Gemini model is
  still sent its calls back without the gateway's id. A tool-result rule's record of a Gemini function response that
  names no call is shown on that response, and its rule reads the arguments of the call it answers rather than of the
  last call of that name.

## [2026.11.19]

- The installer moves to a newer release of its deployment tool. The gateway, control plane, console and provisioning
  images move to Alpine 3.24.4, and their system zlib, as the front's and the backup runner's, is 1.4, past a critical
  decompression flaw (the console's node runtime carries a zlib of its own, built without the module the flaw is in).
  The database image, the official PostgreSQL build pinned by digest, still carries zlib 1.3.2.
- `vm create` now takes a `byo` certificate and the secret inputs (in the answers file), sending them over SSH to the
  first install, so a VM can start in `byo`. An answers file may carry the front's TLS settings in a `tls` section, and
  `install --given`, `k8s install --given` and `k8s upgrade --given` take install answers, a secret one included, from
  a file or standard input.
- A VM whose first boot took a newer release's OS while its first install waited for what `vm create` sends over SSH no
  longer falls back to the older OS at its next reboot, whose installer refused that install.

## [2026.11.18]

- **BREAKING for an inline gateway**: the analyze API's contract moves to version 2. A response half must state
  `upstream_status`, the HTTP status the upstream answered with. Version 1 is refused. A rewrite caller asking for no
  transformed body now counts as forwarding the original: a change is recorded not applied and an enforce finding is
  answered `block`.
- An analyzed answer carrying an error is recorded as an error, as on the proxied path: its status, finish and detail. A 2xx
  carrying one reached the client, so its row keeps the answer and says **Not applied**; a relayed refusal keeps none.
- A tool call an inline gateway did not stop no longer reads as blocked: it shows **Would block**, an amber card in the
  conversation, with its own filter on the tool calls page, and is counted apart from blocks on the dashboards and the tool
  inventory. A rule's activity still counts it, as a match.
- Inbound screening now reads the text documents the model reads, in a user message or a tool result: Anthropic `document`
  blocks (a user message's title and context too, and a `content` source given as a string), Responses and Chat files, and
  Gemini text blobs. An enforce edit lands in the document, which stays a document.
- Inbound screening now reads the results of tools the server ran, which a stateless client sends back and could forge:
  Responses `mcp_call`, `code_interpreter_call`, `file_search_call` and off-spec `computer_call_output` text, an MCP
  approval's reason, and Anthropic's `mcp_tool_result`, web fetch and code execution results, and a `search_result` block.
- A finding on a message with no text of its own, a document alone or a server-run result, now shows in the conversation.
- A text file's unpadded or line-wrapped `data:` URL is read as the text it encodes, and a Responses message without its optional `type`
  keeps its images and files when it sits among other items.

## [2026.11.17]

- The installer moves to a newer release of its deployment tool. The front, the backup runner and the audit scanner it
  publishes now run fixed versions of their compression libraries.

## [2026.11.16]

- `ssai-stow status` and `ps` name a service that is down, with its exit code, the signal, whether its memory limit
  killed it and that limit. On the VM appliance, the system's `/etc/resolv.conf` now lists the DNS servers, so the host
  and a service on the host's network resolve names, and the appliance journals a service going down. The installer
  moves to a newer release of its deployment tool.
- The database image moves to the official PostgreSQL 18.6 rebuild on Alpine 3.24.4, carrying the libcurl and brotli
  security fixes.

## [2026.11.15]

- `ssai provision` and `ssai status` read OpenCode's configs the way OpenCode does: your home-directory config, a
  repository's own `opencode.json` and `.opencode/opencode.json`, in OpenCode's order. They now name a file in the
  repository that denies the gateway, pins an agent elsewhere or brings the hosted provider back, say whether plain `opencode`,
  `ssai run opencode` or both are affected, and stop warning about `~/.opencode` for a project outside your home
  directory, where OpenCode does not load it.
- `ssai provision` and `ssai status` no longer say OpenCode runs an agent on the provider it is pinned to when your
  rules deny that provider: OpenCode runs it on the default model, so such a pin is not reported.

## [2026.11.14]

- OpenCode configs for the gateway's models, written by the CLI or Web Quickstart, no longer leave OpenCode's own hosted
  provider on offer: its free models appeared beside the gateway's, and a request to one never
  reached the gateway. Both the project and the home-directory form now deny it. `ssai provision`
  and `ssai status` name a home-directory rule that allows it again. Existing setups get the deny on
  their next `ssai sync` or `ssai provision`, or by pasting a new Web Quickstart config. A tenant
  that edited its OpenCode client profile keeps its version, so its admin adds the rule there.

## [2026.11.13]

- Analyzing sessions again stores an identical alert note or issue only once. One the model words
  differently is still stored, because it may be a different finding.
- Analysis start takes an optional time, so a restart can pass one session its provider refuses
  without dropping the rest of that day. The notification for a paused profile dates that session.
- An expert reading both single sessions and clusters no longer skips sessions when only one of the
  two fails: each keeps its own position, and the expert shows the older one.
- A session active while another expert's analysis was finishing a cycle could be passed unread by
  an expert that had already finished; it is now read at the next cycle.

## [2026.11.12]

- An expert analysis whose judge model can no longer be called, because it is not granted to the
  Agent workspace or its provider stopped serving it, now waits instead of skipping sessions: they
  used to be passed over for good. The Dashboard says which model it is, and analysis resumes where
  it stopped once it can be called or another model is chosen.
- The judge model and per-expert override lists offer only models the Agent workspace can call, and
  saving another one is refused. A model saved before its grant was revoked stays shown, with a
  warning.
- An expert profile can restart its analysis from a date, in its new **Analysis start** section:
  today to skip a backlog, an earlier date to analyze sessions again. It names the workspaces it
  covers.
- **BREAKING**: the per-expert **Reset** button and `POST /api/v1/admin/experts/{id}/actions/reset`
  are removed. They said they rescanned every session and rescanned none; use Analysis start.
- A save that fails says which part could not be saved, in a full sentence.

## [2026.11.11]

- An image in a type Anthropic refuses (HEIC, BMP), or a document in a user message the target cannot
  read (anything but a PDF or text, on Anthropic or Chat Completions), no longer fails the whole
  request on another protocol's model: a note takes its place and the request's audit row names it.
- A conversation ending on assistant turns holding only media the target cannot carry no longer ends
  on a note, which Anthropic would read as a prefill: those turns are left out, and the audit row still
  names the media.
- A computer-use screenshot in a Responses request is stored as a media blob in the audit like any
  other image, shows as the client's image on the conversation view, and is refused for a model that
  does not declare vision.
- A Gemini function response's media sent by file reference is held to the model's capabilities, like
  the same media sent inline, and reaches a model of another protocol as a reference where its tool
  results can carry one, or a note the audit row names where they cannot.
- A file in a Chat Completions message is stored as a media blob in the audit like a Responses file.
- A file reference that points at nothing, and a document or file sent only by its label because the
  target has no channel for it, are named on the request's audit row, as is audio the target has no
  channel for. `image/jpg` reaches Anthropic as `image/jpeg`.
- A file reference only its own store can read (a `gs://` object, a Gemini Files API resource) no
  longer fails the request on another provider: a note takes its place and the audit row names it.
- A Gemini request writing its media members in snake case, or a file reference with an empty media
  type, is held to the model's capabilities like any other.
- A Gemini client's tool calls and results that state no `id`, which is optional there, stay paired on
  a Chat Completions model, where the whole exchange used to be left out of the request.
- A file or other part a client attaches that the gateway does not model appears on the conversation
  view as an attachment, named by its kind and media type, instead of showing nothing.

## [2026.11.10]

- A video clip a Gemini client attaches is no longer sent to a model of another protocol as an
  image. A model not declared to take video refuses the request, as before; on a model of another
  protocol declared to take it, the request's audit row names the clip as not carried (in a user
  message, a note takes its place); a Gemini model receives it.
- A Gemini client's image, audio or document attachment written in URL-safe, unpadded or line-wrapped base64
  reaches a model of another protocol in the standard encoding it reads, and is stored with the
  request like any other.
- An image, audio clip or file in an earlier assistant turn that the target protocol has no place
  for is replaced by a note saying so, and named as not carried on the request's audit row, instead
  of disappearing without a trace.
- A text file whose bytes are not UTF-8 is sent as attached to a model of the client's own protocol
  and named as not carried elsewhere, whichever protocol the client speaks, instead of being turned
  into an untyped file no model accepts.

## [2026.11.9]

- A model server whose list really shrank (a router serving four models replaced by an engine
  serving one, or the server pointed at another host) can now be reconciled: the sync **Review**
  offers every model the server no longer lists for removal, however short its list (while one of
  its endpoints does not answer, an endpoint's own short list still removes nothing). Auto-sync and
  **Sync now** still refuse a list under half the server's models, and now say to review the sync
  to accept it; the review warns when it offers removals Sync now would not make. A list that names
  no model at all is never taken as the server's: it removes nothing, even in the review.
- A server with no key on your own host (a local engine) now offers **Sync now**, **Review** and its
  auto-sync switch on the LLM gateway page, like any other server whose models are discovered; a
  keyless server at its provider's own address shows its auto-sync switch, so it can be turned off.
- A deletion's preview (the impact shown before you confirm deleting a user, a provider, a server
  or a server endpoint) is recorded in the admin audit log under its own action, ending in
  `_dry_run`, instead of reading as the deletion itself.
- A text file a Gemini client attaches to its message is read as a text document — sent as text to
  a model of another protocol — instead of as an image.

## [2026.11.8]

- `ssai run` sandboxes agents on Windows: the agent runs as a dedicated local account of yours,
  which reads nothing in your profile but what a run grants it — the tool's folder, program and
  configuration, the trusted roots and any file an `--env` value names — writes only the project and the tool's own folder, and reaches only the gateway and the
  destinations your administrator allows.
  `ssai sandbox setup` creates it once (one administrator prompt) and repairs it when re-run,
  `ssai sandbox setup --check` checks it, `ssai sandbox revoke` takes a project's access back and
  `ssai sandbox uninstall` removes it. A project outside your profile is refused unless
  `--allow-outside-profile` is passed. Claude Code, Codex, Gemini CLI, OpenCode and Goose run there
  with their terminal interfaces.
- The sandbox no longer lets an agent change a project's existing git hooks or configuration, a
  worktree's or submodule's links, `.streamscopeai/`, or rename `.git`, so it cannot rewrite what
  runs when you use git outside the sandbox — on macOS, on Windows and in the container sandbox; git commands
  that write the repository's configuration (`git push -u`, `git remote add`) are refused there. On
  Linux the native sandbox cannot hold them, and `ssai run` says so when it starts.
- `ssai run` works in a git linked worktree: the agent can commit from it.
- The container sandbox now gives a tool provisioned in your home its configuration: it ran without
  it, warning that each file was not a plain file under your home.

## [2026.11.7]

- `ssai-stow audit` names the file each vulnerable package was found in, where the release's
  SBOM records it, and counts a package found in two programs as two findings.
- Each vulnerability exception a release ships past accepts its finding only in the package (and,
  where it sits in one program, the file) it was granted for: the same vulnerability anywhere else
  in the release still stops it.

## [2026.11.6]

- The TLS front and the backup runner the installer deploys are rebuilt without any fixable
  critical or high vulnerability.
- The VM appliance's OS is built on Ubuntu 26.04's current base image.
- Every image, installer and VM disk a release publishes is scanned for known vulnerabilities
  before it is published, and a fixable high or critical finding stops it, unless the fix waits
  on an upstream release and the exception is time-limited and reviewed again at every release.

## [2026.11.5]

- First public release.
