# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Calendar Versioning](https://calver.org/) (`YYYY.M.MICRO`).

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
