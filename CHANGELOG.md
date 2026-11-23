# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Calendar Versioning](https://calver.org/) (`YYYY.M.MICRO`).

## [2026.11.82]

### Fixed

- **Windows sandbox: the agent's commits carry your git identity.** They were authored by the sandbox
  account (`ssai-sbx-…` at the computer's name), or refused for want of one. `ssai run --sandbox native`
  now gives the agent the `user.name` and `user.email` your global git configuration gives you in the
  project as its own global configuration, so a repository that sets its own identity keeps it, as on
  your computer. That configuration is read-only to the agent: its `git config --global` fails, and
  what the sandbox account's own global configuration held no longer applies. Aider, with an identity
  in your global git configuration, no longer needs one set in the project, or `--no-git`.

## [2026.11.81]

### Added

- **`ssai sandbox doctor` (Windows) says why the agent cannot open a file, and `--fix` repairs it.**
  It checks the sandbox account on this computer and, in the project of the current folder (a named
  one, or every granted one with `--all`), that the project is granted, that a project outside your
  profile sits in a folder private to you, the folders and files that inherit nothing (copied in
  with an access list of their own, or locked by a tool), and the files moved into the project after
  the grant, which keep the access of the folder they came from. It changes nothing unless `--fix`,
  which lists what it will do and asks (`--yes` to skip the question): it turns inheritance back on
  for those items, keeping their own entries but those of every account, and applies the project's
  access again to everything below. It never changes the own access lists of the `.streamscopeai`
  folder or of the configuration files `ssai` provisioned. It exits 1 when it finds a problem. `ssai run` names what
  its first grant of a project does not reach, and points to it.
- **A long sandbox grant, check or repair on Windows shows its progress**: a line counts the files as
  it goes (a plain line every few seconds when the output is not a terminal), then says how many it
  covered.

### Changed

- **BREAKING (Windows CLI): a project outside your profile now sits in a folder private to you, made
  once for every project in it.** `ssai run` makes the folder directly under the drive's root (`C:\Projects`
  for `C:\Projects\team\app`) — meant to hold only your project data — private to you as a whole, as your
  profile is, after asking: it stops inheriting from
  the drive and no longer lets every account read or write it (nor gives whoever creates a file there
  full control of it, nor keeps an entry of its own giving every account access on an item in it), and the folders and files in it that inherited nothing inherit again. Before,
  only the project folder was made private, and every account could still read it. A program kept in
  that folder is reachable by the agent only where a run grants it (the tool's own folder, `ssai`'s);
  install shared tools for all users instead. A folder that
  already names none of those is private as it is. `--private-project` is renamed `--private-root`.
  Under a private root, the agent can no longer change who may open the files it creates. A project
  folder an earlier `ssai` made private keeps running as it did, with that warning; `ssai sandbox
  doctor` reports it and `--fix` makes its folder private the new way. A project inside your profile
  that every account may write, by its own access list or one it inherits, is made private the same
  way, after asking; so is the project folder itself where you may not change the folder above it
  (one an administrator made).
- **The Overview dashboard's attention tiles follow the period you pick.** Alerts, Blocked tools,
  Guardrail, Errors and Upstream health's refusals counted the last 24 hours whatever the period said;
  they now count the selected period like every other panel, are labelled with it, and their links
  open the list on exactly the rows they counted. **BREAKING (API):** `GET
  /api/v1/admin/analytics/cross/attention` takes the window as `days` or `start`/`end`, like the
  other dashboard reads (default one day), in place of `window_days`, and returns the window it used
  as `start`/`end`.

### Fixed

- **`ssai sandbox revoke` with no folder refused a project whose tools were provisioned globally**
  ("not inside a provisioned project"); it now takes back the project `ssai run` confines to in the
  current folder, and a project folder deleted since its grant can still be named.
- **A dashboard period of more days than a date can hold made the request fail** with a server error;
  `days` above a century is now refused as an invalid window.

## [2026.11.80]

### Changed

- **The VM appliance runs on Kairos 4.6.** A running appliance upgrades onto it as usual, and rolls
  back to the previous release whole. The system no longer merges extension images found on its
  disk over `/usr` or `/etc`: what runs is the signed OS the release carries.

### Fixed

- **An appliance with a second network interface answered IPv6 clients unreliably**: from the boot's
  first seconds that interface kept IPv6 routes of the primary's network, so a reply could leave by
  it and never arrive. The appliance's network is now only what its settings give it, from the start
  of the boot, so an appliance with IPv6 off has no IPv6 address at all: if you reach one over an
  address its router advertised, turn IPv6 on (Operator Guide, *Changing the network settings*)
  before upgrading.
- **A crafted URL could crash the service reading its origin** (RUSTSEC-2026-0592: a stack overflow on
  nested `blob:` URLs, such as one an upstream sends in a redirect); the URL library is updated.

## [2026.11.79]

### Added

- **`ssai run` confines the agent on FreeBSD.** Each run puts the tool in a jail of its own, built by
  a service set up once per machine with `sudo ssai sandbox setup` (`--check` checks it, `sudo ssai
  sandbox uninstall` removes it) and removed when the run ends or `ssai` is killed. Inside, the tool
  runs as you and sees the system read-only, a `/tmp` of its own, and of your home only the project,
  its own folders and the read-only tools the other platforms grant; its only network route is the
  gateway, through the run's guard; git's hooks and configuration and `.streamscopeai/` are
  read-only and `.git` cannot be renamed; it gets a terminal of its own. A tool published for Linux
  only runs there under the Linux binary compatibility (FreeBSD 15.0 or newer). `--sandbox off` is
  no longer needed on FreeBSD, and a workspace that requires the sandbox now accepts FreeBSD runs.

## [2026.11.78]

### Fixed

- **`install.sh` fetched from the gateway's API address now installs.** Its check of whether the
  machine trusts the gateway's certificate asked a path only the console's address answers, and
  read any error answer as an untrusted certificate, so a script fetched from the API address — or
  one answered by the pre-login rate limit — reported a trusted certificate as untrusted and stopped
  with "publishes no root CA". Only a failed connection or TLS handshake now counts. The install command the
  portal shows was affected only by the rate limit.

## [2026.11.77]

### Added

- **The `ssai` CLI for FreeBSD.** Every gateway now serves an amd64 build for FreeBSD 14.4 and newer:
  `install.sh` installs it (and, for a gateway with a private CA, adds its root to the system trust
  store through `certctl`), and `ssai update` keeps it current. Logging in, provisioning and `sync`
  work as on any system; FreeBSD has no sandbox, so `ssai run` there needs
  `--sandbox off`, and is refused where the administrator requires the sandbox.

## [2026.11.76]

### Fixed

- **A model's answer cut short is closed as truncated for a client of another protocol.** When the
  upstream closed the connection mid-answer (a server hitting its context limit), an OpenAI Chat
  Completions client of a translated model was sent no finish and no end, and a Gemini client a half-written tool call with
  empty arguments. Both now get the answer closed as truncated (`finish_reason: "length"`,
  `finishReason: MAX_TOKENS`), and a Gemini client is never sent a tool call whose arguments were
  cut off — whether the connection closed or the model hit its own token limit — it is told in its
  place, and the request's record names it as not delivered. A client of a translated model whose
  upstream closed before any of the answer is told to retry (`overloaded_error`), as an Anthropic
  client already was. The request is recorded as truncated where the model's server cut the answer.
- **An upstream error after a finished answer no longer costs the client the answer.** A model
  server that reported an error after its answer had finished made every client's SDK raise and
  discard the answer. The client now receives the whole answer and the stream's normal end; the
  request's record still shows the upstream's error. An error after an answer that itself ended in
  failure still reaches the client.
- **A model server that sends Anthropic or OpenAI Responses stream events without their event names**
  is now read correctly instead of yielding an empty answer.
- **Gemini's `CONTINUATION` finish (its token limit) reaches a client of another protocol as a
  truncated answer, and `ESCALATION` as a filtered one,** instead of an error.
- **A prompt a Gemini model blocks reaches a client of another protocol as a filtered answer** (for
  example `finish_reason: "content_filter"`) instead of an empty stream.
- **A tool of an MCP server whose name starts with `mcp-` is read as that server's** when a client
  writes it in the plain `<server>_<tool>` form (OpenCode), instead of as a tool of no server, so the
  server's tool rules apply to it.
- **`ssai run --sandbox learn` reaches the gateway alone.** A learn run leaves the filesystem open to
  record what a client needs, and is meant to keep its network to the gateway; it was given the
  workspace's full destination policy, so on a workspace allowing the Internet it reached every
  destination not blocked. Its network is now the gateway alone, as its banner says; a learn run no
  longer reads the workspace's destination lists (an entry this build cannot read no longer refuses
  it), and `--network policy` cannot widen it.

## [2026.11.75]

### Added

- **The Windows `ssai` CLI a gateway serves is signed by Norvex Labs** (Authenticode, SHA-256,
  timestamped). An organisation that deploys the published certificate (thumbprint
  `8061BA54146A8D17F22E4B5210650147C1CAB75A`) to Trusted Root and Trusted Publishers sees the
  signature as valid and can allow the CLI by publisher in App Control (WDAC) or AppLocker. Without
  it, SmartScreen and Smart App Control treat the CLI as before.

### Fixed

- **A stream that fails no longer hands the client a tool call it cannot run.** When the model's
  stream failed before its answer finished — an upstream error, or the stream idle timeout — a client
  whose protocol was translated to OpenAI Chat Completions or Gemini was still sent the tool calls
  still being assembled, a Gemini call with its arguments cut off as `{}`. It is now sent only the
  error, as Anthropic and Responses clients already were, and the request's record names each call
  that was not delivered.
- **An upstream's error reaches every client in that client's terms.** An Anthropic client of
  another vendor's model is now told when an error is a timeout, an overload, a rate limit or a
  rejected request (`timeout_error`, `overloaded_error`, `rate_limit_error`,
  `invalid_request_error`) instead of always `api_error`. An OpenAI-compatible server's error sent
  as a bare message, or without the members a client requires, now reaches an OpenAI Chat Completions
  or Gemini client of the same protocol as that protocol's error object (OpenCode refused it), and an
  OpenAI Chat Completions client whose upstream ended on its own error is sent the `[DONE]` that ends
  the stream.

## [2026.11.74]

### Fixed

- **A model that stops sending mid-answer now ends the client's stream with an error the client
  understands.** When the upstream went silent past the stream idle timeout (5 minutes by default),
  a client speaking the upstream's own protocol was sent an error in no protocol's format (OpenCode
  aborted the session on it), and one whose protocol was translated was sent nothing. Every client now
  gets a timeout error in its own protocol's format, after the text it was already sent: an Anthropic
  `timeout_error` event, the OpenAI error chunk followed by `[DONE]`, a Responses `error` event, or a
  Gemini `DEADLINE_EXCEEDED` error. An Anthropic client of a translated model gets this error instead
  of a `max_tokens` stop. A stall after the answer finished is not an error: the client gets the
  stream's end (`[DONE]`, `message_stop`), and once its usage had arrived the request is no longer
  recorded as timed out. A Gemini client of a translated model is now told when an upstream error is
  a timeout, an overload, a rate limit or a rejected request, instead of always a server error. A Chat error that arrived with usage the client had
  not asked for is no longer dropped.
- **A tool rule written for one MCP server no longer applies to a client's own tool whose name starts
  with that server's name in another case** (for example a tool `W_A` beside a server `w`).

## [2026.11.73]

### Fixed

- **A conversation whose client sends its session id on its MCP and A2A calls too is listed once.**
  Since 2026.11.62 those calls were also listed as a second, empty session beside the conversation.
  The Sessions list no longer lists that session beside its conversation, unless it carries an
  expert alert you are shown, and the conversation's page links to it (**All tool and agent calls under
  this client's session id**). A search, an **Alert** filter or a **Linked** choice still lists it
  flat. Nothing is removed. A conversation from before the upgrade folds it once it continues. A
  client that only calls MCP or A2A tools still has a session of its own, whose page now names its
  user, key and workspace instead of "--".

## [2026.11.72]

### Fixed

- **A tool-call rule written for the built-in Web server now decides the web searches and fetches
  the gateway runs for a substitution rule.** A rule on the built-in Web server's `web_search` or
  `web_fetch` — with no server filter, or one matching that server (`*` included) — now refuses or
  rewrites the same call when the model reaches it through a substituted tool (a provider's
  server-side search, or a coding client's own web tool), beside the rules on the client's tool
  name, which are read first.

## [2026.11.71]

### Added

- **Sub-agents nest under their parent in the Sessions list**, in the console and the portal. The
  list shows top-level sessions; a parent's sub-agent badge opens its sub-agents in place (up to 25,
  then a link to the session), and the parent shows when one of its sub-agents carries an expert
  alert. A continuation stays a row of its own. A search, an alert filter or a **Linked** choice
  shows the flat list, where a sub-agent's row names its parent. A sub-agent whose parent is not on the list (no longer
  kept, excluded by your filters, or one a portal member cannot see) stays a row of its own.
  The API lists sessions flat unless asked for `linked=top_level`.
- **Show expert alerts** — a Portal & clients profile's Portal pages setting. Each session's
  alerts reach its user in the portal as its own workspace's profile decides.

### Changed

- **BREAKING (portal) — members now see their sessions' expert alerts by default**: the alert and
  its note, the alert badge on a request, a sub-agent's alert on its parent, and the alert filter.
  Turn **Show expert alerts** off in a workspace's Portal & clients profile to keep them
  console-only, as before. The portal sessions API now applies `alert_level` and `sort=alerts`
  (to the alerts the member is shown) instead of ignoring them, and refuses `sort=alerts` with a
  search term, as the console's does.
- Deep pages of the Sessions list load faster.

## [2026.11.70]

### Changed

- **BREAKING (audit) — a gateway whose audit trail cannot keep up now holds new requests rather
  than dropping their records.** `AUDIT_FAIL_MODE` defaults to `closed`: a gateway producing audit
  records faster than it can store them on its own disk serves at the rate it stores them, the
  Inline AI analysis endpoint included, rather than dropping them. Set `open` (**Settings →
  Advanced**, applied when each gateway restarts) to keep serving at full speed and drop those
  records instead. An unreachable or upgrading console holds no request in either mode: the gateway
  keeps buffering its records on its own disk, up to its outbox cap.
- The limit meters in the portal and the console no longer carry a "fleet estimate" note.

## [2026.11.69]

### Changed

- **BREAKING (tool rules) — a tool rule filtered on an MCP server applies to the model's calls to
  that server's tools.** Before, a rule with an MCP server filter acted only on the MCP gateway:
  when a model called the tool through the LLM gateway the rule never blocked, rewrote or classified
  anything there, although the console's risk classification showed it matching. It now applies to
  the tool's definition, the model's call (streamed or not) and the tool's result — for a tool the
  client runs or the gateway serves, not a provider's own MCP connector. The server is a gateway
  virtual server's upstream, or, for a server the developer runs themselves (a local MCP server),
  the `<server>` of a tool the client names `mcp__<server>__<tool>` (Claude Code, Codex, Qwen Code);
  `-` and `_` match each other, as Codex writes a server's `-` as `_`. A rule you wrote with a
  server filter may therefore start acting on model traffic it ignored before. The rule sandbox now
  tests the server filter too.

## [2026.11.68]

### Changed

- **BREAKING (audit) — what a gateway does when its audit trail cannot keep up is a setting,
  `AUDIT_FAIL_MODE`.**
  Before, a gateway serving faster than it could store its audit records slowed down and grew in
  memory until it was restarted.
  - **`open` (the new default)** keeps serving and drops the records it cannot queue. Each is
    counted in `streamscope_proxy_audit_dropped_records_total`, with an error logged at most once a
    minute; a dropped request leaves no audit row.
  - **`closed`** holds each new request until the audit trail has room, so no request's record is
    lost and the gateway slows down instead.

  An unreachable console does not by itself trigger either: the gateway keeps buffering on its own
  disk. What fills the queue is a gateway producing records faster than it can store them. The
  records queued in memory per kind fall from 10,000 to 1,000 (`AUDIT_CHANNEL_CAPACITY`).

### Fixed

- **A gateway under a burst of long agent sessions no longer runs out of memory recording them.**
  Each turn of a conversation re-sends its whole history and tool list. The gateway recorded all of
  it on every turn, and held it until the audit trail had taken it in. A few hundred agents working
  without pause on long sessions could exhaust a 2 GB gateway in seconds. Three changes fix this:
  - A turn now records only the messages and tool list the audit trail does not already hold, and
    names the others. Requests carrying images, documents or audio still record their whole history.
  - An MCP call's arguments and answer are held as text while they wait to be recorded.
  - Requests no longer pile up in memory waiting, with their records, for room in the audit trail
    (see `AUDIT_FAIL_MODE` above).

  New gauges show the content the gateway knows the audit trail holds, and how often a turn's
  messages are found there.

- **One organisation can no longer crowd others out of the MCP gateway's session records.** Each
  organisation holds at most half of each record the gateway keeps of MCP client sessions, upstream
  protocol eras, client log levels and the upstream connections it opens itself. Those connections
  are now limited by the memory they take, not their number: an upstream server answering its
  handshake with large instructions takes the room of several, and one answering with more than
  64 KB is used for its request but not kept.
- **Windows sandbox: no error dialog when security software blocks the Task Scheduler.** On a
  computer whose security software stops the sandbox account from using the Task Scheduler, a run
  no longer shows an error dialog before and after it. The tasks it could not check are reported as
  a warning.
- **Windows sandbox: shared skills are readable.** Skills installed for several clients, kept once
  in `.agents\skills`, are readable by the sandboxed client.

## [2026.11.67]

### Changed

- **BREAKING (field profiles) — tool rules recognise a gateway MCP server's tools under every
  client's naming.** Each coding client shows a virtual server's tools to its model under a name of
  its own — `mcp__web__web_fetch` in Claude Code and Codex, `mcp_web_web_fetch` in Gemini CLI and
  Crush, `web_web_fetch` in OpenCode. Tool rules and field profiles now read each of these as the
  tool of the MCP upstream server behind the virtual server, the server the MCP gateway itself
  names, on the request, on the answer (streamed or not), in tool-result redaction and in the
  console's risk classification, tool inventory, field discovery and rule sandbox. Before, a call to
  the built-in Web tools missed their own field profile under every client and was caught only by a
  generic one, and OpenCode's and Gemini CLI's calls to any virtual server's tools were not
  recognised at all. A field profile scoped to an MCP server now matches by the upstream server's
  name: one keyed on a virtual server's slug instead stops matching a model's calls — rename it to
  the upstream's name. A client's own tool whose name only starts like a slug (OpenCode's
  `web_search` beside the `web` virtual server) stays the client's. A Web substitute rule rewrites
  only the client's own web tool, never a virtual server's tool, which the gateway already serves.

### Fixed

- **Codex's MCP tools reach every model.** Codex declares each MCP server's tools as a Responses
  `namespace` group. On a route to a Chat Completions, Anthropic or Gemini model the gateway dropped
  the whole group, so the model saw none of the tools; it now offers each tool to the model as
  `<namespace>__<tool>` (`mcp__web__web_fetch`) and hands the model's calls back to Codex as the
  member of its namespace, streamed or not. A Responses model is sent the group as Codex declared
  it. Tool rules and field profiles read these calls as the MCP server's tools on every route. A
  request whose namespace member would reach the model under the same name as another of its tools
  is refused with a 400.

## [2026.11.66]

### Changed

- **BREAKING (MCP) — a `completion/complete` whose `ref` names a prompt or resource the virtual
  server does not serve answers `-32602` (Invalid params)**, in every protocol revision, as the MCP
  completion specification answers an invalid prompt name. It was `-32001` for a prompt no route
  serves (and for an unknown resource on an older revision); a prompt a route filters out already
  answered `-32602`, and the two now answer alike. A resource ref names its `uri` in the error's
  `data`.
- **The installer moves to a newer Stowage.** The VM is no longer created by the installer:
  `vm create` writes the disk and the seed and prints the steps, and an OpenTofu root of your own
  creates the VM from `vm seed --json`; `vm destroy` and `vm create --create opentofu` are gone. A
  VM created that way by an earlier installer keeps running and upgrading; remove it with that
  installer's `vm destroy`, or adopt it into a root of your own. On TrueNAS, `vm truenas
  import-image`, `seed` and `stop` are documented.
- **The first start after the upgrade recreates every service once** (each container is now told
  the deploy shape it runs on). On the VM appliance the console's memory tile then shows the whole
  VM's memory.
- **A restore loads only this install's own backups** unless `--unrecorded` is given (a backup
  another VM took — a rebuild's, a restore drill's source).
- **VM disk images are published weekly** (and on request), not with every release; a release
  without disks boots the newest disk set of its channel and writes its own OS at first boot.

### Added

- **New installer options:** `--registry-login-file` and `registry-login` (a pull login per
  install), `--acme-ca` / `--acme-ca-root` (another ACME CA than Let's Encrypt), `--known-hosts-line`
  for the VM's SSH host key, `upgrade --dry-run` / `rollback --dry-run` on the VM, and on Kubernetes
  `k8s secrets export` / `k8s install --secrets` (disaster recovery across shapes).
- **The gateway's metrics show what it holds per user and per session**: the turns it keeps to
  recognise a conversation's next turn, the budget and rate counters it tracks, its MCP sessions,
  the upstream connections and notification streams behind them, and how many audit records the
  console has answered for — so a gateway's memory can be sized from what it serves before it runs
  short (Operator Guide § Monitoring — Prometheus metrics).
- **The Server Tool Substituted badge names the client's settings the gateway did not apply.**
  When the gateway runs a provider's server-side web search itself, the limits the client set on
  that tool (`max_uses`, a domain list, `user_location`, a code-execution caller, …) are listed on
  the request's badge by name only, never their values.

### Fixed

- **The audit trail keeps up with a few hundred active users.** The console merged each gateway's
  budget and rate counters one at a time; with a few hundred users that took several seconds per
  report and the gateway's audit records queued behind it without end. Counters now merge in
  batches.
- **The images carry OpenSSL's latest security fixes** (OpenSSL 3.5.9-r1 in every image the
  release ships but the database's, whose official image has no such build yet), and the console's
  Node.js its latest patch release.
- **The guardrail's record of what it already screened is held to its size in real memory.** It
  counted only part of what each entry costs, so it could grow to about three times its limit.
- **MCP — a modern client asked for input it did not declare is told what it is missing.** The
  `-32021` the gateway answers in that case now carries `data.requiredCapabilities`, listing every
  capability missing, not only the first; an upstream asking for an input kind the gateway does
  not know is answered as the upstream's failure instead.
- **Past a few thousand MCP users, the gateway no longer forgets a live MCP session or opens a new
  upstream connection on every call.** Each MCP session store holds up to 65,536 entries (was
  4,096, `MCP_SESSION_MAX_ENTRIES`), and the upstream connections the gateway opens itself, larger
  each, up to a quarter of that; a session already held is always kept current at the limit,
  where before its activity stopped being recorded and it could be dropped while in use. A new
  entry past the limit is counted in a metric and logged once per sweep rather than on every
  request. The upstream session behind a client session the gateway no longer holds is now
  released once idle, where before it was kept for the gateway's lifetime.

## [2026.11.65]

### Changed

- **BREAKING — requests per minute are limited per surface.** The workspace pool, the default
  member limit and member exceptions now each take three request rates: LLM (chat, media and
  analysis), MCP (the built-in Web tools included) and A2A. Before, one rate counted all three
  together. On upgrade every rate you had set is copied to all three surfaces, so no surface you
  capped becomes unlimited — but the three together can now reach up to three times the old
  figure; lower a surface's own field to tighten it. A refused request's 429 (and an MCP call's
  error data) names the `surface` beside the `bucket`. A script that writes a workspace's or a
  member's limits must send the new fields: a field left out of a full update is cleared, as for
  the existing ones.
- **BREAKING (MCP) — an unknown tool or prompt answers `-32602` (Invalid params)**, including a
  name a route filters out and a built-in Web tool the server does not offer (`web_search` with no
  search backend), in every protocol revision, as the MCP specification's own example does; it was
  `-32004`.
- **BREAKING (MCP) — a tool call a tool-call rule blocks now answers as a tool error** (a result with
  `isError`) naming the rule, so the model can adapt, instead of the JSON-RPC error `-32506`; the
  audit records it as blocked, as before. A blocked resource read or prompt still answers `-32506`.
- **New workspaces start with a default member limit** of 120 LLM, 300 MCP and 60 A2A requests a
  minute, so one member's runaway client cannot use up the team's pool. Existing workspaces keep
  what they have; the Agent and Inline AI workspaces take no default.
- **A workspace's default member limit no longer applies to service accounts**, in every
  workspace: a service account is held by the workspace pool, the organisation ceiling and its own
  member exception, if you give it one.
- **A new budget counts the spend already made in its window.** Setting a member, key or
  organisation budget where there was none now counts the spend the audit trail already holds for
  the current day and 30-day period, so a $50 monthly limit set after $40 of spend stops at $50
  instead of letting $90 through.
- **BREAKING — the built-in Web tools speak the interface models know.** A failed `web_search` or
  `web_fetch` call on the Web MCP server now comes back as a tool error the model can read and act
  on (a result with `isError`: a short code such as `invalid_tool_input` or `url_not_allowed`, then
  what to fix), instead of a JSON-RPC error (`-32505`, `-32506`, `-32500`, …) many clients never show
  the model. `web_fetch` reads a long page in slices: `max_length` (characters, at least 1) and
  `start_index` replace `max_bytes`, which is no longer read — a call still sending it gets the whole
  page — and a cut page says where to continue. The tools carry clearer descriptions, a title and read-only hints, and `web_search`
  returns structured results. A substitution rule's fetch tool gains the same optional paging
  arguments; a rule you edited keeps working as it is.

### Fixed

- A web search the gateway runs in place of Anthropic's own now reports a failure with one of the
  error codes Anthropic defines, instead of an internal one a strict client could not read.
- An MCP server's tool that reports a failure (`isError`), and a streamed JSON-RPC error, now
  show as errors on the request's audit entry (a tool's own failure under its own category), with
  the message bounded and stripped of credentials; both read as successes before.
- A web call with malformed arguments is audited as invalid arguments rather than as a
  configuration error.
- A web search the gateway runs for a Responses client names its query in `action.queries` as well
  as `action.query`, as the current specification defines both.
- In the CLI, a run's end always releases its hold on the sandbox's run lock, so a cleanup that
  needs the lock alone is no longer skipped when another process was starting at that instant.

## [2026.11.64]

### Added

- **Open Code Review works as a tool of another sandboxed client.** An agent run under `ssai run
  --sandbox` (OpenCode, Claude Code, …) can now run Open Code Review, for example as a skill, with
  the Open Code Review setup provisioned for the same workspace. Before, it failed with "no valid
  LLM endpoint configured". A new client-profile setting, **usable as a tool**, decides which
  clients this applies to: it is on for Open Code Review only, and turning it on lets the agents
  of the workspace's other clients read that client's key. It applies to clients provisioned
  globally; run `ssai sync` to pick it up.

### Fixed

- After a client run in a terminal under the Windows sandbox, copy and paste work again in that
  terminal: the terminal modes the client left on (mouse tracking, bracketed paste and the like)
  are switched off when the run ends.
- Leaving a client run under the Windows sandbox is faster: the cleanup of what the sandbox
  account left scheduled no longer starts PowerShell, so it takes a fraction of a second at the
  start and the end of each run instead of several seconds, and the files the agent wrote are
  handed back in parallel.

## [2026.11.63]

### Changed

- **BREAKING (API):** The conversation API no longer returns `detected_spawn_points`; a subagent's
  spawning call is named by its session link (`link.spawned_at`).

### Fixed

- Gemini CLI's built-in subagents use the model the client was set up with, instead of a Google
  model the gateway does not serve (which made them retry without pause for up to ten minutes).
  Provision Gemini CLI again to get the new settings.
- A session is titled by the user's own prompt, not by the context a client puts before or after
  it: Gemini CLI's session context, Crush's todo reminder, Qwen Code's memory catalog, Goose's
  turn context.

## [2026.11.62]

- **Each conversation an agent runs is its own session, and sessions are linked by what they
  quote.** A session is now one conversation, decided by its messages: a client that sends one
  session id for several conversations side by side (OpenCode names its parent's session from
  every subagent) gets one session per conversation, so session counts rise and each reads as the
  agent ran it; a client that keeps only the latest part of a long conversation stays one
  session, and a client's instructions or environment sent as the first message never make two
  conversations one. A new conversation is linked to a recent one of the same user when its
  opening quotes it: a subagent opening with the prompt its parent's tool call gave it moments
  before is the parent's **child**, placed at that call; a conversation opening with the summary of
  an earlier answer (a compaction) **continues** it. A single line two conversations share links
  nothing, nor does a client's `X-Parent-Session-Id` header, and the instructions and reminders a
  client adds to every conversation are never read as a quote. Links are found for conversations
  up to a day apart, from the upgrade on. The MCP, web and A2A calls made under a session id still
  show in the conversations that carry it, while each was under way, and so does a media call (an
  image, an embedding, speech) made under the session id; a Responses turn chained to an earlier
  answer joins the conversation its session id is having. A session row
  counts its sub-agents, and a compacted conversation links forward to the one that continues it.
  **BREAKING (API):** on a session summary and a session's conversation, `parent_session_id`, the
  `linkage_*` fields and `child_count` are replaced by `link` (the session it is linked to, the
  kind of link, what it was read from, and a sub-agent's spawn point) and `links` (its sub-agents
  and the session that continues it).

## [2026.11.61]

- **The gateway's session tracking holds long agent sessions in a fraction of the memory, and its
  ceiling is set in megabytes.** The turns of one conversation now share the messages they have in
  common instead of each repeating every earlier one, so a gateway remembers far more sessions in
  the same memory, and turns are numbered in the order they arrive. The ceiling is a memory size,
  `SESSION_DETECTOR_MAX_MB` (by default a tenth of the gateway's memory limit), replacing the entry
  count `SESSION_DETECTOR_MAX_ENTRIES`, which is no longer read. The record saved for restarts is
  written in a new form: at the upgrade, a conversation in progress that names no session of its
  own continues as a new session, and one that does (`X-Session-Id`) numbers its next turns from 0
  again.

## [2026.11.60]

- **The gateway's session tracking uses less memory.** The record of recent turns the gateway links
  sessions with keeps each message's hash as 32 bytes rather than as text, about a third of the memory
  per hash; long coding-agent sessions, whose every turn repeats the earlier messages' hashes, gain
  the most.

## [2026.11.59]

- **Security: the console's web framework is updated** (SvelteKit 3.1.1), fixing two high-severity
  advisories (GHSA-3r8g-jcqq-3p5j, GHSA-m9j8-jcmv-hp69) that 2026.11.58 was published with.
- **`npx` and `uvx` work under the native sandbox whatever the client.** A local MCP server started
  with `uvx` under OpenCode (or with `npx` under a client not written in Node, such as Codex) failed
  on its package cache, as did an agent's own `uv run` or `npx`. Every client may now write npm's and
  uv's caches and uv's tools folder — created on a first run when npm or uv is installed — and run
  the Python versions uv installed, on Linux and macOS. uv's logins stay out of every client but the
  Python-based ones.
- **The container sandbox trusts the certificate authorities your machine trusts.** A client under
  `ssai run --sandbox docker` could not reach a gateway whose certificate your machine's system store
  already trusts (a corporate CA): the container knew only its image's public roots. Node in the
  container now also trusts your machine's system store when neither the run nor the image names a
  certificate file of its own, and the client's installation into the image trusts it too. A
  container run that waits for `ssai sandbox prepare` now names the command for the client being run
  (`ssai sandbox prepare claude`) instead of a placeholder.

## [2026.11.58]

- **A gateway serving several hundred active users no longer stops answering.** Once enough users
  were active within a week, the gateway could stop accepting requests entirely — health checks
  hung, nothing was logged and the process used no CPU — until it was restarted. A remote MCP server
  on the older SSE transport answering a request long after the gateway gave up on it could do the
  same.
- **Memory limits sized for more users.** The console's limit rises from 256 MB to 384 MB (it used
  159 MB at 500 active users), and on Kubernetes the gateway and admin API pods' from 512 MiB to 1 GiB,
  with a 512 MiB request. The Operator Guide now says what was measured: 500 active users within a
  4 GB VM's memory, and what large coding-agent turns and long sessions cost while in flight.

## [2026.11.57]

- **The tool dashboards and the audit list stay within the admin API's memory on a busy
  deployment.** The tool inventory (the dashboard, and the agent's tool review every cycle), each
  tool rule's activity on the Tool rules page, the tool-call feed and tool field discovery read the
  whole window's tool calls, or every tool list it named, at once — a client sending large file
  writes or a changing tool list could restart the admin API at its memory limit. The inventory and
  rule activity now read the window's tool calls one at a time, and the feed and field discovery
  read tool lists a few at a time. The merged request list ("All" kinds, console and portal) no
  longer holds the full content of every row up to the page it shows, nor does the tool-call feed
  for its MCP and web calls.

## [2026.11.56]

- **A long agent session opens without exhausting the admin API's memory.** Opening a session of a
  few hundred turns or more could grow the admin API by gigabytes until its memory limit restarted
  it — notably an OpenCode session whose subagents ran side by side, which share the root session
  and so make nearly every turn a fresh start. A session now shows each message once: a turn that
  starts afresh shows only what the session has not shown yet, and each system prompt shows once. A turn's tools load when its Request
  Parameters panel is opened, in the console and the portal alike, rather than one tool list per
  turn. **BREAKING** for API clients: a session's `turn_params[].params` no longer holds `tools`;
  each entry names its tool list by `tools_hash` with its `protocol`, and
  `GET …/audit/tool-definitions/{hash}?protocol=<protocol>` returns its `tools`.
- **A Gemini turn lists every tool it offered.** The Request Parameters panel and the tool-call
  feed showed only the first function of each Gemini tool group and none of its built-in tools
  (Google Search, code execution, …); they now list them all.

## [2026.11.55]

- **A model's refusal reaches every client.** A Chat model's refusal now reaches a Responses client as a
  refusal part and an Anthropic or Gemini client as text, where it was left out; a Responses refusal
  reaches a Chat client in the message's `refusal`, streamed or not, where it was folded into the
  content. A refusal a round the gateway runs a tool in carries on to the model's next round. A
  response script no longer rewrites a streamed Responses refusal (it never rewrote any other), and the
  response PII guardrail scans a refusal on its own, as it masks it.
- **Reasoning effort and prompt-cache options follow the serving model.** A reasoning effort of `xhigh`
  or `max` now reaches a model documented to take it as asked — on OpenAI's API, `xhigh` on GPT-5.2,
  5.2-Codex, 5.3-Codex, 5.4, 5.4 mini, 5.5 and 5.5 pro, and both on GPT-5.6, 5.6 Sol and GPT-6 Sol, Luna
  and Astra; on Claude, `xhigh` on Opus 4.7 and later, Sonnet 5 and later, Haiku 5.5 and the numbered
  Fable and Mythos models, `max` on those and on Opus 4.6, Sonnet 4.6 and Mythos Preview — and a model
  taking fewer levels gets the deepest one it does, which the audit row names; a request the gateway
  re-sends in the client's own protocol keeps its level. A thinking budget the gateway sizes from
  `xhigh` or `max` is larger than the one for `high`. `prompt_cache_options` now crosses between Chat
  Completions and Responses to OpenAI's GPT-5.6, 5.6 Sol and GPT-6 Sol, Luna and Astra. Both apply on
  OpenAI's own API; an Azure deployment is sent `high` and no cache options, as before. The effort
  `none` now also reaches GPT-5.4 and GPT-5.4 mini.
- **An image's detail crosses between Chat Completions and Responses** (`image_url.detail`,
  `input_image.detail`, `original` included), is named where Anthropic or Gemini cannot take it, and
  shows in sessions as a file's does.
- **Sessions record what the client was sent.** A streamed answer whose text a response script rewrote
  no longer records the sources the client was not sent with it. A Chat stream carrying annotations,
  which some servers send though the streaming format defines none, is no longer stored in the response
  cache, where its replay lost them, and a client of another protocol is told they were not carried. A client's
  request to compact the conversation shows as requested, apart from a compaction that happened.

## [2026.11.54]

- **An OpenAI client is answered as the Chat Completions and Responses APIs define it.** A streaming
  Chat client that did not ask for usage (`stream_options.include_usage`) is no longer sent the extra
  usage chunk, whose empty `choices` broke clients reading the first choice of every chunk; one that
  asked still gets it. The rest of a client's `stream_options` (`include_obfuscation`) now reaches the
  upstream. A negative `seed` is accepted. `temperature`, `top_p` and the penalties reach the upstream
  exactly as written on every path, never as `0.699999988`. An upstream's output limit now also caps
  `max_completion_tokens`, not only the older `max_tokens`. A Responses request that names no
  `model` or no `input` — one relying on a stored prompt or conversation — is refused with an error
  saying why, instead of a parse error.
- **Newer request settings are carried or named on a translation.** A reasoning effort of `xhigh` or
  `max` is sent to another protocol as `high`, which every reasoning model accepts, and the audit row
  now says so. A file's `detail` reaches a Responses upstream and is named where it is lost. The newest
  Responses input items (`program`, `program_output`, `compaction_trigger`) are recognised and named on
  a translation rather than read as unknown. A Responses refusal now reaches a client of another
  protocol as text instead of an empty answer.
- **Sessions and the audit show what an OpenAI answer cites, and when the model refused.** An answer's
  annotations — a Responses answer's web pages and files, streamed or not, a Chat answer's web pages —
  are recorded and shown in the **Sources** list, as are those of an answer sent back in a
  conversation's history; a response PII guardrail reads and masks their titles, a response script that
  rewrites the text drops the annotations pointing into it, and such an answer is not stored in the
  response cache. An answer that is the model's refusal is recorded with the refusal as its text (a Chat
  refusal was recorded as an empty answer) and badged **Refusal**; it is not stored in the response cache,
  and a response PII guardrail now masks it. In a conversation's history, a program the model ran and its
  output show as a tool call and its result, a compaction request as a compaction, and a file the
  detail it was sent with.
- The database image takes the current rebuild of the official PostgreSQL 18.7 Alpine 3.24 image, with
  its latest OS package updates.

## [2026.11.53]

- **An Anthropic request reaches Anthropic with every block member the Messages API defines.** Forwarded
  to an Anthropic upstream, a request lost a text block's `citations` (in a message, a tool result or
  the system prompt), a tool call's `caller` and `toolset_name`, and a tool result document's `title`,
  `context` and `citations` settings — so a conversation's web-search and document citations, and a
  programmatic tool call's link to the code that made it, were gone on the next turn. They now travel
  as sent. A translated request names each one it cannot carry on the audit row. The inbound guardrail
  screens a tool result document's name and context like a message's. Any rewrite of a text — by the
  guardrail, a script or a tool-policy redaction — drops that text's citations. A document name sent
  to Anthropic is kept within the 500 characters it accepts, and an empty one is left out, instead of
  failing the request. A notice the gateway adds to the system prompt goes beside the client's own
  blocks, which keep their cache breakpoints.
- **Sessions and the audit show what an answer cites.** A message that cites sources — an Anthropic
  answer's web-search or document citations, streamed or not, or such an answer sent back in a
  conversation's history — carries a collapsed **Sources** list with each source's title or link, where
  the quote is, and the quote; a document shows the context sent beside it. A response PII guardrail
  now reads each quoted source too, and masks it in an answer that is not streamed; a response script
  that rewrites an answer's text drops the citations quoting it. Such an answer is not stored in the response
  cache. A request translated for another
  protocol names the citations its client was not sent.

## [2026.11.52]

- **Git works in a submodule under the Windows sandbox.** A commit or any other git command inside a
  submodule's folder failed with "dubious ownership"; with Git for Windows 2.46 or later, every
  repository in the project is now trusted for the run.
- **`ssai restore` keeps a gateway key out of git.** A restored file holding a gateway key the CLI
  recorded is checked like a provisioned one: refused when git tracks it, kept out of commits when it is untracked. Refusing a
  tracked file your clone marks `skip-worktree` or `assume-unchanged` now says so — git does not promise
  that either mark keeps a change out of a commit.

## [2026.11.51]

- **On macOS, a sandboxed tool can write to `/dev/null`.** Under `ssai run`, every write to `/dev/null`,
  `/dev/zero`, `/dev/tty`, `/dev/stdout`, `/dev/stderr` or `/dev/fd/<n>` was refused, so `git commit`
  failed and every `2>/dev/null` in an agent's shell command failed the command instead of hiding its
  errors. Those devices are now writable; nothing else under `/dev` is.
- **`ssai provision` and `ssai status` read every OpenCode 2 setting that takes it off the gateway.**
  They now name an agent a Markdown file pins to another provider, a config loaded after the gateway's
  that sets the default `model` elsewhere (every agent without a model of its own runs there — a
  repository's root `opencode.json` does this under `ssai run`), and a deny in OpenCode's top-level
  `policies`. A project config kept in a folder other than `.opencode` is judged the way `ssai run`
  launches it, and `status` run from a shell inside that project's `ssai run` judges plain `opencode`
  from your own config folder. `ssai run opencode` now prints the same warnings as it starts, judged from the folder
  you start it in — so a config there that a global provisioning's `status` cannot see is named too.
  Under `--sandbox docker`, whose home your machine does not read, the run checks the OpenCode configs it
  loads inside the container, with the agent's own permissions.
- **A global OpenCode provisioning lifts a deny of every provider in OpenCode's top-level `policies`.**
  Its provider rules — the gateway's allow and the deny of OpenCode's own hosted provider — now go in
  that list as well as in `experimental.policies`, so a `deny` on `*` there no longer hides the gateway
  from plain `opencode`.

## [2026.11.50]

- **An MCP notification subscription answers for each server on its own.** When a client opens a
  `subscriptions/listen` stream, the gateway's acknowledgement answers for each route separately, so two
  routes to one server no longer vouch for each other's resources, and once a server's own stream has
  acknowledged what it agreed to deliver, later subscriptions leave out what it declined. A server's own acknowledgement no longer reaches other
  subscribers as a stray notification.
- **The CLI keeps your keys and sign-in tokens out of every git commit.** When your home directory is a
  git repository, `ssai login`, `provision` and `sync` add the CLI's own settings folder and each tool
  config they write your key into to that repository's `.git/info/exclude` (read by your clone alone)
  and say so; any command refreshing your sign-in does the same. They refuse — before signing in or
  asking for a key — when git already tracks one of those files, when a rule in that repository's
  `.gitignore` brings them back, or when a git repository is above it but git cannot answer for it (git
  not installed, a broken repository). A `--dry-run` or `--print` in a project now keeps its
  `.streamscopeai` folder git-ignored too.

## [2026.11.49]

- **A Responses client's prompt-cache breakpoints reach an Anthropic model.** A `prompt_cache_breakpoint`
  on a message part or a tool result's part is sent to an Anthropic upstream as a cache breakpoint at
  the same place, of Anthropic's default lifetime, the latest four of them; earlier ones and a lifetime
  the client stated are named on the request's translation badge. A cache breakpoint a target has no place for — any breakpoint sent
  to Chat Completions, Gemini or Responses from another protocol — is now named there too, instead of
  being left out silently. Moving a breakpoint from one turn to the next no longer splits a Responses
  session.
- **A Gemini prompt written beside an image in the same part reaches the model.** The text is sent as a
  part of its own, read by inbound screening and shown in the audit like any prompt.
- **A Gemini client's text sent with a tool's result reaches another protocol's model.** Text in the
  same turn as a function response is now sent after the result, where it came before it and an
  Anthropic or Chat Completions model refused the request.
- **A Responses turn that failed or was cancelled no longer hands its tool calls to a client of
  another protocol.** A Chat Completions, Anthropic or Gemini client receiving such a turn,
  non-streamed, gets its text and a notice in place of the calls, with a stop that claims no tool call,
  and the audit row records each call as not carried.

## [2026.11.48]

- **Inbound screening reads a Gemini conversation's tool results.** A code execution result's output and a
  built-in tool's response that a client sends back in its history are now screened like the results of
  other tools the server ran. An enforce edit replaces only that text: the code, the call and what pairs
  the result with it stay as sent.

## [2026.11.47]

- **The portal explains how the sandbox works.** Under the Quickstart's run step, a short expandable
  reference lists the run modes (the default sandbox, `--sandbox docker`, `--sandbox off`), what a run
  can reach and what to do when something is blocked, the commands that keep a container up to date,
  and the other options. The step's own line no longer says every run uses the native sandbox.
- **`ssai sandbox status` lists only projects that still exist.** A project whose folder was deleted is
  no longer listed; the images and volumes the sandbox made for it show under "Not used by a project".

## [2026.11.46]

- **The experts read text written in a framework's tag form.** A block shaped like context a client
  injects (`<system-reminder>`, a slash-command echo) is shown to the experts in a section of its own,
  each distinct block once per session, so instructions written in that form no longer go unread by
  them, in a share of what they read set aside for it.
- **A request script's message edits keep everything the script does not see.** Each message a script
  is given now carries `origin`, the message of the request it is, and is written back over that
  message: an edit keeps the message's images, its `name`, thinking blocks, the calls' signatures and
  every item around it as sent. A script that drops, adds, moves or copies messages keeps every turn
  whose messages it kept together, edited in place; a turn it split or partly dropped is rebuilt from
  what it wrote, shown as **Not applied** on the request where that lost something the script cannot
  see. A map the script builds itself is a new message. The seeded compression script now keeps the
  last user message's images. On the OpenAI Responses API, an edit is now applied, and reasoning and
  shell items are kept. On Gemini, a call the client sent without an id is never written back with one.

## [2026.11.45]

- **A default container image per Portal & clients profile.** With **Allow the container sandbox** on,
  the profile's Sandbox section sets the image `ssai run --sandbox docker` uses in a project that has no
  `.streamscopeai/sandbox.json` of its own, with its Docker engine switch and its memory and CPU limits.
  A project's own file still replaces it whole; without either, the run is refused as before. The
  sandbox adds the tool to the image itself, as for any image.
- **The container sandbox's disk use is visible and freed per project.** `ssai sandbox status` lists
  each project's image, tool layers and volumes with their sizes, what no project uses any more, and
  what a prune would free; `ssai sandbox prune --project` removes one project's — the registry image
  the sandbox pulled for it included — and `ssai sandbox prune` everything the sandbox made. An image
  you had before, or named yourself, is never removed.
- **Editing a lifecycle command no longer rebuilds a dev container image with features.** The Dev
  Container CLI now builds it from what the build reads (the image or Dockerfile, the features, their
  order and lockfile, the users), so a changed `postStartCommand`, `postCreateCommand` or variable runs at
  the next run with no `ssai sandbox prepare`, and `initializeCommand` beside features is noted instead of
  refused.

## [2026.11.44]

- **The container sandbox's Docker engine just works.** With `"docker": true`, plain `docker run`,
  `docker build`, compose, Testcontainers and kind reach what the sandbox allows, with no proxy
  setting: every connection made in the container, the engine's own containers and builds
  included, is taken to the sandbox's guard by name, and what it refuses is named after the run.
  An image without Docker Engine (such as `mcr.microsoft.com/devcontainers/javascript-node:22`) gets
  one from its own distribution instead of failing to start `dockerd`.
- **The container sandbox no longer needs Node.js in the image**: the tools it installs run on a
  pinned Node.js runtime of the sandbox's own, verified against its published checksum, which
  leaves the image's own `node` to the project.
- **The sandbox's network has three settings**, on a Portal & clients profile's Sandbox section:
  **Internet** (every destination a blocked list does not name), **Allowed lists only** (what an
  allowed list names, as before) and **Gateway only**. A new organization's Default, and a profile
  created fresh, start on **Internet** with a new seeded **Internal networks** list blocked — the
  private, shared, loopback and link-local address ranges stay out of reach; existing profiles
  keep **Allowed lists only**.
  A developer can narrow a run to the gateway alone with `ssai run --network gateway` (for the
  container sandbox also `"network": "gateway"` in the project's `sandbox.json`), and the run's
  banner names the setting.
- The database image moves to PostgreSQL 18.7 (the official Alpine 3.24 build; CloudNativePG's 18.7 image on
  Kubernetes), carrying the zlib, Kerberos and libxslt security fixes.
- **Fixed: on PostgreSQL 18.7, configuration changes could take seconds to reach the gateways** — an external
  database that had moved to 18.7 matched each model to its catalog entry by reading the organization's whole
  model catalog, once per route. The request log also finds each request's session directly now, instead of
  comparing against every session of the organization.

## [2026.11.43]

- **Fixed: a session's system prompt could be shown cut short**, in the console and the portal:
  a prompt that mentions a framework tag in its own text — Claude Code's describes its
  `<system-reminder>` blocks — ended at that mention, and the session's analysis read the same
  shortened prompt. The system prompt is now shown, and analysed, exactly as sent. Elsewhere a
  framework block is only a tag that begins a line, through its closing tag, so a message that
  mentions such a tag is shown as written. A request's detail view now shows these block cards
  too, and their names are translated in the portal. A user message starting `[SYSTEM` or
  `[SUGGESTION MODE` is shown as the message it is. A conversation in progress across the upgrade
  may continue as a new session when its messages mention such a tag, start with an unclosed one,
  or carry one inside a line.
- **BREAKING: a session conversation's `framework_reminder` event names its block with a code**
  (`system_reminder`, `deferred_tools`, `local_command`, `command`, `session_context`) instead of
  a display name ("System Reminder", …), on the console, portal and request-detail APIs.
- **Fixed: inbound PII screening missed what a user wrote after mentioning a framework tag**
  ("why does `<system-reminder>` show up? …"); the rest of the message is screened again.

## [2026.11.42]

- **BREAKING: a workspace's OIDC auto-membership pattern matches a whole group name.** `IT` now
  joins members of `IT` alone, no longer of `IT-Admins` or `SECURITY`: write `IT.*` for "starts
  with" or `.*IT.*` for "contains". A pattern anchored on one side only now matches whole too
  (`^eng-` matches `eng-` alone: write `eng-.*`), and a provider that sends several groups as one
  string no longer matches part of it. Memberships already granted are kept. A stored pattern
  that begins with an embedded option such as `(?i)` now joins nobody: rewrite it (`[Rr][Dd]` for
  `(?i)rd`). Saving a rule refuses a pattern that is not a valid regular expression, a blank
  value, and a claim name without a pattern or the reverse (a rule is cleared with `null`); the
  workspace page lists example patterns.
- **Fixed: one broken workspace OIDC rule stopped every workspace's auto-membership**, and so did
  a U+0000 anywhere in the ID token: the whole sync failed at each sign-in, silently. Each rule
  is now judged alone, on its own claim's values.

## [2026.11.41]

- **Fixed: a gateway could lose audit records while one very long agent session flooded it.** A
  session of thousands of turns made the gateway's local buffer of audit records — what it holds
  until the control plane has them — lock up for over an hour: records of every organisation on
  that gateway were lost, and the buffer grew far past its size cap. A write to the buffer now
  waits its turn instead of failing, none waits behind a whole batch or a long read, and sending
  costs only what is sent, so the buffer drains and its size cap holds.

## [2026.11.40]

- **Open Code Review is a supported client.** `ssai provision` detects `ocr` and writes its
  configuration for the gateway (OpenAI-compatible by default, Anthropic Messages and Responses
  variants, MCP servers included), as does the portal Quickstart; its traffic is named Open Code
  Review in the audit, its MCP calls included; `ssai run` runs it in the sandbox on Linux, macOS and
  Windows. On an organisation that existed before this release it arrives **disabled**, flagged
  **new**, on each Portal & clients profile: enable it where it should be offered.
- **Fixed: on Windows, most clients started under the sandbox without their configuration.**
  Qwen Code, OpenCode, Crush, the Continue CLI, Mistral Vibe, Aider and Open Code Review read the
  configuration `provision` wrote into your profile only from their home folder, which under the
  sandbox is the sandbox account's — so they started unconfigured (OpenCode fell back to its own
  hosted model). Each is now pointed at its folder in your profile, which alone is granted. A
  Python tool installed with uv or pipx (Aider, Vibe) now starts under the sandbox. Known limits on
  Windows, in the Admin Guide: Aider needs a git identity set in the project, Mistral Vibe stops at
  its first session, and Open Code Review's `review` needs a project outside your profile.
  On Linux, Mistral Vibe now gets a Python tool's grants under the sandbox (uv's and pipx's
  folders), where it was given a Node tool's.

- **Fixed: some MCP calls were recorded with no client application.** A modern MCP client's
  discovery and notification-stream requests, which the gateway answers itself, and requests the
  gateway refused before forwarding, and the sampling an upstream asked of a call, carried no app
  in the audit even when the client named itself with `X-App-Id`. They now carry the app the
  request names, as its forwarded calls do.

## [2026.11.39]

- **Fixed (security): a conversation could show another user's message.** When two users of an
  organisation sent the same prompt, the stored copy of the first sender's message could be shown in
  the second sender's conversation — including the context their client adds to it (a coding
  agent's reminder carrying the user's email, project instructions and git status), or their
  `name`. Each distinct message is now stored on its own, so a conversation shows only messages its
  own requests sent. **Conversations recorded before this release can still show another user's
  copy**: which copy each one shows cannot be told after the fact. They leave with your retention
  period; to remove them sooner, delete the affected sessions or use **Wipe All Data**.
- **Fixed (security): a response cache hit could carry another caller's identifiers.** On an OpenAI
  Responses provider, an answer served from the cache repeated the `metadata`, `user`,
  `safety_identifier` and prompt cache key of the request that first produced it. A cache hit now
  carries the requester's own.

## [2026.11.38]

- **Fixed: the gateway offered no `ssai` for macOS since 2026.11.36.** Those releases were
  published without it; every release now carries the macOS build of its own version, and is not
  published without it.
- **`ssai-stow updates` on Docker and Kubernetes** (`k8s updates`): which release `upgrade
  --version` would move to, with its changelog, read from the install's registry and signed by a
  key the install trusts — as on the VM appliance.
- **Fixed: on Windows, a sandboxed run's first start went over every file in your profile.**
  Opening the folders above the project to the sandbox's account rewrote the access of everything
  under them, so on a full profile the first run of each project or tool, and each revoke, took
  minutes. Those folders are now changed alone; only the project and the tool's own folders are
  given access file by file, once.
- **BREAKING (Windows): a project folder every account may write is made private instead of run
  as it is.** `--allow-outside-profile` is gone. When the project folder lets every account on the
  computer write it (a folder made directly on a drive does), `ssai run --sandbox` explains why the
  sandbox cannot confine its writes there and asks to make it private to you; `--private-project`
  does so without asking. A folder above the project that every account may write is named on
  each run. A project on a network share, which the sandbox's account cannot reach, is refused. A project
  outside your profile that no other account may write now runs without any flag.

## [2026.11.37]

- **`ssai provision` says when your CLI is older than the gateway's.** Every run first checks the
  version the gateway serves and, when it is newer, names the `ssai update` to run — so a provision
  an older CLI can no longer complete still tells you the fix. `ssai sync` does the same once a day,
  now before it syncs rather than after.
- **Fixed: on Windows and macOS, `ssai login` named the device `unknown-device`.** It now names
  it after the machine.

## [2026.11.36]

- **The portal's CLI steps name no particular client.** The Quickstart's run step reads
  `ssai run <client>` and says what to put there: the client's id as `ssai status` lists it, or
  the command that starts it.

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
