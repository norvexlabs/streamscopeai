# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Calendar Versioning](https://calver.org/) (`YYYY.M.MICRO`).

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
