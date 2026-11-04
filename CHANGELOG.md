# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
This project uses [Calendar Versioning](https://calver.org/) (`YYYY.M.MICRO`).

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
