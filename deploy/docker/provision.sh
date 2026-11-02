#!/usr/bin/env bash
#
# provision.sh — take a freshly migrated Streamscope database to a platform
# administrator, an organisation and its administrator. Everything inside the
# organisation — users, providers, workspace grants, API keys, MCP servers,
# policies — is the console's. The same flow runs on every deploy shape: as the
# installer's provision hook on Docker and the VM, and as the Job the installer
# runs once a Kubernetes release is settled.
#
# It WRITES NO FILES. Inputs arrive in the environment; progress goes to stderr
# and the results go to stdout as `KEY=VALUE` lines, which the installer records
# (under the operator's own account; on Kubernetes in a release Secret) and
# hands back on the next run. A value this script mints (a password, a key) is
# printed BEFORE the step that uses it, so a run that fails after the step still
# leaves it recorded.
#
# A key it prints is never one of its inputs: the installer refuses a returned
# value that would overwrite what the operator chose.
#
# Every step is idempotent — a second run changes nothing and still succeeds.
#
# A step whose inputs are empty is skipped, with everything that depends on it:
# no TENANT_SLUG stops after the platform administrator, no TENANT_ADMIN_EMAIL
# after the organisation.
#
# Inputs:
#   ADMIN_API_URL           where to reach the API (default http://admin-api:9090)
#   SETUP_ADMIN_EMAIL       platform super-admin           (required)
#   SETUP_ADMIN_PASSWORD    its password; minted when empty
#   OPERATOR_AK             a previously minted operator key; skips the password
#   TENANT_NAME/TENANT_SLUG the organisation to create (the name defaults to the slug)
#   TENANT_ADMIN_EMAIL      its administrator
#   TENANT_ADMIN_PASSWORD   its password; minted when empty
#   TENANT_AK               a previously minted organisation key; skips the invite
#   TENANT_AK_SLUG          the organisation it was minted for; another one drops it
set -euo pipefail

API="${ADMIN_API_URL:-http://admin-api:9090}"
BODY="$(mktemp)"
trap 'rm -f "$BODY"' EXIT

say()  { printf '  %s\n' "$*" >&2; }
step() { printf '\n%s\n' "$*" >&2; }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }
emit() { printf '%s=%s\n' "$1" "$2"; }

need() { [ -n "${2:-}" ] || die "$1 is required"; }

# A password for an account this run creates, when none is given. Printed at
# once, so it is recorded before the account that uses it exists.
mint() {
  local name="$1" value
  [ -n "${!name:-}" ] && return 0
  value="$(head -c 64 /dev/urandom | base64 | tr -dc 'A-Za-z0-9' | cut -c1-24)"
  [ "${#value}" -ge 16 ] || die "could not mint $name"
  printf -v "$name" '%s' "$value"
  export "${name?}"
  emit "$name" "$value"
}

# The steps a run reaches, from its inputs (see the header). Addresses are
# compared as the API stores them, trimmed and lowercased: one typed with
# capitals is the same account, and a raw comparison would miss it on a re-run.
email() { printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]' | sed 's/^[[:space:]]*//; s/[[:space:]]*$//'; }
TENANT_SLUG="${TENANT_SLUG:-}"
TENANT_NAME="${TENANT_NAME:-$TENANT_SLUG}"
SETUP_ADMIN_EMAIL="$(email "${SETUP_ADMIN_EMAIL:-}")"
TENANT_ADMIN_EMAIL="$(email "${TENANT_ADMIN_EMAIL:-}")"
export SETUP_ADMIN_EMAIL TENANT_ADMIN_EMAIL

# request METHOD PATH [AUTH] [JSON] -> prints the status code, body in $BODY.
#
# The body goes in on stdin, never as an argument: a request carrying a password
# would otherwise sit in /proc/<pid>/cmdline, which any
# account on the host can read for as long as the call takes. `000` is reserved
# for curl failing outright, and is printed INSTEAD of its output rather than
# appended to it — the two concatenated read as a status code that never existed.
request() {
  local method="$1" path="$2" auth="${3:-}" json="${4:-}" out=""
  set -- -sS -X "$method" -o "$BODY" -w '%{http_code}' --max-time 60
  [ -n "$auth" ] && set -- "$@" -H "Authorization: Bearer $auth"
  if [ -n "$json" ]; then
    out="$(printf '%s' "$json" | curl "$@" -H 'Content-Type: application/json' \
           --data-binary @- "${API}${path}" 2>/dev/null)" || out=""
  else
    out="$(curl "$@" "${API}${path}" 2>/dev/null)" || out=""
  fi
  printf '%s' "${out:-000}"
}

ok()      { case "$1" in 200|201|204) return 0 ;; *) return 1 ;; esac; }
conflict(){ [ "$1" = "409" ]; }
jqr()     { jq -r "$1" < "$BODY" 2>/dev/null || true; }
# A recorded key the API no longer accepts (revoked in the console, or a
# restore that brought back data without it) is dropped, so the run signs in
# again and mints a new one. Only a 401 says that; an accepted key is kept, and
# any other answer stops the run: it says nothing about the key.
key_refused() {
  local code
  code="$(request GET "$1" "$2")"
  [ "$code" = 401 ] && return 0
  ok "$code" && return 1
  die "could not check the recorded $3 (HTTP $code): $(cat "$BODY")"
}
# The operator's way out when an account exists and the credential recorded for
# it is refused: only they know its current password.
stale() { die "$1 — give its current password: run provisioning again with --set $2=…"; }
# A sign-in refused for another reason than the password: password sign-in is
# off (the account signs in through an identity provider) and only a key gets
# past it. Any other answer (an outage, a rate limit) is worth a plain retry.
no_login() {
  [ "$(jqr '.error.code')" = password_login_disabled ] || die "could not sign in as $1 (HTTP $2): $(cat "$BODY")"
  die "$1 cannot sign in with a password (it signs in through an identity provider) — give a key of its installer service account: run provisioning again with --set $3=…"
}

# The installer service account of the caller's tenant, created when absent, and
# a new key of it minted with body $2, in INSTALLER_KEY. $3 names the key.
INSTALLER_KEY=""
installer_key() {
  local auth="$1" body="$2" what="$3" code sa
  code="$(request POST /api/v1/admin/service-accounts "$auth" '{"name":"installer"}')"
  if ok "$code"; then
    sa="$(jqr '.id')"
  else
    sa="$(list_find /api/v1/admin/service-accounts "$auth" \
          '.items[] | select(.display_name == "installer") | .id' | head -1)"
  fi
  [ -n "$sa" ] || die "could not create or find the installer service account for the $what"
  code="$(request POST "/api/v1/admin/service-accounts/${sa}/keys" "$auth" "$body")"
  ok "$code" || die "could not mint the $what (HTTP $code): $(cat "$BODY")"
  INSTALLER_KEY="$(jqr '.key')"
  [ -n "$INSTALLER_KEY" ] || die "the $what minted came back without a key"
}

# Walk every page of a list endpoint and print the values whose rows match a jq
# filter. Paging follows `has_more`, never a page size — `limit` is capped
# server-side, so asking for one huge page silently truncates.
#
# Results are collected and written ONCE at the end. Callers take the first line
# with `head -1`, which closes the pipe as soon as it has it; writing page by
# page into that closed pipe would kill this function part-way through, and the
# caller's assignment would then fail rather than yield the value it already had.
#
# A page that cannot be read, or that the filter cannot read, stops the run
# naming the list: callers read an empty result as "not present" and create the
# thing, so an unread list must never come back empty.
list_find() {
  local path="$1" auth="$2" filter="$3" offset=0 code more page out=""
  while : ; do
    local sep='?'; case "$path" in *\?*) sep='&' ;; esac
    code="$(request GET "${path}${sep}limit=100&offset=${offset}" "$auth")"
    ok "$code" || die "could not read $path (HTTP $code): $(cat "$BODY")"
    page="$(jq -r "$filter" < "$BODY")" || die "could not read the answer of $path"
    out="${out}${page}
"
    more="$(jqr '.has_more')"
    [ "$more" = "true" ] || break
    offset=$((offset + 100))
  done
  printf '%s' "$out" | grep -v '^$' || true
}

need SETUP_ADMIN_EMAIL "${SETUP_ADMIN_EMAIL:-}"

# ---------------------------------------------------------------------------
# 1. Wait for the API, and only ever act on a definitive answer.
#
# A transport error is not "setup is already done" — reading it that way would
# skip creating the platform administrator and leave a console nobody can enter.
# ---------------------------------------------------------------------------
step "Waiting for the API"
NEEDS_SETUP=""
i=0
while [ "$i" -lt 150 ]; do
  code="$(request GET /api/v1/auth/setup/status)"
  if ok "$code"; then
    NEEDS_SETUP="$(jqr '.needs_setup')"
    case "$NEEDS_SETUP" in true|false) break ;; esac
  fi
  i=$((i + 1)); sleep 2
done
case "${NEEDS_SETUP:-}" in
  true|false) say "API is ready (setup needed: $NEEDS_SETUP)" ;;
  *) die "the API did not become ready within 300s" ;;
esac

# ---------------------------------------------------------------------------
# 2-4. Platform administrator, then a durable operator key.
#
# The key is what makes re-runs work without a stored password: key
# authentication ignores the sign-in mode, so it keeps working even after the
# platform is switched to an identity provider. It is shown exactly once at mint
# time, so the installer stores what we emit here.
# ---------------------------------------------------------------------------
step "Platform administrator"
SYS_JWT=""
OPERATOR_AK="${OPERATOR_AK:-}"
if [ -n "$OPERATOR_AK" ] && key_refused "/api/v1/admin/tenants?limit=1" "$OPERATOR_AK" "operator key"; then
  say "the recorded operator key is refused: signing in for a new one"
  OPERATOR_AK=""
fi
# A password is minted only for the administrator this run creates: one minted
# for an existing account would be recorded as its credential and then refused.
if [ -z "$OPERATOR_AK" ] && [ "$NEEDS_SETUP" = "true" ]; then mint SETUP_ADMIN_PASSWORD; fi
if [ "$NEEDS_SETUP" = "true" ]; then
  need SETUP_ADMIN_PASSWORD "${SETUP_ADMIN_PASSWORD:-}"
  code="$(request POST /api/v1/auth/setup "" \
    "$(jq -n --arg e "$SETUP_ADMIN_EMAIL" --arg p "$SETUP_ADMIN_PASSWORD" '{email:$e,password:$p}')")"
  ok "$code" || die "could not create the platform administrator (HTTP $code): $(cat "$BODY")"
  SYS_JWT="$(jqr '.token')"
  say "created $SETUP_ADMIN_EMAIL"
else
  say "already present"
fi

if [ -z "$OPERATOR_AK" ] && [ -z "$SYS_JWT" ]; then
  [ -n "${SETUP_ADMIN_PASSWORD:-}" ] || stale "$SETUP_ADMIN_EMAIL exists and no password is recorded for it" SETUP_ADMIN_PASSWORD
  code="$(request POST /api/v1/auth/login "" \
    "$(jq -n --arg e "$SETUP_ADMIN_EMAIL" --arg p "$SETUP_ADMIN_PASSWORD" \
            '{email:$e,password:$p,tenant_slug:"system"}')")"
  [ "$code" = 401 ] && stale "the password recorded for $SETUP_ADMIN_EMAIL is refused" SETUP_ADMIN_PASSWORD
  ok "$code" || no_login "$SETUP_ADMIN_EMAIL" "$code" OPERATOR_AK
  SYS_JWT="$(jqr '.token')"
fi
if [ -z "$OPERATOR_AK" ]; then
  # The SYSTEM tenant mints only operator-scoped keys, by design.
  installer_key "$SYS_JWT" '{"type":"admin","admin_scope":"super_admin","name":"installer"}' "operator key"
  OPERATOR_AK="$INSTALLER_KEY"
  say "minted an operator key"
  emit OPERATOR_AK "$OPERATOR_AK"
fi
OP_AUTH="$OPERATOR_AK"

if [ -z "$TENANT_SLUG" ]; then
  say "no tenant asked for: done"
  exit 0
fi

# ---------------------------------------------------------------------------
# 5. The tenant.
#
# Creating it seeds its Default, Agent and inline workspaces, every policy
# profile, the model and tool catalogs and the built-in web server. It does not
# seed any user, membership, provider or key: those are the console's.
# ---------------------------------------------------------------------------
step "Tenant"
code="$(request POST /api/v1/admin/tenants "$OP_AUTH" \
  "$(jq -n --arg n "$TENANT_NAME" --arg s "$TENANT_SLUG" '{name:$n,slug:$s}')")"
if ok "$code"; then
  say "created $TENANT_SLUG"
elif conflict "$code"; then
  say "$TENANT_SLUG already exists"
else
  die "could not create the tenant (HTTP $code): $(cat "$BODY")"
fi

# ---------------------------------------------------------------------------
# 6-8. The tenant administrator, and a tenant key recorded for the next run.
#
# A platform key cannot create users inside a tenant — the tenant a request
# acts in comes from the credential presented, and there is no impersonation.
# An invitation is the only way in for the first administrator. The tenant key
# minted from its session is what a re-run checks the administrator with, so it
# never needs the password again.
# ---------------------------------------------------------------------------
if [ -z "$TENANT_ADMIN_EMAIL" ]; then
  say "no tenant administrator asked for: done"
  exit 0
fi

step "Tenant administrator"
TENANT_JWT=""
TENANT_AK="${TENANT_AK:-}"
# A key recorded for another organisation (TENANT_SLUG changed since) would carry
# every later step into it: it is not this one's.
if [ -n "$TENANT_AK" ] && [ -n "${TENANT_AK_SLUG:-}" ] && [ "$TENANT_AK_SLUG" != "$TENANT_SLUG" ]; then
  say "the recorded tenant key is $TENANT_AK_SLUG's: signing in for one of $TENANT_SLUG"
  TENANT_AK=""
fi
if [ -n "$TENANT_AK" ] && key_refused "/api/v1/admin/service-accounts?limit=1" "$TENANT_AK" "tenant key"; then
  say "the recorded tenant key is refused: signing in for a new one"
  TENANT_AK=""
fi
if [ -z "$TENANT_AK" ]; then
  code=""
  if [ -n "${TENANT_ADMIN_PASSWORD:-}" ]; then
    code="$(request POST /api/v1/auth/login "" \
      "$(jq -n --arg e "$TENANT_ADMIN_EMAIL" --arg p "$TENANT_ADMIN_PASSWORD" --arg s "$TENANT_SLUG" \
              '{email:$e,password:$p,tenant_slug:$s}')")"
  fi
  if ok "$code"; then
    TENANT_JWT="$(jqr '.token')"
    say "already present"
  else
    [ -z "$code" ] || [ "$code" = 401 ] || no_login "$TENANT_ADMIN_EMAIL" "$code" TENANT_AK
    # Not signed in. A password is minted only for an administrator this run
    # creates: one minted for an existing account would be recorded as its
    # credential and then refused.
    exists="$(list_find "/api/v1/admin/tenants/${TENANT_SLUG}/admins" "$OP_AUTH" \
              '.items[] | select((.email // "" | ascii_downcase) == env.TENANT_ADMIN_EMAIL) | .id' | head -1)"
    if [ -n "$exists" ]; then
      [ -n "${TENANT_ADMIN_PASSWORD:-}" ] \
        && stale "the password recorded for $TENANT_ADMIN_EMAIL is refused" TENANT_ADMIN_PASSWORD
      stale "$TENANT_ADMIN_EMAIL exists and no password is recorded for it" TENANT_ADMIN_PASSWORD
    fi
    mint TENANT_ADMIN_PASSWORD
    # For this address alone and short-lived, and deleted if it is not
    # accepted: an open administrator invitation is a credential.
    code="$(request POST "/api/v1/admin/tenants/${TENANT_SLUG}/invites" "$OP_AUTH" \
      "$(jq -n --arg e "$TENANT_ADMIN_EMAIL" '{role:"admin",email:$e,expires_in_hours:1}')")"
    ok "$code" || die "could not create the administrator invitation (HTTP $code): $(cat "$BODY")"
    INVITE="$(jqr '.token')"; INVITE_ID="$(jqr '.id')"
    code="$(request POST "/api/v1/invites/${INVITE}/accept" "" \
      "$(jq -n --arg e "$TENANT_ADMIN_EMAIL" --arg p "$TENANT_ADMIN_PASSWORD" '{email:$e,password:$p}')")"
    if ! ok "$code"; then
      failed="$(cat "$BODY")"
      request DELETE "/api/v1/admin/tenants/${TENANT_SLUG}/invites/${INVITE_ID}" "$OP_AUTH" >/dev/null || true
      die "could not accept the administrator invitation (HTTP $code): $failed"
    fi
    TENANT_JWT="$(jqr '.token')"
    say "created $TENANT_ADMIN_EMAIL"
  fi

  installer_key "$TENANT_JWT" '{"type":"admin","admin_scope":"admin","name":"installer"}' "tenant key"
  TENANT_AK="$INSTALLER_KEY"
fi
emit TENANT_AK "$TENANT_AK"
emit TENANT_AK_SLUG "$TENANT_SLUG"
say "done: sign in to the console as $TENANT_ADMIN_EMAIL to add a provider, users and keys"
