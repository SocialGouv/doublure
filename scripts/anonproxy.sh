#!/usr/bin/env bash
# anonproxy — bring the chain up for one project, and take it down.
#
#   claude ──ANTHROPIC_BASE_URL──► proxy :8090 ──► api.anthropic.com
#                                     │
#                                     └── detector :9000
#
# One entry point for every project. There used to be a copy of these steps in
# each sandbox; they drifted, and one of the copies had renamed the vault files
# to names the hook does not recognise — which quietly left a session free to
# read its own vault. A project now holds only its own content.
#
# Usage:
#   scripts/anonproxy.sh start [PROJECT] [--mode=auto|consciencieux|ferme]
#   scripts/anonproxy.sh stop  [PROJECT]
#   scripts/anonproxy.sh state [PROJECT]
#   scripts/anonproxy.sh watch [PROJECT]      live view, refreshed each second
#   scripts/anonproxy.sh policy [PROJECT] -- questions
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
# shellcheck source=lib/state.sh
source "${REPO}/scripts/lib/state.sh"

PROXY_PORT="${ANONPROXY_PORT:-8090}"
DETECT_PORT="${DETECT_PORT:-9000}"

usage() { sed -n '2,20p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; }

# resolve_project — the project directory, defaulting to the working directory.
resolve_project() {
  local candidate="${1:-}"
  if [[ -z "${candidate}" || "${candidate}" == --* ]]; then
    candidate="${PWD}"
  fi
  (cd "${candidate}" 2>/dev/null && pwd) || {
    echo "anonproxy: no such project directory: ${candidate}" >&2
    exit 1
  }
}

cmd_state() {
  local project state
  project="$(resolve_project "${1:-}")"
  state="$(anonproxy_state_dir "${project}")"
  echo "project : ${project}"
  echo "state   : ${state}"
  # Metadata only. The vault's contents are never printed, by design.
  ls -1 "${state}" 2>/dev/null | sed 's/^/          /'
}

cmd_start() {
  local project state mode="" arg
  project="$(resolve_project "${1:-}")"
  shift || true
  for arg in "$@"; do
    case "${arg}" in --mode=*) mode="${arg#--mode=}" ;; esac
  done
  state="$(anonproxy_state_dir "${project}")"
  anonproxy_export_env "${project}" "${state}"
  [[ -n "${mode}" ]] && export ANONPROXY_MODE="${mode}"

  echo "→ project : ${project}"
  echo "→ state   : ${state}"
  echo "→ mode    : ${ANONPROXY_MODE:-auto (default)}"

  # --- master key ----------------------------------------------------------
  if [[ ! -f "${ANONPROXY_MASTER_KEY_FILE}" ]]; then
    (umask 077 && openssl rand -hex 32 > "${ANONPROXY_MASTER_KEY_FILE}")
    echo "→ master key created (it never leaves the state directory)"
  fi

  # --- hook ----------------------------------------------------------------
  # Rebuilt every time: a stale hook keeps the old policy without saying so.
  # A build failure REFUSES the session rather than starting it unguarded.
  if ! (cd "${REPO}" && go build -C go -o ../go/bin/anonproxy-guard ./cmd/anonproxy-guard); then
    echo "anonproxy: the Go hook does not build — session refused." >&2
    exit 1
  fi
  echo "→ hook    : ${REPO}/go/bin/anonproxy-guard"

  # --- detector ------------------------------------------------------------
  if ! curl -sf -m 5 "http://127.0.0.1:${DETECT_PORT}/healthz" >/dev/null 2>&1; then
    echo "anonproxy: no detector on :${DETECT_PORT}." >&2
    echo "           Start it first, in another terminal:" >&2
    echo "           ${REPO}/services/anonshield/wrapper/run.sh" >&2
    exit 1
  fi
  echo "→ detector: already listening on :${DETECT_PORT}"
  export ANONPROXY_DETECT_URL="http://127.0.0.1:${DETECT_PORT}"
  export ANONPROXY_PORT="${PROXY_PORT}"

  # --- proxy ---------------------------------------------------------------
  if curl -sf -m 3 "http://127.0.0.1:${PROXY_PORT}/healthz" >/dev/null 2>&1; then
    echo "→ proxy   : already listening on :${PROXY_PORT}"
    echo "            (if it runs with another vault, stop it and start again)"
  else
    # `setsid --fork`, not `nohup … &`. Two problems, one cause: the proxy has
    # to stop being this shell's child.
    #
    # nohup ignores SIGHUP, but an IDE closing its integrated terminal sends
    # SIGTERM to the whole process GROUP — the proxy died mid-session and the
    # session got ConnectionRefused, with nothing in the log but a clean
    # shutdown. And `uv run` stays alive supervising uvicorn, so as a child it
    # also kept this script from ever returning.
    #
    # --fork makes setsid fork, so the proxy is reparented immediately: no
    # child to wait for, no process group to inherit a signal from. It records
    # its OWN pid, since setsid's exits at once; stopping it signals the group.
    (cd "${REPO}" && setsid --fork bash -c \
        "echo \$\$ > '${state}/proxy.pid'; exec uv run python -m uvicorn \
         anonproxy.proxy.app:app --host 127.0.0.1 --port '${PROXY_PORT}' \
         --workers 1 --log-level info" \
        < /dev/null > "${state}/proxy.log" 2>&1)
    for _ in $(seq 1 60); do
      curl -sf -m 2 "http://127.0.0.1:${PROXY_PORT}/healthz" >/dev/null 2>&1 && break
      sleep 0.5
    done
    if ! curl -sf -m 2 "http://127.0.0.1:${PROXY_PORT}/healthz" >/dev/null 2>&1; then
      echo "anonproxy: the proxy did not start — see ${state}/proxy.log" >&2
      tail -20 "${state}/proxy.log" >&2
      exit 1
    fi
    echo "→ proxy   : listening on :${PROXY_PORT}, detached from this terminal"
  fi

  curl -s "http://127.0.0.1:${PROXY_PORT}/healthz" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("→ ready   : scope", d["scope"], "·", d["vault_entries"],
      "vault entry(ies) · detector", d["detector"]["device"])
'
  cat <<FIN

────────────────────────────────────────────────────────────────────────────
Open ${project} in the IDE and start Claude Code. Its .claude/settings.json
points ANTHROPIC_BASE_URL at the proxy and the PreToolUse hook at the Go
binary — nothing to export.

  scripts/anonproxy.sh policy ${project} -- questions   what was anonymised
                                                        without a rule
  scripts/anonproxy.sh state ${project}                 where the state lives
  scripts/anonproxy.sh stop  ${project}                 stop the proxy
────────────────────────────────────────────────────────────────────────────
FIN
}

cmd_stop() {
  local project state pid
  project="$(resolve_project "${1:-}")"
  state="$(anonproxy_state_dir "${project}")"
  pid="$(cat "${state}/proxy.pid" 2>/dev/null || true)"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    # The whole GROUP: `uv run` supervises uvicorn, and signalling only the
    # supervisor left the server listening on the port.
    kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}"
    echo "→ proxy stopped (process group ${pid})"
    rm -f "${state}/proxy.pid"
  else
    echo "→ no proxy recorded for this project"
  fi
  echo "  the detector is left running: it is shared and slow to warm up."
}

cmd_watch() {
  local project state
  project="$(resolve_project "${1:-}")"
  state="$(anonproxy_state_dir "${project}")"
  exec python3 "${REPO}/scripts/watch.py" "${project}" "${state}" \
       "http://127.0.0.1:${PROXY_PORT}"
}

cmd_policy() {
  local project state
  project="$(resolve_project "${1:-}")"
  shift || true
  [[ "${1:-}" == "--" ]] && shift
  state="$(anonproxy_state_dir "${project}")"
  anonproxy_export_env "${project}" "${state}"
  (cd "${REPO}" && uv run python scripts/anonproxy_policy.py "$@")
}

case "${1:-}" in
  start)  shift; cmd_start "$@" ;;
  stop)   shift; cmd_stop "$@" ;;
  state)  shift; cmd_state "$@" ;;
  watch)  shift; cmd_watch "$@" ;;
  policy) shift; cmd_policy "$@" ;;
  ""|-h|--help) usage ;;
  *) echo "anonproxy: unknown command: $1" >&2; usage >&2; exit 1 ;;
esac
