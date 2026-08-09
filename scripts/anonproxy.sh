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

# resolve_project — sets PROJECT to the project directory, or STOPS.
#
# It assigns a global rather than printing, because the caller used to read it
# through a command substitution — and `exit` inside one leaves only the
# subshell. The script carried on with an empty project and built a state path
# from it, so it read a vault somewhere else instead of failing. Fail loudly:
# a wrong store read in silence is worse than not starting.
PROJECT=""
resolve_project() {
  local candidate="${1:-}"
  if [[ -z "${candidate}" || "${candidate}" == --* ]]; then
    candidate="${PWD}"
  fi
  # A `~` held in a VARIABLE is not expanded by the shell: `task state -- $D`
  # passes the tilde through literally, and nothing would find that directory.
  candidate="${candidate/#\~/${HOME}}"
  PROJECT="$(cd "${candidate}" 2>/dev/null && pwd)" || PROJECT=""
  if [[ -z "${PROJECT}" ]]; then
    echo "anonproxy: no such project directory: ${candidate}" >&2
    exit 1
  fi
}

cmd_state() {
  local project state
  resolve_project "${1:-}"; project="${PROJECT}"
  state="$(anonproxy_state_dir "${project}")"
  echo "project : ${project}"
  echo "state   : ${state}"
  # Metadata only. The vault's contents are never printed, by design.
  ls -1 "${state}" 2>/dev/null | sed 's/^/          /'
}

cmd_start() {
  local project state mode="" arg
  resolve_project "${1:-}"; project="${PROJECT}"
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
    # A port that answers is NOT a proxy in a coherent state. Wiping the state
    # directory leaves the running proxy serving a store that no longer exists
    # — it holds the deleted file open — while everything started afterwards
    # opens it BY PATH and fails. Trusting the port alone turned that into an
    # error about SQLite, three steps away from the cause.
    if [[ ! -f "${ANONPROXY_VAULT}" ]]; then
      echo "anonproxy: a proxy answers on :${PROXY_PORT}, but the store it" >&2
      echo "           should be using is gone from ${state}." >&2
      echo "           It is running against a deleted store; stop it first:" >&2
      echo "             scripts/anonproxy.sh stop ${project}" >&2
      exit 1
    fi
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

  # --- control service -----------------------------------------------------
  # The arbitration API, on a UNIX SOCKET and never a port: it returns REAL
  # values, and the agent runs on this machine where the hook lets loopback
  # through — a port would reopen exactly what the hook closes.
  export ANONPROXY_API_SOCKET="${state}/control.sock"
  if [[ -S "${ANONPROXY_API_SOCKET}" ]] && \
     curl -sf -m 2 --unix-socket "${ANONPROXY_API_SOCKET}" http://localhost/health >/dev/null 2>&1; then
    echo "→ control : already listening"
  else
    rm -f "${ANONPROXY_API_SOCKET}"
    if ! (cd "${REPO}" && go build -C go -o ../go/bin/anonproxy-control ./cmd/anonproxy-control); then
      echo "anonproxy: the control service does not build — session refused." >&2
      exit 1
    fi
    (cd "${REPO}" && setsid --fork bash -c \
        "echo \$\$ > '${state}/control.pid'; exec '${REPO}/go/bin/anonproxy-control'" \
        < /dev/null > "${state}/control.log" 2>&1)
    for _ in $(seq 1 20); do
      [[ -S "${ANONPROXY_API_SOCKET}" ]] && break
      sleep 0.25
    done
    if [[ ! -S "${ANONPROXY_API_SOCKET}" ]]; then
      echo "anonproxy: the control service did not start — see ${state}/control.log" >&2
      tail -10 "${state}/control.log" >&2
      exit 1
    fi
    echo "→ control : arbitration socket ready"
  fi

  curl -s "http://127.0.0.1:${PROXY_PORT}/healthz" | python3 -c '
import json, sys
d = json.load(sys.stdin)
print("→ ready   : scope", d["scope"], "·", d["vault_entries"],
      "vault entry(ies) · detector", d["detector"]["device"])
'
  # Saying this plainly matters: the command returning immediately reads like
  # the services stopping, and the first person to run it read it that way.
  cat <<FIN

────────────────────────────────────────────────────────────────────────────
This command is DONE. The proxy and the control service keep running in the
background, in their own session — they survive this terminal and the IDE.

Open ${project} and start Claude Code. Its .claude/settings.json points
ANTHROPIC_BASE_URL at the proxy and the PreToolUse hook at the Go binary —
nothing to export.

  task watch  -- ${project}   live view
  task policy -- ${project} -- questions   anonymised without a rule
  task state  -- ${project}   where the state lives
  task stop   -- ${project}   stop both services
────────────────────────────────────────────────────────────────────────────
FIN
}

cmd_stop() {
  local project state pid
  resolve_project "${1:-}"; project="${PROJECT}"
  state="$(anonproxy_state_dir "${project}")"
  pid="$(cat "${state}/proxy.pid" 2>/dev/null || true)"
  # The pid file lives in the state directory it helps clean up: wipe the
  # state and `stop` loses the only handle it had, reports "nothing to stop",
  # and leaves a proxy running against a store that no longer exists. The
  # PORT is the durable handle — it does not live in the directory.
  if [[ -z "${pid}" ]] || ! kill -0 "${pid}" 2>/dev/null; then
    pid="$(ss -lntpH "sport = :${PROXY_PORT}" 2>/dev/null \
           | grep -oE 'pid=[0-9]+' | head -1 | cut -d= -f2)"
    [[ -n "${pid}" ]] && echo "→ pid file gone; found the proxy by its port"
  fi
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    # The whole GROUP: `uv run` supervises uvicorn, and signalling only the
    # supervisor left the server listening on the port.
    kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}"
    echo "→ proxy stopped (process group ${pid})"
    rm -f "${state}/proxy.pid"
  else
    echo "→ no proxy recorded for this project"
  fi
  pid="$(cat "${state}/control.pid" 2>/dev/null || true)"
  if [[ -n "${pid}" ]] && kill -0 "${pid}" 2>/dev/null; then
    kill -TERM -- "-${pid}" 2>/dev/null || kill -TERM "${pid}"
    echo "→ control service stopped"
    rm -f "${state}/control.pid" "${state}/control.sock"
  fi
  echo "  the detector is left running: it is shared and slow to warm up."
}

cmd_watch() {
  local project state
  resolve_project "${1:-}"; project="${PROJECT}"
  state="$(anonproxy_state_dir "${project}")"
  exec python3 "${REPO}/scripts/watch.py" "${project}" "${state}" \
       "http://127.0.0.1:${PROXY_PORT}"
}

cmd_policy() {
  local project state
  resolve_project "${1:-}"; project="${PROJECT}"
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
