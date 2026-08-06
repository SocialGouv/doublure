#!/usr/bin/env bash
# The Go control service against a vault written by the Python engine.
#
# What this proves, in order of importance:
#   1. the agent CANNOT reach the socket — the whole point of the design;
#   2. the socket is 0600, and the service refuses to start without explicit paths;
#   3. Go reads a vault Python sealed — the crypto port is exact, not approximate;
#   4. decisions taken over the API reach the engine;
#   5. D4 holds: the API is not a derogation;
#   6. the event stream PUSHES, it is not polled.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

STATE="$(mktemp -d -t anonproxy-control-XXXXXX)"
trap 'rm -rf "${STATE}"; [[ -n "${SERVICE_PID:-}" ]] && kill "${SERVICE_PID}" 2>/dev/null' EXIT

export ANONPROXY_STATE_DIR="${STATE}"
export ANONPROXY_POLICY_DIR="${STATE}/policy"
export ANONPROXY_VAULT="${STATE}/store-test.db"
export ANONPROXY_MASTER_KEY_FILE="${STATE}/secret-test"
export ANONPROXY_API_SOCKET="${STATE}/control.sock"
export ANONPROXY_SCOPE="project:control-proof"
export ANONPROXY_DETECT_URL="http://127.0.0.1:${DETECT_PORT:-9000}"
openssl rand -hex 32 > "${ANONPROXY_MASTER_KEY_FILE}"
chmod 600 "${ANONPROXY_MASTER_KEY_FILE}"

curl -sf -m 5 "${ANONPROXY_DETECT_URL}/healthz" >/dev/null || {
  echo "FAIL: detector not listening — start services/anonshield/wrapper/run.sh" >&2
  exit 1
}

TEXT="Move traffic to db-master-01-prod.acmecorp.internal, tell alice.dupont@acmecorp.example."
echo "-> the Python engine anonymises, with no rule at all"
uv run python tests/policy_e2e_tour.py "${TEXT}" > "${STATE}/turn1.txt" || exit 1
cat "${STATE}/turn1.txt"

rc=0

echo
echo "== the service refuses to start without explicit paths =="
go build -C go -o "${STATE}/anonproxy-control" ./cmd/anonproxy-control || exit 1
# Captured to a file rather than piped: a pipeline here made the check report
# a failure while the message was plainly there, and a check that fails for
# the wrong reason is worth no more than one that passes for the wrong reason.
( unset ANONPROXY_API_SOCKET; "${STATE}/anonproxy-control" ) \
  > "${STATE}/no-paths.txt" 2>&1
if grep -qF "is required" "${STATE}/no-paths.txt"; then
  echo "OK   : refuses to start, does not fall back to a default store"
else
  echo "FAIL : started without explicit paths"
  head -2 "${STATE}/no-paths.txt"
  rc=1
fi

echo
echo "-> starting the Go service"
"${STATE}/anonproxy-control" > "${STATE}/service.log" 2>&1 &
SERVICE_PID=$!
for _ in $(seq 1 100); do [[ -S "${ANONPROXY_API_SOCKET}" ]] && break; sleep 0.1; done
[[ -S "${ANONPROXY_API_SOCKET}" ]] || { echo "FAIL: no socket"; cat "${STATE}/service.log"; exit 1; }

echo
echo "== 1. the agent cannot reach the socket =="
if uv run python -c "
import sys; sys.path.insert(0,'hooks'); import pretooluse_guard as g
for url in ('http://x/questions', 'http://localhost/questions', 'http://127.0.0.1/questions'):
    cmd = 'curl -s --unix-socket ${ANONPROXY_API_SOCKET} ' + url
    if not g.check_bash(cmd):
        print('  PASSES:', cmd); sys.exit(1)
print('  every form refused')
"; then echo "OK   : the hook refuses the socket, whatever the URL"
else echo "FAIL : the agent could read the store through the API"; rc=1; fi

echo
echo "== 2. socket permissions =="
PERM=$(stat -c '%a' "${ANONPROXY_API_SOCKET}")
if [[ "${PERM}" == "600" ]]; then echo "OK   : socket is 0600"
else echo "FAIL : socket is ${PERM}"; rc=1; fi

echo
echo "== 3-6. a Node client, exactly what the extension does =="
node tests/control_client.js "${ANONPROXY_API_SOCKET}" > "${STATE}/node.txt" 2>&1 \
  || { echo "FAIL: Node client failed"; cat "${STATE}/node.txt"; rc=1; }
cat "${STATE}/node.txt"

echo
echo "-> the decision taken over the API reaches the engine"
uv run python tests/policy_e2e_tour.py "${TEXT}" > "${STATE}/turn2.txt" || exit 1
cat "${STATE}/turn2.txt"

check() {
  if grep -qF -- "$3" "$2"; then found=present; else found=absent; fi
  if [[ "${found}" == "$4" ]]; then echo "OK   : $1"
  else echo "FAIL : $1 (expected $4, found ${found})"; rc=1; fi
}

echo
echo "== Verdict =="
check "turn 1 — host anonymised"                "${STATE}/turn1.txt" "db-master-01-prod.acmecorp.internal" absent
check "Go decrypted a vault Python sealed"      "${STATE}/node.txt"  "db-master-01-prod.acmecorp.internal" present
check "D4 — revealing a secret is REFUSED"      "${STATE}/node.txt"  "SECRET-REFUSED-OK"                   present
check "the stream PUSHED without being polled"  "${STATE}/node.txt"  "PUSH-OK"                             present
check "turn 2 — the arbitrated host is revealed" "${STATE}/turn2.txt" "db-master-01-prod.acmecorp.internal" present
check "turn 2 — the e-mail stays anonymised"    "${STATE}/turn2.txt" "alice.dupont@acmecorp.example"       absent

if grep -rqF "acmecorp" "${ANONPROXY_POLICY_DIR}" 2>/dev/null; then
  echo "FAIL : the policy holds a real value"; rc=1
else
  echo "OK   : the policy holds no real value"
fi

echo
[[ ${rc} -eq 0 ]] && echo "**PASS**" || echo "**FAIL**"
exit ${rc}
