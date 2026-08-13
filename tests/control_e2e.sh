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

echo
echo "== 7. a value Go cannot render truthfully is REFUSED, not replaced =="
# Python lets a lone surrogate through on purpose: it must still be
# substituted. Go's JSON encoder replaces each bad byte with U+FFFD, so the
# operator would read a value the vault never held — and three distinct hosts
# would render as ONE identical string, making "reveal A while meaning B"
# possible. Reveal is the decision that cannot be taken back.
uv run python -c "
import sys; sys.path.insert(0, 'src')
from anonproxy.policy import Policy
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault
cle = open('${ANONPROXY_MASTER_KEY_FILE}').read().strip()
pol = Policy(racine='${ANONPROXY_POLICY_DIR}', master_key=cle,
             scope_key='${ANONPROXY_SCOPE}')
m = SurrogateEngine(vault=Vault('${ANONPROXY_VAULT}', master_key=cle),
                    master_key=cle, scope_key='${ANONPROXY_SCOPE}', policy=pol)
for i in range(3):
    demi = chr(0xD800 + i)   # composé, jamais écrit en littéral : un
                             # '\\uD80x' dans une source se coupe mal
    m.substitute_value('HOSTNAME', 'srv-0%d%s.example.com' % (i, demi))
" || exit 1
curl -s --unix-socket "${ANONPROXY_API_SOCKET}" http://localhost/questions \
  > "${STATE}/questions-wtf8.json"
if grep -q $'\xef\xbf\xbd' "${STATE}/questions-wtf8.json"; then
  echo "FAIL : a replacement character reached the operator — the value shown"
  echo "       is NOT the value stored"
  rc=1
elif grep -q "value_error" "${STATE}/questions-wtf8.json"; then
  echo "OK   : the question is still listed, and says why its value is missing"
else
  echo "FAIL : neither a value_error nor a replacement — what was rendered?"
  head -c 400 "${STATE}/questions-wtf8.json"
  rc=1
fi


check() {
  if grep -qF -- "$3" "$2"; then found=present; else found=absent; fi
  if [[ "${found}" == "$4" ]]; then echo "OK   : $1"
  else echo "FAIL : $1 (expected $4, found ${found})"; rc=1; fi
}

# --------------------------------------------------------------------------- #
# La réponse « CE MESSAGE » traverse la frontière : Go l'écrit, Python l'honore.
#
# C'est la SEULE façon de savoir que le portage est juste. Deux fois déjà, les
# deux côtés ont écrit le même fichier différemment, et l'opérateur a arbitré
# dans le vide — sur la seule décision qu'on ne peut pas reprendre.
# --------------------------------------------------------------------------- #
curl -s --unix-socket "${ANONPROXY_API_SOCKET}" -X POST \
  -H 'content-type: application/json' \
  -d '{"scope":"message","granularity":"type","target":"DATE","decision":"reveler"}' \
  http://localhost/decide > "${STATE}/message.json" 2>&1 || true

uv run python - > "${STATE}/message.txt" 2>&1 <<'FIN' || true
import os, sys
from pathlib import Path
sys.path.insert(0, "src")
from anonproxy.policy import Policy, Decision
from anonproxy.config import read_master_key
pol = Policy(racine=os.environ["ANONPROXY_POLICY_DIR"],
             master_key=read_master_key(Path(os.environ["ANONPROXY_MASTER_KEY_FILE"])),
             scope_key=os.environ["ANONPROXY_SCOPE"])
decision, source = pol.decide("DATE", "infra", "3 février 2026")
print("PY-HONOURS-GO" if (decision is Decision.REVELER
                          and source == "message:type") else f"NON:{decision}/{source}")
# Et elle ne survit PAS au message suivant.
pol.debut_message()
d2, _ = pol.decide("DATE", "infra", "3 février 2026")
print("PY-DIES-WITH-MESSAGE" if d2 is Decision.ANONYMISER else f"SURVIT:{d2}")
FIN

# La classe `secret` doit être refusée par CE chemin aussi, pas seulement par
# `Set` : un chemin d'écriture oublié ouvrirait un secret.
curl -s --unix-socket "${ANONPROXY_API_SOCKET}" -X POST \
  -H 'content-type: application/json' \
  -d '{"scope":"message","granularity":"classe","target":"secret","decision":"reveler"}' \
  http://localhost/decide > "${STATE}/message-secret.json" 2>&1 || true

echo
echo "== Verdict =="
check "turn 1 — host anonymised"                "${STATE}/turn1.txt" "db-master-01-prod.acmecorp.internal" absent
check "Go decrypted a vault Python sealed"      "${STATE}/node.txt"  "db-master-01-prod.acmecorp.internal" present
check "D4 — revealing a secret is REFUSED"      "${STATE}/node.txt"  "SECRET-REFUSED-OK"                   present
check "the stream PUSHED without being polled"  "${STATE}/node.txt"  "PUSH-OK"                             present
check "turn 2 — the arbitrated host is revealed" "${STATE}/turn2.txt" "db-master-01-prod.acmecorp.internal" present
check "turn 2 — the e-mail stays anonymised"    "${STATE}/turn2.txt" "alice.dupont@acmecorp.example"       absent

check "Go wrote a message answer Python honours" "${STATE}/message.txt" "PY-HONOURS-GO"        present
check "and it dies with the message"            "${STATE}/message.txt" "PY-DIES-WITH-MESSAGE" present
check "D4 — a secret is refused on THAT path too" "${STATE}/message-secret.json" "never revealable" present

if grep -rqF "acmecorp" "${ANONPROXY_POLICY_DIR}" 2>/dev/null; then
  echo "FAIL : the policy holds a real value"; rc=1
else
  echo "OK   : the policy holds no real value"
fi

echo
[[ ${rc} -eq 0 ]] && echo "**PASS**" || echo "**FAIL**"
exit ${rc}
