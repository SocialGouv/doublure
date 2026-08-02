#!/usr/bin/env bash
# Critère de sortie Phase 3 (plan §5) :
#   « Une session Claude Code complète fonctionne à l'identique, et la capture
#     mitmproxy ne montre AUCUNE valeur réelle dans le corps sortant. »
#
# Chaîne montée :
#   claude ──ANTHROPIC_BASE_URL──► anonproxy:8090 ──HTTPS_PROXY──► mitmdump:8091 ──► api.anthropic.com
#                                       │
#                                       └── détecteur AnonShield :9000
#
# La capture conserve les CORPS sortants ; on y cherche littéralement chaque
# valeur sensible de la fixture SYNTHÉTIQUE. Une seule occurrence = échec.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
STAMP="$(date +%Y%m%d-%H%M%S)"
OUT="${REPO_ROOT}/captures/phase3-${STAMP}"
BODIES="${OUT}/bodies"
CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
FIXTURE="tests/fixtures/synthetic_infra.md"

DETECT_PORT="${DETECT_PORT:-9000}"
PROXY_PORT="${PROXY_PORT:-8090}"
MITM_PORT="${MITM_PORT:-8091}"

mkdir -p "${BODIES}"
cd "${REPO_ROOT}"

cleanup() {
  [[ -n "${MITM_PID:-}"  ]] && kill "${MITM_PID}"  2>/dev/null
  [[ -n "${PROXY_PID:-}" ]] && kill "${PROXY_PID}" 2>/dev/null
  wait 2>/dev/null
}
trap cleanup EXIT

# --- 1. détecteur ----------------------------------------------------------- #
if ! curl -sf -m 5 "http://127.0.0.1:${DETECT_PORT}/healthz" >/dev/null; then
  echo "ÉCHEC : détecteur absent sur :${DETECT_PORT} — lancer services/anonshield/wrapper/run.sh" >&2
  exit 1
fi
echo "→ détecteur OK ($(curl -s "http://127.0.0.1:${DETECT_PORT}/healthz" | python3 -c 'import json,sys; d=json.load(sys.stdin); print(d["model"], d["device"])'))"

# --- 2. mitmdump (capture des corps) ---------------------------------------- #
command -v mitmdump >/dev/null || { echo "ÉCHEC : mitmdump absent (uv tool install mitmproxy)" >&2; exit 1; }
mitmdump -q --listen-host 127.0.0.1 --listen-port "${MITM_PORT}" \
  -s tests/egress/leak_check_addon.py --set leak_dir="${BODIES}" \
  > "${OUT}/mitmdump.log" 2>&1 &
MITM_PID=$!
sleep 3
[[ -f "${CA}" ]] || { echo "ÉCHEC : CA mitmproxy absente (${CA})" >&2; exit 1; }

# --- 3. proxy de pseudonymisation ------------------------------------------- #
# Coffre dédié à ce test : le déterminisme se vérifie sur une base neuve.
export ANONPROXY_SCOPE="project:phase3-e2e"
export ANONPROXY_VAULT="${OUT}/vault.db"
export ANONPROXY_MASTER_KEY_FILE="${ANONPROXY_MASTER_KEY_FILE:-${HOME}/.local/state/anonproxy/anon_secret_key}"
export ANONPROXY_CA_BUNDLE="${CA}"
export HTTPS_PROXY="http://127.0.0.1:${MITM_PORT}"
export HTTP_PROXY="http://127.0.0.1:${MITM_PORT}"
export NO_PROXY="127.0.0.1,localhost"

uv run python -m uvicorn anonproxy.proxy.app:app \
  --host 127.0.0.1 --port "${PROXY_PORT}" --log-level info \
  > "${OUT}/proxy.log" 2>&1 &
PROXY_PID=$!

for _ in $(seq 1 30); do
  curl -sf -m 2 "http://127.0.0.1:${PROXY_PORT}/healthz" >/dev/null && break
  sleep 1
done
curl -sf -m 5 "http://127.0.0.1:${PROXY_PORT}/healthz" >/dev/null || {
  echo "ÉCHEC : proxy pas prêt ; log :" >&2; tail -20 "${OUT}/proxy.log" >&2; exit 1; }
echo "→ proxy OK sur :${PROXY_PORT} (portée ${ANONPROXY_SCOPE})"

# --- 4. session Claude Code réelle ------------------------------------------ #
# Sans HTTPS_PROXY pour le client : on veut mesurer le canal 1 via le proxy,
# pas re-router le client. CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 coupe la
# télémétrie (découverte Phase 0) pour garder la capture lisible.
echo "→ session Claude Code (fixture synthétique)…"
CLAUDE_OUT="${OUT}/claude_stdout.txt"
env -u HTTPS_PROXY -u HTTP_PROXY \
  ANTHROPIC_BASE_URL="http://127.0.0.1:${PROXY_PORT}" \
  CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC=1 \
  claude -p "Lis ${FIXTURE} et réponds à la question posée à la fin du fichier." \
    --allowedTools Read --max-turns 6 \
    > "${CLAUDE_OUT}" 2>"${OUT}/claude_stderr.txt"
CLAUDE_RC=$?
echo "   code retour claude : ${CLAUDE_RC}"
if [[ ${CLAUDE_RC} -ne 0 ]]; then
  # Sans cette garde, une session qui plante donnait « aucune fuite » — pour
  # la seule raison qu'elle n'avait rien envoyé.
  echo "ÉCHEC : la session a échoué (code ${CLAUDE_RC}) ; le verdict de fuite" >&2
  echo "        ne prouverait rien. Sortie :" >&2
  head -5 "${CLAUDE_OUT}" >&2
  exit 1
fi

sleep 2
cleanup
trap - EXIT
sleep 1

# --- 5. verdict ------------------------------------------------------------- #
uv run python tests/egress/leak_report.py "${OUT}" "${FIXTURE}" "${CLAUDE_OUT}"
exit $?
