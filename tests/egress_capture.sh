#!/usr/bin/env bash
# Harnais d'egress — Phase 0 du plan.
#
# Capture TOUT le trafic sortant d'une session Claude Code de référence via
# mitmproxy (proxy explicite + CA), produit un inventaire des destinations
# (captures/<ts>/report.md) et échoue si une destination n'est pas justifiée
# dans tests/egress/known_destinations.json.
#
# Rejouable : sert de garde-fou de non-régression permanent.

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
OUT_DIR="${ROOT}/captures/${TS}"
FLOWS="${OUT_DIR}/flows.jsonl"
REPORT="${OUT_DIR}/report.md"
TRANSCRIPT="${OUT_DIR}/session_transcript.txt"
PORT="${EGRESS_PROXY_PORT:-8091}"
MITM_CA="${HOME}/.mitmproxy/mitmproxy-ca-cert.pem"
SESSION_TIMEOUT="${EGRESS_SESSION_TIMEOUT:-480}"

mkdir -p "${OUT_DIR}"

command -v mitmdump >/dev/null 2>&1 || {
  echo "ERREUR : mitmdump introuvable — installe-le : uv tool install mitmproxy" >&2
  exit 2
}

wait_for_port() {
  local tries=0
  until (exec 3<>"/dev/tcp/127.0.0.1/${PORT}") 2>/dev/null; do
    tries=$((tries + 1))
    [[ ${tries} -ge 30 ]] && return 1
    sleep 0.5
  done
  exec 3>&- 3<&- 2>/dev/null || true
  return 0
}

# --- CA mitmproxy (générée au premier démarrage) --------------------------- #
if [[ ! -f "${MITM_CA}" ]]; then
  echo "→ génération de la CA mitmproxy (premier lancement)"
  mitmdump -q --listen-host 127.0.0.1 --listen-port "${PORT}" &
  CA_PID=$!
  for _ in $(seq 1 30); do
    [[ -f "${MITM_CA}" ]] && break
    sleep 0.5
  done
  kill "${CA_PID}" 2>/dev/null || true
  wait "${CA_PID}" 2>/dev/null || true
  [[ -f "${MITM_CA}" ]] || { echo "ERREUR : CA non générée (${MITM_CA})" >&2; exit 2; }
fi

# --- démarrage du proxy de capture ----------------------------------------- #
echo "→ mitmdump sur 127.0.0.1:${PORT} — capture : ${FLOWS}"
mitmdump -q --listen-host 127.0.0.1 --listen-port "${PORT}" \
  -s "${ROOT}/tests/egress/inventory_addon.py" \
  --set "egress_log=${FLOWS}" &
MITM_PID=$!
trap 'kill "${MITM_PID}" 2>/dev/null || true' EXIT

wait_for_port || { echo "ERREUR : mitmdump n'écoute pas sur ${PORT}" >&2; exit 2; }

# --- session Claude Code de référence -------------------------------------- #
# kubectl : cluster kind local si présent, sinon commande purement locale.
KUBECTL_STEP='kubectl version --client'
if command -v kind >/dev/null 2>&1 && [[ -n "$(kind get clusters 2>/dev/null || true)" ]]; then
  KUBECTL_STEP='kubectl get pods -A'
fi
echo "→ étape kubectl de la session : ${KUBECTL_STEP}"

PROMPT="$(sed "s|__KUBECTL_STEP__|${KUBECTL_STEP}|" "${ROOT}/tests/egress/reference_session.md")"

echo "→ session Claude Code de référence (via proxy, transcript : ${TRANSCRIPT})"
set +e
env -u ANTHROPIC_BASE_URL \
  HTTPS_PROXY="http://127.0.0.1:${PORT}" \
  HTTP_PROXY="http://127.0.0.1:${PORT}" \
  NO_PROXY="localhost,127.0.0.1" \
  NODE_EXTRA_CA_CERTS="${MITM_CA}" \
  SSL_CERT_FILE="${MITM_CA}" \
  REQUESTS_CA_BUNDLE="${MITM_CA}" \
  CURL_CA_BUNDLE="${MITM_CA}" \
  timeout "${SESSION_TIMEOUT}" \
  claude -p "${PROMPT}" \
    --model haiku \
    --allowed-tools "Read" "WebSearch" "WebFetch" "Bash(kubectl:*)" "Bash(rtk:*)" "mcp__context7__resolve-library-id" \
    >"${TRANSCRIPT}" 2>&1
CLAUDE_RC=$?
set -e
echo "   session terminée (code ${CLAUDE_RC})"

# --- arrêt propre du proxy, puis rapport ----------------------------------- #
kill "${MITM_PID}" 2>/dev/null || true
wait "${MITM_PID}" 2>/dev/null || true
trap - EXIT

echo "→ génération du rapport : ${REPORT}"
set +e
python3 "${ROOT}/tests/egress/report.py" "${FLOWS}" \
  --known "${ROOT}/tests/egress/known_destinations.json" \
  --out "${REPORT}" \
  --session-rc "${CLAUDE_RC}"
RC=$?
set -e

echo
cat "${REPORT}"
echo
echo "→ artefacts : ${OUT_DIR}/ (flows.jsonl, report.md, session_transcript.txt)"
exit "${RC}"
