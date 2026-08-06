#!/usr/bin/env bash
# L'API d'arbitrage sur sa VRAIE socket, interrogée par un client Node —
# exactement ce que fera l'extension.
#
# Ce que ce script prouve, dans l'ordre d'importance :
#   1. l'agent NE PEUT PAS joindre la socket (c'est tout le choix de conception) ;
#   2. la socket est en 0600 ;
#   3. l'arbitrage par l'API produit le même effet que par la CLI ;
#   4. D4 tient : l'API n'est pas une dérogation.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

ETAT="$(mktemp -d -t anonproxy-api-XXXXXX)"
trap 'rm -rf "${ETAT}"; [[ -n "${API_PID:-}" ]] && kill "${API_PID}" 2>/dev/null' EXIT

export ANONPROXY_STATE_DIR="${ETAT}"
export ANONPROXY_POLICY_DIR="${ETAT}/politique"
export ANONPROXY_VAULT="${ETAT}/coffre-essai.db"
export ANONPROXY_MASTER_KEY_FILE="${ETAT}/cle-essai"
export ANONPROXY_API_SOCKET="${ETAT}/arbitrage.sock"
export ANONPROXY_SCOPE="project:preuve-api"
export ANONPROXY_DETECT_URL="http://127.0.0.1:${DETECT_PORT:-9000}"
openssl rand -hex 32 > "${ANONPROXY_MASTER_KEY_FILE}"
chmod 600 "${ANONPROXY_MASTER_KEY_FILE}"

curl -sf -m 5 "${ANONPROXY_DETECT_URL}/healthz" >/dev/null || {
  echo "ÉCHEC : détecteur absent — lancer services/anonshield/wrapper/run.sh" >&2
  exit 1
}

TEXTE="Bascule vers db-master-01-prod.acmecorp.internal, previens alice.dupont@acmecorp.example."
echo "→ une session anonymise, sans aucune règle"
uv run python tests/policy_e2e_tour.py "${TEXTE}" > "${ETAT}/tour1.txt" || exit 1
cat "${ETAT}/tour1.txt"

echo
echo "→ démarrage de l'API sur la socket"
bash scripts/run-policy-api.sh > "${ETAT}/api.log" 2>&1 &
API_PID=$!
for _ in $(seq 1 200); do [[ -S "${ANONPROXY_API_SOCKET}" ]] && break; sleep 0.1; done
[[ -S "${ANONPROXY_API_SOCKET}" ]] || { echo "ÉCHEC : socket absente"; cat "${ETAT}/api.log"; exit 1; }
sleep 1

rc=0
echo
echo "== 1. l'agent ne peut pas joindre la socket =="
if uv run python -c "
import sys; sys.path.insert(0,'hooks'); import pretooluse_guard as g
cmd = 'curl -s --unix-socket ${ANONPROXY_API_SOCKET} http://x/questions'
raison = g.check_bash(cmd)
print('  refus :', raison)
sys.exit(0 if raison else 1)
"; then echo "OK   : le hook refuse la socket"; else echo "ÉCHEC: l'agent pourrait lire le coffre par l'API"; rc=1; fi

echo
echo "== 2. permissions de la socket =="
PERM=$(stat -c '%a' "${ANONPROXY_API_SOCKET}")
if [[ "${PERM}" == "600" ]]; then
  echo "OK   : socket en 0600"
else
  echo "ÉCHEC: socket en ${PERM} — joignable par un autre utilisateur local"; rc=1
fi

echo
echo "== 3. l'extension parle à l'API (client Node, comme elle) =="
node "${REPO_ROOT}/tests/api_client.js" "${ANONPROXY_API_SOCKET}" \
  > "${ETAT}/node.txt" 2>&1 || { echo "ÉCHEC : le client Node a échoué"; cat "${ETAT}/node.txt"; rc=1; }
cat "${ETAT}/node.txt"

echo
echo "→ la décision prise par l'API s'applique au moteur"
uv run python tests/policy_e2e_tour.py "${TEXTE}" > "${ETAT}/tour2.txt" || exit 1
cat "${ETAT}/tour2.txt"

verifie() {
  if grep -qF -- "$3" "$2"; then trouve=present; else trouve=absent; fi
  if [[ "${trouve}" == "$4" ]]; then echo "OK   : $1"
  else echo "ÉCHEC: $1 (attendu $4, trouvé ${trouve})"; rc=1; fi
}

echo
echo "== Verdict =="
verifie "tour 1 — l'hôte est anonymisé"        "${ETAT}/tour1.txt" "db-master-01-prod.acmecorp.internal" absent
verifie "l'API a montré la valeur RÉELLE"      "${ETAT}/node.txt"  "db-master-01-prod.acmecorp.internal" present
verifie "D4 — révéler un secret est REFUSÉ"    "${ETAT}/node.txt"  "REFUS-SECRET-OK"                     present
verifie "tour 2 — l'hôte arbitré est révélé"   "${ETAT}/tour2.txt" "db-master-01-prod.acmecorp.internal" present
verifie "tour 2 — l'e-mail reste anonymisé"    "${ETAT}/tour2.txt" "alice.dupont@acmecorp.example"       absent

if grep -rqF "acmecorp" "${ANONPROXY_POLICY_DIR}" 2>/dev/null; then
  echo "ÉCHEC: la politique contient une valeur réelle"; rc=1
else
  echo "OK   : la politique ne contient aucune valeur réelle"
fi

echo
[[ ${rc} -eq 0 ]] && echo "**PASS**" || echo "**FAIL**"
exit ${rc}
