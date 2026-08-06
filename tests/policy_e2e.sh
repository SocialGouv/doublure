#!/usr/bin/env bash
# Preuve de bout en bout de la politique de confidentialité.
#
# Le scénario est celui que décrit la demande : le système est fermé, il
# anonymise tout et CONSIGNE une question ; l'opérateur y répond une fois ; à
# partir de là, et seulement à partir de là, la valeur sort en clair.
#
# Chaîne réelle : détecteur AnonShield :9000 → pipeline → moteur → coffre,
# puis la CLI d'arbitrage, puis le même texte rejoué.
#
# Tout est SYNTHÉTIQUE et vit dans un répertoire temporaire : ni le coffre ni
# la clé de l'opérateur ne sont touchés.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

DETECT_PORT="${DETECT_PORT:-9000}"
ETAT="$(mktemp -d -t anonproxy-politique-XXXXXX)"
trap 'rm -rf "${ETAT}"' EXIT

export ANONPROXY_STATE_DIR="${ETAT}"
export ANONPROXY_POLICY_DIR="${ETAT}/politique"
export ANONPROXY_VAULT="${ETAT}/coffre-essai.db"
export ANONPROXY_MASTER_KEY_FILE="${ETAT}/cle-essai"
export ANONPROXY_SCOPE="project:preuve-politique"
export ANONPROXY_DETECT_URL="http://127.0.0.1:${DETECT_PORT}"
openssl rand -hex 32 > "${ANONPROXY_MASTER_KEY_FILE}"
chmod 600 "${ANONPROXY_MASTER_KEY_FILE}"

TEXTE="Bascule le trafic de db-master-01-prod.acmecorp.internal vers 10.1.2.4 le 3 fevrier 2026, et previens alice.dupont@acmecorp.example."

echo "→ détecteur"
curl -sf -m 5 "http://127.0.0.1:${DETECT_PORT}/healthz" >/dev/null || {
  echo "ÉCHEC : détecteur absent sur :${DETECT_PORT} — lancer services/anonshield/wrapper/run.sh" >&2
  exit 1
}

echo "→ tour 1 : rien n'est réglé, tout doit être anonymisé"
uv run python tests/policy_e2e_tour.py "${TEXTE}" > "${ETAT}/tour1.txt" || exit 1
cat "${ETAT}/tour1.txt"

echo
echo "→ questions consignées (la file ne porte que des substituts)"
uv run python scripts/anonproxy_policy.py questions | tee "${ETAT}/questions.txt"

echo
echo "→ arbitrage : « les adresses IP en général : révéler », portée projet"
uv run python scripts/anonproxy_policy.py definir projet type IP_ADDRESS reveler

echo
echo "→ tour 2 : l'IP sort en clair, le reste NON"
uv run python tests/policy_e2e_tour.py "${TEXTE}" > "${ETAT}/tour2.txt" || exit 1
cat "${ETAT}/tour2.txt"

echo
echo "→ arbitrage interactif, réponse « v » (révéler CETTE valeur), portée session"
uv run python scripts/anonproxy_policy.py arbitrer --portee session --repondre v \
  | grep -E "^\[|valeur réelle|→ révéler|⚠"

AUTRE="Le noeud db-replica-99-prod.acmecorp.internal est hors rotation."
echo
echo "→ tour 3 : les valeurs arbitrées sortent, une NOUVELLE du même type non"
uv run python tests/policy_e2e_tour.py "${TEXTE}" > "${ETAT}/tour3.txt" || exit 1
uv run python tests/policy_e2e_tour.py "${AUTRE}" > "${ETAT}/tour3b.txt" || exit 1
cat "${ETAT}/tour3.txt" "${ETAT}/tour3b.txt"

echo
echo "→ état de la politique"
uv run python scripts/anonproxy_policy.py etat

echo
echo "== Verdict =="
rc=0
verifie() {  # libellé, fichier, motif, attendu(present|absent)
  if grep -qF -- "$3" "$2"; then trouve=present; else trouve=absent; fi
  if [[ "${trouve}" == "$4" ]]; then
    echo "OK   : $1"
  else
    echo "ÉCHEC: $1 (attendu ${4}, trouvé ${trouve})"
    rc=1
  fi
}

verifie "tour 1 — l'hôte est anonymisé"       "${ETAT}/tour1.txt" "db-master-01-prod.acmecorp.internal" absent
verifie "tour 1 — l'IP est anonymisée"        "${ETAT}/tour1.txt" "10.1.2.4"                            absent
verifie "tour 1 — l'e-mail est anonymisé"     "${ETAT}/tour1.txt" "alice.dupont@acmecorp.example"       absent
verifie "questions — l'opérateur voit le réel" "${ETAT}/questions.txt" "db-master-01-prod.acmecorp.internal" present
verifie "tour 2 — l'IP est RÉVÉLÉE"           "${ETAT}/tour2.txt" "10.1.2.4"                            present
verifie "tour 2 — l'hôte reste anonymisé"     "${ETAT}/tour2.txt" "db-master-01-prod.acmecorp.internal" absent
verifie "tour 2 — l'e-mail reste anonymisé"   "${ETAT}/tour2.txt" "alice.dupont@acmecorp.example"       absent
verifie "tour 3 — l'hôte arbitré est révélé"  "${ETAT}/tour3.txt" "db-master-01-prod.acmecorp.internal" present
verifie "tour 3 — l'e-mail arbitré est révélé" "${ETAT}/tour3.txt" "alice.dupont@acmecorp.example"      present
verifie "tour 3 — un AUTRE hôte reste anonymisé" "${ETAT}/tour3b.txt" "db-replica-99-prod.acmecorp.internal" absent

# --------------------------------------------------------------------------- #
# TROU DE DÉTECTION, trouvé par ce script même — pas par une revue.
#
# Le détecteur ne rend AUCUN span pour une date, sous aucune forme : ni
# « 3 fevrier 2026 », ni « 03/02/2026 », ni ISO 8601, ni une date de naissance
# en contexte explicite. `DATE`/`DATE_TIME` n'existe nulle part dans la table
# des classes. Une date sort donc en clair SANS entrée de coffre et SANS
# question — le mode d'échec silencieux, celui que tout le reste du système
# évite.
#
# La politique ne peut pas gouverner ce qui n'est pas détecté : c'est
# précisément l'exemple qui a motivé cette couche. Les deux modèles mesurés
# (`bench_privacy_filter.py`, `bench_gliner.py`) attrapent la date, chacun
# à 1.00 — le correctif est un choix de détecteur, pas de politique.
#
# Cette vérification est écrite à l'ENVERS : elle constate le trou. Le jour où
# il est comblé, elle ÉCHOUE — et c'est le signal attendu.
# --------------------------------------------------------------------------- #
if grep -qF -- "3 fevrier 2026" "${ETAT}/tour1.txt"; then
  echo "TROU : la date sort en clair — non détectée (attendu tant qu'aucun"
  echo "       détecteur de dates n'est en place ; cf. commentaire ci-dessus)"
else
  echo "ÉCHEC: la date est désormais traitée — retirer ce constat du script"
  rc=1
fi

# La politique ne doit contenir aucune valeur réelle, jamais.
if grep -rqF "acmecorp" "${ANONPROXY_POLICY_DIR}" 2>/dev/null; then
  echo "ÉCHEC: la politique contient une valeur réelle"; rc=1
else
  echo "OK   : la politique ne contient aucune valeur réelle"
fi

echo
[[ ${rc} -eq 0 ]] && echo "**PASS**" || echo "**FAIL**"
exit ${rc}
