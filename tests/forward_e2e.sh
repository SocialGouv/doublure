#!/usr/bin/env bash
# Preuve de bout en bout du MODE SORTANT.
#
# Le seul mécanisme livré que rien n'avait éprouvé en usage. Les tests montrent
# que l'interception fonctionne contre un client qui ne croit que notre
# autorité ; ils ne montrent pas qu'un AGENT RÉEL travaille dessous.
#
# La question à laquelle ce script répond : un agent lancé par
# `python -m anonproxy.forward` fait-il son travail, et le proxy voit-il
# réellement passer ses destinations ?
#
# Tout est SYNTHÉTIQUE et vit dans un répertoire d'état temporaire : ni le
# coffre ni la clé de l'opérateur ne sont touchés.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

ETAT="$(mktemp -d -t doublure-forward-XXXXXX)"
trap 'rm -rf "${ETAT}"' EXIT

export ANONPROXY_STATE_DIR="${ETAT}"
export ANONPROXY_POLICY_DIR="${ETAT}/politique"
export ANONPROXY_VAULT="${ETAT}/coffre.db"
export ANONPROXY_MASTER_KEY_FILE="${ETAT}/cle"
export ANONPROXY_SCOPE="project:preuve-forward"
openssl rand -hex 32 > "${ANONPROXY_MASTER_KEY_FILE}"
chmod 600 "${ANONPROXY_MASTER_KEY_FILE}"

# La liste des destinations vit dans le répertoire d'état, hors de portée de
# l'agent — c'est la règle, et ce script la respecte plutôt que de la
# contourner. `api.anthropic.com` est TUNNELÉ : le canal 1 a son propre proxy,
# et l'inspecter ici appliquerait l'adaptateur JSON-RPC à des corps qui n'en
# sont pas.
cat > "${ETAT}/forward-destinations.txt" <<'FIN'
tunnel api.anthropic.com
tunnel statsig.anthropic.com
FIN

echo "→ répertoire d'état : ${ETAT}"
echo "→ destinations déclarées :"
sed 's/^/     /' "${ETAT}/forward-destinations.txt"
echo

echo "→ session Claude Code SOUS le proxy sortant…"
SORTIE="${ETAT}/reponse.txt"
uv run python -m anonproxy.forward -- \
  claude -p "Réponds exactement: MODE-SORTANT-OK" --max-turns 3 \
  > "${SORTIE}" 2> "${ETAT}/decisions.txt"
RC_CLAUDE=$?

echo "   code retour : ${RC_CLAUDE}"
echo
echo "== Réponse du modèle =="
cat "${SORTIE}"
echo
echo "== Décisions du proxy sortant =="
grep -c . "${ETAT}/decisions.txt" >/dev/null 2>&1 && cat "${ETAT}/decisions.txt" || echo "(aucune)"

echo
echo "== Verdict =="
rc=0
if grep -q "MODE-SORTANT-OK" "${SORTIE}"; then
  echo "OK   : l'agent a travaillé sous le proxy sortant"
else
  echo "ÉCHEC: l'agent n'a pas abouti — la chaîne ne le laisse pas travailler"
  rc=1
fi

# La preuve que le proxy a bien vu passer le trafic : sans elle, un agent qui
# ignorerait HTTPS_PROXY donnerait exactement le même succès.
if grep -q "api.anthropic.com" "${ETAT}/decisions.txt"; then
  echo "OK   : le trafic du modèle est PASSÉ par le proxy sortant"
else
  echo "ÉCHEC: aucune décision sur api.anthropic.com — l'agent a contourné"
  echo "       le proxy, et le succès ci-dessus ne prouve rien"
  rc=1
fi

# LA propriété que ce mode existe pour donner. La Phase 0 avait mesuré que
# quatre destinations sur cinq échappent à `ANTHROPIC_BASE_URL` ; ici elles
# doivent se heurter à un refus, sans qu'aucune socket ne s'ouvre — et la
# session doit tout de même aboutir, sinon le point de passage est un mur.
ECHAPPAIENT=0
for d in api.githubcopilot.com mcp.context7.com registry.npmjs.org; do
  if grep -q "${d}.*refuse" "${ETAT}/decisions.txt"; then
    ECHAPPAIENT=$((ECHAPPAIENT + 1))
  fi
done
if [[ ${ECHAPPAIENT} -ge 1 ]]; then
  echo "OK   : ${ECHAPPAIENT} destination(s) qui ÉCHAPPAIENT au proxy sont refusées"
  grep "refuse" "${ETAT}/decisions.txt" | sed 's/^/         /'
else
  echo "NOTE : aucune destination tierce sollicitée pendant cette session —"
  echo "       le refus par défaut n'est donc pas exercé par cette exécution"
fi

echo
[[ ${rc} -eq 0 ]] && echo "**PASS**" || echo "**FAIL**"
exit ${rc}
