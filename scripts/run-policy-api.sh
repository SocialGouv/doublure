#!/usr/bin/env bash
# API locale d'arbitrage, sur une SOCKET UNIX — jamais sur un port.
#
# Un port local serait joignable par l'agent lui-même (`curl` vers le loopback
# passe le hook), et cette API affiche les valeurs RÉELLES : ce serait rouvrir
# la mitigation du gap « coffre local, même utilisateur » (§3.5). La socket est
# refusée par le hook, et son chemin vit dans le répertoire d'état.
#
# Processus SÉPARÉ du proxy : l'arbitrage n'a pas à être disponible pour que la
# pseudonymisation fonctionne, et l'inverse non plus.
#
# Les chemins d'état ne sont PAS répétés ici : `Settings.from_env()` les connaît
# déjà, et deux jeux de valeurs par défaut auraient divergé.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

SOCKET="$(uv run python -c '
import sys
sys.path.insert(0, "src")
from anonproxy.policy_api import chemin_socket
print(chemin_socket())
')" || { echo "configuration illisible" >&2; exit 1; }

mkdir -p "$(dirname "${SOCKET}")"
# Une socket résiduelle d'un processus mort empêcherait le bind.
[[ -S "${SOCKET}" ]] && rm -f "${SOCKET}"

# uvicorn crée la socket en 0666 : tout utilisateur local pourrait s'y
# connecter et lire les valeurs réelles. On la referme dès qu'elle existe.
(
  for _ in $(seq 1 200); do
    [[ -S "${SOCKET}" ]] && { chmod 600 "${SOCKET}"; break; }
    sleep 0.05
  done
) &

echo "→ arbitrage sur ${SOCKET}"
exec uv run python -m uvicorn anonproxy.policy_api:app \
  --uds "${SOCKET}" --workers 1 --log-level warning
