#!/usr/bin/env bash
# Démarre le service de détection AnonShield (wrapper GPL, port 9000).
#
# - Génère et persiste ANON_SECRET_KEY au premier lancement, dans
#   ${ANONPROXY_STATE_DIR:-~/.doublure/shared}/anon_secret_key
#   (0600, jamais affichée). Cette clé + la base = les deux moitiés du
#   secret : sauvegarder le dossier, le perdre rend la dé-anonymisation
#   impossible.
# - Premier démarrage : télécharge le modèle NER depuis Hugging Face
#   (~/.cache/huggingface). Démarrages suivants : hors-ligne.

set -euo pipefail

WRAPPER_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UPSTREAM="$(cd "${WRAPPER_DIR}/../upstream" && pwd)"
STATE_DIR="${ANONPROXY_STATE_DIR:-${HOME}/.doublure/shared}"
KEY_FILE="${STATE_DIR}/anon_secret_key"
PORT="${ANON_WRAPPER_PORT:-9000}"

umask 077
mkdir -p "${STATE_DIR}"
if [[ ! -f "${KEY_FILE}" ]]; then
  openssl rand -hex 32 > "${KEY_FILE}"
  echo "→ ANON_SECRET_KEY générée et persistée (${KEY_FILE}, 0600) — non affichée"
fi

export ANON_SECRET_KEY_FILE="${KEY_FILE}"
export TOKENIZERS_PARALLELISM=false

# .venv/bin/python DIRECT, pas `uv run` : uv run re-synchroniserait le venv
# sur le lock (wheels CPU) et écraserait la déviation CUDA d'install-cuda.sh.
cd "${UPSTREAM}"
exec env PYTHONPATH="${UPSTREAM}" "${UPSTREAM}/.venv/bin/python" -m uvicorn \
  --app-dir "${WRAPPER_DIR}" app:app \
  --host 127.0.0.1 --port "${PORT}" --workers 1 --log-level info
