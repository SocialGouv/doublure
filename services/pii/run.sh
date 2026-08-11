#!/usr/bin/env bash
# Detection service for personal data — port 9100.
#
# Its own virtualenv, deliberately. The model brings its own heavy stack, and
# the AnonShield environment is pinned and fragile: installing it there breaks
# the detector that already works. That trap is documented in CLAUDE.md and it
# has been paid.
set -euo pipefail

SERVICE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VENV="${SERVICE_DIR}/.venv"
PORT="${DOUBLURE_PII_PORT:-9100}"

if [[ ! -x "${VENV}/bin/python" ]]; then
  echo "→ création du venv du service (gliner, torch)…"
  uv venv "${VENV}" --python 3.12
  uv pip install --python "${VENV}/bin/python" \
    gliner torch fastapi "uvicorn[standard]"
fi

# `.venv/bin/python` DIRECT, jamais `uv run` : `uv run` resynchronise
# l'environnement du PROJET et remplacerait ces dépendances par celles du lock.
exec "${VENV}/bin/python" -m uvicorn app:app \
  --app-dir "${SERVICE_DIR}" --host 127.0.0.1 --port "${PORT}"
