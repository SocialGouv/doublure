#!/usr/bin/env bash
# Démarre le proxy de pseudonymisation (canal 1), port 8090 par défaut.
# Prérequis : le service de détection tourne (wrapper/run.sh, port 9000).
#
# Branchement client :  ANTHROPIC_BASE_URL=http://127.0.0.1:8090 claude

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
STATE_DIR="${ANONPROXY_STATE_DIR:-${HOME}/.local/state/anonproxy}"

export ANONPROXY_SCOPE="${ANONPROXY_SCOPE:-project:$(basename "${REPO_ROOT}")}"
export ANONPROXY_MASTER_KEY_FILE="${ANONPROXY_MASTER_KEY_FILE:-${STATE_DIR}/anon_secret_key}"
export ANONPROXY_VAULT="${ANONPROXY_VAULT:-${STATE_DIR}/vault.db}"

if [[ ! -f "${ANONPROXY_MASTER_KEY_FILE}" ]]; then
  echo "clé maître absente — lancer d'abord services/anonshield/wrapper/run.sh" >&2
  exit 1
fi

cd "${REPO_ROOT}"
exec uv run python -m uvicorn anonproxy.proxy.app:app \
  --host "${ANONPROXY_HOST:-127.0.0.1}" --port "${ANONPROXY_PORT:-8090}" \
  --workers 1 --log-level info
