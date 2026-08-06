#!/usr/bin/env bash
# Control service (Go) — arbitration API on a Unix socket.
#
# State paths are NOT repeated here: `Settings.from_env()` already knows them,
# and a second set of defaults would drift. The Go binary has no defaults at
# all, on purpose — it refuses to start rather than read the wrong store.

set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${REPO_ROOT}"

eval "$(uv run python -c '
import sys
sys.path.insert(0, "src")
from anonproxy.config import Settings
s = Settings.from_env()
print(f"export ANONPROXY_VAULT={s.vault_path}")
print(f"export ANONPROXY_MASTER_KEY_FILE={s.master_key_file}")
print(f"export ANONPROXY_POLICY_DIR={s.policy_dir}")
print(f"export ANONPROXY_SCOPE={s.scope_key}")
print(f"export ANONPROXY_API_SOCKET={s.policy_dir.parent}/control.sock")
')" || { echo "unreadable configuration" >&2; exit 1; }

go build -C go -o "${REPO_ROOT}/go/bin/anonproxy-control" ./cmd/anonproxy-control \
  || { echo "build failed" >&2; exit 1; }

echo "-> control service on ${ANONPROXY_API_SOCKET}"
exec "${REPO_ROOT}/go/bin/anonproxy-control"
