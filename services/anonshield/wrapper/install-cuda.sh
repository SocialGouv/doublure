#!/usr/bin/env bash
# Déviation documentée (décision jo 2026-08-02, blocage Phase 1) : l'upstream
# épingle torch CPU dans uv.lock ; on installe torch CUDA + fastapi/uvicorn
# localement dans le venv upstream.
#
# PIÈGE uv : `uv sync` ET `uv run` (qui sync implicitement) RESTAURENT les
# wheels CPU du lock et retirent fastapi/uvicorn. Donc :
#   - ré-exécuter CE script après tout `uv sync`/`uv run` dans upstream/ ;
#   - ne jamais lancer le service via `uv run` → run.sh utilise
#     .venv/bin/python directement.

set -euo pipefail
UPSTREAM="$(cd "$(dirname "${BASH_SOURCE[0]}")/../upstream" && pwd)"
VENV_PY="${UPSTREAM}/.venv/bin/python"
cd "${UPSTREAM}"

# --reinstall : sans lui, uv considère torch==2.13.0 satisfait par le wheel
# +cpu du lock et n'installe rien.
uv pip install --reinstall --index-url https://download.pytorch.org/whl/cu130 \
  torch==2.13.0 torchvision
uv pip install fastapi 'uvicorn[standard]'

"${VENV_PY}" - <<'EOF'
import torch, fastapi, uvicorn
assert torch.cuda.is_available(), f"CUDA indisponible (torch {torch.__version__})"
print(f"torch {torch.__version__} | CUDA OK : {torch.cuda.get_device_name(0)}")
print(f"fastapi {fastapi.__version__} | uvicorn {uvicorn.__version__}")
EOF
