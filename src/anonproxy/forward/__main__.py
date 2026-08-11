"""`python -m anonproxy.forward -- <agent> [args…]`

Runs any agent behind the forward proxy: destinations decided by the operator's
list, MCP bodies pseudonymised on the way out and restored on the way back.

The vault, the detector and the surrogate engine are the SAME ones the reverse
proxy uses. Two engines would mean two mappings for one real value, and the
operator would see a session restore half of what it substituted.
"""
from __future__ import annotations

import sys

from ..config import STATE_DIR, Settings, read_master_key
from .jsonrpc import JsonRpcTransform
from .launcher import run


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print("usage: python -m anonproxy.forward -- <commande> [args…]",
              file=sys.stderr)
        return 2

    # Import tardif : monter le proxy inverse coûte le coffre et le détecteur,
    # et `--help` n'a pas à les exiger.
    from ..proxy.app import ProxyState

    etat = ProxyState(Settings.from_env())
    try:
        transform = JsonRpcTransform(
            to_surrogate=etat.pseudonymizer.to_surrogate,
            # `to_real` rend aussi les substituts NON résolus ; le canal n'en
            # fait rien pour l'instant, mais les compter est ce qui distingue
            # un résidu accepté d'un résidu ignoré.
            to_real=lambda texte: etat.incoming().to_real(texte)[0],
        )
        return run(argv, state_dir=STATE_DIR, transform=transform)
    finally:
        etat.vault.close()
        etat.detector.close()


if __name__ == "__main__":
    raise SystemExit(main())
