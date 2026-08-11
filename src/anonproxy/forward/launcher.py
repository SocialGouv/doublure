"""`doublure run -- <any agent>` — the entry point that is not Claude Code.

Everything else in this package is agent-agnostic already: the engine, the
vault, the policy, the arbitration. What was not, until here, is the way a
client is pointed at us — `ANTHROPIC_BASE_URL` names one API of one vendor.

`HTTPS_PROXY` names none. Any runtime that speaks HTTP honours it, which is
what makes one launcher enough for every agent rather than one integration per
agent.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from .ca import InterceptionCA
from .policy import ForwardPolicy
from .proxy import ForwardProxy

#: Les variables que les runtimes lisent réellement. Node ignore le magasin du
#: système et n'a QUE `NODE_EXTRA_CA_CERTS` ; Python et curl ont chacun la
#: leur. En oublier une donne une erreur de confiance que personne ne rattache
#: au proxy — c'est le piège payé dès la Phase 0.
_VARIABLES_CA = ("NODE_EXTRA_CA_CERTS", "SSL_CERT_FILE", "REQUESTS_CA_BUNDLE",
                 "CURL_CA_BUNDLE", "GIT_SSL_CAINFO")


def build_env(base: dict[str, str], ca: InterceptionCA, port: int) -> dict[str, str]:
    """L'environnement à donner à l'agent.

    `NO_PROXY` garde le local DIRECT : le détecteur du projet écoute sur la
    boucle locale, et le faire transiter par le proxy le ferait dépendre de
    lui-même.
    """
    paquet = str(ca.bundle_path())
    adresse = f"http://127.0.0.1:{port}"
    env = dict(base)
    env.update({
        "HTTP_PROXY": adresse, "HTTPS_PROXY": adresse,
        "http_proxy": adresse, "https_proxy": adresse,
        "NO_PROXY": "localhost,127.0.0.1,::1",
        "no_proxy": "localhost,127.0.0.1,::1",
    })
    env.update({nom: paquet for nom in _VARIABLES_CA})
    return env


def run(commande: list[str], *, state_dir: Path, transform=None,
        destinations: Path | None = None) -> int:
    """Démarre le proxy, lance la commande dessous, et l'arrête après.

    Le proxy meurt avec la commande : une interception qui survit à la session
    qu'elle protégeait est une interception que plus personne n'a voulue.
    """
    ca = InterceptionCA(state_dir)
    politique = ForwardPolicy.load(
        destinations or state_dir / "forward-destinations.txt")
    proxy = ForwardProxy(politique, ca, transform=transform)
    proxy.start_in_thread()
    try:
        env = build_env(os.environ, ca, proxy.port)
        return subprocess.run(commande, env=env).returncode
    finally:
        proxy.stop()
        for decision in proxy.decisions:
            print(f"doublure: {decision.destination} -> "
                  f"{decision.verdict.value} ({decision.reason})",
                  file=sys.stderr)
