#!/usr/bin/env python3
"""Un tour de pseudonymisation, chaîne réelle, pour `policy_e2e.sh`.

Monte exactement ce que monte le proxy — détecteur, coffre, politique,
moteur — et imprime le texte tel qu'il PARTIRAIT. Rien n'est simulé : c'est le
même `Pseudonymizer` que celui du chemin de requête.
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from anonproxy.allowlist import Allowlist  # noqa: E402
from anonproxy.config import Settings, read_master_key  # noqa: E402
from anonproxy.detect import DetectClient, DetectionUnavailable  # noqa: E402
from anonproxy.pipeline import Pseudonymizer  # noqa: E402
from anonproxy.policy import Policy  # noqa: E402
from anonproxy.surrogates.engine import SurrogateEngine  # noqa: E402
from anonproxy.vault import Vault  # noqa: E402


def main() -> int:
    texte = sys.argv[1]
    reglages = Settings.from_env()
    master = read_master_key(reglages.master_key_file)
    politique = Policy(racine=reglages.policy_dir, master_key=master,
                       scope_key=reglages.scope_key, session=reglages.session_id)
    moteur = SurrogateEngine(
        vault=Vault(reglages.vault_path, master_key=master),
        master_key=master, scope_key=reglages.scope_key,
        is_public=Allowlist.load(reglages.allowlist_file).is_exact,
        policy=politique,
    )
    detecteur = DetectClient(reglages.detect_url,
                             regex_threshold=reglages.regex_threshold)
    try:
        sortie = Pseudonymizer(detecteur, moteur).to_surrogate(texte)
    except DetectionUnavailable as exc:
        print(f"détecteur indisponible : {exc}", file=sys.stderr)
        return 1
    print(sortie)
    return 0


if __name__ == "__main__":
    sys.exit(main())
