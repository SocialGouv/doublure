#!/usr/bin/env python3
"""Migre un coffre au format « valeurs en clair » vers le format chiffré.

Le coffre ne peut pas être simplement recréé : les substituts déjà envoyés à
Anthropic ne seraient plus restaurables, et les tours suivants d'une
conversation en cours cesseraient d'être compris.

Le fichier d'origine n'est pas modifié — la nouvelle base est écrite à côté.

Usage :
    uv run python scripts/migrate_vault.py ANCIEN.db NOUVEAU.db
    # la clé maître est lue via ANONPROXY_MASTER_KEY_FILE, jamais affichée
"""
from __future__ import annotations

import os
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from anonproxy.config import STATE_DIR, read_master_key  # noqa: E402
from anonproxy.vault import SurrogateConflict, Vault  # noqa: E402


def main() -> int:
    if len(sys.argv) != 3:
        print(__doc__)
        return 2
    ancien, nouveau = Path(sys.argv[1]), Path(sys.argv[2])
    if not ancien.exists():
        print(f"coffre source introuvable : {ancien}", file=sys.stderr)
        return 1
    if nouveau.exists():
        print(f"la cible existe déjà : {nouveau} — refus d'écraser", file=sys.stderr)
        return 1

    key_file = Path(os.environ.get("ANONPROXY_MASTER_KEY_FILE", STATE_DIR / "anon_secret_key"))
    master = read_master_key(key_file)  # jamais journalisée

    src = sqlite3.connect(ancien)
    colonnes = {r[1] for r in src.execute("PRAGMA table_info(mapping)")}
    if "real" not in colonnes:
        print("ce coffre est déjà au format chiffré — rien à faire", file=sys.stderr)
        return 1

    cible = Vault(nouveau, master_key=master)
    lus = ecrits = conflits = 0
    for scope, etype, real, surrogate in src.execute(
        "SELECT scope, etype, real, surrogate FROM mapping"
    ):
        lus += 1
        try:
            cible.bind(scope, etype, real, surrogate)
            ecrits += 1
        except SurrogateConflict:
            # Ne devrait pas arriver : la source portait déjà la contrainte.
            conflits += 1
            print(f"conflit ignoré : portée={scope!r} type={etype!r}", file=sys.stderr)
    cible.close()
    src.close()

    print(f"{lus} correspondance(s) lues, {ecrits} écrites, {conflits} conflit(s).")
    print(f"Nouveau coffre : {nouveau} (0600)")
    print("Vérifier, puis remplacer l'ancien. Le conserver hors ligne le temps "
          "de valider : sans lui ni la clé, rien n'est restaurable.")
    return 0 if conflits == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
