"""Addon mitmproxy : capture des CORPS sortants vers l'API modèle (Phase 3).

Complète `inventory_addon.py` (qui ne compte que des octets). Ici on conserve
le corps intégral des requêtes vers api.anthropic.com afin de vérifier, par
recherche littérale, qu'AUCUNE valeur réelle n'a quitté la machine.

Usage :
    mitmdump -s leak_check_addon.py --set leak_dir=captures/<ts>/bodies

Les corps capturés sont ceux du canal 1 uniquement, et la session de test est
100 % synthétique : ce fichier ne doit jamais servir sur du trafic réel sans
décision explicite (il écrit des payloads en clair sur le disque).
"""

import json
import os
import time

from mitmproxy import ctx

MODEL_HOST = "api.anthropic.com"


class LeakCheck:
    def __init__(self):
        self.n = 0

    def load(self, loader):
        loader.add_option(
            name="leak_dir", typespec=str, default="",
            help="Répertoire où écrire les corps de requêtes du canal 1",
        )

    def configure(self, updated):
        if "leak_dir" in updated and ctx.options.leak_dir:
            os.makedirs(ctx.options.leak_dir, exist_ok=True)

    def request(self, flow):
        if not ctx.options.leak_dir:
            return
        if flow.request.host.lower() != MODEL_HOST:
            return
        if not flow.request.path.startswith("/v1/"):
            return

        self.n += 1
        path = flow.request.path.split("?", 1)[0].strip("/").replace("/", "_")
        name = f"{self.n:03d}_{path}.json"
        body = flow.request.raw_content or b""
        meta = {
            "ts": round(time.time(), 3),
            "method": flow.request.method,
            "path": flow.request.path,
            "bytes": len(body),
        }
        with open(os.path.join(ctx.options.leak_dir, name), "wb") as fh:
            fh.write(body)
        with open(os.path.join(ctx.options.leak_dir, "index.jsonl"), "a", encoding="utf-8") as fh:
            fh.write(json.dumps({**meta, "file": name}, ensure_ascii=False) + "\n")


addons = [LeakCheck()]
