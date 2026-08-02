"""Addon mitmproxy : que contiennent les logs envoyés à Datadog ?

Répond à une question factuelle laissée ouverte en Phase 0 : le binaire Claude
Code envoie ~343 Ko à `http-intake.logs.us5.datadoghq.com` par session. On
savait le VOLUME, pas le CONTENU.

Cet addon capture les corps vers ce seul hôte et en produit une synthèse
STRUCTURELLE : noms de champs, types d'événements, tailles. Les valeurs ne
sont PAS recopiées telles quelles dans le rapport — seuls des extraits
tronqués des champs jugés non sensibles, et un décompte des champs suspects.

Usage :
    mitmdump -s datadog_probe.py --set dd_out=captures/<ts>/datadog

À n'utiliser que sur une session SYNTHÉTIQUE, et à supprimer après analyse :
les corps bruts écrits sur disque sont, eux, non filtrés.
"""

import gzip
import json
import os

from mitmproxy import ctx

TARGET_SUBSTRINGS = ("datadoghq.com", "datadoghq.eu", "ddog-gov.com")


class DatadogProbe:
    def __init__(self):
        self.n = 0

    def load(self, loader):
        loader.add_option(name="dd_out", typespec=str, default="",
                          help="Répertoire de sortie des corps Datadog")

    def configure(self, updated):
        if "dd_out" in updated and ctx.options.dd_out:
            os.makedirs(ctx.options.dd_out, exist_ok=True)

    def request(self, flow):
        if not ctx.options.dd_out:
            return
        host = flow.request.host.lower()
        if not any(s in host for s in TARGET_SUBSTRINGS):
            return

        raw = flow.request.raw_content or b""
        body = raw
        if flow.request.headers.get("content-encoding", "").lower() == "gzip":
            try:
                body = gzip.decompress(raw)
            except OSError:
                pass

        self.n += 1
        path = os.path.join(ctx.options.dd_out, f"{self.n:03d}.json")
        with open(path, "wb") as fh:
            fh.write(body)
        with open(os.path.join(ctx.options.dd_out, "index.jsonl"), "a",
                  encoding="utf-8") as fh:
            fh.write(json.dumps({
                "file": os.path.basename(path),
                "host": host,
                "path": flow.request.path,
                "bytes_wire": len(raw),
                "bytes_plain": len(body),
                "content_type": flow.request.headers.get("content-type", ""),
            }, ensure_ascii=False) + "\n")


addons = [DatadogProbe()]
