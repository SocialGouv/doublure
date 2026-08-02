"""Addon mitmproxy : inventaire d'egress en JSONL (Phase 0).

Chargé par mitmdump (`-s inventory_addon.py --set egress_log=…`). Écrit une
ligne JSON par événement réseau :

  kind="connect" : CONNECT du proxy explicite — la destination est visible
                   même si le client refuse ensuite la CA (TLS non déchiffré).
  kind="http"    : flux HTTP complet — octets de corps sortants/entrants.
                   Le chemin n'est conservé que pour api.anthropic.com
                   (distinguer /v1/messages de count_tokens) : les chemins des
                   autres hôtes ne sont pas nécessaires à l'inventaire.
  kind="error"   : flux en erreur (connexion interrompue, TLS refusée…).

Les corps de réponse sont streamés (compteur au vol) : le SSE d'Anthropic
traverse sans être bufferisé, la session de référence reste représentative.
"""

import json
import logging
import time

from mitmproxy import ctx

MODEL_HOST = "api.anthropic.com"
BYTES_IN_KEY = "egress_bytes_in"


class EgressInventory:
    def __init__(self):
        self._fh = None

    def load(self, loader):
        loader.add_option(
            name="egress_log",
            typespec=str,
            default="",
            help="Chemin du fichier JSONL d'inventaire d'egress",
        )

    def configure(self, updated):
        if "egress_log" in updated and ctx.options.egress_log:
            # line-buffered : rien n'est perdu si mitmdump est tué
            self._fh = open(ctx.options.egress_log, "a", buffering=1, encoding="utf-8")

    def done(self):
        if self._fh:
            self._fh.close()
            self._fh = None

    def _emit(self, **rec):
        if self._fh is None:
            logging.warning("egress_log non configuré : événement perdu")
            return
        rec.setdefault("ts", round(time.time(), 3))
        self._fh.write(json.dumps(rec, ensure_ascii=False) + "\n")

    # -- hooks mitmproxy ---------------------------------------------------- #

    def http_connect(self, flow):
        self._emit(kind="connect", host=flow.request.host, port=flow.request.port)

    def responseheaders(self, flow):
        flow.metadata[BYTES_IN_KEY] = 0

        def _count(chunk: bytes) -> bytes:
            flow.metadata[BYTES_IN_KEY] += len(chunk)
            return chunk

        flow.response.stream = _count

    def response(self, flow):
        req = flow.request
        rec = {
            "kind": "http",
            "host": req.host,
            "port": req.port,
            "method": req.method,
            "bytes_out": len(req.raw_content or b""),
            "bytes_in": flow.metadata.get(BYTES_IN_KEY, 0),
            "status": flow.response.status_code,
            "content_type": flow.response.headers.get("content-type", ""),
        }
        if req.host.lower() == MODEL_HOST:
            rec["path"] = req.path.split("?", 1)[0]
        self._emit(**rec)

    def error(self, flow):
        req = getattr(flow, "request", None)
        self._emit(
            kind="error",
            host=req.host if req else "?",
            port=req.port if req else 0,
            error=str(flow.error) if flow.error else "inconnue",
        )


addons = [EgressInventory()]
