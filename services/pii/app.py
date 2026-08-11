"""Personal-data detection service — the class the cyber NER does not have.

A separate process for two reasons, neither of them licensing:

- the model needs `transformers >= 5`, and the AnonShield virtualenv is pinned
  and fragile — installing it there breaks the detector that already works;
- it is Apache-2.0, so it must NOT live inside the GPL wrapper.

It is the same shape as the other detector: `/detect` returns spans, `/healthz`
says whether the model is loaded. What it does not do is decide anything — the
proxy composes the two streams and the engine arbitrates overlaps.
"""
from __future__ import annotations

import logging
import os
import threading
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("doublure.pii")

MODEL = os.environ.get("DOUBLURE_PII_MODEL", "openai/privacy-filter")
#: Le modèle rend des étiquettes `private_*`. On les laisse telles quelles :
#: la correspondance vers nos types est une décision du CLIENT, et la dupliquer
#: ici ferait deux endroits où la changer.
_LOCK = threading.Lock()
_ENGINE: dict = {"ready": False}

app = FastAPI(title="doublure-pii")


class Entree(BaseModel):
    text: str


def _charger() -> None:
    if _ENGINE.get("ready"):
        return
    debut = time.perf_counter()
    from transformers import (AutoModelForTokenClassification, AutoTokenizer,
                              pipeline)

    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    modele = AutoModelForTokenClassification.from_pretrained(MODEL)
    ner = pipeline("token-classification", model=modele, tokenizer=tokenizer,
                   aggregation_strategy="simple")
    # Chauffe réelle : le premier appel paie le graphe, et le payer sur la
    # première requête d'une session la ferait passer pour lente.
    ner("Jean Dupont, 12 rue de la Paix, le 3 février 2026.")
    _ENGINE.update(ready=True, ner=ner,
                   loaded_in_s=round(time.perf_counter() - debut, 1),
                   loaded_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    logger.info("modèle prêt : %s en %ss", MODEL, _ENGINE["loaded_in_s"])


@app.on_event("startup")
def _demarrage() -> None:
    _charger()


@app.get("/healthz")
def healthz() -> dict:
    if not _ENGINE.get("ready"):
        raise HTTPException(status_code=503, detail="modèle non chargé")
    return {"status": "ok", "model": MODEL,
            "loaded_in_s": _ENGINE["loaded_in_s"],
            "loaded_at": _ENGINE["loaded_at"], "pid": os.getpid()}


@app.post("/detect")
def detect(entree: Entree) -> dict:
    if not _ENGINE.get("ready"):
        raise HTTPException(status_code=503, detail="modèle non chargé")
    t0 = time.perf_counter()
    # Sérialisé : le pipeline transformers n'est pas garanti réentrant, et deux
    # requêtes concurrentes rendraient des offsets entremêlés.
    with _LOCK:
        spans = _ENGINE["ner"](entree.text)
    return {
        "entities": [
            {"type": s["entity_group"], "value": s["word"],
             "start": int(s["start"]), "end": int(s["end"]),
             "score": round(float(s["score"]), 4)}
            for s in spans
        ],
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
