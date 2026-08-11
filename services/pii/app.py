"""Personal-data detection service — the class the cyber NER does not have.

A separate process for two reasons, neither of them licensing:

- the model needs its own heavy dependencies, and the AnonShield virtualenv is
  pinned and fragile — installing there breaks the detector that already works;
- it is Apache-2.0, so it must NOT live inside the GPL wrapper.

**Why GLiNER and not a fixed-label classifier.** The first model shipped here
returned two of the three people in a real incident file, and the third was
only recovered by submitting its line alone — five times the latency. GLiNER
takes its types in natural language at inference time, and asking it for
`address` rather than `postal address` is the difference between finding the
address and not: measured, 3/3 people and the address in ONE span, at 249 ms
against 315 ms for two thirds of the same job.

It also returns whole entities instead of subword fragments, which turns the
reassembly on the client side from a necessity into a safety net.
"""
from __future__ import annotations

import logging
import os
import threading
import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("doublure.pii")

MODEL = os.environ.get("DOUBLURE_PII_MODEL", "urchade/gliner_multi_pii-v1")
#: Les types sont posés en langage naturel. Leur formulation DÉCIDE : mesuré,
#: `postal address` ne trouve pas ce que `address` trouve, sur le même texte et
#: le même modèle. Les changer sans mesurer revient à changer le détecteur.
LABELS = [l.strip() for l in os.environ.get(
    "DOUBLURE_PII_LABELS", "person,date,address").split(",") if l.strip()]
SEUIL = float(os.environ.get("DOUBLURE_PII_THRESHOLD", "0.4"))

_LOCK = threading.Lock()
_ENGINE: dict = {"ready": False}

app = FastAPI(title="doublure-pii")


class Entree(BaseModel):
    text: str


def _charger() -> None:
    if _ENGINE.get("ready"):
        return
    debut = time.perf_counter()
    from gliner import GLiNER

    modele = GLiNER.from_pretrained(MODEL)
    # Chauffe réelle : le premier appel paie le graphe, et le payer sur la
    # première requête d'une session la ferait passer pour lente.
    modele.predict_entities("Jean Dupont, 12 rue de la Paix, le 3 février 2026.",
                            LABELS, threshold=SEUIL)
    _ENGINE.update(ready=True, modele=modele,
                   loaded_in_s=round(time.perf_counter() - debut, 1),
                   loaded_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    logger.info("modèle prêt : %s en %ss, types %s",
                MODEL, _ENGINE["loaded_in_s"], LABELS)


@app.on_event("startup")
def _demarrage() -> None:
    _charger()


@app.get("/healthz")
def healthz() -> dict:
    if not _ENGINE.get("ready"):
        raise HTTPException(status_code=503, detail="modèle non chargé")
    return {"status": "ok", "model": MODEL, "labels": LABELS,
            "threshold": SEUIL, "loaded_in_s": _ENGINE["loaded_in_s"],
            "loaded_at": _ENGINE["loaded_at"], "pid": os.getpid()}


@app.post("/detect")
def detect(entree: Entree) -> dict:
    if not _ENGINE.get("ready"):
        raise HTTPException(status_code=503, detail="modèle non chargé")
    t0 = time.perf_counter()
    # Sérialisé : le modèle n'est pas garanti réentrant, et deux requêtes
    # concurrentes rendraient des offsets entremêlés.
    with _LOCK:
        spans = _ENGINE["modele"].predict_entities(
            entree.text, LABELS, threshold=SEUIL)
    return {
        "entities": [
            {"type": s["label"], "value": s["text"],
             "start": int(s["start"]), "end": int(s["end"]),
             "score": round(float(s["score"]), 4)}
            for s in spans
        ],
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
