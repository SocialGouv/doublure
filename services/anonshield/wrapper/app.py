# SPDX-License-Identifier: GPL-3.0-or-later
"""Wrapper HTTP synchrone minimal autour d'AnonShield : POST /detect.

Côté GPL de la frontière D7 : ce module importe ``src.anon`` (GPL-3.0) et le
reste du projet ne le joint QUE via HTTP. Ne jamais l'importer depuis
``src/anonproxy``.

- Le modèle NER est chargé UNE fois au démarrage (lifespan) et reste résident.
- ``POST /detect`` est synchrone : stratégie ``filtered`` (NER transformer +
  recognizers regex) par défaut, ``regex`` (sans NER) pour les gros volumes.
- ``ANON_SECRET_KEY_FILE`` doit être posé par run.sh AVANT l'import de
  src.anon (src.anon.config lit la clé à l'import). La clé n'est jamais lue
  ni affichée ici.

Démarrage : services/anonshield/wrapper/run.sh
"""
from __future__ import annotations

import json
import logging
import os
import re
import threading
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

logger = logging.getLogger("anonshield.wrapper")

WRAPPER_DIR = Path(__file__).resolve().parent
MODEL = os.environ.get("ANON_TRANSFORMER_MODEL", "attack-vector/SecureModernBERT-NER")
LANG = "en"
#: Configuration en terrain NEUTRE : le moteur de substituts la lit aussi, pour
#: que « ce qui est public » ne soit maintenu qu'à un seul endroit.
CONFIG_DIR = WRAPPER_DIR.parents[2] / "config"
ALLOWLIST_FILE = Path(os.environ.get("ANON_ALLOWLIST_FILE", CONFIG_DIR / "allowlist.txt"))
CUSTOM_PATTERNS_FILE = Path(
    os.environ.get("ANON_CUSTOM_PATTERNS_FILE", CONFIG_DIR / "custom_patterns.json")
)

# État module : rempli une seule fois par _load_engine() au startup.
_LOCK = threading.Lock()  # presidio/spacy non garantis thread-safe → sérialisation
_ENGINE: dict = {"ready": False}


# --------------------------------------------------------------------------- #
# Configuration : allowlist et custom patterns
# --------------------------------------------------------------------------- #


def _load_allowlist(path: Path) -> tuple[list[str], list[re.Pattern[str]]]:
    """Deux formes de lignes : chaîne exacte, ou ``re:<regex>`` (full-match)."""
    exact: list[str] = []
    patterns: list[re.Pattern[str]] = []
    if not path.exists():
        raise FileNotFoundError(f"allowlist introuvable : {path}")
    for lineno, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("re:"):
            try:
                patterns.append(re.compile(line[3:]))
            except re.error as exc:
                raise ValueError(f"{path}:{lineno} — regex allowlist invalide : {exc}") from exc
        else:
            exact.append(line)
    return exact, patterns


def _load_custom_patterns(path: Path) -> list[dict]:
    """[{entity_type, pattern, score}] ; les clés préfixées `_` sont ignorées."""
    if not path.exists():
        raise FileNotFoundError(f"custom patterns introuvables : {path}")
    raw = json.loads(path.read_text(encoding="utf-8"))
    out = []
    for i, p in enumerate(raw):
        if not isinstance(p, dict) or "pattern" not in p:
            raise ValueError(f"{path}[{i}] — entrée invalide (clé 'pattern' requise)")
        out.append(
            {
                "entity_type": p.get("entity_type", "CUSTOM"),
                "pattern": p["pattern"],
                "score": float(p.get("score", 0.85)),
            }
        )
    return out


def _place_model(analyzer) -> str:
    """Place le modèle NER sur le device demandé (ANON_DEVICE=auto|cuda|cpu).

    Presidio n'expose pas de réglage de device : le pipeline HF vit dans le
    composant spacy de spacy_huggingface_pipelines (attribut ``hf_pipeline``),
    on le déplace après chargement. ``ANON_DEVICE=cuda`` exige CUDA — échec
    explicite plutôt que fallback silencieux.
    """
    import torch

    want = os.environ.get("ANON_DEVICE", "auto")
    if want == "auto":
        device = "cuda" if torch.cuda.is_available() else "cpu"
    elif want == "cuda":
        if not torch.cuda.is_available():
            raise RuntimeError("ANON_DEVICE=cuda mais torch.cuda.is_available()=False")
        device = "cuda"
    elif want == "cpu":
        device = "cpu"
    else:
        raise RuntimeError(f"ANON_DEVICE invalide : {want!r} (attendu auto|cuda|cpu)")

    if device == "cuda":
        moved = 0
        for lang_nlp in analyzer.nlp_engine.nlp.values():
            for _name, comp in lang_nlp.components:
                hf = getattr(comp, "hf_pipeline", None)
                if hf is not None:
                    hf.model.to("cuda")
                    hf.device = torch.device("cuda")
                    moved += 1
        if moved == 0:
            raise RuntimeError(
                "aucun composant HF (hf_pipeline) trouvé à déplacer sur CUDA — "
                "structure presidio/spacy inattendue"
            )
        logger.info("modèle NER sur CUDA (%d composant(s) déplacé(s))", moved)
    return device


# --------------------------------------------------------------------------- #
# Chargement du moteur (une fois, au startup)
# --------------------------------------------------------------------------- #


def _load_engine() -> None:
    if not os.environ.get("ANON_SECRET_KEY_FILE") and not os.environ.get("ANON_SECRET_KEY"):
        raise RuntimeError(
            "ANON_SECRET_KEY_FILE non défini — lance ce service via run.sh "
            "(src.anon.config exige la clé à l'import)."
        )

    t0 = time.perf_counter()
    allow_exact, allow_patterns = _load_allowlist(ALLOWLIST_FILE)
    custom_patterns = _load_custom_patterns(CUSTOM_PATTERNS_FILE)

    # Imports src.anon APRÈS la mise en place de l'environnement.
    from presidio_analyzer import Pattern, PatternRecognizer

    from src.anon.api import get_supported_entities
    from src.anon.config import NerDefaults
    from src.anon.engine import AnonymizationOrchestrator, load_custom_recognizers
    from src.anon.entity_detector import EntityDetector

    threshold = float(os.environ.get("ANON_SCORE_THRESHOLD", NerDefaults.SCORE_THRESHOLD))

    # Détecteur regex-only (stratégie "regex", sans NER) : recognizers fournis
    # + custom patterns, compilés comme le fait src.anon.api.anonymize_file.
    compiled: list[dict] = []
    for recognizer in load_custom_recognizers([LANG]):
        etype = recognizer.supported_entities[0]
        for pattern in recognizer.patterns:
            try:
                compiled.append(
                    {
                        "label": etype,
                        "regex": re.compile(pattern.regex, flags=re.DOTALL | re.IGNORECASE),
                        "score": pattern.score,
                    }
                )
            except re.error:
                logger.warning("regex fournie invalide ignorée (%s)", etype)
    custom_types: set[str] = set()
    for p in custom_patterns:
        custom_types.add(p["entity_type"])
        compiled.append(
            {
                "label": p["entity_type"],
                "regex": re.compile(p["pattern"], flags=re.IGNORECASE),
                "score": p["score"],
            }
        )
    detector = EntityDetector(
        compiled_patterns=compiled,
        entities_to_preserve=set(),
        allow_list=set(allow_exact),
        entity_mapping=None,
    )

    # Orchestrateur "filtered" : construit TransformersNlpEngine (modèle résident,
    # cache module _ENGINE_CACHE côté src.anon) + recognizers regex.
    orch = AnonymizationOrchestrator(
        lang=LANG,
        db_context=None,
        allow_list=allow_exact,
        entities_to_preserve=[],
        strategy_name="filtered",
        entity_detector=detector,
        transformer_model=MODEL,
        ner_score_threshold=threshold,
    )
    analyzer = orch.analyzer_engine.analyzer_engine  # AnalyzerEngine presidio (scores)

    # Custom patterns aussi côté presidio (stratégie "filtered").
    for p in custom_patterns:
        analyzer.registry.add_recognizer(
            PatternRecognizer(
                supported_entity=p["entity_type"],
                patterns=[Pattern(name=p["entity_type"], regex=p["pattern"], score=p["score"])],
            )
        )

    # Périmètre "filtered" : types custom + types du modèle NER, PAS les
    # recognizers larges de presidio (source de faux positifs mesurée).
    entities = sorted(set(get_supported_entities("filtered", lang=LANG, model=MODEL)) | custom_types)

    device = _place_model(analyzer)

    # Warm-up réel : force le chargement HF + le chemin chunké (>400 tokens).
    warm_text = ("demo-node-01.internal.example 203.0.113.7 warmup alice.demo@example.org ") * 40
    analyzer.analyze(text=warm_text, language=LANG, entities=entities, score_threshold=threshold)

    _ENGINE.update(
        ready=True,
        analyzer=analyzer,
        detector=detector,
        entities=entities,
        threshold=threshold,
        device=device,
        allow_exact=allow_exact,
        allow_patterns=allow_patterns,
        loaded_in_s=round(time.perf_counter() - t0, 1),
        loaded_at=time.strftime("%Y-%m-%dT%H:%M:%S%z"),
    )
    logger.info("moteur prêt : %s en %ss, %d types d'entités", MODEL, _ENGINE["loaded_in_s"], len(entities))


_TRIM_LEFT = "([{<\"'`"
_TRIM_RIGHT = ")]}>\"'`.,;:!?"


def _expand_token(text: str, start: int, end: int) -> str:
    """Étend un span à son token complet (délimité par des espaces).

    Le NER ne renvoie souvent que le domaine : `github.com` dans
    `github.com/spf13/cobra`. Sans cette expansion, l'allowlist §6 ne peut
    pas reconnaître un chemin d'import Go ou une image publique — c'est le
    poste qui détermine si l'agent reste utilisable (82 % de faux positifs
    sans allowlist, selon le plan).
    """
    left = start
    while left > 0 and not text[left - 1].isspace():
        left -= 1
    right = end
    while right < len(text) and not text[right].isspace():
        right += 1
    return text[left:right].lstrip(_TRIM_LEFT).rstrip(_TRIM_RIGHT)


def _trim_span(text: str, ent: dict) -> dict:
    """Retire la ponctuation happée en bord de span.

    Les recognizers d'URL avalent volontiers le backtick ou le point qui
    ferment la phrase. Le span devient alors le plus LONG et remporte
    l'arbitrage des recouvrements face au type le plus précis
    (`CONTAINER_IMAGE`), dont le générateur seul sait traiter le chemin.
    """
    start, end = ent["start"], ent["end"]
    while end > start and text[end - 1] in _TRIM_RIGHT:
        end -= 1
    while start < end and text[start] in _TRIM_LEFT:
        start += 1
    if (start, end) == (ent["start"], ent["end"]):
        return ent
    return {**ent, "start": start, "end": end, "value": text[start:end]}


def _allowed(value: str, allow_exact: list[str],
             allow_patterns: list[re.Pattern[str]]) -> str | None:
    """La RAISON pour laquelle une valeur est publique, ou None.

    Distinguer l'entrée exacte de la règle de FORME n'est pas cosmétique :
    l'exacte est une décision prise token par token, la forme est une
    heuristique, et c'est la seule des deux dont l'échec soit SILENCIEUX (la
    valeur sort en clair, sans entrée de coffre ni substitut non résolu).
    Elle est donc comptée.
    """
    if value in allow_exact:
        return "exact"
    for p in allow_patterns:
        if p.fullmatch(value):
            return p.pattern
    return None


# --------------------------------------------------------------------------- #
# API HTTP
# --------------------------------------------------------------------------- #


@asynccontextmanager
async def lifespan(app: FastAPI):
    _load_engine()
    yield


app = FastAPI(title="anonshield-detect", lifespan=lifespan)


class DetectIn(BaseModel):
    text: str
    strategy: str = "filtered"  # "filtered" (NER + regex) | "regex" (sans NER)


@app.get("/healthz")
def healthz():
    return {
        "status": "ok" if _ENGINE.get("ready") else "loading",
        "model": MODEL,
        "device": _ENGINE.get("device"),
        "warm": bool(_ENGINE.get("ready")),
        "loaded_in_s": _ENGINE.get("loaded_in_s"),
        "loaded_at": _ENGINE.get("loaded_at"),
        "entity_types": len(_ENGINE.get("entities", [])),
        "pid": os.getpid(),
    }


@app.post("/detect")
def detect(inp: DetectIn):
    if not _ENGINE.get("ready"):
        raise HTTPException(status_code=503, detail="moteur non chargé")
    t0 = time.perf_counter()

    if inp.strategy == "regex":
        raw = _ENGINE["detector"].extract_regex_entities(inp.text)
        ents = [
            {"type": e["label"], "value": e["text"], "start": e["start"], "end": e["end"],
             "score": round(float(e["score"]), 4)}
            for e in raw
        ]
    elif inp.strategy == "filtered":
        with _LOCK:
            results = _ENGINE["analyzer"].analyze(
                text=inp.text,
                language=LANG,
                entities=_ENGINE["entities"],
                allow_list=_ENGINE["allow_exact"],
                score_threshold=_ENGINE["threshold"],
            )
        ents = [
            {"type": r.entity_type, "value": inp.text[r.start:r.end], "start": r.start,
             "end": r.end, "score": round(float(r.score), 4)}
            for r in results
        ]
    else:
        raise HTTPException(status_code=422, detail=f"stratégie inconnue : {inp.strategy!r}")

    ents = [_trim_span(inp.text, e) for e in ents]
    allow_exact, allow_patterns = _ENGINE["allow_exact"], _ENGINE["allow_patterns"]
    gardees: list[dict] = []
    # Dédoublonné par VALEUR : un même token reçoit plusieurs spans (SERVICE,
    # HOSTNAME, URL), et compter les spans donnerait un chiffre sans rapport
    # avec le nombre d'identifiants réellement rendus publics.
    par_forme: dict[str, dict] = {}
    for e in ents:
        raison = (_allowed(e["value"], allow_exact, allow_patterns)
                  or _allowed(_expand_token(inp.text, e["start"], e["end"]),
                              allow_exact, allow_patterns))
        if raison is None:
            gardees.append(e)
        elif raison != "exact":
            # Une règle de FORME suppose un contexte que le token n'a pas :
            # `README.md` et `acme.md` lui sont indiscernables. Le résidu est
            # assumé, mais il ne doit pas être invisible.
            vu = par_forme.setdefault(
                e["value"], {"value": e["value"], "types": [], "rule": raison})
            if e["type"] not in vu["types"]:
                vu["types"].append(e["type"])
                vu["types"].sort()
            logger.info("public par règle de forme : %r (%s)", e["value"], raison)
    gardees.sort(key=lambda e: (e["start"], -e["score"]))
    return {
        "entities": gardees,
        "public_by_shape": list(par_forme.values()),
        "strategy": inp.strategy,
        "elapsed_ms": round((time.perf_counter() - t0) * 1000, 1),
    }
