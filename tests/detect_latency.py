#!/usr/bin/env python3
"""Preuve du critère de sortie Phase 1 (plan §5) :

    POST /detect < 150 ms sur un texte de 2 Ko, modèle déjà chaud,
    pas de rechargement de modèle entre requêtes.

Protocole : attendre /healthz warm, 3 requêtes d'échauffement, puis N requêtes
chronométrées côté client (wall-clock, HTTP compris). Verdict sur le P95.
La stabilité 1re moitié vs 2de moitié atteste l'absence de rechargement.

Texte 100 % SYNTHÉTIQUE (aucune valeur réelle). Stdlib uniquement.
Usage : python3 tests/detect_latency.py  [DETECT_URL=http://127.0.0.1:9000]
"""

from __future__ import annotations

import json
import os
import sys
import time
import urllib.error
import urllib.request

BASE = os.environ.get("DETECT_URL", "http://127.0.0.1:9000")
N = int(os.environ.get("DETECT_N", "30"))
P95_BUDGET_MS = 150.0
SIZE = 2048  # « texte de 2 Ko »

_SYNTHETIC_LINES = [
    "2026-08-01T10:00:01Z INFO gateway demo-node-01.internal.example accepted conn from 203.0.113.7:51442",
    "2026-08-01T10:00:02Z WARN auth service svc-checkout-prod token refresh for alice.demo@example.org failed",
    "2026-08-01T10:00:03Z INFO scheduler pod demo-apps/checkout-7f9c grabbed node 10.240.12.34 (aa:bb:cc:dd:ee:01)",
    "2026-08-01T10:00:04Z INFO puller image docker.io/library/nginx:1.27 digest sha256:1f2a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708",
    "2026-08-01T10:00:05Z INFO api GET https://api.demo-corp.example/v2/orders?limit=50 200 in 12ms",
    "2026-08-01T10:00:06Z ERROR scanner CVE-2024-12345 detected on demo-node-02.internal.example, scope Mail.ReadWrite",
    "2026-08-01T10:00:07Z INFO ns kube-system unchanged; module github.com/spf13/cobra v1.8.2 loaded",
]


def build_text(size: int = SIZE) -> str:
    filler = "2026-08-01T10:00:08Z DEBUG heartbeat ok latency 3ms queue 0 retries 0 status green\n"
    text = "\n".join(_SYNTHETIC_LINES) + "\n"
    while len(text) < size:
        text += filler
    text = text[:size]
    assert len(text.encode("utf-8")) == size, "texte de référence ≠ 2 Ko exacts"
    return text


def _get(path: str, timeout: float = 10.0) -> dict:
    with urllib.request.urlopen(BASE + path, timeout=timeout) as r:
        return json.loads(r.read())


def _post(path: str, payload: dict, timeout: float = 120.0) -> dict:
    req = urllib.request.Request(
        BASE + path,
        data=json.dumps(payload).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def wait_warm(timeout_s: float = 900.0) -> dict:
    """Premier démarrage : inclut le téléchargement du modèle HF — patient."""
    t0 = time.time()
    last = None
    while time.time() - t0 < timeout_s:
        try:
            last = _get("/healthz")
            if last.get("warm"):
                return last
        except (urllib.error.URLError, ConnectionError):
            pass
        time.sleep(2)
    raise SystemExit(f"ÉCHEC : service pas chaud après {timeout_s}s (dernier état : {last})")


def percentile(sorted_ms: list[float], p: float) -> float:
    idx = min(len(sorted_ms) - 1, max(0, round(p / 100 * len(sorted_ms) + 0.5) - 1))
    return sorted_ms[idx]


def main() -> int:
    text = build_text()
    health = wait_warm()
    print(f"service chaud : modèle {health['model']} chargé en {health['loaded_in_s']}s, "
          f"{health['entity_types']} types d'entités, pid {health['pid']}")

    for _ in range(3):  # échauffement (JIT, caches alloc)
        _post("/detect", {"text": text})

    timings: list[float] = []
    last: dict = {}
    for _ in range(N):
        t0 = time.perf_counter()
        last = _post("/detect", {"text": text})
        timings.append((time.perf_counter() - t0) * 1000)

    s = sorted(timings)
    half = N // 2
    med_1st = sorted(timings[:half])[half // 2]
    med_2nd = sorted(timings[half:])[(N - half) // 2]

    t0 = time.perf_counter()
    rx = _post("/detect", {"text": text, "strategy": "regex"})
    regex_ms = (time.perf_counter() - t0) * 1000

    print(f"\n{N} requêtes /detect (filtered) sur {len(text)} octets, modèle chaud :")
    print(f"  min {s[0]:.1f} ms · p50 {percentile(s, 50):.1f} ms · "
          f"p95 {percentile(s, 95):.1f} ms · max {s[-1]:.1f} ms")
    print(f"  stabilité (pas de rechargement) : médiane 1re moitié {med_1st:.1f} ms, "
          f"2de moitié {med_2nd:.1f} ms")
    print(f"  stratégie regex (1 requête) : {regex_ms:.1f} ms, {len(rx['entities'])} entités")

    ents = last.get("entities", [])
    print(f"\n{len(ents)} entités détectées (filtered), échantillon :")
    for e in ents[:8]:
        print(f"  [{e['start']:4d}:{e['end']:4d}] {e['type']:<16} score {e['score']:<6} {e['value']!r}")

    p95 = percentile(s, 95)
    if p95 < P95_BUDGET_MS:
        print(f"\nPASS : p95 {p95:.1f} ms < {P95_BUDGET_MS:.0f} ms")
        return 0
    print(f"\nFAIL : p95 {p95:.1f} ms ≥ {P95_BUDGET_MS:.0f} ms")
    return 1


if __name__ == "__main__":
    sys.exit(main())
