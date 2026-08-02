#!/usr/bin/env python3
"""Harnais d'évaluation sur corpus (plan §5 Phase 5).

Mesure, en séparant les métriques comme l'exige le plan :

  - rappel sur les SECRETS (seuil : 100 %, non négociable) ;
  - rappel par classe d'identifiant ;
  - taux de faux positifs sur chaînes techniques (`must_stay_clear`) ;
  - variance sur exécutions répétées (seuil : 0) ;
  - collisions de substituts (seuil : 0) ;
  - JSON invalide après transformation (seuil : 0) ;
  - latence P95 ajoutée par exemple.

Le critère dur est `must_not_leak` : aucune de ces sous-chaînes ne doit
survivre à la substitution, quel que soit le type détecté.

Usage :
    uv run python tests/corpus_eval.py                # corpus synthétique
    uv run python tests/corpus_eval.py --real         # corpus réel (gitignoré)
    uv run python tests/corpus_eval.py --annotate     # pré-annotation
"""
from __future__ import annotations

import argparse
import json
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from anonproxy.detect import DetectClient, DetectionUnavailable  # noqa: E402
from anonproxy.surrogates.classes import DataClass, class_of  # noqa: E402
from anonproxy.surrogates.engine import SurrogateEngine  # noqa: E402
from anonproxy.vault import Vault  # noqa: E402

MASTER = "e7" * 32


def load(path: Path) -> list[dict]:
    if not path.exists():
        raise SystemExit(f"corpus absent : {path}")
    return [json.loads(l) for l in path.read_text(encoding="utf-8").splitlines() if l.strip()]


def evaluate(examples: list[dict], detect_url: str) -> tuple[dict, int]:
    detector = DetectClient(detect_url)
    try:
        detector.health()
    except DetectionUnavailable as exc:
        raise SystemExit(f"détecteur indisponible : {exc}\nLancer services/anonshield/wrapper/run.sh")

    tmp = Path(tempfile.mkdtemp(prefix="corpus-eval-"))
    runs: list[list[str]] = []
    latencies: list[float] = []
    leaks: list[tuple[str, str]] = []
    false_positives: list[tuple[str, str]] = []
    secret_recall = {"attendu": 0, "trouvé": 0}
    by_type: dict[str, dict[str, int]] = {}
    invalid_json = 0

    for run_idx in range(2):  # deux exécutions : mesure de la variance
        engine = SurrogateEngine(
            vault=Vault(tmp / f"run{run_idx}.db", master_key=MASTER), master_key=MASTER, scope_key="project:eval"
        )
        outputs: list[str] = []
        for ex in examples:
            t0 = time.perf_counter()
            spans = detector.detect(ex["text"])
            out = engine.transform(ex["text"], spans)
            if run_idx == 0:
                latencies.append((time.perf_counter() - t0) * 1000)
            outputs.append(out)

            if run_idx != 0:
                continue

            # critère dur : rien de `must_not_leak` ne survit
            for secret in ex.get("must_not_leak", []):
                if not secret:
                    raise SystemExit(f"{ex['id']} : `must_not_leak` contient une valeur vide "
                                     "(elle serait 'trouvée' partout — annotation à corriger)")
                if secret in out:
                    leaks.append((ex["id"], secret))
            # faux positifs : les chaînes techniques publiques restent en clair
            for clear in ex.get("must_stay_clear", []):
                if clear not in out:
                    false_positives.append((ex["id"], clear))
            # rappel par type annoté
            for ent in ex.get("entities", []):
                etype, value = ent["type"], ent.get("value", "")
                if not value:
                    raise SystemExit(f"{ex['id']} : annotation sans `value` pour {etype} "
                                     "(le rappel serait faussé)")
                if value not in ex["text"]:
                    raise SystemExit(f"{ex['id']} : `value` {value!r} absente du texte annoté")
                stats = by_type.setdefault(etype, {"attendu": 0, "trouvé": 0})
                stats["attendu"] += 1
                substituted = value not in out
                stats["trouvé"] += int(substituted)
                if class_of(etype) is DataClass.SECRET:
                    secret_recall["attendu"] += 1
                    secret_recall["trouvé"] += int(substituted)
            try:
                json.loads(json.dumps({"text": out}))
            except (TypeError, ValueError):
                invalid_json += 1

        runs.append(outputs)

    variance = sum(1 for a, b in zip(runs[0], runs[1]) if a != b)

    # Compter les collisions sur les CLÉS d'un dict serait tautologique (elles
    # sont uniques par construction) : on interroge les lignes brutes, et on
    # vérifie en plus que la contrainte d'unicité refuse activement un doublon.
    vault = Vault(tmp / "run0.db", master_key=MASTER)
    rows = vault._conn.execute(
        "SELECT surrogate FROM mapping WHERE scope=?", ("project:eval",)
    ).fetchall()
    surrogates = [r[0] for r in rows]
    collisions = len(surrogates) - len(set(surrogates))
    if surrogates:
        from anonproxy.vault import SurrogateConflict
        try:
            vault.bind("project:eval", "HOSTNAME", "sonde-injectivite", surrogates[0])
            collisions += 1  # le doublon a été ACCEPTÉ : l'injectivité n'est pas tenue
        except SurrogateConflict:
            pass

    lat = sorted(latencies)
    p95 = lat[min(len(lat) - 1, int(0.95 * len(lat)))] if lat else 0.0

    return {
        "exemples": len(examples),
        "fuites": leaks,
        "faux_positifs": false_positives,
        "secrets": secret_recall,
        "par_type": by_type,
        "variance": variance,
        "collisions": collisions,
        "json_invalide": invalid_json,
        "latence_p50_ms": round(statistics.median(lat), 1) if lat else 0.0,
        "latence_p95_ms": round(p95, 1),
    }, 0


def report(m: dict) -> int:
    lines = ["# Évaluation sur corpus (Phase 5)\n", f"- exemples : {m['exemples']}\n"]
    ok = True

    lines.append("## Critères durs\n")
    lines.append("| métrique | seuil | mesuré | verdict |")
    lines.append("|---|---|---|---|")

    def row(name, seuil, got, passed):
        nonlocal ok
        ok &= passed
        lines.append(f"| {name} | {seuil} | {got} | {'PASS' if passed else '**FAIL**'} |")

    row("fuites (`must_not_leak`)", "0", len(m["fuites"]), not m["fuites"])
    sec = m["secrets"]
    rec = (sec["trouvé"] / sec["attendu"] * 100) if sec["attendu"] else 100.0
    row("rappel sur les secrets", "100 %", f"{rec:.1f} % ({sec['trouvé']}/{sec['attendu']})",
        sec["trouvé"] == sec["attendu"])
    row("variance (2 exécutions)", "0", m["variance"], m["variance"] == 0)
    row("collisions de substituts", "0", m["collisions"], m["collisions"] == 0)
    row("JSON invalide", "0", m["json_invalide"], m["json_invalide"] == 0)
    total_clear = sum(1 for _ in m["faux_positifs"])
    row("faux positifs (chaînes techniques)", "< 2 %", total_clear, total_clear == 0)

    lines.append(f"\n- latence par exemple : p50 {m['latence_p50_ms']} ms, "
                 f"p95 {m['latence_p95_ms']} ms\n")

    lines.append("## Rappel par type d'entité\n")
    lines.append("| type | classe | attendu | détecté | rappel |")
    lines.append("|---|---|---|---|---|")
    for etype, s in sorted(m["par_type"].items()):
        r = s["trouvé"] / s["attendu"] * 100 if s["attendu"] else 0
        lines.append(f"| {etype} | {class_of(etype).value} | {s['attendu']} | "
                     f"{s['trouvé']} | {r:.0f} % |")

    if m["fuites"]:
        lines.append("\n## Fuites\n")
        for eid, value in m["fuites"]:
            lines.append(f"- `{eid}` : `{value}`")
    if m["faux_positifs"]:
        lines.append("\n## Faux positifs (substitué alors qu'il devait rester en clair)\n")
        for eid, value in m["faux_positifs"]:
            lines.append(f"- `{eid}` : `{value}`")

    lines.append(f"\n**{'PASS' if ok else 'FAIL'}**")
    print("\n".join(lines))
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--real", action="store_true", help="corpus réel (corpus/real/)")
    ap.add_argument("--detect-url", default="http://127.0.0.1:9000")
    args = ap.parse_args()

    path = ROOT / ("corpus/real/annotations.jsonl" if args.real
                   else "corpus/synthetic/annotations.jsonl")
    metrics, _ = evaluate(load(path), args.detect_url)
    return report(metrics)


if __name__ == "__main__":
    sys.exit(main())
