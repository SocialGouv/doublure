#!/usr/bin/env python3
"""Trois façons de décider « ce token est public », mesurées sur le même banc.

Question posée par jo : mieux intégrer l'IA à la classification améliore-t-il
ou empire-t-il ?

  A — RÈGLES DE FORME seules (état actuel : l'allowlist §6).
  B — A + INVENTAIRE : une liste de ce qui est à nous, qui PRIME sur toute
      règle de forme. Déterministe.
  C — B + IA LOCALE, appelée UNIQUEMENT sur la bande où une règle de forme a
      rendu un token public, et qui ne peut QUE remonter la protection.
      Elle ne publie jamais rien : c'est la contrainte qui l'empêche de
      réintroduire le seul mode d'échec silencieux du système.

Le banc sépare trois groupes, parce qu'ils ne se jugent pas ensemble :
  - `residu_inventaire`  : fuites documentées, fermables par une DONNÉE ;
  - `public_a_preserver` : un faux positif ici a déjà interrompu une session ;
  - `ambigu_contexte`    : même token, deux phrases, deux verdicts opposés —
                           c'est la seule bande où le contexte tranche, donc
                           la seule où l'IA peut apporter quelque chose.

Usage : uv run python tests/bench_classification.py [--sans-ia]
"""
from __future__ import annotations

import argparse
import json
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from anonproxy.allowlist import Allowlist  # noqa: E402
from anonproxy.inventory import Inventory  # noqa: E402

BANC = ROOT / "tests" / "bench_classification.jsonl"
DETECT_URL = "http://127.0.0.1:9000/detect"
OLLAMA_URL = "http://127.0.0.1:11434/api/generate"
MODELE = "gemma4:latest"

#: Ce qui borde un token dans une phrase, et que le NER happe volontiers.
_BORDS = " \t\n.,;:!?()[]{}'\"`"


def detecte(text: str) -> list[dict]:
    corps = json.dumps({"text": text, "strategy": "filtered"}).encode()
    requete = urllib.request.Request(
        DETECT_URL, data=corps, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(requete, timeout=30) as r:
        rep = json.load(r)
    # Le détecteur a DÉJÀ retiré ce que l'allowlist rend public : on veut ici
    # les spans BRUTS pour rejouer la décision nous-mêmes. `public_by_shape`
    # les rend, sans leurs bornes — on les recolle depuis le texte.
    spans = list(rep["entities"])
    for p in rep.get("public_by_shape", []):
        deb = text.find(p["value"])
        if deb >= 0:
            spans.append({"type": p["types"][0], "value": p["value"],
                          "start": deb, "end": deb + len(p["value"]),
                          "score": 1.0})
    return spans


def token_entier(text: str, start: int, end: int) -> str:
    """Le token complet autour d'un span, comme le fait le détecteur."""
    g = start
    while g > 0 and not text[g - 1].isspace():
        g -= 1
    d = end
    while d < len(text) and not text[d].isspace():
        d += 1
    return text[g:d].strip(_BORDS)


# --------------------------------------------------------------------------- #
# L'IA locale : elle ne peut que REMONTER la protection
# --------------------------------------------------------------------------- #
#: Gabarit en ANGLAIS et raisonnement ACTIVÉ : les deux ont été mesurés.
#: Sans raisonnement, les deux modèles locaux répondent « fichier » quasiment
#: partout — ils s'ancrent sur la FORME du token et ignorent la phrase, donc
#: ils ne font que recopier la règle qu'ils étaient censés arbitrer.
GABARIT = """Classify an identifier found in an operator's message.

Sentence: {phrase}
Identifier: {token}

Does this identifier refer to:
(A) a FILE name, a public library module, or a standard;
(B) a machine, domain, service or component SPECIFIC to one organisation —
    something that must not leave that organisation.

Answer with a single letter, A or B. If unsure, answer B."""


def demande_a_l_ia(phrase: str, token: str, cache: dict) -> tuple[str, float]:
    """Rend 'A' (public) ou 'B' (propre à l'organisation), et la latence.

    Le résultat est CACHÉ : une même question ne se repose pas. C'est ce qui
    rend la réponse monotone et le coût décroissant — et ce qui permettrait,
    en vrai, de la faire arbitrer par l'humain UNE fois.
    """
    cle = (phrase, token)
    if cle in cache:
        return cache[cle], 0.0
    corps = json.dumps({
        "model": MODELE,
        "prompt": GABARIT.format(phrase=phrase, token=token),
        "stream": False,
        # Le raisonnement est le seul montage où le modèle utilise la PHRASE.
        # Il coûte dix fois plus cher — c'est le prix mesuré de la seule
        # variante qui apporte quelque chose.
        "think": True,
        "options": {"temperature": 0, "num_predict": 512},
    }).encode()
    requete = urllib.request.Request(
        OLLAMA_URL, data=corps, headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(requete, timeout=120) as r:
            reponse = json.load(r).get("response", "")
    except (urllib.error.URLError, TimeoutError) as exc:
        # Indisponible = on ne sait pas = on protège. Fail-closed, comme
        # partout ailleurs (D5).
        print(f"  ia indisponible ({exc}) → protection", file=sys.stderr)
        return "B", time.perf_counter() - t0
    ms = time.perf_counter() - t0
    lettre = "B"
    if (m := re.search(r"\b([AB])\b", reponse.upper())):
        lettre = m.group(1)
    cache[cle] = lettre
    return lettre, ms


# --------------------------------------------------------------------------- #
# Les trois bras
# --------------------------------------------------------------------------- #
def verdict(bras: str, text: str, token: str, allow: Allowlist,
            inv: Inventory, cache: dict) -> tuple[str, float]:
    """'public' ou 'sensible', et le coût en secondes."""
    if bras in ("B", "C") and inv.est_a_nous(token):
        return "sensible", 0.0
    raison = None
    if allow.is_exact(token):
        raison = "exact"
    else:
        for p in allow.patterns:
            if p.fullmatch(token):
                raison = p.pattern
                break
    if raison is None:
        return "sensible", 0.0
    if raison == "exact" or bras != "C":
        return "public", 0.0
    # Bande de l'IA : une règle de FORME, et elle seule. L'IA ne peut que
    # remonter la protection — jamais publier ce que la forme n'a pas publié.
    lettre, ms = demande_a_l_ia(text, token, cache)
    return ("public" if lettre == "A" else "sensible"), ms


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--sans-ia", action="store_true",
                    help="ne mesurer que A et B")
    args = ap.parse_args()

    cas = [json.loads(l) for l in BANC.read_text(encoding="utf-8").splitlines()
           if l.strip()]
    allow = Allowlist.load()
    inv = Inventory.load()
    bras = ["A", "B"] if args.sans_ia else ["A", "B", "C"]
    cache: dict = {}

    resultats: dict[str, list[dict]] = {b: [] for b in bras}
    non_detectes = []
    for c in cas:
        spans = detecte(c["text"])
        vus = {s["value"] for s in spans}
        vus |= {token_entier(c["text"], s["start"], s["end"]) for s in spans}
        if c["token"] not in vus:
            non_detectes.append(c)
        for b in bras:
            v, ms = verdict(b, c["text"], c["token"], allow, inv, cache)
            resultats[b].append({**c, "verdict": v, "ms": ms})

    groupes = ["residu_inventaire", "public_a_preserver", "ambigu_contexte"]
    print(f"{len(cas)} cas · {len(non_detectes)} non détectés par le NER\n")
    entete = f"{'groupe':<22}" + "".join(f"{'bras ' + b:>14}" for b in bras)
    print(entete)
    print("-" * len(entete))
    for g in groupes:
        ligne = f"{g:<22}"
        for b in bras:
            items = [r for r in resultats[b] if r["groupe"] == g]
            faux = [r for r in items if r["verdict"] != r["attendu"]]
            ligne += f"{len(items) - len(faux):>8}/{len(items):<6}"
        print(ligne)

    print()
    for b in bras:
        fuites = [r for r in resultats[b]
                  if r["attendu"] == "sensible" and r["verdict"] == "public"]
        fp = [r for r in resultats[b]
              if r["attendu"] == "public" and r["verdict"] == "sensible"]
        cout = sum(r["ms"] for r in resultats[b])
        appels = sum(1 for r in resultats[b] if r["ms"] > 0)
        print(f"bras {b} : {len(fuites)} fuite(s), {len(fp)} faux positif(s)"
              f" · {appels} appel(s) IA, {cout:.1f} s")
        for r in fuites:
            print(f"    FUITE  {r['id']:<12} {r['token']!r} — {r['motif']}")
        for r in fp:
            print(f"    FAUX+  {r['id']:<12} {r['token']!r} — {r['motif']}")

    # L'IA en ROUTEUR plutôt qu'en décideur : ce qui compte alors n'est pas
    # son verdict mais la PRÉCISION de ses désaccords — combien de questions
    # elle poserait à l'opérateur, et combien seraient justifiées.
    if "C" in bras:
        bande = [(a, c) for a, c in zip(resultats["B"], resultats["C"])
                 if a["verdict"] == "public"]
        escalades = [(a, c) for a, c in bande if c["verdict"] == "sensible"]
        justes = [c for _, c in escalades if c["attendu"] == "sensible"]
        print(f"\nIA en ROUTEUR : bande de {len(bande)} tokens rendus publics"
              f" par une règle de forme")
        print(f"   {len(escalades)} escalade(s) vers l'opérateur, dont"
              f" {len(justes)} justifiée(s)")
        for _, c in escalades:
            marque = "justifiée" if c["attendu"] == "sensible" else "à tort"
            print(f"      {marque:<10} {c['id']:<12} {c['token']!r}")

    manques = [c for c in non_detectes if c["attendu"] == "sensible"]
    if manques:
        print("\nNon détectés par le NER — ils sortent sans même être comptés,"
              "\nc'est une AUTRE fuite que celles ci-dessus :")
        for c in manques:
            print(f"    {c['id']:<12} {c['token']!r}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
