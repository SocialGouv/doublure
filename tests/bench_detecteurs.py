#!/usr/bin/env python3
"""Le détecteur en place contre `openai/privacy-filter`, sur les mêmes phrases.

La sonde `bench_privacy_filter.py` a montré que le modèle d'OpenAI ne tranche
PAS la bande ambiguë (0/6). Reste la question qui compte pour l'adoption :
détecte-t-il ce que notre pile RATE, et rate-t-il ce qu'elle détecte ?

Le fait mesuré en Phase 1 rend la question sérieuse : sur du texte d'infra, le
NER actuel (SecureModernBERT) renvoie 0 entité — TOUT vient des recognizers
regex. Un classifieur de jetons qui, lui, voit les noms d'hôtes internes ne
serait pas un arbitre mais un REMPLAÇANT du NER.

Le détecteur doit tourner (`services/anonshield/wrapper/run.sh`).
Environnement : cf. `bench_privacy_filter.py`.
    .venv-pf/bin/python tests/bench_detecteurs.py
"""
import json
import time
import urllib.request

DETECT_URL = "http://127.0.0.1:9000/detect"
MODELE = "openai/privacy-filter"

#: Chaque phrase porte les valeurs qui DOIVENT être repérées. Synthétique.
CAS = [
    ("Le pod tourne sur node-03-prod.acmecorp.internal en 10.42.3.17.",
     ["node-03-prod.acmecorp.internal", "10.42.3.17"]),
    ("Bascule le trafic vers db-master-01-prod.acmecorp.internal ce soir.",
     ["db-master-01-prod.acmecorp.internal"]),
    ("On tire registry.acmecorp.io/payments/api:4.2.1 depuis le miroir.",
     ["registry.acmecorp.io/payments/api:4.2.1"]),
    ("Le depot est github.com/acmecorp/payments-api, branche main.",
     ["github.com/acmecorp/payments-api"]),
    ("Contacte alice.dupont@acmecorp.example pour l'incident.",
     ["alice.dupont@acmecorp.example"]),
    ("Le compte de service svc-backup-agent@acmecorp.example a expire.",
     ["svc-backup-agent@acmecorp.example"]),
    ("La cle AKIAIOSFODNN7EXAMPLE est encore active sur le compte.",
     ["AKIAIOSFODNN7EXAMPLE"]),
    ("Le jeton est ghp_16C7e42F292c6912E7710c838347Ae178B4a pour le CI.",
     ["ghp_16C7e42F292c6912E7710c838347Ae178B4a"]),
    ("Le namespace demo-apps heberge svc-payments-prod.",
     ["demo-apps", "svc-payments-prod"]),
    ("La passerelle publique est en 198.51.100.42, port 8443.",
     ["198.51.100.42"]),
]


def couvre(trouves: list[str], valeur: str) -> bool:
    """Un span recouvre-t-il la valeur ? Les tokeniseurs la coupent volontiers."""
    return any(t and (t in valeur or valeur in t) and len(t) >= 3
               for t in trouves)


def par_le_detecteur(texte: str) -> tuple[list[str], float]:
    corps = json.dumps({"text": texte, "strategy": "filtered"}).encode()
    r = urllib.request.Request(DETECT_URL, data=corps,
                               headers={"Content-Type": "application/json"})
    t0 = time.perf_counter()
    with urllib.request.urlopen(r, timeout=60) as rep:
        out = json.load(rep)
    return [e["value"] for e in out["entities"]], (time.perf_counter() - t0) * 1000


def main() -> None:
    from transformers import (AutoModelForTokenClassification, AutoTokenizer,
                              pipeline)
    import torch

    print(f"chargement de {MODELE} …")
    tok = AutoTokenizer.from_pretrained(MODELE)
    mdl = AutoModelForTokenClassification.from_pretrained(MODELE)
    gpu = torch.cuda.is_available()
    clf = pipeline("token-classification", model=mdl.to("cuda" if gpu else "cpu"),
                   tokenizer=tok, aggregation_strategy="simple",
                   device=0 if gpu else -1)
    clf("echauffement")

    lignes = []
    ms_det, ms_pf = [], []
    for texte, attendus in CAS:
        vus_det, ms = par_le_detecteur(texte)
        ms_det.append(ms)
        t0 = time.perf_counter()
        vus_pf = [e["word"].strip() for e in clf(texte)]
        ms_pf.append((time.perf_counter() - t0) * 1000)
        for a in attendus:
            lignes.append((a, couvre(vus_det, a), couvre(vus_pf, a)))

    print(f"\n{'valeur à repérer':<44} {'en place':>10} {'privacy-filter':>16}")
    print("-" * 72)
    for valeur, det, pf in lignes:
        print(f"{valeur:<44} {'vu' if det else 'RATÉ':>10}"
              f" {'vu' if pf else 'RATÉ':>16}")

    n = len(lignes)
    d = sum(1 for _, det, _ in lignes if det)
    p = sum(1 for _, _, pf in lignes if pf)
    seuls_pf = [v for v, det, pf in lignes if pf and not det]
    seuls_det = [v for v, det, pf in lignes if det and not pf]
    print("-" * 72)
    print(f"{'total':<44} {f'{d}/{n}':>10} {f'{p}/{n}':>16}")
    print(f"\nlatence médiane   en place {sorted(ms_det)[len(ms_det)//2]:6.1f} ms"
          f" · privacy-filter {sorted(ms_pf)[len(ms_pf)//2]:6.1f} ms")
    print(f"\nvu SEULEMENT par privacy-filter ({len(seuls_pf)}) : {seuls_pf}")
    print(f"vu SEULEMENT par la pile en place ({len(seuls_det)}) : {seuls_det}")
    union = sum(1 for _, det, pf in lignes if det or pf)
    print(f"\nunion des deux : {union}/{n}"
          f" — c'est le gain plafond d'un ajout, pas d'un remplacement")


if __name__ == "__main__":
    main()
