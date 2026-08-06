#!/usr/bin/env python3
"""Le terrain où `openai/privacy-filter` pourrait battre notre pile.

`bench_detecteurs.py` montre que sur des identifiants d'INFRASTRUCTURE le
modèle n'apporte rien (0 valeur vue par lui seul). Ce n'est pas une faiblesse
du modèle : ce n'est pas sa cible. La sienne est la donnée PERSONNELLE en
PROSE — un nom, une adresse postale, une date de naissance — que nos
recognizers regex ne peuvent structurellement pas attraper, faute de forme.

Or le corpus doré de la Phase 5 est fait de « logs, tickets, CI » : un ticket
porte des noms de clients, des adresses, des numéros. C'est la seule question
que le banc synthétique d'infra ne pouvait pas trancher, et elle décide.

Le détecteur doit tourner. Environnement : cf. `bench_privacy_filter.py`.
    .venv-pf/bin/python tests/bench_donnees_personnelles.py
"""
import json
import time
import urllib.request

DETECT_URL = "http://127.0.0.1:9000/detect"
MODELE = "openai/privacy-filter"

#: Prose de ticket, 100 % SYNTHÉTIQUE. Aucune de ces valeurs n'a de forme
#: reconnaissable par une regex : c'est tout l'intérêt du cas.
CAS = [
    ("Le client Marguerite Vasseur signale que sa commande n'est jamais arrivee.",
     ["Marguerite Vasseur"]),
    ("Rappeler M. Thibault Escourrou au 06 12 34 56 78 avant vendredi.",
     ["Thibault Escourrou", "06 12 34 56 78"]),
    ("Livraison a relancer au 14 rue des Grands-Augustins, 75006 Paris.",
     ["14 rue des Grands-Augustins", "75006 Paris"]),
    ("Le dossier de Solveig Bergqvist est bloque depuis le 3 fevrier 1987.",
     ["Solveig Bergqvist", "3 fevrier 1987"]),
    ("Virement recu sur le compte FR76 3000 6000 0112 3456 7890 189.",
     ["FR76 3000 6000 0112 3456 7890 189"]),
    ("Notre contact chez le prestataire est Amaury de Villechaize.",
     ["Amaury de Villechaize"]),
    ("Le ticket a ete ouvert par Ines Ferreira-Konate le 12 mars.",
     ["Ines Ferreira-Konate"]),
    ("Sa carte se termine par 4539 1488 0343 6467, a verifier.",
     ["4539 1488 0343 6467"]),
]


def couvre(trouves: list[str], valeur: str) -> bool:
    """Un span recouvre-t-il la valeur, même partiellement ?

    Volontairement PERMISSIF : un nom composé est souvent coupé en deux spans,
    et refuser une couverture partielle sous-estimerait les deux camps de la
    même façon. Un fragment de moins de 3 caractères ne compte pas.
    """
    for t in trouves:
        if not t or len(t) < 3:
            continue
        if t in valeur or valeur in t:
            return True
        if any(len(mot) >= 3 and mot in t for mot in valeur.split()):
            return True
    return False


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

    tok = AutoTokenizer.from_pretrained(MODELE)
    mdl = AutoModelForTokenClassification.from_pretrained(MODELE)
    gpu = torch.cuda.is_available()
    clf = pipeline("token-classification", model=mdl.to("cuda" if gpu else "cpu"),
                   tokenizer=tok, aggregation_strategy="simple",
                   device=0 if gpu else -1)
    clf("echauffement")

    lignes = []
    for texte, attendus in CAS:
        vus_det, _ = par_le_detecteur(texte)
        vus_pf = [e["word"].strip() for e in clf(texte)]
        for a in attendus:
            lignes.append((a, couvre(vus_det, a), couvre(vus_pf, a)))

    print(f"\n{'donnée personnelle en prose':<40} {'en place':>10} {'privacy-filter':>16}")
    print("-" * 68)
    for valeur, det, pf in lignes:
        print(f"{valeur:<40} {'vu' if det else 'RATÉ':>10}"
              f" {'vu' if pf else 'RATÉ':>16}")
    n = len(lignes)
    d = sum(1 for _, det, _ in lignes if det)
    p = sum(1 for _, _, pf in lignes if pf)
    seuls_pf = [v for v, det, pf in lignes if pf and not det]
    print("-" * 68)
    print(f"{'total':<40} {f'{d}/{n}':>10} {f'{p}/{n}':>16}")
    print(f"\nvu SEULEMENT par privacy-filter ({len(seuls_pf)}/{n}) :")
    for v in seuls_pf:
        print(f"    {v}")


if __name__ == "__main__":
    main()
