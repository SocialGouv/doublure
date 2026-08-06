#!/usr/bin/env python3
"""`openai/privacy-filter` face à NOTRE menace, qui n'est pas la sienne.

Le modèle vise la donnée PERSONNELLE (personne, e-mail, téléphone, adresse,
date, numéro de compte, URL privée, secret) ; notre bande résiduelle est
l'identifiant d'INFRASTRUCTURE. La question n'est donc pas « est-il bon », mais
« est-il bon SUR CE QUE NOUS RATONS ».

C'est la bonne CLASSE d'outil, contrairement aux modèles de conversation
mesurés par `bench_classification.py` : classifieur de jetons, une seule passe,
déterministe, Apache 2.0 — donc utilisable de NOTRE côté de la frontière D7,
là où AnonShield est GPL-3.0.

Trois épreuves :
  1. la bande ambiguë — même token, contexte de fichier contre contexte
     d'hôte, en français ET en anglais (pour ne pas confondre « incapable »
     et « anglophone ») ;
  2. les identifiants d'infrastructure du corpus synthétique ;
  3. latence et déterminisme, les deux critères durs.

Environnement : ce modèle exige transformers >= 5. Le venv d'AnonShield est
épinglé et fragile (cf. CLAUDE.md) — ne PAS l'y installer. Venv jetable :
    uv venv /tmp/pf --python 3.12
    uv pip install --python /tmp/pf/bin/python "transformers>=5" torch accelerate
    /tmp/pf/bin/python tests/bench_privacy_filter.py
"""
import time

from transformers import AutoModelForTokenClassification, AutoTokenizer, pipeline

MODELE = "openai/privacy-filter"

AMBIGU_FR = [
    ("Ouvre le fichier rapport-incident.md et extrais la chronologie.",
     "rapport-incident.md", "public"),
    ("Le serveur rapport-incident.md ne repond plus au ping depuis 3h.",
     "rapport-incident.md", "sensible"),
    ("Le plan est ecrit dans migration-2026.md a la racine du depot.",
     "migration-2026.md", "public"),
    ("Ajoute migration-2026.md dans la zone DNS avec un enregistrement A.",
     "migration-2026.md", "sensible"),
    ("Le script de deploiement lit deploy-prod.conf au demarrage.",
     "deploy-prod.conf", "public"),
    ("Ping deploy-prod.conf depuis le bastion pour verifier la route.",
     "deploy-prod.conf", "sensible"),
]

AMBIGU_EN = [
    ("Open the file incident-report.md and extract the timeline.",
     "incident-report.md", "public"),
    ("The server incident-report.md has not answered ping for 3 hours.",
     "incident-report.md", "sensible"),
    ("The plan is written in migration-2026.md at the repository root.",
     "migration-2026.md", "public"),
    ("Add migration-2026.md to the DNS zone with an A record.",
     "migration-2026.md", "sensible"),
]

INFRA = [
    ("Le pod tourne sur node-03-prod.acmecorp.internal en 10.42.3.17.",
     ["node-03-prod.acmecorp.internal", "10.42.3.17"]),
    ("On tire registry.acmecorp.io/payments/api:4.2.1 depuis le miroir.",
     ["registry.acmecorp.io/payments/api:4.2.1"]),
    ("Le compte de service svc-backup-agent@acmecorp.example a expire.",
     ["svc-backup-agent@acmecorp.example"]),
    ("Contacte alice.dupont@acmecorp.example pour l'incident.",
     ["alice.dupont@acmecorp.example"]),
    ("Le depot est github.com/acmecorp/payments-api, branche main.",
     ["github.com/acmecorp/payments-api"]),
    ("La cle AKIAIOSFODNN7EXAMPLE est encore active sur le compte.",
     ["AKIAIOSFODNN7EXAMPLE"]),
]


def main() -> None:
    print(f"chargement de {MODELE} …")
    t0 = time.perf_counter()
    tok = AutoTokenizer.from_pretrained(MODELE)
    mdl = AutoModelForTokenClassification.from_pretrained(MODELE)
    mdl = mdl.to("cuda" if _cuda() else "cpu")
    clf = pipeline("token-classification", model=mdl, tokenizer=tok,
                   aggregation_strategy="simple",
                   device=0 if _cuda() else -1)
    print(f"chargé en {time.perf_counter() - t0:.1f}s · "
          f"{sum(p.numel() for p in mdl.parameters()) / 1e9:.2f} G paramètres · "
          f"{next(mdl.parameters()).device}")
    classes = sorted({v.split("-", 1)[-1] for v in mdl.config.id2label.values()})
    print(f"classes : {classes}\n")

    def spans(texte):
        return [(e["entity_group"], e["word"].strip(), round(float(e["score"]), 3))
                for e in clf(texte)]

    def couvre(trouves, token):
        """Un span recouvre-t-il le token visé ? Le tokeniseur le coupe volontiers."""
        return any(t in token or token in t
                   or any(p and p in t for p in token.replace("/", ".").split("."))
                   for _, t, _ in trouves)

    clf("echauffement du modele")

    for nom, jeu in (("BANDE AMBIGUË — français", AMBIGU_FR),
                     ("BANDE AMBIGUË — anglais", AMBIGU_EN)):
        print(f"### {nom}")
        bons = 0
        for texte, token, attendu in jeu:
            trouves = spans(texte)
            verdict = "sensible" if couvre(trouves, token) else "public"
            bons += verdict == attendu
            print(f"  {'ok ' if verdict == attendu else 'NON'} attendu"
                  f" {attendu:<9} → {verdict:<9} {token:<22} {trouves}")
        print(f"  {bons}/{len(jeu)}\n")

    print("### IDENTIFIANTS D'INFRASTRUCTURE (notre menace réelle)")
    vus = total = 0
    for texte, attendus in INFRA:
        trouves = spans(texte)
        for a in attendus:
            ok = couvre(trouves, a)
            vus += ok
            total += 1
            print(f"  {'vu  ' if ok else 'RATÉ'} {a:<42} {trouves}")
    print(f"  {vus}/{total} détectés\n")

    print("### latence, modèle chaud")
    for taille, texte in (("phrase", AMBIGU_FR[0][0]),
                          ("2 Ko", " ".join([AMBIGU_FR[0][0]] * 30))):
        mesures = sorted((time.perf_counter() - t) * 1000
                         for t in [_chrono(clf, texte) for _ in range(10)])
        print(f"  {taille:<8} p50 {mesures[5]:6.1f} ms · max {mesures[-1]:6.1f} ms")

    print("\n### déterminisme (5 passes identiques)")
    ref = spans(AMBIGU_FR[1][0])
    print(f"  stable : {all(spans(AMBIGU_FR[1][0]) == ref for _ in range(5))}")


def _chrono(clf, texte):
    t = time.perf_counter()
    clf(texte)
    return t


def _cuda() -> bool:
    import torch
    return torch.cuda.is_available()


if __name__ == "__main__":
    main()
