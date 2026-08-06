#!/usr/bin/env python3
"""GLiNER : on DÉCLARE les types, donc notre menace, pas une taxonomie figée.

C'est ce qui manquait aux deux essais précédents :
  - les modèles de conversation (`bench_classification.py`) devinent, coûtent
    des secondes et ne sont pas reproductibles ;
  - `openai/privacy-filter` (`bench_privacy_filter.py`) est déterministe et
    rapide, mais ses huit catégories sont FIXES et visent la personne, pas
    l'infrastructure — il rate l'image, le dépôt, le namespace.

GLiNER prend les types en langage naturel À L'INFÉRENCE. On peut donc lui
demander « internal hostname », « container image », « kubernetes namespace »,
et surtout poser à la bande ambiguë la question BIEN FORMÉE : « file name » ET
« server hostname » comme types CONCURRENTS, en laissant le contexte trancher.
C'est la question que je n'avais jamais pu poser correctement.

Environnement : cf. `bench_privacy_filter.py`, plus `uv pip install gliner`.
    .venv-pf/bin/python tests/bench_gliner.py
"""
import time

#: Licences vérifiées : `urchade` est Apache 2.0 (donc utilisable de NOTRE côté
#: de la frontière D7, contrairement à AnonShield qui est GPL-3.0) ; `nvidia`
#: est sous NVIDIA Open Model License, usage commercial autorisé.
MODELES = [
    "urchade/gliner_multi_pii-v1",   # 0,3 G · MULTILINGUE — notre corpus est en français
    "nvidia/gliner-PII",             # 0,57 G · 55+ catégories, dérivé de gliner_large (anglais)
    "knowledgator/gliner-pii-large-v1.0",
]

#: Nos types, tels qu'on les nommerait à un humain.
TYPES_INFRA = [
    "internal hostname", "ip address", "container image reference",
    "git repository", "kubernetes namespace", "service account",
    "email address", "secret key or token", "file name",
]

#: Pour la bande ambiguë : deux types CONCURRENTS, le contexte tranche.
TYPES_AMBIGU = ["file name", "server hostname", "domain name"]

#: Donnée personnelle : le terrain où privacy-filter gagnait.
TYPES_PERSO = ["person name", "postal address", "phone number",
               "date of birth", "bank account number", "credit card number"]

INFRA = [
    ("Le pod tourne sur node-03-prod.acmecorp.internal en 10.42.3.17.",
     ["node-03-prod.acmecorp.internal", "10.42.3.17"]),
    ("On tire registry.acmecorp.io/payments/api:4.2.1 depuis le miroir.",
     ["registry.acmecorp.io/payments/api:4.2.1"]),
    ("Le depot est github.com/acmecorp/payments-api, branche main.",
     ["github.com/acmecorp/payments-api"]),
    ("Le namespace demo-apps heberge svc-payments-prod.",
     ["demo-apps", "svc-payments-prod"]),
    ("La cle AKIAIOSFODNN7EXAMPLE est encore active sur le compte.",
     ["AKIAIOSFODNN7EXAMPLE"]),
    ("Le jeton est ghp_16C7e42F292c6912E7710c838347Ae178B4a pour le CI.",
     ["ghp_16C7e42F292c6912E7710c838347Ae178B4a"]),
]

AMBIGU = [
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
    ("Relis CLAUDE.md avant de committer quoi que ce soit.",
     "CLAUDE.md", "public"),
    ("Le serveur CLAUDE.md ne repond plus depuis la migration.",
     "CLAUDE.md", "sensible"),
]

PERSO = [
    ("Livraison a relancer au 14 rue des Grands-Augustins, 75006 Paris.",
     ["14 rue des Grands-Augustins"]),
    ("Le dossier de Solveig Bergqvist est bloque depuis le 3 fevrier 1987.",
     ["Solveig Bergqvist", "3 fevrier 1987"]),
    ("Le ticket a ete ouvert par Ines Ferreira-Konate le 12 mars.",
     ["Ines Ferreira-Konate"]),
    ("Rappeler M. Thibault Escourrou au 06 12 34 56 78 avant vendredi.",
     ["Thibault Escourrou", "06 12 34 56 78"]),
]

SEUIL = 0.35


def couvre(spans, valeur):
    for s in spans:
        t = s["text"].strip()
        if len(t) < 3:
            continue
        if t in valeur or valeur in t:
            return s
        if any(len(m) >= 3 and m in t for m in valeur.replace("/", ".").split(".")):
            return s
    return None


def main() -> None:
    from gliner import GLiNER
    import torch

    for nom in MODELES:
        print(f"\n{'=' * 74}\n{nom}")
        t0 = time.perf_counter()
        try:
            mdl = GLiNER.from_pretrained(nom)
        except Exception as exc:  # noqa: BLE001
            print(f"  chargement impossible : {type(exc).__name__}: {exc}")
            continue
        if torch.cuda.is_available():
            mdl = mdl.to("cuda")
        print(f"chargé en {time.perf_counter() - t0:.1f}s")

        def pred(texte, types):
            return mdl.predict_entities(texte, types, threshold=SEUIL)

        pred("echauffement", TYPES_INFRA)

        print("\n### INFRASTRUCTURE — types déclarés par nous")
        vus = total = 0
        for texte, attendus in INFRA:
            spans = pred(texte, TYPES_INFRA)
            for a in attendus:
                s = couvre(spans, a)
                vus += s is not None
                total += 1
                etiquette = f"{s['label']} {s['score']:.2f}" if s else ""
                print(f"  {'vu  ' if s else 'RATÉ'} {a:<42} {etiquette}")
        print(f"  {vus}/{total}")

        print("\n### BANDE AMBIGUË — « file name » CONTRE « server hostname »")
        bons = 0
        for texte, token, attendu in AMBIGU:
            spans = pred(texte, TYPES_AMBIGU)
            s = couvre(spans, token)
            # Le verdict vient de l'ÉTIQUETTE gagnante, pas de la seule présence.
            verdict = "public"
            if s and s["label"] in ("server hostname", "domain name"):
                verdict = "sensible"
            bons += verdict == attendu
            etiquette = f"{s['label']} {s['score']:.2f}" if s else "aucun span"
            print(f"  {'ok ' if verdict == attendu else 'NON'} attendu"
                  f" {attendu:<9} → {verdict:<9} {token:<21} {etiquette}")
        print(f"  {bons}/{len(AMBIGU)}")

        print("\n### DONNÉE PERSONNELLE EN PROSE")
        vus = total = 0
        for texte, attendus in PERSO:
            spans = pred(texte, TYPES_PERSO)
            for a in attendus:
                s = couvre(spans, a)
                vus += s is not None
                total += 1
                etiquette = f"{s['label']} {s['score']:.2f}" if s else ""
                print(f"  {'vu  ' if s else 'RATÉ'} {a:<36} {etiquette}")
        print(f"  {vus}/{total}")

        mesures = []
        for _ in range(10):
            t = time.perf_counter()
            pred(AMBIGU[0][0], TYPES_AMBIGU)
            mesures.append((time.perf_counter() - t) * 1000)
        mesures.sort()
        ref = pred(AMBIGU[1][0], TYPES_AMBIGU)
        stable = all(pred(AMBIGU[1][0], TYPES_AMBIGU) == ref for _ in range(5))
        print(f"\n  latence p50 {mesures[5]:.1f} ms · max {mesures[-1]:.1f} ms"
              f" · déterministe : {stable}")


if __name__ == "__main__":
    main()
