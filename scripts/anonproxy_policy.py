#!/usr/bin/env python3
"""Gestionnaire de la politique de confidentialité.

Le proxy anonymise tout et consigne une question pour chaque valeur qu'aucune
règle ne couvre. Cet outil sert à répondre à ces questions, et à relire ou
modifier les règles.

    anonproxy_policy.py etat                  ce qui est réglé, par portée
    anonproxy_policy.py questions             ce qui attend un arbitrage
    anonproxy_policy.py arbitrer              les poser une à une
    anonproxy_policy.py definir <portée> <granularité> <clé> <décision>
    anonproxy_policy.py retirer <portée> <granularité> <clé>

Portées      : global · projet · session   (chacune sert de défaut à la suivante)
Granularités : classe · type · valeur      (la plus précise l'emporte)
Décisions    : anonymiser · reveler

L'arbitrage lit la valeur RÉELLE dans le coffre pour te la montrer : la file
d'attente, elle, ne porte que le substitut et ne révèle rien.

Non interactif (pour scripter ou tester) :
    anonproxy_policy.py arbitrer --repondre t   # « ce TYPE, révéler »
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from anonproxy.config import Settings, read_master_key  # noqa: E402
from anonproxy.policy import (  # noqa: E402
    GRANULARITES, PORTEES, Decision, PolitiqueInvalide, Policy,
)
from anonproxy.vault import Vault  # noqa: E402

#: Ce que l'opérateur peut répondre. « Révéler » n'est jamais le défaut : il
#: faut le taper.
REPONSES = {
    "v": ("valeur", Decision.REVELER, "révéler CETTE valeur"),
    "t": ("type", Decision.REVELER, "révéler ce TYPE en entier"),
    "c": ("classe", Decision.REVELER, "révéler cette CLASSE en entier"),
    "T": ("type", Decision.ANONYMISER, "anonymiser ce TYPE (ne plus demander)"),
    "C": ("classe", Decision.ANONYMISER, "anonymiser cette CLASSE (ne plus demander)"),
}


def _outils(args) -> tuple[Policy, Vault, str]:
    reglages = Settings.from_env()
    master = read_master_key(reglages.master_key_file)
    politique = Policy(racine=args.policy_dir or reglages.policy_dir,
                       master_key=master, scope_key=reglages.scope_key,
                       session=reglages.session_id)
    return politique, Vault(reglages.vault_path, master_key=master), reglages.scope_key


def cmd_etat(args) -> int:
    politique, _, scope = _outils(args)
    print(f"portée du projet : {scope}"
          f" · session : {politique.session or '(aucune)'}\n")
    for portee, contenu in politique.resolue().items():
        regles = sum(len(v) for v in contenu.values() if isinstance(v, dict))
        print(f"── {portee} ({regles} règle(s)) — {politique._fichiers[portee]}")
        for granularite in GRANULARITES:
            for cle, decision in sorted((contenu.get(granularite) or {}).items()):
                marque = "RÉVÈLE " if decision == "reveler" else "anonymise"
                court = cle if len(cle) <= 34 else cle[:31] + "…"
                print(f"     {marque} {granularite:<7} {court}")
    print("\nDéfaut, en l'absence de toute règle : anonymiser.")
    return 0


def cmd_questions(args) -> int:
    politique, coffre, scope = _outils(args)
    vue = coffre.view(scope)
    questions = politique.questions()
    if not questions:
        print("aucune question en attente.")
        return 0
    print(f"{len(questions)} valeur(s) anonymisée(s) sans règle explicite :\n")
    for q in questions:
        reel = vue.get(q["substitut"], "(hors coffre)")
        print(f"  {q['classe']:<6} {q['type']:<16} {reel!r}")
        print(f"  {'':<6} {'':<16} → envoyé sous {q['substitut']!r}")
    print("\n`arbitrer` pour les trancher une à une.")
    return 0


def cmd_arbitrer(args) -> int:
    politique, coffre, scope = _outils(args)
    vue = coffre.view(scope)
    questions = politique.questions()
    if not questions:
        print("aucune question en attente.")
        return 0

    portee = args.portee
    for i, q in enumerate(questions, 1):
        reel = vue.get(q["substitut"], "(hors coffre)")
        print(f"\n[{i}/{len(questions)}] {q['classe']} · {q['type']}")
        print(f"  valeur réelle : {reel!r}")
        print(f"  envoyée sous  : {q['substitut']!r}  (anonymisée par défaut)")
        for touche, (granularite, decision, libelle) in REPONSES.items():
            print(f"    {touche} — {libelle}")
        print("    ⏎ — laisser anonymisé, redemander plus tard")

        choix = args.repondre if args.repondre is not None else input("  > ").strip()
        if not choix:
            continue
        if choix not in REPONSES:
            print(f"  réponse inconnue : {choix!r} — laissé anonymisé")
            continue
        granularite, decision, libelle = REPONSES[choix]
        cle = {"valeur": q["empreinte"], "type": q["type"],
               "classe": q["classe"]}[granularite]
        try:
            chemin = politique.definir(portee, granularite, cle, decision)
        except PolitiqueInvalide as exc:
            print(f"  REFUSÉ : {exc}")
            continue
        print(f"  → {libelle}, portée {portee} ({chemin.name})")
        if decision is Decision.REVELER:
            print("  ⚠ à partir de maintenant cette valeur SORT en clair ;"
                  " révoquer la règle ne rappellera pas ce qui est déjà parti.")
    return 0


def cmd_definir(args) -> int:
    politique, _, _ = _outils(args)
    try:
        chemin = politique.definir(args.portee_pos, args.granularite, args.cle,
                                   Decision(args.decision))
    except (PolitiqueInvalide, ValueError) as exc:
        print(f"REFUSÉ : {exc}", file=sys.stderr)
        return 2
    print(f"écrit dans {chemin}")
    return 0


def cmd_retirer(args) -> int:
    politique, _, _ = _outils(args)
    ok = politique.retirer(args.portee_pos, args.granularite, args.cle)
    print("règle retirée." if ok else "aucune règle de ce nom.")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--policy-dir", type=Path, default=None)
    sous = ap.add_subparsers(dest="commande", required=True)

    sous.add_parser("etat").set_defaults(func=cmd_etat)
    sous.add_parser("questions").set_defaults(func=cmd_questions)

    p = sous.add_parser("arbitrer")
    p.add_argument("--portee", choices=PORTEES, default="projet",
                   help="portée où écrire la décision (défaut : projet)")
    p.add_argument("--repondre", choices=sorted(REPONSES), default=None,
                   help="répondre la même chose à tout, sans interaction")
    p.set_defaults(func=cmd_arbitrer)

    for nom, fonction in (("definir", cmd_definir), ("retirer", cmd_retirer)):
        p = sous.add_parser(nom)
        p.add_argument("portee_pos", choices=PORTEES, metavar="portée")
        p.add_argument("granularite", choices=GRANULARITES, metavar="granularité")
        p.add_argument("cle", metavar="clé")
        if nom == "definir":
            p.add_argument("decision", choices=[d.value for d in Decision])
        p.set_defaults(func=fonction)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
