#!/usr/bin/env python3
"""Gestionnaire de la politique de confidentialité.

Le proxy anonymise tout et consigne une question pour chaque valeur qu'aucune
règle ne couvre. Cet outil sert à répondre à ces questions, et à relire ou
modifier les règles.

    anonproxy_policy.py etat                  ce qui est réglé, par portée
    anonproxy_policy.py questions             ce qui attend un arbitrage
    anonproxy_policy.py arbitrer              les poser une à une
    anonproxy_policy.py valeur  <portée> <TYPE> <VALEUR> <décision>\n    anonproxy_policy.py definir <portée> <granularité> <clé> <décision>
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
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from anonproxy.config import Settings, read_master_key  # noqa: E402
from anonproxy.modes import (  # noqa: E402
    ENV, MODES, REGLAGES, ReglageInvalide, defauts_du_mode,
)
from anonproxy.policy import (  # noqa: E402
    GRANULARITES, PORTEES, Decision, PolitiqueInvalide, Policy,
)
from anonproxy.vault import SurrogateConflict, Vault  # noqa: E402

#: Ce que l'opérateur peut répondre. « Révéler » n'est jamais le défaut : il
#: faut le taper.
#: Les libellés NOMMENT le type et la classe, et l'affichage y ajoute combien
#: de questions en attente la réponse réglerait.
#:
#: « révéler ce TYPE en entier » se lit comme une décision sur l'entrée qu'on
#: regarde. Elle en ouvre une dizaine d'un coup au niveau CLASSE — et révéler
#: est la seule décision qui fasse sortir une valeur, dont l'erreur est
#: silencieuse et que révoquer ne rattrape pas. La portée doit être lisible AU
#: MOMENT du choix, pas après.
REPONSES = {
    "v": ("valeur", Decision.REVELER, "révéler CETTE valeur, elle seule"),
    "t": ("type", Decision.REVELER, "révéler TOUT le type {type}"),
    "c": ("classe", Decision.REVELER, "révéler TOUTE la classe {classe}"),
    "T": ("type", Decision.ANONYMISER,
          "anonymiser tout le type {type}, ne plus demander"),
    "C": ("classe", Decision.ANONYMISER,
          "anonymiser toute la classe {classe}, ne plus demander"),
}

#: Révéler POUR CE MESSAGE, à la granularité de ce qui est affiché — le groupe
#: entier s'il est groupé, la valeur seule s'il a été détaillé.
#:
#: Ce n'est pas une quatrième portée : rien n'est écrit dans un fichier de
#: portée, donc rien ne survit. C'est la réponse à la question courante, et
#: c'est ce qui manquait — « juste ici, juste maintenant » était la seule chose
#: que l'opérateur ne pouvait pas dire sans laisser une règle derrière lui.
TOUCHE_MESSAGE = "m"


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


def cmd_mode(args) -> int:
    politique, _, _ = _outils(args)
    resolus = politique.reglages_resolus()
    print(f"mode en vigueur : {resolus['mode']}\n")
    for nom in REGLAGES:
        origine = "défaut du mode"
        if os.environ.get(ENV[nom]):
            origine = f"variable d'env {ENV[nom]}"
        else:
            for portee in reversed(PORTEES):
                if nom in (politique.resolue()[portee].get("reglages") or {}):
                    origine = f"portée {portee}"
                    break
        print(f"  {nom:<18} {str(resolus[nom]):<14} ({origine})")
    print("\nModes disponibles :")
    for nom, reglages in sorted(MODES.items()):
        detail = " · ".join(f"{k}={v}" for k, v in reglages.items())
        print(f"  {nom:<14} {detail}")
    print("\nUn mode n'est qu'un JEU de réglages : chacun se surcharge"
          "\nindividuellement, et aucun mode ne peut ouvrir quoi que ce soit —"
          "\nle défaut reste ANONYMISER partout.")
    return 0


def cmd_regler(args) -> int:
    politique, _, _ = _outils(args)
    try:
        chemin = politique.definir_reglage(args.portee_pos, args.nom, args.valeur)
    except ReglageInvalide as exc:
        print(f"REFUSÉ : {exc}", file=sys.stderr)
        return 2
    print(f"{args.nom} = {args.valeur} (portée {args.portee_pos}) → {chemin}")
    if args.nom == "mode":
        for nom, valeur in sorted(defauts_du_mode(args.valeur).items()):
            print(f"    {nom} = {valeur}")
    return 0


#: Combien d'exemples montrer par groupe. Assez pour reconnaître de quoi il
#: s'agit, pas assez pour redevenir une liste à plat.
APERCU = 3


def _groupes(questions: list[dict]) -> list[list[dict]]:
    """La file, groupée par TYPE — l'axe qui transforme 205 gestes en 15.

    L'ouverture est PROGRESSIVE par conception : une décision de type règle
    d'un coup toutes les questions du même type. Présenter la file à plat
    cachait cet axe, et l'opérateur voyait deux cents lignes là où quinze
    suffisent. Les plus nombreux d'abord : c'est là qu'un geste rapporte le
    plus.
    """
    par_type: dict[str, list[dict]] = {}
    for q in questions:
        par_type.setdefault(q["type"], []).append(q)
    return sorted(par_type.values(), key=len, reverse=True)


def _apercu(groupe: list[dict], vue: dict, marge: str = "        ") -> None:
    for q in groupe[:APERCU]:
        reel = vue.get(q["substitut"], "(hors coffre)")
        print(f"{marge}{reel!r} → {q['substitut']!r}")
    if len(groupe) > APERCU:
        print(f"{marge}… et {len(groupe) - APERCU} autre(s)")


def cmd_questions(args) -> int:
    politique, coffre, scope = _outils(args)
    vue = coffre.view(scope)
    questions = politique.questions()
    if not questions:
        print("aucune question en attente.")
        return 0
    groupes = _groupes(questions)
    print(f"{len(questions)} valeur(s) anonymisée(s) sans règle explicite, "
          f"en {len(groupes)} type(s) :\n")
    for groupe in groupes:
        tete = groupe[0]
        print(f"  {len(groupe):>4}  {tete['classe']:<6} {tete['type']}")
        _apercu(groupe, vue)
    print(f"\n`arbitrer` — {len(groupes)} geste(s) pour tout solder, "
          f"ou `arbitrer --une-par-une` pour trancher valeur par valeur.")
    return 0


def cmd_substituer(args) -> int:
    """Choisir soi-même le substitut d'une valeur.

    Le générateur vise la plausibilité (D1) sans rien connaître du domaine :
    parfois l'opérateur sait mieux, et un nom qu'il reconnaît lui coûte moins
    à relire. C'est un choix d'ERGONOMIE, jamais une ouverture — la valeur
    réelle reste dans le coffre et ne part pas davantage.
    """
    _politique, coffre, scope = _outils(args)
    ancien = coffre.get_surrogate(scope, args.type, args.valeur)
    try:
        coffre.rebind(scope, args.type, args.valeur, args.substitut)
    except SurrogateConflict as exc:
        # Refuser, jamais écraser : deux réels sous une même identité fictive
        # rendraient la restauration ambiguë, et le silence est le pire mode
        # d'échec de ce système.
        print(f"refusé : {exc}", file=sys.stderr)
        print("  ce substitut appartient déjà à une AUTRE valeur ; en choisir "
              "un autre.", file=sys.stderr)
        return 1
    if ancien and ancien != args.substitut:
        print(f"{args.valeur!r} : {ancien!r} → {args.substitut!r}")
        print(f"  {ancien!r} reste restaurable : il est déjà parti sous ce nom.")
    else:
        print(f"{args.valeur!r} sortira désormais sous {args.substitut!r}")
    return 0


def cmd_arbitrer(args) -> int:
    politique, coffre, scope = _outils(args)
    vue = coffre.view(scope)
    questions = politique.questions()
    if not questions:
        print("aucune question en attente.")
        return 0

    portee = args.portee
    # Par GROUPE de type ; `--une-par-une` retrouve le geste fin. Le défaut est
    # le groupe parce que c'est là que le temps d'arbitrage se joue : quinze
    # gestes au lieu de deux cents, sans rien perdre — le détail reste à une
    # touche, et une réponse de type couvre exactement le groupe affiché.
    unites = ([[q] for q in questions] if getattr(args, "une_par_une", False)
              else _groupes(questions))
    file_a_traiter = list(unites)
    i = 0
    while file_a_traiter:
        groupe = file_a_traiter.pop(0)
        i += 1
        q = groupe[0]
        groupe_entier = len(groupe) > 1
        reel = vue.get(q["substitut"], "(hors coffre)")
        print(f"\n[{i}/{len(unites)}] {q['classe']} · {q['type']}"
              + (f"   — {len(groupe)} valeur(s)" if groupe_entier else ""))
        if groupe_entier:
            _apercu(groupe, vue, marge="  ")
        else:
            print(f"  valeur réelle : {reel!r}")
            print(f"  envoyée sous  : {q['substitut']!r}  (anonymisée par défaut)")
        couvre = {
            "valeur": 1,
            "type": sum(1 for x in questions if x["type"] == q["type"]),
            "classe": sum(1 for x in questions if x["classe"] == q["classe"]),
        }
        for touche, (granularite, decision, modele) in REPONSES.items():
            # Sur un groupe, « CETTE valeur » n'a pas de référent : c'est
            # précisément ce que `d` sert à obtenir.
            if groupe_entier and granularite == "valeur":
                continue
            libelle = modele.format(type=q["type"], classe=q["classe"])
            combien = couvre[granularite]
            portee_visible = (f"   ({combien} question(s) en attente)"
                              if combien > 1 else "")
            print(f"    {touche} — {libelle}{portee_visible}")
        print(f"    {TOUCHE_MESSAGE} — révéler pour CE MESSAGE seulement"
              f" ({'ce groupe' if groupe_entier else 'cette valeur'},"
              " rien n'est enregistré)")
        if groupe_entier:
            print(f"    d — détailler les {len(groupe)} valeurs, une par une")
        print("    ⏎ — laisser anonymisé, redemander plus tard")

        choix = args.repondre if args.repondre is not None else input("  > ").strip()
        if not choix:
            continue
        if groupe_entier and choix == "d":
            # Le groupe repasse en tête, éclaté : la granularité fine reste à
            # une touche, elle n'est simplement plus le défaut.
            file_a_traiter[:0] = [[x] for x in groupe]
            unites = unites + [[x] for x in groupe]
            continue
        if choix == TOUCHE_MESSAGE:
            granularite = "type" if groupe_entier else "valeur"
            cle = q["type"] if groupe_entier else q["empreinte"]
            politique.repondre_pour_le_message(granularite, cle,
                                               Decision.REVELER)
            print(f"  → révélé pour CE MESSAGE ({granularite} {cle}) ;"
                  " rien n'est enregistré, la réponse meurt avec le message")
            print("  ⚠ ce qui sort maintenant est SORTI : y revenir ne le"
                  " rappellera pas.")
            continue
        if choix not in REPONSES:
            print(f"  réponse inconnue : {choix!r} — laissé anonymisé")
            continue
        granularite, decision, modele = REPONSES[choix]
        libelle = modele.format(type=q["type"], classe=q["classe"])
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


def cmd_valeur(args) -> int:
    """Décider sur UNE valeur qu'on désigne par ce qu'elle est.

    `definir … valeur` attend une EMPREINTE, qui n'existe que dans la file
    d'arbitrage : hors de ce flux, l'opérateur ne pouvait pas désigner une
    valeur qu'il a en tête — `Claude`, `::c`, un mot que le détecteur prend pour
    un hôte. La décision était juste et inapplicable.

    L'empreinte est imprimée : c'est elle qu'il faudra pour révoquer.
    """
    # Le moteur consulte la politique APRÈS canonicalisation — c'est ce qui fait
    # qu'une décision prise sur `DB-01.acme.internal` vaut aussi pour
    # `db-01.acme.internal`. Calculer l'empreinte sur la valeur BRUTE écrivait
    # donc une règle qui ne s'applique jamais : elle a l'air prise, et elle ne
    # décide rien. On réutilise la fonction du moteur plutôt que de refaire la
    # canonicalisation ici, qui divergerait au premier changement.
    from anonproxy.surrogates.canonical import canonicalize
    from anonproxy.surrogates.engine import _display_value

    politique, _, _ = _outils(args)
    canon = canonicalize(args.type_pos, args.valeur)
    empreinte = politique.empreinte(args.type_pos, _display_value(canon, args.valeur))
    decision = Decision(args.decision)
    try:
        chemin = politique.definir(args.portee_pos, "valeur", empreinte, decision)
    except (PolitiqueInvalide, ValueError) as exc:
        print(f"REFUSÉ : {exc}", file=sys.stderr)
        return 2
    print(f"{args.valeur!r} ({args.type_pos}) → {decision.value}, "
          f"portée {args.portee_pos}")
    print(f"  empreinte : {empreinte}   (pour révoquer : retirer "
          f"{args.portee_pos} valeur {empreinte})")
    if decision is Decision.REVELER:
        print("  ⚠ cette valeur SORT désormais en clair ; révoquer la règle ne "
              "rappellera pas ce qui est déjà parti.")
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
    sous.add_parser("mode").set_defaults(func=cmd_mode)

    p = sous.add_parser("regler", help="poser un réglage, ou un mode entier")
    p.add_argument("portee_pos", choices=PORTEES, metavar="portée")
    p.add_argument("nom", metavar="réglage",
                   choices=[*REGLAGES, "mode"])
    p.add_argument("valeur")
    p.set_defaults(func=cmd_regler)
    sous.add_parser("questions").set_defaults(func=cmd_questions)

    p = sous.add_parser("substituer",
                        help="choisir soi-même le substitut d'une valeur")
    p.add_argument("type", metavar="TYPE", help="HOSTNAME, IP_ADDRESS, PERSON…")
    p.add_argument("valeur", metavar="VALEUR", help="la valeur RÉELLE")
    p.add_argument("substitut", metavar="SUBSTITUT", help="ce qu'Anthropic verra")
    p.set_defaults(func=cmd_substituer)

    p = sous.add_parser("arbitrer")
    p.add_argument("--portee", choices=PORTEES, default="projet",
                   help="portée où écrire la décision (défaut : projet)")
    p.add_argument("--repondre", choices=sorted(REPONSES), default=None,
                   help="répondre la même chose à tout, sans interaction")
    p.add_argument("--une-par-une", action="store_true", dest="une_par_une",
                   help="trancher valeur par valeur (défaut : par type)")
    p.set_defaults(func=cmd_arbitrer)

    p = sous.add_parser("valeur")
    p.add_argument("portee_pos", choices=PORTEES, metavar="portée")
    p.add_argument("type_pos", metavar="TYPE", help="le type détecté, ex. PERSON")
    p.add_argument("valeur", metavar="VALEUR", help="la valeur RÉELLE, en clair")
    p.add_argument("decision", choices=[d.value for d in Decision])
    p.set_defaults(func=cmd_valeur)

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
