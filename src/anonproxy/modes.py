"""Modes — des JEUX de réglages nommés, jamais des comportements opaques.

Un mode ne fait rien qu'un réglage ne fasse : il en pose plusieurs d'un coup.
C'est ce qui le rend inspectable (`politique.sh mode` imprime ce qu'il vaut) et
surchargeable réglage par réglage. Un mode qui cacherait de la logique serait
un défaut : on ne pourrait ni le lire, ni en dévier d'un cran.

Les réglages se résolvent comme tout le reste (philosophie, §3.1) :

    défaut du mode  →  global  →  projet  →  session  →  variable d'env

Le plus proche l'emporte, et une variable d'environnement gagne toujours :
c'est le levier de dépannage, il doit primer.

## Les deux modes que jo a demandés

**`auto`** — rapide. Tout est substitué sans jamais rien demander ; la question
est consignée pour plus tard, sans bloquer. Si l'agent est informé de la
couche, c'est LUI qui sollicite l'opérateur quand une valeur lui manque
vraiment. On paie une latence nulle et on accepte de ne rien arbitrer d'avance.

**`consciencieux`** — chaque valeur inconnue est soumise à l'opérateur AVANT
d'être remplacée. La requête attend. C'est lent par construction, et c'est le
but : rien de nouveau ne part sans qu'un humain l'ait vu passer.

Un troisième existe pour ce qu'il représente, pas pour l'usage courant :
**`ferme`** ne dit rien au modèle et ne demande rien à personne. C'est le
réglage le plus discret vis-à-vis de l'amont — au prix d'un agent qui devine
devant une incohérence, ce qu'on a mesuré comme défaillant.

## Ce qu'un mode ne décide JAMAIS

Le défaut reste ANONYMISER dans tous les modes, y compris `auto`. Un mode
choisit quand et comment l'opérateur est sollicité, jamais si la protection
s'applique. Aucun mode ne peut ouvrir quoi que ce soit.
"""
from __future__ import annotations

#: Annoncer la couche au modèle.
ANNONCE_SILENCIEUX = "silencieux"
ANNONCE_ANNONCE = "annonce"

#: Quand l'opérateur est sollicité pour une valeur qu'aucune règle ne couvre.
ARBITRAGE_DIFFERE = "differe"      # substitue, consigne, continue
ARBITRAGE_BLOQUANT = "bloquant"    # attend la décision avant de substituer

#: Espace des noms de domaine fictifs.
DOMAINES_TLD_REELS = "tld_reels"   # plausible (D1), collision possible
DOMAINES_RESERVES = "reserves"     # RFC 2606/6761 : prouvablement à personne

#: Ce qu'on substitue dans un CHEMIN. Un chemin est un contenant : ses
#: segments n'ont pas tous la même nature. `/home` est sur toutes les machines
#: du monde, le nom d'utilisateur désigne une personne, et le nom du projet
#: peut nommer un client — trois choses différentes que masquer en bloc
#: confondait.
#:
#: Le prix du masquage total n'est pas théorique : au round 7, une extension
#: prise pour un domaine a empêché l'agent de retrouver le fichier dont on lui
#: parlait, et il a épuisé ses tours à le chercher. Un agent bloqué est aussi
#: cassé qu'un agent qui fuit.
CHEMINS_COMPLET = "complet"                        # tout, l'ancien comportement
CHEMINS_UTILISATEUR_PROJET = "utilisateur_projet"  # l'utilisateur ET le projet
CHEMINS_UTILISATEUR = "utilisateur"                # l'utilisateur seul

#: Valeurs admises, par réglage. Une valeur hors liste est REFUSÉE : une faute
#: de frappe retomberait sinon en silence sur un défaut que l'opérateur croit
#: avoir changé.
VALEURS: dict[str, tuple[str, ...]] = {
    "annonce": (ANNONCE_SILENCIEUX, ANNONCE_ANNONCE),
    "arbitrage": (ARBITRAGE_DIFFERE, ARBITRAGE_BLOQUANT),
    "domaines_fictifs": (DOMAINES_TLD_REELS, DOMAINES_RESERVES),
    "chemins": (CHEMINS_COMPLET, CHEMINS_UTILISATEUR_PROJET, CHEMINS_UTILISATEUR),
}

#: Réglage numérique : combien de temps la requête attend une décision, en
#: mode bloquant. À l'échéance, on ANONYMISE — jamais l'inverse.
DELAI_ARBITRAGE = "delai_arbitrage"

MODES: dict[str, dict[str, object]] = {
    "auto": {
        "annonce": ANNONCE_ANNONCE,
        "arbitrage": ARBITRAGE_DIFFERE,
        "domaines_fictifs": DOMAINES_TLD_REELS,
        "chemins": CHEMINS_UTILISATEUR_PROJET,
        DELAI_ARBITRAGE: 0,
    },
    "consciencieux": {
        "annonce": ANNONCE_ANNONCE,
        "arbitrage": ARBITRAGE_BLOQUANT,
        "domaines_fictifs": DOMAINES_RESERVES,
        "chemins": CHEMINS_UTILISATEUR_PROJET,
        DELAI_ARBITRAGE: 120,
    },
    "ferme": {
        "annonce": ANNONCE_SILENCIEUX,
        "arbitrage": ARBITRAGE_DIFFERE,
        "domaines_fictifs": DOMAINES_RESERVES,
        "chemins": CHEMINS_UTILISATEUR_PROJET,
        DELAI_ARBITRAGE: 0,
    },
}

MODE_DEFAUT = "auto"

#: Variable d'environnement correspondant à chaque réglage.
ENV: dict[str, str] = {
    "annonce": "ANONPROXY_ANNONCE",
    "arbitrage": "ANONPROXY_ARBITRAGE",
    "domaines_fictifs": "ANONPROXY_DOMAINES_FICTIFS",
    "chemins": "ANONPROXY_CHEMINS",
    DELAI_ARBITRAGE: "ANONPROXY_DELAI_ARBITRAGE",
}


class ReglageInvalide(ValueError):
    """Réglage ou valeur hors du vocabulaire : refusé, jamais ignoré."""


def valide(nom: str, valeur) -> object:
    """Rend la valeur normalisée, ou lève. Le refus est le comportement utile :
    un réglage mal orthographié laisserait croire à un changement qui n'a pas
    eu lieu."""
    if nom == DELAI_ARBITRAGE:
        try:
            secondes = int(valeur)
        except (TypeError, ValueError):
            raise ReglageInvalide(
                f"{DELAI_ARBITRAGE} attend un nombre de secondes, reçu {valeur!r}"
            ) from None
        if secondes < 0:
            raise ReglageInvalide(f"{DELAI_ARBITRAGE} négatif : {secondes}")
        return secondes
    if nom not in VALEURS:
        raise ReglageInvalide(
            f"réglage inconnu : {nom!r} (parmi {', '.join(sorted(REGLAGES))})")
    v = str(valeur).lower()
    if v not in VALEURS[nom]:
        raise ReglageInvalide(
            f"{nom}={valeur!r} inconnu — attendu {' ou '.join(VALEURS[nom])}")
    return v


REGLAGES: tuple[str, ...] = (*VALEURS, DELAI_ARBITRAGE)


def defauts_du_mode(mode: str) -> dict[str, object]:
    if mode not in MODES:
        raise ReglageInvalide(
            f"mode inconnu : {mode!r} (parmi {', '.join(sorted(MODES))})")
    return dict(MODES[mode])
