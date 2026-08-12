"""Reading a date, and writing it back in the same hand.

A date is not replaced, it is SHIFTED — by one constant per scope. An incident
is a sequence, and drawing each date independently would hand the operator a
chronology that contradicts itself: closed before opened, an outage lasting
minus three days. The engine already carries an invariant for exactly this
family of defect — a surrogate must be indistinguishable IN NATURE from what it
replaces — and for a date, its nature includes its place in a series.

Parsing here is deliberately narrow. A permissive parser would read a version
number or a port range as a date and shift it, which breaks something that was
never a date to begin with; and what this module cannot read is not left alone,
it is handed back to the generic substitution.
"""
from __future__ import annotations

import datetime as dt
import re
import unicodedata
from typing import Callable

MOIS_FR = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet",
           "août", "septembre", "octobre", "novembre", "décembre")
MOIS_EN = ("january", "february", "march", "april", "may", "june", "july",
           "august", "september", "october", "november", "december")

#: `2026-02-03`, éventuellement suivi d'une HEURE qu'on ne touche pas.
#:
#: La queue était `[T ].*` — libre, donc elle avalait tout ce qui suivait, y
#: compris une SECONDE date : `2020-03-15 to 2020-04-16` se lisait comme une
#: date suivie d'un « reste » recopié verbatim, et la seconde date sortait en
#: clair. Une queue libre après un motif ancré est la même classe que celle
#: payée sur les chemins d'URL au tour 11 : elle doit dire ce qu'elle accepte.
_ISO = re.compile(
    r"^(\d{4})-(\d{2})-(\d{2})"
    r"(?P<reste>[T ]\d{2}:\d{2}(?::\d{2})?(?:[.,]\d+)?"
    r"(?:Z|[+-]\d{2}:?\d{2})?)?$")
#: `2026/02/03` — année d'abord : l'ordre lève l'ambiguïté par lui-même.
_ISO_SLASH = re.compile(r"^(\d{4})/(\d{1,2})/(\d{1,2})$")
#: `03/02/2026`, `03-02-2026`, `3.2.2026` — jour d'abord, usage européen.
_NUMERIQUE = re.compile(r"^(\d{1,2})([/.\-])(\d{1,2})\2(\d{4})$")
#: `12 mars 2019`, `1er janvier 2020`, `12 March 2019`, `3 fév. 2020`.
_LITTERAL = re.compile(r"^(\d{1,2})(er)? ([^\W\d_]+)(\.?) (\d{4})$", re.UNICODE)
#: `March 3, 2020` — le mois d'abord, usage anglophone.
_LITTERAL_EN = re.compile(r"^([^\W\d_]+)(\.?) (\d{1,2}),? (\d{4})$", re.UNICODE)


def _sans_accent(mot: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", mot.lower())
                   if unicodedata.category(c) != "Mn")


def _sans_accents(table: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_sans_accent(m) for m in table)


_MOIS_FR_NUS = _sans_accents(MOIS_FR)
#: En dessous, un préfixe ne désigne plus un mois : `ju` vaut juin ET juillet,
#: `ma` vaut mars ET mai. Trois lettres suffisent partout ailleurs.
_ABREV_MIN = 3


def _mois_index(nom: str, preferee: tuple[str, ...] = MOIS_FR
                ) -> tuple[int, tuple[str, ...]] | None:
    """Le numéro du mois et la table qui l'a reconnu, ou None.

    Comparé SANS accent : `fevrier` et `aout` sont la norme dans un log ASCII,
    et les refuser faisait retomber la date sur la substitution générique — un
    mot d'hôte là où le document annonce une date, donc la nature perdue sur la
    moitié des documents français.

    Une ABRÉVIATION est acceptée quand elle ne désigne qu'un seul mois :
    `3 fév.` et `15 Sept 2020` s'écrivent partout, et retombaient en mot.
    L'unicité est vérifiée, jamais supposée — `jui` vaut juin comme juillet, et
    le prendre pour l'un des deux fabriquerait une date fausse.
    """
    nu = _sans_accent(nom)
    # La table PRÉFÉRÉE d'abord : `sept` préfixe `septembre` ET `september`,
    # donc l'ordre décidait seul. Un document anglais (`sept 15, 2020`) recevait
    # un mois FRANÇAIS — une forme hybride que le modèle normalise en anglais
    # dans sa réponse, et que le coffre ne reconnaît plus : la restauration se
    # perd EN SILENCE. La syntaxe lue est le seul indice de langue disponible,
    # et c'est l'appelant qui la connaît.
    tables = ((preferee, _sans_accents(preferee)),
              *((t, _sans_accents(t)) for t in (MOIS_FR, MOIS_EN) if t is not preferee))
    for table, nus in tables:
        if nu in nus:
            return nus.index(nu) + 1, table
    if len(nu) < _ABREV_MIN:
        return None
    for table, nus in tables:
        candidats = [i for i, m in enumerate(nus) if m.startswith(nu)]
        if len(candidats) == 1:
            return candidats[0] + 1, table
    return None


def _rendre_mois(nom_source: str, point: str, table: tuple[str, ...],
                 mois_source: int, mois: int) -> str:
    """Le mois d'arrivée, écrit comme celui de départ.

    Rendre `septembre` là où le document portait `fév.` change la forme sous
    les yeux de l'opérateur sans rien protéger de plus : une abréviation reste
    une abréviation, et la casse est celle qu'on a lue.

    La longueur se compare au mois de DÉPART, pas à celui d'arrivée : `March`
    est un nom complet de cinq lettres, et le mesurer contre `january` en
    faisait une abréviation — `15 March 2020` revenait `30 Janua 2021`.
    """
    nom = table[mois - 1]
    # La source a-t-elle RETIRÉ un accent que son propre mois porte ? Alors le
    # document est écrit en ASCII et le rendu doit l'être aussi : couper `août`
    # à trois donnait `aoû` là où le document portait `fev`, et le modèle
    # « corrige » ce qu'il lit — le coffre ne reconnaît plus rien.
    #
    # La condition porte sur le mois de DÉPART, pas sur la simple absence
    # d'accent : `janvier` n'en a pas parce que le mot n'en a pas, et en
    # déduire de l'ASCII faisait rendre `fevrier` au lieu de `février`.
    canonique = table[mois_source - 1]
    if _sans_accent(canonique) != canonique and \
            _sans_accent(nom_source) == nom_source.lower():
        nom = _sans_accent(nom)
    coupe = len(_sans_accent(nom_source))
    if coupe < len(_sans_accent(table[mois_source - 1])):
        tronque = nom[:coupe]
        # **Ce qu'on écrit doit pouvoir se relire.** `juillet` coupé à trois
        # donne `jui`, précisément le préfixe que `_mois_index` REFUSE parce
        # qu'il vaut juin ET juillet : la restauration s'y perdait en silence.
        relu = _mois_index(tronque, table)
        if relu is not None and relu[0] == mois:
            nom = tronque
    if nom_source.isupper():
        nom = nom.upper()
    elif nom_source[:1].isupper():
        nom = nom.capitalize()
    return nom + point


def parse(valeur: str) -> tuple[dt.date, Callable[[dt.date], str]] | None:
    """Rend la date lue et de quoi la RÉÉCRIRE dans la même forme.

    Le rendu est une fermeture plutôt qu'un nom de format : c'est ce qui garde
    la forme d'origine — séparateur, casse du mois, zéros de tête — sans avoir
    à l'énumérer une seconde fois au moment d'écrire.
    """
    valeur = valeur.strip()

    if (m := _ISO.match(valeur)):
        reste = m.group("reste") or ""
        try:
            jour = dt.date(int(m[1]), int(m[2]), int(m[3]))
        except ValueError:
            return None
        # L'heure est CONSERVÉE : décaler l'heure casserait l'ordre des
        # événements à l'intérieur d'une journée, qui est ce que l'agent lit.
        return jour, lambda d: f"{d.isoformat()}{reste}"

    if (m := _ISO_SLASH.match(valeur)):
        largeurs = (len(m[2]), len(m[3]))
        try:
            jour = dt.date(int(m[1]), int(m[2]), int(m[3]))
        except ValueError:
            return None
        return jour, lambda d: (f"{d.year:04d}/{d.month:0{largeurs[0]}d}"
                                f"/{d.day:0{largeurs[1]}d}")

    if (m := _NUMERIQUE.match(valeur)):
        sep, largeur = m[2], (2 if len(m[1]) == 2 else 1)
        # Jour d'abord, comme le reste du fichier. Quand cette lecture est
        # IMPOSSIBLE — `03/15/2020`, où 15 ne peut pas être un mois — la forme
        # anglophone est la seule qui reste, donc il n'y a rien à deviner. Une
        # date ambiguë (deux nombres ≤ 12) reste lue jour d'abord : choisir une
        # convention et s'y tenir est ce qui préserve les INTERVALLES, et un
        # intervalle faux se voit moins qu'une date fausse.
        for annee, mois, jour_du_mois, inverse in (
                (m[4], m[3], m[1], False), (m[4], m[1], m[3], True)):
            try:
                jour = dt.date(int(annee), int(mois), int(jour_du_mois))
            except ValueError:
                continue
            ordre = (lambda d: (d.month, d.day)) if inverse else \
                (lambda d: (d.day, d.month))
            return jour, lambda d, _o=ordre: sep.join(
                (f"{_o(d)[0]:0{largeur}d}", f"{_o(d)[1]:0{largeur}d}",
                 f"{d.year:04d}"))
        return None

    for motif, ordre_en in ((_LITTERAL, False), (_LITTERAL_EN, True)):
        if not (m := motif.match(valeur)):
            continue
        nom_mois, point = (m[1], m[2]) if ordre_en else (m[3], m[4])
        # La syntaxe dit la langue : `March 3, 2020` est anglophone,
        # `3 mars 2020` francophone. C'est le seul indice disponible, et
        # sans lui une abréviation commune aux deux tables (`sept`, `oct`,
        # `nov`, `dec`) faisait rendre un mois français dans une forme
        # anglaise.
        reconnu = _mois_index(nom_mois, MOIS_EN if ordre_en else MOIS_FR)
        if reconnu is None:
            return None
        mois, table = reconnu
        virgule = "," if ordre_en and ", " in valeur else ""
        try:
            jour = dt.date(int(m[4] if ordre_en else m[5]), mois,
                           int(m[3] if ordre_en else m[1]))
        except ValueError:
            return None

        ordinal = "" if ordre_en else (m[2] or "")

        def rendre(d: dt.date, _en=ordre_en, _nom=nom_mois, _pt=point,
                   _t=table, _v=virgule, _src=mois, _ord=ordinal) -> str:
            écrit = _rendre_mois(_nom, _pt, _t, _src, d.month)
            if _en:
                return f"{écrit} {d.day}{_v} {d.year}"
            # `1er` ne vaut qu'au premier du mois : le recopier sur un autre
            # jour écrirait une forme que le français n'a pas.
            return f"{d.day}{_ord if d.day == 1 else ''} {écrit} {d.year}"

        return jour, rendre

    return None




#: Les formes reconnues, CHERCHÉES dans le span plutôt qu'imposées à lui.
#:
#: Un détecteur rend le champ tel qu'il est écrit — `3 février 2026 à 14h32`,
#: `le 3 février 2026`, `du 12 mars 2019 au`. Exiger une date NUE faisait
#: échouer la lecture, et la valeur retombait sur la substitution générique :
#: le modèle recevait un mot d'hôte là où le document annonçait une date, et
#: cessait de pouvoir répondre « quand ». L'entourage n'est pas du bruit, c'est
#: du texte qu'il faut rendre intact.
#: `(?<![^\W\d_])` — le motif qui commence par un NOM DE MOIS doit commencer un
#: mot. Sans cette assertion, sa tête est une classe libre : sur une longue
#: suite de lettres sans date, le moteur consomme toute la suite depuis CHAQUE
#: position, donc un coût quadratique. Mesuré avant : 565 ms sur 10 Ko, 56,7 s
#: sur 100 Ko — de quoi figer l'agent sans qu'aucune date soit en jeu.
#:
#: Ce projet a payé trois tours entiers sur cette même famille dans le hook, et
#: la règle qui en était sortie était « tout motif ancré sur son littéral ». Je
#: l'ai rouverte en ajoutant une forme. Les autres motifs commencent par un
#: chiffre borné, donc échouent au premier caractère d'une suite de lettres.
_CHERCHE = (
    re.compile(r"\d{4}-\d{2}-\d{2}"),
    re.compile(r"\d{4}/\d{1,2}/\d{1,2}"),
    re.compile(r"\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4}"),
    re.compile(r"\d{1,2}(?:er)? [^\W\d_]+\.? \d{4}", re.UNICODE),
    re.compile(r"(?<![^\W\d_])[^\W\d_]+\.? \d{1,2},? \d{4}", re.UNICODE),
)


def chercher_toutes(valeur: str) -> list[tuple[int, int]]:
    """Bornes de TOUTES les dates lisibles, de gauche à droite, sans recouvrement.

    Une valeur en porte souvent plusieurs — `du 3 février 2026 au 12 mars 2026`
    est la forme ordinaire d'une plage. N'en traiter qu'une laissait la seconde
    VERBATIM : hors du span resserré, donc jamais substituée, ou recopiée telle
    quelle dans le substitut. Une vraie date sortait.

    En cas de recouvrement, la plus LONGUE gagne : `3 février 2026` doit primer
    sur ce qu'un motif plus court pourrait attraper dedans.
    """
    trouves: list[tuple[int, int]] = []
    for motif in _CHERCHE:
        for m in motif.finditer(valeur):
            if parse(m.group(0)) is not None:
                trouves.append((m.start(), m.end()))
    retenus: list[tuple[int, int]] = []
    for debut, fin in sorted(trouves, key=lambda b: (b[0], -(b[1] - b[0]))):
        if all(fin <= d or debut >= f for d, f in retenus):
            retenus.append((debut, fin))
    return sorted(retenus)


def chercher(valeur: str) -> tuple[int, int] | None:
    """Bornes de la PREMIÈRE date contenue dans la valeur, ou None.

    Sert d'abord à resserrer un span avant qu'il n'entre au coffre : la clé
    doit être la date, pas le champ qui la porte, sinon le modèle citant la
    date seule ne retrouve rien. L'appelant doit vérifier avec
    `chercher_toutes` qu'il n'y en a pas plusieurs — resserrer sur la première
    ferait sortir les suivantes du span, donc en clair.
    """
    toutes = chercher_toutes(valeur)
    return toutes[0] if toutes else None


def shift(valeur: str, jours: int) -> str | None:
    """Décale la date CONTENUE dans la valeur, en gardant tout le reste.

    None seulement s'il n'y a aucune date lisible — auquel cas l'appelant
    substitue génériquement, et la nature ne peut pas être tenue.
    """
    lu = parse(valeur)
    if lu is not None:
        jour, rendre = lu
        try:
            return rendre(jour + dt.timedelta(days=jours))
        except OverflowError:
            return None

    # TOUTES les dates, pas la première. N'en décaler qu'une laissait les
    # suivantes VERBATIM dans le substitut : `du 3 février 2026 au 12 mars
    # 2026` sortait avec sa seconde date intacte, donc une vraie date partait.
    bornes = chercher_toutes(valeur)
    if not bornes:
        return None
    morceaux: list[str] = []
    curseur = 0
    decalee_au_moins_une = False
    for debut, fin in bornes:
        if (debut, fin) == (0, len(valeur)):
            # `parse` a déjà refusé cette valeur entière : se rappeler dessus
            # ne peut que recommencer. Une date qui a la FORME d'une date sans
            # en être une (`2020-02-30`, courant dans un export) faisait ainsi
            # exploser la pile, et `RecursionError` n'est rattrapée nulle part.
            return None
        decalee = shift(valeur[debut:fin], jours)
        morceaux.append(valeur[curseur:debut])
        morceaux.append(decalee if decalee is not None else valeur[debut:fin])
        decalee_au_moins_une |= decalee is not None
        curseur = fin
    morceaux.append(valeur[curseur:])
    return "".join(morceaux) if decalee_au_moins_une else None
