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

#: `2026-02-03`, éventuellement suivi d'une heure qu'on ne touche pas.
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?P<reste>[T ].*)?$")
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


_MOIS_FR_NUS = tuple(_sans_accent(m) for m in MOIS_FR)
#: En dessous, un préfixe ne désigne plus un mois : `ju` vaut juin ET juillet,
#: `ma` vaut mars ET mai. Trois lettres suffisent partout ailleurs.
_ABREV_MIN = 3


def _mois_index(nom: str) -> tuple[int, tuple[str, ...]] | None:
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
    for table, nus in ((MOIS_FR, _MOIS_FR_NUS), (MOIS_EN, MOIS_EN)):
        if nu in nus:
            return nus.index(nu) + 1, table
    if len(nu) < _ABREV_MIN:
        return None
    for table, nus in ((MOIS_FR, _MOIS_FR_NUS), (MOIS_EN, MOIS_EN)):
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
    coupe = len(_sans_accent(nom_source))
    if coupe < len(_sans_accent(table[mois_source - 1])):
        nom = nom[:coupe]
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
        reconnu = _mois_index(nom_mois)
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
_CHERCHE = (
    re.compile(r"\d{4}-\d{2}-\d{2}"),
    re.compile(r"\d{4}/\d{1,2}/\d{1,2}"),
    re.compile(r"\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4}"),
    re.compile(r"\d{1,2}(?:er)? [^\W\d_]+\.? \d{4}", re.UNICODE),
    re.compile(r"[^\W\d_]+\.? \d{1,2},? \d{4}", re.UNICODE),
)


def chercher(valeur: str) -> tuple[int, int] | None:
    """Bornes de la date CONTENUE dans la valeur, ou None.

    Sert d'abord à resserrer un span avant qu'il n'entre au coffre : la clé
    doit être la date, pas le champ qui la porte, sinon le modèle citant la
    date seule ne retrouve rien.
    """
    for motif in _CHERCHE:
        trouve = motif.search(valeur)
        if trouve is not None and parse(trouve.group(0)) is not None:
            return trouve.start(), trouve.end()
    return None


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

    for motif in _CHERCHE:
        trouve = motif.search(valeur)
        if trouve is None:
            continue
        if trouve.group(0) == valeur:
            # `parse` a déjà refusé cette valeur entière : se rappeler dessus
            # ne peut que recommencer. Une date qui a la FORME d'une date sans
            # en être une (`2020-02-30`, courant dans un export) faisait ainsi
            # exploser la pile, et `RecursionError` n'est rattrapée nulle part.
            return None
        decalee = shift(trouve.group(0), jours)
        if decalee is not None:
            return valeur[:trouve.start()] + decalee + valeur[trouve.end():]
    return None
