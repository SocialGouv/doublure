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
from typing import Callable

MOIS_FR = ("janvier", "février", "mars", "avril", "mai", "juin", "juillet",
           "août", "septembre", "octobre", "novembre", "décembre")
MOIS_EN = ("january", "february", "march", "april", "may", "june", "july",
           "august", "september", "october", "november", "december")

#: `2026-02-03`, éventuellement suivi d'une heure qu'on ne touche pas.
_ISO = re.compile(r"^(\d{4})-(\d{2})-(\d{2})(?P<reste>[T ].*)?$")
#: `03/02/2026`, `03-02-2026`, `3.2.2026` — jour d'abord, usage européen.
_NUMERIQUE = re.compile(r"^(\d{1,2})([/.\-])(\d{1,2})\2(\d{4})$")
#: `12 mars 2019`, `1er janvier 2020`, `12 March 2019`.
_LITTERAL = re.compile(r"^(\d{1,2})(er)? ([^\W\d_]+) (\d{4})$", re.UNICODE)


def _mois_index(nom: str) -> int | None:
    nom = nom.lower()
    for table in (MOIS_FR, MOIS_EN):
        if nom in table:
            return table.index(nom) + 1
    return None


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

    if (m := _NUMERIQUE.match(valeur)):
        sep, largeur = m[2], (2 if len(m[1]) == 2 else 1)
        try:
            jour = dt.date(int(m[4]), int(m[3]), int(m[1]))
        except ValueError:
            return None
        return jour, lambda d: sep.join(
            (f"{d.day:0{largeur}d}", f"{d.month:0{largeur}d}", f"{d.year:04d}"))

    if (m := _LITTERAL.match(valeur)):
        mois = _mois_index(m[3])
        if mois is None:
            return None
        table = MOIS_FR if m[3].lower() in MOIS_FR else MOIS_EN
        capitale = m[3][:1].isupper()
        try:
            jour = dt.date(int(m[4]), mois, int(m[1]))
        except ValueError:
            return None

        def rendre(d: dt.date) -> str:
            nom = table[d.month - 1]
            return f"{d.day} {nom.capitalize() if capitale else nom} {d.year}"

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
    re.compile(r"\d{1,2}[/.\-]\d{1,2}[/.\-]\d{4}"),
    re.compile(r"\d{1,2}(?:er)? [^\W\d_]+ \d{4}", re.UNICODE),
)


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
        decalee = shift(trouve.group(0), jours)
        if decalee is not None:
            return valeur[:trouve.start()] + decalee + valeur[trouve.end():]
    return None
