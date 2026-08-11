"""Reassembling entities a token classifier returned in pieces.

Measured on the real model: `Ines Ferreira-Konate` comes back as
`' Ines Ferreira-K'` then `'onate'`. Substituting the pieces separately would
store half a name and let the other half leave — a leak wearing the shape of a
substitution, which is the worst form a defect takes in this system.

The merge works on OFFSETS, never on text: the text is precisely what is
fragmented. And it refuses to cross anything that is not part of a name, since
welding two people into one would hand two humans a single surrogate — the
injectivity guarantee (D6) broken from the other side.
"""
from __future__ import annotations

import re

#: Ce qui peut se trouver À L'INTÉRIEUR d'un nom entre deux fragments : la
#: coupure d'un mot (rien), une espace, un trait d'union, une apostrophe. Une
#: virgule, un point ou un mot séparent deux entités — pas deux morceaux d'une.
_LIAISONS = set(" -'’")
#: Au-delà, ce n'est plus une liaison mais du texte entre deux entités.
_ECART_MAX = 2
#: Le modèle rend volontiers l'espace qui précède le mot.
_BORDURES = " \t\n\r,;:.!?()[]{}\"'"


#: Vocabulaire de voie : sa présence suffit à faire une adresse d'un seul mot
#: composé. Sans lui, il faut au moins deux jetons ou une virgule.
_VOIES = ("rue", "avenue", "boulevard", "impasse", "place", "chemin", "quai",
          "route", "street", "road", "lane", "drive", "way")


def garder(span: dict) -> bool:
    """Ce span a-t-il la FORME de ce que le modèle en dit ?

    Mesuré sur un ticket réel : le numéro `4218` est rendu `ADDRESS` à 1.00, et
    `lica-` — quatre lettres prises au milieu de `db-replica-02-prod` — aussi.
    Ni l'un ni l'autre ne fuit : ils substituent PLUS que nécessaire, ce qui est
    le sens sans danger. Mais tous deux abîment le texte, et un modèle qui lit
    un document mutilé répond sur un document mutilé.

    La garde est volontairement grossière. Plus fine, elle serait un second
    détecteur en train de contredire le premier — et c'est le premier qui a vu
    le contexte.
    """
    valeur = span.get("value", "").strip()
    if not valeur:
        return False
    etype = span.get("type")
    mots = [m for m in re.split(r"[\s,]+", valeur) if m]

    if etype == "ADDRESS":
        if not any(c.isalpha() for c in valeur):
            return False  # `4218`, `75006` : un nombre n'est pas une adresse
        if any(m.lower().strip(".,") in _VOIES for m in mots):
            return True
        return len(mots) >= 2 or "," in valeur

    if etype == "PERSON":
        if not any(c.isalpha() for c in valeur):
            return False  # `14`
        # Un mot unique tout en minuscules est du vocabulaire, pas quelqu'un.
        return len(mots) >= 2 or valeur[:1].isupper()

    if etype == "DATE":
        return any(c.isdigit() for c in valeur)

    return True


def merge_fragments(spans: list[dict], text: str) -> list[dict]:
    """Fusionne les fragments voisins de MÊME type en entités entières."""
    if not spans:
        return []
    # Le modèle ne garantit pas l'ordre : trier fait partie de la fusion, sinon
    # deux fragments consécutifs ne se voient pas.
    restants = sorted(spans, key=lambda s: (s["start"], s["end"]))
    fusionnes: list[dict] = []
    courant = dict(restants[0])
    for suivant in restants[1:]:
        ecart = text[courant["end"]:suivant["start"]]
        if (suivant["type"] == courant["type"]
                and len(ecart) <= _ECART_MAX
                and set(ecart) <= _LIAISONS):
            courant["end"] = max(courant["end"], suivant["end"])
            # Le score le plus BAS gagne : un fragment douteux ne doit pas être
            # blanchi par un voisin certain, sinon le seuil ne porte plus sur
            # ce qu'on garde réellement.
            courant["score"] = min(courant["score"], suivant["score"])
        else:
            fusionnes.append(courant)
            courant = dict(suivant)
    fusionnes.append(courant)
    return [ajuste for s in fusionnes if (ajuste := _ajuster(s, text))]


def _ajuster(span: dict, text: str) -> dict | None:
    """Recale les bornes sur le texte et retire la ponctuation de bordure.

    Le modèle rend ` Ines`, espace compris : garder cette forme mettrait au
    coffre une valeur qui ne correspond à aucun jeton du texte, donc
    irrestaurable au retour.
    """
    debut, fin = span["start"], span["end"]
    while debut < fin and text[debut] in _BORDURES:
        debut += 1
    while fin > debut and text[fin - 1] in _BORDURES:
        fin -= 1
    if debut >= fin:
        return None
    return {**span, "start": debut, "end": fin, "value": text[debut:fin]}
