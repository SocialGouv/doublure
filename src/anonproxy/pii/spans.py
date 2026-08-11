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


#: Un identifiant composite se délimite par ses séparateurs. `acmecorp` est un
#: segment de `acmecorp-billing` ; il n'en est pas un d'`acmecorporation`, et
#: confondre les deux ferait substituer du vocabulaire qui ressemble.
_JETON = re.compile(r"[\w.:/@+-]+", re.UNICODE)


def spans_inventaire(text: str, inventory, deja: list[dict]) -> list[dict]:
    """Spans que l'INVENTAIRE produit là où aucun détecteur n'a rien vu.

    Mesuré : `kubectl get pods -n acmecorp-billing` ne rend qu'un span, `TOOL:
    kubectl`. Le namespace porte le nom de l'organisation, `acmecorp` est
    déclaré dans l'inventaire, et il partait en clair — parce que l'inventaire
    ne savait que RETRANCHER de ce que le détecteur avait déjà trouvé.

    L'instruction la moins ambiguë que l'opérateur puisse donner — « ce nom est
    à nous » — dépendait donc qu'un modèle remarque le mot. L'inventaire ne
    peut que remonter la protection : c'est précisément pour ça qu'il est le
    bon endroit où poser une certitude.
    """
    if not inventory:
        return []
    couverts = [(s["start"], s["end"]) for s in deja]
    produits = []
    for jeton in _JETON.finditer(text):
        if not inventory.est_a_nous(jeton.group(0)):
            continue
        if any(a < jeton.end() and jeton.start() < b for a, b in couverts):
            continue  # déjà vu par un détecteur : deux spans se disputeraient
        produits.append({
            "type": "INVENTORY", "value": jeton.group(0),
            "start": jeton.start(), "end": jeton.end(), "score": 1.0,
        })
    return produits


def resserrer(spans: list[dict], text: str) -> list[dict]:
    """Réduit un span de DATE à la date qu'il contient.

    Ce qui entre au coffre doit être ce que le modèle citera. Sur le texte tel
    que l'outil `Read` l'envoie, le détecteur rend le champ avec son heure —
    `3 février 2026 à 14h32` — et cette chaîne entière devenait la clé. Le
    modèle citait la date seule, plus rien ne la reconnaissait, et l'opérateur
    lisait une date fictive **sans aucun moyen de le savoir** : un substitut non
    résolu est compté, un substitut que personne ne reconnaît comme tel ne
    l'est pas.

    La deuxième date du même fichier, sans heure après elle, revenait
    parfaitement. Un document, un type, deux sorts — pour quatre caractères
    d'entourage.

    Seul le type DATE est resserré : une adresse réduite à sa date n'est plus
    une adresse.
    """
    from ..surrogates.dates import chercher

    sortie = []
    for span in spans:
        if span.get("type") != "DATE":
            sortie.append(span)
            continue
        trouve = chercher(span.get("value", ""))
        if trouve is None:
            sortie.append(span)
            continue
        debut, fin = trouve
        sortie.append({**span,
                       "start": span["start"] + debut,
                       "end": span["start"] + fin,
                       "value": span["value"][debut:fin]})
    return sortie


#: L'ÉCHAFAUDAGE d'une sortie d'outil : un retour à la ligne, des espaces, un
#: numéro, une tabulation. C'est ainsi que `Read` numérote ce qu'il rend, et
#: une entité qui court sur deux lignes l'avale.
#:
#: La tabulation qui suit immédiatement des chiffres en tête de ligne est ce
#: qui rend le motif sûr : aucune adresse, aucun nom n'en contient.
_ECHAFAUDAGE = re.compile(r"\n[ \t]*\d+\t")
#: Le même échafaudage EN TÊTE de span : sur la première ligne d'une sortie
#: d'outil, le modèle commence au numéro et non au saut de ligne qui le
#: précède, donc le motif ci-dessus ne matche pas et le numéro se fait
#: réécrire.
_TETE_ECHAFAUDAGE = re.compile(r"^[ \t]*\d+\t")


def couper_echafaudage(spans: list[dict], text: str) -> list[dict]:
    """Coupe les spans à l'échafaudage plutôt que de le réécrire.

    Mesuré en session réelle : une adresse client à cheval sur deux lignes
    emportait le numéro de ligne, le générateur le remplaçait par un autre
    nombre, et le modèle lisait un document dont la numérotation ne
    correspondait plus — il l'a dit et a refusé de répondre à une partie de la
    question. Rien n'avait fuité ; le coût est le même que celui d'une erreur.

    Les deux morceaux restent des entités, donc restent substitués. Ce qui
    n'est jamais touché, c'est ce qui n'appartient pas au document.
    """
    sortie: list[dict] = []
    for span in spans:
        debut = span["start"]
        morceaux: list[tuple[int, int]] = []
        for coupure in _ECHAFAUDAGE.finditer(text, span["start"], span["end"]):
            morceaux.append((debut, coupure.start()))
            debut = coupure.end()
        if not morceaux:
            sortie.append(span)
            continue
        morceaux.append((debut, span["end"]))
        for a, b in morceaux:
            if (ajuste := _ajuster({**span, "start": a, "end": b}, text)):
                sortie.append(ajuste)
    return [_sans_tete(s, text) for s in sortie]


def _sans_tete(span: dict, text: str) -> dict:
    tete = _TETE_ECHAFAUDAGE.match(span.get("value", ""))
    if tete is None:
        return span
    return _ajuster({**span, "start": span["start"] + tete.end()}, text) or span


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
