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

#: Les formes PARTIELLES — un rapport d'incident, un inventaire et un contrat en
#: sont faits : « August 2026 », « Feb 28 », « Q3 2024 ». Aucune ne portait de
#: branche, donc toutes tombaient au repli générique et sortaient en MOT : le
#: modèle recevait un nom d'hôte là où le document annonce une date.
#:
#: Elles ne se décalent PAS en jours. Voir `_decaler_mois` : ce serait perdre
#: l'injectivité, donc D6.
#: `août 2026`, `February 2026`, `fév. 2026`.
_MOIS_ANNEE = re.compile(r"^([^\W\d_]+)(\.?) (\d{4})$", re.UNICODE)
#: `2026-08` — année et mois, ISO. L'ordre lève l'ambiguïté par lui-même.
_ISO_MOIS = re.compile(r"^(\d{4})-(\d{2})$")
#: `Feb 28`, `déc. 3` — mois puis jour, sans année.
_MOIS_JOUR = re.compile(r"^([^\W\d_]+)(\.?) (\d{1,2})$", re.UNICODE)
#: `28 février`, `1er mars` — jour puis mois, sans année.
_JOUR_MOIS = re.compile(r"^(\d{1,2})(er)? ([^\W\d_]+)(\.?)$", re.UNICODE)
#: `Q3 2024`, `T3 2024` — le trimestre est une date, à sa granularité.
_TRIMESTRE = re.compile(r"^([QT])([1-4]) (\d{4})$", re.IGNORECASE)


def _sans_accent(mot: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", mot.lower())
                   if unicodedata.category(c) != "Mn")


def _sans_accents(table: tuple[str, ...]) -> tuple[str, ...]:
    return tuple(_sans_accent(m) for m in table)


_MOIS_FR_NUS = _sans_accents(MOIS_FR)
#: Les abréviations qu'un humain ÉCRIT, et rien d'autre. Accepter n'importe
#: quel préfixe non ambigu produisait des formes que personne n'utilise —
#: `janv.` faisait rendre `nove.`, `févr.` faisait rendre `déce.`, et `Marc`
#: passait pour mars. Le modèle normalise alors vers l'écriture standard, le
#: coffre ne contient que la forme aberrante, et la restauration se perd EN
#: SILENCE. Prouver qu'une forme se relit par le PARSEUR ne prouve pas qu'elle
#: s'écrit.
#: Plusieurs formes sont ACCEPTÉES par mois, la PREMIÈRE est celle qu'on écrit.
_ABREV_FR = (("janv", "jan"), ("févr", "fév"), ("mars",), ("avr",), ("mai",),
             ("juin",), ("juil",), ("août", "aout"), ("sept", "sep"),
             ("oct",), ("nov",), ("déc",))
#: `sept` s'écrit aussi en anglais, et sans lui `sept 15, 2020` — une forme
#: anglophone — retombait sur la table française : le mois hybride revenait.
_ABREV_EN = (("jan",), ("feb",), ("mar",), ("apr",), ("may",), ("jun",),
             ("jul",), ("aug",), ("sep", "sept"), ("oct",), ("nov",), ("dec",))


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
    for table, _ in tables:
        abrevs = _ABREV_FR if table is MOIS_FR else _ABREV_EN
        for i, formes in enumerate(abrevs):
            if nu in (_sans_accent(f) for f in formes):
                return i + 1, table
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
    if len(_sans_accent(nom_source)) < len(_sans_accent(table[mois_source - 1])):
        # La source était ABRÉGÉE : on abrège aussi, mais avec la forme
        # STANDARD du mois d'arrivée — pas une troncature à la même longueur.
        # `janv.` faisait rendre `nove.`, qui ne s'écrit nulle part : le modèle
        # le normalise, et le coffre ne connaît que l'aberration.
        standard = (_ABREV_FR if table is MOIS_FR else _ABREV_EN)[mois - 1][0]
        nom = _sans_accent(standard) if nom != table[mois - 1] else standard
        if standard == table[mois - 1]:
            # `mars`, `mai`, `juin`, `août` et `may` n'ONT pas d'abréviation :
            # leur forme standard est le nom entier. Y coller le point de la
            # source écrivait `mars.`, `mai.`, `août.`, `May.` — que le parseur
            # relit, mais que personne n'écrit. Or c'est exactement ce que le
            # tour 12 avait corrigé pour les autres mois : relire n'est pas
            # écrire, le modèle normalise vers la forme sans point, et le
            # coffre ne connaît que l'aberration.
            point = ""
    if nom_source.isupper():
        nom = nom.upper()
    elif nom_source[:1].isupper():
        nom = nom.capitalize()
    return nom + point


def parse(valeur: str) -> tuple[
        dt.date, Callable[[dt.date], str],
        Callable[[dt.date, int], dt.date]] | None:
    """Rend la date lue, de quoi la RÉÉCRIRE, et à quelle granularité la décaler.

    Le rendu est une fermeture plutôt qu'un nom de format : c'est ce qui garde
    la forme d'origine — séparateur, casse du mois, zéros de tête — sans avoir
    à l'énumérer une seconde fois au moment d'écrire.

    Le décaleur voyage AVEC la forme, et non à côté : une année-mois se décale
    en mois, un trimestre en trimestres, un mois-jour dans l'année. Le déduire
    ailleurs ferait deux sources de vérité pour une seule propriété.
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
        return jour, lambda d: f"{d.isoformat()}{reste}", _decaler

    if (m := _ISO_SLASH.match(valeur)):
        largeurs = (len(m[2]), len(m[3]))
        try:
            jour = dt.date(int(m[1]), int(m[2]), int(m[3]))
        except ValueError:
            return None
        return jour, lambda d: (f"{d.year:04d}/{d.month:0{largeurs[0]}d}"
                                f"/{d.day:0{largeurs[1]}d}"), _decaler

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
                 f"{d.year:04d}")), _decaler
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

        # `1er` est la forme canonique du premier du mois en français, et le
        # modèle l'écrit ainsi en recopiant. La source ne dit ce qu'elle en
        # pense que si ELLE tombait un premier : sinon `15 mars 2020` décalé
        # sur un premier rendait `1 août 2022`, le modèle recopiait
        # `1er août 2022`, et le coffre ne reconnaissait plus rien.
        #
        # Ce qui décide est la LANGUE — donc la table résolue — et non l'ordre
        # des champs. Le motif jour-mois reconnaît aussi les mois anglais
        # (`3 May 2020`, la forme internationale), et s'appuyer sur l'ordre
        # produisait `1er November 2021` : un marqueur français devant un mois
        # anglais, que le modèle retire en recopiant. Même correction que le
        # tour 13 pour `sept`, portée cette fois sur le marqueur ordinal.
        ordinal = "" if table is MOIS_EN else (
            m[2] or ("" if int(m[1]) == 1 else "er"))

        def rendre(d: dt.date, _en=ordre_en, _nom=nom_mois, _pt=point,
                   _t=table, _v=virgule, _src=mois, _ord=ordinal) -> str:
            écrit = _rendre_mois(_nom, _pt, _t, _src, d.month)
            # L'année sur QUATRE chiffres, comme les formes numériques. Les
            # formes littérales étaient les seules à l'écrire nue, et le
            # décalage tourne près de `9999-12-31` : `December 31, 9999`
            # rendait `October 16, 2`, que personne n'écrit et que le parseur
            # de ce module refuse — donc une restauration perdue en silence.
            if _en:
                return f"{écrit} {d.day}{_v} {d.year:04d}"
            # `1er` ne vaut qu'au premier du mois : le recopier sur un autre
            # jour écrirait une forme que le français n'a pas.
            return f"{d.day}{_ord if d.day == 1 else ''} {écrit} {d.year:04d}"

        return jour, rendre, _decaler

    return _partielle(valeur)


def _partielle(valeur: str):
    """Les formes qui ne portent PAS tous les champs d'une date.

    Elles sont cherchées après les formes complètes, qui doivent gagner : `Feb
    28, 2026` est un mois-jour-année, pas un mois-jour suivi d'une année.

    Ce qu'on N'invente PAS : le champ absent. Rendre `12 mars 2031` pour
    `August 2026` serait une date — et une invention, puisque le document ne dit
    pas le jour. Le décalage se fait donc à la granularité de ce qui est écrit.
    """
    if (m := _ISO_MOIS.match(valeur)):
        try:
            jour = dt.date(int(m[1]), int(m[2]), 1)
        except ValueError:
            return None
        return jour, lambda d: f"{d.year:04d}-{d.month:02d}", _decaler_mois

    if (m := _TRIMESTRE.match(valeur)):
        lettre, rang = m[1], int(m[2])
        try:
            jour = dt.date(int(m[3]), (rang - 1) * 3 + 1, 1)
        except ValueError:
            return None
        return (jour,
                lambda d: f"{lettre}{(d.month - 1) // 3 + 1} {d.year:04d}",
                _decaler_trimestre)

    # Mois-année et mois-jour partagent leur syntaxe à un champ près, et rien
    # dans la forme ne dit la langue — contrairement à `March 3, 2020`, dont
    # l'ordre la trahit. Le NOM la dit quand il est écrit en entier ; une
    # abréviation commune aux deux tables (`sept`, `oct`, `nov`, `dec`) reste
    # indécidable, et la table préférée tranche. Résidu énoncé.
    for motif, mois_puis_nombre in ((_MOIS_ANNEE, True), (_MOIS_JOUR, True),
                                    (_JOUR_MOIS, False)):
        if not (m := motif.match(valeur)):
            continue
        nom_mois, point = (m[1], m[2]) if mois_puis_nombre else (m[3], m[4])
        reconnu = _mois_index(nom_mois)
        if reconnu is None:
            return None
        mois, table = reconnu
        nombre = int(m[3] if mois_puis_nombre else m[1])

        if motif is _MOIS_ANNEE:
            try:
                jour = dt.date(nombre, mois, 1)
            except ValueError:
                return None
            return (jour,
                    lambda d, _n=nom_mois, _p=point, _t=table, _s=mois: (
                        f"{_rendre_mois(_n, _p, _t, _s, d.month)} {d.year:04d}"),
                    _decaler_mois)

        # Sans année, l'année de référence est bissextile pour que le 29 février
        # existe des deux côtés du décalage.
        try:
            jour = dt.date(_ANNEE_REF, mois, nombre)
        except ValueError:
            return None
        ordinal = "" if table is MOIS_EN else (
            (m[2] or "") if not mois_puis_nombre else "")

        def rendre(d: dt.date, _n=nom_mois, _p=point, _t=table, _s=mois,
                   _avant=mois_puis_nombre, _o=ordinal) -> str:
            écrit = _rendre_mois(_n, _p, _t, _s, d.month)
            if _avant:
                return f"{écrit} {d.day}"
            return f"{d.day}{_o if d.day == 1 else ''} {écrit}"

        return jour, rendre, _decaler_dans_l_annee

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
    # Les formes PARTIELLES. Même assertion de début de mot que ci-dessus sur
    # celles dont la tête est une classe libre : sans elle le moteur repart de
    # CHAQUE position d'une longue suite de lettres, ce que les tours 8 à 10 ont
    # payé dans le hook et le tour 12 ici même.
    #
    # Les négations qui suivent chaque motif l'empêchent de proposer un PRÉFIXE
    # d'une forme complète — `2026-08` dans `2026-08-13`, `3 février` dans
    # `3 février 2026`. Le départage par longueur les écarterait aussi, mais les
    # écarter avant coûte moins et dit l'intention.
    re.compile(r"\d{4}-\d{2}(?!-?\d)"),
    re.compile(r"(?<![^\W\d_])[^\W\d_]+\.? \d{4}(?!\d)", re.UNICODE),
    re.compile(r"(?<![^\W\d_])[^\W\d_]+\.? \d{1,2}(?![\d,]? ?\d)", re.UNICODE),
    re.compile(r"\d{1,2}(?:er)? [^\W\d_]+\.?(?! \d)", re.UNICODE),
    re.compile(r"(?<!\w)[QqTt][1-4] \d{4}(?!\d)"),
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
    # Comparer chaque candidat à TOUS les retenus était quadratique : 30 000
    # dates dans un texte de 300 Ko coûtaient 12,6 s. Les candidats étant triés
    # par début croissant, un candidat ne peut chevaucher que le DERNIER retenu
    # — leurs fins sont croissantes par construction.
    retenus: list[tuple[int, int]] = []
    for debut, fin in sorted(trouves, key=lambda b: (b[0], -(b[1] - b[0]))):
        if not retenus or debut >= retenus[-1][1]:
            retenus.append((debut, fin))
    return retenus


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


#: Nombre de jours représentables : `date.min` a l'ordinal 1, `date.max` celui-ci.
_ETENDUE = dt.date.max.toordinal()


def _tourner(o: int, bas: int, haut: int, pas: int) -> int:
    """Fait tourner `o` dans `[bas, haut]`, sans jamais rendre `o`.

    Borner la rotation à un INTERVALLE est ce qui rend « la date reste de son
    côté du présent » vrai jusqu'aux bords : chaque côté est son propre espace,
    donc deux dates du même côté restent distinctes (même pas), et deux côtés
    différents ne peuvent pas se rejoindre (espaces disjoints). D6 tient par
    construction, au lieu de tenir « sauf près des bornes ».

    Le pas arrive SIGNÉ et déjà borné : reculer dans le passé, avancer dans le
    futur, de la même quantité que le décalage libre. Le calculer ici à partir
    de l'étendue du côté donnerait un pas énorme — mesuré : février 2026
    ressortait en l'an 2, ce qui est bien une date passée et n'est plus
    plausible (D1), et l'écart aux autres dates du document était perdu.

    Un intervalle d'un seul rang ne peut pas décaler sans rendre le réel : on
    le dit à l'appelant plutôt que de rendre l'identité en silence.
    """
    etendue = haut - bas + 1
    if etendue < 2:
        raise CoteImpossible(f"un seul rang disponible entre {bas} et {haut}")
    return bas + (o - bas + pas) % etendue


def _signe(pas: int, vers_le_passe: bool, etendue: int) -> int:
    """Le pas, orienté du bon côté et ramené dans l'étendue disponible.

    Reculer garde une date passée dans le passé, avancer garde une date future
    dans le futur — et la MAGNITUDE reste celle du décalage libre, donc les
    écarts entre dates d'un même côté sont conservés exactement.
    """
    borne = max(1, pas % max(1, etendue - 1) or 1)
    return -borne if vers_le_passe else borne


class CoteImpossible(ValueError):
    """Le côté du présent est trop étroit pour y décaler quoi que ce soit."""


def _cote(o: int, o_aujourdhui: int, bas: int, haut: int) -> tuple[int, int]:
    """L'intervalle du côté d'aujourd'hui où vit cette date.

    Aujourd'hui compte pour le PASSÉ : une date du jour n'est pas « à venir »,
    et la ranger dans le futur ferait dire au modèle l'inverse de ce que le
    document dit.
    """
    return (bas, o_aujourdhui) if o <= o_aujourdhui else (o_aujourdhui + 1, haut)


def _decaler(jour: dt.date, jours: int, aujourd_hui: dt.date | None = None) -> dt.date:
    """Le jour décalé, en TOURNANT dans la plage des dates représentables.

    Une addition nue lève `OverflowError` à moins de `jours` de `9999-12-31` —
    la date « sans fin » que portent les contrats, les abonnements et les
    droits, donc tout sauf un cas de laboratoire. La date réelle repartait
    alors VERBATIM dans le substitut.

    Tourner plutôt que déborder garde les deux propriétés qui comptent : le
    résultat est une DATE (la nature du substitut, cf. l'invariant), et la
    transformation reste une BIJECTION, donc deux dates distinctes ne peuvent
    pas tomber sur la même (D6). Prix assumé : pour la poignée de dates qui
    tournent, l'écart aux autres n'est plus préservé.
    """
    if aujourd_hui is None:
        return dt.date.fromordinal((jour.toordinal() - 1 + jours) % _ETENDUE + 1)
    o, auj = jour.toordinal(), aujourd_hui.toordinal()
    bas, haut = _cote(o, auj, 1, _ETENDUE)
    return dt.date.fromordinal(_tourner(o, bas, haut, _signe(jours, o <= auj,
                                                             haut - bas + 1)))


#: Étendues des granularités PARTIELLES, pour tourner comme `_decaler` tourne.
_MOIS_ETENDUE = 9999 * 12
_TRIMESTRE_ETENDUE = 9999 * 4
#: L'année de référence d'une date sans année est BISSEXTILE : sans cela le 29
#: février n'aurait pas de substitut de sa propre forme.
_ANNEE_REF = 2024
_JOURS_ANNEE = 366


#: Durées moyennes grégoriennes, pour convertir le décalage d'une granularité à
#: l'autre plutôt que d'en tirer un par forme.
_JOURS_PAR_MOIS = 30.436875
_JOURS_PAR_TRIMESTRE = 91.310625


def _pas(jours: int, par: float, etendue: int) -> int:
    """Le décalage CONVERTI à cette granularité, jamais nul.

    Converti, et non tiré à part : un même document mêle les granularités —
    « l'incident du 3 février 2026 » et « le rapport de février 2026 ». Deux pas
    indépendants placeraient ces deux dates à des dizaines d'années l'une de
    l'autre là où la source les donne dans le même mois, et la chronologie est
    précisément ce que ce module existe pour préserver.

    Jamais nul non plus : un décalage nul rendrait le réel comme substitut, et
    ce substitut serait rendu, donc jugé bon — le mode d'échec le plus
    silencieux qu'on puisse écrire.
    """
    return max(1, round(jours / par) % etendue)


def _decaler_mois(jour: dt.date, jours: int,
                  aujourd_hui: dt.date | None = None) -> dt.date:
    """Décale de MOIS entiers, parce qu'une année-mois n'a pas de jour.

    Décaler en JOURS ne serait pas injectif : février et mars d'une même année
    sont distants de vingt-huit jours, qui tiennent dans un mois de trente et un.
    Décalés du même nombre de jours, les deux peuvent donc tomber dans le MÊME
    mois — deux dates réelles sous un seul substitut, ce que D6 interdit.
    """
    rang = (jour.year - 1) * 12 + jour.month - 1
    if aujourd_hui is None:
        o = (rang + _pas(jours, _JOURS_PAR_MOIS, _MOIS_ETENDUE)) % _MOIS_ETENDUE
    else:
        auj = (aujourd_hui.year - 1) * 12 + aujourd_hui.month - 1
        bas, haut = _cote(rang, auj, 0, _MOIS_ETENDUE - 1)
        o = _tourner(rang, bas, haut,
                     _signe(_pas(jours, _JOURS_PAR_MOIS, _MOIS_ETENDUE),
                            rang <= auj, haut - bas + 1))
    return dt.date(o // 12 + 1, o % 12 + 1, 1)


def _decaler_trimestre(jour: dt.date, jours: int,
                       aujourd_hui: dt.date | None = None) -> dt.date:
    """Décale de TRIMESTRES entiers — même raison qu'au-dessus, un cran plus haut."""
    rang = (jour.year - 1) * 4 + (jour.month - 1) // 3
    pas = _pas(jours, _JOURS_PAR_TRIMESTRE, _TRIMESTRE_ETENDUE)
    if aujourd_hui is None:
        o = (rang + pas) % _TRIMESTRE_ETENDUE
    else:
        auj = (aujourd_hui.year - 1) * 4 + (aujourd_hui.month - 1) // 3
        bas, haut = _cote(rang, auj, 0, _TRIMESTRE_ETENDUE - 1)
        o = _tourner(rang, bas, haut, _signe(pas, rang <= auj, haut - bas + 1))
    return dt.date(o // 4 + 1, (o % 4) * 3 + 1, 1)


def _decaler_dans_l_annee(jour: dt.date, jours: int,
                          aujourd_hui: dt.date | None = None) -> dt.date:
    """Décale un mois-jour DANS l'année, qui est tout ce que la valeur porte.

    Tourner dans l'année garde la forme (pas d'année à inventer) et reste une
    bijection sur les trois cent soixante-six couples possibles.

    Le côté du présent n'a pas de sens ici : `Feb 28` ne porte pas d'année,
    donc rien ne dit s'il est passé ou futur. Le réglage ne s'y applique pas,
    et c'est énoncé plutôt que deviné.
    """
    del aujourd_hui
    rang = dt.date(_ANNEE_REF, jour.month, jour.day).timetuple().tm_yday - 1
    o = (rang + _pas(jours, 1, _JOURS_ANNEE)) % _JOURS_ANNEE
    return dt.date(_ANNEE_REF, 1, 1) + dt.timedelta(days=o)


def shift(valeur: str, jours: int,
          aujourd_hui: dt.date | None = None) -> str | None:
    """Décale la date CONTENUE dans la valeur, en gardant tout le reste.

    None seulement s'il n'y a aucune date lisible — auquel cas l'appelant
    substitue génériquement, et la nature ne peut pas être tenue.

    `aujourd_hui` renseigné, chaque date tourne dans SON côté du présent : une
    date passée reste passée, une future reste future. Le réglage qui l'active
    est `dates=cote_du_present`, et son prix est écrit là-bas.
    """
    lu = parse(valeur)
    if lu is not None:
        jour, rendre, decaler = lu
        return rendre(decaler(jour, jours, aujourd_hui))

    # TOUTES les dates, pas la première. N'en décaler qu'une laissait les
    # suivantes VERBATIM dans le substitut : `du 3 février 2026 au 12 mars
    # 2026` sortait avec sa seconde date intacte, donc une vraie date partait.
    bornes = chercher_toutes(valeur)
    if not bornes:
        return None
    morceaux: list[str] = []
    curseur = 0
    for debut, fin in bornes:
        if (debut, fin) == (0, len(valeur)):
            # `parse` a déjà refusé cette valeur entière : se rappeler dessus
            # ne peut que recommencer. Une date qui a la FORME d'une date sans
            # en être une (`2020-02-30`, courant dans un export) faisait ainsi
            # exploser la pile, et `RecursionError` n'est rattrapée nulle part.
            return None
        decalee = shift(valeur[debut:fin], jours, aujourd_hui)
        if decalee is None:
            # Recopier le fragment non décalable faisait sortir une VRAIE date
            # en clair dès qu'une AUTRE date de la valeur, elle, se décalait :
            # le substitut était rendu, donc jugé bon, et il contenait le réel.
            # Rendre None masque la valeur entière — la seule direction sûre.
            return None
        morceaux.append(valeur[curseur:debut])
        morceaux.append(decalee)
        curseur = fin
    morceaux.append(valeur[curseur:])
    return "".join(morceaux)
