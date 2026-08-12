"""A date is not substituted, it is SHIFTED — and that is the whole design.

An incident reads as a sequence. Drawing each date independently would turn
`14h32 → 14h58 → 15h20` and `opened 12 March, closed 3 April` into noise, and
the operator would be handed a chronology that contradicts itself — which is
exactly the failure the surrogate invariant was written for after three
defects of the same family.

One shift, constant per scope, keeps every interval intact while no date stays
itself. It is also injective by construction: a translation never maps two
distinct dates onto one.

The price is stated rather than discovered: **the interval between two dates is
preserved**, and joins the four attributes already accepted as leaks.
"""
from __future__ import annotations

import datetime as dt
import re

import pytest

from anonproxy.allowlist import DEFAULT_ALLOWLIST
from anonproxy.proxy.app import predicat_public
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "e2" * 32


def moteur(tmp_path, scope="project:dates"):
    return SurrogateEngine(
        vault=Vault(tmp_path / f"{scope.replace(':', '-')}.db", master_key=MASTER),
        master_key=MASTER, scope_key=scope,
        is_public=predicat_public(DEFAULT_ALLOWLIST))


@pytest.fixture
def m(tmp_path):
    return moteur(tmp_path)


def sub(m, valeur):
    return m.substitute_value("DATE", valeur)


# --------------------------------------------------------------------------- #
# La forme : un substitut doit être indiscernable EN NATURE
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("reel, motif", [
    ("2026-02-03", r"^\d{4}-\d{2}-\d{2}$"),
    ("03/02/2026", r"^\d{2}/\d{2}/\d{4}$"),
    ("03-02-2026", r"^\d{2}-\d{2}-\d{4}$"),
    ("12 mars 2019", r"^\d{1,2} [a-zéû]+ \d{4}$"),
    ("12 March 2019", r"^\d{1,2} [A-Za-z]+ \d{4}$"),
])
def test_the_format_survives(m, reel, motif):
    """Rendre une ISO là où il y avait « 12 mars 2019 » se remarque, et change
    la structure du texte que le modèle lit."""
    sortie = sub(m, reel)
    assert re.match(motif, sortie), f"{reel!r} -> {sortie!r}"
    assert sortie != reel


def test_a_timestamp_keeps_its_time(m):
    """Décaler l'heure casserait l'ordre des événements d'un incident, qui est
    précisément ce que l'agent doit pouvoir lire."""
    sortie = sub(m, "2026-02-03T14:32:00Z")
    assert sortie.endswith("T14:32:00Z"), sortie
    assert not sortie.startswith("2026-02-03")


# --------------------------------------------------------------------------- #
# La propriété : les intervalles tiennent
# --------------------------------------------------------------------------- #


def test_the_interval_between_two_dates_is_preserved(m):
    a, b = sub(m, "2026-02-03"), sub(m, "2026-02-24")
    ecart = dt.date.fromisoformat(b) - dt.date.fromisoformat(a)
    assert ecart.days == 21, f"{a} → {b}"


def test_the_order_of_events_is_preserved(m):
    dates = ["2026-01-05", "2026-02-03", "2026-11-30"]
    rendus = [dt.date.fromisoformat(sub(m, d)) for d in dates]
    assert rendus == sorted(rendus)


def test_the_shift_crosses_formats(m):
    """Le même jour écrit de deux façons doit tomber sur le même jour décalé,
    sinon un document se contredit selon la ligne qu'on lit."""
    iso = dt.date.fromisoformat(sub(m, "2026-02-03"))
    fr = sub(m, "03/02/2026")
    jour, mois, annee = (int(x) for x in fr.split("/"))
    assert dt.date(annee, mois, jour) == iso


# --------------------------------------------------------------------------- #
# Ce qui doit tenir de toute façon
# --------------------------------------------------------------------------- #


def test_the_result_is_a_real_date(m):
    """Un décalage appliqué à un objet date ne peut pas produire un 31 février
    — mais le rendu, lui, pourrait. On le vérifie sur une année bissextile."""
    assert dt.date.fromisoformat(sub(m, "2024-02-29"))


def test_it_is_deterministic_within_a_scope(m):
    assert sub(m, "2026-02-03") == sub(m, "2026-02-03")


def test_another_scope_shifts_differently(tmp_path):
    un = sub(moteur(tmp_path, "project:un"), "2026-02-03")
    deux = sub(moteur(tmp_path, "project:deux"), "2026-02-03")
    assert un != deux, "le décalage ne dépend pas de la portée"


def test_two_dates_never_share_a_surrogate(m):
    jours = [f"2026-03-{j:02d}" for j in range(1, 29)]
    rendus = [sub(m, j) for j in jours]
    assert len(set(rendus)) == len(jours)


def test_a_span_holding_no_date_falls_back_and_that_is_a_RESIDUAL(m):
    """Sans date lisible, la valeur reste protégée — mais elle sort en MOT, et
    la nature n'est plus tenue.

    Cette assertion, écrite « c'est toujours protégé », a couvert un vrai
    défaut : `3 février 2026 à 14h32` ne se parsait pas non plus, sortait en
    nom d'hôte, et le modèle a cessé de pouvoir répondre « quand ». Vérifier la
    protection ne vérifie pas l'invariant — il fallait les deux, et le second
    était déjà écrit deux modules plus loin.

    Les formes entourées sont désormais couvertes (`test_dates_entourees.py`).
    Ce qui reste ici est le résidu nommé : un span sans aucune date dedans.
    """
    assert sub(m, "le jour de la Saint-Glinglin") != "le jour de la Saint-Glinglin"


# --------------------------------------------------------------------------- #
# Tour 11 — les formes qui retombaient en MOT
# --------------------------------------------------------------------------- #
from anonproxy.surrogates import dates as _dates  # noqa: E402


@pytest.mark.parametrize("ecrit,attendu", [
    ("3 fev 2020", dt.date(2020, 2, 3)),        # sans accent, abrégé
    ("3 fév. 2020", dt.date(2020, 2, 3)),       # abrégé avec point
    ("15 Sept 2020", dt.date(2020, 9, 15)),
    ("2020/03/15", dt.date(2020, 3, 15)),       # année d'abord
    ("March 3, 2020", dt.date(2020, 3, 3)),     # mois d'abord, anglophone
    ("Mar. 3 2020", dt.date(2020, 3, 3)),
    ("03/15/2020", dt.date(2020, 3, 15)),       # jour d'abord IMPOSSIBLE ici
])
def test_une_forme_de_date_reconnue_de_plus(ecrit, attendu):
    """Ces formes retombaient sur la substitution GÉNÉRIQUE, donc sortaient en
    MOT : le modèle recevait un nom d'hôte là où le document annonçait une
    date, et cessait de pouvoir répondre « quand ». Rien ne fuyait — c'est la
    nature du substitut qui était perdue (D1)."""
    lu = _dates.parse(ecrit)
    assert lu is not None, f"{ecrit!r} retombe encore en mot"
    assert lu[0] == attendu


@pytest.mark.parametrize("ecrit,decalage,attendu", [
    # Un nom COMPLET reste complet : la longueur se compare au mois de DÉPART,
    # pas à celui d'arrivée — sinon `March` devient `Janua`.
    ("15 March 2020", 321, "30 January 2021"),
    ("15 mars 2020", 321, "30 janvier 2021"),
    ("12 MARS 2020", 321, "27 JANVIER 2021"),
    # Une ABRÉVIATION reste une abréviation, de la même longueur.
    # Source ASCII (`fev` pour `février`) : le rendu reste ASCII, sinon le
    # modèle « corrige » l'accent et le coffre ne reconnaît plus rien.
    ("3 fev 2020", 321, "20 dec 2020"),
    ("3 fév. 2020", 321, "20 déc. 2020"),
    ("Mar. 3 2020", 321, "Jan. 18 2021"),
    ("March 3, 2020", 321, "January 18, 2021"),
    # Les formes numériques gardent leur séparateur et leur ordre.
    ("2020/03/15", 321, "2021/01/30"),
    ("03/15/2020", 321, "01/30/2021"),
    ("15/03/2020", 321, "30/01/2021"),
    # `1er` ne vaut qu'au premier du mois.
    ("1er janvier 2020", 31, "1er février 2020"),
    ("1er janvier 2020", 321, "17 novembre 2020"),
])
def test_la_forme_d_ecriture_survit_au_decalage(ecrit, decalage, attendu):
    """D1 : l'opérateur et le modèle doivent lire une date écrite comme celle
    qu'ils ont remplacée."""
    jour, rendre = _dates.parse(ecrit)
    assert rendre(jour + dt.timedelta(days=decalage)) == attendu


@pytest.mark.parametrize("ecrit", [
    "3 jui 2020",      # juin ou juillet : deviner fabriquerait une date fausse
    "15/03/20",        # année sur deux chiffres : le siècle est un pari
    "32/01/2020",      # pas une date
    "3 ma 2020",       # deux lettres : mars, mai
])
def test_ce_qui_reste_ambigu_n_est_pas_deviné(ecrit):
    """L'unicité d'une abréviation est VÉRIFIÉE, jamais supposée. Ce qui n'est
    pas reconnu retombe en mot — visible, et c'est le résidu documenté."""
    assert _dates.parse(ecrit) is None


def test_chercher_ne_backtracke_pas_sur_un_long_texte_sans_date():
    """HAUT, déni de service. Le motif qui commence par un NOM DE MOIS avait
    une classe libre en tête : sur une longue suite de lettres sans date, le
    moteur consommait toute la suite depuis CHAQUE position.

    Mesuré avant correctif : 565 ms sur 10 Ko, **56,7 s sur 100 Ko** — de quoi
    figer l'agent sans qu'aucune date soit en jeu. Ce projet a payé trois tours
    entiers sur cette famille dans le hook, et la règle qui en était sortie —
    « tout motif ancré sur son littéral » — a été rouverte en ajoutant une
    forme deux heures plus tôt."""
    import time

    for texte in ("abcdefgh" * 12_500, "éàüñ" * 12_500):
        debut = time.monotonic()
        _dates.chercher(texte)
        ecoule = time.monotonic() - debut
        assert ecoule < 1.0, f"{len(texte)} caractères en {ecoule:.1f} s"


@pytest.mark.parametrize("texte,attendu", [
    ("March 3, 2020", (0, 13)),          # en tête de texte
    ("le March 3, 2020 à 14h", (3, 16)),  # après un mot
    ("du 3 fév. 2020 au", (3, 14)),
    # L'assertion corrige aussi un faux positif : `xMarch` est UN mot, pas le
    # mois de mars précédé d'un x.
    ("xMarch 3, 2020", None),
])
def test_l_ancrage_ne_perd_aucune_date(texte, attendu):
    assert _dates.chercher(texte) == attendu


@pytest.mark.parametrize("valeur,attendu", [
    # La forme ordinaire d'une PLAGE, dans les cinq écritures reconnues.
    ("2020-03-15 to 2020-04-16", "2020-11-20 to 2020-12-22"),
    ("du 3 février 2026 au 12 mars 2026", "du 11 octobre 2026 au 17 novembre 2026"),
    ("March 3, 2020 through April 5, 2020",
     "November 8, 2020 through December 11, 2020"),
    ("2020-03-15 et 2020-04-16 et 2020-05-17",
     "2020-11-20 et 2020-12-22 et 2021-01-22"),
    # La même date deux fois doit recevoir le même décalage.
    ("3 janvier 2020 puis 3 janvier 2020", "9 septembre 2020 puis 9 septembre 2020"),
])
def test_toutes_les_dates_d_une_valeur_sont_decalees(valeur, attendu):
    """CRITIQUE. Le décalage ne traitait que la PREMIÈRE date : les suivantes
    étaient recopiées VERBATIM dans le substitut, donc une vraie date sortait.

    Et `resserrer` aggravait le cas : il réduisait le span à la première, ce
    qui faisait tomber les suivantes HORS du périmètre substitué — en clair,
    sans entrée au coffre ni rien à compter. Une plage de dates est la forme la
    plus ordinaire qui soit dans un ticket ou un log."""
    assert _dates.shift(valeur, 250) == attendu


def test_un_span_a_plusieurs_dates_n_est_pas_resserre():
    """Le pendant du précédent : un span qui porte plusieurs dates reste
    ENTIER, sinon les suivantes sortent du périmètre substitué. C'est le
    décalage qui les traite toutes."""
    from anonproxy.pii.spans import resserrer

    texte = "du 3 février 2026 au 12 mars 2026"
    span = [{"type": "DATE", "value": texte, "start": 0, "end": len(texte),
             "score": 0.9}]
    rendu = resserrer(span, texte)[0]
    assert (rendu["start"], rendu["end"]) == (0, len(texte))
    # …alors qu'une seule date est bien resserrée sur elle-même.
    entoure = "le 3 février 2026 à 14h32"
    span1 = [{"type": "DATE", "value": entoure, "start": 0, "end": len(entoure),
              "score": 0.9}]
    r1 = resserrer(span1, entoure)[0]
    assert entoure[r1["start"]:r1["end"]] == "3 février 2026"


@pytest.mark.parametrize("valeur", [
    "2020-03-15T14:32:00Z",
    "2020-03-15 14:32",
    "2020-03-15T14:32:00.123+02:00",
])
def test_l_heure_est_toujours_preservee(valeur):
    """L'AUTRE MOITIÉ : borner la queue de la forme ISO ne doit pas perdre
    l'heure. Décaler l'heure casserait l'ordre des événements dans une
    journée, qui est ce que l'agent lit."""
    decalee = _dates.shift(valeur, 250)
    assert decalee is not None and decalee.endswith(valeur[10:])


@pytest.mark.parametrize("ecrit", [
    "sept 15, 2020", "oct 3, 2020", "dec 25, 2020", "nov 5, 2020",
    "jan 7, 2020", "mar 2, 2020",
])
def test_une_forme_anglaise_recoit_un_mois_anglais(ecrit):
    """HAUT, perte de restauration SILENCIEUSE. `sept` préfixe `septembre` ET
    `september` : l'ordre des tables décidait seul, et un document anglais
    recevait un mois FRANÇAIS (`sept 15, 2020` → `août 2, 2021`).

    Le modèle normalise alors ce qu'il lit — `August 2, 2021` — et le coffre,
    qui ne contient que la forme française, ne reconnaît plus rien. La valeur
    n'a pas fuité ; l'opérateur lit simplement une date fictive sans le savoir,
    et rien ne le compte. La syntaxe est le seul indice de langue disponible :
    mois d'abord = anglophone."""
    jour, rendre = _dates.parse(ecrit)
    rendu = rendre(jour + dt.timedelta(days=321))
    mois = rendu.split()[0].rstrip(".,").lower()
    assert any(m.startswith(mois) for m in _dates.MOIS_EN), rendu


@pytest.mark.parametrize("ecrit,decalage", [
    ("nov 5, 2020", 321),       # `juillet` tronqué donnerait `jui`, ambigu
    ("dec 25, 2020", 321),      # `août` tronqué donnerait `aoû`, accentué
    ("3 fev 2020", 321),
    ("15 Sept 2020", 321),
])
def test_ce_qui_est_ecrit_peut_toujours_se_relire(ecrit, decalage):
    """L'invariant qui manquait : **ce qu'on écrit doit pouvoir se relire.**

    La troncature produisait `jui` — le préfixe que `_mois_index` refuse parce
    qu'il vaut juin ET juillet — et `aoû`, accentué là où la source était de
    l'ASCII pur. Dans les deux cas le modèle « corrige », et la restauration se
    perd sans que rien ne le signale. Le rendu se relit désormais lui-même
    avant d'accepter une abréviation, et retombe sur le nom complet sinon."""
    jour, rendre = _dates.parse(ecrit)
    rendu = rendre(jour + dt.timedelta(days=decalage))
    relu = _dates.parse(rendu)
    assert relu is not None, f"{ecrit!r} rendu {rendu!r}, illisible"
    # …et se relit sur la MÊME date.
    assert relu[0] == jour + dt.timedelta(days=decalage)


def test_une_source_ascii_reste_ascii():
    """`dec` est de l'ASCII ; rendre `aoû` y met un accent que le document
    n'avait pas, et que le modèle réécrira."""
    jour, rendre = _dates.parse("dec 25, 2020")
    rendu = rendre(jour + dt.timedelta(days=250))
    assert rendu == rendu.encode("ascii", "ignore").decode(), rendu


def test_chercher_ne_devient_pas_quadratique_sur_un_texte_DENSE_en_dates():
    """HAUT, déni de service — et le test qui existait passait à côté.

    `test_chercher_ne_backtracke_pas_sur_un_long_texte_sans_date` mesure du
    texte SANS date : c'est là que le défaut PRÉCÉDENT vivait. Celui-ci naît à
    l'inverse, quand tout matche : la déduplication comparait chaque candidat à
    TOUS les retenus. Mesuré : 30 000 dates = 12,6 s, 100 000 ne finissaient
    pas. J'ai testé là où le défaut d'avant était, pas là où le nouveau
    pouvait naître."""
    import time

    texte = " ".join(["2020-03-15"] * 30_000)
    debut = time.monotonic()
    trouves = _dates.chercher_toutes(texte)
    ecoule = time.monotonic() - debut
    assert len(trouves) == 30_000
    assert ecoule < 1.0, f"30 000 dates en {ecoule:.1f} s"


@pytest.mark.parametrize("ecrit,attendu_mois", [
    ("1er janv. 2020", "nov."),      # `nove.` ne s'écrit nulle part
    ("3 févr. 2026", "déc."),        # ni `déce.`
    ("Feb 3, 2026", "Dec"),
])
def test_une_abreviation_rendue_est_une_abreviation_QUI_S_ECRIT(ecrit, attendu_mois):
    """HAUT, restauration perdue en SILENCE. La garde précédente prouvait que
    le PARSEUR sait relire ce qu'il écrit — pas qu'un humain l'écrirait.
    `janv.` faisait rendre `nove.`, `févr.` faisait rendre `déce.` : le modèle
    normalise vers l'écriture standard, le coffre ne contient que l'aberration,
    et l'opérateur lit une date fictive sans le savoir."""
    jour, rendre = _dates.parse(ecrit)
    rendu = rendre(jour + dt.timedelta(days=321))
    assert attendu_mois in rendu, rendu
    assert _dates.parse(rendu) is not None


def test_un_prefixe_qui_n_est_pas_une_abreviation_n_est_pas_une_date():
    """`Marc` préfixe `march` sans être une abréviation de mois. Accepter tout
    préfixe non ambigu faisait d'un prénom une date décalée."""
    assert _dates.parse("Marc 3, 2020") is None


@pytest.mark.parametrize("valeur,reel", [
    ("contrat 1985-06-15 au 9999-12-31", "9999-12-31"),
    ("Contrat du 01/06/1985 au 31/12/9999", "31/12/9999"),
    ("From January 1, 2024 to December 31, 9999", "December 31, 9999"),
])
def test_une_date_indecalable_ne_repart_pas_VERBATIM(valeur, reel):
    """CRITIQUE — une VRAIE date sortait en clair dans le substitut.

    `9999-12-31` est la date « sans fin » des contrats, des abonnements et des
    droits. À moins de `jours` de `date.max`, l'addition débordait, le fragment
    était recopié TEL QUEL, et comme l'autre date de l'intervalle, elle, se
    décalait, le substitut était rendu — donc jugé bon — en portant le réel.

    Même classe que le tour 11, où `resserrer` laissait la seconde date HORS du
    segment substitué : la couverture d'alors n'utilisait que des dates
    confortablement décalables, donc elle prouvait le cas facile.
    """
    rendu = _dates.shift(valeur, 654)
    assert rendu is not None
    assert reel not in rendu, rendu


def test_un_debordement_rend_toujours_une_DATE():
    """Tourner dans la plage plutôt que déborder : le substitut reste une date
    (la nature), et la transformation reste une bijection (D6)."""
    rendu = _dates.shift("9999-12-31", 654)
    assert rendu is not None and _dates.parse(rendu) is not None
    assert rendu != "9999-12-31"
    # Bijection : deux dates distinctes ne peuvent pas tomber sur la même.
    tournees = {_dates.shift(f"9999-12-{j:02d}", 654) for j in range(20, 32)}
    assert len(tournees) == 12


@pytest.mark.parametrize("texte", [
    "du 3 février 2026 au 12 mars 2026",
    "contrat 1985-06-15 au 9999-12-31",
    "2020-02-30 puis 2026-02-03",          # une FORME de date qui n'en est pas
    "From January 1, 2024 to December 31, 9999",
])
def test_toute_borne_trouvee_est_relisible(texte):
    """L'invariant qui rend le recopiage VERBATIM impossible dans `shift`.

    `shift` refuse désormais la valeur entière plutôt que de recopier un
    fragment qu'il ne sait pas décaler — mais ce refus ne doit jamais se
    produire, parce que `chercher_toutes` ne rend que des bornes que `parse`
    accepte. Si les deux divergent un jour, c'est ce test qui le dit, et le
    refus qui évite la fuite en attendant.
    """
    for debut, fin in _dates.chercher_toutes(texte):
        fragment = texte[debut:fin]
        assert _dates.parse(fragment) is not None, fragment
        assert _dates.shift(fragment, 654) is not None, fragment
