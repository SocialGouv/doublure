"""Round 6, detection surface — four defects, all written the same day.

None was found by the suite that shipped with them. Each is a boundary I did
not think to cross, and three of the four break the session rather than leak:

- a date that PARSES as syntax and does not exist as a day (`2020-02-30`, a
  common software bug in exported logs) recursed until the stack gave up;
- two spellings of one date collided in the vault and took the request down;
- the score threshold was applied to FRAGMENTS, so a low-confidence piece was
  dropped before it could be reassembled — and its real text stayed in the
  output, glued to the surrogate of the piece that survived. That one IS a
  leak, and it wears the shape of a substitution;
- the line-number cut only handled a span CROSSING the scaffolding, never one
  STARTING at it — the first line of a `Read` output.
"""
from __future__ import annotations

import re

import pytest

from anonproxy.allowlist import DEFAULT_ALLOWLIST
from anonproxy.pii.spans import couper_echafaudage, merge_fragments
from anonproxy.proxy.app import predicat_public
from anonproxy.surrogates import dates
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "c1" * 32


@pytest.fixture
def m(tmp_path):
    return SurrogateEngine(
        vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
        scope_key="project:rva6",
        is_public=predicat_public(DEFAULT_ALLOWLIST))


# --------------------------------------------------------------------------- #
# 1. Une date qui a la FORME d'une date sans en être une
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("valeur", [
    "2020-02-30",   # le 30 février : bug logiciel courant dans un export
    "0000-01-01",
    "2020-13-01",
    "2020-01-32",
    "31/02/2020",
])
def test_a_calendar_impossible_date_does_not_blow_the_stack(m, valeur):
    """Le repli cherchait la date DANS la valeur, retrouvait la valeur
    entière, et se rappelait dessus. `RecursionError` n'est rattrapée nulle
    part : 500 non structuré, session interrompue."""
    assert dates.shift(valeur, 300) is None
    assert m.substitute_value("DATE", valeur) != valeur


# --------------------------------------------------------------------------- #
# 2. Deux écritures d'un même jour
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("a, b", [
    ("1 janvier 2020", "1er janvier 2020"),
    ("1er mars 2021", "1 mars 2021"),
])
def test_two_spellings_of_one_day_do_not_kill_the_request(m, a, b):
    """Attente CORRIGÉE vers le comportement réel, pas vers le vert.

    J'avais écrit que les deux devaient partager UN substitut. C'est faux : le
    coffre restaure une CHAÎNE vers elle-même, donc `1 janvier` et
    `1er janvier` sont deux entrées, et deux entrées ne peuvent pas partager un
    substitut sans casser D6.

    Ce qui était cassé, c'est que le générateur rendait la MÊME date aux 64
    tentatives : la seconde forme ne trouvait jamais de place et la requête
    tombait en 503, sur un document qui mêle la forme formelle et celle d'un
    tableau. Le défaut est là, pas dans le partage."""
    un, deux = m.substitute_value("DATE", a), m.substitute_value("DATE", b)
    assert un != deux
    for rendu in (un, deux):
        assert re.match(r"^\d{1,2}(er)? [a-zéûîà]+ \d{4}$", rendu), rendu


def test_two_different_days_still_never_share_one(m):
    """Le pendant : sans lui, le test précédent serait satisfait en donnant le
    même substitut à tout le monde."""
    jours = [f"{j} janvier 2020" for j in range(1, 20)]
    rendus = [m.substitute_value("DATE", j) for j in jours]
    assert len(set(rendus)) == len(jours)


# --------------------------------------------------------------------------- #
# 3. Le seuil de score portait sur les FRAGMENTS
# --------------------------------------------------------------------------- #


def test_a_low_score_fragment_is_judged_after_reassembly():
    """Un morceau sous le seuil était jeté AVANT la fusion, et son texte réel
    restait en clair, collé au substitut du morceau resté. Le seuil doit porter
    sur l'ENTITÉ : c'est elle que le modèle a vue."""
    texte = "Ouvert par Ines Ferreira-Konate hier."
    fragments = [
        {"type": "PERSON", "value": "Ines Ferreira-K", "score": 0.9,
         "start": 11, "end": 26},
        {"type": "PERSON", "value": "onate", "score": 0.42,
         "start": 26, "end": 31},
    ]
    (entier,) = merge_fragments(fragments, texte)
    assert entier["value"] == "Ines Ferreira-Konate"
    # Le score de l'entité est celui du morceau le moins sûr : c'est LUI qui
    # doit être comparé au seuil, une fois l'entité reconstituée.
    assert entier["score"] == pytest.approx(0.42)


# --------------------------------------------------------------------------- #
# 4. Une span qui COMMENCE au numéro de ligne
# --------------------------------------------------------------------------- #


def test_a_span_starting_at_a_number_is_NOT_cut(m):
    """ATTENTE RETOURNÉE au tour 8, et c'est une décision.

    J'ai voulu retirer le numéro de ligne d'une span qui commence dessus. Un
    numéro de ligne et un matricule métier ont la MÊME forme — chiffres,
    tabulation, début de ligne, parfois alignés. J'ai tenté deux discriminants
    (« au moins une espace », puis « le padding précède la span ») et les deux
    fois un identifiant RÉEL est sorti en clair, sans rien pour le compter.

    Le discriminant n'existe pas dans le contexte local. La span n'est donc
    plus coupée en tête : le numéro de la PREMIÈRE ligne se fera substituer
    avec l'entité, et la numérotation y sera fausse d'une ligne.

    C'est l'arbitrage de tout le projet : une numérotation abîmée est VISIBLE
    — le modèle la signale, on l'a vu faire — un matricule qui part ne l'est
    pas.
    """
    texte = "     3\t42 rue de la Paix\n     4\t75001 Paris\n"
    debut = texte.index("3\t42")
    span = {"type": "ADDRESS", "value": "3\t42 rue de la Paix",
            "start": debut, "end": debut + len("3\t42 rue de la Paix"),
            "score": 0.99}
    (rendu,) = couper_echafaudage([span], texte)
    assert rendu["value"] == "3\t42 rue de la Paix"
    # Et ce qui compte : substitué, le numéro ne part PAS en clair.
    assert "3\t42" not in m.substitute_value("ADDRESS", rendu["value"])


# --------------------------------------------------------------------------- #
# Tour 7 — deux régressions de mes propres correctifs du tour 6
# --------------------------------------------------------------------------- #


@pytest.mark.parametrize("prefixe", ["12345", "999888", "42"])
def test_a_tab_separated_id_is_not_mistaken_for_a_line_number(prefixe):
    """RÉGRESSION du tour 6, et elle FUIT en silence.

    Ma coupure d'en-tête acceptait zéro espace devant le numéro, donc elle
    prenait `12345\tadresse` d'un fichier tabulé pour un numéro de ligne :
    le matricule sortait du span et partait EN CLAIR, sans entrée de coffre ni
    ligne à compter. `Read` aligne ses numéros à droite ; un TSV natif n'a pas
    de padding, et cette espace est ce qui les distingue.
    """
    texte = f"{prefixe}\t42 rue de la Paix, 75001 Paris"
    span = {"type": "ADDRESS", "value": texte, "start": 0,
            "end": len(texte), "score": 0.99}
    (rendu,) = couper_echafaudage([span], texte)
    assert prefixe in rendu["value"], rendu["value"]


def test_a_span_crossing_a_line_end_is_still_cut():
    """Le pendant qui tient encore : une span qui TRAVERSE une fin de ligne
    est nécessairement dans une sortie numérotée — le `\n` le prouve, et lui
    seul. C'est la seule coupure qui reste."""
    texte = "42 rue de la Paix,\n     4\t75001 Paris"
    span = {"type": "ADDRESS", "value": texte, "start": 0,
            "end": len(texte), "score": 0.99}
    morceaux = couper_echafaudage([span], texte)
    assert [x["value"] for x in morceaux] == ["42 rue de la Paix",
                                              "75001 Paris"]


@pytest.mark.parametrize("sans, avec", [
    ("3 fevrier 2026", "3 février 2026"),
    ("10 aout 2020", "10 août 2020"),
    ("1 decembre 2020", "1 décembre 2020"),
])
def test_an_unaccented_french_month_is_still_a_date(m, sans, avec):
    """Un log ASCII écrit `fevrier`. Refusé, il retombait sur la substitution
    générique : un mot d'hôte là où le document annonce une date, et le modèle
    cesse de pouvoir répondre « quand »."""
    assert dates.parse(sans) is not None
    assert dates.parse(sans)[0] == dates.parse(avec)[0]
    assert re.match(r"^\d{1,2} [a-zéûîà]+ \d{4}$", m.substitute_value("DATE", sans))
