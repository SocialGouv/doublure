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


def test_a_span_starting_at_the_line_number_is_cut_too():
    """La coupure ne traitait que la span qui TRAVERSE l'échafaudage. Celle
    qui COMMENCE dessus — la première ligne d'un `Read` — passait entière, et
    le générateur d'adresses réécrivait le numéro."""
    texte = "     3\t42 rue de la Paix\n     4\t75001 Paris\n"
    debut = texte.index("3\t42")
    span = {"type": "ADDRESS", "value": "3\t42 rue de la Paix",
            "start": debut, "end": debut + len("3\t42 rue de la Paix"),
            "score": 0.99}
    (coupe,) = couper_echafaudage([span], texte)
    assert coupe["value"] == "42 rue de la Paix"
    assert texte[coupe["start"]:coupe["end"]] == coupe["value"]
