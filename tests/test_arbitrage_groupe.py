"""La file se présente par TYPE : quinze gestes, pas deux cents.

L'ouverture est PROGRESSIVE par conception — « une décision de classe
transforme trente questions en une ». Mais la file était affichée À PLAT, ce
qui cachait l'axe : mesurée sur un bac à sable réel, elle comptait 205 valeurs
pour 15 types. L'opérateur voyait deux cents lignes là où quinze suffisent, et
le coût d'arbitrage n'a rien à voir avec le nombre de valeurs.

Le groupe est le DÉFAUT, jamais une perte : le détail reste à une touche
(`d`), et `--une-par-une` retrouve le geste fin. Sur un groupe, « révéler
CETTE valeur » disparaît — elle n'a pas de référent, et c'est précisément ce
que `d` sert à obtenir.
"""
from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

RACINE = Path(__file__).resolve().parents[1]


@pytest.fixture(scope="module")
def cli():
    spec = importlib.util.spec_from_file_location(
        "_policy_cli", RACINE / "scripts" / "anonproxy_policy.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def question(etype: str, i: int) -> dict:
    classe = "pii" if etype in ("EMAIL_ADDRESS", "PERSON") else "infra"
    return {"type": etype, "classe": classe, "empreinte": f"e{i}",
            "substitut": f"s{i}"}


FILE = (
    [question("HOSTNAME", i) for i in range(83)]
    + [question("FILE_PATH", 100 + i) for i in range(69)]
    + [question("URL", 200 + i) for i in range(20)]
    + [question("EMAIL_ADDRESS", 300 + i) for i in range(8)]
    + [question("IBAN_CODE", 400 + i) for i in range(2)]
)


def test_le_nombre_de_gestes_tombe_au_nombre_de_types(cli):
    groupes = cli._groupes(FILE)
    assert len(FILE) == 182
    assert len(groupes) == 5, [g[0]["type"] for g in groupes]


def test_les_groupes_les_plus_nombreux_d_abord(cli):
    """Un geste rapporte le plus là où la file est la plus longue."""
    tailles = [len(g) for g in cli._groupes(FILE)]
    assert tailles == sorted(tailles, reverse=True)


def test_un_groupe_ne_melange_pas_deux_types(cli):
    for groupe in cli._groupes(FILE):
        assert len({q["type"] for q in groupe}) == 1


def test_aucune_question_n_est_perdue(cli):
    """Le groupement est une PRÉSENTATION : il ne doit rien écarter."""
    groupes = cli._groupes(FILE)
    assert sum(len(g) for g in groupes) == len(FILE)
    assert {q["empreinte"] for g in groupes for q in g} \
        == {q["empreinte"] for q in FILE}


def test_une_file_vide_ne_casse_pas(cli):
    assert cli._groupes([]) == []
