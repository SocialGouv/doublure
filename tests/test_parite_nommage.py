"""The two implementations name the same files, or the arbitration goes nowhere.

Python decides and Go serves the interface, and they read and write the SAME
directory. When their naming diverged — Python moved to a length-prefixed
fingerprint, Go stayed on character substitution — the service wrote the
operator's decision into a file the engine never opened. The interface reported
success and nothing changed, on the one decision that cannot be taken back.

It survived TWO review rounds because none of the five proofs I was replaying
crossed into Go. Pinning vectors on each side was not enough either: the five I
pinned all had a benign scope key, so they DEFENDED what they checked without
COVERING the class, and the readable prefix went on diverging — same
fingerprint, different file name. The corpus now lives in ONE file that both
sides read, and `test_le_corpus_couvre_le_defaut_d_ordre` requires it to hold a
witness of the trap: a key for which truncating and trimming do not commute.
"""
from __future__ import annotations

import json
import re
from pathlib import Path

import pytest

from anonproxy.policy import _fichier_de_portee

#: Lu AUSSI par `go/internal/policy/naming_test.go`. Un vecteur ajouté d'un
#: seul côté ne prouve rien : c'est ce qui a laissé passer la divergence.
#:
#: Il vit dans le paquet Go parce que `go test` ne piste pas un fichier lu hors
#: de son module : sous `tests/`, un corpus modifié rendait `ok (cached)` sans
#: rien exécuter. Le seul endroit d'où les DEUX preuves rougissent est ici.
CORPUS = (Path(__file__).parent.parent / "go" / "internal" / "policy"
          / "vecteurs_nommage.json")
VECTEURS = json.loads(CORPUS.read_text(encoding="utf-8"))


@pytest.mark.parametrize("v", VECTEURS, ids=lambda v: f"{v['portee']}:{v['scope_key'][:24]}")
def test_le_nom_de_fichier_est_celui_que_le_go_calcule(v):
    obtenu = _fichier_de_portee(Path("/racine"), v["portee"], v["scope_key"],
                                v["session"] or None).name
    assert obtenu == v["attendu"]


def test_les_vecteurs_couvrent_les_trois_portees():
    """C'est la portée SESSION qui avait divergé en dernier (chaîne vide contre
    `sans-id`), et elle n'aurait pas été vue par des vecteurs qui n'en portent
    qu'une."""
    assert {v["portee"] for v in VECTEURS} == {"global", "projet", "session"}


def test_le_corpus_couvre_le_defaut_d_ordre():
    """Le préfixe lisible se construit en TRONQUANT puis en ROGNANT, et les
    deux opérations ne commutent pas. Le Go les faisait dans l'autre ordre.

    Exiger un TÉMOIN plutôt qu'énumérer des cas : un corpus réécrit avec des
    clés anodines redevient rouge, alors qu'une liste de vecteurs se raccourcit
    sans que rien ne proteste.
    """
    def propre(k):
        return re.sub(r"[^A-Za-z0-9_.-]", "-", k)

    temoins = [v["scope_key"] for v in VECTEURS
               if propre(v["scope_key"])[:40].strip("-.")
               != propre(v["scope_key"]).strip("-.")[:40]]
    assert temoins, ("aucun vecteur ne distingue « tronquer puis rogner » de "
                     "« rogner puis tronquer » : la divergence Go/Python "
                     "repasserait sans rougir")


def test_le_corpus_couvre_le_repli_sur_une_cle_sans_caractere_utile():
    """Une clé faite de séparateurs seuls se réduit à vide, et le repli
    `portee` est le seul endroit où le nom ne dérive plus de la clé."""
    assert any(v["attendu"].startswith("portee-") for v in VECTEURS)


def test_le_corpus_couvre_le_defaut_d_octets():
    """La JUMELLE du témoin ci-dessus, et elle manquait.

    Le préfixe de longueur compte des OCTETS en Go et l'a longtemps compté en
    CARACTÈRES en Python : un accent dans la clé de portée suffisait à produire
    deux empreintes, donc deux fichiers, donc une révélation qui traverse. Un
    seul vecteur du corpus distingue les deux comptages ; rien n'exigeait sa
    présence, et « nettoyer l'unicode du corpus » — exactement le geste qui
    avait laissé passer la première divergence — aurait rouvert la seconde sans
    qu'aucune preuve ne rougisse.
    """
    temoins = [v for v in VECTEURS
               if any(len(champ) != len(champ.encode("utf-8"))
                      for champ in (v["scope_key"], v["session"] or ""))]
    assert temoins, ("aucun vecteur non-ASCII : le comptage en caractères "
                     "contre le comptage en octets repasserait sans rougir")
