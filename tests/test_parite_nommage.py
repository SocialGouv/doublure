"""The two implementations name the same files, or the arbitration goes nowhere.

Python decides and Go serves the interface, and they read and write the SAME
directory. When their naming diverged — Python moved to a length-prefixed
fingerprint, Go stayed on character substitution — the service wrote the
operator's decision into a file the engine never opened. The interface reported
success and nothing changed, on the one decision that cannot be taken back.

It survived TWO review rounds because none of the five proofs I was replaying
crossed into Go. The vectors below are pinned on both sides; if either drifts,
one of the two goes red.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from anonproxy.policy import _fichier_de_portee

#: Les mêmes que `go/internal/policy/naming_test.go`.
VECTEURS = [
    ("projet", "project:control-proof", None,
     "project-control-proof-061aed50418cd255.json"),
    ("session", "project:control-proof", "s-42",
     "project-control-proof-session-6cf7f5ee649ee882.json"),
    ("projet", "team/prod", "x", "team-prod-304a320b1e1c0edf.json"),
    ("session", "a:b/c", None, "a-b-c-session-9a18584f8d73ee66.json"),
    ("global", "peu:importe", None, "global.json"),
]


@pytest.mark.parametrize("portee,scope_key,session,attendu", VECTEURS)
def test_le_nom_de_fichier_est_celui_que_le_go_calcule(portee, scope_key,
                                                       session, attendu):
    assert _fichier_de_portee(Path("/racine"), portee, scope_key,
                              session).name == attendu


def test_les_vecteurs_couvrent_les_trois_portees():
    """Un vecteur par portée au moins : c'est la portée SESSION qui avait
    divergé en dernier (chaîne vide contre `sans-id`), et elle n'aurait pas
    été vue par des vecteurs qui n'en portent qu'une."""
    assert {v[0] for v in VECTEURS} == {"global", "projet", "session"}
