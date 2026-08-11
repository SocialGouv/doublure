"""A span must not swallow the scaffolding of the tool output it sits in.

Measured in a real session. The `Read` tool numbers the lines it returns, so a
customer address spanning two lines comes back as

    '14 rue des Grands-Augustins,\\n    21\\t75006 Paris'

— line number and tab included. The address generator then treats `21` as a
number to replace, the numbering it corrupts is the one the model uses to cite
the file, and the model reads `41 rue des Isley, 69 62242 Arden`.

Nothing leaked. But the model saw a mangled document, said so, and refused to
answer part of the question — which is the same cost as being wrong.

The rule: a span is **cut** at the scaffolding, never rewritten across it. Both
halves are still addresses, so both are still substituted; the numbering is
untouched because nothing ever touches it.
"""
from __future__ import annotations

from anonproxy.pii.spans import couper_echafaudage

TEXTE = ("    20\tLa commande de X (livraison au 14 rue des Grands-Augustins,\n"
         "    21\t75006 Paris) est restée bloquée.")


def _span(valeur, etype="ADDRESS"):
    debut = TEXTE.index(valeur)
    return {"type": etype, "value": valeur, "start": debut,
            "end": debut + len(valeur), "score": 0.99}


def test_a_span_crossing_a_line_number_is_cut():
    span = _span("14 rue des Grands-Augustins,\n    21\t75006 Paris")
    morceaux = couper_echafaudage([span], TEXTE)
    # La virgule finale tombe avec la ponctuation de bordure : elle
    # n'appartient pas à l'adresse, et la garder mettrait au coffre une clé
    # qui ne correspond à aucun jeton du texte.
    assert [m["value"] for m in morceaux] == [
        "14 rue des Grands-Augustins", "75006 Paris"]


def test_the_offsets_still_point_at_the_text():
    span = _span("14 rue des Grands-Augustins,\n    21\t75006 Paris")
    for m in couper_echafaudage([span], TEXTE):
        assert TEXTE[m["start"]:m["end"]] == m["value"]


def test_the_line_number_is_never_part_of_a_piece():
    span = _span("14 rue des Grands-Augustins,\n    21\t75006 Paris")
    for m in couper_echafaudage([span], TEXTE):
        assert "21" not in m["value"] and "\t" not in m["value"]


def test_a_span_without_scaffolding_is_untouched():
    span = _span("14 rue des Grands-Augustins,")
    assert couper_echafaudage([span], TEXTE) == [span]


def test_a_plain_newline_is_not_scaffolding():
    """Un texte multiligne SANS numérotation n'a pas à être découpé : couper
    partout produirait des moitiés d'entités là où il n'y a pas de problème."""
    texte = "14 rue des Grands-Augustins,\n75006 Paris"
    span = {"type": "ADDRESS", "value": texte, "start": 0,
            "end": len(texte), "score": 1.0}
    assert couper_echafaudage([span], texte) == [span]
