"""What goes in the vault must be what the model will quote back.

Found in a real session, and it is the nastiest shape a defect takes here: the
operator was shown `11 juillet 2027` and had no way to know it was fiction.
Not a leak — the reverse. A surrogate that never came home, wearing the face of
a real value.

The mechanism: on the text as the `Read` tool sends it, the detector returns
the field with its time — `3 février 2026 à 14h32`. That whole string became
the vault key, so the surrogate was `… à 14h32` too. The model quoted the date
alone, nothing matched, and nothing counted it either: an unresolved surrogate
is counted, a surrogate nobody recognises as one is not.

The second date in the same file, `12 mars 2019`, has no time after it. It
restored perfectly. One document, one type, two fates — the difference being
four characters of surround.

So a span is NARROWED to the entity before it reaches the vault. The vault key
is the date; the surround is text, and text is not substituted.
"""
from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from anonproxy.allowlist import DEFAULT_ALLOWLIST  # noqa: E402
from anonproxy.pii.spans import resserrer  # noqa: E402
from anonproxy.proxy.app import predicat_public  # noqa: E402
from anonproxy.surrogates.engine import SurrogateEngine  # noqa: E402
from anonproxy.vault import Vault  # noqa: E402
from anthropic_walker import Substituter  # noqa: E402

MASTER = "ad" * 32
CHAMP = "**Ouvert le** 3 février 2026 à 14h32 par Ines"


def _span(valeur, texte=CHAMP, etype="DATE"):
    debut = texte.index(valeur)
    return {"type": etype, "value": valeur, "start": debut,
            "end": debut + len(valeur), "score": 1.0}


@pytest.mark.parametrize("brut, attendu", [
    ("3 février 2026 à 14h32", "3 février 2026"),
    ("3 février 2026", "3 février 2026"),
])
def test_a_date_span_is_narrowed_to_the_date(brut, attendu):
    (span,) = resserrer([_span(brut)], CHAMP)
    assert span["value"] == attendu
    assert CHAMP[span["start"]:span["end"]] == attendu


def test_a_leading_preposition_is_left_out():
    texte = "ouvert le 3 février 2026, sévérité majeure"
    (span,) = resserrer([_span("le 3 février 2026", texte)], texte)
    assert span["value"] == "3 février 2026"


def test_a_span_of_another_type_is_untouched():
    """Resserrer une adresse sur sa date la détruirait."""
    texte = "14 rue des Grands-Augustins, 75006 Paris"
    span = _span(texte, texte, "ADDRESS")
    assert resserrer([span], texte) == [span]


def test_a_span_with_no_date_survives_as_is():
    texte = "la semaine dernière"
    span = _span(texte, texte)
    assert resserrer([span], texte) == [span]


def test_the_model_quoting_the_date_alone_gets_it_restored(tmp_path):
    """LE test. Il aurait attrapé le défaut, et aucun de ceux que j'avais
    écrits ne le pouvait : ils s'arrêtaient à la substitution."""
    moteur = SurrogateEngine(
        vault=Vault(tmp_path / "v.db", master_key=MASTER), master_key=MASTER,
        scope_key="project:restauration",
        is_public=predicat_public(DEFAULT_ALLOWLIST))

    (span,) = resserrer([_span("3 février 2026 à 14h32")], CHAMP)
    substitut = moteur.substitute_value("DATE", span["value"])

    restaure = Substituter(to_surrogate=lambda s: s,
                           surrogates=moteur.surrogates_view())
    rendu, non_resolus = restaure.to_real(f"Le ticket est daté du {substitut}.")
    assert "3 février 2026" in rendu, rendu
    assert not non_resolus
