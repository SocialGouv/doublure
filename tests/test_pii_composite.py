"""Composing two detectors — and refusing when either is down.

Neither subsumes the other: a cyber NER has no `PERSON`, a privacy model has no
`K8S_NAMESPACE`. The point of composing is to close the class, not to trade one
blind spot for another.

The test that matters is the outage one. Carrying on without the personal-data
pass would silently restore the behaviour that let three names out of a real
session, with nothing to count — which is exactly the failure mode this project
refuses everywhere else.
"""
from __future__ import annotations

import pytest

from anonproxy.detect import DetectionUnavailable
from anonproxy.pii.composite import CompositeDetector


class _Fixe:
    def __init__(self, spans):
        self.spans = spans
        self.ferme = False

    def detect(self, text, *, strategy=None):
        return list(self.spans)

    def health(self):
        return {"status": "ok"}

    def close(self):
        self.ferme = True


class _EnPanne(_Fixe):
    def detect(self, text, *, strategy=None):
        raise DetectionUnavailable("service arrêté")


def _span(valeur, etype, debut):
    return {"type": etype, "value": valeur, "start": debut,
            "end": debut + len(valeur), "score": 1.0}


def test_both_streams_end_up_in_one():
    compose = CompositeDetector(
        _Fixe([_span("db-01.acme.internal", "HOSTNAME", 20)]),
        _Fixe([_span("Ines Ferreira", "PERSON", 0)]))
    types = {s["type"] for s in compose.detect("…")}
    assert types == {"HOSTNAME", "PERSON"}


def test_the_stream_is_ordered_by_position():
    """Le moteur arbitre les recouvrements sur un flux ORDONNÉ ; deux sources
    concaténées ne le sont pas."""
    compose = CompositeDetector(
        _Fixe([_span("db-01", "HOSTNAME", 40)]),
        _Fixe([_span("Ines", "PERSON", 5)]))
    positions = [s["start"] for s in compose.detect("…")]
    assert positions == sorted(positions)


def test_an_outage_of_the_personal_pass_is_a_refusal():
    """Continuer sans elle rendrait en silence le comportement qui a laissé
    sortir trois noms — et une panne n'a pas à prendre cette décision."""
    compose = CompositeDetector(_Fixe([]), _EnPanne([]))
    with pytest.raises(DetectionUnavailable):
        compose.detect("…")


def test_an_outage_of_the_infrastructure_pass_is_a_refusal():
    compose = CompositeDetector(_EnPanne([]), _Fixe([]))
    with pytest.raises(DetectionUnavailable):
        compose.detect("…")


def test_closing_reaches_the_second_even_if_the_first_throws():
    """Une fermeture qui s'arrête au premier échec laisse une connexion ouverte
    pour toujours."""
    class _FermetureCassee(_Fixe):
        def close(self):
            raise OSError("socket déjà fermée")

    second = _Fixe([])
    compose = CompositeDetector(_FermetureCassee([]), second)
    with pytest.raises(OSError):
        compose.close()
    assert second.ferme, "le second détecteur n'a jamais été fermé"
