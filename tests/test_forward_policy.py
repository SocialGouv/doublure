"""What the forward proxy does with a destination — decided before it connects.

Three verdicts, and the default is the one that matters: **refuse**. A forward
proxy is the only place in this system that sees every destination an agent
opens, so a permissive default would turn the one chokepoint into a doorway.

`tunnel` deserves its own name rather than being folded into `inspect`: some
destinations must NOT be intercepted — a host that pins its certificate breaks,
and one carrying credentials we have no business reading is better relayed
blind than decrypted and logged.
"""
from __future__ import annotations

import pytest

from anonproxy.forward.policy import ForwardPolicy, Verdict


def test_an_unknown_destination_is_refused():
    """Fail-closed. Ajouter une destination est un geste ; en oublier une ne
    doit pas être une ouverture."""
    politique = ForwardPolicy(inspect=["api.example.test"], tunnel=[])
    assert politique.verdict("collecte.exfil.test") is Verdict.REFUSE


def test_a_subdomain_is_covered_but_a_neighbour_is_not():
    """Comparé comme un HÔTE, jamais comme une sous-chaîne : le propriétaire de
    `example.test.attaquant.test` n'est pas le même. Leçon du round 3, où un
    test de préfixe acceptait `127.evil.test`."""
    politique = ForwardPolicy(inspect=["example.test"], tunnel=[])
    assert politique.verdict("docs.example.test") is Verdict.INSPECT
    assert politique.verdict("example.test") is Verdict.INSPECT
    assert politique.verdict("example.test.attaquant.test") is Verdict.REFUSE
    assert politique.verdict("notexample.test") is Verdict.REFUSE


def test_the_case_of_a_host_does_not_decide():
    politique = ForwardPolicy(inspect=["API.Example.Test"], tunnel=[])
    assert politique.verdict("api.example.test") is Verdict.INSPECT


def test_tunnel_and_inspect_are_distinct():
    politique = ForwardPolicy(inspect=["a.test"], tunnel=["b.test"])
    assert politique.verdict("a.test") is Verdict.INSPECT
    assert politique.verdict("b.test") is Verdict.TUNNEL


def test_the_narrowest_rule_wins():
    """`tunnel` sur un sous-domaine d'un domaine inspecté doit tenir : c'est
    ainsi qu'on épargne un hôte qui épingle son certificat sans rouvrir tout
    le domaine."""
    politique = ForwardPolicy(inspect=["example.test"],
                              tunnel=["pinned.example.test"])
    assert politique.verdict("pinned.example.test") is Verdict.TUNNEL
    assert politique.verdict("autre.example.test") is Verdict.INSPECT


def test_a_destination_declared_twice_is_an_error():
    """Un doublon entre les deux listes se résoudrait en silence par l'ordre de
    lecture, et le mode d'interception d'un hôte serait décidé par un hasard
    d'écriture."""
    with pytest.raises(ValueError, match="a.test"):
        ForwardPolicy(inspect=["a.test"], tunnel=["a.test"])


def test_the_port_is_not_part_of_the_host():
    politique = ForwardPolicy(inspect=["example.test"], tunnel=[])
    assert politique.verdict("example.test:8443") is Verdict.INSPECT


def test_an_address_is_matched_exactly():
    """Un littéral n'a pas de sous-domaine : le suffixe ne s'y applique pas,
    sinon `7.0.0.1` couvrirait `127.0.0.1`."""
    politique = ForwardPolicy(inspect=["127.0.0.1"], tunnel=[])
    assert politique.verdict("127.0.0.1") is Verdict.INSPECT
    assert politique.verdict("10.127.0.0.1") is Verdict.REFUSE
