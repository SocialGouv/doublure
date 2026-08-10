"""A network declaration must not kill the session.

Found by `tests/phase3_e2e.sh`, which failed with eleven 503s and zero bytes
sent — the exact failure mode the harness exists to catch, and one no unit test
saw. Two distinct defects, one root cause: `_fake_cidr` is the ONLY generator
that ignores the attempt number, so the outer loop's 64 retries are inert. Its
single candidate is either right the first time or the request is refused.

DEFECT 1 — the fictional space cannot represent ITSELF.
    Masking a fictional address to a short prefix collapses it onto the base of
    the range it was drawn from. Round 18 chose those ranges precisely because
    they are reserved — `10/8`, `172.16/12`, RFC 2544 `198.18/15`, RFC 3849
    `2001:db8::/32` — so a declaration OF one of them substitutes to itself,
    the `candidate == real` guard rejects all 64 attempts, and the request is
    refused. `198.18.0.0/15` is written in this repository's own CLAUDE.md,
    which Claude Code loads into the system prompt of EVERY request: the whole
    session was refused before a single byte went out.

    These are RFC constants, not anyone's addressing plan: `10.0.0.0/8` says
    only "this organisation uses private space", which every organisation does.
    They belong in the allowlist, next to `127.0.0.1` and `::1`. What stays
    sensitive is a SPECIFIC subnet — `10.1.2.0/24` reveals the plan, `10/8`
    does not.

DEFECT 2 — two distinct networks collide, unrecoverably.
    Masking discards the octets below the prefix, so two fictional subnets that
    differ only there become the same network. The vault refuses the duplicate
    (D6 holds, nothing leaks) but every retry produces the same candidate.
    Measured: five distinct /16 networks are enough.
"""
from __future__ import annotations

import ipaddress

import pytest

from anonproxy.allowlist import Allowlist
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32


@pytest.fixture
def engine(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "c.db", master_key=MASTER),
                           master_key=MASTER, scope_key="project:cidr",
                           is_public=Allowlist.load().is_exact)


# --------------------------------------------------------------------------- #
# DEFECT 1 — the reserved bases are constants, and belong to the allowlist
# --------------------------------------------------------------------------- #

RESERVED = [
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",     # RFC 1918
    "127.0.0.0/8", "169.254.0.0/16",                     # loopback, link-local
    "198.18.0.0/15",                                     # RFC 2544, our v4 space
    "192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24",  # RFC 5737
    "2001:db8::/32",                                     # RFC 3849, our v6 space
    "fc00::/7", "fe80::/10",                             # ULA, link-local v6
]


@pytest.mark.parametrize("value", RESERVED)
def test_a_reserved_network_is_a_constant(value):
    assert Allowlist.load()(value), (
        f"{value!r} substituted: it names nobody, and its own range is where "
        f"the surrogates come from — so it can only substitute to itself")


@pytest.mark.parametrize("value", [
    "10.1.2.0/24", "10.5.0.0/16", "172.20.5.0/24", "192.168.42.0/24",
    "198.18.7.0/24", "2001:db8:acme::/48",
])
def test_a_specific_subnet_is_still_the_operator_s_plan(value):
    assert not Allowlist.load()(value), (
        f"{value!r} made public: a subnet reveals the addressing plan")


@pytest.mark.parametrize("value", RESERVED)
def test_the_engine_survives_a_reserved_network_anyway(engine, value):
    """Defence in depth: the allowlist drops these in the DETECTOR, so the
    engine only sees one when the detector is out of date — which is exactly
    what refused the whole session. It must hand the constant back, not refuse
    the request. An EXACT allowlist entry is valid everywhere (round 9), so
    consulting it here reuses the decision instead of restating it."""
    assert engine.substitute_value("IP_ADDRESS", value) == value


# --------------------------------------------------------------------------- #
# DEFECT 2 — distinct networks, distinct surrogates, no refusal
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("prefixlen", [12, 16, 20, 24, 28])
def test_many_networks_of_one_prefix_never_exhaust(engine, prefixlen):
    """Five distinct /16s were enough to refuse the request."""
    seen = {}
    step, base = 1 << (32 - prefixlen), int(ipaddress.ip_address("10.0.0.0"))
    for i in range(1, 41):
        value = str(ipaddress.ip_network((base + i * step, prefixlen)))
        surrogate = engine.substitute_value("IP_ADDRESS", value)
        assert surrogate not in seen, (
            f"{value} and {seen[surrogate]} share {surrogate}")
        seen[surrogate] = value


def test_a_network_is_never_substituted_by_itself(engine):
    for i in range(1, 30):
        value = f"10.{i}.0.0/16"
        assert engine.substitute_value("IP_ADDRESS", value) != value


FICTION = [ipaddress.ip_network(n) for n in
           ("10.0.0.0/8", "172.16.0.0/12", "198.18.0.0/15",
            "192.168.0.0/16", "2001:db8::/32", "fc00::/7")]


@pytest.mark.parametrize("value", ["10.7.0.0/16", "172.20.0.0/14",
                                   "192.168.9.0/24", "203.0.113.0/26"])
def test_the_surrogate_network_names_nobody(engine, value):
    """Round 18's invariant: a surrogate must never designate a real-world
    entity. Leaving the reserved space lands on allocated, routed addresses."""
    net = ipaddress.ip_network(engine.substitute_value("IP_ADDRESS", value))
    assert any(net.subnet_of(f) for f in FICTION if f.version == net.version), \
        f"{value} -> {net}: outside every reserved range"


@pytest.mark.parametrize("pair", [
    ("4.0.0.0/15", "6.0.0.0/15"),      # RFC 2544 offers exactly ONE /15
    ("2000::/32", "2400::/32"),        # RFC 3849 offers exactly ONE /32
])
def test_a_reserved_space_of_one_slot_is_not_a_space(engine, pair):
    """At its own prefix length a reserved range holds a single network: the
    first value takes it and the second can only collide, sixty-four times.
    Such a range must be skipped, not offered."""
    premier, second = (engine.substitute_value("IP_ADDRESS", v) for v in pair)
    assert premier != second


def test_a_saturated_space_falls_through_to_the_next(engine):
    """RFC 2544 `198.18.0.0/15` ne contient que DEUX /16 : le troisième réseau
    public de cette taille n'avait plus d'emplacement, et la boucle rendait
    toujours le premier espace valide au lieu de passer au repli. Un espace
    saturé doit céder la place, pas refuser la requête."""
    vus = set()
    for i in range(130, 145):
        vus.add(engine.substitute_value("IP_ADDRESS", f"{i}.0.0.0/16"))
    assert len(vus) == 15, vus


@pytest.mark.parametrize("value", ["0.0.0.0/0", "::/0"])
def test_the_default_route_is_a_constant(value):
    """`0.0.0.0/0` is quoted in every iptables, Kubernetes and Terraform
    prompt. It designates no machine and no addressing plan — and no reserved
    range can hold a /0, so it can only ever refuse."""
    assert Allowlist.load()(value), f"{value!r} would refuse the request"


@pytest.mark.parametrize("value", [
    "128.0.0.0/1", "10.0.0.0/2", "2000::/3", "fd00::/7", "fe00::/7",
    "fc00::/4", "fc00::/5",
])
def test_a_network_too_broad_for_any_reserved_space_is_a_constant(engine, value):
    """Skipping a one-slot space (the fix just above) sends more prefixes past
    the last fallback, where the raise became a 503 — including forms that were
    substituted before. A network that wide designates no machine and no
    addressing plan: it is handed back, exactly as `10.0.0.0/8` is. Refusing
    would trade a leak that does not exist for a session that dies.

    Compared as NETWORKS, not as strings: `fd00::/7` and `fc00::/4` are not
    canonical, and handing back the canonical form of the same network is the
    right answer, not a substitution."""
    rendu = ipaddress.ip_network(engine.substitute_value("IP_ADDRESS", value))
    assert rendu == ipaddress.ip_network(value, strict=False)


def test_a_slash_24_still_contains_its_own_hosts(engine):
    """Round 18: co-membership at /24 is a preserved attribute (§3.4). The
    model saw hosts inside a fictional network and a subnet declaration that
    was not one, and reported the inventory as self-contradictory."""
    net = ipaddress.ip_network(engine.substitute_value("IP_ADDRESS",
                                                       "10.1.2.0/24"))
    for host in ("10.1.2.3", "10.1.2.4", "10.1.2.200"):
        fake = ipaddress.ip_address(engine.substitute_value("IP_ADDRESS", host))
        assert fake in net, f"{host} -> {fake} outside {net}"
