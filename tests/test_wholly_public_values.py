"""A value with nothing left to hide must not refuse the request.

Second defect found by the same `phase3_e2e.sh` run, once the CIDR one was
closed — and it is the same shape, reached through another type. A composite
value whose identifying parts are ALL public (`http://127.0.0.1/`,
`http://localhost:8090`, `https://claude.ai`) is rebuilt identically by the
generator. The `candidate == real` guard then rejects all 64 attempts — that
guard is right, it exists so a finite lexicon never lets a value substitute to
itself — and the request falls to 503.

Two of those five were broken by adding `claude.ai` and `example.com` to the
allowlist in this same session: widening what is public turned a substituted
URL into an unsubstitutable one. The perimeter I extended is the one that
broke, which is the round 11 lesson repeating.

The rule that closes it distinguishes the two reasons a candidate is rejected.
An IDENTITY means the generator has nothing to work with; sixty-four in a row
is not bad luck, it is a statement about the value. A CONFLICT means the
surrogate is taken — real contention, and there the refusal stands. So a single
conflict anywhere in the sixty-four attempts keeps the request refused: we never
hand back a real value because a surrogate was busy.
"""
from __future__ import annotations

import pytest

from anonproxy.allowlist import Allowlist
from anonproxy.surrogates.engine import SurrogateEngine
from anonproxy.vault import Vault

MASTER = "f6" * 32


@pytest.fixture
def engine(tmp_path):
    return SurrogateEngine(vault=Vault(tmp_path / "p.db", master_key=MASTER),
                           master_key=MASTER, scope_key="project:public",
                           is_public=Allowlist.load().is_exact)


# --------------------------------------------------------------------------- #
# What must come back intact — nothing in it identifies anyone
# --------------------------------------------------------------------------- #

WHOLLY_PUBLIC = [
    "http://127.0.0.1/",
    "http://127.0.0.1:9000",
    "http://localhost:8090",
    "https://example.com",
    "https://claude.ai",
    "https://anthropic.com",
]


@pytest.mark.parametrize("value", WHOLLY_PUBLIC)
def test_a_wholly_public_url_is_returned_intact(engine, value):
    assert engine.substitute_value("URL", value) == value


# --------------------------------------------------------------------------- #
# What must still be substituted — the counter-test of the rule above
# --------------------------------------------------------------------------- #

STILL_SENSITIVE = [
    # a public host does not make its path public
    "https://claude.ai/tenant-acme-nda",
    "http://localhost:8090/db-master.acme.internal",
    "https://example.com/?host=db-01.acme.internal",
    "http://127.0.0.1/clients/acme-nda-2025",
    # a neighbouring host is not the allowlisted one
    "https://claude.ai.acme.internal/",
    "https://db-01.acme.internal/",
    # credentials are secrets, never restorable (D4)
    "https://alice:s3cr3t@example.com/",
]


@pytest.mark.parametrize("value", STILL_SENSITIVE)
def test_a_public_host_does_not_make_the_rest_public(engine, value):
    surrogate = engine.substitute_value("URL", value)
    assert surrogate != value, f"{value!r} left in the clear"
    for secret in ("tenant-acme-nda", "db-master.acme.internal",
                   "db-01.acme.internal", "acme-nda-2025", "s3cr3t"):
        assert secret not in surrogate, f"{secret!r} survived in {surrogate!r}"


@pytest.mark.parametrize("value,secret", [
    ("https://claude.ai:db-01.acme.internal", "db-01.acme.internal"),
    ("https://api.anthropic.com:tenant-acme-nda", "tenant-acme-nda"),
    ("https://srv.acme.internal:tenant-billing-01/foo", "tenant-billing-01"),
    # La LONGUEUR ne suffit pas : RFC 6335 borne un port à 65535, au-delà
    # c'est un compteur ou un identifiant interne.
    ("https://srv.acme.internal:99999/", "99999"),
    ("https://srv.acme.internal:65536/", "65536"),
])
def test_what_follows_the_colon_is_only_a_port_if_it_is_a_number(
        engine, value, secret):
    """RFC 3986 puts a PORT after the colon. It was copied verbatim whatever it
    held, so an identifier written there left in the clear with no vault entry —
    and when the host is public on top of that, the whole URL became its own
    identity and was handed back untouched. The two defects compose into the
    quietest leak the system can produce."""
    assert secret not in engine.substitute_value("URL", value)


@pytest.mark.parametrize("etype", ["API_KEY", "PASSWORD", "AUTH_TOKEN"])
@pytest.mark.parametrize("value", ["default", "localhost", "iana.org", "admin"])
def test_a_secret_stays_a_secret_even_when_it_reads_as_public(
        engine, etype, value):
    """`default` and `localhost` are among the most common weak passwords there
    are. Testing the allowlist BEFORE the class let them out verbatim, and
    skipped the reference D4 demands: a secret is never restored, so it is
    never returned as itself either."""
    assert engine.substitute_value(etype, value) != value


@pytest.mark.parametrize("value,secret", [
    ("git@user:pass@github.com:org/name.git", "pass"),
    ("git@alice-payments-svc:TOKEN@github.com:org/name.git",
     "alice-payments-svc"),
    ("git@oauth2:ghp_realtoken1234567890@github.com:org/name.git",
     "ghp_realtoken1234567890"),
])
def test_ssh_credentials_never_ride_out_as_the_host(engine, value, secret):
    """Découper sur le PREMIER `@` prenait l'identifiant pour l'hôte et le
    recopiait tel quel — alors que la canonicalisation l'avait justement retiré
    de la clé de coffre. C'est le dernier `@` qui sépare l'autorité, et un
    identifiant est un secret : il ne se recopie jamais (D4)."""
    assert secret not in engine.substitute_value("REPO", value)


def test_a_plain_ssh_repo_keeps_its_shape(engine):
    """Le pendant : sans identifiant, la forme SSH reste lisible."""
    rendu = engine.substitute_value("REPO", "git@github.com:acmecorp/api.git")
    assert rendu.startswith("git@github.com:") and rendu.endswith(".git")
    assert "acmecorp" not in rendu


def test_a_taken_surrogate_still_refuses(engine, monkeypatch):
    """The rule must not become 'after 64 failures, hand back the real value'.
    A CONFLICT is real contention: the request stays refused, fail-closed."""
    from anonproxy.surrogates import engine as moteur

    monkeypatch.setattr(engine, "_candidate",
                        lambda *a, **k: "srv-pris.exemple.internal")
    engine.vault.bind("project:public", "URL", "autre-valeur",
                      "srv-pris.exemple.internal")
    with pytest.raises(moteur.SurrogateCollisionError):
        engine.substitute_value("URL", "https://db-01.acme.internal/")
